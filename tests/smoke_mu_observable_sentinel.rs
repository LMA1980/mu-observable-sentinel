#![deny(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mu_observable_ipc::{decode_log_batch, decode_metric_batch, OtelLogEntry, OtelMetricEntry};
use mu_observable_sentinel::{
    apply_sentinel_startup_sandbox, CollectorArrowEmitter, HostSentinelCollector, SentinelConfig,
    SentinelError, SentinelSandboxConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const DEFAULT_SMOKE_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone)]
struct SmokeConfig {
    target_url: Option<String>,
    #[allow(dead_code)]
    tls_ca_file: Option<PathBuf>,
    #[allow(dead_code)]
    tls_cert_file: Option<PathBuf>,
    #[allow(dead_code)]
    tls_key_file: Option<PathBuf>,
    #[allow(dead_code)]
    bearer_token: Option<String>,
    timeout: Duration,
}

impl SmokeConfig {
    fn from_env() -> Result<Self, String> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let tls_ca_file = non_empty_path(&lookup, "MU_SMOKE_TLS_CA_FILE")?;
        let tls_cert_file = non_empty_path(&lookup, "MU_SMOKE_TLS_CERT_FILE")?;
        let tls_key_file = non_empty_path(&lookup, "MU_SMOKE_TLS_KEY_FILE")?;

        if tls_cert_file.is_some() != tls_key_file.is_some() {
            return Err(
                "MU_SMOKE_TLS_CERT_FILE and MU_SMOKE_TLS_KEY_FILE must both be set when configuring client mTLS"
                    .to_string(),
            );
        }

        if let Some(ref ca_path) = tls_ca_file {
            read_trimmed_secret(ca_path, "MU_SMOKE_TLS_CA_FILE")?;
        }
        if let (Some(ref cert_path), Some(ref key_path)) = (&tls_cert_file, &tls_key_file) {
            read_trimmed_secret(cert_path, "MU_SMOKE_TLS_CERT_FILE")?;
            read_trimmed_secret(key_path, "MU_SMOKE_TLS_KEY_FILE")?;
        }

        let bearer_token = match non_empty_path(&lookup, "MU_SMOKE_BEARER_TOKEN_FILE")? {
            Some(path) => Some(read_trimmed_secret(&path, "MU_SMOKE_BEARER_TOKEN_FILE")?),
            None => None,
        };

        let timeout_secs = match non_empty_var(&lookup, "MU_SMOKE_TIMEOUT_SECS") {
            Some(raw) => {
                let parsed = raw
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid MU_SMOKE_TIMEOUT_SECS '{raw}': {e}"))?;
                if parsed == 0 {
                    return Err("MU_SMOKE_TIMEOUT_SECS must be greater than 0".to_string());
                }
                parsed
            }
            None => DEFAULT_SMOKE_TIMEOUT_SECS,
        };

        let target_url = match non_empty_var(&lookup, "MU_SMOKE_TARGET_URL") {
            Some(url) => Some(url.trim_end_matches('/').to_string()),
            None => non_empty_var(&lookup, "MU_SMOKE_TARGET_ADDR").map(|addr| {
                let trimmed = addr.trim_end_matches('/');
                if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                    trimmed.to_string()
                } else {
                    format!("http://{trimmed}")
                }
            }),
        };

        Ok(Self {
            target_url,
            tls_ca_file,
            tls_cert_file,
            tls_key_file,
            bearer_token,
            timeout: Duration::from_secs(timeout_secs),
        })
    }
}

fn non_empty_var<F>(lookup: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn non_empty_path<F>(lookup: &F, key: &str) -> Result<Option<PathBuf>, String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Err(format!("{key} was set but empty"))
            } else {
                Ok(Some(PathBuf::from(trimmed)))
            }
        }
        None => Ok(None),
    }
}

fn read_trimmed_secret(path: &Path, var_name: &str) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Failed to read {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{var_name} at '{}' is empty after trimming (fail closed)",
            path.display()
        ));
    }
    Ok(trimmed.to_string())
}

async fn http_get_healthz(base_url: &str, timeout: Duration) -> Result<serde_json::Value, String> {
    if base_url.starts_with("https://") {
        return Err(
            "mu-observable-sentinel emitter targets loopback http:// collector endpoints only"
                .to_string(),
        );
    }
    let authority_and_prefix = base_url
        .strip_prefix("http://")
        .ok_or_else(|| format!("Unsupported URL scheme in '{base_url}'"))?;
    let (authority, base_path) = match authority_and_prefix.find('/') {
        Some(idx) => (&authority_and_prefix[..idx], &authority_and_prefix[idx..]),
        None => (authority_and_prefix, ""),
    };
    let connect_addr = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:4318")
    };
    let path = format!("{}/healthz", base_path.trim_end_matches('/'));

    tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect(&connect_addr)
            .await
            .map_err(|e| format!("Failed connecting to {connect_addr}: {e}"))?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("Failed writing GET /healthz: {e}"))?;
        stream
            .flush()
            .await
            .map_err(|e| format!("Failed flushing GET /healthz: {e}"))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|e| format!("Failed reading GET /healthz response: {e}"))?;
        let sep = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| "Malformed HTTP response from collector".to_string())?;
        let head =
            std::str::from_utf8(&raw[..sep]).map_err(|e| format!("Invalid UTF-8 headers: {e}"))?;
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(500);
        if status != 200 {
            return Err(format!("GET {path} returned unexpected HTTP {status}"));
        }
        serde_json::from_slice(&raw[sep + 4..])
            .map_err(|e| format!("Invalid JSON in /healthz response: {e}"))
    })
    .await
    .map_err(|_| "GET /healthz timed out".to_string())?
}

#[derive(Default)]
struct CapturedBatches {
    metrics: Vec<OtelMetricEntry>,
    logs: Vec<OtelLogEntry>,
}

async fn spawn_ephemeral_collector_receiver(
    fail_post_with_503: bool,
) -> (
    String,
    Arc<Mutex<CapturedBatches>>,
    tokio::task::JoinHandle<()>,
) {
    let captured = Arc::new(Mutex::new(CapturedBatches::default()));
    let captured_srv = captured.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let captured = captured_srv.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let header_end;
                loop {
                    let n = match stream.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = pos + 4;
                        break;
                    }
                }

                let header_str = String::from_utf8_lossy(&buf[..header_end]).into_owned();
                let first_line = header_str.lines().next().unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let content_len: usize = header_str
                    .lines()
                    .find_map(|line| {
                        let lower = line.to_ascii_lowercase();
                        lower
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);

                while buf.len() < header_end + content_len {
                    let n = match stream.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                }
                let body = &buf[header_end..(header_end + content_len).min(buf.len())];

                let (status_line, resp_body) = match (method.as_str(), path.as_str()) {
                    ("GET", "/healthz") => (
                        "HTTP/1.1 200 OK",
                        r#"{"status":"ok","node_id":"node-a","wal_used_bytes":0,"wal_pending_batches":0}"#.as_bytes().to_vec(),
                    ),
                    ("POST", "/v1/metrics") => {
                        if fail_post_with_503 {
                            ("HTTP/1.1 503 Service Unavailable", br#"{"error":"overloaded"}"#.to_vec())
                        } else {
                            let entries = decode_metric_batch(body).expect("valid Arrow metrics batch");
                            captured.lock().await.metrics.extend(entries);
                            ("HTTP/1.1 200 OK", br#"{"accepted_records":1,"wal_sequence":1,"dropped_backpressure":false}"#.to_vec())
                        }
                    }
                    ("POST", "/v1/logs") => {
                        if fail_post_with_503 {
                            ("HTTP/1.1 503 Service Unavailable", br#"{"error":"overloaded"}"#.to_vec())
                        } else {
                            let entries = decode_log_batch(body).expect("valid Arrow logs batch");
                            captured.lock().await.logs.extend(entries);
                            ("HTTP/1.1 200 OK", br#"{"accepted_records":1,"wal_sequence":2,"dropped_backpressure":false}"#.to_vec())
                        }
                    }
                    _ => ("HTTP/1.1 404 Not Found", br#"{"error":"not_found"}"#.to_vec()),
                };

                let resp = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp_body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(&resp_body).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    (format!("http://{addr}"), captured, handle)
}

fn populate_synthetic_proc_and_sys(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let proc_root = root.join("proc");
    let sys_root = root.join("sys");
    let ckpt_path = root.join("state").join("kmsg.ckpt");

    std::fs::create_dir_all(proc_root.join("pressure")).unwrap();
    std::fs::create_dir_all(proc_root.join("net")).unwrap();
    std::fs::create_dir_all(proc_root.join("sys/kernel/random")).unwrap();
    std::fs::create_dir_all(
        sys_root
            .join("fs")
            .join("btrfs")
            .join("uuid-smoke")
            .join("devinfo")
            .join("1"),
    )
    .unwrap();

    std::fs::write(
        proc_root.join("sys/kernel/random/boot_id"),
        "smoke-boot-uuid-0001\n",
    )
    .unwrap();
    std::fs::write(
        proc_root.join("pressure/io"),
        "some avg10=1.25 avg60=0.50 avg300=0.10 total=100\nfull avg10=0.20 avg60=0.10 avg300=0.05 total=20\n",
    )
    .unwrap();
    std::fs::write(
        proc_root.join("pressure/memory"),
        "some avg10=0.50 avg60=0.20 avg300=0.05 total=50\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
    )
    .unwrap();
    std::fs::write(
        proc_root.join("pressure/cpu"),
        "some avg10=0.80 avg60=0.40 avg300=0.10 total=80\n",
    )
    .unwrap();
    std::fs::write(
        proc_root.join("meminfo"),
        "MemTotal:       16384000 kB\nMemAvailable:   12000000 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\nDirty:               256 kB\nWriteback:             0 kB\n",
    )
    .unwrap();
    std::fs::write(
        proc_root.join("net/unix"),
        "00000000: 00000002 00000000 00010000 0002 01 12345 /run/systemd/journal/dev-log\n",
    )
    .unwrap();
    std::fs::write(
        proc_root.join("diskstats"),
        "   8       48 sdd 100 0 800 500 200 0 1600 1000 0 800 1500 0 0 0 0 0 0\n",
    )
    .unwrap();
    std::fs::write(proc_root.join("uptime"), "1000.00 900.00\n").unwrap();
    std::fs::write(
        sys_root.join("fs/btrfs/uuid-smoke/devinfo/1/error_stats"),
        "write_io_errs 0\nread_io_errs 0\nflush_io_errs 0\ncorruption_errs 0\ngeneration_errs 0\n",
    )
    .unwrap();

    (proc_root, sys_root, ckpt_path)
}

#[test]
#[cfg_attr(miri, ignore)]
fn smoke_config_enforces_fail_closed_credentials_and_sandbox_readiness() {
    let temp = tempfile::tempdir().unwrap();
    let token_path = temp.path().join("sentinel.token");
    std::fs::write(&token_path, "  sentinel-bearer-secret \n").unwrap();

    let ok_env = HashMap::from([
        ("MU_SMOKE_TARGET_URL", "http://127.0.0.1:4318/".to_string()),
        (
            "MU_SMOKE_BEARER_TOKEN_FILE",
            token_path.to_string_lossy().into_owned(),
        ),
    ]);
    let cfg = SmokeConfig::from_lookup(|k| ok_env.get(k).cloned()).unwrap();
    assert_eq!(cfg.target_url.as_deref(), Some("http://127.0.0.1:4318"));
    assert_eq!(cfg.bearer_token.as_deref(), Some("sentinel-bearer-secret"));
    assert_eq!(cfg.timeout, Duration::from_secs(10));

    // Unreadable bearer token file fails closed
    let missing_tok = HashMap::from([(
        "MU_SMOKE_BEARER_TOKEN_FILE",
        temp.path()
            .join("missing.token")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| missing_tok.get(k).cloned()).is_err());

    // Unreadable TLS CA file fails closed
    let missing_ca = HashMap::from([(
        "MU_SMOKE_TLS_CA_FILE",
        temp.path()
            .join("missing.ca")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| missing_ca.get(k).cloned()).is_err());

    // Half-configured client mTLS fails closed
    let partial = HashMap::from([(
        "MU_SMOKE_TLS_CERT_FILE",
        token_path.to_string_lossy().into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| partial.get(k).cloned()).is_err());

    // Validate MuIsolation KernelSandbox startup plan
    let plan = apply_sentinel_startup_sandbox(&SentinelSandboxConfig::default())
        .expect("sentinel startup sandbox plan");
    assert!(!plan.landlock_rules.is_empty());
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn smoke_mu_observable_sentinel_parsers_and_collector_readiness() {
    let smoke_cfg = SmokeConfig::from_env().expect("valid MU_SMOKE_* environment configuration");

    // Always validate isolated local parser & sweep readiness against tempfile fixtures
    let temp = tempfile::tempdir().unwrap();
    let (proc_root, sys_root, ckpt_path) = populate_synthetic_proc_and_sys(temp.path());

    if let Some(ref target_url) = smoke_cfg.target_url {
        let health = http_get_healthz(target_url, smoke_cfg.timeout)
            .await
            .expect("live collector GET /healthz must succeed");
        assert_eq!(health["status"], "ok");

        // Strictly non-polluting empty-slice emitter checks
        let emitter = CollectorArrowEmitter::new(target_url);
        emitter
            .emit_metrics(&[])
            .await
            .expect("empty metrics emit is a non-polluting no-op");
        emitter
            .emit_logs(&[])
            .await
            .expect("empty logs emit is a non-polluting no-op");

        // Run local fixture sweep strictly in memory without emitting to live collector
        let cfg = SentinelConfig {
            node_id: "node-a".to_string(),
            arch: "x86_64".to_string(),
            collector_url: target_url.clone(),
            proc_root,
            sys_root,
            kmsg_checkpoint_path: Some(ckpt_path),
            ..SentinelConfig::default()
        };
        let mut collector = HostSentinelCollector::new(cfg);
        let (metrics, _) = collector.sweep_once(5_000);
        assert!(!metrics.is_empty());
        return;
    }

    // Ephemeral mode: spin up local 127.0.0.1:0 receiver and exercise full pipeline
    let (ephemeral_url, captured, srv_handle) = spawn_ephemeral_collector_receiver(false).await;

    let health = http_get_healthz(&ephemeral_url, smoke_cfg.timeout)
        .await
        .expect("ephemeral GET /healthz");
    assert_eq!(health["status"], "ok");

    let cfg = SentinelConfig {
        node_id: "node-a".to_string(),
        arch: "x86_64".to_string(),
        collector_url: ephemeral_url.clone(),
        proc_root,
        sys_root,
        kmsg_checkpoint_path: Some(ckpt_path),
        ..SentinelConfig::default()
    };
    let mut collector = HostSentinelCollector::new(cfg);
    let (metrics, mut logs) = collector.sweep_once(5_000);
    assert!(!metrics.is_empty());

    let kmsg_logs = collector.ingest_kmsg_lines(
        "3,501,100000,-;critical target error, dev sdd, sector 42 op 0x3:(DISCARD)\n",
    );
    assert_eq!(kmsg_logs.len(), 1);
    logs.extend(kmsg_logs);

    let emitter = CollectorArrowEmitter::new(&ephemeral_url);
    emitter.emit_metrics(&[]).await.unwrap();
    emitter.emit_logs(&[]).await.unwrap();
    emitter
        .emit_metrics(&metrics)
        .await
        .expect("emit Arrow metrics to ephemeral receiver");
    emitter
        .emit_logs(&logs)
        .await
        .expect("emit Arrow logs to ephemeral receiver");

    {
        let got = captured.lock().await;
        assert_eq!(got.metrics.len(), metrics.len());
        assert_eq!(got.logs.len(), logs.len());
    }
    srv_handle.abort();

    // Verify CollectorArrowEmitter surfaces non-2xx HTTP failure cleanly
    let (err_url, _, err_handle) = spawn_ephemeral_collector_receiver(true).await;
    let err_emitter = CollectorArrowEmitter::new(&err_url);
    let err = err_emitter.emit_metrics(&metrics).await.unwrap_err();
    assert!(matches!(
        err,
        SentinelError::CollectorHttp { status: 503, .. }
    ));
    err_handle.abort();
}
