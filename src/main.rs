use mu_observable_ipc::OtelLogEntry;
use mu_observable_sentinel::{
    apply_sentinel_startup_sandbox, env_var_first_with, resolve_preferred_path_chain,
    should_serve_from_env, stream_kmsg_lines, CollectorArrowEmitter, HostSentinelCollector,
    SentinelConfig, SentinelSandboxConfig, DEFAULT_SENTINEL_CHECKPOINT_PATH,
    DEFAULT_SENTINEL_CONFIG_DIR, DEFAULT_SENTINEL_STATE_DIR, LEGACY_SENTINEL_CHECKPOINT_PATH,
    LEGACY_SENTINEL_MUOBSERVE_CHECKPOINT_PATH, LEGACY_SENTINEL_MUOBSERVE_CONFIG_DIR,
    LEGACY_SENTINEL_MUSENTINEL_CONFIG_DIR,
};
use std::path::Path;
use tokio::sync::mpsc;

const MAX_PENDING_KMSG_LOGS: usize = 1024;

#[allow(clippy::too_many_arguments)]
fn resolve_sentinel_config_with<F>(
    mut lookup: F,
    default_config_dir: &Path,
    legacy_muobserve_config_dir: &Path,
    legacy_musentinel_config_dir: &Path,
    default_state_dir: &Path,
    default_ckpt_path: &Path,
    legacy_muobserve_ckpt_path: &Path,
    legacy_musentinel_ckpt_path: &Path,
) -> SentinelConfig
where
    F: FnMut(&str) -> Option<String>,
{
    let mut cfg = SentinelConfig::from_env_with(&mut lookup);

    if env_var_first_with(
        &[
            "MU_OBSERVABLE_SENTINEL_CONFIG_DIR",
            "MUSENTINEL_CONFIG_DIR",
            "MUOBSERVE_SENTINEL_CONFIG_DIR",
            "MUOBSERVE_CONFIG_DIR",
        ],
        &mut lookup,
    )
    .is_none()
    {
        cfg.config_dir = resolve_preferred_path_chain(
            default_config_dir,
            &[legacy_muobserve_config_dir, legacy_musentinel_config_dir],
        );
    }

    if cfg.kmsg_checkpoint_path.is_none() {
        if default_ckpt_path.exists() || default_state_dir.exists() {
            cfg.kmsg_checkpoint_path = Some(default_ckpt_path.to_path_buf());
        } else if legacy_muobserve_ckpt_path.exists() {
            cfg.kmsg_checkpoint_path = Some(legacy_muobserve_ckpt_path.to_path_buf());
        } else if legacy_musentinel_ckpt_path.exists() {
            cfg.kmsg_checkpoint_path = Some(legacy_musentinel_ckpt_path.to_path_buf());
        }
    }

    cfg
}

fn resolve_sentinel_config() -> SentinelConfig {
    resolve_sentinel_config_with(
        |k| std::env::var(k).ok(),
        Path::new(DEFAULT_SENTINEL_CONFIG_DIR),
        Path::new(LEGACY_SENTINEL_MUOBSERVE_CONFIG_DIR),
        Path::new(LEGACY_SENTINEL_MUSENTINEL_CONFIG_DIR),
        Path::new(DEFAULT_SENTINEL_STATE_DIR),
        Path::new(DEFAULT_SENTINEL_CHECKPOINT_PATH),
        Path::new(LEGACY_SENTINEL_MUOBSERVE_CHECKPOINT_PATH),
        Path::new(LEGACY_SENTINEL_CHECKPOINT_PATH),
    )
}

fn ingest_kmsg_batch(
    collector: &mut HostSentinelCollector,
    batch: &str,
    pending: &mut Vec<OtelLogEntry>,
) {
    let mut ingested = collector.ingest_kmsg_lines(batch);
    if pending.len() < MAX_PENDING_KMSG_LOGS {
        let remaining = MAX_PENDING_KMSG_LOGS - pending.len();
        ingested.truncate(remaining);
        pending.extend(ingested);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = resolve_sentinel_config();
    let sandbox_cfg = SentinelSandboxConfig {
        node_id: cfg.node_id.clone(),
        arch: cfg.arch.clone(),
        config_dir: cfg.config_dir.clone(),
        kmsg_checkpoint_path: cfg.kmsg_checkpoint_path.clone(),
        enforce_landlock_on_linux: cfg.enforce_landlock_on_linux,
        ..SentinelSandboxConfig::default()
    };
    let plan = apply_sentinel_startup_sandbox(&sandbox_cfg)?;
    tracing::info!(
        node_id = %cfg.node_id,
        arch = %cfg.arch,
        collector_url = %cfg.collector_url,
        poll_secs = cfg.poll_interval.as_secs(),
        kmsg_seek_to_tail = cfg.kmsg_seek_to_tail,
        landlock_rules = plan.landlock_rules.len(),
        "mu-observable-sentinel v{} initialized under MuIsolation KernelSandbox",
        env!("CARGO_PKG_VERSION")
    );

    if !should_serve_from_env() {
        return Ok(());
    }

    let emitter = CollectorArrowEmitter::new(&cfg.collector_url);

    // Background /dev/kmsg reader seeking to tail on startup; parsed lines flow through
    // HostSentinelCollector::ingest_kmsg_lines for monotonic sequence checkpoint tracking.
    let (kmsg_tx, mut kmsg_rx) = mpsc::channel(256);
    let kmsg_path = cfg.kmsg_path.clone();
    let kmsg_seek_to_tail = cfg.kmsg_seek_to_tail;
    tokio::spawn(stream_kmsg_lines(kmsg_path, kmsg_seek_to_tail, kmsg_tx));

    let poll_ms = cfg.poll_interval.as_millis() as u64;
    let mut interval = tokio::time::interval(cfg.poll_interval);
    let mut collector = HostSentinelCollector::new(cfg);
    let mut kmsg_closed = false;
    let mut pending_kmsg_logs = Vec::new();

    loop {
        tokio::select! {
            maybe_line = kmsg_rx.recv(), if !kmsg_closed => {
                match maybe_line {
                    Some(mut batch) => {
                        while let Ok(next_line) = kmsg_rx.try_recv() {
                            batch.push('\n');
                            batch.push_str(&next_line);
                        }
                        ingest_kmsg_batch(&mut collector, &batch, &mut pending_kmsg_logs);
                    }
                    None => {
                        kmsg_closed = true;
                    }
                }
            }
            _ = interval.tick() => {
                let mut batch = String::new();
                while let Ok(line) = kmsg_rx.try_recv() {
                    if !batch.is_empty() {
                        batch.push('\n');
                    }
                    batch.push_str(&line);
                }
                if !batch.is_empty() {
                    ingest_kmsg_batch(&mut collector, &batch, &mut pending_kmsg_logs);
                }

                let (metrics, mut logs) = collector.sweep_once(poll_ms);
                logs.append(&mut pending_kmsg_logs);
                if let Err(e) = emitter.emit_metrics(&metrics).await {
                    tracing::warn!(error = %e, "Failed to emit host metrics to MuObserve-collector");
                }
                if let Err(e) = emitter.emit_logs(&logs).await {
                    tracing::warn!(error = %e, "Failed to emit host logs to MuObserve-collector");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received shutdown signal; exiting mu-observable-sentinel");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_sentinel_on_disk_fallback_for_config_dir_and_kmsg_checkpoint() {
        let dir = tempdir().expect("tempdir");
        let canon_cfg = dir.path().join("etc/mu-observable-sentinel");
        let legacy_muobserve_cfg = dir.path().join("etc/muobserve-sentinel");
        let legacy_musentinel_cfg = dir.path().join("etc/musentinel");
        let canon_state = dir.path().join("var/lib/mu-observable-sentinel");
        let canon_ckpt = canon_state.join("kmsg.ckpt");
        let legacy_muobserve_ckpt = dir.path().join("var/lib/muobserve-sentinel/kmsg.ckpt");
        let legacy_musentinel_ckpt = dir.path().join("var/lib/musentinel/kmsg.ckpt");

        let empty: HashMap<&str, &str> = HashMap::new();

        // 1. Neither exists -> canonical config_dir and None checkpoint
        let cfg_none = resolve_sentinel_config_with(
            |k| empty.get(k).map(|v| (*v).to_string()),
            &canon_cfg,
            &legacy_muobserve_cfg,
            &legacy_musentinel_cfg,
            &canon_state,
            &canon_ckpt,
            &legacy_muobserve_ckpt,
            &legacy_musentinel_ckpt,
        );
        assert_eq!(cfg_none.config_dir, canon_cfg);
        assert!(cfg_none.kmsg_checkpoint_path.is_none());

        // 2. Only legacy /etc/musentinel and /var/lib/musentinel/kmsg.ckpt exist -> fallbacks used
        std::fs::create_dir_all(&legacy_musentinel_cfg).unwrap();
        std::fs::create_dir_all(legacy_musentinel_ckpt.parent().unwrap()).unwrap();
        std::fs::write(&legacy_musentinel_ckpt, "10\n").unwrap();

        let cfg_legacy_musentinel = resolve_sentinel_config_with(
            |k| empty.get(k).map(|v| (*v).to_string()),
            &canon_cfg,
            &legacy_muobserve_cfg,
            &legacy_musentinel_cfg,
            &canon_state,
            &canon_ckpt,
            &legacy_muobserve_ckpt,
            &legacy_musentinel_ckpt,
        );
        assert_eq!(cfg_legacy_musentinel.config_dir, legacy_musentinel_cfg);
        assert_eq!(
            cfg_legacy_musentinel.kmsg_checkpoint_path,
            Some(legacy_musentinel_ckpt.clone())
        );

        // 3. /etc/muobserve-sentinel takes precedence over /etc/musentinel when canonical is absent
        std::fs::create_dir_all(&legacy_muobserve_cfg).unwrap();
        let cfg_legacy_muobserve = resolve_sentinel_config_with(
            |k| empty.get(k).map(|v| (*v).to_string()),
            &canon_cfg,
            &legacy_muobserve_cfg,
            &legacy_musentinel_cfg,
            &canon_state,
            &canon_ckpt,
            &legacy_muobserve_ckpt,
            &legacy_musentinel_ckpt,
        );
        assert_eq!(cfg_legacy_muobserve.config_dir, legacy_muobserve_cfg);

        // 4. Canonical directories exist -> canonical paths win
        std::fs::create_dir_all(&canon_cfg).unwrap();
        std::fs::create_dir_all(&canon_state).unwrap();
        let cfg_canon = resolve_sentinel_config_with(
            |k| empty.get(k).map(|v| (*v).to_string()),
            &canon_cfg,
            &legacy_muobserve_cfg,
            &legacy_musentinel_cfg,
            &canon_state,
            &canon_ckpt,
            &legacy_muobserve_ckpt,
            &legacy_musentinel_ckpt,
        );
        assert_eq!(cfg_canon.config_dir, canon_cfg);
        assert_eq!(cfg_canon.kmsg_checkpoint_path, Some(canon_ckpt.clone()));

        // 5. Explicit env overrides win over disk paths
        let env: HashMap<&str, &str> = HashMap::from([
            ("MU_OBSERVABLE_SENTINEL_CONFIG_DIR", "/custom/etc/sentinel"),
            (
                "MU_OBSERVABLE_SENTINEL_KMSG_CHECKPOINT_PATH",
                "/custom/var/kmsg.ckpt",
            ),
        ]);
        let cfg_override = resolve_sentinel_config_with(
            |k| env.get(k).map(|v| (*v).to_string()),
            &canon_cfg,
            &legacy_muobserve_cfg,
            &legacy_musentinel_cfg,
            &canon_state,
            &canon_ckpt,
            &legacy_muobserve_ckpt,
            &legacy_musentinel_ckpt,
        );
        assert_eq!(
            cfg_override.config_dir,
            PathBuf::from("/custom/etc/sentinel")
        );
        assert_eq!(
            cfg_override.kmsg_checkpoint_path,
            Some(PathBuf::from("/custom/var/kmsg.ckpt"))
        );
    }
}
