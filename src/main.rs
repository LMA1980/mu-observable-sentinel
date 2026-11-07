use mu_observable_sentinel::{
    apply_sentinel_startup_sandbox, now_unix_nano, parse_kmsg_line, CollectorArrowEmitter,
    HostSentinelCollector, SentinelConfig, SentinelSandboxConfig,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = SentinelConfig::from_env();
    let sandbox_cfg = SentinelSandboxConfig {
        node_id: cfg.node_id.clone(),
        arch: cfg.arch.clone(),
        enforce_landlock_on_linux: cfg.enforce_landlock_on_linux,
        ..SentinelSandboxConfig::default()
    };
    let plan = apply_sentinel_startup_sandbox(&sandbox_cfg)?;
    tracing::info!(
        node_id = %cfg.node_id,
        arch = %cfg.arch,
        collector_url = %cfg.collector_url,
        poll_secs = cfg.poll_interval.as_secs(),
        landlock_rules = plan.landlock_rules.len(),
        "mu-observable-sentinel v{} initialized under MuIsolation KernelSandbox",
        env!("CARGO_PKG_VERSION")
    );

    if !std::env::var("MUSENTINEL_SERVE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return Ok(());
    }

    let emitter = CollectorArrowEmitter::new(&cfg.collector_url);

    // Optional background reader for /dev/kmsg streaming
    let (kmsg_tx, mut kmsg_rx) = mpsc::channel(256);
    let kmsg_path = cfg.kmsg_path.clone();
    let kmsg_node_id = cfg.node_id.clone();
    tokio::spawn(async move {
        if let Ok(file) = tokio::fs::File::open(&kmsg_path).await {
            let mut lines = BufReader::new(file).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(Some(rec)) = parse_kmsg_line(&line) {
                    if rec.is_actionable() {
                        let log = rec.to_otel_log(&kmsg_node_id, now_unix_nano());
                        if kmsg_tx.send(log).await.is_err() {
                            break;
                        }
                    }
                }
            }
        } else {
            tracing::debug!(path = %kmsg_path.display(), "/dev/kmsg stream unavailable; continuing with procfs/sysfs sweeps");
        }
    });

    let poll_ms = cfg.poll_interval.as_millis() as u64;
    let mut interval = tokio::time::interval(cfg.poll_interval);
    let mut collector = HostSentinelCollector::new(cfg);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let (metrics, mut logs) = collector.sweep_once(poll_ms);
                while let Ok(klog) = kmsg_rx.try_recv() {
                    logs.push(klog);
                }
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
