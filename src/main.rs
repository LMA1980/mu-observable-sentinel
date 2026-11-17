use mu_observable_ipc::OtelLogEntry;
use mu_observable_sentinel::{
    apply_sentinel_startup_sandbox, stream_kmsg_lines, CollectorArrowEmitter,
    HostSentinelCollector, SentinelConfig, SentinelSandboxConfig,
};
use tokio::sync::mpsc;

const MAX_PENDING_KMSG_LOGS: usize = 1024;

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

    let cfg = SentinelConfig::from_env();
    let sandbox_cfg = SentinelSandboxConfig {
        node_id: cfg.node_id.clone(),
        arch: cfg.arch.clone(),
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

    if !std::env::var("MUSENTINEL_SERVE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
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
