//! `mu-observable-sentinel`: Sandboxed host infrastructure and kernel telemetry sentinel daemon (`M1`).
//!
//! Bridges host-level OS signals into `MuObserve-collector` (`http://127.0.0.1:4318/v1/{logs,metrics}`)
//! using native Apache Arrow IPC streams (`mu-observable-ipc`):
//! - `/dev/kmsg` kernel ring-buffer anomaly parser and classifier (`src/kmsg.rs`)
//! - `/proc/pressure/{io,memory,cpu}` PSI stall metrics and `D`-state task inspector (`src/psi.rs`)
//! - `/proc/diskstats` per-device `await` latency and `/sys/fs/btrfs` device error counters (`src/storage.rs`)
//! - `/proc/net/unix` systemd journal socket backpressure and `/proc/meminfo` memory headroom (`src/systemd_socket.rs`)
//! - `/proc/[pid]/stat` runaway build/test process watchdog (`src/process_watchdog.rs`)
//! - `MuIsolation` `KernelSandbox` read-only startup confinement (`src/sandbox.rs`)

#![forbid(unsafe_code)]

pub mod config;
pub mod emitter;
pub mod error;
pub mod kmsg;
pub mod process_watchdog;
pub mod psi;
pub mod sandbox;
pub mod storage;
pub mod systemd_socket;

pub use config::{
    SentinelConfig, DEFAULT_COLLECTOR_URL, DEFAULT_DISK_AWAIT_WARN_MS, DEFAULT_POLL_INTERVAL_SECS,
    DEFAULT_PSI_WARN_PCT, DEFAULT_RUNAWAY_SECS,
};
pub use emitter::CollectorArrowEmitter;
pub use error::SentinelError;
pub use kmsg::{classify_kmsg_body, parse_kmsg_line, KmsgCategory, KmsgRecord};
pub use process_watchdog::{
    is_watched_build_comm, parse_proc_stat_starttime, parse_uptime_ticks,
    runaway_processes_to_logs, scan_runaway_processes, RunawayProcessInfo, DEFAULT_CLK_TCK,
};
pub use psi::{
    build_psi_dstate_alert, parse_proc_stat_state, parse_psi_content, psi_snapshot_to_metrics,
    scan_dstate_processes, BlockedProcessInfo, PsiResourceSnapshot, PsiWindow,
};
pub use sandbox::{
    apply_sentinel_startup_sandbox, build_sentinel_sandbox_policy, SentinelSandboxConfig,
    DEFAULT_SENTINEL_CONFIG_DIR,
};
pub use storage::{
    btrfs_errors_to_telemetry, compute_disk_latency_deltas, disk_deltas_to_telemetry,
    is_monitored_whole_disk, parse_btrfs_error_stats, parse_diskstats, scan_btrfs_error_stats,
    BtrfsDeviceErrors, DiskLatencyDelta, DiskStatsCounter,
};
pub use systemd_socket::{
    count_systemd_journal_sockets, meminfo_to_telemetry, parse_meminfo, HostMeminfoSnapshot,
};

use mu_observable_ipc::{OtelLogEntry, OtelMetricEntry};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current wall-clock time in nanoseconds since the Unix epoch.
#[must_use]
pub fn now_unix_nano() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Stateful host infrastructure collector that maintains the previous `/proc/diskstats`
/// and `/dev/kmsg` sequence state across sweeps.
#[derive(Debug)]
pub struct HostSentinelCollector {
    cfg: SentinelConfig,
    prev_diskstats: HashMap<String, DiskStatsCounter>,
    last_kmsg_seq: u64,
}

impl HostSentinelCollector {
    /// Creates a new [`HostSentinelCollector`] from `cfg`.
    #[must_use]
    pub fn new(cfg: SentinelConfig) -> Self {
        Self {
            cfg,
            prev_diskstats: HashMap::new(),
            last_kmsg_seq: 0,
        }
    }

    /// Executes a single deterministic sweep over `proc_root` and `sys_root`, returning
    /// `(Vec<OtelMetricEntry>, Vec<OtelLogEntry>)`.
    pub fn sweep_once(&mut self, elapsed_ms: u64) -> (Vec<OtelMetricEntry>, Vec<OtelLogEntry>) {
        let ts_nano = now_unix_nano();
        let mut metrics = Vec::new();
        let mut logs = Vec::new();

        // 1. PSI (/proc/pressure/{io,memory,cpu}) + D-state task inspection
        let mut io_psi = None;
        let mut mem_psi = None;
        for resource in ["io", "memory", "cpu"] {
            let path = self.cfg.proc_root.join("pressure").join(resource);
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(snap) = parse_psi_content(resource, &content) {
                    metrics.extend(psi_snapshot_to_metrics(
                        resource,
                        &snap,
                        &self.cfg.node_id,
                        &self.cfg.arch,
                        ts_nano,
                    ));
                    if resource == "io" {
                        io_psi = Some(snap);
                    } else if resource == "memory" {
                        mem_psi = Some(snap);
                    }
                }
            }
        }
        let blocked = scan_dstate_processes(&self.cfg.proc_root);
        if let Some(alert) = build_psi_dstate_alert(
            io_psi.as_ref(),
            mem_psi.as_ref(),
            &blocked,
            self.cfg.psi_warn_pct,
            &self.cfg.node_id,
            ts_nano,
        ) {
            logs.push(alert);
        }

        // 2. Block I/O latency (/proc/diskstats)
        if let Ok(disk_raw) = std::fs::read_to_string(self.cfg.proc_root.join("diskstats")) {
            if let Ok(curr) = parse_diskstats(&disk_raw) {
                if !self.prev_diskstats.is_empty() {
                    let deltas =
                        compute_disk_latency_deltas(&self.prev_diskstats, &curr, elapsed_ms);
                    let (m, l) = disk_deltas_to_telemetry(
                        &deltas,
                        self.cfg.disk_await_warn_ms,
                        &self.cfg.node_id,
                        &self.cfg.arch,
                        ts_nano,
                    );
                    metrics.extend(m);
                    logs.extend(l);
                }
                self.prev_diskstats = curr;
            }
        }

        // 3. Btrfs device error counters (/sys/fs/btrfs/*/devinfo/*/error_stats)
        let btrfs_items = scan_btrfs_error_stats(&self.cfg.sys_root);
        let (btrfs_m, btrfs_l) =
            btrfs_errors_to_telemetry(&btrfs_items, &self.cfg.node_id, &self.cfg.arch, ts_nano);
        metrics.extend(btrfs_m);
        logs.extend(btrfs_l);

        // 4. Memory headroom (/proc/meminfo) & systemd journal sockets (/proc/net/unix)
        let journal_sockets = std::fs::read_to_string(self.cfg.proc_root.join("net").join("unix"))
            .map(|s| count_systemd_journal_sockets(&s))
            .unwrap_or(0);
        if let Ok(mem_raw) = std::fs::read_to_string(self.cfg.proc_root.join("meminfo")) {
            if let Ok(mem_snap) = parse_meminfo(&mem_raw) {
                let (mem_m, mem_l) = meminfo_to_telemetry(
                    &mem_snap,
                    journal_sockets,
                    &self.cfg.node_id,
                    &self.cfg.arch,
                    ts_nano,
                );
                metrics.extend(mem_m);
                logs.extend(mem_l);
            }
        }

        // 5. Runaway process watchdog (/proc/[pid]/stat)
        let runaways = scan_runaway_processes(&self.cfg.proc_root, self.cfg.runaway_process_secs);
        logs.extend(runaway_processes_to_logs(
            &runaways,
            &self.cfg.node_id,
            ts_nano,
        ));

        (metrics, logs)
    }

    ///Ingests a batch of `/dev/kmsg` text lines and returns new actionable [`OtelLogEntry`] records
    /// with `seq > self.last_kmsg_seq`.
    pub fn ingest_kmsg_lines(&mut self, content: &str) -> Vec<OtelLogEntry> {
        let ts_nano = now_unix_nano();
        let mut out = Vec::new();
        for line in content.lines() {
            if let Ok(Some(rec)) = parse_kmsg_line(line) {
                if rec.seq > self.last_kmsg_seq {
                    self.last_kmsg_seq = rec.seq;
                    if rec.is_actionable() {
                        out.push(rec.to_otel_log(&self.cfg.node_id, ts_nano));
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_host_sweep_end_to_end() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proc_root = tmp.path().join("proc");
        let sys_root = tmp.path().join("sys");

        std::fs::create_dir_all(proc_root.join("pressure")).unwrap();
        std::fs::create_dir_all(proc_root.join("net")).unwrap();
        std::fs::create_dir_all(proc_root.join("412")).unwrap();
        std::fs::create_dir_all(
            sys_root
                .join("fs")
                .join("btrfs")
                .join("uuid-1")
                .join("devinfo")
                .join("1"),
        )
        .unwrap();

        std::fs::write(
            proc_root.join("pressure").join("io"),
            "some avg10=22.50 avg60=10.00 avg300=2.00 total=1000\nfull avg10=15.00 avg60=5.00 avg300=1.00 total=800\n",
        )
        .unwrap();
        std::fs::write(
            proc_root.join("412").join("stat"),
            "412 (systemd-journal) D 1 412 412 0 -1 4194560 1204 0 12 0 14 28 0 0 20 0 1 0 100 123456 789\n",
        )
        .unwrap();
        std::fs::write(
            proc_root.join("412").join("wchan"),
            "btrfs_commit_transaction\n",
        )
        .unwrap();
        std::fs::write(
            proc_root.join("diskstats"),
            "   8       48 sdd 100 0 800 500 200 0 1600 1000 0 800 1500 0 0 0 0 0 0\n",
        )
        .unwrap();
        std::fs::write(
            proc_root.join("meminfo"),
            "MemTotal:       16384000 kB\nMemAvailable:   12000000 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\nDirty:               512 kB\nWriteback:             0 kB\n",
        )
        .unwrap();
        std::fs::write(
            proc_root.join("net").join("unix"),
            "00000000: 00000002 00000000 00010000 0002 01 12345 /run/systemd/journal/dev-log\n",
        )
        .unwrap();
        std::fs::write(proc_root.join("uptime"), "10000.00 9000.00\n").unwrap();
        std::fs::write(
            sys_root
                .join("fs")
                .join("btrfs")
                .join("uuid-1")
                .join("devinfo")
                .join("1")
                .join("error_stats"),
            "write_io_errs 1\nread_io_errs 0\nflush_io_errs 0\ncorruption_errs 0\ngeneration_errs 0\n",
        )
        .unwrap();

        let cfg = SentinelConfig {
            node_id: "node-a".to_string(),
            arch: "x86_64".to_string(),
            proc_root: proc_root.clone(),
            sys_root,
            ..SentinelConfig::default()
        };

        let mut collector = HostSentinelCollector::new(cfg);
        let (m1, l1) = collector.sweep_once(5_000);
        assert!(!m1.is_empty());
        // Should contain PSI D-state alert and Btrfs error alert
        assert!(l1.iter().any(|l| l.attributes_json.contains("psi_dstate")));
        assert!(l1
            .iter()
            .any(|l| l.attributes_json.contains("btrfs_errors")));

        // Second sweep with high disk write latency
        std::fs::write(
            proc_root.join("diskstats"),
            "   8       48 sdd 110 0 880 600 210 0 1680 9000 2 5800 9600 0 0 0 0 0 0\n",
        )
        .unwrap();
        let (m2, l2) = collector.sweep_once(5_000);
        assert!(m2
            .iter()
            .any(|m| m.metric_name == "host.disk.write_await_ms"));
        assert!(l2
            .iter()
            .any(|l| l.attributes_json.contains("disk_latency")));

        // Kmsg ingestion
        let kmsg_logs = collector.ingest_kmsg_lines(
            "3,901,1000200,-;critical target error, dev sdd, sector 2099200 op 0x3:(DISCARD)\n",
        );
        assert_eq!(kmsg_logs.len(), 1);
        assert_eq!(kmsg_logs[0].severity_text, "ERROR");
    }
}
