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
    SentinelConfig, DEFAULT_ALERT_COOLDOWN_SECS, DEFAULT_COLLECTOR_URL, DEFAULT_DISK_AWAIT_WARN_MS,
    DEFAULT_KMSG_SEEK_TO_TAIL, DEFAULT_POLL_INTERVAL_SECS, DEFAULT_PSI_CRITICAL_PCT,
    DEFAULT_PSI_PERSISTENCE_SAMPLES, DEFAULT_PSI_WARN_PCT, DEFAULT_RUNAWAY_SECS,
};
pub use emitter::CollectorArrowEmitter;
pub use error::SentinelError;
pub use kmsg::{
    classify_kmsg_body, load_kmsg_checkpoint, open_kmsg_reader, parse_kmsg_line, read_boot_id,
    save_kmsg_checkpoint, stream_kmsg_lines, KmsgCategory, KmsgCheckpoint, KmsgRecord,
};
pub use process_watchdog::{
    is_active_runaway_state, is_watched_build_comm, parse_proc_stat_starttime, parse_uptime_ticks,
    runaway_processes_to_logs, scan_runaway_processes, RunawayAlertTracker, RunawayProcessInfo,
    DEFAULT_CLK_TCK,
};
pub use psi::{
    build_psi_dstate_alert, is_kernel_thread, is_kworker_comm, parse_proc_stat_details,
    parse_proc_stat_state, parse_psi_content, psi_snapshot_to_metrics, scan_dstate_processes,
    BlockedProcessInfo, ProcStatDetails, PsiAlertTracker, PsiResourceSnapshot, PsiSweepSample,
    PsiWindow, PF_KTHREAD,
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

/// Stateful host infrastructure collector that maintains `/proc/diskstats` deltas,
/// PSI/D-state persistence & cooldown state, `(pid, starttime_ticks)` runaway deduplication,
/// and `/dev/kmsg` sequence checkpoint state across sweeps.
#[derive(Debug)]
pub struct HostSentinelCollector {
    cfg: SentinelConfig,
    prev_diskstats: HashMap<String, DiskStatsCounter>,
    psi_tracker: PsiAlertTracker,
    runaway_tracker: RunawayAlertTracker,
    elapsed_total_ms: u64,
    last_kmsg_seq: Option<u64>,
    boot_id: Option<String>,
}

impl HostSentinelCollector {
    /// Creates a new [`HostSentinelCollector`] from `cfg`.
    #[must_use]
    pub fn new(cfg: SentinelConfig) -> Self {
        let boot_id = read_boot_id(&cfg.proc_root);
        let last_kmsg_seq = cfg
            .kmsg_checkpoint_path
            .as_deref()
            .and_then(|path| load_kmsg_checkpoint(path, boot_id.as_deref()));
        let cooldown_ms = cfg.alert_cooldown_secs.saturating_mul(1_000);
        Self {
            psi_tracker: PsiAlertTracker::new(
                cfg.psi_persistence_samples,
                DEFAULT_PSI_CRITICAL_PCT,
                cooldown_ms,
            ),
            runaway_tracker: RunawayAlertTracker::new(),
            elapsed_total_ms: 0,
            last_kmsg_seq,
            boot_id,
            prev_diskstats: HashMap::new(),
            cfg,
        }
    }

    /// Returns the highest `/dev/kmsg` sequence number ingested so far, if any.
    #[must_use]
    pub const fn last_kmsg_seq(&self) -> Option<u64> {
        self.last_kmsg_seq
    }

    /// Executes a single deterministic sweep over `proc_root` and `sys_root`, returning
    /// `(Vec<OtelMetricEntry>, Vec<OtelLogEntry>)`.
    pub fn sweep_once(&mut self, elapsed_ms: u64) -> (Vec<OtelMetricEntry>, Vec<OtelLogEntry>) {
        self.elapsed_total_ms = self.elapsed_total_ms.saturating_add(elapsed_ms);
        let ts_nano = now_unix_nano();
        let mut metrics = Vec::new();
        let mut logs = Vec::new();

        // 1. PSI (/proc/pressure/{io,memory,cpu}) + D-state task inspection (persistence + cooldown)
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
        if let Some(alert) = self.psi_tracker.observe(&PsiSweepSample {
            io_snap: io_psi.as_ref(),
            mem_snap: mem_psi.as_ref(),
            blocked: &blocked,
            warn_pct: self.cfg.psi_warn_pct,
            node_id: &self.cfg.node_id,
            elapsed_total_ms: self.elapsed_total_ms,
            now_unix_nano: ts_nano,
        }) {
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

        // 5. Runaway process watchdog (/proc/[pid]/stat) with (pid, starttime_ticks) deduplication
        let cooldown_ms = self.cfg.alert_cooldown_secs.saturating_mul(1_000);
        let runaways = scan_runaway_processes(&self.cfg.proc_root, self.cfg.runaway_process_secs);
        let due_runaways =
            self.runaway_tracker
                .filter_due(&runaways, self.elapsed_total_ms, cooldown_ms);
        logs.extend(runaway_processes_to_logs(
            &due_runaways,
            &self.cfg.node_id,
            ts_nano,
        ));

        (metrics, logs)
    }

    /// Ingests a batch of `/dev/kmsg` text lines and returns new actionable [`OtelLogEntry`]
    /// records with `seq > self.last_kmsg_seq`, optionally persisting the updated checkpoint.
    pub fn ingest_kmsg_lines(&mut self, content: &str) -> Vec<OtelLogEntry> {
        let prev_seq = self.last_kmsg_seq;
        let ts_nano = now_unix_nano();
        let mut out = Vec::new();
        for line in content.lines() {
            if let Ok(Some(rec)) = parse_kmsg_line(line) {
                let is_new = self.last_kmsg_seq.is_none_or(|last| rec.seq > last);
                if is_new {
                    self.last_kmsg_seq = Some(rec.seq);
                    if rec.is_actionable() {
                        out.push(rec.to_otel_log(&self.cfg.node_id, ts_nano));
                    }
                }
            }
        }
        if self.last_kmsg_seq != prev_seq {
            if let (Some(ckpt_path), Some(seq)) =
                (&self.cfg.kmsg_checkpoint_path, self.last_kmsg_seq)
            {
                if let Err(err) = save_kmsg_checkpoint(ckpt_path, seq, self.boot_id.as_deref()) {
                    tracing::warn!(
                        path = %ckpt_path.display(),
                        error = %err,
                        "Failed to persist /dev/kmsg sequence checkpoint"
                    );
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
        // Sweep 1: Btrfs error alerts immediately, while psi_dstate awaits 3-sweep persistence
        assert!(!l1.iter().any(|l| l.attributes_json.contains("psi_dstate")));
        assert!(l1
            .iter()
            .any(|l| l.attributes_json.contains("btrfs_errors")));

        // Second sweep with high disk write latency (still < 3 sweeps for psi_dstate)
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
        assert!(!l2.iter().any(|l| l.attributes_json.contains("psi_dstate")));

        // Third sweep reaches 3 consecutive D-state / PSI ticks and emits ERROR
        let (_m3, l3) = collector.sweep_once(5_000);
        let psi_err = l3
            .iter()
            .find(|l| l.attributes_json.contains("psi_dstate"))
            .expect("3rd consecutive sweep emits psi_dstate");
        assert_eq!(psi_err.severity_text, "ERROR");

        // Fourth sweep within 300s cooldown suppresses duplicate psi_dstate alert
        let (_m4, l4) = collector.sweep_once(5_000);
        assert!(!l4.iter().any(|l| l.attributes_json.contains("psi_dstate")));

        // Kmsg ingestion
        let kmsg_logs = collector.ingest_kmsg_lines(
            "3,901,1000200,-;critical target error, dev sdd, sector 2099200 op 0x3:(DISCARD)\n",
        );
        assert_eq!(kmsg_logs.len(), 1);
        assert_eq!(kmsg_logs[0].severity_text, "ERROR");
        assert_eq!(collector.last_kmsg_seq(), Some(901));
    }

    #[test]
    fn test_collector_filters_kworkers_and_dedups_runaways_across_sweeps() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proc_root = tmp.path().join("proc");
        let sys_root = tmp.path().join("sys");

        std::fs::create_dir_all(proc_root.join("pressure")).unwrap();
        std::fs::create_dir_all(proc_root.join("net")).unwrap();
        std::fs::create_dir_all(proc_root.join("105")).unwrap();
        std::fs::create_dir_all(proc_root.join("201")).unwrap();
        std::fs::create_dir_all(proc_root.join("202")).unwrap();
        std::fs::create_dir_all(proc_root.join("203")).unwrap();
        std::fs::create_dir_all(&sys_root).unwrap();

        std::fs::write(
            proc_root.join("pressure").join("io"),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        .unwrap();
        // kworker in D-state with 0.00% PSI -> must never alert
        std::fs::write(
            proc_root.join("105").join("stat"),
            "105 (kworker/u16:2+ixgbe) D 2 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n",
        )
        .unwrap();
        std::fs::write(proc_root.join("105").join("wchan"), "0\n").unwrap();

        // Uptime 5000s = 500_000 ticks
        std::fs::write(proc_root.join("uptime"), "5000.00 4000.00\n").unwrap();
        // Sleeping cargo-llvm-cov wrapper past 2100s -> ignored
        std::fs::write(
            proc_root.join("201").join("stat"),
            "201 (cargo-llvm-cov) S 1 201 201 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 100000 0 0\n",
        )
        .unwrap();
        // Active miri at exactly 1800s (start = 320_000 ticks) -> ignored under 2100s default
        std::fs::write(
            proc_root.join("202").join("stat"),
            "202 (miri) R 1 202 202 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 320000 0 0\n",
        )
        .unwrap();
        // Active rustc at 2200s (start = 280_000 ticks) -> alerts once and deduplicates
        std::fs::write(
            proc_root.join("203").join("stat"),
            "203 (rustc) R 1 203 203 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 280000 0 0\n",
        )
        .unwrap();

        let cfg = SentinelConfig {
            node_id: "node-a".to_string(),
            arch: "x86_64".to_string(),
            proc_root,
            sys_root,
            ..SentinelConfig::default()
        };
        let mut collector = HostSentinelCollector::new(cfg);

        // Sweep 1: single runaway alert for pid 203, zero psi_dstate alerts
        let (_, l1) = collector.sweep_once(5_000);
        let r1: Vec<_> = l1
            .iter()
            .filter(|l| l.attributes_json.contains("runaway_process"))
            .collect();
        assert_eq!(r1.len(), 1);
        assert!(r1[0].body.contains("comm=rustc pid=203"));
        assert!(!l1.iter().any(|l| l.attributes_json.contains("psi_dstate")));

        // Sweeps 2..=4: kworker still silent, pid 203 deduplicated during 300s cooldown
        for _ in 0..3 {
            let (_, logs) = collector.sweep_once(5_000);
            assert!(!logs
                .iter()
                .any(|l| l.attributes_json.contains("psi_dstate")));
            assert!(!logs
                .iter()
                .any(|l| l.attributes_json.contains("runaway_process")));
        }
    }

    #[test]
    fn test_collector_kmsg_checkpoint_prevents_replay_across_restarts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proc_root = tmp.path().join("proc");
        let boot_dir = proc_root.join("sys/kernel/random");
        std::fs::create_dir_all(&boot_dir).unwrap();
        std::fs::write(boot_dir.join("boot_id"), "boot-uuid-1\n").unwrap();

        let ckpt_path = tmp.path().join("state").join("kmsg.ckpt");
        let cfg = SentinelConfig {
            node_id: "node-a".to_string(),
            arch: "x86_64".to_string(),
            proc_root: proc_root.clone(),
            sys_root: tmp.path().join("sys"),
            kmsg_checkpoint_path: Some(ckpt_path.clone()),
            ..SentinelConfig::default()
        };

        let mut first = HostSentinelCollector::new(cfg.clone());
        let boot_lines = concat!(
            "3,0,100,-;ima: Error Communicating to TPM chip\n",
            "4,10,500,-;invoked oom-killer: gfp_mask=0x100cca\n",
            "6,11,600,-;routine info line\n",
        );
        let first_logs = first.ingest_kmsg_lines(boot_lines);
        assert_eq!(first_logs.len(), 2);
        assert_eq!(first.last_kmsg_seq(), Some(11));
        drop(first);

        // Simulated restart with same boot_id and checkpoint must skip seq <= 11
        let mut restarted = HostSentinelCollector::new(cfg);
        assert_eq!(restarted.last_kmsg_seq(), Some(11));
        let replay_plus_new = format!(
            "{boot_lines}3,12,900,-;critical target error, dev sda, sector 10 op 0x3:(DISCARD)\n"
        );
        let restart_logs = restarted.ingest_kmsg_lines(&replay_plus_new);
        assert_eq!(restart_logs.len(), 1);
        assert!(restart_logs[0].body.contains("critical target error"));
        assert_eq!(restarted.last_kmsg_seq(), Some(12));
    }
}
