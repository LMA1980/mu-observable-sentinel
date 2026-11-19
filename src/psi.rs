//! Linux Pressure Stall Information (`/proc/pressure/{io,memory,cpu}`) and
//! uninterruptible sleep (`D`-state / `TASK_UNINTERRUPTIBLE`) task inspector.

use crate::config::{
    DEFAULT_PSI_CRITICAL_PCT, DEFAULT_PSI_PERSISTENCE_SAMPLES, SENTINEL_SERVICE_NAME,
};
use crate::error::SentinelError;
use mu_observable_ipc::{OtelLogEntry, OtelMetricEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Linux `include/linux/sched.h` task flag identifying kernel threads (`kthreadd`, `kworker/*`).
pub const PF_KTHREAD: u64 = 0x0020_0000;

/// Parsed line from `/proc/pressure/<resource>` (`some` or `full`).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PsiWindow {
    /// 10-second moving average stall percentage (`0.0..=100.0`).
    pub avg10: f64,
    /// 60-second moving average stall percentage (`0.0..=100.0`).
    pub avg60: f64,
    /// 300-second moving average stall percentage (`0.0..=100.0`).
    pub avg300: f64,
    /// Cumulative stall time in microseconds.
    pub total_usec: u64,
}

/// Complete PSI snapshot for a single resource (`io`, `memory`, or `cpu`).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PsiResourceSnapshot {
    pub some: PsiWindow,
    pub full: Option<PsiWindow>,
}

/// Process blocked in uninterruptible sleep (`D` state) discovered in `/proc/[pid]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedProcessInfo {
    pub pid: u32,
    pub comm: String,
    pub wchan: String,
}

/// Parses the contents of `/proc/pressure/{io,memory,cpu}` into a [`PsiResourceSnapshot`].
pub fn parse_psi_content(
    resource_name: &str,
    content: &str,
) -> Result<PsiResourceSnapshot, SentinelError> {
    let mut some: Option<PsiWindow> = None;
    let mut full: Option<PsiWindow> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let kind = parts.next().ok_or_else(|| SentinelError::Parse {
            source_name: format!("/proc/pressure/{resource_name}"),
            detail: "empty PSI line".to_string(),
        })?;
        let mut avg10 = 0.0;
        let mut avg60 = 0.0;
        let mut avg300 = 0.0;
        let mut total_usec = 0_u64;

        for token in parts {
            if let Some((k, v)) = token.split_once('=') {
                match k {
                    "avg10" => {
                        avg10 = v.parse::<f64>().map_err(|e| SentinelError::Parse {
                            source_name: format!("/proc/pressure/{resource_name}"),
                            detail: format!("invalid avg10 '{v}': {e}"),
                        })?;
                    }
                    "avg60" => {
                        avg60 = v.parse::<f64>().map_err(|e| SentinelError::Parse {
                            source_name: format!("/proc/pressure/{resource_name}"),
                            detail: format!("invalid avg60 '{v}': {e}"),
                        })?;
                    }
                    "avg300" => {
                        avg300 = v.parse::<f64>().map_err(|e| SentinelError::Parse {
                            source_name: format!("/proc/pressure/{resource_name}"),
                            detail: format!("invalid avg300 '{v}': {e}"),
                        })?;
                    }
                    "total" => {
                        total_usec = v.parse::<u64>().map_err(|e| SentinelError::Parse {
                            source_name: format!("/proc/pressure/{resource_name}"),
                            detail: format!("invalid total '{v}': {e}"),
                        })?;
                    }
                    _ => {}
                }
            }
        }
        let window = PsiWindow {
            avg10,
            avg60,
            avg300,
            total_usec,
        };
        match kind {
            "some" => some = Some(window),
            "full" => full = Some(window),
            _ => {}
        }
    }

    let some = some.ok_or_else(|| SentinelError::Parse {
        source_name: format!("/proc/pressure/{resource_name}"),
        detail: "missing 'some' line".to_string(),
    })?;

    Ok(PsiResourceSnapshot { some, full })
}

/// Converts a [`PsiResourceSnapshot`] into [`OtelMetricEntry`] items.
#[must_use]
pub fn psi_snapshot_to_metrics(
    resource: &str,
    snap: &PsiResourceSnapshot,
    node_id: &str,
    arch: &str,
    now_unix_nano: i64,
) -> Vec<OtelMetricEntry> {
    let attrs = serde_json::json!({
        "subsystem": "psi",
        "resource": resource,
    })
    .to_string();

    let mut out = vec![
        OtelMetricEntry {
            timestamp_unix_nano: now_unix_nano,
            service_name: SENTINEL_SERVICE_NAME.to_string(),
            node_id: node_id.to_string(),
            metric_name: format!("host.psi.{resource}.some_avg10"),
            metric_unit: "%".to_string(),
            value_f64: snap.some.avg10,
            arch: arch.to_string(),
            cpu_cluster: None,
            vlen_bits: None,
            memlock_used_bytes: None,
            memlock_limit_bytes: None,
            trace_id: None,
            span_id: None,
            attributes_json: attrs.clone(),
        },
        OtelMetricEntry {
            timestamp_unix_nano: now_unix_nano,
            service_name: SENTINEL_SERVICE_NAME.to_string(),
            node_id: node_id.to_string(),
            metric_name: format!("host.psi.{resource}.some_avg60"),
            metric_unit: "%".to_string(),
            value_f64: snap.some.avg60,
            arch: arch.to_string(),
            cpu_cluster: None,
            vlen_bits: None,
            memlock_used_bytes: None,
            memlock_limit_bytes: None,
            trace_id: None,
            span_id: None,
            attributes_json: attrs.clone(),
        },
    ];

    if let Some(full) = snap.full {
        out.push(OtelMetricEntry {
            timestamp_unix_nano: now_unix_nano,
            service_name: SENTINEL_SERVICE_NAME.to_string(),
            node_id: node_id.to_string(),
            metric_name: format!("host.psi.{resource}.full_avg10"),
            metric_unit: "%".to_string(),
            value_f64: full.avg10,
            arch: arch.to_string(),
            cpu_cluster: None,
            vlen_bits: None,
            memlock_used_bytes: None,
            memlock_limit_bytes: None,
            trace_id: None,
            span_id: None,
            attributes_json: attrs,
        });
    }

    out
}

/// Parsed fields from `/proc/[pid]/stat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStatDetails {
    /// Process ID (field 1).
    pub pid: u32,
    /// Executable command name inside parentheses (field 2).
    pub comm: String,
    /// Process state character (field 3).
    pub state: char,
    /// Parent process ID (field 4), when present.
    pub ppid: Option<u32>,
    /// Kernel flags word (field 9), when present.
    pub flags: Option<u64>,
    /// Start time in clock ticks since boot (field 22), when present.
    pub starttime_ticks: Option<u64>,
}

/// Parses `/proc/[pid]/stat` content into [`ProcStatDetails`].
#[must_use]
pub fn parse_proc_stat_details(stat_line: &str) -> Option<ProcStatDetails> {
    let trimmed = stat_line.trim();
    let open_paren = trimmed.find('(')?;
    let close_paren = trimmed.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }
    let pid = trimmed[..open_paren].trim().parse::<u32>().ok()?;
    let comm = trimmed[open_paren + 1..close_paren].to_string();
    let after_comm: Vec<&str> = trimmed[close_paren + 1..].split_whitespace().collect();
    let state = after_comm.first()?.chars().next()?;
    let ppid = after_comm.get(1).and_then(|s| s.parse::<u32>().ok());
    let flags = after_comm.get(6).and_then(|s| s.parse::<u64>().ok());
    let starttime_ticks = after_comm.get(19).and_then(|s| s.parse::<u64>().ok());
    Some(ProcStatDetails {
        pid,
        comm,
        state,
        ppid,
        flags,
        starttime_ticks,
    })
}

/// Parses `/proc/[pid]/stat` content to extract `(pid, comm, state_char)`.
#[must_use]
pub fn parse_proc_stat_state(stat_line: &str) -> Option<(u32, String, char)> {
    parse_proc_stat_details(stat_line).map(|d| (d.pid, d.comm, d.state))
}

/// Returns `true` if `comm` matches known kernel thread command names (`kthreadd`, `kworker/*`).
#[must_use]
pub fn is_kworker_comm(comm: &str) -> bool {
    comm == "kthreadd" || comm == "kworker" || comm.starts_with("kworker/")
}

/// Returns `true` if the `/proc/[pid]/stat` entry represents a Linux kernel thread
/// (`PF_KTHREAD` flag `0x0020_0000`, `pid == 2`, `ppid == 2`, or `kworker/*`).
#[must_use]
pub fn is_kernel_thread(details: &ProcStatDetails) -> bool {
    details.pid == 2
        || details.ppid == Some(2)
        || details.flags.is_some_and(|f| (f & PF_KTHREAD) != 0)
        || is_kworker_comm(&details.comm)
}

/// Scans `proc_root` for actionable user-space tasks currently in `D` state (`TASK_UNINTERRUPTIBLE`),
/// excluding Linux kernel threads (`PF_KTHREAD`, `ppid == 2`, `kworker/*`).
pub fn scan_dstate_processes(proc_root: &Path) -> Vec<BlockedProcessInfo> {
    let mut blocked = Vec::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return blocked;
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name_str) = file_name.to_str() else {
            continue;
        };
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid_dir = entry.path();
        let Ok(stat_content) = std::fs::read_to_string(pid_dir.join("stat")) else {
            continue;
        };
        if let Some(details) = parse_proc_stat_details(&stat_content) {
            if details.state == 'D' && !is_kernel_thread(&details) {
                let wchan = std::fs::read_to_string(pid_dir.join("wchan"))
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();
                blocked.push(BlockedProcessInfo {
                    pid: details.pid,
                    comm: details.comm,
                    wchan,
                });
            }
        }
    }
    blocked.sort_by_key(|b| b.pid);
    blocked
}

/// Inputs for a single PSI / D-state observation tick in [`PsiAlertTracker`].
#[derive(Debug, Clone, Copy)]
pub struct PsiSweepSample<'a> {
    pub io_snap: Option<&'a PsiResourceSnapshot>,
    pub mem_snap: Option<&'a PsiResourceSnapshot>,
    pub blocked: &'a [BlockedProcessInfo],
    pub warn_pct: f64,
    pub node_id: &'a str,
    pub elapsed_total_ms: u64,
    pub now_unix_nano: i64,
}

/// Stateful persistence and cooldown tracker for `psi_dstate` alerts across sweeps.
///
/// Requires `persistence_samples` consecutive sweeps before escalating user-space D-state
/// tasks or sustained PSI pressure into an alert, and rate-limits steady conditions with
/// a bounded `cooldown_ms` while allowing immediate `WARN` -> `ERROR` severity escalation.
#[derive(Debug, Clone)]
pub struct PsiAlertTracker {
    persistence_samples: u32,
    critical_psi_pct: f64,
    cooldown_ms: u64,
    dstate_streaks: HashMap<(u32, String), u32>,
    psi_warn_streak: u32,
    psi_critical_streak: u32,
    last_alert: Option<(u64, u8)>,
}

impl Default for PsiAlertTracker {
    fn default() -> Self {
        Self::new(
            DEFAULT_PSI_PERSISTENCE_SAMPLES,
            DEFAULT_PSI_CRITICAL_PCT,
            300_000,
        )
    }
}

impl PsiAlertTracker {
    /// Creates a new [`PsiAlertTracker`] requiring `persistence_samples.max(1)` consecutive
    /// sweeps and enforcing `cooldown_ms` between steady alerts.
    #[must_use]
    pub fn new(persistence_samples: u32, critical_psi_pct: f64, cooldown_ms: u64) -> Self {
        Self {
            persistence_samples: persistence_samples.max(1),
            critical_psi_pct,
            cooldown_ms,
            dstate_streaks: HashMap::new(),
            psi_warn_streak: 0,
            psi_critical_streak: 0,
            last_alert: None,
        }
    }

    /// Evaluates the latest sweep sample and returns an [`OtelLogEntry`] only when
    /// persistence thresholds are met and the alert is outside the active cooldown window
    /// (or escalating from `WARN` to `ERROR`).
    pub fn observe(&mut self, sample: &PsiSweepSample<'_>) -> Option<OtelLogEntry> {
        let io_some_avg10 = sample.io_snap.map(|s| s.some.avg10).unwrap_or(0.0);
        let io_full_avg10 = sample
            .io_snap
            .and_then(|s| s.full.map(|f| f.avg10))
            .unwrap_or(0.0);
        let mem_full_avg10 = sample
            .mem_snap
            .and_then(|s| s.full.map(|f| f.avg10))
            .unwrap_or(0.0);

        let mut next_streaks = HashMap::with_capacity(sample.blocked.len());
        let mut persistent_blocked = Vec::new();
        for proc_info in sample.blocked {
            if is_kworker_comm(&proc_info.comm) {
                continue;
            }
            let key = (proc_info.pid, proc_info.comm.clone());
            let streak = self
                .dstate_streaks
                .get(&key)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            next_streaks.insert(key, streak);
            if streak >= self.persistence_samples {
                persistent_blocked.push(proc_info.clone());
            }
        }
        self.dstate_streaks = next_streaks;

        if io_some_avg10 >= sample.warn_pct || mem_full_avg10 >= sample.warn_pct {
            self.psi_warn_streak = self.psi_warn_streak.saturating_add(1);
        } else {
            self.psi_warn_streak = 0;
        }

        if io_full_avg10 >= self.critical_psi_pct {
            self.psi_critical_streak = self.psi_critical_streak.saturating_add(1);
        } else {
            self.psi_critical_streak = 0;
        }

        let error_ready =
            !persistent_blocked.is_empty() || self.psi_critical_streak >= self.persistence_samples;
        let warn_ready = self.psi_warn_streak >= self.persistence_samples;
        if !error_ready && !warn_ready {
            return None;
        }

        let severity_number: u8 = if error_ready { 17 } else { 13 };
        if let Some((last_ms, last_sev)) = self.last_alert {
            let within_cooldown =
                sample.elapsed_total_ms.saturating_sub(last_ms) < self.cooldown_ms;
            if within_cooldown && severity_number <= last_sev {
                return None;
            }
        }

        let entry = build_psi_dstate_log_entry(
            sample.io_snap,
            sample.mem_snap,
            &persistent_blocked,
            sample.warn_pct,
            error_ready,
            sample.node_id,
            sample.now_unix_nano,
        )?;
        self.last_alert = Some((sample.elapsed_total_ms, severity_number));
        Some(entry)
    }
}

fn build_psi_dstate_log_entry(
    io_snap: Option<&PsiResourceSnapshot>,
    mem_snap: Option<&PsiResourceSnapshot>,
    blocked: &[BlockedProcessInfo],
    warn_pct: f64,
    escalate_error: bool,
    node_id: &str,
    now_unix_nano: i64,
) -> Option<OtelLogEntry> {
    let io_full_avg10 = io_snap.and_then(|s| s.full.map(|f| f.avg10)).unwrap_or(0.0);
    let io_some_avg10 = io_snap.map(|s| s.some.avg10).unwrap_or(0.0);
    let mem_full_avg10 = mem_snap
        .and_then(|s| s.full.map(|f| f.avg10))
        .unwrap_or(0.0);

    let filtered_blocked: Vec<&BlockedProcessInfo> = blocked
        .iter()
        .filter(|b| !is_kworker_comm(&b.comm))
        .collect();

    if !escalate_error
        && io_some_avg10 < warn_pct
        && mem_full_avg10 < warn_pct
        && filtered_blocked.is_empty()
    {
        return None;
    }

    let blocked_summary: Vec<String> = filtered_blocked
        .iter()
        .map(|b| format!("{}(pid={},wchan={})", b.comm, b.pid, b.wchan))
        .collect();

    let body = format!(
        "Host pressure / D-state alert: io_some_avg10={io_some_avg10:.2}% io_full_avg10={io_full_avg10:.2}% mem_full_avg10={mem_full_avg10:.2}% dstate_tasks=[{}]",
        blocked_summary.join(", ")
    );
    let attrs = serde_json::json!({
        "subsystem": "psi_dstate",
        "io_some_avg10": io_some_avg10,
        "io_full_avg10": io_full_avg10,
        "mem_full_avg10": mem_full_avg10,
        "dstate_count": filtered_blocked.len(),
        "dstate_processes": filtered_blocked,
    });

    Some(OtelLogEntry {
        timestamp_unix_nano: now_unix_nano,
        trace_id: format!("{:032x}", now_unix_nano as u128),
        span_id: format!("{:016x}", now_unix_nano as u64),
        severity_number: if escalate_error { 17 } else { 13 },
        severity_text: if escalate_error {
            "ERROR".to_string()
        } else {
            "WARN".to_string()
        },
        service_name: SENTINEL_SERVICE_NAME.to_string(),
        node_id: node_id.to_string(),
        body,
        attributes_json: attrs.to_string(),
        job_id: None,
        stage_id: None,
    })
}

/// Builds an [`OtelLogEntry`] when PSI exceeds `warn_pct` or actionable user-space
/// `D`-state processes are present (filtering `kworker/*` threads).
#[must_use]
pub fn build_psi_dstate_alert(
    io_snap: Option<&PsiResourceSnapshot>,
    mem_snap: Option<&PsiResourceSnapshot>,
    blocked: &[BlockedProcessInfo],
    warn_pct: f64,
    node_id: &str,
    now_unix_nano: i64,
) -> Option<OtelLogEntry> {
    let io_full_avg10 = io_snap.and_then(|s| s.full.map(|f| f.avg10)).unwrap_or(0.0);
    let has_user_blocked = blocked.iter().any(|b| !is_kworker_comm(&b.comm));
    let escalate_error = has_user_blocked || io_full_avg10 >= DEFAULT_PSI_CRITICAL_PCT;
    build_psi_dstate_log_entry(
        io_snap,
        mem_snap,
        blocked,
        warn_pct,
        escalate_error,
        node_id,
        now_unix_nano,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psi_snap(some_avg10: f64, full_avg10: f64) -> PsiResourceSnapshot {
        PsiResourceSnapshot {
            some: PsiWindow {
                avg10: some_avg10,
                avg60: 0.0,
                avg300: 0.0,
                total_usec: 0,
            },
            full: Some(PsiWindow {
                avg10: full_avg10,
                avg60: 0.0,
                avg300: 0.0,
                total_usec: 0,
            }),
        }
    }

    #[test]
    fn test_parse_psi_io_and_alert() {
        let sample = "some avg10=18.42 avg60=5.10 avg300=1.02 total=4829100\nfull avg10=14.20 avg60=3.50 avg300=0.80 total=3100200\n";
        let snap = parse_psi_content("io", sample).expect("valid PSI");
        assert!((snap.some.avg10 - 18.42).abs() < 1e-6);
        let full = snap.full.expect("has full");
        assert!((full.avg10 - 14.20).abs() < 1e-6);

        let metrics = psi_snapshot_to_metrics("io", &snap, "node-a", "x86_64", 1_000_000);
        assert_eq!(metrics.len(), 3);
        assert!(metrics
            .iter()
            .all(|m| m.service_name == SENTINEL_SERVICE_NAME));

        let blocked = vec![BlockedProcessInfo {
            pid: 412,
            comm: "systemd-journal".to_string(),
            wchan: "btrfs_commit_transaction".to_string(),
        }];
        let alert = build_psi_dstate_alert(Some(&snap), None, &blocked, 10.0, "node-a", 1_000_000)
            .expect("should alert");
        assert_eq!(alert.severity_text, "ERROR");
        assert_eq!(alert.service_name, SENTINEL_SERVICE_NAME);
        assert!(alert.body.contains("systemd-journal"));
        assert!(alert.body.contains("btrfs_commit_transaction"));
    }

    #[test]
    fn test_parse_proc_stat_with_spaces_and_parens() {
        let line = "412 (systemd-journal) D 1 412 412 0 -1 4194560 1204 0 12 0 14 28 0 0 20 0 1 0 120 123456 789";
        let (pid, comm, state) = parse_proc_stat_state(line).expect("parsed");
        assert_eq!(pid, 412);
        assert_eq!(comm, "systemd-journal");
        assert_eq!(state, 'D');
    }

    #[test]
    fn test_scan_dstate_excludes_kernel_threads_and_kworkers() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proc_root = tmp.path();

        // 1. kthreadd (pid 2, PF_KTHREAD = 0x00200000 = 2097152)
        std::fs::create_dir_all(proc_root.join("2")).unwrap();
        std::fs::write(
            proc_root.join("2/stat"),
            "2 (kthreadd) D 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0\n",
        )
        .unwrap();

        // 2. kworker child of kthreadd (ppid=2, PF_KTHREAD)
        std::fs::create_dir_all(proc_root.join("105")).unwrap();
        std::fs::write(
            proc_root.join("105/stat"),
            "105 (kworker/u16:2+ixgbe) D 2 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 50 0 0\n",
        )
        .unwrap();
        std::fs::write(proc_root.join("105/wchan"), "0\n").unwrap();

        // 3. Non-kworker kernel thread identified via PF_KTHREAD (btrfs-transacti, ppid=2)
        std::fs::create_dir_all(proc_root.join("210")).unwrap();
        std::fs::write(
            proc_root.join("210/stat"),
            "210 (btrfs-transacti) D 2 0 0 0 -1 2097152 0 0 0 0 0 0 0 0 20 0 1 0 60 0 0\n",
        )
        .unwrap();

        // 4. Synthetic kworker fixture without full stat fields
        std::fs::create_dir_all(proc_root.join("300")).unwrap();
        std::fs::write(
            proc_root.join("300/stat"),
            "300 (kworker/u32:1+flush-btrfs-1) D 1\n",
        )
        .unwrap();

        // 5. Genuine user-space task in D state (ppid=1, flags=0x400100 = 4194560)
        std::fs::create_dir_all(proc_root.join("412")).unwrap();
        std::fs::write(
            proc_root.join("412/stat"),
            "412 (systemd-journal) D 1 412 412 0 -1 4194560 0 0 0 0 1 2 0 0 20 0 1 0 120 0 0\n",
        )
        .unwrap();
        std::fs::write(proc_root.join("412/wchan"), "btrfs_commit_transaction\n").unwrap();

        let blocked = scan_dstate_processes(proc_root);
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].pid, 412);
        assert_eq!(blocked[0].comm, "systemd-journal");

        // Zero PSI + kworker-only input to build_psi_dstate_alert also produces None
        let kworker_only = vec![BlockedProcessInfo {
            pid: 105,
            comm: "kworker/u16:2+ixgbe".to_string(),
            wchan: "0".to_string(),
        }];
        let zero_psi = psi_snap(0.0, 0.0);
        assert!(build_psi_dstate_alert(
            Some(&zero_psi),
            Some(&zero_psi),
            &kworker_only,
            10.0,
            "node-a",
            1_000_000,
        )
        .is_none());
    }

    #[test]
    fn test_psi_tracker_persistence_cooldown_and_escalation() {
        let mut tracker = PsiAlertTracker::new(3, 25.0, 300_000);
        let zero_psi = psi_snap(0.0, 0.0);
        let user_blocked = vec![BlockedProcessInfo {
            pid: 412,
            comm: "systemd-journal".to_string(),
            wchan: "btrfs_commit_transaction".to_string(),
        }];

        // Sweeps 1 and 2 of user D-state must not emit prematurely
        assert!(tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&zero_psi),
                mem_snap: Some(&zero_psi),
                blocked: &user_blocked,
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 5_000,
                now_unix_nano: 1,
            })
            .is_none());
        assert!(tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&zero_psi),
                mem_snap: Some(&zero_psi),
                blocked: &user_blocked,
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 10_000,
                now_unix_nano: 2,
            })
            .is_none());

        // Transient clear resets streak; next sweep restarts at 1
        assert!(tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&zero_psi),
                mem_snap: Some(&zero_psi),
                blocked: &[],
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 15_000,
                now_unix_nano: 3,
            })
            .is_none());
        assert!(tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&zero_psi),
                mem_snap: Some(&zero_psi),
                blocked: &user_blocked,
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 20_000,
                now_unix_nano: 4,
            })
            .is_none());
        assert!(tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&zero_psi),
                mem_snap: Some(&zero_psi),
                blocked: &user_blocked,
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 25_000,
                now_unix_nano: 5,
            })
            .is_none());

        // 3rd consecutive sweep emits ERROR
        let err_alert = tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&zero_psi),
                mem_snap: Some(&zero_psi),
                blocked: &user_blocked,
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 30_000,
                now_unix_nano: 6,
            })
            .expect("3rd consecutive D-state sweep emits ERROR");
        assert_eq!(err_alert.severity_text, "ERROR");
        assert_eq!(err_alert.severity_number, 17);

        // Steady condition inside 300s cooldown is suppressed
        assert!(tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&zero_psi),
                mem_snap: Some(&zero_psi),
                blocked: &user_blocked,
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 35_000,
                now_unix_nano: 7,
            })
            .is_none());

        // Cooldown expiry re-emits once
        let re_emitted = tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&zero_psi),
                mem_snap: Some(&zero_psi),
                blocked: &user_blocked,
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 330_000,
                now_unix_nano: 8,
            })
            .expect("cooldown expired should re-emit");
        assert_eq!(re_emitted.severity_text, "ERROR");

        // Fresh tracker: single io_full >= 25% spike does not emit ERROR; sustained WARN escalates to ERROR
        let mut psi_tracker = PsiAlertTracker::new(3, 25.0, 300_000);
        let warn_psi = psi_snap(15.0, 10.0);
        let spike_psi = psi_snap(30.0, 28.0);
        assert!(psi_tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&warn_psi),
                mem_snap: None,
                blocked: &[],
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 5_000,
                now_unix_nano: 10,
            })
            .is_none());
        assert!(psi_tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&warn_psi),
                mem_snap: None,
                blocked: &[],
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 10_000,
                now_unix_nano: 11,
            })
            .is_none());
        // 3rd sample has 1-tick critical spike: warn_streak=3, critical_streak=1 -> WARN only
        let warn_alert = psi_tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&spike_psi),
                mem_snap: None,
                blocked: &[],
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 15_000,
                now_unix_nano: 12,
            })
            .expect("3rd sustained warn sweep emits WARN");
        assert_eq!(warn_alert.severity_text, "WARN");
        assert_eq!(warn_alert.severity_number, 13);

        // 2nd critical sample stays within cooldown without ERROR
        assert!(psi_tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&spike_psi),
                mem_snap: None,
                blocked: &[],
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 20_000,
                now_unix_nano: 13,
            })
            .is_none());

        // 3rd critical sample escalates WARN -> ERROR immediately bypassing cooldown
        let escalated = psi_tracker
            .observe(&PsiSweepSample {
                io_snap: Some(&spike_psi),
                mem_snap: None,
                blocked: &[],
                warn_pct: 10.0,
                node_id: "node-a",
                elapsed_total_ms: 25_000,
                now_unix_nano: 14,
            })
            .expect("3rd critical sweep escalates to ERROR");
        assert_eq!(escalated.severity_text, "ERROR");
        assert_eq!(escalated.severity_number, 17);
    }
}
