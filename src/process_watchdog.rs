//! Runaway build/test child process watchdog (`/proc/uptime` + `/proc/[pid]/stat`).
//!
//! Detects long-running active compiler or interpreter processes (`miri`, `cargo`, `rustc`)
//! in `R` or `D` state whose elapsed runtime exceeds `MUSENTINEL_RUNAWAY_SECS` (`2100s` default)
//! and emits deduplicated `OtelLogEntry` diagnostics (`subsystem = "runaway_process"`).

use crate::psi::{is_kernel_thread, parse_proc_stat_details};
use mu_observable_ipc::OtelLogEntry;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Default Linux `SC_CLK_TCK` (`USER_HZ = 100` ticks per second).
pub const DEFAULT_CLK_TCK: u64 = 100;

/// Monitored process info when elapsed runtime exceeds `max_runtime_secs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunawayProcessInfo {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub elapsed_secs: u64,
    pub starttime_ticks: u64,
}

/// Parses `/proc/uptime` (`<uptime_secs> <idle_secs>`) and returns host uptime in clock ticks (`USER_HZ`).
#[must_use]
pub fn parse_uptime_ticks(uptime_content: &str, clk_tck: u64) -> Option<u64> {
    let first = uptime_content.split_whitespace().next()?;
    let secs = first.parse::<f64>().ok()?;
    if secs < 0.0 {
        return None;
    }
    Some((secs * (clk_tck as f64)) as u64)
}

/// Parses `/proc/[pid]/stat` and returns `(pid, comm, state, starttime_ticks)`.
#[must_use]
pub fn parse_proc_stat_starttime(stat_line: &str) -> Option<(u32, String, char, u64)> {
    let details = parse_proc_stat_details(stat_line)?;
    let starttime_ticks = details.starttime_ticks?;
    Some((details.pid, details.comm, details.state, starttime_ticks))
}

/// Returns `true` if `comm` is a monitored build/test process (`miri`, `cargo`, `rustc`, `rustdoc`).
#[must_use]
pub fn is_watched_build_comm(comm: &str) -> bool {
    let lower = comm.to_ascii_lowercase();
    lower.contains("miri")
        || lower == "cargo"
        || lower == "rustc"
        || lower == "rustdoc"
        || lower.starts_with("cargo-")
}

/// Returns `true` if the `/proc/[pid]/stat` state represents an active or uninterruptibly
/// blocked process (`R` or `D`), excluding sleeping orchestrator wrappers (`S`, `I`, `T`, `Z`).
#[must_use]
pub const fn is_active_runaway_state(state: char) -> bool {
    matches!(state, 'R' | 'D')
}

/// Scans `proc_root` for active (`R`/`D`) watched build/test processes exceeding `max_runtime_secs`.
pub fn scan_runaway_processes(proc_root: &Path, max_runtime_secs: u64) -> Vec<RunawayProcessInfo> {
    let mut out = Vec::new();
    let Ok(uptime_str) = std::fs::read_to_string(proc_root.join("uptime")) else {
        return out;
    };
    let Some(uptime_ticks) = parse_uptime_ticks(&uptime_str, DEFAULT_CLK_TCK) else {
        return out;
    };
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return out;
    };

    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(name_str) = fname.to_str() else {
            continue;
        };
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(stat_line) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(details) = parse_proc_stat_details(&stat_line) else {
            continue;
        };
        if is_kernel_thread(&details)
            || !is_watched_build_comm(&details.comm)
            || !is_active_runaway_state(details.state)
        {
            continue;
        }
        let Some(start_ticks) = details.starttime_ticks else {
            continue;
        };
        let elapsed_secs = uptime_ticks.saturating_sub(start_ticks) / DEFAULT_CLK_TCK;
        if elapsed_secs >= max_runtime_secs {
            out.push(RunawayProcessInfo {
                pid: details.pid,
                comm: details.comm,
                state: details.state,
                elapsed_secs,
                starttime_ticks: start_ticks,
            });
        }
    }

    out.sort_by_key(|p| p.pid);
    out
}

/// Stateful per-process deduplication and cooldown tracker keyed by `(pid, starttime_ticks)`.
#[derive(Debug, Default)]
pub struct RunawayAlertTracker {
    alerted: HashMap<(u32, u64), u64>,
}

impl RunawayAlertTracker {
    /// Creates an empty [`RunawayAlertTracker`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filters `runaways` to only those `(pid, starttime_ticks)` entries not suppressed by
    /// `cooldown_ms`, updating internal tracking state and pruning expired entries.
    pub fn filter_due(
        &mut self,
        runaways: &[RunawayProcessInfo],
        elapsed_total_ms: u64,
        cooldown_ms: u64,
    ) -> Vec<RunawayProcessInfo> {
        let active: HashSet<(u32, u64)> = runaways
            .iter()
            .map(|p| (p.pid, p.starttime_ticks))
            .collect();

        self.alerted.retain(|key, last_ms| {
            active.contains(key) || elapsed_total_ms.saturating_sub(*last_ms) < cooldown_ms
        });

        let mut due = Vec::new();
        for proc_info in runaways {
            let key = (proc_info.pid, proc_info.starttime_ticks);
            let within_cooldown = self.alerted.get(&key).is_some_and(|last_ms| {
                cooldown_ms > 0 && elapsed_total_ms.saturating_sub(*last_ms) < cooldown_ms
            });
            if within_cooldown {
                continue;
            }
            self.alerted.insert(key, elapsed_total_ms);
            due.push(proc_info.clone());
        }
        due
    }
}

/// Converts discovered [`RunawayProcessInfo`] entries into [`OtelLogEntry`] warnings.
#[must_use]
pub fn runaway_processes_to_logs(
    items: &[RunawayProcessInfo],
    node_id: &str,
    now_unix_nano: i64,
) -> Vec<OtelLogEntry> {
    items
        .iter()
        .map(|p| {
            let body = format!(
                "Runaway process detected: comm={} pid={} state={} elapsed={}s",
                p.comm, p.pid, p.state, p.elapsed_secs
            );
            let attrs = serde_json::json!({
                "subsystem": "runaway_process",
                "pid": p.pid,
                "comm": p.comm,
                "state": p.state.to_string(),
                "elapsed_secs": p.elapsed_secs,
                "starttime_ticks": p.starttime_ticks,
            });
            OtelLogEntry {
                timestamp_unix_nano: now_unix_nano,
                trace_id: format!("{:032x}", u128::from(p.pid)),
                span_id: format!("{:016x}", u64::from(p.pid)),
                severity_number: 13,
                severity_text: "WARN".to_string(),
                service_name: "musentinel".to_string(),
                node_id: node_id.to_string(),
                body,
                attributes_json: attrs.to_string(),
                job_id: None,
                stage_id: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_RUNAWAY_SECS;

    fn write_proc_stat(proc_root: &Path, pid: u32, comm: &str, state: char, start_ticks: u64) {
        let dir = proc_root.join(pid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let line = format!(
            "{pid} ({comm}) {state} 1 {pid} {pid} 0 -1 4194304 100 0 0 0 95000 120 0 0 20 0 1 0 {start_ticks} 123456 789\n"
        );
        std::fs::write(dir.join("stat"), line).unwrap();
    }

    #[test]
    fn test_parse_proc_stat_starttime_and_runaway_log() {
        let line = "29104 (miri) R 1 29104 29104 0 -1 4194304 100 0 0 0 95000 120 0 0 20 0 1 0 10000 123456 789";
        let (pid, comm, state, start_ticks) = parse_proc_stat_starttime(line).unwrap();
        assert_eq!(pid, 29104);
        assert_eq!(comm, "miri");
        assert_eq!(state, 'R');
        assert_eq!(start_ticks, 10000);
        assert!(is_watched_build_comm(&comm));

        let logs = runaway_processes_to_logs(
            &[RunawayProcessInfo {
                pid,
                comm,
                state,
                elapsed_secs: 2200,
                starttime_ticks: start_ticks,
            }],
            "node-a",
            12345,
        );
        assert_eq!(logs.len(), 1);
        assert!(logs[0].body.contains("elapsed=2200s"));
        assert!(logs[0]
            .attributes_json
            .contains("\"starttime_ticks\":10000"));
    }

    #[test]
    fn test_ignores_sleeping_wrappers_and_compliant_1800s_ci_stages() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proc_root = tmp.path();
        // Uptime = 5000.00s = 500_000 ticks
        std::fs::write(proc_root.join("uptime"), "5000.00 4000.00\n").unwrap();

        // Sleeping parent wrapper cargo-llvm-cov running for 2500s (state = S) -> ignored
        write_proc_stat(proc_root, 1001, "cargo-llvm-cov", 'S', 250_000);
        // Sleeping parent cargo wrapper running for 2500s (state = S) -> ignored
        write_proc_stat(proc_root, 1002, "cargo", 'S', 250_000);
        // Active miri running for exactly 1800s (start = 320_000 ticks) -> ignored under 2100s default
        write_proc_stat(proc_root, 1003, "miri", 'R', 320_000);
        // Active rustc running for 2200s (start = 280_000 ticks) -> detected
        write_proc_stat(proc_root, 1004, "rustc", 'R', 280_000);

        let found = scan_runaway_processes(proc_root, DEFAULT_RUNAWAY_SECS);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pid, 1004);
        assert_eq!(found[0].comm, "rustc");
        assert_eq!(found[0].elapsed_secs, 2200);
        assert_eq!(found[0].starttime_ticks, 280_000);
    }

    #[test]
    fn test_runaway_tracker_dedup_pid_reuse_and_cooldown() {
        let mut tracker = RunawayAlertTracker::new();
        let proc_v1 = RunawayProcessInfo {
            pid: 29104,
            comm: "miri".to_string(),
            state: 'R',
            elapsed_secs: 2200,
            starttime_ticks: 10_000,
        };

        // First sighting alerts
        let due1 = tracker.filter_due(std::slice::from_ref(&proc_v1), 5_000, 300_000);
        assert_eq!(due1.len(), 1);

        // Subsequent 5s poll within 300s cooldown is suppressed
        let due2 = tracker.filter_due(std::slice::from_ref(&proc_v1), 10_000, 300_000);
        assert!(due2.is_empty());

        // Brief R->S->R flicker (empty scan then back) inside cooldown stays suppressed
        let due_gap = tracker.filter_due(&[], 15_000, 300_000);
        assert!(due_gap.is_empty());
        let due_back = tracker.filter_due(std::slice::from_ref(&proc_v1), 20_000, 300_000);
        assert!(due_back.is_empty());

        // PID reuse with a different starttime_ticks alerts immediately
        let proc_v2 = RunawayProcessInfo {
            pid: 29104,
            comm: "rustc".to_string(),
            state: 'D',
            elapsed_secs: 2150,
            starttime_ticks: 99_999,
        };
        let due_reused = tracker.filter_due(&[proc_v2], 25_000, 300_000);
        assert_eq!(due_reused.len(), 1);
        assert_eq!(due_reused[0].starttime_ticks, 99_999);

        // After cooldown expires for still-running proc_v1, re-alerts once
        let due_expired = tracker.filter_due(&[proc_v1], 310_000, 300_000);
        assert_eq!(due_expired.len(), 1);
    }
}
