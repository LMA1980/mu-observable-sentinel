//! Runaway build/test child process watchdog (`/proc/uptime` + `/proc/[pid]/stat`).
//!
//! Detects long-running compiler or interpreter processes (`miri`, `cargo`, `rustc`)
//! whose elapsed runtime exceeds `MUSENTINEL_RUNAWAY_SECS` (`900s` default) and emits
//! structured `OtelLogEntry` diagnostics (`subsystem = "runaway_process"`).

use mu_observable_ipc::OtelLogEntry;
use serde::{Deserialize, Serialize};
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
    let trimmed = stat_line.trim();
    let open_paren = trimmed.find('(')?;
    let close_paren = trimmed.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }
    let pid = trimmed[..open_paren].trim().parse::<u32>().ok()?;
    let comm = trimmed[open_paren + 1..close_paren].to_string();
    let after_comm: Vec<&str> = trimmed[close_paren + 1..].split_whitespace().collect();
    // Field 3 is state (after_comm[0]), field 22 is starttime (after_comm[19])
    if after_comm.len() < 20 {
        return None;
    }
    let state = after_comm[0].chars().next()?;
    let starttime_ticks = after_comm[19].parse::<u64>().ok()?;
    Some((pid, comm, state, starttime_ticks))
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

/// Scans `proc_root` for watched build/test processes exceeding `max_runtime_secs`.
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
        let Some((pid, comm, state, start_ticks)) = parse_proc_stat_starttime(&stat_line) else {
            continue;
        };
        if !is_watched_build_comm(&comm) {
            continue;
        }
        let elapsed_secs = uptime_ticks.saturating_sub(start_ticks) / DEFAULT_CLK_TCK;
        if elapsed_secs >= max_runtime_secs {
            out.push(RunawayProcessInfo {
                pid,
                comm,
                state,
                elapsed_secs,
            });
        }
    }

    out.sort_by_key(|p| p.pid);
    out
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
                elapsed_secs: 1800,
            }],
            "node-a",
            12345,
        );
        assert_eq!(logs.len(), 1);
        assert!(logs[0].body.contains("elapsed=1800s"));
    }
}
