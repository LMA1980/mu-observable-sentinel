//! Linux Pressure Stall Information (`/proc/pressure/{io,memory,cpu}`) and
//! uninterruptible sleep (`D`-state / `TASK_UNINTERRUPTIBLE`) task inspector.

use crate::error::SentinelError;
use mu_observable_ipc::{OtelLogEntry, OtelMetricEntry};
use serde::{Deserialize, Serialize};
use std::path::Path;

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
            service_name: "musentinel".to_string(),
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
            service_name: "musentinel".to_string(),
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
            service_name: "musentinel".to_string(),
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

/// Parses `/proc/[pid]/stat` content to extract `(pid, comm, state_char)`.
pub fn parse_proc_stat_state(stat_line: &str) -> Option<(u32, String, char)> {
    let trimmed = stat_line.trim();
    let open_paren = trimmed.find('(')?;
    let close_paren = trimmed.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }
    let pid = trimmed[..open_paren].trim().parse::<u32>().ok()?;
    let comm = trimmed[open_paren + 1..close_paren].to_string();
    let rest = trimmed[close_paren + 1..].trim_start();
    let state_char = rest.chars().next()?;
    Some((pid, comm, state_char))
}

/// Scans `proc_root` for tasks currently in `D` state (`TASK_UNINTERRUPTIBLE`).
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
        if let Some((pid, comm, 'D')) = parse_proc_stat_state(&stat_content) {
            let wchan = std::fs::read_to_string(pid_dir.join("wchan"))
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string();
            blocked.push(BlockedProcessInfo { pid, comm, wchan });
        }
    }
    blocked
}

/// Builds an [`OtelLogEntry`] when PSI exceeds `warn_pct` or `D`-state processes are present.
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
    let io_some_avg10 = io_snap.map(|s| s.some.avg10).unwrap_or(0.0);
    let mem_full_avg10 = mem_snap
        .and_then(|s| s.full.map(|f| f.avg10))
        .unwrap_or(0.0);

    if io_some_avg10 < warn_pct && mem_full_avg10 < warn_pct && blocked.is_empty() {
        return None;
    }

    let blocked_summary: Vec<String> = blocked
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
        "dstate_count": blocked.len(),
        "dstate_processes": blocked,
    });

    Some(OtelLogEntry {
        timestamp_unix_nano: now_unix_nano,
        trace_id: format!("{:032x}", now_unix_nano as u128),
        span_id: format!("{:016x}", now_unix_nano as u64),
        severity_number: if !blocked.is_empty() || io_full_avg10 >= 25.0 {
            17
        } else {
            13
        },
        severity_text: if !blocked.is_empty() || io_full_avg10 >= 25.0 {
            "ERROR".to_string()
        } else {
            "WARN".to_string()
        },
        service_name: "musentinel".to_string(),
        node_id: node_id.to_string(),
        body,
        attributes_json: attrs.to_string(),
        job_id: None,
        stage_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_psi_io_and_alert() {
        let sample = "some avg10=18.42 avg60=5.10 avg300=1.02 total=4829100\nfull avg10=14.20 avg60=3.50 avg300=0.80 total=3100200\n";
        let snap = parse_psi_content("io", sample).expect("valid PSI");
        assert!((snap.some.avg10 - 18.42).abs() < 1e-6);
        let full = snap.full.expect("has full");
        assert!((full.avg10 - 14.20).abs() < 1e-6);

        let metrics = psi_snapshot_to_metrics("io", &snap, "node-a", "x86_64", 1_000_000);
        assert_eq!(metrics.len(), 3);

        let blocked = vec![BlockedProcessInfo {
            pid: 412,
            comm: "systemd-journal".to_string(),
            wchan: "btrfs_commit_transaction".to_string(),
        }];
        let alert = build_psi_dstate_alert(Some(&snap), None, &blocked, 10.0, "node-a", 1_000_000)
            .expect("should alert");
        assert_eq!(alert.severity_text, "ERROR");
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
}
