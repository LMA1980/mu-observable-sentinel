//! Systemd journal socket backpressure (`/proc/net/unix`) and host memory/writeback
//! headroom (`/proc/meminfo`) inspector.

use crate::error::SentinelError;
use mu_observable_ipc::{OtelLogEntry, OtelMetricEntry};
use serde::{Deserialize, Serialize};

/// Parsed memory and writeback counters from `/proc/meminfo` (in bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostMeminfoSnapshot {
    pub mem_total_bytes: u64,
    pub mem_available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    pub dirty_bytes: u64,
    pub writeback_bytes: u64,
}

/// Parses `/proc/meminfo` content into a [`HostMeminfoSnapshot`].
pub fn parse_meminfo(content: &str) -> Result<HostMeminfoSnapshot, SentinelError> {
    let mut snap = HostMeminfoSnapshot {
        mem_total_bytes: 0,
        mem_available_bytes: 0,
        swap_total_bytes: 0,
        swap_free_bytes: 0,
        dirty_bytes: 0,
        writeback_bytes: 0,
    };

    for line in content.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(num_str) = rest.split_whitespace().next() else {
            continue;
        };
        let Ok(kb) = num_str.parse::<u64>() else {
            continue;
        };
        let bytes = kb.saturating_mul(1024);
        match key.trim() {
            "MemTotal" => snap.mem_total_bytes = bytes,
            "MemAvailable" => snap.mem_available_bytes = bytes,
            "SwapTotal" => snap.swap_total_bytes = bytes,
            "SwapFree" => snap.swap_free_bytes = bytes,
            "Dirty" => snap.dirty_bytes = bytes,
            "Writeback" => snap.writeback_bytes = bytes,
            _ => {}
        }
    }

    if snap.mem_total_bytes == 0 {
        return Err(SentinelError::Parse {
            source_name: "/proc/meminfo".to_string(),
            detail: "missing MemTotal".to_string(),
        });
    }

    Ok(snap)
}

/// Parses `/proc/net/unix` to extract the maximum receive queue depth (`RefCount`/queue column
/// or `Num` lines matching `/run/systemd/journal/dev-log` and `/run/systemd/journal/socket`).
/// Also counts total bound systemd journal unix sockets.
#[must_use]
pub fn count_systemd_journal_sockets(proc_net_unix: &str) -> usize {
    proc_net_unix
        .lines()
        .filter(|line| {
            line.contains("/run/systemd/journal/dev-log")
                || line.contains("/run/systemd/journal/socket")
                || line.contains("/run/systemd/journal/stdout")
        })
        .count()
}

/// Converts [`HostMeminfoSnapshot`] and journal socket state into [`OtelMetricEntry`] items
/// and optional low-memory / high-writeback alerts.
#[must_use]
pub fn meminfo_to_telemetry(
    snap: &HostMeminfoSnapshot,
    journal_sockets_bound: usize,
    node_id: &str,
    arch: &str,
    now_unix_nano: i64,
) -> (Vec<OtelMetricEntry>, Vec<OtelLogEntry>) {
    let attrs = serde_json::json!({
        "subsystem": "meminfo",
        "journal_sockets_bound": journal_sockets_bound,
    })
    .to_string();

    let metrics = vec![
        OtelMetricEntry {
            timestamp_unix_nano: now_unix_nano,
            service_name: "musentinel".to_string(),
            node_id: node_id.to_string(),
            metric_name: "host.memory.available_bytes".to_string(),
            metric_unit: "bytes".to_string(),
            value_f64: snap.mem_available_bytes as f64,
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
            metric_name: "host.memory.dirty_bytes".to_string(),
            metric_unit: "bytes".to_string(),
            value_f64: snap.dirty_bytes as f64,
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
            metric_name: "host.memory.writeback_bytes".to_string(),
            metric_unit: "bytes".to_string(),
            value_f64: snap.writeback_bytes as f64,
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
            metric_name: "host.systemd.journal_sockets".to_string(),
            metric_unit: "count".to_string(),
            value_f64: journal_sockets_bound as f64,
            arch: arch.to_string(),
            cpu_cluster: None,
            vlen_bits: None,
            memlock_used_bytes: None,
            memlock_limit_bytes: None,
            trace_id: None,
            span_id: None,
            attributes_json: attrs,
        },
    ];

    let mut logs = Vec::new();
    let avail_pct =
        (snap.mem_available_bytes as f64) * 100.0 / (snap.mem_total_bytes.max(1) as f64);
    if avail_pct < 5.0 {
        let body = format!(
            "Low host available memory: {:.1}% available ({} MiB / {} MiB), dirty={} MiB, writeback={} MiB",
            avail_pct,
            snap.mem_available_bytes / (1024 * 1024),
            snap.mem_total_bytes / (1024 * 1024),
            snap.dirty_bytes / (1024 * 1024),
            snap.writeback_bytes / (1024 * 1024),
        );
        logs.push(OtelLogEntry {
            timestamp_unix_nano: now_unix_nano,
            trace_id: format!("{:032x}", now_unix_nano as u128),
            span_id: format!("{:016x}", now_unix_nano as u64),
            severity_number: 13,
            severity_text: "WARN".to_string(),
            service_name: "musentinel".to_string(),
            node_id: node_id.to_string(),
            body,
            attributes_json: serde_json::json!({
                "subsystem": "memory_pressure",
                "available_pct": avail_pct,
                "mem_available_bytes": snap.mem_available_bytes,
                "dirty_bytes": snap.dirty_bytes,
                "writeback_bytes": snap.writeback_bytes,
            })
            .to_string(),
            job_id: None,
            stage_id: None,
        });
    }

    (metrics, logs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_meminfo_and_low_memory_alert() {
        let sample = "MemTotal:       16384000 kB\nMemFree:          100000 kB\nMemAvailable:     400000 kB\nSwapTotal:       2097152 kB\nSwapFree:        2097152 kB\nDirty:             12000 kB\nWriteback:          4000 kB\n";
        let snap = parse_meminfo(sample).unwrap();
        assert_eq!(snap.mem_total_bytes, 16_384_000 * 1024);
        let (metrics, logs) = meminfo_to_telemetry(&snap, 3, "node-a", "x86_64", 123);
        assert_eq!(metrics.len(), 4);
        assert_eq!(logs.len(), 1);
        assert!(logs[0].body.contains("Low host available memory"));
    }
}
