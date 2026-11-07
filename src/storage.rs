//! Block device latency (`/proc/diskstats`) and Btrfs device error counter
//! (`/sys/fs/btrfs/<uuid>/devinfo/<devid>/error_stats`) telemetry and alerting.

use crate::error::SentinelError;
use mu_observable_ipc::{OtelLogEntry, OtelMetricEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Raw cumulative counters parsed from a single line of `/proc/diskstats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskStatsCounter {
    pub major: u32,
    pub minor: u32,
    pub device: String,
    pub reads_completed: u64,
    pub read_time_ms: u64,
    pub writes_completed: u64,
    pub write_time_ms: u64,
    pub ios_in_progress: u64,
    pub io_time_ms: u64,
}

/// Computed delta metrics for a block device over an elapsed sampling interval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskLatencyDelta {
    pub device: String,
    pub read_await_ms: f64,
    pub write_await_ms: f64,
    pub ios_in_progress: u64,
    pub io_util_pct: f64,
}

/// Btrfs device error counters parsed from `/sys/fs/btrfs/<uuid>/devinfo/<devid>/error_stats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsDeviceErrors {
    pub fs_uuid: String,
    pub devid: String,
    pub write_io_errs: u64,
    pub read_io_errs: u64,
    pub flush_io_errs: u64,
    pub corruption_errs: u64,
    pub generation_errs: u64,
}

impl BtrfsDeviceErrors {
    /// Total sum of all 5 Btrfs error counters on this device.
    #[must_use]
    pub const fn total_errors(&self) -> u64 {
        self.write_io_errs
            .saturating_add(self.read_io_errs)
            .saturating_add(self.flush_io_errs)
            .saturating_add(self.corruption_errs)
            .saturating_add(self.generation_errs)
    }
}

/// Returns `true` if `dev` is a physical whole-disk block device worth tracking
/// (`sd[a-z]+`, `nvme[0-9]+n[0-9]+`, `vd[a-z]+`, `mmcblk[0-9]+`), excluding partitions and loop/ram devices.
#[must_use]
pub fn is_monitored_whole_disk(dev: &str) -> bool {
    if let Some(suffix) = dev.strip_prefix("sd").or_else(|| dev.strip_prefix("vd")) {
        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_lowercase())
    } else if let Some(rest) = dev.strip_prefix("nvme") {
        // e.g. nvme0n1 (no 'p' partition suffix)
        rest.contains('n') && !rest.contains('p')
    } else if let Some(rest) = dev.strip_prefix("mmcblk") {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

/// Parses `/proc/diskstats` text into a map keyed by whole-disk device name.
pub fn parse_diskstats(content: &str) -> Result<HashMap<String, DiskStatsCounter>, SentinelError> {
    let mut map = HashMap::new();
    for raw_line in content.lines() {
        let cols: Vec<&str> = raw_line.split_whitespace().collect();
        if cols.len() < 14 {
            continue;
        }
        let dev = cols[2];
        if !is_monitored_whole_disk(dev) {
            continue;
        }
        let major = cols[0].parse::<u32>().unwrap_or(0);
        let minor = cols[1].parse::<u32>().unwrap_or(0);
        let reads_completed = cols[3].parse::<u64>().unwrap_or(0);
        let read_time_ms = cols[6].parse::<u64>().unwrap_or(0);
        let writes_completed = cols[7].parse::<u64>().unwrap_or(0);
        let write_time_ms = cols[10].parse::<u64>().unwrap_or(0);
        let ios_in_progress = cols[11].parse::<u64>().unwrap_or(0);
        let io_time_ms = cols[12].parse::<u64>().unwrap_or(0);

        map.insert(
            dev.to_string(),
            DiskStatsCounter {
                major,
                minor,
                device: dev.to_string(),
                reads_completed,
                read_time_ms,
                writes_completed,
                write_time_ms,
                ios_in_progress,
                io_time_ms,
            },
        );
    }
    Ok(map)
}

/// Computes [`DiskLatencyDelta`] values between `prev` and `curr` snapshots over `elapsed_ms`.
#[must_use]
pub fn compute_disk_latency_deltas(
    prev: &HashMap<String, DiskStatsCounter>,
    curr: &HashMap<String, DiskStatsCounter>,
    elapsed_ms: u64,
) -> Vec<DiskLatencyDelta> {
    let elapsed_f64 = (elapsed_ms.max(1)) as f64;
    let mut out = Vec::new();

    for (dev, now) in curr {
        let Some(old) = prev.get(dev) else {
            continue;
        };
        let d_reads = now.reads_completed.saturating_sub(old.reads_completed);
        let d_read_ms = now.read_time_ms.saturating_sub(old.read_time_ms);
        let d_writes = now.writes_completed.saturating_sub(old.writes_completed);
        let d_write_ms = now.write_time_ms.saturating_sub(old.write_time_ms);
        let d_io_ms = now.io_time_ms.saturating_sub(old.io_time_ms);

        let read_await_ms = if d_reads > 0 {
            (d_read_ms as f64) / (d_reads as f64)
        } else {
            0.0
        };
        let write_await_ms = if d_writes > 0 {
            (d_write_ms as f64) / (d_writes as f64)
        } else {
            0.0
        };
        let io_util_pct = ((d_io_ms as f64) * 100.0 / elapsed_f64).clamp(0.0, 100.0);

        out.push(DiskLatencyDelta {
            device: dev.clone(),
            read_await_ms,
            write_await_ms,
            ios_in_progress: now.ios_in_progress,
            io_util_pct,
        });
    }
    out.sort_by(|a, b| a.device.cmp(&b.device));
    out
}

/// Converts [`DiskLatencyDelta`] items into [`OtelMetricEntry`] samples and optional high-await alerts.
#[must_use]
pub fn disk_deltas_to_telemetry(
    deltas: &[DiskLatencyDelta],
    await_warn_ms: f64,
    node_id: &str,
    arch: &str,
    now_unix_nano: i64,
) -> (Vec<OtelMetricEntry>, Vec<OtelLogEntry>) {
    let mut metrics = Vec::new();
    let mut logs = Vec::new();

    for d in deltas {
        let attrs = serde_json::json!({
            "subsystem": "diskstats",
            "device": d.device,
        })
        .to_string();

        for (name, unit, val) in [
            ("host.disk.read_await_ms", "ms", d.read_await_ms),
            ("host.disk.write_await_ms", "ms", d.write_await_ms),
            ("host.disk.in_flight", "count", d.ios_in_progress as f64),
            ("host.disk.io_util_pct", "%", d.io_util_pct),
        ] {
            metrics.push(OtelMetricEntry {
                timestamp_unix_nano: now_unix_nano,
                service_name: "musentinel".to_string(),
                node_id: node_id.to_string(),
                metric_name: name.to_string(),
                metric_unit: unit.to_string(),
                value_f64: val,
                arch: arch.to_string(),
                cpu_cluster: None,
                vlen_bits: None,
                memlock_used_bytes: None,
                memlock_limit_bytes: None,
                trace_id: None,
                span_id: None,
                attributes_json: attrs.clone(),
            });
        }

        if d.read_await_ms >= await_warn_ms || d.write_await_ms >= await_warn_ms {
            let body = format!(
                "Block device {} high I/O latency: read_await={:.1}ms write_await={:.1}ms in_flight={} util={:.1}%",
                d.device, d.read_await_ms, d.write_await_ms, d.ios_in_progress, d.io_util_pct
            );
            let alert_attrs = serde_json::json!({
                "subsystem": "disk_latency",
                "device": d.device,
                "read_await_ms": d.read_await_ms,
                "write_await_ms": d.write_await_ms,
                "in_flight": d.ios_in_progress,
                "io_util_pct": d.io_util_pct,
            });
            logs.push(OtelLogEntry {
                timestamp_unix_nano: now_unix_nano,
                trace_id: format!("{:032x}", now_unix_nano as u128),
                span_id: format!("{:016x}", now_unix_nano as u64),
                severity_number: 13,
                severity_text: "WARN".to_string(),
                service_name: "musentinel".to_string(),
                node_id: node_id.to_string(),
                body,
                attributes_json: alert_attrs.to_string(),
                job_id: None,
                stage_id: None,
            });
        }
    }

    (metrics, logs)
}

/// Parses a single `/sys/fs/btrfs/<uuid>/devinfo/<devid>/error_stats` file.
pub fn parse_btrfs_error_stats(
    fs_uuid: &str,
    devid: &str,
    content: &str,
) -> Result<BtrfsDeviceErrors, SentinelError> {
    let mut stats = BtrfsDeviceErrors {
        fs_uuid: fs_uuid.to_string(),
        devid: devid.to_string(),
        write_io_errs: 0,
        read_io_errs: 0,
        flush_io_errs: 0,
        corruption_errs: 0,
        generation_errs: 0,
    };

    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(val_str) = parts.next() else {
            continue;
        };
        let val = val_str.parse::<u64>().map_err(|e| SentinelError::Parse {
            source_name: format!("btrfs/{fs_uuid}/devinfo/{devid}/error_stats"),
            detail: format!("invalid counter '{val_str}': {e}"),
        })?;
        match key {
            "write_io_errs" => stats.write_io_errs = val,
            "read_io_errs" => stats.read_io_errs = val,
            "flush_io_errs" => stats.flush_io_errs = val,
            "corruption_errs" => stats.corruption_errs = val,
            "generation_errs" => stats.generation_errs = val,
            _ => {}
        }
    }

    Ok(stats)
}

/// Scans `<sys_root>/fs/btrfs/*/devinfo/*/error_stats` and collects all [`BtrfsDeviceErrors`].
pub fn scan_btrfs_error_stats(sys_root: &Path) -> Vec<BtrfsDeviceErrors> {
    let mut out = Vec::new();
    let btrfs_dir = sys_root.join("fs").join("btrfs");
    let Ok(fs_entries) = std::fs::read_dir(btrfs_dir) else {
        return out;
    };

    for fs_entry in fs_entries.flatten() {
        let fs_uuid = fs_entry.file_name().to_string_lossy().to_string();
        if fs_uuid == "features" {
            continue;
        }
        let devinfo_dir = fs_entry.path().join("devinfo");
        let Ok(dev_entries) = std::fs::read_dir(devinfo_dir) else {
            continue;
        };
        for dev_entry in dev_entries.flatten() {
            let devid = dev_entry.file_name().to_string_lossy().to_string();
            let err_path = dev_entry.path().join("error_stats");
            if let Ok(content) = std::fs::read_to_string(err_path) {
                if let Ok(parsed) = parse_btrfs_error_stats(&fs_uuid, &devid, &content) {
                    out.push(parsed);
                }
            }
        }
    }
    out
}

/// Converts [`BtrfsDeviceErrors`] into [`OtelMetricEntry`] items and alerts on any non-zero counter.
#[must_use]
pub fn btrfs_errors_to_telemetry(
    items: &[BtrfsDeviceErrors],
    node_id: &str,
    arch: &str,
    now_unix_nano: i64,
) -> (Vec<OtelMetricEntry>, Vec<OtelLogEntry>) {
    let mut metrics = Vec::new();
    let mut logs = Vec::new();

    for item in items {
        let total = item.total_errors();
        let attrs = serde_json::json!({
            "subsystem": "btrfs_errors",
            "fs_uuid": item.fs_uuid,
            "devid": item.devid,
            "write_io_errs": item.write_io_errs,
            "read_io_errs": item.read_io_errs,
            "flush_io_errs": item.flush_io_errs,
            "corruption_errs": item.corruption_errs,
            "generation_errs": item.generation_errs,
        });

        metrics.push(OtelMetricEntry {
            timestamp_unix_nano: now_unix_nano,
            service_name: "musentinel".to_string(),
            node_id: node_id.to_string(),
            metric_name: "host.btrfs.device_errors".to_string(),
            metric_unit: "count".to_string(),
            value_f64: total as f64,
            arch: arch.to_string(),
            cpu_cluster: None,
            vlen_bits: None,
            memlock_used_bytes: None,
            memlock_limit_bytes: None,
            trace_id: None,
            span_id: None,
            attributes_json: attrs.to_string(),
        });

        if total > 0 {
            let body = format!(
                "Btrfs device error counter non-zero on fs={} devid={}: write={} read={} flush={} corruption={} generation={}",
                item.fs_uuid,
                item.devid,
                item.write_io_errs,
                item.read_io_errs,
                item.flush_io_errs,
                item.corruption_errs,
                item.generation_errs
            );
            logs.push(OtelLogEntry {
                timestamp_unix_nano: now_unix_nano,
                trace_id: format!("{:032x}", now_unix_nano as u128),
                span_id: format!("{:016x}", now_unix_nano as u64),
                severity_number: 17,
                severity_text: "ERROR".to_string(),
                service_name: "musentinel".to_string(),
                node_id: node_id.to_string(),
                body,
                attributes_json: attrs.to_string(),
                job_id: None,
                stage_id: None,
            });
        }
    }

    (metrics, logs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diskstats_delta_and_high_await_alert() {
        let t0 = "   8       48 sdd 100 0 800 500 200 0 1600 1000 0 800 1500 0 0 0 0 0 0\n";
        let t1 = "   8       48 sdd 110 0 880 1500 210 0 1680 12000 4 5800 13500 0 0 0 0 0 0\n";

        let m0 = parse_diskstats(t0).unwrap();
        let m1 = parse_diskstats(t1).unwrap();
        let deltas = compute_disk_latency_deltas(&m0, &m1, 5_000);
        assert_eq!(deltas.len(), 1);
        let d = &deltas[0];
        assert_eq!(d.device, "sdd");
        assert!((d.read_await_ms - 100.0).abs() < 1e-6);
        assert!((d.write_await_ms - 1100.0).abs() < 1e-6);
        assert!((d.io_util_pct - 100.0).abs() < 1e-6);

        let (metrics, logs) = disk_deltas_to_telemetry(&deltas, 500.0, "node-a", "x86_64", 12345);
        assert_eq!(metrics.len(), 4);
        assert_eq!(logs.len(), 1);
        assert!(logs[0].body.contains("write_await=1100.0ms"));
    }

    #[test]
    fn test_parse_btrfs_error_stats_alert() {
        let raw = "write_io_errs    2\nread_io_errs     0\nflush_io_errs    0\ncorruption_errs  1\ngeneration_errs  0\n";
        let stats = parse_btrfs_error_stats("uuid-1234", "1", raw).unwrap();
        assert_eq!(stats.total_errors(), 3);
        let (metrics, logs) = btrfs_errors_to_telemetry(&[stats], "node-a", "x86_64", 999);
        assert_eq!(metrics.len(), 1);
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].severity_text, "ERROR");
    }
}
