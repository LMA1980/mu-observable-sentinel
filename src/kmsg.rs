//! Kernel ring-buffer (`/dev/kmsg`) parser and anomaly classifier.
//!
//! Linux `/dev/kmsg` emits structured lines formatted as:
//! `<prio>,<seq>,<ts_usec>,<flags>;<message>\n`
//! followed by optional ` KEY=VALUE` continuation lines starting with a single space.

use crate::error::SentinelError;
use mu_observable_ipc::OtelLogEntry;
use serde::{Deserialize, Serialize};

/// Canonical severity category classified from a kernel ring-buffer message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KmsgCategory {
    /// Block device or SCSI/SATA/USB transport error (`critical target error`, `I/O error`, `Sense Key`, `DISCARD`).
    BlockStorageError,
    /// Btrfs filesystem error or warning (`BTRFS error`, `BTRFS warning`).
    BtrfsAnomaly,
    /// Out-of-memory killer invocation (`Out of memory: Killed process`, `oom-kill`).
    OomKiller,
    /// CPU instruction trap or segfault (`unhandled signal`, `SIGILL`, `segfault at`).
    HardwareOrSignalTrap,
    /// Systemd or journald watchdog/service timeout logged to kmsg.
    SystemdWatchdog,
    /// General kernel warning or error (`loglevel <= 4`).
    GeneralKernelAlert,
}

impl KmsgCategory {
    /// Returns the canonical string tag stored in `attributes_json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlockStorageError => "block_storage_error",
            Self::BtrfsAnomaly => "btrfs_anomaly",
            Self::OomKiller => "oom_killer",
            Self::HardwareOrSignalTrap => "hardware_or_signal_trap",
            Self::SystemdWatchdog => "systemd_watchdog",
            Self::GeneralKernelAlert => "general_kernel_alert",
        }
    }
}

/// Parsed representation of a single `/dev/kmsg` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsgRecord {
    /// Full syslog priority/facility prefix (`prio & 7` is the kernel loglevel `0..=7`).
    pub priority: u32,
    /// Kernel loglevel (`0` = EMERG .. `4` = WARNING .. `7` = DEBUG).
    pub loglevel: u8,
    /// Monotonic `/dev/kmsg` sequence number.
    pub seq: u64,
    /// Monotonic timestamp in microseconds since boot.
    pub timestamp_usec: u64,
    /// Unescaped kernel message text.
    pub message: String,
    /// Classified anomaly category.
    pub category: KmsgCategory,
}

impl KmsgRecord {
    /// Returns `true` if this record should be forwarded to `MuObserve-collector`
    /// (`loglevel <= 4` OR matched a specific storage/Btrfs/OOM/trap pattern).
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        self.loglevel <= 4 || self.category != KmsgCategory::GeneralKernelAlert
    }

    /// Converts this kernel record into an [`OtelLogEntry`] correlated with `node_id`.
    #[must_use]
    pub fn to_otel_log(&self, node_id: &str, now_unix_nano: i64) -> OtelLogEntry {
        let (severity_number, severity_text) = match self.loglevel {
            0..=2 => (21, "FATAL"),
            3 => (17, "ERROR"),
            4 => (13, "WARN"),
            _ => (9, "INFO"),
        };
        let attrs = serde_json::json!({
            "subsystem": "kernel_kmsg",
            "category": self.category.as_str(),
            "kmsg_seq": self.seq,
            "kmsg_ts_usec": self.timestamp_usec,
            "kmsg_loglevel": self.loglevel,
        });
        OtelLogEntry {
            timestamp_unix_nano: now_unix_nano,
            trace_id: format!("{:032x}", u128::from(self.seq).wrapping_add(1)),
            span_id: format!("{:016x}", self.seq.wrapping_add(1)),
            severity_number,
            severity_text: severity_text.to_string(),
            service_name: "musentinel".to_string(),
            node_id: node_id.to_string(),
            body: self.message.clone(),
            attributes_json: attrs.to_string(),
            job_id: None,
            stage_id: None,
        }
    }
}

/// Classifies a kernel message string into a [`KmsgCategory`].
#[must_use]
pub fn classify_kmsg_body(msg: &str) -> KmsgCategory {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("critical target error")
        || lower.contains("i/o error")
        || lower.contains("sense key")
        || lower.contains("op 0x3:(discard)")
        || lower.contains("failed command:")
        || lower.contains(" Buffer I/O error".to_ascii_lowercase().as_str())
        || lower.contains("reset high-speed usb device")
        || lower.contains("reset superspeed usb device")
    {
        KmsgCategory::BlockStorageError
    } else if lower.contains("btrfs error")
        || lower.contains("btrfs warning")
        || lower.contains("btrfs: Transaction aborted".to_ascii_lowercase().as_str())
    {
        KmsgCategory::BtrfsAnomaly
    } else if lower.contains("out of memory: killed process")
        || lower.contains("oom-kill:")
        || lower.contains("invoked oom-killer")
    {
        KmsgCategory::OomKiller
    } else if lower.contains("unhandled signal")
        || lower.contains("sigill")
        || lower.contains("illegal instruction")
        || lower.contains("segfault at")
        || lower.contains("kernel bug at")
    {
        KmsgCategory::HardwareOrSignalTrap
    } else if lower.contains("watchdog timeout") || lower.contains("systemd-journald") {
        KmsgCategory::SystemdWatchdog
    } else {
        KmsgCategory::GeneralKernelAlert
    }
}

/// Parses a single `/dev/kmsg` header+message line (`<prio>,<seq>,<ts_usec>,<flags>;<message>`).
/// Returns `Ok(None)` for continuation lines (starting with `' '`).
pub fn parse_kmsg_line(line: &str) -> Result<Option<KmsgRecord>, SentinelError> {
    let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
    if trimmed.is_empty() || trimmed.starts_with(' ') {
        return Ok(None);
    }
    let Some((header, raw_msg)) = trimmed.split_once(';') else {
        return Err(SentinelError::Parse {
            source_name: "/dev/kmsg".to_string(),
            detail: format!("missing ';' separator in line: {trimmed}"),
        });
    };
    let mut parts = header.split(',');
    let prio_str = parts.next().ok_or_else(|| SentinelError::Parse {
        source_name: "/dev/kmsg".to_string(),
        detail: "missing priority field".to_string(),
    })?;
    let seq_str = parts.next().ok_or_else(|| SentinelError::Parse {
        source_name: "/dev/kmsg".to_string(),
        detail: "missing sequence field".to_string(),
    })?;
    let ts_str = parts.next().ok_or_else(|| SentinelError::Parse {
        source_name: "/dev/kmsg".to_string(),
        detail: "missing timestamp field".to_string(),
    })?;

    let priority = prio_str.parse::<u32>().map_err(|e| SentinelError::Parse {
        source_name: "/dev/kmsg".to_string(),
        detail: format!("invalid priority '{prio_str}': {e}"),
    })?;
    let seq = seq_str.parse::<u64>().map_err(|e| SentinelError::Parse {
        source_name: "/dev/kmsg".to_string(),
        detail: format!("invalid seq '{seq_str}': {e}"),
    })?;
    let timestamp_usec = ts_str.parse::<u64>().map_err(|e| SentinelError::Parse {
        source_name: "/dev/kmsg".to_string(),
        detail: format!("invalid timestamp '{ts_str}': {e}"),
    })?;

    let loglevel = (priority & 0x7) as u8;
    let message = raw_msg.replace("\\x0a", " ").trim().to_string();
    let category = classify_kmsg_body(&message);

    Ok(Some(KmsgRecord {
        priority,
        loglevel,
        seq,
        timestamp_usec,
        message,
        category,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kmsg_discard_error() {
        let line = "3,1492,283910442,-;critical target error, dev sdd, sector 2099200 op 0x3:(DISCARD) flags 0x800 phys_seg 1 prio class 0\n";
        let rec = parse_kmsg_line(line)
            .expect("valid parse")
            .expect("not continuation");
        assert_eq!(rec.loglevel, 3);
        assert_eq!(rec.seq, 1492);
        assert_eq!(rec.category, KmsgCategory::BlockStorageError);
        assert!(rec.is_actionable());

        let log = rec.to_otel_log("node-a", 1_700_000_000_000_000_000);
        assert_eq!(log.severity_text, "ERROR");
        assert_eq!(log.service_name, "musentinel");
        assert!(log.attributes_json.contains("block_storage_error"));
    }

    #[test]
    fn test_ignore_continuation_and_debug_lines() {
        let cont = " SUBSYSTEM=block\n";
        assert!(parse_kmsg_line(cont).expect("valid").is_none());

        let debug_line = "7,1493,283910500,-;usb 2-2: routine debug poll\n";
        let rec = parse_kmsg_line(debug_line).unwrap().unwrap();
        assert_eq!(rec.loglevel, 7);
        assert!(!rec.is_actionable());
    }
}
