//! Kernel ring-buffer (`/dev/kmsg`) parser and anomaly classifier.
//!
//! Linux `/dev/kmsg` emits structured lines formatted as:
//! `<prio>,<seq>,<ts_usec>,<flags>;<message>\n`
//! followed by optional ` KEY=VALUE` continuation lines starting with a single space.

use crate::error::SentinelError;
use mu_observable_ipc::OtelLogEntry;
use serde::{Deserialize, Serialize};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;

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

/// Persisted `/dev/kmsg` sequence checkpoint scoped to the host's current boot ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsgCheckpoint {
    /// Host kernel boot UUID (`/proc/sys/kernel/random/boot_id`), when available.
    pub boot_id: Option<String>,
    /// Highest `/dev/kmsg` sequence number already processed.
    pub last_seq: u64,
}

/// Reads the current host kernel boot UUID from `<proc_root>/sys/kernel/random/boot_id`.
#[must_use]
pub fn read_boot_id(proc_root: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(
        proc_root
            .join("sys")
            .join("kernel")
            .join("random")
            .join("boot_id"),
    )
    .ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Loads the persisted `/dev/kmsg` sequence checkpoint from `path`, returning `None` if
/// the file is absent/invalid or belongs to a previous `boot_id`.
#[must_use]
pub fn load_kmsg_checkpoint(path: &Path, current_boot_id: Option<&str>) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(ckpt) = serde_json::from_str::<KmsgCheckpoint>(trimmed) {
        if let (Some(curr), Some(saved)) = (current_boot_id, ckpt.boot_id.as_deref()) {
            if curr != saved {
                return None;
            }
        }
        return Some(ckpt.last_seq);
    }
    trimmed.parse::<u64>().ok()
}

/// Persists the highest ingested `/dev/kmsg` sequence checkpoint to `path`.
pub fn save_kmsg_checkpoint(
    path: &Path,
    last_seq: u64,
    current_boot_id: Option<&str>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let ckpt = KmsgCheckpoint {
        boot_id: current_boot_id.map(str::to_string),
        last_seq,
    };
    let payload = serde_json::to_string(&ckpt)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    std::fs::write(path, payload)
}

/// Opens a kernel ring-buffer file (e.g. `/dev/kmsg`) and optionally seeks to [`SeekFrom::End`]
/// (`SeekFrom::End(0)`) so historical boot-era ring-buffer records are not replayed at daemon startup.
pub async fn open_kmsg_reader(
    path: &Path,
    seek_to_tail: bool,
) -> std::io::Result<BufReader<tokio::fs::File>> {
    let mut file = tokio::fs::File::open(path).await?;
    if seek_to_tail {
        file.seek(SeekFrom::End(0)).await?;
    }
    Ok(BufReader::new(file))
}

/// Streams `/dev/kmsg` lines from `path` into `tx`, seeking to tail on startup when `seek_to_tail`
/// is enabled and recovering gracefully from `BrokenPipe` (`EPIPE`) ring-buffer overruns.
pub async fn stream_kmsg_lines(path: PathBuf, seek_to_tail: bool, tx: mpsc::Sender<String>) {
    let mut reader = match open_kmsg_reader(&path, seek_to_tail).await {
        Ok(reader) => reader,
        Err(err) => {
            tracing::debug!(
                path = %path.display(),
                error = %err,
                "/dev/kmsg stream unavailable; continuing with procfs/sysfs sweeps"
            );
            return;
        }
    };

    let mut raw_buf = Vec::with_capacity(512);
    loop {
        raw_buf.clear();
        match reader.read_until(b'\n', &mut raw_buf).await {
            Ok(0) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&raw_buf)
                    .trim_end_matches(&['\r', '\n'][..])
                    .to_string();
                if tx.send(line).await.is_err() {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "/dev/kmsg ring buffer overflowed (EPIPE); advancing to oldest available record"
                );
            }
            Err(err) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %err,
                    "Stopping /dev/kmsg reader after I/O error"
                );
                break;
            }
        }
    }
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

    #[test]
    fn test_kmsg_checkpoint_roundtrip_and_boot_id_reset() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ckpt_path = tmp.path().join("state").join("kmsg.ckpt");

        assert!(load_kmsg_checkpoint(&ckpt_path, Some("boot-1")).is_none());

        save_kmsg_checkpoint(&ckpt_path, 4096, Some("boot-1")).expect("save ckpt");
        assert_eq!(load_kmsg_checkpoint(&ckpt_path, Some("boot-1")), Some(4096));
        assert_eq!(load_kmsg_checkpoint(&ckpt_path, None), Some(4096));
        // Different boot_id invalidates stale sequence number
        assert!(load_kmsg_checkpoint(&ckpt_path, Some("boot-2")).is_none());

        // Plain integer checkpoint file is also supported
        std::fs::write(&ckpt_path, "777\n").unwrap();
        assert_eq!(load_kmsg_checkpoint(&ckpt_path, None), Some(777));
    }

    #[test]
    fn test_read_boot_id_from_proc_root() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let boot_dir = tmp.path().join("sys/kernel/random");
        std::fs::create_dir_all(&boot_dir).unwrap();
        std::fs::write(
            boot_dir.join("boot_id"),
            "11111111-2222-3333-4444-555555555555\n",
        )
        .unwrap();

        assert_eq!(
            read_boot_id(tmp.path()).as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
    }
}
