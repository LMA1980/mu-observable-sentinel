//! Runtime configuration and threshold parameters for `MuSentinel`.

use std::path::PathBuf;
use std::time::Duration;

/// Default local `MuObserve-collector` HTTP base URL.
pub const DEFAULT_COLLECTOR_URL: &str = "http://127.0.0.1:4318";

/// Default polling interval in seconds (`5s`).
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;

/// Default block I/O `await` warning threshold in milliseconds (`500 ms`).
pub const DEFAULT_DISK_AWAIT_WARN_MS: f64 = 500.0;

/// Default runaway process elapsed threshold in seconds (`2100s` / 35 minutes),
/// calibrated above `1800s` CI `coverage-check` / `miri-check` stage ceilings.
pub const DEFAULT_RUNAWAY_SECS: u64 = 2_100;

/// Default PSI `avg10` warning threshold percentage (`10.0%`).
pub const DEFAULT_PSI_WARN_PCT: f64 = 10.0;

/// Default critical PSI `io_full_avg10` escalation threshold percentage (`25.0%`).
pub const DEFAULT_PSI_CRITICAL_PCT: f64 = 25.0;

/// Default number of consecutive sweeps required before a PSI/D-state condition alerts (`3`).
pub const DEFAULT_PSI_PERSISTENCE_SAMPLES: u32 = 3;

/// Default alert cooldown interval in seconds (`300s` / 5 minutes).
pub const DEFAULT_ALERT_COOLDOWN_SECS: u64 = 300;

/// Default startup behavior for `/dev/kmsg`: seek to tail (`SeekFrom::End(0)`).
pub const DEFAULT_KMSG_SEEK_TO_TAIL: bool = true;

/// Runtime configuration for `MuSentinel` loaded from environment variables.
#[derive(Debug, Clone)]
pub struct SentinelConfig {
    /// Node identifier reported in `OtelMetricEntry` and `OtelLogEntry` (`MUOBSERVE_NODE_ID`).
    pub node_id: String,
    /// Host CPU architecture (`x86_64` or `riscv64gc`).
    pub arch: String,
    /// Base URL for `MuObserve-collector` (`MUOBSERVE_COLLECTOR_URL`).
    pub collector_url: String,
    /// Polling interval between procfs/sysfs sweeps (`MUSENTINEL_POLL_SECS`).
    pub poll_interval: Duration,
    /// Disk read/write `await` threshold in milliseconds before emitting a warning log (`MUSENTINEL_DISK_AWAIT_WARN_MS`).
    pub disk_await_warn_ms: f64,
    /// PSI `avg10` stall percentage threshold before emitting a warning log (`MUSENTINEL_PSI_WARN_PCT`).
    pub psi_warn_pct: f64,
    /// Consecutive sweeps required before PSI or user-space D-state conditions alert (`MUSENTINEL_PSI_PERSISTENCE_SAMPLES`).
    pub psi_persistence_samples: u32,
    /// Cooldown window in seconds between repeated `psi_dstate` or `runaway_process` alerts (`MUSENTINEL_ALERT_COOLDOWN_SECS`).
    pub alert_cooldown_secs: u64,
    /// Maximum runtime in seconds for monitored build/test processes before alerting (`MUSENTINEL_RUNAWAY_SECS`).
    pub runaway_process_secs: u64,
    /// Root path for procfs (defaults to `/proc`).
    pub proc_root: PathBuf,
    /// Root path for sysfs (defaults to `/sys`).
    pub sys_root: PathBuf,
    /// Path to `/dev/kmsg` (defaults to `/dev/kmsg`).
    pub kmsg_path: PathBuf,
    /// Seek `/dev/kmsg` to `SeekFrom::End(0)` on startup to avoid replaying boot records (`MUSENTINEL_KMSG_SEEK_TAIL`).
    pub kmsg_seek_to_tail: bool,
    /// Optional path to persist the last ingested `/dev/kmsg` sequence checkpoint (`MUSENTINEL_KMSG_CHECKPOINT_PATH`).
    pub kmsg_checkpoint_path: Option<PathBuf>,
    /// Whether to enforce Landlock V3+ rules at startup (`MUSENTINEL_ENFORCE_LANDLOCK`).
    pub enforce_landlock_on_linux: bool,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        let host_arch = std::env::consts::ARCH;
        let arch = if matches!(host_arch, "x86_64" | "riscv64" | "riscv64gc") {
            host_arch.to_string()
        } else {
            "riscv64gc".to_string()
        };
        Self {
            node_id: "worker-node".to_string(),
            arch,
            collector_url: DEFAULT_COLLECTOR_URL.to_string(),
            poll_interval: Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS),
            disk_await_warn_ms: DEFAULT_DISK_AWAIT_WARN_MS,
            psi_warn_pct: DEFAULT_PSI_WARN_PCT,
            psi_persistence_samples: DEFAULT_PSI_PERSISTENCE_SAMPLES,
            alert_cooldown_secs: DEFAULT_ALERT_COOLDOWN_SECS,
            runaway_process_secs: DEFAULT_RUNAWAY_SECS,
            proc_root: PathBuf::from("/proc"),
            sys_root: PathBuf::from("/sys"),
            kmsg_path: PathBuf::from("/dev/kmsg"),
            kmsg_seek_to_tail: DEFAULT_KMSG_SEEK_TO_TAIL,
            kmsg_checkpoint_path: None,
            enforce_landlock_on_linux: false,
        }
    }
}

fn parse_bool_flag(raw: &str) -> Option<bool> {
    let trimmed = raw.trim();
    if trimmed == "1" || trimmed.eq_ignore_ascii_case("true") {
        Some(true)
    } else if trimmed == "0" || trimmed.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

impl SentinelConfig {
    /// Constructs [`SentinelConfig`] from process environment variables with safe defaults.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_with(|key| std::env::var(key).ok())
    }

    /// Constructs [`SentinelConfig`] from a custom key lookup closure (useful for deterministic tests).
    #[must_use]
    pub fn from_env_with<F>(mut lookup: F) -> Self
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut cfg = Self::default();
        if let Some(node_id) = lookup("MUOBSERVE_NODE_ID") {
            if !node_id.trim().is_empty() {
                cfg.node_id = node_id.trim().to_string();
            }
        }
        if let Some(url) = lookup("MUOBSERVE_COLLECTOR_URL") {
            if !url.trim().is_empty() {
                cfg.collector_url = url.trim().trim_end_matches('/').to_string();
            }
        }
        if let Some(secs) = lookup("MUSENTINEL_POLL_SECS") {
            if let Ok(parsed) = secs.trim().parse::<u64>() {
                if parsed > 0 {
                    cfg.poll_interval = Duration::from_secs(parsed);
                }
            }
        }
        if let Some(ms) = lookup("MUSENTINEL_DISK_AWAIT_WARN_MS") {
            if let Ok(parsed) = ms.trim().parse::<f64>() {
                if parsed > 0.0 {
                    cfg.disk_await_warn_ms = parsed;
                }
            }
        }
        if let Some(pct) = lookup("MUSENTINEL_PSI_WARN_PCT") {
            if let Ok(parsed) = pct.trim().parse::<f64>() {
                if parsed > 0.0 {
                    cfg.psi_warn_pct = parsed;
                }
            }
        }
        if let Some(samples) = lookup("MUSENTINEL_PSI_PERSISTENCE_SAMPLES") {
            if let Ok(parsed) = samples.trim().parse::<u32>() {
                if parsed > 0 {
                    cfg.psi_persistence_samples = parsed;
                }
            }
        }
        if let Some(cooldown) = lookup("MUSENTINEL_ALERT_COOLDOWN_SECS") {
            if let Ok(parsed) = cooldown.trim().parse::<u64>() {
                cfg.alert_cooldown_secs = parsed;
            }
        }
        if let Some(secs) = lookup("MUSENTINEL_RUNAWAY_SECS") {
            if let Ok(parsed) = secs.trim().parse::<u64>() {
                if parsed > 0 {
                    cfg.runaway_process_secs = parsed;
                }
            }
        }
        if let Some(seek_tail) = lookup("MUSENTINEL_KMSG_SEEK_TAIL") {
            if let Some(parsed) = parse_bool_flag(&seek_tail) {
                cfg.kmsg_seek_to_tail = parsed;
            }
        }
        if let Some(ckpt_path) = lookup("MUSENTINEL_KMSG_CHECKPOINT_PATH") {
            let trimmed = ckpt_path.trim();
            if !trimmed.is_empty() {
                cfg.kmsg_checkpoint_path = Some(PathBuf::from(trimmed));
            }
        }
        if let Some(enforce) = lookup("MUSENTINEL_ENFORCE_LANDLOCK") {
            if let Some(parsed) = parse_bool_flag(&enforce) {
                cfg.enforce_landlock_on_linux = parsed;
            }
        }
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_default_config_invariants() {
        let cfg = SentinelConfig::default();
        assert_eq!(cfg.collector_url, "http://127.0.0.1:4318");
        assert_eq!(cfg.poll_interval, Duration::from_secs(5));
        assert!((cfg.disk_await_warn_ms - 500.0).abs() < f64::EPSILON);
        assert_eq!(cfg.runaway_process_secs, 2_100);
        assert_eq!(cfg.psi_persistence_samples, 3);
        assert_eq!(cfg.alert_cooldown_secs, 300);
        assert!(cfg.kmsg_seek_to_tail);
        assert!(cfg.kmsg_checkpoint_path.is_none());
    }

    #[test]
    fn test_config_from_env_overrides() {
        let env: HashMap<&str, &str> = HashMap::from([
            ("MUOBSERVE_NODE_ID", "node-a"),
            ("MUSENTINEL_RUNAWAY_SECS", "2400"),
            ("MUSENTINEL_PSI_PERSISTENCE_SAMPLES", "4"),
            ("MUSENTINEL_ALERT_COOLDOWN_SECS", "120"),
            ("MUSENTINEL_KMSG_SEEK_TAIL", "false"),
            (
                "MUSENTINEL_KMSG_CHECKPOINT_PATH",
                "/var/lib/musentinel/kmsg.ckpt",
            ),
        ]);
        let cfg = SentinelConfig::from_env_with(|k| env.get(k).map(|v| (*v).to_string()));
        assert_eq!(cfg.node_id, "node-a");
        assert_eq!(cfg.runaway_process_secs, 2_400);
        assert_eq!(cfg.psi_persistence_samples, 4);
        assert_eq!(cfg.alert_cooldown_secs, 120);
        assert!(!cfg.kmsg_seek_to_tail);
        assert_eq!(
            cfg.kmsg_checkpoint_path,
            Some(PathBuf::from("/var/lib/musentinel/kmsg.ckpt"))
        );
    }
}
