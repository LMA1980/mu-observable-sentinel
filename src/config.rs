//! Runtime configuration and threshold parameters for `mu-observable-sentinel`.

use crate::sandbox::DEFAULT_SENTINEL_CONFIG_DIR;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Canonical telemetry `service_name` emitted on all `mu-observable-sentinel` logs and metrics.
pub const SENTINEL_SERVICE_NAME: &str = "mu-observable-sentinel";

/// Canonical production state directory for `mu-observable-sentinel`.
pub const DEFAULT_SENTINEL_STATE_DIR: &str = "/var/lib/mu-observable-sentinel";

/// Canonical production `/dev/kmsg` sequence checkpoint path.
pub const DEFAULT_SENTINEL_CHECKPOINT_PATH: &str = "/var/lib/mu-observable-sentinel/kmsg.ckpt";

/// Legacy `muobserve-sentinel` checkpoint path retained for on-disk fallback.
pub const LEGACY_SENTINEL_MUOBSERVE_CHECKPOINT_PATH: &str = "/var/lib/muobserve-sentinel/kmsg.ckpt";

/// Legacy `musentinel` checkpoint path retained for on-disk fallback.
pub const LEGACY_SENTINEL_CHECKPOINT_PATH: &str = "/var/lib/musentinel/kmsg.ckpt";

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

/// Runtime configuration for `mu-observable-sentinel` loaded from environment variables.
#[derive(Debug, Clone)]
pub struct SentinelConfig {
    /// Node identifier reported in `OtelMetricEntry` and `OtelLogEntry` (`MU_OBSERVABLE_SENTINEL_NODE_ID`).
    pub node_id: String,
    /// Host CPU architecture (`x86_64` or `riscv64gc`).
    pub arch: String,
    /// Base URL for `mu-observable-collector` (`MU_OBSERVABLE_SENTINEL_COLLECTOR_URL`).
    pub collector_url: String,
    /// Polling interval between procfs/sysfs sweeps (`MU_OBSERVABLE_SENTINEL_POLL_SECS`).
    pub poll_interval: Duration,
    /// Disk read/write `await` threshold in milliseconds before emitting a warning log (`MU_OBSERVABLE_SENTINEL_DISK_AWAIT_WARN_MS`).
    pub disk_await_warn_ms: f64,
    /// PSI `avg10` stall percentage threshold before emitting a warning log (`MU_OBSERVABLE_SENTINEL_PSI_WARN_PCT`).
    pub psi_warn_pct: f64,
    /// Consecutive sweeps required before PSI or user-space D-state conditions alert (`MU_OBSERVABLE_SENTINEL_PSI_PERSISTENCE_SAMPLES`).
    pub psi_persistence_samples: u32,
    /// Cooldown window in seconds between repeated `psi_dstate` or `runaway_process` alerts (`MU_OBSERVABLE_SENTINEL_ALERT_COOLDOWN_SECS`).
    pub alert_cooldown_secs: u64,
    /// Maximum runtime in seconds for monitored build/test processes before alerting (`MU_OBSERVABLE_SENTINEL_RUNAWAY_SECS`).
    pub runaway_process_secs: u64,
    /// Root path for procfs (defaults to `/proc`).
    pub proc_root: PathBuf,
    /// Root path for sysfs (defaults to `/sys`).
    pub sys_root: PathBuf,
    /// Path to `/dev/kmsg` (defaults to `/dev/kmsg`).
    pub kmsg_path: PathBuf,
    /// Seek `/dev/kmsg` to `SeekFrom::End(0)` on startup to avoid replaying boot records (`MU_OBSERVABLE_SENTINEL_KMSG_SEEK_TAIL`).
    pub kmsg_seek_to_tail: bool,
    /// Optional path to persist the last ingested `/dev/kmsg` sequence checkpoint (`MU_OBSERVABLE_SENTINEL_KMSG_CHECKPOINT_PATH`).
    pub kmsg_checkpoint_path: Option<PathBuf>,
    /// Whether to enforce Landlock V3+ rules at startup (`MU_OBSERVABLE_SENTINEL_ENFORCE_LANDLOCK`).
    pub enforce_landlock_on_linux: bool,
    /// Configuration directory allowlisted for read-only Landlock access (`MU_OBSERVABLE_SENTINEL_CONFIG_DIR`).
    pub config_dir: PathBuf,
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
            config_dir: PathBuf::from(DEFAULT_SENTINEL_CONFIG_DIR),
        }
    }
}

/// Returns the first non-empty trimmed value matching `keys` in precedence order.
pub fn env_var_first_with<F>(keys: &[&str], mut lookup: F) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    for key in keys {
        if let Some(raw) = lookup(key) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Returns the first non-empty trimmed process environment variable matching `keys` in order.
#[must_use]
pub fn env_var_first(keys: &[&str]) -> Option<String> {
    env_var_first_with(keys, |k| std::env::var(k).ok())
}

/// Resolves `canonical` unless `canonical` does not exist on disk and a path in `fallbacks` does.
#[must_use]
pub fn resolve_preferred_path_chain(canonical: &Path, fallbacks: &[&Path]) -> PathBuf {
    if canonical.exists() {
        return canonical.to_path_buf();
    }
    for legacy in fallbacks {
        if legacy.exists() {
            return legacy.to_path_buf();
        }
    }
    canonical.to_path_buf()
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

/// Returns whether continuous polling serve mode is enabled via
/// `MU_OBSERVABLE_SENTINEL_SERVE`, falling back to `MUSENTINEL_SERVE` and `MUOBSERVE_SERVE`.
#[must_use]
pub fn should_serve_from_env() -> bool {
    should_serve_from_env_with(|k| std::env::var(k).ok())
}

/// Evaluates continuous polling serve mode using a custom lookup closure.
pub fn should_serve_from_env_with<F>(lookup: F) -> bool
where
    F: FnMut(&str) -> Option<String>,
{
    env_var_first_with(
        &[
            "MU_OBSERVABLE_SENTINEL_SERVE",
            "MUSENTINEL_SERVE",
            "MUOBSERVE_SERVE",
        ],
        lookup,
    )
    .and_then(|v| parse_bool_flag(&v))
    .unwrap_or(false)
}

impl SentinelConfig {
    /// Constructs [`SentinelConfig`] from process environment variables with safe defaults.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_with(|key| std::env::var(key).ok())
    }

    /// Constructs [`SentinelConfig`] from a custom key lookup closure (useful for deterministic tests),
    /// preferring `MU_OBSERVABLE_SENTINEL_*` variables before `MUSENTINEL_*` and `MUOBSERVE_*`.
    #[must_use]
    pub fn from_env_with<F>(mut lookup: F) -> Self
    where
        F: FnMut(&str) -> Option<String>,
    {
        let mut cfg = Self::default();
        if let Some(node_id) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_NODE_ID",
                "MUSENTINEL_NODE_ID",
                "MUOBSERVE_NODE_ID",
            ],
            &mut lookup,
        ) {
            cfg.node_id = node_id;
        }
        if let Some(url) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_COLLECTOR_URL",
                "MUSENTINEL_COLLECTOR_URL",
                "MUOBSERVE_COLLECTOR_URL",
            ],
            &mut lookup,
        ) {
            cfg.collector_url = url.trim_end_matches('/').to_string();
        }
        if let Some(secs) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_POLL_SECS",
                "MUSENTINEL_POLL_SECS",
                "MUOBSERVE_POLL_SECS",
            ],
            &mut lookup,
        ) {
            if let Ok(parsed) = secs.parse::<u64>() {
                if parsed > 0 {
                    cfg.poll_interval = Duration::from_secs(parsed);
                }
            }
        }
        if let Some(ms) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_DISK_AWAIT_WARN_MS",
                "MUSENTINEL_DISK_AWAIT_WARN_MS",
                "MUOBSERVE_DISK_AWAIT_WARN_MS",
            ],
            &mut lookup,
        ) {
            if let Ok(parsed) = ms.parse::<f64>() {
                if parsed > 0.0 {
                    cfg.disk_await_warn_ms = parsed;
                }
            }
        }
        if let Some(pct) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_PSI_WARN_PCT",
                "MUSENTINEL_PSI_WARN_PCT",
                "MUOBSERVE_PSI_WARN_PCT",
            ],
            &mut lookup,
        ) {
            if let Ok(parsed) = pct.parse::<f64>() {
                if parsed > 0.0 {
                    cfg.psi_warn_pct = parsed;
                }
            }
        }
        if let Some(samples) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_PSI_PERSISTENCE_SAMPLES",
                "MUSENTINEL_PSI_PERSISTENCE_SAMPLES",
                "MUOBSERVE_PSI_PERSISTENCE_SAMPLES",
            ],
            &mut lookup,
        ) {
            if let Ok(parsed) = samples.parse::<u32>() {
                if parsed > 0 {
                    cfg.psi_persistence_samples = parsed;
                }
            }
        }
        if let Some(cooldown) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_ALERT_COOLDOWN_SECS",
                "MUSENTINEL_ALERT_COOLDOWN_SECS",
                "MUOBSERVE_ALERT_COOLDOWN_SECS",
            ],
            &mut lookup,
        ) {
            if let Ok(parsed) = cooldown.parse::<u64>() {
                cfg.alert_cooldown_secs = parsed;
            }
        }
        if let Some(secs) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_RUNAWAY_SECS",
                "MUSENTINEL_RUNAWAY_SECS",
                "MUOBSERVE_RUNAWAY_SECS",
            ],
            &mut lookup,
        ) {
            if let Ok(parsed) = secs.parse::<u64>() {
                if parsed > 0 {
                    cfg.runaway_process_secs = parsed;
                }
            }
        }
        if let Some(seek_tail) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_KMSG_SEEK_TAIL",
                "MUSENTINEL_KMSG_SEEK_TAIL",
                "MUOBSERVE_KMSG_SEEK_TAIL",
            ],
            &mut lookup,
        ) {
            if let Some(parsed) = parse_bool_flag(&seek_tail) {
                cfg.kmsg_seek_to_tail = parsed;
            }
        }
        if let Some(ckpt_path) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_KMSG_CHECKPOINT_PATH",
                "MUSENTINEL_KMSG_CHECKPOINT_PATH",
                "MUOBSERVE_KMSG_CHECKPOINT_PATH",
            ],
            &mut lookup,
        ) {
            cfg.kmsg_checkpoint_path = Some(PathBuf::from(ckpt_path));
        }
        if let Some(enforce) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_ENFORCE_LANDLOCK",
                "MUSENTINEL_ENFORCE_LANDLOCK",
                "MUOBSERVE_ENFORCE_LANDLOCK",
            ],
            &mut lookup,
        ) {
            if let Some(parsed) = parse_bool_flag(&enforce) {
                cfg.enforce_landlock_on_linux = parsed;
            }
        }
        if let Some(config_dir) = env_var_first_with(
            &[
                "MU_OBSERVABLE_SENTINEL_CONFIG_DIR",
                "MUSENTINEL_CONFIG_DIR",
                "MUOBSERVE_SENTINEL_CONFIG_DIR",
                "MUOBSERVE_CONFIG_DIR",
            ],
            &mut lookup,
        ) {
            cfg.config_dir = PathBuf::from(config_dir);
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
        assert_eq!(SENTINEL_SERVICE_NAME, "mu-observable-sentinel");
        assert_eq!(cfg.collector_url, "http://127.0.0.1:4318");
        assert_eq!(cfg.poll_interval, Duration::from_secs(5));
        assert!((cfg.disk_await_warn_ms - 500.0).abs() < f64::EPSILON);
        assert_eq!(cfg.runaway_process_secs, 2_100);
        assert_eq!(cfg.psi_persistence_samples, 3);
        assert_eq!(cfg.alert_cooldown_secs, 300);
        assert!(cfg.kmsg_seek_to_tail);
        assert!(cfg.kmsg_checkpoint_path.is_none());
        assert_eq!(cfg.config_dir, PathBuf::from("/etc/mu-observable-sentinel"));
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

    #[test]
    fn test_canonical_mu_observable_sentinel_env_precedence() {
        let env: HashMap<&str, &str> = HashMap::from([
            ("MU_OBSERVABLE_SENTINEL_SERVE", "false"),
            ("MUSENTINEL_SERVE", "true"),
            ("MUOBSERVE_SERVE", "true"),
            ("MU_OBSERVABLE_SENTINEL_NODE_ID", "worker-riscv64"),
            ("MUSENTINEL_NODE_ID", "legacy-musentinel"),
            ("MUOBSERVE_NODE_ID", "legacy-muobserve"),
            (
                "MU_OBSERVABLE_SENTINEL_COLLECTOR_URL",
                "http://127.0.0.1:14318/",
            ),
            ("MUSENTINEL_COLLECTOR_URL", "http://127.0.0.1:24318"),
            ("MUOBSERVE_COLLECTOR_URL", "http://127.0.0.1:34318"),
            ("MU_OBSERVABLE_SENTINEL_POLL_SECS", "10"),
            ("MUSENTINEL_POLL_SECS", "20"),
            ("MU_OBSERVABLE_SENTINEL_DISK_AWAIT_WARN_MS", "250.5"),
            ("MUSENTINEL_DISK_AWAIT_WARN_MS", "750.0"),
            ("MU_OBSERVABLE_SENTINEL_PSI_WARN_PCT", "15.0"),
            ("MUSENTINEL_PSI_WARN_PCT", "30.0"),
            ("MU_OBSERVABLE_SENTINEL_PSI_PERSISTENCE_SAMPLES", "5"),
            ("MUSENTINEL_PSI_PERSISTENCE_SAMPLES", "2"),
            ("MU_OBSERVABLE_SENTINEL_ALERT_COOLDOWN_SECS", "90"),
            ("MUSENTINEL_ALERT_COOLDOWN_SECS", "600"),
            ("MU_OBSERVABLE_SENTINEL_RUNAWAY_SECS", "3600"),
            ("MUSENTINEL_RUNAWAY_SECS", "1200"),
            ("MU_OBSERVABLE_SENTINEL_KMSG_SEEK_TAIL", "false"),
            ("MUSENTINEL_KMSG_SEEK_TAIL", "true"),
            (
                "MU_OBSERVABLE_SENTINEL_KMSG_CHECKPOINT_PATH",
                "/var/lib/mu-observable-sentinel/kmsg.ckpt",
            ),
            (
                "MUSENTINEL_KMSG_CHECKPOINT_PATH",
                "/var/lib/musentinel/kmsg.ckpt",
            ),
            ("MU_OBSERVABLE_SENTINEL_ENFORCE_LANDLOCK", "true"),
            ("MUSENTINEL_ENFORCE_LANDLOCK", "false"),
            (
                "MU_OBSERVABLE_SENTINEL_CONFIG_DIR",
                "/etc/mu-observable-sentinel",
            ),
            ("MUSENTINEL_CONFIG_DIR", "/etc/musentinel"),
        ]);

        assert!(!should_serve_from_env_with(|k| env
            .get(k)
            .map(|v| (*v).to_string())));

        let serve_legacy: HashMap<&str, &str> = HashMap::from([("MUSENTINEL_SERVE", "true")]);
        assert!(should_serve_from_env_with(|k| serve_legacy
            .get(k)
            .map(|v| (*v).to_string())));

        let cfg = SentinelConfig::from_env_with(|k| env.get(k).map(|v| (*v).to_string()));
        assert_eq!(cfg.node_id, "worker-riscv64");
        assert_eq!(cfg.collector_url, "http://127.0.0.1:14318");
        assert_eq!(cfg.poll_interval, Duration::from_secs(10));
        assert!((cfg.disk_await_warn_ms - 250.5).abs() < f64::EPSILON);
        assert!((cfg.psi_warn_pct - 15.0).abs() < f64::EPSILON);
        assert_eq!(cfg.psi_persistence_samples, 5);
        assert_eq!(cfg.alert_cooldown_secs, 90);
        assert_eq!(cfg.runaway_process_secs, 3600);
        assert!(!cfg.kmsg_seek_to_tail);
        assert_eq!(
            cfg.kmsg_checkpoint_path,
            Some(PathBuf::from("/var/lib/mu-observable-sentinel/kmsg.ckpt"))
        );
        assert!(cfg.enforce_landlock_on_linux);
        assert_eq!(cfg.config_dir, PathBuf::from("/etc/mu-observable-sentinel"));
    }
}
