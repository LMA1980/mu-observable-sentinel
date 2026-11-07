//! `MuIsolation` `KernelSandbox` startup confinement for `MuSentinel`.

use crate::error::SentinelError;
use mu_ci_isolation::{
    EffectiveSandboxPolicy, IsolationBackend, KernelSandbox, LandlockRuleBuilder,
    NetworkEgressMode, SandboxBackendKind, SandboxExecutionPlan,
};
use std::ffi::OsString;
use std::path::PathBuf;

/// Canonical configuration directory allowlisted for read-only access by `MuSentinel`.
pub const DEFAULT_SENTINEL_CONFIG_DIR: &str = "/etc/musentinel";

/// Startup confinement configuration for `MuSentinel` backed by `MuIsolation` [`KernelSandbox`].
#[derive(Debug, Clone)]
pub struct SentinelSandboxConfig {
    pub node_id: String,
    pub arch: String,
    pub config_dir: PathBuf,
    pub memlock_limit_kb: u64,
    pub max_pids: u32,
    pub max_memory_mb: u64,
    pub max_cpu_cores: u32,
    pub enforce_landlock_on_linux: bool,
}

impl Default for SentinelSandboxConfig {
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
            config_dir: PathBuf::from(DEFAULT_SENTINEL_CONFIG_DIR),
            memlock_limit_kb: 65_536, // 64 MiB bounded memlock ceiling
            max_pids: 32,
            max_memory_mb: 128,
            max_cpu_cores: 1,
            enforce_landlock_on_linux: false,
        }
    }
}

/// Builds the read-only [`EffectiveSandboxPolicy`] for `MuSentinel` allowlisting
/// `/proc`, `/sys`, `/dev`, and `/etc/musentinel` with zero writable host paths.
#[must_use]
pub fn build_sentinel_sandbox_policy(cfg: &SentinelSandboxConfig) -> EffectiveSandboxPolicy {
    EffectiveSandboxPolicy {
        node_id: cfg.node_id.clone(),
        arch: cfg.arch.clone(),
        backend: SandboxBackendKind::Kernel,
        read_paths: vec![
            cfg.config_dir.clone(),
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
            PathBuf::from("/usr"),
            PathBuf::from("/lib"),
        ],
        write_paths: Vec::new(),
        exec_paths: vec![PathBuf::from("/usr/local/bin"), PathBuf::from("/usr/bin")],
        network_mode: NetworkEgressMode::RestrictedCidrs(vec!["127.0.0.1/32".to_string()]),
        memlock_limit_kb: cfg.memlock_limit_kb,
        max_pids: cfg.max_pids,
        max_memory_mb: cfg.max_memory_mb,
        max_cpu_cores: cfg.max_cpu_cores,
        cpu_affinity_mask: Some(0x00FF),
        require_set_ai_thread: false,
    }
}

/// Validates and lowers the `MuIsolation` [`KernelSandbox`] startup confinement plan.
pub fn apply_sentinel_startup_sandbox(
    cfg: &SentinelSandboxConfig,
) -> Result<SandboxExecutionPlan, SentinelError> {
    let policy = build_sentinel_sandbox_policy(cfg);
    let sandbox = KernelSandbox::new();
    let argv = vec![OsString::from("/usr/local/bin/musentinel")];
    let plan = sandbox.build_execution_plan(&policy, &argv)?;

    if cfg.enforce_landlock_on_linux {
        LandlockRuleBuilder::apply_rules(&plan.landlock_rules)?;
    } else {
        #[cfg(not(target_os = "linux"))]
        LandlockRuleBuilder::apply_rules(&plan.landlock_rules)?;
    }

    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sentinel_sandbox_plan_is_read_only() {
        let cfg = SentinelSandboxConfig::default();
        let policy = build_sentinel_sandbox_policy(&cfg);
        assert!(policy.write_paths.is_empty());
        assert_eq!(policy.memlock_limit_kb, 65_536);
        let plan = apply_sentinel_startup_sandbox(&cfg).expect("valid sandbox plan");
        assert!(!plan.landlock_rules.is_empty());
    }
}
