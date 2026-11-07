//! Typed error hierarchy for `MuSentinel`.

use thiserror::Error;

/// Canonical error variants returned by `MuSentinel` collectors, parsers, sandbox, and HTTP emitter.
#[derive(Debug, Error)]
pub enum SentinelError {
    /// I/O error reading procfs, sysfs, `/dev/kmsg`, or communicating with `MuObserve-collector`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Wire encoding/decoding failure from `mu-observable-ipc`.
    #[error("IPC wire error: {0}")]
    Ipc(#[from] mu_observable_ipc::IpcError),

    /// Startup sandbox confinement error from `mu-ci-isolation`.
    #[error("MuIsolation sandbox error: {0}")]
    Isolation(#[from] mu_ci_isolation::IsolationError),

    /// Malformed procfs, sysfs, or `/dev/kmsg` line.
    #[error("Parse error in {source_name}: {detail}")]
    Parse { source_name: String, detail: String },

    /// HTTP collector endpoint rejected or failed an ingestion request.
    #[error("Collector HTTP ingestion error ({status}): {detail}")]
    CollectorHttp { status: u16, detail: String },
}
