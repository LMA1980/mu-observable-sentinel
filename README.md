# mu-observable-sentinel

**Sandboxed Host Infrastructure & Kernel Telemetry Sentinel Daemon (`mu-observable-sentinel`)**

`mu-observable-sentinel` bridges host-level operating system, block storage, filesystem, and kernel ring-buffer diagnostics into [`mu-observable-collector`](https://github.com/LMA1980/mu-observable-collector) (`http://127.0.0.1:4318/v1/{logs,metrics}`) using native Apache Arrow IPC streams (`application/vnd.apache.arrow.stream`) defined in [`mu-observable-ipc`](https://github.com/LMA1980/mu-observable-ipc).

## Runtime Configuration

- `MU_OBSERVABLE_SENTINEL_SERVE=true` (or `1`; falls back to `MUSENTINEL_SERVE` / `MUOBSERVE_SERVE`): Runs the continuous polling and `/dev/kmsg` streaming loop after startup sandbox validation; when unset, the binary validates the sandbox plan and exits cleanly.
- `MU_OBSERVABLE_SENTINEL_COLLECTOR_URL` (falls back to `MUSENTINEL_COLLECTOR_URL` / `MUOBSERVE_COLLECTOR_URL`): Base URL for [`mu-observable-collector`](https://github.com/LMA1980/mu-observable-collector) (defaults to `http://127.0.0.1:4318`).
- `MU_OBSERVABLE_SENTINEL_NODE_ID` (falls back to `MUSENTINEL_NODE_ID` / `MUOBSERVE_NODE_ID`): Node identifier attached to emitted `OtelMetricEntry` and `OtelLogEntry` payloads.
- Systemd deployment templates live in `deploy/mu-observable-sentinel.service` and `deploy/mu-observable-sentinel.env.example` (targeting `/etc/mu-observable-sentinel/sentinel.env` and `/var/lib/mu-observable-sentinel`).

## Core Capabilities

1. **Kernel Ring-Buffer Watcher (`/dev/kmsg`)**:
   - Seeks to `/dev/kmsg` tail (`SeekFrom::End(0)`, `MUSENTINEL_KMSG_SEEK_TAIL=true`) on startup, tracks monotonic sequence checkpoints across batches (with optional persistent checkpoint via `MUSENTINEL_KMSG_CHECKPOINT_PATH`), and continuously parses structured kernel log records (`<prio>,<seq>,<ts_us>,<flags>;<message>`) for `loglevel <= 4` (`KERN_WARNING`, `KERN_ERR`, `KERN_CRIT`, `KERN_ALERT`, `KERN_EMERG`).
   - Classifies block I/O errors (`critical target error`, `op 0x3:(DISCARD)`, `Sense Key`, `I/O error`), Btrfs anomalies (`BTRFS error`, `BTRFS warning`), OOM killer events (`Out of memory: Killed process`), and hardware/instruction traps (`SIGILL`, `unhandled signal`).
1. **Pressure Stall Information (PSI) & Uninterruptible (`D`-State) Task Inspector**:
   - Samples `/proc/pressure/{io,memory,cpu}` (`some` and `full` `avg10`, `avg60`, `total`) into `OtelMetricEntry` telemetry (`host.psi.io.full_avg10`, `host.psi.memory.full_avg10`, `host.psi.cpu.some_avg10`).
   - Inspects `/proc/[pid]/{stat,wchan}` while excluding Linux kernel threads (`PF_KTHREAD`, `ppid == 2`, `kworker/*`), requiring multi-sample persistence (`MUSENTINEL_PSI_PERSISTENCE_SAMPLES=3` default) and bounded alert cooldown (`MUSENTINEL_ALERT_COOLDOWN_SECS=300` default) before emitting structured `OtelLogEntry` diagnostics (`subsystem = "psi_dstate"`).
1. **Block Storage Latency (`/proc/diskstats`) & Btrfs Device Error Counters (`/sys/fs/btrfs`)**:
   - Computes per-device read/write `await` latency (`ms`), active `in_flight` requests, and I/O utilization percentage (`host.disk.read_await_ms`, `host.disk.write_await_ms`, `host.disk.in_flight`, `host.disk.io_util_pct`), alerting when `await` exceeds `MUSENTINEL_DISK_AWAIT_WARN_MS` (`500 ms` default).
   - Polls `/sys/fs/btrfs/<uuid>/devinfo/<devid>/error_stats` (`write_io_errs`, `read_io_errs`, `flush_io_errs`, `corruption_errs`, `generation_errs`) and alerts immediately on any non-zero counter (`subsystem = "btrfs_errors"`).
1. **Systemd Journal Socket Backpressure & Memory Headroom (`/proc/net/unix`, `/proc/meminfo`)**:
   - Monitors `/run/systemd/journal/dev-log` and `/run/systemd/journal/socket` receive queue depths (`host.systemd.journal_rx_queue`) and `/proc/meminfo` (`MemAvailable`, `SwapFree`, `Dirty`, `Writeback`) to provide early warning before `systemd-journald` or `sshd` stalls occur.
1. **Runaway Process Watchdog (`/proc/[pid]/stat`)**:
   - Detects active (`R`/`D`) build/test child processes (`miri`, `cargo`, `rustc`) exceeding `MUSENTINEL_RUNAWAY_SECS` (`2100s` default, calibrated above `1800s` CI stage ceilings) while ignoring sleeping parent wrappers (`state = S`) and deduplicating per `(pid, starttime_ticks)` (`subsystem = "runaway_process"`).
1. **[`mu-ci-isolation`](https://github.com/LMA1980/mu-ci-isolation) Startup Confinement**:
   - Validates and lowers a read-only `mu_ci_isolation::KernelSandbox` execution plan restricting filesystem access to `/proc`, `/sys`, `/dev/kmsg`, and `/etc/mu-observable-sentinel` (with on-disk fallback to `/etc/muobserve-sentinel` / `/etc/musentinel`) with bounded `RLIMIT_MEMLOCK` (`64 MiB`).

## Ecosystem Integration

- **Parent & Sibling Crates**: [`mu-observable`](https://github.com/LMA1980/mu-observable), [`mu-observable-ipc`](https://github.com/LMA1980/mu-observable-ipc), [`mu-observable-collector`](https://github.com/LMA1980/mu-observable-collector), [`mu-observable-hub`](https://github.com/LMA1980/mu-observable-hub)
- **Confinement**: [`mu-ci-isolation`](https://github.com/LMA1980/mu-ci-isolation)

## Testing & Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cargo build --workspace --all-targets
cargo test --workspace
cargo llvm-cov --workspace --summary-only
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --workspace --lib
```

## License

Licensed under the **GNU Affero General Public License v3.0 only (`AGPL-3.0-only`)**. See [LICENSE](LICENSE) for full terms.
