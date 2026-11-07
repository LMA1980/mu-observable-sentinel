# mu-observable-sentinel

**Sandboxed Host Infrastructure & Kernel Telemetry Sentinel Daemon (`mu-observable-sentinel`)**

`mu-observable-sentinel` bridges host-level operating system, block storage, filesystem, and kernel ring-buffer diagnostics into `MuObserve-collector` (`http://127.0.0.1:4318/v1/{logs,metrics}`) using native Apache Arrow IPC streams (`application/vnd.apache.arrow.stream`) defined in `mu-observable-ipc`.

## Core Capabilities

1. **Kernel Ring-Buffer Watcher (`/dev/kmsg`)**:
   - Continuously parses structured kernel log records (`<prio>,<seq>,<ts_us>,<flags>;<message>`) for `loglevel <= 4` (`KERN_WARNING`, `KERN_ERR`, `KERN_CRIT`, `KERN_ALERT`, `KERN_EMERG`).
   - Classifies block I/O errors (`critical target error`, `op 0x3:(DISCARD)`, `Sense Key`, `I/O error`), Btrfs anomalies (`BTRFS error`, `BTRFS warning`), OOM killer events (`Out of memory: Killed process`), and hardware/instruction traps (`SIGILL`, `unhandled signal`).
2. **Pressure Stall Information (PSI) & Uninterruptible (`D`-State) Task Inspector**:
   - Samples `/proc/pressure/{io,memory,cpu}` (`some` and `full` `avg10`, `avg60`, `total`) into `OtelMetricEntry` telemetry (`host.psi.io.full_avg10`, `host.psi.memory.full_avg10`, `host.psi.cpu.some_avg10`).
   - Automatically inspects `/proc/[pid]/{stat,comm,wchan}` whenever I/O pressure or `D`-state tasks (`TASK_UNINTERRUPTIBLE`) are detected, emitting structured `OtelLogEntry` diagnostics (`subsystem = "psi_dstate"`) with PID, process name, and kernel wait channel (`wchan`).
3. **Block Storage Latency (`/proc/diskstats`) & Btrfs Device Error Counters (`/sys/fs/btrfs`)**:
   - Computes per-device read/write `await` latency (`ms`), active `in_flight` requests, and I/O utilization percentage (`host.disk.read_await_ms`, `host.disk.write_await_ms`, `host.disk.in_flight`, `host.disk.io_util_pct`), alerting when `await` exceeds `MUSENTINEL_DISK_AWAIT_WARN_MS` (`500 ms` default).
   - Polls `/sys/fs/btrfs/<uuid>/devinfo/<devid>/error_stats` (`write_io_errs`, `read_io_errs`, `flush_io_errs`, `corruption_errs`, `generation_errs`) and alerts immediately on any non-zero counter (`subsystem = "btrfs_errors"`).
4. **Systemd Journal Socket Backpressure & Memory Headroom (`/proc/net/unix`, `/proc/meminfo`)**:
   - Monitors `/run/systemd/journal/dev-log` and `/run/systemd/journal/socket` receive queue depths (`host.systemd.journal_rx_queue`) and `/proc/meminfo` (`MemAvailable`, `SwapFree`, `Dirty`, `Writeback`) to provide early warning before `systemd-journald` or `sshd` stalls occur.
5. **Runaway Process Watchdog (`/proc/[pid]/stat`)**:
   - Detects runaway build/test child processes (`miri`, `cargo`, `rustc`) exceeding `MUSENTINEL_RUNAWAY_SECS` (`900s` default) and emits structured warnings (`subsystem = "runaway_process"`).
6. **`mu-ci-isolation` Startup Confinement**:
   - Validates and lowers a read-only `mu_ci_isolation::KernelSandbox` execution plan restricting filesystem access to `/proc`, `/sys`, `/dev/kmsg`, and `/etc/musentinel` with bounded `RLIMIT_MEMLOCK` (`64 MiB`).

## License

Licensed under the **GNU Affero General Public License v3.0 only (`AGPL-3.0-only`)**. See [LICENSE](LICENSE) for full terms.
