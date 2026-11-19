---
name: mu-observable-sentinel
description: "Configure, extend, and diagnose the mu-observable-sentinel host infrastructure & kernel telemetry sentinel daemon bridging /dev/kmsg, PSI & D-state stalls, per-disk latency (/proc/diskstats), Btrfs sysfs errors, journal socket backpressure, and runaway processes into MuObserve-collector."
---

# `mu-observable-sentinel` Host Infrastructure Sentinel Invariants

## 1. Self-Confining Read-Only Startup Sandbox (`mu-ci-isolation`)

- `mu-observable-sentinel` confines itself at startup via `KernelSandbox` (Landlock V3+ allowlisting `/proc`, `/sys`, and `/dev/kmsg` read-only, bounded `64 MiB` `RLIMIT_MEMLOCK`, and zero filesystem write paths) without spawning privileged external subprocesses (`smartctl`, `btrfs`, `dmesg`).

## 2. Six-Layer Host & Kernel Signal Bridge to `MuObserve-collector`

1. **Kernel Ring Buffer (`/dev/kmsg`, `subsystem = "kernel_kmsg"`)**: Seeks to tail (`SeekFrom::End(0)`, `MU_OBSERVABLE_SENTINEL_KMSG_SEEK_TAIL=true`) on startup, tracks monotonic sequence numbers (with optional persisted checkpoint via `MU_OBSERVABLE_SENTINEL_KMSG_CHECKPOINT_PATH`), and captures `KERN_EMERG..KERN_WARNING` (`severity <= 4`), automatically classifying SCSI/block target errors (`op 0x3:(DISCARD)`, `Sense Key`, `I/O error`), Btrfs errors, OOM kills, and hardware traps into high-priority `OtelLogEntry` batches.
2. **Linux Pressure Stall Information & Uninterruptible `D`-State Tasks (`/proc/pressure/{io,memory,cpu}`, `/proc/[pid]/{stat,wchan}`, `subsystem = "psi_dstate"`)**: Emits `host.psi.{io,memory,cpu}.{some,full}_avg10` metrics and logs persistent user-space processes stuck in `D` (`TASK_UNINTERRUPTIBLE`) state along with kernel wait channel (`wchan`, e.g., `btrfs_sync_file`), excluding kernel threads (`PF_KTHREAD`, `ppid == 2`, `kworker/*`) and gating alerts on consecutive-sample persistence (`MU_OBSERVABLE_SENTINEL_PSI_PERSISTENCE_SAMPLES=3`) and cooldown (`MU_OBSERVABLE_SENTINEL_ALERT_COOLDOWN_SECS=300`).
3. **Per-Disk Queue & Latency Telemetry (`/proc/diskstats`, `subsystem = "storage_latency"`)**: Tracks delta read/write IOPS, `in_flight` queue depth, and average `read_await_ms` / `write_await_ms` per block device (`sda..sdz`, `nvme*`), alerting when per-device write or read await exceeds threshold (catching SMR shingle-rewrite stalls or degraded media).
4. **Btrfs Sysfs Device Error Counters (`/sys/fs/btrfs/<uuid>/devinfo/<devid>/error_stats`, `subsystem = "btrfs_errors"`)**: Emits `host.btrfs.device_errors` (`write_errs`, `read_errs`, `flush_errs`, `corruption_errs`, `generation_errs`) per filesystem label and device directly from sysfs and alerts immediately on any non-zero error count.
5. **Journal & Syslog Socket Backpressure (`/proc/net/unix`, `/proc/meminfo`, `subsystem = "journal_backpressure"`)**: Monitors receive/transmit queue depths on `/run/systemd/journal/dev-log` and `/run/systemd/journal/socket` plus dirty/writeback page memory pressure to detect `systemd-journald` -> `sshd` / `pam_systemd` stalls before SSH logins hang.
6. **Runaway Process & CI Child Watchdog (`/proc/[pid]/stat`, `subsystem = "runaway_process"`)**: Tracks active (`R`/`D`) compute/test processes (`miri`, `cargo`, `rustc`) excluding sleeping orchestrator wrappers (`state = S`), emitting `(pid, starttime_ticks)`-deduplicated warnings when runtime exceeds `MU_OBSERVABLE_SENTINEL_RUNAWAY_SECS` (`2100s` default, above `1800s` CI stage ceilings).
