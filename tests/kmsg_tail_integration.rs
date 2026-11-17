use mu_observable_sentinel::{
    open_kmsg_reader, stream_kmsg_lines, HostSentinelCollector, SentinelConfig,
};
use std::io::Write;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_kmsg_tail_seek_skips_historical_boot_errors_and_reads_live_records() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kmsg_path = tmp.path().join("kmsg");
    let proc_root = tmp.path().join("proc");
    std::fs::create_dir_all(&proc_root).unwrap();

    // Pre-existing boot-era records sitting in ring buffer before daemon startup
    let historical = concat!(
        "3,0,100,-;ima: Error Communicating to TPM chip\n",
        "4,5,250,-;invoked oom-killer: gfp_mask=0x100cca\n",
    );
    std::fs::write(&kmsg_path, historical).unwrap();

    // Open with seek_to_tail = true (mirrors startup behavior in main.rs)
    let mut reader = open_kmsg_reader(&kmsg_path, true)
        .await
        .expect("open kmsg at tail");

    // Append a new live record after startup
    let mut appender = std::fs::OpenOptions::new()
        .append(true)
        .open(&kmsg_path)
        .expect("open for append");
    writeln!(
        appender,
        "3,6,900000,-;critical target error, dev sdd, sector 2099200 op 0x3:(DISCARD)"
    )
    .unwrap();
    appender.flush().unwrap();

    let mut line = String::new();
    let n = reader.read_line(&mut line).await.expect("read live line");
    assert!(n > 0);

    let cfg = SentinelConfig {
        node_id: "node-a".to_string(),
        proc_root,
        sys_root: tmp.path().join("sys"),
        kmsg_path: kmsg_path.clone(),
        ..SentinelConfig::default()
    };
    let mut collector = HostSentinelCollector::new(cfg);
    let logs = collector.ingest_kmsg_lines(&line);

    assert_eq!(logs.len(), 1);
    assert!(logs[0].body.contains("critical target error"));
    assert!(!logs[0].body.contains("TPM chip"));
    assert_eq!(collector.last_kmsg_seq(), Some(6));
}

#[tokio::test]
async fn test_stream_kmsg_lines_at_tail_emits_zero_historical_records() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kmsg_path = tmp.path().join("kmsg");
    std::fs::write(
        &kmsg_path,
        concat!(
            "3,1,10,-;ima: historical boot error\n",
            "4,2,20,-;historical firmware warning\n",
        ),
    )
    .unwrap();

    let (tx, mut rx) = mpsc::channel(16);
    stream_kmsg_lines(kmsg_path, true, tx).await;

    let mut received = Vec::new();
    while let Some(line) = rx.recv().await {
        received.push(line);
    }
    assert!(
        received.is_empty(),
        "tail-seek stream must not replay pre-existing boot records"
    );
}

#[tokio::test]
async fn test_stream_kmsg_lines_with_checkpoint_skips_replayed_records_on_restart() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let kmsg_path = tmp.path().join("kmsg");
    let ckpt_path = tmp.path().join("state").join("kmsg.ckpt");
    let proc_root = tmp.path().join("proc");
    std::fs::create_dir_all(proc_root.join("sys/kernel/random")).unwrap();
    std::fs::write(proc_root.join("sys/kernel/random/boot_id"), "boot-a\n").unwrap();

    std::fs::write(
        &kmsg_path,
        concat!(
            "3,1,10,-;ima: boot error\n",
            "4,2,20,-;invoked oom-killer: historical trace\n",
        ),
    )
    .unwrap();

    let cfg = SentinelConfig {
        node_id: "node-a".to_string(),
        proc_root,
        sys_root: tmp.path().join("sys"),
        kmsg_path: kmsg_path.clone(),
        kmsg_seek_to_tail: false,
        kmsg_checkpoint_path: Some(ckpt_path),
        ..SentinelConfig::default()
    };

    // First daemon run ingests seq 1 and 2 and persists checkpoint = 2
    let (tx1, mut rx1) = mpsc::channel(16);
    stream_kmsg_lines(kmsg_path.clone(), false, tx1).await;
    let mut collector1 = HostSentinelCollector::new(cfg.clone());
    let mut first_logs = Vec::new();
    while let Some(line) = rx1.recv().await {
        first_logs.extend(collector1.ingest_kmsg_lines(&line));
    }
    assert_eq!(first_logs.len(), 2);
    assert_eq!(collector1.last_kmsg_seq(), Some(2));
    drop(collector1);

    // Append seq 3, then simulate daemon restart without tail-seek
    let mut appender = std::fs::OpenOptions::new()
        .append(true)
        .open(&kmsg_path)
        .unwrap();
    writeln!(
        appender,
        "3,3,300,-;BTRFS error (device sda): parent transid verify failed"
    )
    .unwrap();

    let (tx2, mut rx2) = mpsc::channel(16);
    stream_kmsg_lines(kmsg_path, false, tx2).await;
    let mut collector2 = HostSentinelCollector::new(cfg);
    assert_eq!(collector2.last_kmsg_seq(), Some(2));

    let mut second_logs = Vec::new();
    while let Some(line) = rx2.recv().await {
        second_logs.extend(collector2.ingest_kmsg_lines(&line));
    }
    assert_eq!(second_logs.len(), 1);
    assert!(second_logs[0].body.contains("BTRFS error"));
    assert_eq!(collector2.last_kmsg_seq(), Some(3));
}
