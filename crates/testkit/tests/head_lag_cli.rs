#![cfg(feature = "soak")]
use consensus_types::primitives::Root;
use std::process::Command;
use testkit::head_lag::{Gap, Head, Sample};

fn record(slot: u64, lag: i64) -> Sample {
    Sample::observed(
        slot,
        Head {
            payload_status: None,
            slot: (100 - lag) as u64,
            root: Root::ZERO,
        },
        Head {
            payload_status: None,
            slot: 100,
            root: Root::ZERO,
        },
    )
    .unwrap()
}

#[test]
fn analyzer_reports_thresholds_gaps_and_safe_errors() {
    for (records, code, p99, gaps) in [
        (vec![record(0, 1), record(1, 2)], 0, Some(2), 0),
        (vec![record(0, 33)], 1, Some(33), 0),
        (vec![Sample::gap(0, Gap::Reference)], 2, None, 1),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("samples.jsonl");
        let mut text = String::new();
        for item in records {
            text.push_str(&serde_json::to_string(&item).unwrap());
            text.push('\n');
        }
        std::fs::write(&path, text).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_head-lag"))
            .args(["analyze", "--samples"])
            .arg(&path)
            .args(["--slots-per-epoch", "32"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(summary["p99"], serde_json::json!(p99));
        assert_eq!(summary["gap_samples"], gaps);
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.jsonl");
    std::fs::write(&path, "private-response-content").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_head-lag"))
        .args(["analyze", "--samples"])
        .arg(path)
        .args(["--slots-per-epoch", "32"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-response-content"));
}

#[test]
fn help_and_unknown_arguments_do_not_echo_values() {
    let help = Command::new(env!("CARGO_BIN_EXE_head-lag"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--offset-ms"));
    let bad = Command::new(env!("CARGO_BIN_EXE_head-lag"))
        .args(["run", "--private-token", "secret-value"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(64));
    assert!(!String::from_utf8_lossy(&bad.stderr).contains("secret-value"));
}

#[cfg(unix)]
#[test]
fn finite_run_records_missed_slots_and_never_overwrites_output() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let url = dir.path().join("reference.url");
    std::fs::write(&url, "http://127.0.0.1:1").unwrap();
    std::fs::set_permissions(&url, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = dir.path().join("run.jsonl");
    let alerts = dir.path().join("alerts.jsonl");
    let metrics = dir.path().join("head-lag.prom");
    let uid = std::fs::metadata(&url).unwrap().uid().to_string();
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_head-lag"))
            .args(["run", "--socket"])
            .arg(dir.path().join("unused.sock"))
            .args(["--server-uid", &uid, "--reference-url-file"])
            .arg(&url)
            .args([
                "--genesis-time",
                "0",
                "--seconds-per-slot",
                "1",
                "--slots-per-epoch",
                "32",
                "--slots",
                "2",
                "--first-slot",
                "0",
                "--offset-ms",
                "0",
                "--out",
            ])
            .arg(&output)
            .arg("--alerts-out")
            .arg(&alerts)
            .arg("--metrics-out")
            .arg(&metrics)
            .output()
            .unwrap()
    };
    let first = invoke();
    assert_eq!(
        first.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(summary["gap_samples"], 2);
    let original = std::fs::read(&output).unwrap();
    let lines = String::from_utf8(original.clone()).unwrap();
    assert_eq!(lines.lines().count(), 2);
    for line in lines.lines() {
        let record: Sample = serde_json::from_str(line).unwrap();
        assert_eq!(record.gap, Some(Gap::MissedSample));
        assert!(record.lag.is_none());
    }
    assert!(std::fs::read(&alerts).unwrap().is_empty());
    assert!(std::fs::read_to_string(&metrics)
        .unwrap()
        .contains("head_lag_available 0\n"));
    let second = invoke();
    assert_eq!(second.status.code(), Some(2));
    assert_eq!(std::fs::read(output).unwrap(), original);
}

#[test]
fn report_command_qualifies_only_complete_days_and_emits_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("day.jsonl");
    let mut input = String::new();
    for slot in 0..7200 {
        input.push_str(&serde_json::to_string(&record(slot, 1)).unwrap());
        input.push('\n');
    }
    std::fs::write(&path, input).unwrap();
    let invoke = |window: &str| {
        Command::new(env!("CARGO_BIN_EXE_head-lag"))
            .args(["report", "--window", window, "--samples"])
            .arg(&path)
            .args(["--seconds-per-slot", "12", "--slots-per-epoch", "32"])
            .output()
            .unwrap()
    };
    let clean = invoke("24h");
    assert_eq!(
        clean.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert!(String::from_utf8_lossy(&clean.stdout).contains("Overall: PASS"));
    std::fs::write(&path, serde_json::to_string(&record(7199, 1)).unwrap()).unwrap();
    let short = invoke("24h");
    assert_eq!(short.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&short.stdout).contains("Overall: FAIL"));
    assert_eq!(invoke("1h").status.code(), Some(64));
    let rules = Command::new(env!("CARGO_BIN_EXE_head-lag"))
        .arg("rules")
        .output()
        .unwrap();
    assert!(rules.status.success());
    let document: serde_json::Value = serde_json::from_slice(&rules.stdout).unwrap();
    assert_eq!(document["groups"][0]["rules"].as_array().unwrap().len(), 3);
    let expressions = [
        "head_lag_p99_slots > 2",
        "head_lag_slots > 32",
        "head_lag_recovery_slots > head_lag_slots_per_epoch",
    ];
    for (rule, threshold) in document["groups"][0]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .zip(expressions)
    {
        assert!(rule["expr"].as_str().unwrap().contains(threshold));
        assert!(
            rule["expr"]
                .as_str()
                .unwrap()
                .contains("head_lag_updated_at_seconds"),
            "stopped runs must age out"
        );
    }
}
