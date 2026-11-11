#![cfg(feature = "soak")]

use std::path::Path;
use std::process::Command;

#[test]
fn cli_check_exit_codes_and_jsonl() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/root_diff");
    for (reference, code, matches) in [
        ("matching.json", 0, serde_json::json!(true)),
        ("finalized-mismatch.json", 1, serde_json::json!(false)),
        ("justified-mismatch.json", 1, serde_json::json!(false)),
        ("absent.json", 2, serde_json::Value::Null),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_root-diff"))
            .arg("check")
            .arg("--ours")
            .arg(dir.join("matching.json"))
            .arg("--reference")
            .arg(dir.join(reference))
            .args(["--epoch", "10"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{reference}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record["match"], matches);
        assert_eq!(record["epoch"], 10);
    }
}

#[test]
fn cli_help_and_usage_are_safe() {
    let help = Command::new(env!("CARGO_BIN_EXE_root-diff"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("query-stub"));
    let bad = Command::new(env!("CARGO_BIN_EXE_root-diff"))
        .args(["check", "--private-token", "do-not-echo"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(64));
    assert!(!String::from_utf8_lossy(&bad.stderr).contains("do-not-echo"));
}

#[cfg(unix)]
#[test]
fn head_run_writes_shared_gap_records_without_overwriting_logs() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let url = dir.path().join("reference.url");
    std::fs::write(&url, "http://127.0.0.1:1").unwrap();
    std::fs::set_permissions(&url, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = dir.path().join("head.jsonl");
    let lag = dir.path().join("lag.jsonl");
    let uid = std::fs::metadata(&url).unwrap().uid().to_string();
    let invoke = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_root-diff"))
            .args(["head-run", "--socket"])
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
            .arg("--lag-out")
            .arg(&lag)
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
    assert_eq!(summary["gaps"], 2);
    assert_eq!(summary["compared"], 0);
    let original = std::fs::read(&output).unwrap();
    for line in String::from_utf8(original.clone()).unwrap().lines() {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(record["compared"], false);
        assert!(record["match"].is_null());
    }
    assert_eq!(
        String::from_utf8(std::fs::read(&lag).unwrap())
            .unwrap()
            .lines()
            .count(),
        2
    );
    assert_eq!(invoke().status.code(), Some(2));
    assert_eq!(std::fs::read(output).unwrap(), original);
}
