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
