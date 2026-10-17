//! The `anchor-fetch` binary: exit codes, stderr and output files. No network: every case
//! here is refused before any request.

use std::path::Path;
use std::process::{Command, Output};

fn anchor_fetch(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anchor-fetch"))
        .args(args)
        .output()
        .unwrap()
}

fn write_config(dir: &Path, op_a: &str, op_b: &str) -> String {
    let path = dir.join("anchor-fetch.toml");
    std::fs::write(
        &path,
        format!(
            "[[provider]]\nname = \"alpha\"\noperator = \"{op_a}\"\nurl = \"https://a.invalid\"\n\
             [[provider]]\nname = \"beta\"\noperator = \"{op_b}\"\nurl = \"https://b.invalid\"\n"
        ),
    )
    .unwrap();
    path.to_str().unwrap().to_owned()
}

#[test]
fn same_operator_exits_non_zero_names_the_error_and_writes_no_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "Op", "op");
    let out = dir.path().join("out");
    let o = anchor_fetch(&[
        "--config",
        &config,
        "--out",
        out.to_str().unwrap(),
        "--quiet",
    ]);
    assert_eq!(o.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("aborted: same_operator"), "{stderr}");
    assert!(!out.join("anchor.json").exists());
    let log = std::fs::read_to_string(out.join("run.log")).unwrap();
    assert!(log
        .lines()
        .last()
        .unwrap()
        .contains(r#""error":"same_operator""#));
    // That run never named its providers, so its log fails the check.
    let o = anchor_fetch(&["check-log", out.join("run.log").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn check_log_accepts_a_log_naming_both_providers() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("run.log");
    std::fs::write(
        &log,
        concat!(
            r#"{"event":"start"}"#,
            "\n",
            r#"{"event":"provider","role":"a","name":"alpha","operator":"A","url":"https://a"}"#,
            "\n",
            r#"{"event":"provider","role":"b","name":"beta","operator":"B","url":"https://b"}"#,
            "\n"
        ),
    )
    .unwrap();
    let o = anchor_fetch(&["check-log", log.to_str().unwrap()]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn usage_errors_exit_64() {
    for args in [
        &["--bogus"][..],
        &["--config"],
        &["check-log"],
        &["check-log", "a", "b"],
    ] {
        let o = anchor_fetch(args);
        assert_eq!(o.status.code(), Some(64), "{args:?}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("usage:"));
    }
}

#[test]
fn a_missing_config_is_a_local_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let missing = dir.path().join("missing.toml");
    let o = anchor_fetch(&[
        "--config",
        missing.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&o.stderr).contains("aborted: io"));
    assert!(!out.join("anchor.json").exists());
}

#[test]
fn a_userinfo_secret_never_reaches_stderr_or_the_run_log() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("anchor-fetch.toml");
    std::fs::write(
        &config,
        "[[provider]]\nname = \"alpha\"\noperator = \"A\"\nurl = \"https://user:hunter2@a.invalid\"\n\
         [[provider]]\nname = \"beta\"\noperator = \"B\"\nurl = \"https://b.invalid\"\n",
    )
    .unwrap();
    let out = dir.path().join("out");
    let o = anchor_fetch(&[
        "--config",
        config.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("aborted: config"), "{stderr}");
    assert!(!stderr.contains("hunter2"), "{stderr}");
    assert!(!String::from_utf8_lossy(&o.stdout).contains("hunter2"));
    let log = std::fs::read_to_string(out.join("run.log")).unwrap();
    assert!(!log.contains("hunter2"), "{log}");
}

#[test]
fn help_names_anchor_json_as_the_commit_marker() {
    for flag in ["--help", "-h"] {
        let o = anchor_fetch(&[flag]);
        assert_eq!(o.status.code(), Some(0), "{flag}");
        let help = String::from_utf8_lossy(&o.stdout);
        assert!(help.contains("usage:"), "{help}");
        assert!(help.contains("anchor.json is written last"), "{help}");
        assert!(help.contains("commit marker"), "{help}");
        assert!(help.contains("ignore block.ssz and state.ssz"), "{help}");
    }
}

#[test]
fn an_unsafe_out_dir_exits_2_without_writing_into_it() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "Op A", "Op B");
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o777)).unwrap();
    let o = anchor_fetch(&["--config", &config, "--out", out.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("aborted: unsafe_path"), "{stderr}");
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
}

#[test]
fn an_out_dir_symlink_with_a_trailing_slash_or_dot_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), "Op A", "Op B");
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.path().join("out");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    for suffix in ["/", "//", "/."] {
        let out = format!("{}{suffix}", link.display());
        let o = anchor_fetch(&["--config", &config, "--out", &out, "--quiet"]);
        assert_eq!(o.status.code(), Some(2), "{suffix}");
        let stderr = String::from_utf8_lossy(&o.stderr);
        assert!(
            stderr.contains("aborted: unsafe_path"),
            "{suffix}: {stderr}"
        );
        assert!(stderr.contains("symlink"), "{suffix}: {stderr}");
        assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0, "{suffix}");
    }
}
