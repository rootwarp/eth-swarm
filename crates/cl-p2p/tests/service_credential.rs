//! The `cl-p2p` binary reads its node key only from `$CREDENTIALS_DIRECTORY/nodekey`: exit 1
//! when the credential is missing or refused, and its output never shows the key. Its stderr is
//! JSON lines, one object per line.

use data_encoding::{BASE64, HEXLOWER};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

const SECRET: [u8; 32] = [0x42; 32];

fn cl_p2p(credentials: Option<&std::path::Path>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cl-p2p"));
    cmd.env_remove(node_key::CREDENTIALS_DIRECTORY);
    if let Some(dir) = credentials {
        cmd.env(node_key::CREDENTIALS_DIRECTORY, dir);
    }
    cmd.output().unwrap()
}

fn credentials(mode: u32) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(node_key::CREDENTIAL);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&SECRET)
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    dir
}

fn output(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Every stderr line is one JSON object with a level, fields and a target, as svc-runtime logs
/// them.
fn assert_json_lines(o: &Output) {
    let text = String::from_utf8_lossy(&o.stderr);
    assert!(!text.is_empty(), "nothing logged");
    for line in text.lines() {
        let event: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("not a JSON line ({e}): {line}"));
        assert!(event["level"].is_string(), "{line}");
        assert!(event["fields"].is_object(), "{line}");
        assert!(event["target"].is_string(), "{line}");
    }
}

fn assert_no_key(text: &str) {
    assert!(!text.contains(&HEXLOWER.encode(&SECRET)), "{text}");
    assert!(!text.contains(&BASE64.encode(&SECRET)), "{text}");
}

#[test]
fn without_the_credential_it_refuses_to_start() {
    let o = cl_p2p(None);
    assert_eq!(o.status.code(), Some(1));
    assert_json_lines(&o);
    assert!(
        output(&o).contains("CREDENTIALS_DIRECTORY"),
        "{}",
        output(&o)
    );
}

#[test]
fn a_credential_others_can_read_is_refused() {
    let dir = credentials(0o644);
    let o = cl_p2p(Some(dir.path()));
    assert_eq!(o.status.code(), Some(1));
    let text = output(&o);
    assert!(text.contains("mode 0644"), "{text}");
    assert_no_key(&text);
    assert_json_lines(&o);
}

#[test]
fn a_good_credential_loads_and_a_missing_config_stops_it_without_showing_the_key() {
    let dir = credentials(0o400);
    let o = cl_p2p(Some(dir.path()));
    // The identity loads, then the config is refused: /etc/ethswarm/cl-p2p.toml is not there.
    assert_eq!(o.status.code(), Some(2));
    let text = output(&o);
    assert!(text.contains("cl-p2p identity loaded"), "{text}");
    assert!(text.contains("config refused"), "{text}");
    assert_no_key(&text);
    assert_json_lines(&o);
}
