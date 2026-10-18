//! The `cl-discv5` binary reads its node key only from `$CREDENTIALS_DIRECTORY/nodekey`: exit 1
//! when the credential is missing or refused, and its output never shows the key.

use data_encoding::{BASE64, HEXLOWER};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

const SECRET: [u8; 32] = [0x42; 32];

fn cl_discv5(credentials: Option<&std::path::Path>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cl-discv5"));
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

fn assert_no_key(text: &str) {
    assert!(!text.contains(&HEXLOWER.encode(&SECRET)), "{text}");
    assert!(!text.contains(&BASE64.encode(&SECRET)), "{text}");
}

#[test]
fn without_the_credential_it_refuses_to_start() {
    let o = cl_discv5(None);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        output(&o).contains("CREDENTIALS_DIRECTORY"),
        "{}",
        output(&o)
    );
}

#[test]
fn a_credential_others_can_read_is_refused() {
    let dir = credentials(0o644);
    let o = cl_discv5(Some(dir.path()));
    assert_eq!(o.status.code(), Some(1));
    let text = output(&o);
    assert!(text.contains("mode 0644"), "{text}");
    assert_no_key(&text);
}

#[test]
fn a_good_credential_loads_and_the_stub_stops_without_showing_the_key() {
    let dir = credentials(0o400);
    let o = cl_discv5(Some(dir.path()));
    // The service itself is still a stub: node key loaded, then "not runnable yet".
    assert_eq!(o.status.code(), Some(2));
    let text = output(&o);
    assert!(text.contains("node key loaded"), "{text}");
    assert!(text.contains("not runnable yet"), "{text}");
    assert_no_key(&text);
}
