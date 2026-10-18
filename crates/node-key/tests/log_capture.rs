//! Log hygiene of the node-key credential: neither a loaded key's hex nor its base64 appears in
//! any log line, on a load or a refusal.
//!
//! Its own test binary with a single test, on purpose: `tracing` caches each callsite's
//! interest process-wide, so a thread-scoped subscriber in a unit test can race other tests
//! hitting the same callsites and miss lines. Here the capturing subscriber is the global
//! default, installed before any callsite is hit, in a process where nothing else runs.

use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD, HEXLOWER, HEXUPPER};
use node_key::{load, CredentialError, CREDENTIAL};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

const UNIT: &str = "ethswarm-test.service";

/// A valid secp256k1 secret that cannot occur by accident in a log.
const SECRET: [u8; 32] = [
    0x5d, 0x02, 0xc8, 0x7e, 0x31, 0x9a, 0xf4, 0x6b, 0x13, 0xe7, 0x48, 0xa5, 0x0c, 0xd9, 0x62, 0xbe,
    0x27, 0x8f, 0x54, 0x1a, 0xc3, 0x96, 0x0d, 0x7b, 0xe2, 0x45, 0x38, 0xaf, 0x61, 0x1c, 0x89, 0xf0,
];

/// A `tracing` writer that keeps everything in memory.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn credentials(mode: u32) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CREDENTIAL);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&SECRET)
        .unwrap();
    if rustix::process::geteuid().is_root() {
        let owner = Some(rustix::process::Uid::from_raw(test_uid()));
        rustix::fs::chown(&path, owner, None).unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    dir
}

/// This process's UID, or (as root, which the loader refuses) a service UID the files are
/// given to.
fn test_uid() -> u32 {
    match rustix::process::geteuid().as_raw() {
        0 => 4242,
        euid => euid,
    }
}

#[test]
fn key_never_logged() {
    // First, before any callsite is hit: the one subscriber of this process.
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");

    let euid = test_uid();
    let good = credentials(0o400);
    let secret = load(Some(good.path().as_os_str()), euid, UNIT).unwrap();
    assert_eq!(secret.expose_secret(), &SECRET);
    // The key printed the way a careless caller would: still redacted.
    tracing::info!(key = %secret, debug = ?secret, "caller logs the key");
    // Refusals of a file holding the same bytes.
    let open = credentials(0o644);
    let err = load(Some(open.path().as_os_str()), euid, UNIT).unwrap_err();
    assert!(matches!(err, CredentialError::Mode { .. }), "{err:?}");
    let err = load(Some(good.path().as_os_str()), euid + 1, UNIT).unwrap_err();
    assert!(matches!(err, CredentialError::Owner { .. }), "{err:?}");

    let raw = log.0.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&raw).into_owned();
    // The capture works: the load and both refusals are there.
    assert!(text.contains("node key loaded"), "{text}");
    assert_eq!(text.matches("node key refused").count(), 2, "{text}");
    assert!(text.contains("<redacted>"), "{text}");
    assert!(text.contains(CREDENTIAL), "{text}");
    let forbidden = [
        ("hex", HEXLOWER.encode(&SECRET)),
        ("HEX", HEXUPPER.encode(&SECRET)),
        ("base64", BASE64.encode(&SECRET)),
        ("base64 unpadded", BASE64_NOPAD.encode(&SECRET)),
        ("base64url", BASE64URL.encode(&SECRET)),
        ("base64url unpadded", BASE64URL_NOPAD.encode(&SECRET)),
        ("bytes", format!("{SECRET:?}")),
    ];
    for (what, needle) in forbidden {
        assert!(!text.contains(&needle), "the key's {what} is in the log");
    }
    // Every 16-byte window too, in case a line shows part of it.
    for window in SECRET.windows(16) {
        assert!(
            !text.contains(&HEXLOWER.encode(window)),
            "part of the key's hex"
        );
    }
    assert!(
        !raw.windows(32).any(|w| w == SECRET),
        "the raw key is in the log"
    );
}
