//! The JWT secret's hex never appears in a log line.
//!
//! Its own test binary on purpose: `tracing` caches each callsite's interest process-wide, so a
//! subscriber installed beside other tests can miss lines. The capturing subscriber is the
//! global default, installed before any callsite is hit.

use cl_engine::jwt::{load, CredentialError, CREDENTIAL};
use data_encoding::HEXLOWER;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

const UNIT: &str = "ethswarm-engine.service";
const SECRET: [u8; 32] = [
    0x5d, 0x02, 0xc8, 0x7e, 0x31, 0x9a, 0xf4, 0x6b, 0x13, 0xe7, 0x48, 0xa5, 0x0c, 0xd9, 0x62, 0xbe,
    0x27, 0x8f, 0x54, 0x1a, 0xc3, 0x96, 0x0d, 0x7b, 0xe2, 0x45, 0x38, 0xaf, 0x61, 0x1c, 0x89, 0xf0,
];

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

fn euid() -> u32 {
    match rustix::process::geteuid().as_raw() {
        0 => 4242,
        euid => euid,
    }
}

fn credentials(mode: u32, text: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CREDENTIAL);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    if rustix::process::geteuid().is_root() {
        rustix::fs::chown(&path, Some(rustix::process::Uid::from_raw(euid())), None).unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    dir
}

#[test]
fn secret_absent_from_logs() {
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");

    let hex = HEXLOWER.encode(&SECRET);
    let good = credentials(0o600, &hex);
    let secret = load(Some(good.path().as_os_str()), euid(), UNIT).unwrap();
    assert_eq!(secret.expose_secret(), &SECRET);
    tracing::info!(jwt_secret = %secret, debug = ?secret, "caller logs the secret");
    let loose = credentials(0o644, &hex);
    let err = load(Some(loose.path().as_os_str()), euid(), UNIT).unwrap_err();
    assert!(matches!(err, CredentialError::Mode { .. }), "{err:?}");

    let raw = log.0.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(text.contains("JWT secret loaded"), "{text}");
    assert!(text.contains("JWT secret refused"), "{text}");
    assert!(text.contains("<redacted>"), "{text}");
    assert!(!text.contains(&hex), "the secret's hex is in the log");
    assert!(!text.contains(&hex.to_ascii_uppercase()));
    for window in hex.as_bytes().windows(16) {
        let needle = std::str::from_utf8(window).unwrap();
        assert!(
            !text.contains(needle),
            "part of the secret's hex is in the log"
        );
    }
    assert!(
        !raw.windows(32).any(|window| window == SECRET),
        "the raw secret is in the log"
    );
}
