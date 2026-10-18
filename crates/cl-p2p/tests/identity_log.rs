//! `cl-p2p` identity log hygiene: the node key's hex and base64 (raw secret and libp2p
//! protobuf encoding) never appear in a log line, while the peer ID does.
//!
//! Its own test binary with a single test, so the capturing subscriber is the global default,
//! installed before any callsite is hit (see `tests/m2a_session.rs` for why).

use cl_p2p::identity;
use data_encoding::{BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD, HEXLOWER, HEXUPPER};
use libp2p::identity::{secp256k1, Keypair};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

/// A valid secp256k1 secret that cannot occur by accident in a log.
const SECRET: [u8; 32] = [
    0x71, 0xc4, 0x0e, 0x9b, 0x26, 0xd8, 0x53, 0xaf, 0x1e, 0x67, 0xb2, 0x04, 0xf9, 0x3d, 0x88, 0xc1,
    0x5a, 0x0f, 0xe6, 0x92, 0x37, 0xbc, 0x4d, 0x18, 0xa3, 0x6e, 0xd1, 0x29, 0x84, 0x5b, 0xf7, 0x30,
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

#[test]
fn key_never_logged() {
    let log = Captured::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(node_key::CREDENTIAL);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&SECRET)
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let euid = rustix::process::geteuid().as_raw();
    let key = identity::load(Some(dir.path().as_os_str()), euid).unwrap();
    let reference = Keypair::from(secp256k1::Keypair::from(
        secp256k1::SecretKey::try_from_bytes(SECRET).unwrap(),
    ));
    assert_eq!(key.peer_id(), reference.public().to_peer_id());
    let protobuf = reference.to_protobuf_encoding().unwrap();
    // A refusal of the same bytes.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(identity::load(Some(dir.path().as_os_str()), euid).is_err());

    let raw = log.0.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(text.contains("cl-p2p identity loaded"), "{text}");
    assert!(text.contains(&key.peer_id().to_string()), "{text}");
    assert!(text.contains("node key refused"), "{text}");
    assert!(text.contains("<redacted>"), "{text}");
    for (what, bytes) in [("secret", &SECRET[..]), ("protobuf", &protobuf[..])] {
        for (encoding, needle) in [
            ("hex", HEXLOWER.encode(bytes)),
            ("HEX", HEXUPPER.encode(bytes)),
            ("base64", BASE64.encode(bytes)),
            ("base64 unpadded", BASE64_NOPAD.encode(bytes)),
            ("base64url", BASE64URL.encode(bytes)),
            ("base64url unpadded", BASE64URL_NOPAD.encode(bytes)),
            ("base58", bs58::encode(bytes).into_string()),
            ("bytes", format!("{bytes:?}")),
        ] {
            assert!(
                !text.contains(&needle),
                "the {what}'s {encoding} is in the log"
            );
        }
    }
    assert!(
        !raw.windows(32).any(|w| w == SECRET),
        "the raw key is in the log"
    );
}
