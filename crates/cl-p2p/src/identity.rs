//! The `cl-p2p` service's libp2p identity: the probe's node key, from the systemd credential
//! `nodekey` ([`node_key`]), never from a config path.
//!
//! [`load`] refuses to run as root and refuses the credential unless `node_key` accepts it,
//! then builds the secp256k1 [`NodeKey`] (`Debug` and `Display` print `<redacted>`) and logs
//! the peer ID it proves. No log line carries key bytes (`tests/identity_log.rs`).

use crate::m2a_session::NodeKey;
use node_key::CredentialError;
use std::ffi::OsStr;

/// The probe unit this service runs as (`ops/probe/ethswarm-p2p.service`): a root-owned,
/// ACL-granted credential is accepted only from `/run/credentials/<UNIT>`.
pub const UNIT: &str = "ethswarm-p2p.service";

/// Why the identity was refused. No variant carries key bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The credential was refused.
    #[error("node key: {0}")]
    Credential(#[from] CredentialError),
    /// libp2p refused the secret.
    #[error("node key: not a secp256k1 secret key")]
    Invalid,
}

/// The identity from `$CREDENTIALS_DIRECTORY/nodekey`, for the effective UID.
pub fn load_from_env() -> Result<NodeKey, IdentityError> {
    load(
        std::env::var_os(node_key::CREDENTIALS_DIRECTORY).as_deref(),
        rustix::process::geteuid().as_raw(),
    )
}

/// The identity from `<credentials_dir>/nodekey` for a process whose effective UID is `euid`.
pub fn load(credentials_dir: Option<&OsStr>, euid: u32) -> Result<NodeKey, IdentityError> {
    let secret = node_key::load(credentials_dir, euid, UNIT)?;
    let key = NodeKey::from_secret(secret).ok_or(IdentityError::Invalid)?;
    tracing::info!(peer_id = %key.peer_id(), node_key = %key, "cl-p2p identity loaded");
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::{secp256k1, Keypair};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn credentials(mode: u32, bytes: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(node_key::CREDENTIAL);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    #[test]
    fn the_identity_is_the_credential_key() {
        let dir = credentials(0o400, &[9; 32]);
        let key = load(Some(dir.path().as_os_str()), euid()).unwrap();
        let want = Keypair::from(secp256k1::Keypair::from(
            secp256k1::SecretKey::try_from_bytes([9; 32]).unwrap(),
        ));
        assert_eq!(key.peer_id(), want.public().to_peer_id());
        assert_eq!(format!("{key:?} {key}"), "<redacted> <redacted>");
    }

    #[test]
    fn refusals_name_the_credential_rule() {
        let dir = credentials(0o644, &[9; 32]);
        let err = load(Some(dir.path().as_os_str()), euid()).unwrap_err();
        assert!(
            matches!(err, IdentityError::Credential(CredentialError::Mode { .. })),
            "{err:?}"
        );
        assert_eq!(
            load(Some(dir.path().as_os_str()), 0).unwrap_err(),
            IdentityError::Credential(CredentialError::Root)
        );
        assert_eq!(
            load(None, euid()).unwrap_err(),
            IdentityError::Credential(CredentialError::NoDirectory)
        );
        assert!(!format!("{err} {err:?}").contains("0909"));
    }
}
