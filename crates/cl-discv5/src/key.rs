//! The node key: one secp256k1 secret, the identity the local record is signed with.
//!
//! It arrives as a systemd credential (`LoadCredential=`), so here it is a path to a file that
//! must be a regular file (not a symlink) of mode 0600 owned by the effective UID and hold
//! exactly the 32 secret bytes. The checks run on the open file (`fstat`), so the file checked
//! is the file read, and the bytes read are wiped on every path. [`NodeKey`] prints
//! `<redacted>` in `Debug` and `Display`, and no error carries key material. The same rules
//! as `m2a-session`'s node key (`cl-p2p`), which the libp2p identity will share.

use enr::CombinedKey;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use zeroize::Zeroizing;

/// The mode a node-key file must have.
pub const KEY_FILE_MODE: u32 = 0o600;
/// A secp256k1 secret key file holds exactly the 32 secret bytes.
pub const KEY_FILE_LEN: u64 = 32;

/// The discv5 node key. Its `Debug` and `Display` never show key material.
pub struct NodeKey(CombinedKey);

impl NodeKey {
    /// The key, to sign the local record with.
    pub fn combined(&self) -> &CombinedKey {
        &self.0
    }

    /// The key, for `Discv5::new`.
    pub fn into_combined(self) -> CombinedKey {
        self.0
    }
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Why a key file was refused. The key bytes are never part of the error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyFileError {
    /// The file could not be opened (missing, a symlink, unreadable).
    #[error("cannot open: {0}")]
    Open(String),
    /// The path is not a regular file.
    #[error("not a regular file")]
    NotRegular,
    /// The permission bits are not 0600.
    #[error("mode {0:04o}, want 0600")]
    Mode(u32),
    /// Another UID owns the file.
    #[error("owned by uid {owner}, want {euid}")]
    Owner {
        /// The file's owner.
        owner: u32,
        /// The effective UID.
        euid: u32,
    },
    /// The file is not 32 bytes.
    #[error("{0} bytes, want {KEY_FILE_LEN}")]
    Length(u64),
    /// The bytes are not a valid secp256k1 secret key.
    #[error("not a secp256k1 secret key")]
    Invalid,
    /// Reading failed.
    #[error("read: {0}")]
    Read(String),
}

/// Loads the node key from `path` for a process whose effective UID is `euid`
/// (`geteuid()` in production).
pub fn load_node_key(path: &Path, euid: u32) -> Result<NodeKey, KeyFileError> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = rustix::fs::open(path, flags, Mode::empty())
        .map_err(|e| KeyFileError::Open(e.to_string()))?;
    let file = File::from(fd);
    let meta = file
        .metadata()
        .map_err(|e| KeyFileError::Read(e.to_string()))?;
    if !meta.file_type().is_file() {
        return Err(KeyFileError::NotRegular);
    }
    let mode = meta.mode() & 0o7777;
    if mode != KEY_FILE_MODE {
        return Err(KeyFileError::Mode(mode));
    }
    if meta.uid() != euid {
        return Err(KeyFileError::Owner {
            owner: meta.uid(),
            euid,
        });
    }
    if meta.len() != KEY_FILE_LEN {
        return Err(KeyFileError::Length(meta.len()));
    }
    // Wiped on drop, on every path: `secp256k1_from_bytes` zeroes its input only on success.
    let mut secret = Zeroizing::new([0u8; KEY_FILE_LEN as usize]);
    (&file)
        .take(KEY_FILE_LEN)
        .read_exact(&mut secret[..])
        .map_err(|e| KeyFileError::Read(e.to_string()))?;
    CombinedKey::secp256k1_from_bytes(&mut secret[..])
        .map(NodeKey)
        .map_err(|_| KeyFileError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use enr::EnrKey;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn key_file(mode: u32, bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        file
    }

    #[test]
    fn key_file_0600_owned_by_euid_loads() {
        let file = key_file(0o600, &[7; 32]);
        let key = load_node_key(file.path(), euid()).unwrap();
        let want = CombinedKey::secp256k1_from_bytes(&mut [7; 32]).unwrap();
        assert_eq!(key.combined().public(), want.public());
        assert_eq!(key.combined().encode(), want.encode());
    }

    #[test]
    fn key_file_refusals() {
        let check = |path: &Path, euid| load_node_key(path, euid).unwrap_err();
        let file = key_file(0o600, &[7; 32]);
        assert_eq!(
            check(file.path(), euid() + 1),
            KeyFileError::Owner {
                owner: euid(),
                euid: euid() + 1
            }
        );
        assert_eq!(
            check(key_file(0o600, &[7; 31]).path(), euid()),
            KeyFileError::Length(31)
        );
        assert_eq!(
            check(key_file(0o600, &[0; 32]).path(), euid()),
            KeyFileError::Invalid
        );
        assert_eq!(
            check(key_file(0o644, &[7; 32]).path(), euid()),
            KeyFileError::Mode(0o644)
        );
        assert_eq!(
            check(key_file(0o400, &[7; 32]).path(), euid()),
            KeyFileError::Mode(0o400)
        );
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(file.path(), &link).unwrap();
        assert!(
            matches!(check(&link, euid()), KeyFileError::Open(_)),
            "symlinks are not followed"
        );
        assert!(matches!(
            check(&dir.path().join("missing"), euid()),
            KeyFileError::Open(_)
        ));
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(check(&sub, euid()), KeyFileError::NotRegular);
    }

    #[test]
    fn node_key_is_redacted() {
        let file = key_file(0o600, &[7; 32]);
        let key = load_node_key(file.path(), euid()).unwrap();
        assert_eq!(format!("{key:?}"), "<redacted>");
        assert_eq!(format!("{key}"), "<redacted>");
        assert_eq!(format!("{:?}", Some(&key)), "Some(<redacted>)");
        let err = load_node_key(key_file(0o600, &[0; 32]).path(), euid()).unwrap_err();
        assert!(!format!("{err} {err:?}").contains("0000"), "{err}");
    }
}
