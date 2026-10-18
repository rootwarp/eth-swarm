//! The probe's node key: one secp256k1 secret, the identity cl-p2p (libp2p peer ID) and
//! cl-discv5 (ENR) share.
//!
//! It reaches a probe process only as the systemd credential `nodekey`
//! (`LoadCredential=nodekey:<path>` in the unit, `ops/probe/`), never as a config path:
//! [`load_from_env`] reads `$CREDENTIALS_DIRECTORY/nodekey`. It refuses to run as root, opens
//! the file without following a symlink and checks the open file (`fstat`, `fgetxattr`), so the
//! file checked is the file read. The file must be a regular file of exactly [`SECRET_LEN`]
//! bytes holding a valid secp256k1 secret (`0 < k < n`), in one of the two shapes systemd's
//! `write_credential()` leaves (it writes the file 0600, `fchmod`s it 0400, then grants the
//! service's user read with an ACL, or, where the filesystem has no ACLs, `fchown`s it):
//!
//! - **Owned** (ramfs, or a file made by hand): owned by the effective UID, mode 0400 or 0600,
//!   and no `system.posix_acl_access` ACL.
//! - **ACL-granted** (tmpfs, Linux only): owned by root, mode 0400 or 0440, with exactly the
//!   ACL `user::r--`, `user:<euid>:r--`, `group::---`, `mask::r--`, `other::---`, in a
//!   directory that is exactly `/run/credentials/<unit>` (`<unit>` the caller's own unit, e.g.
//!   `ethswarm-p2p.service`) on a read-only tmpfs or ramfs.
//!
//! Anything else is refused. The bytes live in a [`NodeKeySecret`]: zeroized on drop (and every
//! buffer they pass through on every path), `<redacted>` in `Debug` and `Display`, never part
//! of an error. Every load is logged through `tracing` (the credential's path, never its
//! bytes); `tests/log_capture.rs` checks that the key's hex and base64 never appear in a
//! captured log, and `tests/credential_acl.rs` (Linux, root) loads an ACL-granted credential
//! from a read-only tmpfs as the service's user.

use rustix::fd::{AsFd, OwnedFd};
use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The environment variable systemd points at the unit's credentials.
pub const CREDENTIALS_DIRECTORY: &str = "CREDENTIALS_DIRECTORY";
/// Where systemd mounts each system unit's credentials: `/run/credentials/<unit>`.
pub const CREDENTIALS_ROOT: &str = "/run/credentials";
/// The credential's name: `LoadCredential=nodekey:<path>`.
pub const CREDENTIAL: &str = "nodekey";
/// A secp256k1 secret key is 32 bytes, and the credential holds exactly those.
pub const SECRET_LEN: usize = 32;
/// The modes an owned credential may have: owner read-write, or owner read-only (systemd's).
pub const MODES: [u32; 2] = [0o600, 0o400];
/// The modes an ACL-granted credential may have: 0400, shown as 0440 when the ACL mask is
/// `r--` (the group bits of `st_mode` are the mask).
pub const ACL_MODES: [u32; 2] = [0o400, 0o440];
/// The ACL extended attribute.
const ACL_XATTR: &str = "system.posix_acl_access";

/// The node key's secret bytes. Zeroized on drop; `Debug` and `Display` print `<redacted>`.
pub struct NodeKeySecret(Zeroizing<[u8; SECRET_LEN]>);

impl NodeKeySecret {
    /// The secret, to build the key from. Never log it or copy it out of a zeroizing buffer.
    pub fn expose_secret(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    /// The secret, mutable, for constructors that wipe their input (libp2p's
    /// `SecretKey::try_from_bytes`, discv5's `CombinedKey::secp256k1_from_bytes`).
    pub fn expose_secret_mut(&mut self) -> &mut [u8; SECRET_LEN] {
        &mut self.0
    }
}

impl fmt::Debug for NodeKeySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for NodeKeySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Why the node key was refused. No variant carries key bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// The process runs as root; a probe service runs as its own OS user.
    #[error("refusing to run as root: run as the unit's own User=")]
    Root,
    /// `$CREDENTIALS_DIRECTORY` is not set (or empty): not started by a unit with the
    /// credential.
    #[error("${CREDENTIALS_DIRECTORY} is not set: start through the systemd unit (LoadCredential={CREDENTIAL}:<path>)")]
    NoDirectory,
    /// `$CREDENTIALS_DIRECTORY` is a relative path.
    #[error("${CREDENTIALS_DIRECTORY} must be an absolute path")]
    NotAbsolute,
    /// The file or its directory could not be opened (missing, a symlink, unreadable).
    #[error("{}: cannot open: {reason}", path.display())]
    Open { path: PathBuf, reason: String },
    /// The path is not a regular file.
    #[error("{}: not a regular file", path.display())]
    NotRegular { path: PathBuf },
    /// The permission bits are not those of the file's shape.
    #[error("{}: mode {mode:04o}, want {want}", path.display())]
    Mode {
        path: PathBuf,
        mode: u32,
        want: &'static str,
    },
    /// Neither the effective UID nor root owns the file.
    #[error("{}: owned by uid {owner}, want {euid} (or root, with an ACL for {euid})", path.display())]
    Owner {
        path: PathBuf,
        owner: u32,
        euid: u32,
    },
    /// The file's ACL is not the one shape allowed: none for an owned file, exactly
    /// systemd's read grant for a root-owned one.
    #[error("{}: ACL: {reason}", path.display())]
    Acl { path: PathBuf, reason: String },
    /// An ACL-granted credential is not in this unit's read-only systemd credentials
    /// filesystem.
    #[error("{}: {reason}", path.display())]
    Mount { path: PathBuf, reason: String },
    /// The file is not [`SECRET_LEN`] bytes.
    #[error("{}: {len} bytes, want {SECRET_LEN}", path.display())]
    Length { path: PathBuf, len: u64 },
    /// The bytes are not a valid secp256k1 secret (zero, or not below the group order).
    #[error("{}: not a secp256k1 secret key", path.display())]
    NotSecp256k1 { path: PathBuf },
    /// Reading failed.
    #[error("{}: read: {reason}", path.display())]
    Read { path: PathBuf, reason: String },
}

/// [`load`] with `$CREDENTIALS_DIRECTORY` and `geteuid()`, for the unit `unit` (its full
/// name, `ethswarm-p2p.service`).
pub fn load_from_env(unit: &str) -> Result<NodeKeySecret, CredentialError> {
    load(
        std::env::var_os(CREDENTIALS_DIRECTORY).as_deref(),
        rustix::process::geteuid().as_raw(),
        unit,
    )
}

/// Loads `<credentials_dir>/nodekey` for a process whose effective UID is `euid`, run as the
/// unit `unit` (an ACL-granted credential must be in `/run/credentials/<unit>`), and logs the
/// outcome (the path and the error, never the bytes).
pub fn load(
    credentials_dir: Option<&OsStr>,
    euid: u32,
    unit: &str,
) -> Result<NodeKeySecret, CredentialError> {
    let result = locate(credentials_dir, euid).and_then(|dir| {
        let path = dir.join(CREDENTIAL);
        let secret = read(dir, euid, unit)?;
        tracing::info!(
            credential = %path.display(),
            node_key = %secret,
            "node key loaded from the systemd credential"
        );
        Ok(secret)
    });
    if let Err(e) = &result {
        tracing::error!(error = %e, "node key refused");
    }
    result
}

/// The credentials directory, once the process is known not to be root.
fn locate(credentials_dir: Option<&OsStr>, euid: u32) -> Result<&Path, CredentialError> {
    if euid == 0 {
        return Err(CredentialError::Root);
    }
    let dir = match credentials_dir {
        Some(d) if !d.is_empty() => Path::new(d),
        _ => return Err(CredentialError::NoDirectory),
    };
    if !dir.is_absolute() {
        return Err(CredentialError::NotAbsolute);
    }
    Ok(dir)
}

/// How the credential is granted to this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    /// The effective UID owns it, and no ACL extends it.
    Owner,
    /// Root owns it, and exactly systemd's ACL grants the effective UID read.
    Acl,
}

/// Opens `<dir>/nodekey` without following a symlink and checks the open file.
fn read(dir: &Path, euid: u32, unit: &str) -> Result<NodeKeySecret, CredentialError> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::io::Read;
    let path = dir.join(CREDENTIAL);
    let at = || path.clone();
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let dir_fd =
        rustix::fs::open(dir, dir_flags, Mode::empty()).map_err(|e| CredentialError::Open {
            path: dir.to_owned(),
            reason: e.to_string(),
        })?;
    // NONBLOCK: a FIFO planted at the path is refused below instead of blocking the open.
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = rustix::fs::openat(&dir_fd, CREDENTIAL, flags, Mode::empty()).map_err(|e| {
        CredentialError::Open {
            path: at(),
            reason: e.to_string(),
        }
    })?;
    let st = rustix::fs::fstat(&fd).map_err(|e| CredentialError::Read {
        path: at(),
        reason: e.to_string(),
    })?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(CredentialError::NotRegular { path: at() });
    }
    let acl = access_acl(&fd, &path)?;
    if grant(
        &path,
        mode_bits(st.st_mode),
        st.st_uid,
        euid,
        acl.as_deref(),
    )? == Grant::Acl
    {
        credentials_mount(&dir_fd, dir, unit)?;
    }
    let len = u64::try_from(st.st_size).unwrap_or(u64::MAX);
    if len != SECRET_LEN as u64 {
        return Err(CredentialError::Length { path: at(), len });
    }
    let mut secret = NodeKeySecret(Zeroizing::new([0; SECRET_LEN]));
    std::fs::File::from(fd)
        .read_exact(&mut secret.0[..])
        .map_err(|e| CredentialError::Read {
            path: at(),
            reason: e.to_string(),
        })?;
    if !is_secp256k1_secret(&secret.0) {
        return Err(CredentialError::NotSecp256k1 { path: at() });
    }
    Ok(secret)
}

/// Which shape grants the file (mode `mode`, owner `owner`, access ACL `acl`) to `euid`, or
/// why none does.
fn grant(
    path: &Path,
    mode: u32,
    owner: u32,
    euid: u32,
    acl: Option<&[u8]>,
) -> Result<Grant, CredentialError> {
    let refuse_acl = |reason: String| CredentialError::Acl {
        path: path.to_owned(),
        reason,
    };
    if owner == euid {
        if !MODES.contains(&mode) {
            return Err(CredentialError::Mode {
                path: path.to_owned(),
                mode,
                want: "0600 or 0400",
            });
        }
        if acl.is_some() {
            return Err(refuse_acl(
                "an owned credential must carry no ACL: it could grant others access".into(),
            ));
        }
        return Ok(Grant::Owner);
    }
    if owner != 0 {
        return Err(CredentialError::Owner {
            path: path.to_owned(),
            owner,
            euid,
        });
    }
    if !ACL_MODES.contains(&mode) {
        return Err(CredentialError::Mode {
            path: path.to_owned(),
            mode,
            want: "0400 or 0440 for a root-owned credential",
        });
    }
    let acl = acl.ok_or_else(|| refuse_acl(format!("root's file and no ACL grants uid {euid}")))?;
    check_acl(acl, euid).map_err(refuse_acl)?;
    Ok(Grant::Acl)
}

/// The file's `system.posix_acl_access`, or `None` if it has none (or the filesystem has no
/// extended attributes, like ramfs). Off Linux there are no POSIX ACL xattrs: always `None`.
#[cfg(target_os = "linux")]
fn access_acl(fd: &OwnedFd, path: &Path) -> Result<Option<Vec<u8>>, CredentialError> {
    use rustix::io::Errno;
    // Room for 16 entries; systemd's ACL has 5.
    let mut buf = [0u8; 4 + 8 * 16];
    match rustix::fs::fgetxattr(fd, ACL_XATTR, &mut buf[..]) {
        Ok(len) => Ok(Some(buf[..len].to_vec())),
        Err(Errno::NODATA | Errno::OPNOTSUPP) => Ok(None),
        Err(Errno::RANGE) => Err(CredentialError::Acl {
            path: path.to_owned(),
            reason: "more than 16 entries".into(),
        }),
        Err(e) => Err(CredentialError::Read {
            path: path.to_owned(),
            reason: format!("{ACL_XATTR}: {e}"),
        }),
    }
}

#[cfg(not(target_os = "linux"))]
fn access_acl(_fd: &OwnedFd, _path: &Path) -> Result<Option<Vec<u8>>, CredentialError> {
    let _ = ACL_XATTR;
    Ok(None)
}

/// Refuses an ACL-granted credential unless its directory `dir` (open as `dir_fd`) is exactly
/// `/run/credentials/<unit>` on a read-only tmpfs or ramfs: the mount systemd sets up, which
/// the service's user cannot change.
fn credentials_mount(dir_fd: &impl AsFd, dir: &Path, unit: &str) -> Result<(), CredentialError> {
    let refuse = |reason: String| CredentialError::Mount {
        path: dir.to_owned(),
        reason,
    };
    if unit.is_empty() || unit == "." || unit == ".." || unit.contains('/') {
        return Err(refuse(format!("{unit:?} is not a unit name")));
    }
    let want = Path::new(CREDENTIALS_ROOT).join(unit);
    if dir.as_os_str() != want.as_os_str() {
        return Err(refuse(format!(
            "a root-owned credential is accepted only from {}, this unit's systemd credentials",
            want.display()
        )));
    }
    credentials_fs(dir_fd).map_err(refuse)
}

/// tmpfs, ramfs: the filesystems systemd puts credentials on.
#[cfg(target_os = "linux")]
const CREDENTIALS_FS_MAGIC: [i64; 2] = [0x0102_1994, 0x8584_58f6];

#[cfg(target_os = "linux")]
fn credentials_fs(dir_fd: &impl AsFd) -> Result<(), String> {
    let fs = rustix::fs::fstatfs(dir_fd).map_err(|e| format!("fstatfs: {e}"))?;
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    let magic = i64::from(fs.f_type) & 0xffff_ffff;
    if !CREDENTIALS_FS_MAGIC.contains(&magic) {
        return Err(format!(
            "filesystem type {magic:#x}, want tmpfs or ramfs (systemd's credentials mount)"
        ));
    }
    let vfs = rustix::fs::fstatvfs(dir_fd).map_err(|e| format!("fstatvfs: {e}"))?;
    if !vfs.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY) {
        return Err("mounted read-write: systemd's credentials mount is read-only".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn credentials_fs(_dir_fd: &impl AsFd) -> Result<(), String> {
    Err("a root-owned, ACL-granted credential is accepted only on Linux".into())
}

/// ACL entry tags (`linux/posix_acl.h`).
const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
/// A named group entry: never part of the accepted shape.
#[cfg(test)]
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;
/// Read permission in an ACL entry.
const ACL_READ: u16 = 0x04;
/// `POSIX_ACL_XATTR_VERSION`.
const ACL_XATTR_VERSION: u32 = 2;

/// One entry of a POSIX ACL xattr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AclEntry {
    tag: u16,
    perm: u16,
    /// The user or group of a named entry; unused (`ACL_UNDEFINED_ID`) otherwise.
    id: u32,
}

/// Decodes `system.posix_acl_access` as the kernel stores it: a little-endian `u32` version
/// 2, then 8-byte entries of tag (`u16`), permissions (`u16`) and id (`u32`).
fn decode_acl(bytes: &[u8]) -> Result<Vec<AclEntry>, String> {
    let Some((version, entries)) = bytes.split_first_chunk::<4>() else {
        return Err(format!("{} bytes: no header", bytes.len()));
    };
    let version = u32::from_le_bytes(*version);
    if version != ACL_XATTR_VERSION {
        return Err(format!("version {version}, want {ACL_XATTR_VERSION}"));
    }
    if entries.len() % 8 != 0 {
        return Err(format!(
            "{} bytes of entries, not a multiple of 8",
            entries.len()
        ));
    }
    Ok(entries
        .as_chunks::<8>()
        .0
        .iter()
        .map(|e| AclEntry {
            tag: u16::from_le_bytes([e[0], e[1]]),
            perm: u16::from_le_bytes([e[2], e[3]]),
            id: u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
        })
        .collect())
}

/// Accepts exactly the ACL systemd's `write_credential()` leaves for the service's user
/// `euid`: `user::r--`, `user:<euid>:r--`, `group::---`, `mask::r--`, `other::---`, in any
/// order, nothing else.
fn check_acl(bytes: &[u8], euid: u32) -> Result<(), String> {
    let entries = decode_acl(bytes)?;
    let want = [
        (ACL_USER_OBJ, ACL_READ, "user::r--"),
        (ACL_USER, ACL_READ, "user:<euid>:r--"),
        (ACL_GROUP_OBJ, 0, "group::---"),
        (ACL_MASK, ACL_READ, "mask::r--"),
        (ACL_OTHER, 0, "other::---"),
    ];
    let shape = "want exactly user::r--, user:<euid>:r--, group::---, mask::r--, other::---";
    if entries.len() != want.len() {
        return Err(format!("{} entries; {shape}", entries.len()));
    }
    for (tag, perm, name) in want {
        let mut matching = entries.iter().filter(|e| e.tag == tag);
        let (Some(entry), None) = (matching.next(), matching.next()) else {
            return Err(format!("not exactly one {name} entry; {shape}"));
        };
        if tag == ACL_USER && entry.id != euid {
            return Err(format!("the named user is uid {}, not {euid}", entry.id));
        }
        if entry.perm != perm {
            return Err(format!("{name} has permissions {:#o}; {shape}", entry.perm));
        }
    }
    // Five entries, each of the five tags once: no named group, no unknown tag.
    Ok(())
}

/// The secp256k1 group order n, big-endian.
const ORDER: [u8; SECRET_LEN] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// `0 < k < n`, read big-endian. Every byte is visited, so the time does not depend on where
/// the secret first differs from n.
fn is_secp256k1_secret(k: &[u8; SECRET_LEN]) -> bool {
    let mut nonzero = 0u8;
    // Below n: at the first byte where k and n differ, k's is the smaller.
    let mut decided = false;
    let mut below = false;
    for (&byte, &order) in k.iter().zip(ORDER.iter()) {
        nonzero |= byte;
        let differs = byte != order;
        below |= !decided & differs & (byte < order);
        decided |= differs;
    }
    nonzero != 0 && below
}

// `mode_t` is `u16` on macOS and `u32` on Linux.
#[allow(clippy::unnecessary_cast)]
fn mode_bits(raw: rustix::fs::RawMode) -> u32 {
    (raw as u32) & 0o7777
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// The secp256k1 group order n.
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    const UNIT: &str = "ethswarm-test.service";

    /// The UID the tests play: this process's, or (as root, which the loader refuses) a
    /// service UID the test files are given to.
    fn euid() -> u32 {
        match rustix::process::geteuid().as_raw() {
            0 => 4242,
            euid => euid,
        }
    }

    /// A credentials directory holding `nodekey` with `bytes` and `mode`, owned by `euid()`.
    fn credentials(mode: u32, bytes: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CREDENTIAL);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        if rustix::process::geteuid().is_root() {
            let owner = Some(rustix::process::Uid::from_raw(euid()));
            rustix::fs::chown(&path, owner, None).unwrap();
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    fn load_in(dir: &tempfile::TempDir, euid: u32) -> Result<NodeKeySecret, CredentialError> {
        load(Some(dir.path().as_os_str()), euid, UNIT)
    }

    #[test]
    fn loads_an_owner_only_credential() {
        for mode in MODES {
            let dir = credentials(mode, &[7; 32]);
            let mut secret = load_in(&dir, euid()).unwrap();
            assert_eq!(secret.expose_secret(), &[7; 32], "{mode:o}");
            assert_eq!(secret.expose_secret_mut(), &mut [7; 32]);
        }
    }

    #[test]
    fn accepts_the_largest_secret_below_the_order() {
        let mut below = ORDER;
        below[31] -= 1;
        let dir = credentials(0o600, &below);
        assert_eq!(load_in(&dir, euid()).unwrap().expose_secret(), &below);
        let mut one = [0; 32];
        one[31] = 1;
        let dir = credentials(0o600, &one);
        assert!(load_in(&dir, euid()).is_ok());
    }

    #[test]
    fn refuses_root_before_reading() {
        let dir = credentials(0o600, &[7; 32]);
        assert_eq!(load_in(&dir, 0).unwrap_err(), CredentialError::Root);
        assert_eq!(load(None, 0, UNIT).unwrap_err(), CredentialError::Root);
    }

    #[test]
    fn needs_an_absolute_credentials_directory() {
        assert_eq!(
            load(None, euid(), UNIT).unwrap_err(),
            CredentialError::NoDirectory
        );
        assert_eq!(
            load(Some(OsStr::new("")), euid(), UNIT).unwrap_err(),
            CredentialError::NoDirectory
        );
        assert_eq!(
            load(Some(OsStr::new("creds")), euid(), UNIT).unwrap_err(),
            CredentialError::NotAbsolute
        );
    }

    #[test]
    fn refuses_a_credential_others_can_read_or_write() {
        for mode in [0o644, 0o640, 0o604, 0o660, 0o700, 0o4600, 0o2400] {
            let dir = credentials(mode, &[7; 32]);
            let err = load_in(&dir, euid()).unwrap_err();
            assert!(
                matches!(err, CredentialError::Mode { mode: m, .. } if m == mode),
                "{mode:o}: {err:?}"
            );
        }
    }

    #[test]
    fn refuses_another_owner() {
        let dir = credentials(0o600, &[7; 32]);
        let err = load_in(&dir, euid() + 1).unwrap_err();
        assert_eq!(
            err,
            CredentialError::Owner {
                path: dir.path().join(CREDENTIAL),
                owner: euid(),
                euid: euid() + 1
            }
        );
    }

    #[test]
    fn refuses_a_wrong_length_or_an_invalid_secret() {
        for bytes in [&[7; 31][..], &[7; 33], &[]] {
            let dir = credentials(0o600, bytes);
            let err = load_in(&dir, euid()).unwrap_err();
            assert!(
                matches!(err, CredentialError::Length { len, .. } if len == bytes.len() as u64),
                "{err:?}"
            );
        }
        for bytes in [[0; 32], ORDER, [0xff; 32]] {
            let dir = credentials(0o600, &bytes);
            let err = load_in(&dir, euid()).unwrap_err();
            assert!(
                matches!(err, CredentialError::NotSecp256k1 { .. }),
                "{err:?}"
            );
        }
    }

    #[test]
    fn refuses_a_missing_file_a_symlink_or_a_directory() {
        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            load_in(&empty, euid()).unwrap_err(),
            CredentialError::Open { .. }
        ));
        let real = credentials(0o600, &[7; 32]);
        let linked = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(real.path().join(CREDENTIAL), linked.path().join(CREDENTIAL))
            .unwrap();
        assert!(
            matches!(
                load_in(&linked, euid()).unwrap_err(),
                CredentialError::Open { .. }
            ),
            "a symlink is not followed"
        );
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join(CREDENTIAL);
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_in(&dir, euid()).unwrap_err(),
            CredentialError::NotRegular { path: sub }
        );
    }

    #[test]
    fn the_secret_and_every_error_are_redacted() {
        let dir = credentials(0o600, &[0xab; 32]);
        let secret = load_in(&dir, euid()).unwrap();
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert_eq!(format!("{secret}"), "<redacted>");
        assert_eq!(format!("{:?}", Some(&secret)), "Some(<redacted>)");
        for (mode, bytes) in [(0o644, [0xab; 32]), (0o600, [0xff; 32])] {
            let dir = credentials(mode, &bytes);
            let err = load_in(&dir, euid()).unwrap_err();
            let shown = format!("{err} {err:?}");
            assert!(
                !shown.contains("abab") && !shown.contains("ffff"),
                "{shown}"
            );
            assert!(!shown.contains("171, 171"), "{shown}");
        }
    }

    // --- the POSIX ACL xattr and the two credential shapes ------------------------------------

    /// `system.posix_acl_access` as the kernel stores it: version 2, then (tag, perm, id)
    /// little-endian.
    fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for &(tag, perm, id) in entries {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&perm.to_le_bytes());
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        bytes
    }

    const NO_ID: u32 = u32::MAX;
    const UID: u32 = 991;

    /// What systemd's `write_credential` leaves: 0400, then read for the service's user.
    fn systemd_acl(uid: u32) -> Vec<u8> {
        acl(&[
            (ACL_USER_OBJ, 4, NO_ID),
            (ACL_USER, 4, uid),
            (ACL_GROUP_OBJ, 0, NO_ID),
            (ACL_MASK, 4, NO_ID),
            (ACL_OTHER, 0, NO_ID),
        ])
    }

    #[test]
    fn decodes_the_acl_systemd_writes() {
        let entries = decode_acl(&systemd_acl(UID)).unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(
            entries[1],
            AclEntry {
                tag: ACL_USER,
                perm: 4,
                id: UID
            }
        );
        assert_eq!(check_acl(&systemd_acl(UID), UID), Ok(()));
        // Entry order does not matter.
        let mut shuffled = decode_acl(&systemd_acl(UID)).unwrap();
        shuffled.reverse();
        let bytes = acl(&shuffled
            .iter()
            .map(|e| (e.tag, e.perm, e.id))
            .collect::<Vec<_>>());
        assert_eq!(check_acl(&bytes, UID), Ok(()));
    }

    #[test]
    fn refuses_any_other_acl() {
        let base = [
            (ACL_USER_OBJ, 4, NO_ID),
            (ACL_USER, 4, UID),
            (ACL_GROUP_OBJ, 0, NO_ID),
            (ACL_MASK, 4, NO_ID),
            (ACL_OTHER, 0, NO_ID),
        ];
        let with = |i: usize, entry: (u16, u16, u32)| {
            let mut e = base.to_vec();
            e[i] = entry;
            acl(&e)
        };
        let plus = |entry: (u16, u16, u32)| {
            let mut e = base.to_vec();
            e.push(entry);
            acl(&e)
        };
        for (what, bytes) in [
            ("another user", with(1, (ACL_USER, 4, UID + 1))),
            ("write for the user", with(1, (ACL_USER, 6, UID))),
            ("execute for the user", with(1, (ACL_USER, 5, UID))),
            ("write for the owner", with(0, (ACL_USER_OBJ, 6, NO_ID))),
            ("a readable group", with(2, (ACL_GROUP_OBJ, 4, NO_ID))),
            ("a write mask", with(3, (ACL_MASK, 6, NO_ID))),
            ("readable by other", with(4, (ACL_OTHER, 4, NO_ID))),
            ("an extra named user", plus((ACL_USER, 4, UID + 1))),
            ("a named group", plus((ACL_GROUP, 4, 50))),
            ("a duplicate entry", plus((ACL_USER, 4, UID))),
            ("an unknown tag", plus((0x40, 0, NO_ID))),
            ("no user entry", acl(&[base[0], base[2], base[3], base[4]])),
            ("no mask", acl(&[base[0], base[1], base[2], base[4]])),
            ("no entries", acl(&[])),
        ] {
            assert!(check_acl(&bytes, UID).is_err(), "{what} accepted");
        }
        let good = systemd_acl(UID);
        let mut v1 = good.clone();
        v1[0] = 1;
        for (what, bytes) in [
            ("empty", Vec::new()),
            ("a short header", good[..3].to_vec()),
            ("a cut entry", good[..good.len() - 1].to_vec()),
            ("version 1", v1),
        ] {
            assert!(decode_acl(&bytes).is_err(), "{what} decoded");
            assert!(check_acl(&bytes, UID).is_err(), "{what} accepted");
        }
    }

    #[test]
    fn grants_exactly_the_two_systemd_shapes() {
        let path = Path::new("/run/credentials/x.service/nodekey");
        let acl = systemd_acl(UID);
        // (a) owned by the service's user, owner-only, no ACL (ramfs, or a hand-made file).
        for mode in [0o400, 0o600] {
            assert_eq!(
                grant(path, mode, UID, UID, None),
                Ok(Grant::Owner),
                "{mode:o}"
            );
        }
        // (b) root's, read-only, the ACL granting the service's user read (tmpfs).
        for mode in [0o400, 0o440] {
            assert_eq!(
                grant(path, mode, 0, UID, Some(&acl)),
                Ok(Grant::Acl),
                "{mode:o}"
            );
        }
        for (what, mode, owner, a) in [
            ("an owned file with an ACL", 0o400, UID, Some(&acl[..])),
            ("an owned file readable by the group", 0o440, UID, None),
            ("root's file without an ACL", 0o400, 0, None),
            ("root's file writable by root", 0o600, 0, Some(&acl[..])),
            (
                "root's file with a group-write mask",
                0o460,
                0,
                Some(&acl[..]),
            ),
            ("root's file readable by other", 0o444, 0, Some(&acl[..])),
            (
                "root's file with another user's ACL",
                0o440,
                0,
                Some(&systemd_acl(UID + 1)[..]),
            ),
            ("another user's file", 0o400, UID + 1, None),
            (
                "another user's file with an ACL",
                0o440,
                UID + 1,
                Some(&acl[..]),
            ),
        ] {
            assert!(grant(path, mode, owner, UID, a).is_err(), "{what} granted");
        }
    }

    #[test]
    fn an_acl_granted_credential_needs_the_units_read_only_credentials_fs() {
        // Off Linux, or anywhere but /run/credentials/<unit>, the ACL shape is refused.
        let dir = tempfile::tempdir().unwrap();
        let fd = rustix::fs::open(
            dir.path(),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let err = credentials_mount(&fd, dir.path(), UNIT).unwrap_err();
        assert!(matches!(err, CredentialError::Mount { .. }), "{err:?}");
        for unit in ["", ".", "..", "a/b.service"] {
            let p = Path::new(CREDENTIALS_ROOT).join(unit);
            assert!(credentials_mount(&fd, &p, unit).is_err(), "{unit:?}");
        }
    }
}
