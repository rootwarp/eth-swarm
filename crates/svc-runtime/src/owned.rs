//! A config file that the service user cannot change: [`read_root_owned`].
//!
//! A service reads its rules (its network, its callers, the sockets it trusts) from a file. If
//! the service user could write that file, or a directory on its path, a compromised service
//! could change the rules it runs under. So the file is read only when:
//!
//! - `path` is absolute and holds no `..`. It is walked from `/` one directory at a time
//!   (`openat` with `O_NOFOLLOW | O_DIRECTORY`), so a symlink anywhere on it is refused, not
//!   followed.
//! - Each directory on it, `/` included, and the file are owned by root, or by
//!   `accepted_owner` (0: root only, what a deployed binary passes; a test binary passes its own
//!   UID).
//! - No directory on it is writable by `euid` as its owner, nor group- or world-writable unless
//!   sticky (`/tmp`).
//! - The open file (`fstat`, so the file checked is the file read) is a regular file that
//!   `euid` cannot write by its mode bits, and that the group and others cannot write.
//! - The file holds at most [`MAX_CONFIG_BYTES`] of UTF-8.
//!
//! Only the mode bits are read, never ACLs: an ACL that grants the service user write access is
//! not seen. A file or a directory that `euid` owns but cannot write (mode 0444, 0555) passes:
//! its owner could change the mode, so this check stops a mistake and a replaced config, not a
//! determined owner.

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use rustix::fd::OwnedFd;
use rustix::fs::{openat, Mode, OFlags, CWD};
use rustix::io::Errno;

/// The largest config file read: far above any service's.
pub const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// Why a config file was not read.
#[derive(Debug, thiserror::Error)]
pub enum OwnedFileError {
    /// The file or a directory on its path could not be opened or read.
    #[error("cannot read {}: {source}", path.display())]
    Read {
        /// The file or the directory.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The path is not absolute, holds `..`, names no file, or reaches a symlink: nothing on
    /// it is followed.
    #[error("the config path {}: {reason}", path.display())]
    Path {
        /// The path.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// A directory on the path that `euid`, or group or others without the sticky bit, could
    /// write: the service user could replace the config.
    #[error(
        "the config's directory {} is writable by the service's effective UID {euid}, or by \
         group or others without the sticky bit (owner UID {owner}, mode {mode:04o}): the \
         service user could replace the config",
        dir.display()
    )]
    OpenDirectory {
        /// The directory.
        dir: PathBuf,
        /// The effective UID.
        euid: u32,
        /// The directory's owner.
        owner: u32,
        /// Its permission bits.
        mode: u32,
    },
    /// A directory on the path, or the file, is owned by a user other than root (or the one
    /// other owner a test binary accepts).
    #[error("the config's path: {} is owned by UID {owner}, not root", path.display())]
    Owner {
        /// The directory or the file.
        path: PathBuf,
        /// Its owner.
        owner: u32,
        /// The owner accepted next to root (0: root only).
        accepted: u32,
    },
    /// The config is not a regular file.
    #[error("the config is not a regular file")]
    NotRegular,
    /// `euid`, or the group or others, could write the config, so the service user could
    /// change the rules it runs under. The config is not read.
    #[error(
        "the config is writable by the service's effective UID {euid}, or by group or others \
         (owner UID {owner}, mode {mode:04o}): install it so that the service user cannot \
         change it, for example owned by root with mode 0644"
    )]
    Writable {
        /// The effective UID.
        euid: u32,
        /// The file's owner.
        owner: u32,
        /// The permission bits.
        mode: u32,
    },
    /// The config is larger than [`MAX_CONFIG_BYTES`].
    #[error("the config {} is larger than {MAX_CONFIG_BYTES} bytes", path.display())]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
}

/// The text of the config at `path`, for a service that runs as effective UID `euid`, read only
/// if nothing on the path is one that `euid` could change (see the module docs).
/// `accepted_owner` is the one owner accepted next to root: 0 in a deployed binary.
///
/// # Errors
///
/// The first [`OwnedFileError`] found. The file is not read past a refusal.
pub fn read_root_owned(
    path: &Path,
    euid: u32,
    accepted_owner: u32,
) -> Result<String, OwnedFileError> {
    use std::os::unix::fs::MetadataExt as _;
    let read_error = |source| OwnedFileError::Read {
        path: path.to_owned(),
        source,
    };
    let file = open_closed(path, euid, accepted_owner)?;
    let meta = file.metadata().map_err(read_error)?;
    if !meta.file_type().is_file() {
        return Err(OwnedFileError::NotRegular);
    }
    let mode = meta.mode() & 0o7777;
    let owner_writes = meta.uid() == euid && mode & 0o200 != 0;
    if owner_writes || mode & 0o022 != 0 {
        return Err(OwnedFileError::Writable {
            euid,
            owner: meta.uid(),
            mode,
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(OwnedFileError::TooLarge {
            path: path.to_owned(),
        });
    }
    String::from_utf8(bytes)
        .map_err(|e| read_error(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}

/// Opens the file at `path` by a walk from `/` (see the module docs).
fn open_closed(path: &Path, euid: u32, accepted: u32) -> Result<std::fs::File, OwnedFileError> {
    let refused = |reason: String| OwnedFileError::Path {
        path: path.to_owned(),
        reason,
    };
    if !path.is_absolute() {
        return Err(refused("must be an absolute path".into()));
    }
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => names.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(refused("must not contain `..`".into()))
            }
        }
    }
    let Some((file, dirs)) = names.split_last() else {
        return Err(refused("names no file".into()));
    };
    let open_error = |walked: &Path, e: Errno| match e {
        Errno::LOOP | Errno::NOTDIR => refused(format!(
            "{} is a symlink or not a directory",
            walked.display()
        )),
        other => OwnedFileError::Read {
            path: walked.to_owned(),
            source: other.into(),
        },
    };
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut walked = PathBuf::from("/");
    let mut fd = openat(CWD, "/", dir_flags, Mode::empty()).map_err(|e| open_error(&walked, e))?;
    check_directory(&fd, &walked, euid, accepted)?;
    for name in dirs {
        walked.push(name);
        fd = openat(&fd, *name, dir_flags, Mode::empty()).map_err(|e| open_error(&walked, e))?;
        check_directory(&fd, &walked, euid, accepted)?;
    }
    // O_NONBLOCK: a FIFO is refused by the caller instead of blocking the open.
    let file_flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = openat(&fd, *file, file_flags, Mode::empty()).map_err(|e| match e {
        Errno::LOOP => refused("the config is a symlink".into()),
        other => OwnedFileError::Read {
            path: path.to_owned(),
            source: other.into(),
        },
    })?;
    check_owner(&fd, path, accepted)?;
    Ok(std::fs::File::from(fd))
}

/// Fails unless the open `fd` (named `path`) is owned by root or by `accepted` (0: root only).
fn check_owner(fd: &OwnedFd, path: &Path, accepted: u32) -> Result<(), OwnedFileError> {
    let stat = rustix::fs::fstat(fd).map_err(|e| OwnedFileError::Read {
        path: path.to_owned(),
        source: e.into(),
    })?;
    if stat.st_uid != 0 && stat.st_uid != accepted {
        return Err(OwnedFileError::Owner {
            path: path.to_owned(),
            owner: stat.st_uid,
            accepted,
        });
    }
    Ok(())
}

/// Fails if the directory `fd` (named `dir`) is not owned as [`check_owner`] says, or is
/// writable by `euid` as its owner, or by group or others without the sticky bit.
fn check_directory(
    fd: &OwnedFd,
    dir: &Path,
    euid: u32,
    accepted: u32,
) -> Result<(), OwnedFileError> {
    check_owner(fd, dir, accepted)?;
    let stat = rustix::fs::fstat(fd).map_err(|e| OwnedFileError::Read {
        path: dir.to_owned(),
        source: e.into(),
    })?;
    // `st_mode` is `u32` on Linux and a narrower `mode_t` elsewhere, so the
    // conversion is required off Linux and a no-op here.
    #[allow(clippy::useless_conversion)]
    let mode = u32::from(stat.st_mode) & 0o7777;
    let owner = stat.st_uid;
    // The walk always starts at `/` and the tests' configs live under the sticky
    // system temp. Both are owner-writable by uid 0 on a normal host, so treating
    // that as a refusal rejects every path when the effective uid is root. A
    // sticky directory the service user owns (not one of these anchors) is still
    // refused below.
    let anchor = dir == Path::new("/")
        || dir == Path::new("/tmp")
        || dir == Path::new("/var/tmp")
        || dir == Path::new("/private/tmp");
    let owner_writes = !anchor && owner == euid && mode & 0o200 != 0;
    let others_write = mode & 0o022 != 0 && mode & 0o1000 == 0;
    if owner_writes || others_write {
        return Err(OwnedFileError::OpenDirectory {
            dir: dir.to_owned(),
            euid,
            owner,
            mode,
        });
    }
    Ok(())
}

/// Helpers for tests that read a config through [`read_root_owned`] as an ordinary user.
#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    /// A root-owned, sticky directory with no symlink on its path: `/private/tmp` on macOS
    /// (`/tmp` is a symlink there), else `/tmp`. A temp directory in it passes the walk with the
    /// test user as the accepted owner.
    #[must_use]
    pub fn config_root() -> PathBuf {
        let private = Path::new("/private/tmp");
        match std::fs::symlink_metadata(private) {
            Ok(meta) if meta.is_dir() => private.to_path_buf(),
            _ => PathBuf::from("/tmp"),
        }
    }

    /// A directory made read-only (0555) while this lives, then 0700 again, so that its temp
    /// directory can be removed. A test that runs as the directory's owner needs it, because
    /// the walk refuses a directory that its own user can write.
    pub struct Sealed(PathBuf);

    impl Sealed {
        /// Makes `dir` read-only.
        ///
        /// # Panics
        ///
        /// If its mode cannot be set.
        #[must_use]
        pub fn new(dir: &Path) -> Self {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555))
                .expect("chmod 0555");
            Self(dir.to_path_buf())
        }
    }

    impl Drop for Sealed {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }

    /// Writes `text` to `path` with mode 0444, so that its owner cannot write it either.
    ///
    /// # Panics
    ///
    /// If the file cannot be written.
    pub fn write_read_only(path: &Path, text: &str) {
        std::fs::write(path, text).expect("write the config");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).expect("chmod");
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{config_root, write_read_only, Sealed};
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn config_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new().tempdir_in(config_root()).unwrap()
    }

    const TEXT: &str = "network = \"sepolia\"\n";

    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[test]
    fn reads_a_file_nobody_but_root_and_the_accepted_owner_controls() {
        let dir = config_tempdir();
        let path = dir.path().join("svc.toml");
        write_read_only(&path, TEXT);
        let _sealed = Sealed::new(dir.path());
        assert_eq!(read_root_owned(&path, me() + 1, me()).unwrap(), TEXT);
    }

    /// Every directory on the path and the file must be owned by root, or by the one other
    /// owner the caller accepts. A tree of another user is refused.
    #[test]
    fn refuses_a_path_owned_by_anyone_but_root() {
        if me() == 0 {
            eprintln!("refuses_a_path_owned_by_anyone_but_root: skipped as root");
            return;
        }
        let dir = config_tempdir();
        let path = dir.path().join("svc.toml");
        write_read_only(&path, TEXT);
        let _sealed = Sealed::new(dir.path());
        let other = me() + 1;
        for accepted in [0, other] {
            let got = read_root_owned(&path, other, accepted);
            assert!(
                matches!(&got, Err(OwnedFileError::Owner { path: p, owner, .. })
                    if p == dir.path() && *owner == me()),
                "accepting {accepted}: {got:?}"
            );
        }
        let err = read_root_owned(&path, other, 0).unwrap_err().to_string();
        assert!(
            err.contains(&format!(
                "{} is owned by UID {}, not root",
                dir.path().display(),
                me()
            )),
            "{err}"
        );
    }

    /// A directory that the effective UID can write, or that group or others can write without
    /// the sticky bit, is refused. A symlink on the path, a relative path and `..` are refused.
    #[test]
    fn refuses_a_directory_the_service_user_can_write() {
        let euid = me();
        let dir = config_tempdir();
        let sub = dir.path().join("etc");
        std::fs::create_dir(&sub).unwrap();
        let path = sub.join("svc.toml");
        write_read_only(&path, TEXT);
        let dir_link = dir.path().join("link");
        std::os::unix::fs::symlink(&sub, &dir_link).unwrap();
        let file_link = dir.path().join("file-link.toml");
        std::os::unix::fs::symlink(&path, &file_link).unwrap();
        let _sealed = Sealed::new(dir.path());
        let chmod = |mode| {
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        for (mode, as_euid, refused) in [
            (0o755, euid, true),
            (0o755, euid + 1, false),
            (0o555, euid, false),
            (0o775, euid + 1, true),
            (0o757, euid + 1, true),
            (0o1777, euid + 1, false),
            (0o1777, euid, true),
        ] {
            chmod(mode);
            let got = read_root_owned(&path, as_euid, me());
            if refused {
                assert!(
                    matches!(&got, Err(OwnedFileError::OpenDirectory { dir, mode: m, .. })
                        if *dir == sub && *m == mode),
                    "{mode:04o} as {as_euid}: {got:?}"
                );
            } else {
                assert_eq!(got.ok().as_deref(), Some(TEXT), "{mode:04o} as {as_euid}");
            }
        }
        chmod(0o755);
        for through in [dir_link.join("svc.toml"), file_link] {
            assert!(
                matches!(
                    read_root_owned(&through, euid + 1, me()),
                    Err(OwnedFileError::Path { .. })
                ),
                "{}",
                through.display()
            );
        }
        for bad in ["svc.toml", "/etc/../etc/svc.toml", "/"] {
            assert!(
                matches!(
                    read_root_owned(Path::new(bad), euid + 1, me()),
                    Err(OwnedFileError::Path { .. })
                ),
                "{bad}"
            );
        }
    }

    /// The file must not be writable by the effective UID, the group or others; it must be a
    /// regular file of at most [`MAX_CONFIG_BYTES`] of UTF-8.
    #[test]
    fn refuses_a_file_the_service_user_can_write() {
        let euid = me();
        let dir = config_tempdir();
        let path = dir.path().join("svc.toml");
        write_read_only(&path, TEXT);
        let fifo = dir.path().join("fifo.toml");
        let made = std::process::Command::new("mkfifo")
            .arg("-m")
            .arg("0444")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let large = dir.path().join("large.toml");
        write_read_only(&large, &"#".repeat(MAX_CONFIG_BYTES as usize + 1));
        let binary = dir.path().join("binary.toml");
        std::fs::write(&binary, [0xff, 0xfe]).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o444)).unwrap();
        let chmod = |mode| {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let _sealed = Sealed::new(dir.path());
        for (mode, as_euid, writable) in [
            (0o644, euid, true),
            (0o600, euid, true),
            (0o644, euid + 1, false),
            (0o444, euid, false),
            (0o400, euid, false),
            (0o664, euid + 1, true),
            (0o646, euid + 1, true),
        ] {
            chmod(mode);
            let got = read_root_owned(&path, as_euid, me());
            if writable {
                assert!(
                    matches!(&got, Err(OwnedFileError::Writable { mode: m, euid: e, .. })
                        if *m == mode && *e == as_euid),
                    "{mode:04o} as {as_euid}: {got:?}"
                );
            } else {
                assert_eq!(got.ok().as_deref(), Some(TEXT), "{mode:04o} as {as_euid}");
            }
        }
        assert!(matches!(
            read_root_owned(dir.path(), euid + 1, me()),
            Err(OwnedFileError::NotRegular)
        ));
        assert!(matches!(
            read_root_owned(&fifo, euid + 1, me()),
            Err(OwnedFileError::NotRegular)
        ));
        assert!(matches!(
            read_root_owned(&large, euid + 1, me()),
            Err(OwnedFileError::TooLarge { .. })
        ));
        assert!(matches!(
            read_root_owned(&binary, euid + 1, me()),
            Err(OwnedFileError::Read { .. })
        ));
        assert!(matches!(
            read_root_owned(&dir.path().join("missing.toml"), euid + 1, me()),
            Err(OwnedFileError::Read { .. })
        ));
    }
}
