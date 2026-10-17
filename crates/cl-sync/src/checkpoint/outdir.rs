//! The output directory and its quarantine, held open by descriptor.
//!
//! [`Dir::open_out`] opens `<out>` with `O_DIRECTORY | O_NOFOLLOW` (creating it, mode 0700, if
//! it is missing) and `fstat`s the open directory: it must be a directory owned by the
//! effective uid with no group or other write permission, or the run is refused with
//! [`AnchorError::UnsafePath`]. [`Dir::open_child`] does the same for `quarantine/` and each
//! run's `quarantine/<random>/`, relative to the parent's descriptor.
//!
//! Every later file operation of a run goes through a held [`Dir`] (`openat`, `mkdirat`,
//! `linkat`, `unlinkat`, `fstatat`, all without following a symlink in the last step), so
//! renaming or replacing a path after the checks cannot redirect a write. Only the last
//! component of `<out>` is checked; the directories above it are taken as given.

use crate::checkpoint::fetch::AnchorError;
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, CWD};
use rustix::io::Errno;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Mode of every directory a run creates.
const DIR_MODE: u32 = 0o700;
/// Mode of every file a run creates.
const FILE_MODE: u32 = 0o600;
/// Group and other write permission.
const GROUP_OTHER_WRITE: u32 = 0o022;

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Why a directory or file of the output directory is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UnsafeReason {
    /// The path is a symlink.
    #[error("is a symlink")]
    Symlink,
    /// The path is not the kind of file expected there.
    #[error("is a {got}, not a {expected}")]
    WrongType {
        expected: &'static str,
        got: &'static str,
    },
    /// The path is owned by another user.
    #[error("is owned by uid {uid}, not the effective uid {euid}")]
    Owner { uid: u32, euid: u32 },
    /// The path is writable by group or other.
    #[error("has mode {mode:04o}: writable by group or other")]
    Writable { mode: u32 },
}

/// A directory held open by descriptor, with the path it was opened at (for messages).
#[derive(Debug)]
pub struct Dir {
    fd: OwnedFd,
    path: PathBuf,
}

impl Dir {
    /// Opens the output directory `path`, creating it (and missing parents, mode 0700) if it
    /// does not exist, and refuses it unless it is safe (see the module docs). A trailing
    /// `/` or `/.` is dropped first, so it cannot get a symlink past the check.
    pub fn open_out(path: &Path) -> Result<Self, AnchorError> {
        let path = &normalise(path);
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(unsafe_path(path, UnsafeReason::Symlink))
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                std::os::unix::fs::DirBuilderExt::mode(&mut builder, DIR_MODE);
                builder
                    .create(path)
                    .map_err(|e| io_err("create", path, e))?;
            }
            Err(e) => return Err(io_err("stat", path, e)),
        }
        let fd = open_dir(CWD, path, path)?;
        Self::checked(fd, path.to_owned())
    }

    /// Opens the directory `name` in this one, first creating it (mode 0700) when `create`
    /// is set and it is missing, and refuses it unless it is safe.
    pub fn open_child(&self, name: &str, create: bool) -> Result<Self, AnchorError> {
        let path = self.join(name);
        if create {
            match rustix::fs::mkdirat(&self.fd, name, mode(DIR_MODE)) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(e) => return Err(io_err("create", &path, e.into())),
            }
        }
        let fd = open_dir(&self.fd, Path::new(name), &path)?;
        Self::checked(fd, path)
    }

    /// Creates the directory `name` in this one (mode 0700), failing if anything is there,
    /// and opens it.
    pub fn create_child(&self, name: &str) -> Result<Self, AnchorError> {
        let path = self.join(name);
        rustix::fs::mkdirat(&self.fd, name, mode(DIR_MODE))
            .map_err(|e| io_err("create", &path, e.into()))?;
        let fd = open_dir(&self.fd, Path::new(name), &path)?;
        Self::checked(fd, path)
    }

    fn checked(fd: OwnedFd, path: PathBuf) -> Result<Self, AnchorError> {
        let st = rustix::fs::fstat(&fd).map_err(|e| io_err("stat", &path, e.into()))?;
        check(&st, FileType::Directory).map_err(|reason| unsafe_path(&path, reason))?;
        Ok(Self { fd, path })
    }

    /// The path this directory was opened at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The path of `name` in this directory, for messages.
    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Opens (creating it, mode 0600, if missing) the regular file `name` with `flags`, never
    /// through a symlink, and refuses it unless it is safe.
    pub fn open_private_file(&self, name: &str, flags: OFlags) -> Result<File, AnchorError> {
        let path = self.join(name);
        let flags = flags | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = match rustix::fs::openat(&self.fd, name, flags, mode(FILE_MODE)) {
            Ok(fd) => fd,
            // A symlink (ELOOP), a directory (EISDIR) and the like are refused as unsafe,
            // not reported as an I/O failure.
            Err(e) => {
                return Err(
                    match rustix::fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
                        Ok(st) => match check(&st, FileType::RegularFile) {
                            Err(reason) => unsafe_path(&path, reason),
                            Ok(()) => io_err("open", &path, e.into()),
                        },
                        Err(_) => io_err("open", &path, e.into()),
                    },
                )
            }
        };
        let st = rustix::fs::fstat(&fd).map_err(|e| io_err("stat", &path, e.into()))?;
        check(&st, FileType::RegularFile).map_err(|reason| unsafe_path(&path, reason))?;
        Ok(File::from(fd))
    }

    /// Creates the file `name` for writing, mode 0600; fails if anything is there (`O_EXCL`,
    /// so a planted symlink is refused, not followed).
    pub fn create_new(&self, name: &str) -> io::Result<File> {
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        Ok(File::from(rustix::fs::openat(
            &self.fd,
            name,
            flags,
            mode(FILE_MODE),
        )?))
    }

    /// Opens the file `name` for reading, never through a symlink.
    pub fn open_read(&self, name: &str) -> io::Result<File> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        Ok(File::from(rustix::fs::openat(
            &self.fd,
            name,
            flags,
            Mode::empty(),
        )?))
    }

    /// Whether anything (a symlink included) is at `name`.
    pub fn exists(&self, name: &str) -> Result<bool, AnchorError> {
        match rustix::fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(e) => Err(io_err("stat", &self.join(name), e.into())),
        }
    }

    /// Hard-links `name` in this directory to `to_name` in `to`, failing with
    /// `AlreadyExists` rather than replacing it. A symlink at `name` is linked, not followed.
    pub fn link(&self, name: &str, to: &Dir, to_name: &str) -> io::Result<()> {
        Ok(rustix::fs::linkat(
            &self.fd,
            name,
            &to.fd,
            to_name,
            AtFlags::empty(),
        )?)
    }

    /// Removes the file `name`.
    pub fn unlink(&self, name: &str) -> io::Result<()> {
        Ok(rustix::fs::unlinkat(&self.fd, name, AtFlags::empty())?)
    }

    /// fsyncs this directory.
    pub fn sync(&self) -> io::Result<()> {
        Ok(rustix::fs::fsync(&self.fd)?)
    }

    /// Removes the directory `name` in this one after removing every file in it (it holds
    /// no subdirectories).
    pub fn remove_child(&self, name: &str) -> io::Result<()> {
        let child = rustix::fs::openat(&self.fd, name, DIR_FLAGS, Mode::empty())?;
        for entry in rustix::fs::Dir::read_from(&child)? {
            let entry = entry?;
            let file = entry.file_name();
            if file.to_bytes() != b"." && file.to_bytes() != b".." {
                rustix::fs::unlinkat(&child, file, AtFlags::empty())?;
            }
        }
        Ok(rustix::fs::unlinkat(&self.fd, name, AtFlags::REMOVEDIR)?)
    }
}

/// `path` rebuilt from its components: a trailing `/` or `/.` (with which
/// `open(O_DIRECTORY | O_NOFOLLOW)` follows a final symlink) and repeated slashes are
/// dropped; `/`, a leading `.` and `..` are kept, and nothing is resolved.
fn normalise(path: &Path) -> PathBuf {
    path.components().collect()
}

/// Opens `name` in `parent` as a directory without following a symlink.
fn open_dir(parent: impl AsFd + Copy, name: &Path, path: &Path) -> Result<OwnedFd, AnchorError> {
    match rustix::fs::openat(parent, name, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Errno::LOOP | Errno::NOTDIR) => {
            let reason = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::Symlink => {
                    UnsafeReason::Symlink
                }
                Ok(st) => UnsafeReason::WrongType {
                    expected: kind_name(FileType::Directory),
                    got: kind_name(FileType::from_raw_mode(st.st_mode)),
                },
                Err(_) => UnsafeReason::WrongType {
                    expected: kind_name(FileType::Directory),
                    got: "non-directory",
                },
            };
            Err(unsafe_path(path, reason))
        }
        Err(e) => Err(io_err("open", path, e.into())),
    }
}

/// Refuses `st` unless it is of type `expected`, owned by the effective uid, and not writable
/// by group or other.
fn check(st: &rustix::fs::Stat, expected: FileType) -> Result<(), UnsafeReason> {
    check_meta(
        FileType::from_raw_mode(st.st_mode),
        mode_bits(st.st_mode),
        st.st_uid,
        rustix::process::geteuid().as_raw(),
        expected,
    )
}

fn check_meta(
    file_type: FileType,
    mode: u32,
    uid: u32,
    euid: u32,
    expected: FileType,
) -> Result<(), UnsafeReason> {
    if file_type == FileType::Symlink {
        return Err(UnsafeReason::Symlink);
    }
    if file_type != expected {
        return Err(UnsafeReason::WrongType {
            expected: kind_name(expected),
            got: kind_name(file_type),
        });
    }
    if uid != euid {
        return Err(UnsafeReason::Owner { uid, euid });
    }
    if mode & GROUP_OTHER_WRITE != 0 {
        return Err(UnsafeReason::Writable { mode });
    }
    Ok(())
}

fn kind_name(t: FileType) -> &'static str {
    match t {
        FileType::RegularFile => "regular file",
        FileType::Directory => "directory",
        FileType::Symlink => "symlink",
        FileType::Fifo => "fifo",
        FileType::Socket => "socket",
        FileType::CharacterDevice => "character device",
        FileType::BlockDevice => "block device",
        _ => "file of unknown type",
    }
}

// `mode_t` is `u16` on macOS and `u32` on Linux.
#[allow(clippy::unnecessary_cast)]
fn mode_bits(raw: rustix::fs::RawMode) -> u32 {
    (raw as u32) & 0o7777
}

#[allow(clippy::unnecessary_cast, clippy::cast_possible_truncation)]
fn mode(bits: u32) -> Mode {
    Mode::from_bits_truncate(bits as rustix::fs::RawMode)
}

fn unsafe_path(path: &Path, reason: UnsafeReason) -> AnchorError {
    AnchorError::UnsafePath {
        path: path.to_owned(),
        reason,
    }
}

fn io_err(what: &str, path: &Path, source: io::Error) -> AnchorError {
    AnchorError::Io {
        context: format!("{what} {}", path.display()),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn reason(err: AnchorError) -> UnsafeReason {
        match err {
            AnchorError::UnsafePath { reason, .. } => reason,
            other => panic!("not unsafe_path: {other:?}"),
        }
    }

    fn chmod(path: &Path, bits: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
    }

    #[test]
    fn creates_a_missing_out_dir_private() {
        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("a/b/out");
        let dir = Dir::open_out(&out).unwrap();
        assert_eq!(dir.path(), out);
        let bits = std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777;
        assert_eq!(bits & 0o077, 0, "{bits:o}");
    }

    #[test]
    fn accepts_an_existing_private_out_dir() {
        let root = tempfile::tempdir().unwrap();
        chmod(root.path(), 0o755);
        assert!(Dir::open_out(root.path()).is_ok());
    }

    #[test]
    fn refuses_an_out_dir_that_is_a_symlink() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = root.path().join("out");
        symlink(&real, &link).unwrap();
        assert_eq!(
            reason(Dir::open_out(&link).unwrap_err()),
            UnsafeReason::Symlink
        );
        // A dangling symlink is refused the same way, and nothing is created behind it.
        let dangling = root.path().join("dangling");
        symlink(root.path().join("nowhere"), &dangling).unwrap();
        assert_eq!(
            reason(Dir::open_out(&dangling).unwrap_err()),
            UnsafeReason::Symlink
        );
        assert!(!root.path().join("nowhere").exists());
    }

    #[test]
    fn refuses_an_out_dir_symlink_named_with_a_trailing_slash_or_dot() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = root.path().join("out");
        symlink(&real, &link).unwrap();
        for suffix in ["/", "//", "/."] {
            let named = PathBuf::from(format!("{}{suffix}", link.display()));
            let err = Dir::open_out(&named).unwrap_err();
            assert_eq!(err.exit_code(), 2, "{suffix}");
            assert_eq!(reason(err), UnsafeReason::Symlink, "{suffix}");
        }
        assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
    }

    #[test]
    fn normalising_drops_only_trailing_slashes_and_dots() {
        for (given, want) in [
            ("a/b/", "a/b"),
            ("a/b//", "a/b"),
            ("a/b/.", "a/b"),
            ("a//b", "a/b"),
            (".", "."),
            ("./a", "./a"),
            ("/", "/"),
            ("a/..", "a/.."),
        ] {
            // `Path` equality ignores trailing slashes, so compare the bytes.
            assert_eq!(normalise(Path::new(given)).as_os_str(), want, "{given}");
        }
    }

    #[test]
    fn refuses_a_directory_where_a_private_file_belongs() {
        let root = tempfile::tempdir().unwrap();
        let out = Dir::open_out(root.path()).unwrap();
        std::fs::create_dir(root.path().join("run.log")).unwrap();
        let err = out
            .open_private_file("run.log", OFlags::RDWR | OFlags::APPEND)
            .unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert_eq!(
            reason(err),
            UnsafeReason::WrongType {
                expected: "regular file",
                got: "directory"
            }
        );
    }

    #[test]
    fn refuses_a_group_or_other_writable_out_dir() {
        for bits in [0o770, 0o707, 0o777] {
            let root = tempfile::tempdir().unwrap();
            chmod(root.path(), bits);
            assert_eq!(
                reason(Dir::open_out(root.path()).unwrap_err()),
                UnsafeReason::Writable { mode: bits },
                "{bits:o}"
            );
        }
    }

    #[test]
    fn refuses_an_out_dir_that_is_a_file() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            reason(Dir::open_out(&file).unwrap_err()),
            UnsafeReason::WrongType {
                got: "regular file",
                ..
            }
        ));
    }

    #[test]
    fn refuses_an_owner_other_than_the_effective_uid() {
        let euid = rustix::process::geteuid().as_raw();
        let other = euid.wrapping_add(1);
        assert_eq!(
            check_meta(FileType::Directory, 0o700, other, euid, FileType::Directory),
            Err(UnsafeReason::Owner { uid: other, euid })
        );
        assert_eq!(
            check_meta(FileType::Directory, 0o700, euid, euid, FileType::Directory),
            Ok(())
        );
        assert_eq!(
            check_meta(FileType::Symlink, 0o777, euid, euid, FileType::RegularFile),
            Err(UnsafeReason::Symlink)
        );
    }

    #[test]
    fn creates_and_checks_a_child_directory() {
        let root = tempfile::tempdir().unwrap();
        let out = Dir::open_out(root.path()).unwrap();
        let q = out.open_child("quarantine", true).unwrap();
        let bits = std::fs::metadata(q.path()).unwrap().permissions().mode() & 0o7777;
        assert_eq!(bits & 0o077, 0, "{bits:o}");
        // An existing one is reused.
        assert!(out.open_child("quarantine", true).is_ok());
        chmod(q.path(), 0o777);
        assert!(matches!(
            reason(out.open_child("quarantine", true).unwrap_err()),
            UnsafeReason::Writable { .. }
        ));
    }

    #[test]
    fn refuses_a_child_directory_that_is_a_symlink() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let out_path = root.path().join("out");
        let out = Dir::open_out(&out_path).unwrap();
        symlink(&elsewhere, out_path.join("quarantine")).unwrap();
        assert_eq!(
            reason(out.open_child("quarantine", true).unwrap_err()),
            UnsafeReason::Symlink
        );
    }

    #[test]
    fn refuses_a_private_file_that_is_a_symlink_and_leaves_its_target_alone() {
        let root = tempfile::tempdir().unwrap();
        let victim = root.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let out_path = root.path().join("out");
        let out = Dir::open_out(&out_path).unwrap();
        symlink(&victim, out_path.join("run.log")).unwrap();
        let err = out
            .open_private_file("run.log", OFlags::RDWR | OFlags::APPEND)
            .unwrap_err();
        assert_eq!(reason(err), UnsafeReason::Symlink);
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    #[test]
    fn file_operations_stay_in_the_held_directory() {
        let root = tempfile::tempdir().unwrap();
        let out_path = root.path().join("out");
        let out = Dir::open_out(&out_path).unwrap();
        let run = out.create_child("run").unwrap();
        std::io::Write::write_all(&mut run.create_new("f").unwrap(), b"data").unwrap();
        assert!(run.create_new("f").is_err(), "create_new replaced a file");
        assert!(run.exists("f").unwrap());
        assert!(!run.exists("g").unwrap());
        run.link("f", &out, "g").unwrap();
        assert_eq!(
            run.link("f", &out, "g").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let mut text = String::new();
        std::io::Read::read_to_string(&mut out.open_read("g").unwrap(), &mut text).unwrap();
        assert_eq!(text, "data");
        out.sync().unwrap();
        out.unlink("g").unwrap();
        assert!(!out_path.join("g").exists());
        assert!(
            out.create_child("run").is_err(),
            "create_child reused a dir"
        );
        out.remove_child("run").unwrap();
        assert!(!out_path.join("run").exists());
    }
}
