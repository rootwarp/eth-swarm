//! Service-owned Unix sockets: `/run/ethswarm/<svc>/<svc>.sock`.
//!
//! ## Layout and modes
//! The runtime root (`/run/ethswarm`, [`DEFAULT_ROOT`]) must be a real directory, named by a path
//! without symlinks, owned by root or by the service user, and writable by nobody else. Under it
//! each service owns one directory, mode `0750`, owner the service user, group the group of its
//! allowed callers; the socket inside is `0660` with the same owner and group. A caller outside
//! the group cannot reach the socket at all; a caller inside it is then checked per method
//! ([`crate::acl`]).
//!
//! ## [`bind`]
//! Nothing that is found wrong is repaired, replaced or removed (the one exception is a stale
//! socket of the service user, step 5); startup fails instead, naming what was found.
//!
//! 1. The advertised socket path `<root>/<svc>/<svc>.sock` must fit a Unix socket address
//!    (`sun_path`: 104 bytes on macOS, 108 on Linux). Clients connect to that path, so a longer
//!    one fails startup before anything on disk is touched.
//! 2. The runtime root must be an absolute path without `..`. It is walked from `/` one
//!    component at a time through directory file descriptors (`openat`, `O_NOFOLLOW |
//!    O_DIRECTORY`, and `O_PATH` on Linux so that search permission suffices): a symlink
//!    anywhere in it is refused, not resolved, so configure `/run/...`, not `/var/run/...`
//!    (a symlink to `/run` on most distributions). Every directory above the root must be
//!    owned by root or us and not writable by group or others (sticky directories such as
//!    `/tmp` excepted), and the root itself writable only by its owner.
//!
//! From there on the filesystem steps are relative to directory file descriptors
//! (`mkdirat`/`openat`/`fstatat`/`fchownat`/`unlinkat`, `O_NOFOLLOW`), so they do not follow a
//! symlink in place of the service directory. The two steps that take a path, the
//! `connect()` probe and `bind(2)`, go through `/proc/thread-self/fd/<dirfd>/` on Linux, and
//! startup fails if `/proc` cannot provide the directory held open; elsewhere they re-resolve
//! the directory path, which is checked first to still name the directory held open:
//!
//! 3. The service directory is created `0750` with the service owner and group set explicitly,
//!    or, if it exists, must already be exactly that: a looser mode, another owner or group, a
//!    symlink or a non-directory fails startup.
//! 4. `<svc>.lock` in that directory is `flock`ed for the life of the process, so a second
//!    instance fails with `AddrInUse` instead of touching the first one's socket. A lock this
//!    start creates is set up under a temporary name, `.<svc>.lock.<random>`: given to the
//!    service user and group, mode `0600`, checked and `flock`ed, and only then linked to
//!    `<svc>.lock` (`linkat`, which never replaces a lock another start published first). A
//!    failure on the way unlinks the temporary name, so `<svc>.lock` never names a lock that
//!    is only half set up; a temporary name a killed start left behind is never looked at, so
//!    it blocks nothing. An existing lock must already be exactly that and is refused
//!    otherwise: a chown or chmod would not revoke a descriptor a caller opened while it was
//!    looser, and with it the caller could hold the flock against every start.
//! 5. A leftover socket path is looked at with `lstat` (`AT_SYMLINK_NOFOLLOW`). Only a socket
//!    owned by the service user that refuses a `connect()` probe is stale and unlinked. A live
//!    socket fails with `AddrInUse`; a symlink, file, directory, or a socket of another user is
//!    left in place and fails startup.
//! 6. The socket is bound in a fresh private directory inside the service directory
//!    (`.<svc>.bind.<random>`, mode `0700`, this process's user), where nobody else can
//!    connect to it. Its owner, group and mode (`0660`) are set explicitly and checked there,
//!    whatever the umask gave it, and only then is it linked to `<svc>.sock` (`linkat`, which
//!    never replaces a name) and the private directory removed. So the advertised path never
//!    names a socket that is not finished. A private directory a killed start left behind is
//!    never looked at. The service directory is writable only by the service user, so nobody
//!    else can swap the socket afterwards.
//!
//! The returned [`SocketGuard`] unlinks the socket when dropped, but only while the path still
//! names the socket this process bound (same device and inode).
//!
//! ## [`connect`]
//! The client connects, reads the server's credentials from the kernel and refuses a server
//! that does not run as the expected UID before tonic writes a byte to the stream
//! ([`PeerCheckedConnector`]), so a counterfeit server on the path never sees a request.

use std::future::Future;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::rt::TokioIo;
use rustix::fs::{AtFlags, FileType, FlockOperation, Gid, Mode, OFlags, Uid, CWD};
use rustix::io::Errno;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::peercred::{self, PeerCredError};

/// Where service socket directories live.
pub const DEFAULT_ROOT: &str = "/run/ethswarm";
/// Mode of a service's socket directory.
pub const DIR_MODE: u32 = 0o750;
/// Mode of a service socket.
pub const SOCKET_MODE: u32 = 0o660;
const LOCK_MODE: u32 = 0o600;

/// Where one service's socket lives: `<root>/<service>/<service>.sock`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketDir {
    root: PathBuf,
    service: String,
}

impl SocketDir {
    /// `service`'s socket under [`DEFAULT_ROOT`].
    pub fn new(service: &str) -> Result<Self, BindError> {
        Self::under(DEFAULT_ROOT, service)
    }

    /// `service`'s socket under another runtime root (tests, non-systemd setups).
    pub fn under(root: impl Into<PathBuf>, service: &str) -> Result<Self, BindError> {
        let ok = !service.is_empty()
            && service.len() <= 64
            && service
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(BindError::Service(service.to_owned()));
        }
        Ok(Self {
            root: root.into(),
            service: service.to_owned(),
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// `<root>/<service>`.
    #[must_use]
    pub fn dir(&self) -> PathBuf {
        self.root.join(&self.service)
    }

    /// `<service>.sock`.
    #[must_use]
    pub fn socket_name(&self) -> String {
        format!("{}.sock", self.service)
    }

    /// `<root>/<service>/<service>.sock`.
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.dir().join(self.socket_name())
    }

    /// `<root>/<service>/<service>.lock`, held while the service runs.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.dir().join(self.lock_name())
    }

    fn lock_name(&self) -> String {
        format!("{}.lock", self.service)
    }
}

/// Who owns a service's directory and socket: the service user, and the group of the callers
/// allowed to connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ownership {
    pub uid: u32,
    pub gid: u32,
}

impl Ownership {
    /// This process's effective UID and GID.
    #[must_use]
    pub fn current() -> Self {
        Self {
            uid: peercred::effective_uid(),
            gid: peercred::effective_gid(),
        }
    }
}

/// Why [`bind`] refused to start.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("{0:?} is not a service name (lowercase letters, digits and -, at most 64)")]
    Service(String),
    #[error("uid or gid {0} is not a valid id")]
    Id(u32),
    /// The socket path cannot be a Unix socket address (too long for `sun_path`, or a NUL
    /// byte), so no client could connect to it; nothing was changed.
    #[error("{}: socket path is too long or invalid for a Unix socket address ({len} bytes): {source}", path.display())]
    SocketPath {
        path: PathBuf,
        len: usize,
        #[source]
        source: io::Error,
    },
    #[error("{op} {}: {source}", path.display())]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The root or service directory is not what it must be; nothing was changed.
    #[error("{}: {reason}", path.display())]
    Insecure { path: PathBuf, reason: String },
    /// Something other than a socket sits at the socket path; it was left in place.
    #[error("{}: a {kind} is in the way; only a stale socket of the service user is removed", path.display())]
    NotASocket { path: PathBuf, kind: &'static str },
    /// A socket of another user sits at the socket path; it was left in place.
    #[error("{}: socket owned by uid {owner}, not the service user (uid {expected}); left in place", path.display())]
    ForeignSocket {
        path: PathBuf,
        owner: u32,
        expected: u32,
    },
    /// Another instance holds the lock, or a server answers on the socket.
    #[error("{}: {reason}", path.display())]
    InUse { path: PathBuf, reason: &'static str },
}

impl BindError {
    /// The `io::ErrorKind` of this failure (`AddrInUse` for a live socket or a held lock).
    #[must_use]
    pub fn kind(&self) -> io::ErrorKind {
        match self {
            Self::Service(_) | Self::Id(_) | Self::SocketPath { .. } => io::ErrorKind::InvalidInput,
            Self::Io { source, .. } => source.kind(),
            Self::Insecure { .. } | Self::NotASocket { .. } | Self::ForeignSocket { .. } => {
                io::ErrorKind::PermissionDenied
            }
            Self::InUse { .. } => io::ErrorKind::AddrInUse,
        }
    }
}

impl From<BindError> for io::Error {
    fn from(e: BindError) -> Self {
        io::Error::new(e.kind(), e)
    }
}

fn io_err<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(Errno) -> BindError + 'a {
    move |e| BindError::Io {
        op,
        path: path.to_owned(),
        source: e.into(),
    }
}

/// The fields of a `stat` this module compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Meta {
    file_type: FileType,
    mode: Mode,
    uid: u32,
    gid: u32,
    dev: u64,
    ino: u64,
}

impl Meta {
    // `st_dev` is `i32` on macOS and `u64` on Linux.
    #[allow(clippy::unnecessary_cast)]
    fn of(st: &rustix::fs::Stat) -> Self {
        Self {
            file_type: FileType::from_raw_mode(st.st_mode),
            mode: Mode::from_raw_mode(st.st_mode),
            uid: st.st_uid,
            gid: st.st_gid,
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
        }
    }

    fn same_file(&self, other: &Self) -> bool {
        (self.dev, self.ino) == (other.dev, other.ino)
    }
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
fn mode_bits(m: Mode) -> u32 {
    m.bits() as u32
}

#[allow(clippy::unnecessary_cast, clippy::cast_possible_truncation)]
fn mode(bits: u32) -> Mode {
    Mode::from_bits_truncate(bits as rustix::fs::RawMode)
}

fn fstat(fd: impl AsFd, path: &Path) -> Result<Meta, BindError> {
    rustix::fs::fstat(fd)
        .map(|st| Meta::of(&st))
        .map_err(io_err("stat", path))
}

/// The owner change of a new inode, made only where its owner `m` is not `owner`: a new inode of
/// a unit's process carries its `User=` and `Group=` already, and the units' seccomp filter
/// (`SystemCallFilter=~@privileged`, which holds `@chown`) kills a process that calls `fchown`
/// or `fchownat`. The caller checks the result afterwards either way. Returns `None` when nothing
/// needs a change; else the uid to set (`None`: keep it) and the gid.
fn owner_change(m: &Meta, owner: Ownership) -> Option<(Option<Uid>, Gid)> {
    if m.uid == owner.uid && m.gid == owner.gid {
        return None;
    }
    #[cfg(test)]
    CHOWNS.with(|c| c.set(c.get() + 1));
    let uid = (m.uid != owner.uid).then(|| Uid::from_raw(owner.uid));
    Some((uid, Gid::from_raw(owner.gid)))
}

#[cfg(test)]
thread_local! {
    /// The owner changes this thread asked for.
    static CHOWNS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Called with the path `bind(2)` used, right after it returned.
    static AFTER_BIND: std::cell::RefCell<Option<AfterBind>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
type AfterBind = Box<dyn FnMut(&Path)>;

/// `lstat` of `name` in `dir`; `None` if nothing is there.
fn lstat_at(dir: impl AsFd, name: &str, path: &Path) -> Result<Option<Meta>, BindError> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => Ok(Some(Meta::of(&st))),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(io_err("lstat", path)(e)),
    }
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// How the directories from `/` down to the runtime root are opened. They are only looked
/// through (`fstat`, `openat`, `mkdirat`), so on Linux `O_PATH`, which needs only search
/// permission, as a path lookup does: an unprivileged service under a root-owned `0711`
/// ancestor can walk it. macOS has no `O_PATH` (and rustix no `O_SEARCH` there), so it opens
/// them `O_RDONLY` and needs read permission on every ancestor.
#[cfg(target_os = "linux")]
const ANCESTOR_FLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
#[cfg(not(target_os = "linux"))]
const ANCESTOR_FLAGS: OFlags = DIR_FLAGS;

/// Opens `name` in `parent` as a directory without following a symlink.
fn open_dir(parent: impl AsFd + Copy, name: &Path, path: &Path) -> Result<OwnedFd, BindError> {
    open_dir_with(parent, name, path, DIR_FLAGS)
}

/// [`open_dir`] for a directory on the way to the runtime root, or the root itself.
fn open_ancestor(parent: impl AsFd + Copy, name: &Path, path: &Path) -> Result<OwnedFd, BindError> {
    open_dir_with(parent, name, path, ANCESTOR_FLAGS)
}

fn open_dir_with(
    parent: impl AsFd + Copy,
    name: &Path,
    path: &Path,
    flags: OFlags,
) -> Result<OwnedFd, BindError> {
    match rustix::fs::openat(parent, name, flags, Mode::empty()) {
        Ok(fd) => Ok(fd),
        Err(Errno::LOOP | Errno::NOTDIR) => {
            let kind = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_or("non-directory", |st| {
                    kind_name(FileType::from_raw_mode(st.st_mode))
                });
            Err(BindError::Insecure {
                path: path.to_owned(),
                reason: format!("is a {kind}, not a directory"),
            })
        }
        Err(e) => Err(io_err("open", path)(e)),
    }
}

/// Where Linux exposes this thread's open descriptors as paths. `thread-self`: a thread holding
/// other credentials (tests) may still read its own fds.
#[cfg(target_os = "linux")]
const PROC_FDS: &str = "/proc/thread-self/fd";

/// The path the kernel resolves to reach `name` in the directory `dir_fd`. On Linux that is
/// `/proc/thread-self/fd/<dirfd>/<name>` (the open directory itself, whatever its path names
/// now), and startup fails if `/proc` cannot provide it; elsewhere it is the path, which
/// [`same_dir`] checked.
fn through_dir(dir_fd: &OwnedFd, name: &str, path: &Path) -> Result<PathBuf, BindError> {
    #[cfg(target_os = "linux")]
    {
        let _ = path;
        through_proc(Path::new(PROC_FDS), dir_fd, name)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dir_fd, name);
        Ok(path.to_owned())
    }
}

/// `<fds>/<dirfd>/<name>`, once `<fds>/<dirfd>` is shown to be the directory held open.
#[cfg(target_os = "linux")]
fn through_proc(fds: &Path, dir_fd: &OwnedFd, name: &str) -> Result<PathBuf, BindError> {
    use std::os::fd::AsRawFd;
    let held = fds.join(dir_fd.as_raw_fd().to_string());
    let want = fstat(dir_fd, &held)?;
    let unusable = |why: String| BindError::Insecure {
        path: held.clone(),
        reason: format!(
            "cannot reach the held service directory through {}: {why} (is /proc mounted?)",
            fds.display()
        ),
    };
    match std::fs::metadata(&held) {
        Ok(m) if m.is_dir() && (m.dev(), m.ino()) == (want.dev, want.ino) => Ok(held.join(name)),
        Ok(_) => Err(unusable("names another file".into())),
        Err(e) => Err(unusable(e.to_string())),
    }
}

/// Opens the runtime root by walking its configured path from `/` ([`walk_closed`]). The root
/// itself must be owned by root or us and writable only by its owner. That includes
/// `/var/run`, a symlink to `/run` on most distributions: configure `/run/...`.
fn open_root(root: &Path) -> Result<OwnedFd, BindError> {
    let me = peercred::effective_uid();
    let fd = walk_closed(root, me)?;
    let m = fstat(&fd, root)?;
    let writable_by_others = m.mode.intersects(Mode::WGRP | Mode::WOTH);
    if (m.uid != 0 && m.uid != me) || writable_by_others {
        return Err(BindError::Insecure {
            path: root.to_owned(),
            reason: format!(
                "runtime root must be owned by root or uid {me} and writable only by its owner \
                 (owner uid {}, mode {:o})",
                m.uid,
                mode_bits(m.mode)
            ),
        });
    }
    Ok(fd)
}

/// Opens `dir` for creating a name in it that is then reached by its path, as the runtime root
/// is walked ([`walk_closed`]): `dir` too must be owned by root or `uid` and not writable by
/// group or others unless sticky. Nobody but root and `uid` can then rename, replace or
/// retarget any directory on the path, so a name created in `dir` stays the one the path
/// reaches.
///
/// # Errors
///
/// [`BindError::Insecure`] for a relative path, `..`, a symlink or a non-directory anywhere in
/// it, or a directory on it that another user could change; [`BindError::Io`] if a directory
/// on it cannot be opened.
pub fn open_closed_dir(dir: &Path, uid: u32) -> Result<OwnedFd, BindError> {
    let fd = walk_closed(dir, uid)?;
    check_closed(&fd, dir, uid, dir)?;
    Ok(fd)
}

/// Fails unless the directory `fd` (named `walked`) is one only root and `me` can change:
/// owned by one of them, and not writable by group or others unless sticky. Otherwise someone
/// else could rename what it holds away and put their own in its place. `path` is what the
/// error names as checked.
fn check_closed(fd: &OwnedFd, walked: &Path, me: u32, path: &Path) -> Result<(), BindError> {
    let m = fstat(fd, walked)?;
    let writable = m.mode.intersects(Mode::WGRP | Mode::WOTH) && !m.mode.contains(Mode::SVTX);
    if (m.uid != 0 && m.uid != me) || writable {
        return Err(BindError::Insecure {
            path: path.to_owned(),
            reason: format!(
                "parent {} must be owned by root or uid {me} and not writable by others unless \
                 sticky (owner uid {}, mode {:o})",
                walked.display(),
                m.uid,
                mode_bits(m.mode)
            ),
        });
    }
    Ok(())
}

/// Opens `root` by walking its path from `/`, one component at a time, through directory
/// descriptors (`openat`, `O_NOFOLLOW | O_DIRECTORY`). Every directory above `root` must be
/// owned by root or `me` and not writable by group or others unless sticky ([`check_closed`]).
/// A symlink anywhere in the path is refused, not resolved; so are a relative path and `..`.
fn walk_closed(root: &Path, me: u32) -> Result<OwnedFd, BindError> {
    use std::path::Component;
    let insecure = |reason: String| BindError::Insecure {
        path: root.to_owned(),
        reason,
    };
    if !root.is_absolute() {
        return Err(insecure("must be an absolute path".into()));
    }
    let mut walked = PathBuf::from("/");
    let mut fd = open_ancestor(CWD, &walked, &walked)?;
    for component in root.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(insecure("must not contain `..`".into()));
            }
        };
        // The directory just walked holds `name`: it must be one nobody else can change.
        check_closed(&fd, &walked, me, root)?;
        walked.push(name);
        fd = open_ancestor(&fd, Path::new(name), &walked)?;
    }
    Ok(fd)
}

/// The service directory, created `0750` `owner` or verified to be exactly that.
fn open_service_dir(
    root: &OwnedFd,
    dir: &SocketDir,
    owner: Ownership,
) -> Result<OwnedFd, BindError> {
    let path = dir.dir();
    let created = match rustix::fs::mkdirat(root, dir.service(), mode(DIR_MODE)) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(e) => return Err(io_err("mkdir", &path)(e)),
    };
    let fd = open_dir(root, Path::new(dir.service()), &path)?;
    if created {
        // Set explicitly: neither the umask nor a setgid parent decides the owner or mode. The
        // owner changes only where it differs (`owner_change`), and is checked below.
        if let Some((uid, gid)) = owner_change(&fstat(&fd, &path)?, owner) {
            rustix::fs::fchown(&fd, uid, Some(gid)).map_err(io_err("chown", &path))?;
        }
        rustix::fs::fchmod(&fd, mode(DIR_MODE)).map_err(io_err("chmod", &path))?;
    }
    let m = fstat(&fd, &path)?;
    let want = mode(DIR_MODE);
    if m.uid != owner.uid || m.gid != owner.gid || m.mode != want {
        return Err(BindError::Insecure {
            path,
            reason: format!(
                "service directory must be uid {} gid {} mode {:o}, is uid {} gid {} mode {:o}",
                owner.uid,
                owner.gid,
                DIR_MODE,
                m.uid,
                m.gid,
                mode_bits(m.mode)
            ),
        });
    }
    Ok(fd)
}

/// `uid A gid B mode C` of a file found.
fn describe(m: &Meta) -> String {
    format!("uid {} gid {} mode {:o}", m.uid, m.gid, mode_bits(m.mode))
}

/// Takes the instance lock for the life of the returned descriptor. An existing lock must
/// already be `owner`'s, mode `0600`, and is never repaired. Without one, a new lock is set up
/// and taken under a temporary name, then published under `<svc>.lock` ([`create_lock`]), so
/// the final name never shows a lock that is only half set up.
fn lock(dir_fd: &OwnedFd, dir: &SocketDir, owner: Ownership) -> Result<OwnedFd, BindError> {
    lock_with(dir_fd, dir, owner, |_| Ok(()))
}

/// [`lock`], running `before_publish` on a new lock right before it is published (tests inject
/// a failure there).
fn lock_with(
    dir_fd: &OwnedFd,
    dir: &SocketDir,
    owner: Ownership,
    before_publish: impl FnOnce(&OwnedFd) -> Result<(), BindError>,
) -> Result<OwnedFd, BindError> {
    if let Some(fd) = open_existing_lock(dir_fd, dir)? {
        return take_existing_lock(&fd, dir, owner).map(|()| fd);
    }
    if let Some(fd) = create_lock(dir_fd, dir, owner, before_publish)? {
        return Ok(fd);
    }
    // Another start published its lock first: it gets the same checks as any existing lock.
    match open_existing_lock(dir_fd, dir)? {
        Some(fd) => take_existing_lock(&fd, dir, owner).map(|()| fd),
        None => Err(io_err("open", &dir.lock_path())(Errno::NOENT)),
    }
}

/// The lock under its final name, opened without following a symlink; `None` if there is none.
fn open_existing_lock(dir_fd: &OwnedFd, dir: &SocketDir) -> Result<Option<OwnedFd>, BindError> {
    let (name, path) = (dir.lock_name(), dir.lock_path());
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rustix::fs::openat(dir_fd, name.as_str(), flags, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(Errno::LOOP) => Err(BindError::NotASocket {
            path,
            kind: "symlink",
        }),
        Err(Errno::ACCESS | Errno::PERM) => {
            let found = lstat_at(dir_fd, &name, &path)?.map(|m| describe(&m));
            Err(BindError::Insecure {
                reason: format!(
                    "uid {} cannot open the lock ({}); refusing it",
                    peercred::effective_uid(),
                    found.as_deref().unwrap_or("gone")
                ),
                path,
            })
        }
        Err(e) => Err(io_err("open", &path)(e)),
    }
}

fn is_exact_lock(m: &Meta, owner: Ownership) -> bool {
    m.file_type == FileType::RegularFile
        && m.uid == owner.uid
        && m.gid == owner.gid
        && m.mode == mode(LOCK_MODE)
}

/// Checks and flocks a lock found under the final name.
fn take_existing_lock(fd: &OwnedFd, dir: &SocketDir, owner: Ownership) -> Result<(), BindError> {
    let path = dir.lock_path();
    let m = fstat(fd, &path)?;
    if m.file_type != FileType::RegularFile {
        return Err(BindError::Insecure {
            path,
            reason: format!("lock is a {}, not a regular file", kind_name(m.file_type)),
        });
    }
    if !is_exact_lock(&m, owner) {
        // Never repaired in place: a caller that opened the lock while it was looser keeps its
        // descriptor, and with it the flock, across a chown or chmod.
        return Err(BindError::Insecure {
            path,
            reason: format!(
                "existing lock must be uid {} gid {} mode {:o}, is {}; refusing it (remove it \
                 once no other process has it open)",
                owner.uid,
                owner.gid,
                LOCK_MODE,
                describe(&m)
            ),
        });
    }
    flock_exclusive(fd, &path)
}

fn flock_exclusive(fd: &OwnedFd, path: &Path) -> Result<(), BindError> {
    match rustix::fs::flock(fd, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(()),
        Err(e) if e == Errno::WOULDBLOCK => Err(BindError::InUse {
            path: path.to_owned(),
            reason: "another instance of the service holds the lock",
        }),
        Err(e) => Err(io_err("lock", path)(e)),
    }
}

/// A new lock's temporary name, `.<svc>.lock.<random>`, unlinked when dropped: on every error
/// and after the lock is published under its final name. A start killed before that leaves the
/// name behind; nothing looks at such names, so it never blocks a later start.
struct TempLockName<'a> {
    dir_fd: &'a OwnedFd,
    name: String,
    path: PathBuf,
}

impl Drop for TempLockName<'_> {
    fn drop(&mut self) {
        if let Err(e) = rustix::fs::unlinkat(self.dir_fd, self.name.as_str(), AtFlags::empty()) {
            tracing::warn!(lock = %self.path.display(), error = %e, "cannot remove a temporary lock name");
        }
    }
}

/// 64 bits that differ on every call (std's per-instance randomized hasher keys).
fn random_suffix() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u32(std::process::id());
    h.finish()
}

/// Creates a lock under a temporary name, gives it to `owner` with mode `0600`, checks that,
/// flocks it, and only then links it to `<svc>.lock` (`linkat`, which never replaces an existing
/// name). `None`: another start published a lock first; it is left to the existing-lock checks.
fn create_lock(
    dir_fd: &OwnedFd,
    dir: &SocketDir,
    owner: Ownership,
    before_publish: impl FnOnce(&OwnedFd) -> Result<(), BindError>,
) -> Result<Option<OwnedFd>, BindError> {
    const ATTEMPTS: usize = 8;
    let path = dir.lock_path();
    let flags = OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut created = None;
    for _ in 0..ATTEMPTS {
        let name = format!(".{}.{:016x}", dir.lock_name(), random_suffix());
        let tmp_path = dir.dir().join(&name);
        match rustix::fs::openat(dir_fd, name.as_str(), flags, mode(LOCK_MODE)) {
            Ok(fd) => {
                let tmp = TempLockName {
                    dir_fd,
                    name,
                    path: tmp_path,
                };
                created = Some((fd, tmp));
                break;
            }
            Err(Errno::EXIST) => {}
            Err(e) => return Err(io_err("create", &tmp_path)(e)),
        }
    }
    let Some((fd, tmp)) = created else {
        return Err(io_err("create", &path)(Errno::EXIST));
    };
    let m = fstat(&fd, &tmp.path)?;
    // Set explicitly on the inode just created: neither the umask nor a setgid directory decides
    // its owner or mode. The owner changes only where it differs (`owner_change`).
    owner_change(&m, owner)
        .map_or(Ok(()), |(uid, gid)| rustix::fs::fchown(&fd, uid, Some(gid)))
        .and_then(|()| rustix::fs::fchmod(&fd, mode(LOCK_MODE)))
        .map_err(|e| BindError::Insecure {
            path: path.clone(),
            reason: format!(
                "new lock is {} and cannot be made uid {} gid {} mode {:o}: {e}",
                describe(&m),
                owner.uid,
                owner.gid,
                LOCK_MODE
            ),
        })?;
    let m = fstat(&fd, &tmp.path)?;
    if !is_exact_lock(&m, owner) {
        return Err(BindError::Insecure {
            path,
            reason: format!(
                "new lock must be uid {} gid {} mode {:o}, is {}",
                owner.uid,
                owner.gid,
                LOCK_MODE,
                describe(&m)
            ),
        });
    }
    // Held before it is published, so a start that finds it under the final name is refused.
    flock_exclusive(&fd, &path)?;
    before_publish(&fd)?;
    match rustix::fs::linkat(
        dir_fd,
        tmp.name.as_str(),
        dir_fd,
        dir.lock_name().as_str(),
        AtFlags::empty(),
    ) {
        Ok(()) => Ok(Some(fd)),
        Err(Errno::EXIST) => Ok(None),
        Err(e) => Err(io_err("publish", &path)(e)),
    }
}

/// Whether a server accepts connections on `path`. A non-blocking connect, so a live server
/// with a full backlog counts as live instead of hanging startup.
fn answers(path: &Path) -> io::Result<bool> {
    use rustix::net::{connect, socket, AddressFamily, SocketAddrUnix, SocketType};
    let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
    rustix::io::ioctl_fionbio(&fd, true)?;
    let addr = SocketAddrUnix::new(path)?;
    match connect(&fd, &addr) {
        Ok(()) => Ok(true),
        Err(e) if e == Errno::INPROGRESS || e == Errno::WOULDBLOCK => Ok(true),
        Err(Errno::CONNREFUSED | Errno::NOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Removes a stale socket of `owner` at the socket path; refuses anything else.
fn clear_stale(dir_fd: &OwnedFd, dir: &SocketDir, owner: Ownership) -> Result<(), BindError> {
    let (name, path) = (dir.socket_name(), dir.socket_path());
    let Some(found) = lstat_at(dir_fd, &name, &path)? else {
        return Ok(());
    };
    if found.file_type != FileType::Socket {
        return Err(BindError::NotASocket {
            path,
            kind: kind_name(found.file_type),
        });
    }
    if found.uid != owner.uid {
        return Err(BindError::ForeignSocket {
            path,
            owner: found.uid,
            expected: owner.uid,
        });
    }
    let live = answers(&through_dir(dir_fd, &name, &path)?).map_err(|source| BindError::Io {
        op: "probe",
        path: path.clone(),
        source,
    })?;
    if live {
        return Err(BindError::InUse {
            path,
            reason: "a server answers on the socket",
        });
    }
    // The directory is ours, so the stale socket cannot have been swapped; check anyway.
    match lstat_at(dir_fd, &name, &path)? {
        Some(now) if now.same_file(&found) => {
            rustix::fs::unlinkat(dir_fd, name.as_str(), AtFlags::empty())
                .map_err(io_err("unlink", &path))?;
            tracing::info!(socket = %path.display(), "removed a stale socket");
            Ok(())
        }
        None => Ok(()),
        Some(_) => Err(BindError::InUse {
            path,
            reason: "the socket changed while it was checked",
        }),
    }
}

/// The socket this process bound. Dropping it unlinks the path while it still names that
/// socket, then releases the instance lock.
#[derive(Debug)]
pub struct SocketGuard {
    dir_fd: OwnedFd,
    name: String,
    path: PathBuf,
    bound: Meta,
    unlinked: bool,
    _lock: OwnedFd,
}

impl SocketGuard {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Removes the socket path now, while it still names our socket, and keeps the instance
    /// lock until the guard drops: new connections fail while open ones drain, and no second
    /// instance starts before this one has exited.
    pub fn unlink(&mut self) {
        if !std::mem::replace(&mut self.unlinked, true) {
            self.remove();
        }
    }

    fn remove(&self) {
        match lstat_at(&self.dir_fd, &self.name, &self.path) {
            Ok(Some(now)) if now.file_type == FileType::Socket && now.same_file(&self.bound) => {
                if let Err(e) =
                    rustix::fs::unlinkat(&self.dir_fd, self.name.as_str(), AtFlags::empty())
                {
                    tracing::warn!(socket = %self.path.display(), error = %e, "cannot remove our socket");
                }
            }
            Ok(_) => tracing::warn!(
                socket = %self.path.display(),
                "socket path no longer names our socket; left in place"
            ),
            Err(e) => {
                tracing::warn!(socket = %self.path.display(), error = %e, "cannot check our socket")
            }
        }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        self.unlink();
    }
}

/// A bound service socket and the guard that removes it.
#[derive(Debug)]
pub struct BoundSocket {
    listener: StdUnixListener,
    guard: SocketGuard,
}

impl BoundSocket {
    #[must_use]
    pub fn path(&self) -> &Path {
        self.guard.path()
    }

    /// The listener and the guard, separately (e.g. to remove the path as soon as shutdown
    /// begins while connections drain).
    #[must_use]
    pub fn into_parts(self) -> (StdUnixListener, SocketGuard) {
        (self.listener, self.guard)
    }

    /// The listener as a tokio listener (call inside a runtime), and the guard.
    pub fn into_tokio(self) -> io::Result<(tokio::net::UnixListener, SocketGuard)> {
        self.listener.set_nonblocking(true)?;
        Ok((
            tokio::net::UnixListener::from_std(self.listener)?,
            self.guard,
        ))
    }
}

/// Creates or verifies `dir`'s directory, takes the instance lock, removes a stale socket of
/// the service user, binds the socket in a private directory, sets its owner, group and mode
/// (`0660`) there and links it into place. See the module docs for what makes it fail.
pub fn bind(dir: &SocketDir, owner: Ownership) -> Result<BoundSocket, BindError> {
    for id in [owner.uid, owner.gid] {
        if id == u32::MAX {
            return Err(BindError::Id(id));
        }
    }
    check_socket_path(&dir.socket_path())?;
    let root_fd = open_root(dir.root())?;
    let dir_fd = open_service_dir(&root_fd, dir, owner)?;
    let lock_fd = lock(&dir_fd, dir, owner)?;
    same_dir(&dir.dir(), &dir_fd)?;
    clear_stale(&dir_fd, dir, owner)?;

    let (name, path) = (dir.socket_name(), dir.socket_path());
    // Bound where only we can reach it, finished there, then published.
    let private = PrivateDir::create(&dir_fd, dir)?;
    let in_private = private.path.join(BOUND_NAME);
    let bind_path = through_dir(&private.fd, BOUND_NAME, &in_private)?;
    let listener = StdUnixListener::bind(&bind_path).map_err(|source| BindError::Io {
        op: "bind",
        path: in_private.clone(),
        source,
    })?;
    #[cfg(test)]
    AFTER_BIND.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(&bind_path);
        }
    });
    let bound =
        lstat_at(&private.fd, BOUND_NAME, &in_private)?.ok_or_else(|| BindError::Insecure {
            path: in_private.clone(),
            reason: "socket vanished right after bind".into(),
        })?;
    set_socket_owner_and_mode(&private.fd, BOUND_NAME, &in_private, &bound, owner)?;
    // `linkat` never replaces a name: the stale socket is gone and the lock is ours, so the
    // advertised name is free unless something is wrong.
    rustix::fs::linkat(
        &private.fd,
        BOUND_NAME,
        &dir_fd,
        name.as_str(),
        AtFlags::empty(),
    )
    .map_err(|e| match e {
        Errno::EXIST => BindError::InUse {
            path: path.clone(),
            reason: "the socket path was taken while the socket was set up",
        },
        e => io_err("link", &path)(e),
    })?;
    // From here on the guard removes the published socket on every error path.
    let guard = SocketGuard {
        dir_fd,
        name,
        path,
        bound,
        unlinked: false,
        _lock: lock_fd,
    };
    check_socket(&guard.dir_fd, &guard.name, &guard.path, &guard.bound, owner)?;
    drop(private);
    Ok(BoundSocket { listener, guard })
}

/// The socket's name inside its [`PrivateDir`]. Short: off Linux, `bind(2)` takes the whole
/// path, which has to fit a `sun_path`.
const BOUND_NAME: &str = "s";

/// A directory only this process's user can enter (`0700`), made in the service directory
/// for one bind and removed, with the socket's name in it, when dropped. A socket bound there
/// can be connected to by nobody else until it is linked to the advertised path, so it never
/// sits at that path with the mode the umask gave it. A directory a killed start left behind is
/// never looked at, so it blocks nothing.
struct PrivateDir {
    parent: OwnedFd,
    name: String,
    path: PathBuf,
    fd: OwnedFd,
}

const PRIVATE_DIR_MODE: u32 = 0o700;

impl PrivateDir {
    fn create(parent: &OwnedFd, dir: &SocketDir) -> Result<Self, BindError> {
        const ATTEMPTS: usize = 8;
        let parent = parent.try_clone().map_err(|source| BindError::Io {
            op: "dup",
            path: dir.dir(),
            source,
        })?;
        for _ in 0..ATTEMPTS {
            let name = format!(".{}.bind.{:016x}", dir.service(), random_suffix());
            let path = dir.dir().join(&name);
            match rustix::fs::mkdirat(&parent, name.as_str(), mode(PRIVATE_DIR_MODE)) {
                Ok(()) => {}
                Err(Errno::EXIST) => continue,
                Err(e) => return Err(io_err("mkdir", &path)(e)),
            }
            let fd = match open_dir(&parent, Path::new(&name), &path) {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = rustix::fs::unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR);
                    return Err(e);
                }
            };
            let private = Self {
                parent,
                name,
                path,
                fd,
            };
            // `0700` exactly, whatever the umask: it only ever narrows what `mkdirat` asks for.
            rustix::fs::fchmod(&private.fd, mode(PRIVATE_DIR_MODE))
                .map_err(io_err("chmod", &private.path))?;
            let m = fstat(&private.fd, &private.path)?;
            if m.uid != peercred::effective_uid() || m.mode != mode(PRIVATE_DIR_MODE) {
                return Err(BindError::Insecure {
                    path: private.path.clone(),
                    reason: format!("private bind directory is {}", describe(&m)),
                });
            }
            return Ok(private);
        }
        Err(io_err("mkdir", &dir.dir())(Errno::EXIST))
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = rustix::fs::unlinkat(&self.fd, BOUND_NAME, AtFlags::empty());
        if let Err(e) = rustix::fs::unlinkat(&self.parent, self.name.as_str(), AtFlags::REMOVEDIR) {
            tracing::warn!(dir = %self.path.display(), error = %e, "cannot remove the private bind directory");
        }
    }
}

/// Clients connect to the advertised path, not the `/proc` one `bind(2)` goes through, so the
/// advertised path must fit a `sun_path` itself.
fn check_socket_path(path: &Path) -> Result<(), BindError> {
    std::os::unix::net::SocketAddr::from_pathname(path)
        .map(drop)
        .map_err(|source| BindError::SocketPath {
            path: path.to_owned(),
            len: path.as_os_str().len(),
            source,
        })
}

/// `bind(2)` takes a path: check it still resolves to the directory we hold open.
fn same_dir(path: &Path, dir_fd: &OwnedFd) -> Result<(), BindError> {
    let held = fstat(dir_fd, path)?;
    let named = std::fs::symlink_metadata(path).map_err(|source| BindError::Io {
        op: "lstat",
        path: path.to_owned(),
        source,
    })?;
    if (named.dev(), named.ino()) == (held.dev, held.ino) && named.is_dir() {
        Ok(())
    } else {
        Err(BindError::Insecure {
            path: path.to_owned(),
            reason: "path no longer names the service directory that was checked".into(),
        })
    }
}

/// Gives the socket `name` in `dir_fd` (the [`PrivateDir`]) its owner, group and mode
/// (`0660`), and checks them.
fn set_socket_owner_and_mode(
    dir_fd: &OwnedFd,
    name: &str,
    path: &Path,
    bound: &Meta,
    owner: Ownership,
) -> Result<(), BindError> {
    // The owner changes only where it differs (`owner_change`), and is checked below.
    if let Some((uid, gid)) = owner_change(bound, owner) {
        rustix::fs::chownat(dir_fd, name, uid, Some(gid), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io_err("chown", path))?;
    }
    // Linux has no fchmodat(AT_SYMLINK_NOFOLLOW) before 6.6; the directory is ours alone
    // (`0700`), so the name cannot have been replaced by a symlink since the bind.
    rustix::fs::chmodat(dir_fd, name, mode(SOCKET_MODE), AtFlags::empty())
        .map_err(io_err("chmod", path))?;
    check_socket(dir_fd, name, path, bound, owner)
}

/// Fails unless `name` in `dir_fd` is the socket `bound`, with `owner`'s uid and gid and mode
/// `0660`.
fn check_socket(
    dir_fd: &OwnedFd,
    name: &str,
    path: &Path,
    bound: &Meta,
    owner: Ownership,
) -> Result<(), BindError> {
    let m = lstat_at(dir_fd, name, path)?;
    let want = mode(SOCKET_MODE);
    match m {
        Some(m)
            if m.same_file(bound) && m.uid == owner.uid && m.gid == owner.gid && m.mode == want =>
        {
            Ok(())
        }
        other => Err(BindError::Insecure {
            path: path.to_owned(),
            reason: format!(
                "socket must be uid {} gid {} mode {:o}, found {:?}",
                owner.uid,
                owner.gid,
                SOCKET_MODE,
                other.map(|m| (m.uid, m.gid, mode_bits(m.mode)))
            ),
        }),
    }
}

/// Why a peer-checked connection failed.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("connect {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The server is not who the client expects; nothing was sent to it.
    #[error("refusing the server on {}: {source}", path.display())]
    Peer {
        path: PathBuf,
        #[source]
        source: PeerCredError,
    },
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// A tonic connector for one Unix socket that refuses a server not running as `expected_uid`.
/// The check runs on the connected stream before it is handed to tonic, so nothing is written
/// to a refused server; it runs again on every reconnect.
#[derive(Clone, Debug)]
pub struct PeerCheckedConnector {
    path: Arc<Path>,
    expected_uid: u32,
}

impl PeerCheckedConnector {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, expected_uid: u32) -> Self {
        Self {
            path: Arc::from(path.into()),
            expected_uid,
        }
    }

    /// Connects and checks the server's UID.
    pub async fn connect(&self) -> Result<UnixStream, ConnectError> {
        let stream = UnixStream::connect(&*self.path)
            .await
            .map_err(|source| ConnectError::Io {
                path: self.path.to_path_buf(),
                source,
            })?;
        peercred::expect_uid(stream.peer_cred(), self.expected_uid).map_err(|source| {
            tracing::error!(
                socket = %self.path.display(),
                error = %source,
                "refusing a server that is not the expected service user"
            );
            ConnectError::Peer {
                path: self.path.to_path_buf(),
                source,
            }
        })?;
        Ok(stream)
    }
}

impl tower::Service<Uri> for PeerCheckedConnector {
    type Response = TokioIo<UnixStream>;
    type Error = ConnectError;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.connect().await.map(TokioIo::new) })
    }
}

/// A channel to `dir`'s service that only talks to a server running as `expected_uid`.
pub async fn connect(
    dir: &SocketDir,
    expected_uid: u32,
) -> Result<Channel, tonic::transport::Error> {
    connect_path(dir.socket_path(), expected_uid).await
}

/// [`connect`] to a socket path.
pub async fn connect_path(
    path: impl Into<PathBuf>,
    expected_uid: u32,
) -> Result<Channel, tonic::transport::Error> {
    // The authority is not used to route anything: the connector picks the socket.
    Endpoint::from_static("http://localhost")
        .connect_with_connector(PeerCheckedConnector::new(path, expected_uid))
        .await
}

/// The pause between two connection attempts of [`connect_path_waiting`].
pub const CONNECT_RETRY: std::time::Duration = std::time::Duration::from_millis(200);

/// [`connect_path`], tried again every [`CONNECT_RETRY`] while the socket is not there yet or
/// nobody listens on it yet ([`is_not_ready`]), until `wait` is over. `waiting` is called once,
/// at the first retry, so the caller can log the wait. Any other error (a server of another
/// user included) is returned at once.
///
/// # Errors
///
/// The last connection error.
pub async fn connect_path_waiting(
    path: &Path,
    expected_uid: u32,
    wait: std::time::Duration,
    waiting: impl FnOnce(),
) -> Result<Channel, tonic::transport::Error> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut waiting = Some(waiting);
    loop {
        match connect_path(path, expected_uid).await {
            Ok(channel) => return Ok(channel),
            Err(e)
                if is_not_ready(&e) && tokio::time::Instant::now() + CONNECT_RETRY <= deadline =>
            {
                if let Some(tell) = waiting.take() {
                    tell();
                }
                tokio::time::sleep(CONNECT_RETRY).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Whether `err` is a socket that is not there yet (`NotFound`) or that nobody listens on yet
/// (`ConnectionRefused`), anywhere in its source chain. A peer check that failed
/// ([`peer_refusal`]) is never "not ready", whatever I/O error it carries.
#[must_use]
pub fn is_not_ready(err: &(dyn std::error::Error + 'static)) -> bool {
    if peer_refusal(err).is_some() {
        return false;
    }
    let mut next = Some(err);
    while let Some(e) = next {
        if let Some(io) = e.downcast_ref::<io::Error>() {
            if matches!(
                io.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) {
                return true;
            }
        }
        next = e.source();
    }
    false
}

/// The peer check that refused a connection, anywhere in `err`'s source chain.
#[must_use]
pub fn peer_refusal<'a>(err: &'a (dyn std::error::Error + 'static)) -> Option<&'a PeerCredError> {
    let mut next = Some(err);
    while let Some(e) = next {
        if let Some(p) = e.downcast_ref::<PeerCredError>() {
            return Some(p);
        }
        next = e.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::net::UnixStream as StdUnixStream;

    #[test]
    fn socket_dir_names_the_paths() {
        let d = SocketDir::new("cl-engine").unwrap();
        assert_eq!(d.root(), Path::new("/run/ethswarm"));
        assert_eq!(d.service(), "cl-engine");
        assert_eq!(d.dir(), Path::new("/run/ethswarm/cl-engine"));
        assert_eq!(
            d.socket_path(),
            Path::new("/run/ethswarm/cl-engine/cl-engine.sock")
        );
        assert_eq!(
            d.lock_path(),
            Path::new("/run/ethswarm/cl-engine/cl-engine.lock")
        );
    }

    #[test]
    fn service_names_cannot_escape_the_root() {
        for bad in ["", "..", "a/b", "Cl-Engine", "cl_engine", &"x".repeat(65)] {
            let err = SocketDir::under("/tmp", bad).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        }
    }

    #[test]
    fn error_kinds() {
        let p = PathBuf::from("/x");
        let in_use = BindError::InUse {
            path: p.clone(),
            reason: "r",
        };
        assert_eq!(io::Error::from(in_use).kind(), io::ErrorKind::AddrInUse);
        let foreign = BindError::ForeignSocket {
            path: p.clone(),
            owner: 1,
            expected: 2,
        };
        assert_eq!(foreign.kind(), io::ErrorKind::PermissionDenied);
        assert!(foreign.to_string().contains("uid 1"), "{foreign}");
        let e = BindError::Io {
            op: "bind",
            path: p,
            source: io::ErrorKind::NotFound.into(),
        };
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert_eq!(BindError::Id(u32::MAX).kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn invalid_ids_are_refused_before_touching_the_disk() {
        let d = SocketDir::under("/nonexistent-root", "svc").unwrap();
        let err = bind(
            &d,
            Ownership {
                uid: u32::MAX,
                gid: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(err, BindError::Id(_)), "{err}");
    }

    #[test]
    fn path_steps_go_through_the_held_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir_fd = open_dir(CWD, tmp.path(), tmp.path()).unwrap();
        let named = tmp.path().join("s.sock");
        let via = through_dir(&dir_fd, "s.sock", &named).unwrap();
        if cfg!(target_os = "linux") {
            assert!(
                via.starts_with("/proc/thread-self/fd/"),
                "{}",
                via.display()
            );
        } else {
            assert_eq!(via, named);
        }
        // Binding and probing through it reach the directory held open.
        let listener = StdUnixListener::bind(&via).unwrap();
        assert!(named.exists());
        assert!(answers(&via).unwrap());
        drop(listener);
        assert!(!answers(&via).unwrap(), "stale");
    }

    /// Without a usable `/proc`, Linux refuses to start instead of falling back to the path.
    #[cfg(target_os = "linux")]
    #[test]
    fn unusable_proc_is_an_error_not_a_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let dir_fd = open_dir(CWD, tmp.path(), tmp.path()).unwrap();
        let missing = tmp.path().join("no-proc");
        let err = through_proc(&missing, &dir_fd, "s.sock").unwrap_err();
        assert!(
            matches!(&err, BindError::Insecure { reason, .. } if reason.contains("/proc")),
            "{err}"
        );
        // A look-alike whose `<fd>` entry is some other directory.
        use std::os::fd::AsRawFd;
        let fake = tmp.path().join("fake");
        std::fs::create_dir_all(fake.join(dir_fd.as_raw_fd().to_string())).unwrap();
        let err = through_proc(&fake, &dir_fd, "s.sock").unwrap_err();
        assert!(err.to_string().contains("another file"), "{err}");
        // The real one works.
        let via = through_proc(Path::new(PROC_FDS), &dir_fd, "s.sock").unwrap();
        assert!(via.starts_with(PROC_FDS), "{}", via.display());
    }

    /// A service directory of ours, held open, under a root named without symlinks.
    fn held_service_dir(tmp: &tempfile::TempDir) -> (SocketDir, OwnedFd) {
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let dir = SocketDir::under(&root, "svc").unwrap();
        let root_fd = open_dir(CWD, &root, &root).unwrap();
        let dir_fd = open_service_dir(&root_fd, &dir, Ownership::current()).unwrap();
        (dir, dir_fd)
    }

    fn entries(dir: &SocketDir) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// Nobody can reach the socket before its owner, group and mode are final: `bind(2)`
    /// creates it in a private `0700` directory, and only the finished socket is linked to the
    /// advertised path. A chmod after a bind at the advertised path would leave it there for a
    /// moment with whatever mode the umask gave it.
    #[test]
    fn the_socket_is_published_only_once_its_mode_is_final() {
        use std::os::unix::fs::FileTypeExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let dir = SocketDir::under(&root, "svc").unwrap();
        let seen = std::rc::Rc::new(std::cell::RefCell::new(None));
        let (advertised, record) = (dir.socket_path(), std::rc::Rc::clone(&seen));
        AFTER_BIND.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |bound_at: &Path| {
                let reachable = std::fs::symlink_metadata(&advertised).is_ok();
                let private = std::fs::metadata(bound_at.parent().unwrap())
                    .map(|m| m.mode() & 0o7777)
                    .ok();
                *record.borrow_mut() = Some((reachable, private));
            }));
        });
        let bound = bind(&dir, Ownership::current());
        AFTER_BIND.with(|hook| hook.borrow_mut().take());
        let bound = bound.unwrap();
        let (reachable, private) = seen.borrow_mut().take().expect("bind(2) ran");
        assert!(
            !reachable,
            "the socket was reachable at its advertised path before its mode was set"
        );
        assert_eq!(private, Some(0o700), "bound outside a private directory");
        let m = std::fs::symlink_metadata(dir.socket_path()).unwrap();
        assert!(m.file_type().is_socket());
        assert_eq!(m.mode() & 0o7777, SOCKET_MODE);
        // Nothing is left behind next to the lock and the socket, and the socket answers at
        // the advertised path.
        assert_eq!(entries(&dir), ["svc.lock", "svc.sock"]);
        drop(StdUnixStream::connect(dir.socket_path()).unwrap());
        drop(bound);
    }

    /// A bind as our own user and group changes no owner: the new directory, lock and socket
    /// carry both already, as a unit's do under its `User=` and `Group=`. The units' seccomp
    /// filter (`SystemCallFilter=~@privileged`, which holds `@chown`) kills a process that
    /// calls `fchown`. Another group of ours is set, and checked, as before.
    #[test]
    fn a_bind_as_our_own_user_and_group_changes_no_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let me = Ownership::current();
        let dir = SocketDir::under(&root, "svc").unwrap();
        CHOWNS.with(|c| c.set(0));
        let bound = bind(&dir, me).unwrap();
        assert_eq!(
            CHOWNS.with(Cell::get),
            0,
            "a chown for ids that already match"
        );
        drop(bound);
        // A group of ours that is not our effective one needs the chown.
        let other = rustix::process::getgroups()
            .unwrap_or_default()
            .into_iter()
            .map(rustix::process::Gid::as_raw)
            .find(|g| *g != me.gid);
        if let Some(gid) = other {
            let dir = SocketDir::under(&root, "other").unwrap();
            let owner = Ownership { uid: me.uid, gid };
            CHOWNS.with(|c| c.set(0));
            let bound = bind(&dir, owner).unwrap();
            assert!(
                CHOWNS.with(Cell::get) > 0,
                "the group of a new file is not set"
            );
            assert_eq!(std::fs::metadata(dir.socket_path()).unwrap().gid(), gid);
            drop(bound);
        }
    }

    /// A start that fails after creating its lock but before publishing it leaves nothing under
    /// either name, and the next start takes a fresh lock.
    #[test]
    fn a_lock_that_fails_before_it_is_published_leaves_nothing_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let (dir, dir_fd) = held_service_dir(&tmp);
        let mut seen = None;
        let err = lock_with(&dir_fd, &dir, Ownership::current(), |fd| {
            // Fully set up but not yet under its final name.
            seen = Some(fstat(fd, &dir.lock_path()).unwrap());
            assert!(!dir.lock_path().exists(), "not published yet");
            Err(BindError::Insecure {
                path: dir.lock_path(),
                reason: "injected".into(),
            })
        })
        .unwrap_err();
        assert!(err.to_string().contains("injected"), "{err}");
        let seen = seen.expect("the hook ran");
        assert_eq!(seen.mode, mode(LOCK_MODE));
        assert_eq!(seen.file_type, FileType::RegularFile);
        assert!(entries(&dir).is_empty(), "{:?}", entries(&dir));

        let held = lock(&dir_fd, &dir, Ownership::current()).unwrap();
        assert_eq!(entries(&dir), ["svc.lock"]);
        // Published already locked: a second instance is refused.
        let err = lock(&dir_fd, &dir, Ownership::current()).unwrap_err();
        assert!(matches!(err, BindError::InUse { .. }), "{err}");
        drop(held);
        // Reused once free, without a new inode.
        let ino = fstat(
            lock(&dir_fd, &dir, Ownership::current()).unwrap(),
            &dir.lock_path(),
        )
        .unwrap()
        .ino;
        assert_eq!(std::fs::metadata(dir.lock_path()).unwrap().ino(), ino);
        assert_eq!(entries(&dir), ["svc.lock"]);
    }

    /// A lock another start published while this one set up its own wins: the temporary name is
    /// removed and the published lock goes through the existing-lock checks.
    #[test]
    fn a_lock_published_first_by_another_start_is_used_instead() {
        let tmp = tempfile::tempdir().unwrap();
        let (dir, dir_fd) = held_service_dir(&tmp);
        // The other start's lock, held by it.
        let mut other = None;
        let err = lock_with(&dir_fd, &dir, Ownership::current(), |_| {
            other = Some(lock(&dir_fd, &dir, Ownership::current()).unwrap());
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, BindError::InUse { .. }), "{err}");
        assert_eq!(entries(&dir), ["svc.lock"]);
        drop(other);
        // A loose lock published first is refused, not replaced.
        std::fs::remove_file(dir.lock_path()).unwrap();
        let err = lock_with(&dir_fd, &dir, Ownership::current(), |_| {
            std::fs::write(dir.lock_path(), b"").unwrap();
            std::fs::set_permissions(
                dir.lock_path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o644),
            )
            .unwrap();
            Ok(())
        })
        .unwrap_err();
        assert!(
            matches!(&err, BindError::Insecure { reason, .. } if reason.contains("existing lock")),
            "{err}"
        );
        assert_eq!(entries(&dir), ["svc.lock"]);
    }

    /// A directory to create a name in is walked as the runtime root is, and must itself be
    /// closed to others too: owned by us or root, not writable by others unless sticky.
    #[test]
    fn a_closed_dir_and_every_directory_above_it_are_closed_to_others() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let me = peercred::effective_uid();
        let set = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let dir = root.join("dir");
        std::fs::create_dir(&dir).unwrap();
        for (mode, ok) in [
            (0o700, true),
            (0o1777, true),
            (0o777, false),
            (0o770, false),
        ] {
            set(&dir, mode);
            let opened = open_closed_dir(&dir, me);
            assert_eq!(opened.is_ok(), ok, "{mode:o}");
            if let Err(e) = opened {
                assert!(e.to_string().contains("not writable by others"), "{e}");
            }
        }
        set(&dir, 0o700);
        if me != 0 {
            let err = open_closed_dir(&dir, me + 1).unwrap_err();
            assert!(err.to_string().contains("owned by root or uid"), "{err}");
        }
        std::os::unix::fs::symlink(&dir, root.join("link")).unwrap();
        let err = open_closed_dir(&root.join("link"), me).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
        let err = open_closed_dir(Path::new("relative"), me).unwrap_err();
        assert!(err.to_string().contains("absolute"), "{err}");
    }

    #[test]
    fn peer_refusal_walks_the_source_chain() {
        let inner = ConnectError::Peer {
            path: "/s".into(),
            source: PeerCredError::WrongUid {
                expected: 1,
                actual: 2,
            },
        };
        let wrapped = io::Error::other(inner);
        assert!(matches!(
            peer_refusal(&wrapped),
            Some(PeerCredError::WrongUid { actual: 2, .. })
        ));
        let plain = io::Error::from(io::ErrorKind::NotFound);
        assert!(peer_refusal(&plain).is_none());
    }

    /// The wait for a socket that is not there yet ends when it accepts; a socket that never
    /// comes ends the wait at its bound with a "not ready" error, and the wait is told once.
    #[tokio::test]
    async fn a_socket_is_waited_for_within_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("svc.sock");
        let uid = Ownership::current().uid;
        let told = std::sync::atomic::AtomicUsize::new(0);
        let err = connect_path_waiting(&path, uid, std::time::Duration::from_millis(500), || {
            told.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .await
        .unwrap_err();
        assert!(is_not_ready(&err), "{err:?}");
        assert_eq!(told.load(std::sync::atomic::Ordering::SeqCst), 1);
        let later = path.clone();
        let bind = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let listener = tokio::net::UnixListener::bind(&later).unwrap();
            let routes = tonic::service::Routes::default();
            tonic::transport::Server::builder()
                .add_routes(routes)
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                .await
        });
        assert!(
            connect_path_waiting(&path, uid, std::time::Duration::from_secs(10), || {})
                .await
                .is_ok()
        );
        bind.abort();
        assert!(!is_not_ready(&std::io::Error::other("other")));
    }
}
