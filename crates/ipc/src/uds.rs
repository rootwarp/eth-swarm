//! Service-owned Unix sockets: `/run/ethswarm/<svc>/<svc>.sock`.
//!
//! ## Layout and modes
//! The runtime root (`/run/ethswarm`, [`DEFAULT_ROOT`]) must be a real directory, owned by root
//! or by the service user, and writable by nobody else. Under it each service owns one
//! directory, mode `0750`, owner the service user, group the group of its allowed callers; the
//! socket inside is `0660` with the same owner and group. A caller outside the group cannot
//! reach the socket at all; a caller inside it is then checked per method ([`crate::acl`]).
//!
//! ## [`bind`]
//! The runtime root's last component is opened with `O_NOFOLLOW`, and every directory above
//! it must be writable only by root or us (sticky directories such as `/tmp` excepted). After
//! that, the filesystem steps are relative to directory file descriptors
//! (`mkdirat`/`openat`/`fstatat`/`fchownat`/`unlinkat`, `O_NOFOLLOW`), so they do not follow a
//! symlink in place of the service directory. The two steps that take a path, the
//! `connect()` probe and `bind(2)`, go through `/proc/thread-self/fd/<dirfd>/` on Linux; elsewhere
//! they re-resolve the directory path, which is checked first to still name the directory
//! held open:
//!
//! 1. The service directory is created `0750` with the service owner and group set explicitly,
//!    or, if it exists, must already be exactly that: a looser mode, another owner or group, a
//!    symlink or a non-directory fails startup. Nothing is repaired.
//! 2. `<svc>.lock` in that directory is set to the service user, mode `0600` (on the inode
//!    found, never replaced) and `flock`ed for the life of the process, so a second instance
//!    fails with `AddrInUse` instead of touching the first one's socket. A lock that cannot be
//!    given to the service user fails startup.
//! 3. A leftover socket path is looked at with `lstat` (`AT_SYMLINK_NOFOLLOW`). Only a socket
//!    owned by the service user that refuses a `connect()` probe is stale and unlinked. A live
//!    socket fails with `AddrInUse`; a symlink, file, directory, or a socket of another user is
//!    left in place and fails startup.
//! 4. The socket is bound, then its group and mode (`0660`) are set explicitly and checked
//!    before the caller is told the service is ready. The directory is writable only by the
//!    service user, so nobody else can swap the socket afterwards.
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
            Self::Service(_) | Self::Id(_) => io::ErrorKind::InvalidInput,
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

/// Opens `name` in `parent` as a directory without following a symlink.
fn open_dir(parent: impl AsFd + Copy, name: &Path, path: &Path) -> Result<OwnedFd, BindError> {
    match rustix::fs::openat(parent, name, DIR_FLAGS, Mode::empty()) {
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

/// The path the kernel resolves to reach `name` in the directory `dir_fd`. On Linux that is
/// `/proc/thread-self/fd/<dirfd>/<name>` (the open directory itself, whatever its path names now);
/// elsewhere, or without `/proc`, the path, which [`same_dir`] checked.
fn through_dir(dir_fd: &OwnedFd, name: &str, path: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // thread-self: a thread holding other credentials (tests) may still read its own fds.
        let held = PathBuf::from(format!("/proc/thread-self/fd/{}", dir_fd.as_raw_fd()));
        if held.is_dir() {
            return held.join(name);
        }
    }
    let _ = (dir_fd, name);
    path.to_owned()
}

/// Every directory above the runtime root (after resolving symlinks) must be owned by root or
/// us and not writable by group or others unless sticky: otherwise someone else could rename
/// the root away and put their own in its place.
fn check_parents(root: &Path) -> Result<(), BindError> {
    let resolved = std::fs::canonicalize(root).map_err(|source| BindError::Io {
        op: "resolve",
        path: root.to_owned(),
        source,
    })?;
    let me = peercred::effective_uid();
    for parent in resolved.ancestors().skip(1) {
        let m = std::fs::metadata(parent).map_err(|source| BindError::Io {
            op: "stat",
            path: parent.to_owned(),
            source,
        })?;
        let writable = m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0;
        if (m.uid() != 0 && m.uid() != me) || writable {
            return Err(BindError::Insecure {
                path: root.to_owned(),
                reason: format!(
                    "parent {} must be owned by root or uid {me} and not writable by others \
                     unless sticky (owner uid {}, mode {:o})",
                    parent.display(),
                    m.uid(),
                    m.mode() & 0o7777
                ),
            });
        }
    }
    Ok(())
}

/// The runtime root: a directory owned by root or us that only its owner can write, under
/// parents nobody else can write either.
fn open_root(root: &Path) -> Result<OwnedFd, BindError> {
    let fd = open_dir(CWD, root, root)?;
    check_parents(root)?;
    let m = fstat(&fd, root)?;
    let me = peercred::effective_uid();
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
        // Set explicitly: neither the umask nor a setgid parent decides the owner or mode.
        let uid = (owner.uid != peercred::effective_uid()).then(|| Uid::from_raw(owner.uid));
        rustix::fs::fchown(&fd, uid, Some(Gid::from_raw(owner.gid)))
            .map_err(io_err("chown", &path))?;
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

/// Takes the instance lock for the life of the returned descriptor.
fn lock(dir_fd: &OwnedFd, dir: &SocketDir, owner: Ownership) -> Result<OwnedFd, BindError> {
    let path = dir.lock_path();
    let flags = OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd = match rustix::fs::openat(dir_fd, dir.lock_name(), flags, mode(LOCK_MODE)) {
        Ok(fd) => fd,
        Err(Errno::LOOP) => {
            return Err(BindError::NotASocket {
                path,
                kind: "symlink",
            })
        }
        Err(Errno::ACCESS | Errno::PERM) => {
            let found = lstat_at(dir_fd, &dir.lock_name(), &path)?
                .map(|m| format!("uid {} mode {:o}", m.uid, mode_bits(m.mode)));
            return Err(BindError::Insecure {
                reason: format!(
                    "uid {} cannot open the lock ({})",
                    peercred::effective_uid(),
                    found.as_deref().unwrap_or("gone")
                ),
                path,
            });
        }
        Err(e) => return Err(io_err("open", &path)(e)),
    };
    let m = fstat(&fd, &path)?;
    if m.file_type != FileType::RegularFile {
        return Err(BindError::Insecure {
            path,
            reason: format!("lock is a {}, not a regular file", kind_name(m.file_type)),
        });
    }
    // Set explicitly on the inode we hold, never replaced: the umask may have loosened a fresh
    // lock, and a lock a caller can open is a lock a caller can hold against every start.
    let uid = (m.uid != owner.uid).then(|| Uid::from_raw(owner.uid));
    let fixed = rustix::fs::fchown(&fd, uid, Some(Gid::from_raw(owner.gid)))
        .and_then(|()| rustix::fs::fchmod(&fd, mode(LOCK_MODE)));
    if let Err(e) = fixed {
        return Err(BindError::Insecure {
            path,
            reason: format!(
                "lock is uid {} gid {} mode {:o} and cannot be made uid {} gid {} mode {:o}: {e}",
                m.uid,
                m.gid,
                mode_bits(m.mode),
                owner.uid,
                owner.gid,
                LOCK_MODE
            ),
        });
    }
    let m = fstat(&fd, &path)?;
    if m.uid != owner.uid || m.mode != mode(LOCK_MODE) {
        return Err(BindError::Insecure {
            path,
            reason: format!(
                "lock must be uid {} mode {:o}, is uid {} mode {:o}",
                owner.uid,
                LOCK_MODE,
                m.uid,
                mode_bits(m.mode)
            ),
        });
    }
    match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(fd),
        Err(e) if e == Errno::WOULDBLOCK => Err(BindError::InUse {
            path,
            reason: "another instance of the service holds the lock",
        }),
        Err(e) => Err(io_err("lock", &path)(e)),
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
    let live = answers(&through_dir(dir_fd, &name, &path)).map_err(|source| BindError::Io {
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
/// the service user, binds the socket and sets its owner, group and mode (`0660`). See the
/// module docs for what makes it fail.
pub fn bind(dir: &SocketDir, owner: Ownership) -> Result<BoundSocket, BindError> {
    for id in [owner.uid, owner.gid] {
        if id == u32::MAX {
            return Err(BindError::Id(id));
        }
    }
    let root_fd = open_root(dir.root())?;
    let dir_fd = open_service_dir(&root_fd, dir, owner)?;
    let lock_fd = lock(&dir_fd, dir, owner)?;
    same_dir(&dir.dir(), &dir_fd)?;
    clear_stale(&dir_fd, dir, owner)?;

    let (name, path) = (dir.socket_name(), dir.socket_path());
    let listener = StdUnixListener::bind(through_dir(&dir_fd, &name, &path)).map_err(|source| {
        BindError::Io {
            op: "bind",
            path: path.clone(),
            source,
        }
    })?;
    let bound = lstat_at(&dir_fd, &name, &path)?.ok_or_else(|| BindError::Insecure {
        path: path.clone(),
        reason: "socket vanished right after bind".into(),
    })?;
    // From here on the guard removes the socket on every error path.
    let guard = SocketGuard {
        dir_fd,
        name,
        path,
        bound,
        unlinked: false,
        _lock: lock_fd,
    };
    set_socket_owner_and_mode(&guard, owner)?;
    Ok(BoundSocket { listener, guard })
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

fn set_socket_owner_and_mode(guard: &SocketGuard, owner: Ownership) -> Result<(), BindError> {
    let path = &guard.path;
    let uid = (owner.uid != peercred::effective_uid()).then(|| Uid::from_raw(owner.uid));
    rustix::fs::chownat(
        &guard.dir_fd,
        guard.name.as_str(),
        uid,
        Some(Gid::from_raw(owner.gid)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(io_err("chown", path))?;
    // Linux has no fchmodat(AT_SYMLINK_NOFOLLOW) before 6.6; the directory is writable only by
    // the service user, so the name cannot have been replaced by a symlink since the bind.
    rustix::fs::chmodat(
        &guard.dir_fd,
        guard.name.as_str(),
        mode(SOCKET_MODE),
        AtFlags::empty(),
    )
    .map_err(io_err("chmod", path))?;
    let m = lstat_at(&guard.dir_fd, &guard.name, path)?;
    let want = mode(SOCKET_MODE);
    match m {
        Some(m)
            if m.same_file(&guard.bound)
                && m.uid == owner.uid
                && m.gid == owner.gid
                && m.mode == want =>
        {
            Ok(())
        }
        other => Err(BindError::Insecure {
            path: path.clone(),
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
        let via = through_dir(&dir_fd, "s.sock", &named);
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
}
