//! On-disk snapshot of the finalized pubkey cache (`pubkeys.bin`).
//!
//! # Format (version 2, little-endian)
//!
//! `MAGIC` (8) | `VERSION` u32 = 2 | `len` u64 | `registry` (32) | `body` (32) | `len` × 96-byte
//! uncompressed points.
//!
//! - `registry`: SHA-256 over the concatenated 48-byte *compressed* keys `0..len`. This is the
//!   digest cl-chain announces for its finalized registry on the first feed response
//!   ([`Registry`]), so a stale or foreign snapshot is told apart before its body is read.
//! - `body`: SHA-256 over the body bytes, so a damaged point is never decoded into the cache.
//!
//! Keys pass `KeyValidate` once, when they enter the cache from the feed, and are verified with
//! `pk_validate = false` afterwards. The body therefore stores uncompressed points, and a reload
//! decodes them with [`KeyCodec::decode_uncompressed_unchecked`]: no decompression, no subgroup
//! check.
//!
//! # Why skipping the subgroup check is sound
//!
//! What binds each decoded point to a key that passed `KeyValidate` is the registry recompute,
//! together with the codec's on-curve check:
//! 1. The codec MUST reject a point that is not on the curve (see [`KeyCodec`]).
//! 2. After decoding, the registry digest is recomputed over `compressed(decoded)` and must equal
//!    the digest cl-chain announced for its finalized registry, whose keys passed `KeyValidate`.
//!
//! A compressed key (x and the sign of y) names exactly one point on the curve, so a point that
//! is on the curve and compresses to a registry entry *is* that validated key, which lies in the
//! subgroup. Without (1), a point with the same x but another y would pass (2); with it, such a
//! point is not on the curve and the load is a rebuild ([`RebuildReason::InvalidPoint`]).
//!
//! The file checks are defence in depth on top of that: a snapshot is read only if it is a
//! regular file (opened without following a symlink or blocking), with mode exactly `0600`,
//! owned by the effective UID of this process, and with a matching body digest, so a damaged or
//! foreign file is dropped before any point is decoded.
//!
//! # Rebuild, never trust
//!
//! [`load_with`] returns [`Startup::Rebuild`] on any wrong owner or mode, short read, unknown
//! version, length mismatch, registry digest mismatch or body digest mismatch. It never returns
//! a partial cache, and [`startup_with`] then rebuilds the whole cache from index 0 over the
//! feed. Writes are atomic ([`stage_with`] then [`StagedSnapshot::commit`]): a crash before the
//! rename leaves the previous snapshot in place.
//!
//! # Codec
//!
//! This crate does not depend on blst. The caller supplies a [`KeyCodec`] for its key type
//! (cl-verify: `blst::min_pk::PublicKey`, via `compress`, `serialize` and an unchecked
//! `from_bytes` of the 96-byte form). A codec value rather than a trait on the key type, because
//! the orphan rule forbids cl-verify from implementing this crate's trait for blst's type.
//!
//! # Legacy format (version 1)
//!
//! [`save`], [`load`] and [`startup`] read and write the earlier version-1 layout
//! (`MAGIC | VERSION | len | sha256(keys) | len × 48-byte compressed keys`) for `[u8; 48]` keys,
//! with no owner or mode checks. They are kept for source compatibility only. A version-1 file
//! is an unknown version to [`load_with`] and is rebuilt.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use sha2::{Digest, Sha256};

use crate::PubkeyCache;

pub type Key = [u8; 48];

/// Bytes of a compressed G1 pubkey (the feed's wire form).
pub const COMPRESSED_LEN: usize = 48;
/// Bytes of an uncompressed G1 pubkey (the snapshot body's form).
pub const UNCOMPRESSED_LEN: usize = 96;
/// Most entries [`startup_with`] asks the feed for at once while rebuilding.
pub const REBUILD_CHUNK_ENTRIES: usize = 4_096;
/// The only mode a snapshot may have.
pub const FILE_MODE: u32 = 0o600;

const MAGIC: &[u8; 8] = b"CLVPKC01";
const VERSION: u32 = 1;
const HEADER: usize = 8 + 4 + 8 + 32;

const FORMAT_VERSION: u32 = 2;
const PREFIX_LEN: usize = 8 + 4;
const HEADER_LEN: usize = PREFIX_LEN + 8 + 32 + 32;
/// Points hashed and decoded per read while loading, so the body is never held twice.
const READ_CHUNK_POINTS: usize = 4_096;

/// Converts the caller's key type to and from the snapshot's byte forms.
pub trait KeyCodec {
    type Key;

    /// The 48-byte compressed form; the registry digest is computed over it.
    fn compressed(&self, key: &Self::Key) -> [u8; COMPRESSED_LEN];

    /// The 96-byte uncompressed form stored in the body.
    fn uncompressed(&self, key: &Self::Key) -> [u8; UNCOMPRESSED_LEN];

    /// Decodes bytes written by [`uncompressed`](Self::uncompressed) for a key that was
    /// validated when it entered the cache. It need not run the subgroup check or decompress.
    ///
    /// It MUST return `None` for a point that is not on the curve (blst's 96-byte `from_bytes`
    /// does this check). The skipped subgroup check is sound only with it; see the
    /// [module docs](self). Any `None` makes the load a rebuild.
    fn decode_uncompressed_unchecked(&self, bytes: &[u8; UNCOMPRESSED_LEN]) -> Option<Self::Key>;
}

/// A finalized registry prefix as cl-chain announces it: its length and the SHA-256 over its
/// concatenated compressed keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Registry {
    pub len: u64,
    pub sha256: [u8; 32],
}

impl Registry {
    /// The registry made of `keys`, indices `0..keys.len()`.
    pub fn of<C: KeyCodec>(codec: &C, keys: &[C::Key]) -> Self {
        let mut hasher = RegistryHasher::default();
        for key in keys {
            hasher.push(&codec.compressed(key));
        }
        hasher.finish()
    }
}

#[derive(Default)]
struct RegistryHasher {
    len: u64,
    sha256: Sha256,
}

impl RegistryHasher {
    fn push(&mut self, compressed: &[u8; COMPRESSED_LEN]) {
        self.len += 1;
        self.sha256.update(compressed);
    }

    fn finish(self) -> Registry {
        Registry {
            len: self.len,
            sha256: self.sha256.finalize().into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("read: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad magic, version or short header")]
    BadHeader,
    #[error("file size does not match header length (partial write)")]
    Truncated,
    #[error("stored root does not match keys")]
    RootMismatch,
}

/// What cl-verify should do after reading the saved file at start-up.
#[derive(Debug)]
pub enum Startup<K = Key> {
    Use(PubkeyCache<K>),
    Rebuild(RebuildReason),
}

/// Why a snapshot was not used. Every reason means a full rebuild from index 0.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RebuildReason {
    /// Partial or corrupted file, or an I/O error (message for the log).
    #[error("unreadable snapshot: {0}")]
    Unreadable(String),
    #[error("snapshot holds {file} entries, the finalized registry {chain}")]
    LengthMismatch { file: u64, chain: u64 },
    /// The snapshot's registry digest is not the finalized registry's.
    #[error("snapshot registry sha256 does not match the finalized registry")]
    RootMismatch,
    /// No snapshot yet (first start).
    #[error("no snapshot")]
    Missing,
    /// A directory, symlink, FIFO or other non-regular file at the snapshot path.
    #[error("snapshot is not a regular file")]
    NotRegularFile,
    #[error("snapshot owned by uid {file}, expected {expected}")]
    WrongOwner { file: u32, expected: u32 },
    #[error("snapshot mode {mode:o}, expected 600")]
    WrongMode { mode: u32 },
    /// The file ends inside the header.
    #[error("snapshot shorter than its header")]
    ShortHeader,
    #[error("snapshot does not start with the expected magic")]
    BadMagic,
    #[error("unknown snapshot format version {version}")]
    UnknownVersion { version: u32 },
    /// File size is not header + `len` × 96 (partial write or trailing bytes).
    #[error("snapshot is {actual} bytes, its header implies {expected}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("snapshot body sha256 mismatch")]
    BodyDigestMismatch,
    #[error("snapshot point {index} does not decode")]
    InvalidPoint { index: u64 },
}

/// The effective UID of this process: the only owner a snapshot may have.
pub fn effective_uid() -> u32 {
    sys::geteuid()
}

mod sys {
    // SAFETY: geteuid(2) (POSIX) takes no arguments, always succeeds and reads or writes no
    // memory of ours; `uid_t` is `u32` on Linux and macOS.
    unsafe extern "C" {
        pub(super) safe fn geteuid() -> u32;
    }

    // open(2) flags, per target, so the crate needs no `libc`. Values match libc 0.2.190.
    // Linux x86_64: include/uapi/asm-generic/fcntl.h (O_NONBLOCK 00004000, O_NOFOLLOW 00400000).
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) const O_NONBLOCK: i32 = 0o4000;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) const O_NOFOLLOW: i32 = 0o400000;

    // Linux aarch64: asm-generic O_NONBLOCK; arch/arm64/include/uapi/asm/fcntl.h overrides
    // O_NOFOLLOW to 0100000 (the 32-bit ARM value).
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(super) const O_NONBLOCK: i32 = 0o4000;
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub(super) const O_NOFOLLOW: i32 = 0o100000;

    // macOS (aarch64 and x86_64): <sys/fcntl.h> (O_NONBLOCK 0x0004, O_NOFOLLOW 0x0100).
    #[cfg(target_os = "macos")]
    pub(super) const O_NONBLOCK: i32 = 0x0004;
    #[cfg(target_os = "macos")]
    pub(super) const O_NOFOLLOW: i32 = 0x0100;

    #[cfg(not(any(
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        target_os = "macos"
    )))]
    compile_error!(
        "cl-verify-cache: no O_NOFOLLOW/O_NONBLOCK values for this target; \
         add them to persist::sys (supported: linux x86_64/aarch64, macOS)"
    );
}

/// Writes `cache` to `path` atomically: [`stage_with`], then [`StagedSnapshot::commit`].
pub fn save_with<C: KeyCodec>(
    codec: &C,
    cache: &PubkeyCache<C::Key>,
    path: &Path,
) -> io::Result<()> {
    stage_with(codec, cache, path)?.commit()
}

/// A complete, fsynced snapshot in its own temp file `<path>.tmp.<pid>.<n>` that has not
/// replaced `path` yet.
///
/// Dropping it without [`commit`](Self::commit) leaves the temp file behind, as a crash would;
/// a later [`stage_with`] for the same path removes it.
#[derive(Debug)]
#[must_use = "a staged snapshot replaces nothing until it is committed"]
pub struct StagedSnapshot {
    tmp: TempClaim,
    dest: PathBuf,
}

impl StagedSnapshot {
    pub fn tmp_path(&self) -> &Path {
        &self.tmp.0
    }

    /// Renames this stage's own temp file over the snapshot, then fsyncs the directory so the
    /// rename is durable.
    pub fn commit(self) -> io::Result<()> {
        std::fs::rename(&self.tmp.0, &self.dest)?;
        sync_parent_dir(&self.dest)
    }
}

/// Temp files of stages alive in this process; [`remove_stale_temps`] never touches them.
static LIVE_TEMPS: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn live_temps() -> MutexGuard<'static, BTreeSet<PathBuf>> {
    LIVE_TEMPS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A temp path registered in [`LIVE_TEMPS`] for as long as this value lives.
#[derive(Debug)]
struct TempClaim(PathBuf);

impl Drop for TempClaim {
    fn drop(&mut self) {
        live_temps().remove(&self.0);
    }
}

/// Writes `cache` to a new temp file next to `path`, with mode 0600, and fsyncs it.
///
/// Each stage gets its own temp file `<path>.tmp.<pid>.<n>` (created exclusively), and its
/// [`commit`](StagedSnapshot::commit) renames only that file, so overlapping stages never publish
/// each other's content. Before creating it, leftover `<path>.tmp.*` files are removed: crash
/// leftovers of earlier processes (possibly with another mode or owner) and stages of this
/// process that were dropped. Live stages of this process are kept.
///
/// One process, cl-verify, writes the snapshot. A second writer process is not supported: its
/// live temp file could be removed here, and its commit would then fail with an error.
pub fn stage_with<C: KeyCodec>(
    codec: &C,
    cache: &PubkeyCache<C::Key>,
    path: &Path,
) -> io::Result<StagedSnapshot> {
    let prefix = tmp_prefix(path)?;
    let tmp = {
        let mut live = live_temps();
        remove_stale_temps(path, &prefix, &live);
        let mut name = prefix;
        name.push(format!(
            "{}.{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let tmp = path.with_file_name(name);
        live.insert(tmp.clone());
        TempClaim(tmp)
    };
    match write_temp(codec, cache, &tmp.0) {
        Ok(()) => Ok(StagedSnapshot {
            tmp,
            dest: path.to_path_buf(),
        }),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp.0);
            Err(e)
        }
    }
}

fn write_temp<C: KeyCodec>(codec: &C, cache: &PubkeyCache<C::Key>, tmp: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(tmp)?;
    // The umask may have cleared bits of FILE_MODE at creation; set it exactly.
    file.set_permissions(Permissions::from_mode(FILE_MODE))?;

    let mut out = BufWriter::with_capacity(1 << 20, file);
    out.write_all(&[0; HEADER_LEN])?;
    let mut registry = RegistryHasher::default();
    let mut body = Sha256::new();
    for key in &cache.keys {
        let point = codec.uncompressed(key);
        body.update(point);
        registry.push(&codec.compressed(key));
        out.write_all(&point)?;
    }
    let mut file = out.into_inner().map_err(io::IntoInnerError::into_error)?;
    let header = encode_header(&registry.finish(), &body.finalize().into());
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    file.sync_all()
}

/// `<file name>.tmp.`: the prefix of every temp file staged for `path`.
fn tmp_prefix(path: &Path) -> io::Result<OsString> {
    let mut name = path
        .file_name()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot path has no file name",
            )
        })?
        .to_os_string();
    name.push(".tmp.");
    Ok(name)
}

/// Best effort: removes `<prefix>*` entries next to `path` that are not in `live`. Failures are
/// ignored; a leftover is never read, only taking up space until the next stage.
fn remove_stale_temps(path: &Path, prefix: &OsStr, live: &BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(parent_dir(path)) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.as_bytes().starts_with(prefix.as_bytes()) {
            continue;
        }
        let candidate = path.with_file_name(&name);
        if !live.contains(&candidate) {
            let _ = std::fs::remove_file(&candidate);
        }
    }
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn sync_parent_dir(path: &Path) -> io::Result<()> {
    File::open(parent_dir(path))?.sync_all()
}

fn encode_header(registry: &Registry, body: &[u8; 32]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(MAGIC);
    h[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    h[12..20].copy_from_slice(&registry.len.to_le_bytes());
    h[20..52].copy_from_slice(&registry.sha256);
    h[52..84].copy_from_slice(body);
    h
}

/// Loads the snapshot at `path` if it is exactly the finalized registry `expected`; anything
/// else is [`Startup::Rebuild`] (see the [module docs](self)). Never returns a partial cache.
pub fn load_with<C: KeyCodec>(codec: &C, path: &Path, expected: &Registry) -> Startup<C::Key> {
    match read_snapshot(codec, path, expected) {
        Ok(keys) => Startup::Use(PubkeyCache { keys }),
        Err(reason) => Startup::Rebuild(reason),
    }
}

fn unreadable(e: &io::Error) -> RebuildReason {
    RebuildReason::Unreadable(e.to_string())
}

fn read_snapshot<C: KeyCodec>(
    codec: &C,
    path: &Path,
    expected: &Registry,
) -> Result<Vec<C::Key>, RebuildReason> {
    let (mut file, meta) = open_snapshot(path)?;

    let mut header = [0u8; HEADER_LEN];
    let (prefix, rest) = header.split_at_mut(PREFIX_LEN);
    read_header_part(&mut file, prefix)?;
    if prefix[..8] != MAGIC[..] {
        return Err(RebuildReason::BadMagic);
    }
    let version = u32::from_le_bytes(prefix[8..12].try_into().expect("4 bytes"));
    if version != FORMAT_VERSION {
        return Err(RebuildReason::UnknownVersion { version });
    }
    read_header_part(&mut file, rest)?;
    let len = u64::from_le_bytes(header[12..20].try_into().expect("8 bytes"));
    if len != expected.len {
        return Err(RebuildReason::LengthMismatch {
            file: len,
            chain: expected.len,
        });
    }
    if header[20..52] != expected.sha256 {
        return Err(RebuildReason::RootMismatch);
    }
    let size = len
        .checked_mul(UNCOMPRESSED_LEN as u64)
        .and_then(|b| b.checked_add(HEADER_LEN as u64));
    if size != Some(meta.len()) {
        return Err(RebuildReason::SizeMismatch {
            expected: size.unwrap_or(u64::MAX),
            actual: meta.len(),
        });
    }
    let body_digest: [u8; 32] = header[52..84].try_into().expect("32 bytes");
    read_body(codec, &mut file, len, &body_digest, expected)
}

/// Opens the snapshot without following a symlink and without blocking (a FIFO opens at once
/// with `O_NONBLOCK`), then checks the open handle with fstat. The checks therefore apply to the
/// file actually read, and no path swap between a check and the open can make start-up hang.
///
/// `O_NONBLOCK` stays set: it has no effect on reads from a regular file (POSIX `read`), and
/// nothing but a regular file gets past [`check_file`].
fn open_snapshot(path: &Path) -> Result<(File, Metadata), RebuildReason> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(sys::O_NOFOLLOW | sys::O_NONBLOCK)
        .open(path)
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => RebuildReason::Missing,
            // O_NOFOLLOW fails on a symlink (ELOOP); name it rather than decode the errno.
            _ if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) => {
                RebuildReason::NotRegularFile
            }
            _ => unreadable(&e),
        })?;
    let meta = file.metadata().map_err(|e| unreadable(&e))?;
    check_file(&meta)?;
    Ok((file, meta))
}

fn check_file(meta: &Metadata) -> Result<(), RebuildReason> {
    if !meta.file_type().is_file() {
        return Err(RebuildReason::NotRegularFile);
    }
    let expected = effective_uid();
    if meta.uid() != expected {
        return Err(RebuildReason::WrongOwner {
            file: meta.uid(),
            expected,
        });
    }
    let mode = meta.mode() & 0o7777;
    if mode != FILE_MODE {
        return Err(RebuildReason::WrongMode { mode });
    }
    Ok(())
}

fn read_header_part(file: &mut File, buf: &mut [u8]) -> Result<(), RebuildReason> {
    file.read_exact(buf).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => RebuildReason::ShortHeader,
        _ => unreadable(&e),
    })
}

/// Streams the body: hashes every byte, decodes points until one fails, then checks the body
/// digest first and the recomputed registry digest last.
fn read_body<C: KeyCodec>(
    codec: &C,
    file: &mut File,
    len: u64,
    body_digest: &[u8; 32],
    expected: &Registry,
) -> Result<Vec<C::Key>, RebuildReason> {
    let len = usize::try_from(len).map_err(|_| {
        RebuildReason::Unreadable(format!("{len} entries exceed the address space"))
    })?;
    let mut keys = Vec::with_capacity(len);
    let mut body = Sha256::new();
    let mut registry = RegistryHasher::default();
    let mut invalid = None;
    let mut buf = vec![0u8; READ_CHUNK_POINTS * UNCOMPRESSED_LEN];
    let mut left = len;
    while left > 0 {
        let n = left.min(READ_CHUNK_POINTS);
        let chunk = &mut buf[..n * UNCOMPRESSED_LEN];
        file.read_exact(chunk).map_err(|e| unreadable(&e))?;
        body.update(&chunk[..]);
        for point in chunk.as_chunks::<UNCOMPRESSED_LEN>().0 {
            if invalid.is_some() {
                break;
            }
            match codec.decode_uncompressed_unchecked(point) {
                Some(key) => {
                    registry.push(&codec.compressed(&key));
                    keys.push(key);
                }
                None => invalid = Some(keys.len() as u64),
            }
        }
        left -= n;
    }
    if body.finalize()[..] != body_digest[..] {
        return Err(RebuildReason::BodyDigestMismatch);
    }
    if let Some(index) = invalid {
        return Err(RebuildReason::InvalidPoint { index });
    }
    if registry.finish() != *expected {
        return Err(RebuildReason::RootMismatch);
    }
    Ok(keys)
}

/// cl-chain's side of `PubkeyFeed`, as [`startup_with`] consumes it. Both calls block, so run
/// the start-up on a blocking thread.
pub trait RegistryFeed {
    type Key;
    type Error;

    /// Waits for the first feed response: the finalized registry cl-chain will serve.
    /// `Ok(None)` means the feed closed before sending it, a contract violation.
    fn registry(&mut self) -> Result<Option<Registry>, Self::Error>;

    /// Waits for finalized entries `start..start + n`, with `1 <= n <= max`, decoded and
    /// `KeyValidate`d by the caller.
    fn range(&mut self, start: u64, max: usize) -> Result<Vec<Self::Key>, Self::Error>;
}

/// The cache cl-verify serves after start-up.
#[derive(Debug)]
pub struct Restored<K> {
    pub cache: PubkeyCache<K>,
    /// `None`: loaded from the snapshot. `Some`: why the snapshot was not used and the cache
    /// was rebuilt from the feed.
    pub rebuilt: Option<RebuildReason>,
}

/// Start-up failed; there is no cache to serve.
#[derive(Debug, thiserror::Error)]
pub enum StartupError<E> {
    #[error("pubkey feed closed before its first response (contract violation)")]
    MissingRegistry,
    #[error("pubkey feed: {0}")]
    Feed(E),
    #[error("pubkey feed sent no entries at index {start} (contract violation)")]
    EmptyRange { start: u64 },
    #[error("pubkey feed sent {got} entries at index {start}, asked for at most {max} (contract violation)")]
    OversizedRange { start: u64, got: u64, max: u64 },
    #[error("pubkey feed entries do not match the registry it announced (contract violation)")]
    RegistryMismatch,
}

impl<E> StartupError<E> {
    /// Whether cl-chain broke the feed contract (`ERROR_CODE_CONTRACT_VIOLATION`), as opposed to
    /// a transport error.
    pub fn is_contract_violation(&self) -> bool {
        !matches!(self, Self::Feed(_))
    }

    /// Converts the feed error, keeping every other variant (e.g. to a displayable type).
    pub fn map_feed<F>(self, f: impl FnOnce(E) -> F) -> StartupError<F> {
        match self {
            Self::Feed(e) => StartupError::Feed(f(e)),
            Self::MissingRegistry => StartupError::MissingRegistry,
            Self::EmptyRange { start } => StartupError::EmptyRange { start },
            Self::OversizedRange { start, got, max } => {
                StartupError::OversizedRange { start, got, max }
            }
            Self::RegistryMismatch => StartupError::RegistryMismatch,
        }
    }
}

/// Waits for the feed's first response (the finalized registry), then loads the snapshot at
/// `path` if it matches exactly, or else rebuilds the whole cache from index 0 in chunks of at
/// most [`REBUILD_CHUNK_ENTRIES`]. A rebuilt cache is served only if it hashes to the announced
/// registry. The caller persists a rebuilt cache with [`save_with`].
pub fn startup_with<C, F>(
    codec: &C,
    path: &Path,
    feed: &mut F,
) -> Result<Restored<C::Key>, StartupError<F::Error>>
where
    C: KeyCodec,
    F: RegistryFeed<Key = C::Key>,
{
    let registry = feed
        .registry()
        .map_err(StartupError::Feed)?
        .ok_or(StartupError::MissingRegistry)?;
    match load_with(codec, path, &registry) {
        Startup::Use(cache) => Ok(Restored {
            cache,
            rebuilt: None,
        }),
        Startup::Rebuild(reason) => Ok(Restored {
            cache: rebuild(codec, &registry, feed)?,
            rebuilt: Some(reason),
        }),
    }
}

fn rebuild<C, F>(
    codec: &C,
    registry: &Registry,
    feed: &mut F,
) -> Result<PubkeyCache<C::Key>, StartupError<F::Error>>
where
    C: KeyCodec,
    F: RegistryFeed<Key = C::Key>,
{
    let mut keys = Vec::new();
    let mut digest = RegistryHasher::default();
    while digest.len < registry.len {
        let start = digest.len;
        let max = usize::try_from(registry.len - start)
            .unwrap_or(usize::MAX)
            .min(REBUILD_CHUNK_ENTRIES);
        let range = feed.range(start, max).map_err(StartupError::Feed)?;
        if range.is_empty() {
            return Err(StartupError::EmptyRange { start });
        }
        if range.len() > max {
            return Err(StartupError::OversizedRange {
                start,
                got: range.len() as u64,
                max: max as u64,
            });
        }
        for key in range {
            digest.push(&codec.compressed(&key));
            keys.push(key);
        }
    }
    if digest.finish() != *registry {
        return Err(StartupError::RegistryMismatch);
    }
    Ok(PubkeyCache { keys })
}

/// SHA-256 over the concatenated compressed keys.
pub fn root_of(keys: &[Key]) -> [u8; 32] {
    let mut h = Sha256::new();
    for k in keys {
        h.update(k);
    }
    h.finalize().into()
}

/// Writes the version-1 file atomically: temp file, fsync, rename. Legacy; see the
/// [module docs](self).
pub fn save(cache: &PubkeyCache<Key>, path: &Path) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(HEADER + cache.keys.len() * 48);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&cache.high_water().to_le_bytes());
    buf.extend_from_slice(&root_of(&cache.keys));
    for k in &cache.keys {
        buf.extend_from_slice(k);
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&buf)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Reads a version-1 file. Legacy; see the [module docs](self).
pub fn load(path: &Path) -> Result<PubkeyCache<Key>, LoadError> {
    let (_, _, keys) = read_checked(&std::fs::read(path)?)?;
    Ok(PubkeyCache { keys })
}

fn read_checked(b: &[u8]) -> Result<(u64, [u8; 32], Vec<Key>), LoadError> {
    let header = b.get(..HEADER).ok_or(LoadError::BadHeader)?;
    let (magic, rest) = header.split_at(8);
    let (version, rest) = rest.split_at(4);
    let (len, root) = rest.split_at(8);
    if magic != MAGIC || version != VERSION.to_le_bytes() {
        return Err(LoadError::BadHeader);
    }
    let len = u64::from_le_bytes(len.try_into().map_err(|_| LoadError::BadHeader)?);
    let root: [u8; 32] = root.try_into().map_err(|_| LoadError::BadHeader)?;
    let body = &b[HEADER..];
    if usize::try_from(len).ok().and_then(|l| l.checked_mul(48)) != Some(body.len()) {
        return Err(LoadError::Truncated);
    }
    let keys: Vec<Key> = body.as_chunks::<48>().0.to_vec();
    if root_of(&keys) != root {
        return Err(LoadError::RootMismatch);
    }
    Ok((len, root, keys))
}

/// Start-up check of a version-1 file against cl-chain's finalized registry (length and root of
/// its pubkeys). Legacy; [`startup_with`] supersedes it.
pub fn startup(path: &Path, chain_len: u64, chain_root: [u8; 32]) -> Startup {
    match std::fs::read(path)
        .map_err(LoadError::from)
        .and_then(|b| read_checked(&b))
    {
        Err(e) => Startup::Rebuild(RebuildReason::Unreadable(e.to_string())),
        Ok((len, _, _)) if len != chain_len => Startup::Rebuild(RebuildReason::LengthMismatch {
            file: len,
            chain: chain_len,
        }),
        Ok((_, root, _)) if root != chain_root => Startup::Rebuild(RebuildReason::RootMismatch),
        Ok((_, _, keys)) => Startup::Use(PubkeyCache { keys }),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: u8) -> Vec<Key> {
        (0..n).map(|i| [i; 48]).collect()
    }

    fn cache(n: u8) -> PubkeyCache<Key> {
        let mut c = PubkeyCache::new();
        c.append_range(0, keys(n)).unwrap();
        c
    }

    fn saved(n: u8) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pubkeys.bin");
        save(&cache(n), &path).unwrap();
        (dir, path)
    }

    #[test]
    fn save_load_round_trip() {
        let (_dir, path) = saved(5);
        let c = load(&path).unwrap();
        assert_eq!(c.high_water(), 5);
        assert_eq!(c.get(4), crate::Lookup::Known(&[4; 48]));
    }

    #[test]
    fn corrupted_file_is_rejected() {
        let (_dir, path) = saved(5);
        let mut b = std::fs::read(&path).unwrap();
        let last = b.len() - 1;
        b[last] ^= 0xff;
        std::fs::write(&path, b).unwrap();
        assert!(matches!(load(&path), Err(LoadError::RootMismatch)));
        let mut b = std::fs::read(&path).unwrap();
        b[0] ^= 0xff;
        std::fs::write(&path, b).unwrap();
        assert!(matches!(load(&path), Err(LoadError::BadHeader)));
    }

    #[test]
    fn partial_file_is_rejected() {
        let (_dir, path) = saved(5);
        let b = std::fs::read(&path).unwrap();
        for cut in [0, 10, 52, b.len() - 1] {
            std::fs::write(&path, &b[..cut]).unwrap();
            assert!(load(&path).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn startup_uses_matching_file_and_rebuilds_on_mismatch() {
        let (_dir, path) = saved(5);
        let root5 = root_of(&keys(5));
        assert!(matches!(startup(&path, 5, root5), Startup::Use(c) if c.high_water() == 5));
        assert!(matches!(
            startup(&path, 6, root_of(&keys(6))),
            Startup::Rebuild(RebuildReason::LengthMismatch { file: 5, chain: 6 })
        ));
        assert!(matches!(
            startup(&path, 5, [9; 32]),
            Startup::Rebuild(RebuildReason::RootMismatch)
        ));
        std::fs::write(&path, b"junk").unwrap();
        assert!(matches!(
            startup(&path, 5, root5),
            Startup::Rebuild(RebuildReason::Unreadable(_))
        ));
        assert!(matches!(
            startup(&path.with_extension("missing"), 5, root5),
            Startup::Rebuild(RebuildReason::Unreadable(_))
        ));
    }

    /// Byte codec for `[u8; 48]`: uncompressed = key twice; decoding requires both halves equal.
    struct Twice;

    impl KeyCodec for Twice {
        type Key = Key;
        fn compressed(&self, key: &Key) -> [u8; 48] {
            *key
        }
        fn uncompressed(&self, key: &Key) -> [u8; 96] {
            let mut out = [0; 96];
            out[..48].copy_from_slice(key);
            out[48..].copy_from_slice(key);
            out
        }
        fn decode_uncompressed_unchecked(&self, b: &[u8; 96]) -> Option<Key> {
            (b[..48] == b[48..]).then(|| b[..48].try_into().unwrap())
        }
    }

    fn v2_file(path: &Path, registry: &Registry, body: &[u8]) {
        let digest: [u8; 32] = Sha256::digest(body).into();
        let mut b = encode_header(registry, &digest).to_vec();
        b.extend_from_slice(body);
        std::fs::write(path, b).unwrap();
        std::fs::set_permissions(path, Permissions::from_mode(FILE_MODE)).unwrap();
    }

    fn rebuild_reason(path: &Path, expected: &Registry) -> RebuildReason {
        match load_with(&Twice, path, expected) {
            Startup::Rebuild(r) => r,
            Startup::Use(c) => panic!("loaded {} entries", c.high_water()),
        }
    }

    #[test]
    fn v2_layout_is_header_then_uncompressed_points() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pubkeys.bin");
        save_with(&Twice, &cache(3), &path).unwrap();
        let b = std::fs::read(&path).unwrap();
        let registry = Registry::of(&Twice, &keys(3));
        assert_eq!(
            registry.sha256,
            root_of(&keys(3)),
            "same digest as the feed's"
        );
        assert_eq!(&b[..8], MAGIC);
        assert_eq!(b[8..12], 2u32.to_le_bytes());
        assert_eq!(b[12..20], 3u64.to_le_bytes());
        assert_eq!(b[20..52], registry.sha256);
        assert_eq!(b[52..84], Sha256::digest(&b[84..])[..]);
        assert_eq!(b.len(), 84 + 3 * 96);
        assert_eq!(&b[84 + 96..84 + 192], &Twice.uncompressed(&[1; 48]));
    }

    /// A point with the same compressed form (x) as a registry key but another y: the registry
    /// recompute cannot tell it apart, since `compressed(decoded)` is the registry entry. The
    /// codec's on-curve rejection (here: the halves disagree) is what rebuilds.
    #[test]
    fn same_compressed_form_other_point_is_rejected_by_the_codec() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pubkeys.bin");
        let registry = Registry::of(&Twice, &keys(3));
        let mut body: Vec<u8> = keys(3).iter().flat_map(|k| Twice.uncompressed(k)).collect();
        body[96 + 50] ^= 1; // point 1, y half: same x, valid body digest, but off the "curve"
        v2_file(&path, &registry, &body);
        assert_eq!(
            rebuild_reason(&path, &registry),
            RebuildReason::InvalidPoint { index: 1 }
        );
    }

    #[test]
    fn body_that_does_not_hash_to_the_registry_rebuilds() {
        // Header claims the expected registry and the body digest is consistent, but the
        // decoded keys are a different registry: the recomputed digest catches it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pubkeys.bin");
        let registry = Registry::of(&Twice, &keys(3));
        let body: Vec<u8> = [[7u8; 48]; 3]
            .iter()
            .flat_map(|k| Twice.uncompressed(k))
            .collect();
        v2_file(&path, &registry, &body);
        assert_eq!(
            rebuild_reason(&path, &registry),
            RebuildReason::RootMismatch
        );
    }

    #[test]
    fn non_regular_files_and_v1_files_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::of(&Twice, &keys(5));
        assert_eq!(
            rebuild_reason(dir.path(), &registry),
            RebuildReason::NotRegularFile
        );
        let target = dir.path().join("target.bin");
        save_with(&Twice, &cache(5), &target).unwrap();
        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            rebuild_reason(&link, &registry),
            RebuildReason::NotRegularFile
        );
        let v1 = dir.path().join("v1.bin");
        save(&cache(5), &v1).unwrap();
        std::fs::set_permissions(&v1, Permissions::from_mode(FILE_MODE)).unwrap();
        assert_eq!(
            rebuild_reason(&v1, &registry),
            RebuildReason::UnknownVersion { version: 1 }
        );
    }

    #[test]
    fn oversized_feed_range_is_a_contract_violation() {
        struct Greedy;
        impl RegistryFeed for Greedy {
            type Key = Key;
            type Error = String;
            fn registry(&mut self) -> Result<Option<Registry>, String> {
                Ok(Some(Registry::of(&Twice, &[[0; 48], [1; 48]])))
            }
            fn range(&mut self, _: u64, max: usize) -> Result<Vec<Key>, String> {
                Ok(vec![[0; 48]; max + 1])
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let err = startup_with(&Twice, &dir.path().join("none"), &mut Greedy).unwrap_err();
        assert!(matches!(
            err,
            StartupError::OversizedRange {
                start: 0,
                got: 3,
                max: 2
            }
        ));
        assert!(err.is_contract_violation());
    }

    /// `open_snapshot` alone, with no earlier path check: a FIFO or a symlink must come back
    /// as `NotRegularFile` without blocking, so the result cannot depend on a check-then-open
    /// race.
    #[test]
    fn open_snapshot_neither_follows_symlinks_nor_blocks_on_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let regular = dir.path().join("regular.bin");
        save_with(&Twice, &cache(1), &regular).unwrap();
        let (to_fifo, to_regular) = (dir.path().join("l1"), dir.path().join("l2"));
        std::os::unix::fs::symlink(&fifo, &to_fifo).unwrap();
        std::os::unix::fs::symlink(&regular, &to_regular).unwrap();
        for path in [fifo, to_fifo, to_regular] {
            let (tx, rx) = std::sync::mpsc::channel();
            let p = path.clone();
            std::thread::spawn(move || {
                let _ = tx.send(open_snapshot(&p).map(drop));
            });
            let got = rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap_or_else(|_| panic!("open_snapshot blocked on {}", path.display()));
            assert_eq!(
                got,
                Err(RebuildReason::NotRegularFile),
                "{}",
                path.display()
            );
        }
        assert!(open_snapshot(&regular).is_ok());
    }

    #[test]
    fn map_feed_converts_only_the_feed_error() {
        let feed: StartupError<u8> = StartupError::Feed(7);
        assert!(matches!(feed.map_feed(|e| e.to_string()), StartupError::Feed(s) if s == "7"));
        let mismatch: StartupError<u8> = StartupError::RegistryMismatch;
        assert!(matches!(
            mismatch.map_feed(|_| ()),
            StartupError::RegistryMismatch
        ));
        let sized: StartupError<u8> = StartupError::OversizedRange {
            start: 1,
            got: 3,
            max: 2,
        };
        assert_eq!(
            sized.map_feed(|_| "x").to_string(),
            "pubkey feed sent 3 entries at index 1, asked for at most 2 (contract violation)"
        );
        let empty: StartupError<u8> = StartupError::EmptyRange { start: 4 };
        assert!(matches!(
            empty.map_feed(|_| ()),
            StartupError::EmptyRange { start: 4 }
        ));
        let missing: StartupError<u8> = StartupError::MissingRegistry;
        assert!(missing.map_feed(|_| ()).is_contract_violation());
    }

    #[test]
    fn snapshot_path_needs_a_file_name() {
        assert!(save_with(&Twice, &cache(1), Path::new("/")).is_err());
    }
}
