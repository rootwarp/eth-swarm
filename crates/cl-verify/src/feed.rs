//! PubkeyFeed: cl-chain appends the finalized validator registry, in order, to the shared cache.
//!
//! A frame carries entries `start_index .. start_index + count`. `count` must equal the number of
//! keys and be at most [`MAX_KEYS_PER_FRAME`], `start_index` must equal the current high-water
//! mark, and every key must decompress and pass `KeyValidate` from exactly 48 compressed bytes;
//! anything else is `ERROR_CODE_CONTRACT_VIOLATION`, and the frame is not applied at all. Every
//! reply carries the high-water mark so the sender can resend from there.
//!
//! # Restore
//!
//! The first frame of every stream announces cl-chain's finalized registry (length and SHA-256
//! over the compressed keys). A server whose cache has not been restored since it started runs
//! [`restore`] on that frame: it loads the on-disk snapshot if it holds exactly that registry, and
//! otherwise rebuilds the whole cache from index 0 over the stream, in frames of at most
//! [`MAX_KEYS_PER_FRAME`]. After a restore, a rebuild or any append marks the snapshot dirty, and
//! the [`SnapshotWriter`] saves it at most once per interval and on shutdown. The shared cache stays empty until the restore has
//! finished and verified, so VerifyBls never sees part of a registry: until then every index is
//! `VERIFY_STATUS_UNKNOWN_INDEX`. Any error during the restore fails the stream, keeps nothing, and
//! the next stream restores again. A restored server only checks the announcement
//! ([`check_first_frame`]).

use std::any::Any;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use blst::min_pk::PublicKey;
use cl_verify_cache::persist::{
    save_with, startup_with, KeyCodec, RebuildReason, Registry, RegistryFeed, StartupError,
    COMPRESSED_LEN, REBUILD_CHUNK_ENTRIES, UNCOMPRESSED_LEN,
};
use cl_verify_cache::PubkeyCache;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, Notify};
use tokio::task::spawn_blocking;
use tokio_stream::Stream;
use tonic::Status;

use crate::bls::decode_pubkey;
use crate::frame::{Inbound, OutFrame};
use crate::metrics::check_epochs;
use crate::proto::common::{Error, ErrorCode};
use crate::proto::verify::{
    PubkeyFeedRequest, PubkeyFeedRequestBody, PubkeyFeedResponse, PubkeyFeedResponseBody,
};
use crate::wire::wire_error;

/// The finalized pubkey cache shared by the feed (writer) and BLS verification (readers).
pub type SharedCache = Arc<RwLock<PubkeyCache<PublicKey>>>;

/// Most keys one feed frame may carry: the snapshot rebuild chunk.
pub const MAX_KEYS_PER_FRAME: usize = REBUILD_CHUNK_ENTRIES;

/// The snapshot codec for blst keys. Keys enter the cache only through [`decode_pubkey`]
/// (`KeyValidate`), so a reload skips decompression and the subgroup check: the 96-byte form is
/// decoded with `from_bytes`, which still rejects a point that is not on the curve.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlstCodec;

impl KeyCodec for BlstCodec {
    type Key = PublicKey;

    fn compressed(&self, key: &PublicKey) -> [u8; COMPRESSED_LEN] {
        key.compress()
    }

    fn uncompressed(&self, key: &PublicKey) -> [u8; UNCOMPRESSED_LEN] {
        key.serialize()
    }

    fn decode_uncompressed_unchecked(&self, bytes: &[u8; UNCOMPRESSED_LEN]) -> Option<PublicKey> {
        // blst `deserialize` of the uncompressed form: on-curve check, no subgroup check.
        PublicKey::from_bytes(bytes).ok()
    }
}

/// The current high-water mark, as sent right after the hello.
pub fn status(cache: &RwLock<PubkeyCache<PublicKey>>) -> PubkeyFeedResponseBody {
    PubkeyFeedResponseBody {
        high_water: high_water(cache),
        err: None,
    }
}

/// Applies one feed frame and returns the reply. Keys are decoded and validated before the write
/// lock is taken, so readers are blocked only for the append itself.
pub fn apply(
    cache: &RwLock<PubkeyCache<PublicKey>>,
    body: &PubkeyFeedRequestBody,
) -> PubkeyFeedResponseBody {
    let result = check_and_decode(cache, body).and_then(|keys| {
        let mut guard = cache.write().map_err(|_| poisoned())?;
        guard
            .append_range(body.start_index, keys)
            .map_err(|e| violation(&e.to_string()))
    });
    PubkeyFeedResponseBody {
        high_water: high_water(cache),
        err: result.err(),
    }
}

fn check_and_decode(
    cache: &RwLock<PubkeyCache<PublicKey>>,
    body: &PubkeyFeedRequestBody,
) -> Result<Vec<PublicKey>, Error> {
    check_count(body)?;
    // Cheap early check; append_range re-checks under the write lock.
    let expected = high_water(cache);
    if body.start_index != expected {
        return Err(violation(&format!(
            "start_index {} != high_water {expected}",
            body.start_index
        )));
    }
    decode_keys(body)
}

fn check_count(body: &PubkeyFeedRequestBody) -> Result<(), Error> {
    if usize::try_from(body.count).ok() != Some(body.pubkeys.len()) {
        return Err(violation(&format!(
            "count {} != {} pubkeys",
            body.count,
            body.pubkeys.len()
        )));
    }
    if body.pubkeys.len() > MAX_KEYS_PER_FRAME {
        return Err(violation(&format!(
            "{} pubkeys exceed the cap of {MAX_KEYS_PER_FRAME} per frame",
            body.pubkeys.len()
        )));
    }
    Ok(())
}

fn decode_keys(body: &PubkeyFeedRequestBody) -> Result<Vec<PublicKey>, Error> {
    body.pubkeys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            decode_pubkey(k).ok_or_else(|| {
                violation(&format!(
                    "pubkey {} is not a valid 48-byte compressed key",
                    body.start_index + i as u64
                ))
            })
        })
        .collect()
}

/// The registry a first frame announces. Missing, a length of 0 or a sha256 that is not 32 bytes
/// is a contract violation.
fn announced(body: &PubkeyFeedRequestBody) -> Result<Registry, Error> {
    let r = body
        .finalized_registry
        .as_ref()
        .ok_or_else(|| violation("first feed frame carries no finalized_registry"))?;
    if r.len == 0 {
        return Err(violation("finalized_registry.len is 0"));
    }
    let sha256 = r.sha256.as_slice().try_into().map_err(|_| {
        violation(&format!(
            "finalized_registry.sha256 is {} bytes, not 32",
            r.sha256.len()
        ))
    })?;
    Ok(Registry { len: r.len, sha256 })
}

/// The first-frame check on a stream to an already restored server: the registry is announced,
/// and it is not shorter than the cache (which holds finalized entries only).
pub fn check_first_frame(
    cache: &RwLock<PubkeyCache<PublicKey>>,
    body: &PubkeyFeedRequestBody,
) -> Result<(), Error> {
    let registry = announced(body)?;
    let held = high_water(cache);
    if registry.len < held {
        return Err(violation(&format!(
            "finalized registry of {} entries is shorter than the {held} cached",
            registry.len
        )));
    }
    Ok(())
}

/// One PubkeyFeed stream as [`restore`] drives it, from a blocking thread.
pub trait FeedLink {
    /// The next body frame; `None` once cl-chain has closed its side.
    fn recv(&mut self) -> Result<Option<PubkeyFeedRequestBody>, Error>;
    /// Sends one reply body.
    fn send(&mut self, reply: PubkeyFeedResponseBody) -> Result<(), Error>;
}

/// How the cache was restored.
#[derive(Debug, PartialEq, Eq)]
pub enum Restored {
    /// From the snapshot, which held exactly the announced registry.
    Loaded,
    /// From the feed, because the snapshot could not be used (why), then saved.
    Rebuilt(RebuildReason),
}

/// The finalized epochs a feed frame carries (see [`crate::metrics`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameEpochs {
    pub feed_finalized_epoch: u64,
    pub chain_finalized_epoch: u64,
}

impl FrameEpochs {
    #[must_use]
    pub fn of(body: &PubkeyFeedRequestBody) -> Self {
        Self {
            feed_finalized_epoch: body.feed_finalized_epoch,
            chain_finalized_epoch: body.chain_finalized_epoch,
        }
    }
}

/// Restores `cache` (empty, not yet served) from the stream's first frame: loads `snapshot` if it
/// holds exactly the announced registry, or else rebuilds from index 0 over `link`. The cache is
/// replaced only on success. Errors are contract violations (or the link's own error); nothing is
/// kept. The caller sends the reply to the last frame and saves a rebuilt cache (the server marks
/// its [`SnapshotWriter`] dirty).
///
/// Every restore frame's epochs must pass [`check_epochs`] against the previous frame's chain
/// epoch. On success, returns the epochs of the frame whose reply completes the restore: the
/// announcing frame for a loaded snapshot, the last rebuild frame otherwise.
pub fn restore<L: FeedLink>(
    cache: &RwLock<PubkeyCache<PublicKey>>,
    snapshot: &Path,
    link: &mut L,
) -> Result<(Restored, FrameEpochs), Error> {
    let mut feed = FrameFeed {
        link,
        pending: None,
        last: None,
    };
    let restored = startup_with(&BlstCodec, snapshot, &mut feed).map_err(|e| match e {
        StartupError::Feed(e) => e,
        other => violation(&other.map_feed(|e| e.detail).to_string()),
    })?;
    let epochs = feed.last.unwrap_or_default();
    *cache.write().map_err(|_| poisoned())? = restored.cache;
    let restored = restored.rebuilt.map_or(Restored::Loaded, Restored::Rebuilt);
    Ok((restored, epochs))
}

/// Floor on the wait before retrying a failed save, so a zero interval cannot spin on a broken
/// disk.
const MIN_SAVE_RETRY: Duration = Duration::from_secs(1);

/// Writes one snapshot of the cache to the path. The production saver is [`save_with`] with
/// [`BlstCodec`]; tests inject slow or failing ones.
pub type Saver = Arc<dyn Fn(&PubkeyCache<PublicKey>, &Path) -> io::Result<()> + Send + Sync>;

/// Keeps the on-disk snapshot current after a restore.
///
/// [`mark_dirty`](Self::mark_dirty) records that the cache has entries the snapshot lacks (a
/// rebuild, or a feed append). A background saver ([`start`](Self::start)) then writes it at most
/// once per `interval`: the first dirty mark after a quiet period is written at once, later ones
/// wait until `interval` has passed since the last save. Nothing is marked dirty before the cache
/// is restored, so an unrestored (empty) cache is never written over a good snapshot.
///
/// Each save runs entirely on a blocking thread: it takes the save lock, clears the dirty mark,
/// copies the cache under its read lock (VerifyBls readers are not blocked; a feed append waits
/// only for the copy, not the write), writes the copy through the atomic stage-and-commit path,
/// and records the outcome. Cancelling the caller (e.g. a timeout around
/// [`save_if_dirty`](Self::save_if_dirty)) does not cut that short, so saves never overlap and a
/// failure is always recorded. Saves are monotonic: a copy shorter than the last committed
/// snapshot is never written. A failed save is logged, leaves the snapshot dirty and is retried
/// after `max(interval, 1 s)`; it is never fatal. A saver that panics counts as a failed save.
pub struct SnapshotWriter {
    interval: Duration,
    wake: Arc<Notify>,
    started: AtomicBool,
    state: Arc<SaveState>,
}

struct SaveState {
    path: PathBuf,
    saver: Saver,
    dirty: AtomicBool,
    /// Held for a whole save; the length of the last committed snapshot, if known.
    committed: std::sync::Mutex<Option<u64>>,
    saves: AtomicU64,
    failures: AtomicU64,
}

impl SaveState {
    /// One save, start to finish, on the calling (blocking) thread.
    fn save(&self, cache: &RwLock<PubkeyCache<PublicKey>>) -> io::Result<bool> {
        let mut committed = self
            .committed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !self.dirty.swap(false, Ordering::SeqCst) {
            return Ok(false);
        }
        let copy = cache.read().unwrap_or_else(PoisonError::into_inner).clone();
        let len = copy.high_water();
        if committed.is_some_and(|last| len < last) {
            tracing::warn!(len, last = ?*committed, "pubkey snapshot not rolled back");
            return Ok(false);
        }
        // A panicking saver is a failed save, recorded here: a cancelled caller never sees the
        // blocking job's outcome.
        let saved = panic::catch_unwind(AssertUnwindSafe(|| (self.saver)(&copy, &self.path)))
            .unwrap_or_else(|payload| Err(io::Error::other(panic_message(&*payload))));
        match saved {
            Ok(()) => {
                *committed = Some(len);
                self.saves.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            }
            Err(e) => {
                self.failed(&e);
                Err(e)
            }
        }
    }

    fn failed(&self, e: &io::Error) {
        self.dirty.store(true, Ordering::SeqCst);
        self.failures.fetch_add(1, Ordering::Relaxed);
        tracing::error!(error = %e, path = %self.path.display(), "pubkey snapshot not saved; will retry");
    }
}

/// The message of a caught panic, for the failed-save log.
fn panic_message(payload: &(dyn Any + Send)) -> String {
    let message = payload
        .downcast_ref::<&str>()
        .map(|m| (*m).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned());
    format!("pubkey snapshot saver panicked: {message}")
}

impl SnapshotWriter {
    /// A writer that saves with [`save_with`] and [`BlstCodec`].
    #[must_use]
    pub fn new(path: PathBuf, interval: Duration) -> Self {
        Self::with_saver(
            path,
            interval,
            Arc::new(|cache: &PubkeyCache<PublicKey>, path: &Path| {
                save_with(&BlstCodec, cache, path)
            }),
        )
    }

    #[must_use]
    pub fn with_saver(path: PathBuf, interval: Duration, saver: Saver) -> Self {
        Self {
            interval,
            wake: Arc::new(Notify::new()),
            started: AtomicBool::new(false),
            state: Arc::new(SaveState {
                path,
                saver,
                dirty: AtomicBool::new(false),
                committed: std::sync::Mutex::new(None),
                saves: AtomicU64::new(0),
                failures: AtomicU64::new(0),
            }),
        }
    }

    /// The snapshot file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.state.path
    }

    /// The cache holds entries the snapshot does not.
    pub fn mark_dirty(&self) {
        self.state.dirty.store(true, Ordering::SeqCst);
        self.wake.notify_one();
    }

    /// The snapshot on disk holds `len` entries (it was just loaded); no save may go below it.
    pub fn note_committed(&self, len: u64) {
        *self
            .state
            .committed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(len);
    }

    /// Snapshots written so far.
    #[must_use]
    pub fn saves(&self) -> u64 {
        self.state.saves.load(Ordering::Relaxed)
    }

    /// Saves that failed so far.
    #[must_use]
    pub fn failures(&self) -> u64 {
        self.state.failures.load(Ordering::Relaxed)
    }

    /// Writes the snapshot now if it is dirty: `Ok(true)` if written, `Ok(false)` if clean (or
    /// the copy would be shorter than the snapshot on disk). A failure leaves it dirty. The save
    /// runs to completion on a blocking thread even if this future is dropped.
    pub async fn save_if_dirty(&self, cache: &SharedCache) -> io::Result<bool> {
        let (state, cache) = (Arc::clone(&self.state), Arc::clone(cache));
        let job = spawn_blocking(move || state.save(&cache));
        match job.await {
            Ok(saved) => saved,
            Err(join) => {
                // The save job panicked outside the saver (which `save` catches): record it like
                // any failed save.
                let e = io::Error::other(join.to_string());
                self.state.failed(&e);
                Err(e)
            }
        }
    }

    /// Starts the background saver for `cache`, once; later calls do nothing. The saver holds
    /// only weak references between saves and ends when the writer or the cache is dropped.
    pub fn start(self: &Arc<Self>, cache: &SharedCache) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let (writer, cache, wake) = (
            Arc::downgrade(self),
            Arc::downgrade(cache),
            Arc::clone(&self.wake),
        );
        tokio::spawn(async move {
            loop {
                let Some(w) = writer.upgrade() else { return };
                if !w.state.dirty.load(Ordering::SeqCst) {
                    drop(w);
                    wake.notified().await;
                    continue;
                }
                let Some(c) = cache.upgrade() else { return };
                let wait = match w.save_if_dirty(&c).await {
                    Ok(_) => w.interval,
                    Err(_) => w.interval.max(MIN_SAVE_RETRY),
                };
                drop((w, c));
                tokio::time::sleep(wait).await;
            }
        });
    }
}

impl Drop for SnapshotWriter {
    fn drop(&mut self) {
        // Wakes a parked saver so it sees the writer gone and ends.
        self.wake.notify_one();
    }
}

/// Adapts the push-style stream to [`RegistryFeed`]: each requested range is asked for by a
/// reply carrying its start, except the first, which is the announcing frame itself.
struct FrameFeed<'a, L> {
    link: &'a mut L,
    pending: Option<PubkeyFeedRequestBody>,
    /// The epochs of the last frame received.
    last: Option<FrameEpochs>,
}

impl<L> FrameFeed<'_, L> {
    /// Checks `frame`'s epochs against the previous frame's and records them.
    fn note_epochs(&mut self, frame: &PubkeyFeedRequestBody) -> Result<(), Error> {
        let epochs = FrameEpochs::of(frame);
        check_epochs(
            epochs.feed_finalized_epoch,
            epochs.chain_finalized_epoch,
            self.last.map(|e| e.chain_finalized_epoch),
        )
        .map_err(|e| violation(&format!("restore frame: {e}")))?;
        self.last = Some(epochs);
        Ok(())
    }
}

impl<L: FeedLink> RegistryFeed for FrameFeed<'_, L> {
    type Key = PublicKey;
    type Error = Error;

    fn registry(&mut self) -> Result<Option<Registry>, Error> {
        let Some(first) = self.link.recv()? else {
            return Ok(None);
        };
        let registry = announced(&first)?;
        self.note_epochs(&first)?;
        if first.start_index != 0 {
            return Err(violation(&format!(
                "first feed frame starts at {}, high_water is 0",
                first.start_index
            )));
        }
        check_count(&first)?;
        self.pending = Some(first);
        Ok(Some(registry))
    }

    fn range(&mut self, start: u64, max: usize) -> Result<Vec<PublicKey>, Error> {
        let frame = match self.pending.take() {
            Some(first) => first,
            None => {
                self.link.send(PubkeyFeedResponseBody {
                    high_water: start,
                    err: None,
                })?;
                let next = self.link.recv()?.ok_or_else(|| {
                    violation(&format!("feed closed during the rebuild, at index {start}"))
                })?;
                self.note_epochs(&next)?;
                next
            }
        };
        if frame.start_index != start {
            return Err(violation(&format!(
                "rebuild frame starts at {}, expected {start}",
                frame.start_index
            )));
        }
        check_count(&frame)?;
        if frame.pubkeys.len() > max {
            return Err(violation(&format!(
                "rebuild frame at {start} carries {} keys, past the announced registry ({max} left)",
                frame.pubkeys.len()
            )));
        }
        decode_keys(&frame)
    }
}

/// A server-side PubkeyFeed stream used from a blocking thread (see [`FeedLink`]). Each read and
/// each reply is bounded by `frame_timeout`: a peer that stalls during a restore is a contract
/// violation, and the restore (with its permit and the restore lock) is released.
pub struct StreamLink<S> {
    inbound: Inbound<S>,
    tx: mpsc::Sender<Result<PubkeyFeedResponse, Status>>,
    runtime: Handle,
    frame_timeout: Duration,
}

impl<S> StreamLink<S> {
    pub fn new(
        inbound: Inbound<S>,
        tx: mpsc::Sender<Result<PubkeyFeedResponse, Status>>,
        runtime: Handle,
        frame_timeout: Duration,
    ) -> Self {
        Self {
            inbound,
            tx,
            runtime,
            frame_timeout,
        }
    }

    pub fn into_inbound(self) -> Inbound<S> {
        self.inbound
    }
}

impl<S> FeedLink for StreamLink<S>
where
    S: Stream<Item = Result<PubkeyFeedRequest, Status>> + Unpin,
{
    fn recv(&mut self) -> Result<Option<PubkeyFeedRequestBody>, Error> {
        let (t, inbound) = (self.frame_timeout, &mut self.inbound);
        // The timer is created inside the runtime: this thread may not be in its context.
        let next = async move { tokio::time::timeout(t, inbound.body()).await };
        self.runtime.block_on(next).unwrap_or_else(|_| {
            Err(violation(&format!(
                "no pubkey feed frame within {:?} during the restore",
                self.frame_timeout
            )))
        })
    }

    fn send(&mut self, reply: PubkeyFeedResponseBody) -> Result<(), Error> {
        let (t, tx) = (self.frame_timeout, &self.tx);
        let sent = async move {
            tokio::time::timeout(t, tx.send(Ok(PubkeyFeedResponse::body(reply)))).await
        };
        match self.runtime.block_on(sent) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(wire_error(
                ErrorCode::ResourceUnavailable,
                "pubkey feed stream closed during the restore",
            )),
            Err(_) => Err(violation(&format!(
                "pubkey feed peer read no reply within {:?} during the restore",
                self.frame_timeout
            ))),
        }
    }
}

fn high_water(cache: &RwLock<PubkeyCache<PublicKey>>) -> u64 {
    cache
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .high_water()
}

fn violation(detail: &str) -> Error {
    wire_error(ErrorCode::ContractViolation, detail)
}

fn poisoned() -> Error {
    wire_error(ErrorCode::ResourceUnavailable, "pubkey cache unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::SecretKey;

    fn key(i: u64) -> Vec<u8> {
        let mut ikm = [3u8; 32];
        ikm[..8].copy_from_slice(&i.to_le_bytes());
        SecretKey::key_gen(&ikm, &[])
            .unwrap()
            .sk_to_pk()
            .compress()
            .to_vec()
    }

    fn body(start: u64, keys: impl IntoIterator<Item = u64>) -> PubkeyFeedRequestBody {
        let pubkeys: Vec<Vec<u8>> = keys.into_iter().map(key).collect();
        PubkeyFeedRequestBody {
            start_index: start,
            count: pubkeys.len() as u64,
            pubkeys,
            finalized_registry: None,
            feed_finalized_epoch: 0,
            chain_finalized_epoch: 0,
        }
    }

    fn code(r: &PubkeyFeedResponseBody) -> Option<ErrorCode> {
        r.err.as_ref().map(Error::code)
    }

    #[test]
    fn appends_in_order_and_reports_the_high_water_mark() {
        let cache = SharedCache::default();
        assert_eq!(status(&cache).high_water, 0);
        let r = apply(&cache, &body(0, 0..3));
        assert_eq!((r.high_water, code(&r)), (3, None));
        let r = apply(&cache, &body(3, 3..5));
        assert_eq!((r.high_water, code(&r)), (5, None));
        assert_eq!(
            status(&cache),
            PubkeyFeedResponseBody {
                high_water: 5,
                err: None
            }
        );
    }

    #[test]
    fn count_must_equal_the_number_of_keys() {
        let cache = SharedCache::default();
        for count in [2, 4, 0] {
            let mut b = body(0, 0..3);
            b.count = count;
            let r = apply(&cache, &b);
            assert_eq!(
                (r.high_water, code(&r)),
                (0, Some(ErrorCode::ContractViolation))
            );
        }
    }

    #[test]
    fn gap_and_overlap_are_contract_violations() {
        let cache = SharedCache::default();
        apply(&cache, &body(0, 0..3));
        for start in [2, 4] {
            let r = apply(&cache, &body(start, 10..12));
            assert_eq!(
                (r.high_water, code(&r)),
                (3, Some(ErrorCode::ContractViolation))
            );
        }
    }

    #[test]
    fn one_invalid_key_rejects_the_whole_frame() {
        let cache = SharedCache::default();
        let mut b = body(0, 0..3);
        b.pubkeys[1] = vec![0xaa; 48];
        let r = apply(&cache, &b);
        assert_eq!(
            (r.high_water, code(&r)),
            (0, Some(ErrorCode::ContractViolation))
        );
        let mut infinity = body(0, 0..1);
        infinity.pubkeys[0] = [&[0xc0u8][..], &[0u8; 47][..]].concat();
        assert_eq!(
            code(&apply(&cache, &infinity)),
            Some(ErrorCode::ContractViolation)
        );
    }

    #[test]
    fn uncompressed_key_is_refused() {
        let cache = SharedCache::default();
        let mut b = body(0, 0..2);
        let mut ikm = [3u8; 32];
        ikm[..8].copy_from_slice(&1u64.to_le_bytes());
        b.pubkeys[1] = SecretKey::key_gen(&ikm, &[])
            .unwrap()
            .sk_to_pk()
            .serialize()
            .to_vec();
        assert_eq!(b.pubkeys[1].len(), 96);
        let r = apply(&cache, &b);
        assert_eq!(
            (r.high_water, code(&r)),
            (0, Some(ErrorCode::ContractViolation))
        );
    }

    #[test]
    fn poisoned_cache_refuses_the_frame() {
        let cache = SharedCache::default();
        let c2 = Arc::clone(&cache);
        let _ = std::thread::spawn(move || {
            let _g = c2.write().unwrap();
            panic!("poison");
        })
        .join();
        let r = apply(&cache, &body(0, 0..1));
        assert_eq!(code(&r), Some(ErrorCode::ResourceUnavailable));
    }

    #[test]
    fn empty_frame_at_the_mark_is_a_no_op() {
        let cache = SharedCache::default();
        let r = apply(&cache, &body(0, []));
        assert_eq!((r.high_water, code(&r)), (0, None));
    }

    // Snapshot restore on the first frame.

    use cl_verify_cache::persist::{load_with, save_with, Registry, Startup};
    use std::collections::VecDeque;

    use crate::proto::verify::FinalizedRegistry;

    /// cl-chain's side as a script: frames to deliver, and the replies cl-verify sent.
    #[derive(Default)]
    struct Script {
        frames: VecDeque<PubkeyFeedRequestBody>,
        replies: Vec<u64>,
    }

    impl FeedLink for Script {
        fn recv(&mut self) -> Result<Option<PubkeyFeedRequestBody>, Error> {
            Ok(self.frames.pop_front())
        }
        fn send(&mut self, reply: PubkeyFeedResponseBody) -> Result<(), Error> {
            self.replies.push(reply.high_water);
            Ok(())
        }
    }

    fn keys(n: u64) -> Vec<PublicKey> {
        (0..n)
            .map(|i| PublicKey::key_validate(&key(i)).unwrap())
            .collect()
    }

    fn registry(n: u64) -> FinalizedRegistry {
        let r = Registry::of(&BlstCodec, &keys(n));
        FinalizedRegistry {
            len: r.len,
            sha256: r.sha256.to_vec(),
        }
    }

    fn announcing(mut b: PubkeyFeedRequestBody, n: u64) -> PubkeyFeedRequestBody {
        b.finalized_registry = Some(registry(n));
        b
    }

    /// Frames for a rebuild of `0..n` in chunks of `chunk`, the first one announcing the registry.
    fn rebuild_frames(n: u64, chunk: u64) -> VecDeque<PubkeyFeedRequestBody> {
        let mut frames: VecDeque<_> = (0..n)
            .step_by(chunk as usize)
            .map(|s| body(s, s..(s + chunk).min(n)))
            .collect();
        let first = frames.pop_front().unwrap();
        frames.push_front(announcing(first, n));
        frames
    }

    fn snapshot_of(n: u64) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pubkeys.bin");
        let mut c = PubkeyCache::new();
        c.append_range(0, keys(n)).unwrap();
        save_with(&BlstCodec, &c, &path).unwrap();
        (dir, path)
    }

    fn cached_keys(cache: &RwLock<PubkeyCache<PublicKey>>) -> Vec<Vec<u8>> {
        let c = cache.read().unwrap();
        (0..c.high_water())
            .map(|i| match c.get(i) {
                cl_verify_cache::Lookup::Known(k) => k.compress().to_vec(),
                cl_verify_cache::Lookup::Unknown => unreachable!(),
            })
            .collect()
    }

    #[test]
    fn blst_codec_round_trips_and_rejects_points_off_the_curve() {
        let k = keys(1).remove(0);
        assert_eq!(BlstCodec.compressed(&k), k.compress());
        let u = BlstCodec.uncompressed(&k);
        assert_eq!(u, k.serialize());
        assert_eq!(BlstCodec.decode_uncompressed_unchecked(&u), Some(k));
        let mut off = u;
        off[95] ^= 1; // same x, another y: not on the curve
        assert_eq!(BlstCodec.decode_uncompressed_unchecked(&off), None);
    }

    #[test]
    fn matching_snapshot_is_loaded_and_the_first_frame_is_not_applied() {
        let (_dir, path) = snapshot_of(5);
        let cache = SharedCache::default();
        let mut link = Script {
            frames: [announcing(body(0, 0..2), 5)].into(),
            ..Script::default()
        };
        assert_eq!(
            restore(&cache, &path, &mut link),
            Ok((Restored::Loaded, FrameEpochs::default()))
        );
        assert_eq!(cached_keys(&cache), (0..5).map(key).collect::<Vec<_>>());
        assert!(
            link.replies.is_empty(),
            "the server replies after the restore"
        );
    }

    #[test]
    fn mismatching_snapshot_is_rebuilt_in_order() {
        let (_dir, path) = snapshot_of(5);
        let cache = SharedCache::default();
        let mut link = Script {
            frames: rebuild_frames(7, 3),
            ..Script::default()
        };
        let (outcome, _) = restore(&cache, &path, &mut link).unwrap();
        assert!(matches!(
            outcome,
            Restored::Rebuilt(RebuildReason::LengthMismatch { file: 5, chain: 7 })
        ));
        assert_eq!(link.replies, [3, 6], "each reply asks for the next range");
        assert_eq!(cached_keys(&cache), (0..7).map(key).collect::<Vec<_>>());
        let r = Registry::of(&BlstCodec, &keys(5));
        assert!(
            matches!(load_with(&BlstCodec, &path, &r), Startup::Use(_)),
            "restore leaves saving to the caller"
        );
    }

    fn at(mut b: PubkeyFeedRequestBody, feed: u64, chain: u64) -> PubkeyFeedRequestBody {
        b.feed_finalized_epoch = feed;
        b.chain_finalized_epoch = chain;
        b
    }

    #[test]
    fn a_restore_reports_the_epochs_of_the_frame_that_completes_it() {
        let epochs = |feed, chain| FrameEpochs {
            feed_finalized_epoch: feed,
            chain_finalized_epoch: chain,
        };
        // Loaded: the announcing frame completes it.
        let (_dir, path) = snapshot_of(5);
        let mut link = Script {
            frames: [at(announcing(body(0, []), 5), 95, 100)].into(),
            ..Script::default()
        };
        let (_, reported) = restore(&SharedCache::default(), &path, &mut link).unwrap();
        assert_eq!(reported, epochs(95, 100));
        // Rebuilt: the last rebuild frame does, at the chain's finality by then.
        let mut frames = rebuild_frames(7, 3);
        for (frame, chain) in frames.iter_mut().zip([99, 100, 101]) {
            *frame = at(frame.clone(), 95, chain);
        }
        let mut link = Script {
            frames,
            ..Script::default()
        };
        let (_, reported) = restore(&SharedCache::default(), &path, &mut link).unwrap();
        assert_eq!(reported, epochs(95, 101));
    }

    #[test]
    fn restore_frames_with_impossible_epochs_are_contract_violations() {
        // The feed ahead of the chain, on the first frame and on a later one.
        violation_of([at(announcing(body(0, 0..2), 2), 101, 100)].into());
        let mut ahead = rebuild_frames(4, 2);
        ahead[1] = at(ahead[1].clone(), 101, 100);
        violation_of(ahead);
        // Finality moving back between restore frames.
        let mut back = rebuild_frames(4, 2);
        back[0] = at(back[0].clone(), 95, 100);
        back[1] = at(back[1].clone(), 95, 99);
        violation_of(back);
    }

    fn violation_of(frames: VecDeque<PubkeyFeedRequestBody>) -> String {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pubkeys.bin");
        let cache = SharedCache::default();
        let mut link = Script {
            frames,
            ..Script::default()
        };
        let err = restore(&cache, &path, &mut link).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation, "{}", err.detail);
        assert_eq!(cache.read().unwrap().high_water(), 0, "nothing is served");
        assert!(!path.exists(), "nothing is saved");
        err.detail
    }

    #[test]
    fn a_missing_or_malformed_registry_is_a_contract_violation() {
        violation_of(VecDeque::new());
        violation_of([body(0, 0..2)].into());
        let mut zero = announcing(body(0, 0..2), 2);
        zero.finalized_registry.as_mut().unwrap().len = 0;
        violation_of([zero].into());
        let mut short = announcing(body(0, 0..2), 2);
        short.finalized_registry.as_mut().unwrap().sha256.pop();
        violation_of([short].into());
    }

    #[test]
    fn a_bad_rebuild_frame_is_a_contract_violation_and_nothing_is_kept() {
        // First frame not at 0.
        violation_of([announcing(body(1, 1..3), 3)].into());
        // Later frame at the wrong index.
        violation_of([announcing(body(0, 0..2), 4), body(3, 3..4)].into());
        // A key that fails KeyValidate.
        let mut bad = rebuild_frames(4, 2);
        bad[1].pubkeys[0] = vec![0xaa; 48];
        violation_of(bad);
        // count != len(pubkeys).
        let mut miscounted = rebuild_frames(4, 2);
        miscounted[1].count = 3;
        violation_of(miscounted);
        // More than asked for: past the registry.
        violation_of([announcing(body(0, 0..3), 2)].into());
        // Keys that do not hash to the announced registry.
        let mut other = rebuild_frames(4, 2);
        other[1] = body(2, 10..12);
        violation_of(other);
        // The stream ends mid-rebuild.
        violation_of([announcing(body(0, 0..2), 4)].into());
    }

    #[test]
    fn more_than_4096_keys_in_one_frame_is_refused() {
        assert_eq!(MAX_KEYS_PER_FRAME, 4_096);
        let cache = SharedCache::default();
        let mut b = body(0, 0..1);
        b.pubkeys = vec![key(0); MAX_KEYS_PER_FRAME + 1];
        b.count = b.pubkeys.len() as u64;
        let r = apply(&cache, &b);
        assert_eq!(
            (r.high_water, code(&r)),
            (0, Some(ErrorCode::ContractViolation))
        );
    }

    #[test]
    fn a_restored_cache_checks_only_the_registry_on_the_first_frame() {
        let cache = SharedCache::default();
        cache.write().unwrap().append_range(0, keys(3)).unwrap();
        assert_eq!(
            check_first_frame(&cache, &announcing(body(3, 3..4), 4)),
            Ok(())
        );
        assert_eq!(
            check_first_frame(&cache, &announcing(body(3, 3..3), 3)),
            Ok(())
        );
        for b in [body(3, 3..4), announcing(body(3, 3..4), 2)] {
            assert_eq!(
                check_first_frame(&cache, &b).unwrap_err().code(),
                ErrorCode::ContractViolation
            );
        }
    }

    // Restore-time error classification over a real stream link.

    use crate::proto::verify::pubkey_feed_request;

    #[allow(clippy::result_large_err)] // a tonic stream item
    fn req(b: PubkeyFeedRequestBody) -> Result<PubkeyFeedRequest, Status> {
        Ok(PubkeyFeedRequest {
            frame: Some(pubkey_feed_request::Frame::Body(b)),
        })
    }

    /// Restores over a `StreamLink` reading `items`, from a plain (non-runtime) thread as the
    /// server's blocking job does, and returns the error code.
    fn restore_code_over(
        items: Vec<Result<PubkeyFeedRequest, Status>>,
        then_stall: bool,
        frame_timeout: Duration,
    ) -> ErrorCode {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let stream = tokio_stream::StreamExt::chain(
            tokio_stream::iter(items),
            tokio_stream::StreamExt::take(
                tokio_stream::pending::<Result<PubkeyFeedRequest, Status>>(),
                usize::from(then_stall),
            ),
        );
        let mut link =
            StreamLink::new(Inbound::new(stream), tx, rt.handle().clone(), frame_timeout);
        let dir = tempfile::tempdir().unwrap();
        let cache = SharedCache::default();
        let err = restore(&cache, &dir.path().join("pubkeys.bin"), &mut link).unwrap_err();
        assert_eq!(cache.read().unwrap().high_water(), 0);
        err.code()
    }

    /// The status a tonic server stream yields for a request message whose bytes are `payload`:
    /// one gRPC frame (uncompressed flag, big-endian length, payload) through `ProstCodec`.
    fn decode_failure(payload: &[u8]) -> Status {
        use prost::Message;
        use tonic::codec::Codec;
        use tonic_prost::ProstCodec;
        assert!(
            PubkeyFeedRequest::decode(payload).is_err(),
            "payload must not decode"
        );
        let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
        let frame = [&[0u8][..], &len, payload].concat();
        let body = String::from_utf8(frame).expect("an ASCII test frame");
        let mut codec = ProstCodec::<PubkeyFeedResponse, PubkeyFeedRequest>::default();
        let mut stream = tonic::Streaming::new_request(codec.decoder(), body, None, None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(stream.message())
            .expect_err("tonic refuses the frame")
    }

    #[test]
    #[allow(clippy::result_large_err)] // tonic stream items
    fn restore_frame_errors_are_contract_violations_and_transport_errors_are_not() {
        let t = Duration::from_secs(5);
        let first = || req(announcing(body(0, 0..2), 4));
        // A frame that does not decode is malformed input. The status comes from tonic's own
        // decode path, so a rewording in tonic or prost fails here.
        let undecodable = decode_failure(&[0x0f]);
        assert_eq!(
            restore_code_over(vec![first(), Err(undecodable)], false, t),
            ErrorCode::ContractViolation
        );
        // A hello mid-stream or an empty frame, during the rebuild.
        let hello = Ok(PubkeyFeedRequest {
            frame: Some(pubkey_feed_request::Frame::Hello(Default::default())),
        });
        let empty = Ok(PubkeyFeedRequest { frame: None });
        for bad in [hello, empty] {
            assert_eq!(
                restore_code_over(vec![first(), bad], false, t),
                ErrorCode::ContractViolation
            );
        }
        // A broken transport stays a transport error.
        let reset = Status::unknown("h2 protocol error: stream reset");
        assert_eq!(
            restore_code_over(vec![first(), Err(reset)], false, t),
            ErrorCode::ResourceUnavailable
        );
    }

    #[test]
    fn a_stalled_restore_frame_times_out_as_a_contract_violation() {
        let t = Duration::from_millis(100);
        // No first frame at all, and a stall between rebuild frames.
        assert_eq!(
            restore_code_over(vec![], true, t),
            ErrorCode::ContractViolation
        );
        assert_eq!(
            restore_code_over(vec![req(announcing(body(0, 0..2), 4))], true, t),
            ErrorCode::ContractViolation
        );
    }

    // Snapshot saves: never rolled back, bookkeeping survives a cancelled caller.

    fn cache_with(n: u64) -> SharedCache {
        let cache = SharedCache::default();
        cache.write().unwrap().append_range(0, keys(n)).unwrap();
        cache
    }

    fn file_len(path: &Path) -> Option<u64> {
        (0..=64).find(|n| {
            let r = Registry::of(&BlstCodec, &keys(*n));
            matches!(load_with(&BlstCodec, path, &r), Startup::Use(_))
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_cancelled_flush_never_rolls_the_snapshot_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pubkeys.bin");
        // The first save blocks until released; later ones go straight through.
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<u64>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let first = std::sync::atomic::AtomicBool::new(true);
        let saver: Saver = Arc::new(move |c: &PubkeyCache<PublicKey>, p: &Path| {
            entered_tx.send(c.high_water()).unwrap();
            if first.swap(false, Ordering::SeqCst) {
                release_rx.lock().unwrap().recv().unwrap();
            }
            save_with(&BlstCodec, c, p)
        });
        let writer = Arc::new(SnapshotWriter::with_saver(
            path.clone(),
            Duration::from_secs(3_600),
            saver,
        ));
        let cache = cache_with(3);
        writer.mark_dirty();
        // The caller gives up while the 3-entry save is mid-write.
        let flush = tokio::time::timeout(Duration::from_millis(50), writer.save_if_dirty(&cache));
        assert!(flush.await.is_err(), "flush cancelled");
        assert_eq!(entered_rx.recv().unwrap(), 3);
        // A later save of 5 entries waits for the cancelled one instead of racing it.
        cache
            .write()
            .unwrap()
            .append_range(3, keys(5)[3..].to_vec())
            .unwrap();
        writer.mark_dirty();
        let later = {
            let (w, c) = (Arc::clone(&writer), Arc::clone(&cache));
            tokio::spawn(async move { w.save_if_dirty(&c).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!later.is_finished(), "saves never overlap");
        release_tx.send(()).unwrap();
        assert!(later.await.unwrap().unwrap());
        assert_eq!(entered_rx.recv().unwrap(), 5);
        assert_eq!(
            file_len(&path),
            Some(5),
            "the newest save is the one on disk"
        );
        assert_eq!((writer.saves(), writer.failures()), (2, 0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_cancelled_failing_flush_is_still_counted_and_retried() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let saver: Saver = Arc::new(move |_: &PubkeyCache<PublicKey>, _: &Path| {
            release_rx.lock().unwrap().recv().unwrap();
            Err(io::Error::other("disk full"))
        });
        let writer =
            SnapshotWriter::with_saver(std::path::PathBuf::from("/unused"), Duration::ZERO, saver);
        let cache = cache_with(2);
        writer.mark_dirty();
        let flush = tokio::time::timeout(Duration::from_millis(50), writer.save_if_dirty(&cache));
        assert!(flush.await.is_err());
        release_tx.send(()).unwrap();
        // The detached write still records its failure and leaves the snapshot dirty.
        for _ in 0..200 {
            if writer.failures() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(writer.failures(), 1);
        release_tx.send(()).unwrap();
        assert!(
            writer.save_if_dirty(&cache).await.is_err(),
            "still dirty: retried"
        );
        assert_eq!(writer.failures(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_saver_panic_in_a_cancelled_save_is_recorded_and_retried() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let first = AtomicBool::new(true);
        let saver: Saver = Arc::new(move |c: &PubkeyCache<PublicKey>, p: &Path| {
            if first.swap(false, Ordering::SeqCst) {
                release_rx.lock().unwrap().recv().unwrap();
                panic!("saver bug");
            }
            save_with(&BlstCodec, c, p)
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pubkeys.bin");
        let writer = SnapshotWriter::with_saver(path.clone(), Duration::ZERO, saver);
        let cache = cache_with(2);
        writer.mark_dirty();
        let flush = tokio::time::timeout(Duration::from_millis(50), writer.save_if_dirty(&cache));
        assert!(flush.await.is_err(), "flush cancelled");
        release_tx.send(()).unwrap();
        // Nobody awaits the panicked save, yet its failure is counted.
        for _ in 0..200 {
            if writer.failures() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(writer.failures(), 1);
        assert!(
            writer.save_if_dirty(&cache).await.unwrap(),
            "still dirty: the retry saves"
        );
        assert_eq!((writer.saves(), file_len(&path)), (1, Some(2)));
    }

    #[test]
    fn a_caught_panic_names_its_message() {
        let message = |payload: Box<dyn Any + Send>| panic_message(&*payload);
        assert!(message(Box::new("plain")).ends_with(": plain"));
        assert!(message(Box::new(String::from("formatted"))).ends_with(": formatted"));
        assert!(message(Box::new(7u8)).ends_with(": non-string panic payload"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_save_never_commits_a_shorter_snapshot() {
        let (dir, path) = snapshot_of(5);
        let writer = SnapshotWriter::new(path.clone(), Duration::ZERO);
        writer.note_committed(5);
        let shorter = cache_with(3);
        writer.mark_dirty();
        assert!(!writer.save_if_dirty(&shorter).await.unwrap(), "skipped");
        assert_eq!(file_len(&path), Some(5));
        assert_eq!(writer.saves(), 0);
        drop(dir);
    }
}
