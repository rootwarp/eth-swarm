//! The read side of the store env: every read is one read transaction, stamped from that same
//! transaction.
//!
//! cl-store opens the env with `MDBX_RDONLY` ([`Reader::open`], through store-schema's
//! [`open_reader`](store_schema::env::open_reader)), so it has no write transaction at all. A
//! read ([`Reader::block`], [`Reader::head`], [`Reader::finalized_blocks`]) opens one read
//! transaction and reads the stamp row ([`store_schema::stamp`]) in it with its data: the stamp
//! names the head the data was committed with. A snapshot with no stamp row serves nothing
//! ([`ReadError::Unavailable`]), whatever rows it holds: the stamp covers the whole env, and rows
//! carry none of their own.
//!
//! The canonical chain is the stamp's: a block by slot is the one on the parent walk down from
//! the stamp's head; for a slot at or below its finalized slot, the one the finalized slot index
//! holds ([`store_schema::finalized`], written with the stamp), or below the index's floor the
//! one on the walk down from its finalized block. A skipped slot, or a slot whose only blocks
//! are off that chain, is [`ReadError::NotFound`].
//!
//! Every transaction runs under its call's [`Deadline`], checked when it opens, every 64 blocks
//! it walks and once more before its data is returned, with the transaction open, so a slow read
//! cannot pin MVCC pages past it. [`ParentWalk`] (`GetBlocksByHead`) is stamped once, by its
//! first transaction, then reads each further block in a short transaction of its own: the
//! walk's deadline bounds when a step may start, and each step's transaction is checked against
//! its step timeout from the step's start ([`ParentWalk::with_step_timeout`]), the first step's
//! against the call's deadline if given ([`ParentWalk::with_first_deadline`]).
//!
//! A read transaction that fails to begin with `MDBX_WANNA_RECOVERY` or `MDBX_PANIC` is
//! `Unavailable`, like any env that cannot be read now, and marks the reader broken: the env
//! handle is of no further use, and [`crate::recover`] reopens the env read-only. Whoever holds
//! the reader across an await can wait for that ([`Reader::broken`]) and let go of it: a
//! `GetBlocksByHead` stream does.

use std::{
    borrow::Borrow,
    cell::Cell,
    ops::ControlFlow,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use store_schema::{
    blocks::{self, Stored},
    env::{self, Env, RoTxn},
    finalized, stamp,
};
pub use store_schema::{keys::Root, stamp::Stamp};

/// A monotonic clock. The server's is [`system_clock`]; tests inject their own.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// [`Instant::now`].
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(Instant::now)
}

/// How many blocks (or index rows) a read takes between two looks at its deadline.
const DEADLINE_EVERY: usize = 64;

/// The point past which a call's read transactions stop with [`ReadError::DeadlineExceeded`].
#[derive(Clone)]
pub struct Deadline {
    /// `None`: the timeout is past what an `Instant` holds; never.
    at: Option<Instant>,
    clock: Clock,
}

impl Deadline {
    /// `timeout` from now on `clock`.
    #[must_use]
    pub fn after(clock: Clock, timeout: Duration) -> Self {
        let at = clock().checked_add(timeout);
        Self { at, clock }
    }

    /// This deadline, or `timeout` from now on its clock if that is sooner.
    #[must_use]
    pub(crate) fn within(&self, timeout: Duration) -> Self {
        let soon = (self.clock)().checked_add(timeout);
        let at = match (self.at, soon) {
            (Some(at), Some(soon)) => Some(at.min(soon)),
            (at, soon) => at.or(soon),
        };
        Self {
            at,
            clock: Arc::clone(&self.clock),
        }
    }

    /// [`ReadError::DeadlineExceeded`] once the deadline has passed.
    pub(crate) fn check(&self) -> Result<(), ReadError> {
        match self.at {
            Some(at) if (self.clock)() >= at => Err(ReadError::DeadlineExceeded),
            _ => Ok(()),
        }
    }
}

/// Why a read served nothing. The messages are fixed: no MDBX error text leaves cl-store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// The snapshot has no stamp row (nothing is stamped yet, so nothing is served), or the
    /// env cannot be read now (out of reader slots, busy, wants recovery, or down until it
    /// reopens: [`crate::recover`]), or a range starts below the floor of the finalized slot
    /// index (what cl-chain has not indexed yet).
    #[error("store unavailable")]
    Unavailable,
    /// No such block in the snapshot, or none on the stamp's chain at that slot.
    #[error("not found")]
    NotFound,
    /// The call's deadline passed while one of its read transactions was open.
    #[error("store read deadline exceeded")]
    DeadlineExceeded,
    /// Any other failure: an MDBX error, or a row that does not have its table's layout.
    #[error("store read failed")]
    Internal,
}

/// Which block [`Reader::block`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRef {
    /// By block root.
    Root(Root),
    /// The canonical block at a slot, on the stamp's chain.
    Slot(u64),
    /// The stamp's head.
    Head,
    /// The stamp's finalized block.
    Finalized,
}

/// A stored block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub slot: u64,
    /// `hash_tree_root(block.message)`.
    pub root: Root,
    /// The `SignedBeaconBlock` SSZ, as stored.
    pub ssz: Vec<u8>,
    /// At or below the stamp's finalized slot and on its finalized chain.
    pub finalized: bool,
}

/// A read's value with the stamp row of the transaction it was read in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamped<T> {
    pub stamp: Stamp,
    pub value: T,
}

/// Read-only view of the store env. It has no write method, and its env has no write
/// transaction.
pub struct Reader {
    env: Box<dyn Borrow<Env> + Send + Sync>,
    /// A read transaction failed to begin with `MDBX_WANNA_RECOVERY` or `MDBX_PANIC`: this
    /// env handle is of no further use ([`crate::recover`] reopens the env).
    broken: AtomicBool,
    /// Wakes every [`Reader::broken`] waiting once `broken` is set.
    on_broken: tokio::sync::Notify,
    /// The blocks and index rows its reads touched, for the tests that count a read's work.
    #[cfg(test)]
    pub(crate) touched: std::sync::atomic::AtomicUsize,
}

impl Reader {
    /// Opens the env at `path` read-only (`MDBX_RDONLY`), checking its schema version and
    /// tables.
    ///
    /// # Errors
    ///
    /// The env does not open, or has a layout this build does not read.
    pub fn open(path: &Path) -> store_schema::Result<Self> {
        Ok(Self {
            env: Box::new(env::open_reader(path)?),
            broken: AtomicBool::new(false),
            on_broken: tokio::sync::Notify::new(),
            #[cfg(test)]
            touched: Default::default(),
        })
    }

    /// A reader of an env this process already has open (the writer's own, in tests): MDBX
    /// refuses a second open of one env in one process. Test seam only (`test-hooks`: another
    /// crate's tests serve cl-store over cl-chain's env, #146).
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn over(env: impl Borrow<Env> + Send + Sync + 'static) -> Self {
        Self {
            env: Box::new(env),
            broken: AtomicBool::new(false),
            on_broken: tokio::sync::Notify::new(),
            #[cfg(test)]
            touched: Default::default(),
        }
    }

    pub(crate) fn env(&self) -> &Env {
        (*self.env).borrow()
    }

    /// Whether a read transaction of this env failed to begin with `MDBX_WANNA_RECOVERY` or
    /// `MDBX_PANIC`.
    pub(crate) fn is_broken(&self) -> bool {
        self.broken.load(Ordering::Relaxed)
    }

    /// Resolves once this reader is broken ([`Self::is_broken`]), at once if it is already.
    pub(crate) async fn broken(&self) {
        // Made before the flag is read: a `notify_waiters` from then on wakes it.
        let notified = self.on_broken.notified();
        if self.is_broken() {
            return;
        }
        notified.await;
    }

    /// Marks the reader broken and wakes whoever waits for that.
    fn mark_broken(&self) {
        self.broken.store(true, Ordering::Relaxed);
        self.on_broken.notify_waiters();
    }

    /// Marks the reader as if a read transaction had failed with `MDBX_WANNA_RECOVERY`.
    #[cfg(test)]
    pub(crate) fn poison(&self) {
        self.mark_broken();
    }

    /// The block `at` names, with the stamp of the transaction it was read in.
    ///
    /// # Errors
    ///
    /// [`ReadError`].
    pub fn block(&self, at: BlockRef, deadline: &Deadline) -> Result<Stamped<Block>, ReadError> {
        self.read(deadline, |snap, stamp| snap.block(stamp, at))
    }

    /// The stamp alone: the head and finalized block the env was last committed with.
    ///
    /// # Errors
    ///
    /// [`ReadError`].
    pub fn head(&self, deadline: &Deadline) -> Result<Stamp, ReadError> {
        self.read(deadline, |_, _| Ok(())).map(|read| read.stamp)
    }

    /// One read transaction: `f` runs in it, and the deadline is checked when it opens and
    /// again, with the transaction still open, before `f`'s value is returned.
    fn view<T>(
        &self,
        deadline: &Deadline,
        f: impl FnOnce(&Snapshot<'_>) -> Result<T, ReadError>,
    ) -> Result<T, ReadError> {
        let txn = env::begin_reader_txn(self.env()).inspect_err(|err| {
            if matches!(
                err,
                store_schema::Error::Mdbx(libmdbx::Error::WannaRecovery | libmdbx::Error::Panic)
            ) {
                self.mark_broken();
            }
        })?;
        let snap = Snapshot {
            txn,
            deadline,
            walked: Cell::new(0),
        };
        deadline.check()?;
        let value = f(&snap);
        #[cfg(test)]
        self.touched.fetch_add(snap.walked.get(), Ordering::Relaxed);
        let value = value?;
        deadline.check()?;
        Ok(value)
    }

    /// One stamped read: [`Self::view`] with the stamp row read first, in the same transaction.
    pub(crate) fn read<T>(
        &self,
        deadline: &Deadline,
        f: impl FnOnce(&Snapshot<'_>, &Stamp) -> Result<T, ReadError>,
    ) -> Result<Stamped<T>, ReadError> {
        self.view(deadline, |snap| {
            let stamp = snap.stamp()?;
            let value = f(snap, &stamp)?;
            Ok(Stamped { stamp, value })
        })
    }
}

impl From<libmdbx::Error> for ReadError {
    fn from(err: libmdbx::Error) -> Self {
        match err {
            libmdbx::Error::ReadersFull | libmdbx::Error::Busy | libmdbx::Error::WannaRecovery => {
                Self::Unavailable
            }
            _ => Self::Internal,
        }
    }
}

impl From<store_schema::Error> for ReadError {
    fn from(err: store_schema::Error) -> Self {
        match err {
            store_schema::Error::Mdbx(err) => err.into(),
            _ => Self::Internal,
        }
    }
}

/// One read transaction under its call's deadline.
pub(crate) struct Snapshot<'r> {
    txn: RoTxn<'r>,
    deadline: &'r Deadline,
    /// Blocks walked and index rows read so far, for the deadline's look every
    /// [`DEADLINE_EVERY`].
    walked: Cell<usize>,
}

impl Snapshot<'_> {
    /// The stamp row; with none there is nothing to serve. Nor with a head `seq` or slot of 0,
    /// which a `ReadMeta` cannot carry (they read as missing).
    fn stamp(&self) -> Result<Stamp, ReadError> {
        match stamp::read(&self.txn)? {
            Some(stamp) if stamp.head_seq > 0 && stamp.head_slot > 0 => Ok(stamp),
            _ => Err(ReadError::Unavailable),
        }
    }

    /// The block at `root` ([`blocks::stored`]).
    fn stored(&self, root: &Root) -> Result<Option<Stored<'_>>, ReadError> {
        Ok(blocks::stored(&self.txn, root)?)
    }

    /// One block or index row read: the deadline looked at every [`DEADLINE_EVERY`].
    fn step(&self) -> Result<(), ReadError> {
        let walked = self.walked.get() + 1;
        self.walked.set(walked);
        if walked.is_multiple_of(DEADLINE_EVERY) {
            self.deadline.check()?;
        }
        Ok(())
    }

    /// [`blocks::walk`] down from `from` to `low`, a [`Self::step`] per block.
    pub(crate) fn walk(
        &self,
        from: Root,
        low: u64,
        mut visit: impl FnMut(u64, Root, &[u8]) -> ControlFlow<()>,
    ) -> Result<(), ReadError> {
        blocks::walk(&self.txn, from, low, |slot, root, ssz| {
            self.step()?;
            Ok::<_, ReadError>(visit(slot, root, ssz))
        })
    }

    /// Whether the finalized slot index covers `slot`, at or below the stamp's finalized slot:
    /// from its floor up.
    pub(crate) fn indexed(&self, slot: u64) -> Result<bool, ReadError> {
        Ok(finalized::indexed_from(&self.txn)?.is_some_and(|from| slot >= from))
    }

    /// [`finalized::range`]: the indexed blocks of `start..end`, a [`Self::step`] per block.
    pub(crate) fn finalized_range(
        &self,
        start: u64,
        end: u64,
        mut visit: impl FnMut(u64, Root, &[u8]),
    ) -> Result<(), ReadError> {
        finalized::range(&self.txn, start, end, |slot, root, ssz| {
            self.step()?;
            visit(slot, root, ssz);
            Ok::<_, ReadError>(())
        })
    }

    /// The stamp's canonical block at `slot`: the one on the walk down from its head; at or
    /// below its finalized slot the index's, or below the index's floor the one on the walk
    /// down from its finalized block. `None` for a skipped slot, a slot above the head and one
    /// below what is stored.
    fn canonical_at(&self, stamp: &Stamp, slot: u64) -> Result<Option<Root>, ReadError> {
        if slot > stamp.head_slot {
            return Ok(None);
        }
        if slot <= stamp.finalized_slot && self.indexed(slot)? {
            return Ok(finalized::root_at(&self.txn, slot)?);
        }
        let from = if slot <= stamp.finalized_slot {
            stamp.finalized_root
        } else {
            stamp.head_root
        };
        let mut found = None;
        self.walk(from, slot, |at, root, _| {
            if at == slot {
                found = Some(root);
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })?;
        Ok(found)
    }

    /// Whether the block `(slot, root)` is finalized by `stamp`: at or below its finalized
    /// slot and the index's block there, a point lookup. Below the index's floor, `false`: not
    /// proven, never a false `true`.
    fn finalized(&self, stamp: &Stamp, slot: u64, root: Root) -> Result<bool, ReadError> {
        Ok(slot <= stamp.finalized_slot
            && self.indexed(slot)?
            && finalized::root_at(&self.txn, slot)? == Some(root))
    }

    fn block(&self, stamp: &Stamp, at: BlockRef) -> Result<Block, ReadError> {
        let root = match at {
            BlockRef::Root(root) => root,
            BlockRef::Slot(slot) => self.canonical_at(stamp, slot)?.ok_or(ReadError::NotFound)?,
            BlockRef::Head => stamp.head_root,
            BlockRef::Finalized => stamp.finalized_root,
        };
        let Stored { slot, ssz, .. } = self.stored(&root)?.ok_or(ReadError::NotFound)?;
        let finalized = match at {
            // By root, the block may be off the stamp's chain.
            BlockRef::Root(_) => self.finalized(stamp, slot, root)?,
            _ => slot <= stamp.finalized_slot,
        };
        Ok(Block {
            slot,
            root,
            ssz: ssz.into_owned(),
            finalized,
        })
    }
}

/// `GetBlocksByHead`: the block at a root, then its parent, and so on, newest first. The first
/// step reads the stamp and the block in one transaction; it stamps every block. Each further
/// step reads one block in a short transaction of its own, under the walk's deadline (and, with
/// a step timeout, within it of the step's start), whatever the stamp is by then. The walk ends
/// after `count` blocks, at a parent that is not stored, after slot 0, or at once for an
/// unknown root; it fuses after an error.
///
/// A block's `finalized` is decided once, at the first block at or below the stamp's finalized
/// slot (whether it is on the stamp's chain, read in that block's transaction), and holds for
/// every block below it: a walk that reaches that slot on a fork reads its blocks below as not
/// finalized, never the other way. Deciding it is a point lookup in the finalized slot index,
/// at any depth; a first block below the index's floor reads `false`, not proven, never a false
/// `true`, and so do the blocks below it.
pub struct ParentWalk {
    reader: Arc<Reader>,
    deadline: Deadline,
    /// Each step's read transaction is checked against this long after the step started, if
    /// set.
    step: Option<Duration>,
    /// The first step's deadline instead, if set: the call's.
    first: Option<Deadline>,
    next: Option<Root>,
    left: u64,
    /// The first step's stamp.
    stamp: Option<Stamp>,
    /// The last block's slot: each parent's is lower.
    above: Option<u64>,
    finalized: Option<bool>,
}

impl ParentWalk {
    #[must_use]
    pub fn new(reader: Arc<Reader>, root: Root, count: u64, deadline: Deadline) -> Self {
        Self {
            reader,
            deadline,
            step: None,
            first: None,
            next: Some(root),
            left: count,
            stamp: None,
            above: None,
            finalized: None,
        }
    }

    /// The same walk, each step's read transaction checked against `timeout` from the step's
    /// start, however far off the walk's deadline is.
    #[must_use]
    pub fn with_step_timeout(mut self, timeout: Duration) -> Self {
        self.step = Some(timeout);
        self
    }

    /// The same walk, its first step's read transaction checked against `first` (the call's
    /// deadline, taken when the call came in) instead of a step timeout from the step's start:
    /// time queued before the first step counts.
    #[must_use]
    pub fn with_first_deadline(mut self, first: Deadline) -> Self {
        self.first = Some(first);
        self
    }

    /// The reader the walk reads through.
    pub(crate) fn reader(&self) -> &Reader {
        &self.reader
    }

    /// The block at `root`, if stored, and where the walk goes on.
    fn step(&mut self, root: Root) -> Result<Option<Stamped<Block>>, ReadError> {
        let decided = self.finalized.is_some();
        let read = |snap: &Snapshot<'_>, stamp: &Stamp| {
            let Some(Stored { slot, parent, ssz }) = snap.stored(&root)? else {
                return Ok(None);
            };
            let finalized = if decided || slot > stamp.finalized_slot {
                None
            } else {
                Some(snap.finalized(stamp, slot, root)?)
            };
            Ok(Some((slot, parent, ssz.into_owned(), finalized)))
        };
        let deadline = match (self.first.take(), self.step) {
            (Some(first), _) => first,
            (None, Some(timeout)) => self.deadline.within(timeout),
            (None, None) => self.deadline.clone(),
        };
        let Stamped { stamp, value } = match self.stamp {
            None => self.reader.read(&deadline, read)?,
            Some(stamp) => Stamped {
                stamp,
                value: self.reader.view(&deadline, |snap| read(snap, &stamp))?,
            },
        };
        self.stamp = Some(stamp);
        let Some((slot, parent, ssz, finalized)) = value else {
            return Ok(None);
        };
        if self.above.is_some_and(|above| slot >= above) {
            return Err(ReadError::Internal);
        }
        self.finalized = self.finalized.or(finalized);
        self.above = Some(slot);
        self.left -= 1;
        self.next = (slot > 0).then_some(parent);
        let finalized = self.finalized == Some(true);
        Ok(Some(Stamped {
            stamp,
            value: Block {
                slot,
                root,
                ssz,
                finalized,
            },
        }))
    }
}

impl Iterator for ParentWalk {
    type Item = Result<Stamped<Block>, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        let root = self.next.take()?;
        if self.left == 0 {
            return None;
        }
        self.step(root).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, block, common, deadline, stamp, Store};
    use std::{
        collections::BTreeSet,
        io::{BufRead, Read, Write},
        path::PathBuf,
        sync::atomic::AtomicU64,
        thread,
    };
    use store_schema::{
        keys::{slot_root_key, STAMP_KEY},
        tables::{BLOCKS, BLOCK_INDEX, COLUMNS, META, TABLES},
        txn::seed_unstamped,
    };

    type Rows = Vec<(Vec<u8>, Vec<u8>)>;

    /// The table names, then every table's rows, as `reader`'s env holds them: the whole env.
    fn env_rows(reader: &Reader) -> Vec<(Option<&'static str>, Rows)> {
        let txn = env::begin_reader_txn(reader.env()).unwrap();
        std::iter::once(None)
            .chain(TABLES.map(Some))
            .map(|table| {
                let handle = txn.open_table(table).unwrap();
                let rows = txn
                    .cursor(&handle)
                    .unwrap()
                    .iter::<Vec<u8>, Vec<u8>>()
                    .map(Result::unwrap)
                    .collect();
                (table, rows)
            })
            .collect()
    }

    fn val(bytes: &[u8]) -> mdbx_sys::MDBX_val {
        mdbx_sys::MDBX_val {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        }
    }

    /// An MDBX error leaves only a fixed kind: `Unavailable` for the env being out of reach
    /// for now (reader slots full, busy, wants recovery), `Internal` for any other; never its
    /// own text.
    #[test]
    fn mdbx_errors_map_to_fixed_kinds() {
        use libmdbx::Error as E;
        for (err, want) in [
            (E::ReadersFull, ReadError::Unavailable),
            (E::Busy, ReadError::Unavailable),
            (E::WannaRecovery, ReadError::Unavailable),
            (E::Corrupted, ReadError::Internal),
            (E::Panic, ReadError::Internal),
            (E::Access, ReadError::Internal),
            (E::Other(5), ReadError::Internal),
        ] {
            let text = err.to_string();
            let got = ReadError::from(store_schema::Error::Mdbx(err));
            assert_eq!(got, want, "{text}");
            assert!(!got.to_string().contains(&text), "{text}");
        }
        let malformed = store_schema::Error::MalformedStamp { len: 3 };
        assert_eq!(ReadError::from(malformed), ReadError::Internal);
    }

    /// The env of the two-user run (`scripts/store-two-users.sh`): another OS user (cl-chain's)
    /// wrote it, and this test binary runs as the reader's user. Unset in an ordinary run.
    const TWO_USER_ENV: &str = "CL_STORE_TWO_USER_ENV";

    fn two_user_env() -> Option<PathBuf> {
        std::env::var_os(TWO_USER_ENV).map(PathBuf::from)
    }

    /// cl-store opens the env read-only: a write transaction, and a put, a delete, a table
    /// create and a table drop in a read transaction of the reader's env, each straight
    /// through the C API, all fail with `EACCES`, and the env reads back unchanged, through
    /// the reader too. In the two-user run the env is the one cl-chain's user wrote
    /// ([`TWO_USER_ENV`]), checked as the reader's user; otherwise this test writes its own.
    #[test]
    fn cannot_write() {
        let _serial = testkit::serial();
        let own = tempfile::tempdir().unwrap();
        let path = two_user_env().unwrap_or_else(|| {
            let (ssz, root) = block(9, [0; 32], 1);
            let writer = env::test_writer(own.path()).unwrap();
            testkit::import(&writer, &[&ssz], stamp(1, (9, root), (9, root)));
            own.path().to_path_buf()
        });
        let reader = Reader::open(&path).expect("the env opens read-only");
        let before = env_rows(&reader);
        let served = reader
            .block(BlockRef::Head, &deadline())
            .expect("the reader serves the stored head");
        let (slot, root) = (served.value.slot, served.value.root);

        let env = reader.env().ptr().0;
        let mut txn = std::ptr::null_mut();
        // SAFETY: `env` is the reader's open env; a txn that did begin is aborted at once.
        let begun = unsafe {
            let rc = mdbx_sys::mdbx_txn_begin_ex(
                env,
                std::ptr::null_mut(),
                mdbx_sys::MDBX_TXN_READWRITE,
                &mut txn,
                std::ptr::null_mut(),
            );
            if rc == mdbx_sys::MDBX_SUCCESS {
                mdbx_sys::mdbx_txn_abort(txn);
            }
            rc
        };
        assert_eq!(begun, mdbx_sys::MDBX_EACCESS, "a write txn");

        let ro = reader.env().begin_ro_txn().unwrap();
        let blocks = ro.open_table(Some(BLOCKS)).unwrap();
        let (raw, dbi) = (ro.txn().0, blocks.dbi());
        let key = slot_root_key(slot, &root);
        let value = b"overwritten".to_vec();
        let mut created = 0;
        // SAFETY: `raw` is the live read txn `ro`, `dbi` its handle of `blocks`; the values
        // point at buffers that outlive the calls.
        let codes = unsafe {
            [
                (
                    "put",
                    mdbx_sys::mdbx_put(
                        raw,
                        dbi,
                        &val(&key),
                        &mut val(&value),
                        mdbx_sys::MDBX_UPSERT,
                    ),
                ),
                (
                    "del",
                    mdbx_sys::mdbx_del(raw, dbi, &val(&key), std::ptr::null()),
                ),
                (
                    "create",
                    mdbx_sys::mdbx_dbi_open(
                        raw,
                        c"intruder".as_ptr(),
                        mdbx_sys::MDBX_CREATE,
                        &mut created,
                    ),
                ),
                ("drop", mdbx_sys::mdbx_drop(raw, dbi, false)),
            ]
        };
        for (what, code) in codes {
            assert_eq!(code, mdbx_sys::MDBX_EACCESS, "{what}");
        }
        drop(ro);
        assert_eq!(env_rows(&reader), before, "a write changed the env");
        assert_eq!(reader.block(BlockRef::Head, &deadline()), Ok(served));
        if let Some(path) = two_user_env() {
            let uid = ipc::peercred::effective_uid();
            println!(
                "two-user: cannot_write ok on {} as uid {uid}",
                path.display()
            );
        }
    }

    /// The two-user run only ([`TWO_USER_ENV`]; skipped otherwise): the env is laid out as
    /// [5.43] has it, by the writer itself under umask 0077, and this user, the reader's,
    /// cannot write it. The directory is 0750 and setgid (2750, cl-node's provisioning keeps
    /// the files in its group), the data file 0640 and the lock file 0660, each owned by
    /// another user (the writer's) and in this user's group (the store group). The data file
    /// does not open for writing and no file can be created in the directory, yet the env
    /// opens read-only and serves its head.
    #[test]
    fn env_permissions() {
        use std::os::unix::fs::MetadataExt;
        let Some(path) = two_user_env() else {
            eprintln!("{TWO_USER_ENV} is not set: skipped (scripts/store-two-users.sh sets it)");
            return;
        };
        let _serial = testkit::serial();
        let (uid, gid) = (
            ipc::peercred::effective_uid(),
            ipc::peercred::effective_gid(),
        );
        assert_ne!(uid, 0, "run as the reader's user, not as root");
        for (name, mode) in [(".", 0o2750), ("mdbx.dat", 0o640), ("mdbx.lck", 0o660)] {
            let meta = std::fs::metadata(path.join(name)).unwrap();
            assert_eq!(meta.mode() & 0o7777, mode, "{name}: mode {:o}", meta.mode());
            assert_ne!(meta.uid(), uid, "{name} is the writer's, not this user's");
            assert_eq!(meta.gid(), gid, "{name} is in the store group");
        }
        let write = std::fs::OpenOptions::new()
            .write(true)
            .open(path.join("mdbx.dat"));
        assert_eq!(
            write.map(drop).map_err(|e| e.kind()),
            Err(std::io::ErrorKind::PermissionDenied),
            "the data file opens for writing"
        );
        let create = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.join("intruder"));
        assert_eq!(
            create.map(drop).map_err(|e| e.kind()),
            Err(std::io::ErrorKind::PermissionDenied),
            "a file is created in the env directory"
        );
        let reader = Reader::open(&path).expect("the env opens read-only");
        reader.head(&deadline()).expect("and serves its stamp");
        println!(
            "two-user: env_permissions ok on {} as uid {uid}",
            path.display()
        );
    }

    /// The reader table of an env as `mdbx_stat -r` prints it: `(pid, txnid)` per row, the
    /// txnid `-` for a slot without a live read transaction.
    fn reader_rows(table: &str) -> Vec<(u32, String)> {
        table
            .lines()
            .filter_map(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                match words.as_slice() {
                    [row, slot, pid, _thread, txnid, ..]
                        if row.ends_with(')') && slot.starts_with('[') =>
                    {
                        Some((pid.parse().ok()?, (*txnid).to_owned()))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// While cl-store holds a read transaction (a read in progress), the env's reader table
    /// lists its pid with that transaction, and `mdbx_chk` checks the env clean all the same.
    /// Both tools are the pinned libmdbx 0.12.13 build of `scripts/build-mdbx-chk.sh`:
    /// `MDBX_CHK`, and `mdbx_stat` beside it (that `mdbx_chk` has no reader listing;
    /// `mdbx_stat -r` prints the table). Skipped unless `MDBX_CHK` is set: the mdbx-chk CI job
    /// sets it.
    #[test]
    fn registered_in_reader_list() {
        let Some(chk) = std::env::var_os("MDBX_CHK").map(PathBuf::from) else {
            eprintln!("MDBX_CHK is not set: skipped (the mdbx-chk CI job runs it)");
            return;
        };
        let stat = chk.with_file_name("mdbx_stat");
        assert!(
            stat.is_file(),
            "MDBX_CHK is {}, but {} (built beside it) is missing",
            chk.display(),
            stat.display()
        );
        let _serial = testkit::serial();
        let dir = tempfile::tempdir().unwrap();
        let (ssz, root) = block(9, [0; 32], 1);
        {
            let writer = env::test_writer(dir.path()).unwrap();
            testkit::import(&writer, &[&ssz], stamp(1, (9, root), (9, root)));
        }
        let reader = Reader::open(dir.path()).expect("the env opens read-only");
        let pid = std::process::id();
        let (table, row) = reader
            .read(&deadline(), |_, _| {
                let out = std::process::Command::new(&stat)
                    .arg("-r")
                    .arg(dir.path())
                    .output()
                    .unwrap();
                let table = String::from_utf8_lossy(&out.stdout).into_owned();
                assert!(out.status.success(), "mdbx_stat -r: {out:?}");
                let row = reader_rows(&table).into_iter().find(|(p, _)| *p == pid);
                let chk = std::process::Command::new(&chk)
                    .arg("-v")
                    .arg("-c")
                    .arg(dir.path())
                    .output()
                    .unwrap();
                let text = String::from_utf8_lossy(&chk.stdout);
                assert!(chk.status.success(), "mdbx_chk -v -c: {chk:?}");
                assert!(!text.lines().any(|l| l.starts_with(" ~ ")), "{text}");
                Ok((table, row))
            })
            .unwrap()
            .value;
        let (_, txnid) = row.unwrap_or_else(|| panic!("pid {pid} is not in the table:\n{table}"));
        assert_ne!(txnid, "-", "pid {pid} has no live read txn:\n{table}");
        println!("the reader table lists cl-store's pid {pid} with read txn {txnid}");
    }

    /// cl-chain's side of [`writer_crash_recovery`]: run as a child of this test binary (with
    /// [`CHILD_ENV`]), it opens the env as its writer and commits block after block from the
    /// stored stamp on (block `n` at slot `n`, [`crash_stamp`]), printing `committed <n>` after
    /// each. With [`CHILD_HOLD`] = `k` it then commits `k` blocks only, writes block `k + 1` in
    /// a write txn and prints `holding <n>` without committing it. It runs until it is
    /// killed. A normal run passes straight through.
    #[test]
    fn child_writer() {
        let Some(path) = std::env::var_os(CHILD_ENV).map(PathBuf::from) else {
            return;
        };
        let hold: Option<u64> = std::env::var(CHILD_HOLD).ok().map(|k| k.parse().unwrap());
        let writer = env::test_writer(&path).unwrap();
        let from = {
            let txn = writer.begin_ro_txn().unwrap();
            store_schema::stamp::read(&txn)
                .unwrap()
                .map_or(0, |s| s.head_seq)
        };
        let mut chain = crash_chain(from);
        let mut out = std::io::stdout();
        for n in from + 1.. {
            let parent = chain.last().map_or([0; 32], |b| b.1);
            chain.push(block(n, parent, n));
            let ssz = &chain[usize::try_from(n - 1).unwrap()].0;
            if hold.is_some_and(|k| n == from + k + 1) {
                let txn = store_schema::txn::begin(&writer).unwrap();
                store_schema::blocks::put::<common::E>(&txn, &common::schedule(), ssz).unwrap();
                writeln!(out, "holding {n}").unwrap();
                out.flush().unwrap();
                std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
                drop(txn);
                return;
            }
            testkit::import(&writer, &[ssz], crash_stamp(&chain, n));
            writeln!(out, "committed {n}").unwrap();
            out.flush().unwrap();
        }
    }

    const CHILD_ENV: &str = "CL_STORE_CHILD_WRITER";
    const CHILD_HOLD: &str = "CL_STORE_CHILD_HOLD";

    /// The finalized block of [`crash_stamp`] trails its head by this many blocks.
    const CRASH_LAG: u64 = 4;

    /// Blocks `1..=upto` of the crash test's chain: `(ssz, root)`, block `n` at slot `n` on
    /// block `n - 1`.
    fn crash_chain(upto: u64) -> Vec<(Vec<u8>, Root)> {
        let mut chain: Vec<(Vec<u8>, Root)> = Vec::new();
        for n in 1..=upto {
            let parent = chain.last().map_or([0; 32], |b| b.1);
            chain.push(block(n, parent, n));
        }
        chain
    }

    /// The stamp of block `n`'s commit: head `n`, seq `n`, finalized [`CRASH_LAG`] behind.
    fn crash_stamp(chain: &[(Vec<u8>, Root)], n: u64) -> Stamp {
        let at = |n: u64| chain[usize::try_from(n - 1).unwrap()].1;
        let fin = n.saturating_sub(CRASH_LAG).max(1);
        stamp(n, (n, at(n)), (fin, at(fin)))
    }

    /// A child writer ([`child_writer`]) and what it printed.
    struct ChildWriter {
        child: std::process::Child,
        lines: std::sync::mpsc::Receiver<String>,
        last: Option<u64>,
    }

    impl ChildWriter {
        fn start(path: &Path, hold: Option<u64>) -> Self {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "reader::tests::child_writer", "--nocapture"])
                .args(["--test-threads=1"])
                .env(CHILD_ENV, path)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped());
            if let Some(k) = hold {
                command.env(CHILD_HOLD, k.to_string());
            }
            let mut child = command.spawn().unwrap();
            let stdout = child.stdout.take().unwrap();
            let (tx, lines) = std::sync::mpsc::channel();
            thread::spawn(move || {
                for line in std::io::BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            Self {
                child,
                lines,
                last: None,
            }
        }

        /// Waits (at most a minute) for a line `<what> <n>`, `n` at least `at_least`.
        fn wait(&mut self, what: &str, at_least: u64) -> u64 {
            let end = Instant::now() + Duration::from_secs(60);
            loop {
                let left = end.saturating_duration_since(Instant::now());
                let line = self
                    .lines
                    .recv_timeout(left)
                    .unwrap_or_else(|_| panic!("no `{what} {at_least}` from the child writer"));
                let Some((word, n)) = line.split_once(' ') else {
                    continue;
                };
                let Ok(n) = n.parse::<u64>() else { continue };
                if word == "committed" {
                    self.last = Some(n);
                }
                if word == what && n >= at_least {
                    return n;
                }
            }
        }

        /// `kill -9`, then everything it printed: the last block it committed.
        fn kill9(mut self) -> Option<u64> {
            self.child.kill().unwrap();
            self.child.wait().unwrap();
            while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(10)) {
                if let Some(n) = line.strip_prefix("committed ") {
                    self.last = n.parse().ok();
                }
            }
            self.last
        }
    }

    impl Drop for ChildWriter {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// cl-chain is killed (`SIGKILL`) while it commits, and later restarts. cl-store, reading
    /// throughout through its [`Recovering`](crate::recover::Recovering) env:
    ///
    /// - starts before cl-chain: no env yet, so `Unavailable`, and the next open waits out the
    ///   reopen backoff on the injected clock (no attempt before it is up, one after);
    /// - serves cl-chain's commits once it has opened the env;
    /// - after a kill in the middle of the commit loop, answers `Unavailable` or the last
    ///   committed stamp (with its block), never an MDBX error, and the same after a kill
    ///   with a write txn open: the block of that txn is never served;
    /// - serves the new stamps once cl-chain has restarted and commits again.
    ///
    /// cl-store never recovers the env itself: it never opens it but read-only.
    #[test]
    fn writer_crash_recovery() {
        use crate::recover::{
            tests::{wait, Manual},
            Recovering, REOPEN_BASE,
        };
        let _serial = testkit::serial();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env");
        let clock = Manual::new();
        let opener_path = path.clone();
        let store =
            Recovering::with_opener(Box::new(move || Reader::open(&opener_path)), clock.clock());
        let head = |store: &Recovering| store.read(|r| r.block(BlockRef::Head, &deadline()));
        // A served head: a stamp the writer committed and its own block, or `Unavailable`.
        let check = |read: &Result<Stamped<Block>, ReadError>| match read {
            Ok(read) => {
                let n = read.stamp.head_seq;
                let chain = crash_chain(n);
                assert_eq!(read.stamp, crash_stamp(&chain, n));
                let (ssz, root) = &chain[usize::try_from(n - 1).unwrap()];
                assert_eq!((&read.value.ssz, read.value.root), (ssz, *root));
            }
            Err(err) => assert_eq!(*err, ReadError::Unavailable, "never an MDBX error"),
        };
        // Reads until one serves, moving the clock past each reopen delay.
        let serve = |store: &Recovering| {
            for _ in 0..100 {
                let read = head(store);
                check(&read);
                if let Ok(read) = read {
                    return read;
                }
                if let Some(at) = store.next_attempt() {
                    clock.advance(at.saturating_duration_since(clock.now()));
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!("the store never served again");
        };

        // cl-store starts first: no env.
        assert_eq!(head(&store), Err(ReadError::Unavailable));
        assert_eq!(store.reopen_attempts(), 1);
        let first = wait(&store, &clock);
        assert!(
            (REOPEN_BASE / 2..=REOPEN_BASE).contains(&first),
            "{first:?}"
        );

        // cl-chain starts and commits; the reopen still waits for its delay.
        let mut writer = ChildWriter::start(&path, None);
        writer.wait("committed", 1);
        assert_eq!(head(&store), Err(ReadError::Unavailable));
        assert_eq!(store.reopen_attempts(), 1, "no attempt before the delay");
        clock.advance(first);
        let read = head(&store);
        check(&read);
        assert!(read.is_ok(), "{read:?}");
        assert_eq!(store.reopen_attempts(), 2);

        // kill -9 in the middle of the commit loop.
        writer.wait("committed", 20);
        let last = writer.kill9().unwrap();
        let after = serve(&store);
        let seq = after.stamp.head_seq;
        assert!(
            seq == last || seq == last + 1,
            "serves {seq}, the writer's last commit was {last} (or one it did not print)"
        );
        for _ in 0..3 {
            assert_eq!(
                head(&store),
                Ok(after.clone()),
                "nothing moves without a writer"
            );
        }

        // cl-chain restarts, commits three blocks, and is killed with a write txn open.
        let mut writer = ChildWriter::start(&path, Some(3));
        let held = writer.wait("holding", seq + 4);
        assert_eq!(held, seq + 4);
        writer.kill9();
        let read = serve(&store);
        assert_eq!(read.stamp.head_seq, seq + 3, "the last committed stamp");
        let (_, uncommitted) = block(held, read.value.root, held);
        assert_eq!(
            store.read(|r| r.block(BlockRef::Root(uncommitted), &deadline())),
            Err(ReadError::NotFound),
            "the killed txn's block"
        );

        // cl-chain restarts and commits: cl-store serves the new stamps.
        let mut writer = ChildWriter::start(&path, None);
        let target = writer.wait("committed", seq + 10);
        let end = Instant::now() + Duration::from_secs(30);
        while serve(&store).stamp.head_seq < target {
            assert!(Instant::now() < end, "the new stamps were never served");
            thread::sleep(Duration::from_millis(10));
        }
        drop(writer);
    }

    /// cl-chain commits 1,000 blocks, each with its stamp, while cl-store reads. Every read's
    /// stamp is the stamp row of the transaction its data came from: it is a stamp the writer
    /// committed (head block `head_seq`, finalized 16 blocks behind), the head read by name is
    /// that stamp's head, a block by slot is there only up to the stamp's head, and a finalized
    /// range holds exactly the blocks up to the stamp's finalized slot.
    #[test]
    fn concurrent_writer() {
        const COUNT: u64 = 1_000;
        const LAG: u64 = 16;
        let store = Store::new();
        // Block n (1..=1000) at slot 2n on block n - 1: the odd slots are empty.
        let mut chain: Vec<Block> = Vec::new();
        for n in 1..=COUNT {
            let parent = chain.last().map_or([0; 32], |b| b.root);
            let (ssz, root) = block(2 * n, parent, n);
            chain.push(Block {
                slot: 2 * n,
                root,
                ssz,
                finalized: true,
            });
        }
        let at = |n: u64| &chain[usize::try_from(n - 1).unwrap()];
        let committed = |n: u64| {
            let finalized = at(n.saturating_sub(LAG).max(1));
            stamp(
                n,
                (at(n).slot, at(n).root),
                (finalized.slot, finalized.root),
            )
        };
        store.import(&[&at(1).ssz], committed(1));
        let reader = store.reader();
        let done = AtomicBool::new(false);
        let mut reads = 0u64;
        let mut seen = BTreeSet::new();
        thread::scope(|scope| {
            scope.spawn(|| {
                for n in 2..=COUNT {
                    store.import(&[&at(n).ssz], committed(n));
                }
                done.store(true, Ordering::SeqCst);
            });
            while !done.load(Ordering::SeqCst) {
                let dl = deadline();
                let row = reader
                    .read(&dl, |snap, _| {
                        let meta = snap.txn.open_table(Some(META)).unwrap();
                        Ok(snap.txn.get::<Vec<u8>>(&meta, STAMP_KEY).unwrap().unwrap())
                    })
                    .unwrap();
                assert_eq!(Stamp::decode(&row.value).unwrap(), row.stamp);
                assert_eq!(row.stamp, committed(row.stamp.head_seq));

                let head = reader.block(BlockRef::Head, &dl).unwrap();
                let n = head.stamp.head_seq;
                assert_eq!(head.stamp, committed(n));
                assert_eq!(
                    (head.value.slot, head.value.root, &head.value.ssz),
                    (at(n).slot, at(n).root, &at(n).ssz)
                );
                seen.insert(n);

                // The next block's slot: served only by a snapshot whose stamp has it.
                let next = head.value.slot + 2;
                match reader.block(BlockRef::Slot(next), &dl) {
                    Ok(b) => {
                        assert_eq!(b.stamp, committed(b.stamp.head_seq));
                        assert!(next <= b.stamp.head_slot, "{next} above {:?}", b.stamp);
                        assert_eq!(b.value.ssz, at(next / 2).ssz);
                    }
                    Err(e) => assert_eq!(e, ReadError::NotFound),
                }

                let start = head.stamp.finalized_slot.saturating_sub(63);
                let range = reader.finalized_blocks(start, 128, &dl).unwrap();
                assert_eq!(range.stamp, committed(range.stamp.head_seq));
                let want: Vec<Block> = chain
                    .iter()
                    .filter(|b| b.slot >= start && b.slot < start + 128)
                    .filter(|b| b.slot <= range.stamp.finalized_slot)
                    .cloned()
                    .collect();
                assert_eq!(range.value, want, "range from {start} at {:?}", range.stamp);
                reads += 1;
            }
        });
        assert!(reads > 0, "no read ran while the writer committed");
        assert!(
            seen.len() > 1,
            "the reads never saw the writer move: {seen:?}"
        );
    }

    /// With no stamp row in the snapshot every read is `Unavailable` and serves no bytes, even
    /// though `blocks`, `block_index` and `columns` rows are there (committed raw, as no writer
    /// path may).
    #[test]
    fn no_stamp_unservable() {
        let store = Store::new();
        let fulu = common::fulu_block(5, [0; 32], 1);
        let (ssz, root) = (
            ssz::Encode::as_ssz_bytes(&fulu),
            common::message_root(&fulu),
        );
        let column_key = [&slot_root_key(5, &root)[..], &0u64.to_be_bytes()].concat();
        let sidecar = common::fulu_sidecar(&fulu, 0);
        let w = store.writer();
        let block_key = slot_root_key(5, &root);
        seed_unstamped(w, BLOCKS, &[(&block_key[..], &ssz[..])]).unwrap();
        seed_unstamped(w, BLOCK_INDEX, &[(&root[..], &5u64.to_be_bytes()[..])]).unwrap();
        seed_unstamped(w, COLUMNS, &[(&column_key[..], &sidecar[..])]).unwrap();
        let reader = store.reader();
        let rows = env_rows(&reader);
        for table in [BLOCKS, BLOCK_INDEX, COLUMNS] {
            let (_, held) = rows.iter().find(|(t, _)| *t == Some(table)).unwrap();
            assert_eq!(held.len(), 1, "{table} holds the seeded row");
        }

        let dl = deadline();
        for at in [
            BlockRef::Root(root),
            BlockRef::Slot(5),
            BlockRef::Head,
            BlockRef::Finalized,
        ] {
            assert_eq!(reader.block(at, &dl), Err(ReadError::Unavailable), "{at:?}");
        }
        assert_eq!(reader.head(&dl), Err(ReadError::Unavailable));
        assert_eq!(
            reader.finalized_blocks(0, 128, &dl),
            Err(ReadError::Unavailable)
        );
        let walk: Vec<_> = ParentWalk::new(Arc::new(reader), root, 8, dl).collect();
        assert_eq!(walk, [Err(ReadError::Unavailable)]);
    }

    /// `n` blocks on one chain, slots 1 to `n`, stamped head and finalized at the last: their
    /// roots, by slot - 1.
    fn linear(store: &Store, n: u64) -> Vec<Root> {
        let (mut ssz, mut roots, mut parent) = (Vec::new(), Vec::new(), [0; 32]);
        for slot in 1..=n {
            let (block, root) = block(slot, parent, 0);
            ssz.push(block);
            roots.push(root);
            parent = root;
        }
        let blocks: Vec<&[u8]> = ssz.iter().map(Vec::as_slice).collect();
        store.import(&blocks, stamp(1, (n, parent), (n, parent)));
        roots
    }

    /// #230 D3b: a walk's deadline bounds when a step may start; each step's read transaction
    /// still ends within the step timeout of the step's start, however far off the walk's
    /// deadline is. On a clock that moves 1 s at every look (a step looks once as it starts,
    /// and twice in its transaction), a 2 s step fails its first read `DeadlineExceeded`, and
    /// a 3 s step walks on, under the same 600 s walk deadline.
    #[test]
    fn parent_walk_step_txn_bounded() {
        let store = Store::new();
        let roots = linear(&store, 4);
        let reader = Arc::new(store.reader());
        let walk = |step: u64| {
            let ticks = AtomicU64::new(0);
            let t0 = Instant::now();
            let clock: Clock =
                Arc::new(move || t0 + Duration::from_secs(ticks.fetch_add(1, Ordering::SeqCst)));
            let deadline = Deadline::after(clock, Duration::from_secs(600));
            ParentWalk::new(Arc::clone(&reader), roots[3], 4, deadline)
                .with_step_timeout(Duration::from_secs(step))
                .map(|b| b.map(|b| b.value.slot))
                .collect::<Vec<_>>()
        };
        assert_eq!(walk(2), [Err(ReadError::DeadlineExceeded)]);
        assert_eq!(walk(3), [Ok(4), Ok(3), Ok(2), Ok(1)]);
    }

    /// #230 (Cole NIT 3 of part A): the first step's read transaction is checked against the
    /// call's deadline, taken when the call came in, not the step timeout from the step's
    /// start: time the call spent queued before its first step counts. A walk whose call came
    /// in 2.5 s before its first step, under a 2 s call timeout, fails that step
    /// `DeadlineExceeded`; without the call's deadline the step has its own 2 s and reads. The
    /// steps after the first still get the step timeout from their own start.
    #[test]
    fn parent_walk_first_step_from_the_call() {
        let store = Store::new();
        let roots = linear(&store, 4);
        let reader = Arc::new(store.reader());
        let (t0, ms) = (Instant::now(), Arc::new(AtomicU64::new(0)));
        let clock: Clock = {
            let ms = Arc::clone(&ms);
            Arc::new(move || t0 + Duration::from_millis(ms.load(Ordering::SeqCst)))
        };
        let walk = |from_the_call: bool| {
            ms.store(0, Ordering::SeqCst);
            let call = Deadline::after(Arc::clone(&clock), Duration::from_secs(2));
            let deadline = Deadline::after(Arc::clone(&clock), Duration::from_secs(600));
            let walk = ParentWalk::new(Arc::clone(&reader), roots[3], 4, deadline)
                .with_step_timeout(Duration::from_secs(2));
            let mut walk = if from_the_call {
                walk.with_first_deadline(call)
            } else {
                walk
            };
            // Queued 2.5 s before the first step.
            ms.store(2_500, Ordering::SeqCst);
            let first = walk.next().map(|b| b.map(|b| b.value.slot));
            // 3 s on: past the call's deadline, but each further step has its own 2 s.
            ms.store(5_500, Ordering::SeqCst);
            let rest: Vec<_> = walk.map(|b| b.map(|b| b.value.slot)).collect();
            (first, rest)
        };
        assert_eq!(
            walk(true),
            (Some(Err(ReadError::DeadlineExceeded)), Vec::new()),
            "the call's 2 s"
        );
        assert_eq!(
            walk(false),
            (Some(Ok(4)), vec![Ok(3), Ok(2), Ok(1)]),
            "the step's own 2 s"
        );
    }

    /// A block by slot is the canonical one of the snapshot's own stamp: the block on the
    /// parent walk from its head. A skipped slot, a slot above the head and a slot whose only
    /// block is on a fork are `NotFound`. After a reorg the same slots read the new chain.
    #[test]
    fn get_block_by_slot() {
        let store = Store::new();
        let (a, ra) = block(10, [0; 32], 1);
        let (b, rb) = block(11, ra, 2);
        let (c, rc) = block(12, rb, 3);
        let (d, rd) = block(14, rc, 4);
        // A fork off B: C' at 12 and E' at 15.
        let (c2, rc2) = block(12, rb, 30);
        let (e2, re2) = block(15, rc2, 50);
        store.import(&[&a, &b, &c, &d, &c2, &e2], stamp(1, (14, rd), (11, rb)));
        let reader = store.reader();
        let dl = deadline();
        let by_slot = |slot| {
            reader
                .block(BlockRef::Slot(slot), &dl)
                .map(|s| (s.value.root, s.value.finalized))
        };
        assert_eq!(by_slot(10), Ok((ra, true)));
        assert_eq!(by_slot(11), Ok((rb, true)));
        assert_eq!(by_slot(12), Ok((rc, false)), "C, not the fork's C'");
        assert_eq!(by_slot(13), Err(ReadError::NotFound), "skipped");
        assert_eq!(by_slot(14), Ok((rd, false)));
        assert_eq!(by_slot(15), Err(ReadError::NotFound), "above the head");
        assert_eq!(
            by_slot(9),
            Err(ReadError::NotFound),
            "below the stored chain"
        );
        let got = reader.block(BlockRef::Slot(14), &dl).unwrap();
        assert_eq!((got.value.slot, &got.value.ssz), (14, &d));
        assert_eq!(got.stamp, stamp(1, (14, rd), (11, rb)));
        // By root a fork block is there, not finalized; a finalized one is.
        let fork = reader.block(BlockRef::Root(rc2), &dl).unwrap();
        assert_eq!((fork.value.slot, fork.value.finalized), (12, false));
        assert!(
            reader
                .block(BlockRef::Root(ra), &dl)
                .unwrap()
                .value
                .finalized
        );

        // Reorg to E': the same snapshot rule now reads the fork.
        store.import(&[], stamp(2, (15, re2), (11, rb)));
        assert_eq!(by_slot(12), Ok((rc2, false)));
        assert_eq!(
            by_slot(14),
            Err(ReadError::NotFound),
            "D is off the new chain"
        );
        assert_eq!(by_slot(15), Ok((re2, false)));
        assert_eq!(by_slot(11), Ok((rb, true)));
        let head = reader.block(BlockRef::Head, &dl).unwrap();
        assert_eq!((head.value.root, head.stamp.head_seq), (re2, 2));
    }
}
