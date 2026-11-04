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
//! the stamp's head (from its finalized block, for a slot at or below it); a skipped slot, or a
//! slot whose only blocks are off that chain, is [`ReadError::NotFound`].
//!
//! Every transaction runs under its call's [`Deadline`], checked when it opens, every
//! [`DEADLINE_EVERY`] blocks it walks and once more before its data is returned, so a slow read
//! cannot pin MVCC pages past it. [`ParentWalk`] (`GetBlocksByHead`) is stamped once, by its
//! first transaction, then reads each further block in a short transaction of its own.

use std::{
    borrow::Borrow,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use store_schema::env::{self, Env, RoTxn};
pub use store_schema::{keys::Root, stamp::Stamp};

/// A monotonic clock. The server's is [`system_clock`]; tests inject their own.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// [`Instant::now`].
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(Instant::now)
}

/// How many blocks a walk reads between two looks at its deadline.
pub const DEADLINE_EVERY: usize = 64;

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
    /// env cannot be read now (out of reader slots, busy, wants recovery).
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
        })
    }

    /// A reader of an env this process already has open (the writer's own, in tests): MDBX
    /// refuses a second open of one env in one process.
    #[cfg(test)]
    pub(crate) fn over(env: impl Borrow<Env> + Send + Sync + 'static) -> Self {
        Self { env: Box::new(env) }
    }

    pub(crate) fn env(&self) -> &Env {
        (*self.env).borrow()
    }

    /// The block `at` names, with the stamp of the transaction it was read in.
    ///
    /// # Errors
    ///
    /// [`ReadError`].
    pub fn block(&self, at: BlockRef, deadline: &Deadline) -> Result<Stamped<Block>, ReadError> {
        let _ = (at, deadline);
        Err(ReadError::Internal)
    }

    /// The stamp alone: the head and finalized block the env was last committed with.
    ///
    /// # Errors
    ///
    /// [`ReadError`].
    pub fn head(&self, deadline: &Deadline) -> Result<Stamp, ReadError> {
        let _ = deadline;
        Err(ReadError::Internal)
    }

    /// One stamped read: `f` runs in a read transaction with the stamp row read in it.
    pub(crate) fn read<T>(
        &self,
        deadline: &Deadline,
        f: impl FnOnce(&Snapshot<'_>, &Stamp) -> Result<T, ReadError>,
    ) -> Result<Stamped<T>, ReadError> {
        let _ = (deadline, f);
        Err(ReadError::Internal)
    }
}

/// One read transaction under its call's deadline.
pub(crate) struct Snapshot<'r> {
    txn: RoTxn<'r>,
}

/// `GetBlocksByHead`: the block at a root, then its parent, and so on, newest first. The first
/// step reads the stamp and the block in one transaction; it stamps every block. Each further
/// step reads one block in a short transaction of its own, under the same deadline, whatever
/// the stamp is by then. The walk ends after `count` blocks, at a parent that is not stored, or
/// at once for an unknown root; it fuses after an error.
pub struct ParentWalk {
    reader: Arc<Reader>,
    deadline: Deadline,
    next: Option<Root>,
    left: u64,
}

impl ParentWalk {
    #[must_use]
    pub fn new(reader: Arc<Reader>, root: Root, count: u64, deadline: Deadline) -> Self {
        Self {
            reader,
            deadline,
            next: Some(root),
            left: count,
        }
    }
}

impl Iterator for ParentWalk {
    type Item = Result<Stamped<Block>, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        let _ = (&self.reader, &self.deadline, self.left);
        self.next.take().map(|_| Err(ReadError::Internal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{self, block, common, deadline, stamp, Store};
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicBool, Ordering},
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
        let txn = reader.env().begin_ro_txn().unwrap();
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

    /// cl-store opens the env read-only: a write transaction, and a put, a delete, a table
    /// create and a table drop in a read transaction of the reader's env, each straight
    /// through the C API, all fail with `EACCES`, and the env reads back unchanged, through
    /// the reader too.
    #[test]
    fn cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        let (ssz, root) = block(9, [0; 32], 1);
        {
            let writer = env::test_writer(dir.path()).unwrap();
            testkit::import(&writer, &[&ssz], stamp(1, (9, root), (9, root)));
        }
        let reader = Reader::open(dir.path()).expect("the env opens read-only");
        let before = env_rows(&reader);
        let served = reader.block(BlockRef::Root(root), &deadline());
        assert_eq!(
            served.as_ref().map(|b| b.value.ssz == ssz),
            Ok(true),
            "the reader serves the stored block"
        );

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
        let key = slot_root_key(9, &root);
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
        drop(blocks);
        drop(ro);
        assert_eq!(env_rows(&reader), before, "a write changed the env");
        assert_eq!(reader.block(BlockRef::Root(root), &deadline()), served);
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
