//! The one way a write transaction of the env commits: with its stamp row ([`crate::stamp`]).
//!
//! No writer path calls `commit()` on a write transaction itself; `scripts/check-stamped-commits.sh`
//! fails CI on one outside this file. The writer's open commits through `commit_open`, called
//! only from [`crate::env::open_writer_with`] (the same script enforces that).
//!
//! A write transaction begins with [`begin`] and commits with [`commit`]:
//!
//! ```no_run
//! use libmdbx::WriteFlags;
//! use store_schema::{env::WriterEnv, tables::STATES, txn::{self, Update}};
//!
//! fn put_state(writer: &WriterEnv) -> store_schema::Result<()> {
//!     let txn = txn::begin(writer)?;
//!     let states = txn.open_table(Some(STATES))?;
//!     txn.put(&states, b"key", b"state", WriteFlags::UPSERT)?;
//!     txn::commit(txn, Update::Carry)?;
//!     Ok(())
//! }
//! ```
//!
//! The transaction has no commit of its own:
//!
//! ```compile_fail,E0599
//! # use store_schema::{env::WriterEnv, txn};
//! fn raw(writer: &WriterEnv) -> store_schema::Result<()> {
//!     let txn = txn::begin(writer)?;
//!     txn.commit()?;
//!     Ok(())
//! }
//! ```
//!
//! nor a way to the libmdbx transaction inside it:
//!
//! ```compile_fail,E0616
//! # use store_schema::{env::WriterEnv, txn};
//! fn raw(writer: &WriterEnv) -> store_schema::Result<()> {
//!     let txn = txn::begin(writer)?;
//!     txn.0.commit()?;
//!     Ok(())
//! }
//! ```
//!
//! and outside this crate the env begins no raw write transaction:
//!
//! ```compile_fail,E0624
//! # use store_schema::env::WriterEnv;
//! fn raw(writer: &WriterEnv) -> store_schema::Result<()> {
//!     writer.begin_rw_txn()?.commit()?;
//!     Ok(())
//! }
//! ```

use libmdbx::{Cursor, Decodable, NoWriteMap, Table, Transaction, TransactionKind, WriteFlags, RW};

use crate::{
    env::WriterEnv,
    keys::STAMP_KEY,
    stamp::{self, Stamp},
    tables::{BLOCKS, BLOCK_INDEX, META},
    Error, Result,
};

/// A write transaction of the env ([`begin`], and [`open_writer_with`]'s upgrade hook). It has
/// no commit of its own and, but for the `test-hooks` seam (a shared reference), no way to the
/// libmdbx transaction inside it: it commits only through [`commit`]; dropped, it aborts and
/// writes nothing.
///
/// [`open_writer_with`]: crate::env::open_writer_with
#[derive(Debug)]
pub struct RwTxn<'env>(Transaction<'env, RW, NoWriteMap>);

impl<'env> RwTxn<'env> {
    pub(crate) fn new(txn: Transaction<'env, RW, NoWriteMap>) -> Self {
        Self(txn)
    }

    /// The libmdbx transaction, for this crate's own reads and table creation.
    pub(crate) fn raw(&self) -> &Transaction<'env, RW, NoWriteMap> {
        &self.0
    }

    /// The libmdbx transaction back, for this crate's tests that commit rows raw, as no writer
    /// path may (blocks with no stamp).
    #[cfg(test)]
    pub(crate) fn into_raw(self) -> Transaction<'env, RW, NoWriteMap> {
        self.0
    }

    /// The libmdbx transaction, for tests that change a store as no writer path may (drop a
    /// table). Only with the `test-hooks` feature; a shared reference, so it cannot commit.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn raw_txn(&self) -> &Transaction<'env, RW, NoWriteMap> {
        self.raw()
    }

    /// libmdbx's `Transaction::open_table`.
    pub fn open_table(&self, name: Option<&str>) -> libmdbx::Result<Table<'_>> {
        self.0.open_table(name)
    }

    /// libmdbx's `Transaction::get`.
    pub fn get<'txn, V: Decodable<'txn>>(
        &'txn self,
        table: &Table<'txn>,
        key: &[u8],
    ) -> libmdbx::Result<Option<V>> {
        self.0.get(table, key)
    }

    /// libmdbx's `Transaction::cursor`.
    pub fn cursor<'txn>(&'txn self, table: &Table<'txn>) -> libmdbx::Result<Cursor<'txn, RW>> {
        self.0.cursor(table)
    }

    /// libmdbx's `Transaction::put`.
    pub fn put<'txn>(
        &'txn self,
        table: &Table<'txn>,
        key: impl AsRef<[u8]>,
        data: impl AsRef<[u8]>,
        flags: WriteFlags,
    ) -> libmdbx::Result<()> {
        self.0.put(table, key, data, flags)
    }

    /// libmdbx's `Transaction::del`: whether a row was deleted.
    pub fn del<'txn>(
        &'txn self,
        table: &Table<'txn>,
        key: impl AsRef<[u8]>,
        data: Option<&[u8]>,
    ) -> libmdbx::Result<bool> {
        self.0.del(table, key, data)
    }
}

/// The reads of a transaction of the env, a write one ([`RwTxn`]) or a libmdbx read one: what a
/// read helper that runs in both takes, as `&impl ReadTxn`.
pub trait ReadTxn {
    /// The kind of the transaction's cursors.
    type Kind: TransactionKind;

    /// libmdbx's `Transaction::open_table`.
    fn open_table(&self, name: Option<&str>) -> libmdbx::Result<Table<'_>>;

    /// libmdbx's `Transaction::get`.
    fn get<'txn, V: Decodable<'txn>>(
        &'txn self,
        table: &Table<'txn>,
        key: &[u8],
    ) -> libmdbx::Result<Option<V>>;

    /// libmdbx's `Transaction::cursor`.
    fn cursor<'txn>(&'txn self, table: &Table<'txn>) -> libmdbx::Result<Cursor<'txn, Self::Kind>>;
}

impl ReadTxn for RwTxn<'_> {
    type Kind = RW;

    fn open_table(&self, name: Option<&str>) -> libmdbx::Result<Table<'_>> {
        RwTxn::open_table(self, name)
    }

    fn get<'txn, V: Decodable<'txn>>(
        &'txn self,
        table: &Table<'txn>,
        key: &[u8],
    ) -> libmdbx::Result<Option<V>> {
        RwTxn::get(self, table, key)
    }

    fn cursor<'txn>(&'txn self, table: &Table<'txn>) -> libmdbx::Result<Cursor<'txn, RW>> {
        RwTxn::cursor(self, table)
    }
}

impl<K: TransactionKind> ReadTxn for Transaction<'_, K, NoWriteMap> {
    type Kind = K;

    fn open_table(&self, name: Option<&str>) -> libmdbx::Result<Table<'_>> {
        Transaction::open_table(self, name)
    }

    fn get<'txn, V: Decodable<'txn>>(
        &'txn self,
        table: &Table<'txn>,
        key: &[u8],
    ) -> libmdbx::Result<Option<V>> {
        Transaction::get(self, table, key)
    }

    fn cursor<'txn>(&'txn self, table: &Table<'txn>) -> libmdbx::Result<Cursor<'txn, K>> {
        Transaction::cursor(self, table)
    }
}

/// A write transaction of `writer`'s env. It commits only through [`commit`].
pub fn begin(writer: &WriterEnv) -> Result<RwTxn<'_>> {
    writer.begin_rw_txn()
}

/// The stamp row a commit writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Update {
    /// A new head or finalized checkpoint (block import), checked as [`stamp::read`] checks a
    /// stored one before it is written, and against the stamp stored before it, if any:
    /// `head_seq` never goes down ([`Error::StampSeqDecrease`]), one `head_seq` names one head
    /// root ([`Error::StampSeqReused`]), and the finalized slot never goes down
    /// ([`Error::StampFinalizedDecrease`]). The same stamp again, and any forward move (a reorg
    /// to a lower head slot included), passes.
    New(Stamp),
    /// The stored stamp, unchanged: a transaction that moves neither (columns, custody). It is
    /// checked again, so a transaction that removed the stamp's block fails.
    ///
    /// Before the first stamp there is nothing to carry. The transaction commits with no stamp
    /// row only while `blocks` and `block_index` are empty as it sees them, its own puts
    /// included: a row in either would be a block with no head, so the commit is refused
    /// ([`Error::StampMissing`], `blocks` checked first) and writes nothing. Columns and custody
    /// before any block commit unstamped. The full rule, no `Carry` before the first stamp for
    /// any table, is turned on later, once a production stamp writer exists (#208a).
    Carry,
}

/// Writes `update`'s stamp row into `txn`, then commits it. Returns the stamp committed, `None`
/// for a [`Update::Carry`] before the first stamp (with `blocks` and `block_index` empty). On
/// an error ([`Update`] names the rules) `txn` is dropped, so nothing of it is written.
pub fn commit(txn: RwTxn<'_>, update: Update) -> Result<Option<Stamp>> {
    let stamp = match update {
        Update::New(new) => {
            new.check(&txn)?;
            let meta = txn.open_table(Some(META))?;
            if let Some(row) = txn.get::<Vec<u8>>(&meta, STAMP_KEY)? {
                // Decoded only: the txn may have pruned the stored stamp's blocks.
                moves_forward(&Stamp::decode(&row)?, &new)?;
            }
            Some(new)
        }
        Update::Carry => carried(&txn)?,
    };
    write(txn, stamp)
}

/// The commit of the writer's open ([`crate::env::open_writer_with`], its only caller). With a
/// stamp stored it is [`commit`] with [`Update::Carry`]. With none it commits no stamp row, and
/// is refused ([`Error::StampMissing`]) if `blocks` or `block_index` holds a row: a store
/// written raw, or a v1 store with blocks and no stamp. Apart from [`Update::Carry`] so the open
/// of a fresh store keeps committing once a `Carry` with no stamp is refused outright (#208a).
pub(crate) fn commit_open(txn: RwTxn<'_>) -> Result<Option<Stamp>> {
    let stamp = carried(&txn)?;
    write(txn, stamp)
}

/// The stored stamp, checked; `None` before the first one, if `blocks` and `block_index` are
/// empty as `txn` sees them, else [`Error::StampMissing`] naming the first that is not.
fn carried(txn: &RwTxn<'_>) -> Result<Option<Stamp>> {
    let stamp = stamp::read(txn)?;
    if stamp.is_none() {
        for table in [BLOCKS, BLOCK_INDEX] {
            let handle = txn.open_table(Some(table))?;
            if txn.cursor(&handle)?.first::<(), ()>()?.is_some() {
                return Err(Error::StampMissing { table });
            }
        }
    }
    Ok(stamp)
}

/// [`Update::New`]'s rules for `new` over the `stored` stamp.
fn moves_forward(stored: &Stamp, new: &Stamp) -> Result<()> {
    if new.head_seq < stored.head_seq {
        return Err(Error::StampSeqDecrease {
            stored: stored.head_seq,
            new: new.head_seq,
        });
    }
    if new.head_seq == stored.head_seq && new.head_root != stored.head_root {
        return Err(Error::StampSeqReused { seq: new.head_seq });
    }
    if new.finalized_slot < stored.finalized_slot {
        return Err(Error::StampFinalizedDecrease {
            stored: stored.finalized_slot,
            new: new.finalized_slot,
        });
    }
    Ok(())
}

/// Writes `stamp`'s row, if any, into `txn` and commits it.
fn write(txn: RwTxn<'_>, stamp: Option<Stamp>) -> Result<Option<Stamp>> {
    if let Some(stamp) = &stamp {
        let meta = txn.open_table(Some(META))?;
        txn.put(&meta, STAMP_KEY, stamp.encode(), WriteFlags::UPSERT)?;
    }
    txn.0.commit().map_err(Error::from)?;
    Ok(stamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blocks,
        env::{self, WriterEnv, WriterOptions, MIN_MAX_SIZE},
        keys::{slot_root_key, Root, STAMP_KEY},
        stamp::tests::{env_with_blocks, valid, A, B},
        tables::{BLOCKS, BLOCK_INDEX, COLUMNS, META, STATES, TABLES},
        testkit::{fulu_block_ssz, schedule, E},
    };
    use libmdbx::WriteFlags;

    const C: Root = [0xcc; 32];
    const D: Root = [0xdd; 32];

    /// Every table's rows, in [`TABLES`] order, each in key order: the whole env.
    type Snapshot = Vec<(&'static str, Vec<(Vec<u8>, Vec<u8>)>)>;

    /// A writer env as the first open leaves it: every table, no row but the version.
    fn fresh() -> (tempfile::TempDir, WriterEnv) {
        let dir = tempfile::tempdir().unwrap();
        let writer = env::open_writer(
            dir.path(),
            WriterOptions {
                max_size: MIN_MAX_SIZE,
            },
        )
        .unwrap();
        (dir, writer)
    }

    fn snapshot(writer: &WriterEnv) -> Snapshot {
        let txn = writer.env().begin_ro_txn().unwrap();
        TABLES
            .iter()
            .map(|&table| {
                let handle = txn.open_table(Some(table)).unwrap();
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

    /// Puts `rows` into `table` and commits raw, past every rule of [`commit`]: a store left by
    /// a writer of before the rule.
    fn seed(writer: &WriterEnv, table: &str, rows: &[(&[u8], &[u8])]) {
        let txn = writer.env().begin_rw_txn().unwrap();
        let handle = txn.open_table(Some(table)).unwrap();
        for (key, value) in rows {
            txn.put(&handle, *key, *value, WriteFlags::UPSERT).unwrap();
        }
        txn.commit().unwrap();
    }

    /// Raw `blocks` rows (the stamp checks only that its blocks are stored), committed raw.
    fn seed_blocks(writer: &WriterEnv, blocks: &[(u64, Root)]) {
        let keys: Vec<_> = blocks
            .iter()
            .map(|(slot, root)| slot_root_key(*slot, root))
            .collect();
        let rows: Vec<(&[u8], &[u8])> = keys.iter().map(|k| (&k[..], &b"block"[..])).collect();
        seed(writer, BLOCKS, &rows);
    }

    fn stamp_row(writer: &WriterEnv) -> Option<Vec<u8>> {
        let txn = writer.env().begin_ro_txn().unwrap();
        let meta = txn.open_table(Some(META)).unwrap();
        txn.get::<Vec<u8>>(&meta, STAMP_KEY).unwrap()
    }

    fn put_state(txn: &RwTxn<'_>, key: &[u8]) {
        let states = txn.open_table(Some(STATES)).unwrap();
        txn.put(&states, key, b"state", WriteFlags::UPSERT).unwrap();
    }

    fn has_state(writer: &WriterEnv, key: &[u8]) -> bool {
        let txn = writer.env().begin_ro_txn().unwrap();
        let states = txn.open_table(Some(STATES)).unwrap();
        txn.get::<Vec<u8>>(&states, key).unwrap().is_some()
    }

    /// A `columns` key: `slot BE ‖ root ‖ index BE`.
    fn column_key(slot: u64, root: &Root, index: u64) -> Vec<u8> {
        [&slot_root_key(slot, root)[..], &index.to_be_bytes()].concat()
    }

    fn put_column(txn: &RwTxn<'_>, key: &[u8]) {
        let columns = txn.open_table(Some(COLUMNS)).unwrap();
        txn.put(&columns, key, b"column", WriteFlags::UPSERT)
            .unwrap();
    }

    fn column(writer: &WriterEnv, key: &[u8]) -> Option<Vec<u8>> {
        let txn = writer.env().begin_ro_txn().unwrap();
        let columns = txn.open_table(Some(COLUMNS)).unwrap();
        txn.get::<Vec<u8>>(&columns, key).unwrap()
    }

    /// Commits a state and a column row with `Carry`; expects [`Error::StampMissing`] naming
    /// `table`, and the env exactly as before: every table's rows, and still no stamp row.
    fn carry_refused(writer: &WriterEnv, table: &str) {
        let before = snapshot(writer);
        let txn = begin(writer).unwrap();
        put_state(&txn, b"one");
        put_column(&txn, &column_key(5, &A, 0));
        let err = commit(txn, Update::Carry).unwrap_err();
        assert!(
            matches!(err, Error::StampMissing { table: t } if t == table),
            "{err:?}"
        );
        assert_eq!(
            snapshot(writer),
            before,
            "the refused commit changed the env"
        );
        assert_eq!(stamp_row(writer), None);
    }

    /// Before the first stamp there is nothing to carry: with `blocks` and `block_index` empty a
    /// `Carry` commit writes its data and no stamp row. With `blocks` rows it is refused
    /// ([`Error::StampMissing`]), and its data is not committed: those blocks would have no
    /// head.
    #[test]
    fn carry_before_the_first_stamp_writes_no_stamp() {
        let (_empty, writer) = fresh();
        let txn = begin(&writer).unwrap();
        put_state(&txn, b"one");
        assert_eq!(commit(txn, Update::Carry).unwrap(), None);
        assert!(has_state(&writer, b"one"));
        assert_eq!(stamp_row(&writer), None);

        let (_dir, writer) = env_with_blocks();
        let txn = begin(&writer).unwrap();
        put_state(&txn, b"one");
        let err = commit(txn, Update::Carry).unwrap_err();
        assert!(
            matches!(err, Error::StampMissing { table: "blocks" }),
            "{err:?}"
        );
        assert!(!has_state(&writer, b"one"));
        assert_eq!(stamp_row(&writer), None);
    }

    /// S1: `blocks` rows and no stamp (a store written raw): a `Carry` of a state and a column
    /// row is refused and commits nothing.
    #[test]
    fn carry_with_blocks_and_no_stamp_is_refused() {
        let (_dir, writer) = env_with_blocks();
        assert_eq!(snapshot(&writer)[4].1.len(), 2, "A and B are seeded");
        carry_refused(&writer, "blocks");
    }

    /// S1: a `block_index` row alone is enough, and the error names that table.
    #[test]
    fn carry_with_block_index_and_no_stamp_is_refused() {
        let (_dir, writer) = fresh();
        seed(&writer, BLOCK_INDEX, &[(&B, &9u64.to_be_bytes())]);
        carry_refused(&writer, "block_index");
    }

    /// S1 counts the rows the txn itself writes: a `Carry` that puts the first block (both its
    /// rows, through [`blocks::put`]) or only a `block_index` row on a fresh, unstamped store
    /// is refused and commits nothing.
    #[test]
    fn carry_that_writes_the_first_block_is_refused() {
        let (_dir, writer) = fresh();
        let before = snapshot(&writer);
        let (ssz, root) = fulu_block_ssz(5, [0; 32], 1);
        let txn = begin(&writer).unwrap();
        assert_eq!(
            blocks::put::<E>(&txn, &schedule(), &ssz).unwrap(),
            (5, root)
        );
        put_state(&txn, &slot_root_key(5, &root));
        let err = commit(txn, Update::Carry).unwrap_err();
        assert!(
            matches!(err, Error::StampMissing { table: "blocks" }),
            "{err:?}"
        );
        assert_eq!(snapshot(&writer), before);

        let txn = begin(&writer).unwrap();
        let index = txn.open_table(Some(BLOCK_INDEX)).unwrap();
        txn.put(&index, root, 5u64.to_be_bytes(), WriteFlags::UPSERT)
            .unwrap();
        let err = commit(txn, Update::Carry).unwrap_err();
        assert!(
            matches!(
                err,
                Error::StampMissing {
                    table: "block_index"
                }
            ),
            "{err:?}"
        );
        assert_eq!(snapshot(&writer), before);
        assert_eq!(stamp_row(&writer), None);
    }

    /// S1's other side: with `blocks` and `block_index` empty, column and custody writes before
    /// any block commit with `Carry` and no stamp row.
    #[test]
    fn carry_of_columns_before_any_block_commits_without_a_stamp() {
        let (_dir, writer) = fresh();
        let key = column_key(5, &A, 3);
        let txn = begin(&writer).unwrap();
        put_column(&txn, &key);
        let meta = txn.open_table(Some(META)).unwrap();
        txn.put(&meta, b"cgc", 8u64.to_be_bytes(), WriteFlags::UPSERT)
            .unwrap();
        assert_eq!(commit(txn, Update::Carry).unwrap(), None);
        assert_eq!(column(&writer, &key), Some(b"column".to_vec()));
        assert_eq!(stamp_row(&writer), None);
    }

    /// The import path on a fresh store: blocks and their first stamp in one `New` commit, then
    /// a `Carry` that commits the same stamp row, byte for byte.
    #[test]
    fn new_with_its_blocks_then_carry_on_a_fresh_store() {
        let (_dir, writer) = fresh();
        let schedule = schedule();
        let (ssz_a, a) = fulu_block_ssz(5, [0; 32], 1);
        let (ssz_b, b) = fulu_block_ssz(9, a, 2);
        let txn = begin(&writer).unwrap();
        blocks::put::<E>(&txn, &schedule, &ssz_a).unwrap();
        blocks::put::<E>(&txn, &schedule, &ssz_b).unwrap();
        let stamp = Stamp {
            head_seq: 1,
            head_root: b,
            head_slot: 9,
            finalized_root: a,
            finalized_slot: 5,
        };
        assert_eq!(commit(txn, Update::New(stamp)).unwrap(), Some(stamp));
        let row = stamp_row(&writer).unwrap();
        assert_eq!(row, stamp.encode());

        let key = column_key(9, &b, 0);
        let txn = begin(&writer).unwrap();
        put_state(&txn, b"two");
        put_column(&txn, &key);
        assert_eq!(commit(txn, Update::Carry).unwrap(), Some(stamp));
        assert!(has_state(&writer, b"two"));
        assert_eq!(column(&writer, &key), Some(b"column".to_vec()));
        assert_eq!(stamp_row(&writer).unwrap(), row);
    }

    /// `New` writes the stamp with the data; `Carry` commits the same stamp, byte for byte.
    #[test]
    fn carry_keeps_the_stamp_unchanged() {
        let (_dir, writer) = env_with_blocks();
        let txn = begin(&writer).unwrap();
        put_state(&txn, b"one");
        assert_eq!(commit(txn, Update::New(valid())).unwrap(), Some(valid()));
        let row = stamp_row(&writer).unwrap();
        assert_eq!(row, valid().encode());
        let txn = begin(&writer).unwrap();
        put_state(&txn, b"two");
        assert_eq!(commit(txn, Update::Carry).unwrap(), Some(valid()));
        assert!(has_state(&writer, b"two"));
        assert_eq!(stamp_row(&writer).unwrap(), row);
    }

    /// A stamp row that does not validate fails the `Carry` commit, and the txn's data is not
    /// committed.
    #[test]
    fn an_invalid_stamp_fails_the_carry_and_commits_nothing() {
        let (_dir, writer) = env_with_blocks();
        {
            let txn = writer.env().begin_rw_txn().unwrap();
            let meta = txn.open_table(Some(META)).unwrap();
            txn.put(&meta, STAMP_KEY, [1u8; 87], WriteFlags::UPSERT)
                .unwrap();
            txn.commit().unwrap();
        }
        let txn = begin(&writer).unwrap();
        put_state(&txn, b"one");
        let err = commit(txn, Update::Carry).unwrap_err();
        assert!(matches!(err, Error::MalformedStamp { len: 87 }), "{err:?}");
        assert!(!has_state(&writer, b"one"));
    }

    /// [`env_with_blocks`] (A at 5, B at 9) plus C at 3 and D at 12, with [`valid`] stored:
    /// head B@9 at `head_seq` 7, finalized A@5.
    fn stamped() -> (tempfile::TempDir, WriterEnv) {
        let (dir, writer) = env_with_blocks();
        seed_blocks(&writer, &[(3, C), (12, D)]);
        let txn = begin(&writer).unwrap();
        assert_eq!(commit(txn, Update::New(valid())).unwrap(), Some(valid()));
        (dir, writer)
    }

    /// Commits `new` over the stored stamp with a state row; expects a refusal that leaves the
    /// stamp row byte for byte and every table as it was.
    fn new_refused(writer: &WriterEnv, new: Stamp) -> Error {
        let before = snapshot(writer);
        let row = stamp_row(writer).expect("a stored stamp");
        let txn = begin(writer).unwrap();
        put_state(&txn, b"refused");
        let err = commit(txn, Update::New(new)).unwrap_err();
        assert_eq!(stamp_row(writer).unwrap(), row, "{new:?} rewrote the stamp");
        assert_eq!(snapshot(writer), before, "{new:?} committed data");
        err
    }

    /// Commits `new` with the state row `state`; expects it committed, the stamp row `new`.
    fn new_accepted(writer: &WriterEnv, new: Stamp, state: &[u8]) {
        let txn = begin(writer).unwrap();
        put_state(&txn, state);
        assert_eq!(commit(txn, Update::New(new)).unwrap(), Some(new), "{new:?}");
        assert_eq!(stamp_row(writer).unwrap(), new.encode(), "{new:?}");
        assert!(has_state(writer, state), "{new:?}");
    }

    /// S2: a `head_seq` below the stored one is refused: one below, 0, and with another valid
    /// head (a stale head event). The stored stamp still moves forward afterwards.
    #[test]
    fn new_with_a_lower_head_seq_is_refused() {
        let (_dir, writer) = stamped();
        for new in [
            Stamp {
                head_seq: 6,
                ..valid()
            },
            Stamp {
                head_seq: 0,
                ..valid()
            },
            Stamp {
                head_seq: 6,
                head_root: D,
                head_slot: 12,
                ..valid()
            },
        ] {
            let err = new_refused(&writer, new);
            assert!(
                matches!(err, Error::StampSeqDecrease { stored: 7, new: n } if n == new.head_seq),
                "{err:?}"
            );
        }
        new_accepted(
            &writer,
            Stamp {
                head_seq: 8,
                ..valid()
            },
            b"after",
        );
    }

    /// S2: the stored `head_seq` again with another head root is refused, at a lower and at a
    /// higher head slot: one sequence number never names two heads.
    #[test]
    fn new_reusing_the_head_seq_with_another_root_is_refused() {
        let (_dir, writer) = stamped();
        for (head_root, head_slot) in [(A, 5), (D, 12)] {
            let err = new_refused(
                &writer,
                Stamp {
                    head_root,
                    head_slot,
                    ..valid()
                },
            );
            assert!(matches!(err, Error::StampSeqReused { seq: 7 }), "{err:?}");
        }
        new_accepted(
            &writer,
            Stamp {
                head_seq: 8,
                head_root: D,
                head_slot: 12,
                ..valid()
            },
            b"after",
        );
    }

    /// S2: a finalized slot below the stored one is refused, even with a higher `head_seq`.
    #[test]
    fn new_with_a_lower_finalized_slot_is_refused() {
        let (_dir, writer) = stamped();
        let err = new_refused(
            &writer,
            Stamp {
                head_seq: 8,
                finalized_root: C,
                finalized_slot: 3,
                ..valid()
            },
        );
        assert!(
            matches!(err, Error::StampFinalizedDecrease { stored: 5, new: 3 }),
            "{err:?}"
        );
        new_accepted(
            &writer,
            Stamp {
                head_seq: 8,
                ..valid()
            },
            b"after",
        );
    }

    /// S2's allowed moves over a stored stamp: the same stamp again (same `head_seq`, same head
    /// root), a higher `head_seq` with the same head, a new head, a reorg back to a lower head
    /// slot, the finalized slot equal or higher.
    #[test]
    fn new_moving_forward_or_repeating_is_allowed() {
        let (_dir, writer) = stamped();
        new_accepted(&writer, valid(), b"same stamp");
        new_accepted(
            &writer,
            Stamp {
                head_seq: 8,
                ..valid()
            },
            b"higher seq, same head, same finalized",
        );
        new_accepted(
            &writer,
            Stamp {
                head_seq: 9,
                head_root: D,
                head_slot: 12,
                ..valid()
            },
            b"new head",
        );
        new_accepted(
            &writer,
            Stamp {
                head_seq: 10,
                ..valid()
            },
            b"reorg to a lower head slot",
        );
        let finalized = Stamp {
            head_seq: 11,
            finalized_root: B,
            finalized_slot: 9,
            ..valid()
        };
        new_accepted(&writer, finalized, b"higher finalized");
        new_accepted(&writer, finalized, b"same seq, same root, again");
    }

    /// A `commit` for every type: `x.commit()` resolves to it only if `x`'s type has no
    /// `commit` method of its own for that receiver (an inherent method wins over a trait's).
    trait CommitFallback: Sized {
        fn commit(self) -> NoRawCommit {
            NoRawCommit
        }
    }
    impl<T> CommitFallback for T {}
    struct NoRawCommit;

    /// One item for every type, and a second for a `Deref` type: naming the item of a `Deref`
    /// type is ambiguous, so it does not compile.
    trait AmbiguousIfDeref<A> {
        fn item() {}
    }
    impl<T: ?Sized> AmbiguousIfDeref<()> for T {}
    impl<T: ?Sized + std::ops::Deref> AmbiguousIfDeref<u8> for T {}

    /// An [`RwTxn`] has no raw commit: no `commit` taking it by value, `&` or `&mut` (each call
    /// below resolves to the fallback, so it compiles), and no `Deref` to the libmdbx
    /// transaction, whose `commit` would be one `*` away. Dropped, it writes nothing; it commits
    /// only through [`commit`], under the stamp rules.
    #[test]
    fn rwtxn_no_raw_commit() {
        let _: fn() = <RwTxn<'_> as AmbiguousIfDeref<_>>::item;
        let (_dir, writer) = fresh();
        let mut txn = begin(&writer).unwrap();
        put_state(&txn, b"dropped");
        let NoRawCommit = (&mut txn).commit();
        let NoRawCommit = (&txn).commit();
        let NoRawCommit = txn.commit();
        assert!(
            !has_state(&writer, b"dropped"),
            "a dropped RwTxn wrote its rows"
        );

        let txn = begin(&writer).unwrap();
        put_state(&txn, b"committed");
        assert_eq!(commit(txn, Update::Carry).unwrap(), None);
        assert!(has_state(&writer, b"committed"));
        assert_eq!(stamp_row(&writer), None);
    }

    /// S2: the first `New` on an unstamped store has nothing to compare with, `head_seq` 0
    /// included.
    #[test]
    fn the_first_new_is_allowed_at_any_seq() {
        let (_dir, writer) = env_with_blocks();
        assert_eq!(stamp_row(&writer), None);
        new_accepted(
            &writer,
            Stamp {
                head_seq: 0,
                ..valid()
            },
            b"first",
        );
    }
}
