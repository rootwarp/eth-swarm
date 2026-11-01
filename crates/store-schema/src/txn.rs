//! The one way a write transaction of the env commits: with its stamp row ([`crate::stamp`]).
//!
//! No writer path calls `commit()` on a write transaction itself; `scripts/check-stamped-commits.sh`
//! fails CI on one outside this file.

use libmdbx::WriteFlags;

use crate::{
    env::RwTxn,
    keys::STAMP_KEY,
    stamp::{self, Stamp},
    tables::META,
    Error, Result,
};

/// The stamp row a commit writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Update {
    /// A new head or finalized checkpoint (block import), checked as [`stamp::read`] checks a
    /// stored one before it is written.
    New(Stamp),
    /// The stored stamp, unchanged: a transaction that moves neither (columns, custody, the
    /// writer's open). It is checked again, so a transaction that removed the stamp's block
    /// fails. Before the first stamp there is nothing to carry and no row is written: the env
    /// has no head yet and no `blocks` row, so data and stamp still agree.
    Carry,
}

/// Writes `update`'s stamp row into `txn`, then commits it. Returns the stamp committed, `None`
/// for a [`Update::Carry`] before the first stamp. On an error `txn` is dropped, so nothing of
/// it is written.
pub fn commit(txn: RwTxn<'_>, update: Update) -> Result<Option<Stamp>> {
    let stamp = match update {
        Update::New(stamp) => {
            stamp.check(&txn)?;
            Some(stamp)
        }
        Update::Carry => stamp::read(&txn)?,
    };
    if let Some(stamp) = &stamp {
        let meta = txn.open_table(Some(META))?;
        txn.put(&meta, STAMP_KEY, stamp.encode(), WriteFlags::UPSERT)?;
    }
    txn.commit().map_err(Error::from)?;
    Ok(stamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keys::STAMP_KEY,
        stamp::tests::{env_with_blocks, valid},
        tables::{META, STATES},
    };
    use libmdbx::WriteFlags;

    fn stamp_row(writer: &crate::env::WriterEnv) -> Option<Vec<u8>> {
        let txn = writer.env().begin_ro_txn().unwrap();
        let meta = txn.open_table(Some(META)).unwrap();
        txn.get::<Vec<u8>>(&meta, STAMP_KEY).unwrap()
    }

    fn put_state(txn: &RwTxn<'_>, key: &[u8]) {
        let states = txn.open_table(Some(STATES)).unwrap();
        txn.put(&states, key, b"state", WriteFlags::UPSERT).unwrap();
    }

    fn has_state(writer: &crate::env::WriterEnv, key: &[u8]) -> bool {
        let txn = writer.env().begin_ro_txn().unwrap();
        let states = txn.open_table(Some(STATES)).unwrap();
        txn.get::<Vec<u8>>(&states, key).unwrap().is_some()
    }

    /// Open question 1's default: before the first stamp there is nothing to carry, so a
    /// `Carry` commit writes its data and no stamp row.
    #[test]
    fn carry_before_the_first_stamp_writes_no_stamp() {
        let (_dir, writer) = env_with_blocks();
        let txn = writer.env().begin_rw_txn().unwrap();
        put_state(&txn, b"one");
        assert_eq!(commit(txn, Update::Carry).unwrap(), None);
        assert!(has_state(&writer, b"one"));
        assert_eq!(stamp_row(&writer), None);
    }

    /// `New` writes the stamp with the data; `Carry` commits the same stamp, byte for byte.
    #[test]
    fn carry_keeps_the_stamp_unchanged() {
        let (_dir, writer) = env_with_blocks();
        let txn = writer.env().begin_rw_txn().unwrap();
        put_state(&txn, b"one");
        assert_eq!(commit(txn, Update::New(valid())).unwrap(), Some(valid()));
        let row = stamp_row(&writer).unwrap();
        assert_eq!(row, valid().encode());
        let txn = writer.env().begin_rw_txn().unwrap();
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
        let txn = writer.env().begin_rw_txn().unwrap();
        put_state(&txn, b"one");
        let err = commit(txn, Update::Carry).unwrap_err();
        assert!(matches!(err, Error::MalformedStamp { len: 87 }), "{err:?}");
        assert!(!has_state(&writer, b"one"));
    }
}
