//! The head stamp: one `meta` row under [`STAMP_KEY`] that every write transaction commits
//! ([`crate::txn::commit`]), so a reader's snapshot holds the blocks and the stamp that names
//! them, never one without the other.
//!
//! [`STAMP_LEN`] bytes: `head_seq (u64 BE) ‖ head_root (32) ‖ head_slot (u64 BE) ‖
//! finalized_root (32) ‖ finalized_slot (u64 BE)`. A row of any other length is
//! [`Error::MalformedStamp`]. A stamp is valid when `finalized_slot <= head_slot` and the
//! `blocks` rows at `(head_slot, head_root)` and `(finalized_slot, finalized_root)` exist;
//! [`read`] checks that, and the writer checks it before it commits a new stamp.

use libmdbx::{NoWriteMap, Transaction, TransactionKind};

use crate::{
    keys::{slot_root_key, Root, STAMP_KEY},
    tables::{BLOCKS, META},
    Error, Result,
};

/// Length of an encoded [`Stamp`].
pub const STAMP_LEN: usize = 8 + 32 + 8 + 32 + 8;

/// The chain's head and finalized checkpoint as of a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// cl-chain's event sequence number of the head.
    pub head_seq: u64,
    /// Root of the head block.
    pub head_root: Root,
    /// Slot of the head block.
    pub head_slot: u64,
    /// Root of the finalized block.
    pub finalized_root: Root,
    /// Slot of the finalized block.
    pub finalized_slot: u64,
}

impl Stamp {
    /// The row value: [`STAMP_LEN`] bytes, integers big-endian.
    #[must_use]
    pub fn encode(&self) -> [u8; STAMP_LEN] {
        let mut out = [0u8; STAMP_LEN];
        out[..8].copy_from_slice(&self.head_seq.to_be_bytes());
        out[8..40].copy_from_slice(&self.head_root);
        out[40..48].copy_from_slice(&self.head_slot.to_be_bytes());
        out[48..80].copy_from_slice(&self.finalized_root);
        out[80..].copy_from_slice(&self.finalized_slot.to_be_bytes());
        out
    }

    /// The stamp a row holds, unchecked against the env; [`Error::MalformedStamp`] unless it is
    /// [`STAMP_LEN`] bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; STAMP_LEN] = bytes
            .try_into()
            .map_err(|_| Error::MalformedStamp { len: bytes.len() })?;
        let word = |at: usize| {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[at..at + 8]);
            u64::from_be_bytes(word)
        };
        let root = |at: usize| {
            let mut root = [0u8; 32];
            root.copy_from_slice(&bytes[at..at + 32]);
            root
        };
        Ok(Self {
            head_seq: word(0),
            head_root: root(8),
            head_slot: word(40),
            finalized_root: root(48),
            finalized_slot: word(80),
        })
    }

    /// Checks the stamp against the env as `txn` sees it: finalized at or below the head, and
    /// both blocks stored at their slots.
    pub(crate) fn check<K: TransactionKind>(
        &self,
        txn: &Transaction<'_, K, NoWriteMap>,
    ) -> Result<()> {
        if self.finalized_slot > self.head_slot {
            return Err(Error::StampFinalizedAfterHead {
                finalized_slot: self.finalized_slot,
                head_slot: self.head_slot,
            });
        }
        let blocks = txn.open_table(Some(BLOCKS))?;
        for (slot, root) in [
            (self.head_slot, self.head_root),
            (self.finalized_slot, self.finalized_root),
        ] {
            if txn
                .get::<()>(&blocks, &slot_root_key(slot, &root))?
                .is_none()
            {
                return Err(Error::StampBlockMissing { slot, root });
            }
        }
        Ok(())
    }
}

/// The stamp `txn` sees, checked; `None` before the first one. A row that is not a valid stamp
/// is an error, never a default.
pub fn read<K: TransactionKind>(txn: &Transaction<'_, K, NoWriteMap>) -> Result<Option<Stamp>> {
    let meta = txn.open_table(Some(META))?;
    let Some(row) = txn.get::<Vec<u8>>(&meta, STAMP_KEY)? else {
        return Ok(None);
    };
    let stamp = Stamp::decode(&row)?;
    stamp.check(txn)?;
    Ok(Some(stamp))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        env::{self, WriterEnv, WriterOptions, MIN_MAX_SIZE},
        keys::{slot_root_key, STAMP_KEY},
        tables::{BLOCKS, META},
        txn::{self, Update},
        Error,
    };
    use libmdbx::WriteFlags;
    use proptest::{
        prelude::*,
        test_runner::{Config, TestRunner},
    };

    pub(crate) const A: Root = [0xaa; 32];
    pub(crate) const B: Root = [0xbb; 32];

    /// A writer env holding block rows A at slot 5 and B at slot 9. Raw rows: the stamp checks
    /// only that its blocks are stored.
    pub(crate) fn env_with_blocks() -> (tempfile::TempDir, WriterEnv) {
        let dir = tempfile::tempdir().unwrap();
        let writer = env::open_writer(
            dir.path(),
            WriterOptions {
                max_size: MIN_MAX_SIZE,
            },
        )
        .unwrap();
        let txn = writer.env().begin_rw_txn().unwrap();
        let blocks = txn.open_table(Some(BLOCKS)).unwrap();
        for (slot, root) in [(5, A), (9, B)] {
            txn.put(
                &blocks,
                slot_root_key(slot, &root),
                b"block",
                WriteFlags::UPSERT,
            )
            .unwrap();
        }
        txn::commit(txn, Update::Carry).unwrap();
        (dir, writer)
    }

    /// Head B at 9, finalized A at 5.
    pub(crate) fn valid() -> Stamp {
        Stamp {
            head_seq: 7,
            head_root: B,
            head_slot: 9,
            finalized_root: A,
            finalized_slot: 5,
        }
    }

    /// [`read`] with `bytes` as the stamp row, in a write txn that is then dropped.
    fn read_row(writer: &WriterEnv, bytes: &[u8]) -> Result<Option<Stamp>> {
        let txn = writer.env().begin_rw_txn().unwrap();
        let meta = txn.open_table(Some(META)).unwrap();
        txn.put(&meta, STAMP_KEY, bytes, WriteFlags::UPSERT)
            .unwrap();
        read(&txn)
    }

    fn stored_stamp(writer: &WriterEnv) -> Option<Stamp> {
        read(&writer.env().begin_ro_txn().unwrap()).unwrap()
    }

    #[test]
    fn the_stamp_is_88_bytes_big_endian() {
        let bytes = valid().encode();
        assert_eq!(STAMP_LEN, 88);
        assert_eq!(bytes.len(), STAMP_LEN);
        assert_eq!(&bytes[..8], &7u64.to_be_bytes());
        assert_eq!(&bytes[8..40], &B);
        assert_eq!(&bytes[40..48], &9u64.to_be_bytes());
        assert_eq!(&bytes[48..80], &A);
        assert_eq!(&bytes[80..], &5u64.to_be_bytes());
        assert_eq!(Stamp::decode(&bytes).unwrap(), valid());
    }

    /// V2: a short, long or garbled stamp row is an error, never a panic and never a default
    /// stamp. Of the 88-byte rows, exactly those whose blocks are stored, finalized at or below
    /// the head, read back.
    #[test]
    fn malformed_stamp_is_error() {
        let (_dir, writer) = env_with_blocks();
        assert_eq!(stored_stamp(&writer), None, "no row is no stamp");
        assert_eq!(read_row(&writer, &valid().encode()).unwrap(), Some(valid()));
        let err = read_row(&writer, &[]).unwrap_err();
        assert!(matches!(err, Error::MalformedStamp { len: 0 }), "{err:?}");

        let stored = [(5u64, A), (9u64, B)];
        let block = || {
            prop_oneof![
                Just(stored[0]),
                Just(stored[1]),
                (any::<u64>(), any::<[u8; 32]>()),
            ]
        };
        let rows = prop_oneof![
            prop::collection::vec(any::<u8>(), 0..200),
            (any::<u64>(), block(), block()).prop_map(|(seq, (hs, hr), (fs, fr))| {
                [
                    &seq.to_be_bytes()[..],
                    &hr,
                    &hs.to_be_bytes(),
                    &fr,
                    &fs.to_be_bytes(),
                ]
                .concat()
            }),
        ];
        let mut runner = TestRunner::new(Config {
            cases: 1024,
            ..Config::default()
        });
        runner
            .run(&rows, |bytes| {
                let got = read_row(&writer, &bytes);
                if bytes.len() != STAMP_LEN {
                    prop_assert!(
                        matches!(got, Err(Error::MalformedStamp { len }) if len == bytes.len()),
                        "{got:?}"
                    );
                    prop_assert!(Stamp::decode(&bytes).is_err());
                    return Ok(());
                }
                let word = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
                let root = |at: usize| -> Root { bytes[at..at + 32].try_into().unwrap() };
                let stamp = Stamp {
                    head_seq: word(0),
                    head_root: root(8),
                    head_slot: word(40),
                    finalized_root: root(48),
                    finalized_slot: word(80),
                };
                prop_assert_eq!(Stamp::decode(&bytes).unwrap(), stamp);
                let ok = stamp.finalized_slot <= stamp.head_slot
                    && stored.contains(&(stamp.head_slot, stamp.head_root))
                    && stored.contains(&(stamp.finalized_slot, stamp.finalized_root));
                if ok {
                    prop_assert_eq!(got.unwrap(), Some(stamp));
                } else {
                    prop_assert!(got.is_err(), "{got:?}");
                }
                Ok(())
            })
            .unwrap();
    }

    /// V2: finalized above the head is refused on read and by the writer before it commits.
    #[test]
    fn finalized_after_head_refused() {
        let (_dir, writer) = env_with_blocks();
        let bad = Stamp {
            head_seq: 1,
            head_root: A,
            head_slot: 5,
            finalized_root: B,
            finalized_slot: 9,
        };
        let refused = |err: &Error| {
            matches!(
                err,
                Error::StampFinalizedAfterHead {
                    finalized_slot: 9,
                    head_slot: 5
                }
            )
        };
        let err = read_row(&writer, &bad.encode()).unwrap_err();
        assert!(refused(&err), "{err:?}");
        let txn = writer.env().begin_rw_txn().unwrap();
        let err = txn::commit(txn, Update::New(bad)).unwrap_err();
        assert!(refused(&err), "{err:?}");
        assert_eq!(
            stored_stamp(&writer),
            None,
            "the refused commit wrote nothing"
        );
        // Finalized at the head is fine.
        let at_head = Stamp {
            finalized_root: B,
            finalized_slot: 9,
            ..valid()
        };
        let txn = writer.env().begin_rw_txn().unwrap();
        assert_eq!(
            txn::commit(txn, Update::New(at_head)).unwrap(),
            Some(at_head)
        );
    }

    /// V2: the head and the finalized checkpoint must each be a stored block, at that slot.
    #[test]
    fn finalized_root_must_be_a_stored_block() {
        let (_dir, writer) = env_with_blocks();
        let c: Root = [0xcc; 32];
        for (stamp, slot, root) in [
            (
                Stamp {
                    finalized_root: c,
                    ..valid()
                },
                5,
                c,
            ),
            // A stored root at another slot is no stored block.
            (
                Stamp {
                    finalized_slot: 4,
                    ..valid()
                },
                4,
                A,
            ),
            (
                Stamp {
                    head_root: c,
                    ..valid()
                },
                9,
                c,
            ),
        ] {
            let missing = |err: &Error| matches!(err, Error::StampBlockMissing { slot: s, root: r } if *s == slot && *r == root);
            let err = read_row(&writer, &stamp.encode()).unwrap_err();
            assert!(missing(&err), "{err:?}");
            let txn = writer.env().begin_rw_txn().unwrap();
            let err = txn::commit(txn, Update::New(stamp)).unwrap_err();
            assert!(missing(&err), "{err:?}");
            assert_eq!(stored_stamp(&writer), None);
        }
        let txn = writer.env().begin_rw_txn().unwrap();
        assert_eq!(
            txn::commit(txn, Update::New(valid())).unwrap(),
            Some(valid())
        );
        assert_eq!(stored_stamp(&writer), Some(valid()));
    }
}
