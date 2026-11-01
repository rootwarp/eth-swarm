//! Imported blocks: `blocks` keyed by `slot ‖ root` and `block_index` from root to slot,
//! always written in one transaction.

use consensus_types::{forked::SignedBeaconBlock, EthSpec, ForkSchedule};
use libmdbx::WriteFlags;

use crate::{
    env::RwTxn,
    keys::{decode_slot_root_key, slot_root_key, Root},
    tables::{BLOCKS, BLOCK_INDEX},
    Error, Result,
};

/// Stores a signed block from its SSZ in `txn` and returns its `(slot, root)`.
///
/// The block is decoded with the fork of its own slot ([`SignedBeaconBlock::from_ssz_bytes_by_slot`]);
/// bytes that do not decode are [`Error::Block`] and write nothing. The key is the block's slot
/// and `hash_tree_root(block.message)`, both taken from the bytes: no caller names them. Writes
/// `blocks[slot ‖ root] = ssz` and `block_index[root] = slot BE`.
pub fn put<E: EthSpec>(
    txn: &RwTxn<'_>,
    schedule: &ForkSchedule,
    ssz: &[u8],
) -> Result<(u64, Root)> {
    let block =
        SignedBeaconBlock::<E>::from_ssz_bytes_by_slot(ssz, schedule).map_err(Error::Block)?;
    let (slot, root) = (block.slot(), block.message_root().0);
    let blocks = txn.open_table(Some(BLOCKS))?;
    txn.put(&blocks, slot_root_key(slot, &root), ssz, WriteFlags::UPSERT)?;
    let index = txn.open_table(Some(BLOCK_INDEX))?;
    txn.put(&index, root, slot.to_be_bytes(), WriteFlags::UPSERT)?;
    Ok((slot, root))
}

/// Fills `block_index` from the keys of every `blocks` row: the upgrade to schema 2, in the
/// transaction that creates the table. No `blocks` row is read beyond its key or rewritten.
pub(crate) fn fill_index(txn: &RwTxn<'_>) -> Result<()> {
    let blocks = txn.open_table(Some(BLOCKS))?;
    let index = txn.open_table(Some(BLOCK_INDEX))?;
    for row in txn.cursor(&blocks)?.iter::<Vec<u8>, ()>() {
        let (key, ()) = row?;
        let (slot, root) = decode_slot_root_key(&key).ok_or(Error::Corrupt { table: BLOCKS })?;
        txn.put(&index, root, slot.to_be_bytes(), WriteFlags::UPSERT)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        env::{self, WriterEnv, WriterOptions, MIN_MAX_SIZE},
        keys::decode_slot_root_key,
        testkit::{fulu_block, fulu_block_ssz, message_root, schedule, E},
        txn::{self, Update},
    };
    use consensus_types::ForkSchedule;
    use network_config::ScheduledFork;
    use proptest::prelude::*;
    use ssz::Encode;
    use std::collections::{BTreeMap, BTreeSet};
    use tree_hash::TreeHash;

    fn writer() -> (tempfile::TempDir, WriterEnv) {
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

    fn rows(writer: &WriterEnv, table: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        let txn = writer.env().begin_ro_txn().unwrap();
        let handle = txn.open_table(Some(table)).unwrap();
        txn.cursor(&handle)
            .unwrap()
            .iter::<Vec<u8>, Vec<u8>>()
            .map(Result::unwrap)
            .collect()
    }

    /// `blocks` as `(slot, root) → ssz`, `block_index` as `root → slot`.
    #[allow(clippy::type_complexity)]
    fn tables(writer: &WriterEnv) -> (BTreeMap<(u64, Root), Vec<u8>>, BTreeMap<Root, u64>) {
        let blocks = rows(writer, BLOCKS)
            .into_iter()
            .map(|(k, v)| (decode_slot_root_key(&k).unwrap(), v))
            .collect();
        let index = rows(writer, BLOCK_INDEX)
            .into_iter()
            .map(|(k, v)| {
                (
                    Root::try_from(k.as_slice()).unwrap(),
                    u64::from_be_bytes(v.as_slice().try_into().unwrap()),
                )
            })
            .collect();
        (blocks, index)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// C3: `block_index` is written in the same txn as `blocks` and always agrees with it:
        /// one index row per block, root → slot BE, and nothing from a txn that did not commit.
        #[test]
        fn index_matches_blocks(
            puts in prop::collection::vec((0u64..64, any::<u64>(), any::<bool>()), 1..16),
            commit_every in 1usize..5,
        ) {
            let (_dir, writer) = writer();
            let schedule = schedule();
            let mut want = BTreeMap::new();
            let mut parent = [0; 32];
            let mut txn = Some(writer.env().begin_rw_txn().unwrap());
            let mut pending = BTreeMap::new();
            for (i, (slot, salt, aborted)) in puts.iter().enumerate() {
                let (ssz, root) = fulu_block_ssz(*slot, parent, *salt);
                let open = txn.get_or_insert_with(|| writer.env().begin_rw_txn().unwrap());
                prop_assert_eq!(put::<E>(open, &schedule, &ssz).unwrap(), (*slot, root));
                // The same block again is the same two rows.
                prop_assert_eq!(put::<E>(open, &schedule, &ssz).unwrap(), (*slot, root));
                pending.insert((*slot, root), ssz);
                parent = root;
                if (i + 1) % commit_every == 0 || i + 1 == puts.len() {
                    let open = txn.take().unwrap();
                    if *aborted {
                        drop(open);
                    } else {
                        txn::commit(open, Update::Carry).unwrap();
                        want.append(&mut pending);
                    }
                    pending.clear();
                }
            }
            let (blocks, index) = tables(&writer);
            prop_assert_eq!(&blocks, &want);
            let want_index: BTreeMap<Root, u64> =
                want.keys().map(|(slot, root)| (*root, *slot)).collect();
            prop_assert_eq!(index, want_index);
        }
    }

    /// V3: the key is the block's own slot and `hash_tree_root(block.message)`, computed from
    /// the SSZ (the API takes nothing else); bytes that do not decode as a block of their
    /// slot's fork write nothing.
    #[test]
    fn key_is_computed_root() {
        let (_dir, writer) = writer();
        let block = fulu_block(12, [1; 32], 3);
        let ssz = block.as_ssz_bytes();
        let root = message_root(&block);
        assert_ne!(
            root,
            block.tree_hash_root().0,
            "not the signed container's root"
        );

        let txn = writer.env().begin_rw_txn().unwrap();
        assert_eq!(put::<E>(&txn, &schedule(), &ssz).unwrap(), (12, root));
        // The same message at another slot is another block, under its own root.
        let mut moved = block.clone();
        moved.message.slot = 13;
        let moved_root = message_root(&moved);
        assert_ne!(moved_root, root);
        assert_eq!(
            put::<E>(&txn, &schedule(), &moved.as_ssz_bytes()).unwrap(),
            (13, moved_root)
        );
        // Not a block; a block before Fulu (Fulu at epoch 10 here, slot 12 is epoch 1).
        let late_fulu = ForkSchedule::new(
            ScheduledFork {
                version: [6, 0, 0, 1],
                epoch: 10,
            },
            ScheduledFork {
                version: [7, 0, 0, 1],
                epoch: 20,
            },
        )
        .unwrap();
        for (bytes, schedule) in [
            (&ssz[..ssz.len() - 1], schedule()),
            (&[0u8; 7][..], schedule()),
            (&ssz[..], late_fulu),
        ] {
            let err = put::<E>(&txn, &schedule, bytes).unwrap_err();
            assert!(matches!(err, Error::Block(_)), "{err:?}");
        }
        txn::commit(txn, Update::Carry).unwrap();

        let (blocks, index) = tables(&writer);
        assert_eq!(
            blocks,
            BTreeMap::from([((12, root), ssz), ((13, moved_root), moved.as_ssz_bytes())])
        );
        assert_eq!(index, BTreeMap::from([(root, 12), (moved_root, 13)]));
        assert_eq!(
            blocks.keys().map(|k| k.1).collect::<BTreeSet<_>>(),
            index.keys().copied().collect()
        );
    }
}
