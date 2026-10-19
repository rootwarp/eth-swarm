//! Random write / finality-prune / reorg-prune sequences checked against an in-memory model.
//! After every step the store must hold exactly the model's columns, and the root index exactly
//! the model's blocks: no orphaned row and no orphaned root entry. Writes at or below the
//! finalized slot must be refused, and so must writes of a root pruned as an orphan.

use std::collections::{BTreeMap, BTreeSet};

use cl_chain_columns::{BlockRoot, Column, ColumnWriter, Error};
use proptest::prelude::*;

const SLOTS: u64 = 12;
const ROOTS_PER_SLOT: u8 = 3;

/// Roots are derived from `(slot, id)`, so every root belongs to exactly one slot.
fn root(slot: u64, id: u8) -> BlockRoot {
    let mut root = [0u8; 32];
    root[..8].copy_from_slice(&slot.to_le_bytes());
    root[31] = id;
    root
}

#[derive(Clone, Debug)]
enum Op {
    Write {
        slot: u64,
        id: u8,
        indices: Vec<u64>,
    },
    PruneFinalized {
        slot: u64,
    },
    PruneOrphaned {
        blocks: Vec<(u64, u8)>,
    },
}

fn op() -> impl Strategy<Value = Op> {
    let block = (0..SLOTS, 0..ROOTS_PER_SLOT);
    prop_oneof![
        4 => (block.clone(), prop::collection::btree_set(0..128u64, 0..40))
            .prop_map(|((slot, id), indices)| Op::Write {
                slot,
                id,
                indices: indices.into_iter().collect(),
            }),
        1 => (0..SLOTS + 2).prop_map(|slot| Op::PruneFinalized { slot }),
        1 => prop::collection::vec(block, 0..4).prop_map(|blocks| Op::PruneOrphaned { blocks }),
    ]
}

/// Stored columns, root → (slot, column_index → ssz), and the finalized-slot watermark.
#[derive(Default)]
struct Model {
    blocks: BTreeMap<BlockRoot, (u64, BTreeMap<u64, Vec<u8>>)>,
    finalized: Option<u64>,
    /// Roots pruned as orphans: no later write may bring them back.
    orphaned: BTreeSet<BlockRoot>,
}

fn apply(writer: &ColumnWriter, model: &mut Model, step: usize, op: &Op) {
    match op {
        Op::Write { slot, id, indices } => {
            let block_root = root(*slot, *id);
            let bytes: Vec<Vec<u8>> = indices
                .iter()
                .map(|i| format!("{slot}/{id}/{i}@{step}").into_bytes())
                .collect();
            let columns: Vec<Column<'_>> = indices
                .iter()
                .zip(&bytes)
                .map(|(&index, ssz)| Column { index, ssz })
                .collect();
            if model.finalized.is_some_and(|f| *slot <= f) {
                let err = writer
                    .write_columns(*slot, &block_root, &columns)
                    .unwrap_err();
                assert!(matches!(err, Error::SlotFinalized { .. }), "{err:?}");
                return;
            }
            if model.orphaned.contains(&block_root) {
                let err = writer
                    .write_columns(*slot, &block_root, &columns)
                    .unwrap_err();
                assert!(matches!(err, Error::RootOrphaned), "{err:?}");
                return;
            }
            let report = writer.write_columns(*slot, &block_root, &columns).unwrap();
            assert_eq!(report.columns, indices.len());
            assert_eq!(report.transactions, indices.len().div_ceil(16));
            if !indices.is_empty() {
                let entry = model
                    .blocks
                    .entry(block_root)
                    .or_insert((*slot, BTreeMap::new()));
                for (&index, ssz) in indices.iter().zip(bytes) {
                    entry.1.insert(index, ssz);
                }
            }
        }
        Op::PruneFinalized { slot } => {
            let expected: u64 = model
                .blocks
                .values()
                .filter(|(s, _)| s <= slot)
                .map(|(_, cols)| cols.len() as u64)
                .sum();
            assert_eq!(writer.prune_finalized(*slot).unwrap().columns, expected);
            model.blocks.retain(|_, (s, _)| *s > *slot);
            model.finalized = model.finalized.max(Some(*slot));
            assert_eq!(writer.reader().finalized_slot().unwrap(), model.finalized);
        }
        Op::PruneOrphaned { blocks } => {
            let roots: Vec<BlockRoot> = blocks.iter().map(|&(s, id)| root(s, id)).collect();
            let mut expected = 0;
            for block_root in &roots {
                if let Some((_, cols)) = model.blocks.remove(block_root) {
                    expected += cols.len() as u64;
                }
                model.orphaned.insert(*block_root);
            }
            assert_eq!(writer.prune_orphaned(&roots).unwrap().columns, expected);
        }
    }
}

fn assert_matches_model(writer: &ColumnWriter, model: &Model) {
    let reader = writer.reader();
    for slot in 0..SLOTS {
        for id in 0..ROOTS_PER_SLOT {
            let block_root = root(slot, id);
            let (stored_slot, columns) = match model.blocks.get(&block_root) {
                Some((s, cols)) => (Some(*s), cols.clone().into_iter().collect()),
                None => (None, Vec::new()),
            };
            assert_eq!(reader.slot_of(&block_root).unwrap(), stored_slot);
            assert_eq!(reader.columns_for_root(&block_root).unwrap(), columns);
        }
    }
    let columns: usize = model.blocks.values().map(|(_, cols)| cols.len()).sum();
    assert_eq!(reader.column_count().unwrap(), columns as u64);
    assert_eq!(reader.block_count().unwrap(), model.blocks.len() as u64);
    assert_eq!(reader.finalized_slot().unwrap(), model.finalized);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn store_matches_model_after_every_step(ops in prop::collection::vec(op(), 1..25)) {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let mut model = Model::default();
        for (step, op) in ops.iter().enumerate() {
            apply(&writer, &mut model, step, op);
            assert_matches_model(&writer, &model);
        }
    }
}
