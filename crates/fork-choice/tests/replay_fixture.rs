//! The pinned minimal Gloas export (`testing/replay.manifest.toml`) through fork choice.
//!
//! The export holds the blocks of slots 0 to 16, and slot 3 is empty. The tests open it only
//! through `open_export_pinned`, read it, and write no file.
//!
//! The provider runs the real state transition, with the state root check. It accepts each
//! signature set without BLS: the export was made with real signatures, and the testkit
//! replay checks them with BLS.

use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{Root, Slot};
use consensus_types::Minimal;
use fork_choice::testing::mark_payload_verified;
use fork_choice::{
    get_forkchoice_store, get_head, is_payload_verified, on_block, on_tick,
    seconds_to_milliseconds, Error, ForkChoiceNode, PayloadStatus, StateProvider,
};
use network_config::ChainConfig;
use sha2::{Digest, Sha256};
use ssz::Decode;
use state_transition::per_slot::process_slots;
use state_transition::testing::{bls_context, ContractBackend};
use state_transition::{state_transition, StfError};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use testkit::export_blocks::open_export_pinned;
use tree_hash::TreeHash;

type E = Minimal;

/// The state transition with the state root check, and no BLS check.
struct Transition;

impl StateProvider<E> for Transition {
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        let backend = ContractBackend::new([]);
        state_transition(state, block, true, &bls_context(&backend))
    }

    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
        let backend = ContractBackend::new([]);
        process_slots(state, slot, &bls_context(&backend))
    }
}

/// `testing/replay.manifest.toml`.
#[derive(serde::Deserialize)]
struct Pin {
    export: String,
    export_sha256: String,
    config: String,
}

/// The export, read through its pin.
struct Replay {
    genesis_state: BeaconState<E>,
    blocks: Vec<SignedBeaconBlock<E>>,
    root_list: Vec<Option<Root>>,
    slot_duration: NonZeroU64,
}

fn testing_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing")
}

fn load() -> Replay {
    let dir = testing_dir();
    let pin: Pin =
        toml::from_str(&std::fs::read_to_string(dir.join("replay.manifest.toml")).unwrap())
            .unwrap();
    let sha: [u8; 32] = hex::decode(&pin.export_sha256).unwrap().try_into().unwrap();
    let export = open_export_pinned(&dir.join(&pin.export), sha).unwrap();
    let yaml = std::fs::read(dir.join(&pin.config)).unwrap();
    let digest: [u8; 32] = Sha256::digest(&yaml).into();
    let config = ChainConfig::from_yaml(&yaml, &digest).unwrap();
    let genesis_state = BeaconState::from_ssz_bytes(&export.genesis_state_ssz().unwrap()).unwrap();
    let blocks = export
        .manifest()
        .blocks
        .iter()
        .map(|entry| SignedBeaconBlock::from_ssz_bytes(&export.block_ssz(entry).unwrap()).unwrap())
        .collect();
    Replay {
        genesis_state,
        blocks,
        root_list: export.root_list(),
        slot_duration: NonZeroU64::new(config.slot_duration_ms()).unwrap(),
    }
}

/// The roots of the blocks whose payload a child builds on: the bid of the child extends the
/// block hash of the bid of the parent. This reads the bids only, not fork choice.
fn full_blocks(blocks: &[SignedBeaconBlock<E>]) -> BTreeSet<Root> {
    let bids: BTreeMap<Root, Root> = blocks
        .iter()
        .map(|b| {
            let bid = &b.message.body.signed_execution_payload_bid.message;
            (b.message.tree_hash_root(), bid.block_hash)
        })
        .collect();
    blocks
        .iter()
        .filter(|b| {
            let bid = &b.message.body.signed_execution_payload_bid.message;
            bids.get(&b.message.parent_root) == Some(&bid.parent_block_hash)
        })
        .map(|b| b.message.parent_root)
        .collect()
}

#[test]
fn replay_export_walk_ends_at_the_exported_head() {
    let replay = load();
    assert_eq!(replay.root_list.len(), 17);
    assert_eq!(replay.root_list[3], None);
    let genesis = replay.blocks[0].message.clone();
    let genesis_root = genesis.tree_hash_root();
    let full = full_blocks(&replay.blocks);
    // The testkit replay counts one FULL parent: the genesis block.
    assert_eq!(full, BTreeSet::from([genesis_root]));
    let genesis_ms = seconds_to_milliseconds(replay.genesis_state.genesis_time);
    let slot_ms = replay.slot_duration.get();
    let mut store =
        get_forkchoice_store(replay.genesis_state, genesis, replay.slot_duration).unwrap();
    let by_slot: BTreeMap<Slot, &SignedBeaconBlock<E>> =
        replay.blocks.iter().map(|b| (b.message.slot, b)).collect();
    let mut head = genesis_root;
    for slot in 0..=16 {
        on_tick(&mut store, genesis_ms + slot * slot_ms).unwrap();
        if let Some(block) = by_slot.get(&slot) {
            let root = block.message.tree_hash_root();
            if slot > 0 {
                on_block(&mut store, &Transition, block)
                    .unwrap_or_else(|e| panic!("slot {slot}: {e}"));
            }
            // The envelope of a FULL block comes after the block.
            if full.contains(&root) {
                mark_payload_verified(&mut store, root);
            }
            head = root;
        }
        let status = if full.contains(&head) {
            PayloadStatus::Full
        } else {
            PayloadStatus::Empty
        };
        let want = ForkChoiceNode {
            root: head,
            payload_status: status,
        };
        assert_eq!(get_head(&store), Ok(want), "slot {slot}");
    }
    let last = replay.root_list.iter().rev().find_map(|r| *r).unwrap();
    assert_eq!(
        get_head(&store),
        Ok(ForkChoiceNode {
            root: last,
            payload_status: PayloadStatus::Empty
        })
    );
    assert_eq!(store.finalized_checkpoint().root, genesis_root);
}

#[test]
fn replay_export_block_on_the_unverified_full_genesis_is_refused() {
    let replay = load();
    let genesis = replay.blocks[0].message.clone();
    let genesis_root = genesis.tree_hash_root();
    let first = &replay.blocks[1];
    let genesis_ms = seconds_to_milliseconds(replay.genesis_state.genesis_time);
    let mut store =
        get_forkchoice_store(replay.genesis_state, genesis, replay.slot_duration).unwrap();
    on_tick(&mut store, genesis_ms + replay.slot_duration.get()).unwrap();
    // The block of slot 1 builds on the FULL genesis block, whose payload is not verified.
    assert!(!is_payload_verified(&store, genesis_root));
    assert_eq!(
        on_block(&mut store, &Transition, first),
        Err(Error::ParentPayloadNotVerified(genesis_root))
    );
    assert_eq!(store.block(first.message.tree_hash_root()), None);
    mark_payload_verified(&mut store, genesis_root);
    assert_eq!(on_block(&mut store, &Transition, first), Ok(()));
    assert_eq!(
        get_head(&store).map(|n| n.root),
        Ok(first.message.tree_hash_root())
    );
}
