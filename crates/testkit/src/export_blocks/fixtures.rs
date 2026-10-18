//! Export fixtures (feature `test-support`): a fixture devnet, a Minimal-preset chain with
//! Fulu from genesis and Gloas from [`GLOAS_SLOT`], whose beacon API a
//! [`FixtureServer`] serves on 127.0.0.1; its config, and an [`ExportConfig`] for it.

use super::{ExportConfig, FINALIZED_HEADER_PATH};
use crate::archive::fixtures::{Spec, GLOAS_SLOT};
use crate::collector::testing::{FixtureServer, Reply};
use consensus_types::fulu;
use consensus_types::primitives::{Root, Slot, B256};
use network_config::ChainConfig;
use sha2::{Digest, Sha256};
use ssz::{BitVector, Encode};
use ssz_types::FixedVector;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tree_hash::TreeHash;

/// The fixture devnet's config: Fulu from genesis, a blob-parameter change at epoch 1, Gloas
/// from epoch 2 (slot 16), as `archive::fixtures::schedule`.
pub const CONFIG: &str = "\
PRESET_BASE: 'minimal'
CONFIG_NAME: 'fixture-devnet'
GENESIS_FORK_VERSION: 0x00000001
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x60000001
FULU_FORK_EPOCH: 0
GLOAS_FORK_VERSION: 0x70000001
GLOAS_FORK_EPOCH: 2
SLOT_DURATION_MS: 6000
MAX_PAYLOAD_SIZE: 10485760
MAX_BLOBS_PER_BLOCK_ELECTRA: 9
BLOB_SCHEDULE:
  - EPOCH: 1
    MAX_BLOBS_PER_BLOCK: 12
";
/// The fixture genesis state's `genesis_time`.
pub const GENESIS_TIME: u64 = 1_760_800_000;
/// The image [`config`] names.
pub const IMAGE: &str = "ethpandaops/lighthouse:unstable-c8ddac7@sha256:\
5b666c7b7d18454828a205bd94edd76c8d19068d62365c0fa676980cdd548bdd";

/// [`CONFIG`], parsed.
pub fn chain() -> ChainConfig {
    ChainConfig::from_yaml(CONFIG.as_bytes(), &config_sha256()).expect("the fixture config parses")
}

/// sha256 of [`CONFIG`].
pub fn config_sha256() -> [u8; 32] {
    Sha256::digest(CONFIG.as_bytes()).into()
}

/// An export of the fixture devnet to `to_slot`, from `cl-1-lighthouse-geth`.
pub fn config(to_slot: Slot) -> ExportConfig {
    ExportConfig {
        devnet: "fixture-devnet".into(),
        source: "cl-1-lighthouse-geth".into(),
        to_slot,
        images: vec![IMAGE.into()],
        config_sha256: config_sha256(),
        request_timeout: Duration::from_secs(5),
        state_timeout: Duration::from_secs(5),
        max_state_bytes: 1 << 20,
    }
}

/// A Fulu genesis state: slot 0, everything else zero or empty but the genesis time and
/// validators root.
pub fn genesis_state() -> fulu::BeaconState<Spec> {
    let payload = p2p_wire::testkit::fulu_block::<Spec>(0)
        .message
        .body
        .execution_payload;
    let checkpoint = fulu::Checkpoint {
        epoch: 0,
        root: Root::ZERO,
    };
    let eth1_data = fulu::Eth1Data {
        deposit_root: Root::ZERO,
        deposit_count: 0,
        block_hash: Root::ZERO,
    };
    let sync_committee = || fulu::SyncCommittee::<Spec> {
        pubkeys: FixedVector::from_elem([0; 48]),
        aggregate_pubkey: [0; 48],
    };
    fulu::BeaconState {
        genesis_time: GENESIS_TIME,
        genesis_validators_root: B256::repeat_byte(0x42),
        slot: 0,
        fork: fulu::Fork {
            previous_version: [0x60, 0, 0, 1],
            current_version: [0x60, 0, 0, 1],
            epoch: 0,
        },
        latest_block_header: fulu::BeaconBlockHeader {
            slot: 0,
            proposer_index: 0,
            parent_root: Root::ZERO,
            state_root: Root::ZERO,
            body_root: Root::ZERO,
        },
        block_roots: Default::default(),
        state_roots: Default::default(),
        historical_roots: Default::default(),
        eth1_data: eth1_data.clone(),
        eth1_data_votes: Default::default(),
        eth1_deposit_index: 0,
        validators: Default::default(),
        balances: Default::default(),
        randao_mixes: Default::default(),
        slashings: Default::default(),
        previous_epoch_participation: Default::default(),
        current_epoch_participation: Default::default(),
        justification_bits: BitVector::new(),
        previous_justified_checkpoint: checkpoint.clone(),
        current_justified_checkpoint: checkpoint.clone(),
        finalized_checkpoint: checkpoint,
        inactivity_scores: Default::default(),
        current_sync_committee: sync_committee(),
        next_sync_committee: sync_committee(),
        latest_execution_payload_header: fulu::ExecutionPayloadHeader {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: GENESIS_TIME,
            extra_data: payload.extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: Root::ZERO,
            withdrawals_root: Root::ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
        },
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: Default::default(),
        deposit_requests_start_index: 0,
        deposit_balance_to_consume: 0,
        exit_balance_to_consume: 0,
        earliest_exit_epoch: 0,
        consolidation_balance_to_consume: 0,
        earliest_consolidation_epoch: 0,
        pending_deposits: Default::default(),
        pending_partial_withdrawals: Default::default(),
        pending_consolidations: Default::default(),
        proposer_lookahead: Default::default(),
    }
}

/// A block as the fixture node serves it: its SSZ and the root its root endpoint answers.
#[derive(Debug, Clone)]
pub struct Served {
    /// The SSZ `GET /eth/v2/beacon/blocks/{slot}` answers.
    pub ssz: Vec<u8>,
    /// The root `GET /eth/v1/beacon/blocks/{slot}/root` answers.
    pub api_root: Root,
}

/// A block at `slot` in the shape of its fork, with `parent_root` and `state_root`, and its
/// root.
pub fn block(slot: Slot, parent_root: Root, state_root: Root) -> (Vec<u8>, Root) {
    if slot >= GLOAS_SLOT {
        let mut b = p2p_wire::testkit::gloas_block::<Spec>(slot);
        b.message.proposer_index = slot;
        b.message.parent_root = parent_root;
        b.message.state_root = state_root;
        (b.as_ssz_bytes(), b.message.tree_hash_root())
    } else {
        let mut b = p2p_wire::testkit::fulu_block::<Spec>(slot);
        b.message.proposer_index = slot;
        b.message.parent_root = parent_root;
        b.message.state_root = state_root;
        (b.as_ssz_bytes(), b.message.tree_hash_root())
    }
}

/// The fixture node's chain and what it answers.
#[derive(Debug, Clone)]
pub struct Devnet {
    /// The genesis state's SSZ.
    pub state: Vec<u8>,
    /// Its `hash_tree_root`.
    pub state_root: Root,
    /// The blocks by slot; a missing slot answers 404.
    pub blocks: BTreeMap<Slot, Served>,
    /// The finalized header's slot; the chain has a block there.
    pub finalized: Slot,
}

/// How far past the export slot [`Devnet::new`] finalizes.
pub const FINALIZED_AFTER: Slot = 8;

impl Devnet {
    /// A chain from genesis to `to + FINALIZED_AFTER`, finalized there, with no block at the
    /// `empty` slots (never the finalized one), each block's parent the one before it.
    pub fn new(to: Slot, empty: &[Slot]) -> Self {
        let state = genesis_state();
        let state_root = state.tree_hash_root();
        let mut blocks = BTreeMap::new();
        let (ssz, mut parent) = block(0, Root::ZERO, state_root);
        blocks.insert(
            0,
            Served {
                ssz,
                api_root: parent,
            },
        );
        let finalized = to + FINALIZED_AFTER;
        assert!(
            !empty.contains(&finalized),
            "the finalized slot has a block"
        );
        for slot in (1..=finalized).filter(|s| !empty.contains(s)) {
            let (ssz, root) = block(slot, parent, B256::repeat_byte(slot as u8));
            blocks.insert(
                slot,
                Served {
                    ssz,
                    api_root: root,
                },
            );
            parent = root;
        }
        Self {
            state: state.as_ssz_bytes(),
            state_root,
            blocks,
            finalized,
        }
    }

    /// The root the API answers for the block at `slot`.
    pub fn root(&self, slot: Slot) -> Root {
        self.blocks[&slot].api_root
    }

    /// Serves the chain; every request path is recorded.
    pub async fn serve(self) -> (FixtureServer, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let server = FixtureServer::start(move |_, path| {
            record.lock().unwrap().push(path.to_owned());
            self.reply(path)
        })
        .await;
        (server, seen)
    }

    /// The node's answer to a request for `path`.
    pub fn reply(&self, path: &str) -> Reply {
        if path == FINALIZED_HEADER_PATH {
            let root = self
                .blocks
                .get(&self.finalized)
                .map_or(Root::ZERO, |b| b.api_root);
            return Reply::json(&finalized_header(self.finalized, root));
        }
        // By id, as Lighthouse serves it, and by its root, as every CL does.
        if path == "/eth/v2/debug/beacon/states/genesis"
            || path == format!("/eth/v2/debug/beacon/states/{}", self.state_root)
        {
            return Reply::ssz(self.state.clone());
        }
        if path.starts_with("/eth/v2/debug/beacon/states/") {
            return Reply::status(404);
        }
        if let Some(slot) = path.strip_prefix("/eth/v1/beacon/blocks/") {
            let slot = slot.strip_suffix("/root").and_then(|s| s.parse().ok());
            return match slot.and_then(|s: Slot| self.blocks.get(&s)) {
                Some(b) => Reply::json(&format!(
                    r#"{{"execution_optimistic":false,"finalized":true,"data":{{"root":"{}"}}}}"#,
                    b.api_root
                )),
                None => Reply::status(404),
            };
        }
        if let Some(slot) = path.strip_prefix("/eth/v2/beacon/blocks/") {
            return match slot.parse().ok().and_then(|s: Slot| self.blocks.get(&s)) {
                Some(b) => Reply::ssz(b.ssz.clone()),
                None => Reply::status(404),
            };
        }
        Reply::status(400)
    }
}

/// The JSON of `GET /eth/v1/beacon/headers/finalized` for the block `root` at `slot`.
pub fn finalized_header(slot: Slot, root: Root) -> String {
    format!(
        r#"{{"data":{{"root":"{root}","canonical":true,"header":{{"message":{{"slot":"{slot}"}}}}}}}}"#
    )
}

impl Devnet {
    /// Re-parents every block after `slot` onto the block before it, from `slot` up, as a
    /// chain that forked at `slot` would have it; each gets the state root `repeat_byte(slot)`.
    pub fn rechain(&mut self, slot: Slot) {
        let after: Vec<Slot> = self.blocks.range(slot + 1..).map(|(s, _)| *s).collect();
        for at in after {
            let parent = self
                .blocks
                .range(..at)
                .next_back()
                .expect("genesis")
                .1
                .api_root;
            self.reparent(at, parent, B256::repeat_byte(at as u8));
        }
    }

    /// Replaces the block at `slot` with one whose parent is `parent_root` and state root
    /// `state_root`; the root endpoint answers the new block's root.
    pub fn reparent(&mut self, slot: Slot, parent_root: Root, state_root: Root) {
        let (ssz, root) = block(slot, parent_root, state_root);
        self.blocks.insert(
            slot,
            Served {
                ssz,
                api_root: root,
            },
        );
    }
}
