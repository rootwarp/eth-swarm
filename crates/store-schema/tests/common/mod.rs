//! Real blocks for the store-schema tests and the `fill_env` example: small Fulu
//! `SignedBeaconBlock`s (Minimal preset) built and SSZ-encoded in code, no spec vectors.
//!
//! Included with `#[path]` by `src/` unit tests, `tests/env.rs` and `examples/fill_env.rs`, so
//! each user leaves some helpers unused.
#![allow(dead_code)]

use alloy_primitives::{Address, B256, U256};
use consensus_types::{fulu, ForkSchedule, Minimal};
use network_config::{ScheduledFork, FAR_FUTURE_EPOCH};
use ssz::Encode;
use ssz_types::{BitVector, FixedVector};
use tree_hash::TreeHash;

/// The preset of every test block.
pub type E = Minimal;

/// Fulu from genesis, Gloas never: every test block decodes as Fulu.
pub fn schedule() -> ForkSchedule {
    ForkSchedule::new(
        ScheduledFork {
            version: [6, 0, 0, 1],
            epoch: 0,
        },
        ScheduledFork {
            version: [7, 0, 0, 1],
            epoch: FAR_FUTURE_EPOCH,
        },
    )
    .expect("Fulu before Gloas")
}

/// A Fulu block at `slot` on `parent`; `salt` varies the body, so one slot can hold several.
pub fn fulu_block(slot: u64, parent: [u8; 32], salt: u64) -> fulu::SignedBeaconBlock<E> {
    let root = |b: u8| B256::repeat_byte(b);
    fulu::SignedBeaconBlock {
        message: fulu::BeaconBlock {
            slot,
            proposer_index: salt % 64,
            parent_root: B256::from(parent),
            state_root: root(2),
            body: fulu::BeaconBlockBody {
                randao_reveal: [0x11; 96],
                eth1_data: fulu::Eth1Data {
                    deposit_root: root(4),
                    deposit_count: 5,
                    block_hash: root(6),
                },
                graffiti: B256::from(U256::from(salt)),
                proposer_slashings: Default::default(),
                attester_slashings: Default::default(),
                attestations: Default::default(),
                deposits: Default::default(),
                voluntary_exits: Default::default(),
                sync_aggregate: fulu::SyncAggregate {
                    sync_committee_bits: BitVector::new(),
                    sync_committee_signature: [0xc0; 96],
                },
                execution_payload: fulu::ExecutionPayload {
                    parent_hash: root(7),
                    fee_recipient: Address::repeat_byte(8),
                    state_root: root(9),
                    receipts_root: root(10),
                    logs_bloom: FixedVector::default(),
                    prev_randao: root(11),
                    block_number: slot,
                    gas_limit: 13,
                    gas_used: 14,
                    timestamp: 15 + slot * 6,
                    extra_data: Default::default(),
                    base_fee_per_gas: U256::from(16),
                    block_hash: root(17),
                    transactions: Default::default(),
                    withdrawals: Default::default(),
                    blob_gas_used: 18,
                    excess_blob_gas: 19,
                },
                bls_to_execution_changes: Default::default(),
                blob_kzg_commitments: Default::default(),
                execution_requests: fulu::ExecutionRequests {
                    deposits: Default::default(),
                    withdrawals: Default::default(),
                    consolidations: Default::default(),
                },
            },
        },
        signature: [0x22; 96],
    }
}

/// `hash_tree_root(block.message)`, computed here rather than by the code under test.
pub fn message_root(block: &fulu::SignedBeaconBlock<E>) -> [u8; 32] {
    block.message.tree_hash_root().0
}

/// The SSZ of [`fulu_block`] and its message root.
pub fn fulu_block_ssz(slot: u64, parent: [u8; 32], salt: u64) -> (Vec<u8>, [u8; 32]) {
    let block = fulu_block(slot, parent, salt);
    (block.as_ssz_bytes(), message_root(&block))
}

/// A Fulu `DataColumnSidecar` of `block` with no blobs, SSZ-encoded: a real column value.
pub fn fulu_sidecar(block: &fulu::SignedBeaconBlock<E>, index: u64) -> Vec<u8> {
    let message = &block.message;
    fulu::DataColumnSidecar::<E> {
        index,
        column: Default::default(),
        kzg_commitments: Default::default(),
        kzg_proofs: Default::default(),
        signed_block_header: consensus_types::common::SignedBeaconBlockHeader {
            message: consensus_types::common::BeaconBlockHeader {
                slot: message.slot,
                proposer_index: message.proposer_index,
                parent_root: message.parent_root,
                state_root: message.state_root,
                body_root: message.body.tree_hash_root(),
            },
            signature: block.signature,
        },
        kzg_commitments_inclusion_proof: Default::default(),
    }
    .as_ssz_bytes()
}
