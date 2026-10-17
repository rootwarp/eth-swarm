//! Test fixtures (feature `testkit`): a fixture [`ContextTable`] and small, complete messages.
//!
//! The digests are made up. The live table is built from `compute_fork_digest` elsewhere; tests
//! and fuzz targets use this one so that no network config is involved.

use crate::rpc::codec::ContextTable;
use crate::rpc::messages::{ForkDigest, MetaDataV3, StatusV2};
use consensus_types::primitives::{Address, BLSSignature, Root, Slot, B256, U256};
use consensus_types::{fulu, gloas, EthSpec, ForkName};
use ssz::BitVector;
use ssz_types::FixedVector;

/// The fixture digest of the Fulu fork.
pub const FULU_DIGEST: ForkDigest = [0xf0, 0x01, 0x00, 0x01];
/// A second Fulu digest, as a blob-parameter-only fork produces one.
pub const FULU_BPO_DIGEST: ForkDigest = [0xf0, 0x01, 0x00, 0x02];
/// The fixture digest of the Gloas fork.
pub const GLOAS_DIGEST: ForkDigest = [0x61, 0x0a, 0x50, 0x01];
/// A digest that is not in [`context_table`].
pub const UNKNOWN_DIGEST: ForkDigest = [0xde, 0xad, 0xbe, 0xef];

const SIG: BLSSignature = [0xaa; 96];
const PUBKEY: [u8; 48] = [0xbb; 48];

/// Fulu (two digests) and Gloas.
pub fn context_table() -> ContextTable {
    let mut table = ContextTable::new();
    table.insert(FULU_DIGEST, ForkName::Fulu);
    table.insert(FULU_BPO_DIGEST, ForkName::Fulu);
    table.insert(GLOAS_DIGEST, ForkName::Gloas);
    table
}

fn root(byte: u8) -> Root {
    B256::repeat_byte(byte)
}

/// A `Status` v2 on the fixture Fulu digest.
pub fn status() -> StatusV2 {
    StatusV2 {
        fork_digest: FULU_DIGEST,
        finalized_root: root(1),
        finalized_epoch: 2,
        head_root: root(3),
        head_slot: 4,
        earliest_available_slot: 5,
    }
}

/// A `MetaData` v3 with a few subnets set.
pub fn metadata() -> MetaDataV3 {
    let mut attnets = BitVector::new();
    attnets.set(0, true).expect("in range");
    attnets.set(63, true).expect("in range");
    let mut syncnets = BitVector::new();
    syncnets.set(2, true).expect("in range");
    MetaDataV3 {
        seq_number: 7,
        attnets,
        syncnets,
        custody_group_count: 4,
    }
}

fn eth1_data() -> fulu::Eth1Data {
    fulu::Eth1Data {
        deposit_root: root(4),
        deposit_count: 5,
        block_hash: root(6),
    }
}

fn sync_aggregate<E: EthSpec>() -> fulu::SyncAggregate<E> {
    fulu::SyncAggregate {
        sync_committee_bits: BitVector::new(),
        sync_committee_signature: SIG,
    }
}

/// A small Fulu block at `slot`.
pub fn fulu_block<E: EthSpec>(slot: Slot) -> fulu::SignedBeaconBlock<E> {
    fulu::SignedBeaconBlock {
        message: fulu::BeaconBlock {
            slot,
            proposer_index: 3,
            parent_root: root(1),
            state_root: root(2),
            body: fulu::BeaconBlockBody {
                randao_reveal: SIG,
                eth1_data: eth1_data(),
                graffiti: root(0x20),
                proposer_slashings: Default::default(),
                attester_slashings: Default::default(),
                attestations: Default::default(),
                deposits: Default::default(),
                voluntary_exits: Default::default(),
                sync_aggregate: sync_aggregate(),
                execution_payload: fulu::ExecutionPayload {
                    parent_hash: root(7),
                    fee_recipient: Address::repeat_byte(8),
                    state_root: root(9),
                    receipts_root: root(10),
                    logs_bloom: FixedVector::default(),
                    prev_randao: root(11),
                    block_number: 12,
                    gas_limit: 13,
                    gas_used: 14,
                    timestamp: 15,
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
        signature: SIG,
    }
}

/// A small Gloas block at `slot`.
pub fn gloas_block<E: EthSpec>(slot: Slot) -> gloas::SignedBeaconBlock<E> {
    gloas::SignedBeaconBlock {
        message: gloas::BeaconBlock {
            slot,
            proposer_index: 3,
            parent_root: root(1),
            state_root: root(2),
            body: gloas::BeaconBlockBody {
                randao_reveal: SIG,
                eth1_data: eth1_data(),
                graffiti: root(0x20),
                proposer_slashings: Default::default(),
                attester_slashings: Default::default(),
                attestations: Default::default(),
                deposits: Default::default(),
                voluntary_exits: Default::default(),
                sync_aggregate: sync_aggregate(),
                bls_to_execution_changes: Default::default(),
                signed_execution_payload_bid: gloas::SignedExecutionPayloadBid {
                    message: gloas::ExecutionPayloadBid {
                        parent_block_hash: root(0x30),
                        parent_block_root: root(0x31),
                        block_hash: root(0x32),
                        prev_randao: root(0x33),
                        fee_recipient: Address::repeat_byte(0x34),
                        gas_limit: 35,
                        builder_index: 36,
                        slot,
                        value: 37,
                        execution_payment: 38,
                        blob_kzg_commitments: vec![PUBKEY].try_into().expect("one commitment"),
                        execution_requests_root: root(0x39),
                    },
                    signature: SIG,
                },
                payload_attestations: Default::default(),
                parent_execution_requests: gloas::ExecutionRequests {
                    deposits: Default::default(),
                    withdrawals: Default::default(),
                    consolidations: Default::default(),
                    builder_deposits: Default::default(),
                    builder_exits: Default::default(),
                },
            },
        },
        signature: SIG,
    }
}
