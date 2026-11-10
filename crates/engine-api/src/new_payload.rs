//! `engine_newPayloadV5` params (`amsterdam.md`) from a Gloas envelope and its committed bid,
//! following consensus-specs v1.7.0-beta.4 `verify_execution_payload_envelope`
//! (`specs/gloas/fork-choice.md` L683-726) and `verify_and_notify_new_payload`
//! (`specs/electra/beacon-chain.md` L1303-1333).

use crate::encoding::{Data, FixedData};
use crate::payload::ExecutionPayloadV4;
use consensus_types::gloas::{ExecutionPayloadBid, ExecutionPayloadEnvelope, ExecutionRequests};
use consensus_types::primitives::{KZGCommitment, VersionedHash};
use consensus_types::EthSpec;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use ssz::Encode;
use std::ops::Deref;

/// `VERSIONED_HASH_VERSION_KZG` (`specs/deneb/beacon-chain.md`).
pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;
/// `DEPOSIT_REQUEST_TYPE` (`specs/electra/beacon-chain.md`).
pub const DEPOSIT_REQUEST_TYPE: u8 = 0x00;
/// `WITHDRAWAL_REQUEST_TYPE` (`specs/electra/beacon-chain.md`).
pub const WITHDRAWAL_REQUEST_TYPE: u8 = 0x01;
/// `CONSOLIDATION_REQUEST_TYPE` (`specs/electra/beacon-chain.md`).
pub const CONSOLIDATION_REQUEST_TYPE: u8 = 0x02;
/// `BUILDER_DEPOSIT_REQUEST_TYPE` (`specs/gloas/beacon-chain.md`).
pub const BUILDER_DEPOSIT_REQUEST_TYPE: u8 = 0x03;
/// `BUILDER_EXIT_REQUEST_TYPE` (`specs/gloas/beacon-chain.md`).
pub const BUILDER_EXIT_REQUEST_TYPE: u8 = 0x04;

/// The four `engine_newPayloadV5` params, which serialize as the JSON-RPC `params` array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewPayloadV5Params {
    /// 1. `executionPayload`.
    pub execution_payload: ExecutionPayloadV4,
    /// 2. `expectedBlobVersionedHashes`.
    pub expected_blob_versioned_hashes: Vec<FixedData<32>>,
    /// 3. `parentBeaconBlockRoot`.
    pub parent_beacon_block_root: FixedData<32>,
    /// 4. `executionRequests`.
    pub execution_requests: Vec<Data>,
}

impl Serialize for NewPayloadV5Params {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (
            &self.execution_payload,
            &self.expected_blob_versioned_hashes,
            &self.parent_beacon_block_root,
            &self.execution_requests,
        )
            .serialize(s)
    }
}

impl<'de> Deserialize<'de> for NewPayloadV5Params {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (payload, hashes, root, requests) = Deserialize::deserialize(d)?;
        Ok(Self {
            execution_payload: payload,
            expected_blob_versioned_hashes: hashes,
            parent_beacon_block_root: root,
            execution_requests: requests,
        })
    }
}

/// `kzg_commitment_to_versioned_hash` (`specs/deneb/beacon-chain.md` L309):
/// `VERSIONED_HASH_VERSION_KZG + sha256(kzg_commitment)[1:]`.
pub fn kzg_commitment_to_versioned_hash(commitment: &KZGCommitment) -> VersionedHash {
    let mut hash: [u8; 32] = Sha256::digest(commitment).into();
    hash[0] = VERSIONED_HASH_VERSION_KZG;
    hash.into()
}

/// `get_execution_requests_list` (`specs/gloas/beacon-chain.md` L2126-2141): `request_type ||
/// ssz_serialize(request_data)` for each non-empty group, in request-type order.
pub fn get_execution_requests_list<E: EthSpec>(r: &ExecutionRequests<E>) -> Vec<Vec<u8>> {
    let mut list = Vec::new();
    push_group(&mut list, DEPOSIT_REQUEST_TYPE, &r.deposits);
    push_group(&mut list, WITHDRAWAL_REQUEST_TYPE, &r.withdrawals);
    push_group(&mut list, CONSOLIDATION_REQUEST_TYPE, &r.consolidations);
    push_group(&mut list, BUILDER_DEPOSIT_REQUEST_TYPE, &r.builder_deposits);
    push_group(&mut list, BUILDER_EXIT_REQUEST_TYPE, &r.builder_exits);
    list
}

fn push_group<L, T>(list: &mut Vec<Vec<u8>>, request_type: u8, requests: &L)
where
    L: Encode + Deref<Target = [T]>,
{
    if requests.is_empty() {
        return;
    }
    let mut bytes = Vec::with_capacity(1 + requests.ssz_bytes_len());
    bytes.push(request_type);
    requests.ssz_append(&mut bytes);
    list.push(bytes);
}

/// The `engine_newPayloadV5` params of `envelope`, whose committed bid is `bid`
/// (`state.latest_execution_payload_bid`).
pub fn new_payload_v5_params<E: EthSpec>(
    envelope: &ExecutionPayloadEnvelope<E>,
    bid: &ExecutionPayloadBid<E>,
) -> NewPayloadV5Params {
    NewPayloadV5Params {
        execution_payload: ExecutionPayloadV4::from(&envelope.payload),
        expected_blob_versioned_hashes: bid
            .blob_kzg_commitments
            .iter()
            .map(|c| kzg_commitment_to_versioned_hash(c).into())
            .collect(),
        parent_beacon_block_root: envelope.parent_beacon_block_root.into(),
        execution_requests: get_execution_requests_list(&envelope.execution_requests)
            .into_iter()
            .map(Data)
            .collect(),
    }
}
