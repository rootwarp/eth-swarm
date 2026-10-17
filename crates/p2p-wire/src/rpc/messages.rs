//! The req/resp message bodies, transcribed from consensus-specs v1.7.0-beta.4.
//!
//! - [`StatusV2`]: `fulu/p2p-interface.md` "Status v2" (adds `earliest_available_slot`).
//! - [`MetaDataV3`]: `fulu/p2p-interface.md` "GetMetaData v3" (adds `custody_group_count`).
//! - [`Ping`] and [`Goodbye`]: `phase0/p2p-interface.md`, a bare `uint64` each.
//! - [`BlocksByRangeV2Request`]: `phase0/p2p-interface.md` "BeaconBlocksByRange v2" request.
//! - [`ErrorMessage`]: `phase0/p2p-interface.md` "Responding side", `List[byte, 256]`.
//!
//! Every type here is fixed-size except [`ErrorMessage`], whose bound is
//! [`MAX_ERROR_MESSAGE_LEN`]; [`crate::rpc::protocols`] holds the length bounds the codec checks
//! before decoding.

use consensus_types::primitives::{Epoch, Root, Slot};
use ssz::BitVector;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use typenum::{U256, U4, U64};

/// `ForkDigest`: the first four bytes of `compute_fork_data_root` (or the BPO-adjusted digest
/// from Fulu on).
pub type ForkDigest = [u8; 4];

/// `ATTESTATION_SUBNET_COUNT` (`phase0/p2p-interface.md` configuration), 64 on every network.
pub type AttestationSubnetCount = U64;
/// `SYNC_COMMITTEE_SUBNET_COUNT` (`altair/validator.md`), 4 on every network.
pub type SyncCommitteeSubnetCount = U4;

/// The longest `ErrorMessage`: `List[byte, 256]`.
pub const MAX_ERROR_MESSAGE_LEN: usize = 256;

/// `Status` v2 (Fulu): the handshake both sides send on `/eth2/beacon_chain/req/status/2/`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct StatusV2 {
    /// The sender's current fork digest.
    pub fork_digest: ForkDigest,
    /// The root of the sender's finalized checkpoint.
    pub finalized_root: Root,
    /// The epoch of the sender's finalized checkpoint.
    pub finalized_epoch: Epoch,
    /// The root of the sender's head block.
    pub head_root: Root,
    /// The slot of the sender's head block.
    pub head_slot: Slot,
    /// The earliest slot the sender can serve blocks for.
    pub earliest_available_slot: Slot,
}

/// `MetaData` v3 (Fulu): the response on `/eth2/beacon_chain/req/metadata/3/`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct MetaDataV3 {
    /// Increments on every change to the other fields.
    pub seq_number: u64,
    /// The attestation subnets the sender is subscribed to.
    pub attnets: BitVector<AttestationSubnetCount>,
    /// The sync-committee subnets the sender is subscribed to.
    pub syncnets: BitVector<SyncCommitteeSubnetCount>,
    /// How many custody groups the sender custodies.
    pub custody_group_count: u64,
}

/// `Ping`: the sender's `MetaData.seq_number`, as both request and response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[ssz(struct_behaviour = "transparent")]
pub struct Ping(pub u64);

/// `Goodbye`: the reason code a peer sends before disconnecting (1 client shutdown, 2
/// irrelevant network, 3 fault/error; 128 and up client specific).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[ssz(struct_behaviour = "transparent")]
pub struct Goodbye(pub u64);

/// The `BeaconBlocksByRange` v2 request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct BlocksByRangeV2Request {
    /// The first slot of the range.
    pub start_slot: Slot,
    /// How many slots the range covers; at most this many blocks come back.
    pub count: u64,
    /// Deprecated, must be 1.
    pub step: u64,
}

/// `ErrorMessage`: the payload of a response chunk with result code 1, 2 or 3. Usually UTF-8,
/// but the spec does not require it, so it stays raw bytes.
pub type ErrorMessage = VariableList<u8, U256>;
