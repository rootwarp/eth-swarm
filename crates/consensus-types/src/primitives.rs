//! Custom types from `phase0/beacon-chain.md` onward, as SSZ-transparent aliases.
//!
//! Integers are plain `u64` so that containers encode and hash exactly like the spec's `Uint64`.

pub use alloy_primitives::{Address, B256, U256};
pub use network_config::{Epoch, ForkName, Version, FAR_FUTURE_EPOCH};

/// `Slot`.
pub type Slot = u64;
/// `CommitteeIndex`.
pub type CommitteeIndex = u64;
/// `ValidatorIndex`.
pub type ValidatorIndex = u64;
/// `BuilderIndex` (Gloas).
pub type BuilderIndex = u64;
/// `Gwei`.
pub type Gwei = u64;
/// `WithdrawalIndex`.
pub type WithdrawalIndex = u64;
/// `ParticipationFlags` (Altair).
pub type ParticipationFlags = u8;
/// `Root`.
pub type Root = B256;
/// `Hash32`.
pub type Hash32 = B256;
/// `Bytes32`.
pub type Bytes32 = B256;
/// `VersionedHash` (Deneb).
pub type VersionedHash = B256;
/// `Domain`.
pub type Domain = B256;
/// `DomainType`.
pub type DomainType = [u8; 4];
/// `ExecutionAddress`.
pub type ExecutionAddress = Address;
/// `BLSPubkey`.
pub type BLSPubkey = [u8; 48];
/// `BLSSignature`.
pub type BLSSignature = [u8; 96];
/// `KZGCommitment` (Deneb).
pub type KZGCommitment = [u8; 48];
/// `KZGProof` (Deneb).
pub type KZGProof = [u8; 48];
/// `ColumnIndex` (Fulu `das-core.md`).
pub type ColumnIndex = u64;
/// `RowIndex` (Fulu `das-core.md`).
pub type RowIndex = u64;
