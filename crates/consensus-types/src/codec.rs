//! Bounded decoding of untrusted bytes.
//!
//! [`decode`] checks `len <= caps::max_size(kind, fork)` before `Decode::from_ssz_bytes` runs, so
//! an oversized message is refused without allocating. The fork is the caller's: from the topic's
//! fork digest, or from the object's slot via [`crate::forked`].

use crate::caps::{self, ObjectKind};
use crate::preset::EthSpec;
use crate::primitives::{ForkName, Slot};
use crate::{common, forked, gloas};
use ssz::Decode;

/// Why bytes did not decode.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum DecodeError {
    /// The input is longer than the kind's cap; nothing was decoded or allocated.
    #[error("{kind} at {fork}: {len} bytes exceeds the cap of {max}")]
    TooLarge {
        /// The object kind.
        kind: ObjectKind,
        /// The fork it was decoded for.
        fork: ForkName,
        /// Input length.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// The fork does not define this kind (e.g. a bid before Gloas).
    #[error("{kind} does not exist at {fork}")]
    NotInFork {
        /// The object kind.
        kind: ObjectKind,
        /// The requested fork.
        fork: ForkName,
    },
    /// The object's slot is before Fulu, which this client does not decode.
    #[error("slot {slot} is before the Fulu fork")]
    PreFulu {
        /// The slot read from the object.
        slot: Slot,
    },
    /// The SSZ decoder rejected the bytes.
    #[error("ssz: {0:?}")]
    Ssz(ssz::DecodeError),
}

impl From<ssz::DecodeError> for DecodeError {
    fn from(e: ssz::DecodeError) -> Self {
        DecodeError::Ssz(e)
    }
}

/// Fails unless `kind` exists at `fork` and `len` is within its cap.
pub fn check_size<E: EthSpec>(
    kind: ObjectKind,
    fork: ForkName,
    len: usize,
) -> Result<(), DecodeError> {
    let max = caps::max_size::<E>(kind, fork).ok_or(DecodeError::NotInFork { kind, fork })?;
    if len > max {
        return Err(DecodeError::TooLarge {
            kind,
            fork,
            len,
            max,
        });
    }
    Ok(())
}

/// Decodes `bytes` as `T` after the size check for `kind` at `fork`.
pub(crate) fn decode_checked<E: EthSpec, T: Decode>(
    kind: ObjectKind,
    fork: ForkName,
    bytes: &[u8],
) -> Result<T, DecodeError> {
    check_size::<E>(kind, fork, bytes.len())?;
    Ok(T::from_ssz_bytes(bytes)?)
}

/// A decoded object of any [`ObjectKind`].
///
/// A short-lived decode result that callers match on immediately; only the state is boxed.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Object<E: EthSpec> {
    /// [`ObjectKind::SignedBeaconBlock`].
    SignedBeaconBlock(forked::SignedBeaconBlock<E>),
    /// [`ObjectKind::BeaconState`].
    BeaconState(Box<forked::BeaconState<E>>),
    /// [`ObjectKind::SignedAggregateAndProof`].
    SignedAggregateAndProof(forked::SignedAggregateAndProof<E>),
    /// [`ObjectKind::SingleAttestation`].
    SingleAttestation(common::SingleAttestation),
    /// [`ObjectKind::AttesterSlashing`].
    AttesterSlashing(forked::AttesterSlashing<E>),
    /// [`ObjectKind::ProposerSlashing`].
    ProposerSlashing(common::ProposerSlashing),
    /// [`ObjectKind::SignedVoluntaryExit`].
    SignedVoluntaryExit(common::SignedVoluntaryExit),
    /// [`ObjectKind::SignedBlsToExecutionChange`].
    SignedBlsToExecutionChange(common::SignedBLSToExecutionChange),
    /// [`ObjectKind::SyncCommitteeMessage`].
    SyncCommitteeMessage(common::SyncCommitteeMessage),
    /// [`ObjectKind::SignedContributionAndProof`].
    SignedContributionAndProof(common::SignedContributionAndProof<E>),
    /// [`ObjectKind::SignedExecutionPayloadBid`].
    SignedExecutionPayloadBid(gloas::SignedExecutionPayloadBid<E>),
    /// [`ObjectKind::SignedExecutionPayloadEnvelope`].
    SignedExecutionPayloadEnvelope(gloas::SignedExecutionPayloadEnvelope<E>),
    /// [`ObjectKind::PayloadAttestationMessage`].
    PayloadAttestationMessage(gloas::PayloadAttestationMessage),
    /// [`ObjectKind::SignedProposerPreferences`].
    SignedProposerPreferences(gloas::SignedProposerPreferences),
}

impl<E: EthSpec> Object<E> {
    /// The kind this object was decoded as.
    pub fn kind(&self) -> ObjectKind {
        use ObjectKind as K;
        match self {
            Object::SignedBeaconBlock(_) => K::SignedBeaconBlock,
            Object::BeaconState(_) => K::BeaconState,
            Object::SignedAggregateAndProof(_) => K::SignedAggregateAndProof,
            Object::SingleAttestation(_) => K::SingleAttestation,
            Object::AttesterSlashing(_) => K::AttesterSlashing,
            Object::ProposerSlashing(_) => K::ProposerSlashing,
            Object::SignedVoluntaryExit(_) => K::SignedVoluntaryExit,
            Object::SignedBlsToExecutionChange(_) => K::SignedBlsToExecutionChange,
            Object::SyncCommitteeMessage(_) => K::SyncCommitteeMessage,
            Object::SignedContributionAndProof(_) => K::SignedContributionAndProof,
            Object::SignedExecutionPayloadBid(_) => K::SignedExecutionPayloadBid,
            Object::SignedExecutionPayloadEnvelope(_) => K::SignedExecutionPayloadEnvelope,
            Object::PayloadAttestationMessage(_) => K::PayloadAttestationMessage,
            Object::SignedProposerPreferences(_) => K::SignedProposerPreferences,
        }
    }
}

/// Decodes `bytes` as `kind` at `fork`, refusing anything over the kind's cap before decoding.
pub fn decode<E: EthSpec>(
    kind: ObjectKind,
    fork: ForkName,
    bytes: &[u8],
) -> Result<Object<E>, DecodeError> {
    use ObjectKind as K;
    let b = bytes;
    Ok(match kind {
        K::SignedBeaconBlock => {
            Object::SignedBeaconBlock(forked::SignedBeaconBlock::from_ssz_bytes_for_fork(b, fork)?)
        }
        K::BeaconState => Object::BeaconState(Box::new(
            forked::BeaconState::from_ssz_bytes_for_fork(b, fork)?,
        )),
        K::SignedAggregateAndProof => Object::SignedAggregateAndProof(
            forked::SignedAggregateAndProof::from_ssz_bytes_for_fork(b, fork)?,
        ),
        K::AttesterSlashing => {
            Object::AttesterSlashing(forked::AttesterSlashing::from_ssz_bytes_for_fork(b, fork)?)
        }
        K::SingleAttestation => Object::SingleAttestation(decode_checked::<E, _>(kind, fork, b)?),
        K::ProposerSlashing => Object::ProposerSlashing(decode_checked::<E, _>(kind, fork, b)?),
        K::SignedVoluntaryExit => {
            Object::SignedVoluntaryExit(decode_checked::<E, _>(kind, fork, b)?)
        }
        K::SignedBlsToExecutionChange => {
            Object::SignedBlsToExecutionChange(decode_checked::<E, _>(kind, fork, b)?)
        }
        K::SyncCommitteeMessage => {
            Object::SyncCommitteeMessage(decode_checked::<E, _>(kind, fork, b)?)
        }
        K::SignedContributionAndProof => {
            Object::SignedContributionAndProof(decode_checked::<E, _>(kind, fork, b)?)
        }
        K::SignedExecutionPayloadBid => {
            Object::SignedExecutionPayloadBid(decode_checked::<E, _>(kind, fork, b)?)
        }
        K::SignedExecutionPayloadEnvelope => {
            Object::SignedExecutionPayloadEnvelope(decode_checked::<E, _>(kind, fork, b)?)
        }
        K::PayloadAttestationMessage => {
            Object::PayloadAttestationMessage(decode_checked::<E, _>(kind, fork, b)?)
        }
        K::SignedProposerPreferences => {
            Object::SignedProposerPreferences(decode_checked::<E, _>(kind, fork, b)?)
        }
    })
}
