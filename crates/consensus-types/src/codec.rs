//! Bounded decoding of untrusted bytes.
//!
//! [`decode`] checks `len <= caps::max_size(kind, fork)` before `Decode::from_ssz_bytes` runs, so
//! an oversized message is refused without allocating. The fork is the caller's: from the topic's
//! fork digest, or from the object's slot via [`crate::forked`].
//!
//! [`decode_for`] and [`check_size_for`] take the network's [`NetworkCaps`], which the Gloas
//! `DataColumnSidecar` cap depends on. [`decode`] and [`check_size`] refuse that kind with
//! [`DecodeError::NeedsNetworkCaps`] and serve every other kind (see [`crate::caps`]).

use crate::caps::{self, NetworkCaps, ObjectKind};
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
    /// The kind's cap depends on the network, and the call was made without a
    /// [`NetworkCaps`]; nothing was decoded.
    #[error("{kind} needs the network's NetworkCaps: decode it with decode_for or a _with/_by_slot call")]
    NeedsNetworkCaps {
        /// The object kind.
        kind: ObjectKind,
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

/// Fails unless `kind` exists at `fork` and `len` is within its cap. Refuses a kind that
/// [needs network caps](ObjectKind::needs_network_caps); use [`check_size_for`] for it.
pub fn check_size<E: EthSpec>(
    kind: ObjectKind,
    fork: ForkName,
    len: usize,
) -> Result<(), DecodeError> {
    check_size_on::<E>(kind, fork, None, len)
}

/// [`check_size`] with the cap on `network`, for every kind.
pub fn check_size_for<E: EthSpec>(
    kind: ObjectKind,
    fork: ForkName,
    network: &NetworkCaps,
    len: usize,
) -> Result<(), DecodeError> {
    check_size_on::<E>(kind, fork, Some(network), len)
}

/// The size check on `network`, or without one, where a network-dependent kind is refused.
fn check_size_on<E: EthSpec>(
    kind: ObjectKind,
    fork: ForkName,
    network: Option<&NetworkCaps>,
    len: usize,
) -> Result<(), DecodeError> {
    let max = match network {
        Some(n) => caps::max_size_for::<E>(kind, fork, n),
        None if kind.needs_network_caps() => return Err(DecodeError::NeedsNetworkCaps { kind }),
        None => caps::max_size::<E>(kind, fork),
    }
    .ok_or(DecodeError::NotInFork { kind, fork })?;
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

/// Decodes `bytes` as `T` after the size check for `kind` at `fork` on `network` (`None`:
/// without one, refusing a network-dependent kind).
pub(crate) fn decode_checked<E: EthSpec, T: Decode>(
    kind: ObjectKind,
    fork: ForkName,
    network: Option<&NetworkCaps>,
    bytes: &[u8],
) -> Result<T, DecodeError> {
    check_size_on::<E>(kind, fork, network, bytes.len())?;
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
    /// [`ObjectKind::DataColumnSidecar`].
    DataColumnSidecar(forked::DataColumnSidecar<E>),
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
            Object::DataColumnSidecar(_) => K::DataColumnSidecar,
        }
    }
}

/// Decodes `bytes` as `kind` at `fork`, refusing anything over the kind's cap before decoding.
/// Refuses a kind that [needs network caps](ObjectKind::needs_network_caps) with
/// [`DecodeError::NeedsNetworkCaps`]; use [`decode_for`] for it.
pub fn decode<E: EthSpec>(
    kind: ObjectKind,
    fork: ForkName,
    bytes: &[u8],
) -> Result<Object<E>, DecodeError> {
    decode_on::<E>(kind, fork, None, bytes)
}

/// [`decode`] with the cap on `network`, for every kind.
pub fn decode_for<E: EthSpec>(
    kind: ObjectKind,
    fork: ForkName,
    network: &NetworkCaps,
    bytes: &[u8],
) -> Result<Object<E>, DecodeError> {
    decode_on::<E>(kind, fork, Some(network), bytes)
}

fn decode_on<E: EthSpec>(
    kind: ObjectKind,
    fork: ForkName,
    network: Option<&NetworkCaps>,
    bytes: &[u8],
) -> Result<Object<E>, DecodeError> {
    use ObjectKind as K;
    let (b, n) = (bytes, network);
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
        K::DataColumnSidecar => {
            Object::DataColumnSidecar(forked::DataColumnSidecar::decode_for_fork(b, fork, n)?)
        }
        K::SingleAttestation => {
            Object::SingleAttestation(decode_checked::<E, _>(kind, fork, n, b)?)
        }
        K::ProposerSlashing => Object::ProposerSlashing(decode_checked::<E, _>(kind, fork, n, b)?),
        K::SignedVoluntaryExit => {
            Object::SignedVoluntaryExit(decode_checked::<E, _>(kind, fork, n, b)?)
        }
        K::SignedBlsToExecutionChange => {
            Object::SignedBlsToExecutionChange(decode_checked::<E, _>(kind, fork, n, b)?)
        }
        K::SyncCommitteeMessage => {
            Object::SyncCommitteeMessage(decode_checked::<E, _>(kind, fork, n, b)?)
        }
        K::SignedContributionAndProof => {
            Object::SignedContributionAndProof(decode_checked::<E, _>(kind, fork, n, b)?)
        }
        K::SignedExecutionPayloadBid => {
            Object::SignedExecutionPayloadBid(decode_checked::<E, _>(kind, fork, n, b)?)
        }
        K::SignedExecutionPayloadEnvelope => {
            Object::SignedExecutionPayloadEnvelope(decode_checked::<E, _>(kind, fork, n, b)?)
        }
        K::PayloadAttestationMessage => {
            Object::PayloadAttestationMessage(decode_checked::<E, _>(kind, fork, n, b)?)
        }
        K::SignedProposerPreferences => {
            Object::SignedProposerPreferences(decode_checked::<E, _>(kind, fork, n, b)?)
        }
    })
}
