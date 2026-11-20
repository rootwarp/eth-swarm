//! The handler `on_execution_payload_envelope` (G L1113-1135), with
//! `verify_execution_payload_envelope` (G L683-728) and the signature set of
//! `verify_execution_payload_envelope_signature` (Gb L2107-2120).
//!
//! Fork choice does no I/O and links no BLS library. Thus three verdicts come from the caller:
//!
//! - the BLS verdict of the envelope signature, through a [`SignatureVerifier`];
//! - `is_data_available` (G L294-310), through a [`DataAvailabilityCheck`]. Column sampling is
//!   the work of the caller;
//! - `execution_engine.verify_and_notify_new_payload`, through an [`ExecutionEngine`], as a
//!   [`PayloadImport`].
//!
//! A VALID answer and an optimistic answer (SYNCING or ACCEPTED) both permit the import. With
//! optimistic sync the payload counts as verified, so a FULL child of its block passes the
//! parent check of `on_block` (G L1058-1061). `store.payloads` holds roots only, so the store
//! does not record which of the two answers the engine gave: the caller must keep the
//! optimistic status. Missing data or a refused answer keeps the root out of `store.payloads`,
//! and the EMPTY node of the block stays viable.
//!
//! Wiring rule: the change that connects this handler to block import must fail closed while
//! `ExecutionStatuses::el_contradiction()` of cl-chain is set. While the flag is set, its
//! [`ExecutionEngine`] must give [`PayloadImport::Refused`] for each envelope. This handler does
//! not read that flag: the flag is cl-chain state, and fork choice does not depend on cl-chain.
//!
//! A failed call leaves the store as it was: the handler changes the store only after each
//! check and each hook passed. Gb is `gloas/beacon-chain.md`.

use crate::attestations::SignatureVerifier;
use crate::store::{compute_time_at_slot_ms, milliseconds_to_seconds, seconds_to_milliseconds};
use crate::{EnvelopeError, Error, Store};
use consensus_types::gloas::{
    BeaconState, ExecutionPayload, ExecutionPayloadEnvelope, ExecutionRequests,
    SignedExecutionPayloadEnvelope,
};
use consensus_types::primitives::{KZGCommitment, Root, VersionedHash};
use consensus_types::signing::{
    compute_signing_root, envelope_signer, SignatureSet, BUILDER_INDEX_SELF_BUILD,
    DOMAIN_BEACON_BUILDER,
};
use consensus_types::EthSpec;
use sha2::{Digest, Sha256};
use state_transition::accessors::{builder_key_version, get_domain};
use state_transition::{state_root, Preset};
use std::num::NonZeroU64;
use tree_hash::TreeHash;

/// The answer of `is_data_available(beacon_block_root)` (G L294-310).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAvailability {
    /// Each column sidecar to sample is available and valid.
    Available,
    /// A column sidecar is missing or is not valid. The payload MAY wait until its data is
    /// available (G L1124-1126).
    Unavailable,
}

/// The data availability check of the caller.
pub trait DataAvailabilityCheck {
    /// `is_data_available(beacon_block_root)`.
    fn is_data_available(&self, beacon_block_root: Root) -> DataAvailability;
}

/// What the answer of the execution engine permits for a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadImport {
    /// VALID: import the payload.
    Valid,
    /// SYNCING or ACCEPTED: import the payload optimistically (`bellatrix/optimistic-sync.md`).
    Optimistic,
    /// No import: INVALID, INVALID_BLOCK_HASH, an engine error, no answer in time, or a gate
    /// of the caller that refuses the import.
    Refused,
}

impl PayloadImport {
    /// Whether the answer permits the import: [`Self::Valid`] or [`Self::Optimistic`].
    pub fn permits_import(self) -> bool {
        matches!(self, Self::Valid | Self::Optimistic)
    }
}

/// `NewPayloadRequest` (Gb L988-995) by reference: the hook reads the envelope in place, and
/// the transactions are not copied.
#[derive(Debug, Clone, Copy)]
pub struct NewPayloadRequestRef<'a, E: EthSpec> {
    /// `execution_payload`.
    pub execution_payload: &'a ExecutionPayload<E>,
    /// `versioned_hashes`: one for each blob commitment of the bid, in order.
    pub versioned_hashes: &'a [VersionedHash],
    /// `parent_beacon_block_root`.
    pub parent_beacon_block_root: Root,
    /// `execution_requests`.
    pub execution_requests: &'a ExecutionRequests<E>,
}

/// The execution engine of the caller.
pub trait ExecutionEngine<E: Preset> {
    /// `execution_engine.verify_and_notify_new_payload(request)` (G L719-726): the engine gets
    /// the request, and its answer comes back as an import permit.
    fn verify_and_notify_new_payload(&self, request: &NewPayloadRequestRef<'_, E>)
        -> PayloadImport;
}

/// `kzg_commitment_to_versioned_hash` (`deneb/beacon-chain.md`):
/// `VERSIONED_HASH_VERSION_KZG + sha256(kzg_commitment)[1:]`.
fn kzg_commitment_to_versioned_hash(commitment: &KZGCommitment) -> VersionedHash {
    /// `VERSIONED_HASH_VERSION_KZG` (`deneb/beacon-chain.md`).
    const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;
    let mut hash: [u8; 32] = Sha256::digest(commitment).into();
    hash[0] = VERSIONED_HASH_VERSION_KZG;
    VersionedHash::from(hash)
}

/// The signature set of `verify_execution_payload_envelope_signature` (Gb L2107-2120) on
/// `state`, without the BLS call.
///
/// The signer is the proposer of the block of `state` with its validator key for a self-build
/// envelope ([`BUILDER_INDEX_SELF_BUILD`]), and else `state.builders[builder_index]` with its
/// key version ([`envelope_signer`]). The signing root is over the envelope in the
/// `DOMAIN_BEACON_BUILDER` of the epoch of `state`. A builder index past the registry fails,
/// as the index lookup of the spec does.
pub fn execution_payload_envelope_signature_set<E: Preset>(
    state: &BeaconState<E>,
    signed_envelope: &SignedExecutionPayloadEnvelope<E>,
) -> Result<SignatureSet, EnvelopeError> {
    let envelope = &signed_envelope.message;
    let index = envelope.builder_index;
    // A self-build envelope has no builder key, so it has no key version.
    let version = if index == BUILDER_INDEX_SELF_BUILD {
        0
    } else {
        builder_key_version(state, index).map_err(|_| EnvelopeError::UnknownBuilder(index))?
    };
    let signer = envelope_signer(index, state.latest_block_header.proposer_index, version);
    let domain = get_domain(state, DOMAIN_BEACON_BUILDER, None);
    Ok(SignatureSet::single(
        signer,
        compute_signing_root(envelope, domain),
        signed_envelope.signature,
    ))
}

/// `verify_execution_payload_envelope` (G L683-728): the signature through `hooks`, the
/// consistency of the envelope with the block and the bid of `state`, the payload against
/// `state`, and then the execution engine through `hooks`. `slot_duration_ms` is the config
/// value `SLOT_DURATION_MS` of `compute_time_at_slot`.
///
/// The checks run in spec order, and the engine gets the payload only after every other check
/// passed. A refused engine answer is [`Error::PayloadRefused`], and a signature check with no
/// verdict is [`Error::NoSignatureVerdict`]: neither proves the envelope invalid.
pub fn verify_execution_payload_envelope<E, H>(
    state: &BeaconState<E>,
    signed_envelope: &SignedExecutionPayloadEnvelope<E>,
    slot_duration_ms: NonZeroU64,
    hooks: &H,
) -> Result<(), Error>
where
    E: Preset,
    H: SignatureVerifier<E> + ExecutionEngine<E> + ?Sized,
{
    let set = execution_payload_envelope_signature_set(state, signed_envelope)?;
    if !hooks
        .verify_signature_sets(state, &[set])
        .map_err(Error::NoSignatureVerdict)?
    {
        return Err(EnvelopeError::InvalidSignature.into());
    }
    let envelope = &signed_envelope.message;
    check_envelope(state, envelope, slot_duration_ms)?;
    let versioned_hashes: Vec<VersionedHash> = state
        .latest_execution_payload_bid
        .blob_kzg_commitments
        .iter()
        .map(kzg_commitment_to_versioned_hash)
        .collect();
    let request = NewPayloadRequestRef {
        execution_payload: &envelope.payload,
        versioned_hashes: &versioned_hashes,
        parent_beacon_block_root: envelope.parent_beacon_block_root,
        execution_requests: &envelope.execution_requests,
    };
    if hooks
        .verify_and_notify_new_payload(&request)
        .permits_import()
    {
        Ok(())
    } else {
        Err(Error::PayloadRefused(envelope.beacon_block_root))
    }
}

/// `Ok` if `holds`, else the assert failure `error`.
fn check(holds: bool, error: impl FnOnce() -> EnvelopeError) -> Result<(), Error> {
    if holds {
        Ok(())
    } else {
        Err(Error::InvalidEnvelope(error()))
    }
}

/// The asserts of `verify_execution_payload_envelope` between the signature and the engine
/// call (G L694-712), in spec order.
fn check_envelope<E: Preset>(
    state: &BeaconState<E>,
    envelope: &ExecutionPayloadEnvelope<E>,
    slot_duration_ms: NonZeroU64,
) -> Result<(), Error> {
    // A copy with no pending update: a milhouse list has a root only after its updates apply.
    let mut state = state.clone();
    let mut header = state.latest_block_header.clone();
    header.state_root = state_root(&mut state).map_err(Error::Stf)?;
    let block_root = header.tree_hash_root();
    check(envelope.beacon_block_root == block_root, || {
        EnvelopeError::BeaconBlockRoot {
            envelope: envelope.beacon_block_root,
            block: block_root,
        }
    })?;
    let parent_root = state.latest_block_header.parent_root;
    check(envelope.parent_beacon_block_root == parent_root, || {
        EnvelopeError::ParentBeaconBlockRoot {
            envelope: envelope.parent_beacon_block_root,
            state: parent_root,
        }
    })?;

    let bid = &state.latest_execution_payload_bid;
    let payload = &envelope.payload;
    check(envelope.builder_index == bid.builder_index, || {
        EnvelopeError::BuilderIndex {
            envelope: envelope.builder_index,
            bid: bid.builder_index,
        }
    })?;
    check(payload.prev_randao == bid.prev_randao, || {
        EnvelopeError::PrevRandao {
            payload: payload.prev_randao,
            bid: bid.prev_randao,
        }
    })?;
    check(payload.gas_limit == bid.gas_limit, || {
        EnvelopeError::GasLimit {
            payload: payload.gas_limit,
            bid: bid.gas_limit,
        }
    })?;
    check(payload.block_hash == bid.block_hash, || {
        EnvelopeError::BlockHash {
            payload: payload.block_hash,
            bid: bid.block_hash,
        }
    })?;
    let requests_root = envelope.execution_requests.tree_hash_root();
    check(requests_root == bid.execution_requests_root, || {
        EnvelopeError::ExecutionRequestsRoot {
            envelope: requests_root,
            bid: bid.execution_requests_root,
        }
    })?;

    check(payload.slot_number == state.slot, || EnvelopeError::Slot {
        payload: payload.slot_number,
        state: state.slot,
    })?;
    check(payload.parent_hash == state.latest_block_hash, || {
        EnvelopeError::ParentHash {
            payload: payload.parent_hash,
            state: state.latest_block_hash,
        }
    })?;
    // `compute_time_at_slot` (P0b L1292-1298): the `Uint64` overflow of the spec fails.
    let genesis_time_ms = seconds_to_milliseconds(state.genesis_time);
    let expected_time = milliseconds_to_seconds(compute_time_at_slot_ms(
        genesis_time_ms,
        state.slot,
        slot_duration_ms,
    )?);
    check(payload.timestamp == expected_time, || {
        EnvelopeError::Timestamp {
            payload: payload.timestamp,
            expected: expected_time,
        }
    })?;
    let withdrawals_root = payload.withdrawals.tree_hash_root();
    let expected_root = state.payload_expected_withdrawals.tree_hash_root();
    check(withdrawals_root == expected_root, || {
        EnvelopeError::WithdrawalsRoot {
            payload: withdrawals_root,
            expected: expected_root,
        }
    })
}

/// `on_execution_payload_envelope` (G L1113-1135).
///
/// The block of the envelope must be in the store, its data must be available, and the
/// envelope must pass [`verify_execution_payload_envelope`] on the post-state of the block.
/// Then the root of the block goes into `store.payloads`, so `is_payload_verified` is true for
/// it. The block can be one that a prune dropped and the store keeps (`Store::dropped`), as
/// the spec's store keeps every block.
///
/// Data availability comes before the envelope checks, as in the spec, so an envelope without
/// its data costs no signature check and no engine call. [`Error::DataUnavailable`] and
/// [`Error::PayloadRefused`] do not prove the envelope invalid: the caller can give it again
/// later.
pub fn on_execution_payload_envelope<E, H>(
    store: &mut Store<E>,
    hooks: &H,
    signed_envelope: &SignedExecutionPayloadEnvelope<E>,
) -> Result<(), Error>
where
    E: Preset,
    H: SignatureVerifier<E> + ExecutionEngine<E> + DataAvailabilityCheck + ?Sized,
{
    let root = signed_envelope.message.beacon_block_root;
    let state = store
        .target_block_state(root)
        .map_err(|_| EnvelopeError::UnknownBeaconBlock(root))?;
    if hooks.is_data_available(root) != DataAvailability::Available {
        return Err(Error::DataUnavailable(root));
    }
    verify_execution_payload_envelope(state, signed_envelope, store.slot_duration_ms, hooks)?;
    store.payloads.insert(root);
    Ok(())
}
