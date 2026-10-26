//! The signature seam of the pure state transition.
//!
//! The transition only builds [`SignatureSet`]s; a [`SignatureBackend`] that the caller
//! supplies checks them. cl-chain uses cl-verify, and the spec-vector runner can use an
//! in-process BLS backend. A set names its signers by [`SignerRef`], never by key material,
//! for registry members.
//!
//! [`block_signature_sets`] gives every set of a block for one backend call. The block
//! processing steps check no signature themselves.
//!
//! The epoch processing also needs `eth_aggregate_pubkeys` for the next sync committee. A
//! [`PubkeyAggregator`] that the caller supplies does it, so the crate links no BLS library.
//! A [`BlsContext`] holds the backend, the aggregator, the `GENESIS_FORK_VERSION` of the
//! deposit domain and the other values of the network config that the transition reads.

pub use consensus_types::signing::{SignatureSet, SignerRef};

use crate::accessors::builder_key_version;
use crate::accessors::{get_block_root_at_slot, get_current_epoch, get_domain};
use crate::per_block::attestation::{check_attestation, check_indexed_attestation};
use crate::per_block::bid::{check_builder_bid_before_block, BlobSchedule};
use crate::per_block::payload_attestation::{
    check_indexed_payload_attestation, check_payload_attestation_target,
    get_indexed_payload_attestation,
};
use crate::per_block::state_proposer_index;
use crate::per_block::BlockContext;
use crate::preset::BUILDER_INDEX_SELF_BUILD;
use crate::{Preset, StfError};
use consensus_types::common::{
    DepositMessage, ProposerSlashing, SignedBLSToExecutionChange, SignedBeaconBlockHeader,
    SignedVoluntaryExit, SyncAggregate,
};
use consensus_types::gloas::{
    Attestation, AttesterSlashing, BeaconBlockBody, BeaconState, IndexedAttestation,
    IndexedPayloadAttestation, PayloadAttestation, SignedBeaconBlock, SignedExecutionPayloadBid,
};
use consensus_types::primitives::{BLSPubkey, BLSSignature, Bytes32, Gwei, Root, Version};
use consensus_types::signing::{
    compute_domain, compute_signing_root, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_BUILDER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_BLS_TO_EXECUTION_CHANGE, DOMAIN_DEPOSIT, DOMAIN_PTC_ATTESTER,
    DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE, DOMAIN_VOLUNTARY_EXIT,
};

/// `G2_POINT_AT_INFINITY` (`altair/bls.md` L25): the compressed G2 identity.
pub const G2_POINT_AT_INFINITY: BLSSignature = {
    let mut bytes = [0u8; 96];
    bytes[0] = 0xc0;
    bytes
};

/// The backend gave no verdict (a timeout, an overload, an unknown signer). This is never a
/// proof that a signature is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("signature backend gave no verdict: {0}")]
pub struct BackendError(pub String);

/// Checks signature sets for the state transition. Calls are synchronous.
pub trait SignatureBackend {
    /// `Ok(true)` if every set in `sets` is valid, `Ok(false)` if at least one is not.
    ///
    /// A key or a signature that does not decode, or a key that fails `KeyValidate`, makes
    /// its set invalid: `Ok(false)`, never `Err`. The spec needs this for the inline keys of
    /// deposits ([`SignerRef::Inline`]): `bls.Verify` returns `False` for such a key, and the
    /// deposit is ignored. `Err` is only for a backend that is not available or that fails
    /// (for example a timeout, an overload or a verdict that was not fetched).
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError>;
}

/// The aggregator failed (for example on a key that fails `KeyValidate`, or on an empty
/// input). The keys come from the validator registry, whose deposits passed a proof of
/// possession, so this is never a proof that an input is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("pubkey aggregation failed: {0}")]
pub struct AggregationError(pub String);

/// `eth_aggregate_pubkeys` (`altair/bls.md` L36-52) for the state transition. cl-chain
/// implements it on `crypto-bls` (feature `aggregate`). Calls are synchronous.
pub trait PubkeyAggregator {
    /// The compressed sum of `pubkeys`, with each duplicate counted. `Err` for an empty input
    /// or for a key that does not decode or fails `KeyValidate`.
    fn aggregate_pubkeys(&self, pubkeys: &[BLSPubkey]) -> Result<BLSPubkey, AggregationError>;
}

/// The BLS inputs of the transition that the state does not hold.
#[derive(Clone, Copy)]
pub struct BlsContext<'a> {
    /// The verdicts of the block signatures and of the deposit signatures.
    pub backend: &'a dyn SignatureBackend,
    /// `eth_aggregate_pubkeys` for `get_next_sync_committee`.
    pub aggregator: &'a dyn PubkeyAggregator,
    /// The `GENESIS_FORK_VERSION` of the network, for the domain of the deposit signatures
    /// and of the BLS-to-execution changes (C L632-634). It is a value of the network
    /// config, not of the preset: Sepolia and Hoodi use the mainnet preset with other
    /// versions. cl-chain reads it from `network_config::ChainConfig::genesis_fork_version()`.
    pub genesis_fork_version: Version,
    /// The `CAPELLA_FORK_VERSION` of the network, for the domain of the voluntary exits
    /// from Deneb (EIP-7044, E L1853-1855). It is a value of the network config, not of the
    /// preset. The network config of cl-chain does not give it yet.
    pub capella_fork_version: Version,
    /// The blob schedule of the network (`BLOB_SCHEDULE` with its BPO forks), for the blob
    /// limit of a bid (G L2183-2187). It is a value of the network config, not of the
    /// preset. cl-chain gives `network_config::ChainConfig::get_blob_parameters`.
    pub blob_schedule: &'a dyn BlobSchedule,
}

/// The proposer signature set of a block: `verify_block_signature` (P0 L1839-1844) without
/// the BLS call.
///
/// `state` is the state at the block's slot. The function first checks that the proposer
/// of `state.proposer_lookahead` for the slot is in the registry. If it is not, our own
/// state is wrong, and the error is [`StfError::ListIndexOutOfRange`] (not a proof) for any
/// block. [`StfError::UnknownValidator`] is only for a block index past the registry when
/// the lookahead is valid.
pub fn block_proposer_signature_set<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
) -> Result<SignatureSet, StfError> {
    state_proposer_index(state)?;
    let block = &signed_block.message;
    if block.proposer_index >= state.validators.len() as u64 {
        return Err(StfError::UnknownValidator(block.proposer_index));
    }
    let domain = get_domain(state, DOMAIN_BEACON_PROPOSER, None);
    Ok(SignatureSet::single(
        SignerRef::Validator(block.proposer_index),
        compute_signing_root(block, domain),
        signed_block.signature,
    ))
}

/// `verify_block_signature` (P0 L1839-1844) through `backend`.
pub fn verify_block_signature<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    let set = block_proposer_signature_set(state, signed_block)?;
    if backend.verify_signature_sets(std::slice::from_ref(&set))? {
        Ok(())
    } else {
        Err(StfError::InvalidBlockSignature)
    }
}

/// The RANDAO reveal set of a block: the `bls.Verify` of `process_randao` (P0 L2376-2381),
/// by the proposer of the state's slot over the current epoch.
pub fn randao_signature_set<E: Preset>(
    state: &BeaconState<E>,
    body: &BeaconBlockBody<E>,
) -> Result<SignatureSet, StfError> {
    let epoch = get_current_epoch(state);
    let proposer = state_proposer_index(state)?;
    let signing_root = compute_signing_root(&epoch, get_domain(state, DOMAIN_RANDAO, None));
    Ok(SignatureSet::single(
        SignerRef::Validator(proposer),
        signing_root,
        body.randao_reveal,
    ))
}

/// The sync aggregate set of a block: the `eth_fast_aggregate_verify` of
/// `process_sync_aggregate` (A L637-664), over the block root of the previous slot.
///
/// The signers are the participants by validator index (duplicates stay, as each position
/// signs). The spec sums the same keys through `aggregate_pubkey` when more than half
/// participate; the sum is the same, because `aggregate_pubkey` is the sum of `pubkeys`.
///
/// With no participant there is no set (`Ok(None)`) if the signature is
/// [`G2_POINT_AT_INFINITY`], and [`StfError::InvalidSyncAggregateSignature`] if it is not.
pub fn sync_aggregate_signature_set<E: Preset>(
    state: &BeaconState<E>,
    sync_aggregate: &SyncAggregate<E>,
) -> Result<Option<SignatureSet>, StfError> {
    sync_aggregate_signature_set_with(state, sync_aggregate, &mut BlockContext::default())
}

/// [`sync_aggregate_signature_set`] with the committee indices of `ctx`, which the rewards
/// of the same block read again. An empty aggregate needs no indices.
pub fn sync_aggregate_signature_set_with<E: Preset>(
    state: &BeaconState<E>,
    sync_aggregate: &SyncAggregate<E>,
    ctx: &mut BlockContext,
) -> Result<Option<SignatureSet>, StfError> {
    let previous_slot = state.slot.saturating_sub(1);
    let domain = get_domain(
        state,
        DOMAIN_SYNC_COMMITTEE,
        Some(E::epoch_at_slot(previous_slot)),
    );
    let signing_root = compute_signing_root(&get_block_root_at_slot(state, previous_slot)?, domain);
    let signature = sync_aggregate.sync_committee_signature;
    let bits = &sync_aggregate.sync_committee_bits;
    if bits.is_zero() {
        return if signature == G2_POINT_AT_INFINITY {
            Ok(None)
        } else {
            Err(StfError::InvalidSyncAggregateSignature)
        };
    }
    let signers = ctx
        .sync_committee_indices(state)?
        .iter()
        .zip(bits.iter())
        .filter(|(_, bit)| *bit)
        .map(|(&index, _)| SignerRef::Validator(index))
        .collect();
    // At least one bit is set, so the signers are not empty.
    SignatureSet::aggregate(signers, signing_root, signature)
        .map(Some)
        .map_err(|_| StfError::InvalidSyncAggregateSignature)
}

/// The sync aggregate check of `process_sync_aggregate` through `backend`, for a caller that
/// processes a sync aggregate outside [`block_signature_sets`].
pub fn verify_sync_aggregate_signature<E: Preset>(
    state: &BeaconState<E>,
    sync_aggregate: &SyncAggregate<E>,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    verify_sync_aggregate_signature_with(
        state,
        sync_aggregate,
        backend,
        &mut BlockContext::default(),
    )
}

/// [`verify_sync_aggregate_signature`] with the committee indices of `ctx`, which
/// [`crate::per_block::sync_aggregate::process_sync_aggregate_with`] reads again.
pub fn verify_sync_aggregate_signature_with<E: Preset>(
    state: &BeaconState<E>,
    sync_aggregate: &SyncAggregate<E>,
    backend: &dyn SignatureBackend,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    match sync_aggregate_signature_set_with(state, sync_aggregate, ctx)? {
        None => Ok(()),
        Some(set) if backend.verify_signature_sets(std::slice::from_ref(&set))? => Ok(()),
        Some(_) => Err(StfError::InvalidSyncAggregateSignature),
    }
}

/// The aggregate signature set of an indexed payload attestation: the
/// `bls.FastAggregateVerify` of `is_valid_indexed_payload_attestation` (G L1094-1110), with
/// the PTC domain of the epoch of `data.slot`.
///
/// The structural checks ([`check_indexed_payload_attestation`]) run first. If one fails,
/// the function gives that error and no set. The signers are the attesting indices in order,
/// a duplicate included, as each PTC position signs.
pub fn indexed_payload_attestation_signature_set<E: Preset>(
    state: &BeaconState<E>,
    indexed: &IndexedPayloadAttestation<E>,
) -> Result<SignatureSet, StfError> {
    check_indexed_payload_attestation(state, indexed)?;
    let epoch = E::epoch_at_slot(indexed.data.slot);
    let domain = get_domain(state, DOMAIN_PTC_ATTESTER, Some(epoch));
    let signers = indexed
        .attesting_indices
        .iter()
        .map(|&index| SignerRef::Validator(index))
        .collect();
    // The structural checks refuse an empty list, so the signers are not empty.
    SignatureSet::aggregate(
        signers,
        compute_signing_root(&indexed.data, domain),
        indexed.signature,
    )
    .map_err(|_| StfError::PayloadAttestationNoAttesters)
}

/// The signature set of a payload attestation in a block: the asserts of
/// `process_payload_attestation` (G L2494-2496) on `parent_root` and `state.slot`, then
/// [`get_indexed_payload_attestation`] and [`indexed_payload_attestation_signature_set`].
///
/// `parent_root` is the parent root of the block. The header step makes it
/// `state.latest_block_header.parent_root` (P0 L2350-2370), which the spec compares. The
/// cheap asserts run before the PTC read, so a wrong target costs no backend call.
pub fn payload_attestation_signature_set<E: Preset>(
    state: &BeaconState<E>,
    payload_attestation: &PayloadAttestation<E>,
    parent_root: Root,
) -> Result<SignatureSet, StfError> {
    check_payload_attestation_target(&payload_attestation.data, parent_root, state.slot)?;
    let indexed = get_indexed_payload_attestation(state, payload_attestation)?;
    indexed_payload_attestation_signature_set(state, &indexed)
}

/// The checks of `process_payload_attestation` with the signature through `backend`, for a
/// caller that processes a payload attestation outside [`block_signature_sets`]. `state` is
/// the state after the header step of the block, so the parent root is
/// `state.latest_block_header.parent_root`.
pub fn verify_payload_attestation_signature<E: Preset>(
    state: &BeaconState<E>,
    payload_attestation: &PayloadAttestation<E>,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    let parent_root = state.latest_block_header.parent_root;
    let set = payload_attestation_signature_set(state, payload_attestation, parent_root)?;
    if backend.verify_signature_sets(std::slice::from_ref(&set))? {
        Ok(())
    } else {
        Err(StfError::InvalidPayloadAttestationSignature)
    }
}

/// The signature set of a voluntary exit: the `bls.Verify` of `process_voluntary_exit`
/// (E L1853-1857), by the key of the validator in the registry, in the domain
/// `compute_domain(DOMAIN_VOLUNTARY_EXIT, CAPELLA_FORK_VERSION, genesis_validators_root)`.
/// That domain does not change with the fork of the state (EIP-7044).
///
/// `capella_fork_version` is the `CAPELLA_FORK_VERSION` of the network. A validator outside
/// the registry has no key: [`StfError::UnknownValidator`], as `state.validators[index]`
/// fails in the spec.
pub fn voluntary_exit_signature_set<E: Preset>(
    state: &BeaconState<E>,
    signed_voluntary_exit: &SignedVoluntaryExit,
    capella_fork_version: Version,
) -> Result<SignatureSet, StfError> {
    let voluntary_exit = &signed_voluntary_exit.message;
    let index = voluntary_exit.validator_index;
    if index >= state.validators.len() as u64 {
        return Err(StfError::UnknownValidator(index));
    }
    let domain = compute_domain(
        DOMAIN_VOLUNTARY_EXIT,
        capella_fork_version,
        state.genesis_validators_root,
    );
    Ok(SignatureSet::single(
        SignerRef::Validator(index),
        compute_signing_root(voluntary_exit, domain),
        signed_voluntary_exit.signature,
    ))
}

/// [`voluntary_exit_signature_set`] through `backend`, for a caller that processes a
/// voluntary exit outside [`block_signature_sets`].
pub fn verify_voluntary_exit_signature<E: Preset>(
    state: &BeaconState<E>,
    signed_voluntary_exit: &SignedVoluntaryExit,
    capella_fork_version: Version,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    let set = voluntary_exit_signature_set(state, signed_voluntary_exit, capella_fork_version)?;
    if backend.verify_signature_sets(std::slice::from_ref(&set))? {
        Ok(())
    } else {
        Err(StfError::InvalidVoluntaryExitSignature)
    }
}

/// The signature set of a BLS-to-execution change: the `bls.Verify` of
/// `process_bls_to_execution_change` (C L632-636), by the inline key `from_bls_pubkey`
/// ([`SignerRef::Inline`]), in the fork-agnostic domain
/// `compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, GENESIS_FORK_VERSION,
/// genesis_validators_root)`.
///
/// `genesis_fork_version` is the `GENESIS_FORK_VERSION` of the network. A key that does
/// not decode makes the set invalid (`Ok(false)` from the backend).
pub fn bls_to_execution_change_signature_set<E: Preset>(
    state: &BeaconState<E>,
    signed_address_change: &SignedBLSToExecutionChange,
    genesis_fork_version: Version,
) -> SignatureSet {
    let address_change = &signed_address_change.message;
    let domain = compute_domain(
        DOMAIN_BLS_TO_EXECUTION_CHANGE,
        genesis_fork_version,
        state.genesis_validators_root,
    );
    SignatureSet::single(
        SignerRef::Inline(address_change.from_bls_pubkey),
        compute_signing_root(address_change, domain),
        signed_address_change.signature,
    )
}

/// [`bls_to_execution_change_signature_set`] through `backend`, for a caller that processes
/// a BLS-to-execution change outside [`block_signature_sets`].
pub fn verify_bls_to_execution_change_signature<E: Preset>(
    state: &BeaconState<E>,
    signed_address_change: &SignedBLSToExecutionChange,
    genesis_fork_version: Version,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    let set =
        bls_to_execution_change_signature_set(state, signed_address_change, genesis_fork_version);
    if backend.verify_signature_sets(std::slice::from_ref(&set))? {
        Ok(())
    } else {
        Err(StfError::InvalidBlsToExecutionChangeSignature)
    }
}

/// The two sets of a proposer slashing: the `bls.Verify` of each header in
/// `process_proposer_slashing` (P0 L2436-2441), by the proposer of `signed_header_1`, each
/// over the `DOMAIN_BEACON_PROPOSER` of the epoch of its own header.
///
/// A proposer past the registry has no key: [`StfError::UnknownValidator`], as
/// `state.validators[header_1.proposer_index]` raises in the spec.
pub fn proposer_slashing_signature_sets<E: Preset>(
    state: &BeaconState<E>,
    proposer_slashing: &ProposerSlashing,
) -> Result<[SignatureSet; 2], StfError> {
    let proposer_index = proposer_slashing.signed_header_1.message.proposer_index;
    if proposer_index >= state.validators.len() as u64 {
        return Err(StfError::UnknownValidator(proposer_index));
    }
    let set = |signed_header: &SignedBeaconBlockHeader| {
        let epoch = E::epoch_at_slot(signed_header.message.slot);
        let domain = get_domain(state, DOMAIN_BEACON_PROPOSER, Some(epoch));
        SignatureSet::single(
            SignerRef::Validator(proposer_index),
            compute_signing_root(&signed_header.message, domain),
            signed_header.signature,
        )
    };
    Ok([
        set(&proposer_slashing.signed_header_1),
        set(&proposer_slashing.signed_header_2),
    ])
}

/// The set of `is_valid_indexed_attestation` (G L1022-1041): after the checks that need no
/// BLS ([`check_indexed_attestation`]), the `bls.FastAggregateVerify` of the attesters over
/// `data`, with the `DOMAIN_BEACON_ATTESTER` of the target epoch.
pub fn indexed_attestation_signature_set<E: Preset>(
    state: &BeaconState<E>,
    indexed_attestation: &IndexedAttestation<E>,
) -> Result<SignatureSet, StfError> {
    check_indexed_attestation(state, indexed_attestation)?;
    let data = &indexed_attestation.data;
    let domain = get_domain(state, DOMAIN_BEACON_ATTESTER, Some(data.target.epoch));
    let signers = indexed_attestation
        .attesting_indices
        .iter()
        .map(|&index| SignerRef::Validator(index))
        .collect();
    // The checks above prove that the signers are not empty.
    SignatureSet::aggregate(
        signers,
        compute_signing_root(data, domain),
        indexed_attestation.signature,
    )
    .map_err(|_| StfError::InvalidIndexedAttestation)
}

/// The two sets of an attester slashing: the `is_valid_indexed_attestation` of each
/// attestation in `process_attester_slashing` (P0 L2453-2454).
pub fn attester_slashing_signature_sets<E: Preset>(
    state: &BeaconState<E>,
    attester_slashing: &AttesterSlashing<E>,
) -> Result<[SignatureSet; 2], StfError> {
    Ok([
        indexed_attestation_signature_set(state, &attester_slashing.attestation_1)?,
        indexed_attestation_signature_set(state, &attester_slashing.attestation_2)?,
    ])
}

/// The set of an attestation: the `is_valid_indexed_attestation` of
/// `get_indexed_attestation(state, attestation)` in `process_attestation` (G L2432).
///
/// The asserts of `process_attestation` before it (G L2403-2423) run first, so that the
/// committees of an epoch other than the previous or the current one are never shuffled.
pub fn attestation_signature_set<E: Preset>(
    state: &BeaconState<E>,
    attestation: &Attestation<E>,
) -> Result<SignatureSet, StfError> {
    attestation_signature_set_with(state, attestation, &mut BlockContext::default())
}

/// [`attestation_signature_set`] with the committee caches of `ctx`, which the other
/// attestations of the block and [`crate::per_block::attestation::process_attestation_with`]
/// read again.
pub fn attestation_signature_set_with<E: Preset>(
    state: &BeaconState<E>,
    attestation: &Attestation<E>,
    ctx: &mut BlockContext,
) -> Result<SignatureSet, StfError> {
    let indexed_attestation = check_attestation(state, attestation, ctx)?;
    indexed_attestation_signature_set(state, &indexed_attestation)
}

/// The signature set of `verify_execution_payload_bid_signature` (G L2149-2156) without the
/// BLS call: the key of `state.builders[bid.builder_index]`, named by
/// [`SignerRef::Builder`] with its [`builder_key_version`], over the bid in the
/// `DOMAIN_BEACON_BUILDER` of the current epoch.
///
/// It checks only that the builder is in the registry ([`StfError::UnknownBuilder`]; a
/// self-build bid also gives it). Run the cheap checks of the bid first: in a block,
/// [`block_bid_signature_set`] runs them, and the gossip validation runs its own
/// (`gloas/p2p-interface.md` L951-1091) before the signature.
pub fn execution_payload_bid_signature_set<E: Preset>(
    state: &BeaconState<E>,
    signed_bid: &SignedExecutionPayloadBid<E>,
) -> Result<SignatureSet, StfError> {
    let index = signed_bid.message.builder_index;
    let signer = SignerRef::Builder {
        index,
        version: builder_key_version(state, index)?,
    };
    let domain = get_domain(state, DOMAIN_BEACON_BUILDER, None);
    Ok(SignatureSet::single(
        signer,
        compute_signing_root(&signed_bid.message, domain),
        signed_bid.signature,
    ))
}

/// The signature set of the bid of a block: `None` for a self-build bid, else
/// [`execution_payload_bid_signature_set`].
///
/// A self-build bid has no BLS check: the bid step checks its value and its infinity
/// signature. For a builder bid, the asserts that need no BLS and that the earlier steps of
/// the block cannot change run first
/// (`per_block::bid::check_builder_bid_before_block`). A bid that fails them gives
/// its error and no set, so it costs no key lookup and no backend call.
///
/// `state` is the state at the block's slot, before `process_block`. `max_blobs_per_block`
/// is the limit of the network at the epoch of the state ([`BlobSchedule`]).
pub fn block_bid_signature_set<E: Preset>(
    state: &BeaconState<E>,
    signed_bid: &SignedExecutionPayloadBid<E>,
    max_blobs_per_block: u64,
) -> Result<Option<SignatureSet>, StfError> {
    if signed_bid.message.builder_index == BUILDER_INDEX_SELF_BUILD {
        return Ok(None);
    }
    check_builder_bid_before_block(state, &signed_bid.message, max_blobs_per_block)?;
    execution_payload_bid_signature_set(state, signed_bid).map(Some)
}

/// [`block_bid_signature_set`] through `backend`, for a caller that processes a bid outside
/// [`block_signature_sets`]. A self-build bid makes no backend call. A set that the backend
/// refuses is [`StfError::InvalidOperationSignature`].
pub fn verify_execution_payload_bid_signature<E: Preset>(
    state: &BeaconState<E>,
    signed_bid: &SignedExecutionPayloadBid<E>,
    max_blobs_per_block: u64,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    match block_bid_signature_set(state, signed_bid, max_blobs_per_block)? {
        None => Ok(()),
        Some(set) => verify_operation_signatures(std::slice::from_ref(&set), backend),
    }
}

/// Checks the sets of one operation through `backend` in one call, for a caller that
/// processes the operation outside [`block_signature_sets`]. A set that the backend refuses
/// is [`StfError::InvalidOperationSignature`].
pub fn verify_operation_signatures(
    sets: &[SignatureSet],
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    if backend.verify_signature_sets(sets)? {
        Ok(())
    } else {
        Err(StfError::InvalidOperationSignature)
    }
}

/// Every signature set of a block, in the order of `process_block`: the proposer
/// signature, the RANDAO reveal, the bid of a builder (none for a self-build bid), two sets
/// for each proposer slashing, two for each attester
/// slashing, one for each attestation, the voluntary exits, the BLS-to-execution changes,
/// one set for each payload attestation, and the sync aggregate (none for an empty
/// aggregate with the infinity signature). The operation sets follow the order of
/// `process_operations` (G L2228-2263). The domains of the exits and the changes take the
/// fork versions of the network from `bls`.
///
/// The bid comes before the RANDAO reveal in `process_block`. The order of the sets in one
/// batch does not change the verdict. The bid set is built after the cheap checks of the
/// bid ([`block_bid_signature_set`]), with the blob limit of `bls.blob_schedule` at the
/// epoch of the state. Each signed part of the body has a set builder here, so that no
/// signature of the block is left out of the batch.
///
/// `state` is the state at the block's slot, after `process_slots` and before
/// `process_block`. The steps before each check do not change what the set reads (the
/// registry keys, the proposer lookahead, the PTC window, the fork, the genesis validators
/// root and the block roots), so the sets are the ones that the spec checks during
/// `process_block`. The payload attestation sets compare with `block.parent_root`, which is
/// the parent root of the latest block header after the header step. The attestation sets
/// also read the beacon committees of the previous and the current epoch. No step of a
/// block changes them: an exit or a slashing sets an exit epoch after `MAX_SEED_LOOKAHEAD`
/// epochs, and the RANDAO mix of the current epoch is not in the seed of these two epochs.
pub fn block_signature_sets<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    bls: &BlsContext,
) -> Result<Vec<SignatureSet>, StfError> {
    block_signature_sets_with(state, signed_block, bls, &mut BlockContext::default())
}

/// [`block_signature_sets`] with a [`BlockContext`] that
/// [`crate::per_block::process_block_with`] can use again for the same block.
pub fn block_signature_sets_with<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    bls: &BlsContext,
    ctx: &mut BlockContext,
) -> Result<Vec<SignatureSet>, StfError> {
    let body = &signed_block.message.body;
    // The proposer set comes first, so its lookahead check runs before any other read.
    let mut sets = vec![
        block_proposer_signature_set(state, signed_block)?,
        randao_signature_set(state, body)?,
    ];
    // `verify_execution_payload_bid_signature` (G L2149-2156).
    let max_blobs_per_block = bls
        .blob_schedule
        .max_blobs_per_block(get_current_epoch(state));
    sets.extend(block_bid_signature_set(
        state,
        &body.signed_execution_payload_bid,
        max_blobs_per_block,
    )?);
    for proposer_slashing in &body.proposer_slashings {
        sets.extend(proposer_slashing_signature_sets(state, proposer_slashing)?);
    }
    for attester_slashing in &body.attester_slashings {
        sets.extend(attester_slashing_signature_sets(state, attester_slashing)?);
    }
    for attestation in &body.attestations {
        sets.push(attestation_signature_set_with(state, attestation, ctx)?);
    }
    for exit in &body.voluntary_exits {
        sets.push(voluntary_exit_signature_set(
            state,
            exit,
            bls.capella_fork_version,
        )?);
    }
    for change in &body.bls_to_execution_changes {
        sets.push(bls_to_execution_change_signature_set(
            state,
            change,
            bls.genesis_fork_version,
        ));
    }
    // `process_payload_attestation` (G L2488-2499), the last operation list.
    for payload_attestation in &body.payload_attestations {
        sets.push(payload_attestation_signature_set(
            state,
            payload_attestation,
            signed_block.message.parent_root,
        )?);
    }
    // Last, as in `process_block`.
    sets.extend(sync_aggregate_signature_set_with(
        state,
        &body.sync_aggregate,
        ctx,
    )?);
    Ok(sets)
}

/// Checks [`block_signature_sets`] through `bls.backend` in one call.
pub fn verify_block_signatures<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    bls: &BlsContext,
) -> Result<(), StfError> {
    verify_block_signatures_with(state, signed_block, bls, &mut BlockContext::default())
}

/// [`verify_block_signatures`] with a [`BlockContext`] for the same block.
pub fn verify_block_signatures_with<E: Preset>(
    state: &BeaconState<E>,
    signed_block: &SignedBeaconBlock<E>,
    bls: &BlsContext,
    ctx: &mut BlockContext,
) -> Result<(), StfError> {
    let sets = block_signature_sets_with(state, signed_block, bls, ctx)?;
    if bls.backend.verify_signature_sets(&sets)? {
        Ok(())
    } else {
        Err(StfError::InvalidBlockSignature)
    }
}

/// The signature set of `is_valid_deposit_signature` (E L1786-1797) without the BLS call:
/// the inline key over its `DepositMessage`, in the domain `compute_domain(DOMAIN_DEPOSIT)`.
/// That domain takes `genesis_fork_version` (see [`BlsContext::genesis_fork_version`]) and a
/// zero genesis validators root, so a deposit is valid across forks.
///
/// The caller uses the set to fetch the verdict before the transition (ADR-011).
pub fn deposit_signature_set(
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
    signature: BLSSignature,
    genesis_fork_version: Version,
) -> SignatureSet {
    let deposit_message = DepositMessage {
        pubkey,
        withdrawal_credentials,
        amount,
    };
    // Fork-agnostic domain since deposits are valid across forks
    let domain = compute_domain(DOMAIN_DEPOSIT, genesis_fork_version, Root::ZERO);
    SignatureSet::single(
        SignerRef::Inline(pubkey),
        compute_signing_root(&deposit_message, domain),
        signature,
    )
}

/// `is_valid_deposit_signature` (E L1786-1797, New in Electra; Gloas keeps it), through
/// `backend`, with the set of [`deposit_signature_set`].
///
/// `Ok(false)` for an invalid signature. By the contract of [`SignatureBackend`], that
/// includes a key or a signature that does not decode or fails `KeyValidate`. A backend
/// without a verdict gives [`StfError::MissingVerdict`], never `Ok(false)`.
pub fn is_valid_deposit_signature(
    pubkey: BLSPubkey,
    withdrawal_credentials: Bytes32,
    amount: Gwei,
    signature: BLSSignature,
    genesis_fork_version: Version,
    backend: &dyn SignatureBackend,
) -> Result<bool, StfError> {
    let set = deposit_signature_set(
        pubkey,
        withdrawal_credentials,
        amount,
        signature,
        genesis_fork_version,
    );
    backend
        .verify_signature_sets(std::slice::from_ref(&set))
        .map_err(StfError::MissingVerdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caches::CommitteeCache;
    use crate::per_slot::process_slots;
    use crate::testing::{
        block_at_state_slot, bls_context, genesis_state, no_bls, ScriptedBackend,
        CAPELLA_FORK_VERSION, GENESIS_FORK_VERSION,
    };
    use consensus_types::common::{
        BLSToExecutionChange, SignedBLSToExecutionChange, SignedVoluntaryExit, VoluntaryExit,
    };
    use consensus_types::gloas::PayloadAttestationData;
    use consensus_types::primitives::Address;
    use consensus_types::Minimal;
    use std::cell::Cell;

    /// A backend with a fixed verdict that counts its calls.
    struct Counting {
        verdict: bool,
        calls: Cell<usize>,
    }

    impl SignatureBackend for Counting {
        fn verify_signature_sets(&self, _: &[SignatureSet]) -> Result<bool, BackendError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.verdict)
        }
    }

    /// 64 validators at slot 9 (epoch 1), with a sync committee of validators `0..32` and a
    /// block of the slot that has `participants` set and the signature `[0x22; 96]`.
    fn state_and_block(
        participants: &[usize],
    ) -> (BeaconState<Minimal>, SignedBeaconBlock<Minimal>) {
        let mut state = genesis_state::<Minimal>(&[32_000_000_000; 64]);
        process_slots(&mut state, 7, &no_bls()).unwrap();
        // Slots 8 and 9 by hand, without the epoch transition: the sets read the slot, the
        // registry and the block root of slot 8, and the test gives that root a known value.
        state.slot = 9;
        *state.block_roots.get_mut(8).unwrap() = Root::repeat_byte(8);
        for i in 0..32 {
            state.current_sync_committee.pubkeys[i] = state.validators.get(i).unwrap().pubkey;
        }
        let mut block = block_at_state_slot(&state);
        block.message.body.randao_reveal = [0x44; 96];
        let aggregate = &mut block.message.body.sync_aggregate;
        for &i in participants {
            aggregate.sync_committee_bits.set(i, true).unwrap();
        }
        aggregate.sync_committee_signature = [0x22; 96];
        (state, block)
    }

    #[test]
    fn block_sets() {
        // A full block: the proposer, RANDAO and sync aggregate sets, in that order.
        let (state, block) = state_and_block(&[1, 4, 4 + 16]);
        let sets = block_signature_sets(&state, &block, &no_bls()).unwrap();
        let proposer = block.message.proposer_index;
        let randao_domain = get_domain(&state, DOMAIN_RANDAO, None);
        let sync_domain = get_domain(&state, DOMAIN_SYNC_COMMITTEE, Some(1));
        let want = vec![
            SignatureSet::single(
                SignerRef::Validator(proposer),
                compute_signing_root(
                    &block.message,
                    get_domain(&state, DOMAIN_BEACON_PROPOSER, None),
                ),
                [0x11; 96],
            ),
            SignatureSet::single(
                SignerRef::Validator(proposer),
                compute_signing_root(&1u64, randao_domain),
                [0x44; 96],
            ),
            SignatureSet::aggregate(
                vec![
                    SignerRef::Validator(1),
                    SignerRef::Validator(4),
                    SignerRef::Validator(20),
                ],
                compute_signing_root(&Root::repeat_byte(8), sync_domain),
                [0x22; 96],
            )
            .unwrap(),
        ];
        assert_eq!(sets, want);
        // One backend call for the whole block.
        let rejecting = Counting {
            verdict: false,
            calls: Cell::new(0),
        };
        assert_eq!(
            verify_block_signatures(&state, &block, &bls_context(&rejecting)),
            Err(StfError::InvalidBlockSignature)
        );
        assert_eq!(rejecting.calls.get(), 1);
        let accepting = Counting {
            verdict: true,
            calls: Cell::new(0),
        };
        assert_eq!(
            verify_block_signatures(&state, &block, &bls_context(&accepting)),
            Ok(())
        );

        // An empty sync aggregate: no sync set with the infinity signature, and an error
        // (with no backend call) without it.
        let (state, mut block) = state_and_block(&[]);
        assert_eq!(
            block_signature_sets(&state, &block, &no_bls()),
            Err(StfError::InvalidSyncAggregateSignature)
        );
        let none = Counting {
            verdict: true,
            calls: Cell::new(0),
        };
        assert_eq!(
            verify_sync_aggregate_signature(&state, &block.message.body.sync_aggregate, &none),
            Err(StfError::InvalidSyncAggregateSignature)
        );
        assert_eq!(none.calls.get(), 0);
        block.message.body.sync_aggregate.sync_committee_signature = G2_POINT_AT_INFINITY;
        let sets = block_signature_sets(&state, &block, &no_bls()).unwrap();
        let mut want = want;
        want[0] = block_proposer_signature_set(&state, &block).unwrap();
        assert_eq!(sets[..], want[..2]);
        assert_eq!(
            verify_sync_aggregate_signature(&state, &block.message.body.sync_aggregate, &none),
            Ok(())
        );
        assert_eq!(none.calls.get(), 0);
    }

    #[test]
    fn randao_signing_root_known_answer() {
        // Fork version 0x07000001, genesis validators root 0x42 * 32, epoch 1 (slot 9).
        let (state, block) = state_and_block(&[]);
        assert_eq!(state.fork.current_version, [0x07, 0, 0, 0x01]);
        assert_eq!(state.genesis_validators_root, Root::repeat_byte(0x42));
        let set = randao_signature_set(&state, &block.message.body).unwrap();

        // The spec formula, step by step with sha256:
        // fork_data_root = sha256(version + 28 zero bytes + genesis_validators_root)
        // domain = DOMAIN_RANDAO + fork_data_root[:28]
        // signing_root = sha256(uint64(epoch) as 32 bytes + domain)
        let mut fork_data = [0u8; 64];
        fork_data[..4].copy_from_slice(&[0x07, 0, 0, 0x01]);
        fork_data[32..].copy_from_slice(&[0x42; 32]);
        let fork_data_root = ethereum_hashing::hash_fixed(&fork_data);
        let mut signing_data = [0u8; 64];
        signing_data[0] = 1;
        signing_data[32..36].copy_from_slice(&DOMAIN_RANDAO);
        signing_data[36..].copy_from_slice(&fork_data_root[..28]);
        let want = ethereum_hashing::hash_fixed(&signing_data);
        assert_eq!(set.signing_root().as_slice(), &want);
        // The same 32 bytes from Python's hashlib.
        assert_eq!(
            format!("{:x}", set.signing_root()),
            "7debcaa30c867dcacb24ce02e86ae835ea813c12712d3072ec3917ac88de5284"
        );
        assert_eq!(
            set.signers(),
            &[SignerRef::Validator(block.message.proposer_index)]
        );
        assert_eq!(set.signature(), &[0x44; 96]);
    }

    #[test]
    fn builder_bid_set_is_in_the_batch() {
        use crate::testing::{bid_for_state, builder};

        let (mut state, block) = state_and_block(&[1]);
        state.finalized_checkpoint.epoch = 1;
        state
            .builders
            .push(builder(0xa1, 5_000_000_000, 0))
            .unwrap();
        // A builder bid: its set comes after the proposer and RANDAO sets, and before the
        // sync aggregate set.
        let mut with = block.clone();
        let bid = bid_for_state(&state, 0, 1);
        with.message.body.signed_execution_payload_bid = bid.clone();
        let sets = block_signature_sets(&state, &with, &no_bls()).unwrap();
        assert_eq!(sets.len(), 4);
        let max = crate::testing::MINIMAL_MAX_BLOBS_PER_BLOCK;
        assert_eq!(
            block_bid_signature_set(&state, &bid, max),
            Ok(Some(sets[2].clone()))
        );
        // A forged bid of a builder that is not active fails the sets of the block, with no
        // key lookup and no backend call.
        let mut forged = with.clone();
        state.builders.get_mut(0).unwrap().deposit_epoch = 1;
        forged.message.body.signed_execution_payload_bid = bid_for_state(&state, 0, 1);
        let backend = Counting {
            verdict: true,
            calls: Cell::new(0),
        };
        assert_eq!(
            verify_block_signatures(&state, &forged, &bls_context(&backend)),
            Err(StfError::BidBuilderNotActive(0))
        );
        assert_eq!(backend.calls.get(), 0);
        // A self-build bid with another signature than the infinity needs no BLS check, but
        // the bid step rejects it; the sets do not fail for it.
        let mut self_build = block.clone();
        self_build
            .message
            .body
            .signed_execution_payload_bid
            .signature = [0x55; 96];
        assert_eq!(
            block_signature_sets(&state, &self_build, &no_bls()).map(|s| s.len()),
            Ok(3)
        );
    }

    /// A proposer slashing of validator 3, two headers of slot 5.
    fn proposer_slashing() -> ProposerSlashing {
        use consensus_types::common::BeaconBlockHeader;
        let header = |body: u8| SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: 5,
                proposer_index: 3,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body_root: Root::repeat_byte(body),
            },
            signature: [body; 96],
        };
        ProposerSlashing {
            signed_header_1: header(1),
            signed_header_2: header(2),
        }
    }

    /// A double vote in epoch 1 of validators `[2, 5]` and `[5, 7]`.
    fn attester_slashing() -> AttesterSlashing<Minimal> {
        use consensus_types::common::{AttestationData, Checkpoint};
        let indexed = |indices: &[u64], root: u8| IndexedAttestation {
            attesting_indices: indices.to_vec().try_into().unwrap(),
            data: AttestationData {
                slot: 8,
                index: 0,
                beacon_block_root: Root::repeat_byte(root),
                source: Checkpoint {
                    epoch: 0,
                    root: Root::ZERO,
                },
                target: Checkpoint {
                    epoch: 1,
                    root: Root::ZERO,
                },
            },
            signature: [root; 96],
        };
        AttesterSlashing {
            attestation_1: indexed(&[2, 5], 1),
            attestation_2: indexed(&[5, 7], 2),
        }
    }

    #[test]
    fn slashing_sets() {
        use crate::per_block::attestation::tests::attestation;
        let (state, block) = state_and_block(&[1]);
        let base = block_signature_sets(&state, &block, &no_bls()).unwrap();
        assert_eq!(base.len(), 3);
        let with = |add: &dyn Fn(&mut BeaconBlockBody<Minimal>)| {
            let mut block = block.clone();
            add(&mut block.message.body);
            let sets = block_signature_sets(&state, &block, &no_bls()).unwrap();
            // The proposer and RANDAO sets first, the sync aggregate set last. The proposer
            // signs the block, so only its signer is the same.
            assert_eq!(sets[0].signers(), base[0].signers());
            assert_eq!(sets[1], base[1]);
            assert_eq!(sets.last(), base.last());
            sets[2..sets.len() - 1].to_vec()
        };

        // An attestation (slot 5, previous epoch): one aggregate set of its attesters.
        let attestation = attestation(&state, 5, &[0, 2]);
        let sets = with(&|b| b.attestations.push(attestation.clone()).unwrap());
        assert_eq!(sets.len(), 1);
        let committee = CommitteeCache::new(&state, 0).unwrap();
        let committee = committee.committee(5, 0).unwrap();
        let mut attesters = vec![committee[0], committee[2]];
        attesters.sort_unstable();
        let domain = get_domain(&state, DOMAIN_BEACON_ATTESTER, Some(0));
        assert_eq!(
            sets[0],
            SignatureSet::aggregate(
                attesters.into_iter().map(SignerRef::Validator).collect(),
                compute_signing_root(&attestation.data, domain),
                attestation.signature,
            )
            .unwrap()
        );

        // An attester slashing: two aggregate sets, one for each attestation.
        let slashing = attester_slashing();
        let sets = with(&|b| b.attester_slashings.push(slashing.clone()).unwrap());
        assert_eq!(sets.len(), 2);
        let domain = get_domain(&state, DOMAIN_BEACON_ATTESTER, Some(1));
        for (set, indexed) in sets
            .iter()
            .zip([&slashing.attestation_1, &slashing.attestation_2])
        {
            let signers: Vec<SignerRef> = indexed
                .attesting_indices
                .iter()
                .map(|&i| SignerRef::Validator(i))
                .collect();
            assert_eq!(set.signers(), &signers[..]);
            assert_eq!(
                set.signing_root(),
                compute_signing_root(&indexed.data, domain)
            );
            assert_eq!(set.signature(), &indexed.signature);
        }

        // A proposer slashing: two sets of the proposer, one for each header, with the
        // domain of the header's epoch.
        let slashing = proposer_slashing();
        let sets = with(&|b| b.proposer_slashings.push(slashing.clone()).unwrap());
        let domain = get_domain(&state, DOMAIN_BEACON_PROPOSER, Some(0));
        let want: Vec<SignatureSet> = [&slashing.signed_header_1, &slashing.signed_header_2]
            .iter()
            .map(|h| {
                SignatureSet::single(
                    SignerRef::Validator(3),
                    compute_signing_root(&h.message, domain),
                    h.signature,
                )
            })
            .collect();
        assert_eq!(sets, want);

        // All three, in the order of `process_operations`: 2 + 2 + 1.
        let all = with(&|b| {
            b.proposer_slashings.push(proposer_slashing()).unwrap();
            b.attester_slashings.push(attester_slashing()).unwrap();
            b.attestations.push(attestation.clone()).unwrap();
        });
        assert_eq!(all.len(), 5);
        assert_eq!(all[..2], want[..]);
        let slashing = attester_slashing();
        assert_eq!(
            all[2..4],
            attester_slashing_signature_sets(&state, &slashing).unwrap()[..]
        );
        assert_eq!(
            all[4],
            attestation_signature_set(&state, &attestation).unwrap()
        );
    }

    #[test]
    fn operation_set_errors() {
        use crate::per_block::attestation::tests::attestation;
        let (state, _) = state_and_block(&[1]);
        // A proposer past the registry has no key.
        let mut stranger = proposer_slashing();
        stranger.signed_header_1.message.proposer_index = 64;
        assert_eq!(
            proposer_slashing_signature_sets(&state, &stranger),
            Err(StfError::UnknownValidator(64))
        );
        // Indices past the registry, or not sorted.
        let mut slashing = attester_slashing();
        slashing.attestation_2.attesting_indices = vec![5, 64].try_into().unwrap();
        assert_eq!(
            attester_slashing_signature_sets(&state, &slashing),
            Err(StfError::UnknownValidator(64))
        );
        slashing.attestation_1.attesting_indices = vec![5, 2].try_into().unwrap();
        assert_eq!(
            attester_slashing_signature_sets(&state, &slashing),
            Err(StfError::InvalidIndexedAttestation)
        );
        // The asserts of `process_attestation` run before the committees are read.
        let mut early = attestation(&state, 5, &[0]);
        early.data.target.epoch = 3;
        assert_eq!(
            attestation_signature_set(&state, &early),
            Err(StfError::AttestationTargetEpoch {
                target: 3,
                state_epoch: 1
            })
        );
        // One operation alone: the backend verdict, and no verdict.
        let sets = proposer_slashing_signature_sets(&state, &proposer_slashing()).unwrap();
        let backend = |verdict: bool| Counting {
            verdict,
            calls: Cell::new(0),
        };
        let rejecting = backend(false);
        assert_eq!(
            verify_operation_signatures(&sets, &rejecting),
            Err(StfError::InvalidOperationSignature)
        );
        assert_eq!(rejecting.calls.get(), 1);
        assert_eq!(verify_operation_signatures(&sets, &backend(true)), Ok(()));
    }

    #[test]
    fn one_shuffle_per_epoch() {
        use crate::per_block::attestation::process_attestation_with;
        use crate::per_block::attestation::tests::attestation;
        // Two attestations of epoch 0 and the step of each share one shuffle.
        let (mut state, mut block) = state_and_block(&[1]);
        let first = attestation(&state, 5, &[0]);
        let second = attestation(&state, 6, &[1]);
        let body = &mut block.message.body;
        body.attestations.push(first.clone()).unwrap();
        body.attestations.push(second.clone()).unwrap();
        let mut ctx = BlockContext::default();
        assert_eq!(
            block_signature_sets_with(&state, &block, &no_bls(), &mut ctx).map(|s| s.len()),
            Ok(5)
        );
        assert_eq!(ctx.committee_shuffles(), 1);
        for attestation in [&first, &second] {
            assert_eq!(
                process_attestation_with(&mut state, attestation, 8, &mut ctx),
                Ok(())
            );
        }
        assert_eq!(ctx.committee_shuffles(), 1);
        // An attestation of the current epoch shuffles that epoch one time.
        let mut third = attestation(&state, 5, &[0]);
        third.data.slot = 8;
        third.data.target.epoch = 1;
        let _ = attestation_signature_set_with(&state, &third, &mut ctx);
        let _ = attestation_signature_set_with(&state, &third, &mut ctx);
        assert_eq!(ctx.committee_shuffles(), 2);
    }

    #[test]
    fn one_index_computation_per_block() {
        use crate::per_block::sync_aggregate::process_sync_aggregate_with;
        use crate::per_block::BlockContext;

        // The set and the rewards share one computation of the committee indices.
        let (mut state, block) = state_and_block(&[1, 4]);
        let mut ctx = BlockContext::default();
        let sets = block_signature_sets_with(&state, &block, &no_bls(), &mut ctx).unwrap();
        assert_eq!(sets.len(), 3);
        assert_eq!(ctx.sync_index_scans(), 1);
        let aggregate = &block.message.body.sync_aggregate;
        assert_eq!(
            process_sync_aggregate_with(&mut state, aggregate, &mut ctx),
            Ok(())
        );
        assert_eq!(ctx.sync_index_scans(), 1);

        // An empty aggregate needs no indices for its set, so only the rewards compute them.
        let (mut state, mut block) = state_and_block(&[]);
        block.message.body.sync_aggregate.sync_committee_signature = G2_POINT_AT_INFINITY;
        let mut ctx = BlockContext::default();
        assert_eq!(
            block_signature_sets_with(&state, &block, &no_bls(), &mut ctx).map(|s| s.len()),
            Ok(2)
        );
        assert_eq!(ctx.sync_index_scans(), 0);
        let aggregate = &block.message.body.sync_aggregate;
        process_sync_aggregate_with(&mut state, aggregate, &mut ctx).unwrap();
        assert_eq!(ctx.sync_index_scans(), 1);
    }

    #[test]
    fn lookahead_outside_the_registry_is_not_a_proof() {
        // The lookahead entry of slot 9 is past the 64 validators. The public set builders
        // give `ListIndexOutOfRange` (a fault of our own state), not `UnknownValidator`,
        // for the index of the lookahead and for any other index of the block.
        let (mut state, block) = state_and_block(&[1]);
        *state.proposer_lookahead.get_mut(9 % 8).unwrap() = 64;
        let outside = StfError::ListIndexOutOfRange {
            list: "validators",
            index: 64,
        };
        for proposer_index in [64, 0] {
            let mut block = block.clone();
            block.message.proposer_index = proposer_index;
            assert_eq!(
                block_proposer_signature_set(&state, &block),
                Err(outside.clone())
            );
            assert_eq!(
                block_signature_sets(&state, &block, &no_bls()),
                Err(outside.clone())
            );
            let backend = Counting {
                verdict: true,
                calls: Cell::new(0),
            };
            let err = verify_block_signatures(&state, &block, &bls_context(&backend)).unwrap_err();
            assert_eq!(err, outside);
            assert!(!err.proves_invalid());
            assert_eq!(backend.calls.get(), 0);
        }
        // With a valid lookahead, a block index past the registry stays `UnknownValidator`.
        let (state, mut block) = state_and_block(&[1]);
        block.message.proposer_index = 64;
        assert_eq!(
            block_proposer_signature_set(&state, &block),
            Err(StfError::UnknownValidator(64))
        );
    }

    #[test]
    fn sync_set_errors() {
        let (mut state, block) = state_and_block(&[0]);
        let aggregate = &block.message.body.sync_aggregate;
        let rejecting = Counting {
            verdict: false,
            calls: Cell::new(0),
        };
        assert_eq!(
            verify_sync_aggregate_signature(&state, aggregate, &rejecting),
            Err(StfError::InvalidSyncAggregateSignature)
        );
        assert_eq!(rejecting.calls.get(), 1);
        // A committee key outside the registry.
        state.current_sync_committee.pubkeys[2] = [0xee; 48];
        assert_eq!(
            sync_aggregate_signature_set(&state, aggregate),
            Err(StfError::UnknownSyncCommitteeMember { position: 2 })
        );
        // The previous slot must be in the block-root history.
        let mut genesis = state.clone();
        genesis.slot = 0;
        assert_eq!(
            sync_aggregate_signature_set(&genesis, aggregate),
            Err(StfError::BlockRootOutOfRange {
                slot: 0,
                state_slot: 0
            })
        );
        // A proposer outside the registry has no RANDAO key.
        *state.proposer_lookahead.get_mut(9 % 8).unwrap() = 64;
        assert_eq!(
            randao_signature_set(&state, &block.message.body),
            Err(StfError::ListIndexOutOfRange {
                list: "validators",
                index: 64
            })
        );
    }

    #[test]
    fn deposit_set_signs_the_deposit_message_in_the_genesis_domain() {
        let mut credentials = Bytes32::ZERO;
        credentials[0] = 0x01;
        let set =
            deposit_signature_set([0xaa; 48], credentials, 7, [0x33; 96], GENESIS_FORK_VERSION);
        let message = DepositMessage {
            pubkey: [0xaa; 48],
            withdrawal_credentials: credentials,
            amount: 7,
        };
        // `compute_domain(DOMAIN_DEPOSIT)`: the genesis fork version and a zero root, so the
        // domain does not change with the fork of the state.
        let domain = compute_domain(DOMAIN_DEPOSIT, GENESIS_FORK_VERSION, Root::ZERO);
        let want = SignatureSet::single(
            SignerRef::Inline([0xaa; 48]),
            compute_signing_root(&message, domain),
            [0x33; 96],
        );
        assert_eq!(set, want);
        let other = deposit_signature_set([0xaa; 48], credentials, 7, [0x33; 96], [0; 4]);
        assert_ne!(other.signing_root(), want.signing_root());
    }

    #[test]
    fn deposit_verdicts_come_from_the_backend() {
        let backend = ScriptedBackend::new([
            Ok(true),
            Ok(false),
            Err(BackendError("not prefetched".into())),
        ]);
        let check = || {
            is_valid_deposit_signature(
                [0xaa; 48],
                Bytes32::ZERO,
                7,
                [0x33; 96],
                GENESIS_FORK_VERSION,
                &backend,
            )
        };
        assert_eq!(check(), Ok(true));
        assert_eq!(check(), Ok(false));
        let missing = check().unwrap_err();
        assert_eq!(
            missing,
            StfError::MissingVerdict(BackendError("not prefetched".into()))
        );
        assert!(!missing.proves_invalid());
        let set = deposit_signature_set(
            [0xaa; 48],
            Bytes32::ZERO,
            7,
            [0x33; 96],
            GENESIS_FORK_VERSION,
        );
        assert_eq!(backend.seen(), vec![set; 3]);
    }

    /// A voluntary exit of `validator_index` in epoch 1 with the signature `[0x33; 96]`.
    fn exit(validator_index: u64) -> SignedVoluntaryExit {
        SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: 1,
                validator_index,
            },
            signature: [0x33; 96],
        }
    }

    /// A BLS-to-execution change of validator 7 from the key `[0x77; 48]`.
    fn change() -> SignedBLSToExecutionChange {
        SignedBLSToExecutionChange {
            message: BLSToExecutionChange {
                validator_index: 7,
                from_bls_pubkey: [0x77; 48],
                to_execution_address: Address::repeat_byte(0xee),
            },
            signature: [0x44; 96],
        }
    }

    #[test]
    fn exit_and_bls_change_sets() {
        let (state, mut block) = state_and_block(&[1]);
        let body = &mut block.message.body;
        for index in [5, 6] {
            body.voluntary_exits.push(exit(index)).unwrap();
        }
        body.bls_to_execution_changes.push(change()).unwrap();
        // A payload attestation of one PTC member for slot 8 and the parent of the block.
        let mut payload_attestation = PayloadAttestation {
            aggregation_bits: Default::default(),
            data: PayloadAttestationData {
                beacon_block_root: block.message.parent_root,
                slot: 8,
                payload_present: true,
                blob_data_available: false,
            },
            signature: [0x55; 96],
        };
        payload_attestation.aggregation_bits.set(0, true).unwrap();
        let body = &mut block.message.body;
        body.payload_attestations
            .push(payload_attestation.clone())
            .unwrap();
        let sets = block_signature_sets(&state, &block, &no_bls()).unwrap();

        // The exits sign over the fixed CAPELLA_FORK_VERSION domain (EIP-7044), and the BLS
        // change over the GENESIS_FORK_VERSION domain, both with the genesis validators
        // root of the state. Neither is the domain of the current fork.
        let gvr = state.genesis_validators_root;
        let exit_domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, [0x03, 0, 0, 0x01], gvr);
        let change_domain = compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, [0, 0, 0, 0x01], gvr);
        assert_ne!(exit_domain, get_domain(&state, DOMAIN_VOLUNTARY_EXIT, None));
        assert_ne!(
            change_domain,
            get_domain(&state, DOMAIN_BLS_TO_EXECUTION_CHANGE, None)
        );
        let exit_set = |index| {
            SignatureSet::single(
                SignerRef::Validator(index),
                compute_signing_root(&exit(index).message, exit_domain),
                [0x33; 96],
            )
        };
        let change_set = SignatureSet::single(
            SignerRef::Inline([0x77; 48]),
            compute_signing_root(&change().message, change_domain),
            [0x44; 96],
        );
        // In the order of `process_operations`: the exits, the change and then the payload
        // attestation. The sync aggregate comes last.
        assert_eq!(sets.len(), 7);
        assert_eq!(sets[2..5], [exit_set(5), exit_set(6), change_set.clone()]);
        assert_eq!(
            sets[5],
            payload_attestation_signature_set(
                &state,
                &payload_attestation,
                block.message.parent_root
            )
            .unwrap()
        );
        assert_eq!(
            sets[6],
            sync_aggregate_signature_set(&state, &block.message.body.sync_aggregate)
                .unwrap()
                .unwrap()
        );
        assert_eq!(
            voluntary_exit_signature_set(&state, &exit(5), CAPELLA_FORK_VERSION),
            Ok(exit_set(5))
        );
        assert_eq!(
            bls_to_execution_change_signature_set(&state, &change(), GENESIS_FORK_VERSION),
            change_set
        );

        // An exit of a validator outside the registry has no key: the block is invalid.
        block.message.body.voluntary_exits.push(exit(64)).unwrap();
        assert_eq!(
            block_signature_sets(&state, &block, &no_bls()),
            Err(StfError::UnknownValidator(64))
        );
    }

    #[test]
    fn verify_exit_and_bls_change() {
        let (state, _) = state_and_block(&[]);
        let backend = |verdict| Counting {
            verdict,
            calls: Cell::new(0),
        };
        let capella = CAPELLA_FORK_VERSION;
        let genesis = GENESIS_FORK_VERSION;
        assert_eq!(
            verify_voluntary_exit_signature(&state, &exit(5), capella, &backend(true)),
            Ok(())
        );
        assert_eq!(
            verify_voluntary_exit_signature(&state, &exit(5), capella, &backend(false)),
            Err(StfError::InvalidVoluntaryExitSignature)
        );
        let none = backend(true);
        assert_eq!(
            verify_voluntary_exit_signature(&state, &exit(64), capella, &none),
            Err(StfError::UnknownValidator(64))
        );
        assert_eq!(none.calls.get(), 0);
        assert_eq!(
            verify_bls_to_execution_change_signature(&state, &change(), genesis, &backend(true)),
            Ok(())
        );
        assert_eq!(
            verify_bls_to_execution_change_signature(&state, &change(), genesis, &backend(false)),
            Err(StfError::InvalidBlsToExecutionChangeSignature)
        );
        // A backend without a verdict is not a proof of a bad signature.
        let unavailable = crate::testing::ScriptedBackend::new([
            Err(BackendError("timeout".into())),
            Err(BackendError("timeout".into())),
        ]);
        assert_eq!(
            verify_voluntary_exit_signature(&state, &exit(5), capella, &unavailable),
            Err(StfError::SignatureBackend(BackendError("timeout".into())))
        );
        assert_eq!(
            verify_bls_to_execution_change_signature(&state, &change(), genesis, &unavailable),
            Err(StfError::SignatureBackend(BackendError("timeout".into())))
        );
    }
}
