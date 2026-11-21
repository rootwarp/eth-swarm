//! Import of one block on the pre-state of its parent.
//!
//! [`import_block`] runs `state_transition` (`phase0/beacon-chain.md`, with the
//! `process_block` of `gloas/beacon-chain.md`) with `validate_result = true` on a copy of the
//! pre-state. Its [`SignatureBackend`] sends the signature sets of the block to cl-verify,
//! through the `verdict` function of the caller, and gives the transition that verdict only:
//! cl-chain runs no BLS check itself. The transition then applies the block and checks
//! `block.state_root`. The import checks `hash_tree_root(post) == block.state_root` again
//! before it returns the post-state, and the caller commits only that post-state. On any other
//! outcome nothing is committed.
//!
//! Each signer goes to cl-verify as a verify.v1 `Signer` of `VERIFY_ORIGIN_IMPORT`: a validator
//! by its index with its key inline, a builder through [`builder_signer`] with the key of the
//! state. cl-chain runs no PubkeyFeed client yet, so cl-verify holds no validator key, and the
//! verify.v1 inline bound (`max(acked, sent)`, both 0) puts each validator key inline. A key
//! without a registry index (a BLS-to-execution change, a deposit) has no verify.v1 signer:
//! such a set is no verdict. The same holds for a deposit signature in the slot loop or in the
//! parent payload, as its verdict is not prefetched yet.
//!
//! The keys come from the pre-state. A validator never changes its key, and the slot loop adds
//! no validator that a valid block signs with (a new validator is not active yet). A builder
//! index can take a new key: the set carries the key version of the state at the block slot,
//! and a pre-state key of another version is no verdict.
//!
//! [`check_proposer_signature`] checks the proposer signature alone on the pre-state, through
//! the same backend, before the slot loop of the transition (the gossip order). The transition
//! then checks it again with the other sets of the block.
//!
//! Before the walk of the chain core toward a block far after its parent,
//! [`check_proposer_signature_in`] checks the proposer signature with the key of the post-state
//! of the parent and the proposer domain of [`schedule_proposer_domain`]: the fork version that
//! the network schedule gives for the epoch of the block. It reads no proposer of that state,
//! and not its `fork`, which a fork in the empty slots would change.
//!
//! The pre-state is the post-state of the parent, or that state after [`process_empty_slots`]
//! to a slot before the block: the walk of the chain core toward a block far after its parent.
//! The walk sends its deposit verdicts through the same backend.
//!
//! Before it returns the post-state, the import asks a [`PayloadImportGate`] about the payload
//! bid of the block. A refusal is IGNORE. The chain core has no gate until one is set, and
//! commits nothing without one; a later check of the execution status of the payload will plug
//! in here.

use crate::verify::client::BlsOutcome;
use crate::verify::pubkey_feed::{builder_signer, BuilderFeed};
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{BLSPubkey, Domain, Epoch, Hash32, Root, Slot};
use consensus_types::signing::{compute_domain, compute_signing_root, DOMAIN_BEACON_PROPOSER};
use crypto_bls::{eth_aggregate_pubkeys, PublicKey};
use ethswarm_proto::verify::{BlsSet, KeyNamespace, Signer, VerifyOrigin};
use network_config::ChainConfig;
use state_transition::per_slot::process_slots;
use state_transition::signatures::verify_block_signature;
use state_transition::{
    state_root, state_transition, AggregationError, BackendError, BlsContext, Preset,
    PubkeyAggregator, SignatureBackend, SignatureSet, SignerRef, StfError,
};
use tree_hash::TreeHash;

/// Says if a block whose payload bid has these hashes may commit. The import asks it only
/// after the transition accepted the bid (`bid.parent_block_hash == state.latest_block_hash`)
/// and the post-state root equals `block.state_root`.
pub trait PayloadImportGate: Send {
    /// `true` if the block may commit. `block_hash` is `bid.block_hash`, `parent_block_hash`
    /// is `bid.parent_block_hash`.
    fn permits(&self, block_hash: &Hash32, parent_block_hash: &Hash32) -> bool;
}

/// A gate that permits each payload. The chain core uses it only when its caller sets it: a
/// core without a gate commits nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct PermitAll;

impl PayloadImportGate for PermitAll {
    fn permits(&self, _block_hash: &Hash32, _parent_block_hash: &Hash32) -> bool {
        true
    }
}

/// The post-state of an imported block, and its roots.
#[derive(Debug, Clone)]
pub struct Imported<E: Preset> {
    /// `hash_tree_root(block.message)`.
    pub block_root: Root,
    /// `hash_tree_root(post)`, equal to `block.state_root`.
    pub state_root: Root,
    /// The post-state.
    pub post: BeaconState<E>,
}

/// Why a block has no post-state. Nothing is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotImported {
    /// A proven invalid block (REJECT): an INVALID verdict
    /// ([`StfError::InvalidBlockSignature`]), a failed spec assert on the block's own
    /// pre-state ([`StfError::proves_invalid`]), or a post-state root that is not
    /// `block.state_root`.
    Invalid(StfError),
    /// No verdict and no proof (IGNORE): no verdict from cl-verify (a timeout, a dropped or
    /// late answer, `UNKNOWN_INDEX`, an overload, a stream error), a set that verify.v1 cannot
    /// carry, or a transition error that is not a proof. Why, for the log.
    Ignored(String),
}

/// Imports `block` on `pre`, the post-state of its parent or that state after
/// [`process_empty_slots`] (see the module docs). `verdict` gives one cl-verify verdict for a
/// batch of sets, or none. `gate` can refuse the payload bid of the block (IGNORE).
pub fn import_block<E: Preset>(
    pre: &BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    config: &ChainConfig,
    verdict: &dyn Fn(Vec<BlsSet>) -> BlsOutcome,
    gate: &dyn PayloadImportGate,
) -> Result<Imported<E>, NotImported> {
    let mut post = pre.clone();
    let applied = with_bls(pre, config, verdict, |bls| {
        state_transition(&mut post, block, true, bls)
    })
    .map_err(NotImported::Ignored)?;
    match applied {
        Ok(()) => {}
        Err(e) if e.proves_invalid() => return Err(NotImported::Invalid(e)),
        Err(e) => return Err(NotImported::Ignored(e.to_string())),
    }
    let computed = state_root(&mut post).map_err(|e| NotImported::Ignored(e.to_string()))?;
    if computed != block.message.state_root {
        return Err(NotImported::Invalid(StfError::StateRootMismatch {
            block: block.message.state_root,
            computed,
        }));
    }
    let bid = &block.message.body.signed_execution_payload_bid.message;
    if !gate.permits(&bid.block_hash, &bid.parent_block_hash) {
        return Err(NotImported::Ignored(format!(
            "the payload gate refused payload {} on parent {}",
            bid.block_hash, bid.parent_block_hash
        )));
    }
    Ok(Imported {
        block_root: block.message.tree_hash_root(),
        state_root: computed,
        post,
    })
}

/// Checks the proposer signature of `block` on `pre`, the pre-state of its import, before the
/// slot loop: the registry key of `proposer_index` in `pre`, and the proposer domain of the
/// epoch of the block (`block_proposer_signature_set`). The set goes to cl-verify alone,
/// through `verdict`. An INVALID verdict is [`StfError::InvalidBlockSignature`]; no verdict is
/// IGNORE.
///
/// `pre` is the post-state of the parent, or that state after [`process_empty_slots`] to the
/// slot before the block. It gives the fork version of the domain, so the check is right only
/// while no fork comes between `pre` and the block. The core imports Gloas blocks on Gloas
/// states only.
pub fn check_proposer_signature<E: Preset>(
    pre: &BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    verdict: &dyn Fn(Vec<BlsSet>) -> BlsOutcome,
) -> Result<(), NotImported> {
    let backend = ClVerify {
        keys: pre,
        builders: BuilderFeed::new(),
        verdict,
    };
    match verify_block_signature(pre, block, &backend) {
        Ok(()) => Ok(()),
        Err(e) if e.proves_invalid() => Err(NotImported::Invalid(e)),
        Err(e) => Err(NotImported::Ignored(e.to_string())),
    }
}

/// `compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, genesis_validators_root)`, where
/// `fork_version` is the version of the fork that the schedule of `config` gives for `epoch`.
/// `None` before the first fork of the schedule (Fulu).
pub fn schedule_proposer_domain(
    config: &ChainConfig,
    epoch: Epoch,
    genesis_validators_root: Root,
) -> Option<Domain> {
    let schedule = config.fork_schedule();
    let fork = schedule.fork_at(epoch)?;
    Some(compute_domain(
        DOMAIN_BEACON_PROPOSER,
        schedule.fork_version(fork),
        genesis_validators_root,
    ))
}

/// Checks the proposer signature of `block` alone, through `verdict`: the registry key of
/// `proposer_index` in `keys`, over the signing root of the block in `domain`. It reads no
/// proposer and no fork of `keys`. An INVALID verdict is [`StfError::InvalidBlockSignature`];
/// no verdict, or an index past the registry of `keys`, is IGNORE.
pub fn check_proposer_signature_in<E: Preset>(
    keys: &BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    domain: Domain,
    verdict: &dyn Fn(Vec<BlsSet>) -> BlsOutcome,
) -> Result<(), NotImported> {
    let set = SignatureSet::single(
        SignerRef::Validator(block.message.proposer_index),
        compute_signing_root(&block.message, domain),
        block.signature,
    );
    let backend = ClVerify {
        keys,
        builders: BuilderFeed::new(),
        verdict,
    };
    match backend.verify_signature_sets(std::slice::from_ref(&set)) {
        Ok(true) => Ok(()),
        Ok(false) => Err(NotImported::Invalid(StfError::InvalidBlockSignature)),
        Err(e) => Err(NotImported::Ignored(e.0)),
    }
}

/// Runs `process_slots(state, slot)` over the empty slots after the post-state of a parent:
/// the walk of the chain core toward a block far after that parent. `keys` gives the keys of
/// the signers. At each epoch boundary, the deposit verdicts that the boundary needs go to
/// cl-verify through `verdict`, one call for each deposit. verify.v1 has no signer for a key
/// that is not in the registry, so such a deposit has no verdict yet. No error of the walk is
/// a proof about a block: each is `Err`, why for the log (IGNORE).
pub fn process_empty_slots<E: Preset>(
    state: &mut BeaconState<E>,
    slot: Slot,
    keys: &BeaconState<E>,
    config: &ChainConfig,
    verdict: &dyn Fn(Vec<BlsSet>) -> BlsOutcome,
) -> Result<(), String> {
    with_bls(keys, config, verdict, |bls| process_slots(state, slot, bls))?
        .map_err(|e| format!("the empty slots before the block: {e}"))
}

/// Runs `f` with the BLS context of an import on the network of `config`: each batch of sets
/// goes to cl-verify through `verdict`, with the keys of `keys`. `Err` if the network config
/// lacks a value of the context.
fn with_bls<E: Preset, R>(
    keys: &BeaconState<E>,
    config: &ChainConfig,
    verdict: &dyn Fn(Vec<BlsSet>) -> BlsOutcome,
    f: impl FnOnce(&BlsContext) -> R,
) -> Result<R, String> {
    let capella_fork_version = config
        .capella_fork_version()
        .map_err(|e| format!("network config: {e}"))?;
    let schedule = |epoch: Epoch| config.get_blob_parameters(epoch).max_blobs_per_block;
    let backend = ClVerify {
        keys,
        builders: BuilderFeed::new(),
        verdict,
    };
    Ok(f(&BlsContext {
        backend: &backend,
        aggregator: &Aggregator,
        genesis_fork_version: config.genesis_fork_version(),
        capella_fork_version,
        blob_schedule: &schedule,
    }))
}

/// The signature backend of an import: each batch goes to cl-verify through `verdict`.
struct ClVerify<'a, E: Preset> {
    /// The pre-state: the keys of the signers.
    keys: &'a BeaconState<E>,
    /// The builder entries cl-verify acknowledged: none yet, so each builder key goes inline.
    builders: BuilderFeed,
    verdict: &'a dyn Fn(Vec<BlsSet>) -> BlsOutcome,
}

impl<E: Preset> ClVerify<'_, E> {
    /// The verify.v1 signer of `signer`.
    fn signer(&self, signer: &SignerRef) -> Result<Signer, BackendError> {
        match *signer {
            SignerRef::Validator(index) => {
                let pubkey = usize::try_from(index)
                    .ok()
                    .and_then(|i| self.keys.validators.get(i))
                    .map(|validator| validator.pubkey)
                    .ok_or_else(|| BackendError(format!("validator {index} has no key")))?;
                Ok(Signer {
                    validator_index: index,
                    inline_pubkey: pubkey.to_vec(),
                    namespace: KeyNamespace::Validator as i32,
                    builder: None,
                })
            }
            SignerRef::Builder { index, version } => {
                let signer = builder_signer(self.keys, index, VerifyOrigin::Import, &self.builders)
                    .map_err(|e| BackendError(e.to_string()))?;
                if signer.builder.as_ref().map(|b| b.key_version) != Some(version) {
                    return Err(BackendError(format!(
                        "builder {index} has another key in the pre-state"
                    )));
                }
                Ok(signer)
            }
            SignerRef::Inline(_) => Err(BackendError(
                "verify.v1 has no signer for a key without a registry index".into(),
            )),
        }
    }
}

impl<E: Preset> SignatureBackend for ClVerify<'_, E> {
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError> {
        let mut wire = Vec::with_capacity(sets.len());
        for set in sets {
            wire.push(BlsSet {
                signers: set
                    .signers()
                    .iter()
                    .map(|signer| self.signer(signer))
                    .collect::<Result<_, _>>()?,
                signing_root: set.signing_root().to_vec(),
                signature: set.signature().to_vec(),
            });
        }
        match (self.verdict)(wire) {
            BlsOutcome::Valid => Ok(true),
            BlsOutcome::Invalid => Ok(false),
            BlsOutcome::NoVerdict(why) => Err(BackendError(why)),
        }
    }
}

/// `eth_aggregate_pubkeys` on `crypto-bls` (feature `aggregate`), for the next sync committee.
struct Aggregator;

impl PubkeyAggregator for Aggregator {
    fn aggregate_pubkeys(&self, pubkeys: &[BLSPubkey]) -> Result<BLSPubkey, AggregationError> {
        let keys = pubkeys
            .iter()
            .map(PublicKey::from_validated_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AggregationError(e.to_string()))?;
        let refs: Vec<&PublicKey> = keys.iter().collect();
        eth_aggregate_pubkeys(&refs)
            .map(|sum| sum.to_bytes())
            .map_err(|e| AggregationError(e.to_string()))
    }
}
