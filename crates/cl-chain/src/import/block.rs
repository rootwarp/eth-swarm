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
//! Before it returns the post-state, the import asks a [`PayloadImportGate`] about the payload
//! bid of the block. A refusal is IGNORE. Today the core uses [`PermitAll`]; a later check of
//! the execution status of the payload will plug in here.

use crate::verify::client::BlsOutcome;
use crate::verify::pubkey_feed::{builder_signer, BuilderFeed};
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{BLSPubkey, Epoch, Hash32, Root};
use crypto_bls::{eth_aggregate_pubkeys, PublicKey};
use ethswarm_proto::verify::{BlsSet, KeyNamespace, Signer, VerifyOrigin};
use network_config::ChainConfig;
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

/// The gate the core uses today: it permits each payload.
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

/// Imports `block` on `pre`, the post-state of its parent (see the module docs). `verdict`
/// gives one cl-verify verdict for a batch of sets, or none. `gate` can refuse the payload bid
/// of the block (IGNORE).
pub fn import_block<E: Preset>(
    pre: &BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    config: &ChainConfig,
    verdict: &dyn Fn(Vec<BlsSet>) -> BlsOutcome,
    gate: &dyn PayloadImportGate,
) -> Result<Imported<E>, NotImported> {
    let capella_fork_version = config
        .capella_fork_version()
        .map_err(|e| NotImported::Ignored(format!("network config: {e}")))?;
    let schedule = |epoch: Epoch| config.get_blob_parameters(epoch).max_blobs_per_block;
    let backend = ClVerify {
        keys: pre,
        builders: BuilderFeed::new(),
        verdict,
    };
    let bls = BlsContext {
        backend: &backend,
        aggregator: &Aggregator,
        genesis_fork_version: config.genesis_fork_version(),
        capella_fork_version,
        blob_schedule: &schedule,
    };
    let mut post = pre.clone();
    match state_transition(&mut post, block, true, &bls) {
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
