//! Replay a devnet export from its genesis state.
//!
//! The export is opened only through [`open_export_pinned`](crate::export_blocks::open_export_pinned),
//! which checks the pinned `export_sha256` and opens every archive segment through
//! [`open_verified`](crate::archive::open_verified). A pin error, an `open_verified` error or a
//! root-list mismatch stops the run before the first block.
//!
//! Each later block is applied with [`state_transition`](state_transition::state_transition)
//! `(..., validate_result = true)` and the in-process BLS backend ([`crypto_bls`]). The
//! post-state `hash_tree_root` must equal `block.state_root`, and the block root must equal the
//! exported root. The first failure writes `pre_state.ssz`, `block.ssz` and `post_state.ssz`
//! under `--out` and returns an error.
//!
//! The report counts blocks, epoch boundaries crossed, FULL and EMPTY parents, and self-build
//! and builder bids. A category with zero blocks is flagged for the adversarial devnet.

use crate::archive::Sha256Digest;
use crate::export_blocks::{open_export_pinned, Export, ExportError, ExportManifest};
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{BLSPubkey, Epoch, Root, Slot};
use consensus_types::{EthSpec, Mainnet, Minimal};
use crypto_bls::{eth_aggregate_pubkeys, eth_fast_aggregate_verify, verify, PublicKey, Signature};
use network_config::ChainConfig;
use sha2::{Digest, Sha256};
use ssz::{Decode, Encode};
use state_transition::per_slot::process_slots;
use state_transition::{
    state_root, state_transition, AggregationError, BackendError, BlobSchedule, BlsContext, Preset,
    PubkeyAggregator, SignatureBackend, SignatureSet, SignerRef,
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tree_hash::TreeHash;

/// Pre-state SSZ written on the first mismatch.
pub const PRE_STATE_SSZ: &str = "pre_state.ssz";
/// Block SSZ written on the first mismatch.
pub const BLOCK_SSZ: &str = "block.ssz";
/// Our post-state SSZ written on the first mismatch.
pub const POST_STATE_SSZ: &str = "post_state.ssz";

/// `BUILDER_INDEX_SELF_BUILD`: a bid the proposer builds itself.
const SELF_BUILD: u64 = consensus_types::signing::BUILDER_INDEX_SELF_BUILD;

/// The largest `config.yaml` read from a replay pin.
const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// What [`replay`] reads. Paths are as the caller resolved them.
pub struct ReplayOptions<'a> {
    /// The export directory (`<out>/<devnet>`).
    pub export_dir: &'a Path,
    /// The `export_sha256` the export printed, the pin in `testing/replay.manifest.toml`.
    pub export_sha256: Sha256Digest,
    /// The devnet `config.yaml` the export was made with.
    pub config: &'a ChainConfig,
    /// Where the three SSZ files go on the first mismatch.
    pub out: &'a Path,
}

/// Counts from one replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Blocks checked, the genesis block included.
    pub blocks: u64,
    /// Epoch boundaries `process_slots` crossed.
    pub epochs_crossed: u64,
    /// Post-genesis blocks whose parent payload is FULL.
    pub full_parents: u64,
    /// Post-genesis blocks whose parent payload is EMPTY.
    pub empty_parents: u64,
    /// Post-genesis blocks with a self-build bid.
    pub self_build: u64,
    /// Post-genesis blocks with a builder bid.
    pub builder_bids: u64,
}

impl Report {
    /// Categories with zero blocks, in report order. Each one is a gap for the adversarial devnet.
    pub fn zero_categories(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.full_parents == 0 {
            names.push("full_parents");
        }
        if self.empty_parents == 0 {
            names.push("empty_parents");
        }
        if self.self_build == 0 {
            names.push("self_build");
        }
        if self.builder_bids == 0 {
            names.push("builder_bids");
        }
        names
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "blocks: {}", self.blocks)?;
        writeln!(f, "epochs_crossed: {}", self.epochs_crossed)?;
        writeln!(f, "full_parents: {}", self.full_parents)?;
        writeln!(f, "empty_parents: {}", self.empty_parents)?;
        writeln!(f, "self_build: {}", self.self_build)?;
        writeln!(f, "builder_bids: {}", self.builder_bids)?;
        for name in self.zero_categories() {
            writeln!(f, "flag: {name}=0 for adversarial devnet [5.32]")?;
        }
        Ok(())
    }
}

/// Why a replay stopped.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The pin file cannot be read or does not hold a digest and two paths.
    #[error("replay pin: {0}")]
    Pin(String),
    /// The devnet config cannot be read, or it disagrees with the export.
    #[error("replay config: {0}")]
    Config(String),
    /// [`open_export_pinned`](crate::export_blocks::open_export_pinned) refused the export.
    #[error(transparent)]
    Open(#[from] ExportError),
    /// The decoded blocks are not the manifest's root list.
    #[error("root list: {0}")]
    RootList(String),
    /// The export's preset is not one this replay decodes.
    #[error("preset {0:?} is not minimal or mainnet")]
    Preset(String),
    /// A block or the genesis state does not decode.
    #[error("slot {slot}: {detail}")]
    Decode {
        /// The object's slot, 0 for the genesis state.
        slot: Slot,
        /// Why.
        detail: String,
    },
    /// The first block whose transition or roots disagree. The three SSZ files are in `out`.
    #[error("slot {slot}: {detail} (wrote {pre}, {block} and {post} under {})", out.display())]
    Mismatch {
        /// The block's slot.
        slot: Slot,
        /// Why it disagrees.
        detail: String,
        /// `--out`.
        out: PathBuf,
        /// [`PRE_STATE_SSZ`].
        pre: &'static str,
        /// [`BLOCK_SSZ`].
        block: &'static str,
        /// [`POST_STATE_SSZ`].
        post: &'static str,
    },
    /// Writing the mismatch files failed.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
}

impl ReplayError {
    /// The run stopped before applying or checking any block.
    pub fn before_first_block(&self) -> bool {
        matches!(
            self,
            Self::Pin(_) | Self::Config(_) | Self::Open(_) | Self::RootList(_) | Self::Preset(_)
        )
    }

    /// [`open_verified`](crate::archive::open_verified) refused a segment.
    pub fn open_verified_failed(&self) -> bool {
        matches!(self, Self::Open(ExportError::Archive(_)))
    }
}

/// The pin file: the export directory, its `export_sha256`, and the devnet config.
/// Paths are relative to the pin file unless absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// The export directory.
    pub export_dir: PathBuf,
    /// The pinned `export_sha256`.
    pub export_sha256: Sha256Digest,
    /// The parsed devnet config.
    pub config: ChainConfig,
}

#[derive(serde::Deserialize)]
struct PinFile {
    export: String,
    export_sha256: String,
    config: String,
}

/// Reads `path` (`testing/replay.manifest.toml`) and the config it names.
pub fn load_pin(path: &Path) -> Result<Pin, ReplayError> {
    let text = fs::read_to_string(path).map_err(|source| ReplayError::Io {
        path: path.to_owned(),
        source,
    })?;
    let file: PinFile =
        toml::from_str(&text).map_err(|e| ReplayError::Pin(format!("{}: {e}", path.display())))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let export_dir = resolve(base, &file.export);
    let config_path = resolve(base, &file.config);
    let export_sha256 = parse_sha(&file.export_sha256)?;
    let yaml = read_limited(&config_path, MAX_CONFIG_BYTES)?;
    let digest: [u8; 32] = Sha256::digest(&yaml).into();
    let config = ChainConfig::from_yaml(&yaml, &digest)
        .map_err(|e| ReplayError::Config(format!("{}: {e}", config_path.display())))?;
    Ok(Pin {
        export_dir,
        export_sha256,
        config,
    })
}

/// [`replay`] of the export named by `manifest`, writing a mismatch into `out`.
pub fn replay_pin(manifest: &Path, out: &Path) -> Result<Report, ReplayError> {
    let pin = load_pin(manifest)?;
    replay(&ReplayOptions {
        export_dir: &pin.export_dir,
        export_sha256: pin.export_sha256,
        config: &pin.config,
        out,
    })
}

/// Replays `opts.export_dir` from genesis. See the module docs.
pub fn replay(opts: &ReplayOptions<'_>) -> Result<Report, ReplayError> {
    let export = open_export_pinned(opts.export_dir, opts.export_sha256)?;
    if export.manifest().preset != opts.config.preset_base() {
        return Err(ReplayError::Config(format!(
            "the export preset is {}, the config preset is {}",
            export.manifest().preset,
            opts.config.preset_base()
        )));
    }
    match export.manifest().preset.as_str() {
        Minimal::NAME => replay_preset::<Minimal>(&export, opts),
        Mainnet::NAME => replay_preset::<Mainnet>(&export, opts),
        other => Err(ReplayError::Preset(other.to_owned())),
    }
}

fn replay_preset<E: Preset>(
    export: &Export,
    opts: &ReplayOptions<'_>,
) -> Result<Report, ReplayError> {
    let chain = load_chain::<E>(export)?;
    replay_chain(&chain, opts.config, opts.out)
}

/// Genesis state, blocks and the exported block roots, checked against the manifest's root list.
struct LoadedChain<E: Preset> {
    state: BeaconState<E>,
    blocks: Vec<SignedBeaconBlock<E>>,
    roots: Vec<Root>,
}

fn load_chain<E: Preset>(export: &Export) -> Result<LoadedChain<E>, ReplayError> {
    let manifest = export.manifest();
    let state_bytes = export.genesis_state_ssz()?;
    let mut state =
        BeaconState::<E>::from_ssz_bytes(&state_bytes).map_err(|e| ReplayError::Decode {
            slot: 0,
            detail: format!("genesis state: {e:?}"),
        })?;
    let state_hash = state_root(&mut state).map_err(|e| ReplayError::Decode {
        slot: 0,
        detail: format!("genesis state root: {e}"),
    })?;
    if state_hash != manifest.genesis_state_root || state.slot != 0 {
        return Err(ReplayError::RootList(format!(
            "genesis state root {state_hash} slot {} , the export says {} at slot 0",
            state.slot, manifest.genesis_state_root
        )));
    }
    let mut blocks = Vec::with_capacity(manifest.blocks.len());
    let mut roots = Vec::with_capacity(manifest.blocks.len());
    for entry in &manifest.blocks {
        let bytes = export.block_ssz(entry)?;
        let block =
            SignedBeaconBlock::<E>::from_ssz_bytes(&bytes).map_err(|e| ReplayError::Decode {
                slot: entry.slot,
                detail: format!("block: {e:?}"),
            })?;
        let root = block.message.tree_hash_root();
        if block.message.slot != entry.slot
            || root != entry.root
            || block.message.parent_root != entry.parent_root
        {
            return Err(ReplayError::RootList(format!(
                "slot {}: decoded block root {root} parent {} , the export lists {} parent {}",
                entry.slot, block.message.parent_root, entry.root, entry.parent_root
            )));
        }
        blocks.push(block);
        roots.push(root);
    }
    check_root_list(manifest, &blocks)?;
    Ok(LoadedChain {
        state,
        blocks,
        roots,
    })
}

/// The manifest's root list, one entry per slot, matches the decoded blocks and the empty slots.
fn check_root_list<E: Preset>(
    manifest: &ExportManifest,
    blocks: &[SignedBeaconBlock<E>],
) -> Result<(), ReplayError> {
    let listed = manifest.root_list();
    let mut from_blocks = vec![None; listed.len()];
    for block in blocks {
        let slot = block.message.slot;
        let index = slot
            .checked_sub(manifest.slot_start)
            .filter(|i| (*i as usize) < from_blocks.len())
            .ok_or_else(|| {
                ReplayError::RootList(format!("slot {slot} is outside the export's root list"))
            })? as usize;
        if from_blocks[index].is_some() {
            return Err(ReplayError::RootList(format!(
                "slot {slot} is listed twice"
            )));
        }
        from_blocks[index] = Some(block.message.tree_hash_root());
    }
    if from_blocks != listed {
        let at = from_blocks
            .iter()
            .zip(&listed)
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        return Err(ReplayError::RootList(format!(
            "decoded roots differ from the export at index {at}"
        )));
    }
    Ok(())
}

/// Replays `blocks` from `state` (the genesis state). Each block's exported root is its
/// `hash_tree_root`. The same transition as [`replay`], without reading an export.
pub fn replay_loaded<E: Preset>(
    state: &BeaconState<E>,
    blocks: &[SignedBeaconBlock<E>],
    config: &ChainConfig,
    out: &Path,
) -> Result<Report, ReplayError> {
    let roots = blocks
        .iter()
        .map(|block| block.message.tree_hash_root())
        .collect();
    replay_chain(
        &LoadedChain {
            state: state.clone(),
            blocks: blocks.to_vec(),
            roots,
        },
        config,
        out,
    )
}

fn replay_chain<E: Preset>(
    chain: &LoadedChain<E>,
    config: &ChainConfig,
    out: &Path,
) -> Result<Report, ReplayError> {
    let mut state = chain.state.clone();
    let mut report = Report {
        blocks: 0,
        epochs_crossed: 0,
        full_parents: 0,
        empty_parents: 0,
        self_build: 0,
        builder_bids: 0,
    };
    for (block, root) in chain.blocks.iter().zip(&chain.roots) {
        apply_block(&mut state, block, *root, config, out, &mut report)?;
    }
    Ok(report)
}

fn apply_block<E: Preset>(
    state: &mut BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    exported_root: Root,
    config: &ChainConfig,
    out: &Path,
    report: &mut Report,
) -> Result<(), ReplayError> {
    let pre = state.as_ssz_bytes();
    let slot = block.message.slot;
    if slot == state.slot {
        if slot != 0 {
            return mismatch(
                slot,
                "the block is at the state's slot and is not the genesis block",
                &pre,
                block,
                state,
                out,
            );
        }
        return check_roots(state, block, exported_root, &pre, out, report);
    }
    if slot < state.slot {
        return mismatch(
            slot,
            "the block slot is before the state slot",
            &pre,
            block,
            state,
            out,
        );
    }
    classify(state, block, report);
    let per_epoch = E::slots_per_epoch();
    report.epochs_crossed += slot / per_epoch - state.slot / per_epoch;
    if let Err(detail) = transition(state, block, config) {
        return mismatch(slot, &detail, &pre, block, state, out);
    }
    check_roots(state, block, exported_root, &pre, out, report)
}

fn check_roots<E: Preset>(
    state: &mut BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    exported_root: Root,
    pre: &[u8],
    out: &Path,
    report: &mut Report,
) -> Result<(), ReplayError> {
    let slot = block.message.slot;
    let got = match state_root(state) {
        Ok(root) => root,
        Err(e) => {
            return mismatch(
                slot,
                &format!("post-state root: {e}"),
                pre,
                block,
                state,
                out,
            )
        }
    };
    let block_root = block.message.tree_hash_root();
    if got != block.message.state_root {
        return mismatch(
            slot,
            &format!(
                "post-state root {got} != block.state_root {}",
                block.message.state_root
            ),
            pre,
            block,
            state,
            out,
        );
    }
    if block_root != exported_root {
        return mismatch(
            slot,
            &format!("block root {block_root} != exported root {exported_root}"),
            pre,
            block,
            state,
            out,
        );
    }
    report.blocks += 1;
    Ok(())
}

/// FULL when the bid extends the parent bid's block hash, EMPTY otherwise (Gloas parent payload).
fn classify<E: Preset>(state: &BeaconState<E>, block: &SignedBeaconBlock<E>, report: &mut Report) {
    let bid = &block.message.body.signed_execution_payload_bid.message;
    if bid.parent_block_hash == state.latest_execution_payload_bid.block_hash {
        report.full_parents += 1;
    } else {
        report.empty_parents += 1;
    }
    if bid.builder_index == SELF_BUILD {
        report.self_build += 1;
    } else {
        report.builder_bids += 1;
    }
}

fn transition<E: Preset>(
    state: &mut BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    config: &ChainConfig,
) -> Result<(), String> {
    let schedule = Schedule(config);
    let pre_keys = StateKeys::new(state);
    let pre = bls_context(config, &pre_keys, &schedule)?;
    let mut at_slot = state.clone();
    let keys = if process_slots(&mut at_slot, block.message.slot, &pre).is_ok() {
        StateKeys::new(&at_slot)
    } else {
        pre_keys
    };
    let bls = bls_context(config, &keys, &schedule)?;
    state_transition(state, block, true, &bls).map_err(|e| e.to_string())
}

fn mismatch<E: Preset>(
    slot: Slot,
    detail: &str,
    pre: &[u8],
    block: &SignedBeaconBlock<E>,
    post: &BeaconState<E>,
    out: &Path,
) -> Result<(), ReplayError> {
    write_mismatch(out, pre, &block.as_ssz_bytes(), &post.as_ssz_bytes())?;
    Err(ReplayError::Mismatch {
        slot,
        detail: detail.to_owned(),
        out: out.to_owned(),
        pre: PRE_STATE_SSZ,
        block: BLOCK_SSZ,
        post: POST_STATE_SSZ,
    })
}

fn write_mismatch(out: &Path, pre: &[u8], block: &[u8], post: &[u8]) -> Result<(), ReplayError> {
    fs::create_dir_all(out).map_err(|source| ReplayError::Io {
        path: out.to_owned(),
        source,
    })?;
    for (name, bytes) in [
        (PRE_STATE_SSZ, pre),
        (BLOCK_SSZ, block),
        (POST_STATE_SSZ, post),
    ] {
        let path = out.join(name);
        fs::write(&path, bytes).map_err(|source| ReplayError::Io { path, source })?;
    }
    Ok(())
}

fn resolve(base: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn parse_sha(text: &str) -> Result<Sha256Digest, ReplayError> {
    let lowercase = text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    let bytes = lowercase
        .then(|| hex::decode(text).ok())
        .flatten()
        .filter(|v| v.len() == 32);
    let Some(bytes) = bytes else {
        return Err(ReplayError::Pin(
            "export_sha256 must be 64 lowercase hex digits".into(),
        ));
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>, ReplayError> {
    let meta = fs::symlink_metadata(path).map_err(|source| ReplayError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !meta.file_type().is_file() {
        return Err(ReplayError::Config(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if meta.len() > max {
        return Err(ReplayError::Config(format!(
            "{} is {} bytes, over {max}",
            path.display(),
            meta.len()
        )));
    }
    fs::read(path).map_err(|source| ReplayError::Io {
        path: path.to_owned(),
        source,
    })
}

/// The blob limit of the devnet config.
struct Schedule<'a>(&'a ChainConfig);

impl BlobSchedule for Schedule<'_> {
    fn max_blobs_per_block(&self, epoch: Epoch) -> u64 {
        self.0.get_blob_parameters(epoch).max_blobs_per_block
    }
}

fn bls_context<'a>(
    config: &ChainConfig,
    keys: &'a StateKeys,
    schedule: &'a Schedule<'_>,
) -> Result<BlsContext<'a>, String> {
    let capella = config
        .capella_fork_version()
        .map_err(|e| format!("CAPELLA_FORK_VERSION: {e}"))?;
    Ok(BlsContext {
        backend: keys,
        aggregator: &AGGREGATOR,
        genesis_fork_version: config.genesis_fork_version(),
        capella_fork_version: capella,
        blob_schedule: schedule,
    })
}

/// `eth_aggregate_pubkeys` on `crypto-bls`.
struct Aggregator;

const AGGREGATOR: Aggregator = Aggregator;

impl PubkeyAggregator for Aggregator {
    fn aggregate_pubkeys(&self, pubkeys: &[BLSPubkey]) -> Result<BLSPubkey, AggregationError> {
        let mut keys = Vec::with_capacity(pubkeys.len());
        for raw in pubkeys {
            keys.push(
                PublicKey::from_validated_bytes(raw)
                    .map_err(|e| AggregationError(e.to_string()))?,
            );
        }
        let refs: Vec<&PublicKey> = keys.iter().collect();
        eth_aggregate_pubkeys(&refs)
            .map(|sum| sum.to_bytes())
            .map_err(|e| AggregationError(e.to_string()))
    }
}

/// Validator and builder keys of one state. Inline deposit keys are taken from the set.
struct StateKeys {
    validators: Vec<BLSPubkey>,
    builders: Vec<BLSPubkey>,
}

impl StateKeys {
    fn new<E: Preset>(state: &BeaconState<E>) -> Self {
        Self {
            validators: state.validators.iter().map(|v| v.pubkey).collect(),
            builders: state.builders.iter().map(|b| b.pubkey).collect(),
        }
    }

    fn lookup(&self, signer: &SignerRef) -> Result<BLSPubkey, BackendError> {
        let found = match signer {
            SignerRef::Validator(index) => usize::try_from(*index)
                .ok()
                .and_then(|i| self.validators.get(i))
                .copied(),
            SignerRef::Builder { index, .. } => usize::try_from(*index)
                .ok()
                .and_then(|i| self.builders.get(i))
                .copied(),
            SignerRef::Inline(key) => Some(*key),
        };
        found.ok_or_else(|| BackendError(format!("unknown signer {signer:?}")))
    }

    /// `Ok(false)` when a key or the signature does not decode. `Err` when a signer is not in
    /// the state and every available encoding decodes.
    fn verify_one(&self, set: &SignatureSet) -> Result<bool, BackendError> {
        let mut unknown = None;
        let mut keys = Vec::with_capacity(set.signers().len());
        for signer in set.signers() {
            match self.lookup(signer) {
                Ok(raw) => match PublicKey::from_validated_bytes(&raw) {
                    Ok(key) => keys.push(key),
                    Err(_) => return Ok(false),
                },
                Err(e) => {
                    unknown.get_or_insert(e);
                }
            }
        }
        let Ok(signature) = Signature::from_validated_bytes(set.signature()) else {
            return Ok(false);
        };
        if let Some(e) = unknown {
            return Err(e);
        }
        let root = set.signing_root();
        let message = root.as_slice();
        let valid = match keys.as_slice() {
            [key] => verify(key, message, &signature),
            many => {
                let refs: Vec<&PublicKey> = many.iter().collect();
                eth_fast_aggregate_verify(&refs, message, &signature)
            }
        };
        Ok(valid)
    }
}

impl SignatureBackend for StateKeys {
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError> {
        for set in sets {
            if !self.verify_one(set)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
