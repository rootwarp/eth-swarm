//! consensus-spec-tests `tests/<preset>/gloas/networking/<handler>/pyspec_tests/<case>/` of the
//! gossip topics of `crates/gossip-validation`, in the format of
//! `tests/formats/networking/gossip_validation.md` at v1.7.0-beta.4:
//!
//! - `gossip_execution_payload_envelope` (topic `execution_payload`):
//!   `validate_execution_payload_envelope_gossip`.
//! - `gossip_payload_attestation_message` (topic `payload_attestation_message`):
//!   `validate_payload_attestation_message_gossip`.
//!
//! A case holds `meta.yaml`, `state.ssz_snappy` (the anchor state), the block and message files
//! that `meta.yaml` names, an optional `config.yaml` and `manifest.yaml` (the suite checks it).
//! [`run`]:
//!
//! 1. checks the `config.yaml`, if the case has one, as the fork_choice runner does, and also
//!    `MAXIMUM_GOSSIP_CLOCK_DISPARITY`: a compared value that is missing or differs fails the
//!    case. The check reads only the values it compares, so another key, unknown or not, fails
//!    nothing. Its `GLOAS_FORK_EPOCH` is the fork epoch of the payload attestation checks.
//! 2. builds the store: `get_forkchoice_store` on the anchor state and the first entry of
//!    `blocks`, which is not state-transitioned (with no `blocks`, the anchor block of
//!    `get_store_from_state` of the pyspec helpers). Each later entry ticks the store to its
//!    slot and goes through `on_block` with the state transition of the fork_choice runner. An
//!    entry with `payload` then goes through `on_execution_payload_envelope`. An entry with
//!    `failed` or `pending` is seen with no post-state: [`GossipStore`] gives its block but no
//!    post-state of it. `finalized_checkpoint` replaces the finalized checkpoint of the store.
//! 3. validates each message in order with one `Seen`. The signature sets of a pending verdict
//!    go to the in-process BLS backend with the keys of the post-state of the block (an
//!    envelope) or of the head state (a payload attestation message), or to no check for
//!    `bls_setting: 2`, and `Seen::resolve` gives the verdict. Its category must be `expected`:
//!    `valid` is ACCEPT, `ignore` IGNORE, `reject` REJECT. The format makes `reason`
//!    informational, so the runner does not compare it.
//!
//! Each input that the runner does not give fails the case: an unknown key of `meta.yaml`, of a
//! `blocks` or `messages` entry or of `finalized_checkpoint`, `payload_status`, a non-empty
//! `seen_partial_data_column_headers`, `subnet_id`, `column_index` and `group_id`, and
//! `current_time_ms` for an envelope, whose validation takes no time. Thus a case that needs
//! more than the runner does cannot pass.
//!
//! An envelope whose payload withdrawals or execution request lists are longer than the bounds
//! of consensus-types does not decode. Decoded with the unbounded lists of the spec, it has the
//! verdict of `verify_execution_requests_limits` or of the withdrawal limit: REJECT. The format
//! lets a client check the conditions in any order, and the vectors fail only that condition.

use crate::bls_backend::{backend_for, bls_setting, Bls, StateKeys};
use crate::config::ForkEpoch;
use crate::coverage::Reads;
use crate::fixture;
use crate::fork_choice::{
    check_store_config, decode, import_block, object, root, unsigned, Transition,
    MAINNET_SLOT_DURATION_MS, MINIMAL_SLOT_DURATION_MS,
};
use crate::operations::SpecExecutionRequests;
use crate::plan::Case;
use consensus_types::gloas::{
    BeaconBlock, BeaconBlockBody, BeaconState, BlockAccessList, Checkpoint, Eth1Data,
    ExecutionRequests, PayloadAttestationMessage, SignedBeaconBlock, SignedExecutionPayloadBid,
    SignedExecutionPayloadEnvelope, SyncAggregate, Transaction, Withdrawal,
};
use consensus_types::primitives::{
    BLSSignature, BuilderIndex, Bytes32, Epoch, ExecutionAddress, Hash32, Root, U256,
};
use consensus_types::{EthSpec, Mainnet, Minimal};
use fork_choice::{get_forkchoice_store, on_execution_payload_envelope, on_tick, Store};
use gossip_validation::{
    validate_execution_payload_envelope_gossip, validate_payload_attestation_message_gossip,
    verify_execution_requests_limits, verify_withdrawals_limit, RejectReason, RequestCounts, Seen,
    StoreView, Verdict, MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS,
};
use ssz::{BitVector, Decode};
use ssz_types::typenum::U0;
use ssz_types::{FixedVector, ProgressiveVariableList, VariableList};
use state_transition::{state_root, Preset};
use std::collections::HashMap;
use std::num::NonZeroU64;
use tree_hash::TreeHash;
use yaml_rust2::Yaml;

/// The Gloas gossip handler directories that this runner runs.
pub const RUNNABLE: [&str; 2] = [
    "gossip_execution_payload_envelope",
    "gossip_payload_attestation_message",
];

/// The Gloas gossip handler directories of v1.7.0-beta.4 that this runner does not run, and
/// that `testing/skip.toml` must skip: `crates/gossip-validation` has no validation of their
/// topics.
pub const NOT_RUN: [&str; 13] = [
    "gossip_attester_slashing",
    "gossip_beacon_aggregate_and_proof",
    "gossip_beacon_attestation",
    "gossip_beacon_block",
    "gossip_bls_to_execution_change",
    "gossip_data_column_sidecar",
    "gossip_execution_payload_bid",
    "gossip_partial_data_column_sidecar",
    "gossip_proposer_preferences",
    "gossip_proposer_slashing",
    "gossip_sync_committee_contribution_and_proof",
    "gossip_sync_committee_message",
    "gossip_voluntary_exit",
];

/// Whether this runner runs a Gloas gossip handler directory. `Err` for a directory that it
/// does not know: the suite fails setup on it, so a new handler gets a decision.
pub fn handler_runs(handler: &str) -> Result<bool, String> {
    if RUNNABLE.contains(&handler) {
        Ok(true)
    } else if NOT_RUN.contains(&handler) {
        Ok(false)
    } else {
        Err(format!(
            "unknown networking handler directory `{handler}`: classify it in crates/spec-tests/src/gossip.rs"
        ))
    }
}

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    fork == "gloas" && matches!(preset, "minimal" | "mainnet") && handler_runs(handler) == Ok(true)
}

/// Runs one case. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    let handler = &case.key.handler;
    if handler_runs(handler) != Ok(true) {
        return Err(format!("no gossip runner for handler {handler}"));
    }
    match case.key.preset.as_str() {
        "minimal" => run_case::<Minimal>(reads, case, MINIMAL_SLOT_DURATION_MS),
        "mainnet" => run_case::<Mainnet>(reads, case, MAINNET_SLOT_DURATION_MS),
        other => Err(format!("no gossip runner for preset {other}")),
    }
}

fn run_case<E: Preset>(reads: &Reads, case: &Case, slot_duration_ms: u64) -> Result<(), String> {
    let setup = setup::<E>(reads, case, slot_duration_ms)?;
    let mut seen = Seen::default();
    for (i, message) in setup.messages.iter().enumerate() {
        validate(reads, case, &setup, &mut seen, message)
            .map_err(|e| format!("messages[{i}]: {e}"))?;
    }
    Ok(())
}

/// The view of the store of a case for the gossip checks: the fork-choice store of the
/// imported blocks, the blocks that are seen with no post-state, and the finalized checkpoint
/// of `meta.yaml`.
pub struct GossipStore<E: Preset> {
    /// The store of the anchor and of each imported block of `blocks`.
    pub store: Store<E>,
    /// Each block of `blocks` with `failed` or `pending`: seen, with no post-state.
    pub unimported: HashMap<Root, BeaconBlock<E>>,
    /// `finalized_checkpoint` of `meta.yaml`, in place of the finalized checkpoint of the store.
    pub finalized_override: Option<Checkpoint>,
}

impl<E: Preset> StoreView<E> for GossipStore<E> {
    fn block(&self, root: Root) -> Option<&BeaconBlock<E>> {
        StoreView::block(&self.store, root).or_else(|| self.unimported.get(&root))
    }

    fn block_state(&self, root: Root) -> Option<&BeaconState<E>> {
        StoreView::block_state(&self.store, root)
    }

    fn finalized_checkpoint(&self) -> &Checkpoint {
        self.finalized_override
            .as_ref()
            .unwrap_or_else(|| self.store.finalized_checkpoint())
    }

    fn genesis_time_ms(&self) -> u64 {
        self.store.genesis_time_ms()
    }

    fn slot_duration_ms(&self) -> NonZeroU64 {
        self.store.slot_duration_ms()
    }

    fn head_state(&self) -> Option<&BeaconState<E>> {
        StoreView::head_state(&self.store)
    }

    fn time_ms(&self) -> u64 {
        self.store.time_ms()
    }
}

/// The topic of a runnable handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Topic {
    ExecutionPayload,
    PayloadAttestationMessage,
}

impl Topic {
    fn of(handler: &str) -> Result<Self, String> {
        match handler {
            "gossip_execution_payload_envelope" => Ok(Self::ExecutionPayload),
            "gossip_payload_attestation_message" => Ok(Self::PayloadAttestationMessage),
            other => Err(format!("no gossip runner for handler {other}")),
        }
    }

    /// The `topic` of `meta.yaml`.
    fn name(self) -> &'static str {
        match self {
            Self::ExecutionPayload => "execution_payload",
            Self::PayloadAttestationMessage => "payload_attestation_message",
        }
    }
}

/// A case after its setup: the store of its `blocks` and `finalized_checkpoint`, and what its
/// messages need.
struct Setup<E: Preset> {
    store: GossipStore<E>,
    topic: Topic,
    bls: Bls,
    /// `GLOAS_FORK_EPOCH` of the `config.yaml`, else `fork.epoch` of the anchor state.
    gloas_fork_epoch: Epoch,
    messages: Vec<Yaml>,
}

/// The keys of `meta.yaml` that the runner reads. `description` and `bls_setting` are the meta
/// tags of the pyspec.
const META_KEYS: [&str; 7] = [
    "topic",
    "blocks",
    "finalized_checkpoint",
    "seen_partial_data_column_headers",
    "messages",
    "bls_setting",
    "description",
];

fn setup<E: Preset>(reads: &Reads, case: &Case, slot_duration_ms: u64) -> Result<Setup<E>, String> {
    let file = |name: &str| case.file(name).ok_or_else(|| format!("case has no {name}"));
    let meta = fixture::load(reads, file("meta.yaml")?)?;
    only(&meta, &META_KEYS).map_err(|e| format!("meta.yaml: {e}"))?;
    let bls = bls_setting(reads, case)?;
    let topic = Topic::of(&case.key.handler)?;
    let named = fixture::field(&meta, "topic")?;
    if named.as_str() != Some(topic.name()) {
        return Err(format!(
            "meta.yaml: topic {named:?} is not `{}`",
            topic.name()
        ));
    }
    match &meta["seen_partial_data_column_headers"] {
        Yaml::BadValue => {}
        headers if fixture::list(headers).is_ok_and(<[Yaml]>::is_empty) => {}
        _ => return Err("meta.yaml: seen_partial_data_column_headers is not supported".into()),
    }
    let state: BeaconState<E> = decode(reads, file("state.ssz_snappy")?)?;
    let fork_epoch = state.fork.epoch;
    let disparity = [(
        "MAXIMUM_GOSSIP_CLOCK_DISPARITY",
        MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS,
    )];
    let gloas_fork_epoch =
        match check_store_config::<E>(reads, case, fork_epoch, slot_duration_ms, &disparity)? {
            ForkEpoch::Same => fork_epoch,
            ForkEpoch::Differs(epoch) => epoch,
        };
    let slot_duration = NonZeroU64::new(slot_duration_ms).ok_or("SLOT_DURATION_MS is zero")?;
    let provider = Transition::new(&case.key.preset, bls);
    let mut store = build_store(
        reads,
        case,
        &provider,
        state,
        &meta["blocks"],
        slot_duration,
    )?;
    store.finalized_override = finalized_checkpoint::<E>(reads, case, &meta)?;
    let messages =
        fixture::list(fixture::field(&meta, "messages")?).map_err(|e| format!("messages: {e}"))?;
    if messages.is_empty() {
        return Err("meta.yaml: messages has no message".into());
    }
    Ok(Setup {
        store,
        topic,
        bls,
        gloas_fork_epoch,
        messages: messages.to_vec(),
    })
}

/// `Err` naming the first key of the mapping `map` that is not in `known`.
fn only(map: &Yaml, known: &[&str]) -> Result<(), String> {
    let map = map
        .as_hash()
        .ok_or_else(|| format!("expected a mapping, got {map:?}"))?;
    match map
        .keys()
        .find(|k| !k.as_str().is_some_and(|k| known.contains(&k)))
    {
        Some(k) => Err(format!("unsupported key `{}`", k.as_str().unwrap_or("?"))),
        None => Ok(()),
    }
}

/// The store of `blocks` on the anchor `state` (see the module docs).
fn build_store<E: Preset>(
    reads: &Reads,
    case: &Case,
    provider: &Transition<'_>,
    state: BeaconState<E>,
    blocks: &Yaml,
    slot_duration: NonZeroU64,
) -> Result<GossipStore<E>, String> {
    let entries = match blocks {
        Yaml::BadValue => &[][..],
        blocks => fixture::list(blocks).map_err(|e| format!("blocks: {e}"))?,
    };
    let entries = entries
        .iter()
        .enumerate()
        .map(|(i, entry)| BlockEntry::of(entry).map_err(|e| format!("blocks[{i}]: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let anchor = match entries.first() {
        Some(entry) if entry.unimported => {
            return Err("blocks[0]: the anchor block cannot be failed or pending".into())
        }
        Some(entry) => object::<SignedBeaconBlock<E>>(reads, case, entry.block)?.message,
        None => anchor_block(&state)?,
    };
    let store = get_forkchoice_store(state, anchor, slot_duration)
        .map_err(|e| format!("get_forkchoice_store: {e}"))?;
    let mut gossip = GossipStore {
        store,
        unimported: HashMap::new(),
        finalized_override: None,
    };
    for (i, entry) in entries.iter().enumerate() {
        add_block(reads, case, &mut gossip, provider, entry, i > 0)
            .map_err(|e| format!("blocks[{i}]: {e}"))?;
    }
    Ok(gossip)
}

/// One entry of `blocks`.
struct BlockEntry<'y> {
    /// The name of the block file.
    block: &'y Yaml,
    /// `failed` or `pending`: the block is seen, and not imported.
    unimported: bool,
    /// The name of the envelope file of the block.
    payload: Option<&'y Yaml>,
}

impl<'y> BlockEntry<'y> {
    fn of(entry: &'y Yaml) -> Result<Self, String> {
        only(
            entry,
            &["block", "failed", "pending", "payload", "payload_status"],
        )?;
        if !entry["payload_status"].is_badvalue() {
            return Err("payload_status is not supported: the runner has no payload status".into());
        }
        let flag = |key: &str| match &entry[key] {
            Yaml::BadValue => Ok(false),
            value => fixture::boolean(value).map_err(|e| format!("{key}: {e}")),
        };
        let (failed, pending) = (flag("failed")?, flag("pending")?);
        let payload = Some(&entry["payload"]).filter(|p| !p.is_badvalue());
        if (failed || pending) && payload.is_some() {
            return Err("a failed or pending block cannot have a payload".into());
        }
        Ok(Self {
            block: fixture::field(entry, "block")?,
            unimported: failed || pending,
            payload,
        })
    }
}

/// Adds the block of `entry` to `store`: as seen with no post-state if it is failed or
/// pending, else through `on_tick` and `on_block` if `import` (each entry but the anchor).
/// Then its payload, if it has one.
fn add_block<E: Preset>(
    reads: &Reads,
    case: &Case,
    store: &mut GossipStore<E>,
    provider: &Transition<'_>,
    entry: &BlockEntry<'_>,
    import: bool,
) -> Result<(), String> {
    let signed: SignedBeaconBlock<E> = object(reads, case, entry.block)?;
    let root = signed.message.tree_hash_root();
    if entry.unimported {
        store.unimported.insert(root, signed.message);
        return Ok(());
    }
    let fc = &mut store.store;
    if import {
        let slot_time = signed
            .message
            .slot
            .checked_mul(fc.slot_duration_ms().get())
            .and_then(|ms| ms.checked_add(fc.genesis_time_ms()))
            .ok_or("the time of the block slot overflows")?;
        if fc.time_ms() < slot_time {
            on_tick(fc, slot_time).map_err(|e| format!("on_tick: {e}"))?;
        }
        let name = entry.block.as_str().unwrap_or_default();
        import_block(fc, provider, &signed, name, true)?;
    }
    if let Some(payload) = entry.payload {
        let envelope: SignedExecutionPayloadEnvelope<E> = object(reads, case, payload)?;
        if envelope.message.beacon_block_root != root {
            return Err(format!(
                "the payload is for another block than {root}: {}",
                envelope.message.beacon_block_root
            ));
        }
        on_execution_payload_envelope(fc, provider, &envelope)
            .map_err(|e| format!("on_execution_payload_envelope refused the payload: {e}"))?;
    }
    Ok(())
}

/// The anchor block of `get_store_from_state` of the pyspec helpers: a default block with the
/// slot and the root of `state`, and its committed bid.
fn anchor_block<E: Preset>(state: &BeaconState<E>) -> Result<BeaconBlock<E>, String> {
    let body = BeaconBlockBody {
        randao_reveal: [0; 96],
        eth1_data: Eth1Data {
            deposit_root: Root::ZERO,
            deposit_count: 0,
            block_hash: Root::ZERO,
        },
        graffiti: Bytes32::ZERO,
        proposer_slashings: Default::default(),
        attester_slashings: Default::default(),
        attestations: Default::default(),
        deposits: Default::default(),
        voluntary_exits: Default::default(),
        sync_aggregate: SyncAggregate {
            sync_committee_bits: BitVector::new(),
            sync_committee_signature: [0; 96],
        },
        bls_to_execution_changes: Default::default(),
        signed_execution_payload_bid: SignedExecutionPayloadBid {
            message: state.latest_execution_payload_bid.clone(),
            signature: [0; 96],
        },
        payload_attestations: Default::default(),
        parent_execution_requests: ExecutionRequests {
            deposits: Default::default(),
            withdrawals: Default::default(),
            consolidations: Default::default(),
            builder_deposits: Default::default(),
            builder_exits: Default::default(),
        },
    };
    let mut state = state.clone();
    Ok(BeaconBlock {
        slot: state.slot,
        proposer_index: 0,
        parent_root: Root::ZERO,
        state_root: state_root(&mut state).map_err(|e| format!("anchor state root: {e}"))?,
        body,
    })
}

/// `finalized_checkpoint` of `meta`, if it has one: `epoch` and either `root` or the root of
/// the block of the file `block`.
fn finalized_checkpoint<E: Preset>(
    reads: &Reads,
    case: &Case,
    meta: &Yaml,
) -> Result<Option<Checkpoint>, String> {
    let checkpoint = &meta["finalized_checkpoint"];
    if checkpoint.is_badvalue() {
        return Ok(None);
    }
    let parse = || {
        only(checkpoint, &["epoch", "root", "block"])?;
        let epoch = fixture::field(checkpoint, "epoch")?;
        let epoch = unsigned(epoch).ok_or_else(|| format!("epoch {epoch:?} is not an epoch"))?;
        let root = match (&checkpoint["root"], &checkpoint["block"]) {
            (value, Yaml::BadValue) if !value.is_badvalue() => {
                root(value).ok_or_else(|| format!("root {value:?} is not a root"))?
            }
            (Yaml::BadValue, block) if !block.is_badvalue() => {
                let block: SignedBeaconBlock<E> = object(reads, case, block)?;
                block.message.tree_hash_root()
            }
            _ => return Err("needs exactly one of root or block".into()),
        };
        Ok(Checkpoint { epoch, root })
    };
    parse()
        .map(Some)
        .map_err(|e: String| format!("finalized_checkpoint: {e}"))
}

/// The keys of a message of `messages` that the runner reads.
const MESSAGE_KEYS: [&str; 4] = ["current_time_ms", "message", "expected", "reason"];

/// Validates one message of `messages`, and compares the verdict with `expected`.
fn validate<E: Preset>(
    reads: &Reads,
    case: &Case,
    setup: &Setup<E>,
    seen: &mut Seen,
    entry: &Yaml,
) -> Result<(), String> {
    for key in ["subnet_id", "column_index", "group_id"] {
        if !entry[key].is_badvalue() {
            return Err(format!(
                "`{key}` is not supported: no runnable topic takes it"
            ));
        }
    }
    only(entry, &MESSAGE_KEYS)?;
    let want = match fixture::field(entry, "expected")?.as_str() {
        Some(want @ ("valid" | "ignore" | "reject")) => want,
        other => return Err(format!("expected: unknown result {other:?}")),
    };
    let time = match &entry["current_time_ms"] {
        Yaml::BadValue => None,
        value => Some(unsigned(value).ok_or_else(|| format!("current_time_ms {value:?}"))?),
    };
    let name = fixture::field(entry, "message")?;
    let store = &setup.store;
    let verdict = match (setup.topic, time) {
        (Topic::ExecutionPayload, None) => envelope_verdict(reads, case, setup, seen, name)?,
        (Topic::PayloadAttestationMessage, Some(time)) => {
            let message: PayloadAttestationMessage = object(reads, case, name)?;
            let epoch = setup.gloas_fork_epoch;
            match validate_payload_attestation_message_gossip(seen, store, &message, time, epoch) {
                Verdict::Pending { bls_sets, seen_key } => {
                    let state = store.head_state().ok_or("the store has no head state")?;
                    let keys = StateKeys::new(state);
                    let signatures = backend_for(setup.bls, &keys).verify_signature_sets(&bls_sets);
                    seen.resolve(seen_key, signatures)
                }
                verdict => verdict,
            }
        }
        (Topic::ExecutionPayload, Some(_)) => {
            return Err("current_time_ms: the execution_payload topic takes no time".into())
        }
        (Topic::PayloadAttestationMessage, None) => return Err("missing `current_time_ms`".into()),
    };
    let got = match verdict {
        Verdict::Accept => "valid",
        Verdict::Ignore(_) => "ignore",
        Verdict::Reject(_) => "reject",
        Verdict::Pending { .. } => "pending",
    };
    if got == want {
        Ok(())
    } else {
        Err(format!("got {verdict:?}, but the vector expects {want}"))
    }
}

/// The verdict of the envelope of the file `name`, after `Seen::resolve` for a pending verdict.
fn envelope_verdict<E: Preset>(
    reads: &Reads,
    case: &Case,
    setup: &Setup<E>,
    seen: &mut Seen,
    name: &Yaml,
) -> Result<Verdict, String> {
    let file = format!(
        "{}.ssz_snappy",
        name.as_str().ok_or("expected a file name")?
    );
    let path = case
        .file(&file)
        .ok_or_else(|| format!("case has no {file}"))?;
    let bytes = fixture::ssz_snappy(reads, path)?;
    let signed = match SignedExecutionPayloadEnvelope::<E>::from_ssz_bytes(&bytes) {
        Ok(signed) => signed,
        Err(e) => {
            return past_limits::<E>(&bytes)
                .map(Verdict::Reject)
                .ok_or_else(|| format!("{}: {e:?}", path.display()))
        }
    };
    let store = &setup.store;
    Ok(
        match validate_execution_payload_envelope_gossip(seen, store, &signed) {
            Verdict::Pending { bls_sets, seen_key } => {
                let state = store
                    .block_state(signed.message.beacon_block_root)
                    .ok_or("the block of a pending envelope has no post-state")?;
                let keys = StateKeys::new(state);
                let signatures = backend_for(setup.bls, &keys).verify_signature_sets(&bls_sets);
                seen.resolve(seen_key, signatures)
            }
            verdict => verdict,
        },
    )
}

/// The REJECT of the envelope `bytes` that the bounded types of consensus-types do not decode:
/// decoded with the unbounded lists of the spec, a request list or the withdrawals of the
/// payload past its limit. `None` if the bytes do not decode so either, or if no limit fails.
fn past_limits<E: Preset>(bytes: &[u8]) -> Option<RejectReason> {
    let spec = SpecSignedEnvelope::<E>::from_ssz_bytes(bytes).ok()?;
    let requests = &spec.message.execution_requests;
    let counts = RequestCounts {
        withdrawals: requests.withdrawals.len(),
        consolidations: requests.consolidations.len(),
        builder_deposits: requests.builder_deposits.len(),
        builder_exits: requests.builder_exits.len(),
    };
    verify_execution_requests_limits::<E>(&counts)
        .and_then(|()| verify_withdrawals_limit::<E>(spec.message.payload.withdrawals.len()))
        .err()
}

/// `SignedExecutionPayloadEnvelope` with the unbounded lists of the spec: [`SpecPayload`] and
/// the `ExecutionRequests` of [`SpecExecutionRequests`]. Its SSZ encoding is the encoding of
/// the bounded type of consensus-types.
#[derive(ssz_derive::Decode)]
#[cfg_attr(test, derive(ssz_derive::Encode))]
struct SpecSignedEnvelope<E: EthSpec> {
    message: SpecEnvelope<E>,
    _signature: BLSSignature,
}

/// `ExecutionPayloadEnvelope` (`gloas/beacon-chain.md`) with [`SpecPayload`] and
/// [`SpecExecutionRequests`].
#[derive(ssz_derive::Decode)]
#[cfg_attr(test, derive(ssz_derive::Encode))]
struct SpecEnvelope<E: EthSpec> {
    payload: SpecPayload<E>,
    execution_requests: SpecExecutionRequests,
    _builder_index: BuilderIndex,
    _beacon_block_root: Root,
    _parent_beacon_block_root: Root,
}

/// The Gloas `ExecutionPayload` with no bound on `withdrawals`: the spec's
/// `ProgressiveList[Withdrawal]`.
#[derive(ssz_derive::Decode)]
#[cfg_attr(test, derive(ssz_derive::Encode))]
struct SpecPayload<E: EthSpec> {
    _parent_hash: Hash32,
    _fee_recipient: ExecutionAddress,
    _state_root: Bytes32,
    _receipts_root: Bytes32,
    _logs_bloom: FixedVector<u8, E::BytesPerLogsBloom>,
    _prev_randao: Bytes32,
    _block_number: u64,
    _gas_limit: u64,
    _gas_used: u64,
    _timestamp: u64,
    _extra_data: VariableList<u8, E::MaxExtraDataBytes>,
    _base_fee_per_gas: U256,
    _block_hash: Hash32,
    _transactions: ProgressiveVariableList<Transaction, U0>,
    withdrawals: ProgressiveVariableList<Withdrawal, U0>,
    _blob_gas_used: u64,
    _excess_blob_gas: u64,
    _block_access_list: BlockAccessList,
    _slot_number: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls_backend::tests::{secret, PUBKEY_1};
    use crate::config::tests::config_yaml;
    use crate::fork_choice::MINIMAL_SLOT_DURATION_MS;
    use crate::plan::{CaseFile, CaseKey};
    use consensus_types::gloas::{
        ExecutionPayload, ExecutionPayloadEnvelope, PayloadAttestationData, WithdrawalRequest,
    };
    use consensus_types::primitives::{BLSPubkey, Slot, ValidatorIndex};
    use consensus_types::signing::{
        compute_signing_root, BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_PROPOSER,
        DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO,
    };
    use fork_choice::{execution_payload_envelope_signature_set, is_payload_verified};
    use gossip_validation::RequestKind;
    use ssz::Encode;
    use ssz_types::typenum::Unsigned;
    use state_transition::accessors::get_domain;
    use state_transition::caches::get_ptc;
    use state_transition::per_slot::process_slots;
    use state_transition::testing::{
        bid_for_state, block_at_state_slot, bls_context, empty_requests, genesis_state, no_bls,
        signed_block, ContractBackend,
    };
    use state_transition::{state_root, state_transition};
    use std::sync::OnceLock;
    use tempfile::TempDir;
    use tree_hash::TreeHash;

    type E = Minimal;

    const GENESIS_TIME: u64 = 1_606_824_000;
    const ENVELOPE: &str = "gossip_execution_payload_envelope";
    const PTC: &str = "gossip_payload_attestation_message";

    /// The signature of `root` with the secret key 1, the key of each validator of the tests.
    fn sign(root: Root) -> BLSSignature {
        crypto_bls::sign(&secret(1), root.as_slice())
            .unwrap()
            .to_bytes()
    }

    /// The time of the start of `slot`, in milliseconds.
    fn time_at(slot: Slot) -> u64 {
        GENESIS_TIME * 1000 + slot * MINIMAL_SLOT_DURATION_MS
    }

    /// The anchor of the cases, a block of slot 1 on it and its post-state.
    struct World {
        state: BeaconState<E>,
        anchor: SignedBeaconBlock<E>,
        block: SignedBeaconBlock<E>,
        post: BeaconState<E>,
    }

    /// A genesis anchor as the pyspec writes it, whose 64 validators and sync committees all
    /// have the key of the secret key 1, and a block of slot 1 with valid signatures whose bid commits to no
    /// execution requests. The latest block hash of the state is not the block hash of the
    /// anchor bid, so the block builds on an EMPTY parent.
    fn world() -> &'static World {
        static WORLD: OnceLock<World> = OnceLock::new();
        WORLD.get_or_init(|| {
            let mut state = genesis_state::<E>(&[32_000_000_000; 64]);
            state.genesis_time = GENESIS_TIME;
            state.latest_block_hash = Root::repeat_byte(0x01);
            let pubkey: BLSPubkey = hex::decode(PUBKEY_1).unwrap().try_into().unwrap();
            for i in 0..64 {
                state.validators.get_mut(i).unwrap().pubkey = pubkey;
            }
            // The sync committees name their members by key.
            for committee in [
                &mut state.current_sync_committee,
                &mut state.next_sync_committee,
            ] {
                committee.pubkeys = FixedVector::from_elem(pubkey);
            }
            state.apply_updates().unwrap();
            let mut anchor = signed_block::<E>(0, 0);
            anchor.message.body.signed_execution_payload_bid.message =
                state.latest_execution_payload_bid.clone();
            state.latest_block_header.body_root = anchor.message.body.tree_hash_root();
            anchor.message.state_root = state_root(&mut state).unwrap();
            let (block, post) = block_on(&state, 1);
            World {
                state,
                anchor,
                block,
                post,
            }
        })
    }

    /// A block of `slot` on the block of `state` with a valid RANDAO reveal and proposer
    /// signature, a self-build bid on the EMPTY parent that commits to no requests, and the
    /// root of its post-state. Gives the block and its post-state.
    fn block_on(state: &BeaconState<E>, slot: Slot) -> (SignedBeaconBlock<E>, BeaconState<E>) {
        let mut at_slot = state.clone();
        process_slots(&mut at_slot, slot, &no_bls()).unwrap();
        let mut block = block_at_state_slot(&at_slot);
        let mut bid = bid_for_state(&at_slot, BUILDER_INDEX_SELF_BUILD, 0);
        bid.message.execution_requests_root = empty_requests::<E>().tree_hash_root();
        block.message.body.signed_execution_payload_bid = bid;
        let epoch = E::epoch_at_slot(slot);
        let randao = get_domain(&at_slot, DOMAIN_RANDAO, Some(epoch));
        block.message.body.randao_reveal = sign(compute_signing_root(&epoch, randao));
        let mut post = state.clone();
        let backend = ContractBackend::new([]);
        state_transition(&mut post, &block, false, &bls_context(&backend)).unwrap();
        block.message.state_root = state_root(&mut post).unwrap();
        let proposer = get_domain(&at_slot, DOMAIN_BEACON_PROPOSER, Some(epoch));
        block.signature = sign(compute_signing_root(&block.message, proposer));
        (block, post)
    }

    /// The envelope of the block of slot 1 that `on_execution_payload_envelope` accepts, with
    /// `requests` and a valid signature of the proposer (a self-build envelope).
    fn envelope_with(requests: ExecutionRequests<E>) -> SignedExecutionPayloadEnvelope<E> {
        let w = world();
        let bid = &w.block.message.body.signed_execution_payload_bid.message;
        let withdrawals: Vec<_> = w
            .post
            .payload_expected_withdrawals
            .iter()
            .cloned()
            .collect();
        let unsigned = SignedExecutionPayloadEnvelope {
            message: ExecutionPayloadEnvelope {
                payload: ExecutionPayload {
                    parent_hash: w.post.latest_block_hash,
                    fee_recipient: bid.fee_recipient,
                    state_root: Root::repeat_byte(0x02),
                    receipts_root: Root::repeat_byte(0x03),
                    logs_bloom: Default::default(),
                    prev_randao: bid.prev_randao,
                    block_number: 1,
                    gas_limit: bid.gas_limit,
                    gas_used: 0,
                    timestamp: time_at(1) / 1000,
                    extra_data: Default::default(),
                    base_fee_per_gas: U256::from(7),
                    block_hash: bid.block_hash,
                    transactions: Default::default(),
                    withdrawals: withdrawals.try_into().unwrap(),
                    blob_gas_used: 0,
                    excess_blob_gas: 0,
                    block_access_list: Default::default(),
                    slot_number: 1,
                },
                execution_requests: requests,
                builder_index: bid.builder_index,
                beacon_block_root: w.block.message.tree_hash_root(),
                parent_beacon_block_root: w.block.message.parent_root,
            },
            signature: [0; 96],
        };
        resign(unsigned)
    }

    fn envelope() -> SignedExecutionPayloadEnvelope<E> {
        envelope_with(empty_requests())
    }

    /// `signed` with the valid signature of its message.
    fn resign(mut signed: SignedExecutionPayloadEnvelope<E>) -> SignedExecutionPayloadEnvelope<E> {
        let set = execution_payload_envelope_signature_set(&world().post, &signed).unwrap();
        signed.signature = sign(set.signing_root());
        signed
    }

    /// A payload attestation message of `slot` for `root` from `validator`, signed with the
    /// PTC domain of the post-state of slot 1 if `signed`, else with the zero signature.
    fn ptc_message(
        slot: Slot,
        root: Root,
        validator: ValidatorIndex,
        signed: bool,
    ) -> PayloadAttestationMessage {
        let data = PayloadAttestationData {
            beacon_block_root: root,
            slot,
            payload_present: true,
            blob_data_available: true,
        };
        let domain = get_domain(
            &world().post,
            DOMAIN_PTC_ATTESTER,
            Some(E::epoch_at_slot(slot)),
        );
        let signature = if signed {
            sign(compute_signing_root(&data, domain))
        } else {
            [0; 96]
        };
        PayloadAttestationMessage {
            validator_index: validator,
            data,
            signature,
        }
    }

    /// Two members of the PTC of `slot` on the post-state of slot 1, and a validator outside it.
    fn ptc_of(slot: Slot) -> ([ValidatorIndex; 2], ValidatorIndex) {
        let ptc = get_ptc(&world().post, slot).unwrap();
        let first = ptc[0];
        let second = *ptc.iter().find(|&&v| v != first).unwrap();
        let outsider = (0..64).find(|v| !ptc.contains(v)).unwrap();
        ([first, second], outsider)
    }

    fn block_root() -> Root {
        world().block.message.tree_hash_root()
    }

    fn snappy(bytes: &[u8]) -> Vec<u8> {
        snap::raw::Encoder::new().compress_vec(bytes).unwrap()
    }

    /// One case in its own directory: the anchor state and the files of the anchor block and
    /// the block of slot 1. The directory lives as long as the case.
    struct CaseDir {
        dir: TempDir,
        files: Vec<CaseFile>,
    }

    impl CaseDir {
        fn new() -> Self {
            let w = world();
            let mut case = Self {
                dir: tempfile::tempdir().unwrap(),
                files: Vec::new(),
            };
            case.put("state.ssz_snappy", &snappy(&w.state.as_ssz_bytes()));
            case.object("block", &w.anchor);
            case.object("block", &w.block);
            case
        }

        fn put(&mut self, name: &str, bytes: &[u8]) {
            let path = self.dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            self.files.retain(|f| f.name != name);
            self.files.push(CaseFile {
                path,
                name: name.into(),
            });
        }

        /// Puts `value` as `<prefix>_0x<root>.ssz_snappy`, and gives the name without
        /// `.ssz_snappy`, as `meta.yaml` names it.
        fn object<T: Encode + TreeHash>(&mut self, prefix: &str, value: &T) -> String {
            self.bytes(prefix, value.tree_hash_root(), &value.as_ssz_bytes())
        }

        /// Puts `bytes` as `<prefix>_0x<root>.ssz_snappy`, and gives its name.
        fn bytes(&mut self, prefix: &str, root: Root, bytes: &[u8]) -> String {
            let name = format!("{prefix}_0x{}", hex::encode(root));
            self.put(&format!("{name}.ssz_snappy"), &snappy(bytes));
            name
        }

        /// A `config.yaml` of the minimal config with `GLOAS_FORK_EPOCH: gloas` and each
        /// value of `replace`.
        fn config(&mut self, gloas: &str, replace: &[(&str, &str)]) {
            let mut text = config_yaml::<E>("minimal", &[("GLOAS_FORK_EPOCH", Some(gloas))]);
            let disparity = MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS.to_string();
            let mut extra: Vec<(String, String)> = fork_choice::config_values()
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();
            extra.push(("SLOT_DURATION_MS".into(), "6000".into()));
            extra.push(("MAXIMUM_GOSSIP_CLOCK_DISPARITY".into(), disparity));
            for (name, value) in extra {
                let value = replace
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map_or(value, |(_, v)| (*v).to_owned());
                text += &format!("{name}: {value}\n");
            }
            self.put("config.yaml", text.as_bytes());
        }

        fn case(&self, preset: &str, handler: &str) -> Case {
            Case {
                key: CaseKey {
                    source: "consensus-specs".into(),
                    fork: "gloas".into(),
                    preset: preset.into(),
                    runner: "networking".into(),
                    handler: handler.into(),
                    case: "pyspec_tests/case_0".into(),
                },
                files: self.files.clone(),
            }
        }

        /// Writes `meta` and runs the case as `handler` of the minimal preset.
        fn run(&mut self, handler: &str, meta: &str) -> Result<(), String> {
            self.put("meta.yaml", meta.as_bytes());
            run(&Reads::default(), &self.case("minimal", handler))
        }
    }

    fn name_of(block: &SignedBeaconBlock<E>) -> String {
        format!("block_0x{}", hex::encode(block.tree_hash_root()))
    }

    /// `blocks` with the anchor and the block of slot 1, whose entry gets `extra`.
    fn blocks(extra: &str) -> String {
        let w = world();
        format!(
            "blocks:\n- {{block: {}}}\n- {{block: {}{extra}}}\n",
            name_of(&w.anchor),
            name_of(&w.block)
        )
    }

    /// The `meta.yaml` of an envelope case with `head` (the topic and `blocks`) and the
    /// messages `(name, expected)`.
    fn envelope_meta(head: &str, messages: &[(&str, &str)]) -> String {
        let mut meta = format!("topic: execution_payload\n{head}messages:\n");
        for (name, expected) in messages {
            meta += &format!("- {{message: {name}, expected: {expected}}}\n");
        }
        meta
    }

    /// The `meta.yaml` of a payload attestation case with `head` and the messages
    /// `(name, expected, current_time_ms)`.
    fn ptc_meta(head: &str, messages: &[(&str, &str, u64)]) -> String {
        let mut meta = format!("topic: payload_attestation_message\n{head}messages:\n");
        for (name, expected, time) in messages {
            meta +=
                &format!("- {{current_time_ms: {time}, message: {name}, expected: {expected}}}\n");
        }
        meta
    }

    #[test]
    fn handler_selection_classifies_each_gloas_gossip_handler() {
        for handler in RUNNABLE {
            assert_eq!(handler_runs(handler), Ok(true), "{handler}");
            assert!(supported("gloas", "minimal", handler), "{handler}");
            assert!(supported("gloas", "mainnet", handler), "{handler}");
            assert!(!supported("fulu", "minimal", handler), "{handler}");
            assert!(!supported("gloas", "general", handler), "{handler}");
        }
        for handler in NOT_RUN {
            assert_eq!(handler_runs(handler), Ok(false), "{handler}");
            assert!(!supported("gloas", "minimal", handler), "{handler}");
        }
        let err = handler_runs("gossip_new_topic").unwrap_err();
        assert!(
            err.contains("gossip_new_topic") && err.contains("gossip.rs"),
            "{err}"
        );
        let err = run(
            &Reads::default(),
            &CaseDir::new().case("minimal", "gossip_beacon_block"),
        )
        .unwrap_err();
        assert!(err.contains("gossip_beacon_block"), "{err}");
        let err = run(&Reads::default(), &CaseDir::new().case("general", ENVELOPE)).unwrap_err();
        assert!(err.contains("general"), "{err}");
    }

    #[test]
    fn a_valid_envelope_accepts_and_its_copy_ignores() {
        let mut case = CaseDir::new();
        let name = case.object("execution_payload_envelope", &envelope());
        let meta = envelope_meta(&blocks(""), &[(&name, "valid"), (&name, "ignore")]);
        case.put("meta.yaml", meta.as_bytes());
        let reads = Reads::default();
        assert_eq!(run(&reads, &case.case("minimal", ENVELOPE)), Ok(()));
        // Each file of the case is read, for the coverage guard.
        for file in &case.files {
            assert!(reads.contains(&file.path), "{}", file.name);
        }
        // The first copy is valid, so the second is not.
        let meta = envelope_meta(&blocks(""), &[(&name, "valid"), (&name, "valid")]);
        let err = case.run(ENVELOPE, &meta).unwrap_err();
        assert!(
            err.contains("messages[1]") && err.contains("Ignore"),
            "{err}"
        );
    }

    #[test]
    fn a_verdict_must_be_in_the_category_that_the_vector_expects() {
        let mut case = CaseDir::new();
        let name = case.object("execution_payload_envelope", &envelope());
        for expected in ["reject", "ignore"] {
            let err = case
                .run(ENVELOPE, &envelope_meta(&blocks(""), &[(&name, expected)]))
                .unwrap_err();
            assert!(err.contains(expected) && err.contains("Accept"), "{err}");
        }
        let err = case
            .run(ENVELOPE, &envelope_meta(&blocks(""), &[(&name, "accept")]))
            .unwrap_err();
        assert!(err.contains("expected"), "{err}");
    }

    #[test]
    fn an_envelope_of_an_unseen_block_ignores() {
        let mut unseen = envelope();
        unseen.message.beacon_block_root = Root::repeat_byte(0xab);
        let mut case = CaseDir::new();
        let name = case.object("execution_payload_envelope", &unseen);
        let meta = envelope_meta(&blocks(""), &[(&name, "ignore")]);
        assert_eq!(case.run(ENVELOPE, &meta), Ok(()));
    }

    #[test]
    fn a_message_of_a_failed_or_pending_block_rejects() {
        let ([member, _], _) = ptc_of(1);
        let message = ptc_message(1, block_root(), member, true);
        for flag in [", failed: true", ", pending: true"] {
            let mut case = CaseDir::new();
            let name = case.object("execution_payload_envelope", &envelope());
            let meta = envelope_meta(&blocks(flag), &[(&name, "reject")]);
            assert_eq!(case.run(ENVELOPE, &meta), Ok(()), "{flag}");
            // The vector cannot expect such an envelope to be valid.
            let meta = envelope_meta(&blocks(flag), &[(&name, "valid")]);
            assert!(case.run(ENVELOPE, &meta).is_err(), "{flag}");

            case.config("0", &[]);
            let name = case.object("payload_attestation_message", &message);
            let meta = ptc_meta(&blocks(flag), &[(&name, "reject", time_at(1) + 100)]);
            assert_eq!(case.run(PTC, &meta), Ok(()), "{flag}");
        }
    }

    #[test]
    fn the_finalized_checkpoint_of_meta_replaces_the_one_of_the_store() {
        let w = world();
        let mut case = CaseDir::new();
        let name = case.object("execution_payload_envelope", &envelope());
        let root = format!("'0x{}'", hex::encode(block_root()));
        // Epoch 2 starts after slot 1: the envelope is before the finalized slot.
        for checkpoint in [
            format!("{{epoch: 2, root: {root}}}"),
            format!("{{epoch: 2, block: {}}}", name_of(&w.block)),
        ] {
            let head = format!("{}finalized_checkpoint: {checkpoint}\n", blocks(""));
            assert_eq!(
                case.run(ENVELOPE, &envelope_meta(&head, &[(&name, "ignore")])),
                Ok(()),
                "{checkpoint}"
            );
        }
        // Epoch 0 keeps the envelope valid.
        let head = format!(
            "{}finalized_checkpoint: {{epoch: 0, root: {root}}}\n",
            blocks("")
        );
        assert_eq!(
            case.run(ENVELOPE, &envelope_meta(&head, &[(&name, "valid")])),
            Ok(())
        );
        // The store view gives the checkpoint of `meta.yaml`.
        let reads = Reads::default();
        let setup = setup::<E>(&reads, &case.case("minimal", ENVELOPE), 6000).unwrap();
        assert_eq!(
            StoreView::finalized_checkpoint(&setup.store),
            &Checkpoint {
                epoch: 0,
                root: block_root()
            }
        );
        for (checkpoint, needle) in [
            ("{epoch: 2}".to_owned(), "root or block"),
            (
                format!("{{epoch: 2, root: {root}, block: {}}}", name_of(&w.block)),
                "root or block",
            ),
            (format!("{{epoch: x, root: {root}}}"), "epoch"),
            ("{epoch: 2, root: '0x12'}".to_owned(), "root"),
            (format!("{{epoch: 2, root: {root}, slot: 3}}"), "slot"),
            (
                "{epoch: 2, block: block_missing}".to_owned(),
                "block_missing",
            ),
        ] {
            let head = format!("{}finalized_checkpoint: {checkpoint}\n", blocks(""));
            let err = case
                .run(ENVELOPE, &envelope_meta(&head, &[(&name, "ignore")]))
                .unwrap_err();
            assert!(err.contains(needle), "{checkpoint}: {err}");
        }
    }

    #[test]
    fn envelopes_that_do_not_match_the_block_reject_before_the_signature() {
        let base = envelope();
        let mut slot = base.clone();
        slot.message.payload.slot_number = 2;
        let mut builder = base.clone();
        builder.message.builder_index = BUILDER_INDEX_SELF_BUILD - 1;
        let mut hash = base.clone();
        hash.message.payload.block_hash = Root::repeat_byte(0xcd);
        let mut requests = empty_requests::<E>();
        requests.withdrawals = vec![WithdrawalRequest {
            source_address: Default::default(),
            validator_pubkey: [0; 48],
            amount: 0,
        }]
        .try_into()
        .unwrap();
        let requests = envelope_with(requests);
        let mut case = CaseDir::new();
        let names: Vec<String> = [slot, builder, hash, requests]
            .iter()
            .map(|e| case.object("execution_payload_envelope", e))
            .collect();
        let messages: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "reject")).collect();
        assert_eq!(
            case.run(ENVELOPE, &envelope_meta(&blocks(""), &messages)),
            Ok(())
        );
    }

    /// The bytes of `signed` with `requests` withdrawal requests and `withdrawals` payload
    /// withdrawals, which the bounded types of consensus-types may not decode.
    fn oversized(
        signed: &SignedExecutionPayloadEnvelope<E>,
        requests: usize,
        withdrawals: usize,
    ) -> Vec<u8> {
        let mut spec = SpecSignedEnvelope::<E>::from_ssz_bytes(&signed.as_ssz_bytes()).unwrap();
        let request = WithdrawalRequest {
            source_address: Default::default(),
            validator_pubkey: [0; 48],
            amount: 0,
        };
        spec.message.execution_requests.withdrawals = vec![request; requests].try_into().unwrap();
        let withdrawal = Withdrawal {
            index: 0,
            validator_index: 0,
            address: Default::default(),
            amount: 0,
        };
        spec.message.payload.withdrawals = vec![withdrawal; withdrawals].try_into().unwrap();
        spec.as_ssz_bytes()
    }

    #[test]
    fn oversized_requests_and_withdrawals_reject_on_the_spec_limits() {
        let max_requests = <E as EthSpec>::MaxWithdrawalRequestsPerPayload::to_usize();
        let max_withdrawals = <E as EthSpec>::MaxWithdrawalsPerPayload::to_usize();
        let signed = envelope();
        // At the bounds the bytes decode, and no limit fails.
        let at_bounds = oversized(&signed, max_requests, max_withdrawals);
        assert!(SignedExecutionPayloadEnvelope::<E>::from_ssz_bytes(&at_bounds).is_ok());
        assert_eq!(past_limits::<E>(&at_bounds), None);
        // One more request or withdrawal does not decode, and fails its limit.
        let too_many_requests = oversized(&signed, max_requests + 1, 0);
        let too_many_withdrawals = oversized(&signed, 0, max_withdrawals + 1);
        for bytes in [&too_many_requests, &too_many_withdrawals] {
            assert!(SignedExecutionPayloadEnvelope::<E>::from_ssz_bytes(bytes).is_err());
        }
        assert_eq!(
            past_limits::<E>(&too_many_requests),
            Some(RejectReason::TooManyRequests {
                kind: RequestKind::Withdrawal,
                count: max_requests + 1,
                limit: max_requests,
            })
        );
        assert_eq!(
            past_limits::<E>(&too_many_withdrawals),
            Some(RejectReason::TooManyWithdrawals {
                count: max_withdrawals + 1,
                limit: max_withdrawals,
            })
        );
        assert_eq!(past_limits::<E>(&[1, 2, 3]), None);

        let mut case = CaseDir::new();
        let root = Root::repeat_byte(0x99);
        let names = [
            case.bytes("execution_payload_envelope", root, &too_many_requests),
            case.bytes(
                "execution_payload_envelope",
                Root::repeat_byte(0x98),
                &too_many_withdrawals,
            ),
        ];
        for name in &names {
            let meta = envelope_meta(&blocks(""), &[(name, "reject")]);
            assert_eq!(case.run(ENVELOPE, &meta), Ok(()), "{name}");
            let meta = envelope_meta(&blocks(""), &[(name, "valid")]);
            let err = case.run(ENVELOPE, &meta).unwrap_err();
            assert!(err.contains("Reject"), "{err}");
        }
        // Bytes that are no envelope at all fail the case.
        let name = case.bytes(
            "execution_payload_envelope",
            Root::repeat_byte(0x97),
            &[1, 2, 3],
        );
        let err = case
            .run(ENVELOPE, &envelope_meta(&blocks(""), &[(&name, "reject")]))
            .unwrap_err();
        assert!(err.contains(&name), "{err}");
    }

    #[test]
    fn an_invalid_signature_rejects_and_a_later_valid_copy_accepts() {
        let valid = envelope();
        let mut invalid = valid.clone();
        invalid.signature = [0; 96];
        let mut wrong_key = valid.clone();
        wrong_key.signature = sign(Root::repeat_byte(0x42));
        let mut case = CaseDir::new();
        let invalid = case.object("execution_payload_envelope", &invalid);
        let wrong_key = case.object("execution_payload_envelope", &wrong_key);
        let valid = case.object("execution_payload_envelope", &valid);
        let meta = envelope_meta(
            &blocks(""),
            &[
                (&invalid, "reject"),
                (&wrong_key, "reject"),
                (&valid, "valid"),
            ],
        );
        assert_eq!(case.run(ENVELOPE, &meta), Ok(()));
    }

    #[test]
    fn bls_setting_2_turns_the_signature_check_off() {
        let mut unsigned = envelope();
        unsigned.signature = [0; 96];
        let mut case = CaseDir::new();
        let name = case.object("execution_payload_envelope", &unsigned);
        let meta = envelope_meta(&blocks(""), &[(&name, "valid")]);
        assert!(case.run(ENVELOPE, &meta).is_err());
        // The block of slot 1 has valid signatures, and BLS off accepts them too.
        let meta = format!("bls_setting: 2\n{meta}");
        assert_eq!(case.run(ENVELOPE, &meta), Ok(()));
    }

    #[test]
    fn a_valid_payload_attestation_message_accepts_and_its_copy_ignores() {
        let ([member, _], _) = ptc_of(1);
        let mut case = CaseDir::new();
        case.config("0", &[]);
        let name = case.object(
            "payload_attestation_message",
            &ptc_message(1, block_root(), member, true),
        );
        let meta = ptc_meta(
            &blocks(""),
            &[
                (&name, "valid", time_at(1) + 100),
                (&name, "ignore", time_at(1) + 200),
            ],
        );
        case.put("meta.yaml", meta.as_bytes());
        let reads = Reads::default();
        assert_eq!(run(&reads, &case.case("minimal", PTC)), Ok(()));
        for file in &case.files {
            assert!(reads.contains(&file.path), "{}", file.name);
        }
        // An invalid signature rejects, and leaves Seen for a valid copy.
        let invalid = case.object(
            "payload_attestation_message",
            &ptc_message(1, block_root(), member, false),
        );
        let meta = ptc_meta(
            &blocks(""),
            &[
                (&invalid, "reject", time_at(1) + 100),
                (&name, "valid", time_at(1) + 100),
            ],
        );
        assert_eq!(case.run(PTC, &meta), Ok(()));
    }

    #[test]
    fn the_clock_disparity_bounds_the_current_slot_on_both_ends() {
        let ([early, late], _) = ptc_of(1);
        let mut case = CaseDir::new();
        case.config("0", &[]);
        let early = case.object(
            "payload_attestation_message",
            &ptc_message(1, block_root(), early, true),
        );
        let late = case.object(
            "payload_attestation_message",
            &ptc_message(1, block_root(), late, true),
        );
        let disparity = MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS;
        let (lower, upper) = (time_at(1) - disparity, time_at(2) + disparity);
        let meta = ptc_meta(
            &blocks(""),
            &[
                (&early, "ignore", lower - 1),
                (&early, "valid", lower),
                (&late, "ignore", upper + 1),
                (&late, "ignore", time_at(1) + 1_000_000),
                (&late, "valid", upper),
            ],
        );
        assert_eq!(case.run(PTC, &meta), Ok(()));
    }

    #[test]
    fn a_validator_outside_the_ptc_or_the_registry_rejects() {
        let (_, outsider) = ptc_of(1);
        let mut case = CaseDir::new();
        case.config("0", &[]);
        let outside = case.object(
            "payload_attestation_message",
            &ptc_message(1, block_root(), outsider, true),
        );
        let unknown = case.object(
            "payload_attestation_message",
            &ptc_message(1, block_root(), 64, false),
        );
        let meta = ptc_meta(
            &blocks(""),
            &[
                (&outside, "reject", time_at(1) + 100),
                (&unknown, "reject", time_at(1) + 100),
            ],
        );
        assert_eq!(case.run(PTC, &meta), Ok(()));
    }

    #[test]
    fn a_block_that_is_unseen_or_not_at_the_slot_of_the_message_ignores() {
        let ([member, _], _) = ptc_of(2);
        let mut case = CaseDir::new();
        case.config("0", &[]);
        let not_at_slot = case.object(
            "payload_attestation_message",
            &ptc_message(2, block_root(), member, true),
        );
        let unseen = case.object(
            "payload_attestation_message",
            &ptc_message(2, Root::repeat_byte(0xee), member, true),
        );
        let meta = ptc_meta(
            &blocks(""),
            &[
                (&not_at_slot, "ignore", time_at(2) + 100),
                (&unseen, "ignore", time_at(2) + 100),
            ],
        );
        assert_eq!(case.run(PTC, &meta), Ok(()));
    }

    #[test]
    fn a_config_value_that_differs_fails_and_a_later_gloas_fork_epoch_is_used() {
        let ([member, _], _) = ptc_of(1);
        let mut case = CaseDir::new();
        let name = case.object(
            "payload_attestation_message",
            &ptc_message(1, block_root(), member, true),
        );
        let meta = ptc_meta(&blocks(""), &[(&name, "valid", time_at(1) + 100)]);
        for (name, value) in [
            ("SLOT_DURATION_MS", "12000"),
            ("MAXIMUM_GOSSIP_CLOCK_DISPARITY", "400"),
            ("PROPOSER_SCORE_BOOST", "41"),
        ] {
            case.config("0", &[(name, value)]);
            let err = case.run(PTC, &meta).unwrap_err();
            assert!(err.contains(name), "{err}");
        }
        // GLOAS_FORK_EPOCH 1 is after the fork epoch of the state: the message of slot 1
        // is before the Gloas fork of the config.
        case.config("1", &[]);
        assert!(case.run(PTC, &meta).is_err());
        let meta = ptc_meta(&blocks(""), &[(&name, "reject", time_at(1) + 100)]);
        assert_eq!(case.run(PTC, &meta), Ok(()));
        // The same message is valid with GLOAS_FORK_EPOCH 0.
        case.config("0", &[]);
        let meta = ptc_meta(&blocks(""), &[(&name, "valid", time_at(1) + 100)]);
        assert_eq!(case.run(PTC, &meta), Ok(()));
    }

    #[test]
    fn a_mainnet_case_takes_the_mainnet_config() {
        let mut state = genesis_state::<Mainnet>(&[32_000_000_000; 64]);
        state.genesis_time = GENESIS_TIME;
        let mut case = CaseDir::new();
        case.put("state.ssz_snappy", &snappy(&state.as_ssz_bytes()));
        // The minimal config of the case is not the mainnet config.
        case.config("0", &[]);
        case.put(
            "meta.yaml",
            ptc_meta("", &[("payload_attestation_message_0x00", "valid", 0)]).as_bytes(),
        );
        let err = run(&Reads::default(), &case.case("mainnet", PTC)).unwrap_err();
        assert!(err.contains("PRESET_BASE"), "{err}");
        let config = case
            .files
            .iter()
            .position(|f| f.name == "config.yaml")
            .unwrap();
        case.files.remove(config);
        // Without a config, the case goes on to its messages.
        let err = run(&Reads::default(), &case.case("mainnet", PTC)).unwrap_err();
        assert!(err.contains("payload_attestation_message_0x00"), "{err}");
    }

    #[test]
    fn a_blocks_entry_with_a_payload_imports_the_envelope() {
        let w = world();
        let mut case = CaseDir::new();
        let payload = case.object("execution_payload_envelope", &envelope());
        let meta = envelope_meta(
            &blocks(&format!(", payload: {payload}")),
            &[(&payload, "valid")],
        );
        assert_eq!(case.run(ENVELOPE, &meta), Ok(()));
        let reads = Reads::default();
        let with = setup::<E>(&reads, &case.case("minimal", ENVELOPE), 6000).unwrap();
        assert!(is_payload_verified(&with.store.store, block_root()));
        // Without the payload, the payload of the block is not verified.
        case.put(
            "meta.yaml",
            envelope_meta(&blocks(""), &[(&payload, "valid")]).as_bytes(),
        );
        let without = setup::<E>(&reads, &case.case("minimal", ENVELOPE), 6000).unwrap();
        assert!(!is_payload_verified(&without.store.store, block_root()));
        assert_eq!(without.store.time_ms(), time_at(1));
        assert_eq!(without.messages.len(), 1);

        // A payload that fork choice refuses, or that is for another block, fails the case.
        let mut wrong_slot = envelope();
        wrong_slot.message.payload.slot_number = 2;
        let wrong_slot = case.object("execution_payload_envelope", &resign(wrong_slot));
        let mut other_block = envelope();
        other_block.message.beacon_block_root = w.anchor.message.tree_hash_root();
        let other_block = case.object("execution_payload_envelope", &resign(other_block));
        for (bad, needle) in [
            (&wrong_slot, "on_execution_payload_envelope"),
            (&other_block, "another block"),
        ] {
            let meta = envelope_meta(
                &blocks(&format!(", payload: {bad}")),
                &[(&payload, "valid")],
            );
            let err = case.run(ENVELOPE, &meta).unwrap_err();
            assert!(err.contains("blocks[1]") && err.contains(needle), "{err}");
        }
    }

    #[test]
    fn a_case_with_no_blocks_takes_the_anchor_block_of_the_pyspec() {
        let w = world();
        let mut state = w.state.clone();
        // `get_store_from_state` of the pyspec helpers: a default block with the slot, the
        // state root and the bid of the state.
        let mut want = signed_block::<E>(0, 0).message;
        want.body.sync_aggregate.sync_committee_signature = [0; 96];
        want.body.signed_execution_payload_bid = SignedExecutionPayloadBid {
            message: state.latest_execution_payload_bid.clone(),
            signature: [0; 96],
        };
        want.state_root = state_root(&mut state).unwrap();
        assert_eq!(anchor_block(&w.state), Ok(want.clone()));
        let mut later = w.state.clone();
        later.slot = 3;
        let anchor = anchor_block(&later).unwrap();
        assert_eq!(
            (anchor.slot, anchor.state_root),
            (3, state_root(&mut later).unwrap())
        );

        // A message for that anchor of slot 0 is valid.
        let member = get_ptc(&w.state, 0).unwrap()[0];
        let mut case = CaseDir::new();
        case.config("0", &[]);
        let name = case.object(
            "payload_attestation_message",
            &ptc_message(0, want.tree_hash_root(), member, true),
        );
        for head in ["", "blocks: []\n"] {
            let meta = ptc_meta(head, &[(&name, "valid", time_at(0) + 100)]);
            case.put("meta.yaml", meta.as_bytes());
            let reads = Reads::default();
            assert_eq!(run(&reads, &case.case("minimal", PTC)), Ok(()), "{head}");
        }
    }

    #[test]
    fn an_unsupported_input_fails_the_case() {
        let w = world();
        let ([member, _], _) = ptc_of(1);
        let mut case = CaseDir::new();
        case.config("0", &[]);
        let envelope = case.object("execution_payload_envelope", &envelope());
        let message = case.object(
            "payload_attestation_message",
            &ptc_message(1, block_root(), member, true),
        );
        let valid = envelope_meta(&blocks(""), &[(&envelope, "valid")]);
        assert_eq!(case.run(ENVELOPE, &valid), Ok(()));
        let anchor = name_of(&w.anchor);
        let one = |extra: &str| format!("- {{message: {envelope}, expected: valid{extra}}}\n");
        let head = format!("topic: execution_payload\n{}", blocks(""));
        for (meta, needle) in [
            (format!("{valid}foo: 1\n"), "`foo`"),
            (valid.replace("execution_payload\n", "beacon_block\n"), "topic"),
            (valid.replace("topic: execution_payload\n", ""), "topic"),
            (
                envelope_meta(&blocks(", payload_status: VALID"), &[(&envelope, "valid")]),
                "payload_status",
            ),
            (envelope_meta(&blocks(", bar: 1"), &[(&envelope, "valid")]), "`bar`"),
            (envelope_meta(&blocks(", failed: 1"), &[(&envelope, "valid")]), "failed"),
            (
                envelope_meta(
                    &blocks(&format!(", pending: true, payload: {envelope}")),
                    &[(&envelope, "valid")],
                ),
                "payload",
            ),
            (
                valid.replace(
                    &format!("{{block: {anchor}}}"),
                    &format!("{{block: {anchor}, failed: true}}"),
                ),
                "anchor",
            ),
            (
                format!("topic: execution_payload\nblocks: 3\nmessages:\n{}", one("")),
                "blocks",
            ),
            (
                format!("{valid}seen_partial_data_column_headers: [{{block_root: '0x00', header: x}}]\n"),
                "seen_partial_data_column_headers",
            ),
            (format!("{head}messages:\n{}", one(", subnet_id: 0")), "subnet_id"),
            (format!("{head}messages:\n{}", one(", column_index: 0")), "column_index"),
            (format!("{head}messages:\n{}", one(", group_id: x")), "group_id"),
            (format!("{head}messages:\n{}", one(", baz: 1")), "`baz`"),
            (
                format!("{head}messages:\n{}", one(", current_time_ms: 1")),
                "current_time_ms",
            ),
            (format!("{head}messages: []\n"), "no message"),
            (head.clone(), "messages"),
            (
                format!("{head}messages:\n- {{message: missing, expected: valid}}\n"),
                "missing",
            ),
        ] {
            let err = case.run(ENVELOPE, &meta).unwrap_err();
            assert!(err.contains(needle), "{needle}: {err}\n{meta}");
        }
        // An empty list of partial headers loads nothing, and passes.
        let meta = format!("{valid}seen_partial_data_column_headers: []\n");
        assert_eq!(case.run(ENVELOPE, &meta), Ok(()));
        // A payload attestation message needs its time.
        let meta = format!(
            "topic: payload_attestation_message\n{}messages:\n- {{message: {message}, expected: valid}}\n",
            blocks("")
        );
        let err = case.run(PTC, &meta).unwrap_err();
        assert!(err.contains("current_time_ms"), "{err}");
        let meta = ptc_meta(&blocks(""), &[(&message, "valid", time_at(1) + 100)])
            .replace("current_time_ms: ", "current_time_ms: -");
        let err = case.run(PTC, &meta).unwrap_err();
        assert!(err.contains("current_time_ms"), "{err}");
    }
}
