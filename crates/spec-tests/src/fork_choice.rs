//! consensus-spec-tests `tests/<preset>/gloas/fork_choice/<handler>/pyspec_tests/<case>/`
//! through the `fork-choice` crate (`tests/formats/fork_choice/README.md` at v1.7.0-beta.4).
//!
//! A case holds `anchor_state.ssz_snappy`, `anchor_block.ssz_snappy`, `steps.yaml`, the
//! `block_<root>.ssz_snappy`, `attestation_<root>.ssz_snappy`,
//! `attester_slashing_<root>.ssz_snappy` and `execution_payload_envelope_<root>.ssz_snappy`
//! files that its steps name, an optional `meta.yaml`
//! (`description`, `bls_setting`), an optional `config.yaml` and `manifest.yaml` (the suite
//! checks it). [`run`] makes the store with `get_forkchoice_store` and the `SLOT_DURATION_MS`
//! of the preset config, and then runs each step in sequence:
//!
//! - `tick`: `on_tick(store, seconds_to_milliseconds(tick))`.
//! - `block`: `on_block`, with `state_transition` and the BLS backend of
//!   [`crate::bls_backend`] (BLS is on unless `bls_setting: 2`). A step with `valid: false`
//!   must fail with an error that proves the block invalid, and must leave the store equal
//!   to the store before the step (as each other step with `valid: false` must). After a
//!   valid block, the runner gives each attestation of the block to
//!   `on_attestation(..., is_from_block=True)` and then each attester slashing to
//!   `on_attester_slashing`, as the pyspec helper `add_block` does; each must pass. The
//!   payload attestations of a block need no more work: `on_block` gives their votes to the
//!   store (`notify_ptc_messages`), and the messages that the format makes from them set the
//!   same votes again. A block that the store has and that carries payload attestations fails
//!   the case: the test format gives its votes to the store again after `on_block`, and
//!   `fork_choice::on_block` returns early for a known block, so the runner cannot tell which
//!   votes the vector expects.
//! - `attestation`: `on_attestation(..., is_from_block=False)`, the default of the format.
//! - `attester_slashing`: `on_attester_slashing`.
//! - `execution_payload`: `on_execution_payload_envelope`, with the BLS backend of the block
//!   step. The step has no data availability input, and the pyspec engine accepts each
//!   payload, so the data is available and the engine answer is VALID.
//! - `checks`: `head` (the slot, root and payload status of `get_head`), `time`,
//!   `genesis_time`, `justified_checkpoint`, `finalized_checkpoint`, `proposer_boost_root` and
//!   `viable_for_head_roots_and_weights`. A `checks` step with no check fails, and so does a
//!   case that runs no check.
//!
//! Each other step, step key or check key fails the case. Thus a case that needs a handler
//! or a check that is not here cannot pass because the runner does less.

use crate::bls_backend::{backend_for, bls_context, bls_setting, Bls, StateKeys};
use crate::config::check_same_config;
use crate::coverage::Reads;
use crate::fixture;
use crate::plan::Case;
use ::fork_choice::{
    get_filtered_node_tree, get_forkchoice_store, get_head, get_node_children, get_weight,
    milliseconds_to_seconds, on_attestation, on_attester_slashing, on_block,
    on_execution_payload_envelope, on_tick, seconds_to_milliseconds, DataAvailability,
    DataAvailabilityCheck, Error, ExecutionEngine, ForkChoiceNode, NewPayloadRequestRef,
    PayloadImport, PayloadStatus, SignatureVerifier, StateProvider, Store,
};
use consensus_types::gloas::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, Checkpoint, SignedBeaconBlock,
    SignedExecutionPayloadEnvelope,
};
use consensus_types::primitives::{Root, Slot};
use consensus_types::{Mainnet, Minimal};
use ssz::Decode;
use state_transition::per_slot::process_slots;
use state_transition::{
    state_transition, BackendError, BlsContext, Preset, SignatureSet, StfError,
};
use std::num::NonZeroU64;
use std::path::Path;
use tree_hash::TreeHash;
use yaml_rust2::Yaml;

/// The Gloas handler directories that this runner runs.
pub const RUNNABLE: [&str; 11] = [
    "on_block",
    "get_head",
    "get_parent_payload_status",
    "filter_node_tree_variants",
    "ex_ante",
    "on_attestation",
    "reorg",
    "withholding",
    "should_apply_proposer_boost",
    "on_execution_payload_envelope",
    "deposit_with_reorg",
];

/// The Gloas handler directories of v1.7.0-beta.4 that this runner does not run: each case
/// needs a `payload_attestation_message` step or payload vote checks. `testing/skip.toml`
/// skips them.
pub const NOT_RUN: [&str; 3] = [
    "on_payload_attestation_message",
    "payload_timeliness",
    "payload_data_availability",
];

/// Whether this runner runs a Gloas handler directory. `Err` for a directory that it does
/// not know: the suite fails setup on it, so a new handler gets a decision.
pub fn handler_runs(handler: &str) -> Result<bool, String> {
    if RUNNABLE.contains(&handler) {
        Ok(true)
    } else if NOT_RUN.contains(&handler) {
        Ok(false)
    } else {
        Err(format!(
            "unknown fork_choice handler directory `{handler}`: classify it in crates/spec-tests/src/fork_choice.rs"
        ))
    }
}

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    fork == "gloas" && matches!(preset, "minimal" | "mainnet") && handler_runs(handler) == Ok(true)
}

/// `SLOT_DURATION_MS` of `configs/minimal.yaml` (L70) at v1.7.0-beta.4.
const MINIMAL_SLOT_DURATION_MS: u64 = 6_000;
/// `SLOT_DURATION_MS` of `configs/mainnet.yaml` (L74) at v1.7.0-beta.4.
const MAINNET_SLOT_DURATION_MS: u64 = 12_000;

/// Runs one case. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    let handler = &case.key.handler;
    if handler_runs(handler) != Ok(true) {
        return Err(format!("no fork_choice runner for handler {handler}"));
    }
    match case.key.preset.as_str() {
        "minimal" => run_case::<Minimal>(reads, case, MINIMAL_SLOT_DURATION_MS),
        "mainnet" => run_case::<Mainnet>(reads, case, MAINNET_SLOT_DURATION_MS),
        other => Err(format!("no fork_choice runner for preset {other}")),
    }
}

fn run_case<E: Preset>(reads: &Reads, case: &Case, slot_duration_ms: u64) -> Result<(), String> {
    let file = |name: &str| case.file(name).ok_or_else(|| format!("case has no {name}"));
    let bls = bls_setting(reads, case)?;
    let anchor_state: BeaconState<E> = decode(reads, file("anchor_state.ssz_snappy")?)?;
    let anchor_block: BeaconBlock<E> = decode(reads, file("anchor_block.ssz_snappy")?)?;
    check_config::<E>(reads, case, anchor_state.fork.epoch, slot_duration_ms)?;
    let steps = fixture::load(reads, file("steps.yaml")?)?;
    let steps = fixture::list(&steps).map_err(|e| format!("steps.yaml: {e}"))?;
    let slot_duration = NonZeroU64::new(slot_duration_ms).ok_or("SLOT_DURATION_MS is zero")?;
    let mut store = get_forkchoice_store(anchor_state, anchor_block, slot_duration)
        .map_err(|e| format!("get_forkchoice_store: {e}"))?;
    let provider = Transition {
        preset: &case.key.preset,
        bls,
    };
    let mut checks = 0;
    for (i, step) in steps.iter().enumerate() {
        checks += apply_step(reads, case, &mut store, &provider, step)
            .map_err(|e| format!("steps.yaml step {i}: {e}"))?;
    }
    // A case with no check would pass for any store.
    if checks == 0 {
        return Err("steps.yaml runs no check".into());
    }
    Ok(())
}

/// The `config.yaml` of a case, if it has one: the values that the transition compiles in
/// ([`check_same_config`]), the values that fork choice compiles in
/// (`fork_choice::config_values`) and `SLOT_DURATION_MS` of the preset.
fn check_config<E: Preset>(
    reads: &Reads,
    case: &Case,
    fork_epoch: u64,
    slot_duration_ms: u64,
) -> Result<(), String> {
    check_same_config::<E>(reads, case, fork_epoch)?;
    let Some(path) = case.file("config.yaml") else {
        return Ok(());
    };
    let config = fixture::load(reads, path)?;
    let values = ::fork_choice::config_values()
        .into_iter()
        .chain([("SLOT_DURATION_MS", slot_duration_ms)]);
    for (name, want) in values {
        let got = fixture::field(&config, name).map_err(|e| format!("config.yaml: {e}"))?;
        if unsigned(got) != Some(want) {
            return Err(format!(
                "config.yaml sets {name} to {got:?}, but the runner uses {want}"
            ));
        }
    }
    Ok(())
}

/// The state transition of the vectors. The signatures go to the in-process BLS backend with
/// the keys of the state, or to no check for `bls_setting: 2`, with the config of the preset.
struct Transition<'a> {
    preset: &'a str,
    bls: Bls,
}

impl Transition<'_> {
    fn context<'k>(&self, keys: &'k StateKeys) -> Result<BlsContext<'k>, StfError> {
        // Only an unknown preset fails here, and `run` accepts only known presets.
        bls_context(self.preset, backend_for(self.bls, keys))
            .map_err(|e| StfError::SignatureBackend(BackendError(e)))
    }
}

impl<E: Preset> StateProvider<E> for Transition<'_> {
    fn state_transition(
        &self,
        state: &mut BeaconState<E>,
        signed_block: &SignedBeaconBlock<E>,
    ) -> Result<(), StfError> {
        // The keys of the state at the slot of the block, as in the sanity runner: an epoch
        // boundary on the way can add validators and builders. If the slots fail,
        // `state_transition` fails on them in the same way.
        let pre_keys = StateKeys::new(state);
        let mut at_slot = state.clone();
        let advanced = process_slots(
            &mut at_slot,
            signed_block.message.slot,
            &self.context(&pre_keys)?,
        )
        .is_ok();
        let keys = if advanced {
            StateKeys::new(&at_slot)
        } else {
            pre_keys
        };
        state_transition(state, signed_block, true, &self.context(&keys)?)
    }

    fn process_slots(&self, state: &mut BeaconState<E>, slot: Slot) -> Result<(), StfError> {
        let keys = StateKeys::new(state);
        process_slots(state, slot, &self.context(&keys)?)
    }
}

impl<E: Preset> SignatureVerifier<E> for Transition<'_> {
    fn verify_signature_sets(
        &self,
        state: &BeaconState<E>,
        sets: &[SignatureSet],
    ) -> Result<bool, BackendError> {
        let keys = StateKeys::new(state);
        backend_for(self.bls, &keys).verify_signature_sets(sets)
    }
}

/// The vectors run with all data available: the format has no availability input for an
/// `execution_payload` step.
impl DataAvailabilityCheck for Transition<'_> {
    fn is_data_available(&self, _: Root) -> DataAvailability {
        DataAvailability::Available
    }
}

/// The engine of the pyspec (`NoopExecutionEngine`) accepts each payload.
impl<E: Preset> ExecutionEngine<E> for Transition<'_> {
    fn verify_and_notify_new_payload(&self, _: &NewPayloadRequestRef<'_, E>) -> PayloadImport {
        PayloadImport::Valid
    }
}

/// Runs one entry of `steps.yaml`, and gives the number of checks that it ran.
fn apply_step<E: Preset>(
    reads: &Reads,
    case: &Case,
    store: &mut Store<E>,
    provider: &Transition<'_>,
    step: &Yaml,
) -> Result<usize, String> {
    let map = step
        .as_hash()
        .ok_or_else(|| format!("expected a mapping, got {step:?}"))?;
    let keys = map
        .keys()
        .map(|k| {
            k.as_str()
                .ok_or_else(|| format!("key {k:?} is not a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let only = |kind: &str, allowed: &[&str]| match keys.iter().find(|k| !allowed.contains(k)) {
        Some(k) => Err(format!("unsupported key `{k}` in a {kind} step")),
        None => Ok(()),
    };
    let valid = match &step["valid"] {
        Yaml::BadValue => true,
        v => fixture::boolean(v).map_err(|e| format!("valid: {e}"))?,
    };
    if keys.contains(&"tick") {
        only("tick", &["tick", "valid"])?;
        tick(store, &step["tick"], valid).map(|()| 0)
    } else if keys.contains(&"block") {
        only("block", &["block", "valid"])?;
        block(reads, case, store, provider, &step["block"], valid).map(|()| 0)
    } else if keys.contains(&"attestation") {
        only("attestation", &["attestation", "valid"])?;
        let attestation: Attestation<E> = object(reads, case, &step["attestation"])?;
        run_handler(store, "on_attestation", valid, |store| {
            on_attestation(store, provider, &attestation, false)
        })
        .map(|()| 0)
    } else if keys.contains(&"attester_slashing") {
        only("attester_slashing", &["attester_slashing", "valid"])?;
        let slashing: AttesterSlashing<E> = object(reads, case, &step["attester_slashing"])?;
        run_handler(store, "on_attester_slashing", valid, |store| {
            on_attester_slashing(store, provider, &slashing)
        })
        .map(|()| 0)
    } else if keys.contains(&"execution_payload") {
        only("execution_payload", &["execution_payload", "valid"])?;
        let envelope: SignedExecutionPayloadEnvelope<E> =
            object(reads, case, &step["execution_payload"])?;
        run_handler(store, "on_execution_payload_envelope", valid, |store| {
            on_execution_payload_envelope(store, provider, &envelope)
        })
        .map(|()| 0)
    } else if keys == ["checks"] {
        let checks = step["checks"]
            .as_hash()
            .ok_or("checks: expected a mapping")?;
        if checks.is_empty() {
            return Err("a checks step has no check".into());
        }
        checks.iter().try_for_each(|(key, want)| {
            let key = key.as_str().ok_or("checks: a key is not a string")?;
            check(store, key, want)
        })?;
        Ok(checks.len())
    } else {
        Err(format!(
            "unsupported step {keys:?}: the runner has only tick, block, attestation, attester_slashing, execution_payload and checks"
        ))
    }
}

fn tick<E: Preset>(store: &mut Store<E>, seconds: &Yaml, valid: bool) -> Result<(), String> {
    let seconds = unsigned(seconds).ok_or_else(|| format!("tick: {seconds:?} is not a time"))?;
    let before = (!valid).then(|| store.clone());
    match (on_tick(store, seconds_to_milliseconds(seconds)), valid) {
        (Ok(()), true) => Ok(()),
        (Err(Error::BeforeGenesis { .. } | Error::Overflow), false) => unchanged(store, before),
        (Ok(()), false) => Err(format!(
            "on_tick accepted tick {seconds}, which the vector expects to fail"
        )),
        (Err(e), _) => Err(format!("on_tick failed on tick {seconds}: {e}")),
    }
}

fn block<E: Preset>(
    reads: &Reads,
    case: &Case,
    store: &mut Store<E>,
    provider: &Transition<'_>,
    name: &Yaml,
    valid: bool,
) -> Result<(), String> {
    let signed_block: SignedBeaconBlock<E> = object(reads, case, name)?;
    let name = name.as_str().unwrap_or_default();
    let body = &signed_block.message.body;
    let known = store.block(signed_block.message.tree_hash_root()).is_some();
    if known && !body.payload_attestations.is_empty() {
        return Err(format!(
            "{name} is in the store and has payload attestations: the test format gives their votes to the store again after on_block, and fork_choice::on_block returns early for a known block"
        ));
    }
    run_handler(store, "on_block", valid, |store| {
        on_block(store, provider, &signed_block)
    })?;
    if !valid {
        return Ok(());
    }
    // `add_block` of the pyspec helpers: the attestations of the block, then its attester
    // slashings.
    for attestation in body.attestations.iter() {
        on_attestation(store, provider, attestation, true)
            .map_err(|e| format!("on_attestation refused an attestation of {name}: {e}"))?;
    }
    for slashing in body.attester_slashings.iter() {
        on_attester_slashing(store, provider, slashing).map_err(|e| {
            format!("on_attester_slashing refused an attester slashing of {name}: {e}")
        })?;
    }
    Ok(())
}

/// The SSZ object of the `<name>.ssz_snappy` file that a step names.
fn object<T: Decode>(reads: &Reads, case: &Case, name: &Yaml) -> Result<T, String> {
    let name = name.as_str().ok_or("expected a file name")?;
    let file = format!("{name}.ssz_snappy");
    let path = case
        .file(&file)
        .ok_or_else(|| format!("case has no {file}"))?;
    decode(reads, path)
}

/// Runs `handler` on `store` for a step with the flag `valid`. A refused step must fail on a
/// spec assert about its input, and must not modify the store (P0 L97-99).
fn run_handler<E: Preset>(
    store: &mut Store<E>,
    name: &str,
    valid: bool,
    handler: impl FnOnce(&mut Store<E>) -> Result<(), Error>,
) -> Result<(), String> {
    let before = (!valid).then(|| store.clone());
    match (handler(store), valid) {
        (Ok(()), true) => Ok(()),
        (Err(e), false) if proves_invalid(&e) => unchanged(store, before),
        (Ok(()), false) => Err(format!(
            "{name} accepted a step that the vector expects to fail"
        )),
        (Err(e), false) => Err(format!(
            "{name} failed with {e}, which is not a spec failure"
        )),
        (Err(e), true) => Err(format!("{name} refused a valid step: {e}")),
    }
}

/// A refused call must not modify the store (P0 L97-99): `store` must equal `before`, the
/// copy from before the call.
fn unchanged<E: Preset>(store: &Store<E>, before: Option<Store<E>>) -> Result<(), String> {
    match before {
        Some(before) if *store != before => Err("the refused call changed the store".into()),
        _ => Ok(()),
    }
}

/// Whether a handler failed on a spec assert about its input, not on a fault of the store.
fn proves_invalid(e: &Error) -> bool {
    match e {
        Error::UnknownParent(_)
        | Error::ParentPayloadNotVerified(_)
        | Error::FutureBlock { .. }
        | Error::NotAfterFinalized { .. }
        | Error::NotFinalizedDescendant { .. }
        | Error::InvalidAttestation(_)
        | Error::InvalidEnvelope(_) => true,
        Error::StateTransition(e) | Error::IndexedAttestation(e) => e.proves_invalid(),
        _ => false,
    }
}

/// One check of a `checks` step against the store.
fn check<E: Preset>(store: &Store<E>, key: &str, want: &Yaml) -> Result<(), String> {
    let result = match key {
        "head" => check_head(store, want),
        "time" => equal(milliseconds_to_seconds(store.time_ms()), want, unsigned),
        "genesis_time" => equal(
            milliseconds_to_seconds(store.genesis_time_ms()),
            want,
            unsigned,
        ),
        "justified_checkpoint" => equal(store.justified_checkpoint().clone(), want, checkpoint),
        "finalized_checkpoint" => equal(store.finalized_checkpoint().clone(), want, checkpoint),
        "proposer_boost_root" => equal(store.proposer_boost_root(), want, root),
        "viable_for_head_roots_and_weights" => check_viable(store, want),
        other => return Err(format!("unsupported check `{other}`")),
    };
    result.map_err(|e| format!("{key}: {e}"))
}

/// `head`: the slot, the root and the payload status of `get_head`.
fn check_head<E: Preset>(store: &Store<E>, want: &Yaml) -> Result<(), String> {
    let map = want.as_hash().ok_or("expected a mapping")?;
    if let Some(k) = map
        .keys()
        .find(|k| !matches!(k.as_str(), Some("slot" | "root" | "payload_status")))
    {
        return Err(format!("unsupported key {k:?}"));
    }
    let head = get_head(store).map_err(|e| format!("get_head: {e}"))?;
    let slot = store
        .block(head.root)
        .map(|b| b.slot)
        .ok_or_else(|| format!("head {} is not in the store", head.root))?;
    let got = (slot, head.root, head.payload_status as u64);
    let field = |name: &str| fixture::field(want, name);
    let want = (
        unsigned(field("slot")?).ok_or("slot is not a slot")?,
        root(field("root")?).ok_or("root is not a root")?,
        unsigned(field("payload_status")?).ok_or("payload_status is not a number")?,
    );
    if got == want {
        Ok(())
    } else {
        Err(format!(
            "got (slot, root, payload_status) {got:?}, want {want:?}"
        ))
    }
}

/// `viable_for_head_roots_and_weights` (`get_viable_for_head_checks` of the pyspec helpers):
/// the root, the weight and the payload status of each leaf of the walk from the PENDING
/// justified node through the children in the filtered node tree. The format lists the
/// leaves in the order of a stack, which the spec does not define, so the runner compares
/// them in sorted order.
fn check_viable<E: Preset>(store: &Store<E>, want: &Yaml) -> Result<(), String> {
    let mut want = fixture::list(want)?
        .iter()
        .map(|leaf| {
            let map = leaf.as_hash().ok_or("expected a mapping")?;
            let known = ["root", "weight", "payload_status"];
            if let Some(k) = map
                .keys()
                .find(|k| !k.as_str().is_some_and(|k| known.contains(&k)))
            {
                return Err(format!("unsupported key {k:?}"));
            }
            Ok((
                root(fixture::field(leaf, "root")?).ok_or("root is not a root")?,
                unsigned(fixture::field(leaf, "weight")?).ok_or("weight is not a number")?,
                unsigned(fixture::field(leaf, "payload_status")?)
                    .ok_or("payload_status is not a number")?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let tree = get_filtered_node_tree(store).map_err(|e| format!("get_filtered_node_tree: {e}"))?;
    let mut pending = vec![ForkChoiceNode {
        root: store.justified_checkpoint().root,
        payload_status: PayloadStatus::Pending,
    }];
    let mut got = Vec::new();
    while let Some(node) = pending.pop() {
        let children = get_node_children(store, &node).map_err(|e| format!("children: {e}"))?;
        let viable: Vec<_> = children.into_iter().filter(|c| tree.contains(c)).collect();
        if viable.is_empty() {
            let weight = get_weight(store, &node).map_err(|e| format!("get_weight: {e}"))?;
            got.push((node.root, weight, node.payload_status as u64));
        }
        pending.extend(viable);
    }
    want.sort_unstable();
    got.sort_unstable();
    if got == want {
        Ok(())
    } else {
        Err(format!(
            "got (root, weight, payload_status) {got:?}, want {want:?}"
        ))
    }
}

/// Compares `got` with `want` as `parse` reads it.
fn equal<T: PartialEq + std::fmt::Debug>(
    got: T,
    want: &Yaml,
    parse: fn(&Yaml) -> Option<T>,
) -> Result<(), String> {
    match parse(want) {
        Some(want) if want == got => Ok(()),
        Some(want) => Err(format!("got {got:?}, want {want:?}")),
        None => Err(format!("cannot read {want:?}")),
    }
}

fn unsigned(y: &Yaml) -> Option<u64> {
    y.as_i64().and_then(|v| u64::try_from(v).ok())
}

fn root(y: &Yaml) -> Option<Root> {
    fixture::hex_array::<32>(y).ok().flatten().map(Root::from)
}

/// A checkpoint `{epoch, root}` with no other key.
fn checkpoint(y: &Yaml) -> Option<Checkpoint> {
    let map = y.as_hash()?;
    let known = map
        .keys()
        .all(|k| matches!(k.as_str(), Some("epoch" | "root")));
    known.then_some(())?;
    Some(Checkpoint {
        epoch: unsigned(&y["epoch"])?,
        root: root(&y["root"])?,
    })
}

/// An SSZ value from a `.ssz_snappy` file.
fn decode<T: Decode>(reads: &Reads, path: &Path) -> Result<T, String> {
    let bytes = fixture::ssz_snappy(reads, path)?;
    T::from_ssz_bytes(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))
}
