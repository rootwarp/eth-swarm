//! consensus-spec-tests `tests/<preset>/gloas/operations/<handler>/pyspec_tests/<case>/`,
//! run through `state_transition::per_block`.
//!
//! Each case holds `pre.ssz_snappy`, the operation (`<operation>.ssz_snappy`), `post.ssz_snappy`
//! when the operation is valid, `manifest.yaml`, and an optional `meta.yaml` with
//! `bls_setting` (0 or absent: check the signatures, 1: they must be checked, 2: do not check
//! them) and, for the Gloas `attestation` handler, `parent_slot`. The check is the handler on
//! `pre`, then `hash_tree_root` against `post`. A case without `post.ssz_snappy` must fail
//! with an error that proves the input invalid (`StfError::proves_invalid`).
//!
//! The signature sets of an operation are checked before the handler, through the
//! in-process backend, as the block checks them in one batch before its steps.
//!
//! Every Gloas operations handler directory must be in [`RUNNABLE`] or [`NOT_RUN`]
//! ([`handler_runs`]); any other directory fails the run. The handlers of [`NOT_RUN`] need a
//! `skip.toml` entry. beta.4 has no `operations/randao` handler: `sanity/blocks` proves
//! `process_randao`.
//!
//! The `payload_attestation` cases also carry `config.yaml`, which [`check_config`] compares
//! with the values that the runner and the transition use.
//!
//! The `withdrawals` handler calls the Gloas `process_withdrawals(state)`, which takes the
//! state only, so its cases have no operation file. A `withdrawals` case without
//! `post.ssz_snappy` has a pre-state that the transition does not make, and it must fail with
//! the index error of the list that its name gives ([`expect_state_only`]).

use crate::bls_backend::{
    backend_for, bls_context, bls_setting, genesis_fork_version, Bls, StateKeys,
};
use crate::coverage::Reads;
use crate::fixture;
use crate::plan::Case;
use consensus_types::common::{
    AttestationData, ConsolidationRequest, ProposerSlashing, SignedBLSToExecutionChange,
    SignedVoluntaryExit, SyncAggregate,
};
use consensus_types::gloas::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, BuilderDepositRequest,
    BuilderExitRequest, PayloadAttestation,
};
use consensus_types::primitives::{BLSSignature, Slot, ValidatorIndex};
use consensus_types::{Mainnet, Minimal};
use ssz::Decode;
use ssz_types::typenum::{Unsigned, U0};
use ssz_types::ProgressiveVariableList;
use state_transition::accessors::TotalActiveBalanceCache;
use state_transition::per_block::attestation::process_attestation_with;
use state_transition::per_block::builder::{
    process_builder_deposit_request, process_builder_exit_request,
};
use state_transition::per_block::exits::{process_bls_to_execution_change, process_voluntary_exit};
use state_transition::per_block::requests::process_consolidation_request;
use state_transition::per_block::sync_aggregate::process_sync_aggregate_with;
use state_transition::per_block::{
    process_attester_slashing, process_block_header, process_payload_attestation,
    process_proposer_slashing, process_withdrawals, BlockContext,
};
use state_transition::signatures::{
    attestation_signature_set_with, attester_slashing_signature_sets,
    proposer_slashing_signature_sets, verify_bls_to_execution_change_signature,
    verify_operation_signatures, verify_payload_attestation_signature,
    verify_sync_aggregate_signature_with, verify_voluntary_exit_signature,
};
use state_transition::{state_root, Preset, StfError};
use std::path::Path;
use tree_hash::TreeHash;
use yaml_rust2::Yaml;

/// Handlers this runner executes.
pub const RUNNABLE: [&str; 13] = [
    "attestation",
    "attester_slashing",
    "block_header",
    "bls_to_execution_change",
    "builder_deposit_request",
    "builder_exit_request",
    "consolidation_request",
    "payload_attestation",
    "proposer_slashing",
    "sync_aggregate",
    "voluntary_exit",
    "voluntary_exit_churn",
    "withdrawals",
];

/// Gloas handlers at beta.4 that the state transition does not port yet. Each needs a
/// `skip.toml` entry.
pub const NOT_RUN: [&str; 4] = [
    "deposit_request",
    "execution_payload_bid",
    "parent_execution_payload",
    "withdrawal_request",
];

/// `Ok(true)` for a handler this runner executes, `Ok(false)` for a known handler that it
/// does not, and `Err` for a handler directory that it does not know.
pub fn handler_runs(handler: &str) -> Result<bool, String> {
    if RUNNABLE.contains(&handler) {
        Ok(true)
    } else if NOT_RUN.contains(&handler) {
        Ok(false)
    } else {
        Err(format!(
            "unknown operations handler directory `{handler}`: classify it in crates/spec-tests/src/operations.rs"
        ))
    }
}

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    fork == "gloas" && matches!(preset, "minimal" | "mainnet") && handler_runs(handler) == Ok(true)
}

/// Runs one case. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    match case.key.preset.as_str() {
        "minimal" => operation::<Minimal>(reads, case),
        "mainnet" => operation::<Mainnet>(reads, case),
        other => Err(format!("no operations runner for preset {other}")),
    }
}

fn operation<E: Preset>(reads: &Reads, case: &Case) -> Result<(), String> {
    let file = |name: &str| case.file(name).ok_or_else(|| format!("case has no {name}"));
    let mut state = decode::<BeaconState<E>>(reads, file("pre.ssz_snappy")?)?;
    let post = case
        .file("post.ssz_snappy")
        .map(|p| decode::<BeaconState<E>>(reads, p))
        .transpose()?;
    let bls = bls_setting(reads, case)?;
    if let Some(path) = case.file("config.yaml") {
        check_config(reads, path, &case.key.preset)?;
    }
    let outcome = match (case.key.runner.as_str(), case.key.handler.as_str()) {
        ("operations", "block_header") => {
            let block = decode::<BeaconBlock<E>>(reads, file("block.ssz_snappy")?)?;
            process_block_header(&mut state, &block)
        }
        ("operations", "builder_deposit_request") => {
            let request = decode::<BuilderDepositRequest>(
                reads,
                file("builder_deposit_request.ssz_snappy")?,
            )?;
            let keys = StateKeys::new(&state);
            let ctx = bls_context(&case.key.preset, backend_for(bls, &keys))?;
            process_builder_deposit_request(
                &mut state,
                &request,
                ctx.genesis_fork_version,
                ctx.backend,
            )
        }
        ("operations", "builder_exit_request") => {
            let request =
                decode::<BuilderExitRequest>(reads, file("builder_exit_request.ssz_snappy")?)?;
            process_builder_exit_request(&mut state, &request)
        }
        ("operations", "payload_attestation") => {
            let attestation =
                decode::<PayloadAttestation<E>>(reads, file("payload_attestation.ssz_snappy")?)?;
            let keys = StateKeys::new(&state);
            verify_payload_attestation_signature(&state, &attestation, backend_for(bls, &keys))
                .and_then(|()| process_payload_attestation(&state, &attestation))
        }
        ("operations", "sync_aggregate") => {
            let aggregate = decode::<SyncAggregate<E>>(reads, file("sync_aggregate.ssz_snappy")?)?;
            // One context: the signature check and the rewards share the committee indices.
            // Under `Bls::Ignore`, `process_sync_aggregate_with` still rejects an empty
            // aggregate without the infinity signature, which the spec with BLS off accepts
            // (see `Bls::Ignore`).
            let mut ctx = BlockContext::default();
            let checked = match bls {
                Bls::Check => verify_sync_aggregate_signature_with(
                    &state,
                    &aggregate,
                    &StateKeys::new(&state),
                    &mut ctx,
                ),
                Bls::Ignore => Ok(()),
            };
            checked.and_then(|()| process_sync_aggregate_with(&mut state, &aggregate, &mut ctx))
        }
        // `voluntary_exit_churn` has the cases of the exit churn: the same operation.
        ("operations", "voluntary_exit" | "voluntary_exit_churn") => {
            let exit = decode::<SignedVoluntaryExit>(reads, file("voluntary_exit.ssz_snappy")?)?;
            let keys = StateKeys::new(&state);
            let ctx = bls_context(&case.key.preset, backend_for(bls, &keys))?;
            let mut cache = TotalActiveBalanceCache::default();
            verify_voluntary_exit_signature(&state, &exit, ctx.capella_fork_version, ctx.backend)
                .and_then(|()| process_voluntary_exit(&mut state, &exit, &mut cache))
        }
        ("operations", "bls_to_execution_change") => {
            let change =
                decode::<SignedBLSToExecutionChange>(reads, file("address_change.ssz_snappy")?)?;
            let keys = StateKeys::new(&state);
            let ctx = bls_context(&case.key.preset, backend_for(bls, &keys))?;
            verify_bls_to_execution_change_signature(
                &state,
                &change,
                ctx.genesis_fork_version,
                ctx.backend,
            )
            .and_then(|()| process_bls_to_execution_change(&mut state, &change))
        }
        ("operations", "consolidation_request") => {
            let request =
                decode::<ConsolidationRequest>(reads, file("consolidation_request.ssz_snappy")?)?;
            let mut cache = TotalActiveBalanceCache::default();
            process_consolidation_request(&mut state, &request, &mut cache)
        }
        ("operations", "proposer_slashing") => {
            let slashing =
                decode::<ProposerSlashing>(reads, file("proposer_slashing.ssz_snappy")?)?;
            let keys = StateKeys::new(&state);
            proposer_slashing_signature_sets(&state, &slashing)
                .and_then(|sets| verify_operation_signatures(&sets, backend_for(bls, &keys)))
                .and_then(|()| process_proposer_slashing(&mut state, &slashing))
        }
        ("operations", "attester_slashing") => {
            let slashing = attester_slashing::<E>(reads, file("attester_slashing.ssz_snappy")?)?;
            let keys = StateKeys::new(&state);
            slashing.and_then(|slashing| {
                attester_slashing_signature_sets(&state, &slashing)
                    .and_then(|sets| verify_operation_signatures(&sets, backend_for(bls, &keys)))
                    .and_then(|()| process_attester_slashing(&mut state, &slashing))
            })
        }
        ("operations", "attestation") => {
            let attestation = decode::<Attestation<E>>(reads, file("attestation.ssz_snappy")?)?;
            let parent_slot = parent_slot(reads, case)?.unwrap_or(state.latest_block_header.slot);
            // One context: the signature set and the step share the committee cache.
            let mut ctx = BlockContext::default();
            let keys = StateKeys::new(&state);
            attestation_signature_set_with(&state, &attestation, &mut ctx)
                .and_then(|set| verify_operation_signatures(&[set], backend_for(bls, &keys)))
                .and_then(|()| {
                    process_attestation_with(&mut state, &attestation, parent_slot, &mut ctx)
                })
        }
        ("operations", "withdrawals") => {
            let outcome = process_withdrawals(&mut state);
            return expect_state_only(case, &mut state, outcome, post);
        }
        (runner, handler) => return Err(format!("no runner for {runner}/{handler}")),
    };
    expect(&mut state, outcome, post)
}

/// Checks the `config.yaml` of a case (the pyspec writes one for the tests that need the
/// config of the preset) against the values that the runner keeps: `PRESET_BASE` is the
/// preset of the case, and `GENESIS_FORK_VERSION` is [`genesis_fork_version`]. The
/// transition reads no config value in the runnable handlers.
///
/// `GLOAS_FORK_EPOCH` is not compared. `get_ptc` reads the Gloas fork epoch from
/// `state.fork.epoch`, which is `GLOAS_FORK_EPOCH` in each state that the transition makes.
/// The case `process_payload_attestation_cross_epoch_wrong_domain` sets `state.fork.epoch` to
/// 1 under a `GLOAS_FORK_EPOCH` of 0, to give its two epochs different fork versions. Thus
/// `get_ptc` refuses the slot of epoch 0 (`EpochOutOfWindow`) before the domain check that
/// the case tests. The case expects an invalid attestation, and it gets one.
fn check_config(reads: &Reads, path: &Path, preset: &str) -> Result<(), String> {
    let config = fixture::load(reads, path)?;
    let wrong = |key: &str, value: &Yaml| format!("config.yaml: {key} is {value:?}");
    let base = fixture::field(&config, "PRESET_BASE")?;
    if base.as_str() != Some(preset) {
        return Err(wrong("PRESET_BASE", base));
    }
    // YAML reads the unquoted `0x` value as an integer.
    let version = fixture::field(&config, "GENESIS_FORK_VERSION")?;
    let parsed = version.as_i64().and_then(|v| u32::try_from(v).ok());
    if parsed.map(u32::to_be_bytes) != Some(genesis_fork_version(preset)?) {
        return Err(wrong("GENESIS_FORK_VERSION", version));
    }
    Ok(())
}

/// `parent_slot` of `meta.yaml`: the slot of the parent block, which the Gloas
/// `process_attestation` takes. `None` if the case has no `meta.yaml` or no such key; the
/// caller then uses the slot of the latest block header of `pre`, which `process_block`
/// passes (`gloas/beacon-chain.md` L1756).
fn parent_slot(reads: &Reads, case: &Case) -> Result<Option<Slot>, String> {
    let Some(path) = case.file("meta.yaml") else {
        return Ok(None);
    };
    match &fixture::load(reads, path)?["parent_slot"] {
        Yaml::BadValue => Ok(None),
        Yaml::Integer(slot) => Slot::try_from(*slot)
            .map(Some)
            .map_err(|_| format!("meta.yaml: parent_slot {slot} is not a slot")),
        other => Err(format!(
            "meta.yaml: parent_slot {other:?} is not an integer"
        )),
    }
}

/// `IndexedAttestation` with the unbounded `AttestingIndices` of the spec
/// (`ProgressiveList[ValidatorIndex]`, `gloas/beacon-chain.md` L225).
#[derive(ssz_derive::Decode)]
struct SpecIndexedAttestation {
    attesting_indices: ProgressiveVariableList<ValidatorIndex, U0>,
    _data: AttestationData,
    _signature: BLSSignature,
}

/// `AttesterSlashing` of two [`SpecIndexedAttestation`]s.
#[derive(ssz_derive::Decode)]
struct SpecAttesterSlashing {
    attestation_1: SpecIndexedAttestation,
    attestation_2: SpecIndexedAttestation,
}

/// The attester slashing of a case.
///
/// The `IndexedAttestation` of consensus-types holds at most `MAX_VALIDATORS_PER_COMMITTEE *
/// MAX_COMMITTEES_PER_SLOT` indices, the bound that `is_valid_indexed_attestation`
/// (`gloas/beacon-chain.md` L1022-1041) asserts. An object that does not decode for that reason only has the verdict
/// of that assert: `Ok(Err(StfError::InvalidIndexedAttestation))`. Any other decode error is
/// a failure of the case (`Err`).
fn attester_slashing<E: Preset>(
    reads: &Reads,
    path: &Path,
) -> Result<Result<AttesterSlashing<E>, StfError>, String> {
    let bytes = fixture::ssz_snappy(reads, path)?;
    let bounded_error = match AttesterSlashing::<E>::from_ssz_bytes(&bytes) {
        Ok(slashing) => return Ok(Ok(slashing)),
        Err(e) => format!("{}: {e:?}", path.display()),
    };
    let spec = SpecAttesterSlashing::from_ssz_bytes(&bytes).map_err(|_| bounded_error.clone())?;
    let bound = E::MaxValidatorsPerSlot::to_usize();
    if spec.attestation_1.attesting_indices.len() > bound
        || spec.attestation_2.attesting_indices.len() > bound
    {
        Ok(Err(StfError::InvalidIndexedAttestation))
    } else {
        Err(bounded_error)
    }
}

/// Compares the outcome of a handler with what the vector expects.
fn expect<E: Preset>(
    state: &mut BeaconState<E>,
    outcome: Result<(), StfError>,
    post: Option<BeaconState<E>>,
) -> Result<(), String> {
    match (outcome, post) {
        (Ok(()), Some(post)) => {
            let got = state_root(state).map_err(|e| format!("post-state root: {e}"))?;
            let want = post.tree_hash_root();
            if got == want {
                Ok(())
            } else {
                Err(format!(
                    "post-state root mismatch: got {got:x}, want {want:x}"
                ))
            }
        }
        (Err(e), None) if e.proves_invalid() => Ok(()),
        (Err(e), None) => Err(format!("failed with {e}, which is not a spec failure")),
        (Ok(()), None) => Err("processed an operation the vector expects to fail".into()),
        (Err(e), Some(_)) => Err(format!("operation failed: {e}")),
    }
}

/// [`expect`] for a handler that takes the state only (`withdrawals`). Such a handler has no
/// operation that an error can prove invalid. Thus a case without `post.ssz_snappy` tests a
/// pre-state that the transition does not make: an index in the state past the end of its
/// list, which the pyspec raises as `IndexError`. That error is
/// [`StfError::ListIndexOutOfRange`], which is not a proof (a fault of our own state).
///
/// A case without a post-state passes only on the `ListIndexOutOfRange` of the list that its
/// name gives ([`expected_index_list`]). Any other error fails it, a proof error too: a port
/// defect that fails earlier must not pass the case. [`expect`] checks the cases with a
/// post-state.
fn expect_state_only<E: Preset>(
    case: &Case,
    state: &mut BeaconState<E>,
    outcome: Result<(), StfError>,
    post: Option<BeaconState<E>>,
) -> Result<(), String> {
    let e = match (outcome, post) {
        (Err(e), None) => e,
        (outcome, post) => return expect(state, outcome, post),
    };
    let Some(want) = expected_index_list(&case.key.case) else {
        return Err(format!(
            "failed with {e}, but the case name gives no expected index error"
        ));
    };
    match &e {
        StfError::ListIndexOutOfRange { list, .. } if *list == want => {
            // Print the error: a port defect that happens to give this error shows in the
            // trial output.
            eprintln!("{}: expected failure: {e}", case.key);
            Ok(())
        }
        _ => Err(format!(
            "failed with {e}, not the index error of `{want}` that the case expects"
        )),
    }
}

/// The list whose index error a `withdrawals` case without a post-state expects, from the
/// name of the case:
///
/// - `invalid_builder_index_pending` and `invalid_builder_index_sweep`: `builders`. The first
///   read of the bad index is `state.builders[builder_index]` in `apply_withdrawals`
///   (G L2002) and in `get_builders_sweep_withdrawals` (G L1931).
/// - `invalid_validator_index_pending_partial` and `invalid_validator_index_sweep`:
///   `validators`. The first read of the bad index is `state.validators[validator_index]` in
///   `get_pending_partial_withdrawals` (E L1378) and `get_validators_sweep_withdrawals`
///   (E L1423), before `state.balances`.
fn expected_index_list(case: &str) -> Option<&'static str> {
    let name = case.rsplit('/').next().unwrap_or(case);
    if name.starts_with("invalid_builder_index_") {
        Some("builders")
    } else if name.starts_with("invalid_validator_index_") {
        Some("validators")
    } else {
        None
    }
}

/// An SSZ object from a `.ssz_snappy` file.
fn decode<T: Decode>(reads: &Reads, path: &Path) -> Result<T, String> {
    let bytes = fixture::ssz_snappy(reads, path)?;
    T::from_ssz_bytes(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls_backend::{capella_fork_version, genesis_fork_version};
    use crate::plan::{CaseFile, CaseKey, Date};
    use crate::sanity::tests::state;
    use crate::suite::{self, Config, SuiteError};
    use consensus_types::common::{BLSToExecutionChange, Validator, VoluntaryExit};
    use consensus_types::primitives::{Address, Bytes32, Root, Version, FAR_FUTURE_EPOCH};
    use consensus_types::signing::{
        compute_domain, compute_signing_root, DOMAIN_BLS_TO_EXECUTION_CHANGE, DOMAIN_VOLUNTARY_EXIT,
    };
    use ssz::Encode;
    use state_transition::per_block::process_sync_aggregate;
    use state_transition::signatures::G2_POINT_AT_INFINITY;

    const ETH: u64 = 1_000_000_000;

    /// [`state`] at slot 2 with two validators, the sync committee all of validator 1, and
    /// the latest block header at slot 1.
    fn pre() -> BeaconState<Minimal> {
        let mut pre = state(2);
        for i in 0..2u8 {
            pre.validators
                .push(Validator {
                    pubkey: [i; 48],
                    withdrawal_credentials: Bytes32::ZERO,
                    effective_balance: 32 * ETH,
                    slashed: false,
                    activation_eligibility_epoch: 0,
                    activation_epoch: 0,
                    exit_epoch: FAR_FUTURE_EPOCH,
                    withdrawable_epoch: FAR_FUTURE_EPOCH,
                })
                .unwrap();
            pre.balances.push(32 * ETH).unwrap();
        }
        for pubkey in pre.current_sync_committee.pubkeys.iter_mut() {
            *pubkey = [1; 48];
        }
        pre.latest_block_header.slot = 1;
        pre.apply_updates().unwrap();
        pre
    }

    fn snappy(bytes: Vec<u8>) -> Vec<u8> {
        snap::raw::Encoder::new().compress_vec(&bytes).unwrap()
    }

    /// A case of `handler` in `dir` with the given files.
    fn case(dir: &Path, handler: &str, files: &[(&str, Vec<u8>)]) -> Case {
        let files = files
            .iter()
            .map(|(name, bytes)| {
                let path = dir.join(name);
                std::fs::write(&path, bytes).unwrap();
                CaseFile {
                    path,
                    name: (*name).into(),
                }
            })
            .collect();
        Case {
            key: CaseKey {
                source: "consensus-specs".into(),
                fork: "gloas".into(),
                preset: "minimal".into(),
                runner: "operations".into(),
                handler: handler.into(),
                case: "pyspec_tests/case_0".into(),
            },
            files,
        }
    }

    fn aggregate(bits: &[usize], signature: [u8; 96]) -> SyncAggregate<Minimal> {
        let mut aggregate = SyncAggregate {
            sync_committee_bits: Default::default(),
            sync_committee_signature: signature,
        };
        for &i in bits {
            aggregate.sync_committee_bits.set(i, true).unwrap();
        }
        aggregate
    }

    #[test]
    fn unknown_handler_fails() {
        assert_eq!(handler_runs("block_header"), Ok(true));
        assert_eq!(handler_runs("withdrawals"), Ok(true));
        assert_eq!(handler_runs("parent_execution_payload"), Ok(false));
        assert_eq!(handler_runs("builder_deposit_request"), Ok(true));
        assert_eq!(handler_runs("builder_exit_request"), Ok(true));
        for handler in [
            "bls_to_execution_change",
            "consolidation_request",
            "voluntary_exit",
            "voluntary_exit_churn",
        ] {
            assert_eq!(handler_runs(handler), Ok(true), "{handler}");
            assert!(supported("gloas", "mainnet", handler), "{handler}");
        }
        let err = handler_runs("randao").unwrap_err();
        assert!(
            err.contains("unknown operations handler directory `randao`"),
            "{err}"
        );
        assert!(!supported("gloas", "minimal", "randao"));
        assert!(!supported("fulu", "minimal", "block_header"));
        assert!(!supported("gloas", "general", "block_header"));
        assert!(supported("gloas", "mainnet", "sync_aggregate"));

        // In a vector tree, the unknown directory fails the setup, and a skip entry for it
        // does not help.
        let tree = tempfile::tempdir().unwrap();
        let file = tree.path().join(
            "consensus-specs/v1.7.0-beta.4/minimal/tests/minimal/gloas/operations/randao/\
             pyspec_tests/case_0/pre.ssz_snappy",
        );
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"x").unwrap();
        let skip = "[[skip]]\nsource = \"consensus-specs\"\nfork = \"*\"\npreset = \"*\"\n\
                    runner = \"*\"\nhandler = \"*\"\nreason = \"test\"\nowner = \"ian\"\n\
                    issue = \"none\"\nexpires = \"2026-11-30\"\n";
        let manifest = "[[source]]\nname = \"consensus-specs\"\ntag = \"v1.7.0-beta.4\"\n";
        let built = suite::build(&Config {
            root: tree.path(),
            manifest,
            skip,
            selection: Some("minimal"),
            today: Date::parse("2026-10-26").unwrap(),
        });
        match built {
            Err(SuiteError::Setup(msg)) => assert!(msg.contains("`randao`"), "{msg}"),
            Err(other) => panic!("expected a setup error, got {other:?}"),
            Ok(_) => panic!("expected a setup error, got a suite"),
        }
    }

    #[test]
    fn block_header_cases() {
        let dir = tempfile::tempdir().unwrap();
        let pre = pre();
        let mut block = empty_block();
        block.slot = 2;
        block.parent_root = pre.latest_block_header.tree_hash_root();
        let mut post = pre.clone();
        process_block_header(&mut post, &block).unwrap();
        post.apply_updates().unwrap();
        let files = |post: Option<&BeaconState<Minimal>>, block: &BeaconBlock<Minimal>| {
            let mut files = vec![
                ("pre.ssz_snappy", snappy(pre.as_ssz_bytes())),
                ("block.ssz_snappy", snappy(block.as_ssz_bytes())),
            ];
            if let Some(post) = post {
                files.push(("post.ssz_snappy", snappy(post.as_ssz_bytes())));
            }
            files
        };
        let c = case(dir.path(), "block_header", &files(Some(&post), &block));
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));

        // The pre-state is not the post-state.
        let c = case(dir.path(), "block_header", &files(Some(&pre), &block));
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("root mismatch"));
        // A valid block that the vector expects to fail.
        let c = case(dir.path(), "block_header", &files(None, &block));
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("expects to fail"));
        // An invalid block that the vector expects to pass, and one that it expects to fail.
        let mut wrong = block.clone();
        wrong.slot = 3;
        let c = case(dir.path(), "block_header", &files(Some(&post), &wrong));
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("operation failed"));
        let c = case(dir.path(), "block_header", &files(None, &wrong));
        assert_eq!(run(&Reads::default(), &c), Ok(()));
    }

    /// A Gloas block at slot 0 by validator 0 with an empty body.
    fn empty_block() -> BeaconBlock<Minimal> {
        use consensus_types::gloas::*;
        use consensus_types::primitives::{Address, Root};
        let bid = ExecutionPayloadBid::<Minimal> {
            parent_block_hash: Root::ZERO,
            parent_block_root: Root::ZERO,
            block_hash: Root::ZERO,
            prev_randao: Root::ZERO,
            fee_recipient: Address::ZERO,
            gas_limit: 0,
            builder_index: 0,
            slot: 0,
            value: 0,
            execution_payment: 0,
            blob_kzg_commitments: Default::default(),
            execution_requests_root: Root::ZERO,
        };
        BeaconBlock::<Minimal> {
            slot: 0,
            proposer_index: 0,
            parent_root: Root::ZERO,
            state_root: Root::ZERO,
            body: BeaconBlockBody {
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
                sync_aggregate: aggregate(&[], G2_POINT_AT_INFINITY),
                bls_to_execution_changes: Default::default(),
                signed_execution_payload_bid: SignedExecutionPayloadBid {
                    message: bid,
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
            },
        }
    }

    #[test]
    fn sync_aggregate_cases() {
        let dir = tempfile::tempdir().unwrap();
        let pre = pre();
        let files = |agg: &SyncAggregate<Minimal>,
                     post: Option<&BeaconState<Minimal>>,
                     meta: Option<&str>| {
            let mut files = vec![
                ("pre.ssz_snappy", snappy(pre.as_ssz_bytes())),
                ("sync_aggregate.ssz_snappy", snappy(agg.as_ssz_bytes())),
            ];
            if let Some(post) = post {
                files.push(("post.ssz_snappy", snappy(post.as_ssz_bytes())));
            }
            if let Some(meta) = meta {
                files.push(("meta.yaml", meta.as_bytes().to_vec()));
            }
            files
        };
        // No participant and the infinity signature: no BLS call, every member penalized.
        let empty = aggregate(&[], G2_POINT_AT_INFINITY);
        let mut post = pre.clone();
        process_sync_aggregate(&mut post, &empty).unwrap();
        post.apply_updates().unwrap();
        assert!(*post.balances.get(1).unwrap() < 32 * ETH);
        let c = case(
            dir.path(),
            "sync_aggregate",
            &files(&empty, Some(&post), Some("{bls_setting: 1}\n")),
        );
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));

        // No participant and another signature is invalid.
        let bad_empty = aggregate(&[], [0; 96]);
        let c = case(dir.path(), "sync_aggregate", &files(&bad_empty, None, None));
        assert_eq!(run(&Reads::default(), &c), Ok(()));
        // A participant whose signature does not verify (its key is not a curve point).
        let one = aggregate(&[0], G2_POINT_AT_INFINITY);
        let c = case(
            dir.path(),
            "sync_aggregate",
            &files(&one, None, Some("{bls_setting: 0}\n")),
        );
        assert_eq!(run(&Reads::default(), &c), Ok(()));
        // bls_setting 2: the signature is not checked.
        let mut rewarded = pre.clone();
        process_sync_aggregate(&mut rewarded, &one).unwrap();
        rewarded.apply_updates().unwrap();
        let c = case(
            dir.path(),
            "sync_aggregate",
            &files(&one, Some(&rewarded), Some("{bls_setting: 2}\n")),
        );
        assert_eq!(run(&Reads::default(), &c), Ok(()));
        // A setting the format does not define.
        let c = case(
            dir.path(),
            "sync_aggregate",
            &files(&one, None, Some("{bls_setting: 3}\n")),
        );
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("bls_setting"));
    }

    /// The compressed G1 generator: the public key of the secret key 1.
    const PUBKEY_1: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    /// sha256 of the 48 bytes of [`PUBKEY_1`], from Python's hashlib.
    const PUBKEY_1_SHA256: &str =
        "7ccf478a431837728dcec3461f4f53b8749cdc4e03496dcaed459dea82b82eb8";

    fn pubkey_1() -> [u8; 48] {
        hex::decode(PUBKEY_1).unwrap().try_into().unwrap()
    }

    /// The signature of the secret key 1 over `root`.
    fn sign_1(root: Root) -> [u8; 96] {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        crypto_bls::sign(&secret, root.as_slice())
            .unwrap()
            .to_bytes()
    }

    /// The minimal Gloas fork version (`configs/minimal.yaml` `GLOAS_FORK_VERSION`).
    const GLOAS_FORK_VERSION: Version = [0x07, 0x00, 0x00, 0x01];

    /// [`pre`] in epoch 64 (`SHARD_COMMITTEE_PERIOD` of the minimal preset) at the Gloas
    /// fork, with a genesis validators root of `0x42` bytes. Validator 0 has the key
    /// [`PUBKEY_1`] and the BLS withdrawal credentials of that key, so it can exit and change
    /// its credentials.
    fn signing_pre() -> BeaconState<Minimal> {
        let mut pre = pre();
        pre.slot = 64 * 8;
        pre.fork.previous_version = GLOAS_FORK_VERSION;
        pre.fork.current_version = GLOAS_FORK_VERSION;
        pre.genesis_validators_root = Root::repeat_byte(0x42);
        let validator = pre.validators.get_mut(0).unwrap();
        validator.pubkey = pubkey_1();
        validator.withdrawal_credentials =
            Bytes32::from_slice(&hex::decode(PUBKEY_1_SHA256).unwrap());
        validator.withdrawal_credentials[0] = 0x00;
        pre.apply_updates().unwrap();
        pre
    }

    /// The files of a case: `pre`, the operation as `name`, and `post` if the case is valid,
    /// with `meta.yaml` `bls_setting: 1`.
    fn signed_case_files(
        pre: &BeaconState<Minimal>,
        name: &'static str,
        operation: Vec<u8>,
        post: Option<&BeaconState<Minimal>>,
    ) -> Vec<(&'static str, Vec<u8>)> {
        let mut files = vec![
            ("pre.ssz_snappy", snappy(pre.as_ssz_bytes())),
            (name, snappy(operation)),
            ("meta.yaml", b"{bls_setting: 1}\n".to_vec()),
        ];
        if let Some(post) = post {
            files.push(("post.ssz_snappy", snappy(post.as_ssz_bytes())));
        }
        files
    }

    #[test]
    fn exit_domain() {
        let pre = signing_pre();
        let exit = VoluntaryExit {
            epoch: 64,
            validator_index: 0,
        };
        let signed_over = |version: Version| SignedVoluntaryExit {
            message: exit.clone(),
            signature: sign_1(compute_signing_root(
                &exit,
                compute_domain(DOMAIN_VOLUNTARY_EXIT, version, pre.genesis_validators_root),
            )),
        };
        let capella = capella_fork_version("minimal").unwrap();
        let keys = StateKeys::new(&pre);
        // EIP-7044: the domain of an exit has CAPELLA_FORK_VERSION at every later fork.
        let current = signed_over(pre.fork.current_version);
        assert_eq!(
            verify_voluntary_exit_signature(&pre, &current, capella, &keys),
            Err(StfError::InvalidVoluntaryExitSignature)
        );
        let fixed = signed_over(capella);
        assert_eq!(
            verify_voluntary_exit_signature(&pre, &fixed, capella, &keys),
            Ok(())
        );

        // Through the runner: the exit over the current fork domain fails, and the exit over
        // the Capella domain starts the exit of validator 0.
        let dir = tempfile::tempdir().unwrap();
        let name = "voluntary_exit.ssz_snappy";
        let mut post = pre.clone();
        process_voluntary_exit(&mut post, &fixed, &mut TotalActiveBalanceCache::default()).unwrap();
        post.apply_updates().unwrap();
        assert_ne!(post.validators.get(0).unwrap().exit_epoch, FAR_FUTURE_EPOCH);
        for handler in ["voluntary_exit", "voluntary_exit_churn"] {
            let files = signed_case_files(&pre, name, current.as_ssz_bytes(), Some(&post));
            assert!(run(&Reads::default(), &case(dir.path(), handler, &files))
                .unwrap_err()
                .contains("invalid voluntary exit signature"));
            let files = signed_case_files(&pre, name, current.as_ssz_bytes(), None);
            assert_eq!(
                run(&Reads::default(), &case(dir.path(), handler, &files)),
                Ok(())
            );
            let files = signed_case_files(&pre, name, fixed.as_ssz_bytes(), Some(&post));
            let c = case(dir.path(), handler, &files);
            let reads = Reads::default();
            assert_eq!(run(&reads, &c), Ok(()));
            assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        }
    }

    #[test]
    fn bls_change_domain() {
        let pre = signing_pre();
        let change = BLSToExecutionChange {
            validator_index: 0,
            from_bls_pubkey: pubkey_1(),
            to_execution_address: Address::repeat_byte(0xee),
        };
        let signed_over = |version: Version| SignedBLSToExecutionChange {
            message: change.clone(),
            signature: sign_1(compute_signing_root(
                &change,
                compute_domain(
                    DOMAIN_BLS_TO_EXECUTION_CHANGE,
                    version,
                    pre.genesis_validators_root,
                ),
            )),
        };
        let genesis = genesis_fork_version("minimal").unwrap();
        let keys = StateKeys::new(&pre);
        // The domain of a change has GENESIS_FORK_VERSION at every fork.
        let current = signed_over(pre.fork.current_version);
        assert_eq!(
            verify_bls_to_execution_change_signature(&pre, &current, genesis, &keys),
            Err(StfError::InvalidBlsToExecutionChangeSignature)
        );
        let fixed = signed_over(genesis);
        assert_eq!(
            verify_bls_to_execution_change_signature(&pre, &fixed, genesis, &keys),
            Ok(())
        );

        // Through the runner, with the vector name of the operation file.
        let dir = tempfile::tempdir().unwrap();
        let name = "address_change.ssz_snappy";
        let handler = "bls_to_execution_change";
        let mut post = pre.clone();
        process_bls_to_execution_change(&mut post, &fixed).unwrap();
        post.apply_updates().unwrap();
        let files = signed_case_files(&pre, name, current.as_ssz_bytes(), Some(&post));
        assert!(run(&Reads::default(), &case(dir.path(), handler, &files))
            .unwrap_err()
            .contains("invalid BLS-to-execution change signature"));
        let files = signed_case_files(&pre, name, current.as_ssz_bytes(), None);
        assert_eq!(
            run(&Reads::default(), &case(dir.path(), handler, &files)),
            Ok(())
        );
        let files = signed_case_files(&pre, name, fixed.as_ssz_bytes(), Some(&post));
        let c = case(dir.path(), handler, &files);
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        // bls_setting 2: the signature over the current fork domain is not checked.
        let mut files = signed_case_files(&pre, name, current.as_ssz_bytes(), Some(&post));
        files[2].1 = b"{bls_setting: 2}\n".to_vec();
        assert_eq!(
            run(&Reads::default(), &case(dir.path(), handler, &files)),
            Ok(())
        );
    }

    #[test]
    fn exit_without_bls_and_consolidation_cases() {
        let pre = signing_pre();
        let dir = tempfile::tempdir().unwrap();
        // bls_setting 2: an exit with a zero signature is valid.
        let exit = SignedVoluntaryExit {
            message: VoluntaryExit {
                epoch: 0,
                validator_index: 1,
            },
            signature: [0; 96],
        };
        let mut post = pre.clone();
        process_voluntary_exit(&mut post, &exit, &mut TotalActiveBalanceCache::default()).unwrap();
        post.apply_updates().unwrap();
        let mut files = signed_case_files(
            &pre,
            "voluntary_exit.ssz_snappy",
            exit.as_ssz_bytes(),
            Some(&post),
        );
        files[2].1 = b"{bls_setting: 2}\n".to_vec();
        assert_eq!(
            run(
                &Reads::default(),
                &case(dir.path(), "voluntary_exit", &files)
            ),
            Ok(())
        );

        // A consolidation request for a key that no validator has does nothing.
        let request = ConsolidationRequest {
            source_address: Address::ZERO,
            source_pubkey: [0xff; 48],
            target_pubkey: [1; 48],
        };
        let files = [
            ("pre.ssz_snappy", snappy(pre.as_ssz_bytes())),
            (
                "consolidation_request.ssz_snappy",
                snappy(request.as_ssz_bytes()),
            ),
            ("post.ssz_snappy", snappy(pre.as_ssz_bytes())),
        ];
        let c = case(dir.path(), "consolidation_request", &files);
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        // A valid request without a post-state: the vector expects it to fail, but a
        // request never fails.
        let c = case(dir.path(), "consolidation_request", &files[..2]);
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("expects to fail"));
    }

    #[test]
    fn builder_request_cases() {
        use consensus_types::gloas::{BuilderDepositRequest, BuilderExitRequest};
        use consensus_types::primitives::Address;

        let dir = tempfile::tempdir().unwrap();
        let pre = pre();
        let files = |name: &'static str,
                     op: Vec<u8>,
                     post: Option<&BeaconState<Minimal>>,
                     meta: Option<&str>| {
            let mut files = vec![
                ("pre.ssz_snappy", snappy(pre.as_ssz_bytes())),
                (name, snappy(op)),
            ];
            if let Some(post) = post {
                files.push(("post.ssz_snappy", snappy(post.as_ssz_bytes())));
            }
            if let Some(meta) = meta {
                files.push(("meta.yaml", meta.as_bytes().to_vec()));
            }
            files
        };
        // An exit request for a key that no builder has is ignored.
        let exit = BuilderExitRequest {
            source_address: Address::ZERO,
            pubkey: [7; 48],
        };
        let c = case(
            dir.path(),
            "builder_exit_request",
            &files(
                "builder_exit_request.ssz_snappy",
                exit.as_ssz_bytes(),
                Some(&pre),
                None,
            ),
        );
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));

        // A deposit request of a new key whose key does not decode is ignored: the in-process
        // backend gives `Ok(false)` for it, not an error.
        let mut withdrawal_credentials = Bytes32::ZERO;
        withdrawal_credentials[0] = 0xb0;
        let deposit = BuilderDepositRequest {
            pubkey: [7; 48],
            withdrawal_credentials,
            amount: 1_000_000_000,
            signature: [0x22; 96],
        };
        let name = "builder_deposit_request.ssz_snappy";
        let c = case(
            dir.path(),
            "builder_deposit_request",
            &files(
                name,
                deposit.as_ssz_bytes(),
                Some(&pre),
                Some("{bls_setting: 1}\n"),
            ),
        );
        assert_eq!(run(&Reads::default(), &c), Ok(()));
        // With bls_setting 2 the signature is not checked, so the same request registers a
        // builder, and the pre-state is not the post-state.
        let c = case(
            dir.path(),
            "builder_deposit_request",
            &files(
                name,
                deposit.as_ssz_bytes(),
                Some(&pre),
                Some("{bls_setting: 2}\n"),
            ),
        );
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("root mismatch"));
        // The minimal state does not decode as a mainnet one.
        let mut c = c;
        c.key.preset = "mainnet".into();
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("pre.ssz_snappy"));
    }

    #[test]
    fn withdrawals_cases() {
        let dir = tempfile::tempdir().unwrap();
        // Validator 1 of `pre` can withdraw its full balance, and the parent of `pre` is FULL.
        let mut pre = pre();
        let validator = pre.validators.get_mut(1).unwrap();
        validator.withdrawal_credentials[0] = 0x01;
        validator.withdrawable_epoch = 0;
        pre.apply_updates().unwrap();
        let mut post = pre.clone();
        process_withdrawals(&mut post).unwrap();
        post.apply_updates().unwrap();
        assert_eq!(*post.balances.get(1).unwrap(), 0);
        // The cases have no operation file.
        let files = |pre: &BeaconState<Minimal>, post: Option<&BeaconState<Minimal>>| {
            let mut files = vec![("pre.ssz_snappy", snappy(pre.as_ssz_bytes()))];
            if let Some(post) = post {
                files.push(("post.ssz_snappy", snappy(post.as_ssz_bytes())));
            }
            files
        };
        let c = case(dir.path(), "withdrawals", &files(&pre, Some(&post)));
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));

        // The pre-state is not the post-state.
        let c = case(dir.path(), "withdrawals", &files(&pre, Some(&pre)));
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("root mismatch"));
        // A valid pre-state that the vector expects to fail.
        let c = case(dir.path(), "withdrawals", &files(&pre, None));
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("expects to fail"));
        // A sweep cursor past the registry: the case expects the `IndexError` of the pyspec
        // on `state.validators`.
        let mut bad = pre.clone();
        bad.next_withdrawal_validator_index = 2;
        let named = |files: &[(&str, Vec<u8>)], name: &str| {
            let mut c = case(dir.path(), "withdrawals", files);
            c.key.case = format!("pyspec_tests/{name}");
            c
        };
        let c = named(&files(&bad, None), "invalid_validator_index_sweep");
        assert_eq!(run(&Reads::default(), &c), Ok(()));
        let c = named(&files(&bad, Some(&post)), "invalid_validator_index_sweep");
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("operation failed"));
        // The same error under a case name that gives no expected list fails.
        let c = case(dir.path(), "withdrawals", &files(&bad, None));
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("gives no expected index error"));

        // Only the index error of the list that the case name gives passes a case without a
        // post-state. A proof error does not, and neither does another fault of our state.
        let index = |list: &'static str| StfError::ListIndexOutOfRange { list, index: 8 };
        let check = |name: &str, outcome: Result<(), StfError>| {
            let mut c = case(dir.path(), "withdrawals", &[]);
            c.key.case = format!("pyspec_tests/{name}");
            expect_state_only(&c, &mut pre.clone(), outcome, None)
        };
        for name in [
            "invalid_builder_index_pending",
            "invalid_builder_index_sweep",
        ] {
            assert_eq!(check(name, Err(index("builders"))), Ok(()), "{name}");
            let err = check(name, Err(index("validators"))).unwrap_err();
            assert!(err.contains("`builders`"), "{err}");
        }
        for name in [
            "invalid_validator_index_pending_partial",
            "invalid_validator_index_sweep",
        ] {
            assert_eq!(check(name, Err(index("validators"))), Ok(()), "{name}");
            for wrong in [
                Err(index("builders")),
                Err(index("balances")),
                Err(StfError::ArithmeticOverflow),
                Err(StfError::StateArithmetic {
                    what: "withdrawal index",
                }),
                Err(StfError::Unimplemented("x")),
            ] {
                let err = check(name, wrong).unwrap_err();
                assert!(err.contains("`validators`"), "{err}");
            }
            // A pre-state that passes is still an error.
            assert!(check(name, Ok(())).unwrap_err().contains("expects to fail"));
        }
    }

    /// A `config.yaml` as the pyspec writes it: the keys that the runner checks, and keys
    /// that it does not compare.
    fn config(preset: &str, version: &str) -> String {
        format!(
            "PRESET_BASE: '{preset}'\nGENESIS_FORK_VERSION: {version}\n\
             GLOAS_FORK_EPOCH: 0\nSHARD_COMMITTEE_PERIOD: 64\n"
        )
    }

    #[test]
    fn payload_attestation_cases() {
        use consensus_types::gloas::{PayloadAttestation, PayloadAttestationData};
        use consensus_types::primitives::Root;

        let dir = tempfile::tempdir().unwrap();
        let pre = pre();
        // The previous slot and the parent root of `pre`, with the first PTC position: the
        // PTC window of `pre` is zero, so the attester is validator 0.
        let mut attestation = PayloadAttestation::<Minimal> {
            aggregation_bits: Default::default(),
            data: PayloadAttestationData {
                beacon_block_root: Root::ZERO,
                slot: 1,
                payload_present: true,
                blob_data_available: true,
            },
            signature: [0x22; 96],
        };
        attestation.aggregation_bits.set(0, true).unwrap();
        let files = |attestation: &PayloadAttestation<Minimal>,
                     post: Option<&BeaconState<Minimal>>,
                     meta: Option<&str>,
                     config: Option<String>| {
            let mut files = vec![
                ("pre.ssz_snappy", snappy(pre.as_ssz_bytes())),
                (
                    "payload_attestation.ssz_snappy",
                    snappy(attestation.as_ssz_bytes()),
                ),
            ];
            if let Some(post) = post {
                files.push(("post.ssz_snappy", snappy(post.as_ssz_bytes())));
            }
            if let Some(meta) = meta {
                files.push(("meta.yaml", meta.as_bytes().to_vec()));
            }
            if let Some(config) = config {
                files.push(("config.yaml", config.into_bytes()));
            }
            files
        };
        let minimal = || Some(config("minimal", "0x00000001"));

        // The key of validator 0 does not decode, so the signature is invalid.
        let c = case(
            dir.path(),
            "payload_attestation",
            &files(&attestation, None, Some("{bls_setting: 1}\n"), minimal()),
        );
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        let c = case(
            dir.path(),
            "payload_attestation",
            &files(&attestation, Some(&pre), None, minimal()),
        );
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("invalid payload attestation signature"));
        // bls_setting 2: the signature is not checked, and the state does not change.
        let c = case(
            dir.path(),
            "payload_attestation",
            &files(&attestation, Some(&pre), Some("{bls_setting: 2}\n"), None),
        );
        assert_eq!(run(&Reads::default(), &c), Ok(()));
        // The asserts that need no BLS run with bls_setting 2 too.
        let mut late = attestation.clone();
        late.data.slot = 2;
        let c = case(
            dir.path(),
            "payload_attestation",
            &files(&late, None, Some("{bls_setting: 2}\n"), None),
        );
        assert_eq!(run(&Reads::default(), &c), Ok(()));

        // A config that the runner does not agree with fails the case.
        for (config, want) in [
            (config("mainnet", "0x00000001"), "PRESET_BASE"),
            (config("minimal", "0x00000000"), "GENESIS_FORK_VERSION"),
            (config("minimal", "0x100000001"), "GENESIS_FORK_VERSION"),
            ("PRESET_BASE: 'minimal'\n".into(), "GENESIS_FORK_VERSION"),
            (": :\n- [".into(), "config.yaml"),
        ] {
            let c = case(
                dir.path(),
                "payload_attestation",
                &files(&attestation, None, Some("{bls_setting: 2}\n"), Some(config)),
            );
            let err = run(&Reads::default(), &c).unwrap_err();
            assert!(err.contains(want), "{want}: {err}");
        }
    }

    #[test]
    fn malformed_cases_fail() {
        let dir = tempfile::tempdir().unwrap();
        let pre = pre();
        let c = case(
            dir.path(),
            "block_header",
            &[("pre.ssz_snappy", snappy(pre.as_ssz_bytes()))],
        );
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("no block.ssz_snappy"));
        let c = case(
            dir.path(),
            "parent_execution_payload",
            &[("pre.ssz_snappy", snappy(pre.as_ssz_bytes()))],
        );
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("no runner for operations/parent_execution_payload"));
        let c = case(
            dir.path(),
            "builder_exit_request",
            &[("pre.ssz_snappy", snappy(pre.as_ssz_bytes()))],
        );
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("no builder_exit_request.ssz_snappy"));
        let mut c = case(
            dir.path(),
            "block_header",
            &[("pre.ssz_snappy", b"not snappy".to_vec())],
        );
        assert!(run(&Reads::default(), &c).unwrap_err().contains("snappy"));
        c.key.preset = "general".into();
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("no operations runner"));
        c.key.preset = "mainnet".into();
        let c = Case {
            files: case(
                dir.path(),
                "block_header",
                &[("pre.ssz_snappy", snappy(pre.as_ssz_bytes()))],
            )
            .files,
            ..c
        };
        // A minimal state does not decode as a mainnet one.
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("pre.ssz_snappy"));
        let c = case(dir.path(), "block_header", &[]);
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("no pre.ssz_snappy"));
        // A post-state of an error that is not a spec failure.
        let mut s = pre.clone();
        assert!(expect(&mut s, Err(StfError::Unimplemented("x")), None)
            .unwrap_err()
            .contains("not a spec failure"));
    }

    /// The files of a case of one operation, with an optional post-state and `meta.yaml`.
    fn op_files(
        pre: &BeaconState<Minimal>,
        name: &'static str,
        op: Vec<u8>,
        post: Option<&BeaconState<Minimal>>,
        meta: Option<&str>,
    ) -> Vec<(&'static str, Vec<u8>)> {
        let mut files = vec![
            ("pre.ssz_snappy", snappy(pre.as_ssz_bytes())),
            (name, snappy(op)),
        ];
        if let Some(post) = post {
            files.push(("post.ssz_snappy", snappy(post.as_ssz_bytes())));
        }
        if let Some(meta) = meta {
            files.push(("meta.yaml", meta.as_bytes().to_vec()));
        }
        files
    }

    fn header(body: u8) -> consensus_types::common::SignedBeaconBlockHeader {
        use consensus_types::common::{BeaconBlockHeader, SignedBeaconBlockHeader};
        use consensus_types::primitives::Root;
        SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: 1,
                proposer_index: 1,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body_root: Root::repeat_byte(body),
            },
            signature: [body; 96],
        }
    }

    #[test]
    fn proposer_slashing_cases() {
        let dir = tempfile::tempdir().unwrap();
        let pre = pre();
        let slashing = ProposerSlashing {
            signed_header_1: header(1),
            signed_header_2: header(2),
        };
        let name = "proposer_slashing.ssz_snappy";
        // bls_setting 2: the signatures are not checked, and validator 1 is slashed.
        let mut post = pre.clone();
        process_proposer_slashing(&mut post, &slashing).unwrap();
        post.apply_updates().unwrap();
        assert!(post.validators.get(1).unwrap().slashed);
        let files = op_files(
            &pre,
            name,
            slashing.as_ssz_bytes(),
            Some(&post),
            Some("{bls_setting: 2}\n"),
        );
        let c = case(dir.path(), "proposer_slashing", &files);
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        // With the check, the key `[1; 48]` does not decode, so the signatures are invalid.
        let files = op_files(&pre, name, slashing.as_ssz_bytes(), None, None);
        let c = case(dir.path(), "proposer_slashing", &files);
        assert_eq!(run(&Reads::default(), &c), Ok(()));
        let files = op_files(&pre, name, slashing.as_ssz_bytes(), Some(&post), None);
        let c = case(dir.path(), "proposer_slashing", &files);
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("invalid operation signature"));
    }

    #[test]
    fn attester_slashing_cases() {
        use consensus_types::common::Checkpoint;
        use consensus_types::gloas::IndexedAttestation;
        use consensus_types::primitives::Root;

        let dir = tempfile::tempdir().unwrap();
        let pre = pre();
        let data = |root: u8| AttestationData {
            slot: 0,
            index: 0,
            beacon_block_root: Root::repeat_byte(root),
            source: Checkpoint {
                epoch: 0,
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: 0,
                root: Root::ZERO,
            },
        };
        let indexed = |indices: Vec<u64>, root: u8| IndexedAttestation::<Mainnet> {
            attesting_indices: indices.try_into().unwrap(),
            data: data(root),
            signature: [root; 96],
        };
        let name = "attester_slashing.ssz_snappy";
        // A double vote of validator 1, with bls_setting 2.
        let slashing = AttesterSlashing::<Mainnet> {
            attestation_1: indexed(vec![1], 1),
            attestation_2: indexed(vec![1], 2),
        };
        let minimal =
            AttesterSlashing::<Minimal>::from_ssz_bytes(&slashing.as_ssz_bytes()).unwrap();
        let mut post = pre.clone();
        process_attester_slashing(&mut post, &minimal).unwrap();
        post.apply_updates().unwrap();
        let files = op_files(
            &pre,
            name,
            slashing.as_ssz_bytes(),
            Some(&post),
            Some("{bls_setting: 2}\n"),
        );
        let c = case(dir.path(), "attester_slashing", &files);
        assert_eq!(run(&Reads::default(), &c), Ok(()));
        // With the check, the key of validator 1 does not decode.
        let files = op_files(&pre, name, slashing.as_ssz_bytes(), None, None);
        assert_eq!(
            run(
                &Reads::default(),
                &case(dir.path(), "attester_slashing", &files)
            ),
            Ok(())
        );

        // More indices than the minimal bound (8192): the verdict of the bound check of
        // `is_valid_indexed_attestation`, which the vector expects to fail.
        let too_many = AttesterSlashing::<Mainnet> {
            attestation_1: indexed((0..8193).collect(), 1),
            attestation_2: indexed(vec![1], 2),
        };
        let files = op_files(&pre, name, too_many.as_ssz_bytes(), None, None);
        let c = case(dir.path(), "attester_slashing", &files);
        assert_eq!(run(&Reads::default(), &c), Ok(()));
        let path = &c.files[1].path;
        assert_eq!(
            attester_slashing::<Minimal>(&Reads::default(), path),
            Ok(Err(StfError::InvalidIndexedAttestation))
        );
        // Bytes that are not an attester slashing at all are a failure of the case.
        let files = op_files(&pre, name, vec![1, 2, 3], None, None);
        let c = case(dir.path(), "attester_slashing", &files);
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("attester_slashing.ssz_snappy"));
        // An attestation in the bound that does not decode for another reason (an offset
        // past the end) is also a failure.
        let mut bytes = slashing.as_ssz_bytes();
        bytes[0] = 0xff;
        let files = op_files(&pre, name, bytes, None, None);
        let c = case(dir.path(), "attester_slashing", &files);
        assert!(run(&Reads::default(), &c).is_err());
    }

    #[test]
    fn attestation_cases() {
        use consensus_types::common::Checkpoint;
        use consensus_types::primitives::Root;
        use ssz::{BitVector, ProgressiveBitList};

        let dir = tempfile::tempdir().unwrap();
        let pre = pre();
        let attestation = Attestation::<Minimal> {
            aggregation_bits: ProgressiveBitList::with_capacity(1),
            data: AttestationData {
                slot: 0,
                index: 2,
                beacon_block_root: Root::ZERO,
                source: Checkpoint {
                    epoch: 0,
                    root: Root::ZERO,
                },
                target: Checkpoint {
                    epoch: 0,
                    root: Root::ZERO,
                },
            },
            signature: [0; 96],
            committee_bits: BitVector::new(),
        };
        let name = "attestation.ssz_snappy";
        // `data.index` 2 fails in both modes, with or without `parent_slot`.
        for meta in [
            None,
            Some("{parent_slot: 1}\n"),
            Some("{parent_slot: 1, bls_setting: 2}\n"),
            Some("{bls_setting: 1}\n"),
        ] {
            let files = op_files(&pre, name, attestation.as_ssz_bytes(), None, meta);
            let c = case(dir.path(), "attestation", &files);
            let reads = Reads::default();
            assert_eq!(run(&reads, &c), Ok(()), "{meta:?}");
            assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        }
        // A `parent_slot` that is not a slot.
        for meta in ["{parent_slot: x}\n", "{parent_slot: -1}\n"] {
            let files = op_files(&pre, name, attestation.as_ssz_bytes(), None, Some(meta));
            let c = case(dir.path(), "attestation", &files);
            assert!(run(&Reads::default(), &c)
                .unwrap_err()
                .contains("parent_slot"));
        }
    }
}
