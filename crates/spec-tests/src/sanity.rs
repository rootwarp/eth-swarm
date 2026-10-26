//! consensus-spec-tests `tests/<preset>/gloas/sanity/<handler>/pyspec_tests/<case>/`: the
//! `slots` handler through `state_transition::per_slot::process_slots`, and the `blocks`
//! handler through `state_transition::state_transition`.
//!
//! A `slots` case holds `pre.ssz_snappy`, `slots.yaml` (the number of slots to process),
//! `post.ssz_snappy` and `manifest.yaml`. The check is `process_slots(pre, pre.slot + slots)`
//! and then `hash_tree_root` against the post-state. A case without `post.ssz_snappy` must
//! fail with an error that proves the input invalid (`StfError::proves_invalid`).
//!
//! A `blocks` case holds `pre.ssz_snappy`, `meta.yaml` with `blocks_count` and an optional
//! `bls_setting`, the blocks `blocks_<i>.ssz_snappy` for `i` in `0..blocks_count`, and
//! `post.ssz_snappy` if the blocks are valid. [`run_blocks`] applies each block in sequence
//! with `state_transition(state, block, validate_result = true)` and the in-process BLS
//! backend, and then compares `hash_tree_root` with the post-state. On a mismatch, the error
//! names the top-level fields that differ. It does so also when the last block fails with
//! `StateRootMismatch` in a case with a post-state. A case without a post-state must apply
//! each block but the last, and the last block must fail: it does not decode, or its
//! transition fails with a proof error. Some cases also hold `config.yaml`, which
//! [`check_same_config`] compares with the config values of the transition.
//!
//! For each block of a `blocks` case, the runner also checks the signature sets of the block
//! in one batch and each set alone ([`batch_matches_single`]). The two verdicts must agree.
//! cl-verify gets the same batch shape. The `finality` runner ([`crate::finality`]) applies
//! its blocks with [`run_blocks`] too.

use crate::bls_backend::{backend_for, bls_context, bls_setting, BatchKeys, Bls, StateKeys};
use crate::check::state_field_diff;
use crate::config::check_same_config;
use crate::coverage::Reads;
use crate::fixture;
use crate::plan::Case;
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::{Mainnet, Minimal};
use ssz::Decode;
use state_transition::per_slot::process_slots;
use state_transition::signatures::{block_signature_sets, verify_block_signatures};
use state_transition::{state_root, state_transition, Preset, StfError};
use std::fmt;
use std::path::Path;
use tree_hash::TreeHash;
use yaml_rust2::Yaml;

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    fork == "gloas"
        && matches!(handler, "slots" | "blocks")
        && matches!(preset, "minimal" | "mainnet")
}

/// Runs one `slots` or `blocks` case. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    match (case.key.handler.as_str(), case.key.preset.as_str()) {
        ("slots", "minimal") => slots::<Minimal>(reads, case),
        ("slots", "mainnet") => slots::<Mainnet>(reads, case),
        ("blocks", _) => run_blocks(reads, case, BatchCheck::Compare),
        (handler, preset) => Err(format!("no sanity runner for {handler} of preset {preset}")),
    }
}

/// Whether [`run_blocks`] also compares the batch verdict of the signature sets of each block
/// with the per-set verdict ([`batch_matches_single`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchCheck {
    /// Compare the two verdicts for each block. Each block then costs its BLS checks three
    /// times.
    Compare,
    /// Apply the blocks only.
    Skip,
}

/// Runs a case of blocks: `pre.ssz_snappy`, `meta.yaml` with `blocks_count`, the blocks
/// `blocks_<i>.ssz_snappy` and an optional `post.ssz_snappy` (see the module docs). The
/// `sanity/blocks` and `finality` runners use it.
pub fn run_blocks(reads: &Reads, case: &Case, check: BatchCheck) -> Result<(), String> {
    match case.key.preset.as_str() {
        "minimal" => blocks::<Minimal>(reads, case, check),
        "mainnet" => blocks::<Mainnet>(reads, case, check),
        other => Err(format!("no blocks runner for preset {other}")),
    }
}

fn slots<E: Preset>(reads: &Reads, case: &Case) -> Result<(), String> {
    let file = |name: &str| case.file(name).ok_or_else(|| format!("case has no {name}"));
    let mut state = decode_state::<E>(reads, file("pre.ssz_snappy")?)?;
    let doc = fixture::load(reads, file("slots.yaml")?)?;
    let slots = doc
        .as_i64()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| format!("slots.yaml: expected an unsigned integer, got {doc:?}"))?;
    let post = case
        .file("post.ssz_snappy")
        .map(|p| decode_state::<E>(reads, p))
        .transpose()?;
    let target = state
        .slot
        .checked_add(slots)
        .ok_or("pre.slot + slots overflows")?;
    // The slots check no block signature: only the deposit verdicts of the epoch steps,
    // whose keys are inline.
    let keys = StateKeys::new(&state);
    let bls = bls_context(&case.key.preset, &keys)?;
    match (process_slots(&mut state, target, &bls), post) {
        (Ok(()), Some(post)) => {
            let got = state_root(&mut state).map_err(|e| format!("post-state root: {e}"))?;
            let want = post.tree_hash_root();
            if got == want {
                Ok(())
            } else {
                Err(format!(
                    "post-state root mismatch: got {got:x}, want {want:x} (slot {}, want {})",
                    state.slot, post.slot
                ))
            }
        }
        (Err(e), None) if e.proves_invalid() => Ok(()),
        (Err(e), None) => Err(format!(
            "process_slots failed with {e}, which is not a spec failure"
        )),
        (Ok(()), None) => Err("processed slots the vector expects to fail".into()),
        (Err(e), Some(_)) => Err(format!("process_slots failed: {e}")),
    }
}

/// Why a block of a case did not apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockFailure {
    /// The block does not decode as a `SignedBeaconBlock`. The spec rejects it.
    Decode(String),
    /// `state_transition` failed.
    Transition(StfError),
    /// A failure of the runner, for example two verdicts that do not agree. It always fails
    /// the case.
    Runner(String),
}

impl fmt::Display for BlockFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "does not decode: {e}"),
            Self::Transition(e) => write!(f, "state_transition failed with {e}"),
            Self::Runner(e) => f.write_str(e),
        }
    }
}

fn blocks<E: Preset>(reads: &Reads, case: &Case, check: BatchCheck) -> Result<(), String> {
    let file = |name: &str| case.file(name).ok_or_else(|| format!("case has no {name}"));
    let mut state = decode_state::<E>(reads, file("pre.ssz_snappy")?)?;
    let count = blocks_count(reads, case)?;
    let setting = bls_setting(reads, case)?;
    let post = case
        .file("post.ssz_snappy")
        .map(|p| decode_state::<E>(reads, p))
        .transpose()?;
    check_same_config::<E>(reads, case, state.fork.epoch)?;
    // Read every block first: a block that does not decode is a verdict, not a runner error.
    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let bytes = fixture::ssz_snappy(reads, file(&format!("blocks_{i}.ssz_snappy"))?)?;
        blocks.push(
            SignedBeaconBlock::<E>::from_ssz_bytes(&bytes)
                .map_err(|e| BlockFailure::Decode(format!("{e:?}"))),
        );
    }
    let preset = &case.key.preset;
    let failure = blocks.into_iter().enumerate().find_map(|(i, block)| {
        block
            .and_then(|block| apply_block(&mut state, &block, preset, setting, check))
            .err()
            .map(|e| (i, e))
    });
    expect_blocks(case, count, failure, &mut state, post)
}

/// `meta.yaml` of a case of blocks: `blocks_count`. A `reveal_deadlines_setting` other than
/// 0 fails the case: no Gloas vector at v1.7.0-beta.4 sets one.
fn blocks_count(reads: &Reads, case: &Case) -> Result<usize, String> {
    let path = case.file("meta.yaml").ok_or("case has no meta.yaml")?;
    let meta = fixture::load(reads, path)?;
    match &meta["reveal_deadlines_setting"] {
        Yaml::BadValue | Yaml::Integer(0) => {}
        other => {
            return Err(format!(
                "meta.yaml: unknown reveal_deadlines_setting {other:?}"
            ))
        }
    }
    let count = &meta["blocks_count"];
    count
        .as_i64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| format!("meta.yaml: blocks_count is {count:?}"))
}

/// Applies one block with `state_transition(state, block, validate_result = true)`.
///
/// The backend takes the keys of the state at the block's slot: an epoch boundary on the way
/// can add validators. With [`BatchCheck::Compare`], [`batch_matches_single`] runs on that
/// state first, with the real BLS checks also for `bls_setting: 2`.
fn apply_block<E: Preset>(
    state: &mut BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    preset: &str,
    setting: Bls,
    check: BatchCheck,
) -> Result<(), BlockFailure> {
    let runner = BlockFailure::Runner;
    let pre_keys = StateKeys::new(state);
    let mut at_slot = state.clone();
    let slot_bls = bls_context(preset, backend_for(setting, &pre_keys)).map_err(runner)?;
    // If the slots fail, `state_transition` fails on them in the same way.
    let advanced = process_slots(&mut at_slot, block.message.slot, &slot_bls).is_ok();
    let keys = if advanced {
        StateKeys::new(&at_slot)
    } else {
        pre_keys
    };
    if advanced && check == BatchCheck::Compare {
        batch_matches_single(&at_slot, block, &keys, preset).map_err(runner)?;
    }
    let bls = bls_context(preset, backend_for(setting, &keys)).map_err(runner)?;
    state_transition(state, block, true, &bls).map_err(BlockFailure::Transition)
}

/// Checks the signature sets of `block` in one batch and each set alone, and fails if the two
/// verdicts differ. `state` is the state at the block's slot.
///
/// The batch is `verify_block_signatures` through [`BatchKeys`] (one
/// `crypto_bls::verify_batch` of all the sets). The single path is `block_signature_sets`,
/// with each set through [`StateKeys::verify_each`]. A block whose sets do not build gives
/// the same error on both paths.
pub fn batch_matches_single<E: Preset>(
    state: &BeaconState<E>,
    block: &SignedBeaconBlock<E>,
    keys: &StateKeys,
    preset: &str,
) -> Result<(), String> {
    let batch_keys = BatchKeys(keys);
    let batch = match verify_block_signatures(state, block, &bls_context(preset, &batch_keys)?) {
        Ok(()) => Ok(true),
        Err(StfError::InvalidBlockSignature) => Ok(false),
        Err(e) => Err(e),
    };
    let single = block_signature_sets(state, block, &bls_context(preset, keys)?)
        .and_then(|sets| keys.verify_each(&sets).map_err(StfError::from));
    if batch == single {
        Ok(())
    } else {
        Err(format!(
            "the batch verdict {batch:?} differs from the per-set verdict {single:?}"
        ))
    }
}

/// Compares the result of the blocks of a case with the vector. `failure` is the first block
/// that did not apply, with its index. The blocks after it did not run.
fn expect_blocks<E: Preset>(
    case: &Case,
    count: usize,
    failure: Option<(usize, BlockFailure)>,
    state: &mut BeaconState<E>,
    post: Option<BeaconState<E>>,
) -> Result<(), String> {
    match (failure, post) {
        (None, Some(post)) => {
            let got = state_root(state).map_err(|e| format!("post-state root: {e}"))?;
            let want = post.tree_hash_root();
            if got == want {
                Ok(())
            } else {
                Err(format!(
                    "post-state root mismatch: got {got:x}, want {want:x}; fields that differ: {}",
                    state_field_diff(state, &post).join(", ")
                ))
            }
        }
        (None, None) => Err(format!(
            "applied all {count} blocks, but the vector expects the last one to fail"
        )),
        // The transition of the last block made a post-state with another root than the
        // block's. `state` holds that post-state, so name its fields that differ from the
        // post-state of the vector.
        (
            Some((i, failure @ BlockFailure::Transition(StfError::StateRootMismatch { .. }))),
            Some(post),
        ) if i + 1 == count => {
            state_root(state).map_err(|e| format!("post-state root: {e}"))?;
            Err(format!(
                "block {i} {failure}; fields that differ: {}",
                state_field_diff(state, &post).join(", ")
            ))
        }
        (Some((i, failure @ BlockFailure::Runner(_))), _) | (Some((i, failure)), Some(_)) => {
            Err(format!("block {i} {failure}"))
        }
        (Some((i, failure)), None) if i + 1 != count => Err(format!(
            "block {i} {failure}, but the vector expects only the last block ({}) to fail",
            count.saturating_sub(1)
        )),
        (Some((i, BlockFailure::Transition(e))), None) if !e.proves_invalid() => Err(format!(
            "block {i}: state_transition failed with {e}, which is not a spec failure"
        )),
        (Some((i, failure)), None) => {
            // Any proof error passes such a case, so print it: a port defect that happens to
            // give a proof error shows in the trial output.
            eprintln!("{}: expected failure: block {i} {failure}", case.key);
            Ok(())
        }
    }
}

/// A `BeaconState` from a `.ssz_snappy` file.
fn decode_state<E: Preset>(reads: &Reads, path: &Path) -> Result<BeaconState<E>, String> {
    let bytes = fixture::ssz_snappy(reads, path)?;
    BeaconState::<E>::from_ssz_bytes(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::tests::config_yaml;
    use crate::plan::{CaseFile, CaseKey};
    use consensus_types::common::PendingConsolidation;
    use consensus_types::gloas::*;
    use consensus_types::primitives::{Address, Root};
    use milhouse::{List, ProgressiveList, Vector};
    use ssz::{BitVector, Encode};
    use ssz_types::FixedVector;

    /// A Gloas minimal state at `slot` with an empty registry: enough for `process_slots`
    /// inside one epoch.
    pub(crate) fn state(slot: u64) -> BeaconState<Minimal> {
        let checkpoint = Checkpoint {
            epoch: 0,
            root: Root::ZERO,
        };
        let sync_committee = SyncCommittee {
            pubkeys: FixedVector::from_elem([0; 48]),
            aggregate_pubkey: [0; 48],
        };
        let withdrawal = BuilderPendingWithdrawal {
            fee_recipient: Address::ZERO,
            amount: 0,
            builder_index: 0,
        };
        BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::ZERO,
            slot,
            fork: Fork {
                previous_version: [0; 4],
                current_version: [0; 4],
                epoch: 0,
            },
            latest_block_header: BeaconBlockHeader {
                slot: 0,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body_root: Root::ZERO,
            },
            block_roots: Vector::default(),
            state_roots: Vector::default(),
            historical_roots: List::default(),
            eth1_data: Eth1Data {
                deposit_root: Root::ZERO,
                deposit_count: 0,
                block_hash: Root::ZERO,
            },
            eth1_data_votes: List::default(),
            eth1_deposit_index: 0,
            validators: ProgressiveList::default(),
            balances: ProgressiveList::default(),
            randao_mixes: Vector::default(),
            slashings: Vector::default(),
            previous_epoch_participation: ProgressiveList::default(),
            current_epoch_participation: ProgressiveList::default(),
            justification_bits: BitVector::new(),
            previous_justified_checkpoint: checkpoint.clone(),
            current_justified_checkpoint: checkpoint.clone(),
            finalized_checkpoint: checkpoint,
            inactivity_scores: ProgressiveList::default(),
            current_sync_committee: sync_committee.clone(),
            next_sync_committee: sync_committee,
            latest_block_hash: Root::ZERO,
            next_withdrawal_index: 0,
            next_withdrawal_validator_index: 0,
            historical_summaries: List::default(),
            deposit_requests_start_index: 0,
            deposit_balance_to_consume: 0,
            exit_balance_to_consume: 0,
            earliest_exit_epoch: 0,
            consolidation_balance_to_consume: 0,
            earliest_consolidation_epoch: 0,
            pending_deposits: ProgressiveList::default(),
            pending_partial_withdrawals: ProgressiveList::default(),
            pending_consolidations: ProgressiveList::default(),
            proposer_lookahead: Vector::default(),
            builders: ProgressiveList::default(),
            next_withdrawal_builder_index: 0,
            execution_payload_availability: BitVector::new(),
            builder_pending_payments: Vector::from_elem(BuilderPendingPayment {
                weight: 0,
                withdrawal,
                proposer_index: 0,
            })
            .unwrap(),
            builder_pending_withdrawals: ProgressiveList::default(),
            latest_execution_payload_bid: ExecutionPayloadBid {
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
            },
            payload_expected_withdrawals: ProgressiveList::default(),
            ptc_window: Vector::default(),
        }
    }

    /// A `slots` case in `dir` of `preset`; `post` is left out when `None`.
    fn case(
        dir: &Path,
        preset: &str,
        pre: Option<&BeaconState<Minimal>>,
        slots: &str,
        post: Option<&BeaconState<Minimal>>,
    ) -> Case {
        let mut files = Vec::new();
        let mut put = |name: &str, bytes: Vec<u8>| {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            files.push(CaseFile {
                path,
                name: name.into(),
            });
        };
        let snappy = |s: &BeaconState<Minimal>| {
            snap::raw::Encoder::new()
                .compress_vec(&s.as_ssz_bytes())
                .unwrap()
        };
        if let Some(pre) = pre {
            put("pre.ssz_snappy", snappy(pre));
        }
        put("slots.yaml", slots.as_bytes().to_vec());
        if let Some(post) = post {
            put("post.ssz_snappy", snappy(post));
        }
        Case {
            key: CaseKey {
                source: "consensus-specs".into(),
                fork: "gloas".into(),
                preset: preset.into(),
                runner: "sanity".into(),
                handler: "slots".into(),
                case: "pyspec_tests/case_0".into(),
            },
            files,
        }
    }

    #[test]
    fn handler_selection() {
        for handler in ["slots", "blocks"] {
            assert!(supported("gloas", "minimal", handler));
            assert!(supported("gloas", "mainnet", handler));
            assert!(!supported("fulu", "minimal", handler));
            assert!(!supported("gloas", "general", handler));
        }
        assert!(!supported("gloas", "minimal", "finality"));
    }

    #[test]
    fn a_matching_post_state_passes_and_every_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state(2);
        let mut post = pre.clone();
        let keys = StateKeys::new(&post);
        process_slots(&mut post, 4, &bls_context("minimal", &keys).unwrap()).unwrap();
        post.apply_updates().unwrap();
        let c = case(dir.path(), "minimal", Some(&pre), "2\n...\n", Some(&post));
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
    }

    #[test]
    fn outcomes_that_differ_from_the_vector_fail() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state(2);
        for (slots, post, needle) in [
            // The pre-state is not the post-state of one more slot.
            ("1", Some(&pre), "root mismatch"),
            // No post-state: the vector expects process_slots to fail.
            ("1", None, "expects to fail"),
            // Slot 8 starts epoch 1, so process_epoch runs. A state without validators has
            // no proposer for the lookahead.
            ("6", Some(&pre), "process_slots failed"),
            ("-1", Some(&pre), "unsigned integer"),
        ] {
            let c = case(dir.path(), "minimal", Some(&pre), slots, post);
            let err = run(&Reads::default(), &c).unwrap_err();
            assert!(err.contains(needle), "{slots}: {err}");
        }
        // A vector without a post-state expects a spec failure, not a fault of our own state:
        // a pending consolidation of a validator outside the registry.
        let mut fault = pre.clone();
        fault
            .pending_consolidations
            .push(PendingConsolidation {
                source_index: 0,
                target_index: 1,
            })
            .unwrap();
        let c = case(dir.path(), "minimal", Some(&fault), "6", None);
        let err = run(&Reads::default(), &c).unwrap_err();
        assert!(err.contains("not a spec failure"), "{err}");
        // Zero slots is rejected by process_slots, as the vector without a post-state expects.
        let c = case(dir.path(), "minimal", Some(&pre), "0", None);
        assert_eq!(run(&Reads::default(), &c), Ok(()));
    }

    #[test]
    fn malformed_cases_fail() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state(2);
        let c = case(dir.path(), "minimal", None, "1", Some(&pre));
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("no pre.ssz_snappy"));
        let c = case(dir.path(), "general", Some(&pre), "1", Some(&pre));
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("no sanity runner"));
        // A minimal state does not decode as a mainnet one.
        let c = case(dir.path(), "mainnet", Some(&pre), "1", None);
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("pre.ssz_snappy"));
        std::fs::write(c.file("pre.ssz_snappy").unwrap(), b"not snappy").unwrap();
        assert!(run(&Reads::default(), &c).unwrap_err().contains("snappy"));
        let c = case(dir.path(), "minimal", Some(&state(u64::MAX - 1)), "2", None);
        assert!(run(&Reads::default(), &c)
            .unwrap_err()
            .contains("overflows"));
    }

    /// A block at `slot` by `proposer` with an empty body: no sync committee bits with the
    /// infinity signature, and a self-build bid. The state root is zero and the signature is
    /// `[0x11; 96]`.
    fn block(slot: u64, proposer: u64) -> SignedBeaconBlock<Minimal> {
        let mut infinity = [0u8; 96];
        infinity[0] = 0xc0;
        let body = BeaconBlockBody {
            randao_reveal: [0; 96],
            eth1_data: Eth1Data {
                deposit_root: Root::ZERO,
                deposit_count: 0,
                block_hash: Root::ZERO,
            },
            graffiti: Root::ZERO,
            proposer_slashings: Default::default(),
            attester_slashings: Default::default(),
            attestations: Default::default(),
            deposits: Default::default(),
            voluntary_exits: Default::default(),
            sync_aggregate: SyncAggregate {
                sync_committee_bits: BitVector::new(),
                sync_committee_signature: infinity,
            },
            bls_to_execution_changes: Default::default(),
            signed_execution_payload_bid: SignedExecutionPayloadBid {
                message: ExecutionPayloadBid {
                    builder_index: u64::MAX,
                    slot,
                    ..state(0).latest_execution_payload_bid
                },
                signature: infinity,
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
        SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                proposer_index: proposer,
                parent_root: Root::ZERO,
                state_root: Root::ZERO,
                body,
            },
            signature: [0x11; 96],
        }
    }

    fn snappy(bytes: Vec<u8>) -> Vec<u8> {
        snap::raw::Encoder::new().compress_vec(&bytes).unwrap()
    }

    /// A minimal case of `runner`/`handler` in a new directory under `dir` with `files`.
    pub(crate) fn blocks_case(
        dir: &Path,
        runner: &str,
        handler: &str,
        files: &[(&str, Vec<u8>)],
    ) -> Case {
        let dir = tempfile::tempdir_in(dir).unwrap().keep();
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
                runner: runner.into(),
                handler: handler.into(),
                case: "pyspec_tests/case_0".into(),
            },
            files,
        }
    }

    /// The files of a `blocks` case: `pre`, `meta.yaml`, the blocks and an optional `post`.
    pub(crate) fn blocks_files(
        pre: &BeaconState<Minimal>,
        meta: &str,
        blocks: &[Vec<u8>],
        post: Option<&BeaconState<Minimal>>,
    ) -> Vec<(String, Vec<u8>)> {
        let mut files = vec![
            ("pre.ssz_snappy".to_owned(), snappy(pre.as_ssz_bytes())),
            ("meta.yaml".to_owned(), meta.as_bytes().to_vec()),
        ];
        for (i, bytes) in blocks.iter().enumerate() {
            files.push((format!("blocks_{i}.ssz_snappy"), snappy(bytes.clone())));
        }
        if let Some(post) = post {
            files.push(("post.ssz_snappy".to_owned(), snappy(post.as_ssz_bytes())));
        }
        files
    }

    fn run_files(dir: &Path, files: &[(String, Vec<u8>)]) -> (Case, Result<(), String>) {
        let named: Vec<(&str, Vec<u8>)> =
            files.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
        let c = blocks_case(dir, "sanity", "blocks", &named);
        let result = run(&Reads::default(), &c);
        (c, result)
    }

    /// A minimal `config.yaml` with one line changed by `replace`.
    fn config(replace: Option<(&str, &str)>) -> Vec<u8> {
        let replace: Vec<(&str, Option<&str>)> =
            replace.into_iter().map(|(n, v)| (n, Some(v))).collect();
        config_yaml::<Minimal>("minimal", &replace).into_bytes()
    }

    #[test]
    fn block_outcomes() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state(2);
        let ssz = |b: &SignedBeaconBlock<Minimal>| b.as_ssz_bytes();
        // No blocks: the post-state is the pre-state, and every file is read.
        let (c, result) = run_files(
            dir.path(),
            &blocks_files(&pre, "{blocks_count: 0}", &[], Some(&pre)),
        );
        assert_eq!(result, Ok(()));
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        for (meta, blocks, post, needle) in [
            // Another post-state names the fields that differ.
            (
                "{blocks_count: 0}",
                vec![],
                Some(state(3)),
                "fields that differ: slot",
            ),
            (
                "{blocks_count: 0}",
                vec![],
                None,
                "expects the last one to fail",
            ),
            // A block of the state's slot proves the case invalid only without a post-state.
            (
                "{blocks_count: 1}",
                vec![ssz(&block(2, 0))],
                Some(pre.clone()),
                "block 0 state_transition failed",
            ),
            // A state without validators has no proposer: a fault of our own state.
            (
                "{blocks_count: 1}",
                vec![ssz(&block(3, 0))],
                None,
                "not a spec failure",
            ),
            // Only the last block may fail.
            (
                "{blocks_count: 2}",
                vec![ssz(&block(2, 0)), ssz(&block(3, 0))],
                None,
                "only the last block (1)",
            ),
            (
                "{blocks_count: 1}",
                vec![vec![1, 2, 3]],
                Some(pre.clone()),
                "does not decode",
            ),
            ("{blocks_count: 1}", vec![], None, "no blocks_0.ssz_snappy"),
            ("{blocks_count: -1}", vec![], None, "blocks_count"),
            (
                "{blocks_count: 0, reveal_deadlines_setting: 1}",
                vec![],
                None,
                "reveal_deadlines_setting",
            ),
            (
                "{blocks_count: 0, bls_setting: 3}",
                vec![],
                None,
                "bls_setting",
            ),
        ] {
            let (_, result) = run_files(
                dir.path(),
                &blocks_files(&pre, meta, &blocks, post.as_ref()),
            );
            let err = result.unwrap_err();
            assert!(err.contains(needle), "{needle}: {err}");
        }
        // The last block fails as the vector expects: it does not decode, or its
        // transition fails with a proof error.
        for (meta, blocks) in [
            ("{blocks_count: 1}", vec![vec![1, 2, 3]]),
            ("{blocks_count: 1, bls_setting: 2}", vec![ssz(&block(2, 0))]),
        ] {
            let (_, result) = run_files(dir.path(), &blocks_files(&pre, meta, &blocks, None));
            assert_eq!(result, Ok(()), "{meta}");
        }
        // A runner failure fails also a case that expects a failed block.
        let c = blocks_case(dir.path(), "sanity", "blocks", &[]);
        let failure = Some((0, BlockFailure::Runner("verdicts differ".into())));
        let err = expect_blocks(&c, 1, failure, &mut pre.clone(), None).unwrap_err();
        assert!(err.contains("verdicts differ"), "{err}");
    }

    /// One block whose state root does not agree with the post-state that the transition
    /// makes: the error names the fields that differ from the post-state of the vector.
    #[test]
    fn a_state_root_mismatch_names_the_fields_that_differ() {
        let dir = tempfile::tempdir().unwrap();
        let c = blocks_case(dir.path(), "sanity", "blocks", &[]);
        let mismatch = StfError::StateRootMismatch {
            block: Root::ZERO,
            computed: Root::repeat_byte(1),
        };
        let failure = Some((0, BlockFailure::Transition(mismatch.clone())));
        let err = expect_blocks(&c, 1, failure, &mut state(2), Some(state(3))).unwrap_err();
        assert!(err.contains("block 0 state_transition failed"), "{err}");
        assert!(err.ends_with("fields that differ: slot"), "{err}");
        // A mismatch of a block before the last one is not compared with the post-state.
        let failure = Some((0, BlockFailure::Transition(mismatch)));
        let err = expect_blocks(&c, 2, failure, &mut state(2), Some(state(3))).unwrap_err();
        assert!(!err.contains("fields that differ"), "{err}");
    }

    #[test]
    fn malformed_block_cases_fail() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state(2);
        let mut files = blocks_files(&pre, "{blocks_count: 0}", &[], Some(&pre));
        files.retain(|(name, _)| name != "meta.yaml");
        let err = run_files(dir.path(), &files).1.unwrap_err();
        assert!(err.contains("no meta.yaml"), "{err}");
        let err = run_files(dir.path(), &files[1..]).1.unwrap_err();
        assert!(err.contains("no pre.ssz_snappy"), "{err}");
        // A preset without a runner.
        let files = blocks_files(&pre, "{blocks_count: 0}", &[], Some(&pre));
        let named: Vec<(&str, Vec<u8>)> =
            files.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
        let mut c = blocks_case(dir.path(), "sanity", "blocks", &named);
        c.key.preset = "general".into();
        let err = run(&Reads::default(), &c).unwrap_err();
        assert!(err.contains("no blocks runner"), "{err}");
        // A block file that is not snappy is a runner error, not an invalid block.
        let mut files = blocks_files(&pre, "{blocks_count: 1}", &[vec![0]], None);
        files[2].1 = b"not snappy".to_vec();
        let err = run_files(dir.path(), &files).1.unwrap_err();
        assert!(err.contains("snappy"), "{err}");
    }

    #[test]
    fn config_of_a_block_case() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state(2);
        let with = |config: Vec<u8>| {
            let mut files = blocks_files(&pre, "{blocks_count: 0}", &[], Some(&pre));
            files.push(("config.yaml".to_owned(), config));
            run_files(dir.path(), &files).1
        };
        assert_eq!(with(config(None)), Ok(()));
        for (replace, needle) in [
            (("GLOAS_FORK_EPOCH", "1"), "GLOAS_FORK_EPOCH"),
            (
                ("CAPELLA_FORK_VERSION", "0x03000000"),
                "CAPELLA_FORK_VERSION",
            ),
            (("SHARD_COMMITTEE_PERIOD", "256"), "SHARD_COMMITTEE_PERIOD"),
            (
                ("GENESIS_FORK_VERSION", "0x00000000"),
                "GENESIS_FORK_VERSION",
            ),
            (("PRESET_BASE", "'mainnet'"), "PRESET_BASE"),
        ] {
            let err = with(config(Some(replace))).unwrap_err();
            assert!(err.contains(needle), "{needle}: {err}");
        }
        let err = with(b"PRESET_BASE: 'minimal'\n".to_vec()).unwrap_err();
        assert!(err.contains("missing"), "{err}");
        let err = with(b"GLOAS_FORK_EPOCH: 0\n".to_vec()).unwrap_err();
        assert!(err.contains("PRESET_BASE"), "{err}");
    }

    #[test]
    fn batch_matches_single() {
        use crate::bls_backend::tests::{secret, PUBKEY_1};
        use crypto_bls::sign;

        // One validator with the key of the secret key 1: the proposer of every slot.
        let mut st = state(1);
        let pubkey: [u8; 48] = hex::decode(PUBKEY_1).unwrap().try_into().unwrap();
        st.validators
            .push(Validator {
                pubkey,
                withdrawal_credentials: Root::ZERO,
                effective_balance: 32_000_000_000,
                slashed: false,
                activation_eligibility_epoch: 0,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
                withdrawable_epoch: u64::MAX,
            })
            .unwrap();
        st.balances.push(32_000_000_000).unwrap();
        st.apply_updates().unwrap();
        let keys = StateKeys::new(&st);
        let bls = bls_context("minimal", &keys).unwrap();
        let sign_with = |n: u8, root: Root| sign(&secret(n), root.as_slice()).unwrap().to_bytes();
        // The RANDAO reveal first: it is in the block root that the proposer signs.
        let mut blk = block(1, 0);
        let sets = block_signature_sets(&st, &blk, &bls).unwrap();
        blk.message.body.randao_reveal = sign_with(1, sets[1].signing_root());
        let sets = block_signature_sets(&st, &blk, &bls).unwrap();
        blk.signature = sign_with(1, sets[0].signing_root());
        // The proposer and the RANDAO sets, both valid.
        let sets = block_signature_sets(&st, &blk, &bls).unwrap();
        assert_eq!(sets.len(), 2);
        assert_eq!(keys.verify_each(&sets), Ok(true));
        assert_eq!(
            super::batch_matches_single(&st, &blk, &keys, "minimal"),
            Ok(())
        );
        // A wrong proposer signature: both verdicts are invalid.
        let mut wrong = blk.clone();
        wrong.signature = sign_with(2, sets[0].signing_root());
        let sets = block_signature_sets(&st, &wrong, &bls).unwrap();
        assert_eq!(keys.verify_each(&sets), Ok(false));
        assert_eq!(
            super::batch_matches_single(&st, &wrong, &keys, "minimal"),
            Ok(())
        );
        // Without validators, the sets do not build, with the same error on both paths.
        let empty = state(1);
        let none = StateKeys::new(&empty);
        assert!(
            block_signature_sets(&empty, &blk, &bls_context("minimal", &none).unwrap()).is_err()
        );
        assert_eq!(
            super::batch_matches_single(&empty, &blk, &none, "minimal"),
            Ok(())
        );
        assert!(super::batch_matches_single(&st, &blk, &keys, "general").is_err());
    }
}
