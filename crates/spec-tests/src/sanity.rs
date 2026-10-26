//! consensus-spec-tests `tests/<preset>/gloas/sanity/slots/pyspec_tests/<case>/`, run through
//! `state_transition::per_slot::process_slots`.
//!
//! Each case holds `pre.ssz_snappy`, `slots.yaml` (the number of slots to process),
//! `post.ssz_snappy` and `manifest.yaml`. The check is `process_slots(pre, pre.slot + slots)`
//! and then `hash_tree_root` against the post-state. A case without `post.ssz_snappy` must
//! fail with an error that proves the input invalid (`StfError::proves_invalid`). Only
//! `slots` runs: the `blocks` handler needs block processing.

use crate::coverage::Reads;
use crate::fixture;
use crate::plan::Case;
use consensus_types::gloas::BeaconState;
use consensus_types::{Mainnet, Minimal};
use ssz::Decode;
use state_transition::per_slot::process_slots;
use state_transition::{state_root, Preset};
use std::path::Path;
use tree_hash::TreeHash;

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    fork == "gloas" && handler == "slots" && matches!(preset, "minimal" | "mainnet")
}

/// Runs one `slots` case. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    match case.key.preset.as_str() {
        "minimal" => slots::<Minimal>(reads, case),
        "mainnet" => slots::<Mainnet>(reads, case),
        other => Err(format!("no sanity runner for preset {other}")),
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
    match (process_slots(&mut state, target), post) {
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

/// A `BeaconState` from a `.ssz_snappy` file.
fn decode_state<E: Preset>(reads: &Reads, path: &Path) -> Result<BeaconState<E>, String> {
    let bytes = fixture::ssz_snappy(reads, path)?;
    BeaconState::<E>::from_ssz_bytes(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{CaseFile, CaseKey};
    use consensus_types::gloas::*;
    use consensus_types::primitives::{Address, Root};
    use milhouse::{List, ProgressiveList, Vector};
    use ssz::{BitVector, Encode};
    use ssz_types::FixedVector;

    /// A Gloas minimal state at `slot` with an empty registry: enough for `process_slots`
    /// inside one epoch.
    fn state(slot: u64) -> BeaconState<Minimal> {
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
        assert!(supported("gloas", "minimal", "slots"));
        assert!(supported("gloas", "mainnet", "slots"));
        assert!(!supported("gloas", "minimal", "blocks"));
        assert!(!supported("fulu", "minimal", "slots"));
        assert!(!supported("gloas", "general", "slots"));
    }

    #[test]
    fn a_matching_post_state_passes_and_every_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let pre = state(2);
        let mut post = pre.clone();
        process_slots(&mut post, 4).unwrap();
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
            // Slot 8 starts epoch 1, so process_epoch runs and is still a stub.
            ("6", Some(&pre), "process_slots failed"),
            ("-1", Some(&pre), "unsigned integer"),
        ] {
            let c = case(dir.path(), "minimal", Some(&pre), slots, post);
            let err = run(&Reads::default(), &c).unwrap_err();
            assert!(err.contains(needle), "{slots}: {err}");
        }
        // A vector without a post-state expects a spec failure, not a missing port: slot 8
        // needs process_epoch, which is still a stub.
        let c = case(dir.path(), "minimal", Some(&pre), "6", None);
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
}
