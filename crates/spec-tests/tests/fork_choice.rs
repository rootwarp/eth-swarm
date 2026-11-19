//! The `fork_choice` runner on small cases in the layout of consensus-spec-tests
//! `tests/<preset>/gloas/fork_choice/<handler>/pyspec_tests/<case>/`. No downloaded vectors
//! are needed.
//!
//! The anchor is a Gloas genesis as the pyspec writes it: the bid of the anchor block is the
//! bid of the state, and the latest block hash of the state is not the block hash of that bid,
//! so a first block builds on an EMPTY parent. The blocks have no valid signatures, so the
//! cases set `bls_setting: 2` unless a test checks the signatures.

use consensus_types::common::AttestationData;
use consensus_types::gloas::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, Checkpoint, ExecutionPayload,
    ExecutionPayloadEnvelope, IndexedAttestation, PayloadAttestation, PayloadAttestationData,
    SignedBeaconBlock, SignedExecutionPayloadEnvelope,
};
use consensus_types::primitives::{Gwei, Root, Slot, ValidatorIndex, U256};
use consensus_types::Minimal;
use spec_tests::coverage::Reads;
use spec_tests::fork_choice::{handler_runs, run, supported, NOT_RUN, RUNNABLE};
use spec_tests::plan::{Case, CaseFile, CaseKey};
use ssz::{BitVector, Encode, ProgressiveBitList};
use ssz_types::ProgressiveVariableList;
use state_transition::caches::CommitteeCache;
use state_transition::per_slot::process_slots;
use state_transition::preset::BUILDER_INDEX_SELF_BUILD;
use state_transition::testing::{
    bid_for_state, block_at_state_slot, bls_context, empty_requests, genesis_state, no_bls,
    signed_block, ContractBackend,
};
use state_transition::{state_root, state_transition};
use tempfile::TempDir;
use tree_hash::TreeHash;

type E = Minimal;

const GENESIS_TIME: u64 = 1_606_824_000;
/// `SLOT_DURATION_MS` of `configs/minimal.yaml`, in seconds.
const SLOT_SECONDS: u64 = 6;

/// The genesis anchor state and block.
fn anchor() -> (BeaconState<E>, BeaconBlock<E>) {
    let mut state = genesis_state::<E>(&[32_000_000_000; 64]);
    state.genesis_time = GENESIS_TIME;
    state.latest_block_hash = Root::repeat_byte(0x01);
    let mut block = signed_block::<E>(0, 0).message;
    block.body.signed_execution_payload_bid.message = state.latest_execution_payload_bid.clone();
    state.latest_block_header.body_root = block.body.tree_hash_root();
    block.state_root = state_root(&mut state).unwrap();
    (state, block)
}

/// A block at `slot` on the block of `state` that `state_transition(validate_result=True)`
/// accepts with BLS off: a self-build bid on the EMPTY parent, and the root of its post-state.
fn block_on(state: &BeaconState<E>, slot: Slot) -> SignedBeaconBlock<E> {
    let mut at_slot = state.clone();
    process_slots(&mut at_slot, slot, &no_bls()).unwrap();
    let mut block = block_at_state_slot(&at_slot);
    block.message.body.signed_execution_payload_bid =
        bid_for_state(&at_slot, BUILDER_INDEX_SELF_BUILD, 0);
    let mut post = state.clone();
    let backend = ContractBackend::new([]);
    state_transition(&mut post, &block, false, &bls_context(&backend)).unwrap();
    block.message.state_root = state_root(&mut post).unwrap();
    block
}

/// A block at `slot` on the block of `state`, as [`block_on`] makes it, whose bid commits to
/// no execution requests, and its post-state.
fn block_and_post(state: &BeaconState<E>, slot: Slot) -> (SignedBeaconBlock<E>, BeaconState<E>) {
    let mut at_slot = state.clone();
    process_slots(&mut at_slot, slot, &no_bls()).unwrap();
    let mut block = block_at_state_slot(&at_slot);
    let mut bid = bid_for_state(&at_slot, BUILDER_INDEX_SELF_BUILD, 0);
    bid.message.execution_requests_root = empty_requests::<E>().tree_hash_root();
    block.message.body.signed_execution_payload_bid = bid;
    let mut post = state.clone();
    let backend = ContractBackend::new([]);
    state_transition(&mut post, &block, false, &bls_context(&backend)).unwrap();
    block.message.state_root = state_root(&mut post).unwrap();
    (block, post)
}

/// The envelope of `block` that `verify_execution_payload_envelope` accepts on `post`, the
/// post-state of the block. Its signature is not valid, so the cases turn BLS off.
fn envelope_of(
    block: &SignedBeaconBlock<E>,
    post: &BeaconState<E>,
) -> SignedExecutionPayloadEnvelope<E> {
    let bid = &block.message.body.signed_execution_payload_bid.message;
    let withdrawals: Vec<_> = post.payload_expected_withdrawals.iter().cloned().collect();
    SignedExecutionPayloadEnvelope {
        message: ExecutionPayloadEnvelope {
            payload: ExecutionPayload {
                parent_hash: post.latest_block_hash,
                fee_recipient: bid.fee_recipient,
                state_root: Root::repeat_byte(0x02),
                receipts_root: Root::repeat_byte(0x03),
                logs_bloom: Default::default(),
                prev_randao: bid.prev_randao,
                block_number: 1,
                gas_limit: bid.gas_limit,
                gas_used: 0,
                timestamp: time_at(post.slot),
                extra_data: Default::default(),
                base_fee_per_gas: U256::from(7),
                block_hash: bid.block_hash,
                transactions: Default::default(),
                withdrawals: withdrawals.try_into().unwrap(),
                blob_gas_used: 0,
                excess_blob_gas: 0,
                block_access_list: Default::default(),
                slot_number: post.slot,
            },
            execution_requests: empty_requests(),
            builder_index: bid.builder_index,
            beacon_block_root: block.message.tree_hash_root(),
            parent_beacon_block_root: block.message.parent_root,
        },
        signature: [0x11; 96],
    }
}

fn hex_root(root: Root) -> String {
    format!("'0x{}'", hex::encode(root))
}

/// The name of the file of `block` in a case, without `.ssz_snappy`.
fn block_name(block: &SignedBeaconBlock<E>) -> String {
    format!("block_0x{}", hex::encode(block.message.tree_hash_root()))
}

fn snappy(bytes: &[u8]) -> Vec<u8> {
    snap::raw::Encoder::new().compress_vec(bytes).unwrap()
}

/// The time of the start of `slot`, in seconds.
fn time_at(slot: Slot) -> u64 {
    GENESIS_TIME + slot * SLOT_SECONDS
}

/// The checks of a store at `time` with the head `head` of `slot` (EMPTY), the anchor as
/// justified and finalized checkpoint, and the boost root `boost`.
fn checks(time: u64, anchor: Root, head: Root, slot: Slot, boost: Root) -> String {
    let anchor = hex_root(anchor);
    format!(
        "- checks:\n    time: {time}\n    head: {{slot: {slot}, root: {}, payload_status: 0}}\n    \
         justified_checkpoint: {{epoch: 0, root: {anchor}}}\n    \
         finalized_checkpoint: {{epoch: 0, root: {anchor}}}\n    proposer_boost_root: {}\n",
        hex_root(head),
        hex_root(boost)
    )
}

/// One case in its own directory. The directory lives as long as the case.
struct CaseDir {
    dir: TempDir,
    files: Vec<CaseFile>,
}

impl CaseDir {
    /// A case with the [`anchor`] files and `meta.yaml` (omitted if `meta` is `None`).
    fn new(meta: Option<&str>) -> Self {
        let mut case = Self {
            dir: tempfile::tempdir().unwrap(),
            files: Vec::new(),
        };
        let (state, block) = anchor();
        case.put("anchor_state.ssz_snappy", &snappy(&state.as_ssz_bytes()));
        case.put("anchor_block.ssz_snappy", &snappy(&block.as_ssz_bytes()));
        if let Some(meta) = meta {
            case.put("meta.yaml", meta.as_bytes());
        }
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

    /// Puts `value` in the case as `<prefix>_0x<root>.ssz_snappy`, and gives the name of the
    /// file without `.ssz_snappy`, as a step names it.
    fn object<T: Encode + TreeHash>(&mut self, prefix: &str, value: &T) -> String {
        let name = format!("{prefix}_0x{}", hex::encode(value.tree_hash_root()));
        self.put(
            &format!("{name}.ssz_snappy"),
            &snappy(&value.as_ssz_bytes()),
        );
        name
    }

    fn block(&mut self, block: &SignedBeaconBlock<E>) {
        let name = format!("{}.ssz_snappy", block_name(block));
        self.put(&name, &snappy(&block.as_ssz_bytes()));
    }

    fn steps(&mut self, steps: &str) {
        self.put("steps.yaml", steps.as_bytes());
    }

    fn case(&self, handler: &str) -> Case {
        Case {
            key: CaseKey {
                source: "consensus-specs".into(),
                fork: "gloas".into(),
                preset: "minimal".into(),
                runner: "fork_choice".into(),
                handler: handler.into(),
                case: "pyspec_tests/case_0".into(),
            },
            files: self.files.clone(),
        }
    }

    /// Runs the case and checks that the runner read every file of it.
    fn run(&self) -> Result<(), String> {
        self.run_as("on_block")
    }

    /// [`CaseDir::run`] for a case of `handler`.
    fn run_as(&self, handler: &str) -> Result<(), String> {
        let case = self.case(handler);
        let reads = Reads::default();
        let result = run(&reads, &case);
        if result.is_ok() {
            for f in &case.files {
                assert!(reads.contains(&f.path), "{} is not read", f.name);
            }
        }
        result
    }
}

const BLS_OFF: Option<&str> = Some("bls_setting: 2\n");

#[test]
fn runner_takes_the_gloas_handlers_of_its_steps() {
    assert_eq!(
        RUNNABLE.as_slice(),
        [
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
        ]
        .as_slice()
    );
    for handler in RUNNABLE {
        assert_eq!(handler_runs(handler), Ok(true));
        assert!(supported("gloas", "minimal", handler));
        assert!(supported("gloas", "mainnet", handler));
        assert!(!supported("fulu", "minimal", handler));
        assert!(!supported("heze", "minimal", handler));
        assert!(!supported("gloas", "general", handler));
    }
    // Each case of these handlers has a payload_attestation_message step or payload vote
    // checks.
    assert_eq!(
        NOT_RUN.as_slice(),
        [
            "on_payload_attestation_message",
            "payload_timeliness",
            "payload_data_availability",
        ]
        .as_slice()
    );
    for handler in NOT_RUN {
        assert_eq!(handler_runs(handler), Ok(false));
        assert!(!supported("gloas", "minimal", handler));
    }
    let unknown = handler_runs("on_tick").unwrap_err();
    assert!(
        unknown.contains("unknown fork_choice handler directory `on_tick`"),
        "{unknown}"
    );
}

#[test]
fn checks_of_the_anchor_store_pass_and_every_file_is_read() {
    let (_, block) = anchor();
    let root = block.tree_hash_root();
    let mut case = CaseDir::new(Some("description: the anchor only\n"));
    let steps = checks(GENESIS_TIME, root, root, 0, Root::ZERO)
        + &format!("- checks:\n    genesis_time: {GENESIS_TIME}\n");
    case.steps(&steps);
    assert_eq!(case.run(), Ok(()));
}

#[test]
fn a_tick_and_a_block_move_the_head_and_the_boost() {
    let (state, anchor_block) = anchor();
    let anchor = anchor_block.tree_hash_root();
    let block = block_on(&state, 1);
    let root = block.message.tree_hash_root();
    let mut case = CaseDir::new(BLS_OFF);
    case.block(&block);
    let steps = format!("- tick: {}\n", time_at(1))
        + &checks(time_at(1), anchor, anchor, 0, Root::ZERO)
        + &format!("- block: {}\n", block_name(&block))
        + &checks(time_at(1), anchor, root, 1, root)
        + &format!("- tick: {}\n", time_at(2))
        + &checks(time_at(2), anchor, root, 1, Root::ZERO);
    case.steps(&steps);
    assert_eq!(case.run(), Ok(()));
}

#[test]
fn a_check_that_differs_from_the_store_fails() {
    let (state, anchor_block) = anchor();
    let anchor = anchor_block.tree_hash_root();
    let block = block_on(&state, 1);
    let root = block.message.tree_hash_root();
    let other = Root::repeat_byte(0x77);
    let prefix = format!("- tick: {}\n- block: {}\n", time_at(1), block_name(&block));
    for (checks, needle) in [
        (checks(time_at(1), anchor, other, 1, root), "head"),
        (checks(time_at(1), anchor, root, 2, root), "head"),
        (checks(time_at(1) + 1, anchor, root, 1, root), "time"),
        (
            checks(time_at(1), anchor, root, 1, other),
            "proposer_boost_root",
        ),
        (
            checks(time_at(1), other, root, 1, root),
            "justified_checkpoint",
        ),
        (
            format!(
                "- checks:\n    head: {{slot: 1, root: {}, payload_status: 1}}\n",
                hex_root(root)
            ),
            "head",
        ),
        (
            format!("- checks:\n    genesis_time: {}\n", GENESIS_TIME + 1),
            "genesis_time",
        ),
        (
            format!(
                "- checks:\n    finalized_checkpoint: {{epoch: 1, root: {}}}\n",
                hex_root(anchor)
            ),
            "finalized_checkpoint",
        ),
    ] {
        let mut case = CaseDir::new(BLS_OFF);
        case.block(&block);
        case.steps(&(prefix.clone() + &checks));
        let err = case.run().unwrap_err();
        assert!(err.contains(needle), "{needle}: {err}");
    }
}

#[test]
fn a_block_step_must_have_the_verdict_of_the_vector() {
    let (state, anchor_block) = anchor();
    let anchor = anchor_block.tree_hash_root();
    let valid = block_on(&state, 1);
    let mut orphan = valid.clone();
    orphan.message.parent_root = Root::repeat_byte(0x45);
    let future = block_on(&state, 2);
    for (block, tick_slot, valid_flag, outcome) in [
        // An invalid block that the vector expects to fail passes, and the store keeps the
        // anchor as head.
        (&orphan, 1, "false", None),
        (&future, 1, "false", None),
        // A valid block marked invalid, and an invalid block marked valid, fail.
        (&valid, 1, "false", Some("accepted")),
        (&orphan, 1, "true", Some("parent block")),
        (&future, 1, "true", Some("after the current slot")),
    ] {
        let mut case = CaseDir::new(BLS_OFF);
        case.block(block);
        let steps = format!(
            "- tick: {}\n- block: {}\n  valid: {valid_flag}\n",
            time_at(tick_slot),
            block_name(block)
        ) + &checks(time_at(tick_slot), anchor, anchor, 0, Root::ZERO);
        case.steps(&steps);
        match (case.run(), outcome) {
            (Ok(()), None) => {}
            (Err(err), Some(needle)) => assert!(err.contains(needle), "{needle}: {err}"),
            (got, want) => panic!(
                "{valid_flag} {}: got {got:?}, want {want:?}",
                block_name(block)
            ),
        }
    }
}

#[test]
fn signatures_are_checked_unless_the_case_turns_bls_off() {
    let (state, _) = anchor();
    let block = block_on(&state, 1);
    for (meta, valid, ok) in [
        (BLS_OFF, "true", true),
        // The block has no valid signatures, so with BLS on it is invalid.
        (None, "false", true),
        (Some("bls_setting: 0\n"), "false", true),
        (Some("bls_setting: 1\n"), "true", false),
    ] {
        let mut case = CaseDir::new(meta);
        case.block(&block);
        case.steps(&format!(
            "- tick: {}\n- block: {}\n  valid: {valid}\n- checks:\n    time: {}\n",
            time_at(1),
            block_name(&block),
            time_at(1)
        ));
        assert_eq!(case.run().is_ok(), ok, "{meta:?} valid: {valid}");
    }
    let mut case = CaseDir::new(Some("bls_setting: 3\n"));
    case.steps("- tick: 1606824006\n- checks:\n    time: 1606824006\n");
    let err = case.run().unwrap_err();
    assert!(err.contains("bls_setting"), "{err}");
}

#[test]
fn a_tick_before_genesis_must_have_the_verdict_of_the_vector() {
    let mut case = CaseDir::new(BLS_OFF);
    case.steps(&format!(
        "- tick: {}\n  valid: false\n- checks:\n    time: {GENESIS_TIME}\n",
        GENESIS_TIME - 1
    ));
    assert_eq!(case.run(), Ok(()));
    let mut case = CaseDir::new(BLS_OFF);
    case.steps(&format!("- tick: {}\n", GENESIS_TIME - 1));
    let err = case.run().unwrap_err();
    assert!(err.contains("tick"), "{err}");
}

#[test]
fn steps_and_checks_that_the_runner_does_not_have_fail_closed() {
    let (state, _) = anchor();
    let block = block_on(&state, 1);
    for (steps, needle) in [
        (
            "- attestation: attestation_0x00\n".to_owned(),
            "attestation_0x00",
        ),
        (
            "- attester_slashing: attester_slashing_0x00\n".to_owned(),
            "attester_slashing_0x00",
        ),
        (
            "- attestation: attestation_0x00\n  extra: 1\n".to_owned(),
            "extra",
        ),
        (
            "- attester_slashing: attester_slashing_0x00\n  extra: 1\n".to_owned(),
            "extra",
        ),
        (
            "- execution_payload: execution_payload_envelope_0x00\n  extra: 1\n".to_owned(),
            "extra",
        ),
        (
            "- payload_attestation_message: payload_attestation_message_0x00\n".to_owned(),
            "payload_attestation_message",
        ),
        (
            "- checks:\n    payload_timeliness_vote: {block_root: '0x00', votes: []}\n"
                .to_owned(),
            "payload_timeliness_vote",
        ),
        (
            "- checks:\n    viable_for_head_roots_and_weights: [{root: '0x00', weight: 0, payload_status: 0, extra: 1}]\n"
                .to_owned(),
            "extra",
        ),
        (
            "- checks:\n    get_proposer_head: '0x00'\n".to_owned(),
            "get_proposer_head",
        ),
        ("- tick: 1606824006\n  extra: 1\n".to_owned(), "extra"),
        (
            format!("- block: {}\n  columns: []\n", block_name(&block)),
            "columns",
        ),
        (
            format!("- block: {}\n  blobs: blobs_0x00\n", block_name(&block)),
            "blobs",
        ),
        ("- block: block_0x00\n".to_owned(), "block_0x00"),
        ("tick: 1\n".to_owned(), "list"),
    ] {
        let mut case = CaseDir::new(BLS_OFF);
        case.block(&block);
        case.steps(&steps);
        let err = case.run().unwrap_err();
        assert!(err.contains(needle), "{needle}: {err}");
    }
}

#[test]
fn a_case_of_another_preset_or_handler_fails() {
    let mut case = CaseDir::new(BLS_OFF);
    case.steps("[]\n");
    let mut other = case.case("on_block");
    other.key.preset = "general".into();
    let err = run(&Reads::default(), &other).unwrap_err();
    assert!(err.contains("general"), "{err}");
    let other = case.case("payload_timeliness");
    let err = run(&Reads::default(), &other).unwrap_err();
    assert!(err.contains("payload_timeliness"), "{err}");
}

#[test]
fn ex_ante_runs_as_a_handler_of_tick_and_block_steps() {
    assert!(RUNNABLE.contains(&"ex_ante"));
    assert!(!NOT_RUN.contains(&"ex_ante"));
    assert_eq!(handler_runs("ex_ante"), Ok(true));
    for preset in ["minimal", "mainnet"] {
        assert!(supported("gloas", preset, "ex_ante"), "{preset}");
    }
    let (_, block) = anchor();
    let root = block.tree_hash_root();
    let mut case = CaseDir::new(BLS_OFF);
    case.steps(&checks(GENESIS_TIME, root, root, 0, Root::ZERO));
    assert_eq!(case.run_as("ex_ante"), Ok(()));
}

#[test]
fn a_case_must_run_at_least_one_check() {
    let (_, block) = anchor();
    let root = block.tree_hash_root();
    for steps in [
        "[]\n".to_owned(),
        format!("- tick: {}\n", time_at(1)),
        format!("- tick: {}\n- checks: {{}}\n", time_at(1)),
        // A checks step with no check fails, also after a step with checks.
        checks(GENESIS_TIME, root, root, 0, Root::ZERO) + "- checks: {}\n",
    ] {
        let mut case = CaseDir::new(BLS_OFF);
        case.steps(&steps);
        match case.run() {
            Err(err) => assert!(err.contains("check"), "{steps}: {err}"),
            Ok(()) => panic!("a case with no check passes: {steps}"),
        }
    }
}

/// `PTC_SIZE` of the minimal preset.
const PTC_SIZE: usize = 16;

/// The post-state of `block` on `state`, with BLS off and no state root check.
fn post_state(state: &BeaconState<E>, block: &SignedBeaconBlock<E>) -> BeaconState<E> {
    let mut post = state.clone();
    let backend = ContractBackend::new([]);
    state_transition(&mut post, block, false, &bls_context(&backend)).unwrap();
    post
}

/// [`block_on`] with a payload attestation of every PTC member for the block of `state`, which
/// must be of the slot before `slot`.
fn block_with_ptc_votes(state: &BeaconState<E>, slot: Slot) -> SignedBeaconBlock<E> {
    let mut at_slot = state.clone();
    process_slots(&mut at_slot, slot, &no_bls()).unwrap();
    let mut block = block_at_state_slot(&at_slot);
    block.message.body.signed_execution_payload_bid =
        bid_for_state(&at_slot, BUILDER_INDEX_SELF_BUILD, 0);
    let mut aggregation_bits = BitVector::new();
    for position in 0..PTC_SIZE {
        aggregation_bits.set(position, true).unwrap();
    }
    let data = PayloadAttestationData {
        beacon_block_root: block.message.parent_root,
        slot: slot - 1,
        payload_present: true,
        blob_data_available: true,
    };
    block
        .message
        .body
        .payload_attestations
        .push(PayloadAttestation {
            aggregation_bits,
            data,
            signature: [0; 96],
        })
        .unwrap();
    let mut post = post_state(state, &block);
    block.message.state_root = state_root(&mut post).unwrap();
    block
}

#[test]
fn a_repeated_block_with_payload_attestations_fails_closed() {
    let (state, anchor_block) = anchor();
    let anchor = anchor_block.tree_hash_root();
    let first = block_on(&state, 1);
    let second = block_with_ptc_votes(&post_state(&state, &first), 2);
    let root = second.message.tree_hash_root();
    let once = format!(
        "- tick: {}\n- block: {}\n- block: {}\n",
        time_at(2),
        block_name(&first),
        block_name(&second)
    );
    let repeat = format!("- block: {}\n", block_name(&second));
    // The spec's on_block runs again for a known block and gives its PTC votes to the store
    // again, but fork_choice::on_block returns early, so the runner must refuse the step.
    for (steps, want) in [
        (once.clone(), None),
        (once + &repeat, Some("payload attestations")),
    ] {
        let mut case = CaseDir::new(BLS_OFF);
        case.block(&first);
        case.block(&second);
        case.steps(&(steps + &checks(time_at(2), anchor, root, 2, root)));
        match (case.run(), want) {
            (Ok(()), None) => {}
            (Err(err), Some(needle)) => assert!(err.contains(needle), "{needle}: {err}"),
            (got, want) => panic!("got {got:?}, want {want:?}"),
        }
    }
}

#[test]
fn a_failed_state_transition_proves_a_block_invalid() {
    let (state, anchor_block) = anchor();
    let anchor = anchor_block.tree_hash_root();
    let mut block = block_on(&state, 1);
    block.message.state_root = Root::repeat_byte(0x66);
    // The transition fails on the state root, which proves the block invalid: a step with
    // `valid: false` passes, and the store keeps the anchor as head.
    for (valid, outcome) in [("false", None), ("true", Some("state root mismatch"))] {
        let mut case = CaseDir::new(BLS_OFF);
        case.block(&block);
        let steps = format!(
            "- tick: {}\n- block: {}\n  valid: {valid}\n",
            time_at(1),
            block_name(&block)
        ) + &checks(time_at(1), anchor, anchor, 0, Root::ZERO);
        case.steps(&steps);
        match (case.run(), outcome) {
            (Ok(()), None) => {}
            (Err(err), Some(needle)) => assert!(err.contains(needle), "{needle}: {err}"),
            (got, want) => panic!("valid: {valid}: got {got:?}, want {want:?}"),
        }
    }
}

/// The balance of each validator of the [`anchor`] state.
const BALANCE: Gwei = 32_000_000_000;

/// The members at `positions` of committee 0 of `slot` of epoch 0, from `state`.
fn members(state: &BeaconState<E>, slot: Slot, positions: &[usize]) -> Vec<ValidatorIndex> {
    let cache = CommitteeCache::new(state, 0).unwrap();
    let committee = cache.committee(slot, 0).unwrap();
    positions.iter().map(|p| committee[*p]).collect()
}

/// The data of a vote of `slot` for `root` with the target `target` of epoch 0 and the source
/// of `state`.
fn vote_data(state: &BeaconState<E>, slot: Slot, root: Root, target: Root) -> AttestationData {
    AttestationData {
        slot,
        index: 0,
        beacon_block_root: root,
        source: state.current_justified_checkpoint.clone(),
        target: Checkpoint {
            epoch: 0,
            root: target,
        },
    }
}

/// An attestation of the members at `positions` of committee 0 of `slot` of epoch 0 for
/// `root`, with the target `target` of epoch 0. The committee comes from `state`.
fn vote(
    state: &BeaconState<E>,
    slot: Slot,
    root: Root,
    target: Root,
    positions: &[usize],
) -> Attestation<E> {
    let size = CommitteeCache::new(state, 0)
        .unwrap()
        .committee(slot, 0)
        .unwrap()
        .len();
    let mut aggregation_bits = ProgressiveBitList::with_capacity(size);
    for &position in positions {
        aggregation_bits.set(position, true).unwrap();
    }
    let mut committee_bits = BitVector::new();
    committee_bits.set(0, true).unwrap();
    Attestation {
        aggregation_bits,
        data: vote_data(state, slot, root, target),
        signature: [0; 96],
        committee_bits,
    }
}

/// The indexed attestation of [`vote`].
fn indexed(
    state: &BeaconState<E>,
    slot: Slot,
    root: Root,
    target: Root,
    positions: &[usize],
) -> IndexedAttestation<E> {
    let mut indices = members(state, slot, positions);
    indices.sort_unstable();
    IndexedAttestation {
        attesting_indices: ProgressiveVariableList::new(indices).unwrap(),
        data: vote_data(state, slot, root, target),
        signature: [0; 96],
    }
}

/// A `viable_for_head_roots_and_weights` check of the EMPTY leaves `leaves` (root, weight).
fn viable(leaves: &[(Root, Gwei)]) -> String {
    let mut step = "- checks:\n    viable_for_head_roots_and_weights:\n".to_owned();
    if leaves.is_empty() {
        step = "- checks:\n    viable_for_head_roots_and_weights: []\n".to_owned();
    }
    for (root, weight) in leaves {
        step += &format!(
            "    - {{root: {}, weight: {weight}, payload_status: 0}}\n",
            hex_root(*root)
        );
    }
    step
}

#[test]
fn attestation_and_attester_slashing_steps_change_the_weights() {
    let (state, anchor_block) = anchor();
    let anchor = anchor_block.tree_hash_root();
    let block = block_on(&state, 1);
    let root = block.message.tree_hash_root();
    // Two votes of slot 2 for the block, then a slashing of the first voter: a second vote of
    // the same target epoch for the anchor.
    let attestation = vote(&state, 2, root, anchor, &[0, 1]);
    let slashing = AttesterSlashing {
        attestation_1: indexed(&state, 2, root, anchor, &[0]),
        attestation_2: indexed(&state, 2, anchor, anchor, &[0]),
    };
    let mut case = CaseDir::new(BLS_OFF);
    case.block(&block);
    let attestation = case.object("attestation", &attestation);
    let slashing = case.object("attester_slashing", &slashing);
    let steps = format!("- tick: {}\n- block: {}\n", time_at(3), block_name(&block))
        + &viable(&[(root, 0)])
        + &format!("- attestation: {attestation}\n")
        + &viable(&[(root, 2 * BALANCE)])
        + &checks(time_at(3), anchor, root, 1, Root::ZERO)
        + &format!("- attester_slashing: {slashing}\n")
        + &viable(&[(root, BALANCE)]);
    case.steps(&steps);
    assert_eq!(case.run_as("on_attestation"), Ok(()));
}

#[test]
fn attestation_and_attester_slashing_steps_must_have_the_verdict_of_the_vector() {
    let (state, anchor_block) = anchor();
    let anchor = anchor_block.tree_hash_root();
    let block = block_on(&state, 1);
    let root = block.message.tree_hash_root();
    let good = vote(&state, 2, root, anchor, &[0]);
    let mut bad_index = good.clone();
    bad_index.data.index = 2;
    let mut too_early = good.clone();
    too_early.data.slot = 3;
    // The same data twice is not a slashable pair.
    let not_slashable = AttesterSlashing {
        attestation_1: indexed(&state, 2, root, anchor, &[0]),
        attestation_2: indexed(&state, 2, root, anchor, &[0]),
    };
    let slashable = AttesterSlashing {
        attestation_1: indexed(&state, 2, root, anchor, &[0]),
        attestation_2: indexed(&state, 2, anchor, anchor, &[0]),
    };
    let prefix = format!("- tick: {}\n- block: {}\n", time_at(3), block_name(&block));
    for (kind, object, valid, outcome) in [
        // A refused step that the vector expects to fail passes, and leaves the store as it
        // was.
        ("attestation", bad_index.as_ssz_bytes(), "false", None),
        ("attestation", too_early.as_ssz_bytes(), "false", None),
        (
            "attester_slashing",
            not_slashable.as_ssz_bytes(),
            "false",
            None,
        ),
        // An accepted step marked invalid, and a refused step marked valid, fail.
        (
            "attestation",
            good.as_ssz_bytes(),
            "false",
            Some("accepted"),
        ),
        (
            "attester_slashing",
            slashable.as_ssz_bytes(),
            "false",
            Some("accepted"),
        ),
        (
            "attestation",
            bad_index.as_ssz_bytes(),
            "true",
            Some("on_attestation"),
        ),
        (
            "attester_slashing",
            not_slashable.as_ssz_bytes(),
            "true",
            Some("on_attester_slashing"),
        ),
    ] {
        let mut case = CaseDir::new(BLS_OFF);
        case.block(&block);
        let name = format!("{kind}_0x{:02x}", object.len());
        case.put(&format!("{name}.ssz_snappy"), &snappy(&object));
        let steps = prefix.clone()
            + &format!("- {kind}: {name}\n  valid: {valid}\n")
            + &viable(&[(root, 0)]);
        case.steps(&steps);
        match (case.run(), outcome) {
            (Ok(()), None) => {}
            (Err(err), Some(needle)) => assert!(err.contains(needle), "{needle}: {err}"),
            (got, want) => panic!("{kind} valid: {valid}: got {got:?}, want {want:?}"),
        }
    }
}

/// A block at `slot` on the anchor `state` with `attestations` and `slashings`, and the root
/// of its post-state with BLS off.
fn block_with_operations(
    state: &BeaconState<E>,
    slot: Slot,
    attestations: Vec<Attestation<E>>,
    slashings: Vec<AttesterSlashing<E>>,
) -> SignedBeaconBlock<E> {
    let mut at_slot = state.clone();
    process_slots(&mut at_slot, slot, &no_bls()).unwrap();
    let mut block = block_at_state_slot(&at_slot);
    block.message.body.signed_execution_payload_bid =
        bid_for_state(&at_slot, BUILDER_INDEX_SELF_BUILD, 0);
    for attestation in attestations {
        block.message.body.attestations.push(attestation).unwrap();
    }
    for slashing in slashings {
        block
            .message
            .body
            .attester_slashings
            .push(slashing)
            .unwrap();
    }
    let mut post = post_state(state, &block);
    block.message.state_root = state_root(&mut post).unwrap();
    block
}

#[test]
fn a_valid_block_applies_its_attestations_and_then_its_attester_slashings() {
    let (state, anchor_block) = anchor();
    let anchor = anchor_block.tree_hash_root();
    let x = block_on(&state, 1);
    let rx = x.message.tree_hash_root();
    // `w` of slot 3 on the anchor carries two votes of slot 2 for `x`, and a slashing of the
    // second voter. Only the first vote keeps its weight.
    let slashing = AttesterSlashing {
        attestation_1: indexed(&state, 2, rx, anchor, &[1]),
        attestation_2: indexed(&state, 2, anchor, anchor, &[1]),
    };
    let w = block_with_operations(
        &state,
        3,
        vec![vote(&state, 2, rx, anchor, &[0, 1])],
        vec![slashing],
    );
    let rw = w.message.tree_hash_root();
    let mut case = CaseDir::new(BLS_OFF);
    case.block(&x);
    case.block(&w);
    // At slot 4, the EMPTY node of `w` of the previous slot has no weight.
    let steps = format!(
        "- tick: {}\n- block: {}\n- block: {}\n- tick: {}\n",
        time_at(3),
        block_name(&x),
        block_name(&w),
        time_at(4)
    ) + &viable(&[(rx, BALANCE), (rw, 0)])
        + &checks(time_at(4), anchor, rx, 1, Root::ZERO);
    case.steps(&steps);
    assert_eq!(case.run(), Ok(()));

    // A block that the state transition accepts, with a vote that fork choice refuses: its
    // target is not a block of the store.
    let unknown = Root::repeat_byte(0x09);
    let w = block_with_operations(&state, 3, vec![vote(&state, 2, rx, unknown, &[0])], vec![]);
    let mut case = CaseDir::new(BLS_OFF);
    case.block(&x);
    case.block(&w);
    case.steps(
        &(format!(
            "- tick: {}\n- block: {}\n- block: {}\n",
            time_at(3),
            block_name(&x),
            block_name(&w)
        ) + &viable(&[(rx, 0)])),
    );
    let err = case.run().unwrap_err();
    assert!(err.contains("on_attestation"), "{err}");
}

#[test]
fn viable_for_head_roots_and_weights_must_match_the_leaves() {
    let (_, anchor_block) = anchor();
    let anchor = anchor_block.tree_hash_root();
    let other = Root::repeat_byte(0x77);
    let full_leaf = format!(
        "- checks:\n    viable_for_head_roots_and_weights:\n    - {{root: {}, weight: 0, payload_status: 1}}\n",
        hex_root(anchor)
    );
    for (steps, ok) in [
        (viable(&[(anchor, 0)]), true),
        (viable(&[(anchor, 1)]), false),
        (viable(&[(other, 0)]), false),
        (viable(&[]), false),
        (viable(&[(anchor, 0), (anchor, 0)]), false),
        (full_leaf, false),
    ] {
        let mut case = CaseDir::new(BLS_OFF);
        case.steps(&steps);
        match case.run_as("should_apply_proposer_boost") {
            Ok(()) => assert!(ok, "{steps}"),
            Err(err) => {
                assert!(!ok, "{steps}: {err}");
                assert!(err.contains("viable_for_head_roots_and_weights"), "{err}");
            }
        }
    }
}

#[test]
fn an_execution_payload_step_verifies_the_payload_of_its_block() {
    let (state, anchor_block) = anchor();
    let anchor = anchor_block.tree_hash_root();
    let (block, post) = block_and_post(&state, 1);
    let root = block.message.tree_hash_root();
    let envelope = envelope_of(&block, &post);
    assert_eq!(envelope.message.builder_index, BUILDER_INDEX_SELF_BUILD);
    let head = |payload_status: u8| {
        format!(
            "- checks:\n    head: {{slot: 1, root: {}, payload_status: {payload_status}}}\n",
            hex_root(root)
        )
    };
    for (valid, outcome) in [("true", None), ("false", Some("accepted"))] {
        let mut case = CaseDir::new(BLS_OFF);
        case.block(&block);
        let name = case.object("execution_payload_envelope", &envelope);
        // Before the envelope only the EMPTY node of the block exists. After it, the FULL node
        // wins the tie at the slot of the block.
        let steps = format!("- tick: {}\n- block: {}\n", time_at(1), block_name(&block))
            + &head(0)
            + &format!("- execution_payload: {name}\n  valid: {valid}\n")
            + &head(1)
            + &checks(time_at(1), anchor, root, 1, root)
                .replace("payload_status: 0", "payload_status: 1");
        case.steps(&steps);
        match (case.run_as("on_execution_payload_envelope"), outcome) {
            (Ok(()), None) => {}
            (Err(err), Some(needle)) => assert!(err.contains(needle), "{needle}: {err}"),
            (got, want) => panic!("valid: {valid}: got {got:?}, want {want:?}"),
        }
    }
}

#[test]
fn an_execution_payload_step_must_have_the_verdict_of_the_vector() {
    let (state, _) = anchor();
    let (block, post) = block_and_post(&state, 1);
    let root = block.message.tree_hash_root();
    let mut wrong_slot = envelope_of(&block, &post);
    wrong_slot.message.payload.slot_number = 2;
    let mut unknown_block = envelope_of(&block, &post);
    unknown_block.message.beacon_block_root = Root::repeat_byte(0x42);
    for (envelope, valid, outcome) in [
        // An invalid envelope that the vector expects to fail passes, and the payload of the
        // block stays unverified: the head stays on the EMPTY node.
        (&wrong_slot, "false", None),
        (&unknown_block, "false", None),
        // An invalid envelope marked valid fails.
        (&wrong_slot, "true", Some("refused a valid step")),
        (&unknown_block, "true", Some("refused a valid step")),
    ] {
        let mut case = CaseDir::new(BLS_OFF);
        case.block(&block);
        let name = case.object("execution_payload_envelope", envelope);
        let steps = format!(
            "- tick: {}\n- block: {}\n- execution_payload: {name}\n  valid: {valid}\n",
            time_at(1),
            block_name(&block)
        ) + &format!(
            "- checks:\n    head: {{slot: 1, root: {}, payload_status: 0}}\n",
            hex_root(root)
        );
        case.steps(&steps);
        match (case.run_as("on_execution_payload_envelope"), outcome) {
            (Ok(()), None) => {}
            (Err(err), Some(needle)) => assert!(err.contains(needle), "{needle}: {err}"),
            (got, want) => panic!("valid: {valid}: got {got:?}, want {want:?}"),
        }
    }
}
