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
    Attestation, BeaconBlock, BeaconState, Checkpoint, SignedBeaconBlock,
};
use consensus_types::primitives::{Root, Slot};
use consensus_types::Minimal;
use spec_tests::coverage::Reads;
use spec_tests::fork_choice::{handler_runs, run, supported, NOT_RUN, RUNNABLE};
use spec_tests::plan::{Case, CaseFile, CaseKey};
use ssz::{BitVector, Encode, ProgressiveBitList};
use state_transition::per_slot::process_slots;
use state_transition::preset::BUILDER_INDEX_SELF_BUILD;
use state_transition::testing::{
    bid_for_state, block_at_state_slot, bls_context, genesis_state, no_bls, signed_block,
    ContractBackend,
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
        let case = self.case("on_block");
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
fn runner_takes_the_four_gloas_handlers_of_tick_and_block_steps() {
    assert_eq!(
        RUNNABLE,
        [
            "on_block",
            "get_head",
            "get_parent_payload_status",
            "filter_node_tree_variants"
        ]
    );
    for handler in RUNNABLE {
        assert_eq!(handler_runs(handler), Ok(true));
        assert!(supported("gloas", "minimal", handler));
        assert!(supported("gloas", "mainnet", handler));
        assert!(!supported("fulu", "minimal", handler));
        assert!(!supported("heze", "minimal", handler));
        assert!(!supported("gloas", "general", handler));
    }
    for handler in [
        "on_attestation",
        "on_execution_payload_envelope",
        "on_payload_attestation_message",
        "ex_ante",
        "reorg",
        "withholding",
        "deposit_with_reorg",
        "payload_timeliness",
        "payload_data_availability",
        "should_apply_proposer_boost",
    ] {
        assert!(NOT_RUN.contains(&handler), "{handler}");
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
            "- tick: {}\n- block: {}\n  valid: {valid}\n",
            time_at(1),
            block_name(&block)
        ));
        assert_eq!(case.run().is_ok(), ok, "{meta:?} valid: {valid}");
    }
    let mut case = CaseDir::new(Some("bls_setting: 3\n"));
    case.steps("- tick: 1606824006\n");
    let err = case.run().unwrap_err();
    assert!(err.contains("bls_setting"), "{err}");
}

#[test]
fn a_tick_before_genesis_must_have_the_verdict_of_the_vector() {
    let mut case = CaseDir::new(BLS_OFF);
    case.steps(&format!("- tick: {}\n  valid: false\n", GENESIS_TIME - 1));
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
    let mut with_attestation = block.clone();
    with_attestation
        .message
        .body
        .attestations
        .push(attestation())
        .unwrap();
    for (steps, needle) in [
        (
            "- attestation: attestation_0x00\n".to_owned(),
            "attestation",
        ),
        (
            "- attester_slashing: attester_slashing_0x00\n".to_owned(),
            "attester_slashing",
        ),
        (
            "- execution_payload: execution_payload_envelope_0x00\n  valid: true\n".to_owned(),
            "execution_payload",
        ),
        (
            "- payload_attestation_message: payload_attestation_message_0x00\n".to_owned(),
            "payload_attestation_message",
        ),
        (
            "- checks:\n    viable_for_head_roots_and_weights: []\n".to_owned(),
            "viable_for_head_roots_and_weights",
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
    // A block with attestations needs `on_attestation` after `on_block`.
    let mut case = CaseDir::new(BLS_OFF);
    case.block(&with_attestation);
    case.steps(&format!(
        "- tick: {}\n- block: {}\n",
        time_at(1),
        block_name(&with_attestation)
    ));
    let err = case.run().unwrap_err();
    assert!(err.contains("on_attestation"), "{err}");
}

/// An `Attestation` of committee 0 at slot 0 with one bit set. The runner refuses the block
/// before it reads the attestation.
fn attestation() -> Attestation<E> {
    let checkpoint = Checkpoint {
        epoch: 0,
        root: Root::ZERO,
    };
    let mut aggregation_bits = ProgressiveBitList::with_capacity(1);
    aggregation_bits.set(0, true).unwrap();
    let mut committee_bits = BitVector::new();
    committee_bits.set(0, true).unwrap();
    Attestation {
        aggregation_bits,
        data: AttestationData {
            slot: 0,
            index: 0,
            beacon_block_root: Root::ZERO,
            source: checkpoint.clone(),
            target: checkpoint,
        },
        signature: [0; 96],
        committee_bits,
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
    let other = case.case("on_attestation");
    let err = run(&Reads::default(), &other).unwrap_err();
    assert!(err.contains("on_attestation"), "{err}");
}
