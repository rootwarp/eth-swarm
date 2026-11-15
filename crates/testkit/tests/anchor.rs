//! Tests of the anchor-directory loader.
//!
//! Each test writes a temporary directory in the `anchor-fetch` layout. The files come from the
//! genesis state and the genesis block of the pinned export. The tests do not change
//! `testing/replay/`.

use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::Minimal;
use ssz::{Decode, Encode};
use std::fs;
use testkit::anchor::fixtures::{pinned_export, AnchorFiles};
use testkit::anchor::{load_anchor, AnchorError, ANCHOR_FILE, STATE_FILE};
use tree_hash::TreeHash;

/// The anchor files of the genesis of the pinned export.
fn genesis_files() -> AnchorFiles {
    let pinned = pinned_export().expect("the pinned export must open");
    AnchorFiles::genesis(&pinned.export).expect("the export must hold its genesis")
}

#[test]
fn loads_a_checked_anchor() {
    let files = genesis_files();
    let dir = tempfile::tempdir().unwrap();
    files.write(dir.path()).unwrap();
    let anchor = load_anchor::<Minimal>(dir.path()).expect("the anchor must load");
    assert_eq!(anchor.block_root(), files.block_root, "block root");
    assert_eq!(anchor.state_root(), files.state_root, "state root");
    assert_eq!(anchor.slot(), 0, "slot");
    assert_eq!(
        anchor.block().message.state_root,
        anchor.state_root(),
        "the block must commit to the state"
    );
    assert_eq!(anchor.block().message.tree_hash_root(), anchor.block_root());
}

#[test]
fn refuses_a_dir_without_anchor_json() {
    let files = genesis_files();
    let dir = tempfile::tempdir().unwrap();
    files.write(dir.path()).unwrap();
    fs::remove_file(dir.path().join(ANCHOR_FILE)).unwrap();
    let err = load_anchor::<Minimal>(dir.path())
        .expect_err("block.ssz and state.ssz without anchor.json must not load");
    assert!(matches!(err, AnchorError::NotCommitted { .. }), "{err}");
}

#[test]
fn refuses_a_state_root_that_disagrees_with_anchor_json() {
    let mut files = genesis_files();
    let mut state = BeaconState::<Minimal>::from_ssz_bytes(&files.state_ssz).unwrap();
    state.genesis_time += 1;
    // The file records carry the sha256 of the changed state. The roots stay those of genesis.
    files.state_ssz = state.as_ssz_bytes();
    let dir = tempfile::tempdir().unwrap();
    files.write(dir.path()).unwrap();
    let err =
        load_anchor::<Minimal>(dir.path()).expect_err("a state with another root must not load");
    assert!(matches!(err, AnchorError::StateRoot { .. }), "{err}");
}

#[test]
fn refuses_a_signed_wrapper_root_as_block_root() {
    let mut files = genesis_files();
    let block = SignedBeaconBlock::<Minimal>::from_ssz_bytes(&files.block_ssz).unwrap();
    files.block_root = block.tree_hash_root();
    assert_ne!(files.block_root, block.message.tree_hash_root());
    let dir = tempfile::tempdir().unwrap();
    files.write(dir.path()).unwrap();
    let err = load_anchor::<Minimal>(dir.path())
        .expect_err("the root of the signed wrapper must not load as block_root");
    assert!(matches!(err, AnchorError::BlockRoot { .. }), "{err}");
}

#[test]
fn refuses_a_file_whose_sha256_disagrees_with_anchor_json() {
    let files = genesis_files();
    let dir = tempfile::tempdir().unwrap();
    files.write(dir.path()).unwrap();
    let path = dir.path().join(STATE_FILE);
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(&path, bytes).unwrap();
    let err = load_anchor::<Minimal>(dir.path())
        .expect_err("a state.ssz with another sha256 must not load");
    assert!(matches!(err, AnchorError::File { .. }), "{err}");
}
