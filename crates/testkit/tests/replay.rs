//! Acceptance tests for devnet replay from genesis.
//!
//! The pinned export is the chain [`chain::genesis_and_blocks`] writes. It is a minimal Gloas
//! chain from this crate, not a Kurtosis capture: no enclave export is in the tree.

#[path = "support/chain.rs"]
mod chain;

use consensus_types::gloas::BeaconState;
use consensus_types::Minimal;
use ssz::Decode;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use testkit::replay::{replay_pin, ReplayError, BLOCK_SSZ, POST_STATE_SSZ, PRE_STATE_SSZ};
use tree_hash::TreeHash;

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn pin_path() -> PathBuf {
    workspace().join("testing/replay.manifest.toml")
}

fn hex_sha(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_pin(dir: &Path, export_dir: &Path, sha: &[u8; 32]) -> PathBuf {
    let config = dir.join("config.yaml");
    fs::write(&config, chain::CONFIG).unwrap();
    let manifest = dir.join("replay.manifest.toml");
    let export = path_from(&manifest, export_dir);
    let config_rel = path_from(&manifest, &config);
    fs::write(
        &manifest,
        format!(
            "export = \"{}\"\nexport_sha256 = \"{}\"\nconfig = \"{}\"\n",
            export.display(),
            hex_sha(sha),
            config_rel.display()
        ),
    )
    .unwrap();
    manifest
}

/// A path `manifest` can name. Absolute, so the pin does not depend on the process cwd.
fn path_from(manifest: &Path, target: &Path) -> PathBuf {
    let _ = manifest;
    target.to_owned()
}

/// `refuses_bad_manifest`: a flipped manifest byte makes `open_verified` fail and stops
/// the run before the first block.
#[test]
fn refuses_bad_manifest() {
    let pin = load_committed_pin();
    let scratch = tempfile::tempdir().unwrap();
    let export = scratch.path().join(chain::DEVNET);
    copy_dir(&pin.export_dir, &export);
    flip_segment_manifest(&export);
    let manifest = write_pin(scratch.path(), &export, &pin.sha);
    let out = scratch.path().join("out");
    let err = replay_pin(&manifest, &out).expect_err("a flipped manifest must fail");
    assert!(err.before_first_block(), "replay started despite {err}");
    assert!(
        err.open_verified_failed(),
        "expected open_verified to fail, got {err}"
    );
    assert!(
        !out.exists(),
        "mismatch files were written before the first block"
    );
}

/// `stops_at_first_mismatch`: a tampered `state_root` exits non-zero and writes the three
/// SSZ files. The export still opens: the block is re-signed and re-exported, so the
/// archive hashes match and the failure is the transition.
#[tokio::test]
async fn stops_at_first_mismatch() {
    let (genesis, mut blocks) = chain::genesis_and_blocks();
    let last = blocks.len() - 1;
    let slot = blocks[last].message.slot;
    chain::tamper_state_root(&genesis, &mut blocks[last]);
    let scratch = tempfile::tempdir().unwrap();
    let exported = chain::export_chain(&genesis, &blocks, scratch.path()).await;
    let manifest = write_pin(scratch.path(), exported.dir(), &exported.export_sha256());
    let out = scratch.path().join("out");
    let err = replay_pin(&manifest, &out).expect_err("a tampered state root must fail");
    assert!(
        !err.before_first_block(),
        "stopped before the first block: {err}"
    );
    match &err {
        ReplayError::Mismatch {
            slot: got, detail, ..
        } => {
            assert_eq!(*got, slot);
            assert!(
                detail.contains("state root"),
                "the tampered state_root must fail the post-state check, got {detail}"
            );
        }
        other => panic!("expected a mismatch, got {other}"),
    }
    let pre = BeaconState::<Minimal>::from_ssz_bytes(&fs::read(out.join(PRE_STATE_SSZ)).unwrap())
        .unwrap();
    let block = consensus_types::gloas::SignedBeaconBlock::<Minimal>::from_ssz_bytes(
        &fs::read(out.join(BLOCK_SSZ)).unwrap(),
    )
    .unwrap();
    let post = BeaconState::<Minimal>::from_ssz_bytes(&fs::read(out.join(POST_STATE_SSZ)).unwrap())
        .unwrap();
    assert_eq!(block.message.slot, slot);
    assert_eq!(
        block.message.state_root,
        consensus_types::primitives::Root::repeat_byte(0xab)
    );
    assert_eq!(post.slot, slot);
    assert_ne!(post.tree_hash_root(), block.message.state_root);
    assert!(pre.slot < slot);
    let ssz = fs::read_dir(&out).unwrap().filter_map(|e| e.ok()).count();
    assert_eq!(
        ssz, 3,
        "the mismatch writes the three SSZ files and nothing else"
    );
}

/// The pinned export replays from genesis and crosses at least two epoch boundaries.
#[test]
fn replays_pinned_export() {
    let root = workspace();
    let out = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_replay");
    let output = Command::new(bin)
        .arg("--manifest")
        .arg(pin_path())
        .arg("--out")
        .arg(out.path())
        .current_dir(&root)
        .output()
        .expect("run replay");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "replay failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(field(&stdout, "blocks"), 16, "{stdout}");
    assert_eq!(field(&stdout, "epochs_crossed"), 2, "{stdout}");
    assert_eq!(field(&stdout, "full_parents"), 1, "{stdout}");
    assert_eq!(field(&stdout, "empty_parents"), 14, "{stdout}");
    assert_eq!(field(&stdout, "self_build"), 15, "{stdout}");
    assert_eq!(field(&stdout, "builder_bids"), 0, "{stdout}");
    assert!(
        stdout.contains("flag: builder_bids=0 for adversarial devnet [5.32]"),
        "{stdout}"
    );
    assert!(!stdout.contains("flag: full_parents"), "{stdout}");
    assert!(!stdout.contains("flag: empty_parents"), "{stdout}");
    assert!(!stdout.contains("flag: self_build"), "{stdout}");
    assert!(!out.path().join(PRE_STATE_SSZ).exists());
}

/// The bytes under `testing/replay/` are the chain [`chain::genesis_and_blocks`] exports.
#[tokio::test]
async fn pinned_export_matches_generator() {
    let scratch = tempfile::tempdir().unwrap();
    let (genesis, blocks) = chain::genesis_and_blocks();
    let exported = chain::export_chain(&genesis, &blocks, scratch.path()).await;
    let pin = load_committed_pin();
    assert_eq!(
        exported.export_sha256(),
        pin.sha,
        "regenerated export_sha256 is {}\ncommitted pin is {}\nrewrite with REPLAY_WRITE_FIXTURE=1",
        hex_sha(&exported.export_sha256()),
        hex_sha(&pin.sha)
    );
    let committed = fs::read(pin.export_dir.join("genesis_state.ssz")).unwrap();
    let fresh = fs::read(exported.dir().join("genesis_state.ssz")).unwrap();
    assert_eq!(committed, fresh);
}

/// Writes `testing/replay/` and `testing/replay.manifest.toml`.
///
/// `REPLAY_WRITE_FIXTURE=1 cargo test -p testkit --test replay write_fixture_when_asked -- --ignored --exact`
#[tokio::test]
#[ignore = "rewrites testing/replay; set REPLAY_WRITE_FIXTURE=1"]
async fn write_fixture_when_asked() {
    if std::env::var_os("REPLAY_WRITE_FIXTURE").is_none() {
        return;
    }
    let root = workspace();
    let replay_dir = root.join("testing/replay");
    let export_dir = replay_dir.join(chain::DEVNET);
    if export_dir.exists() {
        fs::remove_dir_all(&export_dir).unwrap();
    }
    fs::create_dir_all(&replay_dir).unwrap();
    fs::write(replay_dir.join("config.yaml"), chain::CONFIG).unwrap();
    let (genesis, blocks) = chain::genesis_and_blocks();
    let exported = chain::export_chain(&genesis, &blocks, &replay_dir).await;
    let sha = hex_sha(&exported.export_sha256());
    let manifest = format!(
        "\
# Pin of the export `replay` and `.github/workflows/replay-nightly.yml` run.
# Paths are relative to this file. A change here is the only way the nightly input changes.
# The chain is the minimal Gloas fixture from crates/testkit/tests/support/chain.rs
# (slots 0..={last}, empty slot {empty}, two epoch boundaries). It is not a Kurtosis capture.
export = \"replay/{devnet}\"
export_sha256 = \"{sha}\"
config = \"replay/config.yaml\"
",
        last = chain::LAST_SLOT,
        empty = chain::EMPTY_SLOT,
        devnet = chain::DEVNET,
    );
    fs::write(root.join("testing/replay.manifest.toml"), manifest).unwrap();
    println!("wrote testing/replay.manifest.toml export_sha256 {sha}");
}

struct CommittedPin {
    export_dir: PathBuf,
    sha: [u8; 32],
}

fn load_committed_pin() -> CommittedPin {
    let path = pin_path();
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut export = None;
    let mut sha = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("export = ") {
            export = Some(rest.trim_matches('"').to_owned());
        } else if let Some(rest) = line.strip_prefix("export_sha256 = ") {
            sha = Some(rest.trim_matches('"').to_owned());
        }
    }
    let export = export.expect("export");
    let sha_text = sha.expect("export_sha256");
    let mut sha = [0u8; 32];
    for (i, byte) in sha.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&sha_text[2 * i..2 * i + 2], 16).expect("hex");
    }
    let export_dir = path.parent().unwrap().join(export);
    CommittedPin { export_dir, sha }
}

fn field(report: &str, name: &str) -> u64 {
    report
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .unwrap_or_else(|| panic!("no {name} in {report}"))
        .trim()
        .parse()
        .unwrap()
}

fn flip_segment_manifest(export: &Path) {
    let mut manifest = None;
    for entry in fs::read_dir(export).unwrap() {
        let path = entry.unwrap().path().join("manifest.toml");
        if path.is_file() {
            manifest = Some(path);
            break;
        }
    }
    let path = manifest.expect("segment manifest.toml");
    let mut bytes = fs::read(&path).unwrap();
    let newline = bytes.iter().position(|b| *b == b'\n').expect("header line");
    let at = newline + 8;
    assert!(at < bytes.len(), "manifest body is shorter than 8 bytes");
    bytes[at] ^= 0x01;
    fs::write(&path, bytes).unwrap();
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        let ty = entry.file_type().unwrap();
        if ty.is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}
