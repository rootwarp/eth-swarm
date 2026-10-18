//! Exports from a fixture beacon node: a Minimal-preset chain with Fulu from genesis and Gloas
//! from [`GLOAS_SLOT`], served over HTTP on 127.0.0.1.

use super::fixtures::{self, chain, config, config_sha256, Devnet, GENESIS_TIME, IMAGE};
use super::*;
use crate::archive::fixtures::{Spec, GLOAS_SLOT};
use crate::archive::open_verified;
use crate::collector::testing::{FixtureServer, Reply};
use consensus_types::primitives::{Root, Slot, B256};
use ssz::Encode;
use std::path::Path;

pub(super) async fn run(devnet: Devnet, to: Slot, out: &Path) -> Result<Export, ExportError> {
    let (server, _) = devnet.serve().await;
    export::<Spec>(&server.url(""), &chain(), &config(to), out).await
}

#[tokio::test]
async fn empty_slot_recorded() {
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(20, &[3, GLOAS_SLOT]);
    let (r2, r4) = (devnet.root(2), devnet.root(4));
    let export = run(devnet.clone(), 20, out.path()).await.unwrap();
    let m = export.manifest();
    assert_eq!(m.empty_slots, vec![3, GLOAS_SLOT]);
    assert_eq!(m.blocks.len(), 21 - 2);
    let at4 = m.blocks.iter().find(|b| b.slot == 4).unwrap();
    assert_eq!(at4.parent_root, r2, "the parent chain spans the empty slot");
    assert_eq!(at4.root, r4);
    let list = export.root_list();
    assert_eq!(list.len(), 21);
    assert_eq!(list[3], None);
    assert_eq!(list[GLOAS_SLOT as usize], None);
    assert_eq!(list[4], Some(r4));
    for (slot, root) in list.iter().enumerate() {
        if let Some(root) = root {
            assert_eq!(*root, devnet.root(slot as Slot), "slot {slot}");
        }
    }
    // Reopened from disk, the manifest and its chain verify again.
    let reopened = open_export(&out.path().join("fixture-devnet")).unwrap();
    assert_eq!(reopened.manifest(), m);
    assert_eq!(reopened.export_sha256(), export.export_sha256());
}

#[tokio::test]
async fn open_verified_opens_the_exported_segment() {
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(20, &[5]);
    let export = run(devnet.clone(), 20, out.path()).await.unwrap();
    let m = export.manifest();
    assert_eq!(m.segments.len(), 1);
    let segment = open_verified(&export.dir().join(&m.segments[0].dir)).unwrap();
    assert_eq!(segment.archive_sha256(), m.segments[0].archive_sha256);
    assert_eq!(segment.manifest().network, "fixture-devnet");
    assert_eq!(segment.files().len(), m.blocks.len());
    for block in &m.blocks {
        let ssz = export.block_ssz(block).unwrap();
        assert_eq!(ssz, devnet.blocks[&block.slot].ssz, "slot {}", block.slot);
    }
}

#[tokio::test]
async fn genesis_state_root_is_recorded() {
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(4, &[]);
    let export = run(devnet.clone(), 4, out.path()).await.unwrap();
    let m = export.manifest();
    assert_eq!(m.genesis_state_root, devnet.state_root);
    assert_eq!(m.genesis_block_root, devnet.root(0));
    assert_eq!(m.genesis_time, GENESIS_TIME);
    assert_eq!(m.genesis_validators_root, B256::repeat_byte(0x42));
    assert_eq!(export.genesis_state_ssz().unwrap(), devnet.state);
    assert_eq!(m.genesis_state.len, devnet.state.len() as u64);
    assert_eq!(m.config_sha256, config_sha256());
    assert_eq!(m.images, vec![IMAGE.to_owned()]);
    assert_eq!((m.slot_start, m.slot_end, m.finalized_slot), (0, 4, 12));
    assert_eq!(m.preset, "minimal");
    assert_eq!(m.source, "cl-1-lighthouse-geth");
    let forks: Vec<_> = m.fork_schedule.iter().map(|f| (f.fork, f.epoch)).collect();
    assert_eq!(
        forks,
        vec![
            (consensus_types::ForkName::Fulu, 0),
            (consensus_types::ForkName::Gloas, 2)
        ]
    );
    // Slots 0..=4 are epoch 0: only the genesis digest is in force.
    assert_eq!(m.fork_digests.len(), 1);
    assert_eq!(m.fork_digests[0].epoch, 0);
}

/// The export failed and left no export behind: the directory has no `export.toml`, so it
/// never opens as one.
fn assert_no_export(out: &Path) {
    let dir = out.join("fixture-devnet");
    assert!(!dir.join(EXPORT_FILE).exists(), "no export.toml");
    assert!(
        open_export(&dir).is_err(),
        "the failed export does not open"
    );
}

#[tokio::test]
async fn root_mismatch_fails() {
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(6, &[]);
    let computed = devnet.root(2);
    let api = B256::repeat_byte(0xee);
    devnet.blocks.get_mut(&2).unwrap().api_root = api;
    let err = run(devnet, 6, out.path()).await.unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::RootMismatch { slot: 2, api: a, computed: c } if a == api && c == computed
        ),
        "{err}"
    );
    assert_no_export(out.path());
}

#[tokio::test]
async fn a_broken_parent_chain_fails() {
    // Slot 5's parent is slot 3, skipping slot 4.
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(8, &[]);
    let (r3, r4) = (devnet.root(3), devnet.root(4));
    devnet.reparent(5, r3, B256::repeat_byte(5));
    let err = run(devnet, 8, out.path()).await.unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::ParentMismatch { slot: 5, parent_root, expected_slot: 4, expected }
                if parent_root == r3 && expected == r4
        ),
        "{err}"
    );
    assert_no_export(out.path());

    // Across an empty slot: slot 4 is empty, so slot 5's parent must be slot 3.
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(8, &[4]);
    let r2 = devnet.root(2);
    devnet.reparent(5, r2, B256::repeat_byte(5));
    let err = run(devnet, 8, out.path()).await.unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::ParentMismatch {
                slot: 5,
                expected_slot: 3,
                ..
            }
        ),
        "{err}"
    );
}

#[tokio::test]
async fn the_genesis_block_must_commit_to_the_genesis_state() {
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(2, &[]);
    devnet.reparent(0, Root::ZERO, B256::repeat_byte(0x99));
    let err = run(devnet, 2, out.path()).await.unwrap_err();
    assert!(
        matches!(&err, ExportError::Genesis(m) if m.contains("state_root")),
        "{err}"
    );

    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(2, &[]);
    let state_root = devnet.state_root;
    devnet.reparent(0, B256::repeat_byte(1), state_root);
    let err = run(devnet, 2, out.path()).await.unwrap_err();
    assert!(
        matches!(&err, ExportError::Genesis(m) if m.contains("parent")),
        "{err}"
    );

    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(2, &[]);
    devnet.blocks.remove(&0);
    let err = run(devnet, 2, out.path()).await.unwrap_err();
    assert!(
        matches!(&err, ExportError::Genesis(m) if m.contains("slot 0")),
        "{err}"
    );
}

/// Serves `devnet`, but answers `replies` for their paths.
async fn serve_with(devnet: Devnet, replies: Vec<(String, Reply)>) -> FixtureServer {
    FixtureServer::start(move |_, path| {
        replies
            .iter()
            .find(|(p, _)| p == path)
            .map_or_else(|| devnet.reply(path), |(_, r)| r.clone())
    })
    .await
}

#[tokio::test]
async fn the_genesis_state_is_read_by_its_root() {
    // As Lodestar without --serveHistoricalState: no state by the `genesis` id or slot 0, only
    // by its root (the genesis block's state_root).
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(4, &[]);
    let refused = Reply::status(500);
    let server = serve_with(
        devnet.clone(),
        vec![
            (
                "/eth/v2/debug/beacon/states/genesis".into(),
                refused.clone(),
            ),
            ("/eth/v2/debug/beacon/states/0".into(), refused),
        ],
    )
    .await;
    let export = export::<Spec>(&server.url(""), &chain(), &config(4), out.path())
        .await
        .unwrap();
    assert_eq!(export.genesis_state_ssz().unwrap(), devnet.state);
    assert_eq!(export.manifest().genesis_state_root, devnet.state_root);
}

#[tokio::test]
async fn a_genesis_state_request_failure_names_the_endpoint_only() {
    const KEY: &str = "/key-hunter2";
    let devnet = Devnet::new(4, &[]);
    let by_root = format!("/eth/v2/debug/beacon/states/{}", devnet.state_root);
    for reply in [Reply::status(500), Reply::status(503)] {
        let out = tempfile::tempdir().unwrap();
        let (devnet, by_root) = (devnet.clone(), by_root.clone());
        let server = FixtureServer::start(move |_, path| {
            let path = path.strip_prefix(KEY).unwrap_or(path);
            if path == by_root {
                reply.clone()
            } else {
                devnet.reply(path)
            }
        })
        .await;
        let err = export::<Spec>(&server.url(KEY), &chain(), &config(4), out.path())
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains(GENESIS_STATE_PATH), "{text}");
        assert!(
            !text.contains("hunter2") && !text.contains("127.0.0.1"),
            "{text}"
        );
    }

    // A state served for the root that hashes to another root.
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(4, &[]);
    let mut other = fixtures::genesis_state();
    other.genesis_time += 1;
    let (state_root, by_root) = (devnet.state_root, by_root.clone());
    devnet.state = other.as_ssz_bytes();
    let server = serve_with(
        devnet.clone(),
        vec![(by_root, Reply::ssz(devnet.state.clone()))],
    )
    .await;
    let err = export::<Spec>(&server.url(""), &chain(), &config(4), out.path())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ExportError::Genesis(m) if m.contains(&state_root.to_string())),
        "{err}"
    );
}

#[tokio::test]
async fn a_block_404_with_a_served_root_fails() {
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(6, &[]);
    let hidden = devnet.root(3);
    let server = serve_with(
        devnet,
        vec![("/eth/v2/beacon/blocks/3".into(), Reply::status(404))],
    )
    .await;
    let err = export::<Spec>(&server.url(""), &chain(), &config(6), out.path())
        .await
        .unwrap_err();
    assert!(
        matches!(err, ExportError::HiddenBlock { slot: 3, root } if root == hidden),
        "{err}"
    );
    assert_no_export(out.path());
}

#[tokio::test]
async fn a_trailing_block_hidden_behind_404s_fails_against_the_finalized_chain() {
    // The CL hides slot 6, block and root: inside the export it looks empty, but the next
    // block on the way to the finalized one has it as its parent.
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(6, &[]);
    let (r5, r6) = (devnet.root(5), devnet.root(6));
    let server = serve_with(
        devnet,
        vec![
            ("/eth/v2/beacon/blocks/6".into(), Reply::status(404)),
            ("/eth/v1/beacon/blocks/6/root".into(), Reply::status(404)),
        ],
    )
    .await;
    let err = export::<Spec>(&server.url(""), &chain(), &config(6), out.path())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::ParentMismatch { slot: 7, parent_root, expected_slot: 5, expected }
                if parent_root == r6 && expected == r5
        ),
        "{err}"
    );
    assert_no_export(out.path());
}

#[tokio::test]
async fn the_export_is_anchored_at_the_finalized_block() {
    // The finalized header names a root that is not the chain's block at its slot.
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(4, &[]);
    let finalized = devnet.finalized;
    let chain_root = devnet.root(finalized);
    let header = fixtures::finalized_header(finalized, B256::repeat_byte(0xfa));
    let server = serve_with(
        devnet,
        vec![(FINALIZED_HEADER_PATH.into(), Reply::json(&header))],
    )
    .await;
    let err = export::<Spec>(&server.url(""), &chain(), &config(4), out.path())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::FinalizedMismatch { slot, root, chain_slot, chain_root: c }
                if slot == finalized && root == B256::repeat_byte(0xfa)
                    && chain_slot == finalized && c == chain_root
        ),
        "{err}"
    );
    assert_no_export(out.path());

    // The finalized block is not at the header's slot: the chain's last block is earlier.
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(4, &[]);
    let finalized = devnet.finalized;
    devnet.blocks.remove(&finalized);
    let last = devnet.root(finalized - 1);
    let header = fixtures::finalized_header(finalized, last);
    let server = serve_with(
        devnet,
        vec![(FINALIZED_HEADER_PATH.into(), Reply::json(&header))],
    )
    .await;
    let err = export::<Spec>(&server.url(""), &chain(), &config(4), out.path())
        .await
        .unwrap_err();
    assert!(
        matches!(err, ExportError::FinalizedMismatch { chain_slot, .. } if chain_slot == finalized - 1),
        "{err}"
    );

    // An export to the finalized slot itself ends on the finalized block.
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(4, &[]);
    let finalized = devnet.finalized;
    let export = run(devnet.clone(), finalized, out.path()).await.unwrap();
    assert_eq!(
        export.manifest().blocks.last().unwrap().root,
        devnet.root(finalized)
    );
}

#[tokio::test]
async fn blocks_decode_by_the_fork_of_their_own_slot() {
    // Both forks export: Fulu blocks before GLOAS_SLOT, Gloas blocks from it.
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(GLOAS_SLOT + 2, &[]);
    let export = run(devnet, GLOAS_SLOT + 2, out.path()).await.unwrap();
    assert_eq!(export.manifest().blocks.len() as u64, GLOAS_SLOT + 3);
    let epochs: Vec<_> = export
        .manifest()
        .fork_digests
        .iter()
        .map(|d| d.epoch)
        .collect();
    assert_eq!(
        epochs,
        vec![0, 1, 2],
        "the genesis, blob-parameter and Gloas digests"
    );

    // The server serves Fulu bytes at a Gloas slot: decoded as Gloas, they are refused.
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(GLOAS_SLOT + 2, &[]);
    let wrong = p2p_wire::testkit::fulu_block::<Spec>(GLOAS_SLOT + 1);
    devnet.blocks.get_mut(&(GLOAS_SLOT + 1)).unwrap().ssz = wrong.as_ssz_bytes();
    let err = run(devnet, GLOAS_SLOT + 2, out.path()).await.unwrap_err();
    let slot = Some(GLOAS_SLOT + 1);
    assert!(
        matches!(err, ExportError::Decode { what: "block", slot: s, .. } if s == slot),
        "{err}"
    );
    assert_no_export(out.path());

    // And Gloas bytes at a Fulu slot.
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(4, &[]);
    let wrong = p2p_wire::testkit::gloas_block::<Spec>(2);
    devnet.blocks.get_mut(&2).unwrap().ssz = wrong.as_ssz_bytes();
    let err = run(devnet, 4, out.path()).await.unwrap_err();
    assert!(
        matches!(err, ExportError::Decode { slot: Some(2), .. }),
        "{err}"
    );
}

#[tokio::test]
async fn a_block_of_another_slot_fails() {
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(4, &[]);
    let other = devnet.blocks[&3].clone();
    devnet.blocks.insert(2, other);
    let err = run(devnet, 4, out.path()).await.unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::SlotMismatch {
                what: "block",
                requested: 2,
                got: 3
            }
        ),
        "{err}"
    );
}

#[tokio::test]
async fn oversized_and_truncated_bodies_are_refused() {
    use consensus_types::caps::MAX_PAYLOAD_SIZE;

    // One byte over MAX_PAYLOAD_SIZE: never read past the bound.
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(3, &[]);
    devnet.blocks.get_mut(&1).unwrap().ssz = vec![0; MAX_PAYLOAD_SIZE + 1];
    let err = run(devnet, 3, out.path()).await.unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::TooLarge {
                path: BLOCK_PATH,
                slot: Some(1),
                max: MAX_PAYLOAD_SIZE
            }
        ),
        "{err}"
    );
    assert_no_export(out.path());

    // A truncated block.
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(3, &[]);
    devnet.blocks.get_mut(&2).unwrap().ssz.pop();
    let err = run(devnet, 3, out.path()).await.unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::Decode {
                what: "block",
                slot: Some(2),
                ..
            }
        ),
        "{err}"
    );

    // A genesis state over the configured bound, and a truncated one.
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(3, &[]);
    let (server, _) = devnet.clone().serve().await;
    let mut small = config(3);
    small.max_state_bytes = devnet.state.len() - 1;
    let err = export::<Spec>(&server.url(""), &chain(), &small, out.path())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::TooLarge {
                path: GENESIS_STATE_PATH,
                slot: None,
                ..
            }
        ),
        "{err}"
    );
    let out = tempfile::tempdir().unwrap();
    let mut devnet = Devnet::new(3, &[]);
    devnet.state.truncate(100);
    let err = run(devnet, 3, out.path()).await.unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::Decode {
                what: "genesis state",
                ..
            }
        ),
        "{err}"
    );

    // A root answer over the JSON bound.
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(3, &[]);
    let server = FixtureServer::start(move |_, path| {
        if path == "/eth/v1/beacon/blocks/1/root" {
            Reply::json(&" ".repeat(crate::collector::MAX_JSON_BYTES + 1))
        } else {
            devnet.reply(path)
        }
    })
    .await;
    let err = export::<Spec>(&server.url(""), &chain(), &config(3), out.path())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::TooLarge {
                path: BLOCK_ROOT_PATH,
                slot: Some(1),
                ..
            }
        ),
        "{err}"
    );
}

#[tokio::test]
async fn two_exports_of_one_chain_have_identical_root_lists() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let devnet = Devnet::new(12, &[4, 9]);
    let ea = run(devnet.clone(), 12, a.path()).await.unwrap();
    let eb = run(devnet.clone(), 12, b.path()).await.unwrap();
    assert_eq!(
        diff_root_lists(&ea.root_list(), &eb.root_list()),
        RootListDiff::Identical { slots: 13 }
    );

    // The second CL saw another block at slot 6, and everything after it differs too.
    let c = tempfile::tempdir().unwrap();
    let mut other = devnet.clone();
    let r5 = other.root(5);
    other.reparent(6, r5, B256::repeat_byte(0x66));
    other.rechain(6);
    let ec = run(other.clone(), 12, c.path()).await.unwrap();
    assert_eq!(
        diff_root_lists(&ea.root_list(), &ec.root_list()),
        RootListDiff::Differ {
            slot: 6,
            a: SlotEntry::Block(devnet.root(6)),
            b: SlotEntry::Block(other.root(6)),
        }
    );
}

#[test]
fn the_root_list_diff_names_the_first_differing_slot() {
    let r = |b: u8| Some(B256::repeat_byte(b));
    let a = [r(1), None, r(3)];
    assert_eq!(
        diff_root_lists(&a, &a),
        RootListDiff::Identical { slots: 3 }
    );
    assert_eq!(
        diff_root_lists(&[], &[]),
        RootListDiff::Identical { slots: 0 }
    );
    assert_eq!(
        diff_root_lists(&a, &[r(1), r(2), r(3)]),
        RootListDiff::Differ {
            slot: 1,
            a: SlotEntry::Empty,
            b: SlotEntry::Block(B256::repeat_byte(2)),
        }
    );
    assert_eq!(
        diff_root_lists(&a, &a[..2]),
        RootListDiff::Differ {
            slot: 2,
            a: SlotEntry::Block(B256::repeat_byte(3)),
            b: SlotEntry::NotExported,
        }
    );
    assert_eq!(
        diff_root_lists(&a[..1], &a),
        RootListDiff::Differ {
            slot: 1,
            a: SlotEntry::NotExported,
            b: SlotEntry::Empty,
        }
    );
}

#[tokio::test]
async fn an_export_is_refused_before_it_starts() {
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(4, &[]);
    let (server, seen) = devnet.clone().serve().await;
    let url = server.url("");
    let refuse = |c: ExportConfig| {
        let url = url.clone();
        let out = out.path().to_owned();
        async move { export::<Spec>(&url, &chain(), &c, &out).await.unwrap_err() }
    };

    let mut c = config(4);
    c.images.clear();
    assert!(matches!(refuse(c).await, ExportError::Config(_)));
    let mut c = config(4);
    c.images = vec!["ethereum/client-go:v1.17.8".into()];
    assert!(matches!(refuse(c).await, ExportError::Config(_)));
    let mut c = config(4);
    c.source = "two words".into();
    assert!(matches!(refuse(c).await, ExportError::Config(_)));
    let mut c = config(4);
    c.devnet = "../up".into();
    assert!(matches!(refuse(c).await, ExportError::Config(_)));
    let mut c = config(4);
    c.to_slot = u64::MAX;
    assert!(matches!(refuse(c).await, ExportError::Config(_)));
    let mut c = config(4);
    c.max_state_bytes = MAX_GENESIS_STATE_BYTES as usize + 1;
    assert!(
        matches!(refuse(c).await, ExportError::Config(m) if m.contains("max_state_bytes")),
        "a state bound over what open_export reads"
    );
    let err = export::<consensus_types::Mainnet>(&url, &chain(), &config(4), out.path())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ExportError::Config(m) if m.contains("preset")),
        "{err}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "no request before the config is checked"
    );

    // Past the finalized block (slot 12).
    let err = refuse(config(13)).await;
    assert!(
        matches!(
            err,
            ExportError::NotFinalized {
                to: 13,
                finalized: 12
            }
        ),
        "{err}"
    );

    // Never into an earlier export.
    std::fs::create_dir(out.path().join("fixture-devnet")).unwrap();
    assert!(matches!(refuse(config(4)).await, ExportError::Exists(_)));
}

#[tokio::test]
async fn concurrent_exports_into_one_directory_one_wins() {
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(6, &[2]);
    let (a, _) = devnet.clone().serve().await;
    let (b, _) = devnet.serve().await;
    let (url_a, url_b) = (a.url(""), b.url(""));
    let (chain, config) = (chain(), config(6));
    let (ra, rb) = tokio::join!(
        export::<Spec>(&url_a, &chain, &config, out.path()),
        export::<Spec>(&url_b, &chain, &config, out.path()),
    );
    let (won, lost) = match (ra, rb) {
        (Ok(won), Err(lost)) | (Err(lost), Ok(won)) => (won, lost),
        (a, b) => panic!("exactly one export wins: {:?} {:?}", a.err(), b.err()),
    };
    assert!(matches!(lost, ExportError::Exists(_)), "{lost}");
    let entries: Vec<String> = std::fs::read_dir(won.dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries
            .iter()
            .all(|e| !e.starts_with(crate::archive::OPEN_PREFIX)),
        "{entries:?}"
    );
    open_export(won.dir()).unwrap();
}

#[tokio::test]
async fn api_failures_stop_the_export_without_quoting_the_url() {
    const KEY: &str = "/key-hunter2";
    let cases: [(&str, Reply); 8] = [
        ("/eth/v2/beacon/blocks/2", Reply::status(500)),
        ("/eth/v1/beacon/blocks/2/root", Reply::status(500)),
        ("/eth/v2/beacon/blocks/2", Reply::json("{}")),
        (
            "/eth/v1/beacon/blocks/2/root",
            Reply::json(r#"{"data":{"root":"0xAB"}}"#),
        ),
        ("/eth/v1/beacon/blocks/2/root", Reply::status(404)),
        ("/eth/v1/beacon/blocks/2/root", Reply::json("hunter2")),
        (
            FINALIZED_HEADER_PATH,
            Reply::json(&fixtures::finalized_header(9, Root::ZERO).replace("\"9\"", "\"+9\"")),
        ),
        (
            FINALIZED_HEADER_PATH,
            Reply::json(r#"{"data":{"root":"0xAB","header":{"message":{"slot":"9"}}}}"#),
        ),
    ];
    for (broken, reply) in cases {
        let out = tempfile::tempdir().unwrap();
        let devnet = Devnet::new(4, &[]);
        let server = FixtureServer::start(move |_, path| {
            let path = path.strip_prefix(KEY).unwrap_or(path);
            if path == broken {
                reply.clone()
            } else {
                devnet.reply(path)
            }
        })
        .await;
        let err = export::<Spec>(&server.url(KEY), &chain(), &config(4), out.path())
            .await
            .unwrap_err();
        assert!(matches!(err, ExportError::Api { .. }), "{broken}: {err}");
        let text = err.to_string();
        assert!(!text.contains("hunter2"), "{broken}: {text}");
        if broken != FINALIZED_HEADER_PATH {
            assert!(text.starts_with("slot 2: "), "{broken}: {text}");
        }
    }
}

/// An export of a short chain, and its directory.
async fn exported(out: &Path) -> (Export, std::path::PathBuf) {
    let export = run(Devnet::new(6, &[2]), 6, out).await.unwrap();
    let dir = export.dir().to_owned();
    (export, dir)
}

/// Rewrites `export.toml` from `edit` of the export's manifest, digest and all.
fn rewrite(export: &Export, edit: impl FnOnce(&mut ExportManifest)) {
    let mut m = export.manifest().clone();
    edit(&mut m);
    let (bytes, _) = m.render().unwrap();
    std::fs::write(export.dir().join(EXPORT_FILE), bytes).unwrap();
}

#[tokio::test]
async fn open_export_refuses_a_tampered_export() {
    use crate::archive::ArchiveError;
    use std::fs;

    // A changed block file: the segment fails open_verified.
    let out = tempfile::tempdir().unwrap();
    let (export, dir) = exported(out.path()).await;
    let segment = dir.join(&export.manifest().segments[0].dir);
    let file = open_verified(&segment).unwrap().files()[0].path.clone();
    let path = segment.join(file);
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(&path, bytes).unwrap();
    let err = open_export(&dir).unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::Archive(ArchiveError::Sha256Mismatch { .. })
        ),
        "{err}"
    );

    // A changed genesis state.
    let out = tempfile::tempdir().unwrap();
    let (_, dir) = exported(out.path()).await;
    let state = dir.join(GENESIS_STATE_FILE);
    let mut bytes = fs::read(&state).unwrap();
    bytes[0] ^= 1;
    fs::write(&state, &bytes).unwrap();
    let err = open_export(&dir).unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::Archive(ArchiveError::Sha256Mismatch { .. })
        ),
        "{err}"
    );
    bytes.push(0);
    fs::write(&state, &bytes).unwrap();
    let err = open_export(&dir).unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::Archive(ArchiveError::LengthMismatch { .. })
        ),
        "{err}"
    );

    // A changed manifest byte.
    let out = tempfile::tempdir().unwrap();
    let (_, dir) = exported(out.path()).await;
    let manifest = dir.join(EXPORT_FILE);
    let mut bytes = fs::read(&manifest).unwrap();
    let last = bytes.len() - 2;
    bytes[last] ^= 1;
    fs::write(&manifest, bytes).unwrap();
    assert!(matches!(
        open_export(&dir).unwrap_err(),
        ExportError::Manifest { .. }
    ));

    // An extra file, and a leftover unsealed segment.
    let out = tempfile::tempdir().unwrap();
    let (_, dir) = exported(out.path()).await;
    fs::write(dir.join("notes.txt"), b"x").unwrap();
    assert!(matches!(
        open_export(&dir).unwrap_err(),
        ExportError::Archive(ArchiveError::ExtraFile(name)) if name == "notes.txt"
    ));
    fs::remove_file(dir.join("notes.txt")).unwrap();
    fs::create_dir(dir.join(".open-0-1")).unwrap();
    assert!(matches!(
        open_export(&dir).unwrap_err(),
        ExportError::Archive(ArchiveError::ExtraFile(_))
    ));

    // A directory not named for the devnet.
    let out = tempfile::tempdir().unwrap();
    let (_, dir) = exported(out.path()).await;
    let moved = out.path().join("other-devnet");
    fs::rename(&dir, &moved).unwrap();
    assert!(matches!(
        open_export(&moved).unwrap_err(),
        ExportError::Mismatch(_)
    ));

    // No manifest at all, and not a directory.
    let out = tempfile::tempdir().unwrap();
    let (_, dir) = exported(out.path()).await;
    fs::remove_file(dir.join(EXPORT_FILE)).unwrap();
    assert!(matches!(
        open_export(&dir).unwrap_err(),
        ExportError::Archive(ArchiveError::MissingFile(_))
    ));
    assert!(matches!(
        open_export(&dir.join(GENESIS_STATE_FILE)).unwrap_err(),
        ExportError::Archive(ArchiveError::NotRegular(_))
    ));
}

#[tokio::test]
async fn open_export_checks_the_segments_against_the_manifest() {
    // A rehashed manifest with another segment digest.
    let out = tempfile::tempdir().unwrap();
    let (export, dir) = exported(out.path()).await;
    rewrite(&export, |m| m.segments[0].archive_sha256 = [0; 32]);
    let err = open_export(&dir).unwrap_err();
    assert!(
        matches!(&err, ExportError::Mismatch(m) if m.contains("archive_sha256")),
        "{err}"
    );

    // A rehashed manifest whose last block root is not the archived one.
    let out = tempfile::tempdir().unwrap();
    let (export, dir) = exported(out.path()).await;
    rewrite(&export, |m| {
        m.blocks.last_mut().unwrap().root = B256::repeat_byte(0xab)
    });
    let err = open_export(&dir).unwrap_err();
    assert!(
        matches!(&err, ExportError::Mismatch(m) if m.contains("block files")),
        "{err}"
    );

    // A rehashed manifest of another preset.
    let out = tempfile::tempdir().unwrap();
    let (export, dir) = exported(out.path()).await;
    rewrite(&export, |m| m.preset = "mainnet".into());
    let err = open_export(&dir).unwrap_err();
    assert!(
        matches!(&err, ExportError::Mismatch(m) if m.contains("preset")),
        "{err}"
    );

    // Only the manifest's blocks are read.
    let out = tempfile::tempdir().unwrap();
    let (export, _) = exported(out.path()).await;
    let mut forged = export.manifest().blocks[1];
    forged.root = B256::repeat_byte(0xcd);
    assert!(matches!(
        export.block_ssz(&forged).unwrap_err(),
        ExportError::Mismatch(_)
    ));
    assert_eq!(export.segments().len(), 1);
}

/// Rewrites the export's first segment from `edit` of its manifest (which may change its
/// files), rehashing it, and returns the new archive digest.
fn rewrite_segment(
    export: &Export,
    edit: impl FnOnce(&mut crate::archive::Manifest, &Path),
) -> crate::archive::Sha256Digest {
    use crate::archive::{Manifest, MANIFEST_FILE};
    let dir = export.dir().join(&export.manifest().segments[0].dir);
    let path = dir.join(MANIFEST_FILE);
    let (mut m, _) = Manifest::parse(&std::fs::read(&path).unwrap()).unwrap();
    edit(&mut m, &dir);
    let (bytes, digest) = m.render().unwrap();
    std::fs::write(path, bytes).unwrap();
    digest
}

#[tokio::test]
async fn open_export_refuses_a_dropped_interior_block() {
    // The forger removes slot 4's block file and its segment entry, rehashes the segment,
    // and lists slot 4 as empty with slot 5's parent as slot 3: every label and digest holds
    // together, but slot 5's block says its parent is slot 4.
    let out = tempfile::tempdir().unwrap();
    let devnet = Devnet::new(6, &[]);
    let export = run(devnet.clone(), 6, out.path()).await.unwrap();
    let archive_sha256 = rewrite_segment(&export, |m, dir| {
        let at = m.files.iter().position(|f| f.slot == 4).unwrap();
        let file = m.files.remove(at);
        m.total_bytes -= file.len;
        std::fs::remove_file(dir.join(&file.path)).unwrap();
    });
    rewrite(&export, |m| {
        m.blocks.retain(|b| b.slot != 4);
        m.empty_slots = vec![4];
        m.blocks
            .iter_mut()
            .find(|b| b.slot == 5)
            .unwrap()
            .parent_root = devnet.root(3);
        m.segments[0].archive_sha256 = archive_sha256;
    });
    let err = open_export(export.dir()).unwrap_err();
    assert!(
        matches!(
            &err,
            ExportError::ParentMismatch { slot: 5, parent_root, .. } if *parent_root == devnet.root(4)
        ),
        "{err}"
    );
}

/// Swaps the block file of `slot` for `ssz` (snappy-compressed), keeping its label, and
/// rehashes the segment and the export manifest to match.
fn replace_block(export: &Export, slot: Slot, ssz: &[u8]) {
    use sha2::Digest;
    let payload = crate::archive::fixtures::snappy(ssz);
    let archive_sha256 = rewrite_segment(export, |m, dir| {
        let file = m.files.iter_mut().find(|f| f.slot == slot).unwrap();
        std::fs::write(dir.join(&file.path), &payload).unwrap();
        m.total_bytes = m.total_bytes - file.len + payload.len() as u64;
        file.len = payload.len() as u64;
        file.sha256 = sha2::Sha256::digest(&payload).into();
    });
    rewrite(export, |m| m.segments[0].archive_sha256 = archive_sha256);
}

#[tokio::test]
async fn open_export_decodes_every_block() {
    let open = |ssz: Vec<u8>| async move {
        let out = tempfile::tempdir().unwrap();
        let export = run(Devnet::new(6, &[]), 6, out.path()).await.unwrap();
        replace_block(&export, 4, &ssz);
        open_export(export.dir()).unwrap_err()
    };

    // Bytes of the wrong fork's shape: Gloas at a Fulu slot.
    let err = open(p2p_wire::testkit::gloas_block::<Spec>(4).as_ssz_bytes()).await;
    assert!(
        matches!(
            err,
            ExportError::Decode {
                what: "block",
                slot: Some(4),
                ..
            }
        ),
        "{err}"
    );

    // Another block at the slot: it does not hash to the listed root.
    let (other, _) = fixtures::block(4, B256::repeat_byte(1), B256::repeat_byte(2));
    let err = open(other).await;
    assert!(
        matches!(&err, ExportError::Mismatch(m) if m.contains("slot 4") && m.contains("root")),
        "{err}"
    );

    // A block of another slot under slot 4's label.
    let (other, _) = fixtures::block(3, B256::repeat_byte(1), B256::repeat_byte(2));
    let err = open(other).await;
    assert!(
        matches!(&err, ExportError::Mismatch(m) if m.contains("slot 4") && m.contains("slot 3")),
        "{err}"
    );
}

#[tokio::test]
async fn open_export_checks_the_genesis_block_against_the_genesis_state() {
    // A genesis block whose state_root is not the export's genesis state root, relabelled
    // and rehashed throughout.
    let out = tempfile::tempdir().unwrap();
    let export = run(Devnet::new(4, &[]), 4, out.path()).await.unwrap();
    let (ssz, root) = fixtures::block(0, Root::ZERO, B256::repeat_byte(0x99));
    let archive_sha256 = rewrite_segment(&export, |m, dir| {
        use sha2::Digest;
        let payload = crate::archive::fixtures::snappy(&ssz);
        let at = m.files.iter().position(|f| f.slot == 0).unwrap();
        let old = m.files.remove(at);
        std::fs::remove_file(dir.join(&old.path)).unwrap();
        let file = crate::archive::ArchiveFile {
            path: format!("{BLOCK_TOPIC}/0_0x{}.ssz_snappy", hex::encode(root)),
            root,
            len: payload.len() as u64,
            sha256: sha2::Sha256::digest(&payload).into(),
            ..old.clone()
        };
        std::fs::write(dir.join(&file.path), &payload).unwrap();
        m.total_bytes = m.total_bytes - old.len + file.len;
        m.files.push(file);
        m.files.sort_by(|a, b| a.path.cmp(&b.path));
    });
    rewrite(&export, |m| {
        m.blocks[0].root = root;
        m.genesis_block_root = root;
        m.segments[0].archive_sha256 = archive_sha256;
        // Slot 1's listed parent follows, so only its decoded parent_root disagrees.
        m.blocks[1].parent_root = root;
    });
    let err = open_export(export.dir()).unwrap_err();
    assert!(
        matches!(&err, ExportError::Genesis(m) if m.contains("state_root")),
        "{err}"
    );
}

#[tokio::test]
async fn open_export_decodes_the_genesis_state() {
    use sha2::Digest;

    // The manifest's genesis fields, each edited and rehashed: the state says otherwise.
    type Edit = fn(&mut ExportManifest);
    let edits: [(&str, Edit); 3] = [
        ("genesis_time", |m| m.genesis_time += 1),
        ("genesis_validators_root", |m| {
            m.genesis_validators_root = B256::repeat_byte(0x41)
        }),
        ("state root", |m| {
            m.genesis_state_root = B256::repeat_byte(0x44)
        }),
    ];
    for (field, edit) in edits {
        let out = tempfile::tempdir().unwrap();
        let (export, dir) = exported(out.path()).await;
        rewrite(&export, edit);
        let err = open_export(&dir).unwrap_err();
        assert!(
            matches!(&err, ExportError::Mismatch(m) if m.contains(field)),
            "{field}: {err}"
        );
    }

    // The state file edited (its genesis_time), with the manifest's length, sha256 and
    // genesis_time rewritten to match: its root is no longer the recorded state root.
    let out = tempfile::tempdir().unwrap();
    let (export, dir) = exported(out.path()).await;
    let mut state = fixtures::genesis_state();
    state.genesis_time += 7;
    let bytes = state.as_ssz_bytes();
    std::fs::write(dir.join(GENESIS_STATE_FILE), &bytes).unwrap();
    rewrite(&export, |m| {
        m.genesis_time += 7;
        m.genesis_state.len = bytes.len() as u64;
        m.genesis_state.sha256 = sha2::Sha256::digest(&bytes).into();
    });
    let err = open_export(&dir).unwrap_err();
    assert!(
        matches!(&err, ExportError::Mismatch(m) if m.contains("state root")),
        "{err}"
    );

    // A state file that does not decode.
    let out = tempfile::tempdir().unwrap();
    let (export, dir) = exported(out.path()).await;
    let bytes = vec![0u8; 64];
    std::fs::write(dir.join(GENESIS_STATE_FILE), &bytes).unwrap();
    rewrite(&export, |m| {
        m.genesis_state.len = bytes.len() as u64;
        m.genesis_state.sha256 = sha2::Sha256::digest(&bytes).into();
    });
    let err = open_export(&dir).unwrap_err();
    assert!(
        matches!(
            err,
            ExportError::Decode {
                what: "genesis state",
                ..
            }
        ),
        "{err}"
    );
}

#[tokio::test]
async fn open_export_checks_the_fork_digests() {
    // Slots to GLOAS_SLOT + 2: the genesis, blob-parameter (epoch 1) and Gloas (epoch 2)
    // digests.
    let to = GLOAS_SLOT + 2;
    let exported =
        |out: std::path::PathBuf| async move { run(Devnet::new(to, &[]), to, &out).await.unwrap() };

    // A changed digest: the files arrived on another one.
    let out = tempfile::tempdir().unwrap();
    let export = exported(out.path().to_owned()).await;
    rewrite(&export, |m| m.fork_digests[0].digest = [9, 9, 9, 9]);
    let err = open_export(export.dir()).unwrap_err();
    assert!(
        matches!(&err, ExportError::Mismatch(m) if m.contains("fork digest")),
        "{err}"
    );

    // A dropped blob-parameter digest: epoch 1's files carry it.
    let out = tempfile::tempdir().unwrap();
    let export = exported(out.path().to_owned()).await;
    rewrite(&export, |m| m.fork_digests.retain(|d| d.epoch != 1));
    let err = open_export(export.dir()).unwrap_err();
    assert!(
        matches!(&err, ExportError::Mismatch(m) if m.contains("fork digest")),
        "{err}"
    );

    // A dropped fork digest: the Gloas fork at epoch 2 has none.
    let out = tempfile::tempdir().unwrap();
    let export = exported(out.path().to_owned()).await;
    let mut m = export.manifest().clone();
    m.fork_digests.retain(|d| d.epoch != 2);
    assert!(
        matches!(m.validate(), Err(ExportManifestError::Invalid(e)) if e.contains("gloas")),
        "the manifest alone is refused"
    );
}

#[test]
fn an_export_manifest_over_the_read_bound_is_never_written() {
    use super::export::check_manifest_len;
    let path = Path::new("x/export.toml");
    check_manifest_len(path, &[0; 8], 8).unwrap();
    let err = check_manifest_len(path, &[0; 9], 8).unwrap_err();
    assert!(
        matches!(&err, ExportError::Manifest { source: ExportManifestError::Invalid(m), .. }
            if m.contains("over 8 bytes")),
        "{err}"
    );
}

/// A forged block: its slot, SSZ, root and parent root.
type Forged = (Slot, Vec<u8>, Root, Root);

/// Replaces every block from `from` on with `forged` (slot, ssz, root, parent): block files,
/// segment manifest and `export.toml` relabelled and rehashed, the slots from `from` without a
/// forged block listed empty. Open checks no signature and runs no state transition, so the
/// result holds together.
fn forge_suffix(export: &Export, from: Slot, forged: &[Forged]) {
    use crate::archive::ArchiveFile;
    use sha2::Digest;
    let archive_sha256 = rewrite_segment(export, |m, dir| {
        let digest = m.files[0].fork_digest;
        for file in m.files.iter().filter(|f| f.slot >= from) {
            std::fs::remove_file(dir.join(&file.path)).unwrap();
        }
        m.files.retain(|f| f.slot < from);
        for (slot, ssz, root, _) in forged {
            let payload = crate::archive::fixtures::snappy(ssz);
            let file = ArchiveFile {
                path: format!("{BLOCK_TOPIC}/{slot}_0x{}.ssz_snappy", hex::encode(root)),
                topic: BLOCK_TOPIC.into(),
                slot: *slot,
                root: *root,
                fork_digest: digest,
                len: payload.len() as u64,
                sha256: sha2::Sha256::digest(&payload).into(),
            };
            std::fs::write(dir.join(&file.path), &payload).unwrap();
            m.files.push(file);
        }
        m.files.sort_by(|a, b| a.path.cmp(&b.path));
        m.total_bytes = m.files.iter().map(|f| f.len).sum();
    });
    rewrite(export, |m| {
        m.blocks.retain(|b| b.slot < from);
        m.blocks.extend(
            forged
                .iter()
                .map(|(slot, _, root, parent_root)| BlockEntry {
                    slot: *slot,
                    root: *root,
                    parent_root: *parent_root,
                }),
        );
        m.empty_slots = (m.slot_start..=m.slot_end)
            .filter(|s| !m.blocks.iter().any(|b| b.slot == *s))
            .collect();
        m.segments[0].archive_sha256 = archive_sha256;
    });
}

/// A forged block at `slot` with parent `parent`, as `forge_suffix` takes it.
fn forged_block(slot: Slot, parent: Root) -> Forged {
    let (ssz, root) = fixtures::block(slot, parent, B256::repeat_byte(0xf0 | slot as u8));
    (slot, ssz, root, parent)
}

#[tokio::test]
async fn only_the_pinned_export_sha256_authenticates_a_forged_suffix() {
    let devnet = Devnet::new(6, &[]);
    let forgeries: [(&str, Slot, Vec<Forged>); 3] = [
        ("a dropped tip", 6, vec![]),
        ("a replaced tip", 6, vec![forged_block(6, devnet.root(5))]),
        ("a rehashed interior suffix", 4, {
            let five = forged_block(5, devnet.root(3));
            let six = forged_block(6, five.2);
            vec![five, six]
        }),
    ];
    for (what, from, forged) in forgeries {
        let out = tempfile::tempdir().unwrap();
        let export = run(devnet.clone(), 6, out.path()).await.unwrap();
        let pin = export.export_sha256();
        forge_suffix(&export, from, &forged);
        // Internally consistent: the unpinned open cannot tell.
        let opened = open_export(export.dir()).unwrap();
        assert_ne!(opened.export_sha256(), pin, "{what}");
        let err = open_export_pinned(export.dir(), pin).unwrap_err();
        assert!(
            matches!(&err, ExportError::NotPinned { expected, actual }
                if *expected == hex::encode(pin) && *actual == hex::encode(opened.export_sha256())),
            "{what}: {err}"
        );
    }
}

#[tokio::test]
async fn the_pinned_export_sha256_opens_the_export() {
    let out = tempfile::tempdir().unwrap();
    let (export, dir) = exported(out.path()).await;
    let opened = open_export_pinned(&dir, export.export_sha256()).unwrap();
    assert_eq!(opened.manifest(), export.manifest());
    let err = open_export_pinned(&dir, [0; 32]).unwrap_err();
    assert!(matches!(err, ExportError::NotPinned { .. }), "{err}");
    // The pin is checked against the manifest before anything else is read.
    std::fs::write(dir.join(GENESIS_STATE_FILE), b"x").unwrap();
    let err = open_export_pinned(&dir, [0; 32]).unwrap_err();
    assert!(matches!(err, ExportError::NotPinned { .. }), "{err}");
}
