//! Two fixture beacon nodes on 127.0.0.1 serving a Gloas anchor built in code.

use super::*;
use crate::checkpoint::outdir::{Dir, UnsafeReason};
use crate::checkpoint::runlog;
use crate::checkpoint::testkit::gloas_fixture::{anchor, post_state};
use crate::checkpoint::testkit::{Reply, Server};
use bytes::Bytes;
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::Root;
use consensus_types::{EthSpec, Mainnet, Minimal};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ssz::Encode;
use std::collections::HashMap;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use tree_hash::TreeHash;

const SLOT: u64 = 100;
const FINALITY: &str = "/eth/v1/beacon/states/finalized/finality_checkpoints";

/// What one fixture node knows.
#[derive(Clone)]
struct Node {
    finalized_epoch: u64,
    finalized_root: Root,
    /// Header replies, by root.
    headers: Vec<(Root, Value)>,
    block: Option<(Root, Bytes)>,
    state: Option<(Root, Reply)>,
}

struct Anchor0 {
    block: SignedBeaconBlock<Mainnet>,
    state: BeaconState<Mainnet>,
    root: Root,
    state_root: Root,
}

fn anchor0() -> Anchor0 {
    let (block, state) = anchor::<Mainnet>(SLOT);
    Anchor0 {
        root: block.message.tree_hash_root(),
        state_root: state.tree_hash_root(),
        block,
        state,
    }
}

fn header_json<E: EthSpec>(block: &SignedBeaconBlock<E>, root: Root, canonical: bool) -> Value {
    let m = &block.message;
    serde_json::json!({
        "execution_optimistic": false,
        "finalized": true,
        "data": {
            "root": root_hex(&root),
            "canonical": canonical,
            "header": {
                "message": {
                    "slot": m.slot.to_string(),
                    "proposer_index": m.proposer_index.to_string(),
                    "parent_root": root_hex(&m.parent_root),
                    "state_root": root_hex(&m.state_root),
                    "body_root": root_hex(&m.body.tree_hash_root()),
                },
                "signature": format!("0x{}", "00".repeat(96)),
            }
        }
    })
}

impl Node {
    /// A node finalized at `epoch` on the anchor, serving its header, block and state.
    fn honest(a: &Anchor0, epoch: u64) -> Self {
        Node {
            finalized_epoch: epoch,
            finalized_root: a.root,
            headers: vec![(a.root, header_json(&a.block, a.root, true))],
            block: Some((a.root, Bytes::from(a.block.as_ssz_bytes()))),
            state: Some((
                a.state_root,
                Reply::Ssz {
                    body: Bytes::from(a.state.as_ssz_bytes()),
                    version: Some("gloas"),
                },
            )),
        }
    }

    fn routes(&self) -> HashMap<String, Reply> {
        let mut routes = HashMap::new();
        routes.insert(
            FINALITY.to_owned(),
            Reply::Json(
                serde_json::json!({
                    "execution_optimistic": false,
                    "finalized": true,
                    "data": {
                        "previous_justified": {"epoch": "0", "root": root_hex(&Root::ZERO)},
                        "current_justified": {"epoch": "0", "root": root_hex(&Root::ZERO)},
                        "finalized": {
                            "epoch": self.finalized_epoch.to_string(),
                            "root": root_hex(&self.finalized_root),
                        },
                    }
                })
                .to_string(),
            ),
        );
        for (root, header) in &self.headers {
            routes.insert(
                format!("/eth/v1/beacon/headers/{}", root_hex(root)),
                Reply::Json(header.to_string()),
            );
        }
        if let Some((root, body)) = &self.block {
            routes.insert(
                format!("/eth/v2/beacon/blocks/{}", root_hex(root)),
                Reply::Ssz {
                    body: body.clone(),
                    version: Some("gloas"),
                },
            );
        }
        if let Some((root, reply)) = &self.state {
            routes.insert(
                format!("/eth/v2/debug/beacon/states/{}", root_hex(root)),
                reply.clone(),
            );
        }
        routes
    }
}

struct Net {
    a: Server,
    b: Server,
    _dir: tempfile::TempDir,
    config: PathBuf,
    out: PathBuf,
    /// B's base path (empty for none).
    b_prefix: String,
}

impl Net {
    async fn start(a: Node, b: Node) -> Self {
        Self::start_with(a, b, ("Operator A", "Operator B"), "").await
    }

    async fn start_with(a: Node, b: Node, operators: (&str, &str), extra: &str) -> Self {
        Self::start_full(a, b, operators, extra, "").await
    }

    /// `b_prefix`: a base path in B's URL, under which B serves its routes.
    async fn start_full(
        a: Node,
        b: Node,
        operators: (&str, &str),
        extra: &str,
        b_prefix: &str,
    ) -> Self {
        let a = Server::start(a.routes()).await;
        let b_routes = b
            .routes()
            .into_iter()
            .map(|(path, reply)| (format!("{b_prefix}{path}"), reply))
            .collect();
        // B on another loopback address, under a name only the fixture resolver knows: the
        // client must dial the address the independence check saw.
        let b = Server::start_on("[::1]:0", b_routes).await;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("anchor-fetch.toml");
        // Same machine, two host names: the config refuses one host behind both providers.
        std::fs::write(
            &config,
            format!(
                "allow_insecure_http = true\n{extra}\n\
                 [[provider]]\nname = \"alpha\"\noperator = \"{}\"\nurl = \"http://127.0.0.1:{}\"\n\
                 [[provider]]\nname = \"beta\"\noperator = \"{}\"\nurl = \"http://beta.test:{}{b_prefix}\"\n",
                operators.0,
                a.addr.port(),
                operators.1,
                b.addr.port()
            ),
        )
        .unwrap();
        let out = dir.path().join("out");
        Net {
            a,
            b,
            _dir: dir,
            config,
            out,
            b_prefix: b_prefix.to_owned(),
        }
    }

    /// The `--providers` value naming both fixture nodes (two host names, one machine).
    fn provider_urls(&self) -> String {
        format!(
            "http://127.0.0.1:{},http://beta.test:{}{}",
            self.a.addr.port(),
            self.b.addr.port(),
            self.b_prefix
        )
    }

    async fn run(&self) -> Result<Anchor, AnchorError> {
        run_with::<Mainnet>(&self.config, &self.out, false, &RealFs, &apart()).await
    }

    async fn run_with(&self, fs: &dyn PublishFs) -> Result<Anchor, AnchorError> {
        run_with::<Mainnet>(&self.config, &self.out, false, fs, &apart()).await
    }

    /// Nothing published: no anchor, block or state in `out/`.
    fn assert_nothing_published(&self) {
        for file in [ANCHOR_FILE, BLOCK_FILE, STATE_FILE] {
            assert!(!self.out.join(file).exists(), "{file} left in out/");
        }
        let leftovers: Vec<_> = std::fs::read_dir(&self.out)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| ![RUN_LOG_FILE, LOCK_FILE, QUARANTINE_DIR].contains(&n.as_str()))
            .collect();
        assert!(leftovers.is_empty(), "left in out/: {leftovers:?}");
    }

    fn run_log(&self) -> String {
        std::fs::read_to_string(self.out.join(RUN_LOG_FILE)).unwrap()
    }

    /// The common checks of every abort: non-zero exit, the error named in the run log, no
    /// `anchor.json`, nothing left in quarantine.
    fn assert_aborted(&self, err: &AnchorError, name: &str) {
        assert_eq!(err.name(), name, "{err:?}");
        assert_ne!(err.exit_code(), 0);
        self.assert_nothing_published();
        let quarantine = self.out.join(QUARANTINE_DIR);
        if quarantine.exists() {
            assert_eq!(std::fs::read_dir(&quarantine).unwrap().count(), 0);
        }
        let last: Value = serde_json::from_str(self.run_log().lines().last().unwrap()).unwrap();
        assert_eq!(last["event"], "abort");
        assert_eq!(last["error"], name);
    }
}

/// A resolver that answers from a table: an IP literal resolves to itself, a listed name to
/// its addresses (or an error), anything else fails.
struct FixtureResolver(HashMap<&'static str, std::io::Result<Vec<std::net::IpAddr>>>);

impl Resolve for FixtureResolver {
    fn resolve<'a>(&'a self, host: &'a str, _port: u16) -> Resolution<'a> {
        let answer = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => Ok(vec![ip]),
            Err(_) => match self.0.get(host) {
                Some(Ok(addrs)) => Ok(addrs.clone()),
                Some(Err(e)) => Err(std::io::Error::new(e.kind(), e.to_string())),
                None => Err(std::io::Error::other("no such host in the fixture")),
            },
        };
        Box::pin(async move { answer })
    }
}

/// B's name, `beta.test`, resolving to where B listens (`::1`), apart from A (127.0.0.1).
fn apart() -> FixtureResolver {
    resolver(Ok(vec![std::net::Ipv6Addr::LOCALHOST.into()]))
}

/// `beta.test` resolving to `answer`.
fn resolver(answer: std::io::Result<Vec<std::net::IpAddr>>) -> FixtureResolver {
    FixtureResolver(HashMap::from([("beta.test", answer)]))
}

fn sha256_hex(bytes: &[u8]) -> String {
    alloy_primitives::hex::encode(Sha256::digest(bytes))
}

#[tokio::test]
async fn happy_path() {
    let a0 = anchor0();
    // B is ahead: the candidate is A's (lower) finalized root, which B also serves.
    let mut b = Node::honest(&a0, 6);
    b.finalized_root = Root::repeat_byte(0x66);
    let net = Net::start(Node::honest(&a0, 5), b).await;

    let anchor = net.run().await.unwrap();

    let text = std::fs::read_to_string(net.out.join(ANCHOR_FILE)).unwrap();
    let on_disk: Anchor = serde_json::from_str(&text).unwrap();
    assert_eq!(on_disk, anchor);
    assert_eq!(anchor.block_root, root_hex(&a0.root));
    assert_eq!(anchor.state_root, root_hex(&a0.state_root));
    assert_eq!(
        (anchor.slot, anchor.epoch, anchor.finalized_epoch),
        (SLOT, 3, 5)
    );
    assert_eq!(anchor.fork, "gloas");
    assert!(anchor.fetched_at.ends_with('Z'));

    // Recompute the roots and digests from the files the anchor names.
    let block_bytes = std::fs::read(net.out.join(&anchor.block.file)).unwrap();
    let state_bytes = std::fs::read(net.out.join(&anchor.state.file)).unwrap();
    assert_eq!(anchor.block.sha256, sha256_hex(&block_bytes));
    assert_eq!(anchor.state.sha256, sha256_hex(&state_bytes));
    assert_eq!(anchor.block.bytes, block_bytes.len() as u64);
    assert_eq!(anchor.state.bytes, state_bytes.len() as u64);
    let block = consensus_types::forked::SignedBeaconBlock::<Mainnet>::from_ssz_bytes_for_fork(
        &block_bytes,
        ForkName::Gloas,
    )
    .unwrap();
    let consensus_types::forked::SignedBeaconBlock::Gloas(block) = block else {
        panic!("not gloas")
    };
    assert_eq!(root_hex(&block.message.tree_hash_root()), anchor.block_root);
    let state = consensus_types::forked::BeaconState::<Mainnet>::from_ssz_bytes_for_fork(
        &state_bytes,
        ForkName::Gloas,
    )
    .unwrap();
    assert_eq!(root_hex(&state.tree_hash_root()), anchor.state_root);
    assert_eq!(root_hex(&block.message.state_root), anchor.state_root);

    // The block came from A only and the state from B only, both by root.
    let block_path = format!("/eth/v2/beacon/blocks/{}", anchor.block_root);
    let state_path = format!("/eth/v2/debug/beacon/states/{}", anchor.state_root);
    assert!(net.a.paths().contains(&block_path));
    assert!(!net.a.paths().contains(&state_path));
    assert!(net.b.paths().contains(&state_path));
    assert!(!net.b.paths().contains(&block_path));
    let block_request = net
        .a
        .seen()
        .into_iter()
        .find(|s| s.path == block_path)
        .unwrap();
    assert_eq!(block_request.headers["accept"], "application/octet-stream");
    assert_eq!(block_request.headers["eth-consensus-version"], "gloas");

    // Both providers are in the anchor and in a run log that passes the check.
    let names: Vec<_> = anchor.providers.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["alpha", "beta"]);
    assert_eq!(anchor.block.provider, "alpha");
    assert_eq!(anchor.state.provider, "beta");
    let log = net.run_log();
    assert_eq!(runlog::verify(&log), Ok(()));
    assert!(log.contains(&format!("http://127.0.0.1:{}", net.a.addr.port())));
    assert!(log.contains(&format!("http://beta.test:{}", net.b.addr.port())));
    let last: Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert_eq!(last["event"], "anchor");
    assert_eq!(
        std::fs::read_dir(net.out.join(QUARANTINE_DIR))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn block_root_mismatch_aborts() {
    let a0 = anchor0();
    let mut a = Node::honest(&a0, 5);
    let mut other = a0.block.clone();
    other.message.proposer_index += 1;
    a.block = Some((a0.root, Bytes::from(other.as_ssz_bytes())));
    let net = Net::start(a, Node::honest(&a0, 5)).await;
    let err = net.run().await.unwrap_err();
    assert!(
        matches!(err, AnchorError::BlockRootMismatch { .. }),
        "{err:?}"
    );
    net.assert_aborted(&err, "block_root_mismatch");
}

#[tokio::test]
async fn header_state_root_mismatch_aborts() {
    // Both providers agree on a header whose state_root is not the block's.
    let a0 = anchor0();
    let mut forged = a0.block.clone();
    forged.message.state_root = Root::repeat_byte(0x55);
    let header = header_json(&forged, a0.root, true);
    let (mut a, mut b) = (Node::honest(&a0, 5), Node::honest(&a0, 5));
    a.headers = vec![(a0.root, header.clone())];
    b.headers = vec![(a0.root, header)];
    let net = Net::start(a, b).await;
    let err = net.run().await.unwrap_err();
    assert!(
        matches!(err, AnchorError::HeaderStateRootMismatch { .. }),
        "{err:?}"
    );
    net.assert_aborted(&err, "header_state_root_mismatch");
}

#[tokio::test]
async fn state_root_mismatch_aborts() {
    let a0 = anchor0();
    let mut other = post_state(&a0.block.message);
    other.genesis_time = 1;
    let mut b = Node::honest(&a0, 5);
    b.state = Some((
        a0.state_root,
        Reply::Ssz {
            body: Bytes::from(other.as_ssz_bytes()),
            version: Some("gloas"),
        },
    ));
    let net = Net::start(Node::honest(&a0, 5), b).await;
    let err = net.run().await.unwrap_err();
    assert!(
        matches!(err, AnchorError::StateRootMismatch { .. }),
        "{err:?}"
    );
    net.assert_aborted(&err, "state_root_mismatch");
}

#[tokio::test]
async fn providers_disagree_aborts() {
    let a0 = anchor0();
    let mut b = Node::honest(&a0, 5);
    b.finalized_root = Root::repeat_byte(0x77);
    let net = Net::start(Node::honest(&a0, 5), b).await;
    let err = net.run().await.unwrap_err();
    assert!(matches!(err, AnchorError::ProvidersDisagree(_)), "{err:?}");
    net.assert_aborted(&err, "providers_disagree");
    // Nothing was downloaded.
    assert!(!net.a.paths().iter().any(|p| p.starts_with("/eth/v2/")));
    assert!(!net.b.paths().iter().any(|p| p.starts_with("/eth/v2/")));
}

#[tokio::test]
async fn providers_disagree_on_the_header_aborts() {
    let a0 = anchor0();
    let mut other = a0.block.clone();
    other.message.slot += 1;
    let mut b = Node::honest(&a0, 5);
    b.headers = vec![(a0.root, header_json(&other, a0.root, true))];
    let net = Net::start(Node::honest(&a0, 5), b).await;
    let err = net.run().await.unwrap_err();
    net.assert_aborted(&err, "providers_disagree");
}

#[tokio::test]
async fn same_operator_aborts() {
    let a0 = anchor0();
    let net = Net::start_with(
        Node::honest(&a0, 5),
        Node::honest(&a0, 5),
        ("Same Operator", "same operator"),
        "",
    )
    .await;
    let err = net.run().await.unwrap_err();
    assert!(matches!(err, AnchorError::SameOperator { .. }), "{err:?}");
    net.assert_aborted(&err, "same_operator");
    assert!(net.a.paths().is_empty() && net.b.paths().is_empty());
}

#[tokio::test]
async fn oversize_body_aborts() {
    // The state never ends; the cap (well above the block, far below the stream) cuts it.
    let a0 = anchor0();
    let mut b = Node::honest(&a0, 5);
    b.state = Some((a0.state_root, Reply::Endless));
    let net = Net::start_with(
        Node::honest(&a0, 5),
        b,
        ("Operator A", "Operator B"),
        "max_body_bytes = 4194304",
    )
    .await;
    let err = net.run().await.unwrap_err();
    assert!(
        matches!(
            err,
            AnchorError::BodyTooLarge {
                limit: 4_194_304,
                content_length: None,
                ..
            }
        ),
        "{err:?}"
    );
    net.assert_aborted(&err, "body_too_large");
    assert!(!net.out.join(STATE_FILE).exists());
}

#[tokio::test]
async fn non_canonical_header_aborts() {
    let a0 = anchor0();
    let mut a = Node::honest(&a0, 5);
    a.headers = vec![(a0.root, header_json(&a0.block, a0.root, false))];
    let net = Net::start(a, Node::honest(&a0, 5)).await;
    let err = net.run().await.unwrap_err();
    net.assert_aborted(&err, "not_canonical");
}

#[tokio::test]
async fn a_header_for_another_root_aborts() {
    let a0 = anchor0();
    let mut a = Node::honest(&a0, 5);
    a.headers = vec![(a0.root, header_json(&a0.block, Root::repeat_byte(1), true))];
    let net = Net::start(a, Node::honest(&a0, 5)).await;
    let err = net.run().await.unwrap_err();
    net.assert_aborted(&err, "bad_response");
}

#[tokio::test]
async fn a_header_after_the_finalized_epoch_aborts() {
    // Slot 100 is in epoch 3; a checkpoint at epoch 3 starts at slot 96.
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 3), Node::honest(&a0, 3)).await;
    let err = net.run().await.unwrap_err();
    net.assert_aborted(&err, "bad_response");
}

#[tokio::test]
async fn no_finalized_checkpoint_yet_aborts() {
    let a0 = anchor0();
    let (mut a, mut b) = (Node::honest(&a0, 0), Node::honest(&a0, 0));
    a.finalized_root = Root::ZERO;
    b.finalized_root = Root::ZERO;
    let net = Net::start(a, b).await;
    let err = net.run().await.unwrap_err();
    net.assert_aborted(&err, "bad_response");
}

#[tokio::test]
async fn header_fields_that_do_not_match_the_block_abort() {
    let a0 = anchor0();
    let mut forged = a0.block.clone();
    forged.message.proposer_index += 1;
    let header = header_json(&forged, a0.root, true);
    let (mut a, mut b) = (Node::honest(&a0, 5), Node::honest(&a0, 5));
    a.headers = vec![(a0.root, header.clone())];
    b.headers = vec![(a0.root, header)];
    let net = Net::start(a, b).await;
    let err = net.run().await.unwrap_err();
    net.assert_aborted(&err, "header_block_mismatch");
}

#[tokio::test]
async fn a_state_that_is_not_post_block_aborts() {
    // An epoch-boundary state (advanced past the block's slot) under the right state root.
    let a0 = anchor0();
    let mut advanced = post_state(&a0.block.message);
    advanced.slot = 128;
    let mut b = Node::honest(&a0, 5);
    b.state = Some((
        a0.state_root,
        Reply::Ssz {
            body: Bytes::from(advanced.as_ssz_bytes()),
            version: Some("gloas"),
        },
    ));
    let net = Net::start(Node::honest(&a0, 5), b).await;
    let err = net.run().await.unwrap_err();
    assert!(
        matches!(err, AnchorError::StateNotPostBlock { .. }),
        "{err:?}"
    );
    net.assert_aborted(&err, "state_not_post_block");
}

#[tokio::test]
async fn a_non_gloas_body_aborts() {
    let a0 = anchor0();
    let mut b = Node::honest(&a0, 5);
    b.state = Some((
        a0.state_root,
        Reply::Ssz {
            body: Bytes::from(a0.state.as_ssz_bytes()),
            version: Some("fulu"),
        },
    ));
    let net = Net::start(Node::honest(&a0, 5), b).await;
    let err = net.run().await.unwrap_err();
    net.assert_aborted(&err, "wrong_fork");
}

#[tokio::test]
async fn an_undecodable_block_aborts() {
    let a0 = anchor0();
    let mut a = Node::honest(&a0, 5);
    a.block = Some((a0.root, Bytes::from_static(b"not ssz")));
    let net = Net::start(a, Node::honest(&a0, 5)).await;
    let err = net.run().await.unwrap_err();
    net.assert_aborted(&err, "decode");
}

#[tokio::test]
async fn a_missing_block_aborts() {
    let a0 = anchor0();
    let mut a = Node::honest(&a0, 5);
    a.block = None;
    let net = Net::start(a, Node::honest(&a0, 5)).await;
    let err = net.run().await.unwrap_err();
    assert!(
        matches!(err, AnchorError::HttpStatus { status: 404, .. }),
        "{err:?}"
    );
    net.assert_aborted(&err, "http_status");
}

#[tokio::test]
async fn an_existing_anchor_is_never_replaced() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    net.run().await.unwrap();
    let before = std::fs::read(net.out.join(ANCHOR_FILE)).unwrap();
    let err = net.run().await.unwrap_err();
    assert!(matches!(err, AnchorError::OutputExists { .. }), "{err:?}");
    assert_ne!(err.exit_code(), 0);
    assert_eq!(std::fs::read(net.out.join(ANCHOR_FILE)).unwrap(), before);
    // Both runs are in the log; the last one aborted after naming its providers.
    let log = net.run_log();
    assert_eq!(
        log.lines()
            .filter(|l| l.contains(r#""event":"start""#))
            .count(),
        2
    );
    assert!(runlog::verify(&log).is_ok());
}

#[test]
fn every_error_has_a_distinct_name_and_a_non_zero_exit() {
    let io = || std::io::Error::other("x");
    let s = String::new;
    let errors = [
        AnchorError::Config(s()),
        AnchorError::SameOperator {
            a: s(),
            b: s(),
            operator: s(),
        },
        AnchorError::SameHost {
            a: s(),
            b: s(),
            host: s(),
        },
        AnchorError::SameDomain {
            a: s(),
            b: s(),
            domain: s(),
        },
        AnchorError::SameAddress {
            a: s(),
            b: s(),
            addr: std::net::Ipv4Addr::LOCALHOST.into(),
        },
        AnchorError::OutputExists {
            path: PathBuf::new(),
        },
        AnchorError::UnsafePath {
            path: PathBuf::new(),
            reason: UnsafeReason::Symlink,
        },
        AnchorError::OutDirBusy {
            path: PathBuf::new(),
        },
        AnchorError::Transport {
            provider: s(),
            path: s(),
            reason: s(),
        },
        AnchorError::Timeout {
            provider: s(),
            path: s(),
        },
        AnchorError::HttpStatus {
            provider: s(),
            path: s(),
            status: 500,
        },
        AnchorError::BadResponse {
            provider: s(),
            path: s(),
            reason: s(),
        },
        AnchorError::BodyTooLarge {
            provider: s(),
            path: s(),
            limit: 1,
            content_length: None,
        },
        AnchorError::ProvidersDisagree(s()),
        AnchorError::NotCanonical {
            provider: s(),
            root: Root::ZERO,
        },
        AnchorError::WrongFork {
            provider: s(),
            path: s(),
            expected: s(),
            got: s(),
        },
        AnchorError::Decode {
            what: "state",
            reason: s(),
        },
        AnchorError::BlockRootMismatch {
            expected: Root::ZERO,
            got: Root::ZERO,
        },
        AnchorError::HeaderStateRootMismatch {
            header: Root::ZERO,
            block: Root::ZERO,
        },
        AnchorError::HeaderBlockMismatch { field: "slot" },
        AnchorError::StateNotPostBlock { reason: s() },
        AnchorError::StateRootMismatch {
            expected: Root::ZERO,
            got: Root::ZERO,
        },
        AnchorError::RunLog(runlog::RunLogError::NoRun),
        AnchorError::Io {
            context: s(),
            source: io(),
        },
        AnchorError::PublishRolledBackIncompletely {
            cause: Box::new(AnchorError::Io {
                context: s(),
                source: io(),
            }),
            cleanup: s(),
            left: vec![PathBuf::from("block.ssz")],
        },
    ];
    let mut names = std::collections::HashSet::new();
    for e in &errors {
        assert!(names.insert(e.name()), "duplicate name {}", e.name());
        assert_ne!(e.exit_code(), 0, "{e:?}");
        assert!(!e.to_string().is_empty());
    }
}

/// Publish steps that fail on demand, otherwise the real ones.
#[derive(Default)]
struct FailingFs {
    /// Fail the link to this name.
    fail_link_to: Option<&'static str>,
    /// Fail the unlink of this name (the rollback's).
    fail_unlink_of: Option<&'static str>,
    /// Fail these `sync_dir` calls, counting from 0: the publish's own fsync is the last
    /// step (call 0), then the rollback's; after a failed link the rollback's is call 0.
    fail_sync_calls: &'static [usize],
    syncs: AtomicUsize,
}

impl PublishFs for FailingFs {
    fn link(&self, from: &Dir, name: &str, to: &Dir, to_name: &str) -> std::io::Result<()> {
        if self.fail_link_to == Some(to_name) {
            return Err(std::io::Error::other("injected link failure"));
        }
        RealFs.link(from, name, to, to_name)
    }

    fn unlink(&self, dir: &Dir, name: &str) -> std::io::Result<()> {
        if self.fail_unlink_of == Some(name) {
            return Err(std::io::Error::other("injected unlink failure"));
        }
        RealFs.unlink(dir, name)
    }

    fn sync_dir(&self, dir: &Dir) -> std::io::Result<()> {
        let call = self.syncs.fetch_add(1, Ordering::SeqCst);
        if self.fail_sync_calls.contains(&call) {
            return Err(std::io::Error::other("injected fsync failure"));
        }
        RealFs.sync_dir(dir)
    }
}

#[tokio::test]
async fn a_failed_publish_step_rolls_back_every_published_file() {
    for fail_link_to in [BLOCK_FILE, STATE_FILE, ANCHOR_FILE] {
        let a0 = anchor0();
        let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
        let fs = FailingFs {
            fail_link_to: Some(fail_link_to),
            ..FailingFs::default()
        };
        let err = net.run_with(&fs).await.unwrap_err();
        assert!(
            matches!(err, AnchorError::Io { .. }),
            "{fail_link_to}: {err:?}"
        );
        net.assert_aborted(&err, "io");
    }
}

#[tokio::test]
async fn a_failed_directory_fsync_removes_the_published_anchor() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    let fs = FailingFs {
        fail_sync_calls: &[0],
        ..FailingFs::default()
    };
    let err = net.run_with(&fs).await.unwrap_err();
    net.assert_aborted(&err, "io");
}

#[test]
fn publish_never_replaces_an_existing_anchor() {
    // Another writer published anchor.json after this run's up-front check.
    let dir = tempfile::tempdir().unwrap();
    let (run_dir, out) = (dir.path().join("q"), dir.path().join("out"));
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(run_dir.join(BLOCK_FILE), b"block").unwrap();
    std::fs::write(run_dir.join(STATE_FILE), b"state").unwrap();
    std::fs::write(out.join(ANCHOR_FILE), b"theirs").unwrap();
    let (run, out_dir) = (
        Dir::open_out(&run_dir).unwrap(),
        Dir::open_out(&out).unwrap(),
    );
    let err = publish(&RealFs, &run, &out_dir, b"ours").unwrap_err();
    assert!(matches!(err, AnchorError::OutputExists { .. }), "{err:?}");
    assert_eq!(std::fs::read(out.join(ANCHOR_FILE)).unwrap(), b"theirs");
    assert!(!out.join(BLOCK_FILE).exists() && !out.join(STATE_FILE).exists());
    let names: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, [ANCHOR_FILE], "temp file left behind");

    // The same holds for a block or state someone else put there.
    std::fs::remove_file(out.join(ANCHOR_FILE)).unwrap();
    std::fs::write(out.join(STATE_FILE), b"theirs").unwrap();
    let err = publish(&RealFs, &run, &out_dir, b"ours").unwrap_err();
    assert!(matches!(err, AnchorError::OutputExists { .. }), "{err:?}");
    assert_eq!(std::fs::read(out.join(STATE_FILE)).unwrap(), b"theirs");
    assert!(!out.join(BLOCK_FILE).exists() && !out.join(ANCHOR_FILE).exists());
}

#[test]
fn the_anchor_temp_file_never_follows_a_planted_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    symlink(&victim, dir.path().join("planted.tmp")).unwrap();
    let out = Dir::open_out(dir.path()).unwrap();
    let err = write_new(&out, "planted.tmp", b"anchor").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
}

#[tokio::test]
async fn an_overlapping_run_into_the_same_out_dir_is_refused() {
    let a0 = anchor0();
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let mut b = Node::honest(&a0, 5);
    let (root, reply) = b.state.take().unwrap();
    b.state = Some((root, Reply::Gated(gate.clone(), Box::new(reply))));
    let net = std::sync::Arc::new(Net::start(Node::honest(&a0, 5), b).await);

    // Run 1 holds the out dir while it waits for the state.
    let first = tokio::spawn({
        let net = net.clone();
        async move { net.run().await }
    });
    let state_path = format!("/eth/v2/debug/beacon/states/{}", root_hex(&a0.state_root));
    while !net.b.paths().contains(&state_path) {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    // Run 2 is refused at once, without touching the run log.
    let log_before = net.run_log();
    let err = net.run().await.unwrap_err();
    assert!(matches!(err, AnchorError::OutDirBusy { .. }), "{err:?}");
    assert_eq!(err.name(), "out_dir_busy");
    assert_ne!(err.exit_code(), 0);
    assert_eq!(net.run_log(), log_before);

    gate.notify_one();
    let anchor = first.await.unwrap().unwrap();
    let block = std::fs::read(net.out.join(BLOCK_FILE)).unwrap();
    let state = std::fs::read(net.out.join(STATE_FILE)).unwrap();
    assert_eq!(anchor.block.sha256, sha256_hex(&block));
    assert_eq!(anchor.state.sha256, sha256_hex(&state));
    assert_eq!(block, a0.block.as_ssz_bytes());
    assert_eq!(state, a0.state.as_ssz_bytes());
    assert_eq!(anchor.block_root, root_hex(&a0.root));
    assert_eq!(anchor.state_root, root_hex(&a0.state_root));
    assert_eq!(runlog::verify(&net.run_log()), Ok(()));
}

#[tokio::test]
async fn each_run_quarantines_into_its_own_directory() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    // A leftover from a crashed run is neither reused nor touched.
    let stale = net.out.join(QUARANTINE_DIR).join("stale");
    std::fs::create_dir_all(&stale).unwrap();
    std::fs::write(stale.join(BLOCK_FILE), b"stale").unwrap();
    net.run().await.unwrap();
    assert_eq!(std::fs::read(stale.join(BLOCK_FILE)).unwrap(), b"stale");
    let dirs: Vec<_> = std::fs::read_dir(net.out.join(QUARANTINE_DIR))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        dirs,
        ["stale"],
        "the run's own quarantine is removed after publishing"
    );
}

#[tokio::test]
async fn a_base_path_token_never_reaches_the_run_log_or_the_anchor() {
    let a0 = anchor0();
    let net = Net::start_full(
        Node::honest(&a0, 5),
        Node::honest(&a0, 5),
        ("Operator A", "Operator B"),
        "",
        "/tok3n-s3cret",
    )
    .await;
    let anchor = net.run().await.unwrap();
    let log = net.run_log();
    let anchor_json = std::fs::read_to_string(net.out.join(ANCHOR_FILE)).unwrap();
    for text in [&log, &anchor_json, &format!("{anchor:?}")] {
        assert!(!text.contains("tok3n-s3cret"), "{text}");
    }
    let redacted = format!("http://beta.test:{}/…", net.b.addr.port());
    assert_eq!(anchor.providers[1].url, redacted);
    assert!(log.contains(&redacted));
    assert_eq!(runlog::verify(&log), Ok(()));
}

#[tokio::test]
async fn a_userinfo_secret_never_reaches_the_run_log_or_the_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("anchor-fetch.toml");
    std::fs::write(
        &config,
        "[[provider]]\nname = \"alpha\"\noperator = \"A\"\nurl = \"https://user:hunter2@a.invalid\"\n\
         [[provider]]\nname = \"beta\"\noperator = \"B\"\nurl = \"https://b.invalid\"\n",
    )
    .unwrap();
    let out = dir.path().join("out");
    let err = run::<Mainnet>(&config, &out, false).await.unwrap_err();
    assert_eq!(err.name(), "config");
    assert!(!err.to_string().contains("hunter2") && !format!("{err:?}").contains("hunter2"));
    let log = std::fs::read_to_string(out.join(RUN_LOG_FILE)).unwrap();
    assert!(!log.contains("hunter2"), "{log}");
    assert!(!out.join(ANCHOR_FILE).exists());
}

fn unsafe_reason(err: &AnchorError) -> UnsafeReason {
    match err {
        AnchorError::UnsafePath { reason, .. } => *reason,
        other => panic!("not unsafe_path: {other:?}"),
    }
}

fn chmod(path: &std::path::Path, bits: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}

/// A refused output directory: named error, exit 2, no request made.
fn assert_refused_before_any_request(net: &Net, err: &AnchorError, reason: UnsafeReason) {
    assert_eq!(err.name(), "unsafe_path", "{err:?}");
    assert_eq!(err.exit_code(), 2);
    assert_eq!(unsafe_reason(err), reason);
    assert!(net.a.paths().is_empty() && net.b.paths().is_empty());
}

#[tokio::test]
async fn an_out_dir_that_is_a_symlink_is_refused() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    let real = net.out.with_file_name("real");
    std::fs::create_dir(&real).unwrap();
    symlink(&real, &net.out).unwrap();
    let err = net.run().await.unwrap_err();
    assert_refused_before_any_request(&net, &err, UnsafeReason::Symlink);
    // Nothing was written behind the link: no lock, run log or quarantine.
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
}

#[tokio::test]
async fn a_group_or_other_writable_out_dir_is_refused() {
    for bits in [0o770, 0o707] {
        let a0 = anchor0();
        let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
        std::fs::create_dir(&net.out).unwrap();
        chmod(&net.out, bits);
        let err = net.run().await.unwrap_err();
        assert_refused_before_any_request(&net, &err, UnsafeReason::Writable { mode: bits });
        assert_eq!(std::fs::read_dir(&net.out).unwrap().count(), 0, "{bits:o}");
    }
}

#[tokio::test]
async fn a_quarantine_that_is_a_symlink_is_refused() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    let elsewhere = net.out.with_file_name("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::create_dir(&net.out).unwrap();
    symlink(&elsewhere, net.out.join(QUARANTINE_DIR)).unwrap();
    let err = net.run().await.unwrap_err();
    assert_refused_before_any_request(&net, &err, UnsafeReason::Symlink);
    net.assert_aborted(&err, "unsafe_path");
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[tokio::test]
async fn a_planted_run_log_symlink_is_refused_and_its_target_is_untouched() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    let victim = net.out.with_file_name("victim");
    std::fs::write(&victim, b"keep").unwrap();
    std::fs::create_dir(&net.out).unwrap();
    symlink(&victim, net.out.join(RUN_LOG_FILE)).unwrap();
    let err = net.run().await.unwrap_err();
    assert_refused_before_any_request(&net, &err, UnsafeReason::Symlink);
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    assert!(!net.out.join(ANCHOR_FILE).exists());
}

#[tokio::test]
async fn a_run_into_an_existing_private_out_dir_still_publishes() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    std::fs::create_dir(&net.out).unwrap();
    chmod(&net.out, 0o755);
    std::fs::create_dir(net.out.join(QUARANTINE_DIR)).unwrap();
    chmod(&net.out.join(QUARANTINE_DIR), 0o700);
    let anchor = net.run().await.unwrap();
    let block = std::fs::read(net.out.join(BLOCK_FILE)).unwrap();
    assert_eq!(anchor.block.sha256, sha256_hex(&block));
    assert!(net.out.join(ANCHOR_FILE).exists() && net.out.join(STATE_FILE).exists());
}

/// The abort line of a rollback that left files behind lists them.
fn assert_abort_lists(net: &Net, left: &[PathBuf]) {
    let last: Value = serde_json::from_str(net.run_log().lines().last().unwrap()).unwrap();
    assert_eq!(last["event"], "abort");
    assert_eq!(last["error"], "publish_rollback_incomplete");
    let listed: Vec<_> = last["left"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| PathBuf::from(v.as_str().unwrap()))
        .collect();
    assert_eq!(listed, left);
}

#[tokio::test]
async fn a_failed_rollback_unlink_reports_the_files_left_behind() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    let fs = FailingFs {
        fail_link_to: Some(ANCHOR_FILE),
        fail_unlink_of: Some(BLOCK_FILE),
        ..FailingFs::default()
    };
    let err = net.run_with(&fs).await.unwrap_err();
    assert_eq!(err.name(), "publish_rollback_incomplete", "{err:?}");
    assert_eq!(err.exit_code(), 4);
    let AnchorError::PublishRolledBackIncompletely {
        cause,
        cleanup,
        left,
    } = &err
    else {
        panic!("{err:?}")
    };
    assert_eq!(cause.name(), "io");
    assert!(cleanup.contains("injected unlink failure"), "{cleanup}");
    let block = net.out.join(BLOCK_FILE);
    assert_eq!(left, std::slice::from_ref(&block));
    assert_eq!(err.left_behind(), std::slice::from_ref(&block));
    assert!(
        err.to_string().contains(&block.display().to_string()),
        "{err}"
    );
    // The block is really still there; the state was removed and no anchor was published.
    assert!(block.exists());
    assert!(!net.out.join(STATE_FILE).exists() && !net.out.join(ANCHOR_FILE).exists());
    assert_abort_lists(&net, &[block]);
}

#[tokio::test]
async fn a_failed_rollback_fsync_reports_the_files_left_behind() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    let fs = FailingFs {
        fail_link_to: Some(ANCHOR_FILE),
        fail_sync_calls: &[0],
        ..FailingFs::default()
    };
    let err = net.run_with(&fs).await.unwrap_err();
    assert_eq!(err.name(), "publish_rollback_incomplete", "{err:?}");
    assert_ne!(err.exit_code(), 0);
    let AnchorError::PublishRolledBackIncompletely { cleanup, left, .. } = &err else {
        panic!("{err:?}")
    };
    assert!(cleanup.contains("injected fsync failure"), "{cleanup}");
    // The removals are not durable, so every removed file is listed: the anchor temp file,
    // then the state and the block (newest first).
    let names: Vec<_> = left
        .iter()
        .map(|p| {
            assert_eq!(p.parent().unwrap(), net.out);
            p.file_name().unwrap().to_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(names.len(), 3, "{names:?}");
    assert!(names[0].starts_with(".anchor.json.") && names[0].ends_with(".tmp"));
    assert_eq!(names[1..], [STATE_FILE, BLOCK_FILE]);
    net.assert_nothing_published();
    assert_abort_lists(&net, left);
}

#[tokio::test]
async fn a_failed_rollback_after_a_failed_publish_fsync_lists_the_temp_file_too() {
    // Every link succeeds and the temp file is already gone when the publish's own fsync
    // fails; the rollback's fsync fails too, so none of the four removals is durable.
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    let fs = FailingFs {
        fail_sync_calls: &[0, 1],
        ..FailingFs::default()
    };
    let err = net.run_with(&fs).await.unwrap_err();
    assert_eq!(err.name(), "publish_rollback_incomplete", "{err:?}");
    let AnchorError::PublishRolledBackIncompletely { cause, left, .. } = &err else {
        panic!("{err:?}")
    };
    assert_eq!(cause.name(), "io");
    let names: Vec<_> = left
        .iter()
        .map(|p| {
            assert_eq!(p.parent().unwrap(), net.out);
            p.file_name().unwrap().to_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(names.len(), 4, "{names:?}");
    assert!(names[0].starts_with(".anchor.json.") && names[0].ends_with(".tmp"));
    assert_eq!(names[1..], [ANCHOR_FILE, STATE_FILE, BLOCK_FILE]);
    net.assert_nothing_published();
    assert_abort_lists(&net, left);
}

#[tokio::test]
async fn a_directory_at_the_run_log_or_lock_is_refused() {
    for name in [RUN_LOG_FILE, LOCK_FILE] {
        let a0 = anchor0();
        let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
        std::fs::create_dir_all(net.out.join(name)).unwrap();
        let err = net.run().await.unwrap_err();
        assert_refused_before_any_request(
            &net,
            &err,
            UnsafeReason::WrongType {
                expected: "regular file",
                got: "directory",
            },
        );
    }
}

// --- anchor-fetch --check ----------------------------------------------------------------------

/// Fixture nodes on their own runtime, so `cli::main` (which builds its own) can run on the
/// test thread.
struct CheckNet {
    net: Net,
    _runtime: tokio::runtime::Runtime,
}

impl CheckNet {
    fn start(a: Node, b: Node) -> Self {
        Self::start_with_prefix(a, b, "")
    }

    fn start_with_prefix(a: Node, b: Node, b_prefix: &str) -> Self {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let net = runtime.block_on(Net::start_full(
            a,
            b,
            ("Operator A", "Operator B"),
            "",
            b_prefix,
        ));
        Self {
            net,
            _runtime: runtime,
        }
    }

    /// `anchor-fetch --providers A,B --check` exactly as the binary runs it, with a fresh
    /// scratch parent: the exit code, and the scratch parent's entries afterwards.
    fn check(&self) -> (u8, Vec<String>) {
        let urls = self.net.provider_urls();
        check_cli(&urls)
    }
}

/// Runs the CLI's check on `urls` with a fresh scratch parent; returns the exit code and what
/// is left in the scratch parent.
fn check_cli(urls: &str) -> (u8, Vec<String>) {
    check_cli_with(urls, &[])
}

/// [`check_cli`] with the arguments `extra` too.
fn check_cli_with(urls: &str, extra: &[&str]) -> (u8, Vec<String>) {
    let scratch = tempfile::tempdir().unwrap();
    let args: Vec<String> = [
        "--providers",
        urls,
        "--allow-insecure-http",
        "--check",
        "--scratch",
        scratch.path().to_str().unwrap(),
        "--quiet",
    ]
    .iter()
    .chain(extra)
    .map(|a| (*a).to_owned())
    .collect();
    let code = crate::checkpoint::cli::main_with(&args, &apart());
    let left = std::fs::read_dir(scratch.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    (code, left)
}

/// A non-zero exit, nothing left in the scratch parent, and no anchor, block or state in the
/// fixture's output directory (which a check never opens).
fn assert_check_refused(net: &Net, (code, left): (u8, Vec<String>), want: u8) {
    assert_eq!(code, want, "exit code");
    assert!(left.is_empty(), "left in the scratch dir: {left:?}");
    assert!(!net.out.exists(), "a check created the output directory");
}

#[test]
fn mismatch_exit_code() {
    let a0 = anchor0();
    // B's header names another state root than A's: the providers disagree on it.
    let mut other = a0.block.clone();
    other.message.state_root = Root::repeat_byte(0x44);
    let mut b = Node::honest(&a0, 5);
    b.headers = vec![(a0.root, header_json(&other, a0.root, true))];
    let net = CheckNet::start(Node::honest(&a0, 5), b);
    assert_check_refused(&net.net, net.check(), 1);
    assert!(!net.net.b.paths().iter().any(|p| p.starts_with("/eth/v2/")));

    // Both headers agree, but the state B serves under that root hashes to another one.
    let mut wrong = post_state(&a0.block.message);
    wrong.genesis_time = 1;
    let mut b = Node::honest(&a0, 5);
    b.state = Some((
        a0.state_root,
        Reply::Ssz {
            body: Bytes::from(wrong.as_ssz_bytes()),
            version: Some("gloas"),
        },
    ));
    let net = CheckNet::start(Node::honest(&a0, 5), b);
    assert_check_refused(&net.net, net.check(), 1);
    let state_path = format!("/eth/v2/debug/beacon/states/{}", root_hex(&a0.state_root));
    assert!(
        net.net.b.paths().contains(&state_path),
        "the state was fetched"
    );
}

/// A node finalized at `epoch` on a minimal-preset anchor, as the Kurtosis devnet serves one.
fn honest_minimal(epoch: u64) -> Node {
    let (block, state) = anchor::<Minimal>(SLOT);
    let root = block.message.tree_hash_root();
    Node {
        finalized_epoch: epoch,
        finalized_root: root,
        headers: vec![(root, header_json(&block, root, true))],
        block: Some((root, Bytes::from(block.as_ssz_bytes()))),
        state: Some((
            state.tree_hash_root(),
            Reply::Ssz {
                body: Bytes::from(state.as_ssz_bytes()),
                version: Some("gloas"),
            },
        )),
    }
}

/// A minimal-preset anchor (the devnet's) passes only with `--preset minimal`: by the mainnet
/// preset its block does not decode, and the check fails.
#[test]
fn a_minimal_anchor_needs_the_minimal_preset() {
    // Slot 100 is in minimal epoch 12: finalized at 13, the anchor is its epoch's last block.
    let net = CheckNet::start(honest_minimal(13), honest_minimal(13));
    let urls = net.net.provider_urls();
    let (code, left) = check_cli_with(&urls, &["--preset", "minimal"]);
    assert_eq!(code, 0);
    assert!(left.is_empty(), "left in the scratch dir: {left:?}");
    let (code, left) = check_cli(&urls);
    assert_ne!(code, 0, "a minimal block by the mainnet preset");
    assert!(left.is_empty(), "left in the scratch dir: {left:?}");
}

#[test]
fn check_block_root_mismatch_exit_code() {
    let a0 = anchor0();
    let mut a = Node::honest(&a0, 5);
    let mut other = a0.block.clone();
    other.message.proposer_index += 1;
    a.block = Some((a0.root, Bytes::from(other.as_ssz_bytes())));
    let net = CheckNet::start(a, Node::honest(&a0, 5));
    assert_check_refused(&net.net, net.check(), 1);
}

#[test]
fn check_header_state_root_mismatch_exit_code() {
    // Both headers agree on a state_root that is not the block's.
    let a0 = anchor0();
    let mut forged = a0.block.clone();
    forged.message.state_root = Root::repeat_byte(0x55);
    let header = header_json(&forged, a0.root, true);
    let (mut a, mut b) = (Node::honest(&a0, 5), Node::honest(&a0, 5));
    a.headers = vec![(a0.root, header.clone())];
    b.headers = vec![(a0.root, header)];
    let net = CheckNet::start(a, b);
    assert_check_refused(&net.net, net.check(), 1);
}

#[test]
fn check_unreachable_provider_exit_code() {
    let a0 = anchor0();
    let net = CheckNet::start(Node::honest(&a0, 5), Node::honest(&a0, 5));
    // A port that refuses every connection on beta.test (::1).
    let closed =
        crate::checkpoint::refused::refused_tcp_addr(std::net::Ipv6Addr::LOCALHOST.into()).port();
    let urls = format!(
        "http://127.0.0.1:{},http://beta.test:{closed}",
        net.net.a.addr.port()
    );
    assert_check_refused(&net.net, check_cli(&urls), 3);
}

#[test]
fn check_refuses_one_provider_given_twice() {
    let a0 = anchor0();
    let net = CheckNet::start(Node::honest(&a0, 5), Node::honest(&a0, 5));
    let one = format!("http://127.0.0.1:{}", net.net.a.addr.port());
    assert_check_refused(&net.net, check_cli(&format!("{one},{one}")), 2);
    assert!(
        net.net.a.paths().is_empty(),
        "a refused check made a request"
    );
}

#[test]
fn check_passes_when_both_providers_agree_and_writes_nothing() {
    let a0 = anchor0();
    let net = CheckNet::start(Node::honest(&a0, 5), Node::honest(&a0, 5));
    let (code, left) = net.check();
    assert_eq!(code, 0);
    assert!(left.is_empty(), "left in the scratch dir: {left:?}");
    assert!(!net.net.out.exists());
    // The block came from A and the state from B, both by root.
    let block_path = format!("/eth/v2/beacon/blocks/{}", root_hex(&a0.root));
    let state_path = format!("/eth/v2/debug/beacon/states/{}", root_hex(&a0.state_root));
    assert!(net.net.a.paths().contains(&block_path));
    assert!(net.net.b.paths().contains(&state_path));
    assert!(!net.net.a.paths().contains(&state_path));
    assert!(!net.net.b.paths().contains(&block_path));
}

#[tokio::test]
async fn check_names_both_providers_by_origin_only() {
    let a0 = anchor0();
    let net = Net::start_full(
        Node::honest(&a0, 5),
        Node::honest(&a0, 5),
        ("Operator A", "Operator B"),
        "",
        "/tok3n-s3cret",
    )
    .await;
    let config = Config::from_provider_urls(&net.provider_urls(), true).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let (result, log) =
        check_logged::<Mainnet>(&config, scratch.path(), RunLog::in_memory(false), &apart()).await;
    let agreement = result.unwrap();
    assert_eq!(agreement.block_root, root_hex(&a0.root));
    assert_eq!(agreement.state_root, root_hex(&a0.state_root));
    assert_eq!((agreement.slot, agreement.finalized_epoch), (SLOT, 5));
    assert_eq!(agreement.fork, "gloas");
    let urls: Vec<_> = agreement.providers.iter().map(|p| p.url.as_str()).collect();
    let a_origin = format!("http://127.0.0.1:{}", net.a.addr.port());
    let b_origin = format!("http://beta.test:{}/…", net.b.addr.port());
    assert_eq!(urls, [a_origin.as_str(), b_origin.as_str()]);
    let text = log.text();
    assert_eq!(runlog::verify(text), Ok(()));
    assert!(
        text.contains(&a_origin) && text.contains(&b_origin),
        "{text}"
    );
    assert!(!text.contains("tok3n-s3cret"), "{text}");
    assert!(!format!("{agreement:?}").contains("tok3n-s3cret"));
    let last: Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(last["event"], "agreed");
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn a_failed_check_logs_the_abort_and_cleans_its_scratch_dir() {
    let a0 = anchor0();
    let mut a = Node::honest(&a0, 5);
    a.block = Some((a0.root, Bytes::from_static(b"not ssz")));
    let net = Net::start(a, Node::honest(&a0, 5)).await;
    let config = Config::from_provider_urls(&net.provider_urls(), true).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let (result, log) =
        check_logged::<Mainnet>(&config, scratch.path(), RunLog::in_memory(false), &apart()).await;
    let err = result.unwrap_err();
    assert_eq!(err.name(), "decode");
    let last: Value = serde_json::from_str(log.text().lines().last().unwrap()).unwrap();
    assert_eq!(last["event"], "abort");
    assert_eq!(last["error"], "decode");
    assert_eq!(std::fs::read_dir(scratch.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn a_check_into_a_missing_scratch_parent_is_a_local_io_error() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    let config = Config::from_provider_urls(&net.provider_urls(), true).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let missing = scratch.path().join("missing");
    let err = check::<Mainnet>(&config, &missing, false)
        .await
        .unwrap_err();
    assert_eq!(err.name(), "io", "{err:?}");
    assert!(!missing.exists());
    assert!(net.a.paths().is_empty() && net.b.paths().is_empty());
}

#[test]
fn check_needs_both_providers_at_the_same_finalized_epoch() {
    // A normal fetch takes the lower checkpoint when one provider is ahead; the start gate
    // does not: the providers must report the same finalized checkpoint.
    let a0 = anchor0();
    let net = CheckNet::start(Node::honest(&a0, 5), Node::honest(&a0, 6));
    assert_check_refused(&net.net, net.check(), 1);
    assert!(!net.net.a.paths().iter().any(|p| p.starts_with("/eth/v2/")));
}

#[tokio::test]
async fn providers_resolving_to_a_common_address_are_refused_before_any_request() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    for (answer, shared) in [
        (vec!["192.0.2.1", "127.0.0.1"], "127.0.0.1"),
        (vec!["::ffff:127.0.0.1"], "127.0.0.1"),
    ] {
        let answer = answer.iter().map(|a| a.parse().unwrap()).collect();
        let err = run_with::<Mainnet>(&net.config, &net.out, false, &RealFs, &resolver(Ok(answer)))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AnchorError::SameAddress { addr, .. } if addr.to_string() == shared),
            "{err:?}"
        );
        net.assert_aborted(&err, "same_address");
        assert_eq!(err.exit_code(), 2);
        let config = Config::from_provider_urls(&net.provider_urls(), true).unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let shared_answer = vec![shared.parse().unwrap()];
        let (result, _) = check_logged::<Mainnet>(
            &config,
            scratch.path(),
            RunLog::in_memory(false),
            &resolver(Ok(shared_answer)),
        )
        .await;
        assert_eq!(result.unwrap_err().name(), "same_address");
    }
    assert!(net.a.paths().is_empty() && net.b.paths().is_empty());
}

#[tokio::test]
async fn a_provider_that_does_not_resolve_is_unreachable() {
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    for answer in [Err(std::io::Error::other("NXDOMAIN")), Ok(vec![])] {
        let err = run_with::<Mainnet>(&net.config, &net.out, false, &RealFs, &resolver(answer))
            .await
            .unwrap_err();
        net.assert_aborted(&err, "transport");
        assert_eq!(err.exit_code(), 3);
    }
    assert!(net.a.paths().is_empty() && net.b.paths().is_empty());
}

#[test]
fn a_scratch_dir_is_removed_when_dropped() {
    let parent = tempfile::tempdir().unwrap();
    let scratch = Scratch::create(parent.path()).unwrap();
    std::fs::write(scratch.path.join("partial"), b"body").unwrap();
    std::fs::create_dir(scratch.path.join(QUARANTINE_DIR)).unwrap();
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 1);
    drop(scratch);
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn a_cancelled_check_removes_its_scratch_dir() {
    // The check is dropped mid-download (a signal, a timeout): nothing may stay behind.
    let a0 = anchor0();
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let mut b = Node::honest(&a0, 5);
    let (root, reply) = b.state.take().unwrap();
    b.state = Some((root, Reply::Gated(gate.clone(), Box::new(reply))));
    let net = Net::start(Node::honest(&a0, 5), b).await;
    let config = Config::from_provider_urls(&net.provider_urls(), true).unwrap();
    let parent = tempfile::tempdir().unwrap();
    let scratch_parent = parent.path().to_owned();
    let task = tokio::spawn(async move {
        check_logged::<Mainnet>(&config, &scratch_parent, RunLog::in_memory(false), &apart())
            .await
            .0
    });
    let state_path = format!("/eth/v2/debug/beacon/states/{}", root_hex(&a0.state_root));
    while !net.b.paths().contains(&state_path) {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    // The block is already in this run's quarantine.
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}

/// Answers `beta.test` with `first`, then with `later` on every further lookup.
struct ChangingResolver {
    first: std::net::IpAddr,
    later: std::net::IpAddr,
    lookups: AtomicUsize,
}

impl Resolve for ChangingResolver {
    fn resolve<'a>(&'a self, host: &'a str, _port: u16) -> Resolution<'a> {
        let answer = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) if self.lookups.fetch_add(1, Ordering::SeqCst) == 0 => vec![self.first],
            Err(_) => vec![self.later],
        };
        Box::pin(async move { Ok(answer) })
    }
}

#[tokio::test]
async fn the_fetch_dials_exactly_the_addresses_the_independence_check_saw() {
    // After the check, beta.test "moves" onto A's address. The fetch still dials ::1, and the
    // name is never looked up again: no second answer can put both providers on one machine.
    let a0 = anchor0();
    let net = Net::start(Node::honest(&a0, 5), Node::honest(&a0, 5)).await;
    let resolver = ChangingResolver {
        first: std::net::Ipv6Addr::LOCALHOST.into(),
        later: std::net::Ipv4Addr::LOCALHOST.into(),
        lookups: AtomicUsize::new(0),
    };
    let anchor = run_with::<Mainnet>(&net.config, &net.out, false, &RealFs, &resolver)
        .await
        .unwrap();
    assert_eq!(anchor.block_root, root_hex(&a0.root));
    assert_eq!(
        resolver.lookups.load(Ordering::SeqCst),
        1,
        "beta.test resolved once"
    );
    let state_path = format!("/eth/v2/debug/beacon/states/{}", root_hex(&a0.state_root));
    assert!(
        net.b.paths().contains(&state_path),
        "B, at ::1, served the state"
    );
    assert!(!net.a.paths().contains(&state_path));
    // The name stays in the Host header.
    let host = net.b.seen()[0].headers["host"].to_str().unwrap().to_owned();
    assert_eq!(host, format!("beta.test:{}", net.b.addr.port()));
}
