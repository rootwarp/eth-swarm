//! Serving the custody columns on local swarms: `DataColumnSidecarsByRange` v1 and
//! `DataColumnSidecarsByRoot` v1 answered from a scripted [`ColumnSource`], under the same
//! per-peer quota and stream cap as every other protocol, the quota booked when a request is
//! admitted, the answer places and the answer budget.

use super::{
    bytes_connect, bytes_peer, config, result_code, send_bytes, status_with, tcp_swarm, Node,
    RawPeer, DIGEST, E, WAIT,
};
use crate::rpc::codec::ReceivedChunk;
use crate::rpc::columns::{ColumnLookup, ColumnReply, ColumnSource, ServedColumn};
use crate::rpc::inbound::{ControlConfig, COLUMN_LOOKUP_TIMEOUT, COLUMN_QUEUE};
use crate::rpc::limits::{Quota, RpcLimits};
use consensus_types::forked;
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::StreamProtocol;
use network_config::ForkName;
use p2p_wire::rpc::codec::{encode_chunk, encode_request};
use p2p_wire::rpc::messages::{
    DataColumnsByRangeV1Request, DataColumnsByRootIdentifier, DataColumnsByRootV1Request,
};
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
use p2p_wire::testkit::{gloas_sidecar, FULU_DIGEST, GLOAS_DIGEST};
use ssz::Encode;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// A column source answering every request with `reply`, once `gate` (if any) lets it.
struct Scripted {
    reply: ColumnReply,
    gate: Option<Arc<Semaphore>>,
    asked: Mutex<Vec<String>>,
}

impl Scripted {
    fn new(reply: ColumnReply) -> Arc<Self> {
        Arc::new(Self {
            reply,
            gate: None,
            asked: Mutex::default(),
        })
    }

    fn gated(reply: ColumnReply, gate: Arc<Semaphore>) -> Arc<Self> {
        Arc::new(Self {
            reply,
            gate: Some(gate),
            asked: Mutex::default(),
        })
    }

    fn asked(&self) -> usize {
        self.asked.lock().unwrap().len()
    }

    fn lookup(&self, what: String) -> ColumnLookup {
        self.asked.lock().unwrap().push(what);
        let (reply, gate) = (self.reply.clone(), self.gate.clone());
        Box::pin(async move {
            if let Some(gate) = gate {
                let _permit = gate.acquire().await;
            }
            reply
        })
    }
}

impl ColumnSource for Scripted {
    fn by_range(&self, request: &DataColumnsByRangeV1Request) -> ColumnLookup {
        self.lookup(format!("range {} {}", request.start_slot, request.count))
    }

    fn by_root(&self, request: &DataColumnsByRootV1Request) -> ColumnLookup {
        self.lookup(format!("root {}", request.0.len()))
    }
}

/// The custody columns of node `U256::MAX`.
const CUSTODY: [u64; 4] = [1, 47, 87, 102];

/// The fixture root of the block at `slot`.
fn root_of(slot: u64) -> [u8; 32] {
    let mut root = [0x40; 32];
    root[..8].copy_from_slice(&slot.to_be_bytes());
    root
}

fn served(slot: u64, index: u64) -> ServedColumn {
    let mut sidecar = gloas_sidecar::<E>(slot, index);
    sidecar.beacon_block_root = root_of(slot).into();
    ServedColumn {
        context: GLOAS_DIGEST,
        fork: ForkName::Gloas,
        slot,
        block_root: root_of(slot),
        ssz: sidecar.as_ssz_bytes(),
    }
}

/// Every custody column of `slots`, in `(slot, column_index)` order.
fn block_columns(slots: std::ops::Range<u64>) -> Vec<ServedColumn> {
    slots
        .flat_map(|slot| CUSTODY.map(|index| served(slot, index)))
        .collect()
}

fn with_columns(source: Arc<dyn ColumnSource>) -> ControlConfig {
    ControlConfig {
        columns: Some(source),
        ..config(status_with(DIGEST), 1, 4)
    }
}

fn by_range(start_slot: u64, count: u64, columns: &[u64]) -> Request {
    Request::DataColumnsByRange(DataColumnsByRangeV1Request {
        start_slot,
        count,
        columns: columns.to_vec().try_into().unwrap(),
    })
}

fn by_root(ids: &[([u8; 32], &[u64])]) -> Request {
    let ids: Vec<_> = ids
        .iter()
        .map(|(root, columns)| DataColumnsByRootIdentifier {
            block_root: (*root).into(),
            columns: columns.to_vec().try_into().unwrap(),
        })
        .collect();
    Request::DataColumnsByRoot(DataColumnsByRootV1Request(ids.try_into().unwrap()))
}

/// A requester connected to `node`.
async fn requester(node: &Node) -> RawPeer {
    let mut raw = RawPeer::new(1);
    raw.connect(node.addr.clone()).await;
    raw
}

/// The code and message of an answer that is one error chunk.
fn refusal(chunks: &[ReceivedChunk<E>]) -> (ResultCode, String) {
    match chunks {
        [ReceivedChunk {
            context: None,
            chunk: ResponseChunk::Error { code, message },
        }] => (*code, String::from_utf8_lossy(message).into_owned()),
        other => panic!("not one error chunk: {other:?}"),
    }
}

/// The code of an answer that is one error chunk.
fn refused(chunks: &[ReceivedChunk<E>]) -> ResultCode {
    refusal(chunks).0
}

/// The sidecars of a success answer, each with its context.
fn sidecars(chunks: Vec<ReceivedChunk<E>>) -> Vec<([u8; 4], Vec<u8>)> {
    chunks
        .into_iter()
        .map(|c| match c {
            ReceivedChunk {
                context: Some(context),
                chunk: ResponseChunk::Success(Response::DataColumn(sidecar)),
            } => {
                assert!(matches!(*sidecar, forked::DataColumnSidecar::Gloas(_)));
                (context, sidecar.as_ssz_bytes())
            }
            other => panic!("not a sidecar: {other:?}"),
        })
        .collect()
}

fn wire(stored: &[ServedColumn]) -> Vec<([u8; 4], Vec<u8>)> {
    stored.iter().map(|s| (s.context, s.ssz.clone())).collect()
}

#[tokio::test]
async fn columns_are_served_by_range_and_root_with_the_digest_of_their_slot() {
    let stored = block_columns(9..11);
    let source = Scripted::new(ColumnReply::Sidecars(stored.clone()));
    let ours = Node::spawn(with_columns(source.clone())).await;
    let mut raw = requester(&ours).await;

    let id = raw.send(ours.peer, by_range(9, 2, &CUSTODY));
    assert_eq!(sidecars(raw.outcome(id).await.unwrap()), wire(&stored));
    let id = raw.send(
        ours.peer,
        by_root(&[(root_of(9), &CUSTODY), (root_of(10), &CUSTODY)]),
    );
    assert_eq!(sidecars(raw.outcome(id).await.unwrap()), wire(&stored));
    assert_eq!(*source.asked.lock().unwrap(), ["range 9 2", "root 2"]);

    // A request that names no sidecar is an empty answer, without a lookup.
    let id = raw.send(ours.peer, by_range(9, 0, &CUSTODY));
    assert_eq!(raw.outcome(id).await.unwrap(), Vec::new());
    let id = raw.send(ours.peer, by_root(&[]));
    assert_eq!(raw.outcome(id).await.unwrap(), Vec::new());
    assert_eq!(source.asked(), 2);
}

/// SEC-004: a refusal goes out with the fixed message of its code, whatever the source said.
#[tokio::test]
async fn refusals_go_out_as_error_chunks_never_as_an_empty_success() {
    let source = Scripted::new(ColumnReply::Refused(
        ResultCode::ResourceUnavailable,
        "mdbx: MDBX_PANIC at /var/lib/ethswarm/columns".into(),
    ));
    let ours = Node::spawn(with_columns(source)).await;
    let mut raw = requester(&ours).await;
    for request in [by_range(0, 32, &CUSTODY), by_root(&[([1; 32], &[47])])] {
        let id = raw.send(ours.peer, request);
        let chunks = raw.outcome(id).await.unwrap();
        assert_eq!(
            refusal(&chunks),
            (
                ResultCode::ResourceUnavailable,
                "resource unavailable".into()
            )
        );
    }
    let failing = Scripted::new(ColumnReply::server_error("column stream: seq gap at 7"));
    let ours = Node::spawn(with_columns(failing)).await;
    let mut raw = requester(&ours).await;
    let id = raw.send(ours.peer, by_range(0, 32, &CUSTODY));
    assert_eq!(
        refusal(&raw.outcome(id).await.unwrap()),
        (ResultCode::ServerError, "server error".into())
    );

    // No column store at all: unavailable too.
    let none = Node::spawn(config(status_with(DIGEST), 1, 4)).await;
    let mut raw = requester(&none).await;
    let id = raw.send(none.peer, by_range(0, 32, &CUSTODY));
    assert_eq!(
        refused(&raw.outcome(id).await.unwrap()),
        ResultCode::ResourceUnavailable
    );
}

#[tokio::test]
async fn requests_past_their_bounds_are_invalid() {
    let source = Scripted::new(ColumnReply::Sidecars(Vec::new()));
    let ours = Node::spawn(with_columns(source.clone())).await;
    let mut raw = requester(&ours).await;
    let all: Vec<u64> = (0..128).collect();
    for request in [
        // An index at NUMBER_OF_COLUMNS.
        by_range(0, 1, &[128]),
        by_root(&[([1; 32], &[47, 200])]),
        // 129 × 128 sidecars, past MAX_REQUEST_DATA_COLUMN_SIDECARS.
        by_range(0, 129, &all),
    ] {
        let id = raw.send(ours.peer, request);
        let chunks = raw.outcome(id).await.unwrap();
        assert_eq!(
            refusal(&chunks),
            (ResultCode::InvalidRequest, "invalid request".into())
        );
    }
    // 128 × 128 is the most a request may name.
    let id = raw.send(ours.peer, by_range(0, 128, &all));
    assert_eq!(raw.outcome(id).await.unwrap(), Vec::new());

    // 129 identifiers: past the list's limit, malformed on the wire.
    let mut ssz: Vec<u8> = (0..129u32)
        .flat_map(|i| (129 * 4 + i * 40).to_le_bytes())
        .collect();
    for _ in 0..129 {
        let mut id = vec![0u8; 40];
        id[32..36].copy_from_slice(&36u32.to_le_bytes());
        ssz.extend(id);
    }
    let wire = send_bytes(
        &ours,
        Protocol::DataColumnsByRootV1,
        encode_chunk(&ssz).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        result_code(Protocol::DataColumnsByRootV1, &wire),
        ResultCode::InvalidRequest
    );
    assert_eq!(source.asked(), 1, "only the valid one");
}

#[tokio::test]
async fn an_answer_the_probe_cannot_vouch_for_is_a_server_error() {
    let mut wrong_context = block_columns(9..10);
    wrong_context[2].context = FULU_DIGEST;
    let mut wrong_slot = block_columns(9..10);
    wrong_slot[1] = served(10, 47);
    wrong_slot[1].slot = 9;
    wrong_slot[1].block_root = root_of(9);
    let mut wrong_root = block_columns(9..10);
    wrong_root[1].block_root = root_of(8);
    wrong_root[1].slot = 9;
    let mut garbage = block_columns(9..10);
    garbage[3].ssz.truncate(20);
    for stored in [wrong_context, wrong_slot, wrong_root, garbage] {
        let ours = Node::spawn(with_columns(Scripted::new(ColumnReply::Sidecars(stored)))).await;
        let mut raw = requester(&ours).await;
        let id = raw.send(ours.peer, by_range(9, 1, &CUSTODY));
        assert_eq!(
            refused(&raw.outcome(id).await.unwrap()),
            ResultCode::ServerError
        );
    }
}

/// SEC-006: a sidecar the request did not name (another slot, index or root, or one named
/// twice) is dropped and counted, never sent.
#[tokio::test]
async fn unrequested_sidecars_are_dropped_and_counted() {
    let mut stored = block_columns(9..11);
    stored.push(served(10, 102)); // twice
    stored.push(served(11, 1)); // past the range
    let source = Scripted::new(ColumnReply::Sidecars(stored.clone()));
    let ours = Node::spawn(with_columns(source)).await;
    let mut raw = requester(&ours).await;
    let id = raw.send(ours.peer, by_range(9, 2, &[1, 47]));
    let got = sidecars(raw.outcome(id).await.unwrap());
    let want: Vec<_> = [&stored[0], &stored[1], &stored[4], &stored[5]]
        .iter()
        .map(|s| (s.context, s.ssz.clone()))
        .collect();
    assert_eq!(got, want);
    assert_eq!(ours.metrics.column_unrequested(), 6);
    // By root: only the named roots' named columns.
    let id = raw.send(ours.peer, by_root(&[(root_of(10), &[87, 102])]));
    let got = sidecars(raw.outcome(id).await.unwrap());
    assert_eq!(got, wire(&stored[6..8]));
    assert_eq!(ours.metrics.column_unrequested(), 6 + 8);
}

// ---------------------------------------------------------------------------------------------
// The shared limits

/// BUG-002 and the byte budget: an answer is cut at the last whole block within the sidecars
/// its quota delivers in the answer window, and within its bytes; the first block always goes.
#[tokio::test]
async fn answers_are_cut_at_a_whole_block_by_count_and_bytes() {
    let stored = block_columns(9..29);
    // 8 at once, one per 10 ms, 100 ms to deliver: 18 sidecars, half of them an answer's
    // share, two whole blocks.
    let mut cfg = with_columns(Scripted::new(ColumnReply::Sidecars(stored.clone())));
    cfg.limits.rate.data_columns_by_range = Quota::new(8, Duration::from_millis(10));
    cfg.limits.column_answer_window = Duration::from_millis(100);
    assert_eq!(
        cfg.limits
            .column_answer_sidecars(Protocol::DataColumnsByRangeV1),
        9
    );
    let ours = Node::spawn(cfg).await;
    let mut raw = requester(&ours).await;
    let id = raw.send(ours.peer, by_range(9, 20, &CUSTODY));
    assert_eq!(sidecars(raw.outcome(id).await.unwrap()), wire(&stored[..8]));

    // Bytes: one and a half blocks' worth holds the first block only.
    let one_block: usize = stored[..4].iter().map(|s| s.ssz.len()).sum();
    let mut cfg = with_columns(Scripted::new(ColumnReply::Sidecars(stored.clone())));
    cfg.limits.max_column_response_bytes = one_block + one_block / 2;
    let ours = Node::spawn(cfg).await;
    let mut raw = requester(&ours).await;
    let id = raw.send(ours.peer, by_range(9, 2, &CUSTODY));
    assert_eq!(sidecars(raw.outcome(id).await.unwrap()), wire(&stored[..4]));
    // Even a first block past it goes whole, as cl-chain sends it.
    let mut cfg = with_columns(Scripted::new(ColumnReply::Sidecars(stored.clone())));
    cfg.limits.max_column_response_bytes = 1;
    let ours = Node::spawn(cfg).await;
    let mut raw = requester(&ours).await;
    let id = raw.send(ours.peer, by_range(9, 2, &CUSTODY));
    assert_eq!(sidecars(raw.outcome(id).await.unwrap()), wire(&stored[..4]));
    // The defaults: 8 MiB, and 756 sidecars, what cl-chain cuts at too; and no more answer
    // places than cl-chain runs reads, so a burst of lookups is never refused as overloaded.
    let limits = RpcLimits::default();
    assert_eq!(limits.max_column_response_bytes, 8 << 20);
    for protocol in [
        Protocol::DataColumnsByRangeV1,
        Protocol::DataColumnsByRootV1,
    ] {
        assert_eq!(
            limits.column_answer_sidecars(protocol),
            cl_chain::reqresp::DEFAULT_MAX_RESPONSE_SIDECARS as u64
        );
    }
    assert_eq!(
        limits.max_column_response_bytes,
        cl_chain::reqresp::DEFAULT_MAX_RESPONSE_BYTES
    );
    assert!(limits.max_column_answers <= cl_chain::reqresp::DEFAULT_MAX_READS);
    assert_eq!(
        crate::rpc::limits::DEFAULT_MAX_COLUMN_ANSWERS,
        cl_chain::reqresp::DEFAULT_MAX_READS
    );
}

/// BUG-002: two answers of the most sidecars at once, as a peer may have two streams open,
/// both complete within the requester's deadlines, each cut at a whole block: each books what
/// the bucket can still deliver in the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_concurrent_maximum_answers_both_complete_in_time() {
    let stored = block_columns(9..409);
    let ours = Node::spawn(with_columns(Scripted::new(ColumnReply::Sidecars(stored)))).await;
    let mut raw = requester(&ours).await;
    let start = Instant::now();
    let ids = [
        raw.send(ours.peer, by_range(9, 400, &CUSTODY)),
        raw.send(ours.peer, by_range(9, 400, &CUSTODY)),
    ];
    let mut done = HashMap::new();
    tokio::time::timeout(WAIT, async {
        while done.len() < 2 {
            let event = raw.swarm.select_next_some().await;
            if let Some((id, outcome)) = raw.handle(event) {
                done.insert(id, (outcome, start.elapsed()));
            }
        }
    })
    .await
    .expect("both ended");
    for id in ids {
        let (outcome, at) = done.remove(&id).unwrap();
        let got = sidecars(outcome.expect("answered within the deadlines"));
        assert!(
            !got.is_empty() && got.len().is_multiple_of(4),
            "{} sidecars",
            got.len()
        );
        assert!(got.len() <= 756);
        assert!(at < crate::rpc::REQUEST_TIMEOUT, "{at:?}");
    }
}

/// SEC-006: a Fulu sidecar must carry the header of the root it is served under.
#[tokio::test]
async fn a_fulu_sidecar_is_held_to_its_header_root() {
    use tree_hash::TreeHash;
    let sidecar = p2p_wire::testkit::fulu_sidecar::<E>(9, 47);
    let header_root = sidecar.signed_block_header.message.tree_hash_root().0;
    let fulu = |block_root| ServedColumn {
        context: FULU_DIGEST,
        fork: ForkName::Fulu,
        slot: 9,
        block_root,
        ssz: sidecar.as_ssz_bytes(),
    };
    let ours = Node::spawn(with_columns(Scripted::new(ColumnReply::Sidecars(vec![
        fulu(header_root),
    ]))))
    .await;
    let mut raw = requester(&ours).await;
    let id = raw.send(ours.peer, by_root(&[(header_root, &[47])]));
    let chunks = raw.outcome(id).await.unwrap();
    assert!(
        matches!(&chunks[..], [ReceivedChunk { chunk: ResponseChunk::Success(Response::DataColumn(s)), .. }] if matches!(**s, forked::DataColumnSidecar::Fulu(_))),
        "{chunks:?}"
    );
    let ours = Node::spawn(with_columns(Scripted::new(ColumnReply::Sidecars(vec![
        fulu(root_of(9)),
    ]))))
    .await;
    let mut raw = requester(&ours).await;
    let id = raw.send(ours.peer, by_root(&[(root_of(9), &[47])]));
    assert_eq!(
        refused(&raw.outcome(id).await.unwrap()),
        ResultCode::ServerError
    );
}

/// SEC-001: requesters that stop reading lose their place once a due chunk cannot be written
/// within the write deadline, so stalled requesters holding every place leave an honest one
/// served within its own deadlines. All of them share 127.0.0.1, whose 8 inbound connections
/// (`max_established_incoming_per_ip`) are 7 stalled peers and the honest one, with as many
/// places as stalled peers, every one of them takeable by that IP: the worst case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_requesters_cannot_keep_an_honest_one_out() {
    let stored: Vec<_> = (9..41)
        .flat_map(|slot| CUSTODY.map(|index| big(slot, index, 2)))
        .collect();
    let mut cfg = with_columns(Scripted::new(ColumnReply::Sidecars(stored)));
    cfg.limits.max_column_answers = 7;
    cfg.limits.max_column_answers_per_ip = 7;
    let ours = Node::spawn(cfg).await;
    let request = encode_request(&by_range(9, 32, &CUSTODY)).unwrap();
    let mut stalled = Vec::new();
    for _ in 0..7 {
        let mut swarm = tcp_swarm(request_response::Behaviour::with_codec(
            Stalling,
            [(
                StreamProtocol::new(Protocol::DataColumnsByRangeV1.id()),
                ProtocolSupport::Outbound,
            )],
            request_response::Config::default().with_request_timeout(Duration::from_secs(60)),
        ));
        swarm.dial(ours.addr.clone()).unwrap();
        tokio::time::timeout(WAIT, async {
            while !matches!(
                swarm.select_next_some().await,
                SwarmEvent::ConnectionEstablished { .. }
            ) {}
        })
        .await
        .expect("connected");
        swarm
            .behaviour_mut()
            .send_request(&ours.peer, request.clone());
        stalled.push(swarm);
    }
    let drive = async {
        loop {
            for peer in &mut stalled {
                let _ =
                    tokio::time::timeout(Duration::from_millis(5), peer.select_next_some()).await;
            }
        }
    };
    let metrics = ours.metrics.clone();
    let honest = async {
        // Every place is held by a stalled requester first.
        let deadline = Instant::now() + WAIT;
        while metrics.column_answers_held() < 7 {
            assert!(
                Instant::now() < deadline,
                "the stalled requesters never took the places"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut raw = requester(&ours).await;
        let id = raw.send(ours.peer, by_range(9, 1, &CUSTODY));
        raw.outcome(id).await
    };
    let outcome = tokio::select! {
        () = drive => unreachable!(),
        outcome = honest => outcome,
    };
    let chunks = outcome.expect("answered within its deadlines");
    assert_eq!(sidecars(chunks).len(), 4, "served, not refused");
}

#[tokio::test]
async fn rate_limited_column_chunks_are_withheld_not_errored() {
    // One sidecar per 300 ms, no burst.
    let stored = block_columns(9..10);
    let mut cfg = with_columns(Scripted::new(ColumnReply::Sidecars(stored.clone())));
    cfg.limits.rate.data_columns_by_range = Quota::new(1, Duration::from_millis(300));
    let ours = Node::spawn(cfg).await;
    let mut raw = requester(&ours).await;
    let start = Instant::now();
    let id = raw.send(ours.peer, by_range(9, 1, &CUSTODY));
    let chunks = raw.outcome(id).await.unwrap();
    let took = start.elapsed();
    assert_eq!(sidecars(chunks).len(), 4, "every sidecar, no error chunk");
    assert!(took >= Duration::from_millis(900), "{took:?}");
    assert_eq!(
        ours.metrics
            .rate_limited_count(Protocol::DataColumnsByRangeV1),
        3
    );
    // By root has a bucket of its own: answered at once.
    let start = Instant::now();
    let id = raw.send(ours.peer, by_root(&[(root_of(9), &CUSTODY)]));
    assert_eq!(sidecars(raw.outcome(id).await.unwrap()).len(), 4);
    assert!(start.elapsed() < Duration::from_millis(900));
}

/// SEC-001: the quota a request books when it is admitted is not given back when the peer
/// resets: its next request waits for it.
#[tokio::test]
async fn a_reset_does_not_refund_the_booked_quota() {
    // One sidecar per 300 ms, no burst: four sidecars book 1.2 s.
    let gate = Arc::new(Semaphore::new(0));
    let source = Scripted::gated(ColumnReply::Sidecars(block_columns(9..10)), gate.clone());
    let mut cfg = with_columns(source.clone());
    cfg.limits.rate.data_columns_by_range = Quota::new(1, Duration::from_millis(300));
    let mut ours = Node::spawn(cfg).await;
    let key = libp2p::identity::Keypair::generate_secp256k1();
    let mut raw = RawPeer::with_key(key.clone(), 1);
    raw.connect(ours.addr.clone()).await;
    raw.send(ours.peer, by_range(9, 1, &CUSTODY));
    tokio::time::timeout(WAIT, async {
        while source.asked() == 0 {
            raw.run_for(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the lookup started");
    // The peer resets (leaves) before its answer; the lookup ends unread.
    let peer = raw.id();
    drop(raw);
    ours.closed(peer).await;
    gate.add_permits(100);
    // Back at once, as the same peer: its one sidecar waits for the booked four.
    let mut raw = RawPeer::with_key(key, 1);
    raw.connect(ours.addr.clone()).await;
    let start = Instant::now();
    let id = raw.send(ours.peer, by_range(9, 1, &[47]));
    assert_eq!(sidecars(raw.outcome(id).await.unwrap()).len(), 1);
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(700), "refunded: {took:?}");
}

/// SEC-001: peers that request and reset at once cannot keep an honest peer from a place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reset_flood_cannot_starve_an_honest_peer() {
    let source = Scripted::new(ColumnReply::Sidecars(block_columns(9..41)));
    let mut cfg = with_columns(source.clone());
    cfg.limits.max_column_answers = 2;
    let ours = Node::spawn(cfg).await;
    let flood = |key: libp2p::identity::Keypair| {
        let addr = ours.addr.clone();
        let to = ours.peer;
        async move {
            for _ in 0..10 {
                let mut raw = RawPeer::with_key(key.clone(), 1);
                raw.connect(addr.clone()).await;
                for _ in 0..2 {
                    raw.send(to, by_range(9, 32, &CUSTODY));
                    raw.send(to, by_root(&[(root_of(9), &CUSTODY)]));
                }
                raw.run_for(Duration::from_millis(5)).await;
            }
        }
    };
    let keys: Vec<_> = (0..4)
        .map(|_| libp2p::identity::Keypair::generate_secp256k1())
        .collect();
    let floods = futures::future::join_all(keys.into_iter().map(|key| tokio::spawn(flood(key))));
    let honest = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut raw = requester(&ours).await;
        let mut served = 0;
        for _ in 0..3 {
            let id = raw.send(ours.peer, by_range(9, 1, &CUSTODY));
            if let Ok(chunks) = raw.outcome(id).await {
                if !matches!(
                    chunks.as_slice(),
                    [ReceivedChunk {
                        chunk: ResponseChunk::Error { .. },
                        ..
                    }]
                ) {
                    served += 1;
                }
            }
        }
        served
    };
    let (served, _) = tokio::join!(honest, floods);
    assert_eq!(served, 3, "the honest peer was starved");
    // Each flooding peer's lookups ran one at a time, booked against its own quota.
    assert!(source.asked() < 4 * 10 * 4, "{} lookups", source.asked());
}

/// A requester that never reads its answers: each stays held in our stream until the write
/// gives up.
#[derive(Clone, Default)]
struct Stalling;

impl request_response::Codec for Stalling {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = ();

    async fn read_request<T>(&mut self, _: &StreamProtocol, _: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, _: &mut T) -> io::Result<()>
    where
        T: AsyncRead + Unpin + Send,
    {
        futures::future::pending().await
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        request: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&request).await?;
        io.close().await
    }

    async fn write_response<T>(&mut self, _: &StreamProtocol, _: &mut T, _: ()) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// A Gloas sidecar of `index` at `slot` with `cells` incompressible cells, so its answer
/// overruns the muxer's window.
fn big(slot: u64, index: u64, cells: usize) -> ServedColumn {
    let mut sidecar = gloas_sidecar::<E>(slot, index);
    let mut x = slot * 131 + index;
    let cells: Vec<_> = (0..cells)
        .map(|_| {
            let bytes: Vec<u8> = (0..2048)
                .map(|_| {
                    x = x
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    (x >> 56) as u8
                })
                .collect();
            consensus_types::fulu::Cell::<E>::new(bytes).unwrap()
        })
        .collect();
    let proofs = vec![[0xbb; 48]; cells.len()];
    sidecar.column = cells.try_into().unwrap();
    sidecar.kzg_proofs = proofs.try_into().unwrap();
    sidecar.beacon_block_root = root_of(slot).into();
    ServedColumn {
        context: GLOAS_DIGEST,
        fork: ForkName::Gloas,
        slot,
        block_root: root_of(slot),
        ssz: sidecar.as_ssz_bytes(),
    }
}

/// BUG-001: requesters that never read hold at most the answer places, each at most one
/// answer's budget; the rest wait or are refused, never held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_reading_requesters_hold_at_most_the_answer_places() {
    let stored: Vec<_> = (9..41)
        .flat_map(|slot| CUSTODY.map(|index| big(slot, index, 2)))
        .collect();
    let answer: usize = stored.iter().map(|s| s.ssz.len()).sum();
    assert!(answer > 256 << 10, "past the muxer window: {answer}");
    let mut cfg = with_columns(Scripted::new(ColumnReply::Sidecars(stored)));
    cfg.limits.max_column_answers = 3;
    cfg.limits.max_column_answers_per_ip = 3;
    cfg.limits.column_write_deadline = Duration::from_secs(30);
    let ours = Node::spawn(cfg).await;
    let request = encode_request(&by_range(9, 32, &CUSTODY)).unwrap();
    let mut peers = Vec::new();
    for _ in 0..6 {
        let mut swarm = tcp_swarm(request_response::Behaviour::with_codec(
            Stalling,
            [(
                StreamProtocol::new(Protocol::DataColumnsByRangeV1.id()),
                ProtocolSupport::Outbound,
            )],
            request_response::Config::default().with_request_timeout(Duration::from_secs(60)),
        ));
        swarm.dial(ours.addr.clone()).unwrap();
        tokio::time::timeout(WAIT, async {
            while !matches!(
                swarm.select_next_some().await,
                SwarmEvent::ConnectionEstablished { .. }
            ) {}
        })
        .await
        .expect("connected");
        for _ in 0..2 {
            swarm
                .behaviour_mut()
                .send_request(&ours.peer, request.clone());
        }
        peers.push(swarm);
    }
    let drive = async {
        loop {
            for peer in &mut peers {
                let _ =
                    tokio::time::timeout(Duration::from_millis(5), peer.select_next_some()).await;
            }
        }
    };
    let metrics = ours.metrics.clone();
    let watch = async {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut most = (0, 0);
        while Instant::now() < deadline {
            most.0 = most.0.max(metrics.column_answers_held());
            most.1 = most.1.max(metrics.column_answer_bytes_held());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        most
    };
    let most = tokio::select! {
        () = drive => unreachable!(),
        most = watch => most,
    };
    assert_eq!(most.0, 3, "every place taken, no more");
    assert!(most.1 <= 3 * answer as u64, "{} bytes held", most.1);
    assert!(most.1 > 0);
}

/// Requests past the answer places wait for one, at most one answer per peer at a time; one
/// that waited past the queue wait gets `2: ServerError`, counted.
#[tokio::test]
async fn requests_wait_for_a_place_one_answer_per_peer() {
    let gate = Arc::new(Semaphore::new(0));
    let source = Scripted::gated(ColumnReply::Sidecars(block_columns(9..10)), gate.clone());
    let mut cfg = with_columns(source.clone());
    cfg.limits.max_column_answers = 1;
    let ours = Node::spawn(cfg).await;
    let mut first = requester(&ours).await;
    let mut second = requester(&ours).await;
    let held = first.send(ours.peer, by_range(9, 1, &CUSTODY));
    // The same peer's second request waits for its first: no second lookup.
    let after = first.send(ours.peer, by_root(&[(root_of(9), &CUSTODY)]));
    tokio::time::timeout(WAIT, async {
        while source.asked() == 0 {
            first.run_for(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the first lookup started");
    first.run_for(Duration::from_millis(200)).await;
    assert_eq!(source.asked(), 1);
    // Another peer waits for the one place; the place frees within its wait: served.
    let waiting = second.send(ours.peer, by_range(9, 1, &[47]));
    second.run_for(Duration::from_millis(300)).await;
    gate.add_permits(100);
    assert_eq!(sidecars(first.outcome(held).await.unwrap()).len(), 4);
    assert_eq!(sidecars(first.outcome(after).await.unwrap()).len(), 4);
    assert_eq!(sidecars(second.outcome(waiting).await.unwrap()).len(), 1);
    assert_eq!(ours.metrics.queues().dropped(COLUMN_QUEUE), 0);

    // A place held past the queue wait: the waiting request gets a server error, counted.
    let stuck = Arc::new(Semaphore::new(0));
    let source = Scripted::gated(ColumnReply::Sidecars(block_columns(9..10)), stuck);
    let mut cfg = with_columns(source.clone());
    cfg.limits.max_column_answers = 1;
    cfg.limits.column_queue_wait = Duration::from_millis(500);
    let ours = Node::spawn(cfg).await;
    let mut first = requester(&ours).await;
    let mut second = requester(&ours).await;
    first.send(ours.peer, by_range(9, 1, &CUSTODY));
    tokio::time::timeout(WAIT, async {
        while source.asked() == 0 {
            first.run_for(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the first lookup started");
    let start = Instant::now();
    let busy = second.send(ours.peer, by_range(9, 1, &CUSTODY));
    let (code, _) = refusal(&second.outcome(busy).await.unwrap());
    assert_eq!(code, ResultCode::ServerError);
    assert!(start.elapsed() < COLUMN_LOOKUP_TIMEOUT + Duration::from_secs(2));
    assert_eq!(ours.metrics.queues().dropped(COLUMN_QUEUE), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_lookups_hold_the_stream_cap_and_their_deadline() {
    let gate = Arc::new(Semaphore::new(0));
    let source = Scripted::gated(ColumnReply::Sidecars(block_columns(9..10)), gate);
    let ours = Node::spawn(with_columns(source.clone())).await;
    // Two requests whose lookups never end hold the peer's two streams; its third is not
    // served. The second waits for the first: one answer per peer at a time.
    let mut peer = bytes_peer(Protocol::DataColumnsByRangeV1.id());
    bytes_connect(&mut peer, ours.addr.clone()).await;
    let request = encode_request(&by_range(9, 1, &CUSTODY)).unwrap();
    let start = Instant::now();
    let held: Vec<_> = (0..2)
        .map(|_| {
            peer.behaviour_mut()
                .send_request(&ours.peer, Some(request.clone()))
        })
        .collect();
    let third = peer
        .behaviour_mut()
        .send_request(&ours.peer, Some(request.clone()));
    let mut answers = HashMap::new();
    tokio::time::timeout(WAIT, async {
        while answers.len() < 3 {
            if let SwarmEvent::Behaviour(event) = peer.select_next_some().await {
                use libp2p::request_response::{Event, Message};
                match event {
                    Event::Message {
                        message:
                            Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    } => {
                        answers.insert(request_id, (Ok(response), start.elapsed()));
                    }
                    Event::OutboundFailure {
                        request_id, error, ..
                    } => {
                        answers.insert(request_id, (Err(error.to_string()), start.elapsed()));
                    }
                    _ => {}
                }
            }
        }
    })
    .await
    .expect("every request ended");
    // The third stream was reset or answered with nothing at all.
    if let Ok(wire) = &answers[&third].0 {
        assert!(wire.is_empty(), "served past the cap: {wire:?}");
    }
    assert!(source.asked() <= 2, "no third lookup");
    // The held two end at their lookup deadline with an error chunk, not silence.
    for id in held {
        let (wire, at) = &answers[&id];
        let wire = wire.as_ref().expect("answered");
        assert_eq!(
            result_code(Protocol::DataColumnsByRangeV1, wire),
            ResultCode::ServerError
        );
        assert!(*at >= COLUMN_LOOKUP_TIMEOUT, "{at:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// End to end: cl-chain's column store behind its ReqRespService over a Unix socket, cl-p2p's
// ChainColumns client, the probe swarm, and a requester peer.

mod end_to_end {
    use super::*;
    use crate::rpc::columns::ChainColumns;
    use crate::rpc::limits::MAX_COLUMN_RESPONSE_BYTES;
    use cl_chain::da::custody::{Advertise, Custody, EnrCgc, EnrError};
    use cl_chain::reqresp::{ColumnServer, ColumnStore, ReqRespServer, ServeBudget, ServeClock};
    use cl_chain_columns::{BlockLink, Column, ColumnWriter};
    use consensus_types::primitives::U256;
    use ethswarm_proto::common::Hello;
    use ipc::envelope::DigestTable;
    use ipc::Link;
    use network_config::{ForkSchedule, ScheduledFork};

    /// The slot custody was set at, and stored from: the start of epoch 2.
    const CGC_SET_SLOT: u64 = 64;
    /// Slots of the stored epoch whose blocks carry no blobs: no columns.
    const NO_BLOBS: [u64; 2] = [70, 81];

    struct NoEnr;

    impl EnrCgc for NoEnr {
        fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
            Ok(())
        }
    }

    /// Every slot in range, every digest the fixture Gloas one.
    struct GloasClock;

    impl ServeClock for GloasClock {
        fn serve_range(&self) -> Option<(u64, u64)> {
            Some((0, 10_000))
        }

        fn fork_digest(&self, _: u64) -> Option<[u8; 4]> {
            Some(GLOAS_DIGEST)
        }
    }

    /// The link both ends hold: Gloas from genesis, one digest.
    fn link() -> Link {
        let at = |epoch| ScheduledFork {
            version: [7, 0, 0, 0],
            epoch,
        };
        let hello = Hello {
            api_version: 1,
            build: "cl-p2p/test".into(),
            min_api_version: 1,
            max_api_version: 1,
            ..Default::default()
        };
        let digests = DigestTable::new(vec![(0, ForkName::Gloas, GLOAS_DIGEST)]).unwrap();
        Link::new::<E>(hello, 1, ForkSchedule::new(at(0), at(0)).unwrap(), digests)
    }

    fn block_root(slot: u64) -> [u8; 32] {
        let mut root = [0x77; 32];
        root[..8].copy_from_slice(&slot.to_be_bytes());
        root
    }

    struct Chain {
        writer: Arc<ColumnWriter>,
        socket: std::path::PathBuf,
        custody: Vec<u64>,
        _stop: tokio::sync::oneshot::Sender<()>,
        _dir: tempfile::TempDir,
    }

    /// cl-chain with one epoch of custody columns stored from [`CGC_SET_SLOT`], serving them on
    /// a Unix socket.
    async fn chain() -> Chain {
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(ColumnWriter::open(dir.path().join("columns")).unwrap());
        let custody = Custody::open(
            Arc::clone(&writer),
            NoEnr,
            U256::MAX,
            Advertise::default(),
            CGC_SET_SLOT,
        )
        .unwrap();
        let custody = custody.custody_columns();
        assert_eq!(custody, CUSTODY);
        // One chain: each block links to the one before it (through the slots without blobs).
        let mut parent = BlockLink::Start;
        for slot in CGC_SET_SLOT..CGC_SET_SLOT + 32 {
            if NO_BLOBS.contains(&slot) {
                continue;
            }
            let sidecars: Vec<Vec<u8>> = custody
                .iter()
                .map(|&index| {
                    let mut sidecar = gloas_sidecar::<E>(slot, index);
                    sidecar.beacon_block_root = block_root(slot).into();
                    sidecar.as_ssz_bytes()
                })
                .collect();
            let columns: Vec<_> = custody
                .iter()
                .zip(&sidecars)
                .map(|(&index, ssz)| Column { index, ssz })
                .collect();
            writer
                .write_block_columns(slot, &block_root(slot), parent, &columns)
                .unwrap();
            parent = BlockLink::Parent(block_root(slot));
        }
        let server = ColumnServer::new(
            Arc::clone(&writer) as Arc<dyn ColumnStore>,
            U256::MAX,
            Arc::new(GloasClock),
            ServeBudget::default(),
        );
        let socket = dir.path().join("chain.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let routes = tonic::service::Routes::new(
            ReqRespServer::new(link(), Arc::new(server)).into_service(),
        );
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(ipc::stub::serve_uds(listener, routes, async {
            let _ = stopped.await;
        }));
        Chain {
            writer,
            socket,
            custody,
            _stop: stop,
            _dir: dir,
        }
    }

    /// The probe swarm serving `chain`'s columns through cl-p2p's chain.v1 client.
    async fn probe(chain: &Chain) -> Node {
        let uid = ipc::uds::Ownership::current().uid;
        let channel = ipc::uds::connect_path(&chain.socket, uid).await.unwrap();
        let source = ChainColumns::new(channel, link(), MAX_COLUMN_RESPONSE_BYTES);
        Node::spawn(with_columns(Arc::new(source))).await
    }

    /// What `chain` stores for `slots`, in `(slot, column_index)` order, with the context each
    /// chunk must carry.
    fn stored(chain: &Chain, slots: std::ops::Range<u64>) -> Vec<([u8; 4], Vec<u8>)> {
        let reader = chain.writer.reader();
        slots
            .filter(|slot| !NO_BLOBS.contains(slot))
            .flat_map(|slot| {
                chain.custody.iter().map(move |&index| {
                    let ssz = reader.get(&block_root(slot), index).unwrap().unwrap();
                    (GLOAS_DIGEST, ssz)
                })
            })
            .collect()
    }

    #[tokio::test]
    async fn a_requester_gets_one_epoch_of_custody_columns_byte_equal() {
        let chain = chain().await;
        let ours = probe(&chain).await;
        let mut raw = requester(&ours).await;

        // One epoch of our custody columns: 30 blocks of 4, slots without blobs skipped.
        let id = raw.send(ours.peer, by_range(CGC_SET_SLOT, 32, &chain.custody));
        let got = sidecars(raw.outcome(id).await.unwrap());
        let want = stored(&chain, CGC_SET_SLOT..CGC_SET_SLOT + 32);
        assert_eq!(got.len(), 30 * 4);
        assert!(got == want, "the sidecars are not the stored bytes");

        // By root: stored identifiers answered, unknown ones omitted.
        let id = raw.send(
            ours.peer,
            by_root(&[
                (block_root(CGC_SET_SLOT + 1), &CUSTODY),
                ([0x5a; 32], &CUSTODY),
                (block_root(CGC_SET_SLOT + 31), &[47]),
            ]),
        );
        let got = sidecars(raw.outcome(id).await.unwrap());
        let mut want = stored(&chain, CGC_SET_SLOT + 1..CGC_SET_SLOT + 2);
        want.push(stored(&chain, CGC_SET_SLOT + 31..CGC_SET_SLOT + 32)[1].clone());
        assert!(got == want, "by root: not the stored bytes");
    }

    #[tokio::test]
    async fn below_earliest_available_slot_is_resource_unavailable_end_to_end() {
        let chain = chain().await;
        let ours = probe(&chain).await;
        let mut raw = requester(&ours).await;
        // The epoch before the first stored slot (= cgc_set_slot): unavailable, never empty.
        let id = raw.send(ours.peer, by_range(CGC_SET_SLOT - 32, 32, &chain.custody));
        assert_eq!(
            refused(&raw.outcome(id).await.unwrap()),
            ResultCode::ResourceUnavailable
        );
        // A column we do not custody.
        let id = raw.send(ours.peer, by_range(CGC_SET_SLOT, 1, &[5]));
        assert_eq!(
            refused(&raw.outcome(id).await.unwrap()),
            ResultCode::ResourceUnavailable
        );
        // cl-chain gone: a server error, not an empty answer.
        drop(chain);
        let id = raw.send(ours.peer, by_range(CGC_SET_SLOT, 1, &CUSTODY));
        assert_eq!(
            refused(&raw.outcome(id).await.unwrap()),
            ResultCode::ServerError
        );
    }
}
