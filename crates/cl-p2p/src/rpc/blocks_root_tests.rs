//! BeaconBlocksByRoot answers over the `blocks::testing` fixture: the chain-first split with
//! its IPC calls, the retry when finality moved, half failures, deadlines and the store-stream
//! pool.

use crate::rpc::blocks::testing::{self as fixture, block, failed, Act, Fake, Step};
use crate::rpc::blocks::{ByRangeResponder, Half, ServedBlock};
use crate::rpc::blocks_head::MAX_BYHEAD_STORE_STREAMS;
use crate::rpc::codec::{Answer, Deadlines, InboundCodec, ReceivedChunk, RpcCodec, RpcRequest};
use crate::rpc::inbound::SharedStatus;
use crate::rpc::metrics::RpcMetrics;
use crate::rpc::responder::{testing, Responder, StreamedAnswer};
use consensus_types::caps::NetworkCaps;
use consensus_types::{ForkName, Minimal};
use libp2p::request_response::Codec as _;
use p2p_wire::rpc::messages::{BlocksByHeadV1Request, BlocksByRootV2Request, StatusV2};
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
use p2p_wire::testkit::{self as wire, FULU_BPO_DIGEST, FULU_DIGEST, GLOAS_DIGEST};
use prometheus_client::registry::Registry;
use ssz::Encode as _;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

type E = Minimal;
const ROOT: Protocol = Protocol::BlocksByRootV2;
const LOOKUPS: usize = 16;
const ROOMY: usize = 1 << 20;
const UNKNOWN: [u8; 32] = [0xee; 32];

fn by_root(roots: &[[u8; 32]]) -> Request {
    let roots: Vec<_> = roots.iter().map(|r| (*r).into()).collect();
    Request::BlocksByRoot(BlocksByRootV2Request(roots.try_into().unwrap()))
}

fn metrics() -> RpcMetrics {
    RpcMetrics::register(&mut Registry::default())
}

/// The production range responder over `fake` and the ByRoot responder it builds.
fn responders(fake: &Fake, metrics: &RpcMetrics) -> (Arc<dyn Responder<E>>, ByRangeResponder) {
    let status = StatusV2 {
        earliest_available_slot: 0,
        ..wire::status()
    };
    let range = ByRangeResponder::new(
        Arc::new(fake.clone()),
        Arc::new(SharedStatus::new(Some(status))),
        LOOKUPS,
        Some(metrics.clone()),
    );
    (Arc::new(range.root_responder()), range)
}

/// Writes `stream` as the stream's writer does, to a requester taking every write at once.
async fn write(stream: StreamedAnswer) -> Vec<u8> {
    let contexts = testing::serving_table(NetworkCaps::PRESET_BOUND);
    let mut writer = InboundCodec::new(RpcCodec::<E>::new(contexts, Deadlines::default()));
    let mut sent = futures::io::Cursor::new(Vec::new());
    let answer = Answer::streamed(stream, None, None);
    writer
        .write_response(&ROOT, &mut sent, answer)
        .await
        .unwrap();
    sent.into_inner()
}

/// `responder`'s answer to `request` from a fresh peer at `ip`, as the requester reads it.
async fn serve_from(
    responder: &Arc<dyn Responder<E>>,
    ip: Option<IpAddr>,
    request: Request,
) -> Vec<ReceivedChunk<E>> {
    let (stream, _, _) = testing::start_from(responder, ip, request.clone(), ROOMY);
    let wire = write(stream).await;
    let contexts = Arc::new(wire::context_table());
    let mut codec = RpcCodec::<E>::new(contexts, Deadlines::default());
    let mut sent = futures::io::sink();
    let valid = RpcRequest::Valid(request);
    codec.write_request(&ROOT, &mut sent, valid).await.unwrap();
    codec.read_response(&ROOT, &mut &wire[..]).await.unwrap()
}

async fn serve(responder: &Arc<dyn Responder<E>>, request: Request) -> Vec<ReceivedChunk<E>> {
    serve_from(responder, None, request).await
}

/// The roots of the blocks of `chunks`, which must all be blocks.
fn roots_of(chunks: &[ReceivedChunk<E>]) -> Vec<[u8; 32]> {
    chunks
        .iter()
        .map(|c| match &c.chunk {
            ResponseChunk::Success(Response::Block(b)) => b.message_root().0,
            other => panic!("not a block: {other:?}"),
        })
        .collect()
}

fn only_error(chunks: &[ReceivedChunk<E>]) -> Option<ResultCode> {
    match chunks {
        [ReceivedChunk {
            context: None,
            chunk: ResponseChunk::Error { code, .. },
        }] => Some(*code),
        _ => None,
    }
}

/// The fork block at 36 (on 35, off the head's chain) and an orphan at 12 (on 11, below
/// the finalized slot 20), both held.
fn forks(fake: &Fake) -> (ServedBlock, ServedBlock) {
    let above = block(36, fixture::at(35).root, 9);
    let below = block(12, fixture::at(11).root, 7);
    fake.add(above.clone());
    fake.add(below.clone());
    (above, below)
}

fn at(slot: u64) -> [u8; 32] {
    fixture::at(slot).root
}

async fn closed(fake: &Fake) {
    for _ in 0..64 {
        if fake.open() == 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("{} lookups still open", fake.open());
}

/// Chain first, then the store for the misses, one call each, in request order: an
/// unfinalized canonical root and the fork block above finality from cl-chain, finalized
/// roots (the finalized slot's own included) from cl-store; an unknown root and the orphan
/// below finality get no chunk, a duplicate is served once. Each chunk carries the digest
/// of its block's epoch and is the block as stored. A request cl-chain answers whole never
/// reaches cl-store.
#[tokio::test(start_paused = true)]
async fn byroot_chain_first_then_store() {
    let fake = Fake::new();
    let (fork, orphan) = forks(&fake);
    let (responder, range) = responders(&fake, &metrics());
    let asked = [
        at(30),
        at(10),
        fork.root,
        UNKNOWN,
        at(30),
        orphan.root,
        at(20),
    ];
    let chunks = serve(&responder, by_root(&asked)).await;
    assert_eq!(roots_of(&chunks), [at(30), at(10), fork.root, at(20)]);
    let unique = vec![at(30), at(10), fork.root, UNKNOWN, orphan.root, at(20)];
    let misses = vec![at(10), UNKNOWN, orphan.root, at(20)];
    assert_eq!(
        fake.root_calls(),
        [(Half::Chain, unique), (Half::Store, misses)],
        "one call per half, the store asked for the misses only"
    );
    for (chunk, slot) in chunks.iter().zip([30, 10, 36, 20]) {
        let (digest, fork_name) = match slot / 8 {
            0..=1 => (FULU_DIGEST, ForkName::Fulu),
            2..=3 => (FULU_BPO_DIGEST, ForkName::Fulu),
            _ => (GLOAS_DIGEST, ForkName::Gloas),
        };
        assert_eq!(chunk.context, Some(digest), "slot {slot}");
        let ResponseChunk::Success(Response::Block(b)) = &chunk.chunk else {
            panic!("a block");
        };
        assert_eq!((b.slot(), b.fork_name()), (slot, fork_name));
        let stored = if slot == 36 {
            fork.clone()
        } else {
            fixture::at(slot)
        };
        assert_eq!(b.as_ssz_bytes(), stored.ssz, "slot {slot}");
    }

    let chunks = serve(&responder, by_root(&[at(40), at(21), at(40)])).await;
    assert_eq!(roots_of(&chunks), [at(40), at(21)]);
    assert_eq!(
        fake.root_calls(),
        [(Half::Chain, vec![at(40), at(21)])],
        "nothing left for the store"
    );
    let chunks = serve(&responder, by_root(&[UNKNOWN])).await;
    assert!(chunks.is_empty(), "an unknown root: no chunk, {chunks:?}");
    assert_eq!(fake.root_calls().len(), 2);
    let chunks = serve(&responder, by_root(&[])).await;
    assert!(chunks.is_empty());
    assert_eq!(fake.root_calls(), [], "no root: nothing asked");
    closed(&fake).await;
    assert_eq!(range.free_lookups(), LOOKUPS);
    assert_eq!(range.held_store_streams(), 0);
}

/// Default 3: a root cl-chain left to the store as finalized while the store's own
/// finalized slot was behind (here 12, cl-chain's 20) comes back as held unfinalized, and
/// the store is asked once more for those roots only, which keep their place in the order.
/// A store still behind then is not asked a third time. With no cl-chain answer there is no
/// finality to have moved: no second call.
#[tokio::test(start_paused = true)]
async fn byroot_retry_once_when_finality_moved() {
    let fake = Fake::new();
    let (responder, _) = responders(&fake, &metrics());
    let asked = [at(18), at(30), at(10), at(14)];
    fake.lag_store([12]);
    let chunks = serve(&responder, by_root(&asked)).await;
    assert_eq!(roots_of(&chunks), [at(18), at(30), at(10), at(14)]);
    assert_eq!(
        fake.root_calls(),
        [
            (Half::Chain, asked.to_vec()),
            (Half::Store, vec![at(18), at(10), at(14)]),
            (Half::Store, vec![at(18), at(14)]),
        ]
    );
    fake.lag_store([12, 12]);
    let chunks = serve(&responder, by_root(&asked)).await;
    assert_eq!(roots_of(&chunks), [at(30), at(10)], "once only");
    assert_eq!(fake.root_calls().len(), 3);

    fake.script(
        Step::Open(Half::Chain),
        Act::Fail(failed(ResultCode::ServerError, "status")),
    );
    fake.lag_store([12]);
    let chunks = serve(&responder, by_root(&asked)).await;
    assert_eq!(roots_of(&chunks), [at(10)]);
    assert_eq!(fake.root_calls().len(), 2, "the chain failed: no retry");
}

/// A half that fails adds nothing and is counted; the other half's blocks still go out.
/// With none found the first failure's code is the answer: cl-chain's `2`, cl-store's `3`
/// (`UNAVAILABLE`). A half that answers a block of a root it was not asked for breaks the
/// contract: none of its blocks is served.
#[tokio::test(start_paused = true)]
async fn byroot_half_failures() {
    let metrics = metrics();
    let fake = Fake::new();
    let (responder, range) = responders(&fake, &metrics);
    let asked = [at(30), at(10)];
    let chain_down = failed(ResultCode::ServerError, "status");
    fake.script(Step::Open(Half::Chain), Act::Fail(chain_down.clone()));
    let chunks = serve(&responder, by_root(&asked)).await;
    assert_eq!(roots_of(&chunks), [at(10)], "the store's half");
    assert_eq!(fake.root_calls()[1], (Half::Store, asked.to_vec()));
    assert_eq!(metrics.block_lookup_failures("chain", "status"), 1);
    let chunks = serve(&responder, by_root(&[at(30)])).await;
    assert_eq!(only_error(&chunks), Some(ResultCode::ServerError));

    let fake = Fake::new();
    let (responder, _) = responders(&fake, &metrics);
    let store_down = failed(ResultCode::ResourceUnavailable, "status");
    fake.script(Step::Open(Half::Store), Act::Fail(store_down));
    let chunks = serve(&responder, by_root(&asked)).await;
    assert_eq!(roots_of(&chunks), [at(30)], "the chain's half");
    let chunks = serve(&responder, by_root(&[at(10)])).await;
    assert_eq!(only_error(&chunks), Some(ResultCode::ResourceUnavailable));
    assert_eq!(metrics.block_lookup_failures("store", "status"), 2);
    fake.script(Step::Open(Half::Chain), Act::Fail(chain_down));
    let chunks = serve(&responder, by_root(&asked)).await;
    assert_eq!(
        only_error(&chunks),
        Some(ResultCode::ServerError),
        "cl-chain's first"
    );

    let fake = Fake::new();
    let (responder, _) = responders(&fake, &metrics);
    fake.replace(30, block(30, [9; 32], 5));
    let chunks = serve(&responder, by_root(&[at(30), at(31), at(10)])).await;
    assert_eq!(roots_of(&chunks), [at(10)], "nothing of the chain's half");
    assert_eq!(metrics.block_lookup_failures("chain", "contract"), 1);
    closed(&fake).await;
    assert_eq!(range.free_lookups(), LOOKUPS);
}

/// A half that stalls mid-request: nothing has gone out, so the stream's writer ends the
/// answer with `2: ServerError` at its first-byte deadline, and the answer's lookup, its
/// lookup slot and its store-stream permit all go with it.
#[tokio::test(start_paused = true)]
async fn byroot_deadline_mid_request() {
    for half in [Half::Chain, Half::Store] {
        let fake = Fake::new();
        let (responder, range) = responders(&fake, &metrics());
        fake.script(Step::Open(half), Act::Stall);
        let start = Instant::now();
        let chunks = serve(&responder, by_root(&[at(30), at(10)])).await;
        assert_eq!(
            only_error(&chunks),
            Some(ResultCode::ServerError),
            "{half:?}"
        );
        let took = Instant::now() - start;
        assert!(took < Duration::from_secs(5), "{half:?}: {took:?}");
        closed(&fake).await;
        assert_eq!(range.free_lookups(), LOOKUPS, "{half:?}");
        assert_eq!(range.held_store_streams(), 0, "{half:?}");
    }
}

/// The cl-store call takes a permit of the BlocksByHead pool: with all of it held by
/// stalled ByHead walks, a by-root answer that needs cl-store is `3` (counted as
/// `{store, streams}`), or its cl-chain blocks alone; one cl-chain serves whole needs none.
#[tokio::test(start_paused = true)]
async fn byroot_store_stream_pool() {
    let metrics = metrics();
    let fake = Fake::new();
    let (responder, range) = responders(&fake, &metrics);
    let head: Arc<dyn Responder<E>> = Arc::new(range.head_responder());
    let walk = Request::BlocksByHead(BlocksByHeadV1Request {
        beacon_root: at(40).into(),
        count: 128,
    });
    let stalled: Vec<_> = (0..MAX_BYHEAD_STORE_STREAMS)
        .map(|i| {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, u8::try_from(i / 2).unwrap()));
            testing::start_from(&head, Some(ip), walk.clone(), ROOMY)
        })
        .collect();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(range.held_store_streams(), MAX_BYHEAD_STORE_STREAMS);
    let ip = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)));
    let chunks = serve_from(&responder, ip, by_root(&[at(10)])).await;
    assert_eq!(only_error(&chunks), Some(ResultCode::ResourceUnavailable));
    assert_eq!(metrics.block_lookup_failures("store", "streams"), 1);
    let chunks = serve_from(&responder, ip, by_root(&[at(30), at(10)])).await;
    assert_eq!(roots_of(&chunks), [at(30)]);
    let chunks = serve_from(&responder, ip, by_root(&[at(30)])).await;
    assert_eq!(roots_of(&chunks), [at(30)]);
    assert_eq!(metrics.block_lookup_failures("store", "streams"), 2);
    drop(stalled);
    closed(&fake).await;
    let chunks = serve_from(&responder, ip, by_root(&[at(30), at(10)])).await;
    assert_eq!(roots_of(&chunks), [at(30), at(10)]);
    assert_eq!(range.held_store_streams(), 0, "given back after the call");
}

/// One token per root named, duplicates included (a duplicate's goes back at the end).
#[test]
fn byroot_cost_is_the_roots_named() {
    let fake = Fake::new();
    let (responder, _) = responders(&fake, &metrics());
    assert_eq!(responder.cost(&by_root(&[at(30), at(30), UNKNOWN])), 3);
    assert_eq!(responder.cost(&by_root(&[])), 0);
}
