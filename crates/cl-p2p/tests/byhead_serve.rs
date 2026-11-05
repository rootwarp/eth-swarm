//! #230: the in-repo stand-in for the Kurtosis acceptance criterion ("a BlocksByHead request to
//! us succeeds, from a reference CL if one sends it, otherwise from a test peer"). Kurtosis runs
//! no cl-store and the probe holds only its anchor block, so, as for #146, the real cl-store
//! `StoreServer` serves the fixture env over a Unix socket; our swarm answers BeaconBlocksByHead
//! v1 with the production `ByHeadResponder` over the production `IpcBlocks`; the requester is a
//! test peer on the [3.7] requester path (`outbound_behaviour` over the production codec, which
//! reads each chunk by its context bytes within its fork's bounds).

mod common;

use cl_p2p::rpc::blocks::ByRangeResponder;
use cl_p2p::rpc::blocks_ipc::IpcBlocks;
use cl_p2p::rpc::codec::{Deadlines, ReceivedChunk, RpcCodec, RpcRequest};
use cl_p2p::rpc::inbound::{SharedStatus, StatusSource};
use common::{contexts, control, digest_at, link, seeded, servers, status, swarm, E, WAIT};
use consensus_types::forked;
use futures::StreamExt as _;
use libp2p::request_response::{self, OutboundFailure};
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use p2p_wire::rpc::messages::BlocksByHeadV1Request;
use p2p_wire::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
use prometheus_client::registry::Registry;
use ssz::Encode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

type Requester = Swarm<request_response::Behaviour<RpcCodec<E>>>;

/// A test peer that requests BeaconBlocksByHead over TCP, Noise and yamux, connected to `addr`.
async fn requester(addr: Multiaddr) -> Requester {
    let codec = RpcCodec::<E>::new(contexts(), Deadlines::default());
    let behaviour = cl_p2p::rpc::outbound_behaviour(Protocol::BlocksByHeadV1, codec);
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|_| behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(WAIT))
        .build();
    swarm.dial(addr).unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            if let SwarmEvent::ConnectionEstablished { .. } = swarm.select_next_some().await {
                return;
            }
        }
    })
    .await
    .expect("connected");
    swarm
}

/// The chunks of our node's answer to a BeaconBlocksByHead request for `count` blocks down
/// from `root`.
async fn by_head(
    swarm: &mut Requester,
    node: PeerId,
    root: [u8; 32],
    count: u64,
) -> Result<Vec<ReceivedChunk<E>>, OutboundFailure> {
    let request = Request::BlocksByHead(BlocksByHeadV1Request {
        beacon_root: root.into(),
        count,
    });
    let id = swarm
        .behaviour_mut()
        .send_request(&node, RpcRequest::Valid(request));
    tokio::time::timeout(WAIT, async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                }) if request_id == id => return Ok(response),
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure {
                    request_id,
                    error,
                    ..
                }) if request_id == id => return Err(error),
                _ => {}
            }
        }
    })
    .await
    .expect("answered")
}

/// The blocks of `chunks`, each checked to carry its own epoch's digest.
fn blocks(chunks: &[ReceivedChunk<E>]) -> Vec<forked::SignedBeaconBlock<E>> {
    chunks
        .iter()
        .map(|c| match &c.chunk {
            ResponseChunk::Success(Response::Block(b)) => {
                assert_eq!(
                    c.context,
                    Some(digest_at(b.slot() / 8)),
                    "slot {}",
                    b.slot()
                );
                (**b).clone()
            }
            other => panic!("not a block: {other:?}"),
        })
        .collect()
}

/// #230: BeaconBlocksByHead v1 from our node, through cl-store's parent walk
/// (`GetBlocksByHead`): the head's ancestry newest first, inclusive of the head, across the
/// store's finalized slot (20) and the Fulu→Gloas switch, each block whole, as stored and with
/// its own epoch's digest; the fork block at 36 gets its own ancestry, never the canonical
/// block's; a root we do not hold is a success of zero chunks; a held root below the serve
/// window's start is `3: ResourceUnavailable`, and a walk reaching it stops cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn byhead_across_finality_and_the_gloas_fork() {
    let env_dir = tempfile::tempdir().unwrap();
    let (env, chain, fork) = seeded(env_dir.path());
    let (sockets, columns_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (store, chain_channel) = servers(&env, sockets.path(), columns_dir.path()).await;

    let ours = Arc::new(SharedStatus::new(Some(status())));
    let window = Arc::new(AtomicU64::new(0));
    let start = Arc::clone(&window);
    let range = ByRangeResponder::new(
        Arc::new(IpcBlocks::new(store, chain_channel, link())),
        Arc::clone(&ours) as Arc<dyn StatusSource>,
        16,
        None,
    )
    .with_window(Arc::new(move || Some(start.load(Ordering::SeqCst))));
    let head = range.head_responder();
    let mut registry = Registry::default();
    let node = control(&mut registry, &ours)
        .with_blocks_responder(Arc::new(range))
        .with_head_responder(Arc::new(head));
    let mut node = swarm(node, true, &mut registry);
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = node.select_next_some().await {
            break address;
        }
    };
    let node_id = *node.local_peer_id();
    tokio::spawn(async move {
        loop {
            node.select_next_some().await;
        }
    });
    let mut peer = requester(addr).await;

    let root = |slot: u64| {
        chain
            .iter()
            .find(|b| b.slot() == slot)
            .unwrap()
            .message_root()
            .0
    };
    let down = |from: u64, n: usize| -> Vec<Vec<u8>> {
        chain
            .iter()
            .rev()
            .filter(|b| b.slot() <= from)
            .take(n)
            .map(Encode::as_ssz_bytes)
            .collect()
    };
    let ssz = |blocks: Vec<forked::SignedBeaconBlock<E>>| -> Vec<Vec<u8>> {
        blocks.iter().map(Encode::as_ssz_bytes).collect()
    };
    let answer = by_head(&mut peer, node_id, root(40), 128).await.unwrap();
    assert_eq!(
        ssz(blocks(&answer)),
        down(40, 36),
        "slots 40 to 1, newest first"
    );
    let answer = by_head(&mut peer, node_id, root(24), u64::MAX)
        .await
        .unwrap();
    assert_eq!(ssz(blocks(&answer)), down(24, 128), "across F0, clamped");

    let fork_root = fork.message_root().0;
    let answer = by_head(&mut peer, node_id, fork_root, 4).await.unwrap();
    let mut want = vec![fork.as_ssz_bytes()];
    want.extend(down(35, 3));
    assert_eq!(ssz(blocks(&answer)), want, "the fork block's own ancestry");

    let answer = by_head(&mut peer, node_id, [0xee; 32], 8).await.unwrap();
    assert!(answer.is_empty(), "an unknown root: {answer:?}");

    window.store(30, Ordering::SeqCst);
    let answer = by_head(&mut peer, node_id, root(29), 8).await.unwrap();
    match &answer[..] {
        [ReceivedChunk {
            chunk: ResponseChunk::Error { code, .. },
            context: None,
        }] => assert_eq!(*code, ResultCode::ResourceUnavailable),
        other => panic!("{other:?}"),
    }
    let answer = by_head(&mut peer, node_id, root(32), 8).await.unwrap();
    assert_eq!(ssz(blocks(&answer)), down(32, 3), "stops below the window");
}
