//! #146, step 7: the in-repo stand-in for the Kurtosis acceptance criterion ("a Lighthouse node
//! range-syncs with our node as its only server"). The real cl-store `StoreServer` and the real
//! cl-chain `ReqRespServer` serve one env over Unix sockets; our swarm answers BeaconBlocksByRange
//! v2 with the production responder over the production IPC client; the requester is the probe's
//! own `RangeRequester`, which checks every block's context bytes and parent link. It syncs the
//! fixture's five epochs across finality and the Fulu→Gloas switch.

mod common;

use cl_p2p::rpc::blocks::ByRangeResponder;
use cl_p2p::rpc::blocks_ipc::IpcBlocks;
use cl_p2p::rpc::inbound::{SharedStatus, StatusSource};
use cl_p2p::rpc::outbound::RangeRequester;
use common::{control, digest_at, link, seeded, servers, status, swarm, FINALIZED, HEAD, WAIT};
use futures::StreamExt as _;
use libp2p::swarm::SwarmEvent;
use network_config::Epoch;
use prometheus_client::registry::Registry;
use ssz::Encode;
use std::sync::Arc;

/// #146: a range-sync from our node alone, through cl-store (the finalized half) and cl-chain
/// (the rest): every canonical block of the fixture, the fork block never, each block's context
/// its epoch's digest and its parent the block before (both checked by the requester), whole
/// and as stored; a range below the store's first block starts at it, one past the head is
/// empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn range_sync_across_finality_and_the_gloas_fork() {
    let env_dir = tempfile::tempdir().unwrap();
    let (env, chain, _) = seeded(env_dir.path());
    let (sockets, columns_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (store, chain_channel) = servers(&env, sockets.path(), columns_dir.path()).await;

    let ours = Arc::new(SharedStatus::new(Some(status())));
    let mut registry = Registry::default();
    let source = IpcBlocks::new(store, chain_channel, link());
    let responder = ByRangeResponder::new(
        Arc::new(source),
        Arc::clone(&ours) as Arc<dyn StatusSource>,
        16,
        None,
    );
    let node = control(&mut registry, &ours).with_blocks_responder(Arc::new(responder));
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

    let theirs = Arc::new(SharedStatus::new(Some(status())));
    let mut requester = swarm(control(&mut registry, &theirs), false, &mut registry);
    requester.dial(addr).unwrap();
    tokio::time::timeout(WAIT, async {
        while requester
            .behaviour()
            .req_resp
            .status_valid_peers()
            .is_empty()
        {
            requester.select_next_some().await;
        }
    })
    .await
    .expect("our node is Status-valid");

    let digests = |epoch: Epoch| Some(digest_at(epoch));
    let mut sync = RangeRequester::new(&mut requester, &digests);
    let canonical = |start: u64, end: u64| -> Vec<Vec<u8>> {
        chain
            .iter()
            .filter(|b| (start..end).contains(&b.slot()))
            .map(Encode::as_ssz_bytes)
            .collect()
    };
    for (start, count) in [(8, 24), (10, 30), (0, 128), (FINALIZED, 2), (HEAD + 1, 8)] {
        let blocks = tokio::time::timeout(WAIT, sync.blocks_by_range(node_id, start, count))
            .await
            .expect("answered")
            .unwrap_or_else(|e| panic!("[{start}, +{count}): {e}"));
        let got: Vec<Vec<u8>> = blocks.iter().map(Encode::as_ssz_bytes).collect();
        assert_eq!(got, canonical(start, start + count), "[{start}, +{count})");
        assert!(blocks.iter().all(|b| b.slot() != 36), "the fork block");
    }
}

/// Cole B1, Vera N1: cl-p2p refuses a range that starts deeper below the store's finalized slot
/// than it lets cl-store walk before it asks cl-store, and cl-store refuses the same depth
/// itself: one value on both sides.
#[test]
fn finalized_depth_matches_the_store() {
    assert_eq!(
        cl_p2p::rpc::blocks::MAX_FINALIZED_DEPTH,
        cl_store::MAX_FINALIZED_DEPTH
    );
}
