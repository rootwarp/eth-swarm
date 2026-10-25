//! cl-p2p's link to cl-chain's `WatchSubscriptions`, against a fake cl-chain on a Unix socket:
//! each body is checked before cl-p2p takes it, a body that breaks the contract fails the
//! stream (and it is opened again), and the stop ends it. The hello of each end follows the
//! clock (`ipc::Link::network`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cl_p2p::service::watch_subscriptions;
use ethswarm_proto::chain as pb;
use ipc::frame::OutFrame;
use ipc::hello::stream_hello;
use ipc::stub::StubStream;
use ipc::Link;
use pb::gossip_service_server::{GossipService, GossipServiceServer};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tonic::{Request, Response, Status, Streaming};

/// A cl-chain that answers `WatchSubscriptions` with our hello and `bodies[n]` on its n-th
/// stream (the last one again past them), then holds the stream open.
#[derive(Clone)]
struct FakeChain {
    link: Link,
    bodies: Arc<Vec<pb::WatchSubscriptionsResponseBody>>,
    streams: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl GossipService for FakeChain {
    type ValidateStream = StubStream<pb::ValidateResponse>;
    type WatchPublishStream = StubStream<pb::WatchPublishResponse>;
    type WatchSubscriptionsStream = StubStream<pb::WatchSubscriptionsResponse>;

    async fn validate(
        &self,
        request: Request<Streaming<pb::ValidateRequest>>,
    ) -> Result<Response<Self::ValidateStream>, Status> {
        ipc::stub::bidi(&self.link, "validate", request)
    }

    async fn watch_publish(
        &self,
        request: Request<pb::WatchPublishRequest>,
    ) -> Result<Response<Self::WatchPublishStream>, Status> {
        ipc::stub::server_stream(&self.link, "watch_publish", request.get_ref())
    }

    async fn watch_subscriptions(
        &self,
        request: Request<pb::WatchSubscriptionsRequest>,
    ) -> Result<Response<Self::WatchSubscriptionsStream>, Status> {
        self.link
            .accept_hello_field(request.get_ref().hello.as_ref())
            .map_err(|e| e.to_status())?;
        let (_, hello) = stream_hello(&self.link.local()).map_err(|e| e.to_status())?;
        let n = self.streams.fetch_add(1, Ordering::SeqCst);
        let body = self.bodies[n.min(self.bodies.len() - 1)].clone();
        let frames = vec![
            Ok(pb::WatchSubscriptionsResponse::hello(hello)),
            Ok(pb::WatchSubscriptionsResponse::body(body)),
        ];
        let open = futures::stream::pending();
        Ok(Response::new(Box::pin(futures::StreamExt::chain(
            futures::stream::iter(frames),
            open,
        ))))
    }

    async fn get_fork_schedule(
        &self,
        _: Request<pb::GetForkScheduleRequest>,
    ) -> Result<Response<pb::GetForkScheduleResponse>, Status> {
        ipc::stub::unary(&self.link, "get_fork_schedule", &[])
    }
}

fn body(columns: Vec<u64>) -> pb::WatchSubscriptionsResponseBody {
    pb::WatchSubscriptionsResponseBody {
        attnets: Vec::new(),
        syncnets: Vec::new(),
        custody_columns: columns,
        fork_digests: vec![vec![1, 2, 3, 4]],
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_subscriptions_reach_cl_p2p_checked() {
    let network = Arc::new(ipc::testkit::devnet::kurtosis_hello("test"));
    let link = Link::network(Arc::clone(&network), 1).unwrap();
    // The first stream breaks the contract (a column past NUMBER_OF_COLUMNS); the second is
    // good.
    let fake = FakeChain {
        link: link.clone(),
        bodies: Arc::new(vec![body(vec![3, 200]), body(vec![3, 70])]),
        streams: Arc::new(AtomicUsize::new(0)),
    };
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cl-chain.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let routes = tonic::service::Routes::new(GossipServiceServer::new(fake.clone()));
    tokio::spawn(ipc::stub::serve_uds(
        listener,
        routes,
        std::future::pending(),
    ));
    let channel = ipc::uds::connect_path(&socket, ipc::uds::Ownership::current().uid)
        .await
        .unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let (stop, stopped) = watch::channel(false);
    let watching = tokio::spawn(watch_subscriptions(channel, link, tx, stopped));
    let got = tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.columns().collect::<Vec<_>>(), [3, 70]);
    assert_eq!(got.fork_digests(), [[1, 2, 3, 4]]);
    // The refused body was never handed over: the stream was opened again.
    assert_eq!(fake.streams.load(Ordering::SeqCst), 2);
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(10), watching)
        .await
        .unwrap()
        .unwrap();
}
