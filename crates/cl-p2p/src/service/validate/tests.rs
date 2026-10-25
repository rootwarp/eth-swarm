#![allow(clippy::unwrap_used, clippy::expect_used)]

//! The column hand-off: the messages it builds, its batches, and its stream against cl-chain's
//! own `GossipService` and against cl-chains that break the contract.

use super::*;
use cl_chain::probe::service::{
    chain_link, ColumnHandOff, GossipColumnBytes, GossipServer, HandOff, ProbeNetwork,
    Subscriptions,
};
use consensus_types::Minimal;
use ethswarm_proto::common::Hello;
use ipc::fence::FencedResult;
use ipc::hello::stream_hello;
use ipc::stub::StubStream;
use ipc::testkit::devnet::{kurtosis_config, DEVNET_GENESIS};
use libp2p::PeerId;
use pb::gossip_service_server::{GossipService, GossipServiceServer};
use ssz::Encode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status, Streaming};

const WAIT: Duration = Duration::from_secs(30);

fn net() -> ProbeNetwork {
    ProbeNetwork::new("test", kurtosis_config(), DEVNET_GENESIS).unwrap()
}

fn link(net: &ProbeNetwork) -> Link {
    chain_link::<Minimal>(net, ipc::hello::system_ms()).unwrap()
}

/// A captured Gloas column sidecar of `slot` and `index` on its subnet's topic under `digest`.
fn captured(digest: [u8; 4], slot: u64, index: u64) -> Captured {
    let subnet_id = consensus_types::das::compute_subnet_for_data_column_sidecar(index);
    let topic = GossipTopic::new(digest, GossipKind::DataColumnSidecar { subnet_id });
    Captured {
        recv_mono: std::time::Instant::now(),
        recv_wall: SystemTime::now(),
        topic: topic.to_string(),
        message_id: vec![u8::try_from(index).unwrap(); 20],
        source: PeerId::random(),
        data: p2p_wire::testkit::gloas_sidecar::<Minimal>(slot, index).as_ssz_bytes(),
    }
}

fn message(ssz_len: usize) -> pb::GossipMessage {
    pb::GossipMessage {
        payload: Some(Envelope {
            ssz: vec![0; ssz_len],
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A column message carries its topic's digest, the sidecar's own slot and subnet, its message
/// ID and source; anything else is no column message.
#[test]
fn a_column_message_names_its_digest_slot_and_subnet() {
    let one = captured([1, 2, 3, 4], 24, 3);
    let built = column_message::<Minimal>(&one).unwrap();
    let payload = built.payload.as_ref().unwrap();
    assert_eq!(payload.fork_digest, [1, 2, 3, 4]);
    assert_eq!(payload.slot, 24);
    assert_eq!(payload.ssz, one.data);
    assert_eq!(payload.payload_type, PayloadType::DataColumnSidecar as i32);
    assert_eq!(payload.seq, 0, "set when it is sent");
    assert_eq!(built.topic, pb::Topic::DataColumnSidecar as i32);
    assert_eq!(built.subnet_id, 3);
    assert_eq!(built.message_id, one.message_id);
    assert_eq!(built.propagation_source.unwrap().id, one.source.to_string());
    assert!(built.received_unix_ms > 0);
    let block = Captured {
        topic: GossipTopic::new([1, 2, 3, 4], GossipKind::BeaconBlock).to_string(),
        ..one.clone()
    };
    assert!(column_message::<Minimal>(&block).is_none());
    let garbage = Captured {
        topic: "/eth2/zz/x/ssz_snappy".into(),
        ..one.clone()
    };
    assert!(column_message::<Minimal>(&garbage).is_none());
    let short = Captured {
        data: vec![1, 2, 3],
        ..one
    };
    assert!(column_message::<Minimal>(&short).is_none());
}

/// A batch is due at 256 messages, at the SSZ cap, or at its window; a message that does not
/// fit sends the batch before it, and a large one goes alone.
#[test]
fn a_batch_is_due_by_count_bytes_or_window() {
    let now = Instant::now();
    let mut batcher = Batcher::default();
    assert_eq!(batcher.due_at(), None);
    for _ in 0..MAX_BATCH_MESSAGES - 1 {
        assert!(batcher.push(message(1), now).is_none());
    }
    assert_eq!(batcher.due_at(), Some(now + BATCH_WINDOW));
    assert_eq!(
        batcher.push(message(1), now).map(|b| b.len()),
        Some(MAX_BATCH_MESSAGES)
    );
    assert!(batcher.is_empty());
    // Bytes: the second of two 1.5 MiB messages sends the first; then a 3 MiB one alone.
    let big = MAX_BATCH_SSZ_BYTES * 3 / 4;
    assert!(batcher.push(message(big), now).is_none());
    assert_eq!(batcher.push(message(big), now).map(|b| b.len()), Some(1));
    assert_eq!(batcher.len(), 1);
    assert_eq!(batcher.take().map(|b| b.len()), Some(1));
    assert_eq!(
        batcher
            .push(message(MAX_BATCH_SSZ_BYTES + 1), now)
            .map(|b| b.len()),
        Some(1)
    );
    assert!(batcher.take().is_none());
}

/// Records every column it takes.
#[derive(Default)]
struct Recorded(Mutex<Vec<(u64, u64)>>);

impl ColumnHandOff for Recorded {
    fn hand_over(&self, column: GossipColumnBytes<'_>) -> HandOff {
        self.0.lock().unwrap().push((column.slot, column.subnet_id));
        HandOff::Stored
    }
}

/// Serves `routes` on a new socket; the channel to it.
async fn serve(routes: tonic::service::Routes) -> (Channel, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("chain.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::spawn(ipc::stub::serve_uds(
        listener,
        routes,
        std::future::pending(),
    ));
    let channel = ipc::uds::connect_path(&socket, ipc::uds::Ownership::current().uid)
        .await
        .unwrap();
    (channel, dir)
}

/// Waits until `done` holds.
async fn eventually(mut done: impl FnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("in time");
}

/// Against cl-chain's own `Validate`: each column sidecar reaches its hand-off with its slot and
/// subnet, and the verdicts settle through their fences.
#[tokio::test(flavor = "multi_thread")]
async fn the_columns_reach_cl_chain_and_are_answered() {
    let net = net();
    let link = link(&net);
    let recorded = Arc::new(Recorded::default());
    let (_stop_chain, chain_stopped) = watch::channel(false);
    let server = GossipServer::new(
        link.clone(),
        Subscriptions::new(&net, vec![3]),
        Arc::new(ipc::hello::system_ms),
        chain_stopped,
    )
    .validating(Arc::clone(&recorded) as Arc<dyn ColumnHandOff>);
    let (channel, _dir) = serve(tonic::service::Routes::new(server.into_service())).await;
    let mut registry = Registry::default();
    let metrics = HandOffMetrics::register(&mut registry);
    let (tx, rx) = mpsc::channel(8);
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(hand_off_columns(
        channel,
        link,
        rx,
        metrics.clone(),
        HandOffLimits::default(),
        stopped,
    ));
    let digest = net.digest_at(3).unwrap();
    for index in [3, 67, 3] {
        let built = column_message::<Minimal>(&captured(digest, 24, index)).unwrap();
        tx.send(built).await.unwrap();
    }
    eventually(|| metrics.answered() == 3).await;
    assert_eq!(*recorded.0.lock().unwrap(), [(24, 3), (24, 67), (24, 3)]);
    assert_eq!((metrics.ignored(), metrics.unsent()), (0, 0));
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
    assert!(
        text.contains("p2p_column_handoff_total{result=\"answered\"} 3"),
        "{text}"
    );
    stop.send_replace(true);
    tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
}

/// How a fake cl-chain answers the batches of a `Validate` stream.
#[derive(Clone, Copy)]
enum Answer {
    /// Never.
    Silent,
    /// With the fences of another item.
    Substituted,
    /// Correctly, after this long.
    Late(Duration),
}

/// A cl-chain whose `Validate` answers as `answer`, counting its streams.
#[derive(Clone)]
struct FakeChain {
    link: Link,
    answer: Answer,
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
        self.streams.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(8);
        let (link, answer) = (self.link.clone(), self.answer);
        tokio::spawn(async move {
            let Ok(mut guarded) = link.open(Inbound::new(request.into_inner())).await else {
                return;
            };
            let (_, hello): (_, Hello) = stream_hello(&link.local()).unwrap();
            if tx
                .send(Ok(pb::ValidateResponse::hello(hello)))
                .await
                .is_err()
            {
                return;
            }
            while let Ok(Some(accepted)) = guarded.body().await {
                let batch = accepted.body;
                let mut verdicts = pb::VerdictBatch {
                    verdicts: vec![pb::GossipVerdict::default(); batch.messages.len()],
                    request_id: batch.request_id,
                };
                let mut fences = batch.result_fences();
                match answer {
                    Answer::Silent => continue,
                    Answer::Substituted => fences[0].item_hash = [0x5a; 32],
                    Answer::Late(after) => tokio::time::sleep(after).await,
                }
                verdicts.stamp(&fences);
                if tx
                    .send(Ok(pb::ValidateResponse::body(verdicts)))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });
        Ok(Response::new(Box::pin(Queued(rx))))
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
        ipc::stub::server_stream(&self.link, "watch_subscriptions", request.get_ref())
    }

    async fn get_fork_schedule(
        &self,
        _: Request<pb::GetForkScheduleRequest>,
    ) -> Result<Response<pb::GetForkScheduleResponse>, Status> {
        ipc::stub::unary(&self.link, "get_fork_schedule", &[])
    }
}

/// The frames of a queue, as a response stream.
struct Queued(mpsc::Receiver<Result<pb::ValidateResponse, Status>>);

impl futures::Stream for Queued {
    type Item = Result<pb::ValidateResponse, Status>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

/// Starts the hand-off against `fake`; its queue, its metrics and its stop.
async fn against(
    fake: FakeChain,
    limits: HandOffLimits,
) -> (
    mpsc::Sender<pb::GossipMessage>,
    HandOffMetrics,
    watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
    tempfile::TempDir,
) {
    let link = fake.link.clone();
    let (channel, dir) = serve(tonic::service::Routes::new(GossipServiceServer::new(fake))).await;
    let metrics = HandOffMetrics::default();
    let (tx, rx) = mpsc::channel(8);
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(hand_off_columns(
        channel,
        link,
        rx,
        metrics.clone(),
        limits,
        stopped,
    ));
    (tx, metrics, stop, task, dir)
}

/// A cl-chain that holds the stream but never answers: each batch fails as IGNORE at its
/// deadline, and once every place of the stream is held by such a batch, the stream is opened
/// again, so the columns after it are sent. The stop ends the hand-off.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_cl_chain_makes_every_batch_ignore_and_the_stream_open_again() {
    let net = net();
    let fake = FakeChain {
        link: link(&net),
        answer: Answer::Silent,
        streams: Arc::default(),
    };
    let limits = HandOffLimits {
        deadline: Duration::from_millis(100),
        max_outstanding: 1,
        first_backoff: Duration::from_millis(10),
    };
    let (tx, metrics, stop, task, _dir) = against(fake.clone(), limits).await;
    let digest = net.digest_at(3).unwrap();
    let column = || column_message::<Minimal>(&captured(digest, 24, 3)).unwrap();
    tx.send(column()).await.unwrap();
    eventually(|| metrics.ignored() == 1).await;
    // The expired batch held the stream's only place: the stream is opened again.
    eventually(|| fake.streams.load(Ordering::SeqCst) >= 2).await;
    tx.send(column()).await.unwrap();
    eventually(|| metrics.ignored() == 2).await;
    assert_eq!((metrics.answered(), metrics.unsent()), (0, 0));
    stop.send_replace(true);
    tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
}

/// Verdicts after the batch's deadline are dropped and counted as late, never answered.
#[tokio::test(flavor = "multi_thread")]
async fn late_verdicts_are_dropped_and_counted() {
    let net = net();
    let fake = FakeChain {
        link: link(&net),
        answer: Answer::Late(Duration::from_millis(300)),
        streams: Arc::default(),
    };
    let limits = HandOffLimits {
        deadline: Duration::from_millis(50),
        ..HandOffLimits::default()
    };
    let (tx, metrics, stop, task, _dir) = against(fake.clone(), limits).await;
    let digest = net.digest_at(3).unwrap();
    tx.send(column_message::<Minimal>(&captured(digest, 24, 3)).unwrap())
        .await
        .unwrap();
    eventually(|| metrics.late() == 1).await;
    assert_eq!((metrics.ignored(), metrics.answered()), (1, 0));
    assert_eq!(
        fake.streams.load(Ordering::SeqCst),
        1,
        "a late verdict keeps the stream"
    );
    stop.send_replace(true);
    tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
}

/// Verdicts with another item's fence fail the stream: its batch fails as IGNORE, never
/// answered, and the stream is opened again.
#[tokio::test(flavor = "multi_thread")]
async fn substituted_verdicts_fail_the_stream_and_it_opens_again() {
    let net = net();
    let fake = FakeChain {
        link: link(&net),
        answer: Answer::Substituted,
        streams: Arc::default(),
    };
    let limits = HandOffLimits {
        first_backoff: Duration::from_millis(10),
        ..HandOffLimits::default()
    };
    let (tx, metrics, stop, task, _dir) = against(fake.clone(), limits).await;
    let digest = net.digest_at(3).unwrap();
    tx.send(column_message::<Minimal>(&captured(digest, 24, 3)).unwrap())
        .await
        .unwrap();
    eventually(|| metrics.ignored() == 1).await;
    eventually(|| fake.streams.load(Ordering::SeqCst) >= 2).await;
    assert_eq!(metrics.answered(), 0);
    stop.send_replace(true);
    tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
}

/// A stalled cl-chain fills the column queue, and the bridge then drops and counts what does
/// not fit: it never waits, so the tap behind it never fills.
#[test]
fn a_full_queue_makes_the_bridge_drop_never_wait() {
    let metrics = HandOffMetrics::default();
    let (tap, reader) = crate::gossip::capture_tap_counted(8, metrics.tap_counter());
    let (tx, _stalled) = mpsc::channel(1);
    let bridge = bridge_tap::<Minimal>(reader, tx, metrics.clone()).unwrap();
    for index in [3, 67, 3, 67, 3] {
        assert!(tap.offer(captured([1, 2, 3, 4], 24, index)));
    }
    drop(tap);
    let by = std::time::Instant::now() + WAIT;
    while !bridge.is_finished() {
        assert!(
            std::time::Instant::now() < by,
            "the bridge waits on a full queue"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    bridge.join().unwrap();
    assert_eq!(metrics.queue_dropped(), 4);
    assert_eq!(metrics.tap_dropped(), 0);
}

/// Only the column topics go to the tap ([`is_column_topic`]).
#[test]
fn only_column_topics_are_tapped() {
    let column = GossipTopic::new([1; 4], GossipKind::DataColumnSidecar { subnet_id: 3 });
    assert!(is_column_topic(&column.to_string()));
    let block = GossipTopic::new([1; 4], GossipKind::BeaconBlock);
    assert!(!is_column_topic(&block.to_string()));
    assert!(!is_column_topic("/eth2/zz/x/ssz_snappy"));
}

/// The bridge passes on only the column sidecars of the tap, and ends with the tap.
#[test]
fn the_bridge_keeps_the_columns_and_ends_with_the_tap() {
    let (tap, reader) = crate::gossip::capture_tap(8);
    let (tx, mut rx) = mpsc::channel(8);
    let bridge = bridge_tap::<Minimal>(reader, tx, HandOffMetrics::default()).unwrap();
    let column = captured([1, 2, 3, 4], 24, 3);
    let block = Captured {
        topic: GossipTopic::new([1, 2, 3, 4], GossipKind::BeaconBlock).to_string(),
        ..column.clone()
    };
    assert!(tap.offer(block));
    assert!(tap.offer(column.clone()));
    drop(tap);
    bridge.join().unwrap();
    let got = rx.blocking_recv().unwrap();
    assert_eq!(got.message_id, column.message_id);
    assert!(
        rx.blocking_recv().is_none(),
        "only the column, then the end"
    );
}

/// A stream that ends counts the batch that was filling up as unsent, and its open batches as
/// IGNORE.
#[test]
fn a_closed_stream_counts_what_it_held() {
    let metrics = HandOffMetrics::default();
    let mut stream = OpenStream::new(&metrics, HandOffLimits::default());
    assert!(stream.batcher.push(message(1), Instant::now()).is_none());
    assert!(stream.batcher.push(message(1), Instant::now()).is_none());
    stream.open.push_back(Open {
        id: 1,
        deadline: Instant::now(),
        messages: 3,
    });
    stream.close();
    assert_eq!((metrics.unsent(), metrics.ignored()), (2, 3));
    assert!(stream.batcher.is_empty() && stream.open.is_empty());
}
