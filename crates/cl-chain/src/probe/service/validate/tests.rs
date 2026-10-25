#![allow(clippy::unwrap_used, clippy::expect_used)]

//! `GossipService/Validate` over a Unix socket, against a column hand-off that records what it
//! takes: the hellos, the fences, IGNORE for every message, and the stream failures.

use super::*;
use crate::probe::service::{chain_link, GossipServer, ProbeNetwork, Subscriptions};
use consensus_types::Minimal;
use ethswarm_proto::common::{ErrorCode, Hello};
use ipc::fence::{FencedRequest, Outstanding};
use ipc::hello::Generation;
use ipc::testkit::devnet::{DEVNET_CONFIG, DEVNET_GENESIS};
use network_config::ChainConfig;
use pb::gossip_service_client::GossipServiceClient;
use std::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;

/// The fixture devnet: minimal preset, 8-slot epochs, its digest changes at epochs 1 and 2.
fn devnet() -> ProbeNetwork {
    let yaml = format!("{DEVNET_CONFIG}MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS: 4096\n");
    let config = ChainConfig::from_devnet_yaml(yaml.as_bytes()).unwrap();
    ProbeNetwork::new("cl-chain/test", config, DEVNET_GENESIS).unwrap()
}

/// One column a hand-off took: `(digest, slot, subnet, ssz)`.
type Taken = ([u8; 4], u64, u64, Vec<u8>);

/// Records every column it takes.
#[derive(Default)]
struct Recorded(Mutex<Vec<Taken>>);

impl Recorded {
    fn taken(&self) -> Vec<Taken> {
        self.0.lock().unwrap().clone()
    }
}

impl ColumnHandOff for Recorded {
    fn hand_over(&self, column: GossipColumnBytes<'_>) -> HandOff {
        self.0.lock().unwrap().push((
            column.fork_digest,
            column.slot,
            column.subnet_id,
            column.ssz.to_vec(),
        ));
        HandOff::Stored
    }
}

/// A served `GossipService` with `Validate` on, and its client's side.
struct Served {
    net: ProbeNetwork,
    link: Link,
    columns: Arc<Recorded>,
    client: GossipServiceClient<tonic::transport::Channel>,
    stop: watch::Sender<bool>,
    _dir: tempfile::TempDir,
}

async fn served() -> Served {
    let net = devnet();
    let link = chain_link::<Minimal>(&net, ipc::hello::system_ms()).unwrap();
    let columns = Arc::new(Recorded::default());
    let (stop, stopped) = watch::channel(false);
    let server = GossipServer::new(
        link.clone(),
        Subscriptions::new(&net, vec![3]),
        Arc::new(ipc::hello::system_ms),
        stopped,
    )
    .validating(Arc::clone(&columns) as Arc<dyn ColumnHandOff>);
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("chain.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let routes = tonic::service::Routes::new(server.into_service());
    tokio::spawn(ipc::stub::serve_uds(
        listener,
        routes,
        std::future::pending(),
    ));
    let channel = ipc::uds::connect_path(&socket, ipc::uds::Ownership::current().uid)
        .await
        .unwrap();
    Served {
        net,
        link,
        columns,
        client: GossipServiceClient::new(channel),
        stop,
        _dir: dir,
    }
}

/// An open stream: what we send on it, and what it answers.
struct Stream {
    tx: mpsc::Sender<pb::ValidateRequest>,
    rx: Streaming<pb::ValidateResponse>,
    generation: Generation,
}

impl Served {
    /// Opens a stream with our `hello` and reads the server's.
    async fn open_with(&mut self, hello: Hello) -> Result<Stream, Status> {
        let (tx, frames) = mpsc::channel(8);
        tx.send(pb::ValidateRequest::hello(hello)).await.unwrap();
        let mut rx = self
            .client
            .validate(ReceiverStream::new(frames))
            .await?
            .into_inner();
        let first = rx.message().await?.expect("a first frame");
        let Some(pb::validate_response::Frame::Hello(server)) = first.frame else {
            panic!("the first frame is not hello: {first:?}");
        };
        let generation = Generation::new(server.generation).expect("a non-zero generation");
        Ok(Stream { tx, rx, generation })
    }

    async fn open(&mut self) -> Stream {
        let hello = self.link.local();
        self.open_with(hello).await.unwrap()
    }

    fn digest(&self, epoch: u64) -> [u8; 4] {
        self.net.digest_at(epoch).unwrap()
    }
}

/// A gossip message on `topic` whose envelope is a column sidecar at `slot` on `digest`.
fn message(n: u8, topic: pb::Topic, digest: [u8; 4], slot: u64, seq: u64) -> pb::GossipMessage {
    pb::GossipMessage {
        message_id: vec![n; 20],
        topic: topic as i32,
        subnet_id: 3,
        propagation_source: None,
        payload: Some(Envelope {
            fork_digest: digest.to_vec(),
            slot,
            ssz: vec![n; 8],
            payload_type: PayloadType::DataColumnSidecar as i32,
            seq,
            ..Default::default()
        }),
        received_unix_ms: 1,
    }
}

fn batch(
    request_id: u64,
    generation: u64,
    messages: Vec<pb::GossipMessage>,
) -> pb::ValidateRequest {
    pb::ValidateRequest::body(pb::ValidateBatch {
        messages,
        request_id,
        generation,
    })
}

/// The verdicts of the next frame.
async fn verdicts(stream: &mut Stream) -> pb::VerdictBatch {
    match stream.rx.message().await.unwrap().and_then(|m| m.frame) {
        Some(pb::validate_response::Frame::Verdicts(v)) => v,
        other => panic!("a verdict batch, got {other:?}"),
    }
}

/// The error code the stream fails with next.
async fn failure(stream: &mut Stream) -> ErrorCode {
    match stream.rx.message().await {
        Ok(Some(frame)) => panic!("a failure, got {frame:?}"),
        Ok(None) => panic!("the stream ended without a failure"),
        Err(status) => ipc::ContractError::from_status(&status).code(),
    }
}

/// A column sidecar is handed over with its envelope's digest, slot and subnet; a digest that
/// is not its slot's, a topic that is not a column's, an unknown topic and a payload that is not
/// a sidecar are not. Every verdict is IGNORE, echoes its message ID, and carries the fence of
/// its message, so the client settles the batch.
#[tokio::test]
async fn every_message_is_ignored_and_only_columns_are_handed_over() {
    let mut served = served().await;
    let mut stream = served.open().await;
    let d3 = served.digest(3);
    let mut block = message(4, pb::Topic::BeaconBlock, d3, 24, 4);
    block.payload.as_mut().unwrap().payload_type = PayloadType::SignedBeaconBlock as i32;
    let mut unknown_topic = message(5, pb::Topic::DataColumnSidecar, d3, 24, 5);
    unknown_topic.topic = 99;
    let mut not_a_sidecar = message(6, pb::Topic::DataColumnSidecar, d3, 24, 6);
    not_a_sidecar.payload.as_mut().unwrap().payload_type = PayloadType::SignedBeaconBlock as i32;
    let messages = vec![
        message(1, pb::Topic::DataColumnSidecar, d3, 24, 1),
        // Epoch 0's digest for a slot of epoch 3: dropped before any decode.
        message(2, pb::Topic::DataColumnSidecar, served.digest(0), 24, 2),
        message(3, pb::Topic::DataColumnSidecar, d3, 25, 3),
        block,
        unknown_topic,
        not_a_sidecar,
    ];
    let mut out = Outstanding::new(stream.generation, 4);
    let (_, request) = out
        .issue(|tag| {
            let body = pb::ValidateBatch {
                messages,
                request_id: tag.request_id,
                generation: tag.generation.get(),
            };
            let hashes = body.item_hashes();
            (body, hashes)
        })
        .unwrap();
    stream
        .tx
        .send(pb::ValidateRequest::body(request))
        .await
        .unwrap();
    let answer = verdicts(&mut stream).await;
    assert_eq!(out.settle_body(&answer), Ok(1), "the verdicts are fenced");
    assert_eq!(answer.verdicts.len(), 6);
    for (n, verdict) in (1u8..).zip(&answer.verdicts) {
        assert_eq!(verdict.verdict, Verdict::Ignore as i32, "{verdict:?}");
        assert_eq!(verdict.message_id, vec![n; 20]);
        assert!(verdict.reason.len() <= 256, "{}", verdict.reason);
    }
    assert_eq!(answer.verdicts[0].reason, HandOff::Stored.reason());
    assert_eq!(answer.verdicts[1].reason, DROPPED);
    assert_eq!(answer.verdicts[3].reason, NOT_A_COLUMN);
    assert_eq!(
        served.columns.taken(),
        vec![(d3, 24, 3, vec![1; 8]), (d3, 25, 3, vec![3; 8])]
    );
    // A second batch on the same stream, with the next id.
    stream
        .tx
        .send(batch(
            2,
            stream.generation.get(),
            vec![message(7, pb::Topic::DataColumnSidecar, d3, 26, 7)],
        ))
        .await
        .unwrap();
    assert_eq!(verdicts(&mut stream).await.request_id, 2);
    assert_eq!(served.columns.taken().len(), 3);
}

/// A batch with another generation than the stream's, a request_id that does not increase, no
/// message, too many, or a message with `TOPIC_UNSPECIFIED` fails the stream with a contract
/// violation, and nothing of it is handed over.
#[tokio::test]
async fn a_batch_that_breaks_the_contract_fails_the_stream() {
    let mut served = served().await;
    let d3 = served.digest(3);
    let column = |n: u8, seq| message(n, pb::Topic::DataColumnSidecar, d3, 24, seq);
    // Another generation.
    let mut stream = served.open().await;
    let other = stream.generation.get().wrapping_add(1).max(1);
    stream
        .tx
        .send(batch(1, other, vec![column(1, 1)]))
        .await
        .unwrap();
    assert_eq!(failure(&mut stream).await, ErrorCode::ContractViolation);
    // A request_id that does not increase.
    let mut stream = served.open().await;
    let g = stream.generation.get();
    stream
        .tx
        .send(batch(1, g, vec![column(1, 1)]))
        .await
        .unwrap();
    verdicts(&mut stream).await;
    stream
        .tx
        .send(batch(1, g, vec![column(2, 2)]))
        .await
        .unwrap();
    assert_eq!(failure(&mut stream).await, ErrorCode::ContractViolation);
    let taken = served.columns.taken().len();
    assert_eq!(taken, 1);
    // No message, and one too many.
    let mut stream = served.open().await;
    let g = stream.generation.get();
    stream.tx.send(batch(1, g, Vec::new())).await.unwrap();
    assert_eq!(failure(&mut stream).await, ErrorCode::ContractViolation);
    let mut stream = served.open().await;
    let g = stream.generation.get();
    let many = (0..=MAX_BATCH_MESSAGES as u64)
        .map(|i| column(1, i + 1))
        .collect();
    stream.tx.send(batch(1, g, many)).await.unwrap();
    assert_eq!(failure(&mut stream).await, ErrorCode::ContractViolation);
    // TOPIC_UNSPECIFIED after a good column: the column is not handed over either.
    let mut stream = served.open().await;
    let g = stream.generation.get();
    let mut unspecified = column(2, 2);
    unspecified.topic = pb::Topic::Unspecified as i32;
    stream
        .tx
        .send(batch(1, g, vec![column(1, 1), unspecified]))
        .await
        .unwrap();
    assert_eq!(failure(&mut stream).await, ErrorCode::ContractViolation);
    assert_eq!(served.columns.taken().len(), taken);
}

/// A hello that is not ours is refused before cl-chain sends its own; a stream opened with a
/// good hello ends with `UNAVAILABLE` when cl-chain stops.
#[tokio::test]
async fn the_hello_is_checked_and_the_stop_ends_the_stream() {
    let mut served = served().await;
    let mut wrong = served.link.local();
    wrong.genesis_validators_root = vec![9; 32];
    let refused = served.open_with(wrong).await.err().expect("refused");
    assert_eq!(
        ipc::ContractError::from_status(&refused).code(),
        ErrorCode::VersionMismatch
    );
    let mut stream = served.open().await;
    served.stop.send_replace(true);
    let status = loop {
        match stream.rx.message().await {
            Err(status) => break status,
            Ok(Some(_)) => {}
            Ok(None) => panic!("the stream ended without UNAVAILABLE"),
        }
    };
    assert_eq!(status.code(), tonic::Code::Unavailable);
}

/// At most four `Validate` streams are open at once: the fifth is `RESOURCE_EXHAUSTED`, and a
/// stream that its client closes gives its place back.
#[tokio::test]
async fn a_fifth_stream_waits_for_a_closed_one() {
    use crate::probe::service::MAX_VALIDATE_STREAMS;
    let mut served = served().await;
    let mut open = Vec::new();
    for _ in 0..MAX_VALIDATE_STREAMS {
        open.push(served.open().await);
    }
    let hello = served.link.local();
    let refused = served
        .open_with(hello.clone())
        .await
        .err()
        .expect("refused");
    assert_eq!(
        refused.code(),
        tonic::Code::ResourceExhausted,
        "{refused:?}"
    );
    drop(open.pop());
    let by = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match served.open_with(hello.clone()).await {
            Ok(_) => break,
            Err(status) => {
                assert_eq!(status.code(), tonic::Code::ResourceExhausted, "{status:?}");
                assert!(
                    tokio::time::Instant::now() < by,
                    "the place never came back"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}

/// Without a column hand-off, `Validate` is the stub's: our hello, then `UNIMPLEMENTED` once the
/// client closes its side.
#[tokio::test]
async fn without_a_hand_off_validate_is_the_stub() {
    let net = devnet();
    let link = chain_link::<Minimal>(&net, ipc::hello::system_ms()).unwrap();
    let (_stop, stopped) = watch::channel(false);
    let server = GossipServer::new(
        link.clone(),
        Subscriptions::new(&net, vec![3]),
        Arc::new(ipc::hello::system_ms),
        stopped,
    );
    assert!(format!("{server:?}").contains("validating: false"));
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("chain.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::spawn(ipc::stub::serve_uds(
        listener,
        tonic::service::Routes::new(server.into_service()),
        std::future::pending(),
    ));
    let channel = ipc::uds::connect_path(&socket, ipc::uds::Ownership::current().uid)
        .await
        .unwrap();
    let mut client = GossipServiceClient::new(channel);
    let hello = pb::ValidateRequest::hello(link.local());
    let mut rx = client
        .validate(tokio_stream::iter(vec![hello]))
        .await
        .unwrap()
        .into_inner();
    assert!(rx.message().await.unwrap().is_some(), "our hello");
    assert_eq!(
        rx.message().await.unwrap_err().code(),
        tonic::Code::Unimplemented
    );
}

#[test]
fn the_reasons_fit_a_verdict() {
    for reason in [
        HandOff::Stored.reason(),
        HandOff::Dropped("x").reason(),
        DROPPED,
        NOT_A_COLUMN,
    ] {
        assert!(reason.len() <= 256 && reason.starts_with("probe: IGNORE") || reason == "x");
    }
}
