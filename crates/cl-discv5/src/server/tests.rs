#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::enr::{build_local_enr, CombinedKey, LocalAddr};
use crate::service::ServiceError;
use crate::subnet_query::SubnetQuery;
use ethswarm_proto::common::ErrorCode;
use ipc::testkit::devnet::{devnet_config, devnet_hello, DEVNET_GENESIS};
use p2p_wire::enr::ForkFields;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use tokio_stream::StreamExt;

fn fork() -> ForkFields {
    ForkFields::from_schedule(&devnet_config(), &DEVNET_GENESIS.genesis_validators_root, 3).unwrap()
}

fn record(ip: Ipv4Addr, tcp: u16) -> Enr {
    on_subnets(ip, tcp, None)
}

/// [`record`] with `attnets` set to `attnets`, if any.
fn on_subnets(ip: Ipv4Addr, tcp: u16, attnets: Option<u64>) -> Enr {
    let addr = LocalAddr {
        ip,
        tcp_port: tcp,
        udp_port: 9000,
    };
    let key = CombinedKey::generate_secp256k1();
    let mut enr = build_local_enr(&key, &fork(), 4, &addr).unwrap();
    if let Some(attnets) = attnets {
        let value = alloy_rlp::Bytes::from(attnets.to_le_bytes().to_vec());
        enr.insert("attnets", &value, &key).unwrap();
    }
    enr
}

#[test]
fn base58btc_matches_its_vectors() {
    assert_eq!(base58btc(b""), "");
    assert_eq!(base58btc(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
    assert_eq!(base58btc(&[0, 0, 1]), "112");
    assert_eq!(
        base58btc(b"The quick brown fox jumps over the lazy dog."),
        "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"
    );
}

/// A candidate is the record, its peer ID, its TCP address, `cgc` and `nfd`; a record without a
/// TCP address is none. (devnet-probe checks the peer ID against libp2p's own.)
#[test]
fn a_candidate_carries_what_cl_p2p_dials() {
    let enr = record(Ipv4Addr::new(10, 0, 0, 2), 9001);
    let c = candidate(&enr).unwrap();
    assert!(c.peer_id.starts_with("16Uiu2"), "{}", c.peer_id);
    assert_eq!(c.peer_id.len(), 53);
    assert_eq!(c.multiaddrs, ["/ip4/10.0.0.2/tcp/9001"]);
    assert_eq!(c.custody_group_count, 4);
    assert_eq!(c.next_fork_digest, fork().nfd.to_vec());
    assert_eq!(c.enr.unwrap().text, enr.to_base64());
    // No IP in the record (unspecified): nothing to dial.
    assert!(candidate(&record(Ipv4Addr::UNSPECIFIED, 9001)).is_none());
}

/// A fixed table and local record; a lookup finds the table, or fails while `fail` is set.
struct Fixed {
    local: Enr,
    table: Mutex<Vec<Enr>>,
    fail: std::sync::atomic::AtomicBool,
}

impl PeerSource for Fixed {
    fn local_enr(&self) -> Enr {
        self.local.clone()
    }

    fn table_records(&self) -> Vec<Enr> {
        self.table.lock().unwrap().clone()
    }

    fn fork_digest(&self) -> ForkDigest {
        fork().eth2.fork_digest
    }

    /// The table's records that `query` matches, as a lookup that finds the whole table.
    async fn find_matching(
        &self,
        query: SubnetQuery,
        max: usize,
    ) -> Result<Vec<Enr>, ServiceError> {
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ServiceError::Query("no session".into()));
        }
        let table = self.table.lock().unwrap().clone();
        Ok(table
            .into_iter()
            .filter(|enr| query.matches(enr))
            .take(max)
            .collect())
    }
}

type Served = (DiscoveryServer<Fixed>, PeerFeed, watch::Sender<bool>, Link);

fn server(table: Vec<Enr>) -> Served {
    serve(Fixed {
        local: record(Ipv4Addr::new(10, 0, 0, 1), 9000),
        table: Mutex::new(table),
        fail: false.into(),
    })
    .0
}

fn serve(source: Fixed) -> (Served, Arc<Fixed>) {
    let source = Arc::new(source);
    let link = Link::network(Arc::new(devnet_hello("cl-discv5/test")), 1).unwrap();
    let feed = PeerFeed::default();
    let (stop, stopped) = watch::channel(false);
    let server = DiscoveryServer::new(
        link.clone(),
        Arc::clone(&source),
        feed.clone(),
        stopped,
        Arc::new(|| 0),
    );
    ((server, feed, stop, link), source)
}

fn peer_of(frame: Result<pb::WatchPeersResponse, Status>) -> String {
    match frame.unwrap().frame {
        Some(pb::watch_peers_response::Frame::Body(body)) => body.candidate.unwrap().peer_id,
        other => panic!("a body, got {other:?}"),
    }
}

/// The stream: our hello, the table's records, then each reported record; it ends with
/// `UNAVAILABLE` at the stop.
#[tokio::test]
async fn watch_peers_sends_the_table_then_the_feed() {
    let known = record(Ipv4Addr::new(10, 0, 0, 3), 9000);
    let (server, feed, stop, link) = server(vec![known.clone()]);
    let mut stream = server
        .watch_peers(Request::new(pb::WatchPeersRequest {
            hello: Some(link.local()),
        }))
        .await
        .unwrap()
        .into_inner();
    match stream.next().await.unwrap().unwrap().frame {
        Some(pb::watch_peers_response::Frame::Hello(h)) => assert_ne!(h.generation, 0),
        other => panic!("first frame {other:?}"),
    }
    assert_eq!(
        peer_of(stream.next().await.unwrap()),
        peer_id_text(&known).unwrap()
    );
    let found = record(Ipv4Addr::new(10, 0, 0, 4), 9000);
    // No TCP address: not sent; the next one is.
    feed.send(record(Ipv4Addr::UNSPECIFIED, 9000));
    feed.send(found.clone());
    assert_eq!(
        peer_of(stream.next().await.unwrap()),
        peer_id_text(&found).unwrap()
    );
    stop.send_replace(true);
    assert_eq!(
        stream.next().await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn get_local_enr_and_the_hello_rule() {
    let (server, _feed, _stop, _link) = server(Vec::new());
    let enr = server
        .get_local_enr(Request::new(pb::GetLocalEnrRequest {}))
        .await
        .unwrap()
        .into_inner()
        .enr
        .unwrap();
    assert!(enr.text.starts_with("enr:"), "{}", enr.text);
    let refused = server
        .watch_peers(Request::new(pb::WatchPeersRequest { hello: None }))
        .await
        .err()
        .expect("refused");
    assert_eq!(
        ipc::ContractError::from_status(&refused).code(),
        ErrorCode::ContractViolation
    );
}

fn find(
    attnets: &[u32],
    target: u32,
    hello: Option<ethswarm_proto::common::Hello>,
) -> Request<pb::FindPeersRequest> {
    Request::new(pb::FindPeersRequest {
        attnets: attnets.to_vec(),
        target,
        hello,
        ..Default::default()
    })
}

fn found(frame: Result<pb::FindPeersResponse, Status>) -> String {
    match frame.unwrap().frame {
        Some(pb::find_peers_response::Frame::Body(body)) => body.candidate.unwrap().peer_id,
        other => panic!("a body, got {other:?}"),
    }
}

/// Our hello, then one candidate per dialable record that serves a wanted subnet, at most
/// `target`, then the end of the stream.
#[tokio::test]
async fn find_peers_sends_the_hello_then_only_matching_candidates() {
    let on_0 = on_subnets(Ipv4Addr::new(10, 0, 0, 3), 9000, Some(1));
    let on_5 = on_subnets(Ipv4Addr::new(10, 0, 0, 4), 9000, Some(1 << 5));
    let undialable = on_subnets(Ipv4Addr::UNSPECIFIED, 9000, Some(1));
    let none = record(Ipv4Addr::new(10, 0, 0, 5), 9000);
    let (server, _feed, _stop, link) = server(vec![undialable, none, on_5, on_0.clone()]);
    let mut stream = server
        .find_peers(find(&[0], 4, Some(link.local())))
        .await
        .unwrap()
        .into_inner();
    match stream.next().await.unwrap().unwrap().frame {
        Some(pb::find_peers_response::Frame::Hello(h)) => assert_ne!(h.generation, 0),
        other => panic!("first frame {other:?}"),
    }
    assert_eq!(
        found(stream.next().await.unwrap()),
        peer_id_text(&on_0).unwrap()
    );
    assert!(stream.next().await.is_none());

    // Two match, one is wanted.
    let stream = server
        .find_peers(find(&[0, 5], 1, Some(link.local())))
        .await
        .unwrap()
        .into_inner();
    let frames: Vec<_> = stream.collect().await;
    assert_eq!(frames.len(), 2, "{frames:?}");
}

#[tokio::test]
async fn find_peers_needs_a_hello() {
    let (server, _feed, _stop, _link) = server(Vec::new());
    let refused = server
        .find_peers(find(&[0], 1, None))
        .await
        .err()
        .expect("refused");
    assert_eq!(
        ipc::ContractError::from_status(&refused).code(),
        ErrorCode::ContractViolation
    );
}

/// A malformed request is `INVALID_ARGUMENT`, another fork digest `FAILED_PRECONDITION`, both
/// before any frame.
#[tokio::test]
async fn find_peers_refuses_bad_requests() {
    let (server, _feed, _stop, link) = server(Vec::new());
    let ok = || find(&[0], 1, Some(link.local())).into_inner();
    let other = fork().eth2.fork_digest.map(|b| !b).to_vec();
    for (request, code) in [
        (
            pb::FindPeersRequest {
                attnets: vec![64],
                ..ok()
            },
            tonic::Code::InvalidArgument,
        ),
        (
            pb::FindPeersRequest {
                syncnets: vec![4],
                ..ok()
            },
            tonic::Code::InvalidArgument,
        ),
        (
            pb::FindPeersRequest {
                custody_columns: vec![128],
                ..ok()
            },
            tonic::Code::InvalidArgument,
        ),
        (
            pb::FindPeersRequest {
                attnets: vec![],
                ..ok()
            },
            tonic::Code::InvalidArgument,
        ),
        (
            pb::FindPeersRequest { target: 0, ..ok() },
            tonic::Code::InvalidArgument,
        ),
        (
            pb::FindPeersRequest {
                fork_digest: vec![1, 2, 3],
                ..ok()
            },
            tonic::Code::InvalidArgument,
        ),
        (
            pb::FindPeersRequest {
                fork_digest: other,
                ..ok()
            },
            tonic::Code::FailedPrecondition,
        ),
    ] {
        let refused = server.find_peers(Request::new(request.clone())).await.err();
        assert_eq!(refused.map(|s| s.code()), Some(code), "{request:?}");
    }
}

/// A failed lookup ends the stream with `UNAVAILABLE` after our hello, and is not cached: the
/// same request in the same slot looks up again.
#[tokio::test]
async fn find_peers_ends_unavailable_when_the_lookup_fails() {
    let on_0 = on_subnets(Ipv4Addr::new(10, 0, 0, 3), 9000, Some(1));
    let ((server, _feed, _stop, link), source) = serve(Fixed {
        local: record(Ipv4Addr::new(10, 0, 0, 1), 9000),
        table: Mutex::new(vec![on_0.clone()]),
        fail: true.into(),
    });
    let mut stream = server
        .find_peers(find(&[0], 1, Some(link.local())))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        stream.next().await.unwrap().unwrap().frame,
        Some(pb::find_peers_response::Frame::Hello(_))
    ));
    assert_eq!(
        stream.next().await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert!(stream.next().await.is_none());

    source
        .fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut stream = server
        .find_peers(find(&[0], 1, Some(link.local())))
        .await
        .unwrap()
        .into_inner();
    stream.next().await.unwrap().unwrap();
    assert_eq!(
        found(stream.next().await.unwrap()),
        peer_id_text(&on_0).unwrap()
    );
}

/// At the stop, the stream sends our hello and ends with `UNAVAILABLE`.
#[tokio::test]
async fn find_peers_ends_unavailable_at_the_stop() {
    let on_0 = on_subnets(Ipv4Addr::new(10, 0, 0, 3), 9000, Some(1));
    let (server, _feed, stop, link) = server(vec![on_0]);
    stop.send_replace(true);
    let mut stream = server
        .find_peers(find(&[0], 1, Some(link.local())))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        stream.next().await.unwrap().unwrap().frame,
        Some(pb::find_peers_response::Frame::Hello(_))
    ));
    assert_eq!(
        stream.next().await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    assert!(stream.next().await.is_none());
}

/// The deadline is the call's `grpc-timeout` from now (1 to 8 digits and a unit, as tonic's
/// server reads it); none without one or for one that does not parse.
#[tokio::test(start_paused = true)]
async fn the_deadline_is_the_grpc_timeout() {
    let now = tokio::time::Instant::now();
    let mut request = Request::new(());
    assert_eq!(deadline(request.metadata()), None);
    request.set_timeout(std::time::Duration::from_millis(1500));
    assert_eq!(
        deadline(request.metadata()),
        Some(now + std::time::Duration::from_millis(1500))
    );
    let secs = std::time::Duration::from_secs;
    for (value, want) in [
        ("2H", Some(secs(7200))),
        ("3M", Some(secs(180))),
        ("4S", Some(secs(4))),
        ("5m", Some(std::time::Duration::from_millis(5))),
        ("6u", Some(std::time::Duration::from_micros(6))),
        ("7n", Some(std::time::Duration::from_nanos(7))),
        ("99999999S", Some(secs(99_999_999))),
        ("123456789S", None),
        ("", None),
        ("S", None),
        ("5", None),
        ("5x", None),
        ("+5S", None),
        ("-5S", None),
        ("5 S", None),
    ] {
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("grpc-timeout", value.parse().unwrap());
        assert_eq!(
            deadline(request.metadata()),
            want.map(|d| now + d),
            "{value:?}"
        );
    }
}
