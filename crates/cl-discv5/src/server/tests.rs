#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::enr::{build_local_enr, CombinedKey, LocalAddr};
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
    let addr = LocalAddr {
        ip,
        tcp_port: tcp,
        udp_port: 9000,
    };
    build_local_enr(&CombinedKey::generate_secp256k1(), &fork(), 4, &addr).unwrap()
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

/// A fixed table and local record.
struct Fixed {
    local: Enr,
    table: Mutex<Vec<Enr>>,
}

impl PeerSource for Fixed {
    fn local_enr(&self) -> Enr {
        self.local.clone()
    }

    fn table_records(&self) -> Vec<Enr> {
        self.table.lock().unwrap().clone()
    }
}

fn server(table: Vec<Enr>) -> (DiscoveryServer<Fixed>, PeerFeed, watch::Sender<bool>, Link) {
    let link = Link::network(Arc::new(devnet_hello("cl-discv5/test")), 1).unwrap();
    let feed = PeerFeed::default();
    let (stop, stopped) = watch::channel(false);
    let source = Fixed {
        local: record(Ipv4Addr::new(10, 0, 0, 1), 9000),
        table: Mutex::new(table),
    };
    let server = DiscoveryServer::new(link.clone(), Arc::new(source), feed.clone(), stopped);
    (server, feed, stop, link)
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
