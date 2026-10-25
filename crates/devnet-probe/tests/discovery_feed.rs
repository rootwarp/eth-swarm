//! The peer feed from cl-discv5 to cl-p2p over a Unix socket: cl-discv5's `WatchPeers` server
//! (`cl_discv5::server`) and cl-p2p's client and parse (`cl_p2p::service::peers`). The peer ID
//! that cl-discv5 writes for a record is the one libp2p derives from the same key, and cl-p2p's
//! node ID of a key is the record's node ID, so the custody columns of both agree. cl-p2p reads
//! the `cgc` of cl-discv5's own record (`GetLocalEnr`) and refuses one that is not its own.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cl_discv5::enr::{build_local_enr, CombinedKey, Enr, LocalAddr};
use cl_discv5::server::{peer_id_text, DiscoveryServer, PeerFeed, PeerSource};
use cl_p2p::service::peers::{watch_peers, Candidate, Discv5Peer};
use ipc::testkit::devnet::{devnet_config, devnet_hello, DEVNET_GENESIS};
use ipc::Link;
use libp2p::identity::Keypair;
use p2p_wire::enr::ForkFields;
use p2p_wire::ip::NetworkMode;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// A libp2p key and the discv5 record signed with the same secret, at `ip:tcp`.
fn key_and_record(ip: Ipv4Addr, tcp: u16) -> (Keypair, Enr) {
    let key = Keypair::generate_secp256k1();
    let mut secret = key
        .clone()
        .try_into_secp256k1()
        .unwrap()
        .secret()
        .to_bytes();
    let combined = CombinedKey::secp256k1_from_bytes(&mut secret).unwrap();
    let fork =
        ForkFields::from_schedule(&devnet_config(), &DEVNET_GENESIS.genesis_validators_root, 3)
            .unwrap();
    let addr = LocalAddr {
        ip,
        tcp_port: tcp,
        udp_port: 9000,
    };
    (key, build_local_enr(&combined, &fork, 4, &addr).unwrap())
}

#[test]
fn the_peer_id_and_the_node_id_are_libp2ps_and_the_records() {
    for _ in 0..16 {
        let (key, enr) = key_and_record(Ipv4Addr::new(10, 0, 0, 2), 9000);
        assert_eq!(
            peer_id_text(&enr).unwrap(),
            key.public().to_peer_id().to_string()
        );
        assert_eq!(
            cl_p2p::service::node_id(&key).unwrap(),
            devnet_probe::serve::node_id(&key).unwrap()
        );
    }
}

struct Table(Vec<Enr>);

impl PeerSource for Table {
    fn local_enr(&self) -> Enr {
        self.0[0].clone()
    }

    fn table_records(&self) -> Vec<Enr> {
        self.0.clone()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cl_p2p_gets_cl_discv5s_peers_over_the_socket() {
    let link = Link::network(Arc::new(devnet_hello("test")), 1).unwrap();
    let (known_key, known) = key_and_record(Ipv4Addr::new(10, 0, 0, 3), 9001);
    let feed = PeerFeed::default();
    let (stop, stopped) = watch::channel(false);
    let server = DiscoveryServer::new(
        link.clone(),
        Arc::new(Table(vec![known])),
        feed.clone(),
        stopped.clone(),
    );
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cl-discv5.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let routes = tonic::service::Routes::new(server.into_service());
    tokio::spawn(ipc::stub::serve_uds(
        listener,
        routes,
        std::future::pending(),
    ));
    let (tx, mut rx) = mpsc::channel(8);
    let discv5 = Discv5Peer {
        socket,
        uid: ipc::uds::Ownership::current().uid,
        mode: NetworkMode::Devnet,
        groups: 4,
    };
    // A cl-p2p of another group count than the record's: refused before any peer, a config
    // to fix (exit 2).
    let (other_tx, mut other_rx) = mpsc::channel(8);
    let other = Discv5Peer {
        groups: 8,
        ..discv5.clone()
    };
    let refused = tokio::time::timeout(
        Duration::from_secs(30),
        watch_peers(other, link.clone(), other_tx, stopped.clone()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(refused.exit_code(), 2, "{refused}");
    assert!(
        refused.to_string().contains("advertises cgc 4"),
        "{refused}"
    );
    assert!(other_rx.try_recv().is_err(), "no peer");
    let watching = tokio::spawn(watch_peers(discv5, link, tx, stopped));
    let next = |rx: &mut mpsc::Receiver<Candidate>| {
        let got = rx.try_recv();
        got.ok()
    };
    // The table's record first.
    let first = tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.peer, known_key.public().to_peer_id());
    assert_eq!(first.addrs[0].to_string(), "/ip4/10.0.0.3/tcp/9001");
    // Then each record discv5 reports, once the stream is open.
    let (found_key, found) = key_and_record(Ipv4Addr::new(10, 0, 0, 4), 9002);
    let got = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            feed.send(found.clone());
            tokio::time::sleep(Duration::from_millis(50)).await;
            if let Some(c) = next(&mut rx) {
                return c;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(got.peer, found_key.public().to_peer_id());
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(10), watching)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
