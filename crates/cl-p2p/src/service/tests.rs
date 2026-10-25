#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::rpc::inbound::SharedStatus;
use consensus_types::das::CUSTODY_REQUIREMENT;
use ipc::testkit::devnet::{kurtosis_config, DEVNET_GENESIS};
use p2p_wire::gossip::{GossipKind, GossipTopic};
use prometheus_client::registry::Registry;

fn body(columns: Vec<u64>, digests: &[[u8; 4]]) -> pb::WatchSubscriptionsResponseBody {
    pb::WatchSubscriptionsResponseBody {
        attnets: Vec::new(),
        syncnets: Vec::new(),
        custody_columns: columns,
        fork_digests: digests.iter().map(|d| d.to_vec()).collect(),
    }
}

/// The node ID is keccak256 of the key's uncompressed public key: the custody columns of the
/// key follow it. (devnet-probe checks it against the discv5 record's node ID.)
#[test]
fn the_custody_check_holds_cl_chain_to_our_key() {
    let key = Keypair::generate_secp256k1();
    let id = node_id(&key).unwrap();
    let ours = custody_columns(id, CUSTODY_REQUIREMENT).unwrap();
    let subs = CustodySubscriptions::from_chain(&body(ours.clone(), &[[1; 4]])).unwrap();
    assert_eq!(check_custody(id, &subs), Ok(CUSTODY_REQUIREMENT));
    // Another key's columns: refused, naming both.
    let other = node_id(&Keypair::generate_secp256k1()).unwrap();
    let theirs = custody_columns(other, CUSTODY_REQUIREMENT).unwrap();
    let subs = CustodySubscriptions::from_chain(&body(theirs.clone(), &[[1; 4]])).unwrap();
    let err = check_custody(id, &subs).unwrap_err();
    assert_eq!(
        err,
        CustodyError::NotOurs {
            chain: theirs,
            ours
        }
    );
    assert!(node_id(&Keypair::generate_ed25519()).is_none());
}

/// Fewer custody groups than `CUSTODY_REQUIREMENT` break the spec, even when the columns are our
/// key's: refused. More are accepted (a supernode custodies all 128).
#[test]
fn the_custody_check_wants_the_custody_requirement() {
    let id = node_id(&Keypair::generate_secp256k1()).unwrap();
    for groups in [1, CUSTODY_REQUIREMENT - 1] {
        let columns = custody_columns(id, groups).unwrap();
        let subs = CustodySubscriptions::from_chain(&body(columns, &[[1; 4]])).unwrap();
        assert_eq!(
            check_custody(id, &subs),
            Err(CustodyError::TooFew { groups }),
            "{groups} groups"
        );
    }
    let all = custody_columns(id, NUMBER_OF_CUSTODY_GROUPS).unwrap();
    let subs = CustodySubscriptions::from_chain(&body(all, &[[1; 4]])).unwrap();
    assert_eq!(check_custody(id, &subs), Ok(NUMBER_OF_CUSTODY_GROUPS));
}

/// The topics of a digest: the topic list under the first two digests, and the custody
/// subnets under each; each once.
#[test]
fn the_topics_are_the_list_and_the_custody_subnets() {
    let text = "topics = [\"beacon_block\", \"data_column_sidecar_3\"]\n";
    let list = crate::gossip::TopicList::parse(text).unwrap();
    let subs =
        CustodySubscriptions::from_chain(&body(vec![3, 70], &[[1; 4], [2; 4], [3; 4]])).unwrap();
    let digests = digests::DigestTopics::new(list, Duration::from_secs(1), subs);
    let names = |digest, index| -> Vec<String> {
        digests
            .topics_under(digest, index)
            .iter()
            .map(ToString::to_string)
            .collect()
    };
    let topic = |digest, kind| GossipTopic::new(digest, kind).to_string();
    let column = |subnet_id| GossipKind::DataColumnSidecar { subnet_id };
    for (digest, index) in [([1; 4], 0), ([2; 4], 1)] {
        assert_eq!(
            names(digest, index),
            [
                topic(digest, GossipKind::BeaconBlock),
                topic(digest, column(3)),
                topic(digest, column(70)),
            ]
        );
    }
    assert_eq!(
        names([3; 4], 2),
        [topic([3; 4], column(3)), topic([3; 4], column(70))]
    );
}

/// The swarm's metrics go to the service's registry without a prefix, under the names the run
/// reports read: `p2p_peers`, `p2p_goodbye_received_total`, and gossipsub's own families on the
/// same registry. gossipsub writes its `topic_msg_*` families with their first message (absent
/// reads 0); `gossip::tests` reads them by these names with traffic.
#[tokio::test]
async fn the_metric_names_the_reports_read() {
    let config = kurtosis_config();
    let mut registry = Registry::default();
    let digest = network_config::digest::compute_fork_digest(
        &config,
        &DEVNET_GENESIS.genesis_validators_root,
        0,
    )
    .unwrap();
    let sources = swarm::Sources {
        status: Arc::new(SharedStatus::new(None)),
        custody_group_count: CUSTODY_REQUIREMENT,
        columns: None,
    };
    let plan = swarm::SwarmPlan {
        listen: Vec::new(),
        idle: IDLE_CONNECTION_TIMEOUT,
        bypass: Vec::new(),
        muxer_observer: None,
        ping_interval: crate::rpc::inbound::PING_INTERVAL,
        gossip: None,
        limits: RpcLimits::default(),
    };
    let gossip = swarm::Gossip {
        topics: vec![GossipTopic::new(digest, GossipKind::BeaconBlock)],
        tap: None,
    };
    let _swarm = swarm::serving_swarm::<Minimal>(
        &config,
        &DEVNET_GENESIS,
        Keypair::generate_secp256k1(),
        sources,
        plan,
        Some(gossip),
        &mut registry,
    )
    .unwrap();
    let _peers = PeerMetrics::register(&mut registry);
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
    for name in [
        "# TYPE mesh_peer_counts gauge",
        "# TYPE topic_subscription_status gauge",
        "# TYPE p2p_peers gauge",
        "# TYPE p2p_goodbye_received counter",
        "# TYPE p2p_goodbye_sent counter",
    ] {
        assert!(text.contains(name), "{name} missing:\n{text}");
    }
    assert!(
        text.contains("p2p_peers{direction=\"inbound\"} 0"),
        "{text}"
    );
    assert!(!text.contains("ethswarm_"), "{text}");
}

#[test]
fn exit_codes_follow_the_unit() {
    use svc_runtime::RuntimeError;
    assert_eq!(ServeError::Unavailable(String::new()).exit_code(), 69);
    assert_eq!(ServeError::Config(String::new()).exit_code(), 2);
    assert_eq!(ServeError::Failed(String::new()).exit_code(), 1);
    // A restart can fix a fault of the run (70), not the socket's bind or the ACL (1).
    let runtime = |e| ServeError::Runtime(e).exit_code();
    assert_eq!(
        runtime(RuntimeError::Bind(ipc::uds::BindError::Service("X".into()))),
        1
    );
    assert_eq!(runtime(RuntimeError::UnservedMethods(Vec::new())), 1);
    assert_eq!(runtime(RuntimeError::Exited), 70);
    assert_eq!(
        runtime(RuntimeError::DrainTimeout(Duration::from_secs(1))),
        70
    );
    assert_eq!(
        runtime(RuntimeError::LogWriter(
            std::io::ErrorKind::WouldBlock.into()
        )),
        71
    );
    assert!(![1, 2, 64].contains(&EXIT_SOFTWARE));
    assert_eq!(
        svc_runtime::config::config_path(SERVICE).to_str(),
        Some(CONFIG_PATH)
    );
}

/// An owner of a swarm on Sepolia with no gossip, for the key of `node` with
/// `CUSTODY_REQUIREMENT` groups; its feed's receiver.
fn sepolia_owner(
    status: Arc<dyn StatusSource>,
    node: U256,
    registry: &mut Registry,
) -> (Owner<Mainnet>, mpsc::Receiver<feed::FeedEvent>) {
    let network = network_config::Network::Sepolia;
    let config = network_config::ChainConfig::load(network).unwrap();
    let genesis = network.genesis().unwrap();
    let swarm = swarm::serving_swarm::<Mainnet>(
        &config,
        &genesis,
        Keypair::generate_secp256k1(),
        swarm::Sources {
            status: Arc::clone(&status),
            custody_group_count: CUSTODY_REQUIREMENT,
            columns: None,
        },
        swarm::SwarmPlan {
            listen: Vec::new(),
            idle: IDLE_CONNECTION_TIMEOUT,
            bypass: Vec::new(),
            muxer_observer: None,
            ping_interval: crate::rpc::inbound::PING_INTERVAL,
            gossip: None,
            limits: RpcLimits::default(),
        },
        None,
        registry,
    )
    .unwrap();
    let (feed_tx, feed_rx) = mpsc::channel(64);
    let owner = Owner {
        swarm,
        peer_metrics: PeerMetrics::register(registry),
        dialer: peers::Dialer::new(1, Vec::new()),
        feed: FeedSender::new(feed_tx, registry),
        status,
        topics: digests::DigestTopics::new(
            crate::gossip::TopicList::parse("topics = [\"beacon_block\"]\n").unwrap(),
            Duration::from_secs(1),
            CustodySubscriptions::from_chain(&body(Vec::new(), &[])).unwrap(),
        ),
        node,
        groups: CUSTODY_REQUIREMENT,
    };
    (owner, feed_rx)
}

/// Every subscriptions body is held to our key, not only the first: a cl-chain that starts to
/// name another key's columns, or another group count than our MetaData and record carry, stops
/// the owner with a refused config (exit 2). A body equal to the first goes on.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_body_of_another_key_stops_the_owner() {
    let id = node_id(&Keypair::generate_secp256k1()).unwrap();
    let ours = custody_columns(id, CUSTODY_REQUIREMENT).unwrap();
    let other = node_id(&Keypair::generate_secp256k1()).unwrap();
    let theirs = custody_columns(other, CUSTODY_REQUIREMENT).unwrap();
    let more = custody_columns(id, CUSTODY_REQUIREMENT * 2).unwrap();
    for (later, why) in [
        (theirs, "set cl-chain's node_id"),
        (more, "custody group count"),
    ] {
        let mut registry = Registry::default();
        let status: Arc<dyn StatusSource> = Arc::new(SharedStatus::new(None));
        let (owner, _feed) = sepolia_owner(status, id, &mut registry);
        let (subs, subs_rx) = mpsc::channel(4);
        let (_candidates, candidates_rx) = mpsc::channel(1);
        let (_stop, stopped) = watch::channel(false);
        for columns in [ours.clone(), ours.clone(), later.clone()] {
            let body = CustodySubscriptions::from_chain(&body(columns, &[[1; 4]])).unwrap();
            subs.send(body).await.unwrap();
        }
        let driving = tokio::spawn(owner.drive(candidates_rx, subs_rx, stopped));
        let err = tokio::time::timeout(Duration::from_secs(10), driving)
            .await
            .expect("the owner stopped")
            .unwrap()
            .unwrap_err();
        assert_eq!(err.exit_code(), EXIT_CONFIG, "{err}");
        assert!(err.to_string().contains(why), "{err}");
        assert!(
            err.to_string().contains(&format!("{later:?}")) || why == "custody group count",
            "names the later columns: {err}"
        );
    }
}

/// The owner loop dials a candidate once there is a Status, hands the peer's judged Status to
/// the ledger's feed, and at the stop says Goodbye 1 to the peer.
#[tokio::test(flavor = "multi_thread")]
async fn the_owner_dials_feeds_the_ledger_and_says_goodbye() {
    use crate::rpc::inbound::ControlEvent;
    use crate::testkit::StatusPeer;
    let peer = StatusPeer::echoing(p2p_wire::testkit::status()).await;
    let pinned = peer.pinned();
    let status: Arc<dyn StatusSource> =
        Arc::new(SharedStatus::new(Some(p2p_wire::testkit::status())));
    let mut registry = Registry::default();
    let (owner, mut feed_rx) = sepolia_owner(status, U256::ZERO, &mut registry);
    let (candidates, candidates_rx) = mpsc::channel(4);
    let (_subscriptions, subscriptions_rx) = mpsc::channel(1);
    let (stop, stopped) = watch::channel(false);
    candidates
        .send(peers::Candidate {
            peer: pinned.peer_id,
            addrs: vec![pinned.addr.clone()],
        })
        .await
        .unwrap();
    let driving = tokio::spawn(owner.drive(candidates_rx, subscriptions_rx, stopped));
    let judged = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match feed_rx.recv().await {
                Some(feed::FeedEvent::Control(ControlEvent::Status {
                    peer, relevance, ..
                })) if peer == pinned.peer_id => {
                    return relevance;
                }
                Some(_) => {}
                None => panic!("the feed closed"),
            }
        }
    })
    .await
    .expect("the peer's Status reached the feed");
    assert!(judged.is_relevant(), "{judged:?}");
    assert!(!peer.requests().is_empty(), "our Status reached the peer");
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(10), driving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
    // The family's series come in no fixed order: one of reason 1 reads 1.
    let sent = text
        .lines()
        .filter(|l| l.starts_with("p2p_goodbye_sent_total{reason=\"1\""))
        .any(|l| l.ends_with(" 1"));
    assert!(sent, "{text}");
    assert!(text.contains("p2p_peers{direction=\"outbound\"}"), "{text}");
}

/// cl-chain's socket that is not there yet is a restart (69); a server of another user is a
/// refusal that a restart cannot fix (1).
#[tokio::test]
async fn a_cl_chain_of_another_user_is_a_failed_start() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cl-chain.sock");
    let me = ipc::uds::Ownership::current().uid;
    let missing = ipc::uds::connect_path_waiting(&socket, me, Duration::ZERO, || {})
        .await
        .unwrap_err();
    assert_eq!(chain_unreachable(&socket, &missing).exit_code(), 69);
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::spawn(ipc::stub::serve_uds(
        listener,
        tonic::service::Routes::default(),
        std::future::pending(),
    ));
    let other = ipc::uds::connect_path_waiting(&socket, me + 1, Duration::from_secs(5), || {})
        .await
        .unwrap_err();
    assert_eq!(chain_unreachable(&socket, &other).exit_code(), 1);
}

/// The swarm's tasks that do not end within their limit after the drain are a fault a restart
/// can fix (70); tasks that end are a clean stop.
#[tokio::test]
async fn tasks_that_do_not_end_in_time_are_70() {
    let err = tasks_end(std::future::pending::<()>(), Duration::from_millis(20))
        .await
        .unwrap_err();
    assert_eq!(err.exit_code(), 70);
    assert!(tasks_end(async {}, Duration::from_secs(5)).await.is_ok());
}
