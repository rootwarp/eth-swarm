#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::verify::client::KzgOutcome;
use consensus_types::Minimal;
use ethswarm_proto::common::ErrorCode;
use ethswarm_proto::verify::KzgCellProof;
use ipc::testkit::devnet::{DEVNET_CONFIG, DEVNET_GENESIS};
use ssz::Encode;
use tokio_stream::StreamExt;

/// The fixture devnet (minimal preset, 6 s slots, 8-slot epochs; its digest changes at epochs
/// 1 and 2), with the serve range's config value.
fn devnet() -> ProbeNetwork {
    let yaml = format!("{DEVNET_CONFIG}MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS: 4096\n");
    let config = ChainConfig::from_devnet_yaml(yaml.as_bytes()).unwrap();
    ProbeNetwork::new("cl-chain/test", config, DEVNET_GENESIS).unwrap()
}

/// Unix milliseconds at the start of `epoch` of the fixture devnet.
fn epoch_ms(epoch: u64) -> u128 {
    devnet().epoch_start_ms(epoch)
}

/// Passes every cell.
struct Valid;

impl KzgVerifier for Valid {
    async fn verify_cells(&self, _: Vec<KzgCellProof>, _: Duration) -> KzgOutcome {
        KzgOutcome::Valid
    }
}

#[test]
fn the_acl_admits_cl_p2p_to_its_five_methods_only() {
    let acl = chain_acl(990).unwrap();
    assert_eq!(acl.methods().collect::<Vec<_>>().len(), CHAIN_METHODS.len());
    for method in CHAIN_METHODS {
        assert!(acl.allows(method, 990), "{method}");
        assert!(!acl.allows(method, 991), "{method}");
    }
    assert!(acl.allows("/ethswarm.chain.v1.GossipService/Validate", 990));
    assert!(!acl.allows("/ethswarm.chain.v1.ReqRespService/GetMetadata", 990));
    assert!(!acl.allows("/ethswarm.chain.v1.GossipService/WatchPublish", 990));
}

#[test]
fn the_network_names_its_epochs_and_digests() {
    let net = devnet();
    assert_eq!(net.slots_per_epoch(), 8);
    assert_eq!(net.preset(), Preset::Minimal);
    assert_eq!(net.genesis(), DEVNET_GENESIS);
    assert_eq!(net.epoch_at(epoch_ms(3) + 1).unwrap(), 3);
    assert!(net.epoch_at(epoch_ms(0) - 1).is_err());
    assert_eq!(net.slot_at(epoch_ms(2) + 6_000), Some(17));
    assert_eq!(net.slot_at(epoch_ms(0) - 1), None);
    let digests: Vec<_> = (0..4).map(|e| net.digest_at(e).unwrap()).collect();
    assert_ne!(digests[0], digests[1]);
    assert_ne!(digests[1], digests[2]);
    assert_eq!(digests[2], digests[3]);
    assert_eq!(net.probe_chain().slots_per_epoch, 8);
    let link = chain_link::<Minimal>(&net, epoch_ms(3)).unwrap();
    assert_eq!(link.local().current_fork_digest, digests[3].to_vec());
    assert!(chain_link::<Minimal>(&net, epoch_ms(0) - 1).is_err());
}

/// The body names the digest of the wall clock and each digest whose change comes within
/// [`SUBSCRIBE_AHEAD`] epochs: two changes one epoch apart each get the full lead.
#[test]
fn subscriptions_name_each_digest_ahead_of_its_change() {
    let net = devnet();
    let subs = Subscriptions::new(&net, vec![3, 70]);
    let d = |e| net.digest_at(e).unwrap().to_vec();
    let digests = |epoch| subs.body_at(epoch_ms(epoch)).unwrap().fork_digests;
    // The changes at epochs 1 and 2 are both within 2 epochs of epoch 0.
    assert_eq!(digests(0), [d(0), d(1), d(2)]);
    assert_eq!(digests(1), [d(1), d(2)]);
    assert_eq!(digests(2), [d(2)]);
    assert_eq!(digests(9), [d(2)]);
    let body = subs.body_at(epoch_ms(5)).unwrap();
    assert_eq!(body.custody_columns, [3, 70]);
    assert!(body.attnets.is_empty() && body.syncnets.is_empty());
    assert_eq!(subs.body_at(epoch_ms(0) - 1), None);
    // The next look is at the next epoch start; before genesis, at genesis.
    assert_eq!(
        subs.wait_from(epoch_ms(4) + 10_000),
        Duration::from_millis(38_000)
    );
    assert_eq!(
        subs.wait_from(epoch_ms(0) - 5_000),
        Duration::from_millis(5_000)
    );
}

fn watch_request(link: &Link) -> Request<pb::WatchSubscriptionsRequest> {
    Request::new(pb::WatchSubscriptionsRequest {
        hello: Some(link.local()),
    })
}

/// The stream sends our hello, then a body each time the digests change, and ends with
/// `UNAVAILABLE` when cl-chain stops.
#[tokio::test(start_paused = true)]
async fn watch_subscriptions_sends_each_change_then_ends_at_the_stop() {
    use pb::watch_subscriptions_response::Frame;
    let net = devnet();
    let start = tokio::time::Instant::now();
    let base = epoch_ms(0);
    let clock: WallMs = Arc::new(move || base + start.elapsed().as_millis());
    let (stop, stopped) = watch::channel(false);
    let link = chain_link::<Minimal>(&net, base).unwrap();
    let server = GossipServer::new(
        link.clone(),
        Subscriptions::new(&net, vec![3]),
        clock,
        stopped,
    );
    let mut stream = server
        .watch_subscriptions(watch_request(&link))
        .await
        .unwrap()
        .into_inner();
    match stream.next().await.unwrap().unwrap().frame {
        Some(Frame::Hello(h)) => assert_ne!(h.generation, 0),
        other => panic!("first frame {other:?}"),
    }
    let d = |e| net.digest_at(e).unwrap().to_vec();
    for want in [vec![d(0), d(1), d(2)], vec![d(1), d(2)], vec![d(2)]] {
        match stream.next().await.unwrap().unwrap().frame {
            Some(Frame::Body(body)) => assert_eq!(body.fork_digests, want),
            other => panic!("a body, got {other:?}"),
        }
    }
    stop.send_replace(true);
    let end = stream.next().await.unwrap().unwrap_err();
    assert_eq!(end.code(), tonic::Code::Unavailable);
    assert!(stream.next().await.is_none());
    // A stream opened after the stop ends at once, after its hello.
    let mut late = server
        .watch_subscriptions(watch_request(&link))
        .await
        .unwrap()
        .into_inner();
    assert!(late.next().await.unwrap().is_ok());
    assert_eq!(
        late.next().await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
}

/// A stream ends when the service is gone, and a request without a hello is a contract
/// violation.
#[tokio::test(start_paused = true)]
async fn watch_subscriptions_ends_with_the_service_and_needs_a_hello() {
    let net = devnet();
    let link = chain_link::<Minimal>(&net, epoch_ms(3)).unwrap();
    let (stop, stopped) = watch::channel(false);
    let server = GossipServer::new(
        link.clone(),
        Subscriptions::new(&net, vec![3]),
        Arc::new(move || epoch_ms(3)),
        stopped,
    );
    let mut stream = server
        .watch_subscriptions(watch_request(&link))
        .await
        .unwrap()
        .into_inner();
    assert!(stream.next().await.unwrap().is_ok());
    assert!(stream.next().await.unwrap().is_ok());
    drop(stop);
    assert_eq!(
        stream.next().await.unwrap().unwrap_err().code(),
        tonic::Code::Unavailable
    );
    let refused = server
        .watch_subscriptions(Request::new(pb::WatchSubscriptionsRequest { hello: None }))
        .await
        .err()
        .expect("refused");
    assert_eq!(
        ipc::ContractError::from_status(&refused).code(),
        ErrorCode::ContractViolation
    );
}

/// A temp directory with no symlink on its path and no ancestor that other users can write,
/// as the store's parent check needs.
fn closed_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .tempdir_in(svc_runtime::owned::testkit::config_root())
        .unwrap()
}

#[test]
fn the_store_dir_is_created_once_and_opened_again() {
    use std::os::unix::fs::PermissionsExt;
    let uid = ipc::uds::Ownership::current().uid;
    let dir = closed_tempdir();
    let store = dir.path().join("columns");
    open_store_dir(&store, uid).unwrap();
    let mode = std::fs::metadata(&store).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o700);
    // A restart: the same directory again.
    open_store_dir(&store, uid).unwrap();
    // Another user's store, or one that others can write: refused.
    assert!(open_store_dir(&store, uid + 1).is_err());
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o770)).unwrap();
    let err = open_store_dir(&store, uid).unwrap_err();
    assert!(err.contains("mode 0770"), "{err}");
    // A symlink in its place, a file, a relative path, and a parent others can write.
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&store, &link).unwrap();
    assert!(open_store_dir(&link, uid)
        .unwrap_err()
        .contains("not a directory"));
    let file = dir.path().join("file");
    std::fs::write(&file, b"").unwrap();
    assert!(open_store_dir(&file, uid).is_err());
    assert!(open_store_dir(Path::new("columns"), uid)
        .unwrap_err()
        .contains("absolute"));
    let open = dir.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = open_store_dir(&open.join("columns"), uid).unwrap_err();
    assert!(err.contains("column store parent"), "{err}");
}

fn plan(dir: &Path, cgc_set_slot: u64) -> ProbePlan<Valid> {
    let net = devnet();
    ProbePlan {
        link: chain_link::<Minimal>(&net, system_ms()).unwrap(),
        node_id: U256::from(7u64),
        columns_dir: dir.to_owned(),
        // Nothing listens there: the follower retries, the Status has no sample.
        reference: BeaconApi::new("http://127.0.0.1:1", Duration::from_millis(200)).unwrap(),
        kzg: Valid,
        verify_timeout: DEFAULT_VERIFY_TIMEOUT,
        cgc_set_slot,
    }
}

/// After a restart the store is opened again, with the custody of its first start: the same
/// columns, and the `cgc_set_slot` it was first given, which the Status floor follows.
#[tokio::test]
async fn a_service_opened_again_keeps_its_custody() {
    let dir = tempfile::tempdir().unwrap();
    let net = devnet();
    let first =
        ProbeService::<Minimal, Valid>::open(&net, plan(dir.path(), 40), &mut Registry::default())
            .unwrap();
    let columns = first.custody_columns().to_vec();
    assert_eq!(columns.len(), 4, "4 custody groups of one column each");
    assert_eq!(first.custody_group_count(), 4);
    assert_eq!(first.cgc_set_slot(), 40);
    assert_eq!(first.status_floor().unwrap(), 40);
    drop(first);
    let again =
        ProbeService::<Minimal, Valid>::open(&net, plan(dir.path(), 900), &mut Registry::default())
            .unwrap();
    assert_eq!(again.custody_columns(), columns);
    assert_eq!(again.cgc_set_slot(), 40);
    assert_eq!(again.status_floor().unwrap(), 40);
    assert_eq!(again.earliest_available_slot(), None);
    // While one runs, a second one cannot open the store.
    let second =
        ProbeService::<Minimal, Valid>::open(&net, plan(dir.path(), 900), &mut Registry::default());
    assert!(second.is_err());
}

/// A column sidecar is handed to the store only on the topic of its slot's digest, and only
/// a Gloas one; another digest is dropped before it is decoded.
#[tokio::test]
async fn a_column_needs_the_digest_of_its_slot() {
    let dir = tempfile::tempdir().unwrap();
    let net = devnet();
    let service =
        ProbeService::<Minimal, Valid>::open(&net, plan(dir.path(), 0), &mut Registry::default())
            .unwrap();
    let gloas = p2p_wire::testkit::gloas_sidecar::<Minimal>(24, 3).as_ssz_bytes();
    let d = |e| net.digest_at(e).unwrap();
    assert!(service.accept_column(d(3), 3, &gloas));
    assert!(!service.accept_column(d(0), 3, &gloas));
    let fulu = p2p_wire::testkit::fulu_sidecar::<Minimal>(1, 3).as_ssz_bytes();
    assert!(!service.accept_column(d(0), 3, &fulu));
    assert!(!service.accept_column(d(3), 3, &[1, 2, 3]));
    // Through the hand-off of Validate: the envelope's slot must be the sidecar's own.
    let hand_off = service.column_hand_off();
    let column = |slot, fork_digest, ssz| GossipColumnBytes {
        fork_digest,
        slot,
        subnet_id: 3,
        ssz,
    };
    assert_eq!(
        hand_off.hand_over(column(24, d(3), &gloas)),
        HandOff::Stored
    );
    assert_eq!(
        hand_off.hand_over(column(8, d(1), &gloas)),
        HandOff::Dropped("probe: IGNORE: the sidecar's slot is not its envelope's")
    );
    assert!(matches!(
        hand_off.hand_over(column(24, d(0), &gloas)),
        HandOff::Dropped(_)
    ));
    assert!(matches!(
        hand_off.hand_over(column(1, d(0), &fulu)),
        HandOff::Dropped(_)
    ));
    // From the stop on, nothing more is handed over, so no hand-off holds the store open.
    service.stream_stop().end_streams();
    assert_eq!(
        hand_off.hand_over(column(24, d(3), &gloas)),
        HandOff::Dropped("probe: IGNORE: cl-chain is stopping")
    );
    // Once the service is gone, the hand-off holds no store: nothing more is handed over.
    drop(service);
    assert_eq!(
        hand_off.hand_over(column(24, d(3), &gloas)),
        HandOff::Dropped("probe: IGNORE: cl-chain is stopping")
    );
}

/// The routes serve `WatchSubscriptions` from the custody, not the stub.
#[tokio::test]
async fn the_routes_serve_the_custody_subscriptions() {
    use pb::gossip_service_client::GossipServiceClient;
    let dir = tempfile::tempdir().unwrap();
    let net = devnet();
    let service =
        ProbeService::<Minimal, Valid>::open(&net, plan(dir.path(), 0), &mut Registry::default())
            .unwrap();
    let socket = dir.path().join("chain.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let stop = service.stream_stop();
    let (done, finished) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(ipc::stub::serve_uds(listener, service.routes(), async {
        let _ = finished.await;
    }));
    let channel = ipc::uds::connect_path(&socket, ipc::uds::Ownership::current().uid)
        .await
        .unwrap();
    let mut client = GossipServiceClient::new(channel);
    let mut stream = client
        .watch_subscriptions(watch_request(service.link()))
        .await
        .unwrap()
        .into_inner();
    assert!(stream.message().await.unwrap().is_some(), "our hello");
    match stream.message().await.unwrap().and_then(|m| m.frame) {
        Some(pb::watch_subscriptions_response::Frame::Body(body)) => {
            assert_eq!(body.custody_columns, service.custody_columns());
        }
        other => panic!("a body, got {other:?}"),
    }
    stop.end_streams();
    assert_eq!(
        stream.message().await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
    let _ = done.send(());
    server.await.unwrap().unwrap();
}

/// At most [`MAX_WATCHERS`] `WatchSubscriptions` streams are open at once; one more is
/// `RESOURCE_EXHAUSTED`, and a place comes back when a stream ends.
#[tokio::test]
async fn the_open_watch_streams_are_bounded() {
    let net = devnet();
    let link = chain_link::<Minimal>(&net, epoch_ms(3)).unwrap();
    let (_stop, stopped) = watch::channel(false);
    let server = GossipServer::new(
        link.clone(),
        Subscriptions::new(&net, vec![3]),
        Arc::new(move || epoch_ms(3)),
        stopped,
    );
    let mut open = Vec::new();
    for _ in 0..MAX_WATCHERS {
        let mut stream = server
            .watch_subscriptions(watch_request(&link))
            .await
            .unwrap()
            .into_inner();
        assert!(stream.next().await.unwrap().is_ok(), "the hello");
        open.push(stream);
    }
    let refused = server
        .watch_subscriptions(watch_request(&link))
        .await
        .err()
        .expect("refused");
    assert_eq!(refused.code(), tonic::Code::ResourceExhausted);
    drop(open.pop());
    let by = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if server
            .watch_subscriptions(watch_request(&link))
            .await
            .is_ok()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < by,
            "the place never came back"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The store keeps the node ID of its first open ([`NODE_ID_FILE`], mode 0600). Opened again
/// with the same one it goes on; with another one it is refused, with a message that tells the
/// operator to clear the store.
#[tokio::test]
async fn a_store_keeps_the_node_id_of_its_first_open() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let net = devnet();
    let open = |node: u64| {
        let mut p = plan(dir.path(), 40);
        p.node_id = U256::from(node);
        ProbeService::<Minimal, Valid>::open(&net, p, &mut Registry::default())
    };
    drop(open(7).unwrap());
    let marker = dir.path().join(NODE_ID_FILE);
    let mode = std::fs::metadata(&marker).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600);
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap().trim(),
        format!("0x{}07", "00".repeat(31))
    );
    drop(open(7).unwrap());
    match open(9) {
        Err(e @ OpenError::NodeIdChanged { .. }) => {
            let text = e.to_string();
            assert!(text.contains("clear the store"), "{text}");
            assert!(text.contains(&format!("0x{}07", "00".repeat(31))), "{text}");
        }
        other => panic!("refused, got {:?}", other.err()),
    }
    // A marker that is not a node ID: refused, never overwritten.
    std::fs::write(&marker, "nonsense").unwrap();
    assert!(matches!(open(7), Err(OpenError::Failed(_))));
    // A symlink in its place: refused.
    std::fs::remove_file(&marker).unwrap();
    std::os::unix::fs::symlink("/etc/hosts", &marker).unwrap();
    assert!(matches!(open(7), Err(OpenError::Failed(_))));
}

/// cl-chain's link follows the clock: a caller that starts after a fork or BPO digest change
/// sends the new digest, and the server that started before the change accepts it. A caller
/// still on the old digest is a version mismatch.
#[tokio::test]
async fn a_caller_that_starts_after_a_digest_change_is_accepted() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let net = devnet();
    let now = Arc::new(AtomicU64::new(u64::try_from(epoch_ms(0)).unwrap()));
    let clock: ipc::hello::Clock = {
        let now = Arc::clone(&now);
        Arc::new(move || u128::from(now.load(Ordering::SeqCst)))
    };
    let link = chain_link_on::<Minimal>(&net, Arc::clone(&clock)).unwrap();
    let (_stop, stopped) = watch::channel(false);
    let server = GossipServer::new(link, Subscriptions::new(&net, vec![3]), clock, stopped);
    let hello_at = |ms: u128| net.hello().at(ms).unwrap();
    let ask = |hello| {
        server.watch_subscriptions(Request::new(pb::WatchSubscriptionsRequest {
            hello: Some(hello),
        }))
    };
    assert!(ask(hello_at(epoch_ms(0))).await.is_ok());
    // The clock passes the changes at epochs 1 and 2; a caller starts now.
    now.store(u64::try_from(epoch_ms(2)).unwrap() + 1, Ordering::SeqCst);
    assert!(ask(hello_at(epoch_ms(2))).await.is_ok());
    let stale = ask(hello_at(epoch_ms(0))).await.err().expect("refused");
    assert_eq!(
        ipc::ContractError::from_status(&stale).code(),
        ErrorCode::VersionMismatch
    );
}

/// A store of an older build has a custody record but no node-ID marker: its custody follows a
/// node ID nobody recorded, so it is refused (with the message to clear the store), never
/// taken as this node ID's.
#[tokio::test]
async fn a_store_without_its_node_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let net = devnet();
    let open = || {
        ProbeService::<Minimal, Valid>::open(&net, plan(dir.path(), 40), &mut Registry::default())
    };
    drop(open().unwrap());
    std::fs::remove_file(dir.path().join(NODE_ID_FILE)).unwrap();
    match open() {
        Err(e @ OpenError::NodeIdUnknown { .. }) => {
            assert!(e.to_string().contains("clear the store"), "{e}");
        }
        other => panic!("refused, got {:?}", other.err()),
    }
    assert!(!dir.path().join(NODE_ID_FILE).exists(), "nothing written");
}

/// The cl-verify directory's check tells apart what a wait can fix from what it cannot: a
/// directory not there yet under closed directories, or one that another user still owns
/// (systemd makes it, then gives it to its user), is retried; an ancestor that others can
/// write is refused at once, whether or not the directory under it is there.
#[test]
fn the_verify_dir_check_tells_apart_what_a_wait_can_fix() {
    use std::os::unix::fs::PermissionsExt;
    let uid = ipc::uds::Ownership::current().uid;
    let root = closed_tempdir();
    let sock = |dir: &str| root.path().join(dir).join("cl-verify.sock");
    // Not there yet, under closed directories.
    assert!(matches!(
        verify_dir_state(&sock("absent"), uid),
        Err(VerifyDirError::Missing(_))
    ));
    // Not there, under a directory that others can write: refused.
    let open = root.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        verify_dir_state(&sock("open/absent"), uid),
        Err(VerifyDirError::Refused(_))
    ));
    // There, closed, and ours.
    let ours = root.path().join("verify");
    std::fs::create_dir(&ours).unwrap();
    std::fs::set_permissions(&ours, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(verify_dir_state(&sock("verify"), uid).is_ok());
    // There and closed, but of another user than cl-verify's: retried.
    assert!(matches!(
        verify_dir_state(&sock("verify"), uid + 1),
        Err(VerifyDirError::Owner(_))
    ));
    // There, but writable by the group: refused.
    std::fs::set_permissions(&ours, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        verify_dir_state(&sock("verify"), uid),
        Err(VerifyDirError::Refused(_))
    ));
}

/// The service closes its store only once no hand-off holds it, so the store closes within the
/// drop that `close_within` times.
#[tokio::test(flavor = "multi_thread")]
async fn the_store_closes_only_once_no_hand_off_holds_it() {
    let dir = tempfile::tempdir().unwrap();
    let net = devnet();
    let service =
        ProbeService::<Minimal, Valid>::open(&net, plan(dir.path(), 0), &mut Registry::default())
            .unwrap();
    // As a hand-off in the middle of a column holds it.
    let held = Arc::clone(&service.ingest);
    let (done, closed) = std::sync::mpsc::channel();
    let dropper = std::thread::spawn(move || {
        drop(service);
        done.send(()).unwrap();
    });
    assert!(
        closed.recv_timeout(Duration::from_millis(300)).is_err(),
        "the service went while a hand-off held its store"
    );
    drop(held);
    closed.recv_timeout(Duration::from_secs(30)).unwrap();
    dropper.join().unwrap();
}
