//! `FindPeers` by subnet and custody column, through the public API: the predicate a lookup runs
//! (`SubnetQuery::matches`, ANDed with the fork and IP filter by `service::lookup_predicate`),
//! and the RPC over a fake discv5 ([`Lookups`]: a gate the test opens, counted lookups) on a
//! paused tokio clock and a fake slot clock.
//!
//! The vectors of the custody tests come from `das::custody_columns` of each record's node ID,
//! so every record (a fresh random key) is checked against its own custody.

use alloy_rlp::Bytes;
use cl_discv5::enr::{CombinedKey, Enr};
use cl_discv5::server::{DiscoveryServer, PeerFeed, PeerSource};
use cl_discv5::service::{lookup_predicate, NetworkMode, PeerFilter, ServiceError};
use cl_discv5::subnet_query::{SubnetQuery, MAX_CACHE_ENTRIES, MAX_CONCURRENT_LOOKUPS, MAX_TARGET};
use consensus_types::das::{self, CUSTODY_REQUIREMENT, NUMBER_OF_COLUMNS};
use consensus_types::primitives::U256;
use ethswarm_proto::discv5 as pb;
use ipc::testkit::devnet::{devnet_config, devnet_hello, DEVNET_GENESIS};
use ipc::Link;
use p2p_wire::enr::ForkFields;
use p2p_wire::rpc::messages::ForkDigest;
use pb::discovery_service_server::DiscoveryService;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_stream::StreamExt;
use tonic::{Code, Request, Status};

/// Our fork fields: the devnet's at epoch 3.
fn fork() -> ForkFields {
    ForkFields::from_schedule(&devnet_config(), &DEVNET_GENESIS.genesis_validators_root, 3).unwrap()
}

/// A dialable record on `fork` (none: no `eth2`) with the extra raw values, signed by a new key.
fn record(fork: Option<&ForkFields>, extra: &[(&str, &[u8])]) -> Enr {
    let key = CombinedKey::generate_secp256k1();
    let mut builder = Enr::builder();
    builder
        .ip4(Ipv4Addr::new(10, 0, 0, 2))
        .tcp4(9000)
        .udp4(9000);
    if let Some(fork) = fork {
        builder.add_value("eth2", &Bytes::from(fork.eth2.to_bytes().to_vec()));
    }
    for (k, v) in extra {
        builder.add_value(*k, &Bytes::copy_from_slice(v));
    }
    builder.build(&key).unwrap()
}

/// The request for these subnets and columns, on our fork.
fn request(attnets: &[u32], syncnets: &[u32], columns: &[u64]) -> pb::FindPeersRequest {
    pb::FindPeersRequest {
        attnets: attnets.to_vec(),
        syncnets: syncnets.to_vec(),
        custody_columns: columns.to_vec(),
        target: 4,
        fork_digest: Vec::new(),
        hello: None,
    }
}

fn query(attnets: &[u32], syncnets: &[u32], columns: &[u64]) -> SubnetQuery {
    let (query, _) = SubnetQuery::parse(
        &request(attnets, syncnets, columns),
        fork().eth2.fork_digest,
    )
    .unwrap();
    query
}

/// The custody columns of `enr` at `cgc`, by the spec helper.
fn custody(enr: &Enr, cgc: u64) -> Vec<u64> {
    das::custody_columns(U256::from_be_bytes(enr.node_id().raw()), cgc).unwrap()
}

fn columns(columns: &[u64]) -> SubnetQuery {
    query(&[], &[], columns)
}

/// A record matches a wanted column of its custody (node ID and `cgc`), and not one outside it;
/// the `cgc` it advertises is read, not assumed.
#[test]
fn predicate_matches_custody() {
    let enr = record(Some(&fork()), &[("cgc", &[8])]);
    let mine = custody(&enr, 8);
    assert_eq!(mine.len(), 8);
    let outside = (0..NUMBER_OF_COLUMNS).find(|c| !mine.contains(c)).unwrap();
    for column in &mine {
        assert!(columns(&[*column]).matches(&enr), "column {column}");
    }
    assert!(!columns(&[outside]).matches(&enr));
    // ANY: one served column among unserved ones is a match.
    assert!(columns(&[outside, mine[3]]).matches(&enr));
    // A column of its 8-group custody that a 4-group custody would not have.
    let beyond = custody(&enr, 4);
    let beyond = mine.iter().find(|c| !beyond.contains(c)).unwrap();
    assert!(columns(&[*beyond]).matches(&enr));
    assert_eq!(columns(&mine).coverage(&enr), 8);
    assert_eq!(columns(&[outside, mine[0], mine[1]]).coverage(&enr), 2);
}

/// A record matches a wanted attestation subnet whose `attnets` bit it sets; an unset bit, no
/// `attnets` at all or a malformed one is no match.
#[test]
fn predicate_matches_attnets() {
    // Subnets 5 and 63: byte 0 bit 5, byte 7 bit 7.
    let enr = record(
        Some(&fork()),
        &[("attnets", &[0b0010_0000, 0, 0, 0, 0, 0, 0, 0b1000_0000])],
    );
    assert!(query(&[5], &[], &[]).matches(&enr));
    assert!(query(&[63], &[], &[]).matches(&enr));
    assert!(!query(&[6], &[], &[]).matches(&enr));
    assert!(query(&[6, 5], &[], &[]).matches(&enr));
    assert_eq!(query(&[5, 6, 63], &[], &[]).coverage(&enr), 2);
    assert!(!query(&[5], &[], &[]).matches(&record(Some(&fork()), &[])));
    let malformed = record(Some(&fork()), &[("attnets", &[0xff; 7])]);
    assert!(!query(&[5], &[], &[]).matches(&malformed));
}

/// The same for `syncnets`; a `syncnets` with a bit past subnet 3 refuses the record.
#[test]
fn predicate_matches_syncnets() {
    let enr = record(Some(&fork()), &[("syncnets", &[0b0100])]);
    assert!(query(&[], &[2], &[]).matches(&enr));
    assert!(!query(&[], &[1], &[]).matches(&enr));
    assert!(!query(&[], &[2], &[]).matches(&record(Some(&fork()), &[])));
    let stray = record(
        Some(&fork()),
        &[
            ("syncnets", &[0b1_0100]),
            ("attnets", &[1, 0, 0, 0, 0, 0, 0, 0]),
        ],
    );
    assert!(!query(&[0], &[2], &[]).matches(&stray));
    // Kinds mix: a syncnet it serves matches a query that also wants an attnet it does not.
    assert!(query(&[9], &[2], &[]).matches(&enr));
}

/// No `cgc`: judged at `CUSTODY_REQUIREMENT` (4), the custody every honest node has
/// (`fulu/das-core.md`: the extended list makes 4 a correct subset of any larger custody). A
/// `cgc` below 4 is taken as advertised; one above `NUMBER_OF_CUSTODY_GROUPS`, or not in its
/// canonical form, refuses the record for every kind.
#[test]
fn cgc_absent_default() {
    let enr = record(Some(&fork()), &[]);
    let four = custody(&enr, CUSTODY_REQUIREMENT);
    assert_eq!(four.len(), 4);
    for column in &four {
        assert!(columns(&[*column]).matches(&enr), "column {column}");
    }
    let outside = (0..NUMBER_OF_COLUMNS).find(|c| !four.contains(c)).unwrap();
    assert!(!columns(&[outside]).matches(&enr));

    let two = record(Some(&fork()), &[("cgc", &[2])]);
    let served = custody(&two, 2);
    let unserved = custody(&two, 4);
    let unserved = unserved.iter().find(|c| !served.contains(c)).unwrap();
    assert!(columns(&served).matches(&two));
    assert!(!columns(&[*unserved]).matches(&two));

    let attnet_0: &[u8] = &[1, 0, 0, 0, 0, 0, 0, 0];
    for cgc in [&[129][..], &[0xff; 8], &[0, 4], &[1; 9]] {
        let enr = record(Some(&fork()), &[("cgc", cgc), ("attnets", attnet_0)]);
        let all: Vec<u64> = (0..NUMBER_OF_COLUMNS).collect();
        assert!(!columns(&all).matches(&enr), "cgc {cgc:?}");
        assert!(!query(&[0], &[], &[]).matches(&enr), "cgc {cgc:?}");
    }
}

/// A present, empty `cgc` is 0 (`fulu/p2p-interface.md`: 0 is the empty byte string): the
/// record custodies no column and matches no column query, not even one of the four a missing
/// `cgc` would give it; its subnets still match.
#[test]
fn cgc_empty_is_zero() {
    let enr = record(
        Some(&fork()),
        &[("cgc", &[]), ("attnets", &[1, 0, 0, 0, 0, 0, 0, 0])],
    );
    let all: Vec<u64> = (0..NUMBER_OF_COLUMNS).collect();
    assert!(!columns(&all).matches(&enr));
    assert!(!columns(&custody(&enr, CUSTODY_REQUIREMENT)).matches(&enr));
    assert!(query(&[0], &[], &[]).matches(&enr));
}

/// A record that serves what is wanted but is on another fork digest, or has no `eth2`, fails the
/// lookup's predicate (the fork filter ANDed with the query); a request for another fork digest
/// is refused with `FAILED_PRECONDITION`, and an empty one means ours.
#[test]
fn fork_digest_filtered() {
    let ours = fork();
    let mut other = fork();
    other.eth2.fork_digest = [0xde, 0xad, 0xbe, 0xef];
    let filter = PeerFilter {
        fork_digest: ours.eth2.fork_digest,
        previous: None,
        mode: NetworkMode::Devnet,
    };
    let attnet_0: &[u8] = &[1, 0, 0, 0, 0, 0, 0, 0];
    let wanted = query(&[0], &[], &[]);
    let predicate = lookup_predicate(filter, move |enr: &Enr| wanted.matches(enr));
    let on = record(Some(&ours), &[("attnets", attnet_0)]);
    let off = record(Some(&other), &[("attnets", attnet_0)]);
    let none = record(None, &[("attnets", attnet_0)]);
    assert!(predicate(&on));
    assert!(!predicate(&off));
    assert!(!predicate(&none));
    // Our fork, but nothing wanted.
    assert!(!predicate(&record(Some(&ours), &[])));

    let digest = ours.eth2.fork_digest;
    let with = |fork_digest: Vec<u8>| pb::FindPeersRequest {
        fork_digest,
        ..request(&[0], &[], &[])
    };
    let refused = SubnetQuery::parse(&with(other.eth2.fork_digest.to_vec()), digest).unwrap_err();
    assert_eq!(
        tonic::Status::from(refused).code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        SubnetQuery::parse(&with(Vec::new()), digest).unwrap().0,
        wanted
    );
    assert_eq!(
        SubnetQuery::parse(&with(digest.to_vec()), digest)
            .unwrap()
            .0,
        wanted
    );
}

/// discv5 as the server reads it: a lookup finds every record of `records` that the query
/// matches (all of them, whatever `max` it is asked for), once `open` is true. It counts the
/// lookups, the most that ran at once and the `max` each was asked for.
struct Lookups {
    local: Enr,
    records: Vec<Enr>,
    digest: Mutex<ForkDigest>,
    open: watch::Receiver<bool>,
    started: AtomicUsize,
    running: AtomicUsize,
    most: AtomicUsize,
    asked: Mutex<Vec<usize>>,
}

impl Lookups {
    fn new(records: Vec<Enr>, open: watch::Receiver<bool>) -> Arc<Self> {
        Arc::new(Self {
            local: record(Some(&fork()), &[]),
            records,
            digest: Mutex::new(fork().eth2.fork_digest),
            open,
            started: AtomicUsize::new(0),
            running: AtomicUsize::new(0),
            most: AtomicUsize::new(0),
            asked: Mutex::new(Vec::new()),
        })
    }

    fn started(&self) -> usize {
        self.started.load(SeqCst)
    }
}

impl PeerSource for Lookups {
    fn local_enr(&self) -> Enr {
        self.local.clone()
    }

    fn table_records(&self) -> Vec<Enr> {
        Vec::new()
    }

    fn fork_digest(&self) -> ForkDigest {
        *self.digest.lock().unwrap()
    }

    async fn find_matching(
        &self,
        query: SubnetQuery,
        max: usize,
    ) -> Result<Vec<Enr>, ServiceError> {
        self.started.fetch_add(1, SeqCst);
        let running = self.running.fetch_add(1, SeqCst) + 1;
        self.most.fetch_max(running, SeqCst);
        self.asked.lock().unwrap().push(max);
        let mut open = self.open.clone();
        let _ = open.wait_for(|open| *open).await;
        self.running.fetch_sub(1, SeqCst);
        Ok(self
            .records
            .iter()
            .filter(|enr| query.matches(enr))
            .cloned()
            .collect())
    }
}

/// The server over `lookups` at the slot `slot` holds, its link and its stop.
fn serve(
    lookups: &Arc<Lookups>,
    slot: &Arc<AtomicU64>,
) -> (DiscoveryServer<Lookups>, Link, watch::Sender<bool>) {
    let link = Link::network(Arc::new(devnet_hello("cl-discv5/test")), 1).unwrap();
    let (stop, stopped) = watch::channel(false);
    let slot = Arc::clone(slot);
    let server = DiscoveryServer::new(
        link.clone(),
        Arc::clone(lookups),
        PeerFeed::default(),
        stopped,
        Arc::new(move || slot.load(SeqCst)),
    );
    (server, link, stop)
}

fn find(
    attnets: &[u32],
    syncnets: &[u32],
    target: u32,
    link: &Link,
) -> Request<pb::FindPeersRequest> {
    Request::new(pb::FindPeersRequest {
        target,
        hello: Some(link.local()),
        ..request(attnets, syncnets, &[])
    })
}

type Frames = std::pin::Pin<
    Box<dyn tokio_stream::Stream<Item = Result<pb::FindPeersResponse, Status>> + Send>,
>;

/// The stream of `request`, its hello read.
async fn opened(
    server: &DiscoveryServer<Lookups>,
    request: Request<pb::FindPeersRequest>,
) -> Frames {
    let mut stream = server.find_peers(request).await.unwrap().into_inner();
    let hello = stream.next().await.unwrap().unwrap().frame;
    assert!(
        matches!(hello, Some(pb::find_peers_response::Frame::Hello(_))),
        "{hello:?}"
    );
    stream
}

/// The candidates' records, to the end of the stream.
async fn candidates(stream: &mut Frames) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(frame) = stream.next().await {
        match frame.unwrap().frame {
            Some(pb::find_peers_response::Frame::Body(body)) => {
                out.push(body.candidate.unwrap().enr.unwrap().text);
            }
            other => panic!("a body, got {other:?}"),
        }
    }
    out
}

/// Every subnet bit set: every attnet and syncnet query matches.
fn everywhere() -> Enr {
    record(
        Some(&fork()),
        &[("attnets", &[0xff; 8]), ("syncnets", &[0x0f])],
    )
}

/// `target` 0 is refused and a larger one is capped at 16; at most two lookups run at once,
/// and a third waits for one until its deadline passes (`DEADLINE_EXCEEDED`), or, without one,
/// until a lookup ends; a repeat in the same slot (and on the same fork digest) is served from
/// the cache, without a lookup; the next slot, or another fork digest, looks up again; and the
/// cache holds at most 64 queries a slot, dropping the oldest first.
#[tokio::test(start_paused = true)]
async fn query_bounded() {
    let (open, gate) = watch::channel(false);
    let lookups = Lookups::new((0..20).map(|_| everywhere()).collect(), gate);
    let slot = Arc::new(AtomicU64::new(7));
    let (server, link, _stop) = serve(&lookups, &slot);

    let refused = server.find_peers(find(&[0], &[], 0, &link)).await.err();
    assert_eq!(refused.map(|s| s.code()), Some(Code::InvalidArgument));

    let mut first = opened(&server, find(&[1], &[], 100, &link)).await;
    let mut second = opened(&server, find(&[2], &[], 1, &link)).await;
    assert_eq!(lookups.started(), 2);
    let mut late = find(&[3], &[], 1, &link);
    late.set_timeout(Duration::from_secs(2));
    let since = Instant::now();
    let mut third = opened(&server, late).await;
    let refused = third.next().await.unwrap().unwrap_err();
    assert_eq!(refused.code(), Code::DeadlineExceeded, "{refused:?}");
    assert_eq!(since.elapsed(), Duration::from_secs(2));
    assert!(third.next().await.is_none());
    assert_eq!(lookups.started(), 2);
    let mut fourth = opened(&server, find(&[4], &[], 1, &link)).await;
    assert_eq!(lookups.started(), 2);

    open.send_replace(true);
    assert_eq!(candidates(&mut first).await.len(), MAX_TARGET);
    assert_eq!(candidates(&mut second).await.len(), 1);
    assert_eq!(candidates(&mut fourth).await.len(), 1);
    assert_eq!(lookups.started(), 3);
    assert_eq!(lookups.most.load(SeqCst), MAX_CONCURRENT_LOOKUPS);
    assert_eq!(MAX_CONCURRENT_LOOKUPS, 2);
    assert!(lookups
        .asked
        .lock()
        .unwrap()
        .iter()
        .all(|&max| max == MAX_TARGET));

    let mut again = opened(&server, find(&[1], &[], 100, &link)).await;
    assert_eq!(candidates(&mut again).await.len(), MAX_TARGET);
    assert_eq!(lookups.started(), 3, "same slot: from the cache");
    slot.store(8, SeqCst);
    let mut again = opened(&server, find(&[1], &[], 100, &link)).await;
    assert_eq!(candidates(&mut again).await.len(), MAX_TARGET);
    assert_eq!(lookups.started(), 4, "next slot: a lookup");
    *lookups.digest.lock().unwrap() = [9; 4];
    let mut again = opened(&server, find(&[1], &[], 100, &link)).await;
    assert_eq!(candidates(&mut again).await.len(), MAX_TARGET);
    assert_eq!(lookups.started(), 5, "another fork digest: a lookup");

    slot.store(9, SeqCst);
    assert_eq!(MAX_CACHE_ENTRIES, 64);
    let queries: Vec<(Vec<u32>, Vec<u32>)> = (0..64)
        .map(|attnet| (vec![attnet], vec![]))
        .chain([(vec![], vec![0])])
        .collect();
    let run = |(attnets, syncnets): &(Vec<u32>, Vec<u32>)| {
        let request = find(attnets, syncnets, 1, &link);
        let server = &server;
        async move { candidates(&mut opened(server, request).await).await.len() }
    };
    let before = lookups.started();
    for query in &queries {
        assert_eq!(run(query).await, 1);
    }
    assert_eq!(lookups.started(), before + 65);
    for query in &queries[1..] {
        assert_eq!(run(query).await, 1);
    }
    assert_eq!(lookups.started(), before + 65, "the newest 64 are cached");
    assert_eq!(run(&queries[0]).await, 1);
    assert_eq!(lookups.started(), before + 66, "the oldest was dropped");
}

/// Peers come most-covering first: the number of wanted subnets and columns each serves, kinds
/// mixed; ties in node ID order. The target takes the first ones.
#[tokio::test(start_paused = true)]
async fn results_ranked_by_coverage() {
    let attnets = |bits: u64| bits.to_le_bytes();
    let one_a = record(Some(&fork()), &[("attnets", &attnets(0b001))]);
    let one_b = record(Some(&fork()), &[("attnets", &attnets(0b100))]);
    let two = record(Some(&fork()), &[("attnets", &attnets(0b110))]);
    let three_a = record(Some(&fork()), &[("attnets", &attnets(0b111))]);
    let three_b = record(
        Some(&fork()),
        &[("attnets", &attnets(0b110)), ("syncnets", &[0b1])],
    );
    let unwanted = record(Some(&fork()), &[("attnets", &attnets(0b1000))]);
    let by_id = |a: &Enr, b: &Enr| {
        if a.node_id().raw() < b.node_id().raw() {
            [a.clone(), b.clone()]
        } else {
            [b.clone(), a.clone()]
        }
    };
    let mut want: Vec<Enr> = by_id(&three_a, &three_b).to_vec();
    want.push(two.clone());
    want.extend(by_id(&one_a, &one_b));
    let want: Vec<String> = want.iter().map(Enr::to_base64).collect();

    let (_open, gate) = watch::channel(true);
    let lookups = Lookups::new(vec![one_a, unwanted, two, three_b, one_b, three_a], gate);
    let slot = Arc::new(AtomicU64::new(1));
    let (server, link, _stop) = serve(&lookups, &slot);
    let wanted = |target| find(&[0, 1, 2], &[0], target, &link);
    assert_eq!(
        candidates(&mut opened(&server, wanted(16)).await).await,
        want
    );
    assert_eq!(
        candidates(&mut opened(&server, wanted(2)).await).await,
        want[..2]
    );
    assert_eq!(lookups.started(), 1);
}
