//! `ethswarm.store.v1` `StoreService` over a [`Reader`].

use std::{sync::Arc, time::Duration};

use ethswarm_proto::store as pb;
use ipc::{
    acl::{AclError, MethodAcl},
    Link,
};
use pb::store_service_server::{StoreService, StoreServiceServer};
use tonic::service::Routes;

use crate::reader::{system_clock, Clock, Reader};

/// The callers of every `StoreService` method.
pub const CALLERS: [&str; 3] = ["cl-api", "cl-sync", "cl-p2p"];

/// Every `StoreService` method.
pub const METHODS: [&str; 8] = [
    "/ethswarm.store.v1.StoreService/GetBlock",
    "/ethswarm.store.v1.StoreService/GetState",
    "/ethswarm.store.v1.StoreService/GetDataColumns",
    "/ethswarm.store.v1.StoreService/GetPayloadEnvelope",
    "/ethswarm.store.v1.StoreService/GetBlocksByRange",
    "/ethswarm.store.v1.StoreService/GetDataColumnsByRange",
    "/ethswarm.store.v1.StoreService/GetChainHead",
    "/ethswarm.store.v1.StoreService/GetBlocksByHead",
];

/// The UIDs of the [`CALLERS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Callers {
    pub api: u32,
    pub sync: u32,
    pub p2p: u32,
}

/// cl-store's method ACL: every method to cl-api, cl-sync and cl-p2p, nobody else.
///
/// # Errors
///
/// The ACL does not load.
pub fn store_acl(callers: Callers) -> Result<MethodAcl, AclError> {
    let _ = callers;
    Err(AclError::Empty {
        service: "cl-store".into(),
    })
}

/// How long one call's reads may take, unless [`StoreServer::with_timeout`] says otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// The `StoreService`.
#[derive(Clone)]
pub struct StoreServer {
    link: Link,
    reader: Arc<Reader>,
    timeout: Duration,
    clock: Clock,
}

impl StoreServer {
    #[must_use]
    pub fn new(link: Link, reader: Arc<Reader>) -> Self {
        Self {
            link,
            reader,
            timeout: DEFAULT_TIMEOUT,
            clock: system_clock(),
        }
    }

    /// The same server with another per-call deadline.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The contract configuration every RPC is checked against.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Every `ethswarm.store.v1` service, ready to serve.
    #[must_use]
    pub fn routes(self) -> Routes {
        Routes::new(StoreServiceServer::new(self))
    }
}

ipc::stub_service!(StoreServer => StoreService {
    unary: [
        get_block(pb::GetBlockRequest) -> pb::GetBlockResponse,
        get_state(pb::GetStateRequest) -> pb::GetStateResponse,
        get_payload_envelope(pb::GetPayloadEnvelopeRequest) -> pb::GetPayloadEnvelopeResponse,
        get_chain_head(pb::GetChainHeadRequest) -> pb::GetChainHeadResponse,
    ],
    unary_envelopes: [
    ],
    server_stream: [
        get_data_columns(pb::GetDataColumnsRequest) -> pb::GetDataColumnsResponse as GetDataColumnsStream,
        get_blocks_by_range(pb::GetBlocksByRangeRequest) -> pb::GetBlocksByRangeResponse as GetBlocksByRangeStream,
        get_data_columns_by_range(pb::GetDataColumnsByRangeRequest) -> pb::GetDataColumnsByRangeResponse as GetDataColumnsByRangeStream,
        get_blocks_by_head(pb::GetBlocksByHeadRequest) -> pb::GetBlocksByHeadResponse as GetBlocksByHeadStream,
    ],
    bidi: [
    ],
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        reader::{Root, Stamp},
        stamp::StoreReader,
        testkit::{block, stamp, Store},
    };
    use ethswarm_proto::common::{ErrorCode, PayloadType};
    use ipc::{
        frame::{Frame, InFrame},
        testkit::{fixture, own_cred, probe::call_unary_empty, surface::surface, Mode, Server},
    };
    use network_config::ForkName;
    use pb::{store_service_client::StoreServiceClient, ReadMeta};
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicUsize, Ordering},
        time::Instant,
    };
    use tonic::Code;

    /// One stored block of a test chain.
    #[derive(Clone)]
    struct Stored {
        slot: u64,
        root: Root,
        ssz: Vec<u8>,
    }

    /// The first Fulu slot of the fixture link's schedule (Sepolia, mainnet preset): every
    /// test block is at or after it, so its fork digest is Fulu's.
    fn fulu_start() -> u64 {
        fixture::sepolia_schedule()
            .fork_epoch(ForkName::Fulu)
            .unwrap()
            * fixture::SLOTS_PER_EPOCH
    }

    /// `n` blocks, each on the one before, from the Fulu start, one per slot but the 6th slot
    /// skipped.
    fn chain(n: u64) -> Vec<Stored> {
        let mut blocks: Vec<Stored> = Vec::new();
        for i in 0..n {
            let slot = fulu_start() + i + u64::from(i >= 5);
            let parent = blocks.last().map_or([0; 32], |b| b.root);
            let (ssz, root) = block(slot, parent, i);
            blocks.push(Stored { slot, root, ssz });
        }
        blocks
    }

    /// The stamp with `head` and `finalized` blocks.
    fn stamp_of(seq: u64, head: &Stored, finalized: &Stored) -> Stamp {
        stamp(
            seq,
            (head.slot, head.root),
            (finalized.slot, finalized.root),
        )
    }

    /// The `ReadMeta` of `stamp`, for a block `finalized` or not.
    fn meta(stamp: &Stamp, finalized: bool) -> Option<ReadMeta> {
        Some(ReadMeta {
            as_of_seq: stamp.head_seq,
            as_of_root: stamp.head_root.to_vec(),
            as_of_slot: stamp.head_slot,
            execution_optimistic: false,
            finalized,
        })
    }

    fn server(store: &Store) -> StoreServer {
        StoreServer::new(fixture::v1_link(), Arc::new(store.reader()))
    }

    /// The contract-checking client of `server`, in process.
    async fn client(server: StoreServer) -> StoreReader<ipc::testkit::Transport> {
        let conn = Mode::InProcess.connect(Server::new(server.routes())).await;
        StoreReader::new(conn.transport.clone(), fixture::v1_link())
    }

    fn by_head(root: &[u8], count: u64) -> pb::GetBlocksByHeadRequest {
        pb::GetBlocksByHeadRequest {
            root: root.to_vec(),
            count,
            hello: None,
        }
    }

    /// `(slot, root, ssz, meta)` of each body.
    fn walked(bodies: &[pb::GetBlocksByHeadResponseBody]) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        bodies
            .iter()
            .map(|b| {
                let block = b.block.as_ref().expect("a block per body");
                assert_eq!(block.payload_type, PayloadType::SignedBeaconBlock as i32);
                (block.slot, block.root.clone(), block.ssz.clone())
            })
            .collect()
    }

    fn want(blocks: &[&Stored]) -> Vec<(u64, Vec<u8>, Vec<u8>)> {
        blocks
            .iter()
            .map(|b| (b.slot, b.root.to_vec(), b.ssz.clone()))
            .collect()
    }

    /// `GetBlocksByHead`: newest first along the parents, every body stamped with the stamp of
    /// the first read; `count` over 128 is served as 128; a parent that is not stored ends the
    /// stream OK; an unknown root gives no body, OK; with no stamp the call is UNAVAILABLE.
    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_by_head_stream() {
        let store = Store::new();
        let blocks = chain(140);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        let (head, fin) = (&blocks[139], &blocks[99]);
        let stamped = stamp_of(1, head, fin);
        store.import(&all, stamped);
        let mut client = client(server(&store)).await;

        let bodies = client
            .get_blocks_by_head(by_head(&head.root, 5))
            .await
            .unwrap();
        let newest: Vec<&Stored> = blocks[135..].iter().rev().collect();
        assert_eq!(walked(&bodies), want(&newest));
        for body in &bodies {
            assert_eq!(body.meta, meta(&stamped, false));
        }

        let bodies = client
            .get_blocks_by_head(by_head(&head.root, 1_000))
            .await
            .unwrap();
        assert_eq!(bodies.len(), 128, "count is clamped to 128");
        let newest: Vec<&Stored> = blocks[12..].iter().rev().collect();
        assert_eq!(walked(&bodies), want(&newest));
        for (body, b) in bodies.iter().zip(&newest) {
            assert_eq!(body.meta, meta(&stamped, b.slot <= fin.slot), "{}", b.slot);
        }

        let from = &blocks[30];
        let bodies = client
            .get_blocks_by_head(by_head(&from.root, 100))
            .await
            .unwrap();
        let down: Vec<&Stored> = blocks[..=30].iter().rev().collect();
        assert_eq!(
            walked(&bodies),
            want(&down),
            "ends at the first unstored parent"
        );

        let none = client
            .get_blocks_by_head(by_head(&[0xee; 32], 10))
            .await
            .unwrap();
        assert!(none.is_empty(), "an unknown root streams no body");

        let short = client.get_blocks_by_head(by_head(&[1; 31], 10)).await;
        assert_eq!(short.unwrap_err().code(), ErrorCode::Invalid);

        let empty = Store::new();
        let err = client_of(&empty)
            .await
            .get_blocks_by_head(by_head(&head.root, 10))
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceUnavailable, "{err}");
    }

    async fn client_of(store: &Store) -> StoreReader<ipc::testkit::Transport> {
        client(server(store)).await
    }

    /// A commit that lands while a `GetBlocksByHead` stream is being read (a new head, a new
    /// stamp) leaves the stream gap-free and without a duplicate: every parent of the root,
    /// once each, all under the first read's stamp. The stream produces at most a body ahead
    /// of the reader, so the commit lands after three bodies and before most reads.
    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_by_head_commit_mid_walk() {
        let store = Store::new();
        let blocks = chain(40);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        let first = stamp_of(1, &blocks[39], &blocks[9]);
        store.import(&all, first);
        let link = fixture::v1_link();
        let conn = Mode::InProcess
            .connect(Server::new(server(&store).routes()))
            .await;
        let mut raw = StoreServiceClient::new(conn.transport.clone());
        let mut stream = raw
            .get_blocks_by_head(pb::GetBlocksByHeadRequest {
                root: blocks[39].root.to_vec(),
                count: 40,
                hello: Some(link.local()),
            })
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(frame(&mut stream).await, Some(Frame::Hello(_))));
        let mut bodies = Vec::new();
        for _ in 0..3 {
            match frame(&mut stream).await {
                Some(Frame::Body(b)) => bodies.push(b),
                other => panic!("{other:?}"),
            }
        }
        // cl-chain commits: five blocks on the head, a new stamp, finality moved.
        let mut parent = blocks[39].root;
        let mut more = Vec::new();
        for i in 0..5 {
            let (ssz, root) = block(blocks[39].slot + 1 + i, parent, 100 + i);
            more.push((ssz, root));
            parent = root;
        }
        let ssz: Vec<&[u8]> = more.iter().map(|(s, _)| s.as_slice()).collect();
        let new_head = Stored {
            slot: blocks[39].slot + 5,
            root: parent,
            ssz: Vec::new(),
        };
        store.import(&ssz, stamp_of(2, &new_head, &blocks[29]));
        while let Some(f) = frame(&mut stream).await {
            match f {
                Frame::Body(b) => bodies.push(b),
                Frame::Hello(h) => panic!("a second hello {h:?}"),
            }
        }

        let down: Vec<&Stored> = blocks.iter().rev().collect();
        assert_eq!(walked(&bodies), want(&down), "no gap, no duplicate");
        let seqs: Vec<u64> = bodies
            .iter()
            .map(|b| b.block.as_ref().unwrap().seq)
            .collect();
        assert_eq!(seqs, (1..=40).collect::<Vec<_>>());
        for (body, b) in bodies.iter().zip(&down) {
            assert_eq!(
                body.meta,
                meta(&first, b.slot <= blocks[9].slot),
                "{}",
                b.slot
            );
        }
        let now = store.reader().head(&crate::testkit::deadline()).unwrap();
        assert_eq!(now.head_seq, 2, "the commit landed");
    }

    /// The next frame of a `GetBlocksByHead` stream, `None` at its end.
    async fn frame(
        stream: &mut tonic::Streaming<pb::GetBlocksByHeadResponse>,
    ) -> Option<Frame<pb::GetBlocksByHeadResponseBody>> {
        let message = stream.message().await.unwrap()?;
        Some(message.into_frame().expect("hello or body"))
    }

    /// A clock that reads `t0` its first `reads` times, then an hour later: time passes once
    /// the call's read txn is open (its first two reads are the call's start and the txn's
    /// open).
    fn late_after(reads: usize) -> Clock {
        let t0 = Instant::now();
        let calls = AtomicUsize::new(0);
        Arc::new(move || {
            if calls.fetch_add(1, Ordering::SeqCst) < reads {
                t0
            } else {
                t0 + Duration::from_secs(3600)
            }
        })
    }

    /// A read txn held past the call's deadline fails the call `DEADLINE_EXCEEDED`, on every
    /// served RPC. The method ACL gives every method of the descriptor to cl-api, cl-sync and
    /// cl-p2p: each of them passes on every method, and any other caller, or one with no
    /// credentials, is refused `PERMISSION_DENIED` before the service sees the call.
    #[tokio::test(flavor = "multi_thread")]
    async fn acl() {
        let store = Store::new();
        let blocks = chain(4);
        let all: Vec<&[u8]> = blocks.iter().map(|b| b.ssz.as_slice()).collect();
        store.import(&all, stamp_of(1, &blocks[3], &blocks[2]));
        let reader = Arc::new(store.reader());
        let late = || {
            StoreServer::new(fixture::v1_link(), Arc::clone(&reader))
                .with_timeout(Duration::from_secs(1))
                .with_clock(late_after(2))
        };
        let head = blocks[3].root.to_vec();
        let block_req = || pb::GetBlockRequest {
            id: Some(pb::BlockId {
                id: Some(pb::block_id::Id::Root(head.clone())),
            }),
        };
        let conn = Mode::InProcess.connect(Server::new(late().routes())).await;
        let status = StoreServiceClient::new(conn.transport.clone())
            .get_block(block_req())
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::DeadlineExceeded, "{status:?}");
        let deadline = ErrorCode::DeadlineExceeded;
        let code = |e: ipc::ContractError| e.code();
        assert_eq!(
            client(late())
                .await
                .get_block(block_req())
                .await
                .map_err(code)
                .err(),
            Some(deadline)
        );
        assert_eq!(
            client(late())
                .await
                .get_chain_head()
                .await
                .map_err(code)
                .err(),
            Some(deadline)
        );
        let range = pb::GetBlocksByRangeRequest {
            start_slot: blocks[0].slot,
            count: 4,
            ..Default::default()
        };
        assert_eq!(
            client(late())
                .await
                .get_blocks_by_range(range)
                .await
                .map_err(code)
                .err(),
            Some(deadline)
        );
        assert_eq!(
            client(late())
                .await
                .get_blocks_by_head(by_head(&head, 4))
                .await
                .map_err(code)
                .err(),
            Some(deadline)
        );

        let methods: BTreeSet<String> = surface("ethswarm.store.v1")
            .rpcs
            .into_iter()
            .map(|r| r.path)
            .collect();
        assert_eq!(methods.len(), METHODS.len());
        let me = own_cred().uid();
        let [a, b, c] = [1, 2, 3].map(|n| me.wrapping_add(n));
        let allowed = [
            Callers {
                api: me,
                sync: a,
                p2p: b,
            },
            Callers {
                api: a,
                sync: me,
                p2p: b,
            },
            Callers {
                api: a,
                sync: b,
                p2p: me,
            },
        ];
        let off = Callers {
            api: a,
            sync: b,
            p2p: c,
        };
        let through = |callers: Callers, credentials: bool| {
            let reader = Arc::clone(&reader);
            let methods = methods.clone();
            async move {
                let acl = store_acl(callers).expect("the ACL loads");
                assert_eq!(
                    acl.methods().map(str::to_owned).collect::<BTreeSet<_>>(),
                    methods
                );
                let server = StoreServer::new(fixture::v1_link(), reader);
                let conn = Mode::InProcess
                    .connect_behind_acl(Server::new(server.routes()), Arc::new(acl), credentials)
                    .await;
                let mut denied = Vec::new();
                for path in &methods {
                    let r = call_unary_empty(conn.connection.transport.clone(), path).await;
                    denied.push(r.err().is_some_and(|s| s.code() == Code::PermissionDenied));
                }
                (denied, conn.reached())
            }
        };
        let n = methods.len();
        for callers in allowed {
            assert_eq!(
                through(callers, true).await,
                (vec![false; n], n as u64),
                "{callers:?}"
            );
        }
        assert_eq!(
            through(off, true).await,
            (vec![true; n], 0),
            "off the allowlist"
        );
        assert_eq!(
            through(allowed[0], false).await,
            (vec![true; n], 0),
            "no credentials"
        );
    }
}
