//! Fixture beacon nodes for the anchor-fetch tests: plain HTTP/1.1 on 127.0.0.1, one canned
//! reply per path, every request recorded.

use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::net::TcpListener;

/// One chunk of the endless body.
static CHUNK: [u8; 64 * 1024] = [0; 64 * 1024];

/// A canned reply.
#[derive(Clone, Debug)]
pub(crate) enum Reply {
    /// 200, `application/json`.
    Json(String),
    /// 200, `application/octet-stream`, with an optional `Eth-Consensus-Version`.
    Ssz {
        body: Bytes,
        version: Option<&'static str>,
    },
    /// 200 with an explicit content type.
    Typed {
        body: Bytes,
        content_type: &'static str,
    },
    /// An empty reply with this status.
    Status(u16),
    /// 200, `application/octet-stream`, chunked and never ending.
    Endless,
    /// 200, `application/octet-stream`, declaring this `Content-Length` but sending one chunk.
    Declared(u64),
    /// The inner reply, once the gate is notified.
    Gated(Arc<tokio::sync::Notify>, Box<Reply>),
}

/// A response body: full, or an endless stream of zero chunks.
pub(crate) enum TestBody {
    Full(Option<Bytes>),
    Endless,
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            TestBody::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            TestBody::Endless => Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(&CHUNK))))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, TestBody::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            TestBody::Full(Some(b)) => SizeHint::with_exact(b.len() as u64),
            TestBody::Full(None) => SizeHint::with_exact(0),
            TestBody::Endless => SizeHint::default(),
        }
    }
}

/// A request the server saw.
#[derive(Clone, Debug)]
pub(crate) struct Seen {
    pub path: String,
    pub headers: HeaderMap,
}

/// A running fixture server.
pub(crate) struct Server {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    /// Serves `routes` (path → reply; anything else is 404) on 127.0.0.1 until the runtime
    /// ends.
    pub async fn start(routes: HashMap<String, Reply>) -> Self {
        Self::start_on("127.0.0.1:0", routes).await
    }

    /// [`Server::start`] on `bind` (`[::1]:0`: another loopback address than 127.0.0.1).
    pub async fn start_on(bind: &str, routes: HashMap<String, Reply>) -> Self {
        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let routes = Arc::new(routes);
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (routes, log) = (Arc::clone(&routes), Arc::clone(&log));
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let mut reply = routes.get(req.uri().path()).cloned();
                        log.lock().unwrap().push(Seen {
                            path: req.uri().path().to_owned(),
                            headers: req.headers().clone(),
                        });
                        async move {
                            if let Some(Reply::Gated(gate, inner)) = reply {
                                gate.notified().await;
                                reply = Some(*inner);
                            }
                            Ok::<_, Infallible>(respond(reply))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { addr, seen }
    }

    /// Every request so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// The paths requested so far.
    pub fn paths(&self) -> Vec<String> {
        self.seen().into_iter().map(|s| s.path).collect()
    }
}

fn respond(reply: Option<Reply>) -> Response<TestBody> {
    let builder = Response::builder();
    let full = |b: Bytes| TestBody::Full(Some(b));
    match reply {
        None => builder
            .status(StatusCode::NOT_FOUND)
            .body(TestBody::Full(None)),
        Some(Reply::Json(text)) => builder
            .header("content-type", "application/json")
            .body(full(Bytes::from(text))),
        Some(Reply::Ssz { body, version }) => {
            let builder = builder.header("content-type", "application/octet-stream");
            match version {
                Some(v) => builder.header("eth-consensus-version", v),
                None => builder,
            }
            .body(full(body))
        }
        Some(Reply::Typed { body, content_type }) => builder
            .header("content-type", content_type)
            .body(full(body)),
        Some(Reply::Status(code)) => builder.status(code).body(TestBody::Full(None)),
        Some(Reply::Endless) => builder
            .header("content-type", "application/octet-stream")
            .body(TestBody::Endless),
        Some(Reply::Gated(..)) => unreachable!("gates are opened before responding"),
        Some(Reply::Declared(len)) => builder
            .header("content-type", "application/octet-stream")
            .header("content-length", len)
            .body(TestBody::Endless),
    }
    .unwrap()
}

/// Gloas fixtures built in code (no spec vectors): an all-zero mainnet-preset state and block,
/// linked the way `process_block` leaves them.
pub(crate) mod gloas_fixture {
    use consensus_types::gloas::{
        BeaconBlock, BeaconBlockBody, BeaconBlockHeader, BeaconState, BuilderPendingPayment,
        BuilderPendingWithdrawal, Checkpoint, Eth1Data, ExecutionPayloadBid, ExecutionRequests,
        Fork, SignedBeaconBlock, SignedExecutionPayloadBid, SyncAggregate, SyncCommittee,
    };
    use consensus_types::primitives::{Address, Root, Slot};
    use consensus_types::EthSpec;
    use milhouse::Vector;
    use ssz::BitVector;
    use ssz_types::FixedVector;
    use tree_hash::TreeHash;

    fn checkpoint() -> Checkpoint {
        Checkpoint {
            epoch: 0,
            root: Root::ZERO,
        }
    }

    fn sync_committee<E: EthSpec>() -> SyncCommittee<E> {
        SyncCommittee {
            pubkeys: FixedVector::from_elem([0; 48]),
            aggregate_pubkey: [0; 48],
        }
    }

    fn eth1_data() -> Eth1Data {
        Eth1Data {
            deposit_root: Root::ZERO,
            deposit_count: 0,
            block_hash: Root::ZERO,
        }
    }

    fn bid<E: EthSpec>() -> ExecutionPayloadBid<E> {
        ExecutionPayloadBid {
            parent_block_hash: Root::ZERO,
            parent_block_root: Root::ZERO,
            block_hash: Root::ZERO,
            prev_randao: Root::ZERO,
            fee_recipient: Address::ZERO,
            gas_limit: 0,
            builder_index: 0,
            slot: 0,
            value: 0,
            execution_payment: 0,
            blob_kzg_commitments: Default::default(),
            execution_requests_root: Root::ZERO,
        }
    }

    /// An all-zero Gloas block at `slot` with `state_root`.
    pub(crate) fn block<E: EthSpec>(slot: Slot, state_root: Root) -> SignedBeaconBlock<E> {
        SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                proposer_index: 7,
                parent_root: Root::repeat_byte(0x0b),
                state_root,
                body: BeaconBlockBody {
                    randao_reveal: [0; 96],
                    eth1_data: eth1_data(),
                    graffiti: Root::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                    sync_aggregate: SyncAggregate {
                        sync_committee_bits: BitVector::new(),
                        sync_committee_signature: [0; 96],
                    },
                    bls_to_execution_changes: Default::default(),
                    signed_execution_payload_bid: SignedExecutionPayloadBid {
                        message: bid(),
                        signature: [0; 96],
                    },
                    payload_attestations: Default::default(),
                    parent_execution_requests: ExecutionRequests {
                        deposits: Default::default(),
                        withdrawals: Default::default(),
                        consolidations: Default::default(),
                        builder_deposits: Default::default(),
                        builder_exits: Default::default(),
                    },
                },
            },
            signature: [0; 96],
        }
    }

    /// The post-block state of `block`: its slot, and `latest_block_header` with a zero
    /// `state_root`, as `process_block_header` leaves it. Everything else is zero or empty.
    pub(crate) fn post_state<E: EthSpec>(block: &BeaconBlock<E>) -> BeaconState<E> {
        BeaconState {
            genesis_time: 0,
            genesis_validators_root: Root::ZERO,
            slot: block.slot,
            fork: Fork {
                previous_version: [0; 4],
                current_version: [0; 4],
                epoch: 0,
            },
            latest_block_header: BeaconBlockHeader {
                slot: block.slot,
                proposer_index: block.proposer_index,
                parent_root: block.parent_root,
                state_root: Root::ZERO,
                body_root: block.body.tree_hash_root(),
            },
            block_roots: Vector::default(),
            state_roots: Vector::default(),
            historical_roots: Default::default(),
            eth1_data: eth1_data(),
            eth1_data_votes: Default::default(),
            eth1_deposit_index: 0,
            validators: Default::default(),
            balances: Default::default(),
            randao_mixes: Vector::default(),
            slashings: Vector::default(),
            previous_epoch_participation: Default::default(),
            current_epoch_participation: Default::default(),
            justification_bits: BitVector::new(),
            previous_justified_checkpoint: checkpoint(),
            current_justified_checkpoint: checkpoint(),
            finalized_checkpoint: checkpoint(),
            inactivity_scores: Default::default(),
            current_sync_committee: sync_committee(),
            next_sync_committee: sync_committee(),
            latest_block_hash: Root::ZERO,
            next_withdrawal_index: 0,
            next_withdrawal_validator_index: 0,
            historical_summaries: Default::default(),
            deposit_requests_start_index: 0,
            deposit_balance_to_consume: 0,
            exit_balance_to_consume: 0,
            earliest_exit_epoch: 0,
            consolidation_balance_to_consume: 0,
            earliest_consolidation_epoch: 0,
            pending_deposits: Default::default(),
            pending_partial_withdrawals: Default::default(),
            pending_consolidations: Default::default(),
            proposer_lookahead: Vector::default(),
            builders: Default::default(),
            next_withdrawal_builder_index: 0,
            execution_payload_availability: BitVector::new(),
            builder_pending_payments: Vector::from_elem(BuilderPendingPayment {
                weight: 0,
                withdrawal: BuilderPendingWithdrawal {
                    fee_recipient: Address::ZERO,
                    amount: 0,
                    builder_index: 0,
                },
                proposer_index: 0,
            })
            .unwrap(),
            builder_pending_withdrawals: Default::default(),
            latest_execution_payload_bid: bid(),
            payload_expected_withdrawals: Default::default(),
            ptc_window: Vector::default(),
        }
    }

    /// A block at `slot` and its post-block state, the block's `state_root` set to the
    /// state's root.
    pub(crate) fn anchor<E: EthSpec>(slot: Slot) -> (SignedBeaconBlock<E>, BeaconState<E>) {
        let mut block = block::<E>(slot, Root::ZERO);
        let state = post_state(&block.message);
        block.message.state_root = state.tree_hash_root();
        (block, state)
    }
}

mod tests {
    use super::gloas_fixture::anchor;
    use consensus_types::{forked, ForkName, Mainnet};
    use ssz::Encode;
    use tree_hash::TreeHash;

    #[test]
    fn the_fixture_is_a_consistent_gloas_anchor() {
        let (block, state) = anchor::<Mainnet>(100);
        assert_eq!(block.message.state_root, state.tree_hash_root());
        let bytes = state.as_ssz_bytes();
        let decoded =
            forked::BeaconState::<Mainnet>::from_ssz_bytes_for_fork(&bytes, ForkName::Gloas)
                .unwrap();
        assert_eq!(decoded.tree_hash_root(), state.tree_hash_root());
        let bytes = block.as_ssz_bytes();
        let decoded =
            forked::SignedBeaconBlock::<Mainnet>::from_ssz_bytes_for_fork(&bytes, ForkName::Gloas)
                .unwrap();
        assert_eq!(decoded.tree_hash_root(), block.tree_hash_root());
    }
}
