//! The production [`BlockSource`] (#146): [`IpcBlocks`], cl-store's `GetChainHead` (the split
//! point, `finalized_slot`) and `GetBlocksByRange` (the finalized half), and cl-chain's
//! `ReqRespService/BlocksByRange` (the rest).
//!
//! - **Contract.** Every stream is read through the `ipc` contract layer ([`Link::open`] on
//!   [`Inbound::from_server`]): the server's hello first, `seq` strictly from 1, and each
//!   envelope's fork digest checked against its slot's fork ([`Link::check_envelope`]), the
//!   fork the block is then decoded with. An envelope dropped by those checks, of another type
//!   than `PAYLOAD_TYPE_SIGNED_BEACON_BLOCK`, or without a 32-byte root breaks the contract:
//!   `2: ServerError`, never decoded.
//! - **The read stamp.** cl-p2p links no cl-store (`scripts/check-m2a-deps.sh`), so it checks
//!   cl-store's `ReadMeta` itself, as `cl_store::stamp::check_read_meta` does: a store answer or
//!   body without its full stamp breaks the contract.
//! - **Codes.** A store call cl-store failed `UNAVAILABLE` (nothing stamped to serve) is
//!   `3: ResourceUnavailable`, any other failed call `2` ([`super::store_status`]). cl-chain's
//!   error chunk `ERROR_CODE_RESOURCE_UNAVAILABLE` is `3`, any other `2`, `ERROR_CODE_INVALID`
//!   included: cl-p2p built the request, so an invalid one is ours, not the peer's (unlike a
//!   column request's).
//! - **Bounds.** Each step (the call, the server's hello, each body) runs under
//!   [`BLOCK_LOOKUP_TIMEOUT`]; past it the half fails `2` and its stream is dropped, which
//!   cancels the call. Bodies are read one at a time as the answer goes out. Messages are
//!   capped at `MAX_PAYLOAD_SIZE` plus 64 KiB.

use super::blocks::{BlockSource, Blocks, Failed, Half, Lookup, ServedBlock, BLOCK_LOOKUP_TIMEOUT};
use super::store_status::store_result_code;
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use ethswarm_proto::chain;
use ethswarm_proto::common::{Envelope, ErrorCode, PayloadType};
use ethswarm_proto::store;
use futures::Stream;
use ipc::envelope::Envelopes;
use ipc::frame::{InFrame, Inbound};
use ipc::link::{Accepted, Guarded};
use ipc::Link;
use p2p_wire::rpc::protocols::ResultCode;
use std::future::Future;
use std::time::Duration;
use tonic::transport::Channel;
use tonic::Status;

/// The largest message either client decodes: one block of `MAX_PAYLOAD_SIZE` and its framing.
const MAX_MESSAGE_BYTES: usize = MAX_PAYLOAD_SIZE + 64 * 1024;

/// The blocks of an answer from cl-store and cl-chain (see the module docs).
#[derive(Clone, Debug)]
pub struct IpcBlocks {
    store: store::store_service_client::StoreServiceClient<Channel>,
    chain: chain::req_resp_service_client::ReqRespServiceClient<Channel>,
    link: Link,
}

impl IpcBlocks {
    /// Asks cl-store over `store` and cl-chain over `chain`, holding their streams to `link`.
    #[must_use]
    pub fn new(store: Channel, chain: Channel, link: Link) -> Self {
        Self {
            store: store::store_service_client::StoreServiceClient::new(store)
                .max_decoding_message_size(MAX_MESSAGE_BYTES),
            chain: chain::req_resp_service_client::ReqRespServiceClient::new(chain)
                .max_decoding_message_size(MAX_MESSAGE_BYTES),
            link,
        }
    }
}

impl BlockSource for IpcBlocks {
    fn finalized_slot(&self) -> Lookup<u64> {
        let mut store = self.store.clone();
        Box::pin(async move {
            let head = within(
                BLOCK_LOOKUP_TIMEOUT,
                store.get_chain_head(store::GetChainHeadRequest {}),
            )
            .await?
            .map_err(|status| call_failed(Half::Store, &status))?;
            finalized_slot(head.get_ref())
        })
    }

    fn blocks(&self, half: Half, start_slot: u64, count: u64) -> Lookup<Blocks> {
        let (link, hello) = (self.link.clone(), Some(self.link.local()));
        let step = BLOCK_LOOKUP_TIMEOUT;
        let failed = move |status: Status| call_failed(half, &status);
        match half {
            Half::Store => {
                let mut store = self.store.clone();
                let request = store::GetBlocksByRangeRequest {
                    start_slot,
                    count,
                    include_envelopes: false,
                    hello,
                };
                Box::pin(async move {
                    let call = within(step, store.get_blocks_by_range(request)).await?;
                    Ok(read_blocks(
                        link,
                        call.map_err(failed)?.into_inner(),
                        half,
                        step,
                    ))
                })
            }
            Half::Chain => {
                let mut chain = self.chain.clone();
                let request = chain::BlocksByRangeRequest {
                    start_slot,
                    count,
                    hello,
                };
                Box::pin(async move {
                    let call = within(step, chain.blocks_by_range(request)).await?;
                    Ok(read_blocks(
                        link,
                        call.map_err(failed)?.into_inner(),
                        half,
                        step,
                    ))
                })
            }
        }
    }
}

/// `step` around one IPC step; past it the step fails `2` (`timeout`).
async fn within<T>(step: Duration, future: impl Future<Output = T>) -> Result<T, Failed> {
    tokio::time::timeout(step, future)
        .await
        .map_err(|_| Failed::server_error("timeout", format!("no answer within {step:?}")))
}

fn contract(why: impl Into<String>) -> Failed {
    Failed::server_error("contract", why)
}

/// cl-store's read stamp, as `cl_store::stamp::check_read_meta` holds it: `as_of_seq`, a
/// 32-byte `as_of_root` and `as_of_slot`, none of them zero.
fn check_read_meta(meta: Option<&store::ReadMeta>) -> Result<(), Failed> {
    match meta {
        Some(m) if m.as_of_seq > 0 && m.as_of_root.len() == 32 && m.as_of_slot > 0 => Ok(()),
        _ => Err(contract("a store answer without its full ReadMeta")),
    }
}

/// The body of one block of a range answer: its envelope, or why there is none.
pub(crate) trait BlockBody {
    fn envelope(self) -> Result<Envelope, Failed>;
}

/// An error a server sent in the stream: `ERROR_CODE_RESOURCE_UNAVAILABLE` is `3`, any other
/// `2`.
fn refused(code: i32, detail: &str) -> Failed {
    let code = match ErrorCode::try_from(code) {
        Ok(ErrorCode::ResourceUnavailable) => ResultCode::ResourceUnavailable,
        _ => ResultCode::ServerError,
    };
    Failed {
        code,
        kind: "refused",
        why: format!("refused: {detail}"),
    }
}

impl BlockBody for store::GetBlocksByRangeResponseBody {
    fn envelope(self) -> Result<Envelope, Failed> {
        check_read_meta(self.meta.as_ref())?;
        if let Some(e) = self.error {
            return Err(refused(e.code, &e.detail));
        }
        self.item
            .ok_or_else(|| contract("a store body without its block"))
    }
}

impl BlockBody for chain::BlocksByRangeResponseBody {
    fn envelope(self) -> Result<Envelope, Failed> {
        match self.item.and_then(|item| item.result) {
            Some(chain::response_chunk::Result::Chunk(envelope)) => Ok(envelope),
            Some(chain::response_chunk::Result::Error(e)) => Err(refused(e.code, &e.detail)),
            // `Envelopes::check_shape` refuses a chunk with neither.
            None => Err(contract("an empty chunk")),
        }
    }
}

/// The store's finalized slot from its `GetChainHead` answer, which must carry its stamp.
pub(crate) fn finalized_slot(head: &store::GetChainHeadResponse) -> Result<u64, Failed> {
    check_read_meta(head.meta.as_ref())?;
    Ok(head.finalized_slot)
}

/// What a call of `half` that failed with `status` ends the answer with: cl-store's own
/// `UNAVAILABLE` is `3`, any other failure `2`.
pub(crate) fn call_failed(half: Half, status: &Status) -> Failed {
    let code = match half {
        Half::Store => store_result_code(status),
        Half::Chain => ResultCode::ServerError,
    };
    Failed {
        code,
        kind: "status",
        why: format!("{:?}: {}", status.code(), status.message()),
    }
}

/// One accepted body as a block.
fn served<B: BlockBody>(link: &Link, accepted: Accepted<B>) -> Result<ServedBlock, Failed> {
    if let Some((_, reason)) = accepted.dropped.first() {
        return Err(contract(format!("an envelope dropped: {reason}")));
    }
    let envelope = accepted.body.envelope()?;
    if envelope.payload_type != PayloadType::SignedBeaconBlock as i32 {
        let why = format!("payload_type {} in a block answer", envelope.payload_type);
        return Err(contract(why));
    }
    let fork = link
        .check_envelope(&envelope)
        .map_err(|e| contract(format!("a block envelope: {e}")))?
        .fork;
    let root = <[u8; 32]>::try_from(envelope.root.as_slice())
        .map_err(|_| contract("a block envelope without a 32-byte root"))?;
    Ok(ServedBlock {
        slot: envelope.slot,
        root,
        fork,
        ssz: envelope.ssz,
    })
}

/// Where a half's stream is.
enum Reading<S> {
    Opening(Inbound<S>),
    Open(Box<Guarded<S>>),
    Done,
}

/// The blocks of `half`'s response `stream` (see the module docs), each step within `step`.
/// The first failure ends them, and drops the stream.
pub(crate) fn read_blocks<S, T>(link: Link, stream: S, half: Half, step: Duration) -> Blocks
where
    S: Stream<Item = Result<T, Status>> + Unpin + Send + 'static,
    T: InFrame + Send + 'static,
    T::Body: Envelopes + BlockBody + Send,
{
    let broken = move |e: ipc::ContractError| contract(format!("{}: {}", half.label(), e.detail()));
    let start = (Reading::Opening(Inbound::from_server(stream)), link);
    Box::pin(futures::stream::unfold(
        start,
        move |(state, link)| async move {
            let mut guarded = match state {
                Reading::Opening(inbound) => match within(step, link.open(inbound)).await {
                    Ok(Ok(guarded)) => Box::new(guarded),
                    Ok(Err(e)) => return Some((Err(broken(e)), (Reading::Done, link))),
                    Err(timeout) => return Some((Err(timeout), (Reading::Done, link))),
                },
                Reading::Open(guarded) => guarded,
                Reading::Done => return None,
            };
            let next = match within(step, guarded.body()).await {
                Ok(Ok(Some(accepted))) => served(&link, accepted),
                Ok(Ok(None)) => return None,
                Ok(Err(e)) => Err(broken(e)),
                Err(timeout) => Err(timeout),
            };
            let state = match next {
                Ok(_) => Reading::Open(guarded),
                Err(_) => Reading::Done,
            };
            Some((next, (state, link)))
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::blocks::testing::chain;
    use crate::rpc::blocks::ServedBlock;
    use consensus_types::Minimal;
    use ethswarm_proto::common::{Envelope, Error, ErrorCode, Hello, PayloadType};
    use futures::StreamExt as _;
    use ipc::envelope::DigestTable;
    use ipc::error::{to_status, wire_error};
    use ipc::frame::OutFrame;
    use network_config::{ForkName, ForkSchedule, ScheduledFork};
    use p2p_wire::rpc::protocols::ResultCode;
    use p2p_wire::testkit::{FULU_BPO_DIGEST, FULU_DIGEST, GLOAS_DIGEST};
    use prost::Message as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use store::ReadMeta;
    use tonic::Code;

    /// The fixture link: Fulu at epoch 0, its BPO digest at 2, Gloas at 4 (minimal preset).
    fn link() -> Link {
        let at = |version, epoch| ScheduledFork { version, epoch };
        let schedule = ForkSchedule::new(at([6, 0, 0, 1], 0), at([7, 0, 0, 1], 4)).unwrap();
        let digests = DigestTable::new(vec![
            (0, ForkName::Fulu, FULU_DIGEST),
            (2, ForkName::Fulu, FULU_BPO_DIGEST),
            (4, ForkName::Gloas, GLOAS_DIGEST),
        ])
        .unwrap();
        let hello = Hello {
            api_version: 1,
            min_api_version: 1,
            max_api_version: 1,
            ..Default::default()
        };
        Link::new::<Minimal>(hello, 1, schedule, digests)
    }

    fn server_hello(link: &Link) -> Hello {
        Hello {
            generation: 7,
            ..link.local()
        }
    }

    fn meta() -> Option<ReadMeta> {
        Some(ReadMeta {
            as_of_seq: 3,
            as_of_root: vec![9; 32],
            as_of_slot: 40,
            execution_optimistic: false,
            finalized: true,
        })
    }

    /// The envelope of `block` at `seq`, with the digest of its slot's epoch.
    fn envelope(block: &ServedBlock, seq: u64) -> Envelope {
        Envelope {
            fork_digest: link().fork_digest_at_slot(block.slot).unwrap().to_vec(),
            slot: block.slot,
            root: block.root.to_vec(),
            ssz: block.ssz.clone(),
            payload_type: PayloadType::SignedBeaconBlock as i32,
            trace_id: Vec::new(),
            seq,
        }
    }

    fn store_body(item: Envelope, meta: Option<ReadMeta>) -> store::GetBlocksByRangeResponse {
        store::GetBlocksByRangeResponse::body(store::GetBlocksByRangeResponseBody {
            item: Some(item),
            meta,
            error: None,
        })
    }

    fn chain_chunk(item: Envelope) -> chain::BlocksByRangeResponse {
        chain::BlocksByRangeResponse::body(chain::BlocksByRangeResponseBody {
            item: Some(chain::ResponseChunk {
                result: Some(chain::response_chunk::Result::Chunk(item)),
            }),
        })
    }

    fn chain_error(code: ErrorCode) -> chain::BlocksByRangeResponse {
        chain::BlocksByRangeResponse::body(chain::BlocksByRangeResponseBody {
            item: Some(chain::ResponseChunk {
                result: Some(chain::response_chunk::Result::Error(Error {
                    code: code as i32,
                    detail: "refused".into(),
                })),
            }),
        })
    }

    /// What [`read_blocks`] makes of `frames`, to the end of the stream.
    async fn read<T>(frames: Vec<T>, half: Half) -> Vec<Result<ServedBlock, Failed>>
    where
        T: InFrame + Send + 'static,
        T::Body: Envelopes + BlockBody + Send,
    {
        let stream = futures::stream::iter(frames.into_iter().map(Ok));
        read_blocks(link(), stream, half, Duration::from_secs(2))
            .collect()
            .await
    }

    /// A `GetChainHead` answer of `meta` whose `finalized_slot` (8) is `finalized`, as cl-store
    /// writes it.
    fn head(meta: Option<ReadMeta>, finalized: u64) -> store::GetChainHeadResponse {
        let mut bytes = store::GetChainHeadResponse {
            head_slot: 40,
            head_root: vec![9; 32],
            meta,
            ..Default::default()
        }
        .encode_to_vec();
        prost::encoding::uint64::encode(8, &finalized, &mut bytes);
        store::GetChainHeadResponse::decode(bytes.as_slice()).unwrap()
    }

    fn code_of(failed: &Failed) -> ResultCode {
        failed.code
    }

    /// #146: cl-p2p links no cl-store, so it checks the read stamp itself. A store answer
    /// without its full `ReadMeta` (a stamp-less `GetChainHead`, a stamp-less range body)
    /// breaks the contract: `2: ServerError`, never a block or a split point.
    #[tokio::test]
    async fn store_body_without_stamp_refused() {
        assert_eq!(finalized_slot(&head(meta(), 20)), Ok(20));
        assert_eq!(
            finalized_slot(&head(meta(), 0)),
            Ok(0),
            "finalized at genesis"
        );
        let no_seq = meta().map(|m| ReadMeta { as_of_seq: 0, ..m });
        let short_root = meta().map(|m| ReadMeta {
            as_of_root: vec![9; 31],
            ..m
        });
        let no_slot = meta().map(|m| ReadMeta { as_of_slot: 0, ..m });
        for meta in [None, no_seq, short_root, no_slot] {
            let refused = finalized_slot(&head(meta.clone(), 20)).unwrap_err();
            assert_eq!(code_of(&refused), ResultCode::ServerError, "{meta:?}");
            assert_eq!(refused.kind, "contract");
        }
        let blocks = chain();
        let link = link();
        let served = read(
            vec![
                store::GetBlocksByRangeResponse::hello(server_hello(&link)),
                store_body(envelope(&blocks[0], 1), meta()),
                store_body(envelope(&blocks[1], 2), meta()),
            ],
            Half::Store,
        )
        .await;
        assert_eq!(served, [Ok(blocks[0].clone()), Ok(blocks[1].clone())]);
        let refused = read(
            vec![
                store::GetBlocksByRangeResponse::hello(server_hello(&link)),
                store_body(envelope(&blocks[0], 1), meta()),
                store_body(envelope(&blocks[1], 2), None),
            ],
            Half::Store,
        )
        .await;
        assert_eq!(refused[0], Ok(blocks[0].clone()));
        let failed = refused[1].clone().unwrap_err();
        assert_eq!(
            (failed.code, failed.kind),
            (ResultCode::ServerError, "contract")
        );
        assert_eq!(refused.len(), 2, "nothing after it");
    }

    /// #146: an envelope whose fork digest is not its slot's epoch's, or whose type is not
    /// `SIGNED_BEACON_BLOCK`, or whose root is not 32 bytes, fails the answer (`2`), never
    /// decoded; so does a stream that breaks the frame contract (no hello first, a `seq`
    /// out of order). Each block carries the fork of its slot.
    #[tokio::test]
    async fn envelope_digest_or_type_mismatch_fails() {
        let blocks = chain();
        let gloas = blocks.iter().find(|b| b.slot >= 32).unwrap();
        let link = link();
        let hello = || chain::BlocksByRangeResponse::hello(server_hello(&link));
        let served = read(vec![hello(), chain_chunk(envelope(gloas, 1))], Half::Chain).await;
        assert_eq!(served, [Ok(gloas.clone())]);
        assert_eq!(served[0].as_ref().unwrap().fork, ForkName::Gloas);
        let wrong_digest = Envelope {
            fork_digest: FULU_DIGEST.to_vec(),
            ..envelope(gloas, 1)
        };
        let wrong_type = Envelope {
            payload_type: PayloadType::DataColumnSidecar as i32,
            ..envelope(&blocks[0], 1)
        };
        let short_root = Envelope {
            root: vec![1; 31],
            ..envelope(&blocks[0], 1)
        };
        for (case, frames) in [
            ("digest", vec![hello(), chain_chunk(wrong_digest)]),
            ("type", vec![hello(), chain_chunk(wrong_type)]),
            ("root", vec![hello(), chain_chunk(short_root)]),
            ("no hello", vec![chain_chunk(envelope(&blocks[0], 1))]),
            (
                "seq",
                vec![
                    hello(),
                    chain_chunk(envelope(&blocks[0], 1)),
                    chain_chunk(envelope(&blocks[1], 1)),
                ],
            ),
        ] {
            let served = read(frames, Half::Chain).await;
            let failed = served.last().unwrap().clone().unwrap_err();
            assert_eq!(failed.code, ResultCode::ServerError, "{case}");
            assert_eq!(failed.kind, "contract", "{case}");
        }
    }

    /// #146: cl-chain's error chunk ends the chain half: `ERROR_CODE_RESOURCE_UNAVAILABLE` is
    /// `3`; anything else is `2`, `ERROR_CODE_INVALID` too (cl-p2p built the request, so an
    /// invalid one is ours, not the peer's). A chain call that failed outright is `2`.
    #[tokio::test]
    async fn chain_error_codes_map() {
        let link = link();
        for (error, code) in [
            (
                ErrorCode::ResourceUnavailable,
                ResultCode::ResourceUnavailable,
            ),
            (ErrorCode::Overloaded, ResultCode::ServerError),
            (ErrorCode::Invalid, ResultCode::ServerError),
            (ErrorCode::DeadlineExceeded, ResultCode::ServerError),
        ] {
            let frames = vec![
                chain::BlocksByRangeResponse::hello(server_hello(&link)),
                chain_error(error),
            ];
            let served = read(frames, Half::Chain).await;
            let failed = served[0].clone().unwrap_err();
            assert_eq!((failed.code, failed.kind), (code, "refused"), "{error:?}");
        }
        for status in [
            Status::unavailable("connection refused"),
            Status::unimplemented("stub"),
            Status::internal("column store failed"),
        ] {
            let failed = call_failed(Half::Chain, &status);
            assert_eq!(failed.code, ResultCode::ServerError, "{status:?}");
            assert_eq!(failed.kind, "status");
        }
    }

    /// #146: a store call that cl-store failed `UNAVAILABLE` with its
    /// `ERROR_CODE_RESOURCE_UNAVAILABLE` (nothing stamped to serve) is `3`; any other failure,
    /// the transport's own `UNAVAILABLE` included, is `2` (`store_status::store_result_code`).
    #[test]
    fn store_unavailable_is_resource_unavailable() {
        let details = to_status(&wire_error(ErrorCode::ResourceUnavailable, "no stamp"))
            .details()
            .to_vec();
        let from_store =
            Status::with_details(Code::Unavailable, "store unavailable", details.into());
        let failed = call_failed(Half::Store, &from_store);
        assert_eq!(
            (failed.code, failed.kind),
            (ResultCode::ResourceUnavailable, "status")
        );
        for status in [
            Status::unavailable("connection refused"),
            Status::deadline_exceeded("late"),
        ] {
            assert_eq!(
                call_failed(Half::Store, &status).code,
                ResultCode::ServerError,
                "{status:?}"
            );
        }
    }

    /// A response stream that yields `frames`, then nothing for good; `dropped` once it is
    /// dropped (the gRPC call cancelled).
    struct Stalling<T> {
        frames: std::collections::VecDeque<T>,
        dropped: Arc<AtomicBool>,
    }

    impl<T: Unpin> Stream for Stalling<T> {
        type Item = Result<T, Status>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            match self.frames.pop_front() {
                Some(frame) => std::task::Poll::Ready(Some(Ok(frame))),
                None => std::task::Poll::Pending,
            }
        }
    }

    impl<T> Drop for Stalling<T> {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    /// #146: each IPC step runs within its step timeout (`BLOCK_LOOKUP_TIMEOUT`, 2 s): a server
    /// that sends no hello, or stops between bodies, fails the half `2` (`timeout`) at the
    /// step's end, and the call's stream is dropped then, which cancels it.
    #[tokio::test(start_paused = true)]
    async fn step_timeout_ends_call() {
        let link = link();
        let blocks = chain();
        for frames in [
            vec![],
            vec![
                chain::BlocksByRangeResponse::hello(server_hello(&link)),
                chain_chunk(envelope(&blocks[0], 1)),
            ],
        ] {
            let ok = frames.len().saturating_sub(1);
            let dropped = Arc::new(AtomicBool::new(false));
            let stream = Stalling {
                frames: frames.into(),
                dropped: Arc::clone(&dropped),
            };
            let start = tokio::time::Instant::now();
            let mut served = read_blocks(link.clone(), stream, Half::Chain, Duration::from_secs(2));
            for _ in 0..ok {
                assert!(served.next().await.unwrap().is_ok());
            }
            let failed = served.next().await.unwrap().unwrap_err();
            assert_eq!(
                (failed.code, failed.kind),
                (ResultCode::ServerError, "timeout")
            );
            assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(2));
            assert!(served.next().await.is_none(), "the half ends with it");
            assert!(dropped.load(Ordering::SeqCst), "the call is cancelled");
        }
    }
}
