//! Stream framing and `Envelope.seq`.
//!
//! Every streamed message is `oneof frame { Hello hello = 1; <Msg>Body body = 2; }`. Each
//! direction sends exactly one `hello`, first, then only `body` frames. A first frame that is
//! not `hello`, a `hello` mid-stream, a frame with neither field set, or a stream that ends
//! before its `hello` is `ERROR_CODE_CONTRACT_VIOLATION` ([`FrameGuard`], [`Inbound`]). A
//! server-streaming request is the client's only frame, so it carries the hello in-line
//! ([`HelloField`]); leaving it out is a contract violation too.
//!
//! `Envelope.seq` increases strictly from 1 per stream direction ([`SeqChecker`] receives,
//! [`SeqCounter`] sends) and is 0 on unary calls ([`check_unary_seq`]). A gap, a repeat or a
//! decrease is a contract violation; receivers never reorder.

use ethswarm_proto::common::Hello;
use ethswarm_proto::{chain, discv5, p2p, store, verify};
use tokio_stream::{Stream, StreamExt};
use tonic::Status;

use crate::error::{inbound_error, ContractError};

/// One decoded frame.
#[derive(Clone, Debug, PartialEq)]
pub enum Frame<B> {
    Hello(Hello),
    Body(B),
}

/// A received message carrying `oneof frame`.
pub trait InFrame {
    type Body;
    /// `None` when neither `hello` nor `body` is set.
    fn into_frame(self) -> Option<Frame<Self::Body>>;
}

/// A sent message carrying `oneof frame`.
pub trait OutFrame {
    type Body;
    fn hello(hello: Hello) -> Self;
    fn body(body: Self::Body) -> Self;
}

/// A server-streaming request, which carries the client's hello in-line.
pub trait HelloField {
    fn hello_field(&self) -> Option<&Hello>;
    fn set_hello_field(&mut self, hello: Option<Hello>);
}

/// Implements [`InFrame`] and [`OutFrame`] for a `oneof frame` message.
macro_rules! framed {
    ($msg:ty, $module:ident, $body:ty, $variant:ident) => {
        impl InFrame for $msg {
            type Body = $body;
            fn into_frame(self) -> Option<Frame<$body>> {
                match self.frame? {
                    $module::Frame::Hello(h) => Some(Frame::Hello(h)),
                    $module::Frame::$variant(b) => Some(Frame::Body(b)),
                }
            }
        }
        impl OutFrame for $msg {
            type Body = $body;
            fn hello(hello: Hello) -> Self {
                Self {
                    frame: Some($module::Frame::Hello(hello)),
                }
            }
            fn body(body: $body) -> Self {
                Self {
                    frame: Some($module::Frame::$variant(body)),
                }
            }
        }
    };
    ($pkg:ident: $($msg:ident / $module:ident / $body:ident),* $(,)?) => {
        $(framed!($pkg::$msg, $module, $pkg::$body, Body);)*
    };
}

macro_rules! hello_field {
    ($pkg:ident: $($msg:ident),* $(,)?) => {
        $(impl HelloField for $pkg::$msg {
            fn hello_field(&self) -> Option<&Hello> {
                self.hello.as_ref()
            }
            fn set_hello_field(&mut self, hello: Option<Hello>) {
                self.hello = hello;
            }
        })*
    };
}

use chain::{
    blocks_by_range_response, blocks_by_root_response, data_columns_by_range_response,
    data_columns_by_root_response, import_batch_request, import_batch_response,
    payload_envelopes_by_range_response, payload_envelopes_by_root_response, subscribe_response,
    validate_request, validate_response, watch_publish_response, watch_subscriptions_response,
};
use discv5::{find_peers_response, watch_peers_response};
use p2p::{
    request_blocks_by_range_response, request_blocks_by_root_response,
    request_data_columns_by_range_response, request_data_columns_by_root_response,
    request_payload_envelopes_by_range_response, request_payload_envelopes_by_root_response,
};
use store::{
    get_blocks_by_range_response, get_data_columns_by_range_response, get_data_columns_response,
};
use verify::{
    builder_key_feed_request, builder_key_feed_response, pubkey_feed_request, pubkey_feed_response,
    verify_bls_request, verify_bls_response, verify_kzg_request, verify_kzg_response,
};

framed!(
    chain::ValidateRequest,
    validate_request,
    chain::ValidateBatch,
    Batch
);
framed!(
    chain::ValidateResponse,
    validate_response,
    chain::VerdictBatch,
    Verdicts
);
framed!(chain:
    ImportBatchRequest / import_batch_request / ImportBatchRequestBody,
    ImportBatchResponse / import_batch_response / ImportBatchResponseBody,
    WatchPublishResponse / watch_publish_response / WatchPublishResponseBody,
    WatchSubscriptionsResponse / watch_subscriptions_response / WatchSubscriptionsResponseBody,
    SubscribeResponse / subscribe_response / SubscribeResponseBody,
    BlocksByRangeResponse / blocks_by_range_response / BlocksByRangeResponseBody,
    BlocksByRootResponse / blocks_by_root_response / BlocksByRootResponseBody,
    DataColumnsByRangeResponse / data_columns_by_range_response / DataColumnsByRangeResponseBody,
    DataColumnsByRootResponse / data_columns_by_root_response / DataColumnsByRootResponseBody,
    PayloadEnvelopesByRangeResponse / payload_envelopes_by_range_response / PayloadEnvelopesByRangeResponseBody,
    PayloadEnvelopesByRootResponse / payload_envelopes_by_root_response / PayloadEnvelopesByRootResponseBody,
);
framed!(store:
    GetDataColumnsResponse / get_data_columns_response / GetDataColumnsResponseBody,
    GetBlocksByRangeResponse / get_blocks_by_range_response / GetBlocksByRangeResponseBody,
    GetDataColumnsByRangeResponse / get_data_columns_by_range_response / GetDataColumnsByRangeResponseBody,
);
framed!(p2p:
    RequestBlocksByRangeResponse / request_blocks_by_range_response / RequestBlocksByRangeResponseBody,
    RequestBlocksByRootResponse / request_blocks_by_root_response / RequestBlocksByRootResponseBody,
    RequestDataColumnsByRangeResponse / request_data_columns_by_range_response / RequestDataColumnsByRangeResponseBody,
    RequestDataColumnsByRootResponse / request_data_columns_by_root_response / RequestDataColumnsByRootResponseBody,
    RequestPayloadEnvelopesByRangeResponse / request_payload_envelopes_by_range_response / RequestPayloadEnvelopesByRangeResponseBody,
    RequestPayloadEnvelopesByRootResponse / request_payload_envelopes_by_root_response / RequestPayloadEnvelopesByRootResponseBody,
);
framed!(discv5:
    WatchPeersResponse / watch_peers_response / WatchPeersResponseBody,
    FindPeersResponse / find_peers_response / FindPeersResponseBody,
);
framed!(verify:
    VerifyBlsRequest / verify_bls_request / VerifyBlsRequestBody,
    VerifyBlsResponse / verify_bls_response / VerifyBlsResponseBody,
    VerifyKzgRequest / verify_kzg_request / VerifyKzgRequestBody,
    VerifyKzgResponse / verify_kzg_response / VerifyKzgResponseBody,
    PubkeyFeedRequest / pubkey_feed_request / PubkeyFeedRequestBody,
    PubkeyFeedResponse / pubkey_feed_response / PubkeyFeedResponseBody,
    BuilderKeyFeedRequest / builder_key_feed_request / BuilderKeyFeedRequestBody,
    BuilderKeyFeedResponse / builder_key_feed_response / BuilderKeyFeedResponseBody,
);

hello_field!(chain:
    WatchPublishRequest,
    WatchSubscriptionsRequest,
    SubscribeRequest,
    BlocksByRangeRequest,
    BlocksByRootRequest,
    DataColumnsByRangeRequest,
    DataColumnsByRootRequest,
    PayloadEnvelopesByRangeRequest,
    PayloadEnvelopesByRootRequest,
);
hello_field!(store: GetDataColumnsRequest, GetBlocksByRangeRequest, GetDataColumnsByRangeRequest);
hello_field!(p2p:
    RequestBlocksByRangeRequest,
    RequestBlocksByRootRequest,
    RequestDataColumnsByRangeRequest,
    RequestDataColumnsByRootRequest,
    RequestPayloadEnvelopesByRangeRequest,
    RequestPayloadEnvelopesByRootRequest,
);
hello_field!(discv5: WatchPeersRequest, FindPeersRequest);

/// The hello-first discipline of one stream direction, one frame at a time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameGuard {
    opened: bool,
}

impl FrameGuard {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the leading hello has been seen.
    #[must_use]
    pub fn opened(&self) -> bool {
        self.opened
    }

    /// Admits the next frame: the first must be `hello`, every later one `body`.
    pub fn admit<B>(&mut self, frame: Option<Frame<B>>) -> Result<Frame<B>, ContractError> {
        match (self.opened, frame) {
            (_, None) => Err(ContractError::violation("frame has neither hello nor body")),
            (false, Some(Frame::Hello(h))) => {
                self.opened = true;
                Ok(Frame::Hello(h))
            }
            (false, Some(Frame::Body(_))) => {
                Err(ContractError::violation("first frame is not hello"))
            }
            (true, Some(Frame::Hello(_))) => Err(ContractError::violation("hello mid-stream")),
            (true, Some(body)) => Ok(body),
        }
    }

    /// The peer closed its side; before the hello that is a contract violation.
    pub fn finish(&self) -> Result<(), ContractError> {
        if self.opened {
            Ok(())
        } else {
            Err(ContractError::violation("stream closed before hello"))
        }
    }
}

/// The receiving side of one stream direction, enforcing [`FrameGuard`].
pub struct Inbound<S> {
    stream: S,
    guard: FrameGuard,
    map_status: fn(&Status) -> ContractError,
    /// The caller decides when the hello is due: `body` does not demand one first.
    caller_ordered: bool,
}

impl<S, T> Inbound<S>
where
    S: Stream<Item = Result<T, Status>> + Unpin,
    T: InFrame,
{
    /// A request stream on the server. A receive error is tonic's own: an over-cap frame is a
    /// contract violation, anything else leaves the resource unavailable.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            guard: FrameGuard::new(),
            map_status: |s| inbound_error(s).into(),
            caller_ordered: false,
        }
    }

    /// A request stream on the server whose hello the caller reads (or has read elsewhere)
    /// before asking for bodies: [`Self::body`] accepts a body without a hello first, and still
    /// refuses a hello. [`Self::hello`] demands a hello as usual.
    pub fn caller_ordered(stream: S) -> Self {
        Self {
            caller_ordered: true,
            ..Self::new(stream)
        }
    }

    /// A response stream on the client. A status is the error the server failed the stream
    /// with, read back from its details.
    pub fn from_server(stream: S) -> Self {
        Self {
            stream,
            guard: FrameGuard::new(),
            map_status: ContractError::from_status,
            caller_ordered: false,
        }
    }

    /// The opening frame, which must be `hello`.
    pub async fn hello(&mut self) -> Result<Hello, ContractError> {
        match self.next().await? {
            Some(Frame::Hello(h)) => Ok(h),
            Some(Frame::Body(_)) => unreachable!("FrameGuard admits only hello first"),
            None => Err(self.guard.finish().expect_err("no hello was admitted")),
        }
    }

    /// The next `body` frame, or `None` once the peer closes its side.
    pub async fn body(&mut self) -> Result<Option<T::Body>, ContractError> {
        if self.caller_ordered {
            self.guard.opened = true;
        }
        match self.next().await? {
            Some(Frame::Body(b)) => Ok(Some(b)),
            Some(Frame::Hello(_)) => unreachable!("FrameGuard admits hello only first"),
            None => self.guard.finish().map(|()| None),
        }
    }

    async fn next(&mut self) -> Result<Option<Frame<T::Body>>, ContractError> {
        match self.stream.next().await {
            None => Ok(None),
            Some(Err(status)) => Err((self.map_status)(&status)),
            Some(Ok(msg)) => self.guard.admit(msg.into_frame()).map(Some),
        }
    }
}

/// `Envelope.seq` on one receiving stream direction: 1, 2, 3, ...
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeqChecker {
    last: u64,
}

impl SeqChecker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The last accepted seq (0 before the first).
    #[must_use]
    pub fn last(&self) -> u64 {
        self.last
    }

    /// Accepts `seq` only if it is exactly one more than the last one.
    pub fn check(&mut self, seq: u64) -> Result<(), ContractError> {
        let expected = self.last.checked_add(1).ok_or_else(|| {
            ContractError::violation("seq exhausted the u64 range on this stream")
        })?;
        if seq == expected {
            self.last = seq;
            return Ok(());
        }
        let what = if seq > expected {
            "gap"
        } else if seq == self.last && seq != 0 {
            "repeat"
        } else {
            "decrease"
        };
        Err(ContractError::violation(format!(
            "non-monotonic seq ({what}): got {seq}, expected {expected}"
        )))
    }
}

/// `Envelope.seq` on one sending stream direction, starting at 1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeqCounter {
    last: u64,
}

impl SeqCounter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The seq of the next envelope sent.
    pub fn next_seq(&mut self) -> u64 {
        self.last += 1;
        self.last
    }
}

/// `Envelope.seq` must be 0 on a unary call.
pub fn check_unary_seq(seq: u64) -> Result<(), ContractError> {
    if seq == 0 {
        Ok(())
    } else {
        Err(ContractError::violation(format!(
            "seq {seq} on a unary call (must be 0)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethswarm_proto::common::ErrorCode;
    use verify::{VerifyKzgRequest, VerifyKzgRequestBody};

    fn hello() -> VerifyKzgRequest {
        VerifyKzgRequest::hello(Hello::default())
    }

    fn body(id: u64) -> VerifyKzgRequest {
        VerifyKzgRequest::body(VerifyKzgRequestBody {
            request_id: id,
            ..Default::default()
        })
    }

    fn inbound(
        frames: Vec<Result<VerifyKzgRequest, Status>>,
    ) -> Inbound<impl Stream<Item = Result<VerifyKzgRequest, Status>> + Unpin> {
        Inbound::new(tokio_stream::iter(frames))
    }

    fn violation<T: std::fmt::Debug>(r: Result<T, ContractError>) -> String {
        let e = r.unwrap_err();
        assert_eq!(e.code(), ErrorCode::ContractViolation, "{e}");
        e.detail().to_owned()
    }

    #[test]
    fn guard_admits_one_hello_then_bodies() {
        let mut g = FrameGuard::new();
        assert!(!g.opened());
        assert!(g.finish().is_err());
        assert_eq!(
            g.admit(Some(Frame::<u8>::Hello(Hello::default()))),
            Ok(Frame::Hello(Hello::default()))
        );
        assert!(g.opened());
        assert_eq!(g.admit(Some(Frame::Body(1u8))), Ok(Frame::Body(1)));
        assert_eq!(g.admit(Some(Frame::Body(2u8))), Ok(Frame::Body(2)));
        assert_eq!(g.finish(), Ok(()));
    }

    #[test]
    fn guard_refuses_every_other_opening() {
        let first = violation(FrameGuard::new().admit(Some(Frame::Body(1u8))));
        assert_eq!(first, "first frame is not hello");
        let empty = violation(FrameGuard::new().admit::<u8>(None));
        assert_eq!(empty, "frame has neither hello nor body");
        let mut g = FrameGuard::new();
        g.admit::<u8>(Some(Frame::Hello(Hello::default()))).unwrap();
        assert_eq!(
            violation(g.admit::<u8>(Some(Frame::Hello(Hello::default())))),
            "hello mid-stream"
        );
        assert_eq!(
            violation(g.admit::<u8>(None)),
            "frame has neither hello nor body"
        );
    }

    #[tokio::test]
    async fn inbound_reads_hello_then_bodies_then_end() {
        let mut s = inbound(vec![Ok(hello()), Ok(body(1)), Ok(body(2))]);
        assert_eq!(s.hello().await, Ok(Hello::default()));
        assert_eq!(s.body().await.unwrap().unwrap().request_id, 1);
        assert_eq!(s.body().await.unwrap().unwrap().request_id, 2);
        assert_eq!(s.body().await, Ok(None));
    }

    #[tokio::test]
    async fn inbound_refuses_a_missing_or_second_hello() {
        assert_eq!(
            violation(inbound(vec![Ok(body(1))]).hello().await),
            "first frame is not hello"
        );
        assert_eq!(
            violation(inbound(vec![]).hello().await),
            "stream closed before hello"
        );
        let mut s = inbound(vec![Ok(hello()), Ok(hello())]);
        s.hello().await.unwrap();
        assert_eq!(violation(s.body().await), "hello mid-stream");
        let mut empty = inbound(vec![Ok(VerifyKzgRequest { frame: None })]);
        violation(empty.hello().await);
    }

    #[tokio::test]
    async fn caller_ordered_inbound_reads_bodies_without_a_hello() {
        // The caller already took the hello elsewhere: bodies are read as they come.
        let mut s = Inbound::caller_ordered(tokio_stream::iter(vec![Ok(body(1)), Ok(hello())]));
        assert_eq!(s.body().await.unwrap().unwrap().request_id, 1);
        assert_eq!(violation(s.body().await), "hello mid-stream");
        let mut t = Inbound::caller_ordered(tokio_stream::iter(vec![
            Ok::<_, Status>(body(1)),
            Err(Status::unknown("h2 reset")),
        ]));
        t.body().await.unwrap();
        assert_eq!(
            t.body().await.unwrap_err().code(),
            ErrorCode::ResourceUnavailable
        );
        let mut ended = Inbound::caller_ordered(tokio_stream::iter(Vec::<
            Result<VerifyKzgRequest, Status>,
        >::new()));
        assert_eq!(ended.body().await, Ok(None));
        // Asking for the hello still demands one.
        let mut h = Inbound::caller_ordered(tokio_stream::iter(vec![Ok(body(1))]));
        assert_eq!(violation(h.hello().await), "first frame is not hello");
    }

    #[tokio::test]
    async fn inbound_body_before_hello_is_refused() {
        let mut s = inbound(vec![Ok(body(1))]);
        violation(s.body().await);
        let mut closed = inbound(vec![]);
        assert_eq!(violation(closed.body().await), "stream closed before hello");
    }

    #[tokio::test]
    async fn receive_errors_map_by_side() {
        let over = Status::out_of_range("too large");
        let mut s = inbound(vec![Ok(hello()), Err(over.clone())]);
        s.hello().await.unwrap();
        violation(s.body().await);

        // On the client a status is the server's own error.
        let theirs = ContractError::version_mismatch("pin").to_status();
        let mut c: Inbound<_> =
            Inbound::from_server(tokio_stream::iter(vec![Err::<VerifyKzgRequest, _>(theirs)]));
        assert_eq!(
            c.hello().await.unwrap_err().code(),
            ErrorCode::VersionMismatch
        );
    }

    #[test]
    fn frames_round_trip_for_every_oneof_shape() {
        assert!(matches!(
            chain::ValidateRequest::body(chain::ValidateBatch::default()).into_frame(),
            Some(Frame::Body(_))
        ));
        assert!(matches!(
            chain::ValidateResponse::hello(Hello::default()).into_frame(),
            Some(Frame::Hello(_))
        ));
        assert!(matches!(
            store::GetDataColumnsResponse::body(Default::default()).into_frame(),
            Some(Frame::Body(_))
        ));
        assert!(discv5::WatchPeersResponse { frame: None }
            .into_frame()
            .is_none());
        assert!(matches!(
            p2p::RequestBlocksByRangeResponse::hello(Hello::default()).frame,
            Some(request_blocks_by_range_response::Frame::Hello(_))
        ));
        assert!(matches!(
            verify::PubkeyFeedResponse::body(Default::default()).frame,
            Some(pubkey_feed_response::Frame::Body(_))
        ));
    }

    #[test]
    fn hello_field_reads_and_sets_the_inline_hello() {
        let mut r = store::GetDataColumnsRequest::default();
        assert!(r.hello_field().is_none());
        r.set_hello_field(Some(Hello::default()));
        assert_eq!(r.hello_field(), Some(&Hello::default()));
    }

    #[test]
    fn seq_increases_strictly_from_one() {
        let mut c = SeqChecker::new();
        for s in 1..=3 {
            c.check(s).unwrap();
        }
        assert_eq!(c.last(), 3);
    }

    #[test]
    fn non_monotonic_seq_is_a_contract_violation() {
        assert!(violation(SeqChecker::new().check(0)).contains("decrease"));
        assert!(violation(SeqChecker::new().check(2)).contains("gap"));
        let mut c = SeqChecker::new();
        c.check(1).unwrap();
        c.check(2).unwrap();
        assert!(violation(c.check(2)).contains("repeat"));
        assert!(violation(c.check(1)).contains("decrease"));
        assert!(violation(c.check(4)).contains("gap"));
        assert_eq!(c.last(), 2, "a refused seq does not advance the checker");
        let mut end = SeqChecker { last: u64::MAX };
        violation(end.check(0));
    }

    #[test]
    fn counter_feeds_the_checker() {
        let (mut tx, mut rx) = (SeqCounter::new(), SeqChecker::new());
        for _ in 0..5 {
            rx.check(tx.next_seq()).unwrap();
        }
    }

    #[test]
    fn unary_seq_is_zero() {
        assert_eq!(check_unary_seq(0), Ok(()));
        violation(check_unary_seq(1));
    }
}
