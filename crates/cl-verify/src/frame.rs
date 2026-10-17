//! Stream framing: every stream message is `oneof frame { Hello hello = 1; <Msg>Body body = 2; }`.
//! Each direction sends exactly one `hello`, first, then only `body` frames. A first frame that is
//! not `hello`, a `hello` mid-stream, or a frame with neither field set is
//! `ERROR_CODE_CONTRACT_VIOLATION` and closes the stream.

use tokio_stream::{Stream, StreamExt};
use tonic::Status;

use crate::proto::common::{Error, ErrorCode, Hello};
use crate::proto::verify::{
    pubkey_feed_request, pubkey_feed_response, verify_bls_request, verify_bls_response,
    verify_kzg_request, verify_kzg_response, PubkeyFeedRequest, PubkeyFeedRequestBody,
    PubkeyFeedResponse, PubkeyFeedResponseBody, VerifyBlsRequest, VerifyBlsRequestBody,
    VerifyBlsResponse, VerifyBlsResponseBody, VerifyKzgRequest, VerifyKzgRequestBody,
    VerifyKzgResponse, VerifyKzgResponseBody,
};
use crate::wire::{inbound_error, wire_error};

/// One decoded frame.
#[derive(Debug, PartialEq)]
pub enum Frame<B> {
    Hello(Hello),
    Body(B),
}

/// A request message carrying `oneof frame`.
pub trait InFrame {
    type Body;
    /// `None` when neither `hello` nor `body` is set.
    fn into_frame(self) -> Option<Frame<Self::Body>>;
}

/// A response message carrying `oneof frame`.
pub trait OutFrame {
    type Body;
    fn hello(hello: Hello) -> Self;
    fn body(body: Self::Body) -> Self;
}

macro_rules! framed {
    ($req:ty, $req_mod:ident, $req_body:ty, $resp:ty, $resp_mod:ident, $resp_body:ty) => {
        impl InFrame for $req {
            type Body = $req_body;
            fn into_frame(self) -> Option<Frame<$req_body>> {
                match self.frame? {
                    $req_mod::Frame::Hello(h) => Some(Frame::Hello(h)),
                    $req_mod::Frame::Body(b) => Some(Frame::Body(b)),
                }
            }
        }
        impl OutFrame for $resp {
            type Body = $resp_body;
            fn hello(hello: Hello) -> Self {
                Self {
                    frame: Some($resp_mod::Frame::Hello(hello)),
                }
            }
            fn body(body: $resp_body) -> Self {
                Self {
                    frame: Some($resp_mod::Frame::Body(body)),
                }
            }
        }
    };
}

framed!(
    VerifyBlsRequest,
    verify_bls_request,
    VerifyBlsRequestBody,
    VerifyBlsResponse,
    verify_bls_response,
    VerifyBlsResponseBody
);
framed!(
    VerifyKzgRequest,
    verify_kzg_request,
    VerifyKzgRequestBody,
    VerifyKzgResponse,
    verify_kzg_response,
    VerifyKzgResponseBody
);
framed!(
    PubkeyFeedRequest,
    pubkey_feed_request,
    PubkeyFeedRequestBody,
    PubkeyFeedResponse,
    pubkey_feed_response,
    PubkeyFeedResponseBody
);

/// Receiving side of a stream that enforces the hello-first discipline.
pub struct Inbound<S> {
    stream: S,
}

impl<S, T> Inbound<S>
where
    S: Stream<Item = Result<T, Status>> + Unpin,
    T: InFrame,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// The opening frame, which must be `hello`.
    pub async fn hello(&mut self) -> Result<Hello, Error> {
        match self.next().await? {
            Some(Frame::Hello(h)) => Ok(h),
            Some(Frame::Body(_)) => Err(violation("first frame is not hello")),
            None => Err(violation("stream closed before hello")),
        }
    }

    /// The next `body` frame, or `None` once the peer closes its side.
    pub async fn body(&mut self) -> Result<Option<T::Body>, Error> {
        match self.next().await? {
            Some(Frame::Body(b)) => Ok(Some(b)),
            Some(Frame::Hello(_)) => Err(violation("hello mid-stream")),
            None => Ok(None),
        }
    }

    async fn next(&mut self) -> Result<Option<Frame<T::Body>>, Error> {
        match self.stream.next().await {
            None => Ok(None),
            Some(Err(status)) => Err(inbound_error(&status)),
            Some(Ok(msg)) => msg
                .into_frame()
                .map(Some)
                .ok_or_else(|| violation("frame has neither hello nor body")),
        }
    }
}

fn violation(detail: &str) -> Error {
    wire_error(ErrorCode::ContractViolation, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> VerifyKzgRequest {
        VerifyKzgRequest {
            frame: Some(verify_kzg_request::Frame::Hello(Hello::default())),
        }
    }

    fn body(id: u64) -> VerifyKzgRequest {
        VerifyKzgRequest {
            frame: Some(verify_kzg_request::Frame::Body(VerifyKzgRequestBody {
                request_id: id,
                ..Default::default()
            })),
        }
    }

    fn inbound(
        frames: Vec<Result<VerifyKzgRequest, Status>>,
    ) -> Inbound<impl Stream<Item = Result<VerifyKzgRequest, Status>> + Unpin> {
        Inbound::new(tokio_stream::iter(frames))
    }

    #[tokio::test]
    async fn hello_then_bodies_then_end() {
        let mut s = inbound(vec![Ok(hello()), Ok(body(1)), Ok(body(2))]);
        assert_eq!(s.hello().await, Ok(Hello::default()));
        assert_eq!(s.body().await.unwrap().unwrap().request_id, 1);
        assert_eq!(s.body().await.unwrap().unwrap().request_id, 2);
        assert_eq!(s.body().await, Ok(None));
    }

    #[tokio::test]
    async fn body_first_is_a_contract_violation() {
        let err = inbound(vec![Ok(body(1))]).hello().await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
    }

    #[tokio::test]
    async fn close_before_hello_is_a_contract_violation() {
        let err = inbound(vec![]).hello().await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
    }

    #[tokio::test]
    async fn second_hello_is_a_contract_violation() {
        let mut s = inbound(vec![Ok(hello()), Ok(hello())]);
        s.hello().await.unwrap();
        assert_eq!(
            s.body().await.unwrap_err().code(),
            ErrorCode::ContractViolation
        );
    }

    #[tokio::test]
    async fn empty_frame_is_a_contract_violation() {
        let mut s = inbound(vec![Ok(VerifyKzgRequest { frame: None })]);
        assert_eq!(
            s.hello().await.unwrap_err().code(),
            ErrorCode::ContractViolation
        );
    }

    #[tokio::test]
    async fn transport_error_is_mapped() {
        let mut s = inbound(vec![Ok(hello()), Err(Status::out_of_range("too large"))]);
        s.hello().await.unwrap();
        assert_eq!(
            s.body().await.unwrap_err().code(),
            ErrorCode::ContractViolation
        );
    }

    #[test]
    fn out_frames_wrap_hello_and_body() {
        assert!(matches!(
            VerifyBlsResponse::hello(Hello::default()).frame,
            Some(verify_bls_response::Frame::Hello(_))
        ));
        assert!(matches!(
            PubkeyFeedResponse::body(PubkeyFeedResponseBody::default()).frame,
            Some(pubkey_feed_response::Frame::Body(_))
        ));
        assert!(matches!(
            PubkeyFeedRequest {
                frame: Some(pubkey_feed_request::Frame::Hello(Hello::default()))
            }
            .into_frame(),
            Some(Frame::Hello(_))
        ));
        assert!(matches!(
            VerifyBlsRequest {
                frame: Some(verify_bls_request::Frame::Body(Default::default()))
            }
            .into_frame(),
            Some(Frame::Body(_))
        ));
    }
}
