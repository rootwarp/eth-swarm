//! Stream framing: every stream message is `oneof frame { Hello hello = 1; <Msg>Body body = 2; }`.
//! Each direction sends exactly one `hello`, first, then only `body` frames. A first frame that is
//! not `hello`, a `hello` mid-stream, or a frame with neither field set is
//! `ERROR_CODE_CONTRACT_VIOLATION` and closes the stream.

use tokio_stream::Stream;
use tonic::Status;

use crate::proto::common::{Error, Hello};

pub use ipc::frame::{Frame, InFrame, OutFrame};

/// Receiving side of a stream: the server reads the hello first, then bodies
/// ([`ipc::frame::Inbound::caller_ordered`], with errors in their `common.v1.Error` form).
pub struct Inbound<S> {
    inner: ipc::frame::Inbound<S>,
}

impl<S, T> Inbound<S>
where
    S: Stream<Item = Result<T, Status>> + Unpin,
    T: InFrame,
{
    pub fn new(stream: S) -> Self {
        Self {
            inner: ipc::frame::Inbound::caller_ordered(stream),
        }
    }

    /// The opening frame, which must be `hello`.
    pub async fn hello(&mut self) -> Result<Hello, Error> {
        self.inner.hello().await.map_err(Error::from)
    }

    /// The next `body` frame, or `None` once the peer closes its side.
    pub async fn body(&mut self) -> Result<Option<T::Body>, Error> {
        self.inner.body().await.map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::common::ErrorCode;
    use crate::proto::verify::{
        pubkey_feed_request, pubkey_feed_response, verify_bls_request, verify_bls_response,
        verify_kzg_request, PubkeyFeedRequest, PubkeyFeedResponse, PubkeyFeedResponseBody,
        VerifyBlsRequest, VerifyBlsResponse, VerifyKzgRequest, VerifyKzgRequestBody,
    };

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
