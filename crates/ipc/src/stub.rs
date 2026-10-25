//! Handlers for RPCs a service does not implement yet.
//!
//! The contract layer still runs in front of them, so a stub service already honours the wire
//! rules: a streaming RPC checks the peer's hello (and, on a bidi stream, every body: framing,
//! `seq`, envelope type and digest) and sends its own hello, with a fresh server generation
//! ([`stream_hello`]), before it fails with
//! `UNIMPLEMENTED`; a unary RPC checks the envelopes it carries (`seq` 0, type, digest) first.

use std::future::Future;
use std::pin::Pin;

pub use ethswarm_proto::common::Envelope;
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tokio_stream::Stream;
use tonic::service::Routes;
use tonic::{Request, Response, Status, Streaming};

use crate::envelope::Envelopes;
use crate::frame::{HelloField, InFrame, Inbound, OutFrame};
use crate::hello::stream_hello;
use crate::link::Link;

/// The response stream of a stub streaming RPC.
pub type StubStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// How every stub's `UNIMPLEMENTED` message ends, which tells it apart from tonic's own answer
/// to a call no service is routed for.
pub const NOT_IMPLEMENTED_SUFFIX: &str = " is not implemented yet";

/// `UNIMPLEMENTED` for `rpc` (`Service/Method`).
#[must_use]
pub fn not_implemented(rpc: &str) -> Status {
    Status::unimplemented(format!("{rpc}{NOT_IMPLEMENTED_SUFFIX}"))
}

/// A unary RPC: the envelopes it carries are checked, then the call fails `UNIMPLEMENTED`.
pub fn unary<T>(link: &Link, rpc: &str, envelopes: &[&Envelope]) -> Result<Response<T>, Status> {
    link.check_unary(envelopes).map_err(|e| e.to_status())?;
    Err(not_implemented(rpc))
}

/// A server-streaming RPC: the request's in-line hello is checked, our hello is sent, then the
/// stream fails `UNIMPLEMENTED`.
pub fn server_stream<Req, Resp>(
    link: &Link,
    rpc: &str,
    request: &Req,
) -> Result<Response<StubStream<Resp>>, Status>
where
    Req: HelloField,
    Resp: OutFrame + Send + 'static,
{
    link.accept_hello_field(request.hello_field())
        .map_err(|e| e.to_status())?;
    let (_, hello) = stream_hello(&link.local()).map_err(|e| e.to_status())?;
    let frames = vec![Ok(Resp::hello(hello)), Err(not_implemented(rpc))];
    Ok(Response::new(Box::pin(tokio_stream::iter(frames))))
}

/// A bidi RPC: the peer's hello is checked and ours sent, every body is checked until the peer
/// closes its side, then the stream fails `UNIMPLEMENTED`. The first contract error fails it
/// instead.
pub fn bidi<Req, Resp>(
    link: &Link,
    rpc: &'static str,
    request: Request<Streaming<Req>>,
) -> Result<Response<StubStream<Resp>>, Status>
where
    Req: InFrame + Send + 'static,
    Req::Body: Envelopes + Send,
    Resp: OutFrame + Send + 'static,
{
    let link = link.clone();
    let (tx, rx) = mpsc::channel(4);
    crate::spawn_in_span(async move {
        let end = async {
            let mut guarded = link.open(Inbound::new(request.into_inner())).await?;
            let (_, hello) = stream_hello(&link.local())?;
            if tx.send(Ok(Resp::hello(hello))).await.is_err() {
                return Ok(());
            }
            while guarded.body().await?.is_some() {}
            Ok(())
        };
        let status = match end.await {
            Ok(()) => not_implemented(rpc),
            Err(e) => crate::ContractError::to_status(&e),
        };
        let _ = tx.send(Err(status)).await;
    });
    Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
}

/// Implements a generated tonic service trait with stub handlers ([`unary`],
/// [`server_stream`], [`bidi`]). `$svc` must have `fn link(&self) -> &ipc::Link`. A unary RPC
/// listed under `unary_envelopes` names the envelopes its request carries.
///
/// ```ignore
/// ipc::stub_service!(ChainStub => chain::query_service_server::QueryService {
///     unary: [get_fork_choice(GetForkChoiceRequest) -> GetForkChoiceResponse],
///     unary_envelopes: [submit(SubmitRequest) -> SubmitResponse => |r| r.items.iter().collect()],
///     server_stream: [],
///     bidi: [],
/// });
/// ```
#[macro_export]
macro_rules! stub_service {
    ($svc:ty => $trait:path {
        unary: [$($u:ident($ureq:ty) -> $uresp:ty),* $(,)?],
        unary_envelopes: [$($e:ident($ereq:ty) -> $eresp:ty => |$r:ident| $envs:expr),* $(,)?],
        server_stream: [$($s:ident($sreq:ty) -> $sresp:ty as $sstream:ident),* $(,)?],
        bidi: [$($b:ident($breq:ty) -> $bresp:ty as $bstream:ident),* $(,)?] $(,)?
    }) => {
        #[::tonic::async_trait]
        impl $trait for $svc {
            $(
                async fn $u(
                    &self,
                    _request: ::tonic::Request<$ureq>,
                ) -> ::std::result::Result<::tonic::Response<$uresp>, ::tonic::Status> {
                    $crate::stub::unary(self.link(), stringify!($u), &[])
                }
            )*
            $(
                async fn $e(
                    &self,
                    request: ::tonic::Request<$ereq>,
                ) -> ::std::result::Result<::tonic::Response<$eresp>, ::tonic::Status> {
                    let $r = request.get_ref();
                    let envelopes: ::std::vec::Vec<&$crate::stub::Envelope> = $envs;
                    $crate::stub::unary(self.link(), stringify!($e), &envelopes)
                }
            )*
            $(
                type $sstream = $crate::stub::StubStream<$sresp>;
                async fn $s(
                    &self,
                    request: ::tonic::Request<$sreq>,
                ) -> ::std::result::Result<::tonic::Response<Self::$sstream>, ::tonic::Status> {
                    $crate::stub::server_stream(self.link(), stringify!($s), request.get_ref())
                }
            )*
            $(
                type $bstream = $crate::stub::StubStream<$bresp>;
                async fn $b(
                    &self,
                    request: ::tonic::Request<::tonic::Streaming<$breq>>,
                ) -> ::std::result::Result<::tonic::Response<Self::$bstream>, ::tonic::Status> {
                    $crate::stub::bidi(self.link(), stringify!($b), request)
                }
            )*
        }
    };
}

/// Serves `routes` on a Unix socket until `shutdown` resolves.
pub async fn serve_uds(
    listener: UnixListener,
    routes: Routes,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), tonic::transport::Error> {
    tonic::transport::Server::builder()
        .add_routes(routes)
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethswarm_proto::common::{ErrorCode, Hello};
    use ethswarm_proto::store::{GetDataColumnsRequest, GetDataColumnsResponse};
    use tokio_stream::StreamExt;

    fn link() -> Link {
        use network_config::{ForkName, ForkSchedule, ScheduledFork};
        let at = |epoch| ScheduledFork {
            version: [0; 4],
            epoch,
        };
        let digests = crate::envelope::DigestTable::new(vec![(0, ForkName::Fulu, [1; 4])]).unwrap();
        let hello = Hello {
            api_version: 1,
            min_api_version: 1,
            max_api_version: 1,
            ..Default::default()
        };
        Link::new::<consensus_types::Mainnet>(
            hello,
            1,
            ForkSchedule::new(at(0), at(u64::MAX)).unwrap(),
            digests,
        )
    }

    #[tokio::test]
    async fn server_stream_checks_the_inline_hello_then_is_unimplemented() {
        let l = link();
        let missing = server_stream::<_, GetDataColumnsResponse>(
            &l,
            "StoreService/GetDataColumns",
            &GetDataColumnsRequest::default(),
        );
        let status = missing.err().unwrap();
        assert_eq!(
            crate::ContractError::from_status(&status).code(),
            ErrorCode::ContractViolation
        );
        let mut ok = GetDataColumnsRequest::default();
        ok.set_hello_field(Some(l.local()));
        let mut s = server_stream::<_, GetDataColumnsResponse>(&l, "S/M", &ok)
            .unwrap()
            .into_inner();
        match s.next().await.unwrap().unwrap().into_frame() {
            Some(crate::frame::Frame::Hello(h)) => {
                assert!(crate::hello::Generation::from_hello(&h).is_ok(), "{h:?}");
            }
            other => panic!("first frame {other:?}"),
        }
        assert_eq!(
            s.next().await.unwrap().unwrap_err().code(),
            tonic::Code::Unimplemented
        );
    }

    #[test]
    fn unary_checks_envelopes_then_is_unimplemented() {
        let l = link();
        let bad = Envelope {
            seq: 3,
            ..Default::default()
        };
        let status = unary::<()>(&l, "S/M", &[&bad]).unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        let status = unary::<()>(&l, "S/M", &[]).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unimplemented);
        assert!(status.message().contains("S/M"));
    }
}
