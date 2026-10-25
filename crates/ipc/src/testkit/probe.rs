//! Probes: typed access to one streaming RPC of a service, driven by message-agnostic
//! [`Step`]s, plus a scripted peer that plays the server side of the same RPC.
//!
//! The client half of a probe ([`Probe::call`]) sends steps to the service under test and
//! records what it answers. The scripted half ([`Probe::scripted`]) answers any call with
//! given steps, so the suite can check the receiving rules on the client side of the link
//! ([`Probe::guarded_call`]): a service's peers hold it to the same contract.

use std::convert::Infallible;
use std::marker::PhantomData;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use ethswarm_proto::common::{Envelope, Hello};
use ethswarm_proto::{chain, discv5, p2p, store, verify};
use http::uri::PathAndQuery;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::body::Body;
use tonic::client::Grpc;
use tonic::server::NamedService;
use tonic::service::Routes;
use tonic::{Request, Response, Status, Streaming};
use tonic_prost::ProstCodec;

use super::{BoxFuture, Server, Transport};
use crate::envelope::Envelopes;
use crate::error::ContractError;
use crate::frame::{Frame, HelloField, InFrame, Inbound, OutFrame};
use crate::link::Link;

/// How long a probe waits for the service before the test fails.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);

/// One frame a probe sends, independent of the message type.
#[derive(Clone, Debug, PartialEq)]
pub enum Step {
    /// A `hello` frame (or, on a server-streaming request, the in-line hello).
    Hello(Hello),
    /// A `body` frame carrying these envelopes (bodies without envelopes ignore them).
    Body(Vec<Envelope>),
    /// A message with neither `hello` nor `body` set.
    Empty,
}

/// What the service answered on one stream.
#[derive(Debug)]
pub struct Answer {
    /// Response frames in order (`None`: neither field set).
    pub frames: Vec<Option<Frame<()>>>,
    /// How the response stream ended: `Ok` or the status it failed with.
    pub end: Result<(), Status>,
}

impl Answer {
    /// The server's hello, if it opened the response with exactly one.
    #[must_use]
    pub fn server_hello(&self) -> Option<&Hello> {
        match self.frames.first() {
            Some(Some(Frame::Hello(h))) => Some(h),
            _ => None,
        }
    }

    /// The contract error the stream failed with. `UNIMPLEMENTED` (a stub handler was reached)
    /// and a clean end are not errors.
    #[must_use]
    pub fn error(&self) -> Option<ContractError> {
        match &self.end {
            Err(s) if s.code() != tonic::Code::Unimplemented => Some(ContractError::from_status(s)),
            _ => None,
        }
    }

    /// The handler behind the contract layer was reached (nothing failed the stream first).
    #[must_use]
    pub fn reached_handler(&self) -> bool {
        self.error().is_none()
    }
}

/// What the ipc client guard made of a scripted response stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardReport {
    pub version: u32,
    pub bodies: usize,
    /// Envelopes dropped (IGNORE or digest mismatch).
    pub dropped: usize,
}

/// One streaming RPC of a service.
pub trait Probe: Send + Sync + 'static {
    /// `/<package>.<Service>/<Method>`.
    fn rpc(&self) -> &'static str;
    /// Bidi stream (else server-streaming, with the client's hello in-line in the request).
    fn bidi(&self) -> bool;
    /// Request bodies carry envelopes.
    fn request_envelopes(&self) -> bool;
    /// Response bodies carry envelopes.
    fn response_envelopes(&self) -> bool;
    /// Sends `steps` to the service (a server-streaming request uses only a leading hello),
    /// closes the request side and collects the answer.
    fn call(&self, transport: Transport, steps: Vec<Step>) -> BoxFuture<Answer>;
    /// A server for this RPC that answers every call with `steps`, then ends cleanly.
    fn scripted(&self, steps: Vec<Step>) -> Server;
    /// Calls with `link`'s hello and reads the response through `link`'s guard.
    fn guarded_call(
        &self,
        transport: Transport,
        link: Link,
    ) -> BoxFuture<Result<GuardReport, ContractError>>;
}

/// A unary RPC whose request carries envelopes.
pub trait UnaryProbe: Send + Sync + 'static {
    fn rpc(&self) -> &'static str;
    /// Calls with a request carrying `envelopes`; `Err` is the status it failed with.
    fn call(&self, transport: Transport, envelopes: Vec<Envelope>)
        -> BoxFuture<Result<(), Status>>;
}

/// Builds a body from probe envelopes; `index` counts bodies from 0 on the stream.
pub trait FromEnvelopes: Sized {
    fn from_envelopes(envelopes: Vec<Envelope>, index: u64) -> Self;

    /// The body as sent on a stream whose server hello announced `generation`. Fenced request
    /// bodies carry it; every other body ignores it.
    fn with_generation(self, _generation: u64) -> Self {
        self
    }
}

impl FromEnvelopes for chain::ImportBatchRequestBody {
    fn from_envelopes(envelopes: Vec<Envelope>, index: u64) -> Self {
        Self {
            batch_id: index.to_be_bytes().to_vec(),
            blocks: envelopes,
            ..Default::default()
        }
    }
}

impl FromEnvelopes for chain::ImportBatchResponseBody {
    fn from_envelopes(_: Vec<Envelope>, index: u64) -> Self {
        Self {
            batch_id: index.to_be_bytes().to_vec(),
            ..Default::default()
        }
    }
}

impl FromEnvelopes for verify::VerifyBlsRequestBody {
    fn from_envelopes(_: Vec<Envelope>, index: u64) -> Self {
        Self {
            request_id: index + 1,
            origin: verify::VerifyOrigin::Gossip as i32,
            ..Default::default()
        }
    }

    fn with_generation(self, generation: u64) -> Self {
        Self { generation, ..self }
    }
}

impl FromEnvelopes for verify::VerifyBlsResponseBody {
    fn from_envelopes(_: Vec<Envelope>, index: u64) -> Self {
        Self {
            request_id: index + 1,
            ..Default::default()
        }
    }
}

impl FromEnvelopes for store::GetDataColumnsResponseBody {
    fn from_envelopes(envelopes: Vec<Envelope>, _: u64) -> Self {
        Self {
            column: envelopes.into_iter().next(),
            ..Default::default()
        }
    }
}

/// A chunk carries its envelope; without one it carries an error, since a chunk with neither is
/// a contract violation.
impl FromEnvelopes for p2p::RequestBlocksByRangeResponseBody {
    fn from_envelopes(envelopes: Vec<Envelope>, _: u64) -> Self {
        let result = match envelopes.into_iter().next() {
            Some(e) => p2p::response_chunk::Result::Chunk(e),
            None => p2p::response_chunk::Result::Error(crate::error::wire_error(
                ethswarm_proto::common::ErrorCode::ResourceUnavailable,
                "probe body without an envelope",
            )),
        };
        Self {
            item: Some(p2p::ResponseChunk {
                peer: None,
                result: Some(result),
            }),
        }
    }
}

impl FromEnvelopes for discv5::WatchPeersResponseBody {
    fn from_envelopes(_: Vec<Envelope>, _: u64) -> Self {
        Self::default()
    }
}

/// The service a probe's RPC belongs to.
pub trait ServiceName: Send + Sync + 'static {
    /// `<package>.<Service>`.
    const NAME: &'static str;
}

macro_rules! service_names {
    ($($ty:ident = $name:literal),* $(,)?) => {
        $(
            #[doc = concat!("`", $name, "`.")]
            pub struct $ty;
            impl ServiceName for $ty {
                const NAME: &'static str = $name;
            }
        )*
    };
}

service_names!(
    ImportService = "ethswarm.chain.v1.ImportService",
    QueryService = "ethswarm.chain.v1.QueryService",
    StoreService = "ethswarm.store.v1.StoreService",
    NetworkService = "ethswarm.p2p.v1.NetworkService",
    DiscoveryService = "ethswarm.discv5.v1.DiscoveryService",
    VerifyService = "ethswarm.verify.v1.VerifyService",
);

fn steps_to_messages<M>(steps: &[Step]) -> Vec<M>
where
    M: OutFrame + Default,
    M::Body: FromEnvelopes,
{
    stamped_messages(steps, 0)
}

/// [`steps_to_messages`] with every body stamped with the stream's server `generation`.
fn stamped_messages<M>(steps: &[Step], generation: u64) -> Vec<M>
where
    M: OutFrame + Default,
    M::Body: FromEnvelopes,
{
    let mut bodies = 0;
    steps
        .iter()
        .map(|s| match s {
            Step::Hello(h) => M::hello(h.clone()),
            Step::Body(envelopes) => {
                bodies += 1;
                M::body(
                    M::Body::from_envelopes(envelopes.clone(), bodies - 1)
                        .with_generation(generation),
                )
            }
            Step::Empty => M::default(),
        })
        .collect()
}

fn path(rpc: &'static str) -> PathAndQuery {
    PathAndQuery::from_static(rpc)
}

async fn collect<M: InFrame>(response: Result<Response<Streaming<M>>, Status>) -> Answer {
    match response {
        Ok(r) => collect_rest(r.into_inner(), Vec::new()).await,
        Err(status) => Answer {
            frames: Vec::new(),
            end: Err(status),
        },
    }
}

/// The rest of a response stream, after the `frames` already read.
async fn collect_rest<M: InFrame>(
    mut stream: Streaming<M>,
    mut frames: Vec<Option<Frame<()>>>,
) -> Answer {
    let end = loop {
        match stream.next().await {
            None => break Ok(()),
            Some(Err(status)) => break Err(status),
            Some(Ok(msg)) => frames.push(erase(msg)),
        }
    };
    Answer { frames, end }
}

fn erase<M: InFrame>(msg: M) -> Option<Frame<()>> {
    msg.into_frame().map(|f| match f {
        Frame::Hello(h) => Frame::Hello(h),
        Frame::Body(_) => Frame::Body(()),
    })
}

async fn ready(transport: Transport) -> Result<Grpc<Transport>, Status> {
    let mut grpc = Grpc::new(transport);
    grpc.ready()
        .await
        .map_err(|e| Status::unavailable(format!("transport not ready: {e}")))?;
    Ok(grpc)
}

async fn within<T>(rpc: &str, fut: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(ANSWER_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| panic!("{rpc}: no answer within {ANSWER_TIMEOUT:?}"))
}

async fn guard<M>(
    link: Link,
    response: Result<Response<Streaming<M>>, Status>,
) -> Result<GuardReport, ContractError>
where
    M: InFrame,
    M::Body: Envelopes,
{
    let stream = response
        .map_err(|s| ContractError::from_status(&s))?
        .into_inner();
    let mut guarded = link.open(Inbound::from_server(stream)).await?;
    let mut report = GuardReport {
        version: guarded.version(),
        bodies: 0,
        dropped: 0,
    };
    while let Some(accepted) = guarded.body().await? {
        report.bodies += 1;
        report.dropped += accepted.dropped.len();
    }
    Ok(report)
}

/// Ties a probe to its message and service types without owning any.
type Types<Req, Resp, N> = PhantomData<fn() -> (Req, Resp, N)>;

/// A bidi RPC: `Req` and `Resp` are its `oneof frame` messages.
pub struct BidiProbe<Req, Resp, N> {
    rpc: &'static str,
    request_envelopes: bool,
    response_envelopes: bool,
    _types: Types<Req, Resp, N>,
}

/// A server-streaming RPC: `Req` carries the hello in-line, `Resp` is `oneof frame`.
pub struct ServerStreamProbe<Req, Resp, N> {
    rpc: &'static str,
    response_envelopes: bool,
    _types: Types<Req, Resp, N>,
}

impl<Req, Resp, N> BidiProbe<Req, Resp, N> {
    #[must_use]
    pub fn new(rpc: &'static str, request_envelopes: bool, response_envelopes: bool) -> Self {
        Self {
            rpc,
            request_envelopes,
            response_envelopes,
            _types: PhantomData,
        }
    }
}

impl<Req, Resp, N> ServerStreamProbe<Req, Resp, N> {
    #[must_use]
    pub fn new(rpc: &'static str, response_envelopes: bool) -> Self {
        Self {
            rpc,
            response_envelopes,
            _types: PhantomData,
        }
    }
}

/// Bounds shared by every probe message.
pub trait Message: prost::Message + Default + Clone + Send + Sync + 'static {}
impl<T: prost::Message + Default + Clone + Send + Sync + 'static> Message for T {}

impl<Req, Resp, N> Probe for BidiProbe<Req, Resp, N>
where
    Req: Message + OutFrame + InFrame,
    <Req as OutFrame>::Body: FromEnvelopes,
    Resp: Message + OutFrame + InFrame,
    <Resp as OutFrame>::Body: FromEnvelopes,
    <Resp as InFrame>::Body: Envelopes,
    N: ServiceName,
{
    fn rpc(&self) -> &'static str {
        self.rpc
    }
    fn bidi(&self) -> bool {
        true
    }
    fn request_envelopes(&self) -> bool {
        self.request_envelopes
    }
    fn response_envelopes(&self) -> bool {
        self.response_envelopes
    }

    /// A stream that opens with our hello waits for the service's first frame before the rest,
    /// as a client of a fenced stream must, and stamps every body with the server generation
    /// that hello announced. Any other opening is sent in one go.
    fn call(&self, transport: Transport, steps: Vec<Step>) -> BoxFuture<Answer> {
        let rpc = self.rpc;
        Box::pin(within(rpc, async move {
            let mut grpc = match ready(transport).await {
                Ok(grpc) => grpc,
                Err(s) => return collect::<Resp>(Err(s)).await,
            };
            let codec = ProstCodec::<Req, Resp>::default;
            if !matches!(steps.first(), Some(Step::Hello(_))) {
                let messages: Vec<Req> = steps_to_messages(&steps);
                let response = grpc
                    .streaming(
                        Request::new(tokio_stream::iter(messages)),
                        path(rpc),
                        codec(),
                    )
                    .await;
                return collect(response).await;
            }
            let (tx, rx) = mpsc::channel(steps.len());
            let opening: Vec<Req> = steps_to_messages(&steps[..1]);
            for m in opening {
                tx.send(m).await.expect("request channel open");
            }
            let response = grpc
                .streaming(Request::new(ReceiverStream::new(rx)), path(rpc), codec())
                .await;
            let mut stream = match response {
                Ok(r) => r.into_inner(),
                Err(status) => return collect::<Resp>(Err(status)).await,
            };
            let first = match stream.next().await {
                None => {
                    return Answer {
                        frames: Vec::new(),
                        end: Ok(()),
                    }
                }
                Some(Err(status)) => {
                    return Answer {
                        frames: Vec::new(),
                        end: Err(status),
                    }
                }
                Some(Ok(msg)) => erase(msg),
            };
            let generation = match &first {
                Some(Frame::Hello(h)) => h.generation,
                _ => 0,
            };
            let rest: Vec<Req> = stamped_messages(&steps, generation);
            for m in rest.into_iter().skip(1) {
                // The service may already have failed the stream; its answer says so.
                if tx.send(m).await.is_err() {
                    break;
                }
            }
            drop(tx);
            collect_rest(stream, vec![first]).await
        }))
    }

    fn scripted(&self, steps: Vec<Step>) -> Server {
        let frames: Vec<Resp> = steps_to_messages(&steps);
        Server::new(Routes::new(Scripted::<Req, Resp, N> {
            rpc: self.rpc,
            frames: Arc::new(frames),
            bidi: true,
            _types: PhantomData,
        }))
    }

    fn guarded_call(
        &self,
        transport: Transport,
        link: Link,
    ) -> BoxFuture<Result<GuardReport, ContractError>> {
        let rpc = self.rpc;
        Box::pin(within(rpc, async move {
            let hello = vec![Req::hello(link.local())];
            let mut grpc = ready(transport)
                .await
                .map_err(|s| ContractError::from_status(&s))?;
            let response = grpc
                .streaming(
                    Request::new(tokio_stream::iter(hello)),
                    path(rpc),
                    ProstCodec::<Req, Resp>::default(),
                )
                .await;
            guard(link, response).await
        }))
    }
}

impl<Req, Resp, N> Probe for ServerStreamProbe<Req, Resp, N>
where
    Req: Message + HelloField,
    Resp: Message + OutFrame + InFrame,
    <Resp as OutFrame>::Body: FromEnvelopes,
    <Resp as InFrame>::Body: Envelopes,
    N: ServiceName,
{
    fn rpc(&self) -> &'static str {
        self.rpc
    }
    fn bidi(&self) -> bool {
        false
    }
    fn request_envelopes(&self) -> bool {
        false
    }
    fn response_envelopes(&self) -> bool {
        self.response_envelopes
    }

    fn call(&self, transport: Transport, steps: Vec<Step>) -> BoxFuture<Answer> {
        let rpc = self.rpc;
        Box::pin(within(rpc, async move {
            let mut request = Req::default();
            if let Some(Step::Hello(h)) = steps.first() {
                request.set_hello_field(Some(h.clone()));
            }
            let response = match ready(transport).await {
                Ok(mut grpc) => {
                    grpc.server_streaming(
                        Request::new(request),
                        path(rpc),
                        ProstCodec::<Req, Resp>::default(),
                    )
                    .await
                }
                Err(s) => Err(s),
            };
            collect(response).await
        }))
    }

    fn scripted(&self, steps: Vec<Step>) -> Server {
        let frames: Vec<Resp> = steps_to_messages(&steps);
        Server::new(Routes::new(Scripted::<Req, Resp, N> {
            rpc: self.rpc,
            frames: Arc::new(frames),
            bidi: false,
            _types: PhantomData,
        }))
    }

    fn guarded_call(
        &self,
        transport: Transport,
        link: Link,
    ) -> BoxFuture<Result<GuardReport, ContractError>> {
        let rpc = self.rpc;
        Box::pin(within(rpc, async move {
            let mut request = Req::default();
            request.set_hello_field(Some(link.local()));
            let mut grpc = ready(transport)
                .await
                .map_err(|s| ContractError::from_status(&s))?;
            let response = grpc
                .server_streaming(
                    Request::new(request),
                    path(rpc),
                    ProstCodec::<Req, Resp>::default(),
                )
                .await;
            guard(link, response).await
        }))
    }
}

/// A unary RPC whose request is built from envelopes.
pub struct EnvelopeUnaryProbe<Req, Resp> {
    rpc: &'static str,
    build: fn(Vec<Envelope>) -> Req,
    _types: PhantomData<fn() -> Resp>,
}

impl<Req, Resp> EnvelopeUnaryProbe<Req, Resp> {
    #[must_use]
    pub fn new(rpc: &'static str, build: fn(Vec<Envelope>) -> Req) -> Self {
        Self {
            rpc,
            build,
            _types: PhantomData,
        }
    }
}

impl<Req: Message, Resp: Message> UnaryProbe for EnvelopeUnaryProbe<Req, Resp> {
    fn rpc(&self) -> &'static str {
        self.rpc
    }

    fn call(
        &self,
        transport: Transport,
        envelopes: Vec<Envelope>,
    ) -> BoxFuture<Result<(), Status>> {
        let (rpc, request) = (self.rpc, (self.build)(envelopes));
        Box::pin(within(rpc, async move {
            ready(transport)
                .await?
                .unary(
                    Request::new(request),
                    path(rpc),
                    ProstCodec::<Req, Resp>::default(),
                )
                .await
                .map(|_| ())
        }))
    }
}

/// Calls unary `rpc` with an empty request, whatever its request type (an empty protobuf
/// message decodes as any message), and returns the status it failed with, if any.
pub async fn call_unary_empty(transport: Transport, rpc: &str) -> Result<(), Status> {
    let path = PathAndQuery::try_from(rpc.to_owned())
        .map_err(|e| Status::invalid_argument(format!("rpc path {rpc}: {e}")))?;
    within(rpc, async move {
        ready(transport)
            .await?
            .unary(Request::new(()), path, ProstCodec::<(), ()>::default())
            .await
            .map(|_| ())
    })
    .await
}

/// The scripted server side of one probe RPC.
struct Scripted<Req, Resp, N> {
    rpc: &'static str,
    frames: Arc<Vec<Resp>>,
    bidi: bool,
    _types: PhantomData<fn() -> (Req, N)>,
}

impl<Req, Resp, N> Clone for Scripted<Req, Resp, N> {
    fn clone(&self) -> Self {
        Self {
            rpc: self.rpc,
            frames: Arc::clone(&self.frames),
            bidi: self.bidi,
            _types: PhantomData,
        }
    }
}

impl<Req, Resp, N: ServiceName> NamedService for Scripted<Req, Resp, N> {
    const NAME: &'static str = N::NAME;
}

impl<Req, Resp, N> tower::Service<http::Request<Body>> for Scripted<Req, Resp, N>
where
    Req: Message,
    Resp: Message,
{
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<Result<http::Response<Body>, Infallible>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        if req.uri().path() != self.rpc {
            let status = Status::unimplemented(format!("scripted peer serves {}", self.rpc));
            return Box::pin(async move { Ok(status.into_http()) });
        }
        let frames = Arc::clone(&self.frames);
        let reply = move || {
            let items: Vec<Result<Resp, Status>> = frames.iter().cloned().map(Ok).collect();
            async move { Ok::<_, Status>(Response::new(tokio_stream::iter(items))) }
        };
        let mut grpc = tonic::server::Grpc::new(ProstCodec::<Resp, Req>::default());
        if self.bidi {
            let svc = tower::service_fn(move |_: Request<Streaming<Req>>| reply());
            Box::pin(async move { Ok(grpc.streaming(svc, req).await) })
        } else {
            let svc = tower::service_fn(move |_: Request<Req>| reply());
            Box::pin(async move { Ok(grpc.server_streaming(svc, req).await) })
        }
    }
}

/// `chain.v1.ImportService/ImportBatch`: bidi, request bodies carry blocks.
#[must_use]
pub fn chain_import_batch() -> Arc<dyn Probe> {
    Arc::new(BidiProbe::<
        chain::ImportBatchRequest,
        chain::ImportBatchResponse,
        ImportService,
    >::new(
        "/ethswarm.chain.v1.ImportService/ImportBatch",
        true,
        false,
    ))
}

/// `chain.v1.QueryService/Submit`: unary, the request carries envelopes (`seq` 0).
#[must_use]
pub fn chain_submit() -> Arc<dyn UnaryProbe> {
    Arc::new(EnvelopeUnaryProbe::<
        chain::SubmitRequest,
        chain::SubmitResponse,
    >::new(
        "/ethswarm.chain.v1.QueryService/Submit",
        |items| chain::SubmitRequest { items },
    ))
}

/// `store.v1.StoreService/GetDataColumns`: server-streaming, response bodies carry columns.
#[must_use]
pub fn store_get_data_columns() -> Arc<dyn Probe> {
    Arc::new(ServerStreamProbe::<
        store::GetDataColumnsRequest,
        store::GetDataColumnsResponse,
        StoreService,
    >::new(
        "/ethswarm.store.v1.StoreService/GetDataColumns", true
    ))
}

/// `p2p.v1.NetworkService/RequestBlocksByRange`: server-streaming, response chunks carry blocks.
#[must_use]
pub fn p2p_request_blocks_by_range() -> Arc<dyn Probe> {
    Arc::new(ServerStreamProbe::<
        p2p::RequestBlocksByRangeRequest,
        p2p::RequestBlocksByRangeResponse,
        NetworkService,
    >::new(
        "/ethswarm.p2p.v1.NetworkService/RequestBlocksByRange",
        true,
    ))
}

/// `discv5.v1.DiscoveryService/WatchPeers`: server-streaming, no envelopes.
#[must_use]
pub fn discv5_watch_peers() -> Arc<dyn Probe> {
    Arc::new(ServerStreamProbe::<
        discv5::WatchPeersRequest,
        discv5::WatchPeersResponse,
        DiscoveryService,
    >::new(
        "/ethswarm.discv5.v1.DiscoveryService/WatchPeers", false
    ))
}

/// `verify.v1.VerifyService/VerifyBls`: bidi, no envelopes.
#[must_use]
pub fn verify_bls() -> Arc<dyn Probe> {
    Arc::new(BidiProbe::<
        verify::VerifyBlsRequest,
        verify::VerifyBlsResponse,
        VerifyService,
    >::new(
        "/ethswarm.verify.v1.VerifyService/VerifyBls",
        false,
        false,
    ))
}
