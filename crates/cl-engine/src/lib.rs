//! `cl-engine`: serves `ethswarm.engine.v1`, the ordered, stateless Engine API adapter (the only holder of the JWT secret).
//!
//! This is a stub. Every RPC runs the `ipc` contract layer first (hello negotiation, frame
//! discipline, `seq`, envelope type and digest checks) and then answers `UNIMPLEMENTED`, so the
//! service already holds its peers to the wire contract. `tests/contract.rs` runs the contract
//! suite against it, in process and over a Unix socket.

use ethswarm_proto::engine as pb;
use ipc::Link;
use pb::engine_service_server::{EngineService, EngineServiceServer};
use tonic::service::Routes;

/// The `cl-engine` service: contract checks, then `UNIMPLEMENTED`.
#[derive(Clone, Debug)]
pub struct EngineStub {
    link: Link,
}

impl EngineStub {
    #[must_use]
    pub fn new(link: Link) -> Self {
        Self { link }
    }

    /// The contract configuration every RPC is checked against.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Every `ethswarm.engine.v1` service, ready to serve.
    #[must_use]
    pub fn routes(self) -> Routes {
        Routes::new(EngineServiceServer::new(self.clone()))
    }
}

ipc::stub_service!(EngineStub => EngineService {
    unary: [
        new_payload(pb::NewPayloadRequest) -> pb::NewPayloadResponse,
        forkchoice_updated(pb::ForkchoiceUpdatedRequest) -> pb::ForkchoiceUpdatedResponse,
        get_payload(pb::GetPayloadRequest) -> pb::GetPayloadResponse,
        get_blobs(pb::GetBlobsRequest) -> pb::GetBlobsResponse,
        exchange_capabilities(pb::ExchangeCapabilitiesRequest) -> pb::ExchangeCapabilitiesResponse,
    ],
    unary_envelopes: [
    ],
    server_stream: [
    ],
    bidi: [
    ],
});
