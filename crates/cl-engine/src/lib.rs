//! `cl-engine`: the ordered, stateless Engine API adapter between cl-chain and one execution
//! client (execution-apis `authentication.md` and `common.md`).
//!
//! It is the only holder of the JWT secret. It never decodes consensus types (ADR-007): JSON
//! params are forwarded as JSON-RPC params. Calls run in `seq` order, one at a time, on one
//! queue per execution client ([`queue`]), over a JWT-authenticated client ([`client`],
//! [`jwt`]) that only sends once the capability gate ([`capabilities`]) has passed.
//!
//! [`EngineStub`] still answers every `ethswarm.engine.v1` RPC with `UNIMPLEMENTED` after the
//! `ipc` contract checks, which is what `tests/contract.rs` drives. The Unix-socket server in
//! front of the queue is a separate change.

pub mod capabilities;
pub mod client;
pub mod jwt;
pub mod queue;

// Unit tests drive the same in-crate mock EL as the integration tests.
#[cfg(test)]
extern crate self as cl_engine;
#[cfg(test)]
#[path = "../tests/common/mod.rs"]
pub(crate) mod test_mock;

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
