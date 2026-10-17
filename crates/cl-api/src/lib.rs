//! `cl-api`: serves `ethswarm.api.v1`, the Beacon API front end (health over gRPC; the Beacon API itself is HTTP).
//!
//! This is a stub. Every RPC runs the `ipc` contract layer first (hello negotiation, frame
//! discipline, `seq`, envelope type and digest checks) and then answers `UNIMPLEMENTED`, so the
//! service already holds its peers to the wire contract. `tests/contract.rs` runs the contract
//! suite against it, in process and over a Unix socket.

use ethswarm_proto::api as pb;
use ipc::Link;
use pb::api_service_server::{ApiService, ApiServiceServer};
use tonic::service::Routes;

/// The `cl-api` service: contract checks, then `UNIMPLEMENTED`.
#[derive(Clone, Debug)]
pub struct ApiStub {
    link: Link,
}

impl ApiStub {
    #[must_use]
    pub fn new(link: Link) -> Self {
        Self { link }
    }

    /// The contract configuration every RPC is checked against.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Every `ethswarm.api.v1` service, ready to serve.
    #[must_use]
    pub fn routes(self) -> Routes {
        Routes::new(ApiServiceServer::new(self.clone()))
    }
}

ipc::stub_service!(ApiStub => ApiService {
    unary: [
        get_health(pb::GetHealthRequest) -> pb::GetHealthResponse,
    ],
    unary_envelopes: [
    ],
    server_stream: [
    ],
    bidi: [
    ],
});
