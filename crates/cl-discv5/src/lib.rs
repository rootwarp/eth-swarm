//! `cl-discv5`: serves `ethswarm.discv5.v1`, peer discovery.
//!
//! This is a stub. Every RPC runs the `ipc` contract layer first (hello negotiation, frame
//! discipline, `seq`, envelope type and digest checks) and then answers `UNIMPLEMENTED`, so the
//! service already holds its peers to the wire contract. `tests/contract.rs` runs the contract
//! suite against it, in process and over a Unix socket.

use ethswarm_proto::discv5 as pb;
use ipc::Link;
use pb::discovery_service_server::{DiscoveryService, DiscoveryServiceServer};
use tonic::service::Routes;

/// The `cl-discv5` service: contract checks, then `UNIMPLEMENTED`.
#[derive(Clone, Debug)]
pub struct Discv5Stub {
    link: Link,
}

impl Discv5Stub {
    #[must_use]
    pub fn new(link: Link) -> Self {
        Self { link }
    }

    /// The contract configuration every RPC is checked against.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Every `ethswarm.discv5.v1` service, ready to serve.
    #[must_use]
    pub fn routes(self) -> Routes {
        Routes::new(DiscoveryServiceServer::new(self.clone()))
    }
}

ipc::stub_service!(Discv5Stub => DiscoveryService {
    unary: [
        update_enr(pb::UpdateEnrRequest) -> pb::UpdateEnrResponse,
        get_local_enr(pb::GetLocalEnrRequest) -> pb::GetLocalEnrResponse,
    ],
    unary_envelopes: [
    ],
    server_stream: [
        watch_peers(pb::WatchPeersRequest) -> pb::WatchPeersResponse as WatchPeersStream,
        find_peers(pb::FindPeersRequest) -> pb::FindPeersResponse as FindPeersStream,
    ],
    bidi: [
    ],
});
