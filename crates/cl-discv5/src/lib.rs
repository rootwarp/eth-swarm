//! `cl-discv5`: serves `ethswarm.discv5.v1`, peer discovery.
//!
//! - [`enr`]: the local record with `eth2`, `cgc` and `nfd`, and the fields of a remote one;
//!   [`enr::signing_key`] turns the node key the `node-key` crate loads into the record's key.
//! - [`service`]: discv5 with the routing-table IP rules and lookups filtered by fork digest;
//!   table records that fail either are evicted on their event and by a periodic sweep.
//! - [`metrics`], the routing-table eviction counter `discv5_table_evictions_total{reason}`.
//!
//! The gRPC service is a stub. Every RPC runs the `ipc` contract layer first (hello
//! negotiation, frame discipline, `seq`, envelope type and digest checks) and then answers
//! `UNIMPLEMENTED`, so the service already holds its peers to the wire contract.
//! `tests/contract.rs` runs the contract suite against it, in process and over a Unix socket.

pub mod enr;
pub mod metrics;
pub mod service;

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
