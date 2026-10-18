//! `cl-p2p`: serves `ethswarm.p2p.v1`, outbound peer requests and peer scoring.
//!
//! This is a stub. Every RPC runs the `ipc` contract layer first (hello negotiation, frame
//! discipline, `seq`, envelope type and digest checks) and then answers `UNIMPLEMENTED`, so the
//! service already holds its peers to the wire contract. `tests/contract.rs` runs the contract
//! suite against it, in process and over a Unix socket.
//!
//! [`rpc`] is req/resp over libp2p `request_response`: the codec (both halves, deadlines
//! inside) and the probe's control protocols ([`rpc::inbound::Control`]: Status, MetaData,
//! Ping, Goodbye). [`m2a_session`] is the pinned-peer session the `m2a-session` binary runs,
//! [`transport`] the TCP muxers (yamux first, then mplex under its stream, buffer and
//! per-connection caps) and the probe swarm over them ([`transport::build_swarm`], with
//! [`behaviour`]), and [`identity`] the service's node key from its systemd credential.
//! [`gossip`] is the probe's gossipsub, which reports IGNORE for every message and so forwards
//! none.

pub mod behaviour;
pub mod gossip;
pub mod identity;
pub mod m2a_session;
pub mod peer_caps;
pub mod rpc;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod transport;

// build.rs's checkout and environment rules, compiled here only to run their tests.
#[cfg(test)]
#[path = "../build_support.rs"]
mod build_support;

use ethswarm_proto::p2p as pb;
use ipc::Link;
use pb::network_service_server::{NetworkService, NetworkServiceServer};
use tonic::service::Routes;

/// The `cl-p2p` service: contract checks, then `UNIMPLEMENTED`.
#[derive(Clone, Debug)]
pub struct P2pStub {
    link: Link,
}

impl P2pStub {
    #[must_use]
    pub fn new(link: Link) -> Self {
        Self { link }
    }

    /// The contract configuration every RPC is checked against.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Every `ethswarm.p2p.v1` service, ready to serve.
    #[must_use]
    pub fn routes(self) -> Routes {
        Routes::new(NetworkServiceServer::new(self.clone()))
    }
}

ipc::stub_service!(P2pStub => NetworkService {
    unary: [
        list_peers(pb::ListPeersRequest) -> pb::ListPeersResponse,
        report_peer(pb::ReportPeerRequest) -> pb::ReportPeerResponse,
    ],
    unary_envelopes: [
    ],
    server_stream: [
        request_blocks_by_range(pb::RequestBlocksByRangeRequest) -> pb::RequestBlocksByRangeResponse as RequestBlocksByRangeStream,
        request_blocks_by_root(pb::RequestBlocksByRootRequest) -> pb::RequestBlocksByRootResponse as RequestBlocksByRootStream,
        request_data_columns_by_range(pb::RequestDataColumnsByRangeRequest) -> pb::RequestDataColumnsByRangeResponse as RequestDataColumnsByRangeStream,
        request_data_columns_by_root(pb::RequestDataColumnsByRootRequest) -> pb::RequestDataColumnsByRootResponse as RequestDataColumnsByRootStream,
        request_payload_envelopes_by_range(pb::RequestPayloadEnvelopesByRangeRequest) -> pb::RequestPayloadEnvelopesByRangeResponse as RequestPayloadEnvelopesByRangeStream,
        request_payload_envelopes_by_root(pb::RequestPayloadEnvelopesByRootRequest) -> pb::RequestPayloadEnvelopesByRootResponse as RequestPayloadEnvelopesByRootStream,
    ],
    bidi: [
    ],
});
