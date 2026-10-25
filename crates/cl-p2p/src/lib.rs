//! `cl-p2p`: the probe's libp2p side, and `ethswarm.p2p.v1` (outbound peer requests and peer
//! scoring).
//!
//! [`service`] is the `cl-p2p` process that `ops/probe/ethswarm-p2p.service` runs: the swarm,
//! cl-chain's Status, columns and custody subscriptions over its socket, cl-discv5's peers, the
//! Goodbye ledger's feed and `/metrics`. [`P2pStub`] serves `ethswarm.p2p.v1` on its socket,
//! still a stub: every RPC runs the `ipc` contract layer first (hello negotiation, frame
//! discipline, `seq`, envelope type and digest checks) and then answers `UNIMPLEMENTED`.
//! `tests/contract.rs` runs the contract suite against it, in process and over a Unix socket.
//!
//! [`rpc`] is req/resp over libp2p `request_response`: the codec (both halves, deadlines
//! inside) and the probe's control protocols ([`rpc::inbound::Control`]: Status, MetaData,
//! Ping, Goodbye, and the custody columns served by range and by root from cl-chain). [`m2a_session`] is the pinned-peer session the `m2a-session` binary runs,
//! [`transport`] the TCP muxers (yamux first, then mplex under its stream, buffer and
//! per-connection caps) and the probe swarm over them ([`transport::build_swarm`], with
//! [`behaviour`]), and [`identity`] the service's node key from its systemd credential.
//! [`gossip`] is the probe's gossipsub, which reports IGNORE for every message and so forwards
//! none; [`custody`] subscribes it to exactly the custody column subnets cl-chain names.
//! [`enr_text`] reads one field of a textual node record.
//! [`peers`] records what the probe learns of its peers: the Goodbye ledger
//! ([`peers::manager::GoodbyeLedger`]), reason-3 Goodbyes from Status-valid peers per hour.

pub mod behaviour;
pub mod custody;
pub mod enr_text;
pub mod gossip;
pub mod identity;
pub mod m2a_session;
pub mod peer_caps;
pub mod peers;
pub mod rpc;
pub mod service;
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
