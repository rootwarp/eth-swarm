//! `cl-p2p`: serves `ethswarm.p2p.v1`, outbound peer requests and peer scoring.
//!
//! This is a stub. Every RPC runs the `ipc` contract layer first (hello negotiation, frame
//! discipline, `seq`, envelope type and digest checks) and then answers `UNIMPLEMENTED`, so the
//! service already holds its peers to the wire contract. `tests/contract.rs` runs the contract
//! suite against it, in process and over a Unix socket.

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
