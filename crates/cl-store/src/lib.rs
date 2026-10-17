//! `cl-store`: serves `ethswarm.store.v1`, the read side: blocks, states, columns and envelopes from a read-only MDBX.
//!
//! This is a stub. Every RPC runs the `ipc` contract layer first (hello negotiation, frame
//! discipline, `seq`, envelope type and digest checks) and then answers `UNIMPLEMENTED`, so the
//! service already holds its peers to the wire contract. `tests/contract.rs` runs the contract
//! suite against it, in process and over a Unix socket.
//!
//! [`stamp`] is the client side every caller of cl-store uses: a response without its full
//! `ReadMeta` stamp is refused.

pub mod stamp;

use ethswarm_proto::store as pb;
use ipc::Link;
use pb::store_service_server::{StoreService, StoreServiceServer};
use tonic::service::Routes;

/// The `cl-store` service: contract checks, then `UNIMPLEMENTED`.
#[derive(Clone, Debug)]
pub struct StoreStub {
    link: Link,
}

impl StoreStub {
    #[must_use]
    pub fn new(link: Link) -> Self {
        Self { link }
    }

    /// The contract configuration every RPC is checked against.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Every `ethswarm.store.v1` service, ready to serve.
    #[must_use]
    pub fn routes(self) -> Routes {
        Routes::new(StoreServiceServer::new(self.clone()))
    }
}

ipc::stub_service!(StoreStub => StoreService {
    unary: [
        get_block(pb::GetBlockRequest) -> pb::GetBlockResponse,
        get_state(pb::GetStateRequest) -> pb::GetStateResponse,
        get_payload_envelope(pb::GetPayloadEnvelopeRequest) -> pb::GetPayloadEnvelopeResponse,
        get_chain_head(pb::GetChainHeadRequest) -> pb::GetChainHeadResponse,
    ],
    unary_envelopes: [
    ],
    server_stream: [
        get_data_columns(pb::GetDataColumnsRequest) -> pb::GetDataColumnsResponse as GetDataColumnsStream,
        get_blocks_by_range(pb::GetBlocksByRangeRequest) -> pb::GetBlocksByRangeResponse as GetBlocksByRangeStream,
        get_data_columns_by_range(pb::GetDataColumnsByRangeRequest) -> pb::GetDataColumnsByRangeResponse as GetDataColumnsByRangeStream,
    ],
    bidi: [
    ],
});
