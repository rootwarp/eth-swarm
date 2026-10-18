//! `cl-chain`: serves `ethswarm.chain.v1`, the single writer: state transition, fork choice, DA status and ePBS.
//!
//! This is a stub. Every RPC runs the `ipc` contract layer first (hello negotiation, frame
//! discipline, `seq`, envelope type and digest checks) and then answers `UNIMPLEMENTED`, so the
//! service already holds its peers to the wire contract. `tests/contract.rs` runs the contract
//! suite against it, in process and over a Unix socket.
//!
//! [`probe`] is probe mode's Status (`ReqRespService/GetStatus`): the wall-clock fork digest and
//! the reference Beacon API's finalized checkpoint, with the last good value kept through an
//! outage.
//!
//! [`da::custody`] owns the node's custody group count: never decreasing, stored in the column
//! env, advertised through the MetaData and the ENR, and the column subnets cl-p2p subscribes.

pub mod da;
pub mod probe;

use ethswarm_proto::chain as pb;
use ipc::Link;
use pb::events_service_server::{EventsService, EventsServiceServer};
use pb::gossip_service_server::{GossipService, GossipServiceServer};
use pb::import_service_server::{ImportService, ImportServiceServer};
use pb::query_service_server::{QueryService, QueryServiceServer};
use pb::req_resp_service_server::{ReqRespService, ReqRespServiceServer};
use tonic::service::Routes;

/// The `cl-chain` service: contract checks, then `UNIMPLEMENTED`.
#[derive(Clone, Debug)]
pub struct ChainStub {
    link: Link,
}

impl ChainStub {
    #[must_use]
    pub fn new(link: Link) -> Self {
        Self { link }
    }

    /// The contract configuration every RPC is checked against.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Every `ethswarm.chain.v1` service, ready to serve.
    #[must_use]
    pub fn routes(self) -> Routes {
        Routes::new(GossipServiceServer::new(self.clone()))
            .add_service(ReqRespServiceServer::new(self.clone()))
            .add_service(ImportServiceServer::new(self.clone()))
            .add_service(QueryServiceServer::new(self.clone()))
            .add_service(EventsServiceServer::new(self.clone()))
    }
}

ipc::stub_service!(ChainStub => GossipService {
    unary: [
        get_fork_schedule(pb::GetForkScheduleRequest) -> pb::GetForkScheduleResponse,
    ],
    unary_envelopes: [
    ],
    server_stream: [
        watch_publish(pb::WatchPublishRequest) -> pb::WatchPublishResponse as WatchPublishStream,
        watch_subscriptions(pb::WatchSubscriptionsRequest) -> pb::WatchSubscriptionsResponse as WatchSubscriptionsStream,
    ],
    bidi: [
        validate(pb::ValidateRequest) -> pb::ValidateResponse as ValidateStream,
    ],
});

ipc::stub_service!(ChainStub => ReqRespService {
    unary: [
        get_status(pb::GetStatusRequest) -> pb::GetStatusResponse,
        get_metadata(pb::GetMetadataRequest) -> pb::GetMetadataResponse,
    ],
    unary_envelopes: [
    ],
    server_stream: [
        blocks_by_range(pb::BlocksByRangeRequest) -> pb::BlocksByRangeResponse as BlocksByRangeStream,
        blocks_by_root(pb::BlocksByRootRequest) -> pb::BlocksByRootResponse as BlocksByRootStream,
        data_columns_by_range(pb::DataColumnsByRangeRequest) -> pb::DataColumnsByRangeResponse as DataColumnsByRangeStream,
        data_columns_by_root(pb::DataColumnsByRootRequest) -> pb::DataColumnsByRootResponse as DataColumnsByRootStream,
        payload_envelopes_by_range(pb::PayloadEnvelopesByRangeRequest) -> pb::PayloadEnvelopesByRangeResponse as PayloadEnvelopesByRangeStream,
        payload_envelopes_by_root(pb::PayloadEnvelopesByRootRequest) -> pb::PayloadEnvelopesByRootResponse as PayloadEnvelopesByRootStream,
    ],
    bidi: [
    ],
});

ipc::stub_service!(ChainStub => ImportService {
    unary: [
        get_chain_status(pb::GetChainStatusRequest) -> pb::GetChainStatusResponse,
    ],
    unary_envelopes: [
        bootstrap(pb::BootstrapRequest) -> pb::BootstrapResponse => |r| r.state.iter().chain(&r.block).chain(&r.payload_envelope).collect(),
    ],
    server_stream: [
    ],
    bidi: [
        import_batch(pb::ImportBatchRequest) -> pb::ImportBatchResponse as ImportBatchStream,
    ],
});

ipc::stub_service!(ChainStub => QueryService {
    unary: [
        get_fork_choice(pb::GetForkChoiceRequest) -> pb::GetForkChoiceResponse,
        get_hot_state(pb::GetHotStateRequest) -> pb::GetHotStateResponse,
        get_state_summary(pb::GetStateSummaryRequest) -> pb::GetStateSummaryResponse,
        get_hot_validators(pb::GetHotValidatorsRequest) -> pb::GetHotValidatorsResponse,
        get_hot_committees(pb::GetHotCommitteesRequest) -> pb::GetHotCommitteesResponse,
        get_duties(pb::GetDutiesRequest) -> pb::GetDutiesResponse,
        produce(pb::ProduceRequest) -> pb::ProduceResponse,
    ],
    unary_envelopes: [
        submit(pb::SubmitRequest) -> pb::SubmitResponse => |r| r.items.iter().collect(),
    ],
    server_stream: [
    ],
    bidi: [
    ],
});

ipc::stub_service!(ChainStub => EventsService {
    unary: [
    ],
    unary_envelopes: [
    ],
    server_stream: [
        subscribe(pb::SubscribeRequest) -> pb::SubscribeResponse as SubscribeStream,
    ],
    bidi: [
    ],
});
