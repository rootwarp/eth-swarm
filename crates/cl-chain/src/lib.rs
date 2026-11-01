//! `cl-chain`: serves `ethswarm.chain.v1`, the single writer: state transition, fork choice, DA status and ePBS.
//!
//! This is mostly a stub. Every RPC runs the `ipc` contract layer first (hello negotiation,
//! frame discipline, `seq`, envelope type and digest checks) and then answers `UNIMPLEMENTED`,
//! so the service already holds its peers to the wire contract. `tests/contract.rs` runs the
//! contract suite against it, in process and over a Unix socket. The exception is probe mode's
//! `ReqRespService`: [`ChainStub::serving`] mounts [`reqresp::ReqRespServer`] over the probe's
//! column store in place of the stub, which serves `DataColumnsByRange`, `DataColumnsByRoot`
//! and `GetStatus` ([`probe::StatusProvider`], with the column server's
//! `earliest_available_slot`).
//!
//! [`probe`] is probe mode: its Status (`ReqRespService/GetStatus`: the wall-clock fork digest
//! and the reference Beacon API's finalized checkpoint, with the last good value kept through an
//! outage), the storage contract for gossip column sidecars (reference root, KZG through
//! cl-verify, custody; anything else dropped) and the forward-only column store behind it
//! (bounded queues, every column reported IGNORE, so none is re-broadcast).
//!
//! [`reqresp`] serves the custody columns of that store to cl-p2p (`ReqRespService`
//! `DataColumnsByRange` and `DataColumnsByRoot`), for peers' `DataColumnSidecarsByRange` and
//! `DataColumnSidecarsByRoot` requests.
//!
//! [`verify`] is cl-chain's side of `ethswarm.verify.v1`: cl-chain never runs BLS or KZG itself.
//!
//! [`da::custody`] owns the node's custody group count: never decreasing, stored in the column
//! env, advertised through the MetaData and the ENR, and the column subnets cl-p2p subscribes.
//!
//! [`compiled_config`] is the startup check of the config values that the state transition
//! compiles in: a network config with another value stops the start.
//!
//! [`probe::service`] puts probe mode together as one service, and [`service`] is the `cl-chain`
//! process that `ops/probe/ethswarm-chain.service` runs: `/etc/ethswarm/cl-chain.toml`, the
//! socket and the method ACL through `svc-runtime`, and the SIGTERM drain.

pub mod compiled_config;
pub mod da;
pub mod persist;
pub mod probe;
pub mod reqresp;
pub mod service;
pub mod verify;

#[cfg(test)]
mod testing;

use ethswarm_proto::chain as pb;
use ipc::Link;
use pb::events_service_server::{EventsService, EventsServiceServer};
use pb::gossip_service_server::{GossipService, GossipServiceServer};
use pb::import_service_server::{ImportService, ImportServiceServer};
use pb::query_service_server::{QueryService, QueryServiceServer};
use pb::req_resp_service_server::{ReqRespService, ReqRespServiceServer};
use tonic::service::Routes;

/// The `cl-chain` service: contract checks, then `UNIMPLEMENTED`, except `ReqRespService`
/// once it is given the probe's column server ([`Self::serving`]) and `GossipService` once it
/// is given the probe's custody subscriptions and column hand-off ([`Self::serving_gossip`]).
#[derive(Clone, Debug)]
pub struct ChainStub {
    link: Link,
    req_resp: Option<reqresp::ReqRespServer>,
    gossip: Option<probe::service::GossipServer>,
}

impl ChainStub {
    #[must_use]
    pub fn new(link: Link) -> Self {
        Self {
            link,
            req_resp: None,
            gossip: None,
        }
    }

    /// The same service with `ReqRespService` served by `req_resp` (the column RPCs from the
    /// probe's column store, and `GetStatus` if it serves one) instead of the stub.
    #[must_use]
    pub fn serving(mut self, req_resp: reqresp::ReqRespServer) -> Self {
        self.req_resp = Some(req_resp);
        self
    }

    /// The same service with `GossipService` served by `gossip` (`WatchSubscriptions` from the
    /// probe's custody, `Validate` into its column store) instead of the stub.
    #[must_use]
    pub fn serving_gossip(mut self, gossip: probe::service::GossipServer) -> Self {
        self.gossip = Some(gossip);
        self
    }

    /// Whether `ReqRespService` is served by the column server.
    #[must_use]
    pub fn serves_columns(&self) -> bool {
        self.req_resp.is_some()
    }

    /// The contract configuration every RPC is checked against.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Every `ethswarm.chain.v1` service, ready to serve.
    #[must_use]
    pub fn routes(self) -> Routes {
        let routes = match self.gossip.clone() {
            Some(server) => Routes::new(server.into_service()),
            None => Routes::new(GossipServiceServer::new(self.clone())),
        };
        let routes = match self.req_resp.clone() {
            Some(server) => routes.add_service(server.into_service()),
            None => routes.add_service(ReqRespServiceServer::new(self.clone())),
        };
        routes
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reqresp::{ColumnServer, ColumnStore, ServeBudget, ServeClock};
    use cl_chain_columns::ColumnWriter;
    use consensus_types::primitives::U256;
    use ethswarm_proto::common::{ErrorCode, Hello};
    use ipc::envelope::DigestTable;
    use network_config::{ForkName, ForkSchedule, ScheduledFork};
    use pb::req_resp_service_client::ReqRespServiceClient;
    use std::sync::Arc;

    struct Always;

    impl ServeClock for Always {
        fn serve_range(&self) -> Option<(u64, u64)> {
            Some((0, 1000))
        }

        fn fork_digest(&self, _: u64) -> Option<[u8; 4]> {
            Some([1, 2, 3, 4])
        }
    }

    fn link() -> Link {
        let at = |epoch| ScheduledFork {
            version: [7, 0, 0, 0],
            epoch,
        };
        let hello = Hello {
            api_version: 1,
            min_api_version: 1,
            max_api_version: 1,
            ..Default::default()
        };
        let digests = DigestTable::new(vec![(0, ForkName::Gloas, [1, 2, 3, 4])]).unwrap();
        Link::new::<consensus_types::Mainnet>(
            hello,
            1,
            ForkSchedule::new(at(0), at(0)).unwrap(),
            digests,
        )
    }

    /// The first error code of a column response, `None` without one.
    async fn first_code(
        mut stream: tonic::Streaming<pb::DataColumnsByRangeResponse>,
    ) -> Option<i32> {
        while let Some(frame) = stream.message().await.unwrap() {
            if let Some(pb::data_columns_by_range_response::Frame::Body(body)) = frame.frame {
                if let Some(pb::response_chunk::Result::Error(e)) = body.item.and_then(|i| i.result)
                {
                    return Some(e.code);
                }
            }
        }
        None
    }

    /// The routes mount the column server once it is given one: a column request is answered
    /// from the store (nothing stored: `3: ResourceUnavailable`), not `UNIMPLEMENTED`.
    #[tokio::test]
    async fn the_routes_mount_the_column_server() {
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(ColumnWriter::open(dir.path().join("columns")).unwrap());
        let columns = Arc::new(ColumnServer::new(
            writer as Arc<dyn ColumnStore>,
            U256::MAX,
            Arc::new(Always),
            ServeBudget::default(),
        ));
        let served = ChainStub::new(link())
            .serving(reqresp::ReqRespServer::new(link(), columns))
            .routes();
        let socket = dir.path().join("chain.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(ipc::stub::serve_uds(listener, served, async {
            let _ = stopped.await;
        }));
        let uid = ipc::uds::Ownership::current().uid;
        let channel = ipc::uds::connect_path(&socket, uid).await.unwrap();
        let mut client = ReqRespServiceClient::new(channel);
        let request = pb::DataColumnsByRangeRequest {
            start_slot: 0,
            count: 1,
            columns: vec![1],
            hello: Some(link().local()),
        };
        let stream = client
            .data_columns_by_range(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            first_code(stream).await,
            Some(ErrorCode::ResourceUnavailable as i32)
        );
        // GetStatus without a Status source is still the stub.
        let err = client
            .get_status(pb::GetStatusRequest {})
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        let _ = stop.send(());
    }

    /// Without a column server the routes are the stub's: our hello, then `UNIMPLEMENTED`.
    #[tokio::test]
    async fn the_stub_routes_answer_unimplemented() {
        use tokio_stream::StreamExt;
        let stub = ChainStub::new(link());
        assert!(!stub.serves_columns());
        let request = pb::DataColumnsByRangeRequest {
            start_slot: 0,
            count: 1,
            columns: vec![1],
            hello: Some(link().local()),
        };
        let mut stream = ReqRespService::data_columns_by_range(&stub, tonic::Request::new(request))
            .await
            .unwrap()
            .into_inner();
        assert!(stream.next().await.unwrap().is_ok());
        let err = stream.next().await.unwrap().unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }
}
