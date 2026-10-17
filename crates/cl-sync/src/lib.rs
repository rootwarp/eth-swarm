//! `cl-sync`: serves `ethswarm.sync.v1`, checkpoint, range and backfill sync.
//!
//! This is a stub. Every RPC runs the `ipc` contract layer first (hello negotiation, frame
//! discipline, `seq`, envelope type and digest checks) and then answers `UNIMPLEMENTED`, so the
//! service already holds its peers to the wire contract. `tests/contract.rs` runs the contract
//! suite against it, in process and over a Unix socket.
//!
//! [`checkpoint`] is the checkpoint-sync anchor fetcher behind the `anchor-fetch` binary: one
//! finalized root agreed by two providers of different operators, the block and state fetched
//! by root, and every root checked before `anchor.json` is written.

use ethswarm_proto::sync as pb;
use ipc::Link;
use pb::sync_service_server::{SyncService, SyncServiceServer};
use tonic::service::Routes;

/// The `cl-sync` service: contract checks, then `UNIMPLEMENTED`.
#[derive(Clone, Debug)]
pub struct SyncStub {
    link: Link,
}

impl SyncStub {
    #[must_use]
    pub fn new(link: Link) -> Self {
        Self { link }
    }

    /// The contract configuration every RPC is checked against.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Every `ethswarm.sync.v1` service, ready to serve.
    #[must_use]
    pub fn routes(self) -> Routes {
        Routes::new(SyncServiceServer::new(self.clone()))
    }
}

ipc::stub_service!(SyncStub => SyncService {
    unary: [
        get_sync_progress(pb::GetSyncProgressRequest) -> pb::GetSyncProgressResponse,
        start_backfill(pb::StartBackfillRequest) -> pb::StartBackfillResponse,
    ],
    unary_envelopes: [
    ],
    server_stream: [
    ],
    bidi: [
    ],
});

pub mod checkpoint;
