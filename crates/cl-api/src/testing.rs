//! Fixtures the route, schema and service tests share: a fake chain.v1 `ImportService`, a
//! fixed clock, Sepolia's config, and requests through the router with tower's `oneshot`.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::Router;
use ethswarm_proto::chain as pb;
use http::{HeaderMap, Request, StatusCode};
use network_config::{ChainConfig, Network};
use pb::import_service_server::{ImportService, ImportServiceServer};
use tokio::sync::oneshot;
use tonic::service::Routes;
use tonic::{Status, Streaming};
use tower::ServiceExt;

use crate::node_state::{NodeState, SlotClock};
use crate::routes::config::ConfigData;
use crate::server::ApiState;

/// The genesis of the fixed clock (Sepolia's).
pub const GENESIS_TIME: u64 = 1_655_733_600;
/// The slot duration of the fixed clock.
pub const SLOT_MS: u64 = 12_000;
/// The wall-clock slot of the fixed clock.
pub const WALL_SLOT: u64 = 1_000_000;

/// A clock fixed in the middle of [`WALL_SLOT`].
pub fn clock() -> SlotClock {
    SlotClock::with_now(GENESIS_TIME, SLOT_MS, || {
        Duration::from_millis(GENESIS_TIME * 1000 + WALL_SLOT * SLOT_MS + SLOT_MS / 2)
    })
}

pub fn sepolia() -> ChainConfig {
    ChainConfig::load(Network::Sepolia).unwrap()
}

/// Handlers over `node` and Sepolia's config.
pub fn api_state(node: NodeState) -> ApiState {
    ApiState {
        node,
        config: Arc::new(ConfigData::new(&sepolia()).unwrap()),
    }
}

/// [`crate::server::router`] over `state`, with the default request timeout.
pub fn router(state: ApiState) -> Router {
    crate::server::router(state, crate::server::HttpLimits::default().request_timeout)
}

/// `request` through `app`: its status, headers and body.
pub async fn request(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 64 << 20).await.unwrap();
    (parts.status, parts.headers, body.to_vec())
}

/// `GET uri` through `app`.
pub async fn get(app: &Router, uri: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    request(app, Request::get(uri).body(Body::empty()).unwrap()).await
}

/// `body` as JSON.
pub fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(body)))
}

/// A chain status with `head_slot`, `optimistic` and `el_offline`.
pub fn sync_status(head_slot: u64, optimistic: bool, el_offline: bool) -> pb::SyncStatus {
    pb::SyncStatus {
        head_slot,
        head_root: vec![0xab; 32],
        finalized: None,
        anchor_slot: 0,
        optimistic,
        el_offline,
    }
}

/// A fake cl-chain `ImportService`: `GetChainStatus` answers the status the test set last (or
/// never, [`Self::hanging`]); the other RPCs are not implemented.
#[derive(Clone)]
pub struct FakeChain {
    status: Arc<Mutex<pb::SyncStatus>>,
    hang: bool,
}

impl FakeChain {
    pub fn new(status: pb::SyncStatus) -> Self {
        Self {
            status: Arc::new(Mutex::new(status)),
            hang: false,
        }
    }

    /// A chain whose `GetChainStatus` never answers.
    pub fn hanging(mut self) -> Self {
        self.hang = true;
        self
    }

    pub fn set(&self, status: pb::SyncStatus) {
        *self.status.lock().unwrap() = status;
    }

    pub fn routes(&self) -> Routes {
        Routes::new(ImportServiceServer::new(self.clone()))
    }

    /// Serves on a Unix socket at `path` (replacing a stale one) until [`RunningChain::stop`].
    pub fn serve_uds(&self, path: &Path) -> RunningChain {
        let _ = std::fs::remove_file(path);
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(ipc::stub::serve_uds(listener, self.routes(), async {
            let _ = stopped.await;
        }));
        RunningChain { stop, task }
    }
}

/// A [`FakeChain`] on a Unix socket.
pub struct RunningChain {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl RunningChain {
    /// Stops serving and waits until every connection is closed.
    pub async fn stop(self) {
        let _ = self.stop.send(());
        self.task.await.unwrap().unwrap();
    }
}

#[tonic::async_trait]
impl ImportService for FakeChain {
    async fn bootstrap(
        &self,
        _: tonic::Request<pb::BootstrapRequest>,
    ) -> Result<tonic::Response<pb::BootstrapResponse>, Status> {
        Err(Status::unimplemented("bootstrap"))
    }

    type ImportBatchStream = ipc::stub::StubStream<pb::ImportBatchResponse>;

    async fn import_batch(
        &self,
        _: tonic::Request<Streaming<pb::ImportBatchRequest>>,
    ) -> Result<tonic::Response<Self::ImportBatchStream>, Status> {
        Err(Status::unimplemented("import_batch"))
    }

    async fn get_chain_status(
        &self,
        _: tonic::Request<pb::GetChainStatusRequest>,
    ) -> Result<tonic::Response<pb::GetChainStatusResponse>, Status> {
        if self.hang {
            std::future::pending::<()>().await;
        }
        let status = self.status.lock().unwrap().clone();
        Ok(tonic::Response::new(pb::GetChainStatusResponse {
            status: Some(status),
        }))
    }
}
