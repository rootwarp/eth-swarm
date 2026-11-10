//! Second-CL adapter for checkpoint/head soak tests. Atomic head status comes from head_v2.
//! Uses a fixed slot header then finality by that header's state root, never two moving heads.
//! Missing slot headers (including empty slots) are unavailable, not invented snapshots.

use crate::collector::{get_json_at, ReferenceApiUrl, MAX_JSON_BYTES};
use crate::root_diff::{Checkpoint, Reference};
use ethswarm_proto::{chain as pb, common};
use pb::query_service_server::{QueryService, QueryServiceServer};
use serde_json::Value;
use std::io;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

/// A private-runtime-dir UDS fixture. Drop signals graceful shutdown; `shutdown` waits for it.
pub struct QueryStub {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
    heads: tokio::sync::watch::Receiver<Option<crate::root_diff::HeadSnapshot>>,
}

impl QueryStub {
    /// Bind safely using ipc's ownership/mode/stale-socket rules. Only this UID may call it.
    /// The caller owns the runtime root; no OS users or global directories are created.
    pub fn start(
        dir: &ipc::uds::SocketDir,
        url: ReferenceApiUrl,
        timeout: Duration,
    ) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero timeout"));
        }
        let (listener, guard) =
            ipc::uds::bind(dir, ipc::uds::Ownership::current())?.into_tokio()?;
        let uid = ipc::peercred::effective_uid();
        let heads = crate::root_diff::HeadStream::start(
            url.clone(),
            timeout,
            Duration::from_secs(24).max(timeout),
        )
        .map_err(io::Error::other)?;
        let head_updates = heads.updates();
        let adapter = Adapter {
            heads,
            reference: Reference::new(url.clone(), timeout),
            url,
            timeout,
        };
        let service = QueryServiceServer::with_interceptor(adapter, move |request: Request<()>| {
            let peer_uid = request
                .extensions()
                .get::<tonic::transport::server::UdsConnectInfo>()
                .and_then(|info| info.peer_cred.as_ref())
                .map(|cred| cred.uid());
            if peer_uid != Some(uid) {
                return Err(Status::permission_denied("query fixture caller UID"));
            }
            Ok(request)
        });
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let result = tonic::transport::Server::builder()
                .concurrency_limit_per_connection(8)
                .timeout(timeout)
                .add_service(service)
                .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                    let _ = stopped.await;
                })
                .await
                .map_err(io::Error::other);
            drop(guard);
            result
        });
        Ok(Self {
            stop: Some(stop),
            task: Some(task),
            heads: head_updates,
        })
    }

    /// Observe second-CL head_v2 readiness/loss without timing sleeps.
    pub fn head_updates(
        &self,
    ) -> tokio::sync::watch::Receiver<Option<crate::root_diff::HeadSnapshot>> {
        self.heads.clone()
    }

    /// Stop accepting and drain deadline-bounded calls, then remove only the owned socket.
    pub async fn shutdown(mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.map_err(io::Error::other)??;
        }
        Ok(())
    }
}

impl Drop for QueryStub {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

struct Adapter {
    heads: crate::root_diff::HeadStream,
    url: ReferenceApiUrl,
    reference: Reference,
    timeout: Duration,
}

fn root(value: &Value) -> Result<Vec<u8>, Status> {
    value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .and_then(crate::archive::canonical_hex::<32>)
        .map(Vec::from)
        .ok_or_else(|| Status::unavailable("invalid reference header root"))
}

fn checkpoint(value: Checkpoint) -> common::Checkpoint {
    common::Checkpoint {
        epoch: value.epoch,
        root: value.root.as_slice().to_vec(),
    }
}

#[tonic::async_trait]
impl QueryService for Adapter {
    async fn get_state_summary(
        &self,
        request: Request<pb::GetStateSummaryRequest>,
    ) -> Result<Response<pb::GetStateSummaryResponse>, Status> {
        let (state, wanted) = match request.into_inner().state.and_then(|s| s.id) {
            Some(pb::hot_state_id::Id::Slot(slot)) => (slot.to_string(), Some(slot)),
            Some(pb::hot_state_id::Id::Named(name)) if name == "head" => (name, None),
            _ => {
                return Err(Status::invalid_argument(
                    "query fixture supports a slot or head",
                ))
            }
        };
        let path = format!("/eth/v1/beacon/headers/{state}");
        let header: Value = get_json_at(
            &self.url,
            "/eth/v1/beacon/headers/{block_id}",
            &path,
            MAX_JSON_BYTES,
            self.timeout,
        )
        .await
        .map_err(|_| Status::unavailable("reference header read failed"))?;
        let message = &header["data"]["header"]["message"];
        let slot_text = message["slot"]
            .as_str()
            .ok_or_else(|| Status::unavailable("invalid reference header slot"))?;
        if slot_text.is_empty() || !slot_text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Status::unavailable("invalid reference header slot"));
        }
        let slot: u64 = slot_text
            .parse()
            .map_err(|_| Status::unavailable("invalid reference header slot"))?;
        if wanted.is_some_and(|wanted| wanted != slot) {
            return Err(Status::unavailable("reference returned another slot"));
        }
        let state_root = root(&message["state_root"])?;
        let block_root = root(&header["data"]["root"])?;
        let checkpoints = self
            .reference
            .read_state(&format!("0x{}", hex::encode(&state_root)))
            .await
            .map_err(|_| Status::unavailable("reference checkpoints read failed"))?;
        let payload_status = if wanted.is_none() {
            self.heads
                .snapshot()
                .filter(|head| head.slot == slot && head.root.as_slice() == block_root.as_slice())
                .map(|head| head.status.to_wire())
        } else {
            None
        };
        Ok(Response::new(pb::GetStateSummaryResponse {
            slot,
            state_root,
            block_root,
            justified: Some(checkpoint(checkpoints.justified)),
            finalized: Some(checkpoint(checkpoints.finalized)),
            stamp: None,
            payload_status,
        }))
    }

    async fn get_fork_choice(
        &self,
        _: Request<pb::GetForkChoiceRequest>,
    ) -> Result<Response<pb::GetForkChoiceResponse>, Status> {
        Err(Status::unimplemented("query fixture: state summaries only"))
    }
    async fn get_hot_state(
        &self,
        _: Request<pb::GetHotStateRequest>,
    ) -> Result<Response<pb::GetHotStateResponse>, Status> {
        Err(Status::unimplemented(
            "query fixture: checkpoint summaries only",
        ))
    }
    async fn get_hot_validators(
        &self,
        _: Request<pb::GetHotValidatorsRequest>,
    ) -> Result<Response<pb::GetHotValidatorsResponse>, Status> {
        Err(Status::unimplemented(
            "query fixture: checkpoint summaries only",
        ))
    }
    async fn get_hot_committees(
        &self,
        _: Request<pb::GetHotCommitteesRequest>,
    ) -> Result<Response<pb::GetHotCommitteesResponse>, Status> {
        Err(Status::unimplemented(
            "query fixture: checkpoint summaries only",
        ))
    }
    async fn get_duties(
        &self,
        _: Request<pb::GetDutiesRequest>,
    ) -> Result<Response<pb::GetDutiesResponse>, Status> {
        Err(Status::unimplemented(
            "query fixture: checkpoint summaries only",
        ))
    }
    async fn produce(
        &self,
        _: Request<pb::ProduceRequest>,
    ) -> Result<Response<pb::ProduceResponse>, Status> {
        Err(Status::unimplemented(
            "query fixture: checkpoint summaries only",
        ))
    }
    async fn submit(
        &self,
        _: Request<pb::SubmitRequest>,
    ) -> Result<Response<pb::SubmitResponse>, Status> {
        Err(Status::unimplemented(
            "query fixture: checkpoint summaries only",
        ))
    }
}
