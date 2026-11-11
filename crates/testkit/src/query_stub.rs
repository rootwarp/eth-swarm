//! Second-CL adapter for checkpoint soak tests. Implements only GetStateSummary in this slice.
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
/// Even silent handshakes and transport drains close within twice the configured timeout.
pub struct QueryStub {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
    #[cfg(test)]
    accepted: tokio::sync::mpsc::Receiver<()>,
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
        let adapter = Adapter {
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
        let incoming = UnixListenerStream::new(listener);
        #[cfg(test)]
        let (accepted_tx, accepted) = tokio::sync::mpsc::channel(1);
        #[cfg(test)]
        let incoming = tokio_stream::StreamExt::map(incoming, move |stream| {
            let _ = accepted_tx.try_send(());
            stream
        });
        let task = tokio::spawn(async move {
            let result = tonic::transport::Server::builder()
                .concurrency_limit_per_connection(8)
                .timeout(timeout)
                // RPC deadlines do not cover HTTP/2 handshakes or graceful transport drain.
                // Tonic's age+grace timer force-closes the owned connection in either state.
                .max_connection_age(timeout)
                .max_connection_age_grace(timeout)
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, async {
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
            #[cfg(test)]
            accepted,
        })
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
    url: ReferenceApiUrl,
    reference: Reference,
    timeout: Duration,
}

fn root(value: &Value) -> Result<Vec<u8>, Status> {
    value
        .as_str()
        .and_then(crate::root_diff::api_root)
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
        Ok(Response::new(pb::GetStateSummaryResponse {
            slot,
            state_root,
            block_root,
            justified: Some(checkpoint(checkpoints.justified)),
            finalized: Some(checkpoint(checkpoints.finalized)),
            stamp: None,
        }))
    }

    async fn get_fork_choice(
        &self,
        _: Request<pb::GetForkChoiceRequest>,
    ) -> Result<Response<pb::GetForkChoiceResponse>, Status> {
        Err(Status::unimplemented(
            "head and payload status belong to the head-comparison slice",
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::testing::{FixtureServer, Reply};
    use tokio::io::AsyncReadExt;

    async fn silent_peer_cleanup(explicit: bool) {
        let api = FixtureServer::start(|_, _| Reply::status(503)).await;
        let dir = tempfile::tempdir().unwrap();
        let socket = ipc::uds::SocketDir::under(dir.path(), "silent-peer").unwrap();
        let deadline = Duration::from_millis(20);
        let mut server = QueryStub::start(&socket, api.url(""), deadline).unwrap();
        let mut peer = tokio::net::UnixStream::connect(socket.socket_path())
            .await
            .unwrap();
        // Accept barrier: no sleeps and no race with the listener's shutdown select.
        server.accepted.recv().await.unwrap();
        tokio::time::timeout(Duration::from_millis(100), async {
            if explicit {
                server.shutdown().await.unwrap();
            } else {
                let task = server.task.take().unwrap();
                drop(server);
                task.await.unwrap().unwrap();
            }
        })
        .await
        .expect("silent handshake must not strand shutdown");
        assert!(
            !socket.socket_path().exists(),
            "owned socket must be removed"
        );
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_millis(100), peer.read_to_end(&mut bytes))
            .await
            .expect("the accepted transport must be closed")
            .unwrap();
        let rebound = QueryStub::start(&socket, api.url(""), deadline).unwrap();
        rebound.shutdown().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn silent_peer_explicit_shutdown_is_bounded() {
        silent_peer_cleanup(true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn silent_peer_drop_closes_transport_and_socket() {
        silent_peer_cleanup(false).await;
    }
}
