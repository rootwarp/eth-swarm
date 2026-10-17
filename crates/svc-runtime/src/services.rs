//! The gRPC services a process serves, and the method paths they answer.
//!
//! The runtime needs both: the routes to serve, and the paths, so that a `[methods]` entry
//! that matches nothing served (a misspelled method, a service this binary does not run)
//! fails startup instead of silently denying the method it was meant to allow
//! ([`Services::unserved`]). The paths come from the compiled `ethswarm.*.v1` descriptor set.

use std::collections::BTreeSet;
use std::convert::Infallible;

use ipc::acl::MethodAcl;
use prost::Message;
use prost_types::FileDescriptorSet;
use tonic::body::Body;
use tonic::server::NamedService;
use tonic::service::Routes;

/// The services to serve, by name.
#[derive(Debug, Default)]
pub struct Services {
    routes: Routes,
    names: BTreeSet<&'static str>,
}

impl Services {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a generated tonic server (e.g. `EngineServiceServer::new(..)`).
    #[must_use]
    pub fn add_service<S>(mut self, svc: S) -> Self
    where
        S: tower::Service<http::Request<Body>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Response: axum::response::IntoResponse,
        S::Future: Send + 'static,
    {
        self.names.insert(S::NAME);
        self.routes = self.routes.add_service(svc);
        self
    }

    /// Fully qualified names of the services added (`ethswarm.engine.v1.EngineService`).
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.names.iter().copied()
    }

    /// Every method path the added services answer, per the descriptor set.
    #[must_use]
    pub fn methods(&self) -> BTreeSet<String> {
        let set = FileDescriptorSet::decode(ethswarm_proto::FILE_DESCRIPTOR_SET)
            .expect("the embedded descriptor set decodes");
        let mut out = BTreeSet::new();
        for file in &set.file {
            for service in &file.service {
                let full = format!("{}.{}", file.package(), service.name());
                if self.names.contains(full.as_str()) {
                    out.extend(
                        service
                            .method
                            .iter()
                            .map(|m| format!("/{full}/{}", m.name())),
                    );
                }
            }
        }
        out
    }

    /// The ACL's method paths that none of these services answers.
    #[must_use]
    pub fn unserved(&self, acl: &MethodAcl) -> Vec<String> {
        let served = self.methods();
        acl.methods()
            .filter(|m| !served.contains(*m))
            .map(str::to_owned)
            .collect()
    }

    /// The routes to hand to tonic.
    #[must_use]
    pub fn into_routes(self) -> Routes {
        self.routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethswarm_proto::sync::sync_service_server::{SyncService, SyncServiceServer};
    use ethswarm_proto::sync::{
        GetSyncProgressRequest, GetSyncProgressResponse, StartBackfillRequest,
        StartBackfillResponse,
    };
    use std::path::Path;
    use tonic::{Request, Response, Status};

    #[derive(Clone, Copy)]
    struct Sync;

    #[tonic::async_trait]
    impl SyncService for Sync {
        async fn get_sync_progress(
            &self,
            _: Request<GetSyncProgressRequest>,
        ) -> Result<Response<GetSyncProgressResponse>, Status> {
            Err(Status::unimplemented("test"))
        }
        async fn start_backfill(
            &self,
            _: Request<StartBackfillRequest>,
        ) -> Result<Response<StartBackfillResponse>, Status> {
            Err(Status::unimplemented("test"))
        }
    }

    fn acl(methods: &[&str]) -> MethodAcl {
        let mut text = String::from("[callers]\ncl-chain = 990\n[methods]\n");
        for m in methods {
            text.push_str(&format!("\"{m}\" = [\"cl-chain\"]\n"));
        }
        MethodAcl::from_toml(&text, Path::new("cl-sync.toml"), "cl-sync").unwrap()
    }

    #[test]
    fn methods_come_from_the_descriptor_set() {
        let s = Services::new().add_service(SyncServiceServer::new(Sync));
        assert_eq!(
            s.names().collect::<Vec<_>>(),
            ["ethswarm.sync.v1.SyncService"]
        );
        assert_eq!(
            s.methods().into_iter().collect::<Vec<_>>(),
            [
                "/ethswarm.sync.v1.SyncService/GetSyncProgress",
                "/ethswarm.sync.v1.SyncService/StartBackfill",
            ]
        );
        assert!(Services::new().methods().is_empty());
        let _routes = s.into_routes();
    }

    #[test]
    fn acl_paths_nothing_serves_are_listed() {
        let s = Services::new().add_service(SyncServiceServer::new(Sync));
        let ok = acl(&["/ethswarm.sync.v1.SyncService/GetSyncProgress"]);
        assert!(s.unserved(&ok).is_empty());
        let typo = acl(&[
            "/ethswarm.sync.v1.SyncService/GetSyncProgress",
            "/ethswarm.sync.v1.SyncService/StartBackFill",
            "/ethswarm.sync.v1.OtherService/Get",
        ]);
        assert_eq!(
            s.unserved(&typo),
            [
                "/ethswarm.sync.v1.OtherService/Get",
                "/ethswarm.sync.v1.SyncService/StartBackFill",
            ]
        );
    }
}
