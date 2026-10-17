//! The gRPC services a process serves, and the method paths they answer.
//!
//! The runtime needs both: the routes to serve, and the paths, so that a `[methods]` entry
//! that matches nothing served (a misspelled method, a service this binary does not run)
//! fails startup instead of silently denying the method it was meant to allow
//! ([`Services::unserved`]). For an `ethswarm.*` service the paths come from the compiled
//! descriptor set ([`Services::add_service`]); any other service (e.g. `grpc.health.v1.Health`)
//! names its methods when it is added ([`Services::add_service_with_methods`]).

use std::collections::BTreeSet;
use std::convert::Infallible;

use ipc::acl::MethodAcl;
use prost::Message;
use prost_types::FileDescriptorSet;
use tonic::body::Body;
use tonic::server::NamedService;
use tonic::service::Routes;

/// The services to serve, by name, and the method paths they answer.
#[derive(Debug, Default)]
pub struct Services {
    routes: Routes,
    names: BTreeSet<&'static str>,
    methods: BTreeSet<String>,
}

impl Services {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a generated tonic server (e.g. `EngineServiceServer::new(..)`). Its method paths come
    /// from the embedded `ethswarm.*` descriptor set; a service outside it answers none, so use
    /// [`Self::add_service_with_methods`] for it.
    #[must_use]
    pub fn add_service<S>(self, svc: S) -> Self
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
        let methods = described_methods(S::NAME);
        self.add(svc, methods)
    }

    /// Adds a server that the `ethswarm.*` descriptor set does not describe, with the names of
    /// the methods it answers (`["Check", "Watch"]` for `grpc.health.v1.Health`): the ACL may
    /// then name `/<service>/<method>` for each.
    #[must_use]
    pub fn add_service_with_methods<S, M>(self, svc: S, methods: M) -> Self
    where
        S: tower::Service<http::Request<Body>, Error = Infallible>
            + NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Response: axum::response::IntoResponse,
        S::Future: Send + 'static,
        M: IntoIterator,
        M::Item: AsRef<str>,
    {
        let methods = methods
            .into_iter()
            .map(|m| format!("/{}/{}", S::NAME, m.as_ref()))
            .collect();
        self.add(svc, methods)
    }

    fn add<S>(mut self, svc: S, methods: BTreeSet<String>) -> Self
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
        self.methods.extend(methods);
        self.routes = self.routes.add_service(svc);
        self
    }

    /// Fully qualified names of the services added (`ethswarm.engine.v1.EngineService`).
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.names.iter().copied()
    }

    /// Every method path the added services answer.
    #[must_use]
    pub fn methods(&self) -> BTreeSet<String> {
        self.methods.clone()
    }

    /// The ACL's method paths that none of these services answers.
    #[must_use]
    pub fn unserved(&self, acl: &MethodAcl) -> Vec<String> {
        self.unserved_paths(acl.methods())
    }

    fn unserved_paths<'a>(&self, paths: impl IntoIterator<Item = &'a str>) -> Vec<String> {
        paths
            .into_iter()
            .filter(|m| !self.methods.contains(*m))
            .map(str::to_owned)
            .collect()
    }

    /// The routes to hand to tonic.
    #[must_use]
    pub fn into_routes(self) -> Routes {
        self.routes
    }
}

/// The method paths of `service` in the embedded `ethswarm.*` descriptor set (none if it is not
/// there).
fn described_methods(service: &str) -> BTreeSet<String> {
    let set = FileDescriptorSet::decode(ethswarm_proto::FILE_DESCRIPTOR_SET)
        .expect("the embedded descriptor set decodes");
    let mut out = BTreeSet::new();
    for file in &set.file {
        for svc in &file.service {
            let full = format!("{}.{}", file.package(), svc.name());
            if full == service {
                out.extend(svc.method.iter().map(|m| format!("/{full}/{}", m.name())));
            }
        }
    }
    out
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

    /// A service outside the `ethswarm.*` descriptor set.
    #[derive(Clone, Copy)]
    struct Health;

    impl NamedService for Health {
        const NAME: &'static str = "grpc.health.v1.Health";
    }

    impl tower::Service<http::Request<Body>> for Health {
        type Response = http::Response<Body>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Infallible>>;

        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Infallible>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: http::Request<Body>) -> Self::Future {
            std::future::ready(Ok(Status::unimplemented("test").into_http()))
        }
    }

    #[test]
    fn a_service_outside_ethswarm_brings_its_methods() {
        const CHECK: &str = "/grpc.health.v1.Health/Check";
        const WATCH: &str = "/grpc.health.v1.Health/Watch";
        // Added without a method list it answers nothing the ACL may name.
        let bare = Services::new().add_service(Health);
        assert!(bare.methods().is_empty());
        assert_eq!(bare.unserved_paths([CHECK]), [CHECK]);

        let s = Services::new()
            .add_service(SyncServiceServer::new(Sync))
            .add_service_with_methods(Health, ["Check", "Watch"]);
        assert_eq!(
            s.names().collect::<Vec<_>>(),
            ["ethswarm.sync.v1.SyncService", "grpc.health.v1.Health"]
        );
        assert_eq!(
            s.methods().into_iter().collect::<Vec<_>>(),
            [
                "/ethswarm.sync.v1.SyncService/GetSyncProgress",
                "/ethswarm.sync.v1.SyncService/StartBackfill",
                CHECK,
                WATCH,
            ]
        );
        let ok = [CHECK, WATCH, "/ethswarm.sync.v1.SyncService/StartBackfill"];
        assert!(s.unserved_paths(ok).is_empty());
        let typo = [
            CHECK,
            "/grpc.health.v1.Health/Chek",
            "/grpc.health.v1.Other/Check",
        ];
        assert_eq!(
            s.unserved_paths(typo),
            ["/grpc.health.v1.Health/Chek", "/grpc.health.v1.Other/Check"]
        );
        // The ethswarm service's paths are still checked through the ACL as before.
        let acl = acl(&["/ethswarm.sync.v1.SyncService/StartBackFill"]);
        assert_eq!(
            s.unserved(&acl),
            ["/ethswarm.sync.v1.SyncService/StartBackFill"]
        );
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
