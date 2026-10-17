//! Per-method caller ACLs: which peer UIDs may call each gRPC method of a service.
//!
//! The socket directory's mode lets only the service's caller group connect at all
//! ([`crate::uds`]); the ACL then decides per method. It is read from the service's config file,
//! `/etc/ethswarm/<service>.toml` by default ([`config_path`]):
//!
//! ```toml
//! [callers]                  # caller name = UID
//! cl-chain = 990
//!
//! [methods]                  # gRPC method path = caller names
//! "/ethswarm.engine.v1.EngineService/NewPayload" = ["cl-chain"]
//! ```
//!
//! Other tables of the file belong to the service runtime and are ignored here. Each method
//! path must belong to the service's own package (`cl-engine` serves `ethswarm.engine.v1`).
//!
//! - A method that is not listed is denied, and so is a caller whose UID is not listed for the
//!   method or a request without peer credentials. Denial is `PERMISSION_DENIED` carrying
//!   `ERROR_CODE_CONTRACT_VIOLATION` ([`Denied::to_status`]), before the request is decoded.
//! - cl-engine and cl-verify are called only by cl-chain ([`sole_caller`]): their ACL must give
//!   every method to `cl-chain` and nobody else, or it does not load.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ethswarm_proto::common::ErrorCode;
use prost::Message;
use serde::Deserialize;
use tonic::{Code, Status};

use crate::error::wire_error;
use crate::peercred::peer_uid;

/// Where service configs live unless a test or the command line says otherwise.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/ethswarm";

/// `/etc/ethswarm/<service>.toml`.
#[must_use]
pub fn config_path(service: &str) -> PathBuf {
    Path::new(DEFAULT_CONFIG_DIR).join(format!("{service}.toml"))
}

/// The only caller a service accepts, where the architecture fixes one: cl-engine (the only
/// holder of the JWT secret) and cl-verify are called only by cl-chain.
#[must_use]
pub fn sole_caller(service: &str) -> Option<&'static str> {
    match service {
        "cl-engine" | "cl-verify" => Some("cl-chain"),
        _ => None,
    }
}

/// The proto package a service serves: `cl-<name>` serves `ethswarm.<name>.v1`.
#[must_use]
pub fn package_of(service: &str) -> Option<String> {
    let name = service.strip_prefix("cl-")?;
    is_name(name).then(|| format!("ethswarm.{name}.v1"))
}

/// The service that serves a proto package (the inverse of [`package_of`]).
#[must_use]
pub fn service_of(package: &str) -> Option<String> {
    let name = package.strip_prefix("ethswarm.")?.strip_suffix(".v1")?;
    is_name(name).then(|| format!("cl-{name}"))
}

/// Lowercase ASCII letters, digits and `-`, not empty.
fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The `[callers]` and `[methods]` tables of a service config.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct AclTables {
    /// Caller name to UID.
    #[serde(default)]
    pub callers: BTreeMap<String, u32>,
    /// gRPC method path (`/<package>.<Service>/<Method>`) to the caller names allowed on it.
    #[serde(default)]
    pub methods: BTreeMap<String, Vec<String>>,
}

/// Why an ACL did not load.
#[derive(Debug, thiserror::Error)]
pub enum AclError {
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{}: {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("{0:?} is not a service name (cl-<name>, lowercase letters, digits and -)")]
    Service(String),
    #[error("{0:?} is not a caller name (lowercase letters, digits and -)")]
    CallerName(String),
    #[error("{method:?} is not a method of {package} (/<package>.<Service>/<Method>)")]
    Method { method: String, package: String },
    #[error("{method}: no callers listed; remove the method to deny it")]
    NoCallers { method: String },
    #[error("{method}: caller {caller:?} is not in [callers]")]
    UnknownCaller { method: String, caller: String },
    #[error("{method}: caller {caller:?} listed twice")]
    DuplicateCaller { method: String, caller: String },
    #[error("{service}: no method is allowed to anyone")]
    Empty { service: String },
    #[error("{service} is called only by {only}; {method} allows {callers:?}")]
    SoleCaller {
        service: String,
        only: &'static str,
        method: String,
        callers: Vec<String>,
    },
}

/// A refused call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denied {
    pub method: String,
    /// The caller's UID, `None` without peer credentials.
    pub peer: Option<u32>,
    pub service: String,
}

impl Denied {
    /// `PERMISSION_DENIED`, with `ERROR_CODE_CONTRACT_VIOLATION` in the status details.
    #[must_use]
    pub fn to_status(&self) -> Status {
        let who = self
            .peer
            .map_or_else(|| "no peer credentials".to_owned(), |u| format!("uid {u}"));
        let err = wire_error(
            ErrorCode::ContractViolation,
            format!("{who} may not call {} on {}", self.method, self.service),
        );
        Status::with_details(
            Code::PermissionDenied,
            err.detail.clone(),
            err.encode_to_vec().into(),
        )
    }
}

/// Which UIDs may call each method of one service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodAcl {
    service: String,
    methods: BTreeMap<String, BTreeSet<u32>>,
}

impl MethodAcl {
    /// The ACL of `service` from its config file at `path`.
    pub fn load(path: &Path, service: &str) -> Result<Self, AclError> {
        let text = std::fs::read_to_string(path).map_err(|source| AclError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml(&text, path, service)
    }

    /// The ACL of `service` from config text (`path` names it in errors).
    pub fn from_toml(text: &str, path: &Path, service: &str) -> Result<Self, AclError> {
        let tables: AclTables = toml::from_str(text).map_err(|source| AclError::Parse {
            path: path.to_owned(),
            source: Box::new(source),
        })?;
        Self::from_tables(service, &tables)
    }

    /// Checks `tables` and resolves caller names to UIDs.
    pub fn from_tables(service: &str, tables: &AclTables) -> Result<Self, AclError> {
        let package = package_of(service).ok_or_else(|| AclError::Service(service.to_owned()))?;
        if let Some(name) = tables.callers.keys().find(|n| !is_name(n)) {
            return Err(AclError::CallerName(name.clone()));
        }
        let only = sole_caller(service);
        let mut methods = BTreeMap::new();
        for (method, callers) in &tables.methods {
            if !is_method_of(method, &package) {
                return Err(AclError::Method {
                    method: method.clone(),
                    package,
                });
            }
            if callers.is_empty() {
                return Err(AclError::NoCallers {
                    method: method.clone(),
                });
            }
            if let Some(only) = only {
                if callers.len() != 1 || callers[0] != only {
                    return Err(AclError::SoleCaller {
                        service: service.to_owned(),
                        only,
                        method: method.clone(),
                        callers: callers.clone(),
                    });
                }
            }
            let mut names = BTreeSet::new();
            let mut uids = BTreeSet::new();
            for caller in callers {
                if !names.insert(caller) {
                    return Err(AclError::DuplicateCaller {
                        method: method.clone(),
                        caller: caller.clone(),
                    });
                }
                let uid = tables
                    .callers
                    .get(caller)
                    .ok_or_else(|| AclError::UnknownCaller {
                        method: method.clone(),
                        caller: caller.clone(),
                    })?;
                uids.insert(*uid);
            }
            methods.insert(method.clone(), uids);
        }
        if methods.is_empty() {
            return Err(AclError::Empty {
                service: service.to_owned(),
            });
        }
        Ok(Self {
            service: service.to_owned(),
            methods,
        })
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Every listed method path.
    pub fn methods(&self) -> impl Iterator<Item = &str> {
        self.methods.keys().map(String::as_str)
    }

    /// Whether `uid` may call `method`.
    #[must_use]
    pub fn allows(&self, method: &str, uid: u32) -> bool {
        self.methods.get(method).is_some_and(|u| u.contains(&uid))
    }

    /// `Ok` if `peer` may call `method`; an unlisted method, an unlisted UID and a request
    /// without credentials are all denied.
    pub fn check(&self, method: &str, peer: Option<u32>) -> Result<(), Denied> {
        match peer {
            Some(uid) if self.allows(method, uid) => Ok(()),
            _ => Err(Denied {
                method: method.to_owned(),
                peer,
                service: self.service.clone(),
            }),
        }
    }
}

/// `/<package>.<Service>/<Method>` with non-empty identifiers.
fn is_method_of(path: &str, package: &str) -> bool {
    let ident =
        |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    path.strip_prefix('/')
        .and_then(|p| p.strip_prefix(package))
        .and_then(|p| p.strip_prefix('.'))
        .and_then(|p| p.split_once('/'))
        .is_some_and(|(svc, method)| ident(svc) && ident(method))
}

type DeniedHook = Arc<dyn Fn(&Denied) + Send + Sync>;

/// A tower layer that applies a [`MethodAcl`] to every request before the service sees it.
/// The caller's UID comes from the connection ([`peer_uid`]); a denied request is answered
/// with [`Denied::to_status`] and its body is never read.
#[derive(Clone)]
pub struct AclLayer {
    acl: Arc<MethodAcl>,
    on_denied: Option<DeniedHook>,
}

impl std::fmt::Debug for AclLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AclLayer")
            .field("acl", &self.acl)
            .finish_non_exhaustive()
    }
}

impl AclLayer {
    #[must_use]
    pub fn new(acl: Arc<MethodAcl>) -> Self {
        Self {
            acl,
            on_denied: None,
        }
    }

    /// Calls `hook` for every denied request (after it is logged), e.g. to count it.
    #[must_use]
    pub fn on_denied(mut self, hook: impl Fn(&Denied) + Send + Sync + 'static) -> Self {
        self.on_denied = Some(Arc::new(hook));
        self
    }
}

impl<S> tower::Layer<S> for AclLayer {
    type Service = AclService<S>;

    fn layer(&self, inner: S) -> AclService<S> {
        AclService {
            inner,
            layer: self.clone(),
        }
    }
}

/// The service [`AclLayer`] wraps around `S`.
#[derive(Clone, Debug)]
pub struct AclService<S> {
    inner: S,
    layer: AclLayer,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl<S, B, R> tower::Service<http::Request<B>> for AclService<S>
where
    S: tower::Service<http::Request<B>, Response = http::Response<R>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    R: Default + Send + 'static,
{
    type Response = http::Response<R>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let peer = peer_uid(request.extensions());
        match self.layer.acl.check(request.uri().path(), peer) {
            Ok(()) => Box::pin(self.inner.call(request)),
            Err(denied) => {
                tracing::warn!(
                    service = %denied.service,
                    method = %denied.method,
                    peer = ?denied.peer,
                    "caller refused by the method ACL"
                );
                if let Some(hook) = &self.layer.on_denied {
                    hook(&denied);
                }
                let response = denied.to_status().into_http::<R>();
                Box::pin(std::future::ready(Ok(response)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tower::{Layer, ServiceExt};

    const NEW_PAYLOAD: &str = "/ethswarm.engine.v1.EngineService/NewPayload";
    const PROGRESS: &str = "/ethswarm.sync.v1.SyncService/GetSyncProgress";
    const BACKFILL: &str = "/ethswarm.sync.v1.SyncService/StartBackfill";

    fn parse(service: &str, text: &str) -> Result<MethodAcl, AclError> {
        MethodAcl::from_toml(text, Path::new("test.toml"), service)
    }

    const SYNC: &str = r#"
        network = "sepolia"   # runtime keys are ignored here

        [callers]
        cl-chain = 990
        cl-api = 993

        [methods]
        "/ethswarm.sync.v1.SyncService/GetSyncProgress" = ["cl-chain", "cl-api"]
        "/ethswarm.sync.v1.SyncService/StartBackfill" = ["cl-chain"]
    "#;

    #[test]
    fn listed_callers_are_allowed_per_method() {
        let acl = parse("cl-sync", SYNC).unwrap();
        assert_eq!(acl.service(), "cl-sync");
        assert_eq!(acl.methods().collect::<Vec<_>>(), [PROGRESS, BACKFILL]);
        assert!(acl.allows(PROGRESS, 990) && acl.allows(PROGRESS, 993));
        assert!(acl.allows(BACKFILL, 990));
        assert_eq!(acl.check(BACKFILL, Some(990)), Ok(()));
        let denied = acl.check(BACKFILL, Some(993)).unwrap_err();
        assert_eq!(
            denied,
            Denied {
                method: BACKFILL.into(),
                peer: Some(993),
                service: "cl-sync".into(),
            }
        );
    }

    #[test]
    fn unlisted_methods_uids_and_missing_credentials_are_denied() {
        let acl = parse("cl-sync", SYNC).unwrap();
        assert!(acl
            .check("/ethswarm.sync.v1.SyncService/Other", Some(990))
            .is_err());
        assert!(acl.check(PROGRESS, Some(0)).is_err(), "root is not listed");
        assert!(acl.check(PROGRESS, None).is_err());
    }

    #[test]
    fn denial_is_permission_denied_with_a_contract_violation() {
        let status = Denied {
            method: BACKFILL.into(),
            peer: Some(993),
            service: "cl-sync".into(),
        }
        .to_status();
        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(status.message().contains("uid 993"), "{status:?}");
        let e = crate::ContractError::from_status(&status);
        assert_eq!(e.code(), ErrorCode::ContractViolation);
        let anonymous = Denied {
            method: BACKFILL.into(),
            peer: None,
            service: "cl-sync".into(),
        };
        assert!(anonymous
            .to_status()
            .message()
            .contains("no peer credentials"));
    }

    #[test]
    fn engine_and_verify_allow_only_cl_chain() {
        assert_eq!(sole_caller("cl-engine"), Some("cl-chain"));
        assert_eq!(sole_caller("cl-verify"), Some("cl-chain"));
        assert_eq!(sole_caller("cl-store"), None);
        let ok =
            format!("[callers]\ncl-chain = 990\n[methods]\n\"{NEW_PAYLOAD}\" = [\"cl-chain\"]");
        assert!(parse("cl-engine", &ok).unwrap().allows(NEW_PAYLOAD, 990));
        for callers in [r#"["cl-chain", "cl-api"]"#, r#"["cl-api"]"#] {
            let text = format!(
                "[callers]\ncl-chain = 990\ncl-api = 993\n[methods]\n\"{NEW_PAYLOAD}\" = {callers}"
            );
            let err = parse("cl-engine", &text).unwrap_err();
            assert!(
                matches!(err, AclError::SoleCaller { .. }),
                "{callers}: {err}"
            );
            assert!(err.to_string().contains("only by cl-chain"), "{err}");
        }
    }

    type Case = (&'static str, &'static str, fn(&AclError) -> bool);

    #[test]
    fn malformed_tables_do_not_load() {
        let cases: [Case; 8] = [
            ("engine", "", |e| matches!(e, AclError::Service(_))),
            ("cl-sync", "[callers]\nCl_Chain = 1", |e| {
                matches!(e, AclError::CallerName(_))
            }),
            (
                "cl-sync",
                "[callers]\na = 1\n[methods]\n\"/ethswarm.sync.v1.SyncService/X\" = []",
                |e| matches!(e, AclError::NoCallers { .. }),
            ),
            (
                "cl-sync",
                "[callers]\na = 1\n[methods]\n\"/ethswarm.sync.v1.SyncService/X\" = [\"b\"]",
                |e| matches!(e, AclError::UnknownCaller { .. }),
            ),
            (
                "cl-sync",
                "[callers]\na = 1\n[methods]\n\"/ethswarm.sync.v1.SyncService/X\" = [\"a\", \"a\"]",
                |e| matches!(e, AclError::DuplicateCaller { .. }),
            ),
            (
                "cl-sync",
                "[callers]\na = 1\n[methods]\n\"/ethswarm.engine.v1.EngineService/NewPayload\" = [\"a\"]",
                |e| matches!(e, AclError::Method { .. }),
            ),
            ("cl-sync", "[callers]\na = 1", |e| {
                matches!(e, AclError::Empty { .. })
            }),
            ("cl-sync", "[methods\n", |e| matches!(e, AclError::Parse { .. })),
        ];
        for (service, text, want) in cases {
            let err = parse(service, text).unwrap_err();
            assert!(want(&err), "{service} {text:?}: {err}");
        }
    }

    #[test]
    fn method_paths_must_be_fully_qualified() {
        let pkg = "ethswarm.sync.v1";
        assert!(is_method_of(PROGRESS, pkg));
        for bad in [
            "ethswarm.sync.v1.SyncService/GetSyncProgress",
            "/ethswarm.sync.v1.SyncService/",
            "/ethswarm.sync.v1./GetSyncProgress",
            "/ethswarm.sync.v1.SyncService/Get/More",
            "/ethswarm.sync.v1SyncService/GetSyncProgress",
            "/ethswarm.sync.v2.SyncService/GetSyncProgress",
        ] {
            assert!(!is_method_of(bad, pkg), "{bad}");
        }
    }

    #[test]
    fn packages_and_services_map_both_ways() {
        assert_eq!(
            package_of("cl-engine").as_deref(),
            Some("ethswarm.engine.v1")
        );
        assert_eq!(
            service_of("ethswarm.engine.v1").as_deref(),
            Some("cl-engine")
        );
        assert_eq!(package_of("engine"), None);
        assert_eq!(package_of("cl-"), None);
        assert_eq!(service_of("ethswarm.engine.v2"), None);
        assert_eq!(
            config_path("cl-engine"),
            Path::new("/etc/ethswarm/cl-engine.toml")
        );
    }

    #[test]
    fn load_reads_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cl-sync.toml");
        assert!(matches!(
            MethodAcl::load(&path, "cl-sync"),
            Err(AclError::Read { .. })
        ));
        std::fs::write(&path, SYNC).unwrap();
        assert_eq!(
            MethodAcl::load(&path, "cl-sync").unwrap(),
            parse("cl-sync", SYNC).unwrap()
        );
    }

    fn request(path: &str, peer: Option<tokio::net::unix::UCred>) -> http::Request<()> {
        let mut req = http::Request::builder().uri(path).body(()).unwrap();
        req.extensions_mut()
            .insert(tonic::transport::server::UdsConnectInfo {
                peer_addr: None,
                peer_cred: peer,
            });
        req
    }

    #[tokio::test]
    async fn layer_answers_denied_calls_without_reaching_the_service() {
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        let me = a.peer_cred().unwrap();
        let text = format!(
            "[callers]\nme = {}\nother = {}\n[methods]\n\"{PROGRESS}\" = [\"me\"]\n\"{BACKFILL}\" = [\"other\"]",
            me.uid(),
            me.uid().wrapping_add(1)
        );
        let acl = Arc::new(parse("cl-sync", &text).unwrap());
        let reached = Arc::new(AtomicU64::new(0));
        let denied = Arc::new(AtomicU64::new(0));
        let inner = {
            let reached = Arc::clone(&reached);
            tower::service_fn(move |_: http::Request<()>| {
                reached.fetch_add(1, Ordering::Relaxed);
                async { Ok::<_, std::convert::Infallible>(http::Response::new(String::new())) }
            })
        };
        let counted = Arc::clone(&denied);
        let layer = AclLayer::new(acl).on_denied(move |_| {
            counted.fetch_add(1, Ordering::Relaxed);
        });
        assert!(format!("{layer:?}").contains("AclLayer"));
        let svc = layer.layer(inner);

        let ok = svc
            .clone()
            .oneshot(request(PROGRESS, Some(me)))
            .await
            .unwrap();
        assert_eq!(ok.headers().get("grpc-status"), None, "passed through");
        for (path, peer) in [(BACKFILL, Some(me)), (PROGRESS, None), ("/x.Y/Z", Some(me))] {
            let resp = svc.clone().oneshot(request(path, peer)).await.unwrap();
            let status = Status::from_header_map(resp.headers()).expect("grpc status");
            assert_eq!(status.code(), Code::PermissionDenied, "{path}");
        }
        let bare = http::Request::builder().uri(PROGRESS).body(()).unwrap();
        let resp = svc.clone().oneshot(bare).await.unwrap();
        assert_eq!(
            Status::from_header_map(resp.headers()).unwrap().code(),
            Code::PermissionDenied,
            "no connection info"
        );
        assert_eq!(reached.load(Ordering::Relaxed), 1);
        assert_eq!(denied.load(Ordering::Relaxed), 4);
    }
}
