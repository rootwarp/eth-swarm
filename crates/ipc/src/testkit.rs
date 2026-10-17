//! The contract suite every service runs: one `#[test]` per rule, once in process and once
//! over a Unix socket in a temp dir.
//!
//! A service's `tests/contract.rs` builds a [`Target`] from a [`Link`] (its tonic routes behind
//! the ipc layers, plus the probes for its wire surface) and calls [`contract_suite!`]:
//!
//! ```ignore
//! fn target(link: ipc::Link) -> ipc::testkit::Target { /* ... */ }
//! ipc::contract_suite!(target);
//! ```
//!
//! That expands to `in_process::<rule>` and `uds::<rule>` for every [`Rule`], so
//! `cargo test --test contract -- --list` shows each rule twice. In process, the client calls
//! the tower service directly (no socket, no HTTP/2); over UDS it goes through tonic's server
//! and a channel on a socket in a fresh temp dir. Both run in this process under one UID, so
//! the peer-UID rule (`so_peercred`) puts the target behind an [`crate::acl::AclLayer`] that
//! names our UID or another one: the kernel credentials of the connection (over UDS) or this
//! process's credentials read from a socket pair (in process) are what the ACL checks.

pub mod fixture;
pub mod probe;
pub mod suite;
pub mod surface;

use std::convert::Infallible;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use hyper_util::rt::TokioIo;
use tokio::net::unix::UCred;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::body::Body;
use tonic::codegen::StdError;
use tonic::service::Routes;
use tonic::transport::server::UdsConnectInfo;
use tonic::transport::{Endpoint, Uri};
use tower::util::BoxCloneSyncService;
use tower::{ServiceBuilder, ServiceExt};

use crate::acl::{AclLayer, MethodAcl};

pub use crate::link::Link;
pub use probe::{Answer, Probe, Step, UnaryProbe};
pub use suite::{ContractSuite, Rule, Target};

/// A boxed future, for object-safe probes.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// The client side of a connection: any gRPC client can run over it.
pub type Transport = BoxCloneSyncService<http::Request<Body>, http::Response<Body>, TransportError>;

/// A transport failure (a concrete error type keeps client futures `Send`).
#[derive(Debug)]
pub struct TransportError(StdError);

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// Serves a [`Server`] on a Unix socket until the receiver fires.
pub type UdsServe =
    Arc<dyn Fn(UnixListener, oneshot::Receiver<()>) -> BoxFuture<()> + Send + Sync + 'static>;

type ExtensionHook = Arc<dyn Fn(&mut http::Extensions) + Send + Sync + 'static>;

/// What a test connects to: tonic routes, plus how to serve them over UDS.
#[derive(Clone)]
pub struct Server {
    routes: Routes,
    in_process_extensions: Option<ExtensionHook>,
    uds: Option<UdsServe>,
}

impl Server {
    /// Routes served by tonic's server over UDS and called directly in process.
    #[must_use]
    pub fn new(routes: Routes) -> Self {
        Self {
            routes,
            in_process_extensions: None,
            uds: None,
        }
    }

    /// Adds request extensions on the in-process path, where no connection supplies them
    /// (e.g. the `UdsConnectInfo` a Unix-socket connection would carry).
    #[must_use]
    pub fn with_in_process_extensions(
        mut self,
        hook: impl Fn(&mut http::Extensions) + Send + Sync + 'static,
    ) -> Self {
        self.in_process_extensions = Some(Arc::new(hook));
        self
    }

    /// Serves over UDS with the service's own server function instead of plain tonic.
    #[must_use]
    pub fn with_uds_server(mut self, serve: UdsServe) -> Self {
        self.uds = Some(serve);
        self
    }
}

/// How a rule reaches the service.
#[derive(Clone, Debug)]
pub enum Mode {
    /// The tower service is called directly.
    InProcess,
    /// Through a Unix socket created in this directory.
    Uds(PathBuf),
}

/// A live connection; dropping it stops the UDS server.
pub struct Connection {
    pub transport: Transport,
    _shutdown: Option<oneshot::Sender<()>>,
}

static SOCKETS: AtomicU64 = AtomicU64::new(0);

/// A fresh socket path in `dir`.
fn next_socket(dir: &Path) -> PathBuf {
    let n = SOCKETS.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("svc-{n}.sock"))
}

/// A connection to a target served behind a method ACL.
pub struct AclConnection {
    pub connection: Connection,
    /// Requests that passed the ACL and reached the target.
    pub reached: Arc<AtomicU64>,
    /// The socket the target listens on (over UDS).
    pub socket: Option<PathBuf>,
}

impl AclConnection {
    #[must_use]
    pub fn reached(&self) -> u64 {
        self.reached.load(Ordering::Relaxed)
    }
}

/// This process's credentials as the peer of a Unix socket sees them (read once from a
/// connected socket pair).
#[must_use]
pub fn own_cred() -> UCred {
    static CRED: OnceLock<UCred> = OnceLock::new();
    *CRED.get_or_init(|| {
        // tokio needs a runtime to wrap the stream; use a private one on its own thread, so this
        // works inside and outside the caller's runtime.
        std::thread::spawn(|| {
            let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socket pair");
            a.set_nonblocking(true).expect("nonblocking");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("runtime");
            let _entered = rt.enter();
            UnixStream::from_std(a)
                .expect("tokio stream")
                .peer_cred()
                .expect("peer credentials")
        })
        .join()
        .expect("read own credentials")
    })
}

impl Mode {
    #[must_use]
    pub fn over_uds(dir: &Path) -> Self {
        Self::Uds(dir.to_path_buf())
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::InProcess => "in_process",
            Self::Uds(_) => "uds",
        }
    }

    /// Serves `server` this way and returns a client transport to it.
    pub async fn connect(&self, server: Server) -> Connection {
        match self {
            Self::InProcess => Connection {
                transport: in_process(server),
                _shutdown: None,
            },
            Self::Uds(dir) => {
                let path = next_socket(dir);
                let listener = UnixListener::bind(&path)
                    .unwrap_or_else(|e| panic!("bind {}: {e}", path.display()));
                let (tx, rx) = oneshot::channel();
                match server.uds {
                    Some(serve) => {
                        tokio::spawn(serve(listener, rx));
                    }
                    None => {
                        tokio::spawn(crate::stub::serve_uds(listener, server.routes, async {
                            let _ = rx.await;
                        }));
                    }
                }
                Connection {
                    transport: uds_channel(&path).await,
                    _shutdown: Some(tx),
                }
            }
        }
    }

    /// Serves `server`'s routes behind `acl` (outermost, ahead of the target's own layers) and
    /// returns a client transport to it. In process, `credentials` says whether requests carry
    /// this process's Unix credentials ([`own_cred`]); over UDS the kernel always supplies them
    /// and the routes are served by plain tonic (a target's own UDS server is not used).
    pub async fn connect_behind_acl(
        &self,
        server: Server,
        acl: Arc<MethodAcl>,
        credentials: bool,
    ) -> AclConnection {
        let reached = Arc::new(AtomicU64::new(0));
        let count = {
            let reached = Arc::clone(&reached);
            move |req: http::Request<Body>| {
                reached.fetch_add(1, Ordering::Relaxed);
                req
            }
        };
        match self {
            Self::InProcess => {
                let cred = credentials.then(own_cred);
                let hook = server.in_process_extensions;
                let svc = ServiceBuilder::new()
                    .map_request(move |mut req: http::Request<Body>| {
                        if let Some(cred) = cred {
                            req.extensions_mut().insert(UdsConnectInfo {
                                peer_addr: None,
                                peer_cred: Some(cred),
                            });
                        }
                        req
                    })
                    .layer(AclLayer::new(acl))
                    .map_request(count)
                    .map_request(move |mut req: http::Request<Body>| {
                        if let Some(hook) = &hook {
                            hook(req.extensions_mut());
                        }
                        req
                    })
                    .service(server.routes.prepare())
                    .map_err(|never: Infallible| -> TransportError { match never {} });
                AclConnection {
                    connection: Connection {
                        transport: BoxCloneSyncService::new(svc),
                        _shutdown: None,
                    },
                    reached,
                    socket: None,
                }
            }
            Self::Uds(dir) => {
                let path = next_socket(dir);
                let listener = UnixListener::bind(&path)
                    .unwrap_or_else(|e| panic!("bind {}: {e}", path.display()));
                let (tx, rx) = oneshot::channel::<()>();
                let layers = ServiceBuilder::new()
                    .layer(AclLayer::new(acl))
                    .map_request(count);
                tokio::spawn(
                    tonic::transport::Server::builder()
                        .layer(layers)
                        .add_routes(server.routes)
                        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                            let _ = rx.await;
                        }),
                );
                AclConnection {
                    connection: Connection {
                        transport: uds_channel(&path).await,
                        _shutdown: Some(tx),
                    },
                    reached,
                    socket: Some(path),
                }
            }
        }
    }
}

fn in_process(server: Server) -> Transport {
    let hook = server.in_process_extensions;
    let svc = ServiceBuilder::new()
        .map_request(move |mut req: http::Request<Body>| {
            if let Some(hook) = &hook {
                hook(req.extensions_mut());
            }
            req
        })
        .service(server.routes.prepare())
        .map_err(|never: Infallible| -> TransportError { match never {} });
    BoxCloneSyncService::new(svc)
}

async fn uds_channel(path: &Path) -> Transport {
    let path = path.to_path_buf();
    let channel = Endpoint::try_from("http://[::]:50051")
        .expect("static URI")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .expect("connect to the service socket");
    BoxCloneSyncService::new(channel.map_err(|e| TransportError(e.into())))
}

/// A fresh temp dir for one UDS run.
#[must_use]
pub fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("contract-")
        .tempdir()
        .expect("create a temp dir")
}

/// Runs `fut` to completion on a fresh multi-threaded runtime.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build a tokio runtime")
        .block_on(fut)
}

/// Expands to `mod in_process` and `mod uds`, each with one `#[test]` per [`Rule`], run
/// against the target `$factory(link)` builds. Extra service-specific rules
/// (`async fn name(mode: Mode)`, defined next to the macro call) are added to both modules.
#[macro_export]
macro_rules! contract_suite {
    ($factory:ident $(, extra: [$($extra:ident),* $(,)?])? $(,)?) => {
        mod in_process {
            $crate::contract_suite!(@rules in_process, $factory;
                hello_version_n_n1 => HelloVersionNN1,
                hello_floor => HelloFloor,
                hello_pin_mismatch => HelloPinMismatch,
                hello_once => HelloOnce,
                seq_monotonic => SeqMonotonic,
                envelope_type_rules => EnvelopeTypeRules,
                envelope_digest_mismatch => EnvelopeDigestMismatch,
                unary_no_hello => UnaryNoHello,
                so_peercred => SoPeercred,
            );
            $($(
                #[test]
                fn $extra() {
                    $crate::testkit::block_on(super::$extra($crate::testkit::Mode::InProcess));
                }
            )*)?
        }

        mod uds {
            $crate::contract_suite!(@rules uds, $factory;
                hello_version_n_n1 => HelloVersionNN1,
                hello_floor => HelloFloor,
                hello_pin_mismatch => HelloPinMismatch,
                hello_once => HelloOnce,
                seq_monotonic => SeqMonotonic,
                envelope_type_rules => EnvelopeTypeRules,
                envelope_digest_mismatch => EnvelopeDigestMismatch,
                unary_no_hello => UnaryNoHello,
                so_peercred => SoPeercred,
            );
            $($(
                #[test]
                fn $extra() {
                    let dir = $crate::testkit::tempdir();
                    $crate::testkit::block_on(super::$extra(
                        $crate::testkit::Mode::over_uds(dir.path()),
                    ));
                }
            )*)?
        }
    };
    (@rules $mode:ident, $factory:ident; $($name:ident => $rule:ident),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                $crate::contract_suite!(@run $mode, $factory, $crate::testkit::Rule::$rule);
            }
        )*
    };
    (@run in_process, $factory:ident, $rule:expr) => {
        $crate::testkit::block_on(
            $crate::testkit::ContractSuite::new(super::$factory).run_in_process($rule),
        )
    };
    (@run uds, $factory:ident, $rule:expr) => {{
        let dir = $crate::testkit::tempdir();
        $crate::testkit::block_on(
            $crate::testkit::ContractSuite::new(super::$factory).run_over_uds($rule, dir.path()),
        )
    }};
}
