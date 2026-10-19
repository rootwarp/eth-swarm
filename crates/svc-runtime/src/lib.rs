//! The bootstrap every ETH Swarm service process runs.
//!
//! ```ignore
//! let config = svc_runtime::Config::load("cl-engine", &svc_runtime::config::config_path("cl-engine"))?;
//! let services = svc_runtime::Services::new().add_service(EngineServiceServer::new(engine));
//! // A log writer that cannot start ends `run` at once, writing nothing:
//! // `exit_code` is then `telemetry::EXIT_NO_LOG_WRITER`.
//! let result = svc_runtime::run(config, services).await;
//! // `run` has logged its error and flushed the log queue. Anything logged after it goes
//! // through `tracing` too (never `eprintln!`: stderr may be stalled), then flush again:
//! svc_runtime::telemetry::flush_logs_async(svc_runtime::lifecycle::LOG_FLUSH_DEADLINE).await;
//! svc_runtime::exit_code(&result)
//! ```
//!
//! - [`config`]: `/etc/ethswarm/<svc>.toml`: the network (resolved through `network-config`),
//!   the `/metrics` port, the drain deadline, the socket group and the method ACL.
//! - [`telemetry`]: JSON `tracing` with a `trace_id` per call, and prometheus-client metrics at
//!   `127.0.0.1:91NN/metrics`.
//! - [`log_writer`]: the bounded queue and writer thread between `tracing` and stderr.
//! - [`lifecycle`]: [`run`]: bind the service socket (`ipc::uds`), serve behind the method ACL
//!   (`ipc::acl`), `sd_notify` READY, and on SIGTERM stop accepting, send STOPPING, and drain
//!   in-flight calls within the deadline.
//! - [`services`]: the gRPC services served and their method paths; an ACL entry nothing
//!   serves fails startup.
//! - [`notify`]: `sd_notify(3)` without libsystemd.

pub mod config;
pub mod lifecycle;
pub mod log_writer;
pub mod notify;
pub mod services;
pub mod telemetry;

pub use config::Config;
pub use lifecycle::{exit_code, run, run_with, Hooks, RuntimeError};
pub use services::Services;
