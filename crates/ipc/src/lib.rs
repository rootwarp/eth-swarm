//! The contract layer every ETH Swarm service puts in front of its gRPC handlers.
//!
//! `proto/README.md` is normative; this crate implements its cross-package rules once:
//!
//! - [`hello`]: the stream handshake. The whole `common.v1.Hello` is compared and the link uses
//!   the highest common API version, `min(max_a, max_b)`, failing below `max(min_a, min_b)` or
//!   the configured floor with `ERROR_CODE_VERSION_MISMATCH`. There is no fallback.
//! - [`frame`]: `oneof frame { hello; body }` discipline (exactly one leading hello per stream
//!   direction) and `Envelope.seq` (strictly increasing from 1 per direction, 0 on unary calls).
//! - [`envelope`]: `open_envelope`, which refuses a zero `payload_type`, ignores an unknown one,
//!   drops a fork digest that does not match the slot's fork, and only then decodes.
//! - [`error`]: [`error::ContractError`] and its `common.v1.Error` / `tonic::Status` forms.
//! - [`link`]: one service's contract configuration and the guarded inbound stream.
//! - [`peercred`]: the Unix-socket peer's UID, checked by both ends of every link.
//! - [`uds`]: the service-owned socket directory (`/run/ethswarm/<svc>/`, 0750, socket 0660),
//!   stale-socket cleanup that never follows a symlink or removes a live or foreign socket, and
//!   the client connector that checks the server's UID before sending a byte.
//! - [`acl`]: per-method caller UIDs from `/etc/ethswarm/<svc>.toml`, as a tower layer.
//! - [`stub`]: handlers for RPCs that are not implemented yet: the contract checks run, then the
//!   call fails with `UNIMPLEMENTED`.
//! - `testkit` (feature `testkit`): the contract suite run against every service, in process
//!   and over a Unix socket.

pub mod acl;
pub mod envelope;
pub mod error;
pub mod frame;
pub mod hello;
pub mod link;
pub mod peercred;
pub mod stub;
#[cfg(feature = "testkit")]
pub mod testkit;
pub mod uds;

pub use error::ContractError;
pub use link::{ContractMetrics, Link};

/// Spawns `future` inside the current tracing span. A streaming handler's worker runs on its
/// own task, outside the span of the call that started it; spawned through this, what it logs
/// still carries that call's span (the method and `trace_id` the service runtime records).
pub fn spawn_in_span<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    use tracing::Instrument;
    tokio::spawn(future.in_current_span())
}
