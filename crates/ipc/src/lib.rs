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
//! - [`stub`]: handlers for RPCs that are not implemented yet: the contract checks run, then the
//!   call fails with `UNIMPLEMENTED`.
//! - `testkit` (feature `testkit`): the contract suite run against every service, in process
//!   and over a Unix socket.

pub mod envelope;
pub mod error;
pub mod frame;
pub mod hello;
pub mod link;
pub mod stub;
#[cfg(feature = "testkit")]
pub mod testkit;

pub use error::ContractError;
pub use link::{ContractMetrics, Link};
