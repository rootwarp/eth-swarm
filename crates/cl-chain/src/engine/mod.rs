//! cl-chain's side of `ethswarm.engine.v1`: cl-chain is cl-engine's only caller, and it owns
//! the order of forkchoiceUpdated calls.
//!
//! - [`fcu`]: the `engine_forkchoiceUpdatedV4` arguments, computed from a fork choice view
//!   ([`fcu::ForkchoiceView`]), and the custody bitmap. Pure.
//! - [`client`]: [`client::FcuSender`], which sends those arguments to cl-engine in `seq` order,
//!   latest value wins; and [`client::NewPayloadClient`], which sends an envelope's
//!   `engine_newPayloadV5` params and gives the EL's verdict.
//! - [`verdict`]: the verdict of a `PayloadStatusV1` (fail closed: never `Valid` without a
//!   `VALID`), the envelope import gate, and the execution status of each payload. Pure.
//!
//! Nothing calls the sender on head changes, or the newPayload client on import, yet: there
//! is no block import core and no fork choice store to call them.

pub mod client;
pub mod fcu;
pub mod verdict;
