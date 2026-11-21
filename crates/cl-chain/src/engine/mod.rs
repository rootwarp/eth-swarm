//! cl-chain's side of `ethswarm.engine.v1`: cl-chain is cl-engine's only caller, and it owns
//! the order of forkchoiceUpdated calls.
//!
//! - [`fcu`]: the `engine_forkchoiceUpdatedV4` arguments, computed from a fork choice view
//!   ([`fcu::ForkchoiceView`]), and the custody bitmap. Pure.
//! - [`client`]: [`client::FcuSender`], which sends those arguments to cl-engine in `seq` order,
//!   latest value wins; and [`client::NewPayloadClient`], which sends an envelope's
//!   `engine_newPayloadV5` params and gives the EL's verdict, as a [`client::NewPayload`].
//! - [`verdict`]: the verdict of a `PayloadStatusV1` (fail closed: never `Valid` without a
//!   `VALID` for the submitted payload), the EL verdict import gate, and the execution status
//!   of each payload, with the optimistic-sync rules, pruning at finality and a bound on the
//!   `Invalid` payloads it keeps. Pure.
//!
//! The chain core ([`crate::core`]) calls newPayload on envelope import and keeps the execution
//! statuses. Nothing calls the sender on head changes yet: there is no fork choice store.

pub mod client;
pub mod fcu;
pub mod verdict;
