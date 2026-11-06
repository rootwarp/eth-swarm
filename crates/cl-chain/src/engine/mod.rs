//! cl-chain's side of `ethswarm.engine.v1`: cl-chain is cl-engine's only caller, and it owns
//! the order of forkchoiceUpdated calls.
//!
//! - [`fcu`]: the `engine_forkchoiceUpdatedV4` arguments, computed from a fork choice view
//!   ([`fcu::ForkchoiceView`]), and the custody bitmap. Pure.
//! - [`client`]: [`client::FcuSender`], which sends those arguments to cl-engine in `seq` order,
//!   latest value wins.
//!
//! Nothing calls the sender on head changes yet: there is no block import core and no fork
//! choice store to call it.

pub mod client;
pub mod fcu;
