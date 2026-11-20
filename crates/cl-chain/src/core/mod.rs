//! The chain core: the single writer of cl-chain's chain state ([`actor`]), its pre-states
//! ([`snapshot`]) and the blocks it refused (`seen`).

pub mod actor;
mod seen;
pub mod snapshot;

pub use actor::{
    queue, AnchorError, ChainCore, CoreQueue, CoreSender, Head, Outcome, Served, SubmitError,
    DEFAULT_VERIFY_TIMEOUT, MAX_FUTURE_SLOTS, MAX_REFUSED_ROOTS,
};
