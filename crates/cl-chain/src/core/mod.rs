//! The chain core: the single writer of cl-chain's chain state ([`actor`]), and its
//! pre-states ([`snapshot`]).

pub mod actor;
pub mod snapshot;

pub use actor::{
    queue, AnchorError, ChainCore, CoreQueue, CoreSender, Head, Outcome, Served, SubmitError,
    DEFAULT_VERIFY_TIMEOUT, MAX_FUTURE_SLOTS,
};
