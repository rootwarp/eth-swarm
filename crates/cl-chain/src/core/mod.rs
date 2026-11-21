//! The chain core: the single writer of cl-chain's chain state ([`actor`]), its pre-states
//! ([`snapshot`]), its walks over empty slots ([`advance`]), the blocks it refused (`seen`) and
//! the hooks of its envelope import (`envelope`).

pub mod actor;
pub mod advance;
mod envelope;
mod seen;
pub mod snapshot;

pub use actor::{
    queue, AnchorError, ChainCore, CoreQueue, CoreSender, Head, Outcome, Served, SubmitError,
    DEFAULT_ENGINE_TIMEOUT, DEFAULT_VERIFY_TIMEOUT, MAX_FUTURE_SLOTS, MAX_REFUSED_ROOTS,
};
pub use advance::{
    MAX_ADVANCED_STATES, MAX_ADVANCE_BUDGET_PROPOSERS, MAX_ADVANCE_EPOCHS,
    MAX_ADVANCE_EPOCHS_PER_PROPOSER_PER_SLOT, MAX_ADVANCE_EPOCHS_PER_SLOT,
};
