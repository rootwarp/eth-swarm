//! What the probe records about its peers.
//!
//! - [`manager`]: the Goodbye ledger ([`manager::GoodbyeLedger`]), reason-3 Goodbyes from
//!   Status-valid peers per hour against a threshold.
//! - [`context`]: what is logged next to each reason-3 Goodbye.

pub mod context;
pub mod manager;
