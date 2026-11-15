//! Block import: the state transition of one block, with its signatures checked by cl-verify
//! ([`block`]). The chain core ([`crate::core`]) runs it and commits its result.

pub mod block;
