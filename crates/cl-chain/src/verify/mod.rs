//! cl-chain's side of `ethswarm.verify.v1`: cl-verify runs every BLS and KZG check, cl-chain
//! only calls it ([`client`]) and feeds it the keys of its finalized builder registry
//! ([`pubkey_feed`]).

pub mod client;
pub mod pubkey_feed;
