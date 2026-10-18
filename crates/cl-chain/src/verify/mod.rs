//! cl-chain's side of `ethswarm.verify.v1`: cl-verify runs every BLS and KZG check, cl-chain
//! only calls it ([`client`]).

pub mod client;
