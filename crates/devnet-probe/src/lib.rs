//! The devnet probe: our probe's checks against the reference CLs of a local Kurtosis devnet,
//! one check per acceptance criterion, each a [`report::Check`] of PASS/FAIL lines (DIAGNOSTIC
//! for a check run outside the acceptance rules, such as a short hold).
//!
//! - [`discover`]: our discv5 ([`cl_discv5::service::Discovery`], local mode: nothing is sent
//!   to an address that is not local), seeded with the bootnode records, finds every
//!   reference CL's record.
//! - [`connect`]: the probe swarm dials each reference CL: TCP, Noise XX (the peer ID) and the
//!   muxer, which must be yamux, named per peer.
//! - [`status`]: Status v2 both ways (ours answered, theirs answered and our answer sent), then
//!   each connection held with our Ping cadence and no Goodbye; a Goodbye is reported with
//!   its reason.
//! - [`fetch`]: one finalized epoch by BlocksByRange v2 ([`cl_p2p::rpc::outbound::fetch_epoch`]
//!   over the [`cl_p2p::rpc::outbound::RangeRequester`]), every slot's root compared with
//!   `/eth/v1/beacon/blocks/{slot}/root` (404: an empty slot); nothing may be unconfirmed.
//!
//! Shared parts: [`devnet`] (the devnet's config, genesis and preset, and the rule that every
//! address the probe contacts is local), [`api`] (the reference beacon API, through
//! testkit's collector client),
//! [`ours`] (our Status from cl-chain's probe-mode [`cl_chain::probe::StatusProvider`]),
//! [`swarm`] (the probe swarm from cl-p2p's `build_swarm` over the devnet's preset) and
//! [`report`]. Everything runs in process against the given addresses; nothing here starts or
//! talks to Kurtosis or Docker. `testing/kurtosis/README.md` ("Probe checks") has the operator
//! commands.
//!
//! The crate links cl-p2p, cl-discv5 and cl-chain together on purpose: cl-p2p must link neither
//! discv5 nor cl-chain (`scripts/check-m2a-deps.sh`), and testkit must not link cl-chain
//! (cl-chain's tests use testkit; `scripts/check-dep-cycles.sh`), so the checks that need all
//! three live in a crate of their own that nothing depends on.

pub mod api;
pub mod connect;
pub mod devnet;
pub mod discover;
pub mod fetch;
#[cfg(any(test, feature = "test-support"))]
pub mod fixtures;
pub mod ours;
pub mod report;
pub mod status;
pub mod swarm;
