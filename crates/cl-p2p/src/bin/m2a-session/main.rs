//! `m2a-session`: the pinned reference node's Status v2, MetaData v3, Ping v1 and
//! BeaconBlocksByRange v2 probe (see `cl_p2p::m2a_session`).
//!
//! ```text
//! m2a-session [--config <path>] [--dial-only | --print-peer-id] [--connect-timeout-secs <n>]
//!             [--gate-file <path>]
//! ```
//!
//! The config (`cl_p2p::m2a_session::config`, default `/etc/ethswarm/m2a-session.toml`) pins the
//! peer, the reference API, the deadlines, the node key and `run_as`. The pre-flight runs before
//! anything else: it refuses root and any effective UID other than that of the `run_as` user.
//!
//! - default: the Status probe ([`probe`]). The pre-flight also requires a clean build
//!   ([`build_info`]) and a passing m2a fuzz gate for the decoders this binary was built from
//!   ([`gate`]; `--gate-file`, default the checkout's `fuzz/artifacts/m2a-gate.json`), and
//!   refuses before dialling without them. Then:
//!   dial, send our Status v2 at the pinned Sepolia fork digest, judge the peer's against the
//!   reference beacon API ([`reference_api`]); request the peer's MetaData v3 on the same
//!   connection and judge it against the node's `/eth/v1/node/identity` ([`metadata`]); Ping
//!   it with our `seq_number` 0 and check its answer against that MetaData ([`ping`]); fetch
//!   its last finalized slots with one BlocksByRange and compare every block root with the
//!   API's, then drop the blocks ([`blocks`]); hold the connection and send a second Status.
//!   One JSON line per step on stdout records it all, and a last `m2a-summary` line
//!   aggregates every check ([`summary`]).
//! - `--dial-only`: dial, check the pinned peer ID (Noise XX, then yamux), disconnect, exit.
//!   No req/resp traffic, so no response decoder runs and no fuzz gate is needed.
//! - `--print-peer-id`: print the node key's peer ID on stdout and exit, without dialling, so
//!   the operator can list it as a trusted peer on the reference node. Needs `node_key`.
//!
//! Exit 0 on success (every check of the summary passed), 1 if the dial, an exchange or a verdict
//! fails, 2 on bad arguments, a refused config or a failed pre-flight.
//!
//! Logs are svc-runtime's JSON lines on stderr, at INFO, through its bounded writer: a stderr
//! nobody reads drops lines instead of blocking the session, and every exit waits for the queue
//! at most [`LOG_FLUSH_DEADLINE`]. If that writer cannot start, it exits at once with
//! [`EXIT_NO_LOG_WRITER`](svc_runtime::telemetry::EXIT_NO_LOG_WRITER) (71), writing nothing.

mod app;
mod blocks;
mod build_info;
mod enr;
mod gate;
mod metadata;
#[cfg(test)]
mod mock_api;
mod ping;
mod probe;
mod reference_api;
mod summary;

/// The deployed binary: never a test build.
fn main() -> std::process::ExitCode {
    app::main(false)
}
