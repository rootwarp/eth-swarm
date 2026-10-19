//! Req/resp over libp2p `request_response`.
//!
//! One [`request_response::Behaviour`] per protocol (and, on the probe, per direction:
//! [`inbound::Duplex`]): `request_response` offers every protocol of a behaviour on each
//! outbound stream and multistream-select picks the first the peer supports, so a behaviour
//! holding all of them would send a `Status` on whatever protocol came first. One protocol per
//! behaviour also makes `with_max_concurrent_streams(2)` the per-protocol limit
//! `MAX_CONCURRENT_REQUESTS` (`phase0/p2p-interface.md` L309) on each connection.
//!
//! - [`codec`]: both halves of the `ssz_snappy` codec, with the deadlines inside it.
//! - [`columns`]: where column answers come from ([`columns::ColumnSource`]): cl-chain's
//!   `ReqRespService` ([`columns::ChainColumns`]).
//! - [`outbound`]: one exchange on a swarm, for the m2a session.
//! - [`inbound`]: the probe swarm's behaviour, answering and initiating Status, MetaData, Ping
//!   and Goodbye, and serving the custody columns ([`inbound::Control`]).
//! - [`limits`]: the per-peer rate limit, the outbound semaphore and the bounded IGNORE queues.
//! - [`metrics`]: `rpc_timeouts_total`, the Goodbye counters, `p2p_status_valid_peers` and the
//!   limit counters.
//! - [`unsupported`]: the MUST-support protocols the probe leaves unregistered (written
//!   deviations), and the count of peers' proposals of them.

pub mod codec;
pub mod columns;
pub mod inbound;
pub mod limits;
pub mod metrics;
pub mod outbound;
#[cfg(test)]
mod tests;
pub mod unsupported;

use codec::RpcCodec;
use consensus_types::EthSpec;
use libp2p::request_response::{self, ProtocolSupport};
use p2p_wire::rpc::protocols::Protocol;
use std::time::Duration;

/// `MAX_CONCURRENT_REQUESTS` (`phase0/p2p-interface.md` L309): open requests per protocol.
pub const MAX_CONCURRENT_REQUESTS: usize = 2;

/// `request_response`'s own deadline for one exchange: the same 10 s \[est\] as
/// [`codec::Deadlines::total`], as a backstop. It is the only deadline `request_response` has,
/// so the first-byte and per-chunk deadlines live in the codec.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// An outbound-only behaviour for `protocol`.
pub fn outbound_behaviour<E: EthSpec>(
    protocol: Protocol,
    codec: RpcCodec<E>,
) -> request_response::Behaviour<RpcCodec<E>> {
    request_response::Behaviour::with_codec(
        codec,
        [(protocol, ProtocolSupport::Outbound)],
        request_response::Config::default()
            .with_request_timeout(REQUEST_TIMEOUT)
            .with_max_concurrent_streams(MAX_CONCURRENT_REQUESTS),
    )
}
