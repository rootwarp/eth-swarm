//! Req/resp over libp2p `request_response`.
//!
//! One [`request_response::Behaviour`] per protocol: `request_response` offers every protocol
//! of a behaviour on each outbound stream and multistream-select picks the first the peer
//! supports, so a behaviour holding all of them would send a `Status` on whatever protocol came
//! first. One protocol per behaviour also makes `with_max_concurrent_streams(2)` the
//! per-protocol limit `MAX_CONCURRENT_REQUESTS` (`phase0/p2p-interface.md` L309).
//!
//! - [`codec`]: both halves of the `ssz_snappy` codec, with the deadlines inside it.
//! - [`outbound`]: one exchange on a swarm, for the m2a session.
//! - [`inbound`]: the probe swarm's behaviour, answering and initiating Status, MetaData, Ping
//!   and Goodbye ([`inbound::Control`]).
//! - [`metrics`]: `rpc_timeouts_total`, the Goodbye counters and `p2p_status_valid_peers`.

pub mod codec;
pub mod inbound;
pub mod metrics;
pub mod outbound;
#[cfg(test)]
mod tests;

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
