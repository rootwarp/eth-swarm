//! Outbound req/resp over libp2p `request_response`.
//!
//! One [`request_response::Behaviour`] per protocol: `request_response` offers every protocol
//! of a behaviour on each outbound stream and multistream-select picks the first the peer
//! supports, so a behaviour holding all four would send a `Status` on whatever protocol came
//! first. One protocol per behaviour also makes `with_max_concurrent_streams(2)` the
//! per-protocol limit `MAX_CONCURRENT_REQUESTS` (`phase0/p2p-interface.md` L309).
//!
//! [`outbound`] runs one exchange on a swarm (Status v2).

pub mod codec;
pub mod outbound;

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
