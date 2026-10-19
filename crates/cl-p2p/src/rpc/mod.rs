//! Req/resp over libp2p `request_response`.
//!
//! One [`request_response::Behaviour`] per protocol (and, on the probe, per direction:
//! [`inbound::Duplex`]): `request_response` offers every protocol of a behaviour on each
//! outbound stream and multistream-select picks the first the peer supports, so a behaviour
//! holding all of them would send a `Status` on whatever protocol came first. One protocol per
//! behaviour also makes `with_max_concurrent_streams(2)` the per-protocol limit
//! `MAX_CONCURRENT_REQUESTS` (`phase0/p2p-interface.md` L309) on each connection.
//!
//! - [`answer_bucket`]: the address block (IPv4 /24, IPv6 /48) a peer's column answer places
//!   are counted against.
//! - [`chain_status`]: our Status from cl-chain's `ReqRespService/GetStatus`
//!   ([`chain_status::ChainStatus`]).
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

pub mod answer_bucket;
pub mod chain_status;
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
use consensus_types::caps::NetworkCaps;
use consensus_types::EthSpec;
use libp2p::request_response::{self, ProtocolSupport};
use network_config::digest::digest_schedule;
use network_config::ChainConfig;
use p2p_wire::rpc::codec::ContextTable;
use p2p_wire::rpc::protocols::Protocol;
use std::time::Duration;

/// `MAX_CONCURRENT_REQUESTS` (`phase0/p2p-interface.md` L309): open requests per protocol.
pub const MAX_CONCURRENT_REQUESTS: usize = 2;

/// `request_response`'s own deadline for one exchange: the same 10 s \[est\] as
/// [`codec::Deadlines::total`], as a backstop. It is the only deadline `request_response` has,
/// so the first-byte and per-chunk deadlines live in the codec.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The context table a swarm of `config`'s network reads and answers with: every fork digest of
/// its schedule from Fulu on (BPO digests included) to its fork, and the network's caps
/// ([`NetworkCaps::from_config`]), without which every column sidecar chunk is refused and
/// every column answer is `2: ServerError`. Every table built for serving comes from here.
#[must_use]
pub fn network_context_table(
    config: &ChainConfig,
    genesis_validators_root: &[u8; 32],
) -> ContextTable {
    let mut table = ContextTable::new().with_network_caps(NetworkCaps::from_config(config));
    for entry in digest_schedule(config, genesis_validators_root) {
        table.insert(entry.fork_digest, entry.fork);
    }
    table
}

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

#[cfg(test)]
mod context_table_tests {
    use super::*;
    use network_config::Network;

    #[test]
    fn the_serving_table_has_every_digest_and_the_networks_caps() {
        let config = ChainConfig::load(Network::Sepolia).unwrap();
        let gvr = Network::Sepolia.genesis().unwrap().genesis_validators_root;
        let table = network_context_table(&config, &gvr);
        assert_eq!(
            table.network_caps(),
            Some(&NetworkCaps::from_config(&config)),
            "a serving table without the network's caps refuses every column answer"
        );
        let schedule = digest_schedule(&config, &gvr);
        assert!(!schedule.is_empty());
        for entry in schedule {
            assert_eq!(table.fork(&entry.fork_digest), Some(entry.fork));
        }
    }
}
