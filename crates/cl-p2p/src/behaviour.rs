//! The probe swarm's [`NetworkBehaviour`]: connection limits (`connection_limits` and
//! [`PeerCaps`]), identify, the req/resp control protocols ([`crate::rpc::inbound::Control`]),
//! and gossipsub ([`crate::gossip::IgnoreAll`], off unless [`Behaviour::with_gossip`] turns it
//! on).
//!
//! Field order is the order the swarm consults the behaviours, so [`SpecBehaviour::limits`]
//! comes first: a connection it denies is never handed to the others.
//!
//! [`SpecBehaviour`] is generic over the preset its req/resp behaviour decodes blocks with;
//! [`Behaviour`] is the one over [`ProbeSpec`], the networks the probe joins. A minimal-preset
//! devnet runs [`SpecBehaviour`] over `Minimal`.

use crate::gossip::IgnoreAll;
use crate::peer_caps::{PeerCaps, PeerCapsConfig};
use crate::rpc::inbound::{Control, ControlEvent};
use crate::rpc::outbound::ControlRpc;
use consensus_types::EthSpec;
use libp2p::identity::PublicKey;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{connection_limits, identify, PeerId};

/// The identify protocol version every consensus-layer client announces.
pub const IDENTIFY_PROTOCOL_VERSION: &str = "eth2/1.0.0";

/// Established connections one peer may hold: one, whichever side dialed.
pub const MAX_ESTABLISHED_PER_PEER: u32 = 1;

/// The longest peer-supplied identify string logged, in chars; the rest is cut.
pub const MAX_LOGGED_CHARS: usize = 128;

/// Caps on the connections the swarm holds, enforced by `connection_limits` and [`PeerCaps`].
///
/// The pinned `connection_limits` caps pending inbound connections per source (an IPv4
/// address, an IPv6 /58), not in total; [`PeerCaps`] adds the total and the per-IP cap on
/// established inbound connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionCaps {
    /// Inbound connections from one source still in the handshake: 8 by default.
    pub max_pending_incoming_per_source: u32,
    /// Established inbound connections: 128 by default.
    pub max_established_incoming: u32,
    /// Established connections both ways: 160 by default, so at least 32 are ours to dial
    /// whatever the inbound side holds.
    pub max_established: u32,
    /// Inbound connections still in the handshake, from every source together: 32 by default.
    pub max_pending_incoming: u32,
    /// Established inbound connections from one IP (an IPv6 /58): 8 by default.
    pub max_established_incoming_per_ip: u32,
}

impl Default for ConnectionCaps {
    fn default() -> Self {
        Self {
            max_pending_incoming_per_source: 8,
            max_established_incoming: 128,
            max_established: 160,
            max_pending_incoming: PeerCapsConfig::default().max_pending_incoming,
            max_established_incoming_per_ip: PeerCapsConfig::default()
                .max_established_incoming_per_ip,
        }
    }
}

/// The preset the probe decodes with: every network it joins (Sepolia, Hoodi) is mainnet.
pub type ProbeSpec = consensus_types::Mainnet;

/// The req/resp slot of [`Behaviour`]: Status, MetaData, Ping, Goodbye, BlocksByRange
/// (answered `3: ResourceUnavailable`) and the custody columns by range and by root.
pub type ReqRespSlot = Control<ProbeSpec>;

/// The gossipsub slot: ignore-all gossipsub, or nothing.
pub type GossipsubSlot = Toggle<IgnoreAll>;

/// [`SpecBehaviour`] over [`ProbeSpec`].
pub type Behaviour = SpecBehaviour<ProbeSpec>;

/// The events of [`Behaviour`].
pub type BehaviourEvent = SpecBehaviourEvent<ProbeSpec>;

/// Connection limits, identify, req/resp and gossipsub, consulted in that order; req/resp
/// decodes blocks under the preset `E`.
#[derive(NetworkBehaviour)]
pub struct SpecBehaviour<E: EthSpec> {
    /// At most [`MAX_ESTABLISHED_PER_PEER`] established connections per peer.
    pub limits: connection_limits::Behaviour,
    /// The pending-total and per-IP inbound caps.
    pub peer_caps: PeerCaps,
    /// Tells each peer who we are and what address we see it on, and tells us the same.
    pub identify: identify::Behaviour,
    pub req_resp: Control<E>,
    pub gossipsub: GossipsubSlot,
}

impl<E: EthSpec> SpecBehaviour<E> {
    /// The behaviour for the node whose public key is `local`, announcing `agent_version`,
    /// under the default [`ConnectionCaps`], with `req_resp` answering the req/resp protocols.
    #[must_use]
    pub fn new(local: PublicKey, agent_version: String, req_resp: Control<E>) -> Self {
        Self::with_caps(local, agent_version, ConnectionCaps::default(), req_resp)
    }

    /// [`Behaviour::new`] under `caps`.
    #[must_use]
    pub fn with_caps(
        local: PublicKey,
        agent_version: String,
        caps: ConnectionCaps,
        req_resp: Control<E>,
    ) -> Self {
        let limits = connection_limits::ConnectionLimits::default()
            .with_max_established_per_peer(Some(MAX_ESTABLISHED_PER_PEER))
            .with_max_pending_incoming_per_source(Some(caps.max_pending_incoming_per_source))
            .with_max_established_incoming(Some(caps.max_established_incoming))
            .with_max_established(Some(caps.max_established));
        // No address cache: nothing dials an address a peer advertised.
        let identify = identify::Config::new(IDENTIFY_PROTOCOL_VERSION.to_owned(), local)
            .with_agent_version(agent_version)
            .with_cache_size(0);
        Self {
            limits: connection_limits::Behaviour::new(limits),
            peer_caps: PeerCaps::new(PeerCapsConfig {
                max_pending_incoming: caps.max_pending_incoming,
                max_established_incoming_per_ip: caps.max_established_incoming_per_ip,
            }),
            identify: identify::Behaviour::new(identify),
            req_resp,
            gossipsub: Toggle::from(None),
        }
    }

    /// Exempts `peer` (the reference node) from the connection caps of both limit slots.
    pub fn bypass(&mut self, peer: PeerId) {
        self.limits.bypass_peer_id(&peer);
        self.peer_caps.bypass(peer);
    }

    /// The same behaviour with `gossip` in the gossipsub slot.
    #[must_use]
    pub fn with_gossip(mut self, gossip: IgnoreAll) -> Self {
        self.gossipsub = Toggle::from(Some(gossip));
        self
    }
}

impl<E: EthSpec> ControlRpc<E> for SpecBehaviour<E> {
    fn control(&self) -> &Control<E> {
        &self.req_resp
    }

    fn control_mut(&mut self) -> &mut Control<E> {
        &mut self.req_resp
    }

    fn control_event(event: SpecBehaviourEvent<E>) -> Option<ControlEvent> {
        match event {
            SpecBehaviourEvent::ReqResp(event) => Some(event),
            _ => None,
        }
    }
}

/// Logs what identify learned: above all the address the peer sees us on, so a host the peer
/// reaches only through a NAT shows up in the log. The peer's strings are logged escaped
/// (`Debug`) and cut at [`MAX_LOGGED_CHARS`], so they cannot forge a log line.
pub fn log_identify(event: &identify::Event) {
    match event {
        identify::Event::Received { peer_id, info, .. } => tracing::info!(
            peer = %peer_id,
            // Peer-supplied too: a `/dns` component may hold any UTF-8.
            observed_addr = ?capped(&info.observed_addr.to_string()),
            agent = ?capped(&info.agent_version),
            protocol_version = ?capped(&info.protocol_version),
            "identify: the peer sees us at observed_addr"
        ),
        identify::Event::Error { peer_id, error, .. } => {
            tracing::debug!(peer = %peer_id, %error, "identify failed");
        }
        identify::Event::Sent { .. } | identify::Event::Pushed { .. } => {}
    }
}

/// `text` cut to its first [`MAX_LOGGED_CHARS`] chars.
pub(crate) fn capped(text: &str) -> &str {
    text.char_indices()
        .nth(MAX_LOGGED_CHARS)
        .map_or(text, |(end, _)| &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_builds_an_idle_behaviour() {
        use libp2p::swarm::NetworkBehaviour as _;
        let local = libp2p::identity::Keypair::generate_secp256k1().public();
        let (req_resp, _) = crate::testkit::control(
            &mut prometheus_client::registry::Registry::default(),
            crate::testkit::control_config(None),
        );
        let mut behaviour = Behaviour::new(local, "ethswarm/test".to_owned(), req_resp);
        // Identify starts with nothing to report: no connection, no cached address to dial.
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(behaviour.poll(&mut cx).is_pending());
    }

    #[test]
    fn logged_strings_are_capped() {
        assert_eq!(capped("lighthouse/v8"), "lighthouse/v8");
        let long = "é".repeat(MAX_LOGGED_CHARS + 5);
        assert_eq!(capped(&long).chars().count(), MAX_LOGGED_CHARS);
        assert!(long.starts_with(capped(&long)));
        let exact = "a".repeat(MAX_LOGGED_CHARS);
        assert_eq!(capped(&exact), exact);
    }
}
