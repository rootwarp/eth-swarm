//! Connection caps the pinned `connection_limits` does not have: a total cap on pending inbound
//! connections and a cap on established inbound connections per IP.
//!
//! `connection_limits` (the [`crate::behaviour::Behaviour::limits`] slot) caps pending inbound
//! connections per source address only, and established ones in total, per direction and per
//! peer. [`PeerCaps`] sits next to it in the probe's behaviour and adds:
//!
//! - **Pending inbound, in total** ([`PeerCapsConfig::max_pending_incoming`], 32 by default
//!   \[est\]): connections still in the TCP, Noise and muxer handshake, from every address
//!   together. A place is taken in `handle_pending_inbound_connection` and given back when the
//!   connection is established (whether or not a behaviour then refuses it) or fails, the
//!   handshake timeout included: the swarm reports every failure of a pending inbound
//!   connection as a `ListenFailure`.
//! - **Established inbound, per IP** ([`PeerCapsConfig::max_established_incoming_per_ip`], 8
//!   by default \[est\]), checked in `handle_established_inbound_connection`. An IPv4 address
//!   counts on its own and an IPv6 address by its /58, the buckets `connection_limits` uses for
//!   its pending cap, so rotating through one allocation buys nothing. A remote address without
//!   an IP (a relay, `/memory`) has no per-IP count. Our own dials are never counted.
//!
//! A peer on the bypass list ([`PeerCaps::bypass`], the reference node) is neither checked nor
//! counted per IP, as `connection_limits::Behaviour::bypass_peer_id` exempts it from that
//! behaviour's caps. Its pending connection still counts: the peer ID is not known before the
//! handshake ends.
//!
//! A denial is a [`CapExceeded`] inside the swarm's `ConnectionDenied`.

use libp2p::core::transport::PortUse;
use libp2p::core::{ConnectedPoint, Endpoint};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fmt;
use std::net::Ipv4Addr;
use std::task::{Context, Poll};

/// The caps [`PeerCaps`] enforces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCapsConfig {
    /// Inbound connections still in the handshake, from every address together: 32 by
    /// default \[est\], four times the per-source cap.
    pub max_pending_incoming: u32,
    /// Established inbound connections from one IP (an IPv6 /58): 8 by default \[est\], so
    /// filling the 128 inbound connections takes at least 16 addresses.
    pub max_established_incoming_per_ip: u32,
}

impl Default for PeerCapsConfig {
    fn default() -> Self {
        Self {
            max_pending_incoming: 32,
            max_established_incoming_per_ip: 8,
        }
    }
}

/// Which cap refused a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapKind {
    /// [`PeerCapsConfig::max_pending_incoming`].
    PendingIncoming,
    /// [`PeerCapsConfig::max_established_incoming_per_ip`].
    EstablishedIncomingPerIp,
}

impl fmt::Display for CapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CapKind::PendingIncoming => "pending incoming connections",
            CapKind::EstablishedIncomingPerIp => "established incoming connections per IP",
        })
    }
}

/// A connection [`PeerCaps`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("connection limit exceeded: at most {limit} {kind} are allowed")]
pub struct CapExceeded {
    limit: u32,
    kind: CapKind,
}

impl CapExceeded {
    /// The cap.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Which cap.
    #[must_use]
    pub fn kind(&self) -> CapKind {
        self.kind
    }
}

/// The per-IP bucket of a remote address: an IPv4 address, or the /58 of an IPv6 one.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum IpBucket {
    V4(Ipv4Addr),
    V6(u64),
}

impl IpBucket {
    /// The bucket of `remote`, `None` if it starts with no IP.
    fn of(remote: &Multiaddr) -> Option<Self> {
        match remote.iter().next()? {
            Protocol::Ip4(ip) => Some(Self::V4(ip)),
            Protocol::Ip6(ip) => {
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&ip.octets()[..8]);
                Some(Self::V6(u64::from_be_bytes(prefix) & !0x3f))
            }
            _ => None,
        }
    }
}

/// The pending-total and per-IP caps (see the module docs).
#[derive(Debug, Default)]
pub struct PeerCaps {
    config: PeerCapsConfig,
    bypass: HashSet<PeerId>,
    pending: HashSet<ConnectionId>,
    per_ip: HashMap<IpBucket, HashSet<ConnectionId>>,
    bucket_of: HashMap<ConnectionId, IpBucket>,
}

impl PeerCaps {
    /// The caps of `config`, nothing counted and no peer exempt.
    #[must_use]
    pub fn new(config: PeerCapsConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Exempts `peer` from the per-IP cap.
    pub fn bypass(&mut self, peer: PeerId) {
        self.bypass.insert(peer);
    }

    /// Whether `peer` is exempt.
    #[must_use]
    pub fn is_bypassed(&self, peer: &PeerId) -> bool {
        self.bypass.contains(peer)
    }

    /// Pending inbound connections counted now.
    #[must_use]
    pub fn pending_incoming(&self) -> usize {
        self.pending.len()
    }

    /// Established inbound connections counted against the IP of `remote`.
    #[must_use]
    pub fn established_from(&self, remote: &Multiaddr) -> usize {
        IpBucket::of(remote)
            .and_then(|bucket| self.per_ip.get(&bucket))
            .map_or(0, HashSet::len)
    }

    fn check(limit: u32, current: usize, kind: CapKind) -> Result<(), ConnectionDenied> {
        if current >= limit as usize {
            return Err(ConnectionDenied::new(CapExceeded { limit, kind }));
        }
        Ok(())
    }

    fn forget(&mut self, connection: ConnectionId) {
        if let Some(bucket) = self.bucket_of.remove(&connection) {
            if let Some(set) = self.per_ip.get_mut(&bucket) {
                set.remove(&connection);
                if set.is_empty() {
                    self.per_ip.remove(&bucket);
                }
            }
        }
    }
}

impl NetworkBehaviour for PeerCaps {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        Self::check(
            self.config.max_pending_incoming,
            self.pending.len(),
            CapKind::PendingIncoming,
        )?;
        self.pending.insert(connection_id);
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.pending.remove(&connection_id);
        if self.is_bypassed(&peer) {
            return Ok(dummy::ConnectionHandler);
        }
        Self::check(
            self.config.max_established_incoming_per_ip,
            self.established_from(remote_addr),
            CapKind::EstablishedIncomingPerIp,
        )?;
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        Ok(Vec::new())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(c) => {
                let ConnectedPoint::Listener { send_back_addr, .. } = c.endpoint else {
                    return;
                };
                if self.is_bypassed(&c.peer_id) {
                    return;
                }
                if let Some(bucket) = IpBucket::of(send_back_addr) {
                    self.per_ip
                        .entry(bucket)
                        .or_default()
                        .insert(c.connection_id);
                    self.bucket_of.insert(c.connection_id, bucket);
                }
            }
            FromSwarm::ConnectionClosed(c) => self.forget(c.connection_id),
            FromSwarm::ListenFailure(f) => {
                self.pending.remove(&f.connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::ConnectedPoint;
    use libp2p::swarm::behaviour::{ConnectionClosed, ConnectionEstablished, ListenFailure};
    use libp2p::swarm::ListenError;

    fn addr(ip: &str, port: u16) -> Multiaddr {
        format!(
            "/{}/{ip}/tcp/{port}",
            if ip.contains(':') { "ip6" } else { "ip4" }
        )
        .parse()
        .unwrap()
    }

    fn local() -> Multiaddr {
        addr("127.0.0.1", 9000)
    }

    fn caps(pending: u32, per_ip: u32) -> PeerCaps {
        PeerCaps::new(PeerCapsConfig {
            max_pending_incoming: pending,
            max_established_incoming_per_ip: per_ip,
        })
    }

    /// The limit and kind of a denial by [`PeerCaps`].
    fn exceeded(denied: ConnectionDenied) -> CapExceeded {
        denied
            .downcast::<CapExceeded>()
            .expect("denied by PeerCaps")
    }

    #[derive(Debug)]
    struct Conn {
        id: ConnectionId,
        peer: PeerId,
        endpoint: ConnectedPoint,
    }

    /// Takes an inbound connection from `remote` through both checks and establishes it.
    fn inbound(
        caps: &mut PeerCaps,
        n: usize,
        peer: PeerId,
        remote: Multiaddr,
    ) -> Result<Conn, CapExceeded> {
        let id = ConnectionId::new_unchecked(n);
        caps.handle_pending_inbound_connection(id, &local(), &remote)
            .map_err(exceeded)?;
        caps.handle_established_inbound_connection(id, peer, &local(), &remote)
            .map_err(exceeded)?;
        let endpoint = ConnectedPoint::Listener {
            local_addr: local(),
            send_back_addr: remote,
        };
        caps.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
        Ok(Conn { id, peer, endpoint })
    }

    fn close(caps: &mut PeerCaps, conn: &Conn) {
        caps.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: conn.peer,
            connection_id: conn.id,
            endpoint: &conn.endpoint,
            cause: None,
            remaining_established: 0,
        }));
    }

    #[test]
    fn inbound_per_ip_cap_counts_each_address_apart() {
        let mut caps = caps(64, 2);
        let one = |port| addr("127.0.0.1", port);
        let first = inbound(&mut caps, 1, PeerId::random(), one(1001)).unwrap();
        inbound(&mut caps, 2, PeerId::random(), one(1002)).unwrap();
        // A third from 127.0.0.1, whatever its port and peer ID.
        let err = inbound(&mut caps, 3, PeerId::random(), one(1003)).unwrap_err();
        assert_eq!(err.limit(), 2);
        assert_eq!(err.kind(), CapKind::EstablishedIncomingPerIp);
        assert!(err.to_string().contains("per IP"), "{err}");
        // Other loopback addresses have their own count.
        for (n, ip) in [(4, "127.0.0.2"), (5, "127.0.0.3"), (6, "127.0.0.2")] {
            inbound(&mut caps, n, PeerId::random(), addr(ip, 1000)).unwrap();
        }
        assert!(inbound(&mut caps, 7, PeerId::random(), addr("127.0.0.2", 1001)).is_err());
        assert_eq!(caps.established_from(&one(0)), 2);
        // A closed connection frees its place.
        close(&mut caps, &first);
        assert_eq!(caps.established_from(&one(0)), 1);
        inbound(&mut caps, 8, PeerId::random(), one(1004)).unwrap();
    }

    #[test]
    fn ipv6_counts_per_slash_58() {
        let mut caps = caps(64, 1);
        inbound(&mut caps, 1, PeerId::random(), addr("2001:db8:0:1::1", 1)).unwrap();
        // The same /58 (2001:db8:0:0 to 2001:db8:0:3f): refused.
        assert!(inbound(&mut caps, 2, PeerId::random(), addr("2001:db8:0:3f::9", 1)).is_err());
        // The next /58: its own count.
        inbound(&mut caps, 3, PeerId::random(), addr("2001:db8:0:40::1", 1)).unwrap();
    }

    #[test]
    fn the_reference_node_is_exempt() {
        let mut caps = caps(64, 1);
        let reference = PeerId::random();
        caps.bypass(reference);
        assert!(caps.is_bypassed(&reference));
        let ip = addr("127.0.0.1", 1);
        inbound(&mut caps, 1, PeerId::random(), ip.clone()).unwrap();
        // Over the cap of its address, but exempt, and not counted.
        let conn = inbound(&mut caps, 2, reference, ip.clone()).unwrap();
        assert_eq!(caps.established_from(&ip), 1);
        close(&mut caps, &conn);
        assert_eq!(caps.established_from(&ip), 1);
        assert!(inbound(&mut caps, 3, PeerId::random(), ip).is_err());
    }

    #[test]
    fn outbound_and_non_ip_connections_are_not_counted() {
        let mut caps = caps(64, 1);
        let ip = addr("127.0.0.1", 1);
        let peer = PeerId::random();
        let id = ConnectionId::new_unchecked(1);
        assert!(caps
            .handle_pending_outbound_connection(id, Some(peer), &[], Endpoint::Dialer)
            .unwrap()
            .is_empty());
        assert!(caps
            .handle_established_outbound_connection(id, peer, &ip, Endpoint::Dialer, PortUse::New)
            .is_ok());
        let endpoint = ConnectedPoint::Dialer {
            address: ip.clone(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        };
        caps.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
        assert_eq!(caps.established_from(&ip), 0);
        inbound(&mut caps, 2, PeerId::random(), ip.clone()).unwrap();
        // A remote address with no IP has no per-IP count.
        let memory: Multiaddr = "/memory/7".parse().unwrap();
        for n in 3..6 {
            inbound(&mut caps, n, PeerId::random(), memory.clone()).unwrap();
        }
        assert_eq!(caps.established_from(&memory), 0);
    }

    #[test]
    fn pending_inbound_total_cap_releases_on_establish_failure_and_timeout() {
        let mut caps = caps(2, 64);
        let pend = |caps: &mut PeerCaps, n: usize, ip: &str| {
            caps.handle_pending_inbound_connection(
                ConnectionId::new_unchecked(n),
                &local(),
                &addr(ip, 1),
            )
        };
        // From any address: the cap is the total.
        pend(&mut caps, 1, "127.0.0.1").unwrap();
        pend(&mut caps, 2, "127.0.0.2").unwrap();
        let err = exceeded(pend(&mut caps, 3, "127.0.0.3").unwrap_err());
        assert_eq!((err.kind(), err.limit()), (CapKind::PendingIncoming, 2));
        assert!(err.to_string().contains("pending incoming"), "{err}");
        assert_eq!(caps.pending_incoming(), 2);

        // Established: released, whether or not a later check refuses it.
        caps.handle_established_inbound_connection(
            ConnectionId::new_unchecked(1),
            PeerId::random(),
            &local(),
            &addr("127.0.0.1", 1),
        )
        .unwrap();
        assert_eq!(caps.pending_incoming(), 1);
        pend(&mut caps, 4, "127.0.0.4").unwrap();

        // A failed or timed-out handshake (the swarm reports both as a listen failure): released.
        for n in [2, 4] {
            caps.on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
                local_addr: &local(),
                send_back_addr: &addr("127.0.0.9", 1),
                error: &ListenError::Aborted,
                connection_id: ConnectionId::new_unchecked(n),
                peer_id: None,
            }));
        }
        assert_eq!(caps.pending_incoming(), 0);
        // A failure of a connection we never counted changes nothing.
        caps.on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
            local_addr: &local(),
            send_back_addr: &addr("127.0.0.9", 1),
            error: &ListenError::Aborted,
            connection_id: ConnectionId::new_unchecked(3),
            peer_id: None,
        }));
        assert_eq!(caps.pending_incoming(), 0);
        pend(&mut caps, 5, "127.0.0.5").unwrap();
        pend(&mut caps, 6, "127.0.0.6").unwrap();
    }

    #[test]
    fn a_refusal_by_the_per_ip_cap_still_releases_the_pending_slot() {
        let mut caps = caps(1, 1);
        let ip = addr("127.0.0.1", 1);
        inbound(&mut caps, 1, PeerId::random(), ip.clone()).unwrap();
        assert!(inbound(&mut caps, 2, PeerId::random(), ip).is_err());
        assert_eq!(caps.pending_incoming(), 0);
        inbound(&mut caps, 3, PeerId::random(), addr("127.0.0.2", 1)).unwrap();
    }

    #[test]
    fn idle_and_default() {
        let mut caps = PeerCaps::new(PeerCapsConfig::default());
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(caps.poll(&mut cx).is_pending());
        let defaults = PeerCapsConfig::default();
        assert_eq!(defaults.max_pending_incoming, 32);
        assert_eq!(defaults.max_established_incoming_per_ip, 8);
    }

    // On the probe swarm: `build_swarm` against peers on 127.0.0.1.

    use crate::transport::{build_swarm, MuxerBudget, SwarmConfig, TransportMetrics};
    use futures::channel::mpsc::{self, UnboundedReceiver};
    use futures::StreamExt;
    use libp2p::identity::Keypair;
    use libp2p::swarm::SwarmEvent;
    use libp2p::{noise, tcp, yamux, Swarm, SwarmBuilder};
    use prometheus_client::registry::Registry;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(20);

    /// What the probe reports.
    #[derive(Debug)]
    enum Probe {
        Established(PeerId),
        /// An inbound connection refused, with the [`CapExceeded`] if `PeerCaps` refused it.
        Refused(Option<CapExceeded>),
        /// An inbound connection that failed otherwise (a handshake timeout).
        Failed,
    }

    fn probe_config() -> SwarmConfig {
        let mut registry = Registry::default();
        let transport = TransportMetrics::register(&mut registry);
        let mut cfg = SwarmConfig::new(MuxerBudget::with_defaults(&transport));
        cfg.listen_addrs = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
        cfg.idle_connection_timeout = WAIT;
        cfg
    }

    /// Runs the probe swarm of `cfg` on its own task: its address and what it reports.
    async fn start_probe(cfg: &SwarmConfig) -> (Multiaddr, UnboundedReceiver<Probe>) {
        let (req_resp, _) = crate::testkit::control(
            &mut Registry::default(),
            crate::testkit::control_config(Some(p2p_wire::testkit::status())),
        );
        let mut swarm = build_swarm(Keypair::generate_secp256k1(), cfg, req_resp).unwrap();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address;
            }
        };
        let (tx, rx) = mpsc::unbounded();
        tokio::spawn(async move {
            loop {
                let seen = match swarm.select_next_some().await {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        Probe::Established(peer_id)
                    }
                    SwarmEvent::IncomingConnectionError {
                        error: libp2p::swarm::ListenError::Denied { cause },
                        ..
                    } => Probe::Refused(cause.downcast_ref::<CapExceeded>().copied()),
                    SwarmEvent::IncomingConnectionError { .. } => Probe::Failed,
                    _ => continue,
                };
                if tx.unbounded_send(seen).is_err() {
                    return;
                }
            }
        });
        (addr, rx)
    }

    async fn next(rx: &mut UnboundedReceiver<Probe>, what: &str) -> Probe {
        tokio::time::timeout(WAIT, rx.next())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .expect("the probe runs")
    }

    /// A bare peer with `key` dialing `addr` over TCP, Noise and yamux, on its own task.
    fn dial_from(key: Keypair, addr: Multiaddr) {
        let mut swarm: Swarm<libp2p::swarm::dummy::Behaviour> =
            SwarmBuilder::with_existing_identity(key)
                .with_tokio()
                .with_tcp(
                    tcp::Config::default(),
                    noise::Config::new,
                    yamux::Config::default,
                )
                .unwrap()
                .with_behaviour(|_| libp2p::swarm::dummy::Behaviour)
                .unwrap()
                .with_swarm_config(|c| c.with_idle_connection_timeout(WAIT))
                .build();
        swarm.dial(addr).unwrap();
        tokio::spawn(async move {
            loop {
                swarm.select_next_some().await;
            }
        });
    }

    #[tokio::test]
    async fn the_probe_caps_inbound_per_ip_and_exempts_the_reference_node() {
        let reference = Keypair::generate_secp256k1();
        let mut cfg = probe_config();
        cfg.caps.max_established_incoming_per_ip = 1;
        cfg.bypass = vec![reference.public().to_peer_id()];
        let (addr, mut probe) = start_probe(&cfg).await;
        let first = Keypair::generate_secp256k1();
        let first_id = first.public().to_peer_id();
        dial_from(first, addr.clone());
        assert!(
            matches!(next(&mut probe, "the first").await, Probe::Established(p) if p == first_id)
        );
        // A second peer from 127.0.0.1: refused by the per-IP cap.
        dial_from(Keypair::generate_secp256k1(), addr.clone());
        match next(&mut probe, "the second").await {
            Probe::Refused(Some(e)) => {
                assert_eq!(
                    (e.kind(), e.limit()),
                    (CapKind::EstablishedIncomingPerIp, 1)
                );
            }
            other => panic!("{other:?}"),
        }
        // The reference node from the same address: let in.
        dial_from(reference.clone(), addr);
        let reference_id = reference.public().to_peer_id();
        assert!(
            matches!(next(&mut probe, "the reference node").await, Probe::Established(p) if p == reference_id)
        );
    }

    #[tokio::test]
    async fn the_probe_caps_pending_inbound_in_total_until_a_handshake_ends() {
        let mut cfg = probe_config();
        cfg.caps.max_pending_incoming = 1;
        cfg.connection_timeout = Duration::from_secs(1);
        let (addr, mut probe) = start_probe(&cfg).await;
        let Some(libp2p::multiaddr::Protocol::Tcp(port)) = addr.iter().nth(1) else {
            panic!("{addr}")
        };
        let target = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        // Two TCP connections that never start the handshake: the second is refused.
        let _first = tokio::net::TcpStream::connect(target).await.unwrap();
        let _second = tokio::net::TcpStream::connect(target).await.unwrap();
        match next(&mut probe, "the second").await {
            Probe::Refused(Some(e)) => {
                assert_eq!((e.kind(), e.limit()), (CapKind::PendingIncoming, 1));
            }
            other => panic!("{other:?}"),
        }
        // The first times out after 1 s, which frees its place: the next one is let in to
        // its own handshake (and times out in turn), not refused.
        assert!(matches!(
            next(&mut probe, "the timeout").await,
            Probe::Failed
        ));
        let _third = tokio::net::TcpStream::connect(target).await.unwrap();
        assert!(matches!(next(&mut probe, "the third").await, Probe::Failed));
    }
}
