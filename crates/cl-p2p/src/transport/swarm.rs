//! The probe swarm: TCP, Noise XX and [`muxers`], listening and dialing, with the peer and
//! dial-failure metrics.
//!
//! Every supported transport MUST be enabled for both dialing and listening
//! (`phase0/p2p-interface.md`), so [`build_swarm`] starts a listener on every
//! [`SwarmConfig::listen_addrs`] address (TCP 9000 by default) and the swarm dials over the same
//! transport. QUIC is not built: see the crate README, §Deviations.
//!
//! The swarm's owner runs its event loop and hands every event to [`PeerMetrics::observe`],
//! which keeps `p2p_peers{direction}` and `p2p_dial_failures_total{reason}` and logs each
//! connection. [`LogNegotiated`] logs the muxer each connection negotiated.

use super::{muxers, with_negotiating_inbound_streams, MuxerBudget, MPLEX_MAX_STREAMS};
use crate::behaviour::{Behaviour, ConnectionCaps, ReqRespSlot};
use libp2p::core::transport::TransportError;
use libp2p::core::upgrade::{
    InboundConnectionUpgrade, NegotiationError, OutboundConnectionUpgrade, UpgradeInfo,
};
use libp2p::identity::Keypair;
use libp2p::swarm::{DialError, SwarmEvent};
use libp2p::{noise, tcp, Multiaddr, PeerId, Swarm, SwarmBuilder};
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::error::Error;
use std::fmt::Write as _;
use std::io;
use std::time::Duration;

/// The TCP port a consensus-layer client listens and is dialed on.
pub const DEFAULT_TCP_PORT: u16 = 9000;

/// Inbound streams one connection may have negotiating at once.
///
/// [`super::BudgetedMuxer`] counts and drains only the streams the swarm has taken from mplex;
/// the swarm takes inbound streams only while fewer than this many are negotiating. At
/// [`MPLEX_MAX_STREAMS`] or more it always takes them, since mplex never holds more. 128 is the
/// libp2p default, set here so a change of default cannot lower it.
pub const MAX_NEGOTIATING_INBOUND_STREAMS: usize = 128;

const _: () = assert!(
    MAX_NEGOTIATING_INBOUND_STREAMS >= MPLEX_MAX_STREAMS,
    "mplex would hold frames for streams the budget does not see"
);

/// How long a connection with no open stream stays up. The req/resp and gossipsub handlers
/// keep a live peer's connection busy; identify alone does not.
pub const DEFAULT_IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a connection may take from TCP connect through Noise and the muxer.
pub const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// What [`build_swarm`] builds.
#[derive(Clone, Debug)]
pub struct SwarmConfig {
    /// Where the swarm listens; `/ip4/0.0.0.0/tcp/9000` by default.
    pub listen_addrs: Vec<Multiaddr>,
    pub idle_connection_timeout: Duration,
    pub connection_timeout: Duration,
    /// What identify announces as our agent.
    pub agent_version: String,
    /// The per-connection budget of the mplex muxer.
    pub budget: MuxerBudget,
    /// The connection caps; see [`ConnectionCaps`] for the defaults.
    pub caps: ConnectionCaps,
    /// Peers exempt from the connection caps: the reference node. None by default.
    pub bypass: Vec<PeerId>,
}

impl SwarmConfig {
    /// The defaults, with mplex under `budget`.
    #[must_use]
    pub fn new(budget: MuxerBudget) -> Self {
        let any_ipv4: Multiaddr = [
            libp2p::multiaddr::Protocol::Ip4(std::net::Ipv4Addr::UNSPECIFIED),
            libp2p::multiaddr::Protocol::Tcp(DEFAULT_TCP_PORT),
        ]
        .into_iter()
        .collect();
        Self {
            listen_addrs: vec![any_ipv4],
            idle_connection_timeout: DEFAULT_IDLE_CONNECTION_TIMEOUT,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            agent_version: concat!("ethswarm/", env!("CARGO_PKG_VERSION")).to_owned(),
            budget,
            caps: ConnectionCaps::default(),
            bypass: Vec::new(),
        }
    }
}

/// Why [`build_swarm`] failed.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The Noise config could not be built from the node key.
    #[error("noise: {0}")]
    Noise(#[from] noise::Error),
    /// A listen address was refused.
    #[error("cannot listen on {addr}: {source}")]
    Listen {
        addr: Multiaddr,
        source: TransportError<io::Error>,
    },
}

/// The probe swarm for the node key `keypair`: TCP (no Nagle), Noise XX, then yamux or mplex
/// ([`muxers`], yamux first, mplex under `cfg.budget`), [`Behaviour`] with `req_resp` in its
/// req/resp slot, listening on every `cfg.listen_addrs` address.
///
/// Must be called within a tokio runtime, which the listeners register with.
///
/// # Errors
///
/// [`BuildError::Noise`] if Noise refuses the key, [`BuildError::Listen`] if an address cannot
/// be listened on.
pub fn build_swarm(
    keypair: Keypair,
    cfg: &SwarmConfig,
    req_resp: ReqRespSlot,
) -> Result<Swarm<Behaviour>, BuildError> {
    let (yamux, mplex) = muxers(cfg.budget.clone());
    let Ok(builder) = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            (
                move || LogNegotiated(yamux()),
                move || LogNegotiated(mplex()),
            ),
        )?
        .with_behaviour(|key| {
            Behaviour::with_caps(key.public(), cfg.agent_version.clone(), cfg.caps, req_resp)
        });
    let mut swarm = builder
        .with_swarm_config(|c| {
            with_negotiating_inbound_streams(
                c.with_idle_connection_timeout(cfg.idle_connection_timeout),
                MAX_NEGOTIATING_INBOUND_STREAMS,
            )
        })
        .with_connection_timeout(cfg.connection_timeout)
        .build();
    for peer in &cfg.bypass {
        swarm.behaviour_mut().bypass(*peer);
    }
    for addr in &cfg.listen_addrs {
        swarm
            .listen_on(addr.clone())
            .map_err(|source| BuildError::Listen {
                addr: addr.clone(),
                source,
            })?;
    }
    Ok(swarm)
}

/// A muxer upgrade that logs the muxer protocol multistream-select settled on, then applies it.
#[derive(Clone, Debug)]
pub struct LogNegotiated<U>(pub U);

impl<U: UpgradeInfo> UpgradeInfo for LogNegotiated<U> {
    type Info = U::Info;
    type InfoIter = U::InfoIter;

    fn protocol_info(&self) -> Self::InfoIter {
        self.0.protocol_info()
    }
}

impl<C, U> InboundConnectionUpgrade<C> for LogNegotiated<U>
where
    U: InboundConnectionUpgrade<C>,
{
    type Output = U::Output;
    type Error = U::Error;
    type Future = U::Future;

    fn upgrade_inbound(self, socket: C, info: Self::Info) -> Self::Future {
        tracing::info!(
            muxer = info.as_ref(),
            role = "listener",
            "negotiated a stream muxer"
        );
        self.0.upgrade_inbound(socket, info)
    }
}

impl<C, U> OutboundConnectionUpgrade<C> for LogNegotiated<U>
where
    U: OutboundConnectionUpgrade<C>,
{
    type Output = U::Output;
    type Error = U::Error;
    type Future = U::Future;

    fn upgrade_outbound(self, socket: C, info: Self::Info) -> Self::Future {
        tracing::info!(
            muxer = info.as_ref(),
            role = "dialer",
            "negotiated a stream muxer"
        );
        self.0.upgrade_outbound(socket, info)
    }
}

/// Which side opened a connection.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Direction {
    /// The peer dialed us.
    Inbound,
    /// We dialed the peer.
    Outbound,
}

impl Direction {
    pub const ALL: [Self; 2] = [Self::Inbound, Self::Outbound];

    /// The direction of a connection on which we are the dialer or not.
    #[must_use]
    pub fn of(is_dialer: bool) -> Self {
        if is_dialer {
            Self::Outbound
        } else {
            Self::Inbound
        }
    }

    /// The `direction` label value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

impl EncodeLabelValue for Direction {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> std::fmt::Result {
        encoder.write_str(self.as_str())
    }
}

/// Why a dial failed: the `reason` label of `p2p_dial_failures_total`.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum DialFailure {
    /// The peer supports none of our security or muxer protocols, or the Noise handshake
    /// failed.
    Negotiation,
    /// Noise proved a peer ID other than the one dialed.
    WrongPeerId,
    /// A behaviour refused the connection (e.g. the per-peer limit).
    Denied,
    /// The TCP connect was refused.
    Refused,
    /// The connection was not up within the connection timeout.
    Timeout,
    /// Any other transport failure.
    Transport,
    /// No address, aborted, the dial condition, or our own peer ID.
    Other,
}

/// What [`libp2p::core::transport::timeout::TransportTimeoutError::Timeout`] displays. The type
/// is generic over the whole transport's error, so it cannot be downcast to.
const TRANSPORT_TIMEOUT: &str = "Timeout has been reached";

impl DialFailure {
    pub const ALL: [Self; 7] = [
        Self::Negotiation,
        Self::WrongPeerId,
        Self::Denied,
        Self::Refused,
        Self::Timeout,
        Self::Transport,
        Self::Other,
    ];

    /// The reason for `error`. A dial to several addresses takes the reason of the first.
    #[must_use]
    pub fn of(error: &DialError) -> Self {
        match error {
            DialError::WrongPeerId { .. } => Self::WrongPeerId,
            DialError::Denied { .. } => Self::Denied,
            DialError::Transport(errors) => match errors.first() {
                Some((_, TransportError::Other(e))) => Self::of_io(e),
                Some((_, TransportError::MultiaddrNotSupported(_))) | None => Self::Transport,
            },
            DialError::LocalPeerId { .. }
            | DialError::NoAddresses
            | DialError::DialPeerConditionFalse(_)
            | DialError::Aborted => Self::Other,
        }
    }

    /// The reason for a transport error: the first cause in its chain that names one.
    ///
    /// `io::Error::source` skips the error an `io::Error` wraps, so it is unwrapped by hand. Any
    /// Noise error is a failed handshake (`negotiation`) unless it timed out. The swarm builder joins its transports with
    /// `Either`, whose `source` skips the side it holds, so a cause with no source of its own
    /// may still hide an `io::Error`: [`Self::of_leaf`] reads that one's kind from its `Debug`.
    fn of_io(error: &io::Error) -> Self {
        let mut next: Option<&(dyn Error + 'static)> = Some(error);
        while let Some(e) = next {
            if e.is::<NegotiationError>() {
                return Self::Negotiation;
            }
            if let Some(noise) = e.downcast_ref::<noise::Error>() {
                // Noise reports a message that fails to decrypt or decode as an `InvalidData`
                // io error with no source: the handshake failed, whatever its kind says,
                // unless it timed out. One that wraps a failed negotiation names it too.
                return match noise {
                    noise::Error::Io(io) if io.kind() == io::ErrorKind::TimedOut => Self::Timeout,
                    _ => Self::Negotiation,
                };
            }
            if let Some(io) = e.downcast_ref::<io::Error>() {
                match io.kind() {
                    io::ErrorKind::ConnectionRefused => return Self::Refused,
                    io::ErrorKind::TimedOut => return Self::Timeout,
                    _ => {}
                }
                next = io.get_ref().map(|inner| inner as &(dyn Error + 'static));
                continue;
            }
            next = e.source();
            if next.is_none() {
                return Self::of_leaf(e);
            }
        }
        Self::Transport
    }

    /// The reason for the last cause of a chain, which no downcast reached: the transport
    /// timeout by its message, else the kind of an `io::Error` it wraps by its `Debug`
    /// (`kind: ConnectionRefused` for an OS error, `Kind(ConnectionRefused)` for a bare kind).
    fn of_leaf(error: &(dyn Error + 'static)) -> Self {
        if error.to_string() == TRANSPORT_TIMEOUT {
            return Self::Timeout;
        }
        let debug = format!("{error:?}");
        let has_kind = |kind: &str| {
            debug.contains(&format!("kind: {kind}")) || debug.contains(&format!("Kind({kind})"))
        };
        if has_kind("ConnectionRefused") {
            Self::Refused
        } else if has_kind("TimedOut") {
            Self::Timeout
        } else {
            Self::Transport
        }
    }

    /// The `reason` label value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Negotiation => "negotiation",
            Self::WrongPeerId => "wrong_peer_id",
            Self::Denied => "denied",
            Self::Refused => "refused",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Other => "other",
        }
    }
}

impl EncodeLabelValue for DialFailure {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> std::fmt::Result {
        encoder.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DirectionLabel {
    direction: Direction,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReasonLabel {
    reason: DialFailure,
}

/// `p2p_peers{direction}` and `p2p_dial_failures_total{reason}`, on the service's
/// prometheus-client [`Registry`].
///
/// `p2p_peers` counts established connections by who dialed. The behaviour allows one per
/// peer, so it is the peer count.
#[derive(Clone, Debug)]
pub struct PeerMetrics {
    peers: Family<DirectionLabel, Gauge>,
    dial_failures: Family<ReasonLabel, Counter>,
}

impl PeerMetrics {
    /// Creates both metrics, every label value at 0, and registers them in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self {
            peers: Family::default(),
            dial_failures: Family::default(),
        };
        for direction in Direction::ALL {
            drop(metrics.peers.get_or_create(&DirectionLabel { direction }));
        }
        for reason in DialFailure::ALL {
            drop(metrics.dial_failures.get_or_create(&ReasonLabel { reason }));
        }
        registry.register(
            "p2p_peers",
            "Connected peers, by who dialed",
            metrics.peers.clone(),
        );
        registry.register(
            "p2p_dial_failures",
            "Dials that failed, by reason",
            metrics.dial_failures.clone(),
        );
        metrics
    }

    /// Updates the metrics for one swarm event, and logs connections and failed dials.
    pub fn observe<E>(&self, event: &SwarmEvent<E>) {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let direction = Direction::of(endpoint.is_dialer());
                self.peers
                    .get_or_create(&DirectionLabel { direction })
                    .inc();
                tracing::info!(
                    peer = %peer_id,
                    direction = direction.as_str(),
                    addr = %endpoint.get_remote_address(),
                    "connection established"
                );
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                endpoint,
                cause,
                ..
            } => {
                let direction = Direction::of(endpoint.is_dialer());
                self.peers
                    .get_or_create(&DirectionLabel { direction })
                    .dec();
                tracing::info!(
                    peer = %peer_id,
                    direction = direction.as_str(),
                    cause = ?cause,
                    "connection closed"
                );
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => self.observe_dial_error(error),
            _ => {}
        }
    }

    /// Counts a failed dial, whether `Swarm::dial` refused it or the attempt failed later.
    pub fn observe_dial_error(&self, error: &DialError) {
        let reason = DialFailure::of(error);
        self.dial_failures
            .get_or_create(&ReasonLabel { reason })
            .inc();
        tracing::debug!(reason = reason.as_str(), %error, "dial failed");
    }

    /// The current `p2p_peers{direction}`.
    #[must_use]
    pub fn peers(&self, direction: Direction) -> i64 {
        self.peers
            .get_or_create(&DirectionLabel { direction })
            .get()
    }

    /// The current `p2p_dial_failures_total{reason}`.
    #[must_use]
    pub fn dial_failures(&self, reason: DialFailure) -> u64 {
        self.dial_failures
            .get_or_create(&ReasonLabel { reason })
            .get()
    }
}
