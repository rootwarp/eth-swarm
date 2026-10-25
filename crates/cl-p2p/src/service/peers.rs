//! The peers cl-p2p dials: the candidates cl-discv5 finds (`ethswarm.discv5.v1.WatchPeers`,
//! [`watch_peers`]) and the static peers of the config, through the [`Dialer`].
//!
//! - **Candidates** ([`Candidate::from_wire`]): a `PeerCandidate` with a peer ID and at least
//!   one `/ip4|ip6/<addr>/tcp/<port>` address that passes the IP rule of the `mode`
//!   (`p2p_wire::ip::ip_rule`, the rule of cl-discv5's routing table). A candidate without them
//!   cannot be dialled and is dropped. cl-discv5 sends only records on our fork digest that pass
//!   its IP rules, but cl-p2p does not trust that: the rule is applied again before each dial.
//!   Noise proves the peer ID at the dial.
//! - **The stream** ([`watch_peers`]): connected to cl-discv5's socket with the peer check (its
//!   server must run as cl-discv5's UID), our hello in the request, read through the contract
//!   layer. When it ends or fails, it is opened again after a backoff (1 s, doubled to 30 s,
//!   and 1 s again after a stream that gave candidates), until the stop. A server of another
//!   user on the socket is logged at ERROR at each try, and nothing is read from it.
//! - **cl-discv5's record** ([`check_record_cgc`]): before each stream, `GetLocalEnr`. Its
//!   `cgc` must be the custody group count of our MetaData (cl-chain's custody), as peers read
//!   both. Another count, or none, stops the process with a refused config (exit 2): the two
//!   configs disagree, and a restart does not fix that.
//! - **The dialer** ([`Dialer`]): it keeps up to `target_peers` of our own dials connected or
//!   dialling. Inbound peers do not count: they have their own slots in the connection caps,
//!   and a peer that connects to us must not stop the dials of the peers we chose. A peer
//!   connected either way is not dialled. The static peers come first and are dialled again
//!   after each disconnect; the candidates follow, newest first. A peer is dialled again at
//!   most once per [`REDIAL_AFTER`]. It remembers at most [`MAX_CANDIDATES`] candidates, the
//!   oldest dropped first.

use crate::enr_text::{custody_group_count, EnrError};
use crate::m2a_session::PinnedPeer;
use crate::service::backoff::Backoff;
use crate::service::ServeError;
use ethswarm_proto::discv5 as pb;
use ipc::frame::Inbound;
use ipc::Link;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use p2p_wire::ip::{ip_rule, NetworkMode};
use pb::discovery_service_client::DiscoveryServiceClient;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

/// The candidates the dialer remembers at most \[est\]: a few lookups' worth.
pub const MAX_CANDIDATES: usize = 1024;

/// How long the dialer waits before it dials a peer again \[est\].
pub const REDIAL_AFTER: Duration = Duration::from_secs(60);

/// How many addresses of one candidate are kept.
pub const MAX_ADDRS: usize = 4;

/// A peer to dial: its ID and its TCP addresses, without `/p2p`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The peer ID that Noise must prove.
    pub peer: PeerId,
    /// Where to dial it.
    pub addrs: Vec<Multiaddr>,
}

impl Candidate {
    /// The candidate of a `PeerCandidate`, with only its TCP addresses that pass the IP rule
    /// of `mode`; `None` without a peer ID or such an address.
    #[must_use]
    pub fn from_wire(wire: &pb::PeerCandidate, mode: NetworkMode) -> Option<Self> {
        let peer: PeerId = wire.peer_id.parse().ok()?;
        let allowed = ip_rule(mode);
        let addrs: Vec<Multiaddr> = wire
            .multiaddrs
            .iter()
            .filter_map(|a| a.parse::<Multiaddr>().ok())
            .filter(|a| tcp_ip(a).is_some_and(allowed))
            .take(MAX_ADDRS)
            .collect();
        (!addrs.is_empty()).then_some(Self { peer, addrs })
    }
}

/// The IP of `/ip4|ip6/<addr>/tcp/<port>` (and nothing else), if the address can be dialled.
fn tcp_ip(addr: &Multiaddr) -> Option<IpAddr> {
    let parts: Vec<Protocol<'_>> = addr.iter().collect();
    match parts.as_slice() {
        [Protocol::Ip4(ip), Protocol::Tcp(port)]
            if *port != 0 && !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast() =>
        {
            Some(IpAddr::V4(*ip))
        }
        [Protocol::Ip6(ip), Protocol::Tcp(port)]
            if *port != 0 && !ip.is_unspecified() && !ip.is_multicast() =>
        {
            Some(IpAddr::V6(*ip))
        }
        _ => None,
    }
}

/// Which peers to dial (see the module docs).
#[derive(Debug)]
pub struct Dialer {
    target: usize,
    statics: Vec<PinnedPeer>,
    candidates: HashMap<PeerId, Vec<Multiaddr>>,
    /// Candidates, oldest first.
    order: VecDeque<PeerId>,
    /// Peers connected either way.
    connected: HashSet<PeerId>,
    /// Peers connected through a dial of ours: what counts toward the target.
    outbound: HashSet<PeerId>,
    dialling: HashSet<PeerId>,
    last_dial: HashMap<PeerId, Instant>,
}

impl Dialer {
    /// A dialer that keeps `target` peers of its dials connected or dialling, `statics` always.
    #[must_use]
    pub fn new(target: usize, statics: Vec<PinnedPeer>) -> Self {
        Self {
            target,
            statics,
            candidates: HashMap::new(),
            order: VecDeque::new(),
            connected: HashSet::new(),
            outbound: HashSet::new(),
            dialling: HashSet::new(),
            last_dial: HashMap::new(),
        }
    }

    /// Remembers `candidate`, newest; the oldest goes past [`MAX_CANDIDATES`].
    pub fn add(&mut self, candidate: Candidate) {
        if self.statics.iter().any(|s| s.peer_id == candidate.peer) {
            return;
        }
        if self
            .candidates
            .insert(candidate.peer, candidate.addrs)
            .is_some()
        {
            self.order.retain(|p| *p != candidate.peer);
        }
        self.order.push_back(candidate.peer);
        while self.order.len() > MAX_CANDIDATES {
            if let Some(old) = self.order.pop_front() {
                self.candidates.remove(&old);
                self.last_dial.remove(&old);
            }
        }
    }

    /// `peer` connected, through a dial of ours if `outbound`. An inbound connection does not
    /// end a dial of ours: that ends when it connects or fails.
    pub fn connected(&mut self, peer: PeerId, outbound: bool) {
        self.connected.insert(peer);
        if outbound {
            self.dialling.remove(&peer);
            self.outbound.insert(peer);
        }
    }

    /// `peer`'s last connection closed.
    pub fn disconnected(&mut self, peer: &PeerId) {
        self.connected.remove(peer);
        self.outbound.remove(peer);
    }

    /// A dial of `peer` failed.
    pub fn failed(&mut self, peer: &PeerId) {
        self.dialling.remove(peer);
    }

    /// Peers connected now, either way.
    #[must_use]
    pub fn connected_count(&self) -> usize {
        self.connected.len()
    }

    /// Peers connected now through a dial of ours.
    #[must_use]
    pub fn outbound_count(&self) -> usize {
        self.outbound.len()
    }

    /// The peers to dial at `now`: the static peers not connected, then candidates, newest
    /// first, until `target` of our dials are connected or dialling; none dialled within
    /// [`REDIAL_AFTER`]. Each one returned counts as dialling until it connects or fails.
    pub fn due(&mut self, now: Instant) -> Vec<(PeerId, Vec<Multiaddr>)> {
        let mut out = Vec::new();
        let rested = |last: Option<&Instant>| last.is_none_or(|t| now >= *t + REDIAL_AFTER);
        let statics: Vec<(PeerId, Vec<Multiaddr>)> = self
            .statics
            .iter()
            .map(|s| (s.peer_id, vec![s.addr.clone()]))
            .collect();
        let newest: Vec<PeerId> = self.order.iter().rev().copied().collect();
        let candidates = newest
            .into_iter()
            .filter_map(|p| self.candidates.get(&p).map(|a| (p, a.clone())));
        for (peer, addrs) in statics.into_iter().chain(candidates) {
            let is_static = self.statics.iter().any(|s| s.peer_id == peer);
            if !is_static && self.outbound.len() + self.dialling.len() >= self.target {
                break;
            }
            if self.connected.contains(&peer)
                || self.dialling.contains(&peer)
                || !rested(self.last_dial.get(&peer))
            {
                continue;
            }
            self.dialling.insert(peer);
            self.last_dial.insert(peer, now);
            out.push((peer, addrs));
        }
        out
    }
}

/// Where cl-discv5 is, who it must be, what its record must say, and which addresses of its
/// candidates may be dialled.
#[derive(Debug, Clone)]
pub struct Discv5Peer {
    /// Its socket.
    pub socket: PathBuf,
    /// The UID its server must run as.
    pub uid: u32,
    /// The IP rule of the candidates' addresses.
    pub mode: NetworkMode,
    /// The custody group count of our MetaData: its record's `cgc` must be the same.
    pub groups: u64,
}

/// Why cl-discv5's record does not fit our custody.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordCgc {
    /// The record advertises another custody group count than our MetaData.
    #[error(
        "cl-discv5's record advertises cgc {record}, but cl-chain custodies {ours} groups: set \
         cgc = {ours} in cl-discv5's [discv5] table"
    )]
    Differs {
        /// The record's count.
        record: u64,
        /// Ours.
        ours: u64,
    },
    /// The record advertises none.
    #[error(
        "cl-discv5's record has no cgc, but cl-chain custodies {ours} groups: set cgc = {ours} \
         in cl-discv5's [discv5] table"
    )]
    Missing {
        /// Ours.
        ours: u64,
    },
    /// The record does not decode.
    #[error("cl-discv5's record: {0}")]
    Unreadable(EnrError),
}

/// Fails unless the textual record `text` advertises `ours` custody groups.
///
/// # Errors
///
/// [`RecordCgc`].
pub fn check_record_cgc(text: &str, ours: u64) -> Result<(), RecordCgc> {
    match custody_group_count(text) {
        Ok(record) if record == ours => Ok(()),
        Ok(record) => Err(RecordCgc::Differs { record, ours }),
        Err(EnrError::NoCgc) => Err(RecordCgc::Missing { ours }),
        Err(e) => Err(RecordCgc::Unreadable(e)),
    }
}

/// Reads cl-discv5's `WatchPeers` stream into `candidates` until `stop` turns true or its
/// sender goes, opening it again after each end or failure (see the module docs). A candidate
/// that the dialer does not take in time is dropped: the next lookup finds it again.
///
/// # Errors
///
/// cl-discv5's record does not advertise our custody group count ([`check_record_cgc`]):
/// nothing more is read, and the process must stop. At the first record that is
/// [`ServeError::Config`] (exit 2, a refused start); after a record passed it is
/// [`ServeError::Software`] (exit 70, logged at ERROR), so that systemd starts the unit again and
/// a bad peer service cannot stop cl-p2p for good.
pub async fn watch_peers(
    discv5: Discv5Peer,
    link: Link,
    candidates: mpsc::Sender<Candidate>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), ServeError> {
    let mut backoff = Backoff::default();
    let mut passed = false;
    loop {
        if *stop.borrow_and_update() {
            return Ok(());
        }
        let started = passed;
        let read = read_stream(&discv5, &link, &candidates, &mut passed);
        let ended = tokio::select! {
            ended = read => ended,
            _ = stop.changed() => return Ok(()),
        };
        if let Err(Unread::Cgc(e)) = ended {
            if !started {
                return Err(ServeError::Config(e.to_string()));
            }
            tracing::error!(error = %e, "cl-discv5's record changed its custody group count");
            return Err(ServeError::Software(format!(
                "cl-discv5's record changed after the start: {e}"
            )));
        }
        let refused = matches!(&ended, Err(Unread::Refused(_)));
        let delivered = match ended {
            Ok(got) => {
                tracing::info!(candidates = got, "cl-discv5's WatchPeers stream ended");
                got > 0
            }
            Err(e) => {
                tracing::warn!(error = %e, "cl-discv5's WatchPeers stream failed");
                false
            }
        };
        if refused {
            tracing::error!(
                socket = %discv5.socket.display(),
                "the server on cl-discv5's socket is not cl-discv5's user: no peers from it"
            );
        }
        tokio::select! {
            () = tokio::time::sleep(backoff.after(delivered)) => {}
            _ = stop.changed() => return Ok(()),
        }
    }
}

/// Why a `WatchPeers` stream gave nothing more.
#[derive(Debug, thiserror::Error)]
enum Unread {
    /// The server on the socket is not cl-discv5's user.
    #[error("{0}")]
    Refused(String),
    /// cl-discv5's record does not advertise our custody group count.
    #[error("{0}")]
    Cgc(RecordCgc),
    /// Anything else: not there yet, gone, or a contract error.
    #[error("{0}")]
    Other(String),
}

impl From<String> for Unread {
    fn from(why: String) -> Self {
        Self::Other(why)
    }
}

/// One `WatchPeers` stream: how many candidates it gave before it ended. `passed` turns true
/// once cl-discv5's record passed the custody check.
async fn read_stream(
    discv5: &Discv5Peer,
    link: &Link,
    candidates: &mpsc::Sender<Candidate>,
    passed: &mut bool,
) -> Result<usize, Unread> {
    let channel = ipc::uds::connect_path(&discv5.socket, discv5.uid)
        .await
        .map_err(|e| {
            let shown = format!("cl-discv5 at {}: {e}", discv5.socket.display());
            if ipc::uds::peer_refusal(&e).is_some() {
                Unread::Refused(shown)
            } else {
                Unread::Other(shown)
            }
        })?;
    let mut client = DiscoveryServiceClient::new(channel);
    let record = client
        .get_local_enr(pb::GetLocalEnrRequest {})
        .await
        .map_err(|e| format!("GetLocalEnr: {}", e.message()))?
        .into_inner()
        .enr
        .map(|enr| enr.text)
        .unwrap_or_default();
    match check_record_cgc(&record, discv5.groups) {
        Ok(()) => *passed = true,
        Err(e @ RecordCgc::Unreadable(_)) => return Err(Unread::Other(e.to_string())),
        Err(e) => return Err(Unread::Cgc(e)),
    }
    let stream = client
        .watch_peers(pb::WatchPeersRequest {
            hello: Some(link.local()),
        })
        .await
        .map_err(|e| format!("WatchPeers: {}", e.message()))?
        .into_inner();
    let mut guarded = link
        .open(Inbound::from_server(stream))
        .await
        .map_err(|e| format!("WatchPeers: {e}"))?;
    tracing::info!(socket = %discv5.socket.display(), "watching cl-discv5's peers");
    let mut got = 0;
    while let Some(accepted) = guarded
        .body()
        .await
        .map_err(|e| format!("WatchPeers: {e}"))?
    {
        let Some(candidate) = accepted
            .body
            .candidate
            .as_ref()
            .and_then(|c| Candidate::from_wire(c, discv5.mode))
        else {
            tracing::debug!(
                "a peer candidate without a peer ID or an allowed TCP address: dropped"
            );
            continue;
        };
        got += 1;
        if candidates.try_send(candidate).is_err() {
            tracing::debug!("the dialer is busy: a peer candidate dropped");
        }
    }
    Ok(got)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        libp2p::identity::Keypair::generate_secp256k1()
            .public()
            .to_peer_id()
    }

    fn wire(peer: &str, addrs: &[&str]) -> pb::PeerCandidate {
        pb::PeerCandidate {
            peer_id: peer.to_owned(),
            multiaddrs: addrs.iter().map(|a| (*a).to_owned()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_candidate_needs_a_peer_id_and_a_tcp_address() {
        let p = peer();
        let got = Candidate::from_wire(
            &wire(
                &p.to_string(),
                &[
                    "/ip4/10.0.0.2/tcp/9000",
                    "/ip4/10.0.0.2/udp/9000",
                    "/ip4/0.0.0.0/tcp/9000",
                    "/ip4/10.0.0.2/tcp/0",
                    "/ip6/fd00::2/tcp/9001",
                    "/ip4/10.0.0.2/tcp/9000/p2p/x",
                    "not an address",
                ],
            ),
            NetworkMode::Devnet,
        )
        .unwrap();
        assert_eq!(got.peer, p);
        let addrs: Vec<String> = got.addrs.iter().map(ToString::to_string).collect();
        assert_eq!(addrs, ["/ip4/10.0.0.2/tcp/9000", "/ip6/fd00::2/tcp/9001"]);
        let devnet = |w: &pb::PeerCandidate| Candidate::from_wire(w, NetworkMode::Devnet);
        assert!(devnet(&wire("x", &["/ip4/10.0.0.2/tcp/9000"])).is_none());
        assert!(devnet(&wire(&p.to_string(), &["/ip4/10.0.0.2/udp/9"])).is_none());
    }

    /// The addresses of a candidate pass the IP rule of the network mode, as cl-discv5's
    /// routing table does: a public network dials no private or loopback address, and a local
    /// one no public address, whatever the record says.
    #[test]
    fn a_candidate_keeps_only_the_addresses_of_the_mode() {
        let p = peer().to_string();
        let mixed = wire(
            &p,
            &[
                "/ip4/127.0.0.1/tcp/9000",
                "/ip4/10.0.0.2/tcp/9000",
                "/ip4/192.168.1.2/tcp/9000",
                "/ip4/8.8.8.8/tcp/9000",
                "/ip6/fd00::2/tcp/9000",
                "/ip6/2001:4860::8888/tcp/9000",
            ],
        );
        let kept = |mode| -> Vec<String> {
            Candidate::from_wire(&mixed, mode)
                .map(|c| c.addrs.iter().map(ToString::to_string).collect())
                .unwrap_or_default()
        };
        assert_eq!(
            kept(NetworkMode::Public),
            ["/ip4/8.8.8.8/tcp/9000", "/ip6/2001:4860::8888/tcp/9000"]
        );
        assert_eq!(
            kept(NetworkMode::Local),
            [
                "/ip4/127.0.0.1/tcp/9000",
                "/ip4/10.0.0.2/tcp/9000",
                "/ip4/192.168.1.2/tcp/9000",
                "/ip6/fd00::2/tcp/9000",
            ]
        );
        assert_eq!(kept(NetworkMode::Devnet).len(), MAX_ADDRS);
        // Only private addresses, on a public network: nothing to dial.
        let private = wire(&p, &["/ip4/10.0.0.2/tcp/9000", "/ip4/127.0.0.1/tcp/9000"]);
        assert!(Candidate::from_wire(&private, NetworkMode::Public).is_none());
    }

    /// cl-discv5's record must advertise the custody group count of our MetaData: another
    /// count, or none, is a config to fix ([`RecordCgc::Differs`], [`RecordCgc::Missing`]); a
    /// record that does not decode is a fault of the stream, tried again.
    #[test]
    fn the_record_must_carry_our_custody_group_count() {
        use crate::testkit::record_text;
        let eth2 = [0u8; 16];
        let with = |cgc: &[u8]| record_text(&[(b"cgc", cgc), (b"eth2", &eth2)]);
        assert_eq!(check_record_cgc(&with(&[4]), 4), Ok(()));
        assert_eq!(check_record_cgc(&with(&[128]), 128), Ok(()));
        assert_eq!(
            check_record_cgc(&with(&[8]), 4),
            Err(RecordCgc::Differs { record: 8, ours: 4 })
        );
        let err = check_record_cgc(&record_text(&[(b"eth2", &eth2)]), 4).unwrap_err();
        assert_eq!(err, RecordCgc::Missing { ours: 4 });
        assert!(err.to_string().contains("cgc = 4"), "{err}");
        assert!(matches!(
            check_record_cgc(&with(&[0, 4]), 4),
            Err(RecordCgc::Unreadable(_))
        ));
        assert!(matches!(
            check_record_cgc("", 4),
            Err(RecordCgc::Unreadable(_))
        ));
    }

    fn candidate(n: u8) -> Candidate {
        Candidate {
            peer: peer(),
            addrs: vec![format!("/ip4/10.0.0.{n}/tcp/9000").parse().unwrap()],
        }
    }

    #[test]
    fn the_dialer_keeps_the_target_newest_first() {
        let mut d = Dialer::new(2, Vec::new());
        let (a, b, c) = (candidate(1), candidate(2), candidate(3));
        for x in [&a, &b, &c] {
            d.add(x.clone());
        }
        let now = Instant::now();
        let first: Vec<PeerId> = d.due(now).into_iter().map(|(p, _)| p).collect();
        assert_eq!(first, [c.peer, b.peer]);
        // Dialling counts: nothing more until one ends.
        assert!(d.due(now).is_empty());
        d.connected(c.peer, true);
        d.failed(&b.peer);
        // `b` rests; `a` is next.
        let next: Vec<PeerId> = d.due(now).into_iter().map(|(p, _)| p).collect();
        assert_eq!(next, [a.peer]);
        d.failed(&a.peer);
        assert!(d.due(now + Duration::from_secs(1)).is_empty());
        // After the rest, both are dialled again, newest first.
        let later: Vec<PeerId> = d
            .due(now + REDIAL_AFTER)
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(later, [b.peer]);
        assert_eq!(d.connected_count(), 1);
    }

    /// Only our own dials count toward the target: inbound peers fill the inbound slots and
    /// must not stop the dials, or an attacker that connects inbound starves us of peers we
    /// chose. A peer connected inbound is not dialled again.
    #[test]
    fn inbound_peers_do_not_stop_the_dials() {
        let mut d = Dialer::new(2, Vec::new());
        let (a, b) = (candidate(1), candidate(2));
        d.add(a.clone());
        d.add(b.clone());
        for _ in 0..8 {
            d.connected(peer(), false);
        }
        d.connected(a.peer, false);
        let now = Instant::now();
        let due: Vec<PeerId> = d.due(now).into_iter().map(|(p, _)| p).collect();
        assert_eq!(
            due,
            [b.peer],
            "inbound peers took no dial slot; a is connected already"
        );
        assert_eq!(d.connected_count(), 9);
        assert_eq!(d.outbound_count(), 0);
        // An inbound connection of a peer we dial does not end our dial: still counted.
        d.connected(b.peer, false);
        assert!(
            d.due(now).is_empty(),
            "b's dial and a's inbound: nothing to dial"
        );
        d.connected(b.peer, true);
        assert_eq!(d.outbound_count(), 1);
        d.disconnected(&b.peer);
        assert_eq!((d.connected_count(), d.outbound_count()), (9, 0));
    }

    #[test]
    fn static_peers_come_first_and_always() {
        let s = PinnedPeer {
            peer_id: peer(),
            addr: "/ip4/10.0.0.9/tcp/9000".parse().unwrap(),
        };
        let mut d = Dialer::new(1, vec![s.clone()]);
        d.add(candidate(1));
        let x = candidate(2);
        d.connected(x.peer, true);
        // The target is reached, but a static peer is dialled anyway.
        let now = Instant::now();
        let due = d.due(now);
        assert_eq!(due, [(s.peer_id, vec![s.addr.clone()])]);
        d.connected(s.peer_id, true);
        d.disconnected(&s.peer_id);
        assert!(d.due(now).is_empty(), "rests after its dial");
        assert_eq!(d.due(now + REDIAL_AFTER).len(), 1);
        // A static peer is never a candidate too.
        d.add(Candidate {
            peer: s.peer_id,
            addrs: vec![s.addr.clone()],
        });
        assert_eq!(d.candidates.len(), 1);
    }

    #[test]
    fn the_dialer_remembers_a_bounded_set() {
        let mut d = Dialer::new(1, Vec::new());
        let first = candidate(1);
        d.add(first.clone());
        for _ in 0..MAX_CANDIDATES {
            d.add(candidate(2));
        }
        assert_eq!(d.candidates.len(), MAX_CANDIDATES);
        assert!(!d.candidates.contains_key(&first.peer));
        // A candidate seen again moves to the newest place.
        let again = candidate(3);
        d.add(again.clone());
        d.add(candidate(4));
        d.add(again.clone());
        assert_eq!(d.order.back(), Some(&again.peer));
    }
}
