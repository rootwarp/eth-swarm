//! The discv5 service: the local record, the routing-table IP rules and fork-filtered lookups.
//!
//! - **IP rules** ([`table_filter`]): discv5's `table_filter` is a bare `fn(&Enr) -> bool`, so
//!   it can hold no state and carries the IP rules only, one function per [`NetworkMode`].
//!   discv5 applies it when a lookup or [`Discovery::add_enr`] would add a record to the
//!   routing table.
//! - **Fork filter** ([`PeerFilter`]): our fork digest and the IP rules together. It is the
//!   `find_node_predicate` closure ([`fork_predicate`]), so a lookup returns only records whose
//!   `eth2.fork_digest` is ours and that pass the IP rules, and it filters the event stream.
//!   The `next_fork_*` fields and `nfd` are not compared: a peer that plans another next fork
//!   is still on our fork until the boundary, and `fulu/p2p-interface.md` forbids dropping it
//!   before then.
//! - **Service** ([`Discovery`]): `Discv5::new` with the local record and node key, the IP
//!   rules as `table_filter`, then `start` and the event stream ([`Events`]). Lookups go
//!   through [`Discovery::find_peers`], which runs the [`PeerFilter`] as the predicate and then
//!   checks every returned record against it again ([`PeerFilter::retain`]). Events go through
//!   [`Events::next`], which applies the [`PeerFilter`] to every record and, for a session,
//!   the IP rules to its source address too.
//! - **Table eviction** ([`EvictionReason`]): discv5 0.12 does not run `table_filter` on every
//!   insertion (the gaps below), so a record that fails the IP rules, or that is on another fork
//!   digest, can still enter the routing table. [`Events::next`] removes the table record of
//!   the peer every `Discovered`, `SessionEstablished` and `NodeInserted` event names when it
//!   fails [`PeerFilter::eviction_reason`], and a task sweeps the whole table every
//!   [`DiscoveryConfig::sweep_interval`] ([`SWEEP_INTERVAL`], [`table_evictions`]) for what no
//!   polled event reported. Both go through `Discv5::remove_node` and count
//!   `discv5_table_evictions_total{reason}` ([`crate::metrics`]). A record added through
//!   [`Discovery::add_enr`] (a boot node) is exempt from the fork rule, never from the IP rules.
//!
//! **What is guaranteed.** A record that fails the IP rules or is on another fork digest is never
//! returned by [`Discovery::find_peers`] and never surfaced by [`Events::next`], and no session
//! from a source address outside the IP rules is surfaced. Such a record does not stay in discv5's
//! routing table: it is evicted on its event, or at the latest one sweep interval (plus the
//! runtime's scheduling delay) after it got in. Until then it holds a table slot and discv5 can use
//! it as a lookup seed and answer FINDNODE with it; it can get back in on its next session, for at
//! most one more interval each time. The fix is upstream (`table_filter` on every insertion). The
//! source address of a session is not a table record, so a session from a refused source whose
//! record passes stays in the table (and is not surfaced). These are the discv5 0.12 gaps, all
//! upstream behaviour this crate cannot change, which is why the checks run on the way out and the
//! table is swept, not only `table_filter`:
//!
//! - `Service::inject_session_established` hands the peer of an incoming session to
//!   `Service::connection_updated`, which inserts it into the routing table without calling
//!   `table_filter`. A lookup then seeds from the table (`Service::start_predicate_query` reads
//!   `closest_values_predicate`).
//! - `Service::start_predicate_query` copies every table record into the query's
//!   `untrusted_enrs` but seeds only the closest `num_results`; `Service::discovered` keeps the
//!   first record seen per node, while the predicate runs on the newer record a response
//!   carries; and the finished query returns that first copy. So a lookup can return a stale
//!   record the predicate never passed, and `find_peers` checks the results again.
//! - `Service::discovered` sends `Event::Discovered` (with `report_discovered_peers`, on by
//!   default) before it checks `table_filter`. It inserts nothing itself, but it replaces a
//!   table copy with a newer record that passes `table_filter`, whatever its fork digest.
//! - `table_filter` cannot see the fork digest, so every path above, and `add_enr`, lets a
//!   record on another fork digest in.
//! - The handler's `verify_enr` accepts any source address when the record has no UDP socket
//!   of that address family, so a session's record can pass the IP rules while the session
//!   comes from a loopback or private address.

use crate::enr::{fork_id, CombinedKey, Enr, FieldError, NodeId, DEFAULT_PORT};
use crate::metrics::EvictionMetrics;
use discv5::{ConfigBuilder, Discv5, Event, ListenConfig};
use p2p_wire::rpc::messages::ForkDigest;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;
use tokio::sync::mpsc;

/// Which addresses the routing table accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// A public network: every address a record advertises must be globally routable.
    Public,
    /// A local devnet: loopback and private addresses are accepted too.
    Devnet,
}

/// The `table_filter` for `mode`.
pub fn table_filter(mode: NetworkMode) -> fn(&Enr) -> bool {
    match mode {
        NetworkMode::Public => public_ip_rules,
        NetworkMode::Devnet => devnet_ip_rules,
    }
}

/// At least one address, and every address globally routable.
fn public_ip_rules(enr: &Enr) -> bool {
    every_address(enr, public_ip)
}

/// At least one address, and none that can never be contacted (unspecified, broadcast,
/// multicast).
fn devnet_ip_rules(enr: &Enr) -> bool {
    every_address(enr, devnet_ip)
}

/// The per-address rule of `mode`, shared by the record rules and the session source check.
fn ip_rule(mode: NetworkMode) -> fn(IpAddr) -> bool {
    match mode {
        NetworkMode::Public => public_ip,
        NetworkMode::Devnet => devnet_ip,
    }
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

fn devnet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_contactable_v4(v4),
        IpAddr::V6(v6) => is_contactable_v6(v6),
    }
}

fn every_address(enr: &Enr, rule: fn(IpAddr) -> bool) -> bool {
    let (ip4, ip6) = (enr.ip4(), enr.ip6());
    if ip4.is_none() && ip6.is_none() {
        return false;
    }
    ip4.is_none_or(|ip| rule(ip.into())) && ip6.is_none_or(|ip| rule(ip.into()))
}

fn is_contactable_v4(ip: Ipv4Addr) -> bool {
    // 0.0.0.0/8 is "this network", never a destination.
    !(ip.octets()[0] == 0 || ip.is_broadcast() || ip.is_multicast())
}

/// An IPv4-mapped address is judged as the IPv4 address it maps.
fn is_contactable_v6(ip: Ipv6Addr) -> bool {
    ip.to_ipv4_mapped().map_or_else(
        || !(ip.is_unspecified() || ip.is_multicast()),
        is_contactable_v4,
    )
}

/// Globally reachable IPv4: the exclusions of std's unstable `Ipv4Addr::is_global` (the IANA
/// IPv4 special-purpose address registry), and never multicast.
fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    // 100.64.0.0/10, shared address space (carrier-grade NAT).
    let shared = a == 100 && (b & 0xc0) == 64;
    // 192.0.0.0/24, IETF protocol assignments, except 192.0.0.9 and 192.0.0.10 (PCP and TURN
    // anycast, globally reachable).
    let protocol_assignments = a == 192 && b == 0 && c == 0 && d != 9 && d != 10;
    // 198.18.0.0/15, benchmarking.
    let benchmarking = a == 198 && (b & 0xfe) == 18;
    // 240.0.0.0/4, reserved, and the broadcast address in it.
    let reserved = a >= 240;
    is_contactable_v4(ip)
        && !(ip.is_private()
            || ip.is_loopback()
            || ip.is_link_local()
            || ip.is_documentation()
            || shared
            || protocol_assignments
            || benchmarking
            || reserved)
}

/// Globally reachable IPv6: global unicast (2000::/3) minus the exclusions of std's unstable
/// `Ipv6Addr::is_global` that fall in it, plus the documentation prefix 3fff::/20. Everything
/// else std excludes (unspecified, loopback, IPv4-mapped, 64:ff9b:1::/48, 100::/64, unique
/// local, link local, 5f00::/16, multicast) is outside 2000::/3.
fn is_global_v6(ip: Ipv6Addr) -> bool {
    let bits = u128::from(ip);
    let [s0, s1, s2, ..] = ip.segments();
    let global_unicast = (s0 & 0xe000) == 0x2000;
    // 2001::/23, IETF protocol assignments (Teredo, benchmarking 2001:2::/48, ORCHID, ...),
    // except the parts IANA lists as globally reachable.
    let protocol_assignments = s0 == 0x2001
        && s1 < 0x200
        && !(bits == 0x2001_0001_0000_0000_0000_0000_0000_0001 // 2001:1::1, PCP anycast
            || bits == 0x2001_0001_0000_0000_0000_0000_0000_0002 // 2001:1::2, TURN anycast
            || s1 == 3 // 2001:3::/32, AMT
            || (s1 == 4 && s2 == 0x112) // 2001:4:112::/48, AS112-v6
            || (0x20..=0x3f).contains(&s1)); // 2001:20::/28 ORCHIDv2, 2001:30::/28 DETs
                                             // 2002::/16, 6to4.
    let six_to_four = s0 == 0x2002;
    // 2001:db8::/32 and 3fff::/20, documentation.
    let documentation = (s0 == 0x2001 && s1 == 0x0db8) || (s0 == 0x3fff && s1 < 0x1000);
    global_unicast && !(protocol_assignments || six_to_four || documentation)
}

/// Which records this node reports: on our fork digest and within the IP rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerFilter {
    /// The local fork digest a record's `eth2.fork_digest` must equal.
    pub fork_digest: ForkDigest,
    /// The IP rules every address of the record must pass, the same rules as `table_filter`.
    pub mode: NetworkMode,
}

impl PeerFilter {
    /// True for a record on our fork digest whose addresses pass the IP rules. A record
    /// without a decodable `eth2` is on no fork.
    pub fn accepts(&self, enr: &Enr) -> bool {
        table_filter(self.mode)(enr) && self.on_fork(enr)
    }

    /// True for a record whose `eth2.fork_digest` is ours.
    fn on_fork(&self, enr: &Enr) -> bool {
        fork_id(enr).is_ok_and(|id| id.fork_digest == self.fork_digest)
    }

    /// Why a routing-table record must leave the table, or `None` when it may stay. The IP
    /// rules bind every record; the fork digest binds every record except one the operator
    /// `added` through [`Discovery::add_enr`] (a boot node often carries a stale digest, or
    /// none, and is the table's only seed until the first lookup).
    pub fn eviction_reason(&self, enr: &Enr, added: bool) -> Option<EvictionReason> {
        if !table_filter(self.mode)(enr) {
            Some(EvictionReason::IpRule)
        } else if !added && !self.on_fork(enr) {
            Some(EvictionReason::ForkDigest)
        } else {
            None
        }
    }

    /// The records of `enrs` that [`Self::accepts`], in order.
    pub fn retain(&self, mut enrs: Vec<Enr>) -> Vec<Enr> {
        enrs.retain(|enr| self.accepts(enr));
        enrs
    }

    /// True when a session's source address passes the IP rules (an IPv4-mapped IPv6 source
    /// is judged as its IPv4 address).
    pub fn accepts_source(&self, addr: &SocketAddr) -> bool {
        let ip = match addr.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        };
        ip_rule(self.mode)(ip)
    }
}

/// Why a record was evicted from the routing table: the `reason` label of
/// `discv5_table_evictions_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvictionReason {
    /// An address outside the IP rules of the mode (`table_filter`).
    IpRule,
    /// Another fork digest than ours, or no decodable `eth2`.
    ForkDigest,
}

impl EvictionReason {
    /// Every reason.
    pub const ALL: [Self; 2] = [Self::IpRule, Self::ForkDigest];

    /// The `reason` label value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IpRule => "ip_rule",
            Self::ForkDigest => "fork_digest",
        }
    }
}

/// The sweep's selection: every record of `table` that [`PeerFilter::eviction_reason`] refuses,
/// in order, with its reason. `added` holds the records added through [`Discovery::add_enr`].
pub fn table_evictions(
    filter: &PeerFilter,
    table: &[Enr],
    added: &HashSet<NodeId>,
) -> Vec<(NodeId, EvictionReason)> {
    table
        .iter()
        .filter_map(|enr| {
            let id = enr.node_id();
            filter
                .eviction_reason(enr, added.contains(&id))
                .map(|reason| (id, reason))
        })
        .collect()
}

/// The `find_node_predicate` closure: [`PeerFilter::accepts`].
pub fn fork_predicate(filter: PeerFilter) -> Box<dyn Fn(&Enr) -> bool + Send> {
    Box::new(move |enr| filter.accepts(enr))
}

/// How often [`Discovery`] sweeps its routing table by default: the longest a record that
/// fails the rules and raised no event stays in the table.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Where the service listens, which addresses it accepts and how often it sweeps the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryConfig {
    /// The UDP listen address.
    pub listen_ip: IpAddr,
    /// The UDP listen port.
    pub udp_port: u16,
    /// The IP rules of the routing table.
    pub mode: NetworkMode,
    /// The period of the routing-table sweep ([`SWEEP_INTERVAL`]); never zero.
    pub sweep_interval: Duration,
}

impl DiscoveryConfig {
    /// `listen_ip` on [`DEFAULT_PORT`], swept every [`SWEEP_INTERVAL`].
    pub const fn new(listen_ip: IpAddr, mode: NetworkMode) -> Self {
        Self {
            listen_ip,
            udp_port: DEFAULT_PORT,
            mode,
            sweep_interval: SWEEP_INTERVAL,
        }
    }
}

/// Why the service could not be set up or a request failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    /// The local record has no usable `eth2` field.
    #[error("local ENR: {0}")]
    LocalEnr(FieldError),
    /// discv5 refused the record and key (the key did not sign the record), or the
    /// configuration is unusable (a zero sweep interval).
    #[error("discv5: {0}")]
    Setup(&'static str),
    /// The UDP socket or the service task did not start.
    #[error("discv5 did not start: {0}")]
    Start(String),
    /// The routing table refused a record (IP rules, no UDP socket, bucket full).
    #[error("routing table refused the record: {0}")]
    AddEnr(&'static str),
    /// A lookup did not run to the end.
    #[error("lookup failed: {0}")]
    Query(String),
}

/// What removes records that fail the rules from discv5's routing table: the rules, the
/// records the operator added through [`Discovery::add_enr`], and the eviction counter. The
/// event stream and the sweep task share it.
#[derive(Debug, Clone)]
struct TableGuard {
    filter: PeerFilter,
    /// Exempt from the fork rule, never from the IP rules. Only [`Discovery::add_enr`] grows it.
    added: Arc<Mutex<HashSet<NodeId>>>,
    metrics: EvictionMetrics,
}

impl TableGuard {
    fn new(filter: PeerFilter) -> Self {
        Self {
            filter,
            added: Arc::default(),
            metrics: EvictionMetrics::default(),
        }
    }

    fn added(&self) -> MutexGuard<'_, HashSet<NodeId>> {
        self.added.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Removes `node_id` when its routing-table record fails the rules. The table's own copy is
    /// judged, never the record an event carried: a third party can relay an old record of a
    /// node whose current one conforms.
    fn evict_if_refused(&self, discv5: &Discv5, node_id: &NodeId) -> Option<EvictionReason> {
        let enr = discv5.find_enr(node_id)?;
        let added = self.added().contains(node_id);
        let reason = self.filter.eviction_reason(&enr, added)?;
        self.evict(discv5, node_id, reason).then_some(reason)
    }

    /// One sweep over the whole table ([`table_evictions`]); returns how many records it removed.
    fn sweep(&self, discv5: &Discv5) -> usize {
        let table = discv5.table_entries_enr();
        let evictions = table_evictions(&self.filter, &table, &self.added());
        evictions
            .into_iter()
            .filter(|(node_id, reason)| self.evict(discv5, node_id, *reason))
            .count()
    }

    /// Removes `node_id` and counts it, when it was in the table.
    fn evict(&self, discv5: &Discv5, node_id: &NodeId, reason: EvictionReason) -> bool {
        let removed = discv5.remove_node(node_id);
        if removed {
            self.metrics.record(reason);
            tracing::debug!(
                node = %node_id,
                reason = reason.as_str(),
                "evicted a routing-table record"
            );
        }
        removed
    }
}

/// A running discv5 node whose lookups return only peers on its fork digest.
pub struct Discovery {
    discv5: Arc<Discv5>,
    guard: TableGuard,
    sweep_interval: Duration,
}

impl Discovery {
    /// Sets up discv5 with `enr` (signed by `key`) and the IP rules of `config.mode`. The fork
    /// digest the lookups filter on is the one in `enr`.
    pub fn new(enr: Enr, key: CombinedKey, config: &DiscoveryConfig) -> Result<Self, ServiceError> {
        let fork_digest = fork_id(&enr).map_err(ServiceError::LocalEnr)?.fork_digest;
        if config.sweep_interval.is_zero() {
            return Err(ServiceError::Setup("the table sweep interval is zero"));
        }
        let listen = ListenConfig::from_ip(config.listen_ip, config.udp_port);
        let discv5_config = ConfigBuilder::new(listen)
            .table_filter(table_filter(config.mode))
            .build();
        let discv5 = Discv5::new(enr, key, discv5_config).map_err(ServiceError::Setup)?;
        Ok(Self {
            discv5: Arc::new(discv5),
            guard: TableGuard::new(PeerFilter {
                fork_digest,
                mode: config.mode,
            }),
            sweep_interval: config.sweep_interval,
        })
    }

    /// Counts evictions on `metrics` (registered with [`EvictionMetrics::register`]) instead of
    /// the unregistered default. Call it before [`Self::start`], which hands the counter on.
    #[must_use]
    pub fn with_metrics(mut self, metrics: EvictionMetrics) -> Self {
        self.guard.metrics = metrics;
        self
    }

    /// Binds the UDP socket, starts the service task, opens the event stream and starts the
    /// routing-table sweep, every `sweep_interval` until the service is dropped.
    pub async fn start(&mut self) -> Result<Events, ServiceError> {
        Arc::get_mut(&mut self.discv5)
            .ok_or_else(|| ServiceError::Start("the service is already started".into()))?
            .start()
            .await
            .map_err(|e| ServiceError::Start(e.to_string()))?;
        let rx = self
            .discv5
            .event_stream()
            .await
            .map_err(|e| ServiceError::Start(e.to_string()))?;
        tokio::spawn(sweep_table(
            Arc::downgrade(&self.discv5),
            self.guard.clone(),
            self.sweep_interval,
        ));
        Ok(Events {
            rx,
            discv5: Arc::downgrade(&self.discv5),
            guard: self.guard.clone(),
        })
    }

    /// The fork digest lookups filter on.
    pub fn fork_digest(&self) -> ForkDigest {
        self.guard.filter.fork_digest
    }

    /// The filter every lookup result and reported event passes.
    pub fn filter(&self) -> PeerFilter {
        self.guard.filter
    }

    /// The routing-table eviction counter.
    pub fn metrics(&self) -> &EvictionMetrics {
        &self.guard.metrics
    }

    /// The local record as it is now (discv5 updates `ip`/`udp` from what peers observe).
    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }

    /// Adds a known record (a boot node) to the routing table, subject to the IP rules. The
    /// record stays exempt from the fork rule of the eviction ([`PeerFilter::eviction_reason`]).
    pub fn add_enr(&self, enr: Enr) -> Result<(), ServiceError> {
        let node_id = enr.node_id();
        // Exempt before it is in the table, so a sweep in between cannot evict it.
        let newly_added = self.guard.added().insert(node_id);
        self.discv5.add_enr(enr).map_err(|e| {
            if newly_added {
                self.guard.added().remove(&node_id);
            }
            ServiceError::AddEnr(e)
        })
    }

    /// An iterative lookup towards `target` that returns at most `max_peers` peers, every one
    /// on our fork digest and within the IP rules: the lookup runs [`fork_predicate`], and every
    /// record it returns is checked again ([`PeerFilter::retain`]), because discv5 can return
    /// an older copy of a record than the one the predicate passed.
    pub async fn find_peers(
        &self,
        target: NodeId,
        max_peers: usize,
    ) -> Result<Vec<Enr>, ServiceError> {
        let filter = self.guard.filter;
        self.discv5
            .find_node_predicate(target, fork_predicate(filter), max_peers)
            .await
            .map(|enrs| filter.retain(enrs))
            .map_err(|e| ServiceError::Query(e.to_string()))
    }
}

/// The sweep task: every `period` (first one `period` after the start), [`TableGuard::sweep`]
/// over the whole table. It holds the service weakly and ends once the [`Discovery`] is dropped.
async fn sweep_table(discv5: Weak<Discv5>, guard: TableGuard, period: Duration) {
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let Some(discv5) = discv5.upgrade() else {
            return;
        };
        guard.sweep(&discv5);
    }
}

/// What the service reports about peers on our fork digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    /// A lookup came across this record.
    Discovered(Enr),
    /// A session with this peer was established at this address.
    SessionEstablished(Enr, SocketAddr),
    /// The local record's socket changed to what peers observe.
    SocketUpdated(SocketAddr),
}

impl PeerEvent {
    /// The event to report for `event`: `None` for a peer the filter refuses (another fork
    /// digest, or an address outside the IP rules), for a session whose source address is
    /// outside the IP rules, and for every event nothing here acts on (`Event` is
    /// `#[non_exhaustive]`).
    pub fn classify(event: Event, filter: &PeerFilter) -> Option<Self> {
        match event {
            Event::Discovered(enr) if filter.accepts(&enr) => Some(Self::Discovered(enr)),
            Event::SessionEstablished(enr, addr)
                if filter.accepts(&enr) && filter.accepts_source(&addr) =>
            {
                Some(Self::SessionEstablished(enr, addr))
            }
            Event::SocketUpdated(addr) => Some(Self::SocketUpdated(addr)),
            _ => None,
        }
    }
}

/// The service's event stream, filtered to [`PeerEvent`]s. It holds the service weakly: the
/// [`Discovery`] owns it.
pub struct Events {
    rx: mpsc::Receiver<Event>,
    discv5: Weak<Discv5>,
    guard: TableGuard,
}

impl Events {
    /// The next event to report, or `None` once the service has stopped. Every event that names
    /// a peer (`Discovered`, `SessionEstablished`, `NodeInserted`) first evicts that peer's
    /// routing-table record if it fails the rules, so the stream must be polled for this to run;
    /// the sweep catches what it misses.
    pub async fn next(&mut self) -> Option<PeerEvent> {
        loop {
            let event = self.rx.recv().await?;
            self.evict_named_peer(&event);
            if let Some(event) = PeerEvent::classify(event, &self.guard.filter) {
                return Some(event);
            }
        }
    }

    fn evict_named_peer(&self, event: &Event) {
        let node_id = match event {
            Event::Discovered(enr) | Event::SessionEstablished(enr, _) => enr.node_id(),
            Event::NodeInserted { node_id, .. } => *node_id,
            _ => return,
        };
        if let Some(discv5) = self.discv5.upgrade() {
            self.guard.evict_if_refused(&discv5, &node_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enr::{build_local_enr, CombinedKey, Enr, LocalAddr, NodeId};
    use network_config::{ChainConfig, Network};
    use p2p_wire::enr::{ForkFields, ETH2_KEY};

    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    fn with_ip4(ip: Ipv4Addr) -> Enr {
        let key = CombinedKey::generate_secp256k1();
        Enr::builder().ip4(ip).udp4(9000).build(&key).unwrap()
    }

    fn with_ip6(ip: Ipv6Addr) -> Enr {
        let key = CombinedKey::generate_secp256k1();
        Enr::builder().ip6(ip).udp6(9000).build(&key).unwrap()
    }

    #[test]
    fn table_filter_ip_rules() {
        let public = table_filter(NetworkMode::Public);
        let devnet = table_filter(NetworkMode::Devnet);

        let local_v4 = [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(127, 1, 2, 3),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(172, 31, 255, 254),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
        ];
        let local_v6 = [
            Ipv6Addr::LOCALHOST,
            "fd00::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
            "::ffff:10.0.0.1".parse().unwrap(),
        ];
        for enr in local_v4.map(with_ip4).iter().chain(&local_v6.map(with_ip6)) {
            assert!(
                !public(enr),
                "public mode refuses {:?} {:?}",
                enr.ip4(),
                enr.ip6()
            );
            assert!(
                devnet(enr),
                "devnet mode accepts {:?} {:?}",
                enr.ip4(),
                enr.ip6()
            );
        }

        // Never contactable, in either mode.
        let unusable_v4 = [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ];
        let unusable_v6 = [Ipv6Addr::UNSPECIFIED, "ff02::1".parse().unwrap()];
        for enr in unusable_v4
            .map(with_ip4)
            .iter()
            .chain(&unusable_v6.map(with_ip6))
        {
            assert!(!public(enr), "{:?} {:?}", enr.ip4(), enr.ip6());
            assert!(!devnet(enr), "{:?} {:?}", enr.ip4(), enr.ip6());
        }

        // Not globally routable: documentation, benchmarking, reserved, shared address space.
        let special_v4 = [
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::new(0, 1, 2, 3),
        ];
        let special_v6: [Ipv6Addr; 2] = ["2001:db8::1".parse().unwrap(), "100::1".parse().unwrap()];
        for enr in special_v4
            .map(with_ip4)
            .iter()
            .chain(&special_v6.map(with_ip6))
        {
            assert!(!public(enr), "{:?} {:?}", enr.ip4(), enr.ip6());
        }

        // Globally routable addresses pass both.
        let global = [
            with_ip4(Ipv4Addr::new(8, 8, 8, 8)),
            with_ip4(Ipv4Addr::new(172, 32, 0, 1)),
            with_ip4(Ipv4Addr::new(100, 128, 0, 1)),
            with_ip6("2a00:1450:4001::1".parse().unwrap()),
        ];
        for enr in &global {
            assert!(public(enr), "{:?} {:?}", enr.ip4(), enr.ip6());
            assert!(devnet(enr), "{:?} {:?}", enr.ip4(), enr.ip6());
        }

        // Every advertised address must pass: a global ip4 next to a private ip6 is refused.
        let key = CombinedKey::generate_secp256k1();
        let mixed = Enr::builder()
            .ip4(Ipv4Addr::new(8, 8, 8, 8))
            .ip6("fd00::1".parse().unwrap())
            .udp4(9000)
            .build(&key)
            .unwrap();
        assert!(!public(&mixed));
        assert!(devnet(&mixed));

        // A valid public ip4 never rescues a bad ip6, in public mode.
        for bad in ["::1", "2001:2::1", "2001:db8::1", "3fff::1", "fe80::1"] {
            let paired = Enr::builder()
                .ip4(Ipv4Addr::new(8, 8, 8, 8))
                .ip6(bad.parse().unwrap())
                .udp4(9000)
                .build(&key)
                .unwrap();
            assert!(!public(&paired), "8.8.8.8 with {bad}");
        }

        // A record with no address at all has nothing to check and nothing to contact.
        let bare = Enr::builder().build(&key).unwrap();
        assert!(!public(&bare));
        assert!(!devnet(&bare));
    }

    /// Both sides of every special-purpose IPv4 range (the list of std's unstable
    /// `Ipv4Addr::is_global`).
    #[test]
    fn public_ipv4_range_boundaries() {
        let public = table_filter(NetworkMode::Public);
        let cases: [([u8; 4], bool); 46] = [
            ([0, 255, 255, 255], false),
            ([1, 0, 0, 0], true),
            ([9, 255, 255, 255], true),
            ([10, 0, 0, 0], false),
            ([10, 255, 255, 255], false),
            ([11, 0, 0, 0], true),
            ([100, 63, 255, 255], true),
            ([100, 64, 0, 0], false),
            ([100, 127, 255, 255], false),
            ([100, 128, 0, 0], true),
            ([126, 255, 255, 255], true),
            ([127, 0, 0, 0], false),
            ([127, 255, 255, 255], false),
            ([128, 0, 0, 0], true),
            ([169, 253, 255, 255], true),
            ([169, 254, 0, 0], false),
            ([169, 254, 255, 255], false),
            ([169, 255, 0, 0], true),
            ([172, 15, 255, 255], true),
            ([172, 16, 0, 0], false),
            ([172, 31, 255, 255], false),
            ([172, 32, 0, 0], true),
            ([191, 255, 255, 255], true),
            ([192, 0, 0, 0], false),
            ([192, 0, 0, 8], false),
            ([192, 0, 0, 9], true),
            ([192, 0, 0, 10], true),
            ([192, 0, 0, 11], false),
            ([192, 0, 0, 255], false),
            ([192, 0, 1, 0], true),
            ([192, 0, 2, 255], false),
            ([192, 0, 3, 0], true),
            ([192, 167, 255, 255], true),
            ([192, 168, 0, 0], false),
            ([192, 168, 255, 255], false),
            ([192, 169, 0, 0], true),
            ([198, 17, 255, 255], true),
            ([198, 18, 0, 0], false),
            ([198, 19, 255, 255], false),
            ([198, 20, 0, 0], true),
            ([198, 51, 100, 255], false),
            ([203, 0, 113, 255], false),
            ([203, 0, 114, 0], true),
            ([223, 255, 255, 255], true),
            ([224, 0, 0, 0], false),
            ([240, 0, 0, 0], false),
        ];
        for (octets, global) in cases {
            let ip = Ipv4Addr::from(octets);
            assert_eq!(public(&with_ip4(ip)), global, "{ip}");
        }
        assert!(!public(&with_ip4(Ipv4Addr::BROADCAST)));
    }

    /// Both sides of every special-purpose IPv6 range (the list of std's unstable
    /// `Ipv6Addr::is_global`, with 3fff::/20, inside global unicast 2000::/3).
    #[test]
    fn public_ipv6_range_boundaries() {
        let public = table_filter(NetworkMode::Public);
        let cases = [
            // Outside global unicast 2000::/3.
            ("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2000::", true),
            ("4000::1", false),
            ("::ffff:8.8.8.8", false),
            ("64:ff9b:1::1", false),
            ("100::1", false),
            // IETF protocol assignments 2001::/23, with its globally reachable exceptions.
            ("2001::1", false),
            ("2001:1::1", true),
            ("2001:1::2", true),
            ("2001:1::3", false),
            ("2001:2::1", false),
            ("2001:2:0:ffff::1", false),
            ("2001:3::1", true),
            ("2001:3:ffff::1", true),
            ("2001:4:111::1", false),
            ("2001:4:112::1", true),
            ("2001:4:112:ffff::1", true),
            ("2001:4:113::1", false),
            ("2001:10::1", false),
            ("2001:1f:ffff::1", false),
            ("2001:20::1", true),
            ("2001:3f:ffff::1", true),
            ("2001:40::1", false),
            ("2001:1ff:ffff::1", false),
            ("2001:200::", true),
            // Documentation 2001:db8::/32 and 3fff::/20.
            ("2001:db7:ffff::1", true),
            ("2001:db8::", false),
            ("2001:db8:ffff::1", false),
            ("2001:db9::", true),
            ("3ffe:ffff::1", true),
            ("3fff::", false),
            ("3fff:fff:ffff::1", false),
            ("3fff:1000::", true),
            // 6to4 2002::/16.
            ("2001:ffff::1", true),
            ("2002::1", false),
            ("2002:ffff::1", false),
            ("2003::", true),
        ];
        for (ip, global) in cases {
            let parsed: Ipv6Addr = ip.parse().unwrap();
            assert_eq!(public(&with_ip6(parsed)), global, "{ip}");
        }
    }

    fn sepolia_fields(epoch: u64) -> ForkFields {
        let config = ChainConfig::load(Network::Sepolia).unwrap();
        let gvr = Network::Sepolia.genesis().unwrap().genesis_validators_root;
        ForkFields::from_schedule(&config, &gvr, epoch).unwrap()
    }

    /// A loopback UDP port nothing listens on right now.
    fn free_udp_port() -> u16 {
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// A started devnet node on loopback with the given fork fields.
    async fn node(fork: &ForkFields) -> (Discovery, Events) {
        node_in(fork, NetworkMode::Devnet).await
    }

    /// A started node on loopback with the given fork fields and IP rules.
    async fn node_in(fork: &ForkFields, mode: NetworkMode) -> (Discovery, Events) {
        node_with(fork, mode, SWEEP_INTERVAL).await
    }

    /// Long enough that no sweep runs during a test: only the event stream evicts.
    const NO_SWEEP: Duration = Duration::from_secs(3600);

    /// A started node on loopback with the given fork fields, IP rules and sweep interval.
    async fn node_with(
        fork: &ForkFields,
        mode: NetworkMode,
        sweep_interval: Duration,
    ) -> (Discovery, Events) {
        let key = CombinedKey::generate_secp256k1();
        let port = free_udp_port();
        let addr = LocalAddr {
            ip: Ipv4Addr::LOCALHOST,
            tcp_port: port,
            udp_port: port,
        };
        let enr = build_local_enr(&key, fork, 4, &addr).unwrap();
        let config = DiscoveryConfig {
            listen_ip: Ipv4Addr::LOCALHOST.into(),
            udp_port: port,
            mode,
            sweep_interval,
        };
        let mut discovery = Discovery::new(enr, key, &config).unwrap();
        let events = discovery.start().await.unwrap();
        (discovery, events)
    }

    fn ids(enrs: &[Enr]) -> HashSet<NodeId> {
        enrs.iter().map(Enr::node_id).collect()
    }

    /// discv5 0.12 inserts the peer of an incoming session into the routing table without its
    /// `table_filter`. A loopback peer on our fork digest that dials a public-mode node must
    /// never come out of a lookup or the event stream, and its event evicts it from the table.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn public_mode_evicts_a_refused_incoming_peer_on_its_event() {
        let ours = sepolia_fields(274_175);
        let (public, mut public_events) = node_with(&ours, NetworkMode::Public, NO_SWEEP).await;
        let (peer, _peer_events) = node(&ours).await;
        let peer_id = peer.local_enr().node_id();

        // The loopback peer looks the public node up, which opens an incoming session there.
        peer.add_enr(public.local_enr()).unwrap();
        let found = ids(&peer.find_peers(NodeId::random(), 16).await.unwrap());
        assert!(found.contains(&public.local_enr().node_id()), "{found:?}");
        // The precondition the test rests on: the session put the peer in the public node's
        // table, past the IP rules.
        assert!(
            public.discv5.table_entries_id().contains(&peer_id),
            "the incoming peer is in the routing table"
        );
        // The control: an unfiltered lookup returns it, so only the filter keeps it out of
        // `find_peers` below.
        let unfiltered = ids(&public.discv5.find_node(peer_id).await.unwrap());
        assert!(unfiltered.contains(&peer_id), "{unfiltered:?}");

        let found = ids(&public.find_peers(NodeId::random(), 16).await.unwrap());
        assert!(!found.contains(&peer_id), "{found:?}");
        let found = ids(&public.find_peers(peer_id, 16).await.unwrap());
        assert!(!found.contains(&peer_id), "{found:?}");

        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_millis(500), public_events.next()).await
        {
            if let PeerEvent::Discovered(enr) | PeerEvent::SessionEstablished(enr, _) = event {
                assert_ne!(enr.node_id(), peer_id, "{enr}");
            }
        }
        // The session's event evicted it, with no sweep.
        assert!(!public.discv5.table_entries_id().contains(&peer_id));
        assert_eq!(public.metrics().evictions(EvictionReason::IpRule), 1);
        assert_eq!(public.metrics().evictions(EvictionReason::ForkDigest), 0);
    }

    /// The loopback peer that dials `node` and looks it up, which opens an incoming session
    /// there. Returns the peer, its event stream and its id.
    async fn dial(node: &Discovery, fork: &ForkFields) -> (Discovery, Events, NodeId) {
        let (peer, peer_events) = node_in(fork, NetworkMode::Devnet).await;
        let peer_id = peer.local_enr().node_id();
        peer.add_enr(node.local_enr()).unwrap();
        // Unfiltered: a peer on another fork must still reach `node`.
        let found = ids(&peer.discv5.find_node(NodeId::random()).await.unwrap());
        assert!(found.contains(&node.local_enr().node_id()), "{found:?}");
        (peer, peer_events, peer_id)
    }

    /// Devnet mode is unchanged: the loopback peer that dials us is reported and stays in the
    /// table past several sweeps.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn devnet_mode_keeps_a_loopback_incoming_peer() {
        let ours = sepolia_fields(274_175);
        let sweep = Duration::from_millis(300);
        let (devnet, mut devnet_events) = node_with(&ours, NetworkMode::Devnet, sweep).await;
        let (_peer, _peer_events, peer_id) = dial(&devnet, &ours).await;

        let mut reported = false;
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_millis(500), devnet_events.next()).await
        {
            if let PeerEvent::SessionEstablished(enr, _) = event {
                reported |= enr.node_id() == peer_id;
            }
        }
        assert!(reported, "the session with the loopback peer is reported");
        tokio::time::sleep(sweep * 3).await;
        assert!(devnet.discv5.table_entries_id().contains(&peer_id));
        for reason in EvictionReason::ALL {
            assert_eq!(devnet.metrics().evictions(reason), 0, "{reason:?}");
        }
        let found = ids(&devnet.find_peers(peer_id, 16).await.unwrap());
        assert!(found.contains(&peer_id), "{found:?}");
    }

    /// A peer on another fork digest gets in the same way (`table_filter` holds the IP rules
    /// only), so it is evicted for its digest; an off-fork record the operator added (a boot
    /// node) stays.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_off_fork_incoming_peer_is_evicted_and_an_added_one_kept() {
        let ours = sepolia_fields(274_175);
        let other = sepolia_fields(274_176);
        let sweep = Duration::from_millis(300);
        let (node, _unpolled) = node_with(&ours, NetworkMode::Devnet, sweep).await;
        let (boot, _boot_events) = node_in(&other, NetworkMode::Devnet).await;
        let boot_id = boot.local_enr().node_id();
        node.add_enr(boot.local_enr()).unwrap();
        let (_peer, _peer_events, peer_id) = dial(&node, &other).await;

        wait_evicted(&node, &peer_id, sweep * 5).await;
        assert_eq!(node.metrics().evictions(EvictionReason::ForkDigest), 1);
        assert_eq!(node.metrics().evictions(EvictionReason::IpRule), 0);
        tokio::time::sleep(sweep * 2).await;
        assert!(node.discv5.table_entries_id().contains(&boot_id));
        assert_eq!(node.metrics().evictions(EvictionReason::ForkDigest), 1);
    }

    /// The event stream and the sweep hold the service weakly: dropping the [`Discovery`]
    /// stops it, and the stream ends.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_service_ends_its_events() {
        let ours = sepolia_fields(274_175);
        let (node, mut events) =
            node_with(&ours, NetworkMode::Devnet, Duration::from_millis(50)).await;
        drop(node);
        let end = tokio::time::timeout(Duration::from_secs(5), events.next()).await;
        assert_eq!(end, Ok(None));
    }

    /// Waits until `id` is out of `node`'s routing table, at most `limit`.
    async fn wait_evicted(node: &Discovery, id: &NodeId, limit: Duration) {
        let deadline = tokio::time::Instant::now() + limit;
        while node.discv5.table_entries_id().contains(id) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{id} still in the routing table after {limit:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The backstop: with the event stream never polled, the sweep alone evicts the refused
    /// incoming peer within an interval, and counts it (so it was in the table).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn public_mode_sweeps_a_refused_incoming_peer_out() {
        let ours = sepolia_fields(274_175);
        let sweep = Duration::from_millis(300);
        let (public, _unpolled) = node_with(&ours, NetworkMode::Public, sweep).await;
        let (_peer, _peer_events, peer_id) = dial(&public, &ours).await;

        // One interval, plus slack for a loaded test machine.
        wait_evicted(&public, &peer_id, sweep * 5).await;
        assert_eq!(public.metrics().evictions(EvictionReason::IpRule), 1);
        assert_eq!(public.metrics().evictions(EvictionReason::ForkDigest), 0);
        let found = ids(&public.find_peers(peer_id, 16).await.unwrap());
        assert!(!found.contains(&peer_id), "{found:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn predicate_filters_digest() {
        // One epoch before the BPO fork at 274176: `ours` is on the Fulu digest, `other` has
        // already moved to the BPO digest, `nfd_only` differs from us only in `nfd`.
        let ours = sepolia_fields(274_175);
        let other = sepolia_fields(274_176);
        assert_ne!(ours.eth2.fork_digest, other.eth2.fork_digest);
        let nfd_only = ForkFields {
            nfd: [0xaa; 4],
            ..ours
        };
        assert_ne!(nfd_only.nfd, ours.nfd);

        let (a, mut a_events) = node(&ours).await;
        let (b, _b_events) = node(&ours).await;
        let (c, _c_events) = node(&other).await;
        let (d, _d_events) = node(&nfd_only).await;
        assert_eq!(a.fork_digest(), ours.eth2.fork_digest);
        let (b_id, c_id, d_id) = (
            b.local_enr().node_id(),
            c.local_enr().node_id(),
            d.local_enr().node_id(),
        );

        // `a` knows only `b`; `b` hands out `c` and `d`. A lookup for `c` reaches `c` through
        // `b` and still never returns it; a lookup for `d` returns `d`.
        a.add_enr(b.local_enr()).unwrap();
        b.add_enr(c.local_enr()).unwrap();
        b.add_enr(d.local_enr()).unwrap();
        // The control: without the filter the same lookup does return `c`, so only the filter
        // keeps it out of `find_peers` below.
        let unfiltered = ids(&a.discv5.find_node(c_id).await.unwrap());
        assert!(unfiltered.contains(&c_id), "{unfiltered:?}");
        let found = ids(&a.find_peers(c_id, 16).await.unwrap());
        assert!(found.contains(&b_id), "{found:?}");
        assert!(!found.contains(&c_id), "{found:?}");
        let found = ids(&a.find_peers(d_id, 16).await.unwrap());
        assert!(found.contains(&d_id), "{found:?}");
        assert!(!found.contains(&c_id), "{found:?}");

        // In `a`'s own table `c` is still never returned, whatever the target.
        a.add_enr(c.local_enr()).unwrap();
        a.add_enr(d.local_enr()).unwrap();
        // The control: `c` is in the unfiltered table and an unfiltered lookup returns it.
        assert!(a.discv5.table_entries_id().contains(&c_id));
        let unfiltered = ids(&a.discv5.find_node(NodeId::random()).await.unwrap());
        assert!(unfiltered.contains(&c_id), "{unfiltered:?}");
        let found = ids(&a.find_peers(NodeId::random(), 16).await.unwrap());
        assert_eq!(found, HashSet::from([b_id, d_id]));

        // The event stream never reports `c` either, and does report a session with `b`.
        let mut seen = HashSet::new();
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_millis(500), a_events.next()).await
        {
            match event {
                PeerEvent::Discovered(enr) | PeerEvent::SessionEstablished(enr, _) => {
                    assert_ne!(enr.node_id(), c_id, "{enr}");
                    seen.insert(enr.node_id());
                }
                PeerEvent::SocketUpdated(_) => {}
            }
        }
        assert!(seen.contains(&b_id), "{seen:?}");
    }

    /// discv5 0.12 returns the first record it saw for a node, which can be the stale table
    /// copy rather than the newer one the predicate passed. `find_peers` checks every result
    /// again, so the stale off-fork copy is dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn find_peers_checks_every_result_again() {
        let ours = sepolia_fields(274_175);
        let other = sepolia_fields(274_176);
        let (a, _a_events) = node(&ours).await;
        let (x, _x_events) = node(&other).await;
        // `b` runs on our fork (`fresh`); `a` holds an older off-fork copy of its record.
        let b_key = CombinedKey::generate_secp256k1();
        let port = free_udp_port();
        let b_addr = LocalAddr {
            ip: Ipv4Addr::LOCALHOST,
            tcp_port: port,
            udp_port: port,
        };
        let b_enr = build_local_enr(&b_key, &ours, 4, &b_addr).unwrap();
        let mut stale = b_enr.clone();
        stale
            .insert(
                ETH2_KEY,
                &alloy_rlp::Bytes::from(other.eth2.to_bytes().to_vec()),
                &b_key,
            )
            .unwrap();
        // The stale copy must look older to `a`'s query than the one `x` hands out.
        let fresh = {
            let mut fresh = stale.clone();
            fresh
                .insert(
                    ETH2_KEY,
                    &alloy_rlp::Bytes::from(ours.eth2.to_bytes().to_vec()),
                    &b_key,
                )
                .unwrap();
            fresh
        };
        assert!(fresh.seq() > stale.seq());
        let b_config = DiscoveryConfig {
            udp_port: port,
            ..DiscoveryConfig::new(Ipv4Addr::LOCALHOST.into(), NetworkMode::Devnet)
        };
        let mut b = Discovery::new(fresh.clone(), b_key, &b_config).unwrap();
        let _b_events = b.start().await.unwrap();

        // A target `x` is strictly closer to than `b`, at a distance whose FINDNODE to `x`
        // covers log2(x, b): the lookup seeds `x` alone (max_peers = 1) and learns the fresh
        // `b` from it.
        let (x_raw, b_raw) = (x.local_enr().node_id().raw(), fresh.node_id().raw());
        let xor: [u8; 32] = std::array::from_fn(|i| x_raw[i] ^ b_raw[i]);
        let first = xor.iter().position(|&byte| byte != 0).unwrap();
        let k = 256 - (first * 8 + xor[first].leading_zeros() as usize);
        assert!(k >= 2, "log2 distance {k}");
        let bit = k - 2;
        let mut target = x_raw;
        target[31 - bit / 8] ^= 1 << (bit % 8);
        let target = NodeId::new(&target);

        a.add_enr(x.local_enr()).unwrap();
        a.add_enr(stale.clone()).unwrap();
        x.add_enr(fresh.clone()).unwrap();
        let found = a.find_peers(target, 1).await.unwrap();
        let filter = a.filter();
        for enr in &found {
            assert!(filter.accepts(enr), "{enr}");
        }
        drop(b);
    }

    #[test]
    fn retain_drops_every_record_the_filter_refuses() {
        let ours = sepolia_fields(274_175);
        let other = sepolia_fields(274_176);
        let key = CombinedKey::generate_secp256k1();
        let public_on =
            build_local_enr(&key, &ours, 4, &LocalAddr::new(Ipv4Addr::new(8, 8, 8, 8))).unwrap();
        let public_off =
            build_local_enr(&key, &other, 4, &LocalAddr::new(Ipv4Addr::new(8, 8, 4, 4))).unwrap();
        let loopback_on =
            build_local_enr(&key, &ours, 4, &LocalAddr::new(Ipv4Addr::LOCALHOST)).unwrap();
        let results = vec![public_off, loopback_on.clone(), public_on.clone()];
        let filter = PeerFilter {
            fork_digest: ours.eth2.fork_digest,
            mode: NetworkMode::Public,
        };
        assert_eq!(filter.retain(results.clone()), vec![public_on.clone()]);
        let devnet = PeerFilter {
            mode: NetworkMode::Devnet,
            ..filter
        };
        assert_eq!(devnet.retain(results), vec![loopback_on, public_on]);
    }

    /// The sweep's selection: every table record that fails the IP rules, or that is on
    /// another fork digest (or none) and was not added through `add_enr`, with its reason.
    #[test]
    fn sweep_selects_every_record_the_rules_refuse() {
        let ours = sepolia_fields(274_175);
        let other = sepolia_fields(274_176);
        let record = |fork: &ForkFields, ip: Ipv4Addr| {
            let key = CombinedKey::generate_secp256k1();
            build_local_enr(&key, fork, 4, &LocalAddr::new(ip)).unwrap()
        };
        let public_on = record(&ours, Ipv4Addr::new(8, 8, 8, 8));
        let public_off = record(&other, Ipv4Addr::new(8, 8, 4, 4));
        let added_off = record(&other, Ipv4Addr::new(1, 1, 1, 1));
        let loopback_on = record(&ours, Ipv4Addr::LOCALHOST);
        let private_on = record(&ours, Ipv4Addr::new(10, 0, 0, 1));
        let added_private = record(&ours, Ipv4Addr::new(192, 168, 1, 1));
        let key = CombinedKey::generate_secp256k1();
        let no_eth2 = Enr::builder()
            .ip4(Ipv4Addr::new(9, 9, 9, 9))
            .udp4(9000)
            .build(&key)
            .unwrap();
        let table = vec![
            public_on.clone(),
            public_off.clone(),
            added_off.clone(),
            loopback_on.clone(),
            private_on.clone(),
            added_private.clone(),
            no_eth2.clone(),
        ];
        let added = HashSet::from([added_off.node_id(), added_private.node_id()]);
        let public = PeerFilter {
            fork_digest: ours.eth2.fork_digest,
            mode: NetworkMode::Public,
        };
        assert_eq!(
            table_evictions(&public, &table, &added),
            vec![
                (public_off.node_id(), EvictionReason::ForkDigest),
                (loopback_on.node_id(), EvictionReason::IpRule),
                (private_on.node_id(), EvictionReason::IpRule),
                // A record added through `add_enr` is kept off-fork, never outside the IP rules.
                (added_private.node_id(), EvictionReason::IpRule),
                (no_eth2.node_id(), EvictionReason::ForkDigest),
            ]
        );

        // Devnet mode keeps loopback and private records; the fork rule is the same.
        let devnet = PeerFilter {
            mode: NetworkMode::Devnet,
            ..public
        };
        assert_eq!(
            table_evictions(&devnet, &table, &added),
            vec![
                (public_off.node_id(), EvictionReason::ForkDigest),
                (no_eth2.node_id(), EvictionReason::ForkDigest),
            ]
        );
        assert_eq!(table_evictions(&devnet, &[], &added), vec![]);
        // Never contactable, in either mode.
        let broadcast = record(&ours, Ipv4Addr::BROADCAST);
        assert_eq!(
            devnet.eviction_reason(&broadcast, false),
            Some(EvictionReason::IpRule)
        );
        assert_eq!(devnet.eviction_reason(&public_on, false), None);
    }

    /// A handshake from an address the record does not advertise (discv5 accepts any source
    /// when the record has no UDP socket of that family): the source must pass the IP rules too.
    #[test]
    fn sessions_from_refused_source_addresses_are_dropped() {
        let ours = sepolia_fields(274_175);
        let key = CombinedKey::generate_secp256k1();
        let enr = Enr::builder()
            .ip4(Ipv4Addr::new(8, 8, 8, 8))
            .add_value(
                ETH2_KEY,
                &alloy_rlp::Bytes::from(ours.eth2.to_bytes().to_vec()),
            )
            .build(&key)
            .unwrap();
        let public = PeerFilter {
            fork_digest: ours.eth2.fork_digest,
            mode: NetworkMode::Public,
        };
        let devnet = PeerFilter {
            mode: NetworkMode::Devnet,
            ..public
        };
        assert!(public.accepts(&enr));
        let session = |addr: &str| {
            let addr: SocketAddr = addr.parse().unwrap();
            (Event::SessionEstablished(enr.clone(), addr), addr)
        };
        let refused = [
            "127.0.0.1:9000",
            "10.0.0.1:9000",
            "192.168.1.1:9000",
            "[::1]:9000",
            "[fd00::1]:9000",
            "[fe80::1]:9000",
            "[::ffff:127.0.0.1]:9000",
            "[::ffff:10.0.0.1]:9000",
        ];
        for addr in refused {
            let (event, _) = session(addr);
            assert_eq!(PeerEvent::classify(event, &public), None, "{addr}");
            let (event, socket) = session(addr);
            assert_eq!(
                PeerEvent::classify(event, &devnet),
                Some(PeerEvent::SessionEstablished(enr.clone(), socket)),
                "{addr}"
            );
        }
        for addr in [
            "8.8.8.8:9000",
            "[2a00:1450:4001::1]:9000",
            "[::ffff:8.8.8.8]:9000",
        ] {
            let (event, socket) = session(addr);
            assert_eq!(
                PeerEvent::classify(event, &public),
                Some(PeerEvent::SessionEstablished(enr.clone(), socket)),
                "{addr}"
            );
        }
    }

    #[test]
    fn events_report_only_our_fork() {
        let ours = sepolia_fields(274_175);
        let other = sepolia_fields(274_176);
        let key = CombinedKey::generate_secp256k1();
        let addr = LocalAddr::new(Ipv4Addr::LOCALHOST);
        let on = build_local_enr(&key, &ours, 4, &addr).unwrap();
        let off = build_local_enr(&key, &other, 4, &addr).unwrap();
        let socket: SocketAddr = (Ipv4Addr::LOCALHOST, 9000).into();
        let filter = PeerFilter {
            fork_digest: ours.eth2.fork_digest,
            mode: NetworkMode::Devnet,
        };
        let classify = |event| PeerEvent::classify(event, &filter);

        assert_eq!(
            classify(Event::Discovered(on.clone())),
            Some(PeerEvent::Discovered(on.clone()))
        );
        assert_eq!(
            classify(Event::SessionEstablished(on.clone(), socket)),
            Some(PeerEvent::SessionEstablished(on.clone(), socket))
        );
        assert_eq!(
            classify(Event::SocketUpdated(socket)),
            Some(PeerEvent::SocketUpdated(socket))
        );
        assert_eq!(classify(Event::Discovered(off.clone())), None);
        assert_eq!(classify(Event::SessionEstablished(off, socket)), None);
        // A record without eth2 is on no fork.
        let bare = Enr::builder().ip4(Ipv4Addr::LOCALHOST).build(&key).unwrap();
        assert_eq!(classify(Event::Discovered(bare)), None);
        // Events nothing here acts on.
        assert_eq!(
            classify(Event::NodeInserted {
                node_id: on.node_id(),
                replaced: None
            }),
            None
        );
        assert_eq!(classify(Event::SessionsExpired(Vec::new())), None);

        // Public mode: a loopback record on our digest is never surfaced, whichever event
        // carries it.
        let public = PeerFilter {
            mode: NetworkMode::Public,
            ..filter
        };
        assert!(!public.accepts(&on));
        assert_eq!(
            PeerEvent::classify(Event::Discovered(on.clone()), &public),
            None
        );
        assert_eq!(
            PeerEvent::classify(Event::SessionEstablished(on, socket), &public),
            None
        );
    }

    #[tokio::test]
    async fn service_errors() {
        let fields = sepolia_fields(300_000);
        let key = CombinedKey::generate_secp256k1();
        let port = free_udp_port();
        let addr = LocalAddr {
            ip: Ipv4Addr::LOCALHOST,
            tcp_port: port,
            udp_port: port,
        };
        let enr = build_local_enr(&key, &fields, 4, &addr).unwrap();
        let config = DiscoveryConfig {
            udp_port: port,
            ..DiscoveryConfig::new(Ipv4Addr::LOCALHOST.into(), NetworkMode::Public)
        };
        assert_eq!(
            DiscoveryConfig::new(Ipv4Addr::LOCALHOST.into(), NetworkMode::Public).udp_port,
            9000
        );

        // A local record without eth2, and a key that did not sign the record.
        let bare_key = CombinedKey::generate_secp256k1();
        let bare = Enr::builder()
            .ip4(Ipv4Addr::LOCALHOST)
            .build(&bare_key)
            .unwrap();
        let err = Discovery::new(bare, bare_key, &config).err();
        assert_eq!(err, Some(ServiceError::LocalEnr(FieldError::NoEth2)));
        let stranger = CombinedKey::generate_secp256k1();
        let err = Discovery::new(enr.clone(), stranger, &config).err();
        assert!(matches!(err, Some(ServiceError::Setup(_))), "{err:?}");

        let mut discovery = Discovery::new(enr, key, &config).unwrap();
        // Not started: no lookup.
        let err = discovery.find_peers(NodeId::random(), 1).await;
        assert!(matches!(err, Err(ServiceError::Query(_))), "{err:?}");
        let _events = discovery.start().await.unwrap();
        let err = discovery.start().await.err();
        assert!(matches!(err, Some(ServiceError::Start(_))), "{err:?}");

        // A sweep interval of zero is refused.
        let zero = DiscoveryConfig {
            sweep_interval: Duration::ZERO,
            ..config
        };
        let err = Discovery::new(
            discovery.local_enr(),
            CombinedKey::generate_secp256k1(),
            &zero,
        )
        .err();
        assert_eq!(
            err,
            Some(ServiceError::Setup("the table sweep interval is zero"))
        );

        // Public mode: a loopback record never enters the routing table.
        let peer_key = CombinedKey::generate_secp256k1();
        let peer =
            build_local_enr(&peer_key, &fields, 4, &LocalAddr::new(Ipv4Addr::LOCALHOST)).unwrap();
        let err = discovery.add_enr(peer).err();
        assert!(matches!(err, Some(ServiceError::AddEnr(_))), "{err:?}");
        // An empty table: the lookup ends with nothing.
        assert_eq!(discovery.find_peers(NodeId::random(), 4).await, Ok(vec![]));
    }
}
