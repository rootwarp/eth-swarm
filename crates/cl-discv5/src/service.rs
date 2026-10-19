//! The discv5 service: the local record, the routing-table IP rules and fork-filtered lookups.
//!
//! - **IP rules** ([`table_filter`]): discv5's `table_filter` is a bare `fn(&Enr) -> bool`, so
//!   it can hold no state and carries the IP rules only, one function per [`NetworkMode`].
//!   discv5 applies it when a lookup or [`Discovery::add_enr`] would add a record to the
//!   routing table.
//! - **Fork filter** ([`PeerFilter`]): our fork digest and the IP rules together. The digest is
//!   read from the local record each time ([`Discovery::filter`]), so it follows a local-record
//!   update at a fork or BPO boundary. It is the
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
//!   polled event reported. Both judge and remove under one write lock of the routing table
//!   (`Discv5::with_kbuckets`), on the entry the table holds then, and count
//!   `discv5_table_evictions_total{reason}` ([`crate::metrics`]) under it. A record added
//!   through [`Discovery::add_enr`] (a boot node) is exempt from the fork rule, never from the
//!   IP rules. A pending entry (a full bucket's candidate) is out of reach: discv5 0.12 can show
//!   it but not clear it, so it is judged once promoted.
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

use crate::enr::{fork_id, value_eq, CombinedKey, Enr, FieldError, NodeId, DEFAULT_PORT};
use crate::metrics::EvictionMetrics;
use alloy_rlp::Bytes;
use discv5::kbucket::{Entry, KBucketsTable, Key};
use discv5::{ConfigBuilder, Discv5, Event, ListenConfig};
use p2p_wire::enr::{encode_cgc, CGC_KEY};
use p2p_wire::rpc::messages::ForkDigest;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

/// Which addresses the routing table accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// A public network: every address a record advertises must be globally routable.
    Public,
    /// A local devnet: loopback and private addresses are accepted too.
    Devnet,
    /// Local addresses only ([`is_local_ip`]): loopback, private, link-local, CGNAT and IPv6
    /// unique-local. For a probe on a devnet's own network (a Docker bridge), which must send
    /// nothing to a public host whatever a peer hands it.
    Local,
}

/// The `table_filter` for `mode`.
pub fn table_filter(mode: NetworkMode) -> fn(&Enr) -> bool {
    match mode {
        NetworkMode::Public => public_ip_rules,
        NetworkMode::Devnet => devnet_ip_rules,
        NetworkMode::Local => local_ip_rules,
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

/// At least one address, and every address local ([`is_local_ip`]).
fn local_ip_rules(enr: &Enr) -> bool {
    every_address(enr, is_local_ip)
}

/// The per-address rule of `mode`, shared by the record rules and the session source check.
fn ip_rule(mode: NetworkMode) -> fn(IpAddr) -> bool {
    match mode {
        NetworkMode::Public => public_ip,
        NetworkMode::Devnet => devnet_ip,
        NetworkMode::Local => is_local_ip,
    }
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

/// A local address: IPv4 loopback (127/8), private (10/8, 172.16/12, 192.168/16), link-local
/// (169.254/16) or shared CGNAT space (100.64/10); IPv6 loopback, unique-local (fc00::/7) or
/// link-local (fe80::/10). An IPv4-mapped address is judged as its IPv4 address.
#[must_use]
pub fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            let cgnat = a == 100 && (b & 0xc0) == 64;
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || cgnat
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_local_ip(IpAddr::V4(v4)),
            None => {
                let first = v6.segments()[0];
                v6.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
            }
        },
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
pub fn table_evictions<'a>(
    filter: &PeerFilter,
    table: impl IntoIterator<Item = &'a Enr>,
    added: &HashSet<NodeId>,
) -> Vec<(NodeId, EvictionReason)> {
    table
        .into_iter()
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
    /// discv5 refused the updated local record (over 300 bytes, or signing failed).
    #[error("local ENR update refused: {0}")]
    UpdateEnr(String),
}

/// What removes records that fail the rules from discv5's routing table: the IP rules, the
/// local record's fork digest, the records the operator added through [`Discovery::add_enr`],
/// and the eviction counter. The event stream and the sweep task share it.
///
/// **Locks.** A judgement and its removal run under one write lock of the routing table
/// (`Discv5::with_kbuckets`), on the entry the table holds then, so a newer record that lands
/// meanwhile is never removed for what an older one carried; the counter moves under the same
/// lock, before anyone else can see the removal. (`Discv5::remove_node` takes that lock itself,
/// so it would deadlock under it; the removal goes through the locked table instead.) The
/// exemptions are locked before the table and held across
/// the judgement, and [`Discovery::add_enr`] holds them across its insertion and rollback, so an
/// exemption never changes under a judgement. Lock order: the local record (read and released
/// first), the exemptions, the table.
#[derive(Debug, Clone)]
struct TableGuard {
    mode: NetworkMode,
    /// The fork digest of the local record when it was last read (big-endian), the fork rule
    /// for when the local record has none it can decode.
    fork_digest: Arc<AtomicU32>,
    /// Exempt from the fork rule, never from the IP rules. Only [`Discovery::add_enr`] grows it.
    added: Arc<Mutex<HashSet<NodeId>>>,
    metrics: EvictionMetrics,
}

impl TableGuard {
    fn new(mode: NetworkMode, fork_digest: ForkDigest) -> Self {
        Self {
            mode,
            fork_digest: Arc::new(AtomicU32::new(u32::from_be_bytes(fork_digest))),
            added: Arc::default(),
            metrics: EvictionMetrics::default(),
        }
    }

    fn added(&self) -> MutexGuard<'_, HashSet<NodeId>> {
        self.added.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The filter of the local record as it is now: its fork digest follows a local-record
    /// update (a fork or BPO boundary). A local record without a decodable `eth2` keeps the
    /// digest last read.
    fn filter(&self, discv5: &Discv5) -> PeerFilter {
        let fork_digest = match fork_id(&discv5.local_enr()) {
            Ok(id) => {
                self.fork_digest
                    .store(u32::from_be_bytes(id.fork_digest), Ordering::Relaxed);
                id.fork_digest
            }
            Err(error) => {
                tracing::warn!(%error, "local ENR: the fork rule keeps the last fork digest");
                self.last_fork_digest()
            }
        };
        PeerFilter {
            fork_digest,
            mode: self.mode,
        }
    }

    /// The filter as of the last read of the local record, for when the service is gone.
    fn last_filter(&self) -> PeerFilter {
        PeerFilter {
            fork_digest: self.last_fork_digest(),
            mode: self.mode,
        }
    }

    fn last_fork_digest(&self) -> ForkDigest {
        self.fork_digest.load(Ordering::Relaxed).to_be_bytes()
    }

    /// Removes `node_id` when its routing-table record fails `filter`. The table's own copy is
    /// judged, never the record an event carried: a third party can relay an old record of a
    /// node whose current one conforms.
    fn evict_if_refused(
        &self,
        discv5: &Discv5,
        filter: &PeerFilter,
        node_id: &NodeId,
    ) -> Option<EvictionReason> {
        let added = self.added();
        discv5
            .with_kbuckets(|kbuckets| self.evict_in(&mut kbuckets.write(), filter, &added, node_id))
    }

    /// One sweep over the whole table; returns how many records it removed.
    fn sweep(&self, discv5: &Discv5) -> usize {
        let filter = self.filter(discv5);
        let added = self.added();
        discv5.with_kbuckets(|kbuckets| self.sweep_in(&mut kbuckets.write(), &filter, &added))
    }

    /// The judgement and removal of `node_id` in `table`, which the caller holds exclusively.
    /// A pending entry is out of reach: discv5 0.12 has no way to clear one.
    fn evict_in(
        &self,
        table: &mut KBucketsTable<NodeId, Enr>,
        filter: &PeerFilter,
        added: &HashSet<NodeId>,
        node_id: &NodeId,
    ) -> Option<EvictionReason> {
        let key = Key::from(*node_id);
        let Entry::Present(entry, _) = table.entry(&key) else {
            return None;
        };
        let reason = filter.eviction_reason(entry.value(), added.contains(node_id))?;
        entry.remove();
        self.counted(node_id, reason);
        Some(reason)
    }

    /// [`table_evictions`] over `table`, which the caller holds exclusively, and their removal,
    /// until a pass finds nothing: a removal can promote a due pending entry into the bucket.
    fn sweep_in(
        &self,
        table: &mut KBucketsTable<NodeId, Enr>,
        filter: &PeerFilter,
        added: &HashSet<NodeId>,
    ) -> usize {
        let mut removed = 0;
        loop {
            let evictions =
                table_evictions(filter, table.iter().map(|entry| entry.node.value), added);
            let before = removed;
            for (node_id, reason) in evictions {
                if table.remove(&Key::from(node_id)) {
                    self.counted(&node_id, reason);
                    removed += 1;
                }
            }
            if removed == before {
                return removed;
            }
        }
    }

    /// Counts one removal, while the table lock that made it is still held.
    fn counted(&self, node_id: &NodeId, reason: EvictionReason) {
        self.metrics.record(reason);
        tracing::debug!(
            node = %node_id,
            reason = reason.as_str(),
            "evicted a routing-table record"
        );
    }
}

/// A running discv5 node whose lookups return only peers on its fork digest.
pub struct Discovery {
    discv5: Arc<Discv5>,
    guard: TableGuard,
    sweep_interval: Duration,
    /// The routing-table sweep, from the moment discv5 runs; aborted when this is dropped.
    sweep: Option<AbortHandle>,
    /// True once [`Self::start`] has handed out the event stream.
    events_open: bool,
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
            guard: TableGuard::new(config.mode, fork_digest),
            sweep_interval: config.sweep_interval,
            sweep: None,
            events_open: false,
        })
    }

    /// Counts evictions on `metrics` (registered with [`EvictionMetrics::register`]) instead of
    /// the unregistered default. Call it before [`Self::start`], which hands the counter on.
    #[must_use]
    pub fn with_metrics(mut self, metrics: EvictionMetrics) -> Self {
        self.guard.metrics = metrics;
        self
    }

    /// Binds the UDP socket, starts the service task and, at once, the routing-table sweep
    /// (every `sweep_interval` until the service is dropped), then opens the event stream. The
    /// sweep never waits on the stream: a `start` dropped before the stream is open leaves
    /// discv5 running and swept, and a retry only opens the stream. Once the stream is handed
    /// out, `start` is refused.
    pub async fn start(&mut self) -> Result<Events, ServiceError> {
        if self.events_open {
            return Err(ServiceError::Start("the service is already started".into()));
        }
        if self.sweep.is_none() {
            Arc::get_mut(&mut self.discv5)
                .ok_or_else(|| ServiceError::Start("the service is already started".into()))?
                .start()
                .await
                .map_err(|e| ServiceError::Start(e.to_string()))?;
            let sweep = tokio::spawn(sweep_table(
                Arc::downgrade(&self.discv5),
                self.guard.clone(),
                self.sweep_interval,
            ));
            self.sweep = Some(sweep.abort_handle());
        }
        let rx = self
            .discv5
            .event_stream()
            .await
            .map_err(|e| ServiceError::Start(e.to_string()))?;
        self.events_open = true;
        Ok(Events {
            rx,
            discv5: Arc::downgrade(&self.discv5),
            guard: self.guard.clone(),
        })
    }

    /// The fork digest lookups filter on: the local record's, as it is now.
    pub fn fork_digest(&self) -> ForkDigest {
        self.filter().fork_digest
    }

    /// The filter every lookup result, reported event and table record passes, on the fork
    /// digest of the local record as it is now.
    pub fn filter(&self) -> PeerFilter {
        self.guard.filter(&self.discv5)
    }

    /// The routing-table eviction counter.
    pub fn metrics(&self) -> &EvictionMetrics {
        &self.guard.metrics
    }

    /// The local record as it is now (discv5 updates `ip`/`udp` from what peers observe).
    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }

    /// Sets the local record's `cgc` (see [`crate::enr::set_cgc`]): one `seq` bump per change,
    /// none when the value is already there. Returns whether the record changed. The check and
    /// the insert are two steps; cl-chain, which owns the count, is the only caller.
    pub fn set_cgc(&self, custody_group_count: u64) -> Result<bool, ServiceError> {
        let value = Bytes::from(encode_cgc(custody_group_count));
        if value_eq(&self.discv5.local_enr(), CGC_KEY, &value) {
            return Ok(false);
        }
        self.discv5
            .enr_insert(CGC_KEY, &value)
            .map_err(|e| ServiceError::UpdateEnr(e.to_string()))?;
        Ok(true)
    }

    /// Adds a known record (a boot node) to the routing table, subject to the IP rules. The
    /// record stays exempt from the fork rule of the eviction ([`PeerFilter::eviction_reason`]).
    pub fn add_enr(&self, enr: Enr) -> Result<(), ServiceError> {
        let node_id = enr.node_id();
        // One lock over the exemption, the insertion and the rollback: no judgement sees the
        // record in the table unexempted, and a concurrent call for the same node cannot set an
        // exemption that this one's rollback then drops.
        let mut added = self.guard.added();
        let newly_added = added.insert(node_id);
        self.discv5.add_enr(enr).map_err(|e| {
            if newly_added {
                added.remove(&node_id);
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
        let filter = self.filter();
        self.discv5
            .find_node_predicate(target, fork_predicate(filter), max_peers)
            .await
            .map(|enrs| filter.retain(enrs))
            .map_err(|e| ServiceError::Query(e.to_string()))
    }
}

impl Drop for Discovery {
    /// Ends the sweep task now rather than at its next tick.
    fn drop(&mut self) {
        if let Some(sweep) = &self.sweep {
            sweep.abort();
        }
    }
}

/// The sweep task: every `period` (first one `period` after the start), [`TableGuard::sweep`]
/// over the whole table. [`Discovery`] aborts it on drop; it also holds the service weakly and
/// ends at its next tick once the service is gone.
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
            let filter = match self.discv5.upgrade() {
                Some(discv5) => {
                    let filter = self.guard.filter(&discv5);
                    self.evict_named_peer(&discv5, &filter, &event);
                    filter
                }
                None => self.guard.last_filter(),
            };
            if let Some(event) = PeerEvent::classify(event, &filter) {
                return Some(event);
            }
        }
    }

    fn evict_named_peer(&self, discv5: &Discv5, filter: &PeerFilter, event: &Event) {
        let node_id = match event {
            Event::Discovered(enr) | Event::SessionEstablished(enr, _) => enr.node_id(),
            Event::NodeInserted { node_id, .. } => *node_id,
            _ => return,
        };
        self.guard.evict_if_refused(discv5, filter, &node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enr::{build_local_enr, CombinedKey, Enr, LocalAddr, NodeId};
    use discv5::kbucket::{
        ConnectionDirection, ConnectionState, InsertResult, NodeStatus, MAX_NODES_PER_BUCKET,
    };
    use network_config::{ChainConfig, Network};
    use p2p_wire::enr::{ForkFields, ETH2_KEY};

    use std::future::Future as _;
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

    /// A loopback UDP port nothing listens on right now. Another process can take it before
    /// the test binds it: start a node on it through [`start_on_free_port`].
    fn free_udp_port() -> u16 {
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// How many ports a test node tries before the test fails.
    const START_ATTEMPTS: usize = 10;

    /// Whether `err` is a start whose UDP port another socket took first.
    fn port_taken(err: &ServiceError) -> bool {
        matches!(err, ServiceError::Start(io) if io.contains("kind: AddrInUse"))
    }

    /// `start` on a port from `ports`, then on the next one while the start finds its port
    /// taken, for at most [`START_ATTEMPTS`] ports. Any other error ends it at once; a start
    /// that gives up names the ports it tried and keeps the last error.
    async fn start_on_ports<T, Fut>(
        mut ports: impl FnMut() -> u16,
        mut start: impl FnMut(u16) -> Fut,
    ) -> Result<T, String>
    where
        Fut: std::future::Future<Output = Result<T, ServiceError>>,
    {
        let mut taken = Vec::with_capacity(START_ATTEMPTS);
        let mut last = None;
        for _ in 0..START_ATTEMPTS {
            let port = ports();
            match start(port).await {
                Ok(started) => return Ok(started),
                Err(e) if port_taken(&e) => {
                    taken.push(port);
                    last = Some(e);
                }
                Err(e) => return Err(format!("the test node on port {port} did not start: {e}")),
            }
        }
        let last = last.map_or_else(String::new, |e| e.to_string());
        Err(format!(
            "every one of {START_ATTEMPTS} ports was taken before the test node bound it: \
             {taken:?}; the last start failed with: {last}"
        ))
    }

    /// `start` on a fresh loopback port, retried on a taken one ([`start_on_ports`]); the
    /// test fails if it never starts.
    async fn start_on_free_port<T, Fut>(start: impl FnMut(u16) -> Fut) -> T
    where
        Fut: std::future::Future<Output = Result<T, ServiceError>>,
    {
        start_on_ports(free_udp_port, start)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// A record on `fork` for loopback `port` (UDP and TCP), signed by `key`.
    fn loopback_enr(key: &CombinedKey, fork: &ForkFields, port: u16) -> Enr {
        let addr = LocalAddr {
            ip: Ipv4Addr::LOCALHOST,
            tcp_port: port,
            udp_port: port,
        };
        build_local_enr(key, fork, 4, &addr).unwrap()
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
        start_on_free_port(|port| started_on(port, fork, mode, sweep_interval)).await
    }

    /// A node on loopback `port` with the given fork fields, IP rules and sweep interval, and
    /// its start.
    async fn started_on(
        port: u16,
        fork: &ForkFields,
        mode: NetworkMode,
        sweep_interval: Duration,
    ) -> Result<(Discovery, Events), ServiceError> {
        let key = CombinedKey::generate_secp256k1();
        let enr = loopback_enr(&key, fork, port);
        let config = DiscoveryConfig {
            listen_ip: Ipv4Addr::LOCALHOST.into(),
            udp_port: port,
            mode,
            sweep_interval,
        };
        let mut discovery = Discovery::new(enr, key, &config).unwrap();
        let events = discovery.start().await?;
        Ok((discovery, events))
    }

    /// A port another socket holds: the start on it fails with `AddrInUse` and the next port
    /// is tried.
    #[tokio::test]
    async fn a_test_node_whose_port_was_taken_starts_on_the_next_one() {
        let ours = sepolia_fields(274_175);
        let holder = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken = holder.local_addr().unwrap().port();
        let mut tried = Vec::new();
        let ports = || {
            let port = if tried.is_empty() {
                taken
            } else {
                free_udp_port()
            };
            tried.push(port);
            port
        };
        let (node, _events) = start_on_ports(ports, |port| {
            started_on(port, &ours, NetworkMode::Devnet, NO_SWEEP)
        })
        .await
        .unwrap();
        // The ports after the held one come from free_udp_port, which another process can
        // race too: the node runs on whichever was tried last.
        assert_eq!(tried[0], taken, "{tried:?}");
        assert!(tried.len() >= 2, "{tried:?}");
        assert_eq!(node.local_enr().udp4(), tried.last().copied());
        drop(holder);
    }

    /// A port that stays taken: the helper gives up after [`START_ATTEMPTS`] ports and names
    /// them.
    #[tokio::test]
    async fn a_test_node_gives_up_when_every_port_is_taken() {
        let ours = sepolia_fields(274_175);
        let holder = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let taken = holder.local_addr().unwrap().port();
        let mut tried = 0;
        let ports = || {
            tried += 1;
            taken
        };
        let err = start_on_ports(ports, |port| {
            started_on(port, &ours, NetworkMode::Devnet, NO_SWEEP)
        })
        .await
        .err()
        .expect("a held port never starts");
        assert_eq!(tried, START_ATTEMPTS);
        assert!(err.contains(&format!("{START_ATTEMPTS} ")), "{err}");
        assert!(err.contains(&taken.to_string()), "{err}");
        // The last start error is kept, not just the ports.
        assert!(err.contains("kind: AddrInUse"), "{err}");
        drop(holder);
    }

    /// Any other start error ends the helper at once: only a taken port is retried.
    #[tokio::test]
    async fn a_test_node_start_error_that_is_not_a_taken_port_is_not_retried() {
        let mut tried = 0;
        let ports = || {
            tried += 1;
            free_udp_port()
        };
        let err = start_on_ports(ports, |_| async {
            Err::<(), _>(ServiceError::Start("the service is already started".into()))
        })
        .await
        .expect_err("the start failed");
        assert_eq!(tried, 1);
        assert!(err.contains("already started"), "{err}");
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

        wait_evicted(&node, &peer_id, EvictionReason::ForkDigest, sweep * 5).await;
        assert_eq!(node.metrics().evictions(EvictionReason::ForkDigest), 1);
        assert_eq!(node.metrics().evictions(EvictionReason::IpRule), 0);
        tokio::time::sleep(sweep * 2).await;
        assert!(node.discv5.table_entries_id().contains(&boot_id));
        assert_eq!(node.metrics().evictions(EvictionReason::ForkDigest), 1);
    }

    /// A public-mode node on loopback, on `fork`, swept every `sweep_interval` once started;
    /// not started yet.
    fn unstarted(port: u16, fork: &ForkFields, sweep_interval: Duration) -> Discovery {
        let key = CombinedKey::generate_secp256k1();
        let enr = loopback_enr(&key, fork, port);
        let config = DiscoveryConfig {
            udp_port: port,
            sweep_interval,
            ..DiscoveryConfig::new(Ipv4Addr::LOCALHOST.into(), NetworkMode::Public)
        };
        Discovery::new(enr, key, &config).unwrap()
    }

    /// The sweep starts as soon as discv5 runs, before the event stream is open: a `start` that
    /// is dropped while it waits for the stream leaves discv5 swept, and a retry opens the
    /// stream. Once the stream is handed out, another `start` is refused.
    #[tokio::test]
    async fn a_start_dropped_before_its_event_stream_still_sweeps() {
        let ours = sepolia_fields(274_175);
        let sweep = Duration::from_millis(100);
        // One poll on this single-threaded runtime: discv5 starts, and the event stream request
        // waits for the service task, which cannot run during the poll. A taken port fails
        // that poll and is retried.
        let mut node = start_on_free_port(|port| async move {
            let mut node = unstarted(port, &ours, sweep);
            let polled = {
                let mut start = std::pin::pin!(node.start());
                std::future::poll_fn(|cx| std::task::Poll::Ready(start.as_mut().poll(cx))).await
            };
            match polled {
                std::task::Poll::Pending => Ok(node),
                std::task::Poll::Ready(Err(e)) => Err(e),
                std::task::Poll::Ready(Ok(_)) => panic!("start finished in one poll"),
            }
        })
        .await;
        let sweeper = node.sweep.clone().expect("the sweep started with discv5");
        assert!(!sweeper.is_finished());

        // A refused record that raised no event is swept out.
        let refused = record_with(
            &CombinedKey::generate_secp256k1(),
            &ours,
            Ipv4Addr::LOCALHOST,
        );
        let _ = insert_unchecked(&node, &refused);
        wait_evicted(
            &node,
            &refused.node_id(),
            EvictionReason::IpRule,
            sweep * 20,
        )
        .await;

        let _events = node.start().await.unwrap();
        let err = node.start().await.err();
        assert!(matches!(err, Some(ServiceError::Start(_))), "{err:?}");
        assert!(!sweeper.is_finished());
    }

    /// Dropping the [`Discovery`] ends its sweep task at once, not one interval later.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_service_aborts_its_sweep() {
        let ours = sepolia_fields(274_175);
        let (node, _events) = node_with(&ours, NetworkMode::Devnet, NO_SWEEP).await;
        let sweeper = node.sweep.clone().expect("a started service sweeps");
        assert!(!sweeper.is_finished());
        drop(node);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !sweeper.is_finished() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the sweep outlived the service"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
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

    /// Waits until `id` is out of `node`'s routing table and an eviction for `reason` is
    /// counted, at most `limit`.
    async fn wait_evicted(node: &Discovery, id: &NodeId, reason: EvictionReason, limit: Duration) {
        let deadline = tokio::time::Instant::now() + limit;
        while in_table(node, id) || node.metrics().evictions(reason) == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "{id} not evicted and counted for {reason:?} after {limit:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A node that is not started, on loopback: its routing table is filled by hand.
    fn idle_node(fork: &ForkFields, mode: NetworkMode) -> Discovery {
        let key = CombinedKey::generate_secp256k1();
        let enr = record_with(&key, fork, Ipv4Addr::LOCALHOST);
        let config = DiscoveryConfig::new(Ipv4Addr::LOCALHOST.into(), mode);
        Discovery::new(enr, key, &config).unwrap()
    }

    /// A record on `fork` at `ip`, signed by `key`.
    fn record_with(key: &CombinedKey, fork: &ForkFields, ip: Ipv4Addr) -> Enr {
        build_local_enr(key, fork, 4, &LocalAddr::new(ip)).unwrap()
    }

    /// Puts `enr` in `node`'s routing table past `table_filter`, disconnected.
    fn insert_unchecked(node: &Discovery, enr: &Enr) -> InsertResult<NodeId> {
        insert_in_state(node, enr, ConnectionState::Disconnected)
    }

    /// Puts `enr` in `node`'s routing table past `table_filter`, in `state`, the way an incoming
    /// session does (connected).
    fn insert_in_state(
        node: &Discovery,
        enr: &Enr,
        state: ConnectionState,
    ) -> InsertResult<NodeId> {
        let status = NodeStatus {
            state,
            direction: ConnectionDirection::Incoming,
        };
        node.discv5.with_kbuckets(|kbuckets| {
            kbuckets
                .write()
                .insert_or_update(&Key::from(enr.node_id()), enr.clone(), status)
        })
    }

    fn in_table(node: &Discovery, id: &NodeId) -> bool {
        node.discv5.table_entries_id().contains(id)
    }

    /// The entry the table holds for `id`: present, pending or absent.
    fn table_slot(node: &Discovery, id: &NodeId) -> &'static str {
        node.discv5
            .with_kbuckets(|kbuckets| match kbuckets.write().entry(&Key::from(*id)) {
                Entry::Present(..) => "present",
                Entry::Pending(..) => "pending",
                Entry::Absent(..) => "absent",
                Entry::SelfEntry => "self",
            })
    }

    /// The judgement and the removal run under one write lock of the routing table, on the
    /// entry the table holds then. The counter moves before the removal is visible to anyone
    /// else, and a conforming, exempt or absent entry is never removed.
    #[tokio::test]
    async fn one_table_lock_judges_and_removes_the_same_entry() {
        let ours = sepolia_fields(274_175);
        let other = sepolia_fields(274_176);
        let node = idle_node(&ours, NetworkMode::Public);
        let key = CombinedKey::generate_secp256k1();
        let off = record_with(&key, &other, Ipv4Addr::new(8, 8, 8, 8));
        let on = record_with(&key, &ours, Ipv4Addr::new(8, 8, 8, 8));
        let id = off.node_id();
        let filter = node.filter();
        let none = HashSet::new();

        assert!(matches!(
            insert_unchecked(&node, &off),
            InsertResult::Inserted
        ));
        let evicted = node.discv5.with_kbuckets(|kbuckets| {
            let mut table = kbuckets.write();
            let reason = node.guard.evict_in(&mut table, &filter, &none, &id);
            // Still under the same lock: out of the table, and already counted.
            assert!(matches!(table.entry(&Key::from(id)), Entry::Absent(..)));
            assert_eq!(node.metrics().evictions(EvictionReason::ForkDigest), 1);
            reason
        });
        assert_eq!(evicted, Some(EvictionReason::ForkDigest));

        // The table's conforming copy is judged, whatever record an event carried.
        assert!(matches!(
            insert_unchecked(&node, &on),
            InsertResult::Inserted
        ));
        assert_eq!(
            node.guard.evict_if_refused(&node.discv5, &filter, &id),
            None
        );
        assert!(in_table(&node, &id));
        // An exempt off-fork entry stays; an absent one is nothing to evict.
        let _ = insert_unchecked(&node, &off);
        let exempt = HashSet::from([id]);
        let kept = node.discv5.with_kbuckets(|kbuckets| {
            node.guard
                .evict_in(&mut kbuckets.write(), &filter, &exempt, &id)
        });
        assert_eq!(kept, None);
        assert!(in_table(&node, &id));
        assert_eq!(
            node.guard
                .evict_if_refused(&node.discv5, &filter, &NodeId::random()),
            None
        );
        assert_eq!(node.metrics().evictions(EvictionReason::ForkDigest), 1);
        assert_eq!(node.metrics().evictions(EvictionReason::IpRule), 0);
    }

    /// A conforming record that replaces a refused one while an eviction of that node waits is
    /// judged as it is then: the eviction reads the table only once it holds every lock it
    /// decides under, so it never removes the newer record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_record_replaced_while_the_eviction_waits_is_kept() {
        let ours = sepolia_fields(274_175);
        let other = sepolia_fields(274_176);
        let node = idle_node(&ours, NetworkMode::Public);
        let key = CombinedKey::generate_secp256k1();
        let off = record_with(&key, &other, Ipv4Addr::new(8, 8, 8, 8));
        let on = record_with(&key, &ours, Ipv4Addr::new(8, 8, 8, 8));
        let id = off.node_id();
        let filter = node.filter();
        assert!(matches!(
            insert_unchecked(&node, &off),
            InsertResult::Inserted
        ));

        std::thread::scope(|scope| {
            let exemptions = node.guard.added();
            let evictor = scope.spawn(|| node.guard.evict_if_refused(&node.discv5, &filter, &id));
            std::thread::sleep(Duration::from_millis(100));
            assert!(matches!(
                insert_unchecked(&node, &on),
                InsertResult::ValueUpdated
            ));
            drop(exemptions);
            assert_eq!(evictor.join().unwrap(), None);
        });
        assert!(in_table(&node, &id));
        assert_eq!(node.metrics().evictions(EvictionReason::ForkDigest), 0);
    }

    /// The fork rule reads the local record each time: once its `eth2` moves to the next
    /// digest (a fork or BPO boundary), records on the new digest are kept, reported and
    /// returned, and records on the old one evicted. A local `eth2` that no longer decodes
    /// keeps the digest last read.
    #[tokio::test]
    async fn the_fork_rule_follows_the_local_record() {
        let ours = sepolia_fields(274_175);
        let next = sepolia_fields(274_176);
        let node = idle_node(&ours, NetworkMode::Public);
        assert_eq!(node.fork_digest(), ours.eth2.fork_digest);
        let on_old = record_with(
            &CombinedKey::generate_secp256k1(),
            &ours,
            Ipv4Addr::new(8, 8, 8, 8),
        );
        let on_new = record_with(
            &CombinedKey::generate_secp256k1(),
            &next,
            Ipv4Addr::new(8, 8, 4, 4),
        );
        assert!(node.filter().accepts(&on_old));

        node.discv5
            .enr_insert(
                ETH2_KEY,
                &alloy_rlp::Bytes::from(next.eth2.to_bytes().to_vec()),
            )
            .unwrap();
        assert_eq!(node.fork_digest(), next.eth2.fork_digest);
        assert!(node.filter().accepts(&on_new));
        assert!(!node.filter().accepts(&on_old));
        let _ = insert_unchecked(&node, &on_old);
        let _ = insert_unchecked(&node, &on_new);
        assert_eq!(node.guard.sweep(&node.discv5), 1);
        assert!(!in_table(&node, &on_old.node_id()));
        assert!(in_table(&node, &on_new.node_id()));
        assert_eq!(node.metrics().evictions(EvictionReason::ForkDigest), 1);

        // An `eth2` that does not decode: the rule keeps the digest last read, here and once
        // the service is gone.
        node.discv5
            .enr_insert(ETH2_KEY, &alloy_rlp::Bytes::from_static(&[0xff; 3]))
            .unwrap();
        assert_eq!(node.fork_digest(), next.eth2.fork_digest);
        assert_eq!(node.guard.last_filter(), node.filter());
        assert_eq!(node.guard.sweep(&node.discv5), 0);
        assert!(in_table(&node, &on_new.node_id()));
    }

    /// `add_enr` holds the exemptions across its insertion and its rollback: a concurrent one
    /// (or a judgement) waits for it, so a failing `add_enr` cannot drop an exemption another
    /// one set meanwhile. A failure rolls back only the exemption it created.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn add_enr_is_one_step_under_the_exemption_lock() {
        let ours = sepolia_fields(274_175);
        let other = sepolia_fields(274_176);
        let node = idle_node(&ours, NetworkMode::Devnet);
        let key = CombinedKey::generate_secp256k1();
        let boot = record_with(&key, &other, Ipv4Addr::LOCALHOST);
        let id = boot.node_id();

        // With the table locked, `add_enr` stops at its insertion. It must hold the exemptions
        // there: had it released them after setting its own, a failing call could drop an
        // exemption another call set in between.
        node.discv5.with_kbuckets(|kbuckets| {
            let table = kbuckets.write();
            std::thread::scope(|scope| {
                let adder = scope.spawn(|| node.add_enr(boot.clone()));
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    match node.guard.added.try_lock() {
                        Err(std::sync::TryLockError::WouldBlock) => break,
                        Err(std::sync::TryLockError::Poisoned(_)) => panic!("poisoned"),
                        Ok(exemptions) => assert!(
                            !exemptions.contains(&id),
                            "add_enr released the exemptions before its insertion"
                        ),
                    }
                    assert!(std::time::Instant::now() < deadline, "add_enr never ran");
                    std::thread::sleep(Duration::from_millis(5));
                }
                drop(table);
                adder.join().unwrap().unwrap();
            });
        });
        assert!(in_table(&node, &id));
        assert!(node.guard.added().contains(&id));

        // The same node again, with a record the table refuses (no UDP socket): the call fails
        // and the exemption the first one set stays.
        let unreachable = Enr::builder().ip4(Ipv4Addr::LOCALHOST).build(&key).unwrap();
        assert_eq!(unreachable.node_id(), id);
        let err = node.add_enr(unreachable.clone()).err();
        assert!(matches!(err, Some(ServiceError::AddEnr(_))), "{err:?}");
        assert!(node.guard.added().contains(&id));
        assert_eq!(node.guard.sweep(&node.discv5), 0);

        // A first, failing add_enr leaves no exemption behind.
        let stranger = Enr::builder()
            .ip4(Ipv4Addr::LOCALHOST)
            .build(&CombinedKey::generate_secp256k1())
            .unwrap();
        assert!(node.add_enr(stranger.clone()).is_err());
        assert!(!node.guard.added().contains(&stranger.node_id()));
    }

    /// A record whose node id falls in the farthest bucket from `local` (log2 distance 256).
    fn farthest(local: &NodeId, fork: &ForkFields, ip: Ipv4Addr) -> Enr {
        loop {
            let enr = record_with(&CombinedKey::generate_secp256k1(), fork, ip);
            if (enr.node_id().raw()[0] ^ local.raw()[0]) & 0x80 != 0 {
                return enr;
            }
        }
    }

    /// The sweep judges and removes under one table lock too. A pending entry (the candidate
    /// waiting for a slot in a full bucket) is out of its reach: discv5 0.12 can show one but
    /// not clear it (`PendingEntry::remove` only removes bucket nodes), so it waits for its
    /// promotion, which the next judgement of the table catches.
    #[tokio::test]
    async fn the_sweep_removes_refused_entries_and_cannot_reach_a_pending_one() {
        let ours = sepolia_fields(274_175);
        let node = idle_node(&ours, NetworkMode::Public);
        let local = node.local_enr().node_id();
        let refused = farthest(&local, &ours, Ipv4Addr::LOCALHOST);
        assert!(matches!(
            insert_unchecked(&node, &refused),
            InsertResult::Inserted
        ));
        let conforming: Vec<Enr> = (1..MAX_NODES_PER_BUCKET)
            .map(|i| farthest(&local, &ours, Ipv4Addr::new(8, 8, 8, i as u8)))
            .collect();
        for enr in &conforming {
            assert!(matches!(
                insert_unchecked(&node, enr),
                InsertResult::Inserted
            ));
        }
        // The bucket is full of disconnected records: a refused incoming session waits in its
        // pending slot.
        let pending = farthest(&local, &ours, Ipv4Addr::LOCALHOST);
        let inserted = insert_in_state(&node, &pending, ConnectionState::Connected);
        assert!(
            matches!(inserted, InsertResult::Pending { .. }),
            "{inserted:?}"
        );

        assert_eq!(node.guard.sweep(&node.discv5), 1);
        assert_eq!(node.metrics().evictions(EvictionReason::IpRule), 1);
        assert_eq!(table_slot(&node, &refused.node_id()), "absent");
        for enr in &conforming {
            assert_eq!(table_slot(&node, &enr.node_id()), "present");
        }
        // Neither the sweep nor the event path can clear the pending entry, and discv5 cannot
        // either: the residual the README states.
        assert_eq!(table_slot(&node, &pending.node_id()), "pending");
        let filter = node.filter();
        assert_eq!(
            node.guard
                .evict_if_refused(&node.discv5, &filter, &pending.node_id()),
            None
        );
        node.discv5.with_kbuckets(|kbuckets| {
            if let Entry::Pending(entry, _) = kbuckets.write().entry(&Key::from(pending.node_id()))
            {
                entry.remove();
            }
        });
        assert_eq!(table_slot(&node, &pending.node_id()), "pending");
        assert_eq!(node.metrics().evictions(EvictionReason::IpRule), 1);
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
        wait_evicted(&public, &peer_id, EvictionReason::IpRule, sweep * 5).await;
        assert_eq!(public.metrics().evictions(EvictionReason::IpRule), 1);
        assert_eq!(public.metrics().evictions(EvictionReason::ForkDigest), 0);
        let found = ids(&public.find_peers(peer_id, 16).await.unwrap());
        assert!(!found.contains(&peer_id), "{found:?}");
    }

    /// The running node's record takes a new `cgc` with one seq bump, and only on a change.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_cgc_updates_the_running_record_once() {
        let (node, _events) = node(&sepolia_fields(274_175)).await;
        let seq = node.local_enr().seq();
        assert_eq!(node.set_cgc(4), Ok(false));
        assert_eq!(node.local_enr().seq(), seq);
        assert_eq!(node.set_cgc(8), Ok(true));
        let enr = node.local_enr();
        assert_eq!(enr.seq(), seq + 1);
        assert!(enr.verify());
        assert_eq!(crate::enr::EnrFields::read(&enr).unwrap().cgc, Some(8));
        assert_eq!(node.set_cgc(8), Ok(false));
        assert_eq!(node.local_enr().seq(), seq + 1);
    }

    /// Local mode takes loopback, private (RFC 1918), link-local, CGNAT and IPv6 unique-local
    /// and link-local addresses, and nothing else: every address of a record must be one.
    #[test]
    fn local_mode_takes_only_local_addresses() {
        let local = table_filter(NetworkMode::Local);
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.10",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.254",
        ] {
            let ip: Ipv4Addr = ip.parse().unwrap();
            assert!(local(&with_ip4(ip)), "{ip}");
            assert!(is_local_ip(ip.into()), "{ip}");
        }
        for ip in ["::1", "fd00::1", "fc00::1", "fe80::1", "::ffff:10.0.0.1"] {
            let ip: Ipv6Addr = ip.parse().unwrap();
            assert!(local(&with_ip6(ip)), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "192.0.2.1",
            "172.32.0.1",
            "100.128.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
        ] {
            let ip: Ipv4Addr = ip.parse().unwrap();
            assert!(!local(&with_ip4(ip)), "{ip}");
            assert!(!is_local_ip(ip.into()), "{ip}");
        }
        for ip in ["2001:4860::1", "::", "ff02::1", "::ffff:8.8.8.8"] {
            let ip: Ipv6Addr = ip.parse().unwrap();
            assert!(!local(&with_ip6(ip)), "{ip}");
        }
        // A local IPv4 address does not excuse a public IPv6 one.
        let key = CombinedKey::generate_secp256k1();
        let mixed = Enr::builder()
            .ip4(Ipv4Addr::LOCALHOST)
            .udp4(9000)
            .ip6("2001:4860::1".parse().unwrap())
            .udp6(9000)
            .build(&key)
            .unwrap();
        assert!(!local(&mixed));
        assert!(table_filter(NetworkMode::Devnet)(&mixed));
        let filter = PeerFilter {
            fork_digest: [0; 4],
            mode: NetworkMode::Local,
        };
        assert!(filter.accepts_source(&"10.1.2.3:9000".parse().unwrap()));
        assert!(!filter.accepts_source(&"8.8.8.8:9000".parse().unwrap()));
    }

    /// The records `events` reports as discovered within half a second.
    async fn discovered(events: &mut Events) -> HashSet<NodeId> {
        let mut seen = HashSet::new();
        while let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_millis(500), events.next()).await
        {
            if let PeerEvent::Discovered(enr) = event {
                seen.insert(enr.node_id());
            }
        }
        seen
    }

    /// A Local-mode node never queries a record whose address is not local, whoever hands it
    /// out. discv5 takes a record a NODES response carries into the lookup (and so sends it a
    /// FINDNODE) only if it passes `table_filter`, the rule `Events` reports `Discovered` by; a
    /// record that fails it is neither queried, nor reported, nor put in the routing table (so
    /// never pinged). The record's address is TEST-NET-1 (192.0.2.1): not local, and no host,
    /// so the Devnet-mode control, which does query it, sends nothing anywhere real.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_mode_never_queries_a_record_that_is_not_local() {
        let ours = sepolia_fields(274_175);
        let (boot, _boot_events) = node(&ours).await;
        let key = CombinedKey::generate_secp256k1();
        let remote = LocalAddr {
            ip: Ipv4Addr::new(192, 0, 2, 1),
            tcp_port: 9000,
            udp_port: 9000,
        };
        let far = build_local_enr(&key, &ours, 4, &remote).unwrap();
        let far_id = far.node_id();
        boot.add_enr(far).unwrap();

        let (local, mut local_events) = node_in(&ours, NetworkMode::Local).await;
        local.add_enr(boot.local_enr()).unwrap();
        let found = ids(&local.find_peers(far_id, 16).await.unwrap());
        assert!(found.contains(&boot.local_enr().node_id()), "{found:?}");
        assert!(!found.contains(&far_id), "{found:?}");
        assert!(!discovered(&mut local_events).await.contains(&far_id));
        assert!(!local.discv5.table_entries_id().contains(&far_id));

        // The control: in Devnet mode the record passes, so the same lookup queries it, and
        // waits for that request to time out.
        let (devnet, mut devnet_events) = node_in(&ours, NetworkMode::Devnet).await;
        devnet.add_enr(boot.local_enr()).unwrap();
        let started = tokio::time::Instant::now();
        let _ = devnet.find_peers(far_id, 16).await;
        assert!(
            started.elapsed() >= Duration::from_millis(900),
            "{:?}",
            started.elapsed()
        );
        assert!(discovered(&mut devnet_events).await.contains(&far_id));
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
        let (b, _b_events, stale, fresh) = start_on_free_port(|port| {
            let (ours, other) = (&ours, &other);
            async move {
                let b_key = CombinedKey::generate_secp256k1();
                let mut stale = loopback_enr(&b_key, ours, port);
                stale
                    .insert(
                        ETH2_KEY,
                        &alloy_rlp::Bytes::from(other.eth2.to_bytes().to_vec()),
                        &b_key,
                    )
                    .unwrap();
                // The stale copy must look older to `a`'s query than the one `x` hands out.
                let mut fresh = stale.clone();
                fresh
                    .insert(
                        ETH2_KEY,
                        &alloy_rlp::Bytes::from(ours.eth2.to_bytes().to_vec()),
                        &b_key,
                    )
                    .unwrap();
                assert!(fresh.seq() > stale.seq());
                let b_config = DiscoveryConfig {
                    udp_port: port,
                    ..DiscoveryConfig::new(Ipv4Addr::LOCALHOST.into(), NetworkMode::Devnet)
                };
                let mut b = Discovery::new(fresh.clone(), b_key, &b_config).unwrap();
                let b_events = b.start().await?;
                Ok((b, b_events, stale, fresh))
            }
        })
        .await;

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
        // Setup binds nothing: the default port is never bound here.
        let config = DiscoveryConfig::new(Ipv4Addr::LOCALHOST.into(), NetworkMode::Public);
        assert_eq!(config.udp_port, 9000);
        let enr = record_with(
            &CombinedKey::generate_secp256k1(),
            &fields,
            Ipv4Addr::LOCALHOST,
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
        let err = Discovery::new(enr, stranger, &config).err();
        assert!(matches!(err, Some(ServiceError::Setup(_))), "{err:?}");

        let (mut discovery, _events) = start_on_free_port(|port| {
            let fields = &fields;
            async move {
                let key = CombinedKey::generate_secp256k1();
                let enr = loopback_enr(&key, fields, port);
                let config = DiscoveryConfig {
                    udp_port: port,
                    ..config
                };
                let mut discovery = Discovery::new(enr, key, &config).unwrap();
                // Not started: no lookup.
                let err = discovery.find_peers(NodeId::random(), 1).await;
                assert!(matches!(err, Err(ServiceError::Query(_))), "{err:?}");
                let events = discovery.start().await?;
                Ok((discovery, events))
            }
        })
        .await;
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
