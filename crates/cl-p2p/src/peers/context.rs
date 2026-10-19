//! What is logged next to a reason-3 Goodbye: the peer's inbound rate-limit events (response
//! chunks we withheld because the peer was over its quota, [`crate::rpc::limits`]) and the
//! gossipsub PRUNEs it sent us. Context only: neither this module nor the ledger infers from it
//! why the peer said Goodbye.
//!
//! [`GoodbyeContext`] keeps, per peer, one [`ContextEntry`] per kind and protocol: how many
//! events, and when the first and the last came. A peer has at most
//! [`MAX_ENTRIES_PER_PEER`] entries (one per req/resp protocol, one for PRUNE), and at most
//! [`MAX_CONTEXT_PEERS`] peers are held; an event of a peer past that is dropped and counted
//! ([`GoodbyeContext::dropped`]). The ledger forgets a peer when it disconnects.
//!
//! # Where the events come from
//!
//! [`layer`] fills it from two `tracing` debug events, the way [`crate::rpc::unsupported`]
//! counts refused proposals: a layer the owner adds to its subscriber next to its formatting
//! layer, which enables those debug events for itself only, so the other layers' levels stay
//! as they are.
//!
//! - **Rate limit**: the `over quota: chunk withheld` and `over quota: column chunk withheld`
//!   events of [`crate::rpc::limits`], with the peer in `peer` and the protocol ID in
//!   `protocol`. Only the seven protocol IDs the probe serves become entries.
//! - **PRUNE**: the pinned gossipsub's PRUNE event, `Handling PRUNE message for peer` (target
//!   `libp2p_gossipsub::behaviour`), with the peer in `peer`.
//!
//! Field values are read into fixed buffers, so a log event costs no allocation. `tracing`
//! caches each callsite's interest process-wide: install the subscriber before the swarm runs,
//! as the process's default.

use crate::rpc::metrics::protocol_label;
use libp2p::PeerId;
use p2p_wire::rpc::protocols::Protocol;
use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::str::FromStr as _;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// Peers whose context is held at once: the probe's 160 established connections
/// ([`crate::behaviour::ConnectionCaps`]) and the bypassed reference peers, with room to spare
/// for peers that left before the owner told the ledger.
pub const MAX_CONTEXT_PEERS: usize = 256;

/// Entries one peer can have: one per req/resp protocol, plus one for PRUNE.
pub const MAX_ENTRIES_PER_PEER: usize = Protocol::ALL.len() + 1;

/// The `tracing` target of the rate limiter's events.
const LIMITS_TARGET: &str = "cl_p2p::rpc::limits";

/// The rate limiter's messages for a withheld chunk.
const WITHHELD: [&str; 2] = [
    "over quota: chunk withheld",
    "over quota: column chunk withheld",
];

/// The `tracing` target of the pinned gossipsub's behaviour.
const GOSSIPSUB_TARGET: &str = "libp2p_gossipsub::behaviour";

/// The message of the pinned gossipsub's PRUNE event.
const PRUNE_RECEIVED: &str = "Handling PRUNE message for peer";

/// The longest field value read, in bytes: past every message above, every protocol ID the
/// probe serves and every peer ID string, so a longer value cannot be one of them.
const MAX_FIELD_LEN: usize = 96;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContextKind {
    /// We withheld a response chunk: the peer was over its quota of the protocol.
    RateLimited,
    /// The peer sent us a gossipsub PRUNE.
    PruneReceived,
}

impl ContextKind {
    /// The `kind` value logged.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "rate_limited",
            Self::PruneReceived => "prune_received",
        }
    }
}

/// One kind of event of one peer, on one protocol (none for PRUNE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextEntry {
    /// What happened.
    pub kind: ContextKind,
    /// The protocol's `protocol` label value ([`protocol_label`]); `""` for PRUNE.
    pub detail: &'static str,
    /// How many times.
    pub count: u64,
    /// When it first happened, in Unix milliseconds.
    pub first_unix_ms: u64,
    /// When it last happened, in Unix milliseconds.
    pub last_unix_ms: u64,
}

#[derive(Debug, Default)]
struct Store {
    peers: HashMap<PeerId, Vec<ContextEntry>>,
    dropped: u64,
}

/// The per-peer context, shared by [`layer`] and the ledger (see the module docs). Cheap to
/// clone: every clone is the same store.
#[derive(Debug, Clone, Default)]
pub struct GoodbyeContext(Arc<Mutex<Store>>);

/// `at` in Unix milliseconds; 0 before the epoch.
pub(crate) fn unix_ms(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl GoodbyeContext {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Store> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// We withheld a chunk of `protocol` from `peer` at `at`.
    pub fn rate_limited(&self, peer: PeerId, protocol: Protocol, at: SystemTime) {
        self.record(peer, ContextKind::RateLimited, protocol_label(protocol), at);
    }

    /// `peer` sent us a PRUNE at `at`.
    pub fn prune_received(&self, peer: PeerId, at: SystemTime) {
        self.record(peer, ContextKind::PruneReceived, "", at);
    }

    fn record(&self, peer: PeerId, kind: ContextKind, detail: &'static str, at: SystemTime) {
        let ms = unix_ms(at);
        let mut store = self.lock();
        if !store.peers.contains_key(&peer) && store.peers.len() >= MAX_CONTEXT_PEERS {
            store.dropped = store.dropped.saturating_add(1);
            return;
        }
        let entries = store.peers.entry(peer).or_default();
        match entries
            .iter_mut()
            .find(|e| e.kind == kind && e.detail == detail)
        {
            Some(entry) => {
                entry.count = entry.count.saturating_add(1);
                entry.first_unix_ms = entry.first_unix_ms.min(ms);
                entry.last_unix_ms = entry.last_unix_ms.max(ms);
            }
            // At most MAX_ENTRIES_PER_PEER: the kinds and details are a closed set.
            None => entries.push(ContextEntry {
                kind,
                detail,
                count: 1,
                first_unix_ms: ms,
                last_unix_ms: ms,
            }),
        }
    }

    /// `peer`'s entries, in the order their first events came.
    #[must_use]
    pub fn entries(&self, peer: &PeerId) -> Vec<ContextEntry> {
        self.lock().peers.get(peer).cloned().unwrap_or_default()
    }

    /// Drops `peer`'s entries.
    pub fn forget(&self, peer: &PeerId) {
        self.lock().peers.remove(peer);
    }

    /// The peers held now.
    #[must_use]
    pub fn peers(&self) -> usize {
        self.lock().peers.len()
    }

    /// Events dropped because [`MAX_CONTEXT_PEERS`] peers were held.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }
}

/// The layer filling `context` from the rate limiter's and gossipsub's debug events (see the
/// module docs), filtered to those two targets at debug.
pub fn layer<S>(context: GoodbyeContext) -> impl Layer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    let events = filter_fn(|meta: &Metadata<'_>| {
        meta.is_event()
            && *meta.level() == Level::DEBUG
            && matches!(meta.target(), LIMITS_TARGET | GOSSIPSUB_TARGET)
    })
    .with_max_level_hint(LevelFilter::DEBUG);
    ContextLayer { context }.with_filter(events)
}

struct ContextLayer {
    context: GoodbyeContext,
}

impl<S: Subscriber> Layer<S> for ContextLayer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut fields = EventFields::default();
        event.record(&mut fields);
        let Some(message) = fields.message.as_str() else {
            return;
        };
        // Target and message first: only an event the layer records costs a peer ID parse.
        let recorded = match event.metadata().target() {
            LIMITS_TARGET if WITHHELD.contains(&message) => {
                let Some(protocol) = fields
                    .protocol
                    .as_str()
                    .and_then(|id| Protocol::ALL.into_iter().find(|p| p.id() == id))
                else {
                    return;
                };
                Some(protocol)
            }
            GOSSIPSUB_TARGET if message == PRUNE_RECEIVED => None,
            _ => return,
        };
        let Some(peer) = fields.peer.as_str().and_then(|p| PeerId::from_str(p).ok()) else {
            return;
        };
        let now = SystemTime::now();
        match recorded {
            Some(protocol) => self.context.rate_limited(peer, protocol, now),
            None => self.context.prune_received(peer, now),
        }
    }
}

/// The three fields the layer reads.
#[derive(Default)]
struct EventFields {
    message: FieldBuf,
    peer: FieldBuf,
    protocol: FieldBuf,
}

impl EventFields {
    fn slot(&mut self, field: &Field) -> Option<&mut FieldBuf> {
        match field.name() {
            "message" => Some(&mut self.message),
            "peer" => Some(&mut self.peer),
            "protocol" => Some(&mut self.protocol),
            _ => None,
        }
    }
}

impl Visit for EventFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if let Some(slot) = self.slot(field) {
            slot.set(format_args!("{value}"));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // `%value` fields and the message arrive here, formatting as their `Display`.
        if let Some(slot) = self.slot(field) {
            slot.set(format_args!("{value:?}"));
        }
    }
}

/// A field value of at most [`MAX_FIELD_LEN`] bytes; a longer one is no value at all.
struct FieldBuf {
    buf: [u8; MAX_FIELD_LEN],
    len: usize,
    overflow: bool,
    set: bool,
}

impl Default for FieldBuf {
    fn default() -> Self {
        Self {
            buf: [0; MAX_FIELD_LEN],
            len: 0,
            overflow: false,
            set: false,
        }
    }
}

impl FieldBuf {
    fn set(&mut self, value: fmt::Arguments<'_>) {
        self.len = 0;
        self.overflow = false;
        self.set = true;
        // An overflow is recorded in `overflow`; the error only stops the formatting.
        let _ = self.write_fmt(value);
    }

    /// The value, unless it was never set or overflowed.
    fn as_str(&self) -> Option<&str> {
        if !self.set || self.overflow {
            return None;
        }
        std::str::from_utf8(&self.buf[..self.len]).ok()
    }
}

impl fmt::Write for FieldBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        if end > MAX_FIELD_LEN {
            self.overflow = true;
            return Err(fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tracing_subscriber::layer::SubscriberExt as _;

    fn at(ms: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(ms)
    }

    /// The store after `emit` ran under a subscriber holding only [`layer`].
    fn recorded(emit: impl FnOnce()) -> GoodbyeContext {
        let context = GoodbyeContext::new();
        let subscriber = tracing_subscriber::registry().with(layer(context.clone()));
        tracing::subscriber::with_default(subscriber, emit);
        context
    }

    #[test]
    fn entries_count_per_kind_and_protocol() {
        let context = GoodbyeContext::new();
        let peer = PeerId::random();
        context.rate_limited(peer, Protocol::PingV1, at(2_000));
        context.rate_limited(peer, Protocol::PingV1, at(1_000));
        context.rate_limited(peer, Protocol::PingV1, at(3_000));
        context.rate_limited(peer, Protocol::StatusV2, at(4_000));
        context.prune_received(peer, at(5_000));
        context.prune_received(peer, at(6_000));
        let entries = context.entries(&peer);
        assert_eq!(
            entries,
            [
                ContextEntry {
                    kind: ContextKind::RateLimited,
                    detail: "ping",
                    count: 3,
                    first_unix_ms: 1_000,
                    last_unix_ms: 3_000,
                },
                ContextEntry {
                    kind: ContextKind::RateLimited,
                    detail: "status",
                    count: 1,
                    first_unix_ms: 4_000,
                    last_unix_ms: 4_000,
                },
                ContextEntry {
                    kind: ContextKind::PruneReceived,
                    detail: "",
                    count: 2,
                    first_unix_ms: 5_000,
                    last_unix_ms: 6_000,
                },
            ]
        );
        assert!(context.entries(&PeerId::random()).is_empty());
        context.forget(&peer);
        assert!(context.entries(&peer).is_empty());
        assert_eq!(context.peers(), 0);
    }

    #[test]
    fn one_peer_has_at_most_one_entry_per_protocol_and_prune() {
        let context = GoodbyeContext::new();
        let peer = PeerId::random();
        for _ in 0..3 {
            for protocol in Protocol::ALL {
                context.rate_limited(peer, protocol, at(1));
            }
            context.prune_received(peer, at(1));
        }
        assert_eq!(context.entries(&peer).len(), MAX_ENTRIES_PER_PEER);
    }

    #[test]
    fn peers_past_the_cap_are_dropped_and_counted() {
        let context = GoodbyeContext::new();
        let held: Vec<PeerId> = (0..MAX_CONTEXT_PEERS).map(|_| PeerId::random()).collect();
        for peer in &held {
            context.prune_received(*peer, at(1));
        }
        let late = PeerId::random();
        context.prune_received(late, at(2));
        context.rate_limited(late, Protocol::PingV1, at(2));
        assert_eq!(context.peers(), MAX_CONTEXT_PEERS);
        assert!(context.entries(&late).is_empty());
        assert_eq!(context.dropped(), 2);
        // A held peer still records.
        context.prune_received(held[0], at(3));
        assert_eq!(context.entries(&held[0])[0].count, 2);
        // Once one leaves, a new one fits.
        context.forget(&held[1]);
        context.prune_received(late, at(4));
        assert_eq!(context.entries(&late).len(), 1);
    }

    #[test]
    fn unix_ms_before_the_epoch_is_zero() {
        assert_eq!(unix_ms(UNIX_EPOCH - Duration::from_secs(1)), 0);
        assert_eq!(unix_ms(at(1_234)), 1_234);
    }

    #[test]
    fn layer_records_rate_limits_and_prunes() {
        let peer = PeerId::random();
        let context = recorded(|| {
            // The shapes of the rate limiter's events: `Display` fields.
            tracing::debug!(
                target: "cl_p2p::rpc::limits",
                peer = %peer,
                protocol = %Protocol::PingV1,
                wait_ms = 10_u64,
                "over quota: chunk withheld"
            );
            tracing::debug!(
                target: "cl_p2p::rpc::limits",
                peer = %peer,
                protocol = %Protocol::DataColumnsByRangeV1,
                chunk = 3_u64,
                "over quota: column chunk withheld"
            );
            // The shape of the pinned gossipsub's PRUNE event.
            tracing::debug!(
                target: "libp2p_gossipsub::behaviour",
                peer = %peer,
                "Handling PRUNE message for peer"
            );
            // A plain `&str` peer field reads the same.
            tracing::debug!(
                target: "libp2p_gossipsub::behaviour",
                peer = peer.to_string().as_str(),
                "Handling PRUNE message for peer"
            );
        });
        let entries = context.entries(&peer);
        let summary: Vec<_> = entries
            .iter()
            .map(|e| (e.kind, e.detail, e.count))
            .collect();
        assert_eq!(
            summary,
            [
                (ContextKind::RateLimited, "ping", 1),
                (ContextKind::RateLimited, "data_column_sidecars_by_range", 1),
                (ContextKind::PruneReceived, "", 2),
            ]
        );
        assert_eq!(ContextKind::RateLimited.as_str(), "rate_limited");
        assert_eq!(ContextKind::PruneReceived.as_str(), "prune_received");
    }

    #[test]
    fn layer_records_nothing_else() {
        let peer = PeerId::random();
        let long = format!("{}{}", Protocol::PingV1, "x".repeat(MAX_FIELD_LEN));
        let context = recorded(|| {
            // Another message of the same targets.
            tracing::debug!(target: "cl_p2p::rpc::limits", peer = %peer, protocol = %Protocol::PingV1, "refunded");
            tracing::debug!(
                target: "libp2p_gossipsub::behaviour",
                peer = %peer,
                "Completed PRUNE handling for peer"
            );
            // Another target, another level.
            tracing::debug!(target: "cl_p2p", peer = %peer, "Handling PRUNE message for peer");
            tracing::info!(
                target: "libp2p_gossipsub::behaviour",
                peer = %peer,
                "Handling PRUNE message for peer"
            );
            // No peer, a peer that does not parse, a protocol we do not serve or too long.
            tracing::debug!(target: "libp2p_gossipsub::behaviour", "Handling PRUNE message for peer");
            tracing::debug!(
                target: "libp2p_gossipsub::behaviour",
                peer = "not-a-peer",
                "Handling PRUNE message for peer"
            );
            for protocol in [
                "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy",
                long.as_str(),
            ] {
                tracing::debug!(
                    target: "cl_p2p::rpc::limits",
                    peer = %peer,
                    protocol = %protocol,
                    "over quota: chunk withheld"
                );
            }
            tracing::debug!(target: "cl_p2p::rpc::limits", peer = %peer, "over quota: chunk withheld");
        });
        assert!(
            context.entries(&peer).is_empty(),
            "{:?}",
            context.entries(&peer)
        );
        assert_eq!(context.peers(), 0);
    }
}
