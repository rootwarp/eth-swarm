# cl-discv5

discv5 0.12.0 peer discovery with the `eth2`/`cgc`/`nfd` local record (`src/enr.rs`), and the
`ethswarm.discv5.v1` service stub (contract layer only, every RPC answers `UNIMPLEMENTED`).
`src/service.rs` is the discovery itself; its module docs are the detailed reference.

## Routing-table rules

`NetworkMode` picks the IP rules. Public mode accepts only globally routable addresses (every
address a record advertises must pass); devnet mode also accepts loopback and private ones and
refuses only addresses that can never be contacted (unspecified, broadcast, multicast). The
rules are discv5's `table_filter`, a bare `fn` pointer, so it cannot hold the fork digest.

- **Lookups** (`Discovery::find_peers`) run `find_node_predicate` with the fork digest and the
  IP rules, and check every returned record again.
- **Events** (`Events::next`) surface `Discovered` and `SessionEstablished` only for records
  on our fork digest within the IP rules, and a session only from a source address within the
  IP rules.

## Table eviction

discv5 0.12 skips `table_filter` on some insertions: an incoming session
(`Service::inject_session_established` → `connection_updated`) inserts the peer unchecked, and
`Service::discovered` sends `Event::Discovered` before it applies the filter. `table_filter`
never sees the fork digest, so a record on another fork digest gets in through every path,
`add_enr` included. `Discovery` therefore removes such records itself, through
`Discv5::remove_node`:

- **On the event.** `Events::next` judges the routing-table copy of the peer every
  `Discovered`, `SessionEstablished` and `NodeInserted` event names, and evicts it when it
  fails the IP rules (`ip_rule`) or is on another fork digest or none (`fork_digest`). The
  table's copy is judged, not the event's record, so a peer relaying an old record of a node
  cannot get that node evicted. This runs only while the stream is polled.
- **Periodic sweep.** A task started with the service walks `table_entries_enr()` every
  `DiscoveryConfig::sweep_interval` (`SWEEP_INTERVAL`, 5 s) and evicts by the same rules. It
  is the backstop for an insertion that raised no event, an event dropped from a full event
  channel, or a stream nobody polls. It holds the service weakly and ends with it.
- **Boot nodes.** A record added through `Discovery::add_enr` is exempt from the fork rule
  (boot nodes often carry a stale digest, or none, and are the only seeds until the first
  lookup), never from the IP rules (`add_enr` refuses those anyway).
- **Metric.** `discv5_table_evictions_total{reason="ip_rule"|"fork_digest"}`, one per record
  removed, on the registry passed to `EvictionMetrics::register` (`Discovery::with_metrics`).

Devnet mode is unchanged: loopback and private records stay; only the fork rule and the
never-contactable addresses evict.

### Residual

Between insertion and eviction, a record that fails the rules occupies a routing-table slot,
and discv5 can use it as a query seed and hand it out in its own NODES responses. That window
is at most one sweep interval (5 s by default, plus scheduling delay), and usually ends at the
record's own event. A peer that keeps dialing gets back in on each new session, each time for
at most one more interval. The record is never returned by `find_peers` and never surfaced by
`Events::next` meanwhile. The session's source address is not a table record, so a session
from a refused source whose record passes stays in the table (and is not surfaced).

The full fix is upstream: discv5 running `table_filter` on every insertion, including
`connection_updated` for incoming sessions. A patched discv5 would need a git dependency
outside the `deny.toml` `allow-git` list, so this crate keeps the outer filters and the
eviction instead.
