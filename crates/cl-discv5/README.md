# cl-discv5

discv5 0.12.0 peer discovery with the `eth2`/`cgc`/`nfd` local record (`src/enr.rs`), and the
`ethswarm.discv5.v1` service. `src/service.rs` is the discovery itself; its module docs are the
detailed reference. `src/server.rs` serves `WatchPeers`, `GetLocalEnr` and `FindPeers` to
cl-p2p (`UpdateEnr` is still a stub), and `src/process.rs` is the `cl-discv5` process that
`ops/probe/ethswarm-discv5.service` runs.

## FindPeers

`FindPeers` (`src/subnet_query.rs`, served by `src/server.rs`) runs a lookup for the peers that
serve at least one wanted attestation subnet (`attnets`), sync-committee subnet (`syncnets`) or
custody column. A peer's custody columns are `das::custody_columns` of its node ID and `cgc`; a
record without `cgc` counts as `CUSTODY_REQUIREMENT` (4), an empty one as 0 (no column), and one
above 128 or not in its canonical form matches nothing. The predicate is ANDed with the fork and
IP filter inside the lookup, and every result is checked against both again.

- **Request.** Every index below its count (64, 4, 128), at least one wanted, `target` at least
  1 (capped at 16); otherwise `INVALID_ARGUMENT`, before any frame. `fork_digest` empty means
  ours; another 4-byte digest is `FAILED_PRECONDITION`, another length `INVALID_ARGUMENT`.
- **Answer.** Our hello, then the dialable candidates ranked by coverage (how many wanted
  subnets and columns each serves, ties in node ID order), at most `target`, then the end.
- **Bounds.** At most two lookups run at once (the periodic lookups are not counted); a request
  waits for one until its `grpc-timeout` passes (`DEADLINE_EXCEEDED`), or without one until the
  client goes. The ranked peers of up to 64 queries are cached for the rest of the slot (from
  the network config's genesis time and slot duration) and our fork digest; a full cache drops
  its oldest query.

## Routing-table rules

`NetworkMode` picks the IP rules. Public mode accepts only globally routable addresses (every
address a record advertises must pass); devnet mode also accepts loopback and private ones and
refuses only addresses that can never be contacted (unspecified, broadcast, multicast); local
mode accepts local addresses only (`is_local_ip`: loopback, RFC 1918, link-local, CGNAT, IPv6
unique-local and link-local), so a node on a devnet's own network (the devnet probe) never
queries or pings a public host, whatever record a peer hands it. The
rules are discv5's `table_filter`, a bare `fn` pointer, so it cannot hold the fork digest.

- **Lookups** (`Discovery::find_peers_matching`, `Discovery::find_peers` for any peer) run
  `find_node_predicate` with the fork digest, the IP rules and the lookup's own predicate, and
  check every returned record against them again.
- **Events** (`Events::next`) surface `Discovered` and `SessionEstablished` only for records
  on our fork digest within the IP rules, and a session only from a source address within the
  IP rules.

## Table eviction

discv5 0.12 skips `table_filter` on some insertions: an incoming session
(`Service::inject_session_established` → `connection_updated`) inserts the peer unchecked, and
`Service::discovered` sends `Event::Discovered` before it applies the filter. `table_filter`
never sees the fork digest, so a record on another fork digest gets in through every path,
`add_enr` included. `Discovery` therefore removes such records itself. Each judgement and its
removal run under one write lock of the routing table (`Discv5::with_kbuckets`), on the entry
the table holds at that moment. A newer conforming record that lands meanwhile is never removed
for what an older one carried. The counter moves under the same lock, so nobody sees the removal
before the count.

- **On the event.** `Events::next` judges the routing-table copy of the peer every
  `Discovered`, `SessionEstablished` and `NodeInserted` event names, and evicts it when it
  fails the IP rules (`ip_rule`) or is on another fork digest or none (`fork_digest`). The
  table's copy is judged, not the event's record, so a peer relaying an old record of a node
  cannot get that node evicted. This runs only while the stream is polled.
- **Periodic sweep.** A task walks the whole table every `DiscoveryConfig::sweep_interval`
  (`SWEEP_INTERVAL`, 5 s) and evicts by the same rules. It is the backstop for an insertion
  that raised no event, an event dropped from a full event channel, or a stream nobody polls.
  It starts as soon as discv5 runs, before the event stream opens. A `Discovery::start` dropped
  while it waits for the stream still leaves discv5 swept, and a retry only opens the stream.
  Dropping the `Discovery` aborts it.
- **Fork digest.** The fork rule reads the local record's `eth2` each time, so it follows a
  local-record update at a fork or BPO boundary. A local `eth2` that stops decoding keeps the
  digest last read.
- **Boot nodes.** A record added through `Discovery::add_enr` is exempt from the fork rule
  (boot nodes often carry a stale digest, or none, and are the only seeds until the first
  lookup), never from the IP rules (`add_enr` refuses those anyway). `add_enr` holds the
  exemptions across the insertion and its rollback, so a failing call cannot drop an exemption
  that a concurrent call for the same node set.
- **Metric.** `discv5_table_evictions_total{reason="ip_rule"|"fork_digest"}`, one per record
  removed, on the registry passed to `EvictionMetrics::register` (`Discovery::with_metrics`).
  The binary registers it on the service's registry without a prefix, so `/metrics` shows it
  under this name (`process::serve`).

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

Pending kbucket entries are out of eviction's reach. When a bucket is full, discv5 keeps one
candidate for it in a pending slot, and an incoming session can put a refused peer there. discv5
0.12 lets the table show that entry but has no way to clear it: `PendingEntry::remove` only
removes bucket nodes. So the refused peer holds the pending slot until discv5 promotes it, after
its pending timeout (60 s), or drops it. While pending it is no lookup seed and is in no NODES
response, but it keeps a conforming candidate out of the slot. Once promoted, its
`NodeInserted` event or the next sweep evicts it. The sweep's own table walk promotes due
entries, and it judges them under the same lock.

The full fix is upstream: discv5 running `table_filter` on every insertion, including
`connection_updated` for incoming sessions. A patched discv5 would need a git dependency
outside the `deny.toml` `allow-git` list, so this crate keeps the outer filters and the
eviction instead.
