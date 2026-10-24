# cl-p2p

The `ethswarm.p2p.v1` service stub, the req/resp codec and control protocols (`src/rpc`), the
probe swarm (`transport::build_swarm`, `src/behaviour.rs`), and the `m2a-session` binary, which
dials one pinned reference node and nothing else.

## Probe swarm

`transport::build_swarm(keypair, &cfg, req_resp)` builds the swarm on TCP (`nodelay`), Noise XX
and the muxers yamux then mplex (mplex under the per-connection budget), and listens on every
`cfg.listen_addrs` address, `/ip4/0.0.0.0/tcp/9000` by default; it dials over the same transport.
The behaviour is `connection_limits`, `peer_caps::PeerCaps`, identify (`eth2/1.0.0`, no address
cache: nothing dials an address a peer advertised), the req/resp control protocols (`req_resp`,
an `rpc::inbound::Control`), and gossipsub, which is off here and on in
`transport::build_swarm_with_gossip(keypair, &cfg, req_resp, gossip)` (see [Gossip](#gossip)).
The behaviour is `behaviour::SpecBehaviour<E>`, generic over the preset its `Control<E>`
decodes blocks with; `behaviour::Behaviour` is the one over `Mainnet` (Sepolia, Hoodi), and a
minimal-preset devnet runs it over `Minimal` (the `devnet-probe` crate).
The connection caps (`SwarmConfig::caps`): one established connection per peer, 8 pending
inbound per source (IPv4 address or IPv6 /58), 32 pending inbound in total (`PeerCaps`: the
pinned `connection_limits` has no total pending cap; a place is freed when the handshake ends,
fails or times out), 8 established inbound per IP (IPv6: per /58), 128 established inbound,
160 established in total \[est\]. `SwarmConfig::bypass` lists the peers exempt from all of
them (the reference node): `connection_limits::Behaviour::bypass_peer_id` and the same list in
`PeerCaps`; its pending connection still counts, since the peer ID is not known yet.

The owner's event loop passes every swarm event to `PeerMetrics::observe` and every identify
event to `behaviour::log_identify`. Metrics, on the registry the service passes in:

- `p2p_peers{direction="inbound"|"outbound"}`: established connections by who dialed (one per
  peer, so the peer count).
- `p2p_dial_failures_total{reason}`: `negotiation` (no common security or muxer protocol, or
  any Noise failure but a timeout), `wrong_peer_id`, `denied`, `refused`, `timeout`,
  `transport`, `other`.

Log lines: `negotiated a stream muxer` (`muxer="/yamux/1.0.0"` or `"/mplex/6.7.0"`, `role`) per
connection (`SwarmConfig::muxer_observer`, if set, is told the same muxer and our side),
`connection established` with `peer`, `direction` and `addr`, and identify's
`observed_addr`, the address the peer sees us on (a NAT'd host shows its public address there,
or an address nobody can dial). The peer's identify strings are logged escaped and cut at 128
chars.

## Req/resp control protocols

`rpc::inbound::Control` answers and initiates Status v2, MetaData v3, Ping v1 and Goodbye v1
(consensus-specs v1.7.0-beta.4, `phase0`/`fulu` `p2p-interface.md`), one `rpc::inbound::Duplex`
per protocol: an inbound-only and an outbound-only `request_response` behaviour, each at most 2
open streams per connection, so the peer's two and our two never take each other's slots and
a peer's third concurrent stream is reset. Those, plus `BeaconBlocksByRange` v2 and the column
protocols `DataColumnSidecarsByRange` v1 and `DataColumnSidecarsByRoot` v1, are the only
protocols offered: any other fails multistream-select negotiation, among them the MUST-support
`BeaconBlocksByHead` v1 and `ExecutionPayloadEnvelopesByRange`/`ByRoot` v1 (see
[Deviations](#beaconblocksbyhead-and-the-execution-payload-envelope-protocols-not-served)).

- **Status**: sent first on every connection we dial, and answered on every one. A peer
  Status with another fork digest, or another finalized root at our finalized epoch, gets
  `Goodbye(2)` and the connection is closed once the Goodbye completed. Each verdict is a
  `ControlEvent::Status`, whose `via` says whether the peer's Status was its request (we
  answered) or its response to ours; `ControlEvent::StatusAnswered` follows once our answer to a
  peer's Status request was written to its stream. A failed exchange (a
  timeout, an error chunk) is ignored: the peer is neither valid nor invalid.
- **MetaData**: one snapshot of `ControlConfig::metadata` (`rpc::inbound::MetaDataSource`, from
  cl-chain): the `seq_number` and the fields it numbers are read together, so an answer that
  waits for its rate-limit token never pairs a bumped `seq_number` with old fields, or the
  reverse. No attestation or sync subnets, and `custody_group_count` equal to the ENR `cgc`
  (cl-p2p does not link cl-discv5, so the owner sets both).
- **Ping**: answered with our `seq_number`. A peer `seq_number` above that of the peer MetaData
  we hold, or any while we hold none, triggers one GetMetaData; no second one while it is open.
  A higher one announced while it is open is asked for once more as soon as it ends, if its
  answer is older. We Ping every connected peer 15 s after it connected and then 15 s after
  its last Ping ended (`rpc::inbound::PING_INTERVAL` \[est\], Lighthouse's own cadence), at
  most one in flight per peer, so two Pings are always 15 s apart, inside every client's Ping
  quota (Lighthouse: 2 per 10 s). Pings go out at once, outside the shared outbound lane: one
  per peer is within `MAX_CONCURRENT_REQUESTS`, which the spec counts per peer (`phase0`
  L1228, L1310–1312), and no slow or silent peer can hold back another's. That is what keeps
  a quiet connection up, since the swarm closes one with no open stream after 30 s
  (`transport::DEFAULT_IDLE_CONNECTION_TIMEOUT`, twice the interval).
- **Goodbye**: answered with one chunk carrying the peer's own reason (`phase0` L1461:
  "Request, Response Content: (Uint64)"; L1483: "The response MUST consist of a single
  `response_chunk`"); the connection closes once the peer closed it, or 1 s after the answer
  went out (`rpc::inbound::GOODBYE_LINGER` \[est\]). Our own Goodbye accepts an answer of one
  chunk or none (Lighthouse sends none). Once either side said Goodbye, nothing but our own
  Goodbye goes out to that peer: no Ping, and a request still waiting for a slot is dropped.
- **Custody columns** (`fulu/p2p-interface.md` L605–775): `DataColumnSidecarsByRange` v1 and
  `DataColumnSidecarsByRoot` v1 are answered from cl-chain's column store; cl-p2p opens no
  database. `ControlConfig::columns` is the source (`rpc::columns::ColumnSource`), in the
  service `rpc::columns::ChainColumns`, the `ethswarm.chain.v1.ReqRespService`
  `DataColumnsByRange`/`DataColumnsByRoot` client, whose server is `cl_chain::reqresp`. cl-chain
  answers one chain of linked blocks in `(slot, column_index)` order with every requested
  column of each block it includes, from our `earliest_available_slot` (which also moves past
  any gap the store detects). Each chunk carries the fork digest of its sidecar's slot's epoch
  as context bytes, and every sidecar is decoded by that fork, at its slot and root, before it
  goes out. A sidecar the request did not name is dropped and counted
  (`rpc_column_unrequested_total`). A range starting below `earliest_available_slot`, or before
  `data_column_serve_range`, gets `3: ResourceUnavailable` (L652–656), never an empty success;
  so does every request with no column store. An index at or past 128, more than 16,384
  sidecars, or more than 128 identifiers is `1: InvalidRequest`. Error chunks carry a fixed
  message per code; details stay in the log.
  - **Admission** (`rpc::limits::BookedChunks`): a request books its tokens when it arrives,
    as many sidecars as it names, at most its share of what the quota delivers in 5 s (half,
    for the two streams a peer may open: `RpcLimits::column_answer_sidecars`, 756 by default)
    and what the bucket can still deliver in that window, at least one whole block. Its lookup
    waits until its first token is due, so a peer over its quota costs no lookup; the answer
    goes out at the booked tokens, and those it does not use go back once it is known, moving
    a booking behind it up. A reset gives back nothing.
  - **Places** (`rpc::limits::ColumnPlaces`): at most 8 column answers held at once
    (`RpcLimits::max_column_answers` \[est\], as many as cl-chain's reads), one per peer and 2
    per address block (`max_column_answers_per_ip` \[est\]), from the lookup until the stream's
    writer returns. An address block is an IPv4 /24 or an IPv6 /48
    (`RpcLimits::column_answer_prefixes`, `rpc::answer_bucket` \[est\]), and an IPv4-mapped IPv6
    address counts as its IPv4 address, so one host cannot take more places by using
    neighbouring addresses. Peers of one devnet network (one /24) share their 2 places too. Each holds at most 8 MiB of SSZ (`MAX_COLUMN_RESPONSE_BYTES` \[est\]) and is
    encoded one chunk at a time: an estimated 8.5 MiB per answer with its copies, about 68 MiB
    in all (`rpc_column_answers`, `rpc_column_answer_bytes`). A due chunk not written within
    1 s (`column_write_deadline` \[est\]) resets its stream and frees the place, so a requester
    that stops reading cannot hold one for the 10 s exchange timeout.
  - **Queue**: a request whose tokens are due waits up to 2 s for a place
    (`RpcLimits::column_queue_wait` \[est\]), at most 64 wait (`column_queue_len` \[est\]);
    past either it gets `2: ServerError`, counted in
    `queue_dropped_total{queue="rpc_column_queue"}`. A request waiting for its tokens is never
    refused: it waits until its stream closes. A lookup past 2 s
    (`rpc::inbound::COLUMN_LOOKUP_TIMEOUT` \[est\], cl-chain's read deadline) is
    `2: ServerError`.
  - **Answer budget**: an answer is cut at the last whole block within its sidecars and its
    8 MiB (the first block always goes), the rule cl-chain cuts by too.
  - **Residual: a requester that half-closes, then drops its stream.** A rust-libp2p
    requester that closes its write side and then drops the stream is not seen until our first
    data frame reaches it, so its answer is booked, looked up and cut as for any requester, and
    it pays for the whole cut answer, never less than an honest reader. Seeing it earlier needs
    a request-response handler that watches the stream while the lookup runs; until then this
    stays as is.
  - **Wiring** (`devnet-probe serve`): cl-chain serves `ReqRespService` (`GetStatus`,
    `DataColumnsByRange`, `DataColumnsByRoot`) on its own Unix socket behind its method ACL,
    which lets only the caller `cl-p2p` call those three; the swarm's `ChainColumns` and
    `rpc::chain_status::ChainStatusSource` connect to it through `ipc::uds`'s peer-checked
    connector. Our Status is read from `GetStatus` afresh for every Status we send or answer
    (`StatusSource::fresh`), so its `earliest_available_slot` never lags the store; a read that
    fails or passes its 2 s deadline sends no Status and answers `2: ServerError`, never the
    cached one. The cached Status (refreshed every 12 s, each call within the same deadline)
    is what a peer's Status is judged against. Every table built for serving comes from
    `rpc::network_context_table` and carries the network's caps
    (`NetworkCaps::from_config`): without them every column answer would be
    `2: ServerError`.
- **Rejects**: a request that breaks the wire format gets `1: InvalidRequest` (a Goodbye's
  too), and so does a
  `BeaconBlocksByRange` request with `step` 0 or a `count` above `MAX_REQUEST_BLOCKS_DENEB` (128;
  semantically invalid, `phase0` L1286, L1514, `deneb` L876; the connection stays). `3:
  ResourceUnavailable` goes out only where the protocol specifies it: `BeaconBlocksByRange`,
  answered so on every other request because the probe stores no blocks, and the two column
  protocols. A Status we cannot
  answer (no Status of ours yet) gets `2: ServerError`. Error chunks carry no context bytes.
- **Deadlines** (in the codec, `tokio::time::timeout`, both directions): 5 s to the first
  byte, 5 s per chunk, 10 s in total \[est\]; `request_response`'s own 10 s request timeout is
  only the backstop. A silent inbound stream is dropped at 5 s and holds one of the 2 stream
  slots until then.
- **Rate limits** (`rpc::limits::RateLimiter`, `ControlConfig::limits`): a token bucket per
  peer and protocol, counted in response chunks \[est\]: Status 5 at once then one per 2 s,
  MetaData and Ping 2 then one per 2 s, BeaconBlocksByRange 128 then one per 20 ms, each
  column protocol 512 sidecars then one per 5 ms. A peer
  over its quota gets no error chunk and its stream stays open: the stream's writer
  (`rpc::codec::InboundCodec`) charges each chunk when it is next to go and withholds it until
  its own token is free, then sends it whole (`phase0` L1269–1274). With at most 2 requests
  open, no chunk waits the requester's 5 s first-byte or per-chunk deadline. A chunk that was
  withheld but never sent (the peer left) is refunded; a sent one stays charged, so
  reconnecting does not refill the bucket.
- **Outbound requests** (`rpc::limits::OutboundSemaphore`): at most 2 in flight per protocol
  across the probe (`MAX_CONCURRENT_REQUESTS`, `phase0` L309, L1228); the rest wait in a
  bounded queue per protocol (256), and a full queue IGNOREs the request (an IGNOREd Goodbye
  closes the connection at once). Pings are the exception: one per peer, sent at once, and
  `rpc_outbound_inflight{protocol="ping"}` counts them across peers.
- **Length prefix** (`p2p_wire`): checked against the type's SSZ bounds, both ends, and
  `MAX_PAYLOAD_SIZE` before a byte of the payload is read or allocated
  (`p2p_wire::rpc::protocols::ProtocolLimits`).

### What our Status advertises (probe mode)

The Status comes from cl-chain (`ethswarm.chain.v1.ReqRespService/GetStatus`,
`cl_chain::probe::StatusProvider`; `rpc::inbound::status_from_chain` maps the response):
`fork_digest` is `compute_fork_digest` at the wall-clock epoch (BPO epochs included), the
finalized checkpoint is the reference Beacon API's, and the head is **the finalized block**, not
the reference node's head. The probe imports nothing past finality, so it advertises only what
it can vouch for. `earliest_available_slot` is the slot the probe serves its custody columns
from (`cl_chain::reqresp::ColumnServer::earliest_available_slot`): the highest of the first
stored column slot, the slot after the finalized-slot watermark, the slot `cgc` was set at and
the slot after the last gap in the store (a blob-carrying block it never held), which for a
store filled forward from the slot `cgc` was set at without a gap is that slot
(`fulu/p2p-interface.md` L552–561, `fulu/validator.md` L173–175); the head slot until a column
is stored. It may sit above the head slot for the first epochs after a start (the head is the
finalized block): a recorded deviation, not clamped, since a lower value would claim slots the
probe cannot serve (`cl_chain::probe`). During a reference API outage the last good sample is kept; before the first one there
is no Status, so none is sent and none is judged. The kept sample never moves back: a sample
with a lower finalized epoch or head slot than the kept one (a slow, earlier refresh finishing
after a newer one) is ignored.

Metrics, on the same registry as the peer metrics (`rpc::metrics::RpcMetrics`):

- `rpc_timeouts_total{kind="ttfb"|"per_chunk"|"total"}`: exchanges that failed on a deadline.
- `rpc_invalid_data_total{direction}`: requests (inbound) or responses (outbound) that broke
  the wire format. Timeouts are never counted here.
- `p2p_goodbye_sent_total{reason, status_valid}` and `p2p_goodbye_received_total{reason,
  status_valid}`: `reason` is the code (0–255, else `other`), `status_valid` is `true`,
  `false` or `unknown` (no Status judged yet).
- `p2p_status_valid_peers`: connected peers whose last Status passed.
- `rpc_outbound_inflight{protocol}`: our requests in flight, at most 2 per protocol; Ping
  excepted, up to one per connected peer.
- `rpc_rate_limited_total{protocol}`: response chunks withheld for a peer over its quota.
- `queue_dropped_total{queue}`: items a bounded queue IGNOREd (`rpc_outbound_<protocol>`), and
  column requests refused because the column queue was full or no place freed in time
  (`rpc_column_queue`).
- `rpc_column_answers`, `rpc_column_answer_bytes`: column answers held now and their SSZ
  bytes; `rpc_column_unrequested_total`: sidecars a source handed over that the request did not
  name, dropped.
- `rpc_inbound_unsupported_total{protocol}`: peers' proposals of a protocol we leave
  unregistered, refused at negotiation; counted only with `rpc::unsupported::layer` in the
  tracing subscriber (see
  [Deviations](#beaconblocksbyhead-and-the-execution-payload-envelope-protocols-not-served)).

Every received Goodbye logs one `goodbye_received` line (`peer`, `reason`, `status_valid`,
`direction`, `unix_ms`) and emits one `ControlEvent::GoodbyeReceived`; every sent one logs
`goodbye_sent`.

### Goodbye ledger (exit 10 (a))

`peers::manager::GoodbyeLedger` counts Goodbye reason 3 ("Fault/error", `phase0` L1457–1483)
from Status-valid peers per wall-clock UTC hour. The owner's event loop feeds it each
`ControlEvent` (`observe`: a judged Status, a received Goodbye) and identify event
(`observe_identify`: the agent version), tells it when a peer disconnects and at what time
(`disconnected`), and ticks it every minute or so (`tick`), so every hour gets its line on
time (a skipped hour is still closed, with the peers connected throughout).

- **Rate**: distinct Status-valid peers that sent reason 3 in the hour ÷ distinct Status-valid
  peers seen in it (a peer whose Status passed in the hour, or one still connected and valid
  from an earlier hour). A Goodbye 3 from a peer whose Status failed or was never judged is
  logged, not counted, and a peer that sends two counts once.
- **Threshold**: N = max(2 %, 2 × the hourly p95 of the Sepolia baseline run)
  (`Threshold::from_baseline_p95`), 2 % until that baseline exists \[est, provisional\]. N is
  `goodbye3_threshold_pct` in `peers::manager::GoodbyeLedgerConfig` (a `[goodbye_ledger]` TOML
  table; unknown keys are refused, and N must be 2 to 100). `baseline_p95_pct` gives the hourly
  p95 of the closed hours a run kept.
- **Verdict**: when an hour ends, one `goodbye3_hourly` line: `hour_start_unix`,
  `status_valid_peers`, `goodbye3_senders`, `rate_pct`, `threshold_pct`, `capped`,
  `clock_stepped`, `unobserved` and `verdict`: `pass` (rate ≤ N), `fail` (logged at WARN),
  `no_peers`, or `inconclusive`: the hour's peer set reached its cap, so the rate is over a sample (and the
  hour after one that turned a Status-valid peer away is inconclusive too, until an hour turns
  none away); the wall clock moved more than 60 s away from the monotonic clock within the
  hour (`peers::manager::MAX_CLOCK_SKEW`, re-anchored at each hour close), which closes the open
  hour and opens the new one as stepped; or the ledger went more than 5 min without a call
  (`peers::manager::MAX_CALL_GAP` \[est\]: the probe paused or blocked), which leaves the open
  hour, the hours skipped and the one it resumes in `unobserved`. Only `pass` and `fail` hours
  enter `baseline_p95_pct`.
- **Context**: next to each Goodbye 3, one `goodbye3_received` line (`peer`, `agent`,
  `status_valid`, `direction`, `unix_ms`, `counted`, and the peer's `rate_limited` and
  `prunes_received` totals) and one `goodbye3_context` line per kind and protocol (`kind` is
  `rate_limited` or `prune_received`, with `protocol`, `count`, `first_unix_ms`,
  `last_unix_ms`). These are context only; nothing infers a cause from them. They come from
  `peers::context::layer`, a `tracing` layer the owner adds to its subscriber: it reads the
  rate limiter's `over quota: ... withheld` debug events and the pinned gossipsub's PRUNE event,
  for itself only, and keeps at most one entry per protocol plus one for
  PRUNE for each of at most 256 peers (`peers::context::GoodbyeContext`).
- **Memory**: one hour is open at a time. Its two peer sets hold at most 2,048 peers
  (`max_peers_per_hour` \[est\], up to 16,384): with 160 connections that is every connection
  replaced about 13 times in an hour, and about 400 KiB at about 80 bytes a peer ID. A closed
  hour keeps only its counts, for the last 168 hours (`hours_kept`, up to 720).

## Gossip

`gossip::IgnoreAll::new(&gossip_cfg, &mut registry)` builds the probe's gossipsub (`src/gossip`):
StrictNoSign (`ValidationMode::Anonymous`, `MessageAuthenticity::Anonymous`), manual
validation, the Altair message-id, `max_message_size()` as the RPC cap and the phase0 mesh and
cache parameters. It subscribes exactly `gossip_cfg.topics` (by default only
`/eth2/<fork_digest>/beacon_block/ssz_snappy`), so more topics are configuration, not code.
Topics, the bounded snappy transform and the message-id are `p2p-wire::gossip`: the compressed
data is held to `max_compressed_len(MAX_PAYLOAD_SIZE)`, and the snappy header's declared length
to the topic's SSZ cap before anything is decompressed. The cap is that of the fork the topic's
digest names (`TopicCaps::from_config`, BPO digests included): on a Fulu digest the column
sidecar of the largest Fulu blob limit at or before the digest (45,380 bytes at 21 blobs on
Mainnet; a BPO entry that lowers the limit keeps the larger cap, for late sidecars), on a Gloas
digest `compute_max_data_column_sidecar_size()` (44,072 bytes on Sepolia and Hoodi). A digest
off the schedule, or a Gloas topic under a Fulu digest, has no cap, and its message is refused
unread.

What this crate bounds in the probe's gossipsub:

- **Subscriptions**: per peer, only subscriptions to whitelisted topics, at most 418 plus 4;
  an RPC with more than 418 subscriptions (every topic of two fork digests: a supernode's
  first RPC lists 128 column subnets alone) has its subscriptions ignored. The whitelist is
  the topics we subscribe and, from the start, all 128 `data_column_sidecar_{subnet_id}`
  subnets of each configured fork digest, so a custody subnet subscribed after peers announced
  it still meshes with them without a reconnect. It stays within 418 topics: two digests'
  configured topics plus their 2 × 128 column subnets are a subset of the two digests' topics.
- **Control-message size**: 46,898 bytes of subscriptions and control per RPC, derived from
  the two-fork topic set (418 entries for the longest topic string, 63 bytes) plus gossipsub's
  default 16 KiB for control.
- **Metric labels**: our topics only (`max_never_subscribed_topics` 0).
- **Topics decoded**: the transform decodes and caches only subscribed topics; a message on
  any other topic (another kind, or ours under another fork digest) is refused before its data
  is decompressed.
- **Payloads**: compressed data at most `max_compressed_len(MAX_PAYLOAD_SIZE)`, decompressed
  data at most the topic's SSZ cap at its fork digest, RPCs at most `max_message_size()`.
- **IHAVE**: ignored (`max_ihave_messages_heartbeat` 0). The probe uses mesh push only.

gossipsub's other internal per-peer state is bounded only by upstream's own limits.

## Deviations

### TCP only, no QUIC

`phase0/p2p-interface.md` (consensus-specs v1.7.0-beta.4, §Transport, L154–161): "All
implementations MUST support the QUIC (UDP) libp2p transport and the TCP libp2p transport. Any
supported transport MUST be enabled for both dialing and listening", and "QUIC is the primary
transport. When a peer is reachable over both TCP and QUIC, clients SHOULD prioritise peer's QUIC
addresses."

The probe swarm builds TCP only: it neither dials nor listens on QUIC, and it does not prefer a
peer's QUIC addresses. TCP is enabled both ways, so the "dialing and listening" MUST holds for
the one transport we support. Peers we reach are those with a TCP address, which every client
must have; a QUIC-only peer is out of reach. Closed by
[#154](https://github.com/rootwarp/eth-swarm/issues/154): QUIC dial and listen next to TCP on
IPv4, with at least one peer each way.

### BeaconBlocksByHead and the execution payload envelope protocols not served

Probe-only. These protocols are MUST-support for the forks the probe joins, and the probe
serves none of them:

- `/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy`: `fulu/p2p-interface.md`
  (consensus-specs v1.7.0-beta.4, §BeaconBlocksByHead v1, L796–863): "Clients MUST support
  requesting blocks on the epoch range `[current_epoch - compute_min_epochs_for_block_requests(),
  current_epoch]`" (L835–836) and "Clients MUST respond with at least one block, if they have
  the block at `beacon_root`" (L840–841).
- `/eth2/beacon_chain/req/execution_payload_envelopes_by_range/1/ssz_snappy`:
  `gloas/p2p-interface.md` (§ExecutionPayloadEnvelopesByRange v1, L1396): its rules are those
  of BeaconBlocksByRange v2 with envelopes for blocks, so "Clients MUST keep a record of signed
  blocks seen on the epoch range … and clients MUST support serving requests of blocks on this
  range" (`phase0` L1527–1530), and "Clients MUST respond with execution payload envelopes from
  their view of the current fork choice" (L1422–1423).
- `/eth2/beacon_chain/req/execution_payload_envelopes_by_root/1/ssz_snappy`:
  `gloas/p2p-interface.md` (§ExecutionPayloadEnvelopesByRoot v1, L1446): "Clients MUST support
  requesting payload envelopes on the epoch range" (L1483), "MUST also keep a record of all
  payload envelopes more recent than their latest finalized checkpoint and MUST support serving
  requests of these payload envelopes" (L1489–1491), and "MUST respond with at least one
  payload envelope, if they have it" (L1493).

The probe registers none of the three ids, so a peer's request fails multistream-select
negotiation (`phase0` L187–196): the probe answers the proposal `na`, no handler sees a stream,
and the connection stays up. No error chunk is sent: `3: ResourceUnavailable` is only valid
where a protocol specifies it, not as a generic "unsupported" answer. The probe stores no
blocks and no envelopes, so it has nothing to serve on them anyway.

Each refused proposal of one of the three ids counts in
`rpc_inbound_unsupported_total{protocol}` (`beacon_blocks_by_head`,
`execution_payload_envelopes_by_range`, `execution_payload_envelopes_by_root`), so the probe
shows how often peers ask. The pinned rust-libp2p reports a failed inbound negotiation to no
behaviour or handler, and names the refused protocol only in `multistream_select`'s
`Listener: rejecting protocol` debug event, so the count is taken from that event:
`rpc::unsupported::layer(metrics)` is a `tracing` layer the owner adds to its subscriber
(without it the counter stays at 0). It enables that one debug event for itself only, and its
label set is the three names above, whatever a peer proposes.

`rpc::tests::unsupported_ids_stay_unregistered` lists the three ids. Closed by [6.42] and
[6.19b], which register these protocols and take them off that list, `rpc::unsupported` and
this section together.

## m2a-session

The session runs as its own OS user, has no listener and no discovery, and dials only the peer
pinned in `/etc/ethswarm/m2a-session.toml`. Noise must prove the pinned peer ID, or the dial
fails with `wrong peer ID` and no connection stays open.

The session runs in production on Linux only. On macOS, `initgroups` adds system groups (12,
61, 100, 701 and others) to every user, which the supplementary-group rule below refuses, so the
production binary refuses to run on any other platform. It checks the platform right after the
process IDs, before it reads the config, so the error names the platform.

The pre-flight checks the OS identity before anything else:

1. It refuses an effective UID of root. It also refuses a real or saved UID that differs from
   the effective UID (as after `setpriv --euid` from root), because the process could switch
   back. It refuses a GID of 0 and a real or saved GID that differs from the effective GID (as
   after `setpriv --reuid` without `--regid`). Linux reads all three IDs with `getresuid` and
   `getresgid`. macOS cannot read the saved IDs, so there only the real and effective IDs are
   compared. These checks run before the config is read and before any name-service lookup.
2. It refuses a config on a path that the session user could change. The path is walked from
   `/` without following a symlink. Each directory on it and the file must be owned by root.
   No directory may be writable by the session's effective UID, nor by group or others unless
   sticky, and the file must not be writable by that UID, group or others. Install it owned by
   root, mode 0644, in a root-owned directory. Only the mode bits are read, not ACLs.
3. It refuses a `run_as` other than the session account `m2a-session`.
4. It finds the UID and primary GID of `run_as` with `getpwnam_r`, through the system's name
   service, and refuses a `run_as` that the system does not know. It refuses every effective
   UID other than that UID, an effective GID other than that GID, and supplementary groups
   other than that GID.

So a run under a shared login account, which can hold SSH keys or the reference node's `.env`,
does not start, even with that account's own 0600 key and its own config. The `m2a-summary`
line names the user and its UID (`os_user`, `euid`), and `own_os_user` passes only for
`m2a-session`.

### Build

Build and install the deployed binary (root-owned, not writable by the session user):

```bash
cargo build --release --locked -p cl-p2p --bin m2a-session
sudo install -o root -g root -m 0755 target/release/m2a-session /usr/local/bin/m2a-session
```

`m2a-session` always runs the strict pre-flight above. The same code is also built as the test
binary `m2a-session-test`, only with the cargo feature `test-run-as`, which only cl-p2p's own
dev-dependency turns on (so `cargo test` and `cargo build --all-targets` build it). The test
binary takes a `run_as` other than `m2a-session` with that user's groups, accepts a config the
test user owns, and runs on any platform. Its first log line says `TEST BUILD`, its summary has
`"test_build": true`, and that summary fails its `production_build` check, so a gate that reads
the summary fails a test-binary run. Never deploy it.

`build.rs` also records the build commit (git's `HEAD`), the commit hash of the compiler
(`rustc -vV`) and if the build was clean. The build is clean only if four conditions are true:

- The build paths have no uncommitted change, no untracked or ignored file and no
  assume-unchanged or skip-worktree flag. The build paths are `Cargo.toml`, `Cargo.lock`,
  `rust-toolchain.toml`, `.cargo`, `proto` and the crates that the binaries compile
  (`BUILD_PATHS` in `build_support.rs`, held to cargo's resolve by a test).
- No rustflags variable, rustc wrapper or linker is set (`RUSTFLAGS`,
  `CARGO_ENCODED_RUSTFLAGS`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER` or `RUSTC_LINKER`).
  Cargo gives the build script these values from each cargo config, also one outside the
  repository, and from `CARGO_TARGET_<triple>_LINKER`.
- No C or proto build variable is set (`CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, `AR`, `ARFLAGS`, also
  with a target suffix or as `TARGET_<name>` and `HOST_<name>`, `CRATE_CC_NO_DEFAULTS` and
  `PROTOC`). They change the C code of ring and blst, and the proto build.
- The compiler is the official pinned one. Its release (`$RUSTC -vV`) is the `channel` of
  `rust-toolchain.toml`, its commit hash is the one of `PINNED_RUSTC` in `build_support.rs`, and
  `RUSTC` (and `CARGO_BUILD_RUSTC`, if set) is, by its canonical path, the `rustc` of the rustup
  toolchain `<channel>-*` under `$RUSTUP_HOME` (default `~/.rustup`). `RUSTC`,
  `RUSTUP_TOOLCHAIN`, a rustup override, `cargo +<toolchain>` or a wrapper can replace the pin.
  Change `PINNED_RUSTC` together with `rust-toolchain.toml`: a test fails if they differ.

The Status probe refuses to dial with a build that was not clean. The summary writes the values
as `build_commit`, `build_rustc_commit` and `build_dirty`. Its `clean_build` check fails a
binary whose build was not clean, or that had no git checkout. Build the deployed binary from
a clean checkout: `build_commit` is then the commit that you post.

### Node key

The reference node trusts one peer ID, so the session needs a stable key, not an ephemeral one.
The key file holds the raw 32-byte secp256k1 secret, mode 0600, owned by the session user:

```sh
sudo -u m2a-session sh -c 'umask 077 && head -c 32 /dev/urandom > /var/lib/m2a-session/node.key'
sudo -u m2a-session m2a-session --print-peer-id    # prints 16Uiu2HAm…, no network contact
```

`--print-peer-id` reads `node_key` from the config, runs the same pre-flight as a session and
prints the peer ID on stdout.

### Config

```toml
# /etc/ethswarm/m2a-session.toml
network = "sepolia"
# The reference node, its peer ID from its /eth/v1/node/identity.
peer = "/ip4/192.0.2.10/tcp/9000/p2p/16Uiu2HAm…"
# The reference node's beacon API: plain HTTP on loopback only (localhost, 127.0.0.0/8, [::1]).
# For a remote node, tunnel it on loopback only:
# ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:5052:127.0.0.1:5052 ref-host
reference_api_url = "http://127.0.0.1:5052"
node_key = "/var/lib/m2a-session/node.key"
# The reference node lists our peer ID as trusted; refused without node_key.
trusted_by_reference = true
# The OS user the session runs as: the default shown, the only value a release build takes.
run_as = "m2a-session"

[deadlines]           # optional; milliseconds, the defaults shown
ttfb_ms = 5000
total_ms = 10000      # at most 10000
per_chunk_ms = 5000
```

Exactly one peer: `peer = "<multiaddr>"` or a `[peer]` table with one `multiaddr` key. A list,
a second peer or an unknown key is refused. `reference_api_url` (needed only by the Status
probe, not by `--dial-only`) must be `http://` to a loopback host, because the probe's verdicts
rest on its answers and plaintext over any other path could be forged on the way. `localhost`
is taken as 127.0.0.1, then ::1, and never looked up. The full rules are in
`src/m2a_session/config.rs`.

### Reference node (ops)

List our peer ID as trusted, so the reference node does not descore us for refusing its inbound
MetaData and Ping requests. For Lighthouse:

```sh
lighthouse bn --network sepolia --trusted-peers 16Uiu2HAm…   # the --print-peer-id output
```

Its p2p TCP port must be reachable from the test host:

```sh
nc -z 192.0.2.10 9000
```

### Status probe (default mode)

```sh
sudo -u m2a-session m2a-session                       # --gate-file <path> to point at the gate
```

Pre-flight first, before any dial:

- the build must be clean (see [Build](#build)): the binary refuses to dial with a build tree
  that was not clean, with a rustflags variable, a rustc wrapper, a linker or a C build
  variable set, with a compiler other than the official pinned one, or with no build commit.
  A session from such a build would fail its `clean_build` check only at the end.
- the fuzz gate file (`fuzz/run-m2a-gate.sh`; default `fuzz/artifacts/m2a-gate.json` of the
  checkout the binary was built in) must pass `fuzz/check-m2a-gate.sh`'s rules for the decoders
  this binary was built from. `build.rs` embeds `check-m2a-gate.sh --print-expected` of the
  build tree, `heads` included: the file's `head` must be the build's commit or an ancestor of
  it with the same decoder key (the script checks the same with git), so the file names a
  commit that was fuzzed. The cl-p2p library from its crate root `lib.rs`, every module that a
  keyed file imports, and each workspace crate that keyed code imports (or a written reason why
  not) are in the key (`crates/ci-checks/tests/fuzz_keys.rs` checks this), so a
  gate file written before they were keyed is stale and the gate has to be run again. A dirty
  keyed path, or a tree without the fuzz harness, embeds no expectations, and every gate file is
  refused. So does a build outside its git checkout
  (`cargo package`, a tarball, or `GIT_DIR`/`GIT_WORK_TREE` pointing elsewhere: the build
  script ignores them).
  git runs with no system or global config, so a checkout owned by another user (which needs
  `safe.directory`) also embeds no expectations.

Then: dial; check the reference API's `/eth/v1/beacon/genesis` against the pinned Sepolia
genesis; read the `eth2` digest of the node's ENR (`/eth/v1/node/identity`); sample the API
(finalized checkpoint, its block, the head); send our Status v2 at
`compute_fork_digest(genesis_validators_root, current_epoch)`; sample again (once more, with
a fresh Status, if finality moved in between); judge the peer's Status. On the same
connection: sample the node's MetaData (`/eth/v1/node/identity`), request the peer's MetaData
v3, sample again (once more if `seq_number` moved in between), and judge it field by field.
Then hold the connection 10 s and send a second Status on it (built afresh, so a hold across a
digest boundary sends the new digest).

One JSON line per step on stdout. Logs go to stderr as svc-runtime's JSON lines, through its
bounded writer: a stderr nobody reads drops lines instead of stalling the session. The
`m2a-status` line records both Status values, the digest
inputs (epoch, fork, fork version, blob parameters, genesis validators root), the ENR digest,
both API samples, the peer's `earliest_available_slot` and a verdict per field (`genesis`,
`fork_digest`, `enr_fork_digest`, `finalized_root`, `finalized_epoch`, `head_root`,
`head_slot`, `earliest_available_slot`, `connection`). The `m2a-metadata` line records the
peer's MetaData, both API samples (in the beacon API's encoding: decimal strings, `0x` hex
bitvectors), the re-run count and a verdict per field (`seq_number`, `attnets`, `syncnets`,
`custody_group_count`). Exit 0 only if every verdict of both steps passed.

### Dial check

```sh
sudo -u m2a-session m2a-session --dial-only
```

TCP, Noise XX with the pinned peer ID checked, yamux, then a disconnect. No req/resp traffic.
Exit 0 on success, 1 if the dial fails or times out (`--connect-timeout-secs`, default 30), 2 on
bad arguments, a refused config or a failed pre-flight.
