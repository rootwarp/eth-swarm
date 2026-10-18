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
a peer's third concurrent stream is reset. Those, plus `BeaconBlocksByRange` v2, are the only
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
- **Rejects**: a request that breaks the wire format gets `1: InvalidRequest` (a Goodbye's
  too), and so does a
  `BeaconBlocksByRange` request with `step` 0 or a `count` above `MAX_REQUEST_BLOCKS_DENEB` (128;
  semantically invalid, `phase0` L1286, L1514, `deneb` L876; the connection stays). `3:
  ResourceUnavailable` goes out only where the protocol specifies it: `BeaconBlocksByRange`,
  answered so on every other request because the probe stores no blocks. A Status we cannot
  answer (no Status of ours yet) gets `2: ServerError`. Error chunks carry no context bytes.
- **Deadlines** (in the codec, `tokio::time::timeout`, both directions): 5 s to the first
  byte, 5 s per chunk, 10 s in total \[est\]; `request_response`'s own 10 s request timeout is
  only the backstop. A silent inbound stream is dropped at 5 s and holds one of the 2 stream
  slots until then.
- **Rate limits** (`rpc::limits::RateLimiter`, `ControlConfig::limits`): a token bucket per
  peer and protocol, counted in response chunks \[est\]: Status 5 at once then one per 2 s,
  MetaData and Ping 2 then one per 2 s, BeaconBlocksByRange 128 then one per 20 ms. A peer
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
it can vouch for; `earliest_available_slot` is that head slot until the probe serves ranges of
its own. During a reference API outage the last good sample is kept; before the first one there
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
- `queue_dropped_total{queue}`: items a bounded queue IGNOREd (`rpc_outbound_<protocol>`).
- `rpc_inbound_unsupported_total{protocol}`: peers' proposals of a protocol we leave
  unregistered, refused at negotiation; counted only with `rpc::unsupported::layer` in the
  tracing subscriber (see
  [Deviations](#beaconblocksbyhead-and-the-execution-payload-envelope-protocols-not-served)).

Every received Goodbye logs one `goodbye_received` line (`peer`, `reason`, `status_valid`,
`direction`, `unix_ms`) and emits one `ControlEvent::GoodbyeReceived`; every sent one logs
`goodbye_sent`.

## Gossip

`gossip::IgnoreAll::new(&gossip_cfg, &mut registry)` builds the probe's gossipsub (`src/gossip`):
StrictNoSign (`ValidationMode::Anonymous`, `MessageAuthenticity::Anonymous`), manual
validation, the Altair message-id, `max_message_size()` as the RPC cap and the phase0 mesh and
cache parameters. It subscribes exactly `gossip_cfg.topics` (by default only
`/eth2/<fork_digest>/beacon_block/ssz_snappy`), so more topics are configuration, not code.
Topics, the bounded snappy transform and the message-id are `p2p-wire::gossip`: the compressed
data is held to `max_compressed_len(MAX_PAYLOAD_SIZE)`, and the snappy header's declared length
to the topic's Gloas SSZ cap before anything is decompressed.

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
  data at most the topic's Gloas SSZ cap, RPCs at most `max_message_size()`.
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

The session runs as its own OS user (it refuses root), has no listener and no discovery, and
dials only the peer pinned in `/etc/ethswarm/m2a-session.toml`. Noise must prove the pinned
peer ID, or the dial fails with `wrong peer ID` and no connection stays open.

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
# For a remote node, tunnel it: ssh -N -L 5052:127.0.0.1:5052 ref-host
reference_api_url = "http://127.0.0.1:5052"
node_key = "/var/lib/m2a-session/node.key"
# The reference node lists our peer ID as trusted; refused without node_key.
trusted_by_reference = true

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

- the fuzz gate file (`fuzz/run-m2a-gate.sh`; default `fuzz/artifacts/m2a-gate.json` of the
  checkout the binary was built in) must pass `fuzz/check-m2a-gate.sh`'s rules for the decoders
  this binary was built from. `build.rs` embeds `check-m2a-gate.sh --print-expected` of the
  build tree, `heads` included: the file's `head` must be the build's commit or an ancestor of
  it with the same decoder key (the script checks the same with git), so the file names a
  commit that was fuzzed. `crates/cl-p2p/src/rpc/unsupported.rs` (which `rpc/metrics.rs`
  imports) is in the key, so a gate file written before it was keyed is stale and the gate has
  to be run again. A dirty keyed path, or a tree without the fuzz harness, embeds no
  expectations, and every gate file is refused. So does a build outside its git checkout
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

One JSON line per step on stdout. The `m2a-status` line records both Status values, the digest
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
