# cl-p2p

The `ethswarm.p2p.v1` service stub, the outbound req/resp codec (`src/rpc`), the probe swarm
(`transport::build_swarm`, `src/behaviour.rs`), and the `m2a-session` binary, which dials one
pinned reference node and nothing else.

## Probe swarm

`transport::build_swarm(keypair, &cfg)` builds the swarm on TCP (`nodelay`), Noise XX and the
muxers yamux then mplex (mplex under the per-connection budget), and listens on every
`cfg.listen_addrs` address, `/ip4/0.0.0.0/tcp/9000` by default; it dials over the same transport.
The behaviour is `connection_limits`, identify (`eth2/1.0.0`, no address cache: nothing dials
an address a peer advertised), and placeholder slots for req/resp and gossipsub. The connection
caps (`SwarmConfig::caps`): one established connection per peer, 8 pending inbound per source
(IPv4 address or IPv6 /58; the pinned `connection_limits` has no total pending cap), 128
established inbound, 160 established in total.

The owner's event loop passes every swarm event to `PeerMetrics::observe` and every identify
event to `behaviour::log_identify`. Metrics, on the registry the service passes in:

- `p2p_peers{direction="inbound"|"outbound"}`: established connections by who dialed (one per
  peer, so the peer count).
- `p2p_dial_failures_total{reason}`: `negotiation` (no common security or muxer protocol, or
  any Noise failure but a timeout), `wrong_peer_id`, `denied`, `refused`, `timeout`,
  `transport`, `other`.

Log lines: `negotiated a stream muxer` (`muxer="/yamux/1.0.0"` or `"/mplex/6.7.0"`, `role`) per
connection, `connection established` with `peer`, `direction` and `addr`, and identify's
`observed_addr`, the address the peer sees us on (a NAT'd host shows its public address there,
or an address nobody can dial). The peer's identify strings are logged escaped and cut at 128
chars.

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
  build tree; a dirty keyed path, or a tree without the fuzz harness, embeds no expectations,
  and every gate file is refused. So does a build outside its git checkout (`cargo package`,
  a tarball, or `GIT_DIR`/`GIT_WORK_TREE` pointing elsewhere: the build script ignores them).
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
