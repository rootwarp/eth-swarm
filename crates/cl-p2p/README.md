# cl-p2p

The `ethswarm.p2p.v1` service stub, the outbound req/resp codec (`src/rpc`), and the
`m2a-session` binary, which dials one pinned reference node and nothing else.

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
a fresh Status, if finality moved in between); judge the peer's Status; hold the connection
10 s and send a second Status on it (built afresh, so a hold across a digest boundary sends the
new digest).

One JSON line on stdout records both Status values, the digest inputs (epoch, fork, fork
version, blob parameters, genesis validators root), the ENR digest, both API samples, the peer's
`earliest_available_slot` and a verdict per field (`genesis`, `fork_digest`, `enr_fork_digest`,
`finalized_root`, `finalized_epoch`, `head_root`, `head_slot`, `earliest_available_slot`,
`connection`). Exit 0 only if every verdict passed.

### Dial check

```sh
sudo -u m2a-session m2a-session --dial-only
```

TCP, Noise XX with the pinned peer ID checked, yamux, then a disconnect. No req/resp traffic.
Exit 0 on success, 1 if the dial fails or times out (`--connect-timeout-secs`, default 30), 2 on
bad arguments, a refused config or a failed pre-flight.
