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
reference_api_url = "http://192.0.2.10:5052"
node_key = "/var/lib/m2a-session/node.key"
# The reference node lists our peer ID as trusted; refused without node_key.
trusted_by_reference = true

[deadlines]           # optional; milliseconds, the defaults shown
ttfb_ms = 5000
total_ms = 10000      # at most 10000
per_chunk_ms = 5000
```

Exactly one peer: `peer = "<multiaddr>"` or a `[peer]` table with one `multiaddr` key. A list,
a second peer or an unknown key is refused. The full rules are in
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

### Dial check

```sh
sudo -u m2a-session m2a-session --dial-only
```

TCP, Noise XX with the pinned peer ID checked, yamux, then a disconnect. No req/resp traffic.
Exit 0 on success, 1 if the dial fails or times out (`--connect-timeout-secs`, default 30), 2 on
bad arguments, a refused config or a failed pre-flight.
