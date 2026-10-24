# Arrival collector (Hoodi and Sepolia reference nodes)

`collector` (`crates/testkit/src/bin/collector.rs`, library `testkit::collector`) records when
each message of the exit-14 topic set arrived (blocks, execution payload envelopes, bids, PTC
messages, aggregates, the sampled attestation subnets and the custody data columns), on a
monotonic and a wall clock, stamped before anything decodes it. On the reference host it reads a
node's `/eth/v1/events` stream; our probe's gossip tap feeds the same collector once the probe
has one. Offsets are computed from the records afterwards with `collector offsets`, and messages
and bytes per slot with `collector rates`.

The systemd template `ethswarm-collector@.service` runs one instance per network,
`ethswarm-collector@hoodi` and `ethswarm-collector@sepolia`, with the same hardening as the
probe units; each may only reach loopback (`IPAddressAllow=localhost`): its node's beacon API
and chronyd on `127.0.0.1:323`. Each instance runs as its own system user,
`ethswarm-collector-<network>`, so neither can read or write the other's captures (one shared
user could, even through `/proc/<pid>/root`, which `ProtectProc=invisible` hides only from
other users). The unit names no node. Each instance reads three files:

| File | Hoodi | Sepolia |
|---|---|---|
| `/etc/ethswarm/collector-<network>.env` (root, 0644) | `collector-hoodi.env.example` | `collector-sepolia.env.example` |
| `COLLECTOR_NETWORK` | `hoodi` | `sepolia` |
| `COLLECTOR_OUT` | `/var/lib/ethswarm-collector/hoodi` | `/var/lib/ethswarm-collector/sepolia` |
| `COLLECTOR_NTP` | `chrony` | `chrony` |
| `/etc/ethswarm/collector-<network>.url` (the instance user's, 0600) | `collector-hoodi.url.example` | `collector-sepolia.url.example` |
| its one line | `http://127.0.0.1:5053` | `http://127.0.0.1:5052` |
| `/etc/ethswarm/collector-<network>.topics.toml` (root, 0644) | `collector-hoodi.topics.toml.example` | `collector-sepolia.topics.toml.example` |
| `sse_events`, `attestation_subnets` | the exit-14 set; the node's subnets | the exit-14 set; the node's subnets |

The topics file is data for the binary (`--topics-file`), not part of the environment, so the
env file keeps its three keys and its grammar (below). The collector opens it the way it opens
the URL file and refuses it unless it is a regular file owned by root (or the instance user)
that group and others may not write, of known event names only; see [Topic set](#topic-set).

The URL file is the only place the reference URL may carry a key: the unit passes its path
(`--url-file`), never the URL, because `/proc/<pid>/cmdline` is readable by every user. The
collector opens it without following a symlink and without blocking (`O_NOFOLLOW | O_NONBLOCK`,
so a FIFO at the path is refused at once instead of hanging the start), after an `lstat` that
refuses anything but a regular file (a device node at the path is never opened), then checks the
open file: a regular file, the one the path named, owned by the user the collector runs as, that
neither group nor others may access (0600 or 0400). It never prints what the file holds; an
error names the path and the reason only.

The env file holds no secret, and the unit's guard keeps it inside a grammar small enough that
the guard and systemd's `EnvironmentFile=` parser read it the same way. It refuses the whole
file otherwise, rather than guess what systemd would make of it:

- **Bytes:** LF and printable ASCII only, and no quote (`"`, `'`) or backslash, comments
  included. systemd also ends a line at a bare CR, and unquotes, unescapes and joins continued
  lines, so any of those could hide a line such as `LD_PRELOAD=…` or `STATE_DIRECTORY=…` from a
  line-by-line check (`#c<CR>LD_PRELOAD=…` would pass as a comment).
- **Lines:** empty, a `#` comment, or `COLLECTOR_NETWORK`, `COLLECTOR_OUT` or `COLLECTOR_NTP`,
  `=`, and a value of `A-Z a-z 0-9 . _ / -`, each of the three exactly once. No `export`, no
  spaces, no `;` comment, no other key: `STATE_DIRECTORY` above all (an env file value would
  override the one systemd sets), and `PATH`.
- **Values:** `COLLECTOR_NETWORK` is the instance name and `COLLECTOR_OUT` its own state
  directory, compared with the literal lines.

The guard checks the file, never the environment systemd built from it: it runs under
`/usr/bin/env -i`, every tool by its absolute path, so even a `PATH=` line could not make it run
a planted binary.

The guard does not protect systemd's own reading of the file. systemd reads the env file for
`EnvironmentFile=` before the guard runs, before the guard has checked a byte of it, so
`env -i` protects only the guard's shell and the tools it starts. What keeps a hostile line out
of the file is its permissions: the env file and `/etc/ethswarm` must stay root-owned and
writable by root only (`install -o root -g root -m 0644` and `-m 0755` below). Check them after
any change: `stat -c '%U:%G %a %n' /etc/ethswarm /etc/ethswarm/collector-*.env`.

The ports are the `ops/ref-node` defaults (`BEACON_API_PORT`): the reference-node stack runs
Sepolia and Hoodi side by side on one host, Sepolia's beacon API on 5052 and Hoodi's on 5053.
A collector reading the wrong one would record the other network's events under its own name,
so it is refused three times over:

- the unit's `ExecStartPre` guard stops an instance whose env file names another network, sets
  an unknown key, leaves the grammar above, or writes anywhere but the instance's own state
  directory `/var/lib/ethswarm-collector/<network>` (compared with that literal path);
- the collector refuses a node whose `/eth/v1/config/spec` `CONFIG_NAME` is not
  `COLLECTOR_NETWORK` (`the node's CONFIG_NAME is sepolia, not hoodi`), and a node without the
  spec endpoint;
- for Sepolia, whose genesis is pinned, it also refuses a node with another `genesis_time`.
  Hoodi's genesis is read from the node, so `CONFIG_NAME` is what catches Sepolia's port there.

`/var/lib/ethswarm-collector` itself stays root-owned, mode 0755, as systemd creates it; only
each instance's directory below it is the instance user's (0750).

`ops/collector/tests/collector-unit.test.sh` (CI) checks the template's hardening, users, env,
URL and topics files, guard and state directory, that it holds no URL, that each example URL's
port is the ref-node default, that each example topics file holds the exit-14 events and sampled
subnets, and this README's migration, topics file install and root-ownership note. It runs the
guard on env files with a CR, NUL, TAB, VT, FF, non-ASCII byte, quote, backslash, continuation,
`export` or `PATH=` line, each of which it must refuse, the last without running a tool from
that `PATH`.

## Topic set

The topics file names the reference node's `/eth/v1/events` topics (beacon-APIs `01e99a6`
eventstream) and the attestation subnets sampled. The shipped examples subscribe the exit-14
set (`gloas/p2p-interface.md`), each as the event the node emits when a message passes that
gossip topic's validation (Lighthouse at the Hoodi pin, `c8ddac7`, emits all of them):

| SSE event | Gossip topic |
|---|---|
| `block_gossip` | `beacon_block` |
| `execution_payload_gossip` | `execution_payload` (the envelope) |
| `execution_payload_bid` | `execution_payload_bid` |
| `payload_attestation_message` | `payload_attestation_message` (PTC) |
| `attestation` | `beacon_aggregate_and_proof` (Lighthouse emits it for verified aggregates) |
| `single_attestation` | `beacon_attestation_{subnet_id}` |
| `data_column_sidecar` | `data_column_sidecar_{subnet_id}` (the node's custody and sampled columns) |

- **What the node emits.** At each start the collector asks the node for each event alone. An
  event the node refuses (`400`: unknown at its version) is not subscribed; it is listed as
  unsupported in `capture.toml` (`sse_topics_unsupported`), in `summary.toml`
  (`unsupported_topics`) and in the log. `block_gossip` and `data_column_sidecar` are the
  fallback: they are required in the file, and a node that refuses either is refused, so a
  capture always has blocks and columns.
- **What it did not see.** `summary.toml` lists every configured event with its count `n` and
  bytes, zeros included (a refused one too, at `n = 0`), and every sampled subnet the same way;
  those with `n = 0` are listed in `missing_topics`, so it holds every configured topic with no
  data, the refused ones included (they stay in `unsupported_topics` as well). The log's
  `topic gaps:` line names each one once, a refused one marked `(refused)`. `undecoded` counts
  only the records written: an attestation the subnet sample drops is not one of them. On Hoodi
  before the Gloas fork (2026-10-26 17:42:48 UTC, 02:42:48 KST on the 27th)
  `execution_payload_gossip`, `execution_payload_bid` and `payload_attestation_message` are
  expected there.
- **Sampled attestation subnets.** A `single_attestation` is recorded only on a subnet in
  `attestation_subnets`; any other (or one whose subnet is unknown) is counted
  (`outside_sampled_subnets`), never written. Its subnet is `compute_subnet_for_attestation`
  from its slot and committee index and the committees per slot, which the collector reads
  from the node at start (`/eth/v1/beacon/states/head/committees` for the current slot, kept in
  `capture.toml`; 64 on Hoodi). A node without validators subscribes only its own two subnets,
  which change every 256 epochs (about 27 h); set `attestation_subnets` to them. The collector
  reads the node's `attnets` at start (`/eth/v1/node/identity`), keeps them in `capture.toml`
  (`node_attnets`) and logs every sampled subnet the node does not subscribe:

  ```bash
  curl -s http://127.0.0.1:5053/eth/v1/node/identity | grep -o '"attnets":"[^"]*"'
  # "attnets":"0x0003000000000000": bit i%8 of byte i/8 is subnet i, so subnets 8 and 9
  ```

- **Volume.** On Hoodi (64 committees a slot) aggregates are up to about 1,000 a slot (16
  aggregators a committee) and two subnets' attestations about as many: roughly 2,000 records a
  slot of a few hundred bytes, about 0.5 MB a slot or several GB a day. Watch the disk
  (`df -h /var/lib/ethswarm-collector`); drop `attestation` from the file if it is short. Event
  JSON is a few hundred bytes, inside every existing bound: the SSE event and name caps, the
  channel's byte budget, and the subscribed-topic allow-list (an event not subscribed is refused
  and counted).

## What a capture holds

Each start of an instance writes a new directory
`/var/lib/ethswarm-collector/<network>/<network>-<unix start seconds>/`:

| File | Content |
|---|---|
| `capture.toml` | network, `genesis_time` (read from the node), `SLOT_DURATION_MS`, column subnet count, subscribed and unsupported events, sampled attestation subnets, the node's `attnets`, committees per slot, host, time daemon, start on both clocks |
| `records.jsonl` | one record per event: `source`, `topic`, `subnet`, `msg_id`, `block_root`, `slot`, `recv_mono_ns`, `recv_wall_ns`, `peer`, `bytes` (the event's JSON for SSE; the message data for gossip) |
| `gaps.jsonl` | one missing interval per disconnect, and one for the time before the first stream, written when the stream is back |
| `ntp.jsonl` | the clock error (local minus NTP) from `chronyc tracking`, every 60 s |
| `summary.toml` | written at stop: record, drop and undecoded counts, the number and total length of the missing intervals (`gaps.jsonl` lists them), and the manifest: `n` and bytes of every configured event, refused ones included (`[[topics]]`), and sampled subnet (`[[attestation_subnets]]`), the gaps (`missing_topics`, `unsupported_topics`), and `outside_sampled_subnets` |

`collector rates DIR` prints one JSON line per topic: `n`, `bytes`, `msgs_per_slot` and
`bytes_per_slot`, and the busiest slot's (`peak_msgs_per_slot`, `peak_bytes_per_slot`); a
`single_attestation` line per sampled subnet too. The per-slot divisor (`slots`) counts only the
slots in which the topic's source recorded something: a slot with nothing from that source (a
missing interval, a quiet stretch) is left out rather than counted as empty, so the rates are
per slot the source was seen in. A record's slot is the wall-clock slot of its arrival; the
busiest slot is the full count of each slot, even if the wall clock stepped back into it. Every
configured topic and sampled subnet of `summary.toml` gets a line, `n = 0` when nothing was
recorded (a refused event included), so the gaps show here too; a capture still running has no
`summary.toml` yet, and then only the recorded topics are listed (said on stderr). These are
the attestation, aggregate and PTC rates (`single_attestation`, `attestation`,
`payload_attestation_message`). SSE bytes are the event's JSON, not the wire size; the probe's
gossip tap gives the wire size.

The stream is reconnected with backoff (1 s, doubling, up to 30 s). Beacon nodes do not replay
missed events, so every disconnect, however short, is a missing interval: from the last bytes
received to the next stream's response, with its reason and failed attempts. The time from the
start to the first stream is one too. A disconnect still open at stop is recorded with
`open_at_shutdown = true`. Events the collector did not subscribe to are refused and counted,
never recorded.

If the capture cannot be written (a full disk, say), the collector stops reading and exits 1,
so `Restart=on-failure` starts a new capture once there is room.

## Install

On the reference host, once the node is synced and its beacon API answers (Hoodi on
`127.0.0.1:5053`, Sepolia on `127.0.0.1:5052`; see `ops/ref-node`). The steps enable a Hoodi
instance; a Sepolia one is the same with `sepolia` for `hoodi`.

1. On a host that ran the earlier single-network unit, retire it first: it reads port 5052,
   which on a shared host is the Sepolia node, and records it as Hoodi. Stop and remove it, and
   give `/var/lib/ethswarm-collector` back to root (that unit left it owned by its user, mode
   0750, which would lock the new instance users out of their own directories):

   ```bash
   sudo systemctl disable --now ethswarm-collector.service
   sudo rm -f /etc/systemd/system/ethswarm-collector.service
   sudo systemctl daemon-reload
   sudo chown root:root /var/lib/ethswarm-collector
   sudo chmod 0755 /var/lib/ethswarm-collector
   ```

   Its captures (`/var/lib/ethswarm-collector/hoodi-<start>/`) stay where they are, still owned
   by the old `ethswarm-collector` user; archive them before removing that user.

2. Build and install the binary (root-owned, not writable by the service users):

   ```bash
   cargo build --release --locked -p testkit --bin collector
   sudo install -o root -g root -m 0755 target/release/collector /usr/local/bin/collector
   ```

3. Create the instance's own system user and install the template:

   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin ethswarm-collector-hoodi
   sudo install -o root -g root -m 0644 ops/collector/ethswarm-collector@.service \
       /etc/systemd/system/ethswarm-collector@.service
   ```

4. Install the instance's env file (root's, 0644: no secret), topics file (root's, 0644) and URL
   file (the instance user's, 0600: the collector refuses any other mode or owner). Edit the env
   file in an editor that keeps LF line ends and ASCII: a CR, a tab or a quote anywhere stops
   the unit. Keep the URL on the Hoodi node's port; a key, if the node needs one, goes in its
   path here and nowhere else. On a host that runs systemd-timesyncd instead of chrony, set
   `COLLECTOR_NTP=timesyncd`.

   ```bash
   sudo install -d -o root -g root -m 0755 /etc/ethswarm
   sudo install -o root -g root -m 0644 ops/collector/collector-hoodi.env.example \
       /etc/ethswarm/collector-hoodi.env
   sudo install -o root -g root -m 0644 ops/collector/collector-hoodi.topics.toml.example /etc/ethswarm/collector-hoodi.topics.toml
   sudo install -o ethswarm-collector-hoodi -g ethswarm-collector-hoodi \
       -m 0600 ops/collector/collector-hoodi.url.example /etc/ethswarm/collector-hoodi.url
   sudo systemd-analyze verify /etc/systemd/system/ethswarm-collector@hoodi.service
   ```

   Then set `attestation_subnets` in `/etc/ethswarm/collector-hoodi.topics.toml` to the node's
   subnets (its `attnets`, step 5) with `sudoedit`.

5. Check the node and the clock first: the node answers on the URL file's port and is on
   Hoodi, and `chronyc -n tracking` works as an unprivileged user (it uses `127.0.0.1:323`):

   ```bash
   curl -s http://127.0.0.1:5053/eth/v1/config/spec | grep -o '"CONFIG_NAME":"[^"]*"'
   # "CONFIG_NAME":"hoodi"
   curl -s http://127.0.0.1:5053/eth/v1/beacon/genesis
   curl -s http://127.0.0.1:5053/eth/v1/node/identity | grep -o '"attnets":"[^"]*"'
   chronyc -n tracking
   ```

6. Start the instance and watch its log:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now ethswarm-collector@hoodi
   journalctl -u ethswarm-collector@hoodi -f
   ```

   The first lines name the events the node does not emit (if any), the capture directory and
   the subscribed events; an `ntp:` line follows
   every minute and a `missing interval:` line after every reconnect. An instance that exits at
   once names the reason: `collector-hoodi.env: …` (the env file), `--url-file: …` (the URL
   file's type, owner, mode or content, never the URL), or `the node's CONFIG_NAME is sepolia, not hoodi`
   (the URL reaches the Sepolia node).

## Upgrade from the beacon_block-only collector

On a host that already runs `ethswarm-collector@<network>` from the earlier template (blocks,
envelopes and columns only): rebuild and reinstall the binary (step 2), install the new
template and the topics file (steps 3 and 4), then restart. The running capture closes with its
`summary.toml`; the restart opens one with the new topic set.

```bash
git -C ~/eth-swarm fetch && git -C ~/eth-swarm checkout <commit>
cd ~/eth-swarm
cargo build --release --locked -p testkit --bin collector
sudo install -o root -g root -m 0755 target/release/collector /usr/local/bin/collector
sudo install -o root -g root -m 0644 ops/collector/ethswarm-collector@.service \
    /etc/systemd/system/ethswarm-collector@.service
sudo install -o root -g root -m 0644 ops/collector/collector-hoodi.topics.toml.example /etc/ethswarm/collector-hoodi.topics.toml
sudoedit /etc/ethswarm/collector-hoodi.topics.toml   # attestation_subnets: the node's attnets
sudo systemd-analyze verify /etc/systemd/system/ethswarm-collector@hoodi.service
sudo systemctl daemon-reload
sudo systemctl restart ethswarm-collector@hoodi
journalctl -u ethswarm-collector@hoodi -n 20 --no-pager
```

## Smoke capture (at least 1 h)

Run it on Sepolia first (`ethswarm-collector@sepolia`; Sepolia is past its Gloas fork, so every
topic should have messages), then on Hoodi after the deploy. Start a fresh capture, let it run
for at least an hour, then close it by restarting the instance (the running capture writes
`summary.toml` on SIGTERM; the restart opens a new one):

```bash
net=sepolia   # then hoodi
sudo systemctl restart ethswarm-collector@$net
journalctl -u ethswarm-collector@$net -n 20 --no-pager   # unsupported events, unsubscribed subnets
date -u; sleep 3700; date -u                              # at least an hour
sudo systemctl restart ethswarm-collector@$net
# The capture before the newest one (the state directory is 0750, so list it as root).
dir=$(sudo sh -c "ls -d /var/lib/ethswarm-collector/$net/$net-*" | sort | tail -2 | head -1)
sudo -u ethswarm-collector-$net cat "$dir/summary.toml"
sudo -u ethswarm-collector-$net grep -E '^(records|dropped|outside_sampled_subnets|missing_topics|unsupported_topics) ' "$dir/summary.toml"
sudo -u ethswarm-collector-$net /usr/local/bin/collector rates "$dir"
sudo -u ethswarm-collector-$net /usr/local/bin/collector offsets "$dir" | tail -1
```

The smoke passes with a non-empty `records.jsonl` covering the hour, the missing intervals
listed, an NTP line every minute in `ntp.jsonl`, and `n > 0` for every subscribed event and
sampled subnet (`missing_topics = []`, `unsupported_topics = []`), or the report names each one
in `missing_topics` and `unsupported_topics` and why (on Hoodi before the fork, the Gloas
events; a sampled subnet the node does not subscribe). Before Hoodi, the same run works against
the Sepolia reference node (`ops/ref-node`), whose pinned genesis the collector also checks
against the node's.

## Hoodi deploy (before 2026-10-27 02:42:48 KST)

On the Hoodi reference host, after the Sepolia smoke passed and with the Hoodi node synced on
`127.0.0.1:5053`: a host without the collector runs [Install](#install) steps 1 to 6; a host
that runs the earlier template runs [Upgrade](#upgrade-from-the-beacon_block-only-collector).
Then:

```bash
systemctl is-active ethswarm-collector@hoodi
sudo -u ethswarm-collector-hoodi sh -c 'cat /var/lib/ethswarm-collector/hoodi/hoodi-*/capture.toml' | tail -20
```

Run the smoke capture with `net=hoodi` and fill the deploy log below. Leave the instance
running across the fork: from the fork's first slot the Gloas events leave `missing_topics`.

## Deploy log

Record the deploy in the run log, dated:

```text
date (UTC):            2026-10-..T..:..:..Z
host:                  <hostname>
instance:              ethswarm-collector@hoodi (user ethswarm-collector-hoodi)
reference node:        the URL file's port, and the node's CONFIG_NAME (curl …/eth/v1/config/spec)
collector sha256:      $(sha256sum /usr/local/bin/collector)
unit sha256:           $(sha256sum /etc/systemd/system/ethswarm-collector@.service)
env file sha256:       $(sudo sha256sum /etc/ethswarm/collector-hoodi.env)
topics file sha256:    $(sha256sum /etc/ethswarm/collector-hoodi.topics.toml)
unsupported / missing: unsupported_topics and missing_topics from summary.toml
git commit:            <commit the binary was built from>
smoke capture:         /var/lib/ethswarm-collector/hoodi/hoodi-<start>/  (start, stop, duration)
records / undecoded / dropped:  from summary.toml
missing intervals:     count and total from summary.toml; each one in gaps.jsonl
ntp clock error range: from ntp.jsonl
```

## Running it elsewhere

The URL must be plain `http://` to a loopback host; the collector refuses anything else and
never prints the URL's path. `--url` puts it in argv, so use it only for a URL without a key;
otherwise give `--url-file` a 0600 file. To read a remote node, tunnel its API to a local port
first:

```bash
ssh -f -N -o ExitOnForwardFailure=yes -L 127.0.0.1:5053:127.0.0.1:5053 ref-host &&
  tunnel=$(pgrep -u "$(id -u)" -f -- '-L 127.0.0.1:5053:') && echo "tunnel PID: $tunnel" &&
  collector sse --network hoodi --url http://127.0.0.1:5053 --out ./captures --host "$(hostname)" --ntp none \
    --topics-file ops/collector/collector-hoodi.topics.toml.example
# After the capture:
kill "$tunnel"
```

`ssh -f` goes to the background only after the forward listens on loopback, so the collector
starts only after that. If `ssh` exits, stop: another process holds the port, and the
collector must not read from it. If the `ssh` process stops while the collector runs, stop the
collector and do not use its capture. A local account can bind the free port and answer. After
the capture, stop the tunnel with `kill "$tunnel"` (the PID that `pgrep` printed).
