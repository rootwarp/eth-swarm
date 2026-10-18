# Arrival collector (Hoodi and Sepolia reference nodes)

`collector` (`crates/testkit/src/bin/collector.rs`, library `testkit::collector`) records when
each block, execution payload envelope and data column arrived, on a monotonic and a wall
clock, stamped before anything decodes it. On the reference host it reads a node's
`/eth/v1/events` stream; our probe's gossip tap feeds the same collector once the probe has
one. Offsets are computed from the records afterwards with `collector offsets`.

The systemd template `ethswarm-collector@.service` runs one instance per network,
`ethswarm-collector@hoodi` and `ethswarm-collector@sepolia`, with the same hardening as the
probe units; each may only reach loopback (`IPAddressAllow=localhost`): its node's beacon API
and chronyd on `127.0.0.1:323`. Each instance runs as its own system user,
`ethswarm-collector-<network>`, so neither can read or write the other's captures (one shared
user could, even through `/proc/<pid>/root`, which `ProtectProc=invisible` hides only from
other users). The unit names no node. Each instance reads two files:

| File | Hoodi | Sepolia |
|---|---|---|
| `/etc/ethswarm/collector-<network>.env` (root, 0644) | `collector-hoodi.env.example` | `collector-sepolia.env.example` |
| `COLLECTOR_NETWORK` | `hoodi` | `sepolia` |
| `COLLECTOR_OUT` | `/var/lib/ethswarm-collector/hoodi` | `/var/lib/ethswarm-collector/sepolia` |
| `COLLECTOR_NTP` | `chrony` | `chrony` |
| `/etc/ethswarm/collector-<network>.url` (the instance user's, 0600) | `collector-hoodi.url.example` | `collector-sepolia.url.example` |
| its one line | `http://127.0.0.1:5053` | `http://127.0.0.1:5052` |

The URL file is the only place the reference URL may carry a key: the unit passes its path
(`--url-file`), never the URL, because `/proc/<pid>/cmdline` is readable by every user. The
collector opens it without following a symlink and without blocking (`O_NOFOLLOW |
O_NONBLOCK`, so a FIFO at the path is refused at once instead of hanging the start), then checks
the open file: a regular file, the one the path named, owned by the user the collector runs as,
that neither group nor others may access (0600 or 0400). It never prints what the file holds;
an error names the path and the reason only.

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

`ops/collector/tests/collector-unit.test.sh` (CI) checks the template's hardening, users, env
and URL files, guard and state directory, that it holds no URL, that each example URL's port is
the ref-node default, and this README's migration step. It runs the guard on env files with a
CR, NUL, TAB, VT, FF, non-ASCII byte, quote, backslash, continuation, `export` or `PATH=` line,
each of which it must refuse, the last without running a tool from that `PATH`.

## What a capture holds

Each start of an instance writes a new directory
`/var/lib/ethswarm-collector/<network>/<network>-<unix start seconds>/`:

| File | Content |
|---|---|
| `capture.toml` | network, `genesis_time` (read from the node), `SLOT_DURATION_MS`, column subnet count, subscribed events, host, time daemon, start on both clocks |
| `records.jsonl` | one record per event: `source`, `topic`, `subnet`, `msg_id`, `block_root`, `slot`, `recv_mono_ns`, `recv_wall_ns`, `peer` |
| `gaps.jsonl` | one missing interval per disconnect, and one for the time before the first stream, written when the stream is back |
| `ntp.jsonl` | the clock error (local minus NTP) from `chronyc tracking`, every 60 s |
| `summary.toml` | written at stop: record, drop and undecoded counts, and the number and total length of the missing intervals (`gaps.jsonl` lists them) |

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

4. Install the instance's env file (root's, 0644: no secret) and URL file (the instance
   user's, 0600: the collector refuses any other mode or owner). Edit the env file in an editor
   that keeps LF line ends and ASCII: a CR, a tab or a quote anywhere stops the unit. Keep the URL on the Hoodi node's port; a
   key, if the node needs one, goes in its path here and nowhere else. On a host that runs
   systemd-timesyncd instead of chrony, set `COLLECTOR_NTP=timesyncd`.

   ```bash
   sudo install -d -o root -g root -m 0755 /etc/ethswarm
   sudo install -o root -g root -m 0644 ops/collector/collector-hoodi.env.example \
       /etc/ethswarm/collector-hoodi.env
   sudo install -o ethswarm-collector-hoodi -g ethswarm-collector-hoodi \
       -m 0600 ops/collector/collector-hoodi.url.example /etc/ethswarm/collector-hoodi.url
   sudo systemd-analyze verify /etc/systemd/system/ethswarm-collector@hoodi.service
   ```

5. Check the node and the clock first: the node answers on the URL file's port and is on
   Hoodi, and `chronyc -n tracking` works as an unprivileged user (it uses `127.0.0.1:323`):

   ```bash
   curl -s http://127.0.0.1:5053/eth/v1/config/spec | grep -o '"CONFIG_NAME":"[^"]*"'
   # "CONFIG_NAME":"hoodi"
   curl -s http://127.0.0.1:5053/eth/v1/beacon/genesis
   chronyc -n tracking
   ```

6. Start the instance and watch its log:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now ethswarm-collector@hoodi
   journalctl -u ethswarm-collector@hoodi -f
   ```

   The first lines name the capture directory and the subscribed events; an `ntp:` line follows
   every minute and a `missing interval:` line after every reconnect. An instance that exits at
   once names the reason: `collector-hoodi.env: …` (the env file), `--url-file: …` (the URL
   file's type, owner, mode or content, never the URL), or `the node's CONFIG_NAME is sepolia, not hoodi`
   (the URL reaches the Sepolia node).

## Smoke capture (at least 1 h)

Let the instance run for at least an hour, then close the capture by restarting it (the
running capture writes `summary.toml` on SIGTERM; the restart opens a new one):

```bash
sudo systemctl restart ethswarm-collector@hoodi
# The capture before the newest one (the state directory is 0750, so list it as root).
dir=$(sudo sh -c 'ls -d /var/lib/ethswarm-collector/hoodi/hoodi-*' | sort | tail -2 | head -1)
sudo -u ethswarm-collector-hoodi cat "$dir/summary.toml"
sudo -u ethswarm-collector-hoodi /usr/local/bin/collector offsets "$dir" | tail -1
```

The smoke passes with a non-empty `records.jsonl` covering the hour, the missing intervals
listed, and an NTP line every minute in `ntp.jsonl`. Before Hoodi, the same run works against
the Sepolia reference node (`ops/ref-node`) with the `ethswarm-collector@sepolia` instance,
whose pinned genesis the collector also checks against the node's.

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
ssh -N -L 5053:127.0.0.1:5053 ref-host &
collector sse --network hoodi --url http://127.0.0.1:5053 --out ./captures --host "$(hostname)" --ntp none
```
