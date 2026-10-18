# Arrival collector (Hoodi reference node)

`collector` (`crates/testkit/src/bin/collector.rs`, library `testkit::collector`) records when
each block, execution payload envelope and data column arrived, on a monotonic and a wall
clock, stamped before anything decodes it. On the Hoodi reference host it reads the node's
`/eth/v1/events` stream; our probe's gossip tap feeds the same collector once the probe has
one. Offsets are computed from the records afterwards with `collector offsets`.

`ethswarm-collector.service` runs it as its own system user with the same hardening as the
probe units, and may only reach loopback (`IPAddressAllow=localhost`): the node's beacon API on
`127.0.0.1:5052` and chronyd on `127.0.0.1:323`.

## What a capture holds

Each start of the unit writes a new directory `/var/lib/ethswarm-collector/hoodi-<unix start
seconds>/`:

| File | Content |
|---|---|
| `capture.toml` | network, `genesis_time` (read from the node), `SLOT_DURATION_MS`, column subnet count, subscribed events, host, time daemon, start on both clocks |
| `records.jsonl` | one record per event: `source`, `topic`, `subnet`, `msg_id`, `block_root`, `slot`, `recv_mono_ns`, `recv_wall_ns`, `peer` |
| `gaps.jsonl` | one missing interval per disconnect, written when the stream is back |
| `ntp.jsonl` | the clock error (local minus NTP) from `chronyc tracking`, every 60 s |
| `summary.toml` | written at stop: record, drop and undecoded counts, and every missing interval |

The stream is reconnected with backoff (1 s, doubling, up to 30 s). Beacon nodes do not replay
missed events, so every disconnect, however short, is a missing interval: from the last bytes
received to the next stream's response, with its reason and failed attempts. A disconnect still
open at stop is recorded with `open_at_shutdown = true`.

## Install

On the Hoodi reference host, once the node is synced and its beacon API answers on
`127.0.0.1:5052`:

1. Build and install the binary (root-owned, not writable by the service user):

   ```bash
   cargo build --release --locked -p testkit --bin collector
   sudo install -o root -g root -m 0755 target/release/collector /usr/local/bin/collector
   ```

2. Create the service user and install the unit:

   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin ethswarm-collector
   sudo install -o root -g root -m 0644 ops/collector/ethswarm-collector.service \
       /etc/systemd/system/ethswarm-collector.service
   sudo systemd-analyze verify /etc/systemd/system/ethswarm-collector.service
   ```

3. Check the node and the clock first: `curl -s http://127.0.0.1:5052/eth/v1/beacon/genesis`
   answers, and `chronyc -n tracking` works as an unprivileged user (it uses
   `127.0.0.1:323`). On a host that runs systemd-timesyncd instead, change `--ntp chrony` to
   `--ntp timesyncd` in the unit.

4. Start it and watch the log:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now ethswarm-collector
   journalctl -u ethswarm-collector -f
   ```

   The first lines name the capture directory and the subscribed events; an `ntp:` line follows
   every minute and a `missing interval:` line after every reconnect.

## Smoke capture (at least 1 h)

Let the unit run for at least an hour, then close the capture by restarting the unit (the
running capture writes `summary.toml` on SIGTERM; the restart opens a new one):

```bash
sudo systemctl restart ethswarm-collector
# The capture before the newest one (the state directory is 0750, so list it as root).
dir=$(sudo sh -c 'ls -d /var/lib/ethswarm-collector/hoodi-*' | sort | tail -2 | head -1)
sudo -u ethswarm-collector cat "$dir/summary.toml"
sudo -u ethswarm-collector /usr/local/bin/collector offsets "$dir" | tail -1
```

The smoke passes with a non-empty `records.jsonl` covering the hour, the missing intervals
listed, and an NTP line every minute in `ntp.jsonl`. Before Hoodi, the same run works against
the Sepolia reference node (`ops/ref-node`): `--network sepolia`, whose pinned genesis the
collector checks against the node's.

## Deploy log

Record the deploy in the run log, dated:

```text
date (UTC):            2026-10-..T..:..:..Z
host:                  <hostname>
collector sha256:      $(sha256sum /usr/local/bin/collector)
unit sha256:           $(sha256sum /etc/systemd/system/ethswarm-collector.service)
git commit:            <commit the binary was built from>
smoke capture:         /var/lib/ethswarm-collector/hoodi-<start>/  (start, stop, duration)
records / undecoded / dropped:  from summary.toml
missing intervals:     from summary.toml
ntp clock error range: from ntp.jsonl
```

## Running it elsewhere

The URL must be plain `http://` to a loopback host; the collector refuses anything else and
never prints the URL's path. To read a remote node, tunnel its API to a local port first:

```bash
ssh -N -L 5052:127.0.0.1:5052 ref-host &
collector sse --network hoodi --url http://127.0.0.1:5052 --out ./captures --host "$(hostname)" --ntp none
```
