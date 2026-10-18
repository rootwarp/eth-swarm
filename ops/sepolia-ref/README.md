# Sepolia reference node (Reth + Lighthouse)

A synced Sepolia EL+CL pair on a Gloas-capable release: the M2-alpha session's static peer and
its Beacon API oracle. Our client never talks to the EL; Reth only keeps Lighthouse synced and
not optimistic, so any EL that supports the fork would do.

`compose.yaml` runs both with `network_mode: host`, so it needs a **Linux** host (Docker
Desktop's host networking does not bind the macOS loopback). The Engine API (8551) and the
Beacon API (5052) listen on the host's 127.0.0.1 only. Each service runs as its own OS user on
a read-only root filesystem, with no capabilities, and mounts only its own data directory and
its own read-only JWT copy from `DATA_ROOT` (default `/srv/ethswarm-ref`):

```text
/srv/ethswarm-ref/reth/{data/,jwt.hex}         reth:reth             0700 / 0600
/srv/ethswarm-ref/lighthouse/{data/,jwt.hex}   lighthouse:lighthouse 0700 / 0600
```

## Firewall and disk

Open inbound, from anywhere: **9000/tcp, 9000/udp, 9001/udp** (Lighthouse: libp2p, discv5,
QUIC) and **30303/tcp, 30303/udp** (Reth: devp2p, discv4). Nothing else: 8551 and 5052 stay
on loopback, and the test host reaches 5052 over SSH.

Reth runs pruned (`--full`; its default is an archive node) and syncs in stages from genesis,
about a day unattended. Size the disk for a pruned Sepolia Reth plus a Lighthouse beacon node
with blob/column data, with headroom; if the host also runs the Hoodi node, confirm the space
for both before either sync starts.

## Versions

`.env.example` pins these (tag and multi-arch index digest). Gloas activated on Sepolia at
epoch 353024 (slot 11296768), 2026-10-06 13:53:36 UTC, which is
`GLOAS_FORK_EPOCH: 353024` / `GLOAS_FORK_VERSION: 0x90000076` in our pinned
`crates/network-config/networks/sepolia/config.yaml`; the EL half is Amsterdam.
`collect-run-log.sh` copies this table into the run log and fails if a pinned tag has no row.

<!-- release-notes:begin -->
| Image | Release | Release-note line: Sepolia Gloas / Amsterdam |
|---|---|---|
| `ghcr.io/paradigmxyz/reth:v2.7.0@sha256:a7f059d470878a5a59f3c575f3fc81b536d0d2d56d7a1cbed73e717a4f766336` | [v2.7.0](https://github.com/paradigmxyz/reth/releases/tag/v2.7.0) | "Reth v2.7.0 prepares Sepolia for the Glamsterdam hardfork" … "**Sepolia operators must upgrade before 6 October 2026 at 13:53:36 UTC.** This release schedules Amsterdam activation on Sepolia testnet and tests the fork ID and `eth_config` transition." |
| `sigp/lighthouse:v8.3.0-rc.0@sha256:3e5f0609c74b824d3cb1049920169114d99fd7bc9082b996b3adae3d4e9ef8dc` | [v8.3.0-rc.0](https://github.com/sigp/lighthouse/releases/tag/v8.3.0-rc.0) | "Lighthouse v8.3.0-rc.0 is a **release candidate with support for the upcoming Gloas hard fork on Sepolia**." Its table: Sepolia, fork epoch 353024, fork slot 11296768, 6 October 2026 13:53:36 UTC. |
<!-- release-notes:end -->

Both notes name the same activation time as our pinned epoch. In a local run, the pinned
Lighthouse image answered `/eth/v1/config/spec` with an empty diff against the pinned config,
and the pinned Reth listed `engine_newPayloadV5`/`V6`, `engine_getPayloadV6` and
`engine_forkchoiceUpdatedV4`/`V5` in `engine_exchangeCapabilities`; Reth's note does not name
the Engine API methods. Neither note names the consensus-specs release it implements, so
beta.4 compatibility is not claimed from the notes; `preflight.sh` and the run log check the
node's `/eth/v1/config/spec` against the pinned config instead. Lighthouse v8.2.x does **not** run Sepolia past the fork (its v8.2.3 notes: "If you
are running a node on Sepolia you'll need v8.3.0-rc.0 instead").

## Runbook

1. **Pick versions.** Check the latest
   [Reth](https://github.com/paradigmxyz/reth/releases) and
   [Lighthouse](https://github.com/sigp/lighthouse/releases) releases for Sepolia Gloas /
   Amsterdam support. To change a pin, take the index digest
   (`docker buildx imagetools inspect <image:tag>`), update `.env.example` and the table above
   with the release-note line. If no Reth release supports the fork, fall back to
   Lighthouse + Geth (snap sync) and record the reason in the run log.
2. **Fill `.env`:** `cp .env.example .env`, then set `CHECKPOINT_SYNC_URL`: https, the API of
   a full Sepolia beacon node on the Gloas config. Public checkpointz proxies
   (`checkpoint-sync.sepolia.ethpandaops.io`, `beaconstate-sepolia.chainsafe.io`) serve only
   24 spec keys and no fork keys, so pre-flight cannot check them and refuses them. No query
   or fragment: the API path is appended to the URL, so a provider key must sit in the path.
   Leave `TRUSTED_PEERS` empty for now.
3. **Set up the host:** `sudo ./setup.sh` creates the users, the directories and the JWT
   copies, and writes the ids and `DATA_ROOT` into `.env` (mode 0600). It is idempotent and
   keeps the secret; `--rotate-jwt` replaces it. It refuses a `DATA_ROOT` that is not a
   root-owned directory closed to group and others (so not `/tmp`), or that sits below a
   directory anyone but root could change, or has a symlink, a `..` or a hard-linked secret
   anywhere on its path or in its tree. It also refuses an `.env` line that compose would
   read differently: `export`, indentation, a key set twice, or a `$` or backtick in a
   value.
4. **Pre-flight:** `sudo ./preflight.sh` checks the pins, the ids (non-root, distinct, the
   users' own), the modes and owners, and the checkpoint endpoint's `/eth/v1/config/spec`
   against the pinned config. Public endpoints have served pre-Gloas configs: pick another if
   the diff is not empty. It also fails if the shell exports any variable compose reads from
   `.env` with another value, since compose would use the exported one; run compose through
   `sudo`, which starts from a clean environment.
5. **Start:** `sudo docker compose up -d`.
6. **Wait for sync** (about a day): `curl -s 127.0.0.1:5052/eth/v1/node/syncing`.
7. **Trust the session's peer ID.** On the test host:
   `sudo -u m2a-session m2a-session --print-peer-id`. Put the ID in `TRUSTED_PEERS` in `.env`,
   then `sudo docker compose up -d lighthouse` (recreates Lighthouse with `--trusted-peers`).
8. **Collect the evidence:**
   `sudo ./collect-run-log.sh > run-log-$(date -u +%Y%m%dT%H%M%SZ).md` (13 samples, 5 min
   apart: 1 h; add `--public-ip <ip>` if the identity shows no public address). It prints the
   run log on stdout and writes no file itself, so the log is created by your own shell, not
   by root. It exits non-zero if a criterion failed. A run of fewer than 12
   samples, or spanning under an hour, is marked DIAGNOSTIC (not acceptance) and never
   passes. Lighthouse creates its node key
   (`$DATA_ROOT/lighthouse/data/beacon/network/key`) under umask 077, so it is 0600.
9. **Post the run log** on the issue. It holds no secret: the JWT is only stat'ed and the
   checkpoint URL is never printed.
10. **Run the session** on the test host: open the tunnel
    (`ssh -N -L 5052:127.0.0.1:5052 <ref-host>`), write `/etc/ethswarm/m2a-session.toml` from
    the run log's last section, and run `sudo -u m2a-session m2a-session --dial-only`.

Lighthouse's checkpoint URL is on its command line, so any local user can read it in `ps`;
on a shared host, use an endpoint without a key in the URL.

## Tests

`bash ops/sepolia-ref/tests/sepolia-ref.test.sh` runs offline as a normal user (CI runs it):
the spec-diff helper, the API verdicts, `setup.sh --test-mode`, `preflight.sh --test-mode`
(which ends "not a deployment gate") and `collect-run-log.sh` against stub commands, and
`docker compose config` when docker is installed. As root it needs `ETHSWARM_ROOT_TESTS=1`
and belongs in a throwaway container only (it creates users): it then runs `setup.sh` and
`preflight.sh` for real, every refusal as root, and the race regressions.
