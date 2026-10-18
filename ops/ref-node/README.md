# Reference node (Reth + Lighthouse): Sepolia and Hoodi

One compose stack, run once per network, each instance a synced EL+CL pair on a Gloas-capable
release. `NETWORK` in the `.env` picks the network; nothing else is copied per network.

| Network | Role | Gloas / Amsterdam fork | `.env` |
|---|---|---|---|
| Sepolia | the M2-alpha session's static peer and Beacon API oracle | epoch 353024, 2026-10-06 13:53:36 UTC (done) | `.env` from `.env.example` |
| Hoodi | hosts the fork-window and steady-state captures (not our probe) | epoch 132352, slot 4235264, **2026-10-26 17:42:48 UTC (2026-10-27 02:42:48 KST)** | `.env.hoodi` from `.env.hoodi.example` |

**Hoodi deadline: the Hoodi node must be synced and its run log must pass by
2026-10-25 23:59 KST**, a day ahead of the fork at 2026-10-27 02:42:48 KST. The Hoodi capture
tools (the gossip collector, the archiver and the extra-topic subscriptions) deploy on this same
host, each with its own runbook, before the fork; this stack provides the host, the node, its
OS users and the firewall rules only.

Our client never talks to the EL; Reth only keeps Lighthouse synced and not optimistic, so any
EL that supports the fork would do.

`compose.yaml` runs both services with `network_mode: host`, so it needs a **Linux** host
(Docker Desktop's host networking does not bind the macOS loopback). The Engine API and the
Beacon API listen on the host's 127.0.0.1 only. Each service runs as its own OS user on a
read-only root filesystem, with no capabilities, its own cgroup namespace (`cgroup: private`,
which a cgroup v1 host does not default to) and Docker's masked and read-only `/proc` and
`/sys` paths, and mounts only its own data directory and its own read-only JWT copy from
`DATA_ROOT`:

```text
<DATA_ROOT>/reth/{data/,jwt.hex}         <reth user>:<reth user>             0700 / 0600
<DATA_ROOT>/lighthouse/{data/,jwt.hex}   <lighthouse user>:<lighthouse user> 0700 / 0600
```

## Two networks on one host

Each network is its own compose project (`<network>-ref`) with its own `.env`, data root, OS
users and ports, so neither can read the other's secret or bind the other's port:

| | Sepolia (`.env`) | Hoodi (`.env.hoodi`) |
|---|---|---|
| compose project | `sepolia-ref` | `hoodi-ref` |
| `DATA_ROOT` | `/srv/ethswarm-ref` | `/srv/ethswarm-ref-hoodi` |
| OS users (from `NETWORK`) | `reth`, `lighthouse` | `reth-hoodi`, `lighthouse-hoodi` |
| `ENGINE_PORT` (127.0.0.1) | 8551 | 8552 |
| `BEACON_API_PORT` (127.0.0.1) | 5052 | 5053 |
| `RETH_P2P_PORT` (tcp+udp) | 30303 | 30304 |
| `LIGHTHOUSE_P2P_PORT` (tcp+udp) | 9000 | 9002 |
| `LIGHTHOUSE_QUIC_PORT` (udp) | 9001 | 9003 |
| checkpoint providers | 1 required (`CHECKPOINT_SYNC_URL`), a 2nd optional | 2 required, different operators |

Pass the env file to **every** command for the second network, and the project to every
compose command: `sudo ./setup.sh --env-file .env.hoodi`, `sudo ./preflight.sh --env-file
.env.hoodi`, `sudo docker compose -p hoodi-ref --env-file .env.hoodi up -d`, `sudo
./collect-run-log.sh --env-file .env.hoodi` (Sepolia: `-p sepolia-ref --env-file .env`).
compose then reads only that file (never `.env`), and the scripts, `preflight.sh` and the run
log check exactly the ports it sets; the run log passes the same `-p` on every compose call.
`-p` wins over `COMPOSE_PROJECT_NAME`, which would otherwise override `name:` (a Sepolia value
would make the Hoodi `up` recreate the Sepolia services); all three scripts refuse any
`COMPOSE_*` key in the `.env`, and `preflight.sh` and the run log refuse `COMPOSE_PROJECT_NAME`
in the environment. Both env files are git-ignored.

The capture tools read the node's Beacon API. `ops/collector` runs one instance per network
(`ethswarm-collector@hoodi`, `@sepolia`), each with its own URL file; its example URL files
carry these defaults, Hoodi 5053 and Sepolia 5052, and its CI test fails if they drift apart.
On a host that runs Hoodi alone, the Hoodi `.env` may take the Sepolia column's ports instead;
set the collector's URL file to match. A collector pointed at the other network's node
refuses to start (its `CONFIG_NAME` differs).

## Firewall and disk

Open inbound, from anywhere, only the p2p ports of each network you run: Sepolia **9000/tcp,
9000/udp, 9001/udp** (Lighthouse: libp2p, discv5, QUIC) and **30303/tcp, 30303/udp** (Reth:
devp2p, discv4); Hoodi **9002/tcp, 9002/udp, 9003/udp** and **30304/tcp, 30304/udp**. Nothing
else: the Engine and Beacon API ports stay on loopback, and the test host reaches a Beacon API
over SSH. The run log reads both containers' processes and `ss -ltnp` together, right before
that check, and fails any non-loopback TCP listener of those processes on another port, a
service with no listener on its own p2p port, and an `ss` that shows no processes.

Reth runs pruned (`--full`; its default is an archive node) and syncs in stages from genesis,
about a day unattended. **Headroom check before either sync starts:** `preflight.sh` prints
the free space under its `DATA_ROOT` (`disk: … GiB free`); compare it with the current sizes the
[Reth](https://reth.rs/run/system-requirements) and
[Lighthouse](https://lighthouse-book.sigmaprime.io/installation.html) docs
give for a pruned node and a beacon node with blob/column data, plus growth to the end of the
capture window. When both data roots share a filesystem, the free space must cover both nodes.

## Versions

`.env.example` and `.env.hoodi.example` pin these (tag and multi-arch index digest; both
networks run the same images today). `collect-run-log.sh` copies the network's table into the
run log and fails if the pinned image has no row or its row says the release does not schedule
the network's fork. The pinned configs are
`crates/network-config/networks/{sepolia,hoodi}/config.yaml`: Sepolia `GLOAS_FORK_EPOCH:
353024`, `GLOAS_FORK_VERSION: 0x90000076`; Hoodi `GLOAS_FORK_EPOCH: 132352`,
`GLOAS_FORK_VERSION: 0x80000910`. The EL half is Amsterdam. The consensus-specs column is the
spec-test pin in the release's own source (`testing/ef_tests/Makefile`
`CONSENSUS_SPECS_TEST_VERSION` at the tag); our client targets **v1.7.0-beta.4**, and the run
log records a different one without failing it.

### Sepolia

<!-- release-notes:sepolia:begin -->
| Image | Release | Schedules Sepolia's fork | consensus-specs | Release-note line: Sepolia Gloas / Amsterdam |
|---|---|---|---|---|
| `ghcr.io/paradigmxyz/reth:v2.7.0@sha256:a7f059d470878a5a59f3c575f3fc81b536d0d2d56d7a1cbed73e717a4f766336` | [v2.7.0](https://github.com/paradigmxyz/reth/releases/tag/v2.7.0) | yes | n/a (EL) | "Reth v2.7.0 prepares Sepolia for the Glamsterdam hardfork" … "**Sepolia operators must upgrade before 6 October 2026 at 13:53:36 UTC.** This release schedules Amsterdam activation on Sepolia testnet and tests the fork ID and `eth_config` transition." |
| `sigp/lighthouse:v8.3.0-rc.0@sha256:3e5f0609c74b824d3cb1049920169114d99fd7bc9082b996b3adae3d4e9ef8dc` | [v8.3.0-rc.0](https://github.com/sigp/lighthouse/releases/tag/v8.3.0-rc.0) | yes | v1.7.0-beta.2 | "Lighthouse v8.3.0-rc.0 is a **release candidate with support for the upcoming Gloas hard fork on Sepolia**." Its table: Sepolia, fork epoch 353024, fork slot 11296768, 6 October 2026 13:53:36 UTC. |
<!-- release-notes:sepolia:end -->

Both notes name the same activation time as our pinned epoch. In a local run, the pinned
Lighthouse image answered `/eth/v1/config/spec` with an empty diff against the pinned config,
and the pinned Reth listed `engine_newPayloadV5`/`V6`, `engine_getPayloadV6` and
`engine_forkchoiceUpdatedV4`/`V5` in `engine_exchangeCapabilities`; Reth's note does not name
the Engine API methods. Lighthouse v8.2.x does **not** run Sepolia past the fork (its v8.2.3
notes: "If you are running a node on Sepolia you'll need v8.3.0-rc.0 instead").

### Hoodi

<!-- release-notes:hoodi:begin -->
| Image | Release | Schedules Hoodi's fork | consensus-specs | Release-note line: Hoodi Gloas / Amsterdam |
|---|---|---|---|---|
| `ghcr.io/paradigmxyz/reth:v2.7.0@sha256:a7f059d470878a5a59f3c575f3fc81b536d0d2d56d7a1cbed73e717a4f766336` | [v2.7.0](https://github.com/paradigmxyz/reth/releases/tag/v2.7.0) | no | n/a (EL) | Sepolia only: "This release schedules Amsterdam activation on Sepolia testnet". No Hoodi line; its Hoodi fork-ID test ends at Osaka and the BPO forks. |
| `sigp/lighthouse:v8.3.0-rc.0@sha256:3e5f0609c74b824d3cb1049920169114d99fd7bc9082b996b3adae3d4e9ef8dc` | [v8.3.0-rc.0](https://github.com/sigp/lighthouse/releases/tag/v8.3.0-rc.0) | no | v1.7.0-beta.2 | "The Gloas fork is not yet scheduled on Hoodi or mainnet." Its built-in Hoodi config has `GLOAS_FORK_EPOCH: 18446744073709551615`. |
<!-- release-notes:hoodi:end -->

**Neither pinned release schedules Hoodi's fork.** As of 2026-10-18 no Reth or Lighthouse
release does: v2.7.0 and v8.3.0-rc.0 are the latest tags, and the Hoodi announcement
([blog.ethereum.org, 2026-10-16](https://blog.ethereum.org/en/2026/10/16/glamsterdam-hoodi-announcement))
leaves both rows of its client tables empty ("Only use a release whose notes explicitly
confirm support for the scheduled Glamsterdam activation on Hoodi"). The fork is scheduled only
in unreleased code: Lighthouse `unstable` (Hoodi `GLOAS_FORK_EPOCH: 132352`, spec tests
v1.7.0-beta.4) and `alloy-hardforks` main (`HOODI_AMSTERDAM_TIMESTAMP` 1793036568, merged
2026-10-12), which Reth v2.7.0 does not include. No Lighthouse release both schedules Hoodi's
Gloas fork and pins consensus-specs v1.7.0-beta.4. The reference nodes run releases that
network operators run, never an `unstable` build.

So the Hoodi node can sync now on these releases (the chain before the fork is the same), but
before **2026-10-25 23:59 KST** both images must move to releases whose notes schedule Hoodi's
fork: take the index digest, put it in `.env.hoodi.example` and `.env.hoodi`, add a row here
with `yes` and the release-note line, and recreate the services. **Until then `preflight.sh`
fails for Hoodi** (it passes only when the README row for each pinned image says `yes`), so
today it blocks the Hoodi start until the images are repinned; the run log fails criterion 1
and (for Lighthouse) the spec diff. If neither team
ships in time, the fallback is a pair the announcement lists (for example Teku 26.10.1 or
Nimbus 26.10.1 with Nethermind 2.2.0 or Besu 26.10.0); that needs its own compose services and
run-log checks, so decide it early.

## Runbook

The steps for one network; for Hoodi add `--env-file .env.hoodi` to every script and compose
command (see above).

1. **Pick versions.** Check the latest
   [Reth](https://github.com/paradigmxyz/reth/releases) and
   [Lighthouse](https://github.com/sigp/lighthouse/releases) releases for the network's Gloas /
   Amsterdam support. To change a pin, take the index digest
   (`docker buildx imagetools inspect <image:tag>`), update the network's `.env` example and
   its table above with the release-note line and the consensus-specs pin at that tag. If no
   Reth release supports the fork, fall back to Lighthouse + Geth (snap sync) and record the
   reason in the run log.
2. **Fill the `.env`:** `cp .env.example .env` (Hoodi: `cp .env.hoodi.example .env.hoodi`),
   then set `CHECKPOINT_SYNC_URL` and, on Hoodi, `CHECKPOINT_SYNC_URL_2`: https, the API of a
   full beacon node on the network's Gloas config, the two run by **different operators**.
   Lighthouse syncs from the first. Public checkpointz proxies
   (`checkpoint-sync.sepolia.ethpandaops.io`, `beaconstate-sepolia.chainsafe.io` and their
   Hoodi equivalents) serve only 24 spec keys and no fork keys, so pre-flight cannot check
   them and refuses them. No query or fragment: the API path is appended to the URL, so a
   provider key must sit in the path. Leave `TRUSTED_PEERS` empty for now.
3. **Set up the host:** `sudo ./setup.sh` creates the network's users, the directories and the
   JWT copies, and writes the ids and `DATA_ROOT` into the `.env` (mode 0600). It is idempotent
   and keeps the secret; `--rotate-jwt` replaces it. It refuses a `DATA_ROOT` that is not a
   root-owned directory closed to group and others (so not `/tmp`), or that sits below a
   directory anyone but root could change, or has a symlink, a `..` or a hard-linked secret
   anywhere on its path or in its tree. It also refuses an `.env` line that compose would
   read differently: `export`, indentation, a key set twice, or a `$` or backtick in a
   value, and a `NETWORK` other than `sepolia` or `hoodi`.

   **Premise: only root or you (the operator) can write to the checkout and to the `.env`
   directory.** Root runs the checkout's scripts and rewrites `.env`, so anyone else who can
   change either one can make root run their code or write where they choose. `setup.sh`
   enforces the `.env` half: it walks the `.env` directory from `/` the way it walks
   `DATA_ROOT`, and refuses a symlink anywhere on that path or a directory on it (the `.env`
   directory included) that is owned by anyone but root or the sudo user (`SUDO_UID`), or
   that group or others can write, unless it is root-owned and sticky like `/tmp`. The
   scripts resolve their own directory and a relative `--env-file` to the physical path first
   (`cd -P`, `pwd -P`), so a checkout under a symlinked home is checked at its real path
   rather than refused. Run it with `sudo` from your own account; run straight from a root
   shell, it accepts only root-owned directories. It cannot check the checkout, so keep the
   clone in a directory only you can write to (for example under your home directory, mode
   0755 or tighter).
4. **Pre-flight:** `sudo ./preflight.sh` checks the pins and that this README's row for each
   pinned image says the release schedules the network's fork (it fails otherwise),
   the ports, the ids (non-root, distinct, the network's users), the modes and owners, each
   checkpoint provider's `/eth/v1/config/spec` against the network's pinned config, and, with
   two providers, that provider 2 holds provider 1's finalized block with the same block and
   state root. The providers it checked are printed (scheme and host only): keep that output
   with the run log. Public endpoints have served pre-Gloas configs: pick another if a diff is
   not empty, and abort if the providers disagree on the anchor. It also fails if the shell
   exports any variable compose reads from the `.env` with another value, since compose would
   use the exported one; run compose through `sudo`, which starts from a clean environment.

   **Anchor hook:** cl-sync's `anchor-fetch` will get `--providers A,B --check`, which fetches
   the finalized state and block from both providers and compares the block root, the state
   root and the header's `state_root`. Once it lands, run it with the two provider URLs before
   the start (the `TODO` in `preflight.sh` marks the place) and feed its verified state and
   block to Lighthouse's checkpoint flags; until then the header comparison above is the
   cross-check.
5. **Start:** `sudo docker compose -p <network>-ref --env-file <.env> up -d` (Sepolia:
   `-p sepolia-ref --env-file .env`; Hoodi: `-p hoodi-ref --env-file .env.hoodi`).
6. **Wait for sync** (about a day): `curl -s 127.0.0.1:<BEACON_API_PORT>/eth/v1/node/syncing`.
7. **Trust the session's peer ID** (Sepolia). On the test host:
   `sudo -u m2a-session m2a-session --print-peer-id`. Put the ID in `TRUSTED_PEERS` in `.env`,
   then `sudo docker compose -p sepolia-ref --env-file .env up -d lighthouse` (recreates
   Lighthouse with `--trusted-peers`).
8. **Collect the evidence:**
   `sudo ./collect-run-log.sh > run-log-$(date -u +%Y%m%dT%H%M%SZ).md` (13 samples, 5 min
   apart: 1 h; add `--public-ip <ip>` if the identity shows no public address). It prints the
   run log on stdout and writes no file itself, so the log is created by your own shell, not
   by root. It exits non-zero if a criterion failed. A run of fewer than 12
   samples, or spanning under an hour, is marked DIAGNOSTIC (not acceptance) and never
   passes. Lighthouse creates its node key
   (`$DATA_ROOT/lighthouse/data/beacon/network/key`) under umask 077, so it is 0600.
9. **Post the run log** on the issue. It holds no secret: the JWT copies and the node key are
   only fstat'ed, through `lib/fsguard.py`, and the checkpoint URLs appear as scheme and host
   only.
10. **Run the session** on the test host (Sepolia): open the tunnel
    (`ssh -N -L 5052:127.0.0.1:5052 <ref-host>`), write `/etc/ethswarm/m2a-session.toml` from
    the run log's last section, and run `sudo -u m2a-session m2a-session --dial-only`.

Lighthouse's checkpoint URL is on its command line, so any local user can read it in `ps`;
on a shared host, use an endpoint without a key in the URL.

## Tests

`bash ops/ref-node/tests/ref-node.test.sh` runs offline as a normal user (CI runs it): the
spec-diff helper against both pinned configs, the API verdicts, the anchor comparison,
`setup.sh --test-mode`, `preflight.sh --test-mode` (which ends "not a deployment gate") and
`collect-run-log.sh` for both networks against stub commands, and `docker compose config`
when docker is installed. As root it needs `ETHSWARM_ROOT_TESTS=1` and belongs in a throwaway
container only (it creates users): it then runs `setup.sh` and `preflight.sh` for real for
both networks side by side, every refusal as root, and the race regressions.
