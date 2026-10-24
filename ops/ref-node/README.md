# Reference node (Reth + Lighthouse): Sepolia and Hoodi

One compose stack, run once per network, each instance a synced EL+CL pair on Gloas-capable
clients: releases on Sepolia, two dev builds pinned by digest on Hoodi until releases schedule
its fork ([Hoodi](#hoodi)). `NETWORK` in the `.env` picks the network; nothing else is copied
per network.

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

Pass the env file to **every** command for the second network, and the project and the file to
every compose command: `sudo ./setup.sh --env-file .env.hoodi`, `sudo ./preflight.sh --env-file
.env.hoodi`, `sudo docker compose -p hoodi-ref --env-file .env.hoodi -f compose.yaml up -d`,
`sudo ./collect-run-log.sh --env-file .env.hoodi` (Sepolia: `-p sepolia-ref --env-file .env -f
compose.yaml`; `preflight.sh` prints the exact start command). compose then reads only that
file (never `.env`), and the scripts, `preflight.sh` and the run log check exactly the ports it
sets; the run log passes the same `-p`, `--env-file` and `-f` on every compose call.
`-p` wins over `COMPOSE_PROJECT_NAME`, which would otherwise override `name:` (a Sepolia value
would make the Hoodi `up` recreate the Sepolia services); all three scripts refuse any
`COMPOSE_*` key in the `.env`. `preflight.sh` and the run log also refuse, in the environment,
any `COMPOSE_*` variable (`COMPOSE_FILE` would pick another file, `COMPOSE_PROFILES` other
services) and any `DOCKER_*` variable (`DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_CONFIG`,
`DOCKER_TLS*` and `DOCKER_CERT_PATH` point docker at another daemon or client config than the
host's, `DOCKER_DEFAULT_PLATFORM` and the rest change what it runs). `sudo` starts from a clean
environment, so run compose through it too, and never use `sudo -E`: it keeps your `HOME`, and
docker reads its config (the current context, so the daemon) and its CLI plugins (`docker
compose` itself) from `$HOME/.docker`. The run log therefore points every docker call at the
`.docker` directory of root's own home from the passwd database (`DOCKER_CONFIG`, normally
`/root/.docker`), whatever `HOME` says. Both env files are git-ignored.

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

`.env.example` and `.env.hoodi.example` pin these (tag and multi-arch index digest): Sepolia
runs releases, Hoodi two dev builds until releases schedule its fork. `preflight.sh` and
`collect-run-log.sh` first check that each image comes from its service's own repository,
matched exactly on the part before the tag's `:` or the `@`: `ghcr.io/paradigmxyz/reth` for
`RETH_IMAGE`, `sigp/lighthouse` for `LIGHTHOUSE_IMAGE` (`lib/common.sh` `service_repo`, the one
place this map lives). So a row edited by hand on the host cannot vouch for the other client's
image or for a lookalike (`ghcr.io/paradigmxyz/reth-evil`, `sigp/lighthouse2`,
`docker.io/sigp/lighthouse`). They then look up the pinned image, tag and digest, in the
network's table below; both fail if it has no row for the variable's own client (Client `reth`
for `RETH_IMAGE`, `lighthouse` for `LIGHTHOUSE_IMAGE`, so pins swapped between the two services
fail) or its row says it does not schedule the network's fork, and the run log copies the
table. The pinned configs are
`crates/network-config/networks/{sepolia,hoodi}/config.yaml`: Sepolia `GLOAS_FORK_EPOCH:
353024`, `GLOAS_FORK_VERSION: 0x90000076`; Hoodi `GLOAS_FORK_EPOCH: 132352`,
`GLOAS_FORK_VERSION: 0x80000910`. The EL half is Amsterdam. The consensus-specs column is the
spec-test pin in the release's own source (`testing/ef_tests/Makefile`
`CONSENSUS_SPECS_TEST_VERSION` at the tag); our client targets **v1.7.0-beta.4**, and the run
log records a different one without failing it.

### Sepolia

<!-- release-notes:sepolia:begin -->
| Image | Client | Release | Schedules Sepolia's fork | consensus-specs | Release-note line: Sepolia Gloas / Amsterdam |
|---|---|---|---|---|---|
| `ghcr.io/paradigmxyz/reth:v2.7.0@sha256:a7f059d470878a5a59f3c575f3fc81b536d0d2d56d7a1cbed73e717a4f766336` | reth | [v2.7.0](https://github.com/paradigmxyz/reth/releases/tag/v2.7.0) | yes | n/a (EL) | "Reth v2.7.0 prepares Sepolia for the Glamsterdam hardfork" … "**Sepolia operators must upgrade before 6 October 2026 at 13:53:36 UTC.** This release schedules Amsterdam activation on Sepolia testnet and tests the fork ID and `eth_config` transition." |
| `sigp/lighthouse:v8.3.0-rc.0@sha256:3e5f0609c74b824d3cb1049920169114d99fd7bc9082b996b3adae3d4e9ef8dc` | lighthouse | [v8.3.0-rc.0](https://github.com/sigp/lighthouse/releases/tag/v8.3.0-rc.0) | yes | v1.7.0-beta.2 | "Lighthouse v8.3.0-rc.0 is a **release candidate with support for the upcoming Gloas hard fork on Sepolia**." Its table: Sepolia, fork epoch 353024, fork slot 11296768, 6 October 2026 13:53:36 UTC. |
<!-- release-notes:sepolia:end -->

Both notes name the same activation time as our pinned epoch. In a local run, the pinned
Lighthouse image answered `/eth/v1/config/spec` with an empty diff against the pinned config,
and the pinned Reth listed `engine_newPayloadV5`/`V6`, `engine_getPayloadV6` and
`engine_forkchoiceUpdatedV4`/`V5` in `engine_exchangeCapabilities`; Reth's note does not name
the Engine API methods. Lighthouse v8.2.x does **not** run Sepolia past the fork (its v8.2.3
notes: "If you are running a node on Sepolia you'll need v8.3.0-rc.0 instead").

### Hoodi

<!-- release-notes:hoodi:begin -->
| Image | Client | Release | Schedules Hoodi's fork | consensus-specs | Release-note line, or a dev build's fork-schedule check: Hoodi Gloas / Amsterdam |
|---|---|---|---|---|---|
| `ghcr.io/paradigmxyz/reth:nightly@sha256:8765a1d57878bebd40362d71bbfc0834d231847952402f9a10848c14476b90d2` | reth | dev build of [`e667968`](https://github.com/paradigmxyz/reth/commit/e667968725ff553f65dfecf161e63f6eab96fcc2) (`nightly`, built 2026-10-18; no release yet) | yes | n/a (EL) | Source check: `e667968725ff553f65dfecf161e63f6eab96fcc2` is 94 commits past `6096d25e9a50` "feat: schedule Hoodi Amsterdam activation" ([#27811](https://github.com/paradigmxyz/reth/pull/27811)) and builds with `alloy-hardforks` 0.4.10, whose `HOODI_AMSTERDAM_TIMESTAMP` is 1793036568 (2026-10-26 17:42:48 UTC, the first slot of epoch 132352). The image's SLSA provenance names this commit. |
| `sigp/lighthouse:latest-unstable@sha256:be7fdbcd4a321647f0300ae8dc3a9542bf391129ecaf521892f0b27dfe2e9658` | lighthouse | dev build of [`c8ddac7`](https://github.com/sigp/lighthouse/commit/c8ddac7b79d49812283873eb6625149ef0d27f95) (`unstable`, built 2026-10-16; no release yet) | yes | v1.7.0-beta.4 | Source check: at `c8ddac7b79d49812283873eb6625149ef0d27f95` the built-in Hoodi config has `GLOAS_FORK_EPOCH: 132352`, and `testing/ef_tests/Makefile` pins `CONSENSUS_SPECS_TEST_VERSION` v1.7.0-beta.4. The Kurtosis devnet's Lighthouse image is built from the same commit; the image's SLSA provenance names it. |
| `ghcr.io/paradigmxyz/reth:v2.7.0@sha256:a7f059d470878a5a59f3c575f3fc81b536d0d2d56d7a1cbed73e717a4f766336` | reth | [v2.7.0](https://github.com/paradigmxyz/reth/releases/tag/v2.7.0) | no | n/a (EL) | Sepolia only: "This release schedules Amsterdam activation on Sepolia testnet". No Hoodi line; its Hoodi fork-ID test ends at Osaka and the BPO forks. |
| `sigp/lighthouse:v8.3.0-rc.0@sha256:3e5f0609c74b824d3cb1049920169114d99fd7bc9082b996b3adae3d4e9ef8dc` | lighthouse | [v8.3.0-rc.0](https://github.com/sigp/lighthouse/releases/tag/v8.3.0-rc.0) | no | v1.7.0-beta.2 | "The Gloas fork is not yet scheduled on Hoodi or mainnet." Its built-in Hoodi config has `GLOAS_FORK_EPOCH: 18446744073709551615`. |
<!-- release-notes:hoodi:end -->

**Hoodi runs two dev builds, pinned by digest.** As of 2026-10-19 no Reth or Lighthouse
release schedules Hoodi's fork: v2.7.0 and v8.3.0-rc.0 are the latest tags, and the Hoodi
announcement
([blog.ethereum.org, 2026-10-16](https://blog.ethereum.org/en/2026/10/16/glamsterdam-hoodi-announcement))
leaves both rows of its client tables empty ("Only use a release whose notes explicitly
confirm support for the scheduled Glamsterdam activation on Hoodi"). The fork is scheduled only
in unreleased code, so `.env.hoodi.example` pins the two dev images of the first two rows, the
reference nodes' one exception to running releases, until the
[repin to releases](#repin-to-releases) below. The Lighthouse build targets consensus-specs
**v1.7.0-beta.4**, the same as our client. Sepolia stays on its releases, which schedule its
fork (already past).

`preflight.sh` accepts for Hoodi exactly the images whose row here says `yes`, each for its
own client: these two digests under these two tags. It refuses a tag alone (`nightly`, `latest-unstable`), the same
tag at any other digest (both tags move every day), the same digest under another tag, any
image with no row (no recorded fork-schedule check), either pin under the other service's
variable or the other client's repository, and the two releases whose rows say `no`.
The run log fails criterion 1 on the same rules.

**Pull both images onto the Hoodi host now, and keep them.** An untagged dev digest stays
pullable only while its registry keeps it, and neither ghcr.io nor Docker Hub promises that
once the tag has moved on. So, on the Hoodi host, before anything else:

```bash
sudo docker pull ghcr.io/paradigmxyz/reth:nightly@sha256:8765a1d57878bebd40362d71bbfc0834d231847952402f9a10848c14476b90d2
sudo docker pull sigp/lighthouse:latest-unstable@sha256:be7fdbcd4a321647f0300ae8dc3a9542bf391129ecaf521892f0b27dfe2e9658
```

Check that both are there (`sudo docker image inspect <pin>` prints the image). Until the
repin, run no `docker image prune -a` or `docker system prune -a` on that host: before the
containers exist, either deletes the pulled images, and the digests may be gone upstream.

<!-- repin-to-releases:begin -->
#### Repin to releases

Aim to finish by **2026-10-24**, a day before the sync deadline. A repin recreates the
containers on the same data directories, which needs no resync unless a release note says
otherwise. Move each client on its own, as soon as its release qualifies:

- [ ] **Reth:** v2.8.0 or later is tagged, its release notes confirm Hoodi's Amsterdam
  activation, and the EF announcement's client table lists it.
- [ ] **Lighthouse:** v8.3.0 is tagged, its release notes confirm Hoodi's Gloas fork (epoch
  132352), and the EF announcement's client table lists it.
- [ ] For each release: take its index digest (`docker buildx imagetools inspect
  <image:tag>`), add a row to the table above with its client, `yes`, the release-note line and (for
  Lighthouse) the `CONSENSUS_SPECS_TEST_VERSION` at the tag, and put the pin in
  `.env.hoodi.example` and the host's `.env.hoodi`. Delete the dev build's row, so that
  `preflight.sh` refuses it again, and update the pins `tests/ref-node.test.sh` checks.
- [ ] On the Hoodi host: `sudo docker pull <the new pin>`, `sudo ./preflight.sh --env-file
  .env.hoodi`, then the `start:` line it prints (recreates the service), and collect a new run
  log.
- [ ] A client whose release is not out by 2026-10-24 keeps its dev pin through the fork; note
  it in the run log.
<!-- repin-to-releases:end -->

If neither team ships and a dev build fails on Hoodi, the fallback is a pair the announcement
lists (for example Teku 26.10.1 or Nimbus 26.10.1 with Nethermind 2.2.0 or Besu 26.10.0); that
needs its own compose services and run-log checks, so decide it early.

## Migrating a Sepolia `.env` from `ops/sepolia-ref`

The stack used to live in `ops/sepolia-ref`, Sepolia only. An `.env` from there has no
`NETWORK`, no `CHECKPOINT_SYNC_URL_2` and none of the port keys, so the scripts refuse it
(`NETWORK must be sepolia or hoodi`). Move it to `ops/ref-node/.env` and add these lines, the
Sepolia values of `.env.example`:

<!-- migration:sepolia-ref:begin -->
```text
NETWORK=sepolia
CHECKPOINT_SYNC_URL_2=
ENGINE_PORT=8551
BEACON_API_PORT=5052
RETH_P2P_PORT=30303
LIGHTHOUSE_P2P_PORT=9000
LIGHTHOUSE_QUIC_PORT=9001
```
<!-- migration:sepolia-ref:end -->

Each key may appear only once, so add none that the file already has. Then rerun `setup.sh`
and `preflight.sh`: a `CHECKPOINT_SYNC_URL` that carries a key in its path is now refused (see
[Keyed checkpoint providers](#keyed-checkpoint-providers)).

## Runbook

The steps for one network; for Hoodi add `--env-file .env.hoodi` to every script and compose
command (see above).

1. **Pick versions.** Check the latest
   [Reth](https://github.com/paradigmxyz/reth/releases) and
   [Lighthouse](https://github.com/sigp/lighthouse/releases) releases for the network's Gloas /
   Amsterdam support (Hoodi: pull and keep its dev images first, and follow
   [Repin to releases](#repin-to-releases)). To change a pin, take the index digest
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
   them and refuses them. No query or fragment (the API path is appended to the URL), no
   credentials, and no path that may hold a provider key: more than one path segment, or one
   of 16 characters or more. `CHECKPOINT_SYNC_URL` is on Lighthouse's command line, which any
   local user reads in `ps`, so a provider that needs a key goes behind a local proxy
   ([Keyed checkpoint providers](#keyed-checkpoint-providers)). Leave `TRUSTED_PEERS` empty for
   now.
3. **Set up the host:** `sudo ./setup.sh` creates the network's users, the directories and the
   JWT copies, and writes the ids and `DATA_ROOT` into the `.env` (mode 0600). It is idempotent
   and keeps the secret; `--rotate-jwt` replaces it. It creates `DATA_ROOT` itself if missing,
   never a directory above it: create the parent first (`/srv` exists on most hosts). It
   refuses a `DATA_ROOT` that is not a root-owned directory closed to group and others (so not
   `/tmp`), or that sits below a missing directory or one anyone but root could change, or has
   a symlink, a `..` or a hard-linked secret anywhere on its path or in its tree. It reads the
   `.env` once, through `lib/fsguard.py`, and refuses one that is a symlink, a FIFO, owned by
   anyone but root or you, or anything but a regular file with one link (`preflight.sh` and the
   run log read it the same way). It also refuses an `.env` that compose's parser would read
   differently: a byte other than printable ASCII and newline (a CR, a TAB, non-ASCII),
   `export`, indentation, a key set twice, and a blank, a quote, a backslash, a `#`, a `$` or
   a backtick in a value (compose keeps reading after a closing quote, so `DUMMY=''RETH_UID=0`
   would set `RETH_UID` too); full-line `#` comments may hold anything printable. It refuses
   a `NETWORK` other than `sepolia` or `hoodi` as well. The scripts keep their temp files
   under `/tmp`, never in `TMPDIR`.

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
   the ports, the ids (non-root, distinct, the network's users), the modes and owners (the
   data directories must be directories, the JWT copies regular files, with no symlink on
   either path), each checkpoint provider's `/eth/v1/config/spec` against the network's pinned
   config, and, with
   two providers, that provider 2 holds provider 1's finalized block with the same block and
   state root. The providers it checked are printed (scheme and host only): keep that output
   with the run log. Public endpoints have served pre-Gloas configs: pick another if a diff is
   not empty, and abort if the providers disagree on the anchor. It also fails if the shell
   exports any variable compose reads from the `.env` with another value, since compose would
   use the exported one; run compose through `sudo`, which starts from a clean environment.
   Its curl reads no `~/.curlrc`, uses no proxy from the environment and keeps no answer over
   1 MiB, for every request. Paste the `start:` line it prints: every word in it is quoted.

   **Anchor hook:** cl-sync's `anchor-fetch` will get `--providers A,B --check`, which fetches
   the finalized state and block from both providers and compares the block root, the state
   root and the header's `state_root`. Once it lands, run it with the two provider URLs before
   the start (the `TODO` in `preflight.sh` marks the place) and feed its verified state and
   block to Lighthouse's checkpoint flags; until then the header comparison above is the
   cross-check.
5. **Start:** the `start:` line `preflight.sh` printed, `sudo docker compose -p <network>-ref
   --env-file <.env> -f <compose.yaml> up -d` (Sepolia: `-p sepolia-ref --env-file .env -f
   compose.yaml`; Hoodi: `-p hoodi-ref --env-file .env.hoodi -f compose.yaml`).
6. **Wait for sync** (about a day): `curl -s 127.0.0.1:<BEACON_API_PORT>/eth/v1/node/syncing`.
7. **Trust the session's peer ID** (Sepolia). `--print-peer-id` reads the session's config and
   node key, so make both first. On the test host:
   1. Create the session's own account, with the key's directory as its home:
      `sudo useradd --system --create-home --home-dir /var/lib/m2a-session --shell
      /usr/sbin/nologin m2a-session`. The session runs only as this account.
   2. Write its node key as that user, mode 0600: `sudo -u m2a-session sh -c 'umask 077 &&
      head -c 32 /dev/urandom > /var/lib/m2a-session/node.key'`.
   3. Write a first `/etc/ethswarm/m2a-session.toml`, owned by root with mode 0644, in the
      root-owned `/etc/ethswarm` (`sudo install -d -m 0755 /etc/ethswarm`, then
      `sudo tee /etc/ethswarm/m2a-session.toml` and `sudo chmod 0644` on it). It holds
      `network = "sepolia"`, `peer = "<multiaddr>"` and
      `node_key = "/var/lib/m2a-session/node.key"`. Take the multiaddr from
      `curl -s 127.0.0.1:<BEACON_API_PORT>/eth/v1/node/identity` on the reference host (its
      `p2p_addresses` entry with the public IP). The session refuses a config that its own user
      could change.
   4. Run `sudo -u m2a-session m2a-session --print-peer-id`. It does not dial.

   Put the ID in `TRUSTED_PEERS` in `.env`, then
   `sudo docker compose -p sepolia-ref --env-file .env -f compose.yaml up -d lighthouse`
   (recreates Lighthouse with `--trusted-peers`). Collect the run log after this: it fails a
   container recreated after its versions check.
8. **Collect the evidence:**
   `sudo ./collect-run-log.sh > run-log-$(date -u +%Y%m%dT%H%M%SZ).md` (13 samples, 5 min
   apart: 1 h; add `--public-ip <ip>` if the identity shows no public address). It prints the
   run log on stdout and writes no file itself, so the log is created by your own shell, not
   by root. It exits non-zero if a criterion failed. Criteria 3 and 9 fail if either service
   runs another container than the one criterion 1 checked (recreated or stopped during the
   hour of samples or the checks after it, its image, hardening and uid unchecked): 3 compares
   right after the samples, 9 once more at the very end. A run of fewer than 12
   samples, or spanning under an hour, is marked DIAGNOSTIC (not acceptance) and never
   passes. Lighthouse creates its node key
   (`$DATA_ROOT/lighthouse/data/beacon/network/key`) under umask 077, so it is 0600.
9. **Post the run log** on the issue. It holds no secret: the JWT copies and the node key are
   only fstat'ed, through `lib/fsguard.py`, and the checkpoint URLs appear as scheme and host
   only.
10. **Run the session** on the test host (Sepolia): open the tunnel
    (`ssh -N -L 5052:127.0.0.1:5052 <ref-host>`), replace `/etc/ethswarm/m2a-session.toml` of
    step 7 with the run log's last section, owned by root with mode 0644 as before, and run
    `sudo -u m2a-session m2a-session --dial-only`. The `m2a-summary` line names the user
    (`os_user`).

## Keyed checkpoint providers

Lighthouse's checkpoint URL is on its command line (`--checkpoint-sync-url`), so any local user
reads it in `ps`. `preflight.sh` therefore refuses a checkpoint URL with credentials or a path
that may hold a key (more than one path segment, or one of 16 characters or more), for both
providers. To use a provider that needs a key, run a reverse proxy on the host's loopback
(nginx or Caddy, for example; this stack does not ship one) that forwards to the provider's
keyed URL over https, with the key in the proxy's own root-only (0600) config file and never on
its command line, and set `CHECKPOINT_SYNC_URL=http://127.0.0.1:<port>`: `preflight.sh` accepts
plain http to a loopback host. Bind it to loopback only and keep its port off the firewall list.
On Hoodi the two providers must be on different hosts, so give a second proxy another loopback
address (`http://127.0.0.2:<port>`), and make sure the two still forward to different operators:
`preflight.sh` and the run log then name only the proxies, so record the upstream providers
with the run log yourself.

The check is a heuristic, not a proof: it cannot see a key that sits in the host name (a
per-customer subdomain such as `<key>.provider.example`) or a key under 16 characters in a
single path segment. Both pass `preflight.sh` and end up readable in `ps`. If a provider puts
any credential in its URL, use the proxy, whatever `preflight.sh` says.

## Tests

`bash ops/ref-node/tests/ref-node.test.sh` runs offline as a normal user (CI runs it): the
spec-diff helper against both pinned configs, the API verdicts, the anchor comparison,
`setup.sh --test-mode`, `preflight.sh --test-mode` (which ends "not a deployment gate") and
`collect-run-log.sh` for both networks against stub commands, and `docker compose config`
when docker is installed. As root it needs `ETHSWARM_ROOT_TESTS=1` and belongs in a throwaway
container only (it creates users): it then runs `setup.sh` and `preflight.sh` for real for
both networks side by side, every refusal as root, and the race regressions.
