# Kurtosis Gloas devnet

A local devnet that starts at Gloas (and Fulu) from genesis, for the p2p probe's discovery,
Status and serving tests and for exporting devnet blocks. `gloas-genesis.yaml` is an
[ethereum-package](https://github.com/ethpandaops/ethereum-package) args file built on the
package's `.github/tests/buildoor-genesis-builder.yaml` (Gloas at genesis, one genesis-registered
ePBS builder driven by buildoor) and `buildoor-instances.yaml` (Lighthouse + Geth and Lodestar +
Geth).

| | |
|---|---|
| Preset | `minimal`: 6 s slots, 8-slot epochs |
| Forks | every fork through Fulu at epoch 0, `gloas_fork_epoch: 0` (Heze off) |
| Participants | `cl-1-lighthouse-geth` (supernode, custodies every column), `cl-2-lodestar-geth`; each with its own validator client |
| Validators | 128: 64 keys per participant from the package's default mnemonic, written out in the file |
| Builders | 1, registered at genesis (`builder_count: 1`), run by `buildoor-lighthouse-geth-1` |
| Load | spamoor `blobs` (2 tx per slot, 2 blobs each), so blocks carry data columns, plus `eoatx` |
| Explorer | dora |

Status: the config, its image pin lint, the runtime checker, the pair runner and the block
export are in the repo. The first two runs (2026-10-18, Kurtosis CLI and engine 1.22.1, Docker
Desktop for macOS) were sequential: the first reached finalized epoch 3 on both CLs, and the
second, started after genesis, reproduced the genesis root but never finalized (see
"Reproducible genesis"). A concurrent pair on 2026-10-19 (same Kurtosis and Docker Desktop)
passed `check-devnet.sh --pair` (`pair verdict: PASS`, one genesis): the check ran from T+31 s to
T+252 s, and finality passed on poll 19 of 80 on the first enclave.

## Pins

The package is pinned to a full commit in every run command:

```text
github.com/ethpandaops/ethereum-package@3416a0252e5bc25a0d31d24fea9c46707447eb08
```

That commit (2026-10-16, "fix: hand genesis-registered builders to buildoor instances (#1483)")
was the head of `main` on 2026-10-18. Both buildoor YAMLs exist there; it accepts
`gloas_fork_epoch: 0` with `builder_count` (its input parser refuses builders unless Gloas is at
genesis); #1483 is the fix that hands the genesis builder to the buildoor instance, which is
exactly this file's builder setup; and its default genesis generator is 6.2.6, the version pinned
below.

Every image in `gloas-genesis.yaml` is pinned as `repo:tag@sha256:<index digest>`, and none is
left to a package default. `scripts/check-kurtosis-pins.sh` (in CI) fails otherwise: it also
requires every image key of each additional service (blockscout, for one, has `image`,
`verif_image` and `frontend_image`, read from the package's `sanity_check.star` and
`input_parser.star` at the pinned commit), fails closed on a service whose keys it does not
know, and requires a non-empty `participants` or `participants_matrix` (without either, the
package runs one default participant on floating images). The digests
are the multi-arch index digests (linux/amd64 and linux/arm64) that
`docker buildx imagetools inspect <repo:tag>` printed on **2026-10-18**.

| Image | Digest | Source commit |
|---|---|---|
| `ethpandaops/lighthouse:unstable-c8ddac7` (CL and VC) | `sha256:5b666c7b7d18454828a205bd94edd76c8d19068d62365c0fa676980cdd548bdd` | sigp/lighthouse `c8ddac7b79d4` (2026-10-16), the head of `unstable` |
| `ethpandaops/lodestar:unstable-b3beff2` (CL and VC) | `sha256:679d32d0f390840ae95b89d55bc1329f913e4a0da933faf0afd09e483dd08036` | ChainSafe/lodestar `b3beff224608` (2026-10-17), the head of `unstable` |
| `ethereum/client-go:v1.17.8` | `sha256:abf3605177f8bdcfce436985a8054cca4ae59256323a4ffb72c56c04f3d1fadd` | release v1.17.8 (2026-10-08) |
| `ethpandaops/buildoor:main-9f07c67` | `sha256:0352e947054d3195e43e8cb46b8704e16395779ba79c25d2369accb54b0bf87a` | ethpandaops/buildoor `9f07c677fabf` (2026-10-15), the head of `main` |
| `ethpandaops/spamoor:master-ca48df9` | `sha256:04e15158b1d1f941d4ff4cfc82f49c5150c23e16498f42fca95267e9c579e041` | ethpandaops/spamoor `ca48df9` (2026-10-16) |
| `ethpandaops/dora:master-28dc4c9` | `sha256:8a5a6af437f731bda765f7f4e43c425fc41909794db2723f3a9555881fc5aaf0` | ethpandaops/dora `28dc4c9` (2026-10-17) |
| `ethpandaops/ethereum-genesis-generator:6.2.6` | `sha256:f9a6d6b3a54942d3adbf057435a230241261d1af7d963637962d1644c29408cb` | release v6.2.6 (2026-10-15) |

On 2026-10-18 the moving tags the issue names had the same digests as the commit tags pinned here:
`ethpandaops/lodestar:unstable` (the issue's override of `chainsafe/lodestar:latest`) is
`sha256:679d32d0…`, and `ethpandaops/lighthouse:unstable` is `sha256:5b666c7b…`. The commit tag is
pinned rather than the moving tag because its name says which source the digest is.

### consensus-specs v1.7.0-beta.4, per client

What was confirmed, and how. No binary was run (downloaded images are treated as data). The
image labels were read from the registry on 2026-10-18 with
`docker buildx imagetools inspect --format '{{json .Image}}' <repo:tag@digest>`, which fetches the
image config without pulling or running it:

- `ethpandaops/lighthouse:unstable-c8ddac7` carries `commit=c8ddac7`,
  `ethpandaops.io.repo=sigp/lighthouse` and `ethpandaops.io.commitRef=unstable` on both
  platforms, so its link to sigp/lighthouse `c8ddac7b79d4` rests on its own labels.
- `ethereum/client-go:v1.17.8` carries `commit=a579077007b98217c3e253a66e4b452ca0c32b96`, the
  commit of the go-ethereum tag `v1.17.8`.
- The Lodestar, buildoor, spamoor, dora and genesis generator images carry no labels, so for
  those the link from image to source commit rests on ethpandaops' `<branch>-<short sha>` tag
  naming (or the release tag) and on the tag's push time on Docker Hub.

The spec version, per client:

- **Lighthouse: beta.4 at the source.** At `c8ddac7b`, `testing/ef_tests/Makefile` has
  `CONSENSUS_SPECS_TEST_VERSION ?= v1.7.0-beta.4`. The commit is 26 commits after `0c3765ea`
  ("Gloas spec v1.7.0-beta.4 (#10307)", 2026-10-12) and 0 behind it. The ethpandaops build sets
  `FEATURES=gnosis,spec-minimal,slasher-lmdb` (eth-client-docker-image-builder
  `lighthouse/Dockerfile`), so the image runs the minimal preset. The Sepolia reference node's
  `sigp/lighthouse:v8.3.0-rc.0` is **not** used here: its Makefile pins v1.7.0-beta.2, and the
  sigp release images are built without `spec-minimal`.
- **Lodestar: beta.4 at the source.** At `b3beff22`,
  `packages/beacon-node/test/spec-tests-version.json` has `"specVersion": "v1.7.0-beta.4"`.
  Lodestar picks the preset at runtime (`LODESTAR_PRESET`, which the package sets for minimal).
- **Geth v1.17.8: no claim to make.** The EL does not implement consensus-specs. The v1.17.6
  and v1.17.7 notes say they are ready for the Amsterdam fork on Sepolia (2026-10-06), and v1.17.8
  is a later security release with fixes for post-Amsterdam DoS cases. beta.3 and beta.4 list
  no Engine API change. Whether Geth runs Amsterdam from genesis with these CLs is unconfirmed
  until the first run.
- **buildoor: not confirmed.** The repository names no consensus-specs version (it builds on
  go-eth2-client v0.1.10). beta.4's only Gloas change is the state-transition rule "clear
  pending builder payments of slashed proposers", which changes no container a builder sends,
  but that is an inference, not a pin.
- **Genesis generator 6.2.6: not confirmed.** Its notes name no consensus-specs version (6.2.5
  bumped eth-beacon-genesis to v0.0.8). Both CLs loading its genesis state, and agreeing on its
  root, is the runtime evidence.
- **spamoor and dora:** tooling with no spec dependency. spamoor sends transactions over EL
  JSON-RPC, and dora reads the beacon API.

The package also starts helper containers from images named in its own source, not in the args
file: `protolambda/eth2-val-tools:latest` (validator keystores), `linuxserver/yq` (reads the
generated config), and the default `plan.run_sh` image. Only the package commit fixes those
references, and the tags can move. None of them builds the genesis state: the pinned generator
derives the validator set from the mnemonic itself.

## Run and tear down

You need the Kurtosis CLI and a running engine on Docker (`kurtosis engine start`). Record the
CLI version (`kurtosis version`) in the run log.

```bash
kurtosis run --enclave ethswarm-gloas \
  github.com/ethpandaops/ethereum-package@3416a0252e5bc25a0d31d24fea9c46707447eb08 \
  --args-file testing/kurtosis/gloas-genesis.yaml

kurtosis enclave inspect ethswarm-gloas          # services and their host ports
kurtosis enclave rm -f ethswarm-gloas            # teardown
kurtosis clean -a                                # also removes stopped enclaves (a clean engine)
```

With `genesis_time: 0`, genesis is the start time plus `genesis_delay` (120 s) plus the package's
startup padding. That is fine for a single run, but two runs get different genesis times and so
different genesis roots. The two-run check is a concurrent pair from one rendered args file
(see "Reproducible genesis").

Kurtosis 1.22.1 on Docker Desktop for macOS prints an OpenTelemetry `WARN` to stderr on every
CLI call (it looks for `/var/run/docker.sock`). It is harmless: `check-devnet.sh` reads only
stdout and shows the stderr only when a call fails, and `$(kurtosis port print ...)` in the
commands here captures stdout only.

## Read the genesis root and the fork schedule

```bash
cl=$(kurtosis port print ethswarm-gloas cl-1-lighthouse-geth http)
curl -s "$cl/eth/v1/beacon/genesis" | jq .data                 # genesis_time, genesis_validators_root, genesis_fork_version
curl -s "$cl/eth/v1/beacon/headers/genesis" \
  | jq '.data | {block_root: .root, state_root: .header.message.state_root}'
curl -s "$cl/eth/v1/config/fork_schedule" | jq -c '.data[]'
curl -s "$cl/eth/v1/config/spec" | jq '.data | {PRESET_BASE, GLOAS_FORK_VERSION, GLOAS_FORK_EPOCH, BLOB_SCHEDULE}'

# The generated network config (config.yaml, genesis.ssz, the EL genesis.json, ...):
kurtosis files download ethswarm-gloas el_cl_genesis_data ./ethswarm-gloas-genesis
```

"Genesis root" in the checks means the genesis block root and the genesis state root
(`hash_tree_root` of the genesis state). Both commit to `genesis_time`.
`genesis_validators_root`, which goes into every fork digest, depends only on the validator set:
the mnemonic, the key count and the withdrawal credentials. With the package defaults, the
generator writes one `BLOB_SCHEDULE` entry at epoch 0 (BPO 2, 21 blobs) and drops BPO 1, which
shares that epoch.

### Expected genesis root

To be filled in after the first pair of runs, with the args file they used (its `genesis_time`):

| Field | Value |
|---|---|
| `genesis_time` | _pending first run_ |
| `genesis_validators_root` | _pending first run_ |
| genesis block root | _pending first run_ |
| genesis state root | _pending first run_ |
| fork digest at epoch 0 | _pending first run_ |

## Reproducible genesis

The validator set is fixed: the mnemonic and key count are written out in the file, shuffling is
off, and the generator image is pinned. The genesis time is the only input that moves. The
package accepts a fixed `genesis_time`, and at the pinned commit uses it literally, but a fixed
value in the committed file would soon lie far in the past. Instead, the two runs of a pair use
one rendered copy with one `genesis_time` T.

**The two runs are a concurrent pair**: two enclaves, `ethswarm-gloas-a-<T>-<pid>` and
`ethswarm-gloas-b-<T>-<pid>` (T the genesis time, pid that of `run-pair.sh`, so no two runs share
an enclave name), started from the same rendered copy at the same time, both fully up before T.
A second run started *after* genesis does not finalize, so there is no path that launches a run
after T. In the first sequential runs, the second enclave started about 70 slots after genesis:
Lodestar (`b3beff2`) could not range-sync the missed slots from Lighthouse
(`DOWNLOAD_BY_RANGE_ERROR_MISSING_BLOCK_RESPONSE`; its only peer went to `failed_download_peers`
and was never retried), and without Lodestar's 64 validators Lighthouse could not justify an
epoch. Any gap after genesis can hit this, so T must leave time for both `kurtosis run`s. On
2026-10-19 the two concurrent runs on one engine, with the images pre-pulled, took 61 s and 64 s;
pulling the images cold adds a few minutes (203 s on the first run).

`run-pair.sh` (below, "Acceptance checks") pre-pulls every pinned image first, so the clock starts
only once both runs can begin, then renders the shared copy with T at least 900 s ahead
(`--lead S`, default and minimum 900; the 2026-10-19 pair used 1500 and was up 1,436 s before
genesis). It writes `target/kurtosis/pair-$T/gloas-genesis.yaml`, fails unless exactly one
`genesis_time` line holds T, and fails unless `scripts/check-kurtosis-pins.sh` passes on the
copy's directory (the rendered copy is pinned too). If you launch by hand without pre-pulling,
or want room for `--sequential-fallback`, leave more margin than 900 s.

Both enclaves then run side by side on one engine:

- **Memory.** On 2026-10-19 the pair peaked at 4.75 GiB and 738% CPU around genesis, then held
  about 4.56 GiB and 197% CPU (one enclave alone peaked at about 2.7 GiB on the first run, the
  Lodestar CL 1.5 GiB of it). That fits the 7.7 GiB Docker Desktop VM of the first runs with
  about 3 GiB to spare for the engine's own containers. Check the VM's size with
  `docker info --format '{{.MemTotal}}'` and stop other containers first; `run-pair.sh` removes
  both enclaves on every exit.
- **Host ports.** The two enclaves do not collide. At the pinned commit every fixed host port
  comes from `port_publisher` (`public_port_start` 32000-38000 per component), and each of its
  sections is off by default; `gloas-genesis.yaml` does not set it. Without it, Kurtosis
  publishes every service port on an ephemeral host port of its own choosing (the first runs
  got `127.0.0.1:50802` and `127.0.0.1:54163`), so read each URL with
  `kurtosis port print <enclave> <service> http`, never a fixed number. Enabling
  `port_publisher` (or adding blockscout, whose frontend has a fixed port) would make the second
  enclave collide with the first.
- **Network.** Each enclave runs on its own Docker network (`kt-<enclave>`), and each enclave's
  CLs boot from its own `cl-1-lighthouse-geth`, so the two chains share a genesis but do not
  peer with each other.

## Acceptance checks

`check-devnet.sh ENCLAVE` finds every `cl-<n>-*` service with `kurtosis enclave inspect`, reads
each one's beacon API through `kurtosis port print ENCLAVE <service> http`, and prints evidence
and a verdict per criterion. It prints `verdict: PASS (3/3 criteria)` and exits 0 only on an
acceptance run where every criterion passes. An acceptance run checks every CL service the
enclave runs, at least 2 distinct ones, with `--min-finalized-epoch` of at least 3. A run that
misses any of these (`--services` naming a subset of the enclave's CLs, a one-CL enclave, or a
lower threshold) prints one `diagnostic:` line per reason and, if every criterion passes,
`verdict: DIAGNOSTIC (...)` with exit 3: useful while debugging, but never acceptance evidence.
A `--services` CL that the enclave does not run is a setup error (exit 2), and a failed
criterion is `verdict: FAIL` (exit 1) either way.

`check-devnet.sh --pair ENCLAVE_A ENCLAVE_B` checks a concurrent pair: every criterion on each
enclave in turn (under a `== <enclave>` header, the same options for both), then
`pair genesis`: both enclaves' genesis records must be equal (`genesis_time`,
`genesis_validators_root`, `genesis_fork_version`, genesis block root and state root). It ends
with `pair verdict: PASS` (exit 0) only when both runs are acceptance passes and the genesis is
one; otherwise exit 2 if either enclave's run is a setup error, else 1 (`pair verdict: FAIL`,
naming the failed enclave or `pair genesis`), else 3 (DIAGNOSTIC). `--record` writes the pair's
one genesis, and `--reference` checks both enclaves against an earlier record. Every `kurtosis`
call (`enclave inspect`, `port print`) is bounded to `--kurtosis-timeout` seconds (default 60);
one that takes longer is killed and is a setup error (exit 2). The criteria:

- `genesis`: every CL reports the same `genesis_time`, `genesis_validators_root`,
  `genesis_fork_version`, genesis block root and genesis state root. With `--reference`, they
  must also equal an earlier run's record (`--record` writes one).
- `fork_schedule`: on every CL, `GLOAS_FORK_EPOCH` is 0, `/eth/v1/config/fork_schedule` has the
  Gloas version at epoch 0 and in force there, every CL serves the same scheduled forks, and
  the fork digests in the CLs' own ENRs (`eth2` entry) agree. Entries at FAR_FUTURE_EPOCH
  (2^64 - 1, a fork the client knows but has not scheduled) are dropped before the schedules
  are compared: Lodestar lists the unscheduled Heze fork there (`0x90000038`), Lighthouse does
  not.
- `finality`: every CL's finalized epoch (`/eth/v1/beacon/states/head/finality_checkpoints`) is
  at least 3 (`--min-finalized-epoch`; below 3 the run is DIAGNOSTIC), on one finalized
  checkpoint (epoch and root). This is polled `--attempts` times (default 40), `--interval`
  seconds apart (default 12).
- `goodbye3` (exit 10 (b), only with `--probe-log FILE`, repeatable, and not with `--pair`):
  zero Goodbyes with reason 3 from every reference CL during the probe's run. It lists each CL
  with its client and pinned image (`cl_image` of participant `<n>` of `--args`, default
  `gloas-genesis.yaml`, for service `cl-<n>-<client>-*`), and the `goodbye_received` lines
  from its peer ID (`/eth/v1/node/identity`) in the probe's stderr logs, by reason, over the
  epochs one log observed it (first to last line naming the peer in that log; an epoch is
  `SLOTS_PER_EPOCH` slots of `SLOT_DURATION_MS` or `SECONDS_PER_SLOT`):
  `cl-1-lighthouse-geth: goodbye3 0 (other Goodbyes 0) in 12.5 epochs (600.0 s in one log, peer ...)`.
  Each log is one probe run, and one run must observe a CL for 2 epochs on its own: windows
  are never joined across logs, since the time between two runs is no observation. Any
  reason-3 Goodbye from a CL fails, and so do a CL the logs never name, two CLs with one peer
  ID, an args participant that runs another client or an image without `@sha256:`, and a log
  that cannot prove there was none: an empty one, a line that is not JSON or has no timestamp,
  the log writer's `log lines dropped` line, or a `goodbye_received` line without an integer
  reason or a well-formed peer ID (`12D3KooW…`, `16Uiu2HA…` or `Qm…`, base58; checked before
  the reference CLs are picked out, since a malformed one could be any CL's). A CL observed
  for under 2 epochs makes the run DIAGNOSTIC. With it the verdict counts 4 criteria.

The concurrent pair from a clean engine (criteria 1, 2 and 4 of the issue) is one script,
`testing/kurtosis/run-pair.sh`, run from anywhere in the checkout. It needs `kurtosis` (with a
running engine), `docker`, `python3` and what `check-devnet.sh` and `check-kurtosis-pins.sh`
need.

**The engine must be dedicated to this run.** Without `--clean-engine` the script never cleans
the engine: it lists the enclaves (`kurtosis enclave ls`) before the pulls and again just before
the launches, and refuses to go on (exit 2, naming them) if there is any, so an enclave created
in between is refused too, never removed. An answer without the `UUID` header line, an empty one
included, is refused as well. Remove the enclaves yourself, or pass `--clean-engine`: then the
script skips both listings and runs `kurtosis clean -a` (bounded to 300 s; one that fails or
times out stops the run, exit 2), which removes **every** enclave on the engine, just before the
launches. Each step fails closed:

1. **Pre-pull and render** ("Reproducible genesis"): any failed pull, render check or pin lint,
   or a logs directory that cannot be made, stops the run before anything is launched (exit 2).
   The run makes `target/kurtosis/pair-$T` itself: one that exists already (another run in the
   same checkout rendered the same T) stops the run too (exit 2), and is left alone.
2. **Launches.** The second listing (or with `--clean-engine`, `kurtosis clean -a`), then both
   `kurtosis run`s at once, of `ethswarm-gloas-a-<T>-<pid>` and `ethswarm-gloas-b-<T>-<pid>`
   (printed as `launching ...`), each logged to `target/kurtosis/pair-$T/<enclave>-run.log`. Both
   must exit 0 (else exit 2, naming the failed ones), and both must be up before T (else exit 4:
   render a later T and start again). A launch still running at T is stopped (exit 4).
3. **Fallback** (`--sequential-fallback`, off by default): if a concurrent launch fails, each
   failed enclave is removed (`kurtosis enclave rm -f`, bounded to 120 s), confirmed gone (a
   `kurtosis enclave ls`, bounded to 30 s, that answers with its `UUID` header and does not list
   it; a listing that fails, times out, has no header or still lists it stops the run, exit 2),
   and launched again alone, one after the other (the failed log is kept as
   `<enclave>-run-concurrent.log`). A relaunch starts only with at least 120 s left before T,
   checked before the removal and again just before the launch, and both enclaves must still be
   up before T.
4. **Check.** After T, `check-devnet.sh --pair --record target/kurtosis/pair-$T/genesis.json`
   on both enclaves, shown and kept in `check.log`. The check's own exit code (0 pair PASS, 1
   FAIL, 2 setup error, 3 DIAGNOSTIC) is the script's exit code; a `check.log` that cannot be
   written turns only a PASS into a 2. The check is bounded to 3600 s (its own bounds, with its
   defaults, add up to about 52 min on the two enclaves); one that runs longer is stopped, exit
   2. On 2026-10-19 (with `--attempts 80`) the check ran from T+31 s to T+252 s and finality
   passed on poll 19, inside the default 40 polls, 12 s apart.
5. **Teardown.** An EXIT/INT/TERM/HUP/PIPE trap, set before the first step, stops the background
   jobs on every exit and, from the launches on, removes the pair, an interrupt while waiting for
   genesis or finality and a closed terminal or output pipe included (exit 130 on INT, 143 on TERM,
   129 on HUP, 141 on PIPE). A signal that lands while a job is starting takes effect once the job
   is recorded, so the teardown always finds it. Every pull, `kurtosis` call, `docker stats`, the
   wait for genesis and the check run as background jobs, each the leader of its own process group;
   stopping one is TERM to the group and to every descendant, then KILL 10 s later to whatever still
   runs, a process that ignores TERM or that left the process tree included. When a job's leader
   ends, whatever is left in its group gets the same TERM, then KILL, so nothing a step started
   outlives it; each launch is swept as soon as it ends, while the other may still run. Whether a
   job still runs is what bash saw of it (its job table), never a lookup of its pid, which another
   process may take once the job has ended. A job stopped with SIGSTOP counts as running: it gets
   the TERM, then CONT so the TERM lands, and the KILL if it outlives the 10 s. The wait for genesis
   polls that job table too, so a genesis sleep stopped with SIGSTOP does not end the run:
   continued, it ends as it would have, and one still stopped at genesis is stopped and the check
   runs. No pid or group below 2 (`kill -- -1` reaches every process the user owns) and never the
   script's own pid gets a signal, and every `ps` runs under `LC_ALL=C`, so start times read the
   same whatever the locale. A group whose leader bash has reaped is signalled only while, in the
   process list read just before, it has a process and no process has its id as pid (the kernel
   gives no process a pid that is still a group's id, so a process with that pid leads another
   group, which took the id once this one emptied). Two cases remain where a signal can still reach
   another process's group, and both need the kernel to hand the same pid out again first: the group
   empties and its id passes to a new group in the milliseconds between that list and the kill; or,
   before the list, the group emptied and a new process took the id as its pid and group, then ended
   while its group lived on. A descendant is signalled only while the same process (pid and start
   time, both from one process list) runs. Each job ignores SIGTTOU, so a terminal with `stty
   tostop` cannot stop the check's output (it would hang the run); bash 3.2 sets SIGTTOU back to its
   default in every child it forks, so the check's `tee` ignores it again as it starts. Then the
   teardown runs `kurtosis enclave rm -f` for each of the run's two enclaves, by name, each bounded
   to 120 s and each run even if an earlier step failed. It removes nothing else: no other run's
   enclave and no `kurtosis clean -a` at the end. A failed teardown after a PASS exits 2.
   `--keep-on-pass` leaves the pair running after a PASS only (exit 0), for "Export blocks and
   roots", and prints the teardown commands; any other exit still tears down.

Each `kurtosis enclave ls` (before the pulls, before the launches and in the fallback) is
bounded to 30 s; one that times out is a setup error (exit 2).

While a job runs, `target/kurtosis/pair-$T/job-groups` lists the process group of each running
job, one per line; the script replaces it whole (a new file renamed over it) as jobs start and
end, and the teardown removes it.

`docker stats --no-stream` (bounded to 30 s, never fatal) is kept for CI sizing as
`stats-up.txt` (both enclaves up) and `stats-checked.txt` (after the check), and the script
prints how long the launches took:

```bash
bash testing/kurtosis/run-pair.sh                       # exit 0: pair PASS, then teardown
bash testing/kurtosis/run-pair.sh --lead 1500 --sequential-fallback --keep-on-pass
bash testing/kurtosis/run-pair.sh --clean-engine        # removes every enclave on the engine first

# Teardown by hand after --keep-on-pass: the two commands it printed, with the run's names.
kurtosis enclave rm -f ethswarm-gloas-a-<T>-<pid>
kurtosis enclave rm -f ethswarm-gloas-b-<T>-<pid>
```

A script killed with SIGKILL runs no teardown, and **its jobs keep running**: each is the leader of
its own process group, so a `kurtosis run` can still be creating an enclave, or the check still
polling, after the script is gone. Stop those groups first, then remove the enclaves. The jobs that
were running are in `job-groups` (before the render, the only job is a `kurtosis enclave ls` or a
`docker pull`, which ends on its own), and the enclave names are those of the `*-run.log` files. A
recorded id is only a number: once its job has ended, another process (yours or not) may hold it.
`stop-killed-run.sh` stops only a recorded group whose leader still runs and names this run's
enclaves on its command line (a `kurtosis run`, a `kurtosis enclave rm`, or the check), as a whole
word: `ethswarm-gloas-a-<T>-<pid>` or `ethswarm-gloas-b-<T>-<pid>` with no letter, digit, `_`, `.`
or `-` on either side, so run `…-4242` never matches `…-42420` or `…-4242-x.log`. The run must be
`<T>-<pid>` exactly (an epoch second of 9 to 11 digits and a pid of 2 or more), else it is a usage
error (exit 2). It never signals an id below 2, its own process group or its own pid, and runs every
`ps` under `LC_ALL=C` (macOS words a start time by the locale) and with `-ww` where it reads a
command line (Linux procps cuts it at an exported `COLUMNS`, even into a pipe). It finds the groups
in one process list, and a list that fails or is empty is read again, 1 s later, up to 3 times. A
list that still cannot be read is an exit 2, never "no recorded group is left" or "nothing was
left": before the TERM nothing has been signalled, so run it again; after the TERM, check by hand
(`LC_ALL=C ps -ww -A -o pid,pgid,command`, then `kill -KILL -- -<pgid>` for what is left of the
listed groups), since another run no longer finds a group whose leader the TERM ended. The other
jobs (`kurtosis enclave ls`, `kurtosis clean -a`, `docker stats`, the wait for genesis) end on their
own. It lists those groups and their processes, sends TERM to each that is still there in a process
list read just before (a leader that ended since it was found, its pid then taken by another
process, gets none), and 10 s later (sooner once none is left) KILL to each that is still there:
while its leader runs (the same pid and start time), or, once TERM has ended the leader, while a
process of the group runs and no process has the group id as its pid (a surviving member keeps the
id from passing to another group, and a process with that pid leads another group). So a child that
ignores TERM still gets the KILL after its leader has died. The same two pid-reuse cases as in the
teardown above remain (the milliseconds between a process list and a kill, and the id passing on
during the 10 s through a process that ended while its group lived on):

```bash
logs=target/kurtosis/pair-<T>                         # the killed run's logs directory
ls "$logs"/*-run.log                                  # <enclave>-run.log: the run's two enclaves
run=<T>-<pid>                                         # their suffix, this run's own
bash testing/kurtosis/stop-killed-run.sh --list "$logs" "$run"   # look first: signals nothing
bash testing/kurtosis/stop-killed-run.sh "$logs" "$run"          # TERM, then KILL 10 s later
kurtosis enclave rm -f ethswarm-gloas-a-<T>-<pid>
kurtosis enclave rm -f ethswarm-gloas-b-<T>-<pid>
rm "$logs/job-groups"
```

The same checks by hand, one CL at a time:

```bash
for svc in cl-1-lighthouse-geth cl-2-lodestar-geth; do
  url=$(kurtosis port print ethswarm-gloas "$svc" http)
  echo "== $svc"
  curl -s "$url/eth/v1/beacon/headers/genesis" | jq -r '.data | "block \(.root) state \(.header.message.state_root)"'
  curl -s "$url/eth/v1/beacon/states/head/finality_checkpoints" | jq -c .data.finalized
  curl -s "$url/eth/v1/config/fork_schedule" | jq -c '[.data[] | select(.epoch == "0") | .current_version] | last'
  curl -s "$url/eth/v1/config/spec" | jq -r '.data.GLOAS_FORK_VERSION'
done
```

The image pin lint (criterion 3) runs in CI and needs no devnet:

```bash
bash scripts/check-kurtosis-pins.sh                       # testing/kurtosis/*.yaml
bash testing/kurtosis/tests/check-devnet.test.sh          # check-devnet.sh against stub kurtosis/curl
bash testing/kurtosis/tests/run-pair.test.sh              # run-pair.sh against stub kurtosis/docker,
                                                          # and stop-killed-run.sh
```

## Export blocks and roots

`export-blocks` (`crates/testkit/src/bin/export-blocks.rs`) reads every slot from genesis to an
export slot from one CL's beacon API and writes `OUT/<devnet>/`: an archive segment of the
blocks (the same format and `manifest.toml` as the archiver), `genesis_state.ssz`, and
`export.toml`, which records the devnet name, the CL it came from, the genesis time, validators
root, block root and state root, the config's sha256, fork schedule and digests, the image
digests, the slot range with its empty slots, and every block's root and parent root. Replay
opens an export only through `testkit::export_blocks::open_export_pinned`, with the export's
`export_sha256` from the run log, which verifies all of it (each segment through
`archive::open_verified`).

Per slot it fetches `/eth/v2/beacon/blocks/{slot}` as SSZ (a 404 is an empty slot, recorded,
only if `/eth/v1/beacon/blocks/{slot}/root` answers 404 too), decodes the block by the fork of
its own slot, and fails the export unless our `hash_tree_root` equals
`/eth/v1/beacon/blocks/{slot}/root` and the block's parent is the previous block (across empty
slots). The genesis block must have a zero parent; the genesis state is read by that block's
`state_root` (`/eth/v2/debug/beacon/states/{state_root}`; Lodestar without
`--serveHistoricalState` answers 500 for the `genesis` id) and must hash to it. The export slot must be at or before
the CL's finalized block, so the roots cannot change under the export, and the walk continues
(checking, not archiving) to the finalized header's block and must end on it, so the trailing
empty slots are anchored too. A CL that also lies on `/eth/v1/beacon/headers/finalized`, or
serves a wrong finalized chain consistently, still passes a single export; only the two-CL
`diff` below catches that. The output directory is claimed with an exclusive `mkdir`, so a
second export into it fails. A failed export writes no `export.toml`, so its directory never
opens as an export. `open_export` decodes the genesis state and every block again and checks
them against `export.toml` (genesis fields and roots, each block's slot, root, parent and fork
digest), and refuses a genesis state file over 256 MiB before reading it.

The contract: opening proves that an export holds together and is a hash chain from its genesis
block and state, nothing more. It checks no signature and runs no state transition, so anyone
who can write the directory can fabricate a consistent suffix (drop or replace the tip, rewrite
the blocks after any slot) and rehash every manifest. Fork digests are not recomputed either
(from Fulu every digest mixes in the epoch's blob parameters, which the export does not carry).
Only the `export_sha256` that `export` printed, kept in the run log, authenticates an export:
`verify --sha256`, `diff --sha256-a/--sha256-b` and `open_export_pinned` refuse any other.

Status: run live on the local devnet pair (export slot 24): the Lighthouse and Lodestar exports
both pass `verify --sha256`, and `diff` reports identical root lists, 25 slots and 25 blocks.
`network-config` reads the generated `config.yaml`.

Run it on a devnet whose finalized epoch is at least 3 (`check-devnet.sh` passes), from the repo
root. For a concurrent pair, export from one of its enclaves (`ethswarm-gloas-a-<T>-<pid>`, as
`run-pair.sh --keep-on-pass` printed it) before the teardown:

```bash
enclave=ethswarm-gloas          # ethswarm-gloas-a-<T>-<pid> for a pair
genesis=target/kurtosis/$enclave-genesis
export_root=target/kurtosis/export
kurtosis files download "$enclave" el_cl_genesis_data "$genesis"   # config.yaml, genesis.ssz, ...
cargo build --release --locked -p testkit --bin export-blocks
bin=target/release/export-blocks

# Every pinned image of the args file, as --image repo:tag@sha256:<digest>.
image_args=()
for image in $(grep -oE '[A-Za-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' \
                 testing/kurtosis/gloas-genesis.yaml | sort -u); do
  image_args+=(--image "$image")
done

lh=$(kurtosis port print "$enclave" cl-1-lighthouse-geth http)
ls=$(kurtosis port print "$enclave" cl-2-lodestar-geth http)

# The export slot: the lower of the two CLs' finalized block slots.
finalized() { curl -s "$1/eth/v1/beacon/headers/finalized" | jq -r .data.header.message.slot; }
a=$(finalized "$lh"); b=$(finalized "$ls"); to=$(( a < b ? a : b )); echo "export slot $to"

# Each export's one-line summary goes into the run log and into this run's own summary file;
# its last field is the export_sha256. pipefail gives each pipe the export's status, not tee's,
# and the && chain stops at a failed export (an --out that exists already, say) and reads no
# pin. The pins come only from this run's summary files, never from an older run-log line.
mkdir -p "$export_root"
set -o pipefail
lh_sha= ls_sha=
"$bin" export --api "$lh" --config "$genesis/config.yaml" --devnet "$enclave" \
  --source cl-1-lighthouse-geth --to "$to" --out "$export_root/lighthouse" "${image_args[@]}" \
  | tee -a "$export_root/run.log" | tee "$export_root/lighthouse.summary" \
&& "$bin" export --api "$ls" --config "$genesis/config.yaml" --devnet "$enclave" \
  --source cl-2-lodestar-geth --to "$to" --out "$export_root/lodestar" "${image_args[@]}" \
  | tee -a "$export_root/run.log" | tee "$export_root/lodestar.summary" \
&& lh_sha=$(awk '{print $NF}' "$export_root/lighthouse.summary") \
&& ls_sha=$(awk '{print $NF}' "$export_root/lodestar.summary") \
|| echo "an export failed: no pins read" >&2
```

Each `export` prints one line: the slot range, the block and empty-slot counts, the genesis
block and state roots, the last block's slot and root, and the export's `export_sha256`.
`verify --sha256 <export_sha256>` prints the same line for an existing export, and exits 1 if
it is refused or is not the pinned export.

The checks, with the two exports above:

```bash
# Each export is the one its run-log digest pins.
"$bin" verify --sha256 "$lh_sha" "$export_root/lighthouse/$enclave"
"$bin" verify --sha256 "$ls_sha" "$export_root/lodestar/$enclave"

# Both CLs' exports have identical root lists (exit 1 and the first differing slot otherwise).
"$bin" diff --sha256-a "$lh_sha" --sha256-b "$ls_sha" \
  "$export_root/lighthouse/$enclave" "$export_root/lodestar/$enclave"

# Count check, on both CLs: each one's API block count over 0..=$to equals its export's
# "N blocks" (printed by the pinned verify above).
for c in lighthouse:$lh lodestar:$ls; do
  n=0
  for s in $(seq 0 "$to"); do
    code=$(curl -s -o /dev/null -w '%{http_code}' "${c#*:}/eth/v1/beacon/headers/$s")
    [ "$code" = 200 ] && n=$((n + 1))
  done
  echo "${c%%:*} API blocks 0..$to: $n"
done

# The exported genesis state is the generator's genesis.ssz, byte for byte.
cmp "$genesis/genesis.ssz" "$export_root/lighthouse/$enclave/genesis_state.ssz" && echo "genesis state ok"
```

Keep the export with the run log: its `export_sha256` pins it, and the block replay harness loads
it with `open_export_pinned` and that digest.

## How the probe attaches

- **Preset and config.** The chain is minimal preset, so the probe runs with the `Minimal` spec
  (`cl-p2p` is generic over `EthSpec`) and the devnet's own `config.yaml` from
  `kurtosis files download ethswarm-gloas el_cl_genesis_data`. A mainnet-preset build cannot
  decode this chain's blocks.
- **Bootnode ENRs.** Each CL's ENR is
  `curl -s "$(kurtosis port print ethswarm-gloas <service> http)/eth/v1/node/identity" | jq -r .data.enr`.
  Its `eth2` entry carries the fork digest the probe must match. The package starts
  `cl-1-lighthouse-geth` first and makes it the other CLs' bootnode.
- **Static peers.** The same answer's `.data.p2p_addresses` and `.data.peer_id` give
  `/ip4/<ip>/tcp/9000/p2p/<peer_id>`. The supernode (`cl-1-lighthouse-geth`) serves every
  column.
- **Network.** The package sets each CL's ENR address to its container IP on the enclave's
  Docker network (`port_publisher` is off), so discovery must run on that network. Find it with
  `docker network ls --filter name=ethswarm-gloas` (Kurtosis names it `kt-ethswarm-gloas`), then
  run the probe as `docker run --network kt-ethswarm-gloas ...`. On Docker Desktop (macOS) a
  process on the host cannot reach those IPs. The libp2p TCP port is also published on a host
  port (`kurtosis port print <enclave> <service> tcp-discovery`), which a process on the host
  can dial: see "Probe checks".

## Probe checks

`devnet-probe` (the `devnet-probe` crate: `crates/devnet-probe/src/main.rs`, the checks in
`crates/devnet-probe/src/`) runs our probe against the reference CLs and prints one
`PASS`/`FAIL` line per thing it judged, a summary line per check and a last
`verdict: PASS|FAIL|DIAGNOSTIC (...)` line. It exits 0 only for an acceptance pass, every check
passed; 1 a failure; 2 usage, which includes an `--api` whose node (`/eth/v1/node/identity`
`peer_id`) is not among the `--peer`s of `connect`, `status`, `fetch-epoch` or `all`, so no
reference CL can be left out; 3 diagnostic: every check passed but one ran outside the
acceptance rules (a `--hold-secs` under 600), which prints `DIAGNOSTIC`, never `PASS`, and is
no acceptance evidence. A recorded deviation (see "Recorded deviations" below) is still an
acceptance pass and exits 0, but each check's summary line and the verdict name it, e.g.
`connect: PASS (2/2; 1 recorded deviation: mplex)` and
`verdict: PASS (2/2 checks; 1 recorded deviation: connect mplex)`, so a run with one never reads
like a run without. Every `-secs` flag takes 1 to 86400.
A `setup` check runs first: the devnet's `config.yaml` parses with `network-config`'s strict
reader, and the genesis of `genesis.ssz` (its first two fields) equals every `--api`'s
`/eth/v1/beacon/genesis`, with the config's `GENESIS_FORK_VERSION`. Every address it is given
must be local (loopback, private, link-local, CGNAT, IPv6 unique-local), and it never starts or
stops anything in Kurtosis or Docker.

| Subcommand | Criterion | What passes |
|---|---|---|
| `discover` | discovery on the devnet | our discv5 (cl-discv5, local mode: a record with any other than a local address is never queried or pinged, so nothing goes to a public host), seeded with `--bootnode`, finds every `--enr` record (and every `--api`'s `/eth/v1/node/identity` ENR) on our fork digest within `--discover-secs` (60) |
| `connect` | TCP + Noise + yamux | each `--peer`: TCP connected, Noise XX proved its peer ID, and the muxer, logged per peer, is `/yamux/1.0.0`; `/mplex/6.7.0` passes as a recorded deviation, labelled `muxer=/mplex/6.7.0 (peer offers no yamux: recorded deviation)` and named `connect mplex` in the summary and the verdict, only for a peer that refused our yamux proposal (our dial proposes yamux first, then mplex, and a peer that speaks yamux accepts it) and then answered our identify over mplex within `--connect-secs` (our dial settles on its last proposal, mplex, without waiting for the peer's answer, so only a round trip shows the peer accepted it); mplex without yamux proposed first, mplex with no identify answer, or another muxer, fails |
| `status` | Status v2 both ways, then a held connection | each `--peer` answers our Status v2 with a relevant one, sends us its own Status (a CL's periodic re-Status, about every 5 minutes on Lighthouse and Lodestar \[est\]: the hold must outlast it) and our answer to it is sent, and keeps the connection `--hold-secs` (600; under 600 the check is `DIAGNOSTIC` and the run exits 3) with our Ping every `--ping-secs` (15) and no Goodbye either way; a Goodbye is reported with its reason |
| `fetch-epoch` | one epoch by range, roots against the API | the finalized epoch before the first `--api`'s finalized epoch (or `--epoch`) fetched by BlocksByRange v2 from the `--peer`s; every slot's root equals that API's `/eth/v1/beacon/blocks/{slot}/root`, an empty slot is a 404 there, and nothing is `unconfirmed` |
| `all` | the four | in that order, from one argument set |

Our Status is probe mode's (`cl_chain::probe::StatusProvider`): the digest of the wall-clock
epoch from `config.yaml` and `genesis.ssz`, the finalized checkpoint and its block from the
first `--api`. The swarm is cl-p2p's `build_swarm` over the `Minimal` preset (the config's
`PRESET_BASE`); `status` and `fetch-epoch` add the probe's ignore-all gossipsub on
`beacon_block` at our fork digest, publishing nothing: a CL drops a peer that does not speak
gossipsub (Lighthouse says Goodbye right after Status). `connect` judges a yamux connection
once it is established and an mplex one once the peer's identify answer came over it, so its
swarm carries none.

### Recorded deviations

The criterion for `connect` is yamux with every reference CL. One pinned reference CL cannot
meet it, and is formally excepted:

| Reference CL | Deviation | Why | What passes instead |
|---|---|---|---|
| Lodestar 1.50.0 (`unstable-b3beff2`) | `connect mplex` | it builds its libp2p node with mplex as its only stream muxer, so it refuses yamux | `/mplex/6.7.0`, after it refused our yamux proposal and answered our identify over mplex (the spec's TCP clients MUST support mplex and MAY support yamux) |

A run with this exception passes with exit 0, and its verdict reads
`verdict: PASS (<n>/<n> checks; 1 recorded deviation: connect mplex)`. A Lodestar pin that
negotiates yamux drops the deviation from the verdict; drop its row here with that pin change.

Run it against the concurrent pair that `testing/kurtosis/run-pair.sh --keep-on-pass` leaves
up after a pair PASS (both enclaves, finalized epoch at least 3); check that script's own exit
code is 0 before going on:

```bash
bash testing/kurtosis/run-pair.sh --keep-on-pass; echo "run-pair exit $?"   # 0: the pair is up
```

Everything below uses the pair's first enclave, `ethswarm-gloas-a-<T>-<pid>` as `run-pair.sh`
printed it (`launching ...`), and runs from the repo root.

The inputs, from Kurtosis and each CL's beacon API:

```bash
enclave=ethswarm-gloas-a-<T>-<pid>                  # the name run-pair.sh printed
net=target/kurtosis/$enclave-genesis
logs=target/kurtosis/probe-$enclave; mkdir -p "$logs"
kurtosis files download "$enclave" el_cl_genesis_data "$net"   # config.yaml, genesis.ssz

apis=() peers=() enrs=()
for svc in cl-1-lighthouse-geth cl-2-lodestar-geth; do
  api=$(kurtosis port print "$enclave" "$svc" http)              # http://127.0.0.1:<port>
  identity=$(curl -s "$api/eth/v1/node/identity")
  id=$(jq -r .data.peer_id <<<"$identity")
  enr=$(jq -r .data.enr <<<"$identity")
  tcp=$(kurtosis port print "$enclave" "$svc" tcp-discovery)    # the libp2p TCP port, on the host
  tcp=${tcp##*:}
  echo "$svc: peer $id, host TCP $tcp, enr $enr" | tee -a "$logs/inputs.log"
  apis+=(--api "$api"); peers+=(--peer "/ip4/127.0.0.1/tcp/$tcp/p2p/$id"); enrs+=(--enr "$enr")
done
# The package boots every CL from cl-1-lighthouse-geth: our discv5 starts from its record only.
boot=$(curl -s "$(kurtosis port print "$enclave" cl-1-lighthouse-geth http)/eth/v1/node/identity" \
  | jq -r .data.enr)
```

`kurtosis enclave inspect "$enclave"` lists each service's port IDs if `tcp-discovery` is named
differently. The first `--api` (Lighthouse's) is the reference for our Status and the roots.

`connect`, `status` and `fetch-epoch` from the host, through each CL's published TCP port
(`status` holds for 10 minutes):

```bash
cargo build --release --locked -p devnet-probe    # or: cargo run --release --locked -p devnet-probe -- <subcommand> ...
probe=target/release/devnet-probe
"$probe" connect --network-dir "$net" "${apis[@]}" "${peers[@]}" 2>"$logs/connect.err" \
  | tee "$logs/connect.log"; echo "connect exit ${PIPESTATUS[0]}"
"$probe" status --network-dir "$net" "${apis[@]}" "${peers[@]}" 2>"$logs/status.err" \
  | tee "$logs/status.log"; echo "status exit ${PIPESTATUS[0]}"
"$probe" fetch-epoch --network-dir "$net" "${apis[@]}" "${peers[@]}" 2>"$logs/fetch.err" \
  | tee "$logs/fetch-epoch.log"; echo "fetch-epoch exit ${PIPESTATUS[0]}"
```

The stderr logs keep cl-p2p's `negotiated a stream muxer` line for each connection, every
`goodbye_received` / `goodbye_sent` event, and the Status verdicts.

The Kurtosis report for exit 10 (b), zero reason-3 Goodbyes from each reference CL, reads the
`status` log (its hold covers 600 s, 12.5 minimal-preset epochs):

```bash
bash testing/kurtosis/check-devnet.sh --probe-log "$logs/status.err" "$enclave" \
  | tee "$logs/goodbye3.log"; echo "check-devnet exit ${PIPESTATUS[0]}"
```

It prints each CL's image and its `goodbye3` count, `goodbye3: PASS` and
`verdict: PASS (4/4 criteria)` (exit 0) when no CL sent one.

`discover` from a container on the enclave's Docker network, since the CLs' records carry
their container IPs (on a Linux host, which routes to those IPs, the host binary works too).
It needs a Linux build of the probe; this one keeps its build in `target/linux` and its crates
in a Docker volume:

```bash
docker run --rm -v "$PWD":/src -w /src -v ethswarm-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/src/target/linux rust:1.99-bookworm bash -c \
  'apt-get update -qq && apt-get install -y -qq protobuf-compiler clang libclang-dev >/dev/null &&
   cargo build --release --locked -p devnet-probe'
docker run --rm --network "kt-$enclave" \
  -v "$PWD/target/linux/release/devnet-probe:/devnet-probe:ro" -v "$PWD/$net:/net:ro" \
  debian:bookworm-slim /devnet-probe discover --network-dir /net --bootnode "$boot" "${enrs[@]}" \
  2>"$logs/discover.err" | tee "$logs/discover.log"; echo "discover exit ${PIPESTATUS[0]}"
```

On a Linux host the four run as one, with the CLs' container addresses as peers
(`.data.p2p_addresses` of the identity) or the published ports above:

```bash
"$probe" all --network-dir "$net" "${apis[@]}" "${peers[@]}" --bootnode "$boot" "${enrs[@]}" \
  2>"$logs/all.err" | tee "$logs/all.log"; echo "all exit ${PIPESTATUS[0]}"
```

Each log's last line is its verdict; keep the logs with the pair's run log. Then tear the
pair down (the commands `run-pair.sh --keep-on-pass` printed, or `kurtosis enclave rm -f` on
both enclaves).

## Changing a pin

1. Pick the new tag and confirm its spec version at the source commit (Lighthouse
   `testing/ef_tests/Makefile`, Lodestar `packages/beacon-node/test/spec-tests-version.json`).
2. `docker buildx imagetools inspect <repo:tag>`, and take the top-level `Digest:` (the index).
3. Update the image in `gloas-genesis.yaml` and its row in the table above, with the date.
4. `bash scripts/check-kurtosis-pins.sh`, then a run pair, then refill the expected genesis root.

A package bump changes the SHA in every command here. Re-read the two buildoor YAMLs and the
package's default genesis generator at the new commit.
