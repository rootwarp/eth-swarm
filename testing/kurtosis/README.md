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

Status: the config, its image pin lint, the runtime checker and the block export are in the
repo; nothing has been run yet, because Kurtosis is not installed on the dev host. The three
runtime criteria below stay open until the first two runs.

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
different genesis roots (see below).

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
package accepts a fixed `genesis_time`, but a fixed value in the committed file would soon lie
far in the past. Instead, both runs of a pair use one rendered copy with the same `genesis_time`:

```bash
T=$(( $(date +%s) + 600 ))                  # genesis 10 minutes from now, shared by both runs
args="$PWD/target/kurtosis/gloas-genesis-$T.yaml"; mkdir -p "${args%/*}"
sed "s/^  genesis_time: 0$/  genesis_time: $T/" testing/kurtosis/gloas-genesis.yaml > "$args"
test "$(grep -c "^  genesis_time: $T$" "$args")" = 1 && echo "rendered $args"
bash scripts/check-kurtosis-pins.sh "${args%/*}"   # the rendered copy is pinned too
```

The second run starts after the first is torn down, so its genesis is already in the past. The
CLs start at the wall-clock slot and process the skipped slots. Keep the gap under about an hour:
the validators' inactivity scores grow during the empty epochs. If the gap is a problem, run both
enclaves at the same time instead (`ethswarm-gloas-a` and `ethswarm-gloas-b`, same `$args`).

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
criterion is `verdict: FAIL` (exit 1) either way. The criteria:

- `genesis`: every CL reports the same `genesis_time`, `genesis_validators_root`,
  `genesis_fork_version`, genesis block root and genesis state root. With `--reference`, they
  must also equal an earlier run's record (`--record` writes one).
- `fork_schedule`: on every CL, `GLOAS_FORK_EPOCH` is 0, `/eth/v1/config/fork_schedule` has the
  Gloas version at epoch 0 and in force there, every CL serves the same schedule, and the fork
  digests in the CLs' own ENRs (`eth2` entry) agree.
- `finality`: every CL's finalized epoch (`/eth/v1/beacon/states/head/finality_checkpoints`) is
  at least 3 (`--min-finalized-epoch`; below 3 the run is DIAGNOSTIC), on one finalized
  checkpoint (epoch and root). This is polled `--attempts` times (default 40), `--interval`
  seconds apart (default 12).

Two runs from a clean engine (criteria 1, 2 and 4 of the issue). Record the wall time and
`docker stats --no-stream` for CI sizing:

```bash
pkg=github.com/ethpandaops/ethereum-package@3416a0252e5bc25a0d31d24fea9c46707447eb08

# Run A
kurtosis clean -a
time kurtosis run --enclave ethswarm-gloas "$pkg" --args-file "$args"
bash testing/kurtosis/check-devnet.sh --record target/kurtosis/run-a.json ethswarm-gloas
docker stats --no-stream
kurtosis enclave rm -f ethswarm-gloas && kurtosis clean -a

# Run B: same args file, same genesis_time
time kurtosis run --enclave ethswarm-gloas "$pkg" --args-file "$args"
bash testing/kurtosis/check-devnet.sh --reference target/kurtosis/run-a.json ethswarm-gloas
docker stats --no-stream
kurtosis enclave rm -f ethswarm-gloas && kurtosis clean -a
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
```

## Export blocks and roots

`export-blocks` (`crates/testkit/src/bin/export-blocks.rs`) reads every slot from genesis to an
export slot from one CL's beacon API and writes `OUT/<devnet>/`: an archive segment of the
blocks (the same format and `manifest.toml` as the archiver), `genesis_state.ssz`, and
`export.toml`, which records the devnet name, the CL it came from, the genesis time, validators
root, block root and state root, the config's sha256, fork schedule and digests, the image
digests, the slot range with its empty slots, and every block's root and parent root. Replay
opens an export only through `testkit::export_blocks::open_export`, which verifies all of it
(each segment through `archive::open_verified`).

Per slot it fetches `/eth/v2/beacon/blocks/{slot}` as SSZ (404 is an empty slot, recorded),
decodes the block by the fork of its own slot, and fails the export unless our
`hash_tree_root` equals `/eth/v1/beacon/blocks/{slot}/root` and the block's parent is the
previous exported block (across empty slots). The genesis block must have a zero parent and the
root of `/eth/v2/debug/beacon/states/genesis` as its `state_root`. The export slot must be at or
before the CL's finalized block, so the roots cannot change under the export. A failed export
writes no `export.toml`, so its directory never opens as an export.

Status: tested against a fixture beacon node only. It has not been run on the devnet yet, so
the first run also confirms that `network-config` reads the generated `config.yaml`.

Run it on a devnet whose finalized epoch is at least 3 (`check-devnet.sh` passes), from the repo
root:

```bash
enclave=ethswarm-gloas
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

"$bin" export --api "$lh" --config "$genesis/config.yaml" --devnet "$enclave" \
  --source cl-1-lighthouse-geth --to "$to" --out "$export_root/lighthouse" "${image_args[@]}"
"$bin" export --api "$ls" --config "$genesis/config.yaml" --devnet "$enclave" \
  --source cl-2-lodestar-geth --to "$to" --out "$export_root/lodestar" "${image_args[@]}"
```

Each `export` prints one line: the slot range, the block and empty-slot counts, the genesis
block and state roots, the last block's slot and root, and the export's `export_sha256`.
`verify` prints the same line for an existing export (exit 1 if it is refused).

The checks, with the two exports above:

```bash
# Both CLs' exports have identical root lists (exit 1 and the first differing slot otherwise).
"$bin" diff "$export_root/lighthouse/$enclave" "$export_root/lodestar/$enclave"

# Count check: the API's block count over 0..=$to equals the export's "N blocks".
"$bin" verify "$export_root/lighthouse/$enclave"
n=0
for s in $(seq 0 "$to"); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$lh/eth/v1/beacon/headers/$s")
  [ "$code" = 200 ] && n=$((n + 1))
done
echo "API blocks 0..$to: $n"

# The exported genesis state is the generator's genesis.ssz, byte for byte.
cmp "$genesis/genesis.ssz" "$export_root/lighthouse/$enclave/genesis_state.ssz" && echo "genesis state ok"
```

Keep the export with the run log: its `export_sha256` pins it, and the block replay harness loads
it with `open_export`.

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
  Docker network (`port_publisher` is off), so the probe must run on that network. Find it with
  `docker network ls --filter name=ethswarm-gloas` (Kurtosis names it `kt-ethswarm-gloas`), then
  run the probe as `docker run --network kt-ethswarm-gloas ...`. On Docker Desktop (macOS) a
  process on the host cannot reach those IPs.

## Changing a pin

1. Pick the new tag and confirm its spec version at the source commit (Lighthouse
   `testing/ef_tests/Makefile`, Lodestar `packages/beacon-node/test/spec-tests-version.json`).
2. `docker buildx imagetools inspect <repo:tag>`, and take the top-level `Digest:` (the index).
3. Update the image in `gloas-genesis.yaml` and its row in the table above, with the date.
4. `bash scripts/check-kurtosis-pins.sh`, then a run pair, then refill the expected genesis root.

A package bump changes the SHA in every command here. Re-read the two buildoor YAMLs and the
package's default genesis generator at the new commit.
