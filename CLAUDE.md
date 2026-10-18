# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ETH Swarm is an Ethereum consensus-layer (beacon node) client in Rust. It is split into separate services (cl-chain, cl-store, cl-engine, cl-verify, cl-p2p, cl-discv5, cl-sync, cl-api) that talk gRPC over tonic/prost. Scope is **Fulu and Gloas only**. Spec pins: consensus-specs **v1.7.0-beta.4**, and ethereum/ssz-specs **v0.1.0** for SSZ (the SSZ spec was removed from consensus-specs).

The repo is an architecture baseline so far: protobuf contracts, a spec-vector test runner, dependency policy, and the cl-verify pubkey cache. `crates/cl-chain-columns` is a placeholder stub.

The design docs live in an external vault. `arch/*.md`, `onboarding/*.md`, `DECISIONS.md` and the top-level `cl-*.md` files are one-line "Moved to vault" pointers with nothing else in them. The normative docs inside the repo are `proto/README.md` and `testing/README.md`.

## Commands

The toolchain is pinned to 1.99.0 (`rust-toolchain.toml`). The workspace MSRV is 1.88.

```bash
cargo build --workspace
cargo clippy --workspace --all-targets
cargo fmt --all
cargo test -p cl-verify-cache                 # unit + proptest
cargo test -p spec-tests --lib                # runner unit tests (no vectors needed)
```

Spec vectors: download them first, then run the `vectors` test target (libtest-mimic, `harness = false`):

```bash
PRESETS="general minimal" testing/fetch-vectors.sh   # → target/spec-vectors; tag→commit and sha256 pinned, fails closed
INCLUDE_OPTIONAL=1 testing/fetch-vectors.sh           # everything: mainnet, cryptography-specs, bls12-381-tests, comptests
cargo test -p spec-tests --release --test vectors
SPEC_SETS="ssz-specs general minimal" cargo test -p spec-tests --release --test vectors   # what PR CI runs
# filter by trial name (a filtered run turns the coverage guard off):
cargo test -p spec-tests --release --test vectors -- gloas_ssz_static_minimal::BeaconState
cargo test -p spec-tests --release --test vectors -- ssz_generic::test_basic_types
```

- Trial names are `ssz_generic::<handler>::<case>`, `<fork>_<runner>_<preset>::<handler>::<case>` (consensus-spec-tests), `cryptography_specs_<runner>::<handler>::<case>`, `bls12_381::<handler>::<case>`, and `comptests_<fork>_<runner>_<preset>::…`.
- `SPEC_SETS` (space or comma separated: `ssz-specs`, `general`, `minimal`, `mainnet`, `cryptography-specs`, `bls12-381-tests`, `comptests`) picks the sets and makes each one required. Unset, ssz-specs and `minimal` are required and the others run only if extracted.
- `SPEC_VECTORS_DIR` overrides `target/spec-vectors`.

Policy and contract gates (CI runs these):

```bash
cargo deny check
bash scripts/check-ssz-revs.sh                # SSZ git deps must match the pinned revs exactly
bash scripts/check-libp2p-revs.sh             # one rust-libp2p SHA, containing the gossipsub fix (needs network)
bash scripts/check-deny-negative.sh           # cargo deny must fail on a 2nd libp2p-swarm / foreign git dep
(cd proto && buf lint && buf build)
scripts/buf-breaking.sh refs/remotes/origin/develop   # default: refs/heads/develop, else the remote ref; --baseline
bash scripts/check-workflows.sh               # runs crates/ci-checks: parses workflows as YAML, enforces hardening
cargo test -p ci-checks                       # workflow rules + offline tests of the CI shell scripts
```

`scripts/check-ssz-revs.sh` (`declare -A`) needs **bash ≥ 4**. On macOS `/bin/bash` is 3.2, and `check-ssz-revs.sh` fails there with "unbound variable", so run it with a Homebrew bash. `fetch-vectors.sh` needs python3 ≥ 3.11 (`tomllib`), `git`, `curl`, `sha256sum` and, for `.zip` assets, `unzip`. The script tests run `bash` from `PATH`.

`bench/verify-ipc` is a **standalone workspace** (it has an empty `[workspace]` and is not a root member), and tonic-prost-build needs `protoc`. It benchmarks BLS batch verification over UDS, comparing gRPC with raw framing. `cargo run --release --manifest-path bench/verify-ipc/Cargo.toml` runs the bench and starts its own `server` child. Its proto (`ethswarm.benchverify.v1`) is local to the bench and is not the real `proto/ethswarm/verify/v1` contract.

`fuzz/` is a second **standalone workspace** with its own committed `fuzz/Cargo.lock` (nightly pinned in `fuzz/rust-toolchain.toml`): the cargo-fuzz targets for the req/resp, gossip and ENR decoders. The m2a gate (the session's four response decoders) is `fuzz/run-m2a-gate.sh` (writes the gate file) and `fuzz/check-m2a-gate.sh` (verifies it); gate 1 (the probe's control, gossip and ENR decoders, seven targets, run nightly) is the same pair with `--gate gate1`, as `fuzz/run-gate1.sh` and `fuzz/check-gate1.sh`. Regenerate `fuzz/Cargo.lock` with `fuzz/regen-lock.sh` (from the root lock) whenever a fuzzed crate's dependencies change; `scripts/check-fuzz-lock.sh` enforces this.

## Architecture

### Service contracts (`proto/`)

Each proto package belongs to the service that **serves** it. `proto/README.md` is normative, so read it before you touch any `.proto`. The ownership model:

- **cl-chain** is the single writer for state transition, fork choice, DA status and ePBS. It serves gossip validation, req/resp, import, query (duties, produce, submit) and sequenced events.
- **cl-store** opens MDBX read-only and has no write RPC. It follows chain's head/finalized events, so head reads can be **one write behind**. Every response carries a `ReadMeta` stamp `(as_of_seq, as_of_root, as_of_slot)`.
- **cl-engine** is the only holder of the JWT secret, and only cl-chain calls it. Chain owns optimistic status and fcU ordering.
- **cl-verify** is called only by cl-chain. It runs BLS (blst) and KZG checks and is stateless apart from the append-only pubkey cache.

Wire rules that cut across every package (full list in `proto/README.md`):
- An `*_UNSPECIFIED` (0) value of **any** enum is `ERROR_CODE_CONTRACT_VIOLATION`. An unknown non-zero value is IGNOREd and never decoded.
- Timeout, overload or an unavailable core means **IGNORE, never ACCEPT**. REJECT is reserved for a proven spec violation.
- Decode SSZ by the fork of the **object's slot**, never the current fork. A fork-digest mismatch means drop without decoding, and from Fulu the digest also changes at BPO epochs.
- Every streamed message is `oneof frame { Hello hello = 1; <Msg>Body body = 2; }`. Each direction sends exactly one `hello`, first. `Envelope.seq` increases strictly from 1. Unary calls carry no Hello.
- Every `bytes` field documents its max size in a comment (`TODO(vera)` if there is no spec limit yet).
- Changes are additive only. Removed fields go into `reserved` (number and name), and field numbers are never reused. A breaking change means a new `v2` package served alongside `v1` (N and N-1 compatibility).
- Re-baselining (`buf build -o .baseline/v1.binpb` from `proto/`) is allowed pre-v1 only. It goes in its own commit that touches only the baseline plus one line in the README's re-baseline log.

### Spec-vector runner (`crates/spec-tests`)

Flow: `suite.rs` walks every extracted set → `plan::plan` against `testing/skip.toml` → one libtest trial per case (`tests/vectors.rs`) → the coverage guard. Runners: `ssz_generic.rs` (ssz-specs JSON fixtures), `ssz_static.rs` (decode, re-encode to identical bytes, compare `hash_tree_root`; `check::round_trip`), `kzg.rs` (cell handlers through `crypto-kzg`, setup via `TrustedSetup::load_pinned`) and `bls.rs` (every handler except the skipped `hash_to_G2`, through `crypto-bls`; `sign`/`aggregate`/`aggregate_verify` via its `test-vectors` feature). A required set with no files, or without its runnable subtrees, fails setup, and setup errors exit non-zero even under a name filter. An unknown handler dir under `bls/` or `kzg/` fails the run, and no skip entry can rescue it.

Coverage guard (`coverage.rs`): runners read vector files only through `coverage::Reads`. After an unfiltered run, a file under a scanned root that no runner read fails the run and is listed, unless its case is skipped or a skip entry with a `file` field excuses it (the case still runs).

The skip list is strict, and the run **fails** in any of these cases:
- a case is neither runnable nor skipped ("unaccounted")
- a skip entry is past its `expires` date (current entries expire 2026-11-30)
- a skip entry matches no discovered case (stale). This is only checked for sets that were scanned, so a minimal-only run doesn't flag mainnet or crypto entries.

Every entry needs `reason`, `owner` and `expires`. `source` and `preset` must be known values. A skip entry wins over a handler. When you add a type, also delete its skip entry, or the type never runs.

To make an ssz_static handler runnable:
1. Add the container to `crates/consensus-types/src/{fulu,gloas}/mod.rs` (`common/` if both forks share it). A new preset-dependent length goes on `EthSpec` in `preset.rs`, for both `Minimal` and `Mainnet`.
2. Add the type name to the `fork_table!` / `with_common!` lists in `ssz_static.rs`.

ssz-specs types go into the `(handler, type_name)` table in `ssz_generic.rs`, keyed by both because filler modules reuse type names with different definitions. The ssz_static types are the production containers from `consensus-types`; the ssz-specs sample types in `ssz_generic.rs` stay test-only.

### cl-verify pubkey cache (`crates/cl-verify-cache`)

The cache holds only the **finalized** validator-registry prefix `0..high_water()`. Before finality, competing branches can give the same new index different keys. An index at or past the high-water mark must carry its pubkey inline, and if it doesn't the lookup is `Unknown`, which maps to IGNORE or retry, never ACCEPT. `append`/`append_range` reject gaps, overlaps and key changes.

`persist.rs` writes the on-disk snapshot `pubkeys.bin` (version 2): `MAGIC | VERSION | len | registry sha256 | body sha256 | len × 96-byte uncompressed points`. The registry sha256 is over the 48-byte compressed keys, the digest cl-chain announces for its finalized registry. Keys are `KeyValidate`d once on entry, so a reload decodes the points unchecked through a caller-supplied `KeyCodec` (the crate has no blst). It is written atomically (tmp, fsync, rename, dir fsync) with mode 0600. A file that is not a regular file with mode 0600 owned by the process's euid, or has any header, length, registry or body digest mismatch, means a full rebuild from index 0, never trust and never partial use. The version-1 `save`/`load`/`startup` remain for source compatibility only. cl-verify (`crates/cl-verify/src/feed.rs`) restores on the first PubkeyFeed frame, which announces cl-chain's finalized registry (`FinalizedRegistry`): it loads the snapshot on an exact match, else rebuilds from index 0 over the stream, and VerifyBls sees an empty cache until then. After that, a rebuild or feed append marks the snapshot dirty; it is saved at most once per `ServerConfig::snapshot_interval` (default 384 s) and flushed by `serve_uds` at shutdown (`VerifyServer::flush_snapshot`). The owner tests need root and run in the `root-tests` CI job (`ETHSWARM_ROOT_TESTS=1`); locally they skip. `proto/ethswarm/verify/v1/verify.proto` documents the same invariant on the wire.

### Dependency policy (`deny.toml`, root `Cargo.toml`)

- The sigp SSZ crates (`ethereum_ssz`, `ssz_types`, `tree_hash`, `milhouse`) are pinned through `[patch.crates-io]` to the exact revisions Lighthouse `unstable` uses. Progressive SSZ types (EIP-7916 and related) exist only at those revs. A rev bump has to update three places together: root `Cargo.toml`, the `deny.toml` `[sources]` comment, and the `REV` table in `scripts/check-ssz-revs.sh`.
- Every `libp2p*` crate (plus `multistream-select`, `rw-stream-sink`, `prost-codec`) comes from one full commit SHA of `libp2p/rust-libp2p` through `[patch.crates-io]`, one entry per `libp2p-*` crate in the graph. The SHA must descend from the gossipsub StrictNoSign `key` rejection (PR 6621, `ba75f82`), which no crates.io gossipsub has yet. `scripts/check-libp2p-revs.sh` fails on a second SHA, a `libp2p*` crate from anywhere else or twice in `Cargo.lock`, a manifest rev that differs, a `libp2p*` deny `skip` entry, or a SHA without that fix (it fetches the commit graph). A bump changes every patch line and the `deny.toml` `[sources]` comment together.
- Git deps are allowed only from rust-libp2p and those four sigp repos. `Cargo.lock` must be committed.
- `multiple-versions = "deny"` with `multiple-versions-include-dev = true`: a new duplicate, dev-only included, fails `cargo deny`. Excuse an unavoidable non-libp2p one in `[bans] skip` with its exact version and a reason, never a `libp2p*` crate. `scripts/check-deny-negative.sh` proves the gate: on a throwaway copy, a second `libp2p-swarm` (normal or dev-only) and a git dep outside `allow-git` must each fail `cargo deny check` with that `error[...]` diagnostic (read from `--format json`), not a warning or an unrelated failure.
- `openssl`/`openssl-sys` are banned, so use rustls. Only permissive licenses are allowed. Every advisory `ignore` needs an ID, a reason, an owner and a review date.
