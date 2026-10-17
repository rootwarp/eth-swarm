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
PRESETS="minimal" testing/fetch-vectors.sh    # → target/spec-vectors, sha256-verified, cached by stamp
cargo test -p spec-tests --release --test vectors
# filter by trial name:
cargo test -p spec-tests --release --test vectors -- gloas_ssz_static_minimal::BeaconState
cargo test -p spec-tests --release --test vectors -- ssz_generic::test_basic_types
```

- Trial names are `ssz_generic::<handler>::<case>` and `<fork>_<runner>_<preset>::<Type>::<suite>::<case>`.
- `SPEC_VECTORS_DIR` overrides `target/spec-vectors`.
- The ssz-specs vectors and the `minimal` preset are required. `mainnet` runs only if it has been extracted.

Policy and contract gates (CI runs these):

```bash
cargo deny check
bash scripts/check-ssz-revs.sh                # SSZ git deps must match the pinned revs exactly
(cd proto && buf lint && buf build)
scripts/buf-breaking.sh                       # vs git `main` if it exists, else proto/.baseline/v1.binpb
```

`scripts/check-ssz-revs.sh` (`declare -A`) and `testing/fetch-vectors.sh` (`mapfile`) need **bash ≥ 4**. On macOS `/bin/bash` is 3.2, and `check-ssz-revs.sh` fails there with "unbound variable", so run both with a Homebrew bash. `fetch-vectors.sh` also needs python3 ≥ 3.11 (`tomllib`) and `sha256sum`.

`bench/verify-ipc` is a **standalone workspace** (it has an empty `[workspace]` and is not a root member), and tonic-build needs `protoc`. It benchmarks BLS batch verification over UDS, comparing gRPC with raw framing. `cargo run --release --manifest-path bench/verify-ipc/Cargo.toml` runs the bench and starts its own `server` child. Its proto (`ethswarm.benchverify.v1`) is local to the bench and is not the real `proto/ethswarm/verify/v1` contract.

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

Flow: `discover` cases (`ssz_generic.rs` for ssz-specs JSON fixtures, `ssz_static.rs` for consensus-spec-tests `ssz_static`) → `plan::plan` against `testing/skip.toml` → one libtest trial per case (`tests/vectors.rs`). Each check is decode, re-encode to identical bytes, and compare `hash_tree_root` (`check::round_trip`).

The skip list is strict, and the run **fails** in any of these cases:
- a case is neither runnable nor skipped ("unaccounted")
- a skip entry is past its `expires` date (current entries expire 2026-11-30)
- a skip entry matches no discovered case (stale)

A skip entry wins over a handler. When you add a type, also delete its skip entry, or the type never runs.

To make an ssz_static handler runnable:
1. Add the container to `src/gloas/containers.rs`. That file is `include!`d twice by `src/gloas/types.rs`, once per preset, with that preset's typenum aliases in scope. A new preset-dependent length needs an alias in **both** modules.
2. Add the type name to the `table!` list in `ssz_static.rs`.

ssz-specs types go into the `(handler, type_name)` table in `ssz_generic.rs`, keyed by both because filler modules reuse type names with different definitions. These Gloas shapes are test-only transcriptions from the spec, not production types.

### cl-verify pubkey cache (`crates/cl-verify-cache`)

The cache holds only the **finalized** validator-registry prefix `0..high_water()`. Before finality, competing branches can give the same new index different keys. An index at or past the high-water mark must carry its pubkey inline, and if it doesn't the lookup is `Unknown`, which maps to IGNORE or retry, never ACCEPT. `append`/`append_range` reject gaps, overlaps and key changes.

`persist.rs` writes the on-disk snapshot: `MAGIC | VERSION | len | sha256(keys) | keys`. Any header, length or root mismatch at startup means rebuild, never trust. `proto/ethswarm/verify/v1/verify.proto` documents the same invariant on the wire.

### Dependency policy (`deny.toml`, root `Cargo.toml`)

- The sigp SSZ crates (`ethereum_ssz`, `ssz_types`, `tree_hash`, `milhouse`) are pinned through `[patch.crates-io]` to the exact revisions Lighthouse `unstable` uses. Progressive SSZ types (EIP-7916 and related) exist only at those revs. A rev bump has to update three places together: root `Cargo.toml`, the `deny.toml` `[sources]` comment, and the `REV` table in `scripts/check-ssz-revs.sh`.
- Git deps are allowed only from those four sigp repos. `Cargo.lock` must be committed.
- `openssl`/`openssl-sys` are banned, so use rustls. Only permissive licenses are allowed. Every advisory `ignore` needs an ID, a reason, an owner and a review date.
