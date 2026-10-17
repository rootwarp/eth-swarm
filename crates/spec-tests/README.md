# spec-tests

This crate runs the pinned test vectors as one libtest trial per case, then checks that every
vector file was read.

```bash
INCLUDE_OPTIONAL=1 PRESETS="general minimal" testing/fetch-vectors.sh   # sha256-verified into target/spec-vectors
cargo test -p spec-tests --release --test vectors
SPEC_SETS="ssz-specs minimal" cargo test -p spec-tests --release --test vectors
```

- **Sets** (`src/suite.rs`): ssz-specs v0.1.0, consensus-spec-tests v1.7.0-beta.4 `general`,
  `minimal`, `mainnet` and `comptests` (scanned by the guard, skipped: no runner yet),
  cryptography-specs v0.1.0 `tests.zip`, bls12-381-tests v0.1.2. Tags
  come from `testing/vectors.manifest.toml`. `SPEC_SETS` (space or comma separated) picks the
  sets, each then required; unset, ssz-specs and minimal are required and the others run when
  extracted. `SPEC_VECTORS_DIR` overrides `target/spec-vectors`.
- **Runners:** `ssz_generic` (ssz-specs fixtures, sample types transcribed from the fillers),
  `ssz_static` (Fulu and Gloas, types from `consensus-types`; decode, re-encode,
  `hash_tree_root`), `kzg` (cell handlers through `crypto-kzg` with `TrustedSetup::load_pinned`)
  and `bls` (every handler through `crypto-bls`, `sign`/`aggregate`/`aggregate_verify` via its
  `test-vectors` feature). consensus-spec-tests cases also have their `manifest.yaml` checked
  against the directory.
- **Handler directories:** `kzg.rs` and `bls.rs` list every handler they run and every one they
  know but do not run. Any other directory under `bls/` or `kzg/` fails the run, skip entry or
  not.
- **Skips:** `testing/skip.toml` (schema in `testing/skip.toml.example`). The run fails on a
  case that is neither run nor skipped, on an expired entry, and on a stale entry of a scanned
  set.
- **Coverage guard** (`src/coverage.rs`, after Lighthouse's `check_all_files_accessed.py`):
  handlers read vector files only through `coverage::Reads`. After an unfiltered run, any file
  under a scanned root that was not read fails the run and is listed, unless its case is
  skipped or a `file` entry excuses it. The roots are walked again at the end, and a file that
  was not there when the cases were planned fails the run too. Filtered runs (`-- <name>`,
  `--skip`, `--ignored`) turn the guard off.
- **Setup:** every scanned set must hold files, including its runnable subtrees (e.g.
  `tests/minimal/{fulu,gloas}/ssz_static`, cryptography-specs `tests/{bls,kzg}`). Setup and
  skip-list errors exit 101 before any trial runs, whatever the name filter.
- **`deserialization_G1` and KeyValidate:** the suite expects the compressed identity to
  decode; `PublicKey::from_validated_bytes` rejects it as a key (`PublicKeyIsInfinity`, reported
  only after a successful decode), so the runner counts that error as a decode. See `src/bls.rs`.
- **SSZ crates:** pinned through `[patch.crates-io]` in the root `Cargo.toml` to the same
  revisions as Lighthouse `unstable`.
