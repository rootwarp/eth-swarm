# spec-tests

This crate runs the SSZ test vectors as one libtest trial per case.

```bash
PRESETS="minimal" testing/fetch-vectors.sh   # verified by sha256 into target/spec-vectors
cargo test -p spec-tests --release
```

- **Set 1:** the ethereum/ssz-specs v0.1.0 fixtures under `fixtures/ssz/ssz/*`. The sample types are transcribed from ssz-specs `tests/fillers/ssz/*.py`.
- **Set 2:** consensus-spec-tests v1.7.0-beta.4 `minimal/gloas/ssz_static`. Each case is decoded, re-encoded, and checked against its `hash_tree_root`. It uses the local Gloas shapes in `src/gloas/types.rs`.
- **Skips:** listed in `testing/skip.toml`. The run fails on a case that is neither run nor skipped, on an expired entry, and on a stale entry.
- **SSZ crates:** pinned through `[patch.crates-io]` in the root `Cargo.toml` to the same revisions as Lighthouse `unstable`.
