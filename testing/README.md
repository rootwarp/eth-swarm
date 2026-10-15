# testing/

| File | Purpose |
|---|---|
| `vectors.manifest.example.toml` | Pinned vector archives: an exact tag plus sha256 for each asset. Copy it to `vectors.manifest.toml` for the runner |
| `skip.toml.example` | Skip-list template. The runner fails on a handler that is neither run nor skipped, on an expired entry, and on an entry that matches nothing |
| `fetch-vectors.sh` | Downloads by exact tag, verifies sha256 (non-zero exit on mismatch), and extracts to `target/spec-vectors/<source>/<tag>/<asset>/` |

The sha256 values were verified on 2026-10-15 by download plus `sha256sum`. They matched GitHub's asset digests, and for ssz-specs they also matched the upstream `.sha256` file.

Notes:
- `general.tar.gz` at v1.7.0-beta.4 is only 3 KB and holds only `altair/bls/eth_*` cases.
- SSZ generic vectors come from ssz-specs instead.
- consensus-specs mainnet plus minimal is about 1.4 GB, so cache them in CI.

## Local
```bash
PRESETS="general minimal" testing/fetch-vectors.sh            # skip mainnet
INCLUDE_OPTIONAL=1 testing/fetch-vectors.sh                    # everything incl. comptests
```

## CI step (GitHub Actions)
```yaml
- name: Cache spec vectors
  uses: actions/cache@v4
  with:
    path: target/spec-vectors
    key: spec-vectors-${{ hashFiles('testing/vectors.manifest*.toml') }}
- name: Fetch and verify spec vectors
  run: PRESETS="general minimal" testing/fetch-vectors.sh testing/vectors.manifest.example.toml target/spec-vectors
- name: Spec-vector tests
  run: cargo nextest run -p spec-tests   # crate name per Ian's crate
```
A pre-merge or nightly job should drop `PRESETS` so mainnet is included.
