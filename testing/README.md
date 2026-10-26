# testing/

| File | Purpose |
|---|---|
| `vectors.manifest.toml` | Pinned vector archives: per source an exact tag plus the commit it resolves to, per asset a sha256 |
| `vectors.manifest.example.toml` | Byte-identical copy of `vectors.manifest.toml` (a test keeps them in sync) |
| `skip.toml` | The skip list of the spec-vector runner and the exclusion list of its coverage guard (see "Skip list" below) |
| `skip.toml.example` | Skip-list template. The runner fails on a handler that is neither run nor skipped, on an expired entry, and on an entry that matches nothing |
| `fetch-vectors.sh` | Checks every tag -> commit pin, downloads, verifies sha256, then extracts to `target/spec-vectors/<source>/<tag>/<asset>/`. Fails closed |

The consensus-specs and ssz-specs sha256 values were verified on 2026-10-15 by download plus `sha256sum`. They matched GitHub's asset digests, and for ssz-specs they also matched the upstream `.sha256` file. The tag commits and the cryptography-specs and bls12-381-tests pins were verified the same way on 2026-10-17.

## Integrity rules (`fetch-vectors.sh`)
- **Tag pin.** Before any download, `git ls-remote` must resolve the tag of every source with a selected asset to its pinned `commit` (sources whose assets are all optional or filtered out by `PRESETS` are not contacted). Annotated tags are peeled via `^{}`, so the pin is the commit, not the tag object. A missing tag, an unreachable remote, or another commit prints `TAG UNRESOLVED` / `TAG MISMATCH` and exits 1.
- **Hash pin.** Each archive downloads to a private `mktemp` file, `.<file>.part.XXXXXX`, next to its final path, and is hashed before it is moved or unpacked. A mismatch prints `SHA256 MISMATCH`, deletes the partial file, and exits 1.
- **No retry, no fallback.** curl runs once without `--retry` (a failure prints `DOWNLOAD FAILED` and exits 1), the first failure stops the run before any later asset, and a missing manifest is an error rather than a fall back to another file. An invalid manifest (placeholder hash, short commit, non-version tag, path-like file name, unsupported archive type) exits 1 before anything is fetched.
- **Stamps are never trusted alone.** `.<file>.ok` is written only after a full extraction, and the verified archive is kept next to it. A later run skips the download only if that archive re-hashes to the pin, and it always re-extracts the tree from that archive, so edited or deleted fixtures never survive. A tampered archive is a `SHA256 MISMATCH` (exit 1, and the entry is deleted). A stamp without its archive, or with another hash, is discarded and the asset is fetched and verified again.
- **Concurrent runs.** Downloads go to `.<file>.part.XXXXXX` and extractions to `.<stem>.extracting.XXXXXX` (both `mktemp`). Each asset is guarded by a `.<file>.lock/` directory that records the owner's PID in `pid`, its `uname -n` in `host`, and its PID namespace (`readlink /proc/$$/ns/pid`, or `none` where there is no `/proc`) in `pidns`. A second run on the same asset fails with `LOCKED` and exit 1 while that PID is alive, or when the PID is missing or unreadable.
- **One kernel lock around every lock change.** Taking the lock, and reclaiming a stale one (`mkdir`, read the owner, check it, remove, `mkdir`, write the PID), all happen under an exclusive `flock(2)` on `.<file>.lockf`, taken through `python3`'s `fcntl.flock` because macOS has no `flock` command. The kernel drops it when the run exits, even on SIGKILL, so it can never go stale. Without it, two runs that read the same dead PID could both reclaim, one moving the other's live lock aside while a third run took the empty path. The `.lockf` files are empty and are never deleted, because deleting a file that another run may be waiting to lock would reopen that race. A run waits at most `FETCH_VECTORS_LOCK_WAIT` seconds for the kernel lock (default 60), then fails with `LOCKED` and exit 1.
- **Stale locks.** If the recorded PID is no longer running (checked with `kill -0`, then `ps -p`), for example after a run was killed with SIGKILL, the next run prints `taking over stale lock` and takes it. **A reclaim only happens on the same host and in the same PID namespace.** A PID means nothing elsewhere, so a destination shared between a container and the host, or over NFS, would otherwise see a live owner as dead. A lock whose `host` or `pidns` differs from the current run's, or is missing (an older lock), fails with `LOCKED`, is left untouched, and must be removed by hand once its run is gone. A lock dir left without a `pid` file (killed between `mkdir` and the PID write) also fails closed and must be removed by hand.
- **Tree swap.** The previous tree is moved to `<stem>.old.<pid>`, the new tree is moved into place, then the old copy is deleted. If the move fails, the old tree is restored and the run exits 1 with `EXTRACT FAILED`.
- Tests: `cargo test -p ci-checks --test fetch_vectors` (offline: local git remote, `file://` releases, a curl shim that counts attempts).

Notes:
- `general.tar.gz` at v1.7.0-beta.4 is only 3 KB and holds only `altair/bls/eth_*` cases.
- SSZ generic vectors come from ssz-specs instead.
- cryptography-specs `tests.zip` and bls12-381-tests feed the spec-tests `kzg` and `bls` runners. They stay `optional`, so the PR job (minimal) skips them; the nightly fetches and runs them.
- `comptests.tar.gz` (fork_choice_compliance vectors plus pyspec sources) has no runner. The nightly extracts it, and the coverage guard scans it under one `skip.toml` entry.
- consensus-specs mainnet plus minimal is about 1.4 GB compressed. CI does **not** cache them: every PR run and the nightly fetch and verify fresh.

## Skip list (`skip.toml`)
Every vector case is either run or matched by an entry. Each entry selects cases by `source`, `fork`, `preset`, `runner`, `handler` and an optional `case` glob (a `file` glob makes it a coverage excuse instead of a skip), and carries a `reason`, an `owner`, an `issue` (the plan item that removes it, or `none`) and an `expires` date. Checks, all in `crates/spec-tests/src/plan.rs`:
- **Schema.** A missing or blank `reason`, `owner`, `issue` or `expires`, an unknown field, a bad date, an unknown `source` or `preset`, or an entry that fits no vector set fails parsing, so `cargo test --workspace` fails in PR CI (`committed_skip_files_parse`, `skip_entry_requires_reason`).
- **Expiry.** An entry is valid through its `expires` day and fails every run from the next day (`skip_expired_fails`; the date is injected through `suite::Config::today`). `committed_skip_list_is_current` checks the committed entries against the real clock, so `cargo test` fails once one has expired.
- **Stale.** An entry that matches no file of a scanned set fails the run (`skip_entry_matches_files`). A case entry also needs its matching case to hold a file; this is a defensive guard, because the vector walk only creates a case for a file. The nightly scans all seven sets, so it checks every entry.

Groups (`tests/skip_list.rs` pins the `issue` of each): the column `ssz_static` types (`1.17`); the light-client `ssz_static` types; the `light_client`, `merkle_proof`, `genesis` and `sync` runners; Fulu `fork`, `transition` and processing runners (no Fulu state transition, `none`); Gloas `fork` (`upgrade_to_gloas` is not ported) and `transition` (needs Fulu processing), both `none` and tracked in GitHub issue 269; no entry may reach a Gloas case of `sanity`, `epoch_processing`, `operations`, `finality`, `rewards`, `random` or `shuffling`, or a phase0 `shuffling` case, or name a `4.x` item (`skip_toml_has_no_m3_entries`); `fork_choice`, `fast_confirmation` and `networking`; pre-Fulu forks (phase0 per runner, so that `shuffling/core` runs) and `heze`; the `value.yaml` excuse; the blob-level KZG handlers and `recover_cells_and_kzg_proofs` (`6.7`); `bls/hash_to_G2`; comptests.

On every manifest bump, run all seven sets guarded, delete each entry reported stale, and give each new unaccounted case or unread file an entry with a reason:
```bash
SPEC_SETS="ssz-specs general minimal mainnet comptests cryptography-specs bls12-381-tests" \
  cargo test -p spec-tests --release --locked --test vectors
```

## Local
```bash
PRESETS="general minimal" testing/fetch-vectors.sh            # skip mainnet
INCLUDE_OPTIONAL=1 testing/fetch-vectors.sh                    # everything incl. comptests
```
`VECTORS_GIT_BASE` and `VECTORS_RELEASE_BASE` (default `https://github.com`) point the tag check and the downloads at another host; the tests use them for local fixtures.

## CI (`.github/workflows/`)
- `ci.yml` (`pull_request`): workflow hardening (`scripts/check-workflows.sh`, which runs the YAML-parsing checker in `crates/ci-checks`), `buf lint`/`buf build`, `buf breaking` against `refs/remotes/origin/develop`, `cargo deny check`, `scripts/check-ssz-revs.sh`, fmt, build, clippy, and `cargo test --workspace` after `PRESETS="general minimal"` fetches the vectors.
- The `pull_request` secrets rule is coarse on purpose. On a raw line, any `secrets` word after a `${{` counts, to the end of the line, because the checker does not parse expressions and a closing `}}` can sit inside a quoted string. So `${{ github.sha }}  # no secrets here`, `${{ inputs.secrets }}` and `${{ github.workspace }}/secrets` are all rejected, and the error says so. A job or step `if:` is an expression even without `${{`, so any `secrets` word anywhere in one is rejected too. The trade-off is that a false positive (reword the line) is preferred to a missed secret.
- `nightly.yml` (`schedule` + `workflow_dispatch`): `INCLUDE_OPTIONAL=1` fetch of every manifest source and preset, the full vector suite in release mode, and the dependency policy.
- Neither restores anything from a cache.
