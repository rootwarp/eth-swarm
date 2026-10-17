# testing/

| File | Purpose |
|---|---|
| `vectors.manifest.toml` | Pinned vector archives: per source an exact tag plus the commit it resolves to, per asset a sha256 |
| `vectors.manifest.example.toml` | Byte-identical copy of `vectors.manifest.toml` (a test keeps them in sync) |
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
- cryptography-specs `tests.zip` and bls12-381-tests are `optional` until a runner uses them; the nightly fetches them.
- consensus-specs mainnet plus minimal is about 1.4 GB compressed. CI does **not** cache them: every PR run and the nightly fetch and verify fresh.

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
