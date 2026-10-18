#!/usr/bin/env bash
# Fetch pinned test vectors, verify them, and extract them. Fails closed.
#
# Every selected source tag must resolve (annotated tags peeled via ^{}) to the pinned commit
# before anything is downloaded, and every archive must match its pinned sha256 before anything
# is unpacked. Any mismatch exits 1 at once: no retry, no fallback, no further assets.
# Sources whose assets are all skipped (optional, or filtered out by PRESETS) are not contacted.
#
# Usage: fetch-vectors.sh [MANIFEST] [DEST]
#   MANIFEST defaults to testing/vectors.manifest.toml and must exist (there is no fallback)
#   DEST     defaults to target/spec-vectors
# Env: INCLUDE_OPTIONAL=1          also fetch assets marked optional = true
#      PRESETS="minimal general"   restrict consensus-specs assets by file stem
#      VECTORS_GIT_BASE            git host for the tag checks      (default https://github.com)
#      VECTORS_RELEASE_BASE        host for the release downloads   (default https://github.com)
#      FETCH_VECTORS_LOCK_WAIT     seconds to wait for another run's lock check (default 60)
#      FETCH_VECTORS_TEST=1        test mode: honour FETCH_VECTORS_LOCK_HOOK (see lock_hook)
#
# Layout under DEST/<source>/<tag>/:
#   <file>        the verified archive, kept so later runs can re-hash it
#   <stem>/       the extracted tree (<file> without .tar.gz / .zip)
#   .<file>.ok    stamp holding the sha256; written only after a full extraction
#   .<file>.lock/ held while this run works on the asset; holds the owner's PID in `pid`,
#                 its `uname -n` in `host` and its PID namespace in `pidns` (`none` without
#                 /proc). A second run fails closed (LOCKED) while that PID is alive, and takes
#                 the lock over only once it is not (e.g. a run killed with SIGKILL), and only
#                 from the same host and namespace.
#   .<file>.lockf empty, kept; taking, reclaiming or releasing .<file>.lock/ happens under an
#                 flock(2) on it, so concurrent reclaims are serialized, only one run can own
#                 the asset, and no run sees a lock half-way through its release.
# A stamp is never trusted on its own: a later run reuses the kept archive only if it
# re-hashes to the pinned sha256, and then re-extracts the tree from it every time, so an
# edited or deleted fixture never survives. A stamp without its archive (for example one
# restored from a CI cache) is discarded and the asset is fetched and verified again.
# Downloads and extractions go to mktemp paths and are swapped in only once complete; the
# previous tree is moved aside first and restored if the new one cannot be moved into place.
# Exit codes: 0 ok, 1 integrity, manifest or download failure, 2 missing tool.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
manifest="${1:-$here/vectors.manifest.toml}"
dest="${2:-${DEST:-target/spec-vectors}}"
include_optional="${INCLUDE_OPTIONAL:-0}"
presets="${PRESETS:-}"
git_base="${VECTORS_GIT_BASE:-https://github.com}"
release_base="${VECTORS_RELEASE_BASE:-https://github.com}"
lock_wait="${FETCH_VECTORS_LOCK_WAIT:-60}"

die() { echo "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || { echo "$1 required${2:+ ($2)}" >&2; exit 2; }; }
digest() { sha256sum "$1" | cut -d' ' -f1; }

[[ -f "$manifest" ]] || die "manifest $manifest not found"
[[ "$lock_wait" =~ ^[0-9]+([.][0-9]+)?$ ]] \
  || die "FETCH_VECTORS_LOCK_WAIT must be a number of seconds (got: $lock_wait)"
need python3 ">=3.11, for tomllib"
need git
need curl
need sha256sum
need tar

# One tab-separated row per source and per asset. A command substitution (not a process
# substitution) so that an invalid manifest aborts the script instead of yielding no rows.
rows="$(python3 -I - "$manifest" <<'PY'
import re, sys, tomllib

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*")
TAG = re.compile(r"v\d+\.\d+\.\d+([.-][0-9A-Za-z.]+)?")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.(tar\.gz|zip)")

path = sys.argv[1]
def fail(msg):
    sys.exit(f"manifest {path}: {msg}")
def field(table, key, pattern, what):
    value = table.get(key)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(f"{what}: {key} = {value!r} is missing or malformed")
    return value

try:
    with open(path, "rb") as f:
        manifest = tomllib.load(f)
except (OSError, tomllib.TOMLDecodeError) as e:
    fail(str(e))
sources = manifest.get("source")
if not isinstance(sources, list) or not sources:
    fail("no [[source]] entries")
for s in sources:
    name = field(s, "name", NAME, "source")
    repo = field(s, "repo", REPO, name)
    tag = field(s, "tag", TAG, f"{name} (an exact version tag)")
    commit = field(s, "commit", COMMIT, f"{name} (the full commit the tag resolves to)")
    print("\t".join(["source", name, repo, tag, commit]))
    assets = s.get("asset")
    if not isinstance(assets, list) or not assets:
        fail(f"{name}: no [[source.asset]] entries")
    for a in assets:
        file = field(a, "file", FILE, f"{name} asset (.tar.gz or .zip)")
        sha = field(a, "sha256", SHA256, f"{name}/{file}")
        optional = a.get("optional", False)
        if not isinstance(optional, bool):
            fail(f"{name}/{file}: optional must be true or false")
        print("\t".join(["asset", name, repo, tag, file, sha, str(int(optional))]))
PY
)"

# Prints the commit refs/tags/<tag> points at, peeling an annotated tag via ^{}.
resolve_tag() {
  local repo="$1" tag="$2" refs
  refs="$(GIT_TERMINAL_PROMPT=0 git ls-remote --tags "$git_base/$repo" \
    "refs/tags/$tag" "refs/tags/$tag^{}")" || return 1
  awk -v ref="refs/tags/$tag" '
    $2 == ref "^{}" { peeled = $1 }
    $2 == ref       { direct = $1 }
    END { print (peeled != "" ? peeled : direct) }
  ' <<<"$refs"
}

part="" staging="" held_lock="" held_lockf="" tree="" old_tree=""
cleanup() {
  if [[ -n "$part" ]]; then rm -f "$part"; fi
  if [[ -n "$staging" ]]; then rm -rf "$staging"; fi
  if [[ -n "$old_tree" && -e "$old_tree" && ! -e "$tree" ]]; then mv "$old_tree" "$tree" || true; fi
  release_lock cleanup || true
  return 0
}
trap cleanup EXIT

alive() { kill -0 "$1" 2>/dev/null || ps -p "$1" >/dev/null 2>&1; }

# A PID only means something on one host and inside one PID namespace, so a lock records both
# next to it and is only ever reclaimed by a run that sees the same ones.
my_host="$(uname -n)"
my_pidns="$(readlink "/proc/$$/ns/pid" 2>/dev/null || echo none)"

# Test-only: with FETCH_VECTORS_TEST=1, FETCH_VECTORS_LOCK_HOOK names a program run as
# `<hook> <stage> <lock>` at each step of taking a lock (waiting, read, owned) and half-way
# through releasing it (releasing, under the flock), so tests can pause concurrent runs at
# chosen points. A failing hook aborts the run. Without FETCH_VECTORS_TEST=1 the hook is
# ignored, so a stray variable in a real environment can never run code inside the lock.
if [[ -n "${FETCH_VECTORS_LOCK_HOOK:-}" && "${FETCH_VECTORS_TEST:-}" != 1 ]]; then
  echo "ignoring FETCH_VECTORS_LOCK_HOOK: it is test-only (FETCH_VECTORS_TEST=1)" >&2
fi
lock_hook() {
  if [[ -n "${FETCH_VECTORS_LOCK_HOOK:-}" && "${FETCH_VECTORS_TEST:-}" == 1 ]]; then
    "$FETCH_VECTORS_LOCK_HOOK" "$1" "$2" || die "lock hook failed at $1"
  fi
}

# Waits up to $1 seconds for an exclusive flock(2) on fd 9. The lock belongs to the open file
# description, so it outlives python3 and is held until this shell closes fd 9 (or exits,
# including on SIGKILL).
flock_fd9() {
  python3 -I -c '
import fcntl, sys, time
deadline = time.monotonic() + float(sys.argv[1])
while True:
    try:
        fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
        break
    except BlockingIOError:
        if time.monotonic() >= deadline:
            sys.exit(1)
        time.sleep(0.05)
' "$1"
}

# Takes the per-asset lock directory $1, writing our PID, host and PID namespace into it. A
# lock whose recorded PID is no longer running on this host, in this namespace, is taken over;
# a lock with a live or unreadable PID, or from another host or namespace, fails closed.
# Every step (mkdir, read, check, remove, mkdir, PID write) runs under an flock on $3, so two
# runs can never both reclaim, or reclaim a lock that another run has just taken.
take_lock() {
  local lock="$1" label="$2" lockf="$3" owner host pidns
  lock_hook waiting "$lock"
  exec 9>>"$lockf"
  flock_fd9 "$lock_wait" || die "LOCKED $label: timed out waiting for $lockf"
  if ! mkdir "$lock" 2>/dev/null; then
    owner="$(cat "$lock/pid" 2>/dev/null || true)"
    host="$(cat "$lock/host" 2>/dev/null || true)"
    pidns="$(cat "$lock/pidns" 2>/dev/null || true)"
    if [[ "$owner" =~ ^[0-9]+$ ]] && [[ "$host" != "$my_host" || "$pidns" != "$my_pidns" ]]; then
      die "LOCKED $label: $lock belongs to PID $owner on host ${host:-unknown}, PID namespace ${pidns:-unknown} (this run: $my_host, $my_pidns); a lock from another host or namespace is never taken over, so remove it by hand once that run is gone"
    fi
    if [[ ! "$owner" =~ ^[0-9]+$ ]] || alive "$owner"; then
      die "LOCKED $label: $lock is held by ${owner:-an unknown process}; another fetch-vectors run is using it"
    fi
    lock_hook read "$lock"
    echo "taking over stale lock $lock (PID $owner is not running)" >&2
    rm -rf "$lock"
    mkdir "$lock" || die "LOCKED $label: could not recreate $lock"
  fi
  held_lock="$lock" held_lockf="$lockf"
  echo "$my_host" >"$lock/host"
  echo "$my_pidns" >"$lock/pidns"
  echo "$$" >"$lock/pid"
  exec 9>&-
  lock_hook owned "$lock"
}

# Removes the lock directory this run holds, under the same flock as take_lock, so a run that
# arrives mid-release waits for it instead of reading a half-removed lock (no PID) and failing
# with a spurious LOCKED. If the flock cannot be had in time the directory is removed anyway:
# that can only make a concurrent run fail closed, never let two runs own the asset.
# `release_lock cleanup` (the exit trap) runs no hook, so a failing hook cannot leave it behind.
release_lock() {
  [[ -n "$held_lock" ]] || return 0
  local locked=0
  exec 9>>"$held_lockf"
  if flock_fd9 "$lock_wait"; then locked=1; fi
  rm -f "$held_lock/pid"
  if ((locked)) && [[ "${1:-}" != cleanup ]]; then lock_hook releasing "$held_lock"; fi
  rm -rf "$held_lock"
  held_lock=""
  exec 9>&-
}

# Pass 0: pick the assets this run fetches. Only their sources get a tag check.
selected="" wanted=" "
while IFS= read -r -u 3 row; do
  IFS=$'\t' read -r kind name _ tag file _ opt <<<"$row"
  [[ "$kind" == asset ]] || continue
  stem="${file%.tar.gz}"; stem="${stem%.zip}"
  if [[ "$opt" == 1 && "$include_optional" != 1 ]]; then
    echo "skip optional $name/$tag/$file"; continue
  fi
  if [[ -n "$presets" && "$name" == consensus-specs && " $presets " != *" $stem "* ]]; then
    echo "skip preset $file"; continue
  fi
  selected+="$row"$'\n'
  wanted+="$name "
done 3<<<"$rows"

# Pass 1: every selected source tag must still point at its pinned commit, before any download.
while IFS=$'\t' read -r -u 3 kind name repo tag commit _; do
  [[ "$kind" == source ]] || continue
  if [[ "$wanted" != *" $name "* ]]; then echo "skip tag check $name (no selected asset)"; continue; fi
  got="$(resolve_tag "$repo" "$tag")" \
    || die "TAG UNRESOLVED $name $tag: git ls-remote $git_base/$repo failed"
  [[ -n "$got" ]] || die "TAG UNRESOLVED $name $tag: no such tag in $git_base/$repo"
  [[ "$got" == "$commit" ]] \
    || die "TAG MISMATCH $name $tag: expected commit $commit got $got"
  echo "tag ok $name $tag -> $commit"
done 3<<<"$rows"

# Pass 2: download (or re-hash the kept archive), then, and only then, extract.
while IFS=$'\t' read -r -u 3 kind name repo tag file sha _; do
  [[ "$kind" == asset ]] || continue
  label="$name/$tag/$file"
  stem="${file%.tar.gz}"; stem="${stem%.zip}"
  [[ "$file" == *.zip ]] && need unzip
  outdir="$dest/$name/$tag"; mkdir -p "$outdir"
  archive="$outdir/$file"; tree="$outdir/$stem"; stamp="$outdir/.$file.ok"
  lock="$outdir/.$file.lock"
  take_lock "$lock" "$label" "$outdir/.$file.lockf"

  verified=0
  if [[ -f "$stamp" && -f "$archive" && "$(<"$stamp")" == "$sha" ]]; then
    got="$(digest "$archive")"
    if [[ "$got" != "$sha" ]]; then
      rm -rf "$archive" "$tree" "$stamp"
      die "SHA256 MISMATCH $label (cached archive): expected $sha got $got"
    fi
    echo "cached $label (re-hashed)"
    verified=1
  fi
  rm -f "$stamp"   # rewritten only after the tree below is complete

  if [[ "$verified" == 0 ]]; then
    url="$release_base/$repo/releases/download/$tag/$file"
    echo "fetch $url"
    part="$(mktemp "$outdir/.$file.part.XXXXXX")"
    curl --fail --silent --show-error --location \
      --proto '=https,file' --proto-redir '=https' \
      -o "$part" "$url" \
      || die "DOWNLOAD FAILED $label from $url (no retry)"
    got="$(digest "$part")"
    [[ "$got" == "$sha" ]] || die "SHA256 MISMATCH $label: expected $sha got $got"
    mv "$part" "$archive"; part=""
  fi

  staging="$(mktemp -d "$outdir/.$stem.extracting.XXXXXX")"
  case "$file" in
    *.tar.gz) tar -xzf "$archive" -C "$staging" ;;
    *.zip) unzip -q "$archive" -d "$staging" ;;
  esac
  # Swap: move the previous tree aside, move the new one in, restore the old one on failure.
  old_tree=""
  if [[ -e "$tree" ]]; then
    old_tree="$tree.old.$$"
    rm -rf "$old_tree"
    mv "$tree" "$old_tree"
  fi
  if ! mv "$staging" "$tree"; then
    if [[ -n "$old_tree" ]]; then mv "$old_tree" "$tree" && old_tree=""; fi
    die "EXTRACT FAILED $label: could not move the new tree into place; previous tree kept"
  fi
  staging=""
  if [[ -n "$old_tree" ]]; then rm -rf "$old_tree"; old_tree=""; fi
  echo "$sha" >"$stamp"
  release_lock
  echo "ok $label"
done 3<<<"$selected"
