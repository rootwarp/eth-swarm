#!/usr/bin/env bash
# Fail unless every libp2p* crate comes from one full commit SHA of libp2p/rust-libp2p, and that
# commit contains the gossipsub StrictNoSign `key` rejection (rust-libp2p PR 6621, merged as FIX).
# Keep in sync with the root Cargo.toml [patch.crates-io] and the deny.toml [sources] comment.
#
# Checks, against <root>/Cargo.lock and every Cargo.toml under <root> (Cargo.lock and deny.toml are
# parsed as TOML with python3 >= 3.11, so any layout cargo accepts is read the same):
#   - every Cargo.lock source naming rust-libp2p is git+https://github.com/libp2p/rust-libp2p
#     ?rev=<40 hex>#<the same 40 hex>, and all of them name one SHA;
#   - every [[package]] named libp2p or libp2p-* has exactly that source (never crates.io) and
#     appears once (a second version is a duplicate, whatever cargo-deny's skip list says);
#   - every Cargo.toml line naming github.com/libp2p/rust-libp2p carries rev = "<that SHA>";
#   - <root>/deny.toml, if present, has no libp2p* crate in [bans] skip or skip-tree, in any entry
#     form ("name", "name@version", { crate = ... }, { name = ..., version = ... }); an entry of
#     another form fails too;
#   - FIX is an ancestor of (or equal to) that SHA, and that SHA is an ancestor of (or equal to)
#     upstream master. The commit graph of the SHA and master is fetched (commits only,
#     --filter=tree:0) from LIBP2P_REMOTE; a failed fetch fails the check.
#
# Usage: scripts/check-libp2p-revs.sh [ROOT]   (default: this repo)
# Env (tests only): LIBP2P_REMOTE (default https://github.com/libp2p/rust-libp2p),
#   LIBP2P_FIX_COMMIT (default FIX below), LIBP2P_SKIP_ANCESTRY=1 (skip the ancestry step).
# Exit: 0 OK, 1 a pin violation, 2 the check could not run (no python3 >= 3.11, or the ancestry
# fetch failed). Works on bash 3.2.
set -euo pipefail
FIX=ba75f82a872075b7f628570cbb8fe6555f6e54b8   # "fix(gossipsub): reject `key` field in anonymous validation mode"
URL=https://github.com/libp2p/rust-libp2p

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
fix=${LIBP2P_FIX_COMMIT:-$FIX}
remote=${LIBP2P_REMOTE:-$URL}
lock="$root/Cargo.lock"
[[ -f $lock ]] || { echo "ERROR: $lock missing: Cargo.lock must be committed"; exit 1; }

# Cargo.lock and deny.toml are read as TOML (python3 -I, so nothing from the CWD is imported), never
# line by line: cargo --locked accepts any layout of the same data. Prints "ERROR ..." per violation,
# then "SHA <sha>" once the one rust-libp2p commit is known. Exit 0 clean, 1 a violation, 2 no tomllib.
read -r -d '' CHECK_PY <<'PY' || true
import re, sys

if sys.version_info < (3, 11):
    print("ERROR: python3 >= 3.11 (tomllib) is required, found %d.%d" % sys.version_info[:2])
    sys.exit(2)
import tomllib

lock_path, deny_path, url = sys.argv[1:4]
errors = []
err = errors.append
SOURCE = re.compile(r"git\+https://github\.com/libp2p/rust-libp2p(\.git)?\?rev=([0-9a-f]{40})#([0-9a-f]{40})")


def libp2p_name(spec):
    # libp2p or libp2p-*, however a version or separator follows: "libp2p-core@0.43.0", "libp2p".
    return isinstance(spec, str) and re.match(r"\s*libp2p(?![A-Za-z0-9])", spec, re.IGNORECASE) is not None


def load(path, what):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        print("ERROR %s: not valid TOML: %s" % (what, e))
        sys.exit(1)


packages = load(lock_path, "Cargo.lock").get("package", [])
if not isinstance(packages, list) or not all(isinstance(p, dict) for p in packages):
    print("ERROR Cargo.lock: package is not an array of tables")
    sys.exit(1)

# Every source naming rust-libp2p: the one accepted form, with the requested rev equal to the SHA.
shas = set()
for p in packages:
    src = p.get("source")
    if isinstance(src, str) and "rust-libp2p" in src.lower():
        m = SOURCE.fullmatch(src)
        if m and m.group(2) == m.group(3):
            shas.add(m.group(3))
        else:
            err("Cargo.lock: rust-libp2p source not pinned by a full rev to its resolved SHA: %s" % src)
if not shas:
    print("ERROR Cargo.lock: no rust-libp2p git source (every libp2p* crate must come from %s)" % url)
    sys.exit(1)
if len(shas) > 1:
    err("Cargo.lock: %d rust-libp2p commits, want exactly one: %s" % (len(shas), " ".join(sorted(shas))))
sha = sorted(shas)[0]
want = "git+%s?rev=%s#%s" % (url, sha, sha)

# Every libp2p* package: from that source (never crates.io), and only one version of each name.
seen = {}
for p in packages:
    name = p.get("name")
    if not libp2p_name(name):
        continue
    seen[name] = seen.get(name, 0) + 1
    if p.get("source") != want:
        err("Cargo.lock: %s %s does not come from %s (source: %s)" % (name, p.get("version"), want, p.get("source") or "none"))
for name, n in sorted(seen.items()):
    if n > 1:
        err("Cargo.lock: %s appears %d times; a second libp2p* version is not allowed" % (name, n))

# deny.toml must never excuse a libp2p* crate from multiple-versions = "deny", in any form cargo-deny
# takes: "name", "name@version", { crate = ... }, or { name = ..., version = ... }.
if deny_path:
    bans = load(deny_path, "deny.toml").get("bans", {})
    if not isinstance(bans, dict):
        err("deny.toml: [bans] is not a table")
        bans = {}
    for key in ("skip", "skip-tree"):
        entries = bans.get(key, [])
        if not isinstance(entries, list):
            err("deny.toml: [bans] %s is not an array" % key)
            continue
        for e in entries:
            if isinstance(e, str):
                specs = [e]
            elif isinstance(e, dict) and any(k in e for k in ("crate", "name")):
                specs = [e[k] for k in ("crate", "name") if k in e]
            else:
                specs = None
            if specs is None or not all(isinstance(x, str) for x in specs):
                err("deny.toml: [bans] %s entry not understood: %r" % (key, e))
            elif any(libp2p_name(x) for x in specs):
                err("deny.toml: libp2p* crate in [bans] skip or skip-tree: %s = %r" % (key, e))

for e in errors:
    print("ERROR " + e)
print("SHA " + sha)
sys.exit(1 if errors else 0)
PY

command -v python3 >/dev/null || { echo "ERROR: python3 >= 3.11 is required to read Cargo.lock"; exit 2; }
deny=""
if [[ -f $root/deny.toml ]]; then deny="$root/deny.toml"; fi
rc=0
out=$(python3 -I -c "$CHECK_PY" "$lock" "$deny" "$URL") || rc=$?
((rc != 2)) || { printf '%s\n' "$out"; exit 2; }
printf '%s\n' "$out" | grep -v '^SHA ' || true
sha=$(printf '%s\n' "$out" | sed -n 's/^SHA \([0-9a-f]\{40\}\)$/\1/p')
fail=0
if ((rc != 0)); then fail=1; fi
[[ -n $sha ]] || exit 1
err() { echo "ERROR $*"; fail=1; }

# Every manifest line naming rust-libp2p pins that SHA as its full rev.
while IFS= read -r line; do
  [[ $line == *"rev = \"$sha\""* ]] || err "Cargo.toml: rust-libp2p not pinned to $sha: $line"
done < <(find "$root" \( -name target -o -name .git \) -prune -o -name Cargo.toml -exec grep -h 'github\.com/libp2p/rust-libp2p' {} + || true)

((fail == 0)) || exit 1

# FIX must be in the history of the pinned commit, and the pinned commit in upstream master's: GitHub
# serves a fork's commit by SHA through the parent repo's URL, so fetching it proves nothing.
if [[ ${LIBP2P_SKIP_ANCESTRY:-} == 1 ]]; then
  echo "WARNING: ancestry check SKIPPED (LIBP2P_SKIP_ANCESTRY=1): $fix not verified in $sha"
else
  git_dir=$(mktemp -d)
  # Best effort: a temp dir that cannot be removed is reported, and the exit status stays the verdict.
  trap 'rm -rf "$git_dir" 2>/dev/null || echo "WARNING: could not remove $git_dir" >&2' EXIT
  git init -q --bare "$git_dir"
  # No auto maintenance: fetch would detach `git maintenance run --auto` (older git: `gc --auto`),
  # whose commit-graph write can recreate files in $git_dir while the trap above removes it.
  git -C "$git_dir" config maintenance.auto false
  git -C "$git_dir" config gc.auto 0
  git -C "$git_dir" remote add origin "$remote"
  git -C "$git_dir" config remote.origin.promisor true
  git -C "$git_dir" config remote.origin.partialclonefilter tree:0
  if ! git -C "$git_dir" fetch -q --no-tags --filter=tree:0 origin "$sha" \
    "+refs/heads/master:refs/remotes/origin/master" 2>"$git_dir/fetch.err"; then
    sed 's/^/  /' "$git_dir/fetch.err"
    echo "ERROR: cannot fetch $sha and master from $remote, so the pin cannot be checked for $fix"
    exit 2
  fi
  if ! GIT_NO_LAZY_FETCH=1 git -C "$git_dir" cat-file -e "$fix^{commit}" 2>/dev/null \
    || ! GIT_NO_LAZY_FETCH=1 git -C "$git_dir" merge-base --is-ancestor "$fix" "$sha"; then
    echo "ERROR: rust-libp2p $sha does not contain $fix (gossipsub StrictNoSign key rejection)"
    exit 1
  fi
  if ! GIT_NO_LAZY_FETCH=1 git -C "$git_dir" merge-base --is-ancestor "$sha" refs/remotes/origin/master; then
    echo "ERROR: rust-libp2p $sha is not on rust-libp2p master (a fork or unmerged commit served by SHA)"
    exit 1
  fi
fi
echo "libp2p revs OK: every libp2p* crate from rust-libp2p $sha"
