#!/usr/bin/env bash
# Fail unless every libp2p* crate comes from one full commit SHA of libp2p/rust-libp2p, and that
# commit contains the gossipsub StrictNoSign `key` rejection (rust-libp2p PR 6621, merged as FIX).
# Keep in sync with the root Cargo.toml [patch.crates-io] and the deny.toml [sources] comment.
#
# Checks, against <root>/Cargo.lock and every Cargo.toml under <root>:
#   - every Cargo.lock source naming rust-libp2p is git+https://github.com/libp2p/rust-libp2p
#     ?rev=<40 hex>#<the same 40 hex>, and all of them name one SHA;
#   - every [[package]] named libp2p or libp2p-* has exactly that source and appears once (a second
#     version is a duplicate, whatever cargo-deny's skip list says);
#   - every Cargo.toml line naming github.com/libp2p/rust-libp2p carries rev = "<that SHA>";
#   - <root>/deny.toml, if present, has no libp2p* crate in [bans] skip or skip-tree;
#   - FIX is an ancestor of (or equal to) that SHA. The commit graph is fetched (commits only,
#     --filter=tree:0) from LIBP2P_REMOTE; a failed fetch fails the check.
#
# Usage: scripts/check-libp2p-revs.sh [ROOT]   (default: this repo)
# Env (tests only): LIBP2P_REMOTE (default https://github.com/libp2p/rust-libp2p),
#   LIBP2P_FIX_COMMIT (default FIX below), LIBP2P_SKIP_ANCESTRY=1 (skip the ancestry step).
# Exit: 0 OK, 1 a pin violation, 2 the ancestry could not be checked. Works on bash 3.2.
set -euo pipefail
FIX=ba75f82a872075b7f628570cbb8fe6555f6e54b8   # "fix(gossipsub): reject `key` field in anonymous validation mode"
URL=https://github.com/libp2p/rust-libp2p

root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
fix=${LIBP2P_FIX_COMMIT:-$FIX}
remote=${LIBP2P_REMOTE:-$URL}
lock="$root/Cargo.lock"
[[ -f $lock ]] || { echo "ERROR: $lock missing: Cargo.lock must be committed"; exit 1; }

fail=0
err() { echo "ERROR $*"; fail=1; }

# Every source naming rust-libp2p: the one accepted form, with the requested rev equal to the SHA.
shas=""
while IFS= read -r src; do
  if [[ $src =~ ^git\+https://github\.com/libp2p/rust-libp2p(\.git)?\?rev=([0-9a-f]{40})#([0-9a-f]{40})$ ]] \
    && [[ ${BASH_REMATCH[2]} == "${BASH_REMATCH[3]}" ]]; then
    shas="$shas${BASH_REMATCH[3]}"$'\n'
  else
    err "Cargo.lock: rust-libp2p source not pinned by a full rev to its resolved SHA: $src"
  fi
done < <(sed -n 's/^source = "\(.*rust-libp2p.*\)"$/\1/p' "$lock")
shas=$(printf '%s' "$shas" | sort -u | sed '/^$/d')
count=$(printf '%s' "$shas" | grep -c . || true)
if ((count == 0)); then
  echo "ERROR Cargo.lock: no rust-libp2p git source (every libp2p* crate must come from $URL)"
  exit 1
fi
if ((count > 1)); then
  err "Cargo.lock: $count rust-libp2p commits, want exactly one:" $shas
fi
sha=$(printf '%s\n' "$shas" | head -n 1)
want="git+$URL?rev=$sha#$sha"

# Every libp2p* package: from that source, and only one version of each name.
while IFS=$'\t' read -r name version source; do
  [[ $source == "$want" ]] || err "Cargo.lock: $name $version does not come from $want (source: ${source:-none})"
done < <(awk '
  function flush() { if (name ~ /^libp2p(-|$)/) printf "%s\t%s\t%s\n", name, version, source; name = version = source = "" }
  /^\[\[package\]\]/ { flush(); next }
  /^name = /    { name = $3; gsub(/"/, "", name) }
  /^version = / { version = $3; gsub(/"/, "", version) }
  /^source = /  { source = $3; gsub(/"/, "", source) }
  END { flush() }
' "$lock")
while read -r n name; do
  err "Cargo.lock: $name appears $n times; a second libp2p* version is not allowed"
done < <(sed -n 's/^name = "\(libp2p\(-.*\)\{0,1\}\)"$/\1/p' "$lock" | sort | uniq -c | awk '$1 > 1')

# Every manifest line naming rust-libp2p pins that SHA as its full rev.
while IFS= read -r line; do
  [[ $line == *"rev = \"$sha\""* ]] || err "Cargo.toml: rust-libp2p not pinned to $sha: $line"
done < <(find "$root" \( -name target -o -name .git \) -prune -o -name Cargo.toml -exec grep -h 'github\.com/libp2p/rust-libp2p' {} + || true)

# deny.toml must never excuse a libp2p* crate from multiple-versions = "deny".
if [[ -f $root/deny.toml ]]; then
  while IFS= read -r line; do
    err "deny.toml: libp2p* crate in [bans] skip or skip-tree: $line"
  done < <(awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*\[/ && !inlist { section = $0 }
    !inlist && /^[[:space:]]*skip(-tree)?[[:space:]]*=/ && (section ~ /^[[:space:]]*\[bans\]/) { inlist = 1 }
    inlist && /crate[[:space:]]*=[[:space:]]*"libp2p(-[^"@]*)?(@[^"]*)?"/ { print }
    inlist && /\][[:space:]]*(#.*)?$/ { inlist = 0 }
  ' "$root/deny.toml")
fi

((fail == 0)) || exit 1

# FIX must be in the history of the pinned commit.
if [[ ${LIBP2P_SKIP_ANCESTRY:-} == 1 ]]; then
  echo "WARNING: ancestry check SKIPPED (LIBP2P_SKIP_ANCESTRY=1): $fix not verified in $sha"
else
  git_dir=$(mktemp -d)
  trap 'rm -rf "$git_dir"' EXIT
  git init -q --bare "$git_dir"
  git -C "$git_dir" remote add origin "$remote"
  git -C "$git_dir" config remote.origin.promisor true
  git -C "$git_dir" config remote.origin.partialclonefilter tree:0
  if ! git -C "$git_dir" fetch -q --no-tags --filter=tree:0 origin "$sha" 2>"$git_dir/fetch.err"; then
    sed 's/^/  /' "$git_dir/fetch.err"
    echo "ERROR: cannot fetch $sha from $remote, so the pin cannot be checked for $fix"
    exit 2
  fi
  if ! GIT_NO_LAZY_FETCH=1 git -C "$git_dir" cat-file -e "$fix^{commit}" 2>/dev/null \
    || ! GIT_NO_LAZY_FETCH=1 git -C "$git_dir" merge-base --is-ancestor "$fix" "$sha"; then
    echo "ERROR: rust-libp2p $sha does not contain $fix (gossipsub StrictNoSign key rejection)"
    exit 1
  fi
fi
echo "libp2p revs OK: every libp2p* crate from rust-libp2p $sha"
