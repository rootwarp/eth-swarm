#!/usr/bin/env bash
# Negative test of the cargo-deny gate: prove that `cargo deny check` FAILS on what deny.toml
# must refuse, so a loosened deny.toml (multiple-versions back to "warn", a libp2p* skip entry, a
# wider allow-git) cannot pass CI unnoticed. Each case copies the workspace manifests into a
# throwaway directory, injects one violation and passes only if cargo deny fails with the
# expected diagnostic:
#   control      the unmodified copy passes `cargo deny check bans sources` (so a failure below
#                comes from the injected violation, not from the copy)
#   libp2p-dup   a second libp2p-swarm version (crates.io =0.47.1 next to the patched 0.48)
#                -> bans: duplicate entries for crate 'libp2p-swarm'
#   git-source   a git dependency from a repo outside [sources] allow-git (a local file:// repo,
#                so no third-party fetch) -> sources: source not allowed
#
# Lockfile: the injected dependency must be resolved, so `cargo update --workspace` writes the
# copy's own Cargo.lock (it cannot take --locked, and it never touches the repo's lock). Every
# cargo deny run is --locked against that lock. Needs crates.io access (libp2p-dup), git and
# cargo-deny. Usage: scripts/check-deny-negative.sh   Exit: 0 every case behaved, 1 otherwise.
# Works on bash 3.2.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0

# workspace <name>: a copy of the workspace manifests, lockfile, deny.toml and crate sources.
workspace() {
  local ws="$tmp/$1"
  mkdir -p "$ws"
  (cd "$root" && tar cf - --exclude target Cargo.toml Cargo.lock deny.toml rust-toolchain.toml crates) | tar xf - -C "$ws"
  echo "$ws"
}

# inject <ws> <Cargo.toml lines...>: appends a dependency table to cl-p2p and resolves it.
inject() {
  local ws=$1
  shift
  printf '%s\n' "" "$@" >> "$ws/crates/cl-p2p/Cargo.toml"
  cargo update --workspace --quiet --manifest-path "$ws/Cargo.toml"
}

# deny <expect: pass|fail> <description> <ws> <output substring for a failure or "">
deny() {
  local expect=$1 desc=$2 ws=$3 want=$4 rc=0 out ok=0
  out=$(cargo deny --locked --manifest-path "$ws/Cargo.toml" check bans sources 2>&1) || rc=$?
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then ok=1; fi
  if ((ok)) && [[ -n $want ]] && ! grep -qF -- "$want" <<<"$out"; then ok=0; fi
  if ((ok)); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc, want $expect)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

ws=$(workspace control)
deny pass "control: the unmodified workspace passes bans and sources" "$ws" ""

ws=$(workspace libp2p-dup)
inject "$ws" '[dependencies.libp2p-swarm-second]' 'package = "libp2p-swarm"' 'version = "=0.47.1"'
deny fail "a second libp2p-swarm version fails bans" "$ws" "duplicate entries for crate 'libp2p-swarm'"

ws=$(workspace git-source)
probe="$tmp/probe"
mkdir -p "$probe/src"
printf '[package]\nname = "deny-probe"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\n' > "$probe/Cargo.toml"
: > "$probe/src/lib.rs"
git -C "$probe" init -q
git -C "$probe" add -A
git -C "$probe" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false commit -q -m probe
rev=$(git -C "$probe" rev-parse HEAD)
inject "$ws" '[dependencies.deny-probe]' "git = \"file://$probe\"" "rev = \"$rev\""
deny fail "a git dependency outside allow-git fails sources" "$ws" "source-not-allowed"

echo "# $passed passed, $failed failed"
((failed == 0))
