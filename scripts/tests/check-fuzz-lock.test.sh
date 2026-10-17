#!/usr/bin/env bash
# Tests for scripts/check-fuzz-lock.sh. Run: bash scripts/tests/check-fuzz-lock.test.sh
# Each case is a throwaway root with a Cargo.toml, Cargo.lock and fuzz/ pair; one runs the real
# repo. The lockfile cases are not real crates, so a stub (FUZZ_LOCK_CARGO) stands in for the
# `cargo metadata --locked` resolution check; the resolution cases build real path-only crates
# and run real cargo, offline. The real-repo case runs real cargo in fuzz/ (the pinned nightly;
# set CARGO_NET_OFFLINE=true to keep it off the network). Needs cargo and python3 >= 3.11.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-fuzz-lock.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The resolution stub: records its directory and arguments, exits FAKE_METADATA_RC (default 0).
stub="$tmp/fake-cargo"
cat > "$stub" <<'EOF'
#!/usr/bin/env bash
echo "$PWD: $*" >> "$STUB_CALLS"
exit "${FAKE_METADATA_RC:-0}"
EOF
chmod +x "$stub"
export STUB_CALLS="$tmp/stub-calls"

passed=0 failed=0
# check <pass|fail> <description> <root> [want in output]: with the resolution stub.
# check_real: the same with real cargo.
check() { FUZZ_LOCK_CARGO=$stub run_check "$@"; }
check_real() { run_check "$@"; }
run_check() {
  local expect=$1 desc=$2 root=$3 want=${4:-} rc=0 out ok=0
  out=$(bash "$script" "$root" 2>&1) || rc=$?
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then ok=1; fi
  if ((ok)) && [[ -n $want ]] && ! grep -qF -- "$want" <<<"$out"; then ok=0; fi
  if ((ok)); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

GIT='git+https://github.com/libp2p/rust-libp2p?rev=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
REG='registry+https://github.com/rust-lang/crates.io-index'
PATCH='[patch.crates-io]
libp2p = { git = "https://github.com/libp2p/rust-libp2p", rev = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }'

pkg() { # pkg <name> <version> [source]
  printf '\n[[package]]\nname = "%s"\nversion = "%s"\n' "$1" "$2"
  [[ -z ${3:-} ]] || printf 'source = "%s"\n' "$3"
}

# fixture <name> <root patch> <fuzz patch> <fuzz lock packages...>: the root lock always holds
# p2p-wire (path), libp2p (git) and snap (registry).
fixture() {
  local root="$tmp/$1" root_patch=$2 fuzz_patch=$3
  shift 3
  mkdir -p "$root/fuzz"
  printf '[workspace]\nmembers = []\n\n%s\n' "$root_patch" > "$root/Cargo.toml"
  { echo 'version = 4'; pkg p2p-wire 0.1.0; pkg libp2p 0.57.1 "$GIT"; pkg snap 1.1.2 "$REG"; } > "$root/Cargo.lock"
  printf '[package]\nname = "ethswarm-fuzz"\n\n[workspace]\n\n%s\n\n[[bin]]\nname = "t"\n' "$fuzz_patch" > "$root/fuzz/Cargo.toml"
  { echo 'version = 4'; for p in "$@"; do printf '%s\n' "$p"; done; } > "$root/fuzz/Cargo.lock"
  echo "$root"
}

shared="$(pkg p2p-wire 0.1.0)
$(pkg libp2p 0.57.1 "$GIT")
$(pkg snap 1.1.2 "$REG")"
fuzz_only="$(pkg ethswarm-fuzz 0.0.0)
$(pkg libfuzzer-sys 0.4.13 "$REG")
$(pkg arbitrary 1.5.0 "$REG")"

check pass "identical patches, shared crates resolved alike" \
  "$(fixture ok "$PATCH" "$PATCH" "$shared" "$fuzz_only")" "fuzz lock OK"
check pass "a subset of the root lock" \
  "$(fixture subset "$PATCH" "$PATCH" "$(pkg p2p-wire 0.1.0)" "$fuzz_only")"
check fail "no [patch.crates-io] in fuzz/Cargo.toml" \
  "$(fixture nopatch "$PATCH" "" "$shared")" "[patch.crates-io]"
check fail "a different patch rev" \
  "$(fixture rev "$PATCH" "${PATCH//aaaa/bbbb}" "$shared")" "[patch.crates-io]"
check fail "an extra patch entry" \
  "$(fixture extra "$PATCH" "$PATCH
snap = { git = \"https://github.com/BurntSushi/rust-snappy\" }" "$shared")" "[patch.crates-io]"
check fail "libp2p from crates.io in the fuzz lock" \
  "$(fixture registry "$PATCH" "$PATCH" "$(pkg libp2p 0.57.1 "$REG")" "$(pkg snap 1.1.2 "$REG")")" \
  "libp2p 0.57.1"
check fail "a shared crate at another version" \
  "$(fixture version "$PATCH" "$PATCH" "$(pkg libp2p 0.57.1 "$GIT")" "$(pkg snap 1.1.1 "$REG")")" \
  "snap 1.1.1"
check fail "a crate the root lock does not have" \
  "$(fixture unknown "$PATCH" "$PATCH" "$shared" "$(pkg evil 1.0.0 "$REG")")" "evil 1.0.0"
check fail "a fuzz-only crate from git" \
  "$(fixture fuzzgit "$PATCH" "$PATCH" "$shared" "$(pkg libfuzzer-sys 0.4.13 "$GIT")")" "libfuzzer-sys"
# Dependency edges. pkgd <name> <version> <source> <dependency string...>, as Cargo.lock writes
# them: "name", "name version" or "name version (source)".
pkgd() {
  local name=$1 version=$2 source=$3
  shift 3
  pkg "$name" "$version" "$source"
  printf 'dependencies = [\n'
  for d in "$@"; do printf ' "%s",\n' "$d"; done
  printf ']\n'
}
# edges <name> <root lock packages> <fuzz lock packages>: identical patches, the given locks.
edges() {
  local root="$tmp/$1"
  mkdir -p "$root/fuzz"
  printf '[workspace]\nmembers = []\n\n%s\n' "$PATCH" > "$root/Cargo.toml"
  printf '[package]\nname = "ethswarm-fuzz"\n\n[workspace]\n\n%s\n' "$PATCH" > "$root/fuzz/Cargo.toml"
  { echo 'version = 4'; printf '%s\n' "$2"; } > "$root/Cargo.lock"
  { echo 'version = 4'; printf '%s\n' "$3"; } > "$root/fuzz/Cargo.lock"
  echo "$root"
}
itertools="$(pkg itertools 0.13.0 "$REG")
$(pkg itertools 0.14.0 "$REG")
$(pkg anyhow 1.0.0 "$REG")"
root_prost="$(pkgd prost-derive 0.14.4 "$REG" anyhow "itertools 0.14.0")
$itertools"
check pass "dependency edges as in the root lock" \
  "$(edges same "$root_prost" "$root_prost")" "fuzz lock OK"
# The reviewer's repro: prost-derive pointed at another itertools the root lock also has.
check fail "a dependency edge moved to another version" \
  "$(edges moved "$root_prost" "$(pkgd prost-derive 0.14.4 "$REG" anyhow "itertools 0.13.0")
$itertools")" "prost-derive 0.14.4 -> itertools 0.13.0"
check fail "a dependency the root lock does not give the package" \
  "$(edges extra "$root_prost" "$(pkgd prost-derive 0.14.4 "$REG" anyhow "itertools 0.14.0" "itertools 0.13.0")
$itertools")" "prost-derive 0.14.4 -> itertools 0.13.0"
check pass "fewer dependencies (features the fuzz build does not enable)" \
  "$(edges fewer "$root_prost" "$(pkgd prost-derive 0.14.4 "$REG" "itertools 0.14.0")
$itertools")"
check fail "a dependency that names no package" \
  "$(edges dangling "$root_prost" "$(pkgd prost-derive 0.14.4 "$REG" anyhow "itertools 0.15.0")
$itertools")" "itertools 0.15.0"
check fail "a bare name that two versions match" \
  "$(edges ambiguous "$root_prost" "$(pkgd prost-derive 0.14.4 "$REG" anyhow itertools)
$itertools")" "matches 2 packages"
check pass "a dependency spelled with its source" \
  "$(edges sourced "$root_prost" "$(pkgd prost-derive 0.14.4 "$REG" anyhow "itertools 0.14.0 ($REG)")
$itertools")"
check fail "a fuzz-only crate with an unshared dependency edge" \
  "$(edges fuzzonly "$root_prost" "$root_prost
$(pkgd libfuzzer-sys 0.4.13 "$REG" "itertools 0.12.0")")" "itertools 0.12.0"

root="$(fixture nolock "$PATCH" "$PATCH" "$shared")"
rm "$root/fuzz/Cargo.lock"
check fail "no fuzz/Cargo.lock" "$root" "fuzz/Cargo.lock"

# The resolution check: the stub is called as `cargo metadata --locked` in fuzz/, and its failure
# fails the check.
root="$(fixture resolve "$PATCH" "$PATCH" "$shared" "$fuzz_only")"
: > "$STUB_CALLS"
check pass "the resolution check runs" "$root"
if grep -qxF "$root/fuzz: metadata --locked --format-version 1" "$STUB_CALLS"; then
  passed=$((passed + 1)); echo "ok   - cargo metadata --locked runs in fuzz/"
else
  failed=$((failed + 1)); echo "FAIL - cargo metadata --locked runs in fuzz/"; sed 's/^/       /' "$STUB_CALLS"
fi
FAKE_METADATA_RC=101 check fail "a lock cargo would have to update" "$root" "cargo metadata --locked"

# Real crates: fuzz/ depends on path crate a, which depends on path crate b. Both locks are
# otherwise consistent, so only cargo's resolution can see what a lock lacks.
crates() { # crates <name> <fuzz lock packages>
  local root="$tmp/$1" c
  mkdir -p "$root/fuzz/src"
  for c in a b; do mkdir -p "$root/crates/$c/src"; : > "$root/crates/$c/src/lib.rs"; done
  printf '[workspace]\nmembers = ["crates/a", "crates/b"]\nresolver = "2"\n' > "$root/Cargo.toml"
  printf '[package]\nname = "a"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nb = { path = "../b" }\n' \
    > "$root/crates/a/Cargo.toml"
  printf '[package]\nname = "b"\nversion = "0.1.0"\nedition = "2021"\n' > "$root/crates/b/Cargo.toml"
  { echo 'version = 4'; pkgd a 0.1.0 "" b; pkg b 0.1.0; } > "$root/Cargo.lock"
  : > "$root/fuzz/src/lib.rs"
  printf '[package]\nname = "ethswarm-fuzz"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\na = { path = "../crates/a" }\n\n[workspace]\n' \
    > "$root/fuzz/Cargo.toml"
  { echo 'version = 4'; printf '%s\n' "$2"; } > "$root/fuzz/Cargo.lock"
  echo "$root"
}
CARGO_NET_OFFLINE=true check_real pass "a fuzz lock that satisfies its manifests" \
  "$(crates complete "$(pkgd ethswarm-fuzz 0.0.0 "" a)
$(pkgd a 0.1.0 "" b)
$(pkg b 0.1.0)")" "fuzz lock OK"
# The stale-lock shape: a path crate gained a dependency the fuzz lock never got.
CARGO_NET_OFFLINE=true check_real fail "a fuzz lock without a package a path crate requires" \
  "$(crates missing "$(pkgd ethswarm-fuzz 0.0.0 "" a)
$(pkg a 0.1.0)")" "does not satisfy"

mode() { python3 -I -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o7777)[2:])' "$1"; }
# The regenerated lock is a normal committed file, whatever mode the old one had.
leftovers() { find "$1/fuzz" -maxdepth 1 -name 'Cargo.lock?*' | sed 's/^/       left over: /'; }

# fuzz/regen-lock.sh repairs that lock: from the root lock, then the check passes.
root="$(crates regen "$(pkgd ethswarm-fuzz 0.0.0 "" a)
$(pkg a 0.1.0)")"
chmod 600 "$root/fuzz/Cargo.lock"
rc=0 out=$(CARGO_NET_OFFLINE=true bash "$repo/fuzz/regen-lock.sh" "$root" 2>&1) || rc=$?
if ((rc == 0)) && grep -q '^name = "b"$' "$root/fuzz/Cargo.lock"; then
  passed=$((passed + 1)); echo "ok   - fuzz/regen-lock.sh adds the missing package"
else
  failed=$((failed + 1)); echo "FAIL - fuzz/regen-lock.sh (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'
fi
if [[ $(mode "$root/fuzz/Cargo.lock") == 644 && -z $(leftovers "$root") ]]; then
  passed=$((passed + 1)); echo "ok   - fuzz/regen-lock.sh leaves the lock at mode 644, no temp files"
else
  failed=$((failed + 1)); echo "FAIL - regenerated lock mode $(mode "$root/fuzz/Cargo.lock"), want 644"; leftovers "$root"
fi

# A regeneration that fails validation leaves the old lock as it was: same bytes, same mode.
# regen_fails <name> <description> <edit to the fixture...>: the edit runs in the fixture root.
regen_fails() {
  local name=$1 desc=$2 root rc=0 out
  shift 2
  root="$(crates "$name" "$(pkgd ethswarm-fuzz 0.0.0 "" a)
$(pkg a 0.1.0)")"
  (cd "$root" && "$@")
  chmod 640 "$root/fuzz/Cargo.lock"
  cp -p "$root/fuzz/Cargo.lock" "$tmp/$name.before"
  out=$(CARGO_NET_OFFLINE=true bash "$repo/fuzz/regen-lock.sh" "$root" 2>&1) || rc=$?
  if ((rc != 0)) && cmp -s "$tmp/$name.before" "$root/fuzz/Cargo.lock" \
    && [[ $(mode "$root/fuzz/Cargo.lock") == 640 && -z $(leftovers "$root") ]]; then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc, mode $(mode "$root/fuzz/Cargo.lock"))"
    printf '%s\n' "$out" | sed 's/^/       /'
    diff "$tmp/$name.before" "$root/fuzz/Cargo.lock" | sed 's/^/       /' || true
    leftovers "$root"
  fi
}
# cargo metadata fails: a path dependency that does not exist.
regen_fails regen-metadata "a failed cargo metadata leaves the old lock byte-identical, mode kept" \
  python3 -I -c 'import pathlib; p = pathlib.Path("fuzz/Cargo.toml"); p.write_text(p.read_text().replace("[dependencies]\n", "[dependencies]\nc = { path = \"../crates/c\" }\n"))'
# scripts/check-fuzz-lock.sh fails: the root has a [patch.crates-io] the fuzz manifest lacks.
regen_fails regen-check "a failed lock check leaves the old lock byte-identical, mode kept" \
  sh -c 'printf "\n[patch.crates-io]\nb = { path = \"crates/b\" }\n" >> Cargo.toml'
CARGO_NET_OFFLINE=true check_real pass "the regenerated lock satisfies its manifests" "$root" "fuzz lock OK"

check_real pass "real repo" "$repo"

echo "# $passed passed, $failed failed"
((failed == 0))
