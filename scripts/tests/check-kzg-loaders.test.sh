#!/usr/bin/env bash
# Tests for scripts/check-kzg-loaders.sh. Run: bash scripts/tests/check-kzg-loaders.test.sh
# Fixture trees stand in for the repo; a stub `cargo` prints a canned `cargo tree`. The rg path
# runs only where rg is installed; the grep fallback always runs. One case runs the real repo.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-kzg-loaders.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0
clean_tree='blst v0.3.17
└── c-kzg v2.1.8
    └── crypto-kzg v0.1.0 (/repo/crates/crypto-kzg)'
portable_tree='blst v0.3.17
├── blst feature "default"
└── blst feature "portable"
    └── c-kzg feature "portable"'

# fixture <name> <cargo-tree-output> <cargo-exit>: a repo root with an innocuous crypto-kzg crate.
fixture() {
  local root="$tmp/$1"
  mkdir -p "$root/crates/crypto-kzg/src" "$root/bin"
  printf 'pub fn load_pinned() {}\n' > "$root/crates/crypto-kzg/src/lib.rs"
  printf '[dependencies]\nc-kzg = { version = "2.1.8", default-features = false }\n' \
    > "$root/crates/crypto-kzg/Cargo.toml"
  printf '%s\n' "$2" > "$root/tree.txt"
  printf '#!/bin/sh\ncat "%s"\nexit %s\n' "$root/tree.txt" "$3" > "$root/bin/cargo"
  chmod +x "$root/bin/cargo"
  echo "$root"
}

# check <expect: pass|fail> <description> <root> [env assignments...]
check() {
  local expect=$1 desc=$2 root=$3 rc=0 out
  shift 3
  out=$(env CARGO="$root/bin/cargo" "$@" bash "$script" "$root" 2>&1) || rc=$?
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

modes=("KZG_CHECK_NO_RG=1")
if command -v rg >/dev/null 2>&1; then modes+=("KZG_CHECK_NO_RG="); else echo "# rg not installed: rg path skipped"; fi

for mode in "${modes[@]}"; do
  m=${mode#KZG_CHECK_NO_RG=}; m=${m:+grep}; m=${m:-rg}
  root=$(fixture "clean-$m" "$clean_tree" 0)
  check pass "[$m] clean crate, no portable" "$root" "$mode"

  root=$(fixture "file-loader-$m" "$clean_tree" 0)
  printf 'fn f() { KzgSettings::load_trusted_setup_file(p, 0); }\n' > "$root/crates/crypto-kzg/src/x.rs"
  check fail "[$m] text-format file loader in source" "$root" "$mode"

  root=$(fixture "embedded-$m" "$clean_tree" 0)
  printf '[features]\nx = ["c-kzg/ethereum_kzg_settings"]\n' >> "$root/crates/crypto-kzg/Cargo.toml"
  check fail "[$m] embedded settings feature in Cargo.toml" "$root" "$mode"

  root=$(fixture "hidden-$m" "$clean_tree" 0)
  printf 'ethereum_kzg_settings\n' > "$root/crates/crypto-kzg/.hidden"
  printf '.hidden\n' > "$root/crates/crypto-kzg/.gitignore"
  check fail "[$m] hidden, ignored file is still searched" "$root" "$mode"
done

root=$(fixture portable "$portable_tree" 0)
check fail "blst portable feature in cargo tree" "$root"

root=$(fixture tree-error "error: package ID specification \`blst\` did not match any packages" 101)
check fail "cargo tree failure is not a pass" "$root"

root=$(fixture empty-tree "" 0)
check fail "empty cargo tree output is not a pass" "$root"

root=$(fixture no-crate "$clean_tree" 0)
rm -r "$root/crates/crypto-kzg"
check fail "missing crypto-kzg directory" "$root"

# The real workspace, with the real cargo.
rc=0; out=$(bash "$script" "$repo" 2>&1) || rc=$?
if ((rc == 0)); then passed=$((passed + 1)); echo "ok   - real workspace passes";
else failed=$((failed + 1)); echo "FAIL - real workspace (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'; fi

echo "# $passed passed, $failed failed"
((failed == 0))
