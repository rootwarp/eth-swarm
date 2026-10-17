#!/usr/bin/env bash
# Tests for scripts/check-setup-pin.sh. Run: bash scripts/tests/check-setup-pin.test.sh
# Fixture trees stand in for the repo. The rg path runs only where rg is installed; the grep
# fallback always runs. One case runs the real repo. Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-setup-pin.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0
good='            setup: TrustedSetup::load_pinned(&config.path, BETA4_MAINNET_SHA256)?,'

# fixture <name>: a repo root whose only out-of-crypto-kzg caller is the pinned one in cl-verify.
fixture() {
  local root="$tmp/$1"
  mkdir -p "$root/crates/crypto-kzg/src" "$root/crates/cl-verify/src"
  printf 'pub fn load_pinned(path: &Path, sha: [u8; 32]) {}\n' > "$root/crates/crypto-kzg/src/setup.rs"
  printf '%s\n' "$good" > "$root/crates/cl-verify/src/kzg.rs"
  echo "$root"
}

# check <expect: pass|fail> <description> <root> [env assignments...]
check() {
  local expect=$1 desc=$2 root=$3 rc=0 out
  shift 3
  out=$(env "$@" bash "$script" "$root" 2>&1) || rc=$?
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

modes=("SETUP_PIN_CHECK_NO_RG=1")
if command -v rg >/dev/null 2>&1; then modes+=("SETUP_PIN_CHECK_NO_RG="); else echo "# rg not installed: rg path skipped"; fi

for mode in "${modes[@]}"; do
  m=${mode#SETUP_PIN_CHECK_NO_RG=}; m=${m:+grep}; m=${m:-rg}

  root=$(fixture "clean-$m")
  check pass "[$m] one pinned call in cl-verify/src/kzg.rs" "$root" "$mode"

  root=$(fixture "excluded-$m")
  mkdir -p "$root/crates/spec-tests/src" "$root/crates/cl-verify/tests" "$root/crates/x/tests/common"
  printf 'TrustedSetup::load_pinned(p, other)\n' > "$root/crates/spec-tests/src/lib.rs"
  printf 'TrustedSetup::load_pinned(p, other)\n' > "$root/crates/cl-verify/tests/kzg.rs"
  printf 'TrustedSetup::load_pinned(p, other)\n' > "$root/crates/x/tests/common/mod.rs"
  printf 'TrustedSetup::load_pinned(p, other)\n' >> "$root/crates/crypto-kzg/src/setup.rs"
  check pass "[$m] crypto-kzg, spec-tests and tests/ dirs are excluded" "$root" "$mode"

  root=$(fixture "none-$m")
  : > "$root/crates/cl-verify/src/kzg.rs"
  check fail "[$m] no caller at all" "$root" "$mode"

  root=$(fixture "second-$m")
  printf 'let s = TrustedSetup::load_pinned(p, BETA4_MAINNET_SHA256);\n' > "$root/crates/cl-verify/src/startup.rs"
  check fail "[$m] a second caller in cl-verify" "$root" "$mode"

  root=$(fixture "other-crate-$m")
  mkdir -p "$root/crates/cl-chain/src"
  printf 'TrustedSetup::load_pinned(p, BETA4_MAINNET_SHA256)\n' > "$root/crates/cl-chain/src/kzg.rs"
  check fail "[$m] a caller in another crate" "$root" "$mode"

  root=$(fixture "moved-$m")
  rm "$root/crates/cl-verify/src/kzg.rs"
  printf '%s\n' "$good" > "$root/crates/cl-verify/src/startup.rs"
  check fail "[$m] the one caller is not in cl-verify/src/kzg.rs" "$root" "$mode"

  root=$(fixture "digest-$m")
  printf 'TrustedSetup::load_pinned(&config.path, config.sha256)?\n' > "$root/crates/cl-verify/src/kzg.rs"
  check fail "[$m] the one caller passes another digest" "$root" "$mode"

  # Calls are counted, not lines.
  root=$(fixture "two-on-a-line-$m")
  printf 'let a = load_pinned(p, other); let b = load_pinned(q, BETA4_MAINNET_SHA256);\n' \
    > "$root/crates/cl-verify/src/kzg.rs"
  check fail "[$m] two calls on one line, one with another digest" "$root" "$mode"

  root=$(fixture "two-pinned-on-a-line-$m")
  printf 'load_pinned(p, BETA4_MAINNET_SHA256); load_pinned(q, BETA4_MAINNET_SHA256);\n' \
    > "$root/crates/cl-verify/src/kzg.rs"
  check fail "[$m] two pinned calls on one line" "$root" "$mode"

  # The digest must be the second argument itself, not a lookalike or another position.
  root=$(fixture "first-arg-$m")
  printf 'load_pinned(BETA4_MAINNET_SHA256, other)\n' > "$root/crates/cl-verify/src/kzg.rs"
  check fail "[$m] digest constant in the wrong argument" "$root" "$mode"

  root=$(fixture "lookalike-$m")
  printf 'load_pinned(p, NOT_BETA4_MAINNET_SHA256)\n' > "$root/crates/cl-verify/src/kzg.rs"
  check fail "[$m] a lookalike constant" "$root" "$mode"

  root=$(fixture "comment-$m")
  printf 'load_pinned(p, other) // BETA4_MAINNET_SHA256\n' > "$root/crates/cl-verify/src/kzg.rs"
  check fail "[$m] the digest only in a trailing comment" "$root" "$mode"

  root=$(fixture "split-$m")
  printf 'load_pinned(\n    p,\n    BETA4_MAINNET_SHA256,\n)\n' > "$root/crates/cl-verify/src/kzg.rs"
  check fail "[$m] a call split over lines is not provably pinned" "$root" "$mode"
done

root=$(fixture no-crates)
rm -r "$root/crates"
check fail "missing crates/ directory" "$root"

# The real workspace.
rc=0; out=$(bash "$script" "$repo" 2>&1) || rc=$?
if ((rc == 0)); then passed=$((passed + 1)); echo "ok   - real workspace passes";
else failed=$((failed + 1)); echo "FAIL - real workspace (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'; fi

echo "# $passed passed, $failed failed"
((failed == 0))
