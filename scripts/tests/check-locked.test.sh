#!/usr/bin/env bash
# Tests for scripts/check-locked.sh. Run: bash scripts/tests/check-locked.test.sh
# Each case writes one workflow into a temp dir and runs the check on it; the committed negative
# fixture (testing/fixtures/workflow-unlocked.yml) and the real workflows are checked too.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-locked.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0 n=0

# run_check <expect-exit> <description> <path...>
run_check() {
  local expect=$1 desc=$2 rc=0 out
  shift 2
  out=$(bash "$script" "$@" 2>&1) || rc=$?
  if ((rc == expect)); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc, want $expect)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

# workflow <expect-exit> <description> <run-block-lines>: a workflow whose one step runs the lines.
workflow() {
  local expect=$1 desc=$2 dir
  n=$((n + 1)); dir="$tmp/case$n"; mkdir -p "$dir"
  { printf 'jobs:\n  j:\n    steps:\n      - run: |\n'; printf '%s\n' "$3" | sed 's/^/          /'; } > "$dir/ci.yml"
  run_check "$expect" "$desc" "$dir"
}

# The committed negative fixture, and the real workflows.
run_check 1 "fixture workflow-unlocked.yml (cargo test without --locked) fails" \
  "$repo/testing/fixtures/workflow-unlocked.yml"
run_check 0 "real .github/workflows pass" "$repo/.github/workflows"
run_check 0 "default path is the real .github/workflows"

# Every subcommand that resolves the lockfile needs --locked, built-in aliases included.
for sub in build b test t clippy run r doc d bench check c install nextest llvm-cov deny; do
  workflow 1 "cargo $sub without --locked fails" "cargo $sub --workspace"
  workflow 0 "cargo $sub --locked passes" "cargo $sub --workspace --locked"
done
workflow 1 "cargo nextest run without --locked" "cargo nextest run --workspace"
workflow 0 "cargo llvm-cov with --locked" "cargo llvm-cov --workspace --summary-only --locked"

# A subcommand on neither list fails until it is classified (user aliases, xtask, typos).
workflow 1 "unknown subcommand fails" "cargo frobnicate --locked"
workflow 1 "cargo xtask fails" "cargo xtask dist"
workflow 1 "a longer subcommand name is not test" "cargo testing --locked"
workflow 1 "cargo with no visible subcommand fails" "cargo"
workflow 1 "only global options, no subcommand" "cargo --locked"

workflow 0 "--locked before the subcommand" "cargo --locked test"
workflow 1 "toolchain override without --locked" "cargo +1.99.0 test -p x"
workflow 0 "toolchain override with --locked" "cargo +1.99.0 test -p x --locked"
workflow 1 "global option with a value" "cargo --manifest-path bench/verify-ipc/Cargo.toml run --release"
workflow 0 "global option with a value, locked" "cargo --manifest-path bench/verify-ipc/Cargo.toml run --release --locked"
workflow 1 "after && on one line" "cd x && cargo test"
workflow 1 "--locked on another command of the same line" "cargo build --locked && cargo test"
workflow 1 "--locked on a backgrounded command of the same line" "cargo test & cargo build --locked"
workflow 1 "--locked on the other side of a pipe" "cargo test | tee log && cargo build --locked"
workflow 1 "--locked after -- goes to the test binary" "cargo test -- --locked"
workflow 1 "--locked only in a trailing comment" "cargo test # --locked"
workflow 0 "--locked on a continuation line" 'cargo test \
  --workspace \
  --locked'
workflow 1 "continuation without --locked" 'cargo test \
  --workspace'
mkdir -p "$tmp/inline"
printf 'jobs:\n  j:\n    steps:\n      - run: cargo test -p y\n' > "$tmp/inline/ci.yml"
run_check 1 "inline run: step without --locked" "$tmp/inline"

# Allowlisted (no lockfile involved) and non-commands.
workflow 0 "cargo fmt takes no --locked" "cargo fmt --all -- --check"
workflow 0 "cargo --version needs no lock" "cargo --version && cargo -V"
workflow 0 "a cargo-deny tool name is not cargo" "tool: cargo-deny@0.20.2"
workflow 0 "a comment line is not a command" "# cargo test"
workflow 0 "an env var or path mentioning cargo is not cargo" "echo \$CARGO_HOME ~/.cargo/bin"

# Folded scalars (run: >) join lines, so a command split across them is invisible line by line:
# any folded run: that mentions cargo is refused.
folded() {
  n=$((n + 1)); mkdir -p "$tmp/case$n"
  { printf 'jobs:\n  j:\n    steps:\n      - run: %s\n' "$2"; printf '%s\n' "$3" | sed 's/^/          /'
    printf '      - run: echo next\n'; } > "$tmp/case$n/ci.yml"
  run_check "$1" "$4" "$tmp/case$n"
}
folded 1 ">" 'cargo
test' "folded run: with cargo and test on separate lines"
folded 1 ">-" 'cargo test --locked' "folded run: with cargo is refused even when locked"
folded 1 ">2" 'cargo build --locked' "folded run: with an indentation indicator"
folded 0 ">" 'echo one
echo two' "folded run: without cargo is fine"
folded 0 "|" 'cargo build --locked
cargo test --locked' "literal run: | block is checked line by line"
mkdir -p "$tmp/folded-end"
printf 'jobs:\n  j:\n    steps:\n      - run: >\n          echo x\n        shell: bash\n      - run: cargo test --locked\n' \
  > "$tmp/folded-end/ci.yml"
run_check 0 "a folded block ends at the next key" "$tmp/folded-end"

# .yaml files are scanned as well, and every file of a directory.
mkdir -p "$tmp/yaml"
printf 'jobs:\n  j:\n    steps:\n      - run: cargo test --locked\n' > "$tmp/yaml/a.yml"
printf 'jobs:\n  j:\n    steps:\n      - run: cargo test\n' > "$tmp/yaml/b.yaml"
run_check 1 ".yaml file in the directory is scanned" "$tmp/yaml"

# Nothing to check is an error, not a pass.
mkdir -p "$tmp/empty"
run_check 2 "directory without workflows" "$tmp/empty"
run_check 2 "missing path" "$tmp/absent"

echo "# $passed passed, $failed failed"
((failed == 0))
