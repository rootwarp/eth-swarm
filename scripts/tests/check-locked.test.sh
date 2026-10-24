#!/usr/bin/env bash
# Tests for scripts/check-locked.sh, the wrapper of crates/ci-checks/src/locked.rs.
# Run: bash scripts/tests/check-locked.test.sh
# The rules have unit tests and an oracle test in crates/ci-checks. These cases check the
# wrapper: its exit codes, its default path, the committed negative fixture
# (testing/fixtures/workflow-unlocked.yml), the real workflows, and one case of each rule.
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
  { printf 'jobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: |\n'; printf '%s\n' "$3" | sed 's/^/          /'; } > "$dir/ci.yml"
  run_check "$expect" "$desc" "$dir"
}

# The committed negative fixture, and the real workflows.
run_check 1 "fixture workflow-unlocked.yml (cargo test without --locked) fails" \
  "$repo/testing/fixtures/workflow-unlocked.yml"
run_check 0 "real .github/workflows pass" "$repo/.github/workflows"
run_check 0 "default path is the real .github/workflows"
cd "$repo"
run_check 0 "a relative path is read from the caller's directory" .github/workflows
cd - >/dev/null

workflow 0 "locked cargo commands pass" "cargo build --workspace --locked
cargo test --locked 2>&1 | tee test.log
cargo fmt --all -- --check"
workflow 1 "cargo test without --locked fails" "cargo test --workspace"
workflow 1 "an unknown subcommand fails" "cargo xtask dist --locked"
workflow 1 "--locked inside a quoted argument fails" 'cargo test "x --locked"'
workflow 1 "a quoted hash before a cargo call fails" 'echo "x #"; cargo build --locked'
workflow 1 "a continuation inside the cargo word fails" 'car\
go build'
workflow 1 "a command substitution fails" 'echo $(cargo build)'
workflow 1 "an fd close fails" 'cargo build --locked >&-'
workflow 1 "a file redirect glued to the flag fails" 'cargo build >&1---locked'
workflow 1 "--locked after the first argument of cargo run goes to the binary" 'cargo run -q x --locked'
workflow 1 "a CARGO_ALIAS_ variable fails" 'CARGO_ALIAS_FMT=build cargo fmt'
workflow 1 "a brace sequence that spells cargo fails" 'car{g..g}o build'
workflow 0 "a line that does not name cargo is not checked" 'echo "x" >> "$GITHUB_ENV"'

# YAML key forms that a line scan misses.
yaml() {
  n=$((n + 1)); mkdir -p "$tmp/case$n"
  printf 'jobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n%s\n' "$3" > "$tmp/case$n/ci.yml"
  run_check "$1" "$2" "$tmp/case$n"
}
yaml 1 "a quoted run key" '      - "run": cargo build'
yaml 1 "a flow mapping step" '      - { run: cargo build }'
yaml 1 "a folded run: scalar that names cargo" '      - run: >
          cargo build --locked'
yaml 1 "a shell template that runs cargo" '      - shell: cargo run --bin x -- {0}
        run: echo hi'

# .yaml files are scanned as well, and every file of a directory.
mkdir -p "$tmp/yaml"
printf 'jobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo test --locked\n' > "$tmp/yaml/a.yml"
printf 'jobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo test\n' > "$tmp/yaml/b.yaml"
run_check 1 ".yaml file in the directory is scanned" "$tmp/yaml"

# Nothing to check is an error, not a pass.
mkdir -p "$tmp/empty"
run_check 2 "directory without workflows" "$tmp/empty"
run_check 2 "missing path" "$tmp/absent"

# The wrapper reports exit 3 when the checker cannot build or run.
mkdir -p "$tmp/fakebin"
printf '#!/bin/sh\nexit 101\n' > "$tmp/fakebin/cargo"
chmod +x "$tmp/fakebin/cargo"
rc=0
out=$(PATH="$tmp/fakebin:$PATH" bash "$script" 2>&1) || rc=$?
if ((rc == 3)) && [[ $out == *"did not run (exit 101)"* ]]; then
  passed=$((passed + 1)); echo "ok   - a checker that does not build exits 3"
else
  failed=$((failed + 1)); echo "FAIL - a checker that does not build exits 3 (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'
fi

echo "# $passed passed, $failed failed"
((failed == 0))
