#!/usr/bin/env bash
# Tests for scripts/check-contract-tests.sh. Run: bash scripts/tests/check-contract-tests.test.sh
# Fixture trees stand in for the repo; a stub `cargo` prints a canned `--list` per crate. The
# last case runs the real workspace with the real cargo.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-contract-tests.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0

# list_for <rules...>: a `--list` output running each rule in both modes.
list_for() {
  local r
  for r in "$@"; do printf 'in_process::%s: test\nuds::%s: test\n' "$r" "$r"; done
  printf '\n%s tests, 0 benchmarks\n' "$(($# * 2))"
}

# fixture <name>: services `alpha` and `beta`, rules r1 r2, both suites complete.
fixture() {
  local root="$tmp/$1" svc
  mkdir -p "$root/crates/ipc" "$root/bin" "$root/lists" "$root/proto/ethswarm/common/v1"
  printf '# rules\nr1\nr2\n' > "$root/crates/ipc/contract-rules.txt"
  for svc in alpha beta; do
    mkdir -p "$root/proto/ethswarm/$svc/v1" "$root/crates/cl-$svc/tests"
    printf 'ipc::contract_suite!(target);\n' > "$root/crates/cl-$svc/tests/contract.rs"
    list_for r1 r2 > "$root/lists/cl-$svc.txt"
  done
  # The stub cargo prints lists/<crate>.txt and exits with lists/<crate>.rc (default 0).
  cat > "$root/bin/cargo" <<STUB
#!/bin/sh
while [ \$# -gt 0 ]; do [ "\$1" = -p ] && crate=\$2; shift; done
cat "$root/lists/\$crate.txt"
[ -f "$root/lists/\$crate.rc" ] && exit "\$(cat "$root/lists/\$crate.rc")"
exit 0
STUB
  chmod +x "$root/bin/cargo"
  echo "$root"
}

# check <expect: pass|fail> <description> <root> [real]
check() {
  local expect=$1 desc=$2 root=$3 rc=0 out
  if [[ ${4:-} == real ]]; then
    out=$(bash "$script" "$root" 2>&1) || rc=$?
  else
    out=$(env CARGO="$root/bin/cargo" bash "$script" "$root" 2>&1) || rc=$?
  fi
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

root=$(fixture complete)
check pass "every service runs every rule in both modes" "$root"

root=$(fixture missing-file)
rm "$root/crates/cl-beta/tests/contract.rs"
check fail "a service without tests/contract.rs" "$root"

root=$(fixture missing-crate)
mkdir -p "$root/proto/ethswarm/gamma/v1"
check fail "a proto package without a service crate" "$root"

root=$(fixture no-suite)
printf '#[test]\nfn t() {}\n' > "$root/crates/cl-alpha/tests/contract.rs"
check fail "contract.rs that does not invoke contract_suite!" "$root"

root=$(fixture missing-uds)
list_for r1 > "$root/lists/cl-alpha.txt"
printf 'in_process::r2: test\n' >> "$root/lists/cl-alpha.txt"
check fail "a rule run in process only" "$root"

root=$(fixture missing-rule)
list_for r1 > "$root/lists/cl-beta.txt"
check fail "a rule missing from one service" "$root"

root=$(fixture extra-unpaired)
printf 'uds::store_only: test\n' >> "$root/lists/cl-alpha.txt"
check fail "a service-specific test without its in-process twin" "$root"

root=$(fixture extra-paired)
list_for r1 r2 extra > "$root/lists/cl-alpha.txt"
check pass "a service-specific rule in both modes" "$root"

root=$(fixture list-error)
echo 101 > "$root/lists/cl-alpha.rc"
check fail "cargo test --list failing is not a pass" "$root"

root=$(fixture no-rules)
printf '# none\n' > "$root/crates/ipc/contract-rules.txt"
check fail "an empty rules file" "$root"

root=$(fixture no-services)
rm -r "$root/proto/ethswarm/alpha" "$root/proto/ethswarm/beta"
check fail "no service packages" "$root"

check pass "real workspace passes" "$repo" real

echo "# $passed passed, $failed failed"
((failed == 0))
