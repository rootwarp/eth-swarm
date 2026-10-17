#!/usr/bin/env bash
# Fail unless every service runs the ipc contract suite, in process and over UDS.
#
# The services are the proto packages: every proto/ethswarm/<svc>/v1 except `common` is served
# by crates/cl-<svc>. For each one:
#   1. crates/cl-<svc>/tests/contract.rs exists and invokes `contract_suite!`.
#   2. `cargo test -p cl-<svc> --test contract -- --list` lists every rule of
#      crates/ipc/contract-rules.txt as both `in_process::<rule>` and `uds::<rule>`, and every
#      other in_process test has its uds twin (and the other way round).
# Usage: scripts/check-contract-tests.sh [repo-root]
# Env: CARGO (default `cargo`). Works on bash 3.2.
set -euo pipefail
root=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
cargo=${CARGO:-cargo}
rules_file="$root/crates/ipc/contract-rules.txt"
fail=0

if [[ ! -f $rules_file ]]; then
  echo "ERROR: $rules_file not found"
  exit 1
fi
rules=$(grep -v '^#' "$rules_file" | grep -v '^[[:space:]]*$' || true)
if [[ -z $rules ]]; then
  echo "ERROR: $rules_file lists no rules"
  exit 1
fi

services=""
for dir in "$root"/proto/ethswarm/*/v1; do
  [[ -d $dir ]] || continue
  svc=$(basename "$(dirname "$dir")")
  [[ $svc == common ]] && continue
  services="$services $svc"
done
if [[ -z $services ]]; then
  echo "ERROR: no service packages under $root/proto/ethswarm"
  exit 1
fi

for svc in $services; do
  crate="cl-$svc"
  file="$root/crates/$crate/tests/contract.rs"
  if [[ ! -f $file ]]; then
    echo "ERROR: $crate has no tests/contract.rs (service package ethswarm.$svc.v1)"
    fail=1
    continue
  fi
  if ! grep -q 'contract_suite!' "$file"; then
    echo "ERROR: $crate/tests/contract.rs does not invoke contract_suite!"
    fail=1
    continue
  fi
  rc=0
  list=$("$cargo" test --locked --manifest-path "$root/Cargo.toml" -p "$crate" --test contract \
    -- --list 2>&1) || rc=$?
  if ((rc != 0)); then
    echo "ERROR: listing $crate contract tests failed (exit $rc):"
    printf '%s\n' "$list" | tail -20
    fail=1
    continue
  fi
  tests=$(printf '%s\n' "$list" | sed -n 's/^\(.*\): test$/\1/p' | sort -u)
  for rule in $rules; do
    for mode in in_process uds; do
      if ! grep -qxF "$mode::$rule" <<<"$tests"; then
        echo "ERROR: $crate does not run $mode::$rule"
        fail=1
      fi
    done
  done
  while IFS= read -r t; do
    [[ -z $t ]] && continue
    case $t in
      in_process::*) twin="uds::${t#in_process::}" ;;
      uds::*) twin="in_process::${t#uds::}" ;;
      *) continue ;;
    esac
    if ! grep -qxF "$twin" <<<"$tests"; then
      echo "ERROR: $crate runs $t but not $twin"
      fail=1
    fi
  done <<<"$tests"
done

if ((fail == 0)); then echo "contract suites OK:$services"; fi
exit $fail
