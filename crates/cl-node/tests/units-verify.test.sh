#!/usr/bin/env bash
# `systemd-analyze verify` on the units `cl-node units` generates (the default profile and the
# supernode one). Run: bash crates/cl-node/tests/units-verify.test.sh
#
# Builds cl-node (--locked), writes the units with --bin-dir pointing at stub executables in a
# temp dir (verify refuses an ExecStart= that is not executable), and runs verify on them. verify
# exits 0 on a line it ignores (an unknown key, a value it cannot parse), so any output at all
# fails too. Two broken copies are the control: each must fail, or the check proves nothing.
#
# verify needs a writable /run/systemd. On a host booted with systemd (CI's ubuntu-24.04) it
# runs as is; elsewhere it runs in a user namespace with a private /run (`unshare -rm`). With
# neither, or without systemd-analyze, the test is skipped with a notice, unless
# ETHSWARM_REQUIRE_SYSTEMD_ANALYZE=1 (CI) makes that a failure. No network, no root.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"   # a stray relative write lands in the temp dir, never in the checkout

skip() {
  if [[ ${ETHSWARM_REQUIRE_SYSTEMD_ANALYZE:-} == 1 ]]; then
    echo "FAIL - $1 (required: ETHSWARM_REQUIRE_SYSTEMD_ANALYZE=1)"
    exit 1
  fi
  echo "SKIP - $1: systemd-analyze verify did not run"
  exit 0
}

command -v systemd-analyze >/dev/null || skip "systemd-analyze is not installed"
if [[ -d /run/systemd/system ]]; then
  wrap=()
elif unshare -rm true 2>/dev/null; then
  # A private tmpfs on /run, where verify can create /run/systemd.
  wrap=(unshare -rm sh -c 'mount -t tmpfs tmpfs /run && exec "$@"' sh)
else
  skip "no systemd on this host and no user namespace for a private /run"
fi
echo "# $(systemd-analyze --version | sed -n 1p)"

passed=0 failed=0
ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() {
  failed=$((failed + 1)); echo "FAIL - $1"
  if [[ -n ${2:-} ]]; then printf '%s\n' "$2" | sed 's/^/       /'; fi
}

cl_node() { cargo run --quiet --locked --manifest-path "$repo/Cargo.toml" -p cl-node --bin cl-node -- "$@"; }

mkdir bin
for svc in verify engine chain store discv5 p2p sync api; do
  printf '#!/bin/sh\nexit 0\n' > "bin/cl-$svc"
  chmod 0755 "bin/cl-$svc"
done

# verify_dir <dir>: verify every unit in <dir>; exit status 0 only if verify exits 0 and prints
# nothing. Its output is in $out.
verify_dir() {
  local rc=0
  out=$(cd "$1" && ${wrap[@]+"${wrap[@]}"} systemd-analyze verify --man=no ./*.service ./*.target 2>&1) || rc=$?
  ((rc == 0)) && [[ -z $out ]]
}

for profile in default supernode; do
  flags=()
  [[ $profile == supernode ]] && flags=(--supernode)
  cl_node units --out "$profile" --network sepolia --bin-dir "$tmp/bin" ${flags[@]+"${flags[@]}"}
  count=$(find "$profile" -type f | wc -l)
  if ((count == 9)); then ok "$profile: nine units written"; else bad "$profile: $count units"; fi
  if verify_dir "$profile"; then
    ok "$profile: systemd-analyze verify passes, no diagnostics"
  else
    bad "$profile: systemd-analyze verify" "$out"
  fi
done

# The controls: a missing binary (verify's exit status) and an unknown key (output only).
for mutation in 's|^ExecStart=.*|ExecStart=/nonexistent/cl-chain|' 's|^Restart=|Restrt=|'; do
  rm -rf broken && cp -R default broken
  sed -i.orig "$mutation" broken/ethswarm-chain.service && rm broken/*.orig
  if verify_dir broken; then
    bad "control: verify passes a broken unit ($mutation)" "$out"
  else
    ok "control: verify fails a broken unit ($mutation)"
  fi
done

echo "passed $passed, failed $failed"
((failed == 0))
