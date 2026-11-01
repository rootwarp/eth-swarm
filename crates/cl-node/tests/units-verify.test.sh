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
#
# Then a probe (bind TCP on an address, connect to it) runs as a transient unit under the
# generated cl-chain unit's RestrictAddressFamilies=, IPAddressAllow= and IPAddressDeny=:
# svc-runtime binds /metrics on 127.0.0.1 before READY=1, so that bind must work, and nothing
# beyond loopback, and no AF_INET6 socket while the unit has no AF_INET6. It needs systemd as
# PID 1, systemd-run, python3, a non-loopback IPv4 address and passwordless sudo (systemd-run as
# root); without them it is skipped with a notice, or fails under
# ETHSWARM_REQUIRE_SYSTEMD_ANALYZE=1.
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

# probe <address> <property>...: the probe as a transient unit with these properties. Status 0
# only if it bound a TCP listener on <address>, connected to it and echoed a byte; output in $out.
probe_py='
import socket, sys
addr = sys.argv[1]
family = socket.AF_INET6 if ":" in addr else socket.AF_INET
try:
    srv = socket.create_server((addr, 0), family=family)
    srv.settimeout(3)
    cli = socket.create_connection(srv.getsockname()[:2], timeout=3)
    conn, _ = srv.accept()
    cli.sendall(b"x")
    if conn.recv(1) != b"x":
        sys.exit(f"probe {addr}: no echo")
except OSError as e:
    sys.exit(f"probe {addr}: {e!r}")
print(f"probe {addr}: bound and connected")
'
probe() {
  local addr=$1 props=() p
  shift
  for p in "$@"; do props+=(-p "$p"); done
  out=$(sudo -n systemd-run --quiet --wait --pipe --collect "${props[@]}" \
    -- "$python" -I -c "$probe_py" "$addr" 2>&1 </dev/null)
}

python=$(command -v python3 || true)
host_ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{sub("/.*", "", $4); print $4; exit}')
why=
if [[ ! -d /run/systemd/system ]]; then why="systemd is not PID 1"
elif ! command -v systemd-run >/dev/null; then why="systemd-run is not installed"
elif [[ -z $python ]]; then why="python3 is not installed"
elif [[ -z $host_ip ]]; then why="no non-loopback IPv4 address"
elif ! sudo -n true 2>/dev/null; then why="no passwordless sudo"
fi
if [[ -n $why ]]; then
  if [[ ${ETHSWARM_REQUIRE_SYSTEMD_ANALYZE:-} == 1 ]]; then
    bad "probe: $why (required: ETHSWARM_REQUIRE_SYSTEMD_ANALYZE=1)"
  else
    echo "SKIP - probe: $why: the cl-chain unit's IP lines did not run under systemd"
  fi
else
  families=$(grep '^RestrictAddressFamilies=' default/ethswarm-chain.service || true)
  mapfile -t pair < <(grep -E '^IPAddress(Allow|Deny)=' default/ethswarm-chain.service || true)
  echo "# probe under cl-chain's: $families ${pair[*]}"
  if probe 127.0.0.1 "$families" "${pair[@]}"; then
    ok "probe: cl-chain's lines allow a TCP bind and connect on 127.0.0.1 (/metrics)"
  else
    bad "probe: cl-chain's lines refuse a TCP bind on 127.0.0.1 (/metrics)" "$out"
  fi
  if probe "$host_ip" "$families" "${pair[@]}"; then
    bad "probe: cl-chain's lines allow IP beyond loopback ($host_ip)" "$out"
  else
    ok "probe: cl-chain's lines refuse IP beyond loopback ($host_ip)"
  fi
  # The controls: the AF_UNIX-only line fails the loopback bind (socket() is refused), and
  # without the IP pair the non-loopback probe passes (the address is reachable).
  if probe 127.0.0.1 RestrictAddressFamilies=AF_UNIX "${pair[@]}"; then
    bad "control: AF_UNIX only allows the 127.0.0.1 bind" "$out"
  elif [[ $out == *"Address family not supported"* ]]; then
    ok "control: AF_UNIX only refuses the 127.0.0.1 bind (EAFNOSUPPORT)"
  else
    bad "control: AF_UNIX only fails the probe, but not on the address family" "$out"
  fi
  if probe "$host_ip" "$families"; then
    ok "control: without the IP pair the probe on $host_ip passes"
  else
    bad "control: without the IP pair the probe on $host_ip fails" "$out"
  fi
  # No AF_INET6 unless the ruling (LOOPBACK_ADDRESS_FAMILIES) grants it: socket() is refused.
  if [[ " ${families#*=} " != *" AF_INET6 "* ]]; then
    if probe ::1 "$families" "${pair[@]}"; then
      bad "probe: cl-chain's lines allow an AF_INET6 socket" "$out"
    elif [[ $out == *"Address family not supported"* ]]; then
      ok "probe: cl-chain's lines refuse an AF_INET6 socket (EAFNOSUPPORT)"
    else
      bad "probe: the ::1 probe fails, but not on the address family" "$out"
    fi
  fi
fi

echo "passed $passed, failed $failed"
((failed == 0))
