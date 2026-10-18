#!/usr/bin/env bash
# Offline tests for the probe systemd units. Run: bash ops/probe/tests/probe-units.test.sh
# The lint (lint_units.py) must pass the committed units in ops/probe/ and fail every copy that
# drops or weakens one rule: the unit's own User=, the node key only as the credential
# `nodekey` (and none for cl-chain), the `anchor-fetch --providers … --check` ExecStartPre=
# whose failure fails the start, and the hardening keys. No network, no root, no systemd.
# Needs python3. Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
probe=$(cd "$here/.." && pwd)
lint=(python3 -I "$here/lint_units.py")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0
ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() {
  failed=$((failed + 1)); echo "FAIL - $1"
  if [[ -n ${2:-} ]]; then printf '%s\n' "$2" | sed 's/^/       /'; fi
}

# No check here pipes into a reader that can exit early (grep -q, head, ...): under pipefail
# the writer can die of SIGPIPE and a match reads as "not found". The guard is tested by
# ops/tests/early-exit-guard.test.sh.
# shellcheck source=ops/tests/early-exit-guard.sh
. "$here/../../tests/early-exit-guard.sh"
if pipes=$(early_exit_pipes "$here/$(basename "${BASH_SOURCE[0]}")"); then
  ok "no check in this script pipes into an early-exiting reader"
else
  bad "a check in this script pipes into an early-exiting reader (read a here-string)" "$pipes"
fi

# expect <exit> <description> <pattern> <dir>: the lint's exit code on <dir>, and an output line
# matching the extended regex <pattern>.
expect() {
  local want=$1 desc=$2 pattern=$3 dir=$4 rc=0 out
  out=$("${lint[@]}" "$dir" 2>&1) || rc=$?
  if ((rc == want)) && grep -Eq -- "$pattern" <<<"$out"; then
    ok "$desc"
  else
    bad "$desc (exit $rc, want $want; want a line matching /$pattern/)" "$out"
  fi
}

# expect_without <description> <pattern> <dir>: the lint's output has no line matching <pattern>.
expect_without() {
  local desc=$1 pattern=$2 dir=$3 out
  out=$("${lint[@]}" "$dir" 2>&1) || true
  if grep -Eq -- "$pattern" <<<"$out"; then
    bad "$desc (a line matches /$pattern/)" "$out"
  else
    ok "$desc"
  fi
}

# variant <name>: a fresh copy of the committed units in $tmp/<name>, printed.
variant() {
  local dir="$tmp/$1"
  mkdir -p "$dir"
  cp "$probe"/ethswarm-*.service "$dir/"
  printf '%s' "$dir"
}

# drop <dir> <unit> <regex>: delete the lines matching <regex> from <dir>/<unit>.
drop() {
  grep -Ev -- "$3" "$1/$2" > "$1/$2.new" || true
  mv "$1/$2.new" "$1/$2"
}

# edit <dir> <unit> <awk program>: rewrite <dir>/<unit> through awk.
edit() {
  awk "$3" "$1/$2" > "$1/$2.new"
  mv "$1/$2.new" "$1/$2"
}

# append <dir> <unit> <line>: add <line> at the end of the [Service] section of <dir>/<unit>
# (just before [Install]), so it is the last assignment of its key.
append() {
  # Through the environment, not -v, which would interpret backslash escapes in <line>.
  APPEND_LINE=$3 awk '/^\[Install\]$/ { print ENVIRON["APPEND_LINE"] } { print }' "$1/$2" > "$1/$2.new"
  mv "$1/$2.new" "$1/$2"
}

# --- the committed units -----------------------------------------------------------------------

expect 0 "the committed units pass" "^ok: 3 units" "$probe"
for unit in ethswarm-p2p ethswarm-discv5 ethswarm-chain; do
  if grep -q "^User=$unit\$" "$probe/$unit.service"; then
    ok "$unit runs as its own user"
  else
    bad "$unit runs as its own user"
  fi
done

# --- every rule, broken once -------------------------------------------------------------------

d=$(variant missing-unit); rm "$d/ethswarm-discv5.service"
expect 1 "a missing unit fails" "ethswarm-discv5.service: missing" "$d"

for key in User NoNewPrivileges ProtectSystem PrivateTmp ProtectHome CapabilityBoundingSet \
  RestrictAddressFamilies ReadWritePaths StateDirectory ExecStartPre; do
  d=$(variant "no-$key"); drop "$d" ethswarm-p2p.service "^$key="
  expect 1 "no $key= fails" "ethswarm-p2p.service: .*$key" "$d"
done

d=$(variant no-credential); drop "$d" ethswarm-discv5.service "^LoadCredential="
expect 1 "a key unit without LoadCredential=nodekey fails" \
  "ethswarm-discv5.service: .*LoadCredential=nodekey" "$d"

d=$(variant other-credential)
edit "$d" ethswarm-p2p.service '{ sub(/^LoadCredential=nodekey:/, "LoadCredential=key:") } { print }'
expect 1 "a credential under another name fails" "ethswarm-p2p.service: .*LoadCredential=nodekey" "$d"

d=$(variant relative-credential)
edit "$d" ethswarm-p2p.service '{ sub(/^LoadCredential=nodekey:\//, "LoadCredential=nodekey:") } { print }'
expect 1 "a relative credential source fails" "ethswarm-p2p.service: .*absolute" "$d"

d=$(variant inline-credential); append "$d" ethswarm-p2p.service "SetCredential=nodekey:0102"
expect 1 "an inline SetCredential= fails" "ethswarm-p2p.service: .*SetCredential" "$d"

d=$(variant chain-key)
append "$d" ethswarm-chain.service "LoadCredential=nodekey:/etc/ethswarm/credentials/nodekey"
expect 1 "cl-chain with the node key fails" "ethswarm-chain.service: .*no node key" "$d"

d=$(variant key-path-in-env)
append "$d" ethswarm-p2p.service "Environment=NODE_KEY=/etc/ethswarm/credentials/nodekey"
expect 1 "the key's path anywhere but LoadCredential= fails" "ethswarm-p2p.service: .*Environment" "$d"

d=$(variant key-flag)
edit "$d" ethswarm-discv5.service '{ sub(/^ExecStart=\/usr\/local\/bin\/cl-discv5$/, "& --node-key /k") } { print }'
expect 1 "a node-key argument fails" "ethswarm-discv5.service: .*ExecStart" "$d"

d=$(variant root); edit "$d" ethswarm-p2p.service '{ sub(/^User=.*/, "User=root") } { print }'
expect 1 "User=root fails" "ethswarm-p2p.service: User=root" "$d"

d=$(variant shared-user)
edit "$d" ethswarm-discv5.service '{ sub(/^User=.*/, "User=ethswarm-p2p") } { print }'
expect 1 "another unit's user fails" "ethswarm-discv5.service: User=ethswarm-p2p" "$d"

d=$(variant dynamic-user); append "$d" ethswarm-chain.service "DynamicUser=yes"
expect 1 "DynamicUser=yes fails" "ethswarm-chain.service: .*DynamicUser" "$d"

d=$(variant ignored-check)
edit "$d" ethswarm-p2p.service '{ sub(/^ExecStartPre=\//, "ExecStartPre=-/") } { print }'
expect 1 "an ExecStartPre= whose failure is ignored fails" "ethswarm-p2p.service: .*prefix" "$d"

d=$(variant privileged-check)
edit "$d" ethswarm-chain.service '{ sub(/^ExecStartPre=\//, "ExecStartPre=+/") } { print }'
expect 1 "an ExecStartPre= with full privileges fails" "ethswarm-chain.service: .*prefix" "$d"

d=$(variant no-check-flag)
edit "$d" ethswarm-p2p.service '{ sub(/ --check$/, "") } { print }'
expect 1 "an anchor-fetch without --check fails" "ethswarm-p2p.service: .*--check" "$d"

d=$(variant no-providers)
edit "$d" ethswarm-p2p.service '{ sub(/--providers \$\{ANCHOR_PROVIDERS\} /, "") } { print }'
expect 1 "an anchor-fetch without --providers fails" "ethswarm-p2p.service: .*--providers" "$d"

d=$(variant check-writes)
edit "$d" ethswarm-p2p.service '{ sub(/ --check$/, " --check --out /var/lib/x") } { print }'
expect 1 "an anchor check with --out fails" "ethswarm-p2p.service: .*--out" "$d"

d=$(variant other-pre)
edit "$d" ethswarm-p2p.service '{ sub(/^ExecStartPre=\/usr\/local\/bin\/anchor-fetch/, "ExecStartPre=/usr/bin/true") } { print }'
expect 1 "an ExecStartPre= that is not anchor-fetch fails" "ethswarm-p2p.service: .*anchor-fetch" "$d"

d=$(variant capability); append "$d" ethswarm-p2p.service "CapabilityBoundingSet=CAP_NET_RAW"
expect 1 "a capability fails" "ethswarm-p2p.service: CapabilityBoundingSet" "$d"

d=$(variant ambient); append "$d" ethswarm-p2p.service "AmbientCapabilities=CAP_NET_BIND_SERVICE"
expect 1 "an ambient capability fails" "ethswarm-p2p.service: AmbientCapabilities" "$d"

d=$(variant packet); append "$d" ethswarm-discv5.service "RestrictAddressFamilies=AF_PACKET"
expect 1 "AF_PACKET fails" "ethswarm-discv5.service: RestrictAddressFamilies" "$d"

d=$(variant deny-list)
edit "$d" ethswarm-discv5.service '{ sub(/^RestrictAddressFamilies=.*/, "RestrictAddressFamilies=~AF_PACKET") } { print }'
expect 1 "a deny-list RestrictAddressFamilies= fails" "ethswarm-discv5.service: RestrictAddressFamilies" "$d"

d=$(variant writable-root); append "$d" ethswarm-chain.service "ReadWritePaths=/"
expect 1 "another ReadWritePaths= fails" "ethswarm-chain.service: ReadWritePaths" "$d"

d=$(variant protect-full)
edit "$d" ethswarm-chain.service '{ sub(/^ProtectSystem=.*/, "ProtectSystem=full") } { print }'
expect 1 "ProtectSystem=full fails" "ethswarm-chain.service: ProtectSystem" "$d"

d=$(variant no-new-privs-off)
edit "$d" ethswarm-chain.service '{ sub(/^NoNewPrivileges=.*/, "NoNewPrivileges=no") } { print }'
expect 1 "NoNewPrivileges=no fails" "ethswarm-chain.service: NoNewPrivileges" "$d"

d=$(variant home-read-only)
edit "$d" ethswarm-chain.service '{ sub(/^ProtectHome=.*/, "ProtectHome=read-only") } { print }'
expect 1 "ProtectHome=read-only fails" "ethswarm-chain.service: ProtectHome" "$d"

d=$(variant no-service); drop "$d" ethswarm-chain.service '^\[Service\]$'
expect 1 "a unit without [Service] fails" "ethswarm-chain.service: .*\[Service\]" "$d"

# --- every Exec*= line: no prefix that runs it with full privileges ----------------------------

for key in ExecStart ExecStartPre ExecStartPost ExecStop ExecStopPost ExecReload ExecCondition; do
  for prefix in "+" "!" "!!" "@+" "-+" ":!" "-!!" "@-:+"; do
    d=$(variant "priv-$key-$prefix"); append "$d" ethswarm-chain.service "$key=$prefix/usr/bin/true"
    expect 1 "$key=$prefix... fails" "ethswarm-chain.service: $key= .*prefix" "$d"
  done
done
# Forms systemd unquotes, unescapes or splits before it reads a prefix: refused outright,
# whatever they hide (the committed units use none of them).
for key in ExecStart ExecStartPre ExecStartPost ExecStop ExecStopPost ExecReload ExecCondition; do
  i=0
  for value in '"+/usr/bin/id"' "'+/usr/bin/id'" '/usr/bin/"true"' '\x2b/usr/bin/id' \
    '/usr/bin/true \; x' '/usr/bin/true ; +/usr/bin/id' '/usr/bin/true ; /usr/bin/id' \
    '|+/usr/bin/id' '|/usr/bin/true' '-|/usr/bin/true'; do
    i=$((i + 1))
    d=$(variant "form-$key-$i"); append "$d" ethswarm-chain.service "$key=$value"
    expect 1 "$key=$value fails" "ethswarm-chain.service: ($key= |line [0-9]+: )" "$d"
  done
done
d=$(variant quoted-check)
edit "$d" ethswarm-p2p.service '{ sub(/\$\{ANCHOR_PROVIDERS\}/, "\"${ANCHOR_PROVIDERS}\"") } { print }'
expect 1 "a quoted anchor check fails" "ethswarm-p2p.service: ExecStartPre= " "$d"

# The reviewer's reproductions of the quoted, chained and piped bypasses.
demo=${PROBE_LINT_DEMO:-}
if [[ -n $demo && -d $demo ]]; then
  for dir in "$demo"/*/; do
    expect 1 "reproduction $(basename "$dir") fails" "Exec(Start|Stop)Post= " "$dir"
  done
fi

d=$(variant priv-main)
edit "$d" ethswarm-chain.service '{ sub(/^ExecStart=\//, "ExecStart=+/") } { print }'
expect 1 "ExecStart=+ on the service itself fails" "ethswarm-chain.service: ExecStart= .*prefix" "$d"
d=$(variant ignored-post); append "$d" ethswarm-p2p.service "ExecStopPost=-/usr/bin/true"
expect 1 "an ExecStopPost= (not in the allow-list) fails" "ethswarm-p2p.service: ExecStopPost= .*allow-list" "$d"

# --- the anchor check's arguments: an allow-list, so no help page can pass for a check --------

for extra in "--help" "-h" "--allow-insecure-http" "--config /etc/x.toml" "--out /x" "--bogus" \
  "--quiet"; do
  d=$(variant "arg-${extra// /_}")
  edit "$d" ethswarm-p2p.service "{ sub(/ --check\$/, \" --check $extra\") } { print }"
  expect 1 "an anchor check with $extra fails" "ethswarm-p2p.service: .*anchor-fetch" "$d"
done
d=$(variant providers-option)
edit "$d" ethswarm-p2p.service '{ sub(/--providers \$\{ANCHOR_PROVIDERS\}/, "--providers --help") } { print }'
expect 1 "--providers followed by an option fails" "ethswarm-p2p.service: .*--providers" "$d"
d=$(variant scratch)
edit "$d" ethswarm-p2p.service '{ sub(/ --check$/, " --check --scratch /tmp") } { print }'
expect 1 "an added --scratch fails (the unit is pinned)" "ethswarm-p2p.service: line [0-9]+: expected" "$d"
d=$(variant relative-scratch)
edit "$d" ethswarm-p2p.service '{ sub(/ --check$/, " --check --scratch tmp") } { print }'
expect 1 "a relative --scratch fails" "ethswarm-p2p.service: .*--scratch" "$d"

# --- start timeout and restart limits -----------------------------------------------------------

for key in TimeoutStartSec RestartPreventExitStatus RestartSec StartLimitIntervalSec StartLimitBurst; do
  d=$(variant "no-$key"); drop "$d" ethswarm-discv5.service "^$key="
  expect 1 "no $key= fails" "ethswarm-discv5.service: .*$key" "$d"
done
for value in 90s 1h infinity 0 "1h 7min"; do
  d=$(variant "timeout-${value// /_}"); append "$d" ethswarm-p2p.service "TimeoutStartSec=$value"
  expect 1 "TimeoutStartSec=$value fails" "ethswarm-p2p.service: TimeoutStartSec" "$d"
done
d=$(variant timeout-long); append "$d" ethswarm-p2p.service "TimeoutStartSec=1h 10min"
expect 1 "an added TimeoutStartSec= fails (the unit is pinned)" "ethswarm-p2p.service: line [0-9]+: " "$d"
for value in "2" "1 2" "" "2 64"; do
  d=$(variant "prevent-${value// /_}"); append "$d" ethswarm-p2p.service "RestartPreventExitStatus="
  append "$d" ethswarm-p2p.service "RestartPreventExitStatus=$value"
  expect 1 "RestartPreventExitStatus= reset to \"$value\" fails" "ethswarm-p2p.service: RestartPreventExitStatus" "$d"
done
d=$(variant restart-fast); append "$d" ethswarm-chain.service "RestartSec=30s"
expect 1 "RestartSec=30s fails" "ethswarm-chain.service: RestartSec" "$d"
d=$(variant burst-high)
edit "$d" ethswarm-chain.service '{ sub(/^StartLimitBurst=.*/, "StartLimitBurst=100") } { print }'
expect 1 "StartLimitBurst=100 fails" "ethswarm-chain.service: .*StartLimitBurst" "$d"
d=$(variant interval-short)
edit "$d" ethswarm-chain.service '{ sub(/^StartLimitIntervalSec=.*/, "StartLimitIntervalSec=10s") } { print }'
expect 1 "StartLimitIntervalSec=10s fails" "ethswarm-chain.service: .*StartLimitIntervalSec" "$d"
d=$(variant limit-in-service); drop "$d" ethswarm-chain.service "^StartLimitBurst="
append "$d" ethswarm-chain.service "StartLimitBurst=3"
expect 1 "StartLimitBurst= outside [Unit] fails" "ethswarm-chain.service: StartLimitBurst" "$d"
# Exit codes only: a signal name (an OOM kill is SIGKILL) would turn that kill into a stop.
for value in SIGKILL KILL SIGTERM; do
  d=$(variant "prevent-signal-$value"); append "$d" ethswarm-p2p.service "RestartPreventExitStatus=$value"
  expect 1 "RestartPreventExitStatus=$value fails" "ethswarm-p2p.service: RestartPreventExitStatus=.*signal" "$d"
done

# --- the memory ceiling: a finite MemoryMax=, no MemoryHigh=, no swap, an OOM kill restarts ----

# cl-p2p's ceiling sits above its transport's budgets (README: about 6.05 GiB), 4G for the rest.
for case in ethswarm-p2p=7G ethswarm-discv5=4G ethswarm-chain=4G; do
  unit=${case%%=*}
  if grep -qx -- "MemoryMax=${case#*=}" "$probe/$unit.service"; then
    ok "$unit has MemoryMax=${case#*=}"
  else
    bad "$unit has MemoryMax=${case#*=}"
  fi
done
for unit in ethswarm-p2p ethswarm-discv5 ethswarm-chain; do
  if grep -q '^MemoryHigh=' "$probe/$unit.service"; then
    bad "$unit sets no MemoryHigh= (without swap it only throttles)"
  else
    ok "$unit sets no MemoryHigh= (without swap it only throttles)"
  fi
  for key in MemoryMax MemorySwapMax OOMPolicy; do
    d=$(variant "mem-drop-$key-$unit"); drop "$d" "$unit.service" "^$key="
    expect 1 "$unit without $key= fails" "^$unit.service: missing $key=" "$d"
  done
  for line in MemoryMax=infinity MemoryMax= MemoryMax=50% MemoryMax=0 MemoryMax=4Q \
    MemorySwapMax=1G MemorySwapMax=infinity MemorySwapMax= OOMPolicy=continue OOMPolicy=; do
    key=${line%%=*}
    d=$(variant "mem-weak-$line-$unit"); append "$d" "$unit.service" "$line"
    expect 1 "$unit with a later $line fails" "^$unit.service: $key=[^ ]*, want" "$d"
  done
  # MemoryHigh= is refused outright, wherever it sits and whatever its value: without swap,
  # past it the kernel only throttles, and a throttled probe stalls instead of being killed.
  for line in MemoryHigh=3G MemoryHigh=infinity MemoryHigh=; do
    d=$(variant "mem-high-$line-$unit"); append "$d" "$unit.service" "$line"
    expect 1 "$unit with $line fails (allow-list)" \
      "^$unit.service: MemoryHigh= is not in the \[Service\] allow-list" "$d"
    expect 1 "$unit with $line fails (no throttling)" "^$unit.service: MemoryHigh= is set.*throttle" "$d"
  done
  # The README's table states the unit's own ceiling.
  max=$(sed -n 's/^MemoryMax=//p' "$probe/$unit.service")
  if grep -qF -- "| \`$unit.service\` | $max |" "$probe/README.md"; then
    ok "the README states $unit's MemoryMax=$max"
  else
    bad "the README states $unit's MemoryMax=$max"
  fi
  d=$(variant "mem-high-before-max-$unit")
  edit "$d" "$unit.service" '/^MemoryMax=/ { print "MemoryHigh=1G" } { print }'
  expect 1 "$unit with MemoryHigh= before MemoryMax= fails" "^$unit.service: line [0-9]+: expected" "$d"
done

# Sizes are digits and an optional K, M, G or T suffix, nothing else; a value too large for
# systemd (2^64 - 1 bytes is its infinity) is a finding, never a traceback that hides the rest.
nines=$(python3 -I -c 'print("9" * 309)')
long=$(python3 -I -c 'print("1" * 2000)')
i=0
for value in "$nines" "${nines}G" "$long" 000000000000000000004G 4.5G 1e3G 1E3 -1G +4G 0x10G 4g 4GB 1P 1E 18446744073709551615 \
  16777216T 18446744073709551616 "4 G"; do
  i=$((i + 1))
  d=$(variant "mem-size-$i"); append "$d" ethswarm-chain.service "MemoryMax=$value"
  # And a second, unrelated finding in another unit: it must still be reported.
  edit "$d" ethswarm-p2p.service '{ sub(/^User=.*/, "User=root") } { print }'
  expect 1 "MemoryMax=${value:0:24} is a finding" "^ethswarm-chain.service: MemoryMax=.*, want a finite size" "$d"
  expect 1 "MemoryMax=${value:0:24} leaves the other findings" "^ethswarm-p2p.service: User=root" "$d"
  expect_without "MemoryMax=${value:0:24} raises no traceback" "Traceback|Error" "$d"
done
for value in 1 4096 512K 64M 4G 1T 16777215T; do
  d=$(variant "mem-size-ok-$value"); append "$d" ethswarm-chain.service "MemoryMax=$value"
  expect_without "MemoryMax=$value is a size" "MemoryMax=.*want" "$d"
done

# --- the full hardening set: removed, reset or overridden by a later line ------------------------

weak() {
  case $1 in
    ProtectSystem) echo full ;;
    ProtectProc) echo default ;;
    ProcSubset) echo all ;;
    SystemCallArchitectures) echo "native x86" ;;
    UMask) echo 0022 ;;
    *) echo no ;;
  esac
}
for key in UMask PrivateDevices RestrictNamespaces RestrictRealtime RestrictSUIDSGID \
  LockPersonality MemoryDenyWriteExecute ProtectKernelTunables ProtectKernelModules \
  ProtectKernelLogs ProtectControlGroups ProtectClock ProtectHostname ProtectProc ProcSubset \
  SystemCallArchitectures SystemCallFilter NoNewPrivileges ProtectSystem ProtectHome PrivateTmp; do
  d=$(variant "hard-drop-$key"); drop "$d" ethswarm-discv5.service "^$key="
  expect 1 "no $key= fails" "ethswarm-discv5.service: .*$key" "$d"
  d=$(variant "hard-weak-$key"); append "$d" ethswarm-discv5.service "$key=$(weak "$key")"
  expect 1 "a later $key=$(weak "$key") fails" "ethswarm-discv5.service: $key" "$d"
  d=$(variant "hard-reset-$key"); append "$d" ethswarm-discv5.service "$key="
  expect 1 "a later empty $key= fails" "ethswarm-discv5.service: $key" "$d"
done
d=$(variant syscall-allow); append "$d" ethswarm-discv5.service "SystemCallFilter=@privileged"
expect 1 "SystemCallFilter=@privileged added fails" "ethswarm-discv5.service: SystemCallFilter" "$d"
d=$(variant syscall-reset-same)
append "$d" ethswarm-discv5.service "SystemCallFilter="
append "$d" ethswarm-discv5.service "SystemCallFilter=@system-service"
append "$d" ethswarm-discv5.service "SystemCallFilter=~@privileged"
expect 1 "a reset and the same filter again fails (the unit is pinned)" "ethswarm-discv5.service: line [0-9]+: " "$d"

# A continuation line is refused: a unit holds no backslash at all.
d=$(variant continued)
edit "$d" ethswarm-p2p.service '{ sub(/^ExecStartPre=\/usr\/local\/bin\/anchor-fetch /, "ExecStartPre=/usr/local/bin/anchor-fetch \\\n  ") } { print }'
expect 1 "a continued ExecStartPre= fails" "ethswarm-p2p.service: line [0-9]+: .*backslash" "$d"

# --- the bytes of a unit file: printable ASCII, tab and newline only, no backslash -------------

# raw <dir> <unit> <before> <text>: insert <text> (Python escapes, decoded to bytes) before the
# first line equal to <before>, or, with <before> = "=User", in place of the User= line.
raw() {
  python3 -I - "$1/$2" "$3" "$4" <<'PY'
import sys
path, before, text = sys.argv[1], sys.argv[2], sys.argv[3]
blob = text.encode("ascii").decode("unicode_escape").encode("latin-1")
lines = open(path, "rb").read().split(b"\n")
out = []
for line in lines:
    if before == "=User" and line.startswith(b"User="):
        out.append(blob.replace(b"{user}", line[len(b"User="):]))
        continue
    if line == before.encode():
        out.append(blob)
    out.append(line)
open(path, "wb").write(b"\n".join(out))
PY
}

# The reviewer's reproductions (confirmed in systemd 257), on every unit.
for unit in ethswarm-p2p ethswarm-discv5 ethswarm-chain; do
  for case in \
    'a-double-backslash|[Install]|Environment=A=b\\\\\nExecStartPost=+/usr/bin/id\n' \
    'b-backslash-space|[Install]|Environment=A=b\\ \nExecStartPost=+/usr/bin/id\n' \
    'c-nul|[Install]|Environment=A=b\x00ExecStartPost=+/usr/bin/id\n' \
    'd-gate-reset|[Install]|Environment=A=b\\\\\nExecStartPre=\n' \
    'e-nul-comment|[Install]|# ignored\x00ExecStopPost=+/usr/bin/id\n' \
    'f-u2028|[Service]|#\xe2\x80\xa8[Install]\nExecStartPre=+/usr/bin/id\n#\xe2\x80\xa8[Service]\n' \
    'g-vt-user|=User|#\x0bUser={user}' \
    'h-nul-value|[Install]|SyslogIdentifier=x\x00ExecStartPost=+/usr/bin/id\n'; do
    name=${case%%|*}; rest=${case#*|}; before=${rest%%|*}; text=${rest#*|}
    d=$(variant "repro-$name-$unit"); raw "$d" "$unit.service" "$before" "$text"
    expect 1 "reproduction $name in $unit fails" "$unit.service: line [0-9]+: " "$d"
  done
done

for case in 'NUL|\x00' 'CR|\r' 'VT|\x0b' 'FF|\x0c' 'U+2028|\xe2\x80\xa8' 'Latin-1|\xe9' 'DEL|\x7f'; do
  name=${case%%|*}; byte=${case#*|}
  d=$(variant "byte-$name"); raw "$d" ethswarm-discv5.service "[Install]" "# a comment $byte here\n"
  expect 1 "a $name byte in a comment fails" "ethswarm-discv5.service: line [0-9]+: .*byte" "$d"
done
d=$(variant tab-ok); raw "$d" ethswarm-discv5.service "[Install]" "#\tan indented comment\n"
expect 0 "a tab passes" "^ok: 3 units" "$d"
d=$(variant backslash-comment); raw "$d" ethswarm-chain.service "[Install]" "# C:\\\\temp\n"
expect 1 "a backslash in a comment fails" "ethswarm-chain.service: line [0-9]+: .*backslash" "$d"
d=$(variant backslash-value); raw "$d" ethswarm-chain.service "[Install]" "SyslogIdentifier=a\\\\b\n"
expect 1 "a backslash in a value fails" "ethswarm-chain.service: line [0-9]+: .*backslash" "$d"

# --- sizes: no line of 2048 bytes or more, which an older systemd would read as two lines -------

# comment <dir> <unit> <bytes>: append one `#` comment line of exactly <bytes> bytes (newline not
# counted) to <dir>/<unit>.
comment() {
  python3 -I - "$1/$2" "$3" <<'PY'
import sys
path, size = sys.argv[1], int(sys.argv[2])
with open(path, "ab") as f:
    f.write(b"#" + b"x" * (size - 1) + b"\n")
PY
}
# fill <dir> <unit> <bytes>: append comment lines of at most 1024 bytes (newline included) so
# that <dir>/<unit> is exactly <bytes> long.
fill() {
  python3 -I - "$1/$2" "$3" <<'PY'
import os, sys
path, size = sys.argv[1], int(sys.argv[2])
left = size - os.path.getsize(path)
with open(path, "ab") as f:
    while left > 0:
        # A line of `line` bytes, newline included; never leave a 1-byte rest.
        line = min(left, 1024)
        if left - line == 1:
            line -= 1
        f.write(b"\n" if line == 1 else b"#" + b"x" * (line - 2) + b"\n")
        left -= line
PY
}
d=$(variant line-below-cap); comment "$d" ethswarm-p2p.service 2047
expect 0 "a comment line of 2047 bytes passes" "^ok: 3 units" "$d"
for size in 2048 2049 4096 1048576 1048577; do
  d=$(variant "line-$size"); comment "$d" ethswarm-chain.service "$size"
  expect 1 "a comment line of $size bytes fails" \
    "ethswarm-chain.service: line [0-9]+: $size bytes, over the 2047-byte line cap" "$d"
done
# The hidden setting a split would expose: the bytes from 2048 on, read as a line of their own.
d=$(variant line-split)
python3 -I - "$d/ethswarm-p2p.service" <<'PY'
import sys
with open(sys.argv[1], "ab") as f:
    f.write(b"#" + b"x" * 2046 + b"ExecStartPost=+/usr/bin/id\n")
PY
expect 1 "a comment hiding a setting past byte 2047 fails" \
  "ethswarm-p2p.service: line [0-9]+: 2073 bytes, over the 2047-byte line cap" "$d"
d=$(variant file-at-cap); fill "$d" ethswarm-discv5.service 65536
expect 0 "a unit of exactly 65536 bytes passes" "^ok: 3 units" "$d"
d=$(variant file-over-cap); fill "$d" ethswarm-discv5.service 65537
expect 1 "a unit of 65537 bytes fails" \
  "ethswarm-discv5.service: 65537 bytes, over the 65536-byte cap" "$d"
expect_without "a unit of 65537 bytes has no long line" "line [0-9]+: [0-9]+ bytes" "$d"

# Drop-ins would change the units behind the lint's back: none may sit next to them.
for dropin in ethswarm-p2p.service.d ethswarm-chain.service.d other.d; do
  d=$(variant "dropin-$dropin"); mkdir "$d/$dropin"
  expect 1 "a drop-in directory $dropin fails" "$dropin: .*drop-in" "$d"
done

# Only the three pinned units: any other *.service next to them would be installed unlinted.
for extra in ethswarm-extra.service ethswarm-p2p.service.bak.service other.service; do
  d=$(variant "extra-$extra"); cp "$d/ethswarm-chain.service" "$d/$extra"
  expect 1 "an extra unit $extra fails" "^$extra: not one of the 3 probe units" "$d"
done
d=$(variant extra-other-file); printf 'notes\n' > "$d/NOTES.md"
expect 0 "a file that is not a unit passes" "^ok: 3 units" "$d"

# --- the README installs exactly the three units, by name, and nothing else into systemd -------

# The one line that puts units on the host: the three by name, never a glob, which would install
# an unlinted one.
INSTALL_LINE='install -m 0644 ops/probe/ethswarm-p2p.service ops/probe/ethswarm-discv5.service ops/probe/ethswarm-chain.service /etc/systemd/system/'
# A line naming /etc/systemd (a `cd` there) or any .../systemd/system unit directory (/etc, /run,
# /lib, /usr/lib, /usr/local/lib), however its slashes are doubled or dotted. Fail-closed: any
# such line but the pinned one is refused, whatever command it runs.
UNIT_DIR='/etc/+(\./+)*systemd([^-.a-z]|$)|systemd/+(\./+)*system([^-.a-z]|$)'
# A line naming a systemd path (`/systemd` or `systemd/`) that holds `..` anywhere: a parent
# alias (`/usr/lib/systemd/user/../system/`, or a `cd` into one and a `../system` after) can
# reach a unit directory without spelling it, so, fail-closed, no such line is resolved; it is
# refused.
SYSTEMD_DOTDOT='(/systemd|systemd/).*\.\.|\.\..*(/systemd|systemd/)'

# readme_findings <file>: one line per README line that would write a unit onto the host other
# than through INSTALL_LINE (UNIT_DIR or SYSTEMD_DOTDOT), and one if INSTALL_LINE is not there
# exactly once. Empty: it holds.
readme_findings() {
  local n=0 number line
  while IFS= read -r line || [[ -n $line ]]; do
    number=${line%%:*}; line=${line#*:}
    if [[ $line == "$INSTALL_LINE" ]]; then
      n=$((n + 1))
    else
      printf 'README line %s names a systemd unit directory: %s\n' "$number" "$line"
    fi
  done < <(grep -nE -e "$UNIT_DIR" -e "$SYSTEMD_DOTDOT" -- "$1" || true)
  if ((n != 1)); then
    printf 'README holds the pinned install line %d times, want once\n' "$n"
  fi
}

# expect_readme <want: ok|refused> <description> <file>
expect_readme() {
  local out
  out=$(readme_findings "$3")
  if [[ $1 == ok && -z $out ]] || [[ $1 == refused && -n $out ]]; then
    ok "$2"
  else
    bad "$2 (want $1)" "${out:-(no finding)}"
  fi
}

expect_readme ok "the README installs the three units by name, and nothing else" "$probe/README.md"
# readme_variant <name> <line>: the README with <line> added after its pinned install line.
readme_variant() {
  local file="$tmp/readme-$1.md"
  LINE=$2 PIN=$INSTALL_LINE awk '{ print } $0 == ENVIRON["PIN"] { print ENVIRON["LINE"] }' \
    "$probe/README.md" > "$file"
  printf '%s' "$file"
}
i=0
for line in \
  'cp ops/probe/*.service /etc/systemd/system/' \
  'cp ops/probe/ethswarm-p2p.service /etc/systemd/system' \
  'sudo install -m 0644 ops/probe/ethswarm-p2p.service ops/probe/ethswarm-discv5.service ops/probe/ethswarm-chain.service /etc/systemd/system/' \
  "  $INSTALL_LINE" \
  'ln -s "$PWD"/ops/probe/ethswarm-p2p.service /etc/systemd/system/' \
  'rsync -a ops/probe/ /etc/systemd/system/' \
  'install -m 0644 ops/probe/extra.service /etc//systemd/./system/' \
  'cat ops/probe/ethswarm-p2p.service > /etc/systemd/system/x.service' \
  'cp ops/probe/*.service /run/systemd/system/' \
  'cp ops/probe/*.service /usr/lib/systemd/system/' \
  'cd /etc/systemd && cp ../../ops/probe/*.service system/' \
  '- `cp ops/probe/*.service /etc/systemd/system/` also works' \
  'cp x.service /usr/lib/systemd/user/../system/' \
  'cp x.service /usr/lib/systemd/user/../system' \
  'cp x.service /lib/systemd//user/./../system/' \
  'cp x.service /run/systemd/transient/../system/' \
  'cp x.service /usr/local/lib/systemd/user/../../systemd/system/' \
  'install -m 0644 x.service /usr/lib/systemd/user/.././system/' \
  'cd /usr/lib/systemd/user && cp x.service ../system/' \
  'cp x.service ../../usr/lib/systemd/user/../system/'; do
  i=$((i + 1))
  expect_readme refused "a README line '$line' is refused" "$(readme_variant "add-$i" "$line")"
done
d=$tmp/readme-twice.md; { cat "$probe/README.md"; printf '%s\n' "$INSTALL_LINE"; } > "$d"
expect_readme refused "the pinned install line twice is refused" "$d"
d=$tmp/readme-none.md; grep -vxF -- "$INSTALL_LINE" "$probe/README.md" > "$d" || true
expect_readme refused "a README without the pinned install line is refused" "$d"
for line in 'systemd-analyze verify ops/probe/*.service' 'see systemd.exec(5) and systemd-system.conf(5)' \
  'cd ../.. && cargo build --release' 'systemd-analyze verify ../probe/ethswarm-p2p.service'; do
  i=$((i + 1))
  expect_readme ok "a README line '$line' passes" "$(readme_variant "add-$i" "$line")"
done

# --- a key allow-list per section: only what the committed units use ----------------------------

for case in 'PermissionsStartOnly=yes' 'SuccessExitStatus=1 2' 'ExecCondition=/usr/bin/true' \
  'SupplementaryGroups=root' 'DynamicUser=no' 'ExecStartPost=/usr/bin/true' 'Environment=A=b' \
  'NotARealKey=1' 'KillMode=none' 'TimeoutSec=infinity'; do
  key=${case%%=*}
  for unit in ethswarm-p2p ethswarm-discv5 ethswarm-chain; do
    d=$(variant "allow-$key-$unit"); append "$d" "$unit.service" "$case"
    expect 1 "$case in $unit fails" "$unit.service: $key= is not in the \[Service\] allow-list" "$d"
  done
done
d=$(variant unit-key)
edit "$d" ethswarm-chain.service '{ print } /^\[Unit\]$/ { print "OnFailure=x.service" }'
expect 1 "an unknown [Unit] key fails" "ethswarm-chain.service: OnFailure= is not in the \[Unit\] allow-list" "$d"
d=$(variant install-key); printf 'Alias=x.service\n' >> "$d/ethswarm-chain.service"
expect 1 "an unknown [Install] key fails" "ethswarm-chain.service: Alias= is not in the \[Install\] allow-list" "$d"
d=$(variant other-section); printf '[Socket]\nListenStream=1\n' >> "$d/ethswarm-chain.service"
expect 1 "an unknown section fails" "ethswarm-chain.service: \[Socket\] is not an allowed section" "$d"

for group in root ethswarm-chain wheel; do
  d=$(variant "group-$group"); edit "$d" ethswarm-p2p.service "{ sub(/^Group=.*/, \"Group=$group\") } { print }"
  expect 1 "Group=$group for ethswarm-p2p fails" "ethswarm-p2p.service: Group=$group" "$d"
done
d=$(variant no-group); drop "$d" ethswarm-discv5.service "^Group="
expect 1 "no Group= fails" "ethswarm-discv5.service: .*Group=" "$d"

for value in y t Yes TRUE On; do
  d=$(variant "true-$value"); append "$d" ethswarm-chain.service "PrivateTmp=$value"
  expect 1 "an added PrivateTmp=$value fails (the unit is pinned)" "ethswarm-chain.service: line [0-9]+: " "$d"
done

for providers in '$P' '$ANCHOR_PROVIDERS' 'x$P' '${A}$B' '$$' '${A' '${A-b}'; do
  d=$(variant "dollar-${#providers}-$RANDOM")
  PROVIDERS=$providers awk '{ sub(/--providers \$\{ANCHOR_PROVIDERS\}/, "--providers " ENVIRON["PROVIDERS"]) } { print }' \
    "$d/ethswarm-p2p.service" > "$d/x" && mv "$d/x" "$d/ethswarm-p2p.service"
  expect 1 "--providers $providers fails" "ethswarm-p2p.service: .*braced" "$d"
done

# --- every unit pinned line for line: only Description= may differ -----------------------------

# set_line <dir> <unit> <key> <new line>: replace the first <key>= line with <new line>.
set_line() {
  KEY=$3 LINE=$4 awk 'index($0, ENVIRON["KEY"] "=") == 1 && !done { print ENVIRON["LINE"]; done = 1; next } { print }' \
    "$1/$2" > "$1/$2.new"
  mv "$1/$2.new" "$1/$2"
}

for unit in ethswarm-p2p ethswarm-discv5 ethswarm-chain; do
  svc=${unit#ethswarm-}
  for line in \
    "ExecStart=/usr/local/bin/cl-$svc --debug" "ExecStart=/tmp/cl-$svc" "Type=exec" "Restart=always" \
    "StateDirectoryMode=0755" "RuntimeDirectoryMode=0755" \
    "RuntimeDirectory=ethswarm/cl-$svc systemd/system" \
    "Wants=network-online.target debug-shell.service" "After=network-online.target debug-shell.service" \
    "EnvironmentFile=/etc/ethswarm/credentials/nodekey" "EnvironmentFile=-/etc/ethswarm/anchor-check.env" \
    "ProtectSystem=STRICT" "ProtectProc=INVISIBLE" "ProcSubset=PID" "PrivateTmp=true" \
    "SystemCallFilter=@system-service ~@privileged" \
    "ExecStartPre=@/usr/local/bin/anchor-fetch --providers check-log --check" \
    "ExecStartPre=/var/lib/$unit/anchor-fetch --providers \${ANCHOR_PROVIDERS} --check" \
    "User= $unit" "User =$unit" "RestartSec=300s" "TimeoutStartSec=4200"; do
    key=${line%%=*}; key=${key% }
    d=$(variant "pin-$unit-$RANDOM"); set_line "$d" "$unit.service" "$key" "$line"
    expect 1 "$unit with $line fails" "$unit.service: line [0-9]+: expected" "$d"
  done
done
for unit in ethswarm-p2p ethswarm-discv5; do
  d=$(variant "pin-cred-$unit"); set_line "$d" "$unit.service" LoadCredential "LoadCredential=nodekey:/etc/shadow"
  expect 1 "$unit with another credential source fails" "$unit.service: line [0-9]+: expected" "$d"
  d=$(variant "pin-cred2-$unit")
  set_line "$d" "$unit.service" LoadCredential "LoadCredential=nodekey:/etc/ethswarm/credentials//nodekey"
  expect 1 "$unit with an aliased credential path fails" "$unit.service: line [0-9]+: expected" "$d"
done
d=$(variant pin-extra-pre); append "$d" ethswarm-p2p.service "ExecStartPre=/usr/bin/od -An -tx1 %d/nodekey"
expect 1 "an extra ExecStartPre= fails" "ethswarm-p2p.service: line [0-9]+: " "$d"
d=$(variant pin-indent); set_line "$d" ethswarm-chain.service User "  User=ethswarm-chain"
expect 1 "an indented line fails" "ethswarm-chain.service: line [0-9]+: expected" "$d"

d=$(variant pin-swap)
awk '/^User=/ { u = $0; next } /^Group=/ { print; print u; next } { print }' "$d/ethswarm-p2p.service" \
  > "$d/x" && mv "$d/x" "$d/ethswarm-p2p.service"
expect 1 "User= and Group= swapped fails" "ethswarm-p2p.service: line [0-9]+: expected" "$d"
d=$(variant pin-install-first)
awk '/^\[Install\]$/ { exit } { print }' "$probe/ethswarm-chain.service" > "$d/body"
{ printf '[Install]\nWantedBy=multi-user.target\n\n'; cat "$d/body"; } > "$d/ethswarm-chain.service"
rm "$d/body"
expect 1 "[Install] moved first fails" "ethswarm-chain.service: line [0-9]+: expected" "$d"
d=$(variant pin-truncated)
awk '/^\[Install\]$/ { exit } { print }' "$probe/ethswarm-discv5.service" > "$d/x" && mv "$d/x" "$d/ethswarm-discv5.service"
expect 1 "a unit without its [Install] tail fails" "ethswarm-discv5.service: .*missing" "$d"

for unit in ethswarm-p2p ethswarm-discv5 ethswarm-chain; do
  d=$(variant "pin-description-$unit"); set_line "$d" "$unit.service" Description "Description=Renamed for the host"
  expect 0 "$unit with another Description= passes" "^ok: 3 units" "$d"
done
d=$(variant pin-comments)
awk '{ print } /^User=/ { print "# a reviewer note"; print "" }' "$probe/ethswarm-chain.service" > "$d/x" \
  && mv "$d/x" "$d/ethswarm-chain.service"
expect 0 "an added comment and blank line pass" "^ok: 3 units" "$d"

# The reviewer's own reproduction directories, when given.
repro=${PROBE_LINT_REPRO:-}
if [[ -n $repro && -d $repro ]]; then
  for dir in "$repro"/*/; do
    case $(basename "$dir") in base) continue ;; esac
    expect 1 "reproduction dir $(basename "$dir") fails" "\\.service: " "$dir"
  done
fi

expect 2 "no directory is a usage error" "usage" "$tmp/nowhere"

echo
echo "$passed passed, $failed failed"
((failed == 0))
