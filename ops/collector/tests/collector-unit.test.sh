#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted ${VAR}s are the unit's own text, matched literally
# Offline tests for ops/collector. Run: bash ops/collector/tests/collector-unit.test.sh
# Checks the systemd template ethswarm-collector@.service: every hardening line, a system user
# per instance, the required per-instance EnvironmentFile, a state directory per instance, the
# reference URL read from a file (never in argv), and no node URL of its own. Runs its
# ExecStartPre guard the way systemd would, env file values overriding systemd's own
# (STATE_DIRECTORY). Checks each example env file (its network, its instance's state directory,
# known keys only) and URL file (loopback on the ref-node default beacon API port: Sepolia 5052,
# Hoodi 5053, cross-checked against BEACON_API_PORT in ops/ref-node's example env files), and
# the README's migration from the single-network unit. Each check is also run on broken
# copies, which must fail. No network, no root, no systemd. Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
collector=$(cd "$here/.." && pwd)
repo=$(cd "$collector/../.." && pwd)
unit="$collector/ethswarm-collector@.service"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"   # a stray relative write lands in the temp dir, never in the checkout

# The ref-node defaults: each network's beacon API port on a host that runs both.
SEPOLIA_PORT=5052
HOODI_PORT=5053

passed=0 failed=0

ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() {
  failed=$((failed + 1)); echo "FAIL - $1"
  if [[ -n ${2:-} ]]; then printf '%s\n' "$2" | sed 's/^/       /'; fi
}

# The [Service] lines the unit must carry exactly, and no other value for their keys.
HARDENING='UMask=0027
StateDirectoryMode=0750
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
User=ethswarm-collector-%i
Group=ethswarm-collector-%i
EnvironmentFile=/etc/ethswarm/collector-%i.env
StateDirectory=ethswarm-collector/%i
ReadWritePaths=/var/lib/ethswarm-collector/%i'

# service_lines FILE: the [Service] settings, one per line, with `\` continuations joined and
# comments and blank lines dropped.
service_lines() {
  awk '
    cont == "" && /^[ \t]*[#;]/ { next }
    {
      line = cont $0
      if (line ~ /\\$/) { sub(/\\$/, " ", line); cont = line; next }
      cont = ""
      if (line ~ /^[ \t]*$/) next
      if (line ~ /^\[/) { section = line; next }
      if (section == "[Service]") print line
    }
  ' "$1"
}

# check_unit FILE: prints each problem; fails if there is one.
check_unit() {
  local file=$1 lines problems="" want key line exec
  lines=$(service_lines "$file")
  while IFS= read -r want; do
    if ! printf '%s\n' "$lines" | grep -Fxq -- "$want"; then
      problems+="missing: $want"$'\n'
    fi
    key=${want%%=*}
    while IFS= read -r line; do
      if [[ -n $line ]] && ! printf '%s\n' "$HARDENING" | grep -Fxq -- "$line"; then
        problems+="another value for $key: $line"$'\n'
      fi
    done <<<"$(printf '%s\n' "$lines" | grep -E "^$key=" || true)"
  done <<<"$HARDENING"
  # The env file and the URL file are the only sources of settings: no Environment= of the
  # unit's own, no URL, address or port in any setting, and the URL never in argv.
  if printf '%s\n' "$lines" | grep -Eq '^Environment='; then
    problems+="sets Environment= (settings belong in the env file)"$'\n'
  fi
  if printf '%s\n' "$lines" | grep -Eiq '://|127\.0\.0\.1|localhost:|\[::1\]|:505[0-9]'; then
    problems+="a hardcoded URL, address or port"$'\n'
  fi
  if printf '%s\n' "$lines" | grep -Eq 'REFERENCE_API_URL|--url([ =]|$)'; then
    problems+="the URL goes into argv (want --url-file)"$'\n'
  fi
  exec=$(printf '%s\n' "$lines" | grep -E '^ExecStart=' || true)
  if [[ $(printf '%s\n' "$exec" | grep -c . || true) != 1 ]]; then
    problems+="want exactly one ExecStart="$'\n'
  fi
  for want in '--network ${COLLECTOR_NETWORK}' '--url-file /etc/ethswarm/collector-%i.url' \
    '--out ${COLLECTOR_OUT}' '--ntp ${COLLECTOR_NTP}'; do
    if [[ $exec != *" $want "* && $exec != *" $want" ]]; then
      problems+="ExecStart= lacks $want"$'\n'
    fi
  done
  if ! printf '%s\n' "$lines" | grep -Fq 'ExecStartPre=/bin/sh -c '; then
    problems+="no ExecStartPre= guard tying the env file to the instance"$'\n'
  fi
  if [[ -n $problems ]]; then
    printf '%s' "$problems"
    return 1
  fi
}

# env_value FILE KEY: the value of KEY (exactly one KEY= line, else empty and a failure).
env_value() {
  local matches
  matches=$(grep -E "^$2=" "$1" || true)
  [[ $(printf '%s\n' "$matches" | grep -c . || true) == 1 ]] || return 1
  printf '%s\n' "${matches#*=}"
}

# The keys an env file may set; the unit's guard refuses any other (STATE_DIRECTORY above all:
# an env file value overrides the one systemd sets).
ENV_KEYS='COLLECTOR_NETWORK|COLLECTOR_OUT|COLLECTOR_NTP'

# check_env FILE NETWORK: prints each problem; fails if there is one.
check_env() {
  local file=$1 network=$2 problems="" key value
  for key in ${ENV_KEYS//|/ }; do
    if ! env_value "$file" "$key" >/dev/null; then problems+="want exactly one $key="$'\n'; fi
  done
  # Plain KEY=value lines only: an unknown key is a typo, or a variable the unit must not take.
  while IFS= read -r line; do
    if [[ -n $line ]]; then problems+="not a known KEY=value line: $line"$'\n'; fi
  done <<<"$(grep -Ev '^(#.*)?$' "$file" | grep -Ev "^($ENV_KEYS)=[^\"' ]+\$" || true)"
  value=$(env_value "$file" COLLECTOR_NETWORK || true)
  [[ $value == "$network" ]] || problems+="COLLECTOR_NETWORK is ${value:-unset}, want $network"$'\n'
  value=$(env_value "$file" COLLECTOR_OUT || true)
  [[ $value == "/var/lib/ethswarm-collector/$network" ]] ||
    problems+="COLLECTOR_OUT is not the instance's state directory /var/lib/ethswarm-collector/$network"$'\n'
  value=$(env_value "$file" COLLECTOR_NTP || true)
  case $value in chrony | timesyncd | none) ;; *) problems+="COLLECTOR_NTP is not chrony, timesyncd or none"$'\n' ;; esac
  if [[ -n $problems ]]; then
    printf '%s' "$problems"
    return 1
  fi
}

# check_url FILE NETWORK PORT: the URL file holds exactly http://127.0.0.1:PORT, one line.
check_url() {
  local file=$1 network=$2 port=$3 lines
  lines=$(grep -c '' "$file" || true)
  if [[ $lines != 1 || $(cat "$file") != "http://127.0.0.1:$port" ]]; then
    echo "$file: want the one line http://127.0.0.1:$port (the ref-node $network default)"
    return 1
  fi
}

# expect_pass / expect_fail <description> <command...>
expect_pass() {
  local desc=$1 out rc=0
  shift
  out=$("$@" 2>&1) || rc=$?
  if ((rc == 0)); then ok "$desc"; else bad "$desc (exit $rc)" "$out"; fi
}
expect_fail() {
  local desc=$1 out rc=0
  shift
  out=$("$@" 2>&1) || rc=$?
  if ((rc != 0)); then ok "$desc"; else bad "$desc (passed, want a failure)" "$out"; fi
}

# replace FILE FROM TO: FILE with every FROM (a literal) replaced by TO, on stdout.
replace() {
  awk -v from="$2" -v to="$3" '{
    out = ""; rest = $0
    while ((i = index(rest, from)) > 0) { out = out substr(rest, 1, i - 1) to; rest = substr(rest, i + length(from)) }
    print out rest
  }' "$1"
}

# --- the template -------------------------------------------------------------------------------

expect_pass "the template has every hardening line, a user per instance, the env and URL files" \
  check_unit "$unit"
if [[ -e $collector/ethswarm-collector.service ]]; then
  bad "the single-network ethswarm-collector.service is gone (it hardcoded Sepolia's port)"
else
  ok "the single-network ethswarm-collector.service is gone (it hardcoded Sepolia's port)"
fi

grep -Fvx 'NoNewPrivileges=yes' "$unit" >"$tmp/no-nnp.service"
expect_fail "a hardening line removed is caught" check_unit "$tmp/no-nnp.service"
replace "$unit" 'ProtectSystem=strict' 'ProtectSystem=full' >"$tmp/weak.service"
expect_fail "a hardening line weakened is caught" check_unit "$tmp/weak.service"
awk '{ print } $0 == "[Service]" { print "MemoryDenyWriteExecute=no" }' "$unit" >"$tmp/override.service"
expect_fail "a hardening line overridden later in [Service] is caught" check_unit "$tmp/override.service"
grep -Ev '^User=' "$unit" >"$tmp/no-user.service"
expect_fail "a unit without User= is caught" check_unit "$tmp/no-user.service"
replace "$unit" 'User=ethswarm-collector-%i' 'User=ethswarm-collector' >"$tmp/shared-user.service"
expect_fail "one user shared by every instance is caught" check_unit "$tmp/shared-user.service"
replace "$unit" 'Group=ethswarm-collector-%i' 'Group=ethswarm-collector' >"$tmp/shared-group.service"
expect_fail "one group shared by every instance is caught" check_unit "$tmp/shared-group.service"
replace "$unit" 'EnvironmentFile=/etc' 'EnvironmentFile=-/etc' >"$tmp/optional-env.service"
expect_fail "an optional EnvironmentFile (-) is caught" check_unit "$tmp/optional-env.service"
replace "$unit" 'StateDirectory=ethswarm-collector/%i' 'StateDirectory=ethswarm-collector' \
  >"$tmp/shared-state.service"
expect_fail "a state directory shared by every instance is caught" \
  check_unit "$tmp/shared-state.service"
replace "$unit" '--url-file /etc/ethswarm/collector-%i.url' '--url ${REFERENCE_API_URL}' \
  >"$tmp/url-in-argv.service"
expect_fail "a URL in argv (--url) is caught" check_unit "$tmp/url-in-argv.service"
replace "$unit" '--url-file /etc/ethswarm/collector-%i.url' '--url http://127.0.0.1:5052' \
  >"$tmp/url.service"
expect_fail "a hardcoded URL in ExecStart is caught" check_unit "$tmp/url.service"
awk '{ print } $0 == "[Service]" { print "Environment=COLLECTOR_NETWORK=hoodi" }' \
  "$unit" >"$tmp/environment.service"
expect_fail "a setting made by Environment= is caught" check_unit "$tmp/environment.service"
grep -Ev '^ExecStartPre=' "$unit" >"$tmp/no-guard.service"
expect_fail "a unit without the instance guard is caught" check_unit "$tmp/no-guard.service"

# --- the ExecStartPre guard, run the way systemd would --------------------------------------------

# guard_of UNIT ENV_FILE: the hoodi instance's guard script, `$$` a literal `$` and %i `hoodi`,
# reading ENV_FILE in place of /etc/ethswarm/collector-hoodi.env.
guard_of() {
  service_lines "$1" | sed -n 's/^ExecStartPre=\/bin\/sh -c '"'"'\(.*\)'"'"'$/\1/p' |
    sed -e 's/\$\$/$/g' -e 's/%i/hoodi/g' | replace /dev/stdin /etc/ethswarm/collector-hoodi.env "$2"
}

# run_guard UNIT ENV_FILE: the hoodi instance's guard with systemd's environment: its own
# STATE_DIRECTORY, then every KEY=value of ENV_FILE, which overrides it.
run_guard() {
  local guard line assignments=()
  guard=$(guard_of "$1" "$2")
  [[ -n $guard ]] || { echo "no ExecStartPre=/bin/sh -c '<guard>'"; return 2; }
  if [[ -f $2 ]]; then
    while IFS= read -r line; do
      if [[ $line == [A-Za-z_]*=* ]]; then assignments+=("$line"); fi
    done <"$2"
  fi
  env -i PATH=/usr/bin:/bin STATE_DIRECTORY=/var/lib/ethswarm-collector/hoodi \
    ${assignments[@]+"${assignments[@]}"} /bin/sh -c "$guard"
}

hoodi_env="$collector/collector-hoodi.env.example"
# with_env NAME LINE...: the hoodi example env file plus LINEs, as $tmp/NAME.env.
with_env() {
  local name=$1
  shift
  { cat "$hoodi_env"; printf '%s\n' "$@"; } >"$tmp/$name.env"
}
replace "$hoodi_env" 'COLLECTOR_OUT=/var/lib/ethswarm-collector/hoodi' 'COLLECTOR_OUT=/tmp' \
  >"$tmp/out-tmp.env"
echo 'STATE_DIRECTORY=/tmp' >>"$tmp/out-tmp.env"
replace "$hoodi_env" 'COLLECTOR_OUT=/var/lib/ethswarm-collector/hoodi' \
  'COLLECTOR_OUT=/var/lib/ethswarm-collector' >"$tmp/shared-out.env"
grep -v '^COLLECTOR_NETWORK=' "$hoodi_env" >"$tmp/no-network.env"
with_env same-state 'STATE_DIRECTORY=/var/lib/ethswarm-collector/hoodi'
with_env preload 'LD_PRELOAD=/tmp/x.so'
with_env url "REFERENCE_API_URL=http://127.0.0.1:$HOODI_PORT"
with_env indented '  COLLECTOR_NTP=none'

expect_pass "the guard passes the hoodi env file on the hoodi instance" run_guard "$unit" "$hoodi_env"
expect_fail "the guard refuses the sepolia env file on the hoodi instance" \
  run_guard "$unit" "$collector/collector-sepolia.env.example"
expect_fail "the guard refuses COLLECTOR_OUT and STATE_DIRECTORY both set to /tmp" \
  run_guard "$unit" "$tmp/out-tmp.env"
expect_fail "the guard refuses an output dir outside the instance's state directory" \
  run_guard "$unit" "$tmp/shared-out.env"
expect_fail "the guard refuses an env file without the network" run_guard "$unit" "$tmp/no-network.env"
expect_fail "the guard refuses any STATE_DIRECTORY line, even the right value" \
  run_guard "$unit" "$tmp/same-state.env"
expect_fail "the guard refuses an unknown key (LD_PRELOAD)" run_guard "$unit" "$tmp/preload.env"
expect_fail "the guard refuses a URL in the env file" run_guard "$unit" "$tmp/url.env"
expect_fail "the guard refuses a line systemd would read as a key the check does not see" \
  run_guard "$unit" "$tmp/indented.env"
expect_fail "the guard refuses a missing env file" run_guard "$unit" "$tmp/missing.env"

# The guard that compared COLLECTOR_OUT with $STATE_DIRECTORY let an env file move both.
guard_refuses_override() { ! run_guard "$1" "$tmp/out-tmp.env" >/dev/null 2>&1; }
cat >"$tmp/old-guard.service" <<'UNIT'
[Service]
ExecStartPre=/bin/sh -c 'if [ "$${COLLECTOR_NETWORK}" != "%i" ] || [ "$${COLLECTOR_OUT}" != "$${STATE_DIRECTORY}" ]; then exit 1; fi'
UNIT
expect_pass "the guard is not fooled by an env file's STATE_DIRECTORY" guard_refuses_override "$unit"
expect_fail "the old \$STATE_DIRECTORY comparison is caught by that case" \
  guard_refuses_override "$tmp/old-guard.service"

# --- the example env and URL files ------------------------------------------------------------------

# ref_node_port NETWORK: the ref-node's default beacon API port for NETWORK (BEACON_API_PORT in
# its example env file), or why there is none.
ref_node_port() {
  local file
  case $1 in
    sepolia) file="$repo/ops/ref-node/.env.example" ;;
    hoodi) file="$repo/ops/ref-node/.env.hoodi.example" ;;
  esac
  if [[ ! -f $file ]]; then
    echo "no $file"
  else
    env_value "$file" BEACON_API_PORT || echo "not exactly one BEACON_API_PORT in $file"
  fi
}

for pair in "sepolia $SEPOLIA_PORT" "hoodi $HOODI_PORT"; do
  network=${pair% *} port=${pair#* }
  expect_pass "collector-$network.env.example: $network, its own state dir, known keys only" \
    check_env "$collector/collector-$network.env.example" "$network"
  expect_pass "collector-$network.url.example: http://127.0.0.1:$port" \
    check_url "$collector/collector-$network.url.example" "$network" "$port"
  found=$(ref_node_port "$network")
  if [[ $found == "$port" ]]; then
    ok "the ref-node $network beacon API default is still $port"
  else
    bad "the ref-node $network beacon API default is still $port" "found: $found"
  fi
done

hoodi_url="$collector/collector-hoodi.url.example"
replace "$hoodi_url" ":$HOODI_PORT" ":$SEPOLIA_PORT" >"$tmp/hoodi-on-sepolia.url"
expect_fail "a Hoodi URL file on Sepolia's port is caught" \
  check_url "$tmp/hoodi-on-sepolia.url" hoodi "$HOODI_PORT"
{ cat "$hoodi_url"; echo "http://127.0.0.1:$SEPOLIA_PORT"; } >"$tmp/two.url"
expect_fail "a URL file with a second line is caught" check_url "$tmp/two.url" hoodi "$HOODI_PORT"

replace "$hoodi_env" 'COLLECTOR_NETWORK=hoodi' 'COLLECTOR_NETWORK=sepolia' >"$tmp/named.env"
expect_fail "a Hoodi env file naming another network is caught" check_env "$tmp/named.env" hoodi
with_env twice 'COLLECTOR_NTP=none'
expect_fail "a second COLLECTOR_NTP line is caught" check_env "$tmp/twice.env" hoodi
with_env typo 'COLLECTOR_NPT=none'
expect_fail "an unknown key is caught" check_env "$tmp/typo.env" hoodi
expect_fail "a URL in the env file is caught" check_env "$tmp/url.env" hoodi
expect_fail "a STATE_DIRECTORY line is caught" check_env "$tmp/same-state.env" hoodi
replace "$hoodi_env" '=chrony' '="chrony"' >"$tmp/quoted.env"
expect_fail "a quoted value is caught" check_env "$tmp/quoted.env" hoodi
expect_fail "an output dir shared by both instances is caught" check_env "$tmp/shared-out.env" hoodi

# --- the README's migration from the single-network unit ----------------------------------------

readme="$collector/README.md"
# The old unit may be named only by the commands that retire it.
MIGRATION='sudo systemctl disable --now ethswarm-collector.service
sudo rm -f /etc/systemd/system/ethswarm-collector.service'
# check_readme FILE: prints each problem; fails if there is one.
check_readme() {
  local file=$1 problems="" want line
  while IFS= read -r want; do
    grep -Fq -- "$want" "$file" || problems+="missing: $want"$'\n'
  done <<<"$MIGRATION
sudo systemctl daemon-reload
sudo chown root:root /var/lib/ethswarm-collector
sudo chmod 0755 /var/lib/ethswarm-collector
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ethswarm-collector-hoodi
-m 0600 ops/collector/collector-hoodi.url.example"
  while IFS= read -r line; do
    if [[ -n $line ]] && ! printf '%s\n' "$MIGRATION" | grep -Fxq -- "$(printf '%s' "$line" | sed 's/^ *//')"; then
      problems+="names the old unit outside its retirement: $line"$'\n'
    fi
  done <<<"$(grep -F 'ethswarm-collector.service' "$file" || true)"
  if grep -Eq 'useradd .* ethswarm-collector$' "$file"; then
    problems+="creates one user shared by every instance"$'\n'
  fi
  if [[ -n $problems ]]; then
    printf '%s' "$problems"
    return 1
  fi
}
expect_pass "the README retires the old unit, fixes /var/lib/ethswarm-collector, a user per network" \
  check_readme "$readme"
grep -Fv 'disable --now ethswarm-collector.service' "$readme" >"$tmp/no-disable.md"
expect_fail "a README that never stops the old unit is caught" check_readme "$tmp/no-disable.md"
grep -Fv 'chown root:root /var/lib/ethswarm-collector' "$readme" >"$tmp/no-chown.md"
expect_fail "a README that leaves the old state dir owner is caught" check_readme "$tmp/no-chown.md"
{ cat "$readme"; echo 'sudo systemctl enable --now ethswarm-collector.service'; } >"$tmp/old-unit.md"
expect_fail "a README that starts the old unit is caught" check_readme "$tmp/old-unit.md"
{ cat "$readme"; echo 'sudo useradd --system ethswarm-collector'; } >"$tmp/shared-user.md"
expect_fail "a README that creates the shared user is caught" check_readme "$tmp/shared-user.md"

echo "collector unit tests: $passed passed, $failed failed"
((failed == 0))
