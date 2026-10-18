# Shell rules shared by setup.sh, preflight.sh and collect-run-log.sh (sourced: functions and
# constants only, no options set). A value never becomes program text: awk gets it through
# ENVIRON (which, unlike -v, decodes no escape), sed and grep never get it in a pattern. The reference host is Linux; the offline tests also source
# this on macOS (bash 3.2, BSD stat), so file_mode_uid takes either stat.
# shellcheck shell=bash

# The networks this stack runs (.env NETWORK), each with its pinned config in
# crates/network-config/networks/<network>/config.yaml.
NETWORKS="sepolia hoodi"

# network_known <name>: 0 if <name> is one of NETWORKS.
network_known() {
  case " $NETWORKS " in
    *" $1 "*) [[ -n $1 ]] ;;
    *) return 1 ;;
  esac
}

# service_user <network> <reth|lighthouse>: the service's OS user. Sepolia keeps the plain
# names; any other network adds its name, so two networks on one host never share a user.
service_user() {
  if [[ $1 == sepolia ]]; then echo "$2"; else echo "$2-$1"; fi
}

# default_data_root <network>: DATA_ROOT when .env leaves it empty (setup.sh writes it).
default_data_root() {
  if [[ $1 == sepolia ]]; then echo /srv/ethswarm-ref; else echo "/srv/ethswarm-ref-$1"; fi
}

# required_providers <network>: how many checkpoint providers preflight.sh must cross-check.
# Hoodi's anchor must agree across two providers run by different operators.
required_providers() {
  if [[ $1 == hoodi ]]; then echo 2; else echo 1; fi
}

# The consensus-specs release our client targets. README.md records the one each pinned CL
# release targets; a different one is recorded in the run log, not failed.
# shellcheck disable=SC2034 # read by collect-run-log.sh
OUR_CONSENSUS_SPECS=v1.7.0-beta.4

# release_notes <README.md> <network>: the network's release-note table, the lines between
# <!-- release-notes:<network>:begin --> and <!-- release-notes:<network>:end -->.
release_notes() {
  RN_NET=$2 awk '
    BEGIN { b = "<!-- release-notes:" ENVIRON["RN_NET"] ":begin -->"; e = "<!-- release-notes:" ENVIRON["RN_NET"] ":end -->" }
    $0 == e { on = 0 } on { print } $0 == b { on = 1 }' "$1"
}

# release_row <README.md> <network> <image ref>: "<schedules>|<consensus-specs>" from the row
# of the network's table whose Image cell is `<image ref>` (tag and digest, so a re-pushed
# tag has no row), cells trimmed; nothing when there is no such row. Columns: Image,
# Release, Schedules the fork (yes or no), consensus-specs, Release-note line.
release_row() {
  release_notes "$1" "$2" | RELEASE_IMG="\`$3\`" awk -F '|' '
    function trim(x) { gsub(/^[ \t]+|[ \t]+$/, "", x); return x }
    NF >= 7 && trim($2) == ENVIRON["RELEASE_IMG"] { print trim($4) "|" trim($5); exit }'
}

# The ports compose.yaml binds, from .env (both .env examples set them; the second network on
# a host takes other ones).
PORT_KEYS="ENGINE_PORT BEACON_API_PORT RETH_P2P_PORT LIGHTHOUSE_P2P_PORT LIGHTHOUSE_QUIC_PORT"

# ports_check <env file>: one line per port key that is not a decimal 1-65535 without a
# leading zero, or that repeats another key's port; 1 if any. The values are printed: ports
# are no secret, and only a well-formed one is.
ports_check() {
  local key value seen=' ' rc=0
  for key in $PORT_KEYS; do
    value=$(env_get "$1" "$key")
    if [[ ! $value =~ ^[1-9][0-9]{0,4}$ ]] || ((value > 65535)); then
      echo "$key: not a port number (1-65535)"; rc=1
    elif [[ $seen == *" $value "* ]]; then
      echo "$key: $value is already another port of this node"; rc=1
    else
      seen="$seen$value "
    fi
  done
  return $rc
}

# The image reference .env must carry: repo:tag@sha256:<64 lower-case hex>. A registry port
# (host:5000/repo) is allowed in the repo part.
IMAGE_PIN_RE='^[a-z0-9]([a-z0-9._/-]|:[0-9]+/)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}$'

# image_pinned <ref>: 0 if <ref> is pinned by tag and digest.
image_pinned() {
  [[ $1 =~ $IMAGE_PIN_RE ]]
}

# redact_url <url>: scheme://host[:port] only, plus "/…" when anything followed it (a path,
# a query, credentials), since a provider key may sit there. Never the rest of the URL.
redact_url() {
  local url=$1 scheme rest authority tail
  scheme=${url%%://*}
  if [[ $url != *://* || ! $scheme =~ ^[A-Za-z][A-Za-z0-9+.-]*$ ]]; then
    echo "(not a URL)"
    return
  fi
  rest=${url#*://}
  authority=${rest%%[/?#]*}
  tail=${rest#"$authority"}
  if [[ $authority == *@* ]]; then
    authority=${authority##*@}
    tail=/x
  fi
  if [[ -z $tail || $tail == / ]]; then
    printf '%s://%s\n' "$scheme" "$authority"
  else
    printf '%s://%s/…\n' "$scheme" "$authority"
  fi
}

# env_check <file>: 0 if every line is blank, a # comment, or a strict KEY=value line with a
# key given once and a value without $ or a backtick, and no COMPOSE_* key; else one line per
# problem (never a value) and 1. compose also reads `export KEY=` and indented lines, lets the
# last of two win, and expands $ in values, so any of those could make it run what the
# scripts never saw; and it takes COMPOSE_PROJECT_NAME, COMPOSE_FILE and the like from .env,
# which would pick another project (another network's) or another compose file.
env_check() {
  awk '
    /^$/ || /^#/ { next }
    !/^[A-Z_][A-Z0-9_]*=/ { printf "%s line %d: not KEY=value (no export, no leading space)\n", FILENAME, NR; bad = 1; next }
    {
      k = substr($0, 1, index($0, "=") - 1)
      if (k ~ /^COMPOSE_/) { printf "%s line %d: %s: compose reads COMPOSE_* keys from .env; none may be set\n", FILENAME, NR, k; bad = 1 }
      if (k in seen) { printf "%s line %d: %s set twice\n", FILENAME, NR, k; bad = 1 }
      seen[k] = 1
      if (substr($0, index($0, "=") + 1) ~ /[$`]/) {
        printf "%s line %d: %s holds a $ or a backtick (compose would expand it)\n", FILENAME, NR, k; bad = 1
      }
    }
    END { exit bad }' "$1"
}

# env_get <file> <key>: the value of the last KEY=value line, surrounding quotes removed. The
# file is read, never sourced, so nothing in it runs.
env_get() {
  ENV_KEY=$2 awk '
    BEGIN { k = ENVIRON["ENV_KEY"] }
    index($0, k "=") == 1 { v = substr($0, length(k) + 2) }
    END {
      if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2)
      print v
    }' "$1"
}

# Every variable compose.yaml interpolates. compose takes a variable set in the shell
# environment over the same one in .env, so a stray export would run another image, root or
# uid than the one preflight.sh and the run log checked in .env.
COMPOSE_VARS="NETWORK RETH_IMAGE LIGHTHOUSE_IMAGE CHECKPOINT_SYNC_URL TRUSTED_PEERS DATA_ROOT RETH_UID RETH_GID LIGHTHOUSE_UID LIGHTHOUSE_GID $PORT_KEYS"

# compose_project <network>: the compose project, passed as -p on every compose call (it wins
# over COMPOSE_PROJECT_NAME and the file's name:).
compose_project() {
  echo "$1-ref"
}

# project_env_check: 1, with a line, if COMPOSE_PROJECT_NAME is set in the environment (even
# empty): compose would take it over compose.yaml's name:, so a Sepolia value would make a
# Hoodi `up` recreate the Sepolia services.
project_env_check() {
  if [[ -n ${COMPOSE_PROJECT_NAME+set} ]]; then
    echo "COMPOSE_PROJECT_NAME is set in the environment; unset it (the project is always -p <network>-ref)"
    return 1
  fi
}

# env_overrides <env file>: one FAIL line per compose variable set in the environment (even to
# empty) with a value other than the file's; 1 if any. Names only, never a value.
env_overrides() {
  local key rc=0
  for key in $COMPOSE_VARS; do
    if [[ -n ${!key+set} && ${!key} != "$(env_get "$1" "$key")" ]]; then
      echo "$key: set in the environment and differs from .env (compose would use it): FAIL"
      rc=1
    fi
  done
  return $rc
}

# fetch <url> <out-file>: GET the URL into the file; curl's exit code. The URL goes to curl on
# stdin (--config -), so it never shows in the process list, and curl's own messages are
# dropped, so it never shows in a log either. No redirects are followed.
fetch() {
  local url=$1 out=$2
  case $url in
    *[[:space:]\"\\]*) return 2 ;;
  esac
  printf 'url = "%s"\n' "$url" |
    curl --config - --fail --silent --max-time "${FETCH_TIMEOUT:-20}" --proto '=http,https' \
      --header 'Accept: application/json' --output "$out" 2>/dev/null
}

# check_binds <ss -ltn output> <port>...: one verdict line per port; 1 unless every listener on
# each port is on 127.0.0.1 (a 0.0.0.0, [::], * or other address fails, as does no listener).
check_binds() {
  local ss_out=$1 port rc=0 locals bad_addr
  shift
  for port in "$@"; do
    locals=$(printf '%s\n' "$ss_out" | BIND_PORT=":$port" awk 'BEGIN { p = ENVIRON["BIND_PORT"] }
      $1 == "LISTEN" && length($4) > length(p) && substr($4, length($4) - length(p) + 1) == p { print $4 }')
    bad_addr=$(printf '%s\n' "$locals" | BIND_WANT="127.0.0.1:$port" awk 'NF && $0 != ENVIRON["BIND_WANT"]' | tr '\n' ' ')
    if [[ -z $locals ]]; then
      echo "port $port: no listener: FAIL"; rc=1
    elif [[ -n $bad_addr ]]; then
      echo "port $port: listening on ${bad_addr% } (not 127.0.0.1 only): FAIL"; rc=1
    else
      echo "port $port: 127.0.0.1 only: PASS"
    fi
  done
  return $rc
}

# check_listeners <ss -ltnp output> <service> <pids> <p2p port>: every TCP listener that one
# of <pids> (the service container's processes, `docker top`, read together with the ss
# output) owns is on a loopback address (127.0.0.0/8, [::1]) or on the service's own
# <p2p port>, and one of them is the p2p listener. One line per p2p listener, one FAIL line per
# other non-loopback listener, then a PASS summary; 1 on any FAIL. It also fails when <pids> is
# empty, when ss shows no process for any listener (not run as root), and when none of the
# service's listeners is on its p2p port (its pids matched nothing, say after a restart), since
# a check that matched nothing proves nothing. An override that opens an RPC on a public
# address (reth --http --http.addr=0.0.0.0) fails here whatever its port.
check_listeners() {
  local ss_out=$1 svc=$2 pids=$3 port=$4 rc=0
  if [[ -z $pids ]]; then
    echo "$svc: no container process to match listeners to: FAIL"
    return 1
  fi
  if ! printf '%s\n' "$ss_out" | grep -q '^LISTEN .*pid=[0-9]'; then
    echo "$svc: ss -ltnp shows no process for any listener (it needs root): FAIL"
    return 1
  fi
  printf '%s\n' "$ss_out" | LS_PIDS=" $pids " LS_PORT="$port" LS_SVC="$svc" awk '
    BEGIN { pids = ENVIRON["LS_PIDS"]; p2p = ENVIRON["LS_PORT"]; svc = ENVIRON["LS_SVC"] }
    $1 != "LISTEN" { next }
    {
      owner = ""; rest = $0
      while (match(rest, /pid=[0-9]+/)) {
        p = substr(rest, RSTART + 4, RLENGTH - 4)
        if (index(pids, " " p " ")) owner = p
        rest = substr(rest, RSTART + RLENGTH)
      }
      if (owner == "") next
      laddr = $4; port = laddr; sub(/.*:/, "", port)
      if (port == p2p) { printf "%s: p2p listener %s (pid %s)\n", svc, laddr, owner; seen = 1; next }
      addr = substr(laddr, 1, length(laddr) - length(port) - 1)
      sub(/%.*/, "", addr)
      if (addr ~ /^127\./ || addr == "[::1]" || addr ~ /^\[::ffff:127\./) next
      printf "%s: listener %s (pid %s) is neither on loopback nor a p2p port: FAIL\n", svc, laddr, owner
      bad = 1
    }
    END {
      if (!seen) { printf "%s: no p2p listener on port %s among pids %s: FAIL\n", svc, p2p, substr(pids, 2, length(pids) - 2); bad = 1 }
      exit bad
    }' || rc=1
  if ((rc == 0)); then
    echo "$svc: no non-loopback TCP listener but p2p port $port (pids $pids): PASS"
  fi
  return $rc
}

# check_mode_owner <path> <"<mode> <owner>"> <owner>: a verdict line; 1 unless the second
# argument is exactly "600 <owner>".
check_mode_owner() {
  if [[ $2 == "600 $3" ]]; then
    echo "$1: $2: PASS"
  else
    echo "$1: ${2:-no such file} (want 600 $3): FAIL"
    return 1
  fi
}

# file_mode_uid <path>: "<octal mode> <owner uid>" (setuid/setgid/sticky included, as GNU
# %a prints them), from GNU or BSD stat; the link itself for a symlink is never asked for.
file_mode_uid() {
  file_stat "$1" | cut -d' ' -f1,2
}

# file_stat <path>: "<octal mode> <owner uid> <link count>".
file_stat() {
  local out mode uid links
  if stat -c '%a' / >/dev/null 2>&1; then
    stat -c '%a %u %h' -- "$1"
  else
    out=$(stat -f '%p %u %l' -- "$1") || return
    read -r mode uid links <<< "$out"
    printf '%o %s %s\n' $((8#$mode & 8#7777)) "$uid" "$links"
  fi
}
