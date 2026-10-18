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

# release_row <README.md> <network> <client> <image ref>: "<schedules>|<consensus-specs>" from
# the first row of the network's table whose Image cell is `<image ref>` (tag and digest, so a
# re-pushed tag has no row) and whose Client cell is <client> (reth or lighthouse: the service
# the image is for, so a pin swapped between the services has no row), cells trimmed; nothing
# when there is no such row. Columns: Image, Client, Release, Schedules the fork (yes or no),
# consensus-specs, Release-note line or fork-schedule check. The awk reads the whole table: one
# that stopped at the match would leave release_notes writing into a closed pipe, and pipefail
# would turn its SIGPIPE into exit 141.
release_row() {
  release_notes "$1" "$2" | RELEASE_CLIENT=$3 RELEASE_IMG="\`$4\`" awk -F '|' '
    function trim(x) { gsub(/^[ \t]+|[ \t]+$/, "", x); return x }
    !found && NF >= 8 && trim($2) == ENVIRON["RELEASE_IMG"] && trim($3) == ENVIRON["RELEASE_CLIENT"] {
      print trim($5) "|" trim($6); found = 1
    }'
}

# service_repo <reth|lighthouse>: the repository the service's image must come from, spelled
# as README.md's tables spell it; 1 for any other service. The one map of service to repository:
# the README's Client cell is hand-editable, so it never decides alone which client an image is.
service_repo() {
  case $1 in
    reth) echo ghcr.io/paradigmxyz/reth ;;
    lighthouse) echo sigp/lighthouse ;;
    *) return 1 ;;
  esac
}

# image_repo <image ref>: the repository part of the ref, everything before the tag's ':' or
# the '@'. A ':' before the last '/' is a registry port and stays (host:5000/repo).
image_repo() {
  local repo=${1%%@*}
  if [[ ${repo##*/} == *:* ]]; then repo=${repo%:*}; fi
  printf '%s\n' "$repo"
}

# repo_check <variable> <service> <image ref>: 0 if the image's repository is exactly the
# service's own (service_repo); else one line naming the variable, the repository it has and
# the one it wants, and 1. preflight.sh and collect-run-log.sh check it before release_row, so
# a README.md row that names the wrong client, or a lookalike repository (reth-evil,
# lighthouse2, docker.io/sigp/lighthouse), never vouches for an image.
repo_check() {
  local want got
  if ! want=$(service_repo "$2"); then
    echo "$1: $2 has no known image repository"
    return 1
  fi
  got=$(image_repo "$3")
  [[ $got == "$want" ]] && return 0
  echo "$1: repository $got is not $2's (want $want)"
  return 1
}

# release_client <README.md> <network> <image ref>: the Client cell of the first row of the
# network's table whose Image cell is `<image ref>`; nothing when there is no such row. Only a
# diagnosis (which client a refused pin belongs to): release_row decides.
release_client() {
  release_notes "$1" "$2" | RELEASE_IMG="\`$3\`" awk -F '|' '
    function trim(x) { gsub(/^[ \t]+|[ \t]+$/, "", x); return x }
    !found && NF >= 8 && trim($2) == ENVIRON["RELEASE_IMG"] { print trim($3); found = 1 }'
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

# env_check <file> [name]: 0 if the file is one compose's dotenv parser and these scripts read
# the same way; else one line per problem (never a value), naming the file <name> (default
# <file>: the scripts check their private copy), and 1. The rule fails closed:
#   - the whole file is printable ASCII and LF (no CR, TAB, NUL, control or non-ASCII byte);
#   - every line is blank, a # comment from its first column (compose skips it whole), or a
#     strict KEY=value line with a key given once and no COMPOSE_* key;
#   - a value holds no blank, no quote, no backslash, no #, no $ and no backtick.
# compose reads `export KEY=` and indented lines, lets the last of two win, expands $, cuts an
# inline comment (` #`), trims blanks, unquotes, and keeps reading after a closing quote, so
# DUMMY=''RETH_UID=0 sets RETH_UID too: any of those could make it run what the scripts never
# saw. And it takes COMPOSE_PROJECT_NAME, COMPOSE_FILE and the like from .env, which would pick
# another project (another network's) or another compose file.
env_check() {
  local name=${2:-$1}
  # tr counts every byte outside the set, NUL included; awk names the lines it can see.
  if [[ $(LC_ALL=C tr -d '\n\040-\176' < "$1" | wc -c | tr -d ' ') != 0 ]]; then
    ENV_NAME=$name LC_ALL=C awk '
      BEGIN { f = ENVIRON["ENV_NAME"] }
      /[^ -~]/ { printf "%s line %d: a byte other than printable ASCII or a newline (a CR, a TAB, a control or non-ASCII byte)\n", f, NR; seen = 1 }
      END { if (!seen) printf "%s: a byte other than printable ASCII or a newline (a NUL)\n", f }' "$1"
    return 1
  fi
  ENV_NAME=$name LC_ALL=C awk '
    BEGIN { f = ENVIRON["ENV_NAME"] }
    /^$/ || /^#/ { next }
    !/^[A-Z_][A-Z0-9_]*=/ { printf "%s line %d: not KEY=value (no export, no leading space)\n", f, NR; bad = 1; next }
    {
      k = substr($0, 1, index($0, "=") - 1)
      v = substr($0, index($0, "=") + 1)
      if (k ~ /^COMPOSE_/) { printf "%s line %d: %s: compose reads COMPOSE_* keys from .env; none may be set\n", f, NR, k; bad = 1 }
      if (k in seen) { printf "%s line %d: %s set twice\n", f, NR, k; bad = 1 }
      seen[k] = 1
      if (v ~ /[$`]/) {
        printf "%s line %d: %s holds a $ or a backtick (compose would expand it)\n", f, NR, k; bad = 1
      } else if (v ~ /[ \047"\\#]/) {
        printf "%s line %d: %s holds a blank, a quote, a backslash or a # (compose would read it differently)\n", f, NR, k; bad = 1
      }
    }
    END { exit bad }' "$1"
}

# env_value_ok <value>: 0 if <value> is one env_check accepts as an .env value: printable ASCII
# only (no control, TAB, newline or non-ASCII byte), with no blank, quote, backslash, #, $ or
# backtick. For a value the scripts write into .env themselves (setup.sh --root): one that
# breaks the rule would make every later run refuse the .env, or compose read another value.
env_value_ok() {
  [[ $(printf '%s' "$1" | LC_ALL=C tr -d '\041-\176' | wc -c | tr -d ' ') == 0 ]] || return 1
  case $1 in
    *[\'\"\\#\$\`]*) return 1 ;;
  esac
}

# no_control_char <string>: 0 unless <string> holds a control byte (0x01-0x1f, 0x7f: a newline,
# a TAB, a CR, an escape). For a path given on the command line: a command substitution drops a
# trailing newline, so $(dirname -- "$p") and $(basename -- "$p") of $'/x/node.env\n' name
# /x/node.env, which would be checked, read and written instead.
no_control_char() {
  [[ $(printf '%s' "$1" | LC_ALL=C tr -dc '\001-\037\177' | wc -c | tr -d ' ') == 0 ]]
}

# env_path_check <path>: 0 unless the --env-file path holds a control character; then an ERROR
# line on stderr (never the path itself) and 1. Each script calls it before it uses the path.
env_path_check() {
  no_control_char "$1" && return 0
  echo "ERROR: --env-file: the path holds a control character (a newline, a TAB, a CR, ...)" >&2
  return 1
}

# env_get <file> <key>: the value of the last KEY=value line, as it is (env_check refuses the
# quotes, blanks and escapes compose would read differently). The file is read, never sourced,
# so nothing in it runs.
env_get() {
  ENV_KEY=$2 awk '
    BEGIN { k = ENVIRON["ENV_KEY"] }
    index($0, k "=") == 1 { v = substr($0, length(k) + 2) }
    END { print v }' "$1"
}

# abs_dir <dir>: <dir> made absolute against the physical working directory, never resolved
# (fsguard refuses a symlink anywhere on the path it gets).
abs_dir() {
  case $1 in
    /*) printf '%s\n' "$1" ;;
    .) pwd -P ;;
    *) printf '%s/%s\n' "$(pwd -P)" "$1" ;;
  esac
}

# sudo_operator: the sudo user (SUDO_UID) who may own the .env and its directory, or -1.
sudo_operator() {
  if [[ ${SUDO_UID:-} =~ ^[0-9]+$ ]]; then echo "$SUDO_UID"; else echo -1; fi
}

# read_env <fsguard.py> <env file> <copy>: the .env read once, through fsguard read-file (the
# walk from / to its directory, which root, the euid or the sudo user owns and nobody else can
# write; then a regular file with one link and such an owner, opened O_NOFOLLOW|O_NONBLOCK),
# into <copy>; fsguard's exit code, its reason on stderr. A path with a control character is
# refused first (exit 2; env_path_check). Every later read uses the copy, so
# the scripts never follow a link, block on a FIFO or see another file the second time.
read_env() {
  env_path_check "$2" || return 2
  python3 -I -B "$1" read-file "$(abs_dir "$(dirname -- "$2")")" "$(basename -- "$2")" "$(id -u)" "$(sudo_operator)" > "$3"
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

# docker_env_check: one "ERROR: ..." line per compose or docker variable set in the
# environment (even empty), and 1 if any; names only, never a value. compose reads every
# COMPOSE_* variable: COMPOSE_PROJECT_NAME would win over compose.yaml's name: (a Sepolia value
# would make a Hoodi `up` recreate the Sepolia services), COMPOSE_FILE would pick the file a
# bare `up` reads, COMPOSE_PROFILES and the rest change what it runs. docker reads every
# DOCKER_* variable, and none is needed here: DOCKER_HOST, DOCKER_CONTEXT, DOCKER_CONFIG,
# DOCKER_TLS* and DOCKER_CERT_PATH would point every docker call (and the operator's `up`) at
# another daemon, or its config, than the host's; DOCKER_DEFAULT_PLATFORM and the rest change
# what it pulls or runs.
docker_env_check() {
  local name rc=0
  for name in $(compgen -e); do
    case $name in
      COMPOSE_PROJECT_NAME) echo "ERROR: $name is set in the environment; unset it (the project is always -p <network>-ref)"; rc=1 ;;
      COMPOSE_FILE) echo "ERROR: $name is set in the environment; unset it (the compose file is always -f compose.yaml)"; rc=1 ;;
      COMPOSE_*) echo "ERROR: $name is set in the environment; unset it (compose reads it)"; rc=1 ;;
      DOCKER_HOST | DOCKER_CONTEXT | DOCKER_CONFIG | DOCKER_TLS* | DOCKER_CERT_PATH)
        echo "ERROR: $name is set in the environment; unset it (it points docker at another daemon or config than the host's)"; rc=1 ;;
      DOCKER_*) echo "ERROR: $name is set in the environment; unset it (docker reads it)"; rc=1 ;;
    esac
  done
  return $rc
}

# docker_config_pin: export DOCKER_CONFIG as the .docker directory in the euid's home from the
# passwd database (/root/.docker for root), never from HOME; 1 and an ERROR line when the euid
# has no passwd entry. docker reads its config (the current context, so which daemon it talks
# to, and the credential helpers it runs) and its CLI plugins (docker compose itself) from
# DOCKER_CONFIG, else from $HOME/.docker, and sudo -E keeps the operator's HOME: root's docker
# would then run the operator's ~/.docker/cli-plugins/docker-compose as root, or talk to the
# daemon the operator's context names. docker_env_check refuses a DOCKER_CONFIG from the
# environment first, so every docker call after this sees only the pinned one.
docker_config_pin() {
  local home
  home=$(python3 -I -B -c 'import os, pwd; print(pwd.getpwuid(os.geteuid()).pw_dir)' 2>/dev/null) || home=''
  if [[ $home != /* ]]; then
    echo "ERROR: uid $(id -u) has no home directory in the passwd database (docker reads its config from there, never from HOME)"
    return 1
  fi
  DOCKER_CONFIG="${home%/}/.docker"
  export DOCKER_CONFIG
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

# The largest answer fetch keeps. The biggest one the scripts read is /eth/v1/config/spec,
# about 20 KB; lib/beacon.py MAX_ANSWER is the same bound.
FETCH_MAX_BYTES=1048576

# fetch <url> <out-file>: GET the URL into the file; curl's exit code. The URL goes to curl on
# stdin (--config -), so it never shows in the process list, and curl's own messages are
# dropped, so it never shows in a log either. No redirects are followed. -q (first, as curl
# requires) skips ~/.curlrc: root's could add a write-out that prints the URL, or a proxy.
# --noproxy '*' ignores the proxy variables for every call, not only the loopback Beacon API: a
# proxy would see each URL in full, and a checkpoint provider must be checked over the direct
# path Lighthouse takes to it (compose.yaml passes it no proxy variable). An answer over
# FETCH_MAX_BYTES fails (exit 63, curl's own code for it) and leaves <out-file> empty: curl's
# --max-filesize stops one that announces its length, and head stops one that does not. Every
# stage of the pipeline counts: curl's own failure is returned as it is, and printf or head
# failing (head cannot write the answer: ENOSPC under /tmp) is exit 23, curl's code for a write
# error; either way <out-file> is left empty, never holding part of an answer.
fetch() {
  local url=$1 out=$2 status
  case $url in
    *[[:space:]\"\\]*) return 2 ;;
  esac
  printf 'url = "%s"\n' "$url" |
    curl -q --config - --noproxy '*' --fail --silent --max-time "${FETCH_TIMEOUT:-20}" --proto '=http,https' \
      --max-filesize "$FETCH_MAX_BYTES" --header 'Accept: application/json' 2>/dev/null |
    head -c "$((FETCH_MAX_BYTES + 1))" > "$out"
  status=("${PIPESTATUS[@]}")
  if (($(wc -c < "$out") > FETCH_MAX_BYTES)); then
    : > "$out"
    return 63
  fi
  if ((status[1] != 0)); then
    : > "$out"
    return "${status[1]}"
  fi
  if ((status[0] != 0 || status[2] != 0)); then
    : > "$out"
    return 23
  fi
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
  # A here-string, not printf | grep -q: grep stops at the first match, and printf writing the
  # rest of a long listing into the closed pipe would make pipefail report "no process".
  if ! grep -q '^LISTEN .*pid=[0-9]' <<< "$ss_out"; then
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
