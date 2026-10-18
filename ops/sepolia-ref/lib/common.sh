# Shell rules shared by setup.sh, preflight.sh and collect-run-log.sh (sourced: functions and
# constants only, no options set). The reference host is Linux; the offline tests also source
# this on macOS (bash 3.2, BSD stat), so file_mode_uid takes either stat.
# shellcheck shell=bash

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
# key given once and a value without $ or a backtick; else one line per problem (never a
# value) and 1. compose also reads `export KEY=` and indented lines, lets the last of two
# win, and expands $ in values, so any of those could make it run what the scripts never saw.
env_check() {
  awk '
    /^$/ || /^#/ { next }
    !/^[A-Z_][A-Z0-9_]*=/ { printf "%s line %d: not KEY=value (no export, no leading space)\n", FILENAME, NR; bad = 1; next }
    {
      k = substr($0, 1, index($0, "=") - 1)
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
  awk -v k="$2" '
    index($0, k "=") == 1 { v = substr($0, length(k) + 2) }
    END {
      if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2)
      print v
    }' "$1"
}

# Every variable compose.yaml interpolates. compose takes a variable set in the shell
# environment over the same one in .env, so a stray export would run another image, root or
# uid than the one preflight.sh and the run log checked in .env.
COMPOSE_VARS="RETH_IMAGE LIGHTHOUSE_IMAGE CHECKPOINT_SYNC_URL TRUSTED_PEERS DATA_ROOT RETH_UID RETH_GID LIGHTHOUSE_UID LIGHTHOUSE_GID"

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
    locals=$(printf '%s\n' "$ss_out" | awk -v p=":$port" '
      $1 == "LISTEN" && length($4) > length(p) && substr($4, length($4) - length(p) + 1) == p { print $4 }')
    bad_addr=$(printf '%s\n' "$locals" | awk -v want="127.0.0.1:$port" 'NF && $0 != want' | tr '\n' ' ')
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

# check_mode_owner <path> <stat -c '%a %U' output> <user>: a verdict line; 1 unless the output
# is exactly "600 <user>".
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
