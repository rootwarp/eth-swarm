#!/usr/bin/env bash
# One-time host setup for the reference node (compose.yaml) of the .env's NETWORK (sepolia or
# hoodi), run as root. Idempotent:
#   0. reads the .env once, through lib/fsguard.py read-file (the walk from / described below
#      for the .env directory, then the file O_NOFOLLOW|O_NONBLOCK: a regular file with one
#      link owned by root or the sudo user, so never through a symlink or a hard link, and
#      never blocking on a FIFO), and works only on that copy, in a temp directory under /tmp
#      (never TMPDIR). Then it refuses, before it changes anything, an .env with a
#      line compose would read differently (lib/common.sh env_check) or a NETWORK it does not
#      know, --test-mode as root, a DATA_ROOT with whitespace or a backslash, and any
#      DATA_ROOT that lib/fsguard.py cannot prove safe: relative, a . or .. component, a
#      missing directory above it (setup.sh creates DATA_ROOT at most, never a parent), a
#      symlink anywhere from / down, a directory on the way not owned by root or open to group
#      or others (unless root-owned and sticky, like /tmp), a DATA_ROOT open to group or
#      others (so not /tmp itself), or below it a symlink, a wrong type, a hard-linked JWT, a
#      foreign owner, or a .staging that is not an empty 0700 directory.
#      fsguard walks every component through directory descriptors (openat, O_NOFOLLOW) and
#      changes things only through them, so nothing checked is resolved again. The .env
#      directory gets the same walk: no symlink from / down to it, and every directory on the
#      way and itself owned by root or by the sudo user (SUDO_UID) and closed to group and
#      others (unless root-owned and sticky);
#   1. creates the network's system users (no login shell, no home) unless they exist:
#      `reth` and `lighthouse` on Sepolia, `reth-<network>` and `lighthouse-<network>` on any
#      other network (lib/common.sh service_user), so two networks never share a user;
#   2. creates DATA_ROOT (0755) if missing (its parent must exist), and
#      DATA_ROOT/{reth,lighthouse}/data, each level owned by its service user, mode 0700;
#   3. writes ONE 32-byte hex JWT secret (os.urandom) as two copies, DATA_ROOT/reth/jwt.hex
#      and DATA_ROOT/lighthouse/jwt.hex, each 0600 and owned by its service user, created
#      O_EXCL in DATA_ROOT/.staging (root only, 0700), chowned there and renamed into place.
#      It is never echoed, logged, held in a shell variable or passed as an argument. An
#      existing secret is kept (one missing copy is restored from the other) unless
#      --rotate-jwt is given; two copies that differ, or that are not 64 hex characters, are
#      refused;
#   4. writes or refreshes DATA_ROOT, RETH_UID/GID and LIGHTHOUSE_UID/GID in .env (mode 0600),
#      through a descriptor of the .env directory that fsguard opens by the same walk from /;
#   5. verifies every mode and owner it set.
#
# Usage: sudo ops/ref-node/setup.sh [--root DIR] [--env-file FILE] [--rotate-jwt] [--test-mode]
#   --root DIR       DATA_ROOT (absolute, its parent existing); default: DATA_ROOT from .env,
#                    else /srv/ethswarm-ref on Sepolia and /srv/ethswarm-ref-<network> elsewhere
#   --env-file FILE  default: .env next to this script; it must exist (cp .env.example .env) as
#                    a regular file with one link, in a directory only root or the sudo user
#                    can change
#   --rotate-jwt     replace the secret (restart both services afterwards)
#   --test-mode      not as root (refused): create no users and chown nothing, record the
#                    caller's own uid and gid for both services, and accept directories it owns
#                    where root is required (the offline tests and a local smoke run)
# Exit: 0 done, 1 a check failed (differing or malformed JWT copies, a wrong mode or owner),
# 2 bad usage, a missing .env or a refused path. Needs python3.
set -euo pipefail
# The physical path (cd -P, pwd -P): a checkout reached through a symlinked home is checked at
# its real path by the walk from /, instead of being refused for the symlink.
here=$(cd -P "$(dirname "$0")" && pwd -P)
# shellcheck source=lib/common.sh
source "$here/lib/common.sh"
umask 077

usage() { sed -n 's/^# \{0,1\}//; /^Usage:/,/^Exit:/p' "$0" | sed '$d' >&2; exit 2; }
refuse() { echo "ERROR: $*" >&2; exit 2; }
fsguard() { python3 -I -B "$here/lib/fsguard.py" "$@"; }

root='' env_file="$here/.env" rotate=0 test_mode=0
while (($# > 0)); do
  case $1 in
    --root) (($# > 1)) || usage; root=$2; shift 2 ;;
    --env-file) (($# > 1)) || usage; env_file=$2; shift 2 ;;
    --rotate-jwt) rotate=1; shift ;;
    --test-mode) test_mode=1; shift ;;
    *) usage ;;
  esac
done

# The .env directory as given (never resolved: fsguard refuses a symlink on its path), made
# absolute against the physical working directory, and the sudo user who may own it.
env_dir=$(abs_dir "$(dirname -- "$env_file")") env_name=$(basename -- "$env_file")
operator=$(sudo_operator)
euid=$(id -u)
# The .env, read once through fsguard into a private copy that every step below uses: a path
# read could follow a symlink planted there, block on a FIFO, or see another file the second
# time. The temp directory is under /tmp whatever TMPDIR says (sudo -E could carry an
# operator-owned one).
work=$(mktemp -d /tmp/ref-node.XXXXXX)
trap 'rm -rf "$work"' EXIT
env_copy="$work/env"
read_env "$here/lib/fsguard.py" "$env_file" "$env_copy" ||
  refuse "$env_file: not read (it must be a regular file with one link, owned by root or you: cp .env.example .env and fill it first)"
env_check "$env_copy" "$env_file" >&2 || refuse "$env_file: fix the lines above"
network=$(env_get "$env_copy" NETWORK)
network_known "$network" || refuse "NETWORK must be sepolia or hoodi (in $env_file)"
reth_user=$(service_user "$network" reth) lh_user=$(service_user "$network" lighthouse)
[[ -n $root ]] || root=$(env_get "$env_copy" DATA_ROOT)
root=${root:-$(default_data_root "$network")}
root=${root%/}
# A backslash is refused too: nothing that reads DATA_ROOT back may decode it as an escape.
if [[ $root != /* || $root =~ [[:space:]] || $root == *\\* ]]; then
  refuse "DATA_ROOT must be an absolute path without whitespace or a backslash"
fi
if ((test_mode)) && ((euid == 0)); then
  refuse "--test-mode is not for root (it would record uid 0 for both services)"
fi
if ((test_mode == 0)) && ((euid != 0)); then
  refuse "run as root (or --test-mode for a run without users)"
fi

# 0. Every path check, before any change (users not created yet count as uid -1).
uid_of() { id -u "$1" 2>/dev/null || echo -1; }
if ((test_mode)); then
  fsguard check "$root" "$euid" "$euid" "$euid" || exit 2
else
  fsguard check "$root" "$euid" "$(uid_of "$reth_user")" "$(uid_of "$lh_user")" || exit 2
fi
fsguard check-dir "$env_dir" "$euid" "$operator" || exit 2

# 1. Users.
ensure_user() {
  if id -u "$1" >/dev/null 2>&1; then
    echo "user $1: exists"
  else
    useradd --system --user-group --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin "$1"
    echo "user $1: created"
  fi
}
if ((test_mode)); then
  reth_uid=$euid reth_gid=$(id -g)
  lh_uid=$reth_uid lh_gid=$reth_gid
  echo "test mode: no users, both services as uid $reth_uid"
else
  ensure_user "$reth_user"
  ensure_user "$lh_user"
  reth_uid=$(id -u "$reth_user") reth_gid=$(id -g "$reth_user")
  lh_uid=$(id -u "$lh_user") lh_gid=$(id -g "$lh_user")
fi

# 2., 3. Directories and the JWT copies, through descriptors only (lib/fsguard.py).
rc=0
fsguard install "$root" "$euid" "$reth_uid" "$reth_gid" "$lh_uid" "$lh_gid" "$rotate" \
  "$((1 - test_mode))" || rc=$?
((rc == 0)) || exit "$rc"

# 4. .env: DATA_ROOT and the ids, each line replaced in place or appended once; the new file
# is created O_EXCL next to .env and renamed over it, both through the descriptor of the .env
# directory that fsguard's walk from / opened (never reopened by name). The values reach awk
# through ENVIRON, which (unlike -v) decodes no backslash escape.
SETUP_SETS="DATA_ROOT=$root RETH_UID=$reth_uid RETH_GID=$reth_gid LIGHTHOUSE_UID=$lh_uid LIGHTHOUSE_GID=$lh_gid" awk '
  BEGIN {
    n = split(ENVIRON["SETUP_SETS"], a, " ")
    for (i = 1; i <= n; i++) { k = substr(a[i], 1, index(a[i], "=") - 1); key[i] = k; line[k] = a[i] }
  }
  {
    for (i = 1; i <= n; i++) {
      if (index($0, key[i] "=") == 1) {
        if (!(key[i] in done)) print line[key[i]]
        done[key[i]] = 1
        next
      }
    }
    print
  }
  END { for (i = 1; i <= n; i++) if (!(key[i] in done)) print line[key[i]] }
' "$env_copy" | fsguard write-file "$env_dir" "$env_name" "$euid" "$operator" || exit 2
echo "env: $env_file (DATA_ROOT, RETH_UID/GID, LIGHTHOUSE_UID/GID)"
got=$(file_mode_uid "$env_file")
if [[ $got != "600 $euid" ]]; then
  echo "verify: $env_file: $got (want 600 $euid): FAIL"
  exit 1
fi
echo "verify: $env_file: $got"
echo "setup OK"
