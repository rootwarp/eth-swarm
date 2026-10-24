#!/usr/bin/env bash
# Collect the run-log evidence for the reference node of the .env's NETWORK (sepolia or hoodi):
# run as root on the reference host once the node is synced. Prints the run log (Markdown: a
# verdict per criterion and the evidence under it) on stdout and writes no file, so the
# operator's own shell creates it:
#   sudo ops/ref-node/collect-run-log.sh > run-log-$(date -u +%Y%m%dT%H%M%SZ).md
# Criteria:
#   1. versions: an .env compose reads as the scripts do (lib/common.sh env_check) and no
#      compose variable overridden by the shell environment; each image's repo digests
#      (`docker image inspect`, which must hold the .env digest); each service's running
#      container (`docker compose ps`) checked through `docker inspect` (lib/beacon.py
#      container: the pinned image ID, Config.User the .env uid:gid and neither 0, read-only
#      root, CapDrop ALL and no CapAdd, only no-new-privileges, not privileged, host network,
#      no extra group or device, no host PID/IPC/UTS namespace, a private cgroup namespace,
#      docker's masked and read-only paths, exactly its data and read-only JWT mounts and a
#      noexec,nosuid,nodev /tmp tmpfs), every process's ruid/euid (`docker top`) the .env uid;
#      each container's `--version`; each image from its service's own repository, exactly
#      (lib/common.sh repo_check: ghcr.io/paradigmxyz/reth, sigp/lighthouse; checked first, so
#      a hand-edited row cannot vouch for another client's image or a lookalike); and the row
#      of README.md's release-note table for the network whose Image cell is the pinned image
#      and whose Client cell is the service (copied into the log): no row fails, so does
#      another client's row and a row that says the release does not schedule the network's
#      fork. The consensus-specs release the CL row records is printed, with a "spec version
#      differs from ours" line when it is not ours (lib/common.sh OUR_CONSENSUS_SPECS; not a
#      FAIL);
#   2. sync: --samples GETs of 127.0.0.1:<BEACON_API_PORT>/eth/v1/node/syncing, --interval
#      seconds apart: is_syncing, is_optimistic and el_offline false, head_slot within 2 of
#      the wall-clock slot from the node's own genesis time and slot length (lib/beacon.py
#      syncing). An acceptance PASS needs every requested sample taken, at least 12 of them,
#      and 3600 s or more from the first to the last; a shorter run that passes is DIAGNOSTIC
#      (not acceptance), and so is the whole log;
#   3. binds: each service still runs the container criterion 1 checked (the same id: one
#      recreated during the sync samples, maybe without the hardening, fails, since its image,
#      hardening and uid were never checked); from `ss -ltnp`, every listener on ENGINE_PORT and
#      BEACON_API_PORT is on 127.0.0.1, and every TCP listener either container's processes own
#      is on loopback or on that service's own p2p port (lib/common.sh check_listeners), so an
#      override that opens an RPC on a public address fails;
#   4. file modes: both JWT copies and Lighthouse's node key (<lighthouse data>/beacon/network/
#      key), opened only through lib/fsguard.py inspect (no symlink on the path, non-blocking,
#      a regular file with one link; nothing is read): mode 600 and owned by the service's
#      .env uid;
#   5. spec: the node's /eth/v1/config/spec against the network's pinned config, the same
#      lib/beacon.py spec-diff preflight.sh runs against the checkpoint providers;
#   6. finalized range: the finalized slot at least 128 slots past the oldest stored block
#      (/lighthouse/database/info anchor.oldest_block_slot; no anchor fails);
#   7. identity: peer_id, p2p_addresses and metadata.custody_group_count;
#   8. session: the m2a-session.toml lines, peer
#      /ip4/<public ip>/tcp/<LIGHTHOUSE_P2P_PORT>/p2p/<peer_id>;
#   9. end: each service still runs the container criterion 1 checked, compared once more
#      after everything else, so one recreated or stopped during sections 4 to 8 fails too.
# The .env is read once, through lib/fsguard.py read-file (lib/common.sh read_env: no symlink,
# FIFO or hard link, a directory and file only root or the sudo user own), and every read and
# compose call uses that private copy. Temp files go under /tmp, never TMPDIR.
# Every compose call is `docker compose -p <network>-ref --env-file <.env> -f compose.yaml`,
# and any COMPOSE_* key in the .env, and any COMPOSE_* variable, DOCKER_HOST, DOCKER_CONTEXT,
# DOCKER_CONFIG or DOCKER_TLS* in the environment (lib/common.sh docker_env_check), is refused,
# so the run log never looks at another network's project, another compose file or another
# daemon. Every docker call then gets DOCKER_CONFIG=<root's passwd home>/.docker
# (lib/common.sh docker_config_pin), so a HOME kept by sudo -E never supplies docker's config
# or CLI plugins.
# It reads no secret: the JWT copies are only fstat'ed, and the checkpoint URLs appear as
# scheme and host only. compose's own stderr (which can quote .env values) is discarded. The
# verdict line goes to stderr.
#
# Usage: sudo ops/ref-node/collect-run-log.sh [--samples N] [--interval S] [--public-ip IP]
#          [--env-file FILE] [--config YAML] > run-log.md
#   --samples N      sync samples (default 13)       --interval S  seconds between them (300)
#   --public-ip IP   the address the test host dials (default: the identity's global IPv4)
#   --env-file FILE  default: .env next to this script
#   --config YAML    default: crates/network-config/networks/<NETWORK>/config.yaml of this repo
# Exit: 0 every criterion passed in an acceptance run, 1 a criterion failed or the run was
# diagnostic, 2 bad usage, an .env that is missing or refused (a line compose reads
# differently, an unknown NETWORK, a port that is not a distinct port number) or a refused
# compose or docker variable in the environment. Needs docker,
# curl, ss (iproute2) and python3.
set -euo pipefail
here=$(cd -P "$(dirname "$0")" && pwd -P)
# shellcheck source=lib/common.sh
source "$here/lib/common.sh"

usage() { sed -n 's/^# \{0,1\}//; /^Usage:/,/^Exit:/p' "$0" | sed '$d' >&2; exit 2; }
refuse() { echo "ERROR: $*" >&2; exit 2; }

# Acceptance: at least this many samples, spanning at least this many seconds.
MIN_SAMPLES=12 MIN_SPAN=3600

samples=13 interval=300 public_ip='' env_file="$here/.env" config=''
while (($# > 0)); do
  (($# > 1)) || usage
  case $1 in
    --samples) samples=$2 ;;
    --interval) interval=$2 ;;
    --public-ip) public_ip=$2 ;;
    --env-file) env_file=$2 ;;
    --config) config=$2 ;;
    *) usage ;;
  esac
  shift 2
done
# Decimal only: a leading zero is octal in bash arithmetic (08 would be an error, 010 is 8).
if [[ ! $samples =~ ^[1-9][0-9]*$ || ! $interval =~ ^[0-9]+$ ]]; then usage; fi
samples=$((10#$samples)) interval=$((10#$interval))
# A control character in the path: a command substitution would drop a trailing newline and
# check another file than the one named.
env_path_check "$env_file" || exit 2
# The .env, read once through fsguard into a private copy that every read below and every
# compose call (--env-file) uses (lib/common.sh read_env), in a temp directory under /tmp
# whatever TMPDIR says.
work=$(mktemp -d /tmp/ref-node.XXXXXX)
trap 'rm -rf "$work"' EXIT
envc="$work/env"
read_env "$here/lib/fsguard.py" "$env_file" "$envc" ||
  refuse "$env_file: not read (a regular file with one link, owned by root or you)"
env_check "$envc" "$env_file" >&2 || refuse "$env_file: fix the lines above"
network=$(env_get "$envc" NETWORK)
network_known "$network" || refuse "NETWORK must be sepolia or hoodi (in $env_file)"
docker_env_check >&2 || exit 2
# Every docker call reads DOCKER_CONFIG, the .docker of root's own home, never $HOME/.docker:
# under sudo -E that is the operator's, with its CLI plugins and its context (lib/common.sh).
docker_config_pin >&2 || exit 2
ports_check "$envc" >&2 || refuse "$env_file: fix the ports above"
config=${config:-$here/../../crates/network-config/networks/$network/config.yaml}
port() { env_get "$envc" "$1"; }
engine_port=$(port ENGINE_PORT) api_port=$(port BEACON_API_PORT)
reth_p2p=$(port RETH_P2P_PORT) lh_p2p=$(port LIGHTHOUSE_P2P_PORT)
# Sepolia, Hoodi: the network's name as a title.
title=$(printf '%s' "${network:0:1}" | tr '[:lower:]' '[:upper:]')${network:1}

api=http://127.0.0.1:$api_port
helper=(python3 -I -B "$here/lib/beacon.py")
compose=(docker compose -p "$(compose_project "$network")" --env-file "$envc" -f "$here/compose.yaml")
root=$(env_get "$envc" DATA_ROOT)
root=${root:-$(default_data_root "$network")}
body="$work/body.md"
: > "$body"
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
providers=''
for key in CHECKPOINT_SYNC_URL CHECKPOINT_SYNC_URL_2; do
  url=$(env_get "$envc" "$key")
  if [[ -n $url ]]; then providers="${providers:+$providers, }$(redact_url "${url%/}")"; fi
done

names=() results=()
# record <criterion> <0|1|DIAGNOSTIC>: its verdict, in order.
record() {
  names+=("$1")
  case $2 in
    0) results+=(PASS) ;;
    DIAGNOSTIC) results+=(DIAGNOSTIC) ;;
    *) results+=(FAIL) ;;
  esac
}
section() { printf '\n## %s. %s\n\n' "$((${#names[@]} + 1))" "$1" >> "$body"; }
# block: stdin as a fenced block in the body.
block() { { echo '```'; cat; echo '```'; } >> "$body"; }
# get <API path> <file>: GET the local Beacon API into $work/<file>.
get() { fetch "$api$1" "$work/$2"; }
# running_ctr <service>: the id of the service's running container now, or nothing. compose's
# stderr is dropped: it can quote .env values. sed reads the whole answer (head -1 would close
# the pipe on a longer one).
running_ctr() {
  "${compose[@]}" ps -q --status running "$1" 2>/dev/null | sed -n 1p || true
}

# 1. Versions, digests, release notes and the running containers.
section "Client versions, image digests and running containers"
bad=0
v="$work/versions.txt"
env_overrides "$envc" >> "$v" || bad=1
for svc in reth lighthouse; do
  if [[ $svc == reth ]]; then pre=RETH; else pre=LIGHTHOUSE; fi
  image=$(env_get "$envc" ${pre}_IMAGE) want_uid=$(env_get "$envc" ${pre}_UID)
  want_gid=$(env_get "$envc" ${pre}_GID)
  {
    echo "${pre}_IMAGE=$image"
    if ! image_pinned "$image"; then
      echo "${pre}_IMAGE: not pinned as repo:tag@sha256:<64 hex>: FAIL"; bad=1
    else
      digest=${image##*@} tag=${image%@*}
      tag=${tag##*:}
      digests=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image" 2>&1) || true
      printf 'RepoDigests:\n%s\n' "$digests"
      if [[ $'\n'$digests$'\n' != *"@$digest"$'\n'* ]]; then
        echo "${pre}_IMAGE: the local image's RepoDigests lack $digest: FAIL"; bad=1
      fi
      # The repository first: README.md is hand-editable, so its Client cell alone never
      # vouches; an image from another repository has no row looked up.
      row='' client=''
      if repo_line=$(repo_check "${pre}_IMAGE" "$svc" "$image"); then
        row=$(release_row "$here/README.md" "$network" "$svc" "$image")
        client=$(release_client "$here/README.md" "$network" "$image")
      fi
      if [[ -n $repo_line ]]; then
        echo "$repo_line: FAIL"; bad=1
      elif [[ -z $row && -n $client ]]; then
        echo "$svc $tag: ${pre}_IMAGE is a $client image in README.md's $network table, not $svc's: FAIL"; bad=1
      elif [[ -z $row ]]; then
        echo "$svc $tag: no $network row in README.md's release notes for this image: FAIL"; bad=1
      else
        if [[ ${row%%|*} == yes ]]; then
          echo "release notes: $svc $tag schedules $network's Gloas / Amsterdam fork (README.md): PASS"
        else
          echo "release notes: $svc $tag does not schedule $network's Gloas / Amsterdam fork (README.md): FAIL"; bad=1
        fi
        specs=${row#*|}
        if [[ $svc == lighthouse ]]; then
          if [[ $specs == "$OUR_CONSENSUS_SPECS" ]]; then
            echo "$svc $tag targets consensus-specs $specs (README.md), the same as ours"
          else
            echo "$svc $tag targets consensus-specs ${specs:-(not recorded)} (README.md): spec version differs from ours ($OUR_CONSENSUS_SPECS); recorded, not a FAIL"
          fi
        fi
      fi
    fi
    # The running container: the pinned image, compose.yaml's hardening, and its uid
    # (configured and real) the .env one, never 0. Its id is kept: section 3 fails if the
    # service runs another container by then.
    ctr=$(running_ctr "$svc")
    printf -v "checked_ctr_$svc" '%s' "$ctr"
    if [[ -z $ctr ]]; then
      echo "$svc: no running container: FAIL"; bad=1
    else
      pinned_id=$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null) || pinned_id=unknown
      docker inspect "$ctr" > "$work/inspect-$svc.json" 2>/dev/null || true
      "${helper[@]}" container "$work/inspect-$svc.json" "$svc" "$root" "$want_uid" "$want_gid" "$pinned_id" \
        > "$work/container-$svc.txt" 2>&1 || bad=1
      # The id is data: prefixed by printf, never put in a sed program.
      while IFS= read -r line; do printf '%s container %s: %s\n' "$svc" "$ctr" "$line"; done < "$work/container-$svc.txt"
      docker top "$ctr" -o ruid,euid,pid,comm > "$work/top-$svc.txt" 2>/dev/null || true
      procs=$(awk 'NR > 1 { print $1 "/" $2 }' "$work/top-$svc.txt" | sort -u | tr '\n' ' ')
      procs=${procs% }
      uid_ok=1
      [[ -n $procs ]] || uid_ok=0
      for p in $procs; do [[ $p == "$want_uid/$want_uid" ]] || uid_ok=0; done
      if [[ ! $want_uid =~ ^[0-9]+$ ]] || ((10#$want_uid == 0)); then uid_ok=0; fi
      if ((uid_ok)); then
        echo "$svc container $ctr: processes ruid/euid ${procs} (want $want_uid): PASS"
      else
        echo "$svc container $ctr: processes ruid/euid ${procs:-none} (want $want_uid): FAIL"; bad=1
      fi
      version=$("${compose[@]}" exec -T "$svc" "$svc" --version 2>/dev/null) || { echo "$svc --version: FAIL"; bad=1; }
      printf '%s --version:\n%s\n' "$svc" "$version"
    fi
    echo
  } >> "$v"
done
block < "$v"
printf 'Release notes (from ops/ref-node/README.md, %s):\n\n%s\n' "$network" "$(release_notes "$here/README.md" "$network")" >> "$body"
record "Client versions, image digests, release notes, running containers (pinned image, non-root uid)" $bad

# 2. Sync samples.
section "Sync: /eth/v1/node/syncing"
bad=0
get /eth/v1/beacon/genesis genesis.json || true
get /eth/v1/config/spec spec.json || true
printf 'Every %ss, %s sample(s): is_syncing, is_optimistic and el_offline false; head_slot within 2 of the wall-clock slot.\n\n' \
  "$interval" "$samples" >> "$body"
printf '| # | UTC | sample |\n|---|---|---|\n' >> "$body"
taken=0 first='' last=''
while ((taken < samples)); do
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ) now=$(date +%s)
  first=${first:-$now} last=$now
  if get /eth/v1/node/syncing syncing.json; then
    line=$("${helper[@]}" syncing "$work/syncing.json" "$work/genesis.json" "$work/spec.json" "$now" 2>&1) || bad=1
  else
    line="GET /eth/v1/node/syncing failed: FAIL"; bad=1
  fi
  taken=$((taken + 1))
  printf '| %s | %s | %s |\n' "$taken" "$ts" "$(printf '%s' "$line" | tr '\n|' ' /')" >> "$body"
  if ((taken < samples)); then sleep "$interval"; fi
done
span=$((last - first))
if ((taken != samples)); then bad=1; fi
if ((bad == 0 && (taken < MIN_SAMPLES || span < MIN_SPAN))); then
  kind="diagnostic (not acceptance: needs $MIN_SAMPLES samples over $MIN_SPAN s)"
  sync_verdict=DIAGNOSTIC
else
  kind=acceptance sync_verdict=$bad
fi
printf '\n%s sample(s) taken of %s, first to last %s s: %s\n' "$taken" "$samples" "$span" "$kind" >> "$body"
record "Synced, not optimistic, EL online, head within 2 slots ($taken samples over $span s)" "$sync_verdict"

# 3. Binds: the containers criterion 1 checked, the API ports on loopback, and no other public
# TCP listener of either container. The containers' ids and pids and the sockets are read
# together, here, not an hour earlier in section 1: a container restarted during the sync
# samples has new pids, and one recreated then is another container, never checked.
section "Listening sockets: ss -ltnp"
bad=0
# pids_of <container id>: the container's host pids, space-separated.
pids_of() {
  [[ -n $1 ]] || return 0
  docker top "$1" -o ruid,euid,pid,comm 2>/dev/null | awk 'NR > 1 && $3 ~ /^[0-9]+$/ { print $3 }' | sort -un | tr '\n' ' ' | sed 's/ $//'
}
# same_ctr <service> <container id now>: one verdict line; 1 unless it is the one checked.
same_ctr() {
  local checked_var="checked_ctr_$1"
  local checked=${!checked_var}
  if [[ -z $checked ]]; then
    echo "$1: no container was running for criterion 1 to check: FAIL"; return 1
  elif [[ -z $2 ]]; then
    echo "$1: container $checked, the one criterion 1 checked, no longer runs: FAIL"; return 1
  elif [[ $2 != "$checked" ]]; then
    echo "$1: container $2 runs now, not $checked, the one criterion 1 checked (recreated during the run; its image, hardening and uid are unchecked): FAIL"; return 1
  fi
  echo "$1: container $checked, the one criterion 1 checked, still runs: PASS"
}
reth_ctr=$(running_ctr reth) lighthouse_ctr=$(running_ctr lighthouse)
reth_pids=$(pids_of "$reth_ctr") lighthouse_pids=$(pids_of "$lighthouse_ctr")
ss_out=$(ss -ltnp 2>&1) || bad=1
{
  same_ctr reth "$reth_ctr" || bad=1
  same_ctr lighthouse "$lighthouse_ctr" || bad=1
  echo
  printf '%s\n' "$ss_out" | SS_PORTS=" $engine_port $api_port " SS_PIDS=" $reth_pids $lighthouse_pids " awk '
    BEGIN { ports = ENVIRON["SS_PORTS"]; pids = ENVIRON["SS_PIDS"] }
    NR == 1 { print; next }
    { p = $4; sub(/.*:/, "", p); mine = index(ports, " " p " ") }
    { rest = $0; while (!mine && match(rest, /pid=[0-9]+/)) { if (index(pids, " " substr(rest, RSTART + 4, RLENGTH - 4) " ")) mine = 1; rest = substr(rest, RSTART + RLENGTH) } }
    mine'
  echo
  check_binds "$ss_out" "$engine_port" "$api_port" || bad=1
  check_listeners "$ss_out" reth "$reth_pids" "$reth_p2p" || bad=1
  check_listeners "$ss_out" lighthouse "$lighthouse_pids" "$lh_p2p" || bad=1
} > "$work/binds.txt"
block < "$work/binds.txt"
record "The containers of criterion 1 still run; Engine ($engine_port) and Beacon ($api_port) API on 127.0.0.1 only; no other non-loopback TCP listener but the p2p ports" $bad

# 4. File modes, through fsguard (a link or a FIFO is refused, nothing is read).
section "File modes: mode and owner uid (lib/fsguard.py inspect)"
bad=0
# mode_line <path> <uid>: one verdict line.
mode_line() {
  local got reason
  if got=$(python3 -I -B "$here/lib/fsguard.py" inspect "$1" 2> "$work/inspect.err"); then
    check_mode_owner "$1" "$got" "$2"
  else
    reason=$(sed -n '1s/^ERROR: //p' "$work/inspect.err")
    echo "$1: ${reason#"$1: "} (want 600 $2): FAIL"
    return 1
  fi
}
reth_uid=$(env_get "$envc" RETH_UID) lh_uid=$(env_get "$envc" LIGHTHOUSE_UID)
{
  echo "owners: reth $reth_uid (user $(service_user "$network" reth)), lighthouse $lh_uid (user $(service_user "$network" lighthouse))"
  mode_line "$root/reth/jwt.hex" "$reth_uid" || bad=1
  mode_line "$root/lighthouse/jwt.hex" "$lh_uid" || bad=1
  mode_line "$root/lighthouse/data/beacon/network/key" "$lh_uid" || bad=1
} > "$work/modes.txt"
block < "$work/modes.txt"
record "JWT copies and node key 600, regular files owned by their service's uid" $bad

# 5. Spec against the pinned config.
section "Spec: /eth/v1/config/spec against the pinned $title config"
bad=0
if [[ -s $work/spec.json ]]; then
  "${helper[@]}" spec-diff "$config" "$work/spec.json" > "$work/spec-diff.txt" 2>&1 || bad=1
else
  echo "GET /eth/v1/config/spec failed: FAIL" > "$work/spec-diff.txt"; bad=1
fi
block < "$work/spec-diff.txt"
record "Spec diff empty (fork versions, fork epochs, BLOB_SCHEDULE)" $bad

# 6. Finalized range.
section "Finalized range: headers/finalized against /lighthouse/database/info"
bad=0
if get /eth/v1/beacon/headers/finalized finalized.json && get /lighthouse/database/info dbinfo.json; then
  "${helper[@]}" finalized "$work/finalized.json" "$work/dbinfo.json" > "$work/finalized.txt" 2>&1 || bad=1
else
  echo "GET /eth/v1/beacon/headers/finalized or /lighthouse/database/info failed: FAIL" > "$work/finalized.txt"; bad=1
fi
block < "$work/finalized.txt"
record "Finalized slot at least 128 slots past the oldest stored block" $bad

# 7. Identity, 8. the session config. The helper writes values as `key: value` and problems as
# `error: ...`, so only a well-formed value line counts.
section "Identity: /eth/v1/node/identity"
bad=0
if get /eth/v1/node/identity identity.json; then
  "${helper[@]}" identity "$work/identity.json" "$public_ip" "$lh_p2p" > "$work/identity.txt" 2>&1 || true
else
  echo "error: GET /eth/v1/node/identity failed" > "$work/identity.txt"
fi
grep -v '^multiaddr: ' "$work/identity.txt" | block
if ! grep -Eq '^peer_id: [1-9A-HJ-NP-Za-km-z]{32,128}$' "$work/identity.txt" ||
  ! grep -Eq '^custody_group_count: [0-9]+$' "$work/identity.txt"; then
  bad=1
fi
record "Peer ID and custody_group_count recorded" $bad

section "m2a-session config (/etc/ethswarm/m2a-session.toml on the test host)"
bad=0
multiaddr=$(awk 'index($0, "multiaddr: ") == 1 && !seen { print substr($0, 12); seen = 1 }' "$work/identity.txt")
if [[ ! $multiaddr =~ ^/ip4/[0-9.]+/tcp/[0-9]+/p2p/[1-9A-HJ-NP-Za-km-z]{32,128}$ || $multiaddr != /ip4/*/tcp/"$lh_p2p"/p2p/* ]]; then
  multiaddr=''
fi
if [[ -z $multiaddr ]]; then
  { grep '^error: ' "$work/identity.txt" || echo "error: no multiaddr"; } | block
  bad=1
else
  if [[ -n $(env_get "$envc" TRUSTED_PEERS) ]]; then trusted=true; else trusted=false; fi
  {
    echo '```toml'
    echo "network = \"$network\""
    echo "peer = \"$multiaddr\""
    # Loopback only, so the forward is not open to the network, and ssh exits if another local
    # account holds the port first.
    echo "# Over the tunnel: ssh -f -N -o ExitOnForwardFailure=yes -L 127.0.0.1:$api_port:127.0.0.1:$api_port <ref-host>"
    echo "reference_api_url = \"http://127.0.0.1:$api_port\""
    echo 'node_key = "/var/lib/m2a-session/node.key"'
    echo "trusted_by_reference = $trusted   # true only once TRUSTED_PEERS holds the session's peer ID"
    echo 'run_as = "m2a-session"   # the only run_as the session takes'
    echo '# Install it owned by root, mode 0644, in the root-owned /etc/ethswarm: the session'
    echo '# refuses a config or a directory on its path that its own user can write.'
    echo '```'
  } >> "$body"
fi
record "m2a-session peer multiaddr" $bad

# 9. The containers once more, last: one recreated or stopped while sections 4 to 8 ran was
# never checked either.
section "Containers at the end of the run"
bad=0
{
  same_ctr reth "$(running_ctr reth)" || bad=1
  same_ctr lighthouse "$(running_ctr lighthouse)" || bad=1
} > "$work/final.txt"
block < "$work/final.txt"
record "The containers of criterion 1 still run at the end" $bad

# The log: header, verdict table, evidence. FAIL beats DIAGNOSTIC beats PASS.
overall=PASS
for r in "${results[@]}"; do
  if [[ $r == FAIL ]]; then overall=FAIL; elif [[ $r == DIAGNOSTIC && $overall == PASS ]]; then overall=DIAGNOSTIC; fi
done
headline=$overall
if [[ $overall == DIAGNOSTIC ]]; then headline="DIAGNOSTIC (not acceptance)"; fi
{
  echo "# $title reference node run log"
  echo
  echo "- Started: $started; written by ops/ref-node/collect-run-log.sh"
  echo "- Network: $network; checkpoint providers: ${providers:-none}"
  echo "- Overall: **$headline**"
  echo
  echo "| # | Criterion | Verdict |"
  echo "|---|---|---|"
  i=0
  while ((i < ${#names[@]})); do
    echo "| $((i + 1)) | ${names[$i]} | ${results[$i]} |"
    i=$((i + 1))
  done
  cat "$body"
}
echo "run log: $headline" >&2
[[ $overall == PASS ]]
