#!/usr/bin/env bash
# Collect the run-log evidence for the Sepolia reference node: run as root on the reference
# host once the node is synced. Prints the run log (Markdown: a verdict per criterion and the
# evidence under it) on stdout and writes no file, so the operator's own shell creates it:
#   sudo ops/sepolia-ref/collect-run-log.sh > run-log-$(date -u +%Y%m%dT%H%M%SZ).md
# Criteria:
#   1. versions: an .env compose reads as the scripts do (lib/common.sh env_check) and no
#      compose variable overridden by the shell environment; each image's repo digests
#      (`docker image inspect`, which must hold the .env digest); each service's running
#      container (`docker compose ps`) checked through `docker inspect` (lib/beacon.py
#      container: the pinned image ID, Config.User the .env uid and never 0, read-only root,
#      CapDrop ALL and no CapAdd, no-new-privileges, not privileged, host network, exactly its
#      data and read-only JWT mounts and a /tmp tmpfs), every process's ruid/euid
#      (`docker top`) the .env uid; each container's `--version`; and the README.md
#      release-note line for each pinned tag (copied into the log; a tag README.md does not
#      record fails);
#   2. sync: --samples GETs of 127.0.0.1:5052/eth/v1/node/syncing, --interval seconds apart:
#      is_syncing, is_optimistic and el_offline false, head_slot within 2 of the wall-clock slot
#      (lib/beacon.py syncing). An acceptance PASS needs every requested sample taken, at
#      least 12 of them, and 3600 s or more from the first to the last; a shorter run that
#      passes is DIAGNOSTIC (not acceptance), and so is the whole log;
#   3. localhost binds: the `ss -ltnp` lines for 8551 and 5052, every one on 127.0.0.1;
#   4. file modes: `stat -c '%a %U'` of both JWT copies and Lighthouse's node key
#      (<lighthouse data>/beacon/network/key): `600` and the owning service user;
#   5. spec: the node's /eth/v1/config/spec against the pinned Sepolia config, the same
#      lib/beacon.py spec-diff preflight.sh runs against the checkpoint endpoint;
#   6. finalized range: the finalized slot at least 128 slots past the oldest stored block
#      (/lighthouse/database/info anchor.oldest_block_slot; no anchor fails);
#   7. identity: peer_id, p2p_addresses and metadata.custody_group_count;
#   8. session: the m2a-session.toml lines, peer /ip4/<public ip>/tcp/9000/p2p/<peer_id>.
# It reads no secret: the JWT copies are only stat'ed, and CHECKPOINT_SYNC_URL is only compared
# with the environment, never printed. compose's own stderr (which can quote .env values) is
# discarded. The verdict line goes to stderr.
#
# Usage: sudo ops/sepolia-ref/collect-run-log.sh [--samples N] [--interval S] [--public-ip IP]
#          [--env-file FILE] [--config YAML] > run-log.md
#   --samples N      sync samples (default 13)       --interval S  seconds between them (300)
#   --public-ip IP   the address the test host dials (default: the identity's global IPv4)
#   --env-file FILE  default: .env next to this script
#   --config YAML    default: crates/network-config/networks/sepolia/config.yaml of this repo
# Exit: 0 every criterion passed in an acceptance run, 1 a criterion failed or the run was
# diagnostic, 2 bad usage or an .env that is missing or refused. Needs docker, curl, ss
# (iproute2), GNU stat and python3.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
source "$here/lib/common.sh"

usage() { sed -n 's/^# \{0,1\}//; /^Usage:/,/^Exit:/p' "$0" | sed '$d' >&2; exit 2; }
refuse() { echo "ERROR: $*" >&2; exit 2; }

# Acceptance: at least this many samples, spanning at least this many seconds.
MIN_SAMPLES=12 MIN_SPAN=3600

samples=13 interval=300 public_ip='' env_file="$here/.env"
config="$here/../../crates/network-config/networks/sepolia/config.yaml"
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
[[ -f $env_file ]] || refuse "$env_file: no such file"
env_check "$env_file" >&2 || refuse "$env_file: fix the lines above"

api=http://127.0.0.1:5052
helper=(python3 -I "$here/lib/beacon.py")
compose=(docker compose --env-file "$env_file" -f "$here/compose.yaml")
root=$(env_get "$env_file" DATA_ROOT)
root=${root:-/srv/ethswarm-ref}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
body="$work/body.md"
: > "$body"
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)

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

# 1. Versions, digests and the running containers.
section "Client versions, image digests and running containers"
bad=0
v="$work/versions.txt"
env_overrides "$env_file" >> "$v" || bad=1
release_notes=$(awk '/<!-- release-notes:begin -->/ {on = 1; next} /<!-- release-notes:end -->/ {on = 0} on' "$here/README.md")
for svc in reth lighthouse; do
  if [[ $svc == reth ]]; then pre=RETH gh=paradigmxyz/reth; else pre=LIGHTHOUSE gh=sigp/lighthouse; fi
  image=$(env_get "$env_file" ${pre}_IMAGE) want_uid=$(env_get "$env_file" ${pre}_UID)
  {
    echo "${pre}_IMAGE=$image"
    if ! image_pinned "$image"; then
      echo "${pre}_IMAGE: not pinned as repo:tag@sha256:<64 hex>: FAIL"; bad=1
    else
      digest=${image##*@} tag=${image%@*}
      tag=${tag##*:}
      digests=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image" 2>&1) || true
      printf 'RepoDigests:\n%s\n' "$digests"
      if ! printf '%s\n' "$digests" | grep -q "@$digest\$"; then
        echo "${pre}_IMAGE: the local image's RepoDigests lack $digest: FAIL"; bad=1
      fi
      if ! printf '%s\n' "$release_notes" | grep -qF "github.com/$gh/releases/tag/$tag)"; then
        echo "$svc $tag: no release-note line in README.md: FAIL"; bad=1
      fi
    fi
    # The running container: the pinned image, compose.yaml's hardening, and its uid
    # (configured and real) the .env one, never 0. compose's stderr is dropped: it can quote
    # .env values.
    ctr=$("${compose[@]}" ps -q --status running "$svc" 2>/dev/null | head -1) || ctr=''
    if [[ -z $ctr ]]; then
      echo "$svc: no running container: FAIL"; bad=1
    else
      pinned_id=$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null) || pinned_id=unknown
      docker inspect "$ctr" > "$work/inspect-$svc.json" 2>/dev/null || true
      "${helper[@]}" container "$work/inspect-$svc.json" "$svc" "$root" "$want_uid" "$pinned_id" \
        > "$work/container-$svc.txt" 2>&1 || bad=1
      sed "s|^|$svc container $ctr: |" "$work/container-$svc.txt"
      procs=$(docker top "$ctr" -o ruid,euid,pid,comm 2>/dev/null | awk 'NR > 1 { print $1 "/" $2 }' | sort -u | tr '\n' ' ')
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
printf 'Release notes (from ops/sepolia-ref/README.md):\n\n%s\n' "$release_notes" >> "$body"
record "Client versions, image digests, running containers (pinned image, non-root uid)" $bad

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

# 3. Localhost binds.
section "Engine and Beacon API binds: ss -ltnp"
bad=0
ss_out=$(ss -ltnp 2>&1) || bad=1
{
  printf '%s\n' "$ss_out" | awk 'NR == 1 || $4 ~ /:(8551|5052)$/'
  echo
  check_binds "$ss_out" 8551 5052 || bad=1
} > "$work/binds.txt"
block < "$work/binds.txt"
record "Engine (8551) and Beacon (5052) API on 127.0.0.1 only" $bad

# 4. File modes.
section "File modes: stat -c '%a %U'"
bad=0
for spec in "$root/reth/jwt.hex reth" "$root/lighthouse/jwt.hex lighthouse" \
  "$root/lighthouse/data/beacon/network/key lighthouse"; do
  path=${spec% *} user=${spec##* }
  got=$(stat -c '%a %U' "$path" 2>/dev/null) || got=
  check_mode_owner "$path" "$got" "$user" >> "$work/modes.txt" || bad=1
done
block < "$work/modes.txt"
record "JWT copies and node key 600, owned by their service user" $bad

# 5. Spec against the pinned config.
section "Spec: /eth/v1/config/spec against the pinned Sepolia config"
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
  "${helper[@]}" identity "$work/identity.json" "$public_ip" > "$work/identity.txt" 2>&1 || true
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
multiaddr=$(sed -n -E 's|^multiaddr: (/ip4/[0-9.]+/tcp/9000/p2p/[1-9A-HJ-NP-Za-km-z]{32,128})$|\1|p' "$work/identity.txt")
if [[ -z $multiaddr ]]; then
  { grep '^error: ' "$work/identity.txt" || echo "error: no multiaddr"; } | block
  bad=1
else
  if [[ -n $(env_get "$env_file" TRUSTED_PEERS) ]]; then trusted=true; else trusted=false; fi
  {
    echo '```toml'
    echo 'network = "sepolia"'
    echo "peer = \"$multiaddr\""
    echo '# Over the tunnel: ssh -N -L 5052:127.0.0.1:5052 <ref-host>'
    echo 'reference_api_url = "http://127.0.0.1:5052"'
    echo 'node_key = "/var/lib/m2a-session/node.key"'
    echo "trusted_by_reference = $trusted   # true only once TRUSTED_PEERS holds the session's peer ID"
    echo '```'
  } >> "$body"
fi
record "m2a-session peer multiaddr" $bad

# The log: header, verdict table, evidence. FAIL beats DIAGNOSTIC beats PASS.
overall=PASS
for r in "${results[@]}"; do
  if [[ $r == FAIL ]]; then overall=FAIL; elif [[ $r == DIAGNOSTIC && $overall == PASS ]]; then overall=DIAGNOSTIC; fi
done
headline=$overall
if [[ $overall == DIAGNOSTIC ]]; then headline="DIAGNOSTIC (not acceptance)"; fi
{
  echo "# Sepolia reference node run log"
  echo
  echo "- Started: $started; written by ops/sepolia-ref/collect-run-log.sh"
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
