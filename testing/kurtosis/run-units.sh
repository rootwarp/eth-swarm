#!/usr/bin/env bash
# Runs the probe's three systemd units (ops/probe) against a running Kurtosis devnet enclave
# (README.md, "Probe units under systemd") and fails closed at every step:
#   1. reads the enclave: its CL services (kurtosis enclave inspect, at least 2), each CL's beacon
#      API on the host (kurtosis port print <enclave> <service> http) and its identity (peer ID,
#      ENR, its address on the enclave's Docker network), and the network files (kurtosis files
#      download <enclave> el_cl_genesis_data);
#   2. builds the Linux binaries in RUST_IMAGE, pinned by digest, with the cargo volume
#      ethswarm-cargo, into target/linux (not with --skip-build): the build container sees the
#      repo read-only and can write only target/linux;
#   3. starts a privileged systemd container (SYSTEMD_IMAGE, pinned by digest) on the enclave's
#      network kt-<enclave>, with only ops/, target/linux/release, the trusted setup, units/
#      and the run's stage mounted, all read-only, and installs the units as ops/probe/README.md
#      says: the lines of its "Install" block run as they are, in two parts (the users first, so
#      that the configs can name their IDs). Two devnet-only additions come from units/: a
#      cl-verify unit, which runs as the ethswarm-verify user and group that the install's
#      usermod line names, and a drop-in for each probe unit that runs the anchor check over
#      plain HTTP with the minimal preset and turns journald's rate limit off (a recorded
#      deviation). Before anything starts, the drop-in must be each unit's own ExecStartPre=
#      with only those two flags added;
#   4. checks that each installed unit equals its file in ops/probe byte for byte, waits until the
#      three units are active, then holds them --minutes, sampling cl-p2p's and cl-chain's
#      /metrics and the units' states every --sample-secs into the run directory. Then it sends
#      its own DataColumnSidecarsByRange and ByRoot requests to the probe unit's libp2p port and
#      compares the answers with the store (devnet-probe answers, in the container);
#   5. stops the units (each must exit 0), keeps their journals, and judges the run: no unit left
#      its active state or restarted; no journal holds the node key in hex or base64, and
#      journald suppressed no line of a probe unit; the last sample has topic_msg_sent_counts,
#      topic_msg_sent_bytes and topic_msg_published at 0 and a Status-valid peer per CL;
#      cl-chain answered column hand-offs and stored columns; every answer to our own column
#      requests was the store's; check-devnet.sh --probe-log on cl-p2p's log passes (no reason-3
#      Goodbye from any CL);
#   6. removes the container (not with --keep) and the staged node key, then exits.
# kurtosis is called only for enclave inspect, port print and files download: the script never
# launches, cleans or removes an enclave, and never runs `kurtosis clean`. Docker objects it
# removes are only the containers this run named (ethswarm-units-<T>-<pid>, and its build
# container); the cargo volume stays. Every step that can take long is a background job, the
# leader of its own process group, bounded in time (lib/jobs.sh, the machinery of run-pair.sh),
# and an EXIT/INT/TERM/HUP/PIPE trap stops the jobs and removes the container on every exit.
# The run directory is target/kurtosis/units-<T>-<pid>, 0700 like everything the script writes
# (umask 077): the configs, every sample, the journals, counters.txt and the checks' logs. While
# a job runs, its job-groups file lists the process group of each.
#
# Usage: testing/kurtosis/run-units.sh [--minutes N] [--sample-secs S] [--api-port P]
#                                      [--skip-build] [--keep] ENCLAVE
#   --minutes N      how long the units run once active (default 10, 1 to 1440)
#   --sample-secs S  seconds between samples (default 10, 1 to 600)
#   --api-port P     the CLs' beacon API port on the enclave network (default 4000, the
#                    ethereum-package's)
#   --skip-build     use the binaries already in target/linux/release
#   --keep           leave the container running at the end, and print how to remove it
# Exit: 0 every criterion passed; 1 a criterion failed; 2 a usage or setup error (a missing tool,
# an enclave or network that cannot be read, a failed build, a container that does not boot, an
# install step or setup write that fails, a drop-in that is not the units' own check, a step past
# its time limit); 3 DIAGNOSTIC: every criterion passed, but check-devnet.sh was DIAGNOSTIC; 129
# on HUP, 130 on INT, 141 on PIPE, 143 on TERM.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# The images, by tag and index digest (docker buildx imagetools inspect <tag>, 2026-10-25).
RUST_IMAGE='rust:1.99-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8'
SYSTEMD_IMAGE='debian:trixie@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308'
CARGO_VOLUME=ethswarm-cargo
BINARIES=(cl-chain cl-p2p cl-discv5 anchor-fetch cl-verify devnet-probe)
# The devnet flags of the drop-in's anchor check, added to each unit's own ExecStartPre=.
DEVNET_FLAGS=' --allow-insecure-http --preset minimal'
TRUSTED_SETUP=crates/crypto-kzg/data/trusted_setup_4096.json
UNITS=(ethswarm-chain ethswarm-discv5 ethswarm-p2p)
SERVICE_RE='^cl-[0-9]+-[a-z0-9]+(-[a-z0-9]+)*$'
KURTOSIS_TIMEOUT=60  # seconds for one kurtosis call
DOCKER_TIMEOUT=60    # seconds for one docker exec, inspect or run -d
CURL_TIMEOUT=10      # seconds for one beacon API request from the host
BUILD_TIMEOUT=5400   # seconds for the Linux build
BOOT_TIMEOUT=600     # seconds for the container's packages and systemd
INSTALL_TIMEOUT=300  # seconds for one install step
VERIFY_TIMEOUT=120   # seconds for cl-verify's socket
START_TIMEOUT=1200   # seconds for the three units to be active (each runs the anchor check first)
STOP_TIMEOUT=120     # seconds for the units to stop
CHECK_TIMEOUT=3600   # seconds for check-devnet.sh --probe-log (its own bounds: about 52 min)
ANSWERS_TIMEOUT=300  # seconds for devnet-probe answers (each request: 30 s)
FINALITY_TIMEOUT=900 # seconds for every CL's finalized state to name a finalized root
# The probe's custody group count (CUSTODY_REQUIREMENT): cl-chain's, which cl-p2p holds
# cl-discv5's record (cgc) to.
CUSTODY_GROUPS=4
RM_TIMEOUT=120       # seconds for one docker rm -f
GRACE=10             # seconds between TERM and KILL when stopping background jobs
POLL=5               # seconds between polls of a state
export JOB_SCRIPT=run-units.sh

usage() {
  echo "usage: run-units.sh [--minutes N] [--sample-secs S] [--api-port P] [--skip-build] [--keep] ENCLAVE" >&2
  exit 2
}
die() { echo "ERROR: $*" >&2; exit 2; }

minutes=10 sample_secs=10 api_port=4000 skip_build=0 keep=0 enclave=''
while (($# > 0)); do
  case $1 in
    --minutes) (($# >= 2)) || usage; minutes=$2; shift 2 ;;
    --sample-secs) (($# >= 2)) || usage; sample_secs=$2; shift 2 ;;
    --api-port) (($# >= 2)) || usage; api_port=$2; shift 2 ;;
    --skip-build) skip_build=1; shift ;;
    --keep) keep=1; shift ;;
    -*) usage ;;
    *) [[ -z $enclave ]] || usage; enclave=$1; shift ;;
  esac
done
[[ -n $enclave ]] || usage
[[ $enclave =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,62}$ ]] || { echo "ENCLAVE must be a Kurtosis enclave name" >&2; usage; }
{ [[ $minutes =~ ^[0-9]+$ ]] && ((minutes >= 1 && minutes <= 1440)); } ||
  { echo "--minutes must be 1 to 1440" >&2; usage; }
{ [[ $sample_secs =~ ^[0-9]+$ ]] && ((sample_secs >= 1 && sample_secs <= 600)); } ||
  { echo "--sample-secs must be 1 to 600" >&2; usage; }
{ [[ $api_port =~ ^[0-9]+$ ]] && ((api_port >= 1 && api_port <= 65535)); } ||
  { echo "--api-port must be 1 to 65535" >&2; usage; }
for tool in kurtosis docker python3 curl; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"
done
# Everything the script writes is ours only: the journals, the configs, the node key.
umask 077
readme="$root/ops/probe/README.md"
for f in "$readme" "$here/units/ethswarm-verify.service" "$here/units/devnet-anchor-check.conf" \
  "$here/lib/jobs.sh" "$here/lib/nodekey.py" "$here/check-devnet.sh" "$root/$TRUSTED_SETUP"; do
  [[ -f $f ]] || die "$f: no such file"
done
for unit in "${UNITS[@]}"; do
  [[ -f $root/ops/probe/$unit.service ]] || die "$root/ops/probe/$unit.service: no such file"
done
# shellcheck source=lib/jobs.sh
. "$here/lib/jobs.sh"

# --- the install block of ops/probe/README.md --------------------------------------------------

# The "## Install" block, run as it is in two parts: up to the end of the useradd loop, and the
# rest. A block of another shape stops the run before anything starts.
FIRST_LINE='for u in ethswarm-p2p ethswarm-discv5 ethswarm-chain; do'
LAST_LINE='systemctl daemon-reload && systemctl enable --now ethswarm-chain ethswarm-discv5 ethswarm-p2p'
block=$(awk '/^## Install$/ { inst = 1; next } inst && /^## / { exit } inst && /^```bash$/ { code = 1; next } code && /^```$/ { exit } code { print }' "$readme")
[[ -n $block ]] || die "$readme: no bash block under '## Install'"
[[ $(printf '%s\n' "$block" | head -n 1) == "$FIRST_LINE" ]] ||
  die "$readme: the install block does not start with the useradd loop ($FIRST_LINE)"
[[ $(printf '%s\n' "$block" | tail -n 1) == "$LAST_LINE" ]] ||
  die "$readme: the install block does not end with: $LAST_LINE"
split=$(printf '%s\n' "$block" | awk '$0 == "done" { print NR; exit }')
[[ -n $split ]] || die "$readme: the install block has no 'done' line ending the useradd loop"
install_users=$(printf '%s\n' "$block" | head -n "$split")
install_rest=$(printf '%s\n' "$block" | tail -n "+$((split + 1))")

# --- the drop-in: each unit's own anchor check, with the devnet flags only ---------------------

dropin="$here/units/devnet-anchor-check.conf"
dropin_lines=$(grep -vE '^[[:space:]]*(#|$)' "$dropin")
check_line=$(grep -E '^ExecStartPre=.+' "$dropin" || true)
want_lines=$(printf '%s\n' '[Service]' 'ExecStartPre=' "$check_line" 'LogRateLimitIntervalSec=0')
[[ $dropin_lines == "$want_lines" ]] ||
  die "$dropin: want exactly [Service], ExecStartPre= (empty), one ExecStartPre= check and LogRateLimitIntervalSec=0"
[[ $check_line == *"$DEVNET_FLAGS --check" ]] ||
  die "$dropin: its check does not end with the devnet flags:$DEVNET_FLAGS --check"
unit_check=${check_line/"$DEVNET_FLAGS"/}
for unit in "${UNITS[@]}"; do
  lines=$(grep -E '^ExecStartPre=' "$root/ops/probe/$unit.service" || true)
  [[ $lines == "$unit_check" ]] ||
    die "$unit.service: its ExecStartPre= is not the drop-in's check without$DEVNET_FLAGS"
done

# --- the teardown ----------------------------------------------------------------------------------

work='' stage='' run='' torn_down=0 CONTAINERS=() unit_ctr=''
# teardown <exit code> (the EXIT trap): stops the background jobs, removes this run's containers
# (the units' one stays with --keep), the staged node key and the scratch files, then exits with
# the run's exit code (2 if only the teardown failed). It ignores further signals, and runs every
# step even when an earlier one fails.
# shellcheck disable=SC2329 # invoked only by the EXIT trap
teardown() {
  trap '' INT TERM HUP PIPE
  held=0 pending=''
  local rc=$1 c failed=0
  set +e
  ((torn_down == 0)) || return 0
  torn_down=1
  stop ${bg_pids[@]+"${bg_pids[@]}"}
  for c in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do
    if ((keep)) && [[ $c == "$unit_ctr" ]]; then
      say "kept $c running (--keep); remove it with: docker rm -f $c"
      continue
    fi
    # A container that is gone already (the build's --rm) is no failure.
    if ! bounded "$RM_TIMEOUT" /dev/null "$work/rm.err" docker rm -f "$c" &&
      ! grep -qi 'no such container' "$work/rm.err" 2>/dev/null; then
      warn "warning: docker rm -f $c failed or timed out"
      failed=1
    fi
  done
  if [[ -n $stage ]]; then rm -rf "$stage"; fi
  if [[ -n $jobs_file ]]; then rm -f "$jobs_file"; fi
  if [[ -n $work ]]; then rm -rf "$work"; fi
  if ((failed && rc == 0)); then
    warn "ERROR: teardown failed; remove what is left (docker ps -a --filter name=ethswarm-units)"
    rc=2
  fi
  if [[ -n $run ]]; then say "run-units: exit $rc (logs in $run)"; fi
  exit "$rc"
}
trap 'teardown $?' EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
trap 'on_signal 129' HUP
trap 'on_signal 141' PIPE
work=$(mktemp -d)

T=$(now)
run="$root/target/kurtosis/units-$T-$$"
mkdir -p "$root/target/kurtosis" 2>/dev/null || die "mkdir -p $root/target/kurtosis failed"
mkdir "$run" 2>/dev/null || die "mkdir $run failed (another run with the same name?)"
jobs_file="$run/job-groups"
stage="$run/stage"
(umask 077 && mkdir "$stage") || die "mkdir $stage failed"
unit_ctr="ethswarm-units-$T-$$"
build_ctr="ethswarm-units-build-$T-$$"

# must <name> <seconds> <command...>: runs the command as a bounded job, its stdout to
# $work/<name>.out and its stderr to $work/<name>.err (shown only when it fails); dies (exit 2)
# on a failure or past the limit. Never called inside $(...): every job is one that this shell
# spawns, so the teardown finds it.
must() {
  local name=$1 limit=$2 rc=0
  shift 2
  bounded "$limit" "$work/$name.out" "$work/$name.err" "$@" || rc=$?
  if ((rc == 124)); then die "$* timed out after $limit s"; fi
  if ((rc != 0)); then die "$* failed (exit $rc): $(cat "$work/$name.err" 2>/dev/null)"; fi
}
# in_ctr <name> <seconds> <command...>: must, for the command run in the units' container, in
# its root: the stage (/work) is removed at the end, and a --keep container outlives it.
in_ctr() {
  local name=$1 limit=$2
  shift 2
  must "$name" "$limit" docker exec -w / "$unit_ctr" "$@"
}
# install_step <name>: the stage's script <name>.sh, run in the stage (/work), whose relative
# paths the README's install lines read.
install_step() {
  must "$1" "$INSTALL_TIMEOUT" docker exec -w /work "$unit_ctr" bash -euo pipefail "/work/$1.sh"
}
# result <name>: what the command of `must <name>` printed, without CR.
result() { tr -d '\r' < "$work/$1.out"; }
# try <name> <seconds> <command...>: the command as a bounded job, its stdout to
# $work/<name>.out; its exit code, never fatal (an empty file after a failure).
try() {
  local name=$1 limit=$2 rc=0
  shift 2
  bounded "$limit" "$work/$name.out" /dev/null "$@" || rc=$?
  if ((rc != 0)); then : > "$work/$name.out"; fi
  return "$rc"
}
# words <name>: the output of `try <name>` on one line, its words separated by one space.
words() { tr -s '\r\n\t ' '    ' < "$work/$1.out" | sed 's/ *$//'; }

# --- 1. the enclave ------------------------------------------------------------------------------

must inspect "$KURTOSIS_TIMEOUT" kurtosis enclave inspect "$enclave"
inspect=$(result inspect)
services=()
while IFS= read -r svc; do
  if [[ -n $svc ]]; then services+=("$svc"); fi
done < <(printf '%s\n' "$inspect" | tr -s ' \t' '\n\n' | grep -E "$SERVICE_RE" | sort -u | sort -t- -k2,2n)
((${#services[@]} >= 2)) || die "enclave $enclave runs ${#services[@]} CL service(s); the anchor check needs 2"
# IDENTITY: python source over an /eth/v1/node/identity answer: prints `<peer ID> <IPv4> <TCP
# port> <ENR>`, the address the first /ip4/<private address>/tcp/<port>/p2p/<peer ID> one of
# p2p_addresses; exits 1 for an answer without one or with a field of another shape.
# shellcheck disable=SC2016 # python source
IDENTITY='
import ipaddress, json, re, sys
data = json.load(sys.stdin)["data"]
peer, enr = data["peer_id"], data["enr"]
if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{40,64}", peer) or not re.fullmatch(r"enr:[A-Za-z0-9_-]{8,4096}", enr):
    sys.exit(1)
for addr in data["p2p_addresses"]:
    m = re.fullmatch(r"/ip4/([0-9.]+)/tcp/([0-9]{1,5})/p2p/([1-9A-HJ-NP-Za-km-z]+)", addr)
    if m and m.group(3) == peer and ipaddress.ip_address(m.group(1)).is_private and not ipaddress.ip_address(m.group(1)).is_loopback:
        print(peer, m.group(1), m.group(2), enr)
        sys.exit(0)
sys.exit(1)'
peers=() ips=() tcps=() enrs=() urls=()
for svc in "${services[@]}"; do
  must "port-$svc" "$KURTOSIS_TIMEOUT" kurtosis port print "$enclave" "$svc" http
  url=$(result "port-$svc")
  [[ $url == *://* ]] || url="http://$url"
  [[ $url =~ ^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[0-9]+$ ]] ||
    die "kurtosis port print $enclave $svc http: '$url' is not an http://host:port URL"
  curl -fsS --max-time "$CURL_TIMEOUT" -H 'Accept: application/json' -o "$work/identity-$svc.json" \
    "$url/eth/v1/node/identity" 2>"$work/identity-$svc.err" ||
    die "$svc: GET /eth/v1/node/identity failed: $(cat "$work/identity-$svc.err")"
  line=$(python3 -I -c "$IDENTITY" < "$work/identity-$svc.json") ||
    die "$svc: its identity has no peer ID, ENR or private /ip4/.../tcp/.../p2p/ address"
  read -r p i t e <<<"$line"
  peers+=("$p") ips+=("$i") tcps+=("$t") enrs+=("$e") urls+=("$url")
  echo "$svc: peer $p at $i (tcp $t), beacon API $url"
done
must network "$DOCKER_TIMEOUT" docker network inspect "kt-$enclave"
must files "$KURTOSIS_TIMEOUT" kurtosis files download "$enclave" el_cl_genesis_data "$stage/network"
for f in config.yaml genesis.ssz; do
  [[ -f $stage/network/$f ]] || die "kurtosis files download: no $f in el_cl_genesis_data"
done

# --- 2. the Linux build ----------------------------------------------------------------------------

if ((skip_build)); then
  echo "--skip-build: using target/linux/release"
else
  bins=()
  for b in "${BINARIES[@]}"; do bins+=(--bin "$b"); done
  echo "building ${BINARIES[*]} in $RUST_IMAGE (up to $BUILD_TIMEOUT s)"
  mkdir -p "$root/target/linux" || die "mkdir -p $root/target/linux failed"
  CONTAINERS+=("$build_ctr")
  rc=0
  bounded "$BUILD_TIMEOUT" "$run/build.log" "$run/build.log" docker run --rm --name "$build_ctr" \
    -v "$root":/src:ro -v "$root/target/linux":/src/target/linux -w /src \
    -v "$CARGO_VOLUME":/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/src/target/linux -e CARGO_INCREMENTAL=0 "$RUST_IMAGE" bash -c \
    'set -e; apt-get update -qq; apt-get install -y -qq protobuf-compiler clang libclang-dev >/dev/null; cargo build --release --locked "$@"' \
    build "${bins[@]}" || rc=$?
  # Only a build stopped at its limit can leave its container behind (--rm removes it).
  if ((rc == 124)); then die "the build ran past $BUILD_TIMEOUT s (see $run/build.log)"; fi
  CONTAINERS=()
  ((rc == 0)) || die "the build failed (exit $rc; see $run/build.log)"
fi
for b in "${BINARIES[@]}"; do
  [[ -f $root/target/linux/release/$b ]] || die "target/linux/release/$b: no such file (build it, or drop --skip-build)"
done

# --- 3. the stage and the container -------------------------------------------------------------

node_id=$(python3 -I "$here/lib/nodekey.py" new "$stage/node.key") || die "the node key was not written"
[[ $node_id =~ ^0x[0-9a-f]{64}$ ]] || die "the node key's node ID is not 0x and 64 hex digits"
python3 -I "$here/lib/nodekey.py" patterns "$stage/node.key" > "$work/key-patterns" ||
  die "the node key's patterns were not written"
echo "node ID $node_id (the key itself stays in $stage, removed at the end)"
ln -s /src/ops "$stage/ops" || die "the stage's ops link was not made"
{ mkdir "$stage/target" && ln -s /src/target/linux/release "$stage/target/release"; } ||
  die "the stage's target/release link was not made"
printf '%s\n' "$install_users" > "$stage/install-users.sh" || die "install-users.sh was not written"
printf '%s\n' "$install_rest" > "$stage/install-rest.sh" || die "install-rest.sh was not written"
# The devnet-only steps, before and after the README's users.
cat > "$stage/devnet-user.sh" <<'SH' || die "devnet-user.sh was not written"
# cl-verify's user and group, which the README's `usermod -a -G ethswarm-verify` line names.
useradd --system --no-create-home --shell /usr/sbin/nologin ethswarm-verify
SH
cat > "$stage/devnet-units.sh" <<'SH' || die "devnet-units.sh was not written"
# The network files, cl-verify and its unit, and the anchor check's drop-in for each probe unit.
install -d -m 0755 /etc/ethswarm /etc/ethswarm/network /usr/local/share/ethswarm
install -m 0644 /work/network/config.yaml /work/network/genesis.ssz /etc/ethswarm/network/
install -m 0644 /src/crates/crypto-kzg/data/trusted_setup_4096.json /usr/local/share/ethswarm/
install -m 0755 /src/target/linux/release/cl-verify /usr/local/bin/
install -m 0600 /work/cl-verify.env /etc/ethswarm/cl-verify.env
install -m 0644 /src/testing/kurtosis/units/ethswarm-verify.service /etc/systemd/system/
for u in ethswarm-p2p ethswarm-discv5 ethswarm-chain; do
  install -d -m 0755 "/etc/systemd/system/$u.service.d"
  install -m 0644 /src/testing/kurtosis/units/devnet-anchor-check.conf "/etc/systemd/system/$u.service.d/"
done
systemctl daemon-reload
systemctl enable --now ethswarm-verify.service
SH
# BOOT: the container's first command: systemd and the tools the run reads with, then systemd as
# PID 1. `/` is made rshared first (a devnet deviation): in the container `/` and `/run` are
# private, so the tmpfs that systemd mounts for a unit's credential at /run/credentials/<unit>
# would not reach the unit's namespace, and node-key would find no credential.
BOOT='set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates curl acl >/dev/null
mount --make-rshared /
exec /sbin/init'
CONTAINERS+=("$unit_ctr")
echo "starting $unit_ctr ($SYSTEMD_IMAGE) on kt-$enclave"
# Only what the install reads, read-only: with --privileged, root in the container could
# remount a mount writable, so the rest of the repo is not there at all.
must run-d "$DOCKER_TIMEOUT" docker run -d --name "$unit_ctr" --hostname ethswarm-units --privileged \
  --cgroupns=private --network "kt-$enclave" --tmpfs /run:rw,mode=0755 --tmpfs /run/lock \
  -e container=docker -v "$root/ops":/src/ops:ro \
  -v "$root/target/linux/release":/src/target/linux/release:ro \
  -v "$root/$TRUSTED_SETUP":"/src/$TRUSTED_SETUP":ro \
  -v "$here/units":/src/testing/kurtosis/units:ro -v "$stage":/work:ro -w / "$SYSTEMD_IMAGE" \
  bash -c "$BOOT"
# wait_for <limit> <what> <command...>: runs the command (bounded to DOCKER_TIMEOUT) every POLL
# seconds until it exits 0, for at most <limit> seconds; dies past it.
wait_for() {
  local limit=$1 what=$2 deadline
  shift 2
  deadline=$(( $(now) + limit ))
  while ! bounded "$DOCKER_TIMEOUT" "$work/wait.out" "$work/wait.err" "$@"; do
    (( $(now) < deadline )) || die "$what: not within $limit s"
    bounded $((POLL + 5)) /dev/null /dev/null sleep "$POLL" || true
  done
}
wait_for "$BOOT_TIMEOUT" "systemd in $unit_ctr" docker exec "$unit_ctr" \
  bash -c 'case $(systemctl is-system-running 2>/dev/null) in running | degraded) exit 0 ;; *) exit 1 ;; esac'
must ip "$DOCKER_TIMEOUT" docker inspect -f "{{(index .NetworkSettings.Networks \"kt-$enclave\").IPAddress}}" "$unit_ctr"
our_ip=$(result ip | tr -d '\n')
[[ $our_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$unit_ctr has no IPv4 address on kt-$enclave"
for ((n = 0; n < ${#services[@]}; n++)); do
  rc=0
  try "reach-$n" "$DOCKER_TIMEOUT" docker exec "$unit_ctr" curl -fsS --max-time "$CURL_TIMEOUT" \
    "http://${ips[n]}:$api_port/eth/v1/node/identity" || rc=$?
  ((rc == 0)) || die "${services[n]}: no beacon API at http://${ips[n]}:$api_port from $unit_ctr (--api-port?)"
  id=$(python3 -I -c 'import json, sys; print(json.load(sys.stdin)["data"]["peer_id"])' < "$work/reach-$n.out") ||
    die "${services[n]}: http://${ips[n]}:$api_port answers no identity"
  [[ $id == "${peers[n]}" ]] || die "${services[n]}: http://${ips[n]}:$api_port is another node ($id)"
done
echo "$unit_ctr at $our_ip reaches every CL's beacon API on port $api_port"

# FINALIZED_ROOT: python source over a finality_checkpoints answer: exits 0 when its finalized
# checkpoint has a root other than the zero root, 1 otherwise.
# shellcheck disable=SC2016 # python source
FINALIZED_ROOT='
import json, sys
root = json.load(sys.stdin)["data"]["finalized"]["root"]
sys.exit(0 if int(root, 16) != 0 else 1)'
# wait_for_finality: waits, up to FINALITY_TIMEOUT, until every CL's finalized state has a
# finalized checkpoint with a root (anchor-fetch reads states/finalized/finality_checkpoints and
# refuses the genesis zero root, which the finalized state keeps until the chain finalizes epoch
# 4); dies past it. The units' anchor checks then find an anchor.
wait_for_finality() {
  local deadline n ready
  deadline=$(( $(now) + FINALITY_TIMEOUT ))
  while :; do
    ready=0
    for ((n = 0; n < ${#urls[@]}; n++)); do
      if curl -fsS --max-time "$CURL_TIMEOUT" -o "$work/finality.json" \
        "${urls[n]}/eth/v1/beacon/states/finalized/finality_checkpoints" 2>/dev/null &&
        python3 -I -c "$FINALIZED_ROOT" < "$work/finality.json" 2>/dev/null; then
        ready=$((ready + 1))
      fi
    done
    if ((ready == ${#urls[@]})); then break; fi
    (( $(now) < deadline )) ||
      die "no finalized checkpoint with a root in every CL's finalized state within $FINALITY_TIMEOUT s"
    bounded $((POLL + 5)) /dev/null /dev/null sleep "$POLL" || true
  done
  echo "the finalized checkpoint of the finalized state has a root on every CL: the anchor checks can pass"
}

# --- 4. the install --------------------------------------------------------------------------------

install_step devnet-user
install_step install-users
# id_of <u|g> <name>: sets got to the UID or GID of a user the install made.
got=''
id_of() {
  in_ctr "id-$1-$2" "$DOCKER_TIMEOUT" id "-$1" "$2"
  got=$(result "id-$1-$2" | tr -d '\n')
  [[ $got =~ ^[0-9]+$ ]] || die "id -$1 $2: '$got' is not an ID"
}
id_of u ethswarm-p2p; uid_p2p=$got
id_of g ethswarm-p2p; gid_p2p=$got
id_of u ethswarm-discv5; uid_discv5=$got
id_of g ethswarm-discv5; gid_discv5=$got
id_of u ethswarm-chain; uid_chain=$got
id_of g ethswarm-chain; gid_chain=$got
id_of u ethswarm-verify; uid_verify=$got
static=''
for ((n = 0; n < ${#services[@]}; n++)); do
  static="$static${static:+, }\"/ip4/${ips[n]}/tcp/${tcps[n]}/p2p/${peers[n]}\""
done
cat > "$stage/cl-chain.toml" <<EOF || die "cl-chain.toml was not written"
network_dir = "/etc/ethswarm/network"
metrics_port = 9102

[socket]
group = $gid_chain

[callers]
cl-p2p = $uid_p2p

[methods]
"/ethswarm.chain.v1.ReqRespService/GetStatus" = ["cl-p2p"]
"/ethswarm.chain.v1.ReqRespService/DataColumnsByRange" = ["cl-p2p"]
"/ethswarm.chain.v1.ReqRespService/DataColumnsByRoot" = ["cl-p2p"]
"/ethswarm.chain.v1.GossipService/WatchSubscriptions" = ["cl-p2p"]
"/ethswarm.chain.v1.GossipService/Validate" = ["cl-p2p"]

[chain]
reference_api_url = "http://${ips[0]}:$api_port"
node_id = "$node_id"
verify_socket = "/run/ethswarm/cl-verify/cl-verify.sock"
verify_uid = $uid_verify
verify_wait_ms = 600000
EOF
cat > "$stage/cl-discv5.toml" <<EOF || die "cl-discv5.toml was not written"
network_dir = "/etc/ethswarm/network"
metrics_port = 9103

[socket]
group = $gid_discv5

[callers]
cl-p2p = $uid_p2p

[methods]
"/ethswarm.discv5.v1.DiscoveryService/WatchPeers" = ["cl-p2p"]
"/ethswarm.discv5.v1.DiscoveryService/GetLocalEnr" = ["cl-p2p"]

[discv5]
mode = "devnet"
bootnodes = ["${enrs[0]}"]
enr_ip = "$our_ip"
cgc = $CUSTODY_GROUPS
EOF
cat > "$stage/cl-p2p.toml" <<EOF || die "cl-p2p.toml was not written"
network_dir = "/etc/ethswarm/network"
metrics_port = 9101

[socket]
group = $gid_p2p

[callers]
cl-sync = 65534

[methods]
"/ethswarm.p2p.v1.NetworkService/ListPeers" = ["cl-sync"]

[p2p]
chain_uid = $uid_chain
discv5_uid = $uid_discv5
static_peers = [$static]
answer_prefix_v4 = 32
answer_prefix_v6 = 128
chain_wait_ms = 600000
mode = "devnet"
EOF
printf 'ANCHOR_PROVIDERS=http://%s:%s,http://%s:%s\n' "${ips[0]}" "$api_port" "${ips[1]}" "$api_port" \
  > "$stage/anchor-check.env" || die "anchor-check.env was not written"
printf 'CHAIN_UID=%s\n' "$uid_chain" > "$stage/cl-verify.env" || die "cl-verify.env was not written"
cp "$stage"/cl-*.toml "$stage/anchor-check.env" "$run/" || die "the configs were not kept in $run"
install_step devnet-units
wait_for "$VERIFY_TIMEOUT" "cl-verify's socket" docker exec "$unit_ctr" test -S /run/ethswarm/cl-verify/cl-verify.sock
echo "installed the devnet's cl-verify unit and the anchor-check drop-ins; installing the probe units"
wait_for_finality
install_step install-rest

failed=() diagnostic=()
# verdict <criterion> <0|1> <evidence>: one PASS or FAIL line; a FAIL joins the failed list.
verdict() {
  if (($2 == 0)); then echo "PASS $1: $3"; else echo "FAIL $1: $3"; failed+=("$1"); fi
}
same=0
for unit in "${UNITS[@]}"; do
  if ! bounded "$DOCKER_TIMEOUT" /dev/null /dev/null docker exec "$unit_ctr" \
    cmp -s "/src/ops/probe/$unit.service" "/etc/systemd/system/$unit.service"; then
    same=1
  fi
  bounded "$DOCKER_TIMEOUT" "$run/systemctl-cat-$unit.txt" "$run/systemctl-cat-$unit.txt" \
    docker exec "$unit_ctr" systemctl cat "$unit" || true
done
verdict units "$same" "each installed unit is its ops/probe file byte for byte (drop-in apart)"

# --- 5. the run ------------------------------------------------------------------------------------

# states: sets now_states to the three units' ActiveState, one word each in UNITS order
# (`unknown` on a failed read).
now_states=''
states() {
  if try states "$DOCKER_TIMEOUT" docker exec "$unit_ctr" systemctl show -p ActiveState --value "${UNITS[@]}"; then
    now_states=$(words states)
  else
    now_states=unknown
  fi
}
active=1 deadline=$(( $(now) + START_TIMEOUT ))
while :; do
  states
  if [[ $now_states == "active active active" ]]; then active=0; break; fi
  if [[ $now_states == *failed* ]] || (( $(now) >= deadline )); then break; fi
  bounded $((POLL + 5)) /dev/null /dev/null sleep "$POLL" || true
done
verdict start "$active" "the three units active (${UNITS[*]}: $now_states)"
held_state=0 samples=0
if ((active == 0)); then
  echo "holding the units for $minutes min, a sample every $sample_secs s"
  end=$(( $(now) + minutes * 60 ))
  while (( $(now) < end )); do
    samples=$((samples + 1))
    t=$(now)
    for m in p2p:9101 chain:9102; do
      if bounded "$DOCKER_TIMEOUT" "$work/sample" /dev/null docker exec "$unit_ctr" \
        curl -fsS --max-time 5 "http://127.0.0.1:${m#*:}/metrics"; then
        { echo "# sample $samples at $t"; cat "$work/sample"; } >> "$run/metrics-${m%%:*}.txt"
        cp "$work/sample" "$work/last-${m%%:*}"
      fi
    done
    states
    echo "$t $now_states" >> "$run/states.txt"
    if [[ $now_states != "active active active" ]]; then held_state=1; fi
    left=$(( end - $(now) ))
    if ((left > sample_secs)); then left=$sample_secs; fi
    if ((left > 0)); then bounded $((left + 5)) /dev/null /dev/null sleep "$left" || true; fi
  done
  verdict hold "$held_state" "every unit active at each of $samples samples over $minutes min (states.txt)"
  # Our own column requests to the probe unit, as a peer's, each answer judged against the
  # store that cl-chain serves from (opened read-only while the units run).
  rc=0
  bounded "$ANSWERS_TIMEOUT" "$run/answers.log" "$run/answers.log" docker exec -w / "$unit_ctr" \
    /src/target/linux/release/devnet-probe answers --network-dir /etc/ethswarm/network \
    --probe /ip4/127.0.0.1/tcp/9000 --columns-dir /var/lib/ethswarm-chain/columns \
    --node-id "$node_id" || rc=$?
  verdict columns "$rc" "our own ByRange and ByRoot requests to the probe unit: every answer the store's (devnet-probe answers exit $rc, answers.log)"
fi
try restarts "$DOCKER_TIMEOUT" docker exec "$unit_ctr" systemctl show -p NRestarts --value "${UNITS[@]}" || true
restarts=$(words restarts)
if [[ $restarts == "0 0 0" ]]; then rc=0; else rc=1; fi
verdict restarts "$rc" "NRestarts of ${UNITS[*]}: ${restarts:-unknown}"
# cl-p2p's own lines of this run (its invocation, its process only: no anchor-fetch, no systemd).
try invocation "$DOCKER_TIMEOUT" docker exec "$unit_ctr" systemctl show -p InvocationID --value ethswarm-p2p || true
invocation=$(words invocation)
# Stop: each unit's main process must exit 0 on SIGTERM.
try stop "$STOP_TIMEOUT" docker exec "$unit_ctr" systemctl stop "${UNITS[@]}" || true
try codes "$DOCKER_TIMEOUT" docker exec "$unit_ctr" systemctl show -p ExecMainStatus --value "${UNITS[@]}" || true
codes=$(words codes)
if ((active == 0)); then
  if [[ $codes == "0 0 0" ]]; then rc=0; else rc=1; fi
  verdict stop "$rc" "the exit codes of ${UNITS[*]} after systemctl stop: ${codes:-unknown}"
fi
for unit in "${UNITS[@]}"; do
  bounded "$DOCKER_TIMEOUT" "$run/journal-$unit.export" /dev/null docker exec "$unit_ctr" \
    journalctl -u "$unit" -o export --no-pager || warn "warning: the journal of $unit was not read"
done
bounded "$DOCKER_TIMEOUT" "$run/journal-all.export" /dev/null docker exec "$unit_ctr" \
  journalctl -o export --no-pager || warn "warning: the whole journal was not read"
if [[ $invocation =~ ^[0-9a-f]{32}$ ]]; then
  bounded "$DOCKER_TIMEOUT" "$run/p2p.log" /dev/null docker exec "$unit_ctr" \
    journalctl "_SYSTEMD_INVOCATION_ID=$invocation" _COMM=cl-p2p -o cat --no-pager || true
fi
# The node key in a journal: each file that holds one of its hex or base64 texts (never the text).
found=()
for f in "$run"/journal-*.export; do
  if [[ ! -s $f ]]; then found+=("${f##*/} (empty or not read)"); continue; fi
  if grep -a -F -q -f "$work/key-patterns" "$f"; then found+=("${f##*/}"); fi
done
if ((${#found[@]} == 0)); then
  verdict keygrep 0 "no journal holds the node key's hex or base64 (standard, URL-safe, padded or not)"
else
  verdict keygrep 1 "the node key's hex or base64, or no journal, in: ${found[*]}"
fi

# journald dropped none of a probe unit's lines (the drop-in turns its rate limit off).
if [[ -s $run/journal-all.export ]]; then
  suppressed=$(grep -a -c -E '^MESSAGE=Suppressed [0-9]+ messages from ethswarm-(p2p|discv5|chain)\.service' \
    "$run/journal-all.export" || true)
  if ((suppressed == 0)); then rc=0; else rc=1; fi
  verdict ratelimit "$rc" "$suppressed journald 'Suppressed' lines for a probe unit (journal-all.export)"
else
  verdict ratelimit 1 "the whole journal was not read"
fi

# The counters of the last sample (#35 and #38 read these).
touch "$work/last-p2p" "$work/last-chain"
grep -E '^(p2p_peers|mesh_peer_counts|p2p_status_valid_peers|p2p_goodbye_(sent|received)_total|rpc_outbound_inflight|rpc_timeouts_total|topic_msg_|p2p_column_handoff_total|rpc_column_sidecars_answered_total)' \
  "$work/last-p2p" > "$run/counters.txt" || true
grep -E '^probe_column_(stored|dropped)_total' "$work/last-chain" >> "$run/counters.txt" || true
# metric <file> <name regex>: the sum of the values of the series whose name matches.
metric() {
  awk -v re="$2" '$1 ~ re { s += $NF } END { printf "%d\n", s }' "$1"
}
sent=$(metric "$work/last-p2p" '^topic_msg_(sent_counts|sent_bytes|published)(_total)?(\\{|$)')
if [[ -s $work/last-p2p ]] && ((sent == 0)); then rc=0; else rc=1; fi
verdict topic_msg "$rc" "topic_msg_sent_counts, topic_msg_sent_bytes and topic_msg_published sum to $sent in the last sample (counters.txt)"
valid=$(metric "$work/last-p2p" '^p2p_status_valid_peers$')
((valid >= ${#services[@]})) && rc=0 || rc=1
verdict status "$rc" "$valid Status-valid peers in the last sample, ${#services[@]} CLs"
answered=$(metric "$work/last-p2p" '^p2p_column_handoff_total\\{result="answered"\\}$')
stored=$(metric "$work/last-chain" '^probe_column_stored_total$')
((answered > 0 && stored > 0)) && rc=0 || rc=1
verdict handoff "$rc" "cl-chain answered $answered column sidecars of the hand-off and stored $stored columns"
served=$(metric "$work/last-p2p" '^rpc_column_sidecars_answered_total')
if ((served > 0)); then
  echo "INFO columns: $served column sidecars answered to peers' requests (rpc_column_sidecars_answered_total)"
else
  echo "INFO columns: no peer asked for columns (rpc_column_sidecars_answered_total 0)"
fi
# No reason-3 Goodbye from any CL, each CL named in cl-p2p's log (check-devnet.sh, goodbye3).
if [[ -s $run/p2p.log ]]; then
  rc=0
  bounded "$CHECK_TIMEOUT" "$run/check.log" "$run/check.log" "${BASH:-bash}" "$here/check-devnet.sh" \
    --probe-log "$run/p2p.log" "$enclave" || rc=$?
  case $rc in
    0) verdict check-devnet 0 "check-devnet.sh --probe-log passed (check.log)" ;;
    3) echo "DIAGNOSTIC check-devnet: check-devnet.sh --probe-log was DIAGNOSTIC (check.log)"; diagnostic+=(check-devnet) ;;
    *) verdict check-devnet 1 "check-devnet.sh --probe-log exited $rc (check.log)" ;;
  esac
else
  verdict check-devnet 1 "no cl-p2p log of this run to check"
fi

if ((${#failed[@]} > 0)); then
  echo "verdict: FAIL (${failed[*]})"
  exit 1
fi
if ((${#diagnostic[@]} > 0)); then
  echo "verdict: DIAGNOSTIC (${diagnostic[*]})"
  exit 3
fi
echo "verdict: PASS"
exit 0
