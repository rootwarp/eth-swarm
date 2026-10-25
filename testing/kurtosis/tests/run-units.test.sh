#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted stub bodies expand when the stubs run, on purpose
# Offline tests for testing/kurtosis/run-units.sh. Run: bash testing/kurtosis/tests/run-units.test.sh
# The script runs from a copy of the repo layout in a temp dir (its own copy of run-units.sh,
# lib/, units/ and ops/probe, and a stub check-devnet.sh), with kurtosis, docker, curl, date and
# sleep as stubs on PATH. `date +%s` reads a fake clock that the stub sleep advances, so a
# 10-minute hold takes no time. No network, no Kurtosis, no Docker. Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
kurtosis_dir="$here/.."
repo=$(cd "$here/../../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"   # a stray relative write lands in the temp dir, never in the checkout

passed=0 failed=0
ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() {
  failed=$((failed + 1)); echo "FAIL - $1"
  if [[ -n ${2:-} ]]; then printf '%s\n' "$2" | sed 's/^/       /'; fi
}
# check <name> <command...>: ok when the command succeeds.
check() {
  local name=$1
  shift
  if "$@"; then ok "$name"; else bad "$name" "${out:-}"; fi
}

RUST_IMAGE='rust:1.99-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8'
SYSTEMD_IMAGE='debian:trixie@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308'
P1=16Uiu2HAm1111111111111111111111111111111111111111
P2=16Uiu2HAm2222222222222222222222222222222222222222
ENCLAVE=ethswarm-gloas-a-1790000900-4242

# --- stubs ---------------------------------------------------------------------------------------

stubs="$tmp/stubs"
mkdir -p "$stubs"
export STUB_DIR="$tmp/stub"

cat > "$stubs/kurtosis" <<'SH'
#!/usr/bin/env bash
# kurtosis stub; every call is logged to $STUB_DIR/kurtosis.log.
# `enclave inspect E`: $STUB_DIR/inspect, else two CL services and an EL one.
# `port print E cl-<n>-... http`: http://127.0.0.1:3250<n>.
# `files download E el_cl_genesis_data DIR`: makes DIR with config.yaml and genesis.ssz.
printf '%s\n' "$*" >> "$STUB_DIR/kurtosis.log"
case "$1 ${2:-}" in
  "enclave inspect")
    if [[ -f $STUB_DIR/inspect ]]; then cat "$STUB_DIR/inspect"; exit 0; fi
    echo "========================================== User Services =========================================="
    echo "UUID           Name                    Ports    Status"
    echo "0a1b2c3d4e5f   cl-1-lighthouse-geth    http: 4000/tcp -> http://127.0.0.1:32501   RUNNING"
    echo "1a1b2c3d4e5f   cl-2-lodestar-geth      http: 4000/tcp -> http://127.0.0.1:32502   RUNNING"
    echo "2a1b2c3d4e5f   el-1-geth-lighthouse    rpc: 8545/tcp                               RUNNING" ;;
  "port print")
    n=${4#cl-}; n=${n%%-*}
    echo "http://127.0.0.1:3250$n" ;;
  "files download")
    mkdir -p "$5" && echo "PRESET_BASE: minimal" > "$5/config.yaml" && printf 'g' > "$5/genesis.ssz" ;;
  *) exit 64 ;;
esac
SH
cat > "$stubs/curl" <<'SH'
#!/usr/bin/env bash
# curl stub (the host's): `-o FILE http://127.0.0.1:3250<n>/eth/v1/node/identity` writes
# $STUB_DIR/identity.<n> (else a CL with peer P<n> at 172.16.0.1<n>). $STUB_DIR/curl.rc fails it.
# `-o FILE .../eth/v1/beacon/states/finalized/finality_checkpoints`: the genesis zero root for the
# first $STUB_DIR/finality.zero answers, then a root.
printf '%s\n' "$*" >> "$STUB_DIR/curl.log"
if [[ -f $STUB_DIR/curl.rc ]]; then exit "$(cat "$STUB_DIR/curl.rc")"; fi
file='' url=''
while (($# > 0)); do
  case $1 in
    -o) file=$2; shift 2 ;;
    --max-time | -H) shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
n=${url#http://127.0.0.1:3250}; n=${n%%/*}
if [[ $url == */eth/v1/beacon/states/finalized/finality_checkpoints ]]; then
  # The first $STUB_DIR/finality.zero answers (all CLs) carry the genesis zero root.
  left=$(cat "$STUB_DIR/finality.zero" 2>/dev/null || echo 0)
  root=0x$(printf '%064d' 0)
  if ((left > 0)); then echo $((left - 1)) > "$STUB_DIR/finality.zero"; else root=0x$(printf '%064d' 7); fi
  printf '{"data":{"finalized":{"epoch":"4","root":"%s"}}}\n' "$root" > "$file"
  exit 0
fi
if [[ -f $STUB_DIR/identity.$n ]]; then cp "$STUB_DIR/identity.$n" "$file"; exit 0; fi
peer=$(cat "$STUB_DIR/peer.$n")
printf '{"data":{"peer_id":"%s","enr":"enr:-cl%s-abcdefgh","p2p_addresses":["/ip4/127.0.0.1/tcp/9000/p2p/%s","/ip4/172.16.0.1%s/tcp/9000/p2p/%s"]}}\n' \
  "$peer" "$n" "$peer" "$n" "$peer" > "$file"
SH
cat > "$stubs/docker" <<'SH'
#!/usr/bin/env bash
# docker stub; every call is logged to $STUB_DIR/docker.log (one line each).
# `network inspect`: exits $STUB_DIR/network.rc (else 0).
# `run --rm ... --bin B...` (the build): with $STUB_DIR/build.block, advances the fake clock by
#   its seconds and blocks (its pid in $STUB_DIR/build.pid); exits $STUB_DIR/build.rc, else
#   writes each B into <the -v source of /src/target/linux>/release.
# `run -d --name C ...`: records C as created and the -v source of /work in $STUB_DIR/stage.path.
# `exec [-w D] C <command...>`: the container's answers (see below).
# `inspect -f ... C`: 172.16.0.50.
# `rm -f C`: removes C; one never created is "No such container" (exit 1).
printf '%s\n' "$*" >> "$STUB_DIR/docker.log"
case $1 in
  network) if [[ -f $STUB_DIR/network.rc ]]; then exit "$(cat "$STUB_DIR/network.rc")"; fi ;;
  run)
    shift
    detach=0 name='' src='' work='' bins=()
    while (($# > 0)); do
      case $1 in
        -d) detach=1; shift ;;
        --name) name=$2; shift 2 ;;
        -v) case $2 in *:/src/target/linux) src=${2%:/src/target/linux} ;; *:/work:ro) work=${2%:/work:ro} ;; esac; shift 2 ;;
        --bin) bins+=("$2"); shift 2 ;;
        *) shift ;;
      esac
    done
    touch "$STUB_DIR/created.$name"
    if ((detach)); then
      echo "$work" > "$STUB_DIR/stage.path"
      echo 0123456789ab
      exit 0
    fi
    if [[ -f $STUB_DIR/build.block ]]; then
      /bin/sleep 0.3   # the script reads its deadline first
      echo $(( $(cat "$STUB_DIR/now") + $(cat "$STUB_DIR/build.block") )) > "$STUB_DIR/now"
      echo $$ > "$STUB_DIR/build.pid"
      while :; do /bin/sleep 0.1; done
    fi
    rm -f "$STUB_DIR/created.$name"
    if [[ -f $STUB_DIR/build.rc ]]; then exit "$(cat "$STUB_DIR/build.rc")"; fi
    mkdir -p "$src/release"
    for b in "${bins[@]}"; do touch "$src/release/$b"; done ;;
  inspect) echo 172.16.0.50 ;;
  rm)
    if [[ ! -f $STUB_DIR/created.$3 ]]; then echo "Error response from daemon: No such container: $3" >&2; exit 1; fi
    rm -f "$STUB_DIR/created.$3" ;;
  exec)
    shift
    if [[ $1 == -w ]]; then shift 2; fi
    shift   # the container
    stage=$(cat "$STUB_DIR/stage.path")
    case "$1 ${2:-}" in
      "bash -c") exit 0 ;;   # systemctl is-system-running
      "bash -euo")
        script=${4##*/}
        cp "$4" "$STUB_DIR/ran.$script" 2>/dev/null || cp "$stage/$script" "$STUB_DIR/ran.$script"
        if [[ -f $STUB_DIR/$script.rc ]]; then exit "$(cat "$STUB_DIR/$script.rc")"; fi ;;
      "curl -fsS")
        url=${*: -1}
        case $url in
          http://127.0.0.1:9101/metrics) cat "$STUB_DIR/metrics-p2p" ;;
          http://127.0.0.1:9102/metrics) cat "$STUB_DIR/metrics-chain" ;;
          */eth/v1/node/identity)
            ip=${url#http://}; ip=${ip%%:*}
            n=${ip#172.16.0.1}
            if [[ ! -f $STUB_DIR/peer.$n ]]; then exit 7; fi
            printf '{"data":{"peer_id":"%s"}}\n' "$(cat "$STUB_DIR/peer.$n")" ;;
          *) exit 7 ;;
        esac ;;
      "id -u" | "id -g")
        if [[ -f $STUB_DIR/block-config ]]; then rm -f "$STUB_DIR/block-config"; mkdir "$stage/cl-chain.toml"; fi
        case $3 in
          ethswarm-verify) echo 989 ;; ethswarm-p2p) echo 988 ;;
          ethswarm-discv5) echo 987 ;; ethswarm-chain) echo 986 ;; *) exit 1 ;;
        esac ;;
      "test -S") exit 0 ;;
      "cmp -s") if [[ -f $STUB_DIR/cmp.rc ]]; then exit "$(cat "$STUB_DIR/cmp.rc")"; fi ;;
      "systemctl cat") echo "# /etc/systemd/system/$3.service" ;;
      "systemctl stop") echo "stop $*" >> "$STUB_DIR/stopped" ;;
      "systemctl show")
        case $4 in
          ActiveState) cat "$STUB_DIR/active" 2>/dev/null || printf 'active\nactive\nactive\n' ;;
          NRestarts) cat "$STUB_DIR/restarts" 2>/dev/null || printf '0\n0\n0\n' ;;
          ExecMainStatus) printf '0\n0\n0\n' ;;
          InvocationID) echo 0123456789abcdef0123456789abcdef ;;
        esac ;;
      "journalctl -u")
        echo "MESSAGE=a line of $3"
        if [[ -f $STUB_DIR/leak.$3 ]]; then
          echo "MESSAGE=key $(od -An -tx1 "$stage/node.key" | tr -d ' \n')"
        fi ;;
      "journalctl -o")
        echo "MESSAGE=the whole journal"
        if [[ -f $STUB_DIR/suppressed ]]; then echo "MESSAGE=Suppressed 5 messages from ethswarm-p2p.service"; fi ;;
      "/src/target/linux/release/devnet-probe answers")
        printf '%s\n' "$*" >> "$STUB_DIR/answers.args"
        echo "answers: PASS (stub)"
        if [[ -f $STUB_DIR/answers.rc ]]; then exit "$(cat "$STUB_DIR/answers.rc")"; fi ;;
      journalctl\ _SYSTEMD_INVOCATION_ID=*) echo '{"timestamp":"2026-10-25T00:00:00Z","fields":{"message":"listening"}}' ;;
      *) echo "unexpected exec: $*" >&2; exit 64 ;;
    esac ;;
  *) exit 64 ;;
esac
SH
cat > "$stubs/date" <<'SH'
#!/usr/bin/env bash
# date stub: `date +%s` is the fake clock in $STUB_DIR/now.
if [[ ${1:-} == +%s ]]; then cat "$STUB_DIR/now"; exit 0; fi
exec /bin/date "$@"
SH
cat > "$stubs/sleep" <<'SH'
#!/usr/bin/env bash
# sleep stub: advances the fake clock by $1 seconds and returns at once; a fraction of a second
# really sleeps. With $STUB_DIR/sleep.block, a sleep of the hold (more than 5 s) blocks for real
# (its pid in $STUB_DIR/sleep.pid), the clock left alone.
if [[ $1 == *.* ]]; then exec /bin/sleep "$1"; fi
if [[ -f $STUB_DIR/sleep.block ]] && (($1 > 5)); then
  echo $$ > "$STUB_DIR/sleep.pid"
  exec /bin/sleep 30
fi
echo $(( $(cat "$STUB_DIR/now") + $1 )) > "$STUB_DIR/now"
SH
chmod +x "$stubs"/*

# --- the repo copy and a run ------------------------------------------------------------------------

copy="$tmp/repo"
layout() {
  rm -rf "$copy"
  mkdir -p "$copy/testing/kurtosis/lib" "$copy/testing/kurtosis/units" "$copy/ops/probe" \
    "$copy/crates/crypto-kzg/data"
  echo '{}' > "$copy/crates/crypto-kzg/data/trusted_setup_4096.json"
  cp "$kurtosis_dir/run-units.sh" "$copy/testing/kurtosis/"
  cp "$kurtosis_dir/lib/jobs.sh" "$kurtosis_dir/lib/nodekey.py" "$copy/testing/kurtosis/lib/"
  cp "$kurtosis_dir/units/"* "$copy/testing/kurtosis/units/"
  cp "$repo/ops/probe/README.md" "$repo/ops/probe/"*.service "$copy/ops/probe/"
  cat > "$copy/testing/kurtosis/check-devnet.sh" <<'SH'
#!/usr/bin/env bash
# check-devnet.sh stub: logs its arguments; exits $STUB_DIR/check.rc (else 0).
printf '%s\n' "$*" >> "$STUB_DIR/check.args"
echo "goodbye3: PASS (stub)"
if [[ -f $STUB_DIR/check.rc ]]; then exit "$(cat "$STUB_DIR/check.rc")"; fi
SH
}

# fresh: a new stub state, the good metrics, and a new repo copy.
fresh() {
  rm -rf "$STUB_DIR"
  mkdir -p "$STUB_DIR"
  echo 1790000000 > "$STUB_DIR/now"
  echo "$P1" > "$STUB_DIR/peer.1"
  echo "$P2" > "$STUB_DIR/peer.2"
  cat > "$STUB_DIR/metrics-p2p" <<'TXT'
# HELP p2p_peers Connected peers.
p2p_peers{direction="outbound"} 2
p2p_status_valid_peers 2
topic_msg_published_total{hash="abc"} 0
topic_msg_sent_counts_total{hash="abc"} 0
topic_msg_recv_counts_total{hash="abc"} 99
p2p_column_handoff_total{result="answered"} 40
p2p_column_handoff_total{result="ignored"} 0
rpc_column_sidecars_answered_total{protocol="data_column_sidecars_by_root"} 3
TXT
  echo "probe_column_stored_total 40" > "$STUB_DIR/metrics-chain"
  layout
}

rc=0 out=''
# run_units <args...>: runs the copy's script with the stubs first on PATH; sets rc and out.
run_units() {
  rc=0
  out=$(PATH="$stubs:$PATH" "${BASH:-bash}" "$copy/testing/kurtosis/run-units.sh" "$@" 2>&1) || rc=$?
}
# run_dir: the run directory the last run made.
run_dir() {
  local d
  for d in "$copy"/target/kurtosis/units-*; do echo "$d"; done | tail -n 1
}

# --- tests -----------------------------------------------------------------------------------------

fresh
for args in "" "$ENCLAVE other" "--minutes 0 $ENCLAVE" "--minutes 1441 $ENCLAVE" \
  "--sample-secs x $ENCLAVE" "--api-port 0 $ENCLAVE" "--bogus $ENCLAVE" "bad_name!"; do
  # shellcheck disable=SC2086 # the arguments, split on purpose
  run_units $args
  check "usage: '$args' exits 2" test "$rc" -eq 2
done
check "a usage error calls neither kurtosis nor docker" test ! -e "$STUB_DIR/kurtosis.log" -a ! -e "$STUB_DIR/docker.log"

fresh
nodocker="$tmp/nodocker"
mkdir -p "$nodocker"
for s in kurtosis curl date sleep; do ln -sf "$stubs/$s" "$nodocker/$s"; done
rc=0
out=$(PATH="$nodocker:/usr/bin:/bin" "${BASH:-bash}" "$copy/testing/kurtosis/run-units.sh" "$ENCLAVE" 2>&1) || rc=$?
check "a missing docker exits 2" test "$rc" -eq 2
check "and says which tool" grep -q "docker not found" <<<"$out"

# The pass: every step, the configs, and the teardown.
fresh
run_units --minutes 1 "$ENCLAVE"
d=$(run_dir)
check "a good run exits 0" test "$rc" -eq 0
check "its verdict is PASS" grep -q "^verdict: PASS$" <<<"$out"
check "kurtosis is only read: inspect, port print, files download" \
  test -z "$(grep -vE '^(enclave inspect|port print|files download) ' "$STUB_DIR/kurtosis.log")"
check "kurtosis is never asked to clean, run or remove" bash -c "! grep -qE '^(clean|run|enclave rm)' '$STUB_DIR/kurtosis.log'"
check "the build runs in the pinned rust image" grep -qF -- "$RUST_IMAGE" "$STUB_DIR/docker.log"
check "with the cargo volume ethswarm-cargo" grep -qF -- "-v ethswarm-cargo:/usr/local/cargo/registry" "$STUB_DIR/docker.log"
check "and cargo build --locked into target/linux" grep -qF -- "CARGO_TARGET_DIR=/src/target/linux" "$STUB_DIR/docker.log"
build_line=$(grep -E '^run --rm ' "$STUB_DIR/docker.log" || true)
check "the build sees the repo read-only, and writes only target/linux" \
  bash -c "grep -qF -- '-v $copy:/src:ro -v $copy/target/linux:/src/target/linux ' <<<'$build_line'"
run_d=$(grep -E '^run -d ' "$STUB_DIR/docker.log" || true)
check "the units' container is privileged, on kt-<enclave>, in the pinned debian image" \
  bash -c "grep -qF -- '--privileged' <<<'$run_d' && grep -qF -- '--network kt-$ENCLAVE' <<<'$run_d' && grep -qF -- '$SYSTEMD_IMAGE' <<<'$run_d'"
mounts=$(grep -oE -- '-v [^ ]+' <<<"$run_d" | sed 's/^-v //' | sort | tr '\n' ' ')
want_mounts=$(printf '%s\n' "$copy/ops:/src/ops:ro" "$copy/target/linux/release:/src/target/linux/release:ro" \
  "$copy/crates/crypto-kzg/data/trusted_setup_4096.json:/src/crates/crypto-kzg/data/trusted_setup_4096.json:ro" \
  "$copy/testing/kurtosis/units:/src/testing/kurtosis/units:ro" "$(cat "$STUB_DIR/stage.path"):/work:ro" | sort | tr '\n' ' ')
check "the units' container mounts ops, the release binaries, the trusted setup, the units and the stage, all read-only" \
  test "$mounts" == "$want_mounts"
block=$(awk '/^## Install$/ { inst = 1; next } inst && /^```bash$/ { code = 1; next } code && /^```$/ { exit } code { print }' "$copy/ops/probe/README.md")
ran=$(cat "$STUB_DIR/ran.install-users.sh" "$STUB_DIR/ran.install-rest.sh" 2>/dev/null || true)
check "the README's install block runs as it is, in two parts" test "$ran" == "$block"
check "the users come first" test "$(tail -n 1 "$STUB_DIR/ran.install-users.sh")" == "done"
check "the devnet's cl-verify user comes before the README's usermod line" grep -qF "useradd --system --no-create-home --shell /usr/sbin/nologin ethswarm-verify" "$STUB_DIR/ran.devnet-user.sh"
check "each probe unit gets the anchor-check drop-in" grep -qF 'devnet-anchor-check.conf "/etc/systemd/system/$u.service.d/"' "$STUB_DIR/ran.devnet-units.sh"
order=$(grep -oE 'bash -euo pipefail /work/[a-z-]+\.sh' "$STUB_DIR/docker.log" | sed 's|.*/||' | tr '\n' ' ')
check "the install order: devnet user, README users, devnet units, README rest" test "$order" == "devnet-user.sh install-users.sh devnet-units.sh install-rest.sh "
check "cl-chain.toml gives the five methods to cl-p2p" test "$(grep -c '= \["cl-p2p"\]$' "$d/cl-chain.toml")" -eq 5
check "cl-chain.toml names Validate" grep -qF '"/ethswarm.chain.v1.GossipService/Validate" = ["cl-p2p"]' "$d/cl-chain.toml"
check "cl-chain.toml: the IDs the install made" bash -c "grep -qx 'group = 986' '$d/cl-chain.toml' && grep -qx 'cl-p2p = 988' '$d/cl-chain.toml' && grep -qx 'verify_uid = 989' '$d/cl-chain.toml'"
check "cl-chain.toml: a node ID and the first CL as the reference" bash -c "grep -qE '^node_id = \"0x[0-9a-f]{64}\"$' '$d/cl-chain.toml' && grep -qx 'reference_api_url = \"http://172.16.0.11:4000\"' '$d/cl-chain.toml'"
check "cl-p2p.toml: each CL as a static peer, at its enclave address" grep -qF "static_peers = [\"/ip4/172.16.0.11/tcp/9000/p2p/$P1\", \"/ip4/172.16.0.12/tcp/9000/p2p/$P2\"]" "$d/cl-p2p.toml"
check "cl-discv5.toml: the first CL's record, our address" bash -c "grep -qx 'bootnodes = \[\"enr:-cl1-abcdefgh\"\]' '$d/cl-discv5.toml' && grep -qx 'enr_ip = \"172.16.0.50\"' '$d/cl-discv5.toml'"
check "cl-p2p.toml: the devnet's IP rule" grep -qx 'mode = "devnet"' "$d/cl-p2p.toml"
check "cl-discv5.toml: the devnet's IP rule and cl-chain's custody group count" \
  bash -c "grep -qx 'mode = \"devnet\"' '$d/cl-discv5.toml' && grep -qx 'cgc = 4' '$d/cl-discv5.toml'"
check "anchor-check.env: the two CLs on the enclave network" grep -qx "ANCHOR_PROVIDERS=http://172.16.0.11:4000,http://172.16.0.12:4000" "$d/anchor-check.env"
check "every sample is kept" test "$(grep -c '^# sample' "$d/metrics-p2p.txt")" -ge 6
mode_of() { python3 -I -c 'import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))' "$1"; }
check "the run directory is ours only (0700)" test "$(mode_of "$d")" == 0o700
check "the journals are ours only (0600)" test "$(mode_of "$d/journal-ethswarm-p2p.export")" == 0o600
check "our own column requests go to the probe unit and its store" \
  grep -qE -- "^exec -w / ethswarm-units-[0-9]+-[0-9]+ /src/target/linux/release/devnet-probe answers --network-dir /etc/ethswarm/network --probe /ip4/127.0.0.1/tcp/9000 --columns-dir /var/lib/ethswarm-chain/columns --node-id 0x[0-9a-f]{64}$" "$STUB_DIR/docker.log"
check "and PASS columns" grep -q "^PASS columns:" <<<"$out"
check "our requests run from / (the stage is gone after the run)" \
  grep -qE -- "^exec -w / ethswarm-units-[0-9]+-[0-9]+ /src/target/linux/release/devnet-probe answers" "$STUB_DIR/docker.log"
check "only the install steps run in the stage" \
  test -z "$(grep -E '^exec -w /work ' "$STUB_DIR/docker.log" | grep -vE ' bash -euo pipefail /work/(devnet-user|install-users|devnet-units|install-rest)\.sh$' || true)"
check "the container starts in /" grep -qE -- " -w / debian:trixie@" <<<"$run_d"
check "/ is rshared before systemd starts, so a unit's credential mount is seen" \
  grep -qE 'mount --make-rshared /.*exec /sbin/init' <<<"$(sed -n '/^run -d /,/exec \/sbin\/init/p' "$STUB_DIR/docker.log" | tr '\n' ' ')"
check "the units start once the finalized state's checkpoint has a root" \
  grep -q "finalized checkpoint of the finalized state has a root" <<<"$out"
check "a peer's own column requests are extra evidence" grep -q "^INFO columns: 3 column sidecars answered to peers' requests" <<<"$out"
check "counters.txt holds the exit run's counters" bash -c "grep -q '^topic_msg_published_total' '$d/counters.txt' && grep -q '^p2p_status_valid_peers 2' '$d/counters.txt' && grep -q '^probe_column_stored_total 40' '$d/counters.txt'"
check "check-devnet.sh reads cl-p2p's log of the run" grep -qx -- "--probe-log $d/p2p.log $ENCLAVE" "$STUB_DIR/check.args"
check "the units are stopped before the journals are read" test -s "$STUB_DIR/stopped"
check "the container is removed at the end" grep -qE "^rm -f ethswarm-units-[0-9]+-[0-9]+$" "$STUB_DIR/docker.log"
check "no container is left" test -z "$(ls "$STUB_DIR" | grep '^created\.' || true)"
check "the staged node key is removed" test ! -e "$d/stage"
check "nothing of the run's scratch is left" bash -c "! find '$copy' -name node.key | grep -q ."

# --keep leaves the container, and says how to remove it.
fresh
run_units --minutes 1 --keep "$ENCLAVE"
check "--keep: exit 0" test "$rc" -eq 0
check "--keep: the container stays" bash -c "! grep -qE '^rm -f ethswarm-units-[0-9]+-[0-9]+$' '$STUB_DIR/docker.log'"
check "--keep: it prints the removal" grep -qE "remove it with: docker rm -f ethswarm-units-" <<<"$out"

# A unit that is not byte for byte its ops/probe file.
fresh
echo 1 > "$STUB_DIR/cmp.rc"
run_units --minutes 1 "$ENCLAVE"
check "an installed unit that differs: exit 1" test "$rc" -eq 1
check "and FAIL units" grep -q "^FAIL units:" <<<"$out"

# The node key in a journal: found, and never printed.
fresh
touch "$STUB_DIR/leak.ethswarm-p2p"
run_units --minutes 1 "$ENCLAVE"
d=$(run_dir)
check "the key's hex in a journal: exit 1" test "$rc" -eq 1
check "FAIL keygrep names the journal" grep -q "^FAIL keygrep: .*journal-ethswarm-p2p.export" <<<"$out"
leaked=$(sed -n 's/^MESSAGE=key //p' "$d/journal-ethswarm-p2p.export")
check "the output never shows the key" bash -c "[[ -n '$leaked' ]] && ! grep -qF '$leaked' <<<\"\$1\"" _ "$out"

# A data message published or forwarded.
fresh
sed -i.bak 's/^topic_msg_published_total{hash="abc"} 0$/topic_msg_published_total{hash="abc"} 1/' "$STUB_DIR/metrics-p2p"
run_units --minutes 1 "$ENCLAVE"
check "topic_msg_published 1: exit 1" test "$rc" -eq 1
check "and FAIL topic_msg" grep -q "^FAIL topic_msg:" <<<"$out"

# A restart, and a unit that failed to start.
fresh
printf '0\n1\n0\n' > "$STUB_DIR/restarts"
run_units --minutes 1 "$ENCLAVE"
check "a restart: exit 1 and FAIL restarts" bash -c "[[ $rc == 1 ]] && grep -q '^FAIL restarts:' <<<\"\$1\"" _ "$out"
fresh
printf 'active\nfailed\nactivating\n' > "$STUB_DIR/active"
run_units --minutes 1 "$ENCLAVE"
d=$(run_dir)
check "a failed unit: exit 1 and FAIL start" bash -c "[[ $rc == 1 ]] && grep -q '^FAIL start:' <<<\"\$1\"" _ "$out"
check "and no hold" test ! -e "$d/metrics-p2p.txt"
check "the container is still removed" grep -qE "^rm -f ethswarm-units-[0-9]+-[0-9]+$" "$STUB_DIR/docker.log"

# No hand-off answers, no Status per CL, a failed goodbye check.
fresh
sed -i.bak 's/^p2p_column_handoff_total{result="answered"} 40$/p2p_column_handoff_total{result="answered"} 0/; s/^p2p_status_valid_peers 2$/p2p_status_valid_peers 1/' "$STUB_DIR/metrics-p2p"
echo 1 > "$STUB_DIR/check.rc"
run_units --minutes 1 "$ENCLAVE"
check "no hand-off answers, one Status-valid peer, a failed check: exit 1" test "$rc" -eq 1
check "FAIL handoff, status and check-devnet" grep -q "^verdict: FAIL (status handoff check-devnet)$" <<<"$out"

# Nobody asked for columns: our own requests still judge the answers.
fresh
sed -i.bak 's/^rpc_column_sidecars_answered_total{protocol="data_column_sidecars_by_root"} 3$/rpc_column_sidecars_answered_total{protocol="data_column_sidecars_by_root"} 0/' "$STUB_DIR/metrics-p2p"
run_units --minutes 1 "$ENCLAVE"
check "no peer's column requests: still exit 0" test "$rc" -eq 0
check "and an INFO line says so" grep -q "^INFO columns: no peer asked for columns" <<<"$out"
# Our own requests get answers that are not the store's.
fresh
echo 1 > "$STUB_DIR/answers.rc"
run_units --minutes 1 "$ENCLAVE"
check "answers that are not the store's: exit 1" test "$rc" -eq 1
check "and FAIL columns" grep -q "^FAIL columns:" <<<"$out"
# journald dropped a probe unit's lines.
fresh
touch "$STUB_DIR/suppressed"
run_units --minutes 1 "$ENCLAVE"
check "a 'Suppressed' line for a probe unit: exit 1" test "$rc" -eq 1
check "and FAIL ratelimit" grep -q "^FAIL ratelimit:" <<<"$out"
# A setup write that fails is a setup error, not a criterion.
fresh
touch "$STUB_DIR/block-config"
run_units --minutes 1 "$ENCLAVE"
check "a config that cannot be written: exit 2" test "$rc" -eq 2
check "the container is removed" grep -qE "^rm -f ethswarm-units-[0-9]+-[0-9]+$" "$STUB_DIR/docker.log"

# The build: a failure, and one past its limit.
fresh
echo 101 > "$STUB_DIR/build.rc"
run_units --minutes 1 "$ENCLAVE"
check "a failed build: exit 2" test "$rc" -eq 2
check "and no container starts" bash -c "! grep -qs '^run -d' '$STUB_DIR/docker.log'"
fresh
echo 5401 > "$STUB_DIR/build.block"
run_units --minutes 1 "$ENCLAVE"
check "a build past its limit: exit 2" test "$rc" -eq 2
check "it says so" grep -q "the build ran past 5400 s" <<<"$out"
pid=$(cat "$STUB_DIR/build.pid" 2>/dev/null || echo 0)
check "the build's process is stopped" bash -c "! kill -0 $pid 2>/dev/null"
check "its container is removed" grep -qE "^rm -f ethswarm-units-build-" "$STUB_DIR/docker.log"
fresh
run_units --minutes 1 --skip-build "$ENCLAVE"
check "--skip-build without binaries: exit 2" test "$rc" -eq 2
check "and no build" bash -c "! grep -qs '^run --rm' '$STUB_DIR/docker.log'"

# An install block of another shape stops the run before anything starts.
fresh
sed -i.bak 's/^for u in ethswarm-p2p ethswarm-discv5 ethswarm-chain; do$/for u in ethswarm-p2p ethswarm-chain; do/' "$copy/ops/probe/README.md"
run_units --minutes 1 "$ENCLAVE"
check "another install block: exit 2" test "$rc" -eq 2
check "before kurtosis or docker" test ! -e "$STUB_DIR/kurtosis.log" -a ! -e "$STUB_DIR/docker.log"

# The enclave: one CL, and a CL without an address on the enclave network.
fresh
printf 'UUID Name\n0a cl-1-lighthouse-geth RUNNING\n' > "$STUB_DIR/inspect"
run_units --minutes 1 "$ENCLAVE"
check "one CL: exit 2" bash -c "[[ $rc == 2 ]] && grep -q 'the anchor check needs 2' <<<\"\$1\"" _ "$out"
fresh
printf '{"data":{"peer_id":"%s","enr":"enr:-cl2-abcdefgh","p2p_addresses":["/ip4/127.0.0.1/tcp/9000/p2p/%s"]}}\n' "$P2" "$P2" > "$STUB_DIR/identity.2"
run_units --minutes 1 "$ENCLAVE"
check "a CL with no private address: exit 2" test "$rc" -eq 2
check "and no container starts" bash -c "! grep -qs '^run -d' '$STUB_DIR/docker.log'"

# The drop-in must be each unit's own anchor check with the two devnet flags, and nothing else.
fresh
sed -i.bak 's|^ExecStartPre=/usr/local/bin/anchor-fetch --providers ${ANCHOR_PROVIDERS} --check$|ExecStartPre=/usr/local/bin/anchor-fetch --providers ${ANCHOR_PROVIDERS} --quiet --check|' "$copy/ops/probe/ethswarm-discv5.service"
run_units --minutes 1 "$ENCLAVE"
check "a unit whose anchor check is not the drop-in's without its flags: exit 2" test "$rc" -eq 2
check "it names the unit" grep -q "ethswarm-discv5.service" <<<"$out"
check "and nothing starts" test ! -e "$STUB_DIR/docker.log" -a ! -e "$STUB_DIR/kurtosis.log"
fresh
echo "Environment=X=1" >> "$copy/testing/kurtosis/units/devnet-anchor-check.conf"
run_units --minutes 1 "$ENCLAVE"
check "a drop-in with another directive: exit 2" test "$rc" -eq 2
check "before anything starts" test ! -e "$STUB_DIR/docker.log"
check "the drop-in turns journald's rate limit off" grep -qx "LogRateLimitIntervalSec=0" "$kurtosis_dir/units/devnet-anchor-check.conf"

# The anchor check needs a finalized state whose own finalized checkpoint is not the genesis zero
# root: the units start only once both CLs have one, and never past the bound.
fresh
echo 5 > "$STUB_DIR/finality.zero"
run_units --minutes 1 "$ENCLAVE"
check "a zero root first, then a root: exit 0" test "$rc" -eq 0
check "it waited for the root" test "$(cat "$STUB_DIR/finality.zero")" -eq 0
check "and asked again" test "$(grep -c finality_checkpoints "$STUB_DIR/curl.log")" -ge 6
fresh
echo 100000 > "$STUB_DIR/finality.zero"
run_units --minutes 1 "$ENCLAVE"
check "a zero root to the end of the bound: exit 2" test "$rc" -eq 2
check "it says so" grep -q "no finalized checkpoint" <<<"$out"
check "and the units never start" bash -c "! grep -qs 'install-rest.sh' '$STUB_DIR/docker.log'"

# SIGTERM during the hold: the container goes, exit 143.
fresh
touch "$STUB_DIR/sleep.block"
PATH="$stubs:$PATH" "${BASH:-bash}" "$copy/testing/kurtosis/run-units.sh" --minutes 1 "$ENCLAVE" > "$tmp/term.out" 2>&1 &
script=$!
for ((i = 0; i < 300; i++)); do if [[ -f $STUB_DIR/sleep.pid ]]; then break; fi; /bin/sleep 0.1; done
kill -TERM "$script" 2>/dev/null || true
rc=0
wait "$script" || rc=$?
check "SIGTERM during the hold: exit 143" test "$rc" -eq 143
check "the container is removed" grep -qE "^rm -f ethswarm-units-[0-9]+-[0-9]+$" "$STUB_DIR/docker.log"
spid=$(cat "$STUB_DIR/sleep.pid" 2>/dev/null || echo 0)
check "the hold's sleep is stopped" bash -c "! kill -0 $spid 2>/dev/null"

# lib/jobs.sh is run-pair.sh's job machinery, unchanged but for the name in JOB_EXEC's error
# line: run-pair.sh keeps its own copy (its tests rewrite that copy), so the two must not drift.
# same_jobs <run-pair.sh> <jobs.sh>: 0 when the library's body is the pair runner's functions.
same_jobs() {
  python3 -I - "$1" "$2" <<'PY'
import sys
pair, lib = (open(p).read() for p in sys.argv[1:3])
def between(text, start, end):
    return text[text.index(start):text.index(end)]
core = between(pair, "# bg_pids holds the jobs whose process groups", "# snapshot <name>: ")
core = core.replace(
    'print(f"run-pair.sh: {sys.argv[2]}: {err.strerror}", file=sys.stderr)',
    "print(f\"{os.environ.get('JOB_SCRIPT', 'jobs')}: {sys.argv[2]}: {err.strerror}\", file=sys.stderr)")
say = between(pair, "# say <text>: a teardown message on stdout.", "work='' torn_down=0")
body = lib[lib.index("now() { date +%s; }\n\n") + len("now() { date +%s; }\n\n"):]
sys.exit(0 if body == core + say.rstrip() + "\n" else 1)
PY
}
check "lib/jobs.sh holds run-pair.sh's job functions, unchanged" same_jobs "$kurtosis_dir/run-pair.sh" "$kurtosis_dir/lib/jobs.sh"
{ cat "$kurtosis_dir/lib/jobs.sh"; echo '# one line more'; } > "$tmp/jobs-drifted.sh"
not() { ! "$@"; }
check "a drifted copy is found" not same_jobs "$kurtosis_dir/run-pair.sh" "$tmp/jobs-drifted.sh"

# The node key helper: the discv5 test vector, and the texts a log must not hold.
key="$tmp/vector.key"
printf '\xee\xf7\x7a\xcb\x6c\x6a\x6e\xeb\xc5\xb3\x63\xa4\x75\xac\x58\x3e\xc7\xec\xcd\xb4\x2b\x64\x81\x42\x4c\x60\xf5\x9a\xa3\x26\x54\x7f' > "$key"
check "nodekey.py id: the discv5 vector's node ID" test "$(python3 -I "$kurtosis_dir/lib/nodekey.py" id "$key")" == 0xaaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb
patterns=$(python3 -I "$kurtosis_dir/lib/nodekey.py" patterns "$key")
check "nodekey.py patterns: hex both cases, base64 with and without padding" bash -c "grep -qx 'eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f' <<<\"\$1\" && grep -qx 'EEF77ACB6C6A6EEBC5B363A475AC583EC7ECCDB42B6481424C60F59AA326547F' <<<\"\$1\" && grep -qx '7vd6y2xqbuvFs2OkdaxYPsfszbQrZIFCTGD1mqMmVH8=' <<<\"\$1\" && grep -qx '7vd6y2xqbuvFs2OkdaxYPsfszbQrZIFCTGD1mqMmVH8' <<<\"\$1\"" _ "$patterns"
printf '\xfb\xff' > "$tmp/urlsafe.key"; head -c 30 /dev/zero >> "$tmp/urlsafe.key"
patterns=$(python3 -I "$kurtosis_dir/lib/nodekey.py" patterns "$tmp/urlsafe.key")
check "nodekey.py patterns: the URL-safe base64 too" bash -c "grep -qx -- '-_8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' <<<\"\$1\" && grep -qx '+/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' <<<\"\$1\"" _ "$patterns"
rc=0; python3 -I "$kurtosis_dir/lib/nodekey.py" new "$key" 2>/dev/null || rc=$?
check "nodekey.py new never replaces a file" test "$rc" -eq 1
printf 'short' > "$tmp/short.key"
rc=0; python3 -I "$kurtosis_dir/lib/nodekey.py" id "$tmp/short.key" 2>/dev/null || rc=$?
check "nodekey.py id refuses a secret that is not 32 bytes" test "$rc" -eq 1

echo
echo "$passed passed, $failed failed"
((failed == 0))
