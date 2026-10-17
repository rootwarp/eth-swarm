#!/usr/bin/env bash
# Tests for scripts/check-deny-negative.sh. Run: bash scripts/tests/check-deny-negative.test.sh
# Offline: a stub `cargo` first on PATH answers `cargo update` with nothing and `cargo deny` with a
# canned JSON report and exit code per case (the case is the throwaway workspace's directory name),
# so the script's verdict logic is tested without crates.io or cargo-deny. CI runs the real script.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-deny-negative.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin"
cat > "$tmp/bin/cargo" <<'STUB'
#!/usr/bin/env bash
# Stub cargo: `update` does nothing; `deny` prints $STUB_CASES/<case>.out and exits <case>.rc.
set -euo pipefail
sub=$1 manifest=""
while (($#)); do
  if [[ $1 == --manifest-path ]]; then manifest=$2; fi
  shift
done
case $sub in
  update) exit 0 ;;
  deny)
    c=$(basename "$(dirname "$manifest")")
    cat "$STUB_CASES/$c.out" >&2
    exit "$(cat "$STUB_CASES/$c.rc")"
    ;;
  *) echo "stub cargo: unexpected subcommand $sub" >&2; exit 99 ;;
esac
STUB
chmod +x "$tmp/bin/cargo"

# diag <severity> <code> <message> [label span] [graph root crate]: one cargo-deny JSON diagnostic.
diag() {
  printf '{"type":"diagnostic","fields":{"severity":"%s","code":"%s","message":"%s","labels":[{"line":1,"column":1,"message":"source","span":"%s"}],"graphs":[{"Krate":{"name":"%s","version":"0.1.0"},"parents":[{"Krate":{"name":"cl-p2p","version":"0.1.0"}}]}]}}\n' \
    "$1" "$2" "$3" "${4:-}" "${5:-}"
}
# summary <bans errors> <bans warnings> <sources errors>: the closing cargo-deny JSON summary line.
summary() {
  printf '{"type":"summary","fields":{"bans":{"errors":%s,"warnings":%s,"notes":0,"helps":0},"sources":{"errors":%s,"warnings":0,"notes":0,"helps":0}}}\n' \
    "$1" "$2" "$3"
}
dup_swarm() { diag error duplicate "found 2 duplicate entries for crate 'libp2p-swarm'"; }
probe_src='git+file:///tmp/probe?rev=0123'

# scenario <name>: a fresh set of canned answers where every case behaves; edit with answer.
scenario() {
  cases="$tmp/$1"
  mkdir -p "$cases"
  answer control 0 "$(summary 0 0 0)"
  answer libp2p-dup 1 "$(dup_swarm; summary 1 0 0)"
  answer dev-dup 1 "$(dup_swarm; summary 1 0 0)"
  answer git-source 1 "$(diag error source-not-allowed "detected 'git' source not specifically allowed" "$probe_src" deny-probe; summary 0 0 1)"
}
# answer <case> <exit code> <output>
answer() { printf '%s\n' "$3" > "$cases/$1.out"; echo "$2" > "$cases/$1.rc"; }

passed=0 failed=0

# check <expect: pass|fail> <description> <output substring>: runs the script on the scenario.
check() {
  local expect=$1 desc=$2 want=$3 rc=0 out ok=0
  out=$(PATH="$tmp/bin:$PATH" STUB_CASES=$cases bash "$script" 2>&1) || rc=$?
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then ok=1; fi
  if ((ok)) && ! grep -qF -- "$want" <<<"$out"; then ok=0; fi
  if ((ok)); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc, want $expect)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

scenario good
check pass "every case reports its expected error" "# 4 passed, 0 failed"
check pass "a dev-only second libp2p-swarm is a case" "ok   - a dev-only second libp2p-swarm version fails bans"

# Severity: the same duplicate text as a warning (a global multiple-versions = "warn") is not a
# failure of the gate, even when another crate's error makes cargo deny exit non-zero.
scenario warn-swarm
answer libp2p-dup 1 "$(diag warning duplicate "found 2 duplicate entries for crate 'libp2p-swarm'"; \
  diag error duplicate "found 2 duplicate entries for crate 'libp2p-core'"; summary 1 1 0)"
check fail "libp2p-swarm duplicate only a warning, libp2p-core an error" "FAIL - a second libp2p-swarm version fails bans"
scenario warn-dev
answer dev-dup 0 "$(diag warning duplicate "found 2 duplicate entries for crate 'libp2p-swarm'"; summary 0 1 0)"
check fail "dev-only duplicate only a warning" "FAIL - a dev-only second libp2p-swarm version fails bans"
scenario warn-source
answer git-source 0 "$(diag warning source-not-allowed "detected 'git' source not specifically allowed" "$probe_src" deny-probe; summary 0 0 0)"
check fail "foreign git source only a warning" "FAIL - a git dependency outside allow-git fails sources"

# The exit must come from those diagnostics, not from something unrelated.
scenario network
answer libp2p-dup 1 "error: failed to fetch the index: found 2 duplicate entries for crate 'libp2p-swarm'"
check fail "non-zero exit with no cargo-deny report (network failure)" "FAIL - a second libp2p-swarm version fails bans"
scenario exit-zero
answer libp2p-dup 0 "$(dup_swarm; summary 1 0 0)"
check fail "error diagnostic but exit 0" "FAIL - a second libp2p-swarm version fails bans"
scenario other-error
answer libp2p-dup 1 "$(dup_swarm; diag error banned "crate 'openssl = 0.10.0' is explicitly banned"; summary 2 0 0)"
check fail "an unrelated error next to the expected one" "FAIL - a second libp2p-swarm version fails bans"
scenario wrong-crate
answer libp2p-dup 1 "$(diag error duplicate "found 2 duplicate entries for crate 'syn'"; summary 1 0 0)"
check fail "a duplicate of another crate, not libp2p-swarm" "FAIL - a second libp2p-swarm version fails bans"
scenario wrong-code
answer git-source 1 "$(diag error duplicate "found 2 duplicate entries for crate 'syn'"; summary 1 0 0)"
check fail "git-source fails with another code" "FAIL - a git dependency outside allow-git fails sources"
scenario summary-mismatch
answer libp2p-dup 1 "$(dup_swarm; summary 3 0 0)"
check fail "summary counts errors the report does not show" "FAIL - a second libp2p-swarm version fails bans"
scenario no-summary
answer git-source 1 "$(diag error source-not-allowed "detected 'git' source not specifically allowed" "$probe_src" deny-probe)"
check fail "report cut off before its summary" "FAIL - a git dependency outside allow-git fails sources"

# The control must be clean: exit 0 and no error.
scenario control-fails
answer control 1 "$(dup_swarm; summary 1 0 0)"
check fail "control copy fails cargo deny" "FAIL - control"

echo "# $passed passed, $failed failed"
((failed == 0))
