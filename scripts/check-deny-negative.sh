#!/usr/bin/env bash
# Negative test of the cargo-deny gate: prove that `cargo deny check` FAILS on what deny.toml
# must refuse, so a loosened deny.toml (multiple-versions back to "warn", dev-dependencies left out,
# a libp2p* skip entry, a wider allow-git) cannot pass CI unnoticed. Each case copies the workspace
# manifests into a throwaway directory, injects one violation and passes only if cargo deny fails
# with the expected diagnostic:
#   control      the unmodified copy passes `cargo deny check bans sources` with no error (so a
#                failure below comes from the injected violation, not from the copy)
#   libp2p-dup   a second libp2p-swarm version (crates.io =0.47.1 next to the patched 0.48)
#                -> error[duplicate] for crate 'libp2p-swarm'
#   dev-dup      the same, as a dev-dependency only (multiple-versions-include-dev)
#                -> error[duplicate] for crate 'libp2p-swarm'
#   git-source   a git dependency from a repo outside [sources] allow-git (a local file:// repo,
#                so no third-party fetch) -> error[source-not-allowed] for crate 'deny-probe'
#
# Verdict: cargo deny runs with --format json and the report is parsed (python3 -I, >= 3.6). A
# failing case passes only if cargo deny exits non-zero, its report ends in a summary whose error
# count matches the error diagnostics, and every error is the expected code naming the expected
# crate: the same text as a warning, an unrelated error or an exit without a report (a network
# failure) does not count.
#
# Lockfile: the injected dependency must be resolved, so `cargo update --workspace` writes the
# copy's own Cargo.lock (it cannot take --locked, and it never touches the repo's lock). Every
# cargo deny run is --locked against that lock. Needs crates.io access (libp2p-dup, dev-dup), git,
# python3 and cargo-deny. Usage: scripts/check-deny-negative.sh
# Exit: 0 every case behaved, 1 otherwise. Works on bash 3.2.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
command -v python3 >/dev/null || { echo "ERROR: python3 is required to read the cargo-deny report"; exit 1; }

passed=0 failed=0

# workspace <name>: a copy of the workspace manifests, lockfile, deny.toml and crate sources.
workspace() {
  local ws="$tmp/$1"
  mkdir -p "$ws"
  (cd "$root" && tar cf - --exclude target Cargo.toml Cargo.lock deny.toml rust-toolchain.toml crates) | tar xf - -C "$ws"
  echo "$ws"
}

# inject <ws> <Cargo.toml lines...>: appends a dependency table to cl-p2p and resolves it.
inject() {
  local ws=$1
  shift
  printf '%s\n' "" "$@" >> "$ws/crates/cl-p2p/Cargo.toml"
  cargo update --workspace --quiet --manifest-path "$ws/Cargo.toml"
}

# The verdict on one cargo-deny JSON report (stdin). argv: <exit code> <expect: pass|fail> [<code>
# <needle>]. Prints why it is wrong and exits 1, or exits 0.
read -r -d '' VERDICT <<'PY' || true
import json, sys

rc, expect = int(sys.argv[1]), sys.argv[2]
code, needle = (sys.argv[3], sys.argv[4]) if expect == "fail" else (None, None)
diags, summary = [], None
for line in sys.stdin:
    try:
        item = json.loads(line)
    except ValueError:
        continue
    if not isinstance(item, dict) or not isinstance(item.get("fields"), dict):
        continue
    if item.get("type") == "diagnostic":
        diags.append(item["fields"])
    elif item.get("type") == "summary":
        summary = item["fields"]

def text(d):
    # The message, the label spans and the crates the graphs start from.
    parts = [d.get("message", "")]
    parts += [l.get("span", "") for l in d.get("labels") or [] if isinstance(l, dict)]
    parts += ["crate '%s'" % (g.get("Krate") or {}).get("name", "")
              for g in d.get("graphs") or [] if isinstance(g, dict)]
    return "\n".join(str(p) for p in parts)

errors = [d for d in diags if d.get("severity") == "error"]
problems = []
if summary is None:
    problems.append("no cargo-deny summary: the run did not complete")
else:
    counted = sum(int(s.get("errors", 0)) for s in summary.values() if isinstance(s, dict))
    if counted != len(errors):
        problems.append("summary counts %d errors, the report has %d" % (counted, len(errors)))
if expect == "pass":
    if rc != 0:
        problems.append("cargo deny exited %d, want 0" % rc)
    problems += ["unexpected error[%s]: %s" % (d.get("code"), d.get("message")) for d in errors]
else:
    if rc == 0:
        problems.append("cargo deny exited 0, want non-zero")
    if not any(d.get("code") == code and needle in text(d) for d in errors):
        problems.append("no error[%s] naming %s" % (code, needle))
    problems += ["unrelated error[%s]: %s" % (d.get("code"), d.get("message"))
                 for d in errors if d.get("code") != code]
for p in problems:
    print(p)
sys.exit(1 if problems else 0)
PY

# deny <expect: pass|fail> <description> <ws> [<diagnostic code> <crate named by it>]
deny() {
  local expect=$1 desc=$2 ws=$3 rc=0 out why
  shift 3
  out=$(cargo deny --locked --format json --manifest-path "$ws/Cargo.toml" check bans sources 2>&1) || rc=$?
  if why=$(python3 -I -c "$VERDICT" "$rc" "$expect" "$@" <<<"$out" 2>&1); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc, want $expect)"
    printf '%s\n' "$why" | sed 's/^/       /'
    printf '%s\n' "$out" | sed 's/^/       | /'
  fi
}

ws=$(workspace control)
deny pass "control: the unmodified workspace passes bans and sources" "$ws"

ws=$(workspace libp2p-dup)
inject "$ws" '[dependencies.libp2p-swarm-second]' 'package = "libp2p-swarm"' 'version = "=0.47.1"'
deny fail "a second libp2p-swarm version fails bans" "$ws" duplicate "crate 'libp2p-swarm'"

ws=$(workspace dev-dup)
inject "$ws" '[dev-dependencies.libp2p-swarm-second]' 'package = "libp2p-swarm"' 'version = "=0.47.1"'
deny fail "a dev-only second libp2p-swarm version fails bans" "$ws" duplicate "crate 'libp2p-swarm'"

ws=$(workspace git-source)
probe="$tmp/probe"
mkdir -p "$probe/src"
printf '[package]\nname = "deny-probe"\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\n' > "$probe/Cargo.toml"
: > "$probe/src/lib.rs"
git -C "$probe" init -q
git -C "$probe" add -A
git -C "$probe" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false commit -q -m probe
rev=$(git -C "$probe" rev-parse HEAD)
inject "$ws" '[dependencies.deny-probe]' "git = \"file://$probe\"" "rev = \"$rev\""
deny fail "a git dependency outside allow-git fails sources" "$ws" source-not-allowed "crate 'deny-probe'"

echo "# $passed passed, $failed failed"
((failed == 0))
