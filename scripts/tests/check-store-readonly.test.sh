#!/usr/bin/env bash
# Tests for scripts/check-store-readonly.sh.
# Run: bash scripts/tests/check-store-readonly.test.sh
# Each case is a fixture tree standing in for the repo; one case runs the real repo.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-store-readonly.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0

# fixture <name>: a cl-store crate that opens the env read-only.
fixture() {
  local root="$tmp/$1"
  mkdir -p "$root/crates/cl-store/src" "$root/crates/cl-store/tests"
  cat > "$root/crates/cl-store/src/lib.rs" <<'RS'
pub fn open(path: &Path) -> Result<Env> {
    let env = store_schema::env::open_reader(path)?;
    let txn = env.begin_ro_txn()?;
    Ok(env)
}
RS
  echo "$root"
}

# check <expect: pass|fail> <description> <root> [text the output must contain]
check() {
  local expect=$1 desc=$2 root=$3 want=${4:-} rc=0 out ok=0
  out=$(bash "$script" "$root" 2>&1) || rc=$?
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then ok=1; fi
  if ((ok)) && [[ -n $want ]] && ! grep -qF -- "$want" <<<"$out"; then ok=0; fi
  if ((ok)); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

root=$(fixture clean)
check pass "a read-only cl-store" "$root" "store readonly OK"

root="$tmp/absent"
mkdir -p "$root/crates"
check pass "no crates/cl-store/ (nothing to check)" "$root" "does not exist"

root=$(fixture mode)
printf 'let m = Mode::ReadWrite(ReadWriteOptions::default());\n' >> "$root/crates/cl-store/src/lib.rs"
check fail "Mode::ReadWrite" "$root" "crates/cl-store/src/lib.rs:6:"

root=$(fixture rw)
printf 'fn t() { let txn = env.begin_rw_txn().unwrap(); }\n' > "$root/crates/cl-store/tests/t.rs"
check fail "begin_rw_txn, in a test file too" "$root" "crates/cl-store/tests/t.rs:1:"

root=$(fixture writer)
printf 'let w = store_schema::env::open_writer(path, opts)?;\n' >> "$root/crates/cl-store/src/lib.rs"
check fail "store_schema::env::open_writer" "$root" "open_writer"

root=$(fixture columns)
printf 'use cl_chain_columns::ColumnWriter;\n' > "$root/crates/cl-store/src/main.rs"
check fail "cl-chain-columns' ColumnWriter" "$root" "main.rs:1:"

check pass "the real repo" "$repo" "store readonly OK"

echo "passed $passed, failed $failed"
((failed == 0))
