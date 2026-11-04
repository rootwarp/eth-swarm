#!/usr/bin/env bash
# Tests for scripts/check-stamped-commits.sh.
# Run: bash scripts/tests/check-stamped-commits.test.sh
# Each case is a fixture tree standing in for the repo; one case runs the real repo.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-stamped-commits.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0

# fixture <name>: a tree with clean store-schema, cl-chain-columns and cl-chain sources. txn.rs
# commits raw (the one allowed place) and every test module commits raw too.
fixture() {
  local root="$tmp/$1"
  mkdir -p "$root/crates/store-schema/src" "$root/crates/cl-chain-columns/src" \
    "$root/crates/cl-chain/src"
  cat > "$root/crates/store-schema/src/txn.rs" <<'RS'
pub fn commit(txn: RwTxn<'_>, update: Update) -> Result<()> {
    txn.commit()?;
    Ok(())
}
RS
  cat > "$root/crates/store-schema/src/env.rs" <<'RS'
/// Commits through `txn::commit`, never `txn.commit()` itself.
pub fn open() -> Result<()> {
    let txn = env.begin_rw_txn()?;
    txn::commit(txn, Update::Carry)?;
    store_schema::txn::commit(txn, Update::Carry)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    fn put() {
        let txn = env.begin_rw_txn().unwrap();
        txn.commit().unwrap();
    }

    mod nested {
        fn raw() {
            txn.commit().unwrap();
        }
    }
}
RS
  cat > "$root/crates/cl-chain-columns/src/writer.rs" <<'RS'
fn write_txn() -> Result<()> {
    // A raw txn.commit() here would skip the stamp.
    let stamp = store_schema::txn::commit(txn, Update::Carry)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    fn raw() {
        txn.commit().unwrap();
    }
}
RS
  cat > "$root/crates/cl-chain/src/import.rs" <<'RS'
/// A block's rows and its new stamp in one txn.
fn import(txn: RwTxn<'_>, stamp: Stamp) -> Result<()> {
    store_schema::txn::commit(txn, Update::New(stamp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    fn raw() {
        txn.commit().unwrap();
    }
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
check pass "txn.rs, txn::commit calls, comments and test modules" "$root" "stamped commits OK"

root=$(fixture columns)
printf 'fn prune() {\n    txn.commit()?;\n}\n' >> "$root/crates/cl-chain-columns/src/writer.rs"
check fail "a raw commit in cl-chain-columns" "$root" "crates/cl-chain-columns/src/writer.rs:14:"

root=$(fixture schema)
printf 'fn upgrade() {\n    txn.commit().map_err(Error::from)?;\n}\n' > "$root/crates/store-schema/src/version.rs"
check fail "a raw commit in store-schema outside txn.rs" "$root" "crates/store-schema/src/version.rs:2:"

root=$(fixture ufcs)
printf 'fn f() {\n    libmdbx::Transaction::commit(txn)?;\n}\n' > "$root/crates/cl-chain-columns/src/reader.rs"
check fail "Transaction::commit(txn)" "$root" "reader.rs:2:"

root=$(fixture chained)
printf 'fn f() {\n    txn\n        .commit ()?;\n}\n' > "$root/crates/cl-chain-columns/src/sched.rs"
check fail "a method chain across lines, a space before (" "$root" "sched.rs:3:"

root=$(fixture helper)
printf '#[cfg(test)]\npub(crate) fn make_legacy() {\n    txn.commit().unwrap();\n}\n' \
  > "$root/crates/cl-chain-columns/src/lib.rs"
check fail "a #[cfg(test)] helper outside the tests module" "$root" "lib.rs:3:"

root=$(fixture after)
printf 'fn after_the_tests() {\n    txn.commit()?;\n}\n' >> "$root/crates/store-schema/src/env.rs"
check fail "production code after the tests module" "$root" "env.rs:23:"

root=$(fixture nested)
mkdir -p "$root/crates/cl-chain-columns/src/sub"
printf 'fn f() {\n    txn.commit()?;\n}\n' > "$root/crates/cl-chain-columns/src/sub/deep.rs"
check fail "a file in a subdirectory" "$root" "src/sub/deep.rs:2:"

root=$(fixture missing)
rm -rf "$root/crates/cl-chain-columns"
check fail "a missing crate directory (never vacuous)" "$root" "not found"

# Other spellings of a raw commit (#295).
root=$(fixture rwtxn)
printf 'fn upgrade() {\n    RwTxn::commit(txn)?;\n}\n' > "$root/crates/store-schema/src/version.rs"
check fail "RwTxn::commit(txn) through the alias" "$root" "crates/store-schema/src/version.rs:2:"

root=$(fixture turbofish)
printf 'fn f() {\n    Transaction::<RW, NoWriteMap>::commit(txn)?;\n}\n' \
  > "$root/crates/store-schema/src/stamp.rs"
check fail "Transaction::<RW, NoWriteMap>::commit(txn)" "$root" "crates/store-schema/src/stamp.rs:2:"

root=$(fixture rebind)
printf 'fn f() {\n    let (_, dbs) = txn.commit_and_rebind_open_dbs()?;\n}\n' \
  > "$root/crates/store-schema/src/blocks.rs"
check fail "txn.commit_and_rebind_open_dbs()" "$root" "crates/store-schema/src/blocks.rs:2:"

# cl-chain writes the env too (block import): its sources are scanned (#295).
root=$(fixture chain)
printf 'fn persist() {\n    txn.commit()?;\n}\n' > "$root/crates/cl-chain/src/persist.rs"
check fail "a raw commit in cl-chain" "$root" "crates/cl-chain/src/persist.rs:2:"

root=$(fixture chain_missing)
rm -rf "$root/crates/cl-chain"
check fail "a missing crates/cl-chain directory (never vacuous)" "$root" "not found"

# txn::commit_open, the writer open's commit without a stamp row of its own, is called only
# from crates/store-schema/src/env.rs (#295).
root=$(fixture open_env)
cat > "$root/crates/store-schema/src/env.rs" <<'RS'
/// The open's txn commits through `txn::commit_open`: no stamp row of its own.
pub fn open_writer_with() -> Result<()> {
    let txn = env.begin_rw_txn()?;
    txn::commit_open(txn)?;
    crate::txn::commit_open (txn)?;
    Ok(())
}
RS
check pass "txn::commit_open from store-schema's env.rs" "$root" "stamped commits OK"

root=$(fixture open_blocks)
printf 'fn put() -> Result<()> {\n    txn::commit_open(txn)?;\n    Ok(())\n}\n' \
  > "$root/crates/store-schema/src/blocks.rs"
check fail "txn::commit_open in store-schema's blocks.rs" "$root" \
  "crates/store-schema/src/blocks.rs:2:"

root=$(fixture open_columns)
printf 'fn open() {\n    store_schema::txn::commit_open (txn)?;\n}\n' \
  >> "$root/crates/cl-chain-columns/src/writer.rs"
check fail "txn::commit_open in cl-chain-columns" "$root" \
  "crates/cl-chain-columns/src/writer.rs:14:"

root=$(fixture open_chain_env)
printf 'fn open() {\n    store_schema::txn::commit_open(txn)?;\n}\n' \
  > "$root/crates/cl-chain/src/env.rs"
check fail "txn::commit_open in an env.rs that is not store-schema's" "$root" \
  "crates/cl-chain/src/env.rs:2:"

root=$(fixture open_use)
printf 'use crate::txn::commit_open;\n\nfn upgrade() {\n    commit_open(txn)?;\n}\n' \
  > "$root/crates/store-schema/src/version.rs"
check fail "commit_open imported, then called bare" "$root" "crates/store-schema/src/version.rs:4:"

# Test modules and comments stay exempt from every spelling above.
root=$(fixture test_modules)
cat > "$root/crates/store-schema/src/blocks.rs" <<'RS'
// Not txn::commit_open(txn) nor RwTxn::commit(txn): blocks commit with their stamp.
pub fn put() {}

#[cfg(test)]
pub(crate) mod tests {
    fn raw() {
        RwTxn::commit(txn).unwrap();
        Transaction::<RW, NoWriteMap>::commit(txn).unwrap();
        txn.commit_and_rebind_open_dbs().unwrap();
        crate::txn::commit_open(txn).unwrap();
    }
}
RS
cat > "$root/crates/cl-chain/src/persist.rs" <<'RS'
pub fn persist() {}

#[cfg(test)]
mod tests {
    fn raw() {
        txn.commit().unwrap();
        RwTxn::commit(txn).unwrap();
        store_schema::txn::commit_open(txn).unwrap();
    }
}
RS
check pass "every spelling inside test modules and comments" "$root" "stamped commits OK"

check pass "the real repo" "$repo" "stamped commits OK"

echo "passed $passed, failed $failed"
((failed == 0))
