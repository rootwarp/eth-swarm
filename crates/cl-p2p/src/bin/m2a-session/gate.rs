//! The fuzz-gate pre-flight: no Status session without a passing m2a fuzz gate for the
//! decoders this binary was built from.
//!
//! The gate file is what `fuzz/run-m2a-gate.sh` writes (default `fuzz/artifacts/m2a-gate.json`).
//! [`check`] applies `fuzz/check-m2a-gate.sh`'s rules to it, against the values `build.rs`
//! embedded from `check-m2a-gate.sh --print-expected` of the build tree ([`Expected::built`];
//! a dirty keyed path voids them, as it fails the checker):
//!
//! - `gate` is `"m2a-fuzz"` and `format` is 1;
//! - `requested_seconds` is an integer of at least [`REQUIRED_SECONDS`];
//! - `dirty` is `false`;
//! - `head` is one of the expected `heads`: the build's commit or an ancestor of it with its
//!   decoder key (`m2a_key_heads`), so the file names a commit that was fuzzed for this build.
//!   The script checks the same with git (a commit of the repository, an ancestor of HEAD, its
//!   key from git the file's); this binary has no git at run time, so `build.rs` embeds the set;
//! - `decoder_key`, `limits` and `cargo_fuzz` equal the expected values exactly, and so do
//!   `toolchain.channel` and `toolchain.rustc_commit`;
//! - `overrides` is `{}`: no tool override (`CARGO`, `RUSTC`, `FUZZ_TOOLCHAIN`,
//!   `RUSTUP_TOOLCHAIN`) was in use;
//! - `targets` lists exactly [`TARGETS`], each with integer `seconds` of at least
//!   [`REQUIRED_SECONDS`], integer `execs` above 0, `crashes`, `ooms`, `timeouts` and
//!   `exit_code` 0, the expected `corpus_sha256`, an integer `seed_ft` at or above the
//!   target's floor (`min_seed_ft`; a target without one fails), an integer `final_ft` at or
//!   above `seed_ft`, `exercised` `true` and `completed` `true`.
//!
//! The rules are mirrored from the script, not shared with it, so the tests hold one list of
//! refused files (`tests::rule_cases`), and where the harness is in the tree they run the real
//! script on every one of them and require the same verdict.
//!
//! Like the script, the file is read once: every rule is checked against the one read.
//!
//! Where the script compares with Python's `==`, this is stricter about types: `crashes`,
//! `ooms`, `timeouts`, `exit_code` and `format` must be JSON integers (Python would also take
//! `false` or `0.0` for 0, or `1.0` for 1), and numbers inside `limits` compare as JSON values
//! (`2048.0` is not `2048`). `run-m2a-gate.sh` only ever writes integers there.

use serde_json::{Map, Value};
use std::io::Read as _;
use std::path::Path;

/// `M2A_TARGETS`: the four response decoders the session runs on peer bytes.
pub const TARGETS: [&str; 4] = [
    "status_v2",
    "metadata_v3",
    "ping_goodbye",
    "blocks_by_range_resp",
];
/// `M2A_REQUIRED_SECONDS`: the fuzzing time each target needs.
pub const REQUIRED_SECONDS: u64 = 3600;
/// What `check-m2a-gate.sh --print-expected` prints, every one required.
pub const EXPECTED_KEYS: [&str; 7] = [
    "decoder_key",
    "limits",
    "toolchain",
    "cargo_fuzz",
    "corpus_sha256",
    "min_seed_ft",
    "heads",
];
/// A gate file larger than this is not one `run-m2a-gate.sh` wrote.
const MAX_GATE_BYTES: u64 = 1 << 20;

/// What a gate file must hold for this binary.
#[derive(Debug, Clone, PartialEq)]
pub enum Expected {
    /// `check-m2a-gate.sh --print-expected` of the build tree: [`EXPECTED_KEYS`].
    Known(Value),
    /// Nothing can vouch for this build: why.
    Unavailable(String),
}

impl Expected {
    /// The values `build.rs` embedded.
    pub fn built() -> Self {
        Self::from_build(env!("M2A_GATE_EXPECTED"), env!("M2A_GATE_UNAVAILABLE"))
    }

    fn from_build(expected: &str, unavailable: &str) -> Self {
        if !unavailable.is_empty() {
            return Self::Unavailable(unavailable.to_owned());
        }
        match serde_json::from_str::<Value>(expected) {
            Ok(v) if EXPECTED_KEYS.iter().all(|k| v.get(k).is_some()) && heads_ok(&v["heads"]) => {
                Self::Known(v)
            }
            _ => Self::Unavailable("the embedded gate expectations are malformed".to_owned()),
        }
    }
}

/// `heads` is a non-empty list of commit ids.
fn heads_ok(heads: &Value) -> bool {
    heads
        .as_array()
        .is_some_and(|h| !h.is_empty() && h.iter().all(Value::is_string))
}

/// The default gate file: `fuzz/artifacts/m2a-gate.json` of the checkout the binary was built
/// in.
pub const DEFAULT_GATE_FILE: &str = env!("M2A_DEFAULT_GATE_FILE");

/// Why the gate refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    /// Nothing can vouch for this build.
    #[error("no gate can vouch for this build: {0}")]
    Unavailable(String),
    /// The gate file could not be read.
    #[error("gate file {path}: {reason}")]
    Read {
        /// The file.
        path: String,
        /// Why.
        reason: String,
    },
    /// The gate file does not pass.
    #[error("gate file {path}: {}", .errors.join("; "))]
    Invalid {
        /// The file.
        path: String,
        /// Every failed rule.
        errors: Vec<String>,
    },
}

/// Checks the gate file at `path` against `expected`.
pub fn check(path: &Path, expected: &Expected) -> Result<(), GateError> {
    let want = match expected {
        Expected::Known(v) => v,
        Expected::Unavailable(why) => return Err(GateError::Unavailable(why.clone())),
    };
    let shown = path.display().to_string();
    let read_err = |reason: String| GateError::Read {
        path: shown.clone(),
        reason,
    };
    let too_big = || {
        read_err(format!(
            "not a regular file of at most {MAX_GATE_BYTES} bytes"
        ))
    };
    let file = std::fs::File::open(path).map_err(|e| read_err(e.to_string()))?;
    let meta = file.metadata().map_err(|e| read_err(e.to_string()))?;
    if !meta.is_file() || meta.len() > MAX_GATE_BYTES {
        return Err(too_big());
    }
    let mut text = Vec::new();
    file.take(MAX_GATE_BYTES + 1)
        .read_to_end(&mut text)
        .map_err(|e| read_err(e.to_string()))?;
    if text.len() as u64 > MAX_GATE_BYTES {
        return Err(too_big());
    }
    let gate: Value =
        serde_json::from_slice(&text).map_err(|e| read_err(format!("not valid JSON: {e}")))?;
    let errors = rules(&gate, want);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(GateError::Invalid {
            path: shown,
            errors,
        })
    }
}

fn as_int(v: Option<&Value>) -> Option<i128> {
    match v? {
        Value::Number(n) => n
            .as_u64()
            .map(i128::from)
            .or_else(|| n.as_i64().map(i128::from)),
        _ => None,
    }
}

fn show(v: Option<&Value>) -> String {
    v.map_or_else(|| "missing".to_owned(), Value::to_string)
}

/// Every rule `gate` breaks.
fn rules(gate: &Value, want: &Value) -> Vec<String> {
    let Some(obj) = gate.as_object() else {
        return vec!["not a JSON object".to_owned()];
    };
    let required = i128::from(REQUIRED_SECONDS);
    let mut errors = Vec::new();
    if obj.get("gate") != Some(&Value::from("m2a-fuzz")) || as_int(obj.get("format")) != Some(1) {
        errors.push(format!(
            "gate/format: want m2a-fuzz format 1, got {} format {}",
            show(obj.get("gate")),
            show(obj.get("format"))
        ));
    }
    if !as_int(obj.get("requested_seconds")).is_some_and(|s| s >= required) {
        errors.push(format!(
            "requested_seconds: {} < {required} (a smoke run is not a gate)",
            show(obj.get("requested_seconds"))
        ));
    }
    if obj.get("dirty") != Some(&Value::Bool(false)) {
        errors.push(format!(
            "dirty: {}: the run was not from a clean tree",
            show(obj.get("dirty"))
        ));
    }
    if let Some(e) = head_rule(obj.get("head"), &want["heads"]) {
        errors.push(e);
    }
    if obj.get("decoder_key") != want.get("decoder_key") {
        errors.extend(key_diff(obj.get("decoder_key"), &want["decoder_key"]));
    }
    if obj.get("limits") != want.get("limits") {
        errors.push(format!(
            "limits: {}, want {}",
            show(obj.get("limits")),
            want["limits"]
        ));
    }
    let empty = Map::new();
    let toolchain = obj
        .get("toolchain")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    for field in ["channel", "rustc_commit"] {
        if toolchain.get(field) != want["toolchain"].get(field) {
            errors.push(format!(
                "toolchain {field}: {}, want {}",
                show(toolchain.get(field)),
                want["toolchain"][field]
            ));
        }
    }
    if obj.get("overrides") != Some(&Value::Object(Map::new())) {
        errors.push(format!(
            "overrides: {}: a gate run uses no tool override (smoke runs only)",
            show(obj.get("overrides"))
        ));
    }
    if obj.get("cargo_fuzz") != want.get("cargo_fuzz") {
        errors.push(format!(
            "cargo_fuzz: {}, want {}",
            show(obj.get("cargo_fuzz")),
            want["cargo_fuzz"]
        ));
    }
    errors.extend(target_rules(obj.get("targets"), required, want));
    errors
}

/// Why `head` is not one of `heads` (the build's commit and its ancestors with its decoder key),
/// if it is not. A commit id is as long as theirs: 40 hex digits, or 64 in a sha256 repository.
fn head_rule(head: Option<&Value>, heads: &Value) -> Option<String> {
    let Some(Value::String(head)) = head else {
        return Some("head: missing, or not a string".to_owned());
    };
    let heads = heads.as_array().map_or(&[][..], Vec::as_slice);
    let len = heads.first().and_then(Value::as_str).map_or(40, str::len);
    let hex = |c: char| c.is_ascii_digit() || ('a'..='f').contains(&c);
    if head.len() != len || !head.chars().all(hex) {
        let shown: String = head.chars().take(80).collect();
        return Some(format!(
            "head: {shown:?} is not a {len}-character lowercase hex commit id"
        ));
    }
    if heads.iter().any(|h| h.as_str() == Some(head)) {
        return None;
    }
    Some(format!(
        "head: {head} is not the build's commit or an ancestor of it with its decoder key: it was not fuzzed for this build"
    ))
}

/// The keyed entries where the gate's key and ours differ.
fn key_diff(got: Option<&Value>, want: &Value) -> Vec<String> {
    let empty = Map::new();
    let got = got.and_then(Value::as_object).unwrap_or(&empty);
    let want = want.as_object().unwrap_or(&empty);
    let mut kinds: Vec<&String> = got.keys().chain(want.keys()).collect();
    kinds.sort();
    kinds.dedup();
    let mut out = Vec::new();
    for kind in kinds {
        let mine = want.get(kind).and_then(Value::as_object).unwrap_or(&empty);
        let theirs = got.get(kind).and_then(Value::as_object).unwrap_or(&empty);
        let mut paths: Vec<&String> = mine.keys().chain(theirs.keys()).collect();
        paths.sort();
        paths.dedup();
        for p in paths {
            if mine.get(p) != theirs.get(p) {
                out.push(format!(
                    "decoder key stale: {kind} {p}: gate {}, build {}",
                    show(theirs.get(p)),
                    show(mine.get(p))
                ));
            }
        }
    }
    if out.is_empty() {
        out.push("decoder key stale".to_owned());
    }
    out
}

fn target_rules(targets: Option<&Value>, required: i128, want: &Value) -> Vec<String> {
    let corpus = &want["corpus_sha256"];
    let floors = &want["min_seed_ft"];
    let mut errors = Vec::new();
    let list = targets
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let mut names: Vec<&str> = list
        .iter()
        .filter_map(|t| t.get("target").and_then(Value::as_str))
        .collect();
    names.sort_unstable();
    let mut want = TARGETS.to_vec();
    want.sort_unstable();
    if names != want || names.len() != list.len() {
        errors.push(format!(
            "targets: want exactly {TARGETS:?}, got {}",
            show(targets)
        ));
    }
    for t in list.iter().filter_map(Value::as_object) {
        let name = t.get("target").and_then(Value::as_str).unwrap_or("?");
        match as_int(t.get("seconds")) {
            None => errors.push(format!(
                "{name}: seconds {} is not an integer",
                show(t.get("seconds"))
            )),
            Some(s) if s < required => errors.push(format!("{name}: {s} s < {required} s")),
            Some(_) => {}
        }
        if !as_int(t.get("execs")).is_some_and(|e| e > 0) {
            errors.push(format!("{name}: execs {}", show(t.get("execs"))));
        }
        for field in ["crashes", "ooms", "timeouts", "exit_code"] {
            if as_int(t.get(field)) != Some(0) {
                errors.push(format!("{name}: {field} {}, want 0", show(t.get(field))));
            }
        }
        if let Some(seeds) = corpus.get(name) {
            if t.get("corpus_sha256") != Some(seeds) {
                errors.push(format!(
                    "{name}: corpus_sha256 {} is not fuzz/corpus/{name} ({seeds})",
                    show(t.get("corpus_sha256"))
                ));
            }
        }
        let (seed_ft, final_ft) = (as_int(t.get("seed_ft")), as_int(t.get("final_ft")));
        let floor = floors.get(name);
        if !matches!((seed_ft, floor.and_then(|f| as_int(Some(f)))), (Some(s), Some(f)) if s >= f) {
            errors.push(format!(
                "{name}: seed_ft {} under the floor {}: the target did not run its decoder",
                show(t.get("seed_ft")),
                show(floor)
            ));
        }
        if final_ft.is_none() || seed_ft.is_some_and(|s| final_ft < Some(s)) {
            errors.push(format!(
                "{name}: final_ft {} below seed_ft {}",
                show(t.get("final_ft")),
                show(t.get("seed_ft"))
            ));
        }
        if t.get("exercised") != Some(&Value::Bool(true)) {
            errors.push(format!("{name}: exercised {}", show(t.get("exercised"))));
        }
        if t.get("completed") != Some(&Value::Bool(true)) {
            errors.push(format!(
                "{name}: completed {}: libFuzzer did not finish its run",
                show(t.get("completed"))
            ));
        }
    }
    errors
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// Expectations shaped like `check-m2a-gate.sh --print-expected` output.
    pub(crate) fn fixture_expected() -> Value {
        json!({
            "decoder_key": {
                "git": {
                    "Cargo.toml": "1111111111111111111111111111111111111111",
                    "crates/p2p-wire": "2222222222222222222222222222222222222222",
                    "crates/cl-p2p/src/rpc/codec.rs": "3333333333333333333333333333333333333333",
                    "fuzz/src": "4444444444444444444444444444444444444444"
                },
                "sha256": {"Cargo.lock": "cd".repeat(32), "fuzz/Cargo.lock": "ab".repeat(32)}
            },
            "limits": {
                "rss_limit_mb": 2048, "malloc_limit_mb": 128, "timeout_s": 10,
                "build_flags": ["-O", "-a"],
                "max_len": {"status_v2": 4096, "metadata_v3": 4096, "ping_goodbye": 4096,
                            "blocks_by_range_resp": 2097152}
            },
            "toolchain": {"channel": "nightly-2026-10-17", "rustc_commit": "5".repeat(40)},
            "cargo_fuzz": "cargo-fuzz 0.13.2",
            "corpus_sha256": {
                "status_v2": "c1".repeat(32), "metadata_v3": "c2".repeat(32),
                "ping_goodbye": "c3".repeat(32), "blocks_by_range_resp": "c4".repeat(32)
            },
            "min_seed_ft": {
                "status_v2": 200, "metadata_v3": 200, "ping_goodbye": 200,
                "blocks_by_range_resp": 2000
            },
            "heads": ["9a".repeat(20), "8b".repeat(20)]
        })
    }

    /// A passing gate file for `want`, shaped as `run-m2a-gate.sh` writes it.
    pub(crate) fn passing_gate(want: &Value) -> Value {
        let targets: Vec<Value> = TARGETS
            .iter()
            .map(|t| {
                json!({
                    "target": t, "seconds": 3601, "execs": 123456789u64, "crashes": 0,
                    "ooms": 0, "timeouts": 0, "completed": true, "exit_code": 0,
                    "peak_rss_mb": 300, "new_units": 12, "artifacts": [],
                    "corpus_sha256": want["corpus_sha256"][t], "corpus_files": 9,
                    "found_corpus_files": 40,
                    "seed_ft": want["min_seed_ft"][t].as_u64().unwrap() + 100,
                    "final_ft": want["min_seed_ft"][t].as_u64().unwrap() + 250,
                    "exercised": true
                })
            })
            .collect();
        json!({
            "gate": "m2a-fuzz", "format": 1, "requested_seconds": 3600,
            "head": want["heads"][0], "dirty": false, "decoder_key": want["decoder_key"],
            "toolchain": {
                "channel": want["toolchain"]["channel"],
                "rustc_commit": want["toolchain"]["rustc_commit"],
                "rustc": "rustc 1.101.0-nightly (5d8fec066 2026-10-16)"
            },
            "cargo_fuzz": want["cargo_fuzz"],
            "overrides": {},
            "limits": want["limits"],
            "targets": targets
        })
    }

    fn errors_of(gate: &Value) -> Vec<String> {
        rules(gate, &fixture_expected())
    }

    fn with(mut gate: Value, edit: impl FnOnce(&mut Value)) -> Value {
        edit(&mut gate);
        gate
    }

    #[test]
    fn a_passing_gate_file_passes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m2a-gate.json");
        let text = serde_json::to_string_pretty(&passing_gate(&fixture_expected())).unwrap();
        std::fs::write(&path, text).unwrap();
        assert_eq!(check(&path, &Expected::Known(fixture_expected())), Ok(()));
    }

    /// Whether `check-m2a-gate.sh` decides a case the same way.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Script {
        /// It refuses the file too.
        Refuses,
        /// It accepts the file (Python's `==` takes `false` for 0, `1.0` for 1); this checker is
        /// stricter about types.
        Accepts,
    }

    /// Every rule of the checker as one refused gate file each: the error it must produce,
    /// the file, and what the script does with it. The single list both the unit test and the
    /// cross-check against the real script use.
    pub(crate) fn rule_cases(want: &Value) -> Vec<(&'static str, Value, Script)> {
        let ok = passing_gate(want);
        let edit = |f: fn(&mut Value)| with(ok.clone(), f);
        use Script::{Accepts, Refuses};
        vec![
            ("gate/format", edit(|g| g["gate"] = json!("other")), Refuses),
            ("gate/format", edit(|g| g["format"] = json!(2)), Refuses),
            ("gate/format", edit(|g| g["format"] = json!(true)), Accepts),
            (
                "smoke run",
                edit(|g| g["requested_seconds"] = json!(60)),
                Refuses,
            ),
            (
                "requested_seconds",
                edit(|g| g["requested_seconds"] = json!(3600.0)),
                Refuses,
            ),
            ("clean tree", edit(|g| g["dirty"] = json!(true)), Refuses),
            ("clean tree", edit(|g| g["dirty"] = json!(null)), Refuses),
            (
                "decoder key stale: git",
                edit(|g| {
                    let git = g["decoder_key"]["git"].as_object_mut().unwrap();
                    let first = git.keys().next().unwrap().clone();
                    git.insert(first, json!("0"));
                }),
                Refuses,
            ),
            (
                "decoder key stale: sha256 fuzz/Cargo.lock",
                edit(|g| g["decoder_key"]["sha256"]["fuzz/Cargo.lock"] = json!("0")),
                Refuses,
            ),
            (
                "decoder key stale: sha256 Cargo.lock",
                edit(|g| g["decoder_key"]["sha256"]["Cargo.lock"] = json!("0")),
                Refuses,
            ),
            (
                "decoder key stale: git fuzz/extra",
                edit(|g| g["decoder_key"]["git"]["fuzz/extra"] = json!("0")),
                Refuses,
            ),
            (
                "decoder key stale",
                edit(|g| g["decoder_key"] = json!([])),
                Refuses,
            ),
            (
                "limits:",
                edit(|g| g["limits"]["malloc_limit_mb"] = json!(256)),
                Refuses,
            ),
            (
                "limits:",
                edit(|g| g["limits"]["rss_limit_mb"] = json!(2048.0)),
                Accepts,
            ),
            (
                "limits:",
                edit(|g| g["limits"]["max_len"]["status_v2"] = json!(64)),
                Refuses,
            ),
            (
                "toolchain channel",
                edit(|g| g["toolchain"]["channel"] = json!("stable")),
                Refuses,
            ),
            (
                "toolchain rustc_commit",
                edit(|g| g["toolchain"] = json!("x")),
                Refuses,
            ),
            (
                "overrides:",
                edit(|g| g["overrides"] = json!({"CARGO": "/x/cargo"})),
                Refuses,
            ),
            (
                "overrides:",
                edit(|g| {
                    g.as_object_mut().unwrap().remove("overrides");
                }),
                Refuses,
            ),
            ("overrides:", edit(|g| g["overrides"] = json!([])), Refuses),
            (
                "cargo_fuzz:",
                edit(|g| g["cargo_fuzz"] = json!("cargo-fuzz 0.12.0")),
                Refuses,
            ),
            (
                "targets: want exactly",
                edit(|g| {
                    g["targets"].as_array_mut().unwrap().pop();
                }),
                Refuses,
            ),
            (
                "targets: want exactly",
                edit(|g| {
                    let first = g["targets"][0].clone();
                    g["targets"].as_array_mut().unwrap().push(first);
                }),
                Refuses,
            ),
            (
                "targets: want exactly",
                edit(|g| {
                    g["targets"].as_array_mut().unwrap().push(json!(7));
                }),
                Refuses,
            ),
            (
                "targets: want exactly",
                edit(|g| g["targets"] = json!({})),
                Refuses,
            ),
            (
                "3599 s < 3600 s",
                edit(|g| g["targets"][0]["seconds"] = json!(3599)),
                Refuses,
            ),
            (
                "is not an integer",
                edit(|g| g["targets"][1]["seconds"] = json!("3600")),
                Refuses,
            ),
            (
                "execs 0",
                edit(|g| g["targets"][0]["execs"] = json!(0)),
                Refuses,
            ),
            (
                "crashes 1, want 0",
                edit(|g| g["targets"][0]["crashes"] = json!(1)),
                Refuses,
            ),
            (
                "crashes false",
                edit(|g| g["targets"][0]["crashes"] = json!(false)),
                Accepts,
            ),
            (
                "ooms 1",
                edit(|g| g["targets"][2]["ooms"] = json!(1)),
                Refuses,
            ),
            (
                "timeouts 2",
                edit(|g| g["targets"][3]["timeouts"] = json!(2)),
                Refuses,
            ),
            (
                "exit_code 1",
                edit(|g| g["targets"][0]["exit_code"] = json!(1)),
                Refuses,
            ),
            (
                "metadata_v3: corpus_sha256",
                edit(|g| g["targets"][1]["corpus_sha256"] = json!("00")),
                Refuses,
            ),
            (
                "status_v2: seed_ft 80 under the floor",
                edit(|g| g["targets"][0]["seed_ft"] = json!(80)),
                Refuses,
            ),
            (
                "blocks_by_range_resp: seed_ft",
                edit(|g| {
                    let t = &mut g["targets"][3];
                    t["seed_ft"] = json!(t["seed_ft"].to_string());
                }),
                Refuses,
            ),
            (
                "ping_goodbye: seed_ft missing",
                edit(|g| {
                    g["targets"][2].as_object_mut().unwrap().remove("seed_ft");
                }),
                Refuses,
            ),
            (
                "status_v2: final_ft",
                edit(|g| {
                    let t = &mut g["targets"][0];
                    t["final_ft"] = json!(t["seed_ft"].as_u64().unwrap() - 1);
                }),
                Refuses,
            ),
            (
                "metadata_v3: final_ft missing",
                edit(|g| {
                    g["targets"][1].as_object_mut().unwrap().remove("final_ft");
                }),
                Refuses,
            ),
            (
                "status_v2: exercised false",
                edit(|g| g["targets"][0]["exercised"] = json!(false)),
                Refuses,
            ),
            (
                "ping_goodbye: exercised missing",
                edit(|g| {
                    g["targets"][2].as_object_mut().unwrap().remove("exercised");
                }),
                Refuses,
            ),
            (
                "did not finish",
                edit(|g| g["targets"][0]["completed"] = json!(false)),
                Refuses,
            ),
            ("head: missing", edit(|g| g["head"] = json!(null)), Refuses),
            (
                "head: missing",
                edit(|g| {
                    g.as_object_mut().unwrap().remove("head");
                }),
                Refuses,
            ),
            ("head: missing", edit(|g| g["head"] = json!(7)), Refuses),
            (
                "lowercase hex commit id",
                edit(|g| g["head"] = json!("")),
                Refuses,
            ),
            (
                "lowercase hex commit id",
                edit(|g| g["head"] = json!(g["head"].as_str().unwrap().to_uppercase())),
                Refuses,
            ),
            (
                "lowercase hex commit id",
                edit(|g| g["head"] = json!(format!("{}0", g["head"].as_str().unwrap()))),
                Refuses,
            ),
            (
                "lowercase hex commit id",
                edit(|g| g["head"] = json!(g["head"].as_str().unwrap()[1..].to_owned())),
                Refuses,
            ),
            (
                "lowercase hex commit id",
                edit(|g| g["head"] = json!(format!("{} ", g["head"].as_str().unwrap()))),
                Refuses,
            ),
            (
                "was not fuzzed for this build",
                edit(|g| g["head"] = json!("0".repeat(40))),
                Refuses,
            ),
            (
                "was not fuzzed for this build",
                edit(|g| g["head"] = json!("1234567".repeat(5) + "12345")),
                Refuses,
            ),
            ("not a JSON object", json!([1]), Refuses),
        ]
    }

    #[test]
    fn every_rule_of_the_checker() {
        assert!(errors_of(&passing_gate(&fixture_expected())).is_empty());
        for (want, gate, _) in rule_cases(&fixture_expected()) {
            let errors = errors_of(&gate);
            assert!(
                errors.iter().any(|e| e.contains(want)),
                "want {want:?} in {errors:?}"
            );
        }
    }

    #[test]
    fn a_head_behind_the_build_with_its_key_passes() {
        let want = fixture_expected();
        let mut gate = passing_gate(&want);
        gate["head"] = want["heads"][1].clone();
        assert!(errors_of(&gate).is_empty(), "{:?}", errors_of(&gate));
        // The heads are 64 characters long in a sha256 repository.
        let mut want = fixture_expected();
        want["heads"] = json!(["ab".repeat(32)]);
        let gate = passing_gate(&want);
        assert!(rules(&gate, &want).is_empty(), "{:?}", rules(&gate, &want));
        let mut short = gate.clone();
        short["head"] = json!("ab".repeat(20));
        let errors = rules(&short, &want);
        assert!(
            errors.iter().any(|e| e.contains("64-character")),
            "{errors:?}"
        );
    }

    #[test]
    fn a_target_without_a_floor_fails() {
        let mut want = fixture_expected();
        want["min_seed_ft"]
            .as_object_mut()
            .unwrap()
            .remove("ping_goodbye");
        let errors = rules(&passing_gate(&fixture_expected()), &want);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("ping_goodbye: seed_ft"), "{errors:?}");
        assert!(errors[0].contains("floor missing"), "{errors:?}");
    }

    /// The real `fuzz/check-m2a-gate.sh` and this checker decide every case of
    /// [`rule_cases`] (and a passing file) alike, on this tree's expected values. Runs only
    /// where the fuzz harness is in the tree and its keyed paths are clean.
    #[test]
    fn agrees_with_the_fuzz_harness_checker() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let checker = repo.join("fuzz/check-m2a-gate.sh");
        if !checker.is_file() {
            eprintln!("skipping: fuzz/check-m2a-gate.sh is not in this tree (no fuzz harness)");
            return;
        }
        let script = |args: &[&std::ffi::OsStr]| {
            std::process::Command::new("bash")
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("GIT_OPTIONAL_LOCKS", "0")
                .current_dir(&repo)
                .arg(&checker)
                .args(args)
                .output()
                .unwrap()
        };
        let printed = script(&["--print-expected".as_ref()]);
        assert!(printed.status.success(), "{printed:?}");
        let want: Value = serde_json::from_slice(&printed.stdout).unwrap();
        let dirty = std::process::Command::new("bash")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .current_dir(&repo)
            .args(["-c", r#". fuzz/m2a-common.sh && m2a_dirty_paths"#])
            .output()
            .unwrap();
        if !dirty.stdout.is_empty() {
            eprintln!(
                "skipping: keyed paths have uncommitted changes, so the script refuses every file:\n{}",
                String::from_utf8_lossy(&dirty.stdout)
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut cases = vec![("passes", passing_gate(&want), None)];
        cases.extend(
            rule_cases(&want)
                .into_iter()
                .map(|(rule, gate, by_script)| (rule, gate, Some(by_script))),
        );
        // The heads that need this repository: HEAD's tree (not a commit) and the newest
        // ancestor with another decoder key (absent from a shallow clone).
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .current_dir(&repo)
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?}: {out:?}");
            String::from_utf8(out.stdout).unwrap()
        };
        let mut tree = passing_gate(&want);
        tree["head"] = Value::from(git(&["rev-parse", "HEAD^{tree}"]).trim());
        cases.push(("a tree as head", tree, Some(Script::Refuses)));
        let heads = want["heads"].as_array().unwrap();
        if let Some(older) = git(&["rev-list", "HEAD"])
            .lines()
            .find(|c| !heads.contains(&Value::from(*c)))
        {
            let mut gate = passing_gate(&want);
            gate["head"] = Value::from(older);
            cases.push(("an ancestor with another key", gate, Some(Script::Refuses)));
        }
        if let Some(behind) = heads.get(1) {
            let mut gate = passing_gate(&want);
            gate["head"] = behind.clone();
            cases.push(("a head behind HEAD with its key", gate, None));
        }
        for (i, (rule, gate, by_script)) in cases.into_iter().enumerate() {
            let path = dir.path().join(format!("case-{i}.json"));
            std::fs::write(&path, gate.to_string()).unwrap();
            let ours = check(&path, &Expected::Known(want.clone())).is_ok();
            let out = script(&[path.as_os_str()]);
            let theirs = match out.status.code() {
                Some(0) => true,
                Some(1) => false,
                other => panic!("{rule}: the script exited {other:?}: {out:?}"),
            };
            match by_script {
                None => assert!(ours && theirs, "{rule}: ours {ours}, script {out:?}"),
                Some(Script::Refuses) => {
                    assert!(!ours && !theirs, "{rule}: ours {ours}, script {theirs}")
                }
                Some(Script::Accepts) => {
                    assert!(!ours && theirs, "{rule}: ours {ours}, script {theirs}")
                }
            }
        }
    }

    #[test]
    fn missing_unreadable_and_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let want = Expected::Known(fixture_expected());
        let missing = dir.path().join("missing.json");
        assert!(matches!(
            check(&missing, &want),
            Err(GateError::Read { .. })
        ));
        assert!(matches!(
            check(dir.path(), &want),
            Err(GateError::Read { .. })
        ));
        let garbage = dir.path().join("garbage.json");
        std::fs::write(&garbage, "{not json").unwrap();
        let err = check(&garbage, &want).unwrap_err();
        assert!(err.to_string().contains("not valid JSON"), "{err}");
        let huge = dir.path().join("huge.json");
        std::fs::write(&huge, vec![b' '; (MAX_GATE_BYTES + 1) as usize]).unwrap();
        assert!(matches!(check(&huge, &want), Err(GateError::Read { .. })));
        let good = dir.path().join("good.json");
        std::fs::write(&good, passing_gate(&fixture_expected()).to_string()).unwrap();
        let err = check(
            &good,
            &Expected::Unavailable("fuzz/src is not in HEAD".into()),
        );
        assert_eq!(
            err,
            Err(GateError::Unavailable("fuzz/src is not in HEAD".into()))
        );
        let mut stale = passing_gate(&fixture_expected());
        stale["dirty"] = json!(true);
        std::fs::write(&good, stale.to_string()).unwrap();
        let err = check(&good, &want).unwrap_err();
        assert!(
            matches!(&err, GateError::Invalid { errors, .. } if errors.len() == 1),
            "{err}"
        );
    }

    #[test]
    fn embedded_expectations_parse() {
        assert_eq!(
            Expected::from_build("", "fuzz/m2a-common.sh is not in this tree"),
            Expected::Unavailable("fuzz/m2a-common.sh is not in this tree".into())
        );
        assert_eq!(
            Expected::from_build(&fixture_expected().to_string(), ""),
            Expected::Known(fixture_expected())
        );
        let mut no_floors = fixture_expected();
        no_floors.as_object_mut().unwrap().remove("min_seed_ft");
        assert!(matches!(
            Expected::from_build(&no_floors.to_string(), ""),
            Expected::Unavailable(_)
        ));
        for heads in [json!(null), json!([]), json!("9a"), json!([7])] {
            let mut bad = fixture_expected();
            bad["heads"] = heads.clone();
            assert!(
                matches!(
                    Expected::from_build(&bad.to_string(), ""),
                    Expected::Unavailable(_)
                ),
                "{heads}"
            );
        }
        for bad in ["[]", "{}", "not json", r#"{"decoder_key": {}}"#] {
            assert!(
                matches!(Expected::from_build(bad, ""), Expected::Unavailable(_)),
                "{bad}"
            );
        }
        // This build's: either every expected value, or a reason.
        match Expected::built() {
            Expected::Known(v) => assert!(v["decoder_key"]["git"].is_object()),
            Expected::Unavailable(why) => assert!(!why.is_empty()),
        }
    }
}
