//! The fuzz gates' decoder keys (`fuzz/m2a-common.sh`) hold the workspace-crate closure of the
//! crates that they key (`ci_checks::fuzz_keys`). The closure comes from `cargo metadata` of the
//! root workspace and of the fuzz workspace: each workspace crate that a keyed crate depends on,
//! transitively, through normal and build dependencies, keyed as its whole directory. A change
//! to any of them makes each gate stale.
//!
//! The keys are read as bash sees them: the script is sourced in a cleared environment, and
//! `gate_select` runs for each gate, so no later assignment in the script can change a key
//! without this test seeing it.

mod common;

use ci_checks::fuzz_keys::{
    closure, harness_reads, key_gaps, packages, proto_imports, stale_build_inputs, BuildInputs,
    Package,
};
use common::{checked, workspace_root};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const SCRIPT: &str = "fuzz/m2a-common.sh";

/// The files that the build script of a crate in a closure reads outside its crate directory,
/// and why the list is complete. A crate with a build script and no entry fails the test.
const BUILD_INPUTS: &[BuildInputs<'static>] = &[
    BuildInputs {
        dir: "crates/ethswarm-proto",
        paths: &["proto/ethswarm"],
        reason: "build.rs compiles the .proto files under proto/ethswarm (its include root is \
            proto/, and every import there is under proto/ethswarm) into the bindings that the \
            crate includes from OUT_DIR",
    },
    BuildInputs {
        dir: "crates/cl-p2p",
        paths: &[],
        reason: "build.rs runs the fuzz gate scripts and git only for the m2a-session binary: \
            it writes the gate expectations and the build state that src/bin/m2a-session \
            embeds, and the library reads none of them",
    },
];

/// The packages of the root workspace and of the fuzz workspace (`cargo metadata --no-deps`:
/// the manifests only, so it needs no network and no fetched sources).
fn workspace_packages(root: &Path) -> Vec<Package> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut all = Vec::new();
    for manifest in ["Cargo.toml", "fuzz/Cargo.toml"] {
        let json = checked(
            Command::new(&cargo)
                .current_dir(root)
                .args([
                    "metadata",
                    "--format-version",
                    "1",
                    "--no-deps",
                    "--offline",
                ])
                .arg("--manifest-path")
                .arg(root.join(manifest)),
        );
        all.extend(packages(&json, root).unwrap_or_else(|e| panic!("{manifest}: {e}")));
    }
    all
}

/// The `[patch]` and `[replace]` entries with a `path` in the manifest of a workspace. Cargo
/// metadata `--no-deps` does not show them, and a patched crate would be a workspace crate that
/// no closure holds.
fn path_patches(manifest: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(manifest).expect("read the manifest");
    let toml: toml::Value = toml::from_str(&text).expect("parse the manifest");
    let mut found = Vec::new();
    let mut tables = Vec::new();
    if let Some(patch) = toml.get("patch").and_then(toml::Value::as_table) {
        tables.extend(patch.values().filter_map(toml::Value::as_table));
    }
    if let Some(replace) = toml.get("replace").and_then(toml::Value::as_table) {
        tables.push(replace);
    }
    for table in tables {
        for (name, spec) in table {
            if spec.get("path").is_some() {
                found.push(format!("{}: {name}", manifest.display()));
            }
        }
    }
    found
}

/// The gates that `gate_select` of the script knows.
const GATES: [&str; 4] = ["m2a", "gate1", "gate2a", "gate2b"];

/// The keys of `fuzz/m2a-common.sh` as the gate scripts use them: `GATE_KEY_PATHS` after
/// `gate_select <gate>`, for each gate, and `M2A_KEY_FILES`. The script is sourced by the
/// `bash` on `PATH` (the one that the other script tests use) with a cleared environment.
struct Keys {
    paths: BTreeMap<String, Vec<String>>,
    files: Vec<String>,
}

fn keys(root: &Path) -> Keys {
    const PRINT: &str = r#"set -eu
. "$1"
shift
for gate in "$@"; do
  gate_select "$gate"
  printf '== %s\n' "$gate"
  printf '%s\n' "${GATE_KEY_PATHS[@]}"
done
printf '== files\n'
printf '%s\n' "${M2A_KEY_FILES[@]}"
"#;
    let path = std::env::var_os("PATH").unwrap_or_default();
    let out = checked(
        Command::new("bash")
            .env_clear()
            .env("PATH", path)
            .current_dir(root)
            .args(["-c", PRINT, "fuzz-keys", SCRIPT])
            .args(GATES),
    );
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current = None;
    for line in out.lines() {
        if let Some(name) = line.strip_prefix("== ") {
            current = Some(name.to_owned());
            lists.entry(name.to_owned()).or_default();
        } else if let Some(name) = &current {
            lists.get_mut(name).expect("listed").push(line.to_owned());
        }
    }
    let files = lists.remove("files").expect("M2A_KEY_FILES printed");
    Keys {
        paths: lists,
        files,
    }
}

fn names(closure: &BTreeMap<PathBuf, PathBuf>) -> Vec<String> {
    closure.keys().map(|d| d.display().to_string()).collect()
}

#[test]
fn every_key_holds_the_workspace_crate_closure_of_the_crates_it_keys() {
    let root = workspace_root();
    let keys = keys(&root);
    let mut gates: Vec<&str> = keys.paths.keys().map(String::as_str).collect();
    gates.sort_by_key(|g| GATES.iter().position(|k| k == g));
    assert_eq!(gates, GATES);
    // The workspace manifest (features) and both lockfiles are in every key.
    for lock in ["Cargo.lock", "fuzz/Cargo.lock"] {
        assert!(keys.files.iter().any(|f| f == lock), "{:?}", keys.files);
    }
    let all = workspace_packages(&root);
    let mut gaps = Vec::new();
    let mut closures = BTreeSet::new();
    for (gate, paths) in &keys.paths {
        assert!(paths.iter().any(|p| p == "Cargo.toml"), "{gate}: {paths:?}");
        for path in paths {
            assert!(root.join(path).exists(), "{gate}: {path} does not exist");
        }
        let reached = closure(paths, &all).expect("the closure");
        // The harness is keyed by every gate, so each closure holds every crate it links.
        assert!(
            reached.contains_key(Path::new("fuzz")),
            "{gate} does not key the harness: {:?}",
            names(&reached)
        );
        closures.extend(reached.into_keys());
        for gap in key_gaps(paths, &all, BUILD_INPUTS).expect("the closure") {
            gaps.push(format!("{gate}: {gap}"));
        }
    }
    assert!(
        gaps.is_empty(),
        "{SCRIPT}: key these too (a build script's inputs go in BUILD_INPUTS of {}):\n{}",
        file!(),
        gaps.join("\n")
    );
    let stale = stale_build_inputs(&all, &closures, BUILD_INPUTS);
    assert!(
        stale.is_empty(),
        "stale BUILD_INPUTS:\n{}",
        stale.join("\n")
    );
    for manifest in ["Cargo.toml", "fuzz/Cargo.toml"] {
        let patches = path_patches(&root.join(manifest));
        assert!(
            patches.is_empty(),
            "a path patch is a workspace crate that no closure holds:\n{}",
            patches.join("\n")
        );
    }
}

/// The closure is the same for every gate: the fuzz targets are the binaries of one package,
/// so each target links the harness library and every crate that it depends on.
#[test]
fn every_gate_keys_the_same_closure_from_the_harness() {
    let root = workspace_root();
    let all = workspace_packages(&root);
    let harness = closure(&["fuzz/Cargo.toml".to_owned()], &all).expect("the closure");
    for (gate, paths) in &keys(&root).paths {
        let reached = closure(paths, &all).expect("the closure");
        assert_eq!(names(&reached), names(&harness), "{gate}");
    }
}

/// Each crate directory of the m2a key is needed: without it the key has a gap.
#[test]
fn a_key_without_any_one_crate_of_its_closure_has_a_gap() {
    let root = workspace_root();
    let all = workspace_packages(&root);
    let m2a = &keys(&root).paths["m2a"];
    let crates: Vec<&String> = m2a.iter().filter(|p| p.starts_with("crates/")).collect();
    assert!(crates.len() >= 2, "{m2a:?}");
    for dropped in crates {
        let paths: Vec<String> = m2a.iter().filter(|p| *p != dropped).cloned().collect();
        let gaps = key_gaps(&paths, &all, BUILD_INPUTS).expect("the closure");
        assert!(
            gaps.iter().any(|g| g.starts_with(&format!("{dropped}: "))),
            "{dropped}: {gaps:?}"
        );
    }
}

/// A dev-dependency is not in a closure: cl-p2p's dev-dependency cl-chain-columns, for one, is
/// reached only through the harness.
#[test]
fn dev_dependencies_stay_out_of_a_closure() {
    let root = workspace_root();
    let all = workspace_packages(&root);
    let p2p = closure(&["crates/cl-p2p".to_owned()], &all).expect("the closure");
    assert!(p2p.contains_key(Path::new("crates/ethswarm-proto")));
    assert!(!p2p.contains_key(Path::new("crates/cl-chain")), "{p2p:?}");
    assert!(!p2p.contains_key(Path::new("crates/cl-chain-columns")));
}

/// A `#[path]` attribute or an `include!` macro in the harness could read a file of the harness
/// directory that no key holds (`fuzz/tests`, `fuzz/examples`): the harness has none.
#[test]
fn the_harness_reads_no_file_through_a_path_or_an_include() {
    let root = workspace_root();
    let all = workspace_packages(&root);
    let reads = harness_reads(&root, &all).expect("the harness sources");
    assert!(reads.is_empty(), "{}", reads.join("\n"));
}

/// Each import of the protos that ethswarm-proto compiles resolves under its include root,
/// `proto/`, to a file that every key holds.
#[test]
fn every_proto_import_is_keyed() {
    let root = workspace_root();
    let keys = keys(&root);
    let mut protos = Vec::new();
    let mut todo = vec![root.join("proto/ethswarm")];
    while let Some(dir) = todo.pop() {
        for entry in std::fs::read_dir(&dir).expect("read a proto directory") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                todo.push(path);
            } else if path.extension().is_some_and(|e| e == "proto") {
                protos.push(path);
            }
        }
    }
    assert!(protos.len() >= 10, "{protos:?}");
    let mut missing = Vec::new();
    for proto in &protos {
        let text = std::fs::read_to_string(proto).expect("read a proto");
        for import in proto_imports(&text) {
            let target = Path::new("proto").join(&import);
            let keyed = keys
                .paths
                .values()
                .all(|paths| paths.iter().any(|k| target.starts_with(k)));
            if !root.join(&target).is_file() || !keyed {
                missing.push(format!("{}: import {import}", proto.display()));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "not under a keyed path:\n{}",
        missing.join("\n")
    );
}
