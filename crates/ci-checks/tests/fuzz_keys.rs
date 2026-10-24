//! The fuzz gates' decoder keys (`fuzz/m2a-common.sh`) hold every module that a keyed file
//! imports, the crate root of each keyed module, and each workspace crate that keyed code
//! imports, unless [`ALLOWED`] lists the importing file with a reason (`ci_checks::fuzz_keys`): a
//! change to any of them makes each gate that runs it stale.

mod common;

use ci_checks::fuzz_keys::{
    key_arrays, not_allowed, stale_allowances, unkeyed_crates, unkeyed_imports, unsafe_globs,
    Allowance,
};
use common::workspace_root;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

const SCRIPT: &str = "fuzz/m2a-common.sh";

/// The workspace crates that keyed code of a gate imports but that the gate does not key: the
/// key array, the crate directory, the keyed files that may import it, and why no fuzz target
/// of that gate runs its code on fuzz input. An import from any other file fails the test, and a
/// listed file that no longer imports the crate is stale.
const ALLOWED: &[Allowance<'static>] = &[
    allow(
        "M2A_KEY_PATHS",
        "crates/ethswarm-proto",
        CL_P2P_PROTO,
        ETHSWARM_PROTO,
    ),
    allow(
        "GATE1_KEY_PATHS",
        "crates/ethswarm-proto",
        GATE1_PROTO,
        ETHSWARM_PROTO,
    ),
    allow("M2A_KEY_PATHS", "crates/ipc", CL_P2P_IPC, IPC),
    allow("GATE1_KEY_PATHS", "crates/ipc", GATE1_IPC, IPC),
    allow("M2A_KEY_PATHS", "crates/cl-chain", FUZZ_CL_CHAIN, CL_CHAIN),
    allow(
        "GATE1_KEY_PATHS",
        "crates/cl-chain",
        FUZZ_CL_CHAIN,
        CL_CHAIN,
    ),
    allow(
        "M2A_KEY_PATHS",
        "crates/cl-chain-columns",
        FUZZ_CONTRACT,
        CL_CHAIN_COLUMNS,
    ),
    allow(
        "GATE1_KEY_PATHS",
        "crates/cl-chain-columns",
        FUZZ_CONTRACT,
        CL_CHAIN_COLUMNS,
    ),
    allow("M2A_KEY_PATHS", "crates/cl-discv5", FUZZ_RECORD, CL_DISCV5),
    allow(
        "GATE2A_KEY_PATHS",
        "crates/cl-discv5",
        FUZZ_RECORD,
        CL_DISCV5,
    ),
    allow(
        "GATE2B_KEY_PATHS",
        "crates/cl-discv5",
        FUZZ_RECORD,
        CL_DISCV5,
    ),
    allow(
        "M2A_KEY_PATHS",
        "crates/node-key",
        CL_P2P_NODE_KEY,
        NODE_KEY,
    ),
    allow(
        "GATE1_KEY_PATHS",
        "crates/node-key",
        GATE1_NODE_KEY,
        NODE_KEY,
    ),
    allow(
        "GATE2A_KEY_PATHS",
        "crates/node-key",
        CL_P2P_NODE_KEY,
        NODE_KEY,
    ),
    allow(
        "GATE2B_KEY_PATHS",
        "crates/node-key",
        CL_P2P_NODE_KEY,
        NODE_KEY,
    ),
];

const fn allow(
    gate: &'static str,
    dir: &'static str,
    files: &'static [&'static str],
    reason: &'static str,
) -> Allowance<'static> {
    Allowance {
        gate,
        dir,
        files,
        reason,
    }
}

/// cl-p2p's chain.v1 users: the custody subscription, the service stub, the Status source, and
/// the column answers with the inbound behaviour that serves them; and the gate-2b harness.
const CL_P2P_PROTO: &[&str] = &[
    "crates/cl-p2p/src/custody.rs",
    "crates/cl-p2p/src/lib.rs",
    "crates/cl-p2p/src/rpc/chain_status.rs",
    "crates/cl-p2p/src/rpc/columns.rs",
    "crates/cl-p2p/src/rpc/inbound.rs",
    "fuzz/src/contract.rs",
];
/// [`CL_P2P_PROTO`] and the cl-discv5 service stub, which gate 1 keys.
const GATE1_PROTO: &[&str] = &[
    "crates/cl-discv5/src/lib.rs",
    "crates/cl-p2p/src/custody.rs",
    "crates/cl-p2p/src/lib.rs",
    "crates/cl-p2p/src/rpc/chain_status.rs",
    "crates/cl-p2p/src/rpc/columns.rs",
    "crates/cl-p2p/src/rpc/inbound.rs",
    "fuzz/src/contract.rs",
];
/// cl-p2p's service stub and its column answers' link to cl-chain; and the gate-2b harness.
const CL_P2P_IPC: &[&str] = &[
    "crates/cl-p2p/src/lib.rs",
    "crates/cl-p2p/src/rpc/columns.rs",
    "fuzz/src/contract.rs",
];
/// [`CL_P2P_IPC`] and the cl-discv5 service stub, which gate 1 keys.
const GATE1_IPC: &[&str] = &[
    "crates/cl-discv5/src/lib.rs",
    "crates/cl-p2p/src/lib.rs",
    "crates/cl-p2p/src/rpc/columns.rs",
    "fuzz/src/contract.rs",
];
/// The gate-2a and gate-2b harnesses.
const FUZZ_CL_CHAIN: &[&str] = &["fuzz/src/columns.rs", "fuzz/src/contract.rs"];
/// The gate-2b harness.
const FUZZ_CONTRACT: &[&str] = &["fuzz/src/contract.rs"];
/// The gate-1 record harness.
const FUZZ_RECORD: &[&str] = &["fuzz/src/record.rs"];
/// cl-p2p's identity and the m2a-session key file.
const CL_P2P_NODE_KEY: &[&str] = &[
    "crates/cl-p2p/src/identity.rs",
    "crates/cl-p2p/src/m2a_session.rs",
];
/// [`CL_P2P_NODE_KEY`] and cl-discv5's record key, which gate 1 keys.
const GATE1_NODE_KEY: &[&str] = &[
    "crates/cl-discv5/src/enr.rs",
    "crates/cl-p2p/src/identity.rs",
    "crates/cl-p2p/src/m2a_session.rs",
];

const ETHSWARM_PROTO: &str = "the chain.v1 messages that cl-p2p's column answers, Status \
    source and service stub, and the cl-discv5 service stub, exchange with cl-chain: no m2a or \
    gate-1 target builds or reads one. Gates 2a and 2b key it.";
const IPC: &str = "the contract layer of the cl-p2p and cl-discv5 gRPC service stubs and of \
    cl-p2p's column answers' link to cl-chain: no m2a or gate-1 target runs it. Gates 2a and 2b \
    key it.";
const CL_CHAIN: &str = "only fuzz/src/columns.rs and fuzz/src/contract.rs import it, for the \
    gate-2a and gate-2b targets: no m2a or gate-1 target runs it. Gates 2a and 2b key it.";
const CL_CHAIN_COLUMNS: &str = "only fuzz/src/contract.rs imports it, for column_contract \
    (gate 2b): no m2a or gate-1 target runs it. Gates 2a and 2b key it.";
const CL_DISCV5: &str = "only fuzz/src/record.rs imports it, for enr_fields (gate 1): no \
    m2a, gate-2a or gate-2b target runs it. Gate 1 keys it.";
const NODE_KEY: &str = "loads a node key credential from a file at startup (cl-p2p's \
    identity and the m2a-session key file, cl-discv5's record key): no fuzz target loads a key, \
    and none of its code runs on peer bytes.";

/// `path` with every `.` and `..` removed.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn read_manifest(path: &Path) -> Result<toml::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The workspace root of the crate in `krate` (relative to `root`): the nearest manifest at or
/// above it, not above `root`, with a `[workspace]` table, and that manifest.
fn workspace_of(root: &Path, krate: &Path) -> Result<(PathBuf, toml::Value), String> {
    let mut dir = krate.to_path_buf();
    loop {
        let manifest = root.join(&dir).join("Cargo.toml");
        if manifest.is_file() {
            let toml = read_manifest(&manifest)?;
            if toml.get("workspace").is_some() {
                return Ok((dir, toml));
            }
        }
        if !dir.pop() {
            return Err(format!(
                "{}: no workspace root at or above it",
                krate.display()
            ));
        }
    }
}

/// The normal path dependencies of the crate in `krate` (relative to `root`): each name in
/// code and its directory. A dependency is a version string, or a table with `path` (relative
/// to the crate), with `workspace = true` (resolved through `[workspace.dependencies]` of the
/// workspace root, a path there relative to that root), or with neither (a registry or git
/// dependency).
///
/// # Errors
///
/// A manifest that cannot be read, or a dependency of another form: never "not a path
/// dependency" for a form this cannot resolve.
fn path_deps(root: &Path, krate: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    let manifest = read_manifest(&root.join(krate).join("Cargo.toml"))?;
    let mut tables = vec![manifest.get("dependencies")];
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        tables.extend(targets.values().map(|t| t.get("dependencies")));
    }
    let mut workspace = None;
    let mut deps = BTreeMap::new();
    for table in tables
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
    {
        for (name, spec) in table {
            let err = |why: &str| format!("{}: {name}: {why}", krate.join("Cargo.toml").display());
            let dir = match spec {
                toml::Value::String(_) => None,
                toml::Value::Table(t) => match (t.get("path"), t.get("workspace")) {
                    (Some(path), None) => {
                        let path = path.as_str().ok_or_else(|| err("path is not a string"))?;
                        Some(normalize(&krate.join(path)))
                    }
                    (None, Some(toml::Value::Boolean(true))) => {
                        if workspace.is_none() {
                            workspace = Some(workspace_of(root, krate)?);
                        }
                        let (ws_dir, ws) = workspace.as_ref().expect("set above");
                        let entry = ws
                            .get("workspace")
                            .and_then(|w| w.get("dependencies"))
                            .and_then(|d| d.get(name))
                            .ok_or_else(|| {
                                err("workspace = true, but [workspace.dependencies] has no entry")
                            })?;
                        match entry {
                            toml::Value::String(_) => None,
                            toml::Value::Table(e) => match e.get("path") {
                                None => None,
                                Some(path) => {
                                    let path = path
                                        .as_str()
                                        .ok_or_else(|| err("workspace path is not a string"))?;
                                    Some(normalize(&ws_dir.join(path)))
                                }
                            },
                            _ => return Err(err("workspace entry is not a version or a table")),
                        }
                    }
                    (None, Some(other)) => return Err(err(&format!("workspace = {other}"))),
                    (Some(_), Some(_)) => return Err(err("both path and workspace")),
                    (None, None) => None,
                },
                _ => return Err(err("not a version string or a table")),
            };
            if let Some(dir) = dir {
                deps.insert(name.replace('-', "_"), dir);
            }
        }
    }
    Ok(deps)
}

#[test]
fn every_module_a_keyed_file_imports_is_keyed() {
    let root = workspace_root();
    let script = std::fs::read_to_string(root.join(SCRIPT)).expect("read the gate script");
    let arrays = key_arrays(&script).expect("the key arrays");
    // m2a, gate 1, gate 2a and gate 2b.
    assert_eq!(
        arrays.keys().collect::<Vec<_>>(),
        [
            "GATE1_KEY_PATHS",
            "GATE2A_KEY_PATHS",
            "GATE2B_KEY_PATHS",
            "M2A_KEY_PATHS"
        ]
    );
    let deps = |krate: &Path| path_deps(&root, krate);
    let mut missing = Vec::new();
    let mut used = BTreeSet::new();
    for (gate, paths) in &arrays {
        assert!(
            ALLOWED.iter().all(|a| arrays.contains_key(a.gate)),
            "an allowance names no key array"
        );
        for unkeyed in unkeyed_imports(&root, paths).expect("the keyed sources") {
            missing.push(format!("{gate}: {unkeyed}"));
        }
        for glob in unsafe_globs(&root, paths, &deps).expect("the keyed sources") {
            missing.push(format!("{gate}: {glob}"));
        }
        let found = unkeyed_crates(&root, paths, &deps).expect("the keyed sources");
        for unkeyed in not_allowed(gate, found, ALLOWED, &mut used) {
            missing.push(format!("{gate}: {unkeyed}"));
        }
    }
    assert!(
        missing.is_empty(),
        "{SCRIPT}: key these too, or allow the importing file in {}:\n{}",
        file!(),
        missing.join("\n")
    );
    let stale = stale_allowances(ALLOWED, &used);
    assert!(stale.is_empty(), "stale allowances:\n{}", stale.join("\n"));
}

/// A `workspace = true` dependency resolves through the `[workspace.dependencies]` of the
/// workspace root manifest; a form that cannot be read, or a workspace name the root does not
/// define, is an error, never "not a path dependency".
#[test]
fn workspace_dependencies_resolve_through_the_root_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let write = |path: &str, text: &str| {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/x\"]\n[workspace.dependencies]\n\
         y-crate = { path = \"crates/y\" }\nserde = \"1\"\nz = { version = \"1\" }\n",
    );
    write(
        "crates/x/Cargo.toml",
        "[package]\nname = \"x\"\n[dependencies]\ny-crate = { workspace = true }\n\
         serde = { workspace = true }\nz.workspace = true\nw = { path = \"../w\" }\n\
         [target.'cfg(unix)'.dependencies]\nu = { path = \"../u\" }\n",
    );
    let deps = path_deps(root, Path::new("crates/x")).unwrap();
    assert_eq!(
        deps,
        [
            ("u", "crates/u"),
            ("w", "crates/w"),
            ("y_crate", "crates/y")
        ]
        .map(|(n, d)| (n.to_owned(), PathBuf::from(d)))
        .into_iter()
        .collect()
    );
    for (dep, want) in [
        ("q = { workspace = true }", "q: workspace = true, but"),
        ("q = 5", "q: not a version string or a table"),
        ("q = { workspace = false }", "q: workspace = false"),
    ] {
        write(
            "crates/x/Cargo.toml",
            &format!("[package]\nname = \"x\"\n[dependencies]\n{dep}\n"),
        );
        let err = path_deps(root, Path::new("crates/x")).unwrap_err();
        assert!(err.contains(want), "{dep}: {err}");
    }
}
