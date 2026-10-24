//! The fuzz gates' decoder keys (`fuzz/m2a-common.sh`) must hold the workspace-crate closure of
//! the crates that they key.
//!
//! A gate file is stale when a keyed path changes. A workspace crate that a fuzz target links
//! but that the key does not hold can change and leave an old gate valid, so this check fails
//! on it. The caller gives the keyed paths of one gate (the integration test reads them from
//! bash, after `gate_select`). A package is keyed if the key holds a path inside its
//! directory. The closure of the keyed packages follows their path dependencies, transitively
//! ([`closure`]), and [`key_gaps`] reports each package of the closure that the key does not
//! hold whole. The key must also hold the directory of the root file of each built target of a
//! package (a `[lib] path`, `[[bin]] path` or `build` can be outside the package directory).
//!
//! The dependency graph comes from `cargo metadata` ([`packages`]), not from the source text.
//! A `use`, a re-export, a glob or an `extern crate` can name only a crate that cargo links, so
//! no import form can reach a crate outside the closure. A crate is keyed as its whole
//! directory, so a `#[path]` attribute or an `include!` that stays inside the crate directory
//! reaches only keyed files too.
//!
//! - Normal and build dependencies are followed. A build script runs when its crate is built,
//!   and the code that it generates is compiled into the crate.
//! - Dev-dependencies are not followed. Cargo builds them only for the tests, benches and
//!   examples of their own crate. Neither `cargo fuzz build` nor a dependent crate builds those.
//! - Optional and target-specific dependencies are followed: a feature or a platform can turn
//!   them on.
//!
//! A package whose directory is the root of its own workspace (the fuzz harness, `fuzz/`) holds
//! the build output of that workspace (`fuzz/target`, `fuzz/artifacts`), which the clean-tree
//! check of the gate must not see. So such a package is keyed by its manifest and by the
//! directory of the root file of each target that is built for it: lib, bin, proc-macro and
//! custom-build, not test, bench or example. A root file directly in the package directory
//! (`fuzz/build.rs`) is keyed as its file. A `#[path]` attribute or an `include!` macro in a
//! harness source could read an unkeyed file of the harness directory (`fuzz/tests`), so
//! [`harness_reads`] reports each one.
//!
//! A build script can read files outside its crate directory. Cargo does not say which, so each
//! package of the closure that has a build script needs a [`BuildInputs`] entry. The entry lists
//! those files, and the key must hold each of them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use yaml_rust2::{Yaml, YamlLoader};

/// How a package depends on another (`kind` in `cargo metadata`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepKind {
    /// `[dependencies]`.
    Normal,
    /// `[build-dependencies]`.
    Build,
    /// `[dev-dependencies]`.
    Dev,
}

/// One path dependency of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathDep {
    /// The kind of the dependency.
    pub kind: DepKind,
    /// The directory of the dependency, relative to the repository root.
    pub dir: PathBuf,
}

/// One package of a `cargo metadata` output. The paths are relative to the repository root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// The package name.
    pub name: String,
    /// The directory of its manifest.
    pub dir: PathBuf,
    /// The directory is the root of the workspace of the package.
    pub own_workspace: bool,
    /// The package has a build script.
    pub build_script: bool,
    /// The root file of each target that is built when the package is built as a dependency or
    /// by `cargo fuzz build`: lib, bin, proc-macro and custom-build.
    pub built_sources: Vec<PathBuf>,
    /// Its path dependencies, of each kind.
    pub path_deps: Vec<PathDep>,
}

/// The packages of one `cargo metadata --format-version 1` output (`--no-deps` is enough),
/// with paths made relative to `root`.
///
/// The output is JSON. It is read with the YAML parser that this crate already has, because
/// YAML 1.2 is a superset of JSON.
///
/// # Errors
///
/// Text that does not parse, a field that is missing or of another type, an unknown dependency
/// kind, or a path outside `root`.
pub fn packages(metadata: &str, root: &Path) -> Result<Vec<Package>, String> {
    let docs = YamlLoader::load_from_str(metadata)
        .map_err(|e| format!("cargo metadata: does not parse: {e}"))?;
    let doc = docs
        .first()
        .ok_or("cargo metadata: does not parse: no document")?;
    let list = doc["packages"]
        .as_vec()
        .ok_or("cargo metadata: no packages list")?;
    let workspace = rel_path(root, str_field(doc, "workspace_root", "cargo metadata")?)?;
    list.iter().map(|p| package(p, root, &workspace)).collect()
}

fn package(p: &Yaml, root: &Path, workspace: &Path) -> Result<Package, String> {
    let name = str_field(p, "name", "a package")?.to_owned();
    let manifest = rel_path(root, str_field(p, "manifest_path", &name)?)?;
    let dir = manifest
        .parent()
        .ok_or_else(|| format!("{name}: manifest_path has no directory"))?
        .to_path_buf();
    let mut build_script = false;
    let mut built_sources = Vec::new();
    for target in list_field(p, "targets", &name)? {
        let kinds = list_field(target, "kind", &name)?;
        let kinds: Vec<&str> = kinds.iter().filter_map(Yaml::as_str).collect();
        build_script |= kinds.contains(&"custom-build");
        if kinds
            .iter()
            .any(|k| !matches!(*k, "test" | "bench" | "example"))
        {
            built_sources.push(rel_path(root, str_field(target, "src_path", &name)?)?);
        }
    }
    let mut path_deps = Vec::new();
    for dep in list_field(p, "dependencies", &name)? {
        let dep_name = str_field(dep, "name", &name)?;
        let kind = match &dep["kind"] {
            Yaml::Null => DepKind::Normal,
            Yaml::String(k) if k == "build" => DepKind::Build,
            Yaml::String(k) if k == "dev" => DepKind::Dev,
            _ => return Err(format!("{name}: {dep_name}: unknown dependency kind")),
        };
        match &dep["path"] {
            Yaml::BadValue => {}
            Yaml::String(path) => path_deps.push(PathDep {
                kind,
                dir: rel_path(root, path)?,
            }),
            _ => return Err(format!("{name}: {dep_name}: path is not a string")),
        }
    }
    Ok(Package {
        own_workspace: dir == workspace,
        name,
        dir,
        build_script,
        built_sources,
        path_deps,
    })
}

fn str_field<'a>(node: &'a Yaml, field: &str, what: &str) -> Result<&'a str, String> {
    node[field]
        .as_str()
        .ok_or_else(|| format!("{what}: no {field}"))
}

fn list_field<'a>(node: &'a Yaml, field: &str, what: &str) -> Result<&'a [Yaml], String> {
    node[field]
        .as_vec()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{what}: no {field} list"))
}

/// `path` (absolute) relative to `root`, with every `.` and `..` resolved first.
fn rel_path(root: &Path, path: &str) -> Result<PathBuf, String> {
    let mut normal = PathBuf::new();
    for c in Path::new(path).components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    normal
        .strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|_| format!("{path} is not under {}", root.display()))
}

/// The workspace packages in the closure of the packages that `keyed` holds a path of. Each
/// package directory goes to the directory of the package that it was first reached from, as
/// a dependency of it (a keyed package goes to itself). Normal and build path dependencies are
/// followed, dev path dependencies are not.
///
/// # Errors
///
/// A path dependency whose directory is the directory of no package in `packages`.
pub fn closure(
    keyed: &[String],
    packages: &[Package],
) -> Result<BTreeMap<PathBuf, PathBuf>, String> {
    let by_dir: BTreeMap<&Path, &Package> = packages.iter().map(|p| (p.dir.as_path(), p)).collect();
    let mut reached = BTreeMap::new();
    let mut todo: Vec<&Package> = packages
        .iter()
        .filter(|p| is_keyed(keyed, &p.dir))
        .collect();
    for p in &todo {
        reached.insert(p.dir.clone(), p.dir.clone());
    }
    while let Some(p) = todo.pop() {
        for dep in p.path_deps.iter().filter(|d| d.kind != DepKind::Dev) {
            let Some(next) = by_dir.get(dep.dir.as_path()) else {
                return Err(format!(
                    "{}: a path dependency on {}, the directory of no package",
                    p.dir.display(),
                    dep.dir.display()
                ));
            };
            if !reached.contains_key(&dep.dir) {
                reached.insert(dep.dir.clone(), p.dir.clone());
                todo.push(next);
            }
        }
    }
    Ok(reached)
}

/// `keyed` holds a path inside `dir`, or a path that holds `dir`.
fn is_keyed(keyed: &[String], dir: &Path) -> bool {
    keyed
        .iter()
        .any(|k| Path::new(k).starts_with(dir) || dir.starts_with(k))
}

/// `keyed` holds `path` whole: `path` is a keyed path or under one.
fn holds(keyed: &[String], path: &Path) -> bool {
    keyed.iter().any(|k| path.starts_with(k))
}

/// The files that the build script of a package reads outside the package directory, and why
/// the list is complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildInputs<'a> {
    /// The package directory, relative to the repository root.
    pub dir: &'a str,
    /// The paths that the build script reads outside the package directory, relative to the
    /// repository root.
    pub paths: &'a [&'a str],
    /// Why.
    pub reason: &'a str,
}

/// Each way that `keyed` (the key of one gate) does not hold its closure ([`closure`]):
///
/// - a package of the closure, other than a harness, whose directory the key does not hold
///   whole;
/// - the directory of the root file of a built target (the file, if it is directly in the
///   package directory), if the key does not hold it. For a package other than a harness, only
///   such a part outside the package directory is reported;
/// - the manifest of a harness (a package that is the root of its own workspace), if the key
///   does not hold it;
/// - a package of the closure with a build script but no entry in `inputs`;
/// - a path of such an entry that the key does not hold.
///
/// # Errors
///
/// An error of [`closure`].
pub fn key_gaps(
    keyed: &[String],
    packages: &[Package],
    inputs: &[BuildInputs<'_>],
) -> Result<Vec<String>, String> {
    let by_dir: BTreeMap<&Path, &Package> = packages.iter().map(|p| (p.dir.as_path(), p)).collect();
    let mut gaps = Vec::new();
    for (dir, from) in closure(keyed, packages)? {
        let package = by_dir[dir.as_path()];
        let shown = dir.display();
        let mut parts = built_parts(package);
        if package.own_workspace {
            parts.insert(0, dir.join("Cargo.toml"));
        } else {
            // A part inside the directory is reported with the directory, below.
            parts.retain(|part| !part.starts_with(&dir));
        }
        for part in parts.iter().filter(|part| !holds(keyed, part)) {
            gaps.push(format!(
                "{shown}: the key does not hold {}, which the package builds from",
                part.display()
            ));
        }
        if !package.own_workspace && !holds(keyed, &dir) {
            let how = if from == dir {
                "keyed".to_owned()
            } else {
                format!("a dependency of {}", from.display())
            };
            gaps.push(format!(
                "{shown}: {how}, but the key does not hold its directory whole"
            ));
        }
        if !package.build_script {
            continue;
        }
        let Some(entry) = inputs.iter().find(|i| Path::new(i.dir) == dir) else {
            gaps.push(format!(
                "{shown}: has a build script, but no build-inputs entry lists what it reads \
                 outside its directory"
            ));
            continue;
        };
        for path in entry.paths.iter().filter(|p| !holds(keyed, Path::new(p))) {
            gaps.push(format!(
                "{shown}: its build script reads {path}, which the key does not hold"
            ));
        }
    }
    Ok(gaps)
}

/// What a key must hold of the built targets of `package`: the directory of the root file of
/// each built target (its modules are found from there), or the file itself if it is in the
/// package directory (the directory of a harness holds its build output).
fn built_parts(package: &Package) -> Vec<PathBuf> {
    let mut parts = Vec::new();
    for src in &package.built_sources {
        let part = match src.parent() {
            Some(parent) if parent != package.dir => parent.to_path_buf(),
            _ => src.clone(),
        };
        if !parts.contains(&part) {
            parts.push(part);
        }
    }
    parts
}

/// Each entry of `inputs` that has no reason, that names no package with a build script, or
/// whose package is in none of the closures (`closures`: the union of the package directories
/// of every [`closure`]).
pub fn stale_build_inputs(
    packages: &[Package],
    closures: &BTreeSet<PathBuf>,
    inputs: &[BuildInputs<'_>],
) -> Vec<String> {
    let mut out = Vec::new();
    for entry in inputs {
        if entry.reason.trim().is_empty() {
            out.push(format!("{}: no reason", entry.dir));
        }
        let built = packages
            .iter()
            .any(|p| p.build_script && p.dir == Path::new(entry.dir) && closures.contains(&p.dir));
        if !built {
            out.push(format!(
                "{}: no package of a closure has a build script there",
                entry.dir
            ));
        }
    }
    out
}

/// Each `#[path]` attribute and each `include!`, `include_str!` and `include_bytes!` in `text`
/// (Rust source). Whitespace is removed first, and comments are not removed.
pub fn source_reads(text: &str) -> Vec<&'static str> {
    let flat: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let mut found = Vec::new();
    for (needle, form) in [("#[path", "#[path"), ("#![path", "#![path")] {
        if flat.contains(needle) {
            found.push(form);
        }
    }
    let cfg_path = ["#[cfg_attr(", "#![cfg_attr("].iter().any(|start| {
        flat.match_indices(start).any(|(at, _)| {
            let attr = &flat[at..];
            attr[..attr.find(']').unwrap_or(attr.len())].contains("path=")
        })
    });
    if cfg_path {
        found.push("#[cfg_attr(path)");
    }
    for form in ["include!", "include_str!", "include_bytes!"] {
        if flat.contains(form) {
            found.push(form);
        }
    }
    found
}

/// Each Rust source of a harness package (one that is the root of its own workspace) that
/// uses a `#[path]` attribute or an `include!` macro ([`source_reads`]).
///
/// # Errors
///
/// A source that cannot be read.
pub fn harness_reads(root: &Path, packages: &[Package]) -> Result<Vec<String>, String> {
    let mut files = BTreeSet::new();
    for package in packages.iter().filter(|p| p.own_workspace) {
        for part in built_parts(package) {
            rust_files(&root.join(&part), &part, &mut files)?;
        }
    }
    let mut out = Vec::new();
    for rel in files {
        let full = root.join(&rel);
        let text =
            std::fs::read_to_string(&full).map_err(|e| format!("{}: {e}", full.display()))?;
        for form in source_reads(&text) {
            let shown = match form {
                "#[path" | "#![path" => format!("{form}]"),
                "#[cfg_attr(path)" => "#[cfg_attr(.., path)]".to_owned(),
                macro_name => macro_name.to_owned(),
            };
            out.push(format!(
                "{}: {shown} can read a file that no key holds",
                rel.display()
            ));
        }
    }
    Ok(out)
}

/// Every `.rs` file at or under `full` (`rel` relative to the repository root) into `out`.
fn rust_files(full: &Path, rel: &Path, out: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    if full.is_dir() {
        let entries = std::fs::read_dir(full).map_err(|e| format!("{}: {e}", full.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", full.display()))?;
            rust_files(&entry.path(), &rel.join(entry.file_name()), out)?;
        }
    } else if rel.extension().is_some_and(|e| e == "rs") {
        out.insert(rel.to_path_buf());
    }
    Ok(())
}

/// The file of each `import` statement in `text` (a `.proto` file).
pub fn proto_imports(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("import") else {
            continue;
        };
        let mut rest = rest.trim_start();
        for modifier in ["public", "weak"] {
            if let Some(after) = rest.strip_prefix(modifier) {
                rest = after.trim_start();
            }
        }
        let Some(quote) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            continue;
        };
        if let Some(end) = rest[1..].find(quote) {
            out.push(rest[1..=end].to_owned());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One dependency of a metadata fixture: (name, kind, path dir under `/repo` or none).
    type Dep<'a> = (&'a str, Option<&'a str>, Option<&'a str>);

    /// One package of a metadata fixture, as `cargo metadata` prints it: its directory under
    /// `/repo`, its targets (kind, root file under the directory) and its dependencies.
    fn package_json(dir: &str, targets: &[(&str, &str)], deps: &[Dep<'_>]) -> String {
        let name = dir.rsplit('/').next().unwrap();
        let targets: Vec<String> = targets
            .iter()
            .map(|(kind, src)| {
                format!(
                    r#"{{"kind":["{kind}"],"crate_types":["{kind}"],"name":"{name}","src_path":"/repo/{dir}/{src}","edition":"2021","doctest":false,"test":true,"doc":true}}"#
                )
            })
            .collect();
        let deps: Vec<String> = deps
            .iter()
            .map(|(dep, kind, path)| {
                let kind = kind.map_or("null".to_owned(), |k| format!("\"{k}\""));
                let (source, path) = match path {
                    Some(p) => ("null".to_owned(), format!(r#","path":"/repo/{p}""#)),
                    None => (
                        "\"registry+https://github.com/rust-lang/crates.io-index\"".to_owned(),
                        String::new(),
                    ),
                };
                format!(
                    r#"{{"name":"{dep}","source":{source},"req":"*","kind":{kind},"rename":null,"optional":false,"uses_default_features":true,"features":[],"target":null,"registry":null{path}}}"#
                )
            })
            .collect();
        format!(
            r#"{{"name":"{name}","version":"0.1.0","id":"path+file:///repo/{dir}#0.1.0","license":null,"description":"a \"quoted\" — text","source":null,"dependencies":[{}],"targets":[{}],"features":{{}},"manifest_path":"/repo/{dir}/Cargo.toml","metadata":null,"publish":[]}}"#,
            deps.join(","),
            targets.join(",")
        )
    }

    /// A `cargo metadata` output of the workspace `/repo/<workspace>` with `packages`.
    fn metadata_json(workspace: &str, packages: &[String]) -> String {
        let root = if workspace.is_empty() {
            "/repo".to_owned()
        } else {
            format!("/repo/{workspace}")
        };
        format!(
            r#"{{"packages":[{}],"workspace_members":[],"resolve":null,"target_directory":"{root}/target","version":1,"workspace_root":"{root}","metadata":null}}"#,
            packages.join(",")
        )
    }

    /// A repository at `/repo`: the workspace crates `a` (a lib with a build script; normal
    /// deps `b` and `serde`, a build dep `c`, a dev dep `d`), `b` (a lib and a bin; normal dep
    /// `e`), `c`, `d` and `e` (libs), `z` (a lib, depended on by nothing), and the harness
    /// `fuzz` (its own workspace: a lib, a bin target, a test; normal dep `a`).
    fn repo() -> Vec<Package> {
        let lib = [("lib", "src/lib.rs")];
        let mut root = vec![
            package_json(
                "crates/a",
                &[("lib", "src/lib.rs"), ("custom-build", "build.rs")],
                &[
                    ("b", None, Some("crates/b")),
                    ("serde", None, None),
                    ("c", Some("build"), Some("crates/c")),
                    ("d", Some("dev"), Some("crates/d")),
                ],
            ),
            package_json(
                "crates/b",
                &[("lib", "src/lib.rs"), ("bin", "src/main.rs")],
                &[("e", None, Some("crates/e"))],
            ),
        ];
        for dir in ["crates/c", "crates/d", "crates/e", "crates/z"] {
            root.push(package_json(dir, &lib, &[]));
        }
        let fuzz = package_json(
            "fuzz",
            &[
                ("lib", "src/lib.rs"),
                ("bin", "fuzz_targets/one.rs"),
                ("test", "tests/harness.rs"),
            ],
            &[("a", None, Some("crates/a"))],
        );
        let mut all = packages(&metadata_json("", &root), Path::new("/repo")).unwrap();
        all.extend(packages(&metadata_json("fuzz", &[fuzz]), Path::new("/repo")).unwrap());
        all
    }

    fn keyed(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|p| (*p).to_owned()).collect()
    }

    fn dirs(map: &BTreeMap<PathBuf, PathBuf>) -> Vec<String> {
        map.keys().map(|d| d.display().to_string()).collect()
    }

    const A_INPUTS: &[BuildInputs<'static>] = &[BuildInputs {
        dir: "crates/a",
        paths: &["proto/a"],
        reason: "build.rs compiles proto/a",
    }];

    /// The fixture's complete key: the harness parts, every crate of the closure whole, and the
    /// input of `a`'s build script.
    const FULL: &[&str] = &[
        "Cargo.toml",
        "fuzz/Cargo.toml",
        "fuzz/src",
        "fuzz/fuzz_targets",
        "crates/a",
        "crates/b",
        "crates/c",
        "crates/e",
        "proto/a",
    ];

    #[test]
    fn packages_read_the_path_dependencies_and_built_targets_of_cargo_metadata() {
        let all = repo();
        let a = &all[0];
        assert_eq!(a.name, "a");
        assert_eq!(a.dir, Path::new("crates/a"));
        assert!(!a.own_workspace);
        assert!(a.build_script);
        assert_eq!(
            a.built_sources,
            [
                PathBuf::from("crates/a/src/lib.rs"),
                "crates/a/build.rs".into()
            ]
        );
        assert_eq!(
            a.path_deps,
            [
                PathDep {
                    kind: DepKind::Normal,
                    dir: "crates/b".into()
                },
                PathDep {
                    kind: DepKind::Build,
                    dir: "crates/c".into()
                },
                PathDep {
                    kind: DepKind::Dev,
                    dir: "crates/d".into()
                },
            ]
        );
        let fuzz = all.last().unwrap();
        assert_eq!(fuzz.dir, Path::new("fuzz"));
        assert!(fuzz.own_workspace);
        assert!(!fuzz.build_script);
        assert_eq!(
            fuzz.built_sources,
            [
                PathBuf::from("fuzz/src/lib.rs"),
                "fuzz/fuzz_targets/one.rs".into()
            ]
        );
    }

    #[test]
    fn packages_refuse_what_they_cannot_read() {
        let root = Path::new("/repo");
        let outside = package_json("crates/a", &[], &[("b", None, Some("../elsewhere"))]);
        for (text, want) in [
            ("{".to_owned(), "does not parse"),
            ("[]".to_owned(), "no packages"),
            (
                metadata_json("", &[outside]),
                "/repo/../elsewhere is not under /repo",
            ),
            (
                metadata_json(
                    "",
                    &[package_json("crates/a", &[], &[("b", Some("weird"), None)])],
                ),
                "b: unknown dependency kind",
            ),
            (
                metadata_json("", &["{\"name\":\"a\"}".to_owned()]),
                "a: no manifest_path",
            ),
        ] {
            let err = packages(&text, root).unwrap_err();
            assert!(err.contains(want), "{text}: {err}");
        }
    }

    #[test]
    fn the_closure_follows_normal_and_build_dependencies_but_not_dev_ones() {
        let all = repo();
        let from_fuzz = closure(&keyed(&["fuzz/src"]), &all).unwrap();
        assert_eq!(
            dirs(&from_fuzz),
            ["crates/a", "crates/b", "crates/c", "crates/e", "fuzz"]
        );
        assert_eq!(from_fuzz[Path::new("fuzz")], Path::new("fuzz"));
        assert_eq!(from_fuzz[Path::new("crates/e")], Path::new("crates/b"));
        // A path inside a crate keys the crate; a path that holds a crate keys it too.
        let from_b = closure(&keyed(&["crates/b/src/lib.rs", "crates/z"]), &all).unwrap();
        assert_eq!(dirs(&from_b), ["crates/b", "crates/e", "crates/z"]);
        let everything = closure(&keyed(&["crates"]), &all).unwrap();
        assert_eq!(
            dirs(&everything),
            ["crates/a", "crates/b", "crates/c", "crates/d", "crates/e", "crates/z"]
        );
        assert!(closure(&keyed(&["Cargo.toml", "proto/a"]), &all)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_path_dependency_of_no_known_package_is_an_error() {
        let all: Vec<Package> = repo()
            .into_iter()
            .filter(|p| p.dir != Path::new("crates/e"))
            .collect();
        let err = closure(&keyed(&["crates/b"]), &all).unwrap_err();
        assert!(err.contains("crates/e"), "{err}");
    }

    #[test]
    fn the_full_closure_has_no_gap() {
        assert_eq!(
            key_gaps(&keyed(FULL), &repo(), A_INPUTS).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn each_crate_of_the_closure_must_be_keyed_whole() {
        let all = repo();
        // Each crate, left out or keyed only in part.
        for (drop, add, want) in [
            ("crates/a", None, "crates/a: a dependency of fuzz, but"),
            ("crates/e", None, "crates/e: a dependency of crates/b, but"),
            ("crates/c", None, "crates/c: a dependency of crates/a, but"),
            (
                "crates/e",
                Some("crates/e/src"),
                "crates/e: keyed, but the key does not hold its directory whole",
            ),
            (
                "crates/b",
                Some("crates/b/src/lib.rs"),
                "crates/b: keyed, but",
            ),
        ] {
            let mut paths: Vec<&str> = FULL.iter().copied().filter(|p| *p != drop).collect();
            paths.extend(add);
            let gaps = key_gaps(&keyed(&paths), &all, A_INPUTS).unwrap();
            assert_eq!(gaps.len(), 1, "{drop}: {gaps:?}");
            assert!(gaps[0].starts_with(want), "{drop}: {gaps:?}");
        }
    }

    #[test]
    fn a_harness_is_keyed_by_its_manifest_and_its_built_target_directories() {
        let all = repo();
        for drop in ["fuzz/Cargo.toml", "fuzz/src", "fuzz/fuzz_targets"] {
            let paths: Vec<&str> = FULL.iter().copied().filter(|p| *p != drop).collect();
            let gaps = key_gaps(&keyed(&paths), &all, A_INPUTS).unwrap();
            assert_eq!(
                gaps,
                [format!(
                    "fuzz: the key does not hold {drop}, which the package builds from"
                )],
                "{drop}"
            );
        }
        // Its tests are not built for a fuzz run; the whole directory is keyed too.
        let mut whole: Vec<&str> = FULL.to_vec();
        whole.retain(|p| !p.starts_with("fuzz/"));
        whole.push("fuzz");
        assert!(key_gaps(&keyed(&whole), &all, A_INPUTS).unwrap().is_empty());
    }

    #[test]
    fn a_build_script_needs_its_inputs_keyed() {
        let all = repo();
        let gaps = key_gaps(&keyed(FULL), &all, &[]).unwrap();
        assert_eq!(
            gaps,
            [
                "crates/a: has a build script, but no build-inputs entry lists what it reads \
              outside its directory"
            ]
        );
        let paths: Vec<&str> = FULL.iter().copied().filter(|p| *p != "proto/a").collect();
        let gaps = key_gaps(&keyed(&paths), &all, A_INPUTS).unwrap();
        assert_eq!(
            gaps,
            ["crates/a: its build script reads proto/a, which the key does not hold"]
        );
        // An input of a crate outside the closure is not asked for.
        let b_only = keyed(&["crates/b", "crates/e"]);
        assert!(key_gaps(&b_only, &all, &[]).unwrap().is_empty());
    }

    #[test]
    fn a_build_inputs_entry_must_not_outlive_its_build_script() {
        let all = repo();
        let closures: BTreeSet<PathBuf> =
            closure(&keyed(FULL), &all).unwrap().into_keys().collect();
        assert!(stale_build_inputs(&all, &closures, A_INPUTS).is_empty());
        let inputs = [
            BuildInputs {
                dir: "crates/a",
                paths: &[],
                reason: " ",
            },
            BuildInputs {
                dir: "crates/b",
                paths: &[],
                reason: "b",
            },
            BuildInputs {
                dir: "crates/q",
                paths: &[],
                reason: "q",
            },
        ];
        assert_eq!(
            stale_build_inputs(&all, &closures, &inputs),
            [
                "crates/a: no reason",
                "crates/b: no package of a closure has a build script there",
                "crates/q: no package of a closure has a build script there",
            ]
        );
        let none = BTreeSet::new();
        assert_eq!(
            stale_build_inputs(&all, &none, A_INPUTS),
            ["crates/a: no package of a closure has a build script there"]
        );
    }

    #[test]
    fn a_built_target_outside_its_crate_directory_must_be_keyed() {
        let root = Path::new("/repo");
        let text = metadata_json(
            "",
            &[package_json(
                "crates/x",
                &[
                    ("lib", "../shared/x/lib.rs"),
                    ("custom-build", "../builds/x.rs"),
                    ("test", "../shared/tests/t.rs"),
                ],
                &[],
            )],
        );
        let all = packages(&text, root).unwrap();
        let inputs = [BuildInputs {
            dir: "crates/x",
            paths: &[],
            reason: "reads nothing",
        }];
        assert_eq!(
            key_gaps(&keyed(&["crates/x"]), &all, &inputs).unwrap(),
            [
                "crates/x: the key does not hold crates/shared/x, which the package builds from",
                "crates/x: the key does not hold crates/builds, which the package builds from",
            ]
        );
        let full = keyed(&["crates/x", "crates/shared/x", "crates/builds"]);
        assert!(key_gaps(&full, &all, &inputs).unwrap().is_empty());
    }

    #[test]
    fn a_harness_source_at_its_root_is_keyed_as_its_file() {
        let root = Path::new("/repo");
        let fuzz = package_json(
            "fuzz",
            &[("lib", "src/lib.rs"), ("custom-build", "build.rs")],
            &[],
        );
        let all = packages(&metadata_json("fuzz", &[fuzz]), root).unwrap();
        let inputs = [BuildInputs {
            dir: "fuzz",
            paths: &[],
            reason: "reads nothing",
        }];
        let key = ["fuzz/Cargo.toml", "fuzz/src"];
        assert_eq!(
            key_gaps(&keyed(&key), &all, &inputs).unwrap(),
            ["fuzz: the key does not hold fuzz/build.rs, which the package builds from"]
        );
        let key = ["fuzz/Cargo.toml", "fuzz/src", "fuzz/build.rs"];
        assert!(key_gaps(&keyed(&key), &all, &inputs).unwrap().is_empty());
    }

    #[test]
    fn source_reads_find_path_attributes_and_include_macros() {
        assert!(source_reads("use std::path::Path;\nfn f(path: &str) {}\n").is_empty());
        for (text, want) in [
            ("#[path = \"../tests/x.rs\"]\nmod x;", "#[path"),
            ("#![path=\"x\"]", "#![path"),
            (
                "#[cfg_attr(test, path = \"x.rs\")]\nmod x;",
                "#[cfg_attr(path)",
            ),
            (
                "const X: &str = include_str!(\"../tests/x\");",
                "include_str!",
            ),
            (
                "const X: &[u8] = include_bytes ! (\"x\");",
                "include_bytes!",
            ),
            ("include! {\"x.rs\"}", "include!"),
            ("// include_str!(\"x\") in a comment", "include_str!"),
        ] {
            assert_eq!(source_reads(text), [want], "{text}");
        }
    }

    #[test]
    fn harness_reads_report_each_harness_source_that_reads_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let write = |path: &str, text: &str| {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("fuzz/src/lib.rs", "pub mod seeds;\n");
        write(
            "fuzz/src/seeds/mod.rs",
            "const S: &[u8] = include_bytes!(\"../../tests/s\");\n",
        );
        write(
            "fuzz/fuzz_targets/one.rs",
            "#[path = \"../examples/x.rs\"]\nmod x;\n",
        );
        write("fuzz/tests/t.rs", "const T: &str = include_str!(\"t\");\n");
        write(
            "crates/a/src/lib.rs",
            "const A: &str = include_str!(\"a\");\n",
        );
        let fuzz = Package {
            name: "fuzz".into(),
            dir: "fuzz".into(),
            own_workspace: true,
            build_script: false,
            built_sources: vec!["fuzz/src/lib.rs".into(), "fuzz/fuzz_targets/one.rs".into()],
            path_deps: Vec::new(),
        };
        let a = Package {
            name: "a".into(),
            dir: "crates/a".into(),
            own_workspace: false,
            built_sources: vec!["crates/a/src/lib.rs".into()],
            ..fuzz.clone()
        };
        assert_eq!(
            harness_reads(root, &[fuzz, a]).unwrap(),
            [
                "fuzz/fuzz_targets/one.rs: #[path] can read a file that no key holds",
                "fuzz/src/seeds/mod.rs: include_bytes! can read a file that no key holds",
            ]
        );
    }

    #[test]
    fn proto_imports_read_each_import_statement() {
        let text = "syntax = \"proto3\";\nimport \"ethswarm/common/v1/a.proto\";\n\
                    import public \"b.proto\";\n  import weak 'c.proto' ;\n\
                    // import \"commented.proto\";\nmessage M { string import = 1; }\n";
        assert_eq!(
            proto_imports(text),
            ["ethswarm/common/v1/a.proto", "b.proto", "c.proto"]
        );
    }
}
