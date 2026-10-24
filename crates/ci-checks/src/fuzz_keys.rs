//! The fuzz gates' decoder keys (`fuzz/m2a-common.sh`) must hold every module that a keyed
//! file imports.
//!
//! A gate file is stale when a keyed path changes. A module that a keyed file imports but that
//! is not keyed can change and leave an old gate valid, so this check fails on it. It reads
//! each `*_KEY_PATHS` array of the script ([`key_arrays`]; `"${OTHER[@]}"` expands to the other
//! array), and for each array it reads every keyed Rust source of a crate `src/` tree
//! ([`unkeyed_imports`]). An import is:
//!
//! - a `crate::`, `super::` or `self::` path, in a `use` tree or in code;
//! - a `use` path that starts with a child module the file declares;
//! - a `mod <name>;` declaration: the child file is compiled into the module.
//!
//! The path goes to the module file it names (`<name>.rs` or `<name>/mod.rs`, from the crate
//! root `src/lib.rs`, `src/main.rs` or `src/bin/<name>/main.rs`). An item that is not a module
//! stops the walk at the file that holds it. Comments, string and char literals, and each item
//! under `#[cfg(test)]` are not read. A test-only file (one that its parent declares only under
//! `#[cfg(test)]`) is not read either, because the fuzz targets do not build it. Paths of other
//! crates are out of scope: a keyed crate is keyed as a whole directory.
//!
//! [`unkeyed_crates`] reports each import of a workspace path crate whose crate root the key does
//! not hold, from a `use` tree, a path in code (a leading `::` too) or `extern crate`. A gate may
//! leave such a crate out only through an [`Allowance`] that lists the importing file
//! ([`not_allowed`]); a listed file that no longer imports it is stale ([`stale_allowances`]).
//!
//! The reader is textual and does not expand macros. It does not know `#[path]` attributes or
//! inline `mod <name> { … }` blocks outside `#[cfg(test)]`; no keyed file has one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// One import of a module that the key does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unkeyed {
    /// The keyed file, relative to the repository root.
    pub file: String,
    /// The 1-based line of the import in it.
    pub line: usize,
    /// The import as written (`super::columns`, `mod quota`).
    pub import: String,
    /// The module file it names, relative to the repository root.
    pub module: String,
}

impl std::fmt::Display for Unkeyed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: `{}` imports {}, which the key does not hold",
            self.file, self.line, self.import, self.module
        )
    }
}

/// Every `<NAME>_KEY_PATHS=( … )` array of `script`, by name, with `"${OTHER[@]}"` expanded.
///
/// # Errors
///
/// An array that is not closed, an expansion of an array that is not defined before it, or no
/// array at all.
pub fn key_arrays(script: &str) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut arrays: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut lines = script.lines();
    while let Some(line) = lines.next() {
        let Some(name) = line
            .trim_end()
            .strip_suffix("=(")
            .filter(|n| n.ends_with("_KEY_PATHS") && is_shell_name(n))
        else {
            continue;
        };
        let mut items = Vec::new();
        let mut closed = false;
        for line in lines.by_ref() {
            let entry = line.split('#').next().unwrap_or("").trim();
            if entry == ")" {
                closed = true;
                break;
            }
            for word in entry.split_whitespace() {
                match word
                    .strip_prefix("\"${")
                    .and_then(|w| w.strip_suffix("[@]}\""))
                {
                    Some(other) => {
                        let expanded = arrays.get(other).ok_or_else(|| {
                            format!("{name} expands {other}, not defined before it")
                        })?;
                        items.extend(expanded.iter().cloned());
                    }
                    None => items.push(word.to_owned()),
                }
            }
        }
        if !closed {
            return Err(format!("{name} is not closed"));
        }
        arrays.insert(name.to_owned(), items);
    }
    if arrays.is_empty() {
        return Err("no *_KEY_PATHS array".into());
    }
    Ok(arrays)
}

fn is_shell_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The keyed paths, and whether a file is under one of them.
struct Keys<'a> {
    root: &'a Path,
    keyed: Vec<PathBuf>,
}

impl<'a> Keys<'a> {
    fn new(root: &'a Path, keyed: &[String]) -> Self {
        Self {
            root,
            keyed: keyed.iter().map(PathBuf::from).collect(),
        }
    }

    /// Every keyed `.rs` file.
    fn sources(&self) -> Result<BTreeSet<PathBuf>, String> {
        let mut sources = BTreeSet::new();
        for path in &self.keyed {
            let full = self.root.join(path);
            if full.is_dir() {
                rust_files(&full, &mut sources)?;
            } else if full.is_file() {
                if full.extension().is_some_and(|e| e == "rs") {
                    sources.insert(full);
                }
            } else {
                return Err(format!("keyed path {} does not exist", path.display()));
            }
        }
        Ok(sources)
    }

    fn holds(&self, file: &Path) -> bool {
        file.strip_prefix(self.root)
            .is_ok_and(|rel| self.keyed.iter().any(|k| rel.starts_with(k)))
    }

    fn rel(&self, file: &Path) -> String {
        file.strip_prefix(self.root)
            .unwrap_or(file)
            .display()
            .to_string()
    }
}

/// Every import in the keyed Rust sources under `root` of a module file that `keyed` does not
/// hold, and every keyed module whose crate root the key does not hold (`crate root`). `keyed`
/// holds paths relative to `root`; a directory keys every file under it.
///
/// # Errors
///
/// A keyed path that does not exist, or a file that cannot be read.
pub fn unkeyed_imports(root: &Path, keyed: &[String]) -> Result<Vec<Unkeyed>, String> {
    let keys = Keys::new(root, keyed);
    let mut found = BTreeSet::new();
    for file in &keys.sources()? {
        let Some(module) = Module::of(file) else {
            continue;
        };
        if module.is_test_only()? {
            continue;
        }
        if !keys.holds(&module.root) {
            found.insert((
                keys.rel(file),
                1,
                "crate root".to_owned(),
                keys.rel(&module.root),
            ));
        }
        for (line, import, target) in module.imports()? {
            if target != *file && !keys.holds(&target) {
                found.insert((keys.rel(file), line, import, keys.rel(&target)));
            }
        }
    }
    Ok(found
        .into_iter()
        .map(|(file, line, import, module)| Unkeyed {
            file,
            line,
            import,
            module,
        })
        .collect())
}

/// One import of a workspace path crate whose crate root (`src/lib.rs`) the key does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnkeyedCrate {
    /// The keyed file, relative to the repository root.
    pub file: String,
    /// The 1-based line of the import in it.
    pub line: usize,
    /// The crate as the file names it (`ethswarm_proto`).
    pub krate: String,
    /// The crate's directory, relative to the repository root.
    pub dir: String,
}

impl std::fmt::Display for UnkeyedCrate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: `{}` imports {}, whose crate root the key does not hold",
            self.file, self.line, self.krate, self.dir
        )
    }
}

/// The path dependencies of a crate: `deps(<crate dir>)`, both relative to the repository
/// root, gives each dependency's name in code (`ethswarm_proto`) and its directory.
pub type PathDeps<'a> = dyn Fn(&Path) -> Result<BTreeMap<String, PathBuf>, String> + 'a;

/// Every import, in the keyed Rust sources under `root`, of a path dependency (`deps`) whose
/// crate root `src/lib.rs` the key does not hold. Each keyed `.rs` file of a crate is read,
/// except its `tests/`, `benches/` and `examples/`, its `build.rs` and its test-only modules.
///
/// # Errors
///
/// A keyed path that does not exist, a file that cannot be read, or an error of `deps`.
pub fn unkeyed_crates(
    root: &Path,
    keyed: &[String],
    deps: &PathDeps<'_>,
) -> Result<Vec<UnkeyedCrate>, String> {
    let keys = Keys::new(root, keyed);
    let mut found = BTreeSet::new();
    let mut bindings = BTreeMap::new();
    for file in &keys.sources()? {
        let Some(krate) = crate_dir(file) else {
            continue;
        };
        let inside = file.strip_prefix(krate).unwrap_or(file);
        let first = inside.components().next().map(|c| c.as_os_str());
        if inside == Path::new("build.rs")
            || first.is_some_and(|c| c == "tests" || c == "benches" || c == "examples")
        {
            continue;
        }
        if let Some(module) = Module::of(file) {
            if module.is_test_only()? {
                continue;
            }
        }
        let rel_krate = krate.strip_prefix(root).unwrap_or(krate);
        let deps = deps(rel_krate)?;
        let mut code = read_code(file)?;
        let uses = use_paths(&mut code);
        let mut names: Vec<(usize, String)> = uses
            .iter()
            .filter_map(|(line, path)| path.first().map(|first| (*line, first.clone())))
            .collect();
        names.extend(path_starts(&code));
        // `extern crate y as w;` here: `w::` names `y`.
        let aliases: BTreeMap<String, String> = extern_crates(&code)
            .into_iter()
            .map(|(_, name, alias)| (alias, name))
            .collect();
        for (_, name) in &mut names {
            if let Some(krate) = aliases.get(name.as_str()) {
                *name = krate.clone();
            }
        }
        // A crate that another module of this crate binds with `use` (`use y as pb;` in the
        // crate root), named through it here (`crate::pb::X`): this file imports that crate.
        if let Some(module) = Module::of(file) {
            let relative = uses
                .iter()
                .cloned()
                .chain(code_paths(&code))
                .filter(|(_, path)| {
                    path.first()
                        .is_some_and(|f| matches!(f.as_str(), "crate" | "super" | "self"))
                });
            for (line, path) in relative {
                if let Some(name) = module.bound_crate(&path, &mut bindings)? {
                    names.push((line, name));
                }
            }
        }
        for (line, name) in names {
            let Some(dir) = deps.get(&name) else {
                continue;
            };
            if !keys.holds(&root.join(dir).join("src/lib.rs")) {
                found.insert((keys.rel(file), line, name, dir.display().to_string()));
            }
        }
    }
    Ok(found
        .into_iter()
        .map(|(file, line, krate, dir)| UnkeyedCrate {
            file,
            line,
            krate,
            dir,
        })
        .collect())
}

/// A workspace crate that a gate's keyed code may import without keying it, from the listed
/// files only, with the reason no fuzz target of that gate runs its code on fuzz input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowance<'a> {
    /// The key array (`M2A_KEY_PATHS`).
    pub gate: &'a str,
    /// The crate's directory, relative to the repository root.
    pub dir: &'a str,
    /// The keyed files that may import it, relative to the repository root.
    pub files: &'a [&'a str],
    /// Why.
    pub reason: &'a str,
}

/// The imports of `found` (the [`unkeyed_crates`] of `gate`) that no allowance of `gate` lists
/// with the importing file. Each `(allowance index, file)` that covered an import goes into
/// `used`, for [`stale_allowances`].
pub fn not_allowed(
    gate: &str,
    found: Vec<UnkeyedCrate>,
    allowed: &[Allowance<'_>],
    used: &mut BTreeSet<(usize, String)>,
) -> Vec<UnkeyedCrate> {
    found
        .into_iter()
        .filter(|import| {
            let covering = allowed.iter().position(|a| {
                a.gate == gate && a.dir == import.dir && a.files.contains(&import.file.as_str())
            });
            match covering {
                Some(index) => {
                    used.insert((index, import.file.clone()));
                    false
                }
                None => true,
            }
        })
        .collect()
}

/// Each allowance without a reason, and each listed file that covered no import (`used`, from
/// [`not_allowed`] over every gate): an allowance must not outlive the import it is for.
pub fn stale_allowances(
    allowed: &[Allowance<'_>],
    used: &BTreeSet<(usize, String)>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (index, a) in allowed.iter().enumerate() {
        if a.reason.trim().is_empty() {
            out.push(format!("{} {}: no reason", a.gate, a.dir));
        }
        for file in a.files {
            if !used.contains(&(index, (*file).to_owned())) {
                out.push(format!(
                    "{} {}: {file} imports nothing of it",
                    a.gate, a.dir
                ));
            }
        }
    }
    out
}

/// A glob `use` in keyed code that could bring a workspace crate in unseen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsafeGlob {
    /// The keyed file, relative to the repository root.
    pub file: String,
    /// The 1-based line of the `use`.
    pub line: usize,
    /// The glob as written, without `use` (`crate::*`).
    pub glob: String,
    /// Why it is refused.
    pub why: String,
}

impl std::fmt::Display for UnsafeGlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: `use {}` is {}: name each item instead, so the per-file allowance sees it",
            self.file, self.line, self.glob, self.why
        )
    }
}

/// Every glob `use` in the keyed non-test Rust sources under `root` (the files
/// [`unkeyed_crates`] reads) that could bring in a workspace path crate (`deps`) unseen, so
/// that a name it brings in would bypass the per-file [`Allowance`]: a glob of a workspace
/// crate (`pub use y::*;`), and a glob of a module of this crate (`use crate::*;`,
/// `use super::*;`) that binds a workspace crate (`use y as pb;`, `extern crate y as w;`, or a
/// crate-relative `use` that leads to one). A glob of another crate, or of a module that binds
/// no workspace crate, is not refused; nor is any glob in test code.
///
/// # Errors
///
/// As [`unkeyed_crates`].
pub fn unsafe_globs(
    root: &Path,
    keyed: &[String],
    deps: &PathDeps<'_>,
) -> Result<Vec<UnsafeGlob>, String> {
    let keys = Keys::new(root, keyed);
    let mut found = BTreeSet::new();
    let mut bindings = BTreeMap::new();
    for file in &keys.sources()? {
        let Some(krate) = crate_dir(file) else {
            continue;
        };
        let inside = file.strip_prefix(krate).unwrap_or(file);
        let first = inside.components().next().map(|c| c.as_os_str());
        if inside == Path::new("build.rs")
            || first.is_some_and(|c| c == "tests" || c == "benches" || c == "examples")
        {
            continue;
        }
        let module = Module::of(file);
        if let Some(module) = &module {
            if module.is_test_only()? {
                continue;
            }
        }
        let deps = deps(krate.strip_prefix(root).unwrap_or(krate))?;
        let code = read_code(file)?;
        let aliases: BTreeMap<String, String> = extern_crates(&code)
            .into_iter()
            .map(|(_, name, alias)| (alias, name))
            .collect();
        for (line, path) in use_globs(&code) {
            let glob = path
                .iter()
                .map(String::as_str)
                .chain(["*"])
                .collect::<Vec<_>>()
                .join("::");
            let first = path.first().map(String::as_str).unwrap_or_default();
            let first = aliases.get(first).map_or(first, String::as_str);
            let reached = if deps.contains_key(first) {
                vec![(first.to_owned(), None)]
            } else if let Some(module) = &module {
                module.glob_reaches(&path, &mut bindings)?
            } else {
                Vec::new()
            };
            // A crate the key holds needs no allowance, so a glob that reaches it bypasses none.
            let unkeyed = |name: &str| {
                deps.get(name)
                    .is_some_and(|dir| !keys.holds(&root.join(dir).join("src/lib.rs")))
            };
            if let Some((name, via)) = reached.into_iter().find(|(name, _)| unkeyed(name)) {
                let why = match via {
                    None => format!("a glob of workspace crate `{name}`"),
                    Some(target) => format!(
                        "a glob of {}, which binds workspace crate `{name}`",
                        keys.rel(&target)
                    ),
                };
                found.insert((keys.rel(file), line, glob, why));
            }
        }
    }
    Ok(found
        .into_iter()
        .map(|(file, line, glob, why)| UnsafeGlob {
            file,
            line,
            glob,
            why,
        })
        .collect())
}

/// `file`'s code: comments, literals and `#[cfg(test)]` items blanked.
fn read_code(file: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    Ok(drop_test_items(&blank_comments_and_literals(&text)))
}

/// The first name of each path in `code` (outside `use` items), with its line: a name followed
/// by `::` that is not a later segment of a path. A name after `::` is a later segment only if
/// a name, `>` or `)` comes right before that `::` (`a::b`, `<T>::b`, `f()::b`); after a leading
/// `::` (`::b`, `(::b`, `-> ::b`, `=> ::b`) it is the crate. `extern crate <name>` also names a crate.
fn path_starts(code: &str) -> Vec<(usize, String)> {
    let src = code.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < src.len() {
        if !is_ident(src[i]) || (i > 0 && is_ident(src[i - 1])) {
            i += 1;
            continue;
        }
        let start = i;
        while i < src.len() && is_ident(src[i]) {
            i += 1;
        }
        let before = code[..start].trim_end();
        let later_segment = before.strip_suffix("::").is_some_and(continues_a_path);
        if !later_segment && src[i..].starts_with(b"::") {
            out.push((line_of(src, start), code[start..i].to_owned()));
        }
    }
    for (line, name, _) in extern_crates(code) {
        out.push((line, name));
    }
    out
}

/// Each `extern crate <name> [as <alias>];` of `code`: its line, the crate and the name it binds
/// (the alias, else the crate). `r#` is stripped from both.
fn extern_crates(code: &str) -> Vec<(usize, String, String)> {
    let src = code.as_bytes();
    let word = |text: &str| -> String {
        let text = text.trim_start();
        let text = text.strip_prefix("r#").unwrap_or(text);
        text.chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect()
    };
    let mut out = Vec::new();
    for (at, _) in keyword(code, "extern") {
        let rest = code[at + "extern".len()..].trim_start();
        let Some(rest) = rest.strip_prefix("crate") else {
            continue;
        };
        if rest.bytes().next().is_some_and(is_ident) {
            continue;
        }
        let name = word(rest);
        if name.is_empty() {
            continue;
        }
        let after = rest.trim_start();
        let after = after.strip_prefix("r#").unwrap_or(after);
        let after = after[name.len()..].trim_start();
        let alias = after
            .strip_prefix("as")
            .filter(|a| a.starts_with(char::is_whitespace))
            .map(word)
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| name.clone());
        out.push((line_of(src, at), name, alias));
    }
    out
}

/// Words that can stand right before a path that starts at a crate (`impl ::y::T`,
/// `x as ::y::T`): a `::` after one of them starts the path, it does not continue one. Not
/// `crate`: `crate::y` is a path of this crate, not of a crate `y`.
const KEYWORDS: &[&str] = &[
    "as", "async", "await", "box", "break", "const", "continue", "dyn", "else", "enum", "extern",
    "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
    "return", "static", "struct", "trait", "type", "unsafe", "use", "where", "while", "yield",
];

/// Whether the `::` after `head` continues a path (`a::`, `<T>::`, `f()::`): a name (not a
/// keyword), `>` or `)` right before it, with no space between. After a space, `->`, `=>`, a
/// keyword or anything else, the `::` starts a path at a crate.
fn continues_a_path(head: &str) -> bool {
    let Some(&last) = head.as_bytes().last() else {
        return false;
    };
    if last.is_ascii_whitespace() || head.ends_with("->") || head.ends_with("=>") {
        return false;
    }
    if is_ident(last) {
        let start = head
            .bytes()
            .rposition(|b| !is_ident(b))
            .map_or(0, |i| i + 1);
        return !KEYWORDS.contains(&&head[start..]);
    }
    last == b'>' || last == b')'
}

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path, out: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.insert(path);
        }
    }
    Ok(())
}

/// The nearest ancestor directory of `file` that holds a `Cargo.toml`.
fn crate_dir(file: &Path) -> Option<&Path> {
    file.ancestors()
        .skip(1)
        .find(|dir| dir.join("Cargo.toml").is_file())
}

/// A module file of a crate `src/` tree.
struct Module {
    file: PathBuf,
    /// The crate root: `src/lib.rs`, `src/main.rs` or `src/bin/<name>/main.rs`.
    root: PathBuf,
}

impl Module {
    /// The module `file` is, or `None` unless `file` is under the `src` directory of the
    /// nearest crate (the nearest ancestor with a `Cargo.toml`): the crate's tests, its build
    /// script, other targets and a file of no crate are not modules.
    fn of(file: &Path) -> Option<Self> {
        let krate = crate_dir(file)?;
        let src = krate.join("src");
        let under = file.strip_prefix(&src).ok()?;
        let mut parts = under.components();
        let root = match (parts.next(), parts.next(), parts.next()) {
            (Some(bin), Some(_), None) if bin.as_os_str() == "bin" => file.to_path_buf(),
            (Some(bin), Some(name), Some(_)) if bin.as_os_str() == "bin" => {
                src.join("bin").join(name).join("main.rs")
            }
            _ if under == Path::new("main.rs") => file.to_path_buf(),
            _ if src.join("lib.rs").is_file() => src.join("lib.rs"),
            _ => src.join("main.rs"),
        };
        Some(Self {
            file: file.to_path_buf(),
            root,
        })
    }

    fn at(&self, file: PathBuf) -> Self {
        Self {
            file,
            root: self.root.clone(),
        }
    }

    fn is_root(&self) -> bool {
        self.file == self.root
    }

    /// The directory of its child modules.
    fn child_dir(&self) -> PathBuf {
        let name = self.file.file_name().and_then(|n| n.to_str());
        if self.is_root() || name == Some("mod.rs") {
            self.file
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default()
        } else {
            self.file.with_extension("")
        }
    }

    /// The child module `name`'s file, if it has one.
    fn child(&self, name: &str) -> Option<Self> {
        let dir = self.child_dir();
        [
            dir.join(format!("{name}.rs")),
            dir.join(name).join("mod.rs"),
        ]
        .into_iter()
        .find(|f| f.is_file())
        .map(|f| self.at(f))
    }

    /// Its parent module and its own name in it; `None` for the crate root.
    fn parent(&self) -> Option<(Self, String)> {
        if self.is_root() {
            return None;
        }
        let file_name = self.file.file_name()?.to_str()?;
        let (dir, name) = if file_name == "mod.rs" {
            let dir = self.file.parent()?;
            (dir.parent()?, dir.file_name()?.to_str()?.to_owned())
        } else {
            (
                self.file.parent()?,
                file_name.strip_suffix(".rs")?.to_owned(),
            )
        };
        let parent = if self.root.parent() == Some(dir) {
            self.root.clone()
        } else if dir.with_extension("rs").is_file() {
            dir.with_extension("rs")
        } else {
            dir.join("mod.rs")
        };
        Some((self.at(parent), name))
    }

    /// The module file that the path `segments` names from here (see the module docs).
    fn resolve(&self, segments: &[&str]) -> Option<PathBuf> {
        self.resolve_rest(segments).map(|(file, _)| file)
    }

    /// As [`Module::resolve`], with the names after the last module (`["pb", "X"]` of
    /// `crate::pb::X` when `pb` is no module of the crate root).
    fn resolve_rest<'s>(&self, segments: &'s [&'s str]) -> Option<(PathBuf, &'s [&'s str])> {
        let mut at = self.at(self.file.clone());
        for (i, segment) in segments.iter().enumerate() {
            at = match *segment {
                "crate" => self.at(self.root.clone()),
                "self" => at,
                "super" => at.parent()?.0,
                name => match at.child(name) {
                    Some(child) => child,
                    None => return Some((at.file, &segments[i..])),
                },
            };
        }
        Some((at.file, &[]))
    }

    /// The first name of the path that a `use` item of the module file `path` resolves to binds
    /// the name after that module (`y` for `crate::pb::X` when the crate root has `use y as
    /// pb;`), following a binding of another crate-relative path a few times. `None` if the
    /// path names a module, or the name is not bound. `bindings` caches each file's.
    fn bound_crate(
        &self,
        path: &[String],
        bindings: &mut BTreeMap<PathBuf, BTreeMap<String, Vec<String>>>,
    ) -> Result<Option<String>, String> {
        let mut at = self.at(self.file.clone());
        let mut path = path.to_vec();
        for _ in 0..4 {
            let segments: Vec<&str> = path.iter().map(String::as_str).collect();
            let Some((target, rest)) = at.resolve_rest(&segments) else {
                return Ok(None);
            };
            let Some(name) = rest.first() else {
                return Ok(None);
            };
            if !bindings.contains_key(&target) {
                bindings.insert(target.clone(), use_bindings(&read_code(&target)?));
            }
            let Some(bound) = bindings[&target].get(*name) else {
                return Ok(None);
            };
            match bound.first().map(String::as_str) {
                Some("crate" | "super" | "self") => {
                    path = bound.clone();
                    at = self.at(target);
                }
                Some(first) => return Ok(Some(first.to_owned())),
                None => return Ok(None),
            }
        }
        Err(format!(
            "{}: more than 4 aliases from `{}`: name the item by its own path",
            self.file.display(),
            path.join("::")
        ))
    }

    /// The crates the glob of `path` (`crate::*` as `["crate"]`) from here could reach: each
    /// first name of a path that a `use` or an `extern crate` of the module it names binds
    /// (following a crate-relative `use` to its crate), with that module; or, for a glob of an
    /// item (`use crate::pb::*;`), the crate the item is bound to, with no module. A path that
    /// names no module of this crate (another crate's) reaches nothing here.
    fn glob_reaches(
        &self,
        path: &[String],
        bindings: &mut BTreeMap<PathBuf, BTreeMap<String, Vec<String>>>,
    ) -> Result<Vec<(String, Option<PathBuf>)>, String> {
        let starts_here = path.first().is_some_and(|f| {
            matches!(f.as_str(), "crate" | "super" | "self") || self.child(f).is_some()
        });
        if !starts_here {
            return Ok(Vec::new());
        }
        let segments: Vec<&str> = path.iter().map(String::as_str).collect();
        let Some((target, rest)) = self.resolve_rest(&segments) else {
            return Ok(Vec::new());
        };
        if !rest.is_empty() {
            return Ok(self
                .bound_crate(path, bindings)?
                .map(|name| (name, None))
                .into_iter()
                .collect());
        }
        if !bindings.contains_key(&target) {
            bindings.insert(target.clone(), use_bindings(&read_code(&target)?));
        }
        let bound: Vec<Vec<String>> = bindings[&target].values().cloned().collect();
        let at = self.at(target.clone());
        let mut out = Vec::new();
        for bound_path in bound {
            let first = bound_path.first().map(String::as_str).unwrap_or_default();
            let name = if matches!(first, "crate" | "super" | "self") {
                at.bound_crate(&bound_path, bindings)?
            } else {
                Some(first.to_owned())
            };
            if let Some(name) = name {
                out.push((name, Some(target.clone())));
            }
        }
        Ok(out)
    }

    /// Its code: comments, literals and `#[cfg(test)]` items blanked.
    fn code(&self) -> Result<String, String> {
        read_code(&self.file)
    }

    /// Whether its parent, or an ancestor's parent, declares it only under `#[cfg(test)]`.
    fn is_test_only(&self) -> Result<bool, String> {
        let Some((parent, name)) = self.parent() else {
            return Ok(false);
        };
        if !declared_mods(&parent.code()?)
            .iter()
            .any(|(_, m)| *m == name)
        {
            return Ok(true);
        }
        parent.is_test_only()
    }

    /// Each import: its line, the path as written and the module file it names.
    fn imports(&self) -> Result<Vec<(usize, String, PathBuf)>, String> {
        let mut code = self.code()?;
        let mods = declared_mods(&code);
        let mut out = Vec::new();
        for (line, name) in &mods {
            if let Some(target) = self.resolve(&[name.as_str()]) {
                out.push((*line, format!("mod {name}"), target));
            }
        }
        let child_mods: BTreeSet<&str> = mods.iter().map(|(_, m)| m.as_str()).collect();
        for (line, path) in use_paths(&mut code) {
            let segments: Vec<&str> = path.iter().map(String::as_str).collect();
            let Some(first) = segments.first() else {
                continue;
            };
            if !matches!(*first, "crate" | "super" | "self") && !child_mods.contains(first) {
                continue;
            }
            if let Some(target) = self.resolve(&segments) {
                out.push((line, segments.join("::"), target));
            }
        }
        for (line, path) in code_paths(&code) {
            let segments: Vec<&str> = path.iter().map(String::as_str).collect();
            if let Some(target) = self.resolve(&segments) {
                out.push((line, segments.join("::"), target));
            }
        }
        Ok(out)
    }
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

/// The 1-based line of byte `at`.
fn line_of(text: &[u8], at: usize) -> usize {
    1 + text[..at].iter().filter(|&&b| b == b'\n').count()
}

/// `bytes[from..to]` as spaces, newlines kept, so every line keeps its number.
fn blank(bytes: &mut [u8], from: usize, to: usize) {
    let to = to.min(bytes.len());
    for b in &mut bytes[from.min(to)..to] {
        if *b != b'\n' {
            *b = b' ';
        }
    }
}

/// `text` with every comment and the inside of every string and char literal blanked.
fn blank_comments_and_literals(text: &str) -> String {
    let src = text.as_bytes();
    let mut out = src.to_vec();
    let n = src.len();
    let mut i = 0;
    while i < n {
        let prev_ident = i > 0 && is_ident(src[i - 1]);
        match src[i] {
            b'/' if src.get(i + 1) == Some(&b'/') => {
                let end = src[i..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(n, |p| i + p);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if src.get(i + 1) == Some(&b'*') => {
                let (mut j, mut depth) = (i + 2, 1);
                while j < n && depth > 0 {
                    if src[j..].starts_with(b"/*") {
                        depth += 1;
                        j += 2;
                    } else if src[j..].starts_with(b"*/") {
                        depth -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                blank(&mut out, i, j);
                i = j;
            }
            b'r' if !prev_ident
                || (i >= 1 && src[i - 1] == b'b' && (i < 2 || !is_ident(src[i - 2]))) =>
            {
                let hashes = src[i + 1..].iter().take_while(|&&b| b == b'#').count();
                if src.get(i + 1 + hashes) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let close: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                let body = i + 2 + hashes;
                let end = src[body..]
                    .windows(close.len())
                    .position(|w| w == close.as_slice())
                    .map_or(n, |p| body + p + close.len());
                blank(&mut out, body, end - close.len().min(end));
                i = end;
            }
            b'"' => {
                let mut j = i + 1;
                while j < n && src[j] != b'"' {
                    j += if src[j] == b'\\' { 2 } else { 1 };
                }
                blank(&mut out, i + 1, j);
                i = j + 1;
            }
            b'\'' => {
                // A char literal, else a lifetime or a label.
                let end = if src.get(i + 1) == Some(&b'\\') {
                    src[(i + 3).min(n)..]
                        .iter()
                        .position(|&b| b == b'\'')
                        .map(|p| i + 3 + p)
                } else {
                    let len = match src.get(i + 1) {
                        Some(&b) if b < 0x80 => 1,
                        Some(&b) if b >= 0xf0 => 4,
                        Some(&b) if b >= 0xe0 => 3,
                        Some(_) => 2,
                        None => 0,
                    };
                    (len > 0 && src.get(i + 1 + len) == Some(&b'\'')).then_some(i + 1 + len)
                };
                match end {
                    Some(end) => {
                        blank(&mut out, i + 1, end);
                        i = end + 1;
                    }
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `code` (comments and literals blanked) with every item under `#[cfg(test)]` blanked: up to
/// its `;` or `,`, or through its `{ … }` body. An inner `#![cfg(test)]` blanks the whole file.
fn drop_test_items(code: &str) -> String {
    let src = code.as_bytes();
    let mut out = src.to_vec();
    let mut i = 0;
    while let Some(p) = src[i..].iter().position(|&b| b == b'#') {
        let at = i + p;
        let Some((inner, attr_end, is_test)) = attribute(src, at) else {
            i = at + 1;
            continue;
        };
        i = attr_end;
        if !is_test {
            continue;
        }
        if inner {
            blank(&mut out, 0, src.len());
            break;
        }
        let end = item_end(src, attr_end);
        blank(&mut out, at, end);
        i = end;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The attribute at `at` (`#[ … ]` or `#![ … ]`): whether it is inner, where it ends and
/// whether it is exactly `cfg(test)`.
fn attribute(src: &[u8], at: usize) -> Option<(bool, usize, bool)> {
    let mut j = at + 1;
    let inner = src.get(j) == Some(&b'!');
    if inner {
        j += 1;
    }
    while src.get(j).is_some_and(u8::is_ascii_whitespace) {
        j += 1;
    }
    if src.get(j) != Some(&b'[') {
        return None;
    }
    let open = j;
    let mut depth = 0;
    while j < src.len() {
        match src[j] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    let body: String = String::from_utf8_lossy(&src[open + 1..j])
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect();
                    return Some((inner, j + 1, body == "cfg(test)"));
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// Where the item that starts at `from` ends: after its `;` or `,`, after its `{ … }` body, or
/// before a `}` that closes the scope around it.
fn item_end(src: &[u8], from: usize) -> usize {
    let mut depth = 0i32;
    let mut j = from;
    while j < src.len() {
        match src[j] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b';' | b',' if depth == 0 => return j + 1,
            b'}' if depth == 0 => return j,
            b'{' if depth == 0 => {
                let mut braces = 0;
                while j < src.len() {
                    match src[j] {
                        b'{' => braces += 1,
                        b'}' => {
                            braces -= 1;
                            if braces == 0 {
                                return j + 1;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                return j;
            }
            _ => {}
        }
        j += 1;
    }
    j
}

/// Each `mod <name>;` declaration of `code`: its line and the name.
fn declared_mods(code: &str) -> Vec<(usize, String)> {
    let src = code.as_bytes();
    let mut out = Vec::new();
    for (at, _) in keyword(code, "mod") {
        let rest = &code[at + 3..];
        let name: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let after = rest.trim_start()[name.len()..].trim_start();
        if !name.is_empty() && after.starts_with(';') {
            let name = name.strip_prefix("r#").unwrap_or(&name).to_owned();
            out.push((line_of(src, at), name));
        }
    }
    out
}

/// Each place `word` is a whole token of `code`: its byte offset.
fn keyword<'a>(code: &'a str, word: &'a str) -> impl Iterator<Item = (usize, &'a str)> + 'a {
    let src = code.as_bytes();
    code.match_indices(word).filter(move |(at, _)| {
        let end = at + word.len();
        (*at == 0 || !is_ident(src[at - 1])) && src.get(end).is_none_or(|&b| !is_ident(b))
    })
}

/// Each leaf path of every `use` tree in `code`, with the line of its `use`; each `use` item is
/// blanked in `code` after it is read, so [`code_paths`] does not read it again.
fn use_paths(code: &mut String) -> Vec<(usize, Vec<String>)> {
    let mut out = Vec::new();
    let mut spans = Vec::new();
    for (at, _) in keyword(code, "use") {
        let Some(len) = code[at..].find(';') else {
            continue;
        };
        let tokens = use_tokens(&code[at + 3..at + len]);
        let mut paths = Vec::new();
        if use_tree(&tokens, &mut 0, &[], &mut paths).is_some() {
            let line = line_of(code.as_bytes(), at);
            out.extend(paths.into_iter().map(|(p, _)| (line, p)));
        }
        spans.push((at, at + len));
    }
    let mut bytes = std::mem::take(code).into_bytes();
    for (from, to) in spans {
        blank(&mut bytes, from, to);
    }
    *code = String::from_utf8_lossy(&bytes).into_owned();
    out
}

/// Each name the `use` items of `code` bind (an alias, or the last name of the path), and the
/// path it names; and each name an `extern crate` binds, to its crate. A glob binds no name.
fn use_bindings(code: &str) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for (_, name, alias) in extern_crates(code) {
        out.insert(alias, vec![name]);
    }
    for (at, _) in keyword(code, "use") {
        let Some(len) = code[at..].find(';') else {
            continue;
        };
        let tokens = use_tokens(&code[at + 3..at + len]);
        let mut paths = Vec::new();
        if use_tree(&tokens, &mut 0, &[], &mut paths).is_some() {
            for (path, name) in paths {
                if name != "*" {
                    out.insert(name, path);
                }
            }
        }
    }
    out
}

/// Each glob `use` of `code` (`use a::b::*;`): its line and the path before `*`.
fn use_globs(code: &str) -> Vec<(usize, Vec<String>)> {
    let mut out = Vec::new();
    for (at, _) in keyword(code, "use") {
        let Some(len) = code[at..].find(';') else {
            continue;
        };
        let tokens = use_tokens(&code[at + 3..at + len]);
        let mut paths = Vec::new();
        if use_tree(&tokens, &mut 0, &[], &mut paths).is_some() {
            let line = line_of(code.as_bytes(), at);
            out.extend(
                paths
                    .into_iter()
                    .filter(|(_, name)| name == "*")
                    .map(|(path, _)| (line, path)),
            );
        }
    }
    out
}

/// The tokens of a `use` tree: names (a raw `r#name` as `name`), `::`, braces, commas and `*`.
fn use_tokens(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ':' if chars.peek() == Some(&':') => {
                chars.next();
                tokens.push("::".into());
            }
            '{' | '}' | ',' | '*' => tokens.push(c.to_string()),
            c if c.is_alphanumeric() || c == '_' => {
                let mut name = c.to_string();
                while let Some(&n) = chars.peek().filter(|n| n.is_alphanumeric() || **n == '_') {
                    name.push(n);
                    chars.next();
                }
                // `r#name`: the raw identifier `name`, as one token.
                if name == "r" && chars.peek() == Some(&'#') {
                    chars.next();
                    name.clear();
                    while let Some(&n) = chars.peek().filter(|n| n.is_alphanumeric() || **n == '_')
                    {
                        name.push(n);
                        chars.next();
                    }
                }
                tokens.push(name);
            }
            _ => {}
        }
    }
    tokens
}

/// Parses one tree of `tokens` at `at` under `prefix` into `out`: each leaf path and the name
/// it binds (its `as` alias, else its last name; `*` for a glob). `None` if malformed.
fn use_tree(
    tokens: &[String],
    at: &mut usize,
    prefix: &[String],
    out: &mut Vec<(Vec<String>, String)>,
) -> Option<()> {
    let mut path = prefix.to_vec();
    loop {
        let token = tokens.get(*at)?;
        *at += 1;
        match token.as_str() {
            "::" => continue,
            "*" => {
                out.push((path, "*".to_owned()));
                return Some(());
            }
            "{" => loop {
                if tokens.get(*at).map(String::as_str) == Some("}") {
                    *at += 1;
                    return Some(());
                }
                use_tree(tokens, at, &path, out)?;
                match tokens.get(*at).map(String::as_str) {
                    Some(",") => *at += 1,
                    Some("}") => {}
                    _ => return None,
                }
            },
            "self" if !path.is_empty() => {}
            name => path.push(name.to_owned()),
        }
        let last = path.last().cloned().unwrap_or_default();
        match tokens.get(*at).map(String::as_str) {
            Some("::") => {}
            Some("as") => {
                let alias = tokens.get(*at + 1).cloned().unwrap_or(last);
                *at += 2;
                out.push((path, alias));
                return Some(());
            }
            _ => {
                out.push((path, last));
                return Some(());
            }
        }
    }
}

/// Each `crate::…`, `super::…` and `self::…` path in `code` outside `use` items, with its
/// line: the names up to the first token that is not `::<name>`.
fn code_paths(code: &str) -> Vec<(usize, Vec<String>)> {
    let src = code.as_bytes();
    let mut out = Vec::new();
    for start in ["crate", "super", "self"] {
        for (at, _) in keyword(code, start) {
            let mut path = vec![start.to_owned()];
            let mut rest = &code[at + start.len()..];
            while let Some(after) = rest.strip_prefix("::") {
                let after = after.strip_prefix("r#").unwrap_or(after);
                let name: String = after
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if name.is_empty() {
                    break;
                }
                rest = &after[name.len()..];
                path.push(name);
            }
            if path.len() > 1 {
                out.push((line_of(src, at), path));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = r#"
# A comment ( with a parenthesis.
A_KEY_PATHS=(
  Cargo.toml
  crates/x/src/rpc   # a trailing comment
)
NOT_A_KEY=(skipped)
B_KEY_PATHS=(
  "${A_KEY_PATHS[@]}"
  crates/x/src/transport.rs
)
"#;

    #[test]
    fn key_arrays_expand_the_arrays_they_name() {
        let arrays = key_arrays(SCRIPT).unwrap();
        assert_eq!(
            arrays.keys().collect::<Vec<_>>(),
            ["A_KEY_PATHS", "B_KEY_PATHS"]
        );
        assert_eq!(arrays["A_KEY_PATHS"], ["Cargo.toml", "crates/x/src/rpc"]);
        assert_eq!(
            arrays["B_KEY_PATHS"],
            [
                "Cargo.toml",
                "crates/x/src/rpc",
                "crates/x/src/transport.rs"
            ]
        );
    }

    #[test]
    fn key_arrays_refuse_what_they_cannot_read() {
        for (script, want) in [
            ("", "no *_KEY_PATHS array"),
            ("A_KEY_PATHS=(\n  x\n", "A_KEY_PATHS is not closed"),
            (
                "A_KEY_PATHS=(\n  \"${B_KEY_PATHS[@]}\"\n)\n",
                "A_KEY_PATHS expands B_KEY_PATHS",
            ),
        ] {
            let err = key_arrays(script).unwrap_err();
            assert!(err.contains(want), "{script:?}: {err}");
        }
    }

    /// A crate `x` under a temp root: `files` of (path under `crates/x/src`, text).
    fn fixture(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("crates/x")).unwrap();
        std::fs::write(dir.path().join("crates/x/Cargo.toml"), "[package]\n").unwrap();
        for (path, text) in files {
            let path = dir.path().join("crates/x/src").join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    /// The crate's layout: an `rpc` directory module, a `transport` module with a child, and a
    /// `gossip` module.
    fn layout(codec: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "lib.rs",
                "pub mod gossip;\npub mod rpc;\npub mod transport;\n".into(),
            ),
            (
                "rpc/mod.rs",
                "pub mod codec;\npub mod columns;\n#[cfg(test)]\nmod tests;\n".into(),
            ),
            ("rpc/codec.rs", codec.into()),
            ("rpc/columns.rs", "pub struct Columns;\n".into()),
            ("rpc/tests.rs", "use crate::gossip::Topic;\n".into()),
            (
                "transport.rs",
                "mod quota;\npub use quota::Budget;\npub enum Direction {}\n".into(),
            ),
            ("transport/quota.rs", "pub struct Budget;\n".into()),
            ("gossip.rs", "pub struct Topic;\n".into()),
        ]
    }

    fn run(codec: &str, keyed: &[&str]) -> Vec<String> {
        let files = layout(codec);
        let files: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
        let dir = fixture(&files);
        let keyed: Vec<String> = keyed.iter().map(|k| format!("crates/x/src/{k}")).collect();
        // The crate root rule has its own test.
        unkeyed_imports(dir.path(), &keyed)
            .unwrap()
            .iter()
            .filter(|u| u.import != "crate root")
            .map(ToString::to_string)
            .collect()
    }

    /// The finding this check exists for: a keyed codec imports `super::columns`, which only
    /// the whole directory keys.
    #[test]
    fn a_super_import_of_an_unkeyed_file_fails() {
        let codec = "use super::columns::Columns;\n";
        assert_eq!(
            run(codec, &["rpc/mod.rs", "rpc/codec.rs"]),
            [
                "crates/x/src/rpc/codec.rs:1: `super::columns::Columns` imports \
                 crates/x/src/rpc/columns.rs, which the key does not hold",
                "crates/x/src/rpc/mod.rs:2: `mod columns` imports crates/x/src/rpc/columns.rs, \
                 which the key does not hold",
            ]
        );
        assert_eq!(run(codec, &["rpc"]), Vec::<String>::new());
    }

    /// A `crate::` path in code, through a `use` tree, and the child module that the imported
    /// file declares and re-exports: each must be keyed.
    #[test]
    fn crate_paths_and_their_child_modules_must_be_keyed() {
        let codec = "use crate::{gossip, transport::{self, Direction}};\n\
                     fn f() { let _ = crate::transport::Direction::A; }\n";
        let got = run(codec, &["rpc"]);
        assert_eq!(
            got,
            [
                "crates/x/src/rpc/codec.rs:1: `crate::gossip` imports crates/x/src/gossip.rs, \
                 which the key does not hold",
                "crates/x/src/rpc/codec.rs:1: `crate::transport` imports \
                 crates/x/src/transport.rs, which the key does not hold",
                "crates/x/src/rpc/codec.rs:1: `crate::transport::Direction` imports \
                 crates/x/src/transport.rs, which the key does not hold",
                "crates/x/src/rpc/codec.rs:2: `crate::transport::Direction::A` imports \
                 crates/x/src/transport.rs, which the key does not hold",
            ]
        );
        let got = run(codec, &["rpc", "gossip.rs", "transport.rs"]);
        assert_eq!(
            got,
            [
                "crates/x/src/transport.rs:1: `mod quota` imports \
                 crates/x/src/transport/quota.rs, which the key does not hold",
                "crates/x/src/transport.rs:2: `quota::Budget` imports \
                 crates/x/src/transport/quota.rs, which the key does not hold",
            ]
        );
        let keyed = ["rpc", "gossip.rs", "transport.rs", "transport"];
        assert_eq!(run(codec, &keyed), Vec::<String>::new());
    }

    /// Comments, literals and `#[cfg(test)]` items are not imports, and a test-only file
    /// (`rpc/tests.rs`, declared under `#[cfg(test)]`) is not read.
    #[test]
    fn test_code_comments_and_literals_import_nothing() {
        let codec = "//! See [`crate::gossip::Topic`].\n\
                     /* crate::gossip */\n\
                     const S: &str = \"crate::gossip::Topic\";\n\
                     const R: &str = r#\"super::columns\"#;\n\
                     const C: char = '\"';\n\
                     fn f<'a>(x: &'a str) -> &'a str { x }\n\
                     #[cfg(test)]\n\
                     mod tests {\n    use crate::gossip::Topic;\n    fn g() { let _ = '}'; }\n}\n\
                     #[cfg(test)]\n\
                     use super::columns;\n\
                     pub(crate) fn h() {}\n";
        assert_eq!(
            run(codec, &["rpc/mod.rs", "rpc/codec.rs", "rpc/columns.rs"]),
            Vec::<String>::new()
        );
        assert_eq!(run(codec, &["rpc"]), Vec::<String>::new());
    }

    /// An item after a test module is still read.
    #[test]
    fn code_after_a_test_module_is_read() {
        let codec = "#[cfg(test)]\nmod tests {\n    fn g() {}\n}\n\nuse crate::gossip::Topic;\n";
        assert_eq!(
            run(codec, &["rpc"]),
            ["crates/x/src/rpc/codec.rs:6: `crate::gossip::Topic` imports crates/x/src/gossip.rs, \
              which the key does not hold"]
        );
    }

    /// A checkout under a directory named `src` (`~/src/eth-swarm`): only the `src` directly
    /// below a crate's `Cargo.toml` is a module tree. The crate's integration tests and a target
    /// outside `src` are not modules, and are not read as modules of the outer `src`.
    #[test]
    fn a_checkout_under_a_src_directory_reads_only_the_crate_src() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("src/eth-swarm");
        for (path, text) in [
            ("crates/x/Cargo.toml", "[package]\n"),
            ("crates/x/src/lib.rs", "pub mod a;\n"),
            ("crates/x/src/a.rs", "pub struct A;\n"),
            ("crates/x/tests/t.rs", "use super::helpers;\nmod helpers;\n"),
            ("crates/x/fuzz_targets/f.rs", "use crate::gone::X;\n"),
            ("crates/x/build.rs", "mod other;\n"),
        ] {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        assert_eq!(unkeyed_imports(&root, &["crates/x".into()]), Ok(Vec::new()));
        // A Rust file in no crate is not a module either.
        std::fs::write(root.join("loose.rs"), "use crate::y;\n").unwrap();
        assert_eq!(unkeyed_imports(&root, &["loose.rs".into()]), Ok(Vec::new()));
    }

    /// A keyed module whose crate root is not keyed: a `#[path]` or `mod` edit in the root
    /// could change what the module is.
    #[test]
    fn the_crate_root_of_a_keyed_module_must_be_keyed() {
        let files = layout("");
        let files: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
        let dir = fixture(&files);
        let got: Vec<String> = unkeyed_imports(dir.path(), &["crates/x/src/gossip.rs".into()])
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            got,
            ["crates/x/src/gossip.rs:1: `crate root` imports crates/x/src/lib.rs, which the key \
              does not hold"]
        );
    }

    /// The path dependencies of crate `x` in the fixtures: `y` (`crates/y`) and `z`. The other
    /// crates have none.
    fn deps(krate: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
        if krate != Path::new("crates/x") {
            return Ok(BTreeMap::new());
        }
        Ok([("y", "crates/y"), ("z_crate", "crates/z")]
            .map(|(i, d)| (i.to_owned(), PathBuf::from(d)))
            .into_iter()
            .collect())
    }

    fn crates_of(codec: &str, keyed: &[&str]) -> Vec<String> {
        let mut files = layout(codec);
        files.push(("../../y/src/lib.rs", "pub struct Y;\n".into()));
        files.push(("../../z/src/lib.rs", "pub struct Z;\n".into()));
        let files: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
        let dir = fixture(&files);
        for k in ["y", "z"] {
            std::fs::write(
                dir.path().join(format!("crates/{k}/Cargo.toml")),
                "[package]\n",
            )
            .unwrap();
        }
        let keyed: Vec<String> = keyed.iter().map(|k| (*k).to_owned()).collect();
        unkeyed_crates(dir.path(), &keyed, &deps)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// An import of a workspace path crate whose root the key does not hold, in a `use` tree or
    /// in code. Another crate's paths, test code and comments are not imports.
    #[test]
    fn an_import_of_an_unkeyed_workspace_crate_is_reported() {
        let codec = "use y::Y;\nuse ::serde::Serialize;\n// z_crate::Z\n\
                     fn f() { let _ = z_crate::Z; let _ = other::y::Q; }\n\
                     #[cfg(test)]\nmod tests { use y::Y; }\n";
        assert_eq!(
            crates_of(codec, &["crates/x"]),
            [
                "crates/x/src/rpc/codec.rs:1: `y` imports crates/y, whose crate root the key \
                 does not hold",
                "crates/x/src/rpc/codec.rs:4: `z_crate` imports crates/z, whose crate root the \
                 key does not hold",
            ]
        );
        assert_eq!(
            crates_of(codec, &["crates/x", "crates/y/src/lib.rs", "crates/z"]),
            Vec::<String>::new()
        );
    }

    /// A path from the crate root (`::y::Y`, `(::y::f)()`) and `extern crate y as w;` import
    /// the crate; a later segment (`a::y::`, `<T>::y::`, `f()::y`) does not.
    #[test]
    fn a_leading_double_colon_and_extern_crate_import_the_crate() {
        for (codec, want) in [
            ("fn f() { let _ = ::y::Y; }\n", Some(1)),
            ("fn f() { (::z_crate::Z)(); }\n", Some(1)),
            ("fn f() -> ::y::Y { todo!() }\n", Some(1)),
            ("fn f(a: u8) { match a { _ => ::y::f() } }\n", Some(1)),
            ("extern crate y as w;\n", Some(1)),
            ("impl ::y::T for X {}\n", Some(1)),
            ("fn f(_: &dyn ::y::T) {}\n", Some(1)),
            ("fn f(_: &mut ::y::T) {}\n", Some(1)),
            ("fn f() { let _ = 1 as ::y::T; }\n", Some(1)),
            ("fn f() -> u8 { return ::y::f(); }\n", Some(1)),
            ("fn f(a: u8) -> bool { a > ::y::B }\n", Some(1)),
            ("fn f() { for _ in ::y::all() {} }\n", Some(1)),
            ("fn f() where T: ::y::T {}\n", Some(1)),
            ("fn f() { let _ = move || ::y::g(); }\n", Some(1)),
            ("fn f() { if a {} else { ::y::g() } }\n", Some(1)),
            ("use r#y::Y;\n", Some(1)),
            ("extern crate z_crate;\n", Some(1)),
            (
                "fn f() { let _ = a::y::Y; let _ = <T>::y::Y; let _ = f()::y::Y; }\n",
                None,
            ),
        ] {
            let got = crates_of(codec, &["crates/x"]);
            match want {
                Some(line) => {
                    assert_eq!(got.len(), 1, "{codec:?}: {got:?}");
                    assert!(
                        got[0].starts_with(&format!("crates/x/src/rpc/codec.rs:{line}: ")),
                        "{got:?}"
                    );
                }
                None => assert_eq!(got, Vec::<String>::new(), "{codec:?}"),
            }
        }
    }

    /// A crate the crate root imports privately (`use y as pb;`) and a keyed child names
    /// through it (`crate::pb::X`, `use crate::pb;`): the child imports that crate.
    #[test]
    fn a_crate_named_through_a_use_of_the_crate_root_is_an_import() {
        let mut files = layout("use crate::pb::Y;\nfn f() { let _ = crate::q::Z; }\n");
        files[0].1 = "pub mod gossip;\npub mod rpc;\npub mod transport;\nuse y as pb;\n\
                      use z_crate::{self as q};\n"
            .into();
        files.push(("../../y/src/lib.rs", "pub struct Y;\n".into()));
        files.push(("../../z/src/lib.rs", "pub struct Z;\n".into()));
        let files: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
        let dir = fixture(&files);
        for k in ["y", "z"] {
            std::fs::write(
                dir.path().join(format!("crates/{k}/Cargo.toml")),
                "[package]\n",
            )
            .unwrap();
        }
        let got: Vec<String> = unkeyed_crates(dir.path(), &["crates/x/src/rpc".into()], &deps)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            got,
            [
                "crates/x/src/rpc/codec.rs:1: `y` imports crates/y, whose crate root the key \
                 does not hold",
                "crates/x/src/rpc/codec.rs:2: `z_crate` imports crates/z, whose crate root the \
                 key does not hold",
            ]
        );
    }

    /// The crate `x` of [`layout`] with `root` as its `lib.rs` and `codec` as `rpc/codec.rs`,
    /// and the crates `y` and `z`; `(unkeyed_crates, unsafe_globs)` of the `rpc` key.
    fn scan(root: &str, codec: &str) -> (Vec<String>, Vec<String>) {
        scan_keyed(root, codec, &["crates/x/src/rpc"])
    }

    /// [`scan`] with the key `keyed`.
    fn scan_keyed(root: &str, codec: &str, keyed: &[&str]) -> (Vec<String>, Vec<String>) {
        let mut files = layout(codec);
        files[0].1 = format!("pub mod gossip;\npub mod rpc;\npub mod transport;\n{root}");
        files.push(("../../y/src/lib.rs", "pub struct Y;\n".into()));
        files.push(("../../z/src/lib.rs", "pub struct Z;\n".into()));
        let files: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
        let dir = fixture(&files);
        for k in ["y", "z"] {
            std::fs::write(
                dir.path().join(format!("crates/{k}/Cargo.toml")),
                "[package]\n",
            )
            .unwrap();
        }
        let keyed: Vec<String> = keyed.iter().map(|k| (*k).to_owned()).collect();
        let crates = unkeyed_crates(dir.path(), &keyed, &deps)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        let globs = unsafe_globs(dir.path(), &keyed, &deps)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        (crates, globs)
    }

    /// A glob of a module that binds a workspace crate (`use crate::*;` with `use y as pb;` in
    /// the crate root) would let `pb::X` name the crate unseen, so it is an error; so is a glob
    /// of a workspace crate itself (`pub use y::*;`), and a glob through a crate that the crate
    /// root binds with `extern crate`. A glob of a module that binds no workspace crate, and a
    /// glob in test code, are not.
    #[test]
    fn a_glob_that_can_reach_a_workspace_crate_is_an_error() {
        let cases = [
            (
                "use y as pb;\n",
                "use crate::*;\nfn f() { let _ = pb::Y; }\n",
                "crate::*",
                "binds workspace crate `y`",
            ),
            (
                "use z_crate::Z;\n",
                "use super::super::*;\n",
                "super::super::*",
                "binds workspace crate `z_crate`",
            ),
            (
                "extern crate y as w;\n",
                "use crate::*;\n",
                "crate::*",
                "binds workspace crate `y`",
            ),
            (
                "",
                "pub use y::*;\n",
                "y::*",
                "a glob of workspace crate `y`",
            ),
            (
                "",
                "use ::z_crate::*;\n",
                "z_crate::*",
                "a glob of workspace crate `z_crate`",
            ),
        ];
        for (root, codec, glob, why) in cases {
            let (_, globs) = scan(root, codec);
            assert_eq!(globs.len(), 1, "{root:?} {codec:?}: {globs:?}");
            assert!(
                globs[0].starts_with("crates/x/src/rpc/codec.rs:1: `use ")
                    && globs[0].contains(&format!("{glob}`"))
                    && globs[0].contains(why),
                "{globs:?}"
            );
        }
        // A glob that reaches only a keyed crate bypasses no allowance: the key holds `y` here.
        let (_, globs) = scan_keyed(
            "use y as pb;\n",
            "use crate::*;\npub use y::*;\n",
            &["crates/x/src/rpc", "crates/y"],
        );
        assert_eq!(globs, Vec::<String>::new());
        for (root, codec) in [
            ("use std::fmt;\n", "use crate::*;\n"),
            ("", "use super::*;\nuse std::collections::*;\n"),
            (
                "use y as pb;\n",
                "#[cfg(test)]\nmod tests {\n    use crate::*;\n}\n",
            ),
        ] {
            assert_eq!(
                scan(root, codec).1,
                Vec::<String>::new(),
                "{root:?} {codec:?}"
            );
        }
    }

    /// `extern crate y as w;` binds `w` to `y`: `w::` in the same file and `crate::w::` in a
    /// child import `y`. Raw names (`crate::r#pb::X`, `extern crate r#y`) are read without `r#`.
    #[test]
    fn extern_crate_aliases_and_raw_names_are_followed() {
        let (crates, _) = scan(
            "extern crate y as w;\n",
            "fn f() { let _ = crate::w::Y; }\n",
        );
        assert_eq!(crates.len(), 1, "{crates:?}");
        assert!(crates[0].contains("`y` imports crates/y"), "{crates:?}");
        let (crates, _) = scan("", "extern crate z_crate as v;\nfn f() { let _ = v::Z; }\n");
        assert!(
            crates
                .iter()
                .all(|c| c.contains("`z_crate` imports crates/z")),
            "{crates:?}"
        );
        assert!(!crates.is_empty());
        let (crates, _) = scan("use y as pb;\n", "fn f() { let _ = crate::r#pb::Y; }\n");
        assert!(
            crates.iter().any(|c| c.contains("`y` imports crates/y")),
            "{crates:?}"
        );
        let (crates, _) = scan("", "extern crate r#y;\n");
        assert!(
            crates.iter().any(|c| c.contains("`y` imports crates/y")),
            "{crates:?}"
        );
    }

    /// A chain of aliases longer than the reader follows is an error, never "not a crate".
    #[test]
    fn a_long_chain_of_aliases_fails_closed() {
        let root =
            "use y as a1;\nuse crate::a1 as a2;\nuse crate::a2 as a3;\nuse crate::a3 as a4;\n\
                    use crate::a4 as a5;\nuse crate::a5 as a6;\n";
        let mut files = layout("fn f() { let _ = crate::a6::Y; }\n");
        files[0].1 = format!("pub mod gossip;\npub mod rpc;\npub mod transport;\n{root}");
        let files: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
        let dir = fixture(&files);
        let err = unkeyed_crates(dir.path(), &["crates/x/src/rpc".into()], &deps).unwrap_err();
        assert!(err.contains("more than 4 aliases"), "{err}");
    }

    /// `crate::y::X` with a local module or item `y` is no import of the crate `y`.
    #[test]
    fn a_crate_relative_path_is_not_a_crate_start() {
        let (crates, _) = scan("pub mod y {}\n", "fn f() { let _ = crate::y::X; }\n");
        assert_eq!(crates, Vec::<String>::new());
    }

    fn unkeyed_crate(file: &str, dir: &str) -> UnkeyedCrate {
        UnkeyedCrate {
            file: file.into(),
            line: 1,
            krate: "y".into(),
            dir: dir.into(),
        }
    }

    /// An allowance covers an import only from a file it lists, in its gate: an import of the
    /// same crate from another file is not allowed. A listed file that imports nothing is stale.
    #[test]
    fn an_allowance_covers_only_the_files_it_lists() {
        let allowed = [Allowance {
            gate: "A_KEY_PATHS",
            dir: "crates/y",
            files: &["crates/x/src/a.rs", "crates/x/src/b.rs"],
            reason: "no target runs it",
        }];
        let mut used = BTreeSet::new();
        let found = vec![
            unkeyed_crate("crates/x/src/a.rs", "crates/y"),
            unkeyed_crate("crates/x/src/codec.rs", "crates/y"),
            unkeyed_crate("crates/x/src/a.rs", "crates/z"),
        ];
        let left = not_allowed("A_KEY_PATHS", found.clone(), &allowed, &mut used);
        assert_eq!(left, found[1..].to_vec());
        assert_eq!(
            not_allowed("B_KEY_PATHS", found[..1].to_vec(), &allowed, &mut used),
            found[..1].to_vec(),
            "another gate"
        );
        assert_eq!(
            stale_allowances(&allowed, &used),
            ["A_KEY_PATHS crates/y: crates/x/src/b.rs imports nothing of it"]
        );
        let empty = [Allowance {
            reason: " ",
            ..allowed[0]
        }];
        assert_eq!(
            stale_allowances(&empty, &used),
            [
                "A_KEY_PATHS crates/y: no reason",
                "A_KEY_PATHS crates/y: crates/x/src/b.rs imports nothing of it",
            ]
        );
    }

    #[test]
    fn a_keyed_path_that_does_not_exist_is_an_error() {
        let dir = fixture(&[("lib.rs", "")]);
        let err = unkeyed_imports(dir.path(), &["crates/x/src/none.rs".into()]).unwrap_err();
        assert!(err.contains("crates/x/src/none.rs"), "{err}");
    }
}
