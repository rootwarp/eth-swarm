//! Every-file-read coverage guard, after Lighthouse's `check_all_files_accessed.py`.
//!
//! [`walk`] lists every file under an extracted vector root and maps each one to the case it
//! belongs to ([`Layout`]); the resulting cases are what [`crate::plan::plan`] classifies.
//! Handlers open vector files only through [`Reads`], which records each path. After the run,
//! [`Guard::check`] fails with every file that no handler read, unless its case is skipped or a
//! `skip.toml` `file` entry excuses it.

use crate::plan::{Case, CaseFile, CaseKey, Disposition, SkipList};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

/// What one directory level below a vector root names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// A fixed directory such as `tests`; not part of the key.
    Dir,
    /// The preset (`minimal`, `mainnet`, `general`).
    Preset,
    /// The fork.
    Fork,
    /// The runner, e.g. `ssz_static` or `kzg`.
    Runner,
    /// The handler, e.g. `BeaconState` or `compute_cells`.
    Handler,
}

/// How the levels below the slots form a case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseShape {
    /// The case is this many directories (consensus-specs: `<suite>/<case>`).
    Dirs(usize),
    /// The case is one file, named by its stem (ssz-specs `<case>.json`).
    File,
}

/// Maps paths below one vector root to case keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// The `source` of every key.
    pub source: &'static str,
    /// Directory levels, outermost first.
    pub slots: &'static [Slot],
    /// The runner of every key when [`Slot::Runner`] is not among the slots.
    pub runner: &'static str,
    /// The case below the slots.
    pub case: CaseShape,
}

impl Layout {
    /// Maps a file's path components (relative to the root, file name last) to its case key
    /// and its name inside the case. Fields without a directory level are `none` (fork,
    /// preset) or the layout's runner; levels missing because the file sits too shallow are
    /// empty, so such stray files still get a key that a skip entry can match.
    pub fn locate(&self, components: &[String]) -> (CaseKey, String) {
        let (name, dirs) = components
            .split_last()
            .map(|(n, d)| (n.clone(), d))
            .unwrap_or_default();
        let mut key = CaseKey {
            source: self.source.into(),
            fork: "none".into(),
            preset: "none".into(),
            runner: self.runner.into(),
            handler: String::new(),
            case: String::new(),
        };
        for (i, slot) in self.slots.iter().enumerate() {
            let v = dirs.get(i).cloned().unwrap_or_default();
            match slot {
                Slot::Dir => {}
                Slot::Preset => key.preset = v,
                Slot::Fork => key.fork = v,
                Slot::Runner => key.runner = v,
                Slot::Handler => key.handler = v,
            }
        }
        if dirs.len() < self.slots.len() {
            return (key, name);
        }
        let rest = &dirs[self.slots.len()..];
        let file = match self.case {
            CaseShape::Dirs(n) => {
                let n = n.min(rest.len());
                key.case = rest[..n].join("/");
                join(&rest[n..], &name)
            }
            CaseShape::File => match rest.split_first() {
                None => {
                    key.case = Path::new(&name)
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    name
                }
                Some((case, deeper)) => {
                    key.case = case.clone();
                    join(deeper, &name)
                }
            },
        };
        (key, file)
    }
}

fn join(dirs: &[String], name: &str) -> String {
    dirs.iter()
        .map(String::as_str)
        .chain([name])
        .collect::<Vec<_>>()
        .join("/")
}

/// Lists every file under `root` (recursively, sorted) as cases of `layout`, in path order.
pub fn walk(root: &Path, layout: &Layout) -> io::Result<Vec<Case>> {
    let mut files = Vec::new();
    collect(root, &mut Vec::new(), &mut files)?;
    let mut cases: Vec<Case> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for (path, components) in files {
        let (key, name) = layout.locate(&components);
        let i = *index.entry(key.to_string()).or_insert_with(|| {
            cases.push(Case {
                key,
                files: Vec::new(),
            });
            cases.len() - 1
        });
        cases[i].files.push(CaseFile { path, name });
    }
    Ok(cases)
}

fn collect(
    dir: &Path,
    prefix: &mut Vec<String>,
    out: &mut Vec<(PathBuf, Vec<String>)>,
) -> io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        prefix.push(e.file_name().to_string_lossy().into_owned());
        if e.file_type()?.is_dir() {
            collect(&path, prefix, out)?;
        } else {
            out.push((path, prefix.clone()));
        }
        prefix.pop();
    }
    Ok(())
}

/// Records every vector file a handler opens. Clones share one record.
#[derive(Clone, Debug, Default)]
pub struct Reads(Arc<Mutex<HashSet<PathBuf>>>);

impl Reads {
    /// [`std::fs::read`], recording `path` once the read succeeds.
    pub fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let bytes = std::fs::read(path)?;
        self.record(path);
        Ok(bytes)
    }

    /// [`std::fs::read_to_string`], recording `path` once the read succeeds.
    pub fn read_to_string(&self, path: &Path) -> io::Result<String> {
        let text = std::fs::read_to_string(path)?;
        self.record(path);
        Ok(text)
    }

    /// Whether `path` was read.
    pub fn contains(&self, path: &Path) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(path)
    }

    fn record(&self, path: &Path) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(path.to_owned());
    }
}

/// How many unread paths [`Unread`] prints before summarising the rest.
pub const MAX_LISTED: usize = 200;

/// The files a handler had to read, fixed once the cases are planned.
///
/// Like Lighthouse's `check_all_files_accessed.py`, [`Guard::check`] can also walk the roots
/// again after the run ([`Guard::rewalk`]): a file that was not there when the cases were
/// planned fails the run too, wherever it appears.
#[derive(Debug)]
pub struct Guard {
    root: PathBuf,
    expected: Vec<PathBuf>,
    total: usize,
    rewalk: Option<Rewalk>,
}

/// The roots to walk again and the files they held before the run.
#[derive(Debug)]
struct Rewalk {
    roots: Vec<PathBuf>,
    before: Arc<Vec<Case>>,
}

impl Guard {
    /// Expects every file of `planned` to be read, except the files of skipped cases and the
    /// files a `file` entry of `skips` excuses. `root` only shortens the paths in reports.
    pub fn new(root: &Path, planned: &[(&Case, Disposition)], skips: &SkipList) -> Self {
        let mut total = 0;
        let mut expected = Vec::new();
        for (case, disposition) in planned {
            total += case.files.len();
            if matches!(disposition, Disposition::Skip(_)) {
                continue;
            }
            expected.extend(
                case.files
                    .iter()
                    .filter(|f| !skips.excuses(&case.key, &f.name))
                    .map(|f| f.path.clone()),
            );
        }
        Self {
            root: root.to_owned(),
            expected,
            total,
            rewalk: None,
        }
    }

    /// Also walks `roots` again in [`Guard::check`] and fails on any file missing from
    /// `before` (the cases the run was planned from).
    pub fn rewalk(mut self, roots: Vec<PathBuf>, before: Arc<Vec<Case>>) -> Self {
        self.rewalk = Some(Rewalk { roots, before });
        self
    }

    /// Passes when every expected file was read and, with [`Guard::rewalk`], no file
    /// appeared since the cases were planned; otherwise names the offending files.
    pub fn check(&self, reads: &Reads) -> Result<Covered, Unread> {
        let short = |p: &Path| p.strip_prefix(&self.root).unwrap_or(p).to_owned();
        let unread: Vec<PathBuf> = self
            .expected
            .iter()
            .filter(|p| !reads.contains(p))
            .map(|p| short(p))
            .collect();
        let (mut appeared, mut errors) = (Vec::new(), Vec::new());
        if let Some(rw) = &self.rewalk {
            let before: HashSet<&Path> = rw
                .before
                .iter()
                .flat_map(|c| c.files.iter().map(|f| f.path.as_path()))
                .collect();
            for root in &rw.roots {
                let mut now = Vec::new();
                match collect(root, &mut Vec::new(), &mut now) {
                    Ok(()) => appeared.extend(
                        now.into_iter()
                            .filter(|(p, _)| !before.contains(p.as_path()))
                            .map(|(p, _)| short(&p)),
                    ),
                    Err(e) => errors.push(format!("{}: {e}", short(root).display())),
                }
            }
        }
        if unread.is_empty() && appeared.is_empty() && errors.is_empty() {
            Ok(Covered {
                read: self.expected.len(),
                total: self.total,
            })
        } else {
            Err(Unread {
                unread,
                appeared,
                errors,
            })
        }
    }
}

/// A passing guard: `read` of `total` files were read; the rest are skipped or excused.
#[derive(Debug, PartialEq, Eq)]
pub struct Covered {
    /// Files read by a handler.
    pub read: usize,
    /// Files under the walked roots.
    pub total: usize,
}

impl fmt::Display for Covered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "coverage guard: {} of {} vector files read; the other {} are skipped or excused \
             in skip.toml",
            self.read,
            self.total,
            self.total - self.read
        )
    }
}

/// A failing guard. Paths are relative to the vectors root.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Unread {
    /// Expected files no handler read.
    pub unread: Vec<PathBuf>,
    /// Files found by the walk after the run that were not there when it was planned.
    pub appeared: Vec<PathBuf>,
    /// Roots the walk after the run could not read.
    pub errors: Vec<String>,
}

fn list(f: &mut fmt::Formatter<'_>, title: &str, items: &[impl fmt::Display]) -> fmt::Result {
    if items.is_empty() {
        return Ok(());
    }
    writeln!(f, "coverage guard: {} {title}:", items.len())?;
    for p in items.iter().take(MAX_LISTED) {
        writeln!(f, "  {p}")?;
    }
    if items.len() > MAX_LISTED {
        writeln!(f, "  ... and {} more", items.len() - MAX_LISTED)?;
    }
    Ok(())
}

impl fmt::Display for Unread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shown = |v: &[PathBuf]| {
            v.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
        };
        list(
            f,
            "vector files were read by no handler and are excused by no skip.toml entry",
            &shown(&self.unread),
        )?;
        list(
            f,
            "vector files appeared during the run (not there when the cases were planned)",
            &shown(&self.appeared),
        )?;
        list(
            f,
            "vector roots could not be walked after the run",
            &self.errors,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{plan, Date};

    const CONSENSUS: Layout = Layout {
        source: "consensus-specs",
        slots: &[
            Slot::Dir,
            Slot::Preset,
            Slot::Fork,
            Slot::Runner,
            Slot::Handler,
        ],
        runner: "",
        case: CaseShape::Dirs(2),
    };

    const FLAT: Layout = Layout {
        source: "bls12-381-tests",
        slots: &[Slot::Handler],
        runner: "bls",
        case: CaseShape::File,
    };

    fn parts(p: &str) -> Vec<String> {
        p.split('/').map(String::from).collect()
    }

    fn located(layout: &Layout, p: &str) -> (String, String) {
        let (k, f) = layout.locate(&parts(p));
        (k.to_string(), f)
    }

    #[test]
    fn consensus_paths_map_to_suite_and_case() {
        assert_eq!(
            located(
                &CONSENSUS,
                "tests/minimal/gloas/ssz_static/Checkpoint/ssz_one/case_0/roots.yaml"
            ),
            (
                "consensus-specs::gloas::minimal::ssz_static::Checkpoint::ssz_one/case_0".into(),
                "roots.yaml".into()
            )
        );
        let (_, nested) = located(
            &CONSENSUS,
            "tests/minimal/fulu/sanity/blocks/pyspec_tests/c/sub/x.ssz",
        );
        assert_eq!(nested, "sub/x.ssz");
    }

    #[test]
    fn shallow_files_get_empty_fields() {
        let (k, f) = CONSENSUS.locate(&parts("tests/minimal/gloas/README"));
        assert_eq!((k.fork.as_str(), k.runner.as_str()), ("gloas", ""));
        assert_eq!((k.handler.as_str(), k.case.as_str()), ("", ""));
        assert_eq!(f, "README");
        let (k, f) = CONSENSUS.locate(&parts("tests/minimal/gloas/ssz_static/Fork/suite/x"));
        assert_eq!((k.case.as_str(), f.as_str()), ("suite", "x"));
    }

    #[test]
    fn file_cases_use_the_stem() {
        assert_eq!(
            located(&FLAT, "verify/verify_valid_case_1.yaml"),
            (
                "bls12-381-tests::none::none::bls::verify::verify_valid_case_1".into(),
                "verify_valid_case_1.yaml".into()
            )
        );
        assert_eq!(
            located(&FLAT, "verify/deeper/x.yaml").1,
            "x.yaml".to_string()
        );
        assert_eq!(located(&FLAT, "README.md").1, "README.md".to_string());
    }

    fn tree(files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for f in files {
            let p = dir.path().join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, f.as_bytes()).unwrap();
        }
        dir
    }

    #[test]
    fn walk_groups_files_by_case_in_path_order() {
        let dir = tree(&["verify/b.yaml", "verify/a.yaml", "sign/a.yaml"]);
        let cases = walk(dir.path(), &FLAT).unwrap();
        let got: Vec<_> = cases
            .iter()
            .map(|c| format!("{}/{}", c.key.handler, c.key.case))
            .collect();
        assert_eq!(got, ["sign/a", "verify/a", "verify/b"]);
        assert_eq!(cases[1].files[0].path, dir.path().join("verify/a.yaml"));
    }

    #[test]
    fn walk_of_a_missing_root_is_an_error() {
        assert!(walk(Path::new("/nonexistent/spec-vectors"), &FLAT).is_err());
    }

    const SKIP_SIGN: &str = "[[skip]]\nsource = \"bls12-381-tests\"\nfork = \"none\"\n\
        preset = \"none\"\nrunner = \"bls\"\nhandler = \"sign\"\nreason = \"r\"\nowner = \"ian\"\n\
        issue = \"TBD\"\nexpires = \"2026-12-31\"\n";

    fn guard_for(dir: &Path, skip: &str) -> (Vec<Case>, SkipList) {
        (walk(dir, &FLAT).unwrap(), SkipList::parse(skip).unwrap())
    }

    #[test]
    fn guard_names_unread_files_and_ignores_skipped_cases() {
        let dir = tree(&["verify/a.yaml", "verify/b.yaml", "sign/a.yaml"]);
        let (cases, skips) = guard_for(dir.path(), SKIP_SIGN);
        let planned = plan(
            &cases,
            |_| true,
            &skips,
            Date::parse("2026-10-17").unwrap(),
            &[],
        )
        .unwrap();
        let guard = Guard::new(dir.path(), &planned, &skips);
        let reads = Reads::default();
        reads.read(&dir.path().join("verify/a.yaml")).unwrap();
        let err = guard.check(&reads).unwrap_err();
        assert_eq!(err.unread, [PathBuf::from("verify/b.yaml")]);
        assert!(err.to_string().contains("verify/b.yaml"), "{err}");

        reads
            .read_to_string(&dir.path().join("verify/b.yaml"))
            .unwrap();
        let ok = guard.check(&reads).unwrap();
        assert_eq!(ok, Covered { read: 2, total: 3 });
        assert!(ok.to_string().contains("2 of 3"), "{ok}");
    }

    #[test]
    fn guard_honours_file_entries() {
        let dir = tree(&["verify/a.yaml", "sign/a.yaml"]);
        let excuse = SKIP_SIGN.replace(
            "handler = \"sign\"",
            "handler = \"verify\"\nfile = \"*.yaml\"",
        );
        let (cases, skips) = guard_for(dir.path(), &(SKIP_SIGN.to_owned() + &excuse));
        let planned = plan(
            &cases,
            |_| true,
            &skips,
            Date::parse("2026-10-17").unwrap(),
            &[],
        )
        .unwrap();
        let guard = Guard::new(dir.path(), &planned, &skips);
        assert_eq!(
            guard.check(&Reads::default()),
            Ok(Covered { read: 0, total: 2 })
        );
    }

    #[test]
    fn rewalk_reports_new_files_and_unreadable_roots() {
        let dir = tree(&["sign/a.yaml"]);
        let (cases, skips) = guard_for(dir.path(), SKIP_SIGN);
        let planned = plan(
            &cases,
            |_| true,
            &skips,
            Date::parse("2026-10-17").unwrap(),
            &[],
        )
        .unwrap();
        let roots = vec![dir.path().to_owned(), dir.path().join("gone")];
        let guard = Guard::new(dir.path(), &planned, &skips).rewalk(roots, Arc::new(cases.clone()));
        std::fs::write(dir.path().join("sign/b.yaml"), b"late").unwrap();
        let err = guard.check(&Reads::default()).unwrap_err();
        assert_eq!(err.appeared, [PathBuf::from("sign/b.yaml")]);
        assert_eq!(err.errors.len(), 1);
        let text = err.to_string();
        assert!(text.contains("appeared during the run"), "{text}");
        assert!(text.contains("could not be walked"), "{text}");
    }

    #[test]
    fn failed_reads_are_not_recorded() {
        let reads = Reads::default();
        let missing = Path::new("/nonexistent/x.yaml");
        assert!(reads.read(missing).is_err());
        assert!(reads.read_to_string(missing).is_err());
        assert!(!reads.contains(missing));
    }

    #[test]
    fn long_reports_are_truncated() {
        let unread = Unread {
            unread: (0..MAX_LISTED + 3)
                .map(|i| PathBuf::from(format!("f{i}")))
                .collect(),
            ..Unread::default()
        };
        let text = unread.to_string();
        assert!(text.contains("... and 3 more"), "{text}");
        assert!(!text.contains(&format!("f{}", MAX_LISTED)), "{text}");
    }
}
