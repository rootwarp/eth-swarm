//! Puts the pieces together: which vector sets to scan, the walk of each, the runner of each
//! case, the skip plan and the coverage guard. `tests/vectors.rs` turns the result into one
//! libtest trial per case.

use crate::coverage::{self, CaseShape, Guard, Layout, Reads, Slot};
use crate::plan::{plan, Case, CaseKey, Date, Disposition, Scope, SkipList, COMPTESTS_PRESETS};
use crate::{
    bls, epoch_processing, finality, fixture, kzg, networking, operations, random, rewards, sanity,
    shuffling, ssz_generic, ssz_static,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Runs one case; `Err` describes the failure.
pub type Runner = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

/// Whether a set must be present when no selection is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// Missing tree fails the run.
    Required,
    /// Scanned only when extracted.
    IfPresent,
}

/// One extracted tree of `testing/fetch-vectors.sh`:
/// `<SPEC_VECTORS_DIR>/<source>/<tag>/<stem>`.
#[derive(Debug)]
pub struct VectorSet {
    /// Name used by `SPEC_SETS`.
    pub name: &'static str,
    /// Manifest source, for the tag.
    pub source: &'static str,
    /// Archive stem; `{tag}` is replaced by the source's tag.
    pub stem: &'static str,
    /// How paths below the stem map to cases (and the `source` of every key).
    pub layout: Layout,
    /// Default presence.
    pub presence: Presence,
    /// What the set can contain, for the skip list's stale check.
    pub scope: Scope,
    /// Directories below the stem that must hold at least one file whenever the set is
    /// scanned: the trees the runners exist for. A set that is there but lacks one fails setup
    /// instead of passing with nothing run.
    pub subtrees: &'static [&'static str],
}

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

const ANY: &[&str] = &["*"];
const NONE: &[&str] = &["none"];

/// A consensus-spec-tests preset tree that may hold any fork and runner.
const fn consensus(
    preset: &'static str,
    presets: &'static [&'static str],
    presence: Presence,
    subtrees: &'static [&'static str],
) -> VectorSet {
    VectorSet {
        name: preset,
        source: "consensus-specs",
        stem: preset,
        layout: CONSENSUS,
        presence,
        scope: Scope {
            source: "consensus-specs",
            presets,
            forks: ANY,
            runners: ANY,
        },
        subtrees,
    }
}

/// Every set the runner knows. Without `SPEC_SETS`, ssz-specs and minimal are required and
/// the rest are scanned when extracted.
///
/// `minimal` and `mainnet` must hold the trees of each runner that no skip entry may reach:
/// `ssz_static`, `phase0/shuffling` and the Gloas state-transition runners. Without these
/// subtrees, a missing tree would pass setup and run no trial.
///
/// `general` at v1.7.0-beta.4 holds only `altair/bls`, which is its scope.
///
/// `comptests` is consensus-specs `comptests.tar.gz`: the `fork_choice_compliance` vectors
/// under `tests/minimal/<fork>/` plus the pyspec and generator Python sources that ship with
/// them. Nothing runs it yet; it is scanned so the guard covers every extracted file. Its keys
/// use source `comptests` and the consensus layout, so `tests/core/pyspec/...` has preset
/// `core` and fork `pyspec`.
pub const SETS: [VectorSet; 7] = [
    VectorSet {
        name: "ssz-specs",
        source: "ssz-specs",
        stem: "ssz-test-vectors-{tag}",
        layout: Layout {
            source: "ssz-specs",
            slots: &[Slot::Dir, Slot::Dir, Slot::Runner, Slot::Handler],
            runner: "",
            case: CaseShape::File,
        },
        presence: Presence::Required,
        scope: Scope {
            source: "ssz-specs",
            presets: NONE,
            forks: NONE,
            runners: &["ssz"],
        },
        subtrees: &["fixtures/ssz/ssz"],
    },
    VectorSet {
        scope: Scope {
            source: "consensus-specs",
            presets: &["general"],
            forks: &["altair"],
            runners: &["bls"],
        },
        ..consensus(
            "general",
            &["general"],
            Presence::IfPresent,
            &["tests/general/altair/bls"],
        )
    },
    consensus(
        "minimal",
        &["minimal"],
        Presence::Required,
        &[
            "tests/minimal/fulu/ssz_static",
            "tests/minimal/gloas/ssz_static",
            "tests/minimal/phase0/shuffling",
            "tests/minimal/gloas/sanity",
            "tests/minimal/gloas/epoch_processing",
            "tests/minimal/gloas/operations",
            "tests/minimal/gloas/finality",
            "tests/minimal/gloas/rewards",
            "tests/minimal/gloas/random",
        ],
    ),
    consensus(
        "mainnet",
        &["mainnet"],
        Presence::IfPresent,
        &[
            "tests/mainnet/fulu/ssz_static",
            "tests/mainnet/gloas/ssz_static",
            "tests/mainnet/phase0/shuffling",
            "tests/mainnet/gloas/sanity",
            "tests/mainnet/gloas/epoch_processing",
            "tests/mainnet/gloas/operations",
            "tests/mainnet/gloas/finality",
            "tests/mainnet/gloas/rewards",
            "tests/mainnet/gloas/random",
        ],
    ),
    VectorSet {
        name: "cryptography-specs",
        source: "cryptography-specs",
        stem: "tests",
        layout: Layout {
            source: "cryptography-specs",
            slots: &[Slot::Dir, Slot::Runner, Slot::Handler],
            runner: "",
            case: CaseShape::Dirs(1),
        },
        presence: Presence::IfPresent,
        scope: Scope {
            source: "cryptography-specs",
            presets: NONE,
            forks: NONE,
            runners: &["bls", "kzg"],
        },
        subtrees: &["tests/bls", "tests/kzg"],
    },
    VectorSet {
        name: "comptests",
        source: "consensus-specs",
        stem: "comptests",
        layout: Layout {
            source: "comptests",
            ..CONSENSUS
        },
        presence: Presence::IfPresent,
        scope: Scope {
            source: "comptests",
            presets: &COMPTESTS_PRESETS,
            forks: ANY,
            runners: ANY,
        },
        subtrees: &["tests/minimal"],
    },
    VectorSet {
        name: "bls12-381-tests",
        source: "bls12-381-tests",
        stem: "bls_tests_yaml",
        layout: Layout {
            source: "bls12-381-tests",
            slots: &[Slot::Handler],
            runner: "bls",
            case: CaseShape::File,
        },
        presence: Presence::IfPresent,
        scope: Scope {
            source: "bls12-381-tests",
            presets: NONE,
            forks: NONE,
            runners: &["bls"],
        },
        subtrees: &[
            "aggregate",
            "aggregate_verify",
            "batch_verify",
            "deserialization_G1",
            "deserialization_G2",
            "fast_aggregate_verify",
            "sign",
            "verify",
        ],
    },
];

/// The sets to scan and whether each must exist. `None` (no `SPEC_SETS`) uses each set's
/// default; otherwise exactly the named sets (space or comma separated) run, all required.
pub fn select(selection: Option<&str>) -> Result<Vec<(&'static VectorSet, Presence)>, String> {
    let Some(spec) = selection else {
        return Ok(SETS.iter().map(|s| (s, s.presence)).collect());
    };
    let names: Vec<&str> = spec.split([' ', ',']).filter(|n| !n.is_empty()).collect();
    if names.is_empty() {
        return Err("SPEC_SETS is empty".into());
    }
    if let Some(bad) = names.iter().find(|n| !SETS.iter().any(|s| s.name == **n)) {
        let known: Vec<_> = SETS.iter().map(|s| s.name).collect();
        return Err(format!("SPEC_SETS: unknown set {bad:?}; known: {known:?}"));
    }
    Ok(SETS
        .iter()
        .filter(|s| names.contains(&s.name))
        .map(|s| (s, Presence::Required))
        .collect())
}

/// `source name -> tag` from `testing/vectors.manifest.toml`.
pub fn manifest_tags(text: &str) -> Result<HashMap<String, String>, String> {
    #[derive(serde::Deserialize)]
    struct Source {
        name: String,
        tag: String,
    }
    #[derive(serde::Deserialize)]
    struct Manifest {
        source: Vec<Source>,
    }
    let m: Manifest = toml::from_str(text).map_err(|e| format!("vectors manifest: {e}"))?;
    Ok(m.source.into_iter().map(|s| (s.name, s.tag)).collect())
}

/// What a trial does.
pub enum Outcome {
    /// Run the handler.
    Run(Runner),
    /// Matched by a skip entry (its reason).
    Skip(String),
    /// Neither runnable nor skipped.
    Unaccounted,
}

/// One case as a named trial.
pub struct Trial {
    /// libtest name, e.g. `gloas_ssz_static_minimal::Checkpoint::ssz_one::case_0`.
    pub name: String,
    /// What the trial does.
    pub outcome: Outcome,
}

/// Why the suite could not be built.
#[derive(Debug, PartialEq, Eq)]
pub enum SuiteError {
    /// Missing tree, unreadable input, unknown handler directory.
    Setup(String),
    /// Expired or stale skip entries.
    Rules(String),
}

/// The planned run.
pub struct Suite {
    /// One per case, in walk order.
    pub trials: Vec<Trial>,
    /// Checks, after the trials ran, that every expected file was read.
    pub guard: Guard,
    /// The record every runner reads through.
    pub reads: Reads,
    /// Names of the sets that were scanned.
    pub scanned: Vec<&'static str>,
}

/// Inputs to [`build`].
pub struct Config<'a> {
    /// `SPEC_VECTORS_DIR`.
    pub root: &'a Path,
    /// Text of `testing/vectors.manifest.toml`.
    pub manifest: &'a str,
    /// Text of `testing/skip.toml`.
    pub skip: &'a str,
    /// `SPEC_SETS`, if set.
    pub selection: Option<&'a str>,
    /// Date the skip expiries are checked against.
    pub today: Date,
}

/// Walks the selected sets, attaches runners, and plans every case against the skip list.
pub fn build(cfg: &Config<'_>) -> Result<Suite, SuiteError> {
    let skips = SkipList::parse(cfg.skip).map_err(|e| SuiteError::Rules(e.to_string()))?;
    let tags = manifest_tags(cfg.manifest).map_err(SuiteError::Setup)?;
    let mut cases = Vec::new();
    let mut scanned = Vec::new();
    let mut walked_sets = Vec::new();
    for (set, presence) in select(cfg.selection).map_err(SuiteError::Setup)? {
        let dir = set_dir(cfg.root, &tags, set).ok_or_else(|| {
            SuiteError::Setup(format!("vectors manifest has no source {:?}", set.source))
        })?;
        if !dir.is_dir() {
            if presence == Presence::Required {
                return Err(SuiteError::Setup(format!(
                    "{} vectors missing at {}; run testing/fetch-vectors.sh",
                    set.name,
                    dir.display()
                )));
            }
            continue;
        }
        let walked = coverage::walk(&dir, &set.layout)
            .map_err(|e| SuiteError::Setup(format!("{}: {e}", dir.display())))?;
        walked_sets.push((set, dir, cases.len()..cases.len() + walked.len()));
        cases.extend(walked);
        scanned.push(set.name);
    }

    let unknown: BTreeSet<String> = cases
        .iter()
        .filter_map(|c| handler_check(&c.key).err())
        .collect();
    if !unknown.is_empty() {
        return Err(SuiteError::Setup(
            unknown.into_iter().collect::<Vec<_>>().join("\n"),
        ));
    }
    let incomplete: Vec<String> = walked_sets
        .iter()
        .filter_map(|(set, dir, range)| incomplete(set, dir, &cases[range.clone()]))
        .collect();
    if !incomplete.is_empty() {
        return Err(SuiteError::Setup(incomplete.join("\n")));
    }
    let scopes: Vec<Scope> = walked_sets.iter().map(|(set, _, _)| set.scope).collect();
    let roots: Vec<PathBuf> = walked_sets.into_iter().map(|(_, dir, _)| dir).collect();

    let reads = Reads::default();
    let kinds: Vec<Option<Kind>> = cases.iter().map(kind).collect();
    let runnable: HashSet<String> = cases
        .iter()
        .zip(&kinds)
        .filter(|(_, k)| k.is_some())
        .map(|(c, _)| c.key.to_string())
        .collect();
    let planned = plan(
        &cases,
        |k| runnable.contains(&k.to_string()),
        &skips,
        cfg.today,
        &scopes,
    )
    .map_err(|errs| {
        SuiteError::Rules(
            errs.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
    })?;
    let guard = Guard::new(cfg.root, &planned, &skips);
    let dispositions: Vec<Disposition> = planned.into_iter().map(|(_, d)| d).collect();

    let cases = Arc::new(cases);
    let guard = guard.rewalk(roots, Arc::clone(&cases));
    let trials = dispositions
        .into_iter()
        .zip(kinds)
        .enumerate()
        .map(|(i, (disposition, kind))| Trial {
            name: trial_name(&cases[i].key),
            outcome: match (disposition, kind) {
                (Disposition::Skip(reason), _) => Outcome::Skip(reason),
                (Disposition::Run, Some(kind)) => {
                    let (cases, reads) = (Arc::clone(&cases), reads.clone());
                    Outcome::Run(Arc::new(move || kind.run(&reads, &cases[i])))
                }
                (Disposition::Run, None) | (Disposition::Unaccounted, _) => Outcome::Unaccounted,
            },
        })
        .collect();
    Ok(Suite {
        trials,
        guard,
        reads,
        scanned,
    })
}

/// Why a scanned set cannot be trusted: no files at all, or a runnable subtree without files.
fn incomplete(set: &VectorSet, dir: &Path, cases: &[Case]) -> Option<String> {
    if cases.iter().all(|c| c.files.is_empty()) {
        return Some(format!(
            "{} vectors hold no files at {}; re-run testing/fetch-vectors.sh",
            set.name,
            dir.display()
        ));
    }
    let missing: Vec<&str> = set
        .subtrees
        .iter()
        .copied()
        .filter(|sub| {
            let sub = dir.join(sub);
            !cases
                .iter()
                .any(|c| c.files.iter().any(|f| f.path.starts_with(&sub)))
        })
        .collect();
    (!missing.is_empty()).then(|| {
        format!(
            "{} vectors at {} lack {}; re-run testing/fetch-vectors.sh",
            set.name,
            dir.display(),
            missing.join(", ")
        )
    })
}

/// Fails on a `bls`, `kzg`, Gloas `epoch_processing` or Gloas `operations` handler
/// directory the runners do not classify.
fn handler_check(k: &CaseKey) -> Result<(), String> {
    if k.handler.is_empty() {
        return Ok(());
    }
    let at = || format!(" (in {} {}/{})", k.source, k.preset, k.fork);
    match k.runner.as_str() {
        "bls" => bls::handler_runs(&k.handler)
            .map(drop)
            .map_err(|e| e + &at()),
        "kzg" => kzg::handler_runs(&k.handler)
            .map(drop)
            .map_err(|e| e + &at()),
        "epoch_processing" => epoch_processing::check_handler(k),
        "operations" if k.source == "consensus-specs" && k.fork == "gloas" => {
            operations::handler_runs(&k.handler)
                .map(drop)
                .map_err(|e| e + &at())
        }
        _ => Ok(()),
    }
}

/// Which runner handles a case.
enum Kind {
    /// ssz-specs; `Err` if the fixture did not load, reported when the trial runs, where a
    /// skip entry can reach it.
    SszGeneric(Result<(), String>),
    SszStatic,
    Bls,
    Kzg,
    Networking,
    Operations,
    Sanity,
    Shuffling,
    EpochProcessing,
    Finality,
    Rewards,
    Random,
}

/// The runner for a case, or `None` if nothing in this crate runs it.
///
/// Planning reads (the ssz-specs fixture, opened to learn its type) go to a throwaway record:
/// only reads made while a trial runs count as coverage, so a run that executes no trial
/// (`--bench`, a filter) cannot look covered.
fn kind(case: &Case) -> Option<Kind> {
    let k = &case.key;
    match (k.source.as_str(), k.runner.as_str()) {
        ("ssz-specs", "ssz") => {
            let planning = Reads::default();
            let loaded =
                ssz_generic::fixture_path(case).and_then(|p| ssz_generic::load(&planning, p));
            match loaded {
                Ok(f) if !ssz_generic::supported(&k.handler, &f.type_name) => None,
                Ok(_) => Some(Kind::SszGeneric(Ok(()))),
                Err(e) => Some(Kind::SszGeneric(Err(e))),
            }
        }
        ("consensus-specs", "ssz_static")
            if ssz_static::supported(&k.fork, &k.preset, &k.handler) =>
        {
            Some(Kind::SszStatic)
        }
        (_, "bls") if bls::handler_runs(&k.handler) == Ok(true) => Some(Kind::Bls),
        ("cryptography-specs", "kzg") if kzg::handler_runs(&k.handler) == Ok(true) => {
            Some(Kind::Kzg)
        }
        ("consensus-specs", "networking") if networking::supported(&k.fork, &k.handler) => {
            Some(Kind::Networking)
        }
        ("consensus-specs", "operations")
            if operations::supported(&k.fork, &k.preset, &k.handler) =>
        {
            Some(Kind::Operations)
        }
        ("consensus-specs", "sanity") if sanity::supported(&k.fork, &k.preset, &k.handler) => {
            Some(Kind::Sanity)
        }
        ("consensus-specs", "shuffling")
            if shuffling::supported(&k.fork, &k.preset, &k.handler) =>
        {
            Some(Kind::Shuffling)
        }
        ("consensus-specs", "epoch_processing")
            if epoch_processing::supported(&k.fork, &k.preset, &k.handler) =>
        {
            Some(Kind::EpochProcessing)
        }
        ("consensus-specs", "finality") if finality::supported(&k.fork, &k.preset, &k.handler) => {
            Some(Kind::Finality)
        }
        ("consensus-specs", "rewards") if rewards::supported(&k.fork, &k.preset, &k.handler) => {
            Some(Kind::Rewards)
        }
        ("consensus-specs", "random") if random::supported(&k.fork, &k.preset, &k.handler) => {
            Some(Kind::Random)
        }
        _ => None,
    }
}

impl Kind {
    fn run(&self, reads: &Reads, case: &Case) -> Result<(), String> {
        let handler = &case.key.handler;
        match self {
            Kind::SszGeneric(Err(e)) => Err(e.clone()),
            Kind::SszGeneric(Ok(())) => ssz_generic::run(reads, case),
            Kind::SszStatic => {
                consensus_manifest(reads, case)?;
                ssz_static::run(reads, case)
            }
            Kind::Bls => {
                consensus_manifest(reads, case)?;
                let name = match case.key.source.as_str() {
                    "bls12-381-tests" => format!("{}.yaml", case.key.case),
                    _ => "data.yaml".to_owned(),
                };
                bls::run(reads, handler, data(case, &name)?)
            }
            Kind::Kzg => kzg::run(reads, handler, data(case, "data.yaml")?),
            Kind::Networking => {
                consensus_manifest(reads, case)?;
                networking::run(reads, handler, data(case, "meta.yaml")?)
            }
            Kind::Operations => {
                consensus_manifest(reads, case)?;
                operations::run(reads, case)
            }
            Kind::Sanity => {
                consensus_manifest(reads, case)?;
                sanity::run(reads, case)
            }
            Kind::Shuffling => {
                consensus_manifest(reads, case)?;
                shuffling::run(reads, &case.key.preset, data(case, "mapping.yaml")?)
            }
            Kind::EpochProcessing => {
                consensus_manifest(reads, case)?;
                epoch_processing::run(reads, case)
            }
            Kind::Finality => {
                consensus_manifest(reads, case)?;
                finality::run(reads, case)
            }
            Kind::Rewards => {
                consensus_manifest(reads, case)?;
                rewards::run(reads, case)
            }
            Kind::Random => {
                consensus_manifest(reads, case)?;
                random::run(reads, case)
            }
        }
    }
}

fn data<'c>(case: &'c Case, name: &str) -> Result<&'c Path, String> {
    case.file(name).ok_or_else(|| format!("case has no {name}"))
}

/// consensus-spec-tests cases carry a `manifest.yaml`; it must name the case's directory.
fn consensus_manifest(reads: &Reads, case: &Case) -> Result<(), String> {
    if case.key.source != "consensus-specs" {
        return Ok(());
    }
    fixture::check_manifest(reads, data(case, "manifest.yaml")?, &case.key)
}

/// The libtest name of a case.
pub fn trial_name(k: &CaseKey) -> String {
    let case = k.case.replace('/', "::");
    match k.source.as_str() {
        "ssz-specs" => format!("ssz_generic::{}::{case}", k.handler),
        "consensus-specs" => format!(
            "{}_{}_{}::{}::{case}",
            k.fork, k.runner, k.preset, k.handler
        ),
        "bls12-381-tests" => format!("bls12_381::{}::{case}", k.handler),
        "comptests" => format!(
            "comptests_{}_{}_{}::{}::{case}",
            k.fork, k.runner, k.preset, k.handler
        ),
        other => format!(
            "{}_{}::{}::{case}",
            other.replace('-', "_"),
            k.runner,
            k.handler
        ),
    }
}

/// `<root>/<source>/<tag>/<stem>` of a set, for callers that plant or inspect files.
pub fn set_dir(root: &Path, tags: &HashMap<String, String>, set: &VectorSet) -> Option<PathBuf> {
    let tag = tags.get(set.source)?;
    Some(
        root.join(set.source)
            .join(tag)
            .join(set.stem.replace("{tag}", tag)),
    )
}
