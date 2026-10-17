//! Skip-list rules (schema: `testing/skip.toml.example`) and per-case disposition.
//!
//! The run fails when a case is neither run nor skipped, when a skip entry has
//! expired, or when a skip entry matches no file of a scanned set (stale).
//!
//! An entry without `file` skips whole cases. An entry with `file` skips nothing: it only
//! excuses the matching files of a case from the coverage guard ([`crate::coverage`]).

use serde::Deserialize;
use std::fmt;
use std::path::PathBuf;

/// Vector sources a skip entry may name (`source` is literal, not a glob). `comptests` is the
/// consensus-specs `comptests.tar.gz` archive, keyed apart so its entries never reach the
/// general/minimal/mainnet trees.
pub const KNOWN_SOURCES: [&str; 5] = [
    "consensus-specs",
    "ssz-specs",
    "cryptography-specs",
    "bls12-381-tests",
    "comptests",
];

/// Presets a skip entry may name besides `*`; `none` is the preset of sources without presets.
pub const KNOWN_PRESETS: [&str; 4] = ["general", "minimal", "mainnet", "none"];

/// The presets of source `comptests`: the compliance vectors sit under `tests/minimal`, the
/// Python sources under `tests/{core,formats,generators}`.
pub const COMPTESTS_PRESETS: [&str; 4] = ["minimal", "core", "formats", "generators"];

/// The presets valid for `source`.
pub fn known_presets(source: &str) -> &'static [&'static str] {
    match source {
        "comptests" => &COMPTESTS_PRESETS,
        _ => &KNOWN_PRESETS,
    }
}

/// What one scanned vector set can contain: its key source and the presets, forks and
/// runners its keys can take (`*` = any). A skip entry is checked for staleness only if some
/// scanned set's scope could hold a case it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    /// Key `source`.
    pub source: &'static str,
    /// Possible `preset` values.
    pub presets: &'static [&'static str],
    /// Possible `fork` values.
    pub forks: &'static [&'static str],
    /// Possible `runner` values.
    pub runners: &'static [&'static str],
}

/// Whether `pattern` can match one of `values`; a `*` value stands for anything.
fn could_match(pattern: &str, values: &[&str]) -> bool {
    values.iter().any(|v| *v == "*" || glob(pattern, v))
}

/// Identifies one test case in the vector trees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseKey {
    /// `consensus-specs` or `ssz-specs`.
    pub source: String,
    /// Fork directory, or `none` for ssz-specs.
    pub fork: String,
    /// Preset directory, or `none` for ssz-specs.
    pub preset: String,
    /// Runner, e.g. `ssz_static`, or `ssz` for ssz-specs.
    pub runner: String,
    /// Handler, e.g. `BeaconState` or `test_progressive_types`.
    pub handler: String,
    /// Case path below the handler, e.g. `ssz_random/case_0`.
    pub case: String,
}

impl fmt::Display for CaseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}::{}::{}::{}::{}::{}",
            self.source, self.fork, self.preset, self.runner, self.handler, self.case
        )
    }
}

/// One file of a case, as found by the coverage walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseFile {
    /// Absolute (or root-joined) path, as handlers open it.
    pub path: PathBuf,
    /// Path inside the case, e.g. `roots.yaml`; what a skip entry's `file` glob matches.
    pub name: String,
}

/// A case and every file the vector tree holds for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    /// Skip-list key.
    pub key: CaseKey,
    /// Files belonging to the case; empty for a case directory without files.
    pub files: Vec<CaseFile>,
}

impl Case {
    /// The path of the file named `name` inside the case.
    pub fn file(&self, name: &str) -> Option<&std::path::Path> {
        self.files
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.path.as_path())
    }
}

/// A calendar date (`YYYY-MM-DD`), compared lexicographically by (y, m, d).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    year: u32,
    month: u32,
    day: u32,
}

impl Date {
    /// Parses `YYYY-MM-DD`.
    pub fn parse(s: &str) -> Option<Self> {
        let mut it = s.split('-');
        let (y, m, d) = (it.next()?, it.next()?, it.next()?);
        if it.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
            return None;
        }
        let date = Self {
            year: y.parse().ok()?,
            month: m.parse().ok()?,
            day: d.parse().ok()?,
        };
        ((1..=12).contains(&date.month) && (1..=31).contains(&date.day)).then_some(date)
    }

    /// Today's UTC date from the system clock.
    pub fn today_utc() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::from_days_since_epoch((secs / 86_400) as i64)
    }

    /// Howard Hinnant's civil-from-days algorithm.
    fn from_days_since_epoch(z: i64) -> Self {
        let z = z + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = (yoe + era * 400 + i64::from(month <= 2)) as u32;
        Self { year, month, day }
    }
}

/// Errors from loading the skip list or planning cases.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PlanError {
    /// The skip file is not valid TOML of the expected shape.
    #[error("invalid skip file: {0}")]
    Parse(String),
    /// A required field is empty or malformed.
    #[error("skip entry #{index}: {problem}")]
    Invalid {
        /// Zero-based entry index in the file.
        index: usize,
        /// What is wrong.
        problem: String,
    },
    /// An entry's `expires` date is before today.
    #[error("skip entry #{index} ({summary}) expired on {expires}")]
    Expired {
        /// Zero-based entry index.
        index: usize,
        /// `runner/handler/case` of the entry.
        summary: String,
        /// The configured expiry.
        expires: String,
    },
    /// An entry matches no file of the discovered cases.
    #[error("skip entry #{index} ({summary}) matches no vector file (stale)")]
    Stale {
        /// Zero-based entry index.
        index: usize,
        /// `runner/handler/case` of the entry.
        summary: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    source: String,
    fork: String,
    preset: String,
    runner: String,
    handler: String,
    case: Option<String>,
    file: Option<String>,
    reason: String,
    owner: String,
    issue: String,
    expires: String,
}

#[derive(Debug, Deserialize)]
struct RawFile {
    #[serde(default)]
    skip: Vec<RawEntry>,
}

#[derive(Debug)]
struct Entry {
    raw: RawEntry,
    expires: Date,
}

impl Entry {
    /// Whether a set of scope `s` could hold a case this entry matches.
    fn in_scope(&self, s: &Scope) -> bool {
        let r = &self.raw;
        glob(&r.source, s.source)
            && could_match(&r.preset, s.presets)
            && could_match(&r.fork, s.forks)
            && could_match(&r.runner, s.runners)
    }

    fn matches_case(&self, k: &CaseKey) -> bool {
        let r = &self.raw;
        glob(&r.source, &k.source)
            && glob(&r.fork, &k.fork)
            && glob(&r.preset, &k.preset)
            && glob(&r.runner, &k.runner)
            && glob(&r.handler, &k.handler)
            && r.case.as_deref().is_none_or(|c| glob(c, &k.case))
    }

    fn matches_file(&self, k: &CaseKey, name: &str) -> bool {
        self.raw
            .file
            .as_deref()
            .is_some_and(|f| glob(f, name) && self.matches_case(k))
    }

    /// Whether a file in `cases` matches: a file of a matching case for case entries, a
    /// matching file for file entries. The `files` check on case entries is a defensive
    /// guard: [`crate::coverage::walk`] only creates a case for a file, so it fires only on
    /// cases built by hand.
    fn matches_any(&self, cases: &[Case]) -> bool {
        match self.raw.file {
            None => cases
                .iter()
                .any(|c| !c.files.is_empty() && self.matches_case(&c.key)),
            Some(_) => cases
                .iter()
                .any(|c| c.files.iter().any(|f| self.matches_file(&c.key, &f.name))),
        }
    }

    fn summary(&self) -> String {
        let r = &self.raw;
        let mut s = format!(
            "{}/{}/{}/{}/{}/{}",
            r.source,
            r.fork,
            r.preset,
            r.runner,
            r.handler,
            r.case.as_deref().unwrap_or("*")
        );
        if let Some(f) = &r.file {
            s.push_str(&format!(" file {f}"));
        }
        s
    }
}

/// The bookkeeping fields of one skip entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryInfo<'a> {
    /// Why it is skipped.
    pub reason: &'a str,
    /// Who is responsible for it.
    pub owner: &'a str,
    /// The plan item that removes it, or `none`.
    pub issue: &'a str,
    /// Last day the entry is valid.
    pub expires: Date,
}

impl<'a> From<&'a Entry> for EntryInfo<'a> {
    fn from(e: &'a Entry) -> Self {
        Self {
            reason: &e.raw.reason,
            owner: &e.raw.owner,
            issue: &e.raw.issue,
            expires: e.expires,
        }
    }
}

/// Parsed skip file; every entry has all required fields and a valid date.
#[derive(Debug)]
pub struct SkipList {
    entries: Vec<Entry>,
}

impl SkipList {
    /// Parses a skip file in the `testing/skip.toml.example` schema.
    pub fn parse(text: &str) -> Result<Self, PlanError> {
        let file: RawFile = toml::from_str(text).map_err(|e| PlanError::Parse(e.to_string()))?;
        let entries = file
            .skip
            .into_iter()
            .enumerate()
            .map(|(index, raw)| {
                let invalid = |problem: &str| PlanError::Invalid {
                    index,
                    problem: problem.to_owned(),
                };
                for (name, v) in [
                    ("source", &raw.source),
                    ("fork", &raw.fork),
                    ("preset", &raw.preset),
                    ("runner", &raw.runner),
                    ("handler", &raw.handler),
                    ("reason", &raw.reason),
                    ("owner", &raw.owner),
                    ("issue", &raw.issue),
                ] {
                    if v.trim().is_empty() {
                        return Err(invalid(&format!("`{name}` is empty")));
                    }
                }
                if raw.file.as_deref().is_some_and(|f| f.trim().is_empty()) {
                    return Err(invalid("`file` is empty"));
                }
                if !KNOWN_SOURCES.contains(&raw.source.as_str()) {
                    return Err(invalid(&format!(
                        "`source` {:?} is not one of {KNOWN_SOURCES:?}",
                        raw.source
                    )));
                }
                let presets = known_presets(&raw.source);
                if raw.preset != "*" && !presets.contains(&raw.preset.as_str()) {
                    return Err(invalid(&format!(
                        "`preset` {:?} is neither \"*\" nor one of {presets:?} for source {:?}",
                        raw.preset, raw.source
                    )));
                }
                let expires = Date::parse(&raw.expires)
                    .ok_or_else(|| invalid("`expires` is not YYYY-MM-DD"))?;
                let entry = Entry { raw, expires };
                // An entry no set could match would never be stale-checked; a typo would
                // then silently skip nothing forever.
                if !crate::suite::SETS
                    .iter()
                    .any(|set| entry.in_scope(&set.scope))
                {
                    return Err(invalid(&format!(
                        "{} matches no vector set (no set in crates/spec-tests/src/suite.rs SETS \
                         has that source, preset, fork and runner)",
                        entry.summary()
                    )));
                }
                Ok(entry)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { entries })
    }

    /// Every entry, in file order.
    pub fn entries(&self) -> impl Iterator<Item = EntryInfo<'_>> {
        self.entries.iter().map(EntryInfo::from)
    }

    /// The first case entry (no `file`) that skips case `k`, if any.
    pub fn skipped_by(&self, k: &CaseKey) -> Option<EntryInfo<'_>> {
        self.entries
            .iter()
            .find(|e| e.raw.file.is_none() && e.matches_case(k))
            .map(EntryInfo::from)
    }

    /// Every entry whose `expires` date is before `today`. An entry is valid through its
    /// expiry day: it expires on the day after.
    pub fn expired(&self, today: Date) -> Vec<PlanError> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.expires < today)
            .map(|(index, e)| PlanError::Expired {
                index,
                summary: e.summary(),
                expires: e.raw.expires.clone(),
            })
            .collect()
    }

    /// Whether a `file` entry excuses file `name` of case `k` from the coverage guard.
    pub fn excuses(&self, k: &CaseKey, name: &str) -> bool {
        self.entries.iter().any(|e| e.matches_file(k, name))
    }
}

/// `*` matches any run of characters; everything else is literal.
fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

/// What to do with one case.
#[derive(Debug, PartialEq, Eq)]
pub enum Disposition {
    /// A handler exists and the case is not skipped.
    Run,
    /// Matched by a skip entry; carries its reason.
    Skip(String),
    /// Neither runnable nor skipped: a coverage failure.
    Unaccounted,
}

/// Decides each case's disposition. A case entry wins over a handler so known
/// failures can be parked explicitly; `file` entries never change a disposition.
/// Fails on expired or stale entries.
///
/// An entry is checked for staleness only when one of `scopes` (the scanned sets) could hold
/// a case it matches: mainnet or cryptography-specs entries are not stale on a run that did
/// not extract those sets, and the `preset = "*"` state-transition entries are not stale on
/// a run of `general` alone (which holds only `altair/bls`). Pass every case of every set
/// that was scanned.
pub fn plan<'a>(
    cases: &'a [Case],
    has_handler: impl Fn(&CaseKey) -> bool,
    skips: &SkipList,
    today: Date,
    scopes: &[Scope],
) -> Result<Vec<(&'a Case, Disposition)>, Vec<PlanError>> {
    let mut errors = skips.expired(today);
    for (index, e) in skips.entries.iter().enumerate() {
        let in_scope = scopes.iter().any(|s| e.in_scope(s));
        if in_scope && !e.matches_any(cases) {
            errors.push(PlanError::Stale {
                index,
                summary: e.summary(),
            });
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(cases
        .iter()
        .map(|c| {
            let k = &c.key;
            let d = match skips.skipped_by(k) {
                Some(e) => Disposition::Skip(e.reason.to_owned()),
                None if has_handler(k) => Disposition::Run,
                None => Disposition::Unaccounted,
            };
            (c, d)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn key(handler: &str, case: &str) -> CaseKey {
        CaseKey {
            source: "consensus-specs".into(),
            fork: "gloas".into(),
            preset: "minimal".into(),
            runner: "ssz_static".into(),
            handler: handler.into(),
            case: case.into(),
        }
    }

    fn entry(handler: &str, case: Option<&str>, expires: &str) -> String {
        let case = case
            .map(|c| format!("case = \"{c}\"\n"))
            .unwrap_or_default();
        format!(
            "[[skip]]\nsource = \"consensus-specs\"\nfork = \"gloas\"\npreset = \"*\"\n\
             runner = \"ssz_static\"\nhandler = \"{handler}\"\n{case}reason = \"r-{handler}\"\n\
             owner = \"ian\"\nissue = \"TBD\"\nexpires = \"{expires}\"\n"
        )
    }

    const SCOPES: [Scope; 1] = [Scope {
        source: "consensus-specs",
        presets: &["minimal"],
        forks: &["*"],
        runners: &["*"],
    }];

    fn today() -> Date {
        Date::parse("2026-10-15").unwrap()
    }

    #[test]
    fn classifies_run_skip_and_unaccounted() {
        let skips = SkipList::parse(&entry("BeaconState", None, "2026-12-31")).unwrap();
        let cases = [
            case("BeaconState", "ssz_random/case_0", &["x"]),
            case("BeaconStateX", "ssz_one/case_0", &["x"]),
            case("Checkpoint", "ssz_one/case_0", &["x"]),
        ];
        let got = plan(
            &cases,
            |k| k.handler == "Checkpoint",
            &skips,
            today(),
            &SCOPES,
        )
        .unwrap();
        let d: Vec<_> = got.into_iter().map(|(_, d)| d).collect();
        assert_eq!(
            d,
            vec![
                Disposition::Skip("r-BeaconState".into()),
                Disposition::Unaccounted,
                Disposition::Run,
            ]
        );
    }

    #[test]
    fn case_glob_narrows_the_skip() {
        let skips = SkipList::parse(&entry("Foo", Some("ssz_random/*"), "2026-12-31")).unwrap();
        let cases = [
            case("Foo", "ssz_random/case_1", &["x"]),
            case("Foo", "ssz_one/case_1", &["x"]),
        ];
        let got = plan(&cases, |_| true, &skips, today(), &SCOPES).unwrap();
        assert_eq!(got[0].1, Disposition::Skip("r-Foo".into()));
        assert_eq!(got[1].1, Disposition::Run);
    }

    #[test]
    fn skip_expired_fails() {
        // (today, yesterday), across a month and a year boundary; the clock is injected.
        for (today, yesterday) in [
            ("2026-10-15", "2026-10-14"),
            ("2026-11-01", "2026-10-31"),
            ("2027-01-01", "2026-12-31"),
        ] {
            let day = Date::parse(today).unwrap();
            let skips = SkipList::parse(&entry("Foo", None, yesterday)).unwrap();
            assert!(
                matches!(
                    skips.expired(day).as_slice(),
                    [PlanError::Expired { index: 0, expires, .. }] if expires == yesterday
                ),
                "{yesterday} must be expired on {today}"
            );
            let cases = [case("Foo", "a/b", &["x"])];
            let errs = plan(&cases, |_| true, &skips, day, &SCOPES).unwrap_err();
            assert!(matches!(errs.as_slice(), [PlanError::Expired { .. }]));

            // The expiry day itself is inclusive.
            let skips = SkipList::parse(&entry("Foo", None, today)).unwrap();
            assert!(skips.expired(day).is_empty(), "{today} expires today");
            assert!(plan(&cases, |_| true, &skips, day, &SCOPES).is_ok());
        }
    }

    #[test]
    fn skip_entry_matches_files() {
        let skips = SkipList::parse(&entry("Foo", None, "2026-12-31")).unwrap();
        let held = [case("Foo", "a/b", &["x"])];
        assert!(plan(&held, |_| true, &skips, today(), &SCOPES).is_ok());
        // A case entry must match a case that holds a file, not just a key.
        for cases in [[case("Bar", "a/b", &["x"])], [case("Foo", "a/b", &[])]] {
            let errs = plan(&cases, |_| true, &skips, today(), &SCOPES).unwrap_err();
            assert!(
                matches!(
                    errs.as_slice(),
                    [PlanError::Stale { index: 0, summary }]
                        if summary == "consensus-specs/gloas/*/ssz_static/Foo/*"
                ),
                "{errs:?}"
            );
        }
    }

    #[test]
    fn skip_entry_requires_reason() {
        let full = entry("Foo", None, "2026-12-31");
        assert!(SkipList::parse(&full).is_ok());
        for field in ["reason", "owner", "issue", "expires"] {
            let line = full
                .lines()
                .find(|l| l.starts_with(&format!("{field} = ")))
                .unwrap();
            let missing = full.replace(&format!("{line}\n"), "");
            match SkipList::parse(&missing) {
                Err(PlanError::Parse(msg)) => {
                    assert!(msg.contains(&format!("missing field `{field}`")), "{msg}")
                }
                other => panic!("without {field}: {other:?}"),
            }
            let blank = full.replace(line, &format!("{field} = \" \""));
            assert!(
                matches!(
                    SkipList::parse(&blank),
                    Err(PlanError::Invalid { index: 0, .. })
                ),
                "blank {field}"
            );
        }
    }

    #[test]
    fn rejects_empty_required_field_and_bad_date() {
        let no_owner = entry("Foo", None, "2026-12-31").replace("owner = \"ian\"", "owner = \"\"");
        assert!(matches!(
            SkipList::parse(&no_owner),
            Err(PlanError::Invalid { index: 0, .. })
        ));
        assert!(matches!(
            SkipList::parse(&entry("Foo", None, "31-12-2026")),
            Err(PlanError::Invalid { index: 0, .. })
        ));
    }

    #[test]
    fn rejects_unknown_field() {
        let text = entry("Foo", None, "2026-12-31") + "bogus = 1\n";
        assert!(matches!(SkipList::parse(&text), Err(PlanError::Parse(_))));
    }

    #[test]
    fn glob_matches_literals_and_wildcards() {
        assert!(glob("*", "anything"));
        assert!(glob("test_progressive_*", "test_progressive_types"));
        assert!(glob("*_ptc_*", "a_multiple_ptc_members"));
        assert!(!glob("*_ptc_*", "a_not_ptc"));
        assert!(!glob("BeaconState", "BeaconStateX"));
    }

    fn case(handler: &str, case: &str, files: &[&str]) -> Case {
        let key = key(handler, case);
        Case {
            files: files
                .iter()
                .map(|f| CaseFile {
                    path: PathBuf::from(format!("/v/{handler}/{case}/{f}")),
                    name: (*f).into(),
                })
                .collect(),
            key,
        }
    }

    #[test]
    fn file_entry_excuses_files_but_does_not_skip_the_case() {
        let text =
            entry("Foo", None, "2026-12-31").replace("reason", "file = \"value.yaml\"\nreason");
        let skips = SkipList::parse(&text).unwrap();
        let cases = [case("Foo", "s/c", &["roots.yaml", "value.yaml"])];
        let got = plan(&cases, |_| true, &skips, today(), &SCOPES).unwrap();
        assert_eq!(got[0].1, Disposition::Run);
        assert!(skips.excuses(&cases[0].key, "value.yaml"));
        assert!(!skips.excuses(&cases[0].key, "roots.yaml"));
    }

    #[test]
    fn file_entry_matching_no_file_is_stale() {
        let text =
            entry("Foo", None, "2026-12-31").replace("reason", "file = \"gone.yaml\"\nreason");
        let skips = SkipList::parse(&text).unwrap();
        let errs = plan(
            &[case("Foo", "s/c", &["roots.yaml"])],
            |_| true,
            &skips,
            today(),
            &SCOPES,
        )
        .unwrap_err();
        assert!(matches!(
            errs.as_slice(),
            [PlanError::Stale { index: 0, .. }]
        ));
    }

    #[test]
    fn entry_for_an_unscanned_source_or_preset_is_not_stale() {
        let crypto = entry("compute_kzg_proof", None, "2026-12-31")
            .replace("\"consensus-specs\"", "\"cryptography-specs\"")
            .replace("\"gloas\"", "\"none\"")
            .replace("\"ssz_static\"", "\"kzg\"");
        let mainnet = entry("Foo", None, "2026-12-31").replace("\"*\"", "\"mainnet\"");
        for text in [crypto, mainnet] {
            let skips = SkipList::parse(&text).unwrap();
            assert!(plan(
                &[case("Foo", "s/c", &["a"])],
                |_| true,
                &skips,
                today(),
                &SCOPES
            )
            .is_ok());
        }
    }

    #[test]
    fn scope_limits_the_stale_check_to_what_a_scanned_set_can_hold() {
        // `general` holds only altair/bls: a phase0 or ssz_static entry is out of its scope.
        const GENERAL: [Scope; 1] = [Scope {
            source: "consensus-specs",
            presets: &["general"],
            forks: &["altair"],
            runners: &["bls"],
        }];
        let general_case = |handler: &str| Case {
            key: CaseKey {
                preset: "general".into(),
                fork: "altair".into(),
                runner: "bls".into(),
                ..key(handler, "bls/c")
            },
            files: Vec::new(),
        };
        let cases = [general_case("eth_aggregate_pubkeys")];
        let phase0 = entry("Foo", None, "2026-12-31").replace("\"gloas\"", "\"phase0\"");
        let ssz_static = entry("Foo", None, "2026-12-31");
        for text in [phase0, ssz_static] {
            let skips = SkipList::parse(&text).unwrap();
            assert!(
                plan(&cases, |_| true, &skips, today(), &GENERAL).is_ok(),
                "{text}"
            );
        }
        let bls_gone = entry("Gone", None, "2026-12-31")
            .replace("\"gloas\"", "\"*\"")
            .replace("\"ssz_static\"", "\"bls\"");
        let skips = SkipList::parse(&bls_gone).unwrap();
        let errs = plan(&cases, |_| true, &skips, today(), &GENERAL).unwrap_err();
        assert!(matches!(
            errs.as_slice(),
            [PlanError::Stale { index: 0, .. }]
        ));
    }

    #[test]
    fn comptests_presets_are_valid_for_comptests_only() {
        let core = |source: &str| {
            entry("Foo", None, "2026-12-31")
                .replace("\"consensus-specs\"", &format!("\"{source}\""))
                .replace("preset = \"*\"", "preset = \"core\"")
        };
        assert!(SkipList::parse(&core("comptests")).is_ok());
        assert!(matches!(
            SkipList::parse(&core("consensus-specs")),
            Err(PlanError::Invalid { index: 0, .. })
        ));
    }

    #[test]
    fn rejects_entries_outside_every_vector_set() {
        let kzg = |runner: &str| {
            entry("compute_cells", None, "2026-12-31")
                .replace("\"consensus-specs\"", "\"cryptography-specs\"")
                .replace("\"gloas\"", "\"none\"")
                .replace("\"ssz_static\"", &format!("\"{runner}\""))
        };
        assert!(SkipList::parse(&kzg("kzg")).is_ok());
        assert!(SkipList::parse(&kzg("k*")).is_ok());
        match SkipList::parse(&kzg("kgz")) {
            Err(PlanError::Invalid { index: 0, problem }) => assert!(
                problem.contains("cryptography-specs/none/*/kgz/compute_cells")
                    && problem.contains("no vector set"),
                "{problem}"
            ),
            other => panic!("{other:?}"),
        }
        // `general` holds only altair/bls, minimal any fork: a phase0 entry fits minimal.
        let phase0 = entry("Foo", None, "2026-12-31").replace("\"gloas\"", "\"phase0\"");
        assert!(SkipList::parse(&phase0).is_ok());
        let general_fork_choice = entry("Foo", None, "2026-12-31")
            .replace("preset = \"*\"", "preset = \"general\"")
            .replace("\"ssz_static\"", "\"fork_choice\"");
        assert!(SkipList::parse(&general_fork_choice).is_err());
    }

    #[test]
    fn rejects_unknown_source_and_preset() {
        let source =
            entry("Foo", None, "2026-12-31").replace("\"consensus-specs\"", "\"consensus-spec\"");
        let preset = entry("Foo", None, "2026-12-31").replace("\"*\"", "\"minmal\"");
        let empty_file = entry("Foo", None, "2026-12-31").replace("reason", "file = \" \"\nreason");
        for text in [source, preset, empty_file] {
            assert!(
                matches!(
                    SkipList::parse(&text),
                    Err(PlanError::Invalid { index: 0, .. })
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn committed_skip_files_parse() {
        for rel in ["testing/skip.toml", "testing/skip.toml.example"] {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../").to_owned() + rel;
            let text = std::fs::read_to_string(&path).unwrap();
            if let Err(e) = SkipList::parse(&text) {
                panic!("{rel}: {e}");
            }
        }
    }

    #[test]
    fn civil_date_from_epoch_days() {
        assert_eq!(
            Date::from_days_since_epoch(0),
            Date::parse("1970-01-01").unwrap()
        );
        assert_eq!(
            Date::from_days_since_epoch(20_741),
            Date::parse("2026-10-15").unwrap()
        );
    }
}
