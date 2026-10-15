//! Skip-list rules (schema: `testing/skip.toml.example`) and per-case disposition.
//!
//! The run fails when a case is neither run nor skipped, when a skip entry has
//! expired, or when a skip entry matches no case (stale).

use serde::Deserialize;
use std::fmt;

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
    /// An entry matches no discovered case.
    #[error("skip entry #{index} ({summary}) matches no case (stale)")]
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
    fn matches(&self, k: &CaseKey) -> bool {
        let r = &self.raw;
        glob(&r.source, &k.source)
            && glob(&r.fork, &k.fork)
            && glob(&r.preset, &k.preset)
            && glob(&r.runner, &k.runner)
            && glob(&r.handler, &k.handler)
            && r.case.as_deref().is_none_or(|c| glob(c, &k.case))
    }

    fn summary(&self) -> String {
        let r = &self.raw;
        format!(
            "{}/{}/{}/{}/{}/{}",
            r.source,
            r.fork,
            r.preset,
            r.runner,
            r.handler,
            r.case.as_deref().unwrap_or("*")
        )
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
                let expires = Date::parse(&raw.expires)
                    .ok_or_else(|| invalid("`expires` is not YYYY-MM-DD"))?;
                Ok(Entry { raw, expires })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { entries })
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

/// Decides each case's disposition. A skip entry wins over a handler so known
/// failures can be parked explicitly. Fails on expired or stale entries.
///
/// Entries are checked for staleness only against `cases`, so pass every case of
/// every source the skip file refers to.
pub fn plan<'a>(
    cases: &'a [CaseKey],
    has_handler: impl Fn(&CaseKey) -> bool,
    skips: &SkipList,
    today: Date,
) -> Result<Vec<(&'a CaseKey, Disposition)>, Vec<PlanError>> {
    let mut errors = Vec::new();
    for (index, e) in skips.entries.iter().enumerate() {
        if e.expires < today {
            errors.push(PlanError::Expired {
                index,
                summary: e.summary(),
                expires: e.raw.expires.clone(),
            });
        }
        if !cases.iter().any(|k| e.matches(k)) {
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
        .map(|k| {
            let d = match skips.entries.iter().find(|e| e.matches(k)) {
                Some(e) => Disposition::Skip(e.raw.reason.clone()),
                None if has_handler(k) => Disposition::Run,
                None => Disposition::Unaccounted,
            };
            (k, d)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn today() -> Date {
        Date::parse("2026-10-15").unwrap()
    }

    #[test]
    fn classifies_run_skip_and_unaccounted() {
        let skips = SkipList::parse(&entry("BeaconState", None, "2026-12-31")).unwrap();
        let cases = [
            key("BeaconState", "ssz_random/case_0"),
            key("BeaconStateX", "ssz_one/case_0"),
            key("Checkpoint", "ssz_one/case_0"),
        ];
        let got = plan(&cases, |k| k.handler == "Checkpoint", &skips, today()).unwrap();
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
            key("Foo", "ssz_random/case_1"),
            key("Foo", "ssz_one/case_1"),
        ];
        let got = plan(&cases, |_| true, &skips, today()).unwrap();
        assert_eq!(got[0].1, Disposition::Skip("r-Foo".into()));
        assert_eq!(got[1].1, Disposition::Run);
    }

    #[test]
    fn expired_entry_fails_the_run() {
        let skips = SkipList::parse(&entry("Foo", None, "2026-10-14")).unwrap();
        let errs = plan(&[key("Foo", "a/b")], |_| true, &skips, today()).unwrap_err();
        assert!(matches!(
            errs.as_slice(),
            [PlanError::Expired { index: 0, .. }]
        ));
    }

    #[test]
    fn entry_expiring_today_is_still_valid() {
        let skips = SkipList::parse(&entry("Foo", None, "2026-10-15")).unwrap();
        assert!(plan(&[key("Foo", "a/b")], |_| true, &skips, today()).is_ok());
    }

    #[test]
    fn stale_entry_fails_the_run() {
        let skips = SkipList::parse(&entry("Gone", None, "2026-12-31")).unwrap();
        let errs = plan(&[key("Foo", "a/b")], |_| true, &skips, today()).unwrap_err();
        assert!(matches!(
            errs.as_slice(),
            [PlanError::Stale { index: 0, .. }]
        ));
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
