//! The anchor-fetch run log: one JSON object per line, appended to `<out>/run.log`.
//!
//! Every line has `ts` (UTC, RFC 3339) and `event`. A run starts with a `start` line and names
//! both providers in `provider` lines (`role` `a`/`b`, `name`, `operator`, `url`) before any
//! request; then come the candidate root, each check's result, and `anchor` or `abort`.
//! [`verify`] rejects a run (the lines after the last `start`) that does not name both
//! providers, so an anchor never comes without a record of where it came from.

use crate::checkpoint::fetch::AnchorError;
use serde_json::{Map, Value};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// The provider roles a run must name.
const ROLES: [&str; 2] = ["a", "b"];
/// The fields every provider line must carry, non-empty.
const PROVIDER_FIELDS: [&str; 3] = ["name", "operator", "url"];

/// An open run log.
#[derive(Debug)]
pub struct RunLog {
    file: File,
    echo: bool,
}

impl RunLog {
    /// Opens `path` for appending (created with mode 0600). With `echo`, every line is also
    /// written to stderr.
    pub fn open(path: &Path, echo: bool) -> io::Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        Ok(Self {
            file: options.open(path)?,
            echo,
        })
    }

    /// Appends one `event` line with `fields` (a JSON object; anything else is logged under
    /// `value`), and flushes it.
    pub fn event(&mut self, event: &str, fields: Value) -> io::Result<()> {
        let mut line = Map::new();
        line.insert("ts".into(), Value::String(rfc3339_utc(SystemTime::now())));
        line.insert("event".into(), Value::String(event.into()));
        match fields {
            Value::Object(map) => line.extend(map),
            Value::Null => {}
            other => {
                line.insert("value".into(), other);
            }
        }
        let mut text = Value::Object(line).to_string();
        text.push('\n');
        self.file.write_all(text.as_bytes())?;
        self.file.flush()?;
        if self.echo {
            eprint!("{text}");
        }
        Ok(())
    }
}

/// Why a run log fails [`verify`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RunLogError {
    /// The log has no `start` line.
    #[error("no run in the log (no start line)")]
    NoRun,
    /// A line is not a JSON object with an `event`.
    #[error("line {line} is not a run-log JSON object")]
    BadLine {
        /// 1-based line number.
        line: usize,
    },
    /// The last run names no provider in this role.
    #[error("the last run names no provider {role}")]
    MissingProvider {
        /// `a` or `b`.
        role: &'static str,
    },
    /// The last run names the provider in this role twice.
    #[error("the last run names provider {role} twice")]
    DuplicateProvider {
        /// `a` or `b`.
        role: &'static str,
    },
    /// A provider line lacks a field, or has it empty.
    #[error("provider {role} has no {field}")]
    MissingField {
        /// `a` or `b`.
        role: &'static str,
        /// `name`, `operator` or `url`.
        field: &'static str,
    },
}

/// Checks that the last run in `text` names both providers with their name, operator and URL.
pub fn verify(text: &str) -> Result<(), RunLogError> {
    let mut lines = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        if raw.trim().is_empty() {
            continue;
        }
        let value: Value =
            serde_json::from_str(raw).map_err(|_| RunLogError::BadLine { line: i + 1 })?;
        if value.get("event").and_then(Value::as_str).is_none() {
            return Err(RunLogError::BadLine { line: i + 1 });
        }
        lines.push(value);
    }
    let start = lines
        .iter()
        .rposition(|l| l["event"] == "start")
        .ok_or(RunLogError::NoRun)?;
    let run = &lines[start..];
    for role in ROLES {
        let mut named = run
            .iter()
            .filter(|l| l["event"] == "provider" && l["role"] == role);
        let line = named.next().ok_or(RunLogError::MissingProvider { role })?;
        if named.next().is_some() {
            return Err(RunLogError::DuplicateProvider { role });
        }
        for field in PROVIDER_FIELDS {
            match line.get(field).and_then(Value::as_str) {
                Some(v) if !v.trim().is_empty() => {}
                _ => return Err(RunLogError::MissingField { role, field }),
            }
        }
    }
    Ok(())
}

/// [`verify`] on the file at `path`.
pub fn verify_file(path: &Path) -> Result<(), AnchorError> {
    let text = std::fs::read_to_string(path).map_err(|source| AnchorError::Io {
        context: format!("read {}", path.display()),
        source,
    })?;
    Ok(verify(&text)?)
}

/// `t` as `YYYY-MM-DDTHH:MM:SSZ` (UTC, whole seconds; times before 1970 print as the epoch).
pub fn rfc3339_utc(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (H. Hinnant's `civil_from_days`).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn provider_line(role: &str, name: &str, operator: &str, url: &str) -> String {
        serde_json::json!({
            "ts": "2026-10-18T00:00:00Z", "event": "provider", "role": role,
            "name": name, "operator": operator, "url": url,
        })
        .to_string()
    }

    fn start() -> String {
        serde_json::json!({"ts": "2026-10-18T00:00:00Z", "event": "start"}).to_string()
    }

    fn good_run() -> String {
        [
            start(),
            provider_line("a", "alpha", "Op A", "https://a.example"),
            provider_line("b", "beta", "Op B", "https://b.example"),
        ]
        .join("\n")
    }

    #[test]
    fn accepts_a_run_that_names_both_providers() {
        assert_eq!(verify(&good_run()), Ok(()));
    }

    #[test]
    fn rejects_a_run_without_provider_lines() {
        let text = [start(), r#"{"event":"candidate"}"#.into()].join("\n");
        assert_eq!(
            verify(&text),
            Err(RunLogError::MissingProvider { role: "a" })
        );
        let only_a = [
            start(),
            provider_line("a", "alpha", "Op A", "https://a.example"),
        ]
        .join("\n");
        assert_eq!(
            verify(&only_a),
            Err(RunLogError::MissingProvider { role: "b" })
        );
    }

    #[test]
    fn rejects_empty_or_missing_provider_fields() {
        let text = [
            start(),
            provider_line("a", "alpha", "Op A", "https://a.example"),
            provider_line("b", "beta", "", "https://b.example"),
        ]
        .join("\n");
        assert_eq!(
            verify(&text),
            Err(RunLogError::MissingField {
                role: "b",
                field: "operator"
            })
        );
        let no_url = [
            start(),
            provider_line("a", "alpha", "Op A", "https://a.example"),
            r#"{"event":"provider","role":"b","name":"beta","operator":"Op B"}"#.into(),
        ]
        .join("\n");
        assert_eq!(
            verify(&no_url),
            Err(RunLogError::MissingField {
                role: "b",
                field: "url"
            })
        );
    }

    #[test]
    fn checks_only_the_last_run() {
        let text = [good_run(), start()].join("\n");
        assert_eq!(
            verify(&text),
            Err(RunLogError::MissingProvider { role: "a" })
        );
        let text = [start(), good_run()].join("\n");
        assert_eq!(verify(&text), Ok(()));
    }

    #[test]
    fn rejects_a_log_without_a_run_or_with_bad_lines() {
        assert_eq!(verify(""), Err(RunLogError::NoRun));
        let text = [good_run(), "not json".into()].join("\n");
        assert_eq!(verify(&text), Err(RunLogError::BadLine { line: 4 }));
    }

    #[test]
    fn rejects_duplicate_provider_roles() {
        let text = [
            good_run(),
            provider_line("a", "x", "X", "https://x.example"),
        ]
        .join("\n");
        assert_eq!(
            verify(&text),
            Err(RunLogError::DuplicateProvider { role: "a" })
        );
    }

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let t = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(rfc3339_utc(t), "2023-11-14T22:13:20Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(rfc3339_utc(leap), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn writes_lines_the_verifier_accepts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.log");
        let mut log = RunLog::open(&path, false).unwrap();
        log.event("start", serde_json::json!({})).unwrap();
        for (role, name) in [("a", "alpha"), ("b", "beta")] {
            log.event(
                "provider",
                serde_json::json!({"role": role, "name": name, "operator": name, "url": "u"}),
            )
            .unwrap();
        }
        drop(log);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert_eq!(verify(&text), Ok(()));
        assert!(verify_file(&path).is_ok());
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["event"], "start");
        assert!(first["ts"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn verify_file_reports_a_missing_log() {
        assert!(verify_file(Path::new("/nonexistent/run.log")).is_err());
    }
}
