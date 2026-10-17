//! CI hardening gate for GitHub Actions workflows.
//!
//! Each workflow is parsed as YAML (so quoting, flow mappings, escapes and aliases cannot
//! hide anything), and the raw text is scanned only where the YAML tree loses information:
//! version comments, and `${{` expressions inside YAML comments. Rules:
//!
//! 1. No `pull_request_target` trigger.
//! 2. Every `uses:` value, anywhere in the tree, is a local `./` action, a `docker://` image
//!    pinned by `@sha256:<64 hex>`, or `owner/repo[/path]@<40 hex>`. Each pinned value must
//!    appear verbatim on its own `uses` line, followed by a `# <version>` comment. A `uses`
//!    line is a block entry (`[- ]uses: <value>`, key optionally quoted) or a flow mapping whose
//!    first key is `uses` (`[- ]{ uses: <value> }`); any other line holding the text is ignored.
//! 3. The top-level `permissions` is exactly `contents: read`, and job-level `permissions`
//!    grant nothing above `read` (each scope `read` or `none`, or `read-all`).
//! 4. A workflow triggered by `pull_request` references no secrets: no `secrets` identifier,
//!    in any letter case, after a `${{` (to the end of the raw line, comment lines included,
//!    and to the end of each decoded string), no `secrets` identifier anywhere in a job- or
//!    step-level `if:` (GitHub evaluates it as an expression even without `${{`), and no
//!    `secrets:` key with a non-empty value.
//!
//! YAML merge keys (`<<`) are rejected because GitHub does not apply them.

use std::fmt;
use std::path::Path;
use yaml_rust2::{Yaml, YamlLoader};

/// One broken rule, reported as `ERROR <file>[:<line>]: <message>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub file: String,
    pub line: Option<usize>,
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "ERROR {}:{line}: {}", self.file, self.message),
            None => write!(f, "ERROR {}: {}", self.file, self.message),
        }
    }
}

/// Result of checking a directory: how many workflow files were read, and what is wrong.
#[derive(Debug)]
pub struct Report {
    pub files: usize,
    pub violations: Vec<Violation>,
}

/// Checks every `*.yml` / `*.yaml` file directly in `dir`. An unreadable directory or one
/// without workflow files is an error, never a pass.
pub fn check_dir(dir: &Path) -> Result<Report, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        let is_yaml = matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yml" | "yaml")
        );
        if is_yaml && path.is_file() {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        return Err(format!("no workflow files in {}", dir.display()));
    }
    paths.sort();
    let mut violations = Vec::new();
    for path in &paths {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        violations.extend(check_workflow(&name, &text));
    }
    Ok(Report {
        files: paths.len(),
        violations,
    })
}

/// Checks one workflow file's text. `name` is only used to label violations.
pub fn check_workflow(name: &str, text: &str) -> Vec<Violation> {
    let mut v = Checker {
        name,
        text,
        out: Vec::new(),
    };
    let docs = match YamlLoader::load_from_str(text) {
        Ok(docs) => docs,
        Err(e) => {
            v.error(None, format!("not valid YAML: {e}"));
            return v.out;
        }
    };
    let [doc] = docs.as_slice() else {
        v.error(None, "expected exactly one YAML document".into());
        return v.out;
    };
    if !matches!(doc, Yaml::Hash(_)) {
        v.error(None, "workflow is not a mapping".into());
        return v.out;
    }
    v.merge_keys(doc);
    let events = v.triggers(doc);
    v.uses(doc);
    v.permissions(doc);
    if events.iter().any(|e| e == "pull_request") {
        v.secrets(doc);
    }
    v.out
}

struct Checker<'a> {
    name: &'a str,
    text: &'a str,
    out: Vec<Violation>,
}

fn key<'y>(map: &'y Yaml, k: &str) -> Option<&'y Yaml> {
    match map {
        Yaml::Hash(h) => h.get(&Yaml::String(k.to_owned())),
        _ => None,
    }
}

/// Calls `f(key, value)` for every mapping entry in the tree.
fn each_entry<'y>(node: &'y Yaml, f: &mut dyn FnMut(&'y Yaml, &'y Yaml)) {
    match node {
        Yaml::Hash(h) => {
            for (k, val) in h {
                f(k, val);
                each_entry(k, f);
                each_entry(val, f);
            }
        }
        Yaml::Array(items) => items.iter().for_each(|i| each_entry(i, f)),
        _ => {}
    }
}

/// Calls `f` for every string scalar in the tree, keys included.
fn each_string<'y>(node: &'y Yaml, f: &mut dyn FnMut(&'y str)) {
    match node {
        Yaml::String(s) => f(s),
        Yaml::Hash(h) => {
            for (k, val) in h {
                each_string(k, f);
                each_string(val, f);
            }
        }
        Yaml::Array(items) => items.iter().for_each(|i| each_string(i, f)),
        _ => {}
    }
}

fn render(node: &Yaml) -> String {
    match node {
        Yaml::String(s) => s.clone(),
        Yaml::Null => "null".into(),
        Yaml::Hash(h) => {
            let parts: Vec<String> = h
                .iter()
                .map(|(k, val)| format!("{}: {}", render(k), render(val)))
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
        other => format!("{other:?}"),
    }
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `owner/repo[/path]@<40 hex>`.
fn is_sha_pinned(r: &str) -> bool {
    let Some((path, sha)) = r.rsplit_once('@') else {
        return false;
    };
    let mut parts = path.split('/');
    let owner_repo_ok = matches!((parts.next(), parts.next()), (Some(o), Some(r)) if !o.is_empty() && !r.is_empty());
    let chars_ok = path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'));
    owner_repo_ok && chars_ok && is_hex(sha, 40)
}

/// `docker://<image>@sha256:<64 hex>`.
fn is_digest_pinned(r: &str) -> bool {
    let Some(image) = r.strip_prefix("docker://") else {
        return false;
    };
    match image.rsplit_once("@sha256:") {
        Some((name, digest)) => {
            !name.is_empty() && !name.contains(char::is_whitespace) && is_hex(digest, 64)
        }
        None => false,
    }
}

/// True if a `secrets` identifier, in any letter case (GitHub matches context names
/// case-insensitively), appears anywhere in `s`: the word itself, not part of a longer
/// identifier such as `my_secrets` or `secrets-dir`.
fn mentions_secrets(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    s.match_indices("secrets").any(|(i, m)| {
        let before = s[..i].chars().next_back();
        let after = s[i + m.len()..].chars().next();
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

/// True if a `secrets` identifier appears anywhere in `s` after its first `${{`. Deliberately
/// coarse: it does not look for the closing `}}` (which may sit inside a quoted string), so
/// anything after an expression opens counts, and a false positive is preferred to a miss.
fn secrets_after_expression_open(s: &str) -> bool {
    s.find("${{")
        .is_some_and(|open| mentions_secrets(&s[open + 3..]))
}

/// Strips `["']?uses["']?\s*:\s*["']?` (the same quote on both sides of the key) from `s`.
fn strip_uses_key(s: &str) -> Option<&str> {
    let quote = s.chars().next().filter(|c| matches!(c, '"' | '\''));
    let s = match quote {
        Some(q) => s[1..].strip_prefix("uses")?.strip_prefix(q)?,
        None => s.strip_prefix("uses")?,
    };
    let s = s.trim_start_matches([' ', '\t']).strip_prefix(':')?;
    let s = s.trim_start_matches([' ', '\t']);
    Some(s.strip_prefix(['"', '\'']).unwrap_or(s))
}

/// True if `line` is a `uses` entry for `value`: `^\s*(-\s+)?["']?uses["']?\s*:\s*["']?<value>`,
/// or the same inside a flow mapping whose first key is `uses` (`- { uses: <value> }`). A
/// `run:`, `name:` or comment line that merely contains the text does not count.
fn is_uses_line_for(line: &str, value: &str) -> bool {
    let mut rest = line.trim_start_matches([' ', '\t']);
    if let Some(after_dash) = rest.strip_prefix('-') {
        if !after_dash.starts_with([' ', '\t']) {
            return false;
        }
        rest = after_dash.trim_start_matches([' ', '\t']);
    }
    if let Some(flow) = rest.strip_prefix('{') {
        rest = flow.trim_start_matches([' ', '\t']);
    }
    strip_uses_key(rest).is_some_and(|v| v.starts_with(value))
}

impl<'a> Checker<'a> {
    fn error(&mut self, line: Option<usize>, message: String) {
        self.out.push(Violation {
            file: self.name.to_owned(),
            line,
            message,
        });
    }

    /// 1-based numbers of the raw lines that contain `needle`.
    fn lines_containing(&self, needle: &str) -> Vec<(usize, &'a str)> {
        let text: &'a str = self.text;
        text.lines()
            .enumerate()
            .filter(|(_, l)| l.contains(needle))
            .map(|(i, l)| (i + 1, l))
            .collect()
    }

    fn merge_keys(&mut self, doc: &Yaml) {
        let mut found = false;
        each_entry(doc, &mut |k, _| found |= k.as_str() == Some("<<"));
        if found {
            self.error(
                None,
                "YAML merge keys (<<) are not allowed; GitHub does not apply them".into(),
            );
        }
    }

    /// Returns the trigger event names; flags pull_request_target and malformed `on`.
    fn triggers(&mut self, doc: &Yaml) -> Vec<String> {
        let mut events = Vec::new();
        let mut malformed = false;
        match key(doc, "on") {
            Some(Yaml::String(e)) => events.push(e.clone()),
            Some(Yaml::Array(items)) => {
                for item in items {
                    match item {
                        Yaml::String(e) => events.push(e.clone()),
                        _ => malformed = true,
                    }
                }
            }
            Some(Yaml::Hash(h)) => {
                for k in h.keys() {
                    match k {
                        Yaml::String(e) => events.push(e.clone()),
                        _ => malformed = true,
                    }
                }
            }
            _ => malformed = true,
        }
        if malformed {
            self.error(None, "`on:` must name its trigger events".into());
        }
        if events.iter().any(|e| e == "pull_request_target") {
            self.error(None, "pull_request_target is forbidden".into());
        }
        events
    }

    fn uses(&mut self, doc: &Yaml) {
        let mut values = Vec::new();
        each_entry(doc, &mut |k, val| {
            if k.as_str() == Some("uses") {
                values.push(val);
            }
        });
        let mut seen: Vec<&str> = Vec::new();
        for val in values.iter().copied() {
            let Some(r) = val.as_str() else {
                self.error(None, format!("uses: {} is not a string", render(val)));
                continue;
            };
            if r.starts_with("./") || seen.contains(&r) {
                continue;
            }
            seen.push(r);
            let lines = self.lines_containing(r);
            if !is_sha_pinned(r) && !is_digest_pinned(r) {
                let line = lines.first().map(|(n, _)| *n);
                self.error(
                    line,
                    format!("uses: {r} is not pinned to a full commit SHA (or image digest)"),
                );
                continue;
            }
            // Each occurrence needs its own plain `uses: <value>` line, so the version comment
            // cannot be borrowed from a comment or another line holding the same text.
            let uses_lines: Vec<_> = lines
                .into_iter()
                .filter(|(_, raw)| is_uses_line_for(raw, r))
                .collect();
            let occurrences = values.iter().filter(|v| v.as_str() == Some(r)).count();
            if uses_lines.len() < occurrences {
                self.error(
                    None,
                    format!(
                        "uses: {r} must be written verbatim on its own uses line so its version comment can be checked"
                    ),
                );
            }
            for (n, raw) in uses_lines {
                let after = &raw[raw.find(r).map_or(0, |i| i + r.len())..];
                let after = after.trim_start_matches(['"', '\'', ' ', '\t', '}', ',']);
                let has_version = after
                    .strip_prefix('#')
                    .is_some_and(|c| !c.trim().is_empty());
                if !has_version {
                    self.error(
                        Some(n),
                        format!("uses: {r} has no '# <version>' version comment"),
                    );
                }
            }
        }
    }

    fn permissions(&mut self, doc: &Yaml) {
        match key(doc, "permissions") {
            Some(p @ Yaml::Hash(h))
                if h.len() == 1 && key(p, "contents").and_then(Yaml::as_str) == Some("read") => {}
            Some(other) => self.error(
                None,
                format!(
                    "top-level permissions must be exactly 'contents: read' (found: {})",
                    render(other)
                ),
            ),
            None => self.error(
                None,
                "top-level permissions must be exactly 'contents: read' (found: none)".into(),
            ),
        }
        let Some(Yaml::Hash(jobs)) = key(doc, "jobs") else {
            self.error(None, "workflow has no jobs mapping".into());
            return;
        };
        for (job, body) in jobs {
            let Some(perms) = key(body, "permissions") else {
                continue;
            };
            let read_only = match perms {
                Yaml::String(s) => s == "read-all",
                Yaml::Hash(h) => h.iter().all(|(k, val)| {
                    k.as_str().is_some() && matches!(val.as_str(), Some("read" | "none"))
                }),
                _ => false,
            };
            if !read_only {
                self.error(
                    None,
                    format!(
                        "job {}: permissions may only be read or none (found: {})",
                        render(job),
                        render(perms)
                    ),
                );
            }
        }
    }

    fn secrets(&mut self, doc: &Yaml) {
        // Raw text, comment lines included: from a `${{` to the end of its line.
        let raw: Vec<usize> = self
            .text
            .lines()
            .enumerate()
            .filter(|(_, l)| secrets_after_expression_open(l))
            .map(|(i, _)| i + 1)
            .collect();
        for line in &raw {
            self.error(
                Some(*line),
                "secrets are forbidden in a pull_request workflow \
                 (any `secrets` word after `${{` on the line counts)"
                    .into(),
            );
        }
        self.secrets_in_conditions(doc);
        // Decoded scalars (escapes resolved, multi-line values joined): to the end of the scalar.
        let mut decoded = false;
        each_string(doc, &mut |s| decoded |= secrets_after_expression_open(s));
        if decoded && raw.is_empty() {
            self.error(
                None,
                "secrets are forbidden in a pull_request workflow (in a decoded string)".into(),
            );
        }
        let mut passed = Vec::new();
        each_entry(doc, &mut |k, val| {
            let empty = match val {
                Yaml::Null => true,
                Yaml::String(s) => s.is_empty(),
                Yaml::Hash(h) => h.is_empty(),
                Yaml::Array(a) => a.is_empty(),
                _ => false,
            };
            let is_secrets_key = k
                .as_str()
                .is_some_and(|k| k.eq_ignore_ascii_case("secrets"));
            if is_secrets_key && !empty {
                passed.push(render(val));
            }
        });
        for val in passed {
            self.error(
                None,
                format!("secrets: {val} is forbidden in a pull_request workflow"),
            );
        }
    }

    /// Job- and step-level `if:` values are expressions even without `${{`, so any `secrets`
    /// identifier in one counts.
    fn secrets_in_conditions(&mut self, doc: &Yaml) {
        let Some(Yaml::Hash(jobs)) = key(doc, "jobs") else {
            return;
        };
        let mut found = Vec::new();
        for (job, body) in jobs {
            let job = render(job);
            if let Some(cond) = key(body, "if").and_then(Yaml::as_str) {
                if mentions_secrets(cond) {
                    found.push(format!("job {job}: if: {cond}"));
                }
            }
            let Some(Yaml::Array(steps)) = key(body, "steps") else {
                continue;
            };
            for (i, step) in steps.iter().enumerate() {
                if let Some(cond) = key(step, "if").and_then(Yaml::as_str) {
                    if mentions_secrets(cond) {
                        found.push(format!("job {job} step {}: if: {cond}", i + 1));
                    }
                }
            }
        }
        for what in found {
            self.error(
                None,
                format!("{what} references secrets; forbidden in a pull_request workflow"),
            );
        }
    }
}

#[cfg(test)]
mod tests;
