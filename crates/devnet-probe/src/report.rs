//! What a probe check prints: one PASS or FAIL line per thing it judged, a summary line per
//! check, and one verdict over every check.

/// One thing a check judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Whether it passed.
    pub pass: bool,
    /// What was judged and what was found.
    pub detail: String,
}

/// What one check (a subcommand) judged, line by line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    name: &'static str,
    lines: Vec<Line>,
    /// Why the check ran outside the acceptance rules: its passes are diagnostic only.
    diagnostic: Option<String>,
}

impl Check {
    /// A check named `name` that has judged nothing yet.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            lines: Vec::new(),
            diagnostic: None,
        }
    }

    /// A check that could not run: one failed line saying why.
    #[must_use]
    pub fn failed(name: &'static str, why: impl Into<String>) -> Self {
        let mut check = Self::new(name);
        check.fail(why);
        check
    }

    /// The check's name, as the subcommand.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The lines judged so far.
    #[must_use]
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    /// Records a passed line.
    pub fn pass(&mut self, detail: impl Into<String>) {
        self.record(true, detail.into());
    }

    /// Records a failed line.
    pub fn fail(&mut self, detail: impl Into<String>) {
        self.record(false, detail.into());
    }

    /// Records a line that passed if `pass`.
    pub fn record(&mut self, pass: bool, detail: impl Into<String>) {
        self.lines.push(Line {
            pass,
            detail: detail.into(),
        });
    }

    /// Marks the check as run outside the acceptance rules (`why`): what passes prints
    /// `DIAGNOSTIC`, never `PASS`, and the verdict over it is at best [`Outcome::Diagnostic`].
    pub fn mark_diagnostic(&mut self, why: impl Into<String>) {
        self.diagnostic = Some(why.into());
    }

    /// Whether the check ran outside the acceptance rules.
    #[must_use]
    pub fn is_diagnostic(&self) -> bool {
        self.diagnostic.is_some()
    }

    /// Whether it judged something and every line passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        !self.lines.is_empty() && self.lines.iter().all(|l| l.pass)
    }

    /// The word for a line or summary that passed if `pass`.
    fn word(&self, pass: bool) -> &'static str {
        match (pass, self.is_diagnostic()) {
            (false, _) => "FAIL",
            (true, false) => "PASS",
            (true, true) => "DIAGNOSTIC",
        }
    }

    /// Every line as `<name>: PASS|FAIL|DIAGNOSTIC <detail>` (each on one line), then
    /// `<name>: PASS|FAIL|DIAGNOSTIC (<passed>/<lines>[; <why diagnostic>])`.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .lines
            .iter()
            .map(|l| {
                let detail = l.detail.replace(['\r', '\n'], " ");
                format!("{}: {} {detail}", self.name, self.word(l.pass))
            })
            .collect();
        let passed = self.lines.iter().filter(|l| l.pass).count();
        let why = self
            .diagnostic
            .as_ref()
            .map_or_else(String::new, |why| format!("; {why}"));
        out.push(format!(
            "{}: {} ({passed}/{}{why})",
            self.name,
            self.word(self.passed()),
            self.lines.len()
        ));
        out
    }
}

/// What a run of checks comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every check passed under the acceptance rules: exit 0.
    Pass,
    /// A check failed: exit 1.
    Fail,
    /// Every check passed, but one ran outside the acceptance rules: exit 3, never an
    /// acceptance pass.
    Diagnostic,
}

impl Outcome {
    /// The process exit code: 0 pass, 1 fail, 3 diagnostic (2 is usage).
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Fail => 1,
            Self::Diagnostic => 3,
        }
    }
}

/// What every check comes to, and the verdict line: `verdict: PASS (<n>/<n> checks)`,
/// `verdict: FAIL (...)` naming the failed ones, or `verdict: DIAGNOSTIC (...)` naming the
/// diagnostic ones and why.
#[must_use]
pub fn verdict(checks: &[Check]) -> (Outcome, String) {
    if checks.is_empty() {
        return (Outcome::Fail, "verdict: FAIL (no check ran)".into());
    }
    let failed: Vec<&str> = checks
        .iter()
        .filter(|c| !c.passed())
        .map(Check::name)
        .collect();
    let passed = checks.len() - failed.len();
    let diagnostic: Vec<String> = checks
        .iter()
        .filter_map(|c| {
            c.diagnostic
                .as_ref()
                .map(|why| format!("{}: {why}", c.name))
        })
        .collect();
    if !failed.is_empty() {
        let line = format!(
            "verdict: FAIL ({passed}/{} checks; failed: {})",
            checks.len(),
            failed.join(", ")
        );
        (Outcome::Fail, line)
    } else if !diagnostic.is_empty() {
        let line = format!(
            "verdict: DIAGNOSTIC ({passed}/{} checks passed; diagnostic: {})",
            checks.len(),
            diagnostic.join(", ")
        );
        (Outcome::Diagnostic, line)
    } else {
        (
            Outcome::Pass,
            format!("verdict: PASS ({passed}/{} checks)", checks.len()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_passes_only_with_every_line_passing() {
        let mut check = Check::new("connect");
        assert!(
            !check.passed(),
            "a check that judged nothing passes nothing"
        );
        check.pass("peer a: muxer /yamux/1.0.0");
        assert!(check.passed());
        check.fail("peer b: dial refused");
        assert!(!check.passed());
        assert_eq!(
            check.render(),
            [
                "connect: PASS peer a: muxer /yamux/1.0.0",
                "connect: FAIL peer b: dial refused",
                "connect: FAIL (1/2)",
            ]
        );
        let failed = Check::failed("status", "no Status of ours");
        assert!(!failed.passed());
        assert_eq!(
            failed.render(),
            ["status: FAIL no Status of ours", "status: FAIL (0/1)"]
        );
        assert_eq!(Check::new("discover").render(), ["discover: FAIL (0/0)"]);
    }

    #[test]
    fn the_verdict_passes_only_with_every_check_passing() {
        let mut ok = Check::new("connect");
        ok.pass("fine");
        let mut also = Check::new("status");
        also.pass("fine");
        assert_eq!(
            verdict(&[ok.clone(), also]),
            (Outcome::Pass, "verdict: PASS (2/2 checks)".into())
        );
        let bad = Check::failed("fetch-epoch", "no peer");
        let worse = Check::failed("status", "no peer");
        assert_eq!(
            verdict(&[ok, bad, worse]),
            (
                Outcome::Fail,
                "verdict: FAIL (1/3 checks; failed: fetch-epoch, status)".into()
            )
        );
        assert_eq!(
            verdict(&[]),
            (Outcome::Fail, "verdict: FAIL (no check ran)".into())
        );
    }

    /// A diagnostic check (one run outside the acceptance rules, a short hold) prints no PASS:
    /// its passing lines and its summary say DIAGNOSTIC, and the verdict is DIAGNOSTIC unless a
    /// check failed.
    #[test]
    fn a_diagnostic_check_never_prints_pass() {
        let mut held = Check::new("status");
        held.pass("peer a: held 1.0 s");
        held.mark_diagnostic("hold 1 s < 600 s");
        assert!(held.passed());
        assert!(held.is_diagnostic());
        assert_eq!(
            held.render(),
            [
                "status: DIAGNOSTIC peer a: held 1.0 s",
                "status: DIAGNOSTIC (1/1; hold 1 s < 600 s)",
            ]
        );
        let mut ok = Check::new("connect");
        ok.pass("fine");
        assert_eq!(
            verdict(&[ok.clone(), held.clone()]),
            (
                Outcome::Diagnostic,
                "verdict: DIAGNOSTIC (2/2 checks passed; diagnostic: status: hold 1 s < 600 s)"
                    .into()
            )
        );
        let bad = Check::failed("fetch-epoch", "no peer");
        assert_eq!(
            verdict(&[ok, held.clone(), bad]).0,
            Outcome::Fail,
            "a failure beats a diagnostic"
        );
        // A diagnostic check that failed prints its failures as such.
        held.fail("peer b: Goodbye 3");
        assert_eq!(held.render()[1], "status: FAIL peer b: Goodbye 3");
        assert_eq!(held.render()[2], "status: FAIL (1/2; hold 1 s < 600 s)");
        assert_eq!(
            [Outcome::Pass, Outcome::Fail, Outcome::Diagnostic].map(Outcome::exit_code),
            [0, 1, 3]
        );
    }

    #[test]
    fn details_stay_on_one_line() {
        let mut check = Check::new("x");
        check.fail("first\nsecond\r\nthird");
        assert_eq!(check.render()[0], "x: FAIL first second  third");
    }
}
