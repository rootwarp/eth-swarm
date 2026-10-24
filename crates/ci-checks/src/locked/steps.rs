//! The step rules of the `--locked` check (rule 8 of the module docs of `locked`): the shell of
//! a step that can run cargo, actions that run cargo, and a Docker action whose entrypoint or
//! arguments can run cargo.
//!
//! The check reads local actions and local reusable workflows (`uses: ./<path>`) in repository
//! mode. It does not read remote actions or remote reusable workflows (`owner/repo@ref`): it
//! knows them only through the fixed list [`CARGO_ACTIONS`] and the `docker://` rule. A remote
//! action that is not on that list and runs cargo inside passes.

use super::shell::can_run_cargo;
use super::{Allow, AllowKind};
use yaml_rust2::Yaml;

/// Actions that run cargo with inputs that the check cannot read. Compare without the `@ref`.
const CARGO_ACTIONS: &[&str] = &[
    "actions-rs/cargo",
    "actions-rs/clippy-check",
    "actions-rs/tarpaulin",
    "clechasseur/rs-cargo",
    "clechasseur/rs-clippy-check",
    "giraffate/clippy-action",
    "houseabsolute/actions-rust-cross",
];

/// The value of `k` in the mapping `map`, with the key in any letter case.
fn get<'y>(map: &'y Yaml, k: &str) -> Option<&'y Yaml> {
    match map {
        Yaml::Hash(h) => h
            .iter()
            .find(|(key, _)| key.as_str().is_some_and(|s| s.eq_ignore_ascii_case(k)))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// `defaults.run.shell` of a workflow or a job.
fn default_shell(node: &Yaml) -> Option<&Yaml> {
    get(node, "defaults")
        .and_then(|d| get(d, "run"))
        .and_then(|r| get(r, "shell"))
}

/// True if `shell` runs the step with bash or sh and nothing more: `bash`, `sh`, or a template
/// of `bash` or `sh`, the options `--noprofile`, `--norc`, `-o <option>` and clusters of
/// `e u x o`, and `{0}` as the last word.
pub(super) fn is_bash_or_sh(shell: &str) -> bool {
    let words: Vec<&str> = shell.split_whitespace().collect();
    let Some((&first, rest)) = words.split_first() else {
        return false;
    };
    if !matches!(first, "bash" | "sh") {
        return false;
    }
    let Some((&last, options)) = rest.split_last() else {
        return true;
    };
    if last != "{0}" {
        return false;
    }
    let mut needs_option_name = false;
    for &w in options {
        if needs_option_name {
            if !matches!(w, "pipefail" | "errexit" | "nounset" | "xtrace") {
                return false;
            }
            needs_option_name = false;
            continue;
        }
        match w {
            "--noprofile" | "--norc" => {}
            _ => {
                let Some(letters) = w.strip_prefix('-') else {
                    return false;
                };
                let known = !letters.is_empty() && letters.chars().all(|c| "euxo".contains(c));
                // `o` takes the next word, so it must end the cluster.
                if !known || letters[..letters.len() - 1].contains('o') {
                    return false;
                }
                needs_option_name = letters.ends_with('o');
            }
        }
    }
    !needs_option_name
}

/// True if the labels of `runs-on` name a runner whose default shell is bash: a Linux or macOS
/// label, no Windows label, and no expression.
fn runs_bash_by_default(job: &Yaml) -> bool {
    let labels: Vec<&str> = match get(job, "runs-on") {
        Some(Yaml::String(s)) => vec![s.as_str()],
        Some(Yaml::Array(items)) => match items.iter().map(Yaml::as_str).collect() {
            Some(labels) => labels,
            None => return false,
        },
        _ => return false,
    };
    let lower: Vec<String> = labels.iter().map(|l| l.to_ascii_lowercase()).collect();
    let unix = lower
        .iter()
        .any(|l| l.contains("ubuntu") || l.contains("linux") || l.contains("macos"));
    let unknown = lower
        .iter()
        .any(|l| l.contains("windows") || l.contains("${{"));
    unix && !unknown
}

fn render(node: Option<&Yaml>) -> String {
    match node {
        Some(Yaml::String(s)) => s.clone(),
        Some(other) => format!("{other:?}"),
        None => "none".into(),
    }
}

/// Checks the steps of each job (`jobs.<id>.steps`) and of a composite action
/// (`runs.steps`). Returns one message for each problem.
pub(super) fn check_steps(doc: &Yaml, allow: &[Allow]) -> Vec<String> {
    let mut out = Vec::new();
    let workflow_shell = default_shell(doc);
    if let Some(Yaml::Hash(jobs)) = get(doc, "jobs") {
        for (name, job) in jobs {
            let shell = default_shell(job).or(workflow_shell);
            let bash_default = runs_bash_by_default(job);
            if let Some(Yaml::Array(steps)) = get(job, "steps") {
                for (i, step) in steps.iter().enumerate() {
                    let at = format!("job {} step {}", render(Some(name)), i + 1);
                    check_step(&at, step, shell, bash_default, allow, &mut out);
                }
            }
        }
    }
    if let Some(runs) = get(doc, "runs") {
        check_docker_action(runs, allow, &mut out);
    }
    if let Some(Yaml::Array(steps)) = get(doc, "runs").and_then(|r| get(r, "steps")) {
        for (i, step) in steps.iter().enumerate() {
            let at = format!("runs step {}", i + 1);
            // A composite step has no default shell.
            check_step(&at, step, None, false, allow, &mut out);
        }
    }
    out
}

fn check_step(
    at: &str,
    step: &Yaml,
    default: Option<&Yaml>,
    bash_default: bool,
    allow: &[Allow],
    out: &mut Vec<String>,
) {
    if let Some(run) = get(step, "run").and_then(Yaml::as_str) {
        if can_run_cargo(run) {
            let shell = get(step, "shell").or(default);
            let ok = match shell {
                Some(s) => s.as_str().is_some_and(is_bash_or_sh),
                None => bash_default,
            };
            if !ok && shell.is_some() {
                out.push(format!(
                    "{at}: the step can run cargo, so its shell must be bash or sh \
                     (found: {})",
                    render(shell)
                ));
            } else if !ok {
                out.push(format!(
                    "{at}: the step can run cargo, but its default shell is not known to be \
                     bash (set shell: bash, or runs-on a Linux or macOS label)"
                ));
            }
        }
    }
    let Some(uses) = get(step, "uses").and_then(Yaml::as_str) else {
        return;
    };
    if allow
        .iter()
        .any(|a| a.kind == AllowKind::Uses && a.line == uses.trim())
    {
        return;
    }
    let name = uses
        .split('@')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if CARGO_ACTIONS.contains(&name.as_str()) {
        out.push(format!(
            "{at}: uses: {uses} runs cargo with inputs that the check cannot read \
             (use a run: step, or add a reviewed allow-list entry)"
        ));
    } else if name.starts_with("docker://") {
        let with = get(step, "with");
        let runs_cargo = ["args", "entrypoint"].iter().any(|k| {
            with.and_then(|w| get(w, k))
                .and_then(Yaml::as_str)
                .is_some_and(can_run_cargo)
        });
        if runs_cargo {
            out.push(format!(
                "{at}: uses: {uses} can run cargo through its args or entrypoint \
                 (use a run: step, or add a reviewed allow-list entry)"
            ));
        }
    }
}

/// The `entrypoint`, `pre-entrypoint`, `post-entrypoint` and `args` of an action's `runs`:
/// each one that can run cargo fails, unless an [`AllowKind::Run`] entry names its text.
fn check_docker_action(runs: &Yaml, allow: &[Allow], out: &mut Vec<String>) {
    for key in ["entrypoint", "pre-entrypoint", "post-entrypoint", "args"] {
        let texts: Vec<&str> = match get(runs, key) {
            Some(Yaml::String(s)) => vec![s.as_str()],
            Some(Yaml::Array(items)) => items.iter().filter_map(Yaml::as_str).collect(),
            Some(_) => vec!["(not a string)"],
            None => continue,
        };
        let text = texts.join(" ");
        let allowed = allow
            .iter()
            .any(|a| a.kind == AllowKind::Run && a.line == text.trim());
        let runs_cargo = texts.iter().any(|t| can_run_cargo(t)) || can_run_cargo(&text);
        if runs_cargo && !allowed {
            out.push(format!(
                "runs.{key}: {text} can run cargo with arguments that the check cannot read \
                 (add a reviewed allow-list entry)"
            ));
        }
    }
}

/// Each `uses` value of the jobs (`jobs.<id>.uses`), of their steps, and of the steps of a
/// composite action.
pub(super) fn uses_values(doc: &Yaml) -> Vec<String> {
    let mut out = Vec::new();
    let mut steps_of = |steps: Option<&Yaml>| {
        if let Some(Yaml::Array(steps)) = steps {
            out.extend(
                steps
                    .iter()
                    .filter_map(|s| get(s, "uses").and_then(Yaml::as_str))
                    .map(str::to_owned),
            );
        }
    };
    if let Some(Yaml::Hash(jobs)) = get(doc, "jobs") {
        for job in jobs.values() {
            steps_of(get(job, "steps"));
        }
    }
    steps_of(get(doc, "runs").and_then(|r| get(r, "steps")));
    if let Some(Yaml::Hash(jobs)) = get(doc, "jobs") {
        out.extend(
            jobs.values()
                .filter_map(|j| get(j, "uses").and_then(Yaml::as_str))
                .map(str::to_owned),
        );
    }
    out
}
