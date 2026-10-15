//! One libtest trial per vector case. Set `SPEC_VECTORS_DIR` to override the default
//! `target/spec-vectors` produced by `testing/fetch-vectors.sh`.

use libtest_mimic::{Arguments, Failed, Trial};
use spec_tests::plan::{plan, CaseKey, Date, Disposition, SkipList};
use spec_tests::{ssz_generic, ssz_static};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

const SSZ_SPECS: &str = "ssz-specs/v0.1.0/ssz-test-vectors-v0.1.0";
const CONSENSUS: &str = "consensus-specs/v1.7.0-beta.4";
/// Presets run when their extracted tree is present; minimal is required.
const PRESETS: [(&str, bool); 2] = [("minimal", true), ("mainnet", false)];

type Runner = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn main() {
    let args = Arguments::from_args();
    let trials = match build_trials() {
        Ok(t) => t,
        Err(e) => vec![Trial::test("setup", move || Err(Failed::from(e.clone())))],
    };
    libtest_mimic::run(&args, trials).exit();
}

fn build_trials() -> Result<Vec<Trial>, String> {
    let root = std::env::var_os("SPEC_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target/spec-vectors"));
    let skip_path = workspace_root().join("testing/skip.toml");
    let skip_text = std::fs::read_to_string(&skip_path).map_err(|e| {
        format!(
            "{}: {e} (copy testing/skip.toml.example)",
            skip_path.display()
        )
    })?;
    let skips = SkipList::parse(&skip_text).map_err(|e| e.to_string())?;

    let mut keys: Vec<CaseKey> = Vec::new();
    let mut runners: Vec<Option<Runner>> = Vec::new();

    let generic = ssz_generic::discover(&root.join(SSZ_SPECS))
        .map_err(|e| format!("ssz-specs vectors missing ({e}); run testing/fetch-vectors.sh"))?;
    for case in generic {
        let fixture = ssz_generic::load(&case.path)?;
        let runnable = ssz_generic::supported(&case.key.handler, &fixture.type_name);
        keys.push(case.key.clone());
        let case = Arc::new(case);
        runners.push(runnable.then(|| -> Runner { Arc::new(move || ssz_generic::run(&case)) }));
    }

    for (preset, required) in PRESETS {
        let dir = root.join(CONSENSUS).join(preset);
        if !dir.exists() && !required {
            continue;
        }
        let statics = ssz_static::discover(&dir, preset, "gloas").map_err(|e| {
            format!("consensus-specs {preset} vectors missing ({e}); run testing/fetch-vectors.sh")
        })?;
        for case in statics {
            let runnable = ssz_static::supported(preset, &case.key.handler);
            keys.push(case.key.clone());
            let case = Arc::new(case);
            runners.push(runnable.then(|| -> Runner { Arc::new(move || ssz_static::run(&case)) }));
        }
    }

    let runnable: HashSet<String> = keys
        .iter()
        .zip(&runners)
        .filter(|(_, r)| r.is_some())
        .map(|(k, _)| k.to_string())
        .collect();
    let planned = match plan(
        &keys,
        |k| runnable.contains(&k.to_string()),
        &skips,
        Date::today_utc(),
    ) {
        Ok(p) => p,
        Err(errs) => {
            let msg = errs
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            return Ok(vec![Trial::test("skip_list::rules", move || {
                Err(msg.clone().into())
            })]);
        }
    };

    Ok(planned
        .into_iter()
        .zip(runners)
        .map(|((key, disposition), runner)| {
            let name = trial_name(key);
            match (disposition, runner) {
                (Disposition::Skip(_), _) => Trial::test(name, || Ok(()))
                    .with_ignored_flag(true)
                    .with_kind("skip"),
                (Disposition::Run, Some(r)) => Trial::test(name, move || r().map_err(Failed::from)),
                (Disposition::Run, None) | (Disposition::Unaccounted, _) => {
                    Trial::test(name, || {
                        Err("unaccounted: no Rust type for this case and no skip entry".into())
                    })
                }
            }
        })
        .collect())
}

fn trial_name(k: &CaseKey) -> String {
    let case = k.case.replace('/', "::");
    if k.source == "ssz-specs" {
        format!("ssz_generic::{}::{case}", k.handler)
    } else {
        format!(
            "{}_{}_{}::{}::{case}",
            k.fork, k.runner, k.preset, k.handler
        )
    }
}
