//! `scripts/check-bls-features.sh`: only spec-tests may turn on `crypto-bls/test-vectors`.
//!
//! Each case builds a throwaway workspace of path-only crates (no registry access) and runs
//! the script against its manifest.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const CRYPTO_BLS: &str = r#"
[features]
verify = []
aggregate = []
test-vectors = []
everything = ["verify", "aggregate", "test-vectors"]
"#;

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/check-bls-features.sh")
}

fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned())
}

/// A workspace of `(crate name, extra manifest text)` members with an up-to-date lockfile.
struct Workspace {
    tmp: TempDir,
}

impl Workspace {
    fn new(crates: &[(&str, &str)]) -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("bls-features-")
            .tempdir()
            .expect("tempdir");
        let members: Vec<String> = crates.iter().map(|(name, _)| format!("{name:?}")).collect();
        fs::write(
            tmp.path().join("Cargo.toml"),
            format!(
                "[workspace]\nresolver = \"2\"\nmembers = [{}]\n",
                members.join(", ")
            ),
        )
        .unwrap();
        for (name, extra) in crates {
            let dir = tmp.path().join(name);
            fs::create_dir_all(dir.join("src")).unwrap();
            fs::write(dir.join("src/lib.rs"), "").unwrap();
            fs::write(
                dir.join("Cargo.toml"),
                format!(
                    "[package]\nname = {name:?}\nversion = \"0.1.0\"\nedition = \"2021\"\n{extra}\n"
                ),
            )
            .unwrap();
        }
        let ws = Self { tmp };
        let out = Command::new(cargo())
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(ws.manifest())
            .output()
            .expect("spawn cargo");
        assert!(out.status.success(), "lockfile:\n{}", describe(&out));
        ws
    }

    fn manifest(&self) -> PathBuf {
        self.tmp.path().join("Cargo.toml")
    }

    fn check(&self) -> Output {
        run_script(&self.manifest())
    }
}

fn run_script(manifest: &Path) -> Output {
    Command::new("bash")
        .arg(script())
        .arg(manifest)
        .env("CARGO", cargo())
        .env("CARGO_NET_OFFLINE", "true")
        .output()
        .expect("spawn bash")
}

fn describe(out: &Output) -> String {
    format!(
        "status: {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_passes(out: &Output) {
    assert!(out.status.success(), "expected pass:\n{}", describe(out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("test-vectors OK"),
        "{}",
        describe(out)
    );
}

fn assert_rejects(out: &Output, offenders: &[&str]) {
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected fail:\n{}",
        describe(out)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    for name in offenders {
        assert!(
            stderr.contains(&format!("crypto-bls/test-vectors enabled by {name}")),
            "{name} not reported:\n{}",
            describe(out)
        );
    }
    assert!(
        !stderr.contains("enabled by spec-tests\n"),
        "spec-tests is allowed:\n{}",
        describe(out)
    );
}

const SPEC_TESTS: (&str, &str) = (
    "spec-tests",
    "[dependencies]\ncrypto-bls = { path = \"../crypto-bls\", features = [\"test-vectors\"] }",
);

#[test]
fn passes_when_nobody_enables_it() {
    let ws = Workspace::new(&[
        ("crypto-bls", CRYPTO_BLS),
        (
            "cl-chain",
            "[dependencies]\ncrypto-bls = { path = \"../crypto-bls\", features = [\"aggregate\"] }",
        ),
    ]);
    assert_passes(&ws.check());
}

#[test]
fn passes_when_only_spec_tests_enables_it() {
    let ws = Workspace::new(&[("crypto-bls", CRYPTO_BLS), SPEC_TESTS]);
    assert_passes(&ws.check());
}

#[test]
fn rejects_a_normal_dependency() {
    let ws = Workspace::new(&[
        ("crypto-bls", CRYPTO_BLS),
        SPEC_TESTS,
        (
            "cl-verify",
            "[dependencies]\ncrypto-bls = { path = \"../crypto-bls\", features = [\"verify\", \"test-vectors\"] }",
        ),
    ]);
    assert_rejects(&ws.check(), &["cl-verify"]);
}

#[test]
fn rejects_a_dev_dependency() {
    let ws = Workspace::new(&[
        ("crypto-bls", CRYPTO_BLS),
        (
            "cl-verify",
            "[dev-dependencies]\ncrypto-bls = { path = \"../crypto-bls\", features = [\"test-vectors\"] }",
        ),
    ]);
    assert_rejects(&ws.check(), &["cl-verify"]);
}

#[test]
fn rejects_an_optional_feature_of_another_crate() {
    let ws = Workspace::new(&[
        ("crypto-bls", CRYPTO_BLS),
        (
            "cl-chain",
            "[dependencies]\ncrypto-bls = { path = \"../crypto-bls\", features = [\"aggregate\"] }\n\
             [features]\nbench = [\"crypto-bls/test-vectors\"]",
        ),
    ]);
    assert_rejects(&ws.check(), &["cl-chain"]);
}

#[test]
fn rejects_a_crypto_bls_feature_that_implies_it() {
    let ws = Workspace::new(&[
        ("crypto-bls", CRYPTO_BLS),
        (
            "cl-api",
            "[dependencies]\ncrypto-bls = { path = \"../crypto-bls\", features = [\"everything\"] }",
        ),
    ]);
    assert_rejects(&ws.check(), &["cl-api"]);
}

#[test]
fn rejects_a_crate_that_pulls_in_spec_tests() {
    let ws = Workspace::new(&[
        ("crypto-bls", CRYPTO_BLS),
        SPEC_TESTS,
        (
            "cl-store",
            "[dependencies]\nspec-tests = { path = \"../spec-tests\" }",
        ),
    ]);
    assert_rejects(&ws.check(), &["cl-store"]);
}

#[test]
fn fails_closed_when_the_feature_is_gone() {
    let ws = Workspace::new(&[("crypto-bls", "[features]\nverify = []")]);
    let out = ws.check();
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no `test-vectors` feature"),
        "{}",
        describe(&out)
    );
}

#[test]
fn fails_closed_without_crypto_bls() {
    let ws = Workspace::new(&[("cl-chain", "")]);
    let out = ws.check();
    assert!(!out.status.success(), "{}", describe(&out));
}

#[test]
fn this_workspace_passes() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    assert_passes(&run_script(&manifest));
}
