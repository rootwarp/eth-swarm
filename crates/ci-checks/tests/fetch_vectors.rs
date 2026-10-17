//! Fail-closed behaviour of `testing/fetch-vectors.sh`, run fully offline.
//!
//! Each test builds a throwaway "GitHub" in a temp dir: a local git repo with a lightweight
//! and an annotated tag (for the tag -> commit pin), and release archives served over
//! `file://`. A `curl` shim on `PATH` logs every download attempt so retries are visible.

mod common;

use common::{bash_script, checked, describe, files_under, stderr, stdout};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const REPO: &str = "ethereum/demo";
const LIGHT_TAG: &str = "v1.0.0";
const ANNOTATED_TAG: &str = "v2.0.0";
const TAR: &str = "demo.tar.gz";
const ZIP: &str = "bundle.zip";
const PAYLOAD: &str = "case/data.txt";
const WRONG_SHA: &str = "0000000000000000000000000000000000000000000000000000000000000000";

struct Fixture {
    tmp: TempDir,
    /// Older commit; no tag points at it.
    old_commit: String,
    /// Commit that both tags resolve to.
    tagged_commit: String,
    /// Object id of the annotated tag itself (what `ls-remote` shows before `^{}`).
    annotated_tag_object: String,
    tar_sha: String,
    zip_sha: String,
}

struct Asset<'a> {
    file: &'a str,
    sha: &'a str,
    optional: bool,
}

impl<'a> Asset<'a> {
    fn new(file: &'a str, sha: &'a str) -> Self {
        Self {
            file,
            sha,
            optional: false,
        }
    }
}

fn git(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ]);
    cmd
}

fn sha256(path: &Path) -> String {
    let line = checked(Command::new("sha256sum").arg(path));
    line.split_whitespace().next().expect("digest").to_owned()
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("fetch-vectors-")
            .tempdir()
            .expect("tempdir");
        let root = tmp.path();

        let repo = root.join("remote").join(REPO);
        fs::create_dir_all(&repo).expect("mkdir repo");
        checked(git(&repo).args(["init", "-q"]));
        checked(git(&repo).args(["commit", "-q", "--allow-empty", "-m", "old"]));
        let old_commit = checked(git(&repo).args(["rev-parse", "HEAD"]));
        checked(git(&repo).args(["commit", "-q", "--allow-empty", "-m", "release"]));
        let tagged_commit = checked(git(&repo).args(["rev-parse", "HEAD"]));
        checked(git(&repo).args(["tag", LIGHT_TAG]));
        checked(git(&repo).args(["tag", "-a", ANNOTATED_TAG, "-m", "annotated"]));
        let annotated_tag_object = checked(git(&repo).args(["rev-parse", ANNOTATED_TAG]));
        assert_ne!(annotated_tag_object, tagged_commit);

        let payload = root.join("payload");
        fs::create_dir_all(payload.join("case")).expect("mkdir payload");
        fs::write(payload.join(PAYLOAD), "vector\n").expect("write payload");
        let built = root.join("built");
        fs::create_dir_all(&built).expect("mkdir built");
        checked(
            Command::new("tar")
                .arg("-czf")
                .arg(built.join(TAR))
                .arg("-C")
                .arg(&payload)
                .arg("case"),
        );
        checked(
            Command::new("python3")
                .args(["-I", "-m", "zipfile", "-c"])
                .arg(built.join(ZIP))
                .arg("case")
                .current_dir(&payload),
        );
        for tag in [LIGHT_TAG, ANNOTATED_TAG] {
            let dir = root
                .join("releases")
                .join(REPO)
                .join("releases/download")
                .join(tag);
            fs::create_dir_all(&dir).expect("mkdir release");
            for file in [TAR, ZIP] {
                fs::copy(built.join(file), dir.join(file)).expect("copy archive");
            }
        }
        let tar_sha = sha256(&built.join(TAR));
        let zip_sha = sha256(&built.join(ZIP));

        let real_curl = checked(Command::new("sh").args(["-c", "command -v curl"]));
        let bin = root.join("bin");
        fs::create_dir_all(&bin).expect("mkdir bin");
        write_executable(
            &bin.join("curl"),
            &format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$*\" >> \"$FAKE_CURL_LOG\"\n\
                 if [ -n \"${{FAKE_CURL_FAIL:-}}\" ]; then\n\
                 \x20 echo 'curl: (22) The requested URL returned error: 503' >&2\n\
                 \x20 exit 22\n\
                 fi\n\
                 exec '{real_curl}' \"$@\"\n"
            ),
        );

        Self {
            tmp,
            old_commit,
            tagged_commit,
            annotated_tag_object,
            tar_sha,
            zip_sha,
        }
    }

    fn root(&self) -> &Path {
        self.tmp.path()
    }

    fn dest(&self) -> PathBuf {
        self.root().join("dest")
    }

    fn out_dir(&self, tag: &str) -> PathBuf {
        self.dest().join("demo").join(tag)
    }

    fn manifest(&self, tag: &str, commit: &str, assets: &[Asset]) -> PathBuf {
        self.manifest_text(&manifest_toml(tag, commit, assets))
    }

    fn manifest_text(&self, toml: &str) -> PathBuf {
        let path = self.root().join("manifest.toml");
        fs::write(&path, toml).expect("write manifest");
        path
    }

    /// Puts an extra executable in front of the real one on `PATH` for later runs.
    fn shim(&self, tool: &str, body: &str) {
        write_executable(&self.root().join("bin").join(tool), body);
    }

    fn run_with(&self, manifest: &Path, env: &[(&str, &str)]) -> Output {
        let path = format!(
            "{}:{}",
            self.root().join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut cmd = bash_script("testing/fetch-vectors.sh");
        cmd.arg(manifest)
            .arg(self.dest())
            .env("PATH", path)
            .env("FAKE_CURL_LOG", self.root().join("curl.log"))
            .env("VECTORS_GIT_BASE", self.root().join("remote"))
            .env(
                "VECTORS_RELEASE_BASE",
                format!("file://{}", self.root().join("releases").display()),
            )
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("PRESETS")
            .env_remove("INCLUDE_OPTIONAL")
            .env_remove("FAKE_CURL_FAIL");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().expect("run fetch-vectors.sh")
    }

    fn run(&self, manifest: &Path) -> Output {
        self.run_with(manifest, &[])
    }

    fn curl_calls(&self) -> Vec<String> {
        fs::read_to_string(self.root().join("curl.log"))
            .map(|log| log.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    fn reset_curl_log(&self) {
        let _ = fs::remove_file(self.root().join("curl.log"));
    }

    fn good_tar_manifest(&self) -> PathBuf {
        self.manifest(
            LIGHT_TAG,
            &self.tagged_commit,
            &[Asset::new(TAR, &self.tar_sha)],
        )
    }
}

fn manifest_toml(tag: &str, commit: &str, assets: &[Asset]) -> String {
    let mut toml = format!(
        "[[source]]\nname = \"demo\"\nrepo = \"{REPO}\"\ntag = \"{tag}\"\ncommit = \"{commit}\"\n"
    );
    for a in assets {
        toml.push_str(&format!(
            "\n  [[source.asset]]\n  file = \"{}\"\n  sha256 = \"{}\"\n  optional = {}\n",
            a.file, a.sha, a.optional
        ));
    }
    toml
}

fn assert_ok(out: &Output) {
    assert!(out.status.success(), "expected success:\n{}", describe(out));
}

fn assert_exit_1(out: &Output) {
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1:\n{}",
        describe(out)
    );
}

fn assert_failed(out: &Output) {
    assert!(
        !out.status.success(),
        "expected failure:\n{}",
        describe(out)
    );
}

#[test]
fn fetches_verifies_and_extracts_tar_and_zip() {
    let fx = Fixture::new();
    let m = fx.manifest(
        LIGHT_TAG,
        &fx.tagged_commit,
        &[Asset::new(TAR, &fx.tar_sha), Asset::new(ZIP, &fx.zip_sha)],
    );

    let out = fx.run(&m);

    assert_ok(&out);
    let dir = fx.out_dir(LIGHT_TAG);
    assert_eq!(
        fs::read_to_string(dir.join("demo").join(PAYLOAD)).unwrap(),
        "vector\n"
    );
    assert!(dir.join("bundle").join(PAYLOAD).is_file());
    assert!(dir.join(TAR).is_file(), "verified archive is kept");
    assert!(dir.join(ZIP).is_file(), "verified archive is kept");
    assert_eq!(
        fs::read_to_string(dir.join(format!(".{TAR}.ok")))
            .unwrap()
            .trim(),
        fx.tar_sha
    );
    assert_eq!(fx.curl_calls().len(), 2);
}

#[test]
fn zip_assets_extract_under_their_stem() {
    let fx = Fixture::new();
    let m = fx.manifest(
        LIGHT_TAG,
        &fx.tagged_commit,
        &[Asset::new(ZIP, &fx.zip_sha)],
    );

    let out = fx.run(&m);

    assert_ok(&out);
    assert!(fx.out_dir(LIGHT_TAG).join("bundle").join(PAYLOAD).is_file());
}

#[test]
fn annotated_tag_is_peeled_to_its_commit() {
    let fx = Fixture::new();
    let m = fx.manifest(
        ANNOTATED_TAG,
        &fx.tagged_commit,
        &[Asset::new(TAR, &fx.tar_sha)],
    );

    let out = fx.run(&m);

    assert_ok(&out);
    assert!(fx
        .out_dir(ANNOTATED_TAG)
        .join("demo")
        .join(PAYLOAD)
        .is_file());
}

#[test]
fn annotated_tag_pinned_to_tag_object_fails() {
    let fx = Fixture::new();
    let m = fx.manifest(
        ANNOTATED_TAG,
        &fx.annotated_tag_object,
        &[Asset::new(TAR, &fx.tar_sha)],
    );

    let out = fx.run(&m);

    assert_exit_1(&out);
    assert!(stderr(&out).contains("TAG MISMATCH"), "{}", describe(&out));
    assert!(fx.curl_calls().is_empty());
}

#[test]
fn tag_pointing_elsewhere_fails_before_any_download() {
    let fx = Fixture::new();
    let m = fx.manifest(LIGHT_TAG, &fx.old_commit, &[Asset::new(TAR, &fx.tar_sha)]);

    let out = fx.run(&m);

    assert_exit_1(&out);
    let err = stderr(&out);
    assert!(err.contains("TAG MISMATCH"), "{}", describe(&out));
    assert!(err.contains(&fx.old_commit) && err.contains(&fx.tagged_commit));
    assert!(
        fx.curl_calls().is_empty(),
        "no download after a tag mismatch"
    );
    assert_eq!(files_under(&fx.dest()), Vec::<PathBuf>::new());
}

#[test]
fn missing_tag_fails() {
    let fx = Fixture::new();
    let m = fx.manifest("v9.9.9", &fx.tagged_commit, &[Asset::new(TAR, &fx.tar_sha)]);

    let out = fx.run(&m);

    assert_exit_1(&out);
    assert!(
        stderr(&out).contains("TAG UNRESOLVED"),
        "{}",
        describe(&out)
    );
    assert!(fx.curl_calls().is_empty());
}

#[test]
fn unreachable_tag_remote_fails() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();
    let nowhere = fx.root().join("no-such-host");

    let out = fx.run_with(&m, &[("VECTORS_GIT_BASE", nowhere.to_str().unwrap())]);

    assert_exit_1(&out);
    assert!(
        stderr(&out).contains("TAG UNRESOLVED"),
        "{}",
        describe(&out)
    );
    assert!(fx.curl_calls().is_empty());
}

#[test]
fn corrupted_hash_prints_sha256_mismatch_and_unpacks_nothing() {
    let fx = Fixture::new();
    let m = fx.manifest(LIGHT_TAG, &fx.tagged_commit, &[Asset::new(TAR, WRONG_SHA)]);

    let out = fx.run(&m);

    assert_exit_1(&out);
    let err = stderr(&out);
    assert!(err.contains("SHA256 MISMATCH"), "{}", describe(&out));
    assert!(err.contains(WRONG_SHA) && err.contains(&fx.tar_sha));
    assert_eq!(
        files_under(&fx.dest()),
        Vec::<PathBuf>::new(),
        "no archive, partial download, stamp or extracted file may remain"
    );
    let calls = fx.curl_calls();
    assert_eq!(calls.len(), 1, "exactly one download attempt: {calls:?}");
    assert!(
        !calls[0].contains("--retry"),
        "curl must not retry: {calls:?}"
    );
}

#[test]
fn mismatch_stops_before_later_assets() {
    let fx = Fixture::new();
    let m = fx.manifest(
        LIGHT_TAG,
        &fx.tagged_commit,
        &[Asset::new(TAR, WRONG_SHA), Asset::new(ZIP, &fx.zip_sha)],
    );

    let out = fx.run(&m);

    assert_exit_1(&out);
    assert_eq!(fx.curl_calls().len(), 1, "no fallback to the next asset");
    assert_eq!(files_under(&fx.dest()), Vec::<PathBuf>::new());
}

#[test]
fn download_failure_is_not_retried() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();

    let out = fx.run_with(&m, &[("FAKE_CURL_FAIL", "1")]);

    assert_exit_1(&out);
    assert!(
        stderr(&out).contains("DOWNLOAD FAILED"),
        "{}",
        describe(&out)
    );
    assert_eq!(fx.curl_calls().len(), 1, "exactly one attempt");
    assert_eq!(files_under(&fx.dest()), Vec::<PathBuf>::new());
}

#[test]
fn missing_manifest_has_no_fallback() {
    let fx = Fixture::new();

    let out = fx.run(&fx.root().join("absent.toml"));

    assert_exit_1(&out);
    assert!(stderr(&out).contains("absent.toml"), "{}", describe(&out));
    assert!(fx.curl_calls().is_empty());
}

#[test]
fn invalid_manifest_entries_fail_closed() {
    let fx = Fixture::new();
    let c = fx.tagged_commit.as_str();
    let sha = fx.tar_sha.as_str();
    let cases = [
        (
            "placeholder sha256",
            manifest_toml(LIGHT_TAG, c, &[Asset::new(TAR, "TODO")]),
        ),
        (
            "short commit",
            manifest_toml(LIGHT_TAG, &c[..8], &[Asset::new(TAR, sha)]),
        ),
        (
            "branch, not a version tag",
            manifest_toml("main", c, &[Asset::new(TAR, sha)]),
        ),
        (
            "path traversal in file",
            manifest_toml(LIGHT_TAG, c, &[Asset::new("../x.tar.gz", sha)]),
        ),
        (
            "unsupported archive",
            manifest_toml(LIGHT_TAG, c, &[Asset::new("demo.tar.xz", sha)]),
        ),
        ("no assets", manifest_toml(LIGHT_TAG, c, &[])),
        ("no sources", "# empty\n".to_owned()),
        ("not TOML", "[[source]\n".to_owned()),
    ];
    for (what, toml) in cases {
        let out = fx.run(&fx.manifest_text(&toml));
        assert_failed(&out);
        assert!(fx.curl_calls().is_empty(), "{what}: nothing fetched");
        assert_eq!(files_under(&fx.dest()), Vec::<PathBuf>::new(), "{what}");
    }
}

#[test]
fn optional_assets_are_skipped_unless_requested() {
    let fx = Fixture::new();
    let m = fx.manifest(
        LIGHT_TAG,
        &fx.tagged_commit,
        &[Asset {
            optional: true,
            ..Asset::new(TAR, &fx.tar_sha)
        }],
    );

    let skipped = fx.run(&m);
    assert_ok(&skipped);
    assert!(stdout(&skipped).contains("skip optional"));
    assert!(fx.curl_calls().is_empty());

    let fetched = fx.run_with(&m, &[("INCLUDE_OPTIONAL", "1")]);
    assert_ok(&fetched);
    assert_eq!(fx.curl_calls().len(), 1);
}

#[test]
fn cached_archive_is_rehashed_instead_of_trusting_the_stamp() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();
    assert_ok(&fx.run(&m));
    fx.reset_curl_log();

    let out = fx.run(&m);

    assert_ok(&out);
    assert!(stdout(&out).contains("re-hashed"), "{}", describe(&out));
    assert!(
        fx.curl_calls().is_empty(),
        "verified cache needs no download"
    );
}

#[test]
fn tampered_cached_archive_fails_even_with_a_valid_stamp() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();
    assert_ok(&fx.run(&m));
    fx.reset_curl_log();
    let dir = fx.out_dir(LIGHT_TAG);
    fs::write(dir.join(TAR), "poisoned cache entry").unwrap();

    let out = fx.run(&m);

    assert_exit_1(&out);
    assert!(
        stderr(&out).contains("SHA256 MISMATCH"),
        "{}",
        describe(&out)
    );
    assert!(fx.curl_calls().is_empty(), "no silent re-download fallback");
    assert_eq!(
        files_under(&fx.dest()),
        Vec::<PathBuf>::new(),
        "poisoned archive, stamp and tree are removed"
    );
}

#[test]
fn stamp_without_archive_is_refetched_and_rehashed() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();
    assert_ok(&fx.run(&m));
    fx.reset_curl_log();
    let dir = fx.out_dir(LIGHT_TAG);
    // A cache that restored only the stamp and the tree, with tampered content.
    fs::remove_file(dir.join(TAR)).unwrap();
    fs::write(dir.join("demo").join(PAYLOAD), "tampered\n").unwrap();

    let out = fx.run(&m);

    assert_ok(&out);
    assert_eq!(fx.curl_calls().len(), 1, "stamp alone is not trusted");
    assert_eq!(
        fs::read_to_string(dir.join("demo").join(PAYLOAD)).unwrap(),
        "vector\n",
        "tree is re-extracted from the verified archive"
    );
}

#[test]
fn stamp_for_another_hash_is_stale() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();
    assert_ok(&fx.run(&m));
    fx.reset_curl_log();
    fs::write(fx.out_dir(LIGHT_TAG).join(format!(".{TAR}.ok")), WRONG_SHA).unwrap();

    let out = fx.run(&m);

    assert_ok(&out);
    assert_eq!(fx.curl_calls().len(), 1);
}

#[test]
fn missing_tree_is_re_extracted_from_the_re_hashed_archive() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();
    assert_ok(&fx.run(&m));
    fx.reset_curl_log();
    let tree = fx.out_dir(LIGHT_TAG).join("demo");
    fs::remove_dir_all(&tree).unwrap();

    let out = fx.run(&m);

    assert_ok(&out);
    assert!(
        fx.curl_calls().is_empty(),
        "the kept archive re-hashed fine"
    );
    assert!(tree.join(PAYLOAD).is_file());
}

#[test]
fn presets_filter_consensus_specs_assets_by_stem() {
    let fx = Fixture::new();
    let toml = manifest_toml(
        LIGHT_TAG,
        &fx.tagged_commit,
        &[Asset::new(TAR, &fx.tar_sha), Asset::new(ZIP, &fx.zip_sha)],
    )
    .replace("name = \"demo\"", "name = \"consensus-specs\"");
    let m = fx.manifest_text(&toml);

    let out = fx.run_with(&m, &[("PRESETS", "general bundle")]);

    assert_ok(&out);
    assert!(stdout(&out).contains(&format!("skip preset {TAR}")));
    let calls = fx.curl_calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].ends_with(ZIP), "{calls:?}");
    let dir = fx.dest().join("consensus-specs").join(LIGHT_TAG);
    assert!(dir.join("bundle").join(PAYLOAD).is_file());
    assert!(!dir.join("demo").exists());
}

#[test]
fn tampered_tree_is_re_extracted_even_with_a_valid_stamp_and_archive() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();
    assert_ok(&fx.run(&m));
    fx.reset_curl_log();
    let tree = fx.out_dir(LIGHT_TAG).join("demo");
    fs::write(tree.join(PAYLOAD), "edited fixture\n").unwrap();
    fs::write(tree.join("case/injected.txt"), "extra case\n").unwrap();

    let out = fx.run(&m);

    assert_ok(&out);
    assert!(fx.curl_calls().is_empty(), "archive re-hashed, no download");
    assert_eq!(fs::read_to_string(tree.join(PAYLOAD)).unwrap(), "vector\n");
    assert!(!tree.join("case/injected.txt").exists(), "tree replaced");
}

#[test]
fn another_runs_temp_files_are_left_alone() {
    let fx = Fixture::new();
    let dir = fx.out_dir(LIGHT_TAG);
    fs::create_dir_all(dir.join(".demo.extracting")).unwrap();
    fs::write(dir.join(format!("{TAR}.part")), "other run").unwrap();
    fs::write(dir.join(".demo.extracting/marker"), "other run").unwrap();

    let out = fx.run(&fx.good_tar_manifest());

    assert_ok(&out);
    assert_eq!(
        fs::read_to_string(dir.join(format!("{TAR}.part"))).unwrap(),
        "other run"
    );
    assert!(dir.join(".demo.extracting/marker").is_file());
    assert!(dir.join("demo").join(PAYLOAD).is_file());
}

#[test]
fn asset_locked_by_another_run_fails_closed() {
    let fx = Fixture::new();
    let lock = fx.out_dir(LIGHT_TAG).join(format!(".{TAR}.lock"));
    fs::create_dir_all(&lock).unwrap();

    let out = fx.run(&fx.good_tar_manifest());

    assert_exit_1(&out);
    assert!(stderr(&out).contains("LOCKED"), "{}", describe(&out));
    assert!(fx.curl_calls().is_empty());
    assert!(lock.is_dir(), "a lock we did not take is not removed");
}

#[test]
fn lock_is_released_after_success_and_after_failure() {
    let fx = Fixture::new();
    let lock = fx.out_dir(LIGHT_TAG).join(format!(".{TAR}.lock"));
    assert_ok(&fx.run(&fx.good_tar_manifest()));
    assert!(!lock.exists());

    let bad = fx.manifest(LIGHT_TAG, &fx.tagged_commit, &[Asset::new(TAR, WRONG_SHA)]);
    assert_exit_1(&fx.run(&bad));
    assert!(!lock.exists());
}

#[test]
fn tags_are_checked_only_for_sources_with_a_selected_asset() {
    let fx = Fixture::new();
    // "extra" pins the wrong commit, but its only asset is optional.
    let extra = manifest_toml(
        LIGHT_TAG,
        &fx.old_commit,
        &[Asset {
            optional: true,
            ..Asset::new(ZIP, &fx.zip_sha)
        }],
    )
    .replace("name = \"demo\"", "name = \"extra\"");
    let toml = format!(
        "{}\n{extra}",
        manifest_toml(
            LIGHT_TAG,
            &fx.tagged_commit,
            &[Asset::new(TAR, &fx.tar_sha)]
        )
    );
    let m = fx.manifest_text(&toml);

    let skipped = fx.run(&m);
    assert_ok(&skipped);
    assert!(!stdout(&skipped).contains("tag ok extra"));

    let selected = fx.run_with(&m, &[("INCLUDE_OPTIONAL", "1")]);
    assert_exit_1(&selected);
    assert!(
        stderr(&selected).contains("TAG MISMATCH extra"),
        "{}",
        describe(&selected)
    );
}

fn dead_pid() -> u32 {
    let mut child = Command::new("true").spawn().expect("spawn true");
    let pid = child.id();
    child.wait().expect("wait");
    pid
}

#[test]
fn lock_left_by_a_dead_run_is_taken_over() {
    let fx = Fixture::new();
    let lock = fx.out_dir(LIGHT_TAG).join(format!(".{TAR}.lock"));
    fs::create_dir_all(&lock).unwrap();
    fs::write(lock.join("pid"), format!("{}\n", dead_pid())).unwrap();

    let out = fx.run(&fx.good_tar_manifest());

    assert_ok(&out);
    assert!(stderr(&out).contains("stale lock"), "{}", describe(&out));
    assert!(!lock.exists(), "lock released after the run");
    assert!(fx.out_dir(LIGHT_TAG).join("demo").join(PAYLOAD).is_file());
}

#[test]
fn lock_held_by_a_live_process_fails_closed() {
    let fx = Fixture::new();
    let lock = fx.out_dir(LIGHT_TAG).join(format!(".{TAR}.lock"));
    fs::create_dir_all(&lock).unwrap();
    fs::write(lock.join("pid"), format!("{}\n", std::process::id())).unwrap();

    let out = fx.run(&fx.good_tar_manifest());

    assert_exit_1(&out);
    assert!(stderr(&out).contains("LOCKED"), "{}", describe(&out));
    assert!(fx.curl_calls().is_empty());
    assert_eq!(
        fs::read_to_string(lock.join("pid")).unwrap().trim(),
        std::process::id().to_string(),
        "a live owner's lock is untouched"
    );
}

#[test]
fn failed_swap_keeps_the_previous_tree() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();
    assert_ok(&fx.run(&m));
    let real_mv = checked(Command::new("sh").args(["-c", "command -v mv"]));
    // Refuse only the move of a freshly extracted tree into place.
    fx.shim(
        "mv",
        &format!(
            "#!/bin/sh\ncase \"$1\" in *.extracting.*) echo 'mv: refused' >&2; exit 1;; esac\nexec '{real_mv}' \"$@\"\n"
        ),
    );

    let out = fx.run(&m);

    assert_exit_1(&out);
    let dir = fx.out_dir(LIGHT_TAG);
    assert_eq!(
        fs::read_to_string(dir.join("demo").join(PAYLOAD)).unwrap(),
        "vector\n",
        "{}",
        describe(&out)
    );
    let leftovers: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".old.") || n.contains(".extracting.") || n.ends_with(".lock"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}
