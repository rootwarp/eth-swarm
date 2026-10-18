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
        self.command(manifest, env)
            .output()
            .expect("run fetch-vectors.sh")
    }

    fn command(&self, manifest: &Path, env: &[(&str, &str)]) -> Command {
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
            .env_remove("FAKE_CURL_FAIL")
            .env_remove("FETCH_VECTORS_TEST")
            .env_remove("FETCH_VECTORS_LOCK_HOOK");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd
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

/// What a failed run left under `dest`, apart from the empty per-asset `.<file>.lockf` files,
/// which are kept on purpose (deleting a file that others may be waiting to flock reopens the
/// race it guards against).
fn leftovers(dest: &Path) -> Vec<PathBuf> {
    files_under(dest)
        .into_iter()
        .filter(|f| {
            let is_lockf = f.extension().is_some_and(|e| e == "lockf");
            !(is_lockf && fs::metadata(dest.join(f)).unwrap().len() == 0)
        })
        .collect()
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
        leftovers(&fx.dest()),
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
    assert_eq!(leftovers(&fx.dest()), Vec::<PathBuf>::new());
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
    assert_eq!(leftovers(&fx.dest()), Vec::<PathBuf>::new());
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
        leftovers(&fx.dest()),
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
    write_lock(&lock, dead_pid(), &our_host(), &our_pidns());

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

/// `uname -n` of this machine, as the script records it next to the PID.
fn our_host() -> String {
    checked(Command::new("uname").arg("-n"))
}

/// The PID namespace of this process (and of the script it spawns), or `none` without `/proc`.
fn our_pidns() -> String {
    fs::read_link("/proc/self/ns/pid")
        .map(|l| l.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "none".to_owned())
}

/// A lock directory as a run on `host` in PID namespace `pidns` leaves it.
fn write_lock(lock: &Path, pid: u32, host: &str, pidns: &str) {
    fs::create_dir_all(lock).unwrap();
    fs::write(lock.join("pid"), format!("{pid}\n")).unwrap();
    fs::write(lock.join("host"), format!("{host}\n")).unwrap();
    fs::write(lock.join("pidns"), format!("{pidns}\n")).unwrap();
}

/// Drives concurrent runs through `FETCH_VECTORS_LOCK_HOOK`: each run logs `<run> <stage>`
/// and, for the stages named in its `HOLD`, waits until the test writes `go.<run>.<stage>`.
struct Choreography {
    ctl: PathBuf,
    hook: PathBuf,
}

impl Choreography {
    fn new(fx: &Fixture) -> Self {
        let ctl = fx.root().join("ctl");
        fs::create_dir_all(&ctl).unwrap();
        let hook = fx.root().join("lock-hook");
        write_executable(
            &hook,
            "#!/bin/sh\n\
             echo \"$RUN $1\" >> \"$CTL/events\"\n\
             case \" $HOLD \" in *\" $1 \"*)\n\
             \x20 n=0\n\
             \x20 while [ ! -e \"$CTL/go.$RUN.$1\" ]; do\n\
             \x20   n=$((n + 1)); [ \"$n\" -lt 1500 ] || exit 1; sleep 0.02\n\
             \x20 done;;\n\
             esac\n",
        );
        Self { ctl, hook }
    }

    fn spawn(&self, fx: &Fixture, manifest: &Path, run: &str, hold: &str) -> std::process::Child {
        let hook = self.hook.to_str().unwrap();
        let ctl = self.ctl.to_str().unwrap();
        fx.command(
            manifest,
            &[
                ("FETCH_VECTORS_TEST", "1"),
                ("FETCH_VECTORS_LOCK_HOOK", hook),
                ("CTL", ctl),
                ("RUN", run),
                ("HOLD", hold),
            ],
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn fetch-vectors.sh")
    }

    fn events(&self) -> Vec<String> {
        fs::read_to_string(self.ctl.join("events"))
            .map(|log| log.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    fn go(&self, run: &str, stage: &str) {
        fs::write(self.ctl.join(format!("go.{run}.{stage}")), "").unwrap();
    }

    /// Waits until one of `events` was logged or `child` exited; panics after 20 s.
    fn wait_for(&self, events: &[&str], child: &mut std::process::Child) {
        for _ in 0..1000 {
            let seen = self.events();
            if events.iter().any(|e| seen.iter().any(|s| s == e)) {
                return;
            }
            if child.try_wait().expect("try_wait").is_some() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!(
            "timed out waiting for {events:?}; events so far: {:?}",
            self.events()
        );
    }
}

#[test]
fn concurrent_reclaims_of_a_stale_lock_leave_exactly_one_owner() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();
    let dir = fx.out_dir(LIGHT_TAG);
    let lock = dir.join(format!(".{TAR}.lock"));
    write_lock(&lock, dead_pid(), &our_host(), &our_pidns());
    let ch = Choreography::new(&fx);

    // A and B both find the dead owner. A is paused before it reclaims; B either read the
    // same dead PID too or is queued behind A's kernel lock.
    let mut a = ch.spawn(&fx, &m, "A", "read owned");
    ch.wait_for(&["A read"], &mut a);
    let mut b = ch.spawn(&fx, &m, "B", "read renamed");
    ch.wait_for(&["B read", "B waiting"], &mut b);
    // A takes the lock over and keeps it.
    ch.go("A", "read");
    ch.wait_for(&["A owned"], &mut a);
    // B goes on with what it read earlier, then C arrives while B is mid-reclaim.
    ch.go("B", "read");
    ch.wait_for(&["B renamed"], &mut b);
    let mut c = ch.spawn(&fx, &m, "C", "owned");
    ch.wait_for(&["C owned"], &mut c);
    ch.go("B", "renamed");
    let b_out = b.wait_with_output().unwrap();
    for run in ["A", "C"] {
        ch.go(run, "owned");
    }
    let a_out = a.wait_with_output().unwrap();
    let c_out = c.wait_with_output().unwrap();

    let owners: Vec<_> = ch
        .events()
        .into_iter()
        .filter(|e| e.ends_with(" owned"))
        .collect();
    let runs = [("A", &a_out), ("B", &b_out), ("C", &c_out)];
    let all: String = runs
        .iter()
        .map(|(r, o)| format!("=== {r}\n{}\n", describe(o)))
        .collect();
    assert_eq!(owners, ["A owned"], "only A may hold the lock\n{all}");
    assert_ok(&a_out);
    for (run, out) in &runs[1..] {
        assert_exit_1(out);
        assert!(stderr(out).contains("LOCKED"), "{run}\n{all}");
    }
    assert!(!lock.exists(), "A released its lock\n{all}");
    assert!(dir.join("demo").join(PAYLOAD).is_file());
}

#[test]
fn kernel_lock_held_too_long_fails_closed() {
    let fx = Fixture::new();
    let dir = fx.out_dir(LIGHT_TAG);
    fs::create_dir_all(&dir).unwrap();
    let lockf = dir.join(format!(".{TAR}.lockf"));
    let mut holder = Command::new("python3")
        .args([
            "-I",
            "-c",
            "import fcntl, sys, time\n\
             f = open(sys.argv[1], 'a')\n\
             fcntl.flock(f, fcntl.LOCK_EX)\n\
             print('locked', flush=True)\n\
             time.sleep(30)\n",
        ])
        .arg(&lockf)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn flock holder");
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(holder.stdout.take().unwrap()),
        &mut line,
    )
    .unwrap();
    assert_eq!(line.trim(), "locked");

    let out = fx.run_with(
        &fx.good_tar_manifest(),
        &[("FETCH_VECTORS_LOCK_WAIT", "0.2")],
    );
    holder.kill().unwrap();
    holder.wait().unwrap();

    assert_exit_1(&out);
    assert!(stderr(&out).contains("LOCKED"), "{}", describe(&out));
    assert!(stderr(&out).contains("timed out"), "{}", describe(&out));
    assert!(fx.curl_calls().is_empty());
    assert!(!dir.join(format!(".{TAR}.lock")).exists());
}

#[test]
fn malformed_lock_wait_is_rejected_before_anything_runs() {
    let fx = Fixture::new();

    let out = fx.run_with(
        &fx.good_tar_manifest(),
        &[("FETCH_VECTORS_LOCK_WAIT", "soon")],
    );

    assert_exit_1(&out);
    assert!(
        stderr(&out).contains("FETCH_VECTORS_LOCK_WAIT"),
        "{}",
        describe(&out)
    );
    assert!(fx.curl_calls().is_empty());
    assert_eq!(files_under(&fx.dest()), Vec::<PathBuf>::new());
}

/// Runs against a lock left by `pid` on `host` in `pidns`, and checks it failed closed and
/// left that lock exactly as it was.
fn assert_foreign_lock_is_kept(host: &str, pidns: &str, needle: &str) {
    let fx = Fixture::new();
    let lock = fx.out_dir(LIGHT_TAG).join(format!(".{TAR}.lock"));
    let pid = dead_pid();
    write_lock(&lock, pid, host, pidns);

    let out = fx.run(&fx.good_tar_manifest());

    assert_exit_1(&out);
    let err = stderr(&out);
    assert!(
        err.contains("LOCKED") && err.contains(needle),
        "{}",
        describe(&out)
    );
    assert!(!err.contains("stale lock"), "{}", describe(&out));
    assert!(fx.curl_calls().is_empty());
    for (file, want) in [
        ("pid", pid.to_string()),
        ("host", host.into()),
        ("pidns", pidns.into()),
    ] {
        assert_eq!(
            fs::read_to_string(lock.join(file)).unwrap().trim(),
            want,
            "{file}"
        );
    }
}

#[test]
fn lock_from_another_host_is_never_taken_over() {
    assert_foreign_lock_is_kept("other-host.invalid", &our_pidns(), "other-host.invalid");
}

#[test]
fn lock_from_another_pid_namespace_is_never_taken_over() {
    assert_foreign_lock_is_kept(&our_host(), "pid:[1]", "pid:[1]");
}

#[test]
fn lock_without_its_owner_identity_fails_closed() {
    let fx = Fixture::new();
    let lock = fx.out_dir(LIGHT_TAG).join(format!(".{TAR}.lock"));
    fs::create_dir_all(&lock).unwrap();
    fs::write(lock.join("pid"), format!("{}\n", dead_pid())).unwrap();

    let out = fx.run(&fx.good_tar_manifest());

    assert_exit_1(&out);
    assert!(stderr(&out).contains("LOCKED"), "{}", describe(&out));
    assert!(fx.curl_calls().is_empty());
    assert!(
        lock.join("pid").is_file(),
        "the lock is left for manual removal"
    );
}

#[test]
fn a_run_arriving_mid_release_waits_instead_of_failing() {
    let fx = Fixture::new();
    let m = fx.good_tar_manifest();
    let lock = fx.out_dir(LIGHT_TAG).join(format!(".{TAR}.lock"));
    let ch = Choreography::new(&fx);

    // A pauses half-way through releasing its lock: its PID is gone, the directory is not.
    let mut a = ch.spawn(&fx, &m, "A", "releasing");
    ch.wait_for(&["A releasing"], &mut a);
    assert!(lock.is_dir() && !lock.join("pid").exists());
    // B arrives then and must wait for the release instead of reading a half-removed lock.
    let mut b = ch.spawn(&fx, &m, "B", "");
    ch.wait_for(&["B waiting"], &mut b);
    std::thread::sleep(std::time::Duration::from_millis(300));
    ch.go("A", "releasing");
    let a_out = a.wait_with_output().unwrap();
    let b_out = b.wait_with_output().unwrap();

    let all = format!("=== A\n{}\n=== B\n{}", describe(&a_out), describe(&b_out));
    assert_ok(&a_out);
    assert_ok(&b_out);
    assert!(!stderr(&b_out).contains("LOCKED"), "{all}");
    assert!(ch.events().iter().any(|e| e == "B owned"), "{all}");
    assert!(!lock.exists(), "{all}");
}

#[test]
fn lock_hook_runs_only_in_test_mode() {
    let fx = Fixture::new();
    let marker = fx.root().join("hook-ran");
    let hook = fx.root().join("failing-hook");
    write_executable(
        &hook,
        &format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
    );
    let hook = hook.to_str().unwrap();

    let out = fx.run_with(
        &fx.good_tar_manifest(),
        &[("FETCH_VECTORS_LOCK_HOOK", hook)],
    );
    assert_ok(&out);
    assert!(!marker.exists(), "{}", describe(&out));
    assert!(
        stderr(&out).contains("ignoring FETCH_VECTORS_LOCK_HOOK"),
        "{}",
        describe(&out)
    );

    let out = fx.run_with(
        &fx.good_tar_manifest(),
        &[
            ("FETCH_VECTORS_LOCK_HOOK", hook),
            ("FETCH_VECTORS_TEST", "1"),
        ],
    );
    assert_exit_1(&out);
    assert!(marker.exists());
    assert!(
        stderr(&out).contains("lock hook failed"),
        "{}",
        describe(&out)
    );
}

#[test]
fn a_hook_failing_mid_release_still_releases_the_lock() {
    let fx = Fixture::new();
    let lock = fx.out_dir(LIGHT_TAG).join(format!(".{TAR}.lock"));
    let hook = fx.root().join("release-hook");
    write_executable(&hook, "#!/bin/sh\n[ \"$1\" != releasing ]\n");

    let out = fx.run_with(
        &fx.good_tar_manifest(),
        &[
            ("FETCH_VECTORS_LOCK_HOOK", hook.to_str().unwrap()),
            ("FETCH_VECTORS_TEST", "1"),
        ],
    );

    assert_exit_1(&out);
    assert!(
        stderr(&out).contains("lock hook failed at releasing"),
        "{}",
        describe(&out)
    );
    assert!(!lock.exists(), "{}", describe(&out));
}

#[test]
fn taken_lock_records_pid_host_and_pid_namespace() {
    let fx = Fixture::new();
    let lock = fx.out_dir(LIGHT_TAG).join(format!(".{TAR}.lock"));
    let ch = Choreography::new(&fx);
    let mut run = ch.spawn(&fx, &fx.good_tar_manifest(), "A", "owned");
    ch.wait_for(&["A owned"], &mut run);

    let read = |f: &str| fs::read_to_string(lock.join(f)).map(|s| s.trim().to_owned());
    let recorded = (read("pid"), read("host"), read("pidns"));
    ch.go("A", "owned");
    let out = run.wait_with_output().unwrap();

    assert_ok(&out);
    let (pid, host, pidns) = recorded;
    assert!(pid.unwrap().parse::<u32>().is_ok());
    assert_eq!(host.unwrap(), our_host());
    assert_eq!(pidns.unwrap(), our_pidns());
}
