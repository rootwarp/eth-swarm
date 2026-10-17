//! On-disk pubkey cache: reload on restart, full rebuild on any mismatch, owner and mode checks,
//! atomic replace.
//!
//! The other-owner cases need root (to `chown` a file to a second UID). They skip with a message
//! when not root, and are mandatory when `ETHSWARM_ROOT_TESTS=1` (the `root-tests` CI job), which
//! also provides the throwaway user's UID in `ETHSWARM_OTHER_UID`.

mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use cl_verify_cache::persist::{
    effective_uid, load_with, save_with, stage_with, startup_with, RebuildReason, Registry,
    Startup, StartupError, REBUILD_CHUNK_ENTRIES,
};
use common::{cache_of, contents, keys, TestCodec, TestKey, VecFeed};

/// Size of the fixed header that precedes the 96-byte points.
const HEADER: usize = 84;

/// A temp file left behind by an earlier cl-verify process that crashed while staging.
const STALE_TMP: &str = "pubkeys.bin.tmp.4242.7";

/// Every staged-snapshot temp file in `dir`, sorted.
fn temps(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("pubkeys.bin.tmp."))
        })
        .collect();
    found.sort();
    found
}

/// Runs `load_with` on another thread and fails the test if it does not return within 5 s.
fn reason_within_5s(path: &Path, expected: &[TestKey]) -> RebuildReason {
    let (tx, rx) = std::sync::mpsc::channel();
    let (path, expected) = (path.to_path_buf(), expected.to_vec());
    std::thread::spawn(move || {
        let _ = tx.send(reason(&path, &expected));
    });
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .expect("load_with blocked on the snapshot path")
}

fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo {}", path.display());
}

fn dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pubkeys.bin");
    (dir, path)
}

fn saved(keys: &[TestKey]) -> (tempfile::TempDir, PathBuf) {
    let (dir, path) = dir();
    save_with(&TestCodec, &cache_of(keys), &path).unwrap();
    (dir, path)
}

fn registry(keys: &[TestKey]) -> Registry {
    Registry::of(&TestCodec, keys)
}

fn reason(path: &Path, expected: &[TestKey]) -> RebuildReason {
    match load_with(&TestCodec, path, &registry(expected)) {
        Startup::Rebuild(reason) => reason,
        Startup::Use(c) => panic!("expected a rebuild, loaded {} entries", c.high_water()),
    }
}

/// Restarts against `feed` and checks the cache served afterwards is exactly the feed's registry.
fn restart_rebuilds(path: &Path, feed_keys: &[TestKey]) -> RebuildReason {
    let mut feed = VecFeed::honest(feed_keys.to_vec());
    let restored = startup_with(&TestCodec, path, &mut feed).unwrap();
    assert_eq!(contents(&restored.cache), feed_keys, "served cache = feed");
    assert_eq!(
        feed.requests.first().map(|r| r.0),
        Some(0),
        "rebuild from 0"
    );
    restored.rebuilt.expect("a full rebuild, not a reload")
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The second UID for the other-owner cases, or `None` (skip) when not running as root.
fn other_uid(test: &str) -> Option<u32> {
    let required = std::env::var("ETHSWARM_ROOT_TESTS").is_ok_and(|v| v == "1");
    let uid = std::env::var("ETHSWARM_OTHER_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    match (effective_uid(), uid) {
        (0, Some(uid)) if uid != 0 => Some(uid),
        (euid, uid) => {
            let why = format!(
                "{test}: needs root and ETHSWARM_OTHER_UID (euid {euid}, ETHSWARM_OTHER_UID {uid:?})"
            );
            assert!(!required, "{why}; mandatory with ETHSWARM_ROOT_TESTS=1");
            eprintln!("SKIPPED {why}");
            None
        }
    }
}

// (a) The persisted cache is reloaded on restart.

#[test]
fn persist_reload_after_restart() {
    let registry_keys = keys(1, 10_000);
    let (_dir, path) = saved(&registry_keys);
    let mut feed = VecFeed::honest(registry_keys.clone());
    let restored = startup_with(&TestCodec, &path, &mut feed).unwrap();
    assert_eq!(restored.rebuilt, None, "loaded from the file");
    assert_eq!(contents(&restored.cache), registry_keys);
    assert!(feed.requests.is_empty(), "no feed ranges needed");
}

#[test]
fn persist_reload_of_an_empty_registry() {
    let (_dir, path) = saved(&[]);
    let restored = startup_with(&TestCodec, &path, &mut VecFeed::honest(vec![])).unwrap();
    assert_eq!((restored.rebuilt, restored.cache.high_water()), (None, 0));
}

// (b) A registry length or sha256 mismatch triggers a full rebuild, never partial use.

#[test]
fn persist_registry_length_mismatch_rebuilds() {
    let file_keys = keys(1, 100);
    let (_dir, path) = saved(&file_keys);
    for chain_len in [99, 101, 5_000] {
        let chain = keys(1, chain_len);
        assert_eq!(
            reason(&path, &chain),
            RebuildReason::LengthMismatch {
                file: 100,
                chain: chain_len
            }
        );
        assert!(matches!(
            restart_rebuilds(&path, &chain),
            RebuildReason::LengthMismatch { file: 100, .. }
        ));
    }
}

#[test]
fn persist_registry_sha256_mismatch_rebuilds() {
    let file_keys = keys(1, 100);
    let (_dir, path) = saved(&file_keys);
    // Same length, one key differs (a competing registry): the file is not used at all.
    let mut chain = file_keys.clone();
    chain[57] = common::key(2, 57);
    assert_eq!(reason(&path, &chain), RebuildReason::RootMismatch);
    assert_eq!(restart_rebuilds(&path, &chain), RebuildReason::RootMismatch);
}

#[test]
fn persist_missing_file_rebuilds_in_4096_entry_chunks() {
    let (_dir, path) = dir();
    let chain = keys(1, 10_000);
    let mut feed = VecFeed::honest(chain.clone());
    let restored = startup_with(&TestCodec, &path, &mut feed).unwrap();
    assert_eq!(restored.rebuilt, Some(RebuildReason::Missing));
    assert_eq!(contents(&restored.cache), chain);
    assert_eq!(REBUILD_CHUNK_ENTRIES, 4_096);
    assert_eq!(
        feed.requests,
        [(0, 4_096), (4_096, 4_096), (8_192, 1_808)],
        "chunked from index 0, never past the registry"
    );
}

#[test]
fn persist_missing_first_feed_response_is_a_contract_violation() {
    let (_dir, path) = saved(&keys(1, 10));
    let mut feed = VecFeed::honest(keys(1, 10));
    feed.registry = None;
    let err = startup_with(&TestCodec, &path, &mut feed).unwrap_err();
    assert!(matches!(err, StartupError::MissingRegistry));
    assert!(err.is_contract_violation());
    assert!(feed.requests.is_empty());
}

#[test]
fn persist_feed_that_breaks_its_registry_yields_no_cache() {
    let (_dir, path) = dir();
    // Announces registry A but serves B: the rebuilt cache is discarded, never served.
    let mut feed = VecFeed::honest(keys(1, 5_000));
    feed.keys = keys(2, 5_000);
    let err = startup_with(&TestCodec, &path, &mut feed).unwrap_err();
    assert!(matches!(err, StartupError::RegistryMismatch), "{err}");
    assert!(err.is_contract_violation());
}

#[test]
fn persist_feed_short_of_its_registry_yields_no_cache() {
    let (_dir, path) = dir();
    let mut feed = VecFeed::honest(keys(1, 5_000));
    feed.keys.truncate(4_500);
    let err = startup_with(&TestCodec, &path, &mut feed).unwrap_err();
    assert!(
        matches!(err, StartupError::EmptyRange { start: 4_500 }),
        "{err}"
    );
    assert!(err.is_contract_violation());
}

#[test]
fn persist_feed_errors_are_passed_through() {
    struct Broken;
    impl cl_verify_cache::persist::RegistryFeed for Broken {
        type Key = TestKey;
        type Error = &'static str;
        fn registry(&mut self) -> Result<Option<Registry>, &'static str> {
            Err("stream reset")
        }
        fn range(&mut self, _: u64, _: usize) -> Result<Vec<TestKey>, &'static str> {
            unreachable!()
        }
    }
    let (_dir, path) = dir();
    let err = startup_with(&TestCodec, &path, &mut Broken).unwrap_err();
    assert!(matches!(err, StartupError::Feed("stream reset")));
    assert!(!err.is_contract_violation());
}

// persist_mode_owner: saved 0600 and owned by us; any other mode or owner is never loaded.

#[test]
fn persist_mode_owner_saved_file_is_0600_and_ours() {
    let (dir, path) = dir();
    // A stale temp file with loose permissions must not leak its mode into the snapshot.
    let tmp = dir.path().join(STALE_TMP);
    std::fs::write(&tmp, b"stale").unwrap();
    set_mode(&tmp, 0o644);
    save_with(&TestCodec, &cache_of(&keys(1, 10)), &path).unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o600);
    assert_eq!(meta.uid(), effective_uid());
    assert!(!tmp.exists(), "stale temp file removed");
    assert_eq!(
        temps(dir.path()),
        Vec::<PathBuf>::new(),
        "own temp renamed into place"
    );
}

#[test]
fn persist_mode_owner_other_modes_rebuild() {
    let registry_keys = keys(1, 10);
    let (_dir, path) = saved(&registry_keys);
    for mode in [0o644, 0o640, 0o604, 0o660, 0o700, 0o400, 0o4600] {
        set_mode(&path, mode);
        assert_eq!(
            reason(&path, &registry_keys),
            RebuildReason::WrongMode { mode },
            "mode {mode:o}"
        );
        assert_eq!(
            restart_rebuilds(&path, &registry_keys),
            RebuildReason::WrongMode { mode }
        );
    }
    set_mode(&path, 0o600);
    assert!(matches!(
        load_with(&TestCodec, &path, &registry(&registry_keys)),
        Startup::Use(_)
    ));
}

#[test]
fn persist_mode_owner_other_owner_rebuilds() {
    let Some(other) = other_uid("persist_mode_owner_other_owner_rebuilds") else {
        return;
    };
    let registry_keys = keys(1, 10);
    let (_dir, path) = saved(&registry_keys);
    std::os::unix::fs::chown(&path, Some(other), None).unwrap();
    set_mode(&path, 0o600);
    let expected = RebuildReason::WrongOwner {
        file: other,
        expected: effective_uid(),
    };
    assert_eq!(reason(&path, &registry_keys), expected);
    assert_eq!(restart_rebuilds(&path, &registry_keys), expected);
}

#[test]
fn persist_mode_owner_save_replaces_a_foreign_file() {
    let Some(other) = other_uid("persist_mode_owner_save_replaces_a_foreign_file") else {
        return;
    };
    let (dir, path) = dir();
    let tmp = dir.path().join(STALE_TMP);
    for p in [&path, &tmp] {
        std::fs::write(p, b"foreign").unwrap();
        std::os::unix::fs::chown(p, Some(other), None).unwrap();
        set_mode(p, 0o644);
    }
    let registry_keys = keys(1, 10);
    save_with(&TestCodec, &cache_of(&registry_keys), &path).unwrap();
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!((meta.uid(), meta.mode() & 0o7777), (effective_uid(), 0o600));
    assert!(matches!(
        load_with(&TestCodec, &path, &registry(&registry_keys)),
        Startup::Use(c) if contents(&c) == registry_keys
    ));
}

// persist_truncated_rebuilds: truncation, a flipped body byte or an unknown version.

#[test]
fn persist_truncated_rebuilds() {
    let registry_keys = keys(1, 100);
    let (_dir, path) = saved(&registry_keys);
    let full = std::fs::read(&path).unwrap();
    assert_eq!(full.len(), HEADER + 100 * 96);
    for cut in [0, 7, 11, 12, HEADER - 1] {
        std::fs::write(&path, &full[..cut]).unwrap();
        assert_eq!(
            reason(&path, &registry_keys),
            RebuildReason::ShortHeader,
            "cut {cut}"
        );
        assert_eq!(
            restart_rebuilds(&path, &registry_keys),
            RebuildReason::ShortHeader
        );
    }
    for cut in [HEADER, HEADER + 95, HEADER + 96, full.len() - 1] {
        std::fs::write(&path, &full[..cut]).unwrap();
        let expected = RebuildReason::SizeMismatch {
            expected: full.len() as u64,
            actual: cut as u64,
        };
        assert_eq!(reason(&path, &registry_keys), expected, "cut {cut}");
        assert_eq!(restart_rebuilds(&path, &registry_keys), expected);
    }
    let mut longer = full.clone();
    longer.push(0);
    std::fs::write(&path, &longer).unwrap();
    assert!(matches!(
        reason(&path, &registry_keys),
        RebuildReason::SizeMismatch { .. }
    ));
}

#[test]
fn persist_flipped_body_byte_rebuilds() {
    let registry_keys = keys(1, 100);
    let (_dir, path) = saved(&registry_keys);
    let full = std::fs::read(&path).unwrap();
    for at in [
        HEADER,
        HEADER + 47,
        HEADER + 48,
        HEADER + 50 * 96 + 70,
        full.len() - 1,
    ] {
        let mut b = full.clone();
        b[at] ^= 0x01;
        std::fs::write(&path, &b).unwrap();
        assert_eq!(
            reason(&path, &registry_keys),
            RebuildReason::BodyDigestMismatch,
            "byte {at}"
        );
        assert_eq!(
            restart_rebuilds(&path, &registry_keys),
            RebuildReason::BodyDigestMismatch
        );
    }
}

#[test]
fn persist_unknown_version_rebuilds() {
    let registry_keys = keys(1, 100);
    let (_dir, path) = saved(&registry_keys);
    let full = std::fs::read(&path).unwrap();
    for version in [0u32, 1, 3, u32::MAX] {
        let mut b = full.clone();
        b[8..12].copy_from_slice(&version.to_le_bytes());
        std::fs::write(&path, &b).unwrap();
        assert_eq!(
            reason(&path, &registry_keys),
            RebuildReason::UnknownVersion { version }
        );
        assert_eq!(
            restart_rebuilds(&path, &registry_keys),
            RebuildReason::UnknownVersion { version }
        );
    }
    let mut b = full.clone();
    b[0] ^= 0xff;
    std::fs::write(&path, &b).unwrap();
    assert_eq!(reason(&path, &registry_keys), RebuildReason::BadMagic);
}

// Non-regular files at the snapshot path are never opened in a way that can block.

#[test]
fn persist_fifo_at_path_rebuilds_without_blocking() {
    let (_dir, path) = dir();
    mkfifo(&path);
    assert_eq!(
        reason_within_5s(&path, &keys(1, 3)),
        RebuildReason::NotRegularFile
    );
}

#[test]
fn persist_symlink_at_path_rebuilds() {
    let registry_keys = keys(1, 3);
    let (dir, path) = dir();
    // A symlink to a valid snapshot and a symlink to a FIFO: neither is followed.
    let target = dir.path().join("real.bin");
    save_with(&TestCodec, &cache_of(&registry_keys), &target).unwrap();
    let fifo = dir.path().join("fifo");
    mkfifo(&fifo);
    for to in [&target, &fifo] {
        let _ = std::fs::remove_file(&path);
        std::os::unix::fs::symlink(to, &path).unwrap();
        assert_eq!(
            reason_within_5s(&path, &registry_keys),
            RebuildReason::NotRegularFile,
            "symlink to {}",
            to.display()
        );
    }
}

// persist_atomic_replace: a crash between write and rename leaves the previous file loadable.

#[test]
fn persist_atomic_replace() {
    let old = keys(1, 1_000);
    let new = keys(1, 1_500);
    let (dir, path) = saved(&old);
    let staged = stage_with(&TestCodec, &cache_of(&new), &path).unwrap();
    let tmp = staged.tmp_path().to_path_buf();
    assert_eq!(temps(dir.path()), std::slice::from_ref(&tmp));
    drop(staged); // crash before rename
    assert!(tmp.exists(), "a crash leaves the temp file behind");
    assert!(matches!(
        load_with(&TestCodec, &path, &registry(&old)),
        Startup::Use(c) if contents(&c) == old
    ));
    // The next save removes the leftover and replaces the snapshot.
    stage_with(&TestCodec, &cache_of(&new), &path)
        .unwrap()
        .commit()
        .unwrap();
    assert!(matches!(
        load_with(&TestCodec, &path, &registry(&new)),
        Startup::Use(c) if contents(&c) == new
    ));
    assert_eq!(temps(dir.path()), Vec::<PathBuf>::new());
}

#[test]
fn persist_overlapping_stages_publish_their_own_content() {
    let (a, b) = (keys(1, 300), keys(2, 400));
    for a_commits_first in [true, false] {
        let (dir, path) = dir();
        let staged_a = stage_with(&TestCodec, &cache_of(&a), &path).unwrap();
        let staged_b = stage_with(&TestCodec, &cache_of(&b), &path).unwrap();
        assert_ne!(staged_a.tmp_path(), staged_b.tmp_path());
        assert!(staged_a.tmp_path().exists(), "staging B kept A's live temp");
        let (first, second, last) = if a_commits_first {
            ((staged_a, &a), (staged_b, &b), &b)
        } else {
            ((staged_b, &b), (staged_a, &a), &a)
        };
        first.0.commit().unwrap();
        assert!(matches!(
            load_with(&TestCodec, &path, &registry(first.1)),
            Startup::Use(c) if contents(&c) == *first.1
        ));
        second.0.commit().unwrap();
        assert!(matches!(
            load_with(&TestCodec, &path, &registry(last)),
            Startup::Use(c) if contents(&c) == *last
        ));
        assert_eq!(temps(dir.path()), Vec::<PathBuf>::new());
    }
}
