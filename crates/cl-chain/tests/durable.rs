//! The C4 durable file set (`persist::durable`): `<datadir>/durable/`, outside MDBX.
//!
//! Crashes are injected through the `test-hooks` seam ([`FileSet::open_crashing`]): at a named
//! step the operation returns [`Error::Crashed`] and leaves the disk as it is, the handle is
//! dropped (the process died), and the next [`FileSet::open`] is the restart. Every test has
//! its own temp dir and its own hook; nothing is shared between tests.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use cl_chain::persist::durable::{
    AppendFault, BaseFiles, BaseKind, Checkpoint, ElStatus, Error, FileSet, ImportRecord, Loaded,
    PayloadStatus, Step,
};
use libmdbx::WriteFlags;
use store_schema::{
    env::{open_writer, WriterOptions},
    keys::{slot_root_key, SCHEMA_VERSION_KEY},
    tables::{BLOCKS, META, TABLES},
    version::SCHEMA_VERSION,
};

const ROOT_A: [u8; 32] = [0xaa; 32];
const ROOT_B: [u8; 32] = [0xbb; 32];
const ROOT_F: [u8; 32] = [0xf1; 32];
const ROOT_G: [u8; 32] = [0xf2; 32];

const ANCHOR: Checkpoint = Checkpoint {
    root: ROOT_A,
    epoch: 7,
};

fn files(tag: &'static str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        format!("block {tag}").into_bytes(),
        format!("state {tag}").into_bytes(),
        format!("envelope {tag}").into_bytes(),
    )
}

/// Writes the base of `tag`, with an envelope.
fn base_files<'a>(f: &'a (Vec<u8>, Vec<u8>, Vec<u8>)) -> BaseFiles<'a> {
    BaseFiles {
        block: &f.0,
        state: &f.1,
        envelope: Some(&f.2),
    }
}

fn durable(datadir: &Path) -> PathBuf {
    datadir.join("durable")
}

fn hex(root: &[u8; 32]) -> String {
    root.iter().map(|b| format!("{b:02x}")).collect()
}

fn open(datadir: &Path) -> (FileSet, Loaded) {
    FileSet::open(datadir).unwrap()
}

fn record(root: [u8; 32], slot: u64) -> ImportRecord {
    ImportRecord {
        root,
        slot,
        payload_status: PayloadStatus::Full,
        el_status: ElStatus::Valid,
    }
}

/// Every `(step, name)` a run of `op` reaches, from a hook that never crashes.
fn steps_of(datadir: &Path, op: impl FnOnce(&mut FileSet)) -> Vec<(Step, String)> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let (mut set, _) = FileSet::open_crashing(datadir, move |step, name| {
        log.lock().unwrap().push((step, name.to_owned()));
        false
    })
    .unwrap();
    seen.lock().unwrap().clear();
    op(&mut set);
    let steps = seen.lock().unwrap().clone();
    steps
}

/// A hook that crashes at its `nth` step (0-based).
fn crash_at(nth: usize) -> impl Fn(Step, &str) -> bool + Send + Sync + 'static {
    let calls = AtomicUsize::new(0);
    move |_, _| calls.fetch_add(1, Ordering::SeqCst) == nth
}

fn assert_crashed<T: std::fmt::Debug>(result: Result<T, Error>, step: Step, name: &str) {
    match result {
        Err(Error::Crashed { step: s, name: n }) if s == step && n == name => {}
        other => panic!("expected a crash at {step:?} {name}, got {other:?}"),
    }
}

/// The names in `durable/`, sorted.
fn entries(datadir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(durable(datadir))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// The base of a load is exactly the one written for `root` with `tag`'s files.
fn assert_base(loaded: &Loaded, kind: BaseKind, root: [u8; 32], tag: &'static str) {
    let base = loaded.base.as_ref().expect("a base");
    let (block, state, envelope) = files(tag);
    assert_eq!((base.kind, base.root), (kind, root));
    assert_eq!(base.anchor, ANCHOR, "the operator anchor is carried");
    assert_eq!(base.block, block);
    assert_eq!(base.state, state);
    assert_eq!(base.envelope.as_deref(), Some(envelope.as_slice()));
}

/// `anchor-<A>/` holds exactly what `install_anchor(ANCHOR, files("A"))` wrote, byte for byte:
/// a finality advance keeps the operator's anchor dir.
fn assert_anchor_dir(datadir: &Path, what: &str) {
    let dir = durable(datadir).join(format!("anchor-{}", hex(&ROOT_A)));
    let (block, state, envelope) = files("A");
    let mut anchor = ROOT_A.to_vec();
    anchor.extend_from_slice(&ANCHOR.epoch.to_be_bytes());
    let want = [
        ("anchor", anchor),
        ("block.ssz", block),
        ("envelope.ssz", envelope),
        ("state.ssz", state),
    ];
    let mut names: Vec<String> = fs::read_dir(&dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    assert_eq!(
        names,
        want.each_ref().map(|(name, _)| *name),
        "{what}: anchor-<A>/"
    );
    for (name, bytes) in want {
        assert_eq!(
            fs::read(dir.join(name)).unwrap(),
            bytes,
            "{what}: anchor-<A>/{name}"
        );
    }
}

#[test]
fn import_log_atomic_with_block() {
    let datadir = tempfile::tempdir().unwrap();
    let env = open_writer(&datadir.path().join("chain"), WriterOptions::default()).unwrap();
    let commit_block = |slot: u64, root: &[u8; 32]| {
        let txn = env.env().begin_rw_txn().unwrap();
        let blocks = txn.open_table(Some(BLOCKS)).unwrap();
        txn.put(
            &blocks,
            slot_root_key(slot, root),
            b"block",
            WriteFlags::UPSERT,
        )
        .unwrap();
        txn.commit().unwrap();
    };
    let stored_blocks = || {
        let txn = env.env().begin_ro_txn().unwrap();
        let blocks = txn.open_table(Some(BLOCKS)).unwrap();
        txn.table_stat(&blocks).unwrap().entries()
    };

    let (mut set, loaded) = open(datadir.path());
    assert!(loaded.imports.is_empty());
    // Block A: committed, then recorded, then acknowledged.
    commit_block(10, &ROOT_A);
    set.record_import(&record(ROOT_A, 10)).unwrap();
    // Block B: committed, then the process dies before the append.
    commit_block(11, &ROOT_B);
    drop(set);

    let (mut set, loaded) = open(datadir.path());
    assert_eq!(stored_blocks(), 2, "both blocks are in MDBX");
    assert_eq!(loaded.imports, vec![record(ROOT_A, 10)]);
    assert!(loaded.is_imported(&ROOT_A));
    assert!(
        !loaded.is_imported(&ROOT_B),
        "a block with no record is ignored"
    );

    // After the append both exist.
    set.record_import(&record(ROOT_B, 11)).unwrap();
    drop(set);
    let (_, loaded) = open(datadir.path());
    assert_eq!(loaded.imports, vec![record(ROOT_A, 10), record(ROOT_B, 11)]);
    assert!(loaded.is_imported(&ROOT_B));

    // Block F: committed, its record written but the process dies before the fsync, and the
    // unsynced tail is torn: it is truncated on load and loading goes on.
    commit_block(12, &ROOT_F);
    let (mut set, _) = FileSet::open_crashing(datadir.path(), |step, name| {
        step == Step::Written && name == "import.log"
    })
    .unwrap();
    assert_crashed(
        set.record_import(&record(ROOT_F, 12)),
        Step::Written,
        "import.log",
    );
    drop(set);
    let log = durable(datadir.path()).join("import.log");
    let whole = fs::metadata(&log).unwrap().len();
    assert_eq!(whole, 3 * 50, "three frames of 8 + 42 bytes");
    fs::OpenOptions::new()
        .write(true)
        .open(&log)
        .unwrap()
        .set_len(whole - 7)
        .unwrap();
    let (mut set, loaded) = open(datadir.path());
    assert_eq!(loaded.imports, vec![record(ROOT_A, 10), record(ROOT_B, 11)]);
    assert!(!loaded.is_imported(&ROOT_F));
    assert_eq!(
        fs::metadata(&log).unwrap().len(),
        2 * 50,
        "the torn tail is cut"
    );
    set.record_import(&record(ROOT_F, 12)).unwrap();
    drop(set);
    let (_, loaded) = open(datadir.path());
    assert_eq!(loaded.imports.len(), 3);
    assert!(loaded.is_imported(&ROOT_F));
    assert_eq!(stored_blocks(), 3);
}

/// A crash at every step of a finality advance leaves exactly one complete base: the old one
/// until `CURRENT` names the new one, the new one from then on, never a mix. The next open
/// cleans up whatever the crash left, and `anchor-<A>/` survives every crash point whole.
#[test]
fn finality_swap_atomic() {
    let template = tempfile::tempdir().unwrap();
    let (a, f) = (files("A"), files("F"));
    {
        let (mut set, _) = open(template.path());
        set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
    }
    let steps = steps_of(template.path(), |set| {
        set.advance_finality(ROOT_F, &base_files(&f)).unwrap();
    });
    let finalized = format!("finalized-{}", hex(&ROOT_F));
    // Every file of the new dir written and fsync'd, the dir fsync'd and renamed, CURRENT
    // swapped atomically. The old base is the anchor: it is kept.
    let want: Vec<(Step, String)> = [
        (Step::Written, "block.ssz"),
        (Step::Synced, "block.ssz"),
        (Step::Written, "state.ssz"),
        (Step::Synced, "state.ssz"),
        (Step::Written, "envelope.ssz"),
        (Step::Synced, "envelope.ssz"),
        (Step::Written, "anchor"),
        (Step::Synced, "anchor"),
        (Step::Synced, finalized.as_str()),
        (Step::Renamed, finalized.as_str()),
        (Step::Written, "CURRENT"),
        (Step::Synced, "CURRENT"),
        (Step::Renamed, "CURRENT"),
        (Step::Swapped, finalized.as_str()),
    ]
    .into_iter()
    .map(|(s, n)| (s, n.to_owned()))
    .collect();
    assert_eq!(steps, want);

    for (nth, (step, name)) in steps.iter().enumerate() {
        let datadir = tempfile::tempdir().unwrap();
        {
            let (mut set, _) = open(datadir.path());
            set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
        }
        let (mut set, _) = FileSet::open_crashing(datadir.path(), crash_at(nth)).unwrap();
        assert_crashed(set.advance_finality(ROOT_F, &base_files(&f)), *step, name);
        drop(set);

        let (_, loaded) = open(datadir.path());
        let swapped = nth >= steps.len() - 2; // CURRENT renamed into place
        let anchor = format!("anchor-{}", hex(&ROOT_A));
        if swapped {
            assert_base(&loaded, BaseKind::Finalized, ROOT_F, "F");
            assert_eq!(
                entries(datadir.path()),
                ["CURRENT", "VERSION", anchor.as_str(), finalized.as_str()]
            );
        } else {
            assert_base(&loaded, BaseKind::Anchor, ROOT_A, "A");
            assert_eq!(
                entries(datadir.path()),
                ["CURRENT", "VERSION", anchor.as_str()]
            );
        }
        assert_anchor_dir(datadir.path(), &format!("crash at {step:?} {name}"));
    }
}

/// A crash at every step of an advance from a finalized base (F to G): the old `finalized-F/`
/// or the new `finalized-G/` is the base, the other is gone after the next open, and
/// `anchor-<A>/` survives every crash point whole.
#[test]
fn every_finality_crash_point_keeps_the_anchor_dir() {
    let (a, f, g) = (files("A"), files("F"), files("G"));
    let setup = |datadir: &Path| {
        let (mut set, _) = open(datadir);
        set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
        set.advance_finality(ROOT_F, &base_files(&f)).unwrap();
    };
    let template = tempfile::tempdir().unwrap();
    setup(template.path());
    let steps = steps_of(template.path(), |set| {
        set.advance_finality(ROOT_G, &base_files(&g)).unwrap();
    });
    assert_eq!(steps.len(), 14);
    let anchor = format!("anchor-{}", hex(&ROOT_A));
    for (nth, (step, name)) in steps.iter().enumerate() {
        let datadir = tempfile::tempdir().unwrap();
        setup(datadir.path());
        let (mut set, _) = FileSet::open_crashing(datadir.path(), crash_at(nth)).unwrap();
        assert_crashed(set.advance_finality(ROOT_G, &base_files(&g)), *step, name);
        drop(set);

        let (_, loaded) = open(datadir.path());
        let (root, tag) = if nth >= steps.len() - 2 {
            (ROOT_G, "G")
        } else {
            (ROOT_F, "F")
        };
        assert_base(&loaded, BaseKind::Finalized, root, tag);
        let finalized = format!("finalized-{}", hex(&root));
        assert_eq!(
            entries(datadir.path()),
            ["CURRENT", "VERSION", anchor.as_str(), finalized.as_str()],
            "crash at {step:?} {name}"
        );
        assert_anchor_dir(datadir.path(), &format!("crash at {step:?} {name}"));
    }
}

/// Install anchor A, advance to F, then to G, reopening after each: `anchor-<A>/` and its
/// block, state and envelope survive byte-identical, and only `finalized-F/` goes when G
/// becomes the base. A new anchor is a new trust root: installing B removes `anchor-<A>/` and
/// every `finalized-*` dir.
#[test]
fn the_anchor_dir_survives_finality_advances() {
    let datadir = tempfile::tempdir().unwrap();
    let (a, b, f, g) = (files("A"), files("B"), files("F"), files("G"));
    let anchor = format!("anchor-{}", hex(&ROOT_A));
    let (fin_f, fin_g) = (
        format!("finalized-{}", hex(&ROOT_F)),
        format!("finalized-{}", hex(&ROOT_G)),
    );

    let (mut set, _) = open(datadir.path());
    set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
    drop(set);
    let (mut set, loaded) = open(datadir.path());
    assert_base(&loaded, BaseKind::Anchor, ROOT_A, "A");
    assert_anchor_dir(datadir.path(), "installed");

    set.advance_finality(ROOT_F, &base_files(&f)).unwrap();
    assert_anchor_dir(datadir.path(), "advanced to F");
    drop(set);
    let (mut set, loaded) = open(datadir.path());
    assert_base(&loaded, BaseKind::Finalized, ROOT_F, "F");
    assert_eq!(
        entries(datadir.path()),
        ["CURRENT", "VERSION", anchor.as_str(), fin_f.as_str()]
    );
    assert_anchor_dir(datadir.path(), "reopened at F");

    set.advance_finality(ROOT_G, &base_files(&g)).unwrap();
    assert_eq!(
        entries(datadir.path()),
        ["CURRENT", "VERSION", anchor.as_str(), fin_g.as_str()],
        "only finalized-F is deleted"
    );
    drop(set);
    let (mut set, loaded) = open(datadir.path());
    assert_base(&loaded, BaseKind::Finalized, ROOT_G, "G");
    assert_eq!(
        entries(datadir.path()),
        ["CURRENT", "VERSION", anchor.as_str(), fin_g.as_str()]
    );
    assert_anchor_dir(datadir.path(), "reopened at G");

    // A new anchor replaces the old anchor and every finalized dir.
    let other = Checkpoint {
        root: ROOT_B,
        epoch: 9,
    };
    set.install_anchor(other, &base_files(&b)).unwrap();
    drop(set);
    let (_, loaded) = open(datadir.path());
    let base = loaded.base.unwrap();
    assert_eq!(
        (base.kind, base.root, base.anchor),
        (BaseKind::Anchor, ROOT_B, other)
    );
    let anchor_b = format!("anchor-{}", hex(&ROOT_B));
    assert_eq!(
        entries(datadir.path()),
        ["CURRENT", "VERSION", anchor_b.as_str()]
    );
}

/// On open, the base CURRENT names and the anchor dir it carries are kept; any other anchor
/// dir and any stale finalized dir are crash leftovers and removed.
#[test]
fn open_keeps_the_current_anchor_and_removes_other_bases() {
    let datadir = tempfile::tempdir().unwrap();
    let (a, f) = (files("A"), files("F"));
    {
        let (mut set, _) = open(datadir.path());
        set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
        set.advance_finality(ROOT_F, &base_files(&f)).unwrap();
    }
    let dir = durable(datadir.path());
    let other_anchor = format!("anchor-{}", hex(&ROOT_B));
    let stale = format!("finalized-{}", hex(&ROOT_G));
    for name in [&other_anchor, &stale] {
        fs::create_dir(dir.join(name)).unwrap();
        fs::write(dir.join(name).join("block.ssz"), b"x").unwrap();
    }
    let (_, loaded) = open(datadir.path());
    assert_base(&loaded, BaseKind::Finalized, ROOT_F, "F");
    let anchor = format!("anchor-{}", hex(&ROOT_A));
    let finalized = format!("finalized-{}", hex(&ROOT_F));
    assert_eq!(
        entries(datadir.path()),
        ["CURRENT", "VERSION", anchor.as_str(), finalized.as_str()]
    );
    assert_anchor_dir(datadir.path(), "reopened");
}

#[test]
fn file_set_versioned_not_mdbx() {
    let datadir = tempfile::tempdir().unwrap();
    let env_dir = datadir.path().join("chain");
    let (a, f) = (files("A"), files("F"));
    {
        let env = open_writer(&env_dir, WriterOptions::default()).unwrap();
        let (mut set, _) = open(datadir.path());
        set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
        set.advance_finality(ROOT_F, &base_files(&f)).unwrap();
        set.record_import(&record(ROOT_G, 99)).unwrap();
        // No MDBX table holds any of it: the only rows are the env's own version row.
        let txn = env.env().begin_ro_txn().unwrap();
        for table in TABLES {
            let handle = txn.open_table(Some(table)).unwrap();
            let rows = txn.table_stat(&handle).unwrap().entries();
            assert_eq!(rows, usize::from(table == META), "table {table}");
        }
    }
    // Plain files under durable/, beside the env, not in it.
    let finalized = format!("finalized-{}", hex(&ROOT_F));
    let anchor = format!("anchor-{}", hex(&ROOT_A));
    assert_eq!(
        entries(datadir.path()),
        [
            "CURRENT",
            "VERSION",
            anchor.as_str(),
            finalized.as_str(),
            "import.log"
        ]
    );
    assert_eq!(
        fs::read(durable(datadir.path()).join("VERSION")).unwrap(),
        b"1\n"
    );
    for name in ["block.ssz", "state.ssz", "envelope.ssz", "anchor"] {
        let path = durable(datadir.path()).join(&finalized).join(name);
        assert!(fs::symlink_metadata(&path).unwrap().is_file(), "{name}");
    }
    assert!(!durable(datadir.path()).starts_with(&env_dir));

    // It survives losing the env entirely, and a new env beside it.
    fs::remove_dir_all(&env_dir).unwrap();
    drop(open_writer(&env_dir, WriterOptions::default()).unwrap());
    let (_, loaded) = open(datadir.path());
    assert_base(&loaded, BaseKind::Finalized, ROOT_F, "F");
    assert_eq!(loaded.imports, vec![record(ROOT_G, 99)]);

    // VERSION gates the start: a newer one refuses, and so does a newer env schema.
    fs::write(durable(datadir.path()).join("VERSION"), b"2\n").unwrap();
    let err = FileSet::open(datadir.path()).unwrap_err();
    assert!(matches!(err, Error::NewerVersion { found: 2 }), "{err:?}");
    {
        let env = open_writer(&env_dir, WriterOptions::default()).unwrap();
        let txn = env.env().begin_rw_txn().unwrap();
        let meta = txn.open_table(Some(META)).unwrap();
        txn.put(
            &meta,
            SCHEMA_VERSION_KEY,
            (SCHEMA_VERSION + 1).to_be_bytes(),
            WriteFlags::UPSERT,
        )
        .unwrap();
        txn.commit().unwrap();
    }
    let err = open_writer(&env_dir, WriterOptions::default()).unwrap_err();
    assert!(
        matches!(err, store_schema::Error::SchemaVersion { found: 2, .. }),
        "{err:?}"
    );
}

/// The anchor format #106 adopts, pinned: the dir name is `anchor-` and the 64 lowercase hex
/// characters of the root, CURRENT names it with one newline, and `anchor` is `root ‖ epoch BE`.
#[test]
fn the_anchor_dir_name_is_pinned() {
    let datadir = tempfile::tempdir().unwrap();
    let root: [u8; 32] = std::array::from_fn(|i| (i as u8) * 8 + 1);
    let name = "anchor-0109111921293139414951596169717981899199a1a9b1b9c1c9d1d9e1e9f1f9";
    let anchor = Checkpoint {
        root,
        epoch: 0x0102,
    };
    let a = files("A");
    let (mut set, _) = open(datadir.path());
    set.install_anchor(anchor, &base_files(&a)).unwrap();
    let dir = durable(datadir.path());
    assert_eq!(
        fs::read(dir.join("CURRENT")).unwrap(),
        format!("{name}\n").into_bytes()
    );
    let mut want = root.to_vec();
    want.extend_from_slice(&0x0102u64.to_be_bytes());
    assert_eq!(fs::read(dir.join(name).join("anchor")).unwrap(), want);
    assert_eq!(fs::read(dir.join(name).join("block.ssz")).unwrap(), a.0);
    assert_eq!(fs::read(dir.join(name).join("state.ssz")).unwrap(), a.1);
    assert_eq!(fs::read(dir.join(name).join("envelope.ssz")).unwrap(), a.2);

    let f = (b"b".to_vec(), b"s".to_vec());
    set.advance_finality(
        ROOT_F,
        &BaseFiles {
            block: &f.0,
            state: &f.1,
            envelope: None,
        },
    )
    .unwrap();
    let finalized = format!("finalized-{}", "f1".repeat(32));
    assert_eq!(
        fs::read(dir.join("CURRENT")).unwrap(),
        format!("{finalized}\n").into_bytes()
    );
    assert_eq!(fs::read(dir.join(&finalized).join("anchor")).unwrap(), want);
    assert!(!dir.join(&finalized).join("envelope.ssz").exists());
    assert!(dir.join(name).is_dir(), "the anchor dir is kept");
    assert_eq!(fs::read(dir.join(name).join("anchor")).unwrap(), want);
    assert_eq!(fs::read(dir.join(name).join("block.ssz")).unwrap(), a.0);
    assert_eq!(fs::read(dir.join(name).join("state.ssz")).unwrap(), a.1);
    assert_eq!(fs::read(dir.join(name).join("envelope.ssz")).unwrap(), a.2);
    drop(set);
    let (_, loaded) = open(datadir.path());
    let base = loaded.base.unwrap();
    assert_eq!(base.anchor, anchor);
    assert_eq!(base.envelope, None);
}

/// The anchor is carried through every finality advance.
#[test]
fn finality_carries_the_anchor_forward() {
    let datadir = tempfile::tempdir().unwrap();
    let (a, f, g) = (files("A"), files("F"), files("G"));
    let (mut set, _) = open(datadir.path());
    let err = set.advance_finality(ROOT_F, &base_files(&f)).unwrap_err();
    assert!(matches!(err, Error::NoBase), "{err:?}");
    set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
    set.advance_finality(ROOT_F, &base_files(&f)).unwrap();
    let err = set.advance_finality(ROOT_F, &base_files(&f)).unwrap_err();
    assert!(matches!(err, Error::BaseIsCurrent { .. }), "{err:?}");
    set.advance_finality(ROOT_G, &base_files(&g)).unwrap();
    drop(set);
    let (_, loaded) = open(datadir.path());
    assert_base(&loaded, BaseKind::Finalized, ROOT_G, "G");
    let finalized = format!("finalized-{}", hex(&ROOT_G));
    let anchor = format!("anchor-{}", hex(&ROOT_A));
    assert_eq!(
        entries(datadir.path()),
        ["CURRENT", "VERSION", anchor.as_str(), finalized.as_str()]
    );
}

/// A crash at every step of installing a new anchor over an old one leaves the old or the new,
/// whole.
#[test]
fn install_anchor_fail_points_leave_old_or_new() {
    let template = tempfile::tempdir().unwrap();
    let (a, b) = (files("A"), files("B"));
    let other = Checkpoint {
        root: ROOT_B,
        epoch: 9,
    };
    {
        let (mut set, _) = open(template.path());
        set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
    }
    let steps = steps_of(template.path(), |set| {
        set.install_anchor(other, &base_files(&b)).unwrap();
    });
    assert_eq!(steps.len(), 14);
    for (nth, (step, name)) in steps.iter().enumerate() {
        let datadir = tempfile::tempdir().unwrap();
        {
            let (mut set, _) = open(datadir.path());
            set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
        }
        let (mut set, _) = FileSet::open_crashing(datadir.path(), crash_at(nth)).unwrap();
        assert_crashed(set.install_anchor(other, &base_files(&b)), *step, name);
        drop(set);
        let (_, loaded) = open(datadir.path());
        let base = loaded.base.unwrap();
        if nth >= steps.len() - 2 {
            assert_eq!(
                (base.root, base.anchor, base.block),
                (ROOT_B, other, b.0.clone())
            );
        } else {
            assert_eq!(
                (base.root, base.anchor, base.block),
                (ROOT_A, ANCHOR, a.0.clone())
            );
        }
        assert_eq!(
            entries(datadir.path()).len(),
            3,
            "CURRENT, VERSION, one base"
        );
    }
}

/// A crash at every step of the first open's VERSION write: the next open finds no VERSION and
/// starts fresh, or finds it whole. Never a partial VERSION.
#[test]
fn version_fail_points_leave_none_or_whole() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let fresh = tempfile::tempdir().unwrap();
    FileSet::open_crashing(fresh.path(), move |step, name| {
        log.lock().unwrap().push((step, name.to_owned()));
        false
    })
    .unwrap();
    let steps = seen.lock().unwrap().clone();
    let want: Vec<(Step, String)> = [Step::Written, Step::Synced, Step::Renamed]
        .into_iter()
        .map(|s| (s, "VERSION".to_owned()))
        .collect();
    assert_eq!(steps, want);
    for (nth, (step, name)) in steps.iter().enumerate() {
        let datadir = tempfile::tempdir().unwrap();
        assert_crashed(
            FileSet::open_crashing(datadir.path(), crash_at(nth)),
            *step,
            name,
        );
        let version = durable(datadir.path()).join("VERSION");
        match fs::read(&version) {
            Ok(bytes) => assert_eq!(bytes, b"1\n"),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        }
        let (_, loaded) = open(datadir.path());
        assert!(loaded.base.is_none() && loaded.imports.is_empty());
        assert_eq!(fs::read(&version).unwrap(), b"1\n");
        assert_eq!(
            entries(datadir.path()),
            ["VERSION"],
            "the tmp file is cleaned up"
        );
    }
}

#[test]
fn a_newer_or_unknown_version_refuses() {
    for (bytes, newer) in [
        (&b"2\n"[..], Some(2)),
        (b"18446744073709551615\n", Some(u64::MAX)),
        (b"0\n", None),
        (b"1", None),
        (b"01\n", None),
        (b"1\n\n", None),
        (b" 1\n", None),
        (b"", None),
        (b"v1\n", None),
    ] {
        let datadir = tempfile::tempdir().unwrap();
        drop(open(datadir.path()));
        fs::write(durable(datadir.path()).join("VERSION"), bytes).unwrap();
        let err = FileSet::open(datadir.path()).unwrap_err();
        match newer {
            Some(v) => assert!(
                matches!(err, Error::NewerVersion { found } if found == v),
                "{bytes:?}: {err:?}"
            ),
            None => assert!(
                matches!(err, Error::UnknownVersion { .. }),
                "{bytes:?}: {err:?}"
            ),
        }
    }
}

#[test]
fn a_missing_version_on_a_non_empty_dir_is_an_error() {
    let datadir = tempfile::tempdir().unwrap();
    {
        let (mut set, _) = open(datadir.path());
        set.record_import(&record(ROOT_A, 1)).unwrap();
    }
    fs::remove_file(durable(datadir.path()).join("VERSION")).unwrap();
    let err = FileSet::open(datadir.path()).unwrap_err();
    assert!(matches!(err, Error::MissingVersion { .. }), "{err:?}");
    assert!(
        durable(datadir.path()).join("import.log").exists(),
        "nothing is deleted"
    );

    // An empty durable dir is a fresh one.
    let empty = tempfile::tempdir().unwrap();
    fs::create_dir(durable(empty.path())).unwrap();
    let (_, loaded) = open(empty.path());
    assert!(loaded.base.is_none());
    assert_eq!(entries(empty.path()), ["VERSION"]);
}

/// Text from CURRENT is never a path: only `anchor-`/`finalized-` and 64 lowercase hex
/// characters, rebuilt from the root bytes, naming a real directory in durable/. Anything else
/// is an error, never a guess, and nothing is cleaned up.
#[test]
fn the_current_resolver_refuses_anything_but_a_base_name() {
    let good = format!("anchor-{}", hex(&ROOT_A));
    let upper = format!("anchor-{}", hex(&ROOT_A).to_uppercase());
    let short = format!("anchor-{}", &hex(&ROOT_A)[..62]);
    let long = format!("anchor-{}aa", hex(&ROOT_A));
    let bad: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"\n".to_vec(),
        b"anch".to_vec(),
        good.as_bytes().to_vec(),            // torn: no newline
        good.as_bytes()[..40].to_vec(),      // torn
        format!("{good}\n\n").into_bytes(),  // extra bytes
        format!("{good}\0\n").into_bytes(),  // NUL
        format!("{upper}\n").into_bytes(),   // uppercase
        format!("{short}\n").into_bytes(),   // short
        format!("{long}\n").into_bytes(),    // long
        format!("../{good}\n").into_bytes(), // ..
        format!("anchor-../../{}\n", &hex(&ROOT_A)[6..]).into_bytes(),
        format!("{good}/block.ssz\n").into_bytes(), // /
        format!("/tmp/{good}\n").into_bytes(),
        format!("snapshot-{}\n", hex(&ROOT_A)).into_bytes(),
        format!("{good}\r\n").into_bytes(),
    ];
    let a = files("A");
    for current in bad {
        let datadir = tempfile::tempdir().unwrap();
        {
            let (mut set, _) = open(datadir.path());
            set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
        }
        fs::write(durable(datadir.path()).join("CURRENT"), &current).unwrap();
        let err = FileSet::open(datadir.path()).unwrap_err();
        assert!(
            matches!(err, Error::BadCurrent { .. }),
            "{current:?}: {err:?}"
        );
        assert!(
            durable(datadir.path()).join(&good).is_dir(),
            "nothing deleted"
        );
    }

    // A well-formed name that is a symlink, a file or nothing at all.
    let other = format!("finalized-{}", hex(&ROOT_F));
    /// Makes `other` in `dir`, given the good base's name.
    type Make = fn(&Path, &str, &str);
    let cases: [(&str, Make); 3] = [
        ("symlink", |dir, good, other| {
            std::os::unix::fs::symlink(dir.join(good), dir.join(other)).unwrap()
        }),
        ("file", |dir, _, other| {
            fs::write(dir.join(other), b"x").unwrap()
        }),
        ("missing", |_, _, _| {}),
    ];
    for (what, make) in cases {
        let datadir = tempfile::tempdir().unwrap();
        {
            let (mut set, _) = open(datadir.path());
            set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
        }
        let dir = durable(datadir.path());
        make(&dir, &good, &other);
        fs::write(dir.join("CURRENT"), format!("{other}\n")).unwrap();
        let err = FileSet::open(datadir.path()).unwrap_err();
        assert!(matches!(err, Error::BaseNotDir { .. }), "{what}: {err:?}");
        assert!(dir.join(&good).is_dir(), "{what}: nothing deleted");
    }
}

/// On open, leftovers of a crash are removed: temp files, temp dirs and base dirs CURRENT does
/// not name. Anything else is left alone.
#[test]
fn leftovers_are_cleaned_on_open() {
    let datadir = tempfile::tempdir().unwrap();
    let a = files("A");
    {
        let (mut set, _) = open(datadir.path());
        set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
    }
    let dir = durable(datadir.path());
    let stale = format!("finalized-{}", hex(&ROOT_F));
    fs::create_dir(dir.join(&stale)).unwrap();
    fs::create_dir(dir.join(format!(".tmp-{stale}"))).unwrap();
    fs::write(dir.join(format!(".tmp-{stale}")).join("block.ssz"), b"x").unwrap();
    fs::write(dir.join("CURRENT.tmp"), b"finalized-").unwrap();
    fs::write(dir.join("operator-notes"), b"kept").unwrap();
    let (_, loaded) = open(datadir.path());
    assert_base(&loaded, BaseKind::Anchor, ROOT_A, "A");
    let anchor = format!("anchor-{}", hex(&ROOT_A));
    assert_eq!(
        entries(datadir.path()),
        ["CURRENT", "VERSION", anchor.as_str(), "operator-notes"]
    );
}

/// The whole log, frame by frame.
fn log_bytes(datadir: &Path) -> Vec<u8> {
    fs::read(durable(datadir).join("import.log")).unwrap()
}

fn write_log(datadir: &Path, bytes: &[u8]) {
    fs::write(durable(datadir).join("import.log"), bytes).unwrap();
}

/// A log of three records, and their frames' bytes.
fn three_records(datadir: &Path) -> (Vec<ImportRecord>, Vec<u8>) {
    let records = vec![
        ImportRecord {
            root: ROOT_A,
            slot: 1,
            payload_status: PayloadStatus::Pending,
            el_status: ElStatus::NotVerified,
        },
        ImportRecord {
            root: ROOT_B,
            slot: 2,
            payload_status: PayloadStatus::Empty,
            el_status: ElStatus::Optimistic,
        },
        record(ROOT_F, u64::MAX),
    ];
    let (mut set, _) = open(datadir);
    for r in &records {
        set.record_import(r).unwrap();
    }
    (records, log_bytes(datadir))
}

#[test]
fn import_records_are_length_and_crc32c_framed() {
    let datadir = tempfile::tempdir().unwrap();
    let (records, bytes) = three_records(datadir.path());
    assert_eq!(bytes.len(), 150);
    let frame = &bytes[50..100];
    assert_eq!(&frame[..4], &42u32.to_le_bytes(), "u32 LE length");
    let payload = &frame[8..];
    assert_eq!(&payload[..32], &ROOT_B);
    assert_eq!(&payload[32..40], &2u64.to_be_bytes());
    assert_eq!(payload[40], 0, "PayloadStatus::Empty");
    assert_eq!(payload[41], 2, "ElStatus::Optimistic");
    let (_, loaded) = open(datadir.path());
    assert_eq!(loaded.imports, records);
}

#[test]
fn a_torn_tail_is_truncated_and_loading_continues() {
    let datadir = tempfile::tempdir().unwrap();
    let (records, bytes) = three_records(datadir.path());
    // A short header, a length past the end, a frame of zeros the size of one frame.
    let mut zeros = bytes[..100].to_vec();
    zeros.extend_from_slice(&[0; 50]);
    for (tail, log) in [
        ("short header", bytes[..105].to_vec()),
        ("length past the end", bytes[..149].to_vec()),
        ("zero-filled frame", zeros),
    ] {
        write_log(datadir.path(), &log);
        let (mut set, loaded) = open(datadir.path());
        assert_eq!(loaded.imports, records[..2], "{tail}");
        assert_eq!(log_bytes(datadir.path()), bytes[..100], "{tail}");
        set.record_import(&records[2]).unwrap();
        assert_eq!(
            log_bytes(datadir.path()),
            bytes,
            "{tail}: appends after the cut"
        );
    }
}

#[test]
fn a_bad_crc_or_unknown_last_record_is_truncated() {
    let datadir = tempfile::tempdir().unwrap();
    let (records, bytes) = three_records(datadir.path());
    for (what, at, value) in [
        ("crc", 104, 0x01),     // the crc of the last frame
        ("payload", 120, 0x01), // a root byte of the last frame
        ("length", 100, 0x01),  // 43: a length no record has
    ] {
        let mut log = bytes.clone();
        log[at] ^= value;
        write_log(datadir.path(), &log);
        let (_, loaded) = open(datadir.path());
        assert_eq!(loaded.imports, records[..2], "{what}");
        assert_eq!(log_bytes(datadir.path()), bytes[..100], "{what}");
    }
    // A status byte no variant has, under a good CRC: an undecodable last record.
    let mut log = bytes[..100].to_vec();
    let mut payload = log[58..100].to_vec();
    payload[41] = 0x7f;
    log.extend_from_slice(&42u32.to_le_bytes());
    log.extend_from_slice(&crc32c(&payload).to_le_bytes());
    log.extend_from_slice(&payload);
    write_log(datadir.path(), &log);
    let (_, loaded) = open(datadir.path());
    assert_eq!(loaded.imports, records[..2]);
}

#[test]
fn a_bad_record_mid_file_refuses_to_start() {
    let datadir = tempfile::tempdir().unwrap();
    let (_, bytes) = three_records(datadir.path());
    for at in [4, 20, 0, 98] {
        let mut log = bytes.clone();
        log[at] ^= 0x01;
        write_log(datadir.path(), &log);
        let err = FileSet::open(datadir.path()).unwrap_err();
        let offset = if at < 50 { 0 } else { 50 };
        assert!(
            matches!(err, Error::CorruptImportLog { offset: o } if o == offset),
            "byte {at}: {err:?}"
        );
        assert_eq!(log_bytes(datadir.path()), log, "nothing truncated");
    }
}

/// A failed append (a short write of any prefix of the frame, a failed fsync) is rolled back
/// to the length before it: the next good append follows the last good frame, and the reopen
/// loads every acknowledged record, never `CorruptImportLog`. Also when the failed append was
/// the one that created `import.log`.
#[test]
fn a_failed_append_is_rolled_back() {
    let faults = [
        AppendFault {
            short_write: Some(0),
            ..AppendFault::default()
        },
        AppendFault {
            short_write: Some(7),
            ..AppendFault::default()
        },
        AppendFault {
            short_write: Some(49),
            ..AppendFault::default()
        },
        AppendFault {
            sync: true,
            ..AppendFault::default()
        },
    ];
    for fault in faults {
        for before in [vec![], vec![record(ROOT_A, 1)]] {
            let what = format!("{fault:?} after {} records", before.len());
            let datadir = tempfile::tempdir().unwrap();
            let (mut set, _) = open(datadir.path());
            for r in &before {
                set.record_import(r).unwrap();
            }
            set.fail_next_append(fault);
            let err = set.record_import(&record(ROOT_F, 2)).unwrap_err();
            assert!(matches!(err, Error::Io(_)), "{what}: {err:?}");
            assert_eq!(
                log_bytes(datadir.path()).len(),
                50 * before.len(),
                "{what}: rolled back"
            );
            set.record_import(&record(ROOT_B, 3)).unwrap();
            drop(set);

            let (_, loaded) =
                FileSet::open(datadir.path()).unwrap_or_else(|e| panic!("{what}: {e:?}"));
            let mut want = before.clone();
            want.push(record(ROOT_B, 3));
            assert_eq!(loaded.imports, want, "{what}");
        }
    }
}

/// When rolling a failed append back fails too, the log may end in a torn frame: every later
/// write (`record_import`, `advance_finality`, `install_anchor`) is `Error::Poisoned` and
/// changes nothing, until the reopen cuts the torn tail; then the set works again.
#[test]
fn a_failed_rollback_poisons_the_set_until_reopen() {
    let datadir = tempfile::tempdir().unwrap();
    let (a, b, f) = (files("A"), files("B"), files("F"));
    let (mut set, _) = open(datadir.path());
    set.install_anchor(ANCHOR, &base_files(&a)).unwrap();
    set.record_import(&record(ROOT_A, 1)).unwrap();
    set.fail_next_append(AppendFault {
        short_write: Some(7),
        rollback: true,
        ..AppendFault::default()
    });
    let err = set.record_import(&record(ROOT_F, 2)).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err:?}");
    assert_eq!(log_bytes(datadir.path()).len(), 57, "the torn frame stays");

    let other = Checkpoint {
        root: ROOT_B,
        epoch: 9,
    };
    let refused = [
        ("record_import", set.record_import(&record(ROOT_B, 3))),
        (
            "advance_finality",
            set.advance_finality(ROOT_F, &base_files(&f)),
        ),
        ("install_anchor", set.install_anchor(other, &base_files(&b))),
        ("record_import again", set.record_import(&record(ROOT_B, 3))),
    ];
    for (what, result) in refused {
        assert!(matches!(result, Err(Error::Poisoned)), "{what}: {result:?}");
    }
    assert_eq!(log_bytes(datadir.path()).len(), 57, "nothing appended");
    let anchor = format!("anchor-{}", hex(&ROOT_A));
    assert_eq!(
        entries(datadir.path()),
        ["CURRENT", "VERSION", anchor.as_str(), "import.log"],
        "no base written"
    );
    drop(set);

    // The reopen cuts the torn tail, and writes work again.
    let (mut set, loaded) = open(datadir.path());
    assert_eq!(loaded.imports, vec![record(ROOT_A, 1)]);
    assert_eq!(log_bytes(datadir.path()).len(), 50, "the torn tail is cut");
    set.record_import(&record(ROOT_B, 3)).unwrap();
    set.advance_finality(ROOT_F, &base_files(&f)).unwrap();
    drop(set);
    let (_, loaded) = open(datadir.path());
    assert_eq!(loaded.imports, vec![record(ROOT_A, 1), record(ROOT_B, 3)]);
    assert_base(&loaded, BaseKind::Finalized, ROOT_F, "F");
}

/// The `(step, name)`s a hook saw.
type Seen = Arc<Mutex<Vec<(Step, String)>>>;

/// A set whose hook records every `(step, name)` from its open on and never crashes, except
/// at `crash` if given.
fn open_recording(datadir: &Path, crash: Option<(Step, &'static str)>) -> (FileSet, Loaded, Seen) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let (set, loaded) = FileSet::open_crashing(datadir, move |step, name| {
        log.lock().unwrap().push((step, name.to_owned()));
        crash == Some((step, name))
    })
    .unwrap();
    (set, loaded, seen)
}

/// Takes the steps recorded so far.
fn take_steps(seen: &Mutex<Vec<(Step, String)>>) -> Vec<(Step, String)> {
    std::mem::take(&mut *seen.lock().unwrap())
}

fn steps(want: &[(Step, &str)]) -> Vec<(Step, String)> {
    want.iter().map(|(s, n)| (*s, (*n).to_owned())).collect()
}

/// `import.log`'s entry in `durable/` is durable before an append is acknowledged, on every
/// path. A crash after the first append created the file and before `durable/` was fsync'd
/// is repaired by the next open: an open that finds `import.log` fsyncs `durable/` before it
/// takes an append. Without one, the first append after each open fsyncs `durable/`, also when
/// the append that created the file failed.
#[test]
fn the_import_log_dir_entry_is_synced_before_an_append_is_acked() {
    let written = (Step::Written, "import.log");
    let dir_synced = (Step::DirSynced, "durable");

    // The very first append dies after its frame is written: no fsync of the file or of
    // durable/ yet.
    let datadir = tempfile::tempdir().unwrap();
    let (mut set, _, seen) = open_recording(datadir.path(), Some(written));
    take_steps(&seen);
    assert_crashed(set.record_import(&record(ROOT_A, 1)), written.0, written.1);
    assert_eq!(take_steps(&seen), steps(&[written]));
    drop(set);

    // The restart fsyncs durable/ during the open, before the next append is acknowledged.
    let (mut set, loaded, seen) = open_recording(datadir.path(), None);
    assert_eq!(loaded.imports, vec![record(ROOT_A, 1)]);
    assert_eq!(
        take_steps(&seen),
        steps(&[dir_synced]),
        "the open syncs durable/"
    );
    set.record_import(&record(ROOT_B, 2)).unwrap();
    set.record_import(&record(ROOT_F, 3)).unwrap();
    assert_eq!(take_steps(&seen), steps(&[written, written]));
    drop(set);

    // No import.log at open: the first append fsyncs durable/, later ones do not.
    let datadir = tempfile::tempdir().unwrap();
    let (mut set, _, seen) = open_recording(datadir.path(), None);
    take_steps(&seen);
    set.record_import(&record(ROOT_A, 1)).unwrap();
    set.record_import(&record(ROOT_B, 2)).unwrap();
    assert_eq!(take_steps(&seen), steps(&[written, dir_synced, written]));
    drop(set);

    // The append that created import.log failed and was rolled back: the file is there but its
    // entry was never fsync'd, so the next append fsyncs durable/.
    let datadir = tempfile::tempdir().unwrap();
    let (mut set, _, seen) = open_recording(datadir.path(), None);
    take_steps(&seen);
    set.fail_next_append(AppendFault {
        short_write: Some(7),
        ..AppendFault::default()
    });
    assert!(matches!(
        set.record_import(&record(ROOT_A, 1)),
        Err(Error::Io(_))
    ));
    assert_eq!(take_steps(&seen), steps(&[]), "the write failed first");
    assert!(durable(datadir.path()).join("import.log").exists());
    set.record_import(&record(ROOT_B, 2)).unwrap();
    assert_eq!(take_steps(&seen), steps(&[written, dir_synced]));
}

/// CRC32C (Castagnoli), as RFC 3720 defines it, to build frames by hand.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
