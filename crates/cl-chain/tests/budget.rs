//! The non-finality disk budget (`cl_chain::persist::budget`): its config and the proposed
//! values of the fixture, the decision at the budget through the direct admit/charge API and
//! through the column writer, the counters (in the write's own transaction, reloaded at open,
//! lowered by the finality prune), the free-space floor's import gate on a fake `statvfs`, the
//! envelope window, and the metrics. No root, no loop device, no tmpfs.

use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cl_chain::persist::budget::{
    keep_envelope, stored, BudgetMetrics, DiskBudget, EnvelopeWindow, FloorError, FloorWatcher,
    FsSpace, FsStats, Statvfs, GIB, MIB,
};
use cl_chain::persist::budget::{Branch, Budget, Caps, Decision, Kind, Usage};
use cl_chain::probe::service::{CHAIN_METHODS, CHAIN_SERVICE};
use cl_chain::service::{settings, ChainSettings, SettingsError};
use cl_chain_columns::{
    BlockLink, BlockRoot, Column, ColumnReader, ColumnWriter, Error, WriterOptions, MIN_MAX_SIZE,
};
use network_config::{ChainConfig, Network};
use prometheus_client::registry::Registry;
use store_schema::txn::{self, Update};

const FIXTURE: &str = include_str!("fixtures/budget.toml");
/// The README section the fixture cites.
const SECTION: &str = "Non-finality disk budget (proposed values)";

// --- config -------------------------------------------------------------------------------

/// A cl-chain config whose `[chain]` table is followed by `budget` (a `[chain.disk_budget]`
/// table, or nothing).
fn config_text(budget: &str) -> String {
    let mut text = "network = \"sepolia\"\nmetrics_port = 9102\n\n[socket]\ngroup = 990\n\n\
                    [callers]\ncl-p2p = 991\n\n[methods]\n"
        .to_owned();
    for method in CHAIN_METHODS {
        text.push_str(&format!("\"{method}\" = [\"cl-p2p\"]\n"));
    }
    text.push_str(
        "\n[chain]\nreference_api_url = \"http://127.0.0.1:5052\"\nnode_id = \"0x\
         0000000000000000000000000000000000000000000000000000000000000007\"\n\
         verify_socket = \"/run/ethswarm/cl-verify/cl-verify.sock\"\nverify_uid = 993\n\n",
    );
    text.push_str(budget);
    text
}

fn parse(budget: &str) -> Result<ChainSettings, SettingsError> {
    let text = config_text(budget);
    let config = svc_runtime::Config::from_toml(CHAIN_SERVICE, &text, Path::new("cl-chain.toml"))?;
    settings(&config)
}

/// The fixture is the compiled-in default and every proposed value, in bytes; it cites the
/// README section that records them, which exists.
#[test]
fn the_fixture_holds_the_proposed_values() {
    let budget = parse(FIXTURE).unwrap().disk_budget;
    assert_eq!(budget, DiskBudget::default());
    assert_eq!(parse("").unwrap().disk_budget, DiskBudget::default());
    let caps = budget.caps();
    assert_eq!(caps.aggregate, 48 * GIB);
    let cap = |kind: Kind| caps.bytes[kind as usize];
    assert_eq!(cap(Kind::Columns), Some(32 * GIB));
    assert_eq!(cap(Kind::States), Some(8 * GIB));
    assert_eq!(cap(Kind::FcSnapshots), Some(512 * MIB));
    assert_eq!(cap(Kind::Envelopes), Some(4 * GIB));
    assert_eq!(cap(Kind::Pending), Some(GIB));
    assert_eq!(cap(Kind::Blocks), None);
    let items = |kind: Kind| caps.items[kind as usize];
    assert_eq!(items(Kind::Pending), Some(4096));
    assert_eq!(items(Kind::FcSnapshots), Some(2));
    assert_eq!(items(Kind::Columns), None);
    assert_eq!(caps.headroom_percent, 10);
    assert_eq!(caps.canonical_limit(), 48 * GIB + 48 * GIB / 10);
    assert_eq!(budget.states_kept_per_epoch, 2);
    let floor = budget.floor();
    // The larger of 10 GiB and 5% of the volume.
    assert_eq!(floor.bytes(100 * GIB), 10 * GIB);
    assert_eq!(floor.bytes(1000 * GIB), 50 * GIB);
    assert_eq!(floor.hysteresis_bytes, GIB);
    assert_eq!(floor.sync_over_bytes, 16 * MIB);
    assert!(
        FIXTURE.contains(SECTION),
        "the fixture cites the README section"
    );
    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("crates/cl-chain/README.md");
    let section = readme
        .split_once(&format!("## {SECTION}"))
        .expect("the README has the section")
        .1;
    for value in [
        "48 GiB", "32 GiB", "8 GiB", "512 MiB", "4 GiB", "1 GiB", "10 GiB", "5%",
    ] {
        assert!(section.contains(value), "the README section names {value}");
    }
    assert!(section.contains("proposed"), "marked proposed");
}

/// An unknown key and a per-type cap above the aggregate fail the start; so do a zero
/// aggregate, a percentage over 100 and a size that overflows. A partial table keeps the
/// defaults of the rest.
#[test]
fn the_budget_table_is_checked_at_startup() {
    let err = parse("[chain.disk_budget]\nhot_states_mib = 1\n").unwrap_err();
    assert!(matches!(err, SettingsError::Config(_)), "{err}");
    assert!(err.to_string().contains("hot_states_mib"), "{err}");
    let caps = [
        "columns_mib",
        "states_mib",
        "fc_snapshots_mib",
        "envelopes_mib",
        "pending_mib",
    ];
    let small = |over: &str, value: u64| {
        let mut table = "[chain.disk_budget]\naggregate_mib = 1024\n".to_owned();
        for key in caps {
            let v = if key == over { value } else { 512 };
            table.push_str(&format!("{key} = {v}\n"));
        }
        table
    };
    for key in caps {
        let err = parse(&small(key, 1025)).unwrap_err();
        assert!(
            matches!(&err, SettingsError::Key { key, .. } if *key == "disk_budget"),
            "{key}: {err}"
        );
        assert!(err.to_string().contains(key), "{err}");
        let ok = parse(&small(key, 1024)).unwrap().disk_budget;
        assert_eq!(ok.caps().aggregate, GIB);
    }
    for bad in [
        "aggregate_mib = 0",
        "floor_percent = 101",
        "canonical_headroom_percent = 101",
        "aggregate_mib = 9223372036854775807",
    ] {
        let err = parse(&format!("[chain.disk_budget]\n{bad}\n")).unwrap_err();
        assert!(
            matches!(&err, SettingsError::Key { key, .. } if *key == "disk_budget"),
            "{bad}: {err}"
        );
    }
    let partial = parse("[chain.disk_budget]\npending_items = 10\n")
        .unwrap()
        .disk_budget;
    assert_eq!(partial.pending_items, 10);
    assert_eq!(
        DiskBudget {
            pending_items: 4096,
            ..partial
        },
        DiskBudget::default()
    );
}

// --- the decision, direct API ---------------------------------------------------------------

/// Aggregate 1000 B with 10% canonical headroom; columns 600 B, states 300 B, the other typed
/// kinds 100 B; pending at most 4 rows, fc snapshots 2.
fn small_caps() -> Caps {
    let mut caps = Caps {
        aggregate: 1000,
        headroom_percent: 10,
        ..Caps::unlimited()
    };
    for (kind, cap) in [
        (Kind::Columns, 600),
        (Kind::States, 300),
        (Kind::FcSnapshots, 100),
        (Kind::Envelopes, 100),
        (Kind::Pending, 100),
    ] {
        caps.bytes[kind as usize] = Some(cap);
    }
    caps.items[Kind::Pending as usize] = Some(4);
    caps.items[Kind::FcSnapshots as usize] = Some(2);
    caps
}

/// A store stamped as cl-chain leaves it, closed: its env opened again with the store-schema
/// writer, for the direct API.
fn stamped_env(dir: &Path) -> store_schema::env::WriterEnv {
    drop(ColumnWriter::open_seeded(dir).unwrap());
    store_schema::env::test_writer(dir).unwrap()
}

/// At its cap, a side-branch write of any kind is ignored (and counted), and leaves the
/// counter as it was; within it, the same write is admitted. Blocks have the aggregate only.
/// Pending stops at its item cap whatever its bytes.
#[test]
fn side_branch_ignored_at_budget() {
    let dir = tempfile::tempdir().unwrap();
    let env = stamped_env(dir.path());
    for (kind, cap) in [
        (Kind::States, 300),
        (Kind::FcSnapshots, 100),
        (Kind::Envelopes, 100),
        (Kind::Pending, 100),
        (Kind::Blocks, 1000),
    ] {
        let budget = Budget::new(small_caps());
        let t = txn::begin(&env).unwrap();
        assert_eq!(
            budget.admit(&t, kind, Branch::Side, cap - 1, 1).unwrap(),
            Decision::Admit,
            "{kind:?}"
        );
        assert!(!budget.reached());
        let before = stored(&t, kind).unwrap();
        assert_eq!(
            budget.admit(&t, kind, Branch::Side, 2, 1).unwrap(),
            Decision::Ignore
        );
        assert_eq!(
            stored(&t, kind).unwrap(),
            before,
            "{kind:?}: a refusal charges nothing"
        );
        assert_eq!(budget.refusals(kind, Branch::Side), 1);
        assert!(budget.reached());
        assert_eq!(
            budget.admit(&t, kind, Branch::Side, 1, 0).unwrap(),
            Decision::Admit
        );
        assert!(!budget.reached());
    }
    let budget = Budget::new(small_caps());
    let t = txn::begin(&env).unwrap();
    for _ in 0..4 {
        assert!(budget
            .admit(&t, Kind::Pending, Branch::Side, 1, 1)
            .unwrap()
            .admitted());
    }
    for branch in [Branch::Side, Branch::Canonical] {
        assert_eq!(
            budget.admit(&t, Kind::Pending, branch, 1, 1).unwrap(),
            Decision::Ignore
        );
    }
    assert_eq!(
        stored(&t, Kind::Pending).unwrap(),
        Some(Usage { bytes: 4, items: 4 })
    );
}

/// At the budget the canonical branch goes on through the headroom (10% over the aggregate)
/// where a side branch is ignored, and stops there too.
#[test]
fn canonical_preferred() {
    let dir = tempfile::tempdir().unwrap();
    let env = stamped_env(dir.path());
    let budget = Budget::new(small_caps());
    let t = txn::begin(&env).unwrap();
    assert!(budget
        .admit(&t, Kind::States, Branch::Canonical, 300, 1)
        .unwrap()
        .admitted());
    assert!(budget
        .admit(&t, Kind::Blocks, Branch::Canonical, 600, 3)
        .unwrap()
        .admitted());
    assert_eq!(
        budget.admit(&t, Kind::States, Branch::Side, 1, 1).unwrap(),
        Decision::Ignore
    );
    assert_eq!(
        budget
            .admit(&t, Kind::Blocks, Branch::Side, 101, 1)
            .unwrap(),
        Decision::Ignore
    );
    assert_eq!(
        budget
            .admit(&t, Kind::States, Branch::Canonical, 50, 1)
            .unwrap(),
        Decision::Headroom
    );
    assert_eq!(
        budget
            .admit(&t, Kind::Blocks, Branch::Canonical, 150, 1)
            .unwrap(),
        Decision::Headroom
    );
    assert_eq!(budget.total(), 1100);
    assert_eq!(
        budget
            .admit(&t, Kind::Blocks, Branch::Canonical, 1, 1)
            .unwrap(),
        Decision::Ignore
    );
    assert_eq!(budget.refusals(Kind::Blocks, Branch::Canonical), 1);
    assert_eq!(budget.refusals(Kind::Blocks, Branch::Side), 1);
    assert_eq!(budget.refusals(Kind::States, Branch::Side), 1);
    // A committed charge is a row of the store, reloaded by the next budget that opens it.
    txn::commit(t, Update::Carry).unwrap();
    let reloaded = Budget::new(small_caps());
    reloaded.load(&env.begin_ro_txn().unwrap()).unwrap();
    assert_eq!(
        reloaded.used(Kind::States),
        Usage {
            bytes: 350,
            items: 2
        }
    );
    assert_eq!(reloaded.total(), 1100);
}

// --- the column writer ----------------------------------------------------------------------

const SIDECAR: usize = 100;

fn root(n: u8) -> BlockRoot {
    [n; 32]
}

/// A column writer of `caps`, stamped.
fn writer(dir: &Path, caps: Caps) -> ColumnWriter {
    let opts = WriterOptions {
        max_size: MIN_MAX_SIZE,
    };
    let writer = ColumnWriter::open_with_budget(dir, opts, Arc::new(Budget::new(caps))).unwrap();
    writer.seed_stamp().unwrap();
    writer
}

/// Writes `count` columns of [`SIDECAR`] bytes of block `n` at `slot` on `branch`.
fn write(writer: &ColumnWriter, slot: u64, n: u8, branch: Branch, count: u64) -> Result<(), Error> {
    let bytes = vec![n; SIDECAR];
    let columns: Vec<Column<'_>> = (0..count)
        .map(|index| Column { index, ssz: &bytes })
        .collect();
    writer
        .write_block_columns_on(slot, &root(n), BlockLink::Gap, branch, &columns)
        .map(|_| ())
        .map_err(|failed| {
            assert_eq!(
                failed.committed.columns, 0,
                "one transaction per write here"
            );
            failed.error
        })
}

fn columns_used(writer: &ColumnWriter) -> Usage {
    writer.budget().used(Kind::Columns)
}

/// The column writer refuses a side-branch column at the columns cap: nothing of it is stored,
/// the counter stays, the refusal is counted. Below the cap the same write was stored.
#[test]
fn the_column_writer_refuses_a_side_branch_column_at_the_budget() {
    let dir = tempfile::tempdir().unwrap();
    let writer = writer(dir.path(), small_caps());
    write(&writer, 1, 1, Branch::Side, 1).unwrap();
    write(&writer, 2, 2, Branch::Canonical, 5).unwrap();
    assert_eq!(
        columns_used(&writer),
        Usage {
            bytes: 600,
            items: 6
        }
    );
    let err = write(&writer, 3, 3, Branch::Side, 1).unwrap_err();
    assert!(
        matches!(
            err,
            Error::OverBudget {
                branch: Branch::Side
            }
        ),
        "{err}"
    );
    assert_eq!(writer.reader().columns_for_root(&root(3)).unwrap(), vec![]);
    assert_eq!(writer.reader().slot_of(&root(3)).unwrap(), None);
    assert_eq!(writer.reader().column_count().unwrap(), 6);
    assert_eq!(
        columns_used(&writer),
        Usage {
            bytes: 600,
            items: 6
        }
    );
    assert_eq!(writer.budget().refusals(Kind::Columns, Branch::Side), 1);
    assert!(writer.budget().reached());
    // Rewriting a stored column with the same bytes charges nothing, so it passes.
    write(&writer, 1, 1, Branch::Side, 1).unwrap();
    assert_eq!(
        columns_used(&writer),
        Usage {
            bytes: 600,
            items: 6
        }
    );
}

/// Through the column writer: past the columns cap canonical columns are still stored, up to
/// the aggregate's headroom, while side-branch ones are refused.
#[test]
fn the_column_writer_prefers_the_canonical_branch() {
    let dir = tempfile::tempdir().unwrap();
    let writer = writer(dir.path(), small_caps());
    write(&writer, 1, 1, Branch::Canonical, 6).unwrap();
    for (slot, n) in [(2, 2), (3, 3), (4, 4), (5, 5), (6, 6)] {
        assert!(write(&writer, slot, 20 + n, Branch::Side, 1).is_err());
        write(&writer, slot, n, Branch::Canonical, 1).unwrap();
    }
    assert_eq!(columns_used(&writer).bytes, 1100);
    let err = write(&writer, 7, 7, Branch::Canonical, 1).unwrap_err();
    assert!(
        matches!(
            err,
            Error::OverBudget {
                branch: Branch::Canonical
            }
        ),
        "{err}"
    );
    assert_eq!(writer.budget().refusals(Kind::Columns, Branch::Side), 5);
    assert_eq!(
        writer.budget().refusals(Kind::Columns, Branch::Canonical),
        1
    );
    assert_eq!(writer.reader().column_count().unwrap(), 11);
}

/// The budget never deletes: at its limit it refuses, and every row it admitted, the trusted
/// checkpoint (the stamp's finalized block) among them, is still there. Finalized data is
/// admitted and not charged however full the budget is; only the finality prune removes
/// columns, and lowers the counter as it does.
#[test]
fn checkpoint_never_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let writer = writer(dir.path(), small_caps());
    for slot in 1..=11 {
        write(&writer, slot, slot as u8, Branch::Canonical, 1).unwrap();
    }
    assert!(write(&writer, 12, 12, Branch::Canonical, 1).is_err());
    assert!(write(&writer, 12, 13, Branch::Side, 1).is_err());
    assert_eq!(writer.reader().column_count().unwrap(), 11);
    // Finalized columns are never refused (and are counted while above finality).
    write(&writer, 12, 14, Branch::Finalized, 1).unwrap();
    assert_eq!(columns_used(&writer).bytes, 1200);
    // Read through the writer's own env: a second open of it in this process would fail.
    let checkpoint = || {
        let t = writer.reader().read_txn().unwrap();
        let stamp = store_schema::stamp::read(&t).unwrap().expect("stamped");
        let blocks = t.open_table(Some(store_schema::tables::BLOCKS)).unwrap();
        let key = store_schema::keys::slot_root_key(stamp.finalized_slot, &stamp.finalized_root);
        t.get::<Vec<u8>>(&blocks, &key).unwrap().is_some()
    };
    assert!(checkpoint(), "the checkpoint block is stored");
    // The counter as stored, reloaded by a budget of its own; the checkpoint never charged.
    let budget = Budget::new(small_caps());
    budget.load(&writer.reader().read_txn().unwrap()).unwrap();
    assert_eq!(budget.used(Kind::Columns).bytes, 1200);
    for kind in [Kind::Blocks, Kind::States] {
        assert_eq!(
            writer.budget().used(kind),
            Usage::default(),
            "the checkpoint is not charged"
        );
    }
    // Finality removes columns, lowering the counter; the checkpoint stays.
    writer.prune_finalized(6).unwrap();
    assert_eq!(writer.reader().column_count().unwrap(), 6);
    assert_eq!(
        columns_used(&writer),
        Usage {
            bytes: 600,
            items: 6
        }
    );
    assert!(checkpoint(), "the checkpoint block is still stored");
}

/// The finalized branch of the direct API: admitted at any fill, nothing charged.
#[test]
fn finalized_data_is_never_charged_or_refused() {
    let dir = tempfile::tempdir().unwrap();
    let env = stamped_env(dir.path());
    let budget = Budget::new(small_caps());
    let t = txn::begin(&env).unwrap();
    assert!(budget
        .admit(&t, Kind::Blocks, Branch::Canonical, 1100, 1)
        .unwrap()
        .admitted());
    for kind in [Kind::Blocks, Kind::States, Kind::Envelopes] {
        assert_eq!(
            budget
                .admit(&t, kind, Branch::Finalized, u64::MAX, 1)
                .unwrap(),
            Decision::Admit
        );
    }
    assert_eq!(stored(&t, Kind::States).unwrap(), None);
    assert_eq!(budget.total(), 1100);
    assert_eq!(budget.refusals(Kind::States, Branch::Finalized), 0);
}

/// A write whose transaction aborts after its puts and its charge, before its commit, leaves
/// neither: after a reopen the counter is the one of the rows stored. Counters are reloaded at
/// open, never lost; an env written before the budget is counted once, at its first open.
#[test]
fn counters_are_atomic_with_the_write_and_reloaded_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let opts = || WriterOptions {
        max_size: MIN_MAX_SIZE,
    };
    let open = || {
        let budget = Arc::new(Budget::new(Caps::unlimited()));
        ColumnWriter::open_with_budget(dir.path(), opts(), budget).unwrap()
    };
    {
        let writer = writer(dir.path(), Caps::unlimited());
        write(&writer, 1, 1, Branch::Canonical, 2).unwrap();
        write(&writer, 2, 2, Branch::Side, 3).unwrap();
        writer.set_before_commit(Box::new(|slot| {
            assert!(slot != 3, "killed before the commit of slot 3");
        }));
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            write(&writer, 3, 3, Branch::Canonical, 4)
        }));
        assert!(crashed.is_err());
    }
    let writer = open();
    assert_eq!(
        columns_used(&writer),
        Usage {
            bytes: 500,
            items: 5
        }
    );
    assert_eq!(writer.reader().column_count().unwrap(), 5);
    assert_eq!(writer.reader().slot_of(&root(3)).unwrap(), None);
    let t = writer.reader().read_txn().unwrap();
    assert_eq!(
        stored(&t, Kind::Columns).unwrap(),
        Some(Usage {
            bytes: 500,
            items: 5
        })
    );
    drop(t);
    drop(writer);
    // An env written before the budget: no counter row. Its first open counts the columns above
    // finality and its first write stores the row.
    {
        let env = store_schema::env::test_writer(dir.path()).unwrap();
        let t = txn::begin(&env).unwrap();
        let meta = t.open_table(Some(store_schema::tables::META)).unwrap();
        assert!(t.del(&meta, b"budget_columns", None).unwrap());
        txn::commit(t, Update::Carry).unwrap();
    }
    let writer = open();
    assert_eq!(
        columns_used(&writer),
        Usage {
            bytes: 500,
            items: 5
        }
    );
    write(&writer, 4, 4, Branch::Canonical, 1).unwrap();
    drop(writer);
    let writer = open();
    assert_eq!(
        columns_used(&writer),
        Usage {
            bytes: 600,
            items: 6
        }
    );
}

/// Every prune lowers the counter by the unfinalized rows it removes, and finality releases the
/// rows it keeps for retention; retention pruning of finalized rows releases nothing again.
/// Each step's counter is the one a reopen reloads.
#[test]
fn prune_lowers_counters() {
    let dir = tempfile::tempdir().unwrap();
    let writer = writer(dir.path(), Caps::unlimited());
    write(&writer, 1, 1, Branch::Canonical, 1).unwrap();
    write(&writer, 2, 2, Branch::Side, 2).unwrap();
    write(&writer, 3, 3, Branch::Canonical, 3).unwrap();
    write(&writer, 3, 5, Branch::Side, 4).unwrap();
    write(&writer, 4, 4, Branch::Canonical, 5).unwrap();
    let check = |writer: &ColumnWriter, bytes: u64, rows: u64| {
        assert_eq!(columns_used(writer), Usage { bytes, items: rows });
        let t = writer.reader().read_txn().unwrap();
        assert_eq!(
            stored(&t, Kind::Columns).unwrap(),
            Some(Usage { bytes, items: rows })
        );
    };
    check(&writer, 1500, 15);
    writer.prune_orphaned(&[root(2)]).unwrap();
    check(&writer, 1300, 13);
    // Finality at slot 3 on the chain of 1 and 3: 5 goes, 1 and 3 stay for retention but no
    // longer count.
    let canonical: HashSet<BlockRoot> = [root(1), root(3)].into();
    writer.finalize(3, &canonical, 0).unwrap();
    assert_eq!(writer.reader().column_count().unwrap(), 9);
    check(&writer, 500, 5);
    writer.prune_before(4).unwrap();
    assert_eq!(writer.reader().column_count().unwrap(), 5);
    check(&writer, 500, 5);
    // Retention past finality removes unfinalized rows: released.
    writer.prune_before(5).unwrap();
    check(&writer, 0, 0);
    write(&writer, 6, 6, Branch::Canonical, 2).unwrap();
    writer.prune_finalized(6).unwrap();
    check(&writer, 0, 0);
}

// --- the floor -------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeState {
    space: Mutex<Option<FsSpace>>,
    calls: AtomicUsize,
    fail: AtomicBool,
}

/// A `statvfs` that answers what the test set, and counts its calls.
#[derive(Debug, Clone, Default)]
struct FakeFs(Arc<FakeState>);

impl FakeFs {
    fn set(&self, free: u64, total: u64) {
        *self.0.space.lock().unwrap() = Some(FsSpace { free, total });
    }

    fn calls(&self) -> usize {
        self.0.calls.load(Ordering::SeqCst)
    }
}

impl FsStats for FakeFs {
    fn space(&self, _: &Path) -> std::io::Result<FsSpace> {
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        if self.0.fail.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("statvfs failed"));
        }
        Ok(self.0.space.lock().unwrap().expect("set"))
    }
}

/// Below the floor the import gate closes; it reopens only once free space is a hysteresis
/// above it. A write over 16 MiB looks at the volume first, a smaller one does not. A failed
/// look leaves the gate as it was. Finalized reads go on while it is closed.
#[test]
fn floor_stops_import() {
    let dir = tempfile::tempdir().unwrap();
    let fs = FakeFs::default();
    // 100 GiB volume: the floor is 10 GiB (more than 5%), reopening at 11 GiB.
    fs.set(20 * GIB, 100 * GIB);
    let watcher = FloorWatcher::new(
        dir.path(),
        Box::new(fs.clone()),
        DiskBudget::default().floor(),
    );
    let gate = watcher.gate();
    assert!(watcher.tick().unwrap());
    assert!(gate.is_open());
    assert_eq!(watcher.free_bytes(), 20 * GIB);
    // Finalized columns, kept for retention, in a store the gate does not concern.
    {
        let writer = writer(&dir.path().join("columns"), Caps::unlimited());
        write(&writer, 1, 1, Branch::Canonical, 2).unwrap();
        writer.finalize(1, &[root(1)].into(), 0).unwrap();
    }
    fs.set(10 * GIB - 1, 100 * GIB);
    assert!(!watcher.tick().unwrap());
    assert!(!gate.is_open());
    assert!(matches!(gate.check(), Err(FloorError::Closed)));
    assert!(matches!(watcher.before_write(MIB), Err(FloorError::Closed)));
    let reader = ColumnReader::open(dir.path().join("columns")).unwrap();
    assert_eq!(reader.finalized_slot().unwrap(), Some(1));
    assert_eq!(reader.columns_for_root(&root(1)).unwrap().len(), 2);
    // Above the floor, within the hysteresis: still closed.
    fs.set(10 * GIB + 512 * MIB, 100 * GIB);
    assert!(!watcher.tick().unwrap());
    fs.set(11 * GIB, 100 * GIB);
    assert!(watcher.tick().unwrap());
    assert!(gate.check().is_ok());
    // Only a write over 16 MiB looks at the volume itself.
    let calls = fs.calls();
    watcher.before_write(16 * MIB).unwrap();
    assert_eq!(fs.calls(), calls);
    fs.set(5 * GIB, 100 * GIB);
    watcher.before_write(16 * MIB).unwrap();
    assert!(matches!(
        watcher.before_write(16 * MIB + 1),
        Err(FloorError::Closed)
    ));
    assert_eq!(fs.calls(), calls + 1);
    assert!(!gate.is_open());
    // A failed look changes nothing, and refuses the large write it was for.
    fs.set(50 * GIB, 100 * GIB);
    fs.0.fail.store(true, Ordering::SeqCst);
    assert!(watcher.tick().is_err());
    assert!(!gate.is_open());
    assert!(matches!(
        watcher.before_write(GIB),
        Err(FloorError::Stats(_))
    ));
    fs.0.fail.store(false, Ordering::SeqCst);
    assert!(watcher.tick().unwrap());
    // On a 1000 GiB volume the floor is 5%: 50 GiB.
    fs.set(50 * GIB - 1, 1000 * GIB);
    assert!(!watcher.tick().unwrap());
    assert!(reader.columns_for_root(&root(1)).unwrap().len() == 2);
}

/// The real `statvfs` reads this volume: no root, no mount.
#[test]
fn statvfs_reads_the_volume() {
    let dir = tempfile::tempdir().unwrap();
    let space = Statvfs.space(dir.path()).unwrap();
    assert!(space.total > 0);
    assert!(space.free <= space.total);
    assert!(Statvfs.space(&dir.path().join("missing")).is_err());
}

// --- the envelope window (Rec 23) -----------------------------------------------------------

/// Every unfinalized envelope is kept; a finalized one is kept inside
/// `[max(GLOAS_FORK_EPOCH, current - compute_min_epochs_for_block_requests()), current]` and
/// is prunable before it, but the anchor's never is. Sepolia's and Hoodi's values.
#[test]
fn envelope_window_rec23() {
    for (network, gloas) in [(Network::Sepolia, 353_024), (Network::Hoodi, 132_352)] {
        let config = ChainConfig::load(network).unwrap();
        let slot = |epoch: u64| epoch * 32;
        let anchor = slot(gloas + 10) + 5;
        let window = EnvelopeWindow::new(&config, 32, anchor).unwrap();
        assert_eq!(window.gloas_fork_epoch, gloas, "{network:?}");
        // EIP-8061 on mainnet values.
        assert_eq!(window.min_epochs, 14_299, "{network:?}");
        let keep = |at, finalized, current| keep_envelope(at, finalized, current, &window);
        // Early in Gloas the window starts at the fork.
        let current = gloas + 100;
        let finalized = slot(current - 2);
        assert!(keep(slot(gloas), finalized, current));
        assert!(keep(finalized, finalized, current));
        assert!(keep(finalized + 1, finalized, current));
        // Later it starts min_epochs before the current epoch.
        let current = gloas + 20_000;
        let start = gloas + 20_000 - 14_299;
        let finalized = slot(current - 3);
        assert!(keep(slot(start), finalized, current), "{network:?}");
        assert!(!keep(slot(start) - 1, finalized, current), "{network:?}");
        assert!(!keep(slot(gloas + 11), finalized, current));
        assert!(
            keep(anchor, finalized, current),
            "the anchor's is never pruned"
        );
        assert!(!keep(anchor + 1, finalized, current));
        assert!(keep(slot(current) + 31, finalized, current), "unfinalized");
        assert!(keep(finalized + 1, finalized, current));
    }
}

// --- metrics --------------------------------------------------------------------------------

/// The budget's and the floor's gauges and the refusal counter, at a scrape.
#[test]
fn the_metrics_follow_the_budget_and_the_floor() {
    let dir = tempfile::tempdir().unwrap();
    let writer = writer(dir.path(), small_caps());
    let fs = FakeFs::default();
    fs.set(20 * GIB, 100 * GIB);
    let watcher = Arc::new(FloorWatcher::new(
        dir.path(),
        Box::new(fs.clone()),
        DiskBudget::default().floor(),
    ));
    let mut registry = Registry::default();
    BudgetMetrics::register(
        &mut registry,
        Arc::clone(writer.budget()),
        Some(Arc::clone(&watcher)),
    );
    write(&writer, 1, 1, Branch::Canonical, 6).unwrap();
    assert!(write(&writer, 2, 2, Branch::Side, 1).is_err());
    watcher.tick().unwrap();
    let scrape = || {
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
        text
    };
    let text = scrape();
    for line in [
        "chain_disk_budget_bytes{kind=\"columns\"} 600",
        "chain_disk_budget_bytes{kind=\"aggregate\"} 600",
        "chain_disk_budget_bytes{kind=\"states\"} 0",
        "chain_disk_budget_cap_bytes{kind=\"columns\"} 600",
        "chain_disk_budget_cap_bytes{kind=\"aggregate\"} 1000",
        "chain_disk_budget_refusals_total{kind=\"columns\",branch=\"side\"} 1",
        "chain_disk_budget_refusals_total{kind=\"columns\",branch=\"canonical\"} 0",
        "chain_disk_budget_reached 1",
        "chain_disk_budget_refusals_total{kind=\"pending\",branch=\"side\"} 0",
        "chain_disk_free_bytes 21474836480",
        "chain_disk_floor_reached 0",
    ] {
        assert!(text.contains(line), "{line} in\n{text}");
    }
    fs.set(GIB, 100 * GIB);
    watcher.tick().unwrap();
    assert!(scrape().contains("chain_disk_floor_reached 1"));
}
