//! The non-finality disk budget's core, shared by every writer of the env: the per-kind
//! counters of unfinalized bytes and the admission decision at the budget. cl-chain-columns'
//! column writer enforces it now; cl-chain's import calls the same API when it lands. cl-chain
//! re-exports it as `persist::budget`, with the config, the free-space floor and the metrics,
//! and its README holds the proposed values.
//!
//! - **What counts.** Only unfinalized bytes: the stored value lengths of a kind's rows above
//!   finality (compressed where stored compressed), not MDBX page usage. Finalized data, the
//!   trusted checkpoint, the anchor and the finalized state ([`Branch::Finalized`]) are never
//!   charged and never refused.
//! - **Counters.** One `meta` row per [`Kind`] (`budget_<kind>`: bytes then items, `u64 BE`
//!   each), written in the same write transaction as the rows it counts, so a transaction that
//!   aborts leaves both as they were. A finality prune lowers it in its own transaction. A
//!   writer reloads the counters from these rows when it opens the env ([`Budget::load`]); it
//!   never rescans to find them.
//! - **At the budget** ([`decide`]). A write that would take its kind over its cap, or all
//!   kinds over the aggregate, is IGNOREd on a side branch. The canonical branch is still
//!   admitted up to the aggregate plus [`Caps::headroom_percent`]; past that it is IGNOREd too.
//!   Item caps bind both. The caller says which branch a write is on; the budget never decides
//!   fork choice.
//! - **Never deletes.** The budget only refuses writes; pruning stays with each table's owner.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    OnceLock,
};

use libmdbx::WriteFlags;

use crate::{
    tables::META,
    txn::{ReadTxn, RwTxn},
    Error, Result,
};

/// How many [`Kind`]s there are.
pub const KINDS: usize = 6;

/// What a counted row holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Unfinalized blocks: no cap of their own, only the aggregate.
    Blocks,
    /// State snapshots.
    States,
    /// Fork-choice snapshots.
    FcSnapshots,
    /// Data column sidecars.
    Columns,
    /// Execution payload envelopes.
    Envelopes,
    /// Blocks and columns waiting for their parent or their data.
    Pending,
}

impl Kind {
    /// Every kind, in counter order.
    pub const ALL: [Kind; KINDS] = [
        Kind::Blocks,
        Kind::States,
        Kind::FcSnapshots,
        Kind::Columns,
        Kind::Envelopes,
        Kind::Pending,
    ];

    /// Its name in metrics and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Blocks => "blocks",
            Kind::States => "states",
            Kind::FcSnapshots => "fc_snapshots",
            Kind::Columns => "columns",
            Kind::Envelopes => "envelopes",
            Kind::Pending => "pending",
        }
    }

    /// Its counter's `meta` key.
    const fn key(self) -> &'static [u8] {
        match self {
            Kind::Blocks => b"budget_blocks",
            Kind::States => b"budget_states",
            Kind::FcSnapshots => b"budget_fc_snapshots",
            Kind::Columns => b"budget_columns",
            Kind::Envelopes => b"budget_envelopes",
            Kind::Pending => b"budget_pending",
        }
    }
}

/// The branch a write is on, as the caller knows it (the head's chain at write time).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Branch {
    /// Finalized data, the trusted checkpoint, the anchor: never charged, never refused.
    Finalized,
    /// The canonical chain above finality.
    Canonical,
    /// Any other branch above finality.
    Side,
}

impl Branch {
    /// Its name in metrics and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Branch::Finalized => "finalized",
            Branch::Canonical => "canonical",
            Branch::Side => "side",
        }
    }
}

/// One kind's stored unfinalized bytes and rows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub bytes: u64,
    pub items: u64,
}

/// The budget's caps, by [`Kind`] in [`Kind::ALL`] order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// All kinds' unfinalized bytes together.
    pub aggregate: u64,
    /// Each kind's bytes; `None` is bound by the aggregate only.
    pub bytes: [Option<u64>; KINDS],
    /// Each kind's rows; `None` is unbounded.
    pub items: [Option<u64>; KINDS],
    /// How far over the aggregate canonical writes are still admitted, in percent of it.
    pub headroom_percent: u64,
}

impl Caps {
    /// No cap at all: counted, never refused.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            aggregate: u64::MAX,
            bytes: [None; KINDS],
            items: [None; KINDS],
            headroom_percent: 0,
        }
    }

    /// The aggregate plus the canonical headroom.
    #[must_use]
    pub fn canonical_limit(&self) -> u64 {
        let headroom = u128::from(self.aggregate) * u128::from(self.headroom_percent) / 100;
        u64::try_from(headroom).map_or(u64::MAX, |h| self.aggregate.saturating_add(h))
    }
}

/// What the budget says to a write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Within every cap (or finalized).
    Admit,
    /// Canonical, over a cap but within the canonical headroom.
    Headroom,
    /// IGNORE: nothing of it is written.
    Ignore,
}

impl Decision {
    /// Whether the write goes ahead.
    #[must_use]
    pub const fn admitted(self) -> bool {
        !matches!(self, Decision::Ignore)
    }
}

/// The decision for `bytes` and `items` more of `kind` on `branch`, with `used` stored now.
#[must_use]
pub fn decide(
    caps: &Caps,
    used: &[Usage; KINDS],
    kind: Kind,
    branch: Branch,
    bytes: u64,
    items: u64,
) -> Decision {
    if branch == Branch::Finalized {
        return Decision::Admit;
    }
    let (k, own) = (kind as usize, used[kind as usize]);
    let total = used
        .iter()
        .fold(bytes, |sum, used| sum.saturating_add(used.bytes));
    let items_ok = caps.items[k].is_none_or(|cap| own.items.saturating_add(items) <= cap);
    let bytes_ok = caps.bytes[k].is_none_or(|cap| own.bytes.saturating_add(bytes) <= cap);
    if items_ok && bytes_ok && total <= caps.aggregate {
        Decision::Admit
    } else if branch == Branch::Canonical && items_ok && total <= caps.canonical_limit() {
        Decision::Headroom
    } else {
        Decision::Ignore
    }
}

/// `kind`'s counter row as `txn` sees it; `None` if it was never written.
///
/// # Errors
///
/// An MDBX error, or [`Error::Corrupt`] for a row that is not 16 bytes.
pub fn stored(txn: &impl ReadTxn, kind: Kind) -> Result<Option<Usage>> {
    let meta = txn.open_table(Some(META))?;
    match txn.get::<[u8; 16]>(&meta, kind.key()) {
        Ok(row) => Ok(row.map(|row| {
            let (bytes, items) = row.split_at(8);
            let u64_of = |half: &[u8]| u64::from_be_bytes(half.try_into().unwrap_or_default());
            Usage {
                bytes: u64_of(bytes),
                items: u64_of(items),
            }
        })),
        Err(libmdbx::Error::DecodeError(_)) => Err(Error::Corrupt { table: META }),
        Err(e) => Err(e.into()),
    }
}

/// Called with `(reached, kind, branch)` each time the budget is reached or left
/// ([`Budget::on_transition`]).
pub type Observer = Box<dyn Fn(bool, Kind, Branch) + Send + Sync>;

/// The budget of one env: its caps, a mirror of its counters for metrics, its refusals and
/// whether it is reached. Shared by every writer of the env (an `Arc`).
///
/// The mirror follows each charge and release as the transaction makes it; a writer whose
/// transaction aborts calls [`Budget::load`] again.
pub struct Budget {
    caps: Caps,
    used: [[AtomicU64; 2]; KINDS],
    refusals: [[AtomicU64; 2]; KINDS],
    reached: AtomicBool,
    observer: OnceLock<Observer>,
}

impl std::fmt::Debug for Budget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Budget")
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl Budget {
    /// A budget of `caps`, its counters at zero until [`Self::load`].
    #[must_use]
    pub fn new(caps: Caps) -> Self {
        Self {
            caps,
            used: Default::default(),
            refusals: Default::default(),
            reached: AtomicBool::new(false),
            observer: OnceLock::new(),
        }
    }

    /// The caps.
    #[must_use]
    pub fn caps(&self) -> &Caps {
        &self.caps
    }

    /// `kind`'s counter, as last charged, released or loaded.
    #[must_use]
    pub fn used(&self, kind: Kind) -> Usage {
        let [bytes, items] = &self.used[kind as usize];
        Usage {
            bytes: bytes.load(Ordering::Relaxed),
            items: items.load(Ordering::Relaxed),
        }
    }

    /// Every kind's bytes together.
    #[must_use]
    pub fn total(&self) -> u64 {
        Kind::ALL
            .iter()
            .fold(0, |sum, &kind| sum.saturating_add(self.used(kind).bytes))
    }

    /// Sets `kind`'s mirrored counter (what a writer counted itself).
    pub fn set(&self, kind: Kind, usage: Usage) {
        let [bytes, items] = &self.used[kind as usize];
        bytes.store(usage.bytes, Ordering::Relaxed);
        items.store(usage.items, Ordering::Relaxed);
    }

    /// Writes of `kind` on `branch` refused so far.
    #[must_use]
    pub fn refusals(&self, kind: Kind, branch: Branch) -> u64 {
        match branch {
            Branch::Finalized => 0,
            Branch::Canonical => self.refusals[kind as usize][0].load(Ordering::Relaxed),
            Branch::Side => self.refusals[kind as usize][1].load(Ordering::Relaxed),
        }
    }

    /// Whether the last decision refused a write (until one is admitted within the caps).
    #[must_use]
    pub fn reached(&self) -> bool {
        self.reached.load(Ordering::Relaxed)
    }

    /// Sets the observer of the budget's transitions; only the first call sets it.
    pub fn on_transition(&self, observer: Observer) {
        let _ = self.observer.set(observer);
    }

    /// Mirrors every counter row `txn` sees (a missing one is zero).
    ///
    /// # Errors
    ///
    /// As [`stored`].
    pub fn load(&self, txn: &impl ReadTxn) -> Result<()> {
        for kind in Kind::ALL {
            self.set(kind, stored(txn, kind)?.unwrap_or_default());
        }
        Ok(())
    }

    /// Decides `bytes` and `items` more of `kind` on `branch` against the counters `txn` holds
    /// ([`decide`]) and, if admitted on a branch above finality, charges them in `txn`. A
    /// refusal is counted, and may mark the budget reached.
    ///
    /// # Errors
    ///
    /// As [`stored`], or the write of the row.
    pub fn admit(
        &self,
        txn: &RwTxn<'_>,
        kind: Kind,
        branch: Branch,
        bytes: u64,
        items: u64,
    ) -> Result<Decision> {
        if branch == Branch::Finalized {
            return Ok(Decision::Admit);
        }
        let mut used = [Usage::default(); KINDS];
        for kind in Kind::ALL {
            used[kind as usize] = stored(txn, kind)?.unwrap_or_default();
        }
        let decision = decide(&self.caps, &used, kind, branch, bytes, items);
        match decision {
            Decision::Ignore => {
                let side = usize::from(branch == Branch::Side);
                self.refusals[kind as usize][side].fetch_add(1, Ordering::Relaxed);
                self.mark(true, kind, branch);
            }
            Decision::Admit | Decision::Headroom => {
                if decision == Decision::Admit {
                    self.mark(false, kind, branch);
                }
                self.charge(txn, kind, bytes, items)?;
            }
        }
        Ok(decision)
    }

    /// Adds `bytes` and `items` to `kind`'s counter in `txn`, with no decision; the new counter.
    ///
    /// # Errors
    ///
    /// As [`Self::admit`].
    pub fn charge(&self, txn: &RwTxn<'_>, kind: Kind, bytes: u64, items: u64) -> Result<Usage> {
        self.apply(txn, kind, |u| Usage {
            bytes: u.bytes.saturating_add(bytes),
            items: u.items.saturating_add(items),
        })
    }

    /// Takes `bytes` and `items` off `kind`'s counter in `txn` (at zero at the least); the new
    /// counter.
    ///
    /// # Errors
    ///
    /// As [`Self::admit`].
    pub fn release(&self, txn: &RwTxn<'_>, kind: Kind, bytes: u64, items: u64) -> Result<Usage> {
        self.apply(txn, kind, |u| Usage {
            bytes: u.bytes.saturating_sub(bytes),
            items: u.items.saturating_sub(items),
        })
    }

    /// Writes `f` of `kind`'s stored counter to its row and the mirror.
    fn apply(&self, txn: &RwTxn<'_>, kind: Kind, f: impl FnOnce(Usage) -> Usage) -> Result<Usage> {
        let usage = f(stored(txn, kind)?.unwrap_or_default());
        let mut row = [0u8; 16];
        row[..8].copy_from_slice(&usage.bytes.to_be_bytes());
        row[8..].copy_from_slice(&usage.items.to_be_bytes());
        let meta = txn.open_table(Some(META))?;
        txn.put(&meta, kind.key(), row, WriteFlags::UPSERT)?;
        self.set(kind, usage);
        Ok(usage)
    }

    /// Sets `reached`, telling the observer if it changed.
    fn mark(&self, reached: bool, kind: Kind, branch: Branch) {
        if self.reached.swap(reached, Ordering::Relaxed) != reached {
            if let Some(observer) = self.observer.get() {
                observer(reached, kind, branch);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{self, WriterEnv, WriterOptions, MIN_MAX_SIZE};
    use crate::{tables::META, txn};
    use libmdbx::WriteFlags;
    use std::sync::{Arc, Mutex};

    fn fresh() -> (tempfile::TempDir, WriterEnv) {
        let dir = tempfile::tempdir().unwrap();
        let opts = WriterOptions {
            max_size: MIN_MAX_SIZE,
        };
        let writer = env::open_writer(dir.path(), opts).unwrap();
        (dir, writer)
    }

    /// Aggregate 100 B, 10% headroom, columns at most 60 B, pending at most 2 rows.
    fn caps() -> Caps {
        let mut caps = Caps {
            aggregate: 100,
            headroom_percent: 10,
            ..Caps::unlimited()
        };
        caps.bytes[Kind::Columns as usize] = Some(60);
        caps.items[Kind::Pending as usize] = Some(2);
        caps
    }

    fn used(columns: u64, states: u64) -> [Usage; KINDS] {
        let mut used = [Usage::default(); KINDS];
        used[Kind::Columns as usize].bytes = columns;
        used[Kind::States as usize].bytes = states;
        used
    }

    #[test]
    fn names_are_distinct() {
        let names: std::collections::HashSet<_> = Kind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(names.len(), KINDS);
        assert_eq!(Kind::FcSnapshots.name(), "fc_snapshots");
        assert_eq!(Branch::Side.name(), "side");
        assert_eq!(Branch::Canonical.name(), "canonical");
    }

    /// Within every cap: admitted. Over the kind's cap or the aggregate: a side branch is
    /// ignored, the canonical one admitted up to the aggregate's headroom; an item cap binds
    /// both; a finalized write is admitted whatever is stored.
    #[test]
    fn the_decision_at_the_budget() {
        use Branch::*;
        use Decision::*;
        let caps = caps();
        assert_eq!(caps.canonical_limit(), 110);
        assert_eq!(Caps::unlimited().canonical_limit(), u64::MAX);
        let cases = [
            (used(50, 0), Kind::Columns, Side, 10, Admit),
            (used(50, 0), Kind::Columns, Side, 11, Ignore),
            (used(50, 0), Kind::Columns, Canonical, 11, Headroom),
            (used(50, 40), Kind::States, Side, 10, Admit),
            (used(50, 40), Kind::States, Side, 11, Ignore),
            (used(50, 40), Kind::States, Canonical, 20, Headroom),
            (used(50, 40), Kind::States, Canonical, 21, Ignore),
            (used(60, 51), Kind::Blocks, Canonical, 0, Ignore),
            (used(60, 50), Kind::Blocks, Finalized, u64::MAX, Admit),
            (used(u64::MAX, 0), Kind::Columns, Side, 1, Ignore),
        ];
        for (used, kind, branch, bytes, want) in cases {
            let got = decide(&caps, &used, kind, branch, bytes, 1);
            assert_eq!(got, want, "{kind:?} {branch:?} {bytes} over {used:?}");
            assert_eq!(got.admitted(), want != Ignore);
        }
        let mut pending = used(0, 0);
        pending[Kind::Pending as usize].items = 2;
        for branch in [Canonical, Side] {
            assert_eq!(decide(&caps, &pending, Kind::Pending, branch, 1, 1), Ignore);
            assert_eq!(decide(&caps, &pending, Kind::Pending, branch, 1, 0), Admit);
        }
        assert_eq!(
            decide(&caps, &pending, Kind::Pending, Finalized, 1, 1),
            Admit
        );
    }

    /// The counter is a row of the transaction that charges it: dropped with it, committed
    /// with it, and what a later load mirrors.
    #[test]
    fn counters_are_rows_of_the_charging_transaction() {
        let (_dir, writer) = fresh();
        let budget = Budget::new(caps());
        let t = txn::begin(&writer).unwrap();
        assert_eq!(
            budget.admit(&t, Kind::States, Branch::Side, 30, 1).unwrap(),
            Decision::Admit
        );
        assert_eq!(
            stored(&t, Kind::States).unwrap(),
            Some(Usage {
                bytes: 30,
                items: 1
            })
        );
        drop(t);
        let t = writer.begin_ro_txn().unwrap();
        assert_eq!(stored(&t, Kind::States).unwrap(), None);
        drop(t);
        let t = txn::begin(&writer).unwrap();
        budget
            .admit(&t, Kind::States, Branch::Canonical, 30, 1)
            .unwrap();
        budget.charge(&t, Kind::Columns, 7, 2).unwrap();
        t.into_raw().commit().unwrap();
        let fresh = Budget::new(caps());
        fresh.load(&writer.begin_ro_txn().unwrap()).unwrap();
        assert_eq!(
            fresh.used(Kind::States),
            Usage {
                bytes: 30,
                items: 1
            }
        );
        assert_eq!(fresh.used(Kind::Columns), Usage { bytes: 7, items: 2 });
        assert_eq!(fresh.used(Kind::Blocks), Usage::default());
        assert_eq!(fresh.total(), 37);
        // A release stops at zero.
        let t = txn::begin(&writer).unwrap();
        let left = fresh.release(&t, Kind::Columns, 5, 1).unwrap();
        assert_eq!(left, Usage { bytes: 2, items: 1 });
        assert_eq!(
            fresh.release(&t, Kind::Columns, 5, 5).unwrap(),
            Usage::default()
        );
        assert_eq!(fresh.used(Kind::Columns), Usage::default());
    }

    /// A finalized write is admitted and not charged; a refusal is counted by kind and branch;
    /// `reached` changes only on a refusal (up) and on an admission within the caps (down),
    /// and the observer hears each change once.
    #[test]
    fn refusals_and_the_reached_edge() {
        let (_dir, writer) = fresh();
        let budget = Budget::new(caps());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        budget.on_transition(Box::new(move |reached, kind, branch| {
            log.lock().unwrap().push((reached, kind, branch));
        }));
        let t = txn::begin(&writer).unwrap();
        let admit = |kind, branch, bytes| budget.admit(&t, kind, branch, bytes, 1).unwrap();
        assert_eq!(
            admit(Kind::States, Branch::Finalized, 1_000),
            Decision::Admit
        );
        assert_eq!(stored(&t, Kind::States).unwrap(), None);
        assert_eq!(admit(Kind::Columns, Branch::Canonical, 60), Decision::Admit);
        assert_eq!(admit(Kind::Columns, Branch::Side, 1), Decision::Ignore);
        assert_eq!(admit(Kind::Columns, Branch::Side, 1), Decision::Ignore);
        assert!(budget.reached());
        assert_eq!(
            admit(Kind::Columns, Branch::Canonical, 5),
            Decision::Headroom
        );
        assert!(budget.reached());
        assert_eq!(admit(Kind::States, Branch::Side, 30), Decision::Admit);
        assert!(!budget.reached());
        assert_eq!(budget.refusals(Kind::Columns, Branch::Side), 2);
        assert_eq!(budget.refusals(Kind::Columns, Branch::Canonical), 0);
        assert_eq!(budget.refusals(Kind::States, Branch::Finalized), 0);
        assert_eq!(budget.used(Kind::Columns).bytes, 65);
        assert_eq!(
            *seen.lock().unwrap(),
            [
                (true, Kind::Columns, Branch::Side),
                (false, Kind::States, Branch::Side)
            ]
        );
    }

    #[test]
    fn a_counter_row_of_another_length_is_corrupt() {
        let (_dir, writer) = fresh();
        let t = txn::begin(&writer).unwrap();
        let meta = t.open_table(Some(META)).unwrap();
        t.put(&meta, b"budget_columns", [0u8; 8], WriteFlags::UPSERT)
            .unwrap();
        let err = stored(&t, Kind::Columns).unwrap_err();
        assert!(
            matches!(err, crate::Error::Corrupt { table: META }),
            "{err}"
        );
    }
}
