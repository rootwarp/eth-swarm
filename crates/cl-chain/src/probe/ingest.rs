//! [`ColumnIngest`]: the forward-only store of custody column sidecars from gossip.
//!
//! cl-p2p's ignore-all gossipsub reports IGNORE for every `data_column_sidecar_{subnet_id}`
//! message and hands the decoded sidecar to cl-chain; [`ColumnIngest::on_column`] takes it from
//! there and answers [`Verdict::Ignore`] for every column, stored or not. So no column this node
//! stores is ever re-broadcast. That is a recorded deviation from `gloas/p2p-interface.md`
//! L1292–1294 ("If validation succeeds, the client MUST re-broadcast the sidecar"): the probe
//! imports no block, so it vouches for no column to its peers.
//!
//! Each column goes through, in order:
//!
//! 1. **The pending queue** ([`IngestLimits::max_items`], [`IngestLimits::max_bytes`]). A column
//!    holds a place, sized by its SSZ, from its arrival until it is stored or dropped. One that
//!    would pass either cap is dropped at once and counted in
//!    `probe_column_queue_dropped_total`. `probe_column_buffer_bytes` is the bytes queued now,
//!    and `probe_column_buffer_alert` is 1 while they are at or above
//!    [`IngestLimits::alert_bytes`] ([`COLUMN_BUFFER_ALERT_BYTES`], 48 MiB).
//! 2. **The local checks** of the storage contract: structure, subnet, custody, and forward only
//!    ([`super::column`]). A column before `cgc_set_slot` is dropped as `before_cgc_set_slot`:
//!    nothing is backfilled.
//! 3. **The root wait.** A column whose block root the reference does not know yet waits for it
//!    (`gloas/p2p-interface.md` L1322–1324: "MAY be queued until block is retrieved"), asking
//!    again every [`IngestLimits::root_retry`], for at most [`IngestLimits::root_wait`] from its
//!    arrival. Then it is dropped as `root_timeout`.
//! 4. **The storage contract** ([`storage_contract`]): root, commitments, KZG through
//!    cl-verify.
//! 5. **The write**, on the [`WRITER_THREAD`] thread: the columns of one block in transactions
//!    of at most [`MAX_COLUMNS_PER_TXN`] (16), each at the column env's background priority, so
//!    block import goes first ([`ColumnWriter::write_columns`]). A refused write is dropped as
//!    `store_failed`.
//!
//! The first stored slot ([`first_stored_column_slot`]) is written in the transaction that
//! stores the column, so it survives a crash together with the columns. Pruning on finality and
//! reorg stays with the column env ([`ColumnWriter::prune_finalized`],
//! [`ColumnWriter::prune_orphaned`]).

use super::column::{local_check, storage_contract, ColumnContract, ColumnMetrics, Drop};
use super::{BlockApi, GossipColumn, RefError, RefView, ReferenceApi, Root};
use crate::da::custody::Custody;
use crate::verify::client::KzgVerifier;
use cl_chain_columns::{Column, ColumnReader, ColumnWriter, MAX_COLUMNS_PER_TXN};
use consensus_types::primitives::Slot;
use consensus_types::EthSpec;
use ethswarm_proto::common::Verdict;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use ssz::Encode;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::Instant;

/// Queued column bytes at which `probe_column_buffer_alert` turns on: 48 MiB.
pub const COLUMN_BUFFER_ALERT_BYTES: usize = 48 << 20;

/// How long a column waits for the reference to learn its block root \[est\]. Provisional: no
/// deadline for this wait is pinned yet, so this is a third of a 12 s slot, long enough for the
/// reference to import a block whose columns arrived first.
pub const DEFAULT_ROOT_WAIT: Duration = Duration::from_secs(4);

/// How often a waiting column asks the reference for its root again \[est\].
pub const DEFAULT_ROOT_RETRY: Duration = Duration::from_millis(250);

/// The name of the thread that writes the column env.
pub const WRITER_THREAD: &str = "columns-writer";

/// Columns the writer takes off its queue for one batch \[est\]: one full block.
const MAX_BATCH: usize = 128;

/// The bounds of a [`ColumnIngest`] (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestLimits {
    /// Columns queued at once, from arrival until stored or dropped.
    pub max_items: usize,
    /// Their SSZ bytes.
    pub max_bytes: usize,
    /// Queued bytes at which `probe_column_buffer_alert` turns on.
    pub alert_bytes: usize,
    /// How long a column waits for its block root, from its arrival.
    pub root_wait: Duration,
    /// How often a waiting column asks for its root again.
    pub root_retry: Duration,
}

impl Default for IngestLimits {
    /// 512 columns (four blocks at full custody) and 64 MiB queued \[est\], the alert at
    /// [`COLUMN_BUFFER_ALERT_BYTES`], [`DEFAULT_ROOT_WAIT`] and [`DEFAULT_ROOT_RETRY`].
    fn default() -> Self {
        Self {
            max_items: 512,
            max_bytes: 64 << 20,
            alert_bytes: COLUMN_BUFFER_ALERT_BYTES,
            root_wait: DEFAULT_ROOT_WAIT,
            root_retry: DEFAULT_ROOT_RETRY,
        }
    }
}

/// The column store's queue and write metrics.
#[derive(Debug, Clone, Default)]
pub struct QueueMetrics {
    queue_dropped: Counter,
    stored: Counter,
    buffer_bytes: Gauge,
    buffer_alert: Gauge,
}

impl QueueMetrics {
    /// Registers `probe_column_queue_dropped_total`, `probe_column_stored_total`,
    /// `probe_column_buffer_bytes` and `probe_column_buffer_alert` in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self::default();
        registry.register(
            "probe_column_queue_dropped",
            "Gossip column sidecars dropped because the pending queue was full (items or bytes)",
            metrics.queue_dropped.clone(),
        );
        registry.register(
            "probe_column_stored",
            "Gossip column sidecars written to the column env",
            metrics.stored.clone(),
        );
        registry.register(
            "probe_column_buffer_bytes",
            "SSZ bytes of the gossip column sidecars queued, from arrival until stored or dropped",
            metrics.buffer_bytes.clone(),
        );
        registry.register(
            "probe_column_buffer_alert",
            "1 while probe_column_buffer_bytes is at or above the alert level, else 0",
            metrics.buffer_alert.clone(),
        );
        metrics
    }

    /// Columns dropped because the queue was full, so far.
    #[must_use]
    pub fn queue_dropped(&self) -> u64 {
        self.queue_dropped.get()
    }

    /// Columns written to the column env, so far.
    #[must_use]
    pub fn stored(&self) -> u64 {
        self.stored.get()
    }
}

/// The lowest slot a column was ever stored at, as persisted with the columns; `None` before
/// the first one.
///
/// # Errors
///
/// The column env's.
pub fn first_stored_column_slot(
    reader: &ColumnReader,
) -> Result<Option<Slot>, cl_chain_columns::Error> {
    reader.first_stored_slot()
}

#[derive(Debug, Default, Clone, Copy)]
struct Pending {
    items: usize,
    bytes: usize,
}

/// The pending queue's accounting.
struct Queue {
    limits: IngestLimits,
    pending: Mutex<Pending>,
    metrics: QueueMetrics,
}

impl Queue {
    /// A place for a column of `bytes`, or `None` if it would pass a cap.
    fn admit(self: &Arc<Self>, bytes: usize) -> Option<Place> {
        let mut pending = self.lock();
        let items = pending.items + 1;
        let total = pending.bytes.checked_add(bytes)?;
        if items > self.limits.max_items || total > self.limits.max_bytes {
            return None;
        }
        *pending = Pending {
            items,
            bytes: total,
        };
        self.publish(*pending);
        Some(Place {
            queue: Arc::clone(self),
            bytes,
        })
    }

    fn release(&self, bytes: usize) {
        let mut pending = self.lock();
        pending.items -= 1;
        pending.bytes -= bytes;
        self.publish(*pending);
    }

    /// Sets the gauges; called under the lock, so they move in the queue's order.
    fn publish(&self, pending: Pending) {
        let metrics = &self.metrics;
        metrics
            .buffer_bytes
            .set(i64::try_from(pending.bytes).unwrap_or(i64::MAX));
        let alert = pending.bytes >= self.limits.alert_bytes;
        if alert != (metrics.buffer_alert.get() == 1) {
            if alert {
                tracing::warn!(bytes = pending.bytes, "column buffer above its alert level");
            } else {
                tracing::info!(
                    bytes = pending.bytes,
                    "column buffer back below its alert level"
                );
            }
            metrics.buffer_alert.set(i64::from(alert));
        }
    }

    /// The counts are updated together under the lock, so a panic cannot leave them half-set.
    fn lock(&self) -> MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One column's place in the pending queue, given back when dropped.
struct Place {
    queue: Arc<Queue>,
    bytes: usize,
}

impl std::ops::Drop for Place {
    fn drop(&mut self) {
        self.queue.release(self.bytes);
    }
}

/// One verified column for the writer thread, holding its queue place until written.
struct Write {
    slot: Slot,
    root: Root,
    index: u64,
    ssz: Vec<u8>,
    _place: Place,
}

/// What a column's task works with.
struct Shared<A, E, V, S, C> {
    refs: RefView<A, E>,
    custody: Custody<S, C>,
    contract: ColumnContract<V>,
    limits: IngestLimits,
}

/// The forward-only custody column store (see the module docs).
///
/// [`ColumnIngest::on_column`] runs each column on its own task of the current tokio runtime,
/// at most [`IngestLimits::max_items`] at a time. Dropping the store aborts those tasks, lets the
/// writer thread finish the columns already handed to it and joins it.
pub struct ColumnIngest<A, E, V, S, C> {
    shared: Arc<Shared<A, E, V, S, C>>,
    queue: Arc<Queue>,
    tasks: Mutex<JoinSet<()>>,
    /// The only strong sender: the writer thread ends once it is dropped and its queue drained.
    writes: Option<mpsc::Sender<Write>>,
    writer_thread: Option<JoinHandle<()>>,
    writer: Arc<ColumnWriter>,
}

impl<A, E, V, S, C> ColumnIngest<A, E, V, S, C>
where
    A: ReferenceApi + BlockApi + 'static,
    E: EthSpec,
    V: KzgVerifier + 'static,
    S: Send + Sync + 'static,
    C: Send + Sync + 'static,
{
    /// A store checking columns against `refs`, `custody` and `contract`, writing them through
    /// `writer` on a new [`WRITER_THREAD`] thread, with its queue metrics in `metrics`.
    ///
    /// # Errors
    ///
    /// The thread could not be spawned.
    pub fn start(
        refs: RefView<A, E>,
        custody: Custody<S, C>,
        contract: ColumnContract<V>,
        writer: Arc<ColumnWriter>,
        limits: IngestLimits,
        metrics: QueueMetrics,
    ) -> std::io::Result<Self> {
        // Every job holds a queue place, so the channel never holds more than `max_items`.
        let (writes, jobs) = mpsc::channel(limits.max_items.max(1));
        let writer_thread = std::thread::Builder::new()
            .name(WRITER_THREAD.into())
            .spawn({
                let writer = Arc::clone(&writer);
                let dropped = contract.metrics.clone();
                let metrics = metrics.clone();
                move || run_writer(&writer, jobs, &dropped, &metrics)
            })?;
        Ok(Self {
            shared: Arc::new(Shared {
                refs,
                custody,
                contract,
                limits,
            }),
            queue: Arc::new(Queue {
                limits,
                pending: Mutex::default(),
                metrics,
            }),
            tasks: Mutex::default(),
            writes: Some(writes),
            writer_thread: Some(writer_thread),
            writer,
        })
    }

    /// Takes a column sidecar from gossip; see the module docs. The verdict is always
    /// [`Verdict::Ignore`]: nothing is re-broadcast. Must be called within a tokio runtime.
    pub fn on_column(&self, column: GossipColumn<E>) -> Verdict {
        let bytes = column.sidecar.ssz_bytes_len();
        let Some(place) = self.queue.admit(bytes) else {
            self.queue.metrics.queue_dropped.inc();
            tracing::debug!(
                index = column.sidecar.index,
                slot = column.sidecar.slot,
                subnet = column.subnet_id,
                bytes,
                "column queue full: column sidecar dropped"
            );
            return Verdict::Ignore;
        };
        let Some(writes) = self.writes.as_ref().map(mpsc::Sender::downgrade) else {
            return Verdict::Ignore;
        };
        let arrived = Instant::now();
        let shared = Arc::clone(&self.shared);
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some(finished) = tasks.try_join_next() {
            if let Err(e) = finished {
                tracing::error!(error = %e, "a column task ended abnormally");
            }
        }
        tasks.spawn(async move { shared.process(column, place, &writes, arrived).await });
        Verdict::Ignore
    }
}

impl<A, E, V, S, C> ColumnIngest<A, E, V, S, C> {
    /// Columns queued now: arrived, neither stored nor dropped yet.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.queue.lock().items
    }

    /// Their SSZ bytes.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.queue.lock().bytes
    }

    /// The custody the columns are checked against.
    #[must_use]
    pub fn custody(&self) -> &Custody<S, C> {
        &self.shared.custody
    }

    /// The storage contract, with its drop counts.
    #[must_use]
    pub fn contract(&self) -> &ColumnContract<V> {
        &self.shared.contract
    }

    /// [`first_stored_column_slot`] of this store's env.
    ///
    /// # Errors
    ///
    /// The column env's.
    pub fn first_stored_column_slot(&self) -> Result<Option<Slot>, cl_chain_columns::Error> {
        first_stored_column_slot(self.writer.reader())
    }
}

impl<A, E, V, S, C> std::ops::Drop for ColumnIngest<A, E, V, S, C> {
    fn drop(&mut self) {
        self.tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .abort_all();
        drop(self.writes.take());
        if let Some(thread) = self.writer_thread.take() {
            if thread.join().is_err() {
                tracing::error!("the {WRITER_THREAD} thread panicked");
            }
        }
    }
}

impl<A, E, V, S, C> Shared<A, E, V, S, C>
where
    A: ReferenceApi + BlockApi,
    E: EthSpec,
    V: KzgVerifier,
{
    /// Steps 2 to 4 of the module docs, then hands the column to the writer thread.
    async fn process(
        &self,
        column: GossipColumn<E>,
        place: Place,
        writes: &mpsc::WeakSender<Write>,
        arrived: Instant,
    ) {
        let metrics = &self.contract.metrics;
        if let Err(reason) = local_check(&column, &self.custody) {
            metrics.drop_column(&column, reason);
            return;
        }
        let root = column.sidecar.beacon_block_root.0;
        if !self
            .wait_for_root(root, arrived + self.limits.root_wait)
            .await
        {
            metrics.drop_column(&column, Drop::RootTimeout);
            return;
        }
        let Ok(verified) =
            storage_contract(&column, &self.refs, &self.custody, &self.contract).await
        else {
            return;
        };
        let sidecar = verified.sidecar();
        let write = Write {
            slot: sidecar.slot,
            root,
            index: sidecar.index,
            ssz: sidecar.as_ssz_bytes(),
            _place: place,
        };
        // Never blocks: the channel has room for every queue place. A store being dropped has
        // no writer any more.
        let sent = writes.upgrade().map(|tx| tx.try_send(write).is_ok());
        if sent != Some(true) {
            metrics.drop_column(&column, Drop::StoreFailed);
        }
    }

    /// Whether the reference knows `root` before `deadline`, asking every `root_retry`.
    async fn wait_for_root(&self, root: Root, deadline: Instant) -> bool {
        loop {
            if Instant::now() >= deadline {
                return false;
            }
            match tokio::time::timeout_at(deadline, self.refs.lookup(root)).await {
                Err(_) => return false,
                Ok(Ok(_)) => return true,
                // The reference names the root but its block does not establish it. Waiting
                // changes nothing; the contract drops the column as `unknown_root`.
                Ok(Err(RefError::Block(_))) => return true,
                // Not known yet, or the reference is slow or busy: ask again.
                Ok(Err(e)) => tracing::trace!(error = %e, "column root not known yet"),
            }
            let retry = Instant::now() + self.limits.root_retry;
            tokio::time::sleep_until(retry.min(deadline)).await;
        }
    }
}

/// The writer thread: takes what is queued, up to [`MAX_BATCH`] columns, and writes it, until
/// every sender is gone.
fn run_writer(
    writer: &ColumnWriter,
    mut jobs: mpsc::Receiver<Write>,
    dropped: &ColumnMetrics,
    metrics: &QueueMetrics,
) {
    while let Some(first) = jobs.blocking_recv() {
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match jobs.try_recv() {
                Ok(write) => batch.push(write),
                Err(_) => break,
            }
        }
        write_batch(writer, batch, dropped, metrics);
    }
}

/// Writes `batch` block by block, at most [`MAX_COLUMNS_PER_TXN`] columns per call. A column
/// that arrived twice is written once. Each column gives its queue place back once written or
/// dropped.
fn write_batch(
    writer: &ColumnWriter,
    batch: Vec<Write>,
    dropped: &ColumnMetrics,
    metrics: &QueueMetrics,
) {
    let mut blocks: BTreeMap<(Slot, Root), BTreeMap<u64, Write>> = BTreeMap::new();
    for write in batch {
        blocks
            .entry((write.slot, write.root))
            .or_default()
            .insert(write.index, write);
    }
    for ((slot, root), columns) in blocks {
        let columns: Vec<Write> = columns.into_values().collect();
        for chunk in columns.chunks(MAX_COLUMNS_PER_TXN) {
            let ssz: Vec<Column<'_>> = chunk
                .iter()
                .map(|w| Column {
                    index: w.index,
                    ssz: &w.ssz,
                })
                .collect();
            match writer.write_columns(slot, &root, &ssz) {
                Ok(_) => {
                    metrics.stored.inc_by(chunk.len() as u64);
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        slot,
                        root = %hex::encode(root),
                        columns = chunk.len(),
                        "column write failed: column sidecars dropped"
                    );
                    for _ in chunk {
                        dropped.count(Drop::StoreFailed);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> (ColumnMetrics, QueueMetrics) {
        (ColumnMetrics::default(), QueueMetrics::default())
    }

    fn queue(limits: IngestLimits) -> Arc<Queue> {
        Arc::new(Queue {
            limits,
            pending: Mutex::default(),
            metrics: QueueMetrics::default(),
        })
    }

    fn write(queue: &Arc<Queue>, slot: Slot, root: Root, index: u64) -> Write {
        let ssz = format!("sidecar {slot}/{index}").into_bytes();
        Write {
            slot,
            root,
            index,
            _place: queue.admit(ssz.len()).unwrap(),
            ssz,
        }
    }

    #[test]
    fn a_block_is_written_in_chunks_of_at_most_sixteen() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let queue = queue(IngestLimits::default());
        let (dropped, metrics) = metrics();
        let mut batch: Vec<_> = (0..20).map(|i| write(&queue, 9, [1; 32], i)).collect();
        // A copy of a column already in the batch, and another block's column.
        batch.push(write(&queue, 9, [1; 32], 3));
        batch.push(write(&queue, 10, [2; 32], 0));
        let before = writer.rw_txns_committed();
        write_batch(&writer, batch, &dropped, &metrics);
        assert_eq!(writer.rw_txns_committed(), before + 3, "16 + 4, then 1");
        assert_eq!(
            writer.reader().columns_for_root(&[1; 32]).unwrap().len(),
            20
        );
        assert_eq!(metrics.stored(), 21);
        assert_eq!(queue.lock().items, 0, "every place is given back");
    }

    #[test]
    fn a_refused_write_is_counted_and_gives_its_places_back() {
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        writer.prune_finalized(20).unwrap();
        let queue = queue(IngestLimits::default());
        let (dropped, metrics) = metrics();
        let batch = vec![write(&queue, 9, [1; 32], 0), write(&queue, 9, [1; 32], 1)];
        write_batch(&writer, batch, &dropped, &metrics);
        assert_eq!(dropped.dropped(Drop::StoreFailed), 2);
        assert_eq!(metrics.stored(), 0);
        assert_eq!(queue.lock().items, 0);
    }

    #[test]
    fn the_queue_holds_both_caps() {
        let queue = queue(IngestLimits {
            max_items: 2,
            max_bytes: 100,
            alert_bytes: 60,
            ..IngestLimits::default()
        });
        let a = queue.admit(50).unwrap();
        assert_eq!(queue.metrics.buffer_alert.get(), 0);
        assert!(queue.admit(51).is_none(), "past the byte cap");
        let b = queue.admit(50).unwrap();
        assert_eq!(queue.metrics.buffer_alert.get(), 1);
        assert!(queue.admit(0).is_none(), "past the item cap");
        assert!(queue.admit(usize::MAX).is_none(), "no overflow");
        drop((a, b));
        let pending = *queue.lock();
        assert_eq!((pending.items, pending.bytes), (0, 0));
        assert_eq!(queue.metrics.buffer_bytes.get(), 0);
        assert_eq!(queue.metrics.buffer_alert.get(), 0);
    }
}
