//! The probe's column store survives a cl-chain killed mid-write: a child process (this test
//! binary, selected by `CHILD_MODE`) stores custody columns from gossip through
//! `cl_chain::probe::ColumnIngest`, then starts a later write that its column env's
//! before-commit hook (`ColumnWriter::set_before_commit`, the `test-hooks` feature) holds open
//! after its puts and before its commit. The child says so and is killed there with SIGKILL; the
//! parent reopens the same column env and finds the earlier columns and
//! `first_stored_column_slot` unchanged, and nothing of the interrupted write: neither its
//! columns nor the lower first stored slot it would have committed with them.
//!
//! The test is `probe::tests::restart_keeps_columns`, but lives in its own test binary rather
//! than in the library's unit tests. MDBX locks its files with open-file-description locks, and a
//! spawned child briefly holds copies of every fd of the spawning process (from the fork until
//! exec closes the `O_CLOEXEC` ones), so a unit test that closes an env and reopens it while
//! this one spawns could find its own released lock still held (see
//! `cl-chain-columns/tests/sole_writer.rs`). Here nothing else opens an env.
//!
//! The reference node and cl-verify are stubs: the reference vouches for its table of blocks,
//! and every KZG batch verifies. The storage contract itself is tested in `cl_chain::probe`.

mod probe {
    pub mod tests {
        use cl_chain::da::custody::{Advertise, Custody, EnrCgc, EnrError};
        use cl_chain::probe::{
            first_stored_column_slot, ApiError, BlockApi, Checkpoint, ColumnContract, ColumnIngest,
            ColumnMetrics, GossipColumn, Header, IngestLimits, QueueMetrics, RefLimits, RefView,
            ReferenceApi, Root,
        };
        use cl_chain::verify::client::{KzgOutcome, KzgVerifier};
        use cl_chain_columns::ColumnWriter;
        use consensus_types::gloas::DataColumnSidecar;
        use consensus_types::primitives::U256;
        use consensus_types::{ForkSchedule, Minimal};
        use ethswarm_proto::verify::KzgCellProof;
        use network_config::ScheduledFork;
        use prometheus_client::registry::Registry;
        use ssz::Encode;
        use std::collections::HashMap;
        use std::io::{Read, Write};
        use std::path::Path;
        use std::process::{Child, Command, ExitStatus, Stdio};
        use std::sync::{Arc, Mutex};
        use std::thread::JoinHandle;
        use std::time::Duration;
        use tokio::time::Instant;
        use tree_hash::TreeHash;

        const CHILD_MODE: &str = "CL_CHAIN_PROBE_CHILD_MODE";
        const CHILD_PATH: &str = "CL_CHAIN_PROBE_CHILD_PATH";
        /// What the child says once the write at [`PAUSED`] is held open before its commit.
        const PAUSED_LINE: &str = "CL_CHAIN_PROBE_CHILD_PAUSED_BEFORE_COMMIT";
        /// How long the child may take to reach the paused write, or to exit once killed.
        const CHILD_DEADLINE: Duration = Duration::from_secs(60);
        /// How long dropping a child may wait for it to be reaped after SIGKILL.
        const REAP_DEADLINE: Duration = Duration::from_secs(10);
        /// How long a store may take to settle.
        const SETTLE: Duration = Duration::from_secs(20);
        /// How often a wait looks again.
        const POLL: Duration = Duration::from_millis(20);
        /// A node id whose four custody groups, and so columns, are `[1, 47, 87, 102]`.
        const NODE: U256 = U256::MAX;
        /// The slot the child's custody is set at.
        const CGC_SET_SLOT: u64 = 16;
        /// The slots of the blocks the child stores columns of.
        const STORED: [u64; 2] = [18, 17];
        /// The slot of the block whose write the child is killed in: below [`STORED`], so the
        /// write would also lower the first stored slot.
        const PAUSED: u64 = CGC_SET_SLOT;

        type Ingest = ColumnIngest<Reference, Minimal, Valid, Arc<ColumnWriter>, NoEnr>;

        /// The ENR is not under test here.
        struct NoEnr;

        impl EnrCgc for NoEnr {
            fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
                Ok(())
            }
        }

        /// cl-verify that verifies every batch.
        struct Valid;

        impl KzgVerifier for Valid {
            async fn verify_cells(&self, _: Vec<KzgCellProof>, _: Duration) -> KzgOutcome {
                KzgOutcome::Valid
            }
        }

        /// A reference node that vouches for the Gloas blocks at its slots, one blob each.
        struct Reference(HashMap<Root, (u64, Vec<u8>)>);

        impl Reference {
            fn new(slots: &[u64]) -> Self {
                Self(
                    slots
                        .iter()
                        .map(|&slot| {
                            let (root, ssz) = block(slot);
                            (root, (slot, ssz))
                        })
                        .collect(),
                )
            }

            fn get(&self, root: Root) -> Result<&(u64, Vec<u8>), ApiError> {
                self.0.get(&root).ok_or_else(|| ApiError("404".into()))
            }
        }

        impl ReferenceApi for Reference {
            async fn finalized_checkpoint(&self) -> Result<Checkpoint, ApiError> {
                Err(ApiError("not used".into()))
            }

            async fn header(&self, root: Root) -> Result<Header, ApiError> {
                let (slot, _) = self.get(root)?;
                Ok(Header { root, slot: *slot })
            }
        }

        impl BlockApi for Reference {
            async fn block(&self, root: Root) -> Result<Vec<u8>, ApiError> {
                Ok(self.get(root)?.1.clone())
            }
        }

        /// Gloas from epoch 1 (slot 8 in the minimal preset), Fulu before.
        fn schedule() -> ForkSchedule {
            ForkSchedule::new(
                ScheduledFork {
                    version: [0x06, 0, 0, 0],
                    epoch: 0,
                },
                ScheduledFork {
                    version: [0x07, 0, 0, 0],
                    epoch: 1,
                },
            )
            .unwrap()
        }

        /// The root and SSZ of the Gloas block at `slot` whose bid commits to one blob.
        fn block(slot: u64) -> (Root, Vec<u8>) {
            let mut block = p2p_wire::testkit::gloas_block::<Minimal>(slot);
            let bid = &mut block.message.body.signed_execution_payload_bid.message;
            bid.blob_kzg_commitments = vec![[0xc0; 48]].try_into().unwrap();
            (block.message.tree_hash_root().0, block.as_ssz_bytes())
        }

        /// Column `index` of the block at `slot`, on its own subnet.
        fn column(slot: u64, index: u64) -> GossipColumn<Minimal> {
            let (root, _) = block(slot);
            GossipColumn {
                sidecar: DataColumnSidecar {
                    index,
                    column: vec![vec![index as u8; 2048].try_into().unwrap()]
                        .try_into()
                        .unwrap(),
                    kzg_proofs: vec![[0x0b; 48]].try_into().unwrap(),
                    slot,
                    beacon_block_root: root.into(),
                },
                subnet_id: index,
            }
        }

        /// The column store on the env at `path`, its custody opened at `slot` (kept from the
        /// env if it has one), and a reference that knows the blocks at `slots`.
        fn open(path: &Path, slot: u64, slots: &[u64]) -> (Ingest, Arc<ColumnWriter>) {
            let writer = Arc::new(ColumnWriter::open(path).unwrap());
            let custody =
                Custody::open(Arc::clone(&writer), NoEnr, NODE, Advertise::Withheld, slot).unwrap();
            let mut registry = Registry::default();
            let contract = ColumnContract {
                kzg: Valid,
                verify_timeout: Duration::from_secs(5),
                metrics: ColumnMetrics::register(&mut registry),
            };
            let refs = RefView::new(Reference::new(slots), schedule(), RefLimits::default());
            let ingest = ColumnIngest::start(
                refs,
                custody,
                contract,
                Arc::clone(&writer),
                IngestLimits::default(),
                QueueMetrics::register(&mut registry),
            )
            .unwrap();
            (ingest, writer)
        }

        /// Polls `done` until it holds; fails after [`SETTLE`].
        async fn settle(what: &str, mut done: impl FnMut() -> bool) {
            let deadline = Instant::now() + SETTLE;
            while !done() {
                assert!(Instant::now() < deadline, "timed out waiting for {what}");
                tokio::time::sleep(POLL).await;
            }
        }

        /// Gossips every custody column of the blocks at [`STORED`] and waits until all are
        /// stored.
        async fn store_all(ingest: &Ingest, writer: &ColumnWriter) {
            let columns = ingest.custody().custody_columns();
            assert_eq!(columns, vec![1, 47, 87, 102]);
            for slot in STORED {
                for &index in &columns {
                    ingest.on_column(column(slot, index));
                }
            }
            let want = (STORED.len() * columns.len()) as u64;
            settle("every column to be stored", || {
                ingest.pending() == 0 && writer.reader().column_count().unwrap() == want
            })
            .await;
        }

        /// Runs only when spawned by [`restart_keeps_columns`]; a normal run passes straight
        /// through.
        #[test]
        fn child_entry() {
            let (Ok(mode), Ok(path)) = (std::env::var(CHILD_MODE), std::env::var(CHILD_PATH))
            else {
                return;
            };
            assert_eq!(mode, "store", "unknown child mode");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let (ingest, writer) = open(Path::new(&path), CGC_SET_SLOT, &[18, 17, PAUSED]);
                // The write of the block at PAUSED stops before its commit, its columns and the
                // lower first stored slot put but uncommitted, until the parent kills this
                // process. It parks the columns-writer thread, not the runtime.
                writer.set_before_commit(Box::new(|slot| {
                    if slot == PAUSED {
                        eprintln!("{PAUSED_LINE}");
                        let _ = std::io::stderr().flush();
                        loop {
                            std::thread::park();
                        }
                    }
                }));
                store_all(&ingest, &writer).await;
                for index in ingest.custody().custody_columns() {
                    ingest.on_column(column(PAUSED, index));
                }
                std::future::pending::<()>().await;
            });
        }

        #[tokio::test]
        async fn restart_keeps_columns() {
            let dir = tempfile::tempdir().unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "probe::tests::child_entry",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_MODE, "store")
                .env(CHILD_PATH, dir.path())
                .stdout(Stdio::null());
            let mut child = OwnedChild::spawn(command).unwrap();
            let paused = child
                .wait_for_stderr(PAUSED_LINE, Instant::now() + CHILD_DEADLINE)
                .await;
            assert!(paused, "the child's write never paused: {}", child.stderr());
            // SIGKILL: no destructor, no flush, no clean close of the env.
            child.kill();
            let status = child.wait_until(Instant::now() + CHILD_DEADLINE).await;
            assert!(status.is_some_and(|s| !s.success()), "{status:?}");

            let expected = |writer: &ColumnWriter| {
                for slot in STORED {
                    let (root, _) = block(slot);
                    let stored = writer.reader().columns_for_root(&root).unwrap();
                    let want: Vec<_> = [1, 47, 87, 102]
                        .into_iter()
                        .map(|i| (i, column(slot, i).sidecar.as_ssz_bytes()))
                        .collect();
                    assert_eq!(stored, want, "the columns of slot {slot}");
                }
            };
            // Reopened after the kill: every column stored before it and the first stored slot
            // are there, and nothing of the interrupted write: no column, no root, and the first
            // stored slot not lowered to it.
            let (ingest, writer) = open(dir.path(), 500, &[12, 20, PAUSED]);
            expected(&writer);
            assert_eq!(writer.reader().column_count().unwrap(), 8);
            assert_eq!(writer.reader().block_count().unwrap(), 2);
            assert_eq!(writer.reader().slot_of(&block(PAUSED).0).unwrap(), None);
            assert_eq!(first_stored_column_slot(writer.reader()).unwrap(), Some(17));
            assert_eq!(ingest.first_stored_column_slot().unwrap(), Some(17));
            assert_eq!(
                ingest.custody().cgc_set_slot(),
                CGC_SET_SLOT,
                "kept from the env"
            );

            // The restarted store goes on forward only: a column before cgc_set_slot is not
            // stored, a later one is, and neither moves the first stored slot or the columns
            // stored before the kill.
            ingest.on_column(column(12, 47));
            ingest.on_column(column(20, 47));
            settle("the later column to be stored", || {
                ingest.pending() == 0 && writer.reader().column_count().unwrap() == 9
            })
            .await;
            assert_eq!(writer.reader().slot_of(&block(12).0).unwrap(), None);
            assert_eq!(writer.reader().slot_of(&block(20).0).unwrap(), Some(20));
            assert_eq!(ingest.first_stored_column_slot().unwrap(), Some(17));
            expected(&writer);

            // The interrupted block, gossiped again, is stored whole, and the first stored slot
            // moves with its columns.
            for index in ingest.custody().custody_columns() {
                ingest.on_column(column(PAUSED, index));
            }
            settle("the interrupted block to be stored", || {
                ingest.pending() == 0 && writer.reader().column_count().unwrap() == 13
            })
            .await;
            let stored = writer.reader().columns_for_root(&block(PAUSED).0).unwrap();
            assert_eq!(stored.len(), 4);
            assert_eq!(ingest.first_stored_column_slot().unwrap(), Some(PAUSED));
            expected(&writer);
        }

        /// A spawned child process the test owns: its stderr is drained on a thread as it
        /// arrives (a child never blocks writing to a full pipe), every wait has a deadline, and
        /// it is killed with SIGKILL and reaped on every way out of the test, from the moment it
        /// is spawned.
        struct OwnedChild {
            child: Reaped,
            stderr: Arc<Mutex<Vec<u8>>>,
            /// Ends at the pipe's end of file, once the child has exited.
            reader: JoinHandle<()>,
        }

        impl OwnedChild {
            /// Spawns `command` with stdin closed and stderr captured. If the stderr thread
            /// cannot start, the child is killed and reaped and the error returned.
            fn spawn(mut command: Command) -> std::io::Result<Self> {
                let child = command
                    .stdin(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()?;
                // Guarded from here on: if the reader cannot start, the `?` below kills and
                // reaps it.
                let mut child = Reaped(child);
                let mut pipe = child.0.stderr.take().expect("stderr is piped");
                let stderr = Arc::<Mutex<Vec<u8>>>::default();
                let sink = Arc::clone(&stderr);
                let reader = std::thread::Builder::new()
                    .name("child-stderr".to_owned())
                    .spawn(move || {
                        let mut buf = [0u8; 8192];
                        loop {
                            match pipe.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                                Err(_) => break,
                            }
                        }
                    })?;
                Ok(Self {
                    child,
                    stderr,
                    reader,
                })
            }

            fn stderr(&self) -> String {
                String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
            }

            /// Whether stderr shows `needle` by `deadline`.
            async fn wait_for_stderr(&self, needle: &str, deadline: Instant) -> bool {
                loop {
                    if self.stderr().contains(needle) {
                        return true;
                    }
                    if Instant::now() >= deadline {
                        return false;
                    }
                    tokio::time::sleep(POLL).await;
                }
            }

            /// SIGKILL (what `Child::kill` sends on Unix).
            fn kill(&mut self) {
                self.child.0.kill().expect("SIGKILL the child");
            }

            /// The exit status, or `None` if the child still runs at `deadline`; then the rest
            /// of stderr, to the same deadline.
            async fn wait_until(&mut self, deadline: Instant) -> Option<ExitStatus> {
                let status = loop {
                    if let Some(status) = self.child.0.try_wait().expect("try_wait on the child") {
                        break status;
                    }
                    if Instant::now() >= deadline {
                        return None;
                    }
                    tokio::time::sleep(POLL).await;
                };
                while !self.reader.is_finished() && Instant::now() < deadline {
                    tokio::time::sleep(POLL).await;
                }
                Some(status)
            }
        }

        /// A child that is killed and reaped when dropped.
        struct Reaped(Child);

        /// SIGKILL, then reap by polling `try_wait` until [`REAP_DEADLINE`]: never a `wait`
        /// that could block the test forever. Killing a child that already exited is harmless.
        impl Drop for Reaped {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let deadline = std::time::Instant::now() + REAP_DEADLINE;
                loop {
                    match self.0.try_wait() {
                        Ok(Some(_)) | Err(_) => return,
                        Ok(None) if std::time::Instant::now() >= deadline => {
                            eprintln!("child {} not reaped within {REAP_DEADLINE:?}", self.0.id());
                            return;
                        }
                        Ok(None) => std::thread::sleep(POLL),
                    }
                }
            }
        }
    }
}
