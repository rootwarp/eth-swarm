//! Admission to the env's single write transaction.
//!
//! libmdbx 0.5.6 begins every write txn on one manager thread; a begin that meets an open write
//! txn gets `MDBX_BUSY` and sleeps 250 ms before retrying. So the writer never lets two threads
//! race for MDBX's lock: every write txn first takes a permit here, and waiters park on a
//! [`Condvar`] instead of spinning.
//!
//! Import-priority txns go ahead of queued background txns (column chunks, prunes), so import
//! waits at most for the one txn in flight. To keep a run of imports from starving the column
//! task, a waiting background txn is admitted after [`MAX_IMPORT_BURST`] consecutive imports.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

/// Consecutive import txns admitted while a background txn waits, before that one goes. One
/// background txn is at most one 16-column chunk or one 128-row prune.
pub(crate) const MAX_IMPORT_BURST: usize = 4;

/// Who is asking for the env's write txn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Priority {
    /// On the import path: goes ahead of queued background txns, within [`MAX_IMPORT_BURST`].
    Import,
    /// Column writes and pruning.
    Background,
}

#[derive(Debug, Default)]
struct State {
    /// A permit is out.
    busy: bool,
    import_waiting: usize,
    background_waiting: usize,
    /// Imports admitted since the last background txn.
    imports_in_a_row: usize,
    #[cfg(test)]
    grants: Vec<Priority>,
}

impl State {
    fn burst_spent(&self) -> bool {
        self.imports_in_a_row >= MAX_IMPORT_BURST && self.background_waiting > 0
    }

    fn may_enter(&self, priority: Priority) -> bool {
        !self.busy
            && match priority {
                Priority::Import => !self.burst_spent(),
                Priority::Background => self.import_waiting == 0 || self.burst_spent(),
            }
    }

    fn waiting(&mut self, priority: Priority) -> &mut usize {
        match priority {
            Priority::Import => &mut self.import_waiting,
            Priority::Background => &mut self.background_waiting,
        }
    }
}

/// Hands out one write-txn permit at a time.
#[derive(Debug, Default)]
pub(crate) struct TxnScheduler {
    state: Mutex<State>,
    changed: Condvar,
}

/// Holds the env's write txn slot until dropped.
#[derive(Debug)]
pub(crate) struct Permit<'a> {
    sched: &'a TxnScheduler,
}

impl TxnScheduler {
    /// Blocks until `priority` may start a write txn.
    pub(crate) fn acquire(&self, priority: Priority) -> Permit<'_> {
        let mut state = self.lock();
        *state.waiting(priority) += 1;
        let mut state = self
            .changed
            .wait_while(state, |s| !s.may_enter(priority))
            .unwrap_or_else(PoisonError::into_inner);
        *state.waiting(priority) -= 1;
        state.busy = true;
        state.imports_in_a_row = match priority {
            Priority::Import => state.imports_in_a_row + 1,
            Priority::Background => 0,
        };
        #[cfg(test)]
        state.grants.push(priority);
        drop(state);
        Permit { sched: self }
    }

    fn release(&self) {
        self.lock().busy = false;
        // Waiters of both classes re-check; only the eligible one proceeds.
        self.changed.notify_all();
    }

    /// The state is a few counters, always updated together under the lock, so a panic elsewhere
    /// cannot leave it half-written.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `(import, background)` txns waiting for a permit.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> (usize, usize) {
        let state = self.lock();
        (state.import_waiting, state.background_waiting)
    }

    /// Every permit handed out, in order.
    #[cfg(test)]
    pub(crate) fn grants(&self) -> Vec<Priority> {
        self.lock().grants.clone()
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.sched.release();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    /// Spins until the scheduler shows the given queue. The deadline only turns a regression
    /// into a failure instead of a hang; no assertion depends on timing.
    pub(crate) fn wait_for_queue(sched: &TxnScheduler, import: usize, background: usize) {
        wait_for_queue_within(sched, import, background, Duration::from_secs(30));
    }

    fn wait_for_queue_within(
        sched: &TxnScheduler,
        import: usize,
        background: usize,
        deadline: Duration,
    ) {
        let start = Instant::now();
        while sched.waiting() != (import, background) {
            assert!(
                start.elapsed() < deadline,
                "queue never reached (import, background) = ({import}, {background}); \
                 still {:?} after {deadline:?}",
                sched.waiting()
            );
            thread::yield_now();
        }
    }

    #[test]
    #[should_panic(expected = "queue never reached")]
    fn waiting_for_a_queue_that_never_forms_fails_instead_of_hanging() {
        let sched = TxnScheduler::default();
        wait_for_queue_within(&sched, 1, 0, Duration::from_millis(20));
    }

    #[test]
    fn import_is_admitted_before_an_earlier_queued_background_txn() {
        let sched = Arc::new(TxnScheduler::default());
        let held = sched.acquire(Priority::Background);

        let background = {
            let sched = sched.clone();
            thread::spawn(move || drop(sched.acquire(Priority::Background)))
        };
        wait_for_queue(&sched, 0, 1);
        let import = {
            let sched = sched.clone();
            thread::spawn(move || drop(sched.acquire(Priority::Import)))
        };
        wait_for_queue(&sched, 1, 1);

        drop(held);
        background.join().unwrap();
        import.join().unwrap();
        assert_eq!(
            sched.grants(),
            vec![Priority::Background, Priority::Import, Priority::Background]
        );
    }

    #[test]
    fn an_import_burst_admits_one_background_txn_after_the_bound() {
        let sched = Arc::new(TxnScheduler::default());
        let held = sched.acquire(Priority::Background);
        let imports = MAX_IMPORT_BURST + 2;

        let background = {
            let sched = sched.clone();
            thread::spawn(move || drop(sched.acquire(Priority::Background)))
        };
        wait_for_queue(&sched, 0, 1);
        let importers: Vec<_> = (0..imports)
            .map(|_| {
                let sched = sched.clone();
                thread::spawn(move || drop(sched.acquire(Priority::Import)))
            })
            .collect();
        wait_for_queue(&sched, imports, 1);

        drop(held);
        background.join().unwrap();
        importers.into_iter().for_each(|t| t.join().unwrap());

        let mut expected = vec![Priority::Background];
        expected.extend(std::iter::repeat_n(Priority::Import, MAX_IMPORT_BURST));
        expected.push(Priority::Background);
        expected.extend(std::iter::repeat_n(Priority::Import, 2));
        assert_eq!(sched.grants(), expected);
    }

    #[test]
    fn imports_run_back_to_back_when_no_background_txn_waits() {
        let sched = TxnScheduler::default();
        for _ in 0..MAX_IMPORT_BURST * 3 {
            drop(sched.acquire(Priority::Import));
        }
        assert_eq!(sched.grants().len(), MAX_IMPORT_BURST * 3);
        assert_eq!(sched.waiting(), (0, 0));
    }
}
