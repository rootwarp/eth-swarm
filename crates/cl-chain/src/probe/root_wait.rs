//! [`RootWaits`]: how a column sidecar learns whether the reference vouches for its block root,
//! waiting a bounded time for a root the reference does not know yet.
//!
//! A column is reported IGNORE whatever happens to it, so a peer pays nothing for columns of
//! made-up roots. What they can cost is bounded, so they cannot crowd out real columns or flood
//! the reference with requests. Columns of a root the reference view has cached never get here.
//!
//! - **One entry per root.** The first column of a root opens its entry and asks the reference;
//!   every later column of the root joins the entry and shares its answer, the block the
//!   reference vouches for or why there is none. One column asks, however many wait.
//! - **Ask first, wait second.** The first ask goes out at once, or at the root's turn in the
//!   first-ask budget. A root the reference knows (in Gloas the block is gossiped before its
//!   payload's columns, so usually) is answered by that one ask and never takes a seat. Only "not
//!   known yet" seats the entry in the wait: asked again every [`IngestLimits::root_retry`],
//!   until [`IngestLimits::root_wait`] after its first column's arrival.
//! - **Two request budgets.** First asks are paced at [`IngestLimits::first_asks_per_sec`],
//!   at most [`IngestLimits::first_ask_burst`] at once, each root booked a turn in arrival order;
//!   one whose turn would come after its wait ends is refused. Retries take a token of their own
//!   budget, [`IngestLimits::retries_per_sec`], which [`IngestLimits::validate`] makes cover a
//!   retry of every seat, so seated roots never take from the first asks' share and a seated root
//!   is never starved of its retries. Each lookup is a header request, and the block once the
//!   header is known.
//! - **Lookup places.** The reference view runs at most `RefLimits::max_in_flight` lookups at
//!   once, and `ColumnIngest::start` requires more places than seats
//!   ([`IngestLimits::validate_for`]), so the seated roots' retries, all in flight together
//!   against a slow reference, never take every place. A lookup that still finds none
//!   ([`Answer::Busy`]) asked nothing: a first ask takes a new turn, at least one first-ask
//!   interval on, while its wait lasts (then `root_wait_full`, not remembered), never a seat; a
//!   retry waits for the next. So a first ask for a known root never depends on a free seat.
//! - **Caps.** At most [`IngestLimits::max_asking_columns`] columns wait for first asks and
//!   [`IngestLimits::max_waiting_columns`] for seated roots, at most
//!   [`IngestLimits::max_waiting_roots`] roots are seated, and at most
//!   [`MAX_CANDIDATES_PER_INDEX`] columns of one index wait for one root, in either phase. A
//!   column past a cap is dropped as `root_wait_full` at once; a column already waiting is never
//!   displaced. An entry not known yet whose seat would pass a cap is refused whole.
//! - **Negative cache.** A root is remembered, at most [`MAX_UNKNOWN_ROOTS`] roots, the oldest
//!   forgotten first, and a column of a remembered root is dropped with that reason without a
//!   request: refused by the reference (it names the root, but its block does not establish it)
//!   as `unknown_root`, and a seated wait that ran out as `root_timeout`, both for
//!   [`IngestLimits::unknown_root_ttl`]; a wait that ran out without a retry, or a root not known
//!   yet that found no seat, for one [`IngestLimits::root_retry`] (as `root_timeout` and
//!   `root_wait_full`), the time it would have been asked again anyway.
//!
//! **Candidates.** Four forged columns of one index that arrive before the real one, while the
//! root is not known yet, fill [`MAX_CANDIDATES_PER_INDEX`], and the real column, arriving
//! fifth, is dropped as `root_wait_full`: nothing tells them apart before the block is known,
//! and holding any number of candidates is the memory a flood would take. That is the limit of
//! the cap, and the real column is **lost**, with no recovery from gossip: its message id is a
//! hash of the topic and the data, and seen ids are kept for 768 s, so a copy from any other
//! peer is a duplicate that never reaches the store, and the store is forward only. Tracked in
//! issue #242.
//!
//! **Residual risk.** A flood of *fresh* made-up roots, each new to the negative cache, books a
//! first ask per root: above [`IngestLimits::first_asks_per_sec`] it delays the turn of every
//! later root, a real one included, and past [`IngestLimits::max_asking_columns`] it refuses
//! them. The budget bounds the reference's load, not the flood's share of it. Closing that needs
//! a per-peer cost (IGNORE-all has none) or seeding the reference view from the reference's head,
//! so real roots are cached before their columns arrive.

use super::column::Drop;
use super::ingest::IngestLimits;
use super::{RefBlock, Root};
use consensus_types::das::NUMBER_OF_COLUMNS;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

/// Roots the negative cache remembers at most \[est\]. Each one cost a lookup or a column of a
/// root that did, so at most about `first_ask_burst + first_asks_per_sec × unknown_root_ttl`
/// are live at once: 144 with the defaults (16 + 32/s × 4 s). The rest is headroom, so a flood
/// cannot push a remembered root out before its time.
pub const MAX_UNKNOWN_ROOTS: usize = 1024;

/// Columns of one index that may wait for one root at once \[est\]: the real column and a few
/// forged ones that arrived first. Gossip does not deduplicate columns with different bytes, and
/// nothing tells them apart before the root is known (see the module docs).
pub const MAX_CANDIDATES_PER_INDEX: u8 = 4;

/// What the reference said about a root, once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Answer {
    /// It vouches for the root: its block.
    Known(Arc<RefBlock>),
    /// It does not know the root yet, or gave no answer in time: ask again.
    Retry,
    /// Not asked: every place for a lookup in flight is taken. Says nothing about the root.
    Busy,
    /// It names the root, but its block does not establish it: waiting changes nothing.
    Refused,
}

/// How a root's wait ended: the block the reference vouches for, or why there is none.
pub(crate) type Outcome = Result<Arc<RefBlock>, Drop>;

/// A lookup budget: `per_sec` lookups a second, `burst` at once, paced by the generic cell rate
/// algorithm. Each lookup is booked a start time, in booking order.
struct Pace {
    /// When the budget is spent up to: the next lookup goes out `tolerance` before it.
    booked_to: Instant,
    interval: Duration,
    tolerance: Duration,
}

impl Pace {
    fn new(per_sec: u32, burst: u32) -> Self {
        let interval = Duration::from_secs_f64(1.0 / f64::from(per_sec.max(1)));
        Self {
            booked_to: Instant::now(),
            interval,
            tolerance: interval * burst.max(1).saturating_sub(1),
        }
    }

    /// Books a lookup at the earliest time from `now` the budget allows, if that is by
    /// `latest`; books nothing otherwise.
    fn book(&mut self, now: Instant, latest: Instant) -> Option<Instant> {
        let start = if now + self.tolerance >= self.booked_to {
            now
        } else {
            self.booked_to - self.tolerance
        };
        if start > latest {
            return None;
        }
        self.booked_to = self.booked_to.max(start) + self.interval;
        Some(start)
    }

    /// Books a lookup at least one interval after `now` (see [`Self::book`]).
    fn book_after(&mut self, now: Instant, latest: Instant) -> Option<Instant> {
        self.book(now + self.interval, latest)
    }

    /// Takes a lookup now, if the budget allows one now.
    fn take(&mut self, now: Instant) -> bool {
        self.book(now, now).is_some()
    }
}

/// The phase of a root's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the first ask's answer.
    Asking,
    /// Not known yet, seated in the wait.
    Seated,
}

/// One root that columns wait for.
struct Entry {
    phase: Phase,
    /// The columns waiting, by index.
    candidates: [u8; NUMBER_OF_COLUMNS as usize],
    /// The columns waiting, in all.
    columns: usize,
    /// Set once by the column asking the reference; `None` until then.
    outcome: watch::Receiver<Option<Outcome>>,
}

struct State {
    entries: HashMap<Root, Entry>,
    /// Columns waiting for first asks, over every root.
    asking_columns: usize,
    /// Columns waiting for seated roots, over every root.
    seated_columns: usize,
    seated_roots: usize,
    /// Remembered roots: until when, and why.
    unknown: HashMap<Root, (Instant, Drop)>,
    /// Remembering order of `unknown`, oldest first.
    unknown_order: VecDeque<Root>,
    first_asks: Pace,
    retries: Pace,
}

impl State {
    /// The drop reason remembered for `root`, if it has not expired at `now`.
    fn remembered(&self, root: &Root, now: Instant) -> Option<Drop> {
        self.unknown
            .get(root)
            .and_then(|&(until, reason)| (now < until).then_some(reason))
    }

    /// Remembers `root` for `reason` until `until`, as the newest entry.
    fn remember(&mut self, root: Root, until: Instant, reason: Drop) {
        if self.unknown.insert(root, (until, reason)).is_some() {
            // Refreshed: it moves to the back, so it is not forgotten before its time.
            self.unknown_order.retain(|r| *r != root);
        }
        while self.unknown.len() > MAX_UNKNOWN_ROOTS {
            let Some(oldest) = self.unknown_order.pop_front() else {
                break;
            };
            self.unknown.remove(&oldest);
        }
        self.unknown_order.push_back(root);
    }

    /// The columns of `phase`, over every root.
    fn pool(&mut self, phase: Phase) -> &mut usize {
        match phase {
            Phase::Asking => &mut self.asking_columns,
            Phase::Seated => &mut self.seated_columns,
        }
    }

    /// The entry of `root`, if it is the one of `wait`.
    fn entry(
        &mut self,
        root: &Root,
        wait: &watch::Receiver<Option<Outcome>>,
    ) -> Option<&mut Entry> {
        self.entries
            .get_mut(root)
            .filter(|entry| entry.outcome.same_channel(wait))
    }

    /// Ends the entry of `root` (if it is the one of `wait`), giving back every column's place.
    fn end(&mut self, root: &Root, wait: &watch::Receiver<Option<Outcome>>) {
        let Some(entry) = self.entry(root, wait) else {
            return;
        };
        let (phase, columns) = (entry.phase, entry.columns);
        self.entries.remove(root);
        *self.pool(phase) -= columns;
        if phase == Phase::Seated {
            self.seated_roots -= 1;
        }
    }
}

/// The bounded root wait (see the module docs).
pub(crate) struct RootWaits {
    limits: IngestLimits,
    state: Mutex<State>,
}

/// What one column does in its root's entry.
enum Role {
    /// It opened the entry: it asks the reference, from `start` on, and tells the others.
    Asks {
        tell: watch::Sender<Option<Outcome>>,
        start: Instant,
    },
    /// It waits for the column that asks.
    Follows(watch::Receiver<Option<Outcome>>),
}

/// One column's place in its root's entry, given back when dropped, however the wait ends.
struct Member<'a> {
    waits: &'a RootWaits,
    root: Root,
    index: usize,
    /// The entry's channel, which tells this entry from a later one of the same root.
    wait: watch::Receiver<Option<Outcome>>,
    /// Whether this column asks, so the entry ends with it.
    asks: bool,
}

impl std::ops::Drop for Member<'_> {
    fn drop(&mut self) {
        let mut state = self.waits.lock();
        if self.asks {
            // Settled already, or cancelled before it was: either way the entry ends here, and
            // the columns following it see its sender gone.
            state.end(&self.root, &self.wait);
            return;
        }
        let Some(entry) = state.entry(&self.root, &self.wait) else {
            return;
        };
        entry.candidates[self.index] -= 1;
        entry.columns -= 1;
        let phase = entry.phase;
        *state.pool(phase) -= 1;
    }
}

/// How the asking column's wait ended, and for how long to remember the root.
struct Settled {
    outcome: Outcome,
    remember_for: Option<Duration>,
}

impl RootWaits {
    pub(crate) fn new(limits: IngestLimits) -> Self {
        // Twice the seats, so retries booked a little early or late never find it empty.
        let retry_burst = u32::try_from(limits.max_waiting_roots.saturating_mul(2))
            .unwrap_or(u32::MAX)
            .max(1);
        Self {
            limits,
            state: Mutex::new(State {
                entries: HashMap::new(),
                asking_columns: 0,
                seated_columns: 0,
                seated_roots: 0,
                unknown: HashMap::new(),
                unknown_order: VecDeque::new(),
                first_asks: Pace::new(limits.first_asks_per_sec, limits.first_ask_burst),
                retries: Pace::new(limits.retries_per_sec, retry_burst),
            }),
        }
    }

    /// The block the reference vouches for as `root`, for the column `index` that arrived at
    /// `arrived`, asking it through `lookup` (see the module docs).
    ///
    /// # Errors
    ///
    /// [`Drop::RootWaitFull`] past a cap, or without a first-ask turn within the wait;
    /// [`Drop::RootTimeout`] if the wait ran out; [`Drop::UnknownRoot`] if the reference
    /// refused the root; any of them, at once, for a root the negative cache remembers.
    pub(crate) async fn wait<F, Fut>(
        &self,
        root: Root,
        index: u64,
        arrived: Instant,
        lookup: F,
    ) -> Outcome
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Answer>,
    {
        let index = usize::try_from(index)
            .ok()
            .filter(|&i| i < NUMBER_OF_COLUMNS as usize)
            .ok_or(Drop::NotCustody)?;
        let deadline = arrived + self.limits.root_wait;
        let (role, member) = self.join(root, index, deadline)?;
        match role {
            Role::Asks { tell, start } => {
                let settled = self.ask(root, &member.wait, start, deadline, lookup).await;
                {
                    let mut state = self.lock();
                    state.end(&root, &member.wait);
                    if let (Err(reason), Some(ttl)) = (&settled.outcome, settled.remember_for) {
                        state.remember(root, Instant::now() + ttl, *reason);
                    }
                }
                tell.send_replace(Some(settled.outcome.clone()));
                settled.outcome
            }
            Role::Follows(mut told) => match told.wait_for(Option::is_some).await {
                Ok(outcome) => outcome.clone().unwrap_or(Err(Drop::RootTimeout)),
                // The asking column was cancelled before it had an answer.
                Err(_) => Err(Drop::RootTimeout),
            },
        }
    }

    /// Joins the column of `index` to the entry of `root`, opening it with a first-ask turn
    /// by `deadline` if there is none, or the reason it cannot.
    fn join(
        &self,
        root: Root,
        index: usize,
        deadline: Instant,
    ) -> Result<(Role, Member<'_>), Drop> {
        let limits = &self.limits;
        let mut state = self.lock();
        let now = Instant::now();
        if let Some(reason) = state.remembered(&root, now) {
            return Err(reason);
        }
        let (asking, seated) = (state.asking_columns, state.seated_columns);
        let (role, wait) = match state.entries.get_mut(&root) {
            Some(entry) => {
                let full = match entry.phase {
                    Phase::Asking => asking >= limits.max_asking_columns,
                    Phase::Seated => seated >= limits.max_waiting_columns,
                };
                if full || entry.candidates[index] >= MAX_CANDIDATES_PER_INDEX {
                    return Err(Drop::RootWaitFull);
                }
                entry.candidates[index] += 1;
                entry.columns += 1;
                let phase = entry.phase;
                let wait = entry.outcome.clone();
                *state.pool(phase) += 1;
                (Role::Follows(wait.clone()), wait)
            }
            None => {
                if asking >= limits.max_asking_columns {
                    return Err(Drop::RootWaitFull);
                }
                let start = state
                    .first_asks
                    .book(now, deadline)
                    .ok_or(Drop::RootWaitFull)?;
                let (tell, outcome) = watch::channel(None);
                let wait = outcome.clone();
                let mut candidates = [0; NUMBER_OF_COLUMNS as usize];
                candidates[index] = 1;
                let entry = Entry {
                    phase: Phase::Asking,
                    candidates,
                    columns: 1,
                    outcome,
                };
                state.entries.insert(root, entry);
                state.asking_columns += 1;
                (Role::Asks { tell, start }, wait)
            }
        };
        let asks = matches!(role, Role::Asks { .. });
        let member = Member {
            waits: self,
            root,
            index,
            wait,
            asks,
        };
        Ok((role, member))
    }

    /// The asking column's part: the first ask at `start`, then, for a root not known yet, the
    /// seat and a retry every `root_retry` until `deadline`.
    async fn ask<F, Fut>(
        &self,
        root: Root,
        wait: &watch::Receiver<Option<Outcome>>,
        start: Instant,
        deadline: Instant,
        mut lookup: F,
    ) -> Settled
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Answer>,
    {
        let limits = &self.limits;
        let timed_out = |remember_for| Settled {
            outcome: Err(Drop::RootTimeout),
            remember_for,
        };
        let mut start = start;
        loop {
            tokio::time::sleep_until(start).await;
            match tokio::time::timeout_at(deadline, lookup()).await {
                // Asked, but no answer: not known for certain.
                Err(_) => return timed_out(Some(limits.root_retry)),
                Ok(Answer::Known(block)) => {
                    return Settled {
                        outcome: Ok(block),
                        remember_for: None,
                    }
                }
                Ok(Answer::Refused) => {
                    return Settled {
                        outcome: Err(Drop::UnknownRoot),
                        remember_for: Some(limits.unknown_root_ttl),
                    }
                }
                Ok(Answer::Retry) => break,
                // Not asked at all, so nothing says the root needs a seat: a new turn, at least
                // one first-ask interval on, while the wait lasts.
                Ok(Answer::Busy) => {
                    let mut state = self.lock();
                    let next = state.first_asks.book_after(Instant::now(), deadline);
                    let Some(next) = next else {
                        return Settled {
                            outcome: Err(Drop::RootWaitFull),
                            remember_for: None,
                        };
                    };
                    start = next;
                }
            }
        }
        if !self.seat(root, wait) {
            // Not known yet, and no seat: resends of the root cost nothing until it would have
            // been asked again.
            return Settled {
                outcome: Err(Drop::RootWaitFull),
                remember_for: Some(limits.root_retry),
            };
        }
        let mut retried = false;
        loop {
            let retry = Instant::now() + limits.root_retry;
            tokio::time::sleep_until(retry.min(deadline)).await;
            let now = Instant::now();
            if now >= deadline {
                // Remembered for the whole ttl only if the wait asked again: a root never
                // retried may be known by now.
                let ttl = if retried {
                    limits.unknown_root_ttl
                } else {
                    limits.root_retry
                };
                return timed_out(Some(ttl));
            }
            if !self.lock().retries.take(now) {
                continue;
            }
            match tokio::time::timeout_at(deadline, lookup()).await {
                Err(_) => return timed_out(Some(limits.unknown_root_ttl)),
                // Not asked: the next retry tries again.
                Ok(Answer::Busy) => continue,
                Ok(Answer::Known(block)) => {
                    return Settled {
                        outcome: Ok(block),
                        remember_for: None,
                    }
                }
                Ok(Answer::Refused) => {
                    return Settled {
                        outcome: Err(Drop::UnknownRoot),
                        remember_for: Some(limits.unknown_root_ttl),
                    }
                }
                Ok(Answer::Retry) => retried = true,
            }
        }
    }

    /// Seats the entry of `root`, with all its columns, if it fits.
    fn seat(&self, root: Root, wait: &watch::Receiver<Option<Outcome>>) -> bool {
        let limits = &self.limits;
        let mut state = self.lock();
        let (seated_roots, seated) = (state.seated_roots, state.seated_columns);
        let Some(entry) = state.entry(&root, wait) else {
            return false;
        };
        let columns = entry.columns;
        if seated_roots >= limits.max_waiting_roots || seated + columns > limits.max_waiting_columns
        {
            return false;
        }
        entry.phase = Phase::Seated;
        state.asking_columns -= columns;
        state.seated_columns += columns;
        state.seated_roots += 1;
        true
    }

    /// Seated roots now.
    #[cfg(test)]
    pub(crate) fn roots(&self) -> usize {
        self.lock().seated_roots
    }

    /// Columns waiting now: for first asks, and for seated roots.
    #[cfg(test)]
    fn columns(&self) -> (usize, usize) {
        let state = self.lock();
        (state.asking_columns, state.seated_columns)
    }

    /// The counts are updated together under the lock, so a panic cannot leave them half-set.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn limits() -> IngestLimits {
        IngestLimits {
            root_wait: Duration::from_secs(4),
            root_retry: Duration::from_millis(250),
            max_waiting_roots: 2,
            max_waiting_columns: 3,
            max_asking_columns: 8,
            unknown_root_ttl: Duration::from_secs(10),
            first_asks_per_sec: 1000,
            first_ask_burst: 1000,
            retries_per_sec: 1000,
            ..IngestLimits::default()
        }
    }

    fn block(root: Root) -> Arc<RefBlock> {
        Arc::new(RefBlock {
            root,
            slot: 9,
            commitments: Vec::new(),
        })
    }

    /// A reference that knows the roots in `known` and no other, refusing those in `refused`,
    /// counting the requests.
    #[derive(Clone, Default)]
    struct Reference {
        requests: Arc<AtomicUsize>,
        known: Arc<Mutex<HashSet<Root>>>,
        refused: Arc<Mutex<HashSet<Root>>>,
        asked: Arc<Mutex<Vec<(Root, Instant)>>>,
    }

    impl Reference {
        fn lookup(&self, root: Root) -> impl FnMut() -> std::future::Ready<Answer> {
            let api = self.clone();
            move || {
                api.requests.fetch_add(1, Ordering::SeqCst);
                api.asked.lock().unwrap().push((root, Instant::now()));
                let answer = if api.refused.lock().unwrap().contains(&root) {
                    Answer::Refused
                } else if api.known.lock().unwrap().contains(&root) {
                    Answer::Known(block(root))
                } else {
                    Answer::Retry
                };
                std::future::ready(answer)
            }
        }

        fn learn(&self, root: Root) {
            self.known.lock().unwrap().insert(root);
        }

        fn refuse(&self, root: Root) {
            self.refused.lock().unwrap().insert(root);
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }

        fn asked_about(&self, root: Root) -> usize {
            let asked = self.asked.lock().unwrap();
            asked.iter().filter(|(r, _)| *r == root).count()
        }
    }

    fn root(i: usize) -> Root {
        let mut root = [0; 32];
        root[..8].copy_from_slice(&(i as u64).to_be_bytes());
        root
    }

    #[tokio::test(start_paused = true)]
    async fn the_columns_of_a_root_share_one_request_per_retry() {
        let waits = RootWaits::new(limits());
        let api = Reference::default();
        let now = Instant::now();
        let release = async {
            tokio::time::sleep(Duration::from_millis(1100)).await;
            assert_eq!((waits.roots(), waits.columns()), (1, (0, 3)));
            api.learn([1; 32]);
        };
        let wait = |index| waits.wait([1; 32], index, now, api.lookup([1; 32]));
        let (a, b, c, ()) = tokio::join!(wait(1), wait(47), wait(87), release);
        assert_eq!(
            (a, b, c),
            (Ok(block([1; 32])), Ok(block([1; 32])), Ok(block([1; 32])))
        );
        // Asked at once, then at 250, 500, 750 and 1000 ms not known yet; at 1250 ms known.
        assert_eq!(
            api.requests(),
            6,
            "one request per retry, for three columns"
        );
        assert_eq!((waits.roots(), waits.columns()), (0, (0, 0)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_known_root_needs_no_seat() {
        let waits = RootWaits::new(limits());
        let api = Reference::default();
        let now = Instant::now();
        let known = async {
            tokio::task::yield_now().await;
            // Made-up roots hold every seat; a root the reference knows is answered at once.
            assert_eq!(waits.roots(), 2);
            api.learn([9; 32]);
            let real = waits
                .wait([9; 32], 47, Instant::now(), api.lookup([9; 32]))
                .await;
            assert_eq!(real, Ok(block([9; 32])));
            assert_eq!(waits.roots(), 2);
        };
        let fake = |i| waits.wait(root(i), 1, now, api.lookup(root(i)));
        let (a, b, ()) = tokio::join!(fake(0), fake(1), known);
        assert_eq!((a, b), (Err(Drop::RootTimeout), Err(Drop::RootTimeout)));
    }

    #[tokio::test(start_paused = true)]
    async fn seats_past_a_cap_are_refused_and_the_seated_keep_them() {
        let limits = IngestLimits {
            max_waiting_columns: 6,
            ..limits()
        };
        let waits = RootWaits::new(limits);
        let api = Reference::default();
        let now = Instant::now();
        let wait = |r: Root, index| waits.wait(r, index, now, api.lookup(r));
        let refused = async {
            tokio::task::yield_now().await;
            assert_eq!((waits.roots(), waits.columns()), (2, (0, 2)));
            // A third root not known yet: no seat, refused whole, and remembered for a retry.
            assert_eq!(wait([3; 32], 1).await, Err(Drop::RootWaitFull));
            assert_eq!(wait([3; 32], 47).await, Err(Drop::RootWaitFull));
            assert_eq!(api.asked_about([3; 32]), 1, "the resend cost nothing");
            // An index past NUMBER_OF_COLUMNS has no place.
            assert_eq!(wait([1; 32], 128).await, Err(Drop::NotCustody));
            // Up to MAX_CANDIDATES_PER_INDEX columns of one index wait together, then no more.
            let candidates =
                async { tokio::join!(wait([1; 32], 1), wait([1; 32], 1), wait([1; 32], 1)) };
            let full = async {
                tokio::task::yield_now().await;
                assert_eq!(waits.columns(), (0, 5));
                assert_eq!(wait([1; 32], 1).await, Err(Drop::RootWaitFull));
                let last = wait([2; 32], 47);
                let past_columns = async {
                    tokio::task::yield_now().await;
                    assert_eq!(waits.columns(), (0, 6));
                    // Past max_waiting_columns, even for a seated root.
                    assert_eq!(wait([1; 32], 87).await, Err(Drop::RootWaitFull));
                    api.learn([1; 32]);
                    api.learn([2; 32]);
                };
                tokio::join!(last, past_columns).0
            };
            let ((x, y, z), last) = tokio::join!(candidates, full);
            assert!([x, y, z, last].iter().all(Result::is_ok));
        };
        let (a, b, ()) = tokio::join!(wait([1; 32], 1), wait([2; 32], 1), refused);
        assert!(a.is_ok() && b.is_ok());
        assert_eq!((waits.roots(), waits.columns()), (0, (0, 0)));
        // Forgotten after a retry: the root not known yet is asked about again.
        tokio::time::sleep(limits.root_retry).await;
        api.learn([3; 32]);
        assert!(wait([3; 32], 1).await.is_ok());
        assert_eq!(api.asked_about([3; 32]), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn columns_sharing_a_first_ask_are_capped() {
        let limits = IngestLimits {
            max_asking_columns: 6,
            ..limits()
        };
        let waits = RootWaits::new(limits);
        let hang = Arc::new(tokio::sync::Notify::new());
        let lookup = || {
            let hang = Arc::clone(&hang);
            async move {
                hang.notified().await;
                Answer::Known(block([1; 32]))
            }
        };
        let now = Instant::now();
        let shares = async {
            tokio::task::yield_now().await;
            // A stalled first ask: forged copies of the root can wait with it, four per index
            // and six in all, and no more.
            let more = |index| waits.wait([1; 32], index, now, lookup);
            let joined = async { tokio::join!(more(1), more(1), more(1), more(47), more(47)) };
            let refused = async {
                tokio::task::yield_now().await;
                assert_eq!(waits.columns(), (6, 0));
                assert_eq!(
                    more(1).await,
                    Err(Drop::RootWaitFull),
                    "past four of index 1"
                );
                assert_eq!(more(87).await, Err(Drop::RootWaitFull), "past six in all");
                // Another root cannot open an entry either.
                let other = waits.wait([2; 32], 1, now, lookup);
                assert_eq!(other.await, Err(Drop::RootWaitFull));
                hang.notify_waiters();
            };
            let (joined, ()) = tokio::join!(joined, refused);
            joined
        };
        let (first, (a, b, c, d, e)) = tokio::join!(waits.wait([1; 32], 1, now, lookup), shares);
        assert!([first, a, b, c, d, e].iter().all(Result::is_ok));
        assert_eq!(waits.columns(), (0, 0));
    }

    /// A lookup answering `Busy` the first `busy` times, then `then`.
    fn busy_then(
        busy: usize,
        then: Answer,
        asked: &AtomicUsize,
    ) -> impl FnMut() -> std::future::Ready<Answer> + '_ {
        move || {
            let n = asked.fetch_add(1, Ordering::SeqCst);
            std::future::ready(if n < busy { Answer::Busy } else { then.clone() })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_busy_first_ask_takes_a_new_turn_not_a_seat() {
        let limits = IngestLimits {
            first_asks_per_sec: 10,
            first_ask_burst: 1,
            ..limits()
        };
        let waits = RootWaits::new(limits);
        let api = Reference::default();
        let now = Instant::now();
        let known = async {
            // The second made-up root's turn comes 100 ms after the first's.
            tokio::time::sleep(Duration::from_millis(150)).await;
            // Every seat is taken; the reference view is busy twice, then knows the root.
            assert_eq!(waits.roots(), 2);
            let asked = AtomicUsize::new(0);
            let start = Instant::now();
            let lookup = busy_then(2, Answer::Known(block([9; 32])), &asked);
            let real = waits.wait([9; 32], 47, start, lookup).await;
            assert_eq!(real, Ok(block([9; 32])));
            assert_eq!(asked.load(Ordering::SeqCst), 3);
            // Each new turn came at least one first-ask interval later.
            assert!(
                start.elapsed() >= Duration::from_millis(200),
                "{:?}",
                start.elapsed()
            );
            assert_eq!(waits.roots(), 2, "no seat taken");
            // Busy until past its wait: refused, and not remembered, as nothing was asked.
            let asked = AtomicUsize::new(0);
            let lookup = busy_then(usize::MAX, Answer::Retry, &asked);
            let busy = waits.wait([8; 32], 47, Instant::now(), lookup).await;
            assert_eq!(busy, Err(Drop::RootWaitFull));
            assert_eq!(waits.lock().remembered(&[8; 32], Instant::now()), None);
        };
        let fake = |i| waits.wait(root(i), 1, now, api.lookup(root(i)));
        let (a, b, ()) = tokio::join!(fake(0), fake(1), known);
        assert!(a.is_err() && b.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_busy_retry_asks_nothing() {
        let limits = limits();
        let waits = RootWaits::new(limits);
        // Not known at the first ask, then the reference view is busy for every retry.
        let asked = AtomicUsize::new(0);
        let lookup = || {
            let n = asked.fetch_add(1, Ordering::SeqCst);
            std::future::ready(if n == 0 { Answer::Retry } else { Answer::Busy })
        };
        let waited = waits.wait([1; 32], 1, Instant::now(), lookup).await;
        assert_eq!(waited, Err(Drop::RootTimeout));
        assert!(asked.load(Ordering::SeqCst) > 2, "retried, every time busy");
        // No retry reached the reference, so the root is remembered only for one retry.
        let state = waits.lock();
        let now = Instant::now();
        assert_eq!(state.remembered(&[1; 32], now), Some(Drop::RootTimeout));
        assert_eq!(state.remembered(&[1; 32], now + limits.root_retry), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_root_that_stays_unknown_is_remembered_for_a_while() {
        let limits = limits();
        let waits = RootWaits::new(limits);
        let api = Reference::default();
        let start = Instant::now();
        let waited = waits.wait([1; 32], 1, start, api.lookup([1; 32]));
        assert_eq!(waited.await, Err(Drop::RootTimeout));
        assert_eq!(start.elapsed(), limits.root_wait);
        assert_eq!(api.requests(), 16, "at once, then every 250 ms until 4 s");
        // Remembered: dropped at once, no request.
        let again = waits.wait([1; 32], 47, Instant::now(), api.lookup([1; 32]));
        assert_eq!(again.await, Err(Drop::RootTimeout));
        assert_eq!(api.requests(), 16);
        // A root the reference refuses is remembered with its own reason.
        api.refuse([2; 32]);
        let refused = waits.wait([2; 32], 1, Instant::now(), api.lookup([2; 32]));
        assert_eq!(refused.await, Err(Drop::UnknownRoot));
        let again = waits.wait([2; 32], 1, Instant::now(), api.lookup([2; 32]));
        assert_eq!(again.await, Err(Drop::UnknownRoot));
        assert_eq!(api.requests(), 17);
        // Forgotten after unknown_root_ttl: asked again.
        tokio::time::sleep(limits.unknown_root_ttl).await;
        api.learn([1; 32]);
        let later = waits.wait([1; 32], 1, Instant::now(), api.lookup([1; 32]));
        assert_eq!(later.await, Ok(block([1; 32])));
        assert_eq!(api.requests(), 18);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_never_retried_is_remembered_only_for_a_retry() {
        let limits = limits();
        let waits = RootWaits::new(limits);
        let api = Reference::default();
        // The retry budget is spent past the whole wait: the root is asked once, never again.
        waits.lock().retries.booked_to = Instant::now() + Duration::from_secs(3600);
        let start = Instant::now();
        let waited = waits.wait([1; 32], 1, start, api.lookup([1; 32]));
        assert_eq!(waited.await, Err(Drop::RootTimeout));
        assert_eq!(api.requests(), 1);
        let state = waits.lock();
        let now = Instant::now();
        assert_eq!(state.remembered(&[1; 32], now), Some(Drop::RootTimeout));
        assert_eq!(state.remembered(&[1; 32], now + limits.root_retry), None);
    }

    #[tokio::test(start_paused = true)]
    async fn seated_retries_never_take_the_first_asks_share() {
        let limits = IngestLimits {
            max_waiting_roots: 16,
            max_waiting_columns: 16,
            max_asking_columns: 32,
            root_retry: Duration::from_millis(500),
            first_asks_per_sec: 32,
            first_ask_burst: 16,
            retries_per_sec: 32,
            ..limits()
        };
        assert!(limits.validate().is_ok());
        let waits = RootWaits::new(limits);
        let api = Reference::default();
        let now = Instant::now();
        let fakes = (0..16).map(|i| waits.wait(root(i), 1, now, api.lookup(root(i))));
        let fakes = join_all(fakes);
        let real = async {
            // Every seat taken and retrying at the full retry rate, the first-ask burst spent.
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert_eq!(waits.roots(), 16);
            for i in 0..16 {
                api.learn(root(100 + i));
            }
            let start = Instant::now();
            // Sixteen known roots in a row: each is asked at its turn of the first-ask share.
            for i in 0..16 {
                let r = root(100 + i);
                assert_eq!(
                    waits.wait(r, 1, Instant::now(), api.lookup(r)).await,
                    Ok(block(r))
                );
            }
            assert!(
                start.elapsed() <= Duration::from_secs(1),
                "{:?}",
                start.elapsed()
            );
        };
        let (fakes, ()) = tokio::join!(fakes, real);
        assert!(fakes.iter().all(|o| *o == Err(Drop::RootTimeout)));
        // Every seated root was retried every 500 ms: none starved.
        for i in 0..16 {
            assert_eq!(api.asked_about(root(i)), 8, "root {i}");
        }
    }

    /// Runs futures of one type together on this task; their outputs, in order.
    async fn join_all<F: Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
        let mut running: Vec<_> = futures.into_iter().map(|f| Some(Box::pin(f))).collect();
        let mut outputs: Vec<Option<F::Output>> = running.iter().map(|_| None).collect();
        std::future::poll_fn(|cx| {
            for (slot, output) in running.iter_mut().zip(&mut outputs) {
                if let Some(future) = slot {
                    if let std::task::Poll::Ready(value) = future.as_mut().poll(cx) {
                        *output = Some(value);
                        *slot = None;
                    }
                }
            }
            if running.iter().all(Option::is_none) {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        outputs.into_iter().map(Option::unwrap).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn first_asks_are_paced_in_turn_and_refused_past_the_wait() {
        let limits = IngestLimits {
            first_asks_per_sec: 10,
            first_ask_burst: 2,
            max_asking_columns: 64,
            root_wait: Duration::from_secs(1),
            ..limits()
        };
        let waits = RootWaits::new(limits);
        let api = Reference::default();
        let now = Instant::now();
        for i in 0..20 {
            api.learn(root(i));
        }
        let asks = (0..20).map(|i| waits.wait(root(i), 1, now, api.lookup(root(i))));
        let outcomes = join_all(asks).await;
        // Two at once, then one each 100 ms: the turns up to the end of the wait are kept.
        let asked = api.asked.lock().unwrap().clone();
        assert_eq!(asked.len(), 12, "two, then ten more within one second");
        for (n, (r, at)) in asked.iter().enumerate() {
            assert_eq!(*r, root(n), "in turn");
            let turn = Duration::from_millis(100) * u32::try_from(n.saturating_sub(1)).unwrap();
            assert_eq!(at.duration_since(now), turn, "turn {n}");
        }
        assert!(outcomes[..12].iter().all(Result::is_ok));
        assert!(outcomes[12..].iter().all(|o| *o == Err(Drop::RootWaitFull)));
    }

    #[tokio::test(start_paused = true)]
    async fn requests_stay_within_the_lookup_budgets() {
        let limits = IngestLimits {
            first_asks_per_sec: 10,
            first_ask_burst: 4,
            retries_per_sec: 40,
            max_waiting_roots: 2,
            max_waiting_columns: 16,
            max_asking_columns: 256,
            root_retry: Duration::from_millis(50),
            root_wait: Duration::from_secs(1),
            ..limits()
        };
        let waits = Arc::new(RootWaits::new(limits));
        let api = Reference::default();
        let start = Instant::now();
        // Two seconds of a flood: a new root every millisecond, half refused, half not known.
        let mut columns = tokio::task::JoinSet::new();
        for i in 0..2000 {
            let (waits, api) = (Arc::clone(&waits), api.clone());
            if i % 2 == 0 {
                api.refuse(root(i));
            }
            columns.spawn(async move {
                let lookup = api.lookup(root(i));
                waits.wait(root(i), 1, Instant::now(), lookup).await
            });
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let outcomes = columns.join_all().await;
        let elapsed = start.elapsed().as_secs_f64();
        let budget = 4.0 + 10.0 * elapsed + 2.0 * 2.0 * elapsed / 0.05 + 2.0 * 2.0;
        let requests = api.requests() as f64;
        assert!(requests <= budget, "{requests} requests, budget {budget}");
        assert!(outcomes.iter().all(Result::is_err));
        // Every refused root that was asked about is remembered, none pushed out by the flood:
        // asked again, it costs nothing.
        let asked: HashSet<Root> = api.asked.lock().unwrap().iter().map(|(r, _)| *r).collect();
        let refused: Vec<Root> = (0..2000)
            .step_by(2)
            .map(root)
            .filter(|r| asked.contains(r))
            .collect();
        assert!(!refused.is_empty());
        let before = api.requests();
        for r in refused {
            let again = waits.wait(r, 1, Instant::now(), api.lookup(r)).await;
            assert_eq!(again, Err(Drop::UnknownRoot));
        }
        assert_eq!(api.requests(), before);
    }

    #[tokio::test(start_paused = true)]
    async fn the_negative_cache_is_bounded_and_a_refresh_moves_to_the_back() {
        let waits = RootWaits::new(limits());
        let until = Instant::now() + Duration::from_secs(60);
        let mut state = waits.lock();
        for i in 0..MAX_UNKNOWN_ROOTS {
            state.remember(root(i), until, Drop::RootTimeout);
        }
        // The oldest is refreshed: the next one is forgotten in its place.
        state.remember(root(0), until, Drop::UnknownRoot);
        state.remember(root(MAX_UNKNOWN_ROOTS), until, Drop::RootTimeout);
        assert_eq!(state.unknown.len(), MAX_UNKNOWN_ROOTS);
        assert_eq!(state.unknown_order.len(), MAX_UNKNOWN_ROOTS);
        let now = Instant::now();
        assert_eq!(state.remembered(&root(0), now), Some(Drop::UnknownRoot));
        assert_eq!(
            state.remembered(&root(1), now),
            None,
            "the oldest is forgotten"
        );
        assert_eq!(
            state.remembered(&root(MAX_UNKNOWN_ROOTS), now),
            Some(Drop::RootTimeout)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_wait_gives_its_places_back() {
        let waits = RootWaits::new(limits());
        let api = Reference::default();
        let now = Instant::now();
        let follows = async {
            tokio::task::yield_now().await;
            waits.wait([1; 32], 47, now, api.lookup([1; 32])).await
        };
        // The asking column gives up first; the one following it is told so.
        let asks = tokio::time::timeout(
            Duration::from_millis(100),
            waits.wait([1; 32], 1, now, api.lookup([1; 32])),
        );
        let (asked, followed) = tokio::join!(asks, follows);
        assert!(asked.is_err(), "cancelled");
        assert_eq!(followed, Err(Drop::RootTimeout));
        assert_eq!((waits.roots(), waits.columns()), (0, (0, 0)));
        assert!(waits.lock().entries.is_empty());
        // Not remembered: no answer was had.
        api.learn([1; 32]);
        let again = waits.wait([1; 32], 1, Instant::now(), api.lookup([1; 32]));
        assert_eq!(again.await, Ok(block([1; 32])));
    }

    #[tokio::test(start_paused = true)]
    async fn a_follower_that_gives_up_gives_its_place_back() {
        let waits = RootWaits::new(limits());
        let api = Reference::default();
        let now = Instant::now();
        let gives_up = async {
            tokio::task::yield_now().await;
            let wait = waits.wait([1; 32], 47, now, api.lookup([1; 32]));
            assert!(tokio::time::timeout(Duration::from_millis(100), wait)
                .await
                .is_err());
            assert_eq!(waits.columns(), (0, 1), "only the asking column waits");
            api.learn([1; 32]);
        };
        let (asked, ()) = tokio::join!(waits.wait([1; 32], 1, now, api.lookup([1; 32])), gives_up);
        assert_eq!(asked, Ok(block([1; 32])));
    }

    #[test]
    fn a_pace_books_its_burst_then_one_per_interval() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async {
            let mut pace = Pace::new(4, 3);
            let now = Instant::now();
            let far = now + Duration::from_secs(10);
            let starts: Vec<_> = (0..5).map(|_| pace.book(now, far).unwrap()).collect();
            let ms = |s: &Instant| s.duration_since(now).as_millis();
            assert_eq!(
                starts.iter().map(ms).collect::<Vec<_>>(),
                [0, 0, 0, 250, 500]
            );
            assert!(!pace.take(now), "spent");
            assert_eq!(pace.book(now, now + Duration::from_millis(600)), None);
            assert!(pace.take(now + Duration::from_millis(750)));
        });
    }
}
