//! Crash-recovery reopen: the store env as cl-store holds it, reopened read-only when it cannot
//! be read.
//!
//! [`Recovering`] holds the open [`Reader`], if there is one. A read takes it
//! ([`Recovering::reader`]) under a lock held only to copy or swap that handle, never across an
//! open or a read, so no read waits on a reopen, on another read, or on the follower (which
//! only sets a flag, [`Recovering::hint`]).
//!
//! - **Down.** The env is down when it did not open (missing, a layout this build does not
//!   read, any MDBX error, `MDBX_WANNA_RECOVERY` included), or once a read transaction of the
//!   open env failed with `MDBX_WANNA_RECOVERY` or `MDBX_PANIC` (that handle is of no further
//!   use). While it is down every read is [`ReadError::Unavailable`], and the caller IGNOREs.
//!   The reason is logged here; no MDBX text reaches a caller, whose error carries only
//!   `ReadError`'s fixed message.
//! - **Reopen.** The first read after the backoff's delay ([`REOPEN_BASE`] doubling to
//!   [`REOPEN_CAP`], jittered: [`Backoff`]) tries one read-only open ([`Reader::open`]) on its
//!   own (blocking) thread. Reads that come meanwhile do not wait for it: they are
//!   `Unavailable`. Every attempt is counted ([`Recovering::reopen_attempts`], the
//!   `store_reopen_attempts` counter). An open resets the backoff. A hint (the follower's: a
//!   subscription to cl-chain opened, so cl-chain is up, maybe after a restart) makes the next
//!   read try at once.
//! - **Never recovery, never write.** cl-store opens the env with `MDBX_RDONLY` only, so it
//!   never recovers it: an env that wants recovery stays down until cl-chain, its one writer,
//!   has opened it. MDBX refuses a second open of one env in one process, so a reopen while a
//!   read still holds the old handle fails, and is tried again on the backoff.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, PoisonError, RwLock, RwLockWriteGuard,
    },
    time::{Duration, Instant},
};

use prometheus_client::{metrics::counter::Counter, registry::Registry};

use crate::{
    backoff::Backoff,
    reader::{system_clock, Clock, ReadError, Reader},
};

/// The first reopen delay.
pub const REOPEN_BASE: Duration = Duration::from_millis(250);

/// The longest reopen delay: [`REOPEN_BASE`] doubled five times.
pub const REOPEN_CAP: Duration = Duration::from_secs(8);

/// How [`Recovering`] opens the env: [`Reader::open`] of its path, or a test's.
pub type Opener = Box<dyn Fn() -> store_schema::Result<Reader> + Send + Sync>;

/// The store env as cl-store holds it (see the module docs).
pub struct Recovering {
    /// `None`: a reader this process opened already, never reopened.
    open: Option<Opener>,
    clock: Clock,
    state: RwLock<State>,
    attempts: Counter,
    hinted: AtomicBool,
}

struct State {
    live: Option<Arc<Reader>>,
    backoff: Backoff,
    /// When the next reopen is due; `None`: at once.
    at: Option<Instant>,
    /// A reopen is under way on some read's thread.
    opening: bool,
}

impl Recovering {
    /// The env at `path`, opened read-only by the first read.
    #[must_use]
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self::with_opener(Box::new(move || Reader::open(&path)), system_clock())
    }

    /// The env `open` opens, its backoff timed on `clock` (tests inject both).
    #[must_use]
    pub fn with_opener(open: Opener, clock: Clock) -> Self {
        Self::new(Some(open), None, clock)
    }

    /// A reader this process opened already, never reopened.
    #[must_use]
    pub fn fixed(reader: Arc<Reader>) -> Self {
        Self::new(None, Some(reader), system_clock())
    }

    fn new(open: Option<Opener>, live: Option<Arc<Reader>>, clock: Clock) -> Self {
        Self {
            open,
            clock,
            state: RwLock::new(State {
                live,
                backoff: Backoff::new(REOPEN_BASE, REOPEN_CAP),
                at: None,
                opening: false,
            }),
            attempts: Counter::default(),
            hinted: AtomicBool::new(false),
        }
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn live(&self) -> Option<Arc<Reader>> {
        let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
        state.live.clone()
    }

    /// The open reader; while the env is down, a reopen if one is due.
    ///
    /// # Errors
    ///
    /// [`ReadError::Unavailable`] while the env is down.
    pub fn reader(&self) -> Result<Arc<Reader>, ReadError> {
        let live = self.live();
        let Some(open) = &self.open else {
            return live.ok_or(ReadError::Unavailable);
        };
        if let Some(reader) = live.filter(|reader| !reader.is_broken()) {
            return Ok(reader);
        }
        let now = (self.clock)();
        // A broken reader taken out is dropped (its env closed, if this held it last) after the
        // lock is released (`state` is declared later, so it drops first) and before a reopen:
        // MDBX refuses a second open of one env in one process.
        let mut broken = None;
        {
            let mut state = self.write();
            if let Some(reader) = state.live.take() {
                if !reader.is_broken() {
                    // Another read reopened it meanwhile.
                    state.live = Some(Arc::clone(&reader));
                    return Ok(reader);
                }
                broken = Some(reader);
                state.at = Some(now + state.backoff.next_delay());
                tracing::warn!(
                    "a read txn of the store env failed (wants recovery or panicked): \
                     reads answer UNAVAILABLE until it reopens read-only"
                );
            }
            let hinted = self.hinted.swap(false, Ordering::SeqCst);
            if state.opening || (!hinted && state.at.is_some_and(|at| now < at)) {
                return Err(ReadError::Unavailable);
            }
            state.opening = true;
        }
        drop(broken);
        self.reopen(open)
    }

    /// One reopen attempt, with `opening` set.
    fn reopen(&self, open: &Opener) -> Result<Arc<Reader>, ReadError> {
        self.attempts.inc();
        let opened = open();
        let mut state = self.write();
        state.opening = false;
        match opened {
            Ok(reader) => {
                let reader = Arc::new(reader);
                state.live = Some(Arc::clone(&reader));
                state.at = None;
                state.backoff.reset();
                self.hinted.store(false, Ordering::SeqCst);
                tracing::info!(
                    attempts = self.attempts.get(),
                    "the store env is open (read-only)"
                );
                Ok(reader)
            }
            Err(err) => {
                let delay = state.backoff.next_delay();
                state.at = Some((self.clock)() + delay);
                tracing::warn!(
                    error = %err,
                    attempts = self.attempts.get(),
                    retry_in = ?delay,
                    "the store env did not open read-only: reads answer UNAVAILABLE"
                );
                Err(ReadError::Unavailable)
            }
        }
    }

    /// `f` on the open reader, on the caller's thread (a blocking one: it may reopen the env).
    ///
    /// # Errors
    ///
    /// `f`'s, or [`ReadError::Unavailable`] while the env is down.
    pub fn read<T>(&self, f: impl FnOnce(&Reader) -> Result<T, ReadError>) -> Result<T, ReadError> {
        f(&*self.reader()?)
    }

    /// cl-chain is up, maybe after a restart: if the env is down, its next read tries a reopen
    /// at once. Never blocks; does nothing while the env is open.
    pub fn hint(&self) {
        if !self.is_open() {
            self.hinted.store(true, Ordering::SeqCst);
        }
    }

    /// Reopen attempts so far (the first open included).
    #[must_use]
    pub fn reopen_attempts(&self) -> u64 {
        self.attempts.get()
    }

    /// Whether the env is open and not found broken.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.live().is_some_and(|reader| !reader.is_broken())
    }

    /// Registers `store_reopen_attempts` (a counter: `_total`).
    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "store_reopen_attempts",
            "Read-only opens of the store env tried, the first included",
            self.attempts.clone(),
        );
    }

    /// When the next reopen is due, if the env is down.
    #[cfg(test)]
    pub(crate) fn next_attempt(&self) -> Option<Instant> {
        let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
        state.live.is_none().then_some(state.at).flatten()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        reader::{BlockRef, Stamped},
        server::StoreServer,
        stamp::StoreReader,
        testkit::{block, deadline, stamp, Store},
    };
    use ethswarm_proto::common::ErrorCode;
    use ipc::testkit::{fixture, Mode, Server};
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex, PoisonError,
    };

    /// A clock the test moves by hand.
    #[derive(Clone)]
    pub(crate) struct Manual(Arc<Mutex<Instant>>);

    impl Manual {
        pub(crate) fn new() -> Self {
            Self(Arc::new(Mutex::new(Instant::now())))
        }

        pub(crate) fn now(&self) -> Instant {
            *self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }

        pub(crate) fn advance(&self, by: Duration) {
            *self.0.lock().unwrap_or_else(PoisonError::into_inner) += by;
        }

        pub(crate) fn clock(&self) -> Clock {
            let now = self.clone();
            Arc::new(move || now.now())
        }
    }

    /// The delay until the next reopen attempt.
    pub(crate) fn wait(store: &Recovering, clock: &Manual) -> Duration {
        let at = store.next_attempt().expect("the env is down, a reopen due");
        at.saturating_duration_since(clock.now())
    }

    /// An env that wants recovery until cl-chain has opened it: every open fails with
    /// `MDBX_WANNA_RECOVERY` while `ready` is false, then opens the store's env.
    fn wants_recovery(store: Arc<Store>, ready: Arc<AtomicBool>, opens: Arc<AtomicU64>) -> Opener {
        Box::new(move || {
            opens.fetch_add(1, Ordering::SeqCst);
            if ready.load(Ordering::SeqCst) {
                Ok(store.reader())
            } else {
                Err(store_schema::Error::Mdbx(libmdbx::Error::WannaRecovery))
            }
        })
    }

    fn head(store: &Recovering) -> Result<Stamped<crate::reader::Block>, ReadError> {
        store.read(|r| r.block(BlockRef::Head, &deadline()))
    }

    /// An env that wants recovery (`MDBX_WANNA_RECOVERY` on open) is `Unavailable` with a fixed
    /// message, never the MDBX text. It is reopened read-only on a bounded backoff timed on the
    /// injected clock: no attempt before the delay is up, one once it is, the delays growing
    /// until [`REOPEN_CAP`] and then staying in `[cap/2, cap]`, every attempt counted. A hint
    /// (cl-chain is back) makes the next read try at once. Once the env opens it serves; a
    /// reader whose read transaction then fails with `MDBX_WANNA_RECOVERY` is taken out, and the
    /// env reopened after the first delay again.
    #[test]
    fn reopen_bounded_backoff() {
        let store = Arc::new(Store::new());
        let (ssz, root) = block(9, [0; 32], 1);
        store.import(&[&ssz], stamp(1, (9, root), (9, root)));
        let (ready, opens) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
        );
        let clock = Manual::new();
        let opener = wants_recovery(Arc::clone(&store), Arc::clone(&ready), Arc::clone(&opens));
        let env = Recovering::with_opener(opener, clock.clock());

        let err = head(&env).unwrap_err();
        assert_eq!(err, ReadError::Unavailable);
        let text = err.to_string().to_lowercase();
        for mdbx in ["recovery", "mdbx", "wanna"] {
            assert!(!text.contains(mdbx), "{text}");
        }
        assert_eq!(
            (env.reopen_attempts(), opens.load(Ordering::SeqCst)),
            (1, 1)
        );
        assert!(!env.is_open());
        for _ in 0..10 {
            assert_eq!(head(&env), Err(ReadError::Unavailable));
        }
        assert_eq!(
            env.reopen_attempts(),
            1,
            "no attempt before the delay is up"
        );

        let mut delays = Vec::new();
        for n in 1..=10u64 {
            let delay = wait(&env, &clock);
            delays.push(delay);
            clock.advance(delay.saturating_sub(Duration::from_nanos(1)));
            assert_eq!(head(&env), Err(ReadError::Unavailable));
            assert_eq!(env.reopen_attempts(), n, "attempt {n}: early");
            clock.advance(Duration::from_nanos(1));
            assert_eq!(head(&env), Err(ReadError::Unavailable));
            assert_eq!(env.reopen_attempts(), n + 1, "attempt {n}: due");
        }
        check_delays(&delays, REOPEN_BASE, REOPEN_CAP);
        assert!(
            delays[6..].iter().all(|d| *d >= REOPEN_CAP / 2),
            "{delays:?}"
        );

        env.hint();
        assert_eq!(head(&env), Err(ReadError::Unavailable));
        assert_eq!(env.reopen_attempts(), 12, "a hint tries at once");

        ready.store(true, Ordering::SeqCst);
        clock.advance(wait(&env, &clock));
        let served = head(&env).expect("serves once the env opens");
        assert_eq!((served.value.root, served.stamp.head_seq), (root, 1));
        assert_eq!(env.reopen_attempts(), 13);
        assert!(env.is_open() && env.next_attempt().is_none());
        assert_eq!(opens.load(Ordering::SeqCst), 13);

        // A read txn that fails with MDBX_WANNA_RECOVERY: the reader is taken out.
        env.reader().unwrap().poison();
        assert_eq!(head(&env), Err(ReadError::Unavailable));
        assert!(!env.is_open());
        let again = wait(&env, &clock);
        assert!(
            (REOPEN_BASE / 2..=REOPEN_BASE).contains(&again),
            "the backoff starts over after a success: {again:?}"
        );
        assert_eq!(env.reopen_attempts(), 13);
        clock.advance(again);
        assert_eq!(head(&env).map(|r| r.value.root), Ok(root));
        assert_eq!(env.reopen_attempts(), 14);
    }

    /// Delays of a bounded backoff from `base` to `cap`: the `n`th at most `base * 2^n` (never
    /// above `cap`) and at least half that. They grow, each at least the one before, until
    /// they reach the cap; then they stay in `[cap/2, cap]`.
    pub(crate) fn check_delays(delays: &[Duration], base: Duration, cap: Duration) {
        let ceiling = |n: usize| base.checked_mul(1 << n.min(30)).map_or(cap, |c| c.min(cap));
        for (n, delay) in delays.iter().enumerate() {
            let top = ceiling(n);
            assert!(
                (top / 2..=top).contains(delay),
                "delay {n} {delay:?} outside {:?}..={top:?}: {delays:?}",
                top / 2
            );
            if n > 0 && ceiling(n - 1) < cap {
                assert!(delays[n - 1] <= *delay, "delay {n} shrinks: {delays:?}");
            }
        }
        assert_eq!(
            ceiling(delays.len() - 1),
            cap,
            "the delays never reach the cap: {delays:?}"
        );
    }

    /// While the env is down every RPC that reads fails UNAVAILABLE with
    /// `ERROR_CODE_RESOURCE_UNAVAILABLE` (the caller IGNOREs) and a fixed message: no MDBX
    /// text reaches a caller.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_down_env_is_unavailable() {
        let store = Arc::new(Store::new());
        let opener = wants_recovery(
            store,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
        );
        let env = Arc::new(Recovering::with_opener(opener, Manual::new().clock()));
        let server = StoreServer::recovering(fixture::v1_link(), env);
        let conn = Mode::InProcess.connect(Server::new(server.routes())).await;
        let raw = ethswarm_proto::store::store_service_client::StoreServiceClient::new(
            conn.transport.clone(),
        )
        .get_chain_head(ethswarm_proto::store::GetChainHeadRequest {})
        .await
        .unwrap_err();
        assert_eq!(raw.code(), tonic::Code::Unavailable, "{raw:?}");
        let text = raw.message().to_lowercase();
        assert!(
            !text.contains("mdbx") && !text.contains("recovery"),
            "{text}"
        );
        let mut client = StoreReader::new(conn.transport.clone(), fixture::v1_link());
        let err = client.get_chain_head().await.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceUnavailable, "{err}");
    }
}
