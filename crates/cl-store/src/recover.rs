//! Crash-recovery reopen: the store env as cl-store holds it, reopened read-only when it cannot
//! be read.

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use prometheus_client::registry::Registry;

use crate::reader::{Clock, ReadError, Reader};

/// The first reopen delay.
pub const REOPEN_BASE: Duration = Duration::from_millis(250);

/// The longest reopen delay.
pub const REOPEN_CAP: Duration = Duration::from_secs(8);

/// How [`Recovering`] opens the env: [`Reader::open`] of its path, or a test's.
pub type Opener = Box<dyn Fn() -> store_schema::Result<Reader> + Send + Sync>;

/// The store env as cl-store holds it.
pub struct Recovering {
    _open: Option<Opener>,
    _clock: Option<Clock>,
    _fixed: Option<Arc<Reader>>,
}

impl Recovering {
    /// The env at `path`, opened read-only by the first read.
    #[must_use]
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let _ = path.into();
        todo!()
    }

    /// The env `open` opens, its backoff timed on `clock`.
    #[must_use]
    pub fn with_opener(open: Opener, clock: Clock) -> Self {
        Self {
            _open: Some(open),
            _clock: Some(clock),
            _fixed: None,
        }
    }

    /// A reader this process opened already, never reopened.
    #[must_use]
    pub fn fixed(reader: Arc<Reader>) -> Self {
        Self {
            _open: None,
            _clock: None,
            _fixed: Some(reader),
        }
    }

    /// The open reader.
    ///
    /// # Errors
    ///
    /// [`ReadError::Unavailable`] while the env is down.
    pub fn reader(&self) -> Result<Arc<Reader>, ReadError> {
        todo!()
    }

    /// `f` on the open reader.
    ///
    /// # Errors
    ///
    /// `f`'s, or [`ReadError::Unavailable`] while the env is down.
    pub fn read<T>(&self, f: impl FnOnce(&Reader) -> Result<T, ReadError>) -> Result<T, ReadError> {
        f(&*self.reader()?)
    }

    /// cl-chain is up again: the next read of an env that is down tries a reopen at once.
    pub fn hint(&self) {}

    /// Reopen attempts so far.
    #[must_use]
    pub fn reopen_attempts(&self) -> u64 {
        0
    }

    /// Whether the env is open and was not found broken.
    #[must_use]
    pub fn is_open(&self) -> bool {
        false
    }

    /// Registers the reopen counter.
    pub fn register(&self, registry: &mut Registry) {
        let _ = registry;
    }

    /// When the next reopen is due, if the env is down.
    #[cfg(test)]
    pub(crate) fn next_attempt(&self) -> Option<Instant> {
        None
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
    /// injected clock: no attempt before the delay is up, one once it is, each delay at least
    /// the one before and at most [`REOPEN_CAP`], every attempt counted. A hint (cl-chain is
    /// back) makes the next read try at once. Once the env opens it serves; a reader whose read
    /// transaction then fails with `MDBX_WANNA_RECOVERY` is taken out, and the env reopened
    /// after the first delay again.
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

    /// Delays of a bounded backoff from `base` to `cap`: the `n`th at most `base * 2^n` and at
    /// least half that, never above `cap`, each at least the one before.
    pub(crate) fn check_delays(delays: &[Duration], base: Duration, cap: Duration) {
        for (n, delay) in delays.iter().enumerate() {
            let ceiling = base.checked_mul(1 << n.min(30)).map_or(cap, |c| c.min(cap));
            assert!(
                (ceiling / 2..=ceiling).contains(delay),
                "delay {n} {delay:?} outside {:?}..={ceiling:?}: {delays:?}",
                ceiling / 2
            );
        }
        assert!(
            delays.windows(2).all(|w| w[0] <= w[1]),
            "the delays shrink: {delays:?}"
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
