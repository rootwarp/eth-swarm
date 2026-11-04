//! The chain.v1 events follower: cl-store's subscription to cl-chain's `EventsService`, on HEAD
//! and FINALIZED_CHECKPOINT, for liveness, `follower_lag` and the reopen hint.
//!
//! It is not the stamp's source. Every read is stamped from the stamp row of its own read
//! transaction ([`crate::reader`]). The follower never produces or caches a stamp, and no read
//! waits on it: it runs in a task of its own, holds no lock a read takes, and tells the reader
//! only through [`Recovering::hint`], which sets a flag.
//!
//! - **What it tracks** ([`Followed`], and the gauges [`Followed::register`] adds): whether a
//!   subscription is open, the last `seq`, the last head's slot, the last finalized
//!   checkpoint's start slot, and `follower_lag`. That is how many slots its last head trails
//!   the head of the store's stamp (cl-chain commits a head before it publishes it). It is
//!   read from the store after each head and after each failed or ended subscription, so it
//!   grows while the follower is down and cl-chain commits.
//! - **The client-side contract.** The stream must open with cl-chain's hello (negotiated by
//!   the link, within its hello timeout), and `seq` must rise. A `seq` that does not, or
//!   `EVENT_KIND_UNSPECIFIED`, ends the subscription as a contract violation. An unknown
//!   non-zero kind is ignored.
//! - **Reconnect.** A subscription that is refused or fails, or whose stream ends (cl-chain
//!   stops, the stream lags cl-chain's bus and is ended `RESOURCE_EXHAUSTED`, the connection
//!   breaks, a contract violation), is followed by a new one after a bounded, jittered,
//!   exponential backoff ([`RESUBSCRIBE_BASE`] doubling to [`RESUBSCRIBE_CAP`]). A subscription
//!   that opens resets it. Nothing is replayed: cl-chain keeps no past events, so each
//!   subscription starts at its next event.
//! - **Reopen hint.** A subscription that opens means cl-chain is up, maybe after a restart, so
//!   an env that wanted recovery may read again: the follower hints the reader
//!   ([`Recovering::hint`]), and the next read of an env that is down tries a reopen at once.
//!   Hello generations are per stream, so a restart looks like any new subscription; a hint to
//!   an open env does nothing.
//! - **ACL.** cl-chain's method ACL must give cl-store [`CHAIN_METHODS`]
//!   (`EventsService/Subscribe`). Without it every subscription is refused
//!   (`PERMISSION_DENIED`) and the follower keeps backing off; reads are not affected. The
//!   probe's cl-chain gives its methods to cl-p2p only, so under the probe the follower is
//!   refused.
//! - **Readiness.** A follower that is down does not make cl-store unready: reads stay correct
//!   from their own stamp.

use std::{
    future::Future,
    path::Path,
    pin::Pin,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use ethswarm_proto::chain::{self as pb, events_service_client::EventsServiceClient, EventKind};
use ipc::{frame::Inbound, uds::PeerCheckedConnector, ContractError, Link};
use prometheus_client::{
    metrics::{counter::Counter, gauge::Gauge},
    registry::Registry,
};
use tonic::transport::{Channel, Endpoint};

use crate::{
    backoff::Backoff,
    reader::{system_clock, Deadline},
    recover::Recovering,
};

/// The chain.v1 methods cl-store calls. cl-chain's method ACL must give each of them to
/// cl-store.
pub const CHAIN_METHODS: [&str; 1] = ["/ethswarm.chain.v1.EventsService/Subscribe"];

/// The first delay before subscribing again.
pub const RESUBSCRIBE_BASE: Duration = Duration::from_millis(250);

/// The longest delay before subscribing again: [`RESUBSCRIBE_BASE`] doubled seven times.
pub const RESUBSCRIBE_CAP: Duration = Duration::from_secs(32);

/// The event kinds the follower subscribes to.
const KINDS: [EventKind; 2] = [EventKind::Head, EventKind::FinalizedCheckpoint];

/// The deadline of the store read behind `follower_lag`.
const LAG_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// How the follower waits between subscriptions: `tokio::time::sleep`, or a test's.
pub type Sleep = Arc<dyn Fn(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

type U64Gauge = Gauge<u64, AtomicU64>;

/// What the follower has seen. Clones share it; it is lock-free.
#[derive(Clone, Debug, Default)]
pub struct Followed {
    connected: U64Gauge,
    seq: U64Gauge,
    head_slot: U64Gauge,
    finalized_slot: U64Gauge,
    lag: U64Gauge,
    subscriptions: Counter,
}

impl Followed {
    /// Whether a subscription is open.
    #[must_use]
    pub fn connected(&self) -> bool {
        self.connected.get() == 1
    }

    /// The `seq` of the last event taken (0 before the first).
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq.get()
    }

    /// The slot of the last head.
    #[must_use]
    pub fn head_slot(&self) -> u64 {
        self.head_slot.get()
    }

    /// The start slot of the last finalized checkpoint.
    #[must_use]
    pub fn finalized_slot(&self) -> u64 {
        self.finalized_slot.get()
    }

    /// `follower_lag`: the slots the last head trails the head of the store's stamp, as of the
    /// last time it was read.
    #[must_use]
    pub fn lag(&self) -> u64 {
        self.lag.get()
    }

    /// Subscriptions opened so far.
    #[must_use]
    pub fn subscriptions(&self) -> u64 {
        self.subscriptions.get()
    }

    /// Registers `store_follower_{connected,seq,head_slot,finalized_slot,lag_slots}` and
    /// `store_follower_subscriptions` (a counter: `_total`).
    pub fn register(&self, registry: &mut Registry) {
        for (name, help, gauge) in [
            (
                "connected",
                "1 while a subscription to cl-chain's events is open",
                &self.connected,
            ),
            (
                "seq",
                "The seq of the last event of cl-chain the follower took",
                &self.seq,
            ),
            (
                "head_slot",
                "The slot of the last head cl-chain published",
                &self.head_slot,
            ),
            (
                "finalized_slot",
                "The start slot of the last finalized checkpoint",
                &self.finalized_slot,
            ),
            (
                "lag_slots",
                "Slots the follower's last head trails the store stamp's head",
                &self.lag,
            ),
        ] {
            registry.register(format!("store_follower_{name}"), help, gauge.clone());
        }
        registry.register(
            "store_follower_subscriptions",
            "Subscriptions to cl-chain's events opened",
            self.subscriptions.clone(),
        );
    }
}

/// The follower (see the module docs).
pub struct Follower {
    link: Link,
    store: Arc<Recovering>,
    seen: Followed,
    backoff: Backoff,
    sleep: Sleep,
}

impl Follower {
    /// A follower with `link`'s hello, hinting `store`.
    #[must_use]
    pub fn new(link: Link, store: Arc<Recovering>) -> Self {
        Self {
            link,
            store,
            seen: Followed::default(),
            backoff: Backoff::new(RESUBSCRIBE_BASE, RESUBSCRIBE_CAP),
            sleep: Arc::new(|delay| Box::pin(tokio::time::sleep(delay))),
        }
    }

    /// What it has seen.
    #[must_use]
    pub fn seen(&self) -> &Followed {
        &self.seen
    }

    /// The same follower, waiting between subscriptions with `sleep` (tests: no real sleep).
    #[must_use]
    pub fn with_sleep(mut self, sleep: Sleep) -> Self {
        self.sleep = sleep;
        self
    }

    /// A client of cl-chain's `EventsService` on `socket`, whose server must run as
    /// `chain_uid` (`ipc::uds::PeerCheckedConnector`). It connects lazily, at each
    /// subscription, so cl-store starts while cl-chain is down.
    #[must_use]
    pub fn client(socket: &Path, chain_uid: u32) -> EventsServiceClient<Channel> {
        let connector = PeerCheckedConnector::new(socket, chain_uid);
        // The authority routes nothing: the connector picks the socket.
        let channel =
            Endpoint::from_static("http://localhost").connect_with_connector_lazy(connector);
        EventsServiceClient::new(channel)
    }

    /// Subscribes through `client`, and again after each end, until `stop`.
    pub async fn run(
        mut self,
        mut client: EventsServiceClient<Channel>,
        stop: impl Future<Output = ()>,
    ) {
        let seen = self.seen.clone();
        let follow = async {
            loop {
                match self.subscription(&mut client).await {
                    Ok(end) => {
                        tracing::warn!(%end, "cl-chain's event stream ended: subscribing again")
                    }
                    Err(e) => tracing::debug!(error = %e, "cannot subscribe to cl-chain's events"),
                }
                self.seen.connected.set(0);
                self.update_lag().await;
                let delay = self.backoff.next_delay();
                (self.sleep)(delay).await;
            }
        };
        tokio::select! {
            () = stop => {}
            () = follow => {}
        }
        seen.connected.set(0);
    }

    /// One subscription: why it ended, or `Err` if it did not open.
    async fn subscription(
        &mut self,
        client: &mut EventsServiceClient<Channel>,
    ) -> Result<String, String> {
        let request = pb::SubscribeRequest {
            kinds: KINDS.map(|kind| kind as i32).to_vec(),
            resume_from_seq: 0,
            hello: Some(self.link.local()),
        };
        let stream = client
            .subscribe(request)
            .await
            .map_err(|e| format!("Subscribe: {e}"))?
            .into_inner();
        let mut frames = self
            .link
            .open(Inbound::from_server(stream))
            .await
            .map_err(|e| format!("Subscribe: {e}"))?;
        self.backoff.reset();
        self.seen.connected.set(1);
        self.seen.subscriptions.inc();
        self.store.hint();
        tracing::info!("following cl-chain's events");
        let mut last = 0;
        loop {
            let body = match frames.body().await {
                Ok(Some(accepted)) => accepted.body,
                Ok(None) => return Ok("cl-chain closed it".to_owned()),
                Err(e) => return Ok(e.to_string()),
            };
            if body.seq <= last || body.kind == EventKind::Unspecified as i32 {
                let e = ContractError::violation(format!(
                    "event seq {} of kind {} after seq {last}",
                    body.seq, body.kind
                ));
                self.link.record(&e);
                return Ok(e.to_string());
            }
            last = body.seq;
            self.seen.seq.set(body.seq);
            match EventKind::try_from(body.kind) {
                Ok(EventKind::Head) => {
                    self.seen.head_slot.set(body.slot);
                    self.update_lag().await;
                }
                Ok(EventKind::FinalizedCheckpoint) => {
                    self.seen.finalized_slot.set(body.slot);
                }
                _ => {}
            }
        }
    }

    /// `follower_lag` from the store's stamp, read on `spawn_blocking` under its own deadline;
    /// left as it was if the store cannot be read.
    async fn update_lag(&self) {
        let store = Arc::clone(&self.store);
        let deadline = Deadline::after(system_clock(), LAG_READ_TIMEOUT);
        let read = tokio::task::spawn_blocking(move || store.read(|r| r.head(&deadline))).await;
        if let Ok(Ok(stamp)) = read {
            let lag = stamp.head_slot.saturating_sub(self.seen.head_slot());
            self.seen.lag.set(lag);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        recover::tests::{check_delays, Manual},
        server::{StoreServer, DEFAULT_TIMEOUT},
        stamp::StoreReader,
        testkit::{block, stamp, Store},
    };
    use cl_chain::{
        events::{BlockTree, ChainEvents, EventsServer, Finalized, Head, ImportedBlock},
        persist::durable::PayloadStatus,
    };
    use consensus_types::primitives::{Root as ChainRoot, Slot};
    use ethswarm_proto::chain::{
        self as pb,
        events_service_server::{EventsService, EventsServiceServer},
    };
    use ethswarm_proto::store as store_pb;
    use ipc::{
        acl::{AclLayer, MethodAcl},
        frame::OutFrame,
        hello::stream_hello,
        stub::StubStream,
        testkit::{fixture, Mode, Server},
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        time::Instant,
    };
    use tokio::{
        net::UnixListener,
        sync::{mpsc, oneshot, watch},
        task::JoinHandle,
    };
    use tokio_stream::{wrappers::UnixListenerStream, StreamExt};
    use tonic::{Request, Response, Status};

    const WITHIN: Duration = Duration::from_secs(10);

    /// The epoch length of the test bus: a FINALIZED_CHECKPOINT of epoch `e` is at slot `8e`.
    const SLOTS: u64 = 8;

    const SUBSCRIBE: &str = "/ethswarm.chain.v1.EventsService/Subscribe";
    const CHAIN_STATUS: &str = "/ethswarm.chain.v1.ImportService/GetChainStatus";

    fn uid() -> u32 {
        ipc::peercred::effective_uid()
    }

    /// Waits (polling, at most [`WITHIN`]) until `done`.
    async fn until(what: &str, mut done: impl FnMut() -> bool) {
        let start = Instant::now();
        while !done() {
            assert!(start.elapsed() < WITHIN, "{what}: not within {WITHIN:?}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// cl-chain's `EventsService` (its `events` source) on a Unix socket, behind a cl-chain
    /// method ACL that gives `methods` to cl-store (this process's UID).
    struct Chain {
        events: ChainEvents,
        denied: Arc<AtomicUsize>,
        stop: watch::Sender<bool>,
        served: JoinHandle<Result<(), tonic::transport::Error>>,
        socket: PathBuf,
    }

    impl Chain {
        fn serve(socket: &Path, methods: &[&str], capacity: usize) -> Self {
            let mut acl = format!("[callers]\ncl-store = {}\n\n[methods]\n", uid());
            for method in methods {
                acl.push_str(&format!("\"{method}\" = [\"cl-store\"]\n"));
            }
            let acl = MethodAcl::from_toml(&acl, Path::new("cl-chain.toml"), "cl-chain").unwrap();
            let denied = Arc::new(AtomicUsize::new(0));
            let count = Arc::clone(&denied);
            let layer = AclLayer::new(Arc::new(acl)).on_denied(move |_| {
                count.fetch_add(1, Ordering::SeqCst);
            });
            let events = ChainEvents::with_capacity(SLOTS, capacity);
            let (stop, stopping) = watch::channel(false);
            let server =
                EventsServer::new(fixture::v1_link(), events.clone()).stopping(stopping.clone());
            let _ = std::fs::remove_file(socket);
            let listener = UnixListener::bind(socket).unwrap();
            let mut shutdown = stopping;
            let served = tokio::spawn(
                tonic::transport::Server::builder()
                    .layer(layer)
                    .add_service(server.into_service())
                    .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async move {
                        let _ = shutdown.wait_for(|stop| *stop).await;
                    }),
            );
            Self {
                events,
                denied,
                stop,
                served,
                socket: socket.to_path_buf(),
            }
        }

        fn denied(&self) -> usize {
            self.denied.load(Ordering::SeqCst)
        }

        /// cl-chain stops: every stream ends `UNAVAILABLE`, and the socket goes.
        async fn stop(self) {
            self.stop.send_replace(true);
            tokio::time::timeout(WITHIN, self.served)
                .await
                .expect("cl-chain's server stops")
                .unwrap()
                .unwrap();
            let _ = std::fs::remove_file(&self.socket);
        }
    }

    /// Fork choice's block tree in these tests: block `n` at slot `n`, on block `n - 1`.
    struct Line;

    impl BlockTree for Line {
        fn parent(&self, root: &ChainRoot) -> Option<(ChainRoot, Slot)> {
            let n = root.0[0];
            (n > 0).then(|| (ChainRoot::repeat_byte(n - 1), u64::from(n - 1)))
        }
    }

    /// The head on block `n`, at slot `n`.
    fn head(n: u8) -> Head {
        Head {
            slot: u64::from(n),
            block: ChainRoot::repeat_byte(n),
            state: ChainRoot::repeat_byte(n | 0x80),
            payload_status: PayloadStatus::Full,
            previous_duty_dependent_root: ChainRoot::repeat_byte(0x71),
            current_duty_dependent_root: ChainRoot::repeat_byte(0x72),
            execution_optimistic: false,
        }
    }

    /// A sleep that does not sleep: each delay goes to the test, and the follower waits for the
    /// test's go.
    type Delays = mpsc::UnboundedReceiver<(Duration, oneshot::Sender<()>)>;

    fn gated() -> (Sleep, Delays) {
        let (tx, rx) = mpsc::unbounded_channel();
        let sleep: Sleep = Arc::new(move |delay| {
            let tx = tx.clone();
            Box::pin(async move {
                let (go, wait) = oneshot::channel();
                if tx.send((delay, go)).is_ok() {
                    let _ = wait.await;
                }
            })
        });
        (sleep, rx)
    }

    async fn next_delay(delays: &mut Delays) -> (Duration, oneshot::Sender<()>) {
        tokio::time::timeout(WITHIN, delays.recv())
            .await
            .expect("the follower backs off")
            .expect("the follower runs")
    }

    /// A store env whose stamp has its head at slot 20.
    fn store_at_20() -> Arc<Recovering> {
        let store = Store::new();
        let (a, ra) = block(10, [0; 32], 1);
        let (b, rb) = block(20, ra, 2);
        store.import(&[&a, &b], stamp(7, (20, rb), (10, ra)));
        // The store's temp dir lives as long as the test's process.
        let store = Box::leak(Box::new(store));
        Arc::new(Recovering::fixed(Arc::new(store.reader())))
    }

    /// The follower on `socket` until the returned stop is sent or dropped.
    fn spawn(follower: Follower, socket: &Path) -> (oneshot::Sender<()>, JoinHandle<()>) {
        let (stop, stopped) = oneshot::channel::<()>();
        let client = Follower::client(socket, uid());
        let task = tokio::spawn(follower.run(client, async {
            let _ = stopped.await;
        }));
        (stop, task)
    }

    /// cl-store follows cl-chain's own `EventsService` over a Unix socket, behind a cl-chain
    /// ACL that gives it [`CHAIN_METHODS`]: it subscribes to HEAD and FINALIZED_CHECKPOINT and
    /// tracks the last `seq` (cl-chain's, which a BLOCK it did not ask for also spends), head
    /// slot and finalized slot, and `follower_lag`, the slots its head trails the store's stamp.
    /// Stopping it closes the subscription.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tracks_head() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("cl-chain.sock");
        let chain = Chain::serve(&socket, &CHAIN_METHODS, 64);
        let follower = Follower::new(fixture::v1_link(), store_at_20());
        let seen = follower.seen().clone();
        let (stop, task) = spawn(follower, &socket);
        until("subscribed", || seen.connected()).await;
        assert_eq!(seen.subscriptions(), 1);

        chain.events.head(head(12), &Line);
        until("the first head", || {
            seen.seq() == 1 && seen.head_slot() == 12
        })
        .await;
        until("the lag behind the stamp's head", || seen.lag() == 8).await;
        chain.events.block(&ImportedBlock {
            slot: 18,
            block: ChainRoot::repeat_byte(18),
            execution_optimistic: false,
            bid: None,
        });
        chain.events.finalized(&Finalized {
            epoch: 1,
            block: ChainRoot::repeat_byte(8),
            state: ChainRoot::repeat_byte(0x88),
            execution_optimistic: false,
        });
        chain.events.head(head(18), &Line);
        until("the second head", || seen.seq() == 4).await;
        assert_eq!(
            (seen.head_slot(), seen.finalized_slot()),
            (18, SLOTS),
            "head at 18, finality at the start of epoch 1"
        );
        until("the lag behind the stamp's head", || seen.lag() == 2).await;
        assert_eq!(chain.denied(), 0);

        stop.send(()).unwrap();
        tokio::time::timeout(WITHIN, task)
            .await
            .expect("the follower stops")
            .unwrap();
        assert!(!seen.connected());
        chain.stop().await;
    }

    /// cl-chain's ACL must give `EventsService/Subscribe` to cl-store ([`CHAIN_METHODS`]):
    /// without it every subscription is refused before cl-chain sees it, and the follower backs
    /// off and tries again, never subscribed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subscribe_needs_the_acl_entry() {
        assert_eq!(CHAIN_METHODS, [SUBSCRIBE]);
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("cl-chain.sock");
        let chain = Chain::serve(&socket, &[CHAIN_STATUS], 64);
        let (sleep, mut delays) = gated();
        let follower = Follower::new(fixture::v1_link(), store_at_20()).with_sleep(sleep);
        let seen = follower.seen().clone();
        let (_stop, _task) = spawn(follower, &socket);
        for _ in 0..3 {
            let (_, go) = next_delay(&mut delays).await;
            go.send(()).unwrap();
        }
        assert!(chain.denied() >= 3, "denied {}", chain.denied());
        assert!(!seen.connected());
        assert_eq!(seen.subscriptions(), 0);
    }

    /// Nothing listens on cl-chain's socket: each failed subscription waits a longer delay
    /// (injected sleep, no real one), up to [`RESUBSCRIBE_CAP`]. Meanwhile the store env, down,
    /// is not retried by the follower's lag reads past its own backoff. Once cl-chain serves,
    /// the follower subscribes, hints the reader (a reopen is tried at once) and tracks heads.
    /// cl-chain stops: the stream ends, the next delay starts over from [`RESUBSCRIBE_BASE`],
    /// and a restarted cl-chain (a new bus, `seq` from 1 again; nothing is replayed) is followed
    /// again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_bounded_backoff() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("cl-chain.sock");
        let opens = Arc::new(AtomicU64::new(0));
        let count = Arc::clone(&opens);
        let down = Arc::new(Recovering::with_opener(
            Box::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
                Err(store_schema::Error::Mdbx(libmdbx::Error::WannaRecovery))
            }),
            Manual::new().clock(),
        ));
        let (sleep, mut delays) = gated();
        let follower = Follower::new(fixture::v1_link(), Arc::clone(&down)).with_sleep(sleep);
        let seen = follower.seen().clone();
        let (_stop, _task) = spawn(follower, &socket);

        let mut got = Vec::new();
        let mut go: Option<oneshot::Sender<()>> = None;
        for _ in 0..12 {
            if let Some(go) = go.take() {
                go.send(()).unwrap();
            }
            let (delay, next) = next_delay(&mut delays).await;
            got.push(delay);
            go = Some(next);
        }
        check_delays(&got, RESUBSCRIBE_BASE, RESUBSCRIBE_CAP);
        assert!(
            got[7..].iter().all(|d| *d >= RESUBSCRIBE_CAP / 2),
            "{got:?}"
        );
        assert_eq!(seen.subscriptions(), 0);
        assert_eq!(down.reopen_attempts(), 1, "the store's backoff holds");

        let chain = Chain::serve(&socket, &CHAIN_METHODS, 64);
        go.take().unwrap().send(()).unwrap();
        until("subscribed", || seen.connected()).await;
        chain.events.head(head(5), &Line);
        until("the head", || seen.head_slot() == 5 && seen.seq() == 1).await;
        until("the hinted reopen", || down.reopen_attempts() == 2).await;

        chain.stop().await;
        let (delay, go) = next_delay(&mut delays).await;
        assert!(!seen.connected());
        assert!(
            (RESUBSCRIBE_BASE / 2..=RESUBSCRIBE_BASE).contains(&delay),
            "the backoff starts over after a subscription: {delay:?}"
        );
        let chain = Chain::serve(&socket, &CHAIN_METHODS, 64);
        go.send(()).unwrap();
        until("subscribed again", || seen.subscriptions() == 2).await;
        chain.events.head(head(6), &Line);
        until("the restarted bus's first event", || {
            seen.head_slot() == 6 && seen.seq() == 1
        })
        .await;
        chain.stop().await;
    }

    /// Stops the flood once dropped, a failed assertion's unwind included: the runtime waits
    /// for its blocking threads.
    struct Flooding(Arc<AtomicBool>);

    impl Drop for Flooding {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    /// An upstream that sends its hello, then nothing, ever.
    struct Stalled;

    #[tonic::async_trait]
    impl EventsService for Stalled {
        type SubscribeStream = StubStream<pb::SubscribeResponse>;

        async fn subscribe(
            &self,
            _: Request<pb::SubscribeRequest>,
        ) -> Result<Response<Self::SubscribeStream>, Status> {
            let (_, hello) = stream_hello(&fixture::v1_link().local()).unwrap();
            let frames = tokio_stream::once(Ok(pb::SubscribeResponse::hello(hello)))
                .chain(tokio_stream::pending());
            Ok(Response::new(Box::pin(frames)))
        }
    }

    /// Reads never wait on the follower. With three followers on the same store: one on a
    /// stalled upstream (hello, then nothing), one backed up (its sleep never returns), and one
    /// chasing a cl-chain bus of capacity 1 flooded with heads (it lags, ends, subscribes
    /// again), `GetBlock`, `GetChainHead` and `GetBlocksByHead` each answer, well within their
    /// deadline, with the store's stamp.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lagging_never_blocks_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new();
        // Blocks at the first Fulu slots of the fixture link's schedule: each has a digest.
        let fulu = fixture::sepolia_schedule()
            .fork_epoch(network_config::ForkName::Fulu)
            .unwrap()
            * fixture::SLOTS_PER_EPOCH;
        let (a, ra) = block(fulu, [0; 32], 1);
        let (b, rb) = block(fulu + 1, ra, 2);
        let (c, rc) = block(fulu + 2, rb, 3);
        let stamped = stamp(9, (fulu + 2, rc), (fulu, ra));
        store.import(&[&a, &b, &c], stamped);
        let env = Arc::new(Recovering::fixed(Arc::new(store.reader())));

        // 1. Stalled.
        let stalled = tmp.path().join("stalled.sock");
        let listener = UnixListener::bind(&stalled).unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(EventsServiceServer::new(Stalled))
                .serve_with_incoming(UnixListenerStream::new(listener)),
        );
        let one = Follower::new(fixture::v1_link(), Arc::clone(&env));
        let stalled_seen = one.seen().clone();
        let _one = spawn(one, &stalled);
        until("subscribed to the stalled upstream", || {
            stalled_seen.connected()
        })
        .await;

        // 2. Backed up: nothing listens, and its first backoff never ends.
        let entered = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&entered);
        let stuck: Sleep = Arc::new(move |_| {
            flag.store(true, Ordering::SeqCst);
            Box::pin(std::future::pending())
        });
        let two = Follower::new(fixture::v1_link(), Arc::clone(&env)).with_sleep(stuck);
        let _two = spawn(two, &tmp.path().join("absent.sock"));
        until("the backed-up follower is stuck", || {
            entered.load(Ordering::SeqCst)
        })
        .await;

        // 3. Lagging: a bus that keeps one event, flooded.
        let flood = tmp.path().join("flood.sock");
        let chain = Chain::serve(&flood, &CHAIN_METHODS, 1);
        let (instant, mut delays) = gated();
        tokio::spawn(async move {
            while let Some((_, go)) = delays.recv().await {
                let _ = go.send(());
            }
        });
        let three = Follower::new(fixture::v1_link(), Arc::clone(&env)).with_sleep(instant);
        let lagging = three.seen().clone();
        let _three = spawn(three, &flood);
        until("subscribed to the flooded bus", || lagging.connected()).await;
        let events = chain.events.clone();
        let flooding = Flooding(Arc::new(AtomicBool::new(true)));
        let more = Arc::clone(&flooding.0);
        let flooder = tokio::task::spawn_blocking(move || {
            let mut n = 0u8;
            while more.load(Ordering::SeqCst) {
                n = n.wrapping_add(1).max(1);
                events.head(head(n), &Line);
            }
        });

        let server = StoreServer::recovering(fixture::v1_link(), Arc::clone(&env));
        let conn = Mode::InProcess.connect(Server::new(server.routes())).await;
        let mut client = StoreReader::new(conn.transport.clone(), fixture::v1_link());
        let in_time = DEFAULT_TIMEOUT;
        for _ in 0..20 {
            let req = store_pb::GetBlockRequest {
                id: Some(store_pb::BlockId {
                    id: Some(store_pb::block_id::Id::Named("head".into())),
                }),
            };
            let got = tokio::time::timeout(in_time, client.get_block(req))
                .await
                .expect("GetBlock in time")
                .unwrap();
            assert_eq!(got.block.unwrap().root, rc.to_vec());
            let got = tokio::time::timeout(in_time, client.get_chain_head())
                .await
                .expect("GetChainHead in time")
                .unwrap();
            assert_eq!(
                (got.head_slot, got.meta.unwrap().as_of_seq),
                (fulu + 2, stamped.head_seq)
            );
            let req = store_pb::GetBlocksByHeadRequest {
                root: rc.to_vec(),
                count: 8,
                hello: None,
            };
            let got = tokio::time::timeout(in_time, client.get_blocks_by_head(req))
                .await
                .expect("GetBlocksByHead in time")
                .unwrap();
            assert_eq!(got.len(), 3);
        }
        assert!(stalled_seen.connected(), "the stalled subscription is open");
        drop(flooding);
        flooder.await.unwrap();
        chain.stop().await;
    }
}
