//! The muxer caps: [`BudgetedMuxer`] over a scripted muxer, then bare two-swarm tests on
//! 127.0.0.1 (TCP + Noise, no discovery, no gossip). The production side is built with
//! `SwarmBuilder::with_tcp` and [`muxers`]; the test peer records the muxer it negotiated.

use super::*;
use futures::channel::mpsc::{self, UnboundedReceiver};
use futures::future::{BoxFuture, Either};
use futures::stream::FuturesUnordered;
use futures::{AsyncReadExt as _, AsyncWriteExt as _, FutureExt as _, StreamExt as _};
use libp2p::core::muxing::{StreamMuxerBox, StreamMuxerExt as _};
use libp2p::core::transport::{Boxed, PortUse};
use libp2p::core::upgrade::{ReadyUpgrade, SelectUpgrade, Version};
use libp2p::core::Endpoint;
use libp2p::identity::Keypair;
use libp2p::swarm::handler::{
    ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
};
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionHandler, ConnectionHandlerEvent, ConnectionId, FromSwarm,
    NetworkBehaviour, Stream, StreamProtocol, SubstreamProtocol, SwarmEvent, THandler,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{noise, tcp, Multiaddr, PeerId, Swarm, SwarmBuilder, Transport as _};
use prometheus_client::encoding::text::encode;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::task::Waker;
use std::time::Duration;

/// A scripted [`StreamMuxer`]: each stream returns the reads queued on its [`Script`].
mod scripted {
    use super::*;

    /// What one read of a scripted stream returns.
    pub(super) enum Read {
        Data(Vec<u8>),
        Eof,
        Fail(io::ErrorKind),
    }

    #[derive(Default)]
    pub(super) struct State {
        /// Pending once empty.
        pub reads: VecDeque<Read>,
        pub written: Vec<u8>,
        pub flushes: usize,
        pub closed: bool,
        pub dropped: bool,
    }

    /// The shared side of a scripted stream, kept by the test.
    #[derive(Clone, Default)]
    pub(super) struct Script(pub Arc<Mutex<State>>);

    impl Script {
        pub fn push(&self, read: Read) {
            self.0.lock().unwrap().reads.push_back(read);
        }

        pub fn state(&self) -> std::sync::MutexGuard<'_, State> {
            self.0.lock().unwrap()
        }

        pub fn stream(&self) -> Stream {
            Stream(self.clone())
        }
    }

    pub(super) struct Stream(Script);

    impl AsyncRead for Stream {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.0.state();
            match state.reads.pop_front() {
                None => Poll::Pending,
                Some(Read::Eof) => Poll::Ready(Ok(0)),
                Some(Read::Fail(kind)) => Poll::Ready(Err(kind.into())),
                Some(Read::Data(mut data)) => {
                    let n = buf.len().min(data.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    if n < data.len() {
                        state.reads.push_front(Read::Data(data.split_off(n)));
                    }
                    Poll::Ready(Ok(n))
                }
            }
        }
    }

    impl AsyncWrite for Stream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.state().written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.0.state().flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.0.state().closed = true;
            Poll::Ready(Ok(()))
        }
    }

    impl Drop for Stream {
        fn drop(&mut self) {
            self.0.state().dropped = true;
        }
    }

    #[derive(Default)]
    pub(super) struct Muxer {
        pub inbound: VecDeque<Stream>,
        pub outbound: VecDeque<Stream>,
        pub fail_poll: Option<io::ErrorKind>,
        pub closed: bool,
    }

    impl StreamMuxer for Muxer {
        type Substream = Stream;
        type Error = io::Error;

        fn poll_inbound(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Result<Stream, io::Error>> {
            self.inbound
                .pop_front()
                .map_or(Poll::Pending, |s| Poll::Ready(Ok(s)))
        }

        fn poll_outbound(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Result<Stream, io::Error>> {
            self.outbound
                .pop_front()
                .map_or(Poll::Pending, |s| Poll::Ready(Ok(s)))
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            self.closed = true;
            Poll::Ready(Ok(()))
        }

        fn poll(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Result<StreamMuxerEvent, io::Error>> {
            match self.fail_poll {
                Some(kind) => Poll::Ready(Err(kind.into())),
                None => Poll::Pending,
            }
        }
    }
}

use scripted::{Read, Script};

type Scripted = BudgetedMuxer<scripted::Muxer>;

fn noop() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

fn registered() -> (Registry, TransportMetrics) {
    let mut registry = Registry::default();
    let metrics = TransportMetrics::register(&mut registry);
    (registry, metrics)
}

fn budget(connection_bytes: usize, stream_bytes: usize) -> (TransportMetrics, MuxerBudget) {
    let (_, metrics) = registered();
    let budget = MuxerBudget::new(connection_bytes, stream_bytes, &metrics).unwrap();
    (metrics, budget)
}

/// A muxer whose inbound streams are `scripts`, in order.
fn muxer(scripts: &[&Script], budget: MuxerBudget) -> Scripted {
    let inner = scripted::Muxer {
        inbound: scripts.iter().map(|s| s.stream()).collect(),
        ..scripted::Muxer::default()
    };
    BudgetedMuxer::new(inner, budget)
}

fn accept(muxer: &mut Scripted) -> BudgetedStream<scripted::Stream> {
    match muxer.poll_inbound_unpin(&mut noop()) {
        Poll::Ready(Ok(stream)) => stream,
        Poll::Ready(Err(e)) => panic!("inbound: {e}"),
        Poll::Pending => panic!("inbound: pending"),
    }
}

/// Polls the muxer once, which drains every stream; `Ok` if it is still open.
fn drain(muxer: &mut Scripted) -> Result<(), String> {
    match muxer.poll_unpin(&mut noop()) {
        Poll::Pending => Ok(()),
        Poll::Ready(Ok(event)) => panic!("unexpected muxer event {event:?}"),
        Poll::Ready(Err(e)) => Err(e.to_string()),
    }
}

fn read(stream: &mut BudgetedStream<scripted::Stream>, len: usize) -> Poll<io::Result<Vec<u8>>> {
    let mut buf = vec![0; len];
    Pin::new(stream)
        .poll_read(&mut noop(), &mut buf)
        .map_ok(|n| buf[..n].to_vec())
}

fn read_kind(stream: &mut BudgetedStream<scripted::Stream>) -> io::ErrorKind {
    match read(stream, 16) {
        Poll::Ready(Err(e)) => e.kind(),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn drained_bytes_are_read_back_in_order() {
    let (_, budget) = budget(1024, 64);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    script.push(Read::Data(b"hello".to_vec()));
    script.push(Read::Data(b" world".to_vec()));

    drain(&mut muxer).unwrap();
    assert_eq!(muxer.buffered(), 11);
    assert!(
        script.state().reads.is_empty(),
        "the muxer drains the stream"
    );

    assert_eq!(
        read(&mut stream, 4).map(Result::unwrap),
        Poll::Ready(b"hell".to_vec())
    );
    assert_eq!(muxer.buffered(), 7);
    assert_eq!(
        read(&mut stream, 64).map(Result::unwrap),
        Poll::Ready(b"o world".to_vec())
    );
    assert_eq!(muxer.buffered(), 0);
    // Nothing buffered and nothing to read: pending, like the stream itself.
    assert!(read(&mut stream, 64).is_pending());
}

#[test]
fn an_empty_buffer_reads_the_stream_directly() {
    let (_, budget) = budget(1024, 64);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    script.push(Read::Data(b"direct".to_vec()));
    assert_eq!(
        read(&mut stream, 64).map(Result::unwrap),
        Poll::Ready(b"direct".to_vec())
    );
    assert_eq!(
        muxer.buffered(),
        0,
        "bytes read straight through are never held"
    );
}

#[test]
fn a_zero_length_read_is_not_end_of_stream() {
    let (_, budget) = budget(1024, 64);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    script.push(Read::Data(b"x".to_vec()));
    assert_eq!(
        read(&mut stream, 0).map(Result::unwrap),
        Poll::Ready(Vec::new())
    );
    assert_eq!(
        read(&mut stream, 8).map(Result::unwrap),
        Poll::Ready(b"x".to_vec())
    );
}

#[test]
fn end_of_stream_follows_the_buffered_bytes() {
    let (_, budget) = budget(1024, 64);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    script.push(Read::Data(b"last".to_vec()));
    script.push(Read::Eof);
    drain(&mut muxer).unwrap();

    assert_eq!(
        read(&mut stream, 64).map(Result::unwrap),
        Poll::Ready(b"last".to_vec())
    );
    // The end is remembered: the stream is not read again.
    for _ in 0..2 {
        assert_eq!(
            read(&mut stream, 64).map(Result::unwrap),
            Poll::Ready(Vec::new())
        );
    }
}

#[test]
fn a_direct_read_end_is_remembered() {
    let (_, budget) = budget(1024, 64);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    script.push(Read::Eof);
    assert_eq!(
        read(&mut stream, 64).map(Result::unwrap),
        Poll::Ready(Vec::new())
    );
    // A later read would be pending if it reached the script; the muxer does not drain it.
    script.push(Read::Data(b"after the end".to_vec()));
    drain(&mut muxer).unwrap();
    assert_eq!(muxer.buffered(), 0);
    assert_eq!(
        read(&mut stream, 64).map(Result::unwrap),
        Poll::Ready(Vec::new())
    );
}

#[test]
fn a_read_error_follows_the_buffered_bytes() {
    let (_, budget) = budget(1024, 64);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    script.push(Read::Data(b"partial".to_vec()));
    script.push(Read::Fail(io::ErrorKind::ConnectionAborted));
    drain(&mut muxer).unwrap();

    assert_eq!(
        read(&mut stream, 64).map(Result::unwrap),
        Poll::Ready(b"partial".to_vec())
    );
    assert_eq!(read_kind(&mut stream), io::ErrorKind::ConnectionAborted);
    assert_eq!(read_kind(&mut stream), io::ErrorKind::ConnectionAborted);
}

#[test]
fn a_direct_read_error_is_remembered() {
    let (_, budget) = budget(1024, 64);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    script.push(Read::Fail(io::ErrorKind::UnexpectedEof));
    assert_eq!(read_kind(&mut stream), io::ErrorKind::UnexpectedEof);
    script.push(Read::Data(b"ignored".to_vec()));
    drain(&mut muxer).unwrap();
    assert_eq!(muxer.buffered(), 0);
    assert_eq!(read_kind(&mut stream), io::ErrorKind::UnexpectedEof);
}

#[test]
fn a_stream_over_its_budget_is_reset() {
    let (metrics, budget) = budget(1024, 8);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    script.push(Read::Data(vec![7; 9]));

    drain(&mut muxer).unwrap();
    assert!(
        script.state().dropped,
        "the inner stream is dropped, which resets it"
    );
    assert_eq!(muxer.buffered(), 0, "its bytes are freed");
    assert_eq!(read_kind(&mut stream), io::ErrorKind::ConnectionReset);
    let write = Pin::new(&mut stream).poll_write(&mut noop(), b"x");
    assert!(matches!(write, Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset));
    let flush = Pin::new(&mut stream).poll_flush(&mut noop());
    assert!(matches!(flush, Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset));
    let close = Pin::new(&mut stream).poll_close(&mut noop());
    assert!(matches!(close, Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset));
    assert_eq!(
        metrics.conn_budget_exceeded(),
        0,
        "a stream reset keeps the connection"
    );
}

#[test]
fn a_stream_at_its_budget_is_kept() {
    let (_, budget) = budget(1024, 8);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    script.push(Read::Data(vec![7; 8]));
    drain(&mut muxer).unwrap();
    assert!(!script.state().dropped);
    assert_eq!(
        read(&mut stream, 64).map(Result::unwrap),
        Poll::Ready(vec![7; 8])
    );
}

#[test]
fn streams_over_the_connection_budget_close_the_connection() {
    let (metrics, budget) = budget(10, 8);
    let (a, b) = (Script::default(), Script::default());
    let mut muxer = muxer(&[&a, &b], budget);
    let _streams = (accept(&mut muxer), accept(&mut muxer));
    a.push(Read::Data(vec![1; 6]));
    b.push(Read::Data(vec![2; 6]));

    let error = drain(&mut muxer).unwrap_err();
    assert!(error.contains("budget"), "{error}");
    assert!(error.contains("12"), "{error}");
    assert_eq!(metrics.conn_budget_exceeded(), 1);
    // Closed for good, counted once.
    assert!(drain(&mut muxer).is_err());
    assert!(matches!(
        muxer.poll_inbound_unpin(&mut noop()),
        Poll::Ready(Err(BudgetedMuxerError::BudgetExceeded {
            buffered: 12,
            budget: 10
        }))
    ));
    assert!(matches!(
        muxer.poll_outbound_unpin(&mut noop()),
        Poll::Ready(Err(BudgetedMuxerError::BudgetExceeded { .. }))
    ));
    assert_eq!(metrics.conn_budget_exceeded(), 1);
}

#[test]
fn the_connection_budget_stops_a_drain_midway() {
    let (metrics, budget) = budget(10, 8);
    let (a, b) = (Script::default(), Script::default());
    let mut muxer = muxer(&[&a, &b], budget);
    let _streams = (accept(&mut muxer), accept(&mut muxer));
    a.push(Read::Data(vec![1; 6]));
    drain(&mut muxer).unwrap();
    for _ in 0..4 {
        b.push(Read::Data(vec![2; 3]));
    }
    assert!(drain(&mut muxer).is_err());
    // 6 + 3 is within 10, 6 + 3 + 3 is not: the rest is left in the stream.
    assert_eq!(b.state().reads.len(), 2);
    assert_eq!(metrics.conn_budget_exceeded(), 1);
}

#[test]
fn a_reset_is_flushed_through_another_stream() {
    let (_, budget) = budget(1024, 8);
    let (a, b) = (Script::default(), Script::default());
    let mut muxer = muxer(&[&a, &b], budget);
    let _streams = (accept(&mut muxer), accept(&mut muxer));
    a.push(Read::Data(vec![1; 9]));
    drain(&mut muxer).unwrap();
    // mplex queues the reset when the stream is dropped and sends it on the next flush.
    assert!(a.state().dropped);
    assert_eq!(b.state().flushes, 1);
    drain(&mut muxer).unwrap();
    assert_eq!(b.state().flushes, 1, "flushed once per reset");
}

#[test]
fn a_reset_with_no_other_stream_is_flushed_through_the_next_one() {
    let (_, budget) = budget(1024, 8);
    let (a, b) = (Script::default(), Script::default());
    let mut muxer = muxer(&[&a, &b], budget);
    let _first = accept(&mut muxer);
    a.push(Read::Data(vec![1; 9]));
    drain(&mut muxer).unwrap();
    assert!(a.state().dropped);
    let _second = accept(&mut muxer);
    drain(&mut muxer).unwrap();
    assert_eq!(b.state().flushes, 1);
}

#[test]
fn a_dropped_stream_frees_its_bytes() {
    let (metrics, budget) = budget(10, 8);
    let (a, b) = (Script::default(), Script::default());
    let mut muxer = muxer(&[&a, &b], budget);
    let first = accept(&mut muxer);
    a.push(Read::Data(vec![1; 6]));
    drain(&mut muxer).unwrap();
    assert_eq!(muxer.buffered(), 6);

    drop(first);
    assert!(a.state().dropped);
    assert_eq!(muxer.buffered(), 0);
    let _second = accept(&mut muxer);
    b.push(Read::Data(vec![2; 6]));
    drain(&mut muxer).unwrap();
    assert_eq!(muxer.buffered(), 6);
    assert_eq!(metrics.conn_budget_exceeded(), 0);
}

#[test]
fn outbound_streams_are_drained_too() {
    let (_, budget) = budget(1024, 64);
    let script = Script::default();
    let inner = scripted::Muxer {
        outbound: VecDeque::from([script.stream()]),
        ..scripted::Muxer::default()
    };
    let mut muxer = BudgetedMuxer::new(inner, budget);
    assert!(muxer.poll_inbound_unpin(&mut noop()).is_pending());
    let Poll::Ready(Ok(mut stream)) = muxer.poll_outbound_unpin(&mut noop()) else {
        panic!("outbound stream");
    };
    script.push(Read::Data(b"out".to_vec()));
    drain(&mut muxer).unwrap();
    assert_eq!(muxer.buffered(), 3);
    assert_eq!(
        read(&mut stream, 8).map(Result::unwrap),
        Poll::Ready(b"out".to_vec())
    );
}

#[test]
fn writes_flushes_and_closes_reach_the_stream() {
    let (_, budget) = budget(1024, 64);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    let mut cx = noop();
    assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, b"abc"),
        Poll::Ready(Ok(3))
    ));
    assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_ready());
    assert!(Pin::new(&mut stream).poll_close(&mut cx).is_ready());
    let state = script.state();
    assert_eq!(
        (state.written.as_slice(), state.flushes, state.closed),
        (&b"abc"[..], 1, true)
    );
}

#[test]
fn muxer_errors_and_close_pass_through() {
    let (metrics, budget) = budget(1024, 64);
    let inner = scripted::Muxer {
        fail_poll: Some(io::ErrorKind::BrokenPipe),
        ..scripted::Muxer::default()
    };
    let mut muxer = BudgetedMuxer::new(inner, budget);
    match muxer.poll_unpin(&mut noop()) {
        Poll::Ready(Err(BudgetedMuxerError::Muxer(e))) => {
            assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
        }
        other => panic!("expected the muxer's error, got {:?}", other.map(|_| ())),
    }
    assert!(matches!(
        muxer.poll_close_unpin(&mut noop()),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(metrics.conn_budget_exceeded(), 0);
}

#[test]
fn a_woken_reader_sees_drained_bytes() {
    struct Flag(std::sync::atomic::AtomicBool);
    impl std::task::Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let (_, budget) = budget(1024, 64);
    let script = Script::default();
    let mut muxer = muxer(&[&script], budget);
    let mut stream = accept(&mut muxer);
    let flag = Arc::new(Flag(false.into()));
    let waker = Waker::from(Arc::clone(&flag));
    let mut buf = [0; 8];
    assert!(Pin::new(&mut stream)
        .poll_read(&mut Context::from_waker(&waker), &mut buf)
        .is_pending());

    script.push(Read::Data(b"woke".to_vec()));
    drain(&mut muxer).unwrap();
    assert!(
        flag.0.load(std::sync::atomic::Ordering::SeqCst),
        "the reader is woken"
    );
    assert_eq!(
        read(&mut stream, 8).map(Result::unwrap),
        Poll::Ready(b"woke".to_vec())
    );
}

#[test]
fn recv_buf_keeps_order_across_chunks() {
    let data: Vec<u8> = (0..3 * RECV_CHUNK + 123).map(|i| (i % 251) as u8).collect();
    let mut buf = RecvBuf::default();
    for piece in data.chunks(5_000) {
        buf.push(piece);
    }
    assert_eq!(buf.len(), data.len());
    let mut out = Vec::new();
    let mut scratch = [0; 7_000];
    while !buf.is_empty() {
        let n = buf.pop_into(&mut scratch);
        assert!(n > 0);
        out.extend_from_slice(&scratch[..n]);
    }
    assert_eq!(out, data);
    assert_eq!(buf.pop_into(&mut scratch), 0);
}

#[test]
fn budget_limits_are_checked() {
    let (_, metrics) = registered();
    assert_eq!(
        MuxerBudget::new(10, 0, &metrics).unwrap_err(),
        BudgetError::ZeroStreamBytes
    );
    let above = MuxerBudget::new(10, 11, &metrics).unwrap_err();
    assert_eq!(
        above,
        BudgetError::StreamAboveConnection {
            stream_bytes: 11,
            connection_bytes: 10
        }
    );
    assert!(above.to_string().contains("11"), "{above}");
    let budget = MuxerBudget::new(10, 10, &metrics).unwrap();
    assert_eq!((budget.connection_bytes(), budget.stream_bytes()), (10, 10));
    let defaults = MuxerBudget::with_defaults(&metrics);
    assert_eq!(
        (defaults.connection_bytes(), defaults.stream_bytes()),
        (DEFAULT_CONNECTION_BYTES, DEFAULT_STREAM_BYTES)
    );
}

#[test]
fn default_budgets_fit_max_size_messages() {
    use consensus_types::caps::MAX_PAYLOAD_SIZE;
    // One stream holds one MAX_PAYLOAD_SIZE message at its snappy worst case...
    assert_eq!(
        DEFAULT_STREAM_BYTES,
        p2p_wire::rpc::codec::max_compressed_len(MAX_PAYLOAD_SIZE)
    );
    // ...and one connection two of them, with room to spare.
    const { assert!(DEFAULT_CONNECTION_BYTES >= 2 * DEFAULT_STREAM_BYTES) };
    assert_eq!(DEFAULT_CONNECTION_BYTES, 32 << 20);
}

#[test]
fn budget_metric_is_registered_at_zero() {
    let (registry, metrics) = registered();
    let mut text = String::new();
    encode(&mut text, &registry).unwrap();
    assert!(
        text.contains("# TYPE p2p_conn_budget_exceeded counter\n"),
        "{text}"
    );
    assert!(
        text.contains("\np2p_conn_budget_exceeded_total 0\n"),
        "{text}"
    );
    assert_eq!(metrics.conn_budget_exceeded(), 0);
}

// ---------------------------------------------------------------------------------------------
// Bare two-swarm tests.

/// Every wait in these tests.
const WAIT: Duration = Duration::from_secs(20);

/// The protocol the hold behaviour opens and accepts streams on.
const HOLD: StreamProtocol = StreamProtocol::new("/ethswarm/test/hold/1");

/// What the hold behaviour writes per call.
const FLOOD_CHUNK: usize = 8 * 1024;

/// What a hold behaviour does on each connection. It never reads a stream.
#[derive(Clone, Copy, Debug, Default)]
struct Plan {
    /// Outbound streams to open.
    open: usize,
    /// Bytes to write into each inbound stream (0: none), then hold it.
    write_inbound: usize,
    /// Bytes to write into each of the first `open` outbound streams (0: none), then hold it.
    write_outbound: usize,
    /// Further outbound streams to open and hold without writing.
    idle: usize,
}

#[derive(Debug)]
enum HoldEvent {
    Inbound,
    Outbound,
    OutboundFailed(String),
    /// A write into a stream ended: the bytes written, or why it failed.
    Wrote {
        result: Result<usize, io::ErrorKind>,
    },
}

/// Opens and accepts [`HOLD`] streams per [`Plan`], keeps every one open and never reads.
struct Hold {
    plan: Plan,
    events: VecDeque<HoldEvent>,
}

impl Hold {
    fn new(plan: Plan) -> Self {
        Self {
            plan,
            events: VecDeque::new(),
        }
    }
}

impl NetworkBehaviour for Hold {
    type ConnectionHandler = HoldHandler;
    type ToSwarm = HoldEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(HoldHandler::new(self.plan))
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(HoldHandler::new(self.plan))
    }

    fn on_swarm_event(&mut self, _: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.events.push_back(event);
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<HoldEvent, Infallible>> {
        self.events
            .pop_front()
            .map_or(Poll::Pending, |e| Poll::Ready(ToSwarm::GenerateEvent(e)))
    }
}

type Flood = BoxFuture<'static, (Stream, Result<usize, io::ErrorKind>)>;

struct HoldHandler {
    plan: Plan,
    requested: usize,
    /// Outbound streams negotiated so far.
    outbound: usize,
    held: Vec<Stream>,
    floods: FuturesUnordered<Flood>,
    events: VecDeque<HoldEvent>,
}

impl HoldHandler {
    fn new(plan: Plan) -> Self {
        Self {
            plan,
            requested: 0,
            outbound: 0,
            held: Vec::new(),
            floods: FuturesUnordered::new(),
            events: VecDeque::new(),
        }
    }

    fn adopt(&mut self, stream: Stream, outbound: bool) {
        let bytes = if !outbound {
            self.plan.write_inbound
        } else if self.outbound <= self.plan.open {
            self.plan.write_outbound
        } else {
            0
        };
        if bytes == 0 {
            self.held.push(stream);
        } else {
            self.floods.push(flood(stream, bytes).boxed());
        }
    }
}

/// Writes `bytes` into `stream`, yielding after each chunk so the connection task can read
/// what the peer sends meanwhile (a reset).
async fn flood(mut stream: Stream, bytes: usize) -> (Stream, Result<usize, io::ErrorKind>) {
    let chunk = [0x5a; FLOOD_CHUNK];
    let mut sent = 0;
    while sent < bytes {
        let n = FLOOD_CHUNK.min(bytes - sent);
        if let Err(e) = stream.write_all(&chunk[..n]).await {
            return (stream, Err(e.kind()));
        }
        sent += n;
        tokio::task::yield_now().await;
    }
    let result = stream.flush().await.map(|()| sent).map_err(|e| e.kind());
    (stream, result)
}

impl ConnectionHandler for HoldHandler {
    type FromBehaviour = Infallible;
    type ToBehaviour = HoldEvent;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(ReadyUpgrade::new(HOLD), ())
    }

    fn connection_keep_alive(&self) -> bool {
        true
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, (), HoldEvent>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(event));
        }
        if self.requested < self.plan.open + self.plan.idle {
            self.requested += 1;
            return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(ReadyUpgrade::new(HOLD), ()),
            });
        }
        if let Poll::Ready(Some((stream, result))) = self.floods.poll_next_unpin(cx) {
            self.held.push(stream);
            return Poll::Ready(ConnectionHandlerEvent::NotifyBehaviour(HoldEvent::Wrote {
                result,
            }));
        }
        Poll::Pending
    }

    fn on_behaviour_event(&mut self, event: Infallible) {
        match event {}
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: stream,
                ..
            }) => {
                self.events.push_back(HoldEvent::Inbound);
                self.adopt(stream, false);
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: stream,
                ..
            }) => {
                self.events.push_back(HoldEvent::Outbound);
                self.outbound += 1;
                self.adopt(stream, true);
            }
            ConnectionEvent::DialUpgradeError(DialUpgradeError { error, .. }) => {
                self.events
                    .push_back(HoldEvent::OutboundFailed(error.to_string()));
            }
            _ => {}
        }
    }
}

/// A swarm event a test waits for.
#[derive(Debug)]
enum Seen {
    Listening(Multiaddr),
    Established(PeerId),
    /// The peer and the cause, if any.
    Closed(PeerId, String),
    Hold(HoldEvent),
}

/// Runs `swarm` on its own task; its events arrive on the receiver until it is dropped.
fn run<B>(mut swarm: Swarm<B>, map: fn(B::ToSwarm) -> Seen) -> UnboundedReceiver<Seen>
where
    B: NetworkBehaviour + Send + 'static,
{
    let (tx, rx) = mpsc::unbounded();
    tokio::spawn(async move {
        loop {
            let seen = match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => Seen::Listening(address),
                SwarmEvent::ConnectionEstablished { peer_id, .. } => Seen::Established(peer_id),
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    Seen::Closed(peer_id, cause.map(|c| c.to_string()).unwrap_or_default())
                }
                SwarmEvent::Behaviour(event) => map(event),
                _ => continue,
            };
            if tx.unbounded_send(seen).is_err() {
                return;
            }
        }
    });
    rx
}

/// The next event `pick` maps to `Some`, within [`WAIT`].
async fn wait_for<T>(
    rx: &mut UnboundedReceiver<Seen>,
    what: &str,
    mut pick: impl FnMut(Seen) -> Option<T>,
) -> T {
    let found = tokio::time::timeout(WAIT, async {
        while let Some(seen) = rx.next().await {
            if let Some(found) = pick(seen) {
                return found;
            }
        }
        panic!("{what}: the swarm stopped");
    });
    found
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

/// The production swarm: `with_tcp` with [`muxers`].
fn production_swarm<B: NetworkBehaviour>(budget: MuxerBudget, behaviour: B) -> Swarm<B> {
    SwarmBuilder::with_existing_identity(Keypair::generate_secp256k1())
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, muxers(budget))
        .expect("tcp transport")
        .with_behaviour(|_| behaviour)
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(WAIT))
        .build()
}

/// The muxers a test peer offers, in its order of preference.
#[derive(Clone)]
enum Offer {
    YamuxThenMplex,
    MplexThenYamux,
    Mplex(libp2p_mplex::Config),
}

/// The muxer each of the test peer's connections negotiated.
type Negotiated = Arc<Mutex<Vec<&'static str>>>;

type PeerTransport =
    Result<Boxed<(PeerId, StreamMuxerBox)>, Box<dyn std::error::Error + Send + Sync>>;

/// TCP + Noise + `offer`, recording the muxer of each upgrade.
fn peer_transport(key: &Keypair, offer: Offer, negotiated: Negotiated) -> PeerTransport {
    let authenticated = tcp::tokio::Transport::new(tcp::Config::default())
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(key)?);
    let record = move |name| negotiated.lock().unwrap().push(name);
    Ok(match offer {
        Offer::YamuxThenMplex => authenticated
            .multiplex(SelectUpgrade::new(
                yamux::Config::default(),
                libp2p_mplex::Config::default(),
            ))
            .map(move |(peer, muxer), _| {
                record(match &muxer {
                    Either::Left(_) => "yamux",
                    Either::Right(_) => "mplex",
                });
                (peer, StreamMuxerBox::new(muxer))
            })
            .boxed(),
        Offer::MplexThenYamux => authenticated
            .multiplex(SelectUpgrade::new(
                libp2p_mplex::Config::default(),
                yamux::Config::default(),
            ))
            .map(move |(peer, muxer), _| {
                record(match &muxer {
                    Either::Left(_) => "mplex",
                    Either::Right(_) => "yamux",
                });
                (peer, StreamMuxerBox::new(muxer))
            })
            .boxed(),
        Offer::Mplex(config) => authenticated
            .multiplex(config)
            .map(move |(peer, muxer), _| {
                record("mplex");
                (peer, StreamMuxerBox::new(muxer))
            })
            .boxed(),
    })
}

fn peer_swarm<B: NetworkBehaviour>(offer: Offer, negotiated: Negotiated, behaviour: B) -> Swarm<B> {
    SwarmBuilder::with_existing_identity(Keypair::generate_secp256k1())
        .with_tokio()
        .with_other_transport(move |key| peer_transport(key, offer, negotiated))
        .expect("peer transport")
        .with_behaviour(|_| behaviour)
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(WAIT))
        .build()
}

fn loopback() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}

/// Starts `swarm` listening on 127.0.0.1 and returns its events and address.
async fn listen<B>(
    mut swarm: Swarm<B>,
    map: fn(B::ToSwarm) -> Seen,
) -> (UnboundedReceiver<Seen>, Multiaddr)
where
    B: NetworkBehaviour + Send + 'static,
{
    swarm.listen_on(loopback()).unwrap();
    let mut rx = run(swarm, map);
    let addr = wait_for(&mut rx, "a listen address", |seen| match seen {
        Seen::Listening(addr) => Some(addr),
        _ => None,
    })
    .await;
    (rx, addr)
}

fn no_event(event: Infallible) -> Seen {
    match event {}
}

#[derive(Clone, Copy)]
enum Dialer {
    Production,
    Peer,
}

/// Connects a production swarm and a test peer offering `offer`; the muxer the peer negotiated.
async fn negotiate(offer: Offer, dialer: Dialer) -> &'static str {
    let (_, metrics) = registered();
    let negotiated = Negotiated::default();
    let ours = production_swarm(MuxerBudget::with_defaults(&metrics), dummy::Behaviour);
    let theirs = peer_swarm(offer, Arc::clone(&negotiated), dummy::Behaviour);
    // Both receivers live to the end: dropping one stops its swarm.
    let _events = match dialer {
        Dialer::Production => {
            let (theirs_rx, addr) = listen(theirs, no_event).await;
            let mut ours = ours;
            ours.dial(addr).unwrap();
            (run(ours, no_event), theirs_rx)
        }
        Dialer::Peer => {
            let (ours_rx, addr) = listen(ours, no_event).await;
            let mut theirs = theirs;
            theirs.dial(addr).unwrap();
            (ours_rx, run(theirs, no_event))
        }
    };
    for _ in 0..(WAIT.as_millis() / 20) {
        if let Some(name) = negotiated.lock().unwrap().first() {
            return name;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the test peer negotiated no muxer");
}

#[tokio::test]
async fn muxer_precedence() {
    // Both peers offer both: yamux, whoever dials.
    assert_eq!(
        negotiate(Offer::YamuxThenMplex, Dialer::Production).await,
        "yamux"
    );
    assert_eq!(
        negotiate(Offer::YamuxThenMplex, Dialer::Peer).await,
        "yamux"
    );
    // Our dial proposes yamux first, so it wins even against a peer that prefers mplex.
    assert_eq!(
        negotiate(Offer::MplexThenYamux, Dialer::Production).await,
        "yamux"
    );
    // A peer offering only mplex gets mplex, whoever dials.
    let mplex = || Offer::Mplex(libp2p_mplex::Config::default());
    assert_eq!(negotiate(mplex(), Dialer::Production).await, "mplex");
    assert_eq!(negotiate(mplex(), Dialer::Peer).await, "mplex");
}

/// A production swarm holding `ours` and a test peer offering `offer` and holding `theirs`,
/// connected (the peer dials).
struct Pair {
    ours: UnboundedReceiver<Seen>,
    theirs: UnboundedReceiver<Seen>,
    /// The test peer.
    peer: PeerId,
}

async fn connect(budget: MuxerBudget, ours: Plan, offer: Offer, theirs: Plan) -> Pair {
    let (mut ours_rx, addr) = listen(production_swarm(budget, Hold::new(ours)), Seen::Hold).await;
    let mut swarm = peer_swarm(offer, Negotiated::default(), Hold::new(theirs));
    let peer = *swarm.local_peer_id();
    swarm.dial(addr).unwrap();
    let theirs_rx = run(swarm, Seen::Hold);
    let connected = wait_for(&mut ours_rx, "the connection", |seen| match seen {
        Seen::Established(id) => Some(id),
        _ => None,
    })
    .await;
    assert_eq!(connected, peer);
    Pair {
        ours: ours_rx,
        theirs: theirs_rx,
        peer,
    }
}

/// Fails if the production side reports the connection closed within `quiet`.
async fn assert_still_connected(rx: &mut UnboundedReceiver<Seen>, quiet: Duration) {
    let closed = tokio::time::timeout(quiet, async {
        while let Some(seen) = rx.next().await {
            if let Seen::Closed(peer, cause) = seen {
                return Some((peer, cause));
            }
        }
        None
    })
    .await;
    if let Ok(Some((peer, cause))) = closed {
        panic!("the connection to {peer} closed: {cause}");
    }
}

#[tokio::test]
async fn sixty_fifth_stream_is_refused() {
    let (_, metrics) = registered();
    // The peer's mplex allows 128 streams, so the 65th is ours to refuse.
    let mut pair = connect(
        MuxerBudget::with_defaults(&metrics),
        Plan::default(),
        Offer::Mplex(libp2p_mplex::Config::default()),
        Plan {
            open: MPLEX_MAX_STREAMS + 1,
            ..Plan::default()
        },
    )
    .await;

    let (mut opened, mut refused) = (0, Vec::new());
    while opened + refused.len() < MPLEX_MAX_STREAMS + 1 {
        let outcome = wait_for(
            &mut pair.theirs,
            "an outbound stream outcome",
            |seen| match seen {
                Seen::Hold(HoldEvent::Outbound) => Some(Ok(())),
                Seen::Hold(HoldEvent::OutboundFailed(e)) => Some(Err(e)),
                _ => None,
            },
        )
        .await;
        match outcome {
            Ok(()) => opened += 1,
            Err(e) => refused.push(e),
        }
    }
    assert_eq!(opened, MPLEX_MAX_STREAMS, "refused: {refused:?}");
    assert_eq!(refused.len(), 1);

    for _ in 0..MPLEX_MAX_STREAMS {
        wait_for(&mut pair.ours, "an inbound stream", |seen| match seen {
            Seen::Hold(HoldEvent::Inbound) => Some(()),
            _ => None,
        })
        .await;
    }
    // A refused stream resets that stream only.
    assert_still_connected(&mut pair.ours, Duration::from_millis(200)).await;
}

#[tokio::test]
async fn stream_overflow_resets_the_stream() {
    let (_, metrics) = registered();
    // We never read; the peer opens one stream and writes far past its 64 KiB budget, and
    // holds a second one open. mplex sends a reset only on the next flush, which we make
    // through the other stream.
    let budget = MuxerBudget::new(1 << 20, 64 << 10, &metrics).unwrap();
    let mut pair = connect(
        budget,
        Plan::default(),
        Offer::Mplex(libp2p_mplex::Config::default()),
        Plan {
            open: 1,
            write_outbound: 64 << 20,
            idle: 1,
            ..Plan::default()
        },
    )
    .await;

    let result = wait_for(&mut pair.theirs, "the peer's write", |seen| match seen {
        Seen::Hold(HoldEvent::Wrote { result, .. }) => Some(result),
        _ => None,
    })
    .await;
    assert!(result.is_err(), "the peer wrote everything: {result:?}");
    // The stream was reset, not the connection.
    assert_still_connected(&mut pair.ours, Duration::from_millis(300)).await;
    assert_eq!(metrics.conn_budget_exceeded(), 0);
}

/// mplex's frame size when it sends: one frame per write of up to 8 KiB.
const MPLEX_FRAME: usize = 8 * 1024;

/// Two mplex muxers over a loopback TCP connection: the sender with the library defaults, the
/// receiver with `receiver`.
async fn mplex_pair(
    receiver: libp2p_mplex::Config,
) -> (
    libp2p_mplex::Multiplex<tcp::tokio::TcpStream>,
    libp2p_mplex::Multiplex<tcp::tokio::TcpStream>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (dialed, accepted) = tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
    let name = "/mplex/6.7.0";
    let sender = libp2p_mplex::Config::default()
        .upgrade_outbound(tcp::tokio::TcpStream(dialed.unwrap()), name)
        .await
        .unwrap();
    let receiver = receiver
        .upgrade_inbound(tcp::tokio::TcpStream(accepted.unwrap().0), name)
        .await
        .unwrap();
    (sender, receiver)
}

async fn next_inbound<M>(muxer: &mut M) -> M::Substream
where
    M: StreamMuxer + Unpin,
    M::Error: std::fmt::Debug,
{
    let next = futures::future::poll_fn(|cx| muxer.poll_inbound_unpin(cx));
    tokio::time::timeout(WAIT, next).await.unwrap().unwrap()
}

#[tokio::test]
async fn mplex_resets_a_stream_past_its_frame_buffer() {
    let (mut sender, mut receiver) = mplex_pair(mplex_config()).await;
    let frame = [0x5a; MPLEX_FRAME];
    // The sender writes 300 frames into a stream the receiver does not read, then opens a
    // second stream, whose Open frame arrives after all 300.
    let send = async {
        let mut unread = futures::future::poll_fn(|cx| sender.poll_outbound_unpin(cx))
            .await
            .unwrap();
        for _ in 0..300 {
            unread.write_all(&frame).await.unwrap();
        }
        unread.flush().await.unwrap();
        let mut marker = futures::future::poll_fn(|cx| sender.poll_outbound_unpin(cx))
            .await
            .unwrap();
        marker.flush().await.unwrap();
        (unread, marker)
    };
    // Accepting the second stream reads every frame of the first.
    let receive = async {
        let first = next_inbound(&mut receiver).await;
        (first, next_inbound(&mut receiver).await)
    };
    let ((mut unread, _marker), (mut stream, mut second)) =
        tokio::time::timeout(WAIT, futures::future::join(send, receive))
            .await
            .unwrap();

    // MaxBufferBehaviour::ResetStream: the frame that overflowed the buffer is kept, nothing
    // after it, and then the stream ends.
    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(
        received.len(),
        (MPLEX_MAX_BUFFERED_FRAMES + 1) * MPLEX_FRAME
    );

    // The reset leaves with the receiver's next flush, and then the sender's writes fail.
    second.flush().await.unwrap();
    let refused = tokio::time::timeout(WAIT, async {
        loop {
            // Reading for new streams makes the sender's mplex process the reset.
            futures::future::poll_fn(|cx| {
                let _ = sender.poll_inbound_unpin(cx);
                Poll::Ready(())
            })
            .await;
            if let Err(e) = unread.write_all(&frame).await {
                return e.kind();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(refused, io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn connection_budget_closes_the_connection() {
    let (_, metrics) = registered();
    // Four streams of 100 KiB each stay under the 128 KiB stream budget, and together pass
    // the 256 KiB connection budget.
    let budget = MuxerBudget::new(256 << 10, 128 << 10, &metrics).unwrap();
    let mut pair = connect(
        budget,
        Plan::default(),
        Offer::Mplex(libp2p_mplex::Config::default()),
        Plan {
            open: 4,
            write_outbound: 100 << 10,
            ..Plan::default()
        },
    )
    .await;

    let (peer, cause) = wait_for(
        &mut pair.ours,
        "the connection to close",
        |seen| match seen {
            Seen::Closed(peer, cause) => Some((peer, cause)),
            _ => None,
        },
    )
    .await;
    assert_eq!(peer, pair.peer);
    assert!(cause.contains("budget"), "{cause}");
    assert_eq!(metrics.conn_budget_exceeded(), 1);
}

#[tokio::test]
async fn a_read_stream_outlasts_the_budget() {
    // What the application reads leaves the budget: 48 MiB through one stream, read as it
    // arrives, never closes a connection whose budget is 32 MiB.
    let (_, metrics) = registered();
    let (mut ours_rx, addr) = listen(
        production_swarm(MuxerBudget::with_defaults(&metrics), Sink),
        no_event,
    )
    .await;
    let mut theirs = peer_swarm(
        Offer::Mplex(libp2p_mplex::Config::default()),
        Negotiated::default(),
        Hold::new(Plan {
            open: 1,
            write_outbound: 48 << 20,
            ..Plan::default()
        }),
    );
    theirs.dial(addr).unwrap();
    let mut theirs_rx = run(theirs, Seen::Hold);
    let result = wait_for(&mut theirs_rx, "the peer's write", |seen| match seen {
        Seen::Hold(HoldEvent::Wrote { result, .. }) => Some(result),
        _ => None,
    })
    .await;
    assert_eq!(result, Ok(48 << 20));
    assert_still_connected(&mut ours_rx, Duration::from_millis(100)).await;
    assert_eq!(metrics.conn_budget_exceeded(), 0);
}

/// Accepts [`HOLD`] streams and reads each as data arrives.
struct Sink;

impl NetworkBehaviour for Sink {
    type ConnectionHandler = SinkHandler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(SinkHandler::default())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(SinkHandler::default())
    }

    fn on_swarm_event(&mut self, _: FromSwarm) {}

    fn on_connection_handler_event(&mut self, _: PeerId, _: ConnectionId, event: Infallible) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Infallible, Infallible>> {
        Poll::Pending
    }
}

#[derive(Default)]
struct SinkHandler {
    reads: FuturesUnordered<BoxFuture<'static, ()>>,
}

impl ConnectionHandler for SinkHandler {
    type FromBehaviour = Infallible;
    type ToBehaviour = Infallible;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(ReadyUpgrade::new(HOLD), ())
    }

    fn connection_keep_alive(&self) -> bool {
        true
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, (), Infallible>> {
        while let Poll::Ready(Some(())) = self.reads.poll_next_unpin(cx) {}
        Poll::Pending
    }

    fn on_behaviour_event(&mut self, event: Infallible) {
        match event {}
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<Self::InboundProtocol, Self::OutboundProtocol>,
    ) {
        if let ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
            protocol: mut stream,
            ..
        }) = event
        {
            self.reads.push(
                async move {
                    let mut chunk = vec![0; 64 << 10];
                    while matches!(stream.read(&mut chunk).await, Ok(n) if n > 0) {}
                    // Keep the stream open once the peer's side ends.
                    futures::future::pending::<()>().await;
                    drop(stream);
                }
                .boxed(),
            );
        }
    }
}
