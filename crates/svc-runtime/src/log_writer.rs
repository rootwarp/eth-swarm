//! Log lines go to a bounded queue; one OS thread of their own writes them out.
//!
//! A caller never blocks on the sink (stderr), so a stalled reader cannot stop a tokio worker,
//! and with it the timers, the signal handlers and the drain deadline.
//!
//! - **Bound**: [`LogQueueBounds`], by bytes and by lines, the line being written included. The
//!   defaults, 4 MiB and 16 384 lines, hold minutes of INFO logging at a few hundred bytes a
//!   line, and keep the queue under about 5 MiB with each entry's own overhead.
//! - **When full**: the new line is dropped and counted in the `dropped` counter (a line the
//!   sink refuses is counted too). The newest go, not the oldest: the queued lines are the ones
//!   from before the stall, the likeliest to explain it, and a drop then costs the caller one
//!   counter increment and leaves the queue alone. Consecutive drops leave one marker in their
//!   place, and once the sink takes lines again the writer writes a summary line there
//!   (`"dropped":N`), so a reader sees where and how many lines are missing. A count the sink
//!   refused to take (a refused line or summary) is carried into the next summary, tried again
//!   once the queue is empty, and a line the sink cut short is ended before the next write.
//! - **Shutdown**: [`LogWriter::flush`] waits for the queue to empty, up to a deadline; a stuck
//!   sink holds no one past it. [`LogWriter::flush_unless_stalled`] waits once per stall.
//! - **A panicking sink** ends the writer thread: the lines it held (queued, and the one being
//!   written) are discarded and counted as dropped, every later line is refused and counted, and
//!   flushes fail at once.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::ThreadId;
use std::time::Duration;

use prometheus_client::metrics::counter::Counter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::MakeWriter;

/// Default [`LogQueueBounds::max_bytes`]: 4 MiB.
pub const DEFAULT_LOG_QUEUE_BYTES: usize = 4 << 20;

/// Default [`LogQueueBounds::max_lines`].
pub const DEFAULT_LOG_QUEUE_LINES: usize = 16_384;

/// How much the queue holds, the line being written included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogQueueBounds {
    /// Bytes of queued lines. A line longer than this is always dropped.
    pub max_bytes: usize,
    /// Queued lines.
    pub max_lines: usize,
}

impl Default for LogQueueBounds {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_LOG_QUEUE_BYTES,
            max_lines: DEFAULT_LOG_QUEUE_LINES,
        }
    }
}

/// The producer side of the queue; clones share it.
#[derive(Clone, Debug)]
pub struct LogWriter {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    bounds: LogQueueBounds,
    dropped: Counter,
    queue: Mutex<Queue>,
    /// Signalled when a line is queued.
    queued: Condvar,
    /// Signalled when the queue is empty and nothing is being written, or the thread ended.
    idle: Condvar,
    /// The writer thread, once it runs.
    thread: OnceLock<ThreadId>,
    /// Entries the writer thread has finished with, written or not: its progress.
    written: AtomicU64,
    /// [`Self::written`] when a [`LogWriter::flush_unless_stalled`] last timed out, or
    /// [`NOT_STALLED`].
    stalled_at: AtomicU64,
}

/// [`Shared::stalled_at`] when the last such flush did not time out.
const NOT_STALLED: u64 = u64::MAX;

#[derive(Debug, Default)]
struct Queue {
    entries: VecDeque<Entry>,
    /// Bytes and lines of the queued lines and of the one being written.
    bytes: usize,
    lines: usize,
    /// The writer thread holds an entry it has not finished writing.
    writing: bool,
    /// The writer thread has ended (its sink panicked): the queue is empty, and nothing will
    /// write it again.
    dead: bool,
}

#[derive(Debug)]
enum Entry {
    Line(Vec<u8>),
    /// This many lines were dropped here. Consecutive drops share one marker, and a marker is
    /// always followed by a line or nothing, so markers are at most one more than the lines and
    /// take no part in the bound.
    Dropped(u64),
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queue> {
        // The critical sections cannot panic; a poisoned queue would still be consistent.
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl LogWriter {
    /// Starts the writer thread over `sink`, counting dropped lines in `dropped`. The thread
    /// lives for the rest of the process.
    pub fn spawn<W>(sink: W, bounds: LogQueueBounds, dropped: Counter) -> io::Result<Self>
    where
        W: io::Write + Send + 'static,
    {
        let shared = Arc::new(Shared {
            bounds,
            dropped,
            queue: Mutex::new(Queue::default()),
            queued: Condvar::new(),
            idle: Condvar::new(),
            thread: OnceLock::new(),
            written: AtomicU64::new(0),
            stalled_at: AtomicU64::new(NOT_STALLED),
        });
        let thread = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("log-writer".into())
            .spawn(move || write_out(&thread, sink))?;
        Ok(Self { shared })
    }

    /// Queues `line`; `false` if it was dropped (counted): the queue is full, or the writer
    /// thread has ended. Never waits for the sink.
    pub fn push(&self, line: &[u8]) -> bool {
        let bounds = self.shared.bounds;
        let mut queue = self.shared.lock();
        if queue.dead {
            drop(queue);
            self.shared.dropped.inc();
            return false;
        }
        let fits = queue.lines < bounds.max_lines
            && queue
                .bytes
                .checked_add(line.len())
                .is_some_and(|total| total <= bounds.max_bytes);
        // A new entry, a line or a marker, wakes the writer; an existing marker's count does not
        // need to.
        let woken = if fits {
            queue.entries.push_back(Entry::Line(line.to_vec()));
            queue.bytes += line.len();
            queue.lines += 1;
            true
        } else if let Some(Entry::Dropped(n)) = queue.entries.back_mut() {
            *n += 1;
            false
        } else {
            queue.entries.push_back(Entry::Dropped(1));
            true
        };
        drop(queue);
        if woken {
            self.shared.queued.notify_one();
        }
        if !fits {
            self.shared.dropped.inc();
        }
        fits
    }

    /// Waits until every queued line is written, up to `timeout`. `false` if the deadline
    /// passed first (the sink is stalled; the lines still queued are left to the thread), or
    /// the writer thread has ended, at once.
    pub fn flush(&self, timeout: Duration) -> bool {
        let queue = self.shared.lock();
        let (queue, waited) = self
            .shared
            .idle
            .wait_timeout_while(queue, timeout, |q| {
                !q.dead && (q.writing || !q.entries.is_empty())
            })
            .unwrap_or_else(PoisonError::into_inner);
        !waited.timed_out() && !queue.dead
    }

    /// [`Self::flush`], but `false` at once where waiting cannot help: on the writer thread
    /// itself, and when an earlier call timed out and the writer has finished nothing since
    /// (one stalled sink costs one wait, not one per caller in turn).
    pub fn flush_unless_stalled(&self, timeout: Duration) -> bool {
        let shared = &*self.shared;
        if shared.thread.get() == Some(&std::thread::current().id()) {
            return false;
        }
        if shared.stalled_at.load(Ordering::SeqCst) == shared.written.load(Ordering::SeqCst) {
            return false;
        }
        // The progress before the wait: what the writer finishes after it, even in the moment
        // between the timeout and this store, is progress the next caller must not take for a
        // stall.
        let before = shared.written.load(Ordering::SeqCst);
        let flushed = self.flush(timeout);
        let stalled_at = if flushed { NOT_STALLED } else { before };
        shared.stalled_at.store(stalled_at, Ordering::SeqCst);
        flushed
    }
}

/// The writer thread: writes each entry, in order, outside the lock.
///
/// The critical sections cannot panic, so the lock is never poisoned; only the sink can panic,
/// outside it. If it does, the thread ends: [`Alive`] discards and counts the lines it held and
/// marks the queue dead, so a flush returns `false` at once instead of waiting out its timeout,
/// and every line pushed after that is refused and counted. Callers still never block.
fn write_out(shared: &Shared, sink: impl io::Write) {
    let _ = shared.thread.set(std::thread::current().id());
    let _alive = Alive(shared);
    let mut out = Out {
        sink,
        unreported: 0,
        cut: false,
    };
    // Whether the summary of a loss has had its one try since the queue last emptied.
    let mut retried = false;
    let mut queue = shared.lock();
    loop {
        let Some(entry) = queue.entries.pop_front() else {
            // A loss with nothing queued after it: one more try to report it before idling.
            if out.unreported > 0 && !retried {
                retried = true;
                queue.writing = true;
                drop(queue);
                out.report();
                shared.written.fetch_add(1, Ordering::SeqCst);
                queue = shared.lock();
                continue;
            }
            queue.writing = false;
            shared.idle.notify_all();
            queue = shared
                .queued
                .wait_while(queue, |q| q.entries.is_empty())
                .unwrap_or_else(PoisonError::into_inner);
            continue;
        };
        retried = false;
        queue.writing = true;
        drop(queue);
        let (bytes, lines) = match entry {
            Entry::Line(line) => {
                if !out.line(&line) {
                    shared.dropped.inc();
                }
                (line.len(), 1)
            }
            Entry::Dropped(n) => {
                out.unreported += n;
                out.report();
                (0, 0)
            }
        };
        shared.written.fetch_add(1, Ordering::SeqCst);
        queue = shared.lock();
        queue.bytes = queue.bytes.saturating_sub(bytes);
        queue.lines = queue.lines.saturating_sub(lines);
    }
}

/// Marks the queue dead when the writer thread ends (it only ends by a panic of its sink), and
/// counts the lines lost with it: the queued ones and the one being written, which `lines`
/// still holds. The lines a marker stands for, and those the sink refused, were counted
/// already.
struct Alive<'a>(&'a Shared);

impl Drop for Alive<'_> {
    fn drop(&mut self) {
        let mut queue = self.0.lock();
        let lost = std::mem::take(&mut queue.lines);
        queue.entries.clear();
        queue.bytes = 0;
        queue.dead = true;
        queue.writing = false;
        drop(queue);
        self.0.dropped.inc_by(lost as u64);
        self.0.idle.notify_all();
    }
}

/// The sink, and what the writer thread owes it.
///
/// Lines lost since the last summary written are carried in `unreported`: the dropped lines
/// of a marker, a line the sink refused, and a summary the sink refused. A marker, the next
/// line, or the queue going idle first writes a summary of them; one the sink refuses again
/// keeps the count for the next try. A write the sink cut short (non-blocking stderr, full)
/// is ended with a newline before anything else is written, so nothing is glued onto it.
struct Out<W> {
    sink: W,
    unreported: u64,
    /// The last write stopped partway through its line.
    cut: bool,
}

impl<W: io::Write> Out<W> {
    /// Writes `line`; `false` (and counted for the next summary) if the sink refused it.
    fn line(&mut self, line: &[u8]) -> bool {
        self.report();
        if self.end_cut() && self.write(line).is_ok() {
            return true;
        }
        self.unreported += 1;
        false
    }

    /// Writes a summary of the unreported lost lines, if any; the count is kept if the sink
    /// refuses it.
    fn report(&mut self) {
        if self.unreported > 0
            && self.end_cut()
            && self.write(summary(self.unreported).as_bytes()).is_ok()
        {
            self.unreported = 0;
        }
    }

    /// Ends a line the sink cut short; `false` if it refuses that too.
    fn end_cut(&mut self) -> bool {
        !self.cut || self.write(b"\n").is_ok()
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut done = 0;
        while done < bytes.len() {
            match self.sink.write(&bytes[done..]) {
                Ok(0) => return self.stopped(done, io::ErrorKind::WriteZero.into()),
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return self.stopped(done, e),
            }
        }
        self.cut = false;
        self.sink.flush()
    }

    /// A write that stopped after `done` bytes.
    fn stopped(&mut self, done: usize, error: io::Error) -> io::Result<()> {
        if done > 0 {
            self.cut = true;
        }
        Err(error)
    }
}

/// The line written where `dropped` lines were lost, in the subscriber's JSON shape.
fn summary(dropped: u64) -> String {
    format!(
        "{{\"timestamp\":\"{}\",\"level\":\"WARN\",\"fields\":{{\"message\":\
         \"log lines dropped: the log queue was full or the sink refused them\",\
         \"dropped\":{dropped}}},\
         \"target\":\"{}\"}}\n",
        timestamp(),
        module_path!()
    )
}

/// Now, as the subscriber writes its `timestamp`: RFC 3339 digits and separators only, so
/// nothing in it needs escaping in JSON.
pub(crate) fn timestamp() -> String {
    let mut timestamp = String::new();
    let _ = SystemTime.format_time(&mut Writer::new(&mut timestamp));
    timestamp
}

/// Appends `value` to `out` as a JSON string: quoted, with `"`, `\` and control characters
/// escaped.
pub(crate) fn push_json_str(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// One event's writer: each [`io::Write::write`] queues what it is given as one line. The fmt
/// layer formats an event into one buffer and writes it in one call, so an event is one entry.
#[derive(Debug)]
pub struct LogLine<'a>(&'a LogWriter);

impl io::Write for LogLine<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.push(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = LogLine<'a>;

    fn make_writer(&'a self) -> LogLine<'a> {
        LogLine(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// What a [`Gate`] holds: open or not, and what it was given.
    #[derive(Default)]
    struct GateState {
        open: bool,
        written: Vec<u8>,
    }

    /// A sink that blocks every write until opened, then keeps what it is given.
    #[derive(Clone, Default)]
    struct Gate {
        state: Arc<(Mutex<GateState>, Condvar)>,
    }

    impl Gate {
        fn open(&self) {
            self.state.0.lock().unwrap().open = true;
            self.state.1.notify_all();
        }

        fn text(&self) -> String {
            String::from_utf8(self.state.0.lock().unwrap().written.clone()).unwrap()
        }
    }

    impl io::Write for Gate {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let (lock, opened) = &*self.state;
            let mut state = opened
                .wait_while(lock.lock().unwrap(), |s| !s.open)
                .unwrap();
            state.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn bounds(max_bytes: usize, max_lines: usize) -> LogQueueBounds {
        LogQueueBounds {
            max_bytes,
            max_lines,
        }
    }

    fn line(n: usize) -> Vec<u8> {
        format!("{{\"n\":{n}}}\n").into_bytes()
    }

    #[test]
    fn a_full_queue_drops_and_counts_without_blocking() {
        let gate = Gate::default();
        let dropped = Counter::default();
        let writer = LogWriter::spawn(gate.clone(), bounds(1 << 20, 4), dropped.clone()).unwrap();
        let started = Instant::now();
        let kept: Vec<bool> = (0..10).map(|n| writer.push(&line(n))).collect();
        assert!(started.elapsed() < Duration::from_secs(1), "a push waited");
        // The line the writer is stuck on still counts: four fit, six are dropped.
        assert_eq!(kept, [[true; 4].as_slice(), &[false; 6]].concat());
        assert_eq!(dropped.get(), 6);
        gate.open();
        assert!(writer.flush(Duration::from_secs(10)));
    }

    #[test]
    fn the_byte_bound_holds_too() {
        let gate = Gate::default();
        let dropped = Counter::default();
        let writer = LogWriter::spawn(gate.clone(), bounds(30, 1000), dropped.clone()).unwrap();
        assert!(writer.push(&[b'a'; 20]));
        assert!(!writer.push(&[b'b'; 11]), "20 + 11 > 30");
        assert!(writer.push(&[b'c'; 10]), "20 + 10 fits");
        assert!(!writer.push(&[b'd'; 31]), "longer than the bound");
        assert_eq!(dropped.get(), 2);
        gate.open();
        assert!(writer.flush(Duration::from_secs(10)));
        assert!(writer.push(&[b'e'; 30]), "space is freed once written");
    }

    #[test]
    fn flush_writes_every_line_in_order() {
        let gate = Gate::default();
        gate.open();
        let writer =
            LogWriter::spawn(gate.clone(), LogQueueBounds::default(), Counter::default()).unwrap();
        let expected: String = (0..100)
            .map(|n| {
                assert!(writer.push(&line(n)));
                String::from_utf8(line(n)).unwrap()
            })
            .collect();
        assert!(writer.flush(Duration::from_secs(10)));
        assert_eq!(gate.text(), expected);
    }

    #[test]
    fn the_flush_deadline_holds_when_the_sink_blocks() {
        let gate = Gate::default();
        let writer =
            LogWriter::spawn(gate.clone(), LogQueueBounds::default(), Counter::default()).unwrap();
        assert!(writer.push(&line(0)));
        let started = Instant::now();
        assert!(!writer.flush(Duration::from_millis(200)));
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(200), "{took:?}");
        assert!(took < Duration::from_secs(2), "{took:?}");
        gate.open();
        assert!(writer.flush(Duration::from_secs(10)));
        assert_eq!(gate.text(), String::from_utf8(line(0)).unwrap());
    }

    #[test]
    fn a_summary_line_marks_the_gap_after_recovery() {
        let gate = Gate::default();
        let dropped = Counter::default();
        let writer = LogWriter::spawn(gate.clone(), bounds(1 << 20, 2), dropped.clone()).unwrap();
        for n in 0..7 {
            writer.push(&line(n));
        }
        assert_eq!(dropped.get(), 5);
        gate.open();
        assert!(writer.flush(Duration::from_secs(10)));
        assert!(writer.push(&line(99)));
        assert!(writer.flush(Duration::from_secs(10)));
        let text = gate.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert_eq!(
            (lines[0], lines[1], lines[3]),
            (r#"{"n":0}"#, r#"{"n":1}"#, r#"{"n":99}"#)
        );
        let summary = lines[2];
        assert!(summary.starts_with(r#"{"timestamp":""#), "{summary}");
        assert!(summary.contains(r#""level":"WARN""#), "{summary}");
        assert!(summary.contains(r#""dropped":5"#), "{summary}");
        assert!(summary.ends_with('}'), "{summary}");
        // Back-to-back drops share one summary.
        assert_eq!(text.matches(r#""dropped":"#).count(), 1);
    }

    #[test]
    fn a_drop_into_an_idle_queue_is_reported_at_once() {
        let gate = Gate::default();
        gate.open();
        let dropped = Counter::default();
        let writer = LogWriter::spawn(gate.clone(), bounds(16, 1000), dropped.clone()).unwrap();
        // One line written and flushed: the writer thread is now waiting for the next.
        assert!(writer.push(b"first\n"));
        assert!(writer.flush(Duration::from_secs(10)));
        assert!(!writer.push(&[b'x'; 17]), "longer than the bound");
        assert!(
            writer.flush(Duration::from_secs(2)),
            "the writer woke for the marker"
        );
        let text = gate.text();
        assert_eq!(text.lines().count(), 2, "{text}");
        assert_eq!(text.matches(r#""dropped":1"#).count(), 1, "{text}");
        assert_eq!(dropped.get(), 1);
    }

    /// What a [`Flaky`] sink does, once, to the first write holding a pattern.
    #[derive(Clone, Copy)]
    enum Fault {
        /// Takes none of it.
        Refuse,
        /// Takes this many bytes, then refuses the next write (non-blocking stderr, full).
        Partial(usize),
    }

    /// Faults the first write of each listed pattern, then takes everything.
    #[derive(Clone)]
    struct Flaky {
        out: Arc<Mutex<Vec<u8>>>,
        faults: Arc<Mutex<Vec<(&'static str, Fault)>>>,
        refuse_next: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Flaky {
        fn new(faults: Vec<(&'static str, Fault)>) -> Self {
            Self {
                out: Arc::default(),
                faults: Arc::new(Mutex::new(faults)),
                refuse_next: Arc::default(),
            }
        }

        fn text(&self) -> String {
            String::from_utf8(self.out.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for Flaky {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            use std::sync::atomic::Ordering;
            if self.refuse_next.swap(false, Ordering::SeqCst) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let text = String::from_utf8_lossy(buf);
            let mut faults = self.faults.lock().unwrap();
            let fault = faults
                .iter()
                .position(|(p, _)| text.contains(p))
                .map(|i| faults.remove(i).1);
            let taken = match fault {
                None => buf.len(),
                Some(Fault::Refuse) => return Err(io::ErrorKind::WouldBlock.into()),
                Some(Fault::Partial(n)) => {
                    self.refuse_next.store(true, Ordering::SeqCst);
                    n
                }
            };
            self.out.lock().unwrap().extend_from_slice(&buf[..taken]);
            Ok(taken)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Pushes lines `ns` one at a time, each written out before the next.
    fn push_each(writer: &LogWriter, ns: impl IntoIterator<Item = usize>) {
        for n in ns {
            assert!(writer.push(&line(n)));
            assert!(writer.flush(Duration::from_secs(10)));
        }
    }

    #[test]
    fn lost_lines_and_a_lost_summary_are_reported_by_the_next_summary() {
        let sink = Flaky::new(vec![
            (r#""n":1"#, Fault::Refuse),
            (r#""dropped""#, Fault::Refuse),
        ]);
        let dropped = Counter::default();
        let writer =
            LogWriter::spawn(sink.clone(), LogQueueBounds::default(), dropped.clone()).unwrap();
        push_each(&writer, 0..4);
        let text = sink.text();
        let lines: Vec<&str> = text.lines().collect();
        // Line 1 is refused, and so is the summary tried once the queue is empty; the one
        // before line 2 reports the loss.
        assert_eq!(lines.len(), 4, "{text}");
        assert_eq!((lines[0], lines[2]), (r#"{"n":0}"#, r#"{"n":2}"#));
        assert!(lines[1].contains(r#""dropped":1"#), "{text}");
        assert_eq!(lines[3], r#"{"n":3}"#);
        assert_eq!(dropped.get(), 1);
    }

    #[test]
    fn a_refused_last_line_is_reported_before_the_queue_goes_idle() {
        let sink = Flaky::new(vec![(r#""n":1"#, Fault::Refuse)]);
        let writer =
            LogWriter::spawn(sink.clone(), LogQueueBounds::default(), Counter::default()).unwrap();
        push_each(&writer, 0..2);
        let text = sink.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert_eq!(lines[0], r#"{"n":0}"#);
        assert!(lines[1].contains(r#""dropped":1"#), "{text}");
    }

    #[test]
    fn a_line_cut_short_is_ended_before_the_summary() {
        let sink = Flaky::new(vec![(r#""n":1"#, Fault::Partial(3))]);
        let dropped = Counter::default();
        let writer =
            LogWriter::spawn(sink.clone(), LogQueueBounds::default(), dropped.clone()).unwrap();
        push_each(&writer, 0..3);
        let text = sink.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert_eq!((lines[0], lines[1]), (r#"{"n":0}"#, r#"{"n"#));
        assert!(lines[2].starts_with(r#"{"timestamp":""#), "{text}");
        assert!(lines[2].contains(r#""dropped":1"#), "{text}");
        assert_eq!(lines[3], r#"{"n":2}"#);
        assert_eq!(dropped.get(), 1);
    }

    #[test]
    fn a_summary_cut_short_keeps_its_count() {
        let sink = Flaky::new(vec![
            (r#""n":1"#, Fault::Refuse),
            (r#""dropped""#, Fault::Partial(5)),
        ]);
        let writer =
            LogWriter::spawn(sink.clone(), LogQueueBounds::default(), Counter::default()).unwrap();
        push_each(&writer, 0..3);
        let text = sink.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert_eq!((lines[0], lines[1]), (r#"{"n":0}"#, r#"{"tim"#));
        assert!(lines[2].contains(r#""dropped":1"#), "{text}");
        assert_eq!(lines[3], r#"{"n":2}"#);
    }

    #[test]
    fn a_stalled_flush_is_not_waited_for_again() {
        let gate = Gate::default();
        let writer =
            LogWriter::spawn(gate.clone(), LogQueueBounds::default(), Counter::default()).unwrap();
        assert!(writer.push(&line(0)));
        let started = Instant::now();
        assert!(!writer.flush_unless_stalled(Duration::from_millis(200)));
        assert!(started.elapsed() >= Duration::from_millis(200));
        // Nothing written since: the next one does not wait.
        assert!(writer.push(&line(1)));
        let started = Instant::now();
        assert!(!writer.flush_unless_stalled(Duration::from_secs(5)));
        assert!(started.elapsed() < Duration::from_secs(1), "it waited");
        // Once the writer moves again, it waits again.
        gate.open();
        assert!(writer.flush(Duration::from_secs(10)));
        assert!(writer.push(&line(2)));
        assert!(writer.flush_unless_stalled(Duration::from_secs(10)));
        assert_eq!(gate.text().lines().count(), 3);
    }

    #[test]
    fn the_writer_thread_never_waits_on_itself() {
        type Slot = Arc<std::sync::OnceLock<LogWriter>>;
        /// A sink whose first write asks its own writer to flush, and records how that went.
        struct Reentrant(Slot, Arc<Mutex<Option<(bool, Duration)>>>);
        impl io::Write for Reentrant {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let mut seen = self.1.lock().unwrap();
                if seen.is_none() {
                    let started = Instant::now();
                    let flushed = self
                        .0
                        .get()
                        .unwrap()
                        .flush_unless_stalled(Duration::from_secs(5));
                    *seen = Some((flushed, started.elapsed()));
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let slot = Slot::default();
        let seen = Arc::default();
        let sink = Reentrant(Arc::clone(&slot), Arc::clone(&seen));
        let writer = LogWriter::spawn(sink, LogQueueBounds::default(), Counter::default()).unwrap();
        slot.set(writer.clone()).unwrap();
        assert!(writer.push(&line(0)));
        assert!(writer.flush(Duration::from_secs(10)));
        let (flushed, took) = seen.lock().unwrap().expect("written");
        assert!(!flushed);
        assert!(took < Duration::from_secs(1), "{took:?}");
    }

    #[test]
    fn a_dead_writer_thread_fails_flush_at_once() {
        struct Panics;
        impl io::Write for Panics {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("a sink that panics (expected by this test)");
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let dropped = Counter::default();
        let writer = LogWriter::spawn(Panics, bounds(1 << 20, 4), dropped.clone()).unwrap();
        assert!(writer.push(&line(0)));
        let started = Instant::now();
        assert!(!writer.flush(Duration::from_secs(10)), "nothing writes");
        assert!(started.elapsed() < Duration::from_secs(5), "it waited");
        // The line it was writing is lost, and counted.
        assert_eq!(dropped.get(), 1);
        // Pushes still return at once, and every one is refused and counted.
        for n in 1..10 {
            assert!(!writer.push(&line(n)), "line {n} was queued");
        }
        assert_eq!(dropped.get(), 10);
        assert!(!writer.flush_unless_stalled(Duration::from_secs(10)));
        assert!(started.elapsed() < Duration::from_secs(5), "it waited");
    }

    #[test]
    fn the_lines_queued_when_the_writer_thread_dies_are_counted() {
        /// Blocks its first write until released, then panics.
        struct PanicsWhenReleased(std::sync::mpsc::Receiver<()>);
        impl io::Write for PanicsWhenReleased {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                let _ = self.0.recv();
                panic!("a sink that panics (expected by this test)");
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (release, released) = std::sync::mpsc::channel();
        let dropped = Counter::default();
        let writer = LogWriter::spawn(
            PanicsWhenReleased(released),
            bounds(1 << 20, 8),
            dropped.clone(),
        )
        .unwrap();
        // Eight lines held (the one being written included), and one over the bound.
        for n in 0..8 {
            assert!(writer.push(&line(n)));
        }
        assert!(!writer.push(&line(8)), "the queue holds 8");
        assert_eq!(dropped.get(), 1);
        release.send(()).unwrap();
        assert!(!writer.flush(Duration::from_secs(10)), "nothing writes");
        // The eight lines it held are lost with it, and counted.
        assert_eq!(dropped.get(), 9);
        assert!(!writer.push(&line(9)));
        assert_eq!(dropped.get(), 10);
    }

    #[test]
    fn progress_during_a_timed_out_flush_is_not_taken_for_a_stall() {
        /// Each write takes one permit; it waits for one, or for the sender to go.
        struct Turnstile(std::sync::mpsc::Receiver<()>);
        impl io::Write for Turnstile {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let _ = self.0.recv();
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (permits, turnstile) = std::sync::mpsc::channel();
        let writer = LogWriter::spawn(
            Turnstile(turnstile),
            LogQueueBounds::default(),
            Counter::default(),
        )
        .unwrap();
        assert!(writer.push(&line(0)));
        assert!(writer.push(&line(1)));
        // Line 0 gets through while the flush waits; line 1 does not.
        let permit = permits.clone();
        let admit = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            permit.send(()).unwrap();
        });
        assert!(!writer.flush_unless_stalled(Duration::from_millis(400)));
        admit.join().unwrap();
        // The writer moved during that wait: the next caller waits again.
        let started = Instant::now();
        assert!(!writer.flush_unless_stalled(Duration::from_millis(200)));
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "it took progress for a stall"
        );
        drop(permits);
        assert!(writer.flush(Duration::from_secs(10)));
    }

    #[test]
    fn writes_the_sink_refuses_count_as_dropped() {
        struct Broken;
        impl io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let dropped = Counter::default();
        let writer = LogWriter::spawn(Broken, LogQueueBounds::default(), dropped.clone()).unwrap();
        for n in 0..3 {
            assert!(writer.push(&line(n)));
        }
        assert!(writer.flush(Duration::from_secs(10)));
        assert_eq!(dropped.get(), 3);
    }

    #[test]
    fn many_threads_logging_into_a_blocked_sink_never_block() {
        const THREADS: usize = 16;
        const LINES: usize = 2000;
        let gate = Gate::default();
        let dropped = Counter::default();
        let max_lines = 1000;
        let writer =
            LogWriter::spawn(gate.clone(), bounds(1 << 20, max_lines), dropped.clone()).unwrap();
        let (done, finished) = std::sync::mpsc::channel();
        for t in 0..THREADS {
            let writer = writer.clone();
            let done = done.clone();
            std::thread::spawn(move || {
                let kept = (0..LINES)
                    .filter(|n| writer.push(&line(t * LINES + n)))
                    .count();
                let _ = done.send(kept);
            });
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut kept = 0;
        for _ in 0..THREADS {
            let left = deadline.saturating_duration_since(Instant::now());
            kept += finished
                .recv_timeout(left)
                .expect("every logging thread finishes with the sink blocked");
        }
        assert_eq!(kept, max_lines);
        assert_eq!(dropped.get(), (THREADS * LINES - max_lines) as u64);
        gate.open();
        assert!(writer.flush(Duration::from_secs(30)));
        let text = gate.text();
        assert_eq!(
            text.lines().count(),
            max_lines + 1,
            "the kept lines and one summary"
        );
    }

    #[test]
    fn it_is_a_tracing_writer() {
        let gate = Gate::default();
        gate.open();
        let writer =
            LogWriter::spawn(gate.clone(), LogQueueBounds::default(), Counter::default()).unwrap();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || tracing::info!("through the queue"));
        assert!(writer.flush(Duration::from_secs(10)));
        assert!(gate.text().contains("through the queue"), "{}", gate.text());
    }
}
