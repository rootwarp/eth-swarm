//! The reference node's head: the roots of the blocks it imports, announced to the [`RefView`]
//! ahead of their columns ([`follow_head`]).
//!
//! The reference streams `/eth/v1/events?topics=block` (beacon-APIs eventstream): one `block`
//! event, `{"slot", "block", "execution_optimistic"}`, per block it imports. [`follow_head`]
//! reads each event's root and announces it ([`RefView::announce`]), then looks it up in the
//! announced roots' own places ([`RefView::lookup_as_announced`]). In Gloas the block is gossiped
//! before its payload's columns, so a real root is usually cached, or its lookup in flight,
//! before its first column arrives, and that column never waits for a first-ask turn
//! (`probe::root_wait`). An announcement is only a hint: the root is still established by the
//! header and the block, decoded and hashed, never by the event.
//!
//! Bounds:
//! - a line or an event over [`MAX_EVENT_BYTES`] ends the stream, and so does an event that
//!   is not a `block` event of the beacon API (bad JSON, a root that is not 32 bytes, a slot
//!   that is not a decimal `u64`); events of other names and comments are skipped;
//! - a stream that sends no bytes for [`HeadFollow::idle_timeout`] ends (a keep-alive comment
//!   counts);
//! - after a stream ends or fails to open, it is opened again after a backoff:
//!   [`HeadFollow::backoff`] (at least [`MIN_BACKOFF`]), doubled after each failure in a row,
//!   up to [`HeadFollow::max_backoff`]. A stream that announced a root, or opened and went
//!   quiet, starts again from [`HeadFollow::backoff`];
//! - at most `max_announced_in_flight` announced roots are looked up at once
//!   ([`super::RefLimits`]); a root announced past that stays a hint, which the first column of
//!   the root uses, and at most `max_announced` hints are kept, the oldest forgotten first. A
//!   hint lives until a lookup resolves its root or the reference refuses it, and after a
//!   lookup without an answer for a while more (`probe::ref_view`).
//!
//! While the stream is down, nothing is announced, and every root takes the root wait as it did
//! without the stream. Errors name the API path only, never the base URL or a value from the
//! stream.

use super::{ApiError, BlockApi, RefView, ReferenceApi, Root};
use consensus_types::EthSpec;
use serde::Deserialize;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

/// The event stream's API path.
pub const EVENTS_PATH: &str = "/eth/v1/events";

/// The largest line, and the largest event's data, the parser holds: 4 KiB \[est\]. A `block`
/// event is about 150 bytes; anything this large is not one, and the stream ends.
pub const MAX_EVENT_BYTES: usize = 4 << 10;

/// The shortest wait before a stream is opened again, whatever [`HeadFollow`] says, so a
/// reference that refuses at once is not asked in a loop.
pub const MIN_BACKOFF: Duration = Duration::from_millis(1);

/// The name of the event that announces a root.
pub(super) const BLOCK_EVENT: &str = "block";

/// A stream of the roots the reference node imports, opened again after it ends.
pub trait HeadSource: Send + Sync {
    /// One open stream.
    type Stream: HeadStream + Send;

    /// Opens a stream.
    fn open(&self) -> impl Future<Output = Result<Self::Stream, ApiError>> + Send;
}

/// One open stream of [`HeadSource`].
pub trait HeadStream {
    /// The next root the reference announces, or `None` for bytes that announce none (a
    /// keep-alive comment, another event). An error ends the stream, its end included.
    fn next_root(&mut self) -> impl Future<Output = Result<Option<Root>, ApiError>> + Send;
}

/// How [`follow_head`] keeps its stream (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadFollow {
    /// A stream that announces nothing for this long ends, and is opened again.
    pub idle_timeout: Duration,
    /// The wait before a stream is opened again, at least [`MIN_BACKOFF`].
    pub backoff: Duration,
    /// The longest wait, at least `backoff`.
    pub max_backoff: Duration,
}

impl Default for HeadFollow {
    /// A 60 s idle timeout (five mainnet slots without a block), and 1 s to 30 s of backoff
    /// \[est\].
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }
}

/// A line or an event over [`MAX_EVENT_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SseError {
    /// A line.
    #[error("an SSE line is over {MAX_EVENT_BYTES} bytes")]
    Line,
    /// An event's data.
    #[error("an SSE event is over {MAX_EVENT_BYTES} bytes")]
    Event,
}

/// One dispatched event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SseEvent {
    /// The `event:` name (`message` when none was given).
    pub(super) name: String,
    /// The `data:` lines joined with `\n`.
    pub(super) data: String,
}

/// An incremental `text/event-stream` parser (WHATWG HTML, "Server-sent events"): lines end
/// in CRLF, LF or CR, `event:` names the event, `data:` lines are joined with `\n`, a line
/// starting with `:` is a comment (a keep-alive), other fields are skipped, and a blank line
/// dispatches the event if it has data.
#[derive(Debug, Default)]
pub(super) struct SseParser {
    line: Vec<u8>,
    after_cr: bool,
    name: String,
    data: String,
}

impl SseParser {
    /// Parses `chunk`, returning every event it completes.
    #[cfg(test)]
    pub(super) fn feed(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, SseError> {
        let mut events = Vec::new();
        self.feed_into(chunk, &mut events)?;
        Ok(events)
    }

    /// Parses `chunk` into `events`; on an error, the events completed before it are there.
    pub(super) fn feed_into(
        &mut self,
        chunk: &[u8],
        events: &mut Vec<SseEvent>,
    ) -> Result<(), SseError> {
        for &b in chunk {
            let after_cr = std::mem::replace(&mut self.after_cr, b == b'\r');
            match b {
                // The LF of a CRLF whose CR ended the line.
                b'\n' if after_cr => {}
                b'\n' | b'\r' => {
                    let line = std::mem::take(&mut self.line);
                    events.extend(self.line_done(&line)?);
                }
                _ if self.line.len() >= MAX_EVENT_BYTES => return Err(SseError::Line),
                _ => self.line.push(b),
            }
        }
        Ok(())
    }

    fn line_done(&mut self, line: &[u8]) -> Result<Option<SseEvent>, SseError> {
        if line.is_empty() {
            let name = std::mem::take(&mut self.name);
            let mut data = std::mem::take(&mut self.data);
            if data.is_empty() {
                return Ok(None);
            }
            data.pop(); // the last `\n`
            let name = if name.is_empty() {
                "message".to_owned()
            } else {
                name
            };
            return Ok(Some(SseEvent { name, data }));
        }
        if line[0] == b':' {
            return Ok(None);
        }
        let line = String::from_utf8_lossy(line);
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (&*line, ""),
        };
        match field {
            "event" => value.clone_into(&mut self.name),
            "data" => {
                if self.data.len() + value.len() >= MAX_EVENT_BYTES {
                    return Err(SseError::Event);
                }
                self.data.push_str(value);
                self.data.push('\n');
            }
            _ => {}
        }
        Ok(None)
    }
}

#[derive(Deserialize)]
struct BlockEvent {
    slot: String,
    block: String,
}

/// The root a `block` event's data announces: JSON with a decimal `slot` and a `0x` root of 32
/// bytes. The error names the path and the fault, never a value.
pub(super) fn block_event_root(data: &str) -> Result<Root, ApiError> {
    let event: BlockEvent = serde_json::from_str(data).map_err(|e| {
        ApiError(format!(
            "{EVENTS_PATH}: block event: json: {:?} error at line {} column {}",
            e.classify(),
            e.line(),
            e.column()
        ))
    })?;
    super::beacon_api::decimal(EVENTS_PATH, &event.slot)?;
    super::beacon_api::root(EVENTS_PATH, &event.block)
}

/// Follows `source` until dropped: announces each root to `refs` and looks it up there, in the
/// announced places, opening the stream again after the backoff whenever it ends (see the
/// module docs).
pub async fn follow_head<H, A, E>(source: H, refs: Arc<RefView<A, E>>, config: HeadFollow)
where
    H: HeadSource,
    A: ReferenceApi + BlockApi + 'static,
    E: EthSpec,
{
    let backoff = config.backoff.max(MIN_BACKOFF);
    let max_backoff = config.max_backoff.max(backoff);
    let idle = config.idle_timeout;
    let mut lookups = JoinSet::new();
    let mut delay = backoff;
    loop {
        // A stream that announced a root, or opened and went quiet, starts the backoff again.
        let mut worked = false;
        let ended = match tokio::time::timeout(idle, source.open()).await {
            Err(_) => Some(ApiError(format!("{EVENTS_PATH}: not open within {idle:?}"))),
            Ok(Err(e)) => Some(e),
            Ok(Ok(mut stream)) => {
                tracing::info!("following the reference's block events");
                loop {
                    // Every chunk, a keep-alive too, starts the idle timeout again.
                    let root = match tokio::time::timeout(idle, stream.next_root()).await {
                        Ok(Ok(Some(root))) => root,
                        Ok(Ok(None)) => continue,
                        Ok(Err(e)) => break Some(e),
                        Err(_) => {
                            worked = true;
                            break None;
                        }
                    };
                    worked = true;
                    // The hint first, so a column that comes before the lookup starts uses it.
                    refs.announce(root);
                    while lookups.try_join_next().is_some() {}
                    // Past the announced places, the root stays a hint for its first column.
                    if lookups.len() < refs.limits().max_announced_in_flight {
                        let refs = Arc::clone(&refs);
                        lookups.spawn(async move {
                            if let Err(e) = refs.lookup_as_announced(root).await {
                                tracing::debug!(error = %e, "announced root not looked up");
                            }
                        });
                    }
                }
            }
        };
        if worked {
            delay = backoff;
        }
        match ended {
            Some(e) => tracing::warn!(
                error = %e,
                retry_in = ?delay,
                "the reference's block events are down: column roots take the root wait"
            ),
            None => tracing::info!(
                idle = ?idle,
                retry_in = ?delay,
                "the reference's block events went quiet: opening them again"
            ),
        }
        tokio::time::sleep(delay).await;
        delay = delay.saturating_mul(2).min(max_backoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(name: &str, data: &str) -> SseEvent {
        SseEvent {
            name: name.into(),
            data: data.into(),
        }
    }

    #[test]
    fn events_comments_and_fields() {
        let mut p = SseParser::default();
        let text = ": keep-alive\n\nevent: block\ndata: {\"slot\":\"1\"}\n\n\
                    data:a\ndata: b\nid: 7\nretry: 100\nfoo\n\nevent: x\n\n";
        let got = p.feed(text.as_bytes()).unwrap();
        // An event without data is not dispatched.
        assert_eq!(
            got,
            vec![ev("block", "{\"slot\":\"1\"}"), ev("message", "a\nb")]
        );
        // The name of an event not dispatched does not leak into the next one.
        assert_eq!(p.feed(b"data: z\n\n").unwrap(), vec![ev("message", "z")]);
    }

    #[test]
    fn every_line_ending_and_split_chunks() {
        let text = b"event: a\r\ndata: 1\r\n\r\nevent: b\rdata: 2\r\revent: c\ndata: 3\n\n";
        let want = vec![ev("a", "1"), ev("b", "2"), ev("c", "3")];
        assert_eq!(SseParser::default().feed(text).unwrap(), want);
        // One byte at a time: a CR at the end of a chunk and its LF in the next are one end.
        let mut bytewise = SseParser::default();
        let mut got = Vec::new();
        for b in text {
            got.extend(bytewise.feed(&[*b]).unwrap());
        }
        assert_eq!(got, want);
    }

    #[test]
    fn oversized_lines_and_events_are_refused() {
        let fits = vec![b'x'; MAX_EVENT_BYTES];
        assert_eq!(SseParser::default().feed(&fits), Ok(vec![]));
        let long = vec![b'x'; MAX_EVENT_BYTES + 1];
        assert_eq!(SseParser::default().feed(&long), Err(SseError::Line));
        // Short lines that add up to an event over the cap.
        let mut p = SseParser::default();
        let line = format!("data: {}\n", "y".repeat(MAX_EVENT_BYTES / 2));
        assert_eq!(p.feed(line.as_bytes()), Ok(vec![]));
        assert_eq!(p.feed(line.as_bytes()), Err(SseError::Event));
        assert_eq!(
            SseError::Event.to_string(),
            "an SSE event is over 4096 bytes"
        );
    }

    const ROOT_HEX: &str = "0xabababababababababababababababababababababababababababababababab";

    #[test]
    fn a_block_event_gives_its_root() {
        let data = format!(r#"{{"slot":"10","block":"{ROOT_HEX}","execution_optimistic":false}}"#);
        assert_eq!(block_event_root(&data), Ok([0xab; 32]));
    }

    #[test]
    fn a_bad_block_event_is_an_error_that_quotes_nothing() {
        let short = "0xabab";
        let long = format!("{ROOT_HEX}ab");
        let cases = [
            ("not json", "{\"slot\":".to_owned()),
            ("no root", r#"{"slot":"987654"}"#.to_owned()),
            (
                "short root",
                format!(r#"{{"slot":"987654","block":"{short}"}}"#),
            ),
            (
                "long root",
                format!(r#"{{"slot":"987654","block":"{long}"}}"#),
            ),
            (
                "no 0x",
                format!(r#"{{"slot":"987654","block":"{}"}}"#, &ROOT_HEX[2..]),
            ),
            (
                "signed slot",
                format!(r#"{{"slot":"-1","block":"{ROOT_HEX}"}}"#),
            ),
            (
                "number slot",
                format!(r#"{{"slot":987654,"block":"{ROOT_HEX}"}}"#),
            ),
        ];
        for (what, data) in cases {
            let err = block_event_root(&data).unwrap_err();
            assert!(err.0.starts_with(EVENTS_PATH), "{what}: {err}");
            for value in ["abab", "-1", "987654"] {
                assert!(!err.0.contains(value), "{what}: {err}");
            }
        }
    }

    use super::super::fake::Silent;
    use super::super::RefLimits;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use tokio::time::Instant;

    /// What a scripted stream does next.
    #[derive(Debug, Clone)]
    enum Step {
        Root(Root),
        /// Bytes with no root (a keep-alive comment), after this long.
        KeepAlive(Duration),
        Fail,
        Hang,
    }

    /// A head source from a script: each open takes the next entry (an open that fails, or a
    /// stream of steps; a stream past its steps ends), and hangs once the script is done.
    #[derive(Default)]
    struct Script {
        opens: Mutex<VecDeque<Option<Vec<Step>>>>,
        opened: Mutex<Vec<Duration>>,
        start: Mutex<Option<Instant>>,
    }

    struct Scripted(VecDeque<Step>);

    impl HeadStream for Scripted {
        async fn next_root(&mut self) -> Result<Option<Root>, ApiError> {
            match self.0.pop_front() {
                Some(Step::Root(root)) => Ok(Some(root)),
                Some(Step::KeepAlive(after)) => {
                    tokio::time::sleep(after).await;
                    Ok(None)
                }
                Some(Step::Hang) => std::future::pending().await,
                Some(Step::Fail) | None => Err(ApiError("the stream ended".into())),
            }
        }
    }

    impl HeadSource for Arc<Script> {
        type Stream = Scripted;

        async fn open(&self) -> Result<Scripted, ApiError> {
            let start = *self.start.lock().unwrap().get_or_insert_with(Instant::now);
            self.opened.lock().unwrap().push(start.elapsed());
            let next = self.opens.lock().unwrap().pop_front();
            match next {
                Some(Some(steps)) => Ok(Scripted(steps.into())),
                Some(None) => Err(ApiError("HTTP 503".into())),
                None => std::future::pending().await,
            }
        }
    }

    impl Script {
        fn new(opens: Vec<Option<Vec<Step>>>) -> Arc<Self> {
            Arc::new(Self {
                opens: Mutex::new(opens.into()),
                ..Self::default()
            })
        }

        fn opened(&self) -> Vec<u64> {
            let opened = self.opened.lock().unwrap();
            opened.iter().map(|d| d.as_secs()).collect()
        }
    }

    type View = RefView<Arc<Silent>, crate::testing::Spec>;

    fn view(reference: &Arc<Silent>, limits: RefLimits) -> Arc<View> {
        Arc::new(View::new(
            Arc::clone(reference),
            crate::testing::schedule(),
            limits,
        ))
    }

    #[tokio::test(start_paused = true)]
    async fn each_announced_root_is_looked_up_ahead_of_its_columns() {
        let reference = Arc::new(Silent::default());
        let roots: Vec<_> = (0..2).map(|i| reference.serve(9 + i)).collect();
        let refs = view(&reference, RefLimits::default());
        let script = Script::new(vec![Some(vec![
            Step::Root(roots[0]),
            Step::Root(roots[1]),
            Step::Hang,
        ])]);
        let follow = tokio::spawn(follow_head(
            Arc::clone(&script),
            Arc::clone(&refs),
            HeadFollow::default(),
        ));
        tokio::time::sleep(Duration::from_millis(1)).await;
        // Cached before any column asked: a column of either root hits the cache.
        for root in &roots {
            assert!(refs.cached_block(root).is_some());
            assert_eq!(reference.asked(*root), 1);
        }
        assert_eq!(refs.announced(), 0, "every hint spent");
        follow.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn lookups_of_announced_roots_are_bounded() {
        let reference = Arc::new(Silent::default());
        let limits = RefLimits {
            max_announced_in_flight: 2,
            max_announced: 4,
            ..RefLimits::default()
        };
        let refs = view(&reference, limits);
        // Six roots the reference does not serve, announced at once: two lookups hang, the
        // rest stay hints, the oldest of them forgotten past four.
        let steps = (0..6).map(|i| Step::Root([i; 32])).chain([Step::Hang]);
        let script = Script::new(vec![Some(steps.collect())]);
        let follow = tokio::spawn(follow_head(
            Arc::clone(&script),
            Arc::clone(&refs),
            HeadFollow::default(),
        ));
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(refs.in_flight(), 2);
        assert_eq!(refs.announced(), 4);
        // A column of a root that stayed a hint finds every announced place taken: busy,
        // so it takes the root wait.
        let busy = refs.lookup_announced([5; 32]).await;
        assert_eq!(busy, Some(Err(super::super::RefError::Busy(2))));
        follow.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_is_opened_again_after_a_backoff() {
        let reference = Arc::new(Silent::default());
        let roots: Vec<_> = (0..2).map(|i| reference.serve(9 + i)).collect();
        let refs = view(&reference, RefLimits::default());
        let script = Script::new(vec![
            None,
            None,
            // Announces a root, then fails: the backoff starts again.
            Some(vec![Step::Root(roots[0]), Step::Fail]),
            // Silent past the idle timeout: an open stream, so the backoff starts again.
            Some(vec![Step::Hang]),
            Some(vec![Step::Root(roots[1]), Step::Hang]),
        ]);
        let follow = tokio::spawn(follow_head(
            Arc::clone(&script),
            Arc::clone(&refs),
            HeadFollow::default(),
        ));
        tokio::time::sleep(Duration::from_secs(120)).await;
        // Open at 0; down, 1 s; down, 2 s; announced and failed, 1 s; idle for 60 s, 1 s.
        assert_eq!(script.opened(), [0, 1, 3, 4, 65]);
        for root in &roots {
            assert!(refs.cached_block(root).is_some());
        }
        follow.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn keep_alives_keep_a_quiet_stream_open() {
        let reference = Arc::new(Silent::default());
        let refs = view(&reference, RefLimits::default());
        // No block for three minutes, a keep-alive every 30 s: the stream stays open.
        let quiet = (0..6).map(|_| Step::KeepAlive(Duration::from_secs(30)));
        let script = Script::new(vec![Some(quiet.chain([Step::Hang]).collect())]);
        let follow = tokio::spawn(follow_head(
            Arc::clone(&script),
            Arc::clone(&refs),
            HeadFollow::default(),
        ));
        tokio::time::sleep(Duration::from_secs(200)).await;
        assert_eq!(script.opened(), [0]);
        follow.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn idle_streams_are_opened_again_without_a_longer_backoff() {
        let reference = Arc::new(Silent::default());
        let refs = view(&reference, RefLimits::default());
        let script = Script::new(vec![Some(vec![Step::Hang]); 4]);
        let follow = tokio::spawn(follow_head(
            Arc::clone(&script),
            Arc::clone(&refs),
            HeadFollow::default(),
        ));
        tokio::time::sleep(Duration::from_secs(200)).await;
        // Idle for 60 s each time, then the first backoff, never a longer one.
        assert_eq!(script.opened(), [0, 61, 122, 183]);
        follow.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_backoff_does_not_spin() {
        let reference = Arc::new(Silent::default());
        let refs = view(&reference, RefLimits::default());
        let script = Script::new(vec![None; 1000]);
        let config = HeadFollow {
            backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            ..HeadFollow::default()
        };
        let follow = tokio::spawn(follow_head(Arc::clone(&script), refs, config));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let opens = script.opened.lock().unwrap().len();
        assert!(opens <= 11, "{opens} opens in 10 ms");
        follow.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_stays_down_backs_off_to_the_cap_and_announces_nothing() {
        let reference = Arc::new(Silent::default());
        let refs = view(&reference, RefLimits::default());
        let script = Script::new(vec![None; 8]);
        let follow = tokio::spawn(follow_head(
            Arc::clone(&script),
            Arc::clone(&refs),
            HeadFollow::default(),
        ));
        tokio::time::sleep(Duration::from_secs(200)).await;
        // 1, 2, 4, 8, 16, then 30 s at most between opens.
        assert_eq!(script.opened(), [0, 1, 3, 7, 15, 31, 61, 91, 121]);
        assert_eq!((refs.announced(), refs.in_flight()), (0, 0));
        follow.abort();
    }
}
