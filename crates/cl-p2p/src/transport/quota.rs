//! The read quota under mplex: what one pass of [`BudgetedMuxer`](super::BudgetedMuxer) lets
//! mplex take from the socket.
//!
//! mplex reads the socket on behalf of whichever stream is being read and keeps what belongs to
//! the others in its own buffers, which the budget does not see. [`QuotaSocket`] sits between
//! mplex and the socket and hands mplex at most [`PASS_BYTES`] bytes and [`PASS_FRAMES`] frames
//! per pass; a pass begins each time the connection task polls the muxer
//! ([`Pass::begin`]). Between two budget checks mplex can therefore take at most one pass from
//! the socket, whoever reads, and spend CPU on at most [`PASS_FRAMES`] frames however small.
//!
//! The socket counts frames by following the mplex framing (`varint header | varint length |
//! data`) of the bytes it hands out, and cuts a pass at the end of the frame that uses up the
//! frame quota; the bytes it read past that point wait for the next pass. It also closes the
//! connection once more than [`MAX_EMPTY_FRAMES`] of [`EMPTY_FRAME_WINDOW`] consecutive frames are
//! empty data frames: they move no bytes, so no byte budget would ever stop them.

use super::{lock, MPLEX_MAX_BUFFERED_FRAMES};
use bytes::{Buf, BytesMut};
use futures::task::AtomicWaker;
use futures::{ready, AsyncRead, AsyncWrite};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// Bytes one pass may hand mplex: 256 KiB.
///
/// What mplex holds uncounted is at most one pass plus the one frame it is still decoding (at
/// most 1 MiB, `muxers/mplex/src/codec.rs`), against a 32 MiB connection budget. A pass is one
/// poll of the connection task, so 256 KiB per poll still moves a busy stream at well over a
/// gigabit while letting the executor run other connections between passes.
pub const PASS_BYTES: usize = 256 << 10;

/// Frames one pass may hand mplex: half of [`MPLEX_MAX_BUFFERED_FRAMES`].
///
/// Every pass drains each stream, so a stream's frames wait inside mplex for at most the rest of
/// one pass and the start of the next: two passes, 256 frames, never the 257 at which mplex
/// resets the stream. It also bounds the CPU a flood of tiny or empty frames costs per poll.
pub const PASS_FRAMES: usize = MPLEX_MAX_BUFFERED_FRAMES / 2;

const _: () = assert!(2 * PASS_FRAMES <= MPLEX_MAX_BUFFERED_FRAMES);

/// The run of consecutive frames the empty-frame ratio is measured over.
pub const EMPTY_FRAME_WINDOW: usize = 1024;

/// Empty data frames one [`EMPTY_FRAME_WINDOW`] may hold before the connection is closed: half.
/// rust-libp2p sends an empty data frame only for an empty write, so a peer sending half its
/// frames empty is not moving data.
pub const MAX_EMPTY_FRAMES: usize = EMPTY_FRAME_WINDOW / 2;

/// One connection's pass, shared by the [`QuotaSocket`] under mplex and the muxer above it.
#[derive(Debug, Default)]
pub(super) struct Pass {
    /// The connection task: woken when the quota runs out, so that it begins the next pass.
    task: AtomicWaker,
    state: Mutex<PassState>,
}

#[derive(Debug)]
struct PassState {
    /// Bytes left in this pass.
    bytes: usize,
    /// Frames left in this pass.
    frames: usize,
    /// Whether mplex may read the socket at all; shut while the muxer sweeps up what mplex
    /// already holds.
    open: bool,
    /// The read the quota left pending, woken when the next pass begins.
    parked: Option<Waker>,
    /// The peer sent too many empty data frames; every further read fails.
    flooded: bool,
}

impl Default for PassState {
    fn default() -> Self {
        Self {
            bytes: PASS_BYTES,
            frames: PASS_FRAMES,
            open: true,
            parked: None,
            flooded: false,
        }
    }
}

impl Pass {
    /// Begins a pass for the connection task `task`: a full quota, and the read the last one
    /// left pending woken.
    pub(super) fn begin(&self, task: &Waker) {
        self.task.register(task);
        let parked = {
            let mut state = lock(&self.state);
            state.bytes = PASS_BYTES;
            state.frames = PASS_FRAMES;
            state.parked.take()
        };
        if let Some(parked) = parked {
            parked.wake();
        }
    }

    /// Remembers `task` as the connection task without beginning a pass.
    pub(super) fn register(&self, task: &Waker) {
        self.task.register(task);
    }

    /// Opens or shuts the socket to mplex.
    pub(super) fn set_open(&self, open: bool) {
        lock(&self.state).open = open;
    }

    /// What is left of this pass: bytes and frames.
    pub(super) fn left(&self) -> (usize, usize) {
        let state = lock(&self.state);
        (state.bytes, state.frames)
    }

    /// Whether this pass has used up its bytes or its frames.
    pub(super) fn exhausted(&self) -> bool {
        let (bytes, frames) = self.left();
        bytes == 0 || frames == 0
    }

    /// Whether the peer flooded the connection with empty data frames.
    pub(super) fn flooded(&self) -> bool {
        lock(&self.state).flooded
    }
}

/// The socket under a [`Budgeted`](super::Budgeted) mplex: reads are held to the connection's
/// pass quota (see the [module docs](self)); writes go straight through.
pub struct QuotaSocket<C> {
    inner: C,
    pass: Arc<Pass>,
    frames: FrameScanner,
    /// Bytes read from the socket past the frame the last pass ended on.
    stash: BytesMut,
}

impl<C> QuotaSocket<C> {
    pub(super) fn new(inner: C, pass: Arc<Pass>) -> Self {
        Self {
            inner,
            pass,
            frames: FrameScanner::default(),
            stash: BytesMut::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn get_ref(&self) -> &C {
        &self.inner
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for QuotaSocket<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let (room, frames) = {
            let mut state = lock(&this.pass.state);
            if state.flooded {
                return Poll::Ready(Err(flood_error()));
            }
            if !state.open {
                // The muxer reopens the socket before it returns, and reads it again.
                return Poll::Pending;
            }
            if state.bytes == 0 || state.frames == 0 {
                state.parked = Some(cx.waker().clone());
                drop(state);
                this.pass.task.wake();
                return Poll::Pending;
            }
            (state.bytes.min(out.len()), state.frames)
        };
        let out = &mut out[..room];
        let stashed = !this.stash.is_empty();
        let n = if stashed {
            let n = room.min(this.stash.len());
            out[..n].copy_from_slice(&this.stash[..n]);
            n
        } else {
            match ready!(Pin::new(&mut this.inner).poll_read(cx, out))? {
                0 => return Poll::Ready(Ok(0)),
                n => n,
            }
        };
        let scanned = this.frames.scan(&out[..n], frames);
        // Every frame takes at least two bytes, so a pass with frames left takes at least one:
        // an `Ok(0)` here would read as the end of the connection.
        debug_assert!(scanned.len > 0);
        if stashed {
            this.stash.advance(scanned.len);
        } else {
            this.stash.extend_from_slice(&out[scanned.len..n]);
        }
        let mut state = lock(&this.pass.state);
        state.bytes = state.bytes.saturating_sub(scanned.len);
        state.frames = state.frames.saturating_sub(scanned.frames);
        if scanned.flooded {
            state.flooded = true;
            drop(state);
            tracing::warn!(
                max = MAX_EMPTY_FRAMES,
                window = EMPTY_FRAME_WINDOW,
                "closing a connection whose peer floods it with empty mplex data frames"
            );
            this.pass.task.wake();
            return Poll::Ready(Err(flood_error()));
        }
        Poll::Ready(Ok(scanned.len))
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for QuotaSocket<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

fn flood_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the peer floods the connection with empty mplex data frames",
    )
}

/// What [`FrameScanner::scan`] let through.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Scanned {
    /// Bytes, from the start.
    pub len: usize,
    /// Frames those bytes completed.
    pub frames: usize,
    /// The last of those frames was one empty data frame too many.
    pub flooded: bool,
}

/// Follows the mplex framing of a byte stream: `varint header | varint length | data`, where
/// the low three bits of the header are the frame's flag (1 and 2 for data).
///
/// It also counts the empty data frames in each [`EMPTY_FRAME_WINDOW`] consecutive frames, frame
/// by frame, so where a read happens to end does not move frames from one window to another.
#[derive(Debug)]
pub(super) struct FrameScanner {
    scan: Scan,
    /// Frames in the current window, and how many of them were empty data frames.
    window: usize,
    empty: usize,
}

#[derive(Debug)]
enum Scan {
    Header {
        value: u64,
        shift: u32,
    },
    Length {
        header: u64,
        value: u64,
        shift: u32,
    },
    Body {
        left: u64,
    },
    /// A varint longer than a `u64`: mplex rejects these bytes and fails the connection, so they
    /// are let through uncounted.
    Lost,
}

const HEADER: Scan = Scan::Header { value: 0, shift: 0 };

impl Default for FrameScanner {
    fn default() -> Self {
        Self {
            scan: HEADER,
            window: 0,
            empty: 0,
        }
    }
}

impl FrameScanner {
    /// The longest prefix of `bytes` that completes at most `max_frames` frames, ending early
    /// at the frame that floods the window.
    pub(super) fn scan(&mut self, bytes: &[u8], max_frames: usize) -> Scanned {
        let mut scanned = Scanned::default();
        while scanned.len < bytes.len() && scanned.frames < max_frames && !scanned.flooded {
            match &mut self.scan {
                Scan::Header { value, shift } => {
                    let byte = bytes[scanned.len];
                    scanned.len += 1;
                    match varint(value, shift, byte) {
                        Varint::More => {}
                        Varint::Done => {
                            self.scan = Scan::Length {
                                header: *value,
                                value: 0,
                                shift: 0,
                            };
                        }
                        Varint::Overflow => self.scan = Scan::Lost,
                    }
                }
                Scan::Length {
                    header,
                    value,
                    shift,
                } => {
                    let byte = bytes[scanned.len];
                    scanned.len += 1;
                    match varint(value, shift, byte) {
                        Varint::More => {}
                        Varint::Done if *value == 0 => {
                            let empty_data = matches!(*header & 7, 1 | 2);
                            self.scan = HEADER;
                            scanned.frames += 1;
                            scanned.flooded = self.count(empty_data);
                        }
                        Varint::Done => self.scan = Scan::Body { left: *value },
                        Varint::Overflow => self.scan = Scan::Lost,
                    }
                }
                Scan::Body { left } => {
                    let rest = bytes.len() - scanned.len;
                    let take = usize::try_from(*left).map_or(rest, |left| left.min(rest));
                    scanned.len += take;
                    *left -= take as u64;
                    if *left == 0 {
                        self.scan = HEADER;
                        scanned.frames += 1;
                        scanned.flooded = self.count(false);
                    }
                }
                Scan::Lost => scanned.len = bytes.len(),
            }
        }
        scanned
    }

    /// Counts one frame into the window; whether it holds too many empty data frames now.
    fn count(&mut self, empty_data: bool) -> bool {
        self.window += 1;
        self.empty += usize::from(empty_data);
        let flooded = self.empty > MAX_EMPTY_FRAMES;
        if self.window == EMPTY_FRAME_WINDOW {
            self.window = 0;
            self.empty = 0;
        }
        flooded
    }
}

enum Varint {
    More,
    Done,
    Overflow,
}

/// Adds `byte` to the LEB128 varint being read into `value`.
fn varint(value: &mut u64, shift: &mut u32, byte: u8) -> Varint {
    if *shift >= u64::BITS {
        return Varint::Overflow;
    }
    *value |= u64::from(byte & 0x7f) << *shift;
    if byte & 0x80 == 0 {
        Varint::Done
    } else {
        *shift += 7;
        Varint::More
    }
}
