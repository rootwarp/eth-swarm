//! `ssz_snappy` req/resp framing (consensus-specs v1.7.0-beta.4).
//!
//! # Wire format
//!
//! `phase0/p2p-interface.md` "Encoding strategies" (L1327-1394) and "Responding side"
//! (L1276-1309), `altair/p2p-interface.md` "Context bytes" (L456-499):
//!
//! ```text
//! request        ::= <payload>                          (nothing at all for an empty request)
//! response_chunk ::= <result> | <context-bytes> | <payload>
//! payload        ::= <varint(len(ssz))> | <snappy frames of ssz>
//! ```
//!
//! - The prefix is the unsigned-LEB128 (protobuf) varint of the *uncompressed* SSZ length, at
//!   most [`MAX_VARINT_LEN`] bytes, minimally encoded.
//! - The prefix must lie within the type's SSZ bounds ([`SszBounds`], from the protocol's
//!   [`ProtocolLimits`](crate::rpc::protocols::ProtocolLimits) row), its upper bound capped at
//!   `MAX_PAYLOAD_SIZE` (10 MiB, `phase0` L299, L1365). It is checked **before** anything is
//!   allocated for the payload or a byte of it is read.
//! - The frames are the snappy framing format. At most [`max_compressed_len`]`(n)` =
//!   `32 + n + n / 6` compressed bytes are read, the decoder's output is read through
//!   `take(n)`, and fewer bytes, more decompressed bytes or more input are each an error.
//! - `result` is 0 (success) or 1-3 (error, payload `ErrorMessage` of at most 256 bytes). Any
//!   other value is refused before the rest of the chunk is read.
//! - Context bytes are the 4-byte fork digest, present only on a success chunk of a protocol
//!   that has them ([`Protocol::has_context_bytes`]); an error chunk's context is empty. The
//!   digest is looked up in an injected [`ContextTable`], and an unknown digest is refused before
//!   the payload is read.
//!
//! # Work and allocation
//!
//! [`ChunkScanner`] and [`ResponseChunkScanner`] are sans-IO and incremental: they parse what
//! has arrived, resume where they stopped, and say exactly how many more bytes the chunk needs.
//! A transport therefore parses each frame once, never reads past a chunk and never buffers more
//! than `max_len` bytes. A frame header that names a body over snappy's maximum is refused from
//! the header, so no buffer grows for it, and at most [`MAX_EMPTY_FRAMES`] frames without data
//! are accepted per payload. [`scan_chunk`] and [`scan_response_chunk`] are their one-shot
//! forms. [`decode_chunk`] allocates the `n`-byte output only
//! after the prefix passed its bound and the frames are all present; besides that, the snappy
//! decoder holds two fixed buffers of under 76 KiB each. `tests/alloc_bound.rs` checks both
//! under a counting allocator.

use crate::rpc::messages::{
    BlocksByRangeV2Request, ErrorMessage, ForkDigest, Goodbye, MetaDataV3, Ping, StatusV2,
    MAX_ERROR_MESSAGE_LEN,
};
use crate::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode, SszBounds};
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use consensus_types::codec::DecodeError;
use consensus_types::{forked, EthSpec, ForkName};
use ssz::Decode;
use std::io::{self, Read, Write};

/// The longest unsigned-LEB128 length prefix: a `u64` needs at most 10 bytes.
pub const MAX_VARINT_LEN: usize = 10;
/// Context bytes: a fork digest.
pub const CONTEXT_BYTES_LEN: usize = 4;

/// A snappy frame header: chunk type and 24-bit little-endian length.
const FRAME_HEADER_LEN: usize = 4;
/// The masked CRC-32C at the start of every data frame.
const FRAME_CRC_LEN: usize = 4;
const FRAME_COMPRESSED: u8 = 0x00;
const FRAME_UNCOMPRESSED: u8 = 0x01;
const FRAME_RESERVED_UNSKIPPABLE: std::ops::RangeInclusive<u8> = 0x02..=0x7f;
/// The most uncompressed bytes one snappy data frame holds (`MAX_BLOCK_SIZE`).
const MAX_FRAME_OUTPUT_LEN: usize = 65_536;

/// The longest frame body `snap`'s decoder accepts (`MAX_COMPRESS_BLOCK_SIZE`, the CRC
/// included): longer frames are refused from their header, before the body is read or buffered.
pub const MAX_FRAME_BODY_LEN: usize = 76_490;
/// The longest uncompressed data frame body: its CRC and at most 64 KiB of data.
pub const MAX_UNCOMPRESSED_FRAME_BODY_LEN: usize = FRAME_CRC_LEN + MAX_FRAME_OUTPUT_LEN;
/// The most frames without data (stream identifier, padding, skippable, empty data frames) one
/// payload may hold. A compliant encoder writes one, the stream identifier; the cap keeps a
/// peer from making the scan parse millions of 4-byte frames that never advance the payload.
pub const MAX_EMPTY_FRAMES: usize = 16;

/// The longest chunk any protocol accepts: result, context, prefix and compressed payload.
const MAX_RESPONSE_CHUNK_LEN: usize =
    1 + CONTEXT_BYTES_LEN + MAX_VARINT_LEN + 32 + MAX_PAYLOAD_SIZE + MAX_PAYLOAD_SIZE / 6;

/// Why bytes did not decode. Every variant is a peer fault, found without panicking.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CodecError {
    /// The length prefix runs past [`MAX_VARINT_LEN`] bytes.
    #[error("length prefix is longer than {MAX_VARINT_LEN} bytes")]
    VarintTooLong,
    /// The length prefix encodes a value above `u64::MAX`.
    #[error("length prefix overflows u64")]
    VarintOverflow,
    /// The length prefix ends in a redundant zero byte.
    #[error("length prefix is not minimally encoded")]
    VarintNotMinimal,
    /// The declared SSZ length is above the bound; nothing was allocated for it.
    #[error("declared length {len} exceeds the bound {max}")]
    PayloadTooLarge {
        /// The declared length.
        len: u64,
        /// The bound: min(type bound, `MAX_PAYLOAD_SIZE`).
        max: usize,
    },
    /// The declared SSZ length is below the type's shortest encoding; nothing was allocated
    /// for it.
    #[error("declared length {len} is below the type's minimum {min}")]
    PayloadTooSmall {
        /// The declared length.
        len: u64,
        /// The shortest valid encoding of the type.
        min: usize,
    },
    /// The compressed payload runs past `max_compressed_len(len)`.
    #[error("compressed payload of a {len}-byte message exceeds {max} bytes")]
    CompressedTooLarge {
        /// The declared SSZ length.
        len: usize,
        /// `max_compressed_len(len)`.
        max: usize,
    },
    /// A frame header names a body longer than snappy allows for its chunk type, or a
    /// compressed block claims more than 64 KiB of output; refused before the body is read.
    #[error("snappy frame of {len} bytes exceeds the frame maximum")]
    FrameTooLarge {
        /// The body length (or, for a compressed block, its claimed output length).
        len: usize,
    },
    /// More than [`MAX_EMPTY_FRAMES`] frames without data.
    #[error("more than {max} snappy frames without data")]
    TooManyEmptyFrames {
        /// [`MAX_EMPTY_FRAMES`].
        max: usize,
    },
    /// The frames decompress to more bytes than the prefix declared.
    #[error("snappy frames hold more than the declared {len} bytes")]
    PayloadOverrun {
        /// The declared SSZ length.
        len: usize,
    },
    /// The input ends inside the chunk.
    #[error("chunk truncated")]
    Truncated,
    /// Bytes follow the chunk.
    #[error("{0} trailing bytes after the chunk")]
    TrailingBytes(usize),
    /// The snappy framing is malformed (stream identifier, reserved chunk type, CRC, block).
    #[error("snappy: {0}")]
    Snappy(String),
    /// The result byte is not 0-3.
    #[error("invalid result code {0}")]
    InvalidResultCode(u8),
    /// The context bytes name no fork in the [`ContextTable`].
    #[error("unknown context bytes {0:02x?}")]
    UnknownContext(ForkDigest),
    /// A success chunk of a protocol with context bytes was handled without them.
    #[error("{0} needs context bytes")]
    MissingContext(Protocol),
    /// The SSZ payload did not decode.
    #[error("decode: {0}")]
    Decode(DecodeError),
}

impl From<ssz::DecodeError> for CodecError {
    fn from(e: ssz::DecodeError) -> Self {
        CodecError::Decode(DecodeError::Ssz(e))
    }
}

impl From<DecodeError> for CodecError {
    fn from(e: DecodeError) -> Self {
        CodecError::Decode(e)
    }
}

impl ResultCode {
    /// The code for result byte `byte`, refusing 4 and up.
    pub fn from_byte(byte: u8) -> Result<Self, CodecError> {
        Ok(match byte {
            0 => ResultCode::Success,
            1 => ResultCode::InvalidRequest,
            2 => ResultCode::ServerError,
            3 => ResultCode::ResourceUnavailable,
            other => return Err(CodecError::InvalidResultCode(other)),
        })
    }

    /// The result byte.
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Fork digest → fork, for the context bytes of a response chunk.
///
/// Injected by the caller, so that decoding peer bytes runs no network-config code. From Fulu
/// on, a blob-parameter-only fork changes the digest without changing the fork, so several
/// digests can name one fork.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextTable {
    entries: Vec<(ForkDigest, ForkName)>,
}

impl ContextTable {
    /// An empty table: every digest is unknown.
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps `digest` to `fork`, returning the fork it named before.
    pub fn insert(&mut self, digest: ForkDigest, fork: ForkName) -> Option<ForkName> {
        match self.entries.iter_mut().find(|(d, _)| *d == digest) {
            Some((_, f)) => Some(std::mem::replace(f, fork)),
            None => {
                self.entries.push((digest, fork));
                None
            }
        }
    }

    /// The fork `digest` names.
    pub fn fork(&self, digest: &ForkDigest) -> Option<ForkName> {
        self.entries
            .iter()
            .find(|(d, _)| d == digest)
            .map(|(_, f)| *f)
    }
}

/// How far a scan of a partly received chunk got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scan {
    /// More bytes are needed.
    Incomplete {
        /// Exactly this many more bytes are needed before the scan can go on; reading them
        /// never reads past the chunk.
        need: usize,
        /// The most bytes the chunk can occupy given what has been parsed so far: the bound to
        /// size a receive buffer against.
        max_len: usize,
    },
    /// The chunk ends after `len` bytes.
    Complete {
        /// The chunk length.
        len: usize,
    },
}

impl Scan {
    fn after(self, head: usize) -> Self {
        match self {
            Scan::Incomplete { need, max_len } => Scan::Incomplete {
                need,
                max_len: max_len + head,
            },
            Scan::Complete { len } => Scan::Complete { len: len + head },
        }
    }
}

/// `max_compressed_len(n)` = `32 + n + n / 6` (`phase0/p2p-interface.md`): the snappy worst case.
pub fn max_compressed_len(n: usize) -> usize {
    n.saturating_add(n / 6).saturating_add(32)
}

/// Appends the unsigned-LEB128 encoding of `n`.
pub fn encode_varint(mut n: u64, out: &mut Vec<u8>) {
    while n >= 0x80 {
        out.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// Reads a length prefix: `Ok(None)` if `buf` ends inside it.
fn read_varint(buf: &[u8]) -> Result<Option<(u64, usize)>, CodecError> {
    let mut value = 0u64;
    for (i, &byte) in buf.iter().take(MAX_VARINT_LEN).enumerate() {
        let last = byte & 0x80 == 0;
        if i == MAX_VARINT_LEN - 1 {
            if !last {
                return Err(CodecError::VarintTooLong);
            }
            if byte > 1 {
                return Err(CodecError::VarintOverflow);
            }
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if last {
            // A zero final byte after a continuation adds nothing: the prefix is not minimal.
            // Compliant encoders always write the minimal form, and Lighthouse's decoder
            // (`unsigned-varint`) refuses the non-minimal one too, so refusing it here costs no
            // interoperability and leaves one encoding per length.
            if byte == 0 && i > 0 {
                return Err(CodecError::VarintNotMinimal);
            }
            return Ok(Some((value, i + 1)));
        }
    }
    Ok(None)
}

/// Decodes a length prefix: the value and its length in bytes.
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), CodecError> {
    read_varint(buf)?.ok_or(CodecError::Truncated)
}

/// The declared length if it is within `bounds` and `MAX_PAYLOAD_SIZE`.
fn check_declared(len: u64, bounds: SszBounds) -> Result<usize, CodecError> {
    let max = bounds.max.min(MAX_PAYLOAD_SIZE);
    match usize::try_from(len) {
        Ok(n) if n > max => Err(CodecError::PayloadTooLarge { len, max }),
        Ok(n) if n < bounds.min => Err(CodecError::PayloadTooSmall {
            len,
            min: bounds.min,
        }),
        Ok(n) => Ok(n),
        Err(_) => Err(CodecError::PayloadTooLarge { len, max }),
    }
}

/// How many decompressed bytes the data frame of type `ty` with body `body` holds.
fn frame_output_len(ty: u8, body: &[u8]) -> Result<usize, CodecError> {
    let data = || {
        body.get(FRAME_CRC_LEN..)
            .ok_or_else(|| CodecError::Snappy("data frame shorter than its CRC".into()))
    };
    match ty {
        FRAME_COMPRESSED => {
            let len = snap::raw::decompress_len(data()?)
                .map_err(|e| CodecError::Snappy(e.to_string()))?;
            if len > MAX_FRAME_OUTPUT_LEN {
                return Err(CodecError::FrameTooLarge { len });
            }
            Ok(len)
        }
        FRAME_UNCOMPRESSED => Ok(data()?.len()),
        t if FRAME_RESERVED_UNSKIPPABLE.contains(&t) => {
            Err(CodecError::Snappy(format!("reserved chunk type {t:#04x}")))
        }
        // Stream identifier, padding and reserved skippable frames hold no data.
        _ => Ok(0),
    }
}

/// The longest body a frame of type `ty` may have.
fn max_frame_body_len(ty: u8) -> usize {
    match ty {
        FRAME_UNCOMPRESSED => MAX_UNCOMPRESSED_FRAME_BODY_LEN,
        _ => MAX_FRAME_BODY_LEN,
    }
}

/// The part of a payload parsed so far, once its prefix is known.
#[derive(Debug, Clone, Copy)]
struct PayloadProgress {
    /// Length of the prefix.
    prefix: usize,
    /// The declared SSZ length.
    n: usize,
    /// `max_compressed_len(n)`.
    limit: usize,
    /// Compressed bytes of whole frames parsed so far.
    pos: usize,
    /// Decompressed bytes those frames hold.
    out: usize,
}

/// An incremental scanner of one payload (prefix and frames) within SSZ bounds.
///
/// Each [`ChunkScanner::scan`] resumes where the last one stopped, so every frame header is
/// parsed once however the bytes arrive: the work is linear in the payload. It fails as soon
/// as the bytes so far break a bound:
///
/// - a prefix over 10 bytes, or a declared length outside the bounds (the upper one capped at
///   `MAX_PAYLOAD_SIZE`);
/// - a frame header that does not fit under `max_compressed_len(n)`, or whose frame would not;
/// - a frame body over snappy's maximum for its type ([`MAX_FRAME_BODY_LEN`],
///   [`MAX_UNCOMPRESSED_FRAME_BODY_LEN`]), refused from the header;
/// - more than [`MAX_EMPTY_FRAMES`] frames without data.
///
/// Frame contents (CRC, stream identifier, decompression) are checked by [`decode_chunk`].
#[derive(Debug, Clone)]
pub struct ChunkScanner {
    bounds: SszBounds,
    progress: Option<PayloadProgress>,
    frames: usize,
    empty_frames: usize,
}

impl ChunkScanner {
    /// A scanner for a payload of at most `max` SSZ bytes.
    pub fn new(max: usize) -> Self {
        Self::with_bounds(SszBounds { min: 0, max })
    }

    /// A scanner for a payload whose SSZ length lies within `bounds`.
    pub fn with_bounds(bounds: SszBounds) -> Self {
        Self {
            bounds,
            progress: None,
            frames: 0,
            empty_frames: 0,
        }
    }

    /// How many frames have been parsed so far.
    pub fn frames_scanned(&self) -> usize {
        self.frames
    }

    /// The declared SSZ length, once the prefix has been read.
    pub fn declared_len(&self) -> Option<usize> {
        self.progress.map(|p| p.n)
    }

    /// Scans `buf`, the payload's bytes received so far. Every call must pass the bytes of the
    /// call before it plus any new ones (the buffer only grows).
    pub fn scan(&mut self, buf: &[u8]) -> Result<Scan, CodecError> {
        let mut p = match self.progress {
            Some(p) => p,
            None => {
                let Some((declared, prefix)) = read_varint(buf)? else {
                    return Ok(Scan::Incomplete {
                        need: 1,
                        max_len: MAX_VARINT_LEN
                            + max_compressed_len(self.bounds.max.min(MAX_PAYLOAD_SIZE)),
                    });
                };
                let n = check_declared(declared, self.bounds)?;
                PayloadProgress {
                    prefix,
                    n,
                    limit: max_compressed_len(n),
                    pos: 0,
                    out: 0,
                }
            }
        };
        let frames = &buf[p.prefix.min(buf.len())..];
        let result = self.advance(&mut p, frames);
        self.progress = Some(p);
        result
    }

    /// Parses the whole frames of `frames` past `p.pos`.
    fn advance(&mut self, p: &mut PayloadProgress, frames: &[u8]) -> Result<Scan, CodecError> {
        let too_large = CodecError::CompressedTooLarge {
            len: p.n,
            max: p.limit,
        };
        let max_len = p.prefix + p.limit;
        while p.out < p.n {
            if p.pos + FRAME_HEADER_LEN > p.limit {
                return Err(too_large);
            }
            let Some(header) = frames.get(p.pos..p.pos + FRAME_HEADER_LEN) else {
                let need = p.pos + FRAME_HEADER_LEN - frames.len();
                return Ok(Scan::Incomplete { need, max_len });
            };
            let ty = header[0];
            let body_len =
                usize::from(header[1]) | usize::from(header[2]) << 8 | usize::from(header[3]) << 16;
            if body_len > max_frame_body_len(ty) {
                return Err(CodecError::FrameTooLarge { len: body_len });
            }
            let end = p.pos + FRAME_HEADER_LEN + body_len;
            if end > p.limit {
                return Err(too_large);
            }
            let Some(body) = frames.get(p.pos + FRAME_HEADER_LEN..end) else {
                return Ok(Scan::Incomplete {
                    need: end - frames.len(),
                    max_len,
                });
            };
            let output = frame_output_len(ty, body)?;
            self.frames += 1;
            if output == 0 {
                self.empty_frames += 1;
                if self.empty_frames > MAX_EMPTY_FRAMES {
                    return Err(CodecError::TooManyEmptyFrames {
                        max: MAX_EMPTY_FRAMES,
                    });
                }
            }
            p.out = p.out.saturating_add(output);
            p.pos = end;
        }
        Ok(Scan::Complete {
            len: p.prefix + p.pos,
        })
    }
}

/// Scans one payload at the start of `buf`, whose SSZ bound is `max`: a one-shot
/// [`ChunkScanner`]. A transport that receives the payload piecewise keeps a [`ChunkScanner`]
/// instead, so it does not re-parse the frames it has.
pub fn scan_chunk(buf: &[u8], max: usize) -> Result<Scan, CodecError> {
    ChunkScanner::new(max).scan(buf)
}

/// Encodes `ssz` as one payload: its length prefix, then snappy frames.
pub fn encode_chunk(ssz: &[u8]) -> Result<Vec<u8>, CodecError> {
    let n = check_declared(ssz.len() as u64, SszBounds::up_to(MAX_PAYLOAD_SIZE))?;
    let mut out = Vec::with_capacity(MAX_VARINT_LEN + max_compressed_len(n));
    encode_varint(n as u64, &mut out);
    let mut encoder = snap::write::FrameEncoder::new(&mut out);
    encoder
        .write_all(ssz)
        .and_then(|()| encoder.flush())
        .map_err(|e| CodecError::Snappy(e.to_string()))?;
    drop(encoder);
    Ok(out)
}

/// Decodes `buf`, which must be exactly one payload whose SSZ bound is `max`, to its SSZ bytes.
pub fn decode_chunk(buf: &[u8], max: usize) -> Result<Vec<u8>, CodecError> {
    decode_chunk_within(buf, SszBounds { min: 0, max })
}

/// Decodes `buf`, which must be exactly one payload whose SSZ length lies within `bounds`, to
/// its SSZ bytes. The prefix is checked first, so a length outside `bounds` is refused before
/// a frame is parsed or a byte allocated.
pub fn decode_chunk_within(buf: &[u8], bounds: SszBounds) -> Result<Vec<u8>, CodecError> {
    let len = match ChunkScanner::with_bounds(bounds).scan(buf)? {
        Scan::Incomplete { .. } => return Err(CodecError::Truncated),
        Scan::Complete { len } => len,
    };
    if len < buf.len() {
        return Err(CodecError::TrailingBytes(buf.len() - len));
    }
    let (declared, prefix) = decode_varint(buf)?;
    let n = check_declared(declared, bounds)?;
    decompress(&buf[prefix..], n)
}

/// Decompresses exactly `n` bytes from `frames`, reading at most `max_compressed_len(n)` of
/// them and at most `n` of the decoder's output (`take(n)`).
fn decompress(frames: &[u8], n: usize) -> Result<Vec<u8>, CodecError> {
    let limit = max_compressed_len(n);
    let mut decoder = snap::read::FrameDecoder::new(frames.take(limit as u64));
    let ended = |decoder: &snap::read::FrameDecoder<io::Take<&[u8]>>| {
        if decoder.get_ref().limit() == 0 {
            CodecError::CompressedTooLarge { len: n, max: limit }
        } else {
            CodecError::Truncated
        }
    };
    let mut out = vec![0u8; n];
    match (&mut decoder).take(n as u64).read_exact(&mut out) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(ended(&decoder)),
        Err(e) => return Err(CodecError::Snappy(e.to_string())),
    }
    // Stop at `n`: a frame that holds more than the prefix declared is an error.
    match decoder.read(&mut [0u8; 1]) {
        Ok(0) => Ok(out),
        Ok(_) => Err(CodecError::PayloadOverrun { len: n }),
        Err(e) => Err(CodecError::Snappy(e.to_string())),
    }
}

/// Encodes a request: one payload, or nothing for an empty request.
pub fn encode_request(request: &Request) -> Result<Vec<u8>, CodecError> {
    match request.ssz_body() {
        Some(ssz) => encode_chunk(&ssz),
        None => Ok(Vec::new()),
    }
}

/// Decodes `buf`, which must be exactly one request of `protocol`.
pub fn decode_request(protocol: Protocol, buf: &[u8]) -> Result<Request, CodecError> {
    let Some(bounds) = protocol.request_bounds() else {
        return match buf.len() {
            0 => Ok(Request::MetaData),
            extra => Err(CodecError::TrailingBytes(extra)),
        };
    };
    let ssz = decode_chunk_within(buf, bounds)?;
    Ok(match protocol {
        Protocol::StatusV2 => Request::Status(StatusV2::from_ssz_bytes(&ssz)?),
        Protocol::PingV1 => Request::Ping(Ping::from_ssz_bytes(&ssz)?),
        Protocol::BlocksByRangeV2 => {
            Request::BlocksByRange(BlocksByRangeV2Request::from_ssz_bytes(&ssz)?)
        }
        Protocol::GoodbyeV1 => Request::Goodbye(Goodbye::from_ssz_bytes(&ssz)?),
        Protocol::MetaDataV3 => Request::MetaData,
    })
}

/// Encodes a success chunk: result 0, the context bytes if any, then the payload.
pub fn encode_success_chunk(
    context: Option<ForkDigest>,
    ssz: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let mut out = vec![ResultCode::Success.as_byte()];
    out.extend(context.iter().flatten());
    out.extend(encode_chunk(ssz)?);
    Ok(out)
}

/// Encodes an error chunk: result 1-3, no context bytes, then the `ErrorMessage` payload.
pub fn encode_error_chunk(code: ResultCode, message: &[u8]) -> Result<Vec<u8>, CodecError> {
    if code == ResultCode::Success {
        return Err(CodecError::InvalidResultCode(code.as_byte()));
    }
    check_declared(
        message.len() as u64,
        SszBounds::up_to(MAX_ERROR_MESSAGE_LEN),
    )?;
    let mut out = vec![code.as_byte()];
    out.extend(encode_chunk(message)?);
    Ok(out)
}

/// The head of a response chunk: result byte and context bytes, read and checked.
#[derive(Debug, Clone, Copy)]
struct ChunkHead {
    code: ResultCode,
    fork: Option<ForkName>,
    /// Bytes before the payload.
    len: usize,
    /// The payload's SSZ bounds.
    bounds: SszBounds,
}

/// Parses the head at the start of `buf`; `Ok(Err(need))` if more bytes are needed.
fn parse_head<E: EthSpec>(
    buf: &[u8],
    protocol: Protocol,
    contexts: &ContextTable,
) -> Result<Result<ChunkHead, usize>, CodecError> {
    let Some(&result) = buf.first() else {
        return Ok(Err(1));
    };
    let code = ResultCode::from_byte(result)?;
    if code != ResultCode::Success {
        return Ok(Ok(ChunkHead {
            code,
            fork: None,
            len: 1,
            bounds: protocol.error_bounds(),
        }));
    }
    let (fork, len) = if protocol.has_context_bytes() {
        let end = 1 + CONTEXT_BYTES_LEN;
        let Some(raw) = buf.get(1..end) else {
            return Ok(Err(end - buf.len()));
        };
        let digest: ForkDigest = raw.try_into().expect("4 bytes");
        let fork = contexts
            .fork(&digest)
            .ok_or(CodecError::UnknownContext(digest))?;
        (Some(fork), end)
    } else {
        (None, 1)
    };
    // Every protocol has a response bound; only a block's needs the fork its context names.
    let Some(bounds) = protocol.response_bounds::<E>(fork) else {
        return Err(CodecError::MissingContext(protocol));
    };
    Ok(Ok(ChunkHead {
        code,
        fork,
        len,
        bounds,
    }))
}

/// An incremental scanner of one response chunk of `protocol`: [`ChunkScanner`] after the head.
///
/// Refuses a result byte of 4 or more as soon as it arrives, and an unknown context digest as
/// soon as its 4 bytes arrive, so neither is followed by a read of the payload.
#[derive(Debug, Clone)]
pub struct ResponseChunkScanner<'a, E: EthSpec> {
    protocol: Protocol,
    contexts: &'a ContextTable,
    head: Option<(ChunkHead, ChunkScanner)>,
    _spec: std::marker::PhantomData<fn() -> E>,
}

impl<'a, E: EthSpec> ResponseChunkScanner<'a, E> {
    /// A scanner for a chunk of `protocol`, looking context bytes up in `contexts`.
    pub fn new(protocol: Protocol, contexts: &'a ContextTable) -> Self {
        Self {
            protocol,
            contexts,
            head: None,
            _spec: std::marker::PhantomData,
        }
    }

    /// Scans `buf`, the chunk's bytes received so far (the buffer only grows between calls).
    pub fn scan(&mut self, buf: &[u8]) -> Result<Scan, CodecError> {
        if self.head.is_none() {
            match parse_head::<E>(buf, self.protocol, self.contexts)? {
                Err(need) => {
                    return Ok(Scan::Incomplete {
                        need,
                        max_len: MAX_RESPONSE_CHUNK_LEN,
                    })
                }
                Ok(head) => {
                    let payload = ChunkScanner::with_bounds(head.bounds);
                    self.head = Some((head, payload));
                }
            }
        }
        let (head, payload) = self.head.as_mut().expect("head parsed above");
        Ok(payload.scan(&buf[head.len..])?.after(head.len))
    }

    /// The result code, once the result byte has been read.
    pub fn code(&self) -> Option<ResultCode> {
        self.head.as_ref().map(|(h, _)| h.code)
    }

    /// The fork the context bytes named, if the chunk has them and they have been read.
    pub fn fork(&self) -> Option<ForkName> {
        self.head.as_ref().and_then(|(h, _)| h.fork)
    }

    /// The payload's declared SSZ length, once its prefix has been read.
    pub fn declared_len(&self) -> Option<usize> {
        self.head.as_ref().and_then(|(_, p)| p.declared_len())
    }

    /// How many payload frames have been parsed so far.
    pub fn frames_scanned(&self) -> usize {
        self.head.as_ref().map_or(0, |(_, p)| p.frames_scanned())
    }
}

/// Scans one response chunk of `protocol` at the start of `buf`: a one-shot
/// [`ResponseChunkScanner`].
pub fn scan_response_chunk<E: EthSpec>(
    buf: &[u8],
    protocol: Protocol,
    contexts: &ContextTable,
) -> Result<Scan, CodecError> {
    ResponseChunkScanner::<E>::new(protocol, contexts).scan(buf)
}

/// Decodes `buf`, which must be exactly one response chunk of `protocol`.
pub fn decode_response_chunk<E: EthSpec>(
    buf: &[u8],
    protocol: Protocol,
    contexts: &ContextTable,
) -> Result<ResponseChunk<E>, CodecError> {
    let head = match parse_head::<E>(buf, protocol, contexts)? {
        Ok(head) => head,
        Err(_) => return Err(CodecError::Truncated),
    };
    let ssz = decode_chunk_within(&buf[head.len..], head.bounds)?;
    if head.code != ResultCode::Success {
        return Ok(ResponseChunk::Error {
            code: head.code,
            message: ErrorMessage::from_ssz_bytes(&ssz)?,
        });
    }
    let response = match protocol {
        Protocol::StatusV2 => Response::Status(StatusV2::from_ssz_bytes(&ssz)?),
        Protocol::MetaDataV3 => Response::MetaData(MetaDataV3::from_ssz_bytes(&ssz)?),
        Protocol::PingV1 => Response::Ping(Ping::from_ssz_bytes(&ssz)?),
        Protocol::BlocksByRangeV2 => {
            let fork = head.fork.ok_or(CodecError::MissingContext(protocol))?;
            Response::Block(Box::new(
                forked::SignedBeaconBlock::from_ssz_bytes_for_fork(&ssz, fork)?,
            ))
        }
        Protocol::GoodbyeV1 => Response::Goodbye(Goodbye::from_ssz_bytes(&ssz)?),
    };
    Ok(ResponseChunk::Success(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::messages::*;
    use crate::rpc::protocols::{Protocol, Request, Response, ResponseChunk, ResultCode};
    use crate::testkit;
    use consensus_types::caps::MAX_PAYLOAD_SIZE;
    use consensus_types::{forked, Minimal};
    use ssz::{Decode, Encode};

    type E = Minimal;

    const STREAM_IDENTIFIER: &[u8] = b"\xff\x06\x00\x00sNaPpY";

    /// A snappy frame of chunk type `ty` around `body` (the CRC, if any, is part of `body`).
    fn frame(ty: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len() as u32;
        let mut out = vec![ty, len as u8, (len >> 8) as u8, (len >> 16) as u8];
        out.extend_from_slice(body);
        out
    }

    fn varint(n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint(n, &mut out);
        out
    }

    /// The frames `snap` writes for `data`, without a length prefix.
    fn snappy_frames(data: &[u8]) -> Vec<u8> {
        let chunk = encode_chunk(data).unwrap();
        let (_, hdr) = decode_varint(&chunk).unwrap();
        chunk[hdr..].to_vec()
    }

    // --- varint ---

    #[test]
    fn varint_roundtrip_at_the_edges() {
        for n in [
            0,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let bytes = varint(n);
            assert!(bytes.len() <= MAX_VARINT_LEN);
            assert_eq!(decode_varint(&bytes), Ok((n, bytes.len())), "{n}");
        }
        assert_eq!(varint(300), [0xac, 0x02]);
        assert_eq!(varint(u64::MAX).len(), 10);
    }

    #[test]
    fn varint_over_10_bytes_rejected() {
        let eleven = [0xff; 11];
        assert_eq!(decode_varint(&eleven), Err(CodecError::VarintTooLong));
        // The 10th byte still has its continuation bit: refused without an 11th.
        assert_eq!(decode_varint(&[0x80; 10]), Err(CodecError::VarintTooLong));
        // Through the chunk decoder too, before any payload bound is looked at.
        assert_eq!(
            decode_chunk(&eleven, MAX_PAYLOAD_SIZE),
            Err(CodecError::VarintTooLong)
        );
        assert_eq!(
            scan_chunk(&[0x80; 10], MAX_PAYLOAD_SIZE),
            Err(CodecError::VarintTooLong)
        );
    }

    #[test]
    fn varint_overflow_and_non_minimal_rejected() {
        let mut over = vec![0xff; 9];
        over.push(0x02); // bit 64
        assert_eq!(decode_varint(&over), Err(CodecError::VarintOverflow));
        assert_eq!(
            decode_varint(&[0x80, 0x00]),
            Err(CodecError::VarintNotMinimal)
        );
        assert_eq!(decode_varint(&[0x81]), Err(CodecError::Truncated));
        assert_eq!(decode_varint(&[]), Err(CodecError::Truncated));
    }

    // --- payload framing ---

    #[test]
    fn max_compressed_len_is_the_spec_formula() {
        assert_eq!(max_compressed_len(0), 32);
        assert_eq!(max_compressed_len(6), 39);
        assert_eq!(
            max_compressed_len(MAX_PAYLOAD_SIZE),
            32 + MAX_PAYLOAD_SIZE + MAX_PAYLOAD_SIZE / 6
        );
    }

    #[test]
    fn chunk_is_length_prefix_then_snappy_frames() {
        let ssz = Ping(1).as_ssz_bytes();
        let chunk = encode_chunk(&ssz).unwrap();
        assert_eq!(chunk[0], 8, "uncompressed SSZ length");
        assert_eq!(&chunk[1..11], STREAM_IDENTIFIER);
        // 8 bytes do not compress: one uncompressed frame (type 1) of CRC + data.
        assert_eq!(&chunk[11..15], [0x01, 12, 0, 0]);
        assert_eq!(&chunk[19..], ssz);
        assert_eq!(decode_chunk(&chunk, 8).unwrap(), ssz);
    }

    #[test]
    fn empty_payload_is_just_the_prefix() {
        assert_eq!(encode_chunk(&[]).unwrap(), [0]);
        assert_eq!(decode_chunk(&[0], 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn large_payload_spans_frames() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let chunk = encode_chunk(&data).unwrap();
        assert_eq!(decode_chunk(&chunk, data.len()).unwrap(), data);
        assert!(chunk.len() <= MAX_VARINT_LEN + max_compressed_len(data.len()));
    }

    #[test]
    fn encode_refuses_more_than_max_payload_size() {
        let big = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(matches!(
            encode_chunk(&big),
            Err(CodecError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn length_prefix_over_type_bound_rejected() {
        let ssz = vec![0u8; 93];
        let chunk = encode_chunk(&ssz).unwrap();
        assert_eq!(
            decode_chunk(&chunk, 92),
            Err(CodecError::PayloadTooLarge { len: 93, max: 92 })
        );
    }

    #[test]
    fn length_prefix_under_type_bound_rejected() {
        // Status is fixed-size: a shorter payload is refused at its prefix, as a request and as
        // a response chunk, before a frame is read.
        let chunk = encode_chunk(&[0u8; 91]).unwrap();
        let err = CodecError::PayloadTooSmall { len: 91, min: 92 };
        assert_eq!(decode_request(Protocol::StatusV2, &chunk), Err(err.clone()));
        let mut response = vec![0];
        response.extend_from_slice(&chunk);
        let contexts = testkit::context_table();
        assert_eq!(
            scan_response_chunk::<E>(&response[..2], Protocol::StatusV2, &contexts),
            Err(err.clone())
        );
        assert_eq!(
            decode_response_chunk::<E>(&response, Protocol::StatusV2, &contexts),
            Err(err)
        );
        assert!(CodecError::PayloadTooSmall { len: 1, min: 2 }
            .to_string()
            .contains("below the type's minimum 2"));
        // A block shorter than any block's fixed parts.
        let tiny = encode_success_chunk(Some(testkit::GLOAS_DIGEST), &[0u8; 100]).unwrap();
        assert!(matches!(
            decode_response_chunk::<E>(&tiny, Protocol::BlocksByRangeV2, &contexts),
            Err(CodecError::PayloadTooSmall { len: 100, .. })
        ));
        // Error messages have no minimum.
        let empty = encode_error_chunk(ResultCode::ServerError, b"").unwrap();
        assert!(decode_response_chunk::<E>(&empty, Protocol::StatusV2, &contexts).is_ok());
    }

    #[test]
    fn truncated_frame_rejected() {
        let chunk = encode_chunk(&Ping(1).as_ssz_bytes()).unwrap();
        for cut in 0..chunk.len() {
            assert_eq!(
                decode_chunk(&chunk[..cut], 8),
                Err(CodecError::Truncated),
                "cut {cut}"
            );
        }
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut chunk = encode_chunk(&Ping(1).as_ssz_bytes()).unwrap();
        chunk.push(0);
        assert_eq!(decode_chunk(&chunk, 8), Err(CodecError::TrailingBytes(1)));
    }

    #[test]
    fn frames_past_the_length_prefix_rejected() {
        // The prefix says 4 bytes; the one frame holds 8. Snappy stops at 4, and the
        // remaining 4 decompressed bytes are an error.
        let mut chunk = varint(4);
        chunk.extend(snappy_frames(&Ping(1).as_ssz_bytes()));
        assert_eq!(
            decode_chunk(&chunk, 8),
            Err(CodecError::PayloadOverrun { len: 4 })
        );
    }

    #[test]
    fn compressed_over_max_compressed_len_rejected() {
        // 8 bytes allow 32 + 8 + 1 = 41 compressed bytes. Padding frames (type 0xfe) are
        // valid snappy, so only the length bound stops them.
        let mut chunk = varint(8);
        chunk.extend_from_slice(STREAM_IDENTIFIER);
        chunk.extend(frame(0xfe, &[0; 40]));
        chunk.extend(&snappy_frames(&Ping(1).as_ssz_bytes())[STREAM_IDENTIFIER.len()..]);
        let err = CodecError::CompressedTooLarge { len: 8, max: 41 };
        assert_eq!(decode_chunk(&chunk, 8), Err(err.clone()));
        // The scanner refuses at the frame header, before the frame body is read.
        let at_header = varint(8).len() + STREAM_IDENTIFIER.len() + 4;
        assert_eq!(scan_chunk(&chunk[..at_header], 8), Err(err));
    }

    #[test]
    fn snappy_bomb_rejected() {
        // At most 1 KiB of input that declares MAX_PAYLOAD_SIZE + 1 bytes: refused at the
        // prefix, so neither the frames nor an output buffer are touched.
        let declared = MAX_PAYLOAD_SIZE + 1;
        let mut bomb = varint(declared as u64);
        bomb.extend(snappy_frames(&[0u8; 16_384]));
        assert!(bomb.len() <= 1024, "{} bytes", bomb.len());
        let err = CodecError::PayloadTooLarge {
            len: declared as u64,
            max: MAX_PAYLOAD_SIZE,
        };
        assert_eq!(decode_chunk(&bomb, usize::MAX), Err(err.clone()));
        assert_eq!(scan_chunk(&bomb[..4], usize::MAX), Err(err));
    }

    #[test]
    fn reserved_frame_type_rejected() {
        let mut chunk = varint(8);
        chunk.extend_from_slice(STREAM_IDENTIFIER);
        chunk.extend(frame(0x02, &[0; 12]));
        assert!(matches!(
            decode_chunk(&chunk, 8),
            Err(CodecError::Snappy(_))
        ));
    }

    #[test]
    fn corrupt_crc_rejected() {
        let mut chunk = encode_chunk(&Ping(1).as_ssz_bytes()).unwrap();
        chunk[15] ^= 1;
        assert!(matches!(
            decode_chunk(&chunk, 8),
            Err(CodecError::Snappy(_))
        ));
    }

    #[test]
    fn scan_asks_for_exactly_what_it_needs() {
        let chunk = encode_chunk(&testkit::status().as_ssz_bytes()).unwrap();
        let mut have = 0;
        let mut steps = 0;
        loop {
            match scan_chunk(&chunk[..have], 92).unwrap() {
                Scan::Incomplete { need, max_len } => {
                    assert!(have + need <= chunk.len(), "over-read at {have}");
                    assert!(
                        max_len >= chunk.len()
                            && max_len <= MAX_VARINT_LEN + max_compressed_len(92)
                    );
                    have += need;
                }
                Scan::Complete { len } => {
                    assert_eq!(len, chunk.len());
                    break;
                }
            }
            steps += 1;
        }
        // prefix, stream-identifier header and body, data-frame header and body
        assert_eq!(steps, 5);
    }

    // --- requests and response chunks ---

    fn roundtrip_success<T: Encode>(protocol: Protocol, value: &T) -> Response<E> {
        let ssz = value.as_ssz_bytes();
        let chunk = encode_success_chunk(None, &ssz).unwrap();
        assert_eq!(chunk[0], 0);
        let decoded = decode_response_chunk::<E>(&chunk, protocol, &testkit::context_table());
        let ResponseChunk::Success(response) = decoded.unwrap() else {
            panic!("not a success chunk")
        };
        response
    }

    #[test]
    fn roundtrip_status_v2() {
        let status = testkit::status();
        let request = Request::Status(status.clone());
        let bytes = encode_request(&request).unwrap();
        assert_eq!(decode_request(Protocol::StatusV2, &bytes).unwrap(), request);
        assert_eq!(
            encode_request(&decode_request(Protocol::StatusV2, &bytes).unwrap()).unwrap(),
            bytes
        );
        let response = roundtrip_success(Protocol::StatusV2, &status);
        assert_eq!(response, Response::Status(status));
    }

    #[test]
    fn roundtrip_metadata_v3() {
        // The request is empty: nothing at all goes on the wire.
        assert_eq!(
            encode_request(&Request::MetaData).unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(
            decode_request(Protocol::MetaDataV3, &[]).unwrap(),
            Request::MetaData
        );
        assert_eq!(
            decode_request(Protocol::MetaDataV3, &[0]),
            Err(CodecError::TrailingBytes(1))
        );
        let metadata = testkit::metadata();
        let ssz = metadata.as_ssz_bytes();
        assert_eq!(ssz.len(), 25);
        let response = roundtrip_success(Protocol::MetaDataV3, &metadata);
        assert_eq!(response, Response::MetaData(metadata.clone()));
        let chunk = encode_success_chunk(None, &ssz).unwrap();
        let Response::MetaData(again) = roundtrip_success(Protocol::MetaDataV3, &metadata) else {
            unreachable!()
        };
        assert_eq!(
            encode_success_chunk(None, &again.as_ssz_bytes()).unwrap(),
            chunk
        );
    }

    #[test]
    fn roundtrip_ping() {
        let request = Request::Ping(Ping(0x0102_0304_0506_0708));
        let bytes = encode_request(&request).unwrap();
        assert_eq!(&bytes[19..], [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(decode_request(Protocol::PingV1, &bytes).unwrap(), request);
        let response = roundtrip_success(Protocol::PingV1, &Ping(9));
        assert_eq!(response, Response::Ping(Ping(9)));
    }

    #[test]
    fn roundtrip_goodbye() {
        let goodbye = Goodbye(3);
        let ssz = goodbye.as_ssz_bytes();
        assert_eq!(ssz, 3u64.to_le_bytes());
        let chunk = encode_chunk(&ssz).unwrap();
        let back = Goodbye::from_ssz_bytes(&decode_chunk(&chunk, 8).unwrap()).unwrap();
        assert_eq!(back, goodbye);
        assert_eq!(encode_chunk(&back.as_ssz_bytes()).unwrap(), chunk);
        // As a request on its own protocol.
        let request = Request::Goodbye(goodbye);
        let bytes = encode_request(&request).unwrap();
        assert_eq!(bytes, chunk);
        assert_eq!(decode_request(Protocol::GoodbyeV1, &bytes), Ok(request));
        // Its response is one Goodbye chunk too; an error chunk decodes as on any protocol.
        let contexts = testkit::context_table();
        let success = encode_success_chunk(None, &ssz).unwrap();
        assert_eq!(
            decode_response_chunk::<E>(&success, Protocol::GoodbyeV1, &contexts),
            Ok(ResponseChunk::Success(Response::Goodbye(goodbye)))
        );
        assert_eq!(
            scan_response_chunk::<E>(&success, Protocol::GoodbyeV1, &contexts),
            Ok(Scan::Complete { len: success.len() })
        );
        let long = encode_success_chunk(None, &[0; 9]).unwrap();
        assert!(decode_response_chunk::<E>(&long, Protocol::GoodbyeV1, &contexts).is_err());
        let error = encode_error_chunk(ResultCode::ServerError, b"no").unwrap();
        assert!(matches!(
            decode_response_chunk::<E>(&error, Protocol::GoodbyeV1, &contexts),
            Ok(ResponseChunk::Error {
                code: ResultCode::ServerError,
                ..
            })
        ));
    }

    #[test]
    fn roundtrip_blocks_by_range_req() {
        let request = Request::BlocksByRange(BlocksByRangeV2Request {
            start_slot: 64,
            count: 2,
            step: 1,
        });
        let bytes = encode_request(&request).unwrap();
        let back = decode_request(Protocol::BlocksByRangeV2, &bytes).unwrap();
        assert_eq!(back, request);
        assert_eq!(encode_request(&back).unwrap(), bytes);
        // A request is never decoded on another protocol's bound.
        assert!(matches!(
            decode_request(Protocol::PingV1, &bytes),
            Err(CodecError::PayloadTooLarge { len: 24, max: 8 })
        ));
    }

    #[test]
    fn block_chunks_decode_by_their_context() {
        let contexts = testkit::context_table();
        let fulu = testkit::fulu_block::<E>(1);
        let gloas = testkit::gloas_block::<E>(2);
        let cases = [
            (
                testkit::FULU_DIGEST,
                fulu.as_ssz_bytes(),
                forked::SignedBeaconBlock::Fulu(fulu.clone()),
            ),
            (
                testkit::FULU_BPO_DIGEST,
                fulu.as_ssz_bytes(),
                forked::SignedBeaconBlock::Fulu(fulu),
            ),
            (
                testkit::GLOAS_DIGEST,
                gloas.as_ssz_bytes(),
                forked::SignedBeaconBlock::Gloas(gloas),
            ),
        ];
        for (digest, ssz, block) in cases {
            let chunk = encode_success_chunk(Some(digest), &ssz).unwrap();
            assert_eq!(&chunk[1..5], digest);
            let decoded =
                decode_response_chunk::<E>(&chunk, Protocol::BlocksByRangeV2, &contexts).unwrap();
            assert_eq!(
                decoded,
                ResponseChunk::Success(Response::Block(Box::new(block)))
            );
        }
    }

    #[test]
    fn block_in_the_wrong_fork_shape_fails_ssz() {
        let ssz = testkit::fulu_block::<E>(1).as_ssz_bytes();
        let chunk = encode_success_chunk(Some(testkit::GLOAS_DIGEST), &ssz).unwrap();
        let err = decode_response_chunk::<E>(
            &chunk,
            Protocol::BlocksByRangeV2,
            &testkit::context_table(),
        );
        assert!(matches!(err, Err(CodecError::Decode(_))), "{err:?}");
    }

    #[test]
    fn error_chunk_codes_1_to_3() {
        let contexts = testkit::context_table();
        let codes = [
            ResultCode::InvalidRequest,
            ResultCode::ServerError,
            ResultCode::ResourceUnavailable,
        ];
        for (code, byte) in codes.into_iter().zip(1u8..) {
            let chunk = encode_error_chunk(code, b"no").unwrap();
            assert_eq!(chunk[0], byte);
            // No context bytes, even on a protocol that has them: the prefix follows directly.
            assert_eq!(chunk[1], 2);
            for protocol in Protocol::ALL {
                let decoded = decode_response_chunk::<E>(&chunk, protocol, &contexts).unwrap();
                let ResponseChunk::Error { code: got, message } = decoded else {
                    panic!("{protocol}: not an error chunk")
                };
                assert_eq!(got, code);
                assert_eq!(&message[..], b"no");
            }
        }
    }

    #[test]
    fn error_message_over_256_bytes_rejected() {
        assert!(matches!(
            encode_error_chunk(ResultCode::ServerError, &[b'x'; 257]),
            Err(CodecError::PayloadTooLarge { len: 257, max: 256 })
        ));
        let mut chunk = vec![2];
        chunk.extend(encode_chunk(&[b'x'; 257]).unwrap());
        assert_eq!(
            decode_response_chunk::<E>(&chunk, Protocol::PingV1, &testkit::context_table()),
            Err(CodecError::PayloadTooLarge { len: 257, max: 256 })
        );
        assert!(encode_error_chunk(ResultCode::Success, b"").is_err());
    }

    #[test]
    fn result_code_4_and_up_rejected_before_decode() {
        let contexts = testkit::context_table();
        for code in [4u8, 127, 128, 255] {
            // Only the result byte: refused without waiting for anything after it.
            assert_eq!(
                scan_response_chunk::<E>(&[code], Protocol::BlocksByRangeV2, &contexts),
                Err(CodecError::InvalidResultCode(code))
            );
            let mut chunk = vec![code];
            chunk.extend(encode_chunk(b"x").unwrap());
            assert_eq!(
                decode_response_chunk::<E>(&chunk, Protocol::PingV1, &contexts),
                Err(CodecError::InvalidResultCode(code))
            );
        }
    }

    #[test]
    fn unknown_context_rejected_before_decode() {
        let contexts = testkit::context_table();
        let head = [0, 0xde, 0xad, 0xbe, 0xef];
        assert_eq!(head[1..], testkit::UNKNOWN_DIGEST);
        // Result byte and digest only: the prefix is never read.
        assert_eq!(
            scan_response_chunk::<E>(&head, Protocol::BlocksByRangeV2, &contexts),
            Err(CodecError::UnknownContext(testkit::UNKNOWN_DIGEST))
        );
        let ssz = testkit::fulu_block::<E>(1).as_ssz_bytes();
        let chunk = encode_success_chunk(Some(testkit::UNKNOWN_DIGEST), &ssz).unwrap();
        assert_eq!(
            decode_response_chunk::<E>(&chunk, Protocol::BlocksByRangeV2, &contexts),
            Err(CodecError::UnknownContext(testkit::UNKNOWN_DIGEST))
        );
        assert_eq!(
            decode_response_chunk::<E>(&chunk, Protocol::BlocksByRangeV2, &ContextTable::new()),
            Err(CodecError::UnknownContext(testkit::UNKNOWN_DIGEST))
        );
    }

    #[test]
    fn response_payload_over_its_type_bound_rejected() {
        let mut chunk = vec![0];
        chunk.extend(encode_chunk(&[0; 93]).unwrap());
        assert_eq!(
            decode_response_chunk::<E>(&chunk, Protocol::StatusV2, &testkit::context_table()),
            Err(CodecError::PayloadTooLarge { len: 93, max: 92 })
        );
    }

    #[test]
    fn response_chunk_scan_and_trailing_bytes() {
        let contexts = testkit::context_table();
        let ssz = testkit::gloas_block::<E>(3).as_ssz_bytes();
        let chunk = encode_success_chunk(Some(testkit::GLOAS_DIGEST), &ssz).unwrap();
        let p = Protocol::BlocksByRangeV2;
        assert_eq!(
            scan_response_chunk::<E>(&chunk, p, &contexts),
            Ok(Scan::Complete { len: chunk.len() })
        );
        assert!(matches!(
            scan_response_chunk::<E>(&chunk[..3], p, &contexts),
            Ok(Scan::Incomplete { need: 2, .. })
        ));
        assert!(matches!(
            scan_response_chunk::<E>(&[], p, &contexts),
            Ok(Scan::Incomplete { need: 1, .. })
        ));
        let mut two = chunk.clone();
        two.extend_from_slice(&chunk);
        assert_eq!(
            scan_response_chunk::<E>(&two, p, &contexts),
            Ok(Scan::Complete { len: chunk.len() })
        );
        assert_eq!(
            decode_response_chunk::<E>(&two, p, &contexts),
            Err(CodecError::TrailingBytes(chunk.len()))
        );
        assert_eq!(
            decode_response_chunk::<E>(&chunk[..chunk.len() - 1], p, &contexts),
            Err(CodecError::Truncated)
        );
    }

    #[test]
    fn context_table_lookup() {
        let mut table = ContextTable::new();
        assert_eq!(table.fork(&testkit::FULU_DIGEST), None);
        assert_eq!(table.insert(testkit::FULU_DIGEST, ForkName::Fulu), None);
        assert_eq!(
            table.insert(testkit::FULU_DIGEST, ForkName::Gloas),
            Some(ForkName::Fulu)
        );
        assert_eq!(table.fork(&testkit::FULU_DIGEST), Some(ForkName::Gloas));
        assert_eq!(
            testkit::context_table().fork(&testkit::GLOAS_DIGEST),
            Some(ForkName::Gloas)
        );
    }

    // --- scan work and frame bounds ---

    /// The bytes of `frames` 64-byte data frames: incompressible, so one uncompressed frame
    /// each, which keeps the payload under `max_compressed_len`.
    fn frame_data(frames: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9u32;
        (0..frames * 64)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    /// `data` as the stream identifier and one data frame per 64 bytes.
    fn small_frames(data: &[u8]) -> Vec<u8> {
        let mut out = varint(data.len() as u64);
        out.extend_from_slice(STREAM_IDENTIFIER);
        for piece in data.chunks(64) {
            out.extend(&snappy_frames(piece)[STREAM_IDENTIFIER.len()..]);
        }
        out
    }

    /// Feeds `buf` to `scanner` the way a transport does: exactly `need` more bytes each time.
    fn feed(scanner: &mut ChunkScanner, buf: &[u8]) -> (Result<Scan, CodecError>, usize) {
        let (mut have, mut calls) = (0, 0);
        loop {
            calls += 1;
            match scanner.scan(&buf[..have]) {
                Ok(Scan::Incomplete { need, .. }) if have + need <= buf.len() => have += need,
                other => return (other, calls),
            }
        }
    }

    #[test]
    fn incremental_scan_parses_each_frame_once() {
        let frames = 2000;
        let data = frame_data(frames);
        let n = data.len();
        let chunk = small_frames(&data);
        let mut scanner = ChunkScanner::new(n);
        let (scan, calls) = feed(&mut scanner, &chunk);
        assert_eq!(scan, Ok(Scan::Complete { len: chunk.len() }));
        // Stream identifier plus one frame per 64 bytes, each parsed once, in ~2 calls a frame.
        assert_eq!(scanner.frames_scanned(), frames + 1);
        assert!(calls <= 2 * (frames + 1) + 4, "{calls} calls");
        assert_eq!(scanner.declared_len(), Some(n));
        assert_eq!(decode_chunk(&chunk, n).unwrap(), data);
        // The stateless entry point gives the same answer.
        assert_eq!(
            scan_chunk(&chunk, n),
            Ok(Scan::Complete { len: chunk.len() })
        );
    }

    #[test]
    fn padding_frames_are_capped() {
        // A 10 MiB prefix, the stream identifier and endless empty padding frames: refused after
        // MAX_EMPTY_FRAMES frames that hold no data, long before max_compressed_len.
        let mut chunk = varint(MAX_PAYLOAD_SIZE as u64);
        chunk.extend_from_slice(STREAM_IDENTIFIER);
        for _ in 0..MAX_EMPTY_FRAMES * 4 {
            chunk.extend_from_slice(&[0xfe, 0, 0, 0]);
        }
        let mut scanner = ChunkScanner::new(MAX_PAYLOAD_SIZE);
        let (scan, _) = feed(&mut scanner, &chunk);
        assert_eq!(
            scan,
            Err(CodecError::TooManyEmptyFrames {
                max: MAX_EMPTY_FRAMES
            })
        );
        assert_eq!(scanner.frames_scanned(), MAX_EMPTY_FRAMES + 1);
        assert_eq!(
            decode_chunk(&chunk, MAX_PAYLOAD_SIZE),
            Err(CodecError::TooManyEmptyFrames {
                max: MAX_EMPTY_FRAMES
            })
        );
        // Empty data frames (a CRC and nothing else) count too.
        let mut empty_data = varint(MAX_PAYLOAD_SIZE as u64);
        empty_data.extend_from_slice(STREAM_IDENTIFIER);
        for _ in 0..MAX_EMPTY_FRAMES {
            empty_data.extend(frame(0x01, &[0; 4]));
        }
        assert_eq!(
            scan_chunk(&empty_data, MAX_PAYLOAD_SIZE),
            Err(CodecError::TooManyEmptyFrames {
                max: MAX_EMPTY_FRAMES
            })
        );
        // A few skippable frames, as a compliant encoder might add, still decode.
        let mut few = varint(8);
        few.extend_from_slice(STREAM_IDENTIFIER);
        few.extend(frame(0x80, &[]));
        few.extend(frame(0xfe, &[0; 2]));
        few.extend(&snappy_frames(&Ping(1).as_ssz_bytes())[STREAM_IDENTIFIER.len()..]);
        assert_eq!(decode_chunk(&few, 8).unwrap(), Ping(1).as_ssz_bytes());
    }

    #[test]
    fn frame_header_past_the_limit_rejected_without_waiting() {
        // 8 bytes allow 41 compressed bytes. The stream identifier (10) and a 27-byte padding
        // frame (31) use all 41; the next frame header cannot fit, so the scan refuses at once
        // instead of asking for 4 more bytes.
        let mut chunk = varint(8);
        chunk.extend_from_slice(STREAM_IDENTIFIER);
        chunk.extend(frame(0xfe, &[0; 27]));
        assert_eq!(chunk.len(), 1 + 41);
        assert_eq!(
            scan_chunk(&chunk, 8),
            Err(CodecError::CompressedTooLarge { len: 8, max: 41 })
        );
    }

    #[test]
    fn oversized_frame_body_rejected_before_read() {
        let header = |ty: u8, len: usize| {
            let mut c = varint(MAX_PAYLOAD_SIZE as u64);
            c.extend_from_slice(STREAM_IDENTIFIER);
            c.extend_from_slice(&[ty, len as u8, (len >> 8) as u8, (len >> 16) as u8]);
            c
        };
        // Header only: refused without waiting for (or buffering) the body.
        let compressed = header(0x00, MAX_FRAME_BODY_LEN + 1);
        assert_eq!(
            scan_chunk(&compressed, MAX_PAYLOAD_SIZE),
            Err(CodecError::FrameTooLarge {
                len: MAX_FRAME_BODY_LEN + 1
            })
        );
        let padding = header(0xfe, 1_000_000);
        assert_eq!(
            scan_chunk(&padding, MAX_PAYLOAD_SIZE),
            Err(CodecError::FrameTooLarge { len: 1_000_000 })
        );
        let uncompressed = header(0x01, MAX_UNCOMPRESSED_FRAME_BODY_LEN + 1);
        assert_eq!(
            scan_chunk(&uncompressed, MAX_PAYLOAD_SIZE),
            Err(CodecError::FrameTooLarge {
                len: MAX_UNCOMPRESSED_FRAME_BODY_LEN + 1
            })
        );
        // A compressed frame whose block claims more than 64 KiB of output.
        let mut body = vec![0; 4];
        body.extend(varint(65_537));
        let mut claim = varint(MAX_PAYLOAD_SIZE as u64);
        claim.extend_from_slice(STREAM_IDENTIFIER);
        claim.extend(frame(0x00, &body));
        assert_eq!(
            scan_chunk(&claim, MAX_PAYLOAD_SIZE),
            Err(CodecError::FrameTooLarge { len: 65_537 })
        );
        // The largest frames snap writes still pass.
        let data: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let chunk = encode_chunk(&data).unwrap();
        assert_eq!(decode_chunk(&chunk, data.len()).unwrap(), data);
    }

    #[test]
    fn response_scanner_resumes_and_reports_the_head() {
        let contexts = testkit::context_table();
        let ssz = testkit::gloas_block::<E>(3).as_ssz_bytes();
        let chunk = encode_success_chunk(Some(testkit::GLOAS_DIGEST), &ssz).unwrap();
        let mut scanner = ResponseChunkScanner::<E>::new(Protocol::BlocksByRangeV2, &contexts);
        let mut have = 0;
        loop {
            match scanner.scan(&chunk[..have]).unwrap() {
                Scan::Incomplete { need, .. } => have += need,
                Scan::Complete { len } => {
                    assert_eq!(len, chunk.len());
                    break;
                }
            }
        }
        assert_eq!(scanner.fork(), Some(ForkName::Gloas));
        assert_eq!(scanner.declared_len(), Some(ssz.len()));
        assert_eq!(scanner.code(), Some(ResultCode::Success));
        assert!(scanner.frames_scanned() >= 2);
        let decoded = decode_response_chunk::<E>(&chunk, Protocol::BlocksByRangeV2, &contexts);
        assert!(decoded.is_ok());
    }
}
