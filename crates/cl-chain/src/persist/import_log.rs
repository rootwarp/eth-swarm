//! `import.log`: one frame per imported block, appended and fsync'd by
//! [`FileSet::record_import`](super::durable::FileSet::record_import).
//!
//! A frame is `len (u32 LE) ‖ crc32c(record) (u32 LE) ‖ record`, and a record is
//! `root (32) ‖ slot (u64 BE) ‖ payload_status (u8) ‖ el_status (u8)`: [`RECORD_LEN`] = 42,
//! [`FRAME_LEN`] = 50 bytes. A length other than [`RECORD_LEN`], a CRC mismatch or a status byte
//! no variant has makes a frame bad.
//!
//! Loading ([`parse`]): frames are read from the start. The writer fsyncs each frame before it
//! writes the next, so only the last frame can be torn by a crash. A bad or short frame with at
//! most one frame's bytes from its start to the end of the file is that last frame: the log is
//! cut there and loading continues. A bad frame with more bytes after it is damage to data that
//! was already durable: the load refuses ([`Error::CorruptImportLog`](super::durable::Error)).

use super::crc32c::crc32c;

/// Length of an encoded [`ImportRecord`].
pub(super) const RECORD_LEN: usize = 32 + 8 + 1 + 1;
/// Length of one frame: the 8-byte header and the record.
pub(super) const FRAME_LEN: usize = 8 + RECORD_LEN;

/// Whether the block's execution payload was in when it was imported. The byte values are Gloas
/// fork choice's `PayloadStatus` constants (consensus-specs v1.7.0-beta.4,
/// `specs/gloas/fork-choice.md` L103-105): `PAYLOAD_STATUS_EMPTY = 0`,
/// `PAYLOAD_STATUS_FULL = 1`, `PAYLOAD_STATUS_PENDING = 2`. A Fulu block carries its payload:
/// [`PayloadStatus::Full`].
///
/// #182 may add variants (new byte values); a byte no variant has is a bad record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PayloadStatus {
    /// Gloas `PAYLOAD_STATUS_EMPTY`: the builder did not reveal the payload.
    Empty = 0,
    /// Gloas `PAYLOAD_STATUS_FULL`: the payload is in.
    Full = 1,
    /// Gloas `PAYLOAD_STATUS_PENDING`: the payload envelope was not seen yet.
    Pending = 2,
}

/// The execution layer's verdict on the block's payload at import.
///
/// #182 may add variants (new byte values); a byte no variant has is a bad record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ElStatus {
    /// No payload was checked with this import ([`PayloadStatus::Pending`] or
    /// [`PayloadStatus::Empty`]).
    NotVerified = 0,
    /// `VALID`.
    Valid = 1,
    /// Imported optimistically: `SYNCING` or `ACCEPTED`.
    Optimistic = 2,
}

/// One imported block, as `import.log` records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ImportRecord {
    /// The block root.
    pub root: [u8; 32],
    /// The block's slot.
    pub slot: u64,
    /// Whether its payload was in.
    pub payload_status: PayloadStatus,
    /// The EL's verdict on it.
    pub el_status: ElStatus,
}

impl ImportRecord {
    fn encode(&self) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[..32].copy_from_slice(&self.root);
        out[32..40].copy_from_slice(&self.slot.to_be_bytes());
        out[40] = self.payload_status as u8;
        out[41] = self.el_status as u8;
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; RECORD_LEN] = bytes.try_into().ok()?;
        let payload_status = match bytes[40] {
            0 => PayloadStatus::Empty,
            1 => PayloadStatus::Full,
            2 => PayloadStatus::Pending,
            _ => return None,
        };
        let el_status = match bytes[41] {
            0 => ElStatus::NotVerified,
            1 => ElStatus::Valid,
            2 => ElStatus::Optimistic,
            _ => return None,
        };
        Some(Self {
            root: bytes[..32].try_into().ok()?,
            slot: u64::from_be_bytes(bytes[32..40].try_into().ok()?),
            payload_status,
            el_status,
        })
    }
}

/// The frame of `record`.
pub(super) fn frame(record: &ImportRecord) -> [u8; FRAME_LEN] {
    let body = record.encode();
    let mut out = [0u8; FRAME_LEN];
    out[..4].copy_from_slice(&(RECORD_LEN as u32).to_le_bytes());
    out[4..8].copy_from_slice(&crc32c(&body).to_le_bytes());
    out[8..].copy_from_slice(&body);
    out
}

/// The record of a whole, good frame at the start of `rest`.
fn record_at(rest: &[u8]) -> Option<ImportRecord> {
    let frame = rest.get(..FRAME_LEN)?;
    let (len, crc, body) = (&frame[..4], &frame[4..8], &frame[8..]);
    if *len != (RECORD_LEN as u32).to_le_bytes() || *crc != crc32c(body).to_le_bytes() {
        return None;
    }
    ImportRecord::decode(body)
}

/// The records of a log and the length of its good prefix (shorter than `log` if its last
/// frame is torn or bad: the caller cuts it there). `Err(offset)`: a bad frame at `offset`
/// with more than one frame's bytes after it.
pub(super) fn parse(log: &[u8]) -> Result<(Vec<ImportRecord>, usize), u64> {
    let mut records = Vec::with_capacity(log.len() / FRAME_LEN);
    let mut at = 0;
    while at < log.len() {
        let rest = &log[at..];
        match record_at(rest) {
            Some(record) => records.push(record),
            None if rest.len() <= FRAME_LEN => break,
            None => return Err(at as u64),
        }
        at += FRAME_LEN;
    }
    Ok((records, at))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(n: u8) -> ImportRecord {
        ImportRecord {
            root: [n; 32],
            slot: u64::from(n) << 40,
            payload_status: PayloadStatus::Full,
            el_status: ElStatus::Optimistic,
        }
    }

    fn log(records: &[ImportRecord]) -> Vec<u8> {
        records.iter().flat_map(frame).collect()
    }

    #[test]
    fn a_record_is_root_slot_and_two_status_bytes() {
        let bytes = rec(3).encode();
        assert_eq!(bytes.len(), RECORD_LEN);
        assert_eq!(&bytes[..32], &[3; 32]);
        assert_eq!(&bytes[32..40], &(3u64 << 40).to_be_bytes());
        assert_eq!(bytes[40..], [1, 2]);
        assert_eq!(ImportRecord::decode(&bytes), Some(rec(3)));
        for (status, byte) in [
            (ElStatus::NotVerified, 0),
            (ElStatus::Valid, 1),
            (ElStatus::Optimistic, 2),
        ] {
            assert_eq!(status as u8, byte);
        }
        // An unknown status byte is no record.
        for at in [40, 41] {
            let mut bad = bytes;
            bad[at] = 3;
            assert_eq!(ImportRecord::decode(&bad), None);
        }
        assert_eq!(ImportRecord::decode(&bytes[..41]), None);
    }

    /// consensus-specs v1.7.0-beta.4, `specs/gloas/fork-choice.md` L103-105 (Constants):
    /// `PAYLOAD_STATUS_EMPTY = PayloadStatus(0)`, `PAYLOAD_STATUS_FULL = PayloadStatus(1)`,
    /// `PAYLOAD_STATUS_PENDING = PayloadStatus(2)`.
    #[test]
    fn payload_status_bytes_are_the_gloas_fork_choice_constants() {
        for (status, byte) in [
            (PayloadStatus::Empty, 0),
            (PayloadStatus::Full, 1),
            (PayloadStatus::Pending, 2),
        ] {
            assert_eq!(status as u8, byte, "{status:?}");
            let mut bytes = rec(1).encode();
            bytes[40] = byte;
            let decoded = ImportRecord::decode(&bytes).map(|r| r.payload_status);
            assert_eq!(decoded, Some(status), "byte {byte}");
        }
    }

    #[test]
    fn a_frame_is_length_crc_and_record() {
        let f = frame(&rec(1));
        assert_eq!(f.len(), FRAME_LEN);
        assert_eq!(&f[..4], &(RECORD_LEN as u32).to_le_bytes());
        assert_eq!(&f[4..8], &crc32c(&f[8..]).to_le_bytes());
        assert_eq!(&f[8..], &rec(1).encode());
    }

    #[test]
    fn parse_keeps_whole_frames_and_cuts_only_the_last() {
        let whole = log(&[rec(1), rec(2), rec(3)]);
        assert_eq!(
            parse(&whole),
            Ok((vec![rec(1), rec(2), rec(3)], whole.len()))
        );
        assert_eq!(parse(&[]), Ok((vec![], 0)));
        // Torn: any prefix of the last frame.
        for cut in 1..FRAME_LEN {
            let torn = &whole[..2 * FRAME_LEN + cut];
            assert_eq!(
                parse(torn),
                Ok((vec![rec(1), rec(2)], 2 * FRAME_LEN)),
                "{cut}"
            );
        }
        // A bad last frame, any byte of it.
        for at in 2 * FRAME_LEN..3 * FRAME_LEN {
            let mut bad = whole.clone();
            bad[at] ^= 0x10;
            assert_eq!(
                parse(&bad),
                Ok((vec![rec(1), rec(2)], 2 * FRAME_LEN)),
                "{at}"
            );
        }
        // A bad frame with more than one frame's bytes after its start: refuse.
        for at in 0..2 * FRAME_LEN {
            let mut bad = whole.clone();
            bad[at] ^= 0x10;
            let offset = (at / FRAME_LEN * FRAME_LEN) as u64;
            assert_eq!(parse(&bad), Err(offset), "{at}");
        }
        // A bad frame followed by a torn one: two frames never were in flight at once.
        let mut bad = whole[..2 * FRAME_LEN + 1].to_vec();
        bad[FRAME_LEN + 9] ^= 1;
        assert_eq!(parse(&bad), Err(FRAME_LEN as u64));
    }
}
