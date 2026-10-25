//! A node record (EIP-778) in its textual form, read for one field at a time: the `eth2` field
//! ([`eth2_fork_id`]) that m2a-session compares with the reference node's, and the `cgc` field
//! ([`custody_group_count`]) that cl-p2p compares with its custody group count in cl-discv5's
//! own record (`GetLocalEnr`).
//!
//! The textual form is `enr:` and the URL-safe base64 of the record's RLP, without padding. The
//! record is `[signature, seq, k1, v1, k2, v2, ...]` with keys sorted and unique, at most 300
//! bytes. The `eth2` value is the SSZ `ENRForkID` (`phase0/p2p-interface.md`): `fork_digest`
//! (4 bytes), `next_fork_version` (4) and `next_fork_epoch` (`uint64`, little-endian), 16
//! bytes in all. The `cgc` value is a big-endian integer with no leading zero byte
//! (`fulu/p2p-interface.md`, [`p2p_wire::enr::decode_cgc`]).
//!
//! The signature is not verified: each record comes from a source that its reader trusts (the
//! reference node's own API, or cl-discv5 behind its socket's peer check), and only one field is
//! compared.

use p2p_wire::enr::{decode_cgc, EnrFieldError, CGC_KEY, ETH2_KEY};

/// The largest record EIP-778 allows.
pub const MAX_RECORD_LEN: usize = 300;

/// The longest record text read: `enr:` and the base64 of [`MAX_RECORD_LEN`] bytes (404 bytes),
/// with room. A longer text is refused before it is decoded, so a peer service cannot make the
/// reader decode an unbounded text.
pub const MAX_TEXT_LEN: usize = 512;

/// `ENRForkID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrForkId {
    /// The node's current fork digest.
    pub fork_digest: [u8; 4],
    /// The next scheduled fork version.
    pub next_fork_version: [u8; 4],
    /// The next scheduled fork epoch.
    pub next_fork_epoch: u64,
}

/// Why a record was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnrError {
    /// No `enr:` prefix, or not unpadded URL-safe base64.
    #[error("not an enr: text record")]
    Text,
    /// A text of more than [`MAX_TEXT_LEN`] bytes, not decoded.
    #[error("record text of {0} bytes, over {MAX_TEXT_LEN}")]
    TextTooLong(usize),
    /// More than [`MAX_RECORD_LEN`] bytes.
    #[error("record of {0} bytes, over {MAX_RECORD_LEN}")]
    TooLong(usize),
    /// Not a canonical RLP list of byte strings, as a record must be.
    #[error("malformed RLP: {0}")]
    Rlp(&'static str),
    /// The keys are not sorted and unique.
    #[error("keys are not sorted and unique")]
    KeyOrder,
    /// No `eth2` key.
    #[error("no eth2 field")]
    NoEth2,
    /// The `eth2` value is not 16 bytes.
    #[error("eth2 field of {0} bytes, want 16")]
    Eth2Len(usize),
    /// No `cgc` key.
    #[error("no cgc field")]
    NoCgc,
    /// The `cgc` value is not a canonical `uint64`.
    #[error("cgc field: {0}")]
    Cgc(EnrFieldError),
}

/// One RLP item: a byte string or a list's payload.
enum Item<'a> {
    Bytes(&'a [u8]),
    List(&'a [u8]),
}

/// A big-endian length of `n` bytes, canonical (no leading zero, and at least 56).
fn long_len(buf: &[u8], n: usize) -> Result<usize, EnrError> {
    let bytes = buf.get(..n).ok_or(EnrError::Rlp("truncated length"))?;
    if bytes.first() == Some(&0) {
        return Err(EnrError::Rlp("length with a leading zero"));
    }
    let len = bytes
        .iter()
        .try_fold(0usize, |acc, &b| {
            acc.checked_mul(256).map(|a| a | usize::from(b))
        })
        .ok_or(EnrError::Rlp("length overflow"))?;
    if len < 56 {
        return Err(EnrError::Rlp("long form for a short item"));
    }
    Ok(len)
}

/// The first item of `buf` and the bytes after it.
fn item(buf: &[u8]) -> Result<(Item<'_>, &[u8]), EnrError> {
    let (&prefix, rest) = buf.split_first().ok_or(EnrError::Rlp("empty"))?;
    let (header, len, list) = match prefix {
        0x00..=0x7f => return Ok((Item::Bytes(&buf[..1]), rest)),
        0x80..=0xb7 => (1, usize::from(prefix - 0x80), false),
        0xb8..=0xbf => {
            let n = usize::from(prefix - 0xb7);
            (1 + n, long_len(rest, n)?, false)
        }
        0xc0..=0xf7 => (1, usize::from(prefix - 0xc0), true),
        0xf8..=0xff => {
            let n = usize::from(prefix - 0xf7);
            (1 + n, long_len(rest, n)?, true)
        }
    };
    let end = header
        .checked_add(len)
        .filter(|&e| e <= buf.len())
        .ok_or(EnrError::Rlp("item runs past the end"))?;
    let payload = &buf[header..end];
    if !list && len == 1 && payload[0] < 0x80 {
        return Err(EnrError::Rlp(
            "a single byte below 0x80 must be its own encoding",
        ));
    }
    let item = if list {
        Item::List(payload)
    } else {
        Item::Bytes(payload)
    };
    Ok((item, &buf[end..]))
}

/// The value of the field `key` of the textual record `text`, if the record has it. The whole
/// record is checked: its text, its length, its RLP and its key order.
///
/// # Errors
///
/// The record is malformed, or the value of `key` is a list.
pub fn field(text: &str, key: &[u8]) -> Result<Option<Vec<u8>>, EnrError> {
    if text.len() > MAX_TEXT_LEN {
        return Err(EnrError::TextTooLong(text.len()));
    }
    let b64 = text.strip_prefix("enr:").ok_or(EnrError::Text)?;
    let raw = data_encoding::BASE64URL_NOPAD
        .decode(b64.as_bytes())
        .map_err(|_| EnrError::Text)?;
    if raw.len() > MAX_RECORD_LEN {
        return Err(EnrError::TooLong(raw.len()));
    }
    let (Item::List(mut body), after) = item(&raw)? else {
        return Err(EnrError::Rlp("the record is not a list"));
    };
    if !after.is_empty() {
        return Err(EnrError::Rlp("bytes after the record"));
    }
    // Signature, then seq.
    for _ in 0..2 {
        let (Item::Bytes(_), rest) = item(body)? else {
            return Err(EnrError::Rlp("signature and seq must be byte strings"));
        };
        body = rest;
    }
    let mut previous: Option<&[u8]> = None;
    let mut found = None;
    while !body.is_empty() {
        let (Item::Bytes(k), rest) = item(body)? else {
            return Err(EnrError::Rlp("a key must be a byte string"));
        };
        if previous.is_some_and(|p| p >= k) {
            return Err(EnrError::KeyOrder);
        }
        previous = Some(k);
        if rest.is_empty() {
            return Err(EnrError::Rlp("a key without a value"));
        }
        let (value, rest) = item(rest)?;
        if k == key {
            match value {
                Item::Bytes(v) => found = Some(v.to_vec()),
                Item::List(_) => return Err(EnrError::Rlp("the field must be a byte string")),
            }
        }
        body = rest;
    }
    Ok(found)
}

/// The `eth2` field of the textual record `text`.
///
/// # Errors
///
/// The record is malformed ([`field`]), or its `eth2` field is missing or not 16 bytes.
pub fn eth2_fork_id(text: &str) -> Result<EnrForkId, EnrError> {
    let v = field(text, ETH2_KEY.as_bytes())?.ok_or(EnrError::NoEth2)?;
    let v: &[u8; 16] = v
        .as_slice()
        .try_into()
        .map_err(|_| EnrError::Eth2Len(v.len()))?;
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&v[8..]);
    Ok(EnrForkId {
        fork_digest: [v[0], v[1], v[2], v[3]],
        next_fork_version: [v[4], v[5], v[6], v[7]],
        next_fork_epoch: u64::from_le_bytes(epoch),
    })
}

/// The `cgc` field of the textual record `text`: the custody group count it advertises.
///
/// # Errors
///
/// The record is malformed ([`field`]), or its `cgc` field is missing or not canonical.
pub fn custody_group_count(text: &str) -> Result<u64, EnrError> {
    let v = field(text, CGC_KEY.as_bytes())?.ok_or(EnrError::NoCgc)?;
    decode_cgc(&v).map_err(EnrError::Cgc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{ENR_BPO2, ENR_GLOAS};

    #[test]
    fn reads_eth2_of_a_record() {
        let id = eth2_fork_id(ENR_GLOAS).unwrap();
        assert_eq!(id.fork_digest, [0x66, 0x9e, 0x6c, 0x11]);
        assert_eq!(id.next_fork_version, [0x90, 0, 0, 0x76]);
        assert_eq!(id.next_fork_epoch, u64::MAX);
        assert_eq!(
            eth2_fork_id(ENR_BPO2).unwrap().fork_digest,
            [0x74, 0xd0, 0x14, 0x59]
        );
    }

    fn rlp_bytes(b: &[u8]) -> Vec<u8> {
        match b {
            [x] if *x < 0x80 => vec![*x],
            _ if b.len() < 56 => [&[0x80 + b.len() as u8][..], b].concat(),
            _ => [&[0xb8, b.len() as u8][..], b].concat(),
        }
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload = items.concat();
        if payload.len() < 56 {
            [vec![0xc0 + payload.len() as u8], payload].concat()
        } else {
            [vec![0xf8, payload.len() as u8], payload].concat()
        }
    }

    fn text(raw: &[u8]) -> String {
        format!("enr:{}", data_encoding::BASE64URL_NOPAD.encode(raw))
    }

    fn record(pairs: &[(&[u8], Vec<u8>)]) -> String {
        let mut items = vec![rlp_bytes(&[0x11; 64]), rlp_bytes(&[1])];
        for (k, v) in pairs {
            items.push(rlp_bytes(k));
            items.push(v.clone());
        }
        text(&rlp_list(&items))
    }

    #[test]
    fn refuses_malformed_records() {
        let eth2 = rlp_bytes(&[0u8; 16]);
        assert!(eth2_fork_id(&record(&[(b"eth2", eth2.clone())])).is_ok());
        let cases: Vec<(String, EnrError)> = vec![
            ("-Ly4QBER".to_owned(), EnrError::Text),
            ("enr:***".to_owned(), EnrError::Text),
            (format!("{ENR_GLOAS}="), EnrError::Text),
            (text(&[0xc0; 301]), EnrError::TooLong(301)),
            // Refused by its length before any decode: 513 bytes of text.
            (
                format!("enr:{}", "A".repeat(509)),
                EnrError::TextTooLong(513),
            ),
            (record(&[(b"id", rlp_bytes(b"v4"))]), EnrError::NoEth2),
            (
                record(&[(b"eth2", rlp_bytes(&[0; 15]))]),
                EnrError::Eth2Len(15),
            ),
            (
                record(&[(b"id", rlp_bytes(b"v4")), (b"eth2", eth2.clone())]),
                EnrError::KeyOrder,
            ),
            (
                record(&[(b"eth2", eth2.clone()), (b"eth2", eth2.clone())]),
                EnrError::KeyOrder,
            ),
            (
                record(&[(b"eth2", rlp_list(&[]))]),
                EnrError::Rlp("the field must be a byte string"),
            ),
            (
                text(&rlp_bytes(b"abc")),
                EnrError::Rlp("the record is not a list"),
            ),
            (
                text(&[0xc1, 0x01, 0x00]),
                EnrError::Rlp("bytes after the record"),
            ),
            (
                text(&[0xc3, 0x81, 0x05, 0x01]),
                EnrError::Rlp("a single byte below 0x80 must be its own encoding"),
            ),
            (
                text(&[0xc2, 0x83, 0x01]),
                EnrError::Rlp("item runs past the end"),
            ),
            (text(&[0xb8]), EnrError::Rlp("truncated length")),
            (
                text(&[0xb8, 0x05, 1, 2, 3, 4, 5]),
                EnrError::Rlp("long form for a short item"),
            ),
            (
                text(&[0xb9, 0x00, 0x40]),
                EnrError::Rlp("length with a leading zero"),
            ),
            (
                text(&[0xc2, 0xc0, 0x01]),
                EnrError::Rlp("signature and seq must be byte strings"),
            ),
            (
                text(&[0xc3, 0x01, 0x01, 0xc0]),
                EnrError::Rlp("a key must be a byte string"),
            ),
            (
                text(&[0xc3, 0x01, 0x01, 0x01]),
                EnrError::Rlp("a key without a value"),
            ),
            (text(&[]), EnrError::Rlp("empty")),
        ];
        for (input, want) in cases {
            assert_eq!(eth2_fork_id(&input), Err(want.clone()), "{input}");
        }
        // A list value under another key is skipped.
        let with_list = record(&[(b"eth", rlp_list(&[rlp_bytes(&[1, 2])])), (b"eth2", eth2)]);
        assert!(eth2_fork_id(&with_list).is_ok());
        // Long-form items parse.
        let long = record(&[(b"eth2", rlp_bytes(&[0; 16])), (b"z", rlp_bytes(&[9; 60]))]);
        assert!(eth2_fork_id(&long).is_ok());
    }

    #[test]
    fn reads_cgc_of_a_record() {
        let eth2 = rlp_bytes(&[0u8; 16]);
        for cgc in [4u64, 8, 128, 0x1234] {
            let text = record(&[
                (b"cgc", rlp_bytes(&p2p_wire::enr::encode_cgc(cgc))),
                (b"eth2", eth2.clone()),
            ]);
            assert_eq!(custody_group_count(&text), Ok(cgc));
            assert!(eth2_fork_id(&text).is_ok());
        }
        // The pinned records carry no cgc.
        assert_eq!(custody_group_count(ENR_GLOAS), Err(EnrError::NoCgc));
        let zero = record(&[(b"cgc", rlp_bytes(&[0, 4]))]);
        assert_eq!(
            custody_group_count(&zero),
            Err(EnrError::Cgc(EnrFieldError::CgcLeadingZero))
        );
        let long = record(&[(b"cgc", rlp_bytes(&[1; 9]))]);
        assert_eq!(
            custody_group_count(&long),
            Err(EnrError::Cgc(EnrFieldError::CgcTooLong(9)))
        );
        assert_eq!(
            custody_group_count("enr:***"),
            Err(EnrError::Text),
            "the whole record is checked"
        );
        assert_eq!(field(ENR_GLOAS, b"nope"), Ok(None));
    }
}
