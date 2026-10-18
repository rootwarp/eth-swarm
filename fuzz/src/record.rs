//! `enr_fields`: a node record's consensus fields, through `cl_discv5::enr::parse_enr_fields`
//! (the RLP `Enr` decode, its signature check, then `get_decodable` of `eth2`, `cgc` and `nfd`
//! and their value decoders, `EnrForkId::from_ssz_bytes` among them).
//!
//! A first byte without [`STRUCTURED_BIT`] makes the rest raw record bytes. Random bytes almost
//! never carry a valid signature, so with the bit the rest describes a record instead
//! ([`structured_input`]): which of `eth2`, `cgc` and `nfd` it holds, and their values, as byte
//! strings or as raw RLP (an RLP list, say). The harness signs it with a fixed key, so the value
//! decoders behind the signature check see fuzzed values, and the record goes through
//! `parse_enr_fields` as bytes.
//!
//! Invariants: an accepted record's fields are its raw values (`eth2` re-encodes to its 16
//! bytes, `cgc` to its canonical form, `nfd` to its 4 bytes); a structured record of byte-string
//! values yields exactly what the value decoders give its values, in the order the reader checks
//! them (key type, `eth2`, `cgc`, `nfd`); and `EnrForkId::from_ssz_bytes` accepts exactly 16 bytes.
//!
//! The harness signs secp256k1 records itself, with a fixed key and RFC 6979 nonces, so a
//! record's bytes depend only on its values and the seeds ([`signed_record`]) are reproducible;
//! `enr`'s own k256 key signs the same digest with a random nonce.

use alloy_rlp::{Bytes, Decodable, Encodable, Header};
use cl_discv5::enr::{parse_enr_fields, CombinedKey, Enr, EnrFields, FieldError};
use enr::k256::ecdsa::signature::hazmat::PrehashSigner;
use enr::k256::ecdsa::{Signature, SigningKey};
use enr::{EnrKey, EnrPublicKey};
use p2p_wire::enr::{
    decode_cgc, decode_eth2, decode_nfd, encode_cgc, EnrForkId, CGC_KEY, ENR_FORK_ID_LEN, ETH2_KEY,
    NFD_KEY,
};
use sha3::{Digest, Keccak256};
use ssz::Decode;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::OnceLock;

/// `enr_fields`: a first byte with this bit set makes the rest a structured record.
pub const STRUCTURED_BIT: u8 = 1;

/// The longest record (EIP-778).
pub const MAX_RECORD_LEN: usize = 300;

/// The structured input's flags: which values the record holds, which of them are raw RLP, and
/// whether it is signed with an ed25519 key instead.
const HAS: [u8; 3] = [1 << 0, 1 << 1, 1 << 2];
const RAW_RLP: [u8; 3] = [1 << 3, 1 << 4, 1 << 5];
const ED25519: u8 = 1 << 6;
/// The record keys, in the order the flags and the values come in.
const KEYS: [&str; 3] = [ETH2_KEY, CGC_KEY, NFD_KEY];

/// One consensus value of a structured record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordValue<'a> {
    /// A byte string: the record holds its RLP string encoding.
    Bytes(&'a [u8]),
    /// Raw RLP, held as it is.
    Rlp(&'a [u8]),
}

/// A structured record: `eth2`, `cgc` and `nfd` (each optional), and the key that signs it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordSpec<'a> {
    /// `eth2`, `cgc`, `nfd`.
    pub values: [Option<RecordValue<'a>>; 3],
    /// Signed with an ed25519 key, which a consensus record must not be.
    pub ed25519: bool,
}

/// The structured input for `spec` (after the selector byte): the flags, then a length byte and
/// the bytes of each value it holds, in [`KEYS`] order. Values are at most 255 bytes.
pub fn structured_input(spec: &RecordSpec<'_>) -> Vec<u8> {
    let mut flags = if spec.ed25519 { ED25519 } else { 0 };
    let mut body = Vec::new();
    for (i, value) in spec.values.iter().enumerate() {
        let bytes = match value {
            None => continue,
            Some(RecordValue::Bytes(b)) => b,
            Some(RecordValue::Rlp(b)) => {
                flags |= RAW_RLP[i];
                b
            }
        };
        flags |= HAS[i];
        body.push(u8::try_from(bytes.len()).expect("a value of at most 255 bytes"));
        body.extend_from_slice(bytes);
    }
    [&[flags][..], &body].concat()
}

/// The record a structured input describes; a value cut short takes what is left.
fn parse_structured(input: &[u8]) -> RecordSpec<'_> {
    let Some((&flags, mut rest)) = input.split_first() else {
        return RecordSpec::default();
    };
    let mut spec = RecordSpec {
        values: [None; 3],
        ed25519: flags & ED25519 != 0,
    };
    for i in 0..KEYS.len() {
        if flags & HAS[i] == 0 {
            continue;
        }
        let (len, tail) = rest
            .split_first()
            .map_or((0, rest), |(&l, t)| (l.into(), t));
        let (bytes, tail) = tail.split_at(len.min(tail.len()));
        rest = tail;
        spec.values[i] = Some(if flags & RAW_RLP[i] != 0 {
            RecordValue::Rlp(bytes)
        } else {
            RecordValue::Bytes(bytes)
        });
    }
    spec
}

/// The secp256k1 secret of every secp256k1 seed and structured record.
const SECP256K1_SECRET: [u8; 32] = [0x11; 32];
/// The ed25519 secret of the ed25519 ones.
const ED25519_SECRET: [u8; 32] = [0x22; 32];
/// The address fields `build_local_enr` writes, as the local record carries them.
const IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PORT: u16 = 9000;

fn secp256k1_key() -> &'static (SigningKey, Vec<u8>) {
    static KEY: OnceLock<(SigningKey, Vec<u8>)> = OnceLock::new();
    KEY.get_or_init(|| {
        let key = SigningKey::from_slice(&SECP256K1_SECRET).expect("a valid scalar");
        let public = CombinedKey::Secp256k1(key.clone()).public().encode();
        (key, public)
    })
}

fn ed25519_key() -> &'static CombinedKey {
    static KEY: OnceLock<CombinedKey> = OnceLock::new();
    KEY.get_or_init(|| {
        CombinedKey::ed25519_from_bytes(&mut ED25519_SECRET.clone()).expect("a valid key")
    })
}

fn rlp<T: Encodable + ?Sized>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value.encode(&mut out);
    out
}

/// `[signature, seq, k, v, ...]` (or the content, without the signature) as an RLP list, the
/// keys in `pairs`' (sorted) order and each value its raw RLP.
fn record_list(signature: Option<&[u8]>, seq: u64, pairs: &BTreeMap<&str, Vec<u8>>) -> Vec<u8> {
    let mut payload = signature.map(rlp).unwrap_or_default();
    seq.encode(&mut payload);
    for (key, value) in pairs {
        key.as_bytes().encode(&mut payload);
        payload.extend_from_slice(value);
    }
    let mut out = Vec::new();
    Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

/// The signed record `spec` describes, as RLP, with the address fields `build_local_enr` writes
/// (`ip`, `tcp`, `udp`). A secp256k1 record is put together and signed here (EIP-778: the
/// RFC 6979 signature of the Keccak-256 of the content), so its bytes depend only on `spec`; it
/// may be longer than a record's 300 bytes, which the decoder must refuse. An ed25519 record
/// (deterministic too) comes from `enr`'s builder; `None` if it does not fit.
pub fn signed_record(spec: &RecordSpec<'_>) -> Option<Vec<u8>> {
    let values = KEYS.iter().zip(spec.values).filter_map(|(k, v)| {
        v.map(|v| match v {
            RecordValue::Bytes(b) => (*k, rlp(b)),
            RecordValue::Rlp(b) => (*k, b.to_vec()),
        })
    });
    if spec.ed25519 {
        let mut builder = Enr::builder();
        builder.ip4(IP).tcp4(PORT).udp4(PORT);
        for (key, value) in values {
            builder.add_value_rlp(key, Bytes::from(value));
        }
        return builder.build(ed25519_key()).ok().map(|r| rlp(&r));
    }
    let (key, public) = secp256k1_key();
    let mut pairs: BTreeMap<&str, Vec<u8>> = BTreeMap::from([
        ("id", rlp("v4")),
        ("ip", rlp(&IP.octets()[..])),
        ("secp256k1", rlp(public.as_slice())),
        ("tcp", rlp(&PORT)),
        ("udp", rlp(&PORT)),
    ]);
    pairs.extend(values);
    let seq = 1;
    let digest = Keccak256::digest(record_list(None, seq, &pairs));
    let signature: Signature = key
        .sign_prehash(&digest)
        .expect("an RFC 6979 signature of a 32-byte digest");
    Some(record_list(Some(&signature.to_vec()), seq, &pairs))
}

/// The signed record a structured input (after the selector byte) describes: what
/// `enr_fields` hands to `parse_enr_fields`.
pub fn structured_record(input: &[u8]) -> Option<Vec<u8>> {
    signed_record(&parse_structured(input))
}

/// What `parse_enr_fields` must return for `spec`, if its values are byte strings. Raw RLP
/// values have no exact oracle, whatever the key: the record they are put in need not decode at
/// all (the builder takes them as they are), so only the record invariants hold for them.
fn expected(spec: &RecordSpec<'_>) -> Option<Result<EnrFields, FieldError>> {
    let mut bytes = [None; 3];
    for (slot, value) in bytes.iter_mut().zip(spec.values) {
        match value {
            None => {}
            Some(RecordValue::Bytes(b)) => *slot = Some(b),
            Some(RecordValue::Rlp(_)) => return None,
        }
    }
    if spec.ed25519 {
        return Some(Err(FieldError::NotSecp256k1));
    }
    let [eth2, cgc, nfd] = bytes;
    Some((|| {
        Ok(EnrFields {
            eth2: decode_eth2(eth2.ok_or(FieldError::NoEth2)?)?,
            cgc: cgc.map(decode_cgc).transpose()?,
            nfd: nfd.map(decode_nfd).transpose()?,
        })
    })())
}

/// The value decoders on their own: `EnrForkId::from_ssz_bytes` takes exactly 16 bytes and
/// agrees with `decode_eth2`, a `cgc` that decodes is canonical, an `nfd` is 4 bytes.
fn value_decoders(spec: &RecordSpec<'_>) {
    let [eth2, cgc, nfd] = spec.values.map(|v| match v {
        Some(RecordValue::Bytes(b) | RecordValue::Rlp(b)) => Some(b),
        None => None,
    });
    if let Some(b) = eth2 {
        let ssz = EnrForkId::from_ssz_bytes(b);
        assert_eq!(
            ssz.is_ok(),
            b.len() == ENR_FORK_ID_LEN,
            "ENRForkID of {} bytes",
            b.len()
        );
        assert_eq!(
            ssz.ok(),
            decode_eth2(b).ok(),
            "the SSZ and eth2 decoders disagree"
        );
    }
    if let Some(Ok(n)) = cgc.map(decode_cgc) {
        assert_eq!(
            Some(encode_cgc(n).as_slice()),
            cgc,
            "a cgc that is not canonical"
        );
    }
    if let Some(b) = nfd {
        assert_eq!(
            decode_nfd(b).is_ok(),
            b.len() == 4,
            "nfd of {} bytes",
            b.len()
        );
    }
}

/// An accepted record's fields are its raw values.
fn check_fields(rlp: &[u8], fields: &EnrFields) {
    let record = Enr::decode(&mut &rlp[..]).expect("an accepted record decodes");
    let raw = |key: &str| {
        record
            .get_decodable::<Bytes>(key)
            .transpose()
            .expect("an accepted value is a byte string")
    };
    let eth2 = raw(ETH2_KEY).expect("an accepted record has eth2");
    assert_eq!(
        EnrForkId::from_ssz_bytes(&eth2).ok(),
        Some(fields.eth2),
        "eth2 decodes to another ENRForkID"
    );
    assert_eq!(
        eth2.as_ref(),
        fields.eth2.to_bytes(),
        "eth2 re-encodes differently"
    );
    assert_eq!(
        raw(CGC_KEY).map(|b| b.to_vec()),
        fields.cgc.map(encode_cgc),
        "cgc re-encodes differently"
    );
    assert_eq!(
        raw(NFD_KEY).map(|b| b.to_vec()),
        fields.nfd.map(|d| d.to_vec()),
        "nfd differs from its value"
    );
}

/// `enr_fields`: see the module docs.
pub fn enr_fields(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    if selector & STRUCTURED_BIT == 0 {
        if let Ok(fields) = parse_enr_fields(rest) {
            check_fields(rest, &fields);
        }
        return;
    }
    let spec = parse_structured(rest);
    value_decoders(&spec);
    let Some(rlp) = signed_record(&spec) else {
        return;
    };
    let parsed = parse_enr_fields(&rlp);
    if let Ok(fields) = &parsed {
        check_fields(&rlp, fields);
    }
    if rlp.len() > MAX_RECORD_LEN {
        assert!(
            matches!(parsed, Err(FieldError::Record(_))),
            "a record of {} bytes: {parsed:?}",
            rlp.len()
        );
    } else if let Some(want) = expected(&spec) {
        assert_eq!(parsed, want, "the record and its value decoders disagree");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_input_round_trips() {
        let spec = RecordSpec {
            values: [
                Some(RecordValue::Bytes(&[1; 16])),
                Some(RecordValue::Rlp(&[0xc1, 0x01])),
                None,
            ],
            ed25519: true,
        };
        assert_eq!(parse_structured(&structured_input(&spec)), spec);
        assert_eq!(parse_structured(&[]), RecordSpec::default());
        // A value cut short takes what is left; a missing length byte is an empty value.
        let cut = parse_structured(&[HAS[0] | HAS[1], 5, 1, 2]);
        assert_eq!(cut.values[0], Some(RecordValue::Bytes(&[1, 2])));
        assert_eq!(cut.values[1], Some(RecordValue::Bytes(&[])));
    }

    /// A raw RLP value can break the record itself, so no oracle applies, ed25519 or not: an
    /// ed25519 record with a broken raw value is refused as a record, not for its key.
    #[test]
    fn raw_rlp_values_have_no_oracle() {
        // The input libFuzzer found, minimized: selector 0x0d (structured), flags 0xde
        // (ed25519; a raw `cgc` and an `nfd` byte string), then a `cgc` length running past the
        // end, which takes the RLP item 0x19 with a stray 0xde after it; an empty `nfd`.
        let found = [0x0d, 0xde, 0xde, 0x19, 0xde];
        let input = &found[1..];
        let spec = parse_structured(input);
        assert!(spec.ed25519);
        assert!(matches!(spec.values[1], Some(RecordValue::Rlp(_))));
        assert_eq!(expected(&spec), None);
        let rlp = signed_record(&spec).unwrap();
        assert!(matches!(parse_enr_fields(&rlp), Err(FieldError::Record(_))));
        enr_fields(&found);
    }

    #[test]
    fn records_are_reproducible_and_parse() {
        let eth2 = [7u8; 16];
        let spec = RecordSpec {
            values: [Some(RecordValue::Bytes(&eth2)), None, None],
            ed25519: false,
        };
        let rlp = signed_record(&spec).unwrap();
        assert_eq!(signed_record(&spec), Some(rlp.clone()));
        let fields = parse_enr_fields(&rlp).unwrap();
        assert_eq!(fields.eth2.to_bytes(), eth2);
        assert_eq!(expected(&spec), Some(Ok(fields)));
        let ed = RecordSpec {
            ed25519: true,
            ..spec
        };
        assert_eq!(
            parse_enr_fields(&signed_record(&ed).unwrap()),
            Err(FieldError::NotSecp256k1)
        );
        let too_long = RecordSpec {
            values: [Some(RecordValue::Bytes(&[0; 255])), None, None],
            ed25519: false,
        };
        let rlp = signed_record(&too_long).unwrap();
        assert!(rlp.len() > MAX_RECORD_LEN);
        assert!(matches!(parse_enr_fields(&rlp), Err(FieldError::Record(_))));
        // The same record within the size: the value decoders decide.
        let short = RecordSpec {
            values: [Some(RecordValue::Bytes(&[0; 15])), None, None],
            ed25519: false,
        };
        assert_eq!(
            parse_enr_fields(&signed_record(&short).unwrap()),
            Err(FieldError::Value(p2p_wire::enr::EnrFieldError::Eth2Len(15)))
        );
        let ed_too_long = RecordSpec {
            ed25519: true,
            ..too_long
        };
        assert_eq!(signed_record(&ed_too_long), None);
    }
}
