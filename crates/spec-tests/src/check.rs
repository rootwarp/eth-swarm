//! The SSZ round-trip check shared by both vector sets.

use ssz::{Decode, Encode};
use tree_hash::TreeHash;

/// What a vector expects of one serialized value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Decodes, re-encodes to the same bytes, and has this `hash_tree_root`.
    Valid {
        /// Expected root.
        root: [u8; 32],
    },
    /// Must be rejected by the decoder.
    Invalid,
}

/// Decodes `bytes` as `T` and checks it against `expect`.
pub fn round_trip<T: Encode + Decode + TreeHash>(
    bytes: &[u8],
    expect: &Expect,
) -> Result<(), String> {
    let decoded = T::from_ssz_bytes(bytes);
    match (expect, decoded) {
        (Expect::Invalid, Err(_)) => Ok(()),
        (Expect::Invalid, Ok(_)) => Err("decoder accepted an invalid encoding".into()),
        (Expect::Valid { .. }, Err(e)) => Err(format!("decode failed: {e:?}")),
        (Expect::Valid { root }, Ok(v)) => {
            let re = v.as_ssz_bytes();
            if re != bytes {
                return Err(format!(
                    "re-encode mismatch: got 0x{}, want 0x{}",
                    hex::encode(&re),
                    hex::encode(bytes)
                ));
            }
            let got = v.tree_hash_root();
            if got.as_slice() != root {
                return Err(format!(
                    "hash_tree_root mismatch: got 0x{}, want 0x{}",
                    hex::encode(got),
                    hex::encode(root)
                ));
            }
            Ok(())
        }
    }
}

/// Parses a `0x`-prefixed hex string.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| format!("bad hex {s:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_of_u16(v: u16) -> [u8; 32] {
        let mut r = [0; 32];
        r[..2].copy_from_slice(&v.to_le_bytes());
        r
    }

    #[test]
    fn valid_value_round_trips() {
        let e = Expect::Valid {
            root: root_of_u16(0x1234),
        };
        assert_eq!(round_trip::<u16>(&[0x34, 0x12], &e), Ok(()));
    }

    #[test]
    fn wrong_root_is_reported() {
        let e = Expect::Valid { root: [0; 32] };
        assert!(round_trip::<u16>(&[0x34, 0x12], &e)
            .unwrap_err()
            .contains("hash_tree_root"));
    }

    #[test]
    fn invalid_must_be_rejected() {
        assert_eq!(round_trip::<u16>(&[1, 2, 3], &Expect::Invalid), Ok(()));
        assert!(round_trip::<u16>(&[1, 2], &Expect::Invalid).is_err());
    }

    #[test]
    fn non_canonical_bool_is_rejected() {
        assert_eq!(round_trip::<bool>(&[2], &Expect::Invalid), Ok(()));
    }

    #[test]
    fn hex_parsing() {
        assert_eq!(parse_hex("0x0aff"), Ok(vec![0x0a, 0xff]));
        assert!(parse_hex("0xzz").is_err());
    }
}
