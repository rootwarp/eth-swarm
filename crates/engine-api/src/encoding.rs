//! Engine API value encodings (execution-apis `src/engine/common.md`, "Encoding").
//!
//! - `DATA`: `0x`, then two hex digits per byte (`^0x(?:[a-fA-F0-9]{2})*$`).
//! - `QUANTITY`: `0x`, then the big-endian value in hex with the leading zeros stripped, `0x0`
//!   for zero (`^0x(?:0|(?:[a-fA-F1-9][a-fA-F0-9]*))$`).
//!
//! Encoding writes lowercase hex, which the OpenRPC base types require (`bytes` is
//! `^0x[0-9a-f]*$`). Decoding accepts either case, as `common.md` does, and nothing else: no
//! missing prefix, odd digit count, wrong fixed length, leading zero or out-of-range quantity.

use alloy_primitives::{hex, Address, FixedBytes, U256};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// `DATA` of any length.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Data(pub Vec<u8>);

/// `DATA` of exactly `N` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FixedData<const N: usize>(pub [u8; N]);

/// `QUANTITY`, 64 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Quantity(pub u64);

/// `QUANTITY`, 256 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Quantity256(pub U256);

impl<const N: usize> From<FixedBytes<N>> for FixedData<N> {
    fn from(bytes: FixedBytes<N>) -> Self {
        Self(bytes.0)
    }
}

impl From<Address> for FixedData<20> {
    fn from(address: Address) -> Self {
        Self(address.into_array())
    }
}

/// The hex digits after the mandatory `0x` prefix, all of them hex.
fn digits(s: &str) -> Result<&str, &'static str> {
    let digits = s.strip_prefix("0x").ok_or("missing the 0x prefix")?;
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not a hex digit");
    }
    Ok(digits)
}

fn decode_data(s: &str) -> Result<Vec<u8>, &'static str> {
    let digits = digits(s)?;
    if digits.len() % 2 != 0 {
        return Err("DATA has an odd number of hex digits");
    }
    hex::decode(digits).map_err(|_| "not a hex digit")
}

/// The `QUANTITY` encoding of a big-endian value.
fn encode_quantity(be: &[u8]) -> String {
    let digits = hex::encode(be);
    match digits.trim_start_matches('0') {
        "" => "0x0".to_owned(),
        trimmed => format!("0x{trimmed}"),
    }
}

/// A `QUANTITY` as `N` big-endian bytes.
fn decode_quantity<const N: usize>(s: &str) -> Result<[u8; N], &'static str> {
    let digits = digits(s)?;
    if digits.is_empty() {
        return Err("QUANTITY has no digits");
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err("QUANTITY has a leading zero");
    }
    if digits.len() > 2 * N {
        return Err("QUANTITY out of range");
    }
    let mut out = [0; N];
    hex::decode_to_slice(format!("{digits:0>width$}", width = 2 * N), &mut out)
        .map_err(|_| "not a hex digit")?;
    Ok(out)
}

fn string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    String::deserialize(d)
}

impl Serialize for Data {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode_prefixed(&self.0))
    }
}

impl<'de> Deserialize<'de> for Data {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        decode_data(&string(d)?).map(Self).map_err(Error::custom)
    }
}

impl<const N: usize> Serialize for FixedData<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode_prefixed(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedData<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = decode_data(&string(d)?).map_err(Error::custom)?;
        let len = bytes.len();
        let bytes = bytes
            .try_into()
            .map_err(|_| Error::custom(format_args!("DATA of {len} bytes, want {N}")))?;
        Ok(Self(bytes))
    }
}

impl Serialize for Quantity {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode_quantity(&self.0.to_be_bytes()))
    }
}

impl<'de> Deserialize<'de> for Quantity {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        decode_quantity(&string(d)?)
            .map(|be| Self(u64::from_be_bytes(be)))
            .map_err(Error::custom)
    }
}

impl Serialize for Quantity256 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode_quantity(&self.0.to_be_bytes::<32>()))
    }
}

impl<'de> Deserialize<'de> for Quantity256 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        decode_quantity(&string(d)?)
            .map(|be: [u8; 32]| Self(U256::from_be_bytes(be)))
            .map_err(Error::custom)
    }
}
