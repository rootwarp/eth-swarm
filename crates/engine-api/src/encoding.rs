//! Engine API value encodings (execution-apis `src/engine/common.md`, "Encoding").
//!
//! - `DATA`: `0x`, then two hex digits per byte (`^0x(?:[a-fA-F0-9]{2})*$`).
//! - `QUANTITY`: `0x`, then the big-endian value in hex with the leading zeros stripped, `0x0`
//!   for zero (`^0x(?:0|(?:[a-fA-F1-9][a-fA-F0-9]*))$`).
//!
//! Encoding writes lowercase hex, which the OpenRPC base types require (`bytes` is
//! `^0x[0-9a-f]*$`). Decoding accepts either case, as `common.md` does, and nothing else: no
//! missing prefix, odd digit count, wrong fixed length, leading zero or out-of-range quantity.

use alloy_primitives::{Address, FixedBytes, U256};
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

impl Serialize for Data {
    fn serialize<S: Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
        todo!()
    }
}

impl<'de> Deserialize<'de> for Data {
    fn deserialize<D: Deserializer<'de>>(_d: D) -> Result<Self, D::Error> {
        todo!()
    }
}

impl<const N: usize> Serialize for FixedData<N> {
    fn serialize<S: Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
        todo!()
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedData<N> {
    fn deserialize<D: Deserializer<'de>>(_d: D) -> Result<Self, D::Error> {
        todo!()
    }
}

impl Serialize for Quantity {
    fn serialize<S: Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
        todo!()
    }
}

impl<'de> Deserialize<'de> for Quantity {
    fn deserialize<D: Deserializer<'de>>(_d: D) -> Result<Self, D::Error> {
        todo!()
    }
}

impl Serialize for Quantity256 {
    fn serialize<S: Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
        todo!()
    }
}

impl<'de> Deserialize<'de> for Quantity256 {
    fn deserialize<D: Deserializer<'de>>(_d: D) -> Result<Self, D::Error> {
        todo!()
    }
}
