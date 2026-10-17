//! ethereum/ssz-specs v0.1.0 fixtures (`fixtures/ssz/ssz/<handler>/<case>.json`).
//!
//! The release ships no type descriptors, so the sample types are transcribed from
//! `tests/fillers/ssz/*.py` at ssz-specs v0.1.0 (commit 7bce07f). Type names repeat
//! across filler modules with different definitions, so lookup is by (handler, type).

use crate::check::{parse_hex, round_trip, Expect};
use crate::coverage::Reads;
use crate::plan::Case;
use alloy_primitives::{U128, U256 as Uint256};
use serde::Deserialize;
use ssz::{BitList, BitVector, ProgressiveBitList};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::*, FixedVector, ProgressiveVariableList, VariableList};
use std::collections::BTreeMap;
use std::path::Path;
use tree_hash_derive::TreeHash;

/// One fixture case.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fixture {
    /// Name of the sample type in the filler module.
    pub type_name: String,
    /// The bytes handed to the decoder.
    pub serialized: String,
    /// Expected root for valid cases; empty for invalid ones.
    #[serde(default)]
    pub root: String,
    /// Present only on cases the decoder must reject.
    pub rejection_reason: Option<String>,
}

impl Fixture {
    fn expect(&self) -> Result<Expect, String> {
        if self.rejection_reason.is_some() {
            return Ok(Expect::Invalid);
        }
        let root: [u8; 32] = parse_hex(&self.root)?
            .try_into()
            .map_err(|_| format!("root {:?} is not 32 bytes", self.root))?;
        Ok(Expect::Valid { root })
    }
}

/// Loads the single fixture in a case file.
pub fn load(reads: &Reads, path: &Path) -> Result<Fixture, String> {
    let text = reads
        .read_to_string(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let map: BTreeMap<String, Fixture> =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut it = map.into_values();
    match (it.next(), it.next()) {
        (Some(f), None) => Ok(f),
        _ => Err(format!("{}: expected exactly one fixture", path.display())),
    }
}

/// Whether a (handler, type) pair has a Rust type.
pub fn supported(handler: &str, type_name: &str) -> bool {
    dispatch(handler, type_name, &[], &Expect::Invalid).is_some()
}

/// The fixture file of a case: its only file, `<case>.json`.
pub fn fixture_path(case: &Case) -> Result<&Path, String> {
    match case.files.as_slice() {
        [f] if f.name == format!("{}.json", case.key.case) => Ok(&f.path),
        _ => Err(format!(
            "expected exactly one file `{}.json` in the case",
            case.key.case
        )),
    }
}

/// Runs one case. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    let f = load(reads, fixture_path(case)?)?;
    let bytes = parse_hex(&f.serialized)?;
    let expect = f.expect()?;
    dispatch(&case.key.handler, &f.type_name, &bytes, &expect)
        .ok_or_else(|| format!("no Rust type for {}/{}", case.key.handler, f.type_name))?
}

macro_rules! table {
    ($h:expr, $t:expr, $b:expr, $e:expr; $($handler:literal : { $($name:literal => $ty:ty),* $(,)? })*) => {
        match ($h, $t) {
            $($(($handler, $name) => Some(round_trip::<$ty>($b, $e)),)*)*
            _ => None,
        }
    };
}

fn dispatch(handler: &str, type_name: &str, b: &[u8], e: &Expect) -> Option<Result<(), String>> {
    table!(handler, type_name, b, e;
        "test_basic_types": {
            "Boolean" => bool, "Uint8" => u8, "Uint16" => u16, "Uint32" => u32,
            "Uint64" => u64, "Uint128" => U128, "Uint256" => Uint256,
            "Bytes4" => FixedVector<u8, U4>, "Bytes32" => FixedVector<u8, U32>,
            "Bytes52" => FixedVector<u8, U52>, "Bytes64" => FixedVector<u8, U64>,
            "ByteList512KiB" => VariableList<u8, U524288>,
            "SampleBitVector8" => BitVector<U8>, "SampleBitVector64" => BitVector<U64>,
            "SampleBitList16" => BitList<U16>,
            "SampleUint16Vector3" => FixedVector<u16, U3>,
            "SampleUint64Vector4" => FixedVector<u64, U4>,
            "SampleUint32List16" => VariableList<u32, U16>,
            "SampleBytes32List8" => VariableList<FixedVector<u8, U32>, U8>,
        }
        "test_merkleization_boundaries": {
            "BoundaryBitVector1" => BitVector<U1>, "BoundaryBitVector7" => BitVector<U7>,
            "BoundaryBitVector9" => BitVector<U9>, "BoundaryBitVector255" => BitVector<U255>,
            "BoundaryBitVector256" => BitVector<U256>, "BoundaryBitVector257" => BitVector<U257>,
            "BoundaryBitList256" => BitList<U256>,
            "BoundaryUint64List32" => VariableList<u64, U32>,
        }
        "test_decode_failure_smoke": { "SmokeBitList8" => BitList<U8> }
        "test_progressive_types": {
            "ProgressiveBitList" => ProgressiveBitList,
            "SampleUint64ProgressiveList" => ProgressiveVariableList<u64>,
            "SampleBytes32ProgressiveList" => ProgressiveVariableList<FixedVector<u8, U32>>,
            "SampleNestedProgressiveList" => ProgressiveVariableList<ProgressiveVariableList<u16>>,
            "SampleContainerWithProgressiveList" => pt::SampleContainerWithProgressiveList,
        }
        "test_progressive_containers": {
            "ProgressiveBitList" => ProgressiveBitList,
            "SampleSquare" => pc::SampleSquare, "SampleCircle" => pc::SampleCircle,
            "SampleOneField" => pc::SampleOneField, "SampleLeadingGaps" => pc::SampleLeadingGaps,
            "SampleMultipleGaps" => pc::SampleMultipleGaps,
            "SampleWidestLayout" => pc::SampleWidestLayout,
            "SampleLevelBoundary" => pc::SampleLevelBoundary,
            "SampleBoundedListField" => pc::SampleBoundedListField,
            "SampleProgressiveFields" => pc::SampleProgressiveFields,
            "SampleInnerShape" => pc::SampleInnerShape, "SampleOuterShape" => pc::SampleOuterShape,
            "SampleSquareProgressiveList" => ProgressiveVariableList<pc::SampleSquare>,
            "SampleShapeContainer" => pc::SampleShapeContainer,
            "SampleUint64ProgressiveList" => ProgressiveVariableList<u64>,
        }
        "test_compatible_unions": {
            "SampleSquare" => pc::SampleSquare, "SampleCircle" => pc::SampleCircle,
            "SampleShape" => cu::SampleShape, "SampleNumbers" => cu::SampleNumbers,
            "SampleEmptyProne" => cu::SampleEmptyProne, "SampleSquareOnly" => cu::SampleSquareOnly,
            "SampleNestedShape" => cu::SampleNestedShape,
            "SampleShapeContainer" => cu::SampleShapeContainer,
            "SampleShapeProgressiveContainer" => cu::SampleShapeProgressiveContainer,
            "SampleShapeProgressiveList" => ProgressiveVariableList<cu::SampleShape>,
        }
    )
}

/// `tests/fillers/ssz/test_progressive_types.py`.
mod pt {
    use super::*;

    #[derive(Debug, Encode, Decode, TreeHash)]
    pub struct SampleContainerWithProgressiveList {
        pub a: u16,
        pub b: ProgressiveVariableList<u64>,
        pub c: u8,
    }
}

/// `tests/fillers/ssz/test_progressive_containers.py`.
mod pc {
    use super::*;

    macro_rules! progressive {
        ($name:ident, [$($af:literal),*], { $($f:ident : $t:ty),* $(,)? }) => {
            #[derive(Debug, Encode, Decode, TreeHash)]
            #[tree_hash(struct_behaviour = "progressive_container", active_fields($($af),*))]
            pub struct $name { $(pub $f: $t),* }
        };
    }

    progressive!(SampleSquare, [1, 0, 1], { side: u16, color: u8 });
    progressive!(SampleCircle, [0, 1, 1], { radius: u16, color: u8 });
    progressive!(SampleOneField, [1], { a: u16 });
    progressive!(SampleLeadingGaps, [0, 0, 1], { c: u32 });
    progressive!(SampleMultipleGaps, [1, 0, 0, 1, 0, 1], { a: u8, b: u16, c: u32 });
    progressive!(SampleWidestLayout, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], { tail: u8 });
    progressive!(SampleLevelBoundary, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], { first: u16, last: u8 });
    progressive!(SampleBoundedListField, [1, 0, 1], { head: u64, body: VariableList<u16, U4> });
    progressive!(SampleProgressiveFields, [1, 1, 1], {
        head: u64, numbers: ProgressiveVariableList<u64>, flags: ProgressiveBitList,
    });
    progressive!(SampleInnerShape, [1, 0, 1], { x: u16, y: u8 });
    progressive!(SampleOuterShape, [1, 0, 1], { head: u8, inner: SampleInnerShape });

    #[derive(Debug, Encode, Decode, TreeHash)]
    pub struct SampleShapeContainer {
        pub tag: u8,
        pub shape: SampleSquare,
    }
}

/// `tests/fillers/ssz/test_compatible_unions.py` (EIP-8016).
mod cu {
    use super::pc::{SampleCircle, SampleSquare};
    use super::*;

    macro_rules! union {
        ($name:ident { $($sel:literal => $v:ident($t:ty)),* $(,)? }) => {
            #[derive(Debug, Encode, Decode, TreeHash)]
            #[ssz(enum_behaviour = "compatible_union")]
            #[tree_hash(enum_behaviour = "compatible_union")]
            pub enum $name { $(#[ssz(selector = $sel)] #[tree_hash(selector = $sel)] $v($t)),* }
        };
    }

    union!(SampleShape { "1" => Square(SampleSquare), "2" => Circle(SampleCircle), "127" => Square127(SampleSquare) });
    union!(SampleNumbers { "1" => List(VariableList<u16, U4>), "2" => Alias(VariableList<u16, U4>) });
    union!(SampleEmptyProne {
        "1" => Squares(ProgressiveVariableList<SampleSquare>),
        "2" => Circles(ProgressiveVariableList<SampleCircle>),
    });
    union!(SampleSquareOnly { "5" => Square(SampleSquare) });
    union!(SampleNestedShape { "1" => Shape(SampleShape), "2" => SquareOnly(SampleSquareOnly) });

    #[derive(Debug, Encode, Decode, TreeHash)]
    pub struct SampleShapeContainer {
        pub tag: u64,
        pub body: SampleShape,
    }

    #[derive(Debug, Encode, Decode, TreeHash)]
    #[tree_hash(struct_behaviour = "progressive_container", active_fields(1, 0, 1))]
    pub struct SampleShapeProgressiveContainer {
        pub tag: u64,
        pub body: SampleShape,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_type_name_resolves_per_handler() {
        assert!(supported(
            "test_progressive_containers",
            "SampleShapeContainer"
        ));
        assert!(supported("test_compatible_unions", "SampleShapeContainer"));
        assert!(!supported("test_basic_types", "SampleShapeContainer"));
    }

    #[test]
    fn fixture_expectation_from_json() {
        let valid: Fixture = serde_json::from_str(
            r#"{"typeName":"Uint8","serialized":"0x01","root":"0x0100000000000000000000000000000000000000000000000000000000000000"}"#,
        )
        .unwrap();
        assert!(matches!(valid.expect(), Ok(Expect::Valid { .. })));
        let invalid: Fixture = serde_json::from_str(
            r#"{"typeName":"Uint8","serialized":"0x0102","root":"","rejectionReason":"SIZE"}"#,
        )
        .unwrap();
        assert_eq!(invalid.expect(), Ok(Expect::Invalid));
    }
}
