//! Fork-dispatched containers.
//!
//! SSZ carries no fork tag, so the decoder must be told the fork. Blocks and states carry their
//! slot at a fixed offset; `from_ssz_bytes_by_slot` reads it (no allocation), maps it through
//! [`ForkSchedule::fork_at`], and decodes with that fork's shape and cap. The fork is never taken
//! from the current wall-clock epoch.
//!
//! A `DataColumnSidecar`'s slot sits at a different offset in each fork (Fulu: in
//! `signed_block_header`; Gloas: its own `slot` field). Its first offset is the length of the
//! fixed part, which differs between the two shapes, so it tells where to read the slot; the
//! slot's fork then decides the shape it is decoded with.
//!
//! Encoding and `hash_tree_root` are those of the inner container.

use crate::caps::{NetworkCaps, ObjectKind};
use crate::codec::{decode_checked, DecodeError};
use crate::preset::EthSpec;
use crate::primitives::{ForkName, Root, Slot};
use crate::{fulu, gloas};
use network_config::ForkSchedule;
use tree_hash::TreeHash;

macro_rules! forked {
    ($(#[$doc:meta])* $name:ident, $kind:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, ssz_derive::Encode, tree_hash_derive::TreeHash)]
        #[ssz(enum_behaviour = "transparent")]
        #[tree_hash(enum_behaviour = "transparent")]
        // Both variants are the same object; boxing one fork would make access asymmetric.
        #[allow(clippy::large_enum_variant)]
        pub enum $name<E: EthSpec> {
            /// The Fulu shape.
            Fulu(fulu::$name<E>),
            /// The Gloas shape.
            Gloas(gloas::$name<E>),
        }

        impl<E: EthSpec> $name<E> {
            /// The object kind used for its decode cap.
            pub const KIND: ObjectKind = $kind;

            /// The fork whose shape this value has.
            pub fn fork_name(&self) -> ForkName {
                match self {
                    Self::Fulu(_) => ForkName::Fulu,
                    Self::Gloas(_) => ForkName::Gloas,
                }
            }

            /// Decodes `bytes` with `fork`'s shape, after checking `fork`'s cap. A kind that
            /// [needs network caps](ObjectKind::needs_network_caps) is refused with
            /// [`DecodeError::NeedsNetworkCaps`].
            pub fn from_ssz_bytes_for_fork(
                bytes: &[u8],
                fork: ForkName,
            ) -> Result<Self, DecodeError> {
                Self::decode_for_fork(bytes, fork, None)
            }

            pub(crate) fn decode_for_fork(
                bytes: &[u8],
                fork: ForkName,
                network: Option<&NetworkCaps>,
            ) -> Result<Self, DecodeError> {
                let (kind, n) = (Self::KIND, network);
                Ok(match fork {
                    ForkName::Fulu => Self::Fulu(decode_checked::<E, _>(kind, fork, n, bytes)?),
                    ForkName::Gloas => Self::Gloas(decode_checked::<E, _>(kind, fork, n, bytes)?),
                })
            }
        }
    };
}

forked!(
    /// `SignedBeaconBlock` of any supported fork.
    SignedBeaconBlock,
    ObjectKind::SignedBeaconBlock
);
forked!(
    /// `BeaconState` of any supported fork.
    BeaconState,
    ObjectKind::BeaconState
);
forked!(
    /// `SignedAggregateAndProof` of any supported fork.
    SignedAggregateAndProof,
    ObjectKind::SignedAggregateAndProof
);
forked!(
    /// `AttesterSlashing` of any supported fork.
    AttesterSlashing,
    ObjectKind::AttesterSlashing
);
forked!(
    /// `DataColumnSidecar` of any supported fork.
    DataColumnSidecar,
    ObjectKind::DataColumnSidecar
);

/// `SignedBeaconBlock`: `message` offset (4) and `signature` (96), then `BeaconBlock.slot`.
const BLOCK_SLOT_OFFSET: usize = 4 + 96;
/// `BeaconState`: `genesis_time` (8) and `genesis_validators_root` (32), then `slot`.
const STATE_SLOT_OFFSET: usize = 8 + 32;
/// `DataColumnSidecar`: `index` (8), then the `column` offset, the first offset of both shapes.
const SIDECAR_FIRST_OFFSET_AT: usize = 8;
/// Fulu `DataColumnSidecar` fixed part: `index` (8), three offsets (12), `signed_block_header`
/// (208) and `kzg_commitments_inclusion_proof` (4 × 32).
const FULU_SIDECAR_FIXED_LEN: usize = 8 + 3 * 4 + 208 + 4 * 32;
/// Fulu `DataColumnSidecar`: `index` and three offsets, then `signed_block_header.message.slot`.
const FULU_SIDECAR_SLOT_OFFSET: usize = 8 + 3 * 4;
/// Gloas `DataColumnSidecar` fixed part: `index` (8), two offsets (8), `slot` (8) and
/// `beacon_block_root` (32).
const GLOAS_SIDECAR_FIXED_LEN: usize = 8 + 2 * 4 + 8 + 32;
/// Gloas `DataColumnSidecar`: `index` and two offsets, then `slot`.
const GLOAS_SIDECAR_SLOT_OFFSET: usize = 8 + 2 * 4;

/// Reads the little-endian `N`-byte integer at `at` without decoding anything else.
fn peek_le<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], DecodeError> {
    let end = at + N;
    let raw = bytes
        .get(at..end)
        .ok_or(ssz::DecodeError::InvalidByteLength {
            len: bytes.len(),
            expected: end,
        })?;
    let mut out = [0u8; N];
    out.copy_from_slice(raw);
    Ok(out)
}

/// Reads the little-endian `Slot` at `at` without decoding anything else.
fn peek_slot(bytes: &[u8], at: usize) -> Result<Slot, DecodeError> {
    peek_le::<8>(bytes, at).map(Slot::from_le_bytes)
}

/// Reads a `DataColumnSidecar`'s slot from whichever fork's shape its first offset names.
fn peek_sidecar_slot(bytes: &[u8]) -> Result<Slot, DecodeError> {
    let first = u32::from_le_bytes(peek_le::<4>(bytes, SIDECAR_FIRST_OFFSET_AT)?) as usize;
    match first {
        FULU_SIDECAR_FIXED_LEN => peek_slot(bytes, FULU_SIDECAR_SLOT_OFFSET),
        GLOAS_SIDECAR_FIXED_LEN => peek_slot(bytes, GLOAS_SIDECAR_SLOT_OFFSET),
        _ if first < GLOAS_SIDECAR_FIXED_LEN => {
            Err(ssz::DecodeError::OffsetIntoFixedPortion(first).into())
        }
        _ => Err(ssz::DecodeError::OffsetSkipsVariableBytes(first).into()),
    }
}

/// The fork for an object at `slot`, or [`DecodeError::PreFulu`].
pub fn fork_at_slot<E: EthSpec>(
    schedule: &ForkSchedule,
    slot: Slot,
) -> Result<ForkName, DecodeError> {
    schedule
        .fork_at(E::epoch_at_slot(slot))
        .ok_or(DecodeError::PreFulu { slot })
}

impl<E: EthSpec> SignedBeaconBlock<E> {
    /// `message.slot`.
    pub fn slot(&self) -> Slot {
        match self {
            Self::Fulu(b) => b.message.slot,
            Self::Gloas(b) => b.message.slot,
        }
    }

    /// The block root: `hash_tree_root(message)`, not the root of the signed container.
    pub fn message_root(&self) -> Root {
        match self {
            Self::Fulu(b) => b.message.tree_hash_root(),
            Self::Gloas(b) => b.message.tree_hash_root(),
        }
    }

    /// Decodes with the fork of the block's own slot.
    pub fn from_ssz_bytes_by_slot(
        bytes: &[u8],
        schedule: &ForkSchedule,
    ) -> Result<Self, DecodeError> {
        let slot = peek_slot(bytes, BLOCK_SLOT_OFFSET)?;
        Self::from_ssz_bytes_for_fork(bytes, fork_at_slot::<E>(schedule, slot)?)
    }
}

impl<E: EthSpec> BeaconState<E> {
    /// `slot`.
    pub fn slot(&self) -> Slot {
        match self {
            Self::Fulu(s) => s.slot,
            Self::Gloas(s) => s.slot,
        }
    }

    /// Decodes with the fork of the state's own slot.
    pub fn from_ssz_bytes_by_slot(
        bytes: &[u8],
        schedule: &ForkSchedule,
    ) -> Result<Self, DecodeError> {
        let slot = peek_slot(bytes, STATE_SLOT_OFFSET)?;
        Self::from_ssz_bytes_for_fork(bytes, fork_at_slot::<E>(schedule, slot)?)
    }
}

impl<E: EthSpec> DataColumnSidecar<E> {
    /// The slot of the sidecar's block: `signed_block_header.message.slot` (Fulu), `slot`
    /// (Gloas).
    pub fn slot(&self) -> Slot {
        match self {
            Self::Fulu(s) => s.signed_block_header.message.slot,
            Self::Gloas(s) => s.slot,
        }
    }

    /// The slot of a sidecar's SSZ, of either fork's shape, read without decoding the rest:
    /// what a check of the fork digest it came with needs before anything is decoded.
    ///
    /// # Errors
    ///
    /// The bytes are of neither shape.
    pub fn peek_slot(bytes: &[u8]) -> Result<Slot, DecodeError> {
        peek_sidecar_slot(bytes)
    }

    /// Decodes with `fork`'s shape, after checking `fork`'s cap on `network`.
    pub fn from_ssz_bytes_for_fork_with(
        bytes: &[u8],
        fork: ForkName,
        network: &NetworkCaps,
    ) -> Result<Self, DecodeError> {
        Self::decode_for_fork(bytes, fork, Some(network))
    }

    /// Decodes with the fork of the sidecar's own slot, after checking that fork's cap on
    /// `network`. Bytes of the other fork's shape fail to decode.
    pub fn from_ssz_bytes_by_slot(
        bytes: &[u8],
        schedule: &ForkSchedule,
        network: &NetworkCaps,
    ) -> Result<Self, DecodeError> {
        let slot = peek_sidecar_slot(bytes)?;
        Self::decode_for_fork(bytes, fork_at_slot::<E>(schedule, slot)?, Some(network))
    }
}
