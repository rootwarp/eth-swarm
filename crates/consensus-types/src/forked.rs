//! Fork-dispatched containers.
//!
//! SSZ carries no fork tag, so the decoder must be told the fork. Blocks and states carry their
//! slot at a fixed offset; `from_ssz_bytes_by_slot` reads it (no allocation), maps it through
//! [`ForkSchedule::fork_at`], and decodes with that fork's shape and cap. The fork is never taken
//! from the current wall-clock epoch.
//!
//! Encoding and `hash_tree_root` are those of the inner container.

use crate::caps::ObjectKind;
use crate::codec::{decode_checked, DecodeError};
use crate::preset::EthSpec;
use crate::primitives::{ForkName, Slot};
use crate::{fulu, gloas};
use network_config::ForkSchedule;

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

            /// Decodes `bytes` with `fork`'s shape, after checking `fork`'s cap.
            pub fn from_ssz_bytes_for_fork(
                bytes: &[u8],
                fork: ForkName,
            ) -> Result<Self, DecodeError> {
                Ok(match fork {
                    ForkName::Fulu => Self::Fulu(decode_checked::<E, _>(Self::KIND, fork, bytes)?),
                    ForkName::Gloas => {
                        Self::Gloas(decode_checked::<E, _>(Self::KIND, fork, bytes)?)
                    }
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

/// `SignedBeaconBlock`: `message` offset (4) and `signature` (96), then `BeaconBlock.slot`.
const BLOCK_SLOT_OFFSET: usize = 4 + 96;
/// `BeaconState`: `genesis_time` (8) and `genesis_validators_root` (32), then `slot`.
const STATE_SLOT_OFFSET: usize = 8 + 32;

/// Reads the little-endian `Slot` at `at` without decoding anything else.
fn peek_slot(bytes: &[u8], at: usize) -> Result<Slot, DecodeError> {
    let end = at + 8;
    let raw = bytes
        .get(at..end)
        .ok_or(ssz::DecodeError::InvalidByteLength {
            len: bytes.len(),
            expected: end,
        })?;
    let mut slot = [0u8; 8];
    slot.copy_from_slice(raw);
    Ok(Slot::from_le_bytes(slot))
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
