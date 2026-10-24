//! Per-type decode caps.
//!
//! Every container implements [`SszMaxLen`]: the longest SSZ encoding its field bounds allow,
//! derived from the spec's `MAX_*` constants rather than a global fallback. [`max_size`] turns
//! that into the byte cap [`crate::codec::decode`] checks before any SSZ decoding starts.
//!
//! The derivation reproduces the `gloas/p2p-interface.md` type-specific bounds
//! `MAX_ATTESTER_SLASHING_SIZE` and `MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE` exactly in both
//! presets. The Gloas `SignedAggregateAndProof` cap is the spec constant
//! `MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE` itself (`gloas/p2p-interface.md` L76, "Type-specific SSZ
//! bounds"), because Gloas aggregation bits have no type bound. `tests/caps.rs` pins all three.
//! Where the type bound is larger than any message can be, the cap is the transport's:
//! [`MAX_PAYLOAD_SIZE`] for p2p objects and [`MAX_SSZ_ENCODING`] for `BeaconState`.
//!
//! # Network-dependent caps
//!
//! The Gloas `DataColumnSidecar` cap is `compute_max_data_column_sidecar_size()`
//! (`gloas/p2p-interface.md` L324-341), which depends on the network's blob schedule. Callers
//! that decode column sidecars build a [`NetworkCaps`] once from the network's
//! [`ChainConfig`] and pass it to [`max_size_for`], [`crate::codec::check_size_for`],
//! [`crate::codec::decode_for`] or [`crate::forked::DataColumnSidecar::from_ssz_bytes_by_slot`].
//! [`ObjectKind::DataColumnSidecar`] requires one ([`ObjectKind::needs_network_caps`]): the
//! entry points without a [`NetworkCaps`] refuse it ([`max_size`] and [`type_max_len`] return
//! `None`, the decoders [`crate::codec::DecodeError::NeedsNetworkCaps`]), so a transport caller
//! cannot fall back to a looser cap by omission. Callers without a network (tests, tools) pass
//! [`NetworkCaps::PRESET_BOUND`] explicitly. No other kind depends on the network.
//!
//! # Decode-memory budget
//!
//! The cap bounds the input, not the heap the decoded value needs. Gloas lists without a spec
//! bound (`U0`) can only hold as many items as their input encodes, so the heap stays a fixed
//! multiple of the input. The figures below are worst cases at the 10 MiB cap, before any
//! signature is checked, in two models:
//!
//! - **Requested bytes** (`*_PEAK_HEAP_PER_INPUT_BYTE`, `*_ALLOCATED_PER_INPUT_BYTE`): what the
//!   decoder asks the allocator for, without any allocator overhead.
//! - **Allocator-adjusted heap model** (`*_HEAP_MODEL_PER_INPUT_BYTE`): every allocation counted
//!   as at least [`MIN_ALLOCATION_BYTES`] (32, glibc's minimum chunk on 64-bit), which captures
//!   the overhead that dominates small allocations. For the worst-case shape (1-byte
//!   transactions) glibc's real chunk sizing, `max(32, round_up(n + 8, 16))`, gives the same
//!   figures, and macOS's allocator gives lower ones.
//!
//! Neither model is a process-RSS bound. Both leave out memory the allocator retains after a
//! free, fragmentation, the input buffer itself and the process baseline, so gossip code sizing
//! decode concurrency from these figures must add its own headroom on top.
//!
//! In both models a growth step that copies holds the old and new buffers at once, and a list
//! grows by doubling past the decoder's first reservation, so the final buffer is under twice
//! the items it holds and all growth steps together allocate under twice the final buffer.
//!
//! - `SignedExecutionPayloadEnvelope`. A `k`-byte transaction costs `4 + k` input bytes, a
//!   24-byte list header in the transactions buffer and, for `k > 0`, its own `k`-byte
//!   allocation. Per input byte the buffer peaks below `72 / (4 + k)` and allocates below
//!   `96 / (4 + k)`; the per-transaction allocations add `k / (4 + k)` requested, or
//!   `max(k, 32) / (4 + k)` in the heap model.
//!   - Requested worst case, empty transactions (`k = 0`): peak ≤
//!     [`ENVELOPE_DECODE_PEAK_HEAP_PER_INPUT_BYTE`] (18, ≈ 180 MiB), allocated ≤
//!     [`ENVELOPE_DECODE_ALLOCATED_PER_INPUT_BYTE`] (24, ≈ 240 MiB). Measured per input byte:
//!     14.4 peak and 18.9 allocated at the cap; 18.0 and 23.6 at `2^21 + 1` transactions, one
//!     past a buffer doubling. 18 is the exact limit `72 / 4` of the doubling decoder, so it has
//!     no slack: a toolchain bump (`Vec` growth) or an `ssz_types` rev bump (first reservation,
//!     list header size) means re-deriving it.
//!   - Heap-model worst case, 1-byte transactions (`k = 1`): peak ≤ 14.4 + 6.4 →
//!     [`ENVELOPE_DECODE_PEAK_HEAP_MODEL_PER_INPUT_BYTE`] (21, ≈ 210 MiB), allocated ≤
//!     19.2 + 6.4 → [`ENVELOPE_DECODE_ALLOCATED_HEAP_MODEL_PER_INPUT_BYTE`] (26, ≈ 260 MiB).
//!     Measured per input byte, requested / heap model: peak 7.3 / 11.2 and allocated
//!     9.5 / 15.7 at the cap; peak 14.6 / 20.8 and allocated 18.8 / 25.0 at `2^20 + 1`
//!     transactions. Empty transactions make no per-item allocation, so their heap-model
//!     figures equal the requested ones.
//! - Gloas `SignedBeaconBlock`: its unbounded lists are parent deposit requests (fixed-size,
//!   reserved exactly) and attestation aggregation bits (copied once), so it makes a handful of
//!   large allocations of about one byte per input byte in both models. Budget: 2 per input byte
//!   for each of [`BLOCK_DECODE_PEAK_HEAP_PER_INPUT_BYTE`],
//!   [`BLOCK_DECODE_ALLOCATED_PER_INPUT_BYTE`], [`BLOCK_DECODE_PEAK_HEAP_MODEL_PER_INPUT_BYTE`]
//!   and [`BLOCK_DECODE_ALLOCATED_HEAP_MODEL_PER_INPUT_BYTE`]. Measured: 10.5 MB in every figure.
//!
//! `tests/caps.rs` decodes each worst-case shape under a counting allocator that records both
//! models, and fails if any figure exceeds its budget.

use crate::preset::EthSpec;
use crate::primitives::{
    Address, ColumnIndex, ForkName, KZGCommitment, KZGProof, Root, B256, U256,
};
use crate::{common, fulu, gloas};
use network_config::{BlobParameters, ChainConfig, MAX_BLOB_COMMITMENTS_PER_BLOCK};
use ssz::{BitList, BitVector, Encode, ProgressiveBitList};
use ssz_types::{FixedVector, ProgressiveVariableList, VariableList};
use std::fmt;
use typenum::Unsigned;

/// `BYTES_PER_LENGTH_OFFSET`.
const OFFSET: u64 = ssz::BYTES_PER_LENGTH_OFFSET as u64;

/// `MAX_PAYLOAD_SIZE` (`phase0/p2p-interface.md` config, 10 MiB on every known network): the
/// largest uncompressed gossip or req/resp payload.
pub const MAX_PAYLOAD_SIZE: usize = 10 * (1 << 20);

/// The largest SSZ encoding: offsets are 4 bytes, so a variable-size object stays below 2^32.
pub const MAX_SSZ_ENCODING: usize = u32::MAX as usize;

/// The longest SSZ encoding a type allows, saturating at `u64::MAX` for unbounded types.
pub trait SszMaxLen {
    /// Maximum encoded length in bytes.
    fn ssz_max_len() -> u64;
}

/// What one field adds to its container: its own maximum, plus an offset if variable-size.
pub fn field_max_len<T: SszMaxLen + Encode>() -> u64 {
    if <T as Encode>::is_ssz_fixed_len() {
        T::ssz_max_len()
    } else {
        T::ssz_max_len().saturating_add(OFFSET)
    }
}

/// `count` elements of `T`, each with an offset if variable-size.
fn list_max_len<T: SszMaxLen + Encode>(count: u64) -> u64 {
    count.saturating_mul(field_max_len::<T>())
}

/// Bound `N`, where `U0` means unbounded.
fn optional_bound<N: Unsigned>() -> u64 {
    match N::to_u64() {
        0 => u64::MAX,
        n => n,
    }
}

macro_rules! fixed_max_len {
    ($($t:ty),*) => {
        $(impl SszMaxLen for $t {
            fn ssz_max_len() -> u64 {
                <$t as Encode>::ssz_fixed_len() as u64
            }
        })*
    };
}

fixed_max_len!(bool, u8, u64, B256, Address, U256);

impl<const N: usize> SszMaxLen for [u8; N] {
    fn ssz_max_len() -> u64 {
        N as u64
    }
}

impl<T: SszMaxLen + Encode, N: Unsigned> SszMaxLen for FixedVector<T, N> {
    fn ssz_max_len() -> u64 {
        list_max_len::<T>(N::to_u64())
    }
}

impl<T: SszMaxLen + Encode, N: Unsigned> SszMaxLen for VariableList<T, N> {
    fn ssz_max_len() -> u64 {
        list_max_len::<T>(N::to_u64())
    }
}

impl<T: SszMaxLen + Encode, N: Unsigned> SszMaxLen for ProgressiveVariableList<T, N> {
    fn ssz_max_len() -> u64 {
        list_max_len::<T>(optional_bound::<N>())
    }
}

impl<T: SszMaxLen + milhouse::Value, N: Unsigned> SszMaxLen for milhouse::Vector<T, N> {
    fn ssz_max_len() -> u64 {
        list_max_len::<T>(N::to_u64())
    }
}

impl<T: SszMaxLen + milhouse::Value, N: Unsigned> SszMaxLen for milhouse::List<T, N> {
    fn ssz_max_len() -> u64 {
        list_max_len::<T>(N::to_u64())
    }
}

impl<T: SszMaxLen + milhouse::Value> SszMaxLen for milhouse::ProgressiveList<T> {
    fn ssz_max_len() -> u64 {
        u64::MAX
    }
}

impl<N: Unsigned + Clone> SszMaxLen for BitVector<N> {
    fn ssz_max_len() -> u64 {
        N::to_u64().div_ceil(8)
    }
}

impl<N: Unsigned + Clone> SszMaxLen for BitList<N> {
    fn ssz_max_len() -> u64 {
        N::to_u64() / 8 + 1
    }
}

impl SszMaxLen for ProgressiveBitList {
    fn ssz_max_len() -> u64 {
        u64::MAX
    }
}

/// An object this node decodes from untrusted bytes: each p2p gossip or req/resp payload type,
/// and `BeaconState` for checkpoint sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    /// `SignedBeaconBlock` (`beacon_block`, `BeaconBlocksByRange/Root`).
    SignedBeaconBlock,
    /// `BeaconState` (checkpoint sync, not p2p).
    BeaconState,
    /// `SignedAggregateAndProof` (`beacon_aggregate_and_proof`).
    SignedAggregateAndProof,
    /// `SingleAttestation` (`beacon_attestation_{subnet_id}`).
    SingleAttestation,
    /// `AttesterSlashing` (`attester_slashing`).
    AttesterSlashing,
    /// `ProposerSlashing` (`proposer_slashing`).
    ProposerSlashing,
    /// `SignedVoluntaryExit` (`voluntary_exit`).
    SignedVoluntaryExit,
    /// `SignedBLSToExecutionChange` (`bls_to_execution_change`).
    SignedBlsToExecutionChange,
    /// `SyncCommitteeMessage` (`sync_committee_{subnet_id}`).
    SyncCommitteeMessage,
    /// `SignedContributionAndProof` (`sync_committee_contribution_and_proof`).
    SignedContributionAndProof,
    /// `SignedExecutionPayloadBid` (`execution_payload_bid`, Gloas).
    SignedExecutionPayloadBid,
    /// `SignedExecutionPayloadEnvelope` (`execution_payload`, `ExecutionPayloadEnvelopesBy*`, Gloas).
    SignedExecutionPayloadEnvelope,
    /// `PayloadAttestationMessage` (`payload_attestation_message`, Gloas).
    PayloadAttestationMessage,
    /// `SignedProposerPreferences` (`proposer_preferences`, Gloas).
    SignedProposerPreferences,
    /// `DataColumnSidecar` (`data_column_sidecar_{subnet_id}`, `DataColumnSidecarsBy*`). Its
    /// Gloas cap depends on the blob schedule ([`NetworkCaps`]).
    DataColumnSidecar,
}

impl ObjectKind {
    /// Every kind.
    pub const ALL: [ObjectKind; 15] = [
        ObjectKind::SignedBeaconBlock,
        ObjectKind::BeaconState,
        ObjectKind::SignedAggregateAndProof,
        ObjectKind::SingleAttestation,
        ObjectKind::AttesterSlashing,
        ObjectKind::ProposerSlashing,
        ObjectKind::SignedVoluntaryExit,
        ObjectKind::SignedBlsToExecutionChange,
        ObjectKind::SyncCommitteeMessage,
        ObjectKind::SignedContributionAndProof,
        ObjectKind::SignedExecutionPayloadBid,
        ObjectKind::SignedExecutionPayloadEnvelope,
        ObjectKind::PayloadAttestationMessage,
        ObjectKind::SignedProposerPreferences,
        ObjectKind::DataColumnSidecar,
    ];

    /// Whether this kind's cap depends on the network, so that it decodes only with a
    /// [`NetworkCaps`] (`DataColumnSidecar`, in both forks).
    pub fn needs_network_caps(self) -> bool {
        self == ObjectKind::DataColumnSidecar
    }

    /// Whether `fork` defines this object.
    pub fn exists_in(self, fork: ForkName) -> bool {
        match self {
            ObjectKind::SignedExecutionPayloadBid
            | ObjectKind::SignedExecutionPayloadEnvelope
            | ObjectKind::PayloadAttestationMessage
            | ObjectKind::SignedProposerPreferences => fork >= ForkName::Gloas,
            _ => true,
        }
    }

    /// The transport limit that applies when the type bound is larger.
    pub fn transport_limit(self) -> usize {
        match self {
            ObjectKind::BeaconState => MAX_SSZ_ENCODING,
            _ => MAX_PAYLOAD_SIZE,
        }
    }
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// The network configuration that caps depend on: the largest blob count of the blob schedule,
/// which bounds the Gloas `DataColumnSidecar`.
///
/// Build it once per network with [`NetworkCaps::from_config`] and pass it to every decode of
/// a column sidecar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetworkCaps {
    max_blobs_per_block: u64,
}

impl NetworkCaps {
    /// The bound without a network config: `MAX_BLOB_COMMITMENTS_PER_BLOCK` blobs, the most a
    /// block can carry (`BlobKZGCommitments` in Fulu, the bid's commitments in Gloas), so no
    /// valid sidecar of any network is larger. Every configured cap is at or below it, and the
    /// Gloas sidecar cap here (8,585,272 bytes) is far above a configured one (44,072 on
    /// Sepolia and Hoodi), so gossip and req/resp decoders use [`NetworkCaps::from_config`].
    /// Only callers without a network (spec vectors, tools) pass this.
    pub const PRESET_BOUND: NetworkCaps = NetworkCaps {
        max_blobs_per_block: MAX_BLOB_COMMITMENTS_PER_BLOCK,
    };

    /// The caps of `config`'s network.
    pub fn from_config(config: &ChainConfig) -> Self {
        Self::from_blob_schedule(config.max_blobs_per_block_electra(), config.blob_schedule())
    }

    /// The largest of `MAX_BLOBS_PER_BLOCK_ELECTRA` and every `BLOB_SCHEDULE` entry's
    /// `MAX_BLOBS_PER_BLOCK`, as `compute_max_data_column_sidecar_size()` takes it: the largest
    /// value of the schedule, whether or not it is the current one.
    pub fn from_blob_schedule(
        max_blobs_per_block_electra: u64,
        blob_schedule: &[BlobParameters],
    ) -> Self {
        let mut max_blobs = max_blobs_per_block_electra;
        for entry in blob_schedule {
            max_blobs = max_blobs.max(entry.max_blobs_per_block);
        }
        Self {
            max_blobs_per_block: max_blobs,
        }
    }

    /// The blob count the column-sidecar cap is computed for.
    pub fn max_blobs_per_block(&self) -> u64 {
        self.max_blobs_per_block
    }
}

/// `compute_max_data_column_sidecar_size()` (`gloas/p2p-interface.md` L324-341): the length of a
/// serialized Gloas `DataColumnSidecar` holding `max_blobs_per_block` cells and proofs.
///
/// The spec serializes such a sidecar; this adds the per-blob lengths to the serialized length
/// of an empty one, which is the same number without allocating. `tests/columns.rs` checks it
/// against the serialized sidecar.
pub fn compute_max_data_column_sidecar_size<E: EthSpec>(network: &NetworkCaps) -> u64 {
    let empty = gloas::DataColumnSidecar::<E> {
        index: 0,
        column: Default::default(),
        kzg_proofs: Default::default(),
        slot: 0,
        beacon_block_root: Root::ZERO,
    };
    let per_blob = field_max_len::<common::Cell<E>>().saturating_add(field_max_len::<KZGProof>());
    (empty.ssz_bytes_len() as u64)
        .saturating_add(network.max_blobs_per_block.saturating_mul(per_blob))
}

/// The length of a serialized Fulu `DataColumnSidecar` (`fulu/das-core.md`) that holds `blobs`
/// cells, commitments and proofs.
///
/// Fulu has no size function like Gloas's `compute_max_data_column_sidecar_size()`. Its bound
/// at an epoch comes from `verify_data_column_sidecar` (`fulu/p2p-interface.md`): at most
/// `get_blob_parameters(epoch).max_blobs_per_block` commitments, and exactly one cell and one
/// proof for each. So this size at that blob limit is the largest valid sidecar of the epoch:
/// 356 fixed bytes and 2,144 per blob in both presets, 45,380 at 21 blobs. `tests/columns.rs`
/// checks it against the serialized sidecar. It saturates at `u64::MAX`.
pub fn fulu_data_column_sidecar_size<E: EthSpec>(blobs: u64) -> u64 {
    // `index`, the `column`, `kzg_commitments` and `kzg_proofs` offsets, the signed header and
    // the inclusion proof.
    let fixed = field_max_len::<ColumnIndex>()
        .saturating_add(3 * OFFSET)
        .saturating_add(field_max_len::<common::SignedBeaconBlockHeader>())
        .saturating_add(field_max_len::<fulu::KZGCommitmentsInclusionProof<E>>());
    let per_blob = field_max_len::<common::Cell<E>>()
        .saturating_add(field_max_len::<KZGCommitment>())
        .saturating_add(field_max_len::<KZGProof>());
    fixed.saturating_add(blobs.saturating_mul(per_blob))
}

/// The type bound of `kind` at `fork`, uncapped; `None` if `fork` does not define it or the
/// kind [needs network caps](ObjectKind::needs_network_caps).
pub fn type_max_len<E: EthSpec>(kind: ObjectKind, fork: ForkName) -> Option<u64> {
    if kind.needs_network_caps() {
        return None;
    }
    type_max_len_for::<E>(kind, fork, &NetworkCaps::PRESET_BOUND)
}

fn type_max_len_for<E: EthSpec>(
    kind: ObjectKind,
    fork: ForkName,
    network: &NetworkCaps,
) -> Option<u64> {
    use ObjectKind as K;
    if !kind.exists_in(fork) {
        return None;
    }
    let by_fork = |fulu: fn() -> u64, gloas: fn() -> u64| match fork {
        ForkName::Fulu => fulu(),
        ForkName::Gloas => gloas(),
    };
    Some(match kind {
        K::SignedBeaconBlock => by_fork(
            fulu::SignedBeaconBlock::<E>::ssz_max_len,
            gloas::SignedBeaconBlock::<E>::ssz_max_len,
        ),
        K::BeaconState => by_fork(
            fulu::BeaconState::<E>::ssz_max_len,
            gloas::BeaconState::<E>::ssz_max_len,
        ),
        // Gloas: unbounded aggregation bits, so the spec's size constant is the bound.
        K::SignedAggregateAndProof => match fork {
            ForkName::Fulu => fulu::SignedAggregateAndProof::<E>::ssz_max_len(),
            ForkName::Gloas => E::MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE,
        },
        K::AttesterSlashing => by_fork(
            fulu::AttesterSlashing::<E>::ssz_max_len,
            gloas::AttesterSlashing::<E>::ssz_max_len,
        ),
        K::SingleAttestation => common::SingleAttestation::ssz_max_len(),
        K::ProposerSlashing => common::ProposerSlashing::ssz_max_len(),
        K::SignedVoluntaryExit => common::SignedVoluntaryExit::ssz_max_len(),
        K::SignedBlsToExecutionChange => common::SignedBLSToExecutionChange::ssz_max_len(),
        K::SyncCommitteeMessage => common::SyncCommitteeMessage::ssz_max_len(),
        K::SignedContributionAndProof => common::SignedContributionAndProof::<E>::ssz_max_len(),
        K::SignedExecutionPayloadBid => gloas::SignedExecutionPayloadBid::<E>::ssz_max_len(),
        K::SignedExecutionPayloadEnvelope => {
            gloas::SignedExecutionPayloadEnvelope::<E>::ssz_max_len()
        }
        K::PayloadAttestationMessage => gloas::PayloadAttestationMessage::ssz_max_len(),
        K::SignedProposerPreferences => gloas::SignedProposerPreferences::ssz_max_len(),
        // Gloas: unbounded column lists, so the spec's size function is the bound.
        K::DataColumnSidecar => match fork {
            ForkName::Fulu => fulu::DataColumnSidecar::<E>::ssz_max_len(),
            ForkName::Gloas => compute_max_data_column_sidecar_size::<E>(network),
        },
    })
}

/// The byte cap for `kind` at `fork`: its type bound, or the transport limit where the type
/// bound is larger. `None` if `fork` does not define `kind`, or if the kind
/// [needs network caps](ObjectKind::needs_network_caps): use [`max_size_for`] for it.
pub fn max_size<E: EthSpec>(kind: ObjectKind, fork: ForkName) -> Option<usize> {
    if kind.needs_network_caps() {
        return None;
    }
    // The network does not enter any other kind's cap.
    max_size_for::<E>(kind, fork, &NetworkCaps::PRESET_BOUND)
}

/// [`max_size`] on the network `network` was built from, for every kind. Only the Gloas
/// `DataColumnSidecar` cap depends on it.
pub fn max_size_for<E: EthSpec>(
    kind: ObjectKind,
    fork: ForkName,
    network: &NetworkCaps,
) -> Option<usize> {
    let bound = type_max_len_for::<E>(kind, fork, network)?;
    let limit = kind.transport_limit();
    Some(usize::try_from(bound).map_or(limit, |b| b.min(limit)))
}

/// Worst-case peak live heap of decoding a Gloas `SignedExecutionPayloadEnvelope`, in requested
/// bytes per input byte, excluding allocator overhead (see the module docs). 18 × 10 MiB =
/// 180 MiB at the cap.
pub const ENVELOPE_DECODE_PEAK_HEAP_PER_INPUT_BYTE: usize = 18;
/// Worst-case total heap bytes allocated while decoding an envelope, per input byte. 24 × 10 MiB
/// = 240 MiB at the cap.
pub const ENVELOPE_DECODE_ALLOCATED_PER_INPUT_BYTE: usize = 24;
/// Worst-case peak live heap of decoding a Gloas `SignedBeaconBlock`, per input byte.
pub const BLOCK_DECODE_PEAK_HEAP_PER_INPUT_BYTE: usize = 2;
/// Worst-case total heap bytes allocated while decoding a Gloas block, per input byte.
pub const BLOCK_DECODE_ALLOCATED_PER_INPUT_BYTE: usize = 2;

/// The per-allocation minimum of the allocator-adjusted heap model: glibc's smallest chunk on
/// 64-bit targets.
pub const MIN_ALLOCATION_BYTES: usize = 32;
/// Envelope peak live heap per input byte, allocator-adjusted heap model (not a process-RSS
/// bound; see the module docs). 21 × 10 MiB = 210 MiB at the cap.
pub const ENVELOPE_DECODE_PEAK_HEAP_MODEL_PER_INPUT_BYTE: usize = 21;
/// Envelope total heap allocated per input byte, allocator-adjusted heap model. 26 × 10 MiB =
/// 260 MiB at the cap.
pub const ENVELOPE_DECODE_ALLOCATED_HEAP_MODEL_PER_INPUT_BYTE: usize = 26;
/// Gloas block peak live heap per input byte, allocator-adjusted heap model.
pub const BLOCK_DECODE_PEAK_HEAP_MODEL_PER_INPUT_BYTE: usize = 2;
/// Gloas block total heap allocated per input byte, allocator-adjusted heap model.
pub const BLOCK_DECODE_ALLOCATED_HEAP_MODEL_PER_INPUT_BYTE: usize = 2;
