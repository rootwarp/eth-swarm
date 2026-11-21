//! Gloas gossip validation (`specs/gloas/p2p-interface.md` at consensus-specs v1.7.0-beta.4)
//! as pure functions of a [`Seen`] set and the fork-choice store.
//!
//! - [`execution_payload`]: the `execution_payload` topic,
//!   [`validate_execution_payload_envelope_gossip`] (L811-885).
//! - [`payload_attestation`]: the `payload_attestation_message` topic,
//!   [`validate_payload_attestation_message_gossip`] (L891-954).
//! - [`seen`]: the spec's `Seen` (L188-219), for the topics of this crate, with bounds by slot
//!   on the envelope keys and payloads and on the payload attestation keys.
//! - [`verdict`]: the [`Verdict`] of a message, and why it is IGNORE or REJECT.
//!
//! The crate does no I/O and links no BLS library. A validation function runs each check that
//! needs no BLS, in spec order, and then gives [`Verdict::Pending`] with the signature sets and
//! the [`SeenKey`] of the message. The caller verifies the sets with its own backend and gives
//! the BLS verdict to [`Seen::resolve`]. Only a valid signature puts the key into `Seen`, so an
//! invalid copy of a message does not stop a later valid copy.
//!
//! A verifier that gives no verdict (timeout, overload, a service that is not available) makes
//! the message IGNORE, never ACCEPT. REJECT is only for a proven spec violation.
//!
//! No gossip dispatch calls this crate yet.

pub mod execution_payload;
pub mod payload_attestation;
pub mod seen;
pub mod verdict;

pub use execution_payload::{
    validate_execution_payload_envelope_gossip, verify_execution_requests_limits,
    verify_withdrawals_limit, RequestCounts,
};
pub use payload_attestation::{
    is_current_slot, oldest_current_slot, validate_payload_attestation_message_gossip,
    MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS,
};
pub use seen::{
    Seen, SeenKey, SeenPayload, MAX_EXECUTION_PAYLOAD_ENVELOPES_PER_SLOT,
    MAX_EXECUTION_PAYLOAD_ENVELOPE_SEEN_SLOTS, MAX_PAYLOAD_ATTESTATION_HEADS_PER_SLOT,
    MAX_PAYLOAD_ATTESTATION_SEEN_SLOTS,
};
pub use verdict::{IgnoreReason, RejectReason, RequestKind, Verdict};

use consensus_types::gloas::{BeaconBlock, BeaconState, Checkpoint};
use consensus_types::primitives::Root;
use fork_choice::Store;
use state_transition::Preset;
use std::num::NonZeroU64;

/// What the gossip checks read of the fork-choice store.
///
/// The spec reads `store.blocks` for a block that the node has seen from any source, and
/// `store.block_states` for a block that passed validation. The fork-choice [`Store`] adds a
/// block and its post-state together, so for it the two sets are equal. A caller that also
/// keeps the blocks that failed validation can give a view in which they are seen but have no
/// post-state.
///
/// The spec's store keeps every block. The fork-choice [`Store`] drops the blocks that do not
/// descend from the finalized block, and retains them with their post-states for a window
/// after the prune. Its view reads them there too ([`Store::block_or_dropped`] and
/// [`Store::block_state_or_dropped`]), so an envelope for a retained dropped block is
/// validated, not ignored as unknown. [`Store::block`] and [`Store::block_state`] have only
/// the blocks that the store keeps. After the window the store forgets a dropped block, and
/// an envelope for it is ignored.
///
/// The head state of the view of the fork-choice [`Store`] runs `get_head` on each call, as the
/// spec does for each payload attestation message.
pub trait StoreView<E: Preset> {
    /// `store.blocks[root]`.
    fn block(&self, root: Root) -> Option<&BeaconBlock<E>>;

    /// `store.block_states[root]`.
    fn block_state(&self, root: Root) -> Option<&BeaconState<E>>;

    /// `store.finalized_checkpoint`.
    fn finalized_checkpoint(&self) -> &Checkpoint;

    /// `store.genesis_time_ms`.
    fn genesis_time_ms(&self) -> u64;

    /// The config value `SLOT_DURATION_MS` of `compute_time_at_slot_ms`.
    fn slot_duration_ms(&self) -> NonZeroU64;

    /// `store.block_states[get_head(store).root]`, or `None` if the store cannot give it: a
    /// fault of the store.
    fn head_state(&self) -> Option<&BeaconState<E>>;

    /// `store.time_ms`: the time of the last tick of the store. The envelope topic reads it
    /// only for the bound of [`Seen`] ([`oldest_current_slot`]), and the spec's function reads
    /// no clock. A time that decreases does not lower the floor of [`Seen`].
    fn time_ms(&self) -> u64;
}

impl<E: Preset> StoreView<E> for Store<E> {
    fn block(&self, root: Root) -> Option<&BeaconBlock<E>> {
        Store::block_or_dropped(self, root)
    }

    fn block_state(&self, root: Root) -> Option<&BeaconState<E>> {
        Store::block_state_or_dropped(self, root)
    }

    fn finalized_checkpoint(&self) -> &Checkpoint {
        Store::finalized_checkpoint(self)
    }

    fn genesis_time_ms(&self) -> u64 {
        Store::genesis_time_ms(self)
    }

    fn slot_duration_ms(&self) -> NonZeroU64 {
        Store::slot_duration_ms(self)
    }

    fn head_state(&self) -> Option<&BeaconState<E>> {
        // The head is a block of the store, so `Store::block_state` has its post-state.
        let head = fork_choice::get_head(self).ok()?;
        Store::block_state(self, head.root)
    }

    fn time_ms(&self) -> u64 {
        Store::time_ms(self)
    }
}
