//! The spec's `Seen` (`gloas/p2p-interface.md` L188-219), for the topics of this crate.
//!
//! A validation function only reads `Seen`. Its [`Verdict::Pending`] carries a [`SeenKey`], and
//! [`Seen::resolve`] adds that key only for a valid signature, the last check of a topic. Thus
//! `Seen` holds only fully valid messages: a copy with an invalid signature, or one that the
//! verifier gave no verdict on, leaves it unchanged, and a later valid copy can still pass.
//!
//! The spec does not prune `Seen`, and neither does this type. It grows by one entry for each
//! accepted envelope, which a block of the chain limits. The change that connects it to gossip
//! must bound it, for example by the finalized slot.

use crate::verdict::{IgnoreReason, RejectReason, Verdict};
use consensus_types::primitives::{BuilderIndex, Hash32, Root};
use state_transition::BackendError;
use std::collections::{HashMap, HashSet};

/// The keys of the fully valid gossip messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Seen {
    /// `seen.execution_payload_envelopes`.
    execution_payload_envelopes: HashSet<(Root, BuilderIndex)>,
    /// `seen.execution_payloads`, with only what its readers need of each payload.
    execution_payloads: HashMap<Hash32, SeenPayload>,
}

/// What `seen.execution_payloads[block_hash]` keeps of a payload. The spec keeps the whole
/// payload, and its reader (the `execution_payload_bid` topic) reads only `gas_limit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeenPayload {
    /// `payload.gas_limit`.
    pub gas_limit: u64,
}

/// The key of a pending message, which [`Seen::resolve`] adds once the message is fully valid.
/// Only the validation functions of this crate make one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenKey(Key);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    /// The key of an envelope, with the payload that `Seen` also keeps.
    ExecutionPayloadEnvelope {
        block_root: Root,
        builder_index: BuilderIndex,
        block_hash: Hash32,
        payload: SeenPayload,
    },
}

impl SeenKey {
    /// The key of an envelope for `block_root` from `builder_index`, whose payload has
    /// `block_hash` and `gas_limit`.
    pub(crate) fn execution_payload_envelope(
        block_root: Root,
        builder_index: BuilderIndex,
        block_hash: Hash32,
        gas_limit: u64,
    ) -> Self {
        Self(Key::ExecutionPayloadEnvelope {
            block_root,
            builder_index,
            block_hash,
            payload: SeenPayload { gas_limit },
        })
    }
}

impl Seen {
    /// `(block_root, builder_index) in seen.execution_payload_envelopes`.
    pub fn has_execution_payload_envelope(
        &self,
        block_root: Root,
        builder_index: BuilderIndex,
    ) -> bool {
        self.execution_payload_envelopes
            .contains(&(block_root, builder_index))
    }

    /// `seen.execution_payloads[block_hash]`.
    pub fn execution_payload(&self, block_hash: Hash32) -> Option<&SeenPayload> {
        self.execution_payloads.get(&block_hash)
    }

    /// The end of a [`Verdict::Pending`]: `signatures` is the BLS verdict of its sets, as
    /// `state_transition::SignatureBackend` gives it.
    ///
    /// - `Ok(true)`: the message is fully valid. `Seen` gets `seen_key`, and the verdict is
    ///   ACCEPT. If another copy got the key first, the verdict is IGNORE and `Seen` does not
    ///   change, so only one copy of a message is ACCEPT.
    /// - `Ok(false)`: REJECT, and `Seen` does not change.
    /// - `Err`: no verdict. IGNORE, and `Seen` does not change.
    pub fn resolve(
        &mut self,
        seen_key: SeenKey,
        signatures: Result<bool, BackendError>,
    ) -> Verdict {
        match signatures {
            Ok(true) => self.commit(seen_key),
            Ok(false) => Verdict::Reject(RejectReason::InvalidSignature),
            Err(_) => Verdict::Ignore(IgnoreReason::NoSignatureVerdict),
        }
    }

    /// Adds the key of a fully valid message ("Mark this envelope as seen and store its
    /// payload", L881-883). Only [`Seen::resolve`] calls it, after a valid signature.
    fn commit(&mut self, SeenKey(key): SeenKey) -> Verdict {
        match key {
            Key::ExecutionPayloadEnvelope {
                block_root,
                builder_index,
                block_hash,
                payload,
            } => {
                if !self
                    .execution_payload_envelopes
                    .insert((block_root, builder_index))
                {
                    return Verdict::Ignore(IgnoreReason::EnvelopeAlreadySeen {
                        block_root,
                        builder_index,
                    });
                }
                self.execution_payloads.insert(block_hash, payload);
                Verdict::Accept
            }
        }
    }
}
