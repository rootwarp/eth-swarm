//! The hooks of `on_execution_payload_envelope` in an envelope import of the chain core
//! ([`EnvelopeHooks`]): the core's data availability check, the envelope signature to
//! cl-verify, and the payload to the EL through the core's [`NewPayload`] call. The core's
//! [`ExecutionStatuses`] records the verdict.

use crate::engine::client::NewPayload;
use crate::engine::verdict::{ElVerdict, ExecutionStatuses, Reason};
use crate::import::block::verify_sets;
use crate::verify::client::BlsOutcome;
use consensus_types::gloas::{BeaconState, ExecutionPayloadBid, ExecutionPayloadEnvelope};
use consensus_types::primitives::Root;
use ethswarm_proto::verify::BlsSet;
use fork_choice::{
    DataAvailability, DataAvailabilityCheck, ExecutionEngine, NewPayloadRequestRef, PayloadImport,
    SignatureVerifier,
};
use state_transition::{BackendError, Preset, SignatureSet};
use std::cell::{Cell, RefCell};
use std::time::Duration;
use tokio::runtime::Handle;

/// The hooks of one envelope import.
pub(super) struct EnvelopeHooks<'a, E: Preset> {
    /// One VerifyBls call, with the deadline of the import.
    pub(super) verdict: &'a dyn Fn(Vec<BlsSet>) -> BlsOutcome,
    pub(super) engine: &'a dyn NewPayload<E>,
    pub(super) data: &'a dyn DataAvailabilityCheck,
    /// The runtime of the core: the newPayload call runs on it, and the core thread waits.
    pub(super) runtime: &'a Handle,
    /// The wait for the EL's verdict, from the start of the call.
    pub(super) timeout: Duration,
    pub(super) envelope: &'a ExecutionPayloadEnvelope<E>,
    /// The committed bid: `latest_execution_payload_bid` of the post-state of the block.
    pub(super) bid: &'a ExecutionPayloadBid<E>,
    pub(super) statuses: RefCell<&'a mut ExecutionStatuses>,
    /// The EL's verdict, once the call is made.
    pub(super) el: Cell<Option<ElVerdict>>,
}

impl<E: Preset> DataAvailabilityCheck for EnvelopeHooks<'_, E> {
    fn is_data_available(&self, beacon_block_root: Root) -> DataAvailability {
        self.data.is_data_available(beacon_block_root)
    }
}

impl<E: Preset> SignatureVerifier<E> for EnvelopeHooks<'_, E> {
    fn verify_signature_sets(
        &self,
        state: &BeaconState<E>,
        sets: &[SignatureSet],
    ) -> Result<bool, BackendError> {
        verify_sets(state, sets, self.verdict)
    }
}

impl<E: Preset> ExecutionEngine<E> for EnvelopeHooks<'_, E> {
    /// Sends the envelope and its bid (the request is built from them again), records the
    /// verdict, and permits the import only if the EL has not contradicted itself and the table
    /// permits it. The wait covers the whole call, a connection to cl-engine included: no
    /// answer within it is [`Reason::Timeout`], and the call is dropped. `INVALID` with a `null`
    /// `latestValidHash` refuses this envelope and records nothing for its `block_hash`
    /// ([`ExecutionStatuses::record`]): this payload does not hash to it, and the honest one can.
    fn verify_and_notify_new_payload(&self, _: &NewPayloadRequestRef<'_, E>) -> PayloadImport {
        let call = self.engine.new_payload(self.envelope, self.bid);
        let verdict = self.runtime.block_on(async {
            tokio::time::timeout(self.timeout, call)
                .await
                .unwrap_or(ElVerdict::NotVerified(Reason::Timeout))
        });
        self.el.set(Some(verdict));
        let payload = &self.envelope.payload;
        let (hash, parent) = (payload.block_hash, payload.parent_hash);
        let mut statuses = self.statuses.borrow_mut();
        statuses.record(hash, parent, &verdict);
        if statuses.el_contradiction() || !statuses.permits_payload_import(&hash, &parent, &verdict)
        {
            PayloadImport::Refused
        } else if verdict == ElVerdict::Valid {
            PayloadImport::Valid
        } else {
            PayloadImport::Optimistic
        }
    }
}
