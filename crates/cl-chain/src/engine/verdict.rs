//! What cl-chain makes of an `engine_newPayloadV5` answer: an [`ElVerdict`] for each reply, and
//! the [`ExecutionStatuses`] of the payloads it has asked about.

use consensus_types::primitives::Hash32;
use engine_api::PayloadStatusV1;
use ethswarm_proto::engine as pb;
use std::collections::HashMap;

/// The EL's verdict on one payload, or why there is none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElVerdict {
    /// `VALID`.
    Valid,
    /// `INVALID` or `INVALID_BLOCK_HASH`, with `latestValidHash` as the EL gave it.
    Invalid {
        /// `latestValidHash`: `None` when the EL sent `null`.
        latest_valid_hash: Option<Hash32>,
    },
    /// `SYNCING` or `ACCEPTED`: not verified yet, and not refuted.
    Optimistic,
    /// No verdict.
    NotVerified(Reason),
}

/// Why a call gave no verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// A status this client cannot name.
    UnknownStatus,
    /// A reply that breaks the Engine API or the engine.v1 contract.
    Malformed,
    /// cl-engine answered this `EngineErrorKind`.
    Engine(i32),
    /// The call failed with this gRPC status.
    Rpc(tonic::Code),
    /// No answer in time.
    Timeout,
    /// No connection to cl-engine.
    Connect,
}

impl ElVerdict {
    /// Whether the envelope may be imported.
    #[must_use]
    pub fn permits_payload_import(&self) -> bool {
        todo!()
    }

    /// The `verdict` label of `chain_new_payload_verdicts_total`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        todo!()
    }
}

/// The verdict of one `PayloadStatusV1`.
#[must_use]
pub fn map(_status: &PayloadStatusV1) -> ElVerdict {
    todo!()
}

/// The verdict of a `PayloadStatusV1` as JSON.
#[must_use]
pub fn map_json(_json: &[u8]) -> ElVerdict {
    todo!()
}

/// The verdict of an engine.v1 `PayloadStatus`.
#[must_use]
pub fn map_proto(_status: &pb::PayloadStatus) -> ElVerdict {
    todo!()
}

/// What cl-chain knows of one execution payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// The EL answered `VALID`.
    Valid,
    /// Imported on `SYNCING` or `ACCEPTED`.
    Optimistic,
    /// The EL answered `INVALID` or `INVALID_BLOCK_HASH`.
    Invalid,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    status: ExecutionStatus,
    parent_hash: Hash32,
}

/// The [`ExecutionStatus`] of each payload, by its `block_hash`.
#[derive(Debug, Default)]
pub struct ExecutionStatuses {
    blocks: HashMap<Hash32, Entry>,
}

impl ExecutionStatuses {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `verdict` for the payload `block_hash` whose parent is `parent_hash`.
    pub fn record(
        &mut self,
        _block_hash: Hash32,
        _parent_hash: Hash32,
        _verdict: &ElVerdict,
    ) -> Option<ExecutionStatus> {
        todo!()
    }

    /// The status of the payload `block_hash`.
    #[must_use]
    pub fn status(&self, _block_hash: &Hash32) -> Option<ExecutionStatus> {
        let _ = &self.blocks;
        todo!()
    }
}
