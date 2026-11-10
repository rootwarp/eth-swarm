//! What cl-chain makes of an `engine_newPayloadV5` answer: an [`ElVerdict`] for each reply, and
//! the [`ExecutionStatuses`] of the payloads it has asked about.
//!
//! - **The map** ([`map`], execution-apis `paris.md` L99-118): `VALID` is [`ElVerdict::Valid`];
//!   `INVALID` and `INVALID_BLOCK_HASH` are [`ElVerdict::Invalid`] with `latestValidHash` as
//!   given, `null` included; `SYNCING` and `ACCEPTED` are [`ElVerdict::Optimistic`]. It reads one
//!   reply: two contradicting replies for one payload are the caller's to reconcile.
//! - **Fail closed.** A status this client cannot name, a reply that breaks the contract, an
//!   error from cl-engine, a failed call and a timeout are [`ElVerdict::NotVerified`], never
//!   `Valid`: [`map_json`] for the Engine API JSON, [`map_proto`] for engine.v1, where
//!   `PAYLOAD_STATUS_KIND_UNSPECIFIED` breaks the contract and an unknown value is not decoded.
//! - **The import gate** ([`ElVerdict::permits_payload_import`]): `Valid` and `Optimistic` only.
//!   No data availability check: that is a separate gate.
//! - **The table** ([`ExecutionStatuses`]): see its docs.

use consensus_types::primitives::Hash32;
use engine_api::{FixedData, PayloadStatusV1, ValidationStatus};
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
    /// A status this client cannot name: a string the Engine API does not define, no status,
    /// or an engine.v1 value it does not know.
    UnknownStatus,
    /// A reply that breaks the Engine API or the engine.v1 contract: a field that does not
    /// decode, `PAYLOAD_STATUS_KIND_UNSPECIFIED`, a `latest_valid_hash` of neither 0 nor 32
    /// bytes, neither a status nor an error, or another call's `seq`.
    Malformed,
    /// cl-engine answered an `EngineError` of this `EngineErrorKind` (its value, maybe one this
    /// client does not know): the EL is unreachable, timed out, refused the params, ...
    Engine(i32),
    /// The call failed with this gRPC status.
    Rpc(tonic::Code),
    /// No answer from cl-engine in time.
    Timeout,
    /// No connection to cl-engine.
    Connect,
}

impl ElVerdict {
    /// Every `label`, in order.
    pub const LABELS: [&'static str; 4] = ["valid", "invalid", "optimistic", "not_verified"];

    /// Whether the envelope may be imported: on `Valid` and `Optimistic` only.
    #[must_use]
    pub fn permits_payload_import(&self) -> bool {
        matches!(self, Self::Valid | Self::Optimistic)
    }

    /// The `verdict` label of `chain_new_payload_verdicts_total`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        let i = match self {
            Self::Valid => 0,
            Self::Invalid { .. } => 1,
            Self::Optimistic => 2,
            Self::NotVerified(_) => 3,
        };
        Self::LABELS[i]
    }
}

/// The verdict of one `PayloadStatusV1`. `validationError` does not change it.
#[must_use]
pub fn map(status: &PayloadStatusV1) -> ElVerdict {
    match status.status {
        ValidationStatus::Valid => ElVerdict::Valid,
        ValidationStatus::Invalid | ValidationStatus::InvalidBlockHash => ElVerdict::Invalid {
            latest_valid_hash: status.latest_valid_hash.map(|h| Hash32::from(h.0)),
        },
        ValidationStatus::Syncing | ValidationStatus::Accepted => ElVerdict::Optimistic,
    }
}

/// The verdict of a `PayloadStatusV1` as JSON. JSON that does not decode is
/// [`Reason::UnknownStatus`] unless its `status` is one the Engine API defines, then
/// [`Reason::Malformed`].
#[must_use]
pub fn map_json(json: &[u8]) -> ElVerdict {
    if let Ok(status) = serde_json::from_slice::<PayloadStatusV1>(json) {
        return map(&status);
    }
    let known = serde_json::from_slice::<serde_json::Value>(json)
        .ok()
        .and_then(|mut value| value.get_mut("status").map(serde_json::Value::take))
        .is_some_and(|status| serde_json::from_value::<ValidationStatus>(status).is_ok());
    ElVerdict::NotVerified(if known {
        Reason::Malformed
    } else {
        Reason::UnknownStatus
    })
}

/// The verdict of an engine.v1 `PayloadStatus`.
#[must_use]
pub fn map_proto(status: &pb::PayloadStatus) -> ElVerdict {
    use pb::PayloadStatusKind as Kind;
    let kind = match Kind::try_from(status.status) {
        Ok(Kind::Valid) => ValidationStatus::Valid,
        Ok(Kind::Invalid) => ValidationStatus::Invalid,
        Ok(Kind::Syncing) => ValidationStatus::Syncing,
        Ok(Kind::Accepted) => ValidationStatus::Accepted,
        Ok(Kind::InvalidBlockHash) => ValidationStatus::InvalidBlockHash,
        Ok(Kind::Unspecified) => return ElVerdict::NotVerified(Reason::Malformed),
        Err(_) => return ElVerdict::NotVerified(Reason::UnknownStatus),
    };
    let latest_valid_hash = match status.latest_valid_hash.as_slice() {
        [] => None,
        bytes => match <[u8; 32]>::try_from(bytes) {
            Ok(hash) => Some(FixedData(hash)),
            Err(_) => return ElVerdict::NotVerified(Reason::Malformed),
        },
    };
    map(&PayloadStatusV1 {
        status: kind,
        latest_valid_hash,
        validation_error: None,
    })
}

/// What cl-chain knows of one execution payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// The EL answered `VALID`, for it or a descendant.
    Valid,
    /// Imported on `SYNCING` or `ACCEPTED`, and not `VALID` yet.
    Optimistic,
    /// The EL answered `INVALID` or `INVALID_BLOCK_HASH`.
    Invalid,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    status: ExecutionStatus,
    parent_hash: Hash32,
}

/// The [`ExecutionStatus`] of each payload cl-chain has a verdict for, by its `block_hash`,
/// with its `parent_hash`. Nothing reads it yet; it will give `execution_optimistic` and the
/// confirmed and safe hashes. It is never pruned yet.
///
/// - `Valid` makes the payload `Valid`, and every ancestor still `Optimistic` too, walking the
///   recorded parent hashes up to the first ancestor that is not recorded or not `Optimistic`.
/// - `Optimistic` makes a payload with no status `Optimistic`, and leaves `Valid` alone.
/// - `Invalid` makes the payload `Invalid`, whatever it was. `INVALID` is final (`paris.md`
///   L114): a later `Valid` or `Optimistic` leaves it `Invalid`. Its descendants are not
///   touched here.
/// - `NotVerified` records nothing: a payload without a status stays without one, and an
///   earlier status stays as it is.
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

    /// Records `verdict` for the payload `block_hash` whose parent is `parent_hash` (see the
    /// type docs), and returns the payload's status after it.
    pub fn record(
        &mut self,
        block_hash: Hash32,
        parent_hash: Hash32,
        verdict: &ElVerdict,
    ) -> Option<ExecutionStatus> {
        let new = match verdict {
            ElVerdict::Valid => ExecutionStatus::Valid,
            ElVerdict::Optimistic => ExecutionStatus::Optimistic,
            ElVerdict::Invalid { .. } => ExecutionStatus::Invalid,
            ElVerdict::NotVerified(_) => return self.status(&block_hash),
        };
        let entry = self.blocks.entry(block_hash).or_insert(Entry {
            status: new,
            parent_hash,
        });
        entry.status = match (entry.status, new) {
            (ExecutionStatus::Invalid, _) | (_, ExecutionStatus::Invalid) => {
                ExecutionStatus::Invalid
            }
            (ExecutionStatus::Valid, _) | (_, ExecutionStatus::Valid) => ExecutionStatus::Valid,
            (ExecutionStatus::Optimistic, ExecutionStatus::Optimistic) => {
                ExecutionStatus::Optimistic
            }
        };
        let (status, mut ancestor) = (entry.status, entry.parent_hash);
        if status == ExecutionStatus::Valid {
            // Each step turns one Optimistic entry Valid, so the walk ends.
            while let Some(entry) = self.blocks.get_mut(&ancestor) {
                if entry.status != ExecutionStatus::Optimistic {
                    break;
                }
                entry.status = ExecutionStatus::Valid;
                ancestor = entry.parent_hash;
            }
        }
        Some(status)
    }

    /// The status of the payload `block_hash`, `None` if it has none.
    #[must_use]
    pub fn status(&self, block_hash: &Hash32) -> Option<ExecutionStatus> {
        self.blocks.get(block_hash).map(|entry| entry.status)
    }
}
