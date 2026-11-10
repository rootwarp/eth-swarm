//! Engine API JSON for Gloas, to ethereum/execution-apis `fd2ba6a`: the `engine_newPayloadV5`
//! params of an execution payload envelope and its committed bid, and the `PayloadStatusV1` the
//! EL answers with.
//!
//! Pure: no I/O and no wiring. The caller serializes [`NewPayloadV5Params`] with any serde JSON
//! serializer and sends it as the JSON-RPC `params` of [`methods::NEW_PAYLOAD_V5`].
//!
//! - [`encoding`]: the `DATA` and `QUANTITY` encodings (`src/engine/common.md`).
//! - [`payload`]: `ExecutionPayloadV4` (`amsterdam.md`), `WithdrawalV1` (`shanghai.md`) and
//!   `PayloadStatusV1` (`paris.md`).
//! - [`new_payload`]: [`new_payload_v5_params`] and the consensus-specs v1.7.0-beta.4 helpers it
//!   uses, `kzg_commitment_to_versioned_hash` and `get_execution_requests_list`.
//! - [`methods`]: the Engine API methods of each fork.

pub mod encoding;
pub mod methods;
pub mod new_payload;
pub mod payload;

pub use encoding::{Data, FixedData, Quantity, Quantity256};
pub use methods::{engine_methods, EngineMethods};
pub use new_payload::{
    get_execution_requests_list, kzg_commitment_to_versioned_hash, new_payload_v5_params,
    NewPayloadV5Params,
};
pub use payload::{ExecutionPayloadV4, PayloadStatusV1, ValidationStatus, WithdrawalV1};
