//! `ExecutionPayloadV4` (`amsterdam.md`), `WithdrawalV1` (`shanghai.md`) and `PayloadStatusV1`
//! (`paris.md`), with their JSON field names.

use crate::encoding::{Data, FixedData, Quantity, Quantity256};
use consensus_types::gloas::{ExecutionPayload, Withdrawal};
use consensus_types::EthSpec;
use serde::{Deserialize, Serialize};

/// `BYTES_PER_LOGS_BLOOM`: `logsBloom` is `DATA`, 256 bytes.
pub const BYTES_PER_LOGS_BLOOM: usize = 256;

/// `WithdrawalV1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WithdrawalV1 {
    pub index: Quantity,
    pub validator_index: Quantity,
    pub address: FixedData<20>,
    /// In Gwei.
    pub amount: Quantity,
}

/// `ExecutionPayloadV4`: `ExecutionPayloadV3` with `blockAccessList` and `slotNumber`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionPayloadV4 {
    pub parent_hash: FixedData<32>,
    pub fee_recipient: FixedData<20>,
    pub state_root: FixedData<32>,
    pub receipts_root: FixedData<32>,
    pub logs_bloom: FixedData<BYTES_PER_LOGS_BLOOM>,
    pub prev_randao: FixedData<32>,
    pub block_number: Quantity,
    pub gas_limit: Quantity,
    pub gas_used: Quantity,
    pub timestamp: Quantity,
    pub extra_data: Data,
    pub base_fee_per_gas: Quantity256,
    pub block_hash: FixedData<32>,
    pub transactions: Vec<Data>,
    pub withdrawals: Vec<WithdrawalV1>,
    pub blob_gas_used: Quantity,
    pub excess_blob_gas: Quantity,
    /// The RLP-encoded block access list (EIP-7928), as the payload carries it.
    pub block_access_list: Data,
    pub slot_number: Quantity,
}

impl From<&Withdrawal> for WithdrawalV1 {
    fn from(_w: &Withdrawal) -> Self {
        todo!()
    }
}

impl<E: EthSpec> From<&ExecutionPayload<E>> for ExecutionPayloadV4 {
    fn from(_p: &ExecutionPayload<E>) -> Self {
        todo!()
    }
}

/// `PayloadStatusV1.status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationStatus {
    Valid,
    Invalid,
    Syncing,
    Accepted,
    /// Deprecated since `engine_newPayloadV2`; an EL that still sends it means INVALID.
    InvalidBlockHash,
}

/// `PayloadStatusV1`. `latestValidHash` and `validationError` are `null` when the EL has none;
/// a missing one reads as `null`. Fields this version does not define are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadStatusV1 {
    pub status: ValidationStatus,
    pub latest_valid_hash: Option<FixedData<32>>,
    pub validation_error: Option<String>,
}
