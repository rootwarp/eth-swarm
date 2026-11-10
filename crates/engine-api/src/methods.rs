//! The Engine API methods of each fork. Gloas runs on Amsterdam (`amsterdam.md`): it uses
//! `engine_newPayloadV5` and `engine_forkchoiceUpdatedV4` only, and never falls back to an
//! earlier version. Fulu runs on Osaka, which keeps Prague's `engine_newPayloadV4` and Cancun's
//! `engine_forkchoiceUpdatedV3` (`osaka.md`).
//!
//! This crate builds the `engine_newPayloadV5` params only. The `engine_forkchoiceUpdatedV4`
//! arguments are built in `cl_chain::engine::fcu`.

use consensus_types::ForkName;

/// `engine_newPayloadV5` (`amsterdam.md`).
pub const NEW_PAYLOAD_V5: &str = "engine_newPayloadV5";
/// `engine_forkchoiceUpdatedV4` (`amsterdam.md`).
pub const FORKCHOICE_UPDATED_V4: &str = "engine_forkchoiceUpdatedV4";
/// `engine_newPayloadV4` (`prague.md`), the Osaka version.
pub const NEW_PAYLOAD_V4: &str = "engine_newPayloadV4";
/// `engine_forkchoiceUpdatedV3` (`cancun.md`), the Osaka version.
pub const FORKCHOICE_UPDATED_V3: &str = "engine_forkchoiceUpdatedV3";

/// The methods a fork's payloads and fork choice updates are sent with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineMethods {
    /// The `engine_newPayload` version.
    pub new_payload: &'static str,
    /// The `engine_forkchoiceUpdated` version.
    pub forkchoice_updated: &'static str,
}

/// The methods of `fork`.
pub const fn engine_methods(_fork: ForkName) -> EngineMethods {
    todo!()
}
