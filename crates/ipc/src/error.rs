//! Contract errors and their two wire forms.
//!
//! A [`ContractError`] carries a `common.v1.ErrorCode` and a detail string. On the wire it is a
//! `common.v1.Error` ([`ContractError::to_wire`]), and a failed call or stream carries that
//! `Error` prost-encoded in the `tonic::Status` details ([`to_status`]), so the peer reads back
//! the exact code ([`error_from_status`]). A status without such details, which the transport
//! itself raised, is mapped from its gRPC code.

use prost::Message;
use tonic::{Code, Status};

pub use ethswarm_proto::common::{Error as WireError, ErrorCode};

/// `common.v1.Error.detail` max length in bytes (error.proto).
pub const MAX_DETAIL_BYTES: usize = 1024;

/// A broken contract rule, as the receiver reports it, or an error a peer sent.
///
/// A peer may send a non-zero `ErrorCode` this build does not know (a newer build added it).
/// That error is kept as received ([`Self::raw_code`]) and is IGNORE ([`Self::is_ignore`]):
/// [`Self::code`] is then `ERROR_CODE_UNSPECIFIED`, which is neither success nor a violation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}: {detail}", code_name(*.code, *.raw))]
pub struct ContractError {
    code: ErrorCode,
    /// The code as on the wire; differs from `code` only for an unknown code.
    raw: i32,
    detail: String,
}

fn code_name(code: ErrorCode, raw: i32) -> String {
    if code == ErrorCode::Unspecified {
        format!("unknown error code {raw}")
    } else {
        code.as_str_name().to_owned()
    }
}

impl ContractError {
    /// An error with `code`; `detail` is truncated to [`MAX_DETAIL_BYTES`].
    #[must_use]
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            raw: code as i32,
            detail: truncate(detail.into()),
        }
    }

    /// An error a peer sent with a non-zero code this build does not know.
    fn unknown(raw: i32, detail: String) -> Self {
        Self {
            code: ErrorCode::Unspecified,
            raw,
            detail: truncate(detail),
        }
    }

    /// `ERROR_CODE_CONTRACT_VIOLATION`: the sender broke the contract.
    #[must_use]
    pub fn violation(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::ContractViolation, detail)
    }

    /// `ERROR_CODE_VERSION_MISMATCH`: the handshakes differ or share no API version.
    #[must_use]
    pub fn version_mismatch(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::VersionMismatch, detail)
    }

    /// The code; `ERROR_CODE_UNSPECIFIED` for an unknown code from a peer (see
    /// [`Self::is_ignore`]).
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// The code as on the wire.
    #[must_use]
    pub fn raw_code(&self) -> i32 {
        self.raw
    }

    /// A peer's error with an unknown non-zero code: IGNORE it (drop, never treat the call as
    /// successful, never REJECT).
    #[must_use]
    pub fn is_ignore(&self) -> bool {
        self.code == ErrorCode::Unspecified
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The `common.v1.Error` form.
    #[must_use]
    pub fn to_wire(&self) -> WireError {
        WireError {
            code: self.raw,
            detail: self.detail.clone(),
        }
    }

    /// The status that fails a call or stream with this error.
    #[must_use]
    pub fn to_status(&self) -> Status {
        to_status(&self.to_wire())
    }

    /// The error a peer failed a call or stream with (see [`error_from_status`]).
    #[must_use]
    pub fn from_status(status: &Status) -> Self {
        error_from_status(status).into()
    }
}

impl From<ContractError> for WireError {
    fn from(e: ContractError) -> Self {
        WireError {
            code: e.raw,
            detail: e.detail,
        }
    }
}

/// A received `common.v1.Error`. The zero code is a contract violation (a sender must never put
/// `ERROR_CODE_UNSPECIFIED` on the wire); an unknown non-zero code is kept and IGNOREd.
impl From<WireError> for ContractError {
    fn from(e: WireError) -> Self {
        match ErrorCode::try_from(e.code) {
            Ok(ErrorCode::Unspecified) => {
                Self::violation(format!("error code 0 from peer: {}", e.detail))
            }
            Ok(code) => Self::new(code, e.detail),
            Err(_) => Self::unknown(e.code, e.detail),
        }
    }
}

fn truncate(mut detail: String) -> String {
    if detail.len() > MAX_DETAIL_BYTES {
        let mut cut = MAX_DETAIL_BYTES;
        while !detail.is_char_boundary(cut) {
            cut -= 1;
        }
        detail.truncate(cut);
    }
    detail
}

/// Builds a wire error, truncating `detail` to [`MAX_DETAIL_BYTES`] on a char boundary.
#[must_use]
pub fn wire_error(code: ErrorCode, detail: impl Into<String>) -> WireError {
    ContractError::new(code, detail).into()
}

/// The gRPC code a failed call or stream carries for `code`.
#[must_use]
pub fn grpc_code(code: ErrorCode) -> Code {
    match code {
        ErrorCode::ContractViolation | ErrorCode::ForkDigestMismatch | ErrorCode::SszDecode => {
            Code::InvalidArgument
        }
        ErrorCode::VersionMismatch => Code::FailedPrecondition,
        ErrorCode::DeadlineExceeded => Code::DeadlineExceeded,
        ErrorCode::Overloaded => Code::ResourceExhausted,
        _ => Code::Unavailable,
    }
}

/// Status that fails a call or stream. The `common.v1.Error` travels prost-encoded in the
/// status details.
#[must_use]
pub fn to_status(err: &WireError) -> Status {
    Status::with_details(
        grpc_code(err.code()),
        err.detail.clone(),
        err.encode_to_vec().into(),
    )
}

/// The `common.v1.Error` a call or stream failed with. A status without (valid) details, such
/// as one raised by the transport itself, is mapped from its gRPC code.
#[must_use]
pub fn error_from_status(status: &Status) -> WireError {
    if let Ok(err) = WireError::decode(status.details()) {
        if err.code != ErrorCode::Unspecified as i32 {
            return err;
        }
    }
    let code = match status.code() {
        Code::DeadlineExceeded | Code::Cancelled => ErrorCode::DeadlineExceeded,
        Code::ResourceExhausted => ErrorCode::Overloaded,
        Code::InvalidArgument | Code::OutOfRange | Code::PermissionDenied => {
            ErrorCode::ContractViolation
        }
        Code::FailedPrecondition => ErrorCode::VersionMismatch,
        _ => ErrorCode::ResourceUnavailable,
    };
    wire_error(code, status.message())
}

/// tonic's message for a received frame that prost could not decode (`Code::Internal`).
const DECODE_FAILURE: &str = "failed to decode Protobuf message";

/// Maps an error tonic raised while receiving a frame. tonic reports a message over the
/// decoding limit as `OutOfRange` from the frame header, before decoding it: a cap breach. A
/// frame that does not decode as protobuf is malformed input, also a contract violation.
/// Anything else is a transport failure.
#[must_use]
pub fn inbound_error(status: &Status) -> WireError {
    match status.code() {
        Code::OutOfRange => wire_error(
            ErrorCode::ContractViolation,
            format!("request over the message cap: {}", status.message()),
        ),
        Code::Internal if status.message().starts_with(DECODE_FAILURE) => wire_error(
            ErrorCode::ContractViolation,
            format!("malformed request frame: {}", status.message()),
        ),
        _ => wire_error(
            ErrorCode::ResourceUnavailable,
            format!("receive failed: {}", status.message()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_is_truncated_on_a_char_boundary() {
        let err = wire_error(ErrorCode::Invalid, "é".repeat(600));
        assert_eq!(err.detail.len(), MAX_DETAIL_BYTES);
        assert_eq!(wire_error(ErrorCode::Invalid, "x").detail, "x");
        let long = ContractError::violation("a".repeat(2000));
        assert_eq!(long.detail().len(), MAX_DETAIL_BYTES);
    }

    #[test]
    fn status_round_trips_the_wire_error() {
        for code in [
            ErrorCode::ContractViolation,
            ErrorCode::VersionMismatch,
            ErrorCode::ForkDigestMismatch,
            ErrorCode::SszDecode,
            ErrorCode::DeadlineExceeded,
            ErrorCode::Overloaded,
            ErrorCode::ResourceUnavailable,
            ErrorCode::NotFound,
        ] {
            let err = ContractError::new(code, "why");
            assert_eq!(ContractError::from_status(&err.to_status()), err);
            assert_eq!(err.to_status().code(), grpc_code(code));
        }
    }

    #[test]
    fn status_without_details_maps_from_the_grpc_code() {
        let cases = [
            (Code::DeadlineExceeded, ErrorCode::DeadlineExceeded),
            (Code::Cancelled, ErrorCode::DeadlineExceeded),
            (Code::ResourceExhausted, ErrorCode::Overloaded),
            (Code::OutOfRange, ErrorCode::ContractViolation),
            (Code::InvalidArgument, ErrorCode::ContractViolation),
            (Code::PermissionDenied, ErrorCode::ContractViolation),
            (Code::FailedPrecondition, ErrorCode::VersionMismatch),
            (Code::Unimplemented, ErrorCode::ResourceUnavailable),
            (Code::Internal, ErrorCode::ResourceUnavailable),
            (Code::Unknown, ErrorCode::ResourceUnavailable),
        ];
        for (grpc, want) in cases {
            assert_eq!(error_from_status(&Status::new(grpc, "m")).code(), want);
        }
    }

    #[test]
    fn unspecified_details_fall_back_to_the_grpc_code() {
        let zero = WireError {
            code: 0,
            detail: "zero".into(),
        };
        let status =
            Status::with_details(Code::FailedPrecondition, "m", zero.encode_to_vec().into());
        assert_eq!(
            error_from_status(&status).code(),
            ErrorCode::VersionMismatch
        );
    }

    #[test]
    fn a_zero_code_from_a_peer_is_a_contract_violation() {
        let got = ContractError::from(WireError {
            code: 0,
            detail: "d".into(),
        });
        assert_eq!(got.code(), ErrorCode::ContractViolation);
        assert!(!got.is_ignore());
        let known = ContractError::from(wire_error(ErrorCode::NotSynced, "d"));
        assert_eq!(known.code(), ErrorCode::NotSynced);
        assert_eq!(known.raw_code(), ErrorCode::NotSynced as i32);
        assert_eq!(known.detail(), "d");
        assert!(!known.is_ignore());
    }

    #[test]
    fn an_unknown_non_zero_code_from_a_peer_is_ignored_and_kept() {
        let got = ContractError::from(WireError {
            code: 999,
            detail: "from a newer build".into(),
        });
        assert!(got.is_ignore());
        assert_ne!(got.code(), ErrorCode::ContractViolation);
        assert_eq!(got.raw_code(), 999);
        // Passed on unchanged, as cl-verify did before.
        assert_eq!(got.to_wire().code, 999);
        assert_eq!(ContractError::from_status(&got.to_status()), got);
        assert!(got.to_string().contains("999"));
    }

    #[test]
    fn inbound_size_limit_is_a_contract_violation() {
        let over = Status::new(Code::OutOfRange, "decoded message length too large");
        assert_eq!(inbound_error(&over).code(), ErrorCode::ContractViolation);
        let other = Status::new(Code::Unknown, "h2 reset");
        assert_eq!(inbound_error(&other).code(), ErrorCode::ResourceUnavailable);
    }

    #[test]
    fn undecodable_frame_is_a_contract_violation() {
        let bad = Status::new(
            Code::Internal,
            "failed to decode Protobuf message: invalid wire type",
        );
        let err = inbound_error(&bad);
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        assert!(err.detail.starts_with("malformed request frame"));
        let internal = Status::new(Code::Internal, "h2 protocol error");
        assert_eq!(
            inbound_error(&internal).code(),
            ErrorCode::ResourceUnavailable
        );
    }

    #[test]
    fn display_names_the_code() {
        let e = ContractError::version_mismatch("floor 2");
        assert_eq!(e.to_string(), "ERROR_CODE_VERSION_MISMATCH: floor 2");
    }
}
