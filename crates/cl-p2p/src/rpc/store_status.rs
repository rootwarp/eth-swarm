//! The result code of a req/resp answer that a failed cl-store call (`ethswarm.store.v1`) ends.
//!
//! No req/resp path reads cl-store yet: the finalized block ranges and the parent walk of
//! `BeaconBlocksByHead` will ([6.17a], [6.42]). This is the boundary they map a failed store
//! call through. cl-store fails a read `UNAVAILABLE`, with `ERROR_CODE_RESOURCE_UNAVAILABLE`
//! in the status details, when it has nothing stamped to serve from: the responder does not
//! have the data, `3: ResourceUnavailable`, never `2: ServerError`.

use p2p_wire::rpc::protocols::ResultCode;
use tonic::Status;

/// The result code for a store call that failed with `status`.
#[must_use]
pub fn store_result_code(status: &Status) -> ResultCode {
    let _ = status;
    ResultCode::ServerError
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethswarm_proto::common::ErrorCode;
    use ipc::error::{to_status, wire_error};
    use tonic::Code;

    /// A status as cl-store fails a call: `code`, with `error` in the details.
    fn store_status(code: Code, error: ErrorCode) -> Status {
        let details = to_status(&wire_error(error, "from cl-store"))
            .details()
            .to_vec();
        Status::with_details(code, "from cl-store", details.into())
    }

    /// cl-store's own `UNAVAILABLE` (no stamp, env not readable now) is
    /// `3: ResourceUnavailable`; its other failures, and a store call that failed without
    /// cl-store's answer (the transport's own `UNAVAILABLE` included), are `2: ServerError`.
    #[test]
    fn store_unavailable_is_resource_unavailable() {
        assert_eq!(
            store_result_code(&store_status(
                Code::Unavailable,
                ErrorCode::ResourceUnavailable
            )),
            ResultCode::ResourceUnavailable
        );
        for (code, error) in [
            (Code::NotFound, ErrorCode::NotFound),
            (Code::DeadlineExceeded, ErrorCode::DeadlineExceeded),
            (Code::InvalidArgument, ErrorCode::Invalid),
        ] {
            assert_eq!(
                store_result_code(&store_status(code, error)),
                ResultCode::ServerError,
                "{code:?}"
            );
        }
        for status in [
            Status::unavailable("connection refused"),
            Status::internal("store read failed"),
        ] {
            assert_eq!(
                store_result_code(&status),
                ResultCode::ServerError,
                "{status:?}"
            );
        }
    }
}
