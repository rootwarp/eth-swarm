//! The capability gate (execution-apis `common.md`, capabilities).
//!
//! `engine_exchangeCapabilities` is optional in the spec. This crate calls it anyway, at start
//! and after every reconnect, and refuses to send engine calls until the EL lists
//! [`NEW_PAYLOAD_V5`] and [`FORKCHOICE_UPDATED_V4`]. An older method is not a substitute.

/// `engine_newPayloadV5` (Gloas / Amsterdam).
pub const NEW_PAYLOAD_V5: &str = "engine_newPayloadV5";
/// `engine_forkchoiceUpdatedV4` (Gloas / Amsterdam).
pub const FORKCHOICE_UPDATED_V4: &str = "engine_forkchoiceUpdatedV4";

/// The methods this client requires. Order is the order a refusal reports.
pub const REQUIRED: [&str; 2] = [NEW_PAYLOAD_V5, FORKCHOICE_UPDATED_V4];

/// What we tell the EL we can call when the caller does not supply a list.
pub const ADVERTISED: [&str; 2] = REQUIRED;

/// The EL's `engine_exchangeCapabilities` result omitted a required method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingCaps {
    missing: Vec<&'static str>,
}

impl MissingCaps {
    /// The required methods the EL did not list, in [`REQUIRED`] order.
    #[must_use]
    pub fn missing(&self) -> &[&'static str] {
        &self.missing
    }
}

impl std::fmt::Display for MissingCaps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "missing {}", self.missing.join(", "))
    }
}

impl std::error::Error for MissingCaps {}

/// Accepts `el_methods` only when both required methods are present.
///
/// Extra methods are ignored. An older `newPayload` or `forkchoiceUpdated` does not stand in
/// for the required version.
pub fn check<'a>(el_methods: impl IntoIterator<Item = &'a str>) -> Result<(), MissingCaps> {
    let mut present = [false; REQUIRED.len()];
    for method in el_methods {
        if let Some(slot) = REQUIRED.iter().position(|required| *required == method) {
            present[slot] = true;
        }
    }
    let missing: Vec<&'static str> = REQUIRED
        .into_iter()
        .zip(present)
        .filter_map(|(method, ok)| (!ok).then_some(method))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(MissingCaps { missing })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_required_pair() {
        assert!(check([NEW_PAYLOAD_V5, FORKCHOICE_UPDATED_V4]).is_ok());
    }

    #[test]
    fn extra_methods_are_ignored() {
        assert!(check([
            "engine_newPayloadV4",
            NEW_PAYLOAD_V5,
            "engine_forkchoiceUpdatedV3",
            FORKCHOICE_UPDATED_V4,
            "engine_getPayloadV6",
        ])
        .is_ok());
    }

    #[test]
    fn no_downgrade_when_either_required_method_is_absent() {
        let cases: &[(&[&str], &[&str])] = &[
            (
                &["engine_newPayloadV4", FORKCHOICE_UPDATED_V4],
                &[NEW_PAYLOAD_V5],
            ),
            (
                &[NEW_PAYLOAD_V5, "engine_forkchoiceUpdatedV3"],
                &[FORKCHOICE_UPDATED_V4],
            ),
            (&[][..], &[NEW_PAYLOAD_V5, FORKCHOICE_UPDATED_V4]),
            (
                &["engine_newPayloadV5 ", "engine_forkchoiceUpdatedV4"],
                &[NEW_PAYLOAD_V5],
            ),
        ];
        for (methods, want) in cases {
            let err = check(methods.iter().copied()).unwrap_err();
            assert_eq!(err.missing(), *want, "{methods:?}");
        }
    }
}
