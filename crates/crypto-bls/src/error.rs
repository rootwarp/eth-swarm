use blst::BLST_ERROR;

/// Why a BLS input was refused. Verification failures are not errors: they return `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Not a canonical compressed encoding (flags, length or field element out of range).
    #[error("bad point encoding")]
    BadEncoding,
    /// The x coordinate has no point on the curve.
    #[error("point is not on the curve")]
    PointNotOnCurve,
    /// On the curve but outside the prime-order subgroup.
    #[error("point is not in the prime-order subgroup")]
    PointNotInGroup,
    /// `KeyValidate` rejects the identity as a public key.
    #[error("public key is the point at infinity")]
    PublicKeyIsInfinity,
    /// The spec asserts a non-empty input.
    #[error("empty input")]
    EmptyInput,
    /// The OS random source failed, so a batch could not get secret randomizers.
    #[error("OS randomness unavailable")]
    RandomnessUnavailable,
    /// Any other blst status; not expected for validated inputs.
    #[error("blst returned status {0}")]
    Blst(u32),
}

impl From<BLST_ERROR> for Error {
    fn from(err: BLST_ERROR) -> Self {
        match err {
            BLST_ERROR::BLST_BAD_ENCODING => Self::BadEncoding,
            BLST_ERROR::BLST_POINT_NOT_ON_CURVE => Self::PointNotOnCurve,
            BLST_ERROR::BLST_POINT_NOT_IN_GROUP => Self::PointNotInGroup,
            BLST_ERROR::BLST_PK_IS_INFINITY => Self::PublicKeyIsInfinity,
            other => Self::Blst(other as u32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_blst_statuses() {
        assert_eq!(
            Error::from(BLST_ERROR::BLST_BAD_ENCODING),
            Error::BadEncoding
        );
        assert_eq!(
            Error::from(BLST_ERROR::BLST_POINT_NOT_ON_CURVE),
            Error::PointNotOnCurve
        );
        assert_eq!(
            Error::from(BLST_ERROR::BLST_POINT_NOT_IN_GROUP),
            Error::PointNotInGroup
        );
        assert_eq!(
            Error::from(BLST_ERROR::BLST_PK_IS_INFINITY),
            Error::PublicKeyIsInfinity
        );
        assert_eq!(Error::from(BLST_ERROR::BLST_BAD_SCALAR), Error::Blst(7));
        assert_eq!(Error::Blst(7).to_string(), "blst returned status 7");
    }
}
