//! Stream handshake: the peer's `common.v1.Hello` is compared with ours in full
//! ([`ipc::hello::negotiate`]).

use crate::proto::common::{Error, Hello};

/// Our side of the handshake plus the configured API-version floor.
#[derive(Clone, Debug)]
pub struct Handshake {
    ours: Hello,
    floor: u32,
}

impl Handshake {
    #[must_use]
    pub fn new(ours: Hello, floor: u32) -> Self {
        Self { ours, floor }
    }

    /// The hello this side sends first on every stream.
    #[must_use]
    pub fn ours(&self) -> &Hello {
        &self.ours
    }

    /// The configured API-version floor.
    #[must_use]
    pub fn floor(&self) -> u32 {
        self.floor
    }

    /// Checks the peer's hello and returns the negotiated API version.
    ///
    /// The whole handshake is compared (proto/README.md rule 8): `api_version`,
    /// `genesis_validators_root`, `current_fork_digest`, `spec_pin`, `fork_schedule` and
    /// `blob_schedule` must be equal, and the link uses `min(max_a, max_b)`, which must be at
    /// least `max(min_a, min_b)` and our floor. Only `build` is informational. A
    /// `FORK_NAME_UNSPECIFIED` entry is a contract violation.
    pub fn accept(&self, theirs: &Hello) -> Result<u32, Error> {
        ipc::hello::negotiate(&self.ours, theirs, self.floor).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::common::{
        BlobScheduleEntry, ErrorCode, ForkName, ForkScheduleEntry, SpecPin,
    };

    fn hello() -> Hello {
        Hello {
            api_version: 1,
            build: "cl-verify/test".into(),
            genesis_validators_root: vec![7; 32],
            current_fork_digest: vec![1, 2, 3, 4],
            spec_pin: Some(SpecPin {
                consensus_specs_tag: "v1.7.0-beta.4".into(),
                ssz_specs_tag: "v0.1.0".into(),
            }),
            fork_schedule: vec![ForkScheduleEntry {
                epoch: 0,
                fork_digest: vec![1, 2, 3, 4],
                fork: ForkName::Fulu as i32,
                fork_version: vec![0, 0, 0, 6],
                max_blobs_per_block: 9,
            }],
            blob_schedule: vec![BlobScheduleEntry {
                epoch: 10,
                max_blobs_per_block: 15,
            }],
            min_api_version: 1,
            max_api_version: 1,
            generation: 0,
        }
    }

    fn code(h: &Handshake, theirs: &Hello) -> ErrorCode {
        h.accept(theirs).unwrap_err().code()
    }

    #[test]
    fn identical_handshake_negotiates_the_highest_common_version() {
        let h = Handshake::new(hello(), 1);
        assert_eq!(h.accept(&hello()), Ok(1));
        let mut ours = hello();
        ours.max_api_version = 2;
        let mut theirs = hello();
        theirs.max_api_version = 3;
        assert_eq!(Handshake::new(ours, 1).accept(&theirs), Ok(2));
    }

    #[test]
    fn build_string_may_differ() {
        let h = Handshake::new(hello(), 1);
        let mut theirs = hello();
        theirs.build = "cl-chain/other".into();
        assert_eq!(h.accept(&theirs), Ok(1));
    }

    #[test]
    fn current_fork_digest_difference_is_a_version_mismatch() {
        let h = Handshake::new(hello(), 1);
        let mut theirs = hello();
        theirs.current_fork_digest = vec![9; 4];
        assert_eq!(code(&h, &theirs), ErrorCode::VersionMismatch);
    }

    #[test]
    fn any_schedule_or_pin_difference_is_a_version_mismatch() {
        let h = Handshake::new(hello(), 1);
        let edits: Vec<fn(&mut Hello)> = vec![
            |t| t.api_version = 2,
            |t| t.genesis_validators_root[0] ^= 1,
            |t| t.spec_pin.as_mut().unwrap().consensus_specs_tag = "v1.7.0-beta.3".into(),
            |t| t.spec_pin = None,
            |t| t.fork_schedule[0].epoch = 1,
            |t| t.fork_schedule[0].fork = ForkName::Gloas as i32,
            |t| t.fork_schedule[0].fork = 77,
            |t| t.blob_schedule[0].max_blobs_per_block = 21,
            |t| t.blob_schedule.clear(),
        ];
        for (i, edit) in edits.into_iter().enumerate() {
            let mut theirs = hello();
            edit(&mut theirs);
            assert_eq!(code(&h, &theirs), ErrorCode::VersionMismatch, "edit {i}");
        }
    }

    #[test]
    fn no_common_version_or_below_floor_is_a_version_mismatch() {
        let mut theirs = hello();
        theirs.min_api_version = 2;
        theirs.max_api_version = 2;
        assert_eq!(
            code(&Handshake::new(hello(), 1), &theirs),
            ErrorCode::VersionMismatch
        );
        let mut ours = hello();
        ours.min_api_version = 1;
        ours.max_api_version = 2;
        // Common version 1 exists but our floor is 2.
        assert_eq!(
            code(&Handshake::new(ours, 2), &hello()),
            ErrorCode::VersionMismatch
        );
        let mut inverted = hello();
        inverted.min_api_version = 2;
        inverted.max_api_version = 1;
        assert_eq!(
            code(&Handshake::new(hello(), 1), &inverted),
            ErrorCode::VersionMismatch
        );
    }

    #[test]
    fn unspecified_fork_name_is_a_contract_violation() {
        let mut theirs = hello();
        theirs.fork_schedule[0].fork = ForkName::Unspecified as i32;
        assert_eq!(
            code(&Handshake::new(hello(), 1), &theirs),
            ErrorCode::ContractViolation
        );
    }
}
