//! The stream handshake: each side's `common.v1.Hello` is compared with the other's in full.
//!
//! `proto/README.md` rule 8 and the `Hello` comments in `envelope.proto`: the receiver compares
//! the whole handshake (`api_version`, `genesis_validators_root`, `current_fork_digest`,
//! `spec_pin`, `fork_schedule`, `blob_schedule`), and any difference fails the stream with
//! `ERROR_CODE_VERSION_MISMATCH`. Only `build` is informational. The link uses the highest
//! common API version, `min(max_a, max_b)`, which must be at least `max(min_a, min_b)` and the
//! receiver's configured floor. There is no fallback to a lower version or an unversioned mode.
//!
//! `generation` is not compared either: it is the server generation of one stream
//! ([`Generation`]). The serving side draws a fresh one from the OS RNG for every stream it
//! answers ([`stream_hello`]), so it changes on every restart and every reconnect; the client
//! reads it from the server's hello ([`Generation::from_hello`], where 0 is a contract
//! violation) and fences every request and result of the stream with it ([`crate::fence`]).

use std::num::NonZeroU64;

use ethswarm_proto::common::{ErrorCode, ForkName, Hello, SpecPin};

use crate::error::ContractError;

/// The server generation of one stream (`Hello.generation`): random and never 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Generation(NonZeroU64);

impl Generation {
    /// `None` for 0, which is never a generation.
    #[must_use]
    pub fn new(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }

    #[must_use]
    pub fn get(self) -> u64 {
        self.0.get()
    }

    /// A fresh generation from the OS RNG; `ERROR_CODE_RESOURCE_UNAVAILABLE` if the RNG fails.
    pub fn random() -> Result<Self, ContractError> {
        Self::draw(getrandom::u64)
    }

    /// Draws until a non-zero value. A source that keeps returning 0 is broken, so it gives up
    /// after a few draws.
    pub(crate) fn draw<E>(mut draw: impl FnMut() -> Result<u64, E>) -> Result<Self, ContractError> {
        const MAX_DRAWS: usize = 8;
        let unavailable =
            || ContractError::new(ErrorCode::ResourceUnavailable, "OS RNG gives no generation");
        for _ in 0..MAX_DRAWS {
            if let Some(g) = Self::new(draw().map_err(|_| unavailable())?) {
                return Ok(g);
            }
        }
        Err(unavailable())
    }

    /// The server generation `hello` announces. 0 (also what an older peer that sets none sends)
    /// is `ERROR_CODE_CONTRACT_VIOLATION`: its results could not be fenced.
    pub fn from_hello(hello: &Hello) -> Result<Self, ContractError> {
        Self::new(hello.generation)
            .ok_or_else(|| ContractError::violation("server hello has generation 0"))
    }
}

/// The hello a server opens one stream with: `local` with a fresh [`Generation`].
pub fn stream_hello(local: &Hello) -> Result<(Generation, Hello), ContractError> {
    let generation = Generation::random()?;
    let hello = Hello {
        generation: generation.get(),
        ..local.clone()
    };
    Ok((generation, hello))
}

/// The proto API version of the `*.v1` packages.
pub const API_VERSION_V1: u32 = 1;

/// The spec pin this build was made against, as it goes into `Hello.spec_pin`.
#[must_use]
pub fn spec_pin() -> SpecPin {
    from_spec_pin(&network_config::SPEC_PIN)
}

/// `network_config::SpecPin` in its wire form.
#[must_use]
pub fn from_spec_pin(pin: &network_config::SpecPin) -> SpecPin {
    SpecPin {
        consensus_specs_tag: pin.consensus_specs.to_owned(),
        ssz_specs_tag: pin.ssz_specs.to_owned(),
    }
}

/// Checks the peer's hello against ours and returns the negotiated API version.
///
/// A `FORK_NAME_UNSPECIFIED` schedule entry is `ERROR_CODE_CONTRACT_VIOLATION` (the zero rule
/// holds for every enum); every other difference is `ERROR_CODE_VERSION_MISMATCH`. `build` and
/// `generation` are not compared.
pub fn negotiate(local: &Hello, remote: &Hello, floor: u32) -> Result<u32, ContractError> {
    if remote
        .fork_schedule
        .iter()
        .any(|e| e.fork == ForkName::Unspecified as i32)
    {
        return Err(ContractError::violation(
            "hello fork_schedule entry has FORK_NAME_UNSPECIFIED",
        ));
    }
    let mismatch = |what: &str| ContractError::version_mismatch(format!("hello {what} differs"));
    if remote.api_version != local.api_version {
        return Err(mismatch("api_version"));
    }
    if remote.genesis_validators_root != local.genesis_validators_root {
        return Err(mismatch("genesis_validators_root"));
    }
    if remote.current_fork_digest != local.current_fork_digest {
        return Err(mismatch("current_fork_digest"));
    }
    if remote.spec_pin != local.spec_pin {
        return Err(mismatch("spec_pin"));
    }
    if remote.fork_schedule != local.fork_schedule {
        return Err(mismatch("fork_schedule"));
    }
    if remote.blob_schedule != local.blob_schedule {
        return Err(mismatch("blob_schedule"));
    }
    let version = local.max_api_version.min(remote.max_api_version);
    let lowest = local.min_api_version.max(remote.min_api_version).max(floor);
    if version < lowest {
        return Err(ContractError::version_mismatch(format!(
            "no common API version: ours {}..={}, theirs {}..={}, floor {floor}",
            local.min_api_version,
            local.max_api_version,
            remote.min_api_version,
            remote.max_api_version,
        )));
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethswarm_proto::common::{BlobScheduleEntry, ErrorCode, ForkScheduleEntry};

    fn hello(min: u32, max: u32) -> Hello {
        Hello {
            api_version: 1,
            build: "ipc/test".into(),
            genesis_validators_root: vec![7; 32],
            current_fork_digest: vec![1, 2, 3, 4],
            spec_pin: Some(spec_pin()),
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
            min_api_version: min,
            max_api_version: max,
            generation: 0,
        }
    }

    fn code(local: &Hello, remote: &Hello, floor: u32) -> ErrorCode {
        negotiate(local, remote, floor).unwrap_err().code()
    }

    #[test]
    fn spec_pin_is_the_workspace_pin() {
        let pin = spec_pin();
        assert_eq!(pin.consensus_specs_tag, "v1.7.0-beta.4");
        assert_eq!(pin.ssz_specs_tag, "v0.1.0");
    }

    #[test]
    fn link_uses_the_highest_common_version() {
        assert_eq!(negotiate(&hello(1, 1), &hello(1, 1), 1), Ok(1));
        // N talks to N-1 at N-1, from either side.
        assert_eq!(negotiate(&hello(1, 2), &hello(1, 1), 1), Ok(1));
        assert_eq!(negotiate(&hello(1, 1), &hello(1, 2), 1), Ok(1));
        // Two N builds use N.
        assert_eq!(negotiate(&hello(1, 2), &hello(1, 2), 1), Ok(2));
        assert_eq!(negotiate(&hello(2, 3), &hello(1, 2), 1), Ok(2));
    }

    #[test]
    fn no_common_version_is_a_version_mismatch() {
        assert_eq!(
            code(&hello(1, 1), &hello(2, 2), 1),
            ErrorCode::VersionMismatch
        );
        assert_eq!(
            code(&hello(2, 2), &hello(1, 1), 1),
            ErrorCode::VersionMismatch
        );
        // An inverted range has no version in it.
        assert_eq!(
            code(&hello(1, 1), &hello(2, 1), 1),
            ErrorCode::VersionMismatch
        );
    }

    #[test]
    fn link_below_the_floor_is_a_version_mismatch() {
        // A common version 1 exists, but the floor has risen to 2: no downgrade.
        assert_eq!(
            code(&hello(1, 2), &hello(1, 1), 2),
            ErrorCode::VersionMismatch
        );
        assert_eq!(negotiate(&hello(1, 2), &hello(1, 2), 2), Ok(2));
        // An unset range (0..=0) is below every floor.
        assert_eq!(
            code(&hello(1, 1), &hello(0, 0), 1),
            ErrorCode::VersionMismatch
        );
    }

    #[test]
    fn build_string_may_differ() {
        let mut theirs = hello(1, 1);
        theirs.build = "cl-chain/other".into();
        assert_eq!(negotiate(&hello(1, 1), &theirs, 1), Ok(1));
    }

    #[test]
    fn any_pin_or_schedule_difference_is_a_version_mismatch() {
        let edits: Vec<fn(&mut Hello)> = vec![
            |t| t.api_version = 2,
            |t| t.genesis_validators_root[0] ^= 1,
            |t| t.current_fork_digest = vec![9; 4],
            |t| t.spec_pin.as_mut().unwrap().consensus_specs_tag = "v1.7.0-beta.3".into(),
            |t| t.spec_pin.as_mut().unwrap().ssz_specs_tag = "v0.2.0".into(),
            |t| t.spec_pin = None,
            |t| t.fork_schedule[0].epoch = 1,
            |t| t.fork_schedule[0].fork_digest = vec![9; 4],
            |t| t.fork_schedule[0].fork = ForkName::Gloas as i32,
            |t| t.fork_schedule[0].fork = 77,
            |t| t.fork_schedule.clear(),
            |t| t.blob_schedule[0].max_blobs_per_block = 21,
            |t| t.blob_schedule[0].epoch = 11,
            |t| t.blob_schedule.clear(),
        ];
        for (i, edit) in edits.into_iter().enumerate() {
            let mut theirs = hello(1, 1);
            edit(&mut theirs);
            assert_eq!(
                code(&hello(1, 1), &theirs, 1),
                ErrorCode::VersionMismatch,
                "edit {i}"
            );
        }
    }

    #[test]
    fn generation_is_not_compared() {
        let mut theirs = hello(1, 1);
        theirs.generation = 0x5eed;
        assert_eq!(negotiate(&hello(1, 1), &theirs, 1), Ok(1));
    }

    #[test]
    fn random_generations_are_non_zero_and_differ() {
        let a = Generation::random().unwrap();
        let b = Generation::random().unwrap();
        assert_ne!(a.get(), 0);
        assert_ne!(a, b, "two 64-bit draws collided");
    }

    #[test]
    fn a_zero_draw_is_redrawn_and_a_broken_source_is_unavailable() {
        let mut draws = [0u64, 0, 7].into_iter();
        let g = Generation::draw(|| Ok::<_, ()>(draws.next().unwrap())).unwrap();
        assert_eq!(g.get(), 7);
        let zeros = Generation::draw(|| Ok::<_, ()>(0)).unwrap_err();
        assert_eq!(zeros.code(), ErrorCode::ResourceUnavailable);
        let failing = Generation::draw(|| Err::<u64, _>("no entropy")).unwrap_err();
        assert_eq!(failing.code(), ErrorCode::ResourceUnavailable);
    }

    #[test]
    fn peer_generation_zero_is_a_contract_violation() {
        assert_eq!(
            Generation::from_hello(&hello(1, 1)).unwrap_err().code(),
            ErrorCode::ContractViolation
        );
        let mut server = hello(1, 1);
        server.generation = 42;
        assert_eq!(Generation::from_hello(&server).unwrap().get(), 42);
        assert_eq!(Generation::new(0), None);
        assert_eq!(Generation::new(42).map(Generation::get), Some(42));
    }

    #[test]
    fn stream_hello_draws_a_fresh_generation_per_stream() {
        let local = hello(1, 1);
        let (g1, h1) = stream_hello(&local).unwrap();
        let (g2, h2) = stream_hello(&local).unwrap();
        assert_eq!(h1.generation, g1.get());
        assert_eq!(h2.generation, g2.get());
        assert_ne!(g1, g2);
        // Everything else is the local hello, so negotiation is unaffected.
        assert_eq!(negotiate(&local, &h1, 1), Ok(1));
        assert_eq!(
            Hello {
                generation: 0,
                ..h1
            },
            local
        );
    }

    #[test]
    fn unspecified_fork_name_is_a_contract_violation() {
        let mut theirs = hello(1, 1);
        theirs.fork_schedule[0].fork = ForkName::Unspecified as i32;
        assert_eq!(code(&hello(1, 1), &theirs, 1), ErrorCode::ContractViolation);
    }
}
