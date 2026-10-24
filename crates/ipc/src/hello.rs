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
//!
//! [`NetworkHello`] builds the network part of a hello from a network's config and genesis, so
//! every service of one node that reads the same network sends the same hello.

use std::num::NonZeroU64;

use consensus_types::{EthSpec, Mainnet, Minimal};
use ethswarm_proto::common::{
    BlobScheduleEntry, ErrorCode, ForkName, ForkScheduleEntry, Hello, SpecPin,
};
use network_config::digest::{compute_fork_digest, current_epoch, digest_schedule, DigestError};
use network_config::{ChainConfig, Genesis};

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

/// A network's `PRESET_BASE` that is neither `minimal` nor `mainnet`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("PRESET_BASE {0:?} is neither minimal nor mainnet")]
pub struct UnknownPreset(pub String);

/// The hello of one network: the genesis validators root, every fork-schedule entry with its
/// digest, fork version and blob limit (`network_config::digest::digest_schedule`, BPO epochs
/// included), the BPO blob schedule, the spec pin and API version [`API_VERSION_V1`]. Only
/// `current_fork_digest` depends on the clock ([`Self::at`]).
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkHello {
    schedule: Hello,
    config: ChainConfig,
    genesis: Genesis,
    slots_per_epoch: u64,
}

impl NetworkHello {
    /// The hello of the network of `config` and `genesis`, sent with `build`. The epoch length is
    /// the one of the preset that `PRESET_BASE` names.
    ///
    /// # Errors
    ///
    /// `PRESET_BASE` is neither `minimal` nor `mainnet`.
    pub fn new(build: &str, config: &ChainConfig, genesis: Genesis) -> Result<Self, UnknownPreset> {
        let slots_per_epoch = match config.preset_base() {
            p if p == Minimal::NAME => Minimal::slots_per_epoch(),
            p if p == Mainnet::NAME => Mainnet::slots_per_epoch(),
            other => return Err(UnknownPreset(other.to_owned())),
        };
        let gvr = genesis.genesis_validators_root;
        let wire = |fork: network_config::ForkName| match fork {
            network_config::ForkName::Fulu => ForkName::Fulu,
            network_config::ForkName::Gloas => ForkName::Gloas,
        };
        let schedule = Hello {
            api_version: API_VERSION_V1,
            build: build.to_owned(),
            genesis_validators_root: gvr.to_vec(),
            current_fork_digest: Vec::new(),
            spec_pin: Some(spec_pin()),
            fork_schedule: digest_schedule(config, &gvr)
                .iter()
                .map(|e| ForkScheduleEntry {
                    epoch: e.epoch,
                    fork_digest: e.fork_digest.to_vec(),
                    fork: wire(e.fork) as i32,
                    fork_version: e.fork_version.to_vec(),
                    max_blobs_per_block: e.blob_parameters.max_blobs_per_block,
                })
                .collect(),
            blob_schedule: config
                .blob_schedule()
                .iter()
                .map(|b| BlobScheduleEntry {
                    epoch: b.epoch,
                    max_blobs_per_block: b.max_blobs_per_block,
                })
                .collect(),
            min_api_version: API_VERSION_V1,
            max_api_version: API_VERSION_V1,
            generation: 0,
        };
        Ok(Self {
            schedule,
            config: config.clone(),
            genesis,
            slots_per_epoch,
        })
    }

    /// The hello without the clock: `current_fork_digest` is empty. The schedules in it give
    /// the network's limits (for example the largest blob count).
    #[must_use]
    pub fn schedule(&self) -> &Hello {
        &self.schedule
    }

    /// `SLOTS_PER_EPOCH` of the network's preset.
    #[must_use]
    pub fn slots_per_epoch(&self) -> u64 {
        self.slots_per_epoch
    }

    /// The hello at `now_ms` (Unix milliseconds): [`Self::schedule`] with the fork digest of the
    /// wall-clock epoch as `current_fork_digest`.
    ///
    /// # Errors
    ///
    /// The clock is before genesis, or the epoch is before Fulu.
    pub fn at(&self, now_ms: u128) -> Result<Hello, DigestError> {
        let epoch = current_epoch(
            self.genesis.genesis_time,
            self.config.slot_duration_ms(),
            self.slots_per_epoch,
            now_ms,
        )?;
        let digest =
            compute_fork_digest(&self.config, &self.genesis.genesis_validators_root, epoch)?;
        Ok(Hello {
            current_fork_digest: digest.to_vec(),
            ..self.schedule.clone()
        })
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

#[cfg(test)]
mod network_tests {
    use super::*;
    use ethswarm_proto::common::{BlobScheduleEntry, ForkScheduleEntry};
    use network_config::digest::{compute_fork_digest, digest_schedule};
    use network_config::{ChainConfig, Genesis};

    /// Fulu from genesis, a blob change at epoch 1, Gloas at epoch 2; 6 s slots.
    const CONFIG: &str = "\
PRESET_BASE: 'minimal'
CONFIG_NAME: 'fixture-devnet'
GENESIS_FORK_VERSION: 0x00000001
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x60000001
FULU_FORK_EPOCH: 0
GLOAS_FORK_VERSION: 0x70000001
GLOAS_FORK_EPOCH: 2
SLOT_DURATION_MS: 6000
MAX_PAYLOAD_SIZE: 10485760
MAX_BLOBS_PER_BLOCK_ELECTRA: 9
BLOB_SCHEDULE:
  - EPOCH: 1
    MAX_BLOBS_PER_BLOCK: 12
";

    const GENESIS: Genesis = Genesis {
        genesis_time: 1_760_800_000,
        genesis_validators_root: [0x42; 32],
    };

    fn config(yaml: &str) -> ChainConfig {
        ChainConfig::from_devnet_yaml(yaml.as_bytes()).unwrap()
    }

    /// Unix milliseconds at `slot` of the fixture (8-slot epochs of 6 s slots).
    fn at_slot(slot: u64) -> u128 {
        u128::from(GENESIS.genesis_time) * 1000 + u128::from(slot) * 6_000
    }

    #[test]
    fn the_network_hello_carries_the_genesis_root_and_every_schedule_entry() {
        let config = config(CONFIG);
        let net = NetworkHello::new("svc/1", &config, GENESIS).unwrap();
        let hello = net.schedule();
        assert_eq!(hello.api_version, API_VERSION_V1);
        assert_eq!(hello.min_api_version, API_VERSION_V1);
        assert_eq!(hello.max_api_version, API_VERSION_V1);
        assert_eq!(hello.build, "svc/1");
        assert_eq!(hello.spec_pin, Some(spec_pin()));
        assert_eq!(hello.genesis_validators_root, [0x42; 32]);
        assert!(hello.current_fork_digest.is_empty());
        assert_eq!(hello.generation, 0);
        let digests = digest_schedule(&config, &GENESIS.genesis_validators_root);
        let want: Vec<ForkScheduleEntry> = digests
            .iter()
            .map(|d| ForkScheduleEntry {
                epoch: d.epoch,
                fork_digest: d.fork_digest.to_vec(),
                fork: match d.fork {
                    network_config::ForkName::Fulu => ForkName::Fulu,
                    network_config::ForkName::Gloas => ForkName::Gloas,
                } as i32,
                fork_version: d.fork_version.to_vec(),
                max_blobs_per_block: d.blob_parameters.max_blobs_per_block,
            })
            .collect();
        assert_eq!(hello.fork_schedule, want);
        assert_eq!(
            hello
                .fork_schedule
                .iter()
                .map(|e| (e.epoch, e.max_blobs_per_block))
                .collect::<Vec<_>>(),
            [(0, 9), (1, 12), (2, 12)]
        );
        assert_eq!(
            hello.blob_schedule,
            [BlobScheduleEntry {
                epoch: 1,
                max_blobs_per_block: 12
            }]
        );
        assert_eq!(net.slots_per_epoch(), 8);
    }

    #[test]
    fn the_current_fork_digest_follows_the_clock() {
        let config = config(CONFIG);
        let net = NetworkHello::new("svc/1", &config, GENESIS).unwrap();
        let gvr = GENESIS.genesis_validators_root;
        for (slot, epoch) in [(0, 0), (7, 0), (8, 1), (16, 2), (400, 50)] {
            let hello = net.at(at_slot(slot)).unwrap();
            assert_eq!(
                hello.current_fork_digest,
                compute_fork_digest(&config, &gvr, epoch).unwrap(),
                "slot {slot}"
            );
            assert_eq!(
                Hello {
                    current_fork_digest: Vec::new(),
                    ..hello
                },
                *net.schedule()
            );
        }
        // The same inputs give the same hello, so two services of one node agree.
        let other = NetworkHello::new("svc/1", &config, GENESIS).unwrap();
        assert_eq!(other.at(at_slot(9)), net.at(at_slot(9)));
        let before = at_slot(0) - 1;
        assert!(matches!(
            net.at(before),
            Err(network_config::digest::DigestError::BeforeGenesis { .. })
        ));
    }

    #[test]
    fn the_preset_gives_the_epoch_length_and_an_unknown_one_is_refused() {
        let mainnet = config(&CONFIG.replace("'minimal'", "'mainnet'"));
        let net = NetworkHello::new("svc/1", &mainnet, GENESIS).unwrap();
        assert_eq!(net.slots_per_epoch(), 32);
        // Slot 8 is still epoch 0 on 32-slot epochs, so before the blob change.
        assert_eq!(
            net.at(at_slot(8)).unwrap().current_fork_digest,
            compute_fork_digest(&mainnet, &GENESIS.genesis_validators_root, 0).unwrap()
        );
        let gnosis = config(&CONFIG.replace("'minimal'", "'gnosis'"));
        let err = NetworkHello::new("svc/1", &gnosis, GENESIS).unwrap_err();
        assert!(err.to_string().contains("gnosis"), "{err}");
    }
}
