//! Stream handshake: the peer's `common.v1.Hello` is compared with ours in full
//! ([`ipc::hello::negotiate`]).
//!
//! Our hello is either fixed ([`Handshake::new`]) or the hello of a network
//! ([`Handshake::network`]). A network hello carries the fork digest of the wall-clock epoch at
//! the time the stream opens, so it follows every fork and BPO digest change of a long run.

use std::sync::Arc;

use ipc::hello::NetworkHello;

use crate::proto::common::{Error, ErrorCode, Hello};
use crate::wire::{wire_error, WallClock};

/// Our hello: fixed, or a network's with the digest of the clock.
#[derive(Clone, Debug)]
enum Ours {
    Fixed(Hello),
    Network(Arc<NetworkHello>),
}

/// Our side of the handshake plus the configured API-version floor.
#[derive(Clone, Debug)]
pub struct Handshake {
    ours: Ours,
    floor: u32,
}

impl Handshake {
    /// A handshake that sends `ours` on every stream.
    #[must_use]
    pub fn new(ours: Hello, floor: u32) -> Self {
        Self {
            ours: Ours::Fixed(ours),
            floor,
        }
    }

    /// A handshake that sends `network`'s hello at the time each stream opens
    /// ([`NetworkHello::at`]).
    #[must_use]
    pub fn network(network: NetworkHello, floor: u32) -> Self {
        Self {
            ours: Ours::Network(Arc::new(network)),
            floor,
        }
    }

    /// Our hello without the clock: the fixed hello, or the network's with an empty
    /// `current_fork_digest` ([`NetworkHello::schedule`]). Its schedules give the caps.
    #[must_use]
    pub fn ours(&self) -> &Hello {
        match &self.ours {
            Ours::Fixed(hello) => hello,
            Ours::Network(network) => network.schedule(),
        }
    }

    /// The configured API-version floor.
    #[must_use]
    pub fn floor(&self) -> u32 {
        self.floor
    }

    /// The hello we send on a stream opened now by `clock`. Only a network hello reads the
    /// clock.
    ///
    /// # Errors
    ///
    /// For a network hello, the clock is before genesis or before Fulu, so there is no fork
    /// digest yet: `ERROR_CODE_RESOURCE_UNAVAILABLE`.
    pub fn ours_at(&self, clock: &dyn WallClock) -> Result<Hello, Error> {
        match &self.ours {
            Ours::Fixed(hello) => Ok(hello.clone()),
            Ours::Network(network) => network.at(u128::from(clock.now_unix_ms())).map_err(|e| {
                wire_error(
                    ErrorCode::ResourceUnavailable,
                    format!("no fork digest yet: {e}"),
                )
            }),
        }
    }

    /// Checks the peer's hello against ours now by `clock` ([`Self::ours_at`]) and returns the
    /// negotiated API version and our hello, which the stream then sends.
    ///
    /// The whole handshake is compared (proto/README.md rule 8): `api_version`,
    /// `genesis_validators_root`, `current_fork_digest`, `spec_pin`, `fork_schedule` and
    /// `blob_schedule` must be equal, and the link uses `min(max_a, max_b)`, which must be at
    /// least `max(min_a, min_b)` and our floor. Only `build` is informational. A
    /// `FORK_NAME_UNSPECIFIED` entry is a contract violation.
    pub fn accept(&self, theirs: &Hello, clock: &dyn WallClock) -> Result<(u32, Hello), Error> {
        let ours = self.ours_at(clock)?;
        let version = ipc::hello::negotiate(&ours, theirs, self.floor).map_err(Error::from)?;
        Ok((version, ours))
    }
}

#[cfg(test)]
pub(crate) mod tests {
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

    /// A clock that always reads one time.
    pub(crate) struct At(pub(crate) u64);

    impl WallClock for At {
        fn now_unix_ms(&self) -> u64 {
            self.0
        }
    }

    fn code(h: &Handshake, theirs: &Hello) -> ErrorCode {
        h.accept(theirs, &At(0)).unwrap_err().code()
    }

    /// The negotiated version only.
    fn version(h: &Handshake, theirs: &Hello) -> Result<u32, Error> {
        h.accept(theirs, &At(0)).map(|(version, _)| version)
    }

    /// A devnet config: Fulu from genesis, a blob change at epoch 1, Gloas at epoch 2; minimal
    /// preset (8-slot epochs) with 6 s slots.
    pub(crate) const DEVNET_CONFIG: &str = "\
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

    /// The devnet's genesis.
    pub(crate) const DEVNET_GENESIS: network_config::Genesis = network_config::Genesis {
        genesis_time: 1_760_800_000,
        genesis_validators_root: [0x42; 32],
    };

    /// The devnet's hello, sent with `build`.
    pub(crate) fn devnet(build: &str) -> NetworkHello {
        let config =
            network_config::ChainConfig::from_devnet_yaml(DEVNET_CONFIG.as_bytes()).unwrap();
        NetworkHello::new(build, &config, DEVNET_GENESIS).unwrap()
    }

    /// Unix milliseconds at `slot` of the devnet.
    pub(crate) fn devnet_ms(slot: u64) -> u64 {
        DEVNET_GENESIS.genesis_time * 1000 + slot * 6_000
    }

    #[test]
    fn a_network_handshake_sends_the_digest_of_the_stream_open_time() {
        let h = Handshake::network(devnet("cl-verify/test"), 1);
        assert_eq!(h.ours(), devnet("cl-verify/test").schedule());
        assert!(h.ours().current_fork_digest.is_empty());
        let chain = devnet("cl-chain/test");
        for slot in [0, 8, 16, 100] {
            let now = devnet_ms(slot);
            let theirs = chain.at(u128::from(now)).unwrap();
            let (version, ours) = h.accept(&theirs, &At(now)).unwrap();
            assert_eq!(version, 1);
            assert_eq!(ours, devnet("cl-verify/test").at(u128::from(now)).unwrap());
            assert_eq!(ours.current_fork_digest, theirs.current_fork_digest);
        }
    }

    #[test]
    fn a_network_handshake_refuses_the_digest_of_another_epoch() {
        let h = Handshake::network(devnet("cl-verify/test"), 1);
        let theirs = devnet("cl-chain/test")
            .at(u128::from(devnet_ms(0)))
            .unwrap();
        // Slot 8 is epoch 1, after the blob change: another digest.
        let err = h.accept(&theirs, &At(devnet_ms(8))).unwrap_err();
        assert_eq!(err.code(), ErrorCode::VersionMismatch);
    }

    #[test]
    fn a_network_handshake_before_genesis_is_unavailable() {
        let h = Handshake::network(devnet("cl-verify/test"), 1);
        let theirs = devnet("cl-chain/test")
            .at(u128::from(devnet_ms(0)))
            .unwrap();
        let err = h.accept(&theirs, &At(devnet_ms(0) - 1)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceUnavailable);
        assert!(err.detail.contains("before genesis"), "{}", err.detail);
    }

    #[test]
    fn a_fixed_handshake_sends_its_hello_at_any_time() {
        let h = Handshake::new(hello(), 1);
        for now in [0, devnet_ms(16)] {
            assert_eq!(h.accept(&hello(), &At(now)), Ok((1, hello())));
        }
    }

    #[test]
    fn identical_handshake_negotiates_the_highest_common_version() {
        let h = Handshake::new(hello(), 1);
        assert_eq!(version(&h, &hello()), Ok(1));
        let mut ours = hello();
        ours.max_api_version = 2;
        let mut theirs = hello();
        theirs.max_api_version = 3;
        assert_eq!(version(&Handshake::new(ours, 1), &theirs), Ok(2));
    }

    #[test]
    fn build_string_may_differ() {
        let h = Handshake::new(hello(), 1);
        let mut theirs = hello();
        theirs.build = "cl-chain/other".into();
        assert_eq!(version(&h, &theirs), Ok(1));
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
