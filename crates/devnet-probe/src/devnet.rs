//! The devnet the probe runs on: its `config.yaml`, its genesis, the preset they name, and the
//! rule that the probe only ever talks to loopback and private addresses.
//!
//! The config goes through `network-config`'s strict reader ([`ChainConfig::from_devnet_yaml`],
//! over the bytes' own sha256: a devnet has no pinned digest). The genesis comes from the
//! genesis state ([`read_genesis`]: `genesis_time` and `genesis_validators_root` are its first
//! two fields, both fixed-size, so they are its first 40 bytes in every fork) or from a reference
//! CL's beacon API (`/eth/v1/beacon/genesis`), and every fork digest from the two. The readers
//! are `network_config::network_dir`'s, which cl-verify's `--network-dir` reads with too.

use cl_chain::probe::ProbeChain;
use cl_p2p::m2a_session::PinnedPeer;
use consensus_types::{EthSpec, Mainnet, Minimal};
use libp2p::multiaddr::Protocol;
use network_config::digest::{compute_fork_digest, current_epoch, DigestError};
use network_config::network_dir;
use network_config::{ChainConfig, Epoch, Genesis};
use p2p_wire::enr::ForkFields;
use p2p_wire::gossip::TopicCaps;
use p2p_wire::rpc::codec::ContextTable;
use p2p_wire::rpc::messages::ForkDigest;
use std::net::IpAddr;
use std::path::Path;

pub use network_config::network_dir::{GENESIS_PREFIX_BYTES, MAX_CONFIG_BYTES};

/// The preset a devnet's `PRESET_BASE` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// `minimal`: 8-slot epochs, what the Kurtosis devnet runs.
    Minimal,
    /// `mainnet`: 32-slot epochs.
    Mainnet,
}

/// A devnet: its config, its genesis and its preset.
#[derive(Debug, Clone)]
pub struct Devnet {
    config: ChainConfig,
    genesis: Genesis,
    preset: Preset,
}

impl Devnet {
    /// The devnet of `config_yaml` (a `config.yaml`) with `genesis`.
    ///
    /// # Errors
    ///
    /// The config does not parse, or its `PRESET_BASE` is neither `minimal` nor `mainnet`.
    pub fn new(config_yaml: &[u8], genesis: Genesis) -> Result<Self, String> {
        let config = ChainConfig::from_devnet_yaml(config_yaml).map_err(|e| e.to_string())?;
        let preset = match config.preset_base() {
            p if p == Minimal::NAME => Preset::Minimal,
            p if p == Mainnet::NAME => Preset::Mainnet,
            other => {
                return Err(format!(
                    "PRESET_BASE {other:?} is neither minimal nor mainnet"
                ))
            }
        };
        Ok(Self {
            config,
            genesis,
            preset,
        })
    }

    /// The config.
    #[must_use]
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// The genesis time and validators root.
    #[must_use]
    pub fn genesis(&self) -> Genesis {
        self.genesis
    }

    /// The preset `PRESET_BASE` names.
    #[must_use]
    pub fn preset(&self) -> Preset {
        self.preset
    }

    /// `SLOTS_PER_EPOCH` of the preset.
    #[must_use]
    pub fn slots_per_epoch(&self) -> u64 {
        match self.preset {
            Preset::Minimal => Minimal::slots_per_epoch(),
            Preset::Mainnet => Mainnet::slots_per_epoch(),
        }
    }

    /// The wall-clock epoch at `now_ms` (Unix milliseconds).
    ///
    /// # Errors
    ///
    /// The clock is before genesis.
    pub fn epoch_at(&self, now_ms: u128) -> Result<Epoch, DigestError> {
        current_epoch(
            self.genesis.genesis_time,
            self.config.slot_duration_ms(),
            self.slots_per_epoch(),
            now_ms,
        )
    }

    /// `compute_fork_digest` of the wall-clock epoch at `now_ms`.
    ///
    /// # Errors
    ///
    /// The clock is before genesis, or the epoch before Fulu.
    pub fn fork_digest(&self, now_ms: u128) -> Result<ForkDigest, DigestError> {
        let epoch = self.epoch_at(now_ms)?;
        compute_fork_digest(&self.config, &self.genesis.genesis_validators_root, epoch)
    }

    /// The ENR fork fields (`eth2`, `nfd`) of the wall-clock epoch at `now_ms`.
    ///
    /// # Errors
    ///
    /// As [`Self::fork_digest`].
    pub fn fork_fields(&self, now_ms: u128) -> Result<ForkFields, DigestError> {
        let epoch = self.epoch_at(now_ms)?;
        ForkFields::from_schedule(&self.config, &self.genesis.genesis_validators_root, epoch)
    }

    /// `compute_fork_digest(epoch)` on the BPO-aware schedule; `None` before Fulu.
    #[must_use]
    pub fn digest_at(&self, epoch: Epoch) -> Option<ForkDigest> {
        compute_fork_digest(&self.config, &self.genesis.genesis_validators_root, epoch).ok()
    }

    /// Fork digest to fork, for every digest of the schedule (the context bytes the codec
    /// decodes responses by), and the devnet's caps, which every column sidecar is read and
    /// served under ([`cl_p2p::rpc::network_context_table`]).
    #[must_use]
    pub fn context_table(&self) -> ContextTable {
        cl_p2p::rpc::network_context_table(&self.config, &self.genesis.genesis_validators_root)
    }

    /// The gossip caps of preset `E` under each fork digest of the schedule, BPO digests
    /// included (`p2p_wire::gossip::TopicCaps::from_config`): every digest is held to its own
    /// fork and blob limit, and a digest off the schedule to none.
    #[must_use]
    pub fn topic_caps<E: EthSpec>(&self) -> TopicCaps {
        TopicCaps::from_config::<E>(&self.config, &self.genesis.genesis_validators_root)
    }

    /// The chain probe mode's Status provider builds our Status for.
    #[must_use]
    pub fn probe_chain(&self) -> ProbeChain {
        ProbeChain {
            config: self.config.clone(),
            genesis: self.genesis,
            slots_per_epoch: self.slots_per_epoch(),
        }
    }
}

/// The genesis of a genesis state's SSZ: its first two fields
/// ([`network_config::network_dir::genesis_from_state`]).
///
/// # Errors
///
/// Fewer than [`GENESIS_PREFIX_BYTES`] bytes.
pub fn genesis_from_state(ssz: &[u8]) -> Result<Genesis, String> {
    network_dir::genesis_from_state(ssz).map_err(|e| e.to_string())
}

/// The genesis of the genesis state at `path` (the generator's `genesis.ssz`), from its first
/// [`GENESIS_PREFIX_BYTES`] bytes ([`network_config::network_dir::read_genesis`]).
///
/// # Errors
///
/// The file cannot be read or is too short.
pub fn read_genesis(path: &Path) -> Result<Genesis, String> {
    network_dir::read_genesis(path).map_err(|e| e.to_string())
}

/// The bytes of the `config.yaml` at `path`, reading at most one byte past
/// [`MAX_CONFIG_BYTES`] ([`network_config::network_dir::read_config`]).
///
/// # Errors
///
/// The file cannot be read or is too large.
pub fn read_config(path: &Path) -> Result<Vec<u8>, String> {
    network_dir::read_config(path).map_err(|e| e.to_string())
}

/// Whether `ip` is a devnet address: a local one, by the rule our discv5 runs in local mode
/// ([`cl_discv5::service::is_local_ip`]: loopback, private, link-local, CGNAT, IPv6
/// unique-local). The probe contacts nothing else: it is for a local devnet, never a public
/// peer.
#[must_use]
pub fn is_devnet_ip(ip: IpAddr) -> bool {
    cl_discv5::service::is_local_ip(ip)
}

/// A reference CL's libp2p address, `/ip4|ip6/<addr>/tcp/<port>/p2p/<peer id>`, at a devnet
/// address ([`is_devnet_ip`]).
///
/// # Errors
///
/// Not such an address.
pub fn parse_peer(text: &str) -> Result<PinnedPeer, String> {
    let peer: PinnedPeer = text.parse().map_err(|e| format!("{e}"))?;
    let ip = peer.addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    });
    match ip {
        Some(ip) if is_devnet_ip(ip) => Ok(peer),
        _ => Err(format!(
            "{} is not a local address (loopback, private, link-local, CGNAT, IPv6 \
             unique-local): the probe talks to a local devnet only",
            peer.addr
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_config::digest::digest_schedule;
    use testkit::export_blocks::fixtures::{CONFIG, GENESIS_TIME};

    const GVR: [u8; 32] = [0x42; 32];

    fn genesis() -> Genesis {
        Genesis {
            genesis_time: GENESIS_TIME,
            genesis_validators_root: GVR,
        }
    }

    /// The first 40 bytes of a genesis state with `time` and `root`, then filler.
    fn state_prefix(time: u64, root: [u8; 32], extra: usize) -> Vec<u8> {
        let mut ssz = time.to_le_bytes().to_vec();
        ssz.extend_from_slice(&root);
        ssz.extend(std::iter::repeat_n(0xee, extra));
        ssz
    }

    #[test]
    fn the_genesis_is_the_states_first_two_fields() {
        let got = genesis_from_state(&state_prefix(GENESIS_TIME, GVR, 100)).unwrap();
        assert_eq!(got, genesis());
        assert_eq!(
            genesis_from_state(&state_prefix(GENESIS_TIME, GVR, 0)).unwrap(),
            genesis()
        );
        let short = &state_prefix(GENESIS_TIME, GVR, 0)[..39];
        assert!(genesis_from_state(short).unwrap_err().contains("39 bytes"));
    }

    #[test]
    fn the_genesis_file_is_read_by_its_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("genesis.ssz");
        std::fs::write(&path, state_prefix(GENESIS_TIME, GVR, 4096)).unwrap();
        assert_eq!(read_genesis(&path).unwrap(), genesis());
        let missing = dir.path().join("missing.ssz");
        assert!(read_genesis(&missing).unwrap_err().contains("missing.ssz"));
        std::fs::write(&path, [1, 2, 3]).unwrap();
        assert!(read_genesis(&path).unwrap_err().contains("3 bytes"));
    }

    #[test]
    fn the_config_names_the_preset() {
        let devnet = Devnet::new(CONFIG.as_bytes(), genesis()).unwrap();
        assert_eq!(devnet.preset(), Preset::Minimal);
        assert_eq!(devnet.slots_per_epoch(), 8);
        assert_eq!(devnet.genesis(), genesis());
        assert_eq!(devnet.config().config_name(), "fixture-devnet");
        let mainnet = CONFIG.replace("'minimal'", "'mainnet'");
        let devnet = Devnet::new(mainnet.as_bytes(), genesis()).unwrap();
        assert_eq!(devnet.preset(), Preset::Mainnet);
        assert_eq!(devnet.slots_per_epoch(), 32);
        let other = CONFIG.replace("'minimal'", "'gnosis'");
        let err = Devnet::new(other.as_bytes(), genesis()).unwrap_err();
        assert!(err.contains("gnosis"), "{err}");
        let broken = CONFIG.replace("FULU_FORK_EPOCH: 0", "FULU_FORK_EPOCH: x");
        assert!(Devnet::new(broken.as_bytes(), genesis()).is_err());
    }

    #[test]
    fn the_config_file_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, CONFIG).unwrap();
        assert_eq!(read_config(&path).unwrap(), CONFIG.as_bytes());
        std::fs::write(&path, vec![b'#'; MAX_CONFIG_BYTES as usize + 1]).unwrap();
        assert!(read_config(&path).unwrap_err().contains("over"));
        assert!(read_config(&dir.path().join("none.yaml")).is_err());
    }

    #[test]
    fn digests_follow_the_schedule_and_the_clock() {
        let devnet = Devnet::new(CONFIG.as_bytes(), genesis()).unwrap();
        let schedule = digest_schedule(devnet.config(), &GVR);
        let ms_at = |epoch: u64| u128::from(GENESIS_TIME + epoch * 48) * 1000 + 1;
        // Fulu at 0, the blob change at 1, Gloas at 2: three digests.
        assert_eq!(schedule.len(), 3);
        for (epoch, entry) in [(0, &schedule[0]), (1, &schedule[1]), (5, &schedule[2])] {
            assert_eq!(devnet.digest_at(epoch), Some(entry.fork_digest));
            let fields = devnet.fork_fields(ms_at(epoch)).unwrap();
            assert_eq!(fields.eth2.fork_digest, entry.fork_digest, "epoch {epoch}");
            assert_eq!(devnet.fork_digest(ms_at(epoch)).unwrap(), entry.fork_digest);
        }
        assert!(devnet
            .fork_fields(u128::from(GENESIS_TIME) * 1000 - 1)
            .is_err());
        let table = devnet.context_table();
        for entry in &schedule {
            assert_eq!(table.fork(&entry.fork_digest), Some(entry.fork));
        }
        // The devnet's caps: without them every column answer is `2: ServerError`.
        assert_eq!(
            table.network_caps(),
            Some(&consensus_types::caps::NetworkCaps::from_config(
                devnet.config()
            ))
        );
        let chain = devnet.probe_chain();
        assert_eq!(chain.slots_per_epoch, 8);
        assert_eq!(chain.genesis, genesis());
    }

    /// The gossip caps follow each digest of the schedule: a Fulu digest caps a column sidecar
    /// at the Fulu sidecar of the largest Fulu blob limit at or before it, the Gloas digest at
    /// `compute_max_data_column_sidecar_size()`, and a digest off the schedule has no cap.
    #[test]
    fn gossip_caps_follow_each_digest_of_the_schedule() {
        use consensus_types::caps::{
            compute_max_data_column_sidecar_size, fulu_data_column_sidecar_size, NetworkCaps,
        };
        use consensus_types::ForkName;
        use p2p_wire::gossip::GossipKind;
        let devnet = Devnet::new(CONFIG.as_bytes(), genesis()).unwrap();
        let caps = devnet.topic_caps::<Minimal>();
        let column = GossipKind::DataColumnSidecar { subnet_id: 0 };
        let schedule = digest_schedule(devnet.config(), &GVR);
        assert_eq!(schedule.len(), 3);
        for entry in &schedule {
            let want = match entry.fork {
                ForkName::Fulu => fulu_data_column_sidecar_size::<Minimal>(
                    entry.blob_parameters.max_blobs_per_block,
                ),
                ForkName::Gloas => compute_max_data_column_sidecar_size::<Minimal>(
                    &NetworkCaps::from_config(devnet.config()),
                ),
            };
            assert_eq!(
                caps.cap_at(entry.fork_digest, column),
                Some(want as usize),
                "{:?}",
                entry.fork
            );
        }
        // The blob change inside Fulu changes the column cap.
        assert_ne!(
            caps.cap_at(schedule[0].fork_digest, column),
            caps.cap_at(schedule[1].fork_digest, column)
        );
        assert_eq!(caps.cap_at([0xee; 4], GossipKind::BeaconBlock), None);
    }

    /// A devnet whose BPO entry lowers the blob limit (9, then 6): the lowered digest keeps the
    /// cap of 9 blobs, because a late sidecar of epoch 0 can arrive under it.
    #[test]
    fn a_lowered_blob_limit_keeps_the_earlier_column_cap() {
        use consensus_types::caps::fulu_data_column_sidecar_size;
        use p2p_wire::gossip::GossipKind;
        let lowered = CONFIG.replace("    MAX_BLOBS_PER_BLOCK: 12", "    MAX_BLOBS_PER_BLOCK: 6");
        assert_ne!(lowered, CONFIG, "the fixture's BPO entry");
        let devnet = Devnet::new(lowered.as_bytes(), genesis()).unwrap();
        let schedule = digest_schedule(devnet.config(), &GVR);
        assert_eq!(schedule[1].blob_parameters.max_blobs_per_block, 6);
        let caps = devnet.topic_caps::<Minimal>();
        let column = GossipKind::DataColumnSidecar { subnet_id: 0 };
        let nine = Some(fulu_data_column_sidecar_size::<Minimal>(9) as usize);
        assert_eq!(caps.cap_at(schedule[0].fork_digest, column), nine);
        assert_eq!(caps.cap_at(schedule[1].fork_digest, column), nine);
    }

    #[test]
    fn only_loopback_and_private_addresses_are_devnet_addresses() {
        for ok in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.10",
            "192.168.1.1",
            "169.254.0.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            let ip: IpAddr = ok.parse().unwrap();
            assert!(is_devnet_ip(ip), "{ok}");
        }
        for bad in [
            "8.8.8.8",
            "192.0.2.1",
            "2001:4860::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert!(!is_devnet_ip(ip), "{bad}");
        }
    }

    #[test]
    fn a_peer_is_a_devnet_tcp_address_with_its_peer_id() {
        let id = libp2p::PeerId::random();
        let peer = parse_peer(&format!("/ip4/127.0.0.1/tcp/4000/p2p/{id}")).unwrap();
        assert_eq!(peer.peer_id, id);
        assert_eq!(peer.addr.to_string(), "/ip4/127.0.0.1/tcp/4000");
        let private = parse_peer(&format!("/ip4/172.16.0.10/tcp/9000/p2p/{id}"));
        assert!(private.is_ok());
        let public = parse_peer(&format!("/ip4/8.8.8.8/tcp/9000/p2p/{id}")).unwrap_err();
        assert!(public.contains("not a local address"), "{public}");
        assert!(parse_peer("/ip4/127.0.0.1/tcp/9000").is_err());
        assert!(parse_peer("nonsense").is_err());
    }
}
