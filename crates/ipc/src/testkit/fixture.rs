//! Fixture link configuration: the Sepolia fork schedule with fixture fork digests.
//!
//! The digests are made up (`compute_fork_digest` is not implemented yet); the epochs are
//! Sepolia's: Fulu at 272640, BPO epochs 274176 and 275712, Gloas at 353024
//! (eth-clients/sepolia `metadata/config.yaml`, embedded in `network-config`).

use consensus_types::Mainnet;
use ethswarm_proto::common::{
    BlobScheduleEntry, ForkName as WireForkName, ForkScheduleEntry, Hello,
};
use network_config::{ChainConfig, Epoch, ForkName, ForkSchedule, Network};

use crate::envelope::{DigestTable, ForkDigest};
use crate::hello::{spec_pin, API_VERSION_V1};
use crate::link::Link;

/// Sepolia `genesis_validators_root`.
pub const SEPOLIA_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61, 0x05, 0x2a,
    0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09, 0xed, 0x9b, 0x80, 0x78,
];

/// `SLOTS_PER_EPOCH` of the fixture (mainnet preset, as Sepolia uses).
pub const SLOTS_PER_EPOCH: u64 = 32;

fn sepolia() -> ChainConfig {
    ChainConfig::load(Network::Sepolia).expect("embedded Sepolia config loads")
}

/// The Sepolia Fulu/Gloas fork schedule.
#[must_use]
pub fn sepolia_schedule() -> ForkSchedule {
    *sepolia().fork_schedule()
}

/// One digest epoch of the fixture schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DigestEpoch {
    pub epoch: Epoch,
    pub fork: ForkName,
    pub digest: ForkDigest,
    pub max_blobs_per_block: u64,
}

/// Every digest epoch: each fork activation and each BPO epoch at or after Fulu, oldest first,
/// with fixture digests `[0xfd, 0x5e, fork, n]`.
#[must_use]
pub fn digest_epochs() -> Vec<DigestEpoch> {
    let config = sepolia();
    let schedule = *config.fork_schedule();
    let mut epochs: Vec<Epoch> = ForkName::ALL
        .into_iter()
        .filter_map(|f| schedule.fork_epoch(f))
        .chain(config.blob_schedule().iter().map(|b| b.epoch))
        .filter(|e| schedule.fork_at(*e).is_some())
        .collect();
    epochs.sort_unstable();
    epochs.dedup();
    epochs
        .into_iter()
        .enumerate()
        .map(|(n, epoch)| {
            let fork = schedule.fork_at(epoch).expect("filtered to Fulu and later");
            DigestEpoch {
                epoch,
                fork,
                digest: [0xfd, 0x5e, fork as u8, u8::try_from(n).expect("few epochs")],
                max_blobs_per_block: config.get_blob_parameters(epoch).max_blobs_per_block,
            }
        })
        .collect()
}

/// The fixture digest of `fork` at `epoch`; panics if there is none.
#[must_use]
pub fn digest_at(fork: ForkName, epoch: Epoch) -> ForkDigest {
    use crate::envelope::ForkDigests;
    fixture_digests()
        .fork_digest(fork, epoch)
        .unwrap_or_else(|| panic!("no fixture digest for {fork} at epoch {epoch}"))
}

/// The fixture digests as a lookup table.
#[must_use]
pub fn fixture_digests() -> DigestTable {
    DigestTable::new(
        digest_epochs()
            .into_iter()
            .map(|d| (d.epoch, d.fork, d.digest))
            .collect(),
    )
    .expect("fixture schedule is ordered")
}

/// A Sepolia hello advertising API versions `min..=max` (the current digest is Gloas's).
#[must_use]
pub fn hello(min_api_version: u32, max_api_version: u32) -> Hello {
    let config = sepolia();
    let schedule = *config.fork_schedule();
    let epochs = digest_epochs();
    let wire_fork = |f: ForkName| match f {
        ForkName::Fulu => WireForkName::Fulu,
        ForkName::Gloas => WireForkName::Gloas,
    };
    Hello {
        api_version: API_VERSION_V1,
        build: "ipc-testkit".into(),
        genesis_validators_root: SEPOLIA_GENESIS_VALIDATORS_ROOT.to_vec(),
        current_fork_digest: epochs.last().expect("non-empty").digest.to_vec(),
        spec_pin: Some(spec_pin()),
        fork_schedule: epochs
            .iter()
            .map(|d| ForkScheduleEntry {
                epoch: d.epoch,
                fork_digest: d.digest.to_vec(),
                fork: wire_fork(d.fork) as i32,
                fork_version: schedule.fork_version(d.fork).to_vec(),
                max_blobs_per_block: d.max_blobs_per_block,
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
        min_api_version,
        max_api_version,
    }
}

/// A Sepolia link with fixture digests, API versions `min..=max` and `floor`.
#[must_use]
pub fn link(min_api_version: u32, max_api_version: u32, floor: u32) -> Link {
    Link::new::<Mainnet>(
        hello(min_api_version, max_api_version),
        floor,
        sepolia_schedule(),
        fixture_digests(),
    )
}

/// The default fixture link: v1 only, floor 1.
#[must_use]
pub fn v1_link() -> Link {
    link(API_VERSION_V1, API_VERSION_V1, API_VERSION_V1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_epochs_cover_forks_and_bpo_epochs() {
        let e: Vec<(Epoch, ForkName, u64)> = digest_epochs()
            .iter()
            .map(|d| (d.epoch, d.fork, d.max_blobs_per_block))
            .collect();
        assert_eq!(
            e,
            [
                (272_640, ForkName::Fulu, 9),
                (274_176, ForkName::Fulu, 15),
                (275_712, ForkName::Fulu, 21),
                (353_024, ForkName::Gloas, 21),
            ]
        );
        assert_eq!(
            digest_at(ForkName::Fulu, 275_711),
            digest_epochs()[1].digest
        );
    }

    #[test]
    fn hello_publishes_the_schedule_the_link_checks_against() {
        let h = hello(1, 2);
        assert_eq!(h.fork_schedule.len(), 4);
        assert_eq!(
            DigestTable::from_schedule(&h.fork_schedule).unwrap(),
            fixture_digests()
        );
        assert_eq!(h.blob_schedule.len(), 2);
        let l = v1_link();
        assert_eq!(l.negotiate(&hello(1, 1)), Ok(1));
    }
}
