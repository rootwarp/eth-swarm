//! `compute_fork_digest` with the Fulu blob-parameter (BPO) rule, and the wall-clock epoch.
//!
//! Spec text this follows (consensus-specs v1.7.0-beta.4; transcribed from memory of the
//! release, no copy of the spec is vendored here, so each rule is restated):
//!
//! - `phase0/beacon-chain.md` `compute_fork_data_root(current_version, genesis_validators_root)`
//!   is `hash_tree_root(ForkData(current_version, genesis_validators_root))`. `ForkData` is two
//!   fields, `Version` (4 bytes, one chunk right-padded with zeros) and `Root` (one chunk), so
//!   its root is `sha256(version ++ 28 zero bytes ++ genesis_validators_root)`. The
//!   `ssz_static/ForkData` vector in the tests pins this.
//! - `fulu/beacon-chain.md` `compute_fork_digest(genesis_validators_root, epoch)`:
//!   `fork_version = compute_fork_version(epoch)`,
//!   `base_digest = compute_fork_data_root(fork_version, genesis_validators_root)`,
//!   `blob_parameters = get_blob_parameters(epoch)`, and the digest is the first 4 bytes of
//!   `xor(base_digest, hash(uint_to_bytes(uint64(blob_parameters.epoch)) +
//!   uint_to_bytes(uint64(blob_parameters.max_blobs_per_block))))`. `uint_to_bytes` of a
//!   `uint64` is its 8-byte little-endian SSZ encoding and `hash` is sha256.
//! - `compute_fork_version(epoch)` (`fulu/beacon-chain.md`, extended for Gloas in
//!   `gloas/beacon-chain.md`) is the version of the latest fork whose epoch is at or before
//!   `epoch`. Only Fulu and Gloas are in scope ([`ForkSchedule`]), so an epoch before
//!   `FULU_FORK_EPOCH` is refused instead of answered with an older version.
//! - `get_blob_parameters(epoch)` is [`ChainConfig::get_blob_parameters`].
//!
//! [`ForkSchedule`]: crate::ForkSchedule

use crate::chain_config::{BlobParameters, ChainConfig};
use crate::fork_schedule::{Epoch, ForkName, Version};
use sha2::{Digest, Sha256};

/// `ForkDigest`: 4 bytes.
pub type ForkDigest = [u8; 4];
/// `Root`: 32 bytes.
pub type Root = [u8; 32];

/// Why no digest or epoch could be computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    /// `epoch` is before `FULU_FORK_EPOCH` (or Fulu is not scheduled): out of scope.
    #[error("epoch {epoch} is before the Fulu fork, which this client does not cover")]
    BeforeFulu {
        /// The epoch asked for.
        epoch: Epoch,
    },
    /// The wall clock is before genesis.
    #[error("the clock ({now_ms} ms) is before genesis ({genesis_time} s)")]
    BeforeGenesis {
        /// Unix milliseconds of the clock.
        now_ms: u128,
        /// Unix seconds of genesis.
        genesis_time: u64,
    },
    /// A slot duration or epoch length of zero.
    #[error("slot duration and slots per epoch must be positive")]
    ZeroDuration,
}

/// Everything `compute_fork_digest` read for one epoch, and the digest it produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestInputs {
    /// The epoch.
    pub epoch: Epoch,
    /// The fork active at `epoch`.
    pub fork: ForkName,
    /// `compute_fork_version(epoch)`.
    pub fork_version: Version,
    /// `get_blob_parameters(epoch)`.
    pub blob_parameters: BlobParameters,
    /// The genesis validators root.
    pub genesis_validators_root: Root,
    /// `compute_fork_digest(genesis_validators_root, epoch)`.
    pub fork_digest: ForkDigest,
}

/// `compute_fork_data_root(current_version, genesis_validators_root)`.
pub fn compute_fork_data_root(current_version: Version, genesis_validators_root: &Root) -> Root {
    let mut chunk = [0u8; 32];
    chunk[..4].copy_from_slice(&current_version);
    let mut h = Sha256::new();
    h.update(chunk);
    h.update(genesis_validators_root);
    h.finalize().into()
}

/// `hash(uint_to_bytes(uint64(epoch)) + uint_to_bytes(uint64(max_blobs_per_block)))`.
fn blob_parameters_hash(params: &BlobParameters) -> Root {
    let mut h = Sha256::new();
    h.update(params.epoch.to_le_bytes());
    h.update(params.max_blobs_per_block.to_le_bytes());
    h.finalize().into()
}

/// `compute_fork_digest(genesis_validators_root, epoch)` under `config`, with its inputs.
pub fn fork_digest_inputs(
    config: &ChainConfig,
    genesis_validators_root: &Root,
    epoch: Epoch,
) -> Result<DigestInputs, DigestError> {
    let schedule = config.fork_schedule();
    let fork = schedule
        .fork_at(epoch)
        .ok_or(DigestError::BeforeFulu { epoch })?;
    let fork_version = schedule.fork_version(fork);
    let blob_parameters = config.get_blob_parameters(epoch);
    let base = compute_fork_data_root(fork_version, genesis_validators_root);
    let mask = blob_parameters_hash(&blob_parameters);
    let mut fork_digest = [0u8; 4];
    for (out, (b, m)) in fork_digest.iter_mut().zip(base.iter().zip(mask.iter())) {
        *out = b ^ m;
    }
    Ok(DigestInputs {
        epoch,
        fork,
        fork_version,
        blob_parameters,
        genesis_validators_root: *genesis_validators_root,
        fork_digest,
    })
}

/// `compute_fork_digest(genesis_validators_root, epoch)` under `config`.
pub fn compute_fork_digest(
    config: &ChainConfig,
    genesis_validators_root: &Root,
    epoch: Epoch,
) -> Result<ForkDigest, DigestError> {
    fork_digest_inputs(config, genesis_validators_root, epoch).map(|i| i.fork_digest)
}

/// The digest of every epoch at which it can change, ascending: `FULU_FORK_EPOCH`, every
/// `BLOB_SCHEDULE` entry and `GLOAS_FORK_EPOCH` when scheduled. Between two consecutive entries
/// the digest is constant, so this is every digest the network uses from Fulu on.
pub fn digest_schedule(config: &ChainConfig, genesis_validators_root: &Root) -> Vec<DigestInputs> {
    let schedule = config.fork_schedule();
    let Some(fulu) = schedule.fork_epoch(ForkName::Fulu) else {
        return Vec::new();
    };
    let mut epochs: Vec<Epoch> = std::iter::once(fulu)
        .chain(config.blob_schedule().iter().map(|b| b.epoch))
        .chain(schedule.fork_epoch(ForkName::Gloas))
        .collect();
    epochs.sort_unstable();
    epochs.dedup();
    epochs
        .into_iter()
        .filter_map(|epoch| fork_digest_inputs(config, genesis_validators_root, epoch).ok())
        .collect()
}

/// The epoch of the wall clock: `compute_epoch_at_slot` of the slot `now_ms` falls in, for a
/// chain that started at `genesis_time` (Unix seconds) with `slot_duration_ms` slots of
/// `slots_per_epoch` each.
pub fn current_epoch(
    genesis_time: u64,
    slot_duration_ms: u64,
    slots_per_epoch: u64,
    now_ms: u128,
) -> Result<Epoch, DigestError> {
    if slot_duration_ms == 0 || slots_per_epoch == 0 {
        return Err(DigestError::ZeroDuration);
    }
    let genesis_ms = u128::from(genesis_time) * 1000;
    let since = now_ms
        .checked_sub(genesis_ms)
        .ok_or(DigestError::BeforeGenesis {
            now_ms,
            genesis_time,
        })?;
    let slot = since / u128::from(slot_duration_ms);
    let epoch = slot / u128::from(slots_per_epoch);
    Ok(Epoch::try_from(epoch).unwrap_or(Epoch::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Network, FAR_FUTURE_EPOCH};

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let s = s.strip_prefix("0x").unwrap_or(s);
        assert_eq!(s.len(), 2 * N, "{s}");
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn sepolia() -> (ChainConfig, Root) {
        let config = ChainConfig::load(Network::Sepolia).unwrap();
        let gvr = Network::Sepolia.genesis().unwrap().genesis_validators_root;
        (config, gvr)
    }

    #[test]
    fn fork_data_root_matches_the_ssz_static_vector() {
        // consensus-spec-tests v1.7.0-beta.4 minimal/fulu/ssz_static/ForkData/ssz_random/case_0.
        let root = compute_fork_data_root(
            hex("0xaa72c8f4"),
            &hex("0x849b3fff314d633501cdbcb4682251b8fe7d27bbe2dcd2a85be5d58f9f5d69d6"),
        );
        assert_eq!(
            root,
            hex::<32>("0x108e884d4063c793c634d7e9f77fd3565597e4b1e71feaa214cad08ef2ec16ff")
        );
    }

    /// The pinned Sepolia digests. Computed independently of this crate (a Python 3 `hashlib`
    /// transcription of the spec functions above, over the pinned config and genesis root).
    const SEPOLIA_FULU: &str = "0x7e0d3447";
    const SEPOLIA_BPO1: &str = "0xfd32b622";
    const SEPOLIA_BPO2: &str = "0x74d01459";
    const SEPOLIA_GLOAS: &str = "0x669e6c11";

    #[test]
    fn bpo_boundaries() {
        let (config, gvr) = sepolia();
        let digest = |epoch| compute_fork_digest(&config, &gvr, epoch).unwrap();
        // Every BPO entry and GLOAS_FORK_EPOCH: the digest changes exactly at the boundary.
        let boundaries = [
            (274_176, SEPOLIA_FULU, SEPOLIA_BPO1),
            (275_712, SEPOLIA_BPO1, SEPOLIA_BPO2),
            (353_024, SEPOLIA_BPO2, SEPOLIA_GLOAS),
        ];
        for (epoch, before, after) in boundaries {
            assert_eq!(digest(epoch - 1), hex(before), "epoch {} - 1", epoch);
            assert_eq!(digest(epoch), hex(after), "epoch {epoch}");
            assert_eq!(digest(epoch + 1), hex(after), "epoch {epoch} + 1");
            assert_ne!(digest(epoch - 1), digest(epoch), "changes at {epoch}");
        }
        // Constant between boundaries.
        assert_eq!(digest(272_640), hex(SEPOLIA_FULU));
        assert_eq!(digest(272_641), hex(SEPOLIA_FULU));
        assert_eq!(digest(FAR_FUTURE_EPOCH), hex(SEPOLIA_GLOAS));
        // The Gloas boundary changes the version, not the blob parameters.
        let before = fork_digest_inputs(&config, &gvr, 353_023).unwrap();
        let at = fork_digest_inputs(&config, &gvr, 353_024).unwrap();
        assert_eq!(before.blob_parameters, at.blob_parameters);
        assert_eq!((before.fork, at.fork), (ForkName::Fulu, ForkName::Gloas));
        assert_eq!(at.fork_version, [0x90, 0, 0, 0x76]);
        // Fulu itself: no BPO entry yet, so the Electra blob parameters mask it.
        let fulu = fork_digest_inputs(&config, &gvr, 272_640).unwrap();
        assert_eq!(
            fulu.blob_parameters,
            BlobParameters {
                epoch: 222_464,
                max_blobs_per_block: 9
            }
        );
        assert_eq!(fulu.genesis_validators_root, gvr);
    }

    #[test]
    fn the_mask_is_the_hash_of_both_little_endian_uint64s() {
        let (config, gvr) = sepolia();
        let inputs = fork_digest_inputs(&config, &gvr, 275_712).unwrap();
        let base = compute_fork_data_root(inputs.fork_version, &gvr);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&275_712u64.to_le_bytes());
        preimage.extend_from_slice(&21u64.to_le_bytes());
        let mask: [u8; 32] = Sha256::digest(&preimage).into();
        let want: ForkDigest = std::array::from_fn(|i| base[i] ^ mask[i]);
        assert_eq!(inputs.fork_digest, want);
    }

    #[test]
    fn before_fulu_is_refused() {
        let (config, gvr) = sepolia();
        assert_eq!(
            compute_fork_digest(&config, &gvr, 272_639),
            Err(DigestError::BeforeFulu { epoch: 272_639 })
        );
        assert_eq!(
            compute_fork_digest(&config, &gvr, 0),
            Err(DigestError::BeforeFulu { epoch: 0 })
        );
    }

    #[test]
    fn another_genesis_root_gives_another_digest() {
        let (config, gvr) = sepolia();
        let mut other = gvr;
        other[31] ^= 1;
        assert_ne!(
            compute_fork_digest(&config, &gvr, 300_000),
            compute_fork_digest(&config, &other, 300_000)
        );
    }

    #[test]
    fn schedule_lists_every_fork_and_bpo_digest() {
        let (config, gvr) = sepolia();
        let got: Vec<(Epoch, ForkName, ForkDigest)> = digest_schedule(&config, &gvr)
            .into_iter()
            .map(|i| (i.epoch, i.fork, i.fork_digest))
            .collect();
        assert_eq!(
            got,
            vec![
                (272_640, ForkName::Fulu, hex(SEPOLIA_FULU)),
                (274_176, ForkName::Fulu, hex(SEPOLIA_BPO1)),
                (275_712, ForkName::Fulu, hex(SEPOLIA_BPO2)),
                (353_024, ForkName::Gloas, hex(SEPOLIA_GLOAS)),
            ]
        );
    }

    #[test]
    fn schedule_without_gloas_or_fulu() {
        let yaml = "\
PRESET_BASE: 'mainnet'
CONFIG_NAME: 'devnet'
GENESIS_FORK_VERSION: 0x00000001
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x06000001
FULU_FORK_EPOCH: 10
GLOAS_FORK_VERSION: 0x07000001
GLOAS_FORK_EPOCH: 18446744073709551615
SLOT_DURATION_MS: 12000
MAX_PAYLOAD_SIZE: 10485760
MAX_BLOBS_PER_BLOCK_ELECTRA: 9
BLOB_SCHEDULE:
  - EPOCH: 10
    MAX_BLOBS_PER_BLOCK: 12
";
        let sha: [u8; 32] = Sha256::digest(yaml.as_bytes()).into();
        let config = ChainConfig::from_yaml(yaml.as_bytes(), &sha).unwrap();
        let got = digest_schedule(&config, &[0; 32]);
        // The BPO entry at the Fulu epoch is one entry, and an unscheduled Gloas is none.
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].epoch, got[0].fork), (10, ForkName::Fulu));
        assert_eq!(got[0].blob_parameters.max_blobs_per_block, 12);

        let unscheduled = yaml
            .replace(
                "FULU_FORK_EPOCH: 10",
                "FULU_FORK_EPOCH: 18446744073709551615",
            )
            .replace("  - EPOCH: 10\n    MAX_BLOBS_PER_BLOCK: 12\n", "");
        let unscheduled = unscheduled.replace("BLOB_SCHEDULE:\n", "");
        let sha: [u8; 32] = Sha256::digest(unscheduled.as_bytes()).into();
        let config = ChainConfig::from_yaml(unscheduled.as_bytes(), &sha).unwrap();
        assert!(digest_schedule(&config, &[0; 32]).is_empty());
    }

    #[test]
    fn current_epoch_from_the_wall_clock() {
        let genesis = Network::Sepolia.genesis().unwrap().genesis_time;
        let at = |secs: u64| current_epoch(genesis, 12_000, 32, u128::from(secs) * 1000);
        assert_eq!(at(genesis), Ok(0));
        assert_eq!(at(genesis + 383), Ok(0));
        assert_eq!(at(genesis + 384), Ok(1));
        // The first Gloas epoch starts 353024 * 384 s after genesis.
        assert_eq!(at(genesis + 353_024 * 384 - 1), Ok(353_023));
        assert_eq!(at(genesis + 353_024 * 384), Ok(353_024));
        assert_eq!(
            current_epoch(genesis, 12_000, 32, u128::from(genesis) * 1000 - 1),
            Err(DigestError::BeforeGenesis {
                now_ms: u128::from(genesis) * 1000 - 1,
                genesis_time: genesis
            })
        );
        assert_eq!(current_epoch(0, 0, 32, 1), Err(DigestError::ZeroDuration));
        assert_eq!(
            current_epoch(0, 12_000, 0, 1),
            Err(DigestError::ZeroDuration)
        );
        assert_eq!(current_epoch(0, 1, 1, u128::MAX), Ok(Epoch::MAX));
    }
}
