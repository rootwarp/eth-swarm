//! The consensus fields of a node record (EIP-778) as bytes: `eth2`, `cgc` and `nfd`
//! (consensus-specs v1.7.0-beta.4, `phase0/p2p-interface.md` "ENR structure" and
//! `fulu/p2p-interface.md` "The discovery domain: discv5").
//!
//! This module has no `enr` or `discv5` dependency, because `m2a-session` links this crate and
//! must have no discovery (`scripts/check-m2a-deps.sh`). It holds the value encodings only; the
//! record itself (RLP, signature, key order) is `cl-discv5::enr`. Every decoder takes the
//! value's bytes after the record's RLP string header, from an untrusted peer, and checks the
//! exact length before anything else.
//!
//! - [`EnrForkId`]: the SSZ `ENRForkID` under `eth2`, 16 bytes.
//! - [`encode_cgc`] / [`decode_cgc`]: the custody group count under `cgc`, a big-endian
//!   `uint64` with no leading zero bytes, 0 as the empty string.
//! - [`decode_nfd`]: the next fork digest under `nfd`, a 4-byte `ForkDigest`, all zero
//!   ([`NO_NEXT_FORK_DIGEST`]) when no fork is scheduled.
//! - [`ForkFields::from_schedule`]: the local `eth2` and `nfd` values at a wall-clock epoch.

use crate::rpc::messages::ForkDigest;
use network_config::digest::{digest_schedule, DigestError, Root};
use network_config::{ChainConfig, Epoch, Version, FAR_FUTURE_EPOCH};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};

/// The record key of the `ENRForkID`.
pub const ETH2_KEY: &str = "eth2";
/// The record key of the custody group count.
pub const CGC_KEY: &str = "cgc";
/// The record key of the next fork digest.
pub const NFD_KEY: &str = "nfd";
/// The SSZ length of `ENRForkID`: `ForkDigest` (4), `Version` (4), `Epoch` (8).
pub const ENR_FORK_ID_LEN: usize = 16;
/// The longest `cgc` value: a `uint64`.
pub const MAX_CGC_LEN: usize = 8;
/// `nfd` when no next fork is scheduled: the SSZ default of `ForkDigest`.
pub const NO_NEXT_FORK_DIGEST: ForkDigest = [0; 4];

/// `ENRForkID`, the value under `eth2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct EnrForkId {
    /// `compute_fork_digest(genesis_validators_root, current_epoch)`.
    pub fork_digest: ForkDigest,
    /// The fork version in effect at `next_fork_epoch`, or the current one when no fork is
    /// scheduled.
    pub next_fork_version: Version,
    /// The epoch of the next regular or BPO fork, `FAR_FUTURE_EPOCH` when none is scheduled.
    pub next_fork_epoch: Epoch,
}

impl EnrForkId {
    /// The SSZ bytes.
    pub fn to_bytes(&self) -> [u8; ENR_FORK_ID_LEN] {
        let mut out = [0u8; ENR_FORK_ID_LEN];
        out.copy_from_slice(&self.as_ssz_bytes());
        out
    }
}

/// Why a record field was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnrFieldError {
    /// The `eth2` value is not 16 bytes.
    #[error("eth2 value of {0} bytes, want {ENR_FORK_ID_LEN}")]
    Eth2Len(usize),
    /// The `cgc` value is longer than a `uint64`.
    #[error("cgc value of {0} bytes, want at most {MAX_CGC_LEN}")]
    CgcTooLong(usize),
    /// The `cgc` value starts with a zero byte (0 is the empty string).
    #[error("cgc value has a leading zero byte")]
    CgcLeadingZero,
    /// The `nfd` value is not 4 bytes.
    #[error("nfd value of {0} bytes, want 4")]
    NfdLen(usize),
}

/// Decodes an `eth2` value.
pub fn decode_eth2(bytes: &[u8]) -> Result<EnrForkId, EnrFieldError> {
    if bytes.len() != ENR_FORK_ID_LEN {
        return Err(EnrFieldError::Eth2Len(bytes.len()));
    }
    // A fixed-size container of exactly its length always decodes.
    EnrForkId::from_ssz_bytes(bytes).map_err(|_| EnrFieldError::Eth2Len(bytes.len()))
}

/// `cgc`: the custody group count as a big-endian integer with no leading zero bytes; 0 is the
/// empty byte string (`fulu/p2p-interface.md` "Custody group count").
pub fn encode_cgc(custody_group_count: u64) -> Vec<u8> {
    let bytes = custody_group_count.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

/// Decodes a `cgc` value, refusing any form [`encode_cgc`] does not produce.
pub fn decode_cgc(bytes: &[u8]) -> Result<u64, EnrFieldError> {
    if bytes.len() > MAX_CGC_LEN {
        return Err(EnrFieldError::CgcTooLong(bytes.len()));
    }
    if bytes.first() == Some(&0) {
        return Err(EnrFieldError::CgcLeadingZero);
    }
    Ok(bytes.iter().fold(0u64, |n, &b| n << 8 | u64::from(b)))
}

/// Decodes an `nfd` value.
pub fn decode_nfd(bytes: &[u8]) -> Result<ForkDigest, EnrFieldError> {
    ForkDigest::try_from(bytes).map_err(|_| EnrFieldError::NfdLen(bytes.len()))
}

/// The local node's `eth2` and `nfd` values at one wall-clock epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkFields {
    /// The value under `eth2`.
    pub eth2: EnrForkId,
    /// The value under `nfd`: the digest at `eth2.next_fork_epoch`, or [`NO_NEXT_FORK_DIGEST`].
    pub nfd: ForkDigest,
}

impl ForkFields {
    /// `eth2` and `nfd` at `current_epoch` (`fulu/p2p-interface.md` "`eth2` field" and "Next
    /// fork digest"), over [`digest_schedule`]: every epoch at which the digest changes, a
    /// regular fork **or** a BPO fork.
    ///
    /// - `fork_digest` is the digest of the latest entry at or before `current_epoch`;
    /// - the next fork is the first entry after it: `next_fork_epoch` is its epoch,
    ///   `next_fork_version` the version in effect there (equal to the current one at a BPO
    ///   fork) and `nfd` its digest;
    /// - with no next fork, `next_fork_epoch` is `FAR_FUTURE_EPOCH`, `next_fork_version` the
    ///   current version and `nfd` all zero. An entry at `FAR_FUTURE_EPOCH` is not scheduled.
    ///
    /// Before `FULU_FORK_EPOCH` there is no digest in scope: [`DigestError::BeforeFulu`].
    pub fn from_schedule(
        config: &ChainConfig,
        genesis_validators_root: &Root,
        current_epoch: Epoch,
    ) -> Result<Self, DigestError> {
        let schedule = digest_schedule(config, genesis_validators_root);
        let current = schedule
            .iter()
            .rev()
            .find(|d| d.epoch <= current_epoch)
            .ok_or(DigestError::BeforeFulu {
                epoch: current_epoch,
            })?;
        let next = schedule
            .iter()
            .find(|d| d.epoch > current_epoch && d.epoch != FAR_FUTURE_EPOCH);
        let (next_fork_version, next_fork_epoch, nfd) = match next {
            Some(n) => (n.fork_version, n.epoch, n.fork_digest),
            None => (current.fork_version, FAR_FUTURE_EPOCH, NO_NEXT_FORK_DIGEST),
        };
        Ok(Self {
            eth2: EnrForkId {
                fork_digest: current.fork_digest,
                next_fork_version,
                next_fork_epoch,
            },
            nfd,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_config::digest::compute_fork_digest;
    use network_config::Network;
    use sha2::Digest;

    #[test]
    fn cgc_encoding() {
        assert_eq!(encode_cgc(0), Vec::<u8>::new());
        assert_eq!(encode_cgc(4), vec![0x04]);
        assert_eq!(encode_cgc(128), vec![0x80]);
        assert_eq!(encode_cgc(256), vec![0x01, 0x00]);
        assert_eq!(encode_cgc(u64::MAX), vec![0xff; 8]);
    }

    #[test]
    fn cgc_decoding_accepts_only_the_canonical_form() {
        for n in [0, 1, 4, 127, 128, 255, 256, 1 << 32, u64::MAX] {
            assert_eq!(decode_cgc(&encode_cgc(n)), Ok(n), "{n}");
        }
        assert_eq!(decode_cgc(&[0x00]), Err(EnrFieldError::CgcLeadingZero));
        assert_eq!(
            decode_cgc(&[0x00, 0x04]),
            Err(EnrFieldError::CgcLeadingZero)
        );
        assert_eq!(decode_cgc(&[0x01; 9]), Err(EnrFieldError::CgcTooLong(9)));
    }

    #[test]
    fn enr_fork_id_is_16_bytes_of_ssz() {
        let id = EnrForkId {
            fork_digest: [0xde, 0xad, 0xbe, 0xef],
            next_fork_version: [0x90, 0, 0, 0x76],
            next_fork_epoch: 353_024,
        };
        let bytes = id.to_bytes();
        assert_eq!(bytes.len(), ENR_FORK_ID_LEN);
        assert_eq!(&bytes[..4], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&bytes[4..8], &[0x90, 0, 0, 0x76]);
        assert_eq!(&bytes[8..], &353_024u64.to_le_bytes());
        assert_eq!(id.as_ssz_bytes(), bytes.to_vec());
        assert_eq!(decode_eth2(&bytes), Ok(id));
        assert_eq!(decode_eth2(&bytes[..15]), Err(EnrFieldError::Eth2Len(15)));
        assert_eq!(decode_eth2(&[0; 17]), Err(EnrFieldError::Eth2Len(17)));
    }

    #[test]
    fn nfd_is_exactly_four_bytes() {
        assert_eq!(decode_nfd(&[1, 2, 3, 4]), Ok([1, 2, 3, 4]));
        assert_eq!(decode_nfd(&[0; 4]), Ok(NO_NEXT_FORK_DIGEST));
        assert_eq!(decode_nfd(&[]), Err(EnrFieldError::NfdLen(0)));
        assert_eq!(decode_nfd(&[0; 5]), Err(EnrFieldError::NfdLen(5)));
    }

    fn hex4(s: &str) -> [u8; 4] {
        let s = s.strip_prefix("0x").unwrap_or(s);
        std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }

    /// The pinned Sepolia digests (`network_config::digest` pins the same values, computed
    /// independently of the Rust code).
    const FULU: &str = "0x7e0d3447";
    const BPO1: &str = "0xfd32b622";
    const BPO2: &str = "0x74d01459";
    const GLOAS: &str = "0x669e6c11";
    const FULU_VERSION: Version = [0x90, 0, 0, 0x75];
    const GLOAS_VERSION: Version = [0x90, 0, 0, 0x76];

    #[test]
    fn fork_id_schedule() {
        let config = ChainConfig::load(Network::Sepolia).unwrap();
        let gvr = Network::Sepolia.genesis().unwrap().genesis_validators_root;
        let at = |epoch| ForkFields::from_schedule(&config, &gvr, epoch).unwrap();
        let want = |digest: &str, version, next_epoch, nfd: ForkDigest| ForkFields {
            eth2: EnrForkId {
                fork_digest: hex4(digest),
                next_fork_version: version,
                next_fork_epoch: next_epoch,
            },
            nfd,
        };

        // BPO fork at 274176: the version stays Fulu, only the digest moves.
        assert_eq!(at(274_175), want(FULU, FULU_VERSION, 274_176, hex4(BPO1)));
        assert_eq!(at(274_176), want(BPO1, FULU_VERSION, 275_712, hex4(BPO2)));
        assert_eq!(at(274_177), want(BPO1, FULU_VERSION, 275_712, hex4(BPO2)));
        // The next BPO fork at 275712, then the regular Gloas fork at 353024.
        assert_eq!(at(275_711), want(BPO1, FULU_VERSION, 275_712, hex4(BPO2)));
        assert_eq!(at(275_712), want(BPO2, GLOAS_VERSION, 353_024, hex4(GLOAS)));
        assert_eq!(at(353_023), want(BPO2, GLOAS_VERSION, 353_024, hex4(GLOAS)));
        // Gloas is the last scheduled fork on Sepolia: from it on nothing is planned, so the
        // spec's no-next-fork values apply (current version, FAR_FUTURE_EPOCH, zero nfd).
        let none = want(GLOAS, GLOAS_VERSION, FAR_FUTURE_EPOCH, NO_NEXT_FORK_DIGEST);
        assert_eq!(at(353_024), none);
        assert_eq!(at(353_025), none);
        // The Fulu fork itself: its digest, the first BPO fork next.
        assert_eq!(at(272_640), want(FULU, FULU_VERSION, 274_176, hex4(BPO1)));
        // Every digest is the BPO-aware `compute_fork_digest` of the epoch.
        for epoch in [272_640, 274_175, 274_176, 275_712, 353_023, 353_024] {
            assert_eq!(
                at(epoch).eth2.fork_digest,
                compute_fork_digest(&config, &gvr, epoch).unwrap()
            );
        }
    }

    #[test]
    fn fork_id_before_fulu_is_refused() {
        let config = ChainConfig::load(Network::Sepolia).unwrap();
        let gvr = Network::Sepolia.genesis().unwrap().genesis_validators_root;
        assert_eq!(
            ForkFields::from_schedule(&config, &gvr, 272_639),
            Err(DigestError::BeforeFulu { epoch: 272_639 })
        );
    }

    #[test]
    fn a_far_future_entry_is_not_a_next_fork() {
        // A devnet with Gloas unscheduled and a BPO entry parked at FAR_FUTURE_EPOCH.
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
  - EPOCH: 20
    MAX_BLOBS_PER_BLOCK: 12
  - EPOCH: 18446744073709551615
    MAX_BLOBS_PER_BLOCK: 15
";
        let sha: [u8; 32] = sha2::Sha256::digest(yaml.as_bytes()).into();
        let config = ChainConfig::from_yaml(yaml.as_bytes(), &sha).unwrap();
        let gvr = [0; 32];
        let before = ForkFields::from_schedule(&config, &gvr, 19).unwrap();
        assert_eq!(before.eth2.next_fork_epoch, 20);
        assert_eq!(before.eth2.next_fork_version, [0x06, 0, 0, 0x01]);
        assert_eq!(before.nfd, compute_fork_digest(&config, &gvr, 20).unwrap());
        let after = ForkFields::from_schedule(&config, &gvr, 20).unwrap();
        assert_eq!(after.eth2.next_fork_epoch, FAR_FUTURE_EPOCH);
        assert_eq!(after.eth2.next_fork_version, [0x06, 0, 0, 0x01]);
        assert_eq!(after.nfd, NO_NEXT_FORK_DIGEST);
    }
}
