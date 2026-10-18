//! The local node record (EIP-778) and the consensus fields of a remote one.
//!
//! Spec: consensus-specs v1.7.0-beta.4, `phase0/p2p-interface.md` "ENR structure" and
//! `fulu/p2p-interface.md` "The discovery domain: discv5". The record carries `eth2` (the SSZ
//! `ENRForkID`), `cgc` (the custody group count) and `nfd` (the next fork digest); their byte
//! encodings live in [`p2p_wire::enr`], which has no `enr` dependency, so this module only
//! moves them in and out of the record's RLP string values.
//!
//! - [`signing_key`]: the node key from `node-key` (the systemd credential) as the record's key.
//! - [`build_local_enr`]: the signed local record, from the BPO-aware [`ForkFields`].
//! - [`EnrFields::read`]: the fields of a decoded record. [`parse_enr_fields`] is the same from
//!   untrusted RLP bytes (signature checked by `enr`, at most 300 bytes, no trailing bytes), the
//!   entry point of the ENR fuzz target.

use alloy_rlp::{Bytes, Decodable};
use p2p_wire::enr::{
    decode_cgc, decode_eth2, decode_nfd, encode_cgc, EnrFieldError, EnrForkId, ForkFields, CGC_KEY,
    ETH2_KEY, NFD_KEY,
};
use p2p_wire::rpc::messages::ForkDigest;
use std::net::Ipv4Addr;

pub use discv5::Enr;
pub use enr::{CombinedKey, CombinedPublicKey, NodeId};

/// The default TCP and UDP port (`phase0/p2p-interface.md` uses 9000 in its examples, and every
/// client defaults to it).
pub const DEFAULT_PORT: u16 = 9000;

/// The addresses the local record advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalAddr {
    /// The IPv4 address peers reach this node at. `0.0.0.0` leaves `ip` out, so discv5 fills
    /// it in from the addresses peers observe.
    pub ip: Ipv4Addr,
    /// The libp2p TCP port (`tcp`).
    pub tcp_port: u16,
    /// The discv5 UDP port (`udp`).
    pub udp_port: u16,
}

impl LocalAddr {
    /// `ip` on [`DEFAULT_PORT`] for both TCP and UDP.
    pub const fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            tcp_port: DEFAULT_PORT,
            udp_port: DEFAULT_PORT,
        }
    }
}

/// Why the local record could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// `enr` refused the record (over 300 bytes, or signing failed).
    #[error("cannot build the local ENR: {0}")]
    Enr(String),
    /// The key is not the one the record is signed with: re-signing would make it another
    /// node's record.
    #[error("the key did not sign this record")]
    WrongKey,
}

/// Why the node key cannot sign the local record. It carries no key bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// `enr` refused the secret as a secp256k1 key.
    #[error("the node key is not a secp256k1 secret key")]
    NotSecp256k1,
}

/// The node key, loaded by `node-key` from the systemd credential `nodekey`, as the key the
/// local record is signed with and `Discv5::new` takes. The secret is consumed: its buffer is
/// wiped on drop, and `CombinedKey` has no `Debug`, so the key cannot be printed.
pub fn signing_key(mut secret: node_key::NodeKeySecret) -> Result<CombinedKey, KeyError> {
    CombinedKey::secp256k1_from_bytes(secret.expose_secret_mut())
        .map_err(|_| KeyError::NotSecp256k1)
}

/// The signed local record: `ip` (unless unspecified), `tcp`, `udp`, `eth2`, `cgc` and `nfd`.
pub fn build_local_enr(
    key: &CombinedKey,
    fork: &ForkFields,
    custody_group_count: u64,
    addr: &LocalAddr,
) -> Result<Enr, BuildError> {
    let mut builder = Enr::builder();
    if !addr.ip.is_unspecified() {
        builder.ip4(addr.ip);
    }
    builder
        .tcp4(addr.tcp_port)
        .udp4(addr.udp_port)
        .add_value(ETH2_KEY, &Bytes::from(fork.eth2.to_bytes().to_vec()))
        .add_value(CGC_KEY, &Bytes::from(encode_cgc(custody_group_count)))
        .add_value(NFD_KEY, &Bytes::from(fork.nfd.to_vec()))
        .build(key)
        .map_err(|e| BuildError::Enr(e.to_string()))
}

/// Sets the local record's `cgc` to `custody_group_count`, re-signed with `key`, which bumps
/// its `seq` by one. The same value again leaves the record (and its `seq`) as it is, so each
/// change is exactly one bump. Returns whether the record changed.
///
/// # Errors
///
/// [`BuildError::WrongKey`] unless `key` signed `enr`, [`BuildError::Enr`] if `enr` refuses the
/// re-signed record; in both cases `enr` is unchanged.
pub fn set_cgc(
    enr: &mut Enr,
    key: &CombinedKey,
    custody_group_count: u64,
) -> Result<bool, BuildError> {
    use enr::EnrKey as _;
    if key.public() != enr.public_key() {
        return Err(BuildError::WrongKey);
    }
    let value = Bytes::from(encode_cgc(custody_group_count));
    if value_eq(enr, CGC_KEY, &value) {
        return Ok(false);
    }
    enr.insert(CGC_KEY, &value, key)
        .map_err(|e| BuildError::Enr(e.to_string()))?;
    Ok(true)
}

/// Whether the record holds exactly `want` under `key`.
pub(crate) fn value_eq(enr: &Enr, key: &'static str, want: &Bytes) -> bool {
    matches!(value(enr, key), Ok(Some(current)) if current == *want)
}

/// Why a record's consensus fields were refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FieldError {
    /// The bytes are not one valid signed record of at most 300 bytes.
    #[error("not a valid node record: {0}")]
    Record(String),
    /// The record is not signed with a secp256k1 key (`phase0/p2p-interface.md`: the record
    /// MUST carry the `secp256k1` public key).
    #[error("the record is not signed with a secp256k1 key")]
    NotSecp256k1,
    /// The record has no `eth2` value.
    #[error("no eth2 field")]
    NoEth2,
    /// A value is not an RLP byte string.
    #[error("{key} is not an RLP byte string")]
    Rlp {
        /// The record key.
        key: &'static str,
    },
    /// A value has the wrong length or form.
    #[error(transparent)]
    Value(#[from] EnrFieldError),
}

/// The consensus fields of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrFields {
    /// `eth2`, which every consensus record MUST carry.
    pub eth2: EnrForkId,
    /// `cgc`, absent on a record from before Fulu was scheduled.
    pub cgc: Option<u64>,
    /// `nfd`, absent on a record from before Fulu was scheduled.
    pub nfd: Option<ForkDigest>,
}

impl EnrFields {
    /// Reads `eth2`, `cgc` and `nfd`. A present field that does not decode is an error, never
    /// a default.
    pub fn read(enr: &Enr) -> Result<Self, FieldError> {
        if !matches!(enr.public_key(), CombinedPublicKey::Secp256k1(_)) {
            return Err(FieldError::NotSecp256k1);
        }
        let eth2 = fork_id(enr)?;
        let cgc = value(enr, CGC_KEY)?.map(|b| decode_cgc(&b)).transpose()?;
        let nfd = value(enr, NFD_KEY)?.map(|b| decode_nfd(&b)).transpose()?;
        Ok(Self { eth2, cgc, nfd })
    }
}

/// The `eth2` value of a record.
pub fn fork_id(enr: &Enr) -> Result<EnrForkId, FieldError> {
    let bytes = value(enr, ETH2_KEY)?.ok_or(FieldError::NoEth2)?;
    Ok(decode_eth2(&bytes)?)
}

/// Decodes one record from untrusted RLP bytes and reads its consensus fields.
pub fn parse_enr_fields(rlp: &[u8]) -> Result<EnrFields, FieldError> {
    let mut buf = rlp;
    let enr = Enr::decode(&mut buf).map_err(|e| FieldError::Record(e.to_string()))?;
    if !buf.is_empty() {
        return Err(FieldError::Record(format!(
            "{} bytes after the record",
            buf.len()
        )));
    }
    EnrFields::read(&enr)
}

/// The RLP byte-string value under `key`, if the record has one.
fn value(enr: &Enr, key: &'static str) -> Result<Option<Bytes>, FieldError> {
    enr.get_decodable::<Bytes>(key)
        .transpose()
        .map_err(|_| FieldError::Rlp { key })
}

#[cfg(test)]
mod tests {
    use super::*;
    use enr::EnrKey;
    use network_config::{ChainConfig, Network};
    use p2p_wire::enr::ForkFields;
    use std::net::Ipv4Addr;

    /// The node key as `node-key` hands it over: an owner-only credential in a credentials
    /// directory, loaded for the UID that owns it.
    fn node_key_secret(bytes: &[u8; 32]) -> node_key::NodeKeySecret {
        use std::io::Write as _;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(node_key::CREDENTIAL);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner = std::fs::metadata(&path).unwrap().uid();
        node_key::load(
            Some(dir.path().as_os_str()),
            owner,
            "ethswarm-discv5.service",
        )
        .unwrap()
    }

    #[test]
    fn the_node_key_signs_the_local_record() {
        let key = signing_key(node_key_secret(&[7; 32])).unwrap();
        let want = CombinedKey::secp256k1_from_bytes(&mut [7; 32]).unwrap();
        assert_eq!(key.public(), want.public());
        assert_eq!(key.encode(), want.encode());
        let enr = build_local_enr(
            &key,
            &sepolia_fields(274_175),
            4,
            &LocalAddr::new(Ipv4Addr::UNSPECIFIED),
        )
        .unwrap();
        assert_eq!(enr.public_key(), want.public());
    }

    fn sepolia_fields(epoch: u64) -> ForkFields {
        let config = ChainConfig::load(Network::Sepolia).unwrap();
        let gvr = Network::Sepolia.genesis().unwrap().genesis_validators_root;
        ForkFields::from_schedule(&config, &gvr, epoch).unwrap()
    }

    #[test]
    fn local_enr_round_trips() {
        let key = CombinedKey::generate_secp256k1();
        let fields = sepolia_fields(274_175);
        let addr = LocalAddr {
            ip: Ipv4Addr::new(192, 0, 2, 7),
            tcp_port: 9000,
            udp_port: 9001,
        };
        let enr = build_local_enr(&key, &fields, 4, &addr).unwrap();
        assert_eq!(enr.ip4(), Some(addr.ip));
        assert_eq!(enr.tcp4(), Some(9000));
        assert_eq!(enr.udp4(), Some(9001));

        let want = EnrFields {
            eth2: fields.eth2,
            cgc: Some(4),
            nfd: Some(fields.nfd),
        };
        assert_eq!(EnrFields::read(&enr), Ok(want));
        // Text form and RLP form decode to the same record and fields.
        let text = enr.to_base64();
        let parsed: Enr = text.parse().unwrap();
        assert_eq!(parsed, enr);
        assert_eq!(EnrFields::read(&parsed), Ok(want));
        let rlp = alloy_rlp::encode(&enr);
        assert_eq!(parse_enr_fields(&rlp), Ok(want));
        // The raw values are the spec encodings.
        assert_eq!(raw(&enr, "eth2"), fields.eth2.to_bytes().to_vec());
        assert_eq!(raw(&enr, "cgc"), vec![0x04]);
        assert_eq!(raw(&enr, "nfd"), fields.nfd.to_vec());
    }

    fn raw(enr: &Enr, key: &str) -> Vec<u8> {
        enr.get_decodable::<alloy_rlp::Bytes>(key)
            .unwrap()
            .unwrap()
            .to_vec()
    }

    /// A secp256k1 record with `eth2` = `eth2` and the given extra raw values.
    fn record(eth2: Option<&[u8]>, extra: &[(&str, &[u8])]) -> Enr {
        let key = CombinedKey::generate_secp256k1();
        let mut b = Enr::builder();
        b.ip4(Ipv4Addr::LOCALHOST).udp4(9000);
        if let Some(eth2) = eth2 {
            b.add_value(ETH2_KEY, &Bytes::copy_from_slice(eth2));
        }
        for (k, v) in extra {
            b.add_value(*k, &Bytes::copy_from_slice(v));
        }
        b.build(&key).unwrap()
    }

    #[test]
    fn field_refusals() {
        let eth2 = sepolia_fields(300_000).eth2.to_bytes();
        let read = |enr: &Enr| EnrFields::read(enr);
        assert_eq!(read(&record(None, &[])), Err(FieldError::NoEth2));
        assert_eq!(
            read(&record(Some(&eth2[..15]), &[])),
            Err(FieldError::Value(EnrFieldError::Eth2Len(15)))
        );
        assert_eq!(
            read(&record(Some(&eth2), &[("cgc", &[0, 4])])),
            Err(FieldError::Value(EnrFieldError::CgcLeadingZero))
        );
        assert_eq!(
            read(&record(Some(&eth2), &[("nfd", &[1, 2, 3])])),
            Err(FieldError::Value(EnrFieldError::NfdLen(3)))
        );
        // Without cgc and nfd (a record from before Fulu): eth2 only.
        let fields = read(&record(Some(&eth2), &[])).unwrap();
        assert_eq!((fields.cgc, fields.nfd), (None, None));
        // A cgc of 0 is the empty string.
        let fields = read(&record(Some(&eth2), &[("cgc", &[])])).unwrap();
        assert_eq!(fields.cgc, Some(0));

        // A value that is an RLP list, not a byte string.
        let key = CombinedKey::generate_secp256k1();
        let list = Enr::builder()
            .add_value(ETH2_KEY, &Bytes::copy_from_slice(&eth2))
            .add_value(CGC_KEY, &vec![1u64, 2])
            .build(&key)
            .unwrap();
        assert_eq!(read(&list), Err(FieldError::Rlp { key: "cgc" }));

        // An ed25519 record is not a consensus record.
        let ed = CombinedKey::generate_ed25519();
        let ed = Enr::builder()
            .add_value(ETH2_KEY, &Bytes::copy_from_slice(&eth2))
            .build(&ed)
            .unwrap();
        assert_eq!(read(&ed), Err(FieldError::NotSecp256k1));
    }

    #[test]
    fn parse_refuses_bad_bytes() {
        let eth2 = sepolia_fields(300_000).eth2.to_bytes();
        let enr = record(Some(&eth2), &[]);
        let rlp = alloy_rlp::encode(&enr);
        assert!(parse_enr_fields(&rlp).is_ok());

        let mut trailing = rlp.clone();
        trailing.push(0);
        assert_eq!(
            parse_enr_fields(&trailing),
            Err(FieldError::Record("1 bytes after the record".into()))
        );
        for bad in [
            &[][..],
            &[0xc0][..],
            &[0xff; 8][..],
            &rlp[..rlp.len() - 1],
            &[0; 301][..],
        ] {
            assert!(
                matches!(parse_enr_fields(bad), Err(FieldError::Record(_))),
                "{bad:?}"
            );
        }
        // A flipped signature byte: the signature no longer verifies.
        let mut forged = rlp.clone();
        forged[5] ^= 1;
        assert!(matches!(
            parse_enr_fields(&forged),
            Err(FieldError::Record(_))
        ));
    }

    /// A new `cgc` re-signs the record once (seq + 1); the same `cgc` again changes nothing.
    #[test]
    fn set_cgc_re_signs_once_per_change() {
        let key = CombinedKey::generate_secp256k1();
        let addr = LocalAddr::new(Ipv4Addr::LOCALHOST);
        let mut enr = build_local_enr(&key, &sepolia_fields(274_175), 0, &addr).unwrap();
        let seq = enr.seq();
        assert_eq!(set_cgc(&mut enr, &key, 4), Ok(true));
        assert_eq!(enr.seq(), seq + 1);
        assert!(enr.verify());
        assert_eq!(raw(&enr, "cgc"), vec![0x04]);
        assert_eq!(EnrFields::read(&enr).unwrap().cgc, Some(4));
        assert_eq!(set_cgc(&mut enr, &key, 4), Ok(false));
        assert_eq!(enr.seq(), seq + 1);

        // Another key would re-sign the record as another node: refused, record unchanged.
        let other = CombinedKey::generate_secp256k1();
        assert_eq!(set_cgc(&mut enr, &other, 8), Err(BuildError::WrongKey));
        assert_eq!(
            (enr.seq(), EnrFields::read(&enr).unwrap().cgc),
            (seq + 1, Some(4))
        );
    }

    #[test]
    fn an_unspecified_ip_is_left_out() {
        let key = CombinedKey::generate_secp256k1();
        let addr = LocalAddr::new(Ipv4Addr::UNSPECIFIED);
        let enr = build_local_enr(&key, &sepolia_fields(300_000), 0, &addr).unwrap();
        assert_eq!(enr.ip4(), None);
        assert_eq!((enr.tcp4(), enr.udp4()), (Some(9000), Some(9000)));
        assert_eq!(raw(&enr, "cgc"), Vec::<u8>::new());
        assert_eq!(EnrFields::read(&enr).unwrap().cgc, Some(0));
    }
}
