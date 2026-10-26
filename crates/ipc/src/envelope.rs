//! Opening an `Envelope`: payload type, fork digest, then decode, in that order.
//!
//! `proto/README.md` rules 1 to 3 and the `Envelope` comments in `envelope.proto`:
//!
//! 1. `payload_type` is a closed enum. Zero (`PAYLOAD_TYPE_UNSPECIFIED`, which is also what a
//!    missing field reads as) is `ERROR_CODE_CONTRACT_VIOLATION`; an unknown non-zero value is
//!    IGNOREd: dropped, never decoded, never REJECTed.
//! 2. `fork_digest` must equal the digest the published schedule gives the fork of the
//!    object's slot (which from Fulu on also changes at BPO epochs). A mismatch means drop and
//!    log `ERROR_CODE_FORK_DIGEST_MISMATCH`; the bytes are never decoded.
//! 3. Only then is the SSZ decoded, by the fork of the object's slot and never the current
//!    fork, through `consensus_types::codec::decode` (which checks the per-type cap first).
//!
//! [`ForkDigests`] is the digest lookup. [`DigestTable`] serves it from the published schedule
//! (the `ForkScheduleEntry` list a `Hello` carries); a `compute_fork_digest` implementation can
//! replace it without touching this module.

use consensus_types::caps::ObjectKind;
use consensus_types::codec::{self, DecodeError, Object};
use consensus_types::EthSpec;
use ethswarm_proto::common::{
    Envelope, ErrorCode, ForkName as WireForkName, ForkScheduleEntry, PayloadType,
};
use ethswarm_proto::{chain, p2p, store};
use network_config::{Epoch, ForkName, ForkSchedule};

use crate::error::ContractError;

/// A 4-byte `ForkDigest`.
pub type ForkDigest = [u8; 4];

/// The fork digest expected for objects of `fork` at `epoch`.
pub trait ForkDigests {
    /// `None` when the schedule has no digest for that fork at that epoch.
    fn fork_digest(&self, fork: ForkName, epoch: Epoch) -> Option<ForkDigest>;
}

/// Digest epochs of one network: each entry applies from its epoch until the next one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestTable {
    /// Sorted by epoch, strictly increasing.
    entries: Vec<(Epoch, ForkName, ForkDigest)>,
}

impl DigestTable {
    /// A table from `(epoch, fork, digest)` entries; epochs must be distinct.
    pub fn new(mut entries: Vec<(Epoch, ForkName, ForkDigest)>) -> Result<Self, ContractError> {
        entries.sort_by_key(|e| e.0);
        if entries.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(ContractError::violation(
                "fork schedule has two digests for one epoch",
            ));
        }
        if entries.windows(2).any(|w| w[1].1 < w[0].1) {
            return Err(ContractError::violation(
                "fork schedule goes back to an earlier fork",
            ));
        }
        Ok(Self { entries })
    }

    /// The table of a published schedule (`Hello.fork_schedule`, `ForkSchedule.entries`).
    pub fn from_schedule(entries: &[ForkScheduleEntry]) -> Result<Self, ContractError> {
        let parsed = entries
            .iter()
            .map(|e| {
                let fork = match WireForkName::try_from(e.fork) {
                    Ok(WireForkName::Fulu) => ForkName::Fulu,
                    Ok(WireForkName::Gloas) => ForkName::Gloas,
                    _ => {
                        return Err(ContractError::violation(format!(
                            "fork schedule entry at epoch {} has fork {}",
                            e.epoch, e.fork
                        )))
                    }
                };
                let digest = ForkDigest::try_from(e.fork_digest.as_slice()).map_err(|_| {
                    ContractError::violation(format!(
                        "fork schedule entry at epoch {} has a {}-byte digest",
                        e.epoch,
                        e.fork_digest.len()
                    ))
                })?;
                Ok((e.epoch, fork, digest))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(parsed)
    }
}

impl ForkDigests for DigestTable {
    fn fork_digest(&self, fork: ForkName, epoch: Epoch) -> Option<ForkDigest> {
        let at = self.entries.partition_point(|e| e.0 <= epoch);
        let (_, entry_fork, digest) = *self.entries.get(at.checked_sub(1)?)?;
        (entry_fork == fork).then_some(digest)
    }
}

impl<T: ForkDigests + ?Sized> ForkDigests for &T {
    fn fork_digest(&self, fork: ForkName, epoch: Epoch) -> Option<ForkDigest> {
        (**self).fork_digest(fork, epoch)
    }
}

/// Why an envelope is not opened.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum EnvelopeError {
    /// `payload_type` is 0 (or missing): `ERROR_CODE_CONTRACT_VIOLATION`.
    #[error("payload_type is PAYLOAD_TYPE_UNSPECIFIED")]
    UnspecifiedType,
    /// An unknown non-zero `payload_type`: IGNORE.
    #[error("unknown payload_type {0}")]
    UnknownType(i32),
    /// The digest is not the one the schedule gives the slot's fork:
    /// `ERROR_CODE_FORK_DIGEST_MISMATCH`, dropped undecoded.
    /// Only the length and the first 4 bytes of the received digest are kept, so an oversized
    /// one costs nothing to report.
    #[error(
        "fork digest {got_prefix:02x?} ({got_len} bytes) at slot {slot}, expected {expected:02x?}"
    )]
    DigestMismatch {
        slot: u64,
        expected: Option<ForkDigest>,
        got_len: usize,
        /// The first 4 bytes, zero-padded.
        got_prefix: ForkDigest,
    },
    /// A known type this crate has no decoder for (data columns, aggregate `Attestation`,
    /// light-client updates): IGNORE here; the owning crate decodes it after [`check_envelope`].
    #[error("no decoder for {0:?}")]
    NoDecoder(PayloadType),
    /// The SSZ did not decode at the slot's fork: `ERROR_CODE_SSZ_DECODE`.
    #[error("decode: {0}")]
    Decode(DecodeError),
}

impl EnvelopeError {
    /// The error code it is reported with; `None` for the IGNORE cases.
    #[must_use]
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::UnspecifiedType => Some(ErrorCode::ContractViolation),
            Self::UnknownType(_) | Self::NoDecoder(_) => None,
            Self::DigestMismatch { .. } => Some(ErrorCode::ForkDigestMismatch),
            Self::Decode(_) => Some(ErrorCode::SszDecode),
        }
    }

    /// IGNORE: dropped silently (apart from a metric), never decoded, never REJECTed.
    #[must_use]
    pub fn is_ignore(&self) -> bool {
        self.code().is_none()
    }

    /// The contract error to log or fail with, if any.
    #[must_use]
    pub fn to_contract_error(&self) -> Option<ContractError> {
        self.code().map(|c| ContractError::new(c, self.to_string()))
    }
}

/// An envelope that passed the type and digest checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checked<'a> {
    pub payload_type: PayloadType,
    /// The fork of the object's slot: the schema to decode with.
    pub fork: ForkName,
    pub epoch: Epoch,
    pub ssz: &'a [u8],
}

/// The type and digest checks of [`open_envelope`], without decoding.
pub fn check_envelope<'a, E: EthSpec>(
    envelope: &'a Envelope,
    schedule: &ForkSchedule,
    digests: &impl ForkDigests,
) -> Result<Checked<'a>, EnvelopeError> {
    check_envelope_at(envelope, E::slots_per_epoch(), schedule, digests)
}

/// [`check_envelope`] with `SLOTS_PER_EPOCH` given as a number.
pub fn check_envelope_at<'a>(
    envelope: &'a Envelope,
    slots_per_epoch: u64,
    schedule: &ForkSchedule,
    digests: &impl ForkDigests,
) -> Result<Checked<'a>, EnvelopeError> {
    let payload_type = match PayloadType::try_from(envelope.payload_type) {
        Ok(PayloadType::Unspecified) => return Err(EnvelopeError::UnspecifiedType),
        Ok(t) => t,
        Err(_) => return Err(EnvelopeError::UnknownType(envelope.payload_type)),
    };
    let slot = envelope.slot;
    let epoch = slot / slots_per_epoch.max(1);
    let fork = schedule.fork_at(epoch);
    let expected = fork.and_then(|f| digests.fork_digest(f, epoch));
    let got = envelope.fork_digest.as_slice();
    match (fork, expected) {
        (Some(fork), Some(digest)) if got.len() == digest.len() && got == digest => Ok(Checked {
            payload_type,
            fork,
            epoch,
            ssz: &envelope.ssz,
        }),
        _ => {
            let mut got_prefix = [0; 4];
            let n = got.len().min(got_prefix.len());
            got_prefix[..n].copy_from_slice(&got[..n]);
            Err(EnvelopeError::DigestMismatch {
                slot,
                expected,
                got_len: got.len(),
                got_prefix,
            })
        }
    }
}

/// The decoder for `payload_type`, if `consensus_types` has one.
#[must_use]
pub fn object_kind(payload_type: PayloadType) -> Option<ObjectKind> {
    use ObjectKind as K;
    use PayloadType as P;
    Some(match payload_type {
        P::SignedBeaconBlock => K::SignedBeaconBlock,
        P::BeaconState => K::BeaconState,
        P::SignedExecutionPayloadEnvelope => K::SignedExecutionPayloadEnvelope,
        P::SignedExecutionPayloadBid => K::SignedExecutionPayloadBid,
        P::PayloadAttestationMessage => K::PayloadAttestationMessage,
        P::SignedProposerPreferences => K::SignedProposerPreferences,
        P::SignedAggregateAndProof => K::SignedAggregateAndProof,
        P::SingleAttestation => K::SingleAttestation,
        P::SignedVoluntaryExit => K::SignedVoluntaryExit,
        P::ProposerSlashing => K::ProposerSlashing,
        P::AttesterSlashing => K::AttesterSlashing,
        P::SignedContributionAndProof => K::SignedContributionAndProof,
        P::SyncCommitteeMessage => K::SyncCommitteeMessage,
        P::SignedBlsToExecutionChange => K::SignedBlsToExecutionChange,
        P::Unspecified
        | P::DataColumnSidecar
        | P::Attestation
        | P::LightClientFinalityUpdate
        | P::LightClientOptimisticUpdate => return None,
    })
}

/// Opens `envelope`: type check, digest check against the fork of its slot, then
/// `consensus_types::codec::decode` at that fork.
pub fn open_envelope<E: EthSpec>(
    envelope: &Envelope,
    schedule: &ForkSchedule,
    digests: &impl ForkDigests,
) -> Result<Object<E>, EnvelopeError> {
    let checked = check_envelope::<E>(envelope, schedule, digests)?;
    let kind =
        object_kind(checked.payload_type).ok_or(EnvelopeError::NoDecoder(checked.payload_type))?;
    codec::decode::<E>(kind, checked.fork, checked.ssz).map_err(EnvelopeError::Decode)
}

/// A message that carries envelopes, listed in field-number order (repeated fields in order).
/// The receiver checks `seq` across them in this order.
pub trait Envelopes {
    fn envelopes(&self) -> Vec<&Envelope>;

    /// Refuses a body that leaves out an envelope its shape requires (checked before any of its
    /// envelopes, so nothing in such a body is admitted).
    fn check_shape(&self) -> Result<(), ContractError> {
        Ok(())
    }
}

macro_rules! no_envelopes {
    ($($ty:ty),* $(,)?) => {
        $(impl Envelopes for $ty {
            fn envelopes(&self) -> Vec<&Envelope> {
                Vec::new()
            }
        })*
    };
}

no_envelopes!(
    chain::ImportBatchResponseBody,
    chain::VerdictBatch,
    chain::WatchSubscriptionsResponseBody,
    chain::SubscribeResponseBody,
    ethswarm_proto::discv5::WatchPeersResponseBody,
    ethswarm_proto::discv5::FindPeersResponseBody,
    ethswarm_proto::verify::VerifyBlsRequestBody,
    ethswarm_proto::verify::VerifyBlsResponseBody,
    ethswarm_proto::verify::VerifyKzgRequestBody,
    ethswarm_proto::verify::VerifyKzgResponseBody,
    ethswarm_proto::verify::PubkeyFeedRequestBody,
    ethswarm_proto::verify::PubkeyFeedResponseBody,
    ethswarm_proto::verify::BuilderKeyFeedRequestBody,
    ethswarm_proto::verify::BuilderKeyFeedResponseBody,
);

impl Envelopes for chain::ImportBatchRequestBody {
    fn envelopes(&self) -> Vec<&Envelope> {
        self.blocks
            .iter()
            .chain(&self.payload_envelopes)
            .chain(&self.data_columns)
            .collect()
    }
}

impl Envelopes for chain::ValidateBatch {
    fn envelopes(&self) -> Vec<&Envelope> {
        self.messages
            .iter()
            .filter_map(|m| m.payload.as_ref())
            .collect()
    }

    /// Every gossip message carries its payload envelope.
    fn check_shape(&self) -> Result<(), ContractError> {
        match self.messages.iter().position(|m| m.payload.is_none()) {
            Some(i) => Err(ContractError::violation(format!(
                "gossip message {i} of the batch has no payload"
            ))),
            None => Ok(()),
        }
    }
}

impl Envelopes for chain::WatchPublishResponseBody {
    fn envelopes(&self) -> Vec<&Envelope> {
        self.payload.iter().collect()
    }
}

macro_rules! chunk_envelopes {
    ($module:ident :: $chunk:ident; $($ty:ident),* $(,)?) => {
        $(impl Envelopes for $module::$ty {
            fn envelopes(&self) -> Vec<&Envelope> {
                match self.item.as_ref().and_then(|i| i.result.as_ref()) {
                    Some($module::response_chunk::Result::Chunk(e)) => vec![e],
                    _ => Vec::new(),
                }
            }

            /// `oneof result { chunk; error }`: leaving both unset is a contract error, and so
            /// is an error with the zero (`ERROR_CODE_UNSPECIFIED`) code.
            fn check_shape(&self) -> Result<(), ContractError> {
                match self.item.as_ref().and_then(|i| i.result.as_ref()) {
                    Some($module::response_chunk::Result::Error(e))
                        if e.code == ErrorCode::Unspecified as i32 =>
                    {
                        Err(ContractError::violation(concat!(
                            stringify!($ty),
                            " response chunk carries error code 0"
                        )))
                    }
                    Some(_) => Ok(()),
                    None => Err(ContractError::violation(concat!(
                        stringify!($ty),
                        " response chunk has neither chunk nor error"
                    ))),
                }
            }
        })*
    };
}

chunk_envelopes!(chain::ResponseChunk;
    BlocksByRangeResponseBody,
    BlocksByRootResponseBody,
    DataColumnsByRangeResponseBody,
    DataColumnsByRootResponseBody,
    PayloadEnvelopesByRangeResponseBody,
    PayloadEnvelopesByRootResponseBody,
);
chunk_envelopes!(p2p::ResponseChunk;
    RequestBlocksByRangeResponseBody,
    RequestBlocksByRootResponseBody,
    RequestDataColumnsByRangeResponseBody,
    RequestDataColumnsByRootResponseBody,
    RequestPayloadEnvelopesByRangeResponseBody,
    RequestPayloadEnvelopesByRootResponseBody,
);

impl Envelopes for store::GetDataColumnsResponseBody {
    fn envelopes(&self) -> Vec<&Envelope> {
        self.column.iter().collect()
    }
}

impl Envelopes for store::GetDataColumnsByRangeResponseBody {
    fn envelopes(&self) -> Vec<&Envelope> {
        self.column.iter().collect()
    }
}

impl Envelopes for store::GetBlocksByRangeResponseBody {
    fn envelopes(&self) -> Vec<&Envelope> {
        self.item.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::Mainnet;
    use network_config::{ChainConfig, Network};

    const FULU: ForkDigest = [0xf0, 0, 0, 0];
    const BPO1: ForkDigest = [0xf0, 0, 0, 1];
    const GLOAS: ForkDigest = [0x61, 0, 0, 0];
    const SLOTS: u64 = 32;

    /// Sepolia: Fulu at 272640, the first BPO at 274176, Gloas at 353024.
    fn sepolia() -> ForkSchedule {
        *ChainConfig::load(Network::Sepolia).unwrap().fork_schedule()
    }

    fn table() -> DigestTable {
        DigestTable::new(vec![
            (353_024, ForkName::Gloas, GLOAS),
            (272_640, ForkName::Fulu, FULU),
            (274_176, ForkName::Fulu, BPO1),
        ])
        .unwrap()
    }

    fn envelope(payload_type: i32, epoch: Epoch, digest: ForkDigest, ssz: Vec<u8>) -> Envelope {
        Envelope {
            fork_digest: digest.to_vec(),
            slot: epoch * SLOTS,
            payload_type,
            ssz,
            ..Default::default()
        }
    }

    fn exit(epoch: Epoch, digest: ForkDigest) -> Envelope {
        envelope(
            PayloadType::SignedVoluntaryExit as i32,
            epoch,
            digest,
            vec![0; 112],
        )
    }

    fn open(e: &Envelope) -> Result<Object<Mainnet>, EnvelopeError> {
        open_envelope::<Mainnet>(e, &sepolia(), &table())
    }

    #[test]
    fn table_lookup_follows_digest_epochs() {
        let t = table();
        assert_eq!(t.fork_digest(ForkName::Fulu, 272_639), None);
        assert_eq!(t.fork_digest(ForkName::Fulu, 272_640), Some(FULU));
        assert_eq!(t.fork_digest(ForkName::Fulu, 274_175), Some(FULU));
        assert_eq!(t.fork_digest(ForkName::Fulu, 274_176), Some(BPO1));
        assert_eq!(t.fork_digest(ForkName::Gloas, 274_176), None);
        assert_eq!(t.fork_digest(ForkName::Gloas, 353_024), Some(GLOAS));
        assert_eq!(t.fork_digest(ForkName::Fulu, 353_024), None);
        let by_ref: &DigestTable = &t;
        assert_eq!(
            ForkDigests::fork_digest(&by_ref, ForkName::Gloas, u64::MAX),
            Some(GLOAS)
        );
    }

    #[test]
    fn table_refuses_duplicate_epochs_and_fork_regressions() {
        assert!(
            DigestTable::new(vec![(1, ForkName::Fulu, FULU), (1, ForkName::Fulu, BPO1)]).is_err()
        );
        assert!(
            DigestTable::new(vec![(1, ForkName::Gloas, GLOAS), (2, ForkName::Fulu, FULU)]).is_err()
        );
    }

    #[test]
    fn table_from_published_schedule() {
        let entry = |epoch, fork: WireForkName, digest: &[u8]| ForkScheduleEntry {
            epoch,
            fork_digest: digest.to_vec(),
            fork: fork as i32,
            ..Default::default()
        };
        let t = DigestTable::from_schedule(&[
            entry(272_640, WireForkName::Fulu, &FULU),
            entry(353_024, WireForkName::Gloas, &GLOAS),
        ])
        .unwrap();
        assert_eq!(t.fork_digest(ForkName::Gloas, 353_024), Some(GLOAS));
        let zero = DigestTable::from_schedule(&[entry(1, WireForkName::Unspecified, &FULU)]);
        assert_eq!(zero.unwrap_err().code(), ErrorCode::ContractViolation);
        let short = DigestTable::from_schedule(&[entry(1, WireForkName::Fulu, &[1, 2])]);
        assert_eq!(short.unwrap_err().code(), ErrorCode::ContractViolation);
    }

    #[test]
    fn zero_or_missing_type_is_a_contract_violation() {
        let e = envelope(0, 272_640, FULU, vec![0; 112]);
        let err = open(&e).unwrap_err();
        assert_eq!(err, EnvelopeError::UnspecifiedType);
        assert_eq!(err.code(), Some(ErrorCode::ContractViolation));
        assert!(!err.is_ignore());
        let missing = Envelope {
            fork_digest: FULU.to_vec(),
            slot: 272_640 * SLOTS,
            ..Default::default()
        };
        assert_eq!(open(&missing).unwrap_err(), EnvelopeError::UnspecifiedType);
    }

    #[test]
    fn unknown_non_zero_type_is_ignored_before_the_digest_is_read() {
        // Even with a wrong digest the unknown type decides: IGNORE, never decoded.
        let e = envelope(99, 272_640, GLOAS, vec![0xff; 3]);
        let err = open(&e).unwrap_err();
        assert_eq!(err, EnvelopeError::UnknownType(99));
        assert!(err.is_ignore());
        assert_eq!(err.to_contract_error(), None);
    }

    #[test]
    fn digest_must_match_the_fork_of_the_slot() {
        // Last Fulu slot before Gloas carries the BPO digest; first Gloas slot the Gloas one.
        assert!(open(&exit(353_023, BPO1)).is_ok());
        assert!(open(&exit(353_024, GLOAS)).is_ok());
        let cases = [
            exit(353_024, BPO1),  // Gloas slot with a Fulu digest
            exit(353_023, GLOAS), // Fulu slot with the Gloas digest
            exit(274_176, FULU),  // a BPO epoch with the pre-BPO digest
            exit(272_639, FULU),  // before Fulu: no digest in the schedule
        ];
        for e in cases {
            let err = open(&e).unwrap_err();
            assert!(
                matches!(err, EnvelopeError::DigestMismatch { .. }),
                "{err:?}"
            );
            assert_eq!(
                err.to_contract_error().unwrap().code(),
                ErrorCode::ForkDigestMismatch
            );
        }
        let mut short = exit(272_640, FULU);
        short.fork_digest.pop();
        assert!(matches!(
            open(&short),
            Err(EnvelopeError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn oversized_digest_is_reported_by_length_and_prefix_only() {
        let mut huge = exit(353_024, GLOAS);
        huge.fork_digest = vec![0x61; 1 << 20];
        match open(&huge).unwrap_err() {
            EnvelopeError::DigestMismatch {
                got_len,
                got_prefix,
                expected,
                ..
            } => {
                assert_eq!(got_len, 1 << 20);
                assert_eq!(got_prefix, [0x61; 4]);
                assert_eq!(expected, Some(GLOAS));
            }
            other => panic!("{other:?}"),
        }
        let detail = open(&huge).unwrap_err().to_string();
        assert!(detail.len() < 200, "{} bytes of detail", detail.len());
        let mut short = exit(353_024, GLOAS);
        short.fork_digest = vec![0x61];
        assert!(matches!(
            open(&short),
            Err(EnvelopeError::DigestMismatch {
                got_len: 1,
                got_prefix: [0x61, 0, 0, 0],
                ..
            })
        ));
    }

    #[test]
    fn mismatched_digest_is_dropped_without_decoding() {
        // Garbage bytes: a decode would fail, but the digest check comes first.
        let e = envelope(
            PayloadType::SignedBeaconBlock as i32,
            353_024,
            FULU,
            vec![0xff; 5],
        );
        assert!(matches!(
            open(&e),
            Err(EnvelopeError::DigestMismatch { .. })
        ));
        let e = envelope(
            PayloadType::SignedBeaconBlock as i32,
            353_024,
            GLOAS,
            vec![0xff; 5],
        );
        let err = open(&e).unwrap_err();
        assert!(matches!(err, EnvelopeError::Decode(_)), "{err:?}");
        assert_eq!(err.code(), Some(ErrorCode::SszDecode));
    }

    #[test]
    fn valid_envelope_decodes_at_the_slots_fork() {
        match open(&exit(353_024, GLOAS)).unwrap() {
            Object::SignedVoluntaryExit(_) => {}
            other => panic!("decoded as {:?}", other.kind()),
        }
        let last_fulu = exit(353_023, BPO1);
        let checked = check_envelope::<Mainnet>(&last_fulu, &sepolia(), &table()).unwrap();
        assert_eq!(checked.fork, ForkName::Fulu);
        assert_eq!(checked.epoch, 353_023);
        assert_eq!(checked.ssz.len(), 112);
        // A Gloas-only type in a Fulu slot does not exist at that fork.
        let bid = envelope(
            PayloadType::SignedExecutionPayloadBid as i32,
            353_023,
            BPO1,
            vec![0; 8],
        );
        assert!(matches!(
            open(&bid),
            Err(EnvelopeError::Decode(DecodeError::NotInFork { .. }))
        ));
    }

    #[test]
    fn types_without_a_decoder_here_are_ignored_after_the_checks() {
        let col = envelope(
            PayloadType::DataColumnSidecar as i32,
            353_024,
            GLOAS,
            vec![1],
        );
        let err = open(&col).unwrap_err();
        assert_eq!(
            err,
            EnvelopeError::NoDecoder(PayloadType::DataColumnSidecar)
        );
        assert!(err.is_ignore());
        let bad = envelope(
            PayloadType::DataColumnSidecar as i32,
            353_024,
            FULU,
            vec![1],
        );
        assert!(matches!(
            open(&bad),
            Err(EnvelopeError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn every_known_type_but_the_external_ones_has_a_decoder() {
        let mut without = Vec::new();
        for v in 1..=18 {
            let t = PayloadType::try_from(v).unwrap();
            if object_kind(t).is_none() {
                without.push(t);
            }
        }
        assert_eq!(
            without,
            [
                PayloadType::DataColumnSidecar,
                PayloadType::Attestation,
                PayloadType::LightClientFinalityUpdate,
                PayloadType::LightClientOptimisticUpdate
            ]
        );
        assert_eq!(object_kind(PayloadType::Unspecified), None);
    }

    /// Checks the shape rule on one req/resp body type: a chunk or an error passes, an item with
    /// neither (or no item) is a contract violation.
    macro_rules! assert_chunk_shape {
        ($module:ident; $($ty:ident),* $(,)?) => {$({
            // p2p's chunk also names the peer; chain's has only the result.
            #[allow(clippy::needless_update)]
            let with = |result| $module::$ty {
                item: Some($module::ResponseChunk {
                    result,
                    ..Default::default()
                }),
            };
            let chunk = $module::response_chunk::Result::Chunk(Envelope::default());
            let error = |code: ErrorCode| {
                $module::response_chunk::Result::Error(crate::error::wire_error(code, "e"))
            };
            assert_eq!(with(Some(chunk)).check_shape(), Ok(()), stringify!($ty));
            let not_found = error(ErrorCode::NotFound);
            assert_eq!(with(Some(not_found)).check_shape(), Ok(()), stringify!($ty));
            let zero = with(Some(error(ErrorCode::Unspecified))).check_shape().unwrap_err();
            assert_eq!(zero.code(), ErrorCode::ContractViolation, stringify!($ty));
            assert!(zero.detail().contains("error code 0"), "{zero}");
            for empty in [with(None), $module::$ty::default()] {
                let err = empty.check_shape().unwrap_err();
                assert_eq!(err.code(), ErrorCode::ContractViolation, stringify!($ty));
                assert!(err.detail().contains("neither chunk nor error"), "{err}");
            }
        })*};
    }

    #[test]
    fn response_chunk_with_neither_chunk_nor_error_is_refused() {
        assert_chunk_shape!(chain;
            BlocksByRangeResponseBody,
            BlocksByRootResponseBody,
            DataColumnsByRangeResponseBody,
            DataColumnsByRootResponseBody,
            PayloadEnvelopesByRangeResponseBody,
            PayloadEnvelopesByRootResponseBody,
        );
        assert_chunk_shape!(p2p;
            RequestBlocksByRangeResponseBody,
            RequestBlocksByRootResponseBody,
            RequestDataColumnsByRangeResponseBody,
            RequestDataColumnsByRootResponseBody,
            RequestPayloadEnvelopesByRangeResponseBody,
            RequestPayloadEnvelopesByRootResponseBody,
        );
    }

    #[test]
    fn bodies_list_their_envelopes_in_field_order() {
        let e = |seq| Envelope {
            seq,
            ..Default::default()
        };
        let body = chain::ImportBatchRequestBody {
            blocks: vec![e(1), e(2)],
            payload_envelopes: vec![e(3)],
            data_columns: vec![e(4)],
            ..Default::default()
        };
        let seqs: Vec<u64> = body.envelopes().iter().map(|e| e.seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4]);
        let batch = chain::ValidateBatch {
            messages: vec![
                chain::GossipMessage {
                    payload: Some(e(5)),
                    ..Default::default()
                },
                chain::GossipMessage::default(),
            ],
            ..Default::default()
        };
        assert_eq!(batch.envelopes().len(), 1);
        let chunk = p2p::RequestBlocksByRangeResponseBody {
            item: Some(p2p::ResponseChunk {
                peer: None,
                result: Some(p2p::response_chunk::Result::Chunk(e(6))),
            }),
        };
        assert_eq!(chunk.envelopes()[0].seq, 6);
        assert!(p2p::RequestBlocksByRangeResponseBody::default()
            .envelopes()
            .is_empty());
        let col = store::GetDataColumnsResponseBody {
            column: Some(e(7)),
            ..Default::default()
        };
        assert_eq!(col.envelopes().len(), 1);
        assert!(ethswarm_proto::verify::VerifyBlsRequestBody::default()
            .envelopes()
            .is_empty());
    }
}
