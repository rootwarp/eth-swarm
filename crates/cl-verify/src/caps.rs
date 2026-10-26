//! Request caps, checked on the received message before any point or cell is decoded.
//!
//! The 4 MiB message cap is enforced by the tonic codec from the gRPC frame header, before the
//! protobuf is decoded at all (see [`crate::server::VerifyServer::into_service`]). The other caps
//! run on the decoded protobuf but before any BLS point, KZG commitment, cell or proof is touched,
//! and before anything is allocated per item. A request over any cap is a contract violation that
//! fails the stream; it never yields a verdict.

use std::collections::HashSet;

pub use cl_verify_cache::MAX_INLINE_KEYS_PER_BATCH;

use crate::proto::common::{Error, ErrorCode, Hello};
use crate::proto::verify::{
    KeyNamespace, Signer, VerifyBlsRequestBody, VerifyKzgRequestBody, VerifyOrigin,
};
use crate::wire::wire_error;

/// Max BLS sets in one `VerifyBlsRequestBody` (verify.proto: "At most 256 sets").
pub const MAX_BLS_SETS: usize = 256;
/// Max encoded size of one request message, checked from the gRPC frame header before decode.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Max distinct columns (`cell_index` values) in one `VerifyKzgRequestBody`: one block's worth,
/// `NUMBER_OF_COLUMNS` = 128 (fulu/das-core.md).
pub const MAX_KZG_COLUMNS: usize = 128;
/// `MAX_VALIDATORS_PER_COMMITTEE` (presets/mainnet/phase0.yaml).
pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
/// `MAX_COMMITTEES_PER_SLOT` (presets/mainnet/phase0.yaml).
pub const MAX_COMMITTEES_PER_SLOT: usize = 64;
/// Max signers in one set. From Electra an on-chain aggregate spans committees:
/// `IndexedAttestation.attesting_indices` is `List[ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE *
/// MAX_COMMITTEES_PER_SLOT]` (electra/beacon-chain.md), and gloas `is_valid_indexed_attestation`
/// refuses more. Sync and PTC aggregates are smaller (512).
pub const MAX_SIGNERS_PER_SET: usize = MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT;
/// Signers across all sets of one request. Equal to the per-set cap, so one maximal set always
/// fits on its own; larger batches are split by cl-chain.
pub const MAX_SIGNERS_PER_REQUEST: usize = MAX_SIGNERS_PER_SET;
/// `MAX_BLOB_COMMITMENTS_PER_BLOCK` (presets/mainnet/deneb.yaml): the absolute blobs-per-block bound.
pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: u64 = 4096;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapError {
    #[error("{got} BLS sets exceed the cap of {max}")]
    TooManySets { got: usize, max: usize },
    /// `eth_fast_aggregate_verify` is true for zero pubkeys and the G2 point at infinity, so a set
    /// with no signers must never reach BLS.
    #[error("set {set} has no signers")]
    NoSigners { set: usize },
    #[error("set {set} carries an inline pubkey on a gossip request")]
    InlineOnGossip { set: usize },
    #[error("set {set} has {got} signers, over the cap of {max}")]
    TooManySignersInSet { set: usize, got: usize, max: usize },
    #[error("{got} signers in one request exceed the cap of {max}")]
    TooManySigners { got: usize, max: usize },
    #[error("VERIFY_ORIGIN_UNSPECIFIED")]
    UnspecifiedOrigin,
    #[error("set {set} has a signer with KEY_NAMESPACE_UNSPECIFIED")]
    UnspecifiedNamespace { set: usize },
    /// A validator signer with a `builder`, or a builder signer without one or with a
    /// `validator_index` or an `inline_pubkey`.
    #[error("set {set} has a signer whose fields do not fit its KeyNamespace")]
    SignerShape { set: usize },
    #[error("{got} inline pubkeys across the sets of one import request exceed the cap of {max}")]
    TooManyInlineKeys { got: usize, max: usize },
    /// The spec's empty batch is vacuously true; an empty request would read as ACCEPT with no
    /// pairing check, so it is refused.
    #[error("KZG request has no cells")]
    NoCells,
    #[error("{got} KZG cells exceed the cap of {max}")]
    TooManyCells { got: usize, max: usize },
    #[error("{got} KZG columns exceed the cap of {max}")]
    TooManyColumns { got: usize, max: usize },
}

impl CapError {
    /// Every cap breach is `ERROR_CODE_CONTRACT_VIOLATION`.
    #[must_use]
    pub fn to_wire(&self) -> Error {
        wire_error(ErrorCode::ContractViolation, self.to_string())
    }
}

/// Request-shape checks for VerifyBls: set count, at least one and at most
/// [`MAX_SIGNERS_PER_SET`] signers per set, [`MAX_SIGNERS_PER_REQUEST`] in all, a zero origin, a
/// zero signer namespace, signer fields that do not fit their namespace, any inline key (validator
/// or builder) on gossip, and the import inline packing cap over both namespaces (which a request
/// of exactly one set may exceed). Each fails the stream with `ERROR_CODE_CONTRACT_VIOLATION`, and
/// the server runs these before the deadline check, so a malformed request is reported even when
/// its deadline is 0 or past. An unknown non-zero origin or signer namespace passes here; the
/// verifier IGNOREs it without BLS work.
pub fn check_bls(body: &VerifyBlsRequestBody) -> Result<(), CapError> {
    let got = body.sets.len();
    if got > MAX_BLS_SETS {
        return Err(CapError::TooManySets {
            got,
            max: MAX_BLS_SETS,
        });
    }
    let gossip = body.origin == VerifyOrigin::Gossip as i32;
    let mut total = 0usize;
    for (set, s) in body.sets.iter().enumerate() {
        let got = s.signers.len();
        if got == 0 {
            return Err(CapError::NoSigners { set });
        }
        for signer in &s.signers {
            check_signer(signer, set)?;
        }
        if gossip && s.signers.iter().any(is_inline) {
            return Err(CapError::InlineOnGossip { set });
        }
        if got > MAX_SIGNERS_PER_SET {
            return Err(CapError::TooManySignersInSet {
                set,
                got,
                max: MAX_SIGNERS_PER_SET,
            });
        }
        total += got;
        if total > MAX_SIGNERS_PER_REQUEST {
            return Err(CapError::TooManySigners {
                got: total,
                max: MAX_SIGNERS_PER_REQUEST,
            });
        }
    }
    if body.origin == VerifyOrigin::Unspecified as i32 {
        return Err(CapError::UnspecifiedOrigin);
    }
    if body.origin == VerifyOrigin::Import as i32 && body.sets.len() > 1 {
        let inline = body
            .sets
            .iter()
            .flat_map(|s| &s.signers)
            .filter(|s| is_inline(s))
            .count();
        if inline > MAX_INLINE_KEYS_PER_BATCH {
            return Err(CapError::TooManyInlineKeys {
                got: inline,
                max: MAX_INLINE_KEYS_PER_BATCH,
            });
        }
    }
    Ok(())
}

/// The namespace rules of one signer: not `UNSPECIFIED`, and the fields of its namespace only. An
/// unknown non-zero namespace passes (it is IGNOREd per set).
fn check_signer(signer: &Signer, set: usize) -> Result<(), CapError> {
    let fits = match KeyNamespace::try_from(signer.namespace) {
        Ok(KeyNamespace::Unspecified) => return Err(CapError::UnspecifiedNamespace { set }),
        Ok(KeyNamespace::Validator) => signer.builder.is_none(),
        Ok(KeyNamespace::Builder) => {
            signer.builder.is_some()
                && signer.validator_index == 0
                && signer.inline_pubkey.is_empty()
        }
        Err(_) => true,
    };
    if fits {
        Ok(())
    } else {
        Err(CapError::SignerShape { set })
    }
}

/// Whether a signer carries an inline key: a validator `inline_pubkey`, or a builder marked
/// `inline`. A signer of an unknown namespace never does: its set is IGNOREd without decoding,
/// so its fields neither fail a gossip request nor count against the inline cap.
fn is_inline(signer: &Signer) -> bool {
    match KeyNamespace::try_from(signer.namespace) {
        Ok(KeyNamespace::Validator) => !signer.inline_pubkey.is_empty(),
        Ok(KeyNamespace::Builder) => signer.builder.as_ref().is_some_and(|b| b.inline),
        Ok(KeyNamespace::Unspecified) | Err(_) => false,
    }
}

/// Most cells one KZG request may carry: every column of one block at the largest blob count in
/// the handshake's fork and BPO schedules, `NUMBER_OF_COLUMNS * max_blobs_per_block`, with the
/// blob count clamped to `MAX_BLOB_COMMITMENTS_PER_BLOCK`.
#[must_use]
pub fn max_kzg_cells(hello: &Hello) -> usize {
    let blobs = hello
        .fork_schedule
        .iter()
        .map(|e| e.max_blobs_per_block)
        .chain(hello.blob_schedule.iter().map(|e| e.max_blobs_per_block))
        .max()
        .unwrap_or(0)
        .min(MAX_BLOB_COMMITMENTS_PER_BLOCK);
    MAX_KZG_COLUMNS * usize::try_from(blobs).unwrap_or(usize::MAX)
}

/// Request-level checks for VerifyKzg: at least one cell, at most `max_cells`, and at most
/// [`MAX_KZG_COLUMNS`] distinct `cell_index` values (counting stops once the cap is passed).
pub fn check_kzg(body: &VerifyKzgRequestBody, max_cells: usize) -> Result<(), CapError> {
    let got = body.cells.len();
    if got == 0 {
        return Err(CapError::NoCells);
    }
    if got > max_cells {
        return Err(CapError::TooManyCells {
            got,
            max: max_cells,
        });
    }
    let mut columns = HashSet::with_capacity(MAX_KZG_COLUMNS + 1);
    for cell in &body.cells {
        columns.insert(cell.cell_index);
        if columns.len() > MAX_KZG_COLUMNS {
            return Err(CapError::TooManyColumns {
                got: columns.len(),
                max: MAX_KZG_COLUMNS,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::common::{BlobScheduleEntry, ForkScheduleEntry};
    use crate::proto::verify::{BlsSet, BuilderSigner, KzgCellProof, Signer, VerifyOrigin};

    fn bls(n: usize) -> VerifyBlsRequestBody {
        VerifyBlsRequestBody {
            request_id: 1,
            sets: vec![signers(1, false); n],
            deadline_unix_ms: 0,
            origin: 1,
            generation: 0,
        }
    }

    fn kzg(indices: impl IntoIterator<Item = u64>) -> VerifyKzgRequestBody {
        VerifyKzgRequestBody {
            request_id: 1,
            cells: indices
                .into_iter()
                .map(|cell_index| KzgCellProof {
                    cell_index,
                    ..KzgCellProof::default()
                })
                .collect(),
            deadline_unix_ms: 0,
            generation: 0,
        }
    }

    fn signers(n: usize, inline: bool) -> BlsSet {
        BlsSet {
            signers: (0..n as u64)
                .map(|i| Signer {
                    validator_index: i,
                    inline_pubkey: if inline { vec![1; 48] } else { vec![] },
                    namespace: KeyNamespace::Validator as i32,
                    builder: None,
                })
                .collect(),
            ..BlsSet::default()
        }
    }

    fn with_sets(sets: Vec<BlsSet>, origin: VerifyOrigin) -> VerifyBlsRequestBody {
        VerifyBlsRequestBody {
            sets,
            origin: origin as i32,
            ..bls(0)
        }
    }

    #[test]
    fn bls_set_cap_is_inclusive() {
        assert_eq!(check_bls(&bls(0)), Ok(()));
        assert_eq!(check_bls(&bls(256)), Ok(()));
        assert_eq!(
            check_bls(&bls(257)),
            Err(CapError::TooManySets { got: 257, max: 256 })
        );
    }

    #[test]
    fn signers_per_set_are_capped_at_the_indexed_attestation_limit() {
        assert_eq!(MAX_SIGNERS_PER_SET, 2048 * 64);
        let at = with_sets(
            vec![signers(MAX_SIGNERS_PER_SET, false)],
            VerifyOrigin::Import,
        );
        assert_eq!(check_bls(&at), Ok(()));
        let over = with_sets(
            vec![signers(1, false), signers(MAX_SIGNERS_PER_SET + 1, false)],
            VerifyOrigin::Import,
        );
        assert_eq!(
            check_bls(&over),
            Err(CapError::TooManySignersInSet {
                set: 1,
                got: MAX_SIGNERS_PER_SET + 1,
                max: MAX_SIGNERS_PER_SET
            })
        );
    }

    #[test]
    fn signers_per_request_have_a_total_budget() {
        let half = MAX_SIGNERS_PER_REQUEST / 2;
        let at = with_sets(
            vec![signers(half, false), signers(half, false)],
            VerifyOrigin::Gossip,
        );
        assert_eq!(check_bls(&at), Ok(()));
        let over = with_sets(
            vec![
                signers(half, false),
                signers(half, false),
                signers(1, false),
            ],
            VerifyOrigin::Gossip,
        );
        assert_eq!(
            check_bls(&over),
            Err(CapError::TooManySigners {
                got: MAX_SIGNERS_PER_REQUEST + 1,
                max: MAX_SIGNERS_PER_REQUEST
            })
        );
    }

    #[test]
    fn unspecified_origin_is_refused_and_unknown_origin_passes_the_caps() {
        let mut b = bls(1);
        b.origin = VerifyOrigin::Unspecified as i32;
        assert_eq!(check_bls(&b), Err(CapError::UnspecifiedOrigin));
        b.origin = 99;
        assert_eq!(
            check_bls(&b),
            Ok(()),
            "unknown non-zero origin is IGNOREd later, not refused"
        );
    }

    #[test]
    fn import_inline_cap_applies_across_sets_but_not_to_one_set() {
        let cap = MAX_INLINE_KEYS_PER_BATCH;
        let one_big = with_sets(vec![signers(cap + 500, true)], VerifyOrigin::Import);
        assert_eq!(
            check_bls(&one_big),
            Ok(()),
            "a single set may exceed the packing cap"
        );
        let at = with_sets(
            vec![signers(cap - 1, true), signers(1, true)],
            VerifyOrigin::Import,
        );
        assert_eq!(check_bls(&at), Ok(()));
        let over = with_sets(
            vec![signers(cap, true), signers(1, true), signers(3, false)],
            VerifyOrigin::Import,
        );
        assert_eq!(
            check_bls(&over),
            Err(CapError::TooManyInlineKeys {
                got: cap + 1,
                max: cap
            })
        );
    }

    #[test]
    fn any_inline_key_on_gossip_is_refused() {
        let one = with_sets(
            vec![signers(3, false), signers(1, true)],
            VerifyOrigin::Gossip,
        );
        assert_eq!(check_bls(&one), Err(CapError::InlineOnGossip { set: 1 }));
        let none = with_sets(vec![signers(3, false)], VerifyOrigin::Gossip);
        assert_eq!(check_bls(&none), Ok(()));
    }

    fn builder(inline: bool) -> Signer {
        Signer {
            namespace: KeyNamespace::Builder as i32,
            builder: Some(BuilderSigner {
                builder_index: 5,
                key_version: 9,
                pubkey: vec![2; 48],
                inline,
            }),
            ..Signer::default()
        }
    }

    fn set_of(signers: Vec<Signer>) -> BlsSet {
        BlsSet {
            signers,
            ..BlsSet::default()
        }
    }

    #[test]
    fn a_zero_signer_namespace_is_refused_and_an_unknown_one_passes() {
        let mut zero = signers(2, false);
        zero.signers[1].namespace = KeyNamespace::Unspecified as i32;
        let b = with_sets(vec![signers(1, false), zero], VerifyOrigin::Import);
        assert_eq!(
            check_bls(&b),
            Err(CapError::UnspecifiedNamespace { set: 1 })
        );
        assert!(CapError::UnspecifiedNamespace { set: 1 }
            .to_wire()
            .detail
            .contains("KEY_NAMESPACE_UNSPECIFIED"));
        let mut unknown = signers(1, false);
        unknown.signers[0].namespace = 99;
        let b = with_sets(vec![unknown], VerifyOrigin::Gossip);
        assert_eq!(check_bls(&b), Ok(()), "IGNOREd per set, not refused");
    }

    #[test]
    fn signer_fields_must_fit_their_namespace() {
        let mut validator_with_builder = signers(1, false);
        validator_with_builder.signers[0].builder = builder(false).builder;
        let mut builder_without = builder(false);
        builder_without.builder = None;
        let mut builder_with_index = builder(false);
        builder_with_index.validator_index = 5;
        let mut builder_with_inline_pubkey = builder(false);
        builder_with_inline_pubkey.inline_pubkey = vec![2; 48];
        for bad in [
            validator_with_builder,
            set_of(vec![builder_without]),
            set_of(vec![builder_with_index]),
            set_of(vec![builder_with_inline_pubkey]),
        ] {
            let b = with_sets(vec![signers(1, false), bad], VerifyOrigin::Import);
            assert_eq!(check_bls(&b), Err(CapError::SignerShape { set: 1 }));
        }
        let fine = with_sets(vec![set_of(vec![builder(false)])], VerifyOrigin::Gossip);
        assert_eq!(check_bls(&fine), Ok(()));
    }

    #[test]
    fn an_inline_builder_key_is_refused_on_gossip_and_counts_against_the_import_cap() {
        let gossip = with_sets(vec![set_of(vec![builder(true)])], VerifyOrigin::Gossip);
        assert_eq!(check_bls(&gossip), Err(CapError::InlineOnGossip { set: 0 }));
        let cap = MAX_INLINE_KEYS_PER_BATCH;
        let at = with_sets(
            vec![signers(cap - 1, true), set_of(vec![builder(true)])],
            VerifyOrigin::Import,
        );
        assert_eq!(check_bls(&at), Ok(()));
        let over = with_sets(
            vec![
                signers(cap, true),
                set_of(vec![builder(true), builder(false)]),
            ],
            VerifyOrigin::Import,
        );
        assert_eq!(
            check_bls(&over),
            Err(CapError::TooManyInlineKeys {
                got: cap + 1,
                max: cap
            })
        );
    }

    #[test]
    fn inline_rules_skip_a_signer_of_an_unknown_namespace() {
        // Inline fields on a signer of a namespace this build does not know: the set is IGNOREd
        // later (VERSION_MISMATCH), so they neither fail gossip nor count against the cap.
        let mut unknown = builder(true);
        unknown.namespace = 99;
        unknown.inline_pubkey = vec![2; 48];
        let gossip = with_sets(
            vec![signers(1, false), set_of(vec![unknown.clone()])],
            VerifyOrigin::Gossip,
        );
        assert_eq!(check_bls(&gossip), Ok(()));
        let cap = MAX_INLINE_KEYS_PER_BATCH;
        let import = with_sets(
            vec![signers(cap, true), set_of(vec![unknown])],
            VerifyOrigin::Import,
        );
        assert_eq!(check_bls(&import), Ok(()));
    }

    #[test]
    fn set_without_signers_is_refused() {
        let b = with_sets(
            vec![signers(1, false), signers(0, false)],
            VerifyOrigin::Import,
        );
        assert_eq!(check_bls(&b), Err(CapError::NoSigners { set: 1 }));
    }

    #[test]
    fn kzg_cap_counts_distinct_columns() {
        // Many blobs in one column: 3 cells, 1 column.
        assert_eq!(check_kzg(&kzg([5, 5, 5]), 10_000), Ok(()));
        assert_eq!(check_kzg(&kzg(0..128), 10_000), Ok(()));
        assert_eq!(check_kzg(&kzg((0..128).chain(0..128)), 10_000), Ok(()));
        assert_eq!(
            check_kzg(&kzg(0..129), 10_000),
            Err(CapError::TooManyColumns { got: 129, max: 128 })
        );
    }

    #[test]
    fn kzg_cell_count_is_capped_before_any_cell_is_looked_at() {
        let max = 128 * 21;
        assert_eq!(
            check_kzg(&kzg((0..max as u64).map(|i| i % 128)), max),
            Ok(())
        );
        let over = kzg((0..=max as u64).map(|i| i % 128));
        assert_eq!(
            check_kzg(&over, max),
            Err(CapError::TooManyCells { got: max + 1, max })
        );
    }

    #[test]
    fn empty_kzg_request_is_refused() {
        assert_eq!(check_kzg(&kzg([]), 128), Err(CapError::NoCells));
    }

    #[test]
    fn max_kzg_cells_is_one_block_of_the_largest_scheduled_blob_count() {
        let mut h = Hello::default();
        assert_eq!(max_kzg_cells(&h), 0);
        h.fork_schedule.push(ForkScheduleEntry {
            max_blobs_per_block: 9,
            ..ForkScheduleEntry::default()
        });
        h.blob_schedule.push(BlobScheduleEntry {
            epoch: 1,
            max_blobs_per_block: 21,
        });
        assert_eq!(max_kzg_cells(&h), 128 * 21);
        h.blob_schedule[0].max_blobs_per_block = u64::MAX;
        assert_eq!(
            max_kzg_cells(&h),
            128 * 4096,
            "clamped to MAX_BLOB_COMMITMENTS_PER_BLOCK"
        );
    }

    #[test]
    fn cap_breach_is_a_contract_violation() {
        let err = check_bls(&bls(257)).unwrap_err().to_wire();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        assert!(err.detail.contains("257"));
    }
}
