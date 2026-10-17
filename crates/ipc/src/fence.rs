//! Request fencing: which result answers which request item.
//!
//! `proto/README.md` (request fencing) and `common.v1.Fence`: on a request/result stream every
//! request carries a `request_id`, unique and increasing on its stream from 1, and the server
//! generation the server's hello announced on that stream ([`crate::hello::Generation`]). Every
//! result carries a [`Fence`]: that id and generation, the 0-based index of the request item it
//! answers, and the SHA-256 of that item's request bytes ([`item_hash`]).
//!
//! The client keeps the requests it has sent in [`Outstanding`] and settles a response only if
//! every fence matches one of them; the request is then forgotten, so a second copy fails. A
//! result is refused ([`FenceError`]) when it is
//!
//! - **reordered**: its position in the response is not the index of the item it answers,
//! - **duplicated**: its request was already settled,
//! - **stale**: it carries another generation than the stream's,
//! - **substituted**: its item hash, or the number of results, is not the request's,
//! - for a request never sent, or without a well-formed fence.
//!
//! Each of those is `ERROR_CODE_CONTRACT_VIOLATION`: the response is dropped, never ACCEPTed.
//! The one exception is a **late** result, for a request the client has already failed locally
//! as IGNORE at its deadline or when it replaced the stream ([`Outstanding::expire`],
//! [`Outstanding::close`]): it is dropped and counted, and is not a violation.
//!
//! Item bytes: an item is the request's i-th repeated element when the request has one result
//! per element (`VerifyBlsRequestBody.sets`), else the whole request body (`VerifyKzgRequestBody`,
//! index 0). Its bytes are its deterministic protobuf encoding, as prost encodes it (fields in
//! field-number order, defaults omitted, no unknown fields), so both sides compute the same hash
//! from the message they hold ([`FencedRequest`], [`FencedResult`]).

use std::collections::{BTreeMap, BTreeSet};

use ethswarm_proto::common::{ErrorCode, Fence as WireFence};
use ethswarm_proto::verify;
use prost::Message;
use sha2::{Digest, Sha256};

use crate::error::ContractError;
use crate::hello::Generation;

/// `common.v1.Fence.item_hash` length: a SHA-256 digest.
pub const ITEM_HASH_BYTES: usize = 32;

/// SHA-256 of one request item's bytes.
pub type ItemHash = [u8; ITEM_HASH_BYTES];

/// The hash a fence carries for an item whose request bytes are `bytes`.
#[must_use]
pub fn item_hash(bytes: &[u8]) -> ItemHash {
    Sha256::digest(bytes).into()
}

/// The hash of an item message: [`item_hash`] of its protobuf encoding.
#[must_use]
pub fn message_hash<M: Message>(item: &M) -> ItemHash {
    item_hash(&item.encode_to_vec())
}

/// What a request carries: its id on the stream and the stream's server generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestTag {
    pub request_id: u64,
    pub generation: Generation,
}

/// One result's fence: the request and item it answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fence {
    pub request_id: u64,
    pub generation: u64,
    pub index: u32,
    pub item_hash: ItemHash,
}

impl Fence {
    /// The fence of the result for item `index` of the request tagged `tag`.
    #[must_use]
    pub fn new(tag: RequestTag, index: u32, item_hash: ItemHash) -> Self {
        Self {
            request_id: tag.request_id,
            generation: tag.generation.get(),
            index,
            item_hash,
        }
    }

    /// The `common.v1.Fence` form.
    #[must_use]
    pub fn to_wire(&self) -> WireFence {
        WireFence {
            request_id: self.request_id,
            generation: self.generation,
            index: self.index,
            item_hash: self.item_hash.to_vec(),
        }
    }

    /// A received fence. A missing one, or an `item_hash` that is not 32 bytes, is malformed.
    pub fn from_wire(wire: Option<&WireFence>) -> Result<Self, FenceError> {
        let wire = wire.ok_or_else(|| FenceError::Malformed("result has no fence".into()))?;
        let item_hash = ItemHash::try_from(wire.item_hash.as_slice()).map_err(|_| {
            FenceError::Malformed(format!(
                "fence item_hash is {} bytes, not {ITEM_HASH_BYTES}",
                wire.item_hash.len()
            ))
        })?;
        Ok(Self {
            request_id: wire.request_id,
            generation: wire.generation,
            index: wire.index,
            item_hash,
        })
    }
}

/// Why a response is not settled.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FenceError {
    /// A result's position in the response is not the index of the item it answers.
    #[error("request {request_id}: result at position {position} answers item {index}")]
    Reordered {
        request_id: u64,
        position: usize,
        index: u32,
    },
    /// The request was already settled: a second copy of its results.
    #[error("request {request_id}: results already settled (duplicate)")]
    Duplicate { request_id: u64 },
    /// The results carry another generation than the stream's.
    #[error("request {request_id}: generation {got:#018x}, the stream's is {expected:#018x}")]
    StaleGeneration {
        request_id: u64,
        expected: u64,
        got: u64,
    },
    /// The results do not answer the request's items: an item hash, the result count, or the
    /// request id of one result differs.
    #[error("request {request_id}: substituted results: {detail}")]
    Substituted { request_id: u64, detail: String },
    /// No request with that id was sent on the stream.
    #[error("request {request_id} was never sent on this stream")]
    Unknown { request_id: u64 },
    /// A missing fence, a short item hash, or a response without results.
    #[error("malformed fence: {0}")]
    Malformed(String),
    /// The request already failed locally as IGNORE (deadline or replaced stream): IGNORE.
    #[error("request {request_id}: late result after the call failed as IGNORE")]
    Late { request_id: u64 },
}

impl FenceError {
    /// `ERROR_CODE_CONTRACT_VIOLATION`, or `None` for a late result (IGNORE: dropped, counted).
    #[must_use]
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Late { .. } => None,
            _ => Some(ErrorCode::ContractViolation),
        }
    }

    /// A late result: dropped and counted, not a contract violation.
    #[must_use]
    pub fn is_ignore(&self) -> bool {
        self.code().is_none()
    }

    /// The contract error to fail the stream with, if any.
    #[must_use]
    pub fn to_contract_error(&self) -> Option<ContractError> {
        self.code().map(|c| ContractError::new(c, self.to_string()))
    }
}

/// A request body that carries a fence tag and one or more items.
pub trait FencedRequest {
    /// `(request_id, generation)` as carried on the wire.
    fn wire_tag(&self) -> (u64, u64);
    /// The hash of every item, in index order.
    fn item_hashes(&self) -> Vec<ItemHash>;

    /// The fences of the results that answer this request, for the server to stamp them with.
    fn result_fences(&self) -> Vec<Fence> {
        let (request_id, generation) = self.wire_tag();
        self.item_hashes()
            .into_iter()
            .zip(0u32..)
            .map(|(item_hash, index)| Fence {
                request_id,
                generation,
                index,
                item_hash,
            })
            .collect()
    }
}

/// A response body whose results carry fences.
pub trait FencedResult {
    /// The `request_id` the body itself names.
    fn request_id(&self) -> u64;
    /// The fence of every result, in result order. A missing or malformed fence, or one that
    /// names another request than the body, is refused.
    fn fences(&self) -> Result<Vec<Fence>, FenceError>;
    /// Stamps the results with `fences` (in result order; extra fences are ignored).
    fn stamp(&mut self, fences: &[Fence]);
}

impl FencedRequest for verify::VerifyBlsRequestBody {
    fn wire_tag(&self) -> (u64, u64) {
        (self.request_id, self.generation)
    }
    fn item_hashes(&self) -> Vec<ItemHash> {
        self.sets.iter().map(message_hash).collect()
    }
}

impl FencedRequest for verify::VerifyKzgRequestBody {
    fn wire_tag(&self) -> (u64, u64) {
        (self.request_id, self.generation)
    }
    fn item_hashes(&self) -> Vec<ItemHash> {
        vec![message_hash(self)]
    }
}

/// Refuses fences that name another request than their body's `request_id`.
fn named_by(request_id: u64, fences: Vec<Fence>) -> Result<Vec<Fence>, FenceError> {
    match fences.iter().find(|f| f.request_id != request_id) {
        Some(other) => Err(FenceError::Substituted {
            request_id,
            detail: format!("a result's fence names request {}", other.request_id),
        }),
        None => Ok(fences),
    }
}

impl FencedResult for verify::VerifyBlsResponseBody {
    fn request_id(&self) -> u64 {
        self.request_id
    }
    fn fences(&self) -> Result<Vec<Fence>, FenceError> {
        let fences = self
            .results
            .iter()
            .map(|r| Fence::from_wire(r.fence.as_ref()))
            .collect::<Result<_, _>>()?;
        named_by(self.request_id, fences)
    }
    fn stamp(&mut self, fences: &[Fence]) {
        for (result, fence) in self.results.iter_mut().zip(fences) {
            result.fence = Some(fence.to_wire());
        }
    }
}

impl FencedResult for verify::VerifyKzgResponseBody {
    fn request_id(&self) -> u64 {
        self.request_id
    }
    fn fences(&self) -> Result<Vec<Fence>, FenceError> {
        named_by(
            self.request_id,
            vec![Fence::from_wire(self.fence.as_ref())?],
        )
    }
    fn stamp(&mut self, fences: &[Fence]) {
        if let Some(fence) = fences.first() {
            self.fence = Some(fence.to_wire());
        }
    }
}

/// The server's check of a received request: it must carry this stream's generation.
pub fn check_request(
    request: &impl FencedRequest,
    generation: Generation,
) -> Result<(), ContractError> {
    let (request_id, got) = request.wire_tag();
    if got == generation.get() {
        Ok(())
    } else {
        Err(ContractError::violation(format!(
            "request {request_id}: generation {got:#018x}, the stream's is {:#018x}",
            generation.get()
        )))
    }
}

/// The requests a client has sent on one stream and not yet settled.
///
/// Request ids are issued from 1, strictly increasing. Every id below the next one is
/// outstanding, expired (failed locally at its deadline, still waiting for its late result) or
/// settled. After [`Outstanding::close`] (the stream was replaced) every result is late.
#[derive(Clone, Debug)]
pub struct Outstanding {
    generation: Generation,
    capacity: usize,
    last_id: u64,
    entries: BTreeMap<u64, Vec<ItemHash>>,
    expired: BTreeSet<u64>,
    closed: bool,
    late: u64,
}

impl Outstanding {
    /// The table of a stream whose server hello announced `generation`. At most `capacity`
    /// (at least 1) requests may be outstanding or expired at once.
    #[must_use]
    pub fn new(generation: Generation, capacity: usize) -> Self {
        Self {
            generation,
            capacity: capacity.max(1),
            last_id: 0,
            entries: BTreeMap::new(),
            expired: BTreeSet::new(),
            closed: false,
            late: 0,
        }
    }

    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// Requests sent and not yet settled, expired or closed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Late results dropped so far ([`FenceError::Late`] from [`Outstanding::settle`]).
    #[must_use]
    pub fn late_dropped(&self) -> u64 {
        self.late
    }

    /// Whether the stream was replaced ([`Outstanding::close`]).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Issues the next request: `build` makes the request for its tag and returns it with the
    /// hash of each of its items. Fails with `ERROR_CODE_OVERLOADED` when `capacity` requests
    /// are pending, `ERROR_CODE_RESOURCE_UNAVAILABLE` once the stream was replaced, and
    /// `ERROR_CODE_CONTRACT_VIOLATION` for a request without items (nothing could answer it).
    pub fn issue<R>(
        &mut self,
        build: impl FnOnce(RequestTag) -> (R, Vec<ItemHash>),
    ) -> Result<(RequestTag, R), ContractError> {
        if self.closed {
            return Err(ContractError::new(
                ErrorCode::ResourceUnavailable,
                "stream was replaced; send on the new one",
            ));
        }
        if self.entries.len() + self.expired.len() >= self.capacity {
            return Err(ContractError::new(
                ErrorCode::Overloaded,
                format!("{} requests pending on the stream", self.capacity),
            ));
        }
        let request_id = self
            .last_id
            .checked_add(1)
            .ok_or_else(|| ContractError::violation("request ids exhausted on this stream"))?;
        let tag = RequestTag {
            request_id,
            generation: self.generation,
        };
        let (request, hashes) = build(tag);
        if hashes.is_empty() {
            return Err(ContractError::violation(format!(
                "request {request_id} has no items"
            )));
        }
        self.last_id = request_id;
        self.entries.insert(request_id, hashes);
        Ok((tag, request))
    }

    /// Settles the response whose results carry `fences` (in result order) and returns its
    /// request id. On an error nothing changes, except that a late result's expired entry is
    /// consumed and counted ([`Outstanding::late_dropped`]). On a closed table everything is
    /// late, whatever its fences.
    pub fn settle(&mut self, fences: &[Fence]) -> Result<u64, FenceError> {
        if self.closed {
            let request_id = fences.first().map_or(0, |f| f.request_id);
            return Err(self.late(request_id));
        }
        let first = fences
            .first()
            .ok_or_else(|| FenceError::Malformed("response has no results".into()))?;
        let request_id = first.request_id;
        if let Some(other) = fences.iter().find(|f| f.request_id != request_id) {
            return Err(FenceError::Substituted {
                request_id,
                detail: format!("a result answers request {}", other.request_id),
            });
        }
        let expected = self.generation.get();
        if let Some(stale) = fences.iter().find(|f| f.generation != expected) {
            return Err(FenceError::StaleGeneration {
                request_id,
                expected,
                got: stale.generation,
            });
        }
        let Some(hashes) = self.entries.get(&request_id) else {
            return Err(if self.expired.remove(&request_id) {
                self.late(request_id)
            } else if request_id != 0 && request_id <= self.last_id {
                FenceError::Duplicate { request_id }
            } else {
                FenceError::Unknown { request_id }
            });
        };
        if fences.len() != hashes.len() {
            return Err(FenceError::Substituted {
                request_id,
                detail: format!("{} results for {} items", fences.len(), hashes.len()),
            });
        }
        for (position, (fence, hash)) in fences.iter().zip(hashes).enumerate() {
            if usize::try_from(fence.index).ok() != Some(position) {
                return Err(FenceError::Reordered {
                    request_id,
                    position,
                    index: fence.index,
                });
            }
            if fence.item_hash != *hash {
                return Err(FenceError::Substituted {
                    request_id,
                    detail: format!("item {position} hash differs"),
                });
            }
        }
        self.entries.remove(&request_id);
        Ok(request_id)
    }

    /// [`Outstanding::settle`] for a response body: on a closed table it is late before its
    /// fences are read, so a malformed one is not a violation there.
    pub fn settle_body(&mut self, body: &impl FencedResult) -> Result<u64, FenceError> {
        if self.closed {
            return Err(self.late(body.request_id()));
        }
        self.settle(&body.fences()?)
    }

    fn late(&mut self, request_id: u64) -> FenceError {
        self.late += 1;
        FenceError::Late { request_id }
    }

    /// The request's deadline passed: it fails locally as IGNORE and its result, if one still
    /// comes, is late. `false` if it was not outstanding (settled, expired or closed already).
    pub fn expire(&mut self, request_id: u64) -> bool {
        if self.entries.remove(&request_id).is_none() {
            return false;
        }
        self.expired.insert(request_id);
        true
    }

    /// The stream was replaced (reconnect): every outstanding request fails locally as IGNORE
    /// and every result that still arrives is late. Returns the ids that failed.
    pub fn close(&mut self) -> Vec<u64> {
        self.closed = true;
        self.expired.clear();
        let ids = self.entries.keys().copied().collect();
        self.entries.clear();
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use verify::{bls_result, BlsResult, BlsSet, VerifyBlsRequestBody, VerifyBlsResponseBody};

    fn generation(g: u64) -> Generation {
        Generation::new(g).unwrap()
    }

    fn hashes(n: u8) -> Vec<ItemHash> {
        (0..n).map(|i| item_hash(&[i])).collect()
    }

    /// A table with one request of `n` items, and the fences an honest server answers with.
    fn one_request(n: u8) -> (Outstanding, Vec<Fence>) {
        let mut out = Outstanding::new(generation(9), 8);
        let (tag, ()) = out.issue(|_| ((), hashes(n))).unwrap();
        let fences = hashes(n)
            .into_iter()
            .zip(0u32..)
            .map(|(h, i)| Fence::new(tag, i, h))
            .collect();
        (out, fences)
    }

    fn violation(e: &FenceError) -> ErrorCode {
        e.to_contract_error().unwrap().code()
    }

    #[test]
    fn item_hash_is_sha256() {
        assert_eq!(
            item_hash(b"abc")[..4],
            [0xba, 0x78, 0x16, 0xbf],
            "SHA-256(\"abc\") starts ba7816bf"
        );
        let set = BlsSet {
            signing_root: vec![1; 32],
            ..Default::default()
        };
        assert_eq!(message_hash(&set), item_hash(&set.encode_to_vec()));
    }

    #[test]
    fn honest_results_settle_once() {
        let (mut out, fences) = one_request(3);
        assert_eq!(out.len(), 1);
        assert_eq!(out.settle(&fences), Ok(1));
        assert!(out.is_empty());
        assert_eq!(
            out.settle(&fences),
            Err(FenceError::Duplicate { request_id: 1 })
        );
    }

    #[test]
    fn ids_increase_from_one_with_the_stream_generation() {
        let mut out = Outstanding::new(generation(5), 8);
        assert_eq!(out.generation(), generation(5));
        let ids: Vec<u64> = (0..3)
            .map(|_| out.issue(|t| (t, hashes(1))).unwrap().0.request_id)
            .collect();
        assert_eq!(ids, [1, 2, 3]);
        let (tag, built) = out.issue(|t| (t, hashes(1))).unwrap();
        assert_eq!(tag, built, "build gets the tag the request is filed under");
        assert_eq!(tag.generation, generation(5));
    }

    #[test]
    fn reordered_results_are_refused() {
        let (mut out, mut fences) = one_request(2);
        fences.swap(0, 1);
        let err = out.settle(&fences).unwrap_err();
        assert_eq!(
            err,
            FenceError::Reordered {
                request_id: 1,
                position: 0,
                index: 1
            }
        );
        assert_eq!(violation(&err), ErrorCode::ContractViolation);
        assert_eq!(out.len(), 1, "a refused response settles nothing");
    }

    #[test]
    fn stale_generation_is_refused() {
        let (mut out, mut fences) = one_request(1);
        fences[0].generation = 8;
        let err = out.settle(&fences).unwrap_err();
        assert_eq!(
            err,
            FenceError::StaleGeneration {
                request_id: 1,
                expected: 9,
                got: 8
            }
        );
        assert_eq!(violation(&err), ErrorCode::ContractViolation);
    }

    #[test]
    fn substituted_results_are_refused() {
        let (mut out, mut fences) = one_request(2);
        fences[1].item_hash = item_hash(b"another item");
        let err = out.settle(&fences).unwrap_err();
        assert!(
            matches!(err, FenceError::Substituted { request_id: 1, .. }),
            "{err}"
        );
        assert_eq!(violation(&err), ErrorCode::ContractViolation);
        // Too few results, and a result of another request mixed in.
        let (mut out, fences) = one_request(2);
        assert!(matches!(
            out.settle(&fences[..1]),
            Err(FenceError::Substituted { .. })
        ));
        let mut mixed = fences.clone();
        mixed[1].request_id = 2;
        assert!(matches!(
            out.settle(&mixed),
            Err(FenceError::Substituted { .. })
        ));
        assert_eq!(out.settle(&fences), Ok(1));
    }

    #[test]
    fn unknown_or_empty_responses_are_refused() {
        let (mut out, mut fences) = one_request(1);
        fences[0].request_id = 7;
        let err = out.settle(&fences).unwrap_err();
        assert_eq!(err, FenceError::Unknown { request_id: 7 });
        fences[0].request_id = 0;
        assert_eq!(
            out.settle(&fences).unwrap_err(),
            FenceError::Unknown { request_id: 0 }
        );
        let empty = out.settle(&[]).unwrap_err();
        assert!(matches!(empty, FenceError::Malformed(_)));
        assert_eq!(violation(&empty), ErrorCode::ContractViolation);
    }

    #[test]
    fn expired_request_gets_one_late_result_then_duplicates() {
        let (mut out, fences) = one_request(1);
        assert!(out.expire(1));
        assert!(!out.expire(1), "already expired");
        assert!(out.is_empty());
        let late = out.settle(&fences).unwrap_err();
        assert_eq!(late, FenceError::Late { request_id: 1 });
        assert!(late.is_ignore());
        assert_eq!(late.to_contract_error(), None);
        assert_eq!(
            out.settle(&fences).unwrap_err(),
            FenceError::Duplicate { request_id: 1 }
        );
    }

    #[test]
    fn closed_table_fails_everything_and_every_result_is_late() {
        let (mut out, fences) = one_request(1);
        out.issue(|_| ((), hashes(1))).unwrap();
        assert!(out.expire(2));
        assert_eq!(out.close(), vec![1]);
        assert!(out.is_closed());
        assert!(out.is_empty());
        // Whatever it carries, a result on a replaced stream is late.
        assert_eq!(out.settle(&fences), Err(FenceError::Late { request_id: 1 }));
        let mut stale = fences.clone();
        stale[0].generation = 1;
        assert_eq!(out.settle(&stale), Err(FenceError::Late { request_id: 1 }));
        let err = out.issue(|_| ((), hashes(1))).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceUnavailable);
    }

    #[test]
    fn a_closed_table_takes_even_empty_or_mixed_responses_as_late() {
        let (mut out, fences) = one_request(2);
        out.close();
        assert!(out.settle(&[]).unwrap_err().is_ignore());
        let mut mixed = fences.clone();
        mixed[1].request_id = 2;
        assert!(out.settle(&mixed).unwrap_err().is_ignore());
        assert_eq!(out.late_dropped(), 2);
    }

    #[test]
    fn fences_must_name_the_outer_request_id() {
        let tag = RequestTag {
            request_id: 1,
            generation: generation(5),
        };
        let request = bls_request(tag, 1);
        let mut response = VerifyBlsResponseBody {
            request_id: 99,
            results: vec![BlsResult::default()],
        };
        response.stamp(&request.result_fences());
        let err = response.fences().unwrap_err();
        assert!(matches!(err, FenceError::Substituted { .. }), "{err}");
        let mut kzg = verify::VerifyKzgResponseBody {
            request_id: 99,
            ..Default::default()
        };
        kzg.stamp(&[Fence::new(tag, 0, item_hash(b"k"))]);
        assert!(matches!(kzg.fences(), Err(FenceError::Substituted { .. })));
    }

    #[test]
    fn late_results_are_counted() {
        let (mut out, fences) = one_request(1);
        out.expire(1);
        assert_eq!(out.late_dropped(), 0);
        assert!(out.settle(&fences).unwrap_err().is_ignore());
        assert_eq!(out.late_dropped(), 1);
    }

    #[test]
    fn capacity_counts_outstanding_and_expired_requests() {
        let mut out = Outstanding::new(generation(1), 2);
        out.issue(|_| ((), hashes(1))).unwrap();
        out.issue(|_| ((), hashes(1))).unwrap();
        assert_eq!(
            out.issue(|_| ((), hashes(1))).unwrap_err().code(),
            ErrorCode::Overloaded
        );
        out.expire(1);
        assert_eq!(
            out.issue(|_| ((), hashes(1))).unwrap_err().code(),
            ErrorCode::Overloaded
        );
        let mut zero = Outstanding::new(generation(1), 0);
        zero.issue(|_| ((), hashes(1))).unwrap();
    }

    #[test]
    fn a_request_without_items_is_refused() {
        let mut out = Outstanding::new(generation(1), 2);
        let err = out.issue(|_| ((), Vec::new())).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
        assert_eq!(out.issue(|t| (t, hashes(1))).unwrap().0.request_id, 1);
    }

    #[test]
    fn exhausted_ids_are_refused() {
        let mut out = Outstanding::new(generation(1), 2);
        out.last_id = u64::MAX;
        assert_eq!(
            out.issue(|_| ((), hashes(1))).unwrap_err().code(),
            ErrorCode::ContractViolation
        );
    }

    #[test]
    fn wire_fences_round_trip_and_bad_ones_are_malformed() {
        let fence = Fence::new(
            RequestTag {
                request_id: 3,
                generation: generation(4),
            },
            2,
            item_hash(b"x"),
        );
        assert_eq!(Fence::from_wire(Some(&fence.to_wire())), Ok(fence));
        assert!(matches!(
            Fence::from_wire(None),
            Err(FenceError::Malformed(_))
        ));
        let mut short = fence.to_wire();
        short.item_hash.pop();
        let err = Fence::from_wire(Some(&short)).unwrap_err();
        assert!(err.to_string().contains("31 bytes"), "{err}");
    }

    fn bls_request(tag: RequestTag, sets: usize) -> VerifyBlsRequestBody {
        VerifyBlsRequestBody {
            request_id: tag.request_id,
            generation: tag.generation.get(),
            sets: (0..sets)
                .map(|i| BlsSet {
                    signing_root: vec![u8::try_from(i).unwrap(); 32],
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn verify_bodies_carry_fences_end_to_end() {
        let mut out = Outstanding::new(generation(77), 4);
        let (tag, request) = out
            .issue(|tag| {
                let r = bls_request(tag, 3);
                let h = r.item_hashes();
                (r, h)
            })
            .unwrap();
        assert_eq!(check_request(&request, tag.generation), Ok(()));
        let mut response = VerifyBlsResponseBody {
            request_id: tag.request_id,
            results: vec![
                BlsResult {
                    result: Some(bls_result::Result::Status(1)),
                    fence: None,
                };
                3
            ],
        };
        assert!(matches!(response.fences(), Err(FenceError::Malformed(_))));
        response.stamp(&request.result_fences());
        assert_eq!(out.settle(&response.fences().unwrap()), Ok(1));

        let (ktag, kzg) = out
            .issue(|tag| {
                let r = verify::VerifyKzgRequestBody {
                    request_id: tag.request_id,
                    generation: tag.generation.get(),
                    deadline_unix_ms: 5,
                    ..Default::default()
                };
                let h = r.item_hashes();
                (r, h)
            })
            .unwrap();
        let mut reply = verify::VerifyKzgResponseBody {
            request_id: ktag.request_id,
            ..Default::default()
        };
        assert!(reply.fences().is_err());
        reply.stamp(&[]);
        assert!(reply.fence.is_none());
        reply.stamp(&kzg.result_fences());
        assert_eq!(reply.fences().unwrap()[0].index, 0);
        assert_eq!(out.settle(&reply.fences().unwrap()), Ok(2));
    }

    #[test]
    fn server_refuses_a_request_with_another_generation() {
        let tag = RequestTag {
            request_id: 1,
            generation: generation(3),
        };
        let err = check_request(&bls_request(tag, 1), generation(4)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContractViolation);
    }
}
