//! What cl-chain makes of an `engine_newPayloadV5` answer: an [`ElVerdict`] for each reply, and
//! the [`ExecutionStatuses`] of the payloads it has asked about.
//!
//! - **The map** ([`map`], execution-apis `paris.md` L99-118): `VALID` is [`ElVerdict::Valid`]
//!   only if its `latestValidHash` is the submitted payload's `block_hash` (`paris.md`, payload
//!   validation, rule 3), else [`Reason::Malformed`]; `INVALID` is [`ElVerdict::Invalid`] with
//!   `latestValidHash` as given, `null` included (the table records nothing for `null`);
//!   `INVALID_BLOCK_HASH` is [`Reason::InvalidBlockHash`], whatever its `latestValidHash`;
//!   `SYNCING` and `ACCEPTED` are [`ElVerdict::Optimistic`]. It reads one reply: two
//!   contradicting replies for one payload are the caller's to reconcile.
//! - **Fail closed.** A status this client cannot name, a reply that breaks the contract, an
//!   error from cl-engine, a failed call and a timeout are [`ElVerdict::NotVerified`], never
//!   `Valid`: [`map_json`] for the Engine API JSON, [`map_proto`] for engine.v1, where
//!   `PAYLOAD_STATUS_KIND_UNSPECIFIED` breaks the contract and an unknown value is not decoded.
//! - **The import gate** ([`ElVerdict::permits_payload_import`]): `Valid` and `Optimistic` only;
//!   [`ExecutionStatuses::permits_payload_import`] also refuses a payload or an execution parent
//!   recorded `Invalid`. This is only the EL verdict gate. It is not the envelope's signature
//!   check, its bid and beacon-block consistency, the other consensus checks, data availability,
//!   or the check that a full parent's payload is verified. Those are separate gates, specified in
//!   `gloas/fork-choice.md::{verify_execution_payload_envelope,on_execution_payload_envelope,on_block,is_payload_verified}`.
//! - **The table** ([`ExecutionStatuses`]): see its docs.

use consensus_types::primitives::Hash32;
use engine_api::{FixedData, PayloadStatusV1, ValidationStatus};
use ethswarm_proto::engine as pb;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// The EL's verdict on one payload, or why there is none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElVerdict {
    /// `VALID`.
    Valid,
    /// `INVALID`, with `latestValidHash` as the EL gave it. `INVALID_BLOCK_HASH` is not this:
    /// see [`Reason::InvalidBlockHash`].
    Invalid {
        /// `latestValidHash`: `None` when the EL sent `null`. Then the payload sent does not hash
        /// to the `block_hash` it claims, which says nothing of the payload that has this hash:
        /// [`ExecutionStatuses::record`] records nothing for it.
        latest_valid_hash: Option<Hash32>,
    },
    /// `SYNCING` or `ACCEPTED`: not verified yet, and not refuted.
    Optimistic,
    /// No verdict.
    NotVerified(Reason),
}

/// Why a call gave no verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// A status this client cannot name: a string the Engine API does not define, no status,
    /// or an engine.v1 value it does not know.
    UnknownStatus,
    /// A reply that breaks the Engine API or the engine.v1 contract: a field that does not
    /// decode, `PAYLOAD_STATUS_KIND_UNSPECIFIED`, a `latest_valid_hash` of neither 0 nor 32
    /// bytes, a `VALID` whose `latestValidHash` is not the submitted payload's `block_hash`
    /// (`null`, empty or another hash), neither a status nor an error, or another call's `seq`.
    /// Also params that would be past the 32 MiB JSON cap, which are never sent.
    Malformed,
    /// cl-engine answered an `EngineError` of this `EngineErrorKind` (its value, maybe one this
    /// client does not know): the EL is unreachable, timed out, refused the params, ...
    Engine(i32),
    /// The call failed with this gRPC status.
    Rpc(tonic::Code),
    /// No answer from cl-engine in time.
    Timeout,
    /// No connection to cl-engine.
    Connect,
    /// `INVALID_BLOCK_HASH`: the payload sent does not hash to the `block_hash` it claims. That
    /// says nothing of the payload that has this hash, which can be an honest one (a tampered
    /// envelope can claim it), so it is no verdict on it. Its `latestValidHash` does not count
    /// either: `paris.md` requires `null` with this status, and one from a faulty EL must not
    /// move a boundary. As the answer to a forkchoiceUpdated it is a protocol fault
    /// ([`ExecutionStatuses::record_head`]).
    InvalidBlockHash,
}

impl ElVerdict {
    /// Every `label`, in order.
    pub const LABELS: [&'static str; 4] = ["valid", "invalid", "optimistic", "not_verified"];

    /// Whether the EL's verdict lets the envelope be imported: on `Valid` and `Optimistic` only
    /// (`bellatrix/optimistic-sync.md`: `VALID` and `NOT_VALIDATED` import, `INVALIDATED` does
    /// not, and an engine error or no answer MUST NOT import).
    ///
    /// This is only the EL verdict gate. It does not check the envelope's signature, its
    /// consistency with the beacon block and the committed bid, the other consensus checks, data
    /// availability, or that the execution parent is fully verified. Those are separate gates:
    /// `gloas/fork-choice.md::{verify_execution_payload_envelope,on_execution_payload_envelope,on_block,is_payload_verified}`.
    /// [`ExecutionStatuses::permits_payload_import`] adds what the table knows: a payload or an
    /// execution parent recorded `Invalid` refuses the import.
    #[must_use]
    pub fn permits_payload_import(&self) -> bool {
        matches!(self, Self::Valid | Self::Optimistic)
    }

    /// The `verdict` label of `chain_new_payload_verdicts_total`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        let i = match self {
            Self::Valid => 0,
            Self::Invalid { .. } => 1,
            Self::Optimistic => 2,
            Self::NotVerified(_) => 3,
        };
        Self::LABELS[i]
    }
}

/// The verdict of one `PayloadStatusV1` for the submitted payload `block_hash`. A `VALID` must
/// carry `block_hash` as `latestValidHash`; `null` or another hash is [`Reason::Malformed`].
/// `INVALID_BLOCK_HASH` is [`Reason::InvalidBlockHash`], with any `latestValidHash`.
/// `validationError` does not change the verdict.
#[must_use]
pub fn map(status: &PayloadStatusV1, block_hash: Hash32) -> ElVerdict {
    match status.status {
        ValidationStatus::Valid => {
            if status.latest_valid_hash.map(|h| Hash32::from(h.0)) == Some(block_hash) {
                ElVerdict::Valid
            } else {
                ElVerdict::NotVerified(Reason::Malformed)
            }
        }
        ValidationStatus::Invalid => ElVerdict::Invalid {
            latest_valid_hash: status.latest_valid_hash.map(|h| Hash32::from(h.0)),
        },
        ValidationStatus::InvalidBlockHash => ElVerdict::NotVerified(Reason::InvalidBlockHash),
        ValidationStatus::Syncing | ValidationStatus::Accepted => ElVerdict::Optimistic,
    }
}

/// The verdict of a `PayloadStatusV1` as JSON, for the submitted payload `block_hash` (see
/// [`map`]). JSON that does not decode is [`Reason::UnknownStatus`] unless its `status` is one
/// the Engine API defines, then [`Reason::Malformed`].
#[must_use]
pub fn map_json(json: &[u8], block_hash: Hash32) -> ElVerdict {
    if let Ok(status) = serde_json::from_slice::<PayloadStatusV1>(json) {
        return map(&status, block_hash);
    }
    let known = serde_json::from_slice::<serde_json::Value>(json)
        .ok()
        .and_then(|mut value| value.get_mut("status").map(serde_json::Value::take))
        .is_some_and(|status| serde_json::from_value::<ValidationStatus>(status).is_ok());
    ElVerdict::NotVerified(if known {
        Reason::Malformed
    } else {
        Reason::UnknownStatus
    })
}

/// The verdict of an engine.v1 `PayloadStatus`, for the submitted payload `block_hash` (see
/// [`map`]). An empty `latest_valid_hash` is `null`.
#[must_use]
pub fn map_proto(status: &pb::PayloadStatus, block_hash: Hash32) -> ElVerdict {
    use pb::PayloadStatusKind as Kind;
    let kind = match Kind::try_from(status.status) {
        Ok(Kind::Valid) => ValidationStatus::Valid,
        Ok(Kind::Invalid) => ValidationStatus::Invalid,
        Ok(Kind::Syncing) => ValidationStatus::Syncing,
        Ok(Kind::Accepted) => ValidationStatus::Accepted,
        Ok(Kind::InvalidBlockHash) => ValidationStatus::InvalidBlockHash,
        Ok(Kind::Unspecified) => return ElVerdict::NotVerified(Reason::Malformed),
        Err(_) => return ElVerdict::NotVerified(Reason::UnknownStatus),
    };
    let latest_valid_hash = match status.latest_valid_hash.as_slice() {
        [] => None,
        bytes => match <[u8; 32]>::try_from(bytes) {
            Ok(hash) => Some(FixedData(hash)),
            Err(_) => return ElVerdict::NotVerified(Reason::Malformed),
        },
    };
    map(
        &PayloadStatusV1 {
            status: kind,
            latest_valid_hash,
            validation_error: None,
        },
        block_hash,
    )
}

/// What cl-chain knows of one execution payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// The EL answered `VALID`, for it or a descendant, or named it as the `latestValidHash` of
    /// an `INVALID`.
    Valid,
    /// Imported on `SYNCING` or `ACCEPTED`, and not `VALID` or `INVALID` yet.
    Optimistic,
    /// The EL answered `INVALID` with a `latestValidHash` for it, or it is in the invalid part of
    /// the chain of such an answer, or it descends from an `Invalid` payload. `INVALID` with a
    /// `null` `latestValidHash` and `INVALID_BLOCK_HASH` never make a payload `Invalid`
    /// ([`Reason::InvalidBlockHash`]).
    Invalid,
}

/// Most `Invalid` payloads [`ExecutionStatuses`] keeps a full entry for: 128 epochs at one per
/// slot. Past it, the payload that became `Invalid` first loses its entry first, and only its
/// hash, parent hash and a boundary it waits for stay. It stays `Invalid` until
/// [`ExecutionStatuses::prune_finalized`] drops it: a later `VALID` or `SYNCING` must not bring
/// an `INVALID` payload back.
pub const MAX_INVALID_PAYLOADS: usize = 4096;

/// One payload's status, as the table holds it.
#[derive(Clone, Copy, Debug)]
enum State {
    Valid,
    Optimistic,
    Invalid {
        /// When it became `Invalid`, in [`ExecutionStatuses::invalid`] order.
        order: u64,
        /// The `latestValidHash` of its `INVALID`, while the boundary waits for a missing
        /// payload: one between the two, or the `latestValidHash` payload itself.
        pending: Option<Hash32>,
    },
}

impl State {
    fn status(self) -> ExecutionStatus {
        match self {
            Self::Valid => ExecutionStatus::Valid,
            Self::Optimistic => ExecutionStatus::Optimistic,
            Self::Invalid { .. } => ExecutionStatus::Invalid,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    state: State,
    parent_hash: Hash32,
}

/// How a walk up from an `INVALID` payload towards its `latestValidHash` ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Walk {
    /// The next hash up is the `latestValidHash`.
    Found,
    /// A payload the walk passed before: the boundary is not in this chain.
    Stopped,
    /// A payload that is not recorded (yet).
    Missing,
}

/// The [`ExecutionStatus`] of each payload cl-chain has a verdict for, by its `block_hash`,
/// with its `parent_hash`. The chain core keeps one and gates block and envelope import on it;
/// it will also give `execution_optimistic` and the confirmed and safe hashes. The rules are
/// those of consensus-specs v1.7.0-beta.4, `specs/bellatrix/optimistic-sync.md`. A payload
/// moves only from `Optimistic` (`NOT_VALIDATED`) to `Valid` or to `Invalid` ("How to
/// optimistically import blocks"). The spec leaves out `Valid` to `Invalid` and `Invalid` to
/// `Valid` ("Transitioning from VALID -> INVALIDATED or INVALIDATED -> VALID"): only a faulty EL
/// asks for them, and they need manual intervention. So the table keeps both as they are and
/// records the contradiction ([`ExecutionStatuses::el_contradiction`]).
///
/// - `Valid` makes the payload `Valid`, and every ancestor still `Optimistic` too, walking the
///   recorded parent hashes up to the first ancestor that is not recorded or not `Optimistic`.
///   An `Invalid` payload, or an `Invalid` ancestor on that walk, stays `Invalid`: an EL
///   contradiction.
/// - `Optimistic` makes a payload with no status `Optimistic`, and leaves `Valid` alone.
/// - `Invalid` with a `latestValidHash` makes the payload and every recorded `Optimistic`
///   descendant `Invalid`. A `Valid` one stays `Valid`: an EL contradiction. `INVALID` is final
///   (`paris.md` L114): a later `Valid` or `Optimistic` leaves it `Invalid`. A payload recorded
///   on an `Invalid` one is `Invalid` whatever its verdict: its parent MUST NOT be `INVALIDATED`.
/// - `Invalid` with a `null` `latestValidHash` records nothing and sets no EL contradiction,
///   like `NotVerified` below. The Engine API gives it for a payload that does not hash to the
///   `block_hash` it claims (`shanghai.md`, from `engine_newPayloadV2`), and a tampered envelope
///   can claim the hash of an honest payload. The import gate still refuses that envelope.
/// - The `latestValidHash` of an `Invalid` sets a boundary ("How to apply `latestValidHash`
///   when payload status is `INVALID`"). The walk goes up every recorded ancestor: an `Invalid`
///   one (an earlier walk of the same boundary, or evicted) does not hide a boundary above it,
///   and a `Valid` one only makes the boundary an EL contradiction. For a hash, if the next hash
///   up is the `latestValidHash`, the topmost payload of the walk is `invalidBlock`: it and its
///   descendants become `Invalid` as above, and the `latestValidHash` payload and its
///   `Optimistic` ancestors become `Valid`. For the zero hash, `invalidBlock` is the first
///   execution payload of the chain, and the table knows none above the topmost of the walk, so
///   that one is. For a hash the walk does not find, only the payload is. A walk that stops at a
///   payload that is not recorded waits for it, and so does a `latestValidHash` payload that is
///   not recorded yet.
/// - A payload recorded after its children links up with them: a `Valid` child makes it `Valid`
///   (with its `Optimistic` ancestors), an `Invalid` one passes `Invalid` down to them, and a
///   boundary below it that waited for it is applied again.
/// - Finality makes the finalized payload of the last [`ExecutionStatuses::prune_finalized`] (the
///   `finalizedBlockHash`) and its ancestors valid. A `latestValidHash` equal to that payload is
///   the ordinary boundary above. An `INVALID` for that payload is an EL contradiction, and so is
///   a walk that reaches it before the boundary: a `latestValidHash` strictly below it, or the
///   zero hash. The zero hash finalizes no payload.
/// - `NotVerified` records nothing: a payload without a status stays without one, and an
///   earlier status stays as it is.
///
/// [`ExecutionStatuses::prune_finalized`] drops what finality makes useless, and at most
/// [`MAX_INVALID_PAYLOADS`] `Invalid` payloads keep a full entry.
#[derive(Debug, Default)]
pub struct ExecutionStatuses {
    blocks: HashMap<Hash32, Entry>,
    /// The recorded payloads on each parent hash, recorded or not, in the order they came. An
    /// evicted payload stays here, so that the walks down and finality still reach it.
    children: HashMap<Hash32, Vec<Hash32>>,
    /// The `Invalid` payloads with a full entry by the order they became `Invalid`: the first
    /// goes first.
    invalid: BTreeMap<u64, Hash32>,
    /// The order the next `Invalid` payload takes.
    next_order: u64,
    /// The `Invalid` payloads that lost their full entry to [`MAX_INVALID_PAYLOADS`]: what stays
    /// of it is their parent hash and a boundary they wait for.
    evicted: HashMap<Hash32, Entry>,
    /// The payload of the last [`ExecutionStatuses::prune_finalized`], `None` for the zero hash.
    finalized: Option<Hash32>,
    /// See [`ExecutionStatuses::el_contradiction`].
    contradiction: bool,
}

impl ExecutionStatuses {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `verdict` for the payload `block_hash` whose parent is `parent_hash` (see the
    /// type docs), and returns the payload's status after it. `NotVerified` and `INVALID` with a
    /// `null` `latestValidHash` record nothing: they return the status the payload already had.
    pub fn record(
        &mut self,
        block_hash: Hash32,
        parent_hash: Hash32,
        verdict: &ElVerdict,
    ) -> Option<ExecutionStatus> {
        if let ElVerdict::NotVerified(_)
        | ElVerdict::Invalid {
            latest_valid_hash: None,
        } = verdict
        {
            return self.status(&block_hash);
        }
        let new = self.get(&block_hash).is_none();
        if new {
            self.blocks.insert(
                block_hash,
                Entry {
                    state: State::Optimistic,
                    parent_hash,
                },
            );
            self.children
                .entry(parent_hash)
                .or_default()
                .push(block_hash);
            // A payload on an Invalid parent is Invalid. This comes before the verdict, so that
            // a VALID cannot make it Valid first: Valid never turns Invalid.
            if self.status(&parent_hash) == Some(ExecutionStatus::Invalid) {
                self.invalidate(block_hash);
            }
        }
        match verdict {
            ElVerdict::Valid => self.make_valid(block_hash),
            ElVerdict::Invalid {
                latest_valid_hash: Some(boundary),
            } => {
                self.invalidate(block_hash);
                self.apply_boundary(block_hash, *boundary);
            }
            ElVerdict::Invalid {
                latest_valid_hash: None,
            }
            | ElVerdict::Optimistic
            | ElVerdict::NotVerified(_) => {}
        }
        if new {
            self.link(block_hash);
        }
        self.evict_past_bound();
        self.status(&block_hash)
    }

    /// [`Self::record`] for `verdict`, the answer to a forkchoiceUpdated with the head `head`,
    /// with the parent hash the table has for it. A head without one records nothing, but an
    /// `INVALID` with a `latestValidHash` for the finalized payload is an EL contradiction.
    /// [`Reason::InvalidBlockHash`] is a newPayload status that a forkchoiceUpdated must not
    /// answer: a protocol fault, so an EL contradiction, and it records nothing for `head`.
    pub fn record_head(&mut self, head: Hash32, verdict: &ElVerdict) -> Option<ExecutionStatus> {
        if *verdict == ElVerdict::NotVerified(Reason::InvalidBlockHash) {
            self.contradiction = true;
            return self.status(&head);
        }
        if let Some((_, parent)) = self.get(&head) {
            return self.record(head, parent, verdict);
        }
        if let ElVerdict::Invalid {
            latest_valid_hash: Some(_),
        } = verdict
        {
            self.contradiction |= self.finalized == Some(head);
        }
        None
    }

    /// The status of the payload `block_hash`, `None` if it has none.
    #[must_use]
    pub fn status(&self, block_hash: &Hash32) -> Option<ExecutionStatus> {
        self.get(block_hash).map(|(status, _)| status)
    }

    /// The table's import gate: [`ElVerdict::permits_payload_import`], and neither the payload
    /// `block_hash` nor its execution parent `parent_hash` is recorded `Invalid`
    /// (`bellatrix/optimistic-sync.md`: the parent MUST NOT have an `INVALIDATED` payload). An
    /// execution parent with no status does not refuse it. Like the verdict's gate, this is only
    /// the EL verdict gate, not the rest of the envelope's verification.
    #[must_use]
    pub fn permits_payload_import(
        &self,
        block_hash: &Hash32,
        parent_hash: &Hash32,
        verdict: &ElVerdict,
    ) -> bool {
        let invalid = |hash| self.status(hash) == Some(ExecutionStatus::Invalid);
        verdict.permits_payload_import() && !invalid(block_hash) && !invalid(parent_hash)
    }

    /// Drops what finality at the payload `finalized` makes useless: `finalized` and every
    /// recorded ancestor of it, and every payload that descends from one of those ancestors but
    /// not from `finalized` (a fork that can no longer become canonical). Keeps the descendants
    /// of `finalized` and the payloads whose ancestry is not recorded. An evicted `Invalid`
    /// payload counts as recorded. Returns how many payloads it dropped: none if `finalized` is
    /// not recorded.
    ///
    /// The walk up ends at a parent hash with no entry, usually the payload an earlier prune
    /// finalized. That payload is an ancestor of `finalized` too, and `children` keeps its
    /// children after its entry is gone, so it anchors the forks off it: none of them leaks
    /// past a later finality. `finalized` stays the finalized payload of the contradiction
    /// check (see the type docs), also if it is not recorded.
    pub fn prune_finalized(&mut self, finalized: &Hash32) -> usize {
        self.finalized = (*finalized != Hash32::ZERO).then_some(*finalized);
        let mut seen = HashSet::new();
        let mut doomed = Vec::new();
        let mut at = *finalized;
        while let Some((_, parent)) = self.get(&at) {
            if !seen.insert(at) {
                break;
            }
            doomed.push(at);
            at = parent;
        }
        if doomed.is_empty() {
            // Nothing tells which children of `finalized` it is not an ancestor of.
            return 0;
        }
        // The forks off the ancestors and off `at`; the chain itself is already in `seen`.
        let mut forks: VecDeque<Hash32> = doomed
            .iter()
            .skip(1)
            .chain([&at])
            .filter_map(|ancestor| self.children.get(ancestor))
            .flatten()
            .copied()
            .collect();
        while let Some(hash) = forks.pop_front() {
            if !seen.insert(hash) {
                continue;
            }
            doomed.push(hash);
            if let Some(children) = self.children.get(&hash) {
                forks.extend(children.iter().copied());
            }
        }
        for hash in &doomed {
            self.remove(hash);
        }
        doomed.len()
    }

    /// Whether the EL has contradicted itself since the table was made: it called a `Valid`
    /// payload invalid (an `INVALID` for it, or a boundary or a descendant cascade that reaches
    /// it), a finalized one invalid (see the type docs), or an `Invalid` payload valid (a `VALID`
    /// for it or a descendant, or a `latestValidHash` that names it), or it answered a
    /// forkchoiceUpdated with `INVALID_BLOCK_HASH` ([`Self::record_head`]). The statuses stay as
    /// they were (see the type docs). It stays `true`: the spec asks for manual intervention, and
    /// how cl-chain reacts is the caller's to decide.
    #[must_use]
    pub fn el_contradiction(&self) -> bool {
        self.contradiction
    }

    /// How many payloads have a full entry: an evicted `Invalid` payload (see
    /// [`MAX_INVALID_PAYLOADS`]) has a status but does not count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether no payload has a full entry (see [`Self::len`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The status and parent hash of the payload `hash`. An evicted payload is `Invalid`.
    fn get(&self, hash: &Hash32) -> Option<(ExecutionStatus, Hash32)> {
        self.entry(hash)
            .map(|entry| (entry.state.status(), entry.parent_hash))
    }

    /// The entry of the payload `hash`, evicted or not.
    fn entry(&self, hash: &Hash32) -> Option<&Entry> {
        self.blocks.get(hash).or_else(|| self.evicted.get(hash))
    }

    /// `hash` and every `Optimistic` ancestor become `Valid`. An `Invalid` one on the way,
    /// `hash` included, stays `Invalid` and ends the walk: an EL contradiction.
    fn make_valid(&mut self, hash: Hash32) {
        let mut at = hash;
        let mut first = true;
        // After the first step, each step turns one Optimistic entry Valid, so the walk ends,
        // also on a parent hash loop.
        while let Some((status, parent)) = self.get(&at) {
            match status {
                ExecutionStatus::Invalid => {
                    self.contradiction = true;
                    return;
                }
                ExecutionStatus::Valid if !first => return,
                ExecutionStatus::Valid | ExecutionStatus::Optimistic => {}
            }
            if let Some(entry) = self.blocks.get_mut(&at) {
                entry.state = State::Valid;
            }
            first = false;
            at = parent;
        }
    }

    /// `hash` and every recorded descendant that is `Optimistic` become `Invalid`. A `Valid` one
    /// stays `Valid` (an EL contradiction), and the walk goes on below it and below an `Invalid`
    /// one: the spec moves every `NOT_VALIDATED` descendant.
    fn invalidate(&mut self, hash: Hash32) {
        let mut seen = HashSet::new();
        let mut queue = VecDeque::from([hash]);
        while let Some(at) = queue.pop_front() {
            if !seen.insert(at) {
                continue;
            }
            match self.status(&at) {
                None => continue,
                Some(ExecutionStatus::Valid) => self.contradiction = true,
                Some(ExecutionStatus::Invalid) => {}
                Some(ExecutionStatus::Optimistic) => {
                    if let Some(entry) = self.blocks.get_mut(&at) {
                        entry.state = State::Invalid {
                            order: self.next_order,
                            pending: None,
                        };
                        self.invalid.insert(self.next_order, at);
                        self.next_order += 1;
                    }
                }
            }
            if let Some(children) = self.children.get(&at) {
                queue.extend(children.iter().copied());
            }
        }
    }

    /// Applies `boundary`, the `latestValidHash` of an `INVALID` for the payload `hash` (see the
    /// type docs).
    fn apply_boundary(&mut self, hash: Hash32, boundary: Hash32) {
        let Some((_, mut at)) = self.get(&hash) else {
            return;
        };
        // An INVALID for the finalized payload, whatever its boundary.
        if self.finalized == Some(hash) {
            self.contradiction = true;
            return;
        }
        let zero = boundary == Hash32::ZERO;
        // The topmost recorded ancestor the walk passed: `invalidBlock` when the walk finds the
        // boundary, and for the zero hash.
        let mut top = None;
        let mut seen = HashSet::new();
        let end = loop {
            // The boundary first: one at the finalized payload is honest.
            if !zero && at == boundary {
                break Walk::Found;
            }
            if self.finalized == Some(at) {
                self.contradiction = true;
                return;
            }
            match self.get(&at) {
                Some((_, parent)) if seen.insert(at) => {
                    top = Some(at);
                    at = parent;
                }
                Some(_) => break Walk::Stopped,
                None => break Walk::Missing,
            }
        };
        if zero || end == Walk::Found {
            // The rest of the walk descends from it.
            if let Some(top) = top {
                self.invalidate(top);
            }
        }
        if end == Walk::Found {
            self.make_valid(boundary);
        }
        // The boundary waits for a payload that is not recorded: the one that ended the walk, or
        // the `latestValidHash` payload, which becomes Valid when it is recorded.
        let waits = match end {
            Walk::Missing => true,
            Walk::Found => self.get(&boundary).is_none(),
            Walk::Stopped => false,
        };
        if let Some(Entry {
            state: State::Invalid { pending, .. },
            ..
        }) = self
            .blocks
            .get_mut(&hash)
            .or_else(|| self.evicted.get_mut(&hash))
        {
            *pending = waits.then_some(boundary);
        }
    }

    /// Links the payload `hash`, recorded for the first time, with what was recorded before
    /// it: its children, and the boundaries below it that waited for it. `record` has applied
    /// an `Invalid` parent already.
    fn link(&mut self, hash: Hash32) {
        let Some(children) = self.children.get(&hash) else {
            return;
        };
        if children
            .iter()
            .any(|child| self.status(child) == Some(ExecutionStatus::Valid))
        {
            self.make_valid(hash);
        }
        for (waiting, boundary) in self.waiting_below(hash) {
            self.apply_boundary(waiting, boundary);
        }
    }

    /// The `Invalid` payloads below `hash` whose boundary waits, with that boundary.
    fn waiting_below(&self, hash: Hash32) -> Vec<(Hash32, Hash32)> {
        let mut waiting = Vec::new();
        let mut seen = HashSet::from([hash]);
        let mut queue = VecDeque::from([hash]);
        while let Some(at) = queue.pop_front() {
            for &child in self.children.get(&at).into_iter().flatten() {
                if !seen.insert(child) {
                    continue;
                }
                if let Some(Entry {
                    state:
                        State::Invalid {
                            pending: Some(boundary),
                            ..
                        },
                    ..
                }) = self.entry(&child)
                {
                    waiting.push((child, *boundary));
                }
                queue.push_back(child);
            }
        }
        waiting
    }

    /// Evicts the oldest `Invalid` payloads past [`MAX_INVALID_PAYLOADS`]: each keeps only its
    /// hash, parent hash and pending boundary, and stays in `children`.
    fn evict_past_bound(&mut self) {
        while self.invalid.len() > MAX_INVALID_PAYLOADS {
            let Some((_, hash)) = self.invalid.pop_first() else {
                break;
            };
            if let Some(entry) = self.blocks.remove(&hash) {
                self.evicted.insert(hash, entry);
            }
        }
    }

    /// Drops the payload `hash`, evicted or not, from the table and its indexes. Its children
    /// keep their status.
    fn remove(&mut self, hash: &Hash32) {
        let parent_hash = if let Some(entry) = self.blocks.remove(hash) {
            if let State::Invalid { order, .. } = entry.state {
                self.invalid.remove(&order);
            }
            entry.parent_hash
        } else if let Some(entry) = self.evicted.remove(hash) {
            entry.parent_hash
        } else {
            return;
        };
        if let Some(siblings) = self.children.get_mut(&parent_hash) {
            siblings.retain(|child| child != hash);
            if siblings.is_empty() {
                self.children.remove(&parent_hash);
            }
        }
    }
}
