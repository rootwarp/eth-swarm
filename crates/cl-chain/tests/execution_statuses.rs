//! The [`ExecutionStatuses`] table on its own, without a client: the `latestValidHash` boundary of
//! an INVALID verdict, invalid descendants, a payload recorded before its parent, the import gate
//! of the table, pruning at finality, the bound on retained Invalid payloads, INVALID_BLOCK_HASH,
//! INVALID with a `null` `latestValidHash`, and the EL contradictions.
//!
//! The rules come from consensus-specs v1.7.0-beta.4, `specs/bellatrix/optimistic-sync.md`: "How
//! to apply `latestValidHash` when payload status is `INVALID`", "How to optimistically import
//! blocks" and "Transitioning from VALID -> INVALIDATED or INVALIDATED -> VALID". A payload is
//! `hash(n)`, and `chain` records each `(n, parent, verdict)` in order.

use cl_chain::engine::verdict::{
    self, ElVerdict, ExecutionStatus, ExecutionStatuses, Reason, MAX_INVALID_PAYLOADS,
};
use consensus_types::primitives::Hash32;
use engine_api::{FixedData, PayloadStatusV1, ValidationStatus};

use ExecutionStatus::{Invalid, Optimistic, Valid};

fn hash(n: u8) -> Hash32 {
    Hash32::repeat_byte(n)
}

fn invalid(latest_valid_hash: Option<Hash32>) -> ElVerdict {
    ElVerdict::Invalid { latest_valid_hash }
}

/// Records each `(n, parent, verdict)` in order.
fn chain(statuses: &mut ExecutionStatuses, entries: &[(u8, u8, ElVerdict)]) {
    for (n, parent, verdict) in entries {
        statuses.record(hash(*n), hash(*parent), verdict);
    }
}

/// The status of each `hash(n)`.
fn statuses_of<const N: usize>(
    statuses: &ExecutionStatuses,
    ns: [u8; N],
) -> [Option<ExecutionStatus>; N] {
    ns.map(|n| statuses.status(&hash(n)))
}

const OPT: ElVerdict = ElVerdict::Optimistic;
const VALID: ElVerdict = ElVerdict::Valid;

/// The verdict of an Engine API reply with `status` and `latest_valid_hash` for the payload
/// `block_hash`.
fn reply(
    status: ValidationStatus,
    latest_valid_hash: Option<Hash32>,
    block_hash: Hash32,
) -> ElVerdict {
    let reply = PayloadStatusV1 {
        status,
        latest_valid_hash: latest_valid_hash.map(|h| FixedData(h.0)),
        validation_error: None,
    };
    verdict::map(&reply, block_hash)
}

/// INVALID for 5 with `latestValidHash` 2: the invalid block is 3, the child of 2 in the chain
/// of 5. 3, 4 and 5 become Invalid, and so do the other descendants of 3 (6 on 3, 7 on 5). 2 is
/// the latest valid payload, so it becomes Valid. 1 stays Valid.
#[test]
fn invalid_applies_the_latest_valid_hash_boundary() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[
            (1, 0, VALID),
            (2, 1, OPT),
            (3, 2, OPT),
            (4, 3, OPT),
            (5, 4, OPT),
            (6, 3, OPT),
            (7, 5, OPT),
        ],
    );
    assert_eq!(
        statuses.record(hash(5), hash(4), &invalid(Some(hash(2)))),
        Some(Invalid)
    );
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3, 4, 5, 6, 7]),
        [
            Some(Valid),
            Some(Valid),
            Some(Invalid),
            Some(Invalid),
            Some(Invalid),
            Some(Invalid),
            Some(Invalid)
        ]
    );
}

/// INVALID for 3 with `latestValidHash` 2, its parent: 3 and every recorded descendant become
/// Invalid, and 2 becomes Valid. 1 stays Valid.
#[test]
fn invalid_invalidates_the_payload_and_its_descendants() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[
            (1, 0, VALID),
            (2, 1, OPT),
            (3, 2, OPT),
            (4, 3, OPT),
            (5, 3, OPT),
            (6, 4, OPT),
        ],
    );
    statuses.record(hash(3), hash(2), &invalid(Some(hash(2))));
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3, 4, 5, 6]),
        [
            Some(Valid),
            Some(Valid),
            Some(Invalid),
            Some(Invalid),
            Some(Invalid),
            Some(Invalid)
        ],
        "each descendant of an Invalid payload must be Invalid"
    );
}

/// INVALID with the all-zero `latestValidHash`: `invalidBlock` is the first execution payload of
/// the chain, so every Optimistic ancestor must become Invalid too. The Valid payload 1 must stay
/// Valid, and the table must report the EL contradiction: the EL calls 1 invalid now.
#[test]
fn invalid_with_the_zero_hash_invalidates_the_optimistic_run() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(1, 0, VALID), (2, 1, OPT), (3, 2, OPT), (4, 3, OPT)],
    );
    statuses.record(hash(4), hash(3), &invalid(Some(Hash32::ZERO)));
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3, 4]),
        [Some(Valid), Some(Invalid), Some(Invalid), Some(Invalid)]
    );
    assert!(statuses.el_contradiction());
}

/// A `latestValidHash` that is not in the chain of the payload invalidates only the payload (and
/// its descendants). A recorded payload on another branch is not made Valid. This is no EL
/// contradiction.
#[test]
fn a_latest_valid_hash_outside_the_chain_invalidates_only_the_payload() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(1, 0, VALID), (2, 1, OPT), (3, 2, OPT), (9, 8, OPT)],
    );
    // 9 is recorded, but on another branch.
    statuses.record(hash(3), hash(2), &invalid(Some(hash(9))));
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3, 9]),
        [
            Some(Valid),
            Some(Optimistic),
            Some(Invalid),
            Some(Optimistic)
        ]
    );
    assert!(!statuses.el_contradiction());
}

/// A payload recorded on an Invalid execution parent is Invalid, whatever its own verdict, and
/// so is a payload recorded later on that one.
#[test]
fn a_payload_on_an_invalid_parent_is_invalid() {
    let mut statuses = ExecutionStatuses::new();
    statuses.record(hash(2), hash(1), &invalid(Some(hash(1))));
    for (n, parent, verdict) in [(3, 2, OPT), (4, 2, VALID), (5, 3, OPT)] {
        assert_eq!(
            statuses.record(hash(n), hash(parent), &verdict),
            Some(Invalid),
            "{n} on {parent} with {verdict:?}"
        );
    }
    // INVALID stays: a later VALID or SYNCING does not undo it.
    for later in [VALID, OPT] {
        assert_eq!(statuses.record(hash(3), hash(2), &later), Some(Invalid));
    }
}

/// A child recorded Valid before its parent: when the parent is recorded Optimistic, it becomes
/// Valid at once, and so does an Optimistic ancestor recorded after it.
#[test]
fn a_parent_recorded_after_a_valid_child_becomes_valid() {
    let mut statuses = ExecutionStatuses::new();
    statuses.record(hash(3), hash(2), &VALID);
    assert_eq!(statuses.record(hash(2), hash(1), &OPT), Some(Valid));
    assert_eq!(statuses.record(hash(1), hash(0), &OPT), Some(Valid));
    assert_eq!(statuses_of(&statuses, [1, 2, 3]), [Some(Valid); 3]);
}

/// Children recorded before their parent: when the parent is recorded Invalid, or on an
/// Invalid parent, the children and their descendants become Invalid.
#[test]
fn a_parent_recorded_after_its_children_passes_on_invalid() {
    let mut statuses = ExecutionStatuses::new();
    // 13 and 14 wait for 12.
    chain(
        &mut statuses,
        &[(13, 12, OPT), (14, 13, OPT), (15, 13, OPT)],
    );
    statuses.record(hash(12), hash(11), &invalid(Some(hash(11))));
    assert_eq!(statuses_of(&statuses, [12, 13, 14, 15]), [Some(Invalid); 4]);

    // 23 waits for 22, which comes on the Invalid 21.
    chain(
        &mut statuses,
        &[(21, 20, invalid(Some(hash(20)))), (23, 22, OPT)],
    );
    assert_eq!(statuses.record(hash(22), hash(21), &OPT), Some(Invalid));
    assert_eq!(statuses_of(&statuses, [21, 22, 23]), [Some(Invalid); 3]);
}

/// INVALID for 33 with `latestValidHash` 31, while 32 is missing: the boundary is not found, so
/// only 33 is Invalid. When 32 is recorded, the boundary is found: 32 is the child of 31, so it
/// is Invalid, and 31 is Valid. A later child of 32 is Invalid.
#[test]
fn a_late_parent_completes_the_latest_valid_hash_boundary() {
    let mut statuses = ExecutionStatuses::new();
    chain(&mut statuses, &[(31, 30, OPT), (33, 32, OPT)]);
    statuses.record(hash(33), hash(32), &invalid(Some(hash(31))));
    assert_eq!(
        statuses_of(&statuses, [31, 32, 33]),
        [Some(Optimistic), None, Some(Invalid)]
    );
    assert_eq!(statuses.record(hash(32), hash(31), &OPT), Some(Invalid));
    assert_eq!(
        statuses_of(&statuses, [31, 32, 33]),
        [Some(Valid), Some(Invalid), Some(Invalid)]
    );
    assert_eq!(statuses.record(hash(34), hash(32), &OPT), Some(Invalid));
}

/// The boundary of 43 (`latestValidHash` 40) needs two missing payloads, 42 and then 41. Only
/// when both are recorded is it found: 41 and 42 become Invalid and 40 Valid.
#[test]
fn a_boundary_two_payloads_up_waits_for_both() {
    let mut statuses = ExecutionStatuses::new();
    chain(&mut statuses, &[(40, 39, OPT), (43, 42, OPT)]);
    statuses.record(hash(43), hash(42), &invalid(Some(hash(40))));
    assert_eq!(statuses.record(hash(42), hash(41), &OPT), Some(Optimistic));
    assert_eq!(
        statuses_of(&statuses, [40, 41, 42, 43]),
        [Some(Optimistic), None, Some(Optimistic), Some(Invalid)]
    );
    assert_eq!(statuses.record(hash(41), hash(40), &OPT), Some(Invalid));
    assert_eq!(
        statuses_of(&statuses, [40, 41, 42, 43]),
        [Some(Valid), Some(Invalid), Some(Invalid), Some(Invalid)]
    );
}

/// INVALID for 3 on 2 with the all-zero `latestValidHash`. The ancestors arrive after it: 2 on 1,
/// then 1 on the missing 9, then 4 on 1. Each ancestor of 3 is in the chain of 3, so it must
/// become Invalid. 4 is on the Invalid 1, so it must become Invalid too. The table must refuse an
/// import of 4 on 1.
#[test]
fn a_zero_latest_valid_hash_invalidates_ancestors_recorded_later() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[
            (3, 2, invalid(Some(Hash32::ZERO))),
            (2, 1, OPT),
            (1, 9, OPT),
            (4, 1, OPT),
        ],
    );
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3, 4]),
        [Some(Invalid); 4],
        "1, 2, 3 and 4 must be Invalid"
    );
    for verdict in [OPT, VALID] {
        assert!(
            !statuses.permits_payload_import(&hash(4), &hash(1), &verdict),
            "the table must refuse 4 on 1 with {verdict:?}"
        );
    }
}

/// INVALID for 3 on 2 with the all-zero `latestValidHash`, while 9 is missing. 1 is on 9, 2 and 4
/// are on 1, and 5 is on 9. The walk up makes 2 and 1 Invalid, and 4 too. When 9 arrives, the
/// boundary applies again. The walk must step over 2 and 1, which are Invalid already. Thus 9
/// and its other child 5 must become Invalid. The boundary continues to wait, so 8 must become
/// Invalid when it arrives.
#[test]
fn a_zero_latest_valid_hash_steps_over_ancestors_that_are_invalid_already() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[
            (1, 9, OPT),
            (2, 1, OPT),
            (4, 1, OPT),
            (5, 9, OPT),
            (3, 2, invalid(Some(Hash32::ZERO))),
        ],
    );
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3, 4, 5]),
        [
            Some(Invalid),
            Some(Invalid),
            Some(Invalid),
            Some(Invalid),
            Some(Optimistic)
        ]
    );
    assert_eq!(
        statuses.record(hash(9), hash(8), &OPT),
        Some(Invalid),
        "9 must be Invalid"
    );
    assert_eq!(
        statuses_of(&statuses, [5, 9]),
        [Some(Invalid); 2],
        "9 and 5 must be Invalid"
    );
    assert!(!statuses.permits_payload_import(&hash(6), &hash(9), &OPT));
    assert_eq!(
        statuses.record(hash(8), hash(7), &OPT),
        Some(Invalid),
        "8 must be Invalid"
    );
}

/// INVALID for 3 on 2 with `latestValidHash` 2, while 2 is missing. The boundary must wait for
/// 2. When 2 arrives, it must become Valid, and its Optimistic parent 1 too. 3 stays Invalid.
/// The same applies with an Optimistic payload between the two: INVALID for 13 on 12 with
/// `latestValidHash` 11 makes 12 Invalid at once, and 11 must become Valid when it arrives.
#[test]
fn a_latest_valid_hash_payload_recorded_later_becomes_valid() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(1, 0, OPT), (3, 2, invalid(Some(hash(2)))), (12, 11, OPT)],
    );
    assert_eq!(
        statuses.record(hash(2), hash(1), &OPT),
        Some(Valid),
        "2 must be Valid"
    );
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3]),
        [Some(Valid), Some(Valid), Some(Invalid)]
    );

    statuses.record(hash(13), hash(12), &invalid(Some(hash(11))));
    assert_eq!(statuses_of(&statuses, [12, 13]), [Some(Invalid); 2]);
    assert_eq!(
        statuses.record(hash(11), hash(10), &OPT),
        Some(Valid),
        "11 must be Valid"
    );
    assert_eq!(
        statuses_of(&statuses, [11, 12, 13]),
        [Some(Valid), Some(Invalid), Some(Invalid)]
    );
}

/// What stays as it was: INVALID is final, SYNCING does not downgrade VALID, and a call with no
/// verdict records nothing.
#[test]
fn invalid_is_final_and_optimistic_never_downgrades_valid() {
    let mut statuses = ExecutionStatuses::new();
    chain(&mut statuses, &[(1, 0, VALID), (2, 1, OPT)]);
    assert_eq!(statuses.record(hash(1), hash(0), &OPT), Some(Valid));
    let none = ElVerdict::NotVerified(Reason::Timeout);
    assert_eq!(statuses.record(hash(3), hash(2), &none), None);
    assert_eq!(statuses.record(hash(2), hash(1), &none), Some(Optimistic));
    statuses.record(hash(2), hash(1), &invalid(Some(hash(1))));
    for later in [VALID, OPT, none] {
        assert_eq!(statuses.record(hash(2), hash(1), &later), Some(Invalid));
    }
    assert_eq!(statuses.status(&hash(1)), Some(Valid));
}

/// The table's import gate: the verdict must permit the import, and neither the payload nor its
/// execution parent may be recorded Invalid. An unrecorded parent does not refuse it.
#[test]
fn the_table_refuses_an_import_on_an_invalid_execution_parent() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(1, 0, VALID), (2, 1, OPT), (3, 1, invalid(Some(hash(1))))],
    );
    for verdict in [VALID, OPT] {
        // On a Valid, an Optimistic and an unrecorded parent.
        for parent in [1, 2, 9] {
            assert!(
                statuses.permits_payload_import(&hash(10 + parent), &hash(parent), &verdict),
                "{verdict:?} on {parent}"
            );
        }
        // On the Invalid 3, and 3 itself.
        assert!(!statuses.permits_payload_import(&hash(4), &hash(3), &verdict));
        assert!(!statuses.permits_payload_import(&hash(3), &hash(1), &verdict));
    }
    for verdict in [
        invalid(Some(hash(1))),
        invalid(None),
        ElVerdict::NotVerified(Reason::Connect),
    ] {
        assert!(!statuses.permits_payload_import(&hash(11), &hash(1), &verdict));
    }
}

/// Finality at 3 prunes 3 and every recorded ancestor of it, and the forks that branch off
/// below 3 (5 and 6 on 1, an Invalid payload included). It keeps the descendants of 3 and a
/// payload whose parent was never recorded. A finalized hash that was never recorded prunes
/// nothing.
#[test]
fn finality_prunes_the_finalized_chain_and_dead_forks() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[
            (0, 99, VALID),
            (1, 0, VALID),
            (2, 1, OPT),
            (3, 2, OPT),
            (4, 3, OPT),
            (7, 3, OPT),
            (5, 1, OPT),
            (6, 5, invalid(Some(hash(5)))),
            (9, 8, OPT),
        ],
    );
    assert_eq!(statuses.len(), 9);
    assert_eq!(
        statuses.prune_finalized(&hash(77)),
        0,
        "77 was never recorded"
    );
    assert_eq!(statuses.prune_finalized(&hash(3)), 6);
    assert_eq!(statuses.len(), 3);
    assert_eq!(
        statuses_of(&statuses, [0, 1, 2, 3, 5, 6]),
        [None; 6],
        "at or below 3, and the dead fork"
    );
    assert_eq!(
        statuses_of(&statuses, [4, 7, 9]),
        [Some(Optimistic); 3],
        "after 3, and a payload with an unrecorded parent"
    );
    // The table still works on what is left: a VALID for 10 on 4 makes 4 Valid, and the walk
    // ends where 3 was.
    assert_eq!(statuses.record(hash(10), hash(4), &VALID), Some(Valid));
    assert_eq!(
        statuses_of(&statuses, [3, 4, 7]),
        [None, Some(Valid), Some(Optimistic)]
    );
}

/// The `i`-th of many distinct payload hashes.
fn wide(i: u32) -> Hash32 {
    let mut bytes = [0xee; 32];
    bytes[..4].copy_from_slice(&i.to_be_bytes());
    Hash32::from(bytes)
}

/// At most `MAX_INVALID_PAYLOADS` Invalid payloads keep a full entry. Past the bound, the payload
/// that became Invalid first loses its entry first, but it must stay Invalid. An Optimistic or
/// Valid payload is never evicted by it.
#[test]
fn retained_invalid_payloads_are_bounded() {
    assert_eq!(MAX_INVALID_PAYLOADS, 4096);
    let mut statuses = ExecutionStatuses::new();
    statuses.record(hash(1), hash(0), &VALID);
    statuses.record(hash(2), hash(1), &OPT);
    let over = 3;
    let total = u32::try_from(MAX_INVALID_PAYLOADS).unwrap() + over;
    for i in 0..total {
        statuses.record(wide(i), hash(0xfe), &invalid(Some(hash(0xfe))));
    }
    assert_eq!(statuses.len(), MAX_INVALID_PAYLOADS + 2);
    for i in 0..total {
        assert_eq!(
            statuses.status(&wide(i)),
            Some(Invalid),
            "invalid payload {i}"
        );
    }
    assert_eq!(
        statuses_of(&statuses, [1, 2]),
        [Some(Valid), Some(Optimistic)]
    );

    // An invalidated subtree counts too: its oldest members go first.
    statuses.record(hash(3), hash(2), &OPT);
    statuses.record(hash(4), hash(3), &OPT);
    statuses.record(hash(3), hash(2), &invalid(Some(hash(2))));
    assert_eq!(statuses.len(), MAX_INVALID_PAYLOADS + 2);
    assert_eq!(statuses_of(&statuses, [3, 4]), [Some(Invalid); 2]);
    for i in over..over + 2 {
        assert_eq!(
            statuses.status(&wide(i)),
            Some(Invalid),
            "invalid payload {i}"
        );
    }
}

/// INVALID_BLOCK_HASH means that the payload does not hash to the `block_hash` that it claims. The
/// claimed hash can be the hash of an honest payload, so the reply must give no verdict and must
/// record nothing for that hash. Its `latestValidHash` must not count, also when it names a
/// recorded payload. The verdict gate must refuse the envelope. A later honest VALID for the
/// claimed hash must still count.
#[test]
fn invalid_block_hash_records_nothing_and_moves_no_boundary() {
    let mut statuses = ExecutionStatuses::new();
    chain(&mut statuses, &[(1, 0, OPT), (2, 1, OPT)]);
    for latest_valid_hash in [Some(hash(1)), None] {
        let verdict = reply(
            ValidationStatus::InvalidBlockHash,
            latest_valid_hash,
            hash(3),
        );
        assert_eq!(
            verdict,
            ElVerdict::NotVerified(Reason::InvalidBlockHash),
            "latestValidHash {latest_valid_hash:?}"
        );
        assert!(!verdict.permits_payload_import());
        assert!(!statuses.permits_payload_import(&hash(3), &hash(2), &verdict));
        assert_eq!(
            statuses.record(hash(3), hash(2), &verdict),
            None,
            "3 must have no status"
        );
        // A tampered envelope can claim the hash of 2, which is recorded.
        let verdict = reply(
            ValidationStatus::InvalidBlockHash,
            latest_valid_hash,
            hash(2),
        );
        assert_eq!(
            statuses.record(hash(2), hash(1), &verdict),
            Some(Optimistic)
        );
        assert_eq!(
            statuses_of(&statuses, [1, 2, 3]),
            [Some(Optimistic), Some(Optimistic), None],
            "1 and 2 must stay Optimistic, and 3 must have no status"
        );
    }
    let honest = reply(ValidationStatus::Valid, Some(hash(3)), hash(3));
    assert_eq!(statuses.record(hash(3), hash(2), &honest), Some(Valid));
    assert_eq!(statuses_of(&statuses, [1, 2, 3]), [Some(Valid); 3]);
    assert!(!statuses.el_contradiction());
}

/// INVALID_BLOCK_HASH is a newPayload status: a forkchoiceUpdated must not answer it. As the
/// answer to a forkchoiceUpdated it is a protocol fault, so an EL contradiction, and it records
/// nothing: the recorded head 2 keeps its status, and the head 9 that has none gets none.
#[test]
fn an_fcu_invalid_block_hash_is_an_el_contradiction_that_records_nothing() {
    for head in [2, 9] {
        let mut statuses = ExecutionStatuses::new();
        chain(&mut statuses, &[(1, 0, VALID), (2, 1, OPT)]);
        let verdict = reply(ValidationStatus::InvalidBlockHash, None, hash(head));
        assert_eq!(
            statuses.record_head(hash(head), &verdict),
            statuses.status(&hash(head))
        );
        assert!(
            statuses.el_contradiction(),
            "INVALID_BLOCK_HASH for the forkchoiceUpdated head {head}"
        );
        assert_eq!(
            statuses_of(&statuses, [1, 2, 9]),
            [Some(Valid), Some(Optimistic), None]
        );
        assert_eq!(statuses.len(), 2);
    }
}

/// Finality at 2 prunes 1 and 2 from the table. INVALID with a `latestValidHash` as the answer
/// to a forkchoiceUpdated whose head is 2, the finalized payload that the table no longer has,
/// calls that payload invalid: an EL contradiction, and it records nothing. The same answer for
/// a head that the table does not have and that is not finalized (9) is no contradiction, and
/// records nothing either.
#[test]
fn an_fcu_invalid_for_the_pruned_finalized_payload_is_an_el_contradiction_that_records_nothing() {
    let finalized_at_2 = || {
        let mut statuses = ExecutionStatuses::new();
        chain(&mut statuses, &[(1, 0, VALID), (2, 1, OPT), (3, 2, OPT)]);
        statuses.prune_finalized(&hash(2));
        assert_eq!(
            statuses_of(&statuses, [1, 2, 3]),
            [None, None, Some(Optimistic)],
            "finality pruned 1 and 2"
        );
        statuses
    };
    for (head, contradiction) in [(2, true), (9, false)] {
        let mut statuses = finalized_at_2();
        assert_eq!(
            statuses.record_head(hash(head), &invalid(Some(hash(1)))),
            None
        );
        assert_eq!(statuses.el_contradiction(), contradiction, "head {head}");
        assert_eq!(
            statuses_of(&statuses, [1, 2, 3, 9]),
            [None, None, Some(Optimistic), None],
            "head {head} records nothing"
        );
        assert_eq!(statuses.len(), 1);
    }
}

/// Finality at 10, a payload the table never recorded, then 1 on 11 (another one, the payload
/// the walk of the next prune ends at), 2 on 1, 3 on 2, 4 on 3, and the fork 5 on 1. Finality at
/// 3 prunes 1, 2, 3 and the fork. INVALID with a `latestValidHash` as the answer to a
/// forkchoiceUpdated whose head finality has passed calls a finalized payload invalid: an EL
/// contradiction that records nothing, for 3 and for each ancestor that finality pruned (2, 1),
/// that the walk ended at (11) or that was finalized before (10). It stays one after a later
/// finality at 4. The same answer for the pruned fork 5, or for a head the table never had (9),
/// is no contradiction, and INVALID with a `null` `latestValidHash` records nothing either.
#[test]
fn an_fcu_invalid_for_a_pruned_ancestor_of_the_finalized_payload_is_an_el_contradiction() {
    let finalized_at_3 = || {
        let mut statuses = ExecutionStatuses::new();
        statuses.prune_finalized(&hash(10));
        chain(
            &mut statuses,
            &[
                (1, 11, VALID),
                (2, 1, OPT),
                (3, 2, OPT),
                (4, 3, OPT),
                (5, 1, OPT),
            ],
        );
        assert_eq!(statuses.prune_finalized(&hash(3)), 4);
        assert_eq!(
            statuses_of(&statuses, [1, 2, 3, 4, 5]),
            [None, None, None, Some(Optimistic), None]
        );
        statuses
    };
    let nothing_recorded = |statuses: &ExecutionStatuses, head: u8| {
        assert_eq!(
            statuses_of(statuses, [1, 2, 3, 4, 5, 9, 10, 11]),
            [None, None, None, Some(Optimistic), None, None, None, None],
            "head {head} records nothing"
        );
        assert_eq!(statuses.len(), 1);
    };
    for (head, contradiction) in [
        (3, true),
        (2, true),
        (1, true),
        (11, true),
        (10, true),
        (5, false),
        (9, false),
    ] {
        let mut statuses = finalized_at_3();
        assert_eq!(
            statuses.record_head(hash(head), &invalid(Some(hash(11)))),
            None
        );
        assert_eq!(statuses.el_contradiction(), contradiction, "head {head}");
        nothing_recorded(&statuses, head);
    }

    let mut statuses = finalized_at_3();
    assert_eq!(statuses.record_head(hash(2), &invalid(None)), None);
    assert!(!statuses.el_contradiction(), "a null latestValidHash");
    nothing_recorded(&statuses, 2);

    for head in [3, 1, 10] {
        let mut statuses = finalized_at_3();
        statuses.record(hash(6), hash(4), &OPT);
        assert_eq!(statuses.prune_finalized(&hash(4)), 1);
        assert_eq!(
            statuses.record_head(hash(head), &invalid(Some(hash(11)))),
            None
        );
        assert!(
            statuses.el_contradiction(),
            "head {head} after a later finality at 4"
        );
        assert_eq!(
            statuses_of(&statuses, [head, 4, 6]),
            [None, None, Some(Optimistic)]
        );
    }
}

/// INVALID with a `null` `latestValidHash` is the Engine API's answer to a payload that does not
/// hash to the `block_hash` that it claims (`shanghai.md`, from `engine_newPayloadV2`), and a
/// tampered envelope can claim the hash of an honest payload. So it records nothing: a hash with
/// no status gets none, and a Valid or Optimistic status stays as it was, with no EL
/// contradiction. The gate must still refuse that envelope. A later VALID for the hash must
/// still count, with no EL contradiction.
#[test]
fn invalid_with_null_records_nothing_and_sets_no_contradiction() {
    let mut statuses = ExecutionStatuses::new();
    chain(&mut statuses, &[(1, 0, VALID), (2, 1, OPT)]);
    let null = reply(ValidationStatus::Invalid, None, hash(3));
    assert_eq!(null, invalid(None));
    for (n, parent, before) in [(1, 0, Some(Valid)), (2, 1, Some(Optimistic)), (3, 2, None)] {
        assert_eq!(
            statuses.record(hash(n), hash(parent), &null),
            before,
            "{n} must keep its status"
        );
        assert!(!statuses.permits_payload_import(&hash(n), &hash(parent), &null));
    }
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3]),
        [Some(Valid), Some(Optimistic), None]
    );
    assert_eq!(statuses.len(), 2, "no entry for 3");
    assert!(!statuses.el_contradiction());

    for (n, parent) in [(1, 0), (3, 2)] {
        assert_eq!(statuses.record(hash(n), hash(parent), &VALID), Some(Valid));
    }
    assert_eq!(statuses_of(&statuses, [1, 2, 3]), [Some(Valid); 3]);
    assert!(!statuses.el_contradiction());
}

/// 1 is Valid, and 2, 3 and 4 are Optimistic. INVALID for 3 with a `latestValidHash` that the walk
/// does not find (9) makes 3 and 4 Invalid, and 2 must stay Optimistic. INVALID for 4 with
/// `latestValidHash` 1 then sets `invalidBlock` to 2, the child of 1 in the chain of 4. The walk up
/// must step over 3, which is Invalid already, and 2 must become Invalid.
#[test]
fn a_later_boundary_steps_over_an_ancestor_that_is_invalid_already() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(1, 0, VALID), (2, 1, OPT), (3, 2, OPT), (4, 3, OPT)],
    );
    statuses.record(hash(3), hash(2), &invalid(Some(hash(9))));
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3, 4]),
        [Some(Valid), Some(Optimistic), Some(Invalid), Some(Invalid)],
        "2 must stay Optimistic"
    );
    statuses.record(hash(4), hash(3), &invalid(Some(hash(1))));
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3, 4]),
        [Some(Valid), Some(Invalid), Some(Invalid), Some(Invalid)],
        "2 must be Invalid"
    );
    assert!(!statuses.el_contradiction());
}

/// The same boundary as above, but 3 and 4 have lost their full entries to newer Invalid
/// payloads. INVALID for 5 on 4 with `latestValidHash` 1 must step over 4 and 3, and 2 must become
/// Invalid.
#[test]
fn a_boundary_steps_over_evicted_invalid_ancestors() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(1, 0, VALID), (2, 1, OPT), (3, 2, OPT), (4, 3, OPT)],
    );
    statuses.record(hash(3), hash(2), &invalid(Some(hash(9))));
    for i in 0..u32::try_from(MAX_INVALID_PAYLOADS).unwrap() {
        statuses.record(wide(i), hash(0xfe), &invalid(Some(hash(0xfe))));
    }
    assert_eq!(
        statuses.len(),
        MAX_INVALID_PAYLOADS + 2,
        "3 and 4 are evicted"
    );
    assert_eq!(
        statuses.record(hash(5), hash(4), &invalid(Some(hash(1)))),
        Some(Invalid)
    );
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3, 4, 5]),
        [
            Some(Valid),
            Some(Invalid),
            Some(Invalid),
            Some(Invalid),
            Some(Invalid)
        ],
        "2 must be Invalid"
    );
}

/// INVALID for 33 on 32 with `latestValidHash` 31, while 32 is missing: the boundary waits for 32.
/// Then 33 loses its full entry to `MAX_INVALID_PAYLOADS` newer Invalid payloads. It must keep
/// its wait: when 32 is recorded, the boundary applies as if 33 had kept its entry. 32 must
/// become Invalid and 31 Valid.
#[test]
fn an_evicted_invalid_payload_keeps_its_latest_valid_hash_wait() {
    let mut statuses = ExecutionStatuses::new();
    chain(&mut statuses, &[(31, 30, OPT), (33, 32, OPT)]);
    statuses.record(hash(33), hash(32), &invalid(Some(hash(31))));
    for i in 0..u32::try_from(MAX_INVALID_PAYLOADS).unwrap() {
        statuses.record(wide(i), hash(0xfe), &invalid(Some(hash(0xfe))));
    }
    assert_eq!(statuses.len(), MAX_INVALID_PAYLOADS + 1, "33 is evicted");
    assert_eq!(
        statuses_of(&statuses, [31, 32, 33]),
        [Some(Optimistic), None, Some(Invalid)]
    );
    assert_eq!(statuses.record(hash(32), hash(31), &OPT), Some(Invalid));
    assert_eq!(
        statuses_of(&statuses, [31, 32, 33]),
        [Some(Valid), Some(Invalid), Some(Invalid)],
        "the boundary of the evicted 33 must apply"
    );
    assert!(!statuses.el_contradiction());
}

/// 33 on the missing 32 is Invalid, and its boundary 9 waits for 32. Then 33 loses its full
/// entry to `MAX_INVALID_PAYLOADS` newer Invalid payloads. A later INVALID for the evicted 33
/// with `latestValidHash` 31 must replace the wait it keeps: when 32 is recorded, the boundary
/// 31 applies. 32 must become Invalid and 31 Valid. With the old wait for 9, the walk up from 32
/// would not find its boundary, and 31 and 32 would stay Optimistic.
#[test]
fn an_evicted_invalid_payload_takes_the_wait_of_a_later_latest_valid_hash() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[
            (31, 30, OPT),
            (33, 32, OPT),
            (33, 32, invalid(Some(hash(9)))),
        ],
    );
    for i in 0..u32::try_from(MAX_INVALID_PAYLOADS).unwrap() {
        statuses.record(wide(i), hash(0xfe), &invalid(Some(hash(0xfe))));
    }
    assert_eq!(statuses.len(), MAX_INVALID_PAYLOADS + 1, "33 is evicted");
    assert_eq!(
        statuses.record(hash(33), hash(32), &invalid(Some(hash(31)))),
        Some(Invalid)
    );
    assert_eq!(statuses.len(), MAX_INVALID_PAYLOADS + 1, "33 stays evicted");
    assert_eq!(
        statuses_of(&statuses, [31, 32, 33]),
        [Some(Optimistic), None, Some(Invalid)]
    );
    assert_eq!(statuses.record(hash(32), hash(31), &OPT), Some(Invalid));
    assert_eq!(
        statuses_of(&statuses, [31, 32, 33]),
        [Some(Valid), Some(Invalid), Some(Invalid)],
        "the later boundary of the evicted 33 must apply"
    );
    assert!(!statuses.el_contradiction());
}

/// Finality at 3 drops 3 and its ancestors. An INVALID for 3, or strictly below it, is an EL
/// contradiction: its `latestValidHash` is an ancestor of 3 (2, for 5 on 4) or the zero hash (for
/// 5 on 4), or it is for 3 itself, also with the parent of 3 as `latestValidHash` (the boundary
/// the walk finds first). A `latestValidHash` equal to 3 is not: INVALID for 4 with
/// `latestValidHash` 3 is the ordinary boundary, and 4 and 5 are Invalid. Above 3 it is not
/// either: INVALID for 5 with `latestValidHash` 4 makes 4 Valid and 5 Invalid. The finalized
/// payload of the zero hash is no payload (`hash(0)` is the zero hash): an INVALID with the zero
/// hash after it sets no contradiction.
#[test]
fn an_invalid_for_or_strictly_below_the_finalized_payload_is_an_el_contradiction() {
    let finalized_at_3 = || {
        let mut statuses = ExecutionStatuses::new();
        chain(
            &mut statuses,
            &[
                (1, 0, VALID),
                (2, 1, OPT),
                (3, 2, OPT),
                (4, 3, OPT),
                (5, 4, OPT),
            ],
        );
        statuses.prune_finalized(&hash(3));
        statuses
    };
    for (n, parent, latest_valid) in [
        (5, 4, hash(2)),
        (5, 4, Hash32::ZERO),
        (3, 2, hash(1)),
        (3, 2, hash(2)),
    ] {
        let mut statuses = finalized_at_3();
        statuses.record(hash(n), hash(parent), &invalid(Some(latest_valid)));
        assert!(
            statuses.el_contradiction(),
            "INVALID for {n} with {latest_valid} must contradict finality at 3"
        );
        assert_eq!(
            statuses.status(&hash(n)),
            Some(Invalid),
            "{n} stays recorded"
        );
    }

    let mut statuses = finalized_at_3();
    statuses.record(hash(4), hash(3), &invalid(Some(hash(3))));
    assert!(
        !statuses.el_contradiction(),
        "a latestValidHash equal to the finalized payload is honest"
    );
    assert_eq!(
        statuses_of(&statuses, [3, 4, 5]),
        [None, Some(Invalid), Some(Invalid)]
    );

    let mut statuses = finalized_at_3();
    statuses.record(hash(5), hash(4), &invalid(Some(hash(4))));
    assert!(!statuses.el_contradiction());
    assert_eq!(statuses_of(&statuses, [4, 5]), [Some(Valid), Some(Invalid)]);

    let mut statuses = ExecutionStatuses::new();
    chain(&mut statuses, &[(1, 0, OPT), (2, 1, OPT)]);
    assert_eq!(hash(0), Hash32::ZERO);
    statuses.prune_finalized(&Hash32::ZERO);
    statuses.record(hash(2), hash(1), &invalid(Some(Hash32::ZERO)));
    assert!(!statuses.el_contradiction());
    assert_eq!(statuses_of(&statuses, [1, 2]), [Some(Invalid); 2]);
}

/// 2 is Invalid, and it loses its full entry to `MAX_INVALID_PAYLOADS` newer Invalid payloads. It
/// must stay Invalid until finality prunes it. A later SYNCING, ACCEPTED or VALID for it must not
/// change that, and the gate must refuse it and a payload on it. A new payload on it must be
/// Invalid. Finality at 3, beside 2, makes 2 a dead fork, and then the table must drop 2 and the
/// payload on it.
#[test]
fn an_evicted_invalid_payload_stays_invalid_until_finality_prunes_it() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[
            (1, 0, VALID),
            (2, 1, OPT),
            (3, 1, OPT),
            (2, 1, invalid(Some(hash(1)))),
        ],
    );
    for i in 0..u32::try_from(MAX_INVALID_PAYLOADS).unwrap() {
        statuses.record(wide(i), hash(0xfe), &invalid(Some(hash(0xfe))));
    }
    assert_eq!(statuses.len(), MAX_INVALID_PAYLOADS + 2, "2 is evicted");
    assert_eq!(statuses.status(&hash(2)), Some(Invalid));
    for status in [
        ValidationStatus::Syncing,
        ValidationStatus::Accepted,
        ValidationStatus::Valid,
    ] {
        let verdict = reply(status, Some(hash(2)), hash(2));
        assert_eq!(
            statuses.record(hash(2), hash(1), &verdict),
            Some(Invalid),
            "{status:?} must leave 2 Invalid"
        );
        assert!(!statuses.permits_payload_import(&hash(2), &hash(1), &verdict));
        assert!(!statuses.permits_payload_import(&hash(4), &hash(2), &verdict));
    }
    assert_eq!(statuses.record(hash(4), hash(2), &OPT), Some(Invalid));

    statuses.prune_finalized(&hash(3));
    assert_eq!(statuses_of(&statuses, [1, 2, 3, 4]), [None; 4]);
}

/// consensus-specs v1.7.0-beta.4, `specs/bellatrix/optimistic-sync.md`. "How to optimistically
/// import blocks": a payload moves only from `NOT_VALIDATED` to `VALID` or to `INVALIDATED`.
/// "Transitioning from VALID -> INVALIDATED or INVALIDATED -> VALID": the specification omits
/// these two transitions, because only a faulty execution engine can cause them, and they need
/// manual intervention.
///
/// 1, 2 and 3 are Valid. INVALID for 1 (with a `latestValidHash` the table does not know) must not
/// change them, and the table must report the EL contradiction. 4 on 3 is Optimistic and descends
/// from 1, so it moves to Invalid.
#[test]
fn invalid_never_changes_a_valid_payload_and_reports_the_contradiction() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(1, 0, VALID), (2, 1, VALID), (3, 2, VALID), (4, 3, OPT)],
    );
    assert!(!statuses.el_contradiction());
    assert_eq!(
        statuses.record(hash(1), hash(0), &invalid(Some(hash(9)))),
        Some(Valid)
    );
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3, 4]),
        [Some(Valid), Some(Valid), Some(Valid), Some(Invalid)],
        "1, 2 and 3 must stay Valid"
    );
    assert!(statuses.el_contradiction());
}

/// The same rules for an INVALID that reaches a Valid payload from above. 13 and 15 on 12 come
/// before 12, and VALID for 15 makes 13 Valid. INVALID for 12 must not change 13 or 15, and the
/// table must report the EL contradiction. 14 on 13 is Optimistic, so it moves to Invalid.
#[test]
fn invalid_for_a_late_parent_never_changes_a_valid_child() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(13, 12, OPT), (14, 13, OPT), (15, 13, VALID)],
    );
    assert!(!statuses.el_contradiction());
    statuses.record(hash(12), hash(11), &invalid(Some(hash(11))));
    assert_eq!(
        statuses_of(&statuses, [12, 13, 14, 15]),
        [Some(Invalid), Some(Valid), Some(Invalid), Some(Valid)],
        "13 and 15 must stay Valid"
    );
    assert!(statuses.el_contradiction());
}

/// The same rules for a `latestValidHash` boundary above a Valid payload. 11, 12 and 13 are Valid,
/// and 14 on 13 is Optimistic. INVALID for 14 with `latestValidHash` 11 sets `invalidBlock` to 12.
/// 12 and 13 must stay Valid, 14 is Invalid, and the table must report the EL contradiction.
#[test]
fn a_boundary_above_a_valid_payload_never_changes_it() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[
            (11, 10, VALID),
            (12, 11, OPT),
            (13, 12, VALID),
            (14, 13, OPT),
        ],
    );
    assert!(!statuses.el_contradiction());
    statuses.record(hash(14), hash(13), &invalid(Some(hash(11))));
    assert_eq!(
        statuses_of(&statuses, [11, 12, 13, 14]),
        [Some(Valid), Some(Valid), Some(Valid), Some(Invalid)],
        "11, 12 and 13 must stay Valid"
    );
    assert!(statuses.el_contradiction());
}

/// The same rules for VALID (see above). 2 is Invalid. VALID for 3 on 2 must not make 3 Valid: 3
/// is new on an Invalid parent, so it is Invalid. 2 must stay Invalid, the gate must refuse 3 on
/// 2, and the table must report the EL contradiction. VALID for an Invalid payload itself must
/// not change it or its Optimistic parent, and the table must report it too. (2 there is INVALID
/// with a `latestValidHash` the walk does not find, so 1 stays Optimistic.)
#[test]
fn valid_never_changes_an_invalid_payload_and_reports_the_contradiction() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(1, 0, VALID), (2, 1, OPT), (2, 1, invalid(Some(hash(1))))],
    );
    assert!(!statuses.el_contradiction());
    assert_eq!(
        statuses.record(hash(3), hash(2), &VALID),
        Some(Invalid),
        "3 must not become Valid"
    );
    assert_eq!(
        statuses_of(&statuses, [1, 2, 3]),
        [Some(Valid), Some(Invalid), Some(Invalid)],
        "2 must stay Invalid"
    );
    assert!(!statuses.permits_payload_import(&hash(3), &hash(2), &VALID));
    assert!(statuses.el_contradiction());

    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(1, 0, OPT), (2, 1, invalid(Some(hash(9))))],
    );
    assert!(!statuses.el_contradiction());
    assert_eq!(statuses.record(hash(2), hash(1), &VALID), Some(Invalid));
    assert_eq!(
        statuses_of(&statuses, [1, 2]),
        [Some(Optimistic), Some(Invalid)]
    );
    assert!(statuses.el_contradiction());
}

/// 1 and 2 are Valid, 9 on 1 is Optimistic, and 3 on 2 is Optimistic. Finality at 1 prunes 1.
/// Finality at 2 then makes 9 a dead fork: 9 descends from 1 but not from 2. The table must drop
/// 9, although its parent 1 has no entry any more. 3 must stay.
#[test]
fn a_later_finality_prunes_a_fork_off_the_previous_finalized_payload() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[(1, 0, VALID), (2, 1, VALID), (9, 1, OPT), (3, 2, OPT)],
    );
    assert_eq!(statuses.prune_finalized(&hash(1)), 1);
    assert_eq!(
        statuses_of(&statuses, [2, 3, 9]),
        [Some(Valid), Some(Optimistic), Some(Optimistic)]
    );
    assert_eq!(statuses.prune_finalized(&hash(2)), 2, "2 and 9");
    assert_eq!(
        statuses_of(&statuses, [2, 3, 9]),
        [None, Some(Optimistic), None],
        "9 must have no status"
    );
}
