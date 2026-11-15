//! The [`ExecutionStatuses`] table on its own, without a client: the `latestValidHash` boundary of
//! an INVALID verdict, invalid descendants, a payload recorded before its parent, the import gate
//! of the table, pruning at finality, and the bound on retained Invalid payloads.
//!
//! The rules come from `bellatrix/optimistic-sync.md`, "How to apply `latestValidHash` when
//! payload status is `INVALID`" and "How to optimistically import blocks". A payload is
//! `hash(n)`, and `chain` records each `(n, parent, verdict)` in order.

use cl_chain::engine::verdict::{
    ElVerdict, ExecutionStatus, ExecutionStatuses, Reason, MAX_INVALID_PAYLOADS,
};
use consensus_types::primitives::Hash32;

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

/// INVALID with a `null` `latestValidHash`: the payload and every recorded descendant become
/// Invalid. Its ancestors keep their status.
#[test]
fn invalid_with_null_invalidates_the_payload_and_its_descendants() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[
            (1, 0, VALID),
            (2, 1, OPT),
            (3, 2, OPT),
            (4, 3, OPT),
            (5, 3, OPT),
            (6, 4, VALID),
        ],
    );
    statuses.record(hash(3), hash(2), &invalid(None));
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
        "a descendant of an Invalid payload is Invalid, also one recorded Valid"
    );
}

/// INVALID with the all-zero `latestValidHash`: every Optimistic ancestor in the chain is
/// invalid too. The walk up stops at a Valid payload, which stays Valid.
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
}

/// A `latestValidHash` that is not in the chain of the payload counts as `null`: only the
/// payload (and its descendants) become Invalid. The walk up never passes a Valid payload, and
/// a recorded payload on another branch is not made Valid.
#[test]
fn a_latest_valid_hash_outside_the_chain_counts_as_null() {
    let mut statuses = ExecutionStatuses::new();
    chain(
        &mut statuses,
        &[
            (1, 0, VALID),
            (2, 1, OPT),
            (3, 2, OPT),
            (9, 8, OPT),
            (11, 10, VALID),
            (12, 11, OPT),
            (13, 12, VALID),
            (14, 13, OPT),
        ],
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
    // 11 is in the chain of 14, but above the Valid 13: the walk stops at 13.
    statuses.record(hash(14), hash(13), &invalid(Some(hash(11))));
    assert_eq!(
        statuses_of(&statuses, [11, 12, 13, 14]),
        [Some(Valid), Some(Valid), Some(Valid), Some(Invalid)]
    );
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
        &[(13, 12, OPT), (14, 13, OPT), (15, 13, VALID)],
    );
    statuses.record(hash(12), hash(11), &invalid(None));
    assert_eq!(statuses_of(&statuses, [12, 13, 14, 15]), [Some(Invalid); 4]);

    // 23 waits for 22, which comes on the Invalid 21.
    chain(
        &mut statuses,
        &[
            (
                21,
                20,
                ElVerdict::Invalid {
                    latest_valid_hash: None,
                },
            ),
            (23, 22, OPT),
        ],
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
    statuses.record(hash(2), hash(1), &invalid(None));
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
        &[(1, 0, VALID), (2, 1, OPT), (3, 2, invalid(None))],
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
        assert!(!statuses.permits_payload_import(&hash(3), &hash(2), &verdict));
    }
    for verdict in [invalid(None), ElVerdict::NotVerified(Reason::Connect)] {
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
            (6, 5, invalid(None)),
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

/// At most `MAX_INVALID_PAYLOADS` Invalid payloads are kept. Past the bound, the payload that
/// became Invalid first goes first. An Optimistic or Valid payload is never evicted by it.
#[test]
fn retained_invalid_payloads_are_bounded() {
    assert_eq!(MAX_INVALID_PAYLOADS, 4096);
    let mut statuses = ExecutionStatuses::new();
    statuses.record(hash(1), hash(0), &VALID);
    statuses.record(hash(2), hash(1), &OPT);
    let over = 3;
    let total = u32::try_from(MAX_INVALID_PAYLOADS).unwrap() + over;
    for i in 0..total {
        statuses.record(wide(i), hash(0xfe), &invalid(None));
    }
    assert_eq!(statuses.len(), MAX_INVALID_PAYLOADS + 2);
    for i in 0..total {
        let want = (i >= over).then_some(Invalid);
        assert_eq!(statuses.status(&wide(i)), want, "invalid payload {i}");
    }
    assert_eq!(
        statuses_of(&statuses, [1, 2]),
        [Some(Valid), Some(Optimistic)]
    );

    // An invalidated subtree counts too: its oldest members go first.
    statuses.record(hash(3), hash(2), &OPT);
    statuses.record(hash(4), hash(3), &OPT);
    statuses.record(hash(3), hash(2), &invalid(None));
    assert_eq!(statuses.len(), MAX_INVALID_PAYLOADS + 2);
    assert_eq!(statuses_of(&statuses, [3, 4]), [Some(Invalid); 2]);
    for i in over..over + 2 {
        assert_eq!(statuses.status(&wide(i)), None, "invalid payload {i}");
    }
}
