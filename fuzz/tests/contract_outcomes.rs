//! Each `column_contract` seed reaches what it is named for: the sidecars of the negative serving
//! cases end as their names say and never come back in an answer, and the serving seeds get the
//! answers the serving rules give.

use ethswarm_fuzz::seeds::{self, Seed};
use ethswarm_fuzz::{column_contract_events, known_blocks, Answer, Event};
use std::sync::OnceLock;

const TARGET: &str = "column_contract";
const NAMES: [&str; 8] = ["P", "A", "B", "C", "D", "F", "G", "H"];

fn seed(name: &str) -> Vec<u8> {
    static ALL: OnceLock<Vec<Seed>> = OnceLock::new();
    ALL.get_or_init(|| seeds::all(&[]))
        .iter()
        .find(|s| s.target == TARGET && s.name == name)
        .unwrap_or_else(|| panic!("no seed {TARGET}/{name}"))
        .bytes
        .clone()
}

/// The events of seed `name`, one line each: `stored`, `dropped <reason>`, `not a sidecar`,
/// `served <block><index> ...` (blocks by their `CHAIN` names), `refused <code>`, `not a
/// request`.
fn trace(name: &str) -> Vec<String> {
    let blocks = known_blocks();
    let block = |root: &[u8; 32]| {
        let i = blocks
            .iter()
            .position(|b| b.root == *root)
            .expect("a known root");
        NAMES[i]
    };
    column_contract_events(&seed(name))
        .into_iter()
        .map(|event| match event {
            Event::Gossip(Some(Ok(()))) => "stored".into(),
            Event::Gossip(Some(Err(reason))) => format!("dropped {}", reason.reason()),
            Event::Gossip(None) => "not a sidecar".into(),
            Event::Answer(Some(Answer::Sidecars(served))) => {
                let served: Vec<String> = served
                    .iter()
                    .map(|(_, root, index)| format!("{}{index}", block(root)))
                    .collect();
                format!("served {}", served.join(" ")).trim_end().into()
            }
            Event::Answer(Some(Answer::Refused(code))) => format!("refused {code:?}"),
            Event::Answer(None) => "not a request".into(),
        })
        .collect()
}

/// The anchor: the four custody columns of `A`, stored.
const ANCHOR: [&str; 4] = ["stored"; 4];
/// `A`'s custody columns, as served.
const SERVED_A: &str = "served A1 A47 A87 A102";

/// `ANCHOR`, then `rest`.
fn anchored(rest: &[&str]) -> Vec<String> {
    ANCHOR.iter().chain(rest).map(|s| s.to_string()).collect()
}

#[test]
fn kzg_invalid_and_unverified_sidecars_are_never_served() {
    assert_eq!(
        trace("kzg-invalid-never-served"),
        anchored(&[
            "dropped kzg_invalid",
            // A copy of a stored column: dropped, and the stored copy is what is served.
            "dropped kzg_invalid",
            SERVED_A,
            SERVED_A,
        ])
    );
    assert_eq!(
        trace("kzg-no-verdict-never-served"),
        anchored(&["dropped verify_timeout", SERVED_A, SERVED_A])
    );
}

#[test]
fn wrong_root_sidecars_are_never_served() {
    assert_eq!(
        trace("wrong-root-never-served"),
        anchored(&[
            // Waited for, then remembered as unknown.
            "dropped root_timeout",
            "dropped root_timeout",
            // A known root at another slot.
            "dropped unknown_root",
            SERVED_A,
            SERVED_A,
            "served",
        ])
    );
}

#[test]
fn other_block_commitments_are_never_served() {
    assert_eq!(
        trace("other-block-commitments-never-served"),
        anchored(&[
            "dropped commitments_mismatch",
            "dropped commitments_mismatch",
            "dropped commitments_mismatch",
            SERVED_A,
            SERVED_A,
        ])
    );
}

#[test]
fn non_custody_and_wrong_subnet_sidecars_are_never_served() {
    assert_eq!(
        trace("non-custody-never-served"),
        anchored(&[
            "dropped not_custody",
            "dropped not_custody",
            "dropped not_custody",
            "dropped wrong_subnet",
            SERVED_A,
            // A range naming a column we do not custody.
            "refused ResourceUnavailable",
            "served A47",
        ])
    );
}

#[test]
fn a_valid_copy_after_an_invalid_one_is_stored_and_served() {
    assert_eq!(
        trace("invalid-then-valid-copy"),
        anchored(&[
            "dropped kzg_invalid",
            "served A47",
            "stored",
            "dropped kzg_invalid",
            "stored",
            "stored",
            "stored",
            "stored",
            "stored",
            "served A1 A47 A87 A102 B1 B47 B87 B102",
            "served A1 A47 A87 A102 B1 B47 B87 B102",
        ])
    );
}

#[test]
fn nothing_before_custody_or_out_of_shape_is_stored() {
    assert_eq!(
        trace("before-cgc-set-slot"),
        anchored(&[
            "dropped before_cgc_set_slot",
            "dropped before_cgc_set_slot",
            "dropped before_cgc_set_slot",
            "dropped before_cgc_set_slot",
            SERVED_A,
            SERVED_A,
            "refused ResourceUnavailable",
        ])
    );
    assert_eq!(
        trace("broken-structure"),
        anchored(&[
            "dropped not_custody",
            "dropped not_custody",
            "dropped kzg_invalid",
            "dropped commitments_mismatch",
            "dropped commitments_mismatch",
            SERVED_A,
            SERVED_A,
        ])
    );
}

#[test]
fn a_range_follows_one_chain_of_whole_blocks() {
    let stored = |n| vec!["stored"; n];
    let chain = [
        stored(16),
        vec![
            "served A1 A47 A87 A102 B1 B47 B87 B102 D1 D47 D87 D102 G1 G47 G87 G102",
            "served A1 A47 A87 A102 B1 B47 B87 B102 D1 D47 D87 D102 G1 G47 G87 G102",
            "served B1 B47 B87 B102 D1 D47 D87 D102",
            "served A1 A102 B1 B102 D1 D102 G1 G102",
        ],
    ]
    .concat();
    assert_eq!(trace("chain-whole"), chain);
    // The longer branch: through F to H, not D.
    let fork = [
        stored(20),
        vec![
        "served A1 A47 A87 A102 B1 B47 B87 B102 F1 F47 F87 F102 H1 H47 H87 H102",
        "served A1 A47 A87 A102 B1 B47 B87 B102 D1 D47 D87 D102 F1 F47 F87 F102 H1 H47 H87 H102",
        "served F1 F47 F87 F102 H1 H47 H87 H102",
    ],
    ]
    .concat();
    assert_eq!(trace("chain-fork"), fork);
    // D waits for B: the range ends before B's slot until B is stored.
    let pending = [
        stored(8),
        vec![SERVED_A, "served A1 A47 A87 A102 D1 D47 D87 D102"],
        stored(4),
        vec![
            "served A1 A47 A87 A102 B1 B47 B87 B102 D1 D47 D87 D102",
            "served A1 A47 A87 A102 B1 B47 B87 B102 D1 D47 D87 D102",
        ],
    ]
    .concat();
    assert_eq!(trace("parent-after-child"), pending);
    // B's parent never came: the writer thread settles B as a gap after H's write (the harness
    // waits for that step and never takes it itself), earliest_available_slot rises to B's
    // slot, and nothing before it is served, A's late columns included.
    let gap = [
        stored(8),
        vec![
            "refused ResourceUnavailable",
            "served B1 B47 B87 B102 H1 H47 H87 H102",
        ],
        stored(4),
        vec![
            "refused ResourceUnavailable",
            "served B1 B47 B87 B102 H1 H47 H87 H102",
        ],
    ]
    .concat();
    assert_eq!(trace("gap-after-a-missing-block"), gap);
    // B misses two columns: a range of all four ends before it (A alone, never A then D), one
    // of the two it has does not.
    assert_eq!(
        trace("partial-block"),
        [
            stored(10),
            vec![
                SERVED_A,
                "served A1 A47 A87 A102 B1 B47 D1 D47 D87 D102",
                "served A1 A47 B1 B47 D1 D47",
            ]
        ]
        .concat()
    );
}

#[test]
fn requests_at_and_past_their_bounds() {
    assert_eq!(
        trace("range-bounds"),
        anchored(&[
            "refused Invalid",
            "refused Invalid",
            "refused ResourceUnavailable",
            "served A1",
            "refused Invalid",
            "served",
            "served",
            "refused ResourceUnavailable",
            "served",
        ])
    );
    assert_eq!(
        trace("root-bounds"),
        anchored(&["served", "served A1 A47 A87", "refused Invalid", SERVED_A])
    );
    assert_eq!(
        trace("every-operation"),
        anchored(&[
            "stored",
            "not a sidecar",
            SERVED_A,
            "served B47",
            "not a request",
            "not a request",
        ])
    );
}

/// Gate 2a's seeds reach cl-chain: every gossip seed that decodes is dropped (its root is not
/// known, or its slot is before custody), every request seed that decodes is answered, and the
/// anchor is still what is served.
#[test]
fn the_gate2a_seeds_reach_cl_chain() {
    let mut decoded = (0, 0);
    for s in seeds::all(&[]) {
        if s.target != TARGET || !s.name.starts_with("gate2a-") {
            continue;
        }
        let trace = trace(&s.name);
        assert_eq!(trace[..4], ANCHOR, "{}", s.name);
        let op = &trace[4];
        if s.name.starts_with("gate2a-range-") || s.name.starts_with("gate2a-root-") {
            assert_eq!(trace.len(), 5, "{}", s.name);
            decoded.1 += usize::from(op != "not a request");
        } else {
            assert!(
                op == "not a sidecar" || op.starts_with("dropped "),
                "{}: {op}",
                s.name
            );
            decoded.0 += usize::from(op != "not a sidecar");
            assert_eq!(trace[5..], [SERVED_A, SERVED_A], "{}", s.name);
        }
    }
    assert!(decoded.0 >= 5, "{} gossip seeds decoded", decoded.0);
    assert!(decoded.1 >= 10, "{} request seeds decoded", decoded.1);
    assert_eq!(
        trace("gate2a-gossip-valid"),
        anchored(&["dropped before_cgc_set_slot", SERVED_A, SERVED_A])
    );
    // Its range starts long before custody.
    assert_eq!(
        trace("gate2a-range-valid"),
        anchored(&["refused ResourceUnavailable"])
    );
    assert_eq!(trace("gate2a-root-valid"), anchored(&["served"]));
}
