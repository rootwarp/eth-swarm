//! Tests of the pre-state LRU of the chain core.

use cl_chain::core::snapshot::{max_pre_states, Snapshots};
use consensus_types::primitives::Root;
use consensus_types::{Mainnet, Minimal};

fn root(byte: u8) -> Root {
    Root::repeat_byte(byte)
}

#[test]
fn the_bound_is_two_epochs_and_the_anchor() {
    assert_eq!(max_pre_states::<Minimal>(), 17);
    assert_eq!(max_pre_states::<Mainnet>(), 65);
}

#[test]
fn the_least_recent_goes_first_and_the_anchor_stays() {
    let mut lru = Snapshots::new(root(0), 0u8, 3);
    lru.insert(root(1), 1);
    lru.insert(root(2), 2);
    assert_eq!(lru.len(), 3);
    // A read makes 1 the most recent.
    assert_eq!(lru.get(&root(1)), Some(&1));
    lru.insert(root(3), 3);
    assert_eq!(lru.len(), 3, "the bound must hold");
    assert_eq!(lru.peek(&root(2)), None, "the least recent must go first");
    assert_eq!(lru.peek(&root(1)), Some(&1));
    assert_eq!(lru.peek(&root(3)), Some(&3));
    for byte in 4..40 {
        lru.insert(root(byte), byte);
    }
    assert_eq!(lru.len(), 3);
    assert_eq!(lru.peek(&root(0)), Some(&0), "the anchor must stay");
    assert_eq!(lru.peek(&root(39)), Some(&39), "the newest must stay");
}

#[test]
fn an_insert_of_a_known_root_replaces_it() {
    let mut lru = Snapshots::new(root(0), 0u8, 3);
    lru.insert(root(1), 1);
    lru.insert(root(1), 9);
    assert_eq!(lru.len(), 2);
    assert_eq!(lru.peek(&root(1)), Some(&9));
    lru.insert(root(0), 7);
    assert_eq!(
        lru.peek(&root(0)),
        Some(&0),
        "an insert must not replace the anchor"
    );
}

#[test]
fn the_newest_stays_under_any_bound() {
    let mut lru = Snapshots::new(root(0), 0u8, 0);
    lru.insert(root(1), 1);
    lru.insert(root(2), 2);
    assert_eq!(lru.len(), 2, "the anchor and the newest post-state");
    assert_eq!(lru.peek(&root(2)), Some(&2));
}
