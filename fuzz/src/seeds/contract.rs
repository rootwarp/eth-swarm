//! The gate-2b seeds: `column_contract` inputs (operation sequences, `crate::contract`).
//!
//! - **Gate 2a's corpus**, each seed after an anchor (the custody columns of the first custody
//!   block, valid) and followed by a range and a root query over the stored blocks: every
//!   `data_column_sidecar` gossip message as a raw gossip operation (`gate2a-<name>`), and every
//!   `columns_by_range_req` and `columns_by_root_req` request as a raw request
//!   (`gate2a-range-<name>`, `gate2a-root-<name>`). Their sidecars name roots the reference does
//!   not know, or slots before custody, so the contract drops them; the oversize ones and the
//!   bombs never decode.
//! - **The negative serving cases** of cl-chain's `tests/v2_serving.rs`, each queried by range
//!   and by root afterwards: KZG-invalid cells and no verdict, an unknown root and a known root
//!   at another slot, another block's commitment count, non-custody and wrong-subnet columns
//!   (also as a second copy of a stored column), an invalid copy before a valid one, a column
//!   before custody, and broken structure.
//! - **The serving rules**: a whole chain, a fork, a block stored before its parent, a gap, and
//!   requests at and past their bounds.

use super::{columns, Seed};
use crate::{
    known_blocks, raw_gossip, raw_request, GossipSpec, RangeSpec, RootSpec, CUSTODY, EXTRA_CELL,
    KZG_INVALID, KZG_NO_VERDICT, KZG_VALID, MISSING_CELL, MISSING_PROOF, OP_RAW_RANGE, OP_RAW_ROOT,
    SLOT_AFTER, UNKNOWN_ROOT, WRONG_SUBNET,
};

const TARGET: &str = "column_contract";

/// The blocks of `crate::CHAIN`, by name.
pub const P: u8 = 0;
pub const A: u8 = 1;
pub const B: u8 = 2;
pub const C: u8 = 3;
pub const D: u8 = 4;
pub const F: u8 = 5;
pub const G: u8 = 6;
pub const H: u8 = 7;

/// [`RangeSpec::start`] of the slot of block `block`.
pub fn start_of(block: u8) -> u8 {
    let blocks = known_blocks();
    let slot = blocks[usize::from(block)].slot;
    u8::try_from(slot - blocks[0].slot + 1).expect("a near slot")
}

/// A valid sidecar of `block`'s column `index`, its cells filled with `fill`.
pub fn valid(block: u8, index: u8, fill: u8) -> GossipSpec {
    GossipSpec {
        block,
        index,
        flags: 0,
        verdict: KZG_VALID,
        fill,
    }
}

/// [`valid`] with `flags`.
pub fn with(flags: u8, block: u8, index: u8) -> GossipSpec {
    GossipSpec {
        flags,
        ..valid(block, index, 0x11)
    }
}

/// [`valid`] with the KZG verdict `verdict`.
pub fn verdict(verdict: u8, block: u8, index: u8) -> GossipSpec {
    GossipSpec {
        verdict,
        ..valid(block, index, 0x22)
    }
}

/// Operations, concatenated.
#[derive(Default)]
pub struct Ops(Vec<u8>);

impl Ops {
    pub fn gossip(mut self, spec: GossipSpec) -> Self {
        self.0.extend(spec.bytes());
        self
    }

    /// Every custody column of `block`, valid.
    pub fn block(mut self, block: u8) -> Self {
        for index in CUSTODY {
            self = self.gossip(valid(block, index as u8, 0x11));
        }
        self
    }

    pub fn range(mut self, start: u8, count: u8, columns: &[u8]) -> Self {
        self.0.extend(
            RangeSpec {
                start,
                count,
                columns: columns.to_vec(),
            }
            .bytes(),
        );
        self
    }

    /// The custody columns over `count` slots from block `block`'s.
    pub fn range_from(self, block: u8, count: u8) -> Self {
        self.range(start_of(block), count, &custody())
    }

    pub fn root(mut self, ids: &[(u8, &[u8])]) -> Self {
        self.0.extend(
            RootSpec {
                ids: ids.iter().map(|(b, c)| (*b, c.to_vec())).collect(),
            }
            .bytes(),
        );
        self
    }

    pub fn raw(mut self, bytes: &[u8]) -> Self {
        self.0.extend(bytes);
        self
    }

    /// Every custody column over the range of `crate::CHAIN` from the first custody block,
    /// then every block's custody columns by root.
    pub fn query_all(self) -> Self {
        let ids: Vec<(u8, Vec<u8>)> = (P..=H).map(|b| (b, custody())).collect();
        let ids: Vec<(u8, &[u8])> = ids.iter().map(|(b, c)| (*b, c.as_slice())).collect();
        self.range_from(A, 8).root(&ids)
    }

    pub fn bytes(self) -> Vec<u8> {
        self.0
    }
}

/// [`CUSTODY`] as index bytes.
pub fn custody() -> Vec<u8> {
    CUSTODY.iter().map(|&i| i as u8).collect()
}

/// Every gate-2b seed.
pub fn all(seeds: &mut Vec<Seed>) {
    let mut add = |name: &str, ops: Ops| {
        seeds.push(Seed {
            target: TARGET,
            slow: false,
            name: name.to_string(),
            bytes: ops.bytes(),
        });
    };
    let anchored = || Ops::default().block(A);

    let mut gate2a = Vec::new();
    columns::all(&mut gate2a);
    for seed in &gate2a {
        let ops = match seed.target {
            "data_column_sidecar" if seed.name.starts_with("gossip-") => {
                anchored().raw(&raw_gossip(seed.bytes[0] >> 1, &seed.bytes[1..]))
            }
            "columns_by_range_req" => {
                let ops = anchored().raw(&raw_request(OP_RAW_RANGE, &seed.bytes));
                add(&format!("gate2a-range-{}", seed.name), ops);
                continue;
            }
            "columns_by_root_req" => {
                let ops = anchored().raw(&raw_request(OP_RAW_ROOT, &seed.bytes));
                add(&format!("gate2a-root-{}", seed.name), ops);
                continue;
            }
            _ => continue,
        };
        add(&format!("gate2a-{}", seed.name), ops.query_all());
    }

    // The negative serving cases: each dropped sidecar is never stored or served.
    add(
        "kzg-invalid-never-served",
        anchored()
            .gossip(verdict(KZG_INVALID, B, 47))
            .gossip(verdict(KZG_INVALID, A, 47))
            .query_all(),
    );
    add(
        "kzg-no-verdict-never-served",
        anchored()
            .gossip(verdict(KZG_NO_VERDICT, B, 47))
            .query_all(),
    );
    add(
        "wrong-root-never-served",
        anchored()
            .gossip(valid(B | UNKNOWN_ROOT, 47, 0x11))
            .gossip(valid(B | UNKNOWN_ROOT, 47, 0x12))
            .gossip(with(SLOT_AFTER, B, 47))
            .query_all()
            .root(&[(B | UNKNOWN_ROOT, &[47])]),
    );
    add(
        "other-block-commitments-never-served",
        anchored()
            .gossip(with(MISSING_CELL, G, 47))
            .gossip(with(EXTRA_CELL, B, 47))
            .gossip(with(EXTRA_CELL, C, 47))
            .query_all(),
    );
    add(
        "non-custody-never-served",
        anchored()
            .gossip(valid(A, 0, 0x11))
            .gossip(valid(A, 5, 0x11))
            .gossip(valid(A, 127, 0x11))
            .gossip(GossipSpec {
                fill: 0x33,
                ..with(WRONG_SUBNET, A, 47)
            })
            .range_from(A, 1)
            .range(start_of(A), 1, &[0, 5, 127])
            .root(&[(A, &[0, 5, 127, 47])]),
    );
    add(
        "invalid-then-valid-copy",
        anchored()
            .gossip(verdict(KZG_INVALID, B, 47))
            .range(start_of(A), 2, &[47])
            .gossip(valid(B, 47, 0x44))
            .gossip(verdict(KZG_INVALID, B, 1))
            .gossip(valid(B, 1, 0x45))
            .block(B)
            .query_all(),
    );
    add(
        "before-cgc-set-slot",
        anchored().block(P).query_all().range_from(P, 2),
    );
    add(
        "broken-structure",
        anchored()
            .gossip(valid(B, 128, 0x11))
            .gossip(valid(B, 255, 0x11))
            .gossip(with(MISSING_PROOF, B, 47))
            .gossip(valid(C, 47, 0x11))
            .gossip(with(MISSING_CELL, B, 47))
            .query_all(),
    );

    // The serving rules.
    add(
        "chain-whole",
        Ops::default()
            .block(A)
            .block(B)
            .block(D)
            .block(G)
            .query_all()
            .range_from(B, 3)
            .range(start_of(A), 6, &[102, 1, 1]),
    );
    add(
        "chain-fork",
        Ops::default()
            .block(A)
            .block(B)
            .block(D)
            .block(F)
            .block(H)
            .query_all()
            .range_from(F, 4),
    );
    add(
        "parent-after-child",
        Ops::default()
            .block(A)
            .block(D)
            .query_all()
            .block(B)
            .query_all(),
    );
    add(
        "gap-after-a-missing-block",
        Ops::default()
            .block(B)
            .block(H)
            .query_all()
            .block(A)
            .query_all(),
    );
    add(
        "partial-block",
        anchored()
            .gossip(valid(B, 1, 0x11))
            .gossip(valid(B, 47, 0x11))
            .block(D)
            .query_all()
            .range(start_of(A), 6, &[1, 47]),
    );
    add(
        "range-bounds",
        anchored()
            .range(start_of(A), 255, &[1])
            .range(start_of(A), 252, &(0..128).collect::<Vec<u8>>())
            .range(start_of(A), 128, &(0..128).collect::<Vec<u8>>())
            .range(start_of(A), 253, &[1, 1])
            .range(start_of(A), 1, &[200])
            .range(start_of(A), 0, &[1])
            .range(start_of(A), 5, &[])
            .range(0, 1, &[1])
            .range(250, 4, &[1]),
    );
    let full: Vec<u8> = (0..128).collect();
    let wide: Vec<(u8, &[u8])> = (0..128u8).map(|i| (i & 7, &full[..])).collect();
    add(
        "root-bounds",
        anchored()
            .root(&[])
            .root(&[(A, &[47, 47, 1]), (A, &[47, 87]), (A | UNKNOWN_ROOT, &[1])])
            .root(&[(A, &[200, 1])])
            .root(&wide),
    );
    add(
        "every-operation",
        anchored()
            .gossip(valid(B, 47, 0x11))
            .raw(&raw_gossip(47, b"not snappy"))
            .range_from(A, 2)
            .root(&[(B, &[47])])
            .raw(&raw_request(OP_RAW_RANGE, b"\x00"))
            .raw(&raw_request(OP_RAW_ROOT, b"")),
    );
}
