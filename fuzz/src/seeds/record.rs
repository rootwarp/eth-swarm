//! The `enr_fields` seeds: signed records as raw bytes, and the same records as structured
//! inputs (`structured-*`).
//!
//! The valid records are the pinned Sepolia schedule's `eth2` and `nfd` on both sides of every
//! digest change from Fulu on: the Fulu fork, each BPO fork (the digest moves, the version does
//! not) and Gloas, the last scheduled fork (nothing next: `FAR_FUTURE_EPOCH` and a zero `nfd`),
//! with a `cgc` of 4. The rest are the refusals and edge cases: `eth2` alone, `cgc` 0 (the empty
//! string) and `u64::MAX`, `eth2` of 15 and 17 bytes, a `cgc` with a leading zero byte or of 9
//! bytes, an `nfd` of 3 and 5 bytes, a `cgc` that is an RLP list, no `eth2`, an ed25519 record,
//! and for the raw bytes a record cut short, with a byte after it, with a forged signature, over
//! 300 bytes, and bytes that are no record at all; plus the inputs the fuzzer found
//! (`regression-*`).

use super::Seed;
use crate::{signed_record, structured_input, RecordSpec, RecordValue, STRUCTURED_BIT};
use network_config::{ChainConfig, Network};
use p2p_wire::enr::{encode_cgc, ForkFields};

const TARGET: &str = "enr_fields";

/// Sepolia epochs on both sides of every digest change from Fulu on.
const BOUNDARIES: [(u64, &str); 7] = [
    (272_640, "fulu-fork"),
    (274_175, "before-bpo1"),
    (274_176, "bpo1"),
    (275_711, "before-bpo2"),
    (275_712, "bpo2"),
    (353_023, "before-gloas"),
    (353_024, "gloas"),
];

/// The raw values of one record: `eth2`, `cgc`, `nfd`, each a byte string or raw RLP.
#[derive(Clone)]
enum Owned {
    Bytes(Vec<u8>),
    Rlp(Vec<u8>),
}

struct Case {
    name: String,
    values: [Option<Owned>; 3],
    ed25519: bool,
}

impl Case {
    fn spec(&self) -> RecordSpec<'_> {
        RecordSpec {
            values: self.values.each_ref().map(|v| {
                v.as_ref().map(|v| match v {
                    Owned::Bytes(b) => RecordValue::Bytes(b),
                    Owned::Rlp(b) => RecordValue::Rlp(b),
                })
            }),
            ed25519: self.ed25519,
        }
    }
}

fn bytes(b: impl Into<Vec<u8>>) -> Option<Owned> {
    Some(Owned::Bytes(b.into()))
}

fn case(name: impl Into<String>, values: [Option<Owned>; 3]) -> Case {
    Case {
        name: name.into(),
        values,
        ed25519: false,
    }
}

fn cases() -> Vec<Case> {
    let config = ChainConfig::load(Network::Sepolia).expect("the pinned Sepolia config");
    let gvr = Network::Sepolia
        .genesis()
        .expect("the pinned Sepolia genesis")
        .genesis_validators_root;
    let at = |epoch| ForkFields::from_schedule(&config, &gvr, epoch).expect("after Fulu");
    let mut out: Vec<Case> = BOUNDARIES
        .iter()
        .map(|&(epoch, label)| {
            let fields = at(epoch);
            case(
                format!("sepolia-{label}-epoch-{epoch}"),
                [
                    bytes(fields.eth2.to_bytes()),
                    bytes(encode_cgc(4)),
                    bytes(fields.nfd),
                ],
            )
        })
        .collect();
    let fields = at(BOUNDARIES[1].0);
    let eth2 = fields.eth2.to_bytes();
    let nfd = fields.nfd;
    let cgc = encode_cgc(4);
    out.extend([
        case("eth2-only", [bytes(eth2), None, None]),
        case("cgc-zero", [bytes(eth2), bytes(encode_cgc(0)), bytes(nfd)]),
        case(
            "cgc-max",
            [bytes(eth2), bytes(encode_cgc(u64::MAX)), bytes(nfd)],
        ),
        case("eth2-15-bytes", [bytes(&eth2[..15]), None, None]),
        case(
            "eth2-17-bytes",
            [bytes([&eth2[..], &[0]].concat()), None, None],
        ),
        case("cgc-leading-zero", [bytes(eth2), bytes([0, 4]), None]),
        case("cgc-9-bytes", [bytes(eth2), bytes([1; 9]), None]),
        case(
            "nfd-3-bytes",
            [bytes(eth2), bytes(cgc.clone()), bytes(&nfd[..3])],
        ),
        case(
            "nfd-5-bytes",
            [bytes(eth2), bytes(cgc.clone()), bytes([0; 5])],
        ),
        case(
            "cgc-rlp-list",
            [bytes(eth2), Some(Owned::Rlp(vec![0xc2, 0x01, 0x02])), None],
        ),
        case("no-eth2", [None, bytes(cgc.clone()), bytes(nfd)]),
        Case {
            name: "ed25519".into(),
            values: [bytes(eth2), bytes(cgc), bytes(nfd)],
            ed25519: true,
        },
    ]);
    out
}

/// Every `enr_fields` seed.
pub fn all(seeds: &mut Vec<Seed>) {
    let mut add = |name: String, bytes: Vec<u8>| {
        seeds.push(Seed {
            target: TARGET,
            slow: false,
            name,
            bytes,
        });
    };
    let raw = |rlp: &[u8]| [&[0u8][..], rlp].concat();
    let cases = cases();
    for case in &cases {
        let spec = case.spec();
        let rlp = signed_record(&spec).expect("every seed record fits");
        add(case.name.clone(), raw(&rlp));
        add(
            format!("structured-{}", case.name),
            [&[STRUCTURED_BIT][..], &structured_input(&spec)].concat(),
        );
    }
    let valid = signed_record(&cases[1].spec()).expect("fits");
    add("truncated".into(), raw(&valid[..valid.len() - 1]));
    add("trailing-byte".into(), raw(&[&valid[..], &[0]].concat()));
    let mut forged = valid.clone();
    // The first byte of the signature, after the list and string headers.
    forged[4] ^= 1;
    add("forged-signature".into(), raw(&forged));
    let long = RecordSpec {
        values: [Some(RecordValue::Bytes(&[0x42; 255])), None, None],
        ed25519: false,
    };
    let over = signed_record(&long).expect("built past the size, for the decoder to refuse");
    add("over-300-bytes".into(), raw(&over));
    add(
        "structured-over-300-bytes".into(),
        [&[STRUCTURED_BIT][..], &structured_input(&long)].concat(),
    );
    add("empty".into(), raw(&[]));
    add("empty-list".into(), raw(&[0xc0]));
    add("not-rlp".into(), raw(&[0xff; 8]));
    add("structured-no-values".into(), vec![STRUCTURED_BIT, 0]);
    // Found by the fuzzer (a harness oracle fault, not a decoder one): an ed25519 record with a
    // raw `cgc` that breaks the record, refused as a record before its key is looked at.
    add(
        "regression-structured-ed25519-broken-raw-cgc".into(),
        vec![0x0d, 0xde, 0xde, 0x19, 0xde],
    );
}
