//! Per-type decode caps: checked before any allocation, derived from the spec bounds.

mod common;

use consensus_types::caps::{
    self, max_size, type_max_len, ObjectKind, MAX_PAYLOAD_SIZE, MAX_SSZ_ENCODING,
};
use consensus_types::codec::{check_size, decode, DecodeError, Object};
use consensus_types::forked::SignedBeaconBlock as SignedBeaconBlockOf;
use consensus_types::{gloas, EthSpec, ForkName, Mainnet, Minimal};
use ssz::Encode;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// Counts allocations, and allocated and peak live bytes, of the current thread while on.
struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
    static LIVE_BYTES: Cell<isize> = const { Cell::new(0) };
    static PEAK_BYTES: Cell<isize> = const { Cell::new(0) };
    static ALLOCATED_MODEL: Cell<usize> = const { Cell::new(0) };
    static LIVE_MODEL: Cell<isize> = const { Cell::new(0) };
    static PEAK_MODEL: Cell<isize> = const { Cell::new(0) };
}

/// The allocator-adjusted heap model: an allocation occupies at least
/// `caps::MIN_ALLOCATION_BYTES`.
fn heap_model(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        size.max(caps::MIN_ALLOCATION_BYTES)
    }
}

/// Adds `new` and then releases `old` on one live/peak/total counter triple.
fn track(live: &Cell<isize>, peak: &Cell<isize>, total: &Cell<usize>, new: usize, old: usize) {
    total.set(total.get() + new);
    let now = live.get() + new as isize;
    peak.set(peak.get().max(now));
    live.set(now - old as isize);
}

/// Records an allocation of `new` bytes that releases `old` bytes once it returns. A `realloc`
/// is modelled as copying: both buffers count as live at the peak.
fn note_allocation(new: usize, old: usize) {
    if COUNTING.with(Cell::get) {
        ALLOCATIONS.with(|a| a.set(a.get() + 1));
        LIVE_BYTES
            .with(|l| PEAK_BYTES.with(|p| ALLOCATED_BYTES.with(|t| track(l, p, t, new, old))));
        LIVE_MODEL.with(|l| {
            PEAK_MODEL.with(|p| {
                ALLOCATED_MODEL.with(|t| track(l, p, t, heap_model(new), heap_model(old)))
            })
        });
    }
}

fn note_release(size: usize) {
    if COUNTING.with(Cell::get) {
        LIVE_BYTES.with(|l| l.set(l.get() - size as isize));
        LIVE_MODEL.with(|l| l.set(l.get() - heap_model(size) as isize));
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_allocation(layout.size(), 0);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_allocation(layout.size(), 0);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_allocation(new_size, layout.size());
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_release(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// What `f` allocated on this thread.
#[derive(Debug)]
struct HeapUse {
    allocations: usize,
    allocated_bytes: usize,
    peak_bytes: usize,
    /// As `allocated_bytes`, with each allocation rounded up to `MIN_ALLOCATION_BYTES`.
    allocated_model: usize,
    /// As `peak_bytes`, with each allocation rounded up to `MIN_ALLOCATION_BYTES`.
    peak_model: usize,
}

fn heap_use_during<R>(f: impl FnOnce() -> R) -> (HeapUse, R) {
    ALLOCATIONS.with(|a| a.set(0));
    ALLOCATED_BYTES.with(|a| a.set(0));
    LIVE_BYTES.with(|l| l.set(0));
    PEAK_BYTES.with(|p| p.set(0));
    ALLOCATED_MODEL.with(|a| a.set(0));
    LIVE_MODEL.with(|l| l.set(0));
    PEAK_MODEL.with(|p| p.set(0));
    COUNTING.with(|c| c.set(true));
    let r = f();
    COUNTING.with(|c| c.set(false));
    let used = HeapUse {
        allocations: ALLOCATIONS.with(Cell::get),
        allocated_bytes: ALLOCATED_BYTES.with(Cell::get),
        peak_bytes: PEAK_BYTES.with(Cell::get).max(0) as usize,
        allocated_model: ALLOCATED_MODEL.with(Cell::get),
        peak_model: PEAK_MODEL.with(Cell::get).max(0) as usize,
    };
    (used, r)
}

/// Runs `f` and returns how many allocations it made on this thread.
fn allocations_during<R>(f: impl FnOnce() -> R) -> (usize, R) {
    let (used, r) = heap_use_during(f);
    (used.allocations, r)
}

fn rejects_over_cap<E: EthSpec>() {
    for fork in ForkName::ALL {
        for kind in ObjectKind::ALL {
            let Some(max) = max_size::<E>(kind, fork) else {
                assert!(!kind.exists_in(fork), "{kind} must have a cap at {fork}");
                assert_eq!(
                    decode::<E>(kind, fork, &[]).unwrap_err(),
                    DecodeError::NotInFork { kind, fork }
                );
                continue;
            };
            if kind == ObjectKind::BeaconState {
                // The 4 GiB cap is never allocated here: the length check alone decides.
                assert_eq!(
                    check_size::<E>(kind, fork, max + 1),
                    Err(DecodeError::TooLarge {
                        kind,
                        fork,
                        len: max + 1,
                        max
                    })
                );
                assert_eq!(check_size::<E>(kind, fork, max), Ok(()));
                continue;
            }
            let bytes = vec![0u8; max + 1];
            let (allocations, over) = allocations_during(|| decode::<E>(kind, fork, &bytes));
            assert_eq!(
                over.unwrap_err(),
                DecodeError::TooLarge {
                    kind,
                    fork,
                    len: max + 1,
                    max
                },
                "{kind} at {fork}"
            );
            assert_eq!(
                allocations, 0,
                "{kind} at {fork} allocated before rejecting"
            );

            match decode::<E>(kind, fork, &bytes[..max]) {
                Ok(object) => assert_eq!(object.kind(), kind),
                Err(DecodeError::Ssz(_)) => {}
                Err(other) => panic!("{kind} at {fork}: {max} bytes did not reach SSZ: {other}"),
            }
        }
    }
}

/// A state within the cap reaches the decoder and decodes; the cap itself is tested by length.
#[test]
fn states_within_cap_decode() {
    for (fork, bytes) in [
        (
            ForkName::Fulu,
            common::fulu_state::<Minimal>(3).as_ssz_bytes(),
        ),
        (
            ForkName::Gloas,
            common::gloas_state::<Minimal>(3).as_ssz_bytes(),
        ),
    ] {
        let decoded = decode::<Minimal>(ObjectKind::BeaconState, fork, &bytes).unwrap();
        assert!(
            matches!(decoded, Object::BeaconState(s) if s.fork_name() == fork && s.slot() == 3)
        );
    }
}

#[test]
fn decode_rejects_over_cap() {
    // The counter itself must see allocations, or a zero below proves nothing.
    assert_eq!(allocations_during(|| drop(vec![1u8; 3])).0, 1);
    rejects_over_cap::<Minimal>();
    rejects_over_cap::<Mainnet>();
}

/// The type-specific SSZ bounds of `gloas/p2p-interface.md` and `presets/*/gloas.yaml`.
#[test]
fn caps_match_gloas_size_presets() {
    let cases = [
        (ObjectKind::SignedAggregateAndProof, 1_462, 16_829),
        (ObjectKind::AttesterSlashing, 131_536, 2_097_616),
        (ObjectKind::SignedExecutionPayloadBid, 196_932, 196_932),
    ];
    for (kind, minimal, mainnet) in cases {
        assert_eq!(
            max_size::<Minimal>(kind, ForkName::Gloas),
            Some(minimal),
            "{kind}"
        );
        assert_eq!(
            max_size::<Mainnet>(kind, ForkName::Gloas),
            Some(mainnet),
            "{kind}"
        );
    }
    // Electra list limits give Fulu the same two bounds.
    assert_eq!(
        max_size::<Mainnet>(ObjectKind::SignedAggregateAndProof, ForkName::Fulu),
        Some(16_829)
    );
    assert_eq!(
        max_size::<Mainnet>(ObjectKind::AttesterSlashing, ForkName::Fulu),
        Some(2_097_616)
    );
}

#[test]
fn transport_limits_apply_only_above_the_type_bound() {
    for fork in ForkName::ALL {
        // Unbounded or astronomically bounded states fall back to the SSZ offset limit.
        assert_eq!(
            max_size::<Mainnet>(ObjectKind::BeaconState, fork),
            Some(MAX_SSZ_ENCODING)
        );
    }
    // Fulu blocks carry the execution payload (2^20 transactions of 2^30 bytes).
    assert_eq!(
        max_size::<Mainnet>(ObjectKind::SignedBeaconBlock, ForkName::Fulu),
        Some(MAX_PAYLOAD_SIZE)
    );
    assert_eq!(
        max_size::<Mainnet>(ObjectKind::SignedExecutionPayloadEnvelope, ForkName::Gloas),
        Some(MAX_PAYLOAD_SIZE)
    );
    // Gloas `parent_execution_requests.deposits` is an unbounded ProgressiveList, so the
    // block's own bound exceeds 10 MiB and the transport limit applies.
    for preset_cap in [
        max_size::<Minimal>(ObjectKind::SignedBeaconBlock, ForkName::Gloas),
        max_size::<Mainnet>(ObjectKind::SignedBeaconBlock, ForkName::Gloas),
    ] {
        assert_eq!(preset_cap, Some(MAX_PAYLOAD_SIZE));
    }
    assert_eq!(
        type_max_len::<Mainnet>(ObjectKind::SignedBeaconBlock, ForkName::Gloas),
        Some(u64::MAX)
    );
}

/// More than the Electra `MAX_DEPOSIT_REQUESTS_PER_PAYLOAD` (8,192) deposit requests is
/// spec-valid in Gloas (`DepositRequests` is a `ProgressiveList` with no asserted bound), so both
/// carriers must decode it.
#[test]
fn gloas_deposit_requests_exceed_electra_bound() {
    let deposits = vec![
        gloas::DepositRequest {
            pubkey: common::PUBKEY,
            withdrawal_credentials: common::root(1),
            amount: 1,
            signature: common::SIG,
            index: 0,
        };
        8_193
    ];

    let mut block = common::gloas_block::<Minimal>(1);
    block.message.body.parent_execution_requests.deposits = deposits.clone().try_into().unwrap();
    let bytes = block.as_ssz_bytes();
    assert!(bytes.len() > 8_193 * 192 && bytes.len() < MAX_PAYLOAD_SIZE);
    let decoded =
        decode::<Minimal>(ObjectKind::SignedBeaconBlock, ForkName::Gloas, &bytes).unwrap();
    assert!(matches!(decoded, Object::SignedBeaconBlock(b) if b.slot() == 1));

    let envelope = gloas::SignedExecutionPayloadEnvelope::<Minimal> {
        message: gloas::ExecutionPayloadEnvelope {
            payload: common::gloas_execution_payload(),
            execution_requests: gloas::ExecutionRequests {
                deposits: deposits.try_into().unwrap(),
                withdrawals: Default::default(),
                consolidations: Default::default(),
                builder_deposits: Default::default(),
                builder_exits: Default::default(),
            },
            builder_index: 1,
            beacon_block_root: common::root(2),
            parent_beacon_block_root: common::root(3),
        },
        signature: common::SIG,
    };
    let bytes = envelope.as_ssz_bytes();
    let decoded = decode::<Minimal>(
        ObjectKind::SignedExecutionPayloadEnvelope,
        ForkName::Gloas,
        &bytes,
    )
    .unwrap();
    assert_eq!(decoded, Object::SignedExecutionPayloadEnvelope(envelope));
}

#[test]
fn fixed_size_kinds_cap_at_their_length() {
    let fixed = [
        (ObjectKind::SingleAttestation, 240),
        (ObjectKind::ProposerSlashing, 416),
        (ObjectKind::SignedVoluntaryExit, 112),
        (ObjectKind::SignedBlsToExecutionChange, 172),
        (ObjectKind::SyncCommitteeMessage, 144),
        (ObjectKind::PayloadAttestationMessage, 146),
        (ObjectKind::SignedProposerPreferences, 172),
    ];
    for (kind, len) in fixed {
        assert_eq!(
            max_size::<Mainnet>(kind, ForkName::Gloas),
            Some(len),
            "{kind}"
        );
    }
}

#[test]
fn decodes_real_objects_within_cap() {
    let block = common::gloas_block::<Minimal>(5);
    let decoded = decode::<Minimal>(
        ObjectKind::SignedBeaconBlock,
        ForkName::Gloas,
        &block.as_ssz_bytes(),
    )
    .unwrap();
    assert_eq!(decoded.kind(), ObjectKind::SignedBeaconBlock);
    assert!(matches!(decoded, Object::SignedBeaconBlock(b) if b.slot() == 5));

    let bid = gloas::SignedExecutionPayloadBid::<Minimal> {
        message: common::gloas_bid(5),
        signature: common::SIG,
    };
    let decoded = decode::<Minimal>(
        ObjectKind::SignedExecutionPayloadBid,
        ForkName::Gloas,
        &bid.as_ssz_bytes(),
    )
    .unwrap();
    assert_eq!(decoded, Object::SignedExecutionPayloadBid(bid));
}

#[test]
fn payload_cap_matches_embedded_networks() {
    for network in network_config::Network::ALL {
        let config = network_config::ChainConfig::load(network).unwrap();
        assert_eq!(
            config.max_payload_size(),
            MAX_PAYLOAD_SIZE as u64,
            "{network}"
        );
    }
}

/// Gloas `Transactions`/`Transaction` are `ProgressiveList`s with no asserted bound, so the
/// Bellatrix `MAX_TRANSACTIONS_PER_PAYLOAD` (2^20) must not reject an envelope at decode.
#[test]
fn gloas_transactions_exceed_bellatrix_bound() {
    let mut payload = common::gloas_execution_payload::<Minimal>();
    payload.transactions = vec![Default::default(); (1 << 20) + 1].try_into().unwrap();
    let envelope = gloas::SignedExecutionPayloadEnvelope::<Minimal> {
        message: gloas::ExecutionPayloadEnvelope {
            payload,
            execution_requests: gloas::ExecutionRequests {
                deposits: Default::default(),
                withdrawals: Default::default(),
                consolidations: Default::default(),
                builder_deposits: Default::default(),
                builder_exits: Default::default(),
            },
            builder_index: 1,
            beacon_block_root: common::root(2),
            parent_beacon_block_root: common::root(3),
        },
        signature: common::SIG,
    };
    let bytes = envelope.as_ssz_bytes();
    assert!(bytes.len() < MAX_PAYLOAD_SIZE);
    let decoded = decode::<Minimal>(
        ObjectKind::SignedExecutionPayloadEnvelope,
        ForkName::Gloas,
        &bytes,
    )
    .unwrap();
    assert_eq!(decoded.kind(), ObjectKind::SignedExecutionPayloadEnvelope);
}

/// Gloas `AggregationBits` is an unbounded `ProgressiveBitList`; `process_attestation` only
/// requires `len == committee_offset`, and committee size has no cap. Four minimal committees of
/// 2,049 validators give 8,196 bits, past `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`.
#[test]
fn gloas_block_carries_sparse_attestation_past_validators_per_slot() {
    let mut aggregation_bits = ssz::ProgressiveBitList::with_capacity(4 * 2_049);
    aggregation_bits.set(0, true).unwrap();
    let attestation = gloas::Attestation::<Minimal> {
        aggregation_bits,
        data: gloas::AttestationData {
            slot: 1,
            index: 0,
            beacon_block_root: common::root(1),
            source: gloas::Checkpoint {
                epoch: 0,
                root: common::root(2),
            },
            target: gloas::Checkpoint {
                epoch: 0,
                root: common::root(3),
            },
        },
        signature: common::SIG,
        committee_bits: ssz::BitVector::new(),
    };
    let mut block = common::gloas_block::<Minimal>(2);
    block.message.body.attestations = vec![attestation].try_into().unwrap();
    let bytes = block.as_ssz_bytes();
    assert!(
        bytes.len() < 4 * 1024,
        "sparse attestation stays small: {}",
        bytes.len()
    );
    let decoded =
        decode::<Minimal>(ObjectKind::SignedBeaconBlock, ForkName::Gloas, &bytes).unwrap();
    assert_eq!(
        decoded,
        Object::SignedBeaconBlock(SignedBeaconBlockOf::Gloas(block))
    );
}

fn empty_requests<E: EthSpec>() -> gloas::ExecutionRequests<E> {
    gloas::ExecutionRequests {
        deposits: Default::default(),
        withdrawals: Default::default(),
        consolidations: Default::default(),
        builder_deposits: Default::default(),
        builder_exits: Default::default(),
    }
}

/// An envelope made only of `tx_len`-byte transactions: `count` of them, or as many as fit the
/// cap when `None`.
fn envelope_of(tx_len: usize, count: Option<usize>) -> Vec<u8> {
    let mut envelope = gloas::SignedExecutionPayloadEnvelope::<Minimal> {
        message: gloas::ExecutionPayloadEnvelope {
            payload: common::gloas_execution_payload(),
            execution_requests: empty_requests(),
            builder_index: 1,
            beacon_block_root: common::root(2),
            parent_beacon_block_root: common::root(3),
        },
        signature: common::SIG,
    };
    envelope.message.payload.transactions = Default::default();
    let base = envelope.as_ssz_bytes().len();
    let fill = (MAX_PAYLOAD_SIZE - base) / (4 + tx_len);
    let tx: gloas::Transaction = vec![0xab; tx_len].try_into().unwrap();
    envelope.message.payload.transactions = vec![tx; count.unwrap_or(fill)].try_into().unwrap();
    let bytes = envelope.as_ssz_bytes();
    assert!(bytes.len() <= MAX_PAYLOAD_SIZE);
    assert!(count.is_some() || MAX_PAYLOAD_SIZE - bytes.len() < 4 + tx_len);
    bytes
}

/// The worst cases for an envelope: empty transactions (a 4-byte offset becomes a 24-byte list
/// header) for requested bytes, and 1-byte transactions (each its own minimum-size allocation)
/// for the allocator-adjusted heap model. Each is decoded at the cap and at one item past a
/// doubling step of the transactions buffer (`2^17 · 2^k + 1` items, the decoder reserving
/// `2^17` first), where the buffer is least full and the per-byte figures are highest.
#[test]
fn envelope_decode_heap_stays_within_budget() {
    let shapes = [
        (0, None),
        (1, None),
        (0, Some((1 << 21) + 1)),
        (1, Some((1 << 20) + 1)),
    ];
    for (tx_len, count) in shapes {
        let bytes = envelope_of(tx_len, count);
        let (used, decoded) = heap_use_during(|| {
            decode::<Minimal>(
                ObjectKind::SignedExecutionPayloadEnvelope,
                ForkName::Gloas,
                &bytes,
            )
        });
        decoded.unwrap();
        println!(
            "envelope ({tx_len}-byte txs, {count:?}): {} input bytes, {used:?}",
            bytes.len()
        );
        let input = bytes.len();
        let within = |got: usize, per_byte: usize| got <= input * per_byte;
        assert!(
            within(
                used.peak_bytes,
                caps::ENVELOPE_DECODE_PEAK_HEAP_PER_INPUT_BYTE
            ),
            "{tx_len}: {used:?}"
        );
        assert!(
            within(
                used.allocated_bytes,
                caps::ENVELOPE_DECODE_ALLOCATED_PER_INPUT_BYTE
            ),
            "{tx_len}: {used:?}"
        );
        assert!(
            within(
                used.peak_model,
                caps::ENVELOPE_DECODE_PEAK_HEAP_MODEL_PER_INPUT_BYTE
            ),
            "{tx_len}: {used:?}"
        );
        assert!(
            within(
                used.allocated_model,
                caps::ENVELOPE_DECODE_ALLOCATED_HEAP_MODEL_PER_INPUT_BYTE
            ),
            "{tx_len}: {used:?}"
        );
    }
}

/// A block whose bulk is one list: parent deposit requests (the only unbounded block list of
/// fixed-size items) or the aggregation bits of a single attestation.
fn cap_sized_blocks() -> Vec<(&'static str, Vec<u8>)> {
    let deposits = {
        let mut block = common::gloas_block::<Minimal>(1);
        let base = block.as_ssz_bytes().len();
        let deposit = gloas::DepositRequest {
            pubkey: common::PUBKEY,
            withdrawal_credentials: common::root(1),
            amount: 1,
            signature: common::SIG,
            index: 0,
        };
        let count = (MAX_PAYLOAD_SIZE - base) / 192;
        block.message.body.parent_execution_requests.deposits =
            vec![deposit; count].try_into().unwrap();
        block.as_ssz_bytes()
    };
    let bits = {
        let mut block = common::gloas_block::<Minimal>(1);
        let attestation = |len| gloas::Attestation::<Minimal> {
            aggregation_bits: ssz::ProgressiveBitList::with_capacity(len),
            data: zero_attestation_data(),
            signature: common::SIG,
            committee_bits: ssz::BitVector::new(),
        };
        block.message.body.attestations = vec![attestation(0)].try_into().unwrap();
        let base = block.as_ssz_bytes().len();
        let len = (MAX_PAYLOAD_SIZE - base) * 8;
        block.message.body.attestations = vec![attestation(len)].try_into().unwrap();
        block.as_ssz_bytes()
    };
    vec![("deposit requests", deposits), ("aggregation bits", bits)]
}

fn zero_attestation_data() -> gloas::AttestationData {
    gloas::AttestationData {
        slot: 0,
        index: 0,
        beacon_block_root: common::root(1),
        source: gloas::Checkpoint {
            epoch: 0,
            root: common::root(2),
        },
        target: gloas::Checkpoint {
            epoch: 0,
            root: common::root(3),
        },
    }
}

/// The worst cases for a block: cap-sized blocks dominated by one list.
#[test]
fn block_decode_heap_stays_within_budget() {
    for (what, bytes) in cap_sized_blocks() {
        assert!(
            bytes.len() <= MAX_PAYLOAD_SIZE && MAX_PAYLOAD_SIZE - bytes.len() < 192,
            "{what}"
        );
        let (used, decoded) = heap_use_during(|| {
            decode::<Minimal>(ObjectKind::SignedBeaconBlock, ForkName::Gloas, &bytes)
        });
        decoded.unwrap();
        println!("block ({what}): {} input bytes, {used:?}", bytes.len());
        let input = bytes.len();
        assert!(
            used.peak_bytes <= input * caps::BLOCK_DECODE_PEAK_HEAP_PER_INPUT_BYTE,
            "{what}: {used:?}"
        );
        assert!(
            used.allocated_bytes <= input * caps::BLOCK_DECODE_ALLOCATED_PER_INPUT_BYTE,
            "{what}: {used:?}"
        );
        assert!(
            used.peak_model <= input * caps::BLOCK_DECODE_PEAK_HEAP_MODEL_PER_INPUT_BYTE,
            "{what}: {used:?}"
        );
        assert!(
            used.allocated_model <= input * caps::BLOCK_DECODE_ALLOCATED_HEAP_MODEL_PER_INPUT_BYTE,
            "{what}: {used:?}"
        );
    }
}
