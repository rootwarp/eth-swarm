//! Data-column sidecars: the Gloas cap over the configured blob schedule, the Fulu type bound,
//! the per-fork list bounds and dispatch by the sidecar's own slot.

mod common;

use consensus_types::caps::{
    compute_max_data_column_sidecar_size, max_size, max_size_for, type_max_len, NetworkCaps,
    ObjectKind,
};
use consensus_types::codec::{check_size, check_size_for, decode, decode_for, DecodeError, Object};
use consensus_types::forked::DataColumnSidecar;
use consensus_types::primitives::*;
use consensus_types::{fulu, gloas, EthSpec, ForkName, ForkSchedule, Mainnet, Minimal};
use network_config::{BlobParameters, ChainConfig, Network};
use ssz::{Decode, Encode};
use ssz_types::FixedVector;

const KIND: ObjectKind = ObjectKind::DataColumnSidecar;

/// `index` (8), the `column` and `kzg_proofs` offsets (4 + 4), `slot` (8), `beacon_block_root`
/// (32).
const GLOAS_SIDECAR_FIXED_PART: u64 = 56;
/// One blob adds a `Cell` (2,048) and a `KZGProof` (48).
const GLOAS_BYTES_PER_BLOB: u64 = 2_048 + 48;

/// A Gloas sidecar of `blobs` zero cells and proofs.
fn gloas_sidecar<E: EthSpec>(blobs: usize, slot: Slot) -> gloas::DataColumnSidecar<E> {
    gloas::DataColumnSidecar {
        index: 0,
        column: vec![FixedVector::default(); blobs].try_into().unwrap(),
        kzg_proofs: vec![[0; 48]; blobs].try_into().unwrap(),
        slot,
        beacon_block_root: Root::ZERO,
    }
}

/// `compute_max_data_column_sidecar_size()` (`gloas/p2p-interface.md`), line by line: the
/// largest blob count of the schedule, then the length of a serialized sidecar that holds it.
fn ported_compute_max_data_column_sidecar_size(config: &ChainConfig) -> u64 {
    let mut max_blobs = config.max_blobs_per_block_electra();
    for entry in config.blob_schedule() {
        max_blobs = max_blobs.max(entry.max_blobs_per_block);
    }
    let sidecar = gloas_sidecar::<Mainnet>(max_blobs as usize, 0);
    sidecar.as_ssz_bytes().len() as u64
}

/// The first slot of `fork` on `network`.
fn first_slot<E: EthSpec>(schedule: &ForkSchedule, fork: ForkName) -> Slot {
    E::start_slot_at_epoch(schedule.fork_epoch(fork).unwrap())
}

fn fulu_sidecar<E: EthSpec>(blobs: usize, slot: Slot) -> fulu::DataColumnSidecar<E> {
    fulu::DataColumnSidecar {
        index: 3,
        column: vec![FixedVector::default(); blobs].try_into().unwrap(),
        kzg_commitments: vec![[0x11; 48]; blobs].try_into().unwrap(),
        kzg_proofs: vec![[0x22; 48]; blobs].try_into().unwrap(),
        signed_block_header: fulu::SignedBeaconBlockHeader {
            message: fulu::BeaconBlockHeader {
                slot,
                proposer_index: 1,
                parent_root: common::root(1),
                state_root: common::root(2),
                body_root: common::root(3),
            },
            signature: common::SIG,
        },
        kzg_commitments_inclusion_proof: FixedVector::from_elem(common::root(4)),
    }
}

#[test]
fn column_sidecar_max_size() {
    for network in Network::ALL {
        let config = ChainConfig::load(network).unwrap();
        let caps = NetworkCaps::from_config(&config);
        let ported = ported_compute_max_data_column_sidecar_size(&config);
        // Both schedules top out at 21 blobs: 56 + 21 * 2,096.
        assert_eq!(caps.max_blobs_per_block(), 21, "{network}");
        assert_eq!(ported, 44_072, "{network}");
        assert_eq!(
            compute_max_data_column_sidecar_size::<Mainnet>(&caps),
            ported
        );
        let max = max_size_for::<Mainnet>(KIND, ForkName::Gloas, &caps).unwrap();
        assert_eq!(max as u64, ported, "{network}");

        // A sidecar of exactly the cap decodes, by fork and by its own slot.
        let slot = first_slot::<Mainnet>(config.fork_schedule(), ForkName::Gloas);
        let sidecar = gloas_sidecar::<Mainnet>(21, slot);
        let bytes = sidecar.as_ssz_bytes();
        assert_eq!(bytes.len(), max, "{network}");
        assert_eq!(
            decode_for::<Mainnet>(KIND, ForkName::Gloas, &caps, &bytes).unwrap(),
            Object::DataColumnSidecar(DataColumnSidecar::Gloas(sidecar.clone()))
        );
        let by_slot = DataColumnSidecar::<Mainnet>::from_ssz_bytes_by_slot(
            &bytes,
            config.fork_schedule(),
            &caps,
        )
        .unwrap();
        assert_eq!(by_slot, DataColumnSidecar::Gloas(sidecar));
        // Its slot, read without decoding it: what a digest check needs first.
        assert_eq!(DataColumnSidecar::<Mainnet>::peek_slot(&bytes), Ok(slot));
        assert!(DataColumnSidecar::<Mainnet>::peek_slot(&bytes[..7]).is_err());

        // One byte more is refused before decoding.
        let mut over = bytes;
        over.push(0);
        let too_large = DecodeError::TooLarge {
            kind: KIND,
            fork: ForkName::Gloas,
            len: max + 1,
            max,
        };
        assert_eq!(
            decode_for::<Mainnet>(KIND, ForkName::Gloas, &caps, &over).unwrap_err(),
            too_large
        );
        assert_eq!(
            DataColumnSidecar::<Mainnet>::from_ssz_bytes_by_slot(
                &over,
                config.fork_schedule(),
                &caps
            )
            .unwrap_err(),
            too_large
        );
    }
}

#[test]
fn network_caps_take_the_largest_blob_count() {
    let entry = |epoch, max_blobs_per_block| BlobParameters {
        epoch,
        max_blobs_per_block,
    };
    for (electra, schedule, expected) in [
        (9, vec![], 9),
        (9, vec![entry(10, 15), entry(20, 21)], 21),
        // A later entry may lower the limit; the cap keeps the largest one.
        (9, vec![entry(10, 21), entry(20, 6)], 21),
        (30, vec![entry(10, 15)], 30),
        (0, vec![], 0),
    ] {
        let caps = NetworkCaps::from_blob_schedule(electra, &schedule);
        assert_eq!(caps.max_blobs_per_block(), expected, "{schedule:?}");
        assert_eq!(
            compute_max_data_column_sidecar_size::<Minimal>(&caps),
            GLOAS_SIDECAR_FIXED_PART + expected * GLOAS_BYTES_PER_BLOB
        );
        let bytes = gloas_sidecar::<Minimal>(expected as usize, 0).as_ssz_bytes();
        assert_eq!(
            max_size_for::<Minimal>(KIND, ForkName::Gloas, &caps),
            Some(bytes.len())
        );
    }
}

/// The preset bound, opted into explicitly, is the largest any valid sidecar can be: a block
/// carries at most `MAX_BLOB_COMMITMENTS_PER_BLOCK` blobs, whatever the blob schedule says.
#[test]
fn preset_bound_gloas_cap_is_the_commitment_bound() {
    assert_eq!(NetworkCaps::PRESET_BOUND.max_blobs_per_block(), 4_096);
    let bound = GLOAS_SIDECAR_FIXED_PART + 4_096 * GLOAS_BYTES_PER_BLOB;
    assert_eq!(bound, 8_585_272);
    for cap in [
        max_size_for::<Minimal>(KIND, ForkName::Gloas, &NetworkCaps::PRESET_BOUND),
        max_size_for::<Mainnet>(KIND, ForkName::Gloas, &NetworkCaps::PRESET_BOUND),
    ] {
        assert_eq!(cap, Some(bound as usize));
    }
    for network in Network::ALL {
        let caps = NetworkCaps::from_config(&ChainConfig::load(network).unwrap());
        assert!(max_size_for::<Mainnet>(KIND, ForkName::Gloas, &caps).unwrap() < bound as usize);
    }
}

/// Fulu has no sidecar size function; its cap is the type bound of its spec list limits, the
/// same on every network.
#[test]
fn fulu_cap_is_the_type_bound() {
    // 8 + 3 offsets + 208 (signed header) + 4 * 32 (inclusion proof), then 4,096 cells,
    // commitments and proofs.
    let bound = 8 + 3 * 4 + 208 + 4 * 32 + 4_096 * (2_048 + 48 + 48);
    assert_eq!(bound, 8_782_180);
    let full = fulu_sidecar::<Minimal>(4_096, 0).as_ssz_bytes();
    assert_eq!(full.len(), bound);
    for preset_cap in [
        max_size_for::<Minimal>(KIND, ForkName::Fulu, &NetworkCaps::PRESET_BOUND),
        max_size_for::<Mainnet>(KIND, ForkName::Fulu, &NetworkCaps::PRESET_BOUND),
    ] {
        assert_eq!(preset_cap, Some(bound));
    }
    for network in Network::ALL {
        let caps = NetworkCaps::from_config(&ChainConfig::load(network).unwrap());
        assert_eq!(
            max_size_for::<Mainnet>(KIND, ForkName::Fulu, &caps),
            Some(bound)
        );
    }
    assert!(matches!(
        decode_for::<Minimal>(KIND, ForkName::Fulu, &NetworkCaps::PRESET_BOUND, &full).unwrap(),
        Object::DataColumnSidecar(DataColumnSidecar::Fulu(s)) if s.column.len() == 4_096
    ));
}

/// Fulu keeps `MAX_BLOB_COMMITMENTS_PER_BLOCK`, `NUMBER_OF_COLUMNS` and the `LIMIT = 1` of
/// `OptionalPartialDataColumnHeader`.
#[test]
fn fulu_lists_keep_their_spec_bounds() {
    // `kzg_proofs` is the last variable field: one more 48-byte proof is the 4,097th.
    let mut sidecar = fulu_sidecar::<Minimal>(0, 0);
    sidecar.kzg_proofs = vec![[0x22; 48]; 4_096].try_into().unwrap();
    let mut bytes = sidecar.as_ssz_bytes();
    assert!(fulu::DataColumnSidecar::<Minimal>::from_ssz_bytes(&bytes).is_ok());
    bytes.extend_from_slice(&[0x22; 48]);
    assert!(fulu::DataColumnSidecar::<Minimal>::from_ssz_bytes(&bytes).is_err());

    let identifier = |columns: u64| {
        let mut bytes = common::root(1).as_slice().to_vec();
        bytes.extend_from_slice(&36u32.to_le_bytes());
        for c in 0..columns {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        fulu::DataColumnsByRootIdentifier::<Minimal>::from_ssz_bytes(&bytes)
    };
    assert_eq!(identifier(128).unwrap().columns.len(), 128);
    assert!(identifier(129).is_err());

    let header = fulu::PartialDataColumnHeader::<Minimal> {
        kzg_commitments: Default::default(),
        signed_block_header: fulu_sidecar::<Minimal>(0, 0).signed_block_header,
        kzg_commitments_inclusion_proof: FixedVector::from_elem(common::root(4)),
    };
    let partial = |headers: Vec<u8>| {
        let mut bytes = Vec::new();
        // Fixed part: four offsets; the bitmap holds the empty-list delimiter bit.
        for offset in [16u32, 17, 17, 17] {
            bytes.extend_from_slice(&offset.to_le_bytes());
        }
        bytes.push(1);
        bytes.extend_from_slice(&headers);
        fulu::PartialDataColumnSidecar::<Minimal>::from_ssz_bytes(&bytes)
    };
    let one = header.as_ssz_bytes();
    // A list of variable-size headers: one offset per header, then the headers.
    let list = |n: usize| {
        let mut bytes = Vec::new();
        for i in 0..n {
            bytes.extend_from_slice(&((4 * n + i * one.len()) as u32).to_le_bytes());
        }
        for _ in 0..n {
            bytes.extend_from_slice(&one);
        }
        bytes
    };
    assert_eq!(partial(list(1)).unwrap().header[0], header);
    assert!(partial(list(2)).is_err());
}

/// Gloas column lists are unbounded (`ProgressiveList`); only the configured cap limits them.
#[test]
fn gloas_lists_are_bounded_by_the_cap_alone() {
    let mut sidecar = gloas_sidecar::<Mainnet>(0, 0);
    sidecar.kzg_proofs = vec![[0; 48]; 4_097].try_into().unwrap();
    let bytes = sidecar.as_ssz_bytes();
    assert_eq!(
        gloas::DataColumnSidecar::<Mainnet>::from_ssz_bytes(&bytes).unwrap(),
        sidecar
    );
    let caps = NetworkCaps::from_config(&ChainConfig::load(Network::Sepolia).unwrap());
    assert!(matches!(
        decode_for::<Mainnet>(KIND, ForkName::Gloas, &caps, &bytes),
        Err(DecodeError::TooLarge { .. })
    ));
}

#[test]
fn sidecars_decode_by_their_own_slot() {
    let config = ChainConfig::load(Network::Hoodi).unwrap();
    let schedule = config.fork_schedule();
    let caps = NetworkCaps::from_config(&config);
    let fulu_slot = first_slot::<Mainnet>(schedule, ForkName::Fulu);
    let gloas_slot = first_slot::<Mainnet>(schedule, ForkName::Gloas);
    let decode =
        |bytes: &[u8]| DataColumnSidecar::<Mainnet>::from_ssz_bytes_by_slot(bytes, schedule, &caps);

    let fulu = fulu_sidecar::<Mainnet>(2, gloas_slot - 1);
    let decoded = decode(&fulu.as_ssz_bytes()).unwrap();
    assert_eq!(decoded.fork_name(), ForkName::Fulu);
    assert_eq!(decoded.slot(), gloas_slot - 1);
    assert_eq!(decoded, DataColumnSidecar::Fulu(fulu));

    let gloas = gloas_sidecar::<Mainnet>(2, gloas_slot);
    let decoded = decode(&gloas.as_ssz_bytes()).unwrap();
    assert_eq!(decoded.fork_name(), ForkName::Gloas);
    assert_eq!(decoded.slot(), gloas_slot);
    assert_eq!(decoded, DataColumnSidecar::Gloas(gloas));

    // The slot's fork decides the shape: a sidecar of the other fork's shape does not decode.
    let misplaced = gloas_sidecar::<Mainnet>(2, gloas_slot - 1).as_ssz_bytes();
    assert!(matches!(decode(&misplaced), Err(DecodeError::Ssz(_))));
    let misplaced = fulu_sidecar::<Mainnet>(2, gloas_slot).as_ssz_bytes();
    assert!(matches!(decode(&misplaced), Err(DecodeError::Ssz(_))));

    let early = fulu_sidecar::<Mainnet>(1, fulu_slot - 1).as_ssz_bytes();
    assert_eq!(
        decode(&early).unwrap_err(),
        DecodeError::PreFulu {
            slot: fulu_slot - 1
        }
    );

    // Too short to hold the first offset, or a first offset that fits neither shape.
    assert!(matches!(
        decode(&[0; 11]),
        Err(DecodeError::Ssz(ssz::DecodeError::InvalidByteLength { .. }))
    ));
    let mut bytes = gloas_sidecar::<Mainnet>(1, gloas_slot).as_ssz_bytes();
    bytes[8..12].copy_from_slice(&57u32.to_le_bytes());
    assert_eq!(
        decode(&bytes).unwrap_err(),
        DecodeError::Ssz(ssz::DecodeError::OffsetSkipsVariableBytes(57))
    );
    bytes[8..12].copy_from_slice(&12u32.to_le_bytes());
    assert_eq!(
        decode(&bytes).unwrap_err(),
        DecodeError::Ssz(ssz::DecodeError::OffsetIntoFixedPortion(12))
    );
}

#[test]
fn sidecar_kind_exists_in_both_forks() {
    assert!(ObjectKind::ALL.contains(&KIND));
    for fork in ForkName::ALL {
        assert!(KIND.exists_in(fork));
    }
    assert_eq!(DataColumnSidecar::<Minimal>::KIND, KIND);
}

/// A sidecar's cap needs the network's blob schedule, so every entry point without a
/// [`NetworkCaps`] refuses the kind with a typed error; the `_for`/`_with` ones decode it.
#[test]
fn sidecars_need_network_caps() {
    let config = ChainConfig::load(Network::Sepolia).unwrap();
    let caps = NetworkCaps::from_config(&config);
    let schedule = config.fork_schedule();
    let needs = DecodeError::NeedsNetworkCaps { kind: KIND };
    let sidecars = [
        (
            ForkName::Fulu,
            fulu_sidecar::<Mainnet>(2, first_slot::<Mainnet>(schedule, ForkName::Fulu))
                .as_ssz_bytes(),
        ),
        (
            ForkName::Gloas,
            gloas_sidecar::<Mainnet>(2, first_slot::<Mainnet>(schedule, ForkName::Gloas))
                .as_ssz_bytes(),
        ),
    ];
    for (fork, bytes) in sidecars {
        assert_eq!(max_size::<Mainnet>(KIND, fork), None, "{fork}");
        assert_eq!(type_max_len::<Mainnet>(KIND, fork), None, "{fork}");
        assert_eq!(
            check_size::<Mainnet>(KIND, fork, bytes.len()),
            Err(needs.clone())
        );
        assert_eq!(decode::<Mainnet>(KIND, fork, &bytes), Err(needs.clone()));
        assert_eq!(
            DataColumnSidecar::<Mainnet>::from_ssz_bytes_for_fork(&bytes, fork),
            Err(needs.clone())
        );

        assert_eq!(
            check_size_for::<Mainnet>(KIND, fork, &caps, bytes.len()),
            Ok(())
        );
        let decoded = decode_for::<Mainnet>(KIND, fork, &caps, &bytes).unwrap();
        assert!(matches!(decoded, Object::DataColumnSidecar(s) if s.fork_name() == fork));
        let decoded =
            DataColumnSidecar::<Mainnet>::from_ssz_bytes_for_fork_with(&bytes, fork, &caps)
                .unwrap();
        assert_eq!(decoded.fork_name(), fork);
    }
    // Only the sidecar needs them; every other kind keeps its no-config cap.
    for kind in ObjectKind::ALL {
        assert_eq!(kind.needs_network_caps(), kind == KIND, "{kind}");
    }
    assert!(needs.to_string().contains("NetworkCaps"), "{needs}");
}
