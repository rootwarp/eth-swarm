//! [`export`]: read a devnet's blocks from genesis to an export slot, cross-check them, and
//! write them as an archive segment with an `export.toml`.

use super::api::BeaconApi;
use super::manifest::{
    validate_image, validate_label, BlockEntry, DigestEntry, ExportManifest, ForkEntry,
    SegmentEntry, StateFile, EXPORT_FILE, GENESIS_STATE_FILE, MAX_SOURCE_LEN,
};
use super::open::{open_export, Export};
use super::ExportError;
use crate::archive::{
    open_verified, validate_network, write_durable, Capture, CaptureConfig, ChainParams,
    ForkDigest, Writer,
};
use crate::collector::ReferenceApiUrl;
use consensus_types::caps::{NetworkCaps, MAX_PAYLOAD_SIZE};
use consensus_types::forked::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{Epoch, ForkName, Root, Slot};
use consensus_types::EthSpec;
use network_config::digest::digest_schedule;
use network_config::ChainConfig;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;
use tree_hash::TreeHash;

/// The archive topic the blocks are filed under.
pub const BLOCK_TOPIC: &str = "beacon_block";
/// The `clock_source` of an export's segments: blocks were read from the API, not captured.
pub const EXPORT_CLOCK_SOURCE: &str = "beacon-api";
/// The default deadline of one block or root request.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The default deadline of the genesis state request.
pub const DEFAULT_STATE_TIMEOUT: Duration = Duration::from_secs(300);
/// The default bound on the genesis state: 256 MiB, far above a devnet's (a minimal-preset
/// state of 128 validators is well under 1 MiB) and a mainnet-preset state of a few hundred
/// thousand validators.
pub const DEFAULT_MAX_STATE_BYTES: usize = 256 << 20;

/// What an export reads and records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportConfig {
    /// The devnet name: the export directory `<out>/<devnet>` and the archive's network.
    pub devnet: String,
    /// The CL the API belongs to (e.g. `cl-1-lighthouse-geth`), for the manifest.
    pub source: String,
    /// The export slot: blocks from genesis through it are exported. It must be at or before
    /// the source's finalized block.
    pub to_slot: Slot,
    /// The devnet's images, `repo:tag@sha256:<digest>`; sorted and deduplicated on export.
    pub images: Vec<String>,
    /// sha256 of the devnet `config.yaml` the [`ChainConfig`] was read from.
    pub config_sha256: [u8; 32],
    /// The deadline of each block, root and header request.
    pub request_timeout: Duration,
    /// The deadline of the genesis state request.
    pub state_timeout: Duration,
    /// The most genesis state bytes read.
    pub max_state_bytes: usize,
}

/// The genesis state as read and checked.
struct Genesis {
    ssz: bytes::Bytes,
    root: Root,
    time: u64,
    validators_root: Root,
}

/// What the slot walk found.
struct Walked {
    blocks: Vec<BlockEntry>,
    empty_slots: Vec<Slot>,
}

/// Exports the devnet behind `url` into `<out>/<devnet>/` and returns it opened through
/// [`open_export`].
///
/// It reads the finalized header (the export slot must be at or before it), then the genesis
/// state, then every slot from 0 to the export slot: a 404 records the slot as empty; a block is
/// decoded with the fork of its own slot, must be at the slot asked for, must hash to the API's
/// root for that slot, and must have the previous exported block as its parent (the genesis
/// block a zero parent and the genesis state's root as its `state_root`). The blocks go into an
/// archive segment as snappy-compressed SSZ, then the genesis state and, last, `export.toml`
/// are written. Any failure stops the export: the segment is sealed as stopped and no
/// `export.toml` is written, so the directory never opens as an export.
pub async fn export<E: EthSpec>(
    url: &ReferenceApiUrl,
    chain: &ChainConfig,
    config: &ExportConfig,
    out: &Path,
) -> Result<Export, ExportError> {
    let mut images = config.images.clone();
    images.sort();
    images.dedup();
    check_config::<E>(chain, config, &images)?;
    let dir = out.join(&config.devnet);
    match fs::symlink_metadata(&dir) {
        Ok(_) => return Err(ExportError::Exists(dir)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(ExportError::io(&dir)(e)),
    }
    let api = BeaconApi::new(url, config.request_timeout);
    let finalized = api.finalized_slot().await?;
    if config.to_slot > finalized {
        return Err(ExportError::NotFinalized {
            to: config.to_slot,
            finalized,
        });
    }
    let genesis = read_genesis::<E>(&api, chain, config).await?;
    let digests: Vec<(Epoch, ForkDigest)> = digest_schedule(chain, &genesis.validators_root.0)
        .into_iter()
        .map(|d| (d.epoch, d.fork_digest))
        .collect();
    let params = ChainParams {
        schedule: *chain.fork_schedule(),
        caps: NetworkCaps::from_config(chain),
    };
    let mut writer = Writer::<E>::create(
        out,
        CaptureConfig {
            network: config.devnet.clone(),
            topics: vec![BLOCK_TOPIC.into()],
            capture_host: config.source.clone(),
            clock_source: EXPORT_CLOCK_SOURCE.into(),
            // One window over the whole export: a segment rolls only on its manifest's size.
            slots_per_segment: config.to_slot + 1,
            // Bounded by the slot count: at most one block of MAX_PAYLOAD_SIZE per slot.
            max_bytes: u64::MAX,
            fork_digests: digests.clone(),
        },
        params,
    )?;
    let walked = walk::<E>(&api, &mut writer, chain, config.to_slot, &genesis, &digests).await;
    let walked = match walked {
        Ok(walked) => walked,
        Err(e) => {
            writer.stop(e.to_string());
            let _ = writer.close();
            return Err(e);
        }
    };
    let mut segments = Vec::new();
    for segment in writer.close()? {
        let archive = open_verified(&segment)?;
        let name = segment
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        segments.push(SegmentEntry {
            dir: name,
            archive_sha256: archive.archive_sha256(),
        });
    }
    write_durable(&dir, GENESIS_STATE_FILE, &genesis.ssz, None, &mut None)?;
    let end_epoch = E::epoch_at_slot(config.to_slot);
    let manifest = ExportManifest {
        devnet: config.devnet.clone(),
        source: config.source.clone(),
        preset: E::NAME.into(),
        slot_start: 0,
        slot_end: config.to_slot,
        finalized_slot: finalized,
        config_sha256: config.config_sha256,
        genesis_time: genesis.time,
        genesis_validators_root: genesis.validators_root,
        genesis_block_root: walked.blocks[0].root,
        genesis_state_root: genesis.root,
        images,
        empty_slots: walked.empty_slots,
        genesis_state: StateFile {
            path: GENESIS_STATE_FILE.into(),
            len: genesis.ssz.len() as u64,
            sha256: Sha256::digest(&genesis.ssz).into(),
        },
        fork_schedule: ForkName::ALL
            .into_iter()
            .filter_map(|fork| {
                let schedule = chain.fork_schedule();
                schedule.fork_epoch(fork).map(|epoch| ForkEntry {
                    fork,
                    version: schedule.fork_version(fork),
                    epoch,
                })
            })
            .collect(),
        fork_digests: digests
            .iter()
            .filter(|(epoch, _)| *epoch <= end_epoch)
            .map(|&(epoch, digest)| DigestEntry { epoch, digest })
            .collect(),
        segments,
        blocks: walked.blocks,
    };
    let (bytes, _) = manifest.render().map_err(|source| ExportError::Manifest {
        path: dir.join(EXPORT_FILE),
        source,
    })?;
    write_durable(&dir, EXPORT_FILE, &bytes, None, &mut None)?;
    open_export(&dir)
}

fn check_config<E: EthSpec>(
    chain: &ChainConfig,
    config: &ExportConfig,
    images: &[String],
) -> Result<(), ExportError> {
    let refuse = |m: String| Err(ExportError::Config(m));
    if chain.preset_base() != E::NAME {
        return refuse(format!(
            "the config's preset is {:?}, the export decodes with {:?}",
            chain.preset_base(),
            E::NAME
        ));
    }
    if config.to_slot > i64::MAX as u64 {
        return refuse(format!("export slot {} is out of range", config.to_slot));
    }
    if images.is_empty() {
        return refuse("name the devnet's images (repo:tag@sha256:<digest>)".into());
    }
    for image in images {
        validate_image(image).map_err(|e| ExportError::Config(e.to_string()))?;
    }
    validate_label("source", &config.source, MAX_SOURCE_LEN)
        .map_err(|e| ExportError::Config(e.to_string()))?;
    validate_network(&config.devnet).map_err(|e| ExportError::Config(e.to_string()))?;
    Ok(())
}

/// Reads the genesis state, decodes it with the fork of slot 0 and checks it is at slot 0.
async fn read_genesis<E: EthSpec>(
    api: &BeaconApi<'_>,
    chain: &ChainConfig,
    config: &ExportConfig,
) -> Result<Genesis, ExportError> {
    let ssz = api
        .genesis_state(config.max_state_bytes, config.state_timeout)
        .await?;
    let state = BeaconState::<E>::from_ssz_bytes_by_slot(&ssz, chain.fork_schedule()).map_err(
        |source| ExportError::Decode {
            what: "genesis state",
            slot: None,
            source,
        },
    )?;
    if state.slot() != 0 {
        return Err(ExportError::SlotMismatch {
            what: "genesis state",
            requested: 0,
            got: state.slot(),
        });
    }
    let (time, validators_root) = match &state {
        BeaconState::Fulu(s) => (s.genesis_time, s.genesis_validators_root),
        BeaconState::Gloas(s) => (s.genesis_time, s.genesis_validators_root),
    };
    Ok(Genesis {
        root: state.tree_hash_root(),
        ssz,
        time,
        validators_root,
    })
}

/// The digest of `digests` (ascending by epoch) in force at `slot`.
fn digest_at<E: EthSpec>(digests: &[(Epoch, ForkDigest)], slot: Slot) -> Option<ForkDigest> {
    let epoch = E::epoch_at_slot(slot);
    digests
        .iter()
        .rev()
        .find(|(from, _)| *from <= epoch)
        .map(|(_, d)| *d)
}

/// The block at `slot` continues the chain exported so far: the genesis block has a zero
/// parent and the genesis state's root; every later one has the last exported block, before
/// any empty slots, as its parent.
fn check_parent(
    exported: &[BlockEntry],
    slot: Slot,
    parent_root: Root,
    state_root: Root,
    genesis: &Genesis,
) -> Result<(), ExportError> {
    let Some(previous) = exported.last() else {
        if parent_root != Root::ZERO {
            return Err(ExportError::Genesis(format!(
                "the slot 0 block's parent {parent_root} is not zero"
            )));
        }
        if state_root != genesis.root {
            return Err(ExportError::Genesis(format!(
                "the slot 0 block's state_root {state_root} is not the genesis state's root {}",
                genesis.root
            )));
        }
        return Ok(());
    };
    if parent_root != previous.root {
        return Err(ExportError::ParentMismatch {
            slot,
            parent_root,
            expected_slot: previous.slot,
            expected: previous.root,
        });
    }
    Ok(())
}

/// Every slot from 0 to `to`: fetched, decoded, cross-checked and archived.
async fn walk<E: EthSpec>(
    api: &BeaconApi<'_>,
    writer: &mut Writer<E>,
    chain: &ChainConfig,
    to: Slot,
    genesis: &Genesis,
    digests: &[(Epoch, ForkDigest)],
) -> Result<Walked, ExportError> {
    let mut walked = Walked {
        blocks: Vec::new(),
        empty_slots: Vec::new(),
    };
    for slot in 0..=to {
        let Some(ssz) = api.block(slot, MAX_PAYLOAD_SIZE).await? else {
            if slot == 0 {
                return Err(ExportError::Genesis(
                    "the API has no block at slot 0".into(),
                ));
            }
            walked.empty_slots.push(slot);
            continue;
        };
        let block = SignedBeaconBlock::<E>::from_ssz_bytes_by_slot(&ssz, chain.fork_schedule())
            .map_err(|source| ExportError::Decode {
                what: "block",
                slot: Some(slot),
                source,
            })?;
        if block.slot() != slot {
            return Err(ExportError::SlotMismatch {
                what: "block",
                requested: slot,
                got: block.slot(),
            });
        }
        let (root, parent_root, state_root) = match &block {
            SignedBeaconBlock::Fulu(b) => (
                b.message.tree_hash_root(),
                b.message.parent_root,
                b.message.state_root,
            ),
            SignedBeaconBlock::Gloas(b) => (
                b.message.tree_hash_root(),
                b.message.parent_root,
                b.message.state_root,
            ),
        };
        let api_root = api.block_root(slot).await?;
        if api_root != root {
            return Err(ExportError::RootMismatch {
                slot,
                api: api_root,
                computed: root,
            });
        }
        check_parent(&walked.blocks, slot, parent_root, state_root, genesis)?;
        let digest = digest_at::<E>(digests, slot).ok_or_else(|| {
            ExportError::Config(format!("the config has no fork digest at slot {slot}"))
        })?;
        let payload = snap::raw::Encoder::new()
            .compress_vec(&ssz)
            .map_err(|e| ExportError::Config(format!("slot {slot}: snappy: {e}")))?;
        writer.put(Capture {
            topic: BLOCK_TOPIC,
            fork_digest: digest,
            payload: &payload,
        })?;
        walked.blocks.push(BlockEntry {
            slot,
            root,
            parent_root,
        });
    }
    Ok(walked)
}
