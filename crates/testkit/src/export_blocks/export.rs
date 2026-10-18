//! [`export`]: read a devnet's blocks from genesis to an export slot, cross-check them, and
//! write them as an archive segment with an `export.toml`.

use super::api::{BeaconApi, BLOCK_ROOT_PATH};
use super::manifest::{
    validate_image, validate_label, BlockEntry, DigestEntry, ExportManifest, ExportManifestError,
    ForkEntry, SegmentEntry, StateFile, EXPORT_FILE, GENESIS_STATE_FILE, MAX_SOURCE_LEN,
};
use super::open::{open_export, Export};
use super::ExportError;
use crate::archive::{
    create_dir_new_durable, open_verified, validate_network, write_durable, ArchiveError, Capture,
    CaptureConfig, ChainParams, ForkDigest, Writer, MAX_MANIFEST_LEN,
};
use crate::collector::{ApiError, ReferenceApiUrl};
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
/// The largest genesis state an export reads, writes or opens: 256 MiB, far above a devnet's
/// (a minimal-preset state of 128 validators is well under 1 MiB) and a mainnet-preset state
/// of a few hundred thousand validators. [`ExportConfig::max_state_bytes`] may lower it, never
/// raise it, and [`open_export`] refuses a larger file before reading it.
pub const MAX_GENESIS_STATE_BYTES: u64 = 256 << 20;
/// The default bound on the genesis state: [`MAX_GENESIS_STATE_BYTES`].
pub const DEFAULT_MAX_STATE_BYTES: usize = MAX_GENESIS_STATE_BYTES as usize;

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
    /// The most genesis state bytes read: at most [`MAX_GENESIS_STATE_BYTES`].
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
/// block and the genesis state by that block's `state_root` (it must hash to it), claims `<out>/<devnet>` with an exclusive `mkdir` (a second export into it fails
/// with [`ExportError::Exists`] before writing anything), then walks every slot from 0 to the
/// finalized one. A slot is empty only when both its block and its root answer 404; a block is
/// decoded with the fork of its own slot, must be at the slot asked for, must hash to the API's
/// root for that slot, and must have the previous block as its parent (the genesis block a zero
/// parent and the genesis state's root as its `state_root`). The blocks to the export slot go
/// into an archive segment as snappy-compressed SSZ; the ones after it are only checked, and
/// the walk must end on the finalized header's block, so the export, its trailing empty slots
/// included, is a prefix of the finalized chain. This reads every block between the export slot
/// and the finalized one. Then the genesis state and, last, `export.toml` are written. Any
/// failure stops the export: the segment is sealed as stopped and no `export.toml` is written,
/// so the directory never opens as an export.
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
    let (finalized, finalized_root) = api.finalized().await?;
    if config.to_slot > finalized {
        return Err(ExportError::NotFinalized {
            to: config.to_slot,
            finalized,
        });
    }
    let Some(genesis_block) = fetch_block::<E>(&api, chain, 0).await? else {
        return Err(ExportError::Genesis(
            "the API has no block at slot 0".into(),
        ));
    };
    let genesis = read_genesis::<E>(&api, chain, config, genesis_block.state_root).await?;
    let digests: Vec<(Epoch, ForkDigest)> = digest_schedule(chain, &genesis.validators_root.0)
        .into_iter()
        .map(|d| (d.epoch, d.fork_digest))
        .collect();
    // Claimed before anything is written: a second export into the directory fails here.
    match create_dir_new_durable(&dir) {
        Err(ArchiveError::Io { source, .. }) if source.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ExportError::Exists(dir))
        }
        claimed => claimed?,
    }
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
    let walk = Walk {
        api: &api,
        chain,
        to: config.to_slot,
        finalized,
        finalized_root,
        genesis: &genesis,
        digests: &digests,
    };
    let walked = walk.run(&mut writer).await;
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
    let path = dir.join(EXPORT_FILE);
    let (bytes, _) = manifest.render().map_err(|source| ExportError::Manifest {
        path: path.clone(),
        source,
    })?;
    check_manifest_len(&path, &bytes, MAX_MANIFEST_LEN)?;
    write_durable(&dir, EXPORT_FILE, &bytes, None, &mut None)?;
    open_export(&dir)
}

/// The manifest is at most `max` bytes, the bound [`open_export`] reads one to, so an export
/// it would refuse is never written.
pub(super) fn check_manifest_len(path: &Path, bytes: &[u8], max: u64) -> Result<(), ExportError> {
    if bytes.len() as u64 > max {
        return Err(ExportError::Manifest {
            path: path.to_owned(),
            source: ExportManifestError::Invalid(format!(
                "{} bytes, over {max} bytes",
                bytes.len()
            )),
        });
    }
    Ok(())
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
    if config.max_state_bytes as u64 > MAX_GENESIS_STATE_BYTES {
        return refuse(format!(
            "max_state_bytes {} is over {MAX_GENESIS_STATE_BYTES}, the most an export opens",
            config.max_state_bytes
        ));
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

/// Reads the genesis state by `state_root`, the genesis block's, decodes it with the fork of
/// slot 0 and checks it is at slot 0 and hashes to `state_root`.
async fn read_genesis<E: EthSpec>(
    api: &BeaconApi<'_>,
    chain: &ChainConfig,
    config: &ExportConfig,
    state_root: Root,
) -> Result<Genesis, ExportError> {
    let ssz = api
        .state_by_root(state_root, config.max_state_bytes, config.state_timeout)
        .await?
        .ok_or_else(|| {
            ExportError::Genesis(format!(
                "the API has no state at the slot 0 block's state_root {state_root}"
            ))
        })?;
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
    let root = state.tree_hash_root();
    if root != state_root {
        return Err(ExportError::Genesis(format!(
            "the state served for the slot 0 block's state_root {state_root} hashes to {root}"
        )));
    }
    Ok(Genesis {
        root,
        ssz,
        time,
        validators_root,
    })
}

/// The digest of `digests` (ascending by epoch) in force at `slot`.
pub(super) fn digest_at<E: EthSpec>(
    digests: &[(Epoch, ForkDigest)],
    slot: Slot,
) -> Option<ForkDigest> {
    let epoch = E::epoch_at_slot(slot);
    digests
        .iter()
        .rev()
        .find(|(from, _)| *from <= epoch)
        .map(|(_, d)| *d)
}

/// The block at `slot` continues the chain walked so far: the genesis block has a zero
/// parent and the genesis state's root; every later one has the last block before it (`tip`,
/// across any empty slots) as its parent.
pub(super) fn check_parent(
    tip: Option<&BlockEntry>,
    slot: Slot,
    parent_root: Root,
    state_root: Root,
    genesis_state_root: Root,
) -> Result<(), ExportError> {
    let Some(previous) = tip else {
        if parent_root != Root::ZERO {
            return Err(ExportError::Genesis(format!(
                "the slot 0 block's parent {parent_root} is not zero"
            )));
        }
        if state_root != genesis_state_root {
            return Err(ExportError::Genesis(format!(
                "the slot 0 block's state_root {state_root} is not the genesis state's root \
                 {genesis_state_root}"
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

/// A block as read and checked: its SSZ and its entry; and its `state_root`.
struct Fetched {
    ssz: bytes::Bytes,
    entry: BlockEntry,
    state_root: Root,
}

/// The slot walk: from genesis to the finalized block, the export slot's blocks archived.
struct Walk<'a> {
    api: &'a BeaconApi<'a>,
    chain: &'a ChainConfig,
    /// The export slot.
    to: Slot,
    /// The finalized header's slot.
    finalized: Slot,
    /// The finalized header's root.
    finalized_root: Root,
    genesis: &'a Genesis,
    digests: &'a [(Epoch, ForkDigest)],
}

impl Walk<'_> {
    /// Every slot from 0 to the finalized one is fetched, decoded and cross-checked, and the
    /// chain must end on the finalized block; the slots to the export slot are archived. The
    /// slots after the export slot anchor its trailing empty slots: the first block after them
    /// has the last exported block as its parent, and so on up to the finalized block.
    async fn run<E: EthSpec>(&self, writer: &mut Writer<E>) -> Result<Walked, ExportError> {
        let mut walked = Walked {
            blocks: Vec::new(),
            empty_slots: Vec::new(),
        };
        let mut tip: Option<BlockEntry> = None;
        for slot in 0..=self.finalized {
            let Some(block) = self.fetch::<E>(slot).await? else {
                if slot == 0 {
                    return Err(ExportError::Genesis(
                        "the API has no block at slot 0".into(),
                    ));
                }
                if slot <= self.to {
                    walked.empty_slots.push(slot);
                }
                continue;
            };
            let entry = block.entry;
            check_parent(
                tip.as_ref(),
                slot,
                entry.parent_root,
                block.state_root,
                self.genesis.root,
            )?;
            if slot <= self.to {
                self.archive(writer, slot, &block.ssz)?;
                walked.blocks.push(entry);
            }
            tip = Some(entry);
        }
        let tip = tip.expect("slot 0 has a block");
        if (tip.slot, tip.root) != (self.finalized, self.finalized_root) {
            return Err(ExportError::FinalizedMismatch {
                slot: self.finalized,
                root: self.finalized_root,
                chain_slot: tip.slot,
                chain_root: tip.root,
            });
        }
        Ok(walked)
    }

    /// [`fetch_block`] from this walk's API and chain.
    async fn fetch<E: EthSpec>(&self, slot: Slot) -> Result<Option<Fetched>, ExportError> {
        fetch_block::<E>(self.api, self.chain, slot).await
    }

    /// Files the block's SSZ, snappy-compressed, under the digest in force at its slot.
    fn archive<E: EthSpec>(
        &self,
        writer: &mut Writer<E>,
        slot: Slot,
        ssz: &[u8],
    ) -> Result<(), ExportError> {
        let digest = digest_at::<E>(self.digests, slot).ok_or_else(|| {
            ExportError::Config(format!("the config has no fork digest at slot {slot}"))
        })?;
        let payload = snap::raw::Encoder::new()
            .compress_vec(ssz)
            .map_err(|e| ExportError::Config(format!("slot {slot}: snappy: {e}")))?;
        writer.put(Capture {
            topic: BLOCK_TOPIC,
            fork_digest: digest,
            payload: &payload,
        })?;
        Ok(())
    }
}

/// The block at `slot`, decoded with the fork of its slot, at that slot and hashing to
/// the API's root for it; `None` when both the block and the root endpoint answer 404.
async fn fetch_block<E: EthSpec>(
    api: &BeaconApi<'_>,
    chain: &ChainConfig,
    slot: Slot,
) -> Result<Option<Fetched>, ExportError> {
    let Some(ssz) = api.block(slot, MAX_PAYLOAD_SIZE).await? else {
        return match api.block_root(slot).await? {
            None => Ok(None),
            Some(root) => Err(ExportError::HiddenBlock { slot, root }),
        };
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
    let (root, parent_root, state_root) = block_fields(&block);
    let api_root = api.block_root(slot).await?.ok_or(ExportError::Api {
        slot: Some(slot),
        source: ApiError::Status {
            path: BLOCK_ROOT_PATH,
            status: 404,
        },
    })?;
    if api_root != root {
        return Err(ExportError::RootMismatch {
            slot,
            api: api_root,
            computed: root,
        });
    }
    Ok(Some(Fetched {
        ssz,
        entry: BlockEntry {
            slot,
            root,
            parent_root,
        },
        state_root,
    }))
}

/// `hash_tree_root(message)`, `parent_root` and `state_root` of a block.
pub(super) fn block_fields<E: EthSpec>(block: &SignedBeaconBlock<E>) -> (Root, Root, Root) {
    match block {
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
    }
}
