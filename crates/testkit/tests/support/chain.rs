//! A minimal-preset Gloas chain from genesis, long enough to cross two epoch boundaries,
//! written as a devnet export. The pinned export in the repo is this chain. A Kurtosis
//! capture of a live enclave is not in the tree.

use blst::min_pk::SecretKey;
use consensus_types::gloas::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{Epoch, Root, Slot};
use consensus_types::signing::{compute_signing_root, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
use consensus_types::{EthSpec, Minimal};
use network_config::ChainConfig;
use sha2::{Digest, Sha256};
use ssz::Encode;
use state_transition::accessors::{get_current_epoch, get_domain};
use state_transition::per_slot::process_slots;
use state_transition::preset::BUILDER_INDEX_SELF_BUILD;
use state_transition::testing::{bid_for_state, block_at_state_slot, genesis_state, signed_block};
use state_transition::{
    state_root, state_transition, AggregationError, BackendError, BlobSchedule, BlsContext,
    PubkeyAggregator, SignatureBackend, SignatureSet,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use testkit::collector::testing::{FixtureServer, Reply};
use testkit::collector::ReferenceApiUrl;
use testkit::export_blocks::fixtures::finalized_header;
use testkit::export_blocks::{export, Export, ExportConfig};
use tree_hash::TreeHash;

/// Validators in the genesis registry. Enough for the minimal proposer lookahead and PTC.
pub const VALIDATORS: usize = 64;
/// Last exported slot. Minimal epochs are 8 slots, so slot 16 crosses the second boundary.
pub const LAST_SLOT: Slot = 16;
/// One empty slot, recorded in the export. Replay advances over it with `process_slots`.
pub const EMPTY_SLOT: Slot = 3;
/// Effective balance of every validator: 32 ETH.
const BALANCE: u64 = 32_000_000_000;

/// The export directory name, and `export.toml`'s `devnet`.
pub const DEVNET: &str = "minimal-gloas";
/// Recorded source. This chain is produced by [`genesis_and_blocks`], not read from a CL.
pub const SOURCE: &str = "replay-fixture";
/// Image reference the export format requires. No container serves it.
pub const IMAGE: &str = "ethswarm/replay-fixture:4.8a@sha256:\
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Gloas from genesis on the minimal preset. Fork versions match the genesis state's fork.
pub const CONFIG: &str = "\
PRESET_BASE: 'minimal'
CONFIG_NAME: 'replay-minimal'
GENESIS_FORK_VERSION: 0x00000001
CAPELLA_FORK_VERSION: 0x03000001
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x06000001
FULU_FORK_EPOCH: 0
GLOAS_FORK_VERSION: 0x07000001
GLOAS_FORK_EPOCH: 0
SLOT_DURATION_MS: 6000
MAX_PAYLOAD_SIZE: 10485760
MAX_BLOBS_PER_BLOCK_ELECTRA: 9
";

/// [`CONFIG`], parsed against its own sha256.
pub fn chain_config() -> ChainConfig {
    let sha: [u8; 32] = Sha256::digest(CONFIG.as_bytes()).into();
    ChainConfig::from_yaml(CONFIG.as_bytes(), &sha).expect("the replay config parses")
}

/// The genesis state and every block from slot 0 through [`LAST_SLOT`], except [`EMPTY_SLOT`].
pub fn genesis_and_blocks() -> (BeaconState<Minimal>, Vec<SignedBeaconBlock<Minimal>>) {
    let keys: Vec<SecretKey> = (0..VALIDATORS as u64).map(secret_key).collect();
    let mut state = genesis_with_keys(&keys);
    let mut genesis = signed_block::<Minimal>(0, 0);
    state.latest_block_header.body_root = genesis.message.body.tree_hash_root();
    genesis.message.state_root = state_root(&mut state).expect("genesis state root");
    genesis.signature = [0; 96];
    let genesis_state = state.clone();
    let config = chain_config();
    let mut blocks = vec![genesis];
    for slot in 1..=LAST_SLOT {
        if slot == EMPTY_SLOT {
            continue;
        }
        let block = next_block(&state, slot, &keys, &config);
        with_bls(&config, |bls| {
            state_transition(&mut state, &block, true, bls).unwrap_or_else(|e| {
                panic!("slot {slot} did not apply: {e}");
            });
        });
        blocks.push(block);
    }
    (genesis_state, blocks)
}

fn genesis_with_keys(keys: &[SecretKey]) -> BeaconState<Minimal> {
    let mut state = genesis_state::<Minimal>(&[BALANCE; VALIDATORS]);
    for (i, sk) in keys.iter().enumerate() {
        state.validators.get_mut(i).expect("registry").pubkey = sk.sk_to_pk().to_bytes();
    }
    // `process_sync_aggregate` maps every current-committee pubkey back to a validator.
    // The testing genesis leaves those keys zero, which no validator has.
    let size = state.current_sync_committee.pubkeys.len();
    let pubkeys: Vec<_> = (0..size)
        .map(|i| state.validators.get(i).expect("committee validator").pubkey)
        .collect();
    let aggregate = aggregate_keys(&pubkeys);
    for (i, pubkey) in pubkeys.iter().enumerate() {
        state.current_sync_committee.pubkeys[i] = *pubkey;
        state.next_sync_committee.pubkeys[i] = *pubkey;
    }
    state.current_sync_committee.aggregate_pubkey = aggregate;
    state.next_sync_committee.aggregate_pubkey = aggregate;
    state.genesis_time = 1_700_000_000;
    state
}

fn aggregate_keys(pubkeys: &[[u8; 48]]) -> [u8; 48] {
    let keys: Vec<_> = pubkeys
        .iter()
        .map(|raw| crypto_bls::PublicKey::from_validated_bytes(raw).expect("validator key"))
        .collect();
    let refs: Vec<_> = keys.iter().collect();
    crypto_bls::eth_aggregate_pubkeys(&refs)
        .expect("aggregate sync committee")
        .to_bytes()
}

/// IKM for validator `index`. Index 0 is not the all-zero IKM.
pub fn secret_key(index: u64) -> SecretKey {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&index.to_le_bytes());
    ikm[8] = 0x42;
    SecretKey::key_gen(&ikm, &[]).expect("32-byte ikm")
}

fn sign(sk: &SecretKey, root: &Root) -> [u8; 96] {
    sk.sign(root.as_slice(), crypto_bls::DST, &[]).to_bytes()
}

fn next_block(
    state: &BeaconState<Minimal>,
    slot: Slot,
    keys: &[SecretKey],
    config: &ChainConfig,
) -> SignedBeaconBlock<Minimal> {
    let mut at = state.clone();
    with_bls(config, |bls| {
        process_slots(&mut at, slot, bls)
            .unwrap_or_else(|e| panic!("process_slots to {slot}: {e}"));
    });
    let mut block = block_at_state_slot(&at);
    let mut bid = bid_for_state(&at, BUILDER_INDEX_SELF_BUILD, 0);
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&slot.to_le_bytes());
    hash[8] = 0xbb;
    bid.message.block_hash = Root::from(hash);
    block.message.body.signed_execution_payload_bid = bid;
    let epoch = get_current_epoch(&at);
    let randao = compute_signing_root(&epoch, get_domain(&at, DOMAIN_RANDAO, None));
    let proposer = block.message.proposer_index;
    block.message.body.randao_reveal = sign(&keys[proposer as usize], &randao);

    let mut post = state.clone();
    with_bls(config, |bls| {
        state_transition(&mut post, &block, false, bls)
            .unwrap_or_else(|e| panic!("slot {slot} produce: {e}"));
    });
    block.message.state_root = state_root(&mut post).expect("post-state root");
    let signing = compute_signing_root(
        &block.message,
        get_domain(&at, DOMAIN_BEACON_PROPOSER, None),
    );
    block.signature = sign(&keys[proposer as usize], &signing);
    block
}

/// Replaces `state_root` with `repeat_byte(0xab)` and re-signs the proposer over that block.
/// The domain comes from `genesis` at the block's epoch (the fork version does not change).
pub fn tamper_state_root(genesis: &BeaconState<Minimal>, block: &mut SignedBeaconBlock<Minimal>) {
    block.message.state_root = Root::repeat_byte(0xab);
    let epoch = Minimal::epoch_at_slot(block.message.slot);
    let domain = get_domain(genesis, DOMAIN_BEACON_PROPOSER, Some(epoch));
    let root = compute_signing_root(&block.message, domain);
    block.signature = sign(&secret_key(block.message.proposer_index), &root);
}

/// Serves the chain on a loopback beacon API and writes `<out>/<DEVNET>/`.
pub async fn export_chain(
    genesis: &BeaconState<Minimal>,
    blocks: &[SignedBeaconBlock<Minimal>],
    out: &Path,
) -> Export {
    let state_ssz = genesis.as_ssz_bytes();
    let state_root = genesis.tree_hash_root();
    let served: BTreeMap<Slot, (Vec<u8>, Root)> = blocks
        .iter()
        .map(|block| {
            (
                block.message.slot,
                (block.as_ssz_bytes(), block.message.tree_hash_root()),
            )
        })
        .collect();
    let finalized = *served
        .keys()
        .next_back()
        .expect("at least the genesis block");
    let finalized_root = served[&finalized].1;
    let server = FixtureServer::start(move |_n, path| {
        reply(
            &state_ssz,
            state_root,
            &served,
            finalized,
            finalized_root,
            path,
        )
    })
    .await;
    let url = ReferenceApiUrl::parse(&format!("http://{}", server.addr)).expect("loopback API");
    let config = chain_config();
    let export_config = ExportConfig {
        devnet: DEVNET.into(),
        source: SOURCE.into(),
        to_slot: finalized,
        images: vec![IMAGE.into()],
        config_sha256: Sha256::digest(CONFIG.as_bytes()).into(),
        request_timeout: Duration::from_secs(10),
        state_timeout: Duration::from_secs(10),
        max_state_bytes: 8 << 20,
    };
    export::<Minimal>(&url, &config, &export_config, out)
        .await
        .unwrap_or_else(|e| panic!("export: {e}"))
}

fn reply(
    state: &[u8],
    state_root: Root,
    blocks: &BTreeMap<Slot, (Vec<u8>, Root)>,
    finalized: Slot,
    finalized_root: Root,
    path: &str,
) -> Reply {
    if path == "/eth/v1/beacon/headers/finalized" {
        return Reply::json(&finalized_header(finalized, finalized_root));
    }
    if path == format!("/eth/v2/debug/beacon/states/{state_root}") {
        return Reply::ssz(state.to_vec());
    }
    if path.starts_with("/eth/v2/debug/beacon/states/") {
        return Reply::status(404);
    }
    if let Some(rest) = path.strip_prefix("/eth/v1/beacon/blocks/") {
        let slot = rest.strip_suffix("/root").and_then(|s| s.parse().ok());
        return match slot.and_then(|s: Slot| blocks.get(&s)) {
            Some((_, root)) => Reply::json(&format!(
                r#"{{"execution_optimistic":false,"finalized":true,"data":{{"root":"{root}"}}}}"#
            )),
            None => Reply::status(404),
        };
    }
    if let Some(rest) = path.strip_prefix("/eth/v2/beacon/blocks/") {
        return match rest.parse().ok().and_then(|s: Slot| blocks.get(&s)) {
            Some((ssz, _)) => Reply::ssz(ssz.clone()),
            None => Reply::status(404),
        };
    }
    Reply::status(400)
}

struct Schedule<'a>(&'a ChainConfig);

impl BlobSchedule for Schedule<'_> {
    fn max_blobs_per_block(&self, epoch: Epoch) -> u64 {
        self.0.get_blob_parameters(epoch).max_blobs_per_block
    }
}

/// `validate_result = false` still aggregates the next sync committee, so the aggregator is
/// real BLS. The backend accepts every set: the fixture's own `state_transition(true)` checks
/// the post-state root, and [`testkit::replay`] checks the signatures.
fn with_bls<R>(config: &ChainConfig, f: impl FnOnce(&BlsContext<'_>) -> R) -> R {
    let schedule = Schedule(config);
    let bls = BlsContext {
        backend: &ACCEPT,
        aggregator: &AGG,
        genesis_fork_version: config.genesis_fork_version(),
        capella_fork_version: config.capella_fork_version().expect("CAPELLA_FORK_VERSION"),
        blob_schedule: &schedule,
    };
    f(&bls)
}

struct Accept;

const ACCEPT: Accept = Accept;

impl SignatureBackend for Accept {
    fn verify_signature_sets(&self, _: &[SignatureSet]) -> Result<bool, BackendError> {
        Ok(true)
    }
}

struct Agg;

const AGG: Agg = Agg;

impl PubkeyAggregator for Agg {
    fn aggregate_pubkeys(
        &self,
        pubkeys: &[consensus_types::primitives::BLSPubkey],
    ) -> Result<consensus_types::primitives::BLSPubkey, AggregationError> {
        let mut keys = Vec::with_capacity(pubkeys.len());
        for raw in pubkeys {
            keys.push(
                crypto_bls::PublicKey::from_validated_bytes(raw)
                    .map_err(|e| AggregationError(e.to_string()))?,
            );
        }
        let refs: Vec<&crypto_bls::PublicKey> = keys.iter().collect();
        crypto_bls::eth_aggregate_pubkeys(&refs)
            .map(|sum| sum.to_bytes())
            .map_err(|e| AggregationError(e.to_string()))
    }
}
