//! Resolve, fetch and check a checkpoint anchor from two providers.
//!
//! The rule: take one finalized block root that two providers run by different operators
//! agree on, then fetch the block and the state by root, or abort. Equality is the fork-choice
//! anchor condition `anchor_block.state_root == hash_tree_root(anchor_state)`.
//!
//! 1. **Resolve.** `GET /eth/v1/beacon/states/finalized/finality_checkpoints` on both. The
//!    candidate is the root of the lower finalized epoch (equal epochs with different roots:
//!    [`AnchorError::ProvidersDisagree`]). Both providers must return the same canonical
//!    `GET /eth/v1/beacon/headers/{root}`. Every later request is by root, so a `finalized`
//!    alias that moves during the run cannot mix two anchors.
//! 2. **Fetch.** The block from A (`/eth/v2/beacon/blocks/{root}`) and the state from B
//!    (`/eth/v2/debug/beacon/states/{state_root}`), both SSZ with `Eth-Consensus-Version:
//!    gloas`, so no single provider supplies both. Bodies stream into `<out>/quarantine/` under
//!    the byte cap ([`crate::checkpoint::http`]).
//! 3. **Check.** `hash_tree_root(block.message) == root`; `block.message.state_root` equals
//!    the headers' `state_root` (and the other header fields match the block); the state is the
//!    post-block state (its slot is the block's and its `latest_block_header` is the block's
//!    with a zero `state_root`, not an epoch-boundary state); `hash_tree_root(state) ==
//!    state_root`, after `apply_updates()` on every milhouse field.
//! 4. **Write.** The run log must name both providers ([`runlog::verify`]); then [`publish`]
//!    hard-links `block.ssz` and `state.ssz` out of quarantine and `anchor.json` from a new,
//!    uniquely named, fsynced temp file, none of them replacing an existing file, and fsyncs
//!    the directory. A failed step removes what was published, and a crash never leaves a
//!    partial `anchor.json`.
//!
//! The run holds an exclusive `flock` on `<out>/.lock` from before the run log is opened until
//! publication, so two runs never share an output directory; each run also streams into its
//! own `quarantine/<random>/`.
//!
//! Any failure aborts with a named [`AnchorError`], deletes the quarantined bodies, records an
//! `abort` line in the run log, and writes no `anchor.json`.
//!
//! The SSZ is decoded with the Gloas shape, the fork this fetcher requests; a response that
//! names another fork in `Eth-Consensus-Version` is refused ([`AnchorError::WrongFork`]).

use crate::checkpoint::api::{Checkpoint, FinalityResponse, HeaderResponse};
use crate::checkpoint::config::{Config, Provider};
use crate::checkpoint::http::{Client, Download};
use crate::checkpoint::runlog::{self, RunLog, RunLogError};
use consensus_types::common::BeaconBlockHeader;
use consensus_types::primitives::Root;
use consensus_types::{forked, gloas, EthSpec, ForkName};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tree_hash::TreeHash;

/// The anchor record, in the output directory.
pub const ANCHOR_FILE: &str = "anchor.json";
/// The run log, in the output directory (appended to on every run).
pub const RUN_LOG_FILE: &str = "run.log";
/// The anchor block's SSZ, in the output directory.
pub const BLOCK_FILE: &str = "block.ssz";
/// The anchor state's SSZ, in the output directory.
pub const STATE_FILE: &str = "state.ssz";
/// Where bodies are streamed before they pass every check: each run gets its own
/// `quarantine/<random>/` (mode 0700), removed when the run ends.
pub const QUARANTINE_DIR: &str = "quarantine";
/// `flock`ed by the run that owns the output directory, from before the run log is opened
/// until the anchor is published. Never deleted, so the lock is always on one inode.
pub const LOCK_FILE: &str = ".lock";

/// The fork this fetcher requests and decodes.
const FORK: ForkName = ForkName::Gloas;
const FINALITY_PATH: &str = "/eth/v1/beacon/states/finalized/finality_checkpoints";

/// Why an anchor fetch aborted. [`AnchorError::name`] is the name written to the run log and
/// printed by the binary; [`AnchorError::exit_code`] is never 0.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// The config is malformed.
    #[error("config: {0}")]
    Config(String),
    /// Both providers name the same operator.
    #[error("providers {a} and {b} are both run by operator {operator:?}")]
    SameOperator {
        a: String,
        b: String,
        operator: String,
    },
    /// Both providers sit on the same host.
    #[error("providers {a} and {b} share the host {host:?}")]
    SameHost { a: String, b: String, host: String },
    /// The output directory already holds an anchor, block or state.
    #[error("{} already exists; an anchor is never replaced", path.display())]
    OutputExists { path: PathBuf },
    /// Another run holds the output directory's lock.
    #[error("{} is in use by another anchor-fetch run", path.display())]
    OutDirBusy { path: PathBuf },
    /// The request did not complete: connect, TLS or HTTP failure.
    #[error("{provider}: GET {path}: {reason}")]
    Transport {
        provider: String,
        path: String,
        reason: String,
    },
    /// The request or its body timed out.
    #[error("{provider}: GET {path}: timed out")]
    Timeout { provider: String, path: String },
    /// The provider answered with a status other than 200.
    #[error("{provider}: GET {path}: HTTP {status}")]
    HttpStatus {
        provider: String,
        path: String,
        status: u16,
    },
    /// The response is not what the beacon API specifies, or not about the asked-for object.
    #[error("{provider}: GET {path}: {reason}")]
    BadResponse {
        provider: String,
        path: String,
        reason: String,
    },
    /// The body is over the cap: by its `Content-Length` (nothing was read) or while reading
    /// (the partial file was deleted).
    #[error("{provider}: GET {path}: body over the {limit}-byte cap (Content-Length {content_length:?})")]
    BodyTooLarge {
        provider: String,
        path: String,
        limit: u64,
        content_length: Option<u64>,
    },
    /// The providers do not agree on the finalized root or its header.
    #[error("providers disagree: {0}")]
    ProvidersDisagree(String),
    /// A provider reports the candidate block as not canonical.
    #[error("{provider}: block {root} is not canonical")]
    NotCanonical { provider: String, root: Root },
    /// The response's `Eth-Consensus-Version` is not the requested fork; its body was not read.
    #[error("{provider}: GET {path}: Eth-Consensus-Version {got:?}, expected {expected}")]
    WrongFork {
        provider: String,
        path: String,
        expected: String,
        got: String,
    },
    /// A body is not valid Gloas SSZ.
    #[error("{what}: {reason}")]
    Decode { what: &'static str, reason: String },
    /// `hash_tree_root(block.message)` is not the agreed root.
    #[error("block root mismatch: hash_tree_root(block.message) is {got}, expected {expected}")]
    BlockRootMismatch { expected: Root, got: Root },
    /// `block.message.state_root` is not the headers' `state_root`.
    #[error("header state_root mismatch: the headers say {header}, the block says {block}")]
    HeaderStateRootMismatch { header: Root, block: Root },
    /// Another header field is not the block's.
    #[error("the agreed header's {field} is not the block's")]
    HeaderBlockMismatch { field: &'static str },
    /// The state is not the block's post-block state (e.g. an epoch-boundary state).
    #[error("the state is not the block's post-block state: {reason}")]
    StateNotPostBlock { reason: String },
    /// `hash_tree_root(state)` is not the agreed `state_root`.
    #[error("state root mismatch: hash_tree_root(state) is {got}, expected {expected}")]
    StateRootMismatch { expected: Root, got: Root },
    /// A run log does not name both providers.
    #[error("run log: {0}")]
    RunLog(#[from] RunLogError),
    /// A local file operation failed.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
}

impl AnchorError {
    /// The error's name in the run log and on stderr.
    pub fn name(&self) -> &'static str {
        match self {
            AnchorError::Config(_) => "config",
            AnchorError::SameOperator { .. } => "same_operator",
            AnchorError::SameHost { .. } => "same_host",
            AnchorError::OutputExists { .. } => "output_exists",
            AnchorError::OutDirBusy { .. } => "out_dir_busy",
            AnchorError::Transport { .. } => "transport",
            AnchorError::Timeout { .. } => "timeout",
            AnchorError::HttpStatus { .. } => "http_status",
            AnchorError::BadResponse { .. } => "bad_response",
            AnchorError::BodyTooLarge { .. } => "body_too_large",
            AnchorError::ProvidersDisagree(_) => "providers_disagree",
            AnchorError::NotCanonical { .. } => "not_canonical",
            AnchorError::WrongFork { .. } => "wrong_fork",
            AnchorError::Decode { .. } => "decode",
            AnchorError::BlockRootMismatch { .. } => "block_root_mismatch",
            AnchorError::HeaderStateRootMismatch { .. } => "header_state_root_mismatch",
            AnchorError::HeaderBlockMismatch { .. } => "header_block_mismatch",
            AnchorError::StateNotPostBlock { .. } => "state_not_post_block",
            AnchorError::StateRootMismatch { .. } => "state_root_mismatch",
            AnchorError::RunLog(_) => "run_log",
            AnchorError::Io { .. } => "io",
        }
    }

    /// The process exit code: 1 a provider served something that fails a check, 2 the config
    /// or output directory is refused, 3 a provider could not be reached or refused the
    /// request, 4 a local I/O or run-log failure.
    pub fn exit_code(&self) -> u8 {
        match self {
            AnchorError::Config(_)
            | AnchorError::SameOperator { .. }
            | AnchorError::SameHost { .. }
            | AnchorError::OutputExists { .. }
            | AnchorError::OutDirBusy { .. } => 2,
            AnchorError::Transport { .. }
            | AnchorError::Timeout { .. }
            | AnchorError::HttpStatus { .. } => 3,
            AnchorError::RunLog(_) | AnchorError::Io { .. } => 4,
            AnchorError::BadResponse { .. }
            | AnchorError::BodyTooLarge { .. }
            | AnchorError::ProvidersDisagree(_)
            | AnchorError::NotCanonical { .. }
            | AnchorError::WrongFork { .. }
            | AnchorError::Decode { .. }
            | AnchorError::BlockRootMismatch { .. }
            | AnchorError::HeaderStateRootMismatch { .. }
            | AnchorError::HeaderBlockMismatch { .. }
            | AnchorError::StateNotPostBlock { .. }
            | AnchorError::StateRootMismatch { .. } => 1,
        }
    }
}

/// A provider, as recorded in `anchor.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRecord {
    /// `a` (block) or `b` (state).
    pub role: String,
    pub name: String,
    pub operator: String,
    pub url: String,
}

/// A downloaded body, as recorded in `anchor.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    /// File name in the output directory.
    pub file: String,
    /// sha256 of the file, lower-case hex.
    pub sha256: String,
    /// File length.
    pub bytes: u64,
    /// Name of the provider it came from.
    pub provider: String,
}

/// `anchor.json`: the checked anchor, for checkpoint sync to start from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// The anchor block root, `0x` hex.
    pub block_root: String,
    /// The block's (and post-block state's) slot.
    pub slot: u64,
    /// `compute_epoch_at_slot(slot)`, the fork-choice anchor epoch.
    pub epoch: u64,
    /// The finalized checkpoint epoch the root was taken from (the lower of the two).
    pub finalized_epoch: u64,
    /// `block.message.state_root == hash_tree_root(state)`, `0x` hex.
    pub state_root: String,
    /// The fork of both bodies.
    pub fork: String,
    pub block: FileRecord,
    pub state: FileRecord,
    /// Both providers, A then B.
    pub providers: Vec<ProviderRecord>,
    /// When the anchor was written, UTC RFC 3339.
    pub fetched_at: String,
}

/// `0x` + 64 lower-case hex digits.
pub fn root_hex(root: &Root) -> String {
    format!("0x{}", alloy_primitives::hex::encode(root))
}

/// Runs one fetch: reads `config_path`, writes into `out_dir` (created if missing), appends
/// to its run log (echoed to stderr with `echo`). On success `anchor.json` exists and is
/// returned; on any error it does not, and the error is the run log's last line.
///
/// The run holds an exclusive `flock` on `<out>/.lock` throughout; a second run into the same
/// directory fails at once with [`AnchorError::OutDirBusy`] and leaves the run log alone.
pub async fn run<E: EthSpec>(
    config_path: &Path,
    out_dir: &Path,
    echo: bool,
) -> Result<Anchor, AnchorError> {
    run_with::<E>(config_path, out_dir, echo, &RealFs).await
}

/// [`run`] with the publish step's file operations from `fs`.
pub(crate) async fn run_with<E: EthSpec>(
    config_path: &Path,
    out_dir: &Path,
    echo: bool,
    fs: &dyn PublishFs,
) -> Result<Anchor, AnchorError> {
    std::fs::create_dir_all(out_dir).map_err(|e| io_err("create", out_dir, e))?;
    let _lock = lock_out_dir(out_dir)?;
    let log_path = out_dir.join(RUN_LOG_FILE);
    let mut log = RunLog::open(&log_path, echo).map_err(|e| io_err("open", &log_path, e))?;
    log_event(
        &mut log,
        &log_path,
        "start",
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "config": config_path.display().to_string(),
            "out_dir": out_dir.display().to_string(),
        }),
    )?;
    let mut fetch = Fetch {
        log,
        log_path,
        out_dir: out_dir.to_owned(),
        run_dir: None,
    };
    let result = fetch.run::<E>(config_path, fs).await;
    fetch.discard_quarantine();
    if let Err(e) = &result {
        // The abort line is best effort: the error already says what went wrong.
        let _ = fetch.log.event(
            "abort",
            json!({"error": e.name(), "message": e.to_string()}),
        );
    }
    result
}

/// Opens `<out>/.lock` (mode 0600, never through a symlink) and takes an exclusive,
/// non-blocking `flock` on it; the lock lasts as long as the returned descriptor.
fn lock_out_dir(out_dir: &Path) -> Result<rustix::fd::OwnedFd, AnchorError> {
    use rustix::fs::{FlockOperation, Mode, OFlags};
    let path = out_dir.join(LOCK_FILE);
    let fd = rustix::fs::open(
        &path,
        OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| io_err("open", &path, e.into()))?;
    match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(fd),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err(AnchorError::OutDirBusy {
            path: out_dir.to_owned(),
        }),
        Err(e) => Err(io_err("flock", &path, e.into())),
    }
}

/// The file operations of the publish step, so tests can fail one of them.
pub(crate) trait PublishFs: Sync {
    /// Hard-links `from` to `to`, failing with `AlreadyExists` rather than replacing `to`.
    fn link(&self, from: &Path, to: &Path) -> io::Result<()>;
    /// fsyncs the directory `dir`.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
}

/// The real file system.
pub(crate) struct RealFs;

impl PublishFs for RealFs {
    fn link(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::hard_link(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        std::fs::File::open(dir)?.sync_all()
    }
}

/// The agreed candidate after resolution.
struct Resolved {
    root: Root,
    finalized_epoch: u64,
    header: BeaconBlockHeader,
}

struct Fetch {
    log: RunLog,
    log_path: PathBuf,
    out_dir: PathBuf,
    /// This run's `quarantine/<random>/`, once created.
    run_dir: Option<PathBuf>,
}

impl Fetch {
    fn event(&mut self, event: &str, fields: serde_json::Value) -> Result<(), AnchorError> {
        log_event(&mut self.log, &self.log_path, event, fields)
    }

    fn check(&mut self, check: &str, ok: bool) -> Result<(), AnchorError> {
        self.event("check", json!({"check": check, "ok": ok}))
    }

    /// Removes this run's quarantine directory: after a failure the bodies are untrusted, and
    /// after publishing they are hard-linked into the output directory.
    fn discard_quarantine(&mut self) {
        if let Some(dir) = self.run_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    async fn run<E: EthSpec>(
        &mut self,
        config_path: &Path,
        fs: &dyn PublishFs,
    ) -> Result<Anchor, AnchorError> {
        let config = Config::load(config_path)?;
        for (role, p) in [("a", &config.a), ("b", &config.b)] {
            self.event(
                "provider",
                json!({"role": role, "name": p.name, "operator": p.operator, "url": p.redacted_url()}),
            )?;
        }
        // Checked up front so a run does not download for nothing; publish enforces it.
        for file in [ANCHOR_FILE, BLOCK_FILE, STATE_FILE] {
            let path = self.out_dir.join(file);
            if path.symlink_metadata().is_ok() {
                return Err(AnchorError::OutputExists { path });
            }
        }
        if config.allow_insecure_http {
            self.event("insecure_http_allowed", json!({}))?;
        }
        let client = Client::new(config.request_timeout, config.body_timeout)?;

        let resolved = self.resolve::<E>(&client, &config).await?;
        let block = self.fetch_block::<E>(&client, &config, &resolved).await?;
        let state = self
            .fetch_state::<E>(&client, &config, &resolved, &block.0)
            .await?;

        runlog::verify_file(&self.log_path)?;
        self.check("run_log_names_providers", true)?;

        let record = |role: &str, p: &Provider| ProviderRecord {
            role: role.into(),
            name: p.name.clone(),
            operator: p.operator.clone(),
            url: p.redacted_url(),
        };
        let file = |file: &str, d: &Download, p: &Provider| FileRecord {
            file: file.into(),
            sha256: alloy_primitives::hex::encode(d.sha256),
            bytes: d.len,
            provider: p.name.clone(),
        };
        let anchor = Anchor {
            block_root: root_hex(&resolved.root),
            slot: resolved.header.slot,
            epoch: E::epoch_at_slot(resolved.header.slot),
            finalized_epoch: resolved.finalized_epoch,
            state_root: root_hex(&resolved.header.state_root),
            fork: FORK.as_str().into(),
            block: file(BLOCK_FILE, &block.1, &config.a),
            state: file(STATE_FILE, &state, &config.b),
            providers: vec![record("a", &config.a), record("b", &config.b)],
            fetched_at: runlog::rfc3339_utc(SystemTime::now()),
        };
        let text = serde_json::to_vec_pretty(&anchor).map_err(|e| AnchorError::Io {
            context: "serialize anchor.json".into(),
            source: e.into(),
        })?;
        // Logged first: publishing is the last fallible step, and it rolls itself back.
        self.event("anchor", serde_json::to_value(&anchor).unwrap_or_default())?;
        let run_dir = self.run_dir()?;
        publish(fs, &run_dir, &self.out_dir, &text)?;
        Ok(anchor)
    }

    async fn resolve<E: EthSpec>(
        &mut self,
        client: &Client,
        config: &Config,
    ) -> Result<Resolved, AnchorError> {
        let mut finalized = Vec::with_capacity(2);
        for p in [&config.a, &config.b] {
            let f: FinalityResponse = client.get_json(p, FINALITY_PATH).await?;
            let cp = f.data.finalized;
            self.event(
                "finality",
                json!({"provider": p.name, "epoch": cp.epoch, "root": root_hex(&cp.root)}),
            )?;
            if cp.root == Root::ZERO {
                return Err(bad_response(
                    p,
                    FINALITY_PATH,
                    "no finalized checkpoint yet",
                ));
            }
            finalized.push(cp);
        }
        let candidate = candidate(finalized[0], finalized[1])?;
        self.event(
            "candidate",
            json!({"root": root_hex(&candidate.root), "finalized_epoch": candidate.epoch}),
        )?;

        let path = format!("/eth/v1/beacon/headers/{}", root_hex(&candidate.root));
        let mut headers = Vec::with_capacity(2);
        for p in [&config.a, &config.b] {
            let h: HeaderResponse = client.get_json(p, &path).await?;
            let m = h.data.header.message;
            self.event(
                "header",
                json!({
                    "provider": p.name, "root": root_hex(&h.data.root),
                    "canonical": h.data.canonical, "slot": m.slot,
                    "parent_root": root_hex(&m.parent_root),
                    "state_root": root_hex(&m.state_root),
                }),
            )?;
            if h.data.root != candidate.root {
                return Err(bad_response(
                    p,
                    &path,
                    &format!("header for {}", root_hex(&h.data.root)),
                ));
            }
            if !h.data.canonical {
                return Err(AnchorError::NotCanonical {
                    provider: p.name.clone(),
                    root: candidate.root,
                });
            }
            headers.push(m);
        }
        let (header, other) = (
            BeaconBlockHeader::from(headers[0]),
            BeaconBlockHeader::from(headers[1]),
        );
        if let Some(field) = differing_field(&header, &other) {
            return Err(AnchorError::ProvidersDisagree(format!(
                "{} and {} return headers for {} with different {field}",
                config.a.name,
                config.b.name,
                root_hex(&candidate.root)
            )));
        }
        self.check("headers_agree", true)?;
        // The checkpoint block is the last one at or before the epoch's first slot.
        if header.slot > E::start_slot_at_epoch(candidate.epoch) {
            return Err(bad_response(
                &config.a,
                &path,
                &format!(
                    "header slot {} is after the start of finalized epoch {}",
                    header.slot, candidate.epoch
                ),
            ));
        }
        Ok(Resolved {
            root: candidate.root,
            finalized_epoch: candidate.epoch,
            header,
        })
    }

    /// This run's own quarantine directory, `quarantine/<random>/` (both mode 0700), created
    /// on first use; a new name never collides with another run's or a crashed run's.
    fn run_dir(&mut self) -> Result<PathBuf, AnchorError> {
        if let Some(dir) = &self.run_dir {
            return Ok(dir.clone());
        }
        let parent = self.out_dir.join(QUARANTINE_DIR);
        private_dir(true)
            .create(&parent)
            .map_err(|e| io_err("create", &parent, e))?;
        let dir = parent.join(random_name()?);
        private_dir(false)
            .create(&dir)
            .map_err(|e| io_err("create", &dir, e))?;
        self.run_dir = Some(dir.clone());
        Ok(dir)
    }

    /// The path for `file` in this run's quarantine; the download creates it new.
    fn prepare_quarantine(&mut self, file: &str) -> Result<PathBuf, AnchorError> {
        Ok(self.run_dir()?.join(file))
    }

    /// Downloads `path` from `provider` into quarantine as `file` (a response naming another
    /// fork is refused before its body is read), logs it, and returns it with its bytes.
    async fn download(
        &mut self,
        client: &Client,
        config: &Config,
        provider: &Provider,
        what: &'static str,
        path: &str,
        file: &str,
    ) -> Result<(Download, Vec<u8>), AnchorError> {
        let dest = self.prepare_quarantine(file)?;
        let d = client
            .download_ssz(provider, path, FORK.as_str(), &dest, config.max_body_bytes)
            .await?;
        self.event(
            "fetch",
            json!({
                "what": what, "provider": provider.name, "path": path, "bytes": d.len,
                "sha256": alloy_primitives::hex::encode(d.sha256),
                "consensus_version": d.consensus_version,
            }),
        )?;
        // The file is at most `max_body_bytes`; decoding needs it in memory.
        let bytes = tokio::fs::read(&dest)
            .await
            .map_err(|e| io_err("read", &dest, e))?;
        Ok((d, bytes))
    }

    /// The block from A, checked against the agreed root and header.
    async fn fetch_block<E: EthSpec>(
        &mut self,
        client: &Client,
        config: &Config,
        resolved: &Resolved,
    ) -> Result<(gloas::SignedBeaconBlock<E>, Download), AnchorError> {
        let path = format!("/eth/v2/beacon/blocks/{}", root_hex(&resolved.root));
        let (d, bytes) = self
            .download(client, config, &config.a, "block", &path, BLOCK_FILE)
            .await?;
        let block = match forked::SignedBeaconBlock::<E>::from_ssz_bytes_for_fork(&bytes, FORK) {
            Ok(forked::SignedBeaconBlock::Gloas(b)) => b,
            Ok(other) => return Err(decode("block", format!("decoded as {}", other.fork_name()))),
            Err(e) => return Err(decode("block", e)),
        };
        drop(bytes);

        let got = block.message.tree_hash_root();
        self.check("block_root", got == resolved.root)?;
        if got != resolved.root {
            return Err(AnchorError::BlockRootMismatch {
                expected: resolved.root,
                got,
            });
        }
        let header = &resolved.header;
        let same = block.message.state_root == header.state_root;
        self.check("header_state_root", same)?;
        if !same {
            return Err(AnchorError::HeaderStateRootMismatch {
                header: header.state_root,
                block: block.message.state_root,
            });
        }
        let m = &block.message;
        let derived = BeaconBlockHeader {
            slot: m.slot,
            proposer_index: m.proposer_index,
            parent_root: m.parent_root,
            state_root: m.state_root,
            body_root: m.body.tree_hash_root(),
        };
        let mismatch = differing_field(&derived, header);
        self.check("header_matches_block", mismatch.is_none())?;
        if let Some(field) = mismatch {
            return Err(AnchorError::HeaderBlockMismatch { field });
        }
        Ok((block, d))
    }

    /// The state from B, checked to be the block's post-block state with the agreed root.
    async fn fetch_state<E: EthSpec>(
        &mut self,
        client: &Client,
        config: &Config,
        resolved: &Resolved,
        block: &gloas::SignedBeaconBlock<E>,
    ) -> Result<Download, AnchorError> {
        let state_root = resolved.header.state_root;
        let path = format!("/eth/v2/debug/beacon/states/{}", root_hex(&state_root));
        let (d, bytes) = self
            .download(client, config, &config.b, "state", &path, STATE_FILE)
            .await?;
        let mut state = match forked::BeaconState::<E>::from_ssz_bytes_for_fork(&bytes, FORK) {
            Ok(forked::BeaconState::Gloas(s)) => Box::new(s),
            Ok(other) => return Err(decode("state", format!("decoded as {}", other.fork_name()))),
            Err(e) => return Err(decode("state", e)),
        };
        drop(bytes);
        state
            .apply_updates()
            .map_err(|e| decode("state", format!("milhouse: {e:?}")))?;

        let post_block = post_block_mismatch(&state, &block.message);
        self.check("state_is_post_block", post_block.is_none())?;
        if let Some(reason) = post_block {
            return Err(AnchorError::StateNotPostBlock { reason });
        }
        let got = state.tree_hash_root();
        self.check("state_root", got == state_root)?;
        if got != state_root {
            return Err(AnchorError::StateRootMismatch {
                expected: state_root,
                got,
            });
        }
        Ok(d)
    }
}

/// Why `state` is not `block`'s post-block state, if it is not: `process_block_header` leaves
/// the state at the block's slot with `latest_block_header` the block's header and a zero
/// `state_root` (filled in by the next `process_slot`).
fn post_block_mismatch<E: EthSpec>(
    state: &gloas::BeaconState<E>,
    block: &gloas::BeaconBlock<E>,
) -> Option<String> {
    if state.slot != block.slot {
        return Some(format!(
            "state slot {}, block slot {}",
            state.slot, block.slot
        ));
    }
    let expected = BeaconBlockHeader {
        slot: block.slot,
        proposer_index: block.proposer_index,
        parent_root: block.parent_root,
        state_root: Root::ZERO,
        body_root: block.body.tree_hash_root(),
    };
    differing_field(&state.latest_block_header, &expected)
        .map(|field| format!("latest_block_header.{field} is not the block's"))
}

fn decode(what: &'static str, reason: impl std::fmt::Display) -> AnchorError {
    AnchorError::Decode {
        what,
        reason: reason.to_string(),
    }
}

/// The candidate: the root of the lower finalized epoch. Equal epochs must have equal roots.
fn candidate(a: Checkpoint, b: Checkpoint) -> Result<Checkpoint, AnchorError> {
    if a.epoch == b.epoch && a.root != b.root {
        return Err(AnchorError::ProvidersDisagree(format!(
            "finalized epoch {} has roots {} and {}",
            a.epoch,
            root_hex(&a.root),
            root_hex(&b.root)
        )));
    }
    Ok(if a.epoch <= b.epoch { a } else { b })
}

/// The first field in which two headers differ.
fn differing_field(a: &BeaconBlockHeader, b: &BeaconBlockHeader) -> Option<&'static str> {
    [
        ("slot", a.slot == b.slot),
        ("proposer_index", a.proposer_index == b.proposer_index),
        ("parent_root", a.parent_root == b.parent_root),
        ("state_root", a.state_root == b.state_root),
        ("body_root", a.body_root == b.body_root),
    ]
    .into_iter()
    .find_map(|(field, same)| (!same).then_some(field))
}

fn log_event(
    log: &mut RunLog,
    path: &Path,
    event: &str,
    fields: serde_json::Value,
) -> Result<(), AnchorError> {
    log.event(event, fields)
        .map_err(|e| io_err("write", path, e))
}

fn io_err(what: &str, path: &Path, source: io::Error) -> AnchorError {
    AnchorError::Io {
        context: format!("{what} {}", path.display()),
        source,
    }
}

fn bad_response(p: &Provider, path: &str, reason: &str) -> AnchorError {
    AnchorError::BadResponse {
        provider: p.name.clone(),
        path: path.to_owned(),
        reason: reason.to_owned(),
    }
}

/// A `DirBuilder` for mode 0700 directories.
fn private_dir(recursive: bool) -> std::fs::DirBuilder {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
}

/// 32 random hex digits from the OS RNG.
fn random_name() -> Result<String, AnchorError> {
    let draw = || getrandom::u64().map_err(|e| io::Error::other(e.to_string()));
    let (hi, lo) = (draw(), draw());
    match (hi, lo) {
        (Ok(hi), Ok(lo)) => Ok(format!("{hi:016x}{lo:016x}")),
        (Err(e), _) | (_, Err(e)) => Err(AnchorError::Io {
            context: "draw a random name".into(),
            source: e,
        }),
    }
}

/// Publishes the checked bodies in `run_dir` and `anchor_json` into `out_dir`, never
/// replacing an existing file: `block.ssz` and `state.ssz` are hard-linked in, `anchor.json`
/// is written to a new uniquely named temp file (fsynced) and hard-linked in last, then the
/// directory is fsynced. Any failure removes every file this call published, so the output
/// directory holds all three or none of them.
pub(crate) fn publish(
    fs: &dyn PublishFs,
    run_dir: &Path,
    out_dir: &Path,
    anchor_json: &[u8],
) -> Result<(), AnchorError> {
    let tmp = out_dir.join(format!(".{ANCHOR_FILE}.{}.tmp", random_name()?));
    let mut published = Vec::with_capacity(3);
    let result = publish_steps(fs, run_dir, out_dir, &tmp, anchor_json, &mut published);
    let _ = std::fs::remove_file(&tmp);
    if result.is_err() {
        for path in published.iter().rev() {
            let _ = std::fs::remove_file(path);
        }
        let _ = fs.sync_dir(out_dir);
    }
    result
}

fn publish_steps(
    fs: &dyn PublishFs,
    run_dir: &Path,
    out_dir: &Path,
    tmp: &Path,
    anchor_json: &[u8],
    published: &mut Vec<PathBuf>,
) -> Result<(), AnchorError> {
    for file in [BLOCK_FILE, STATE_FILE] {
        let to = out_dir.join(file);
        link_new(fs, &run_dir.join(file), &to)?;
        published.push(to);
    }
    write_new(tmp, anchor_json).map_err(|e| io_err("write", tmp, e))?;
    let anchor = out_dir.join(ANCHOR_FILE);
    link_new(fs, tmp, &anchor)?;
    published.push(anchor);
    std::fs::remove_file(tmp).map_err(|e| io_err("remove", tmp, e))?;
    fs.sync_dir(out_dir)
        .map_err(|e| io_err("fsync", out_dir, e))
}

fn link_new(fs: &dyn PublishFs, from: &Path, to: &Path) -> Result<(), AnchorError> {
    match fs.link(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(AnchorError::OutputExists {
            path: to.to_owned(),
        }),
        Err(e) => Err(io_err("link", to, e)),
    }
}

/// Writes `bytes` to a file that must not exist yet (`O_CREAT | O_EXCL`, so a planted symlink
/// is refused, not followed), mode 0600, and fsyncs it.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut f = options.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests;
