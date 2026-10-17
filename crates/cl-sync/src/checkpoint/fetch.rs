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
//!    the directory. A failed step removes what was published; if that cleanup fails too, the
//!    error is [`AnchorError::PublishRolledBackIncompletely`] and lists the files left behind.
//!
//! **`anchor.json` is the commit marker.** It is linked last, so a crash (SIGKILL, power loss)
//! between the links can leave `block.ssz` or `state.ssz` without it, but never a partial
//! `anchor.json`. A consumer must ignore `block.ssz` and `state.ssz` unless an `anchor.json`
//! next to them names their sha256 values and they match.
//!
//! The output directory is opened once, with `O_DIRECTORY | O_NOFOLLOW`, and refused
//! ([`AnchorError::UnsafePath`]) if it is a symlink, owned by another user, or writable by
//! group or other; so is `quarantine/`. Every later file operation is relative to those held
//! descriptors ([`crate::checkpoint::outdir`]), so another user cannot redirect a write by
//! renaming a path after the checks.
//!
//! The run holds an exclusive `flock` on `<out>/.lock` from before the run log is opened until
//! publication, so two runs never share an output directory; each run also streams into its
//! own `quarantine/<random>/`.
//!
//! Any failure aborts with a named [`AnchorError`], deletes the quarantined bodies, records an
//! `abort` line in the run log, and leaves no `anchor.json` this run published, unless the
//! rollback of a failed publish fails too: then the error and the `abort` line's `left` list
//! name every file that may remain, and the operator deletes them.
//!
//! The SSZ is decoded with the Gloas shape, the fork this fetcher requests; a response that
//! names another fork in `Eth-Consensus-Version` is refused ([`AnchorError::WrongFork`]).

use crate::checkpoint::api::{Checkpoint, FinalityResponse, HeaderResponse};
use crate::checkpoint::config::{Config, Provider};
use crate::checkpoint::http::{Client, Download};
use crate::checkpoint::outdir::{Dir, UnsafeReason};
use crate::checkpoint::runlog::{self, RunLog, RunLogError};
use consensus_types::common::BeaconBlockHeader;
use consensus_types::primitives::Root;
use consensus_types::{forked, gloas, EthSpec, ForkName};
use rustix::fs::OFlags;
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
    /// The output directory, its quarantine, or a file the run opens in it is a symlink, of
    /// the wrong type, owned by another user, or writable by group or other.
    #[error("{} {reason}; refusing to use it", path.display())]
    UnsafePath { path: PathBuf, reason: UnsafeReason },
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
    /// Publishing failed (`cause`) and so did removing what it had published (`cleanup`): the
    /// files in `left` may still be in the output directory. Recovery: delete them by hand.
    #[error(
        "{cause}; the rollback failed too ({cleanup}): delete these files by hand: {}",
        display_paths(left)
    )]
    PublishRolledBackIncompletely {
        cause: Box<AnchorError>,
        cleanup: String,
        left: Vec<PathBuf>,
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
            AnchorError::UnsafePath { .. } => "unsafe_path",
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
            AnchorError::PublishRolledBackIncompletely { .. } => "publish_rollback_incomplete",
        }
    }

    /// The files a failed rollback left in the output directory (empty for every other
    /// error); the operator deletes them.
    pub fn left_behind(&self) -> &[PathBuf] {
        match self {
            AnchorError::PublishRolledBackIncompletely { left, .. } => left,
            _ => &[],
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
            | AnchorError::UnsafePath { .. }
            | AnchorError::OutDirBusy { .. } => 2,
            AnchorError::Transport { .. }
            | AnchorError::Timeout { .. }
            | AnchorError::HttpStatus { .. } => 3,
            AnchorError::RunLog(_)
            | AnchorError::Io { .. }
            | AnchorError::PublishRolledBackIncompletely { .. } => 4,
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

/// Runs one fetch: reads `config_path`, writes into `out_dir` (created mode 0700 if missing),
/// appends to its run log (echoed to stderr with `echo`). On success `anchor.json` exists and
/// is returned; on any error the error is the run log's last line and this run published
/// nothing, unless the publish's rollback failed
/// ([`AnchorError::PublishRolledBackIncompletely`] lists what may remain).
///
/// An unsafe `out_dir` (a symlink, another user's, or group/other-writable) or `run.log` is
/// refused with [`AnchorError::UnsafePath`] before anything is written. The run holds an
/// exclusive `flock` on `<out>/.lock` throughout; a second run into the same directory fails
/// at once with [`AnchorError::OutDirBusy`] and leaves the run log alone.
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
    let out = Dir::open_out(out_dir)?;
    let _lock = lock_out_dir(&out)?;
    let mut log = RunLog::open_in(&out, RUN_LOG_FILE, echo)?;
    log_event(
        &mut log,
        "start",
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "config": config_path.display().to_string(),
            "out_dir": out_dir.display().to_string(),
        }),
    )?;
    let mut fetch = Fetch {
        log,
        out,
        quarantine: None,
    };
    let result = fetch.run::<E>(config_path, fs).await;
    fetch.discard_quarantine();
    if let Err(e) = &result {
        let mut fields = json!({"error": e.name(), "message": e.to_string()});
        let left = e.left_behind();
        if !left.is_empty() {
            let left: Vec<_> = left.iter().map(|p| p.display().to_string()).collect();
            fields["left"] = json!(left);
        }
        // The abort line is best effort: the error already says what went wrong.
        let _ = fetch.log.event("abort", fields);
    }
    result
}

/// Opens `<out>/.lock` (mode 0600, never through a symlink) and takes an exclusive,
/// non-blocking `flock` on it; the lock lasts as long as the returned file.
fn lock_out_dir(out: &Dir) -> Result<std::fs::File, AnchorError> {
    use rustix::fs::FlockOperation;
    let file = out.open_private_file(LOCK_FILE, OFlags::RDWR)?;
    match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Err(AnchorError::OutDirBusy {
            path: out.path().to_owned(),
        }),
        Err(e) => Err(io_err("flock", &out.join(LOCK_FILE), e.into())),
    }
}

/// The file operations of the publish step and its rollback, so tests can fail one of them.
pub(crate) trait PublishFs: Sync {
    /// Hard-links `name` in `from` to `to_name` in `to`, failing with `AlreadyExists` rather
    /// than replacing it.
    fn link(&self, from: &Dir, name: &str, to: &Dir, to_name: &str) -> io::Result<()>;
    /// Removes the file `name` in `dir`.
    fn unlink(&self, dir: &Dir, name: &str) -> io::Result<()>;
    /// fsyncs the directory `dir`.
    fn sync_dir(&self, dir: &Dir) -> io::Result<()>;
}

/// The real file system.
pub(crate) struct RealFs;

impl PublishFs for RealFs {
    fn link(&self, from: &Dir, name: &str, to: &Dir, to_name: &str) -> io::Result<()> {
        from.link(name, to, to_name)
    }

    fn unlink(&self, dir: &Dir, name: &str) -> io::Result<()> {
        dir.unlink(name)
    }

    fn sync_dir(&self, dir: &Dir) -> io::Result<()> {
        dir.sync()
    }
}

/// `quarantine/` and this run's own `quarantine/<random>/` in it.
struct Quarantine {
    parent: Dir,
    name: String,
    run: Dir,
}

/// The agreed candidate after resolution.
struct Resolved {
    root: Root,
    finalized_epoch: u64,
    header: BeaconBlockHeader,
}

struct Fetch {
    log: RunLog,
    out: Dir,
    /// Opened first thing in [`Fetch::run`].
    quarantine: Option<Quarantine>,
}

impl Fetch {
    fn event(&mut self, event: &str, fields: serde_json::Value) -> Result<(), AnchorError> {
        log_event(&mut self.log, event, fields)
    }

    fn check(&mut self, check: &str, ok: bool) -> Result<(), AnchorError> {
        self.event("check", json!({"check": check, "ok": ok}))
    }

    /// Removes this run's quarantine directory: after a failure the bodies are untrusted, and
    /// after publishing they are hard-linked into the output directory.
    fn discard_quarantine(&mut self) {
        if let Some(q) = self.quarantine.take() {
            drop(q.run);
            let _ = q.parent.remove_child(&q.name);
        }
    }

    /// Opens `quarantine/` (created mode 0700 if missing) and creates this run's own
    /// `quarantine/<random>/` (mode 0700) in it; a new name never collides with another
    /// run's or a crashed run's. Both are refused unless safe.
    fn open_quarantine(&mut self) -> Result<(), AnchorError> {
        let parent = self.out.open_child(QUARANTINE_DIR, true)?;
        let name = random_name()?;
        let run = parent.create_child(&name)?;
        self.quarantine = Some(Quarantine { parent, name, run });
        Ok(())
    }

    /// This run's quarantine directory.
    fn run_dir(&self) -> Result<&Dir, AnchorError> {
        self.quarantine
            .as_ref()
            .map(|q| &q.run)
            .ok_or_else(|| AnchorError::Io {
                context: "quarantine".into(),
                source: io::Error::other("not opened"),
            })
    }

    async fn run<E: EthSpec>(
        &mut self,
        config_path: &Path,
        fs: &dyn PublishFs,
    ) -> Result<Anchor, AnchorError> {
        self.open_quarantine()?;
        let config = Config::load(config_path)?;
        for (role, p) in [("a", &config.a), ("b", &config.b)] {
            self.event(
                "provider",
                json!({"role": role, "name": p.name, "operator": p.operator, "url": p.redacted_url()}),
            )?;
        }
        // Checked up front so a run does not download for nothing; publish enforces it.
        for file in [ANCHOR_FILE, BLOCK_FILE, STATE_FILE] {
            if self.out.exists(file)? {
                return Err(AnchorError::OutputExists {
                    path: self.out.join(file),
                });
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

        self.log.verify()?;
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
        // Logged first: publishing is the last fallible step, and it rolls itself back (or
        // reports what it could not remove).
        self.event("anchor", serde_json::to_value(&anchor).unwrap_or_default())?;
        publish(fs, self.run_dir()?, &self.out, &text)?;
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
        let run_dir = self.run_dir()?;
        let d = client
            .download_ssz(
                provider,
                path,
                FORK.as_str(),
                run_dir,
                file,
                config.max_body_bytes,
            )
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
        let run_dir = self.run_dir()?;
        let read = |e| io_err("read", &run_dir.join(file), e);
        let mut bytes = Vec::new();
        let mut f = tokio::fs::File::from_std(run_dir.open_read(file).map_err(read)?);
        tokio::io::AsyncReadExt::read_to_end(&mut f, &mut bytes)
            .await
            .map_err(read)?;
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

fn log_event(log: &mut RunLog, event: &str, fields: serde_json::Value) -> Result<(), AnchorError> {
    log.event(event, fields)
        .map_err(|e| io_err("write", log.path(), e))
}

fn display_paths(paths: &[PathBuf]) -> String {
    let shown: Vec<_> = paths.iter().map(|p| p.display().to_string()).collect();
    shown.join(", ")
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

/// Publishes the checked bodies in `run_dir` and `anchor_json` into `out`, never replacing an
/// existing file: `block.ssz` and `state.ssz` are hard-linked in, `anchor.json` is written to a
/// new uniquely named temp file (fsynced) and hard-linked in last, then the directory is
/// fsynced. `anchor.json` is the commit marker: a crash between the links can leave the
/// bodies without it, never the reverse.
///
/// A failed step is rolled back: the temp file and every file this call published are
/// removed (newest first) and `out` is fsynced again. When that cleanup succeeds `out` holds
/// none of this call's files and the step's error is returned. When it fails (an unlink
/// error, or an fsync error that leaves the removals not durable) the error is
/// [`AnchorError::PublishRolledBackIncompletely`], whose `left` lists every file that may
/// remain; the operator deletes those files by hand.
pub(crate) fn publish(
    fs: &dyn PublishFs,
    run_dir: &Dir,
    out: &Dir,
    anchor_json: &[u8],
) -> Result<(), AnchorError> {
    let tmp = format!(".{ANCHOR_FILE}.{}.tmp", random_name()?);
    let mut progress = Progress::default();
    match publish_steps(fs, run_dir, out, &tmp, anchor_json, &mut progress) {
        Ok(()) => Ok(()),
        Err(cause) => Err(roll_back(fs, out, &tmp, &progress, cause)),
    }
}

/// How far [`publish_steps`] got.
#[derive(Default)]
struct Progress {
    /// The names linked into the output directory, in order.
    published: Vec<&'static str>,
    /// The temp file was unlinked, not yet durably (that is the final fsync's job).
    tmp_removed: bool,
}

fn publish_steps(
    fs: &dyn PublishFs,
    run_dir: &Dir,
    out: &Dir,
    tmp: &str,
    anchor_json: &[u8],
    progress: &mut Progress,
) -> Result<(), AnchorError> {
    for file in [BLOCK_FILE, STATE_FILE] {
        link_new(fs, run_dir, file, out, file)?;
        progress.published.push(file);
    }
    write_new(out, tmp, anchor_json).map_err(|e| io_err("write", &out.join(tmp), e))?;
    link_new(fs, out, tmp, out, ANCHOR_FILE)?;
    progress.published.push(ANCHOR_FILE);
    fs.unlink(out, tmp)
        .map_err(|e| io_err("remove", &out.join(tmp), e))?;
    progress.tmp_removed = true;
    fs.sync_dir(out).map_err(|e| io_err("fsync", out.path(), e))
}

/// Removes the temp file and the published names (newest first) from `out` and fsyncs it,
/// after `cause`. Returns `cause` if that worked, else the incomplete rollback with every
/// file that may be left: those it could not remove and, if the fsync failed, every removal
/// not yet on disk (the temp file's included, even when [`publish_steps`] removed it).
fn roll_back(
    fs: &dyn PublishFs,
    out: &Dir,
    tmp: &str,
    progress: &Progress,
    cause: AnchorError,
) -> AnchorError {
    let mut failures = Vec::new();
    let mut left = Vec::new();
    let mut removed = Vec::new();
    if progress.tmp_removed {
        removed.push(out.join(tmp));
    }
    let names = std::iter::once(tmp).chain(progress.published.iter().rev().copied());
    for name in names {
        match fs.unlink(out, name) {
            Ok(()) => removed.push(out.join(name)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                failures.push(format!("remove {}: {e}", out.join(name).display()));
                left.push(out.join(name));
            }
        }
    }
    if let Err(e) = fs.sync_dir(out) {
        // The removals may not be on disk: after a crash every removed file can come back.
        failures.push(format!("fsync {}: {e}", out.path().display()));
        left.extend(removed);
    }
    if failures.is_empty() {
        return cause;
    }
    AnchorError::PublishRolledBackIncompletely {
        cause: Box::new(cause),
        cleanup: failures.join("; "),
        left,
    }
}

fn link_new(
    fs: &dyn PublishFs,
    from: &Dir,
    name: &str,
    to: &Dir,
    to_name: &str,
) -> Result<(), AnchorError> {
    match fs.link(from, name, to, to_name) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(AnchorError::OutputExists {
            path: to.join(to_name),
        }),
        Err(e) => Err(io_err("link", &to.join(to_name), e)),
    }
}

/// Writes `bytes` to the file `name` in `dir`, which must not exist yet (`O_CREAT | O_EXCL`,
/// so a planted symlink is refused, not followed), mode 0600, and fsyncs it.
pub(crate) fn write_new(dir: &Dir, name: &str, bytes: &[u8]) -> io::Result<()> {
    let mut f = dir.create_new(name)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests;
