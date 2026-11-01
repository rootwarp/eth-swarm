//! The C4 durable file set: what cl-chain needs to restart, as plain files under
//! `<datadir>/durable/`, outside MDBX. The env can be lost or replaced and this set still names
//! the restart base; no MDBX table holds any of it.
//!
//! # Layout (format version 1; #106 installs anchors in it unchanged)
//!
//! ```text
//! <datadir>/durable/
//!   VERSION              "1\n"
//!   CURRENT              "anchor-<root>\n" or "finalized-<root>\n": the restart base
//!   anchor-<root>/       the operator's anchor (install_anchor); <root> is the anchor's root.
//!                        Kept beside finalized-* until a new anchor replaces it
//!   finalized-<root>/    the latest finalized block and its state (advance_finality)
//!     block.ssz          the block, SSZ (opaque here, never decoded)
//!     state.ssz          its post-state, SSZ
//!     envelope.ssz       optional: its Gloas payload envelope, SSZ
//!     anchor             the operator anchor checkpoint: root (32) ‖ epoch (u64 BE)
//!   import.log           one frame per imported block (see import_log)
//! ```
//!
//! `<root>` is exactly the 64 lowercase hex characters of the 32-byte block root, always
//! formatted from the root's bytes. CURRENT names exactly one base dir. `anchor` is carried into
//! every `finalized-*` dir, so the ancestry check against the operator anchor (#192) survives
//! finality advances.
//!
//! # Writes
//!
//! - Every file, VERSION and CURRENT included: `<name>.tmp` written and fsync'd, renamed onto
//!   `<name>`, `durable/` fsync'd. A crash leaves the old content or the new, never a mix.
//! - A base dir: built as `.tmp-<name>/` (each file written and fsync'd, the dir fsync'd),
//!   renamed into place, `durable/` fsync'd.
//! - A base change ([`FileSet::install_anchor`], [`FileSet::advance_finality`]): the new dir,
//!   then CURRENT swapped, then every base dir the new base does not keep deleted. A base keeps
//!   itself and `anchor-<root>/` of the anchor it carries. So a finality advance deletes only the
//!   previous `finalized-*` dir, never the anchor dir: the anchor's block, state and envelope
//!   stay for the ancestry check (#192). A new anchor is a new trust root: installing it deletes
//!   the previous anchor dir and every `finalized-*` dir. A crash at any step leaves CURRENT
//!   naming one complete base: the old one until CURRENT is renamed, the new one from then on.
//! - [`FileSet::record_import`]: one frame appended and fsync'd. Until `durable/` has been
//!   fsync'd with `import.log` in it since the open, the append fsyncs `durable/` too, so the
//!   log's entry is durable before the import is acknowledged. A failed append is cut back
//!   off (truncate, fsync) before the error returns, so the next append follows the last good
//!   frame. If that cut fails too, the set takes no more writes ([`Error::Poisoned`]) until it
//!   is reopened, and the reopen cuts the torn tail.
//!
//! # Open
//!
//! [`FileSet::open`] checks VERSION: missing on a missing or empty `durable/` (crash leftovers
//! aside) it is created; missing otherwise is [`Error::MissingVersion`]; newer is
//! [`Error::NewerVersion`]; anything but `1\n` is [`Error::UnknownVersion`]. It then resolves
//! CURRENT: the text must parse as a base name whose re-formatted bytes are equal to it (so no
//! `..`, `/`, NUL, uppercase, wrong length or extra bytes), naming a real directory (not a
//! symlink) in `durable/`; else [`Error::BadCurrent`] or [`Error::BaseNotDir`], with nothing
//! deleted. The base is read next ([`Error::BadBase`], nothing deleted). Only then are a crash's
//! leftovers removed: `*.tmp`, `.tmp-*` and base dirs the base does not keep (any other anchor
//! dir, any stale `finalized-*` dir); nothing else is touched. Last, `import.log` is loaded, a
//! torn tail cut, and if it exists `durable/` is fsync'd before any append: a crash between the
//! log's creation and the fsync of its entry is repaired here.

use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
};

use super::atomic::{is_leftover, sync_dir, AtomicDir, Hooks};
#[cfg(feature = "test-hooks")]
pub use super::atomic::{AppendFault, Step};
#[cfg(not(feature = "test-hooks"))]
use super::atomic::{AppendFault, Step};
use super::base::BaseName;
pub use super::base::{Base, BaseFiles, BaseKind, Checkpoint};
use super::import_log;
pub use super::import_log::{ElStatus, ImportRecord, PayloadStatus};

/// The file set format this build reads and writes, in VERSION.
pub const FORMAT_VERSION: u64 = 1;

const DIR: &str = "durable";
const VERSION: &str = "VERSION";
const CURRENT: &str = "CURRENT";
const IMPORT_LOG: &str = "import.log";
const BLOCK: &str = "block.ssz";
const STATE: &str = "state.ssz";
const ENVELOPE: &str = "envelope.ssz";
const ANCHOR: &str = "anchor";

/// Errors of the durable file set.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file system call failed.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// `durable/` holds files but no VERSION.
    #[error("{} holds files but no VERSION", dir.display())]
    MissingVersion {
        /// The `durable/` dir.
        dir: PathBuf,
    },
    /// VERSION is newer than [`FORMAT_VERSION`]: a newer cl-chain wrote the set.
    #[error("durable VERSION {found} is newer than {FORMAT_VERSION}")]
    NewerVersion {
        /// The stored version.
        found: u64,
    },
    /// VERSION is not a version this build knows.
    #[error("durable VERSION {found:?} is not a known version")]
    UnknownVersion {
        /// Its bytes, escaped.
        found: String,
    },
    /// CURRENT is torn or malformed: not exactly one base name and a newline.
    #[error("CURRENT {found:?} names no base")]
    BadCurrent {
        /// Its bytes, escaped.
        found: String,
    },
    /// CURRENT names a base that is not a real directory in `durable/`.
    #[error("CURRENT names {name}, which is not a directory in durable/")]
    BaseNotDir {
        /// The base name.
        name: String,
    },
    /// The base CURRENT names lacks a file, or its `anchor` is malformed.
    #[error("base {name}: {file} is missing or malformed")]
    BadBase {
        /// The base name.
        name: String,
        /// The file.
        file: &'static str,
    },
    /// [`FileSet::advance_finality`] before any anchor is installed.
    #[error("no base is installed")]
    NoBase,
    /// The new base is the current one.
    #[error("{name} is already the current base")]
    BaseIsCurrent {
        /// The base name.
        name: String,
    },
    /// A bad `import.log` frame with more data after it: not a torn tail.
    #[error("import.log has a bad record at byte {offset} with more after it")]
    CorruptImportLog {
        /// Where the bad frame starts.
        offset: u64,
    },
    /// An `import.log` append failed and rolling it back failed too, so the log may end in a
    /// torn frame: the set takes no more writes until it is reopened, which cuts that tail.
    #[error("an import.log append could not be rolled back; reopen the durable file set")]
    Poisoned,
    /// A crash injected by [`FileSet::open_crashing`]: the operation stopped there and left the
    /// disk as it was.
    #[cfg(feature = "test-hooks")]
    #[error("injected crash at {step:?} of {name}")]
    Crashed {
        /// The step.
        step: Step,
        /// The file or dir it was writing.
        name: String,
    },
}

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// What [`FileSet::open`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded {
    /// The restart base; `None` before the first [`FileSet::install_anchor`].
    pub base: Option<Base>,
    /// `import.log`'s records in append order, a torn tail cut.
    pub imports: Vec<ImportRecord>,
}

impl Loaded {
    /// Whether `root`'s import completed: `import.log` records it. A block in MDBX `blocks`
    /// with no record was never acknowledged (the process died between the commit and the
    /// append) and is ignored.
    #[must_use]
    pub fn is_imported(&self, root: &[u8; 32]) -> bool {
        self.imports.iter().any(|record| record.root == *root)
    }
}

/// The durable file set of one datadir. Its writes take `&mut self`: one writer.
pub struct FileSet {
    dir: AtomicDir,
    /// What the next [`Self::record_import`] injects (`test-hooks`); nothing without the
    /// feature.
    fault: AppendFault,
    /// A failed append could not be rolled back: no more writes until a reopen.
    poisoned: bool,
    /// `durable/` was fsync'd with `import.log` in it since the open.
    log_synced: bool,
}

impl fmt::Debug for FileSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSet")
            .field("dir", &self.dir.path())
            .finish_non_exhaustive()
    }
}

impl FileSet {
    /// Opens `<datadir>/durable/` (see the module docs): VERSION, CURRENT, cleanup, the base
    /// and the import log.
    pub fn open(datadir: &Path) -> Result<(Self, Loaded)> {
        Self::open_with(datadir, Hooks::default())
    }

    /// [`Self::open`] with a crash injected wherever `crash_at` returns true, also during the
    /// open: the operation returns [`Error::Crashed`] and leaves the disk as it is.
    #[cfg(feature = "test-hooks")]
    pub fn open_crashing(
        datadir: &Path,
        crash_at: impl Fn(Step, &str) -> bool + Send + Sync + 'static,
    ) -> Result<(Self, Loaded)> {
        Self::open_with(datadir, Hooks::crashing(crash_at))
    }

    fn open_with(datadir: &Path, hooks: Hooks) -> Result<(Self, Loaded)> {
        let mut set = Self {
            dir: AtomicDir::new(datadir.join(DIR), hooks),
            fault: AppendFault::default(),
            poisoned: false,
            log_synced: false,
        };
        set.check_version(datadir)?;
        let base = set.current()?.map(|name| set.read_base(name)).transpose()?;
        let keep: Vec<BaseName> = base
            .iter()
            .flat_map(|base| kept(BaseName::of(base), base.anchor))
            .collect();
        set.clean(&keep)?;
        let imports = set.load_log()?;
        Ok((set, Loaded { base, imports }))
    }

    /// Makes `anchor` the restart base: writes `anchor-<root>/` with `files`, swaps CURRENT to
    /// it, then deletes the previous base. A new anchor is a new trust root, so the previous
    /// anchor dir and every `finalized-*` dir go.
    pub fn install_anchor(&mut self, anchor: Checkpoint, files: &BaseFiles<'_>) -> Result<()> {
        self.writable()?;
        let old = self.current()?;
        let new = BaseName {
            kind: BaseKind::Anchor,
            root: anchor.root,
        };
        self.swap_base(old, new, anchor, files)
    }

    /// Makes the finalized block `root` the restart base: writes `finalized-<root>/` with
    /// `files` and the current base's anchor, swaps CURRENT to it, then deletes the previous
    /// `finalized-*` dir. `anchor-<root>/` of the carried anchor is kept.
    pub fn advance_finality(&mut self, root: [u8; 32], files: &BaseFiles<'_>) -> Result<()> {
        self.writable()?;
        let old = self.current()?.ok_or(Error::NoBase)?;
        let anchor = self.read_anchor(old)?;
        let new = BaseName {
            kind: BaseKind::Finalized,
            root,
        };
        self.swap_base(Some(old), new, anchor, files)
    }

    /// Appends `record` to `import.log` and fsyncs it.
    ///
    /// Contract: call it after the block's `blocks` transaction has committed and before the
    /// import is acknowledged. A crash before it leaves a block with no record, which loading
    /// ignores ([`Loaded::is_imported`]); once it returns, both are durable.
    ///
    /// On an I/O error the import is not acknowledged and the frame is cut back off: the file
    /// is truncated to its length before the append and fsync'd, so a partial frame never sits
    /// before a later good one. If that fails too, the set is poisoned: this and every later
    /// write is [`Error::Poisoned`] until [`Self::open`], whose load cuts the torn tail.
    pub fn record_import(&mut self, record: &ImportRecord) -> Result<()> {
        self.writable()?;
        let fault = std::mem::take(&mut self.fault);
        let path = self.dir.join(IMPORT_LOG);
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        let len = file.metadata()?.len();
        let appended = self.append(&mut file, record, fault);
        // Only an I/O error: an injected crash is the process dying, and nothing runs after it.
        if let Err(Error::Io(_)) = appended {
            if fault.truncate(&file, len).is_err() {
                self.poisoned = true;
            }
        }
        appended
    }

    /// Makes the next [`Self::record_import`] fail as `fault` says, once.
    #[cfg(feature = "test-hooks")]
    pub fn fail_next_append(&mut self, fault: AppendFault) {
        self.fault = fault;
    }

    /// Writes `record`'s frame at the end of `file` and fsyncs it, and `durable/` too if it
    /// was not fsync'd with the log in it since the open.
    fn append(&mut self, file: &mut File, record: &ImportRecord, fault: AppendFault) -> Result<()> {
        fault.write(file, &import_log::frame(record))?;
        self.dir.at(Step::Written, IMPORT_LOG)?;
        fault.sync(file)?;
        if !self.log_synced {
            self.sync_log_entry()?;
        }
        Ok(())
    }

    /// fsyncs `durable/`, so `import.log`'s entry in it is durable.
    fn sync_log_entry(&mut self) -> Result<()> {
        sync_dir(self.dir.path())?;
        self.log_synced = true;
        self.dir.at(Step::DirSynced, DIR)
    }

    /// [`Error::Poisoned`] once a failed append could not be rolled back.
    fn writable(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        Ok(())
    }

    fn check_version(&self, datadir: &Path) -> Result<()> {
        match fs::read(self.dir.join(VERSION)) {
            Ok(bytes) => return parse_version(&bytes),
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            Err(_) => {}
        }
        match fs::read_dir(self.dir.path()) {
            Ok(entries) => {
                for entry in entries {
                    if !is_leftover(&entry?.file_name()) {
                        return Err(Error::MissingVersion {
                            dir: self.dir.path().to_path_buf(),
                        });
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(self.dir.path())?;
                sync_dir(datadir)?;
            }
            Err(e) => return Err(e.into()),
        }
        self.dir
            .write_file(VERSION, format!("{FORMAT_VERSION}\n").as_bytes())
    }

    /// The base CURRENT names, `None` without a CURRENT.
    fn current(&self) -> Result<Option<BaseName>> {
        let bytes = match fs::read(self.dir.join(CURRENT)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let name = bytes
            .strip_suffix(b"\n")
            .and_then(|text| std::str::from_utf8(text).ok())
            .and_then(BaseName::parse)
            .ok_or_else(|| Error::BadCurrent {
                found: bytes.escape_ascii().to_string(),
            })?;
        let path = self.dir.join(&name.to_string());
        if !fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir()) {
            return Err(Error::BaseNotDir {
                name: name.to_string(),
            });
        }
        Ok(Some(name))
    }

    /// Removes temp files and dirs, and base dirs not in `keep`: a crash's leftovers, or the
    /// bases a base change replaced.
    fn clean(&self, keep: &[BaseName]) -> Result<()> {
        let mut removed = false;
        for entry in fs::read_dir(self.dir.path())? {
            let entry = entry?;
            let name = entry.file_name();
            let stale = name
                .to_str()
                .and_then(BaseName::parse)
                .is_some_and(|base| !keep.contains(&base));
            if !stale && !is_leftover(&name) {
                continue;
            }
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
            removed = true;
        }
        if removed {
            sync_dir(self.dir.path())?;
        }
        Ok(())
    }

    fn read_anchor(&self, name: BaseName) -> Result<Checkpoint> {
        read_optional(&self.dir.join(&name.to_string()).join(ANCHOR))?
            .as_deref()
            .and_then(Checkpoint::decode)
            .filter(|anchor| name.kind == BaseKind::Finalized || anchor.root == name.root)
            .ok_or_else(|| bad_base(name, ANCHOR))
    }

    fn read_base(&self, name: BaseName) -> Result<Base> {
        let dir = self.dir.join(&name.to_string());
        let required = |file| read_optional(&dir.join(file))?.ok_or_else(|| bad_base(name, file));
        Ok(Base {
            kind: name.kind,
            root: name.root,
            anchor: self.read_anchor(name)?,
            block: required(BLOCK)?,
            state: required(STATE)?,
            envelope: read_optional(&dir.join(ENVELOPE))?,
        })
    }

    fn load_log(&mut self) -> Result<Vec<ImportRecord>> {
        let path = self.dir.join(IMPORT_LOG);
        let mut file = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut log = Vec::new();
        file.read_to_end(&mut log)?;
        let (records, good) =
            import_log::parse(&log).map_err(|offset| Error::CorruptImportLog { offset })?;
        if good < log.len() {
            file.set_len(good as u64)?;
            file.sync_all()?;
        }
        self.sync_log_entry()?;
        Ok(records)
    }

    fn swap_base(
        &mut self,
        old: Option<BaseName>,
        new: BaseName,
        anchor: Checkpoint,
        files: &BaseFiles<'_>,
    ) -> Result<()> {
        let name = new.to_string();
        if old == Some(new) {
            return Err(Error::BaseIsCurrent { name });
        }
        let encoded = anchor.encode();
        let mut contents = vec![(BLOCK, files.block), (STATE, files.state)];
        contents.extend(files.envelope.map(|envelope| (ENVELOPE, envelope)));
        contents.push((ANCHOR, &encoded));
        self.dir.write_dir(&name, &contents)?;
        self.dir
            .write_file(CURRENT, format!("{name}\n").as_bytes())?;
        self.dir.at(Step::Swapped, &name)?;
        self.clean(&kept(new, anchor))
    }
}

fn parse_version(bytes: &[u8]) -> Result<()> {
    let found = bytes
        .strip_suffix(b"\n")
        .and_then(|text| std::str::from_utf8(text).ok())
        .and_then(|text| text.parse::<u64>().ok().filter(|v| v.to_string() == text));
    match found {
        Some(FORMAT_VERSION) => Ok(()),
        Some(found) if found > FORMAT_VERSION => Err(Error::NewerVersion { found }),
        _ => Err(Error::UnknownVersion {
            found: bytes.escape_ascii().to_string(),
        }),
    }
}

/// The base dirs `base` keeps: itself and `anchor-<root>/` of the operator anchor it carries
/// (for an anchor base, the same dir twice).
fn kept(base: BaseName, anchor: Checkpoint) -> [BaseName; 2] {
    let anchor = BaseName {
        kind: BaseKind::Anchor,
        root: anchor.root,
    };
    [base, anchor]
}

fn bad_base(name: BaseName, file: &'static str) -> Error {
    Error::BadBase {
        name: name.to_string(),
        file,
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
