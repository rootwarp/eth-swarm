//! Atomic writes into one directory, and the crash-injection seam the tests drive.
//!
//! - [`AtomicDir::write_file`]: `<name>.tmp` written and fsync'd, renamed onto `<name>`, the
//!   directory fsync'd. A crash leaves the old content or the new, never a mix.
//! - [`AtomicDir::write_dir`]: `.tmp-<name>/` built (each file written and fsync'd, the dir
//!   fsync'd), renamed onto `<name>/`, the directory fsync'd.
//!
//! Each step reports to the [`Hooks`]; with the `test-hooks` feature a hook can stop the write
//! there ([`super::durable::Error::Crashed`]), leaving the disk as it is. An [`AppendFault`]
//! makes an `import.log` append fail with an I/O error instead, and the process goes on.

use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

use super::durable::Result;

const TMP_SUFFIX: &str = ".tmp";
const TMP_DIR_PREFIX: &str = ".tmp-";

/// A point of a durable write where a test injects a crash
/// ([`FileSet::open_crashing`](super::durable::FileSet::open_crashing), feature `test-hooks`).
/// The hook gets the step and the name of the file or dir being written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Bytes written (to a temp file, into a temp dir, or appended to `import.log`), not
    /// fsync'd.
    Written,
    /// A file, or a base dir under its temp name, fsync'd and not renamed into place.
    Synced,
    /// Renamed into place; the directory not fsync'd.
    Renamed,
    /// CURRENT names the new base (named here), durably; the old base is not deleted.
    Swapped,
    /// `durable/` (named here) fsync'd for `import.log`: the log's entry in it is durable.
    DirSynced,
}

#[cfg(feature = "test-hooks")]
type CrashAt = Box<dyn Fn(Step, &str) -> bool + Send + Sync>;

/// The fail points: none without the `test-hooks` feature.
#[derive(Default)]
pub(super) struct Hooks {
    #[cfg(feature = "test-hooks")]
    crash_at: Option<CrashAt>,
}

impl Hooks {
    /// `Err(Crashed)` if the hook asks for a crash at this step.
    fn at(&self, _step: Step, _name: &str) -> Result<()> {
        #[cfg(feature = "test-hooks")]
        if (self.crash_at.as_ref()).is_some_and(|crash| crash(_step, _name)) {
            return Err(super::durable::Error::Crashed {
                step: _step,
                name: _name.to_owned(),
            });
        }
        Ok(())
    }

    /// Hooks that crash wherever `crash_at` returns true.
    #[cfg(feature = "test-hooks")]
    pub(super) fn crashing(crash_at: impl Fn(Step, &str) -> bool + Send + Sync + 'static) -> Self {
        Self {
            crash_at: Some(Box::new(crash_at)),
        }
    }
}

/// A directory written only through atomic steps.
pub(super) struct AtomicDir {
    path: PathBuf,
    hooks: Hooks,
}

impl AtomicDir {
    pub(super) fn new(path: PathBuf, hooks: Hooks) -> Self {
        Self { path, hooks }
    }

    /// The directory.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// `name` inside the directory.
    pub(super) fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// `Err(Crashed)` if the hook asks for a crash at this step.
    pub(super) fn at(&self, step: Step, name: &str) -> Result<()> {
        self.hooks.at(step, name)
    }

    /// Writes the file `name` atomically.
    pub(super) fn write_file(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let tmp = self.join(&format!("{name}{TMP_SUFFIX}"));
        self.write_synced(&tmp, name, bytes)?;
        fs::rename(&tmp, self.join(name))?;
        self.at(Step::Renamed, name)?;
        sync_dir(&self.path)
    }

    /// Writes the directory `name` holding `files` atomically. A directory of that name left by
    /// a crashed write is replaced; the caller never names one it still needs.
    pub(super) fn write_dir(&self, name: &str, files: &[(&'static str, &[u8])]) -> Result<()> {
        let tmp = self.join(&format!("{TMP_DIR_PREFIX}{name}"));
        remove_dir_if_any(&tmp)?;
        fs::create_dir(&tmp)?;
        for (file, bytes) in files {
            self.write_synced(&tmp.join(file), file, bytes)?;
        }
        sync_dir(&tmp)?;
        self.at(Step::Synced, name)?;
        let target = self.join(name);
        remove_dir_if_any(&target)?;
        fs::rename(&tmp, &target)?;
        self.at(Step::Renamed, name)?;
        sync_dir(&self.path)
    }

    fn write_synced(&self, path: &Path, name: &str, bytes: &[u8]) -> Result<()> {
        let mut file = File::create(path)?;
        file.write_all(bytes)?;
        self.at(Step::Written, name)?;
        file.sync_all()?;
        self.at(Step::Synced, name)
    }
}

/// A temp file or dir a crashed write can leave.
pub(super) fn is_leftover(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.ends_with(TMP_SUFFIX) || name.starts_with(TMP_DIR_PREFIX))
}

/// fsyncs a directory, so the entries created, renamed or removed in it are durable.
pub(super) fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// I/O failures a test injects into one `import.log` append
/// ([`FileSet::fail_next_append`](super::durable::FileSet::fail_next_append), feature
/// `test-hooks`). Unlike a crash, the append returns [`super::durable::Error::Io`], as a full
/// disk or a failing device would, and the process goes on. Without the feature it has no
/// fields and injects nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AppendFault {
    /// The frame's write puts only its first `n` bytes in the file, then fails. `None`: the
    /// whole frame is written.
    #[cfg(feature = "test-hooks")]
    pub short_write: Option<usize>,
    /// The frame's fsync fails.
    #[cfg(feature = "test-hooks")]
    pub sync: bool,
    /// Rolling the failed append back (truncate and fsync) fails.
    #[cfg(feature = "test-hooks")]
    pub rollback: bool,
}

impl AppendFault {
    /// Writes `frame` to `file`; with a short write, only its first bytes and then an error.
    pub(super) fn write(&self, file: &mut File, frame: &[u8]) -> io::Result<()> {
        #[cfg(feature = "test-hooks")]
        if let Some(n) = self.short_write {
            file.write_all(frame.get(..n).unwrap_or(frame))?;
            return Err(injected("write"));
        }
        file.write_all(frame)
    }

    /// fsyncs the data appended to `file`.
    pub(super) fn sync(&self, file: &File) -> io::Result<()> {
        #[cfg(feature = "test-hooks")]
        if self.sync {
            return Err(injected("fsync"));
        }
        file.sync_data()
    }

    /// Cuts `file` back to `len` bytes and fsyncs it.
    pub(super) fn truncate(&self, file: &File, len: u64) -> io::Result<()> {
        #[cfg(feature = "test-hooks")]
        if self.rollback {
            return Err(injected("truncate"));
        }
        file.set_len(len)?;
        file.sync_all()
    }
}

#[cfg(feature = "test-hooks")]
fn injected(call: &str) -> io::Error {
    io::Error::other(format!("injected {call} failure"))
}

fn remove_dir_if_any(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}
