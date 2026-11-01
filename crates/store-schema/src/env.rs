//! Env options shared by the writer and readers. Every opener uses [`SyncMode::Durable`] and
//! `max_tables` = [`MAX_TABLES`]: MDBX returns `MDBX_INCOMPATIBLE` when one process opens an
//! env `SafeNoSync`/`UtterlyNoSync` and another opens it `Durable`, so the sync mode is fixed
//! here and not configurable.

use std::path::Path;
use std::time::Duration;

use libmdbx::{
    Database, DatabaseOptions, Mode, NoWriteMap, ReadWriteOptions, SyncMode, TableFlags,
    Transaction, RW,
};

use crate::{
    tables::{MAX_TABLES, TABLES},
    version, Error, Result,
};

/// The env handle.
pub type Env = Database<NoWriteMap>;

/// A write transaction of the env, as [`open_writer_with`]'s upgrade hook gets it.
pub type RwTxn<'env> = Transaction<'env, RW, NoWriteMap>;

/// Default upper bound of the memory map, 256 GiB. Only address space is reserved up front; the
/// file grows in 256 MiB steps.
///
/// What that holds: a full-custody block at 48 blobs is 128 Fulu sidecars of
/// `356 + 48 * 2144` = 103,268 B, 104 KiB each once MDBX rounds the value up to 4 KiB overflow
/// pages, so about 13.6 MB per block. 256 GiB is then about 20,000 blocks: about 2.8 days of
/// 12 s slots without finality, nearer 2.7 after MDBX free-page overhead, less with more blobs.
/// Past that, writes fail with `MDBX_MAP_FULL`; raise [`WriterOptions::max_size`] for longer
/// non-finality.
pub const DEFAULT_MAX_SIZE: usize = 256 << 30;
const GROWTH_STEP: usize = 256 << 20;

/// Smallest accepted [`WriterOptions::max_size`]: one growth step, far above MDBX's own minimum
/// (three pages).
pub const MIN_MAX_SIZE: usize = GROWTH_STEP;

/// [`WriterOptions::max_size`] must be a multiple of this. MDBX rounds the map's upper bound up
/// to the larger of the OS and DB page size (at most 64 KiB); with a 1 MiB multiple no rounding
/// happens, so the effective size can be compared with the requested one exactly.
pub const MAX_SIZE_ALIGN: usize = 1 << 20;

/// Options for [`open_writer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterOptions {
    /// Upper bound of the memory map in bytes: a multiple of [`MAX_SIZE_ALIGN`], at least
    /// [`MIN_MAX_SIZE`]. Default [`DEFAULT_MAX_SIZE`].
    ///
    /// MDBX applies a new size only when the writer opens the env alone. While another process
    /// (cl-store's reader) has it open, MDBX keeps the size stored in the env and the open fails
    /// with [`Error::GeometryMismatch`] rather than run with a size the caller did not ask for.
    pub max_size: usize,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_SIZE,
        }
    }
}

/// File name (no sub-directory) of the writer guard env inside the env directory.
const WRITER_GUARD: &str = "writer.guard";

/// The options of every open; only the mode differs between the writer and readers.
fn options(mode: Mode) -> DatabaseOptions {
    DatabaseOptions {
        max_tables: Some(MAX_TABLES),
        mode,
        ..DatabaseOptions::default()
    }
}

/// The env opened read-write, and the writer guard that keeps every other writer out. Dropping
/// it closes the env first, then releases the guard.
#[derive(Debug)]
pub struct WriterEnv {
    // Field order is drop order: close the data env before releasing the guard.
    env: Env,
    guard: WriterGuard,
}

/// The held writer guard; dropping it lets the next writer in.
#[derive(Debug)]
pub struct WriterGuard {
    _env: Env,
}

impl WriterEnv {
    /// The env, for read and write transactions.
    #[must_use]
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// The env and the guard apart, for a caller that keeps the env elsewhere. Drop the env
    /// before the guard.
    #[must_use]
    pub fn into_parts(self) -> (Env, WriterGuard) {
        (self.env, self.guard)
    }
}

/// [`open_writer_with`] with no upgrade of its own.
pub fn open_writer(path: &Path, opts: WriterOptions) -> Result<WriterEnv> {
    open_writer_with(path, opts, |_, _| Ok(()))
}

/// Opens (creating if needed) the env at `path` as its one writer.
///
/// Takes the writer guard, opens the env read-write and checks that the requested map size is
/// in effect. Then, in one write transaction: checks the schema version ([`version`]), creates
/// every missing table, runs `upgrade` with the names of the tables this open created, writes
/// the version row if there was none, and commits. An error anywhere aborts the transaction,
/// so a refused or failed open writes nothing.
///
/// `upgrade` is where a crate that owns some tables migrates their data in the same transaction
/// that creates the tables (cl-chain-columns' links migration).
///
/// Blocking: an `EAGAIN` on the guard or the env is retried for about a second
/// ([`WRITER_LOCK_ATTEMPTS`] tries, [`WRITER_LOCK_RETRY_INTERVAL`] apart), sleeping the calling
/// thread. Call it at startup, or from async code through `spawn_blocking`.
///
/// Why a geometry error and not a resize after open: libmdbx 0.5.6 has no API to change the
/// geometry of an open env, and calling `mdbx_env_set_geometry` through the C API would run
/// MDBX's own write txn outside the caller's txn scheduler and libmdbx's txn manager thread.
/// Restarting with readers detached (or keeping the stored size) is the safe way to resize.
pub fn open_writer_with<E, F>(path: &Path, opts: WriterOptions, upgrade: F) -> Result<WriterEnv, E>
where
    E: From<Error>,
    F: FnOnce(&RwTxn<'_>, &[&'static str]) -> Result<(), E>,
{
    let guard = WriterGuard {
        _env: lock_writer(path)?,
    };
    let env = open_rw(path, opts)?;
    let txn = env.begin_rw_txn().map_err(Error::from)?;
    let stored = version::check(&txn)?;
    let mut created = Vec::new();
    for table in TABLES {
        match txn.open_table(Some(table)) {
            Ok(_) => {}
            Err(libmdbx::Error::NotFound) => {
                txn.create_table(Some(table), TableFlags::empty())
                    .map_err(Error::from)?;
                created.push(table);
            }
            Err(e) => return Err(Error::from(e).into()),
        }
    }
    upgrade(&txn, &created)?;
    if stored.is_none() {
        version::write(&txn)?;
    }
    txn.commit().map_err(Error::from)?;
    Ok(WriterEnv { env, guard })
}

/// Opens an existing env with `MDBX_RDONLY` (no write txn at all) and the writer's options,
/// and checks its schema version. Never opens the writer guard.
pub fn open_reader(path: &Path) -> Result<Env> {
    let env = Env::open_with_options(path, options(Mode::ReadOnly))?;
    version::check(&env.begin_ro_txn()?)?;
    Ok(env)
}

/// [`open_rw_with`] with the production pace and opener.
fn open_rw(path: &Path, opts: WriterOptions) -> Result<Env> {
    open_rw_with(path, opts, WriterLockPace::production(), |path, options| {
        Env::open_with_options(path, options)
    })
}

/// Opens the env read-write with the pace of the `EAGAIN` retries and the env opener given
/// (tests), and checks the map size.
fn open_rw_with(
    path: &Path,
    opts: WriterOptions,
    pace: WriterLockPace,
    mut open: impl FnMut(&Path, DatabaseOptions) -> std::result::Result<Env, libmdbx::Error>,
) -> Result<Env> {
    let requested = opts.max_size;
    let max_size = isize::try_from(requested)
        .ok()
        .filter(|_| requested >= MIN_MAX_SIZE && requested.is_multiple_of(MAX_SIZE_ALIGN))
        .ok_or(Error::InvalidMaxSize {
            max_size: requested,
        })?;
    let growth_step = GROWTH_STEP as isize;
    std::fs::create_dir_all(path)?;
    // The same lingering lock the guard can meet after a writer is reaped ([`lock_writer`]):
    // retried on the same budget.
    let env = retry_writer_lock(path, pace, || {
        open(
            path,
            options(Mode::ReadWrite(ReadWriteOptions {
                sync_mode: SyncMode::Durable,
                max_size: Some(max_size),
                growth_step: Some(growth_step),
                ..ReadWriteOptions::default()
            })),
        )
    })?;
    let effective = env.info()?.map_size();
    if effective != requested {
        return Err(Error::GeometryMismatch {
            requested,
            effective,
        });
    }
    Ok(env)
}

/// How many times the writer guard is tried before [`Error::WriterHeld`].
pub const WRITER_LOCK_ATTEMPTS: u32 = 50;

/// Pause between those attempts. Fifty tries at this interval is about one second.
pub const WRITER_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// How [`retry_writer_lock`] waits. Tests pass [`Duration::ZERO`] so a full budget does not
/// sleep.
struct WriterLockPace {
    /// Tries, including the first. At least 1.
    attempts: u32,
    /// Sleep after an `EAGAIN` that will be tried again. Zero skips the sleep.
    interval: Duration,
}

impl WriterLockPace {
    const fn production() -> Self {
        Self {
            attempts: WRITER_LOCK_ATTEMPTS,
            interval: WRITER_LOCK_RETRY_INTERVAL,
        }
    }
}

/// Takes the writer guard: a tiny env next to the data opened `MDBX_EXCLUSIVE`.
///
/// A live holder makes that open return `EAGAIN`/`EWOULDBLOCK` (`libmdbx::Error::Other(11)`
/// on Linux): the OFD lock. The same errno comes back for a moment after the holder is reaped.
/// A `/proc` reader (`maps`, `smaps`, `environ`) can keep the dead child's address space alive,
/// and its mmaps pin the open-file description, so the lock lingers with no fd holder. Only
/// that errno is retried, [`WRITER_LOCK_ATTEMPTS`] times, [`WRITER_LOCK_RETRY_INTERVAL`] apart.
/// `MDBX_BUSY` is [`Error::EnvBusy`] on that attempt. Any other error is returned as-is, also
/// without a retry.
fn lock_writer(path: &Path) -> Result<Env> {
    std::fs::create_dir_all(path)?;
    let guard = path.join(WRITER_GUARD);
    retry_writer_lock(path, WriterLockPace::production(), || {
        Env::open_with_options(
            &guard,
            DatabaseOptions {
                no_sub_dir: true,
                exclusive: true,
                ..DatabaseOptions::default()
            },
        )
    })
}

/// Runs `attempt` until the exclusive lock is held, the `EAGAIN` budget is spent, or some
/// other error comes back. `path` is the env directory, named in the error.
fn retry_writer_lock<T, F>(path: &Path, pace: WriterLockPace, mut attempt: F) -> Result<T>
where
    F: FnMut() -> std::result::Result<T, libmdbx::Error>,
{
    let held = || path.to_path_buf();
    let mut n = 0u32;
    loop {
        n += 1;
        match attempt() {
            Ok(guard) => return Ok(guard),
            Err(err) if is_eagain(&err) && n < pace.attempts => {
                if !pace.interval.is_zero() {
                    std::thread::sleep(pace.interval);
                }
            }
            Err(err) if is_eagain(&err) => return Err(Error::WriterHeld { path: held() }),
            Err(libmdbx::Error::Busy) => return Err(Error::EnvBusy { path: held() }),
            Err(err) => return Err(err.into()),
        }
    }
}

/// `EAGAIN` and `EWOULDBLOCK`. On Linux they are the same errno (`11`); both are
/// [`std::io::ErrorKind::WouldBlock`].
fn is_eagain(err: &libmdbx::Error) -> bool {
    match err {
        libmdbx::Error::Other(code) => {
            std::io::Error::from_raw_os_error(*code).kind() == std::io::ErrorKind::WouldBlock
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `EAGAIN` on Linux. `EWOULDBLOCK` is the same value, so one errno covers both names.
    const EAGAIN: i32 = 11;

    fn pace() -> WriterLockPace {
        WriterLockPace {
            attempts: WRITER_LOCK_ATTEMPTS,
            interval: Duration::ZERO,
        }
    }

    #[test]
    fn eagain_then_success_counts_every_attempt() {
        let mut calls = 0;
        let got = retry_writer_lock(Path::new("/env"), pace(), || {
            calls += 1;
            if calls <= 3 {
                Err(libmdbx::Error::Other(EAGAIN))
            } else {
                Ok(calls)
            }
        })
        .unwrap();
        assert_eq!(calls, 4);
        assert_eq!(got, 4);
    }

    #[test]
    fn eagain_until_the_cap_is_writer_held_after_exactly_50() {
        let mut calls = 0;
        let err = retry_writer_lock(Path::new("/env"), pace(), || {
            calls += 1;
            Err::<(), _>(libmdbx::Error::Other(EAGAIN))
        })
        .unwrap_err();
        assert!(
            matches!(err, Error::WriterHeld { ref path } if path == Path::new("/env")),
            "{err}"
        );
        assert_eq!(calls, WRITER_LOCK_ATTEMPTS);
    }

    #[test]
    fn mdbx_busy_is_env_busy_on_the_first_attempt() {
        let mut calls = 0;
        let err = retry_writer_lock(Path::new("/env"), pace(), || {
            calls += 1;
            Err::<(), _>(libmdbx::Error::Busy)
        })
        .unwrap_err();
        assert!(
            matches!(err, Error::EnvBusy { ref path } if path == Path::new("/env")),
            "{err}"
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn eagain_then_busy_stops_without_finishing_the_budget() {
        let mut calls = 0;
        let err = retry_writer_lock(Path::new("/env"), pace(), || {
            calls += 1;
            if calls <= 2 {
                Err(libmdbx::Error::Other(EAGAIN))
            } else {
                Err::<(), _>(libmdbx::Error::Busy)
            }
        })
        .unwrap_err();
        assert!(matches!(err, Error::EnvBusy { .. }), "{err}");
        assert_eq!(calls, 3);
    }

    /// The data env open meets the same lingering lock as the guard after a writer is reaped
    /// (see [`lock_writer`]): its `EAGAIN` is retried on the same budget.
    #[test]
    fn the_data_env_open_retries_eagain_on_the_writer_lock_budget() {
        let dir = tempfile::tempdir().unwrap();
        let mut calls = 0;
        let env = open_rw_with(
            dir.path(),
            WriterOptions::default(),
            pace(),
            |path, options| {
                calls += 1;
                if calls <= 3 {
                    Err(libmdbx::Error::Other(EAGAIN))
                } else {
                    Env::open_with_options(path, options)
                }
            },
        )
        .unwrap();
        assert_eq!(calls, 4);
        drop(env);
        let mut calls = 0;
        let err = open_rw_with(dir.path(), WriterOptions::default(), pace(), |_, _| {
            calls += 1;
            Err(libmdbx::Error::Other(EAGAIN))
        })
        .unwrap_err();
        assert!(matches!(err, Error::WriterHeld { .. }), "{err}");
        assert_eq!(calls, WRITER_LOCK_ATTEMPTS);
    }

    #[test]
    fn any_other_lock_error_fails_on_the_first_attempt() {
        let mut calls = 0;
        let err = retry_writer_lock(Path::new("/env"), pace(), || {
            calls += 1;
            Err::<(), _>(libmdbx::Error::Other(1))
        })
        .unwrap_err();
        assert!(
            matches!(err, Error::Mdbx(libmdbx::Error::Other(1))),
            "{err:?}"
        );
        assert_eq!(calls, 1);
    }
}
