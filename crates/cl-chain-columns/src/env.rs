//! Env options shared by the writer and readers. Every opener uses [`SyncMode::Durable`]: MDBX
//! returns `MDBX_INCOMPATIBLE` when one process opens an env `SafeNoSync`/`UtterlyNoSync` and
//! another opens it `Durable`, so the sync mode is fixed here and not configurable.

use std::path::Path;
use std::time::Duration;

use libmdbx::{
    Database, DatabaseOptions, Mode, NoWriteMap, ReadWriteOptions, SyncMode, TableFlags, WriteFlags,
};

use crate::{
    error::{Error, Result},
    keys::{CONTIGUOUS_FROM_KEY, LINKS_TABLE, META_TABLE, TABLES},
    reader::{after_highest_block, meta_u64},
};

pub(crate) type Env = Database<NoWriteMap>;

/// `max_tables` for the env. Must be set before any named table is created or opened:
/// `DatabaseOptions::default()` leaves it `None` and named tables then fail with `DbsFull`.
pub(crate) const MAX_TABLES: u64 = TABLES.len() as u64;

/// Default upper bound of the memory map, 256 GiB. Only address space is reserved up front; the
/// file grows in 256 MiB steps.
///
/// What that holds: a full-custody block at 48 blobs is 128 Fulu sidecars of
/// `356 + 48 * 2144` = 103,268 B, 104 KiB each once MDBX rounds the value up to 4 KiB overflow
/// pages, so about 13.6 MB per block. 256 GiB is then about 20,000 blocks: about 2.8 days of
/// 12 s slots without finality, nearer 2.7 after MDBX free-page overhead, less with more blobs.
/// Past that, writes fail with [`Error::MapFull`]; raise [`WriterOptions::max_size`] for longer
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

/// Options for [`ColumnWriter::open_with`](crate::ColumnWriter::open_with).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterOptions {
    /// Upper bound of the memory map in bytes: a multiple of [`MAX_SIZE_ALIGN`], at least
    /// [`MIN_MAX_SIZE`]. Default [`DEFAULT_MAX_SIZE`].
    ///
    /// MDBX applies a new size only when the writer opens the env alone. While another process
    /// (cl-store's [`ColumnReader`](crate::ColumnReader)) has it open, MDBX keeps the size stored
    /// in the env and the open fails with [`Error::GeometryMismatch`] rather than run with a
    /// size the caller did not ask for.
    pub max_size: usize,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            max_size: DEFAULT_MAX_SIZE,
        }
    }
}

/// File name (no sub-directory) of the writer guard env inside the column env directory.
const WRITER_GUARD: &str = "writer.guard";

fn options(mode: Mode) -> DatabaseOptions {
    DatabaseOptions {
        max_tables: Some(MAX_TABLES),
        mode,
        ..DatabaseOptions::default()
    }
}

/// Opens (creating if needed) the column env read-write, checks that the requested map size is
/// in effect, and creates every table in one txn.
///
/// Why an error and not a resize after open: libmdbx 0.5.6 has no API to change the geometry
/// of an open env, and calling `mdbx_env_set_geometry` through the C API would run MDBX's own
/// write txn outside the writer's txn scheduler and libmdbx's txn manager thread. Restarting
/// with cl-store detached (or keeping the stored size) is the safe way to resize.
pub(crate) fn open_rw(path: &Path, opts: WriterOptions) -> Result<Env> {
    let requested = opts.max_size;
    let max_size = isize::try_from(requested)
        .ok()
        .filter(|_| requested >= MIN_MAX_SIZE && requested.is_multiple_of(MAX_SIZE_ALIGN))
        .ok_or(Error::InvalidMaxSize {
            max_size: requested,
        })?;
    let growth_step = GROWTH_STEP as isize;
    std::fs::create_dir_all(path)?;
    let env = Env::open_with_options(
        path,
        options(Mode::ReadWrite(ReadWriteOptions {
            sync_mode: SyncMode::Durable,
            max_size: Some(max_size),
            growth_step: Some(growth_step),
            ..ReadWriteOptions::default()
        })),
    )?;
    let effective = env.info()?.map_size();
    if effective != requested {
        return Err(Error::GeometryMismatch {
            requested,
            effective,
        });
    }
    let txn = env.begin_rw_txn()?;
    let had_links = match txn.open_table(Some(LINKS_TABLE)) {
        Ok(_) => true,
        Err(libmdbx::Error::NotFound) => false,
        Err(e) => return Err(e.into()),
    };
    for table in TABLES {
        txn.create_table(Some(table), TableFlags::empty())?;
    }
    // An env written before the links table existed: its blocks have no links, so none of
    // them can be chained to; claim nothing up to and including its highest stored block.
    if !had_links {
        if let Some(after) = after_highest_block(&txn)? {
            let meta = txn.open_table(Some(META_TABLE))?;
            let current = meta_u64(&txn, CONTIGUOUS_FROM_KEY)?;
            let from = current.map_or(after, |c| c.max(after));
            txn.put(
                &meta,
                CONTIGUOUS_FROM_KEY,
                from.to_be_bytes(),
                WriteFlags::UPSERT,
            )?;
        }
    }
    // Pending links stored without their target's slot.
    crate::writer::migrate_legacy_pending(&txn)?;
    txn.commit()?;
    Ok(env)
}

/// Opens an existing column env with `MDBX_RDONLY`: such an env has no write txn at all.
pub(crate) fn open_ro(path: &Path) -> Result<Env> {
    Ok(Env::open_with_options(path, options(Mode::ReadOnly))?)
}

/// How many times [`lock_writer`] tries the exclusive guard before
/// [`Error::WriterAlreadyOpen`].
pub const WRITER_LOCK_ATTEMPTS: u32 = 50;

/// Pause between those attempts. Fifty tries at this interval is about one second.
pub const WRITER_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// How [`lock_writer`] waits. Tests pass [`Duration::ZERO`] so a full budget does not sleep.
pub(crate) struct WriterLockPace {
    /// Tries, including the first. At least 1.
    pub attempts: u32,
    /// Sleep after an `EAGAIN` that will be tried again. Zero skips the sleep.
    pub interval: Duration,
}

impl WriterLockPace {
    pub(crate) const fn production() -> Self {
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
pub(crate) fn lock_writer(path: &Path) -> Result<Env> {
    std::fs::create_dir_all(path)?;
    let guard = path.join(WRITER_GUARD);
    retry_writer_lock(path, WriterLockPace::production(), || {
        open_exclusive(&guard)
    })
}

fn open_exclusive(guard: &Path) -> std::result::Result<Env, libmdbx::Error> {
    Env::open_with_options(
        guard,
        DatabaseOptions {
            no_sub_dir: true,
            exclusive: true,
            ..DatabaseOptions::default()
        },
    )
}

/// Runs `attempt` until the exclusive lock is held, the `EAGAIN` budget is spent, or some
/// other error comes back. `path` is the column env directory, named in the error.
pub(crate) fn retry_writer_lock<T, F>(
    path: &Path,
    pace: WriterLockPace,
    mut attempt: F,
) -> Result<T>
where
    F: FnMut() -> std::result::Result<T, libmdbx::Error>,
{
    let mut n = 0u32;
    loop {
        n += 1;
        match attempt() {
            Ok(guard) => return Ok(guard),
            Err(err) if is_eagain(&err) && n < pace.attempts => {
                tracing::warn!(
                    attempt = n,
                    attempts = pace.attempts,
                    path = %path.display(),
                    "exclusive writer lock returned EAGAIN; retrying"
                );
                if !pace.interval.is_zero() {
                    std::thread::sleep(pace.interval);
                }
            }
            Err(err) if is_eagain(&err) => {
                return Err(Error::WriterAlreadyOpen {
                    path: path.to_path_buf(),
                });
            }
            Err(libmdbx::Error::Busy) => {
                return Err(Error::EnvBusy {
                    path: path.to_path_buf(),
                });
            }
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
    fn eagain_until_the_cap_is_writer_already_open_after_exactly_50() {
        let mut calls = 0;
        let err = retry_writer_lock(Path::new("/env"), pace(), || {
            calls += 1;
            Err::<(), _>(libmdbx::Error::Other(EAGAIN))
        })
        .unwrap_err();
        assert!(
            matches!(err, Error::WriterAlreadyOpen { ref path } if path == Path::new("/env")),
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
