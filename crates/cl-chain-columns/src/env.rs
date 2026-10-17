//! Env options shared by the writer and readers. Every opener uses [`SyncMode::Durable`]: MDBX
//! returns `MDBX_INCOMPATIBLE` when one process opens an env `SafeNoSync`/`UtterlyNoSync` and
//! another opens it `Durable`, so the sync mode is fixed here and not configurable.

use std::path::Path;

use libmdbx::{
    Database, DatabaseOptions, Mode, NoWriteMap, ReadWriteOptions, SyncMode, TableFlags,
};

use crate::{
    error::{Error, Result},
    keys::TABLES,
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
    for table in TABLES {
        txn.create_table(Some(table), TableFlags::empty())?;
    }
    txn.commit()?;
    Ok(env)
}

/// Opens an existing column env with `MDBX_RDONLY`: such an env has no write txn at all.
pub(crate) fn open_ro(path: &Path) -> Result<Env> {
    Ok(Env::open_with_options(path, options(Mode::ReadOnly))?)
}

/// Takes the writer guard: a tiny env next to the data opened `MDBX_EXCLUSIVE`. While any process
/// (this one included) has it open, MDBX refuses another open with `MDBX_BUSY` or the file-lock
/// errno (`EWOULDBLOCK`). The lock is an OS file lock, released when the holder exits, so a
/// crashed writer never leaves a stale lock behind.
pub(crate) fn lock_writer(path: &Path) -> Result<Env> {
    std::fs::create_dir_all(path)?;
    Env::open_with_options(
        path.join(WRITER_GUARD),
        DatabaseOptions {
            no_sub_dir: true,
            exclusive: true,
            ..DatabaseOptions::default()
        },
    )
    .map_err(|e| busy_means_writer_open(e, path))
}

fn busy_means_writer_open(e: libmdbx::Error, path: &Path) -> Error {
    let held = match e {
        libmdbx::Error::Busy => true,
        libmdbx::Error::Other(code) => {
            std::io::Error::from_raw_os_error(code).kind() == std::io::ErrorKind::WouldBlock
        }
        _ => false,
    };
    if held {
        Error::WriterAlreadyOpen {
            path: path.to_path_buf(),
        }
    } else {
        Error::Mdbx(e)
    }
}
