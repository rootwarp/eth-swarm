//! "An oversized genesis state is refused without being read", measured: `open_export` runs
//! under a counting global allocator that records the peak live heap on the measuring thread,
//! against a state file one byte over [`MAX_GENESIS_STATE_BYTES`] (sparse, so it costs no disk).

use sha2::{Digest, Sha256};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use testkit::archive::fixtures::Spec;
use testkit::export_blocks::fixtures::{chain, config, Devnet};
use testkit::export_blocks::{
    export, open_export, ExportError, EXPORT_FILE, GENESIS_STATE_FILE, MAX_GENESIS_STATE_BYTES,
};

/// Far below the state bound, far above what opening a five-block export allocates.
const PEAK_LIMIT: usize = 16 << 20;

struct Counting;

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

fn record_alloc(size: usize) {
    let _ = ON.try_with(|on| {
        if on.get() {
            LIVE.with(|l| {
                let live = l.get() + size;
                l.set(live);
                PEAK.with(|p| p.set(p.get().max(live)));
            });
        }
    });
}

fn record_free(size: usize) {
    let _ = ON.try_with(|on| {
        if on.get() {
            LIVE.with(|l| l.set(l.get().saturating_sub(size)));
        }
    });
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_alloc(layout.size());
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_alloc(layout.size());
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record_free(layout.size());
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_free(layout.size());
        record_alloc(new_size);
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// `f`'s result and the peak live heap while it runs, on this thread.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    LIVE.with(|c| c.set(0));
    PEAK.with(|c| c.set(0));
    ON.with(|on| on.set(true));
    let value = f();
    ON.with(|on| on.set(false));
    (value, PEAK.with(Cell::get))
}

/// A fresh export of a short fixture chain under `out`, and its directory.
fn exported(out: &Path) -> PathBuf {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (server, _) = Devnet::new(4, &[]).serve().await;
        let export = export::<Spec>(&server.url(""), &chain(), &config(4), out)
            .await
            .unwrap();
        export.dir().to_owned()
    })
}

/// Rewrites `export.toml` with the genesis state's `len` set to `len`, rehashed, without
/// validating it (a forger's manifest).
fn forge_state_len(dir: &Path, len: u64) {
    let path = dir.join(EXPORT_FILE);
    let text = fs::read_to_string(&path).unwrap();
    let (_, body) = text.split_once('\n').unwrap();
    let at = body.find("\nlen = ").unwrap() + 1;
    let end = at + body[at..].find('\n').unwrap();
    let body = format!("{}len = {len}{}", &body[..at], &body[end..]);
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    fs::write(path, format!("export_sha256 = \"{digest}\"\n{body}")).unwrap();
}

/// Grows the genesis state file, sparsely, to one byte over the bound.
fn oversize_state(dir: &Path) {
    let file = fs::OpenOptions::new()
        .write(true)
        .open(dir.join(GENESIS_STATE_FILE))
        .unwrap();
    file.set_len(MAX_GENESIS_STATE_BYTES + 1).unwrap();
}

#[test]
fn an_oversized_state_file_is_refused_by_its_size() {
    // The manifest lists the bound itself; the file is one byte over it.
    let out = tempfile::tempdir().unwrap();
    let dir = exported(out.path());
    forge_state_len(&dir, MAX_GENESIS_STATE_BYTES);
    oversize_state(&dir);
    let (opened, peak) = measure(|| open_export(&dir));
    let err = opened.unwrap_err();
    assert!(
        matches!(&err, ExportError::Mismatch(m) if m.contains("bound")),
        "{err}"
    );
    assert!(peak < PEAK_LIMIT, "peak heap {peak} bytes");
}

#[test]
fn a_manifest_over_the_state_bound_is_refused_before_any_read() {
    let out = tempfile::tempdir().unwrap();
    let dir = exported(out.path());
    forge_state_len(&dir, MAX_GENESIS_STATE_BYTES + 1);
    oversize_state(&dir);
    let (opened, peak) = measure(|| open_export(&dir));
    let err = opened.unwrap_err();
    assert!(matches!(err, ExportError::Manifest { .. }), "{err}");
    assert!(peak < PEAK_LIMIT, "peak heap {peak} bytes");
}

#[test]
fn an_honest_export_opens_within_the_bound() {
    let out = tempfile::tempdir().unwrap();
    let dir = exported(out.path());
    let (opened, peak) = measure(|| open_export(&dir));
    opened.unwrap();
    assert!(peak < PEAK_LIMIT, "peak heap {peak} bytes");
}
