//! Test fixtures: cl-chain's side of the tests (a writer env and stamped imports, through
//! store-schema's `test-hooks` seam) and real Fulu blocks from store-schema's `tests/common`.

#[path = "../../store-schema/tests/common/mod.rs"]
pub(crate) mod common;

use std::{borrow::Borrow, sync::Arc, time::Duration};

use store_schema::{
    env::{self, Env, WriterEnv},
    keys::Root,
    stamp::Stamp,
    txn::{self, Update},
};

use crate::reader::{system_clock, Deadline, Reader};

/// The writer's env, shared with the readers of the same process: MDBX refuses a second open
/// of one env in one process, so an in-process reader reads through the writer's own env.
struct Shared(Arc<WriterEnv>);

impl Borrow<Env> for Shared {
    fn borrow(&self) -> &Env {
        self.0.raw_env()
    }
}

/// A store env in a temp dir and its writer: cl-chain, as the tests need it.
pub(crate) struct Store {
    writer: Arc<WriterEnv>,
    _dir: tempfile::TempDir,
}

impl Store {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(env::test_writer(dir.path()).unwrap());
        Self { writer, _dir: dir }
    }

    pub(crate) fn writer(&self) -> &WriterEnv {
        &self.writer
    }

    /// A reader of this env, reading through the writer's env.
    pub(crate) fn reader(&self) -> Reader {
        Reader::over(Shared(Arc::clone(&self.writer)))
    }

    /// [`import`] into this env.
    pub(crate) fn import(&self, blocks: &[&[u8]], stamp: Stamp) {
        import(&self.writer, blocks, stamp);
    }
}

/// cl-chain's import: `blocks` and `stamp` in one write txn, through store-schema's stamped
/// commit.
pub(crate) fn import(writer: &WriterEnv, blocks: &[&[u8]], stamp: Stamp) {
    let txn = txn::begin(writer).unwrap();
    for ssz in blocks {
        store_schema::blocks::put::<common::E>(&txn, &common::schedule(), ssz).unwrap();
    }
    assert_eq!(txn::commit(txn, Update::New(stamp)).unwrap(), Some(stamp));
}

/// The SSZ and root of a Fulu block at `slot` on `parent`; `salt` makes siblings differ.
pub(crate) fn block(slot: u64, parent: Root, salt: u64) -> (Vec<u8>, Root) {
    common::fulu_block_ssz(slot, parent, salt)
}

/// A stamp: event `seq`, head and finalized `(slot, root)`.
pub(crate) fn stamp(seq: u64, head: (u64, Root), finalized: (u64, Root)) -> Stamp {
    Stamp {
        head_seq: seq,
        head_root: head.1,
        head_slot: head.0,
        finalized_root: finalized.1,
        finalized_slot: finalized.0,
    }
}

/// A deadline no test read comes near.
pub(crate) fn deadline() -> Deadline {
    Deadline::after(system_clock(), Duration::from_secs(600))
}
