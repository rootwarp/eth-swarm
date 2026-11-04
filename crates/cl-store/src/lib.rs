//! `cl-store`: serves `ethswarm.store.v1`, the read side of the store env cl-chain writes.
//!
//! - [`reader`]: the env opened read-only (`MDBX_RDONLY`). Every read is one read transaction
//!   that reads the stamp row with its data, under a per-call deadline; no stamp, no data.
//! - `ranges`: finalized block ranges ([`Reader::finalized_blocks`]), under the same rules.
//! - [`server`]: the `StoreService`: `GetBlock`, `GetBlocksByRange`, `GetChainHead` and the
//!   streamed parent walk `GetBlocksByHead`, behind the `ipc` contract layer and the method
//!   ACL ([`server::store_acl`]: cl-api, cl-sync, cl-p2p). The other RPCs run the contract
//!   checks and answer `UNIMPLEMENTED`. `tests/contract.rs` runs the contract suite against it,
//!   in process and over a Unix socket.
//! - [`stamp`]: the client side every caller of cl-store uses: a response without its full
//!   `ReadMeta` stamp is refused.

mod ranges;
pub mod reader;
pub mod server;
pub mod stamp;
#[cfg(test)]
mod testkit;

pub use reader::{BlockRef, Deadline, ReadError, Reader};
pub use server::{store_acl, Callers, StoreServer};
