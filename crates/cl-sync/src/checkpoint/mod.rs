//! Checkpoint sync anchor.
//!
//! [`fetch`] takes one finalized block root that two beacon API providers run by different
//! operators agree on, then downloads the block and the post-block state by root and refuses
//! the anchor unless every root checks out (`gloas/fork-choice.md`, anchor rule:
//! `anchor_block.state_root == hash_tree_root(anchor_state)`).
//!
//! - [`cli`]: the `anchor-fetch` command line, fetch and `--check`.
//! - [`config`]: `anchor-fetch.toml`, two providers as `{name, operator, url}`.
//! - [`http`]: the hyper 1 + rustls client and the byte-capped quarantine download.
//! - [`outdir`]: the output directory and its quarantine, checked and held by descriptor.
//! - [`runlog`]: the JSON-lines run log and its verifier.
//! - [`fetch`]: resolve, fetch, check, and write `anchor.json` (or, as [`fetch::check`], write
//!   nothing).

pub mod cli;
pub mod config;
pub mod fetch;
pub mod http;
pub mod outdir;
pub mod runlog;

#[cfg(test)]
mod testkit;

mod api;
