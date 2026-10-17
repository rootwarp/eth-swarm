//! Fulu and Gloas consensus containers on the pinned sigp SSZ crates.
//!
//! - [`preset`]: [`EthSpec`] with the [`Minimal`] and [`Mainnet`] presets.
//! - [`common`], [`fulu`], [`gloas`]: the containers, transcribed from consensus-specs
//!   v1.7.0-beta.4. Fulu is codec-only (no state transition). The data-column containers are
//!   defined elsewhere.
//! - [`caps`] and [`codec`]: every untrusted decode is bounded by a per-type byte cap derived
//!   from the spec's `MAX_*` constants, checked before the SSZ decoder runs.
//! - [`forked`]: fork-dispatched enums; the fork comes from the object's slot.
//! - [`signing`]: `compute_domain`, `compute_signing_root` and signature-set descriptions.

mod macros;

pub mod caps;
pub mod codec;
pub mod common;
pub mod forked;
pub mod fulu;
pub mod gloas;
pub mod preset;
pub mod primitives;
pub mod signing;

pub use network_config::{ForkName, ForkSchedule};
pub use preset::{EthSpec, Mainnet, Minimal};
