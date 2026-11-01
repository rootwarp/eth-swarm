//! A restart base: the dir CURRENT names (`anchor-<root>/` or `finalized-<root>/`), its
//! name and its files. The layout is in [`super::durable`].

use std::fmt;

/// An operator anchor checkpoint: `block_root:epoch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// The anchor block's root.
    pub root: [u8; 32],
    /// Its epoch.
    pub epoch: u64,
}

impl Checkpoint {
    /// The `anchor` file: `root (32) ‖ epoch (u64 BE)`.
    pub(super) fn encode(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.root);
        out[32..].copy_from_slice(&self.epoch.to_be_bytes());
        out
    }

    /// An `anchor` file's checkpoint; `None` for any other length.
    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; 40] = bytes.try_into().ok()?;
        Some(Self {
            root: bytes[..32].try_into().ok()?,
            epoch: u64::from_be_bytes(bytes[32..].try_into().ok()?),
        })
    }
}

/// Which kind of restart base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseKind {
    /// The operator's anchor (`anchor-<root>/`).
    Anchor,
    /// A finalized block and state (`finalized-<root>/`).
    Finalized,
}

/// The bytes of a base to write, stored as given.
#[derive(Clone, Copy, Debug)]
pub struct BaseFiles<'a> {
    /// The block's SSZ.
    pub block: &'a [u8],
    /// Its post-state's SSZ.
    pub state: &'a [u8],
    /// Its Gloas payload envelope's SSZ, if any.
    pub envelope: Option<&'a [u8]>,
}

/// The restart base CURRENT names.
#[derive(Clone, PartialEq, Eq)]
pub struct Base {
    /// Anchor or finalized.
    pub kind: BaseKind,
    /// The block root its dir is named by.
    pub root: [u8; 32],
    /// The operator anchor, carried from the anchor dir.
    pub anchor: Checkpoint,
    /// The block's SSZ.
    pub block: Vec<u8>,
    /// Its post-state's SSZ.
    pub state: Vec<u8>,
    /// Its payload envelope's SSZ, if one was written.
    pub envelope: Option<Vec<u8>>,
}

impl fmt::Debug for Base {
    /// Lengths, not the bytes: a state is hundreds of megabytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Base")
            .field("kind", &self.kind)
            .field("root", &hex::encode(self.root))
            .field("anchor", &self.anchor)
            .field("block_len", &self.block.len())
            .field("state_len", &self.state.len())
            .field("envelope_len", &self.envelope.as_ref().map(Vec::len))
            .finish()
    }
}

/// A base dir's name, always formatted from the root's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BaseName {
    pub(super) kind: BaseKind,
    pub(super) root: [u8; 32],
}

impl BaseName {
    /// The name of `base`'s dir.
    pub(super) fn of(base: &Base) -> Self {
        Self {
            kind: base.kind,
            root: base.root,
        }
    }

    /// The name `text` is, if formatting it back gives exactly `text`.
    pub(super) fn parse(text: &str) -> Option<Self> {
        let (kind, hex) = text.split_once('-')?;
        let kind = match kind {
            "anchor" => BaseKind::Anchor,
            "finalized" => BaseKind::Finalized,
            _ => return None,
        };
        let mut root = [0u8; 32];
        hex::decode_to_slice(hex, &mut root).ok()?;
        let name = Self { kind, root };
        (name.to_string() == text).then_some(name)
    }
}

impl fmt::Display for BaseName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            BaseKind::Anchor => "anchor",
            BaseKind::Finalized => "finalized",
        };
        write!(f, "{kind}-{}", hex::encode(self.root))
    }
}
