//! `manifest.toml`: what a segment holds and the sha256 of every file in it.
//!
//! The first line is `archive_sha256 = "<hex>"`, the sha256 of every byte after that line (the
//! body). The body is TOML: the capture fields, then one `[[files]]` table per file, sorted by
//! path. Every file's sha256 is in the body, so the archive digest covers every payload, and a
//! changed byte anywhere in the manifest fails either the header, the digest or the parse.
//!
//! ```toml
//! archive_sha256 = "…"
//! format_version = 1
//! network = "hoodi"
//! preset = "mainnet"
//! slot_start = 4235264
//! slot_end = 4235295
//! fork_digests = ["0x…"]
//! topics = ["beacon_block", "data_column_sidecar_3"]
//! peer_count = 48
//! capture_host = "hoodi-ref-1"
//! clock_source = "chrony"
//! closed_by = "roll"
//! total_bytes = 123456
//!
//! [[files]]
//! path = "beacon_block/4235264_0x….ssz_snappy"
//! topic = "beacon_block"
//! slot = 4235264
//! root = "0x…"
//! fork_digest = "0x…"
//! len = 81234
//! sha256 = "…"
//! ```

use super::names::{file_path, validate_network, validate_topic, NameError, TopicKind};
use consensus_types::caps::MAX_PAYLOAD_SIZE;
use consensus_types::primitives::{Root, Slot};
use p2p_wire::rpc::codec::max_compressed_len;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// The manifest's file name in a segment.
pub const MANIFEST_FILE: &str = "manifest.toml";
/// The manifest format this crate writes and reads.
pub const FORMAT_VERSION: u32 = 1;
/// The presets a manifest may name.
pub const PRESETS: [&str; 2] = ["mainnet", "minimal"];
/// The largest manifest: the reader refuses a larger one, and the writer rolls a segment
/// before its manifest would pass it. Far above the ~250 bytes per file of a real segment.
pub const MAX_MANIFEST_LEN: u64 = 64 << 20;
/// The longest `error` a manifest records; the writer cuts a longer one at a char boundary.
pub const MAX_ERROR_LEN: usize = 1024;
const HEADER_KEY: &str = "archive_sha256 = \"";
/// The header line: the key, 64 hex digits, the closing quote and the newline.
const HEADER_LINE_LEN: u64 = (HEADER_KEY.len() + 64 + 2) as u64;
/// What a file adds besides its own keys: the blank line and `[[files]]` before its table, and
/// at most one more `"0x<8 hex>", ` in `fork_digests`.
const FILE_TABLE_OVERHEAD: u64 = ("\n[[files]]\n".len() + "\"0x00000000\", ".len()) as u64;

/// A sha256 digest.
pub type Sha256Digest = [u8; 32];
/// A 4-byte fork digest.
pub type ForkDigest = [u8; 4];

/// Why a segment was sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClosedBy {
    /// The capture moved past the segment's slot window (`slot_end` is the window's end), or
    /// the manifest reached its size limit (`slot_end` is the last slot stored).
    Roll,
    /// The capture closed.
    Close,
    /// The capture stopped on an error (`error` says which); later payloads are not in it.
    Error,
}

/// One archived payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFile {
    /// `<topic>/<slot>_0x<root>.ssz_snappy`, relative to the segment.
    pub path: String,
    /// The gossip topic name, without fork digest and encoding.
    pub topic: String,
    /// The object's slot.
    pub slot: Slot,
    /// The block root: of the block, or of the sidecar's block.
    pub root: Root,
    /// The fork digest of the topic it arrived on.
    pub fork_digest: ForkDigest,
    /// The file length: the snappy-compressed payload as received.
    pub len: u64,
    /// sha256 of the file.
    pub sha256: Sha256Digest,
}

/// A segment's manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The network name (the archive's parent directory).
    pub network: String,
    /// The preset the payloads were decoded with.
    pub preset: String,
    /// The first slot the segment covers.
    pub slot_start: Slot,
    /// The last slot the segment covers.
    pub slot_end: Slot,
    /// Every fork digest the files arrived on, sorted.
    pub fork_digests: Vec<ForkDigest>,
    /// The topics the capture subscribed to, sorted; subnets are in the topic names.
    pub topics: Vec<String>,
    /// The capture's peer count when the segment was sealed.
    pub peer_count: u32,
    /// The host that captured.
    pub capture_host: String,
    /// The clock the capture host kept time with (e.g. `chrony`).
    pub clock_source: String,
    /// Why the segment was sealed.
    pub closed_by: ClosedBy,
    /// The error that stopped the capture, with [`ClosedBy::Error`].
    pub error: Option<String>,
    /// The sum of every file's length.
    pub total_bytes: u64,
    /// The files, sorted by path.
    pub files: Vec<ArchiveFile>,
}

/// A manifest that cannot be read or does not hold together.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// The first line is not `archive_sha256 = "<64 lowercase hex>"`.
    #[error("first line must be archive_sha256 = \"<64 lowercase hex>\"")]
    Header,
    /// The body does not hash to `archive_sha256`.
    #[error("archive sha256 mismatch: manifest says {recorded}, body hashes to {computed}")]
    DigestMismatch {
        /// The header's digest.
        recorded: String,
        /// The body's digest.
        computed: String,
    },
    /// The body is not the manifest TOML.
    #[error("toml: {0}")]
    Toml(String),
    /// A version this crate does not read.
    #[error("format_version {0}, expected {FORMAT_VERSION}")]
    Version(u32),
    /// A network or topic name that cannot be a path component.
    #[error(transparent)]
    Name(#[from] NameError),
    /// The fields contradict each other.
    #[error("{0}")]
    Invalid(String),
}

impl Manifest {
    /// Checks that the fields hold together: valid names, a known preset, `slot_start <=
    /// slot_end`, sorted unique topics the archive supports, at least one file, files sorted
    /// by path and unique, each at the path its topic, slot and root give, on a subscribed
    /// topic, inside the slot range and within the gossip size bound; `fork_digests` the
    /// sorted set of the files' digests, `total_bytes` their sum, and `error` set exactly when
    /// `closed_by` is `error`.
    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_network(&self.network)?;
        if !PRESETS.contains(&self.preset.as_str()) {
            return invalid(format!("unknown preset {:?}", self.preset));
        }
        if self.slot_start > self.slot_end {
            return invalid(format!(
                "slot_start {} is after slot_end {}",
                self.slot_start, self.slot_end
            ));
        }
        if self.capture_host.is_empty() || self.clock_source.is_empty() {
            return invalid("capture_host and clock_source must not be empty".into());
        }
        if (self.closed_by == ClosedBy::Error) != self.error.is_some() {
            return invalid("error is set exactly when closed_by is \"error\"".into());
        }
        for topic in &self.topics {
            validate_topic(topic)?;
            TopicKind::of(topic)?;
        }
        if !strictly_sorted(&self.topics) {
            return invalid("topics must be sorted and unique".into());
        }
        if self.files.is_empty() {
            return invalid("a segment holds at least one file".into());
        }
        if !strictly_sorted(self.files.iter().map(|f| &f.path)) {
            return invalid("files must be sorted by path and unique".into());
        }
        let max_len = max_compressed_len(MAX_PAYLOAD_SIZE) as u64;
        let mut digests = BTreeSet::new();
        let mut total: u64 = 0;
        for f in &self.files {
            if self.topics.binary_search(&f.topic).is_err() {
                return invalid(format!("{}: topic {:?} is not subscribed", f.path, f.topic));
            }
            if f.path != file_path(&f.topic, f.slot, &f.root) {
                return invalid(format!(
                    "{}: path does not match topic, slot and root",
                    f.path
                ));
            }
            if !(self.slot_start..=self.slot_end).contains(&f.slot) {
                return invalid(format!("{}: slot outside the segment", f.path));
            }
            if f.len > max_len {
                return invalid(format!("{}: {} bytes, over {max_len}", f.path, f.len));
            }
            digests.insert(f.fork_digest);
            total = total.saturating_add(f.len);
        }
        if self.fork_digests != digests.into_iter().collect::<Vec<_>>() {
            return invalid("fork_digests must be the sorted digests of the files".into());
        }
        if self.total_bytes != total {
            return invalid(format!(
                "total_bytes {} but the files hold {total}",
                self.total_bytes
            ));
        }
        Ok(())
    }

    /// The manifest bytes and the archive sha256 (the digest of the body), after
    /// [validating](Manifest::validate).
    pub fn render(&self) -> Result<(Vec<u8>, Sha256Digest), ManifestError> {
        self.validate()?;
        let body = toml::to_string(&RawManifest::from(self))
            .map_err(|e| ManifestError::Toml(e.to_string()))?;
        let digest: Sha256Digest = Sha256::digest(body.as_bytes()).into();
        let mut out = format!("{HEADER_KEY}{}\"\n", hex::encode(digest)).into_bytes();
        out.extend_from_slice(body.as_bytes());
        Ok((out, digest))
    }

    /// Parses manifest bytes, checking the header digest first and then every field
    /// ([`Manifest::validate`]). Returns the manifest and its archive sha256.
    pub fn parse(bytes: &[u8]) -> Result<(Self, Sha256Digest), ManifestError> {
        let newline = bytes.iter().position(|&b| b == b'\n');
        let (header, body) = newline
            .map(|at| (&bytes[..at], &bytes[at + 1..]))
            .ok_or(ManifestError::Header)?;
        let recorded = std::str::from_utf8(header)
            .ok()
            .and_then(|h| h.strip_prefix(HEADER_KEY)?.strip_suffix('"'))
            .and_then(canonical_hex::<32>)
            .ok_or(ManifestError::Header)?;
        let computed: Sha256Digest = Sha256::digest(body).into();
        if computed != recorded {
            return Err(ManifestError::DigestMismatch {
                recorded: hex::encode(recorded),
                computed: hex::encode(computed),
            });
        }
        let body = std::str::from_utf8(body).map_err(|e| ManifestError::Toml(e.to_string()))?;
        let raw: RawManifest =
            toml::from_str(body).map_err(|e| ManifestError::Toml(e.to_string()))?;
        let manifest = Manifest::try_from(raw)?;
        manifest.validate()?;
        Ok((manifest, computed))
    }
}

/// `error` cut to at most [`MAX_ERROR_LEN`] bytes, at a char boundary.
pub(crate) fn truncate_error(error: &str) -> String {
    let mut end = error.len().min(MAX_ERROR_LEN);
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error[..end].to_owned()
}

/// An upper bound on the length of a manifest with these capture fields and no files: the
/// header line and the body with every other field at its longest (the largest slots, peer
/// count and total, the longer `closed_by`, an error of [`MAX_ERROR_LEN`] bytes that each
/// escape to six). Add [`file_len_bound`] per file.
pub(crate) fn base_len_bound(
    network: &str,
    topics: &[String],
    capture_host: &str,
    clock_source: &str,
) -> u64 {
    let largest = i64::MAX as u64;
    let raw = RawManifest {
        format_version: FORMAT_VERSION,
        network: network.to_owned(),
        preset: PRESETS
            .iter()
            .max_by_key(|p| p.len())
            .copied()
            .unwrap_or_default()
            .to_owned(),
        slot_start: largest,
        slot_end: largest,
        fork_digests: Vec::new(),
        topics: topics.to_vec(),
        peer_count: u32::MAX,
        capture_host: capture_host.to_owned(),
        clock_source: clock_source.to_owned(),
        closed_by: ClosedBy::Error,
        error: Some("\u{7}".repeat(MAX_ERROR_LEN)),
        total_bytes: largest,
        files: Vec::new(),
    };
    toml::to_string(&raw).map_or(u64::MAX, |body| HEADER_LINE_LEN + body.len() as u64)
}

/// An upper bound on what `file` adds to a manifest: its `[[files]]` table and its digest.
pub(crate) fn file_len_bound(file: &ArchiveFile) -> u64 {
    toml::to_string(&RawFile::from(file))
        .map_or(u64::MAX, |table| table.len() as u64 + FILE_TABLE_OVERHEAD)
}

fn invalid<T>(message: String) -> Result<T, ManifestError> {
    Err(ManifestError::Invalid(message))
}

fn strictly_sorted<'a, T: Ord + 'a>(items: impl IntoIterator<Item = &'a T>) -> bool {
    let mut it = items.into_iter().peekable();
    while let Some(a) = it.next() {
        if it.peek().is_some_and(|b| a >= *b) {
            return false;
        }
    }
    true
}

/// `N` bytes from exactly `2 * N` lowercase hex digits.
fn canonical_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let lower = text
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let mut out = [0u8; N];
    (lower && hex::decode_to_slice(text, &mut out).is_ok()).then_some(out)
}

/// `0x` and `2 * N` lowercase hex digits, as the Beacon API writes roots.
fn prefixed_hex<const N: usize>(field: &str, text: &str) -> Result<[u8; N], ManifestError> {
    text.strip_prefix("0x")
        .and_then(canonical_hex::<N>)
        .ok_or_else(|| {
            ManifestError::Invalid(format!(
                "{field} {text:?} is not 0x and {} lowercase hex digits",
                2 * N
            ))
        })
}

fn plain_hex<const N: usize>(field: &str, text: &str) -> Result<[u8; N], ManifestError> {
    canonical_hex::<N>(text).ok_or_else(|| {
        ManifestError::Invalid(format!(
            "{field} {text:?} is not {} lowercase hex digits",
            2 * N
        ))
    })
}

/// The TOML shape of [`Manifest`]: digests and roots as hex strings.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    format_version: u32,
    network: String,
    preset: String,
    slot_start: u64,
    slot_end: u64,
    fork_digests: Vec<String>,
    topics: Vec<String>,
    peer_count: u32,
    capture_host: String,
    clock_source: String,
    closed_by: ClosedBy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    total_bytes: u64,
    files: Vec<RawFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    path: String,
    topic: String,
    slot: u64,
    root: String,
    fork_digest: String,
    len: u64,
    sha256: String,
}

impl From<&Manifest> for RawManifest {
    fn from(m: &Manifest) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            network: m.network.clone(),
            preset: m.preset.clone(),
            slot_start: m.slot_start,
            slot_end: m.slot_end,
            fork_digests: m
                .fork_digests
                .iter()
                .map(|d| format!("0x{}", hex::encode(d)))
                .collect(),
            topics: m.topics.clone(),
            peer_count: m.peer_count,
            capture_host: m.capture_host.clone(),
            clock_source: m.clock_source.clone(),
            closed_by: m.closed_by,
            error: m.error.clone(),
            total_bytes: m.total_bytes,
            files: m.files.iter().map(RawFile::from).collect(),
        }
    }
}

impl From<&ArchiveFile> for RawFile {
    fn from(f: &ArchiveFile) -> Self {
        Self {
            path: f.path.clone(),
            topic: f.topic.clone(),
            slot: f.slot,
            root: format!("0x{}", hex::encode(f.root)),
            fork_digest: format!("0x{}", hex::encode(f.fork_digest)),
            len: f.len,
            sha256: hex::encode(f.sha256),
        }
    }
}

impl TryFrom<RawManifest> for Manifest {
    type Error = ManifestError;

    fn try_from(raw: RawManifest) -> Result<Self, ManifestError> {
        if raw.format_version != FORMAT_VERSION {
            return Err(ManifestError::Version(raw.format_version));
        }
        let fork_digests = raw
            .fork_digests
            .iter()
            .map(|d| prefixed_hex::<4>("fork digest", d))
            .collect::<Result<_, _>>()?;
        let files = raw
            .files
            .into_iter()
            .map(|f| {
                Ok(ArchiveFile {
                    root: Root::from(prefixed_hex::<32>("root", &f.root)?),
                    fork_digest: prefixed_hex::<4>("fork_digest", &f.fork_digest)?,
                    sha256: plain_hex::<32>("sha256", &f.sha256)?,
                    path: f.path,
                    topic: f.topic,
                    slot: f.slot,
                    len: f.len,
                })
            })
            .collect::<Result<_, ManifestError>>()?;
        Ok(Self {
            network: raw.network,
            preset: raw.preset,
            slot_start: raw.slot_start,
            slot_end: raw.slot_end,
            fork_digests,
            topics: raw.topics,
            peer_count: raw.peer_count,
            capture_host: raw.capture_host,
            clock_source: raw.clock_source,
            closed_by: raw.closed_by,
            error: raw.error,
            total_bytes: raw.total_bytes,
            files,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use consensus_types::primitives::B256;

    pub(crate) fn file(topic: &str, slot: Slot, root: u8, digest: ForkDigest) -> ArchiveFile {
        let root = B256::repeat_byte(root);
        ArchiveFile {
            path: file_path(topic, slot, &root),
            topic: topic.into(),
            slot,
            root,
            fork_digest: digest,
            len: 100 + slot,
            sha256: [slot as u8; 32],
        }
    }

    pub(crate) fn manifest() -> Manifest {
        let files = vec![
            file("beacon_block", 10, 1, [1, 2, 3, 4]),
            file("beacon_block", 11, 2, [1, 2, 3, 5]),
            file("data_column_sidecar_3", 10, 1, [1, 2, 3, 4]),
        ];
        Manifest {
            network: "hoodi".into(),
            preset: "mainnet".into(),
            slot_start: 8,
            slot_end: 15,
            fork_digests: vec![[1, 2, 3, 4], [1, 2, 3, 5]],
            topics: vec!["beacon_block".into(), "data_column_sidecar_3".into()],
            peer_count: 48,
            capture_host: "hoodi-ref-1".into(),
            clock_source: "chrony".into(),
            closed_by: ClosedBy::Roll,
            error: None,
            total_bytes: files.iter().map(|f| f.len).sum(),
            files,
        }
    }

    fn with_digest(body: &str) -> Vec<u8> {
        let digest = hex::encode(Sha256::digest(body.as_bytes()));
        format!("archive_sha256 = \"{digest}\"\n{body}").into_bytes()
    }

    fn body(m: &Manifest) -> String {
        let (bytes, _) = m.render().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        text.split_once('\n').unwrap().1.to_owned()
    }

    fn invalid(m: Manifest) -> ManifestError {
        let err = m.validate().unwrap_err();
        assert_eq!(m.render().unwrap_err(), err, "render validates");
        err
    }

    #[test]
    fn render_parse_round_trip() {
        let m = manifest();
        let (bytes, digest) = m.render().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let (header, body) = text.split_once('\n').unwrap();
        assert_eq!(
            header,
            format!("archive_sha256 = \"{}\"", hex::encode(digest))
        );
        assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(body.as_bytes())));
        for field in [
            "network = \"hoodi\"",
            "peer_count = 48",
            "clock_source = \"chrony\"",
        ] {
            assert!(body.contains(field), "{field} in\n{body}");
        }
        assert_eq!(Manifest::parse(&bytes).unwrap(), (m, digest));
    }

    fn bound(m: &Manifest) -> u64 {
        base_len_bound(&m.network, &m.topics, &m.capture_host, &m.clock_source)
            + m.files.iter().map(file_len_bound).sum::<u64>()
    }

    #[test]
    fn the_length_bound_holds_at_the_extremes() {
        let mut m = manifest();
        assert!(m.render().unwrap().0.len() as u64 <= bound(&m));

        // Every field at its longest: a full error of control characters (each escaped to six
        // bytes), the largest slots, peer count and total, a digest per file.
        m.closed_by = ClosedBy::Error;
        m.error = Some(truncate_error(&"\u{7}".repeat(MAX_ERROR_LEN + 10)));
        m.peer_count = u32::MAX;
        m.capture_host = "\"".repeat(40);
        let top = i64::MAX as u64;
        m.files = (0..20u8)
            .map(|i| {
                let mut f = file("data_column_sidecar_127", top - u64::from(i), i, [i; 4]);
                f.len = max_compressed_len(MAX_PAYLOAD_SIZE) as u64;
                f
            })
            .collect();
        m.files.sort_by(|a, b| a.path.cmp(&b.path));
        m.topics = vec!["data_column_sidecar_127".into()];
        m.fork_digests = (0..20u8).map(|i| [i; 4]).collect();
        m.slot_start = top - 19;
        m.slot_end = top;
        m.total_bytes = m.files.iter().map(|f| f.len).sum();
        let rendered = m.render().unwrap().0.len() as u64;
        assert!(rendered <= bound(&m), "{rendered} > {}", bound(&m));
        assert!(bound(&m) - rendered < 1024, "the bound stays close");
    }

    #[test]
    fn a_long_error_is_cut_at_a_char_boundary() {
        assert_eq!(truncate_error("short"), "short");
        let long = "é".repeat(MAX_ERROR_LEN);
        let cut = truncate_error(&long);
        assert!(cut.len() <= MAX_ERROR_LEN && cut.len() > MAX_ERROR_LEN - 2);
        assert!(long.starts_with(&cut));
    }

    #[test]
    fn every_flipped_byte_is_refused() {
        let (bytes, _) = manifest().render().unwrap();
        for at in 0..bytes.len() {
            for bit in [0x01, 0x20, 0x80] {
                let mut flipped = bytes.clone();
                flipped[at] ^= bit;
                assert!(
                    Manifest::parse(&flipped).is_err(),
                    "byte {at} ^ {bit:#x} accepted"
                );
            }
        }
        assert!(
            Manifest::parse(&bytes[..bytes.len() - 1]).is_err(),
            "truncated"
        );
        let mut appended = bytes.clone();
        appended.extend_from_slice(b"\n");
        assert!(Manifest::parse(&appended).is_err(), "appended");
    }

    #[test]
    fn header_and_digest() {
        assert_eq!(Manifest::parse(b""), Err(ManifestError::Header));
        assert_eq!(
            Manifest::parse(b"network = \"x\"\n"),
            Err(ManifestError::Header)
        );
        let upper = format!("archive_sha256 = \"{}\"\n", "AB".repeat(32));
        assert_eq!(
            Manifest::parse(upper.as_bytes()),
            Err(ManifestError::Header)
        );
        let (mut bytes, _) = manifest().render().unwrap();
        bytes[HEADER_KEY.len()] = if bytes[HEADER_KEY.len()] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert!(matches!(
            Manifest::parse(&bytes),
            Err(ManifestError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn a_rehashed_body_must_still_parse_and_hold_together() {
        let good = body(&manifest());
        let unknown = format!("extra = 1\n{good}");
        assert!(matches!(
            Manifest::parse(&with_digest(&unknown)),
            Err(ManifestError::Toml(_))
        ));
        let v2 = good.replace("format_version = 1", "format_version = 2");
        assert_eq!(
            Manifest::parse(&with_digest(&v2)),
            Err(ManifestError::Version(2))
        );
        let upper_root = good.replacen("0x0101", "0xABAB", 1);
        assert!(matches!(
            Manifest::parse(&with_digest(&upper_root)),
            Err(ManifestError::Invalid(_))
        ));
        let short_digest = good.replacen("\"0x01020304\"", "\"0x010203\"", 1);
        assert!(matches!(
            Manifest::parse(&with_digest(&short_digest)),
            Err(ManifestError::Invalid(_))
        ));
        let negative = good.replace("slot_start = 8", "slot_start = -8");
        assert!(matches!(
            Manifest::parse(&with_digest(&negative)),
            Err(ManifestError::Toml(_))
        ));
        let not_utf8 = [b"archive_sha256 = \"".as_slice(), &[0xff; 3]].concat();
        assert_eq!(Manifest::parse(&not_utf8), Err(ManifestError::Header));
    }

    #[test]
    fn contradictions_are_refused() {
        let mut m = manifest();
        m.network = "../etc".into();
        assert!(matches!(invalid(m), ManifestError::Name(_)));

        let mut m = manifest();
        m.preset = "gnosis".into();
        assert!(matches!(invalid(m), ManifestError::Invalid(_)));

        let mut m = manifest();
        m.slot_start = 16;
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "start after end"
        );

        let mut m = manifest();
        m.slot_end = 10;
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "file past the end"
        );

        let mut m = manifest();
        m.topics.reverse();
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "unsorted topics"
        );

        let mut m = manifest();
        m.topics = vec!["beacon_block".into()];
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "unsubscribed file"
        );

        let mut m = manifest();
        m.topics.push("voluntary_exit".into());
        assert!(
            matches!(invalid(m), ManifestError::Name(_)),
            "unsupported topic"
        );

        let mut m = manifest();
        m.files.swap(0, 1);
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "unsorted files"
        );

        let mut m = manifest();
        m.files.push(m.files[0].clone());
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "duplicate file"
        );

        let mut m = manifest();
        m.files.clear();
        m.total_bytes = 0;
        m.fork_digests.clear();
        assert!(matches!(invalid(m), ManifestError::Invalid(_)), "no files");

        let mut m = manifest();
        m.files[0].path = "beacon_block/../../x".into();
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "path not derived"
        );

        let mut m = manifest();
        m.files[0].len = max_compressed_len(MAX_PAYLOAD_SIZE) as u64 + 1;
        m.total_bytes = m.files.iter().map(|f| f.len).sum();
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "oversized file"
        );

        let mut m = manifest();
        m.total_bytes += 1;
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "total bytes"
        );

        let mut m = manifest();
        m.fork_digests.pop();
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "fork digests"
        );

        let mut m = manifest();
        m.closed_by = ClosedBy::Error;
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "error without reason"
        );

        let mut m = manifest();
        m.error = Some("disk full".into());
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "reason without error"
        );

        let mut m = manifest();
        m.capture_host.clear();
        assert!(matches!(invalid(m), ManifestError::Invalid(_)), "no host");

        let mut m = manifest();
        m.clock_source.clear();
        assert!(
            matches!(invalid(m), ManifestError::Invalid(_)),
            "no clock source"
        );

        let mut m = manifest();
        m.closed_by = ClosedBy::Error;
        m.error = Some("disk full".into());
        assert_eq!(m.validate(), Ok(()));
        let (bytes, _) = m.render().unwrap();
        assert_eq!(Manifest::parse(&bytes).unwrap().0, m);
    }
}
