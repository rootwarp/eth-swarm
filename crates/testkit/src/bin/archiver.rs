//! `archiver`: write captured gossip payloads into a verified block/column archive, and verify
//! one.
//!
//! ```text
//! archiver capture --network sepolia|hoodi --input DIR --out DIR --host HOST
//!                  --clock-source SOURCE --peer-count N [--topic TOPIC]...
//!                  [--slots-per-segment N] [--max-bytes N]
//!                  [--genesis-validators-root 0xROOT]
//! archiver verify SEGMENT_DIR
//! archiver --help
//! ```
//!
//! `capture` reads `DIR/<seq>_<fork_digest>_<topic>.ssz_snappy` files (decimal arrival
//! sequence, 8 hex digits of fork digest, gossip topic name; the bytes as gossip delivered
//! them) in sequence order and archives them with [`testkit::archive::Writer`] (mainnet preset)
//! under `OUT/<network>/`, printing each sealed segment. The topics default to those in the
//! input. Each payload's fork digest must be the network's for the object's slot
//! (`digest_schedule`, blob-parameter changes included), which takes the genesis validators
//! root: the pinned one, or `--genesis-validators-root` for a network without one (Hoodi). A
//! refused payload is reported and skipped; an error that stops the capture, including an input
//! file over the gossip size bound (never read past it), seals what was written, marked as
//! stopped. Each manifest records the digest schedule over its segment's slot range, so a
//! segment that spans a fork or BPO boundary (a late payload joins the open segment) names
//! both digests. `verify` runs [`testkit::archive::open_verified`] and prints the segment's
//! slot range, file count and archive sha256. It refuses a file whose fork digest is not the
//! one that the manifest's schedule gives for its slot.
//!
//! Exit codes: 0 done, 1 a payload refused, the capture stopped or the archive refused, 64
//! usage.

use consensus_types::caps::NetworkCaps;
use consensus_types::Mainnet;
use network_config::digest::digest_schedule;
use network_config::{ChainConfig, Network};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use testkit::archive::{
    max_compressed_payload_len, open_verified, Capture, CaptureConfig, ChainParams, ForkDigest,
    Writer,
};

const USAGE: &str = "\
usage: archiver capture --network sepolia|hoodi --input DIR --out DIR --host HOST
                        --clock-source SOURCE --peer-count N [--topic TOPIC]...
                        [--slots-per-segment N] [--max-bytes N]
                        [--genesis-validators-root 0xROOT]
       archiver verify SEGMENT_DIR
       archiver --help";
const HELP: &str = "\
Archive captured gossip payloads with a sha256 manifest, or verify an archive segment.

capture reads DIR/<seq>_<fork_digest>_<topic>.ssz_snappy (decimal arrival sequence, 8 hex
digits of fork digest, gossip topic name; snappy-compressed SSZ as gossip delivered it) in
sequence order and writes OUT/<network>/<slot_start>-<slot_end>/ segments, printing each one.

  --network NAME          sepolia or hoodi (the embedded config; mainnet preset)
  --input DIR             the captured payloads
  --out DIR               the archive root
  --host HOST             the capture host, for the manifest
  --clock-source SOURCE   the host's clock (e.g. chrony), for the manifest
  --peer-count N          the capture's peer count, for the manifest
  --topic TOPIC           a subscribed topic, repeatable (default: the input's topics)
  --slots-per-segment N   the segment window (default 32)
  --max-bytes N           the payload disk budget (default 10 GiB)
  --genesis-validators-root 0xROOT
                          the network's genesis validators root, for its fork digests:
                          required where none is pinned (hoodi), else must match the pinned one

A payload on a fork digest other than the network's for its slot is refused; an input file
over the gossip size bound stops the capture.

verify checks a segment's manifest digest and every file's length and sha256, and refuses
missing and extra files. It also checks each file's fork digest against the digest schedule
in the manifest (each digest with the epoch where it starts) for the file's slot.

Exit codes: 0 done, 1 a payload refused, the capture stopped or the archive refused, 64 usage.";

const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 64;
const DEFAULT_SLOTS_PER_SEGMENT: u64 = 32;
const DEFAULT_MAX_BYTES: u64 = 10 << 30;
const INPUT_SUFFIX: &str = ".ssz_snappy";

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Verify(PathBuf),
    Capture(CaptureArgs),
}

#[derive(Debug, PartialEq, Eq)]
struct CaptureArgs {
    network: Network,
    input: PathBuf,
    out: PathBuf,
    host: String,
    clock_source: String,
    peer_count: u32,
    topics: Vec<String>,
    slots_per_segment: u64,
    max_bytes: u64,
    genesis_validators_root: [u8; 32],
}

/// One captured payload file.
#[derive(Debug, PartialEq, Eq)]
struct InputFile {
    seq: u64,
    fork_digest: ForkDigest,
    topic: String,
    path: PathBuf,
}

fn parse(args: &[String]) -> Result<Command, String> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Command::Help);
    }
    match args.first().map(String::as_str) {
        Some("verify") => match &args[1..] {
            [dir] => Ok(Command::Verify(dir.into())),
            _ => Err("verify takes exactly one SEGMENT_DIR".into()),
        },
        Some("capture") => parse_capture(&args[1..]).map(Command::Capture),
        Some(other) => Err(format!("unknown command {other:?}")),
        None => Err("no command".into()),
    }
}

fn parse_capture(args: &[String]) -> Result<CaptureArgs, String> {
    let (mut network, mut input, mut out, mut host, mut clock_source, mut peer_count) =
        (None, None, None, None, None, None);
    let mut topics = Vec::new();
    let mut slots_per_segment = DEFAULT_SLOTS_PER_SEGMENT;
    let mut max_bytes = DEFAULT_MAX_BYTES;
    let mut genesis_validators_root = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))
            .map(String::as_str);
        match flag.as_str() {
            "--network" => {
                let name = value?;
                let found = Network::ALL.into_iter().find(|n| n.name() == name);
                network =
                    Some(found.ok_or_else(|| format!("--network: unknown network {name:?}"))?);
            }
            "--input" => input = Some(PathBuf::from(value?)),
            "--out" => out = Some(PathBuf::from(value?)),
            "--host" => host = Some(value?.to_owned()),
            "--clock-source" => clock_source = Some(value?.to_owned()),
            "--peer-count" => peer_count = Some(number(flag, value?)?),
            "--topic" => topics.push(value?.to_owned()),
            "--slots-per-segment" => slots_per_segment = number(flag, value?)?,
            "--max-bytes" => max_bytes = number(flag, value?)?,
            "--genesis-validators-root" => {
                genesis_validators_root = Some(root(flag, value?)?);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    fn required<T>(value: Option<T>, flag: &str) -> Result<T, String> {
        value.ok_or_else(|| format!("{flag} is required"))
    }
    let network = required(network, "--network")?;
    let pinned = network.genesis().map(|g| g.genesis_validators_root);
    let genesis_validators_root = match (pinned, genesis_validators_root) {
        (Some(pinned), Some(given)) if pinned != given => {
            return Err(format!(
                "--genesis-validators-root is not {network}'s pinned 0x{}",
                hex::encode(pinned)
            ))
        }
        (Some(root), _) | (None, Some(root)) => root,
        (None, None) => {
            return Err(format!(
                "--genesis-validators-root is required: {network} has no pinned genesis"
            ))
        }
    };
    Ok(CaptureArgs {
        network,
        input: required(input, "--input")?,
        out: required(out, "--out")?,
        host: required(host, "--host")?,
        clock_source: required(clock_source, "--clock-source")?,
        peer_count: required(peer_count, "--peer-count")?,
        topics,
        slots_per_segment,
        max_bytes,
        genesis_validators_root,
    })
}

/// `0x` and 64 lowercase hex digits.
fn root(flag: &str, value: &str) -> Result<[u8; 32], String> {
    let digits = value.strip_prefix("0x").unwrap_or_default();
    let lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    let mut root = [0u8; 32];
    if digits.len() != 64 || !digits.bytes().all(lower_hex) {
        return Err(format!(
            "{flag}: {value:?} is not 0x and 64 lowercase hex digits"
        ));
    }
    hex::decode_to_slice(digits, &mut root).map_err(|e| format!("{flag}: {e}"))?;
    Ok(root)
}

fn number<T: std::str::FromStr>(flag: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("{flag}: {value:?} is not a number"))
}

/// `<seq>_<fork_digest>_<topic>.ssz_snappy`.
fn parse_input_name(name: &str) -> Option<(u64, ForkDigest, String)> {
    let (seq, rest) = name.strip_suffix(INPUT_SUFFIX)?.split_once('_')?;
    let (digest, topic) = rest.split_once('_')?;
    let lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) || topic.is_empty() {
        return None;
    }
    if digest.len() != 8 || !digest.bytes().all(lower_hex) {
        return None;
    }
    let mut fork_digest = [0u8; 4];
    hex::decode_to_slice(digest, &mut fork_digest).ok()?;
    Some((seq.parse().ok()?, fork_digest, topic.to_owned()))
}

/// The input files, in sequence order; a name that does not parse or a repeated sequence
/// number refuses the whole input.
fn read_input(dir: &Path) -> Result<Vec<InputFile>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let parsed = parse_input_name(&name).filter(|_| entry.path().is_file());
        let Some((seq, fork_digest, topic)) = parsed else {
            return Err(format!(
                "{}: not a <seq>_<fork_digest>_<topic>{INPUT_SUFFIX} file",
                entry.path().display()
            ));
        };
        files.push(InputFile {
            seq,
            fork_digest,
            topic,
            path: entry.path(),
        });
    }
    files.sort_by_key(|f| f.seq);
    if let Some(pair) = files.windows(2).find(|w| w[0].seq == w[1].seq) {
        return Err(format!(
            "sequence {} appears twice: {} and {}",
            pair[0].seq,
            pair[0].path.display(),
            pair[1].path.display()
        ));
    }
    Ok(files)
}

/// The bytes of one input file, reading at most one byte past the gossip bound: a larger file
/// is refused without being read into memory.
fn read_payload(path: &Path) -> Result<Vec<u8>, String> {
    let max = max_compressed_payload_len();
    let mut payload = Vec::new();
    File::open(path)
        .and_then(|f| f.take(max as u64 + 1).read_to_end(&mut payload))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if payload.len() > max {
        return Err(format!(
            "{}: over the gossip bound of {max} compressed bytes",
            path.display()
        ));
    }
    Ok(payload)
}

fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let command = match parse(args) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "archiver: {e}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    match command {
        Command::Help => {
            let _ = writeln!(out, "{USAGE}\n\n{HELP}");
            0
        }
        Command::Verify(dir) => verify(&dir, out, err),
        Command::Capture(args) => capture(&args, out, err),
    }
}

fn verify(dir: &Path, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    match open_verified(dir) {
        Ok(archive) => {
            let m = archive.manifest();
            let _ = writeln!(
                out,
                "{}: ok, {} files, slots {}-{}, archive_sha256 {}",
                dir.display(),
                archive.files().len(),
                m.slot_start,
                m.slot_end,
                hex::encode(archive.archive_sha256())
            );
            0
        }
        Err(e) => {
            let _ = writeln!(err, "archiver: {}: refused: {e}", dir.display());
            EXIT_FAILED
        }
    }
}

fn capture(args: &CaptureArgs, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let mut fail = |message: String| {
        let _ = writeln!(err, "archiver: {message}");
    };
    let files = match read_input(&args.input) {
        Ok(files) => files,
        Err(e) => {
            fail(e);
            return EXIT_FAILED;
        }
    };
    let config = match ChainConfig::load(args.network) {
        Ok(config) => config,
        Err(e) => {
            fail(format!("{} config: {e}", args.network.name()));
            return EXIT_FAILED;
        }
    };
    let chain = ChainParams {
        schedule: *config.fork_schedule(),
        caps: NetworkCaps::from_config(&config),
    };
    let topics = if args.topics.is_empty() {
        files.iter().map(|f| f.topic.clone()).collect()
    } else {
        args.topics.clone()
    };
    let capture_config = CaptureConfig {
        network: args.network.name().to_owned(),
        topics,
        capture_host: args.host.clone(),
        clock_source: args.clock_source.clone(),
        slots_per_segment: args.slots_per_segment,
        max_bytes: args.max_bytes,
        fork_digests: digest_schedule(&config, &args.genesis_validators_root)
            .into_iter()
            .map(|d| (d.epoch, d.fork_digest))
            .collect(),
    };
    let mut writer = match Writer::<Mainnet>::create(&args.out, capture_config, chain) {
        Ok(w) => w,
        Err(e) => {
            fail(e.to_string());
            return EXIT_FAILED;
        }
    };
    writer.set_peer_count(args.peer_count);
    let mut failed = false;
    for file in &files {
        let payload = match read_payload(&file.path) {
            Ok(payload) => payload,
            Err(reason) => {
                fail(format!("capture stopped: {reason}"));
                writer.stop(reason);
                failed = true;
                break;
            }
        };
        let stored = writer.put(Capture {
            topic: &file.topic,
            fork_digest: file.fork_digest,
            payload: &payload,
        });
        if let Err(e) = stored {
            let stops = e.stops_capture();
            let what = if stops { "capture stopped" } else { "skipped" };
            fail(format!("{}: {what}: {e}", file.path.display()));
            failed = true;
            if stops {
                break;
            }
        }
    }
    let sealed_before_close = writer.sealed().to_vec();
    let (segments, closed) = match writer.close() {
        Ok(segments) => (segments, Ok(())),
        Err(e) => (sealed_before_close, Err(e)),
    };
    for segment in &segments {
        let _ = writeln!(out, "{}", segment.display());
    }
    if let Err(e) = closed {
        fail(format!("closing the capture: {e}"));
        return EXIT_FAILED;
    }
    if failed {
        EXIT_FAILED
    } else {
        0
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&args, &mut std::io::stdout(), &mut std::io::stderr()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::primitives::{Root, Slot};
    use consensus_types::{EthSpec, ForkName, ForkSchedule};
    use network_config::digest::compute_fork_digest;
    use sha2::{Digest, Sha256};
    use std::fs;
    use testkit::archive::{
        fixtures, ArchiveError, ArchiveFile, ClosedBy, DigestEntry, Fault, Manifest, ManifestError,
        MANIFEST_FILE, OPEN_PREFIX,
    };

    const FULU_DIGEST: &str = "7e0d3447";
    const GLOAS_DIGEST: &str = "669e6c11";
    const COLUMN: &str = "data_column_sidecar_5";

    /// The test digests are Sepolia's at the first Fulu and the first Gloas epoch.
    #[test]
    fn the_test_digests_are_sepolias() {
        let config = ChainConfig::load(Network::Sepolia).unwrap();
        let gvr = Network::Sepolia.genesis().unwrap().genesis_validators_root;
        let s = sepolia();
        let at = |fork| {
            let epoch = s.fork_epoch(fork).unwrap();
            hex::encode(compute_fork_digest(&config, &gvr, epoch).unwrap())
        };
        assert_eq!(
            (at(ForkName::Fulu), at(ForkName::Gloas)),
            (FULU_DIGEST.to_owned(), GLOAS_DIGEST.to_owned())
        );
    }

    fn sepolia_digests() -> Vec<(consensus_types::primitives::Epoch, ForkDigest)> {
        let config = ChainConfig::load(Network::Sepolia).unwrap();
        let gvr = Network::Sepolia.genesis().unwrap().genesis_validators_root;
        digest_schedule(&config, &gvr)
            .into_iter()
            .map(|d| (d.epoch, d.fork_digest))
            .collect()
    }

    fn sepolia() -> ForkSchedule {
        *ChainConfig::load(Network::Sepolia).unwrap().fork_schedule()
    }

    /// The first slot of Fulu and of Gloas on Sepolia.
    fn fork_slots() -> (Slot, Slot) {
        let s = sepolia();
        let first = |fork| Mainnet::start_slot_at_epoch(s.fork_epoch(fork).unwrap());
        (
            first(consensus_types::ForkName::Fulu),
            first(consensus_types::ForkName::Gloas),
        )
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn run_args(list: &[&str]) -> (u8, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(&args(list), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    /// One expected archive file: what the capture got and what it must be filed as.
    #[derive(Debug, Clone)]
    struct Expected {
        topic: &'static str,
        slot: Slot,
        root: Root,
        digest: &'static str,
        payload: Vec<u8>,
    }

    /// A Fulu block and column, then two Gloas blocks and a Gloas column, written as capture
    /// input in arrival order.
    fn captured(input: &Path) -> Vec<Expected> {
        let (fulu, gloas) = fork_slots();
        let s = sepolia();
        let (fb, fb_root) = fixtures::block_on::<Mainnet>(&s, fulu, 1);
        let (fc, fc_root) = fixtures::column_on::<Mainnet>(&s, fulu, 1, 5);
        let (gb, gb_root) = fixtures::block_on::<Mainnet>(&s, gloas, 2);
        let (gb2, gb2_root) = fixtures::block_on::<Mainnet>(&s, gloas + 1, 3);
        let (gc, gc_root) = fixtures::column_on::<Mainnet>(&s, gloas, 2, 5);
        assert_eq!(
            (fc_root, gc_root),
            (fb_root, gb_root),
            "columns of those blocks"
        );
        let expected = vec![
            Expected {
                topic: "beacon_block",
                slot: fulu,
                root: fb_root,
                digest: FULU_DIGEST,
                payload: fb,
            },
            Expected {
                topic: COLUMN,
                slot: fulu,
                root: fc_root,
                digest: FULU_DIGEST,
                payload: fc,
            },
            Expected {
                topic: "beacon_block",
                slot: gloas,
                root: gb_root,
                digest: GLOAS_DIGEST,
                payload: gb,
            },
            Expected {
                topic: COLUMN,
                slot: gloas,
                root: gc_root,
                digest: GLOAS_DIGEST,
                payload: gc,
            },
            Expected {
                topic: "beacon_block",
                slot: gloas + 1,
                root: gb2_root,
                digest: GLOAS_DIGEST,
                payload: gb2,
            },
        ];
        fs::create_dir_all(input).unwrap();
        for (seq, e) in expected.iter().enumerate() {
            let name = format!("{seq}_{}_{}{INPUT_SUFFIX}", e.digest, e.topic);
            fs::write(input.join(name), &e.payload).unwrap();
        }
        expected
    }

    fn capture_args<'a>(input: &'a str, out: &'a str) -> Vec<&'a str> {
        vec![
            "capture",
            "--network",
            "sepolia",
            "--input",
            input,
            "--out",
            out,
            "--host",
            "sepolia-ref-1",
            "--clock-source",
            "chrony",
            "--peer-count",
            "42",
        ]
    }

    /// Runs `archiver capture` on [`captured`] input; returns the sealed segments.
    fn capture_into(root: &Path) -> (Vec<PathBuf>, Vec<Expected>) {
        let input = root.join("input");
        let out = root.join("archive");
        let expected = captured(&input);
        let (code, stdout, stderr) = run_args(&capture_args(
            input.to_str().unwrap(),
            out.to_str().unwrap(),
        ));
        assert_eq!(code, 0, "{stderr}");
        (stdout.lines().map(PathBuf::from).collect(), expected)
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn digest(hex: &str) -> ForkDigest {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn file_of(e: &Expected) -> ArchiveFile {
        ArchiveFile {
            path: format!(
                "{}/{}_0x{}.ssz_snappy",
                e.topic,
                e.slot,
                hex::encode(e.root)
            ),
            topic: e.topic.into(),
            slot: e.slot,
            root: e.root,
            fork_digest: digest(e.digest),
            len: e.payload.len() as u64,
            sha256: sha256(&e.payload),
        }
    }

    fn sorted(mut files: Vec<ArchiveFile>) -> Vec<ArchiveFile> {
        files.sort_by(|a, b| a.path.cmp(&b.path));
        files
    }

    /// Write, then `open_verified` returns the same files, roots and fields.
    #[test]
    fn manifest_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let (segments, expected) = capture_into(tmp.path());
        let (fulu, gloas) = fork_slots();
        let net = tmp.path().join("archive/sepolia");
        assert_eq!(
            segments,
            [
                net.join(format!("{fulu}-{}", fulu + 31)),
                net.join(format!("{gloas}-{}", gloas + 1))
            ]
        );

        let archives: Vec<_> = segments.iter().map(|s| open_verified(s).unwrap()).collect();
        let topics = ["beacon_block".to_string(), COLUMN.to_string()];
        let want = [
            (fulu, fulu + 31, ClosedBy::Roll, FULU_DIGEST, &expected[..2]),
            (
                gloas,
                gloas + 1,
                ClosedBy::Close,
                GLOAS_DIGEST,
                &expected[2..],
            ),
        ];
        for (archive, (start, end, closed_by, fork_digest, files)) in archives.iter().zip(want) {
            let m = archive.manifest();
            assert_eq!(m.network, "sepolia");
            assert_eq!(m.preset, "mainnet");
            assert_eq!((m.slot_start, m.slot_end), (start, end));
            assert_eq!(m.fork_digests, [digest(fork_digest)]);
            assert_eq!(m.topics, topics);
            assert_eq!(m.peer_count, 42);
            assert_eq!(m.capture_host, "sepolia-ref-1");
            assert_eq!(m.clock_source, "chrony");
            assert_eq!((m.closed_by, m.error.as_deref()), (closed_by, None));
            assert_eq!(archive.files(), sorted(files.iter().map(file_of).collect()));
            for e in files {
                let file = file_of(e);
                assert_eq!(archive.read(&file).unwrap(), e.payload);
            }
            // The archive digest is the manifest body's, and pins every file's sha256.
            let bytes = fs::read(archive.dir().join(MANIFEST_FILE)).unwrap();
            assert_eq!(
                Manifest::parse(&bytes).unwrap(),
                (m.clone(), archive.archive_sha256())
            );
        }
    }

    /// One flipped byte, a deleted file or an extra file each make `open_verified` fail.
    #[test]
    fn tampered_or_missing_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (segments, expected) = capture_into(tmp.path());
        let segment = &segments[1];
        let victim = segment.join(file_of(&expected[2]).path);
        let original = fs::read(&victim).unwrap();

        // Every single flipped byte of a payload.
        for at in 0..original.len() {
            let mut flipped = original.clone();
            flipped[at] ^= 0x01;
            fs::write(&victim, &flipped).unwrap();
            let e = open_verified(segment).unwrap_err();
            assert!(
                matches!(e, ArchiveError::Sha256Mismatch { .. }),
                "byte {at}: {e}"
            );
        }
        fs::write(&victim, &original).unwrap();
        open_verified(segment).unwrap();

        // A flipped manifest byte.
        let manifest = segment.join(MANIFEST_FILE);
        let good = fs::read(&manifest).unwrap();
        let mut flipped = good.clone();
        *flipped.last_mut().unwrap() ^= 0x01;
        fs::write(&manifest, &flipped).unwrap();
        assert!(matches!(
            open_verified(segment).unwrap_err(),
            ArchiveError::Manifest {
                source: ManifestError::DigestMismatch { .. },
                ..
            }
        ));
        fs::write(&manifest, &good).unwrap();

        // A truncated or extended payload.
        fs::write(&victim, &original[..original.len() - 1]).unwrap();
        assert!(matches!(
            open_verified(segment).unwrap_err(),
            ArchiveError::LengthMismatch { .. }
        ));
        fs::write(&victim, [original.as_slice(), &[0]].concat()).unwrap();
        assert!(matches!(
            open_verified(segment).unwrap_err(),
            ArchiveError::LengthMismatch { .. }
        ));

        // A deleted file, and a deleted topic directory.
        fs::remove_file(&victim).unwrap();
        let e = open_verified(segment).unwrap_err();
        assert!(
            matches!(&e, ArchiveError::MissingFile(p) if victim.ends_with(p)),
            "{e}"
        );
        fs::write(&victim, &original).unwrap();
        let column_dir = segment.join(COLUMN);
        let moved = tmp.path().join("moved");
        fs::rename(&column_dir, &moved).unwrap();
        assert!(matches!(
            open_verified(segment).unwrap_err(),
            ArchiveError::MissingFile(_)
        ));
        fs::rename(&moved, &column_dir).unwrap();

        // An extra file: a payload the manifest does not list, next to the listed ones.
        let s = sepolia();
        let (extra, extra_root) = fixtures::block_on::<Mainnet>(&s, fork_slots().1 + 1, 99);
        let extra_path = segment.join(format!(
            "beacon_block/{}_0x{}.ssz_snappy",
            fork_slots().1 + 1,
            hex::encode(extra_root)
        ));
        fs::write(&extra_path, &extra).unwrap();
        assert!(matches!(
            open_verified(segment).unwrap_err(),
            ArchiveError::ExtraFile(_)
        ));
        fs::remove_file(&extra_path).unwrap();

        // The CLI refuses the same way.
        fs::write(&victim, b"tampered").unwrap();
        let (code, _, stderr) = run_args(&["verify", segment.to_str().unwrap()]);
        assert_eq!(code, EXIT_FAILED);
        assert!(stderr.contains("bytes, manifest says"), "{stderr}");
        fs::write(&victim, &original).unwrap();
        let (code, stdout, _) = run_args(&["verify", segment.to_str().unwrap()]);
        assert_eq!(code, 0);
        assert!(stdout.contains("3 files"), "{stdout}");
    }

    /// An interrupted write leaves no partial file referenced by a manifest.
    #[test]
    fn crash_mid_write() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, gloas) = fork_slots();
        let s = sepolia();
        let chain = ChainParams {
            schedule: s,
            caps: NetworkCaps::from_config(&ChainConfig::load(Network::Sepolia).unwrap()),
        };
        let config = CaptureConfig {
            network: "sepolia".into(),
            topics: vec!["beacon_block".into()],
            capture_host: "sepolia-ref-1".into(),
            clock_source: "chrony".into(),
            slots_per_segment: 32,
            max_bytes: 1 << 30,
            fork_digests: sepolia_digests(),
        };
        let put = |w: &mut Writer<Mainnet>, slot: Slot| {
            let (payload, root) = fixtures::block_on::<Mainnet>(&s, slot, 0);
            w.put(Capture {
                topic: "beacon_block",
                fork_digest: digest(GLOAS_DIGEST),
                payload: &payload,
            })
            .map(|_| (root, payload))
        };

        // Two segments: the first rolls (sealed), the second crashes mid-write.
        let mut w = Writer::<Mainnet>::create(tmp.path(), config.clone(), chain).unwrap();
        put(&mut w, gloas).unwrap();
        put(&mut w, gloas + 32).unwrap();
        let (payload, _) = fixtures::block_on::<Mainnet>(&s, gloas + 33, 0);
        w.inject_fault(Fault::Crash {
            after: payload.len() / 2,
        });
        assert!(put(&mut w, gloas + 33).unwrap_err().stops_capture());
        let sealed = w.sealed().to_vec();
        drop(w);

        // The sealed segment verifies and holds only the complete payload.
        let net = tmp.path().join("sepolia");
        assert_eq!(sealed, [net.join(format!("{gloas}-{}", gloas + 31))]);
        let archive = open_verified(&sealed[0]).unwrap();
        assert_eq!(
            archive.files().iter().map(|f| f.slot).collect::<Vec<_>>(),
            [gloas]
        );

        // The crashed segment is no archive: no manifest, so nothing references its files.
        let mut open: Vec<_> = fs::read_dir(&net)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with(OPEN_PREFIX)
            })
            .collect();
        assert_eq!(open.len(), 1);
        let open = open.remove(0);
        assert!(!open.join(MANIFEST_FILE).exists());
        let partial: Vec<_> = fs::read_dir(open.join("beacon_block"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "tmp"))
            .collect();
        assert_eq!(partial.len(), 1, "the crashed temp file");
        assert_eq!(fs::read(&partial[0]).unwrap(), payload[..payload.len() / 2]);
        assert!(matches!(
            open_verified(&open),
            Err(ArchiveError::Unsealed(_))
        ));
        let (code, _, _) = run_args(&["verify", open.to_str().unwrap()]);
        assert_eq!(code, EXIT_FAILED);

        // A restarted capture seals its own segment; no manifest names the partial file.
        let mut w = Writer::<Mainnet>::create(tmp.path(), config, chain).unwrap();
        put(&mut w, gloas + 33).unwrap();
        let restarted = w.close().unwrap();
        assert_eq!(
            restarted,
            [net.join(format!("{}-{}", gloas + 33, gloas + 33))]
        );
        let partial_name = partial[0].file_name().unwrap().to_str().unwrap().to_owned();
        for segment in sealed.iter().chain(&restarted) {
            let archive = open_verified(segment).unwrap();
            assert!(archive
                .files()
                .iter()
                .all(|f| !f.path.contains(&partial_name)));
        }
    }

    /// The exit-14 manifest fields are all there, and replay refuses an archive whose sha256
    /// mismatches.
    #[test]
    fn exit14_manifest_fields_and_sha256_refusal() {
        let tmp = tempfile::tempdir().unwrap();
        let (segments, expected) = capture_into(tmp.path());
        let text = fs::read_to_string(segments[0].join(MANIFEST_FILE)).unwrap();
        let (fulu, _) = fork_slots();
        for field in [
            "archive_sha256 = \"".to_string(),
            "network = \"sepolia\"".into(),
            format!("fork_digests = [\"0x{FULU_DIGEST}\"]"),
            format!("slot_start = {fulu}"),
            format!("slot_end = {}", fulu + 31),
            format!("topics = [\"beacon_block\", \"{COLUMN}\"]"),
            "peer_count = 42".into(),
            "capture_host = \"sepolia-ref-1\"".into(),
            "clock_source = \"chrony\"".into(),
            format!("sha256 = \"{}\"", hex::encode(sha256(&expected[0].payload))),
            format!("root = \"0x{}\"", hex::encode(expected[0].root)),
        ] {
            assert!(text.contains(&field), "{field} missing from\n{text}");
        }

        // A file whose sha256 no longer matches (same length): refused.
        let victim = segments[0].join(file_of(&expected[0]).path);
        let mut bytes = fs::read(&victim).unwrap();
        bytes[0] ^= 0x80;
        fs::write(&victim, &bytes).unwrap();
        let e = open_verified(&segments[0]).unwrap_err();
        let ArchiveError::Sha256Mismatch {
            expected: want,
            actual,
            ..
        } = e
        else {
            panic!("{e}");
        };
        assert_eq!(want, hex::encode(sha256(&expected[0].payload)));
        assert_eq!(actual, hex::encode(sha256(&bytes)));

        // The manifest's own sha256 (a file entry's digest edited): refused by the archive
        // digest even though the file then matches.
        bytes[0] ^= 0x80;
        fs::write(&victim, &bytes).unwrap();
        let manifest = segments[0].join(MANIFEST_FILE);
        let forged = text.replace(
            &hex::encode(sha256(&expected[0].payload)),
            &hex::encode(sha256(b"forged")),
        );
        fs::write(&manifest, forged).unwrap();
        assert!(matches!(
            open_verified(&segments[0]).unwrap_err(),
            ArchiveError::Manifest {
                source: ManifestError::DigestMismatch { .. },
                ..
            }
        ));
    }

    /// A genesis validators root for the Hoodi tests. Hoodi pins none, and any root gives a
    /// consistent digest schedule.
    const HOODI_TEST_ROOT: [u8; 32] = [0x21; 32];

    fn hoodi() -> ChainConfig {
        ChainConfig::load(Network::Hoodi).unwrap()
    }

    /// Hoodi's Gloas fork epoch and its first slot.
    fn hoodi_gloas() -> (consensus_types::primitives::Epoch, Slot) {
        let epoch = hoodi().fork_schedule().fork_epoch(ForkName::Gloas).unwrap();
        (epoch, Mainnet::start_slot_at_epoch(epoch))
    }

    /// Hoodi's digest at an epoch, with [`HOODI_TEST_ROOT`].
    fn hoodi_digest(epoch: consensus_types::primitives::Epoch) -> ForkDigest {
        compute_fork_digest(&hoodi(), &HOODI_TEST_ROOT, epoch).unwrap()
    }

    /// Replaces the `fork_digest` of the file at `path` in the manifest text with `to`, and
    /// rehashes the body: a forged manifest whose archive digest still holds.
    fn forge_file_digest(manifest: &str, path: &str, to: ForkDigest) -> String {
        let (_, body) = manifest.split_once('\n').unwrap();
        let table = body.find(&format!("path = \"{path}\"")).unwrap();
        let key = "fork_digest = \"0x";
        let at = table + body[table..].find(key).unwrap() + key.len();
        let mut body = body.to_owned();
        body.replace_range(at..at + 8, &hex::encode(to));
        let digest = hex::encode(sha256(body.as_bytes()));
        format!("archive_sha256 = \"{digest}\"\n{body}")
    }

    /// A Hoodi segment across the Gloas fork (epoch 132352, slot 4235264): the Gloas block and
    /// column, then the last Fulu block and column late, then the next Gloas block. The late
    /// payloads join the open segment, so one manifest holds both digests. It round-trips, and
    /// `open_verified` refuses a file whose fork digest is not the one of its slot.
    #[test]
    fn two_digest_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let (gloas_epoch, gloas) = hoodi_gloas();
        assert_eq!((gloas_epoch, gloas), (132352, 4_235_264));
        let schedule = *hoodi().fork_schedule();
        let (pre, post) = (hoodi_digest(gloas_epoch - 1), hoodi_digest(gloas_epoch));
        assert_ne!(pre, post);
        let late = gloas - 1;
        let input = tmp.path().join("input");
        fs::create_dir_all(&input).unwrap();
        let payloads = [
            (
                "beacon_block",
                gloas,
                fixtures::block_on::<Mainnet>(&schedule, gloas, 1),
            ),
            (
                COLUMN,
                gloas,
                fixtures::column_on::<Mainnet>(&schedule, gloas, 1, 5),
            ),
            (
                "beacon_block",
                late,
                fixtures::block_on::<Mainnet>(&schedule, late, 2),
            ),
            (
                COLUMN,
                late,
                fixtures::column_on::<Mainnet>(&schedule, late, 2, 5),
            ),
            (
                "beacon_block",
                gloas + 1,
                fixtures::block_on::<Mainnet>(&schedule, gloas + 1, 3),
            ),
        ];
        for (seq, (topic, slot, (payload, _))) in payloads.iter().enumerate() {
            let digest = if *slot < gloas { pre } else { post };
            let name = format!("{seq}_{}_{topic}{INPUT_SUFFIX}", hex::encode(digest));
            fs::write(input.join(name), payload).unwrap();
        }
        let out = tmp.path().join("archive");
        let mut a = capture_args(input.to_str().unwrap(), out.to_str().unwrap());
        let gvr = format!("0x{}", hex::encode(HOODI_TEST_ROOT));
        a[2] = "hoodi";
        a.extend(["--genesis-validators-root", &gvr]);
        let (code, stdout, stderr) = run_args(&a);
        assert_eq!(code, 0, "{stderr}");
        let segment = out.join(format!("hoodi/{late}-{}", gloas + 1));
        assert_eq!(
            stdout.lines().collect::<Vec<_>>(),
            [segment.to_str().unwrap()]
        );

        // The manifest names both digests, the schedule over its slot range and, per file, the
        // digest of its slot.
        let archive = open_verified(&segment).unwrap();
        let m = archive.manifest();
        let bpo = hoodi()
            .blob_schedule()
            .iter()
            .map(|b| b.epoch)
            .filter(|e| *e < gloas_epoch)
            .max()
            .unwrap();
        assert_eq!(hoodi_digest(bpo), pre, "the last BPO digest is in force");
        assert_eq!(
            m.digest_schedule,
            [
                DigestEntry {
                    epoch: bpo,
                    digest: pre
                },
                DigestEntry {
                    epoch: gloas_epoch,
                    digest: post
                }
            ]
        );
        let mut both = vec![pre, post];
        both.sort();
        assert_eq!(m.fork_digests, both);
        assert_eq!(archive.files().len(), payloads.len());
        for f in archive.files() {
            let want = if f.slot < gloas { pre } else { post };
            assert_eq!((f.fork_digest, m.digest_at(f.slot)), (want, Some(want)));
        }
        let text = fs::read_to_string(segment.join(MANIFEST_FILE)).unwrap();
        for field in [
            "format_version = 2".to_string(),
            format!(
                "[[digest_schedule]]\nepoch = {bpo}\ndigest = \"0x{}\"",
                hex::encode(pre)
            ),
            format!(
                "[[digest_schedule]]\nepoch = {gloas_epoch}\ndigest = \"0x{}\"",
                hex::encode(post)
            ),
        ] {
            assert!(text.contains(&field), "{field} missing from\n{text}");
        }
        let (bytes, digest) = m.render().unwrap();
        assert_eq!(
            (bytes, digest),
            (text.clone().into_bytes(), archive.archive_sha256())
        );
        assert_eq!(
            Manifest::parse(text.as_bytes()).unwrap(),
            (m.clone(), digest)
        );

        // A file on the other digest than its slot's, in a rehashed manifest: refused, in both
        // directions across the fork.
        let manifest = segment.join(MANIFEST_FILE);
        for (slot, wrong, right) in [(late, post, pre), (gloas, pre, post)] {
            let file = archive
                .files()
                .iter()
                .find(|f| f.slot == slot && f.topic == "beacon_block")
                .unwrap();
            fs::write(&manifest, forge_file_digest(&text, &file.path, wrong)).unwrap();
            let e = open_verified(&segment).unwrap_err();
            assert!(
                matches!(
                    &e,
                    ArchiveError::Manifest {
                        source: ManifestError::ForkDigest { path, slot: s, expected, got },
                        ..
                    } if *path == file.path && *s == slot && *expected == Some(right)
                        && *got == wrong
                ),
                "{slot}: {e}"
            );
            let (code, _, stderr) = run_args(&["verify", segment.to_str().unwrap()]);
            assert_eq!(code, EXIT_FAILED);
            assert!(stderr.contains("fork digest"), "{stderr}");
        }
        fs::write(&manifest, &text).unwrap();
        let (code, stdout, _) = run_args(&["verify", segment.to_str().unwrap()]);
        assert_eq!(code, 0);
        assert!(stdout.contains("5 files"), "{stdout}");
    }

    /// A segment of the format before the digest schedule, rehashed so that its archive
    /// digest holds: `verify` refuses it as a format version.
    #[test]
    fn verify_refuses_a_version_1_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let (segments, _) = capture_into(tmp.path());
        let manifest = segments[0].join(MANIFEST_FILE);
        let text = fs::read_to_string(&manifest).unwrap();
        let (_, body) = text.split_once('\n').unwrap();
        let start = body.find("[[digest_schedule]]").unwrap();
        let end = body.find("[[files]]").unwrap();
        let v1 = format!("{}{}", &body[..start], &body[end..]).replacen(
            "format_version = 2",
            "format_version = 1",
            1,
        );
        let digest = hex::encode(sha256(v1.as_bytes()));
        fs::write(&manifest, format!("archive_sha256 = \"{digest}\"\n{v1}")).unwrap();
        let (code, stdout, stderr) = run_args(&["verify", segments[0].to_str().unwrap()]);
        assert_eq!(code, EXIT_FAILED);
        assert!(stdout.is_empty(), "{stdout}");
        assert!(
            stderr.contains("refused") && stderr.contains("format_version 1, expected 2"),
            "{stderr}"
        );
        assert!(matches!(
            open_verified(&segments[0]),
            Err(ArchiveError::Manifest {
                source: ManifestError::Version(1),
                ..
            })
        ));
    }

    #[test]
    fn capture_reports_refusals_and_stops() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("input");
        let out = tmp.path().join("archive");
        let expected = captured(&input);
        // A payload that does not decode, on a known topic.
        fs::write(
            input.join(format!("9_{GLOAS_DIGEST}_beacon_block{INPUT_SUFFIX}")),
            b"junk",
        )
        .unwrap();
        let (i, o) = (input.to_str().unwrap(), out.to_str().unwrap());
        let (code, stdout, stderr) = run_args(&capture_args(i, o));
        assert_eq!(code, EXIT_FAILED);
        assert!(
            stderr.contains("9_") && stderr.contains("refused"),
            "{stderr}"
        );
        assert_eq!(stdout.lines().count(), 2, "both segments still sealed");

        // A budget that stops the capture after the first payload: the seal says so.
        let out2 = tmp.path().join("archive2");
        let budget = (expected[0].payload.len() + 1).to_string();
        let mut a = capture_args(i, out2.to_str().unwrap());
        a.extend(["--max-bytes", &budget]);
        let (code, stdout, stderr) = run_args(&a);
        assert_eq!(code, EXIT_FAILED);
        assert!(stderr.contains("disk budget"), "{stderr}");
        let segment = PathBuf::from(stdout.lines().next().unwrap());
        let m = open_verified(&segment).unwrap().manifest().clone();
        assert_eq!(m.closed_by, ClosedBy::Error);
        assert_eq!(m.files.len(), 1);
    }

    #[test]
    fn a_payload_on_the_wrong_fork_digest_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("input");
        let out = tmp.path().join("archive");
        let expected = captured(&input);
        // The Gloas block again under the Fulu digest, as if it came in on a Fulu topic.
        fs::write(
            input.join(format!("9_{FULU_DIGEST}_beacon_block{INPUT_SUFFIX}")),
            &expected[2].payload,
        )
        .unwrap();
        let (code, stdout, stderr) = run_args(&capture_args(
            input.to_str().unwrap(),
            out.to_str().unwrap(),
        ));
        assert_eq!(code, EXIT_FAILED);
        assert!(
            stderr.contains("9_") && stderr.contains("skipped") && stderr.contains("fork digest"),
            "{stderr}"
        );
        let segments: Vec<PathBuf> = stdout.lines().map(PathBuf::from).collect();
        assert_eq!(segments.len(), 2);
        let m = open_verified(&segments[1]).unwrap().manifest().clone();
        assert_eq!(m.closed_by, ClosedBy::Close);
        assert_eq!(m.fork_digests, [digest(GLOAS_DIGEST)]);
    }

    #[test]
    fn an_input_over_the_gossip_bound_stops_the_capture_unread() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("input");
        let out = tmp.path().join("archive");
        captured(&input);
        // Sparse, so the test does not write it out; the archiver must not read it in.
        let huge = input.join(format!("9_{GLOAS_DIGEST}_beacon_block{INPUT_SUFFIX}"));
        fs::File::create(&huge).unwrap().set_len(64 << 30).unwrap();
        let (code, stdout, stderr) = run_args(&capture_args(
            input.to_str().unwrap(),
            out.to_str().unwrap(),
        ));
        assert_eq!(code, EXIT_FAILED);
        assert!(stderr.contains("over the gossip bound"), "{stderr}");
        let segments: Vec<PathBuf> = stdout.lines().map(PathBuf::from).collect();
        assert_eq!(segments.len(), 2);
        let m = open_verified(&segments[1]).unwrap().manifest().clone();
        assert_eq!(m.closed_by, ClosedBy::Error);
        assert!(
            m.error
                .as_deref()
                .unwrap()
                .contains("over the gossip bound"),
            "{:?}",
            m.error
        );
        assert_eq!(m.files.len(), 3, "every payload before it");

        // One byte over the bound is refused; exactly the bound is read (and refused later as a
        // payload, not as an input).
        let max = max_compressed_payload_len();
        let file = tmp.path().join("bound");
        fs::File::create(&file)
            .unwrap()
            .set_len(max as u64 + 1)
            .unwrap();
        assert!(read_payload(&file).is_err());
        fs::File::create(&file)
            .unwrap()
            .set_len(max as u64)
            .unwrap();
        assert_eq!(read_payload(&file).unwrap().len(), max);
        assert!(read_payload(&tmp.path().join("absent"))
            .unwrap_err()
            .contains("absent"));
    }

    #[test]
    fn capture_refuses_bad_input_before_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("input");
        let out = tmp.path().join("archive");
        captured(&input);
        let (i, o) = (input.to_str().unwrap(), out.to_str().unwrap());
        let mut with_topic = capture_args(i, o);
        with_topic.extend(["--topic", "beacon_block"]);
        // The column files are on a topic not subscribed: refused one by one.
        let (code, stdout, stderr) = run_args(&with_topic);
        assert_eq!(code, EXIT_FAILED);
        assert!(stderr.contains("not subscribed"), "{stderr}");
        assert_eq!(stdout.lines().count(), 2);

        for bad in [
            "x_f0010001_beacon_block.ssz_snappy",
            "1_f00100_beacon_block.ssz_snappy",
        ] {
            let input = tmp.path().join(format!("bad-{}", bad.len()));
            captured(&input);
            fs::write(input.join(bad), b"").unwrap();
            let out = tmp.path().join(format!("out-{}", bad.len()));
            let (code, _, stderr) = run_args(&capture_args(
                input.to_str().unwrap(),
                out.to_str().unwrap(),
            ));
            assert_eq!(code, EXIT_FAILED, "{bad}");
            assert!(stderr.contains(bad), "{stderr}");
            assert!(!out.exists(), "nothing written for {bad}");
        }
        let input = tmp.path().join("dup");
        captured(&input);
        fs::write(
            input.join(format!("0_{FULU_DIGEST}_beacon_block_x{INPUT_SUFFIX}")),
            b"",
        )
        .unwrap();
        let (code, _, stderr) = run_args(&capture_args(input.to_str().unwrap(), o));
        assert_eq!(code, EXIT_FAILED);
        assert!(stderr.contains("sequence 0"), "{stderr}");

        let (code, _, stderr) = run_args(&capture_args(
            tmp.path().join("absent").to_str().unwrap(),
            o,
        ));
        assert_eq!(code, EXIT_FAILED);
        assert!(stderr.contains("absent"), "{stderr}");

        let empty = tmp.path().join("empty");
        fs::create_dir(&empty).unwrap();
        let (code, _, stderr) = run_args(&capture_args(empty.to_str().unwrap(), o));
        assert_eq!(code, EXIT_FAILED);
        assert!(stderr.contains("no topic"), "{stderr}");
    }

    #[test]
    fn input_names() {
        assert_eq!(
            parse_input_name("12_f0010001_data_column_sidecar_5.ssz_snappy"),
            Some((12, [0xf0, 1, 0, 1], COLUMN.to_string()))
        );
        for bad in [
            "12_f0010001_beacon_block.ssz",
            "12_f0010001_.ssz_snappy",
            "12_F0010001_beacon_block.ssz_snappy",
            "12_f001000_beacon_block.ssz_snappy",
            "-1_f0010001_beacon_block.ssz_snappy",
            "_f0010001_beacon_block.ssz_snappy",
            "12f0010001_beacon_block.ssz_snappy",
            "12_f0010001beacon_block.ssz_snappy",
        ] {
            assert_eq!(parse_input_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn usage() {
        let tmp = tempfile::tempdir().unwrap();
        let (i, o) = (tmp.path().to_str().unwrap(), tmp.path().to_str().unwrap());
        let (code, stdout, _) = run_args(&["--help"]);
        assert_eq!(code, 0);
        assert!(stdout.contains("archiver verify"));
        for bad in [
            vec![],
            vec!["verify"],
            vec!["verify", "a", "b"],
            vec!["bogus"],
            vec!["capture", "--network", "mainnet"],
            vec!["capture", "--input"],
            vec!["capture", "--peer-count", "many"],
            vec!["capture", "--frobnicate"],
        ] {
            let (code, _, stderr) = run_args(&bad);
            assert_eq!(code, EXIT_USAGE, "{bad:?}");
            assert!(stderr.contains("usage:"), "{bad:?}: {stderr}");
        }
        // Every required option.
        let full = capture_args(i, o);
        for required in [
            "--network",
            "--input",
            "--out",
            "--host",
            "--clock-source",
            "--peer-count",
        ] {
            let at = full.iter().position(|a| *a == required).unwrap();
            let mut missing = full.clone();
            missing.drain(at..at + 2);
            let (code, _, stderr) = run_args(&missing);
            assert_eq!(code, EXIT_USAGE, "{required}");
            assert!(stderr.contains(required), "{stderr}");
        }
        let mut full = full;
        full.extend([
            "--topic",
            "beacon_block",
            "--topic",
            COLUMN,
            "--slots-per-segment",
            "8",
            "--max-bytes",
            "100",
        ]);
        assert_eq!(
            parse(&args(&full)).unwrap(),
            Command::Capture(CaptureArgs {
                network: Network::Sepolia,
                input: i.into(),
                out: o.into(),
                host: "sepolia-ref-1".into(),
                clock_source: "chrony".into(),
                peer_count: 42,
                topics: vec!["beacon_block".into(), COLUMN.into()],
                slots_per_segment: 8,
                max_bytes: 100,
                genesis_validators_root: Network::Sepolia
                    .genesis()
                    .unwrap()
                    .genesis_validators_root,
            })
        );

        // Hoodi has no pinned genesis: its root must be given.
        let mut hoodi: Vec<String> = capture_args(i, o)
            .iter()
            .map(|a| if *a == "sepolia" { "hoodi" } else { a }.to_string())
            .collect();
        let e = parse(&hoodi).unwrap_err();
        assert!(e.contains("--genesis-validators-root is required"), "{e}");
        let gvr = format!("0x{}", "ab".repeat(32));
        hoodi.extend(["--genesis-validators-root".into(), gvr]);
        let Command::Capture(c) = parse(&hoodi).unwrap() else {
            panic!("capture");
        };
        assert_eq!(
            (
                c.network,
                c.slots_per_segment,
                c.max_bytes,
                c.genesis_validators_root
            ),
            (
                Network::Hoodi,
                DEFAULT_SLOTS_PER_SEGMENT,
                DEFAULT_MAX_BYTES,
                [0xab; 32]
            )
        );

        // A given root must be the pinned one, and well-formed.
        let pinned = hex::encode(Network::Sepolia.genesis().unwrap().genesis_validators_root);
        let wrong = format!("0x{}", "ab".repeat(32));
        let upper = format!("0x{}", pinned.to_uppercase());
        let pinned = format!("0x{pinned}");
        for (root, ok) in [
            (pinned.as_str(), true),
            (wrong.as_str(), false),
            (upper.as_str(), false),
            (&pinned[2..], false),
            ("0xab", false),
        ] {
            let mut a = capture_args(i, o);
            a.extend(["--genesis-validators-root", root]);
            assert_eq!(parse(&args(&a)).is_ok(), ok, "{root}");
        }
    }
}
