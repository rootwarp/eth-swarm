//! `export-blocks`: export a devnet's blocks and roots, verify an export, or diff the root lists
//! of two.
//!
//! ```text
//! export-blocks export --api URL --config PATH --devnet NAME --source NAME --to SLOT
//!                      --out DIR --image REF [--image REF]...
//!                      [--timeout-secs N] [--state-timeout-secs N] [--max-state-bytes N]
//! export-blocks verify [--sha256 HEX] EXPORT_DIR
//! export-blocks diff EXPORT_DIR EXPORT_DIR
//! export-blocks --help
//! ```
//!
//! `export` runs [`testkit::export_blocks::export`] against one CL's beacon API (plain
//! `http://` to a loopback host; `kurtosis port print <enclave> <service> http` gives one) with
//! the devnet's `config.yaml`, whose preset picks the spec, and writes `OUT/<devnet>/`. `verify`
//! opens an export through [`testkit::export_blocks::open_export`], or with `--sha256` through
//! [`testkit::export_blocks::open_export_pinned`] (the only check that authenticates an
//! export: the digest `export` printed, from the run log), and prints its slot range, block and
//! empty-slot counts, genesis roots and digest. `diff` opens two exports unpinned and compares
//! their root lists ([`testkit::export_blocks::diff_root_lists`]); verify each pinned first.
//!
//! Exit codes: 0 done (or identical root lists), 1 the export failed, an export was refused or
//! the root lists differ, 64 usage.

use consensus_types::{Mainnet, Minimal};
use network_config::ChainConfig;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use testkit::collector::ReferenceApiUrl;
use testkit::export_blocks::{
    diff_root_lists, export, open_export, open_export_pinned, Export, ExportConfig, RootListDiff,
    SlotEntry, DEFAULT_MAX_STATE_BYTES, DEFAULT_REQUEST_TIMEOUT, DEFAULT_STATE_TIMEOUT,
};

const USAGE: &str = "\
usage: export-blocks export --api URL --config PATH --devnet NAME --source NAME --to SLOT
                            --out DIR --image REF [--image REF]...
                            [--timeout-secs N] [--state-timeout-secs N] [--max-state-bytes N]
       export-blocks verify [--sha256 HEX] EXPORT_DIR
       export-blocks diff EXPORT_DIR EXPORT_DIR
       export-blocks --help";
const HELP: &str = "\
Export a devnet's blocks and roots from genesis to an export slot, plus its genesis state, into
a verified archive; verify an export; or diff the root lists of two exports.

export reads GET /eth/v2/beacon/blocks/{slot} (SSZ) for every slot from 0 to the CL's finalized
block, cross-checks each block's hash_tree_root against /eth/v1/beacon/blocks/{slot}/root and
its parent against the previous block (a slot is empty only if both answer 404), requires the
chain to end on the finalized block, and writes OUT/<devnet>/: an archive segment of the blocks
to --to, genesis_state.ssz and export.toml.

  --api URL                  the CL's beacon API, http:// to a loopback host
  --config PATH              the devnet's config.yaml (its PRESET_BASE picks the spec)
  --devnet NAME              the devnet name, the export directory ([a-z0-9_-])
  --source NAME              the CL read from, for the manifest (e.g. cl-1-lighthouse-geth)
  --to SLOT                  the export slot, at or before the CL's finalized block
  --out DIR                  where OUT/<devnet>/ is written; it must not exist yet
  --image REF                a devnet image, repo:tag@sha256:<digest>, repeatable (at least one)
  --timeout-secs N           the deadline of each block and root request (default 30)
  --state-timeout-secs N     the deadline of the genesis state request (default 300)
  --max-state-bytes N        the largest genesis state read (default and most 268435456)

verify checks an export (manifest digest, every segment through open_verified, the block files
against the manifest's blocks, then the genesis state and every block decoded again) and prints
what it holds. That proves it holds together, not that it is the devnet's: anyone who can write
the directory can forge a consistent chain suffix. --sha256 HEX (the export_sha256 export
printed, from the run log) refuses any export but that one; only the pin authenticates it.

  --sha256 HEX               the pinned export_sha256, 64 lowercase hex digits

diff verifies two exports, unpinned, and compares their root lists slot by slot from genesis;
verify each one pinned first.

Exit codes: 0 done (or identical root lists), 1 the export failed, an export was refused or the
root lists differ, 64 usage.";

const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 64;
/// The largest `config.yaml` read: far above any network's (Sepolia's is under 10 KiB).
const MAX_CONFIG_BYTES: u64 = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Verify(PathBuf, Option<[u8; 32]>),
    Diff(PathBuf, PathBuf),
    Export(ExportArgs),
}

#[derive(Debug, PartialEq, Eq)]
struct ExportArgs {
    api: String,
    config: PathBuf,
    devnet: String,
    source: String,
    to: u64,
    out: PathBuf,
    images: Vec<String>,
    timeout: Duration,
    state_timeout: Duration,
    max_state_bytes: usize,
}

fn parse(args: &[String]) -> Result<Command, String> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Command::Help);
    }
    match args.first().map(String::as_str) {
        Some("verify") => parse_verify(&args[1..]),
        Some("diff") => match &args[1..] {
            [a, b] => Ok(Command::Diff(a.into(), b.into())),
            _ => Err("diff takes exactly two EXPORT_DIRs".into()),
        },
        Some("export") => parse_export(&args[1..]).map(Command::Export),
        Some(_) => Err("unknown command (want export, verify or diff)".into()),
        None => Err("no command".into()),
    }
}

fn parse_verify(args: &[String]) -> Result<Command, String> {
    let (mut dir, mut pin) = (None, None);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "--sha256" {
            let value = it.next().ok_or("--sha256 needs a value")?;
            if pin.replace(sha256_hex(value)?).is_some() {
                return Err("give --sha256 once".into());
            }
        } else if dir.replace(PathBuf::from(arg)).is_some() {
            return Err("verify takes exactly one EXPORT_DIR".into());
        }
    }
    let dir = dir.ok_or("verify takes exactly one EXPORT_DIR")?;
    Ok(Command::Verify(dir, pin))
}

/// 64 lowercase hex digits; the error never quotes the value.
fn sha256_hex(value: &str) -> Result<[u8; 32], String> {
    let lower = value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let mut digest = [0; 32];
    match hex::decode_to_slice(value, &mut digest) {
        Ok(()) if lower => Ok(digest),
        _ => Err("--sha256: want 64 lowercase hex digits".into()),
    }
}

fn parse_export(args: &[String]) -> Result<ExportArgs, String> {
    let (mut api, mut config, mut devnet, mut source, mut to, mut out) =
        (None, None, None, None, None, None);
    let mut images = Vec::new();
    let mut timeout = DEFAULT_REQUEST_TIMEOUT;
    let mut state_timeout = DEFAULT_STATE_TIMEOUT;
    let mut max_state_bytes = DEFAULT_MAX_STATE_BYTES;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))
            .map(String::as_str);
        match flag.as_str() {
            "--api" => api = Some(value?.to_owned()),
            "--config" => config = Some(PathBuf::from(value?)),
            "--devnet" => devnet = Some(value?.to_owned()),
            "--source" => source = Some(value?.to_owned()),
            "--to" => to = Some(number(flag, value?)?),
            "--out" => out = Some(PathBuf::from(value?)),
            "--image" => images.push(value?.to_owned()),
            "--timeout-secs" => timeout = seconds(flag, value?)?,
            "--state-timeout-secs" => state_timeout = seconds(flag, value?)?,
            "--max-state-bytes" => max_state_bytes = number(flag, value?)?,
            other => return Err(unknown_argument(other)),
        }
    }
    fn required<T>(value: Option<T>, flag: &str) -> Result<T, String> {
        value.ok_or_else(|| format!("{flag} is required"))
    }
    if images.is_empty() {
        return Err("--image is required (each repo:tag@sha256:<digest>)".into());
    }
    Ok(ExportArgs {
        api: required(api, "--api")?,
        config: required(config, "--config")?,
        devnet: required(devnet, "--devnet")?,
        source: required(source, "--source")?,
        to: required(to, "--to")?,
        out: required(out, "--out")?,
        images,
        timeout,
        state_timeout,
        max_state_bytes,
    })
}

/// The error for an argument `export` does not take. An argument can hold a keyed URL
/// (`--api=http://…/<key>`, or a URL where a flag was due), so, as the collector does, only a
/// flag's key is named, and only when it looks like one; never a value.
fn unknown_argument(arg: &str) -> String {
    let key = arg.split_once('=').map_or(arg, |(key, _)| key);
    let flag_like = key.len() <= 32
        && key.strip_prefix("--").is_some_and(|name| {
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if flag_like {
        format!("unknown argument {key} (a flag and its value are two arguments)")
    } else {
        "unknown argument (not shown: it may hold a URL)".into()
    }
}

/// A decimal number; the error names the flag, never the value.
fn number<T: std::str::FromStr>(flag: &str, value: &str) -> Result<T, String> {
    let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
    digits
        .then(|| value.parse().ok())
        .flatten()
        .ok_or_else(|| format!("{flag}: not a number"))
}

fn seconds(flag: &str, value: &str) -> Result<Duration, String> {
    match number::<u64>(flag, value)? {
        0 => Err(format!("{flag} must be at least 1")),
        s => Ok(Duration::from_secs(s)),
    }
}

/// The config bytes, reading at most one byte past [`MAX_CONFIG_BYTES`].
fn read_config(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(format!("{}: over {MAX_CONFIG_BYTES} bytes", path.display()));
    }
    Ok(bytes)
}

fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let command = match parse(args) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(err, "export-blocks: {e}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    match command {
        Command::Help => {
            let _ = writeln!(out, "{USAGE}\n\n{HELP}");
            0
        }
        Command::Verify(dir, pin) => verify(&dir, pin, out, err),
        Command::Diff(a, b) => diff(&a, &b, out, err),
        Command::Export(args) => match run_export(&args) {
            Ok(export) => {
                let _ = writeln!(out, "{}", summary(&export));
                0
            }
            Err(e) => {
                let _ = writeln!(err, "export-blocks: export failed: {e}");
                EXIT_FAILED
            }
        },
    }
}

fn run_export(args: &ExportArgs) -> Result<Export, String> {
    let url = ReferenceApiUrl::parse(&args.api).map_err(|e| format!("--api: {e}"))?;
    let yaml = read_config(&args.config)?;
    let config_sha256: [u8; 32] = Sha256::digest(&yaml).into();
    let chain = ChainConfig::from_yaml(&yaml, &config_sha256)
        .map_err(|e| format!("{}: {e}", args.config.display()))?;
    let config = ExportConfig {
        devnet: args.devnet.clone(),
        source: args.source.clone(),
        to_slot: args.to,
        images: args.images.clone(),
        config_sha256,
        request_timeout: args.timeout,
        state_timeout: args.state_timeout,
        max_state_bytes: args.max_state_bytes,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    let exported = runtime.block_on(async {
        match chain.preset_base() {
            "minimal" => export::<Minimal>(&url, &chain, &config, &args.out).await,
            "mainnet" => export::<Mainnet>(&url, &chain, &config, &args.out).await,
            other => Err(testkit::export_blocks::ExportError::Config(format!(
                "unknown PRESET_BASE {other:?}"
            ))),
        }
    });
    exported.map_err(|e| e.to_string())
}

/// One line: where the export is, what it holds, and its digest.
fn summary(export: &Export) -> String {
    let m = export.manifest();
    let last = m.blocks.last().expect("an export has a genesis block");
    format!(
        "{}: ok, devnet {} source {} slots {}-{}: {} blocks, {} empty; genesis block {} \
         state {}; last block slot {} root {}; export_sha256 {}",
        export.dir().display(),
        m.devnet,
        m.source,
        m.slot_start,
        m.slot_end,
        m.blocks.len(),
        m.empty_slots.len(),
        m.genesis_block_root,
        m.genesis_state_root,
        last.slot,
        last.root,
        hex::encode(export.export_sha256())
    )
}

fn open(dir: &Path, pin: Option<[u8; 32]>, err: &mut dyn Write) -> Option<Export> {
    let opened = match pin {
        Some(pin) => open_export_pinned(dir, pin),
        None => open_export(dir),
    };
    match opened {
        Ok(export) => Some(export),
        Err(e) => {
            let _ = writeln!(err, "export-blocks: {}: refused: {e}", dir.display());
            None
        }
    }
}

fn verify(dir: &Path, pin: Option<[u8; 32]>, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    match open(dir, pin, err) {
        Some(export) => {
            let _ = writeln!(out, "{}", summary(&export));
            0
        }
        None => EXIT_FAILED,
    }
}

fn entry(e: SlotEntry) -> String {
    match e {
        SlotEntry::Block(root) => format!("block {root}"),
        SlotEntry::Empty => "empty".into(),
        SlotEntry::NotExported => "not exported".into(),
    }
}

fn diff(a: &Path, b: &Path, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let (Some(ea), Some(eb)) = (open(a, None, err), open(b, None, err)) else {
        return EXIT_FAILED;
    };
    let (ma, mb) = (ea.manifest(), eb.manifest());
    match diff_root_lists(&ea.root_list(), &eb.root_list()) {
        RootListDiff::Identical { slots } => {
            let _ = writeln!(
                out,
                "identical: {slots} slots, {} blocks ({} from {}, {} from {})",
                ma.blocks.len(),
                a.display(),
                ma.source,
                b.display(),
                mb.source
            );
            0
        }
        RootListDiff::Differ { slot, a: x, b: y } => {
            let _ = writeln!(
                err,
                "export-blocks: root lists differ, first at slot {slot}: {} ({}) has {}, {} ({}) \
                 has {}",
                a.display(),
                ma.source,
                entry(x),
                b.display(),
                mb.source,
                entry(y)
            );
            EXIT_FAILED
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&args, &mut std::io::stdout(), &mut std::io::stderr()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use testkit::export_blocks::fixtures::{Devnet, CONFIG, IMAGE};
    use testkit::export_blocks::FINALIZED_HEADER_PATH;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
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

    #[test]
    fn export_arguments() {
        let full = args(&[
            "export",
            "--api",
            "http://127.0.0.1:5052",
            "--config",
            "c.yaml",
            "--devnet",
            "dev",
            "--source",
            "cl-1",
            "--to",
            "95",
            "--out",
            "o",
            "--image",
            "a@sha256:x",
            "--image",
            "b@sha256:y",
            "--timeout-secs",
            "7",
            "--state-timeout-secs",
            "9",
            "--max-state-bytes",
            "1024",
        ]);
        assert_eq!(
            parse(&full),
            Ok(Command::Export(ExportArgs {
                api: "http://127.0.0.1:5052".into(),
                config: "c.yaml".into(),
                devnet: "dev".into(),
                source: "cl-1".into(),
                to: 95,
                out: "o".into(),
                images: vec!["a@sha256:x".into(), "b@sha256:y".into()],
                timeout: Duration::from_secs(7),
                state_timeout: Duration::from_secs(9),
                max_state_bytes: 1024,
            }))
        );
        let Ok(Command::Export(defaults)) = parse(&full[..15]) else {
            panic!("the required flags parse");
        };
        assert_eq!(defaults.timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(defaults.state_timeout, DEFAULT_STATE_TIMEOUT);
        assert_eq!(defaults.max_state_bytes, DEFAULT_MAX_STATE_BYTES);
        assert_eq!(defaults.images, vec!["a@sha256:x".to_owned()]);

        for (bad, why) in [
            (&full[..13], "--image is required"),
            (&full[..2], "--api needs a value"),
            (&args(&["export", "--to", "-1"])[..], "--to: not a number"),
            (&args(&["export", "--to", "+1"])[..], "--to: not a number"),
            (&args(&["export", "--timeout-secs", "0"])[..], "at least 1"),
            (
                &args(&["export", "--bogus", "1"])[..],
                "unknown argument --bogus",
            ),
            (&args(&["export", "--image", "a"])[..], "--api is required"),
        ] {
            let e = parse(bad).unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
    }

    #[test]
    fn usage_errors_never_quote_a_value() {
        // A misplaced URL can hold a key: no value given on the command line is echoed.
        const SECRET: &str = "hunter2";
        for bad in [
            &["export", "--to", "http://127.0.0.1/hunter2"][..],
            &["export", "--max-state-bytes", "hunter2"],
            &["export", "http://127.0.0.1/hunter2"],
            &["export", "--api=http://127.0.0.1/hunter2"],
            &[
                "export",
                "--hunter2-and-a-long-tail-of-more-characters",
                "x",
            ],
            &["hunter2"],
        ] {
            let e = parse(&args(bad)).unwrap_err();
            assert!(!e.contains(SECRET), "{bad:?}: {e}");
            let (code, _, err) = run_args(bad);
            assert_eq!(code, EXIT_USAGE);
            assert!(!err.contains(SECRET), "{bad:?}: {err}");
        }
        let e = parse(&args(&["export", "--api=http://x/hunter2"])).unwrap_err();
        assert!(e.contains("unknown argument --api"), "{e}");
    }

    #[test]
    fn commands_and_usage() {
        assert_eq!(
            parse(&args(&["verify", "x"])),
            Ok(Command::Verify("x".into(), None))
        );
        let pin = "ab".repeat(32);
        assert_eq!(
            parse(&args(&["verify", "--sha256", &pin, "x"])),
            Ok(Command::Verify("x".into(), Some([0xab; 32])))
        );
        assert_eq!(
            parse(&args(&["verify", "x", "--sha256", &pin])),
            Ok(Command::Verify("x".into(), Some([0xab; 32])))
        );
        for bad in [
            vec!["verify", "--sha256"],
            vec!["verify", "--sha256", &pin],
            vec!["verify", "--sha256", &pin, "--sha256", &pin, "x"],
            vec!["verify", "x", "y"],
        ] {
            assert!(parse(&args(&bad)).is_err(), "{bad:?}");
        }
        for hunter in [
            "AB".repeat(32),
            "ab".repeat(31),
            format!("{}hunter2", "a".repeat(57)),
        ] {
            let e = parse(&args(&["verify", "--sha256", &hunter, "x"])).unwrap_err();
            assert!(e.contains("--sha256: want 64 lowercase hex"), "{e}");
            assert!(!e.contains(&hunter), "{e}");
        }
        assert_eq!(
            parse(&args(&["diff", "a", "b"])),
            Ok(Command::Diff("a".into(), "b".into()))
        );
        assert_eq!(parse(&args(&["diff", "-h"])), Ok(Command::Help));
        for bad in [&["verify"][..], &["diff", "a"], &["frob"], &[]] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
        let (code, out, _) = run_args(&["--help"]);
        assert_eq!(code, 0);
        assert!(out.contains("--image REF"), "{out}");
        let (code, _, err) = run_args(&["frob"]);
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("usage:"), "{err}");
    }

    /// Exports `devnet` to slot `to` through the command line, into `out`.
    async fn export_cli(
        devnet: Devnet,
        to: u64,
        out: &Path,
        config: &Path,
    ) -> (u8, String, String) {
        let (server, _) = devnet.serve().await;
        let api = format!("http://{}", server.addr);
        let to = to.to_string();
        let (out, config) = (
            out.to_str().unwrap().to_owned(),
            config.to_str().unwrap().to_owned(),
        );
        tokio::task::spawn_blocking(move || {
            run_args(&[
                "export",
                "--api",
                &api,
                "--config",
                &config,
                "--devnet",
                "fixture-devnet",
                "--source",
                "cl-1-lighthouse-geth",
                "--to",
                &to,
                "--out",
                &out,
                "--image",
                IMAGE,
            ])
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn export_verify_and_diff() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.yaml");
        std::fs::write(&config, CONFIG).unwrap();
        let (a, b, c) = (
            tmp.path().join("a"),
            tmp.path().join("b"),
            tmp.path().join("c"),
        );

        let devnet = Devnet::new(10, &[3]);
        let (code, exported_a, err) = export_cli(devnet.clone(), 10, &a, &config).await;
        assert_eq!(code, 0, "{err}");
        assert!(
            exported_a.contains("slots 0-10: 10 blocks, 1 empty"),
            "{exported_a}"
        );
        let (code, _, err) = export_cli(devnet.clone(), 10, &b, &config).await;
        assert_eq!(code, 0, "{err}");

        let mut other = devnet.clone();
        let parent = other.root(7);
        other.reparent(
            8,
            parent,
            consensus_types::primitives::B256::repeat_byte(0x88),
        );
        other.rechain(8);
        let (code, exported_c, err) = export_cli(other, 10, &c, &config).await;
        assert_eq!(code, 0, "{err}");

        let (da, db, dc) = (
            a.join("fixture-devnet"),
            b.join("fixture-devnet"),
            c.join("fixture-devnet"),
        );
        let (code, out, _) = run_args(&["verify", da.to_str().unwrap()]);
        assert_eq!(code, 0);
        assert!(
            out.contains(": ok, devnet fixture-devnet source cl-1-lighthouse-geth"),
            "{out}"
        );
        // Pinned by the digest the export printed; another export's digest is refused.
        let pin = |out: &str| out.trim_end().rsplit(' ').next().unwrap().to_owned();
        let (pin_a, pin_c) = (pin(&exported_a), pin(&exported_c));
        let (code, out, err) = run_args(&["verify", "--sha256", &pin_a, da.to_str().unwrap()]);
        assert_eq!(code, 0, "{err}");
        assert!(out.ends_with(&format!("export_sha256 {pin_a}\n")), "{out}");
        let (code, _, err) = run_args(&["verify", "--sha256", &pin_c, da.to_str().unwrap()]);
        assert_eq!(code, EXIT_FAILED);
        assert!(
            err.contains("refused") && err.contains("not the pinned"),
            "{err}"
        );

        let (code, out, err) = run_args(&["diff", da.to_str().unwrap(), db.to_str().unwrap()]);
        assert_eq!(code, 0, "{err}");
        assert!(out.starts_with("identical: 11 slots, 10 blocks"), "{out}");

        let (code, _, err) = run_args(&["diff", da.to_str().unwrap(), dc.to_str().unwrap()]);
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("root lists differ, first at slot 8"), "{err}");

        // An export into an existing directory fails; so does a refused export dir.
        let (code, _, err) = export_cli(devnet, 10, &a, &config).await;
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("exists already"), "{err}");
        let (code, _, err) = run_args(&["verify", tmp.path().to_str().unwrap()]);
        assert_eq!(code, EXIT_FAILED);
        assert!(err.contains("refused"), "{err}");
        let (code, _, _) = run_args(&["diff", tmp.path().to_str().unwrap(), db.to_str().unwrap()]);
        assert_eq!(code, EXIT_FAILED);
    }

    #[test]
    fn export_setup_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config.yaml");
        let mut base = ExportArgs {
            api: "http://10.0.0.1:5052".into(),
            config: config.clone(),
            devnet: "fixture-devnet".into(),
            source: "cl-1".into(),
            to: 1,
            out: tmp.path().join("out"),
            images: vec![IMAGE.into()],
            timeout: Duration::from_secs(1),
            state_timeout: Duration::from_secs(1),
            max_state_bytes: 1024,
        };
        let e = run_export(&base).unwrap_err();
        assert!(e.contains("--api") && e.contains("loopback"), "{e}");
        base.api = "http://127.0.0.1:5052".into();
        let e = run_export(&base).unwrap_err();
        assert!(e.contains("config.yaml"), "missing config: {e}");
        std::fs::write(&config, "PRESET_BASE: 'minimal'\n").unwrap();
        let e = run_export(&base).unwrap_err();
        assert!(e.contains("missing"), "{e}");
        std::fs::write(&config, CONFIG.replace("'minimal'", "'gnosis'")).unwrap();
        let e = run_export(&base).unwrap_err();
        assert!(e.contains("unknown PRESET_BASE"), "{e}");
        std::fs::write(&config, vec![b'#'; MAX_CONFIG_BYTES as usize + 1]).unwrap();
        let e = run_export(&base).unwrap_err();
        assert!(e.contains("over"), "{e}");
        // A mainnet config reaches the API: a node that hangs up on every connection.
        let node = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        base.api = format!("http://{}", node.local_addr().unwrap());
        let hang_up = std::thread::spawn(move || drop(node.accept()));
        std::fs::write(&config, CONFIG.replace("'minimal'", "'mainnet'")).unwrap();
        let e = run_export(&base).unwrap_err();
        assert!(e.contains(FINALIZED_HEADER_PATH), "{e}");
        hang_up.join().unwrap();
    }
}
