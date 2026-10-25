//! The `anchor-fetch` command line: [`main`] is the whole binary, so tests run exactly what
//! it runs and see its exit code.
//!
//! ```text
//! anchor-fetch [--config FILE] [--out DIR] [--quiet]
//! anchor-fetch --check (--providers A,B [--allow-insecure-http] | --config FILE)
//!              [--preset mainnet|minimal] [--scratch DIR] [--quiet]
//! anchor-fetch check-log RUN_LOG
//! anchor-fetch --help
//! ```
//!
//! The first form is [`fetch::run`]; `--check` is [`fetch::check`], which writes nothing and
//! is what a probe unit runs as `ExecStartPre=`. Both use the mainnet preset (Sepolia, Hoodi
//! and mainnet all use it). `--check --preset minimal` decodes with the minimal preset instead:
//! the Kurtosis devnet's (`testing/kurtosis`), whose probe units add it in a devnet-only
//! drop-in.

use crate::checkpoint::config::Config;
use crate::checkpoint::{fetch, runlog};
use consensus_types::{EthSpec, Mainnet, Minimal};
use std::future::Future;
use std::path::PathBuf;

/// Usage errors.
pub const EXIT_USAGE: u8 = 64;

const USAGE: &str = "\
usage: anchor-fetch [--config FILE] [--out DIR] [--quiet]
       anchor-fetch --check (--providers A,B [--allow-insecure-http] | --config FILE) [--preset mainnet|minimal] [--scratch DIR] [--quiet]
       anchor-fetch check-log RUN_LOG";

const HELP: &str = "\
Fetch a checkpoint anchor that two providers run by different operators agree on.

Options:
  --config FILE          provider config (default anchor-fetch.toml)
  --out DIR              output directory (default .; created 0700 if missing)
  --quiet                do not echo the run log to stderr
  --check                run every check, write nothing (no --out); exit 0 only if both
                         providers report the same finalized checkpoint and agree on the
                         block root, the header state_root and the state root
  --providers A,B        with --check: the two provider URLs instead of --config; one host,
                         one domain (same last two DNS labels) or one resolved address
                         behind both is refused
  --allow-insecure-http  with --providers: accept http:// URLs (local fixtures only)
  --preset P             with --check: decode by the preset P, mainnet (the default) or
                         minimal (a local devnet)
  --scratch DIR          with --check: where the bodies are held while they are checked, in a
                         new private directory removed before exit (default: $TMPDIR or /tmp)
  -h, --help             print this help

Output: DIR/block.ssz, DIR/state.ssz and DIR/anchor.json, each written only if every check
passes and never replacing an existing file; every run appends to DIR/run.log. A --check run
writes none of them: its run log goes to stderr only, the providers named by origin.

anchor.json is written last and is the commit marker: a killed run can leave block.ssz or
state.ssz without it. Consumers must ignore block.ssz and state.ssz unless an anchor.json next
to them names their sha256 values and they match.

DIR and DIR/quarantine must not be symlinks, must be owned by you and not writable by group or
other (else exit 2, unsafe_path). If a failed publish cannot be rolled back (exit 4,
publish_rollback_incomplete), the error and the run log's abort line list the files left
behind: delete them by hand.

Exit codes: 0 anchor written (or, with --check, agreed), 1 check failed, 2 config or output
refused, 3 provider unreachable, 4 local I/O, 64 usage (--help is honoured only alone),
130/143 a --check cancelled by SIGINT/SIGTERM (its scratch directory removed). check-log exits
0 only if the last run in RUN_LOG names both providers.";

/// Where `--check` takes its two providers from.
#[derive(Debug, PartialEq, Eq)]
enum Providers {
    /// `--providers A,B`.
    Urls {
        list: String,
        allow_insecure_http: bool,
    },
    /// `--config FILE`.
    Config(PathBuf),
}

/// The preset a check decodes the block and the state by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Preset {
    /// Sepolia, Hoodi and mainnet.
    #[default]
    Mainnet,
    /// A local devnet (Kurtosis).
    Minimal,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Fetch {
        config: PathBuf,
        out: PathBuf,
        echo: bool,
    },
    Check {
        providers: Providers,
        preset: Preset,
        scratch: PathBuf,
        echo: bool,
    },
    CheckLog(PathBuf),
}

/// The options as given, before the combinations are checked.
#[derive(Default)]
struct Flags {
    config: Option<PathBuf>,
    out: Option<PathBuf>,
    providers: Option<String>,
    scratch: Option<PathBuf>,
    preset: Option<Preset>,
    allow_insecure_http: bool,
    check: bool,
    quiet: bool,
}

/// Whether `arg` is a help flag.
fn is_help(arg: &str) -> bool {
    arg == "--help" || arg == "-h"
}

/// The value after an option, which must not itself look like an option: an empty or hostile
/// `--providers ${ANCHOR_PROVIDERS}` must not swallow `--check` or smuggle in `--help`.
fn value<'a>(it: &mut std::slice::Iter<'a, String>, what: &str) -> Result<&'a str, String> {
    match it.next() {
        Some(v) if !v.starts_with('-') => Ok(v),
        Some(v) => Err(format!("{what}, got the option {v:?}")),
        None => Err(what.to_owned()),
    }
}

/// Parses the arguments. Help is honoured only as the whole command line: anywhere else (an
/// option's value, next to `--check`) it is a usage error, so the start gate can never exit 0
/// on a help page.
fn parse(args: &[String]) -> Result<Command, String> {
    if let [only] = args {
        if is_help(only) {
            return Ok(Command::Help);
        }
    }
    if let Some(help) = args.iter().find(|a| is_help(a)) {
        return Err(format!("{help} goes alone, without other arguments"));
    }
    if args.first().map(String::as_str) == Some("check-log") {
        return match args {
            [_, path] => Ok(Command::CheckLog(path.into())),
            _ => Err("check-log takes exactly one RUN_LOG".into()),
        };
    }
    let mut f = Flags::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => f.config = Some(value(&mut it, "--config needs a FILE")?.into()),
            "--out" => f.out = Some(value(&mut it, "--out needs a DIR")?.into()),
            "--providers" => f.providers = Some(value(&mut it, "--providers needs A,B")?.into()),
            "--scratch" => f.scratch = Some(value(&mut it, "--scratch needs a DIR")?.into()),
            "--preset" => {
                f.preset = Some(match value(&mut it, "--preset needs mainnet or minimal")? {
                    "mainnet" => Preset::Mainnet,
                    "minimal" => Preset::Minimal,
                    other => return Err(format!("--preset {other:?}: want mainnet or minimal")),
                });
            }
            "--allow-insecure-http" => f.allow_insecure_http = true,
            "--check" => f.check = true,
            "--quiet" => f.quiet = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let echo = !f.quiet;
    if !f.check {
        for (given, flag) in [
            (f.providers.is_some(), "--providers"),
            (f.scratch.is_some(), "--scratch"),
            (f.preset.is_some(), "--preset"),
            (f.allow_insecure_http, "--allow-insecure-http"),
        ] {
            if given {
                return Err(format!("{flag} needs --check"));
            }
        }
        return Ok(Command::Fetch {
            config: f.config.unwrap_or_else(|| "anchor-fetch.toml".into()),
            out: f.out.unwrap_or_else(|| ".".into()),
            echo,
        });
    }
    if f.out.is_some() {
        return Err("--check writes nothing: --out is not allowed".into());
    }
    let providers = match (f.providers, f.config) {
        (Some(_), Some(_)) => return Err("--providers and --config exclude each other".into()),
        (None, None) => return Err("--check needs --providers A,B or --config FILE".into()),
        (Some(list), None) => Providers::Urls {
            list,
            allow_insecure_http: f.allow_insecure_http,
        },
        (None, Some(_)) if f.allow_insecure_http => return Err(
            "--allow-insecure-http goes with --providers; a config file sets allow_insecure_http"
                .into(),
        ),
        (None, Some(path)) => Providers::Config(path),
    };
    Ok(Command::Check {
        providers,
        preset: f.preset.unwrap_or_default(),
        scratch: f.scratch.unwrap_or_else(std::env::temp_dir),
        echo,
    })
}

/// Runs `anchor-fetch` with `args` (without the program name) and returns its exit code.
pub fn main(args: &[String]) -> u8 {
    main_with(args, &fetch::SystemResolver)
}

/// [`main`] with the provider host names resolved by `resolver`.
pub(crate) fn main_with(args: &[String], resolver: &dyn fetch::Resolve) -> u8 {
    let command = match parse(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("anchor-fetch: {e}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    match command {
        Command::Help => {
            println!("{USAGE}\n       anchor-fetch --help\n\n{HELP}");
            0
        }
        Command::CheckLog(path) => match runlog::verify_file(&path) {
            Ok(()) => {
                eprintln!("anchor-fetch: {} names both providers", path.display());
                0
            }
            Err(e) => {
                eprintln!("anchor-fetch: {}: {e}", path.display());
                1
            }
        },
        Command::Fetch { config, out, echo } => {
            let run = fetch::run_with::<Mainnet>(&config, &out, echo, &fetch::RealFs, resolver);
            match block_on(run) {
                Ok(Ok(anchor)) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&anchor).unwrap_or_default()
                    );
                    eprintln!(
                        "anchor-fetch: anchor {} at slot {} written to {}",
                        anchor.block_root,
                        anchor.slot,
                        out.join(fetch::ANCHOR_FILE).display()
                    );
                    0
                }
                Ok(Err(e)) => aborted(&e),
                Err(code) => code,
            }
        }
        Command::Check {
            providers,
            preset,
            scratch,
            echo,
        } => {
            let config = match providers {
                Providers::Urls {
                    list,
                    allow_insecure_http,
                } => Config::from_provider_urls(&list, allow_insecure_http),
                Providers::Config(path) => Config::load(&path),
            };
            let config = match config {
                Ok(c) => c,
                Err(e) => return aborted(&e),
            };
            match preset {
                Preset::Mainnet => check::<Mainnet>(&config, &scratch, echo, resolver),
                Preset::Minimal => check::<Minimal>(&config, &scratch, echo, resolver),
            }
        }
    }
}

/// The `--check` of `config` by the preset `E`; the exit code.
fn check<E: EthSpec>(
    config: &Config,
    scratch: &std::path::Path,
    echo: bool,
    resolver: &dyn fetch::Resolve,
) -> u8 {
    let log = runlog::RunLog::in_memory(echo);
    let check = fetch::check_logged::<E>(config, scratch, log, resolver);
    match block_on(until_signalled(async { check.await.0 })) {
        Err(code) => code,
        Ok(Err(Interrupted::Signal(name, code))) => {
            eprintln!("anchor-fetch: interrupted by {name}; the check was cancelled and its scratch directory removed");
            code
        }
        Ok(Err(Interrupted::Setup(e))) => {
            eprintln!("anchor-fetch: signal handlers: {e}");
            4
        }
        Ok(Ok(result)) => match result {
            Ok(agreement) => {
                println!("{}", serde_json::to_string(&agreement).unwrap_or_default());
                let [a, b] = [&agreement.providers[0], &agreement.providers[1]];
                eprintln!(
                    "anchor-fetch: check passed: {} ({}) and {} ({}) agree on block {} and \
                     state root {} at slot {}",
                    a.name,
                    a.url,
                    b.name,
                    b.url,
                    agreement.block_root,
                    agreement.state_root,
                    agreement.slot
                );
                0
            }
            Err(e) => aborted(&e),
        },
    }
}

/// Why a check stopped before it finished.
enum Interrupted {
    /// SIGTERM or SIGINT: its name and the exit code (128 + the signal number).
    Signal(&'static str, u8),
    /// The handlers could not be installed.
    Setup(std::io::Error),
}

/// Runs `future` until it finishes or SIGTERM/SIGINT arrives. On a signal the future is
/// dropped, which cancels the check and removes its scratch directory.
async fn until_signalled<F: Future>(future: F) -> Result<F::Output, Interrupted> {
    use tokio::signal::unix::{signal, SignalKind};
    let (mut term, mut int) = match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(term), Ok(int)) => (term, int),
        (Err(e), _) | (_, Err(e)) => return Err(Interrupted::Setup(e)),
    };
    tokio::select! {
        output = future => Ok(output),
        _ = term.recv() => Err(Interrupted::Signal("SIGTERM", 143)),
        _ = int.recv() => Err(Interrupted::Signal("SIGINT", 130)),
    }
}

/// Prints an abort and returns its exit code.
fn aborted(e: &fetch::AnchorError) -> u8 {
    eprintln!("anchor-fetch: aborted: {}: {e}", e.name());
    e.exit_code()
}

/// Runs `future` on a new multi-threaded runtime; `Err(4)` if the runtime cannot be built.
fn block_on<F: Future>(future: F) -> Result<F::Output, u8> {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => Ok(runtime.block_on(future)),
        Err(e) => {
            eprintln!("anchor-fetch: tokio runtime: {e}");
            Err(4)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn parses_a_check_with_providers() {
        let c = parse(&args(&[
            "--check",
            "--providers",
            "https://a,https://b",
            "--scratch",
            "/s",
            "--quiet",
        ]))
        .unwrap();
        assert_eq!(
            c,
            Command::Check {
                providers: Providers::Urls {
                    list: "https://a,https://b".into(),
                    allow_insecure_http: false
                },
                preset: Preset::Mainnet,
                scratch: "/s".into(),
                echo: false,
            }
        );
        let c = parse(&args(&["--config", "f.toml", "--check"])).unwrap();
        assert_eq!(
            c,
            Command::Check {
                providers: Providers::Config("f.toml".into()),
                preset: Preset::Mainnet,
                scratch: std::env::temp_dir(),
                echo: true,
            }
        );
        let c = parse(&args(&[
            "--config", "f.toml", "--check", "--preset", "minimal",
        ]))
        .unwrap();
        assert!(matches!(
            c,
            Command::Check {
                preset: Preset::Minimal,
                ..
            }
        ));
    }

    #[test]
    fn parses_a_fetch_with_its_defaults() {
        assert_eq!(
            parse(&[]).unwrap(),
            Command::Fetch {
                config: "anchor-fetch.toml".into(),
                out: ".".into(),
                echo: true
            }
        );
    }

    #[test]
    fn refuses_check_options_out_of_place() {
        for list in [
            &["--providers", "https://a,https://b"][..],
            &["--scratch", "/s"],
            &["--allow-insecure-http"],
            &["--check"],
            &[
                "--check",
                "--out",
                "d",
                "--providers",
                "https://a,https://b",
            ],
            &["--check", "--providers", "x", "--config", "f"],
            &["--check", "--config", "f", "--allow-insecure-http"],
            &["--check", "--providers"],
            &["--check", "--scratch"],
            &["--preset", "minimal"],
            &["--check", "--config", "f", "--preset"],
            &["--check", "--config", "f", "--preset", "--quiet"],
            &["--check", "--config", "f", "--preset", "gnosis"],
            &["--out"],
        ] {
            assert!(parse(&args(list)).is_err(), "{list:?}");
            assert_eq!(main(&args(list)), EXIT_USAGE, "{list:?}");
        }
    }

    #[test]
    fn help_is_only_ever_the_whole_command_line() {
        for alone in ["--help", "-h"] {
            assert_eq!(parse(&args(&[alone])).unwrap(), Command::Help);
            assert_eq!(main(&args(&[alone])), 0);
        }
        // An empty or hostile ANCHOR_PROVIDERS must never turn the start gate into a help
        // page that exits 0.
        for list in [
            &["--providers", "--help", "--check"][..],
            &["--providers", "-h", "--check"],
            &["--check", "--providers", "--help"],
            &["--check", "--help"],
            &["-h", "--check"],
            &["--check", "--providers", "https://a,https://b", "--help"],
            &["--help", "--help"],
            &["--config", "--help"],
            &[
                "--scratch",
                "-h",
                "--check",
                "--providers",
                "https://a,https://b",
            ],
            &["check-log", "--help"],
            &["--out", "--check"],
        ] {
            assert!(parse(&args(list)).is_err(), "{list:?}");
            assert_eq!(main(&args(list)), EXIT_USAGE, "{list:?}");
        }
    }

    #[test]
    fn a_refused_provider_list_exits_2_before_any_request() {
        for list in [
            "https://a.invalid",
            "https://a.invalid,https://a.invalid/other",
        ] {
            let code = main(&args(&["--check", "--providers", list, "--quiet"]));
            assert_eq!(code, 2, "{list}");
        }
    }

    #[test]
    fn a_missing_check_config_is_a_local_io_error() {
        let code = main(&args(&[
            "--check",
            "--config",
            "/nonexistent/anchor-fetch.toml",
        ]));
        assert_eq!(code, 4);
    }
}
