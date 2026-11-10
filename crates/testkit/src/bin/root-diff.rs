//! Root-diff CLI: offline fixture checks, finite epoch-aligned runs, and the second-CL adapter.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use testkit::collector::{Clock, ReferenceApiUrl, SystemClock, TokioPause};
use testkit::root_diff::{
    compare, parse_finality, run, QuerySource, Reference, RunConfig, Schedule,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HELP: &str = "\
usage: root-diff check --ours JSON --reference JSON --epoch N
       root-diff run --socket PATH --server-uid UID --reference-url-file FILE
         --genesis-time UNIX_SECONDS --seconds-per-slot N --slots-per-epoch N
         --epochs N --out NEW_FILE [--first-epoch N] [--timeout-secs N]
       root-diff query-stub --runtime-root DIR --reference-url-file FILE [--timeout-secs N]

Compares finalized and current justified checkpoint epoch/root pairs. Run samples the fixed
state slot at each epoch boundary + one slot. JSONL gaps have match:null, never match:true.
The reference URL file uses the collector's owner/mode/loopback restrictions (use tunnels).
The query-stub serves GetStateSummary from a second CL; missing headers become gaps.
Head/payload-status comparison is a later slice. Output files must not already exist.
Exit codes: 0 all match, 1 any mismatch, 2 gaps/runtime failure, 64 usage, 130 interrupted.";

enum Args {
    Check {
        ours: PathBuf,
        reference: PathBuf,
        epoch: u64,
    },
    Run {
        socket: PathBuf,
        uid: u32,
        url: PathBuf,
        schedule: Schedule,
        first: Option<u64>,
        epochs: u64,
        out: PathBuf,
        timeout: Duration,
    },
    Stub {
        root: PathBuf,
        url: PathBuf,
        timeout: Duration,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    let args = match parse(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("root-diff: {error}\n{HELP}");
            return ExitCode::from(64);
        }
    };
    match execute(args).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("root-diff: {error}");
            ExitCode::from(2)
        }
    }
}

fn parse(args: Vec<String>) -> Result<Args, String> {
    let mut args = args.into_iter();
    let mode = args.next().ok_or("missing command")?;
    let allowed: &[&str] = match mode.as_str() {
        "check" => &["--ours", "--reference", "--epoch"],
        "run" => &[
            "--socket",
            "--server-uid",
            "--reference-url-file",
            "--genesis-time",
            "--seconds-per-slot",
            "--slots-per-epoch",
            "--epochs",
            "--out",
            "--first-epoch",
            "--timeout-secs",
        ],
        "query-stub" => &["--runtime-root", "--reference-url-file", "--timeout-secs"],
        _ => return Err("unknown command".into()),
    };
    let mut values = BTreeMap::new();
    while let Some(flag) = args.next() {
        if !allowed.contains(&flag.as_str()) {
            return Err("unknown option".into());
        }
        let value = args
            .next()
            .filter(|v| !v.starts_with("--"))
            .ok_or("missing option value")?;
        if values.insert(flag, value).is_some() {
            return Err("duplicate option".into());
        }
    }
    let required = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| format!("missing {name}"))
    };
    let number = |name: &str| {
        required(name)?
            .parse::<u64>()
            .map_err(|_| format!("invalid {name}"))
    };
    if mode == "check" {
        return Ok(Args::Check {
            ours: required("--ours")?.into(),
            reference: required("--reference")?.into(),
            epoch: number("--epoch")?,
        });
    }
    let timeout = values
        .get("--timeout-secs")
        .map(|s| s.parse::<u64>())
        .transpose()
        .map_err(|_| "invalid timeout")?
        .unwrap_or(6);
    if timeout == 0 {
        return Err("zero timeout".into());
    }
    let timeout = Duration::from_secs(timeout);
    let url = required("--reference-url-file")?.into();
    if mode == "query-stub" {
        return Ok(Args::Stub {
            root: required("--runtime-root")?.into(),
            url,
            timeout,
        });
    }
    let schedule = Schedule::new(
        number("--genesis-time")?,
        number("--seconds-per-slot")?,
        number("--slots-per-epoch")?,
    )
    .map_err(|e| e.to_string())?;
    let epochs = number("--epochs")?;
    if epochs == 0 {
        return Err("zero epochs".into());
    }
    let first = values
        .get("--first-epoch")
        .map(|s| s.parse())
        .transpose()
        .map_err(|_| "invalid first epoch")?;
    let uid = number("--server-uid")?
        .try_into()
        .map_err(|_| "invalid server UID")?;
    Ok(Args::Run {
        socket: required("--socket")?.into(),
        uid,
        url,
        schedule,
        first,
        epochs,
        out: required("--out")?.into(),
        timeout,
    })
}

async fn url_file(path: PathBuf) -> Result<ReferenceApiUrl, String> {
    tokio::task::spawn_blocking(move || ReferenceApiUrl::read_file(&path))
        .await
        .map_err(|_| "URL file reader failed")?
        .map_err(|_| "invalid reference URL file".into())
}

async fn fixture(path: PathBuf) -> Option<testkit::root_diff::Checkpoints> {
    let file = tokio::fs::File::open(path).await.ok()?;
    let mut bytes = Vec::new();
    file.take((testkit::collector::MAX_JSON_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .ok()?;
    if bytes.len() > testkit::collector::MAX_JSON_BYTES {
        return None;
    }
    parse_finality(&bytes).ok()
}

async fn execute(args: Args) -> Result<u8, String> {
    match args {
        Args::Check {
            ours,
            reference,
            epoch,
        } => {
            let (ours, reference) = tokio::join!(fixture(ours), fixture(reference));
            let record = compare(epoch, ours, reference);
            let code = if record.is_mismatch() {
                1
            } else if record.gap.is_some() {
                2
            } else {
                0
            };
            let mut line = serde_json::to_vec(&record).map_err(|_| "record encoding failed")?;
            line.push(b'\n');
            let mut stdout = tokio::io::stdout();
            stdout
                .write_all(&line)
                .await
                .map_err(|_| "record write failed")?;
            stdout.flush().await.map_err(|_| "record flush failed")?;
            Ok(code)
        }
        Args::Stub { root, url, timeout } => {
            let dir = ipc::uds::SocketDir::under(root, "query-stub")
                .map_err(|_| "invalid runtime directory")?;
            let server = testkit::query_stub::QueryStub::start(&dir, url_file(url).await?, timeout)
                .map_err(|_| "query stub bind failed")?;
            let interrupted = tokio::signal::ctrl_c().await;
            server
                .shutdown()
                .await
                .map_err(|_| "query stub shutdown failed")?;
            interrupted.map_err(|_| "interrupt handler failed")?;
            Ok(130)
        }
        Args::Run {
            socket,
            uid,
            url,
            schedule,
            first,
            epochs,
            out,
            timeout,
        } => {
            let reference = Reference::new(url_file(url).await?, timeout);
            let ours = QuerySource::new(socket, uid, timeout);
            let clock = SystemClock::new();
            let first_epoch = first
                .map(Ok)
                .unwrap_or_else(|| schedule.next_epoch(Duration::from_nanos(clock.now().wall_ns)))
                .map_err(|e| e.to_string())?;
            let mut output = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out)
                .await
                .map_err(|_| "cannot create new run log")?;
            tokio::select! {
                result = run(RunConfig { schedule, first_epoch, epochs }, &ours, &reference, &clock, &TokioPause, &mut output) => result.map(|report| report.exit_code()).map_err(|e|e.to_string()),
                interrupted = tokio::signal::ctrl_c() => { interrupted.map_err(|_|"interrupt handler failed")?; Ok(130) }
            }
        }
    }
}
