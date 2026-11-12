//! Finite slot-aligned head sampling and offline run-wide computation.
use std::{collections::BTreeMap, path::PathBuf, process::ExitCode, time::Duration};
use testkit::collector::{Clock, ReferenceApiUrl, SystemClock, TokioPause};
use testkit::head_lag::{analyze_jsonl, run_live, RunConfig, SlotSchedule, Summary, MAX_SAMPLES};
use testkit::root_diff::{QuerySource, Reference};
use tokio::io::AsyncWriteExt;

const HELP: &str = "\
usage: head-lag report --window 24h --samples JSONL --seconds-per-slot N
         --slots-per-epoch N [--end-slot N]
       head-lag rules
       head-lag analyze --samples JSONL --slots-per-epoch N
       head-lag run --socket PATH --server-uid UID --reference-url-file FILE
         --genesis-time UNIX_SECONDS --seconds-per-slot N --slots-per-epoch N
         --slots N --out NEW_FILE [--first-slot N] [--offset-ms 4000] [--timeout-secs 6]
         [--alerts-out NEW_FILE] [--metrics-out NEW_FILE]

Samples reference-minus-ours head slot lag every slot, normally +4 seconds into the slot.
Run writes shared JSONL and prints run-wide JSON statistics. Analyze recomputes from JSONL.
Nearest-rank p99 <=2, worst <=32, recovery <=one epoch. Gaps never become zero lag.
Reference URL files use the collector's owner/mode/loopback restrictions (use tunnels).
Run emits rising-edge alert JSONL immediately (stderr unless --alerts-out is set).
Metrics use atomic prometheus-client textfile snapshots; rules gate their freshness.
Report emits 24h Markdown; missing coverage/open recovery cannot qualify as PASS.
All run output paths must be new; existing logs are never overwritten.
Exit codes: 0 within thresholds, 1 computed breach, 2 gaps/runtime failure, 64 usage, 130 interrupted.";

enum Args {
    Report {
        samples: PathBuf,
        sps: u64,
        spe: u64,
        end: Option<u64>,
    },
    Rules,
    Analyze {
        samples: PathBuf,
        spe: u64,
    },
    Run {
        socket: PathBuf,
        uid: u32,
        url: PathBuf,
        schedule: SlotSchedule,
        first: Option<u64>,
        slots: u64,
        spe: u64,
        out: PathBuf,
        timeout: Duration,
        alerts: Option<PathBuf>,
        metrics: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|value| value == "--help" || value == "-h") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    let args = match parse(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("head-lag: {error}\n{HELP}");
            return ExitCode::from(64);
        }
    };
    match execute(args).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("head-lag: {error}");
            ExitCode::from(2)
        }
    }
}

fn parse(args: Vec<String>) -> Result<Args, String> {
    let mut args = args.into_iter();
    let mode = args.next().ok_or("missing command")?;
    if mode == "rules" {
        return if args.next().is_none() {
            Ok(Args::Rules)
        } else {
            Err("unexpected rules argument".into())
        };
    }
    let allowed: &[&str] = match mode.as_str() {
        "report" => &[
            "--window",
            "--samples",
            "--seconds-per-slot",
            "--slots-per-epoch",
            "--end-slot",
        ],
        "analyze" => &["--samples", "--slots-per-epoch"],
        "run" => &[
            "--socket",
            "--server-uid",
            "--reference-url-file",
            "--genesis-time",
            "--seconds-per-slot",
            "--slots-per-epoch",
            "--slots",
            "--out",
            "--first-slot",
            "--offset-ms",
            "--timeout-secs",
            "--alerts-out",
            "--metrics-out",
        ],
        _ => return Err("unknown command".into()),
    };
    let mut values = BTreeMap::new();
    while let Some(flag) = args.next() {
        if !allowed.contains(&flag.as_str()) {
            return Err("unknown option".into());
        }
        let value = args
            .next()
            .filter(|value| !value.starts_with("--"))
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
    let optional = |name: &str| {
        values
            .get(name)
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|_| format!("invalid {name}"))
    };
    let spe = number("--slots-per-epoch")?;
    if spe == 0 {
        return Err("zero epoch length".into());
    }
    if mode == "report" {
        let sps = number("--seconds-per-slot")?;
        if required("--window")? != "24h" || sps == 0 || 86400 % sps != 0 {
            return Err("report requires a whole-slot 24h window".into());
        }
        return Ok(Args::Report {
            samples: required("--samples")?.into(),
            sps,
            spe,
            end: optional("--end-slot")?,
        });
    }
    if mode == "analyze" {
        return Ok(Args::Analyze {
            samples: required("--samples")?.into(),
            spe,
        });
    }
    let schedule = SlotSchedule::new(
        number("--genesis-time")?,
        number("--seconds-per-slot")?,
        Duration::from_millis(optional("--offset-ms")?.unwrap_or(4000)),
    )
    .map_err(|error| error.to_string())?;
    let slots = number("--slots")?;
    if !(1..=MAX_SAMPLES).contains(&slots) {
        return Err("invalid run length".into());
    }
    let timeout = optional("--timeout-secs")?.unwrap_or(6);
    if !(1..=60).contains(&timeout) {
        return Err("timeout must be between one and sixty seconds".into());
    }
    Ok(Args::Run {
        socket: required("--socket")?.into(),
        uid: number("--server-uid")?
            .try_into()
            .map_err(|_| "invalid server UID")?,
        url: required("--reference-url-file")?.into(),
        schedule,
        first: optional("--first-slot")?,
        slots,
        spe,
        out: required("--out")?.into(),
        timeout: Duration::from_secs(timeout),
        alerts: values.get("--alerts-out").map(PathBuf::from),
        metrics: values.get("--metrics-out").map(PathBuf::from),
    })
}

async fn print_summary(summary: Summary) -> Result<u8, String> {
    let mut bytes = serde_json::to_vec(&summary).map_err(|_| "summary encoding failed")?;
    bytes.push(b'\n');
    let mut stdout = tokio::io::stdout();
    stdout
        .write_all(&bytes)
        .await
        .map_err(|_| "summary write failed")?;
    stdout.flush().await.map_err(|_| "summary flush failed")?;
    Ok(summary.exit_code())
}

async fn execute(args: Args) -> Result<u8, String> {
    match args {
        Args::Rules => {
            let mut stdout = tokio::io::stdout();
            stdout
                .write_all(testkit::head_lag::ALERT_RULES.as_bytes())
                .await
                .map_err(|_| "rules write failed")?;
            stdout.flush().await.map_err(|_| "rules flush failed")?;
            Ok(0)
        }
        Args::Report {
            samples,
            sps,
            spe,
            end,
        } => {
            let input = tokio::fs::File::open(samples)
                .await
                .map_err(|_| "cannot open samples")?;
            let report = testkit::head_lag::report_jsonl(input, sps, spe, end)
                .await
                .map_err(|error| error.to_string())?;
            let mut stdout = tokio::io::stdout();
            stdout
                .write_all(report.markdown().as_bytes())
                .await
                .map_err(|_| "report write failed")?;
            stdout.flush().await.map_err(|_| "report flush failed")?;
            Ok(report.exit_code())
        }
        Args::Analyze { samples, spe } => {
            let input = tokio::fs::File::open(samples)
                .await
                .map_err(|_| "cannot open samples")?;
            let summary = analyze_jsonl(input, spe)
                .await
                .map_err(|error| error.to_string())?;
            print_summary(summary).await
        }
        Args::Run {
            socket,
            uid,
            url,
            schedule,
            first,
            slots,
            spe,
            out,
            timeout,
            alerts,
            metrics,
        } => {
            let url = tokio::task::spawn_blocking(move || ReferenceApiUrl::read_file(&url))
                .await
                .map_err(|_| "URL file reader failed")?
                .map_err(|_| "invalid reference URL file")?;
            let ours = QuerySource::new(socket, uid, timeout);
            let reference = Reference::new(url, timeout);
            let clock = SystemClock::new();
            let first_slot = first
                .map(Ok)
                .unwrap_or_else(|| schedule.next_slot(Duration::from_nanos(clock.now().wall_ns)))
                .map_err(|error| error.to_string())?;
            let mut output = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(out)
                .await
                .map_err(|_| "cannot create new run log")?;
            let mut alert_output: Box<dyn tokio::io::AsyncWrite + Unpin> =
                if let Some(path) = alerts {
                    Box::new(
                        tokio::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(path)
                            .await
                            .map_err(|_| "cannot create new alert log")?,
                    )
                } else {
                    Box::new(tokio::io::stderr())
                };
            if let Some(path) = &metrics {
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .await
                    .map_err(|_| "cannot create new metrics file")?;
            }
            tokio::select! {
                result = run_live(RunConfig {schedule,first_slot,slots,slots_per_epoch:spe},&ours,&reference,&clock,&TokioPause,(&mut output,&mut alert_output,metrics.as_deref())) => print_summary(result.map_err(|error|error.to_string())?).await,
                interrupted = tokio::signal::ctrl_c() => {interrupted.map_err(|_|"interrupt handler failed")?;Ok(130)}
            }
        }
    }
}
