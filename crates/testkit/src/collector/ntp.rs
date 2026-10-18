//! The host clock's offset from NTP, sampled from its time daemon every [`NTP_INTERVAL`] and
//! logged, so a capture's wall-clock offsets can be judged against how far the clock was off.
//!
//! [`TimeDaemon`] is injectable: the collector asks chrony (`chronyc -n tracking`) or
//! systemd-timesyncd (`timedatectl timesync-status`), and tests use a scripted daemon. A failed
//! sample is recorded with its reason, never skipped.
//!
//! The recorded value is the clock error, local time minus NTP time: positive when the host
//! clock is ahead. chrony reports it as `System time : X seconds fast|slow of NTP time`;
//! timesyncd's `Offset:` is the correction (server minus local), so its sign is flipped.

use super::clock::{Clock, Stamp};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How often the collector samples the offset.
pub const NTP_INTERVAL: Duration = Duration::from_secs(60);

/// One sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtpSample {
    /// When it was taken, monotonic nanoseconds.
    pub mono_ns: u64,
    /// When it was taken, Unix nanoseconds.
    pub wall_ns: u64,
    /// The daemon asked (`chrony`, `timesyncd`).
    pub daemon: String,
    /// Local time minus NTP time, nanoseconds; `None` if the sample failed.
    pub clock_error_ns: Option<i64>,
    /// Why the sample failed.
    pub error: Option<String>,
}

/// A host time daemon that reports the clock error.
pub trait TimeDaemon: Send + Sync {
    /// Its name, for the record.
    fn name(&self) -> &str;
    /// Local time minus NTP time, nanoseconds.
    fn clock_error_ns(&self) -> Result<i64, String>;
}

/// Samples `daemon` now.
pub fn sample(clock: &dyn Clock, daemon: &dyn TimeDaemon) -> NtpSample {
    let Stamp { mono_ns, wall_ns } = clock.now();
    let result = daemon.clock_error_ns();
    NtpSample {
        mono_ns,
        wall_ns,
        daemon: daemon.name().to_owned(),
        clock_error_ns: result.as_ref().ok().copied(),
        error: result.err(),
    }
}

/// A daemon asked through its command-line client.
#[derive(Debug, Clone)]
pub struct CommandDaemon {
    name: &'static str,
    program: String,
    args: Vec<String>,
    parse: fn(&str) -> Result<i64, String>,
    timeout: Duration,
}

/// How long a daemon's client may take.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

impl CommandDaemon {
    /// chrony: `chronyc -n tracking`.
    pub fn chrony() -> Self {
        Self::new(
            "chrony",
            "chronyc",
            &["-n", "tracking"],
            parse_chrony_tracking,
        )
    }

    /// systemd-timesyncd: `timedatectl timesync-status`.
    pub fn timesyncd() -> Self {
        Self::new(
            "timesyncd",
            "timedatectl",
            &["timesync-status"],
            parse_timesyncd_status,
        )
    }

    /// A daemon asked with `program args…`, whose output `parse` reads.
    pub fn new(
        name: &'static str,
        program: &str,
        args: &[&str],
        parse: fn(&str) -> Result<i64, String>,
    ) -> Self {
        Self {
            name,
            program: program.to_owned(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            parse,
            timeout: COMMAND_TIMEOUT,
        }
    }

    /// This daemon with another client timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Runs the client (`LC_ALL=C`, no stdin) and returns its stdout; a spawn failure, a
    /// non-zero exit or no exit within the timeout is an error.
    fn output(&self) -> Result<String, String> {
        let program = &self.program;
        let mut child = Command::new(program)
            .args(&self.args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("{program}: {e}"))?;
        let mut stdout = child.stdout.take().expect("piped");
        let reader = std::thread::spawn(move || {
            let mut text = String::new();
            stdout.read_to_string(&mut text).map(|_| text)
        });
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{program}: no answer within {:?}", self.timeout));
                }
                Err(e) => return Err(format!("{program}: {e}")),
            }
        };
        let text = reader
            .join()
            .map_err(|_| format!("{program}: reading its output failed"))?
            .map_err(|e| format!("{program}: {e}"))?;
        if !status.success() {
            return Err(format!("{program}: {status}"));
        }
        Ok(text)
    }
}

impl TimeDaemon for CommandDaemon {
    fn name(&self) -> &str {
        self.name
    }

    fn clock_error_ns(&self) -> Result<i64, String> {
        (self.parse)(&self.output()?)
    }
}

/// `System time : 0.000012345 seconds fast of NTP time` (or `slow`) of `chronyc tracking`.
pub fn parse_chrony_tracking(text: &str) -> Result<i64, String> {
    let value = field(text, "System time")?;
    let bad = || {
        format!("chronyc: System time {value:?} is not \"<seconds> seconds fast|slow of NTP time\"")
    };
    let mut words = value.split_whitespace();
    let (
        Some(seconds),
        Some("seconds"),
        Some(direction),
        Some("of"),
        Some("NTP"),
        Some("time"),
        None,
    ) = (
        words.next(),
        words.next(),
        words.next(),
        words.next(),
        words.next(),
        words.next(),
        words.next(),
    )
    else {
        return Err(bad());
    };
    let ns = decimal_ns(seconds, NS_PER_S).ok_or_else(bad)?;
    match direction {
        "fast" => Ok(ns),
        "slow" => Ok(-ns),
        _ => Err(bad()),
    }
}

/// `Offset: -123us` of `timedatectl timesync-status`, sign flipped.
pub fn parse_timesyncd_status(text: &str) -> Result<i64, String> {
    let value = field(text, "Offset")?;
    let bad = || format!("timedatectl: Offset {value:?} is not a signed ns/us/ms/s span");
    let (negative, magnitude) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    if magnitude == "0" {
        return Ok(0);
    }
    let units: [(&str, u64); 5] = [
        ("ns", 1),
        ("us", 1_000),
        ("\u{b5}s", 1_000),
        ("ms", 1_000_000),
        ("s", NS_PER_S),
    ];
    let correction = units
        .iter()
        .find_map(|(unit, ns)| decimal_ns(magnitude.strip_suffix(unit)?, *ns))
        .ok_or_else(bad)?;
    // timesyncd's offset is server minus local: the clock error is its negation.
    Ok(if negative { correction } else { -correction })
}

const NS_PER_S: u64 = 1_000_000_000;

/// The value of the `name : value` line of `text`, trimmed.
fn field<'a>(text: &'a str, name: &str) -> Result<&'a str, String> {
    text.lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name).then(|| value.trim())
        })
        .ok_or_else(|| format!("no \"{name}\" line in the daemon's output"))
}

/// An unsigned decimal (`12`, `0.000012345`) of `unit_ns` nanoseconds each, in nanoseconds;
/// digits past a nanosecond are dropped. `None` if malformed or past `i64`.
fn decimal_ns(text: &str, unit_ns: u64) -> Option<i64> {
    let (int, frac) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if int.is_empty() || !digits(int) || !digits(frac) || (text.contains('.') && frac.is_empty()) {
        return None;
    }
    let mut ns = u128::from(int.parse::<u64>().ok()?).checked_mul(u128::from(unit_ns))?;
    let mut scale = u128::from(unit_ns);
    for d in frac.bytes() {
        scale /= 10;
        ns += u128::from(d - b'0') * scale;
    }
    i64::try_from(ns).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::clock::SystemClock;

    const CHRONY: &str = "\
Reference ID    : C0A80101 (192.168.1.1)
Stratum         : 3
Ref time (UTC)  : Sun Oct 18 08:00:00 2026
System time     : 0.000012345 seconds slow of NTP time
Last offset     : +0.000001234 seconds
RMS offset      : 0.000010000 seconds
Frequency       : 1.234 ppm slow
Leap status     : Normal
";

    const TIMESYNCD: &str = "\
       Server: 192.168.1.1 (ntp.example)
Poll interval: 34min 8s (min: 32s; max 34min 8s)
         Leap: normal
Root distance: 1.234ms (max: 5s)
       Offset: -1.5ms
        Delay: 1.234ms
";

    #[test]
    fn chrony_fast_is_ahead_and_slow_behind() {
        assert_eq!(parse_chrony_tracking(CHRONY), Ok(-12_345));
        let fast = CHRONY.replace("slow of", "fast of");
        assert_eq!(parse_chrony_tracking(&fast), Ok(12_345));
        let big = CHRONY.replace("0.000012345 seconds slow", "2.5 seconds fast");
        assert_eq!(parse_chrony_tracking(&big), Ok(2_500_000_000));
        for bad in [
            "",
            "System time     : 0.1 seconds sideways of NTP time\n",
            "System time     : x seconds fast of NTP time\n",
            "System time     : -0.1 seconds fast of NTP time\n",
            "System time     : 0.1 minutes fast of NTP time\n",
            "System time     : 1e30 seconds fast of NTP time\n",
        ] {
            assert!(parse_chrony_tracking(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn timesyncd_offset_is_the_correction() {
        // The server is 1.5 ms ahead of us: our clock is 1.5 ms behind.
        assert_eq!(parse_timesyncd_status(TIMESYNCD), Ok(1_500_000));
        for (offset, want) in [
            ("+123us", -123_000),
            ("-7ns", 7),
            ("+2s", -2_000_000_000),
            ("0", 0),
            ("+12µs", -12_000),
        ] {
            let text = TIMESYNCD.replace("-1.5ms", offset);
            assert_eq!(parse_timesyncd_status(&text), Ok(want), "{offset}");
        }
        for bad in ["1min 2s", "+ms", "+1.5h", "12"] {
            let text = TIMESYNCD.replace("-1.5ms", bad);
            assert!(parse_timesyncd_status(&text).is_err(), "{bad}");
        }
        assert!(parse_timesyncd_status("Server: x\n").is_err());
    }

    #[test]
    fn a_command_daemon_runs_its_client() {
        let echo = CommandDaemon::new(
            "chrony",
            "/bin/sh",
            &[
                "-c",
                "printf 'System time : 0.25 seconds fast of NTP time\\n'",
            ],
            parse_chrony_tracking,
        );
        assert_eq!(echo.name(), "chrony");
        assert_eq!(echo.clock_error_ns(), Ok(250_000_000));

        let failing = CommandDaemon::new("x", "/bin/sh", &["-c", "exit 3"], parse_chrony_tracking);
        let err = failing.clock_error_ns().unwrap_err();
        assert!(err.contains("exit"), "{err}");

        let missing = CommandDaemon::new("x", "/nonexistent/chronyc", &[], parse_chrony_tracking);
        assert!(missing
            .clock_error_ns()
            .unwrap_err()
            .contains("/nonexistent/chronyc"));

        let slow = CommandDaemon::new("x", "/bin/sh", &["-c", "sleep 10"], parse_chrony_tracking)
            .with_timeout(Duration::from_millis(100));
        let started = Instant::now();
        assert!(slow.clock_error_ns().unwrap_err().contains("no answer"));
        assert!(started.elapsed() < Duration::from_secs(5));

        assert_eq!(CommandDaemon::chrony().name(), "chrony");
        assert_eq!(CommandDaemon::timesyncd().name(), "timesyncd");
    }

    struct Scripted(Result<i64, String>);

    impl TimeDaemon for Scripted {
        fn name(&self) -> &str {
            "scripted"
        }
        fn clock_error_ns(&self) -> Result<i64, String> {
            self.0.clone()
        }
    }

    #[test]
    fn a_sample_records_the_value_or_the_failure() {
        let clock = SystemClock::new();
        let ok = sample(&clock, &Scripted(Ok(-5)));
        assert_eq!((ok.clock_error_ns, ok.error), (Some(-5), None));
        assert_eq!(ok.daemon, "scripted");
        let failed = sample(&clock, &Scripted(Err("daemon down".into())));
        assert_eq!(failed.clock_error_ns, None);
        assert_eq!(failed.error.as_deref(), Some("daemon down"));
        assert!(failed.wall_ns > 0);
    }
}
