//! The command line: `cl-node units ...` and `cl-node launch --foreground ...` ([`USAGE`]).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::units::{Config, Unit, CREDENTIALS_DIR, DEFAULT_BIN_DIR, DEFAULT_NETWORK};

pub const USAGE: &str = "\
usage: cl-node units --out <dir> [--network <name>] [--supernode] [--bin-dir <dir>]
       cl-node launch --foreground --network <name> [--bin-dir <dir>] [--credentials-dir <dir>]
                      [--runtime-dir <dir>] [--ready-timeout <secs>] [--stop-grace <secs>]

  units   write the eight services' systemd units and ethswarm.target into <dir>
          --network   names the network in Description= (default mainnet)
          --supernode cl-p2p's supernode memory profile (MemoryHigh=1G, MemoryMax=1536M)
          --bin-dir   where ExecStart= finds cl-<svc> (default /usr/local/bin)
  launch  run the eight services as children, in start order, each ready before the next
          (containers; crates/cl-node/README.md)
          --credentials-dir  the jwt and nodekey sources (default /etc/ethswarm/credentials)
          --runtime-dir      the services' runtime directories (default /run/ethswarm)
          --ready-timeout    seconds for each READY=1 (default 90, the units' TimeoutStartSec=)
          --stop-grace       seconds from SIGTERM to SIGKILL (default 30, TimeoutStopSec=)

Exit status: 0 done (launch: stopped by SIGTERM or SIGINT), 1 a failure, 2 a usage error.";

/// The runtime directory unless `--runtime-dir` says otherwise (ipc's socket root).
pub const DEFAULT_RUNTIME_DIR: &str = "/run/ethswarm";

/// What `cl-node launch --foreground` runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// The network and `--bin-dir`, checked as for the units.
    pub config: Config,
    pub credentials_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub ready_timeout: Duration,
    pub stop_grace: Duration,
}

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    Units { out: PathBuf, config: Config },
    Launch(Launch),
}

/// The flags that take a value, by command.
const UNITS_FLAGS: [&str; 3] = ["--out", "--network", "--bin-dir"];
const LAUNCH_FLAGS: [&str; 6] = [
    "--network",
    "--bin-dir",
    "--credentials-dir",
    "--runtime-dir",
    "--ready-timeout",
    "--stop-grace",
];

/// Parses the arguments after the program name. The message is printed with [`USAGE`].
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut args = args.into_iter();
    let sub = args.next().ok_or("no command")?;
    let (launch, flags, switch) = match sub.to_str() {
        Some("-h" | "--help") => return Ok(Command::Help),
        Some("units") => (false, &UNITS_FLAGS[..], "--supernode"),
        Some("launch") => (true, &LAUNCH_FLAGS[..], "--foreground"),
        _ => return Err(format!("unknown command {sub:?}")),
    };
    let (mut values, mut switched) = (BTreeMap::new(), false);
    while let Some(flag) = args.next() {
        match flag.to_str() {
            Some("-h" | "--help") => return Ok(Command::Help),
            Some(s) if s == switch => switched = true,
            Some(f) if flags.contains(&f) => {
                let value = args.next().ok_or(format!("{f} needs a value"))?;
                values.insert(f.to_owned(), value);
            }
            _ => return Err(format!("unknown argument {flag:?}")),
        }
    }
    let mut take = |f: &str| values.remove(f);
    let network = match (take("--network"), launch) {
        (Some(n), _) => n,
        (None, false) => DEFAULT_NETWORK.into(),
        (None, true) => return Err("launch needs --network <name>".into()),
    };
    let network = network
        .to_str()
        .ok_or_else(|| format!("network {network:?} is not UTF-8"))?;
    let bin_dir = take("--bin-dir").unwrap_or_else(|| DEFAULT_BIN_DIR.into());
    let config = Config::new(network, switched && !launch, Path::new(&bin_dir))
        .map_err(|e| e.to_string())?;
    if !launch {
        let out = take("--out").ok_or("units needs --out <dir>")?;
        return Ok(Command::Units {
            out: out.into(),
            config,
        });
    }
    if !switched {
        return Err("launch needs --foreground (the only mode)".into());
    }
    let mut dir = |f: &str, default: &str| {
        let dir = PathBuf::from(take(f).unwrap_or_else(|| default.into()));
        if dir.is_absolute() {
            Ok(dir)
        } else {
            Err(format!("{f} {}: not an absolute path", dir.display()))
        }
    };
    let credentials_dir = dir("--credentials-dir", CREDENTIALS_DIR)?;
    let runtime_dir = dir("--runtime-dir", DEFAULT_RUNTIME_DIR)?;
    let mut secs = |f: &str, default: u64| {
        let value = take(f).map(|v| v.to_string_lossy().parse::<u64>());
        match value.unwrap_or(Ok(default)) {
            Ok(s @ 1..=86_400) => Ok(Duration::from_secs(s)),
            _ => Err(format!("{f}: want whole seconds, 1 to 86400")),
        }
    };
    Ok(Command::Launch(Launch {
        config,
        credentials_dir,
        runtime_dir,
        ready_timeout: secs("--ready-timeout", crate::units::START_TIMEOUT_SECS)?,
        stop_grace: secs("--stop-grace", crate::units::STOP_TIMEOUT_SECS)?,
    }))
}

/// Writes each unit into `dir` (created if missing) through a temporary file and a rename, so a
/// reader never sees half a unit. Refuses, before writing anything, if a unit's path holds
/// anything but a regular file (a symlink, a directory): a rename would replace it.
pub fn write_units(dir: &Path, units: &[Unit]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    for unit in units {
        let path = dir.join(&unit.name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if !meta.file_type().is_file() => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a regular file", path.display()),
                ));
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    for unit in units {
        let path = dir.join(&unit.name);
        let tmp = dir.join(format!(".{}.{}.tmp", unit.name, std::process::id()));
        let written = (|| {
            // create_new: never follows or reuses whatever is at the temporary name.
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(unit.text.as_bytes())?;
            // Unit files are not secret: 0644 like `install -m 0644`, whatever the umask.
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
            fs::rename(&tmp, &path)
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(io::Error::new(e.kind(), format!("{}: {e}", path.display())));
        }
    }
    fs::File::open(dir)?.sync_all()
}
