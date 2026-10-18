//! `anchor-fetch`: fetch a checkpoint anchor that two providers agree on, or only check it.
//!
//! ```text
//! anchor-fetch [--config anchor-fetch.toml] [--out DIR] [--quiet]
//! anchor-fetch --check (--providers A,B [--allow-insecure-http] | --config FILE)
//!              [--scratch DIR] [--quiet]
//! anchor-fetch check-log RUN_LOG
//! anchor-fetch --help
//! ```
//!
//! The first form runs [`cl_sync::checkpoint::fetch::run`] with the mainnet preset (Sepolia,
//! Hoodi and mainnet all use it): on success `DIR/anchor.json` (printed to stdout),
//! `DIR/block.ssz` and `DIR/state.ssz` exist; on any abort the error's name and message go to
//! stderr, no `anchor.json` is written, and the exit code is non-zero (1 check failed, 2
//! config or output refused, 3 provider unreachable, 4 local I/O). Every run appends to
//! `DIR/run.log`, echoed to stderr unless `--quiet`. A run locks `DIR`: a second run into it
//! exits 2 (`out_dir_busy`) at once, and an existing anchor, block or state is never replaced.
//! `DIR` (created 0700 if missing) and `DIR/quarantine` must not be symlinks, must be owned by
//! the effective uid and not writable by group or other, or the run exits 2 (`unsafe_path`).
//! Provider URLs appear only as `scheme://host:port` (plus `/…` for a base path).
//!
//! `--check` runs [`cl_sync::checkpoint::fetch::check`]: every check of a fetch, and nothing
//! written (no `--out`, no anchor, block, state or run log; the bodies are held in a private
//! directory under `--scratch`, removed before exit, also on SIGTERM/SIGINT, which exit
//! 143/130). It exits 0 only if both providers report the same finalized checkpoint, agree on
//! its block root and header, the block from A hashes to that root, its `state_root` is the
//! headers', and the state from B hashes to that state root; otherwise with the codes above.
//! The providers come from `--providers A,B` (two URLs) or from `--config`; one host, one
//! domain or one resolved address behind both exits 2. The run log goes to stderr only
//! (unless `--quiet`), naming both providers by origin. A probe unit runs it as
//! `ExecStartPre=`, so the probe starts only on a two-provider match. `--help` is honoured
//! only as the whole command line: next to other arguments it is a usage error (64), so a
//! hostile `--providers` value cannot turn the gate into a help page that exits 0.
//!
//! `anchor.json` is written last and is the commit marker: a killed run can leave
//! `block.ssz` or `state.ssz` without it. Consumers must ignore `block.ssz` and `state.ssz`
//! unless an `anchor.json` next to them names their sha256 values and they match. If a failed
//! publish cannot be rolled back (`publish_rollback_incomplete`, exit 4), stderr and the run
//! log's `abort` line list the files left behind: delete them by hand.
//!
//! `check-log` exits 0 only if the last run in `RUN_LOG` names both providers (name, operator,
//! URL), and 1 otherwise. Usage errors exit 64. The command line is
//! [`cl_sync::checkpoint::cli`].

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(cl_sync::checkpoint::cli::main(&args))
}
