# svc-runtime

The bootstrap every ETH Swarm service process runs: config and method ACL, the service socket,
JSON tracing through a bounded stderr writer, loopback `/metrics`, `sd_notify` and the SIGTERM
drain. The crate docs (`src/lib.rs`) describe each module.

## Logging when the writer cannot start

`telemetry::try_init_tracing_with` starts one `log-writer` thread that owns stderr. The first
call settles the process's logging. If that thread cannot start:

- no subscriber is installed, so nothing is logged;
- the panic hook drops each panic's message (counted in `ethswarm_log_lines_dropped_total`)
  instead of writing it to stderr, so no thread ever blocks on a stalled stderr. If another
  subscriber is already the global default, its owner's panic hook is left in place;
- `run` returns `RuntimeError::LogWriter` before binding anything, and `exit_code` makes it
  `EXIT_NO_LOG_WRITER` (71, `EX_OSERR`);
- the binaries (`cl-p2p`, `cl-discv5`, `m2a-session`, `devnet-probe`) call
  `init_binary_tracing` and exit 71 at once.

Nothing is written to stderr on this path, because stderr may be the reason the thread could
not start. An owner that would rather run without logs calls `try_init_tracing` itself first
and carries on past `TracingInitError::WriterUnavailable`. Later calls, `run`'s included, then
find logging settled and go on.

Calls are serialized, and the first one holds the others until its panic hook is installed.
So a call that finds logging settled, from any thread, returns only after the bounded hook is
in place.

## What `m2a-session` links through this crate

cl-p2p and cl-discv5 depend on svc-runtime as a normal dependency for the bounded log writer
and telemetry only. So the `m2a-session` binary links the whole service bootstrap, although it
uses none of the socket, ACL, `/metrics`, `sd_notify` or drain code. Measured with
`cargo tree -p cl-p2p -e normal --target all`, with and without `--prune svc-runtime`, and with
`cargo metadata` for the requested features:

- **Crates that only svc-runtime brings into cl-p2p's graph:** `svc-runtime` itself,
  `prost-types`, and `rand` 0.8 with `rand_chacha` 0.3, `rand_core` 0.6, `ppv-lite86` and
  `zerocopy`/`zerocopy-derive`. `rand` makes the random trace ids, and `prost-types` reads the
  descriptor set for the ACL check. Everything else it uses (`ipc`, `ethswarm-proto`, `tonic`,
  `axum`, `hyper`, `hyper-util`, `tower`, `tokio-stream`, `prometheus-client`, `toml`,
  `network-config`, `serde`, `thiserror`) is already in the graph through cl-p2p's own
  dependencies.
- **Features that only svc-runtime turns on:** tokio `rt-multi-thread` (`run`'s runtime) and
  `signal` (SIGTERM/SIGINT), and tracing-subscriber `json` (the JSON log lines). No other crate
  in cl-p2p's normal graph asks for these.

`scripts/check-m2a-deps.sh` still passes: none of these is discv5 or a store crate. If the
M2-α audit wants a minimal surface, a small crate holding `log_writer` and `telemetry`'s
tracing init and panic hooks, used by cl-p2p and cl-discv5, would drop the crates above,
`rt-multi-thread` and `signal`. `json` would stay, because the log lines are JSON.
