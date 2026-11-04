//! `cl-api` binary. It takes no argument and reads `/etc/ethswarm/cl-api.toml`. It serves the
//! Beacon API on HTTP (127.0.0.1:5052 by default) and `ethswarm.api.v1` on its socket. See
//! [`cl_api::service`] for the config.
//!
//! Logs are svc-runtime's JSON lines on stderr through its bounded writer. If that writer cannot
//! start, the binary exits at once with `EXIT_NO_LOG_WRITER` (71) and writes nothing.

fn main() -> std::process::ExitCode {
    cl_api::service::main()
}
