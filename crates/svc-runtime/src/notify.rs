//! systemd service notification (`sd_notify(3)`) without libsystemd.
//!
//! The service manager passes a datagram socket in `$NOTIFY_SOCKET`: an absolute path, or
//! `@name` for a Linux abstract socket. With the variable unset or empty no manager is
//! listening and nothing is sent.

use std::ffi::OsStr;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

/// The environment variable systemd sets for `Type=notify` services.
pub const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";
/// Startup is complete: the socket is bound with its final owner and mode.
pub const READY: &str = "READY=1";
/// Shutdown has begun: no new calls are accepted.
pub const STOPPING: &str = "STOPPING=1";

/// Where lifecycle state changes are reported.
pub trait Notifier: Send + Sync {
    /// Sends `state` (newline-separated `KEY=value` assignments).
    fn notify(&self, state: &str) -> io::Result<()>;
}

/// `$NOTIFY_SOCKET` of this process, read at each notification.
#[derive(Clone, Copy, Debug, Default)]
pub struct Systemd;

impl Notifier for Systemd {
    fn notify(&self, state: &str) -> io::Result<()> {
        notify(std::env::var_os(NOTIFY_SOCKET).as_deref(), state).map(drop)
    }
}

/// Sends `state` to the manager socket `socket` (the value of `$NOTIFY_SOCKET`) without
/// blocking. `Ok(false)` if there is no socket to notify.
pub fn notify(socket: Option<&OsStr>, state: &str) -> io::Result<bool> {
    let Some(socket) = socket.filter(|s| !s.is_empty()) else {
        return Ok(false);
    };
    let sock = UnixDatagram::unbound()?;
    // Never wait on the manager: with its queue full this fails (`WouldBlock`) and the caller
    // logs it, instead of stalling startup or shutdown.
    sock.set_nonblocking(true)?;
    let bytes = socket.as_encoded_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        send_abstract(&sock, name, state)?;
    } else if bytes.starts_with(b"/") {
        sock.send_to(state.as_bytes(), Path::new(socket))?;
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{NOTIFY_SOCKET} is neither an absolute path nor @abstract: {socket:?}"),
        ));
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn send_abstract(sock: &UnixDatagram, name: &[u8], state: &str) -> io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
    sock.send_to_addr(state.as_bytes(), &addr).map(drop)
}

#[cfg(not(target_os = "linux"))]
fn send_abstract(_: &UnixDatagram, _: &[u8], _: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "abstract notify sockets exist only on Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn recv(sock: &UnixDatagram) -> String {
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 256];
        let n = sock.recv(&mut buf).unwrap();
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    /// A manager that stops reading must not stall the service: once its queue is full a
    /// notification fails at once (`WouldBlock`, or `ENOBUFS` on macOS) instead of blocking.
    #[test]
    fn full_manager_queue_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let manager = UnixDatagram::bind(&path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for sent in 0..1_000_000u32 {
                if let Err(e) = notify(Some(path.as_os_str()), READY) {
                    let _ = tx.send(Some((sent, e.kind())));
                    return;
                }
            }
            let _ = tx.send(None);
        });
        let (sent, kind) = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("notify blocked on a full manager queue")
            .expect("the queue never filled");
        assert!(sent > 0, "the first notifications went through");
        assert_ne!(kind, io::ErrorKind::InvalidInput);
        drop(manager);
    }

    #[test]
    fn unset_or_empty_socket_sends_nothing() {
        assert!(!notify(None, READY).unwrap());
        assert!(!notify(Some(OsStr::new("")), READY).unwrap());
    }

    #[test]
    fn states_reach_a_path_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let manager = UnixDatagram::bind(&path).unwrap();
        assert!(notify(Some(path.as_os_str()), READY).unwrap());
        assert_eq!(recv(&manager), "READY=1");
        assert!(notify(Some(path.as_os_str()), STOPPING).unwrap());
        assert_eq!(recv(&manager), "STOPPING=1");
    }

    #[test]
    fn relative_or_missing_sockets_are_errors() {
        let err = notify(Some(OsStr::new("notify.sock")), READY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent.sock");
        assert!(notify(Some(absent.as_os_str()), READY).is_err());
    }

    #[test]
    fn systemd_notifier_without_a_manager_is_a_no_op() {
        // The test runner is not started by systemd with Type=notify.
        if std::env::var_os(NOTIFY_SOCKET).is_none() {
            Systemd.notify(READY).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn states_reach_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("svc-runtime-notify-test-{}", std::process::id());
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(&name).unwrap();
        let manager = UnixDatagram::bind_addr(&addr).unwrap();
        assert!(notify(Some(OsStr::new(&format!("@{name}"))), READY).unwrap());
        assert_eq!(recv(&manager), "READY=1");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn abstract_socket_is_unsupported_off_linux() {
        let err = notify(Some(OsStr::new("@x")), READY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
