//! systemd readiness notification (`sd_notify(3)`) without libsystemd.
//!
//! The service manager passes a datagram socket in `$NOTIFY_SOCKET`: an absolute filesystem path,
//! or `@name` for a Linux abstract socket. With the variable unset or empty there is no manager
//! listening and nothing is sent.

use std::ffi::OsStr;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

/// The environment variable systemd sets for `Type=notify` services.
pub const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";
/// The state that tells the manager startup is complete.
pub const READY: &str = "READY=1";

/// Sends `state` to the manager socket `socket` (the value of `$NOTIFY_SOCKET`). `Ok(false)` if
/// there is no socket to notify.
pub fn notify(socket: Option<&OsStr>, state: &str) -> io::Result<bool> {
    let Some(socket) = socket.filter(|s| !s.is_empty()) else {
        return Ok(false);
    };
    let sock = UnixDatagram::unbound()?;
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

/// [`notify`] with [`READY`] to the socket in this process's `$NOTIFY_SOCKET`.
pub fn notify_ready() -> io::Result<bool> {
    notify(std::env::var_os(NOTIFY_SOCKET).as_deref(), READY)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn send_abstract(sock: &UnixDatagram, name: &[u8], state: &str) -> io::Result<()> {
    #[cfg(target_os = "android")]
    use std::os::android::net::SocketAddrExt;
    #[cfg(target_os = "linux")]
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
    sock.send_to_addr(state.as_bytes(), &addr).map(drop)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
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
        let mut buf = [0u8; 64];
        let n = sock.recv(&mut buf).unwrap();
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    #[test]
    fn unset_or_empty_socket_sends_nothing() {
        assert!(!notify(None, READY).unwrap());
        assert!(!notify(Some(OsStr::new("")), READY).unwrap());
    }

    #[test]
    fn ready_reaches_a_path_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify.sock");
        let manager = UnixDatagram::bind(&path).unwrap();
        assert!(notify(Some(path.as_os_str()), READY).unwrap());
        assert_eq!(recv(&manager), "READY=1");
    }

    #[test]
    fn relative_socket_is_refused() {
        let err = notify(Some(OsStr::new("notify.sock")), READY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn missing_path_socket_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.sock");
        assert!(notify(Some(path.as_os_str()), READY).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ready_reaches_an_abstract_socket() {
        use std::os::linux::net::SocketAddrExt;
        let name = format!("cl-verify-notify-test-{}", std::process::id());
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(&name).unwrap();
        let manager = UnixDatagram::bind_addr(&addr).unwrap();
        assert!(notify(Some(OsStr::new(&format!("@{name}"))), READY).unwrap());
        assert_eq!(recv(&manager), "READY=1");
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[test]
    fn abstract_socket_is_unsupported_off_linux() {
        let err = notify(Some(OsStr::new("@x")), READY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
