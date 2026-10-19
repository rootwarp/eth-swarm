//! A loopback TCP address that refuses every connection, for the tests whose request must fail
//! to connect. Shared by the unit tests and `tests/anchor_fetch.rs`.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// The TCP port of [`refused_tcp_addr`]: tcpmux, which nothing serves.
pub const REFUSED_PORT: u16 = 1;

/// A TCP address on loopback `ip` that refuses every connection.
///
/// A port bound and then released can be taken by another socket before the test connects,
/// which then connects instead of being refused. [`REFUSED_PORT`] lies below every ephemeral
/// port range, so the system never hands it to a socket that binds port 0; it is dialed once
/// here, and the test fails at once if anything accepts there.
pub fn refused_tcp_addr(ip: IpAddr) -> SocketAddr {
    refused(SocketAddr::new(ip, REFUSED_PORT)).unwrap_or_else(|e| panic!("{e}"))
}

/// `addr` if a connection to it is refused; why not otherwise.
fn refused(addr: SocketAddr) -> Result<SocketAddr, String> {
    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Ok(addr),
        Err(e) => Err(format!(
            "a connection to {addr} must be refused, it failed with: {e}"
        )),
        Ok(_) => Err(format!(
            "a connection to {addr} must be refused, it connected"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};

    #[test]
    fn the_refused_address_refuses_a_connection() {
        for ip in [
            IpAddr::from(Ipv4Addr::LOCALHOST),
            Ipv6Addr::LOCALHOST.into(),
        ] {
            let addr = refused_tcp_addr(ip);
            assert_eq!(addr, SocketAddr::new(ip, REFUSED_PORT));
            let err = TcpStream::connect(addr).expect_err("nothing accepts there");
            assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused, "{err}");
        }
    }

    /// An address that accepts is never handed out as a refused one.
    #[test]
    fn an_address_that_accepts_is_not_refused() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let err = refused(addr).expect_err("the listener accepts");
        assert!(err.contains(&addr.to_string()), "{err}");
    }
}
