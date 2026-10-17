//! Unix-socket peer credentials: who is on the other end of a connection.
//!
//! The kernel reports the peer's UID for a connected Unix socket (`SO_PEERCRED` on Linux,
//! `getpeereid` on macOS; tokio's `UnixStream::peer_cred` uses whichever the target has). Both
//! ends of every link check it:
//!
//! - the **client** checks the server's UID before it sends a byte ([`expect_uid`], used by
//!   [`crate::uds::PeerCheckedConnector`]), so a counterfeit server listening on the path is
//!   refused before it can answer anything;
//! - the **server** reads the caller's UID from the connection ([`peer_uid`], from tonic's
//!   `UdsConnectInfo`) and checks it per method ([`crate::acl`]).
//!
//! A connection without credentials (not a Unix socket, or the lookup failed) is refused on
//! both sides; there is no fallback to an unauthenticated mode.

use std::io;

use tonic::transport::server::UdsConnectInfo;

pub use tokio::net::unix::UCred;

/// Why a peer was refused.
#[derive(Debug, thiserror::Error)]
pub enum PeerCredError {
    /// The kernel did not report the peer's credentials.
    #[error("peer credentials unavailable: {0}")]
    Unavailable(#[source] io::Error),
    /// The connection carries no peer credentials (not a Unix socket).
    #[error("no peer credentials")]
    Missing,
    /// The peer runs as another user.
    #[error("peer uid {actual}, expected uid {expected}")]
    WrongUid { expected: u32, actual: u32 },
}

/// The effective UID of this process.
#[must_use]
pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The effective GID of this process.
#[must_use]
pub fn effective_gid() -> u32 {
    rustix::process::getegid().as_raw()
}

/// The peer credentials `cred` (as the kernel reported them), if they are `expected`'s.
pub fn expect_uid(cred: io::Result<UCred>, expected: u32) -> Result<UCred, PeerCredError> {
    let cred = cred.map_err(PeerCredError::Unavailable)?;
    if cred.uid() == expected {
        Ok(cred)
    } else {
        Err(PeerCredError::WrongUid {
            expected,
            actual: cred.uid(),
        })
    }
}

/// The caller's UID on a request served over a Unix socket: tonic attaches the connection's
/// `UdsConnectInfo`, whose `peer_cred` the kernel filled in at accept time. `None` when the
/// request did not come over a Unix socket or the kernel reported no credentials.
#[must_use]
pub fn peer_uid(extensions: &http::Extensions) -> Option<u32> {
    extensions
        .get::<UdsConnectInfo>()
        .and_then(|info| info.peer_cred)
        .map(|cred| cred.uid())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn own_cred() -> UCred {
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        a.peer_cred().unwrap()
    }

    #[test]
    fn effective_ids_are_this_process() {
        assert_eq!(effective_uid(), rustix::process::geteuid().as_raw());
        assert_eq!(effective_gid(), rustix::process::getegid().as_raw());
    }

    #[tokio::test]
    async fn expect_uid_accepts_only_the_expected_uid() {
        let cred = own_cred().await;
        let me = effective_uid();
        assert_eq!(cred.uid(), me);
        assert_eq!(expect_uid(Ok(cred), me).unwrap().uid(), me);
        let other = me.wrapping_add(1);
        match expect_uid(Ok(cred), other) {
            Err(PeerCredError::WrongUid { expected, actual }) => {
                assert_eq!((expected, actual), (other, me));
            }
            r => panic!("{r:?}"),
        }
        let gone = expect_uid(Err(io::Error::from(io::ErrorKind::NotConnected)), me);
        assert!(
            matches!(gone, Err(PeerCredError::Unavailable(_))),
            "{gone:?}"
        );
    }

    #[tokio::test]
    async fn peer_uid_reads_the_connection_info() {
        let mut ext = http::Extensions::new();
        assert_eq!(peer_uid(&ext), None);
        ext.insert(UdsConnectInfo {
            peer_addr: None,
            peer_cred: None,
        });
        assert_eq!(peer_uid(&ext), None, "no credentials");
        ext.insert(UdsConnectInfo {
            peer_addr: None,
            peer_cred: Some(own_cred().await),
        });
        assert_eq!(peer_uid(&ext), Some(effective_uid()));
    }

    #[test]
    fn errors_name_both_uids() {
        let e = PeerCredError::WrongUid {
            expected: 990,
            actual: 1000,
        };
        assert_eq!(e.to_string(), "peer uid 1000, expected uid 990");
        assert_eq!(PeerCredError::Missing.to_string(), "no peer credentials");
    }
}
