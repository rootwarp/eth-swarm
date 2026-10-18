//! [`ReferenceApiUrl`]: the reference node's beacon API, plain `http://` to a loopback host.
//!
//! The same rule as `m2a-session`'s `reference_api_url` (`cl_p2p::m2a_session::config`): the
//! collector has no TLS stack, and plaintext over any other path could be forged or read by
//! anyone on it, so a remote node is reached through an SSH tunnel to a local port
//! (`ssh -L 5052:127.0.0.1:5052 ref-host`). No credentials, query or fragment. The base path
//! may carry a key, so errors never quote the URL and `Debug` shows `scheme://host:port` only.
//! Hosts are never resolved: `localhost` is `127.0.0.1` then `::1`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Why a URL was refused. Never quotes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("reference API URL: {0}")]
pub struct UrlError(pub &'static str);

/// A checked reference API URL.
#[derive(Clone, PartialEq, Eq)]
pub struct ReferenceApiUrl {
    uri: http::Uri,
    addrs: Vec<SocketAddr>,
    authority: String,
    base: String,
}

impl ReferenceApiUrl {
    /// Checks `url`: `http://`, a loopback host (`localhost`, `127.0.0.0/8`, `[::1]`), an
    /// optional port in `1..=65535` and base path, nothing else.
    pub fn parse(url: &str) -> Result<Self, UrlError> {
        let bad = UrlError;
        let uri: http::Uri = url.parse().map_err(|_| bad("not a valid URL"))?;
        if uri.scheme_str() != Some("http") {
            return Err(bad(
                "the scheme must be http:// (loopback only; tunnel to a remote node over SSH)",
            ));
        }
        let authority = uri.authority().ok_or(bad("no host"))?;
        if authority.as_str().contains('@') {
            return Err(bad("credentials in the URL are refused"));
        }
        if uri.query().is_some() || url.contains('#') {
            return Err(bad("no query or fragment allowed"));
        }
        let host = authority.host();
        if host.is_empty() {
            return Err(bad("no host"));
        }
        // `http` accepts junk between an IPv6 literal and the port and gives no port for an
        // out-of-range one, so what follows the host must be nothing, or `:` and a port.
        let after_host = authority
            .as_str()
            .strip_prefix(host)
            .ok_or(bad("no host"))?;
        let port = match after_host {
            "" => 80,
            rest => {
                let digits = rest
                    .strip_prefix(':')
                    .ok_or(bad("only :<port> may follow the host"))?;
                match digits.parse::<u16>() {
                    Ok(p) if p != 0 && digits.bytes().all(|b| b.is_ascii_digit()) => p,
                    _ => return Err(bad("the port must be 1..=65535")),
                }
            }
        };
        let ips = loopback_ips(host);
        if ips.is_empty() {
            return Err(bad(
                "the host must be loopback (localhost, 127.0.0.0/8 or [::1]); \
                 tunnel to a remote node over SSH",
            ));
        }
        Ok(Self {
            addrs: ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
            authority: authority.as_str().to_owned(),
            base: uri.path().trim_end_matches('/').to_owned(),
            uri,
        })
    }

    /// The literal loopback addresses to connect to, in order.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        self.addrs.clone()
    }

    /// The `Host:` header value.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The base path without a trailing `/`; may hold a key, never shown.
    pub fn base_path(&self) -> &str {
        &self.base
    }
}

/// The addresses of a loopback `host`, without a lookup: `localhost` (any case) is `127.0.0.1`
/// then `::1`, an IPv4 literal in `127.0.0.0/8` or `[::1]` is itself; anything else has none.
fn loopback_ips(host: &str) -> Vec<IpAddr> {
    if host.eq_ignore_ascii_case("localhost") {
        return vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
    }
    let ip = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<Ipv6Addr>().map(IpAddr::from).ok(),
        None => host.parse::<Ipv4Addr>().map(IpAddr::from).ok(),
    };
    ip.filter(IpAddr::is_loopback).into_iter().collect()
}

impl fmt::Debug for ReferenceApiUrl {
    /// `scheme://host:port`, plus `/…` when there is a base path.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = self.uri.host().unwrap_or_default();
        let port = self.addrs.first().map_or(80, SocketAddr::port);
        write!(f, "http://{host}:{port}")?;
        if self.base.is_empty() {
            Ok(())
        } else {
            f.write_str("/…")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_and_shown_without_the_path() {
        for good in [
            "http://127.0.0.1:5052",
            "http://127.0.0.1/beacon/",
            "http://localhost:5052",
            "http://LOCALHOST:5052",
            "http://[::1]:5052",
            "http://127.8.9.10:5052",
        ] {
            assert!(ReferenceApiUrl::parse(good).is_ok(), "{good}");
        }
        let keyed = ReferenceApiUrl::parse("http://127.0.0.1/key/abc/").unwrap();
        assert_eq!(format!("{keyed:?}"), "http://127.0.0.1:80/…");
        assert_eq!(keyed.base_path(), "/key/abc");
        assert_eq!(keyed.authority(), "127.0.0.1");
        let v6 = ReferenceApiUrl::parse("http://[::1]").unwrap();
        assert_eq!(format!("{v6:?}"), "http://[::1]:80");
        assert_eq!(v6.base_path(), "");
    }

    #[test]
    fn refused_without_quoting() {
        for bad in [
            "ftp://127.0.0.1",
            "https://127.0.0.1:5052",
            "127.0.0.1:5052",
            "/eth/v1",
            "http://",
            "http://user:hunter2@127.0.0.1",
            "http://hunter2@127.0.0.1",
            "http://127.0.0.1/?token=hunter2",
            "http://127.0.0.1/#hunter2",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://127.0.0.1:hunter2",
            "http://[::1]junk:65536",
            "http://[::1]hunter2",
            "http://[::1]:",
            "http://127.0.0.1:+5052",
            "not a url hunter2",
            "http://192.0.2.10:5052",
            "http://0.0.0.0:5052",
            "http://ref.example:5052",
            "http://localhost.:5052",
            "http://127.0.0.1.ref.example:5052",
            "http://[::]:5052",
            "http://[::ffff:127.0.0.1]:5052",
        ] {
            let err = ReferenceApiUrl::parse(bad).unwrap_err();
            assert!(!err.to_string().contains("hunter2"), "{bad}: {err}");
            assert!(!format!("{err:?}").contains("hunter2"), "{bad}: {err:?}");
        }
        let remote = ReferenceApiUrl::parse("http://10.0.0.1:5052").unwrap_err();
        assert!(remote.0.contains("loopback"), "{remote}");
        let tls = ReferenceApiUrl::parse("https://127.0.0.1").unwrap_err();
        assert!(tls.0.contains("http://"), "{tls}");
    }

    #[test]
    fn connects_only_to_literal_loopback_addresses() {
        let addrs = |u: &str| ReferenceApiUrl::parse(u).unwrap().addrs();
        assert_eq!(
            addrs("http://localhost:5052"),
            vec![
                "127.0.0.1:5052".parse::<SocketAddr>().unwrap(),
                "[::1]:5052".parse().unwrap()
            ]
        );
        assert_eq!(
            addrs("http://127.0.0.2"),
            vec!["127.0.0.2:80".parse().unwrap()]
        );
        assert_eq!(addrs("http://[::1]:1"), vec!["[::1]:1".parse().unwrap()]);
    }
}
