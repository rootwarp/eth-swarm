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
use std::path::Path;

/// Why a URL was refused. Never quotes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("reference API URL: {0}")]
pub struct UrlError(pub &'static str);

/// Cap on a URL file ([`ReferenceApiUrl::read_file`]): 4 KiB.
pub const MAX_URL_FILE_BYTES: usize = 4 << 10;

/// Why a URL file was refused: the file's path and why, never its content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {reason}")]
pub struct UrlFileError {
    /// The file, as given.
    pub path: String,
    /// Why.
    pub reason: String,
}

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

    /// Reads the URL from `path`, so a key in it stays out of the process's argv: a regular
    /// file (not a symlink, a FIFO or a device) owned by the effective UID that neither group
    /// nor others may access (mode 0600 or 0400), at most [`MAX_URL_FILE_BYTES`], holding one
    /// URL and at most a trailing newline, checked as [`ReferenceApiUrl::parse`] does. Errors
    /// name the file, never what it holds.
    pub fn read_file(path: &Path) -> Result<Self, UrlFileError> {
        Self::read_file_as(path, rustix::process::geteuid().as_raw())
    }

    /// [`ReferenceApiUrl::read_file`] for a process whose effective UID is `euid`.
    fn read_file_as(path: &Path, euid: u32) -> Result<Self, UrlFileError> {
        use rustix::fs::{Mode, OFlags};
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let bad = |reason: String| UrlFileError {
            path: path.display().to_string(),
            reason,
        };
        let before = std::fs::symlink_metadata(path).map_err(|e| bad(format!("open: {e}")))?;
        if before.file_type().is_symlink() {
            return Err(bad("a symlink (want a regular file)".into()));
        }
        // NOFOLLOW: a symlink swapped in after the lstat is not followed. NONBLOCK: a FIFO at
        // the path is opened at once and refused below, instead of blocking until a writer
        // comes. Every check after this one is on the open file.
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let fd = rustix::fs::open(path, flags, Mode::empty())
            .map_err(|e| bad(format!("open: {}", std::io::Error::from(e))))?;
        let file = std::fs::File::from(fd);
        let meta = file.metadata().map_err(|e| bad(format!("stat: {e}")))?;
        if !meta.is_file() {
            return Err(bad("not a regular file".into()));
        }
        if (meta.dev(), meta.ino()) != (before.dev(), before.ino()) {
            return Err(bad("replaced while it was opened".into()));
        }
        if meta.uid() != euid {
            return Err(bad(format!("owned by uid {}, want {euid}", meta.uid())));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(bad(
                "group or others may access it (want mode 0600 or 0400)".into(),
            ));
        }
        let mut body = Vec::new();
        file.take(MAX_URL_FILE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| bad(format!("read: {e}")))?;
        if body.len() > MAX_URL_FILE_BYTES {
            return Err(bad(format!("over {MAX_URL_FILE_BYTES} bytes")));
        }
        let text = String::from_utf8(body).map_err(|_| bad("not UTF-8".into()))?;
        let line = text
            .strip_suffix('\n')
            .map_or(text.as_str(), |t| t.strip_suffix('\r').unwrap_or(t));
        if line.contains(['\n', '\r']) {
            return Err(bad("more than one line (want one URL)".into()));
        }
        if line.is_empty() {
            return Err(bad("empty (want one URL)".into()));
        }
        Self::parse(line).map_err(|e| bad(e.0.into()))
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

    /// `body` in a fresh file of `mode` under `dir`.
    fn url_file(dir: &Path, name: &str, body: &[u8], mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn a_url_file_is_read_without_its_newline() {
        let dir = tempfile::tempdir().unwrap();
        for (name, body, mode) in [
            ("a", &b"http://127.0.0.1:5053/key-hunter2\n"[..], 0o600),
            ("b", b"http://127.0.0.1:5053/key-hunter2", 0o400),
            ("c", b"http://127.0.0.1:5053/key-hunter2\r\n", 0o600),
        ] {
            let path = url_file(dir.path(), name, body, mode);
            let url = ReferenceApiUrl::read_file(&path).unwrap();
            assert_eq!(format!("{url:?}"), "http://127.0.0.1:5053/…", "{name}");
            assert_eq!(url.base_path(), "/key-hunter2", "{name}");
        }
    }

    #[test]
    fn a_url_file_others_can_read_or_that_is_not_one_url_is_refused_unquoted() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"http://127.0.0.1:5053/key-hunter2\n";
        let mut long = b"http://127.0.0.1:5053/".to_vec();
        long.extend(std::iter::repeat_n(b'k', MAX_URL_FILE_BYTES));
        let cases = [
            (url_file(dir.path(), "group", key, 0o640), "group or others"),
            (url_file(dir.path(), "world", key, 0o604), "group or others"),
            (url_file(dir.path(), "empty", b"\n", 0o600), "empty"),
            (
                url_file(
                    dir.path(),
                    "two",
                    b"http://127.0.0.1:5053\nhunter2\n",
                    0o600,
                ),
                "one line",
            ),
            (url_file(dir.path(), "long", &long, 0o600), "bytes"),
            (
                url_file(dir.path(), "binary", b"\xffhunter2", 0o600),
                "UTF-8",
            ),
            (
                url_file(dir.path(), "remote", b"http://192.0.2.1/hunter2\n", 0o600),
                "loopback",
            ),
            (dir.path().to_path_buf(), "not a regular file"),
            (dir.path().join("missing"), "open"),
        ];
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("group"), &link).unwrap();
        let link_case = [(link, "symlink")];
        for (path, why) in cases.iter().chain(&link_case) {
            let err = ReferenceApiUrl::read_file(path).unwrap_err().to_string();
            assert!(err.starts_with(&path.display().to_string()), "{err}");
            assert!(err.contains(why), "{err} (want {why})");
            assert!(!err.contains("hunter2") && !err.contains("kkkk"), "{err}");
        }
    }

    #[test]
    fn a_fifo_at_the_url_file_path_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg("-m")
            .arg("0600")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success(), "mkfifo: {made}");
        // A blocking open waits for a writer that never comes: give it 10 s, then fail.
        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(ReferenceApiUrl::read_file(&path).map(|_| ()));
        });
        let err = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("read_file blocked on a FIFO")
            .unwrap_err()
            .to_string();
        assert!(err.starts_with(&fifo.display().to_string()), "{err}");
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[test]
    fn a_url_file_another_uid_owns_is_refused_unquoted() {
        let dir = tempfile::tempdir().unwrap();
        let path = url_file(
            dir.path(),
            "theirs",
            b"http://127.0.0.1:5053/key-hunter2\n",
            0o600,
        );
        let euid = rustix::process::geteuid().as_raw();
        assert!(ReferenceApiUrl::read_file_as(&path, euid).is_ok());
        // The euid is injected, so another owner is testable without root.
        let other = euid.wrapping_add(1);
        let err = ReferenceApiUrl::read_file_as(&path, other)
            .unwrap_err()
            .to_string();
        assert!(err.starts_with(&path.display().to_string()), "{err}");
        assert!(
            err.contains(&format!("owned by uid {euid}, want {other}")),
            "{err}"
        );
        assert!(!err.contains("hunter2"), "{err}");
    }
}
