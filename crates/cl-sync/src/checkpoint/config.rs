//! `anchor-fetch.toml`: the two providers and the download limits.
//!
//! ```toml
//! # max_body_bytes = 1073741824     # cap per SSZ body (default 1 GiB)
//! # request_timeout_secs = 30       # connect, response headers and JSON bodies
//! # body_timeout_secs = 1800        # one SSZ body download
//! # allow_insecure_http = false     # plain http:// URLs (local fixtures only)
//!
//! [[provider]]
//! name = "a"
//! operator = "operator-a"
//! url = "https://a.example"
//!
//! [[provider]]
//! name = "b"
//! operator = "operator-b"
//! url = "https://b.example/beacon"
//! ```
//!
//! Exactly two providers. Their names, operators and hosts must all differ (compared
//! case-insensitively): one operator, or one host behind two names, is one source of truth,
//! not two. Host names that end in the same two DNS labels (`a.example.com`,
//! `b.example.com`) are refused as one domain; this is a heuristic, not a public-suffix check
//! (`a.co.uk` and `b.co.uk` are refused too), and two domains of one operator pass. At run
//! time the fetcher also refuses two hosts that resolve to a common address. Beyond that,
//! operator independence rests on the `operator` names the config gives. IP literals are compared in canonical form (`[0:0:0:0:0:0:0:1]` is `[::1]`, and an
//! IPv4-mapped IPv6 address is its IPv4 address); host names are compared as written, lower-cased
//! and without a trailing dot, not resolved, so two names for the same machine are not caught
//! here. URLs must be `https://` unless `allow_insecure_http` is set, and may carry a base path
//! but no query, fragment or credentials; only `:PORT` (1..=65535, digits only) may follow
//! the host.
//!
//! `anchor-fetch --check --providers A,B` builds the same [`Config`] from two URLs
//! ([`Config::from_provider_urls`]): providers `a` and `b`, operator
//! [`PROVIDER_URLS_OPERATOR`], the default limits, the same URL rules, and one host given twice
//! refused.
//!
//! A base path may carry an API key, so the path never leaves this module in readable form:
//! the run log, `anchor.json` and errors see [`Provider::redacted_url`]
//! (`scheme://host:port`, plus `/…` when there is a path), and validation errors never quote
//! the URL.

use crate::checkpoint::fetch::AnchorError;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

/// Default cap on one SSZ body: 1 GiB. A mainnet-preset Gloas state is a few hundred MiB at
/// today's validator counts.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 1 << 30;
/// Default timeout for connecting, for the response headers, and for a whole JSON body.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default timeout for one SSZ body download.
pub const DEFAULT_BODY_TIMEOUT: Duration = Duration::from_secs(1800);
/// The operator of a provider given by URL alone (`--providers`), which names none.
pub const PROVIDER_URLS_OPERATOR: &str = "unnamed";

/// URL scheme of a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// TLS through rustls, verified against the webpki roots.
    Https,
    /// Plain TCP; only with `allow_insecure_http`.
    Http,
}

/// One beacon API provider.
#[derive(Clone, PartialEq, Eq)]
pub struct Provider {
    /// Short name used in the run log and errors.
    pub name: String,
    /// Who runs it.
    pub operator: String,
    /// `https` or `http`.
    pub scheme: Scheme,
    /// Host name (lower-cased, no trailing dot) or canonical IP literal (no IPv6 brackets).
    pub host: String,
    /// TCP port (explicit, or 443/80 by scheme).
    pub port: u16,
    /// Base path without a trailing `/` (empty for the root). May hold a secret: only
    /// [`Provider::path`] reads it.
    pub(crate) base_path: String,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("name", &self.name)
            .field("operator", &self.operator)
            .field("url", &self.redacted_url())
            .finish()
    }
}

impl Provider {
    /// `scheme://host:port`, plus `/…` when the URL has a base path, which is never shown.
    pub fn redacted_url(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Https => "https",
            Scheme::Http => "http",
        };
        let path = if self.base_path.is_empty() {
            ""
        } else {
            "/…"
        };
        format!("{scheme}://{}:{}{path}", self.bracketed_host(), self.port)
    }

    fn bracketed_host(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    /// The `Host` header value.
    pub fn authority(&self) -> String {
        let host = self.bracketed_host();
        let default_port = match self.scheme {
            Scheme::Https => 443,
            Scheme::Http => 80,
        };
        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// `path` (starting with `/`) under the provider's base path.
    pub fn path(&self, path: &str) -> String {
        format!("{}{path}", self.base_path)
    }
}

/// The validated `anchor-fetch.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Provider A: finality, header, and the block.
    pub a: Provider,
    /// Provider B: finality, header, and the state.
    pub b: Provider,
    /// Cap on one SSZ body, checked against `Content-Length` and while reading.
    pub max_body_bytes: u64,
    /// Timeout for connecting, response headers and JSON bodies.
    pub request_timeout: Duration,
    /// Timeout for one SSZ body.
    pub body_timeout: Duration,
    /// Whether `http://` URLs are accepted.
    pub allow_insecure_http: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    provider: Vec<RawProvider>,
    max_body_bytes: Option<u64>,
    request_timeout_secs: Option<u64>,
    body_timeout_secs: Option<u64>,
    #[serde(default)]
    allow_insecure_http: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProvider {
    name: String,
    operator: String,
    url: String,
}

impl Config {
    /// Reads and validates `path`.
    pub fn load(path: &Path) -> Result<Self, AnchorError> {
        let text = std::fs::read_to_string(path).map_err(|source| AnchorError::Io {
            context: format!("read {}", path.display()),
            source,
        })?;
        Self::from_toml(&text)
    }

    /// Parses and validates a config.
    pub fn from_toml(text: &str) -> Result<Self, AnchorError> {
        let raw: RawConfig =
            toml::from_str(text).map_err(|e| AnchorError::Config(e.message().to_owned()))?;
        let allow_insecure_http = raw.allow_insecure_http;
        let [a, b]: [RawProvider; 2] = raw.provider.try_into().map_err(|v: Vec<_>| {
            AnchorError::Config(format!(
                "need exactly two [[provider]] entries, got {}",
                v.len()
            ))
        })?;
        let a = provider(a, allow_insecure_http)?;
        let b = provider(b, allow_insecure_http)?;
        if a.name.eq_ignore_ascii_case(&b.name) {
            return Err(AnchorError::Config(format!(
                "both providers are named {:?}",
                a.name
            )));
        }
        if a.operator.to_lowercase() == b.operator.to_lowercase() {
            return Err(AnchorError::SameOperator {
                a: a.name,
                b: b.name,
                operator: a.operator,
            });
        }
        independent_hosts(&a, &b)?;
        let max_body_bytes = raw.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES);
        if max_body_bytes == 0 {
            return Err(AnchorError::Config(
                "max_body_bytes must be positive".into(),
            ));
        }
        Ok(Config {
            a,
            b,
            max_body_bytes,
            request_timeout: timeout(raw.request_timeout_secs, DEFAULT_REQUEST_TIMEOUT)?,
            body_timeout: timeout(raw.body_timeout_secs, DEFAULT_BODY_TIMEOUT)?,
            allow_insecure_http,
        })
    }
}

impl Config {
    /// `--providers A,B` of `anchor-fetch --check`: two provider URLs, comma separated, named
    /// `a` and `b`, with the default limits. The URL rules are the config file's. A URL list
    /// says nothing about operators, so both are [`PROVIDER_URLS_OPERATOR`] and independence
    /// rests on the hosts: one host given twice (the same provider twice, or one host behind
    /// two ports or paths) is refused with [`AnchorError::SameHost`].
    pub fn from_provider_urls(list: &str, allow_insecure_http: bool) -> Result<Self, AnchorError> {
        let urls: Vec<&str> = list.split(',').map(str::trim).collect();
        let [url_a, url_b] = urls[..] else {
            return Err(AnchorError::Config(format!(
                "--providers needs exactly two URLs, A,B; got {}",
                urls.len()
            )));
        };
        let raw = |name: &str, url: &str| RawProvider {
            name: name.into(),
            operator: PROVIDER_URLS_OPERATOR.into(),
            url: url.into(),
        };
        let a = provider(raw("a", url_a), allow_insecure_http)?;
        let b = provider(raw("b", url_b), allow_insecure_http)?;
        independent_hosts(&a, &b)?;
        Ok(Config {
            a,
            b,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            body_timeout: DEFAULT_BODY_TIMEOUT,
            allow_insecure_http,
        })
    }
}

/// Refuses two providers on one host, or under one domain: host names that end in the same
/// two DNS labels (`a.example.com` and `b.example.com`). This is a heuristic, not a public-suffix
/// check: `a.co.uk` and `b.co.uk` are refused too, and `a.example.co.uk` and
/// `b.other.co.uk` are refused although they are different registrations. IP literals are
/// compared only for equality here; [`crate::checkpoint::fetch`] also refuses names that
/// resolve to a common address.
fn independent_hosts(a: &Provider, b: &Provider) -> Result<(), AnchorError> {
    if a.host == b.host {
        return Err(AnchorError::SameHost {
            a: a.name.clone(),
            b: b.name.clone(),
            host: a.host.clone(),
        });
    }
    match (domain(&a.host), domain(&b.host)) {
        (Some(x), Some(y)) if x == y => Err(AnchorError::SameDomain {
            a: a.name.clone(),
            b: b.name.clone(),
            domain: x.to_owned(),
        }),
        _ => Ok(()),
    }
}

/// The last two DNS labels of a host name (already lower-cased, no trailing dot); `None` for
/// an IP literal or a single-label name.
fn domain(host: &str) -> Option<&str> {
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let mut dots = host.rmatch_indices('.');
    let _last = dots.next()?;
    Some(match dots.next() {
        Some((i, _)) => &host[i + 1..],
        None => host,
    })
}

fn timeout(secs: Option<u64>, default: Duration) -> Result<Duration, AnchorError> {
    match secs {
        None => Ok(default),
        Some(0) => Err(AnchorError::Config("timeouts must be positive".into())),
        Some(s) => Ok(Duration::from_secs(s)),
    }
}

fn provider(raw: RawProvider, allow_insecure_http: bool) -> Result<Provider, AnchorError> {
    let name = raw.name.trim().to_owned();
    let operator = raw.operator.trim().to_owned();
    if name.is_empty() || operator.is_empty() {
        return Err(AnchorError::Config(
            "every provider needs a non-empty name and operator".into(),
        ));
    }
    // Never quote the URL: it may carry credentials or a key.
    let bad = |why: &str| AnchorError::Config(format!("provider {name}: url: {why}"));
    let url = raw.url.trim().trim_end_matches('/');
    let uri: http::Uri = url.parse().map_err(|_| bad("not a valid URL"))?;
    let scheme = match uri.scheme_str() {
        Some("https") => Scheme::Https,
        Some("http") if allow_insecure_http => Scheme::Http,
        Some("http") => return Err(bad("http:// needs allow_insecure_http = true")),
        _ => return Err(bad("the scheme must be https://")),
    };
    let authority = uri.authority().ok_or_else(|| bad("no host"))?;
    if authority.as_str().contains('@') {
        return Err(bad("credentials in the URL are refused"));
    }
    if uri.query().is_some() || url.contains('#') {
        return Err(bad("no query or fragment allowed"));
    }
    let host = canonical_host(authority.host()).ok_or_else(|| bad("no host"))?;
    // `Authority::port` is `None` for an out-of-range port, and `http` skips junk after an
    // IP literal, so read what follows the host: nothing, or `:` and the port's digits.
    let rest = authority
        .as_str()
        .strip_prefix(authority.host())
        .ok_or_else(|| bad("no host"))?;
    let port = match rest.strip_prefix(':') {
        None if rest.is_empty() => match scheme {
            Scheme::Https => 443,
            Scheme::Http => 80,
        },
        None => return Err(bad("only :PORT may follow the host")),
        Some(p) => match p.parse::<u16>() {
            Ok(port) if port != 0 && p.bytes().all(|b| b.is_ascii_digit()) => port,
            _ => return Err(bad("the port must be 1..=65535")),
        },
    };
    let base_path = uri.path().trim_end_matches('/').to_owned();
    Ok(Provider {
        name,
        operator,
        scheme,
        host,
        port,
        base_path,
    })
}

/// An IP literal in canonical form (IPv4-mapped IPv6 as IPv4), or a host name lower-cased
/// without a trailing dot. `None` if empty.
fn canonical_host(host: &str) -> Option<String> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Some(ip.to_canonical().to_string());
    }
    let name = bare.trim_end_matches('.').to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two(a: (&str, &str, &str), b: (&str, &str, &str), extra: &str) -> String {
        format!(
            "{extra}\n[[provider]]\nname = \"{}\"\noperator = \"{}\"\nurl = \"{}\"\n\
             [[provider]]\nname = \"{}\"\noperator = \"{}\"\nurl = \"{}\"\n",
            a.0, a.1, a.2, b.0, b.1, b.2
        )
    }

    #[test]
    fn parses_two_https_providers_with_defaults() {
        let c = Config::from_toml(&two(
            ("a", "Op A", "https://a.example/"),
            ("b", "Op B", "https://B.example:8443/beacon/"),
            "",
        ))
        .unwrap();
        assert_eq!(c.a.redacted_url(), "https://a.example:443");
        assert_eq!(
            (c.a.scheme, c.a.port, c.a.base_path.as_str()),
            (Scheme::Https, 443, "")
        );
        assert_eq!(c.a.authority(), "a.example");
        assert_eq!((c.b.host.as_str(), c.b.port), ("b.example", 8443));
        assert_eq!(c.b.authority(), "b.example:8443");
        assert_eq!(c.b.path("/eth/v1/x"), "/beacon/eth/v1/x");
        assert_eq!(c.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(c.max_body_bytes, 1 << 30);
        assert_eq!(c.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(c.body_timeout, DEFAULT_BODY_TIMEOUT);
        assert!(!c.allow_insecure_http);
    }

    #[test]
    fn same_operator_is_refused_case_insensitively() {
        let err = Config::from_toml(&two(
            ("a", "Same Op", "https://a.example"),
            ("b", " same op ", "https://b.example"),
            "",
        ))
        .unwrap_err();
        assert!(matches!(err, AnchorError::SameOperator { .. }), "{err:?}");
    }

    #[test]
    fn same_host_is_refused_even_on_other_ports() {
        let err = Config::from_toml(&two(
            ("a", "A", "https://node.example:5052"),
            ("b", "B", "https://NODE.example./other"),
            "",
        ))
        .unwrap_err();
        assert!(matches!(err, AnchorError::SameHost { ref host, .. } if host == "node.example"));
    }

    #[test]
    fn http_needs_the_explicit_flag() {
        let text = two(
            ("a", "A", "http://127.0.0.1:1"),
            ("b", "B", "http://localhost:2"),
            "",
        );
        assert!(matches!(
            Config::from_toml(&text),
            Err(AnchorError::Config(_))
        ));
        let c = Config::from_toml(&format!("allow_insecure_http = true\n{text}")).unwrap();
        assert_eq!((c.a.scheme, c.b.scheme), (Scheme::Http, Scheme::Http));
        assert_eq!(c.a.authority(), "127.0.0.1:1");
    }

    #[test]
    fn refuses_bad_shapes() {
        let ok_b = ("b", "B", "https://b.example");
        for (a, extra) in [
            (("a", "A", "ftp://a.example"), ""),
            (("a", "A", "a.example"), ""),
            (("a", "A", "https://user:pw@a.example"), ""),
            (("a", "A", "https://a.example/?x=1"), ""),
            (("a", "A", "https://a.example/#frag"), ""),
            (("", "A", "https://a.example"), ""),
            (("a", " ", "https://a.example"), ""),
            (("B", "A", "https://a.example"), ""),
            (("a", "A", "https://a.example"), "max_body_bytes = 0"),
            (("a", "A", "https://a.example"), "request_timeout_secs = 0"),
            (("a", "A", "https://a.example"), "body_timeout_secs = 0"),
            (("a", "A", "https://a.example"), "unknown_key = 1"),
        ] {
            let text = two(a, ok_b, extra);
            assert!(
                matches!(Config::from_toml(&text), Err(AnchorError::Config(_))),
                "accepted {text}"
            );
        }
    }

    #[test]
    fn needs_exactly_two_providers() {
        let one = "[[provider]]\nname = \"a\"\noperator = \"A\"\nurl = \"https://a.example\"\n";
        assert!(matches!(
            Config::from_toml(one),
            Err(AnchorError::Config(_))
        ));
        assert!(matches!(Config::from_toml(""), Err(AnchorError::Config(_))));
        let three = format!(
            "{}{one}",
            two(
                ("x", "X", "https://x.example"),
                ("y", "Y", "https://y.example"),
                ""
            )
        );
        assert!(matches!(
            Config::from_toml(&three),
            Err(AnchorError::Config(_))
        ));
    }

    #[test]
    fn ipv6_hosts_keep_their_brackets_in_the_authority() {
        let c = Config::from_toml(&two(
            ("a", "A", "https://[::1]:9000"),
            ("b", "B", "https://b.example"),
            "",
        ))
        .unwrap();
        assert_eq!(c.a.host, "::1");
        assert_eq!(c.a.authority(), "[::1]:9000");
    }

    #[test]
    fn overrides_limits() {
        let c = Config::from_toml(&two(
            ("a", "A", "https://a.example"),
            ("b", "B", "https://b.example"),
            "max_body_bytes = 10\nrequest_timeout_secs = 2\nbody_timeout_secs = 3",
        ))
        .unwrap();
        assert_eq!(c.max_body_bytes, 10);
        assert_eq!(c.request_timeout, Duration::from_secs(2));
        assert_eq!(c.body_timeout, Duration::from_secs(3));
    }

    #[test]
    fn validation_errors_never_echo_the_url() {
        for url in [
            "https://user:hunter2@a.example",
            "https://a.example/?key=hunter2",
            "https://a.example/#hunter2",
            "ftp://hunter2.example",
            "http://hunter2.example",
            "https://a.example:99999/hunter2",
            "not a url hunter2",
        ] {
            let text = two(("a", "A", url), ("b", "B", "https://b.example"), "");
            let err = Config::from_toml(&text).unwrap_err();
            assert!(matches!(err, AnchorError::Config(_)), "{url}: {err:?}");
            assert!(!err.to_string().contains("hunter2"), "{url}: {err}");
            assert!(!format!("{err:?}").contains("hunter2"), "{url}: {err:?}");
        }
    }

    #[test]
    fn the_logged_url_hides_the_path() {
        let c = Config::from_toml(&two(
            ("a", "A", "https://a.example"),
            ("b", "B", "https://b.example:8443/tok3n/beacon"),
            "",
        ))
        .unwrap();
        assert_eq!(c.a.redacted_url(), "https://a.example:443");
        assert_eq!(c.b.redacted_url(), "https://b.example:8443/…");
        assert_eq!(c.b.path("/x"), "/tok3n/beacon/x");
        assert!(!format!("{:?}", c.b).contains("tok3n"));
        assert!(!format!("{c:?}").contains("tok3n"));
    }

    #[test]
    fn ip_literals_are_compared_canonically() {
        for (a, b) in [
            ("https://[::1]:1", "https://[0:0:0:0:0:0:0:1]:2"),
            ("https://[::ffff:127.0.0.1]", "https://127.0.0.1:8443"),
            ("https://[::1]", "https://[0::1]"),
        ] {
            let err = Config::from_toml(&two(("a", "A", a), ("b", "B", b), "")).unwrap_err();
            assert!(
                matches!(err, AnchorError::SameHost { .. }),
                "{a} {b}: {err:?}"
            );
        }
        let c = Config::from_toml(&two(
            ("a", "A", "https://[0:0:0:0:0:0:0:1]:9000"),
            ("b", "B", "https://b.example"),
            "",
        ))
        .unwrap();
        assert_eq!(c.a.host, "::1");
    }

    #[test]
    fn an_invalid_port_is_refused() {
        for url in ["https://a.example:70000", "https://a.example:0"] {
            let text = two(("a", "A", url), ("b", "B", "https://b.example"), "");
            assert!(
                matches!(Config::from_toml(&text), Err(AnchorError::Config(_))),
                "accepted {url}"
            );
        }
    }

    #[test]
    fn only_a_port_may_follow_the_host() {
        for url in [
            "http://[::1]junk:65536",
            "http://[::1]x:5052",
            "http://[::1]:",
            "https://ref.example:",
            "https://ref.example:+443",
            "https://ref.example:0443x",
        ] {
            let text = two(
                ("a", "A", url),
                ("b", "B", "https://b.example"),
                "allow_insecure_http = true",
            );
            match Config::from_toml(&text) {
                Err(AnchorError::Config(msg)) => {
                    assert!(
                        !msg.contains("ref.example") && !msg.contains("::1"),
                        "{msg}"
                    );
                }
                other => panic!("{url}: {other:?}"),
            }
        }
    }

    #[test]
    fn provider_urls_are_providers_a_and_b_with_default_limits() {
        let c =
            Config::from_provider_urls(" https://a.example/ , https://b.example:8443/k3y/", false)
                .unwrap();
        assert_eq!((c.a.name.as_str(), c.b.name.as_str()), ("a", "b"));
        assert_eq!(c.a.operator, PROVIDER_URLS_OPERATOR);
        assert_eq!(c.a.redacted_url(), "https://a.example:443");
        assert_eq!(c.b.redacted_url(), "https://b.example:8443/…");
        assert_eq!(c.b.path("/x"), "/k3y/x");
        assert_eq!(c.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(c.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(c.body_timeout, DEFAULT_BODY_TIMEOUT);
        assert!(!c.allow_insecure_http);
        assert!(!format!("{c:?}").contains("k3y"));
    }

    #[test]
    fn provider_urls_refuse_one_provider_given_twice() {
        for list in [
            "https://a.example,https://a.example",
            "https://a.example:1,https://A.example.:2/other",
            "https://[::1],https://[0:0:0:0:0:0:0:1]",
        ] {
            let err = Config::from_provider_urls(list, false).unwrap_err();
            assert!(
                matches!(err, AnchorError::SameHost { .. }),
                "{list}: {err:?}"
            );
            assert_eq!(err.exit_code(), 2);
        }
    }

    #[test]
    fn provider_urls_need_exactly_two_entries() {
        for list in [
            "",
            "https://a.example",
            "https://a.example,",
            ",https://b.example",
            "https://a.example,https://b.example,https://c.example",
        ] {
            let err = Config::from_provider_urls(list, false).unwrap_err();
            assert!(matches!(err, AnchorError::Config(_)), "{list:?}: {err:?}");
        }
    }

    #[test]
    fn provider_urls_follow_the_url_rules_and_never_echo_a_url() {
        let local = "http://127.0.0.1:1,http://localhost:2";
        assert!(matches!(
            Config::from_provider_urls(local, false),
            Err(AnchorError::Config(_))
        ));
        let c = Config::from_provider_urls(local, true).unwrap();
        assert!(c.allow_insecure_http);
        assert_eq!((c.a.scheme, c.b.scheme), (Scheme::Http, Scheme::Http));
        for bad in [
            "https://user:hunter2@a.example,https://b.example",
            "https://a.example/?key=hunter2,https://b.example",
            "https://a.example,ftp://hunter2.example",
        ] {
            let err = Config::from_provider_urls(bad, false).unwrap_err();
            assert!(matches!(err, AnchorError::Config(_)), "{bad}: {err:?}");
            assert!(!format!("{err} {err:?}").contains("hunter2"), "{err}");
        }
    }

    #[test]
    fn hosts_under_one_registrable_looking_domain_are_refused() {
        for (a, b, domain) in [
            (
                "https://a.example.com",
                "https://b.example.com",
                "example.com",
            ),
            (
                "https://example.com",
                "https://beacon.Example.COM.",
                "example.com",
            ),
            (
                "https://x.y.provider.io:1",
                "https://z.provider.io/p",
                "provider.io",
            ),
        ] {
            for err in [
                Config::from_toml(&two(("a", "A", a), ("b", "B", b), "")).unwrap_err(),
                Config::from_provider_urls(&format!("{a},{b}"), false).unwrap_err(),
            ] {
                assert!(
                    matches!(&err, AnchorError::SameDomain { domain: d, .. } if d == domain),
                    "{a} {b}: {err:?}"
                );
                assert_eq!(err.name(), "same_domain");
                assert_eq!(err.exit_code(), 2);
            }
        }
        // Different last two labels, IP literals, and single-label names pass.
        for (a, b) in [
            ("https://a.example.com", "https://a.example.org"),
            ("https://beacon.a-op.net", "https://beacon.b-op.net"),
            ("https://10.0.0.1", "https://10.0.0.2"),
            ("https://[::1]", "https://localhost"),
        ] {
            assert!(
                Config::from_provider_urls(&format!("{a},{b}"), false).is_ok(),
                "{a} {b}"
            );
        }
    }

    #[test]
    fn load_reports_a_missing_file() {
        let err = Config::load(Path::new("/nonexistent/anchor-fetch.toml")).unwrap_err();
        assert!(matches!(err, AnchorError::Io { .. }));
    }
}
