//! The neighbourhood a peer's column answer places are counted against
//! ([`super::limits::ColumnPlaces`], `RpcLimits::max_column_answers_per_ip`).
//!
//! A host that holds a block of neighbouring addresses could take one place per address if the
//! cap counted exact IPs. So the places of one IPv4 /24 ([`DEFAULT_ANSWER_IPV4_PREFIX`]) or one
//! IPv6 /48 ([`DEFAULT_ANSWER_IPV6_PREFIX`]) are counted together \[est\]: the smallest blocks
//! commonly handed to one customer or site. An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is
//! that IPv4 address, so a dual-stack listener cannot be used to escape the IPv4 count. Both
//! prefix lengths are configurable ([`AnswerPrefixes`]); a length past the family's width counts
//! exact addresses.

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The IPv4 prefix length whose addresses share their column answer places by default: /24.
pub const DEFAULT_ANSWER_IPV4_PREFIX: u8 = 24;

/// The IPv6 prefix length whose addresses share their column answer places by default: /48.
pub const DEFAULT_ANSWER_IPV6_PREFIX: u8 = 48;

/// The prefix of an address its peers' column answer places are counted against.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum AnswerBucket {
    /// The address with every bit past the IPv4 prefix cleared.
    V4(Ipv4Addr),
    /// The address with every bit past the IPv6 prefix cleared.
    V6(Ipv6Addr),
}

/// How wide an [`AnswerBucket`] is in each family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnswerPrefixes {
    /// IPv4 prefix length; 32 or more counts exact addresses.
    pub ipv4: u8,
    /// IPv6 prefix length; 128 or more counts exact addresses.
    pub ipv6: u8,
}

impl Default for AnswerPrefixes {
    /// [`DEFAULT_ANSWER_IPV4_PREFIX`] and [`DEFAULT_ANSWER_IPV6_PREFIX`].
    fn default() -> Self {
        Self {
            ipv4: DEFAULT_ANSWER_IPV4_PREFIX,
            ipv6: DEFAULT_ANSWER_IPV6_PREFIX,
        }
    }
}

/// The `bits` high bits of a `width`-bit value set, the rest clear.
fn mask(bits: u8, width: u32) -> u128 {
    let bits = u32::from(bits).min(width);
    match bits {
        0 => 0,
        bits => (u128::MAX << (128 - bits)) >> (128 - width),
    }
}

impl AnswerPrefixes {
    /// The bucket of `ip`; an IPv4-mapped IPv6 address is bucketed as its IPv4 address.
    #[must_use]
    pub fn bucket(&self, ip: IpAddr) -> AnswerBucket {
        let v4 = |ip: Ipv4Addr| {
            let bits = u128::from(u32::from(ip)) & mask(self.ipv4, 32);
            AnswerBucket::V4(Ipv4Addr::from(
                u32::try_from(bits).expect("masked to 32 bits"),
            ))
        };
        match ip {
            IpAddr::V4(ip) => v4(ip),
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(mapped) => v4(mapped),
                None => AnswerBucket::V6(Ipv6Addr::from(u128::from(ip) & mask(self.ipv6, 128))),
            },
        }
    }

    /// The bucket of the IP `remote` starts with (after an `/ip6zone`, which names an
    /// interface), `None` if it starts with no IP.
    #[must_use]
    pub fn of(&self, remote: &Multiaddr) -> Option<AnswerBucket> {
        let mut parts = remote.iter();
        let first = match parts.next()? {
            Protocol::Ip6zone(_) => parts.next()?,
            other => other,
        };
        match first {
            Protocol::Ip4(ip) => Some(self.bucket(IpAddr::V4(ip))),
            Protocol::Ip6(ip) => Some(self.bucket(IpAddr::V6(ip))),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(prefixes: AnswerPrefixes, ip: &str) -> AnswerBucket {
        prefixes.bucket(ip.parse().unwrap())
    }

    #[test]
    fn ipv4_addresses_share_their_slash_24() {
        let p = AnswerPrefixes::default();
        let one = bucket(p, "203.0.113.7");
        assert_eq!(one, AnswerBucket::V4(Ipv4Addr::new(203, 0, 113, 0)));
        assert_eq!(bucket(p, "203.0.113.250"), one);
        assert_eq!(bucket(p, "203.0.113.0"), one);
        assert_ne!(bucket(p, "203.0.114.7"), one);
        assert_ne!(bucket(p, "198.51.100.7"), one);
    }

    #[test]
    fn ipv6_addresses_share_their_slash_48() {
        let p = AnswerPrefixes::default();
        let one = bucket(p, "2001:db8:1:2::7");
        assert_eq!(one, AnswerBucket::V6("2001:db8:1::".parse().unwrap()));
        assert_eq!(bucket(p, "2001:db8:1:ffff:ffff::1"), one);
        assert_ne!(bucket(p, "2001:db8:2::7"), one);
        assert_ne!(bucket(p, "2001:db9:1::7"), one);
    }

    #[test]
    fn an_ipv4_mapped_ipv6_address_counts_as_its_ipv4_address() {
        let p = AnswerPrefixes::default();
        assert_eq!(bucket(p, "::ffff:203.0.113.9"), bucket(p, "203.0.113.7"));
        assert_ne!(bucket(p, "::ffff:203.0.114.9"), bucket(p, "203.0.113.7"));
        // Not mapped: an IPv6 address of its own, though its low bits spell the same.
        assert!(matches!(bucket(p, "::203.0.113.9"), AnswerBucket::V6(_)));
    }

    #[test]
    fn the_prefixes_are_configurable() {
        let exact = AnswerPrefixes {
            ipv4: 32,
            ipv6: 128,
        };
        assert_ne!(bucket(exact, "203.0.113.7"), bucket(exact, "203.0.113.8"));
        assert_ne!(bucket(exact, "2001:db8::1"), bucket(exact, "2001:db8::2"));
        // A length past the family's width counts exact addresses too.
        let over = AnswerPrefixes {
            ipv4: 40,
            ipv6: 200,
        };
        assert_eq!(
            bucket(over, "203.0.113.7"),
            AnswerBucket::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
        assert_eq!(
            bucket(over, "2001:db8::1"),
            AnswerBucket::V6("2001:db8::1".parse().unwrap())
        );
        let wide = AnswerPrefixes { ipv4: 8, ipv6: 0 };
        assert_eq!(bucket(wide, "10.1.2.3"), bucket(wide, "10.200.0.1"));
        assert_eq!(bucket(wide, "2001:db8::1"), bucket(wide, "fd00::1"));
    }

    #[test]
    fn a_remote_address_is_bucketed_by_the_ip_it_starts_with() {
        let p = AnswerPrefixes::default();
        let addr = |s: &str| s.parse::<Multiaddr>().unwrap();
        assert_eq!(
            p.of(&addr("/ip4/203.0.113.7/tcp/9000")),
            Some(bucket(p, "203.0.113.1"))
        );
        assert_eq!(
            p.of(&addr("/ip6/::ffff:203.0.113.7/tcp/9000")),
            Some(bucket(p, "203.0.113.1"))
        );
        assert_eq!(
            p.of(&addr("/ip6/2001:db8:1::5/tcp/9000")),
            Some(bucket(p, "2001:db8:1:9::"))
        );
        // A zone names the interface, not the address: the address after it is bucketed.
        assert_eq!(
            p.of(&addr("/ip6zone/eth0/ip6/fe80::1:2/tcp/9000")),
            Some(bucket(p, "fe80::"))
        );
        assert_eq!(p.of(&addr("/ip6zone/eth0/dns6/example.org/tcp/9000")), None);
        assert_eq!(p.of(&addr("/dns4/example.org/tcp/9000")), None);
        assert_eq!(p.of(&Multiaddr::empty()), None);
    }
}
