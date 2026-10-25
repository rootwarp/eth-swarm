//! The IP rules of a network mode ([`NetworkMode`]): which addresses a node may contact. cl-discv5
//! holds every record of its routing table to them, and cl-p2p every address it dials, so the
//! two use one rule ([`ip_rule`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Which addresses a node may contact: the routing table's rules in cl-discv5, and the dial
/// rule in cl-p2p.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// A public network: every address a record advertises must be globally routable.
    Public,
    /// A local devnet: loopback and private addresses are accepted too.
    Devnet,
    /// Local addresses only ([`is_local_ip`]): loopback, private, link-local, CGNAT and IPv6
    /// unique-local. For a probe on a devnet's own network (a Docker bridge), which must send
    /// nothing to a public host whatever a peer hands it.
    Local,
}

/// The per-address rule of `mode`: every address a record advertises must pass it, and so must
/// the source of a discv5 session and every address cl-p2p dials. No mode passes a cloud
/// metadata service ([`is_cloud_metadata`]).
#[must_use]
pub fn ip_rule(mode: NetworkMode) -> fn(IpAddr) -> bool {
    match mode {
        NetworkMode::Public => public_ip,
        NetworkMode::Devnet => devnet_ip,
        NetworkMode::Local => is_local_ip,
    }
}

/// The address of a cloud instance metadata service: 169.254.169.254 (AWS, GCP, Azure and most
/// others), also IPv4-mapped, and AWS's IPv6 endpoint fd00:ec2::254. No mode contacts one, so a
/// record cannot make a node on a cloud host send to the service that holds its credentials.
#[must_use]
pub fn is_cloud_metadata(ip: IpAddr) -> bool {
    const V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
    const V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);
    match ip {
        IpAddr::V4(v4) => v4 == V4,
        IpAddr::V6(v6) => v6 == V6 || v6.to_ipv4_mapped() == Some(V4),
    }
}

fn public_ip(ip: IpAddr) -> bool {
    if is_cloud_metadata(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

/// A local address: IPv4 loopback (127/8), private (10/8, 172.16/12, 192.168/16), link-local
/// (169.254/16) or shared CGNAT space (100.64/10); IPv6 loopback, unique-local (fc00::/7) or
/// link-local (fe80::/10). An IPv4-mapped address is judged as its IPv4 address. A cloud
/// metadata service ([`is_cloud_metadata`]) is not one.
#[must_use]
pub fn is_local_ip(ip: IpAddr) -> bool {
    if is_cloud_metadata(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            let cgnat = a == 100 && (b & 0xc0) == 64;
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || cgnat
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_local_ip(IpAddr::V4(v4)),
            None => {
                let first = v6.segments()[0];
                v6.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
            }
        },
    }
}

fn devnet_ip(ip: IpAddr) -> bool {
    if is_cloud_metadata(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => is_contactable_v4(v4),
        IpAddr::V6(v6) => is_contactable_v6(v6),
    }
}

fn is_contactable_v4(ip: Ipv4Addr) -> bool {
    // 0.0.0.0/8 is "this network", never a destination.
    !(ip.octets()[0] == 0 || ip.is_broadcast() || ip.is_multicast())
}

/// An IPv4-mapped address is judged as the IPv4 address it maps.
fn is_contactable_v6(ip: Ipv6Addr) -> bool {
    ip.to_ipv4_mapped().map_or_else(
        || !(ip.is_unspecified() || ip.is_multicast()),
        is_contactable_v4,
    )
}

/// Globally reachable IPv4: the exclusions of std's unstable `Ipv4Addr::is_global` (the IANA
/// IPv4 special-purpose address registry), and never multicast.
fn is_global_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    // 100.64.0.0/10, shared address space (carrier-grade NAT).
    let shared = a == 100 && (b & 0xc0) == 64;
    // 192.0.0.0/24, IETF protocol assignments, except 192.0.0.9 and 192.0.0.10 (PCP and TURN
    // anycast, globally reachable).
    let protocol_assignments = a == 192 && b == 0 && c == 0 && d != 9 && d != 10;
    // 198.18.0.0/15, benchmarking.
    let benchmarking = a == 198 && (b & 0xfe) == 18;
    // 240.0.0.0/4, reserved, and the broadcast address in it.
    let reserved = a >= 240;
    is_contactable_v4(ip)
        && !(ip.is_private()
            || ip.is_loopback()
            || ip.is_link_local()
            || ip.is_documentation()
            || shared
            || protocol_assignments
            || benchmarking
            || reserved)
}

/// Globally reachable IPv6: global unicast (2000::/3) minus the exclusions of std's unstable
/// `Ipv6Addr::is_global` that fall in it, plus the documentation prefix 3fff::/20. Everything
/// else std excludes (unspecified, loopback, IPv4-mapped, 64:ff9b:1::/48, 100::/64, unique
/// local, link local, 5f00::/16, multicast) is outside 2000::/3.
fn is_global_v6(ip: Ipv6Addr) -> bool {
    let bits = u128::from(ip);
    let [s0, s1, s2, ..] = ip.segments();
    let global_unicast = (s0 & 0xe000) == 0x2000;
    // 2001::/23, IETF protocol assignments (Teredo, benchmarking 2001:2::/48, ORCHID, ...),
    // except the parts IANA lists as globally reachable.
    let protocol_assignments = s0 == 0x2001
        && s1 < 0x200
        && !(bits == 0x2001_0001_0000_0000_0000_0000_0000_0001 // 2001:1::1, PCP anycast
            || bits == 0x2001_0001_0000_0000_0000_0000_0000_0002 // 2001:1::2, TURN anycast
            || s1 == 3 // 2001:3::/32, AMT
            || (s1 == 4 && s2 == 0x112) // 2001:4:112::/48, AS112-v6
            || (0x20..=0x3f).contains(&s1)); // 2001:20::/28 ORCHIDv2, 2001:30::/28 DETs
                                             // 2002::/16, 6to4.
    let six_to_four = s0 == 0x2002;
    // 2001:db8::/32 and 3fff::/20, documentation.
    let documentation = (s0 == 0x2001 && s1 == 0x0db8) || (s0 == 0x3fff && s1 < 0x1000);
    global_unicast && !(protocol_assignments || six_to_four || documentation)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each mode's rule on one address of each kind. cl-discv5's routing-table tests hold every
    /// range boundary through the same rules.
    /// The cloud metadata services are contacted in no mode, also as IPv4-mapped addresses; the
    /// rest of link-local and unique-local space keeps the rule of its mode.
    #[test]
    fn no_mode_contacts_a_cloud_metadata_service() {
        for text in ["169.254.169.254", "::ffff:169.254.169.254", "fd00:ec2::254"] {
            let ip: IpAddr = text.parse().unwrap();
            assert!(is_cloud_metadata(ip), "{text}");
            assert!(!is_local_ip(ip), "{text}: local");
            for mode in [NetworkMode::Public, NetworkMode::Devnet, NetworkMode::Local] {
                assert!(!ip_rule(mode)(ip), "{text} in {mode:?}");
            }
        }
        for text in ["169.254.169.253", "fd00:ec2::253"] {
            let ip: IpAddr = text.parse().unwrap();
            assert!(!is_cloud_metadata(ip), "{text}");
            assert!(ip_rule(NetworkMode::Local)(ip), "{text} stays local");
            assert!(ip_rule(NetworkMode::Devnet)(ip), "{text} stays contactable");
        }
    }

    #[test]
    fn each_mode_has_its_rule() {
        let cases: [(&str, bool, bool, bool); 12] = [
            // (address, public, devnet, local)
            ("8.8.8.8", true, true, false),
            ("10.0.0.2", false, true, true),
            ("127.0.0.1", false, true, true),
            ("100.64.0.1", false, true, true),
            ("192.0.2.1", false, true, false),
            ("0.1.2.3", false, false, false),
            ("224.0.0.1", false, false, false),
            ("2001:4860::8888", true, true, false),
            ("2001:db8::1", false, true, false),
            ("fd00::2", false, true, true),
            ("::ffff:10.0.0.1", false, true, true),
            ("ff02::1", false, false, false),
        ];
        for (ip, public, devnet, local) in cases {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(ip_rule(NetworkMode::Public)(ip), public, "public {ip}");
            assert_eq!(ip_rule(NetworkMode::Devnet)(ip), devnet, "devnet {ip}");
            assert_eq!(ip_rule(NetworkMode::Local)(ip), local, "local {ip}");
        }
    }
}
