use crate::lanscan_interface::*;
use dashmap::DashMap;
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, trace};

lazy_static! {
    /// A concurrent cache of IP addresses that are known to be local.
    /// Limited to MAX_CACHE_SIZE entries
    static ref KNOWN_LOCAL_IP_CACHE: DashMap<IpAddr, std::time::Instant> = DashMap::new();

    /// A cache for LAN IPv6 network ranges.
    /// The key is the IPv6 prefix (u8) and the value is a set of network addresses (stored as a u128)
    /// computed by applying that prefix to each LAN IPv6 interface.
    static ref LAN_IPV6_LOCAL_NETS: DashMap<u8, HashSet<u128>> = DashMap::new();

    /// Flag indicating if the local cache was initialized.
    static ref CACHE_INITIALIZED: AtomicBool = AtomicBool::new(false);
}

const MAX_CACHE_SIZE: usize = 10000;
const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600); // 1 hour

/// --------------------------------------------------------------------
/// Helper functions
/// --------------------------------------------------------------------

/// Converts an IPv4 address to a u32 (big‑endian).
#[inline(always)]
fn ipv4_to_u32(ip: &Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

/// Converts an IPv6 address to a u128 (big‑endian).
#[inline(always)]
fn ipv6_to_u128(ip: &Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

/// Applies a CIDR mask on an IPv6 address.
pub fn apply_mask_v6(ip_addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mask: u128 = if prefix == 0 {
        0
    } else {
        !0u128 << (128 - prefix)
    };
    Ipv6Addr::from(u128::from(ip_addr) & mask)
}

/// Fast IPv4 local IP check using bit‑wise comparisons.
#[inline(always)]
fn is_lan_ipv4_fast(ip: &Ipv4Addr) -> bool {
    let val = ipv4_to_u32(ip);

    // Check unspecified (0.0.0.0) and broadcast (255.255.255.255)
    if val == 0 || val == 0xFFFFFFFF {
        return true;
    }
    // Loopback: 127.0.0.0/8
    if (val >> 24) == 127 {
        return true;
    }
    // Multicast: 224.0.0.0/4 (upper 4 bits equal 0xE)
    if (val >> 28) == 0xE {
        return true;
    }
    // Link-local: 169.254.0.0/16
    if (val >> 16) == 0xA9FE {
        return true;
    }
    // Private ranges:
    // 10.0.0.0/8:
    if (val >> 24) == 10 {
        return true;
    }
    // 172.16.0.0/12:
    if (val >> 24) == 172 {
        let second = (val >> 16) & 0xFF;
        if second >= 16 && second <= 31 {
            return true;
        }
    }
    // 192.168.0.0/16:
    if (val >> 16) == 0xC0A8 {
        return true;
    }
    false
}

#[inline(always)]
pub fn is_link_local_ipv6(ip: &Ipv6Addr) -> bool {
    // Link-local (fe80::/10)
    let segs = ip.segments();
    (segs[0] & 0xffc0) == 0xfe80
}

pub fn is_private_ipv6(ip: &IpAddr) -> bool {
    match ip {
        // fc00::/7
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            segments[0] == 0xfc00 || segments[0] == 0xfd00
        }
        _ => false,
    }
}

#[inline(always)]
pub fn is_local_ipv6(ip: &Ipv6Addr) -> bool {
    let segs = ip.segments();
    // Check unspecified (::)
    if ip.is_unspecified() {
        return true;
    }
    // Check loopback (::1)
    if ip.is_loopback() {
        return true;
    }
    // Multicast (ff00::/8)
    if (segs[0] & 0xff00) == 0xff00 {
        return true;
    }
    // Unique local (fc00::/7)
    if (segs[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    false
}

/// Fast LAN IPv6 check that uses the precomputed LAN cache.
/// For each prefix in the cache, the candidate IPv6 address is masked and its network number
/// is checked for membership.
#[inline(always)]
fn is_lan_ipv6_fast(ip: &Ipv6Addr) -> bool {
    let ip_u128 = ipv6_to_u128(ip);
    for entry in LAN_IPV6_LOCAL_NETS.iter() {
        let prefix = *entry.key();
        let mask = if prefix == 0 {
            0
        } else {
            !0u128 << (128 - prefix)
        };
        let candidate_network = ip_u128 & mask;
        if entry.value().contains(&candidate_network) {
            return true;
        }
    }
    false
}

/// --------------------------------------------------------------------
/// Initialization function to build the local cache based on current interfaces.
///
/// This must be called externally (e.g. when the interfaces change)
/// so that LAN_IPV6_LOCAL_NETS and KNOWN_LOCAL_IP_CACHE are up-to-date.
/// --------------------------------------------------------------------
pub fn init_local_cache(interfaces: &LANScanInterfaces) {
    // Clear any existing caches.
    KNOWN_LOCAL_IP_CACHE.clear();
    LAN_IPV6_LOCAL_NETS.clear();

    // For each interface's IPv6 address, compute its network (by applying its CIDR prefix)
    // and store the network number in the LAN IPv6 cache.
    for interface in interfaces.iter() {
        for addr in &interface.ipv6 {
            let (ip, prefix) = match addr {
                LANScanInterfaceAddrTypeV6::Temporary(info)
                | LANScanInterfaceAddrTypeV6::Secured(info)
                | LANScanInterfaceAddrTypeV6::Unspecified(info) => (info.ip, info.prefix),
                // No need to use the LinkLocal or Local addresses, as they will be filtered out by the basic IPv6 check.
                LANScanInterfaceAddrTypeV6::LinkLocal(_info)
                | LANScanInterfaceAddrTypeV6::Local(_info) => continue,
            };
            let masked = apply_mask_v6(ip, prefix);
            let net = ipv6_to_u128(&masked);
            LAN_IPV6_LOCAL_NETS.entry(prefix).or_default().insert(net);
        }
    }
    trace!(
        "Local cache initialized with {} LAN IPv6 prefixes",
        LAN_IPV6_LOCAL_NETS.len()
    );
    CACHE_INITIALIZED.store(true, Ordering::Relaxed);
}

/// --------------------------------------------------------------------
/// Main local IP check function.  
///
/// This function uses fast numeric checks for IPv4 and IPv6,
/// and consults the precomputed LAN cache for IPv6.  
/// --------------------------------------------------------------------
pub fn is_lan_ip(ip: &IpAddr) -> bool {
    if KNOWN_LOCAL_IP_CACHE.len() > MAX_CACHE_SIZE {
        cleanup_cache();
    }
    if !CACHE_INITIALIZED.load(Ordering::Relaxed) {
        error!(
            "is_local_ip called without an initialized cache. Please run init_local_cache first."
        );
    }

    // First, check if the IP is already in our known-local cache.
    if KNOWN_LOCAL_IP_CACHE.contains_key(ip) {
        trace!("IP address {:?} found in known-local cache", ip);
        return true;
    }

    let local = match ip {
        IpAddr::V4(ipv4) => is_lan_ipv4_fast(ipv4),
        IpAddr::V6(ipv6) => {
            // Do basic IPv6 local checks.
            if is_local_ipv6(ipv6) {
                true
            } else {
                // Otherwise, check against the precomputed LAN IPv6 networks.
                is_lan_ipv6_fast(ipv6)
            }
        }
    };

    // Cache the result for faster future lookups.
    if local {
        KNOWN_LOCAL_IP_CACHE.insert(ip.clone(), std::time::Instant::now());
        trace!("IP address {:?} determined local and cached", ip);
    } else {
        trace!("IP address {:?} determined not local", ip);
    }
    local
}

/// Convert an IPv4 netmask to a CIDR prefix
pub fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// Utility to apply a prefix (CIDR) as a subnet mask on an IPv4
pub fn apply_mask(ip_addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(ip_addr) & mask)
}

fn cleanup_cache() {
    let now = std::time::Instant::now();
    KNOWN_LOCAL_IP_CACHE.retain(|_, v| now.duration_since(*v) < CACHE_TTL);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_ipv4_to_u32() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let num = ipv4_to_u32(&ip);
        assert_eq!(num, 3232235777); // 192.168.1.1 in big‑endian u32
    }

    #[test]
    fn test_ipv6_to_u128() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let num = ipv6_to_u128(&ip);
        let expected = u128::from_be_bytes(ip.octets());
        assert_eq!(num, expected);
    }

    #[test]
    fn test_apply_mask_v6() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        // Prefix 64: lower 64 bits should be zeroed
        let masked = apply_mask_v6(ip, 64);
        let expected: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert_eq!(masked, expected);

        // Prefix 128: should return the same address
        let full_masked = apply_mask_v6(ip, 128);
        assert_eq!(full_masked, ip);

        // Prefix 0: should return the unspecified address
        let zero_masked = apply_mask_v6(ip, 0);
        let expected_zero: Ipv6Addr = "::".parse().unwrap();
        assert_eq!(zero_masked, expected_zero);
    }

    #[test]
    fn test_is_local_ipv4() {
        // Check well‑known local IPv4 addresses
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_lan_ip(&loopback));

        let unspecified: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(is_lan_ip(&unspecified));

        let broadcast: IpAddr = "255.255.255.255".parse().unwrap();
        assert!(is_lan_ip(&broadcast));

        // Private IPv4 addresses
        let private1: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_lan_ip(&private1));

        let private2: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(is_lan_ip(&private2));

        let private3: IpAddr = "172.16.5.9".parse().unwrap();
        assert!(is_lan_ip(&private3));

        // Public IPv4 address should not be considered local.
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_lan_ip(&public));
    }

    #[test]
    fn test_is_local_ipv6() {
        // IPv6 loopback and unspecified should be local.
        let loopback: IpAddr = "::1".parse().unwrap();
        assert!(is_lan_ip(&loopback));

        let unspecified: IpAddr = "::".parse().unwrap();
        assert!(is_lan_ip(&unspecified));

        // Multicast address (ff00::/8 format) is caught by the basic IPv6 check.
        let multicast: IpAddr = "ff02::1".parse().unwrap();
        assert!(is_lan_ip(&multicast));

        // Link-local check.
        let link_local: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_lan_ip(&link_local));

        // Global unicast address not matching any special criteria is not local.
        let global: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!is_lan_ip(&global));
    }

    #[test]
    fn test_is_link_local_ipv6() {
        let link_local: Ipv6Addr = "fe80::1234".parse().unwrap();
        assert!(is_link_local_ipv6(&link_local));

        let non_link_local: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!is_link_local_ipv6(&non_link_local));
    }

    #[test]
    fn test_is_private_ipv6() {
        let private1: IpAddr = "fc00::1".parse().unwrap();
        let private2: IpAddr = "fd00::1".parse().unwrap();
        let non_private: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(is_private_ipv6(&private1));
        assert!(is_private_ipv6(&private2));
        assert!(!is_private_ipv6(&non_private));
    }

    #[test]
    fn test_mask_to_prefix() {
        let mask1: Ipv4Addr = "255.255.255.0".parse().unwrap();
        assert_eq!(mask_to_prefix(mask1), 24);

        let mask2: Ipv4Addr = "255.0.0.0".parse().unwrap();
        assert_eq!(mask_to_prefix(mask2), 8);

        let mask3: Ipv4Addr = "255.255.255.255".parse().unwrap();
        assert_eq!(mask_to_prefix(mask3), 32);

        let mask4: Ipv4Addr = "0.0.0.0".parse().unwrap();
        assert_eq!(mask_to_prefix(mask4), 0);
    }

    #[test]
    fn test_apply_mask_ipv4() {
        let ip: Ipv4Addr = "192.168.1.129".parse().unwrap();
        let masked = apply_mask(ip, 24);
        let expected: Ipv4Addr = "192.168.1.0".parse().unwrap();
        assert_eq!(masked, expected);

        let ip2: Ipv4Addr = "10.10.10.200".parse().unwrap();
        let masked2 = apply_mask(ip2, 8);
        let expected2: Ipv4Addr = "10.0.0.0".parse().unwrap();
        assert_eq!(masked2, expected2);

        let ip3: Ipv4Addr = "172.16.29.10".parse().unwrap();
        let masked3 = apply_mask(ip3, 12);
        let expected3: Ipv4Addr = "172.16.0.0".parse().unwrap();
        assert_eq!(masked3, expected3);
    }

    #[test]
    fn test_cache_behavior_ipv4() {
        // Clear the cache to ensure a clean slate.
        KNOWN_LOCAL_IP_CACHE.clear();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // The first call should determine the IP as local and cache it.
        assert!(is_lan_ip(&ip));
        // The IP should now appear in the KNOWN_LOCAL_IP_CACHE.
        assert!(KNOWN_LOCAL_IP_CACHE.contains_key(&ip));
    }

    #[test]
    fn test_lan_ipv6_cache() {
        // This test simulates a LAN IPv6 network range by inserting a network (derived
        // from a given IP and its prefix) into the LAN_IPV6_LOCAL_NETS cache. Afterward,
        // an IP within that LAN should return true for is_local_ip.

        // Clear caches.
        KNOWN_LOCAL_IP_CACHE.clear();
        LAN_IPV6_LOCAL_NETS.clear();

        // Define a LAN network with prefix 64 using a sample IPv6 address.
        let prefix: u8 = 64;
        let base_ip: Ipv6Addr = "2001:db8:abcd:12::1".parse().unwrap();
        let masked = apply_mask_v6(base_ip, prefix);
        let net = ipv6_to_u128(&masked);
        LAN_IPV6_LOCAL_NETS.entry(prefix).or_default().insert(net);

        // An IP within the same LAN (matching the network portion) should now be local.
        let local_ip: IpAddr = "2001:db8:abcd:12::1234".parse().unwrap();
        assert!(is_lan_ip(&local_ip));

        // An IP outside the LAN should not be local.
        let non_local_ip: IpAddr = "2001:db8:abcd:13::1234".parse().unwrap();
        assert!(!is_lan_ip(&non_local_ip));
    }
}
