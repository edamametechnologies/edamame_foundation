use crate::lanscan_interface::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::trace;

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

pub fn apply_mask_v6(ip_addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mask: u128 = if prefix == 0 {
        0
    } else {
        !0u128 << (128 - prefix)
    };
    Ipv6Addr::from(u128::from(ip_addr) & mask)
}

pub fn is_link_local_ipv6(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            // Check that the address is fe80::/10.
            (segments[0] & 0xffc0) == 0xfe80
        }
        _ => false,
    }
}

pub fn is_lan_ipv6(ip: &IpAddr, interfaces: &LANScanInterfaces) -> bool {
    // Scan all the interfaces and check if any of the interfaces' IPv6 share the same LAN prefix
    for interface in interfaces.iter() {
        for interface_ip in interface.ipv6.clone() {
            let (interface_ip_v6, interface_prefix) = match interface_ip {
                LANScanInterfaceAddrTypeV6::Temporary(ipv6) => (ipv6.ip, ipv6.prefix),
                LANScanInterfaceAddrTypeV6::Secured(ipv6) => (ipv6.ip, ipv6.prefix),
                LANScanInterfaceAddrTypeV6::LinkLocal(ipv6) => (ipv6.ip, ipv6.prefix),
                LANScanInterfaceAddrTypeV6::Local(ipv6) => (ipv6.ip, ipv6.prefix),
                LANScanInterfaceAddrTypeV6::Unspecified(ipv6) => (ipv6.ip, ipv6.prefix),
            };
            // Apply the mask to the IP addresses
            let masked_interface_ip = apply_mask_v6(interface_ip_v6, interface_prefix);
            let masked_ip = match ip {
                IpAddr::V6(ipv6) => apply_mask_v6(*ipv6, interface_prefix),
                _ => return false,
            };
            if masked_interface_ip == masked_ip {
                return true;
            }
        }
    }
    false
}

pub fn is_private_ipv6(ip: &IpAddr, interfaces: &LANScanInterfaces) -> bool {
    match ip {
        // fc00::/7
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            segments[0] == 0xfc00 || segments[0] == 0xfd00 || is_lan_ipv6(ip, interfaces)
        }
        _ => false,
    }
}

// Pass in the interfaces in order to check if an IPv6 is local using the system interface's prefixes (optional)
pub fn is_local_ip(ip: &IpAddr, interfaces: Option<&LANScanInterfaces>) -> bool {
    let local = match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_loopback()
                || ipv4.is_multicast()
                || ipv4.is_unspecified()
                || ipv4.is_broadcast()
        }
        IpAddr::V6(ipv6) => {
            let is_private = if let Some(interfaces) = interfaces {
                is_private_ipv6(ip, interfaces)
            } else {
                false
            };
            is_private
                || is_link_local_ipv6(ip)
                || ipv6.is_loopback()
                || ipv6.is_multicast()
                || ipv6.is_unspecified()
        }
    };
    if local {
        trace!("IP address {:?} is not eligible", ip);
    } else {
        trace!("IP address {:?} is eligible", ip);
    }
    local
}
