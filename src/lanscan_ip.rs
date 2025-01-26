use std::net::IpAddr;
use tracing::trace;

pub fn is_link_local_ipv6(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(ipv6) => ipv6.to_string().starts_with("fe80"),
        _ => false,
    }
}

pub fn is_private_ipv6(ip: &IpAddr) -> bool {
    match ip {
        // fc00::/7
        IpAddr::V6(ipv6) => {
            ipv6.to_string().starts_with("fc00") || ipv6.to_string().starts_with("fd00")
        }
        _ => false,
    }
}

pub fn is_local_ip(ip: &IpAddr) -> bool {
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
            is_private_ipv6(ip)
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
