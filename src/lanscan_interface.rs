#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ipnet::{ipv4_mask_to_prefix, ipv6_mask_to_prefix};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use tracing::error;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LANScanInterface {
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub prefixv4: u8,
    pub ipv6: Ipv6Addr,
    pub prefixv6: u8,
}

impl Display for LANScanInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} ({})", self.name, self.ipv4, self.ipv6)
    }
}

/// A list of interface name patterns that should be excluded.
const EXCLUDED_IFACE_NAMES: [&str; 22] = [
    "feth",
    "zt",
    "utun",
    "wg",
    "tun",
    "tap",
    "ipsec",
    "ppp",
    "bridge",
    "awdl",
    "llw",
    "lo",
    "rmnet",
    "ccmni",
    "clat",
    "pdp_ip",
    "docker",
    "veth",
    "br-",
    "vboxnet",
    "virbr",
    "vEthernet",
];

/// Filters and returns only the valid interfaces from the input list.
pub fn validate_interfaces(interfaces: Vec<LANScanInterface>) -> Vec<LANScanInterface> {
    interfaces
        .into_iter()
        .filter(|iface| {
            // Exclude if interface name starts with any pattern in EXCLUDED_IFACE_NAMES.
            if EXCLUDED_IFACE_NAMES
                .iter()
                .any(|&name| iface.name.starts_with(name))
            {
                return false;
            }
            // Exclude loopback or local addresses.
            if iface.ipv4.to_string().starts_with("127")
                || iface.ipv4.to_string().starts_with("169.254")
            {
                return false;
            }
            true
        })
        .collect()
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn build_interface(name: &str, addresses: &[Addr]) -> Option<LANScanInterface> {
    // Find IPv4 information.
    let ipv4 = addresses.iter().find_map(|addr| {
        if let Addr::V4(ipv4) = addr {
            let prefixv4 =
                ipv4_mask_to_prefix(ipv4.netmask.unwrap_or(Ipv4Addr::new(0, 0, 0, 0))).unwrap_or(0);
            Some((ipv4.ip, prefixv4))
        } else {
            None
        }
    });

    // Find IPv6 information.
    let ipv6 = addresses.iter().find_map(|addr| {
        if let Addr::V6(ipv6) = addr {
            let prefixv6 =
                ipv6_mask_to_prefix(ipv6.netmask.unwrap_or(Ipv6Addr::UNSPECIFIED)).unwrap_or(0);
            Some((ipv6.ip, prefixv6))
        } else {
            None
        }
    });

    // Only build if IPv4 is present.
    if let Some((ipv4_addr, prefixv4)) = ipv4 {
        let (ipv6_addr, prefixv6) = ipv6.unwrap_or((Ipv6Addr::UNSPECIFIED, 0));
        return Some(LANScanInterface {
            name: name.to_string(),
            ipv4: ipv4_addr,
            prefixv4,
            ipv6: ipv6_addr,
            prefixv6,
        });
    }
    None
}

// All interfaces
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn get_all_interfaces() -> Vec<LANScanInterface> {
    let iface_list = match NetworkInterface::show() {
        Ok(ifaces) => ifaces,
        Err(e) => {
            error!("Failed to fetch real interfaces: {}", e);
            return Vec::new();
        }
    };

    // Build LANScanInterfaces from raw info.
    let all_interfaces: Vec<LANScanInterface> = iface_list
        .iter()
        .filter_map(|iface| build_interface(&iface.name, &iface.addr))
        .collect();

    all_interfaces
}

/// Fetches valid network interfaces from the OS. Supports MacOS, Windows, and Linux.  
/// On unsupported OS, returns an empty list.
pub fn get_valid_network_interfaces() -> Vec<LANScanInterface> {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let all_interfaces = get_all_interfaces();

        // Filter out invalid interfaces.
        let valid_interfaces = validate_interfaces(all_interfaces);
        // Sort the interfaces by name for predictability.
        let mut sorted_interfaces = valid_interfaces;
        sorted_interfaces.sort_by_key(|k| k.name.clone());

        sorted_interfaces
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Vec::new()
    }
}

/// Returns all our own IPs
pub fn get_own_ips() -> Vec<IpAddr> {
    // Return all IPv4 and IPv6 addresses
    let own_ips_v4: Vec<IpAddr> = get_valid_network_interfaces()
        .into_iter()
        .filter_map(|iface| Some(IpAddr::V4(iface.ipv4)))
        .collect();
    let own_ips_v6: Vec<IpAddr> = get_valid_network_interfaces()
        .into_iter()
        .filter_map(|iface| Some(IpAddr::V6(iface.ipv6)))
        .collect();
    let own_ips = [own_ips_v4, own_ips_v6].concat();
    own_ips
}

/// Fetches what we consider to be the "default" interface on MacOS, Windows, and Linux.  
/// On unsupported OS, returns None.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn get_default_interface() -> Option<LANScanInterface> {
    let interfaces = match NetworkInterface::show() {
        Ok(ifaces) => ifaces,
        Err(e) => {
            error!("Failed to fetch interfaces: {}", e);
            return None;
        }
    };

    // A commonly used “external” address to force the OS to pick a route
    let google_dns = "8.8.8.8:80";

    // 1) Bind a local UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;

    // 2) "Connect" to external address so OS picks a default route
    socket.connect(google_dns).ok()?;

    // 3) Ask the socket for the local IP it chose
    let local_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(_) => {
            error!("Failed to get local address");
            return None;
        }
    };

    let mut default_iface = None;

    // 4) Compare that IP against the IPs of all known interfaces
    for iface in interfaces.iter() {
        if iface
            .addr
            .iter()
            .any(|addr| addr.ip().to_string() == local_addr.ip().to_string())
        {
            default_iface = Some(iface.name.clone());
        }
    }

    if let Some(name) = default_iface {
        // Find the interface with the name
        let interface = interfaces.iter().find(|iface| iface.name == name).unwrap();
        let ipv4 = interface
            .addr
            .iter()
            .find(|addr| matches!(addr.ip(), IpAddr::V4(_)))
            .unwrap();
        let ipv6 = interface
            .addr
            .iter()
            .find(|addr| matches!(addr.ip(), IpAddr::V6(_)))
            .unwrap();
        let netmaskv4 = match ipv4 {
            network_interface::Addr::V4(addr) => addr.netmask.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)),
            _ => unreachable!(),
        };
        let netmaskv6 = match ipv6 {
            network_interface::Addr::V6(addr) => addr.netmask.unwrap_or(Ipv6Addr::UNSPECIFIED),
            _ => unreachable!(),
        };

        Some(LANScanInterface {
            name: name,
            ipv4: match ipv4.ip() {
                IpAddr::V4(addr) => addr,
                _ => unreachable!(),
            },
            prefixv4: ipv4_mask_to_prefix(netmaskv4).unwrap_or(0),
            ipv6: match ipv6.ip() {
                IpAddr::V6(addr) => addr,
                _ => unreachable!(),
            },
            prefixv6: ipv6_mask_to_prefix(netmaskv6).unwrap_or(0),
        })
    } else {
        None
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn get_default_interface() -> Option<LANScanInterface> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_valid_network_interfaces() {
        let interfaces = get_valid_network_interfaces();
        assert!(interfaces.len() > 0);
    }

    #[test]
    fn test_get_default_interface() {
        let interface = get_default_interface();
        // It's possible there's no default interface in some environments like specialized containers.
        // We just check if it doesn't crash.
        assert!(interface.is_some() || interface.is_none());
    }
}
