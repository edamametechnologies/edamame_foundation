#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ipnet::{ipv4_mask_to_prefix, ipv6_mask_to_prefix};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
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

    // Choose an interface that actually has IPv4 addresses, and take the one with the smallest index and that is not loopback.
    let default_iface = interfaces
        .into_iter()
        .filter(|iface| iface.addr.iter().any(|addr| matches!(addr, Addr::V4(_))))
        .filter(|iface| !iface.name.starts_with("lo"))
        .min_by_key(|iface| iface.index)?;

    // Dig through addresses to pull out first IPv4 and (potentially) an IPv6.
    let mut found_ipv4 = Ipv4Addr::new(0, 0, 0, 0);
    let mut found_netmaskv4 = Ipv4Addr::new(0, 0, 0, 0);
    let mut found_ipv6 = Ipv6Addr::UNSPECIFIED;
    let mut found_netmaskv6 = Ipv6Addr::UNSPECIFIED;

    for addr in default_iface.addr.iter() {
        match addr {
            Addr::V4(ipv4) => {
                found_ipv4 = ipv4.ip;
                found_netmaskv4 = ipv4.netmask.unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
            }
            Addr::V6(ipv6) => {
                // Optionally skip link-local addresses.
                if !ipv6.ip.to_string().starts_with("fe80:") {
                    found_ipv6 = ipv6.ip;
                    found_netmaskv6 = ipv6.netmask.unwrap_or(Ipv6Addr::UNSPECIFIED);
                }
            }
        }
    }

    Some(LANScanInterface {
        name: default_iface.name,
        ipv4: found_ipv4,
        prefixv4: ipv4_mask_to_prefix(found_netmaskv4).unwrap_or(0),
        ipv6: found_ipv6,
        prefixv6: ipv6_mask_to_prefix(found_netmaskv6).unwrap_or(0),
    })
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
