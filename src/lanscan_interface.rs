#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ipnet::{ipv4_mask_to_prefix, ipv6_mask_to_prefix};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};
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

pub fn validate_interfaces(interfaces: Vec<LANScanInterface>) -> Vec<LANScanInterface> {
    let mut valid_interfaces = Vec::new();
    for iface in interfaces {
        // Check if the interface name is excluded
        if EXCLUDED_IFACE_NAMES
            .iter()
            .any(|&name| iface.name.starts_with(name))
        {
            continue;
        }

        // Exclude loopback or local addresses
        if iface.ipv4.to_string().starts_with("127")
            || iface.ipv4.to_string().starts_with("169.254")
        {
            continue;
        }

        valid_interfaces.push(iface);
    }

    valid_interfaces
}

pub fn get_valid_network_interfaces() -> Vec<LANScanInterface> {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let iface_list = match network_interface::NetworkInterface::show() {
            Ok(ifaces) => ifaces,
            Err(e) => {
                error!("Failed to fetch real interfaces: {}", e);
                return Vec::new();
            }
        };

        let mut valid_interfaces = Vec::new();
        for iface in iface_list {
            // We look for an IPv4 with a prefix:
            let ipv4_addr = iface.addr.iter().find_map(|a| {
                if let network_interface::Addr::V4(ipv4) = a {
                    Some((ipv4.ip, ipv4.netmask))
                } else {
                    None
                }
            });
            if let Some((ipv4, mask_opt)) = ipv4_addr {
                let prefixv4 = if let Some(mask) = mask_opt {
                    ipv4_mask_to_prefix(mask).unwrap_or(0)
                } else {
                    0
                };

                valid_interfaces.push(LANScanInterface {
                    name: iface.name.clone(),
                    ipv4,
                    prefixv4,
                    ipv6: Ipv6Addr::UNSPECIFIED,
                    prefixv6: 0,
                });
            }
        }

        // Validate the interfaces
        valid_interfaces = validate_interfaces(valid_interfaces);

        // Sort the interfaces by name
        valid_interfaces.sort_by_key(|k| k.name.clone());

        valid_interfaces
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        // On unsupported OS, just return an empty list for now
        vec![]
    }
}

// Get the default interface name
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn get_default_interface() -> Option<LANScanInterface> {
    // Gather all interfaces using network_interface
    let interfaces = match NetworkInterface::show() {
        Ok(ifaces) => ifaces,
        Err(e) => {
            error!("Failed to fetch interfaces: {}", e);
            return None;
        }
    };

    // Pick the interface with an IPv4 and the smallest index as the "default"
    let default_iface = interfaces
        .into_iter()
        .filter(|iface| iface.addr.iter().any(|a| matches!(a, Addr::V4(_))))
        .min_by_key(|iface| iface.index);

    if let Some(iface) = default_iface {
        // We'll gather the first available IPv4 and IPv6
        let mut found_ipv4 = Ipv4Addr::new(0, 0, 0, 0);
        let mut found_netmaskv4 = Ipv4Addr::new(0, 0, 0, 0);

        let mut found_ipv6 = Ipv6Addr::UNSPECIFIED;
        let mut found_netmaskv6 = Ipv6Addr::UNSPECIFIED;
        for addr in &iface.addr {
            match addr {
                Addr::V4(ipv4) => {
                    found_ipv4 = ipv4.ip;
                    found_netmaskv4 = ipv4.netmask.unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
                }
                Addr::V6(ipv6) => {
                    // Optionally skip link-local addresses if desired.
                    if !ipv6.ip.to_string().starts_with("fe80:") {
                        found_ipv6 = ipv6.ip;
                        found_netmaskv6 = ipv6.netmask.unwrap_or(Ipv6Addr::UNSPECIFIED);
                    }
                }
            }
        }

        Some(LANScanInterface {
            name: iface.name,
            ipv4: found_ipv4,
            prefixv4: ipv4_mask_to_prefix(found_netmaskv4).unwrap_or(0),
            ipv6: found_ipv6,
            prefixv6: ipv6_mask_to_prefix(found_netmaskv6).unwrap_or(0),
        })
    } else {
        None
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_valid_network_interfaces() {
        let interfaces = get_valid_network_interfaces();
        assert!(!interfaces.is_empty());
    }

    #[test]
    fn test_get_default_interface() {
        let interface = get_default_interface();
        assert!(interface.is_some());
    }
}
