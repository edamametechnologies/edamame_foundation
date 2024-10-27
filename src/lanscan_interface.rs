#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use ipnet::ipv4_mask_to_prefix;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use netdev;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use tracing::error;
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use tracing::{info, trace};

// Search for the interfaces - the ones that are up, not loopback or link layer and has an IPv4 address and sorted with the lowest index first (the default)
// Returns (ip, prefix, name)
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn get_valid_network_interfaces() -> Vec<(String, u8, String)> {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        let interfaces = match NetworkInterface::show() {
            Ok(interfaces) => interfaces,
            Err(e) => {
                error!("Failed to get network interfaces: {}", e);
                return Vec::new();
            }
        };
        trace!("Available interfaces: {:?}", interfaces);

        let excluded_prefixes = [
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

        let mut valid_interfaces: Vec<(String, u8, String)> = interfaces
            .into_iter()
            .filter(|iface| {
                !excluded_prefixes
                    .iter()
                    .any(|&prefix| iface.name.starts_with(prefix))
            })
            .filter(|iface| iface.addr.iter().any(|ip| matches!(ip, Addr::V4(_))))
            .filter(|iface| {
                iface.addr.iter().any(|ip| match ip {
                    Addr::V4(ipv4) => {
                        let ip_str = ipv4.ip.to_string();
                        !ip_str.starts_with("127") && !ip_str.starts_with("169.254")
                    }
                    _ => false,
                })
            })
            .filter_map(|iface| {
                iface.addr.iter().find_map(|ip| match ip {
                    Addr::V4(ipv4) => Some((
                        ipv4.ip.to_string(),
                        ipv4_mask_to_prefix(ipv4.netmask.unwrap()).unwrap_or(0),
                        iface.name.clone(),
                    )),
                    _ => None,
                })
            })
            .collect();

        // Sort the interfaces by name
        valid_interfaces.sort_by_key(|k| k.2.clone());

        info!("Valid interfaces: {:?}", valid_interfaces);
        valid_interfaces
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Vec::new()
    }
}

// Get the default interface name
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn get_default_interface() -> Option<(String, u8, String)> {
    match netdev::get_default_interface() {
        Ok(iface) => match iface.ipv4.first() {
            Some(ip) => Some((ip.addr().to_string(), ip.prefix_len(), iface.name)),
            None => None,
        },
        Err(e) => {
            error!("Failed to get default interface: {}", e);
            None
        }
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
