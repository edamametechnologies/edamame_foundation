use anyhow::{anyhow, Result};
use std::net::IpAddr;

/// Checks if a MAC address string is valid.  
/// Syntax: xx:xx:xx:xx:xx:xx, and not all zeros.
pub fn is_valid_mac_address(mac_address: &str) -> bool {
    mac_address.len() == 17
        && mac_address
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':')
        && mac_address != "00:00:00:00:00:00"
}

// ---------------------------------------------------------------------------
// Platform-specific implementations
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod platform_impl {
    use super::*;
    use powershell_script::PsScriptBuilder;
    use regex::Regex;
    use tracing::trace;

    /// On Windows, use PowerShell's Get-NetNeighbor to retrieve the MAC.
    pub async fn get_mac_address_from_ip(
        _interface_name: &str,
        ip_addr: &IpAddr,
    ) -> Result<String> {
        trace!("Starting ARP query for {} on Windows", ip_addr);

        // Example command: Get-NetNeighbor -IPAddress 192.168.1.42
        let cmd = &format!("Get-NetNeighbor -IPAddress {}", ip_addr);
        let ps = PsScriptBuilder::new()
            .no_profile(true)
            .non_interactive(true)
            .hidden(true)
            .print_commands(false)
            .build();

        let (stdout, _stderr) = match ps.run(cmd) {
            Ok(output) => (
                output.stdout().as_deref().unwrap_or("").to_string(),
                output.stderr().as_deref().unwrap_or("").to_string(),
            ),
            Err(e) => {
                return Err(anyhow!("Error querying ARP table: {}", e.to_string()));
            }
        };

        trace!("Get-NetNeighbor output: {}", stdout);

        // Regex to match the IP and MAC address
        // Example line might look like: "192.168.1.42  2C-54-91-88-C9-E3 ..."
        // We'll capture the second part for the MAC address.
        let re = Regex::new(&format!(
            r"{}\s+((\w\w-\w\w-\w\w-\w\w-\w\w-\w\w)\s)",
            ip_addr
        ))?;
        let caps = match re.captures(&stdout) {
            Some(caps) => caps,
            None => {
                return Err(anyhow!("No valid MAC address found for {}", ip_addr));
            }
        };

        let mac = caps[2].trim().to_string();
        // Convert to lowercase and replace '-' with ':'
        let formatted_mac = mac.to_lowercase().replace('-', ":");

        if !is_valid_mac_address(&formatted_mac) {
            return Err(anyhow!("Invalid MAC address: {}", formatted_mac));
        }

        Ok(formatted_mac)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod platform_impl {
    use super::*;
    use libarp::{client::ArpClient, interfaces::Interface};
    use std::time::Duration;
    use tracing::trace;

    /// On Unix-like platforms, use libarp to send an ARP query directly.
    pub async fn get_mac_address_from_ip(interface_name: &str, ip_addr: &IpAddr) -> Result<String> {
        trace!(
            "Starting ARP query for {} on interface {} (Unix-like)",
            ip_addr,
            interface_name
        );

        // Only IPv4 addresses are supported
        let ipv4_addr = match ip_addr {
            IpAddr::V4(v4) => v4,
            _ => return Err(anyhow!("Only IPv4 addresses are supported")),
        };

        let iface = match Interface::new_by_name(interface_name) {
            Some(iface) => iface,
            None => {
                trace!("Error creating Interface");
                return Err(anyhow!("Error creating Interface"));
            }
        };

        let mut client = match ArpClient::new_with_iface(&iface) {
            Ok(c) => c,
            Err(e) => {
                trace!("Error creating ArpClient: {}", e);
                return Err(anyhow!(e.to_string()));
            }
        };

        trace!("Created ARP client");
        let mac_str = client
            .ip_to_mac(*ipv4_addr, Some(Duration::from_millis(8000)))
            .await?;
        trace!("Ending ARP scan");

        if !is_valid_mac_address(&mac_str.to_string()) {
            return Err(anyhow!("Invalid MAC address: {}", mac_str));
        }

        Ok(mac_str.to_string())
    }
}

#[cfg(any(target_os = "ios", target_os = "android"))]
mod platform_impl {
    use super::*;

    /// On iOS/Android, ARP is not supported in this library's approach.
    pub async fn get_mac_address_from_ip(
        _interface_name: &str,
        ip_addr: &IpAddr,
    ) -> Result<String> {
        return Err(anyhow!(
            "MAC address lookup not supported on mobile devices (iOS/Android). IP: {}",
            ip_addr
        ));
    }
}

// ---------------------------------------------------------------------------
// Re-export a single cross-platform function name, choosing the right impl
// ---------------------------------------------------------------------------
#[cfg(target_os = "windows")]
pub use platform_impl::get_mac_address_from_ip;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use platform_impl::get_mac_address_from_ip;

#[cfg(any(target_os = "ios", target_os = "android"))]
pub use platform_impl::get_mac_address_from_ip;
