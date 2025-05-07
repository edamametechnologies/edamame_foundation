use anyhow::{anyhow, Result};
use macaddr::MacAddr6;
use std::net::Ipv4Addr;

#[cfg(target_os = "windows")]
mod platform_impl {
    use super::*;
    use powershell_script::PsScriptBuilder;
    use regex::Regex;
    use std::str::FromStr;
    use tracing::trace;

    /// On Windows, use PowerShell's Get-NetNeighbor to retrieve the MAC.
    pub async fn get_mac_address_from_ip(
        _interface_name: &str,
        ip_addr: &Ipv4Addr,
    ) -> Result<MacAddr6> {
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

        // Check if the MAC address is valid (not all zeros or all FF:FF:FF:FF:FF:FF)
        if formatted_mac == "00:00:00:00:00:00"
            || formatted_mac == "0:0:0:0:0:0:0:0"
            || formatted_mac == "ff:ff:ff:ff:ff:ff"
        {
            return Err(anyhow!("Invalid MAC address: {}", formatted_mac));
        }

        // Convert to MacAddr6
        let mac = match MacAddr6::from_str(&formatted_mac) {
            Ok(mac) => mac,
            Err(e) => return Err(anyhow!("Invalid MAC address: {}", e)),
        };

        Ok(mac)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod platform_impl {
    use super::*;
    use libarp::{client::ArpClient, interfaces::Interface, interfaces::MacAddr};
    use std::time::Duration;
    use tracing::trace;

    /// On Unix-like platforms, use libarp to send an ARP query directly.
    pub async fn get_mac_address_from_ip(
        interface_name: &str,
        ipv4_addr: &Ipv4Addr,
    ) -> Result<MacAddr6> {
        trace!(
            "Starting ARP query for {} on interface {} (Unix-like)",
            ipv4_addr,
            interface_name
        );

        // Create interface
        let iface = match Interface::new_by_name(interface_name) {
            Some(iface) => iface,
            None => {
                trace!("Error creating Interface");
                return Err(anyhow!("Error creating Interface"));
            }
        };

        // Create ARP client
        let mut client = match ArpClient::new_with_iface(&iface) {
            Ok(c) => c,
            Err(e) => {
                trace!("Error creating ArpClient: {}", e);
                return Err(anyhow!(e.to_string()));
            }
        };

        trace!("Created ARP client");

        // Attempt ARP resolution
        let formatted_mac = client
            .ip_to_mac(*ipv4_addr, Some(Duration::from_millis(8000)))
            .await?;

        // Check if the MAC address is valid (not all zeros)
        if formatted_mac == MacAddr::new(0, 0, 0, 0, 0, 0) {
            return Err(anyhow!("Invalid MAC address: {}", formatted_mac));
        }

        let mac = MacAddr6::new(
            formatted_mac.0,
            formatted_mac.1,
            formatted_mac.2,
            formatted_mac.3,
            formatted_mac.4,
            formatted_mac.5,
        );

        // Return the MAC address
        Ok(mac)
    }
}

#[cfg(any(target_os = "ios", target_os = "android"))]
mod platform_impl {
    use super::*;

    /// On iOS/Android, ARP is not supported in this library's approach.
    pub async fn get_mac_address_from_ip(
        _interface_name: &str,
        ip_addr: &Ipv4Addr,
    ) -> Result<MacAddr6> {
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
