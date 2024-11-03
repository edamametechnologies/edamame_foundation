use std::net::IpAddr;
use tracing::trace;
// Not on Windows as it depends on Packet.lib / Packet.dll that we don't want to ship with the binary
use anyhow::{anyhow, Result};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use libarp::{client::ArpClient, interfaces::Interface};
#[cfg(target_os = "windows")]
use powershell_script::PsScriptBuilder;
#[cfg(target_os = "windows")]
use regex::Regex;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::Duration;

pub fn mac_address_is_valid(mac_address: &str) -> bool {
    // Syntax is xx:xx:xx:xx:xx:xx
    mac_address.len() == 17 && mac_address.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
    // Check we don't have 00:00:00:00:00:00
    && mac_address != "00:00:00:00:00:00"
}

// Gets the MAC address of a device given its IP address.
pub async fn get_mac_address_from_ip(interface_name: &str, ip_addr: &IpAddr) -> Result<String> {
    trace!(
        "Starting ARP query for {} on interface {}",
        ip_addr,
        interface_name
    );

    // Just use PS...
    #[cfg(target_os = "windows")]
    {
        // No need to specify the interface
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

        trace!("Get-NetNeighbor: {}", stdout);

        // Regex to match the IP and MAC address
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
        // Convert to lowercase and replace - by :
        let formatted_mac = mac.to_lowercase().replace("-", ":");

        // Check that the MAC address is valid
        if !mac_address_is_valid(&formatted_mac) {
            return Err(anyhow!("Invalid MAC address: {}", formatted_mac));
        }

        Ok(formatted_mac)
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        match ip_addr {
            IpAddr::V4(ipv4_addr) => {
                let iface = match Interface::new_by_name(interface_name) {
                    Some(iface) => iface,
                    None => {
                        // This will fail if the interface is invalid
                        trace!("Error creating Interface");
                        return Err(anyhow!("Error creating Interface"));
                    }
                };
                let mut client = match ArpClient::new_with_iface(&iface) {
                    Ok(client) => client,
                    Err(e) => {
                        // This will fail if we are in userspace
                        trace!("Error creating ArpClient: {}", e);
                        return Err(anyhow!(e.to_string()));
                    }
                };
                trace!("Created ARP client");
                let mac_address = client
                    .ip_to_mac(*ipv4_addr, Some(Duration::from_millis(8000)))
                    .await?;
                trace!("Ending ARP scan");
                // Check that the MAC address is valid
                if !mac_address_is_valid(&mac_address.to_string()) {
                    return Err(anyhow!("Invalid MAC address: {}", mac_address));
                }

                Ok(mac_address.to_string())
            }
            _ => Err(anyhow!("Only IPv4 addresses are supported")),
        }
    }

    #[cfg(any(target_os = "ios", target_os = "android"))]
    Err(anyhow!(
        "MAC address lookup not supported on mobile devices"
    ))
}
