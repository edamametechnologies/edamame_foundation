use log::trace;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use log::warn;

use std::net::IpAddr;


// Not on Windows as it depends on Packet.lib / Packet.dll that we don't want to ship with the binary
#[cfg(any(target_os = "macos", target_os = "linux"))]
use libarp::{client::ArpClient, interfaces::Interface};

#[cfg(target_os = "windows")]
use powershell_script::PsScriptBuilder;
#[cfg(target_os = "windows")]
use regex::Regex;
#[cfg(target_os = "windows")]
use log::error;

use anyhow::{anyhow, Result};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::Duration;

// Gets the MAC address of a device given its IP address.
pub async fn get_mac_address_from_ip(interface_name: &str, ip_addr: &IpAddr) -> Result<String> {

    trace!("Starting ARP query for {} on interface {}", ip_addr, interface_name);

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
            Ok(output) => {
                (output.stdout().as_deref().unwrap_or("").to_string(), output.stderr().as_deref().unwrap_or("").to_string())
            },
            Err(e) => {
                error!("Powershell execution error with calling {:?} : {:?}", cmd, e.to_string());
                return Err(anyhow!("Error querying ARP table: {}", e.to_string()));
            }
        };

        trace!("Get-NetNeighbor: {}", stdout);

        // Regex to match the IP and MAC address
        let re = Regex::new(&format!(r"{}\s+((\w\w-\w\w-\w\w-\w\w-\w\w-\w\w)\s)", ip_addr))?;
        let caps = match re.captures(&stdout) {
            Some(caps) => caps,
            None => {
                return Err(anyhow!("No valid MAC address found for {}", ip_addr));
            }
        };

        Ok(caps[2].trim().to_string())
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        match ip_addr {
            IpAddr::V4(ipv4_addr) => {
                let iface = Interface::new_by_name(interface_name).unwrap();
                let mut client =
                    match ArpClient::new_with_iface(&iface) {
                        Ok(client) => client,
                        Err(e) => {
                            warn!("Error creating ArpClient: {}", e);
                            return Err(anyhow!(e.to_string()));
                        }
                    };
                trace!("Created ARP client");
                let mac_address = client
                    .ip_to_mac(*ipv4_addr, Some(Duration::from_millis(8000)))
                    .await?;
                trace!("Ending ARP scan");
                Ok(mac_address.to_string())
            }
            _ => Err(anyhow!("Only IPv4 addresses are supported")),
        }
    }

    #[cfg(any(target_os = "ios", target_os = "android"))]
    Err(anyhow!("MAC address lookup not supported on mobile devices"))
}