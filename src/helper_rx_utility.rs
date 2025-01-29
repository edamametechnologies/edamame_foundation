use crate::helper_rx::{order_error, CARGO_PKG_VERSION};
use crate::lanscan_arp::*;
use crate::lanscan_broadcast::scan_hosts_broadcast;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use crate::lanscan_capture::LANScanCapture;
use crate::lanscan_mdns::*;
use crate::lanscan_neighbors::scan_neighbors;
use crate::logger::get_all_logs;
use crate::runner_cli::run_cli;
use crate::runtime::async_spawn;
use anyhow::Result;
use lazy_static::lazy_static;
#[cfg(target_os = "macos")]
use libc::EACCES;
use macaddr::MacAddr6;
use serde_json;
#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
lazy_static! {
    pub static ref CAPTURE: Arc<Mutex<LANScanCapture>> =
        Arc::new(Mutex::new(LANScanCapture::new()));
}
use crate::lanscan_interface::*;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use crate::lanscan_sessions::SessionFilter;

lazy_static! {
    // Current default interface
    pub static ref INTERFACES_NAMES: Arc<Mutex<Vec<String>>> =
        Arc::new(Mutex::new(Vec::new()));
    pub static ref INTERFACES_SIGNATURE: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
}

// Detect and check interface changes
pub async fn check_interfaces_changes() -> bool {
    let interfaces = get_valid_network_interfaces();
    let mut interfaces_changed = false;
    *INTERFACES_NAMES.lock().await = interfaces
        .interfaces
        .iter()
        .map(|iface| iface.name.clone())
        .collect::<Vec<_>>();
    let interfaces_signature = interfaces.signature();
    if *INTERFACES_SIGNATURE.lock().await != interfaces_signature {
        *INTERFACES_SIGNATURE.lock().await = interfaces_signature;
        interfaces_changed = true;
    }
    return interfaces_changed;
}

pub async fn utility_broadcast_ping(broadcast_addr: &str) -> Result<String> {
    let broadcast_addr = match broadcast_addr.parse::<Ipv4Addr>() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Error parsing broadcast address {}: {}", broadcast_addr, e);
            return order_error(
                &format!("error parsing broadcast address {}: {}", broadcast_addr, e),
                false,
            );
        }
    };

    match scan_hosts_broadcast(
        broadcast_addr,
        1000, // 1 second timeout
        3,    // 3 attempts
    )
    .await
    {
        Ok(ips) => {
            info!("Broadcast scan results: {:?}", ips);
            Ok(serde_json::to_string(&ips)?)
        }
        Err(e) => {
            warn!("Error performing broadcast_ping: {}", e);
            order_error(&format!("error performing broadcast_ping: {}", e), false)
        }
    }
}

pub async fn utility_get_neighbors(interface_name: &str) -> Result<String> {
    let interface = interface_name.to_string();
    match scan_neighbors(Some(&interface)).await {
        Ok(ips) => {
            info!("NDP scan results: {:?}", ips);
            Ok(serde_json::to_string(&ips)?)
        }
        Err(e) => {
            warn!("Error scanning NDP: {}", e);
            order_error(&format!("error scanning NDP: {}", e), false)
        }
    }
}

pub async fn utility_arp_resolve(addresses: &str) -> Result<String> {
    let mut arp_results = Vec::new();
    for address in serde_json::from_str::<Vec<(String, String)>>(addresses)? {
        match address.1.parse::<Ipv4Addr>() {
            Ok(ip_addr) => {
                match get_mac_address_from_ip(&address.0, &ip_addr).await {
                    Ok(mac_address) => arp_results.push((address.0, address.1, mac_address)),
                    // Only warn
                    Err(e) => warn!(
                        "Error resolving MAC for IP {} on interface {} : {}",
                        address.1, address.0, e
                    ),
                }
            }
            Err(e) => error!("Error parsing IP address {}: {}", address.1, e),
        }
    }
    info!("ARP results: {:?}", arp_results);
    // Convert MacAddr6 to String to make it serializable
    let arp_results: Vec<(String, String, String)> = arp_results
        .into_iter()
        .map(|(iface, ip, mac)| (iface, ip, mac.to_string()))
        .collect();
    Ok(serde_json::to_string(&arp_results)?)
}

pub async fn utility_mdns_resolve(addresses: &str) -> Result<String> {
    let mut mdns_results: Vec<(IpAddr, String, MacAddr6, Vec<String>)> = Vec::new();
    for address in serde_json::from_str::<Vec<IpAddr>>(addresses)? {
        if let Some(mdns_info) = mdns_get_by_ip(&address).await {
            // Combine instances & services
            let mut mdns_services_instances = mdns_info.instances.to_vec();
            mdns_services_instances.extend(mdns_info.services.to_vec());
            mdns_services_instances.sort();
            mdns_services_instances.dedup();
            mdns_results.push((
                address,
                mdns_info.hostname,
                mdns_info.mac_address,
                mdns_services_instances,
            ));
        } else {
            warn!("No mDNS info found for IP {}", address);
        }
    }
    Ok(serde_json::to_string(&mdns_results)?)
}

pub async fn utility_getappleid_email(username: &str) -> Result<String> {
    run_cli(
        r#"defaults read MobileMeAccounts Accounts | grep AccountID | grep -o "\".*\"" | sed "s/\"//g" | tr -d "\n""#,
        username,
        true,
    ).await
}

pub async fn utility_helper_check() -> Result<String> {
    // Return current helper version
    Ok(CARGO_PKG_VERSION.to_string())
}

pub async fn utility_helper_flags() -> Result<String> {
    // Additional system info - e.g. macOS full disk access check
    #[cfg(target_os = "macos")]
    {
        let path = "/Library/Application Support/com.apple.TCC/TCC.db";
        let file_result = File::open(path);
        let full_disk_access = match file_result {
            Ok(_) => true,
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied => false,
            Err(ref e) if e.raw_os_error() == Some(EACCES) => false,
            Err(e) => {
                error!("Failed to check full disk access: {}", e);
                false
            }
        };
        Ok(format!("full_disk_access={}", full_disk_access))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok("".to_string())
    }
}

pub async fn utility_get_logs() -> Result<String> {
    let logs = get_all_logs();
    Ok(logs)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_start_capture() -> Result<String> {
    if CAPTURE.lock().await.is_capturing().await {
        return order_error("capture already started", false);
    }
    let interfaces = INTERFACES_NAMES.lock().await.clone();
    let interfaces_string = interfaces.join(",");
    CAPTURE.lock().await.start(&interfaces_string).await;
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_stop_capture() -> Result<String> {
    CAPTURE.lock().await.stop().await;
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_restart_capture() -> Result<String> {
    if !CAPTURE.lock().await.is_capturing().await {
        return order_error("capture not running", false);
    }
    let interfaces = INTERFACES_NAMES.lock().await.clone();
    let interfaces_string = interfaces.join(",");
    CAPTURE.lock().await.restart(&interfaces_string).await;
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_is_capturing() -> Result<String> {
    let is_capturing = CAPTURE.lock().await.is_capturing().await;
    let result = is_capturing.to_string();
    info!("Returning is_capturing: {}", result);
    Ok(result)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_set_whitelist(whitelist_name: &str) -> Result<String> {
    CAPTURE.lock().await.set_whitelist(whitelist_name).await;
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_whitelist() -> Result<String> {
    let whitelist = CAPTURE.lock().await.get_whitelist().await;
    info!("Returning whitelist: {}", whitelist);
    Ok(whitelist)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_set_filter(filter: &str) -> Result<String> {
    match serde_json::from_str::<SessionFilter>(filter) {
        Ok(filter) => CAPTURE.lock().await.set_filter(filter).await,
        Err(e) => {
            error!("Invalid argument for set_filter {} : {}", filter, e);
            return order_error(
                &format!("invalid argument for set_filter: {}", filter),
                false,
            );
        }
    };
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_filter() -> Result<String> {
    let filter = CAPTURE.lock().await.get_filter().await;
    let json_filter = match serde_json::to_string(&filter) {
        Ok(json) => json,
        Err(e) => {
            error!("Error serializing filter to JSON: {}", e);
            return order_error(&format!("error serializing filter to JSON: {}", e), false);
        }
    };
    info!("Returning filter: {}", json_filter);
    Ok(json_filter)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_sessions() -> Result<String> {
    let sessions = CAPTURE.lock().await.get_sessions().await;
    let json_sessions = match serde_json::to_string(&sessions) {
        Ok(json) => json,
        Err(e) => {
            error!("Error serializing sessions to JSON: {}", e);
            return order_error(&format!("error serializing sessions to JSON: {}", e), false);
        }
    };
    info!("Returning {} sessions", sessions.len());
    Ok(json_sessions)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_current_sessions() -> Result<String> {
    let active_sessions = CAPTURE.lock().await.get_current_sessions().await;
    let json_active_sessions = match serde_json::to_string(&active_sessions) {
        Ok(json) => json,
        Err(e) => {
            error!("Error serializing current sessions to JSON: {}", e);
            return order_error(
                &format!("error serializing current sessions to JSON: {}", e),
                false,
            );
        }
    };
    info!("Returning {} current sessions", active_sessions.len());
    Ok(json_active_sessions)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_whitelist_conformance() -> Result<String> {
    let conformance = CAPTURE
        .lock()
        .await
        .get_whitelist_conformance()
        .await
        .to_string();
    info!("Returning whitelist conformance: {}", conformance);
    Ok(conformance)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_whitelist_exceptions() -> Result<String> {
    let exceptions = CAPTURE.lock().await.get_whitelist_exceptions().await;
    let json_exceptions = match serde_json::to_string(&exceptions) {
        Ok(json) => json,
        Err(e) => {
            error!("Error serializing whitelist exceptions to JSON: {}", e);
            return order_error(
                &format!("error serializing whitelist exceptions to JSON: {}", e),
                false,
            );
        }
    };
    info!("Returning {} whitelist exceptions", exceptions.len());
    Ok(json_exceptions)
}

#[cfg(
    any(target_os = "macos", target_os = "linux", target_os = "windows")
)]
pub fn start_interface_monitor() {

    #[cfg(all(
        any(target_os = "macos", target_os = "linux", target_os = "windows"),
        feature = "packetcapture"
    ))]
    let capture = CAPTURE.clone();
    async_spawn(async move {
        loop {
            if check_interfaces_changes().await {
                // Handle capture restart
                #[cfg(all(
                    any(target_os = "macos", target_os = "linux", target_os = "windows"),
                    feature = "packetcapture"
                ))]
                {
                    let is_capturing = capture.lock().await.is_capturing().await;
                    if is_capturing {
                        capture.lock().await.stop().await;
                        let interfaces = INTERFACES_NAMES.lock().await.clone();
                        let interfaces_string = interfaces.join(",");
                        info!(
                            "Interfaces changed, restarting capture on {}",
                            interfaces_string
                        );
                        capture.lock().await.start(&interfaces_string).await;
                    }
                }
                // mDNS flush
                info!("Interfaces changed, flushing mDNS cache");
                mdns_flush().await;
            }
            sleep(Duration::from_secs(10)).await;
        }
    });
}
