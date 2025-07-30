use crate::helper_rx::{order_error, CARGO_PKG_VERSION};
use crate::logger::get_all_logs;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use crate::peer_ids::get_peer_ids;
use crate::runner_cli::run_cli;
use anyhow::Result;
use flodbadd::arp::*;
use flodbadd::broadcast::scan_hosts_broadcast;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use flodbadd::capture::FlodbaddCapture;
use flodbadd::interface::*;
use flodbadd::ip::*;
use flodbadd::mdns::*;
use flodbadd::neighbors::scan_neighbors;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use flodbadd::sessions::SessionFilter;
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
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};
use undeadlock::CustomRwLock;

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
lazy_static! {
    pub static ref CAPTURE: Arc<CustomRwLock<FlodbaddCapture>> =
        Arc::new(CustomRwLock::new(FlodbaddCapture::new()));
}

lazy_static! {
    // Current default interface
    pub static ref INTERFACES: Arc<CustomRwLock<FlodbaddInterfaces>> =
        Arc::new(CustomRwLock::new(FlodbaddInterfaces::new()));
    pub static ref INTERFACES_SIGNATURE: Arc<CustomRwLock<String>> = Arc::new(CustomRwLock::new(String::new()));
}

// Detect and check interface changes
pub async fn check_interfaces_changes() -> bool {
    let interfaces = get_valid_network_interfaces();

    let mut interfaces_changed = false;
    *INTERFACES.write().await = interfaces.clone();
    let interfaces_signature = interfaces.signature();
    if *INTERFACES_SIGNATURE.read().await != interfaces_signature {
        *INTERFACES_SIGNATURE.write().await = interfaces_signature;
        interfaces_changed = true;
    }
    return interfaces_changed;
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_peer_ids() -> Result<String> {
    let peer_ids = get_peer_ids().await;
    Ok(serde_json::to_string(&peer_ids)?)
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
            debug!("No mDNS info found for IP {}", address);
        }
    }
    // Convert MacAddr6 to String to make it serializable consistently
    let mdns_results_serializable: Vec<(IpAddr, String, String, Vec<String>)> = mdns_results
        .into_iter()
        .map(|(ip, hostname, mac, services)| (ip, hostname, mac.to_string(), services))
        .collect();
    Ok(serde_json::to_string(&mdns_results_serializable)?)
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
    let interfaces = INTERFACES.read().await.clone();
    let capture_start_result = CAPTURE.write().await.start(&interfaces).await;
    if let Err(e) = capture_start_result {
        error!("Capture start failed: {}", e);
        return order_error(&format!("capture start failed: {}", e), false);
    }
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_stop_capture() -> Result<String> {
    CAPTURE.write().await.stop().await;
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_restart_capture() -> Result<String> {
    let interfaces = INTERFACES.read().await.clone();
    let capture_restart_result = CAPTURE.write().await.restart(&interfaces).await;
    if let Err(e) = capture_restart_result {
        error!("Capture restart failed: {}", e);
        return order_error(&format!("capture restart failed: {}", e), false);
    }
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_is_capturing() -> Result<String> {
    let is_capturing = CAPTURE.read().await.is_capturing().await;
    let result = is_capturing.to_string();
    info!("Returning is_capturing: {}", result);
    Ok(result)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_set_whitelist(whitelist_name: &str) -> Result<String> {
    match CAPTURE.write().await.set_whitelist(whitelist_name).await {
        Ok(_) => Ok("".to_string()),
        Err(e) => {
            error!("Error setting whitelist: {}", e);
            order_error(&format!("error setting whitelist: {}", e), false)
        }
    }
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_set_custom_whitelists(whitelist_json: &str) -> Result<String> {
    CAPTURE
        .write()
        .await
        .set_custom_whitelists(whitelist_json)
        .await;
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_create_custom_whitelists() -> Result<String> {
    let whitelist = match CAPTURE.write().await.create_custom_whitelists().await {
        Ok(whitelist) => whitelist,
        Err(e) => {
            error!("Error creating custom whitelists: {}", e);
            return order_error(&format!("error creating custom whitelists: {}", e), false);
        }
    };
    tracing::debug!("Returning whitelist: {}", whitelist);
    Ok(whitelist)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_augment_custom_whitelists() -> Result<String> {
    let whitelist = match CAPTURE.write().await.augment_custom_whitelists().await {
        Ok(whitelist) => whitelist,
        Err(e) => {
            error!("Error augmenting custom whitelists: {}", e);
            return order_error(&format!("error augmenting custom whitelists: {}", e), false);
        }
    };
    tracing::debug!("Returning whitelist: {}", whitelist);
    Ok(whitelist)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_merge_custom_whitelists(
    whitelist1_json: &str,
    whitelist2_json: &str,
) -> Result<String> {
    let whitelist =
        match FlodbaddCapture::merge_custom_whitelists(whitelist1_json, whitelist2_json).await {
            Ok(whitelist) => whitelist,
            Err(e) => {
                error!("Error merging custom whitelists: {}", e);
                return order_error(&format!("error merging custom whitelists: {}", e), false);
            }
        };
    tracing::debug!("Returning whitelist: {}", whitelist);
    Ok(whitelist)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_set_custom_blacklists(blacklist_json: &str) -> Result<String> {
    let _ = CAPTURE
        .write()
        .await
        .set_custom_blacklists(blacklist_json)
        .await;
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_set_filter(filter: &str) -> Result<String> {
    match serde_json::from_str::<SessionFilter>(filter) {
        Ok(filter) => CAPTURE.write().await.set_filter(filter).await,
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
    let filter = CAPTURE.read().await.get_filter().await;
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
pub async fn utility_get_sessions(incremental: bool) -> Result<String> {
    let sessions = CAPTURE.read().await.get_sessions(incremental).await;
    let json_sessions = match serde_json::to_string(&sessions) {
        Ok(json) => json,
        Err(e) => {
            error!("Error serializing sessions to JSON: {}", e);
            return order_error(&format!("error serializing sessions to JSON: {}", e), false);
        }
    };
    info!(
        "Returning {} sessions, incremental: {}",
        sessions.len(),
        incremental
    );
    Ok(json_sessions)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_current_sessions(incremental: bool) -> Result<String> {
    let active_sessions = CAPTURE.read().await.get_current_sessions(incremental).await;
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
    info!(
        "Returning {} current sessions, incremental: {}",
        active_sessions.len(),
        incremental
    );
    Ok(json_active_sessions)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_packet_stats() -> Result<String> {
    let stats = CAPTURE.read().await.get_packet_stats().await;
    let json_stats = match serde_json::to_string(&stats) {
        Ok(json) => json,
        Err(e) => {
            error!("Error serializing packet stats to JSON: {}", e);
            return order_error(
                &format!("error serializing packet stats to JSON: {}", e),
                false,
            );
        }
    };
    info!("Returning packet stats: {}", json_stats);
    Ok(json_stats)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_whitelist_conformance() -> Result<String> {
    let conformance = CAPTURE
        .read()
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
pub async fn utility_get_whitelist_exceptions(incremental: bool) -> Result<String> {
    let exceptions = CAPTURE
        .read()
        .await
        .get_whitelist_exceptions(incremental)
        .await;
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
    info!(
        "Returning {} whitelist exceptions, incremental: {}",
        exceptions.len(),
        incremental
    );
    Ok(json_exceptions)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_blacklisted_status() -> Result<String> {
    let status = CAPTURE
        .read()
        .await
        .get_blacklisted_status()
        .await
        .to_string();
    info!("Returning blacklisted status: {}", status);
    Ok(status)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_blacklisted_sessions(incremental: bool) -> Result<String> {
    let sessions = CAPTURE
        .read()
        .await
        .get_blacklisted_sessions(incremental)
        .await;
    let json_sessions = match serde_json::to_string(&sessions) {
        Ok(json) => json,
        Err(e) => {
            error!("Error serializing blacklisted sessions to JSON: {}", e);
            return order_error(
                &format!("error serializing blacklisted sessions to JSON: {}", e),
                false,
            );
        }
    };
    info!(
        "Returning {} blacklisted sessions, incremental: {}",
        sessions.len(),
        incremental
    );
    Ok(json_sessions)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_whitelists() -> Result<String> {
    let json = CAPTURE.read().await.get_whitelists().await;
    info!("Returning whitelists JSON");
    Ok(json)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_blacklists() -> Result<String> {
    let json = CAPTURE.read().await.get_blacklists().await;
    info!("Returning blacklists JSON");
    Ok(json)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_whitelist_name() -> Result<String> {
    let name = CAPTURE.read().await.get_whitelist_name().await;
    info!("Returning whitelist name: {}", name);
    Ok(name)
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub fn start_interface_monitor() {
    let rt = crate::runtime::handle();

    #[cfg(all(
        any(target_os = "macos", target_os = "linux", target_os = "windows"),
        feature = "packetcapture"
    ))]
    let capture = CAPTURE.clone();

    rt.spawn(async move {
        loop {
            if check_interfaces_changes().await {
                let interfaces = INTERFACES.read().await.clone();
                // Handle capture restart
                #[cfg(all(
                    any(target_os = "macos", target_os = "linux", target_os = "windows"),
                    feature = "packetcapture"
                ))]
                {
                    let is_capturing = capture.read().await.is_capturing().await;
                    if is_capturing {
                        info!("Interfaces changed, restarting capture on {:?}", interfaces);
                        match capture.write().await.restart(&interfaces).await {
                            Ok(_) => {
                                info!("Capture restarted successfully");
                            }
                            Err(e) => {
                                error!("Failed to restart capture: {}", e);
                            }
                        }
                    }
                }
                // Initialize the local IP cache
                info!("Interfaces changed, initializing local IP cache");
                init_local_cache(&interfaces);
                // mDNS flush
                info!("Interfaces changed, flushing mDNS cache");
                mdns_flush().await;
            }
            sleep(Duration::from_secs(10)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use flodbadd::sessions::{
        Protocol, Session, SessionFilter, SessionInfo, SessionStats, SessionStatus, WhitelistState,
    };
    use macaddr::MacAddr6;
    use serde_json;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_arp_resolve_serialization_format() {
        let mac1 = MacAddr6::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let mac2 = MacAddr6::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let data: Vec<(String, Ipv4Addr, MacAddr6)> = vec![
            ("eth0".to_string(), "192.168.1.100".parse().unwrap(), mac1),
            ("eth1".to_string(), "10.0.0.50".parse().unwrap(), mac2),
        ];

        // Manually convert MacAddr6 to String before serialization, mirroring utility_arp_resolve
        let data_serializable: Vec<(String, String, String)> = data
            .into_iter()
            .map(|(iface, ip, mac)| (iface, ip.to_string(), mac.to_string()))
            .collect();

        let json_string = serde_json::to_string(&data_serializable).unwrap();

        // Expected format: MAC is a string (lowercase hex)
        let expected_json = r#"[["eth0","192.168.1.100","00:11:22:33:44:55"],["eth1","10.0.0.50","AA:BB:CC:DD:EE:FF"]]"#;
        assert_eq!(json_string, expected_json);
    }

    #[test]
    fn test_mdns_resolve_serialization_format() {
        let mac1 = MacAddr6::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let ip1: IpAddr = "192.168.1.101".parse().unwrap();
        let data: Vec<(IpAddr, String, MacAddr6, Vec<String>)> = vec![(
            ip1,
            "mydevice.local".to_string(),
            mac1,
            vec![
                "_http._tcp.local".to_string(),
                "_service._udp.local".to_string(),
            ],
        )];

        // Manually convert MacAddr6 to String before serialization, mirroring utility_mdns_resolve
        let data_serializable: Vec<(IpAddr, String, String, Vec<String>)> = data
            .into_iter()
            .map(|(ip, hostname, mac, services)| (ip, hostname, mac.to_string(), services))
            .collect();

        let json_string = serde_json::to_string(&data_serializable).unwrap();

        // Expected format: MAC is a string
        let expected_json = r#"[["192.168.1.101","mydevice.local","11:22:33:44:55:66",["_http._tcp.local","_service._udp.local"]]]"#;
        assert_eq!(json_string, expected_json);
    }

    #[test]
    fn test_boolean_serialization() {
        let bool_true_str = true.to_string();
        assert_eq!(bool_true_str, "true");

        let bool_false_str = false.to_string();
        assert_eq!(bool_false_str, "false");
    }

    #[test]
    fn test_session_filter_serialization() {
        let filter = SessionFilter::LocalOnly;
        let json_string = serde_json::to_string(&filter).unwrap();
        // Enums like SessionFilter serialize directly to their variant name as a string
        let expected_json = r#""LocalOnly""#;
        assert_eq!(json_string, expected_json);
    }

    #[test]
    fn test_session_info_vec_serialization() {
        // Create a minimal SessionInfo for testing serialization
        let session_info = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: "192.168.1.1".parse().unwrap(),
                src_port: 12345,
                dst_ip: "8.8.8.8".parse().unwrap(),
                dst_port: 53,
            },
            status: SessionStatus {
                // Provide default or minimal values
                active: true,
                added: true,
                activated: true,
                deactivated: false,
            },
            stats: SessionStats {
                start_time: Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap(),
                end_time: None,
                last_activity: Utc.with_ymd_and_hms(2023, 1, 1, 12, 5, 0).unwrap(),
                inbound_bytes: 100,
                outbound_bytes: 200,
                orig_pkts: 2,
                resp_pkts: 1,
                orig_ip_bytes: 240,
                resp_ip_bytes: 160,
                history: "ShAD".to_string(),
                conn_state: Some("ESTABLISHED".to_string()),
                missed_bytes: 0,
                average_packet_size: 0.0,
                inbound_outbound_ratio: 0.0,
                segment_count: 0,
                current_segment_start: Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap(),
                last_segment_end: None,
                segment_interarrival: 0.0,
                total_segment_interarrival: 0.0,
                in_segment: false,
                segment_timeout: 5.0,
            },
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: Some("dns.google".to_string()),
            dst_service: Some("dns".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: None,
            is_whitelisted: WhitelistState::Unknown,
            criticality: "low".to_string(),
            dismissed: false,
            whitelist_reason: None,
            uid: "test-uid-123".to_string(),
            last_modified: Utc.with_ymd_and_hms(2023, 1, 1, 12, 5, 1).unwrap(),
        };
        let sessions = vec![session_info];
        let json_string = serde_json::to_string(&sessions).unwrap();

        // Just check it serializes without error and is not empty
        // A full comparison is brittle due to timestamps, etc.
        assert!(json_string.starts_with("["));
        assert!(json_string.ends_with("]"));
        assert!(json_string.contains("test-uid-123"));
        assert!(json_string.contains("dns.google"));
    }
}
