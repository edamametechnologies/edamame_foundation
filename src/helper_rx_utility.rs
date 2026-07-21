use crate::helper_rx::{order_error, CARGO_PKG_VERSION};
use crate::logger::get_all_logs;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use crate::peer_ids::get_peer_ids;
use crate::runner_cli::run_cli;
use anyhow::Result;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    any(feature = "packetcapture", feature = "fim")
))]
use base64::{engine::general_purpose, Engine as _};
use flodbadd::broadcast::scan_hosts_broadcast;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use flodbadd::capture::FlodbaddCapture;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
use flodbadd::fim::{FimMode, FimWatcher};
use flodbadd::interface::*;
use flodbadd::ip::*;
use flodbadd::mdns::mdns_flush;
use flodbadd::neighbors::scan_neighbors;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
use flodbadd::sessions::SessionFilter;
use lazy_static::lazy_static;
use serde_json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    any(feature = "packetcapture", feature = "fim")
))]
use std::time::Instant;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
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

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
lazy_static! {
    pub static ref FIM_WATCHER: Arc<CustomRwLock<Option<FimWatcher>>> =
        Arc::new(CustomRwLock::new(None));
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
const FIM_PROCESS_ATTRIBUTION_BACKFILL_LIMIT: usize = 128;

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
pub async fn utility_get_peer_ids(username: &str) -> Result<String> {
    let peer_ids = get_peer_ids(username).await;
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
    let pairs: Vec<(String, String)> = serde_json::from_str(addresses)?;
    let results = flodbadd::arp::arp_resolve_batch(&pairs).await;
    info!("ARP results: {:?}", results);
    let serializable: Vec<(String, String, String)> = results
        .into_iter()
        .map(|(iface, ip, mac)| (iface, ip, mac.to_string()))
        .collect();
    Ok(serde_json::to_string(&serializable)?)
}

pub async fn utility_mdns_resolve(addresses: &str) -> Result<String> {
    let ips: Vec<IpAddr> = serde_json::from_str(addresses)?;
    let results = flodbadd::mdns::mdns_resolve_batch(&ips).await;
    let serializable: Vec<(IpAddr, String, String, Vec<String>)> = results
        .into_iter()
        .map(|(ip, hostname, mac, services)| (ip, hostname, mac.to_string(), services))
        .collect();
    Ok(serde_json::to_string(&serializable)?)
}

pub async fn utility_getappleid_email(username: &str) -> Result<String> {
    // Use full path to plist file since defaults doesn't respect HOME when running as root
    run_cli(
        r#"defaults read "$HOME/Library/Preferences/MobileMeAccounts.plist" Accounts | grep AccountID | grep -o "\".*\"" | sed "s/\"//g" | tr -d "\n""#,
        username,
        true,
        None,
    ).await
}

pub async fn utility_helper_check() -> Result<String> {
    // Return current helper version
    Ok(CARGO_PKG_VERSION.to_string())
}

pub async fn utility_helper_flags() -> Result<String> {
    Ok(crate::helper_state::get_helper_flags())
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
    if CAPTURE.read().await.is_capturing().await {
        info!("Capture already running, skipping start");
        return Ok("".to_string());
    }
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
    if !CAPTURE.read().await.is_capturing().await {
        info!("Capture not running, skipping stop");
        return Ok("".to_string());
    }
    CAPTURE.write().await.stop().await;
    Ok("".to_string())
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_restart_capture() -> Result<String> {
    let interfaces = INTERFACES.read().await.clone();
    if !CAPTURE.read().await.is_capturing().await {
        info!("Capture not running, starting instead of restarting");
        let result = CAPTURE.write().await.start(&interfaces).await;
        if let Err(e) = result {
            error!("Capture start failed: {}", e);
            return order_error(&format!("capture start failed: {}", e), false);
        }
    } else {
        let result = CAPTURE.write().await.restart(&interfaces).await;
        if let Err(e) = result {
            error!("Capture restart failed: {}", e);
            return order_error(&format!("capture restart failed: {}", e), false);
        }
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
pub async fn utility_augment_custom_whitelists() -> Result<(String, f64)> {
    let result = CAPTURE
        .write()
        .await
        .augment_custom_whitelists()
        .await
        .map_err(|e| {
            error!("Error augmenting custom whitelists: {}", e);
            anyhow::anyhow!("error augmenting custom whitelists: {}", e)
        })?;
    tracing::debug!(
        "Returning whitelist: {}, % similarity: {}",
        result.0,
        result.1
    );
    Ok(result)
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
pub async fn utility_compare_custom_whitelists(
    whitelist1_json: &str,
    whitelist2_json: &str,
) -> Result<f64> {
    let diff_percentage =
        match FlodbaddCapture::compare_custom_whitelists(whitelist1_json, whitelist2_json).await {
            Ok(diff) => diff,
            Err(e) => {
                error!("Error comparing custom whitelists: {}", e);
                return Err(anyhow::anyhow!("error comparing custom whitelists: {}", e));
            }
        };
    tracing::debug!("Returning whitelist difference: {}%", diff_percentage);
    Ok(diff_percentage)
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
    let start = Instant::now();
    info!("Starting get_sessions (incremental: {})", incremental);
    let sessions = CAPTURE.read().await.get_sessions(incremental).await;
    let fetch_elapsed_ms = start.elapsed().as_millis();
    // Use bincode for efficient binary serialization (5-10x smaller/faster than JSON)
    // Then base64 encode for transport over the string-based protobuf channel
    let bincode_sessions =
        match bincode::serde::encode_to_vec(&sessions, bincode::config::standard()) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Error serializing sessions to bincode: {}", e);
                return order_error(
                    &format!("error serializing sessions to bincode: {}", e),
                    false,
                );
            }
        };
    let bincode_len = bincode_sessions.len();
    let bincode_elapsed_ms = start.elapsed().as_millis();
    let encoded = general_purpose::STANDARD.encode(&bincode_sessions);
    let base64_elapsed_ms = start.elapsed().as_millis();
    info!(
        "Returning {} sessions, incremental: {}, size: {} bytes (bincode: {} bytes, fetch: {}ms, bincode: {}ms, base64: {}ms)",
        sessions.len(),
        incremental,
        encoded.len(),
        bincode_len,
        fetch_elapsed_ms,
        bincode_elapsed_ms,
        base64_elapsed_ms
    );
    Ok(encoded)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "packetcapture"
))]
pub async fn utility_get_current_sessions(incremental: bool) -> Result<String> {
    let start = Instant::now();
    info!(
        "Starting get_current_sessions (incremental: {})",
        incremental
    );
    let active_sessions = CAPTURE.read().await.get_current_sessions(incremental).await;
    let fetch_elapsed_ms = start.elapsed().as_millis();
    // Use bincode for efficient binary serialization
    let bincode_sessions =
        match bincode::serde::encode_to_vec(&active_sessions, bincode::config::standard()) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Error serializing current sessions to bincode: {}", e);
                return order_error(
                    &format!("error serializing current sessions to bincode: {}", e),
                    false,
                );
            }
        };
    let bincode_len = bincode_sessions.len();
    let bincode_elapsed_ms = start.elapsed().as_millis();
    let encoded = general_purpose::STANDARD.encode(&bincode_sessions);
    let base64_elapsed_ms = start.elapsed().as_millis();
    info!(
        "Returning {} current sessions, incremental: {}, size: {} bytes (bincode: {} bytes, fetch: {}ms, bincode: {}ms, base64: {}ms)",
        active_sessions.len(),
        incremental,
        encoded.len(),
        bincode_len,
        fetch_elapsed_ms,
        bincode_elapsed_ms,
        base64_elapsed_ms
    );
    Ok(encoded)
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
    // Use bincode for efficient binary serialization
    let bincode_exceptions =
        match bincode::serde::encode_to_vec(&exceptions, bincode::config::standard()) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Error serializing whitelist exceptions to bincode: {}", e);
                return order_error(
                    &format!("error serializing whitelist exceptions to bincode: {}", e),
                    false,
                );
            }
        };
    let encoded = general_purpose::STANDARD.encode(&bincode_exceptions);
    info!(
        "Returning {} whitelist exceptions, incremental: {}, size: {} bytes (bincode+base64)",
        exceptions.len(),
        incremental,
        encoded.len()
    );
    Ok(encoded)
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
    // Use bincode for efficient binary serialization
    let bincode_sessions =
        match bincode::serde::encode_to_vec(&sessions, bincode::config::standard()) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Error serializing blacklisted sessions to bincode: {}", e);
                return order_error(
                    &format!("error serializing blacklisted sessions to bincode: {}", e),
                    false,
                );
            }
        };
    let encoded = general_purpose::STANDARD.encode(&bincode_sessions);
    info!(
        "Returning {} blacklisted sessions, incremental: {}, size: {} bytes (bincode+base64)",
        sessions.len(),
        incremental,
        encoded.len()
    );
    Ok(encoded)
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
        // Initialize the cache immediately on startup, not just on changes
        let initial_interfaces = get_valid_network_interfaces();
        *INTERFACES.write().await = initial_interfaces.clone();
        *INTERFACES_SIGNATURE.write().await = initial_interfaces.signature();

        if !initial_interfaces.is_empty() {
            info!(
                "Helper startup: Initializing local IP cache with {} interfaces",
                initial_interfaces.len()
            );
            init_local_cache(&initial_interfaces);
        } else {
            warn!("Helper startup: No interfaces found for cache initialization");
        }

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

pub async fn utility_provision_agent_plugin(agent_type: &str, arg2: &str) -> Result<String> {
    let (user_home, workspace_root) =
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(arg2) {
            (
                parsed
                    .get("user_home")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                parsed
                    .get("workspace_root")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        } else {
            (arg2.to_string(), String::new())
        };
    let user_home_path = if user_home.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(&user_home))
    };
    let result = crate::agent_plugin::provision_agent_plugin(
        agent_type,
        &workspace_root,
        user_home_path.as_deref(),
    )
    .await;
    serde_json::to_string(&result)
        .map_err(|e| anyhow::anyhow!("Failed to serialize provision result: {}", e))
}

pub async fn utility_get_agent_plugin_status(agent_type: &str, user_home: &str) -> Result<String> {
    let status = if user_home.is_empty() {
        crate::agent_plugin::get_agent_plugin_status(agent_type)
    } else {
        let home = std::path::PathBuf::from(user_home);
        crate::agent_plugin::get_agent_plugin_status_for_home(agent_type, &home)
    };
    serde_json::to_string(&status)
        .map_err(|e| anyhow::anyhow!("Failed to serialize plugin status: {}", e))
}

pub async fn utility_list_agent_plugins(user_home: &str) -> Result<String> {
    let plugins = if user_home.is_empty() {
        crate::agent_plugin::list_agent_plugins()
    } else {
        let home = std::path::PathBuf::from(user_home);
        crate::agent_plugin::list_agent_plugins_for_home(&home)
    };
    serde_json::to_string(&plugins)
        .map_err(|e| anyhow::anyhow!("Failed to serialize plugin list: {}", e))
}

pub async fn utility_uninstall_agent_plugin(agent_type: &str, user_home: &str) -> Result<String> {
    let result = if user_home.is_empty() {
        crate::agent_plugin::uninstall_agent_plugin(agent_type, None)
    } else {
        let home = std::path::PathBuf::from(user_home);
        crate::agent_plugin::uninstall_agent_plugin_for_home(agent_type, &home)
    };
    serde_json::to_string(&result)
        .map_err(|e| anyhow::anyhow!("Failed to serialize uninstall result: {}", e))
}

pub async fn utility_test_agent_plugin(agent_type: &str, user_home: &str) -> Result<String> {
    Ok(crate::agent_plugin::run_agent_plugin_healthcheck(
        agent_type, user_home,
    ))
}

pub async fn utility_scan_secret_content(paths_json: &str) -> Result<String> {
    let paths: Vec<String> = serde_json::from_str(paths_json)
        .map_err(|e| anyhow::anyhow!("Failed to parse secret-content scan paths: {}", e))?;
    let matches = crate::secret_content_scan::scan_secret_like_files(&paths);
    serde_json::to_string(&matches)
        .map_err(|e| anyhow::anyhow!("Failed to serialize secret-content matches: {}", e))
}

/// Helper-side transcript collection. `arg1` is the agent type, `arg2` is a
/// JSON object with `home` (required, helper-resolved real home of the user)
/// and `options` (CollectOptions JSON, optional). The helper crosses the
/// macOS sandbox boundary on behalf of the (sandboxed) app to read transcript
/// files under the user's actual home directory.
pub async fn utility_collect_agent_transcripts(
    agent_type: &str,
    args_json: &str,
) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Args {
        #[serde(default)]
        home: String,
        #[serde(default)]
        options: Option<crate::agent_transcripts::CollectOptions>,
    }

    let args: Args = if args_json.trim().is_empty() {
        Args {
            home: String::new(),
            options: None,
        }
    } else {
        serde_json::from_str(args_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse collect_agent_transcripts args: {}", e))?
    };

    let home_path = if args.home.is_empty() {
        crate::agent_plugin::real_home_dir().ok_or_else(|| {
            anyhow::anyhow!("Unable to resolve real_home_dir for agent transcripts")
        })?
    } else {
        std::path::PathBuf::from(args.home)
    };
    let options = args.options.unwrap_or_default();
    crate::agent_transcripts::collect_to_json(agent_type, &home_path, &options)
}

/// Which of the given agent types have a detected headless CLI on this host.
/// `arg1` is a JSON array of agent types; `arg2` is a JSON object with `home`
/// (the user's real home, so user-level install locations are probed even
/// though the helper runs as root). Returns a JSON array of agent types.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub async fn utility_detect_agent_clis(agent_types_json: &str, args_json: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Args {
        #[serde(default)]
        home: String,
    }

    let agent_types: Vec<String> = serde_json::from_str(agent_types_json)
        .map_err(|e| anyhow::anyhow!("Failed to parse detect_agent_clis agent types: {}", e))?;
    let args: Args = if args_json.trim().is_empty() {
        Args {
            home: String::new(),
        }
    } else {
        serde_json::from_str(args_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse detect_agent_clis args: {}", e))?
    };
    let home_path = if args.home.is_empty() {
        crate::agent_plugin::real_home_dir()
    } else {
        Some(std::path::PathBuf::from(args.home))
    };

    let detected = crate::agent_cli_insight::detect_agent_clis(&agent_types, home_path.as_deref());
    serde_json::to_string(&detected)
        .map_err(|e| anyhow::anyhow!("Failed to serialize detected agent CLIs: {}", e))
}

/// Run a read-only, ephemeral Enlightenment Coach insight generation through
/// a detected agent CLI. `arg1` is the agent type; `arg2` is a JSON object
/// `{"prompt": "...", "home": "..."}`. Returns the extracted model text (the
/// core-side envelope validator decides whether it is acceptable).
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub async fn utility_run_agent_cli_insight(agent_type: &str, args_json: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Args {
        prompt: String,
        #[serde(default)]
        home: String,
    }

    let args: Args = serde_json::from_str(args_json)
        .map_err(|e| anyhow::anyhow!("Failed to parse run_agent_cli_insight args: {}", e))?;
    let home_path = if args.home.is_empty() {
        crate::agent_plugin::real_home_dir()
    } else {
        Some(std::path::PathBuf::from(args.home))
    };

    crate::agent_cli_insight::run_agent_cli_insight(agent_type, &args.prompt, home_path.as_deref())
        .await
}

/// Launch an **interactive** fix run in a real terminal window through a
/// detected agent CLI. This opens a user-visible terminal in the target user's
/// desktop session, seeds the prompt, and lets the agent's native approval UI
/// gate every tool call -- so the operator reads and confirms each step. On
/// Windows the helper runs as SYSTEM and crosses into the active console
/// session via `WTSQueryUserToken` + `CreateProcessAsUserW`; on macOS/Linux it
/// drops from root into the target user's session.
///
/// `arg1` is the agent type; `arg2` is a JSON object
/// `{"workspace_path": "...", "prompt": "...", "home": "..."}`. Returns the
/// JSON-serialized `AgentCliFixSpawn` confirmation (interactive launches are
/// watched live in the operator's terminal, so there is no captured log file).
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub async fn utility_run_agent_cli_fix_interactive(
    agent_type: &str,
    args_json: &str,
) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Args {
        workspace_path: String,
        prompt: String,
        #[serde(default)]
        home: String,
    }

    let args: Args = serde_json::from_str(args_json).map_err(|e| {
        anyhow::anyhow!("Failed to parse run_agent_cli_fix_interactive args: {}", e)
    })?;
    let home_path = if args.home.is_empty() {
        crate::agent_plugin::real_home_dir()
    } else {
        Some(std::path::PathBuf::from(args.home))
    };

    let spawn = crate::agent_cli_insight::run_agent_cli_fix_interactive(
        agent_type,
        &args.workspace_path,
        &args.prompt,
        home_path.as_deref(),
    )?;
    serde_json::to_string(&spawn).map_err(|e| {
        anyhow::anyhow!(
            "Failed to serialize interactive fix launch confirmation: {}",
            e
        )
    })
}

/// Build the structural agent-visibility bundle (MCP inventory + risk findings,
/// agent component inventories, capability-graph edges) for the host. Like
/// `utility_collect_agent_transcripts`, this crosses the macOS sandbox boundary
/// on behalf of the (sandboxed) app so MCP config files under the user's actual
/// home directory are readable.
///
/// `arg1` is a reserved domain selector (`"all"` for MVP -- the full bundle is
/// always built in one discovery pass since it is cheap). `arg2` is a JSON
/// object carrying the user home: `{"home": "/Users/foo"}` (empty -> resolve
/// `real_home_dir()`).
pub async fn utility_collect_agent_visibility(_domain: &str, args_json: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Args {
        #[serde(default)]
        home: String,
    }

    let args: Args = if args_json.trim().is_empty() {
        Args {
            home: String::new(),
        }
    } else {
        serde_json::from_str(args_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse collect_agent_visibility args: {}", e))?
    };

    let home_path = if args.home.is_empty() {
        crate::agent_plugin::real_home_dir().ok_or_else(|| {
            anyhow::anyhow!("Unable to resolve real_home_dir for agent visibility")
        })?
    } else {
        std::path::PathBuf::from(args.home)
    };

    let bundle = crate::agent_visibility::build_visibility_bundle(&home_path);
    serde_json::to_string(&bundle)
        .map_err(|e| anyhow::anyhow!("Failed to serialize visibility bundle: {}", e))
}

/// Read a single instruction artifact body (skill / command / rule) on demand,
/// honoring the privacy tier (invariant I5). Crosses the macOS sandbox boundary
/// on behalf of the sandboxed app so files under the user's real home
/// (`~/.cursor/skills/...`, `~/.claude/...`) are readable.
///
/// `arg1` is the privacy tier selector (`metadata_only` | `redacted_excerpt` |
/// `forensic_full_content`). `arg2` is a JSON object `{"path": "...",
/// "home": "..."}`. The shared foundation reader enforces both guards
/// (instruction-artifact shape + confinement under `home`), so an arbitrary
/// file cannot be exfiltrated through this order.
pub async fn utility_read_instruction_content(tier: &str, args_json: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Args {
        #[serde(default)]
        path: String,
        #[serde(default)]
        home: String,
    }

    let args: Args = serde_json::from_str(args_json)
        .map_err(|e| anyhow::anyhow!("Failed to parse read_instruction_content args: {}", e))?;

    if args.path.trim().is_empty() {
        return Err(anyhow::anyhow!("read_instruction_content: empty path"));
    }

    let home_path = if args.home.is_empty() {
        crate::agent_plugin::real_home_dir().ok_or_else(|| {
            anyhow::anyhow!("Unable to resolve real_home_dir for instruction content read")
        })?
    } else {
        std::path::PathBuf::from(args.home)
    };

    let result = crate::agent_visibility::read_instruction_content(
        std::path::Path::new(&args.path),
        &home_path,
        tier,
    );
    serde_json::to_string(&result)
        .map_err(|e| anyhow::anyhow!("Failed to serialize instruction content result: {}", e))
}

/// Reveal a path in the operator's file manager. Crosses the macOS sandbox
/// boundary so transcript / instruction folders under the real home are
/// openable from the sandboxed app. `arg1` is the path (absolute or
/// dash-encoded workspace slug); `arg2` is the target user home (may be
/// empty -- helper then uses `real_home_dir()`).
pub async fn utility_reveal_path_in_file_manager(path: &str, user_home: &str) -> Result<String> {
    if path.trim().is_empty() {
        return Err(anyhow::anyhow!("reveal_path_in_file_manager: empty path"));
    }
    let home_path = if user_home.is_empty() {
        crate::agent_plugin::real_home_dir().ok_or_else(|| {
            anyhow::anyhow!("Unable to resolve real_home_dir for reveal_path_in_file_manager")
        })?
    } else {
        std::path::PathBuf::from(user_home)
    };
    let result = crate::file_reveal::reveal_path_in_file_manager(path, &home_path);
    serde_json::to_string(&result)
        .map_err(|e| anyhow::anyhow!("Failed to serialize reveal result: {}", e))
}

/// Resolve the distinct workspace roots referenced by a set of transcript
/// `source_paths` and collect each root's project-scoped instruction inventory
/// (`.cursor/rules`, `.claude/skills`, top-level `AGENTS.md`, ...). Like
/// `utility_collect_agent_visibility`, this crosses the macOS sandbox boundary
/// on behalf of the (sandboxed) app so the user's actual project directories are
/// readable.
///
/// `arg1` is reserved (unused). `arg2` is a JSON object carrying the transcript
/// source paths: `{"source_paths": ["/Users/.../projects/<slug>/.../x.jsonl"]}`.
/// The helper resolves each slug back to an on-disk directory itself (the app
/// cannot), so only the raw transcript paths cross the boundary.
pub async fn utility_collect_workspace_inventory(
    _reserved: &str,
    args_json: &str,
) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Args {
        #[serde(default)]
        source_paths: Vec<String>,
    }

    let args: Args = if args_json.trim().is_empty() {
        Args {
            source_paths: Vec::new(),
        }
    } else {
        serde_json::from_str(args_json).map_err(|e| {
            anyhow::anyhow!("Failed to parse collect_workspace_inventory args: {}", e)
        })?
    };

    let inventories = crate::agent_visibility::collect_workspace_inventories(&args.source_paths);
    serde_json::to_string(&inventories)
        .map_err(|e| anyhow::anyhow!("Failed to serialize workspace inventories: {}", e))
}

/// Confirm which observed instruction paths are absent on disk (a `NotFound`
/// stat, symlinks followed). Like `utility_collect_workspace_inventory`, this
/// crosses the macOS sandbox boundary on behalf of the (sandboxed) app so the
/// user's actual project / drive directories are stat-able.
///
/// `arg1` is reserved (unused). `arg2` is a JSON object carrying the candidate
/// paths: `{"paths": ["/Users/.../skills/x/SKILL.md"]}`. Returns a JSON array of
/// the confirmed-absent subset; the caller drops exactly those and keeps
/// everything else (fail-open).
pub async fn utility_confirm_absent_instruction_paths(
    _reserved: &str,
    args_json: &str,
) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Args {
        paths: Vec<String>,
    }

    let args: Args = if args_json.trim().is_empty() {
        Args { paths: Vec::new() }
    } else {
        serde_json::from_str(args_json).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse confirm_absent_instruction_paths args: {}",
                e
            )
        })?
    };

    let absent = crate::agent_visibility::confirm_absent_instruction_paths(&args.paths);
    serde_json::to_string(&absent)
        .map_err(|e| anyhow::anyhow!("Failed to serialize absent instruction paths: {}", e))
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
pub async fn utility_start_file_monitor(paths_json: &str, start_args_json: &str) -> Result<String> {
    #[derive(Default, serde::Deserialize)]
    struct StartFileMonitorArgs {
        user_home: String,
    }

    let start_args = if start_args_json.trim().is_empty() {
        StartFileMonitorArgs::default()
    } else {
        serde_json::from_str::<StartFileMonitorArgs>(start_args_json).unwrap_or_else(|_| {
            StartFileMonitorArgs {
                user_home: start_args_json.to_string(),
            }
        })
    };
    let user_home = start_args.user_home;

    {
        let mut guard = FIM_WATCHER.write().await;
        if let Some(watcher) = guard.take() {
            watcher.stop();
        }
    }

    let raw_paths: Vec<String> = serde_json::from_str(paths_json).unwrap_or_default();
    let user_home_path = (!user_home.is_empty()).then(|| std::path::Path::new(&user_home));
    let watch_paths =
        crate::fim_support::resolve_fim_watch_paths(&raw_paths, user_home_path, FimMode::Desktop);

    let config = crate::fim_support::current_fim_config();
    match FimWatcher::start(watch_paths, config) {
        Ok(watcher) => {
            let mut guard = FIM_WATCHER.write().await;
            *guard = Some(watcher);
            info!("File monitor started via helper");
            Ok("".to_string())
        }
        Err(e) => {
            error!("Failed to start file monitor: {}", e);
            order_error(&format!("start_file_monitor failed: {}", e), false)
        }
    }
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
pub async fn utility_stop_file_monitor() -> Result<String> {
    let mut guard = FIM_WATCHER.write().await;
    if let Some(watcher) = guard.take() {
        watcher.stop();
        info!("File monitor stopped via helper");
    }
    Ok("".to_string())
}

/// Bincode payload returned by `utility_get_file_events`. Both the helper
/// (sender, in this file) and the core (`helper_tx_utility::utility_get_file_events`
/// typed wrapper, the receiver) reference this same struct so the wire format
/// stays bit-identical.
///
/// `events` is either the full snapshot (`incremental == false`) or only the
/// subset whose `last_modified` is strictly newer than the helper-side cursor
/// stored in `FimWatcher::last_get_file_events_fetch_timestamp`
/// (`incremental == true`). The core merges incremental deltas into its own
/// `app_fim_cache` (an `Arc<FimEventStore>`), mirroring how the capture pipeline
/// merges incremental session deltas.
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FimEventsPayload {
    pub events: Vec<flodbadd::fim_events::FimEvent>,
    pub is_monitoring: bool,
    pub watch_paths: Vec<String>,
    pub event_count: u64,
    pub last_event_time: Option<String>,
    pub has_suspicious_events: bool,
    pub cursor_now: chrono::DateTime<chrono::Utc>,
    pub incremental: bool,
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
pub async fn utility_get_file_events(incremental: bool) -> Result<String> {
    let start = Instant::now();
    let now = chrono::Utc::now();

    // Snapshot only what we need under the FIM_WATCHER read lock, then drop
    // the guard. The Tier-3 fallback in backfill_missing_process_attribution
    // probes live processes via lsof / sysinfo, which can stall on macOS
    // sandbox / SIP boundaries. Holding FIM_WATCHER.read() across that work
    // starves utility_start_file_monitor / utility_stop_file_monitor writers
    // (Sentry: EDAMAME-HELPER-1HP).
    //
    // We also clone the watcher's store + watch_paths + monitoring flag here,
    // and call `watcher.get_events(incremental)` AFTER dropping the read guard
    // by carrying the cursor lock through the cloned store/state path.
    let snapshot_inputs = {
        let guard = FIM_WATCHER.read().await;
        guard.as_ref().map(|watcher| {
            (
                watcher.store_arc(),
                watcher
                    .watch_paths()
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect::<Vec<_>>(),
                watcher.is_running(),
                watcher.fetch_cursor(),
            )
        })
    };

    let payload = match snapshot_inputs {
        Some((store, watch_paths, is_monitoring, cursor)) => {
            // Backfill mutates the store and bumps `last_modified` on affected
            // events so the next incremental tick picks them up automatically.
            flodbadd::fim::backfill_missing_process_attribution(
                &store,
                FIM_PROCESS_ATTRIBUTION_BACKFILL_LIMIT,
            );

            // Mirror `FlodbaddCapture::get_sessions(incremental: bool)`:
            // read the previous cursor, fetch deltas, then advance the cursor.
            let prev_cursor = {
                let reader = cursor.read().await;
                *reader
            };
            let events = if incremental {
                store.get_events_modified_since(prev_cursor)
            } else {
                store.get_all_events()
            };
            {
                let mut writer = cursor.write().await;
                *writer = now;
            }

            let event_count = store.event_count() as u64;
            let last_event_time = events.first().map(|e| e.last_modified.to_rfc3339());
            let has_suspicious = store.has_suspicious_events();

            FimEventsPayload {
                events,
                is_monitoring,
                watch_paths,
                event_count,
                last_event_time,
                has_suspicious_events: has_suspicious,
                cursor_now: now,
                incremental,
            }
        }
        None => FimEventsPayload {
            events: vec![],
            is_monitoring: false,
            watch_paths: vec![],
            event_count: 0,
            last_event_time: None,
            has_suspicious_events: false,
            cursor_now: now,
            incremental,
        },
    };

    // bincode + base64, same envelope as utility_get_sessions, so the gRPC
    // string-only channel can carry binary payloads end-to-end.
    let bincode_payload = match bincode::serde::encode_to_vec(&payload, bincode::config::standard())
    {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Error serializing FIM events to bincode: {}", e);
            return order_error(
                &format!("error serializing FIM events to bincode: {}", e),
                false,
            );
        }
    };
    let bincode_len = bincode_payload.len();
    let encoded = general_purpose::STANDARD.encode(&bincode_payload);
    let elapsed_ms = start.elapsed().as_millis();

    info!(
        "Returning {} FIM events, incremental: {}, size: {} bytes (bincode: {} bytes, total: {}ms)",
        payload.events.len(),
        incremental,
        encoded.len(),
        bincode_len,
        elapsed_ms
    );

    Ok(encoded)
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
pub async fn utility_get_file_monitor_status() -> Result<String> {
    // Same pattern as utility_get_file_events: snapshot under the lock,
    // drop the guard, then serialize. This call is invoked very frequently
    // (~4 Hz) by the core's fim_event_sync_task; keeping it lock-cheap
    // prevents it from competing with start/stop_file_monitor writers.
    let snapshot_inputs = {
        let guard = FIM_WATCHER.read().await;
        guard.as_ref().map(|watcher| {
            (
                watcher.store_arc(),
                watcher.is_running(),
                watcher
                    .watch_paths()
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect::<Vec<_>>(),
            )
        })
    };

    let status = match snapshot_inputs {
        Some((store, is_running, watch_paths)) => {
            let all_events = store.get_all_events();
            serde_json::json!({
                "is_monitoring": is_running,
                "watch_paths": watch_paths,
                "event_count": store.event_count() as u64,
                "last_event_time": all_events.first().map(|e| e.timestamp.to_rfc3339()),
            })
        }
        None => serde_json::json!({
            "is_monitoring": false,
            "watch_paths": [],
            "event_count": 0,
            "last_event_time": null,
        }),
    };

    serde_json::to_string(&status)
        .map_err(|e| anyhow::anyhow!("Failed to serialize FIM status: {}", e))
}

#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "fim"
))]
pub async fn utility_clear_file_events() -> Result<String> {
    // Snapshot the store handle, drop the guard, then clear. Keeps writers
    // (start/stop_file_monitor) unblocked even if the underlying clear ends
    // up doing more work than expected.
    let store_arc = {
        let guard = FIM_WATCHER.read().await;
        guard.as_ref().map(|w| w.store_arc())
    };
    if let Some(store) = store_arc {
        store.clear();
        info!("File events cleared via helper");
    }
    Ok("".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use flodbadd::sessions::DomainResolutionType;
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
            src_domain_type: DomainResolutionType::Forward,
            dst_domain_type: DomainResolutionType::Forward,
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
