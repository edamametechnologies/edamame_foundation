use crate::helper_tx::helper_utility_order;
use crate::lanscan_sessions::*;
use anyhow::{anyhow, Result};
use macaddr::MacAddr6;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::warn;

pub async fn utility_broadcast_ping(broadcast_addr: &str) -> Result<Vec<IpAddr>> {
    let result_json = helper_utility_order("broadcast_ping", broadcast_addr).await?;
    let result: Vec<IpAddr> = serde_json::from_str(&result_json)
        .map_err(|e| anyhow!("Failed to parse broadcast_ping result: {}", e))?;
    Ok(result)
}

pub async fn utility_get_neighbors(
    interface: &str,
) -> Result<Vec<(MacAddr6, Vec<Ipv4Addr>, Vec<Ipv6Addr>)>> {
    let result_json = helper_utility_order("get_neighbors", interface).await?;
    let result: Vec<(MacAddr6, Vec<Ipv4Addr>, Vec<Ipv6Addr>)> = serde_json::from_str(&result_json)
        .map_err(|e| anyhow!("Failed to parse neighbors result: {}", e))?;
    Ok(result)
}

pub async fn utility_arp_resolve(
    addresses: &[(String, Ipv4Addr)],
) -> Result<Vec<(String, Ipv4Addr, MacAddr6)>> {
    let addresses_json = serde_json::to_string(&addresses)?;
    let result_json = helper_utility_order("arp_resolve", &addresses_json).await?;
    let result: Vec<(String, Ipv4Addr, MacAddr6)> = serde_json::from_str(&result_json)
        .map_err(|e| anyhow!("Failed to parse arp_resolve result: {}", e))?;
    Ok(result)
}

pub async fn utility_mdns_resolve(
    addresses: &[IpAddr],
) -> Result<Vec<(IpAddr, String, MacAddr6, Vec<String>)>> {
    let addresses_json = serde_json::to_string(&addresses)?;
    let result_json = helper_utility_order("mdns_resolve", &addresses_json).await?;
    let result: Vec<(IpAddr, String, MacAddr6, Vec<String>)> =
        serde_json::from_str(&result_json)
            .map_err(|e| anyhow!("Failed to parse mdns_resolve result: {}", e))?;
    Ok(result)
}

pub async fn utility_getappleid_email(username: &str) -> Result<String> {
    // Get the email through the helper if present
    #[cfg(target_os = "macos")]
    match helper_utility_order("getappleid_email", username).await {
        Ok(email) => Ok(email),
        Err(e) => {
            warn!("Failed to get email from utility order: {}", e);
            Ok("".to_string())
        }
    }
}

pub async fn utility_helper_check() -> Result<String> {
    let result_string = helper_utility_order("helper_check", "").await?;
    Ok(result_string)
}

pub async fn utility_helper_flags() -> Result<String> {
    let result_string = helper_utility_order("helper_flags", "").await?;
    Ok(result_string)
}

pub async fn utility_get_logs() -> Result<String> {
    let result_string = helper_utility_order("get_logs", "").await?;
    Ok(result_string)
}

pub async fn utility_start_capture() -> Result<()> {
    helper_utility_order("start_capture", "").await?;
    Ok(())
}

pub async fn utility_stop_capture() -> Result<()> {
    helper_utility_order("stop_capture", "").await?;
    Ok(())
}

pub async fn utility_restart_capture() -> Result<()> {
    helper_utility_order("restart_capture", "").await?;
    Ok(())
}

pub async fn utility_set_whitelist(whitelist_name: &str) -> Result<()> {
    helper_utility_order("set_whitelist", whitelist_name).await?;
    Ok(())
}

pub async fn utility_set_filter(filter: &SessionFilter) -> Result<()> {
    let filter_json = serde_json::to_string(filter)?;
    helper_utility_order("set_filter", &filter_json).await?;
    Ok(())
}

pub async fn utility_get_current_sessions() -> Result<Vec<SessionInfo>> {
    let result_json = helper_utility_order("get_current_sessions", "true").await?;
    serde_json::from_str(&result_json)
        .map_err(|e| anyhow!("Failed to parse current sessions result: {}", e))
}

pub async fn utility_is_capturing() -> Result<bool> {
    let result = helper_utility_order("is_capturing", "").await?;
    result
        .parse::<bool>()
        .map_err(|e| anyhow!("Failed to parse is_capturing result: {}", e))
}

pub async fn utility_get_whitelist() -> Result<String> {
    let result_string = helper_utility_order("get_whitelist", "").await?;
    Ok(result_string)
}

pub async fn utility_get_filter() -> Result<SessionFilter> {
    let result_json = helper_utility_order("get_filter", "").await?;
    serde_json::from_str(&result_json).map_err(|e| anyhow!("Failed to parse filter result: {}", e))
}

pub async fn utility_get_sessions() -> Result<Vec<SessionInfo>> {
    let result_json = helper_utility_order("get_sessions", "").await?;
    serde_json::from_str(&result_json)
        .map_err(|e| anyhow!("Failed to parse sessions result: {}", e))
}

pub async fn utility_get_whitelist_conformance() -> Result<bool> {
    let result = helper_utility_order("get_whitelist_conformance", "").await?;
    result
        .parse::<bool>()
        .map_err(|e| anyhow!("Failed to parse whitelist conformance result: {}", e))
}

pub async fn utility_get_whitelist_exceptions() -> Result<Vec<SessionInfo>> {
    let result_json = helper_utility_order("get_whitelist_exceptions", "").await?;
    serde_json::from_str(&result_json)
        .map_err(|e| anyhow!("Failed to parse whitelist exceptions result: {}", e))
}
