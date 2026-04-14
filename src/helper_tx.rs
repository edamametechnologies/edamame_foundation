use crate::helper_proto::*;
use crate::order_type::*;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use edamame_proto::edamame_helper_client::EdamameHelperClient;
use edamame_proto::HelperRequest;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{debug, trace, warn};

pub static HELPER_FATAL_ERROR: AtomicBool = AtomicBool::new(false);

pub const UTILITY_ORDER_NAMES: &[&str] = &[
    "arp_resolve",
    "augment_custom_whitelists",
    "broadcast_ping",
    "clear_file_events",
    "compare_custom_whitelists",
    "create_custom_whitelists",
    "get_agent_plugin_status",
    "get_blacklisted_sessions",
    "get_blacklisted_status",
    "get_blacklists",
    "get_current_sessions",
    "get_file_events",
    "get_file_monitor_status",
    "get_filter",
    "get_logs",
    "get_neighbors",
    "get_packet_stats",
    "get_peer_ids",
    "get_sessions",
    "get_whitelist_conformance",
    "get_whitelist_exceptions",
    "get_whitelist_name",
    "get_whitelists",
    "getappleid_email",
    "helper_check",
    "helper_flags",
    "is_capturing",
    "list_agent_plugins",
    "mdns_resolve",
    "merge_custom_whitelists",
    "provision_agent_plugin",
    "restart_capture",
    "set_custom_blacklists",
    "set_custom_whitelists",
    "set_filter",
    "set_whitelist",
    "start_capture",
    "start_file_monitor",
    "stop_capture",
    "stop_file_monitor",
    "test_agent_plugin",
    "uninstall_agent_plugin",
];

// Version
pub static CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Cached gRPC channel and its credential fingerprint.
/// The fingerprint (hash of ca_pem + client_pem + client_key) lets us
/// detect credential rotation and rebuild the channel.
static CHANNEL_CACHE: Mutex<Option<CachedChannel>> = Mutex::const_new(None);

struct CachedChannel {
    channel: Channel,
    cred_fingerprint: u64,
}

fn credential_fingerprint(ca_pem: &str, client_pem: &str, client_key: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ca_pem.hash(&mut hasher);
    client_pem.hash(&mut hasher);
    client_key.hash(&mut hasher);
    hasher.finish()
}

fn decode_and_build_tls(
    ca_pem: &str,
    client_pem: &str,
    client_key: &str,
) -> Result<ClientTlsConfig> {
    let ca_decoded = general_purpose::STANDARD.decode(ca_pem)?;
    let ca_str = str::from_utf8(&ca_decoded)?;
    let ca_cert = Certificate::from_pem(ca_str);

    let cert_decoded = general_purpose::STANDARD.decode(client_pem)?;
    let cert_str = str::from_utf8(&cert_decoded)?;

    let key_decoded = general_purpose::STANDARD.decode(client_key)?;
    let key_str = str::from_utf8(&key_decoded)?;

    let identity = Identity::from_pem(cert_str, key_str);

    Ok(ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(ca_cert)
        .identity(identity))
}

async fn connect_channel(
    tls: ClientTlsConfig,
    target: &'static str,
) -> Result<Channel> {
    let endpoint = Channel::from_static(target)
        .tls_config(tls)?
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(120))
        .keep_alive_while_idle(true);

    let channel = timeout(Duration::from_secs(120), endpoint.connect()).await??;
    Ok(channel)
}

async fn get_or_create_channel(
    ca_pem: &str,
    client_pem: &str,
    client_key: &str,
    target: &'static str,
) -> Result<Channel> {
    let fp = credential_fingerprint(ca_pem, client_pem, client_key);
    let mut cache = CHANNEL_CACHE.lock().await;

    if let Some(cached) = cache.as_ref() {
        if cached.cred_fingerprint == fp {
            return Ok(cached.channel.clone());
        }
        debug!("Credential fingerprint changed, rebuilding gRPC channel");
    }

    let tls = decode_and_build_tls(ca_pem, client_pem, client_key)?;
    let channel = connect_channel(tls, target).await?;

    *cache = Some(CachedChannel {
        channel: channel.clone(),
        cred_fingerprint: fp,
    });

    Ok(channel)
}

/// Invalidate the cached channel so the next call creates a fresh connection.
fn invalidate_channel_cache() {
    if let Ok(mut cache) = CHANNEL_CACHE.try_lock() {
        *cache = None;
    }
}

pub async fn helper_run_utility(
    subordertype: &str,
    arg1: &str,
    arg2: &str,
    ca_pem: &str,
    client_pem: &str,
    client_key: &str,
    target: &'static str,
) -> Result<String> {
    // No signature for utility orders
    match helper_run(
        "utilityorder",
        subordertype,
        arg1,
        arg2,
        "",
        ca_pem,
        client_pem,
        client_key,
        target,
    )
    .await
    {
        Ok(result) => {
            trace!("Unsetting the HELPER_FATAL_ERROR flag");
            HELPER_FATAL_ERROR.store(false, Ordering::Relaxed);
            Ok(result)
        }
        Err(e) => {
            if e.to_string().contains("Fatal") {
                trace!("Setting the HELPER_FATAL_ERROR flag");
                HELPER_FATAL_ERROR.store(true, Ordering::Relaxed);
            }
            Err(e)
        }
    }
}

pub async fn helper_run_metric(
    subordertype: MetricOrderType,
    threat: &str,
    username: &str,
    signature: &str,
    ca_pem: &str,
    client_pem: &str,
    client_key: &str,
    target: &'static str,
) -> Result<String> {
    // Convert to string using the Display trait
    match helper_run(
        "metricorder",
        &subordertype.to_string(),
        threat,
        username,
        signature,
        ca_pem,
        client_pem,
        client_key,
        target,
    )
    .await
    {
        Ok(result) => {
            trace!("Unsetting the HELPER_FATAL_ERROR flag");
            HELPER_FATAL_ERROR.store(false, Ordering::Relaxed);
            Ok(result)
        }
        Err(e) => {
            if e.to_string().contains("Fatal") {
                trace!("Setting the HELPER_FATAL_ERROR flag");
                HELPER_FATAL_ERROR.store(true, Ordering::Relaxed);
            }
            Err(e)
        }
    }
}

async fn helper_run(
    ordertype: &str,
    subordertype: &str,
    arg1: &str,
    arg2: &str,
    signature: &str,
    ca_pem: &str,
    client_pem: &str,
    client_key: &str,
    target: &'static str,
) -> Result<String> {
    trace!("helper_run {} / {}", ordertype, subordertype);

    let result = helper_run_with_channel(
        ordertype, subordertype, arg1, arg2, signature,
        ca_pem, client_pem, client_key, target,
    ).await;

    match result {
        Ok(output) => Ok(output),
        Err(first_err) => {
            warn!(
                "gRPC call {} / {} failed on cached channel, retrying with fresh connection: {}",
                ordertype, subordertype, first_err
            );
            invalidate_channel_cache();
            helper_run_with_channel(
                ordertype, subordertype, arg1, arg2, signature,
                ca_pem, client_pem, client_key, target,
            ).await
        }
    }
}

async fn helper_run_with_channel(
    ordertype: &str,
    subordertype: &str,
    arg1: &str,
    arg2: &str,
    signature: &str,
    ca_pem: &str,
    client_pem: &str,
    client_key: &str,
    target: &'static str,
) -> Result<String> {
    let channel = get_or_create_channel(ca_pem, client_pem, client_key, target).await?;

    let mut client = EdamameHelperClient::new(channel)
        .max_decoding_message_size(1000 * 1024 * 1024)
        .max_encoding_message_size(1000 * 1024 * 1024);

    let request = tonic::Request::new(HelperRequest {
        ordertype: ordertype.to_owned(),
        subordertype: subordertype.to_owned(),
        arg1: arg1.to_owned(),
        arg2: arg2.to_owned(),
        signature: signature.to_owned(),
        version: CARGO_PKG_VERSION.to_string(),
    });

    let response = match timeout(Duration::from_secs(180), client.execute(request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            return Err(anyhow!(
                "Error sending request {} / {} to helper: {:?}",
                ordertype,
                subordertype,
                e
            ))
        }
        Err(_) => {
            return Err(anyhow!(
                "Timeout sending request {} / {} to helper (180s exceeded)",
                ordertype,
                subordertype,
            ))
        }
    };
    let output = response.into_inner().output;
    trace!("Helper response: {:?}", output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_decoding_and_creation() {
        let ca_pem = std::env::var("EDAMAME_CA_PEM")
            .unwrap_or("".to_string())
            .trim_matches('"')
            .to_string();
        let client_pem = std::env::var("EDAMAME_CLIENT_PEM")
            .unwrap_or("".to_string())
            .trim_matches('"')
            .to_string();
        let client_key = std::env::var("EDAMAME_CLIENT_KEY")
            .unwrap_or("".to_string())
            .trim_matches('"')
            .to_string();

        // Decode the CA certificate
        let server_root_ca_cert_base64 = ca_pem;
        let server_root_ca_cert_decoded = general_purpose::STANDARD
            .decode(&server_root_ca_cert_base64)
            .expect("Failed to decode server root CA certificate");
        let server_root_ca_cert = str::from_utf8(&server_root_ca_cert_decoded)
            .expect("Failed to convert server root CA certificate to string");
        let server_root_ca_cert = Certificate::from_pem(server_root_ca_cert);

        // Decode the client certificate
        let client_cert_base64 = client_pem;
        let client_cert_decoded = general_purpose::STANDARD
            .decode(&client_cert_base64)
            .expect("Failed to decode client certificate");
        let client_cert = str::from_utf8(&client_cert_decoded)
            .expect("Failed to convert client certificate to string");

        // Decode the client key
        let client_key_base64 = client_key;
        let client_key_decoded = general_purpose::STANDARD
            .decode(&client_key_base64)
            .expect("Failed to decode client key");
        let client_key =
            str::from_utf8(&client_key_decoded).expect("Failed to convert client key to string");

        // Create client identity
        let client_identity = Identity::from_pem(client_cert, client_key);

        // Create TLS config
        let _ = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(server_root_ca_cert)
            .identity(client_identity);
    }
}
