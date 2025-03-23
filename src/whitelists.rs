use crate::cloud_model::*;
use crate::lanscan_sessions::SessionInfo;
use crate::rwlock::CustomRwLock;
use crate::whitelists_db::WHITELISTS;
use anyhow::{anyhow, Context, Result};
use chrono;
use dashmap::DashMap;
use ipnet::IpNet;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, trace, warn};

// Constants
const WHITELISTS_FILE_NAME: &str = "whitelists-db.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct WhitelistEndpoint {
    pub domain: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub as_number: Option<u32>,
    pub as_country: Option<String>,
    pub as_owner: Option<String>,
    pub process: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct WhitelistInfo {
    pub name: String,
    pub extends: Option<Vec<String>>,
    pub endpoints: Vec<WhitelistEndpoint>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct WhitelistsJSON {
    pub date: String,
    pub signature: Option<String>,
    pub whitelists: Vec<WhitelistInfo>,
}

pub struct Whitelists {
    pub date: String,
    pub signature: Option<String>,
    pub whitelists: DashMap<String, WhitelistInfo>,
}

impl From<Whitelists> for WhitelistsJSON {
    fn from(whitelists: Whitelists) -> Self {
        WhitelistsJSON {
            date: whitelists.date,
            signature: whitelists.signature,
            whitelists: whitelists
                .whitelists
                .iter()
                .map(|r| r.value().clone())
                .collect(),
        }
    }
}

impl CloudSignature for Whitelists {
    fn get_signature(&self) -> String {
        self.signature.clone().unwrap_or_default()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }
}

impl Whitelists {
    /// Creates a new Whitelists instance from the provided JSON data.
    pub fn new_from_json(whitelist_info: WhitelistsJSON) -> Self {
        info!("Loading whitelists from JSON");

        let whitelists = DashMap::new();

        for info in whitelist_info.whitelists {
            whitelists.insert(info.name.clone(), info);
        }

        info!("Loaded {} whitelists", whitelists.len());

        Whitelists {
            date: whitelist_info.date,
            signature: whitelist_info.signature,
            whitelists,
        }
    }

    // Create a whitelist from a list of sessions
    pub fn new_from_sessions(sessions: &Vec<SessionInfo>) -> Self {
        let whitelists = DashMap::new();

        // Create a whitelist with the current sessions
        let mut endpoints = Vec::new();
        // HashSet to track unique endpoint fingerprints for deduplication
        let mut unique_fingerprints = std::collections::HashSet::new();

        for session in sessions {
            let endpoint = WhitelistEndpoint {
                // Do not include the domain if set to "Unknown" or "Resolving"
                domain: if session.dst_domain == Some("Unknown".to_string())
                    || session.dst_domain == Some("Resolving".to_string())
                {
                    None
                } else {
                    session.dst_domain.clone()
                },
                // Always include the IP address as a fallback to when the domain is set but not resolved
                ip: Some(session.session.dst_ip.to_string()),
                // Always include the port
                port: Some(session.session.dst_port),
                // Always include the protocol
                protocol: Some(session.session.protocol.to_string()),
                // Don't include AS info
                as_number: None, // Session doesn't have AS info
                as_country: None,
                as_owner: None,
                // Include the process info if available
                process: session.l7.as_ref().map(|l7| l7.process_name.clone()),
                description: Some(format!(
                    "Auto-generated from session: {}:{} -> {}:{}",
                    session.session.src_ip,
                    session.session.src_port,
                    session.session.dst_ip,
                    session.session.dst_port
                )),
            };

            // Create a fingerprint tuple that uniquely identifies this endpoint
            // (excluding description which doesn't affect deduplication)
            let fingerprint = (
                endpoint.domain.clone(),
                endpoint.ip.clone(),
                endpoint.port,
                endpoint.protocol.clone(),
                endpoint.as_number,
                endpoint.as_country.clone(),
                endpoint.as_owner.clone(),
                endpoint.process.clone(),
            );

            // Only add the endpoint if we haven't seen this fingerprint before
            if unique_fingerprints.insert(fingerprint) {
                endpoints.push(endpoint);
            }
        }

        let whitelist_info = WhitelistInfo {
            name: "custom_whitelist".to_string(),
            extends: None,
            endpoints,
        };

        whitelists.insert(whitelist_info.name.clone(), whitelist_info);

        // Use "Month DDth YYYY" format as seen in whitelists-db.json
        let today = chrono::Local::now().format("%B %dth %Y").to_string();

        Whitelists {
            date: today,
            signature: None, // No signature for auto-generated whitelists
            whitelists,
        }
    }

    /// Retrieves all endpoints for a given whitelist, including inherited ones.
    fn get_all_endpoints(
        &self,
        whitelist_name: &str,
        visited: &mut HashSet<String>,
    ) -> Result<Vec<WhitelistEndpoint>> {
        // Get the whitelist info and handle the case where it's not found
        let info = self
            .whitelists
            .get(whitelist_name)
            .ok_or_else(|| anyhow!("Whitelist not found: {}", whitelist_name))?;

        // Clone the necessary data
        let endpoints = info.endpoints.clone();
        let extends = info.extends.clone();

        // Drop the Ref to release the lock on the DashMap
        drop(info);

        // Initialize the list of all endpoints with the current ones
        let mut all_endpoints = endpoints;

        if let Some(extends) = extends {
            for parent in extends {
                if !visited.contains(&parent) {
                    visited.insert(parent.clone());
                    // Recursively get endpoints from inherited whitelists
                    all_endpoints.extend(self.get_all_endpoints(&parent, visited)?);
                }
            }
        }
        Ok(all_endpoints)
    }
}

// Global LISTS Variable using lazy_static! and Tokio's RwLock
lazy_static! {
    pub static ref LISTS: CustomRwLock<CloudModel<Whitelists>> = {
        let model = CloudModel::initialize(WHITELISTS_FILE_NAME.to_string(), WHITELISTS, |data| {
            let whitelist_info_json: WhitelistsJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(Whitelists::new_from_json(whitelist_info_json))
        })
        .expect("Failed to initialize CloudModel");
        CustomRwLock::new(model)
    };
}

pub async fn is_valid_whitelist(whitelist_name: &str) -> bool {
    LISTS
        .read()
        .await
        .data
        .read()
        .await
        .whitelists
        .contains_key(whitelist_name)
}

/// Checks if a given session is in the specified whitelist.
pub async fn is_session_in_whitelist(
    session_domain: Option<&str>,
    session_ip: Option<&str>,
    port: u16,
    protocol: &str,
    custom_whitelists: &Arc<CustomRwLock<Option<Whitelists>>>,
    whitelist_name: &str,
    as_number: Option<u32>,
    as_country: Option<&str>,
    as_owner: Option<&str>,
    process: Option<&str>,
) -> bool {
    trace!(
        "Checking if domain: {:?}, ip: {:?}, port: {} ({}) is in whitelist {} with ASN {:?}, Country {:?}, Owner {:?}, L7 Process {:?}",
        session_domain,
        session_ip,
        port,
        protocol,
        whitelist_name,
        as_number,
        as_country,
        as_owner,
        process
    );

    let mut visited = HashSet::new();
    visited.insert(whitelist_name.to_string());

    // Decide which whitelist to use (custom or global)
    let custom_guard = custom_whitelists.read().await;
    let endpoints = if let Some(whitelists) = custom_guard.as_ref() {
        // We have a custom whitelist, use it
        let custom_endpoints = whitelists.get_all_endpoints(whitelist_name, &mut visited);

        // Drop the guard to avoid holding it longer than needed
        drop(custom_guard);

        match custom_endpoints {
            Ok(eps) => eps,
            Err(err) => {
                warn!("Error retrieving endpoints from custom whitelist: {}", err);
                return false;
            }
        }
    } else {
        // No custom whitelist, use the global one
        // Drop the custom guard first to avoid potential deadlocks
        drop(custom_guard);

        let global_guard = LISTS.read().await;
        let global_data_guard = global_guard.data.read().await;

        let global_endpoints = global_data_guard.get_all_endpoints(whitelist_name, &mut visited);

        // Drop the guards
        drop(global_data_guard);
        drop(global_guard);

        match global_endpoints {
            Ok(eps) => eps,
            Err(err) => {
                warn!("Error retrieving endpoints from global whitelist: {}", err);
                return false;
            }
        }
    };

    // Match the session against the endpoints
    endpoints.iter().any(|endpoint| {
        endpoint_matches(
            session_domain,
            session_ip,
            port,
            protocol,
            as_number,
            as_country,
            as_owner,
            process,
            endpoint,
        )
    })
}

/// Helper function to match the session against a whitelist endpoint.
fn endpoint_matches(
    session_domain: Option<&str>,
    session_ip: Option<&str>,
    port: u16,
    protocol: &str,
    as_number: Option<u32>,
    as_country: Option<&str>,
    as_owner: Option<&str>,
    process: Option<&str>,
    endpoint: &WhitelistEndpoint,
) -> bool {
    let domain_match = domain_matches(session_domain, &endpoint.domain);
    let ip_match = ip_matches(session_ip, &endpoint.ip);
    let port_match = port_matches(port, endpoint.port);
    let protocol_match = protocol_matches(protocol, &endpoint.protocol);
    let as_number_match = as_number_matches(as_number, endpoint.as_number);
    let country_match = as_country_matches(as_country, &endpoint.as_country);
    let owner_match = as_owner_matches(as_owner, &endpoint.as_owner);
    let l7_match = process_matches(process, &endpoint.process);

    if domain_match
        && ip_match
        && port_match
        && protocol_match
        && as_number_match
        && country_match
        && owner_match
        && l7_match
    {
        trace!("Matched whitelist endpoint: {:?}", endpoint);
        true
    } else {
        trace!(
            "Did not match whitelist endpoint: {:?}, Reasons: domain_match={}, ip_match={}, port_match={}, protocol_match={}, as_number_match={}, country_match={}, owner_match={}, l7_match={}",
            endpoint,
            domain_match,
            ip_match,
            port_match,
            protocol_match,
            as_number_match,
            country_match,
            owner_match,
            l7_match
        );
        false
    }
}

/// Helper function to match domain names with optional wildcards.
fn domain_matches(session_domain: Option<&str>, endpoint_domain: &Option<String>) -> bool {
    match endpoint_domain {
        Some(pattern) => match session_domain {
            Some(domain) => {
                // Convert both to lowercase for case-insensitive matching
                let domain = domain.to_lowercase();
                let pattern = pattern.to_lowercase();

                // Check if pattern contains a wildcard
                if pattern.contains('*') {
                    // Handle prefix wildcard (*.example.com)
                    if pattern.starts_with("*.") {
                        let suffix = &pattern[2..]; // Remove the "*." prefix

                        // If domain exactly matches suffix (e.g., "example.com" vs "*.example.com"),
                        // this should NOT match since *.example.com means there must be a subdomain
                        if domain == suffix {
                            return false;
                        }

                        // For wildcard to match, domain must end with the suffix
                        return domain.ends_with(suffix);
                    }

                    // Handle suffix wildcard (example.*)
                    if pattern.ends_with(".*") {
                        let prefix = &pattern[..pattern.len() - 2]; // Remove the ".*" suffix

                        // For wildcard to match:
                        // 1. domain must start with the prefix
                        // 2. if the domain is longer than the prefix, the next character must be a dot
                        //    (ensuring prefix is a complete domain component)
                        if domain.starts_with(prefix) {
                            if domain.len() == prefix.len() {
                                // Domain exactly matches prefix, which is valid
                                return true;
                            } else if domain.len() > prefix.len()
                                && domain.as_bytes()[prefix.len()] == b'.'
                            {
                                // Domain has the prefix followed by a dot, which is valid
                                return true;
                            }
                        }

                        // All other cases are not matches
                        return false;
                    }

                    // Handle middle position wildcard (prefix.*.suffix)
                    let parts: Vec<&str> = pattern.split('*').collect();
                    if parts.len() == 2 {
                        let prefix = parts[0];
                        let suffix = parts[1];

                        // For wildcard to match, domain must start with prefix and end with suffix
                        // and the domain must be longer than just the prefix and suffix combined
                        return domain.starts_with(prefix)
                            && domain.ends_with(suffix)
                            && domain.len() > prefix.len() + suffix.len();
                    }

                    // Unsupported wildcard pattern
                    return false;
                }

                // Exact match for non-wildcard patterns
                domain == pattern
            }
            None => false,
        },
        None => true, // No domain specified in the endpoint, so it's a match
    }
}

/// Helper function to match IP addresses and prefixes.
fn ip_matches(session_ip: Option<&str>, endpoint_ip: &Option<String>) -> bool {
    match endpoint_ip {
        Some(pattern) => match session_ip {
            Some(ip_str) => {
                let ip_addr = match ip_str.parse::<IpAddr>() {
                    Ok(ip) => ip,
                    Err(_) => return false,
                };

                if pattern.contains('/') {
                    // Pattern is an IP network (e.g., "192.168.1.0/24")
                    match pattern.parse::<IpNet>() {
                        Ok(ip_network) => ip_network.contains(&ip_addr),
                        Err(_) => false,
                    }
                } else {
                    // Pattern is a single IP address
                    match pattern.parse::<IpAddr>() {
                        Ok(pattern_ip) => pattern_ip == ip_addr,
                        Err(_) => false,
                    }
                }
            }
            None => false,
        },
        None => true, // No IP specified in the endpoint, so it's a match
    }
}

/// Helper function to match ports.
fn port_matches(port: u16, whitelist_port: Option<u16>) -> bool {
    whitelist_port.map_or(true, |wp| wp == port)
}

/// Helper functions to match ASN and L7 criteria
fn as_number_matches(session_as_number: Option<u32>, whitelist_as_number: Option<u32>) -> bool {
    match whitelist_as_number {
        Some(w_as_number) => session_as_number == Some(w_as_number),
        None => true,
    }
}

fn as_country_matches(
    session_as_country: Option<&str>,
    whitelist_as_country: &Option<String>,
) -> bool {
    match whitelist_as_country {
        Some(w_country) => match session_as_country {
            Some(s_country) => s_country.eq_ignore_ascii_case(w_country),
            None => false,
        },
        None => true,
    }
}

fn as_owner_matches(session_as_owner: Option<&str>, whitelist_as_owner: &Option<String>) -> bool {
    match whitelist_as_owner {
        Some(w_owner) => match session_as_owner {
            Some(s_owner) => s_owner.eq_ignore_ascii_case(w_owner),
            None => false,
        },
        None => true,
    }
}

fn process_matches(session_l7: Option<&str>, whitelist_l7: &Option<String>) -> bool {
    match whitelist_l7 {
        Some(w_l7) => match session_l7 {
            Some(s_l7) => s_l7.eq_ignore_ascii_case(w_l7),
            None => false,
        },
        None => true,
    }
}

fn protocol_matches(session_protocol: &str, whitelist_protocol: &Option<String>) -> bool {
    match whitelist_protocol {
        // Convert to uppercase both sides
        Some(w_protocol) => session_protocol.eq_ignore_ascii_case(w_protocol),
        None => true,
    }
}

/// Updates the whitelists by fetching the latest data from the specified branch.
/// This function utilizes the `CloudModel` to perform the update.
pub async fn update_whitelists(branch: &str) -> Result<UpdateStatus> {
    info!("Starting whitelists update from backend");

    // Acquire lock on LISTS
    let model = LISTS.read().await;

    // Perform the update
    let status = model
        .update(branch, false, |data| {
            let whitelist_info_json: WhitelistsJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(Whitelists::new_from_json(whitelist_info_json))
        })
        .await?;

    match status {
        UpdateStatus::Updated => info!("Whitelists were successfully updated."),
        UpdateStatus::NotUpdated => info!("Whitelists are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the whitelists data."),
    }

    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Helper function to initialize LISTS with controlled test data
    async fn initialize_test_whitelists() {
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-19".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![
                WhitelistInfo {
                    name: "base_whitelist".to_string(),
                    extends: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("example.com".to_string()),
                        ip: None,
                        port: Some(443),
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("HTTPS endpoint".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "extended_whitelist".to_string(),
                    extends: Some(vec!["base_whitelist".to_string()]),
                    endpoints: vec![WhitelistEndpoint {
                        domain: None,
                        ip: Some("192.168.1.0/24".to_string()),
                        port: Some(80),
                        protocol: Some("TCP".to_string()),
                        as_number: Some(12345),
                        as_country: Some("US".to_string()),
                        as_owner: Some("Test ISP".to_string()),
                        process: Some("nginx".to_string()),
                        description: Some("Internal web server".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "wildcard_whitelist".to_string(),
                    extends: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("*.example.com".to_string()),
                        ip: None,
                        port: None,
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Wildcard domain".to_string()),
                    }],
                },
            ],
        };

        let whitelists = Whitelists::new_from_json(test_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_whitelist_inheritance() {
        initialize_test_whitelists().await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Test inherited endpoint from base_whitelist
        assert!(
            is_session_in_whitelist(
                Some("example.com"),
                None,
                443,
                "TCP",
                &custom_whitelists,
                "extended_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match inherited endpoint"
        );

        // Test endpoint from extended_whitelist
        assert!(
            is_session_in_whitelist(
                None,
                Some("192.168.1.100"),
                80,
                "TCP",
                &custom_whitelists,
                "extended_whitelist",
                Some(12345),
                Some("US"),
                Some("Test ISP"),
                Some("nginx")
            )
            .await,
            "Should match extended whitelist endpoint"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_wildcard_domain_matching() {
        // Initialize test data with various wildcard patterns
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "wildcard_domain_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: Some("*.example.com".to_string()),
                    ip: None,
                    port: None,
                    protocol: Some("TCP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("Prefix wildcard".to_string()),
                }],
            }],
        };

        let whitelists = Whitelists::new_from_json(test_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Test prefix wildcard (*.example.com)
        assert!(
            is_session_in_whitelist(
                Some("sub.example.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "wildcard_domain_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match sub.example.com with *.example.com"
        );

        // Test non-matching cases
        assert!(
            !is_session_in_whitelist(
                Some("example.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "wildcard_domain_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should not match example.com with *.example.com"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_as_number_matching() {
        initialize_test_whitelists().await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Test complete ASN match
        assert!(
            is_session_in_whitelist(
                None,
                Some("192.168.1.100"),
                80,
                "TCP",
                &custom_whitelists,
                "extended_whitelist",
                Some(12345),
                Some("US"),
                Some("Test ISP"),
                Some("nginx")
            )
            .await,
            "Should match with complete ASN info"
        );

        // Test partial ASN match (missing some fields)
        assert!(
            !is_session_in_whitelist(
                None,
                Some("192.168.1.100"),
                80,
                "TCP",
                &custom_whitelists,
                "extended_whitelist",
                Some(12345),
                Some("UK"), // Different country
                Some("Test ISP"),
                Some("nginx")
            )
            .await,
            "Should not match with different country"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_whitelist() {
        initialize_test_whitelists().await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Test non-existent whitelist
        assert!(
            !is_session_in_whitelist(
                Some("example.com"),
                None,
                443,
                "TCP",
                &custom_whitelists,
                "nonexistent_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should return false for non-existent whitelist"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_l7_process_matching() {
        initialize_test_whitelists().await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Test matching l7 process
        assert!(
            is_session_in_whitelist(
                None,
                Some("192.168.1.100"),
                80,
                "TCP",
                &custom_whitelists,
                "extended_whitelist",
                Some(12345),
                Some("US"),
                Some("Test ISP"),
                Some("nginx")
            )
            .await,
            "Should match with correct l7 process"
        );

        // Test non-matching l7 process
        assert!(
            !is_session_in_whitelist(
                None,
                Some("192.168.1.100"),
                80,
                "TCP",
                &custom_whitelists,
                "extended_whitelist",
                Some(12345),
                Some("US"),
                Some("Test ISP"),
                Some("apache")
            )
            .await,
            "Should not match with different l7 process"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_is_valid_whitelist() {
        // Then test the test whitelists
        initialize_test_whitelists().await;

        assert!(
            is_valid_whitelist("base_whitelist").await,
            "Should return true for existing whitelist"
        );
        assert!(
            !is_valid_whitelist("nonexistent_whitelist").await,
            "Should return false for non-existent whitelist"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_recursive_inheritance() {
        // Initialize whitelists with recursive inheritance
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-19".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![
                WhitelistInfo {
                    name: "whitelist_a".to_string(),
                    extends: Some(vec!["whitelist_b".to_string()]),
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("a.com".to_string()),
                        ip: None,
                        port: Some(80),
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Whitelist A".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "whitelist_b".to_string(),
                    extends: Some(vec!["whitelist_c".to_string()]),
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("b.com".to_string()),
                        ip: None,
                        port: Some(80),
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Whitelist B".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "whitelist_c".to_string(),
                    extends: Some(vec!["whitelist_a".to_string()]), // Creates a cycle
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("c.com".to_string()),
                        ip: None,
                        port: Some(80),
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Whitelist C".to_string()),
                    }],
                },
            ],
        };

        let whitelists = Whitelists::new_from_json(test_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Test that endpoints are correctly aggregated without infinite recursion
        assert!(
            is_session_in_whitelist(
                Some("a.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "whitelist_c",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match 'a.com' in 'whitelist_c' due to recursive inheritance"
        );

        assert!(
            is_session_in_whitelist(
                Some("b.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "whitelist_a",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match 'b.com' in 'whitelist_a' due to recursive inheritance"
        );

        assert!(
            is_session_in_whitelist(
                Some("c.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "whitelist_b",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match 'c.com' in 'whitelist_b' due to recursive inheritance"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_extended_wildcard_domain_matching() {
        // Initialize test data with wildcard domains
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "wildcard_domain_whitelist".to_string(),
                extends: None,
                endpoints: vec![
                    WhitelistEndpoint {
                        domain: Some("*.example.com".to_string()),
                        ip: None,
                        port: None,
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Wildcard domain".to_string()),
                    },
                    WhitelistEndpoint {
                        domain: Some("specific.domain.com".to_string()),
                        ip: None,
                        port: None,
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Specific domain".to_string()),
                    },
                ],
            }],
        };

        let whitelists = Whitelists::new_from_json(test_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Should match subdomains of example.com
        assert!(
            is_session_in_whitelist(
                Some("sub.example.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "wildcard_domain_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match sub.example.com"
        );

        // Should match multiple levels of subdomains
        assert!(
            is_session_in_whitelist(
                Some("deep.sub.example.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "wildcard_domain_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match deep.sub.example.com"
        );

        // Should not match the base domain without subdomain
        assert!(
            !is_session_in_whitelist(
                Some("example.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "wildcard_domain_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should not match example.com without subdomain"
        );

        // Should match the specific domain
        assert!(
            is_session_in_whitelist(
                Some("specific.domain.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "wildcard_domain_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match specific.domain.com"
        );

        // Should not match unrelated domains
        assert!(
            !is_session_in_whitelist(
                Some("otherdomain.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "wildcard_domain_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should not match otherdomain.com"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_ipv4_network_matching() {
        // Initialize test data with IPv4 network
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "ipv4_network_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: None,
                    ip: Some("192.168.1.0/24".to_string()),
                    port: None,
                    protocol: Some("TCP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("IPv4 network".to_string()),
                }],
            }],
        };

        let whitelists = Whitelists::new_from_json(test_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Should match IP within the network
        assert!(
            is_session_in_whitelist(
                None,
                Some("192.168.1.50"),
                80,
                "TCP",
                &custom_whitelists,
                "ipv4_network_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match IP within IPv4 network"
        );

        // Should not match IP outside the network
        assert!(
            !is_session_in_whitelist(
                None,
                Some("192.168.2.50"),
                80,
                "TCP",
                &custom_whitelists,
                "ipv4_network_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should not match IP outside IPv4 network"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_ipv6_network_matching() {
        // Initialize test data with IPv6 network
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "ipv6_network_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: None,
                    ip: Some("2001:db8::/32".to_string()),
                    port: None,
                    protocol: Some("TCP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("IPv6 network".to_string()),
                }],
            }],
        };

        let whitelists = Whitelists::new_from_json(test_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Should match IP within the network
        assert!(
            is_session_in_whitelist(
                None,
                Some("2001:db8::1"),
                80,
                "TCP",
                &custom_whitelists,
                "ipv6_network_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match IP within IPv6 network"
        );

        // Should not match IP outside the network
        assert!(
            !is_session_in_whitelist(
                None,
                Some("2001:db9::1"),
                80,
                "TCP",
                &custom_whitelists,
                "ipv6_network_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should not match IP outside IPv6 network"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_port_only_whitelist() {
        // Initialize test data with a port-only whitelist
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "port_only_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: None,
                    ip: None,
                    port: Some(8080),
                    protocol: None,
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("Port-only endpoint".to_string()),
                }],
            }],
        };

        // Overwrite the global LISTS with the test data
        let whitelists = Whitelists::new_from_json(test_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Test that a session with port 8080 matches the whitelist
        assert!(
            is_session_in_whitelist(
                None,                  // session_domain
                None,                  // session_ip
                8080,                  // port
                "TCP",                 // protocol
                &custom_whitelists,    // custom_whitelists
                "port_only_whitelist", // whitelist_name
                None,                  // as_number
                None,                  // as_country
                None,                  // as_owner
                None                   // process
            )
            .await,
            "Should match session with port 8080"
        );

        // Test that a session with a different port does not match
        assert!(
            !is_session_in_whitelist(
                None,                  // session_domain
                None,                  // session_ip
                80,                    // port
                "TCP",                 // protocol
                &custom_whitelists,    // custom_whitelists
                "port_only_whitelist", // whitelist_name
                None,                  // as_number
                None,                  // as_country
                None,                  // as_owner
                None                   // process
            )
            .await,
            "Should not match session with port 80"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_field_in_whitelist_entry() {
        // Initialize test data with an invalid field "domaine" instead of "domain"
        let invalid_whitelist_json = r#"
        {
            "date": "2024-10-25",
            "signature": "invalid_test_signature",
            "whitelists": [
                {
                    "name": "invalid_whitelist",
                    "extends": null,
                    "endpoints": [
                        {
                            "domaine": "invalid.com", // Invalid field
                            "ip": "10.0.0.1",
                            "port": 8080,
                            "protocol": "TCP",
                            "description": "Invalid endpoint"
                        }
                    ]
                }
            ]
        }
        "#;

        // Attempt to deserialize the invalid JSON
        let result: Result<WhitelistsJSON> =
            serde_json::from_str(invalid_whitelist_json).context("Deserialization failed");

        // Assert that deserialization fails due to unknown field
        assert!(
            result.is_err(),
            "Deserialization should fail due to unknown field 'domaine'"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_new_from_sessions() {
        use crate::lanscan_sessions::{
            Protocol, Session, SessionInfo, SessionStats, SessionStatus, WhitelistState,
        };
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Helper function to create a basic SessionInfo
        fn create_test_session(
            src_ip: IpAddr,
            src_port: u16,
            dst_ip: IpAddr,
            dst_port: u16,
            protocol: Protocol,
            dst_domain: Option<String>,
        ) -> SessionInfo {
            // Create minimal SessionStats
            let stats = SessionStats {
                start_time: Utc.timestamp_opt(1600000000, 0).unwrap(),
                end_time: None,
                last_activity: Utc.timestamp_opt(1600000100, 0).unwrap(),
                inbound_bytes: 0,
                outbound_bytes: 0,
                orig_pkts: 0,
                resp_pkts: 0,
                orig_ip_bytes: 0,
                resp_ip_bytes: 0,
                history: String::new(),
                conn_state: None,
                missed_bytes: 0,
                uid: "test-uid".to_string(),
            };

            // Create minimal SessionStatus
            let status = SessionStatus {
                active: true,
                added: true,
                activated: true,
                deactivated: false,
            };

            // Create Session
            let session = Session {
                protocol,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            };

            // Create SessionInfo
            SessionInfo {
                session,
                status,
                stats,
                is_local_src: true,
                is_local_dst: false,
                is_self_src: false,
                is_self_dst: false,
                src_domain: None,
                dst_domain,
                dst_service: None,
                l7: None,
                src_asn: None,
                dst_asn: None,
                is_whitelisted: WhitelistState::Unknown,
                criticality: "Low".to_string(),
            }
        }

        // Create test session data
        let test_sessions = vec![
            // Session 1 - with domain (HTTPS)
            create_test_session(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                54321,
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                443,
                Protocol::TCP,
                Some("example.com".to_string()),
            ),
            // Session 2 - without domain (DNS)
            create_test_session(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
                54322,
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                53,
                Protocol::UDP,
                None,
            ),
            // Session 3 - duplicate of Session 1 (should be deduplicated)
            create_test_session(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
                54325,
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                443,
                Protocol::TCP,
                Some("example.com".to_string()),
            ),
        ];

        // Create a whitelist from the sessions
        let whitelist = Whitelists::new_from_sessions(&test_sessions);

        // Verify the structure of the created whitelist
        assert_eq!(
            whitelist.whitelists.len(),
            1,
            "Should create exactly one whitelist"
        );
        assert!(
            whitelist.whitelists.contains_key("custom_whitelist"),
            "Should create a whitelist named 'custom_whitelist'"
        );

        // Get the whitelist entries
        let custom_whitelists = whitelist.whitelists.get("custom_whitelist").unwrap();

        // With our improved deduplication, we expect 2 endpoints
        // (Session 1 and 3 should be deduplicated even though they're not consecutive)
        assert_eq!(
            custom_whitelists.endpoints.len(),
            2,
            "Should have 2 endpoints after proper deduplication"
        );

        // Find and verify the example.com endpoint
        let example_endpoint = custom_whitelists
            .endpoints
            .iter()
            .find(|e| e.domain.as_deref() == Some("example.com"))
            .expect("Should contain an endpoint for example.com");

        assert_eq!(
            example_endpoint.ip.as_deref(),
            Some("93.184.216.34"),
            "Should have correct IP"
        );
        assert_eq!(example_endpoint.port, Some(443), "Should have correct port");
        assert_eq!(
            example_endpoint.protocol.as_deref(),
            Some("TCP"),
            "Should have correct protocol"
        );

        // Find and verify the DNS endpoint
        let dns_endpoint = custom_whitelists
            .endpoints
            .iter()
            .find(|e| e.ip.as_deref() == Some("8.8.8.8"))
            .expect("Should contain an endpoint for 8.8.8.8");

        assert_eq!(dns_endpoint.domain, None, "Should have no domain");
        assert_eq!(dns_endpoint.port, Some(53), "Should have correct port");
        assert_eq!(
            dns_endpoint.protocol.as_deref(),
            Some("UDP"),
            "Should have correct protocol"
        );

        // Verify today's date is used
        let today = chrono::Local::now().format("%B %dth %Y").to_string();
        assert_eq!(whitelist.date, today, "Date should be today's date");

        // Verify no signature is set
        assert_eq!(whitelist.signature, None, "Signature should be None");
    }

    #[tokio::test]
    #[serial]
    async fn test_new_from_sessions_empty() {
        use crate::lanscan_sessions::SessionInfo;

        // Test with an empty sessions list
        let empty_sessions: Vec<SessionInfo> = Vec::new();

        let whitelist = Whitelists::new_from_sessions(&empty_sessions);

        // Verify we still create a whitelist structure
        assert_eq!(
            whitelist.whitelists.len(),
            1,
            "Should create a whitelist even with empty sessions"
        );
        assert!(
            whitelist.whitelists.contains_key("custom_whitelist"),
            "Should create a whitelist named 'custom_whitelist'"
        );

        // Get the whitelist entries
        let custom_whitelists = whitelist.whitelists.get("custom_whitelist").unwrap();

        // Verify it has no endpoints
        assert_eq!(
            custom_whitelists.endpoints.len(),
            0,
            "Should have 0 endpoints with empty sessions list"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_new_from_sessions_with_process_info() {
        use crate::asn_db::Record;
        use crate::lanscan_sessions::{
            Protocol, Session, SessionInfo, SessionL7, SessionStats, SessionStatus, WhitelistState,
        };
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Helper function to create a session with process and ASN info
        fn create_session_with_process(
            dst_ip: IpAddr,
            dst_port: u16,
            protocol: Protocol,
            process_name: &str,
            as_number: u32,
            as_country: &str,
            as_owner: &str,
        ) -> SessionInfo {
            // Create Session
            let session = Session {
                protocol,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 49152,
                dst_ip,
                dst_port,
            };

            // Create process info
            let l7 = SessionL7 {
                pid: 1234,
                process_name: process_name.to_string(),
                process_path: format!("/usr/bin/{}", process_name),
                username: "testuser".to_string(),
            };

            // Create ASN info
            let dst_asn = Record {
                as_number,
                country: as_country.to_string(),
                owner: as_owner.to_string(),
            };

            // Create minimal SessionStats
            let stats = SessionStats {
                start_time: Utc.timestamp_opt(1600000000, 0).unwrap(),
                end_time: None,
                last_activity: Utc.timestamp_opt(1600000100, 0).unwrap(),
                inbound_bytes: 1024,
                outbound_bytes: 512,
                orig_pkts: 10,
                resp_pkts: 8,
                orig_ip_bytes: 1200,
                resp_ip_bytes: 800,
                history: "ShAdDf".to_string(),
                conn_state: Some("S1".to_string()),
                missed_bytes: 0,
                uid: format!("test-uid-{}", dst_port),
            };

            // Create minimal SessionStatus
            let status = SessionStatus {
                active: true,
                added: true,
                activated: true,
                deactivated: false,
            };

            SessionInfo {
                session,
                status,
                stats,
                is_local_src: true,
                is_local_dst: false,
                is_self_src: false,
                is_self_dst: false,
                src_domain: None,
                dst_domain: None,
                dst_service: None,
                l7: Some(l7),
                src_asn: None,
                dst_asn: Some(dst_asn),
                is_whitelisted: WhitelistState::Unknown,
                criticality: "Medium".to_string(),
            }
        }

        // Create test sessions with process and ASN info
        let test_sessions = vec![
            // Chrome connecting to a web server
            create_session_with_process(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                443,
                Protocol::TCP,
                "chrome",
                15169, // Google ASN
                "US",
                "GOOGLE",
            ),
            // Firefox connecting to a different web server
            create_session_with_process(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
                443,
                Protocol::TCP,
                "firefox",
                16509, // Amazon ASN
                "US",
                "AMAZON-02",
            ),
            // Another Chrome session connecting to the same endpoint as first session (should be deduplicated)
            create_session_with_process(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                443,
                Protocol::TCP,
                "chrome", // Same process
                15169,    // Same ASN
                "US",
                "GOOGLE",
            ),
            // Chrome connecting to another endpoint (different destination, should NOT be deduplicated)
            create_session_with_process(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)),
                443,
                Protocol::TCP,
                "chrome",
                15169, // Google ASN
                "US",
                "GOOGLE",
            ),
        ];

        // Create whitelist from sessions
        let whitelist = Whitelists::new_from_sessions(&test_sessions);

        // Verify the whitelist structure
        assert_eq!(
            whitelist.whitelists.len(),
            1,
            "Should create exactly one whitelist"
        );
        let custom_whitelists = whitelist.whitelists.get("custom_whitelist").unwrap();

        // Should have 3 unique endpoints (with proper deduplication of same destination)
        assert_eq!(
            custom_whitelists.endpoints.len(),
            3,
            "Should have 3 endpoints after deduplication"
        );

        // Verify which IPs are present after deduplication
        let ips: Vec<_> = custom_whitelists
            .endpoints
            .iter()
            .filter_map(|e| e.ip.as_deref())
            .collect();

        // Should include 203.0.113.10 (only once despite appearing twice in input),
        // 198.51.100.20, and 203.0.113.20
        assert!(
            ips.contains(&"203.0.113.10"),
            "Should contain first Google endpoint IP"
        );
        assert!(
            ips.contains(&"198.51.100.20"),
            "Should contain Amazon endpoint IP"
        );
        assert!(
            ips.contains(&"203.0.113.20"),
            "Should contain second Google endpoint IP"
        );

        // Find and verify each endpoint
        let google_endpoint = custom_whitelists
            .endpoints
            .iter()
            .find(|e| e.ip.as_deref() == Some("203.0.113.10"))
            .expect("Should have endpoint for 203.0.113.10");

        let amazon_endpoint = custom_whitelists
            .endpoints
            .iter()
            .find(|e| e.ip.as_deref() == Some("198.51.100.20"))
            .expect("Should have endpoint for 198.51.100.20");

        // Verify the process information IS preserved in the whitelist
        // (new_from_sessions includes process info in created whitelists)
        assert_eq!(
            google_endpoint.process.as_deref(),
            Some("chrome"),
            "Process info should be preserved in the whitelist"
        );
        assert_eq!(
            amazon_endpoint.process.as_deref(),
            Some("firefox"),
            "Process info should be preserved in the whitelist"
        );

        // Verify IP, port and protocol are correctly preserved
        assert_eq!(google_endpoint.port, Some(443), "Should have correct port");
        assert_eq!(
            google_endpoint.protocol.as_deref(),
            Some("TCP"),
            "Should have correct protocol"
        );

        assert_eq!(amazon_endpoint.port, Some(443), "Should have correct port");
        assert_eq!(
            amazon_endpoint.protocol.as_deref(),
            Some("TCP"),
            "Should have correct protocol"
        );

        // Verify ASN information is NOT preserved
        assert_eq!(
            google_endpoint.as_number, None,
            "ASN info should not be preserved"
        );
        assert_eq!(
            google_endpoint.as_country, None,
            "Country info should not be preserved"
        );
        assert_eq!(
            google_endpoint.as_owner, None,
            "Owner info should not be preserved"
        );

        // Verify that all endpoints have descriptions containing session info
        assert!(
            google_endpoint
                .description
                .as_ref()
                .unwrap()
                .contains("Auto-generated from session"),
            "Description should indicate auto-generated source"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_as_number_deserialization_and_matching() {
        // Initialize test data with an endpoint specifying ASN
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-24".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "as_number_test_whitelist".to_string(),
                extends: None,
                endpoints: vec![
                    WhitelistEndpoint {
                        domain: None,
                        ip: None,
                        port: Some(443),
                        protocol: Some("TCP".to_string()),
                        as_number: Some(16509), // Amazon ASN
                        as_country: Some("US".to_string()),
                        as_owner: Some("AMAZON-02".to_string()),
                        process: None,
                        description: Some("Amazon HTTPS".to_string()),
                    },
                    WhitelistEndpoint {
                        domain: None,
                        ip: Some("1.1.1.1".to_string()),
                        port: Some(443),
                        protocol: Some("TCP".to_string()),
                        as_number: Some(13335), // Cloudflare ASN
                        as_country: Some("US".to_string()),
                        as_owner: Some("CLOUDFLARENET".to_string()),
                        process: None,
                        description: Some("Cloudflare HTTPS".to_string()),
                    },
                ],
            }],
        };

        // Overwrite the global LISTS with the test data
        let whitelists = Whitelists::new_from_json(test_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Session that should match (Amazon ASN)
        assert!(
            is_session_in_whitelist(
                None,                       // session_domain
                Some("54.239.28.85"),       // Amazon IP
                443,                        // port
                "TCP",                      // protocol
                &custom_whitelists,         // custom_whitelists
                "as_number_test_whitelist", // whitelist_name
                Some(16509),                // as_number
                Some("US"),                 // as_country
                Some("AMAZON-02"),          // as_owner
                None                        // process
            )
            .await,
            "Should match session with ASN 16509 (Amazon)"
        );

        // Session that should not match (Different ASN)
        assert!(
            !is_session_in_whitelist(
                None,                       // session_domain
                Some("8.8.8.8"),            // Google IP
                443,                        // port
                "TCP",                      // protocol
                &custom_whitelists,         // custom_whitelists
                "as_number_test_whitelist", // whitelist_name
                Some(15169),                // as_number (Google ASN)
                Some("US"),                 // as_country
                Some("GOOGLE"),             // as_owner
                None                        // process
            )
            .await,
            "Should not match session with ASN 15169 (Google)"
        );

        // Session that should match (Cloudflare ASN)
        assert!(
            is_session_in_whitelist(
                None,                       // session_domain
                Some("1.1.1.1"),            // Cloudflare IP
                443,                        // port
                "TCP",                      // protocol
                &custom_whitelists,         // custom_whitelists
                "as_number_test_whitelist", // whitelist_name
                Some(13335),                // as_number
                Some("US"),                 // as_country
                Some("CLOUDFLARENET"),      // as_owner
                None                        // process
            )
            .await,
            "Should match session with ASN 13335 (Cloudflare)"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_multi_component_wildcard_matching() {
        // Initialize test data with wildcard patterns
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![
                WhitelistInfo {
                    name: "prefix_wildcard_whitelist".to_string(),
                    extends: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("*.example.com".to_string()),
                        ip: None,
                        port: None,
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Prefix wildcard".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "middle_wildcard_whitelist".to_string(),
                    extends: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("example.*.com".to_string()),
                        ip: None,
                        port: None,
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Middle wildcard".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "suffix_wildcard_whitelist".to_string(),
                    extends: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("example.*".to_string()),
                        ip: None,
                        port: None,
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Suffix wildcard".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "noncentral_wildcard_whitelist".to_string(),
                    extends: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("toto.too.toto.*.toto".to_string()),
                        ip: None,
                        port: None,
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Non-central wildcard position".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "complex_wildcard_whitelist".to_string(),
                    extends: None,
                    endpoints: vec![
                        WhitelistEndpoint {
                            domain: Some("cloud-mirror-lb.*.azure.com".to_string()),
                            ip: None,
                            port: None,
                            protocol: Some("TCP".to_string()),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            process: None,
                            description: Some("Azure wildcard".to_string()),
                        },
                        WhitelistEndpoint {
                            domain: Some("*.toto".to_string()),
                            ip: None,
                            port: None,
                            protocol: Some("TCP".to_string()),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            process: None,
                            description: Some("Prefix wildcard with short TLD".to_string()),
                        },
                    ],
                },
            ],
        };

        let whitelists = Whitelists::new_from_json(test_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));

        // Test prefix wildcard (*.example.com)
        // Single subdomain
        assert!(
            is_session_in_whitelist(
                Some("sub.example.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "prefix_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match sub.example.com with *.example.com"
        );

        // Multiple subdomains
        assert!(
            is_session_in_whitelist(
                Some("a.b.c.example.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "prefix_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match a.b.c.example.com with *.example.com"
        );

        // Base domain should NOT match prefix wildcard
        assert!(
            !is_session_in_whitelist(
                Some("example.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "prefix_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should NOT match example.com with *.example.com"
        );

        // Test middle wildcard (example.*.com)
        // Single component in middle
        assert!(
            is_session_in_whitelist(
                Some("example.test.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "middle_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match example.test.com with example.*.com"
        );

        // Multiple components in middle
        assert!(
            is_session_in_whitelist(
                Some("example.one.two.three.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "middle_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match example.one.two.three.com with example.*.com"
        );

        // Test suffix wildcard (example.*)
        // Simple TLD
        assert!(
            is_session_in_whitelist(
                Some("example.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "suffix_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match example.com with example.*"
        );

        // Complex TLD
        assert!(
            is_session_in_whitelist(
                Some("example.co.uk"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "suffix_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match example.co.uk with example.*"
        );

        // Test complex wildcard patterns
        assert!(
            is_session_in_whitelist(
                Some("cloud-mirror-lb.eastus.westus.northeurope.southeurope.cloudapp.azure.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "complex_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match complex domain with multiple middle components"
        );

        // Test specific case for *.toto matching cloud-mirror-lb.cloudapp.azure.com.toto
        assert!(
            is_session_in_whitelist(
                Some("cloud-mirror-lb.cloudapp.azure.com.toto"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "complex_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match cloud-mirror-lb.cloudapp.azure.com.toto with *.toto"
        );

        // Test complex non-central wildcard pattern (toto.too.toto.*.toto)
        assert!(
            is_session_in_whitelist(
                Some("toto.too.toto.middle.toto"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "noncentral_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match toto.too.toto.middle.toto with toto.too.toto.*.toto"
        );

        // Test complex non-central wildcard with multiple components in wildcard position
        assert!(
            is_session_in_whitelist(
                Some("toto.too.toto.one.two.three.toto"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "noncentral_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match toto.too.toto.one.two.three.toto with toto.too.toto.*.toto"
        );

        // Test non-matching case for non-central wildcard
        assert!(
            !is_session_in_whitelist(
                Some("toto.too.different.middle.toto"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "noncentral_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should not match toto.too.different.middle.toto with toto.too.toto.*.toto"
        );

        // General negative tests (should not match any of our whitelists)
        assert!(
            !is_session_in_whitelist(
                Some("different.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "prefix_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should not match different.com with *.example.com"
        );

        // Make sure unrelated domain with similar prefix doesn't match
        assert!(
            !is_session_in_whitelist(
                Some("examplesite.com"),
                None,
                80,
                "TCP",
                &custom_whitelists,
                "suffix_wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should not match examplesite.com with example.*"
        );
    }
}
