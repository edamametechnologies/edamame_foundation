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
/// Returns a tuple (bool, Option<String>) where:
/// - The boolean indicates whether the session is in the whitelist
/// - If false, the Option<String> contains a reason why the session didn't match
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
) -> (bool, Option<String>) {
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
                let error_msg =
                    format!("Error retrieving endpoints from custom whitelist: {}", err);
                warn!("{}", error_msg);
                return (false, Some(error_msg));
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
                let error_msg =
                    format!("Error retrieving endpoints from global whitelist: {}", err);
                warn!("{}", error_msg);
                return (false, Some(error_msg));
            }
        }
    };

    if endpoints.is_empty() {
        return (
            false,
            Some(format!(
                "Whitelist '{}' contains no endpoints",
                whitelist_name
            )),
        );
    }

    // Match the session against the endpoints
    for endpoint in &endpoints {
        let (matches, _reason) = endpoint_matches_with_reason(
            session_domain,
            session_ip,
            port,
            protocol,
            as_number,
            as_country,
            as_owner,
            process,
            endpoint,
        );

        if matches {
            trace!("Matched whitelist endpoint: {:?}", endpoint);
            return (true, None);
        }
    }

    // If we got here, no endpoint matched
    let reason = format!(
        "No matching endpoint found in whitelist '{}' for domain: {:?}, ip: {:?}, port: {}, protocol: {}, ASN: {:?}, Country: {:?}, Owner: {:?}, Process: {:?}",
        whitelist_name, session_domain, session_ip, port, protocol, as_number, as_country, as_owner, process
    );

    (false, Some(reason))
}

/// Helper function to match the session against a whitelist endpoint with reason.
fn endpoint_matches_with_reason(
    session_domain: Option<&str>,
    session_ip: Option<&str>,
    port: u16,
    protocol: &str,
    as_number: Option<u32>,
    as_country: Option<&str>,
    as_owner: Option<&str>,
    process: Option<&str>,
    endpoint: &WhitelistEndpoint,
) -> (bool, Option<String>) {
    // Process name, protocol and port are fundamental for service identification - they must match
    let protocol_match = protocol_matches(protocol, &endpoint.protocol);
    let port_match = port_matches(port, endpoint.port);
    let process_match = process_matches(process, &endpoint.process);

    if !protocol_match || !port_match || !process_match {
        // If protocol or port don't match, there's no need to proceed further
        let mut reasons = Vec::new();
        if !protocol_match {
            reasons.push(format!(
                "Protocol mismatch: {} not matching {:?}",
                protocol, endpoint.protocol
            ));
        }
        if !port_match {
            reasons.push(format!(
                "Port mismatch: {} not matching {:?}",
                port, endpoint.port
            ));
        }
        if !process_match {
            reasons.push(format!(
                "Process mismatch: {:?} not matching {:?}",
                process, endpoint.process
            ));
        }
        return (false, Some(reasons.join(", ")));
    }

    // Check if we have a domain match
    let domain_match = domain_matches(session_domain, &endpoint.domain);
    let domain_specified = endpoint.domain.is_some();

    // If domain is specified and matches, other checks are irrelevant
    if domain_specified && domain_match {
        return (true, None);
    }

    // Check if we have an IP match
    let ip_match = ip_matches(session_ip, &endpoint.ip);
    let ip_specified = endpoint.ip.is_some();

    // If IP is specified and matches, return true
    if ip_specified && ip_match {
        return (true, None);
    }

    // Track whether we need to check the domain or IP
    let entity_matched = (domain_specified && domain_match) || (ip_specified && ip_match);
    let needs_entity_match = domain_specified || ip_specified;

    // If entity matching is required but failed, we don't match
    if needs_entity_match && !entity_matched {
        let mut reasons = Vec::new();
        if domain_specified {
            reasons.push(format!(
                "Domain mismatch: {:?} not matching {:?}",
                session_domain, endpoint.domain
            ));
        }
        if ip_specified {
            reasons.push(format!(
                "IP mismatch: {:?} not matching {:?}",
                session_ip, endpoint.ip
            ));
        }
        return (false, Some(reasons.join(", ")));
    }

    // AS checks are only relevant if no domain/IP were specified or if they weren't provided in the session
    let should_check_as = (!domain_specified && !ip_specified)
        || (endpoint.as_number.is_some()
            || endpoint.as_owner.is_some()
            || endpoint.as_country.is_some());

    if should_check_as {
        // Check AS number if specified (most specific identifier)
        if let Some(whitelist_asn) = endpoint.as_number {
            match as_number {
                Some(session_asn) if session_asn == whitelist_asn => {
                    // ASN matches, continue to next checks
                }
                _ => {
                    return (
                        false,
                        Some(format!(
                            "AS number mismatch: {:?} not matching {:?}",
                            as_number, endpoint.as_number
                        )),
                    );
                }
            }
        }

        // Check AS owner if specified
        if let Some(ref whitelist_owner) = endpoint.as_owner {
            match as_owner {
                Some(session_owner) if session_owner.eq_ignore_ascii_case(whitelist_owner) => {
                    // Owner matches, continue
                }
                _ => {
                    return (
                        false,
                        Some(format!(
                            "Owner mismatch: {:?} not matching {:?}",
                            as_owner, endpoint.as_owner
                        )),
                    );
                }
            }
        }

        // Check AS country if specified
        if let Some(ref whitelist_country) = endpoint.as_country {
            match as_country {
                Some(session_country)
                    if session_country.eq_ignore_ascii_case(whitelist_country) =>
                {
                    // Country matches, continue
                }
                _ => {
                    return (
                        false,
                        Some(format!(
                            "Country mismatch: {:?} not matching {:?}",
                            as_country, endpoint.as_country
                        )),
                    );
                }
            }
        }
    }

    // All required checks passed
    (true, None)
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

                        // For a valid subdomain match:
                        // 1. Domain must end with the suffix
                        // 2. The character before the suffix must be a dot (.)
                        return domain.ends_with(suffix)
                            && domain.len() > suffix.len()
                            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.';
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
                                // Domain has the prefix followed by a dot and any TLD, which is valid
                                // For suffix wildcards (example.*), we want to match any TLD
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
            .await
            .0,
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
            .await
            .0,
            "Should match extended whitelist endpoint"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_wildcard_domain_patterns() {
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "wildcard_patterns".to_string(),
                extends: None,
                endpoints: vec![
                    WhitelistEndpoint {
                        domain: Some("*.example.com".to_string()),
                        ip: None,
                        port: Some(443),
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Prefix wildcard".to_string()),
                    },
                    WhitelistEndpoint {
                        domain: Some("example.*".to_string()),
                        ip: None,
                        port: Some(443),
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Suffix wildcard".to_string()),
                    },
                    WhitelistEndpoint {
                        domain: Some("api.*.example.com".to_string()),
                        ip: None,
                        port: Some(443),
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("Middle wildcard".to_string()),
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

        // Test prefix wildcard (*.example.com)
        assert!(
            is_session_in_whitelist(
                Some("sub.example.com"),
                None,
                443,
                "TCP",
                &custom_whitelists,
                "wildcard_patterns",
                None,
                None,
                None,
                None
            )
            .await
            .0,
            "Should match subdomain with prefix wildcard"
        );

        // Test suffix wildcard (example.*)
        assert!(
            is_session_in_whitelist(
                Some("example.net"),
                None,
                443,
                "TCP",
                &custom_whitelists,
                "wildcard_patterns",
                None,
                None,
                None,
                None
            )
            .await
            .0,
            "Should match TLD with suffix wildcard"
        );

        // Test middle wildcard (api.*.example.com)
        assert!(
            is_session_in_whitelist(
                Some("api.prod.example.com"),
                None,
                443,
                "TCP",
                &custom_whitelists,
                "wildcard_patterns",
                None,
                None,
                None,
                None
            )
            .await
            .0,
            "Should match domain with middle wildcard"
        );

        // Test invalid matches
        // Create a new whitelist specifically for testing the prefix wildcard
        let test_prefix_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "prefix_only_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: Some("*.example.com".to_string()),
                    ip: None,
                    port: Some(443),
                    protocol: Some("TCP".to_string()),
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    process: None,
                    description: Some("Only prefix wildcard".to_string()),
                }],
            }],
        };

        let prefix_whitelists = Whitelists::new_from_json(test_prefix_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(prefix_whitelists)
            .await;

        assert!(
            !is_session_in_whitelist(
                Some("example.com"),
                None,
                443,
                "TCP",
                &custom_whitelists,
                "prefix_only_whitelist",
                None,
                None,
                None,
                None
            )
            .await
            .0,
            "Should not match base domain with prefix wildcard"
        );

        assert!(
            !is_session_in_whitelist(
                Some("api.example"),
                None,
                443,
                "TCP",
                &custom_whitelists,
                "wildcard_patterns",
                None,
                None,
                None,
                None
            )
            .await
            .0,
            "Should not match incomplete domain with suffix wildcard"
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
            .await
            .0,
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
            .await
            .0,
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
            .await
            .0,
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
            .await
            .0,
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
            .await
            .0,
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
            .await
            .0,
            "Should match 'c.com' in 'whitelist_b' due to recursive inheritance"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_domain_priority_matching() {
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "priority_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: Some("example.com".to_string()),
                    ip: Some("192.168.1.1".to_string()), // Different IP
                    port: Some(443),
                    protocol: Some("TCP".to_string()),
                    as_number: Some(12345), // Different AS info
                    as_country: Some("US".to_string()),
                    as_owner: Some("Test ISP".to_string()),
                    process: None,
                    description: Some("Domain priority test".to_string()),
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

        // Should match based on domain even with mismatched IP and AS info
        assert!(
            is_session_in_whitelist(
                Some("example.com"),
                Some("10.0.0.1"), // Different IP
                443,
                "TCP",
                &custom_whitelists,
                "priority_whitelist",
                Some(54321),       // Different AS number
                Some("UK"),        // Different country
                Some("Other ISP"), // Different owner
                None
            )
            .await
            .0,
            "Should match based on domain regardless of IP and AS info"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_ip_priority_over_as() {
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "ip_priority_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: None,
                    ip: Some("192.168.1.0/24".to_string()),
                    port: Some(443),
                    protocol: Some("TCP".to_string()),
                    as_number: Some(12345), // Different AS info
                    as_country: Some("US".to_string()),
                    as_owner: Some("Test ISP".to_string()),
                    process: None,
                    description: Some("IP priority test".to_string()),
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

        // Should match based on IP even with mismatched AS info
        assert!(
            is_session_in_whitelist(
                None,
                Some("192.168.1.100"),
                443,
                "TCP",
                &custom_whitelists,
                "ip_priority_whitelist",
                Some(54321),       // Different AS number
                Some("UK"),        // Different country
                Some("Other ISP"), // Different owner
                None
            )
            .await
            .0,
            "Should match based on IP regardless of AS info"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_as_only_matching() {
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "as_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: None,
                    ip: None,
                    port: Some(443),
                    protocol: Some("TCP".to_string()),
                    as_number: Some(12345),
                    as_country: Some("US".to_string()),
                    as_owner: Some("Test ISP".to_string()),
                    process: None,
                    description: Some("AS-only test".to_string()),
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

        // Should match when only AS info matches
        assert!(
            is_session_in_whitelist(
                None,
                Some("10.0.0.1"),
                443,
                "TCP",
                &custom_whitelists,
                "as_whitelist",
                Some(12345),
                Some("US"),
                Some("Test ISP"),
                None
            )
            .await
            .0,
            "Should match based on AS info when no domain/IP specified"
        );

        // Should not match with mismatched AS info
        assert!(
            !is_session_in_whitelist(
                None,
                Some("10.0.0.1"),
                443,
                "TCP",
                &custom_whitelists,
                "as_whitelist",
                Some(54321),
                Some("UK"),
                Some("Other ISP"),
                None
            )
            .await
            .0,
            "Should not match with mismatched AS info"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_mixed_criteria_matching() {
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "mixed_whitelist".to_string(),
                extends: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: Some("example.com".to_string()),
                    ip: Some("192.168.1.0/24".to_string()),
                    port: Some(443),
                    protocol: Some("TCP".to_string()),
                    as_number: Some(12345),
                    as_country: Some("US".to_string()),
                    as_owner: Some("Test ISP".to_string()),
                    process: Some("test-process".to_string()),
                    description: Some("Mixed criteria test".to_string()),
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

        // Should match on domain regardless of other criteria
        assert!(
            is_session_in_whitelist(
                Some("example.com"),
                Some("10.0.0.1"), // Different IP
                443,
                "TCP",
                &custom_whitelists,
                "mixed_whitelist",
                Some(54321), // Different AS
                Some("UK"),
                Some("Other ISP"),
                Some("test-process")
            )
            .await
            .0,
            "Should match on domain despite mismatched IP and AS"
        );

        // Should match on IP when domain doesn't match
        assert!(
            is_session_in_whitelist(
                Some("other.com"),
                Some("192.168.1.100"),
                443,
                "TCP",
                &custom_whitelists,
                "mixed_whitelist",
                Some(54321), // Different AS
                Some("UK"),
                Some("Other ISP"),
                Some("test-process")
            )
            .await
            .0,
            "Should match on IP when domain doesn't match"
        );

        // Should not match when required process doesn't match
        assert!(
            !is_session_in_whitelist(
                Some("example.com"),
                Some("192.168.1.100"),
                443,
                "TCP",
                &custom_whitelists,
                "mixed_whitelist",
                Some(12345),
                Some("US"),
                Some("Test ISP"),
                Some("different-process")
            )
            .await
            .0,
            "Should not match when process doesn't match"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_ip_cidr_matching() {
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "ip_cidr_whitelist".to_string(),
                extends: None,
                endpoints: vec![
                    WhitelistEndpoint {
                        domain: None,
                        ip: Some("192.168.1.0/24".to_string()),
                        port: Some(443),
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("IPv4 CIDR test".to_string()),
                    },
                    WhitelistEndpoint {
                        domain: None,
                        ip: Some("2001:db8::/32".to_string()),
                        port: Some(443),
                        protocol: Some("TCP".to_string()),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        process: None,
                        description: Some("IPv6 CIDR test".to_string()),
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

        // Test IPv4 CIDR matching
        assert!(
            is_session_in_whitelist(
                None,
                Some("192.168.1.100"),
                443,
                "TCP",
                &custom_whitelists,
                "ip_cidr_whitelist",
                None,
                None,
                None,
                None
            )
            .await
            .0,
            "Should match IPv4 in CIDR range"
        );

        // Test IPv6 CIDR matching
        assert!(
            is_session_in_whitelist(
                None,
                Some("2001:db8:1234::1"),
                443,
                "TCP",
                &custom_whitelists,
                "ip_cidr_whitelist",
                None,
                None,
                None,
                None
            )
            .await
            .0,
            "Should match IPv6 in CIDR range"
        );

        // Test IP outside CIDR range
        assert!(
            !is_session_in_whitelist(
                None,
                Some("192.168.2.1"),
                443,
                "TCP",
                &custom_whitelists,
                "ip_cidr_whitelist",
                None,
                None,
                None,
                None
            )
            .await
            .0,
            "Should not match IP outside CIDR range"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_protocol_case_sensitivity() {
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "protocol_whitelist".to_string(),
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
                    description: Some("Protocol case test".to_string()),
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

        // Test case-insensitive protocol matching
        assert!(
            is_session_in_whitelist(
                Some("example.com"),
                None,
                443,
                "tcp",
                &custom_whitelists,
                "protocol_whitelist",
                None,
                None,
                None,
                None
            )
            .await
            .0,
            "Should match lowercase protocol"
        );

        assert!(
            is_session_in_whitelist(
                Some("example.com"),
                None,
                443,
                "TcP",
                &custom_whitelists,
                "protocol_whitelist",
                None,
                None,
                None,
                None
            )
            .await
            .0,
            "Should match mixed-case protocol"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_empty_whitelist() {
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-20".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![WhitelistInfo {
                name: "empty_whitelist".to_string(),
                extends: None,
                endpoints: vec![],
            }],
        };

        let whitelists = Whitelists::new_from_json(test_whitelist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;

        let custom_whitelists = Arc::new(CustomRwLock::new(None));
        // Test empty whitelist behavior
        let (matches, reason) = is_session_in_whitelist(
            Some("example.com"),
            None,
            443,
            "TCP",
            &custom_whitelists,
            "empty_whitelist",
            None,
            None,
            None,
            None,
        )
        .await;

        assert!(!matches, "Empty whitelist should not match any session");
        assert!(
            reason.is_some() && reason.unwrap().contains("contains no endpoints"),
            "Should return appropriate error message for empty whitelist"
        );
    }
}
