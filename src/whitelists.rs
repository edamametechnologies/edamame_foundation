use crate::cloud_model::*;
use crate::rwlock::CustomRwLock;
use crate::whitelists_db::WHITELISTS;
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use ipnet::IpNet;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::{info, trace, warn};

// Constants
const WHITELISTS_FILE_NAME: &str = "whitelists-db.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhitelistEndpoint {
    pub domain: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub as_number: Option<u32>,
    pub as_country: Option<String>,
    pub as_owner: Option<String>,
    pub l7_process_name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhitelistInfo {
    pub name: String,
    #[serde(rename = "extends")]
    pub inherits: Option<Vec<String>>,
    pub endpoints: Vec<WhitelistEndpoint>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
        let inherits = info.inherits.clone();

        // Drop the Ref to release the lock on the DashMap
        drop(info);

        // Initialize the list of all endpoints with the current ones
        let mut all_endpoints = endpoints;

        if let Some(inherits) = inherits {
            for parent in inherits {
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
    whitelist_name: &str,
    as_number: Option<u32>,
    as_country: Option<&str>,
    as_owner: Option<&str>,
    l7_process_name: Option<&str>,
) -> bool {
    trace!(
        "Checking if domain: {:?}, ip: {:?}, port: {} is in whitelist {} with ASN {:?}, Country {:?}, Owner {:?}, L7 Process {:?}",
        session_domain,
        session_ip,
        port,
        whitelist_name,
        as_number,
        as_country,
        as_owner,
        l7_process_name
    );
    let mut visited = HashSet::new();
    visited.insert(whitelist_name.to_string());

    // Acquire lock on LISTS
    let model = LISTS.read().await;
    let lists = &model.data;

    let endpoints = match lists
        .read()
        .await
        .get_all_endpoints(whitelist_name, &mut visited)
    {
        Ok(endpoints) => endpoints,
        Err(err) => {
            warn!("Error retrieving endpoints: {}", err);
            // Whitelist not found, return false to deny by default
            return false;
        }
    };

    endpoints.iter().any(|endpoint| {
        endpoint_matches(
            session_domain,
            session_ip,
            port,
            as_number,
            as_country,
            as_owner,
            l7_process_name,
            endpoint,
        )
    })
}

/// Helper function to match the session against a whitelist endpoint.
fn endpoint_matches(
    session_domain: Option<&str>,
    session_ip: Option<&str>,
    port: u16,
    as_number: Option<u32>,
    as_country: Option<&str>,
    as_owner: Option<&str>,
    l7_process_name: Option<&str>,
    endpoint: &WhitelistEndpoint,
) -> bool {
    let domain_match = domain_matches(session_domain, &endpoint.domain);
    let ip_match = ip_matches(session_ip, &endpoint.ip);
    let port_match = port_matches(port, endpoint.port);
    let asn_match = as_number_matches(as_number, endpoint.as_number);
    let country_match = as_country_matches(as_country, &endpoint.as_country);
    let owner_match = as_owner_matches(as_owner, &endpoint.as_owner);
    let l7_match = l7_process_name_matches(l7_process_name, &endpoint.l7_process_name);

    if domain_match
        && ip_match
        && port_match
        && asn_match
        && country_match
        && owner_match
        && l7_match
    {
        trace!("Matched whitelist endpoint: {:?}", endpoint);
        true
    } else {
        trace!(
            "Did not match whitelist endpoint: {:?}, Reasons: domain_match={}, ip_match={}, port_match={}, asn_match={}, country_match={}, owner_match={}, l7_match={}",
            endpoint,
            domain_match,
            ip_match,
            port_match,
            asn_match,
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
                let domain = domain.to_lowercase();
                if pattern.starts_with("*.") {
                    let suffix = pattern[2..].to_lowercase();
                    domain.ends_with(&format!(".{}", suffix))
                } else {
                    domain.eq_ignore_ascii_case(&pattern.to_lowercase())
                }
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
        Some(w_asn) => session_as_number == Some(w_asn),
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

fn l7_process_name_matches(session_l7: Option<&str>, whitelist_l7: &Option<String>) -> bool {
    match whitelist_l7 {
        Some(w_l7) => match session_l7 {
            Some(s_l7) => s_l7.eq_ignore_ascii_case(w_l7),
            None => false,
        },
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
                    inherits: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("example.com".to_string()),
                        ip: None,
                        port: Some(443),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        l7_process_name: None,
                        description: Some("HTTPS endpoint".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "extended_whitelist".to_string(),
                    inherits: Some(vec!["base_whitelist".to_string()]),
                    endpoints: vec![WhitelistEndpoint {
                        domain: None,
                        ip: Some("192.168.1.0/24".to_string()),
                        port: Some(80),
                        as_number: Some(12345),
                        as_country: Some("US".to_string()),
                        as_owner: Some("Test ISP".to_string()),
                        l7_process_name: Some("nginx".to_string()),
                        description: Some("Internal web server".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "wildcard_whitelist".to_string(),
                    inherits: None,
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("*.example.com".to_string()),
                        ip: None,
                        port: None,
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        l7_process_name: None,
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

        // Test inherited endpoint from base_whitelist
        assert!(
            is_session_in_whitelist(
                Some("example.com"),
                None,
                443,
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
        initialize_test_whitelists().await;

        // Test exact subdomain match
        assert!(
            is_session_in_whitelist(
                Some("sub.example.com"),
                None,
                80,
                "wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match wildcard subdomain"
        );

        // Test multiple level subdomain match
        assert!(
            is_session_in_whitelist(
                Some("sub.sub2.example.com"),
                None,
                80,
                "wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should match multiple level subdomain"
        );

        // Test non-matching domain
        assert!(
            !is_session_in_whitelist(
                Some("example.org"),
                None,
                80,
                "wildcard_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Should not match different domain"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_asn_matching() {
        initialize_test_whitelists().await;

        // Test complete ASN match
        assert!(
            is_session_in_whitelist(
                None,
                Some("192.168.1.100"),
                80,
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

        // Test non-existent whitelist
        assert!(
            !is_session_in_whitelist(
                Some("example.com"),
                None,
                443,
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

        // Test matching l7 process
        assert!(
            is_session_in_whitelist(
                None,
                Some("192.168.1.100"),
                80,
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
                    inherits: Some(vec!["whitelist_b".to_string()]),
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("a.com".to_string()),
                        ip: None,
                        port: Some(80),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        l7_process_name: None,
                        description: Some("Whitelist A".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "whitelist_b".to_string(),
                    inherits: Some(vec!["whitelist_c".to_string()]),
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("b.com".to_string()),
                        ip: None,
                        port: Some(80),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        l7_process_name: None,
                        description: Some("Whitelist B".to_string()),
                    }],
                },
                WhitelistInfo {
                    name: "whitelist_c".to_string(),
                    inherits: Some(vec!["whitelist_a".to_string()]), // Creates a cycle
                    endpoints: vec![WhitelistEndpoint {
                        domain: Some("c.com".to_string()),
                        ip: None,
                        port: Some(80),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        l7_process_name: None,
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

        // Test that endpoints are correctly aggregated without infinite recursion
        assert!(
            is_session_in_whitelist(
                Some("a.com"),
                None,
                80,
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
                inherits: None,
                endpoints: vec![
                    WhitelistEndpoint {
                        domain: Some("*.example.com".to_string()),
                        ip: None,
                        port: None,
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        l7_process_name: None,
                        description: Some("Wildcard domain".to_string()),
                    },
                    WhitelistEndpoint {
                        domain: Some("specific.domain.com".to_string()),
                        ip: None,
                        port: None,
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        l7_process_name: None,
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

        // Should match subdomains of example.com
        assert!(
            is_session_in_whitelist(
                Some("sub.example.com"),
                None,
                80,
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
                inherits: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: None,
                    ip: Some("192.168.1.0/24".to_string()),
                    port: None,
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    l7_process_name: None,
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

        // Should match IP within the network
        assert!(
            is_session_in_whitelist(
                None,
                Some("192.168.1.50"),
                80,
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
                inherits: None,
                endpoints: vec![WhitelistEndpoint {
                    domain: None,
                    ip: Some("2001:db8::/32".to_string()),
                    port: None,
                    as_number: None,
                    as_country: None,
                    as_owner: None,
                    l7_process_name: None,
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

        // Should match IP within the network
        assert!(
            is_session_in_whitelist(
                None,
                Some("2001:db8::1"),
                80,
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
}
