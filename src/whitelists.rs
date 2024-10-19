use crate::rwlock::CustomRwLock;
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{info, trace, warn};

use crate::cloud_model::*; // Ensure this path is correct based on your project structure
use crate::whitelists_db::WHITELISTS;

// Constants
const WHITELISTS_FILE_NAME: &str = "whitelists-db.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhitelistEndpoint {
    pub destination: Option<String>,
    pub port: Option<u16>,
    pub as_number: Option<u32>,          // New field for ASN number
    pub as_country: Option<String>,      // New field for ASN country
    pub as_owner: Option<String>,        // New field for ASN owner
    pub l7_process_name: Option<String>, // New field for L7 process name
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhitelistInfo {
    pub name: String,
    #[serde(rename = "extends", deserialize_with = "deserialize_extends")]
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

fn deserialize_extends<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ExtendsVisitor;

    impl<'de> serde::de::Visitor<'de> for ExtendsVisitor {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string, an array of strings, or null")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.eq_ignore_ascii_case("none") {
                Ok(None)
            } else {
                Ok(Some(vec![value.to_string()]))
            }
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                vec.push(value);
            }
            Ok(Some(vec))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(ExtendsVisitor)
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

/// Checks if a given destination and port are in the specified whitelist.
pub async fn is_destination_in_whitelist(
    destination: Option<&str>, // Now optional
    port: u16,
    whitelist_name: &str,
    as_number: Option<u32>,
    as_country: Option<&str>,
    as_owner: Option<&str>,
    l7_process_name: Option<&str>,
) -> bool {
    trace!(
        "Checking if {:?}:{} is in whitelist {} with ASN {:?}, Country {:?}, Owner {:?}, L7 Process {:?}",
        destination,
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
        let dest_match = destination_matches(destination, &endpoint.destination);
        let port_match = port_matches(port, endpoint.port);
        let asn_match = as_number_matches(as_number, endpoint.as_number);
        let country_match = as_country_matches(as_country, &endpoint.as_country);
        let owner_match = as_owner_matches(as_owner, &endpoint.as_owner);
        let l7_match = l7_process_name_matches(l7_process_name, &endpoint.l7_process_name);

        if dest_match && port_match && asn_match && country_match && owner_match && l7_match {
            trace!("Matched whitelist endpoint: {:?}", endpoint);
            true
        } else {
            trace!(
                "Did not match whitelist endpoint: {:?}, Reasons: dest_match={}, port_match={}, asn_match={}, country_match={}, owner_match={}, l7_match={}",
                endpoint,
                dest_match,
                port_match,
                asn_match,
                country_match,
                owner_match,
                l7_match
            );
            false
        }
    })
}

/// Helper function to match destinations, supporting wildcards.
fn destination_matches(
    session_destination: Option<&str>,
    endpoint_destination: &Option<String>,
) -> bool {
    match endpoint_destination {
        Some(pattern) => match session_destination {
            Some(dest) => {
                if pattern.starts_with("*.") {
                    let suffix = &pattern[2..];
                    dest == suffix || dest.ends_with(&format!(".{}", suffix))
                } else {
                    dest.eq_ignore_ascii_case(pattern)
                }
            }
            None => false, // Session requires a destination but it's not provided
        },
        None => true, // Whitelist endpoint applies to any destination
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

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to initialize `LISTS` with controlled test data.
    async fn initialize_test_whitelists() {
        // Define test whitelists JSON
        let test_whitelist_json = WhitelistsJSON {
            date: "2024-10-19".to_string(),
            signature: Some("test_signature".to_string()),
            whitelists: vec![
                // Base Whitelist
                WhitelistInfo {
                    name: "base_whitelist".to_string(),
                    inherits: None,
                    endpoints: vec![WhitelistEndpoint {
                        destination: Some("api.edamame.tech".to_string()),
                        port: Some(443),
                        as_number: None,
                        as_country: None,
                        as_owner: None,
                        l7_process_name: None,
                        description: Some("Edamame API endpoint".to_string()),
                    }],
                },
                // CICD Dependencies Whitelist
                WhitelistInfo {
                    name: "cicd_dependencies".to_string(),
                    inherits: Some(vec!["base_whitelist".to_string()]),
                    endpoints: vec![
                        WhitelistEndpoint {
                            destination: Some("github.com".to_string()),
                            port: Some(443),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            l7_process_name: None,
                            description: Some("GitHub main website".to_string()),
                        },
                        WhitelistEndpoint {
                            destination: Some("api.github.com".to_string()),
                            port: Some(443),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            l7_process_name: None,
                            description: Some("GitHub API endpoint".to_string()),
                        },
                    ],
                },
                // CICD Tools Whitelist
                WhitelistInfo {
                    name: "cicd_tools".to_string(),
                    inherits: None,
                    endpoints: vec![
                        WhitelistEndpoint {
                            destination: Some("jenkins.io".to_string()),
                            port: Some(443),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            l7_process_name: None,
                            description: Some("Jenkins CI/CD".to_string()),
                        },
                        WhitelistEndpoint {
                            destination: Some("circleci.com".to_string()),
                            port: Some(443),
                            as_number: None,
                            as_country: None,
                            as_owner: None,
                            l7_process_name: None,
                            description: Some("CircleCI".to_string()),
                        },
                    ],
                },
                // CICD Whitelist inheriting from dependencies and tools
                WhitelistInfo {
                    name: "cicd".to_string(),
                    inherits: Some(vec![
                        "cicd_dependencies".to_string(),
                        "cicd_tools".to_string(),
                    ]),
                    endpoints: vec![], // No direct endpoints
                },
                // Extended Whitelist for ASN and L7 Testing
                WhitelistInfo {
                    name: "extended_whitelist".to_string(),
                    inherits: Some(vec!["base_whitelist".to_string()]),
                    endpoints: vec![WhitelistEndpoint {
                        destination: Some("api.example.com".to_string()),
                        port: Some(443),
                        as_number: Some(12345),
                        as_country: Some("US".to_string()),
                        as_owner: Some("Example Corp".to_string()),
                        l7_process_name: Some("nginx".to_string()),
                        description: Some("Trusted API".to_string()),
                    }],
                },
            ],
        };

        // Initialize `Whitelists` from the test JSON
        let whitelists = Whitelists::new_from_json(test_whitelist_json);

        // Overwrite `LISTS` with the test data
        LISTS
            .write()
            .await
            .overwrite_with_test_data(whitelists)
            .await;
    }

    /// Ensures that `initialize_test_whitelists` is called before each test.
    struct TestSetup;

    #[async_trait::async_trait]
    impl Drop for TestSetup {
        fn drop(&mut self) {
            // Note: Drop cannot be async. Ensure reset is called manually if needed.
        }
    }

    #[tokio::test]
    async fn test_is_destination_in_whitelist() {
        // Initialize test data
        initialize_test_whitelists().await;

        // Ensure cleanup after test
        let _setup = TestSetup;

        // Test that destinations are correctly identified in the whitelist
        assert!(
            is_destination_in_whitelist(
                Some("api.edamame.tech"),
                443,
                "base_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "api.edamame.tech should be in base_whitelist"
        );

        assert!(
            is_destination_in_whitelist(
                Some("github.com"),
                443,
                "cicd_dependencies",
                None,
                None,
                None,
                None
            )
            .await,
            "github.com should be in cicd_dependencies"
        );

        assert!(
            is_destination_in_whitelist(
                Some("api.edamame.tech"),
                443,
                "cicd_dependencies",
                None,
                None,
                None,
                None
            )
            .await,
            "api.edamame.tech should be inherited in cicd_dependencies"
        ); // inherited from base_whitelist

        assert!(
            is_destination_in_whitelist(Some("github.com"), 443, "cicd", None, None, None, None)
                .await,
            "github.com should be in cicd via inheritance"
        );

        assert!(
            is_destination_in_whitelist(Some("jenkins.io"), 443, "cicd", None, None, None, None)
                .await,
            "jenkins.io should be in cicd via cicd_tools inheritance"
        ); // from cicd_tools

        assert!(
            !is_destination_in_whitelist(
                Some("malicious.com"),
                80,
                "cicd_dependencies",
                None,
                None,
                None,
                None
            )
            .await,
            "malicious.com should not be in cicd_dependencies"
        );

        assert!(
            !is_destination_in_whitelist(
                Some("github.com"),
                80,
                "cicd_dependencies",
                None,
                None,
                None,
                None
            )
            .await,
            "github.com on port 80 should not be in cicd_dependencies"
        );
    }

    #[tokio::test]
    async fn test_destination_matches() {
        // Initialize test data if necessary
        initialize_test_whitelists().await;

        // Test the destination matching function
        assert!(
            destination_matches(Some("example.com"), &Some("example.com".to_string())),
            "Exact match should return true"
        );

        assert!(
            destination_matches(
                Some("subdestination.example.com"),
                &Some("*.example.com".to_string())
            ),
            "Wildcard match should return true"
        );

        assert!(
            destination_matches(Some("example.com"), &Some("*.example.com".to_string())),
            "Exact match against wildcard should return true"
        );

        assert!(
            !destination_matches(Some("notexample.com"), &Some("*.example.com".to_string())),
            "Non-matching domain should return false"
        );

        assert!(
            !destination_matches(
                Some("anotherexample.com"),
                &Some("*.example.com".to_string())
            ),
            "Another non-matching domain should return false"
        );
    }

    #[tokio::test]
    async fn test_port_matches() {
        // Initialize test data if necessary
        initialize_test_whitelists().await;

        // Test the port matching function
        assert!(
            port_matches(80, Some(80)),
            "Port 80 should match whitelist port 80"
        );

        assert!(
            port_matches(80, None),
            "Port 80 should match when whitelist port is None (any port)"
        );

        assert!(
            !port_matches(8080, Some(80)),
            "Port 8080 should not match whitelist port 80"
        );
    }

    #[tokio::test]
    async fn test_whitelist_inheritance() {
        // Initialize test data
        initialize_test_whitelists().await;

        // Ensure cleanup after test
        let _setup = TestSetup;

        // Test that inheritance works correctly
        // "cicd_dependencies" inherits from "base_whitelist"
        assert!(
            is_destination_in_whitelist(
                Some("api.edamame.tech"),
                443,
                "cicd_dependencies",
                None,
                None,
                None,
                None
            )
            .await,
            "api.edamame.tech should be inherited in cicd_dependencies"
        );

        // "cicd" inherits from "cicd_dependencies" and "cicd_tools"
        assert!(
            is_destination_in_whitelist(
                Some("api.edamame.tech"),
                443,
                "cicd",
                None,
                None,
                None,
                None
            )
            .await,
            "api.edamame.tech should be inherited in cicd via cicd_dependencies"
        );

        assert!(
            is_destination_in_whitelist(Some("github.com"), 443, "cicd", None, None, None, None)
                .await,
            "github.com should be inherited in cicd via cicd_dependencies"
        );

        assert!(
            is_destination_in_whitelist(Some("jenkins.io"), 443, "cicd", None, None, None, None)
                .await,
            "jenkins.io should be inherited in cicd via cicd_tools"
        );

        assert!(
            !is_destination_in_whitelist(Some("unknown.com"), 80, "cicd", None, None, None, None)
                .await,
            "unknown.com should not be in cicd"
        );
    }

    #[tokio::test]
    async fn test_whitelist_not_found() {
        // Initialize test data
        initialize_test_whitelists().await;

        // Ensure cleanup after test
        let _setup = TestSetup;

        // Test that querying a non-existent whitelist returns false
        assert!(
            !is_destination_in_whitelist(
                Some("example.com"),
                80,
                "non_existent_whitelist",
                None,
                None,
                None,
                None
            )
            .await,
            "Non-existent whitelist should return false"
        );
    }

    #[tokio::test]
    async fn test_wildcard_destination() {
        // Initialize test data
        initialize_test_whitelists().await;

        // Test destination matching with wildcard endpoints
        assert!(
            destination_matches(Some("sub.example.com"), &Some("*.example.com".to_string())),
            "Wildcard subdomain should match"
        );

        assert!(
            destination_matches(Some("example.com"), &Some("*.example.com".to_string())),
            "Exact match against wildcard should return true"
        );

        assert!(
            !destination_matches(Some("other.com"), &Some("*.example.com".to_string())),
            "Non-matching domain should return false"
        );
    }

    #[tokio::test]
    async fn test_is_destination_in_whitelist_with_asn_and_l7() {
        // Initialize test data
        initialize_test_whitelists().await;

        // Ensure cleanup after test
        let _setup = TestSetup;

        // Test matching criteria with correct ASN and L7
        assert!(
            is_destination_in_whitelist(
                Some("api.example.com"),
                443,
                "extended_whitelist",
                Some(12345),
                Some("US"),
                Some("Example Corp"),
                Some("nginx"),
            )
            .await,
            "api.example.com with correct ASN and L7 should be in extended_whitelist"
        );

        // Test mismatching ASN number
        assert!(
            !is_destination_in_whitelist(
                Some("api.example.com"),
                443,
                "extended_whitelist",
                Some(54321), // Different ASN
                Some("US"),
                Some("Example Corp"),
                Some("nginx"),
            )
            .await,
            "api.example.com with incorrect ASN should not be in extended_whitelist"
        );

        // Test mismatching country
        assert!(
            !is_destination_in_whitelist(
                Some("api.example.com"),
                443,
                "extended_whitelist",
                Some(12345),
                Some("CA"), // Different country
                Some("Example Corp"),
                Some("nginx"),
            )
            .await,
            "api.example.com with incorrect country should not be in extended_whitelist"
        );

        // Test mismatching owner
        assert!(
            !is_destination_in_whitelist(
                Some("api.example.com"),
                443,
                "extended_whitelist",
                Some(12345),
                Some("US"),
                Some("Other Corp"), // Different owner
                Some("nginx"),
            )
            .await,
            "api.example.com with incorrect owner should not be in extended_whitelist"
        );

        // Test mismatching L7 process name
        assert!(
            !is_destination_in_whitelist(
                Some("api.example.com"),
                443,
                "extended_whitelist",
                Some(12345),
                Some("US"),
                Some("Example Corp"),
                Some("apache"), // Different L7 process
            )
            .await,
            "api.example.com with incorrect L7 should not be in extended_whitelist"
        );
    }
}
