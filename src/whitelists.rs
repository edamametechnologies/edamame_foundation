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
    pub destination: String,
    pub port: Option<u16>,
    pub comment: Option<String>,
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
    destination: &str,
    port: u16,
    whitelist_name: &str,
) -> bool {
    trace!(
        "Checking if {}:{} is in whitelist {}",
        destination,
        port,
        whitelist_name
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
            // Whitelist not found, return true
            return true;
        }
    };
    endpoints.iter().any(|endpoint| {
        destination_matches(destination, &endpoint.destination) && port_matches(port, endpoint.port)
    })
}

/// Helper function to match destinations, supporting wildcards.
fn destination_matches(destination: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        let suffix = &pattern[2..];
        destination == suffix || destination.ends_with(&format!(".{}", suffix))
    } else {
        destination.eq_ignore_ascii_case(pattern)
    }
}

/// Helper function to match ports.
fn port_matches(port: u16, whitelist_port: Option<u16>) -> bool {
    whitelist_port.map_or(true, |wp| wp == port)
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

    fn setup() {
        // Any setup code if necessary
    }

    #[tokio::test]
    async fn test_is_destination_in_whitelist() {
        setup();

        // Perform an update from the 'main' branch
        let status = update_whitelists("main").await.expect("Update failed");
        assert!(matches!(
            status,
            UpdateStatus::Updated | UpdateStatus::NotUpdated
        ));

        // Test that destinations are correctly identified in the whitelist
        assert!(is_destination_in_whitelist("api.edamame.tech", 443, "base_whitelist").await);
        assert!(is_destination_in_whitelist("github.com", 443, "cicd_dependencies").await);
        assert!(is_destination_in_whitelist("api.edamame.tech", 443, "cicd_dependencies").await); // inherited from base_whitelist
        assert!(is_destination_in_whitelist("github.com", 443, "cicd").await);
        assert!(is_destination_in_whitelist("jenkins.io", 443, "cicd").await); // from cicd_tools
        assert!(!is_destination_in_whitelist("malicious.com", 80, "cicd_dependencies").await);
        assert!(!is_destination_in_whitelist("github.com", 80, "cicd_dependencies").await);
    }

    #[tokio::test]
    async fn test_destination_matches() {
        setup();
        // Test the destination matching function
        assert!(destination_matches("example.com", "example.com"));
        assert!(destination_matches(
            "subdestination.example.com",
            "*.example.com"
        ));
        assert!(destination_matches("example.com", "*.example.com"));
        assert!(!destination_matches("notexample.com", "*.example.com"));
        assert!(!destination_matches("anotherexample.com", "*.example.com"));
    }

    #[tokio::test]
    async fn test_port_matches() {
        setup();
        // Test the port matching function
        assert!(port_matches(80, Some(80)));
        assert!(port_matches(80, None));
        assert!(!port_matches(8080, Some(80)));
    }

    #[tokio::test]
    async fn test_whitelist_inheritance() {
        setup();

        // Perform an update from the 'main' branch
        let status = update_whitelists("main").await.expect("Update failed");
        assert!(matches!(
            status,
            UpdateStatus::Updated | UpdateStatus::NotUpdated
        ));

        // Test that inheritance works correctly
        // "cicd_dependencies" inherits from "base_whitelist"
        assert!(is_destination_in_whitelist("api.edamame.tech", 443, "cicd_dependencies").await);
        // "cicd" inherits from "cicd_dependencies" and "cicd_tools"
        assert!(is_destination_in_whitelist("api.edamame.tech", 443, "cicd").await);
        assert!(is_destination_in_whitelist("github.com", 443, "cicd").await);
        assert!(is_destination_in_whitelist("jenkins.io", 443, "cicd").await);
        assert!(!is_destination_in_whitelist("unknown.com", 80, "cicd").await);
    }

    #[tokio::test]
    async fn test_whitelist_not_found() {
        setup();
        // Test that querying a non-existent whitelist returns true
        assert!(is_destination_in_whitelist("example.com", 80, "non_existent_whitelist").await);
    }

    #[tokio::test]
    async fn test_wildcard_destination() {
        setup();
        // Test destination matching with wildcard endpoints
        assert!(destination_matches("sub.example.com", "*.example.com"));
        assert!(destination_matches("example.com", "*.example.com"));
        assert!(!destination_matches("other.com", "*.example.com"));
    }
}
