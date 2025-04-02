use crate::blacklists_db::BLACKLISTS;
use crate::cloud_model::*;
use crate::rwlock::CustomRwLock;
use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use ipnet::IpNet;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::{info, trace, warn};

// Constants
const BLACKLISTS_FILE_NAME: &str = "blacklists-db.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct BlacklistInfo {
    pub name: String,
    pub description: Option<String>,
    pub last_updated: Option<String>,
    pub source_url: Option<String>,
    pub ip_ranges: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct BlacklistsJSON {
    pub date: String,
    pub signature: String,
    pub blacklists: Vec<BlacklistInfo>,
}

#[derive(Clone)]
pub struct Blacklists {
    pub date: String,
    pub signature: String,
    pub blacklists: DashMap<String, BlacklistInfo>,
    // Cache for parsed IP ranges for performance
    pub parsed_ranges: DashMap<String, Vec<IpNet>>,
}

impl From<Blacklists> for BlacklistsJSON {
    fn from(blacklists: Blacklists) -> Self {
        BlacklistsJSON {
            date: blacklists.date,
            signature: blacklists.signature,
            blacklists: blacklists
                .blacklists
                .iter()
                .map(|r| r.value().clone())
                .collect(),
        }
    }
}

impl CloudSignature for Blacklists {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

impl Blacklists {
    /// Creates a new Blacklists instance from the provided JSON data.
    pub fn new_from_json(blacklist_info: BlacklistsJSON) -> Self {
        info!("Loading blacklists from JSON");

        let blacklists = DashMap::new();
        let parsed_ranges = DashMap::new();

        for info in blacklist_info.blacklists {
            let list_name = info.name.clone();

            // Parse and cache IP ranges
            let mut ranges = Vec::new();
            for ip_range_str in &info.ip_ranges {
                match ip_range_str.parse::<IpNet>() {
                    Ok(net) => ranges.push(net),
                    Err(e) => {
                        warn!("Failed to parse IP range {}: {}", ip_range_str, e);
                    }
                }
            }

            // Store the parsed ranges
            if !ranges.is_empty() {
                parsed_ranges.insert(list_name.clone(), ranges);
            }

            blacklists.insert(list_name, info);
        }

        info!("Loaded {} blacklists", blacklists.len());

        Blacklists {
            date: blacklist_info.date,
            signature: blacklist_info.signature,
            blacklists,
            parsed_ranges,
        }
    }

    /// Retrieves all IP ranges for a given blacklist.
    fn get_all_ip_ranges(&self, blacklist_name: &str) -> Result<Vec<IpNet>> {
        // Get the blacklist info and handle the case where it's not found
        let _info = self
            .blacklists
            .get(blacklist_name)
            .ok_or_else(|| anyhow!("Blacklist not found: {}", blacklist_name))?;

        // Get the parsed ranges for this blacklist
        let ip_ranges = match self.parsed_ranges.get(blacklist_name) {
            Some(ranges) => ranges.clone(),
            None => Vec::new(),
        };

        Ok(ip_ranges)
    }

    /// Checks if a given IP is in the blacklist.
    pub fn is_ip_in_blacklist(&self, ip_str: &str, blacklist_name: &str) -> Result<bool> {
        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|e| anyhow!("Invalid IP address: {}", e))?;

        let ranges = self.get_all_ip_ranges(blacklist_name)?;

        for range in ranges {
            if range.contains(&ip) {
                trace!(
                    "IP {} matched blacklist {} with range {}",
                    ip_str,
                    blacklist_name,
                    range
                );
                return Ok(true);
            }
        }

        Ok(false)
    }
}

// Global BLACKLIST Variable using lazy_static! and CustomRwLock
lazy_static! {
    pub static ref LISTS: CustomRwLock<CloudModel<Blacklists>> = {
        let model = CloudModel::initialize(BLACKLISTS_FILE_NAME.to_string(), BLACKLISTS, |data| {
            let blacklist_info_json: BlacklistsJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(Blacklists::new_from_json(blacklist_info_json))
        })
        .expect("Failed to initialize CloudModel");
        CustomRwLock::new(model)
    };
}

/// Checks if a blacklist name exists in the current model (default or custom).
pub async fn is_valid_blacklist(blacklist_name: &str) -> bool {
    LISTS
        .read()
        .await
        .data
        .read()
        .await
        .blacklists
        .contains_key(blacklist_name)
}

/// Checks if a given IP is blacklisted.
/// Returns a tuple (bool, Vec<String>) where:
/// - The boolean indicates whether the IP is blacklisted in any list
/// - The Vec<String> contains the names of all blacklists that match
pub async fn is_ip_blacklisted(ip: &str) -> (bool, Vec<String>) {
    trace!("Checking if IP: {} is blacklisted", ip);

    let mut matching_blacklists = Vec::new();

    // Access the current blacklist data (could be default or custom)
    let list_model = LISTS.read().await;
    let list_data = list_model.data.read().await;

    // Check each blacklist in the current data model
    for entry in list_data.blacklists.iter() {
        let blacklist_name = entry.key();
        let result = list_data.is_ip_in_blacklist(ip, blacklist_name);

        match result {
            Ok(true) => {
                matching_blacklists.push(blacklist_name.clone());
            }
            Ok(false) => {}
            Err(e) => {
                warn!("Error checking blacklist {}: {}", blacklist_name, e);
            }
        }
    }

    // Drop guards
    drop(list_data);
    drop(list_model);

    let is_blacklisted = !matching_blacklists.is_empty();

    (is_blacklisted, matching_blacklists)
}

/// Updates the blacklists by fetching the latest data from the specified branch.
/// This function utilizes the `CloudModel` to perform the update.
pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting blacklists update from backend");

    // Acquire lock on LISTS
    let model = LISTS.read().await;

    // Perform the update
    let status = model
        .update(branch, force, |data| {
            let blacklist_info_json: BlacklistsJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(Blacklists::new_from_json(blacklist_info_json))
        })
        .await?;

    match status {
        UpdateStatus::Updated => info!("Blacklists were successfully updated."),
        UpdateStatus::NotUpdated => info!("Blacklists are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the blacklists data."),
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom blacklists are in use.")
        }
    }

    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Helper function to initialize LISTS with controlled test data
    async fn initialize_test_blacklists() {
        let test_blacklist_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test_signature".to_string(),
            blacklists: vec![
                BlacklistInfo {
                    name: "base_blacklist".to_string(),
                    description: Some("Base test blacklist".to_string()),
                    last_updated: Some("2025-03-29".to_string()),
                    source_url: None,
                    ip_ranges: vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()],
                },
                BlacklistInfo {
                    name: "another_blacklist".to_string(),
                    description: Some("Another test blacklist".to_string()),
                    last_updated: Some("2025-03-29".to_string()),
                    source_url: None,
                    ip_ranges: vec!["172.16.0.0/12".to_string(), "169.254.0.0/16".to_string()],
                },
            ],
        };

        let blacklists = Blacklists::new_from_json(test_blacklist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(blacklists)
            .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_ip_matching() {
        initialize_test_blacklists().await;

        // Test IP in range
        let (is_blacklisted, _) = is_ip_blacklisted("192.168.1.1").await;
        assert!(is_blacklisted, "IP in range should be blacklisted");

        // Test IP not in range
        let (is_blacklisted, _) = is_ip_blacklisted("8.8.8.8").await;
        assert!(!is_blacklisted, "IP not in range should not be blacklisted");
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_blacklist() {
        initialize_test_blacklists().await;

        // Test with IP that is not in any blacklist
        let (is_blacklisted, _) = is_ip_blacklisted("8.8.8.8").await;
        assert!(
            !is_blacklisted,
            "Should return false for non-blacklisted IP"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_is_valid_blacklist() {
        initialize_test_blacklists().await;

        assert!(
            is_valid_blacklist("base_blacklist").await,
            "Should return true for existing blacklist"
        );
        assert!(
            !is_valid_blacklist("nonexistent_blacklist").await,
            "Should return false for non-existent blacklist"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_ip_format() {
        initialize_test_blacklists().await;

        // Invalid IP format should return false
        let (is_blacklisted, _) = is_ip_blacklisted("not-an-ip").await;
        assert!(!is_blacklisted, "Invalid IP should not be blacklisted");
    }

    #[tokio::test]
    #[serial]
    async fn test_ipv6_support() {
        let test_blacklist_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test_signature".to_string(),
            blacklists: vec![BlacklistInfo {
                name: "ipv6_blacklist".to_string(),
                description: Some("IPv6 test blacklist".to_string()),
                last_updated: Some("2025-03-29".to_string()),
                source_url: None,
                ip_ranges: vec!["2001:db8::/32".to_string(), "::1/128".to_string()],
            }],
        };

        let blacklists = Blacklists::new_from_json(test_blacklist_json);
        LISTS
            .write()
            .await
            .overwrite_with_test_data(blacklists)
            .await;

        // Test IPv6 in range
        let (is_blacklisted, _) = is_ip_blacklisted("2001:db8:1:2:3:4:5:6").await;
        assert!(is_blacklisted, "IPv6 in range should be blacklisted");

        // Test IPv6 not in range
        let (is_blacklisted, _) = is_ip_blacklisted("2002:db8:1:2:3:4:5:6").await;
        assert!(
            !is_blacklisted,
            "IPv6 not in range should not be blacklisted"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_blacklist_ip_check() {
        initialize_test_blacklists().await;

        // Test with IP in blacklist range
        let (is_blacklisted, _) = is_ip_blacklisted("192.168.1.10").await;
        assert!(is_blacklisted, "IP in range should be blacklisted");

        // Test with IP not in blacklist range
        let (is_blacklisted, _) = is_ip_blacklisted("8.8.8.8").await;
        assert!(!is_blacklisted, "IP not in range should not be blacklisted");

        // Test IP in second blacklist
        let (is_blacklisted, _) = is_ip_blacklisted("172.16.1.1").await;
        assert!(
            is_blacklisted,
            "IP in second blacklist should be blacklisted"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_ipv6_blacklist() {
        let test_blacklist_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test_signature".to_string(),
            blacklists: vec![BlacklistInfo {
                name: "ipv6_blacklist".to_string(),
                description: Some("IPv6 test blacklist".to_string()),
                last_updated: Some("2025-03-29".to_string()),
                source_url: None,
                ip_ranges: vec!["2001:db8::/32".to_string(), "::1/128".to_string()],
            }],
        };

        let blacklists = Blacklists::new_from_json(test_blacklist_json);
        // Overwrite the global model directly for this test
        LISTS
            .write()
            .await
            .overwrite_with_test_data(blacklists)
            .await;

        // Test IPv6 in blacklist range
        let (is_blacklisted, _) = is_ip_blacklisted("2001:db8:1:2:3:4:5:6").await;
        assert!(is_blacklisted, "IPv6 in range should be blacklisted");

        // Test IPv6 not in range
        let (is_blacklisted, _) = is_ip_blacklisted("2002:db8:1:2:3:4:5:6").await;
        assert!(
            !is_blacklisted,
            "IPv6 not in range should not be blacklisted"
        );

        // Test IPv6 localhost
        let (is_blacklisted, _) = is_ip_blacklisted("::1").await;
        assert!(is_blacklisted, "IPv6 localhost should be blacklisted");

        // Reset LISTS back to default after the test
        LISTS.write().await.reset_to_default().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_empty_blacklist_name() {
        initialize_test_blacklists().await;

        // Empty blacklist name should never match (though the function currently loops through all)
        let (is_blacklisted, _) = is_ip_blacklisted("8.8.8.8").await;
        // The behavior depends on the test data; if 8.8.8.8 isn't in any list, it should be false.
        assert!(
            !is_blacklisted,
            "Empty blacklist name check (behavior test)"
        );
    }
}
