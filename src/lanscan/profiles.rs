use crate::cloud_model::*;
use crate::customlock::*;
use crate::lanscan::port_info::*;
use crate::lanscan::profiles_db::*;
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{info, trace, warn};

// Constants for repository and file names
const PROFILES_NAME: &str = "lanscan-profiles-db.json";

// Cache for device_type computation: key -> device type
lazy_static! {
    static ref DEVICE_TYPE_CACHE: CustomDashMap<String, String> =
        CustomDashMap::new("Profiles Device Type Cache");
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Attributes {
    pub open_ports: Option<Vec<u16>>,
    pub mdns_services: Option<Vec<String>>,
    pub vendors: Option<Vec<String>>,
    pub hostnames: Option<Vec<String>>,
    pub banners: Option<Vec<String>>,
    pub negate: Option<bool>, // Field to indicate negation
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum Condition {
    Leaf(Attributes),
    Node {
        #[serde(rename = "type")]
        condition_type: String,
        sub_conditions: Vec<Condition>,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DeviceTypeRule {
    pub device_type: String,
    pub conditions: Vec<Condition>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceTypeListJSON {
    pub date: String,
    pub signature: String,
    pub profiles: Vec<DeviceTypeRule>,
}

impl CloudSignature for DeviceTypeList {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

#[derive(Clone)]
pub struct DeviceTypeList {
    pub date: String,
    pub signature: String,
    pub profiles: Arc<CustomDashMap<String, DeviceTypeRule>>,
}

impl DeviceTypeList {
    pub fn new_from_json(device_info: DeviceTypeListJSON) -> Self {
        info!("Loading device profiles from JSON");

        let profiles = Arc::new(CustomDashMap::new("Profiles"));
        for profile in device_info.profiles {
            profiles.insert(profile.device_type.clone(), profile);
        }

        DeviceTypeList {
            date: device_info.date,
            signature: device_info.signature,
            profiles,
        }
    }
}

lazy_static! {
    pub static ref PROFILES: CloudModel<DeviceTypeList> = {
        let model = CloudModel::initialize(PROFILES_NAME.to_string(), DEVICE_PROFILES, |data| {
            let profiles_list: DeviceTypeListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(DeviceTypeList::new_from_json(profiles_list))
        })
        .expect("Failed to initialize CloudModel");
        model
    };
}

pub async fn device_type(
    open_ports: &Vec<PortInfo>,
    mdns_services: &Vec<String>,
    oui_vendor: &str,
    hostname: &str,
) -> String {
    // Build a deterministic cache key
    let mut ports_vec: Vec<u16> = open_ports.iter().map(|p| p.port).collect();
    ports_vec.sort_unstable();
    let ports_key = ports_vec
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<String>>()
        .join(",");

    let mut mdns_vec: Vec<String> = mdns_services.iter().map(|s| s.to_lowercase()).collect();
    mdns_vec.sort();
    let mdns_key = mdns_vec.join(",");

    let banners_vec: Vec<String> = open_ports
        .iter()
        .map(|info| info.banner.to_lowercase())
        .collect();
    let mut banners_sorted = banners_vec.clone();
    banners_sorted.sort();
    let banners_key = banners_sorted.join(",");

    let key = format!(
        "{}|{}|{}|{}|{}",
        ports_key,
        mdns_key,
        oui_vendor.to_lowercase(),
        hostname.to_lowercase(),
        banners_key
    );

    if let Some(entry) = DEVICE_TYPE_CACHE.get(&key) {
        return entry.clone();
    }

    trace!(
        "Computing device type for ports {:?}, mdns {:?}, vendor {}, hostname {}",
        open_ports,
        mdns_services,
        oui_vendor,
        hostname
    );

    // Convert inputs to lowercase for case-insensitive comparison
    let oui_vendor_lower = oui_vendor.to_lowercase();
    let hostname_lower = hostname.to_lowercase();
    let mdns_services_lower: Vec<String> = mdns_services
        .iter()
        .map(|service| service.to_lowercase())
        .collect();
    let open_ports_set: HashSet<u16> = open_ports.iter().map(|info| info.port).collect();
    let banners_lower: Vec<String> = open_ports
        .iter()
        .map(|info| info.banner.to_lowercase())
        .collect();

    // Clone the Arc to avoid holding the lock during iteration
    let profiles_map = PROFILES.data.read().await.profiles.clone();

    for profile in profiles_map.iter() {
        for condition in &profile.value().conditions {
            if match_condition(
                condition,
                &open_ports_set,
                &mdns_services_lower,
                &oui_vendor_lower,
                &hostname_lower,
                &banners_lower,
            ) {
                trace!("Match for device type {:?}", profile.value().device_type);
                let result = profile.value().device_type.clone();

                // Store in cache before returning
                DEVICE_TYPE_CACHE.insert(key, result.clone());

                return result;
            }
        }
    }

    if (!open_ports.is_empty() || !mdns_services.is_empty()) && !oui_vendor.is_empty() {
        let ports: Vec<u16> = open_ports.iter().map(|info| info.port).collect();
        warn!(
            "Unknown device type for ports {:?}, mdns {:?}, vendor {}, hostname {}, banners {:?}",
            ports, mdns_services, oui_vendor, hostname, banners_lower
        );
    }

    let result = "Unknown".to_string();

    // Store in cache before returning
    DEVICE_TYPE_CACHE.insert(key, result.clone());

    result
}

fn match_condition(
    condition: &Condition,
    open_ports_set: &HashSet<u16>,
    mdns_services: &Vec<String>,
    oui_vendor: &str,
    hostname: &str,
    banners: &Vec<String>,
) -> bool {
    match condition {
        Condition::Leaf(attributes) => {
            let port_match = match &attributes.open_ports {
                Some(open_ports) => {
                    let match_result = open_ports.iter().all(|port| open_ports_set.contains(port));
                    if match_result {
                        trace!("Port match: {:?} against {:?}", open_ports, open_ports_set);
                    }
                    match_result
                }
                None => true,
            };

            let mdns_match = match &attributes.mdns_services {
                Some(services) if !services.is_empty() => {
                    let match_result = services.iter().any(|service| {
                        mdns_services
                            .iter()
                            .any(|mdns_service| mdns_service.contains(service))
                    });
                    if match_result {
                        trace!("MDNS match: {:?} against {:?}", services, mdns_services);
                    }
                    match_result
                }
                _ => true,
            };

            let vendor_match = match &attributes.vendors {
                Some(vendors) if !vendors.is_empty() => {
                    let match_result = vendors.iter().any(|vendor| oui_vendor.contains(vendor));
                    if match_result {
                        trace!("Vendor match: {:?} against {:?}", vendors, oui_vendor);
                    }
                    match_result
                }
                _ => true,
            };

            let hostname_match = match &attributes.hostnames {
                Some(hostnames) if !hostnames.is_empty() => {
                    let match_result = hostnames.iter().any(|host| hostname.contains(host));
                    if match_result {
                        trace!("Hostname match: {:?} against {:?}", hostnames, hostname);
                    }
                    match_result
                }
                _ => true,
            };

            let banner_match = match &attributes.banners {
                Some(banners_attr) if !banners_attr.is_empty() => {
                    let match_result = banners_attr.iter().any(|banner_attr| {
                        banners.iter().any(|banner| banner.contains(banner_attr))
                    });
                    if match_result {
                        trace!("Banner match: {:?} against {:?}", banners_attr, banners);
                    }
                    match_result
                }
                _ => true,
            };

            let result = port_match && mdns_match && vendor_match && hostname_match && banner_match;

            if attributes.negate.unwrap_or(false) {
                !result
            } else {
                result
            }
        }
        Condition::Node {
            condition_type,
            sub_conditions,
        } => match condition_type.as_str() {
            "AND" => sub_conditions.iter().all(|sub| {
                match_condition(
                    sub,
                    open_ports_set,
                    mdns_services,
                    oui_vendor,
                    hostname,
                    banners,
                )
            }),
            "OR" => sub_conditions.iter().any(|sub| {
                match_condition(
                    sub,
                    open_ports_set,
                    mdns_services,
                    oui_vendor,
                    hostname,
                    banners,
                )
            }),
            _ => false,
        },
    }
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting profiles update from backend");

    let status = PROFILES
        .update(branch, force, |data| {
            let profiles_list: DeviceTypeListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(DeviceTypeList::new_from_json(profiles_list))
        })
        .await?;

    // Clear computed device_type cache whenever we attempt an update (conservative)
    DEVICE_TYPE_CACHE.clear();

    match status {
        UpdateStatus::Updated => info!("Profiles were successfully updated."),
        UpdateStatus::NotUpdated => info!("Profiles are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the profiles data."),
        UpdateStatus::SkippedCustom => info!("Update skipped because custom profiles are in use."),
    }

    Ok(status)
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_model::UpdateStatus;
    use serial_test::serial;
    use std::sync::Once;

    // Initialize logging or other necessary setup here
    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            // Initialize logging or any other setup here
        });

        // Clear device type cache to ensure test isolation
        DEVICE_TYPE_CACHE.clear();
    }

    #[tokio::test]
    #[serial]
    async fn test_match_condition() {
        setup();
        let condition = Condition::Leaf(Attributes {
            open_ports: Some(vec![80, 443]),
            mdns_services: Some(vec!["http".to_string(), "https".to_string()]),
            vendors: Some(vec!["cisco".to_string(), "arista".to_string()]),
            hostnames: Some(vec!["router".to_string(), "switch".to_string()]),
            banners: Some(vec!["cisco ios".to_string(), "arista eos".to_string()]),
            negate: Some(false),
        });

        let open_ports_set = HashSet::from([80, 443]);
        let mdns_services = vec!["http".to_string(), "https".to_string()];
        let oui_vendor = "cisco";
        let hostname = "router";
        let banners = vec!["cisco ios".to_string(), "arista eos".to_string()];

        assert!(match_condition(
            &condition,
            &open_ports_set,
            &mdns_services,
            &oui_vendor,
            &hostname,
            &banners
        ));
    }

    #[tokio::test]
    #[serial]
    async fn test_match_condition_negate() {
        setup();
        let condition = Condition::Leaf(Attributes {
            open_ports: Some(vec![80, 443]),
            mdns_services: Some(vec!["http".to_string(), "https".to_string()]),
            vendors: Some(vec!["cisco".to_string(), "arista".to_string()]),
            hostnames: Some(vec!["router".to_string(), "switch".to_string()]),
            banners: Some(vec!["cisco ios".to_string(), "arista eos".to_string()]),
            negate: Some(true),
        });

        let open_ports_set = HashSet::from([80, 443]);
        let mdns_services = vec!["http".to_string(), "https".to_string()];
        let oui_vendor = "cisco";
        let hostname = "router";
        let banners = vec!["cisco ios".to_string(), "arista eos".to_string()];

        assert!(!match_condition(
            &condition,
            &open_ports_set,
            &mdns_services,
            &oui_vendor,
            &hostname,
            &banners
        ));
    }

    #[tokio::test]
    #[serial]
    async fn test_match_condition_no_open_ports() {
        setup();
        let condition = Condition::Leaf(Attributes {
            open_ports: None,
            mdns_services: Some(vec!["http".to_string(), "https".to_string()]),
            vendors: Some(vec!["cisco".to_string(), "arista".to_string()]),
            hostnames: Some(vec!["router".to_string(), "switch".to_string()]),
            banners: Some(vec!["cisco ios".to_string(), "arista eos".to_string()]),
            negate: Some(false),
        });

        let open_ports_set = HashSet::new();
        let mdns_services = vec!["http".to_string(), "https".to_string()];
        let oui_vendor = "cisco";
        let hostname = "router";
        let banners = vec!["cisco ios".to_string(), "arista eos".to_string()];

        assert!(match_condition(
            &condition,
            &open_ports_set,
            &mdns_services,
            &oui_vendor,
            &hostname,
            &banners
        ));
    }

    #[tokio::test]
    #[serial]
    async fn test_device_type_unknown() {
        setup();
        let open_ports = vec![];
        let mdns_services = vec![];
        let oui_vendor = "";
        let hostname = "";

        let result = device_type(&open_ports, &mdns_services, oui_vendor, hostname).await;
        assert_eq!(result, "Unknown");
    }

    // New test: Modify the signature to zeros, perform an update, and check the signature changes
    #[tokio::test]
    #[serial]
    async fn test_signature_update_after_modification() {
        setup();
        let branch = "main";

        // Acquire a write lock to modify the signature
        {
            PROFILES
                .set_signature("00000000000000000000000000000000".to_string())
                .await;
        }

        // Perform the update
        let status = update(branch, false).await.expect("Update failed");

        // Check that the update was performed
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::SkippedCustom),
            "Expected the update to be performed or skipped due to custom data"
        );

        // Check that the signature is no longer zeros
        let current_signature = PROFILES.get_signature().await;
        assert_ne!(
            current_signature, "00000000000000000000000000000000",
            "Signature should have been updated"
        );
        assert!(
            !current_signature.is_empty(),
            "Signature should not be empty after update"
        );
    }

    // Additional test: Ensure that an invalid update does not change the signature
    #[tokio::test]
    #[serial]
    async fn test_invalid_update_does_not_change_signature() {
        setup();
        let branch = "nonexistent-branch";

        // Get the current signature
        let original_signature = PROFILES.get_signature().await;

        // Attempt to perform an update from a nonexistent branch
        let result = update(branch, false).await;

        // The update should fail
        assert!(result.is_err(), "Update should have failed");

        // Check that the signature has not changed
        let current_signature = PROFILES.get_signature().await;
        assert_eq!(
            current_signature, original_signature,
            "Signature should not have changed after failed update"
        );
    }
}
