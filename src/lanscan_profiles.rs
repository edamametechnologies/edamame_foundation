use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use log::{info, trace, warn};
use tokio::sync::Mutex;
use once_cell::sync::Lazy;
use std::error::Error;
use std::time::Duration;
use reqwest::Client;
use crate::lanscan_types::*;
use crate::lanscan_profiles_db::*;

const PROFILES_REPO: &str = "https://raw.githubusercontent.com/edamametechnologies/threatmodels";
const PROFILES_NAME: &str = "lanscan_profiles_db.json";

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Attributes {
    open_ports: Option<Vec<u16>>,
    mdns_services: Option<Vec<String>>,
    vendors: Option<Vec<String>>,
    hostnames: Option<Vec<String>>,
    banners: Option<Vec<String>>,
    negate: Option<bool>, // New field to indicate negation
}

#[derive(Debug, Deserialize, Serialize, Clone)]
enum Condition {
    Leaf(Attributes),
    Node {
        #[serde(rename = "type")]
        condition_type: String,
        sub_conditions: Vec<Condition>,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DeviceTypeRule {
    device_type: String,
    conditions: Vec<Condition>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DeviceTypeListJSON {
    date: String,
    signature: String,
    profiles: Vec<DeviceTypeRule>,
}

struct DeviceTypeList {
    profiles: Vec<DeviceTypeRule>,
}

impl DeviceTypeList {
    fn new_from_json(device_info: &DeviceTypeListJSON) -> Self {
        info!("Loading device profiles from JSON");

        DeviceTypeList {
            profiles: device_info.profiles.clone(),
        }
    }
}

static PROFILES: Lazy<Mutex<DeviceTypeList>> = Lazy::new(|| {
    let profiles_list: DeviceTypeListJSON = serde_json::from_str(DEVICE_PROFILES).unwrap();
    let profiles = DeviceTypeList::new_from_json(&profiles_list);
    Mutex::new(profiles)
});

pub async fn device_type(open_ports: &Vec<PortInfo>, mdns_services: &Vec<String>, oui_vendor: &str, hostname: &str) -> String {
    trace!("Computing device type for ports {:?}, mdns {:?}, vendor {}, hostname {}", open_ports, mdns_services, oui_vendor, hostname);

    let device_types = PROFILES.lock().await;

    // To lower case as used in the profiles
    let oui_vendor_lower = oui_vendor.to_lowercase();
    let hostname_lower = hostname.to_lowercase();
    let mdns_services_lower: Vec<String> = mdns_services.iter().map(|service| service.to_lowercase()).collect();
    let open_ports_set: HashSet<u16> = open_ports.iter().map(|info| info.port).collect();
    let banners_lower: Vec<String> = open_ports.iter().map(|info| info.banner.to_lowercase()).collect();

    for profile in device_types.profiles.iter() {
        for condition in &profile.conditions {
            if match_condition(condition, &open_ports_set, &mdns_services_lower, &oui_vendor_lower, &hostname_lower, &banners_lower) {
                trace!("Match for device type {:?}", profile.device_type);
                return profile.device_type.to_string();
            }
        }
    }

    if (!open_ports.is_empty() || !mdns_services.is_empty()) && !oui_vendor.is_empty() {
        let ports: Vec<u16> = open_ports.iter().map(|info| info.port).collect();
        warn!("Unknown device type for ports {:?}, mdns {:?}, vendor {}, hostname {}, banners {:?}", ports, mdns_services, oui_vendor, hostname, banners_lower);
    }

    "Unknown".to_string()
}

fn match_condition(condition: &Condition, open_ports_set: &HashSet<u16>, mdns_services: &Vec<String>, oui_vendor: &str, hostname: &str, banners:  &Vec<String>) -> bool {
    match condition {
        Condition::Leaf(attributes) => {
            // All ports must match
            let port_match = attributes.open_ports.as_ref()
                .map_or(true, |open_ports_to_match| open_ports_to_match.iter().all(|open_port_to_match| open_ports_set.contains(open_port_to_match)));

            // Any mdns must match
            let mdns_match = attributes.mdns_services.as_ref()
                .map_or(true, |services_to_match| services_to_match.iter().any(|service_to_match| mdns_services.iter().any(|mdns_service| mdns_service.contains(service_to_match))));

            // Any vendor must match
            let vendor_match = attributes.vendors.as_ref().map_or(true, |vendors_to_match| vendors_to_match.iter().any(|vendor_to_match| oui_vendor.contains(vendor_to_match)));

            // Any host must match
            let hostname_match = attributes.hostnames.as_ref().map_or(true, |hostnames_to_match| hostnames_to_match.iter().any(|hostname_to_match| hostname.contains(hostname_to_match)));

            // Any banner must match
            let banner_match = attributes.banners.as_ref().map_or(true, |banners_to_match| banners_to_match.iter().any(|banner_to_match| banners.contains(banner_to_match)));
            let result = port_match && mdns_match && vendor_match && hostname_match && banner_match;

            if attributes.negate.unwrap_or(false) { // Check if negation is true
                !result
            } else {
                result
            }
        }
        Condition::Node { condition_type, sub_conditions } => {
            match condition_type.as_str() {
                "AND" => sub_conditions.iter().all(|sub| match_condition(sub, open_ports_set, mdns_services, oui_vendor, hostname, banners)),
                "OR" => sub_conditions.iter().any(|sub| match_condition(sub, open_ports_set, mdns_services, oui_vendor, hostname, banners)),
                _ => false,
            }
        }
    }
}

pub async fn update(branch: &str) -> Result<bool, Box<dyn Error>> {
    info!("Starting profiles update from backend");

    let mut success = false;

    let url = format!(
        "{}/{}/{}",
        PROFILES_REPO, branch, PROFILES_NAME
    );

    info!("Fetching profiles from {}", url);
    // Create a client with a timeout
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;

    // Use the client to make a request
    let response = client.get(&url).send().await;

    match response {
        Ok(res) => {
            if res.status().is_success() {
                info!("Profiles transfer complete");
                success = true;

                let json: DeviceTypeListJSON = res.json().await?;
                let mut locked_vulns = PROFILES.lock().await;
                *locked_vulns = DeviceTypeList::new_from_json(&json);
            } else {
                error!(
                        "Profiles transfer failed with status: {:?}",
                        res.status()
                    );
            }
        }
        Err(err) => {
            // Only warn this can happen if the device is offline
            warn!("Profiles transfer failed: {:?}", err);
        }
    }

    Ok(success)
}




