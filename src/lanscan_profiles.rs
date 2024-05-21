use crate::lanscan_port_info::*;
use crate::lanscan_profiles_db::*;
use crate::update::*;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info, trace, warn};

const PROFILES_REPO: &str = "https://raw.githubusercontent.com/edamametechnologies/threatmodels";
const PROFILES_NAME: &str = "lanscan-profiles-db.json";

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

pub async fn device_type(
    open_ports: &Vec<PortInfo>,
    mdns_services: &Vec<String>,
    oui_vendor: &str,
    hostname: &str,
) -> String {
    trace!(
        "Computing device type for ports {:?}, mdns {:?}, vendor {}, hostname {}",
        open_ports,
        mdns_services,
        oui_vendor,
        hostname
    );

    let device_types = PROFILES.lock().await;

    // To lower case as used in the profiles
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

    for profile in device_types.profiles.iter() {
        for condition in &profile.conditions {
            // Only check if

            if match_condition(
                condition,
                &open_ports_set,
                &mdns_services_lower,
                &oui_vendor_lower,
                &hostname_lower,
                &banners_lower,
            ) {
                trace!("Match for device type {:?}", profile.device_type);
                return profile.device_type.to_string();
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

    "Unknown".to_string()
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
                    let match_result =
                        services
                            .iter()
                            .filter(|service| !service.is_empty())
                            .any(|service| {
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
                    let match_result = vendors
                        .iter()
                        .filter(|vendor| !vendor.is_empty())
                        .any(|vendor| oui_vendor.contains(vendor));
                    if match_result {
                        trace!("Vendor match: {:?} against {:?}", vendors, oui_vendor);
                    }
                    match_result
                }
                _ => true,
            };

            let hostname_match = match &attributes.hostnames {
                Some(hostnames) if !hostnames.is_empty() => {
                    let match_result = hostnames
                        .iter()
                        .filter(|host| !host.is_empty())
                        .any(|host| hostname.contains(host));
                    if match_result {
                        trace!("Hostname match: {:?} against {:?}", hostnames, hostname);
                    }
                    match_result
                }
                _ => true,
            };

            let banner_match = match &attributes.banners {
                Some(banners_attr) if !banners_attr.is_empty() => {
                    let match_result = banners_attr.iter().filter(|banner| !banner.is_empty()).any(
                        |banner_attr| banners.iter().any(|banner| banner.contains(banner_attr)),
                    );
                    if match_result {
                        trace!("Banner match: {:?} against {:?}", banners_attr, banners);
                    }
                    match_result
                }
                _ => true,
            };

            let result = port_match && mdns_match && vendor_match && hostname_match && banner_match;
            if !result {
                trace!("No match for {:?}", attributes);
            }

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

pub async fn update(branch: &str) -> Result<UpdateStatus, Box<dyn Error>> {
    info!("Starting profiles update from backend");

    let mut status = UpdateStatus::NotUpdated;

    let url = format!("{}/{}/{}", PROFILES_REPO, branch, PROFILES_NAME);

    info!("Fetching port vulns from {}", url);

    // Create a client with a long timeout as the file can be large
    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;

    // Use the client to make a request
    let response = client.get(&url).send().await;
    match response {
        Ok(res) => {
            if res.status().is_success() {
                info!("Model transfer complete");
                // Perform the transfer and decode in 2 steps in order to catch format errors
                let json: DeviceTypeListJSON = match res.text().await {
                    Ok(json) => {
                        match serde_json::from_str(&json) {
                            Ok(json) => json,
                            Err(err) => {
                                error!("Model decoding failed : {:?}", err);
                                // Catch a JSON format mismatch
                                return Ok(UpdateStatus::FormatError);
                            }
                        }
                    }
                    Err(err) => {
                        // Only warn this can happen if the device is offline
                        warn!("Model transfer failed: {:?}", err);
                        return Err(err.into());
                    }
                };
                let mut locked_vulns = PROFILES.lock().await;
                *locked_vulns = DeviceTypeList::new_from_json(&json);
                // Success
                status = UpdateStatus::Updated;
            } else {
                // Only warn this can happen if the device is offline
                warn!("Model transfer failed with status: {:?}", res.status());
            }
        }
        Err(err) => {
            // Only warn this can happen if the device is offline
            warn!("Model transfer failed: {:?}", err);
        }
    }
    Ok(status)
}
