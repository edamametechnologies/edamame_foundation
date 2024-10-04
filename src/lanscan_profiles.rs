use crate::cloud_model::*;
use crate::lanscan_port_info::*;
use crate::lanscan_profiles_db::*;
use crate::rwlock::CustomRwLock;
use anyhow::{Context, Result};
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{info, trace, warn};

// Constants for repository and file names
const PROFILES_NAME: &str = "lanscan-profiles-db.json";

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Attributes {
    open_ports: Option<Vec<u16>>,
    mdns_services: Option<Vec<String>>,
    vendors: Option<Vec<String>>,
    hostnames: Option<Vec<String>>,
    banners: Option<Vec<String>>,
    negate: Option<bool>, // Field to indicate negation
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
    device_type: String,
    conditions: Vec<Condition>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceTypeListJSON {
    date: String,
    signature: String,
    profiles: Vec<DeviceTypeRule>,
}

impl CloudSignature for DeviceTypeList {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

pub struct DeviceTypeList {
    pub date: String,
    pub signature: String,
    pub profiles: DashMap<String, DeviceTypeRule>,
}

impl DeviceTypeList {
    pub fn new_from_json(device_info: DeviceTypeListJSON) -> Self {
        info!("Loading device profiles from JSON");

        let profiles = DashMap::new();
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
    pub static ref PROFILES: CustomRwLock<CloudModel<DeviceTypeList>> = {
        let model = CloudModel::initialize(PROFILES_NAME.to_string(), DEVICE_PROFILES, |data| {
            let profiles_list: DeviceTypeListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(DeviceTypeList::new_from_json(profiles_list))
        })
        .expect("Failed to initialize CloudModel");
        CustomRwLock::new(model)
    };
}

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

    // Acquire read lock on PROFILES
    let profiles_lock = PROFILES.read().await;

    for profile in profiles_lock.data.read().await.profiles.iter() {
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
                return profile.value().device_type.clone();
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

    let profiles_lock = PROFILES.read().await;
    let status = profiles_lock
        .update(branch, force, |data| {
            let profiles_list: DeviceTypeListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(DeviceTypeList::new_from_json(profiles_list))
        })
        .await?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_condition() {
        let condition = Condition::Leaf(Attributes {
            open_ports: Some(vec![80, 443]),
            mdns_services: Some(vec!["http".to_string(), "https".to_string()]),
            vendors: Some(vec!["Cisco".to_string(), "Arista".to_string()]),
            hostnames: Some(vec!["router".to_string(), "switch".to_string()]),
            banners: Some(vec!["Cisco IOS".to_string(), "Arista EOS".to_string()]),
            negate: Some(false),
        });

        let open_ports_set = HashSet::from([80, 443]);
        let mdns_services = vec!["http".to_string(), "https".to_string()];
        let oui_vendor = "Cisco";
        let hostname = "router";
        let banners = vec!["Cisco IOS".to_string(), "Arista EOS".to_string()];

        assert!(match_condition(
            &condition,
            &open_ports_set,
            &mdns_services,
            &oui_vendor,
            &hostname,
            &banners
        ));
    }

    #[test]
    fn test_match_condition_negate() {
        let condition = Condition::Leaf(Attributes {
            open_ports: Some(vec![80, 443]),
            mdns_services: Some(vec!["http".to_string(), "https".to_string()]),
            vendors: Some(vec!["Cisco".to_string(), "Arista".to_string()]),
            hostnames: Some(vec!["router".to_string(), "switch".to_string()]),
            banners: Some(vec!["Cisco IOS".to_string(), "Arista EOS".to_string()]),
            negate: Some(true),
        });

        let open_ports_set = HashSet::from([80, 443]);
        let mdns_services = vec!["http".to_string(), "https".to_string()];
        let oui_vendor = "Cisco";
        let hostname = "router";
        let banners = vec!["Cisco IOS".to_string(), "Arista EOS".to_string()];

        assert!(!match_condition(
            &condition,
            &open_ports_set,
            &mdns_services,
            &oui_vendor,
            &hostname,
            &banners
        ));
    }

    #[test]
    fn test_match_condition_no_open_ports() {
        let condition = Condition::Leaf(Attributes {
            open_ports: None,
            mdns_services: Some(vec!["http".to_string(), "https".to_string()]),
            vendors: Some(vec!["Cisco".to_string(), "Arista".to_string()]),
            hostnames: Some(vec!["router".to_string(), "switch".to_string()]),
            banners: Some(vec!["Cisco IOS".to_string(), "Arista EOS".to_string()]),
            negate: Some(false),
        });

        let open_ports_set = HashSet::new();
        let mdns_services = vec!["http".to_string(), "https".to_string()];
        let oui_vendor = "Cisco";
        let hostname = "router";
        let banners = vec!["Cisco IOS".to_string(), "Arista EOS".to_string()];

        assert!(match_condition(
            &condition,
            &open_ports_set,
            &mdns_services,
            &oui_vendor,
            &hostname,
            &banners
        ));
    }

    #[test]
    fn test_match_condition_no_mdns_services() {
        let condition = Condition::Leaf(Attributes {
            open_ports: Some(vec![80, 443]),
            mdns_services: None,
            vendors: Some(vec!["Cisco".to_string(), "Arista".to_string()]),
            hostnames: Some(vec!["router".to_string(), "switch".to_string()]),
            banners: Some(vec!["Cisco IOS".to_string(), "Arista EOS".to_string()]),
            negate: Some(false),
        });

        let open_ports_set = HashSet::from([80, 443]);
        let mdns_services = vec![];
        let oui_vendor = "Cisco";
        let hostname = "router";
        let banners = vec!["Cisco IOS".to_string(), "Arista EOS".to_string()];

        assert!(match_condition(
            &condition,
            &open_ports_set,
            &mdns_services,
            &oui_vendor,
            &hostname,
            &banners
        ));
    }
}
