use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use log::{info, trace, error, warn};
// Tokio Mutex
use tokio::sync::Mutex;
use once_cell::sync::Lazy;
use std::error::Error;

use crate::lanscan_types::*;
use crate::lanscan_profiles_db::*;

const PROFILES_REPO: &str = "https://raw.githubusercontent.com/edamametechnologies/threatmodels";
const PROFILES_NAME: &str = "lanscan_profiles_db.json";

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DeviceTypeRule {
    device_type: String,
    open_ports: Vec<u16>,
    mdns_services: Vec<String>,
    vendors: Vec<String>,
    os_list: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceTypeListJSON {
    pub date: String,
    pub signature: String,
    pub profiles: Vec<DeviceTypeRule>,
}

pub struct DeviceTypeList {
    pub date: String,
    pub signature: String,
    pub device_types: Vec<DeviceTypeRule>,
}

impl DeviceTypeList {
    pub fn new_from_json(device_info: &DeviceTypeListJSON) -> Self {
        info!("Loading device profiles from JSON");

        DeviceTypeList {
            date: device_info.date.clone(),
            signature: device_info.signature.clone(),
            device_types: device_info.profiles.clone(),
        }
    }
}

static PROFILES: Lazy<Mutex<DeviceTypeList>> = Lazy::new(|| {
    let profiles_list: DeviceTypeListJSON = serde_json::from_str(DEVICE_PROFILES).unwrap();
    let profiles = DeviceTypeList::new_from_json(&profiles_list);
    Mutex::new(profiles)
});

// TODO: also use the discovered services to determine the device type (for example "Deskjet" in the case of a printer)

pub async fn device_type(port_info: &Vec<PortInfo>, mdns_services: &Vec<String>, oui_vendor: &str, os_name: &str) -> String {
    trace!("Computing device type for ports {:?}, mdns {:?}, vendor {}, OS name {}", port_info, mdns_services, oui_vendor, os_name);

    trace!("Locking PROFILES - start");
    let device_types = PROFILES.lock().await;
    trace!("Locking PROFILES - end");

    let oui_vendor_lower = oui_vendor.to_lowercase();
    let open_ports_set: HashSet<u16> = port_info.iter().map(|info| info.port).collect();

    for rule in device_types.device_types.iter() {

        // Match on ports, a type can be defined by a unique set of ports
        if ! rule.open_ports.is_empty() && rule
            .open_ports
            .iter()
            .all(|port| open_ports_set.contains(port)) {
            trace!("Match for ports {:?} : {:?}", rule.open_ports, rule);
            return rule.device_type.to_string();
        };

        // Match on services, a type can be defined by the presence of at least one service
        if ! rule.mdns_services.is_empty() && rule
            .mdns_services
            .iter()
            .any(|service| mdns_services.contains(service))
        {
            trace!("Match for services {:?} : {:?}", rule.mdns_services, rule);
            return rule.device_type.to_string();
        }

        // Match on vendors, a type can be defined by the presence of at least one vendor
        if ! rule.vendors.is_empty() && rule
            .vendors
            .iter()
            .any(|brand| oui_vendor_lower.contains(brand))
        {
            trace!("Match for vendors {:?} : {:?}", rule.vendors, rule);
            return rule.device_type.to_string();
        }

        // We don't use os name for now
    }
    // Generate an error if there is significant information in order to improve the profiles
    if (! port_info.is_empty() || ! mdns_services.is_empty()) && ! oui_vendor.is_empty() {
        error!("Unknown device type for ports {:?}, mdns {:?}, vendor {}, OS name {}", port_info, mdns_services, oui_vendor, os_name);
    }

    "Unknown".to_string()
}

pub async fn update(branch: &str) -> Result<bool, Box<dyn Error>> {
    info!("Starting port vulns update from backend");

    let mut success = false;

    let url = format!(
        "{}/{}/{}",
        PROFILES_REPO, branch, PROFILES_NAME
    );

    info!("Fetching profile from {}", url);

    let response = reqwest::get(&url).await;

    match response {
        Ok(res) => {
            if res.status().is_success() {
                info!("Profile transfer complete");
                success = true;

                let json: DeviceTypeListJSON = res.json().await?;
                let mut locked_vulns = PROFILES.lock().await;
                *locked_vulns = DeviceTypeList::new_from_json(&json);

            } else {
                error!(
                        "Profile transfer failed with status: {:?}",
                        res.status()
                    );
            }
        }
        Err(err) => {
            // Only warn this can happen if the device is offline
            warn!("Profile transfer failed: {:?}", err);
        }
    }

    Ok(success)
}




