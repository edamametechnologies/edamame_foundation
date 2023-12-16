use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use log::{info, trace, error};
// Tokio Mutex
use tokio::sync::Mutex;
use once_cell::sync::Lazy;

use crate::lanscan_profile_db::*;
use crate::lanscan_types::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceTypeRule {
    device_type: String,
    open_ports: Vec<u16>,
    mdns_services: Vec<String>,
    vendors: Vec<String>,
    os_list: Vec<String>,
}

pub struct DeviceTypeList {
    pub device_types: Vec<DeviceTypeRule>,
}

impl DeviceTypeList {
    pub fn new_from_str(json: &str) -> Self {
        info!("Loading device profiles from JSON");
        DeviceTypeList {
            device_types: serde_json::from_str(json).unwrap(),
        }
    }
}

static PROFILES: Lazy<Mutex<DeviceTypeList>> = Lazy::new(|| {
    let profiles = DeviceTypeList::new_from_str(DEVICE_PROFILES);
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

        // Match on ports, a type is defined by a unique set of ports
        if ! rule.open_ports.is_empty() && rule
            .open_ports
            .iter()
            .all(|port| open_ports_set.contains(port)) {
            trace!("Match for ports {:?} : {:?}", rule.open_ports, rule);
            return rule.device_type.to_string();
        };

        // Match on vendors, a type is defined by the presence of at least one vendor
        if ! rule.vendors.is_empty() && rule
            .vendors
            .iter()
            .any(|brand| oui_vendor_lower.contains(brand))
        {
            trace!("Match for vendors {:?} : {:?}", rule.vendors, rule);
            return rule.device_type.to_string();
        }

        // Match on services, a type is defined by the presence of at least one service
        if ! rule.mdns_services.is_empty() && rule
            .mdns_services
            .iter()
            .any(|service| mdns_services.contains(service))
        {
            trace!("Match for services {:?} : {:?}", rule.mdns_services, rule);
            return rule.device_type.to_string();
        }

        // We don't use os name for now
    }
    // Generate an error to be able to see if we missed a device type
    error!("Unknown device type for ports {:?}, mdns {:?}, vendor {}, OS name {}", port_info, mdns_services, oui_vendor, os_name);

    "Unknown".to_string()
}




