use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use log::{info, trace};
// Tokio Mutex
use tokio::sync::Mutex;
use once_cell::sync::Lazy;

use crate::lanscan_profile_db::*;
use crate::lanscan_port_vulns::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceTypeRule {
    device_type: String,
    open_ports: Vec<u16>,
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

pub async fn device_type(port_info: &Vec<PortInfo>, oui_vendor: &str, os_name: &str) -> String {
    trace!("Computing device type for {:?} ports, {} vendor, {} OS", port_info, oui_vendor, os_name);

    trace!("Locking PROFILES - start");
    let device_types = PROFILES.lock().await;
    trace!("Locking PROFILES - end");

    let oui_vendor_lower = oui_vendor.to_lowercase();
    let open_ports_set: HashSet<u16> = port_info.iter().map(|info| info.port).collect();

    for rule in device_types.device_types.iter() {
        // Check all mandatory ports are here, unless the list is empty
        if rule.open_ports.is_empty() || rule.open_ports.iter().all(|port| open_ports_set.contains(port)) {
            trace!("Match for ports {:?} : {:?}", rule.open_ports, rule);
            // Check at least one vendor is here, unless the list is empty
            if rule.vendors.is_empty() || rule
                .vendors
                .iter()
                .any(|brand| oui_vendor_lower.contains(brand))
            {
                trace!("Match for vendors {:?} : {:?}", rule.vendors, rule);
                // Use the OS as sanity check unless the provided OS name is empty
                if os_name.is_empty() || rule.os_list.contains(&os_name.to_owned()) {
                    trace!("Match for os {:?} : {:?}", rule.os_list, rule);
                    trace!("Found device type {:?}", rule.device_type);
                    return rule.device_type.to_string();
                }
            }
        }
    }

    "Unknown".to_string()
}




