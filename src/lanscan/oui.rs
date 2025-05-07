use crate::customlock::CustomDashMap;
use crate::customlock::CustomRwLock;
use crate::lanscan::oui_db::*;
use lazy_static::lazy_static;
use macaddr::MacAddr6;
use oui::OuiDatabase;
use std::sync::Arc;
use tracing::{error, warn};

// TODO load from the cloud regularly and store locally
// const OUI_DB_URL: &str = "https://www.wireshark.org/download/automated/data/manuf";

lazy_static! {
    static ref OUI: Arc<CustomRwLock<OuiDatabase>> = {
        let oui = OuiDatabase::new_from_str(OUI_DB).unwrap();
        Arc::new(CustomRwLock::new(oui))
    };

    // Cache of MAC string -> vendor string for fast repeat look-ups
    static ref VENDOR_CACHE: CustomDashMap<String, String> = CustomDashMap::new("vendor_cache");
}

pub async fn get_mac_address_vendor(mac_address: &MacAddr6) -> String {
    // Convert to canonical string once
    let mac_str = mac_address.to_string();

    // Check cache first
    if let Some(vendor_entry) = VENDOR_CACHE.get(&mac_str) {
        return vendor_entry.value().clone();
    }

    let oui = OUI.read().await;

    let vendor = match oui.query_by_str(&mac_str) {
        Ok(Some(res)) => {
            if let Some(name_long) = res.name_long {
                name_long
            } else if !res.name_short.is_empty() {
                res.name_short
            } else {
                warn!("No vendor name found for MAC address: {}", mac_str);
                "".to_string()
            }
        }
        Ok(None) => {
            warn!("No vendor found for MAC address: {}", mac_str);
            "".to_string()
        }
        Err(err) => {
            error!(
                "Failed to query the vendor database for MAC address: {} - {}",
                mac_str, err
            );
            "".to_string()
        }
    };

    // Store in cache for subsequent fast access
    VENDOR_CACHE.insert(mac_str, vendor.clone());

    vendor
}
