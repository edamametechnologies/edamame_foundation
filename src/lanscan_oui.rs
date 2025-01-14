use crate::lanscan_oui_db::*;
use crate::rwlock::CustomRwLock;
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
}

pub async fn get_mac_address_vendor(mac_address: &MacAddr6) -> String {
    let oui = OUI.read().await;

    let mac_address = mac_address.to_string();

    match oui.query_by_str(&mac_address) {
        Ok(Some(res)) => {
            if let Some(name_long) = res.name_long {
                name_long
            } else if !res.name_short.is_empty() {
                res.name_short
            } else {
                warn!("No vendor name found for MAC address: {}", mac_address);
                "".to_string()
            }
        }
        Ok(None) => {
            warn!("No vendor found for MAC address: {}", mac_address);
            "".to_string()
        }
        Err(err) => {
            error!(
                "Failed to query the vendor database for MAC address: {} - {}",
                mac_address, err
            );
            "".to_string()
        }
    }
}
