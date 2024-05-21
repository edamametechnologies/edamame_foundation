use oui::OuiDatabase;
use tracing::{error, trace, warn};
// Tokio Mutex
use once_cell::sync::Lazy;
use tokio::sync::Mutex;

use crate::lanscan_oui_db::*;

// TODO load from the cloud regularly and store locally
// const OUI_DB_URL: &str = "https://www.wireshark.org/download/automated/data/manuf";

static OUI: Lazy<Mutex<OuiDatabase>> = Lazy::new(|| {
    let oui = OuiDatabase::new_from_str(OUI_DB).unwrap();
    Mutex::new(oui)
});

pub async fn get_mac_address_vendor(mac_address: &str) -> String {
    trace!("Locking OUI - start");
    let oui = OUI.lock().await;
    trace!("Locking OUI - end");

    match oui.query_by_str(mac_address) {
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
