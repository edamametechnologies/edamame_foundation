use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info, trace, warn};

use crate::lanscan_vendor_vulns_db::*;
use crate::lanscan_vulnerability_info::*;
use crate::update::*;

const VENDOR_VULNS_REPO: &str =
    "https://raw.githubusercontent.com/edamametechnologies/threatmodels";
const VENDOR_VULNS_NAME: &str = "lanscan-vendor-vulns-db.json";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityVendorInfo {
    pub vendor: String,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityVendorInfoListJSON {
    pub date: String,
    pub signature: String,
    pub vulnerabilities: Vec<VulnerabilityVendorInfo>,
}

pub struct VulnerabilityInfoList {
    pub date: String,
    pub signature: String,
    pub vendor_vulns: HashMap<String, VulnerabilityVendorInfo>,
}

impl VulnerabilityInfoList {
    pub fn new_from_json(vuln_info: &VulnerabilityVendorInfoListJSON) -> Self {
        info!("Loading vendor info list from JSON");
        let vendor_vulns_list = vuln_info.vulnerabilities.clone();
        let mut vendor_vulns = HashMap::new();

        for vendor_info in vendor_vulns_list {
            vendor_vulns.insert(vendor_info.vendor.clone(), vendor_info);
        }

        info!("Loaded {} vendors", vendor_vulns.len());

        VulnerabilityInfoList {
            date: vuln_info.date.clone(),
            signature: vuln_info.signature.clone(),
            vendor_vulns,
        }
    }
}

pub static VULNS: Lazy<Mutex<VulnerabilityInfoList>> = Lazy::new(|| {
    let vuln_info: VulnerabilityVendorInfoListJSON = serde_json::from_str(VENDOR_VULNS).unwrap();
    let vulns = VulnerabilityInfoList::new_from_json(&vuln_info);
    Mutex::new(vulns)
});

pub async fn get_vendors() -> Vec<String> {
    trace!("Locking VULNS - start");
    let vulns = VULNS.lock().await;
    trace!("Locking VULNS - end");
    vulns.vendor_vulns.keys().cloned().collect()
}

pub async fn get_deep_vendors() -> Vec<u16> {
    (0..65535).collect()
}

pub async fn get_description_from_vendor(vendor: &str) -> String {
    trace!("Locking VULNS - start");
    let vulns = VULNS.lock().await;
    trace!("Locking VULNS - end");
    vulns
        .vendor_vulns
        .get(vendor)
        .map_or("".to_string(), |vendor_info| vendor_info.vendor.clone())
}

pub async fn get_vulns_of_vendor(vendor: &str) -> Vec<VulnerabilityInfo> {
    trace!("Locking VULNS - start");
    let vulns = VULNS.lock().await;
    trace!("Locking VULNS - end");

    // Try the full vendor name first, then try to remove the trailing words one by one until we find a match
    let mut vendor_name = vendor.to_string();
    while !vendor_name.is_empty() {
        if let Some(vendor_info) = vulns.vendor_vulns.get(&vendor_name) {
            return vendor_info.vulnerabilities.clone();
        }
        // Attempt to remove the last word
        if let Some(pos) = vendor_name.rfind(' ') {
            vendor_name.truncate(pos);
        } else {
            // No space found, clear the string to exit the loop
            vendor_name.clear();
        }
    }
    vec![]
}

pub async fn update(branch: &str) -> Result<UpdateStatus, Box<dyn Error>> {
    info!("Starting vendor vulns update from backend");

    let mut status = UpdateStatus::NotUpdated;

    let url = format!("{}/{}/{}", VENDOR_VULNS_REPO, branch, VENDOR_VULNS_NAME);

    info!("Fetching port vulns from {}", url);

    // Create a client with a long timeout as the file can be large
    let client = Client::builder()
        .gzip(true)
        .timeout(Duration::from_secs(120))
        .build()?;

    // Use the client to make a request
    let response = client.get(&url).send().await;
    match response {
        Ok(res) => {
            if res.status().is_success() {
                info!("Model transfer complete");
                // Perform the transfer and decode in 2 steps in order to catch format errors
                let json: VulnerabilityVendorInfoListJSON = match res.text().await {
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
                let mut locked_vulns = VULNS.lock().await;
                *locked_vulns = VulnerabilityInfoList::new_from_json(&json);
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
