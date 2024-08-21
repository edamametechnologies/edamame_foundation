use dashmap::DashMap;
use lazy_static::lazy_static;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Duration;
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
    pub vendor_vulns: DashMap<String, VulnerabilityVendorInfo>,
}

impl VulnerabilityInfoList {
    pub fn new_from_json(vuln_info: &VulnerabilityVendorInfoListJSON) -> Self {
        info!("Loading vendor info list from JSON");

        let vendor_vulns = DashMap::new();

        for vendor_info in &vuln_info.vulnerabilities {
            vendor_vulns.insert(vendor_info.vendor.clone(), vendor_info.clone());
        }

        info!("Loaded {} vendors", vendor_vulns.len());

        VulnerabilityInfoList {
            date: vuln_info.date.clone(),
            signature: vuln_info.signature.clone(),
            vendor_vulns,
        }
    }
}

lazy_static! {
    pub static ref VULNS: DashMap<String, VulnerabilityVendorInfo> = {
        let vuln_info: VulnerabilityVendorInfoListJSON =
            serde_json::from_str(VENDOR_VULNS).unwrap();
        let vendor_vulns = DashMap::new();
        for vendor_info in vuln_info.vulnerabilities {
            vendor_vulns.insert(vendor_info.vendor.clone(), vendor_info);
        }
        vendor_vulns
    };
}

pub async fn get_vendors() -> Vec<String> {
    trace!("Accessing VULNS - start");
    let vulns = &*VULNS;
    trace!("Accessing VULNS - end");
    vulns.iter().map(|entry| entry.key().clone()).collect()
}

pub async fn get_deep_vendors() -> Vec<u16> {
    (0..65535).collect()
}

pub async fn get_description_from_vendor(vendor: &str) -> String {
    trace!("Accessing VULNS - start");
    let vulns = &*VULNS;
    trace!("Accessing VULNS - end");
    vulns
        .get(vendor)
        .map_or("".to_string(), |vendor_info| vendor_info.vendor.clone())
}

pub async fn get_vulns_of_vendor(vendor: &str) -> Vec<VulnerabilityInfo> {
    trace!("Accessing VULNS - start");
    let vulns = &*VULNS;
    trace!("Accessing VULNS - end");

    let mut vendor_name = vendor.to_string();
    while !vendor_name.is_empty() {
        if let Some(vendor_info) = vulns.get(&vendor_name) {
            return vendor_info.vulnerabilities.clone();
        }
        if let Some(pos) = vendor_name.rfind(' ') {
            vendor_name.truncate(pos);
        } else {
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

    let client = Client::builder()
        .gzip(true)
        .timeout(Duration::from_secs(120))
        .build()?;

    let response = client.get(&url).send().await;
    match response {
        Ok(res) => {
            if res.status().is_success() {
                info!("Model transfer complete");
                let json: VulnerabilityVendorInfoListJSON = match res.text().await {
                    Ok(json) => match serde_json::from_str(&json) {
                        Ok(json) => json,
                        Err(err) => {
                            error!("Model decoding failed : {:?}", err);
                            return Ok(UpdateStatus::FormatError);
                        }
                    },
                    Err(err) => {
                        warn!("Model transfer failed: {:?}", err);
                        return Err(err.into());
                    }
                };
                // Clear the existing DashMap and insert the new data
                VULNS.clear();
                for vendor_info in json.vulnerabilities {
                    VULNS.insert(vendor_info.vendor.clone(), vendor_info);
                }
                status = UpdateStatus::Updated;
            } else {
                warn!("Model transfer failed with status: {:?}", res.status());
            }
        }
        Err(err) => {
            warn!("Model transfer failed: {:?}", err);
        }
    }
    Ok(status)
}
