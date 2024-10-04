use crate::cloud_model::*;
use crate::lanscan_vendor_vulns_db::*;
use crate::lanscan_vulnerability_info::*;
use crate::rwlock::CustomRwLock;
use anyhow::{Context, Result};
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use tracing::{info, trace};

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

impl CloudSignature for VulnerabilityInfoList {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
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
    pub static ref VULNS: CustomRwLock<CloudModel<VulnerabilityInfoList>> = {
        let model = CloudModel::initialize(VENDOR_VULNS_NAME.to_string(), VENDOR_VULNS, |data| {
            let vuln_info_json: VulnerabilityVendorInfoListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(VulnerabilityInfoList::new_from_json(&vuln_info_json))
        })
        .expect("Failed to initialize CloudModel");
        CustomRwLock::new(model)
    };
}

pub async fn get_vendors() -> Vec<String> {
    trace!("Accessing VULNS - start");
    let vulns_lock = VULNS.read().await;
    let vendors = vulns_lock
        .data
        .read()
        .await
        .vendor_vulns
        .iter()
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();
    trace!("Accessing VULNS - end");
    vendors
}

pub async fn get_description_from_vendor(vendor: &str) -> String {
    trace!("Accessing VULNS - start");
    let vulns_lock = VULNS.read().await;
    let description = vulns_lock
        .data
        .read()
        .await
        .vendor_vulns
        .get(vendor)
        .map_or_else(|| "".to_string(), |v| v.vendor.clone());
    trace!("Accessing VULNS - end");
    description
}

pub async fn get_vulns_of_vendor(vendor: &str) -> Vec<VulnerabilityInfo> {
    trace!("Accessing VULNS - start");
    let vulns_lock = VULNS.read().await;
    let vendor_vulns = &vulns_lock.data.read().await.vendor_vulns;
    trace!("Accessing VULNS - end");

    let mut vendor_name = vendor.to_string();
    while !vendor_name.is_empty() {
        if let Some(vendor_info) = vendor_vulns.get(&vendor_name) {
            let mut vulnerabilities = vendor_info.vulnerabilities.clone();
            // Sort by reverse order of name (therefore date)
            vulnerabilities.sort_by(|a, b| b.name.cmp(&a.name));
            return vulnerabilities;
        }
        if let Some(pos) = vendor_name.rfind(' ') {
            vendor_name.truncate(pos);
        } else {
            vendor_name.clear();
        }
    }
    vec![]
}

pub async fn get_vulns_names_of_vendor(vendor: &str) -> Vec<String> {
    let vulns = get_vulns_of_vendor(vendor).await;
    vulns.iter().map(|vuln| vuln.name.clone()).collect()
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting vendor vulns update from backend");

    let vulns_lock = VULNS.read().await;
    let status = vulns_lock
        .update(branch, force, |data| {
            let vuln_info_json: VulnerabilityVendorInfoListJSON = serde_json::from_str(data)?;
            Ok(VulnerabilityInfoList::new_from_json(&vuln_info_json))
        })
        .await?;
    Ok(status)
}
