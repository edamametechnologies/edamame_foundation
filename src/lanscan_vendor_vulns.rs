use crate::cloud_model::*;
use crate::lanscan_vendor_vulns_db::*;
use crate::lanscan_vulnerability_info::*;
use anyhow::{Context, Result};
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

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

#[derive(Clone)]
pub struct VulnerabilityInfoList {
    pub date: String,
    pub signature: String,
    pub vendor_vulns: Arc<DashMap<String, VulnerabilityVendorInfo>>,
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

        let vendor_vulns = Arc::new(DashMap::new());

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
    pub static ref VULNS: CloudModel<VulnerabilityInfoList> = {
        let model = CloudModel::initialize(VENDOR_VULNS_NAME.to_string(), VENDOR_VULNS, |data| {
            let vuln_info_json: VulnerabilityVendorInfoListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(VulnerabilityInfoList::new_from_json(&vuln_info_json))
        })
        .expect("Failed to initialize CloudModel");
        model
    };
}

pub async fn get_vendors() -> Vec<String> {
    let vendors_map = VULNS.data.read().await.vendor_vulns.clone();
    vendors_map
        .iter()
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>()
}

pub async fn get_description_from_vendor(vendor: &str) -> String {
    let vendors_map = VULNS.data.read().await.vendor_vulns.clone();
    vendors_map
        .get(vendor)
        .map_or_else(|| "".to_string(), |v| v.vendor.clone())
}

pub async fn get_vulns_of_vendor(vendor: &str) -> Vec<VulnerabilityInfo> {
    let vendors_map = VULNS.data.read().await.vendor_vulns.clone();

    let mut vendor_name = vendor.to_string();
    while !vendor_name.is_empty() {
        if let Some(vendor_info) = vendors_map.get(&vendor_name) {
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

    let status = VULNS
        .update(branch, force, |data| {
            let vuln_info_json: VulnerabilityVendorInfoListJSON = serde_json::from_str(data)?;
            Ok(VulnerabilityInfoList::new_from_json(&vuln_info_json))
        })
        .await?;

    match status {
        UpdateStatus::Updated => info!("Vendor vulns were successfully updated."),
        UpdateStatus::NotUpdated => info!("Vendor vulns are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the vendor vulns data."),
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom vendor vulns are in use.")
        }
    }

    Ok(status)
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // Initialize logging or other necessary setup here
    fn setup() {
        // Setup code here if needed
    }

    #[tokio::test]
    #[serial]
    async fn test_get_vendors() {
        setup();
        let vendors = get_vendors().await;
        assert!(!vendors.is_empty(), "Vendors list should not be empty");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_vulns_of_vendor() {
        setup();
        let vendor = "6Wind";
        let vulns = get_vulns_of_vendor(vendor).await;
        assert!(
            !vulns.is_empty(),
            "Vulnerabilities for the vendor should not be empty"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_update_vendor_vulns() {
        setup();
        let branch = "main";
        let status = update(branch, false).await.expect("Update failed");
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::NotUpdated),
            "Update status should be either Updated or NotUpdated"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_signature_update_after_modification() {
        setup();
        let branch = "main";

        // Acquire a write lock to modify the signature
        {
            VULNS
                .set_signature("00000000000000000000000000000000".to_string())
                .await;
        }

        // Perform the update
        let status = update(branch, false).await.expect("Update failed");

        // Check that the update was performed
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::SkippedCustom),
            "Expected the update to be performed or skipped due to custom data"
        );

        // Check that the signature is no longer zeros
        let current_signature = VULNS.get_signature().await;
        assert_ne!(
            current_signature, "00000000000000000000000000000000",
            "Signature should have been updated"
        );
        assert!(
            !current_signature.is_empty(),
            "Signature should not be empty after update"
        );
    }

    // Additional test: Ensure that an invalid update does not change the signature
    #[tokio::test]
    #[serial]
    async fn test_invalid_update_does_not_change_signature() {
        setup();
        let branch = "nonexistent-branch";

        // Get the current signature
        let original_signature = VULNS.get_signature().await;

        // Attempt to perform an update from a nonexistent branch
        let result = update(branch, false).await;

        // The update should fail
        assert!(result.is_err(), "Update should have failed");

        // Check that the signature has not changed
        let current_signature = VULNS.get_signature().await;
        assert_eq!(
            current_signature, original_signature,
            "Signature should not have changed after failed update"
        );
    }
}
