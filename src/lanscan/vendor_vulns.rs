use crate::cloud_model::*;
use crate::customlock::*;
use crate::lanscan::vendor_vulns_db::*;
use crate::lanscan::vulnerability_info::*;
use anyhow::{Context, Result};
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
    pub vendor_vulns: Arc<CustomDashMap<String, VulnerabilityVendorInfo>>,
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

        let vendor_vulns = Arc::new(CustomDashMap::new("Vendor Vulns"));
        let mut vendor_vec: Vec<String> = Vec::new();

        for vendor_info in &vuln_info.vulnerabilities {
            vendor_vulns.insert(vendor_info.vendor.clone(), vendor_info.clone());
            vendor_vec.push(vendor_info.vendor.clone());
        }

        vendor_vec.sort();

        // We don't try to update the cache here because this is called from a non-async context
        // The cache will be populated on first access instead

        for vendor_info in &vuln_info.vulnerabilities {
            let mut vulns_sorted = vendor_info.vulnerabilities.clone();
            vulns_sorted.sort_by(|a, b| b.name.cmp(&a.name));

            VULN_LISTS_CACHE.insert(vendor_info.vendor.clone(), Arc::new(vulns_sorted.clone()));

            let vuln_names: Vec<String> = vulns_sorted.iter().map(|v| v.name.clone()).collect();
            VULN_NAME_LISTS_CACHE.insert(vendor_info.vendor.clone(), Arc::new(vuln_names));
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

    // Cache for vendor list (we only need one since it's cleared on update)
    static ref VENDOR_LIST_CACHE: Arc<CustomRwLock<Vec<String>>> = Arc::new(CustomRwLock::new(Vec::new()));

    // Cache for vulnerabilities by vendor
    static ref VULN_LISTS_CACHE: CustomDashMap<String, Arc<Vec<VulnerabilityInfo>>> = CustomDashMap::new("Vendor Vulnerability Lists Cache");

    // Cache for vulnerability names by vendor
    static ref VULN_NAME_LISTS_CACHE: CustomDashMap<String, Arc<Vec<String>>> = CustomDashMap::new("Vendor Vulnerability Names Cache");
}

// Clear all caches
async fn clear_caches() {
    // No try_write, we just execute the actual clear operation
    // in an async context where we can properly await
    let mut vendor_list = VENDOR_LIST_CACHE.write().await;
    vendor_list.clear();
    drop(vendor_list); // Explicitly release the lock

    VULN_LISTS_CACHE.clear();
    VULN_NAME_LISTS_CACHE.clear();
}

pub async fn get_vendors() -> Vec<String> {
    // Try to get from cache first
    {
        let cached = VENDOR_LIST_CACHE.read().await;
        if !cached.is_empty() {
            return cached.clone();
        }
    } // Release the read lock

    // If not in cache, regenerate and cache it
    let data = VULNS.data.read().await;
    let mut vendor_vec: Vec<String> = data
        .vendor_vulns
        .iter()
        .map(|entry| entry.key().clone())
        .collect();

    vendor_vec.sort();

    // Update the cache
    {
        let mut vendor_list = VENDOR_LIST_CACHE.write().await;
        *vendor_list = vendor_vec.clone();
    } // Release the write lock

    vendor_vec
}

pub async fn get_description_from_vendor(vendor: &str) -> String {
    let vendors_map = VULNS.data.read().await.vendor_vulns.clone();
    vendors_map
        .get(vendor)
        .map_or_else(|| "".to_string(), |v| v.vendor.clone())
}

pub async fn get_vulns_of_vendor(vendor: &str) -> Vec<VulnerabilityInfo> {
    let mut vendor_name = vendor.to_string();
    while !vendor_name.is_empty() {
        // Check cache first
        if let Some(cached_vulns) = VULN_LISTS_CACHE.get(&vendor_name) {
            return cached_vulns.as_ref().clone();
        }

        // If not in cache, check if we have this vendor in our data
        let store = VULNS.data.read().await;
        if let Some(vendor_data) = store.vendor_vulns.get(&vendor_name) {
            let mut vulns_sorted = vendor_data.vulnerabilities.clone();
            vulns_sorted.sort_by(|a, b| b.name.cmp(&a.name));

            let arc_vulns = Arc::new(vulns_sorted.clone());
            VULN_LISTS_CACHE.insert(vendor_name, arc_vulns);

            return vulns_sorted;
        }

        // Fallback to parent vendor name
        if let Some(pos) = vendor_name.rfind(' ') {
            vendor_name.truncate(pos);
        } else {
            vendor_name.clear();
        }
    }
    Vec::new()
}

pub async fn get_vulns_names_of_vendor(vendor: &str) -> Vec<String> {
    let mut vendor_name = vendor.to_string();
    while !vendor_name.is_empty() {
        // Check cache first
        if let Some(cached_names) = VULN_NAME_LISTS_CACHE.get(&vendor_name) {
            return cached_names.as_ref().clone();
        }

        // If not in cache, check if we have this vendor in our data
        let store = VULNS.data.read().await;
        if let Some(vendor_data) = store.vendor_vulns.get(&vendor_name) {
            let mut vulns_sorted = vendor_data.vulnerabilities.clone();
            vulns_sorted.sort_by(|a, b| b.name.cmp(&a.name));

            let vuln_names: Vec<String> = vulns_sorted.iter().map(|v| v.name.clone()).collect();

            let arc_names = Arc::new(vuln_names.clone());
            VULN_NAME_LISTS_CACHE.insert(vendor_name, arc_names);

            return vuln_names;
        }

        // Fallback to parent vendor name
        if let Some(pos) = vendor_name.rfind(' ') {
            vendor_name.truncate(pos);
        } else {
            vendor_name.clear();
        }
    }
    Vec::new()
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting vendor vulns update from backend");

    let status = VULNS
        .update(branch, force, |data| {
            let vuln_info_json: VulnerabilityVendorInfoListJSON = serde_json::from_str(data)?;
            Ok(VulnerabilityInfoList::new_from_json(&vuln_info_json))
        })
        .await?;

    // Clear caches on update
    clear_caches().await;

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
        clear_caches().await;
        let vendors = get_vendors().await;
        assert!(!vendors.is_empty(), "Vendors list should not be empty");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_vulns_of_vendor() {
        setup();
        clear_caches().await;
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
        clear_caches().await;
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
        clear_caches().await;
        let branch = "main";

        // Acquire a write lock to modify the signature
        {
            VULNS
                .set_signature("00000000000000000000000000000000".to_string())
                .await;
            // Clear caches when signature changes
            clear_caches().await;
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
        clear_caches().await;
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

    #[tokio::test]
    #[serial]
    async fn test_caching_behavior() {
        setup();
        clear_caches().await;

        // First call should populate cache
        let vendors1 = get_vendors().await;
        let vendor = if !vendors1.is_empty() {
            vendors1[0].clone()
        } else {
            "6Wind".to_string()
        };

        // Get vulnerabilities and names
        let vulns1 = get_vulns_of_vendor(&vendor).await;
        let names1 = get_vulns_names_of_vendor(&vendor).await;

        // Second call should use cache
        let vendors2 = get_vendors().await;
        let vulns2 = get_vulns_of_vendor(&vendor).await;
        let names2 = get_vulns_names_of_vendor(&vendor).await;

        // Verify results are the same
        assert_eq!(vendors1, vendors2, "Cached vendors should match");
        assert_eq!(vulns1, vulns2, "Cached vulnerabilities should match");
        assert_eq!(names1, names2, "Cached vulnerability names should match");
    }
}
