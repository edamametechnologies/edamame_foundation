use crate::cloud_model::*;
use crate::customlock::*;
use crate::lanscan::port_info::*;
use crate::lanscan::port_vulns_db::*;
use crate::lanscan::vulnerability_info::*;
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::default::Default;
use std::sync::Arc;
use tracing::{info, warn};

const PORT_VULNS_NAME: &str = "lanscan-port-vulns-db.json";

#[derive(Debug, Serialize, Deserialize, Clone, Ord, Eq, PartialEq, PartialOrd)]
pub struct VulnerabilityPortInfo {
    pub port: u16,
    pub name: String,
    pub description: String,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub count: u32,
    pub protocol: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityPortInfoListJSON {
    pub date: String,
    pub signature: String,
    pub vulnerabilities: Vec<VulnerabilityPortInfo>,
}

impl CloudSignature for VulnerabilityPortInfoList {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

#[derive(Clone)]
pub struct VulnerabilityPortInfoList {
    pub date: String,
    pub signature: String,
    pub port_vulns: Arc<CustomDashMap<u16, VulnerabilityPortInfo>>,
    pub http_ports: Arc<CustomDashMap<u16, VulnerabilityPortInfo>>,
    pub https_ports: Arc<CustomDashMap<u16, VulnerabilityPortInfo>>,
}

impl VulnerabilityPortInfoList {
    pub fn new_from_json(vuln_info: VulnerabilityPortInfoListJSON) -> Self {
        info!("Loading port info list from JSON");

        let port_vulns = Arc::new(CustomDashMap::new("Port Vulns"));
        let http_ports = Arc::new(CustomDashMap::new("HTTP Ports"));
        let https_ports = Arc::new(CustomDashMap::new("HTTPS Ports"));

        let mut http_vec: Vec<u16> = Vec::new();
        let mut https_vec: Vec<u16> = Vec::new();

        for port_info in vuln_info.vulnerabilities {
            if port_info.protocol == "http" {
                http_ports.insert(port_info.port, port_info.clone());
                http_vec.push(port_info.port);
            } else if port_info.protocol == "https" {
                https_ports.insert(port_info.port, port_info.clone());
                https_vec.push(port_info.port);
            }
            port_vulns.insert(port_info.port, port_info.clone());

            PORT_NAMES_CACHE.insert(port_info.port, port_info.name.clone());
            PORT_DESCRIPTIONS_CACHE.insert(port_info.port, port_info.description.clone());
            PORT_VULN_LISTS_CACHE
                .insert(port_info.port, Arc::new(port_info.vulnerabilities.clone()));
            PORT_COUNTS_CACHE.insert(port_info.port, port_info.count);
        }

        http_vec.sort_unstable();
        https_vec.sort_unstable();

        // We don't try to update the cache here because this is called from a non-async context
        // The HTTP/HTTPS port lists will be populated on first access instead

        info!(
            "Loaded {} ports, {} HTTP ports, {} HTTPS ports",
            port_vulns.len(),
            http_ports.len(),
            https_ports.len()
        );

        VulnerabilityPortInfoList {
            date: vuln_info.date,
            signature: vuln_info.signature,
            port_vulns,
            http_ports,
            https_ports,
        }
    }
}

// Define a wrapper for port mappings used in testing
#[derive(Clone, Debug)]
pub struct ServicePortsMap {
    pub port_map: Arc<CustomDashMap<u16, String>>,
    pub signature: String,
}

impl Default for ServicePortsMap {
    fn default() -> Self {
        Self {
            port_map: Arc::new(CustomDashMap::new("Port Map")),
            signature: "test_signature".to_string(),
        }
    }
}

impl CloudSignature for ServicePortsMap {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }

    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

lazy_static! {
    pub static ref VULNS: CloudModel<VulnerabilityPortInfoList> = {
        let model = CloudModel::initialize(PORT_VULNS_NAME.to_string(), PORT_VULNS, |data| {
            let vuln_info_json: VulnerabilityPortInfoListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(VulnerabilityPortInfoList::new_from_json(vuln_info_json))
        })
        .expect("Failed to initialize CloudModel");
        model
    };

    // For testing purposes - a simple service ports mapping
    pub static ref SERVICE_PORTS: CloudModel<ServicePortsMap> = {
        let model = CloudModel::initialize_empty();
        model
    };

    // Cache for port names by port
    static ref PORT_NAMES_CACHE: CustomDashMap<u16, String> = CustomDashMap::new("Port Names Cache");

    // Cache for port descriptions by port
    static ref PORT_DESCRIPTIONS_CACHE: CustomDashMap<u16, String> = CustomDashMap::new("Port Descriptions Cache");

    // Cache for port vulnerability lists by port
    static ref PORT_VULN_LISTS_CACHE: CustomDashMap<u16, Arc<Vec<VulnerabilityInfo>>> = CustomDashMap::new("Port Vulnerability Lists Cache");

    // Cache for port counts by port
    static ref PORT_COUNTS_CACHE: CustomDashMap<u16, u32> = CustomDashMap::new("Port Counts Cache");

    // Cache for HTTP port lists
    static ref HTTP_PORT_LIST_CACHE: Arc<CustomRwLock<Vec<u16>>> = Arc::new(CustomRwLock::new(Vec::new()));

    // Cache for HTTPS port lists
    static ref HTTPS_PORT_LIST_CACHE: Arc<CustomRwLock<Vec<u16>>> = Arc::new(CustomRwLock::new(Vec::new()));

    // Cache for device criticality computations – key is a comma-separated sorted list of ports
    static ref CRITICALITY_CACHE: CustomDashMap<String, String> = CustomDashMap::new("Port Vulns Criticality Cache");
}

// Clear all caches
async fn clear_caches() {
    PORT_NAMES_CACHE.clear();
    PORT_DESCRIPTIONS_CACHE.clear();
    PORT_VULN_LISTS_CACHE.clear();
    PORT_COUNTS_CACHE.clear();

    // No try_write, we just execute the actual clear operation
    // in an async context where we can properly await
    let mut http_list = HTTP_PORT_LIST_CACHE.write().await;
    http_list.clear();
    drop(http_list); // Explicitly release the lock

    let mut https_list = HTTPS_PORT_LIST_CACHE.write().await;
    https_list.clear();
    drop(https_list); // Explicitly release the lock

    CRITICALITY_CACHE.clear();
}

pub async fn get_ports() -> Vec<u16> {
    // Clone the Arc to the DashMap so we don't need to hold the lock during iteration
    let ports_map = VULNS.data.read().await.port_vulns.clone();
    ports_map.iter().map(|entry| *entry.key()).collect()
}

pub fn get_deep_ports() -> Vec<u16> {
    (0..65535).collect()
}

pub async fn get_description_from_port(port: u16) -> String {
    // Try cache first
    if let Some(cached) = PORT_DESCRIPTIONS_CACHE.get(&port) {
        return cached.clone();
    }

    // If not in cache, get from the data
    let port_vulns = VULNS.data.read().await.port_vulns.clone();
    if let Some(port_info) = port_vulns.get(&port) {
        let description = port_info.description.clone();
        PORT_DESCRIPTIONS_CACHE.insert(port, description.clone());
        return description;
    }

    "".to_string()
}

pub async fn get_name_from_port(port: u16) -> String {
    // Try cache first
    if let Some(cached) = PORT_NAMES_CACHE.get(&port) {
        return cached.clone();
    }

    // If not in cache, get from the data
    let port_vulns = VULNS.data.read().await.port_vulns.clone();
    if let Some(port_info) = port_vulns.get(&port) {
        let name = port_info.name.clone();
        PORT_NAMES_CACHE.insert(port, name.clone());
        return name;
    }

    "".to_string()
}

pub async fn get_http_ports() -> Vec<u16> {
    // Try cache first
    {
        let cached = HTTP_PORT_LIST_CACHE.read().await;
        if !cached.is_empty() {
            return cached.clone();
        }
    } // Release the read lock

    // If not in cache, generate and cache it
    let http_ports = VULNS.data.read().await.http_ports.clone();
    let mut http_vec: Vec<u16> = http_ports.iter().map(|entry| *entry.key()).collect();
    http_vec.sort_unstable();

    // Update the cache
    {
        let mut http_list = HTTP_PORT_LIST_CACHE.write().await;
        *http_list = http_vec.clone();
    } // Release the write lock

    http_vec
}

pub async fn get_https_ports() -> Vec<u16> {
    // Try cache first
    {
        let cached = HTTPS_PORT_LIST_CACHE.read().await;
        if !cached.is_empty() {
            return cached.clone();
        }
    } // Release the read lock

    // If not in cache, generate and cache it
    let https_ports = VULNS.data.read().await.https_ports.clone();
    let mut https_vec: Vec<u16> = https_ports.iter().map(|entry| *entry.key()).collect();
    https_vec.sort_unstable();

    // Update the cache
    {
        let mut https_list = HTTPS_PORT_LIST_CACHE.write().await;
        *https_list = https_vec.clone();
    } // Release the write lock

    https_vec
}

pub async fn get_vulns_of_port(port: u16) -> Vec<VulnerabilityInfo> {
    // Try cache first
    if let Some(cached) = PORT_VULN_LISTS_CACHE.get(&port) {
        let mut vulns = cached.as_ref().clone();
        vulns.sort_by(|a, b| b.name.cmp(&a.name));
        return vulns;
    }

    // If not in cache, get from the data
    let port_vulns = VULNS.data.read().await.port_vulns.clone();
    if let Some(port_info) = port_vulns.get(&port) {
        let mut vulns = port_info.vulnerabilities.clone();
        vulns.sort_by(|a, b| b.name.cmp(&a.name));

        let arc_vulns = Arc::new(vulns.clone());
        PORT_VULN_LISTS_CACHE.insert(port, arc_vulns);

        return vulns;
    }

    Vec::new()
}

pub async fn get_vulns_names_of_port(port: u16) -> Vec<String> {
    let vulns = get_vulns_of_port(port).await;
    vulns.iter().map(|vuln| vuln.name.clone()).collect()
}

pub async fn get_device_criticality(port_info_list: &[PortInfo]) -> String {
    // Build a deterministic key – sorted list of ports
    let mut ports: Vec<u16> = port_info_list.iter().map(|p| p.port).collect();
    ports.sort_unstable();
    let key = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<String>>()
        .join(",");

    // Check cache first
    if let Some(entry) = CRITICALITY_CACHE.get(&key) {
        return entry.clone();
    }

    // Get port_vulns outside the fold closure to avoid await inside non-async closure
    let port_vulns = VULNS.data.read().await.port_vulns.clone();

    // Compute sum of counts
    let count_sum = ports.iter().fold(0, |acc, port| {
        if let Some(count) = PORT_COUNTS_CACHE.get(port) {
            acc + *count
        } else {
            // If not in cache, use the already retrieved port_vulns
            if let Some(port_info) = port_vulns.get(port) {
                let count = port_info.count;
                PORT_COUNTS_CACHE.insert(*port, count);
                acc + count
            } else {
                acc
            }
        }
    });

    let criticality = if count_sum >= 10 {
        "High".to_string()
    } else if !ports.is_empty() {
        "Medium".to_string()
    } else {
        "Low".to_string()
    };

    CRITICALITY_CACHE.insert(key, criticality.clone());
    criticality
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting port vulns update from backend");

    let status = VULNS
        .update(branch, force, |data| {
            let vuln_info_json: VulnerabilityPortInfoListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(VulnerabilityPortInfoList::new_from_json(vuln_info_json))
        })
        .await?;

    // Clear caches on update
    clear_caches().await;

    match status {
        UpdateStatus::Updated => info!("Port vulns were successfully updated."),
        UpdateStatus::NotUpdated => info!("Port vulns are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the port vulns data."),
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom port vulns are in use.")
        }
    }

    Ok(status)
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::lanscan::port_info::PortInfo;
    use serial_test::serial;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            // Initialize logging or any other setup here
        });
    }

    #[tokio::test]
    #[serial]
    async fn test_get_ports() {
        setup();
        clear_caches().await;
        let ports = get_ports().await;
        assert!(!ports.is_empty(), "Ports list should not be empty");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_http_ports() {
        setup();
        clear_caches().await;
        let http_ports = get_http_ports().await;
        assert!(
            !http_ports.is_empty(),
            "HTTP ports list should not be empty"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_https_ports() {
        setup();
        clear_caches().await;
        let https_ports = get_https_ports().await;
        assert!(
            !https_ports.is_empty(),
            "HTTPS ports list should not be empty"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_description_from_port() {
        setup();
        clear_caches().await;
        let port = 80; // Replace with a port known to exist in your data
        let description = get_description_from_port(port).await;
        assert!(
            !description.is_empty(),
            "Description for port {} should not be empty",
            port
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_vulns_of_port() {
        setup();
        clear_caches().await;
        let port = 80; // Replace with a port known to have vulnerabilities
        let vulns = get_vulns_of_port(port).await;
        assert!(
            !vulns.is_empty(),
            "Vulnerabilities for port {} should not be empty",
            port
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_device_criticality() {
        setup();
        clear_caches().await;
        let port_info_list = vec![
            PortInfo {
                port: 80,
                protocol: "tcp".to_string(),
                banner: "".to_string(),
                service: "http".to_string(),
            },
            PortInfo {
                port: 22,
                protocol: "tcp".to_string(),
                banner: "".to_string(),
                service: "ssh".to_string(),
            },
        ];
        let criticality = get_device_criticality(&port_info_list).await;
        assert!(
            criticality == "Medium" || criticality == "High",
            "Criticality should be 'Medium' or 'High', got '{}'",
            criticality
        );
    }

    // New test: Modify the signature to zeros, perform an update, and check the signature changes
    #[tokio::test]
    #[serial]
    async fn test_signature_update_after_modification() {
        setup();
        clear_caches().await;
        let branch = "main";
        let signature = "00000000000000000000000000000000".to_string();
        VULNS.set_signature(signature.clone()).await;

        // Clear caches when signature changes
        clear_caches().await;

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
        let http_ports1 = get_http_ports().await;
        let https_ports1 = get_https_ports().await;

        let port = if !http_ports1.is_empty() {
            http_ports1[0]
        } else {
            80
        };

        let name1 = get_name_from_port(port).await;
        let description1 = get_description_from_port(port).await;
        let vulns1 = get_vulns_of_port(port).await;

        // Second call should use cache
        let http_ports2 = get_http_ports().await;
        let https_ports2 = get_https_ports().await;
        let name2 = get_name_from_port(port).await;
        let description2 = get_description_from_port(port).await;
        let vulns2 = get_vulns_of_port(port).await;

        // Verify results are the same
        assert_eq!(http_ports1, http_ports2, "Cached HTTP ports should match");
        assert_eq!(
            https_ports1, https_ports2,
            "Cached HTTPS ports should match"
        );
        assert_eq!(name1, name2, "Cached port name should match");
        assert_eq!(
            description1, description2,
            "Cached port description should match"
        );
        assert_eq!(vulns1, vulns2, "Cached port vulnerabilities should match");
    }
}
