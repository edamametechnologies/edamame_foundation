use crate::cloud_model::*;
use crate::lanscan_port_info::*;
use crate::lanscan_port_vulns_db::*;
use crate::lanscan_vulnerability_info::*;
use anyhow::{Context, Result};
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
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
    pub port_vulns: Arc<DashMap<u16, VulnerabilityPortInfo>>,
    pub http_ports: Arc<DashMap<u16, VulnerabilityPortInfo>>,
    pub https_ports: Arc<DashMap<u16, VulnerabilityPortInfo>>,
}

impl VulnerabilityPortInfoList {
    pub fn new_from_json(vuln_info: VulnerabilityPortInfoListJSON) -> Self {
        info!("Loading port info list from JSON");

        let port_vulns = Arc::new(DashMap::new());
        let http_ports = Arc::new(DashMap::new());
        let https_ports = Arc::new(DashMap::new());

        for port_info in vuln_info.vulnerabilities {
            if port_info.protocol == "http" {
                http_ports.insert(port_info.port, port_info.clone());
            } else if port_info.protocol == "https" {
                https_ports.insert(port_info.port, port_info.clone());
            }
            port_vulns.insert(port_info.port, port_info);
        }

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
    let ports_map = VULNS.data.read().await.port_vulns.clone();
    ports_map
        .get(&port)
        .map_or_else(|| "".to_string(), |port_info| port_info.description.clone())
}

pub async fn get_name_from_port(port: u16) -> String {
    let ports_map = VULNS.data.read().await.port_vulns.clone();
    ports_map
        .get(&port)
        .map_or_else(|| "".to_string(), |port_info| port_info.name.clone())
}

pub async fn get_http_ports() -> Vec<u16> {
    let http_ports_map = VULNS.data.read().await.http_ports.clone();
    http_ports_map.iter().map(|entry| *entry.key()).collect()
}

pub async fn get_https_ports() -> Vec<u16> {
    let https_ports_map = VULNS.data.read().await.https_ports.clone();
    https_ports_map.iter().map(|entry| *entry.key()).collect()
}

pub async fn get_vulns_of_port(port: u16) -> Vec<VulnerabilityInfo> {
    let ports_map = VULNS.data.read().await.port_vulns.clone();
    let mut vulnerabilities = ports_map
        .get(&port)
        .map_or_else(Vec::new, |port_info| port_info.vulnerabilities.clone());
    vulnerabilities.sort_by(|a, b| b.name.cmp(&a.name));
    vulnerabilities
}

pub async fn get_vulns_names_of_port(port: u16) -> Vec<String> {
    let vulns = get_vulns_of_port(port).await;
    vulns.iter().map(|vuln| vuln.name.clone()).collect()
}

pub async fn get_device_criticality(port_info_list: &[PortInfo]) -> String {
    // Clone the Arc to avoid holding the lock during iteration
    let ports_map = VULNS.data.read().await.port_vulns.clone();

    // Use the cloned Arc without any await
    let count_sum = port_info_list.iter().fold(0, |acc, port_info| {
        let known_port_info = ports_map.get(&port_info.port);
        if let Some(info) = known_port_info {
            acc + info.count
        } else {
            acc
        }
    });

    if count_sum >= 10 {
        "High".to_string()
    } else if !port_info_list.is_empty() {
        "Medium".to_string()
    } else {
        "Low".to_string()
    }
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
    use crate::lanscan_port_info::PortInfo;
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
        let ports = get_ports().await;
        assert!(!ports.is_empty(), "Ports list should not be empty");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_http_ports() {
        setup();
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
        let branch = "main";
        let signature = "00000000000000000000000000000000".to_string();
        VULNS.set_signature(signature.clone()).await;
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
