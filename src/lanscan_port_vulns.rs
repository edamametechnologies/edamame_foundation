use crate::cloud_model::*;
use crate::lanscan_port_info::*;
use crate::lanscan_port_vulns_db::*;
use crate::lanscan_vulnerability_info::*;
use crate::rwlock::CustomRwLock;
use anyhow::{Context, Result};
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use tracing::info;

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

pub struct VulnerabilityPortInfoList {
    pub date: String,
    pub signature: String,
    pub port_vulns: DashMap<u16, VulnerabilityPortInfo>,
    pub http_ports: DashMap<u16, VulnerabilityPortInfo>,
    pub https_ports: DashMap<u16, VulnerabilityPortInfo>,
}

impl VulnerabilityPortInfoList {
    pub fn new_from_json(vuln_info: VulnerabilityPortInfoListJSON) -> Self {
        info!("Loading port info list from JSON");

        let port_vulns = DashMap::new();
        let http_ports = DashMap::new();
        let https_ports = DashMap::new();

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
    pub static ref VULNS: CustomRwLock<CloudModel<VulnerabilityPortInfoList>> = {
        let model = CloudModel::initialize(PORT_VULNS_NAME.to_string(), PORT_VULNS, |data| {
            let vuln_info_json: VulnerabilityPortInfoListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(VulnerabilityPortInfoList::new_from_json(vuln_info_json))
        })
        .expect("Failed to initialize CloudModel");
        CustomRwLock::new(model)
    };
}

pub async fn get_ports() -> Vec<u16> {
    let vulns_lock = VULNS.read().await;
    let ports = vulns_lock
        .data
        .read()
        .await
        .port_vulns
        .iter()
        .map(|entry| *entry.key())
        .collect();
    ports
}

pub fn get_deep_ports() -> Vec<u16> {
    (0..65535).collect()
}

pub async fn get_description_from_port(port: u16) -> String {
    let vulns_lock = VULNS.read().await;
    let description = vulns_lock
        .data
        .read()
        .await
        .port_vulns
        .get(&port)
        .map_or_else(|| "".to_string(), |port_info| port_info.description.clone());
    description
}

pub async fn get_name_from_port(port: u16) -> String {
    let vulns_lock = VULNS.read().await;
    let name = vulns_lock
        .data
        .read()
        .await
        .port_vulns
        .get(&port)
        .map_or_else(|| "".to_string(), |port_info| port_info.name.clone());
    name
}

pub async fn get_http_ports() -> Vec<u16> {
    let vulns_lock = VULNS.read().await;
    let http_ports = vulns_lock
        .data
        .read()
        .await
        .http_ports
        .iter()
        .map(|entry| *entry.key())
        .collect();
    http_ports
}

pub async fn get_https_ports() -> Vec<u16> {
    let vulns_lock = VULNS.read().await;
    let https_ports = vulns_lock
        .data
        .read()
        .await
        .https_ports
        .iter()
        .map(|entry| *entry.key())
        .collect();
    https_ports
}

pub async fn get_vulns_of_port(port: u16) -> Vec<VulnerabilityInfo> {
    let vulns_lock = VULNS.read().await;
    let mut vulnerabilities = vulns_lock
        .data
        .read()
        .await
        .port_vulns
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
    // Acquire the necessary locks before the closure
    let vulns_lock = VULNS.read().await;
    let data_lock = vulns_lock.data.read().await;

    // Use the data inside the closure without any await
    let count_sum = port_info_list.iter().fold(0, |acc, port_info| {
        let known_port_info = data_lock.port_vulns.get(&port_info.port);
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

    let vulns_lock = VULNS.read().await;
    let status = vulns_lock
        .update(branch, force, |data| {
            let vuln_info_json: VulnerabilityPortInfoListJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            Ok(VulnerabilityPortInfoList::new_from_json(vuln_info_json))
        })
        .await?;
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

        // Acquire a write lock to modify the signature
        {
            let vulns_write = VULNS.write().await;
            let mut data_write = vulns_write.data.write().await;

            // Modify the signature to a string of zeros
            data_write.set_signature("00000000000000000000000000000000".to_string());
        }

        // Perform the update
        let status = update(branch, false).await.expect("Update failed");

        // Check that the update was performed
        assert_eq!(
            status,
            UpdateStatus::Updated,
            "Expected the update to be performed"
        );

        // Check that the signature is no longer zeros
        let current_signature = VULNS.read().await.data.read().await.get_signature();
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
        let original_signature = VULNS.read().await.data.read().await.get_signature();

        // Attempt to perform an update from a nonexistent branch
        let result = update(branch, false).await;

        // The update should fail
        assert!(result.is_err(), "Update should have failed");

        // Check that the signature has not changed
        let current_signature = VULNS.read().await.data.read().await.get_signature();
        assert_eq!(
            current_signature, original_signature,
            "Signature should not have changed after failed update"
        );
    }
}
