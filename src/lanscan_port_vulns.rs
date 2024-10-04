use crate::cloud_model::*;
use crate::lanscan_port_info::*;
use crate::lanscan_port_vulns_db::*;
use crate::lanscan_vulnerability_info::*;
use crate::rwlock::CustomRwLock;
use anyhow::{Context, Result};
use dashmap::DashMap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use tracing::{info, trace};

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
            if port_info.protocol == "HTTP" {
                http_ports.insert(port_info.port, port_info.clone());
            } else if port_info.protocol == "HTTPS" {
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
    trace!("Accessing VULNS - start");
    let vulns_lock = VULNS.read().await;
    let ports = vulns_lock
        .data
        .read()
        .await
        .port_vulns
        .iter()
        .map(|entry| *entry.key())
        .collect();
    trace!("Accessing VULNS - end");
    ports
}

pub fn get_deep_ports() -> Vec<u16> {
    (0..65535).collect()
}

pub async fn get_description_from_port(port: u16) -> String {
    trace!("Accessing VULNS - start");
    let vulns_lock = VULNS.read().await;
    let description = vulns_lock
        .data
        .read()
        .await
        .port_vulns
        .get(&port)
        .map_or_else(|| "".to_string(), |port_info| port_info.description.clone());
    trace!("Accessing VULNS - end");
    description
}

pub async fn get_http_ports() -> Vec<u16> {
    trace!("Accessing VULNS - start");
    let vulns_lock = VULNS.read().await;
    let http_ports = vulns_lock
        .data
        .read()
        .await
        .http_ports
        .iter()
        .map(|entry| *entry.key())
        .collect();
    trace!("Accessing VULNS - end");
    http_ports
}

pub async fn get_https_ports() -> Vec<u16> {
    trace!("Accessing VULNS - start");
    let vulns_lock = VULNS.read().await;
    let https_ports = vulns_lock
        .data
        .read()
        .await
        .https_ports
        .iter()
        .map(|entry| *entry.key())
        .collect();
    trace!("Accessing VULNS - end");
    https_ports
}

pub async fn get_vulns_of_port(port: u16) -> Vec<VulnerabilityInfo> {
    trace!("Accessing VULNS - start");
    let vulns_lock = VULNS.read().await;
    let mut vulnerabilities = vulns_lock
        .data
        .read()
        .await
        .port_vulns
        .get(&port)
        .map_or_else(Vec::new, |port_info| port_info.vulnerabilities.clone());
    trace!("Accessing VULNS - end");
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
