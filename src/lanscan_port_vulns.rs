use crate::lanscan_port_info::*;
use crate::lanscan_port_vulns_db::*;
use crate::lanscan_vulnerability_info::*;
use crate::update::*;
use dashmap::DashMap;
use lazy_static::lazy_static;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::RwLock;
use std::time::Duration;
use tracing::{error, info, trace, warn};

const PORT_VULNS_REPO: &str = "https://raw.githubusercontent.com/edamametechnologies/threatmodels";
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

pub struct VulnerabilityPortInfoList {
    pub date: RwLock<String>,
    pub signature: RwLock<String>,
    pub port_vulns: DashMap<u16, VulnerabilityPortInfo>,
    pub http_ports: DashMap<u16, VulnerabilityPortInfo>,
    pub https_ports: DashMap<u16, VulnerabilityPortInfo>,
}

impl VulnerabilityPortInfoList {
    pub fn new_from_json(vuln_info: &VulnerabilityPortInfoListJSON) -> Self {
        info!("Loading port info list from JSON");

        let port_vulns = DashMap::new();
        let http_ports = DashMap::new();
        let https_ports = DashMap::new();

        for port_info in &vuln_info.vulnerabilities {
            if port_info.protocol == "HTTP" {
                http_ports.insert(port_info.port, port_info.clone());
            } else if port_info.protocol == "HTTPS" {
                https_ports.insert(port_info.port, port_info.clone());
            }
            port_vulns.insert(port_info.port, port_info.clone());
        }

        info!(
            "Loaded {} ports, {} HTTP ports, {} HTTPS ports",
            port_vulns.len(),
            http_ports.len(),
            https_ports.len()
        );

        VulnerabilityPortInfoList {
            date: RwLock::new(vuln_info.date.clone()),
            signature: RwLock::new(vuln_info.signature.clone()),
            port_vulns,
            http_ports,
            https_ports,
        }
    }
}

lazy_static! {
    pub static ref VULNS: VulnerabilityPortInfoList = {
        let vuln_info: VulnerabilityPortInfoListJSON = serde_json::from_str(PORT_VULNS).unwrap();
        VulnerabilityPortInfoList::new_from_json(&vuln_info)
    };
}

pub fn get_ports() -> Vec<u16> {
    trace!("Accessing VULNS - start");
    let ports = VULNS.port_vulns.iter().map(|entry| *entry.key()).collect();
    trace!("Accessing VULNS - end");
    ports
}

pub fn get_deep_ports() -> Vec<u16> {
    (0..65535).collect()
}

pub fn get_description_from_port(port: u16) -> String {
    trace!("Accessing VULNS - start");
    let description = VULNS
        .port_vulns
        .get(&port)
        .map_or("".to_string(), |port_info| port_info.description.clone());
    trace!("Accessing VULNS - end");
    description
}

pub fn get_http_ports() -> Vec<u16> {
    trace!("Accessing VULNS - start");
    let http_ports = VULNS.http_ports.iter().map(|entry| *entry.key()).collect();
    trace!("Accessing VULNS - end");
    http_ports
}

pub fn get_https_ports() -> Vec<u16> {
    trace!("Accessing VULNS - start");
    let https_ports = VULNS.https_ports.iter().map(|entry| *entry.key()).collect();
    trace!("Accessing VULNS - end");
    https_ports
}

pub fn get_vulns_of_port(port: u16) -> Vec<VulnerabilityInfo> {
    trace!("Accessing VULNS - start");
    let vulnerabilities = VULNS
        .port_vulns
        .get(&port)
        .map_or(Vec::new(), |port_info| port_info.vulnerabilities.clone());
    trace!("Accessing VULNS - end");
    vulnerabilities
}

pub fn get_vulns_names_of_port(port: u16) -> Vec<String> {
    let vulns = get_vulns_of_port(port);
    vulns.iter().map(|vuln| vuln.name.clone()).collect()
}

pub fn get_device_criticality(port_info_list: &[PortInfo]) -> String {
    let count_sum = port_info_list.iter().fold(0, |acc, port_info| {
        if let Some(known_port_info) = VULNS.port_vulns.get(&port_info.port) {
            acc + known_port_info.count
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

pub async fn update(branch: &str) -> Result<UpdateStatus, Box<dyn Error>> {
    info!("Starting port vulns update from backend");

    let mut status = UpdateStatus::NotUpdated;

    let url = format!("{}/{}/{}", PORT_VULNS_REPO, branch, PORT_VULNS_NAME);

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
                let json: VulnerabilityPortInfoListJSON = match res.text().await {
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

                // Clear the existing entries
                VULNS.port_vulns.clear();
                VULNS.http_ports.clear();
                VULNS.https_ports.clear();

                // Insert the new data
                for (port, info) in json
                    .vulnerabilities
                    .iter()
                    .map(|info| (info.port, info.clone()))
                {
                    VULNS.port_vulns.insert(port, info.clone());
                    if info.protocol == "HTTP" {
                        VULNS.http_ports.insert(port, info.clone());
                    } else if info.protocol == "HTTPS" {
                        VULNS.https_ports.insert(port, info);
                    }
                }

                // Update the metadata
                {
                    let mut date = VULNS.date.write().unwrap();
                    *date = json.date.clone();
                }
                {
                    let mut signature = VULNS.signature.write().unwrap();
                    *signature = json.signature.clone();
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
