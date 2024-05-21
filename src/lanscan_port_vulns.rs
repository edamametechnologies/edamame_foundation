use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info, trace, warn};

use crate::lanscan_port_info::*;
use crate::lanscan_port_vulns_db::*;
use crate::lanscan_vulnerability_info::*;
use crate::update::*;

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
    pub date: String,
    pub signature: String,
    pub port_vulns: HashMap<u16, VulnerabilityPortInfo>,
    pub http_ports: HashMap<u16, VulnerabilityPortInfo>,
    pub https_ports: HashMap<u16, VulnerabilityPortInfo>,
}

impl VulnerabilityPortInfoList {
    pub fn new_from_json(vuln_info: &VulnerabilityPortInfoListJSON) -> Self {
        info!("Loading port info list from JSON");
        let port_vulns_list = vuln_info.vulnerabilities.clone();
        let mut port_vulns = HashMap::new();
        let mut http_ports = HashMap::new();
        let mut https_ports = HashMap::new();

        for port_info in port_vulns_list {
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
            date: vuln_info.date.clone(),
            signature: vuln_info.signature.clone(),
            port_vulns,
            http_ports,
            https_ports,
        }
    }
}

pub static VULNS: Lazy<Mutex<VulnerabilityPortInfoList>> = Lazy::new(|| {
    let vuln_info: VulnerabilityPortInfoListJSON = serde_json::from_str(PORT_VULNS).unwrap();
    let vulns = VulnerabilityPortInfoList::new_from_json(&vuln_info);
    Mutex::new(vulns)
});

pub async fn get_ports() -> Vec<u16> {
    trace!("Locking VULNS - start");
    let vulns = VULNS.lock().await;
    trace!("Locking VULNS - end");
    vulns.port_vulns.keys().cloned().collect()
}

pub async fn get_deep_ports() -> Vec<u16> {
    (0..65535).collect()
}

pub async fn get_description_from_port(port: u16) -> String {
    trace!("Locking VULNS - start");
    let vulns = VULNS.lock().await;
    trace!("Locking VULNS - end");
    vulns
        .port_vulns
        .get(&port)
        .map_or("".to_string(), |port_info| port_info.description.clone())
}

pub async fn get_http_ports() -> Vec<u16> {
    trace!("Locking VULNS - start");
    let vulns = VULNS.lock().await;
    trace!("Locking VULNS - end");
    vulns.http_ports.keys().cloned().collect()
}

pub async fn get_https_ports() -> Vec<u16> {
    trace!("Locking VULNS - start");
    let vulns = VULNS.lock().await;
    trace!("Locking VULNS - end");
    vulns.https_ports.keys().cloned().collect()
}

pub async fn get_vulns_of_port(port: u16) -> Vec<VulnerabilityInfo> {
    trace!("Locking VULNS - start");
    let vulns = VULNS.lock().await;
    trace!("Locking VULNS - end");
    vulns
        .port_vulns
        .get(&port)
        .map_or(Vec::new(), |port_info| port_info.vulnerabilities.clone())
}

pub async fn get_device_criticality(port_info_list: &Vec<PortInfo>) -> String {
    let vulns = VULNS.lock().await;

    // Compute the sum of vulnerabilities count in the port info list
    let count_sum = port_info_list.iter().fold(0, |acc, port_info| {
        if let Some(known_port_info) = vulns.port_vulns.get(&port_info.port) {
            acc + known_port_info.count
        } else {
            acc
        }
    });

    // More than 10 vulnerabilities is high, at least one port open is medium, otherwise low
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

    // Create a client with a long timeout as the file can be large
    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;

    // Use the client to make a request
    let response = client.get(&url).send().await;
    match response {
        Ok(res) => {
            if res.status().is_success() {
                info!("Model transfer complete");
                // Perform the transfer and decode in 2 steps in order to catch format errors
                let json: VulnerabilityPortInfoListJSON = match res.text().await {
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
                *locked_vulns = VulnerabilityPortInfoList::new_from_json(&json);
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
