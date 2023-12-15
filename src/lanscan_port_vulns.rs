use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::Mutex;
use log::{info, trace};
use once_cell::sync::Lazy;

use crate::lanscan_types::*;
use crate::lanscan_port_vulns_db::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityInfo {
    pub name: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilityPortInfo {
    pub port: u16,
    pub name: String,
    pub description: String,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub count: u32,
    pub generated_date: String,
    pub protocol: String,
}

pub struct VulnerabilityInfoList {
    pub port_vulns: HashMap<u16, VulnerabilityPortInfo>,
    pub http_ports: HashMap<u16, VulnerabilityPortInfo>,
    pub https_ports: HashMap<u16, VulnerabilityPortInfo>,
}

impl VulnerabilityInfoList {

    pub fn new_from_str(json: &str) -> Self {
        info!("Loading port info list from JSON");
        let port_vulns_list: Vec<VulnerabilityPortInfo> = serde_json::from_str(json).unwrap();
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

        VulnerabilityInfoList {
            port_vulns,
            http_ports,
            https_ports,
        }
    }
}

pub static VULNS: Lazy<Mutex<VulnerabilityInfoList>> = Lazy::new(|| {
    let vulns = VulnerabilityInfoList::new_from_str(PORT_VULNS);
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
    vulns.port_vulns.get(&port)
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
