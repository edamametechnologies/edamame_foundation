use serde::{Deserialize, Serialize};
use crate::lanscan_port_vulns::*;

#[derive(Debug, Serialize, Deserialize, Clone, Ord, Eq, PartialEq, PartialOrd)]
pub struct PortInfo {

    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub banner: String,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
}