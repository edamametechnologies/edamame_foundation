use crate::lanscan_vulnerability_info::*;
use serde::{Deserialize, Serialize};
use edamame_backend::lanscan_port_info_backend::PortInfoBackend;

#[derive(Debug, Serialize, Deserialize, Clone, Ord, Eq, PartialEq, PartialOrd)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub banner: String,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
}

impl Into<PortInfoBackend> for PortInfo {
    fn into(self) -> PortInfoBackend {
        PortInfoBackend {
            port: self.port,
            protocol: self.protocol,
            service: self.service,
            banner: self.banner,
            vulnerabilities: self.vulnerabilities.into_iter().map(|v| v.into()).collect(),
        }
    }
}