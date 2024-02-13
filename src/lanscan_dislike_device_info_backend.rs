use serde::{Deserialize, Serialize};
use crate::lanscan_port_info::PortInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DislikeDeviceInfoBackend {
    pub device_type: String,
    pub open_ports: Vec<PortInfo>,
    pub mdns_services: Vec<String>,
    pub device_vendor: String,
    pub hostname: String,
    /// User comment
    pub note: String,
}