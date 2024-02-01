use serde::{Deserialize, Serialize};
use crate::lanscan_port_info::PortInfo;

// Simplified version for use with the backend
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceInfoBackend {
    // PII
    pub mdns_services: Vec<String>,
    // Non-PII
    pub device_vendor: String,
    // Sorted Vec would be better but we had trouble with the bridge once...
    pub open_ports: Vec<PortInfo>,
}