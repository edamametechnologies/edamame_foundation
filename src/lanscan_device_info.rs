use crate::lanscan_port_info::*;
use crate::lanscan_vulnerability_info::*;
use chrono::{DateTime, Utc};
use edamame_backend::lanscan_device_info_backend::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::trace;

pub static DEVICE_ACTIVITY_TIMEOUT: i64 = 900;

// We should really use HashSets instead of Vec, but we don't in order to make it more usable with FFI
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceInfo {
    // PII
    pub ip_address: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: String,
    pub mac_addresses: Vec<String>,
    pub hostname: String,
    pub custom_name: String,
    pub mdns_services: Vec<String>,
    // Non-PII
    pub os_name: String,
    pub os_version: String,
    pub device_vendor: String,
    // Vendor related vulnerabilities
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    // Sorted Vec would be better but had trouble with the bridge once...
    pub open_ports: Vec<PortInfo>,
    // Device state
    // Sorted Vec would be better but had trouble with the bridge once...
    pub dismissed_ports: Vec<u16>,
    pub last_seen: DateTime<Utc>,
    pub active: bool,
    pub added: bool,
    pub activated: bool,
    pub deactivated: bool,
    pub no_icmp: bool,
    pub non_std_ports: bool,
    pub criticality: String,
    pub device_type: String,
}

impl DeviceInfo {
    pub fn new() -> DeviceInfo {
        DeviceInfo {
            ip_address: "".to_string(),
            ip_addresses: Vec::new(),
            mac_address: "".to_string(),
            mac_addresses: Vec::new(),
            hostname: "".to_string(),
            custom_name: "".to_string(),
            mdns_services: Vec::new(),
            os_name: "".to_string(),
            os_version: "".to_string(),
            device_vendor: "".to_string(),
            vulnerabilities: Vec::new(),
            open_ports: Vec::new(),
            dismissed_ports: Vec::new(),
            // Initialize the last detected time to UNIX_EPOCH
            last_seen: DateTime::from_timestamp(0, 0).unwrap(),
            active: false,
            added: false,
            activated: false,
            deactivated: false,
            no_icmp: false,
            non_std_ports: false,
            criticality: "Unknown".to_string(),
            device_type: "Unknown".to_string(),
        }
    }

    // Used before any query to AI assistance
    pub fn sanitized_backend_device_info(device: &DeviceInfo) -> DeviceInfoBackend {
        let mut device_backend = DeviceInfoBackend {
            mdns_services: device.mdns_services.clone(),
            device_vendor: device.device_vendor.clone(),
            // Convert the vectors using into
            vulnerabilities: device
                .vulnerabilities
                .iter()
                .map(|v| v.clone().into())
                .collect(),
            open_ports: device
                .open_ports
                .clone()
                .iter()
                .map(|p| p.clone().into())
                .collect(),
        };

        // mDNS instances can be prefixed by the device's serial, mac, ip address.
        // We keep only the part from _xxx._yyy.local onwards
        let re = Regex::new(r".*?(_.*?\.local)").unwrap();

        let mut mdns_services_sanitized = Vec::new();
        for mdns_service in device_backend.mdns_services.iter() {
            // Replace the matched pattern with the first captured group, which is _xxx._yyy.local
            let sanitized = re.replace(mdns_service, "$1").to_string();
            mdns_services_sanitized.push(sanitized);
        }
        device_backend.mdns_services = mdns_services_sanitized;

        // Sort the entries to make sure they are always in the same order
        device_backend.mdns_services.sort();
        // The sanitization can create duplicates
        device_backend.mdns_services.dedup();
        device_backend
            .open_ports
            .sort_by(|a, b| a.port.cmp(&b.port));
        device_backend
            .vulnerabilities
            .sort_by(|a, b| a.name.cmp(&b.name));

        device_backend
    }

    pub fn sanitized_backend_device_key(&self) -> String {
        let sanitized_device = DeviceInfo::sanitized_backend_device_info(self);
        format!(
            "{}{}{}{}",
            sanitized_device.device_vendor,
            sanitized_device.mdns_services.join(""),
            sanitized_device.vulnerabilities.len(),
            sanitized_device.open_ports.len()
        )
    }

    // Combine the devices based on the hostname or IP address
    pub fn merge_vec(devices: &mut Vec<DeviceInfo>, new_devices: &Vec<DeviceInfo>) {
        for new_device in new_devices {
            let mut found = false;

            // If the new device information is not recent, skip it
            if new_device.last_seen
                < Utc::now() - chrono::Duration::seconds(DEVICE_ACTIVITY_TIMEOUT)
            {
                trace!(
                    "Skipping device {} as it is not recent",
                    new_device.ip_address
                );
                continue;
            }

            for device in devices.iter_mut() {
                // If the hostname matches => device has been seen before and possibly has a different IP address
                // or if the IP address matches => device has been seen before and possibly has a different hostname
                // Note that devices can have multiple IP addresses and one unique hostname
                if (!new_device.hostname.is_empty()
                    && !device.hostname.is_empty()
                    && device.hostname == new_device.hostname)
                    || (!new_device.ip_address.is_empty()
                        && !device.ip_address.is_empty()
                        && (new_device.ip_address == device.ip_address))
                {
                    // Merge the devices
                    DeviceInfo::merge(device, new_device);
                    found = true;
                    break;
                }
            }

            // If no match was found, add the new device
            if !found {
                devices.push(new_device.clone());
            }
        }
    }

    pub fn merge(device: &mut DeviceInfo, new_device: &DeviceInfo) {
        // Priority to the first device
        if device.ip_address.is_empty() {
            device.ip_address.clone_from(&new_device.ip_address);
        }
        if device.mac_address.is_empty() {
            device.mac_address.clone_from(&new_device.mac_address);
        }

        // Merge the ip addresses
        if !new_device.ip_addresses.is_empty() {
            device.ip_addresses.extend(new_device.ip_addresses.clone());
            // Deduplicate
            device.ip_addresses.sort();
            device.ip_addresses.dedup();
        }

        // Merge the MAC addresses
        if !new_device.mac_addresses.is_empty() {
            device
                .mac_addresses
                .extend(new_device.mac_addresses.clone());
            // Deduplicate
            device.mac_addresses.sort();
            device.mac_addresses.dedup();
        }

        // Allow fields to be updated
        if !new_device.hostname.is_empty() {
            device.hostname.clone_from(&new_device.hostname);
        }

        if !new_device.custom_name.is_empty() {
            device.custom_name.clone_from(&new_device.custom_name);
        }

        if !new_device.os_name.is_empty() {
            device.os_name.clone_from(&new_device.os_name);
        }

        if !new_device.os_version.is_empty() {
            device.os_version.clone_from(&new_device.os_version);
        }

        // Merge open ports
        if !new_device.open_ports.is_empty() {
            // We need to do it manually as the services or banners might be different as it can include timestamps
            for new_port in new_device.open_ports.iter() {
                let mut found = false;
                for existing_port in device.open_ports.iter_mut() {
                    if existing_port.port == new_port.port {
                        // Use the latest info
                        *existing_port = new_port.clone();
                        found = true;
                        break;
                    }
                }
                // If no match was found, add the new port
                if !found {
                    device.open_ports.push(new_port.clone());
                }
            }

            // Sort the ports - Sorted Vec would be better but had trouble with the bridge once...
            device.open_ports.sort_by(|a, b| a.port.cmp(&b.port));
        }

        // Merge mDNS services
        if !new_device.mdns_services.is_empty() {
            device
                .mdns_services
                .extend(new_device.mdns_services.clone());

            // Deduplicate
            device.mdns_services.sort();
            device.mdns_services.dedup();
        }

        // Remove entries that are the suffix of another entry
        // For example, if we have _xxx._apple-mobdev2._tcp.local and _apple-mobdev2._tcp.local, we remove _apple-mobdev2._tcp.local
        let mut mdns_services_cleaned = Vec::new();
        for mdns_service in device.mdns_services.iter() {
            let mut found = false;
            for mdns_service2 in device.mdns_services.iter() {
                if mdns_service != mdns_service2 && mdns_service2.ends_with(mdns_service) {
                    found = true;
                    break;
                }
            }
            if !found {
                mdns_services_cleaned.push(mdns_service.clone());
            }
        }

        device.mdns_services = mdns_services_cleaned;

        // Update the last detected time and highest criticality
        if device.last_seen < new_device.last_seen {
            device.last_seen = new_device.last_seen;
        }

        // Update the flags
        // Or
        device.active = device.active || new_device.active;
        device.non_std_ports = device.non_std_ports || new_device.non_std_ports;
        device.added = device.added || new_device.added;
        device.activated = device.activated || new_device.activated;
        device.deactivated = device.deactivated || new_device.deactivated;
        device.no_icmp = device.no_icmp || new_device.no_icmp;

        // Dynamic fields - use the latest if valid (not unknown)
        // Always update device type
        if new_device.device_type != "Unknown" {
            device.device_type.clone_from(&new_device.device_type);
        }

        // Always update device vendor
        if !new_device.device_vendor.is_empty() {
            device.device_vendor.clone_from(&new_device.device_vendor);
        }

        // Always update device criticality
        if new_device.criticality != "Unknown" {
            device.criticality.clone_from(&new_device.criticality);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_merge_devices_last_seen_updated() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.2".to_string();
        device2.hostname = "device1".to_string(); // same hostname as device1
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    #[test]
    fn test_merge_devices_last_seen_not_updated() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.2".to_string();
        device2.hostname = "device1".to_string(); // same hostname as device1
        device2.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].last_seen, device1.last_seen); // last_seen should remain the more recent value
    }

    #[test]
    fn test_add_new_device() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.2".to_string();
        device2.hostname = "device2".to_string(); // different hostname
        device2.last_seen = Utc::now() - Duration::seconds(300); // 5 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 2);
        assert_eq!(devices[1].ip_address, device2.ip_address); // new device should be added
    }

    #[test]
    fn test_merge_devices_with_empty_last_seen() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.hostname = "device1".to_string();
        device1.last_seen = DateTime::from_timestamp(0, 0).unwrap(); // initial last_seen

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.1".to_string();
        device2.hostname = "device1".to_string(); // same hostname and IP
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }
}
