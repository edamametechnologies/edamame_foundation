use crate::lanscan_port_info::*;
use crate::lanscan_port_vulns::*;
use crate::lanscan_vendor_vulns::*;
use chrono::{DateTime, Utc};
use edamame_backend::lanscan_device_info_backend::*;
use edamame_backend::lanscan_port_info_backend::*;
use edamame_backend::lanscan_vulnerability_info_backend::VulnerabilityInfoBackend;
use regex::Regex;
use serde::{Deserialize, Serialize};

// We should really use HashSets instead of Vec, but we don't in order to make it more usable with FFI
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceInfo {
    // PII
    pub ip_address: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: String,
    pub mac_addresses: Vec<String>,
    pub hostname: String,
    pub mdns_services: Vec<String>,
    // Non-PII
    pub os_name: String,
    pub os_version: String,
    pub device_vendor: String,
    // Sorted Vec would be better but had trouble with the bridge once...
    pub open_ports: Vec<PortInfo>,
    // Below is the device state
    pub active: bool,
    pub added: bool,
    pub activated: bool,
    pub deactivated: bool,
    pub no_icmp: bool,
    pub non_std_ports: bool,
    pub criticality: String,
    pub device_type: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    // Below are user properties
    // Sorted Vec would be better but had trouble with the bridge once...
    pub dismissed_ports: Vec<u16>,
    pub custom_name: String,
    pub deleted: bool,
    pub last_modified: DateTime<Utc>,
}

impl DeviceInfo {
    pub fn new() -> DeviceInfo {
        DeviceInfo {
            ip_address: "".to_string(),
            ip_addresses: Vec::new(),
            mac_address: "".to_string(),
            mac_addresses: Vec::new(),
            hostname: "".to_string(),
            mdns_services: Vec::new(),
            os_name: "".to_string(),
            os_version: "".to_string(),
            device_vendor: "".to_string(),
            open_ports: Vec::new(),
            // Below is the device state
            active: false,
            added: false,
            activated: false,
            deactivated: false,
            no_icmp: false,
            non_std_ports: false,
            criticality: "Unknown".to_string(),
            device_type: "Unknown".to_string(),
            // Initialize the times to UNIX_EPOCH
            first_seen: DateTime::from_timestamp(0, 0).unwrap(),
            last_seen: DateTime::from_timestamp(0, 0).unwrap(),
            // Below are user properties
            dismissed_ports: Vec::new(),
            custom_name: "".to_string(),
            // Not deleted by default
            deleted: false,
            // Initialize the last time to UNIX_EPOCH
            last_modified: DateTime::from_timestamp(0, 0).unwrap(),
        }
    }

    // Used before any query to AI assistance
    pub async fn sanitized_backend_device_info(device: &DeviceInfo) -> DeviceInfoBackend {
        // Include the vulnerabilities
        let vulnerabilities: Vec<VulnerabilityInfoBackend> =
            get_vulns_of_vendor(&device.device_vendor)
                .await
                .iter()
                .map(|vuln| vuln.clone().into())
                .collect();
        let mut open_ports: Vec<PortInfoBackend> = Vec::new();
        for port in device.open_ports.iter() {
            let mut port_info: PortInfoBackend = port.clone().into();
            port_info.vulnerabilities = get_vulns_of_port(port.port)
                .await
                .iter()
                .map(|vuln| vuln.clone().into())
                .collect();
            open_ports.push(port_info);
        }

        // mDNS instances can be prefixed by the device's serial, mac, ip address.
        // We keep only the part from _xxx._yyy.local onwards
        let re = Regex::new(r".*?(_.*?\.local)").unwrap();

        let mut mdns_services = Vec::new();
        for mdns_service in device.mdns_services.iter() {
            // Replace the matched pattern with the first captured group, which is _xxx._yyy.local
            let sanitized = re.replace(mdns_service, "$1").to_string();
            mdns_services.push(sanitized);
        }
        let mut device_backend = DeviceInfoBackend {
            mdns_services,
            device_vendor: device.device_vendor.clone(),
            vulnerabilities,
            open_ports,
        };

        // Sort the entries to make sure they are always in the same order to have prompt consistency
        device_backend.mdns_services.sort();
        // The sanitization can create duplicates
        device_backend.mdns_services.dedup();
        device_backend
            .open_ports
            .sort_by(|a, b| a.port.cmp(&b.port));
        device_backend
    }

    pub async fn sanitized_backend_device_key(&self) -> String {
        let sanitized_device = DeviceInfo::sanitized_backend_device_info(self).await;
        format!(
            "{}{}{}{}",
            sanitized_device.device_vendor,
            sanitized_device.mdns_services.join(""),
            sanitized_device.vulnerabilities.len(),
            sanitized_device.open_ports.len()
        )
    }

    // Check if devices in the device list shall be merged
    fn dedup_vec(devices: &mut Vec<DeviceInfo>) {
        let mut i = 0;
        while i < devices.len() {
            let mut j = i + 1;
            while j < devices.len() {
                let (left, right) = devices.split_at_mut(j); // Split the vector at j
                let device1 = &mut left[i]; // Mutable reference to device1 from left side
                let device2 = &right[0]; // Immutable reference to device2 from right side
                let is_duplicate = (!device1.hostname.is_empty()
                    && !device2.hostname.is_empty()
                    && device1.hostname == device2.hostname)
                    || (!device1.ip_address.is_empty()
                        && !device2.ip_address.is_empty()
                        && device1.ip_address == device2.ip_address)
                    || (!device1.ip_addresses.is_empty()
                        && !device2.ip_addresses.is_empty()
                        && device1
                            .ip_addresses
                            .iter()
                            .any(|ip| device2.ip_addresses.contains(ip)));

                if is_duplicate {
                    // Merge device2 into device1
                    DeviceInfo::merge(device1, device2);
                    // Remove device2 from the list
                    devices.remove(j);
                } else {
                    j += 1;
                }
            }
            i += 1;
        }
    }

    // Combine the devices based on the hostname or IP address
    pub fn merge_vec(devices: &mut Vec<DeviceInfo>, new_devices: &Vec<DeviceInfo>) {
        // Always deduplicate the devices before merging
        DeviceInfo::dedup_vec(devices);
        let mut new_devices = new_devices.clone();
        DeviceInfo::dedup_vec(&mut new_devices);

        for new_device in new_devices {
            let mut found = false;

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
                    || (!new_device.ip_addresses.is_empty()
                        && !device.ip_addresses.is_empty()
                        && new_device
                            .ip_addresses
                            .iter()
                            .any(|ip| device.ip_addresses.contains(ip)))
                {
                    // Merge the devices
                    DeviceInfo::merge(device, &new_device);
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
        // If we receive a deleted flag with a last modified date more recent than our last modified date, we clear ourselves and flag ourselves as deleted
        if new_device.deleted && new_device.last_modified > device.last_modified {
            device.delete();
            // We don't need to merge anything
            return;
        }

        // Undelete the device if the new device last_seen is more recent than our last_modified
        if device.deleted && new_device.last_seen > device.last_modified {
            device.undelete();
            // We continue to merge
        }

        // Now we merge based on the hostname or IP address(es)

        // Use the most recent non empty ip address
        if !new_device.ip_address.is_empty() {
            if new_device.last_seen > device.last_seen || device.ip_address.is_empty() {
                device.ip_address.clone_from(&new_device.ip_address);
            }
        }

        // Merge the ip addresses
        if !new_device.ip_addresses.is_empty() {
            device.ip_addresses.extend(new_device.ip_addresses.clone());
            // Deduplicate
            device.ip_addresses.sort();
            device.ip_addresses.dedup();
        }

        // Use the most recent non empty mac address
        if !new_device.mac_address.is_empty() {
            if new_device.last_seen > device.last_seen || device.mac_address.is_empty() {
                device.mac_address.clone_from(&new_device.mac_address);
            }
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

        // Use the most recent non empty hostname
        if !new_device.hostname.is_empty() {
            if new_device.last_seen > device.last_seen || device.hostname.is_empty() {
                device.hostname.clone_from(&new_device.hostname);
            }
        }

        // Use the most recent non empty os name
        if !new_device.os_name.is_empty() {
            if new_device.last_seen > device.last_seen || device.os_name.is_empty() {
                device.os_name.clone_from(&new_device.os_name);
            }
        }

        if !new_device.os_version.is_empty() {
            if new_device.last_seen > device.last_seen || device.os_version.is_empty() {
                device.os_version.clone_from(&new_device.os_version);
            }
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

        // Update the flags
        // Or
        device.active = device.active || new_device.active;
        device.non_std_ports = device.non_std_ports || new_device.non_std_ports;
        device.added = device.added || new_device.added;
        device.activated = device.activated || new_device.activated;
        device.deactivated = device.deactivated || new_device.deactivated;
        device.no_icmp = device.no_icmp || new_device.no_icmp;

        // Dynamic fields
        // Use the most recent if valid (not unknown)
        if new_device.device_type != "Unknown" {
            if new_device.last_seen > device.last_seen || device.device_type == "Unknown" {
                device.device_type.clone_from(&new_device.device_type);
            }
        }

        // Use the most recent non empty device vendor
        if !new_device.device_vendor.is_empty() {
            if new_device.last_seen > device.last_seen || device.device_vendor.is_empty() {
                device.device_vendor.clone_from(&new_device.device_vendor);
            }
        }

        // Use the most recent if valid (not unknown)
        if new_device.criticality != "Unknown" {
            if new_device.last_seen > device.last_seen || device.criticality == "Unknown" {
                device.criticality.clone_from(&new_device.criticality);
            }
        }

        // Update the first seen time, beware of the UNIX_EPOCH
        if new_device.first_seen < device.first_seen
            && new_device.first_seen != DateTime::from_timestamp(0, 0).unwrap()
        {
            device.first_seen = new_device.first_seen;
        }

        // Update the last seen time (no need to check for UNIX_EPOCH)
        if new_device.last_seen > device.last_seen {
            device.last_seen = new_device.last_seen;
        }

        // Merge user properties based on the last modified date
        if new_device.last_modified > device.last_modified {
            device.custom_name.clone_from(&new_device.custom_name);
            device.dismissed_ports = new_device.dismissed_ports.clone();
            device.last_modified = new_device.last_modified;
        }
    }

    pub fn clear(&mut self) {
        // Clear the device, only keep the main IP address
        let ip_address = self.ip_address.clone();
        *self = DeviceInfo::new();
        self.ip_address = ip_address.clone();
        self.ip_addresses = vec![ip_address];
    }

    pub fn delete(&mut self) {
        // Clear the device
        self.clear();
        // Flag the device as deleted
        self.deleted = true;
        // Update the last modified to now
        self.last_modified = Utc::now();
    }

    pub fn undelete(&mut self) {
        // Flag the device as not deleted
        self.deleted = false;
        // Update the last modified to now
        self.last_modified = Utc::now();
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

    #[test]
    fn test_merge_devices_with_same_ip_addresses() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.193".to_string();
        device1.ip_addresses = vec!["192.168.1.194".to_string(), "192.168.1.193".to_string()];
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.193".to_string(); // overlapping IP address
        device2.ip_addresses = vec!["192.168.1.193".to_string(), "192.168.1.194".to_string()];
        device2.hostname = "device2".to_string();
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ip_address, device1.ip_address);
        assert_eq!(devices[0].ip_addresses.len(), 2);
        assert!(devices[0]
            .ip_addresses
            .contains(&"192.168.1.193".to_string()));
        assert!(devices[0]
            .ip_addresses
            .contains(&"192.168.1.194".to_string()));
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    #[test]
    fn test_merge_devices_with_partially_overlapping_ip_addresses() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.193".to_string();
        device1.ip_addresses = vec!["192.168.1.194".to_string(), "192.168.1.193".to_string()];
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.194".to_string(); // different primary IP but overlapping secondary IP
        device2.ip_addresses = vec!["192.168.1.194".to_string(), "192.168.1.193".to_string()];
        device2.hostname = "device2".to_string();
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert!(devices[0]
            .ip_addresses
            .contains(&"192.168.1.193".to_string()));
        assert!(devices[0]
            .ip_addresses
            .contains(&"192.168.1.194".to_string()));
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    #[test]
    fn test_merge_devices_with_multiple_ip_addresses() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.193".to_string();
        device1.ip_addresses = vec![
            "192.168.1.193".to_string(),
            "192.168.1.194".to_string(),
            "192.168.1.195".to_string(),
        ];
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.196".to_string();
        device2.ip_addresses = vec![
            "192.168.1.193".to_string(),
            "192.168.1.196".to_string(),
            "192.168.1.197".to_string(),
        ];
        device2.hostname = "device2".to_string();
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert!(devices[0]
            .ip_addresses
            .contains(&"192.168.1.193".to_string()));
        assert!(devices[0]
            .ip_addresses
            .contains(&"192.168.1.194".to_string()));
        assert!(devices[0]
            .ip_addresses
            .contains(&"192.168.1.195".to_string()));
        assert!(devices[0]
            .ip_addresses
            .contains(&"192.168.1.196".to_string()));
        assert!(devices[0]
            .ip_addresses
            .contains(&"192.168.1.197".to_string()));
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    #[test]
    fn test_no_merge_for_different_devices() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.193".to_string();
        device1.ip_addresses = vec!["192.168.1.193".to_string()];
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.195".to_string();
        device2.ip_addresses = vec!["192.168.1.195".to_string()];
        device2.hostname = "device2".to_string();
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].ip_address, device1.ip_address);
        assert_eq!(devices[1].ip_address, device2.ip_address);
        assert_eq!(devices[0].last_seen, device1.last_seen);
        assert_eq!(devices[1].last_seen, device2.last_seen);
    }

    #[test]
    fn test_merge_devices_with_overlapping_mdns_services() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.hostname = "device1".to_string();
        device1.mdns_services = vec![
            "_service1._tcp.local".to_string(),
            "_service2._tcp.local".to_string(),
        ];
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.2".to_string();
        device2.hostname = "device1".to_string();
        device2.mdns_services = vec![
            "_service1._tcp.local".to_string(),
            "_service3._tcp.local".to_string(),
        ];
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mdns_services.len(), 3);
        assert!(devices[0]
            .mdns_services
            .contains(&"_service1._tcp.local".to_string()));
        assert!(devices[0]
            .mdns_services
            .contains(&"_service2._tcp.local".to_string()));
        assert!(devices[0]
            .mdns_services
            .contains(&"_service3._tcp.local".to_string()));
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    #[test]
    fn test_merge_devices_with_different_hostnames_overlapping_ips() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.ip_addresses = vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()];
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.2".to_string();
        device2.ip_addresses = vec!["192.168.1.2".to_string(), "192.168.1.3".to_string()];
        device2.hostname = "device2".to_string(); // different hostname
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ip_addresses.len(), 3);
        assert!(devices[0].ip_addresses.contains(&"192.168.1.1".to_string()));
        assert!(devices[0].ip_addresses.contains(&"192.168.1.2".to_string()));
        assert!(devices[0].ip_addresses.contains(&"192.168.1.3".to_string()));
        assert_eq!(devices[0].hostname, device2.hostname);
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    #[test]
    fn test_merge_devices_with_overlapping_mac_addresses() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.mac_address = "AA:BB:CC:DD:EE:FF".to_string();
        device1.mac_addresses = vec![
            "AA:BB:CC:DD:EE:FF".to_string(),
            "FF:EE:DD:CC:BB:AA".to_string(),
        ];
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.1".to_string();
        device2.mac_address = "11:22:33:44:55:66".to_string(); // same mac address
        device2.mac_addresses = vec![
            "AA:BB:CC:DD:EE:FF".to_string(),
            "11:22:33:44:55:66".to_string(),
        ];
        device2.hostname = "device2".to_string(); // different hostname
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mac_address, device2.mac_address);
        assert_eq!(devices[0].mac_addresses.len(), 3);
        assert!(devices[0]
            .mac_addresses
            .contains(&"AA:BB:CC:DD:EE:FF".to_string()));
        assert!(devices[0]
            .mac_addresses
            .contains(&"FF:EE:DD:CC:BB:AA".to_string()));
        assert!(devices[0]
            .mac_addresses
            .contains(&"11:22:33:44:55:66".to_string()));
        assert_eq!(devices[0].hostname, device2.hostname);
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    #[test]
    fn test_merge_devices_with_non_overlapping_ports() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.hostname = "device1".to_string();
        device1.open_ports = vec![PortInfo {
            port: 80,
            service: "http".to_string(),
            banner: "Apache".to_string(),
            protocol: "tcp".to_string(),
        }];
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.2".to_string();
        device2.hostname = "device1".to_string();
        device2.open_ports = vec![PortInfo {
            port: 22,
            service: "ssh".to_string(),
            banner: "OpenSSH".to_string(),
            protocol: "tcp".to_string(),
        }];
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].open_ports.len(), 2);
        assert!(devices[0].open_ports.iter().any(|p| p.port == 80));
        assert!(devices[0].open_ports.iter().any(|p| p.port == 22));
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    #[test]
    fn test_merge_devices_with_overlapping_and_non_overlapping_ports() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.hostname = "device1".to_string();
        device1.open_ports = vec![
            PortInfo {
                port: 80,
                service: "http".to_string(),
                banner: "Apache".to_string(),
                protocol: "tcp".to_string(),
            },
            PortInfo {
                port: 443,
                service: "https".to_string(),
                banner: "Apache".to_string(),
                protocol: "tcp".to_string(),
            },
        ];
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.2".to_string();
        device2.hostname = "device1".to_string();
        device2.open_ports = vec![
            PortInfo {
                port: 80,
                service: "http".to_string(),
                banner: "Nginx".to_string(),
                protocol: "tcp".to_string(),
            }, // same port, different banner
            PortInfo {
                port: 22,
                service: "ssh".to_string(),
                banner: "OpenSSH".to_string(),
                protocol: "tcp".to_string(),
            },
        ];
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].open_ports.len(), 3);
        assert!(devices[0]
            .open_ports
            .iter()
            .any(|p| p.port == 80 && p.banner == "Nginx"));
        assert!(devices[0].open_ports.iter().any(|p| p.port == 443));
        assert!(devices[0].open_ports.iter().any(|p| p.port == 22));
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    #[test]
    fn test_merge_devices_with_different_criticalities() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.hostname = "device1".to_string();
        device1.criticality = "Low".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.2".to_string();
        device2.hostname = "device1".to_string();
        device2.criticality = "High".to_string();
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].criticality, "High"); // criticality should be updated to the more recent value
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    #[test]
    fn test_merge_devices_with_different_device_types() {
        let mut device1 = DeviceInfo::new();
        device1.ip_address = "192.168.1.1".to_string();
        device1.hostname = "device1".to_string();
        device1.device_type = "Laptop".to_string();
        device1.last_seen = Utc::now() - Duration::seconds(1800); // 30 minutes ago

        let mut device2 = DeviceInfo::new();
        device2.ip_address = "192.168.1.2".to_string();
        device2.hostname = "device1".to_string();
        device2.device_type = "Smartphone".to_string();
        device2.last_seen = Utc::now() - Duration::seconds(600); // 10 minutes ago

        let mut devices = vec![device1.clone()];
        let new_devices = vec![device2.clone()];

        DeviceInfo::merge_vec(&mut devices, &new_devices);

        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_type, "Smartphone"); // device_type should be updated to the more recent value
        assert_eq!(devices[0].last_seen, device2.last_seen); // last_seen should be updated to the more recent value
    }

    // Test if a new device with a delete flag result into the same device ip address and all the other fields are cleared
    #[test]
    fn test_delete_flag() {
        let mut device = DeviceInfo::new();
        device.ip_address = "192.168.1.1".to_string();
        device.ip_addresses = vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()];
        device.hostname = "device1".to_string();
        device.mac_address = "AA:BB:CC:DD:EE:FF".to_string();
        device.mac_addresses = vec![
            "AA:BB:CC:DD:EE:FF".to_string(),
            "FF:EE:DD:CC:BB:AA".to_string(),
        ];
        device.deleted = true;
        device.clear();
        assert_eq!(device.ip_address, "192.168.1.1".to_string());
        assert_eq!(device.ip_addresses.len(), 1);
        assert!(device.ip_addresses.contains(&"192.168.1.1".to_string()));
        assert_eq!(device.hostname, "");
        assert_eq!(device.mac_address, "");
        assert_eq!(device.mac_addresses.len(), 0);
    }

    // Test if a new device with a last modified date more recent than our last modified date properly deletes us
    #[test]
    fn test_delete_with_last_modified() {
        let mut new_device = DeviceInfo::new();
        new_device.ip_address = "192.168.1.1".to_string();
        new_device.last_modified = Utc::now() - Duration::seconds(600); // 5 minutes ago
        new_device.deleted = true;

        let mut device = DeviceInfo::new();
        device.ip_address = "192.168.1.1".to_string();
        device.last_seen = Utc::now() - Duration::seconds(30); // 30 minutes ago
        device.last_modified = Utc::now() - Duration::seconds(1800); // 30 minutes ago
        device.deleted = false;

        DeviceInfo::merge(&mut device, &new_device);

        assert!(device.deleted);
        assert!(device.last_modified > new_device.last_modified);
    }

    // Test if a last modified date of a new device properly undelete a device
    #[test]
    fn test_undelete_with_last_seen() {
        let mut new_device = DeviceInfo::new();
        new_device.ip_address = "192.168.1.1".to_string();
        new_device.last_seen = Utc::now() - Duration::seconds(600); // 5 minutes ago
        new_device.last_modified = Utc::now() - Duration::seconds(1800); // 30 minutes ago
        new_device.deleted = false;

        let mut device = DeviceInfo::new();
        device.ip_address = "192.168.1.1".to_string();
        device.last_modified = Utc::now() - Duration::seconds(1800); // 30 minutes ago
        device.deleted = true;
        DeviceInfo::merge(&mut device, &new_device);

        assert!(!device.deleted);
        assert!(device.last_modified > new_device.last_modified);
    }
}
