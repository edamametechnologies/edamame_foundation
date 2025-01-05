use crate::lanscan_arp::is_valid_mac_address;
use crate::lanscan_ip::is_valid_ip_address;
use crate::lanscan_port_info::*;
use crate::lanscan_port_vulns::*;
use crate::lanscan_vendor_vulns::*;
use chrono::{DateTime, Utc};
use edamame_backend::lanscan_device_info_backend::*;
use edamame_backend::lanscan_port_info_backend::*;
use edamame_backend::lanscan_vulnerability_info_backend::VulnerabilityInfoBackend;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::warn;

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
        // Validate key fields of the new device
        // Check if the MAC address is valid
        if !new_device.mac_address.is_empty() {
            if !is_valid_mac_address(&new_device.mac_address) {
                warn!(
                    "Invalid MAC address: {}, ignoring new device: {:?}",
                    new_device.mac_address, new_device
                );
                return;
            }
        }

        // Check if the IP address is valid
        if !new_device.ip_address.is_empty() {
            if !is_valid_ip_address(&new_device.ip_address) {
                warn!(
                    "Invalid IP address: {}, ignoring new device: {:?}",
                    new_device.ip_address, new_device
                );
                return;
            }
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

        // Update the first seen time
        if new_device.first_seen < device.first_seen {
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
            device.deleted = new_device.deleted;
            device.last_modified = new_device.last_modified;
        }
    }

    pub fn clear(&mut self) {
        // Clear the device, only keep the main IP address, the first_seen timestamp and the last_seen timestamp
        let ip_address = self.ip_address.clone();
        let first_seen = self.first_seen;
        let last_seen = self.last_seen;
        *self = DeviceInfo::new();
        self.ip_address = ip_address.clone();
        self.ip_addresses = vec![ip_address];
        self.first_seen = first_seen;
        self.last_seen = last_seen;
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
    use chrono::{TimeZone, Utc};

    #[test]
    fn test_merge_deletion() {
        let mut device_original = DeviceInfo::new();
        device_original.ip_address = "192.168.0.10".to_string();
        device_original.deleted = false;
        device_original.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        device_original.last_modified = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device_deleting = device_original.clone();
        // Simulate a manual delete with a later last_modified
        device_deleting.deleted = true;
        device_deleting.last_modified =
            device_original.last_modified + chrono::Duration::seconds(10);

        // Merge: the second device is "fresher" and marks it deleted
        DeviceInfo::merge(&mut device_original, &device_deleting);

        assert_eq!(
            device_original.deleted, true,
            "Device should have been marked as deleted."
        );
        assert_eq!(
            device_original.last_modified, device_deleting.last_modified,
            "last_modified should match the fresher device's timestamp."
        );
    }

    #[test]
    fn test_merge_undelete() {
        let mut device_deleted = DeviceInfo::new();
        device_deleted.ip_address = "192.168.0.20".to_string();
        device_deleted.deleted = true;
        device_deleted.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 5, 0).unwrap();
        device_deleted.last_modified = Utc.with_ymd_and_hms(2023, 1, 1, 12, 5, 0).unwrap();

        // "Rescan" or updated device info that says it's not deleted
        let mut device_undeleting = device_deleted.clone();
        device_undeleting.deleted = false;
        device_undeleting.last_modified =
            device_deleted.last_modified + chrono::Duration::seconds(10);

        DeviceInfo::merge(&mut device_deleted, &device_undeleting);

        assert_eq!(
            device_deleted.deleted, false,
            "Device should have been 'undeleted' when merging from the fresher source."
        );
        assert_eq!(
            device_deleted.last_modified, device_undeleting.last_modified,
            "last_modified should match the fresher device's timestamp."
        );
    }

    #[test]
    fn test_merge_no_change_if_older() {
        // If the new device data is older, it should be ignored
        let mut device_current = DeviceInfo::new();
        device_current.ip_address = "192.168.0.30".to_string();
        device_current.deleted = false;
        device_current.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 13, 0, 0).unwrap();
        device_current.last_modified = Utc.with_ymd_and_hms(2023, 5, 1, 13, 0, 0).unwrap();

        let mut device_older = device_current.clone();
        device_older.deleted = true;
        // artificially roll back the last_modified to be older
        device_older.last_modified = device_current.last_modified - chrono::Duration::seconds(30);

        // Merge the older device
        DeviceInfo::merge(&mut device_current, &device_older);

        // The older data should NOT override the current device
        assert_eq!(
            device_current.deleted, false,
            "The device should remain not deleted because incoming data was older."
        );
    }

    #[test]
    fn test_merge_vec_multiple() {
        // Test merging multiple new devices, some overlap, some new
        let mut existing_list = vec![
            {
                let mut d = DeviceInfo::new();
                d.ip_address = "192.168.0.10".to_string();
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 0, 0).unwrap();
                d.deleted = false;
                d
            },
            {
                let mut d = DeviceInfo::new();
                d.ip_address = "192.168.0.11".to_string();
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 5, 0).unwrap();
                d.deleted = true;
                d
            },
        ];

        let new_list = vec![
            // This device has a fresher timestamp and says it's deleted
            {
                let mut d = DeviceInfo::new();
                d.ip_address = "192.168.0.10".to_string();
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 15, 0).unwrap();
                d.deleted = true;
                d
            },
            // This device is brand new
            {
                let mut d = DeviceInfo::new();
                d.ip_address = "192.168.0.12".to_string();
                d.last_modified = Utc.with_ymd_and_hms(2023, 2, 10, 9, 0, 0).unwrap();
                d.deleted = false;
                d
            },
            // This device is older info for .11 so it should not override
            {
                let mut d = DeviceInfo::new();
                d.ip_address = "192.168.0.11".to_string();
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 0, 0).unwrap(); // older
                d.deleted = false; // says undeleted, but older
                d
            },
        ];

        DeviceInfo::merge_vec(&mut existing_list, &new_list);

        // After merging, let's check the results
        // 1) 192.168.0.10 should now be deleted
        let device_10 = existing_list
            .iter()
            .find(|d| d.ip_address == "192.168.0.10")
            .unwrap();
        assert!(
            device_10.deleted,
            "192.168.0.10 should have been marked deleted from the fresher 'new_list' entry."
        );

        // 2) 192.168.0.12 should have been added
        let device_12 = existing_list
            .iter()
            .find(|d| d.ip_address == "192.168.0.12");
        assert!(
            device_12.is_some(),
            "192.168.0.12 should have been newly added."
        );

        // 3) 192.168.0.11 should remain deleted, because the new data was older
        let device_11 = existing_list
            .iter()
            .find(|d| d.ip_address == "192.168.0.11")
            .unwrap();
        assert!(
            device_11.deleted,
            "192.168.0.11 should remain deleted because incoming data was older."
        );
    }
}
