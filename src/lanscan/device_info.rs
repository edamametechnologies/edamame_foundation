use crate::lanscan::port_info::*;
use crate::lanscan::port_vulns::*;
use crate::lanscan::vendor_vulns::*;
use chrono::{DateTime, Utc};
use edamame_backend::lanscan_device_info_backend::*;
use edamame_backend::lanscan_port_info_backend::*;
use edamame_backend::lanscan_vulnerability_info_backend::VulnerabilityInfoBackend;
use macaddr::MacAddr6;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, warn};

// We should really use HashSets instead of Vec, but we don't in order to make it more usable with FFI
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceInfo {
    // PII
    // Main address is IPv4 or IPv6
    ip_address: IpAddr,
    pub ip_addresses_v4: Vec<Ipv4Addr>,
    pub ip_addresses_v6: Vec<Ipv6Addr>,
    mac_address: Option<MacAddr6>,
    pub mac_addresses: Vec<MacAddr6>,
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
    // Origin tracking for community sharing
    pub origin_ip: String, // IP of the device that first discovered this device
    pub origin_network: String, // Network identifier of where the device was first discovered
    // Below are user properties
    // Sorted Vec would be better but had trouble with the bridge once...
    pub dismissed_ports: Vec<u16>,
    pub custom_name: String,
    pub deleted: bool,
    pub last_modified: DateTime<Utc>,
    // Below are internal properties (not serialized)
    // Flag to track devices seen by direct scanning
    #[serde(skip)]
    pub is_local: bool,
}

impl DeviceInfo {
    pub fn new(ip_address: Option<IpAddr>) -> DeviceInfo {
        let ip_address = ip_address.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let ip_addresses_v4 = match ip_address {
            IpAddr::V4(ip) => vec![ip],
            IpAddr::V6(_) => vec![],
        };
        let ip_addresses_v6 = match ip_address {
            IpAddr::V4(_) => vec![],
            IpAddr::V6(ip) => vec![ip],
        };
        DeviceInfo {
            ip_address: ip_address,
            ip_addresses_v4: ip_addresses_v4,
            ip_addresses_v6: ip_addresses_v6,
            mac_address: None,
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
            first_seen: DateTime::<Utc>::from(std::time::UNIX_EPOCH),
            last_seen: DateTime::<Utc>::from(std::time::UNIX_EPOCH),
            // Origin tracking for community sharing
            origin_ip: "".to_string(), // IP of the device that first discovered this device
            origin_network: "".to_string(), // Network identifier of where the device was first discovered
            // Below are user properties
            dismissed_ports: Vec::new(),
            custom_name: "".to_string(),
            // Not deleted by default
            deleted: false,
            // Initialize the last time to UNIX_EPOCH
            last_modified: DateTime::<Utc>::from(std::time::UNIX_EPOCH),
            // Below are internal properties (not serialized)
            // Not local by default
            is_local: false,
        }
    }

    pub fn get_ip_address(&self) -> IpAddr {
        self.ip_address
    }

    pub fn set_ip_address(
        &mut self,
        ip_address: IpAddr,
        ip_addresses_v4: Vec<Ipv4Addr>,
        ip_addresses_v6: Vec<Ipv6Addr>,
    ) {
        // Ignore unspecified ip addresses
        if ip_address.is_unspecified() {
            return;
        }
        // Add the IP address
        match self.ip_address {
            IpAddr::V4(ip) => {
                self.ip_addresses_v4.push(ip);
            }
            IpAddr::V6(ip) => {
                self.ip_addresses_v6.push(ip);
            }
        }
        self.add_ip_addresses(ip_addresses_v4, ip_addresses_v6);
    }

    pub fn add_ip_addresses(
        &mut self,
        ip_addresses_v4: Vec<Ipv4Addr>,
        ip_addresses_v6: Vec<Ipv6Addr>,
    ) {
        // Add the provided vectors
        self.ip_addresses_v4.extend(ip_addresses_v4);
        // Sort and deduplicate
        self.ip_addresses_v4.sort();
        self.ip_addresses_v4.dedup();

        self.ip_addresses_v6.extend(ip_addresses_v6);
        // Sort and deduplicate
        self.ip_addresses_v6.sort();
        self.ip_addresses_v6.dedup();
    }

    pub fn get_mac_address(&self) -> Option<MacAddr6> {
        self.mac_address
    }

    pub fn set_mac_address(&mut self, mac_address: MacAddr6, mac_addresses: Vec<MacAddr6>) {
        // Ignore nil mac addresses
        if mac_address.is_nil() {
            return;
        }
        self.mac_address = Some(mac_address);
        self.mac_addresses.push(mac_address);
        self.mac_addresses.extend(mac_addresses);
        // Sort and deduplicate
        self.mac_addresses.sort();
        self.mac_addresses.dedup();
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

    // Check if devices in the device list shall be merged based on
    //  (1) same (non empty) hostname
    //  (2) same (non empty) IP v4
    //  (3) same (non empty) IP v6
    fn dedup_vec(devices: &mut Vec<DeviceInfo>) {
        let mut i = 0;
        while i < devices.len() {
            let mut j = i + 1;
            while j < devices.len() {
                let (left, right) = devices.split_at_mut(j); // Split the vector at j
                let device1 = &mut left[i]; // Mutable reference to device1 from left side
                let device2 = &mut right[0]; // Mutable reference to device2 from right side

                let same_hostname = !device1.hostname.is_empty()
                    && !device2.hostname.is_empty()
                    && device1.hostname == device2.hostname;

                let same_ip = (matches!(device1.ip_address, IpAddr::V4(_))
                    && matches!(device2.ip_address, IpAddr::V4(_))
                    && device1.ip_address == device2.ip_address)
                    || (matches!(device1.ip_address, IpAddr::V6(_))
                        && matches!(device2.ip_address, IpAddr::V6(_))
                        && device1.ip_address == device2.ip_address);

                let overlaping_ips = (!device1.ip_addresses_v4.is_empty()
                    && !device2.ip_addresses_v4.is_empty()
                    && device1
                        .ip_addresses_v4
                        .iter()
                        .any(|ip| device2.ip_addresses_v4.contains(ip)))
                    || (!device1.ip_addresses_v6.is_empty()
                        && !device2.ip_addresses_v6.is_empty()
                        && device1
                            .ip_addresses_v6
                            .iter()
                            .any(|ip| device2.ip_addresses_v6.contains(ip)));

                let is_duplicate = same_hostname || same_ip || overlaping_ips;

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

    // Combine the devices based on the same criteria as above
    pub fn merge_vec(devices: &mut Vec<DeviceInfo>, new_devices: &Vec<DeviceInfo>) {
        // Always deduplicate the devices before merging
        DeviceInfo::dedup_vec(devices);
        let mut new_devices = new_devices.clone();
        DeviceInfo::dedup_vec(&mut new_devices);

        debug!(
            "Merging {} devices into {} devices",
            new_devices.len(),
            devices.len()
        );

        for new_device in new_devices {
            let mut found = false;

            for device in devices.iter_mut() {
                // If the hostname matches => device has been seen before and possibly has different IPs
                // If one IP v4 matches => device has been seen before
                // If one IP v6 matches => device has been seen before
                // Note that devices can have multiple IP addresses and one unique hostname
                if (!new_device.hostname.is_empty()
                    && !device.hostname.is_empty()
                    && device.hostname == new_device.hostname)
                    || (matches!(new_device.ip_address, IpAddr::V4(_))
                        && matches!(device.ip_address, IpAddr::V4(_))
                        && new_device.ip_address == device.ip_address)
                    || (!new_device.ip_addresses_v4.is_empty()
                        && !device.ip_addresses_v4.is_empty()
                        && new_device
                            .ip_addresses_v4
                            .iter()
                            .any(|ip| device.ip_addresses_v4.contains(ip)))
                    || (matches!(new_device.ip_address, IpAddr::V6(_))
                        && matches!(device.ip_address, IpAddr::V6(_))
                        && new_device.ip_address == device.ip_address)
                    || (!new_device.ip_addresses_v6.is_empty()
                        && !device.ip_addresses_v6.is_empty()
                        && new_device
                            .ip_addresses_v6
                            .iter()
                            .any(|ip| device.ip_addresses_v6.contains(ip)))
                {
                    // Merge the devices
                    DeviceInfo::merge(device, &new_device);
                    debug!(
                        "[merge_vec] After merge: {:?} last_seen: {:?} is_local: {:?} active: {:?}",
                        device.get_ip_address(),
                        device.last_seen,
                        device.is_local,
                        device.active
                    );
                    found = true;
                    break;
                }
            }

            // If no match was found, add the new device
            if !found {
                devices.push(new_device.clone());
                debug!("[merge_vec] New device added: {:?} last_seen: {:?} is_local: {:?} active: {:?}", new_device.get_ip_address(), new_device.last_seen, new_device.is_local, new_device.active);
            }
        }

        debug!("Total devices after merge: {}", devices.len());
    }

    pub fn merge(device: &mut DeviceInfo, new_device: &DeviceInfo) {
        // Validate key fields of the new device
        // Check if there is a valid IPv4 or IPv6 address
        if new_device.ip_address.is_unspecified() {
            warn!(
                "No valid IPv4 or IPv6 address found, ignoring new device: {:?}",
                new_device
            );
            return;
        }

        // Now we merge based on the hostname or IPv4 or IPv6 address(es)
        // At that stage the new_device.ip_address is guaranteed to be valid

        // IPv4 takes precedence over IPv6: always use the new_device.ip_address if it's IPv4
        if let IpAddr::V4(_) = new_device.ip_address {
            if new_device.last_seen > device.last_seen {
                device.set_ip_address(
                    new_device.ip_address,
                    new_device.ip_addresses_v4.clone(),
                    new_device.ip_addresses_v6.clone(),
                );
            }
        // The new device is IPv6 and the device is IPv4, we keep the device's IPv4 and we merge the IP addresses
        } else if matches!(new_device.ip_address, IpAddr::V6(_))
            && matches!(device.ip_address, IpAddr::V4(_))
        {
            if new_device.last_seen > device.last_seen {
                device.add_ip_addresses(
                    new_device.ip_addresses_v4.clone(),
                    new_device.ip_addresses_v6.clone(),
                );
            }
        } else {
            // The new device is IPv6 and the device is IPv6
            // We set the device's ip_address to the new IPv6 if it's fresher
            if new_device.last_seen > device.last_seen {
                device.set_ip_address(
                    new_device.ip_address,
                    new_device.ip_addresses_v4.clone(),
                    new_device.ip_addresses_v6.clone(),
                );
            }
        }

        // Use the most recent non empty mac address
        if new_device.mac_address.is_some() {
            if new_device.last_seen > device.last_seen || device.mac_address.is_none() {
                device.mac_address = new_device.mac_address.clone();
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
        // If either device is local, the result is local
        device.is_local = device.is_local || new_device.is_local;

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

        // Update the first seen time, but do not overwrite if new_device.first_seen is just the default epoch
        if new_device.first_seen < device.first_seen
            && new_device.first_seen > DateTime::<Utc>::from(std::time::UNIX_EPOCH)
        {
            device.first_seen = new_device.first_seen;
        }

        // Update the last seen time only if the new device is local
        if new_device.is_local && new_device.last_seen > device.last_seen {
            debug!(
                "[merge] Updating last_seen for {:?} from {:?} to {:?} (is_local: {:?})",
                device.get_ip_address(),
                device.last_seen,
                new_device.last_seen,
                new_device.is_local
            );
            device.last_seen = new_device.last_seen;
        }

        // Handle origin information
        // If the new device is local, use its origin_ip
        if new_device.is_local && !new_device.origin_ip.is_empty() {
            device.origin_ip.clone_from(&new_device.origin_ip);
        } else if device.origin_ip.is_empty() && !new_device.origin_ip.is_empty() {
            // Otherwise preserve origin information - only set it if the target doesn't have it
            device.origin_ip.clone_from(&new_device.origin_ip);
        }

        // Also update origin_network with the same logic
        if new_device.is_local && !new_device.origin_network.is_empty() {
            device.origin_network.clone_from(&new_device.origin_network);
        } else if device.origin_network.is_empty() && !new_device.origin_network.is_empty() {
            // Otherwise preserve origin information - only set it if the target doesn't have it
            device.origin_network.clone_from(&new_device.origin_network);
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
        let ip_addresses_v4 = if let IpAddr::V4(ipv4) = ip_address {
            vec![ipv4]
        } else {
            vec![]
        };
        let ip_addresses_v6 = if let IpAddr::V6(ipv6) = ip_address {
            vec![ipv6]
        } else {
            vec![]
        };
        let first_seen = self.first_seen;
        let last_seen = self.last_seen;
        *self = DeviceInfo::new(None);
        self.ip_address = ip_address;
        self.ip_addresses_v4 = ip_addresses_v4;
        self.ip_addresses_v6 = ip_addresses_v6;
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
        let mut device_original = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
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
        let mut device_deleted = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 20))));
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
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 30))));
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
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 0, 0).unwrap();
                d.deleted = false;
                d
            },
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 11))));
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 5, 0).unwrap();
                d.deleted = true;
                d
            },
        ];

        let new_list = vec![
            // This device has a fresher timestamp and says it's deleted
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
                d.set_ip_address(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)), vec![], vec![]);
                d.last_modified = Utc.with_ymd_and_hms(2023, 1, 10, 10, 15, 0).unwrap();
                d.deleted = true;
                d
            },
            // This device is brand new
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 12))));
                d.last_modified = Utc.with_ymd_and_hms(2023, 2, 10, 9, 0, 0).unwrap();
                d.deleted = false;
                d
            },
            // This device is older info for .11 so it should not override
            {
                let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 11))));
                d.set_ip_address(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 11)), vec![], vec![]);
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
            .find(|d| d.get_ip_address() == IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)))
            .unwrap();
        assert!(
            device_10.deleted,
            "192.168.0.10 should have been marked deleted from the fresher 'new_list' entry."
        );

        // 2) 192.168.0.12 should have been added
        let device_12 = existing_list
            .iter()
            .find(|d| d.get_ip_address() == IpAddr::V4(Ipv4Addr::new(192, 168, 0, 12)));
        assert!(
            device_12.is_some(),
            "192.168.0.12 should have been newly added."
        );

        // 3) 192.168.0.11 should remain deleted, because the new data was older
        let device_11 = existing_list
            .iter()
            .find(|d| d.get_ip_address() == IpAddr::V4(Ipv4Addr::new(192, 168, 0, 11)))
            .unwrap();
        assert!(
            device_11.deleted,
            "192.168.0.11 should remain deleted because incoming data was older."
        );
    }

    #[test]
    fn test_merge_ipv6() {
        // Check that merges also occur when IPv6 matches
        let mut device1 = DeviceInfo::new(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        device1.hostname = "device1".to_string();
        device1.last_seen = Utc.with_ymd_and_hms(2023, 6, 1, 8, 0, 0).unwrap();
        device1.origin_ip = "127.0.0.1".to_string();
        device1.origin_network = "local-network".to_string();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        device2.hostname = "device1-new".to_string(); // different hostname
        device2.last_seen = Utc.with_ymd_and_hms(2023, 6, 1, 9, 0, 0).unwrap();
        device2.origin_ip = "127.0.0.1".to_string();
        device2.origin_network = "local-network".to_string();
        device2.is_local = true; // Mark as local for test to pass

        let mut devices = vec![device1.clone()];
        DeviceInfo::merge_vec(&mut devices, &vec![device2.clone()]);
        assert_eq!(
            devices.len(),
            1,
            "They should merge since they share the same IPv6 address."
        );

        // device1 was older, so we expect device2's info to override fields as needed
        let merged = &devices[0];
        assert_eq!(
            merged.hostname, "device1-new",
            "Hostname from device2 should be used since device2 is newer and they have the same origin."
        );
        assert_eq!(
            merged.get_ip_address(),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "IPv6 is still localhost."
        );
        assert_eq!(
            merged.last_seen, device2.last_seen,
            "Since device2 was fresher, last_seen should be updated."
        );
    }

    #[test]
    fn test_merge_first_seen_older_valid() {
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));
        // Current device was first seen at 2023-05-01 13:00:00
        device_current.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 13, 0, 0).unwrap();

        let mut device_new = device_current.clone();
        // The new device has an older (earlier) first_seen of 2023-05-01 12:00:00
        device_new.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 12, 0, 0).unwrap();

        // Merge them
        DeviceInfo::merge(&mut device_current, &device_new);

        // We expect the device_current.first_seen to be the older date (12:00:00).
        assert_eq!(
            device_current.first_seen,
            Utc.with_ymd_and_hms(2023, 5, 1, 12, 0, 0).unwrap(),
            "The existing device's first_seen should take the older timestamp from new_device if it is valid."
        );
    }

    #[test]
    fn test_merge_first_seen_newer_does_not_override() {
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2))));
        // Current device was first seen at 2023-05-01 10:00:00
        device_current.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 10, 0, 0).unwrap();

        let mut device_new = device_current.clone();
        // The new device has a later first_seen (2023-05-01 11:00:00),
        // but we do NOT want to override with a "newer" first_seen.
        // Because the code sets first_seen to the older of the two.
        device_new.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 11, 0, 0).unwrap();

        // Merge them
        DeviceInfo::merge(&mut device_current, &device_new);

        // Expect that we still have the same older first_seen (10:00:00).
        assert_eq!(
            device_current.first_seen,
            Utc.with_ymd_and_hms(2023, 5, 1, 10, 0, 0).unwrap(),
            "We should keep the older existing first_seen when merging."
        );
    }

    #[test]
    fn test_merge_first_seen_ignore_default_epoch() {
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 3))));
        // Current device was first seen at 2023-05-01 10:30:00
        device_current.first_seen = Utc.with_ymd_and_hms(2023, 5, 1, 10, 30, 0).unwrap();

        let mut device_new = device_current.clone();
        // The new device has the default epoch (1970-01-01) as first_seen
        device_new.first_seen = DateTime::<Utc>::from(std::time::UNIX_EPOCH);

        // Merge them
        DeviceInfo::merge(&mut device_current, &device_new);

        // The existing device's first_seen is valid, so it should NOT be overridden by epoch.
        assert_eq!(
            device_current.first_seen,
            Utc.with_ymd_and_hms(2023, 5, 1, 10, 30, 0).unwrap(),
            "We should ignore default (UNIX epoch) first_seen from the new device."
        );
    }

    #[test]
    fn test_merge_last_seen_newer_overrides() {
        // If the new device has a more recent last_seen and is local, it should override the existing device
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1))));
        device_current.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 13, 0, 0).unwrap();
        device_current.origin_ip = "192.168.1.100".to_string();
        device_current.origin_network = "test-network".to_string();

        let mut device_new = device_current.clone();
        // Give the new device a more recent last_seen
        device_new.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 14, 0, 0).unwrap();
        // Make the device local to allow updating last_seen
        device_new.is_local = true;
        // Keep the same origin info
        device_new.origin_ip = "192.168.1.100".to_string();
        device_new.origin_network = "test-network".to_string();

        DeviceInfo::merge(&mut device_current, &device_new);

        // The device_current should be updated to the newer last_seen
        assert_eq!(
            device_current.last_seen,
            Utc.with_ymd_and_hms(2023, 5, 1, 14, 0, 0).unwrap(),
            "A more recent last_seen from a local device should override the existing device's last_seen"
        );
    }

    #[test]
    fn test_merge_last_seen_older_no_update() {
        // If the new device has an older last_seen, we do not change the existing device
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 2))));
        device_current.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 13, 30, 0).unwrap();

        let mut device_older = device_current.clone();
        // Make the new device's last_seen older than the current
        device_older.last_seen = Utc.with_ymd_and_hms(2023, 5, 1, 12, 30, 0).unwrap();

        DeviceInfo::merge(&mut device_current, &device_older);

        // The device_current's last_seen should not be updated
        assert_eq!(
            device_current.last_seen,
            Utc.with_ymd_and_hms(2023, 5, 1, 13, 30, 0).unwrap(),
            "An older last_seen should NOT override the existing device's last_seen"
        );
    }

    // Test that the active state is not overridden by the new device with diferent origin
    #[test]
    fn test_merge_active_state() {
        let mut device_current = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 3))));
        device_current.active = true;

        let mut device_new = device_current.clone();
        device_new.active = false;
        device_new.origin_ip = "192.168.10.4".to_string();

        DeviceInfo::merge(&mut device_current, &device_new);

        assert_eq!(
            device_current.active, true,
            "Active state should not be overridden by the new device"
        );
    }

    #[test]
    fn test_merge_cross_origin_devices() {
        // Test that devices from different origins can be merged properly
        // after removing the origin IP restriction
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Create a device representing a local detection
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "test-device".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Create a device representing a community detection
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "test-device".to_string();
        community_device.os_name = "Community OS".to_string(); // Additional info from community
        community_device.device_vendor = "Community Vendor".to_string();
        community_device.origin_ip = "10.0.0.1".to_string(); // Different origin IP
        community_device.origin_network = "friend-network".to_string(); // Different origin network
        community_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap(); // Newer timestamp
        community_device.is_local = false; // Community devices are NOT local

        // Merge the community device into the local device
        DeviceInfo::merge(&mut local_device, &community_device);

        // Verify that the community device updated the local device's metadata
        assert_eq!(local_device.os_name, "Community OS");
        assert_eq!(local_device.device_vendor, "Community Vendor");

        // The last_seen time should NOT update since community device isn't local
        assert_eq!(
            local_device.last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );

        // Verify origin info remains unchanged
        assert_eq!(local_device.origin_ip, "192.168.1.1");
        assert_eq!(local_device.origin_network, "home-network");
    }

    #[test]
    fn test_merge_older_community_device() {
        // Test that older community devices don't update newer local devices
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Create a device representing a local detection with newer timestamp
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "test-device".to_string();
        local_device.os_name = "Local OS".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 14, 0, 0).unwrap(); // Newer timestamp

        // Create a device representing an older community detection
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "test-device".to_string();
        community_device.os_name = "Community OS".to_string();
        community_device.origin_ip = "10.0.0.1".to_string(); // Different origin IP
        community_device.origin_network = "friend-network".to_string();
        community_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap(); // Older timestamp

        // Merge the community device into the local device
        DeviceInfo::merge(&mut local_device, &community_device);

        // Verify that the community device did NOT update the local device
        assert_eq!(local_device.os_name, "Local OS");
        assert_eq!(
            local_device.last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 14, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_merge_open_ports_from_community() {
        // Test that open ports are merged correctly from community devices
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Create a device representing a local detection
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "test-device".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Add some open ports to the local device
        local_device.open_ports.push(PortInfo {
            port: 80,
            protocol: "tcp".to_string(),
            service: "http".to_string(),
            banner: "".to_string(),
        });

        // Create a device representing a community detection with additional ports
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "test-device".to_string();
        community_device.origin_ip = "10.0.0.1".to_string(); // Different origin IP
        community_device.origin_network = "friend-network".to_string();
        community_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap(); // Newer timestamp
        community_device.is_local = false; // Community devices are NOT local

        // Add different open ports to the community device
        community_device.open_ports.push(PortInfo {
            port: 443,
            protocol: "tcp".to_string(),
            service: "https".to_string(),
            banner: "".to_string(),
        });

        // Merge the community device into the local device
        DeviceInfo::merge(&mut local_device, &community_device);

        // Verify that both ports are now in the local device
        assert_eq!(local_device.open_ports.len(), 2);

        // Sort by port number for consistent testing
        local_device.open_ports.sort_by(|a, b| a.port.cmp(&b.port));

        assert_eq!(local_device.open_ports[0].port, 80);
        assert_eq!(local_device.open_ports[0].service, "http");
        assert_eq!(local_device.open_ports[1].port, 443);
        assert_eq!(local_device.open_ports[1].service, "https");

        // Verify timestamp NOT updated since community device isn't local
        assert_eq!(
            local_device.last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_merge_vec_preserves_user_customizations() {
        // Test that merge_vec preserves user customizations when merging community devices
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Create a local device with user customizations
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "test-device".to_string();
        local_device.custom_name = "My Custom Device".to_string(); // User customization
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Add a dismissed port
        local_device.dismissed_ports.push(8080);

        // Create a vector of local devices
        let mut local_devices = vec![local_device];

        // Create a community device with newer information
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "community-name-for-device".to_string(); // Different hostname
        community_device.origin_ip = "10.0.0.1".to_string();
        community_device.origin_network = "friend-network".to_string();
        community_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap(); // Newer timestamp
        community_device.is_local = false; // Community devices are NOT local

        // Add some new ports
        community_device.open_ports.push(PortInfo {
            port: 8080, // This port was dismissed by the user
            protocol: "tcp".to_string(),
            service: "http-alt".to_string(),
            banner: "".to_string(),
        });

        // Create a vector of community devices
        let community_devices = vec![community_device];

        // Merge the community devices into the local devices
        DeviceInfo::merge_vec(&mut local_devices, &community_devices);

        // Verify that user customizations are preserved
        assert_eq!(local_devices[0].custom_name, "My Custom Device");
        assert_eq!(local_devices[0].dismissed_ports, vec![8080]);

        // Verify hostname from community device was merged
        assert_eq!(local_devices[0].hostname, "community-name-for-device");

        // Verify timestamp is NOT updated since community device isn't local
        assert_eq!(
            local_devices[0].last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );
    }

    #[test]
    fn test_merge_multiple_community_devices() {
        // Test merging multiple community devices with a local device
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Create a local device
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "test-device".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Add a local device to the vector
        let mut local_devices = vec![local_device];

        // Create a community device #1 with OS info
        let mut community_device1 =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device1.hostname = "test-device".to_string();
        community_device1.os_name = "Community OS".to_string();
        community_device1.origin_ip = "10.0.0.1".to_string();
        community_device1.origin_network = "friend-network-1".to_string();
        community_device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();
        community_device1.is_local = false; // Community devices are NOT local

        // Create a community device #2 with vendor info and a later timestamp
        let mut community_device2 =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device2.hostname = "test-device".to_string();
        community_device2.device_vendor = "Community Vendor".to_string();
        community_device2.origin_ip = "10.0.0.2".to_string();
        community_device2.origin_network = "friend-network-2".to_string();
        community_device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 14, 0, 0).unwrap();
        community_device2.is_local = false; // Community devices are NOT local

        // Create a vector of community devices
        let community_devices = vec![community_device1, community_device2];

        // Merge the community devices into the local devices
        DeviceInfo::merge_vec(&mut local_devices, &community_devices);

        // Verify that information from both community devices was merged
        assert_eq!(local_devices[0].os_name, "Community OS");
        assert_eq!(local_devices[0].device_vendor, "Community Vendor");

        // Verify the timestamp is NOT updated since community devices aren't local
        assert_eq!(
            local_devices[0].last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );

        // Verify origin info remains unchanged
        assert_eq!(local_devices[0].origin_ip, "192.168.1.1");
        assert_eq!(local_devices[0].origin_network, "home-network");
    }

    #[test]
    fn test_last_seen_during_scanning_and_mdns() {
        // Test that last_seen updates correctly during various detection methods
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // Step 1: Initial discovery via scanning
        let mut device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        device.hostname = "test-device".to_string();
        device.origin_ip = "192.168.1.1".to_string();
        device.origin_network = "home-network".to_string();
        // Override the default timestamp for testing
        device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        device.first_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        // Add a port from scanning
        device.open_ports.push(PortInfo {
            port: 80,
            protocol: "tcp".to_string(),
            service: "http".to_string(),
            banner: "".to_string(),
        });

        // Step 2: Simulate mDNS discovery (happens after initial scan)
        // In LANScanFactory::populate_mdns, a new device is created and merged
        let mut mdns_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        mdns_device.hostname = "mdns-hostname".to_string(); // Better hostname from mDNS
        mdns_device.origin_ip = "192.168.1.1".to_string(); // Same origin
        mdns_device.origin_network = "home-network".to_string();
        // The mDNS device should be local
        mdns_device.is_local = true;
        // In real code, mDNS sets both timestamps to mdns_info.first_seen
        let mdns_timestamp = Utc.with_ymd_and_hms(2023, 1, 1, 12, 15, 0).unwrap();
        mdns_device.first_seen = mdns_timestamp;
        mdns_device.last_seen = mdns_timestamp; // Same as first_seen for mDNS

        // Add mDNS services
        mdns_device.mdns_services.push("_http._tcp".to_string());

        // Merge the mDNS device into our device
        DeviceInfo::merge(&mut device, &mdns_device);

        // Verify mDNS update
        assert_eq!(device.hostname, "mdns-hostname"); // Got better hostname
        assert_eq!(device.mdns_services, vec!["_http._tcp"]);
        assert_eq!(device.last_seen, mdns_timestamp); // Timestamp updated to mDNS detection time

        // Step 3: Simulate a re-scan 30 minutes later (creates a new device instance)
        let mut rescan_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        rescan_device.origin_ip = "192.168.1.1".to_string();
        rescan_device.origin_network = "home-network".to_string();
        // The rescan device should be local
        rescan_device.is_local = true;

        // In real code this is Utc::now() at scan time
        let rescan_timestamp = Utc.with_ymd_and_hms(2023, 1, 1, 12, 30, 0).unwrap();
        rescan_device.last_seen = rescan_timestamp;
        rescan_device.first_seen = rescan_timestamp; // New device gets current time for both

        // Found new port during rescan
        rescan_device.open_ports.push(PortInfo {
            port: 443,
            protocol: "tcp".to_string(),
            service: "https".to_string(),
            banner: "".to_string(),
        });

        // Merge the rescan device
        DeviceInfo::merge(&mut device, &rescan_device);

        // Verify rescan updates
        assert_eq!(device.open_ports.len(), 2); // Now has both ports
        assert_eq!(device.last_seen, rescan_timestamp); // Timestamp updated to scan time
        assert_eq!(
            device.first_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        ); // First seen preserved

        // Step 4: Simulate community device received later
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "mdns-hostname".to_string(); // Same for matching
        community_device.os_name = "Ubuntu 22.04".to_string(); // OS info from community
        community_device.origin_ip = "10.0.0.1".to_string(); // Different origin
        community_device.origin_network = "friend-network".to_string();

        // Community detected this 15 minutes after our rescan
        let community_timestamp = Utc.with_ymd_and_hms(2023, 1, 1, 12, 45, 0).unwrap();
        community_device.last_seen = community_timestamp;

        // Merge the community device
        DeviceInfo::merge(&mut device, &community_device);

        // Verify community updates
        assert_eq!(device.os_name, "Ubuntu 22.04");
        // last_seen should NOT be updated since community device is not local
        assert_eq!(device.last_seen, rescan_timestamp);

        // Step 5: Receive older community information (shouldn't update timestamp)
        let mut older_community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        older_community_device.hostname = "mdns-hostname".to_string();
        older_community_device.device_vendor = "Old Vendor".to_string();
        older_community_device.origin_ip = "10.0.0.2".to_string();
        older_community_device.origin_network = "another-network".to_string();

        // This community detection is older
        let older_timestamp = Utc.with_ymd_and_hms(2023, 1, 1, 12, 10, 0).unwrap();
        older_community_device.last_seen = older_timestamp;

        // Merge the older community device
        DeviceInfo::merge(&mut device, &older_community_device);

        // Verify older info behavior
        assert_eq!(device.device_vendor, "Old Vendor"); // Vendor info applied since our device had no vendor
        assert_eq!(device.last_seen, rescan_timestamp); // Timestamp not changed (still has rescan timestamp)
    }

    #[test]
    fn test_last_seen_handling_in_community_lan() {
        // This test simulates the complete flow of device discovery, sharing and merging
        use chrono::{TimeZone, Utc};
        use std::net::{IpAddr, Ipv4Addr};

        // 1. Create a local device as if detected by scanning
        let mut local_device = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        local_device.hostname = "local-discovery".to_string();
        local_device.origin_ip = "192.168.1.1".to_string();
        local_device.origin_network = "home-network".to_string();
        local_device.is_local = true; // This is a local device
        local_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();
        local_device.open_ports.push(PortInfo {
            port: 80,
            protocol: "tcp".to_string(),
            service: "http".to_string(),
            banner: "".to_string(),
        });

        // 2. Create a device as if detected by another community member
        let mut community_device =
            DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        community_device.hostname = "local-discovery".to_string(); // Same hostname for matching
        community_device.os_name = "Linux".to_string(); // OS detected by community member
        community_device.origin_ip = "10.0.0.1".to_string(); // Different origin
        community_device.origin_network = "friend-network".to_string();
        community_device.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap(); // Later detection
                                                                                          // Set is_local to false to test local-only time update restriction
        community_device.is_local = false;
        community_device.open_ports.push(PortInfo {
            port: 443,
            protocol: "tcp".to_string(),
            service: "https".to_string(),
            banner: "".to_string(),
        });

        // 3. Simulate the process in community_lan.rs's LanDeviceShared event
        let mut devices_vec = vec![local_device.clone()];
        let community_device_vec = vec![community_device.clone()];

        // 4. Merge the community device (this is what happens after reception)
        DeviceInfo::merge_vec(&mut devices_vec, &community_device_vec);

        // 5. Verify that the merge preserved timestamps correctly
        assert_eq!(devices_vec.len(), 1); // Still just one device

        // The device should have info from both sources
        assert_eq!(devices_vec[0].os_name, "Linux"); // Got OS from community

        // Ports from both sources should be present
        assert_eq!(devices_vec[0].open_ports.len(), 2);
        devices_vec[0]
            .open_ports
            .sort_by(|a, b| a.port.cmp(&b.port));
        assert_eq!(devices_vec[0].open_ports[0].port, 80); // Local port
        assert_eq!(devices_vec[0].open_ports[1].port, 443); // Community port

        // The timestamp should NOT be updated from the community device since it's not local
        assert_eq!(
            devices_vec[0].last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap()
        );

        // Origin should still be from the local device
        assert_eq!(devices_vec[0].origin_ip, "192.168.1.1");
        assert_eq!(devices_vec[0].origin_network, "home-network");
    }

    #[test]
    fn test_merge_is_local_updates_origin_ip() {
        // Test that when a local device is merged, its origin_ip is used
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30))));
        device1.origin_ip = "192.168.1.100".to_string(); // Existing origin_ip
        device1.is_local = false;
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30))));
        device2.origin_ip = "192.168.1.200".to_string(); // New origin_ip
        device2.is_local = true; // This device is local
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify the origin_ip was updated because the new device is local
        assert_eq!(
            device1.origin_ip, "192.168.1.200",
            "origin_ip should be updated when merging a local device"
        );
    }

    #[test]
    fn test_merge_not_local_preserves_origin_ip() {
        // Test that when a non-local device is merged, the original origin_ip is preserved
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40))));
        device1.origin_ip = "192.168.1.100".to_string(); // Original origin_ip
        device1.is_local = false;
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40))));
        device2.origin_ip = "192.168.1.200".to_string(); // Different origin_ip
        device2.is_local = false; // This device is NOT local
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify the origin_ip was NOT updated because the new device is not local
        assert_eq!(
            device1.origin_ip, "192.168.1.100",
            "origin_ip should be preserved when merging a non-local device"
        );
    }

    #[test]
    fn test_merge_is_local_updates_origin_network() {
        // Test that when a local device is merged, its origin_network is used
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        device1.origin_network = "old-network".to_string(); // Existing origin_network
        device1.is_local = false;
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        device2.origin_network = "new-network".to_string(); // New origin_network
        device2.is_local = true; // This device is local
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify the origin_network was updated because the new device is local
        assert_eq!(
            device1.origin_network, "new-network",
            "origin_network should be updated when merging a local device"
        );
    }

    #[test]
    fn test_merge_not_local_preserves_origin_network() {
        // Test that when a non-local device is merged, the original origin_network is preserved
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60))));
        device1.origin_network = "old-network".to_string(); // Original origin_network
        device1.is_local = false;
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60))));
        device2.origin_network = "new-network".to_string(); // Different origin_network
        device2.is_local = false; // This device is NOT local
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify the origin_network was NOT updated because the new device is not local
        assert_eq!(
            device1.origin_network, "old-network",
            "origin_network should be preserved when merging a non-local device"
        );
    }

    #[test]
    fn test_merge_is_local_preserved() {
        // Test that is_local flag is preserved when merging
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        device1.is_local = true;
        device1.hostname = "local-device".to_string();
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))));
        device2.is_local = true; // Local for timestamp to be updated
        device2.os_name = "Some OS".to_string();
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify is_local remains true
        assert!(
            device1.is_local,
            "is_local should remain true after merging"
        );
        // Also verify other fields were updated
        assert_eq!(device1.os_name, "Some OS", "OS name should be updated");
        assert_eq!(
            device1.last_seen,
            Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap(),
            "last_seen should be updated from newer device"
        );
    }

    #[test]
    fn test_merge_is_local_propagates() {
        // Test that is_local=true propagates from source to destination
        let mut device1 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))));
        device1.is_local = false;
        device1.hostname = "device".to_string();
        device1.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 12, 0, 0).unwrap();

        let mut device2 = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20))));
        device2.is_local = true; // Source device is marked as local
        device2.last_seen = Utc.with_ymd_and_hms(2023, 1, 1, 13, 0, 0).unwrap();

        // Merge device2 into device1
        DeviceInfo::merge(&mut device1, &device2);

        // Verify is_local was propagated from device2 to device1
        assert!(
            device1.is_local,
            "is_local should be propagated from source to destination"
        );
    }

    #[test]
    fn test_merge_vec_is_local_behavior() {
        // Test that is_local behavior works correctly when merging vectors
        let mut devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
            d.is_local = false;
            d
        }];

        let new_devices = vec![{
            let mut d = DeviceInfo::new(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10))));
            d.is_local = true;
            d
        }];

        // Merge the vectors
        DeviceInfo::merge_vec(&mut devices, &new_devices);

        // Verify the result has is_local=true
        assert!(
            devices[0].is_local,
            "is_local should be true after merging vectors"
        );
    }
}
