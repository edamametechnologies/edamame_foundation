use std::collections::HashMap;
use std::{net::IpAddr, sync::{Arc}};
use std::net::Ipv6Addr;
use log::{error, info, trace, warn};
use tokio::task;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tokio::time::Duration;
use lazy_static::lazy_static;
use sorted_vec::SortedVec;
use regex::Regex;

// Our own fork with minor adjustements
use wez_mdns::{QueryParameters, Host};

lazy_static! {
    static ref SHOULD_STOP: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    static ref DEVICES: Arc<Mutex<HashMap<String, mDNSInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref MDNS_HANDLE: Arc<Mutex<Option<task::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
}

#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub struct mDNSInfo {
    pub ip_addr: Option<IpAddr>,
    pub ipv6_addr: Vec<IpAddr>,
    pub mac_address: String,
    pub services: SortedVec<String>,
    pub hostname: String,
    pub instances: SortedVec<String>
}

pub async fn mdns_start() {
    if MDNS_HANDLE.lock().await.is_some() {
        trace!("mDNS task already running");
        return;
    }
    info!("Starting mDNS task");
    *MDNS_HANDLE.lock().await = Some(task::spawn(fetch_mdns_info()));
}

pub fn mdns_stop() {
    info!("Terminating mDNS task");
    SHOULD_STOP.store(true, Ordering::Relaxed);
}

// To be called in case of network change
pub async fn mdns_flush() {
    info!("Flushing mDNS database");
    let mut locked_devices = DEVICES.lock().await;
    locked_devices.clear();
}

pub async fn mdns_get_by_ipv4(ipv4: &IpAddr) -> Option<mDNSInfo> {
    let locked_devices = DEVICES.lock().await;
    locked_devices.iter()
        .find_map(|(_hostname, mdns_info)| {
            if let Some(ip_addr) = &mdns_info.ip_addr {
                if ip_addr == ipv4 {
                    info!("Found mDNS entry for {}: {:?}", ipv4, mdns_info);
                    Some(mdns_info.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
}

fn v6_to_mac(ipv6: &str) -> Option<String> {
    trace!("Attempting to convert IPv6 address {} to MAC address", ipv6);

    let ipv6_addr: Ipv6Addr = ipv6.parse().ok()?;
    let segments = ipv6_addr.segments();

    if segments[0] != 0xfe80 {
        trace!("IPv6 address {} is not a link-local address", ipv6);
        return None;
    }

    trace!("Found link-local IPv6 address {}", ipv6);

    let eui64_bytes = [
        (segments[4] >> 8) as u8,
        (segments[4] & 0xff) as u8,
        (segments[5] >> 8) as u8,
        (segments[5] & 0xff) as u8,
        (segments[6] >> 8) as u8,
        (segments[6] & 0xff) as u8,
        (segments[7] >> 8) as u8,
        (segments[7] & 0xff) as u8,
    ];

    // Convert EUI-64 to EUI-48 (MAC address)
    let eui48_bytes = [
        eui64_bytes[0] ^ 0x02,
        eui64_bytes[1],
        eui64_bytes[2],
        eui64_bytes[5],
        eui64_bytes[6],
        eui64_bytes[7],
    ];

    let mac = eui48_bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join(":");
    trace!("Converted link-local IPv6 address {} to MAC address {}", ipv6, mac);
    Some(mac)
}

fn extract_mac_address(input: &str) -> Option<String> {
    let re = Regex::new(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})").unwrap();
    re.find(input).map(|mat| mat.as_str().to_string())
}

async fn process_host(host: Host, service_name: String) {

    if host.host_name.is_some() {
        let hostname = host.host_name.as_ref().unwrap();
        let instance = host.name.clone();
        if !host.ip_address.is_empty() {
            let ip_addresses = host.ip_address.clone();
            trace!("Found instance {} with host {} and ips {:?}", instance, hostname, ip_addresses);
            // Fill in the info for this host
            let mut locked_devices = DEVICES.lock().await;
            let mdns_info = locked_devices.entry(hostname.clone()).or_insert(mDNSInfo {
                ip_addr: None,
                ipv6_addr: Vec::new(),
                mac_address: "".to_string(),
                services: SortedVec::new(),
                hostname: hostname.clone(),
                instances: SortedVec::new()
            });
            // Process the ip addresses
            for ip in ip_addresses {
                // Get the IPv4 address
                if ip.is_ipv4() {
                    // Keep only one IPv4 address
                    mdns_info.ip_addr = Some(ip);
                }
                // Get the IPv6 addresses
                if ip.is_ipv6() && !mdns_info.ipv6_addr.contains(&ip) {
                    mdns_info.ipv6_addr.push(ip);
                    // Convert the IPv6 address to a MAC address
                    if mdns_info.mac_address.is_empty() {
                        if let Some(mac) = v6_to_mac(&ip.to_string()) {
                            info!("Found MAC address {} for IPv6 address {}", mac, ip);
                            mdns_info.mac_address = mac;
                        }
                    }
                }
            }
            // Process the service and instance names
            if !mdns_info.services.contains(&service_name) {
                info!("Found service {} for host {}", service_name, hostname);
                mdns_info.services.push(service_name.clone());
            }

            // Filter out the instances limited to the host name
            if !mdns_info.instances.contains(&instance) && &instance != hostname {
                info!("Found instance {} for host {}", instance, hostname);
                mdns_info.instances.push(host.name.clone());
            }

            // Check if the instance name is containing a MAC address using a regex
            match extract_mac_address(&instance) {
                Some(mac_address) => {
                    info!("Extracted MAC Address {} from instance {}", mac_address, instance);
                    if mdns_info.mac_address.is_empty() {
                        mdns_info.mac_address = mac_address;
                    } else if mdns_info.mac_address != mac_address {
                        warn!("MAC Address {} from instance {} is different from the one already found {}, using the one from instance", mac_address, instance, mdns_info.mac_address);
                        mdns_info.mac_address = mac_address;
                    }
                },
                None => {
                    trace!("No MAC Address found in the service");
                }
            }
        }
    }
}

async fn fetch_mdns_info() {

    let pause_duration = Duration::from_secs(5);

    loop {
        if SHOULD_STOP.load(Ordering::Relaxed) {
            info!("Received mDNS termination signal");
            trace!("mDNS database: {:?}", DEVICES.lock().await);
            break;
        }
        trace!("Starting mDNS discovery loop");
        // First discover all the services
        let responses = match wez_mdns::resolve("_services._dns-sd._udp.local", QueryParameters::SERVICE_LOOKUP).await {
            Ok(responses) => responses,
            Err(e) => {
                error!("Error querying mDNS services: {:?}", e);
                tokio::time::sleep(pause_duration).await;
                continue;
            }
        };
        let services = match responses.recv().await {
            Ok(services) => {
                services
            },
            Err(e) => {
                warn!("Error receiving mDNS services query response: {:?}", e);
                tokio::time::sleep(pause_duration).await;
                continue;
            }
        };
        let hosts = services.hosts();
        trace!("Response: {:#?}", services);
        trace!("Hosts: {:#?}", hosts);
        // Only do services once
        let mut done_service = Vec::new();
        for service in hosts {
            if done_service.contains(&service.name) {
                continue;
            }
            let service_name = service.name.clone();
            let service_name_clone = service_name.clone();
            trace!("Found service: {}", service_name);
            done_service.push(service_name.clone());
            // Now discover all the instances of this service
            let responses = match wez_mdns::resolve(service_name.clone(), QueryParameters::SERVICE_LOOKUP).await {
                Ok(responses) => responses,
                Err(e) => {
                    // Only warn to prevent multiple sentry errors
                    warn!("Error querying mDNS service {}: {:?}", service_name.clone(), e);
                    continue;
                }
            };
            // Get the instances
            let instances = match responses.recv().await {
                Ok(instances) => instances,
                Err(e) => {
                    // Only warn to prevent multiple sentry errors
                    warn!("Error receiving mDNS query response for service {} : {:?}", service_name, e);
                    continue;
                }
            };
            // Scan the hostnames for each instance
            for host in instances.hosts() {
                let host_clone = host.clone();
                // Check if we have a host name
                if let Some(hostname) = host_clone.host_name {
                    process_host(host, service_name_clone.clone()).await;
                    // Now resolve the host to get all the A and AAAA records (IPv6 addresses) to extrapolate the MAC address
                    let responses = match wez_mdns::resolve(hostname.clone(), QueryParameters::HOST_LOOKUP).await {
                        Ok(responses) => responses,
                        Err(e) => {
                            // Only warn to prevent multiple sentry errors
                            warn!("Error resolving hostname {}: {:?}", hostname.clone(), e);
                            continue;
                        }
                    };
                    let hosts = match responses.recv().await {
                        Ok(hosts) => hosts,
                        Err(e) => {
                            // Only warn to prevent multiple sentry errors
                            warn!("Error receiving mDNS query response for hostname {}: {:?}", hostname, e);
                            continue;
                        }
                    };
                    // Scan the hosts for each entry
                    for host in hosts.hosts() {
                        process_host(host, service_name_clone.clone()).await;
                    }
                }
            }
        }
        // Wait for 5 seconds before scanning again
        tokio::time::sleep(pause_duration).await;
    }
}

pub async fn get_mdns_by_hostname(hostname: &str) -> Option<mDNSInfo> {
    let locked_devices = DEVICES.lock().await;
    match locked_devices.get(hostname) {
        Some(mdns_info) => {
            info!("Found mDNS entry for {}: {:?}", hostname, mdns_info);
            Some(mdns_info.clone())
        }
        None => None,
    }
}
