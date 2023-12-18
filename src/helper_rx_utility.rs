use log::{error, warn, info};
use std::error::Error;
use serde_json;
use std::net::IpAddr;
use lazy_static::lazy_static;
use std::sync::Arc;
// Tokio Mutex
use tokio::sync::Mutex;

use crate::lanscan_arp::*;
use crate::lanscan_mdns::*;
use crate::lanscan_interface::*;

lazy_static!(
    static ref INTERFACES: Arc<Mutex<Vec<(String, u8, String)>>> = Arc::new(Mutex::new(get_valid_network_interfaces()));
);

pub async fn arp_resolve(addresses: &str) -> Result<String, Box<dyn Error>> {
    let mut arp_results = Vec::new();
    for address in serde_json::from_str::<Vec<(String, String)>>(addresses)? {
        match address.1.parse::<IpAddr>() {
            Ok(ip_addr) => {
                match get_mac_address_from_ip(&address.0, &ip_addr).await {
                    Ok(mac_address) => arp_results.push((address.0, address.1, mac_address)),
                    // Only warn
                    Err(e) => warn!("Error resolving MAC for IP {} on interface {} : {}", address.1, address.0, e),
                }
            },
            Err(e) => error!("Error parsing IP address {}: {}", address.1, e),
        }
    }
    info!("ARP results: {:?}", arp_results);
    Ok(serde_json::to_string(&arp_results)?)
}

pub async fn mdns_resolve(addresses: &str) -> Result<String, Box<dyn Error>> {

    // Check if the interfaces have changed
    let mut interfaces = INTERFACES.lock().await;
    let interfaces_new = get_valid_network_interfaces();
    if *interfaces != interfaces_new {
        info!("Interfaces have changed (was {:?}, now {:?}), flushing mDNS cache", *interfaces, interfaces_new);
        mdns_flush().await;
        *interfaces = interfaces_new;
    }

    let mut mdns_results: Vec<(String, String, String, Vec<String>)> = Vec::new();
    for address in serde_json::from_str::<Vec<String>>(addresses)? {
        match address.parse() {
            Ok(ip) => {
                if let Some(mdns_info) = mdns_get_by_ipv4(&ip).await {

                    // mDNS info - we combine instances and services
                    let mut mdns_services_instances = mdns_info.instances.to_vec();
                    mdns_services_instances.extend(mdns_info.services.to_vec());
                    // Deduplicate
                    mdns_services_instances.sort();
                    mdns_services_instances.dedup();

                    mdns_results.push((address, mdns_info.hostname, mdns_info.mac_address, mdns_services_instances));
                } else {
                    // Only warn
                    warn!("No mDNS info found for IP {}", address);
                }
            }
            Err(e) => error!("Error parsing address {}: {}", address, e),
        }
    }
    info!("mDNS results: {:?}", mdns_results);
    Ok(serde_json::to_string(&mdns_results)?)
}