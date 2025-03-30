use crate::blacklists::{Blacklists, BlacklistsJSON};
use crate::lanscan_dns::DnsPacketProcessor;
use crate::lanscan_interface::*;
use crate::lanscan_ip::*;
use crate::lanscan_l7::LANScanL7;
use crate::lanscan_mdns::*;
use crate::lanscan_packets::*;
use crate::lanscan_resolver::LANScanResolver;
use crate::lanscan_sessions::session_macros::*;
use crate::lanscan_sessions::*;
use crate::runtime::*;
use crate::rwlock::CustomRwLock;
use crate::whitelists::{is_session_in_whitelist, is_valid_whitelist, Whitelists, WhitelistsJSON};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "asyncpacketcapture"
))]
use futures::StreamExt;
#[cfg(not(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "asyncpacketcapture"
)))]
use pcap::Capture;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "asyncpacketcapture"
))]
use pcap::{Capture, Packet, PacketCodec};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "asyncpacketcapture"
))]
use tokio::select;
#[cfg(all(
    any(target_os = "macos", target_os = "linux", target_os = "windows"),
    feature = "asyncpacketcapture"
))]
use tokio::time::interval;
use tracing::{debug, error, info, trace, warn};

/*
 * DNS Resolution and L7 Process Resolution Architecture
 * ====================================================
 *
 * DNS Resolution Logic:
 * ---------------------
 * The system uses a hybrid approach to DNS resolution combining passive monitoring
 * and active resolution:
 *
 * 1. Passive DNS Monitoring (DnsPacketProcessor):
 *    - Captures actual DNS query/response packets from network traffic
 *    - Extracts domain-to-IP mappings in real-time from observed DNS traffic
 *    - Provides immediate and accurate mappings for domains actively being accessed
 *
 * 2. Active DNS Resolution (LANScanResolver):
 *    - Performs programmatic DNS lookups for IPs without observed DNS packets
 *    - Handles both forward resolution (domain → IP) and reverse resolution (IP → domain)
 *    - Maintains a cache of resolved entries with TTL management
 *
 * 3. Integration Strategy:
 *    - DNS packet data is prioritized over active lookups (in populate_domain_names)
 *    - Important services (ports 80, 443, 22, etc.) are prioritized for resolution
 *    - Resolutions are continuously updated as connections remain active
 *    - The integrate_dns_with_resolver method synchronizes data between both systems
 *
 * L7 Process Resolution Logic:
 * ---------------------------
 * L7 resolution identifies which applications/processes own network connections:
 *
 * 1. Resolution Triggering:
 *    - New connections are immediately queued for L7 resolution when first seen
 *    - Sessions with missing L7 data are re-queued during the populate_l7 phase (not needed for most sessions)
 *
 * 2. Resolution Strategy (in LANScanL7):
 *    - Uses a multi-tiered matching approach to find the responsible process:
 *      a. Exact socket matches (full match on src/dst IP:port pairs)
 *      b. Partial matches (match on one endpoint)
 *      c. Port-only matches (when endpoints change but ports remain consistent)
 *    - Applies different retry strategies for ephemeral vs. long-lived connections
 *      - Ephemeral connections (DNS, high ports): Very fast 50ms retries
 *      - Standard connections: Exponential backoff (100ms to 10s)
 *
 * 3. Caching Mechanism:
 *    - Port-to-process cache retains successful resolutions
 *    - Host service cache tracks local services
 *    - Long-lived cache for frequently accessed services
 *    - Periodic cleanup of stale cache entries
 *
 * This approach ensures accurate resolution of both short-lived connections
 * (like DNS queries or ephemeral client connections) and long-running sessions
 * while maintaining efficient system resource usage.
 */

// A session is considered active if it has had activity in the last 60 seconds
static CONNECTION_ACTIVITY_TIMEOUT: ChronoDuration = ChronoDuration::seconds(60);
// A session is considered current if it has been active in the last 180 seconds
static CONNECTION_CURRENT_TIMEOUT: ChronoDuration = ChronoDuration::seconds(180);
// Keep 1 hour of history
static CONNECTION_RETENTION_TIMEOUT: ChronoDuration = ChronoDuration::seconds(60 * 60 * 1);
// Current whitelist exceptions
static WHITELIST_EXCEPTION_TIMEOUT: ChronoDuration = CONNECTION_RETENTION_TIMEOUT;

pub struct LANScanCapture {
    interfaces: Arc<CustomRwLock<LANScanInterfaces>>,
    capture_task_handles: Arc<DashMap<String, TaskHandle>>,
    sessions: Arc<DashMap<Session, SessionInfo>>,
    current_sessions: Arc<CustomRwLock<Vec<Session>>>,
    resolver: Option<Arc<LANScanResolver>>,
    l7: Option<Arc<LANScanL7>>,
    whitelist_name: Arc<CustomRwLock<String>>,
    custom_whitelists: Arc<CustomRwLock<Option<Whitelists>>>,
    whitelist_conformance: Arc<AtomicBool>,
    last_whitelist_exception_time: Arc<CustomRwLock<DateTime<Utc>>>,
    whitelist_exceptions: Arc<CustomRwLock<Vec<Session>>>,
    filter: Arc<CustomRwLock<SessionFilter>>,
    dns_packet_processor: Option<Arc<DnsPacketProcessor>>,
    custom_blacklists: Arc<CustomRwLock<Option<Blacklists>>>,
}

impl LANScanCapture {
    pub fn new() -> Self {
        Self {
            interfaces: Arc::new(CustomRwLock::new(LANScanInterfaces::new())),
            capture_task_handles: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            current_sessions: Arc::new(CustomRwLock::new(Vec::new())),
            resolver: None,
            l7: None,
            whitelist_name: Arc::new(CustomRwLock::new("".to_string())),
            custom_whitelists: Arc::new(CustomRwLock::new(None)),
            whitelist_conformance: Arc::new(AtomicBool::new(true)),
            last_whitelist_exception_time: Arc::new(CustomRwLock::new(DateTime::<Utc>::from(
                std::time::UNIX_EPOCH,
            ))),
            whitelist_exceptions: Arc::new(CustomRwLock::new(Vec::new())),
            filter: Arc::new(CustomRwLock::new(SessionFilter::GlobalOnly)),
            dns_packet_processor: None,
            custom_blacklists: Arc::new(CustomRwLock::new(None)),
        }
    }

    pub async fn reset_whitelist(&mut self) {
        // Reset the conformance flag
        self.whitelist_conformance.store(true, Ordering::Relaxed);
        // Clear the exceptions
        self.whitelist_exceptions.write().await.clear();
        // Update the whitelist state of each session
        let sessions = self.sessions.clone();
        for mut session in sessions.iter_mut() {
            session.is_whitelisted = WhitelistState::Unknown;
        }
    }

    pub async fn set_whitelist(&mut self, whitelist_name: &str) {
        // Check if the whitelist is valid (either a standard whitelist or our custom one)
        if !whitelist_name.is_empty()
            && whitelist_name != "custom_whitelist"
            && !is_valid_whitelist(whitelist_name).await
        {
            error!("Invalid whitelist name: {}", whitelist_name);
            return;
        }

        // If we're switching to a non-custom whitelist, check if it's different
        if whitelist_name != "custom_whitelist"
            && self.whitelist_name.read().await.eq(whitelist_name)
        {
            return;
        }

        // Set the new whitelist name
        *self.whitelist_name.write().await = whitelist_name.to_string();

        // Clear the custom whitelists if we're switching to a standard whitelist
        if whitelist_name != "custom_whitelist" {
            *self.custom_whitelists.write().await = None;
        }

        // Reset the whitelist state
        self.reset_whitelist().await;
    }

    pub async fn set_filter(&mut self, filter: SessionFilter) {
        *self.filter.write().await = filter;
    }

    pub async fn start(&mut self, interfaces: &LANScanInterfaces) {
        info!("Starting LANScanCapture");

        // Start mDNS task (if it's not already running)
        mdns_start().await;

        // Initialize and start L7
        if let Some(l7) = &mut self.l7 {
            if let Some(l7) = Arc::get_mut(l7) {
                l7.start().await;
            } else {
                error!("Unable to get mutable reference to L7");
            }
        } else {
            self.l7 = Some(Arc::new(LANScanL7::new()));
            if let Some(l7) = &mut self.l7 {
                if let Some(l7) = Arc::get_mut(l7) {
                    l7.start().await;
                } else {
                    error!("Unable to get mutable reference to L7");
                }
            }
        }

        // Initialize and start resolver
        if let Some(resolver) = &mut self.resolver {
            if let Some(resolver) = Arc::get_mut(resolver) {
                resolver.start().await;
            }
        } else {
            self.resolver = Some(Arc::new(LANScanResolver::new()));
            if let Some(resolver) = &mut self.resolver {
                if let Some(resolver) = Arc::get_mut(resolver) {
                    resolver.start().await;
                } else {
                    error!("Unable to get mutable reference to resolver");
                }
            }
        }

        self.start_dns_packet_processor_task().await;

        // Set the interface
        *self.interfaces.write().await = interfaces.clone();

        // Start tasks
        // If the capture task is already running, return
        if !self.capture_task_handles.is_empty() {
            warn!("Capture task already running");
            return;
        }

        // Then start the capture task to populate the sessions map
        self.start_capture_task().await;
    }

    pub async fn stop(&mut self) {
        info!("Stopping LANScanCapture");

        if self.capture_task_handles.is_empty() {
            warn!("Capture task not running");
            return;
        }

        // First stop the capture tasks
        self.stop_capture_tasks().await;

        // Stop the resolver
        if let Some(resolver) = &mut self.resolver {
            if let Some(resolver) = Arc::get_mut(resolver) {
                resolver.stop().await;
                info!("Resolver stopped");
            } else {
                error!("Unable to get mutable reference to resolver");
            }
        }

        // Stop the L7
        if let Some(l7) = &mut self.l7 {
            if let Some(l7) = Arc::get_mut(l7) {
                l7.stop().await;
                info!("L7 stopped");
            } else {
                error!("Unable to get mutable reference to L7");
            }
        }

        // Stop the DNS packet processor
        self.stop_dns_packet_processor_task().await;
    }

    pub async fn restart(&mut self, interfaces: &LANScanInterfaces) {
        // Only restart if capturing and if the interface string has changed
        if !self.is_capturing().await || self.interfaces.read().await.eq(interfaces) {
            info!("Not restarting capture as it's not capturing or interface has not changed");
            return;
        };

        info!("Restarting LANScanCapture");
        // Only restart the capture task
        self.stop_capture_tasks().await;
        self.start_capture_task().await;
    }

    pub async fn is_capturing(&self) -> bool {
        !self.capture_task_handles.is_empty()
    }

    pub async fn get_whitelist(&self) -> String {
        // Simply return the configured whitelist name
        // It will already be "custom_whitelist" when custom whitelists are in use
        self.whitelist_name.read().await.clone()
    }

    pub async fn set_custom_whitelists(&mut self, whitelist_json: &str) {
        // Clear the custom whitelists if the JSON is empty
        if whitelist_json.is_empty() {
            *self.custom_whitelists.write().await = None;
            // Don't reset the whitelist name if we're clearing custom whitelists
            // since the user might be switching back to a standard whitelist
            self.reset_whitelist().await;
            return;
        }

        let whitelist_result = serde_json::from_str::<WhitelistsJSON>(whitelist_json);

        match whitelist_result {
            Ok(whitelist_data) => {
                let whitelist = Some(Whitelists::new_from_json(whitelist_data));
                *self.custom_whitelists.write().await = whitelist;
                // Set the whitelist name to indicate we're using a custom whitelist
                *self.whitelist_name.write().await = "custom_whitelist".to_string();
            }
            Err(e) => {
                error!("Error setting custom whitelists: {}", e);
                *self.custom_whitelists.write().await = None;
            }
        }

        // Reset the whitelist
        self.reset_whitelist().await;
    }

    pub async fn create_custom_whitelists(&mut self) -> Result<String> {
        // First update all sessions
        self.update_sessions().await;

        // Create a whitelist using all sessions instead of just current sessions
        let sessions_vec: Vec<SessionInfo> = self
            .sessions
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        let whitelist = Whitelists::new_from_sessions(&sessions_vec);
        let whitelist_json = WhitelistsJSON::from(whitelist);
        match serde_json::to_string(&whitelist_json) {
            Ok(json) => Ok(json),
            Err(e) => {
                error!("Error creating custom whitelists: {}", e);
                return Err(anyhow!("Error creating custom whitelists: {}", e));
            }
        }
    }

    pub async fn get_filter(&self) -> SessionFilter {
        self.filter.read().await.clone()
    }

    async fn start_dns_packet_processor_task(&mut self) {
        // Create a new DNS packet processor if it doesn't exist
        if self.dns_packet_processor.is_none() {
            self.dns_packet_processor = Some(Arc::new(DnsPacketProcessor::new()));
        }

        // Start the cleanup task
        if let Some(dns_processor) = &mut self.dns_packet_processor {
            if let Some(dns_processor) = Arc::get_mut(dns_processor) {
                dns_processor.start().await;
            } else {
                error!("Failed to get mutable reference to DNS packet processor");
            }
        }
    }

    async fn stop_dns_packet_processor_task(&mut self) {
        // Stop the DNS packet processor cleanup task
        if let Some(dns_processor) = &mut self.dns_packet_processor {
            if let Some(dns_processor) = Arc::get_mut(dns_processor) {
                dns_processor.stop_dns_query_cleanup_task().await;
                info!("DNS packet processor stopped");
            } else {
                error!("Failed to get mutable reference to DNS packet processor");
            }
        }
    }

    pub fn get_interface_from_device(device: &pcap::Device) -> Result<LANScanInterface> {
        info!("Attempting to find interface from device: {}", device.name);
        let interface_list = get_valid_network_interfaces();

        // Check for name match.
        if let Some(intf) = interface_list
            .interfaces
            .iter()
            .find(|iface| iface.name == device.name)
        {
            info!("Interface found in list by name {}", intf.name);
            return Ok(intf.clone());
        }

        // Check if the device has no address - this can happen on Windows with the default device (WAN Miniport monitor)
        let device_addr = match device.addresses.get(0) {
            Some(device_addr) => device_addr.addr,
            None => {
                warn!(
                    "Device {} has no address, creating a dummy interface",
                    device.name
                );
                let new_interface = LANScanInterface {
                    name: device.name.clone(),
                    ipv4: None,
                    ipv6: Vec::new(),
                };
                return Ok(new_interface);
            }
        };

        // Check for IPv4 match (if available).
        if let Some(intf) = interface_list.interfaces.iter().find(|iface| {
            iface
                .ipv4
                .as_ref()
                .map_or(false, |ipv4| ipv4.ip == device_addr)
        }) {
            info!("Interface found in list by IPv4 address {}", intf.name);
            return Ok(intf.clone());
        }

        // Check for IPv6 match.
        if let Some(intf) = interface_list
            .interfaces
            .iter()
            .find(|iface| iface.ipv6.iter().any(|ipv6| ipv6.ip() == device_addr))
        {
            info!("Interface found in list by IPv6 address {}", intf.name);
            return Ok(intf.clone());
        }

        // If no matching interface is found.
        warn!("No matching interface found for device: {}", device.name);
        Err(anyhow!(
            "No matching interface found for device: {}",
            device.name
        ))
    }

    async fn get_device_from_interface(interface: &LANScanInterface) -> Result<pcap::Device> {
        info!(
            "Attempting to find device from interface: {}",
            interface.name
        );
        let device_list = pcap::Device::list().map_err(|e| anyhow!(e))?;

        // Check for a device with a matching name (case-insensitive).
        if let Some(dev) = device_list
            .iter()
            .find(|dev| dev.name.eq_ignore_ascii_case(&interface.name))
        {
            info!(
                "Device {:?} found in list by name {}",
                dev.name, interface.name
            );
            return Ok(dev.clone());
        }

        // Check for IPv4 match if available.
        if let Some(ipv4) = &interface.ipv4 {
            if let Some(dev) = device_list
                .iter()
                .find(|dev| dev.addresses.iter().any(|addr| addr.addr == ipv4.ip))
            {
                info!(
                    "Device {:?} found in list by IPv4 address {}",
                    dev.name, ipv4.ip
                );
                return Ok(dev.clone());
            }
        }

        // If IPv6 addresses exist, check for IPv6 match.
        if !interface.ipv6.is_empty() {
            if let Some(dev) = device_list.iter().find(|dev| {
                interface
                    .ipv6
                    .iter()
                    .any(|ipv6_addr| dev.addresses.iter().any(|addr| addr.addr == ipv6_addr.ip()))
            }) {
                info!(
                    "Device {:?} found in list by IPv6 addresses {:?}",
                    dev.name, interface.ipv6
                );
                return Ok(dev.clone());
            } else {
                warn!(
                    "No matching device found by IPv6 addresses for interface {:?}",
                    interface
                );
                return Err(anyhow!(format!(
                    "Interface {:?} not found in device list",
                    interface
                )));
            }
        }

        // If no matching device is found.
        warn!(
            "Interface {:?} not found in device list {:?}",
            interface, device_list
        );
        Err(anyhow!(format!(
            "Interface {:?} not found in device list",
            interface
        )))
    }

    async fn get_default_device() -> Result<pcap::Device> {
        let device = match pcap::Device::lookup() {
            Ok(Some(device)) => {
                // Only for macOS
                if cfg!(target_os = "macos") && device.name.starts_with("ap") {
                    return Err(anyhow!("Interface from lookup is incorrect"));
                } else {
                    device
                }
            }
            Ok(None) => {
                return Err(anyhow!("No device found from lookup"));
            }
            Err(e) => {
                return Err(anyhow!(e));
            }
        };
        Ok(device)
    }

    async fn start_capture_task(&mut self) {
        // Retrieve the configured interfaces from our stored LANScanInterfaces
        let interfaces = self.interfaces.read().await;
        let passed_interface_success = if !interfaces.interfaces.is_empty() {
            let mut at_least_one_success = false;
            for interface in &interfaces.interfaces {
                info!(
                    "Initializing capture task for interface: {}",
                    interface.name
                );
                let device = match Self::get_device_from_interface(interface).await {
                    Ok(device) => device,
                    Err(e) => {
                        warn!(
                            "Failed to get device from interface {}: {}",
                            interface.name, e
                        );
                        continue;
                    }
                };
                // Use the interface name (or any other unique identifier) as the key
                self.start_capture_task_for_device(&device, &interface.name)
                    .await;
                at_least_one_success = true;
            }
            at_least_one_success
        } else {
            warn!(
                "Passed interfaces {:?} did not return any capture devices",
                interfaces
            );
            false
        };

        // Release the read lock
        drop(interfaces);

        // If no passed interfaces were found, use a default interface.
        if !passed_interface_success {
            let mut default_interface = match get_default_interface() {
                Some(interface) => {
                    info!("Using default interface: {}", interface.name);
                    interface
                }
                None => {
                    error!("No default interface detected, aborting capture");
                    return;
                }
            };

            let default_device = match Self::get_device_from_interface(&default_interface).await {
                Ok(device) => device,
                Err(e) => {
                    warn!(
                        "Failed to get device from default interface, using pcap devicelookup: {}",
                        e
                    );
                    match Self::get_default_device().await {
                        Ok(device) => {
                            // Update default_interface name from the resolved device.
                            default_interface.name = device.name.clone();
                            device
                        }
                        Err(e) => {
                            error!("Failed to get default device: {}", e);
                            return;
                        }
                    }
                }
            };

            // Find back the interface from name
            let default_interface = match Self::get_interface_from_device(&default_device.clone()) {
                Ok(interface) => interface,
                Err(e) => {
                    error!("Failed to get interface from name: {}", e);
                    return;
                }
            };
            // Initialize the local IP cache with the default interface
            let interfaces = LANScanInterfaces {
                interfaces: vec![default_interface.clone()],
            };
            init_local_cache(&interfaces);

            self.start_capture_task_for_device(&default_device, &default_interface.name)
                .await;
        }
    }

    async fn start_capture_task_for_device(
        &self,
        device: &pcap::Device,
        interfaces_ipv4_addresses: &str,
    ) {
        // Clone shared resources for each capture task
        let sessions = self.sessions.clone();
        let current_sessions = self.current_sessions.clone();
        let filter = self.filter.clone();

        // Create a new stop flag for this interface's capture task
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        // Clone the interface name for the async move block
        let interface_clone = interfaces_ipv4_addresses.to_string();

        // Clone the device for the async move block
        let device_clone = device.clone();

        // Clone the DNS packet processor for the async move block
        let dns_packet_processor = self.dns_packet_processor.clone();

        // Clone the L7 for the async move block
        let l7 = self.l7.clone();

        // Clone the custom_blacklists for the async move block
        let custom_blacklists = self.custom_blacklists.clone();

        // Spawn the capture task
        let handle = async_spawn(async move {
            let mut cap = match Capture::from_device(device_clone.clone()) {
                Ok(cap) => cap,
                Err(e) => {
                    error!("Failed to create capture on device: {}", e);
                    return;
                }
            };

            // Extract a vector of IP addresses from the device addresses
            let self_ips: Vec<_> = device_clone
                .addresses
                .iter()
                .filter_map(|addr| Some(addr.addr))
                .collect();

            // Set immediate mode
            cap = cap.immediate_mode(true);

            // Open the capture
            // Type is changing from Inactive to Active, we need a let
            let mut cap = match cap.promisc(false).timeout(1000).open() {
                Ok(cap) => cap,
                Err(e) => {
                    error!("Failed to open pcap capture: {}", e);
                    return;
                }
            };

            #[cfg(not(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "asyncpacketcapture"
            )))]
            {
                info!("Using sync capture for {}", interface_clone);

                while !stop_flag_clone.load(Ordering::Relaxed) {
                    match cap.next_packet() {
                        Ok(packet) => {
                            if let Some(parsed_packet) = parse_packet_pcap(packet.data) {
                                match parsed_packet {
                                    ParsedPacket::SessionPacket(cp) => {
                                        process_parsed_packet(
                                            cp,
                                            &sessions,
                                            &current_sessions,
                                            &self_ips,
                                            &filter,
                                            l7.as_ref(),
                                            Some(&custom_blacklists),
                                        )
                                        .await;
                                    }
                                    ParsedPacket::DnsPacket(dp) => {
                                        if let Some(dns_packet_processor) =
                                            dns_packet_processor.as_ref()
                                        {
                                            dns_packet_processor
                                                .process_dns_packet(dp.dns_payload)
                                                .await;
                                        }
                                    }
                                }
                            }
                        }
                        Err(pcap::Error::TimeoutExpired) => {
                            // Read timeout occurred, check stop_flag
                            continue;
                        }
                        Err(e) => {
                            error!("Failed to read packet: {}", e);
                            break;
                        }
                    }
                }
                info!("Stopping sync capture for {}", interface_clone);
            }

            #[cfg(all(
                any(target_os = "macos", target_os = "linux", target_os = "windows"),
                feature = "asyncpacketcapture"
            ))]
            {
                info!("Using async capture for {}", interface_clone);

                // Required for async
                cap = match cap.setnonblock() {
                    Ok(cap) => cap,
                    Err(e) => {
                        error!("Failed to set non blocking: {}", e);
                        return;
                    }
                };

                // Define codec and packet structures
                pub struct OwnedCodec;
                pub struct PacketOwned {
                    pub data: Box<[u8]>,
                }

                impl PacketCodec for OwnedCodec {
                    type Item = PacketOwned;

                    fn decode(&mut self, pkt: Packet) -> Self::Item {
                        PacketOwned {
                            data: pkt.data.into(),
                        }
                    }
                }
                // Create a new packet stream
                let mut packet_stream = match cap.stream(OwnedCodec) {
                    Ok(stream) => stream,
                    Err(e) => {
                        error!(
                            "Failed to create packet stream on {}: {}",
                            interface_clone, e
                        );
                        return;
                    }
                };

                let mut interval = interval(tokio::time::Duration::from_millis(100));

                tracing::debug!("Starting async capture task for {}", interface_clone);
                loop {
                    select! {
                        _ = interval.tick() => {
                            if stop_flag_clone.load(Ordering::Relaxed) {
                                info!("Stopping async capture task for {}", interface_clone);
                                break;
                            }
                        }
                        packet_owned = packet_stream.next() => {
                            trace!("Received packet on {}", interface_clone);
                            match packet_owned {
                                Some(Ok(packet_owned)) => match parse_packet_pcap(&packet_owned.data) {
                                    Some(ParsedPacket::SessionPacket(cp)) => {
                                        process_parsed_packet(
                                            cp,
                                            &sessions,
                                            &current_sessions,
                                            &self_ips,
                                            &filter,
                                            l7.as_ref(),
                                            Some(&custom_blacklists),
                                        )
                                        .await;
                                    }
                                    Some(ParsedPacket::DnsPacket(dp)) => {
                                        if let Some(dns_packet_processor) = dns_packet_processor.as_ref() {
                                            dns_packet_processor.process_dns_packet(dp.dns_payload).await;
                                        }
                                    }
                                    None => {
                                        trace!("Error parsing packet on {}", interface_clone);
                                    }
                                }
                                Some(Err(e)) => {
                                    warn!("Error capturing packet on {}: {}", interface_clone, e);
                                }
                                None => {
                                    warn!("Packet stream ended for {}", interface_clone);
                                }
                            }
                        }
                    }
                }
            };
            info!("Capture task for {} terminated", interface_clone);
        });
        // Store the task handle and its stop flag
        self.capture_task_handles.insert(
            interfaces_ipv4_addresses.to_string(),
            TaskHandle { handle, stop_flag },
        );
    }

    async fn stop_capture_tasks(&mut self) {
        // Collect all keys first to avoid holding references while modifying the DashMap
        let keys: Vec<String> = self
            .capture_task_handles
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys {
            // Remove the TaskHandle from the DashMap, taking ownership
            if let Some((_, task_handle)) = self.capture_task_handles.remove(&key) {
                task_handle.stop_flag.store(true, Ordering::Relaxed);
                let _ = task_handle.handle.await;
            }
        }

        info!("All capture tasks have been stopped");
    }

    async fn check_whitelisted_destinations(
        custom_whitelists: &Arc<CustomRwLock<Option<Whitelists>>>,
        whitelist_name: &str,
        whitelist_conformance: &AtomicBool,
        whitelist_exceptions: &Arc<CustomRwLock<Vec<Session>>>,
        sessions: &DashMap<Session, SessionInfo>,
        last_whitelist_exception_time: &Arc<CustomRwLock<DateTime<Utc>>>,
    ) {
        // If the whitelist name is "custom_whitelist", we check the custom whitelists
        // If it's something else, we check the standard whitelist with that name
        let using_custom = whitelist_name == "custom_whitelist";

        // Skip the check if the specified whitelist doesn't exist
        if (using_custom && custom_whitelists.read().await.is_none())
            || (!using_custom && !is_valid_whitelist(whitelist_name).await)
        {
            if !whitelist_name.is_empty() {
                error!("Invalid or missing whitelist: {}", whitelist_name);
            }
            return;
        }

        let mut whitelist_check_results = Vec::new();

        // Process each active session
        for key in sessions.iter() {
            let session_info = key.value().clone();

            let dst_domain = session_info.dst_domain.clone();

            if let Some(dst_domain) = dst_domain {
                // If the domain is unknown or resolving, use the IP address instead
                if dst_domain == "Unknown".to_string() || dst_domain == "Resolving".to_string() {
                    // The domain has not been resolved successfully, use the IP address instead
                    let (is_whitelisted, reason) = is_session_in_whitelist(
                        None,
                        Some(&session_info.session.dst_ip.to_string()),
                        session_info.session.dst_port,
                        session_info.session.protocol.to_string().as_str(),
                        custom_whitelists,
                        whitelist_name,
                        session_info.dst_asn.as_ref().map(|asn| asn.as_number),
                        session_info
                            .dst_asn
                            .as_ref()
                            .map(|asn| asn.country.as_str()),
                        session_info.dst_asn.as_ref().map(|asn| asn.owner.as_str()),
                        session_info.l7.as_ref().map(|l7| l7.process_name.as_str()),
                    )
                    .await;

                    whitelist_check_results.push((
                        session_info.session.clone(),
                        is_whitelisted,
                        reason,
                    ));
                } else {
                    // The domain has been resolved
                    let (is_whitelisted, reason) = is_session_in_whitelist(
                        Some(&dst_domain),
                        None,
                        session_info.session.dst_port,
                        session_info.session.protocol.to_string().as_str(),
                        custom_whitelists,
                        whitelist_name,
                        session_info.dst_asn.as_ref().map(|asn| asn.as_number),
                        session_info
                            .dst_asn
                            .as_ref()
                            .map(|asn| asn.country.as_str()),
                        session_info.dst_asn.as_ref().map(|asn| asn.owner.as_str()),
                        session_info.l7.as_ref().map(|l7| l7.process_name.as_str()),
                    )
                    .await;

                    whitelist_check_results.push((
                        session_info.session.clone(),
                        is_whitelisted,
                        reason,
                    ));
                }
            } else {
                // The domain has not been resolved yet, use the IP address instead
                let (is_whitelisted, reason) = is_session_in_whitelist(
                    None,
                    Some(&session_info.session.dst_ip.to_string()),
                    session_info.session.dst_port,
                    session_info.session.protocol.to_string().as_str(),
                    custom_whitelists,
                    whitelist_name,
                    session_info.dst_asn.as_ref().map(|asn| asn.as_number),
                    session_info
                        .dst_asn
                        .as_ref()
                        .map(|asn| asn.country.as_str()),
                    session_info.dst_asn.as_ref().map(|asn| asn.owner.as_str()),
                    session_info.l7.as_ref().map(|l7| l7.process_name.as_str()),
                )
                .await;

                whitelist_check_results.push((
                    session_info.session.clone(),
                    is_whitelisted,
                    reason,
                ));
            }
        }

        // Process the results
        let mut updated_exceptions = Vec::new();
        let mut whitelisted_sessions = Vec::new();

        for (session, is_whitelisted, reason) in whitelist_check_results {
            if !is_whitelisted {
                trace!("Session {:?} failed whitelist check", session);
                updated_exceptions.push(session.clone());
                *last_whitelist_exception_time.write().await = Utc::now();

                if let Some(mut session_info) = sessions.get_mut(&session) {
                    session_info.value_mut().is_whitelisted = WhitelistState::NonConforming;
                    session_info.value_mut().whitelist_reason = reason;
                }
            } else {
                whitelisted_sessions.push(session.clone());

                if let Some(mut session_info) = sessions.get_mut(&session) {
                    session_info.value_mut().is_whitelisted = WhitelistState::Conforming;
                    session_info.value_mut().whitelist_reason = None;
                }
            }
        }

        // If one session is not whitelisted, set the whitelist conformance to false
        if !updated_exceptions.is_empty() {
            whitelist_conformance.store(false, Ordering::Relaxed);
        }

        // Merge the updated exceptions with the existing ones
        let mut new_exceptions = whitelist_exceptions.read().await.clone();
        new_exceptions.extend(updated_exceptions);

        // Deduplicate the exceptions
        new_exceptions.sort_by_key(|k| k.clone());
        new_exceptions.dedup_by_key(|k| k.clone());
        *whitelist_exceptions.write().await = new_exceptions;

        info!(
            "Total whitelist exceptions: {}",
            whitelist_exceptions.read().await.len()
        );

        // Clear the whitelist_conformance if it's been more than WHITELIST_EXCEPTION_TIMEOUT seconds
        if !whitelist_conformance.load(Ordering::Relaxed)
            && Utc::now()
                > *last_whitelist_exception_time.read().await + WHITELIST_EXCEPTION_TIMEOUT
        {
            info!(
                "Clearing whitelist conformance after no activity for {} seconds",
                WHITELIST_EXCEPTION_TIMEOUT.num_seconds()
            );
            whitelist_conformance.store(true, Ordering::Relaxed);
        }
    }

    // Only for current sessions
    async fn populate_domain_names(
        sessions: &DashMap<Session, SessionInfo>,
        resolver: &Option<Arc<LANScanResolver>>,
        dns_resolutions: &Arc<DashMap<IpAddr, String>>,
        current_sessions: &Arc<CustomRwLock<Vec<Session>>>,
    ) {
        if resolver.is_none() {
            return;
        }

        let resolver = resolver.as_ref().unwrap();
        let current_sessions = current_sessions.read().await.clone();

        for session in current_sessions {
            // Determine if this is an important service based on port numbers
            let is_important_dst = match session.dst_port {
                // Common server ports that should be prioritized
                80 | 443 | 22 | 21 | 25 | 587 | 3306 | 5432 | 27017 => true,
                _ => false,
            };

            let is_important_src = match session.src_port {
                // Common server ports that should be prioritized
                80 | 443 | 22 | 21 | 25 | 587 | 3306 | 5432 | 27017 => true,
                _ => false,
            };

            // Try to get domain from DNS resolutions first
            let src_domain = dns_resolutions
                .get(&session.src_ip)
                .map(|d| d.value().clone());
            let dst_domain = dns_resolutions
                .get(&session.dst_ip)
                .map(|d| d.value().clone());

            // Use prioritize_resolution for important services
            if is_important_dst {
                resolver.prioritize_resolution(&session.dst_ip, true).await;
            } else if dst_domain.is_none() {
                resolver.add_ip_to_resolver(&session.dst_ip).await;
            }

            if is_important_src {
                resolver.prioritize_resolution(&session.src_ip, true).await;
            } else if src_domain.is_none() {
                resolver.add_ip_to_resolver(&session.src_ip).await;
            }
            // Try to get domain from resolver cache
            let src_domain = match src_domain {
                Some(domain) => Some(domain),
                None => resolver.get_resolved_ip(&session.src_ip).await,
            };
            let dst_domain = match dst_domain {
                Some(domain) => Some(domain),
                None => resolver.get_resolved_ip(&session.dst_ip).await,
            };

            // Update session info with domains
            if src_domain.is_some() || dst_domain.is_some() {
                if let Some(mut session_info) = sessions.get_mut(&session) {
                    if let Some(domain) = src_domain {
                        if domain != "Unknown" && domain != "Resolving" {
                            session_info.src_domain = Some(domain);
                        }
                    }
                    if let Some(domain) = dst_domain {
                        if domain != "Unknown" && domain != "Resolving" {
                            session_info.dst_domain = Some(domain);
                        }
                    }
                }
            }
        }
    }

    // Populate L7
    async fn populate_l7(
        sessions: &DashMap<Session, SessionInfo>,
        l7: &Option<Arc<LANScanL7>>,
        current_sessions: &Arc<CustomRwLock<Vec<Session>>>,
    ) {
        if let Some(l7) = l7.as_ref() {
            let current_sessions_clone = current_sessions.read().await.clone();
            for key in current_sessions_clone.iter() {
                // Clone necessary data
                let session_info = if let Some(session_info) = sessions.get(key) {
                    session_info.clone()
                } else {
                    error!("Session was not found for key: {:?}", key);
                    continue;
                };

                // Add connection to resolver queue if it doesn't already have L7 data
                let needs_resolution = if let Some(session_info) = sessions.get(key) {
                    session_info.value().l7.is_none()
                } else {
                    false
                };

                if needs_resolution {
                    // Add connection to the resolver queue if it's not already there
                    l7.add_connection_to_resolver(&session_info.session).await;
                }

                // Always attempt to get the resolved L7 data
                let l7_resolution = l7.get_resolved_l7(&session_info.session).await;

                // Update the session info after await
                let key_clone = key.clone();
                if let Some(mut session_info_mut) = sessions.get_mut(&key_clone) {
                    if let Some(l7_resolution) = l7_resolution {
                        if let Some(l7_data) = l7_resolution.l7 {
                            session_info_mut.l7 = Some(l7_data.clone());
                            trace!("Updated L7 data for session {:?}: {:?}", key, l7_data);
                        }
                    }
                }
            }
        }
        // Compute L7 % of successful resolutions
        let total_sessions = sessions.len();
        let successful_resolutions = sessions
            .iter()
            .filter(|session| session.value().l7.is_some())
            .count();

        if total_sessions > 0 {
            let l7_success_rate = (successful_resolutions as f64 / total_sessions as f64) * 100.0;
            info!("L7 success rate: {:.2}%", l7_success_rate);
        }
    }

    async fn update_sessions_status(
        sessions: &DashMap<Session, SessionInfo>,
        current_sessions: &Arc<CustomRwLock<Vec<Session>>>,
    ) {
        let mut updated_current_sessions = Vec::new();
        let mut sessions_to_remove = Vec::new();

        // Iterate over mutable references to session entries
        for mut entry in sessions.iter_mut() {
            let key = entry.key().clone();
            let session_info = entry.value_mut();

            // Previous status
            let previous_status = session_info.status.clone();

            // New status
            let now = Utc::now();
            let active = session_info.stats.last_activity >= now - CONNECTION_ACTIVITY_TIMEOUT;
            let added = session_info.stats.start_time >= now - CONNECTION_ACTIVITY_TIMEOUT;
            // If the session was not added and is now active, it was activated
            let activated = !previous_status.active && active;
            // If the session was active and is no longer active, it was deactivated
            let deactivated = previous_status.active && !active;

            // Create new status with updated previous bytes
            let new_status = SessionStatus {
                active,
                added,
                activated,
                deactivated,
            };

            // Update the session info directly
            session_info.status = new_status;

            // Only include sessions that are within the current time frame
            if now < session_info.stats.last_activity + CONNECTION_CURRENT_TIMEOUT {
                updated_current_sessions.push(session_info.session.clone());
            }

            // Flag sessions that are older than the retention timeout
            if now > session_info.stats.last_activity + CONNECTION_RETENTION_TIMEOUT {
                sessions_to_remove.push(key.clone());
            }
        }

        // Update the current sessions
        {
            let mut current_sessions_guard = current_sessions.write().await;
            *current_sessions_guard = updated_current_sessions;
        }

        // Purge the sessions that are older than the retention timeout
        for key in sessions_to_remove.iter() {
            sessions.remove(key);
        }
    }

    async fn update_sessions(&self) {
        // Update the sessions status and current sessions
        Self::update_sessions_status(&self.sessions, &self.current_sessions).await;

        // Update L7 information for all sessions
        if let Some(l7) = &self.l7 {
            Self::populate_l7(&self.sessions, &Some(l7.clone()), &self.current_sessions).await;
        }

        // Enrich DNS resolutions with DNS packet processor information
        self.integrate_dns_with_resolver().await;

        // Then update resolver information for all sessions
        if let (Some(resolver), Some(dns_processor)) = (&self.resolver, &self.dns_packet_processor)
        {
            Self::populate_domain_names(
                &self.sessions,
                &Some(resolver.clone()),
                &dns_processor.get_dns_resolutions(),
                &self.current_sessions,
            )
            .await;
        }

        // Finally update whitelist information
        let whitelist_name = self.whitelist_name.read().await.clone();
        if !whitelist_name.is_empty() || self.custom_whitelists.read().await.is_some() {
            Self::check_whitelisted_destinations(
                &self.custom_whitelists,
                &whitelist_name,
                &self.whitelist_conformance,
                &self.whitelist_exceptions,
                &self.sessions,
                &self.last_whitelist_exception_time,
            )
            .await;
        }
    }

    // Get historical sessions as a vector of SessionInfo
    pub async fn get_sessions(&self) -> Vec<SessionInfo> {
        // First update all sessions
        self.update_sessions().await;

        let mut sessions_vec = Vec::new();
        let filter = self.filter.read().await.clone();
        for entry in self.sessions.iter() {
            let session_info = entry.value();
            // Remove the "Unknown" flag from the domain
            let mut session_info_clone = session_info.clone();
            if session_info_clone.dst_domain == Some("Unknown".to_string()) {
                session_info_clone.dst_domain = None;
            }
            // Apply filter
            if filter == SessionFilter::All {
                sessions_vec.push(session_info_clone);
            } else if filter == SessionFilter::LocalOnly {
                if is_local_session!(session_info_clone) {
                    sessions_vec.push(session_info_clone);
                }
            } else if filter == SessionFilter::GlobalOnly {
                if is_global_session!(session_info_clone) {
                    sessions_vec.push(session_info_clone);
                }
            }
        }
        sessions_vec
    }

    // Active sessions as a vector of SessionInfo
    pub async fn get_current_sessions(&self) -> Vec<SessionInfo> {
        // First update all sessions
        self.update_sessions().await;

        // Get the sessions from the DashMap that match the keys in the current_sessions Vec
        let filter = self.filter.read().await.clone();
        let mut current_sessions_vec = Vec::new();
        for key in self.current_sessions.read().await.iter() {
            if let Some(entry) = self.sessions.get(key) {
                let session_info = entry.value();
                // Remove the "Unknown" flag from the domain
                let mut session_info_clone = session_info.clone();
                if session_info_clone.dst_domain == Some("Unknown".to_string()) {
                    session_info_clone.dst_domain = None;
                }
                // Apply filter
                if filter == SessionFilter::All {
                    current_sessions_vec.push(session_info_clone);
                } else if filter == SessionFilter::LocalOnly {
                    if is_local_session!(session_info_clone) {
                        current_sessions_vec.push(session_info_clone);
                    }
                } else if filter == SessionFilter::GlobalOnly {
                    if is_global_session!(session_info_clone) {
                        current_sessions_vec.push(session_info_clone);
                    }
                }
            }
        }
        current_sessions_vec
    }

    pub async fn get_whitelist_conformance(&self) -> bool {
        // First update all sessions
        self.update_sessions().await;

        self.whitelist_conformance.load(Ordering::Relaxed)
    }

    pub async fn get_whitelist_exceptions(&self) -> Vec<SessionInfo> {
        // First update all sessions
        self.update_sessions().await;

        let mut exceptions = Vec::new();
        for key in self.whitelist_exceptions.read().await.iter() {
            if let Some(entry) = self.sessions.get(key) {
                exceptions.push(entry.clone());
            }
        }
        exceptions
    }

    // Enrich dns resolutions with DNS packet processor information
    async fn integrate_dns_with_resolver(&self) {
        if self.dns_packet_processor.is_none() || self.resolver.is_none() {
            trace!("Cannot integrate DNS sources: one or more components missing");
            return;
        }

        let dns_processor = self.dns_packet_processor.as_ref().unwrap();
        let resolver = self.resolver.as_ref().unwrap();

        // Get DNS resolutions from packet processor
        let dns_resolutions = dns_processor.get_dns_resolutions();

        // Don't do anything if there are no DNS resolutions
        if dns_resolutions.is_empty() {
            trace!("No DNS resolutions to integrate");
            return;
        }

        // Integrate the DNS resolutions with the resolver
        let added_count = resolver.add_dns_resolutions(&dns_resolutions);

        if added_count > 0 {
            debug!(
                "Integrated {} DNS resolutions from packet capture",
                added_count
            );
        }
    }

    pub async fn set_custom_blacklists(&mut self, blacklist_json: &str) {
        // Clear the custom blacklists if the JSON is empty
        if blacklist_json.is_empty() {
            *self.custom_blacklists.write().await = None;
            return;
        }

        let blacklist_result = serde_json::from_str::<BlacklistsJSON>(blacklist_json);

        match blacklist_result {
            Ok(blacklist_data) => {
                let blacklist = Some(Blacklists::new_from_json(blacklist_data));
                *self.custom_blacklists.write().await = blacklist;
            }
            Err(e) => {
                error!("Error setting custom blacklists: {}", e);
                *self.custom_blacklists.write().await = None;
            }
        }
    }
}

impl Clone for LANScanCapture {
    fn clone(&self) -> Self {
        Self {
            interfaces: self.interfaces.clone(),
            capture_task_handles: self.capture_task_handles.clone(),
            sessions: self.sessions.clone(),
            current_sessions: self.current_sessions.clone(),
            resolver: self.resolver.clone(),
            l7: self.l7.clone(),
            whitelist_name: self.whitelist_name.clone(),
            custom_whitelists: self.custom_whitelists.clone(),
            whitelist_conformance: self.whitelist_conformance.clone(),
            last_whitelist_exception_time: self.last_whitelist_exception_time.clone(),
            whitelist_exceptions: self.whitelist_exceptions.clone(),
            filter: self.filter.clone(),
            dns_packet_processor: self.dns_packet_processor.clone(),
            custom_blacklists: self.custom_blacklists.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::*;
    use crate::blacklists::*;
    use chrono::Utc;
    use pnet_packet::tcp::TcpFlags;
    use serial_test::serial;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::{sleep, Duration};
    use uuid::Uuid;

    #[tokio::test]
    #[serial]
    async fn test_session_management() {
        let mut capture = LANScanCapture::new();
        capture.set_filter(SessionFilter::All).await;

        // Simulate an outbound packet
        let session_packet = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                dst_port: 80,
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        // Simulate an inbound packet (response)
        let response_packet = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                src_port: 80,
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_port: 12345,
            },
            packet_length: 150,
            ip_packet_length: 170,
            flags: Some(TcpFlags::ACK),
        };

        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];

        // Process both packets
        process_parsed_packet(
            session_packet,
            &capture.sessions,
            &capture.current_sessions,
            &self_ips,
            &capture.filter,
            capture.l7.as_ref(),
            Some(&capture.custom_blacklists),
        )
        .await;

        process_parsed_packet(
            response_packet,
            &capture.sessions,
            &capture.current_sessions,
            &self_ips,
            &capture.filter,
            capture.l7.as_ref(),
            Some(&capture.custom_blacklists),
        )
        .await;

        // Check the statistics
        let sessions = capture.get_sessions().await;
        let session_info = sessions[0].clone();
        let stats = session_info.stats;

        assert_eq!(stats.outbound_bytes, 100);
        assert_eq!(stats.inbound_bytes, 150);
        assert_eq!(stats.orig_pkts, 1);
        assert_eq!(stats.resp_pkts, 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_session_management_revert() {
        let mut capture = LANScanCapture::new();
        capture.set_whitelist("github").await;
        capture.set_filter(SessionFilter::All).await; // Include all sessions in the filter

        // Create a synthetic packet that should be inverted TCP 168.63.129.16:32526 -> 10.1.0.40:44442
        let session_packet = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16)),
                src_port: 32526,
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 40)),
                dst_port: 44442,
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        // Get self IPs (your local IP)
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 40))];

        // Process the synthetic packet
        process_parsed_packet(
            session_packet,
            &capture.sessions,
            &capture.current_sessions,
            &self_ips,
            &capture.filter,
            capture.l7.as_ref(),
            Some(&capture.custom_blacklists),
        )
        .await;

        // Check that the session has been added
        let sessions = capture.get_sessions().await;
        let sessions = sessions.iter().collect::<Vec<_>>();
        assert_eq!(sessions.len(), 1);

        let session_info = sessions[0];
        let session = session_info.session.clone();
        let stats = session_info.stats.clone();

        // Check that the session has been inverted
        assert_eq!(session.src_ip, IpAddr::V4(Ipv4Addr::new(10, 1, 0, 40)));
        assert_eq!(session.dst_ip, IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16)));
        // Since the packet is from remote to local, we expect inbound_bytes to be updated
        assert_eq!(stats.outbound_bytes, 0);
        assert_eq!(stats.inbound_bytes, 100);
        assert_eq!(stats.orig_pkts, 0);
        assert_eq!(stats.resp_pkts, 1);
        // The history should be 's' because it's a SYN from the responder
        assert_eq!(stats.history, "s");
    }

    #[tokio::test]
    #[serial]
    async fn test_populate_domain_names() {
        let mut capture = LANScanCapture::new();
        capture.set_whitelist("github").await;

        // Initialize the resolver component
        let resolver = Arc::new(LANScanResolver::new());
        resolver.start().await;
        capture.resolver = Some(resolver.clone());

        // Create a synthetic session and add it to sessions
        let session = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_port: 80,
        };

        let stats = SessionStats {
            start_time: Utc::now(),
            end_time: None,
            last_activity: Utc::now(),
            inbound_bytes: 0,
            outbound_bytes: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_ip_bytes: 0,
            resp_ip_bytes: 0,
            history: String::new(),
            conn_state: None,
            missed_bytes: 0,
        };

        let session_info = SessionInfo {
            session: session.clone(),
            stats,
            status: SessionStatus {
                active: false,
                added: true,
                activated: false,
                deactivated: false,
            },
            is_local_src: false,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: None,
            dst_service: None,
            l7: None,
            src_asn: None,
            dst_asn: None,
            is_whitelisted: WhitelistState::Unknown,
            criticality: "".to_string(),
            whitelist_reason: None,
            uid: Uuid::new_v4().to_string(),
            last_modified: Utc::now(),
        };

        capture.sessions.insert(session.clone(), session_info);
        capture.current_sessions.write().await.push(session.clone());

        // Use the dns_packet_processor
        let dns_processor = DnsPacketProcessor::new();

        // Insert a DNS resolution into dns_resolutions
        dns_processor.get_dns_resolutions().insert(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            "dns.google".to_string(),
        );

        // Call populate_domain_names
        LANScanCapture::populate_domain_names(
            &capture.sessions,
            &capture.resolver,
            &dns_processor.get_dns_resolutions(),
            &capture.current_sessions,
        )
        .await;

        // Check that dst_domain is set
        if let Some(entry) = capture.sessions.get(&session) {
            assert_eq!(entry.dst_domain, Some("dns.google".to_string()));
        } else {
            panic!("Session not found");
        };

        // Clean up
        if let Some(resolver) = &capture.resolver {
            let resolver = Arc::clone(resolver);
            resolver.stop().await;
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_update_sessions_status_added() {
        let mut capture = LANScanCapture::new();
        capture.set_filter(SessionFilter::All).await;

        // Create a synthetic session and add it to sessions
        let session = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_port: 80,
        };

        let now = Utc::now();

        let stats = SessionStats {
            start_time: now - ChronoDuration::seconds(5), // Recent start time
            end_time: None,
            last_activity: now - ChronoDuration::seconds(5), // Recent activity
            inbound_bytes: 5000,
            outbound_bytes: 5000,
            orig_pkts: 50,
            resp_pkts: 50,
            orig_ip_bytes: 0,
            resp_ip_bytes: 0,
            history: String::new(),
            conn_state: None,
            missed_bytes: 0,
        };

        let session_info = SessionInfo {
            session: session.clone(),
            stats,
            status: SessionStatus {
                active: false,
                added: true,
                activated: false,
                deactivated: false,
            },
            is_local_src: false,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: None,
            dst_domain: None,
            dst_service: None,
            l7: None,
            src_asn: None,
            dst_asn: None,
            is_whitelisted: WhitelistState::Unknown,
            criticality: "".to_string(),
            whitelist_reason: None,
            uid: Uuid::new_v4().to_string(),
            last_modified: Utc::now(),
        };

        capture.sessions.insert(session.clone(), session_info);
        capture.current_sessions.write().await.push(session.clone());

        // Check current sessions
        let current_sessions = capture.get_current_sessions().await;

        assert_eq!(current_sessions.len(), 1);
        assert_eq!(current_sessions[0].session, session);
        assert!(current_sessions[0].status.active);
        assert!(current_sessions[0].status.added);
        assert!(current_sessions[0].status.activated);
    }

    #[tokio::test]
    #[serial]
    async fn test_process_dns_packet() {
        // Updated to use DnsPacketProcessor

        let dns_payload = vec![
            // A minimal DNS response packet in bytes
            0x12, 0x34, // Transaction ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Queries
            0x03, b'w', b'w', b'w', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o',
            b'm', 0x00, // Name: www.google.com
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            // Answers
            0xc0, 0x0c, // Name: pointer to offset 12 (www.google.com)
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x00, 0x3c, // TTL: 60
            0x00, 0x04, // Data length: 4
            0x08, 0x08, 0x08, 0x08, // Address: 8.8.8.8
        ];

        let dns_processor = DnsPacketProcessor::new();

        // Simulate receiving the DNS query first
        let dns_query_payload = vec![
            // Same Transaction ID as response
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // Questions
            0x00, 0x00, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Queries
            0x03, b'w', b'w', b'w', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o',
            b'm', 0x00, // Name: www.google.com
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        // Process the DNS query
        dns_processor.process_dns_packet(dns_query_payload).await;

        // Process the DNS response
        dns_processor.process_dns_packet(dns_payload).await;

        // Check that the DNS resolution was stored
        if let Some(domain) = dns_processor
            .get_dns_resolutions()
            .get(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        {
            assert_eq!(domain.as_str(), "www.google.com");
        } else {
            panic!("DNS resolution not found");
        };
    }

    #[tokio::test]
    #[serial]
    async fn test_process_dns_packet_tcp() {
        // Updated to use DnsPacketProcessor

        // Construct a DNS-over-TCP payload
        // DNS-over-TCP starts with a 2-byte length field followed by the DNS message
        let dns_message = vec![
            // A minimal DNS response packet in bytes (without length prefix)
            0x12, 0x34, // Transaction ID
            0x81, 0x80, // Flags
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Queries
            0x03, b'w', b'w', b'w', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o',
            b'm', 0x00, // Name: www.google.com
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            // Answers
            0xc0, 0x0c, // Name: pointer to offset 12 (www.google.com)
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x00, 0x3c, // TTL: 60
            0x00, 0x04, // Data length: 4
            0x08, 0x08, 0x08, 0x08, // Address: 8.8.8.8
        ];

        let dns_processor = DnsPacketProcessor::new();

        // Simulate receiving the DNS query first
        let dns_query_message = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // Questions
            0x00, 0x00, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Queries
            0x03, b'w', b'w', b'w', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o',
            b'm', 0x00, // Name: www.google.com
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        // Process the DNS query
        dns_processor.process_dns_packet(dns_query_message).await;

        // Process the DNS response
        dns_processor.process_dns_packet(dns_message).await;

        // Check that the DNS resolution was stored
        if let Some(domain) = dns_processor
            .get_dns_resolutions()
            .get(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        {
            assert_eq!(domain.as_str(), "www.google.com");
        } else {
            panic!("DNS-over-TCP resolution not found");
        };
    }

    #[tokio::test]
    #[serial]
    async fn test_whitelist_conformance_with_multiple_exceptions() {
        let mut capture = LANScanCapture::new();
        capture.set_whitelist("github").await;
        capture.set_filter(SessionFilter::All).await;

        // Add multiple non-conforming sessions
        for i in 0..5 {
            let session = Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)),
                src_port: 12345 + i as u16,
                dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                dst_port: 80,
            };

            let stats = SessionStats {
                start_time: Utc::now(),
                end_time: None,
                last_activity: Utc::now(),
                inbound_bytes: 0,
                outbound_bytes: 0,
                orig_pkts: 0,
                resp_pkts: 0,
                orig_ip_bytes: 0,
                resp_ip_bytes: 0,
                history: String::new(),
                conn_state: None,
                missed_bytes: 0,
            };

            let session_info = SessionInfo {
                session: session.clone(),
                stats,
                status: SessionStatus {
                    active: false,
                    added: false,
                    activated: false,
                    deactivated: false,
                },
                is_local_src: false,
                is_local_dst: false,
                is_self_src: false,
                is_self_dst: false,
                src_domain: None,
                dst_domain: None,
                dst_service: None,
                l7: None,
                src_asn: None,
                dst_asn: None,
                is_whitelisted: WhitelistState::Unknown,
                criticality: "".to_string(),
                whitelist_reason: None,
                uid: Uuid::new_v4().to_string(),
                last_modified: Utc::now(),
            };

            capture.sessions.insert(session.clone(), session_info);
            capture.current_sessions.write().await.push(session.clone());
        }

        // Run whitelist check
        LANScanCapture::check_whitelisted_destinations(
            &capture.custom_whitelists,
            "github",
            &capture.whitelist_conformance,
            &capture.whitelist_exceptions,
            &capture.sessions,
            &capture.last_whitelist_exception_time,
        )
        .await;

        // Assert that conformance is false
        assert!(!capture.get_whitelist_conformance().await);

        // Assert that exceptions are recorded
        let exceptions = capture.get_whitelist_exceptions().await;
        assert_eq!(exceptions.len(), 5);
    }

    #[tokio::test]
    async fn test_default_interface_has_device() {
        // Not working on windows in the CI/CD pipeline yet (no pcap support)
        if cfg!(windows) {
            return;
        }

        // Only if admin
        if !get_admin_status() {
            return;
        }

        // Get the default network interface (LANScanInterfaces)
        let default_interface = match get_default_interface() {
            Some(interface) => interface,
            None => {
                println!("No default interface found");
                return;
            }
        };

        let device_result = LANScanCapture::get_device_from_interface(&default_interface).await;
        assert!(
            device_result.is_ok(),
            "Failed to get device from default interface {:?}",
            default_interface
        );
    }

    #[tokio::test]
    async fn test_default_device_has_interface() {
        // Not working on windows in the CI/CD pipeline yet (no pcap support)
        if cfg!(windows) {
            return;
        }

        // Only if admin
        if !get_admin_status() {
            return;
        }

        let default_device = match LANScanCapture::get_default_device().await {
            Ok(device) => device,
            Err(e) => {
                println!("Failed to get default device: {}", e);
                return;
            }
        };

        let interface_result = LANScanCapture::get_interface_from_device(&default_device);
        assert!(
            interface_result.is_ok(),
            "Failed to get interface from default device {:?}",
            default_device
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_start_capture_if_admin() {
        // Not working on windows in the CI/CD pipeline yet (no pcap support)
        if cfg!(windows) {
            return;
        }

        // Skip test if not running as admin/root
        if !get_admin_status() {
            println!("Skipping test_start_capture_if_admin: not running with admin privileges");
            return;
        }

        // Create a LANScanCapture instance
        let mut capture = LANScanCapture::new();

        // Get the default interface
        let default_interface = match get_default_interface() {
            Some(interface) => {
                println!("Using default interface: {}", interface.name);
                interface
            }
            None => {
                println!("No default interface detected, skipping test");
                return;
            }
        };

        // Create an interfaces struct with the default interface
        let interfaces = LANScanInterfaces {
            interfaces: vec![default_interface],
        };

        // Start the capture
        println!("Starting capture...");
        capture.start(&interfaces).await;

        // Make sure we have an L7 processor
        assert!(capture.l7.is_some(), "Capture should have an L7 processor");

        // Make sure we have a resolver
        assert!(capture.resolver.is_some(), "Capture should have a resolver");

        // Make sure we have a DNS packet processor
        assert!(
            capture.dns_packet_processor.is_some(),
            "Capture should have a DNS packet processor"
        );

        // Check if capture is running
        assert!(capture.is_capturing().await, "Capture should be running");

        // Delay to allow capture to get some sessions and be resolved
        sleep(Duration::from_secs(60)).await;

        // Make sure we have sessions
        let sessions = capture.get_sessions().await;
        assert!(!sessions.is_empty(), "Capture should have sessions");

        // Make sure we have current sessions
        let current_sessions = capture.get_current_sessions().await;
        assert!(
            !current_sessions.is_empty(),
            "Capture should have current sessions"
        );

        // Try to create a custom whitelist
        let custom_whitelist = capture.create_custom_whitelists().await;
        assert!(
            custom_whitelist.is_ok(),
            "Custom whitelist should be created"
        );
        let custom_whitelist = custom_whitelist.unwrap();
        assert!(
            !custom_whitelist.is_empty(),
            "Custom whitelist should have endpoints"
        );

        // Set the whitelist
        capture.set_custom_whitelists(&custom_whitelist).await;

        // Make sure all sessions have a status that is not Unknown, and at least some have process info and DNS info
        let sessions = capture.get_sessions().await;
        let mut have_process_info = false;
        let mut have_dns_info = false;
        let mut have_unknown = false;
        for session in sessions {
            if session.is_whitelisted == WhitelistState::Unknown {
                have_unknown = true;
            }
            if session.is_whitelisted == WhitelistState::NonConforming {
                println!("Session is non-conforming: {:?}", session.clone());
            }
            if session.l7.is_some() && !session.l7.unwrap().process_name.is_empty() {
                have_process_info = true;
            }
            if session.dst_domain.is_some() && !session.dst_domain.unwrap().is_empty() {
                have_dns_info = true;
            }
        }
        assert!(!have_unknown, "All sessions should have a whitelist status");
        assert!(have_process_info, "Some sessions should have process info");
        assert!(have_dns_info, "Some sessions should have DNS info");

        // Stop the capture
        capture.stop().await;

        // Check if capture has stopped
        assert!(!capture.is_capturing().await, "Capture should have stopped");

        println!("Capture test completed successfully");
    }

    #[tokio::test]
    #[serial]
    async fn test_blacklist_integration() {
        let mut capture = LANScanCapture::new();
        capture.set_filter(SessionFilter::All).await;

        // Create a custom blacklist that includes our test IP
        let blacklist_info = BlacklistInfo {
            name: "firehol_level1".to_string(),
            description: Some("Test blacklist".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec![
                "100.64.0.0/10".to_string(), // Carrier-grade NAT range
            ],
        };

        let blacklists_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![blacklist_info],
        };

        let blacklists = Blacklists::new_from_json(blacklists_json);

        // Override global blacklists with our test data
        LISTS
            .write()
            .await
            .overwrite_with_test_data(blacklists)
            .await;

        // Simulate an outbound packet to a known blacklisted IP (in firehol_level1)
        // Using 100.64.0.0/10 from the blacklist (Carrier-grade NAT range)
        let session_packet = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(100, 64, 1, 1)),
                dst_port: 80,
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];

        // Process the packet
        process_parsed_packet(
            session_packet,
            &capture.sessions,
            &capture.current_sessions,
            &self_ips,
            &capture.filter,
            capture.l7.as_ref(),
            Some(&capture.custom_blacklists),
        )
        .await;

        // Check that the session has the criticality field set
        let sessions = capture.get_sessions().await;
        assert_eq!(sessions.len(), 1);
        let session_info = &sessions[0];

        // Verify the criticality field is set as expected
        assert_eq!(session_info.criticality, "blacklist:firehol_level1");
    }

    #[tokio::test]
    #[serial]
    async fn test_blacklist_functionality() {
        let mut capture = LANScanCapture::new();

        // Verify we can set custom blacklists
        let blacklist_info = BlacklistInfo {
            name: "another_test_blacklist".to_string(),
            description: Some("Another test blacklist".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec!["192.168.5.0/24".to_string(), "10.10.10.0/24".to_string()],
        };

        let blacklists_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![blacklist_info],
        };

        let json_str = serde_json::to_string(&blacklists_json).unwrap();

        // Set the custom blacklist
        capture.set_custom_blacklists(&json_str).await;

        // Verify the custom blacklist exists
        assert!(capture.custom_blacklists.read().await.is_some());

        // Clear custom blacklists
        capture.set_custom_blacklists("").await;

        // Verify the custom blacklist is cleared
        assert!(capture.custom_blacklists.read().await.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_custom_blacklists() {
        let mut capture = LANScanCapture::new();

        // Create a custom blacklist
        let blacklist_info = BlacklistInfo {
            name: "custom_test_blacklist".to_string(),
            description: Some("Custom test blacklist".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec!["192.168.1.100/32".to_string(), "1.1.1.0/24".to_string()],
        };

        let blacklists_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![blacklist_info],
        };

        let json_str = serde_json::to_string(&blacklists_json).unwrap();

        // Clear the global blacklist first to avoid interference
        let empty_blacklists = Blacklists::new_from_json(BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![],
        });

        LISTS
            .write()
            .await
            .overwrite_with_test_data(empty_blacklists)
            .await;

        // Set the custom blacklist
        capture.set_custom_blacklists(&json_str).await;

        // Verify the custom blacklist exists
        assert!(capture.custom_blacklists.read().await.is_some());

        // Simulate a packet to 1.1.1.1 (which is in our custom blacklist)
        let session_packet = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                dst_port: 80,
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];

        process_parsed_packet(
            session_packet,
            &capture.sessions,
            &capture.current_sessions,
            &self_ips,
            &capture.filter,
            capture.l7.as_ref(),
            Some(&capture.custom_blacklists),
        )
        .await;

        // Check that the session has the criticality field set
        let sessions = capture.get_sessions().await;
        assert_eq!(sessions.len(), 1);
        let session_info = &sessions[0];

        // Verify the criticality field is set as expected
        assert_eq!(session_info.criticality, "blacklist:custom_test_blacklist");
    }

    #[tokio::test]
    #[serial]
    async fn test_multiple_blacklists() {
        let mut capture = LANScanCapture::new();
        capture.set_filter(SessionFilter::All).await;

        // Create multiple blacklists that include the same IP
        let blacklist_info1 = BlacklistInfo {
            name: "malware_ips".to_string(),
            description: Some("Malware IP addresses".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec![
                "192.0.2.0/24".to_string(), // TEST-NET-1 range
            ],
        };

        let blacklist_info2 = BlacklistInfo {
            name: "spam_ips".to_string(),
            description: Some("Spam IP addresses".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec![
                "192.0.2.0/28".to_string(), // Subset of TEST-NET-1
            ],
        };

        let blacklists_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![blacklist_info1, blacklist_info2],
        };

        let blacklists = Blacklists::new_from_json(blacklists_json);

        // Override global blacklists with our test data
        LISTS
            .write()
            .await
            .overwrite_with_test_data(blacklists)
            .await;

        // Simulate an outbound packet to an IP that should be in both blacklists
        let session_packet = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
                dst_port: 80,
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];

        // Process the packet
        process_parsed_packet(
            session_packet,
            &capture.sessions,
            &capture.current_sessions,
            &self_ips,
            &capture.filter,
            capture.l7.as_ref(),
            Some(&capture.custom_blacklists),
        )
        .await;

        // Check that the session has the criticality field set
        let sessions = capture.get_sessions().await;
        assert_eq!(sessions.len(), 1);
        let session_info = &sessions[0];

        // Verify the criticality field contains both blacklist names (in alphabetical order)
        assert_eq!(
            session_info.criticality,
            "blacklist:malware_ips,blacklist:spam_ips"
        );
    }
}
