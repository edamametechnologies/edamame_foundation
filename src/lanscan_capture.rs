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
use crate::whitelists::*;
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
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, trace, warn};

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
    current_sessions_handle: Option<TaskHandle>,
    resolver: Option<Arc<LANScanResolver>>,
    resolver_handle: Option<TaskHandle>,
    l7: Option<Arc<LANScanL7>>,
    l7_handle: Option<TaskHandle>,
    whitelist_check_handle: Option<TaskHandle>,
    whitelist_name: Arc<CustomRwLock<String>>,
    whitelist_conformance: Arc<AtomicBool>,
    last_whitelist_exception_time: Arc<CustomRwLock<DateTime<Utc>>>,
    whitelist_exceptions: Arc<CustomRwLock<Vec<Session>>>,
    filter: Arc<CustomRwLock<SessionFilter>>,
    dns_packet_processor: Option<Arc<DnsPacketProcessor>>,
}

impl LANScanCapture {
    pub fn new() -> Self {
        debug!("Creating new LANScanCapture");
        Self {
            interfaces: Arc::new(CustomRwLock::new(LANScanInterfaces::new())),
            capture_task_handles: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            current_sessions: Arc::new(CustomRwLock::new(Vec::new())),
            current_sessions_handle: None,
            resolver: None,
            resolver_handle: None,
            l7: None,
            l7_handle: None,
            whitelist_check_handle: None,
            whitelist_name: Arc::new(CustomRwLock::new("".to_string())),
            whitelist_conformance: Arc::new(AtomicBool::new(true)),
            last_whitelist_exception_time: Arc::new(CustomRwLock::new(DateTime::<Utc>::from(
                std::time::UNIX_EPOCH,
            ))),
            whitelist_exceptions: Arc::new(CustomRwLock::new(Vec::new())),
            filter: Arc::new(CustomRwLock::new(SessionFilter::GlobalOnly)),
            dns_packet_processor: None,
        }
    }

    pub async fn set_whitelist(&mut self, whitelist_name: &str) {
        // Check if the whitelist is valid
        if !is_valid_whitelist(whitelist_name).await && !whitelist_name.is_empty() {
            error!("Invalid whitelist name: {}", whitelist_name);
            return;
        }
        // Check if the whitelist is different
        if self.whitelist_name.read().await.eq(whitelist_name) {
            return;
        }
        // Set the new whitelist name
        *self.whitelist_name.write().await = whitelist_name.to_string();
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

    pub async fn set_filter(&mut self, filter: SessionFilter) {
        *self.filter.write().await = filter;
    }

    pub async fn start(&mut self, interfaces: &LANScanInterfaces) {
        info!("Starting LANScanCapture");

        // Start mDNS task
        mdns_start().await;

        // Set the interface
        *self.interfaces.write().await = interfaces.clone();

        // Start tasks
        // If the capture task is already running, return
        if !self.capture_task_handles.is_empty() {
            warn!("Capture task already running");
            return;
        }
        // First start DNS packet processor task
        self.start_dns_packet_processor_task().await;
        // Then start the capture task to populate the sessions map
        self.start_capture_task().await;
        // Then start DNS resolution tasks
        self.start_resolver_task().await;
        // Then start L7 task
        self.start_l7_task().await;
        // Then start current sessions task
        self.start_current_sessions_task().await;
        // Finally start whitelist check task
        self.start_whitelist_check_task().await;
    }

    pub async fn stop(&mut self) {
        info!("Stopping LANScanCapture");

        if self.capture_task_handles.is_empty() {
            warn!("Capture task not running");
            return;
        }

        // First stop the capture task
        self.stop_capture_tasks().await;
        // Then stop the other tasks, they will populate their latest data
        self.stop_l7_task().await;
        // Then stop the resolver task
        self.stop_resolver_task().await;
        // Then stop the current sessions task
        self.stop_current_sessions_task().await;
        // Then stop the whitelist check task
        self.stop_whitelist_check_task().await;
        // Finally stop the DNS packet processor task
        self.stop_dns_packet_processor_task().await;

        // Don't clear the state; this is a pause rather than a stop
        // Don't stop the mDNS task as it's shared with other modules
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
        self.whitelist_name.read().await.clone()
    }

    pub async fn get_filter(&self) -> SessionFilter {
        self.filter.read().await.clone()
    }

    async fn start_current_sessions_task(&mut self) {
        let current_sessions = self.current_sessions.clone();
        let sessions = self.sessions.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));

        let stop_flag_clone = stop_flag.clone();
        let handle = async_spawn(async move {
            loop {
                trace!("Sessions status update started");
                Self::update_sessions_status(&sessions, &current_sessions).await;
                info!(
                    "Sessions status update completed - {} current sessions, {} total sessions",
                    current_sessions.read().await.len(),
                    sessions.len()
                );
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                sleep(Duration::from_secs(5)).await;
            }
            info!("Active sessions task terminated");
        });

        self.current_sessions_handle = Some(TaskHandle {
            handle,
            stop_flag: stop_flag_clone,
        });
    }

    async fn stop_current_sessions_task(&mut self) {
        if let Some(task_handle) = self.current_sessions_handle.take() {
            task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = task_handle.handle.await;
        } else {
            error!("Active sessions task not running");
        }
    }

    async fn start_resolver_task(&mut self) {
        // Create a new resolver if it doesn't exist
        if self.resolver.is_none() {
            self.resolver = Some(Arc::new(LANScanResolver::new()));
        }

        // Start the resolver if it exists
        if let Some(resolver) = &mut self.resolver {
            if let Some(resolver) = Arc::get_mut(resolver) {
                resolver.start().await;
            } else {
                error!("Failed to get mutable reference to resolver");
            }
        }

        let resolver = self.resolver.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let sessions = self.sessions.clone();
        let current_sessions = self.current_sessions.clone();
        let dns_packet_processor = self.dns_packet_processor.clone();

        let stop_flag_clone = stop_flag.clone();
        let handle = async_spawn(async move {
            loop {
                trace!("Domain name population started");
                if let Some(dns_packet_processor) = dns_packet_processor.as_ref() {
                    Self::populate_domain_names(
                        &sessions,
                        &resolver,
                        &dns_packet_processor.get_dns_resolutions(),
                        &current_sessions,
                    )
                    .await;
                }
                info!("Domain name population completed");
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                sleep(Duration::from_secs(5)).await;
            }
            info!("Resolver task terminated");
        });

        self.resolver_handle = Some(TaskHandle {
            handle,
            stop_flag: stop_flag_clone,
        });
    }

    async fn stop_resolver_task(&mut self) {
        if let Some(task_handle) = self.resolver_handle.take() {
            task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = task_handle.handle.await;
        } else {
            error!("Resolver task not running");
        }

        // Stop the resolver if it exists
        if let Some(resolver) = &mut self.resolver {
            if let Some(resolver) = Arc::get_mut(resolver) {
                resolver.stop().await;
            } else {
                error!("Failed to get mutable reference to resolver");
            }
        }
    }

    async fn start_dns_packet_processor_task(&mut self) {
        // Create a new DNS packet processor if it doesn't exist
        if self.dns_packet_processor.is_none() {
            self.dns_packet_processor = Some(Arc::new(DnsPacketProcessor::new()));
        }

        // Start the DNS packet processor if it exists
        if let Some(dns_processor) = &mut self.dns_packet_processor {
            if let Some(dns_processor) = Arc::get_mut(dns_processor) {
                dns_processor.start_dns_query_cleanup_task().await;
            } else {
                error!("Failed to get mutable reference to DNS packet processor");
            }
        }
    }

    async fn stop_dns_packet_processor_task(&mut self) {
        if let Some(dns_processor) = &mut self.dns_packet_processor {
            if let Some(dns_processor) = Arc::get_mut(dns_processor) {
                dns_processor.stop_dns_query_cleanup_task().await;
            } else {
                error!("Failed to get mutable reference to DNS packet processor");
            }
        }
    }

    async fn start_l7_task(&mut self) {
        // Create L7 resolver if it doesn't exist
        if self.l7.is_none() {
            self.l7 = Some(Arc::new(LANScanL7::new()));
        }

        // Start the L7 resolver if it exists
        if let Some(l7) = &mut self.l7 {
            if let Some(l7) = Arc::get_mut(l7) {
                l7.start().await;
            } else {
                error!("Failed to get mutable reference to L7 resolver");
            }
        }

        let l7 = self.l7.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let sessions = self.sessions.clone();
        let current_sessions = self.current_sessions.clone();

        let stop_flag_clone = stop_flag.clone();
        let handle = async_spawn(async move {
            loop {
                trace!("L7 update started");
                Self::populate_l7(&sessions, &l7, &current_sessions).await;
                info!("L7 update completed");
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                sleep(Duration::from_secs(5)).await;
            }
            info!("L7 task terminated");
        });

        self.l7_handle = Some(TaskHandle {
            handle,
            stop_flag: stop_flag_clone,
        });
    }

    async fn stop_l7_task(&mut self) {
        if let Some(task_handle) = self.l7_handle.take() {
            task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = task_handle.handle.await;
        } else {
            error!("L7 task not running");
        }

        // Stop the L7 resolver if it exists
        if let Some(l7) = &mut self.l7 {
            if let Some(l7) = Arc::get_mut(l7) {
                l7.stop().await;
            } else {
                error!("Failed to get mutable reference to L7 resolver");
            }
        }
    }

    async fn start_whitelist_check_task(&mut self) {
        let whitelist_name = self.whitelist_name.clone();
        let whitelist_exceptions = self.whitelist_exceptions.clone();
        let whitelist_conformance = self.whitelist_conformance.clone();
        let last_whitelist_exception_time = self.last_whitelist_exception_time.clone();
        let sessions = self.sessions.clone();
        let current_sessions = self.current_sessions.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));

        let stop_flag_clone = stop_flag.clone();
        let handle = async_spawn(async move {
            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                trace!("Whitelist check started");
                let whitelist_name_clone = whitelist_name.read().await.clone();
                if !whitelist_name_clone.is_empty() {
                    Self::check_whitelisted_destinations(
                        &whitelist_name_clone,
                        &whitelist_conformance,
                        &whitelist_exceptions,
                        &sessions,
                        &current_sessions,
                        &last_whitelist_exception_time,
                    )
                    .await;
                    info!("Whitelist check completed");
                }
                sleep(Duration::from_secs(5)).await;
            }
            info!("Whitelist check task terminated");
        });

        self.whitelist_check_handle = Some(TaskHandle {
            handle,
            stop_flag: stop_flag_clone,
        });
    }

    async fn stop_whitelist_check_task(&mut self) {
        if let Some(task_handle) = self.whitelist_check_handle.take() {
            task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = task_handle.handle.await;
        } else {
            error!("Whitelist check task not running");
        }
    }

    async fn get_device_from_interface(
        &self,
        interface: &LANScanInterface,
    ) -> Result<pcap::Device> {
        let device_list = match pcap::Device::list() {
            Ok(list) => list,
            Err(e) => return Err(anyhow!(e)),
        };

        // Attempt to find the device in the list by name then by ipv4 address
        let device = if let Some(device_in_list) = device_list
            .iter()
            .find(|dev| dev.name.to_lowercase() == interface.name.to_lowercase())
        {
            device_in_list.clone()
        } else if let Some(device_in_list) = device_list.iter().find(|dev| {
            dev.addresses.iter().any(|addr| {
                addr.addr.to_string()
                    == interface
                        .ipv4
                        .as_ref()
                        .unwrap_or(&LANScanInterfaceAddrV4::default())
                        .ip
                        .to_string()
            })
        }) {
            device_in_list.clone()
        } else {
            warn!(
                "Interface {} not found in device list {:?}",
                interface.name, device_list
            );
            return Err(anyhow!(format!(
                "Interface {} not found in device list",
                interface.name
            )));
        };
        Ok(device)
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
                let device = match self.get_device_from_interface(interface).await {
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
            false
        };

        // Release the read lock
        drop(interfaces);

        // If no passed interfaces were found, use a default interface.
        if !passed_interface_success {
            warn!("No passed interfaces found, using default interface");
            let mut default_interface = match get_default_interface() {
                Some(interface) => interface,
                None => {
                    error!("No default interface detected, aborting capture");
                    return;
                }
            };

            let default_device = match self.get_device_from_interface(&default_interface).await {
                Ok(device) => device,
                Err(e) => {
                    warn!(
                        "Failed to get device from default interface, using lookup: {}",
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
            let default_interface = match get_interface_from_name(&default_device.name.clone()) {
                Some(interface) => interface,
                None => {
                    error!("Failed to get interface from name: {}", default_device.name);
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

                let mut interval = interval(Duration::from_millis(100));

                debug!("Starting async capture task for {}", interface_clone);
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
        whitelist_name: &str,
        whitelist_conformance: &AtomicBool,
        whitelist_exceptions: &Arc<CustomRwLock<Vec<Session>>>,
        sessions: &DashMap<Session, SessionInfo>,
        current_sessions: &Arc<CustomRwLock<Vec<Session>>>,
        last_whitelist_exception_time: &Arc<CustomRwLock<DateTime<Utc>>>,
    ) {
        let mut updated_exceptions = Vec::new();
        let mut whitelisted_sessions = Vec::new();
        // Clone the current_sessions to avoid holding the lock for too long
        let current_sessions_clone = current_sessions.read().await.clone();

        if is_valid_whitelist(whitelist_name).await {
            for key in current_sessions_clone.iter() {
                // Clone necessary data to avoid holding the lock
                let session_info = if let Some(session) = sessions.get(key) {
                    session.clone()
                } else {
                    error!("Session not found in sessions map");
                    continue;
                };

                let dst_domain = session_info.dst_domain.clone();

                if let Some(dst_domain) = dst_domain {
                    if dst_domain == "Unknown".to_string() {
                        // The domain has not been resolved successfully, use the IP address instead
                        if !is_session_in_whitelist(
                            None,
                            Some(&session_info.session.dst_ip.to_string()),
                            session_info.session.dst_port,
                            session_info.session.protocol.to_string().as_str(),
                            whitelist_name,
                            session_info.dst_asn.as_ref().map(|asn| asn.as_number),
                            session_info
                                .dst_asn
                                .as_ref()
                                .map(|asn| asn.country.as_str()),
                            session_info.dst_asn.as_ref().map(|asn| asn.owner.as_str()),
                            session_info.l7.as_ref().map(|l7| l7.process_name.as_str()),
                        )
                        .await
                        {
                            trace!("Session {:?} failed whitelist check", key);
                            updated_exceptions.push(session_info.session.clone());
                            *last_whitelist_exception_time.write().await = Utc::now();
                        } else {
                            whitelisted_sessions.push(session_info.session.clone());
                        }
                    } else {
                        if dst_domain == "Resolving".to_string() {
                            // The domain is still being resolved, ignore it
                            continue;
                        } else {
                            // The domain has been resolved
                            if !is_session_in_whitelist(
                                Some(&dst_domain),
                                None,
                                session_info.session.dst_port,
                                session_info.session.protocol.to_string().as_str(),
                                whitelist_name,
                                session_info.dst_asn.as_ref().map(|asn| asn.as_number),
                                session_info
                                    .dst_asn
                                    .as_ref()
                                    .map(|asn| asn.country.as_str()),
                                session_info.dst_asn.as_ref().map(|asn| asn.owner.as_str()),
                                session_info.l7.as_ref().map(|l7| l7.process_name.as_str()),
                            )
                            .await
                            {
                                trace!("Session {:?} failed whitelist check", key);
                                updated_exceptions.push(session_info.session.clone());
                                *last_whitelist_exception_time.write().await = Utc::now();
                            } else {
                                whitelisted_sessions.push(session_info.session.clone());
                            }
                        }
                    }
                } else {
                    // The domain has not been resolved yet, use the IP address instead
                    if !is_session_in_whitelist(
                        None,
                        Some(&session_info.session.dst_ip.to_string()),
                        session_info.session.dst_port,
                        session_info.session.protocol.to_string().as_str(),
                        whitelist_name,
                        session_info.dst_asn.as_ref().map(|asn| asn.as_number),
                        session_info
                            .dst_asn
                            .as_ref()
                            .map(|asn| asn.country.as_str()),
                        session_info.dst_asn.as_ref().map(|asn| asn.owner.as_str()),
                        session_info.l7.as_ref().map(|l7| l7.process_name.as_str()),
                    )
                    .await
                    {
                        trace!("Session {:?} failed whitelist check", key);
                        updated_exceptions.push(session_info.session.clone());
                        *last_whitelist_exception_time.write().await = Utc::now();
                    }
                }
            }
            // If one session is not whitelisted, set the whitelist conformance to false
            if !updated_exceptions.is_empty() {
                whitelist_conformance.store(false, Ordering::Relaxed);
            }
            // Set the is_whitelisted flag for each session
            for exception in updated_exceptions.iter() {
                if let Some(mut session) = sessions.get_mut(exception) {
                    session.value_mut().is_whitelisted = WhitelistState::NonConforming;
                } else {
                    error!("Session not found in sessions map");
                }
            }
            for session in whitelisted_sessions.iter() {
                if let Some(mut session_info) = sessions.get_mut(session) {
                    session_info.value_mut().is_whitelisted = WhitelistState::Conforming;
                } else {
                    error!("Session not found in sessions map");
                }
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
        } else {
            if !whitelist_name.is_empty() {
                error!("Invalid whitelist name: {}", whitelist_name);
            }
        }
    }

    // Only for current sessions
    async fn populate_domain_names(
        sessions: &DashMap<Session, SessionInfo>,
        resolver: &Option<Arc<LANScanResolver>>,
        dns_resolutions: &Arc<DashMap<IpAddr, String>>,
        current_sessions: &Arc<CustomRwLock<Vec<Session>>>,
    ) {
        let current_sessions_clone = current_sessions.read().await.clone();
        let mut dst_dns_resolution_count = 0;
        let mut dst_resolver_resolution_count = 0;

        for key in current_sessions_clone.iter() {
            // Clone necessary data to avoid holding lock across await
            let session_info = if let Some(session_info) = sessions.get(key) {
                session_info.clone()
            } else {
                error!("Session was not found for key: {:?}", key);
                continue;
            };

            // Prepare to collect updates
            let mut new_src_domain = session_info.src_domain.clone();
            let mut new_dst_domain = session_info.dst_domain.clone();

            // Check DNS resolution for source IP only if it's not a local IP
            if !crate::lanscan_ip::is_lan_ip(&session_info.session.src_ip) {
                if let Some(domain) = dns_resolutions.get(&session_info.session.src_ip) {
                    trace!("Using DNS resolution for src_ip: {:?}", domain);
                    new_src_domain = Some(domain.clone());
                } else {
                    // If not in dns_resolutions, use the resolver
                    if let Some(resolver) = resolver.as_ref() {
                        let domain = resolver.get_resolved_ip(&session_info.session.src_ip).await;
                        if let Some(domain) = domain {
                            trace!(
                                "Using resolver for src_ip: {:?}",
                                session_info.session.src_ip
                            );
                            new_src_domain = Some(domain);
                        } else {
                            resolver
                                .add_ip_to_resolver(&session_info.session.src_ip)
                                .await;
                        }
                    }
                }
            } else {
                // Use mDNS for local IPs
                if let Some(src_domain) =
                    mdns_get_hostname_by_ip(&session_info.session.src_ip).await
                {
                    trace!("Using mDNS for src_ip: {:?}", src_domain);
                    new_src_domain = Some(src_domain);
                }
            }

            // Check DNS resolution for destination IP only if it's not a local IP
            if !crate::lanscan_ip::is_lan_ip(&session_info.session.dst_ip) {
                if let Some(domain) = dns_resolutions.get(&session_info.session.dst_ip) {
                    trace!("Using DNS resolution for dst_ip: {:?}", domain);
                    new_dst_domain = Some(domain.clone());
                    dst_dns_resolution_count += 1;
                } else {
                    // If not in dns_resolutions, use the resolver
                    if let Some(resolver) = resolver.as_ref() {
                        let domain = resolver.get_resolved_ip(&session_info.session.dst_ip).await;
                        if let Some(domain) = domain {
                            trace!(
                                "Using resolver for dst_ip: {:?}",
                                session_info.session.dst_ip
                            );
                            new_dst_domain = Some(domain);
                            dst_resolver_resolution_count += 1;
                        } else {
                            resolver
                                .add_ip_to_resolver(&session_info.session.dst_ip)
                                .await;
                        }
                    }
                }
            } else {
                // Use mDNS for local IPs
                if let Some(dst_domain) =
                    mdns_get_hostname_by_ip(&session_info.session.dst_ip).await
                {
                    trace!("Using mDNS for dst_ip: {:?}", dst_domain);
                    new_dst_domain = Some(dst_domain);
                }
            }

            // Update the session info after await points
            let key_clone = key.clone();
            let new_src_domain_clone = new_src_domain.clone();
            let new_dst_domain_clone = new_dst_domain.clone();
            if let Some(mut session_info_mut) = sessions.get_mut(&key_clone) {
                session_info_mut.src_domain = new_src_domain_clone;
                session_info_mut.dst_domain = new_dst_domain_clone;
            }
        }
        // Compute domain % of successful resolutions
        let total_sessions = sessions.len();
        let domain_success_rate = (dst_dns_resolution_count + dst_resolver_resolution_count) as f64
            / total_sessions as f64
            * 100.0;
        let dns_success_rate = dst_dns_resolution_count as f64 / total_sessions as f64 * 100.0;
        let resolver_success_rate =
            dst_resolver_resolution_count as f64 / total_sessions as f64 * 100.0;
        info!(
            "Destination domain success rate: {:.2}% (DNS: {:.2}% + Resolver: {:.2}%)",
            domain_success_rate, dns_success_rate, resolver_success_rate
        );
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
        let l7_success_rate = (successful_resolutions as f64 / total_sessions as f64) * 100.0;
        info!("L7 success rate: {:.2}%", l7_success_rate);
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

    // Get historical sessions as a vector of SessionInfo
    pub async fn get_sessions(&self) -> Vec<SessionInfo> {
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
        self.whitelist_conformance.load(Ordering::Relaxed)
    }

    pub async fn get_whitelist_exceptions(&self) -> Vec<SessionInfo> {
        let mut exceptions = Vec::new();
        for key in self.whitelist_exceptions.read().await.iter() {
            if let Some(entry) = self.sessions.get(key) {
                exceptions.push(entry.clone());
            }
        }
        exceptions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::*;
    use crate::lanscan_interface::get_valid_network_interfaces;
    use pnet_packet::tcp::TcpFlags;
    use serial_test::serial;
    use std::net::{IpAddr, Ipv4Addr};
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
        )
        .await;

        process_parsed_packet(
            response_packet,
            &capture.sessions,
            &capture.current_sessions,
            &self_ips,
            &capture.filter,
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
        // Updated to reflect the new dns_packet_processor

        let mut capture = LANScanCapture::new();
        capture.set_whitelist("github").await;

        // Do not call capture.start().await

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
            uid: Uuid::new_v4().to_string(),
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
    }

    #[tokio::test]
    #[serial]
    async fn test_update_sessions_status_added() {
        let mut capture = LANScanCapture::new();
        capture.set_filter(SessionFilter::All).await; // Include all sessions in the filter

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
            start_time: now - ChronoDuration::seconds(10),
            end_time: None,
            last_activity: now - ChronoDuration::seconds(10),
            // History of bytes
            inbound_bytes: 5000,
            outbound_bytes: 5000,
            orig_pkts: 50,
            resp_pkts: 50,
            orig_ip_bytes: 0,
            resp_ip_bytes: 0,
            history: String::new(),
            conn_state: None,
            missed_bytes: 0,
            uid: Uuid::new_v4().to_string(),
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
        };

        capture.sessions.insert(session.clone(), session_info);
        capture.current_sessions.write().await.push(session.clone());

        // Simulate activity by updating last_activity and bytes transferred
        if let Some(mut entry) = capture.sessions.get_mut(&session) {
            entry.stats.last_activity = now;
            entry.stats.outbound_bytes += 5000; // Added 5000 bytes outbound
            entry.stats.inbound_bytes += 10000; // Added 10000 bytes inbound
        }

        LANScanCapture::update_sessions_status(&capture.sessions, &capture.current_sessions).await;

        // Check current sessions
        let current_sessions = capture.get_current_sessions().await;
        capture.current_sessions.write().await.push(session.clone());

        assert_eq!(current_sessions.len(), 1);
        assert_eq!(current_sessions[0].session, session);
        assert!(current_sessions[0].status.active);
        assert!(current_sessions[0].status.added);
        assert!(current_sessions[0].status.activated);
    }

    #[tokio::test]
    #[serial]
    async fn test_update_sessions_status_activated() {
        let mut capture = LANScanCapture::new();
        capture.set_filter(SessionFilter::All).await; // Include all sessions in the filter

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
            // Old start time
            start_time: now - ChronoDuration::seconds(1800),
            end_time: None,
            last_activity: now - ChronoDuration::seconds(1800),
            inbound_bytes: 5000,
            outbound_bytes: 5000,
            orig_pkts: 50,
            resp_pkts: 50,
            orig_ip_bytes: 0,
            resp_ip_bytes: 0,
            history: String::new(),
            conn_state: None,
            missed_bytes: 0,
            uid: Uuid::new_v4().to_string(),
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
        };

        capture.sessions.insert(session.clone(), session_info);
        capture.current_sessions.write().await.push(session.clone());

        // Check the filter - removing this creates a race condition
        assert_eq!(capture.filter.read().await.clone(), SessionFilter::All);
        let current_sessions = capture.get_current_sessions().await;

        LANScanCapture::update_sessions_status(&capture.sessions, &capture.current_sessions).await;

        assert_eq!(current_sessions.len(), 1);
        assert_eq!(current_sessions[0].session, session);
        assert!(!current_sessions[0].status.active);
        assert!(!current_sessions[0].status.added);
        assert!(!current_sessions[0].status.activated);

        // Simulate activity
        if let Some(mut entry) = capture.sessions.get_mut(&session) {
            entry.stats.last_activity = now;
            entry.stats.outbound_bytes += 5000; // Added 5000 bytes outbound
            entry.stats.inbound_bytes += 10000; // Added 10000 bytes inbound
        }

        LANScanCapture::update_sessions_status(&capture.sessions, &capture.current_sessions).await;

        // Check current sessions
        let current_sessions = capture.get_current_sessions().await;

        assert_eq!(current_sessions.len(), 1);
        assert_eq!(current_sessions[0].session, session);
        assert!(current_sessions[0].status.active);
        assert!(!current_sessions[0].status.added);
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
                uid: Uuid::new_v4().to_string(),
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
            };

            capture.sessions.insert(session.clone(), session_info);
            capture.current_sessions.write().await.push(session.clone());
        }

        // Run whitelist check
        LANScanCapture::check_whitelisted_destinations(
            "github",
            &capture.whitelist_conformance,
            &capture.whitelist_exceptions,
            &capture.sessions,
            &capture.current_sessions,
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
    async fn test_valid_interfaces_have_devices() {
        // Only if admin
        if !get_admin_status() {
            return;
        }

        // Get the valid network interfaces (LANScanInterfaces)
        let valid_interfaces = get_valid_network_interfaces();
        assert!(
            !valid_interfaces.interfaces.is_empty(),
            "No valid network interfaces found"
        );

        // Create a new capture instance to use its get_device_from_interface method
        let capture = LANScanCapture::new();

        // For each valid interface, try to fetch a pcap::Device.
        // The call must succeed for every interface.
        for iface in valid_interfaces.interfaces.iter() {
            let device_result = capture.get_device_from_interface(&iface).await;
            assert!(
                device_result.is_ok(),
                "Device not found for interface: {} in {:?}",
                iface.name,
                pcap::Device::list()
            );
            let device = device_result.unwrap();
            println!("Found device for interface {}: {}", iface.name, device.name);
        }
    }
}
