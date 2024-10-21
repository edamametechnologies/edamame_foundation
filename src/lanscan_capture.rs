use crate::lanscan_asn::*;
use crate::lanscan_interface::get_default_interface;
use crate::lanscan_l7::LANScanL7;
use crate::lanscan_mdns::*;
use crate::lanscan_port_vulns::get_name_from_port;
use crate::lanscan_resolver::LANScanResolver;
use crate::lanscan_sessions::*;
use crate::runtime::async_spawn;
use crate::rwlock::CustomRwLock;
use crate::whitelists::*;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use dns_parser::Packet as DnsPacket;
#[cfg(not(all(
    any(target_os = "macos", target_os = "linux"),
    feature = "asyncpacketcapture"
)))]
use futures::StreamExt;
#[cfg(all(
    any(target_os = "macos", target_os = "linux"),
    feature = "asyncpacketcapture"
))]
use pcap::Capture;
#[cfg(not(all(
    any(target_os = "macos", target_os = "linux"),
    feature = "asyncpacketcapture"
)))]
use pcap::{Capture, Packet, PacketCodec};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::{TcpFlags, TcpPacket};
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet as PnetPacket;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(not(all(
    any(target_os = "macos", target_os = "linux"),
    feature = "asyncpacketcapture"
)))]
use tokio::select;
use tokio::task::JoinHandle;
#[cfg(not(all(
    any(target_os = "macos", target_os = "linux"),
    feature = "asyncpacketcapture"
)))]
use tokio::time::interval;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

// A session is considered active if it has had activity in the last 60 seconds
static CONNECTION_ACTIVITY_TIMEOUT: ChronoDuration = ChronoDuration::seconds(60);
// A session is considered current if it has been active in the last 300 seconds
static CONNECTION_CURRENT_TIMEOUT: ChronoDuration = ChronoDuration::seconds(300);
// Current whitelist exceptions
static WHITELIST_EXCEPTION_TIMEOUT: ChronoDuration = CONNECTION_CURRENT_TIMEOUT;
// Keep 2 hours of history
static CONNECTION_RETENTION_TIMEOUT: ChronoDuration = ChronoDuration::seconds(60 * 60 * 2);

#[derive(Debug)]
enum ParsedPacket {
    SessionPacket(SessionPacketData),
    DnsPacket(DnsPacketData),
}

#[derive(Debug)]
struct SessionPacketData {
    session: Session,
    packet_length: usize,
    ip_packet_length: usize,
    flags: Option<u8>,
}

#[derive(Debug)]
struct DnsPacketData {
    dns_payload: Vec<u8>,
}

pub struct LANScanCapture {
    interface: Arc<CustomRwLock<String>>,
    capture_task_handles: Arc<DashMap<String, TaskHandle>>,
    sessions: Arc<DashMap<Session, SessionInfo>>,
    current_sessions: Arc<CustomRwLock<Vec<Session>>>,
    current_sessions_handle: Option<TaskHandle>,
    resolver: Arc<Option<LANScanResolver>>,
    resolver_handle: Option<TaskHandle>,
    l7: Arc<Option<LANScanL7>>,
    l7_handle: Option<TaskHandle>,
    dns_resolutions: Arc<DashMap<IpAddr, String>>,
    whitelist_check_handle: Option<TaskHandle>,
    whitelist_name: Arc<CustomRwLock<String>>,
    whitelist_conformance: Arc<AtomicBool>,
    last_whitelist_exception_time: Arc<CustomRwLock<DateTime<Utc>>>,
    whitelist_exceptions: Arc<CustomRwLock<Vec<Session>>>,
    filter: Arc<CustomRwLock<SessionFilter>>,
}

struct TaskHandle {
    handle: JoinHandle<()>,
    stop_flag: Arc<AtomicBool>,
}

impl LANScanCapture {
    pub fn new() -> Self {
        debug!("Creating new LANScanCapture");
        Self {
            interface: Arc::new(CustomRwLock::new("".to_string())),
            capture_task_handles: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            current_sessions: Arc::new(CustomRwLock::new(Vec::new())),
            current_sessions_handle: None,
            resolver: Arc::new(None),
            resolver_handle: None,
            l7: Arc::new(None),
            l7_handle: None,
            dns_resolutions: Arc::new(DashMap::new()),
            whitelist_check_handle: None,
            whitelist_name: Arc::new(CustomRwLock::new("".to_string())),
            whitelist_conformance: Arc::new(AtomicBool::new(true)),
            last_whitelist_exception_time: Arc::new(CustomRwLock::new(DateTime::<Utc>::from(
                std::time::UNIX_EPOCH,
            ))),
            whitelist_exceptions: Arc::new(CustomRwLock::new(Vec::new())),
            filter: Arc::new(CustomRwLock::new(SessionFilter::GlobalOnly)),
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

    pub async fn start(&mut self, interface: &str) {
        info!("Starting LANScanCapture");

        // If the capture task is already running, return
        if !self.capture_task_handles.is_empty() {
            warn!("Capture task already running");
            return;
        }

        // Start mDNS task
        mdns_start().await;

        // Set the interface
        *self.interface.write().await = interface.to_string();

        // Start tasks
        // First start the capture task to populate the sessions map
        self.start_capture_task().await;
        // Then start DNS/L7 resolution tasks
        self.start_resolver_task().await;
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
        self.stop_resolver_task().await;
        // Then stop the current sessions task
        self.stop_current_sessions_task().await;
        // Finally stop the whitelist check task
        self.stop_whitelist_check_task().await;

        // Don't clear the state this is a pause rather than a stop

        // Don't stop the mDNS task as it's shared with other modules
    }

    pub async fn restart(&mut self, interface: &str) {
        // Only restart if capturing and if the interface string has changed
        if !self.is_capturing().await || !self.interface.read().await.eq(interface) {
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
            self.resolver = Arc::new(Some(LANScanResolver::new()));
        }

        // Start the resolver if it exists
        if let Some(resolver) = Arc::get_mut(&mut self.resolver).and_then(|r| r.as_mut()) {
            resolver.start().await;
        }

        let resolver: Arc<Option<LANScanResolver>> = self.resolver.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let dns_resolutions = self.dns_resolutions.clone();
        let sessions = self.sessions.clone();
        let current_sessions = self.current_sessions.clone();

        let stop_flag_clone = stop_flag.clone();
        let handle = async_spawn(async move {
            loop {
                trace!("Domain name population started");
                Self::populate_domain_names(
                    &sessions,
                    &resolver,
                    &dns_resolutions,
                    &current_sessions,
                )
                .await;
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
        if let Some(resolver) = Arc::get_mut(&mut self.resolver).and_then(|r| r.as_mut()) {
            resolver.stop().await;
        }
    }

    async fn start_l7_task(&mut self) {
        // Create L7 resolver if it doesn't exist
        if self.l7.is_none() {
            self.l7 = Arc::new(Some(LANScanL7::new()));
        }

        // Start the L7 resolver if it exists
        if let Some(l7) = Arc::get_mut(&mut self.l7).and_then(|l| l.as_mut()) {
            l7.start().await;
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
        if let Some(l7) = Arc::get_mut(&mut self.l7).and_then(|l| l.as_mut()) {
            l7.stop().await;
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
                trace!("Whitelist check started");
                let whitelist_name = whitelist_name.read().await.clone();
                if !whitelist_name.is_empty() {
                    Self::check_whitelisted_destinations(
                        &whitelist_name,
                        &whitelist_conformance,
                        &whitelist_exceptions,
                        &sessions,
                        &current_sessions,
                        &last_whitelist_exception_time,
                    )
                    .await;
                    info!("Whitelist check completed");
                }
                if stop_flag.load(Ordering::Relaxed) {
                    break;
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

    async fn start_capture_task(&mut self) {
        // Read and split the interfaces by comma, trimming whitespace
        let interfaces_str = self.interface.read().await.clone();
        let mut interfaces: Vec<String> = interfaces_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if interfaces.is_empty() {
            info!("No valid interfaces provided for capture, using default interface discovery");
            interfaces = match get_default_interface() {
                Some((_, _, name)) => vec![name],
                None => {
                    error!("No default interface detected");
                    return;
                }
            };

            info!("Using default interfaces: {:?}", interfaces);
        } else {
            info!("Provided capture interfaces: {:?}", interfaces);
        }

        for interface in interfaces {
            info!("Initializing capture task for {}", interface);

            // Clone shared resources for each capture task
            let sessions = self.sessions.clone();
            let current_sessions = self.current_sessions.clone();
            let dns_resolutions = self.dns_resolutions.clone();
            let filter = self.filter.clone();

            // Create a new stop flag for this interface's capture task
            let stop_flag = Arc::new(AtomicBool::new(false));
            let stop_flag_clone = stop_flag.clone();

            // Clone the interface name for the async move block
            let interface_clone = interface.clone();

            // Spawn the capture task
            let handle = async_spawn(async move {
                let device_list = match pcap::Device::list() {
                    Ok(list) => list,
                    Err(e) => {
                        error!("Failed to get device list for {}: {}", interface_clone, e);
                        return;
                    }
                };

                info!("Capture devices list: {:?}", device_list);

                // Find the device matching the current interface
                // Match the default interface name in the device list
                let device = if let Some(device_in_list) =
                    device_list.iter().find(|dev| dev.name == interface_clone)
                {
                    device_in_list.clone()
                } else {
                    error!("No default interface detected");
                    return;
                };

                info!("Starting packet capture on device {:?}", device);

                let mut cap = match Capture::from_device(interface_clone.as_str()) {
                    Ok(cap) => cap,
                    Err(e) => {
                        error!("Failed to create capture on device: {}", e);
                        return;
                    }
                };

                // Extract a vector of IP addresses from the device addresses
                let self_ips: Vec<_> = device
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

                #[cfg(all(
                    any(target_os = "macos", target_os = "linux"),
                    feature = "asyncpacketcapture"
                ))]
                {
                    info!("Using sync capture for {}", interface_clone);

                    while !stop_flag_clone.load(Ordering::Relaxed) {
                        match cap.next_packet() {
                            Ok(packet) => {
                                if let Some(parsed_packet) = Self::parse_packet_pcap(packet.data) {
                                    match parsed_packet {
                                        ParsedPacket::SessionPacket(cp) => {
                                            LANScanCapture::process_parsed_packet(
                                                cp,
                                                &sessions,
                                                &current_sessions,
                                                &self_ips,
                                                &filter,
                                            )
                                            .await;
                                        }
                                        ParsedPacket::DnsPacket(dp) => {
                                            Self::process_dns_packet(dp, &dns_resolutions);
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

                #[cfg(not(all(
                    any(target_os = "macos", target_os = "linux"),
                    feature = "asyncpacketcapture"
                )))]
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

                    loop {
                        select! {
                            _ = interval.tick() => {
                                if stop_flag_clone.load(Ordering::Relaxed) {
                                    info!("Stopping async capture task for {}", interface_clone);
                                    break;
                                }
                            }
                            packet_owned = packet_stream.next() => {
                                match packet_owned {
                                    Some(Ok(packet_owned)) => match LANScanCapture::parse_packet_pcap(&packet_owned.data) {
                                        Some(ParsedPacket::SessionPacket(cp)) => {
                                            LANScanCapture::process_parsed_packet(
                                                cp,
                                                &sessions,
                                                &current_sessions,
                                                &self_ips,
                                                &filter,
                                            )
                                            .await;
                                        }
                                        Some(ParsedPacket::DnsPacket(dp)) => {
                                            LANScanCapture::process_dns_packet(dp, &dns_resolutions);
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
            self.capture_task_handles
                .insert(interface.clone(), TaskHandle { handle, stop_flag });
        }
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

                if let Some(dst_domain) = session_info.dst_domain {
                    if dst_domain == "Unknown".to_string() {
                        // The domain has not been resolved, use the IP address instead
                        let destination = session_info.session.dst_ip.to_string();
                        if !is_destination_in_whitelist(
                            Some(&destination),
                            session_info.session.dst_port,
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
                    } else {
                        // The domain has been resolved
                        if !is_destination_in_whitelist(
                            Some(&dst_domain),
                            session_info.session.dst_port,
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
                } else {
                    // The domain has not been resolved yet, use the IP address instead
                    let destination = session_info.session.dst_ip.to_string();
                    if !is_destination_in_whitelist(
                        Some(&destination),
                        session_info.session.dst_port,
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
            // Clear the whitelist_conformance if it's been more than 600 seconds
            if Utc::now()
                > *last_whitelist_exception_time.read().await + WHITELIST_EXCEPTION_TIMEOUT
            {
                info!(
                    "Clearing whitelist conformance after no activity for {} seconds",
                    WHITELIST_EXCEPTION_TIMEOUT.num_seconds()
                );
                whitelist_conformance.store(true, Ordering::Relaxed);
            }
        } else {
            if whitelist_name != "" {
                error!("Invalid whitelist name: {}", whitelist_name);
            }
        }
    }

    // Only for current sessions
    async fn populate_domain_names(
        sessions: &DashMap<Session, SessionInfo>,
        resolver: &Arc<Option<LANScanResolver>>,
        dns_resolutions: &Arc<DashMap<IpAddr, String>>,
        current_sessions: &Arc<CustomRwLock<Vec<Session>>>,
    ) {
        let current_sessions_clone = current_sessions.read().await.clone();

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

            // Check DNS resolution for source IP
            if let Some(domain) = dns_resolutions.get(&session_info.session.src_ip) {
                trace!("Using DNS resolution for src_ip: {:?}", domain);
                new_src_domain = Some(domain.clone());
            } else {
                // If not in dns_resolutions, use the resolver (only for eligible IPs)
                if !is_local_ip(&session_info.session.src_ip) {
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
                } else {
                    // Use mDNS for local IPs
                    if let Some(src_domain) =
                        mdns_get_hostname_by_ip(&session_info.session.src_ip).await
                    {
                        trace!("Using mDNS for src_ip: {:?}", src_domain);
                        new_src_domain = Some(src_domain);
                    }
                }
            }

            // Check DNS resolution for destination IP
            if let Some(domain) = dns_resolutions.get(&session_info.session.dst_ip) {
                trace!("Using DNS resolution for dst_ip: {:?}", domain);
                new_dst_domain = Some(domain.clone());
            } else {
                if !is_local_ip(&session_info.session.dst_ip) {
                    if let Some(resolver) = resolver.as_ref() {
                        let domain = resolver.get_resolved_ip(&session_info.session.dst_ip).await;
                        if let Some(domain) = domain {
                            trace!(
                                "Using resolver for dst_ip: {:?}",
                                session_info.session.dst_ip
                            );
                            new_dst_domain = Some(domain);
                        } else {
                            resolver
                                .add_ip_to_resolver(&session_info.session.dst_ip)
                                .await;
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
            }

            // Update the session info after await points
            if let Some(mut session_info_mut) = sessions.get_mut(key) {
                session_info_mut.src_domain = new_src_domain;
                session_info_mut.dst_domain = new_dst_domain;
            }
        }
    }

    // Populate L7
    async fn populate_l7(
        sessions: &DashMap<Session, SessionInfo>,
        l7: &Arc<Option<LANScanL7>>,
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
                if let Some(mut session_info_mut) = sessions.get_mut(key) {
                    if let Some(l7_resolution) = l7_resolution {
                        if let Some(l7_data) = l7_resolution.l7 {
                            session_info_mut.l7 = Some(l7_data.clone());
                            trace!("Updated L7 data for session {:?}: {:?}", key, l7_data);
                        }
                    }
                }
            }
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
            let active =
                session_info.stats.last_activity > Utc::now() - CONNECTION_ACTIVITY_TIMEOUT;
            let added = session_info.stats.start_time > Utc::now() - CONNECTION_ACTIVITY_TIMEOUT;
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
            if Utc::now() < session_info.stats.last_activity + CONNECTION_CURRENT_TIMEOUT {
                updated_current_sessions.push(session_info.session.clone());
            }

            // Flag sessions that are older than the retention timeout
            if Utc::now() > session_info.stats.last_activity + CONNECTION_RETENTION_TIMEOUT {
                sessions_to_remove.push(key.clone());
            }
        }

        // Update the current sessions
        {
            let mut current_sessions_guard = current_sessions.write().await;
            let _old_value =
                std::mem::replace(&mut *current_sessions_guard, updated_current_sessions);
        }

        // Purge the sessions that are older than the retention timeout
        for key in sessions_to_remove.iter() {
            sessions.remove(key);
        }
    }

    // Get historical sessions as a vector of SessionInfo
    // TODO: specify a time range
    pub async fn get_sessions(&self) -> Vec<SessionInfo> {
        let mut sessions_vec = Vec::new();
        let filter = self.filter.read().await;
        for entry in self.sessions.iter() {
            let mut session_info = entry.clone();
            // Remove the "Unkown" flag from the domain
            if session_info.dst_domain == Some("Unknown".to_string()) {
                session_info.dst_domain = None;
            }
            // Apply filter
            if *filter == SessionFilter::All {
                sessions_vec.push(session_info);
            } else if *filter == SessionFilter::LocalOnly {
                if entry.is_local_src && entry.is_local_dst {
                    sessions_vec.push(session_info);
                }
            } else if *filter == SessionFilter::GlobalOnly {
                if !entry.is_local_src || !entry.is_local_dst {
                    sessions_vec.push(session_info);
                }
            }
        }
        sessions_vec
    }

    // Active sessions as a vector of SessionInfo
    pub async fn get_current_sessions(&self) -> Vec<SessionInfo> {
        // Get the sessions from the DashMap that match the keys in the current_sessions Vec
        let filter = self.filter.read().await;
        let mut current_sessions_vec = Vec::new();
        for key in self.current_sessions.read().await.iter() {
            if let Some(entry) = self.sessions.get(key) {
                let mut session_info = entry.clone();
                // Remove the "Unknown" flag from the domain
                if session_info.dst_domain == Some("Unknown".to_string()) {
                    session_info.dst_domain = None;
                }
                // Apply filter
                if *filter == SessionFilter::All {
                    current_sessions_vec.push(session_info);
                } else if *filter == SessionFilter::LocalOnly {
                    if session_info.is_local_src && session_info.is_local_dst {
                        current_sessions_vec.push(session_info);
                    }
                } else if *filter == SessionFilter::GlobalOnly {
                    if !session_info.is_local_src || !session_info.is_local_dst {
                        current_sessions_vec.push(session_info);
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

    async fn process_parsed_packet(
        parsed_packet: SessionPacketData,
        sessions: &Arc<DashMap<Session, SessionInfo>>,
        current_sessions: &Arc<CustomRwLock<Vec<Session>>>,
        self_ips: &Vec<IpAddr>,
        filter: &Arc<CustomRwLock<SessionFilter>>,
    ) {
        // Set the time to now, we could use the time provided by pcap too but we don't want to bother converting to UTC
        let now = Utc::now();

        let key = parsed_packet.session.clone();
        let reverse_key = Session {
            protocol: parsed_packet.session.protocol.clone(),
            src_ip: parsed_packet.session.dst_ip,
            src_port: parsed_packet.session.dst_port,
            dst_ip: parsed_packet.session.src_ip,
            dst_port: parsed_packet.session.src_port,
        };

        // Update session stats
        if let Some(mut info) = sessions.get_mut(&key) {
            let stats: &mut SessionStats = &mut info.stats;
            stats.last_activity = now.clone();
            // Packet from originator to responder
            stats.outbound_bytes += parsed_packet.packet_length as u64;
            stats.orig_pkts += 1;
            stats.orig_ip_bytes += parsed_packet.ip_packet_length as u64;
            // Update history
            if let Some(flags) = parsed_packet.flags {
                let c = Self::map_tcp_flags(flags, parsed_packet.packet_length, true);
                stats.history.push(c);
                if (flags & (TcpFlags::FIN | TcpFlags::RST)) != 0 && stats.end_time.is_none() {
                    stats.end_time = Some(now.clone());
                    stats.conn_state = Some(Self::determine_conn_state(&stats.history));
                }
            }
        } else if let Some(mut info) = sessions.get_mut(&reverse_key) {
            // Packet from responder to originator
            let stats: &mut SessionStats = &mut info.stats;
            stats.last_activity = now.clone();
            stats.inbound_bytes += parsed_packet.packet_length as u64;
            stats.resp_pkts += 1;
            stats.resp_ip_bytes += parsed_packet.ip_packet_length as u64;
            // Update history
            if let Some(flags) = parsed_packet.flags {
                let c = Self::map_tcp_flags(flags, parsed_packet.packet_length, false);
                stats.history.push(c);
                if (flags & (TcpFlags::FIN | TcpFlags::RST)) != 0 && stats.end_time.is_none() {
                    stats.end_time = Some(Utc::now());
                    stats.conn_state = Some(Self::determine_conn_state(&stats.history));
                }
            }
        } else {
            // Neither key nor reverse key found, new session
            let uid = Uuid::new_v4().to_string();
            let mut stats = SessionStats {
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
                uid,
            };

            // Check if the session is local
            let is_local_src = is_local_ip(&parsed_packet.session.src_ip);
            let is_local_dst = is_local_ip(&parsed_packet.session.dst_ip);

            // Apply filter here for performance reasons. This means that we won't keep the history of filtered sessions.
            let filter = filter.read().await.clone();
            if filter == SessionFilter::LocalOnly {
                if !is_local_src || !is_local_dst {
                    return;
                }
            } else if filter == SessionFilter::GlobalOnly {
                if is_local_src || is_local_dst {
                    return;
                }
            }

            // Check if the session is self by comparing to the pcap interface IP
            let is_self_src = self_ips.contains(&parsed_packet.session.src_ip);
            let is_self_dst = self_ips.contains(&parsed_packet.session.dst_ip);

            // This is the first packet, we need to determine the direction of the session
            // Check if the source port is a known service port and the destination port is not a known service port
            let key = if !get_name_from_port(parsed_packet.session.src_port)
                .await
                .is_empty()
                && get_name_from_port(parsed_packet.session.dst_port)
                    .await
                    .is_empty()
            {
                // The key is reverse_key
                reverse_key
            } else {
                // We assume the packet is from the originator to the responder
                // The key is key
                key
            };

            // Update session stats
            stats.last_activity = Utc::now();
            // Packet from originator to responder
            stats.outbound_bytes += parsed_packet.packet_length as u64;
            stats.orig_pkts += 1;
            stats.orig_ip_bytes += parsed_packet.ip_packet_length as u64;

            // Update history
            if let Some(flags) = parsed_packet.flags {
                let c = Self::map_tcp_flags(flags, parsed_packet.packet_length, true);
                stats.history.push(c);
            }
            let key_clone = key.clone();
            trace!("New session: {:?}", key_clone);

            // Query the ASN database for non-local addresses
            let src_asn = if !is_local_ip(&key.src_ip) {
                get_asn(key.src_ip).await
            } else {
                None
            };
            let dst_asn = if !is_local_ip(&key.dst_ip) {
                get_asn(key.dst_ip).await
            } else {
                None
            };

            // Get the service from the destination port
            let final_dst_service = get_name_from_port(key.dst_port).await;

            // Set initial status
            let status = SessionStatus {
                active: true,
                added: true,
                activated: false,
                deactivated: false,
            };

            sessions.insert(
                key.clone(),
                SessionInfo {
                    session: key,
                    stats,
                    status,
                    is_local_src,
                    is_local_dst,
                    is_self_src,
                    is_self_dst,
                    src_domain: None,
                    dst_domain: None,
                    dst_service: if final_dst_service.is_empty() {
                        None
                    } else {
                        Some(final_dst_service)
                    },
                    l7: None,
                    src_asn,
                    dst_asn,
                    // Whitelisted by default
                    is_whitelisted: WhitelistState::Unknown,
                },
            );
            // Add to current sessions
            current_sessions.write().await.push(key_clone);
        }
    }

    fn determine_conn_state(history: &str) -> String {
        if history.contains('S')
            && history.contains('H')
            && history.contains('F')
            && history.contains('f')
        {
            "SF".to_string()
        } else if history.contains('S') && !history.contains('h') && !history.contains('r') {
            "S0".to_string()
        } else if history.contains('R') || history.contains('r') {
            "REJ".to_string()
        } else if history.contains('S')
            && history.contains('H')
            && !history.contains('F')
            && !history.contains('f')
        {
            "S1".to_string()
        } else {
            "-".to_string()
        }
    }

    fn map_tcp_flags(flags: u8, packet_length: usize, is_originator: bool) -> char {
        if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK == 0 {
            if is_originator {
                'S'
            } else {
                's'
            }
        } else if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
            if is_originator {
                'H'
            } else {
                'h'
            }
        } else if flags & TcpFlags::FIN != 0 {
            if is_originator {
                'F'
            } else {
                'f'
            }
        } else if flags & TcpFlags::RST != 0 {
            if is_originator {
                'R'
            } else {
                'r'
            }
        } else if packet_length > 0 {
            if is_originator {
                '>'
            } else {
                '<'
            }
        } else if flags & TcpFlags::ACK != 0 {
            if is_originator {
                'A'
            } else {
                'a'
            }
        } else {
            '-'
        }
    }

    fn process_dns_packet(
        dns_packet_data: DnsPacketData,
        dns_resolutions: &Arc<DashMap<IpAddr, String>>,
    ) {
        match DnsPacket::parse(&dns_packet_data.dns_payload) {
            Ok(dns_packet) => {
                // Process the DNS packet
                // If it's a response, extract the answers
                if !dns_packet.answers.is_empty() {
                    for answer in dns_packet.answers {
                        if let dns_parser::rdata::RData::A(ipv4_addr) = answer.data {
                            let ip_addr = IpAddr::V4(ipv4_addr.0);
                            let domain_name = answer.name.to_string();
                            // Exclude "myip.opendns.com"
                            if domain_name != "myip.opendns.com" {
                                trace!(
                                    "DNS resolution (using capture): {} -> {}",
                                    ip_addr,
                                    domain_name
                                );
                                dns_resolutions.insert(ip_addr, domain_name);
                            }
                        } else if let dns_parser::rdata::RData::AAAA(ipv6_addr) = answer.data {
                            let ip_addr = IpAddr::V6(ipv6_addr.0);
                            let domain_name = answer.name.to_string();
                            // Exclude "myip.opendns.com"
                            if domain_name != "myip.opendns.com" {
                                trace!(
                                    "DNS resolution (using capture): {} -> {}",
                                    ip_addr,
                                    domain_name
                                );
                                dns_resolutions.insert(ip_addr, domain_name);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                trace!("Failed to parse DNS packet: {}", e);
            }
        }
    }

    fn parse_packet_pcap(packet_data: &[u8]) -> Option<ParsedPacket> {
        let ethernet = EthernetPacket::new(packet_data)?;
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4 = Ipv4Packet::new(ethernet.payload())?;
                let ip_packet_length = ipv4.get_total_length() as usize;
                let next_protocol = ipv4.get_next_level_protocol();
                match next_protocol {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp = TcpPacket::new(ipv4.payload())?;
                        let src_ip = IpAddr::V4(ipv4.get_source());
                        let dst_ip = IpAddr::V4(ipv4.get_destination());
                        let src_port = tcp.get_source();
                        let dst_port = tcp.get_destination();
                        let flags = tcp.get_flags(); // flags is u8
                        let packet_length = tcp.payload().len();

                        if src_port == 53 || dst_port == 53 {
                            // This is DNS over TCP
                            let dns_payload = tcp.payload().to_vec();
                            trace!("Found DNS over TCP for IPv4: {:?}", dns_payload);
                            return Some(ParsedPacket::DnsPacket(DnsPacketData { dns_payload }));
                        }

                        let session = Session {
                            protocol: Protocol::TCP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };

                        Some(ParsedPacket::SessionPacket(SessionPacketData {
                            session,
                            packet_length,
                            ip_packet_length,
                            flags: Some(flags),
                        }))
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp = UdpPacket::new(ipv4.payload())?;
                        let src_ip = IpAddr::V4(ipv4.get_source());
                        let dst_ip = IpAddr::V4(ipv4.get_destination());
                        let src_port = udp.get_source();
                        let dst_port = udp.get_destination();
                        let packet_length = udp.payload().len();

                        if src_port == 53 || dst_port == 53 {
                            // This is DNS over UDP
                            let dns_payload = udp.payload().to_vec();
                            trace!("Found DNS over UDP for IPv4: {:?}", dns_payload);
                            return Some(ParsedPacket::DnsPacket(DnsPacketData { dns_payload }));
                        }

                        let session = Session {
                            protocol: Protocol::UDP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };

                        Some(ParsedPacket::SessionPacket(SessionPacketData {
                            session,
                            packet_length,
                            ip_packet_length,
                            flags: None,
                        }))
                    }
                    _ => None,
                }
            }
            EtherTypes::Ipv6 => {
                let ipv6 = Ipv6Packet::new(ethernet.payload())?;
                let ip_packet_length = ipv6.get_payload_length() as usize + 40; // IPv6 header is 40 bytes
                let next_protocol = ipv6.get_next_header();
                match next_protocol {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp = TcpPacket::new(ipv6.payload())?;
                        let src_ip = IpAddr::V6(ipv6.get_source());
                        let dst_ip = IpAddr::V6(ipv6.get_destination());
                        let src_port = tcp.get_source();
                        let dst_port = tcp.get_destination();
                        let flags = tcp.get_flags(); // flags is u8
                        let packet_length = tcp.payload().len();

                        if src_port == 53 || dst_port == 53 {
                            // This is DNS over TCP
                            let dns_payload = tcp.payload().to_vec();
                            trace!("Found DNS over TCP for IPv6: {:?}", dns_payload);
                            return Some(ParsedPacket::DnsPacket(DnsPacketData { dns_payload }));
                        }

                        let session = Session {
                            protocol: Protocol::TCP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };

                        Some(ParsedPacket::SessionPacket(SessionPacketData {
                            session,
                            packet_length,
                            ip_packet_length,
                            flags: Some(flags),
                        }))
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp = UdpPacket::new(ipv6.payload())?;
                        let src_ip = IpAddr::V6(ipv6.get_source());
                        let dst_ip = IpAddr::V6(ipv6.get_destination());
                        let src_port = udp.get_source();
                        let dst_port = udp.get_destination();
                        let packet_length = udp.payload().len();

                        if src_port == 53 || dst_port == 53 {
                            // This is DNS over UDP
                            let dns_payload = udp.payload().to_vec();
                            trace!("Found DNS over UDP for IPv6: {:?}", dns_payload);
                            return Some(ParsedPacket::DnsPacket(DnsPacketData { dns_payload }));
                        }

                        let session = Session {
                            protocol: Protocol::UDP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };

                        Some(ParsedPacket::SessionPacket(SessionPacketData {
                            session,
                            packet_length,
                            ip_packet_length,
                            flags: None,
                        }))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_session_management() {
        let mut capture = LANScanCapture::new();
        capture.set_whitelist("cicd").await;
        capture.set_filter(SessionFilter::All).await; // Include all sessions in the filter

        // Do not call capture.start().await

        // Create a synthetic session packet data
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

        // Get self IPs (empty for testing)
        let self_ips = vec![];

        // Process the synthetic packet
        LANScanCapture::process_parsed_packet(
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

        let session_info = sessions[0].clone();
        let session = session_info.session.clone();
        let stats = session_info.stats.clone();

        // Check session details
        assert_eq!(session.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(session.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(stats.outbound_bytes, 100);
        assert_eq!(stats.orig_pkts, 1);
        assert_eq!(stats.history, "S");
    }

    #[tokio::test]
    async fn test_populate_domain_names() {
        let mut capture = LANScanCapture::new();
        capture.set_whitelist("cicd").await;

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

        // Insert a DNS resolution into dns_resolutions
        capture.dns_resolutions.insert(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            "dns.google".to_string(),
        );

        // Call populate_domain_names
        LANScanCapture::populate_domain_names(
            &capture.sessions,
            &capture.resolver,
            &capture.dns_resolutions,
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
            start_time: now - ChronoDuration::seconds(3600),
            end_time: None,
            last_activity: now - ChronoDuration::seconds(3600),
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
    async fn test_process_dns_packet() {
        let dns_payload = vec![
            // A minimal DNS response packet in bytes
            0x00, 0x00, // Transaction ID
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

        let dns_packet_data = DnsPacketData { dns_payload };

        let dns_resolutions = Arc::new(DashMap::new());

        LANScanCapture::process_dns_packet(dns_packet_data, &dns_resolutions);

        // Check that the DNS resolution was stored
        if let Some(domain) = dns_resolutions.get(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))) {
            assert_eq!(domain.as_str(), "www.google.com");
        } else {
            panic!("DNS resolution not found");
        };
    }
}
