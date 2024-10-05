use crate::lanscan_connections::*;
use crate::lanscan_l7::LANScanL7;
use crate::lanscan_mdns::*;
use crate::lanscan_resolver::LANScanResolver;
use crate::runtime::async_spawn;
use crate::rwlock::CustomRwLock;
use crate::whitelists::is_destination_in_whitelist;
use chrono::{DateTime, TimeDelta, Utc};
use dashmap::DashMap;
use dns_parser::Packet as DnsPacket;
use pcap::Capture;
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
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tracing::{error, info, trace};
use uuid::Uuid;
use lanscan_asn::*;

static CONNECTION_ACTIVITY_TIMEOUT: Duration = Duration::from_secs(600);
// 24 hours
static CONNECTION_RETENTION_TIMEOUT: Duration = Duration::from_secs(60 * 60 * 24);
static WHITELIST_EXCEPTION_TIMEOUT: TimeDelta = TimeDelta::seconds(600);

#[derive(Debug)]
enum ParsedPacket {
    ConnectionPacket(ConnectionPacketData),
    DnsPacket(DnsPacketData),
}

#[derive(Debug)]
struct ConnectionPacketData {
    connection: Connection,
    packet_length: usize,
    ip_packet_length: usize,
    flags: Option<u8>,
}

#[derive(Debug)]
struct DnsPacketData {
    dns_payload: Vec<u8>,
}

pub struct LANScanCapture {
    capture_task_handle: Option<TaskHandle>,
    connections: Arc<DashMap<Connection, ConnectionInfo>>,
    // Store the keys of active connections
    active_connections: Arc<CustomRwLock<Vec<Connection>>>,
    active_connections_handle: Option<TaskHandle>,
    // Resolver
    resolver: Arc<Option<LANScanResolver>>,
    resolver_handle: Option<TaskHandle>,
    // L7
    l7: Arc<Option<LANScanL7>>,
    l7_handle: Option<TaskHandle>,
    // Captured DNS resolutions
    dns_resolutions: Arc<DashMap<IpAddr, String>>,
    whitelist_check_handle: Option<TaskHandle>,
    whitelist_name: String,
    whitelist_conformance: Arc<AtomicBool>,
    last_whitelist_exception_time: Arc<CustomRwLock<DateTime<Utc>>>,
    // Store the keys of whitelist exceptions
    whitelist_exceptions: Arc<CustomRwLock<Vec<Connection>>>,
}

struct TaskHandle {
    handle: JoinHandle<()>,
    stop_flag: Arc<AtomicBool>,
}

impl LANScanCapture {
    pub fn new() -> Self {
        Self {
            capture_task_handle: None,
            connections: Arc::new(DashMap::new()),
            active_connections: Arc::new(CustomRwLock::new(Vec::new())),
            active_connections_handle: None,
            resolver: Arc::new(None),
            resolver_handle: None,
            l7: Arc::new(None),
            l7_handle: None,
            dns_resolutions: Arc::new(DashMap::new()),
            whitelist_check_handle: None,
            whitelist_name: "".to_string(),
            whitelist_conformance: Arc::new(AtomicBool::new(true)),
            last_whitelist_exception_time: Arc::new(CustomRwLock::new(Utc::now())),
            whitelist_exceptions: Arc::new(CustomRwLock::new(Vec::new())),
        }
    }

    async fn check_whitelisted_destinations(
        whitelist_name: &str,
        whitelist_conformance: &AtomicBool,
        whitelist_exceptions: &Arc<CustomRwLock<Vec<Connection>>>,
        connections: &DashMap<Connection, ConnectionInfo>,
        active_connections: &Arc<CustomRwLock<Vec<Connection>>>,
        last_whitelist_exception_time: &Arc<CustomRwLock<DateTime<Utc>>>,
    ) {
        let mut updated_exceptions = Vec::new();
        // Clone the active_connections to avoid holding the lock for too long
        let active_connections_clone = active_connections.read().await.clone();
        for key in active_connections_clone.iter() {
            if let Some(connection) = connections.get(key) {
                // If resolution is not complete, add to exceptions
                if let Some(dst_domain) = connection.dst_domain.clone() {
                    if dst_domain == "Unknown".to_string() {
                        let destination = connection.connection.dst_ip.to_string();
                        // Handle IP addresses that failed to resolve
                        if !is_destination_in_whitelist(
                            &destination,
                            connection.connection.dst_port,
                            whitelist_name,
                        )
                        .await
                        {
                            trace!("Connection {:?} failed whitelist check", key);
                            updated_exceptions.push(connection.connection.clone());
                            *last_whitelist_exception_time.write().await = Utc::now();
                        }
                    } else {
                        if !is_destination_in_whitelist(
                            &dst_domain,
                            connection.connection.dst_port,
                            whitelist_name,
                        )
                        .await
                        {
                            trace!("Connection {:?} failed whitelist check", key);
                            updated_exceptions.push(connection.connection.clone());
                            *last_whitelist_exception_time.write().await = Utc::now();
                        }
                    }
                }
            } else {
                error!("Connection not found in connections map");
            }
        }
        // If one connection is not whitelisted, set the whitelist conformance to false
        if !updated_exceptions.is_empty() {
            whitelist_conformance.store(false, Ordering::Relaxed);
        }
        // Set the is_whitelisted flag for each connection
        for exception in updated_exceptions.iter() {
            if let Some(mut connection) = connections.get_mut(&exception) {
                connection.value_mut().is_whitelisted = WhitelistState::NonConforming;
            } else {
                error!("Connection not found in connections map");
            }
        }
        // Merge the updated exceptions with the existing ones
        whitelist_exceptions
            .write()
            .await
            .extend(updated_exceptions);
        // Deduplicate the exceptions
        whitelist_exceptions
            .write()
            .await
            .sort_by_key(|k| k.clone());
        whitelist_exceptions
            .write()
            .await
            .dedup_by_key(|k| k.clone());

        info!(
            "Total whitelist exceptions: {}",
            whitelist_exceptions.read().await.len()
        );
        // Clear the whitelist_conformance if it's been more than 600 seconds
        if Utc::now() - *last_whitelist_exception_time.read().await > WHITELIST_EXCEPTION_TIMEOUT {
            info!(
                "Clearing whitelist conformance after no activity for {} seconds",
                WHITELIST_EXCEPTION_TIMEOUT.num_seconds()
            );
            whitelist_conformance.store(true, Ordering::Relaxed);
        }
    }

    // Only for active connections
    async fn populate_domain_names(
        connections: &DashMap<Connection, ConnectionInfo>,
        resolver: &Arc<Option<LANScanResolver>>,
        dns_resolutions: &Arc<DashMap<IpAddr, String>>,
        active_connections: &Arc<CustomRwLock<Vec<Connection>>>,
    ) {
        let active_connections_clone = active_connections.read().await.clone();

        for key in active_connections_clone.iter() {
            // Get a mutable reference to the connection info
            if let Some(mut connection_info) = connections.get_mut(key) {
                trace!(
                    "Populating domain names for connection: {:?}",
                    connection_info
                );

                // Check DNS resolution for source IP
                if let Some(domain) = dns_resolutions.get(&connection_info.connection.src_ip) {
                    trace!("Using DNS resolution for src_ip: {:?}", domain);
                    connection_info.src_domain = Some(domain.clone());
                } else {
                    // If not in dns_resolutions, use the resolver (only for eligible IPs)
                    if Self::is_eligible_ip(&connection_info.connection.src_ip) {
                        if let Some(resolver) = resolver.as_ref() {
                            let domain = resolver
                                .get_resolved_ip(&connection_info.connection.src_ip)
                                .await;
                            if let Some(domain) = domain {
                                trace!(
                                    "Using resolver for src_ip: {:?}",
                                    connection_info.connection.src_ip
                                );
                                connection_info.src_domain = Some(domain);
                            } else {
                                resolver
                                    .add_ip_to_resolver(&connection_info.connection.src_ip)
                                    .await;
                            }
                        }
                    } else {
                        // Use mDNS for local IPs
                        if let Some(src_domain) =
                            mdns_get_hostname_by_ip(&connection_info.connection.src_ip).await
                        {
                            trace!("Using mDNS for src_ip: {:?}", src_domain);
                            connection_info.src_domain = Some(src_domain);
                        }
                    }
                }

                // Check DNS resolution for destination IP
                if let Some(domain) = dns_resolutions.get(&connection_info.connection.dst_ip) {
                    trace!("Using DNS resolution for dst_ip: {:?}", domain);
                    connection_info.dst_domain = Some(domain.clone());
                } else {
                    if Self::is_eligible_ip(&connection_info.connection.dst_ip) {
                        if let Some(resolver) = resolver.as_ref() {
                            let domain = resolver
                                .get_resolved_ip(&connection_info.connection.dst_ip)
                                .await;
                            if let Some(domain) = domain {
                                trace!(
                                    "Using resolver for dst_ip: {:?}",
                                    connection_info.connection.dst_ip
                                );
                                connection_info.dst_domain = Some(domain);
                            } else {
                                resolver
                                    .add_ip_to_resolver(&connection_info.connection.dst_ip)
                                    .await;
                            }
                        }
                    } else {
                        if let Some(dst_domain) =
                            mdns_get_hostname_by_ip(&connection_info.connection.dst_ip).await
                        {
                            trace!("Using mDNS for dst_ip: {:?}", dst_domain);
                            connection_info.dst_domain = Some(dst_domain);
                        }
                    }
                }
            } else {
                error!("Connection was not found for key: {:?}", key);
            }
        }
    }

    //Populate L7
    async fn populate_l7(
        connections: &DashMap<Connection, ConnectionInfo>,
        l7: &Arc<Option<LANScanL7>>,
        active_connections: &Arc<CustomRwLock<Vec<Connection>>>,
    ) {
        if let Some(l7) = l7.as_ref() {
            let active_connections_clone = active_connections.read().await.clone();
            for key in active_connections_clone.iter() {
                if let Some(mut connection_info) = connections.get_mut(key) {
                    // Always attempt to get the resolved L7 data
                    if let Some(l7_resolution) =
                        l7.get_resolved_l7(&connection_info.connection).await
                    {
                        if let Some(l7_data) = l7_resolution.l7 {
                            connection_info.l7 = Some(l7_data.clone());
                            trace!("Updated L7 data for connection {:?}: {:?}", key, l7_data);
                        }
                    }
                } else {
                    error!("Connection was not found for key: {:?}", key);
                }
            }
        }
    }
    async fn update_active_connections(
        connections: &DashMap<Connection, ConnectionInfo>,
        active_connections: &Arc<CustomRwLock<Vec<Connection>>>,
    ) {
        let mut updated_active_connections = Vec::new();
        // Clone the active_connections to avoid holding the lock for too long
        let active_connections_clone = active_connections.read().await.clone();
        for key in active_connections_clone.iter() {
            if let Some(connection) = connections.get(key) {
                if connection.stats.last_activity > Utc::now() - CONNECTION_ACTIVITY_TIMEOUT {
                    updated_active_connections.push(connection.connection.clone());
                }
            }
        }
        *active_connections.write().await = updated_active_connections;

        // Remove connections that are older than the retention timeout within the whole connections
        let retention_timeout = Utc::now() - CONNECTION_RETENTION_TIMEOUT;
        for key in connections.iter() {
            if key.stats.last_activity < retention_timeout {
                connections.remove(&key.connection);
            }
        }
    }

    pub async fn start(&mut self, whitelist_name: &str) {
        // Start mDNS task
        mdns_start().await;

        // Active connections handle
        let active_connections = self.active_connections.clone();
        let active_connections_stop_flag = Arc::new(AtomicBool::new(false));
        let active_connections_stop_flag_clone = active_connections_stop_flag.clone();
        let connections = self.connections.clone();
        let active_connections_handle = async_spawn(async move {
            while !active_connections_stop_flag.load(Ordering::Relaxed) {
                trace!("Active connections update started");
                Self::update_active_connections(&connections, &active_connections).await;
                info!(
                    "Active connections update completed - {} connections",
                    active_connections.read().await.len()
                );
                sleep(Duration::from_secs(5)).await;
            }
            info!("Stopped active connections task");
        });
        self.active_connections_handle = Some(TaskHandle {
            handle: active_connections_handle,
            stop_flag: active_connections_stop_flag_clone,
        });

        // Create a new resolver if it doesn't exist
        if self.resolver.is_none() {
            self.resolver = Arc::new(Some(LANScanResolver::new()));
        }
        // Start the resolver if it exists
        if let Some(resolver) = Arc::get_mut(&mut self.resolver).and_then(|r| r.as_mut()) {
            resolver.start().await;
        }
        let resolver: Arc<Option<LANScanResolver>> = self.resolver.clone();
        let resolver_stop_flag = Arc::new(AtomicBool::new(false));
        let resolver_stop_flag_clone = resolver_stop_flag.clone();
        let dns_resolutions = self.dns_resolutions.clone();
        let connections = self.connections.clone();
        let active_connections = self.active_connections.clone();
        let resolver_handle = async_spawn(async move {
            while !resolver_stop_flag.load(Ordering::Relaxed) {
                trace!("Domain name population started");
                Self::populate_domain_names(
                    &connections,
                    &resolver,
                    &dns_resolutions,
                    &active_connections,
                )
                .await;
                info!("Domain name population completed");
                sleep(Duration::from_secs(5)).await;
            }
            info!("Stopped resolver task");
        });
        self.resolver_handle = Some(TaskHandle {
            handle: resolver_handle,
            stop_flag: resolver_stop_flag_clone,
        });

        // Create L7 resolver if it doesn't exist
        if self.l7.is_none() {
            self.l7 = Arc::new(Some(LANScanL7::new()));
        }
        // Start the L7 resolver if it exists
        if let Some(l7) = Arc::get_mut(&mut self.l7).and_then(|l| l.as_mut()) {
            l7.start().await;
        }
        let l7 = self.l7.clone();
        let l7_stop_flag = Arc::new(AtomicBool::new(false));
        let l7_stop_flag_clone = l7_stop_flag.clone();
        let connections = self.connections.clone();
        let active_connections = self.active_connections.clone();
        let l7_handle = async_spawn(async move {
            while !l7_stop_flag.load(Ordering::Relaxed) {
                trace!("L7 update started");
                Self::populate_l7(&connections, &l7, &active_connections).await;
                info!("L7 update completed");
                sleep(Duration::from_secs(5)).await;
            }
            info!("Stopped L7 task");
        });
        self.l7_handle = Some(TaskHandle {
            handle: l7_handle,
            stop_flag: l7_stop_flag_clone,
        });

        // Whitelist check handle
        if !whitelist_name.is_empty() {
            let whitelist_name = whitelist_name.to_string();
            self.whitelist_name = whitelist_name.to_string();
            let whitelist_exceptions = self.whitelist_exceptions.clone();
            let whitelist_conformance = self.whitelist_conformance.clone();
            let whitelist_check_stop_flag = Arc::new(AtomicBool::new(false));
            let whitelist_check_stop_flag_clone: Arc<AtomicBool> =
                whitelist_check_stop_flag.clone();
            let last_whitelist_exception_time = self.last_whitelist_exception_time.clone();
            let connections = self.connections.clone();
            let active_connections = self.active_connections.clone();
            let whitelist_check_handle = async_spawn(async move {
                while !whitelist_check_stop_flag.load(Ordering::Relaxed) {
                    trace!("Whitelist check started");
                    Self::check_whitelisted_destinations(
                        &whitelist_name,
                        &whitelist_conformance,
                        &whitelist_exceptions,
                        &connections,
                        &active_connections,
                        &last_whitelist_exception_time,
                    )
                    .await;
                    info!("Whitelist check completed");
                    sleep(Duration::from_secs(5)).await;
                }
                info!("Stopped whitelist check task");
            });
            self.whitelist_check_handle = Some(TaskHandle {
                handle: whitelist_check_handle,
                stop_flag: whitelist_check_stop_flag_clone,
            });
        }

        // Capture handle
        let connections = self.connections.clone();
        let active_connections = self.active_connections.clone();
        let capture_stop_flag = Arc::new(AtomicBool::new(false));
        let capture_stop_flag_clone = capture_stop_flag.clone();
        let dns_resolutions = self.dns_resolutions.clone();
        // Spawn packet capture task
        let capture_task_handle = {
            async_spawn(async move {
                // get the default Device
                let device = pcap::Device::lookup()
                    .expect("device lookup failed")
                    .expect("no device available");

                info!("Starting packet capture on device {}", device.name);

                let mut cap = Capture::from_device(device)
                    .expect("Failed to open capture on default device")
                    .promisc(false)
                    .timeout(1000) // Set read timeout in milliseconds
                    .open()
                    .expect("Failed to open pcap capture");

                while !capture_stop_flag.load(Ordering::Relaxed) {
                    match cap.next_packet() {
                        Ok(packet) => {
                            if let Some(parsed_packet) = Self::parse_packet_pcap(packet.data) {
                                match parsed_packet {
                                    ParsedPacket::ConnectionPacket(cp) => {
                                        Self::process_parsed_packet(
                                            cp,
                                            &connections,
                                            &active_connections,
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
            })
        };

        self.capture_task_handle = Some(TaskHandle {
            handle: capture_task_handle,
            stop_flag: capture_stop_flag_clone,
        });
    }

    pub async fn stop(&mut self) {
        if let Some(capture_task_handle) = self.capture_task_handle.take() {
            capture_task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = capture_task_handle.handle.await;
            info!("Stopped packet capture on all interfaces");
        }

        if let Some(whitelist_check_handle) = self.whitelist_check_handle.take() {
            whitelist_check_handle
                .stop_flag
                .store(true, Ordering::Relaxed);
            let _ = whitelist_check_handle.handle.await;
            info!("Stopped whitelist check task");
        }
    }

    // Get connections as a vector of ConnectionInfo
    pub async fn get_connections(&self, local_traffic: bool) -> Vec<ConnectionInfo> {
        let mut connections_vec = Vec::new();
        for key in self.connections.iter() {
            if let Some(entry) = self.connections.get(&key.connection) {
                connections_vec.push(entry.clone());
            }
        }
        if local_traffic {
            connections_vec = Self::filter_local_traffic(&connections_vec);
        }
        connections_vec
    }

    // Active connections as a vector of ConnectionInfo
    pub async fn get_active_connections(&self, local_traffic: bool) -> Vec<ConnectionInfo> {
        // Get the connections from the DashMap that match the keys in the active_connections Vec
        let mut active_connections_vec = Vec::new();
        for key in self.active_connections.read().await.iter() {
            if let Some(entry) = self.connections.get(key) {
                active_connections_vec.push(entry.clone());
            }
        }
        if local_traffic {
            active_connections_vec = Self::filter_local_traffic(&active_connections_vec);
        }
        active_connections_vec
    }

    pub async fn get_whitelist_conformance(&self) -> bool {
        self.whitelist_conformance.load(Ordering::Relaxed)
    }

    pub async fn get_whitelist_exceptions(&self) -> Vec<ConnectionInfo> {
        let mut exceptions = Vec::new();
        for key in self.whitelist_exceptions.read().await.iter() {
            if let Some(entry) = self.connections.get(key) {
                exceptions.push(entry.clone());
            }
        }
        exceptions
    }

    fn filter_local_traffic(connections: &Vec<ConnectionInfo>) -> Vec<ConnectionInfo> {
        connections
            .iter()
            .filter(|c| {
                Self::is_eligible_ip(&c.connection.src_ip)
                    || Self::is_eligible_ip(&c.connection.dst_ip)
            })
            .cloned()
            .collect()
    }

    pub fn format_connections_zeek(
        connections: &Vec<ConnectionInfo>,
        local_traffic: bool,
    ) -> Vec<String> {
        let mut zeek_logs = Vec::new();

        let connections = if !local_traffic {
            Self::filter_local_traffic(connections)
        } else {
            connections.clone()
        };

        // Add a header to the Zeek log
        let header = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            "ts",
            "uid",
            "id.orig_h",
            "id.orig_p",
            "id.resp_h",
            "id.resp_p",
            "proto",
            "service",
            "duration",
            "orig_bytes",
            "resp_bytes",
            "conn_state",
            "local_orig",
            "local_resp",
            "missed_bytes",
            "history",
            "orig_pkts",
            "orig_ip_bytes",
            "resp_pkts",
            "resp_ip_bytes",
            "tunnel_parents"
        );
        zeek_logs.push(header);

        for connection in connections {
            let start_time = connection.stats.start_time.timestamp() as f64
                + (connection.stats.start_time.timestamp_subsec_micros() as f64 / 1_000_000.0);
            let duration = match connection.stats.end_time {
                Some(end_time) => format!(
                    "{:.6}",
                    (end_time - connection.stats.start_time)
                        .num_microseconds()
                        .unwrap_or(0) as f64
                        / 1_000_000.0
                ),
                None => "-".to_string(),
            };
            let orig_bytes = connection.stats.outbound_bytes.to_string();
            let resp_bytes = connection.stats.inbound_bytes.to_string();
            let proto = match connection.connection.protocol {
                Protocol::TCP => "tcp",
                Protocol::UDP => "udp",
            };
            let conn_state = connection
                .stats
                .conn_state
                .clone()
                .unwrap_or("-".to_string());

            let zeek_entry = format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                start_time,
                connection.stats.uid,
                connection.connection.src_ip,
                connection.connection.src_port,
                connection.connection.dst_ip,
                connection.connection.dst_port,
                proto,
                "-", // Service detection not implemented
                duration,
                orig_bytes,
                resp_bytes,
                conn_state,
                "-", // Local origination not determined
                "-", // Local response not determined
                connection.stats.missed_bytes,
                connection.stats.history,
                connection.stats.orig_pkts,
                connection.stats.orig_ip_bytes,
                connection.stats.resp_pkts,
                connection.stats.resp_ip_bytes,
                "-" // Tunnel parents not implemented
            );

            zeek_logs.push(zeek_entry);
        }

        zeek_logs
    }

    // Get connections as a vector of String in a readable log format
    pub fn format_connections_log(
        connections: &Vec<ConnectionInfo>,
        local_traffic: bool,
    ) -> Vec<String> {
        let mut log_entries = Vec::new();

        let connections = if !local_traffic {
            Self::filter_local_traffic(connections)
        } else {
            connections.clone()
        };

        for connection in connections.iter() {
            let src_domain = connection.src_domain.clone();
            let dst_domain = connection.dst_domain.clone();

            let (username, process_name) = match connection.l7.clone() {
                Some(l7) => (l7.username, l7.process_name),
                None => ("-".to_string(), "-".to_string()),
            };

            let stats = connection.stats.clone();
            let is_whitelisted = connection.is_whitelisted.clone();
            let connection = connection.connection.clone();
            let start_time = stats.start_time.to_rfc3339();
            let duration = match stats.end_time {
                Some(end_time) => {
                    let duration = end_time - stats.start_time;
                    format!("{}s", duration.num_seconds())
                }
                None => "ongoing".to_string(),
            };

            // Replace IP addresses with resolved names when available and not "Resolving" or "Unknown"
            let src_name = match src_domain {
                Some(name) => match name.as_str() {
                    "Resolving" => connection.src_ip.to_string(),
                    "Unknown" => connection.src_ip.to_string(),
                    _ => name.clone(),
                },
                None => connection.src_ip.to_string(),
            };

            let dst_name = match dst_domain {
                Some(name) => match name.as_str() {
                    "Resolving" => connection.dst_ip.to_string(),
                    "Unknown" => connection.dst_ip.to_string(),
                    _ => name.clone(),
                },
                None => connection.dst_ip.to_string(),
            };

            let log_entry = format!(
                "[{}] {} {} - {}:{} -> {}:{} ({}, {} bytes sent, {} bytes received, duration: {}, whitelisted: {})",
                start_time,
                username,
                process_name,
                src_name,
                connection.src_port,
                dst_name,
                connection.dst_port,
                connection.protocol,
                stats.outbound_bytes,
                stats.inbound_bytes,
                duration,
                is_whitelisted
            );

            log_entries.push(log_entry);
        }

        log_entries
    }

    fn is_link_local_ipv6(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V6(ipv6) => ipv6.to_string().starts_with("fe80"),
            _ => false,
        }
    }

    fn is_private_ipv6(ip: &IpAddr) -> bool {
        match ip {
            // fc00::/7
            IpAddr::V6(ipv6) => {
                ipv6.to_string().starts_with("fc00") || ipv6.to_string().starts_with("fd00")
            }
            _ => false,
        }
    }

    fn is_eligible_ip(ip: &IpAddr) -> bool {
        let not_eligible = match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private()
                    || ipv4.is_link_local()
                    || ipv4.is_loopback()
                    || ipv4.is_multicast()
                    || ipv4.is_unspecified()
                    || ipv4.is_broadcast()
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
                    || ipv6.is_multicast()
                    || ipv6.is_unspecified()
                    || Self::is_link_local_ipv6(ip)
                    || Self::is_private_ipv6(ip)
            }
        };
        if not_eligible {
            trace!("IP address {:?} is not eligible", ip);
        } else {
            trace!("IP address {:?} is eligible", ip);
        }
        !not_eligible
    }

    async fn process_parsed_packet(
        parsed_packet: ConnectionPacketData,
        connections: &Arc<DashMap<Connection, ConnectionInfo>>,
        active_connections: &Arc<CustomRwLock<Vec<Connection>>>,
    ) {
        let key = parsed_packet.connection.clone();
        let reverse_key = Connection {
            protocol: parsed_packet.connection.protocol.clone(),
            src_ip: parsed_packet.connection.dst_ip,
            src_port: parsed_packet.connection.dst_port,
            dst_ip: parsed_packet.connection.src_ip,
            dst_port: parsed_packet.connection.src_port,
        };

        // Update connection stats
        if let Some(mut info) = connections.get_mut(&key) {
            let stats: &mut ConnectionStats = &mut info.stats;
            stats.last_activity = Utc::now();
            // Packet from originator to responder
            stats.outbound_bytes += parsed_packet.packet_length as u64;
            stats.orig_pkts += 1;
            stats.orig_ip_bytes += parsed_packet.ip_packet_length as u64;
            // Update history
            if let Some(flags) = parsed_packet.flags {
                let c = Self::map_tcp_flags(flags, parsed_packet.packet_length, true);
                stats.history.push(c);
                if (flags & (TcpFlags::FIN | TcpFlags::RST)) != 0 && stats.end_time.is_none() {
                    stats.end_time = Some(Utc::now());
                    stats.conn_state = Some(Self::determine_conn_state(&stats.history));
                }
            }
        } else if let Some(mut info) = connections.get_mut(&reverse_key) {
            // Packet from responder to originator
            let stats: &mut ConnectionStats = &mut info.stats;
            stats.last_activity = Utc::now();
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
            // New connection
            let uid = Uuid::new_v4().to_string();
            let mut stats = ConnectionStats {
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
            // Assume first packet is from originator to responder
            stats.outbound_bytes += parsed_packet.packet_length as u64;
            stats.orig_pkts += 1;
            stats.orig_ip_bytes += parsed_packet.ip_packet_length as u64;
            // Update history
            if let Some(flags) = parsed_packet.flags {
                let c = Self::map_tcp_flags(flags, parsed_packet.packet_length, true);
                stats.history.push(c);
            }
            let key_clone = key.clone();
            trace!("New connection: {:?}", key_clone);

            // Query the ASN database
            let src_asn = get_asn(key.src_ip).await;
            let dst_asn = get_asn(key.dst_ip).await;

            connections.insert(
                key.clone(),
                ConnectionInfo {
                    connection: key,
                    stats,
                    src_domain: None,
                    dst_domain: None,
                    l7: None,
                    src_asn,
                    dst_asn,
                    // Whitelisted by default
                    is_whitelisted: WhitelistState::Unknown,
                },
            );
            // Add to active connections
            active_connections.write().await.push(key_clone);
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

                        let connection = Connection {
                            protocol: Protocol::TCP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };

                        Some(ParsedPacket::ConnectionPacket(ConnectionPacketData {
                            connection,
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

                        let connection = Connection {
                            protocol: Protocol::UDP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };

                        Some(ParsedPacket::ConnectionPacket(ConnectionPacketData {
                            connection,
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

                        let connection = Connection {
                            protocol: Protocol::TCP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };

                        Some(ParsedPacket::ConnectionPacket(ConnectionPacketData {
                            connection,
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

                        let connection = Connection {
                            protocol: Protocol::UDP,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                        };

                        Some(ParsedPacket::ConnectionPacket(ConnectionPacketData {
                            connection,
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
    use crate::admin::get_admin_status;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_capture() {
        let mut capture = LANScanCapture::new();
        capture.start("cicd").await;

        // Verify handles are running
        assert!(capture.resolver_handle.is_some());
        assert!(capture.whitelist_check_handle.is_some());
        assert!(capture.active_connections_handle.is_some());

        // Insert a fake connection
        let connection = Connection {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 8000,
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_port: 53,
        };

        let connection_info = ConnectionInfo {
            connection: connection.clone(),
            stats: ConnectionStats {
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
            },
            src_domain: None,
            dst_domain: None,
            l7: None,
            asn: None,
            is_whitelisted: WhitelistState::Unknown,
        };

        capture
            .connections
            .insert(connection.clone(), connection_info);
        capture
            .active_connections
            .write()
            .await
            .push(connection.clone());

        // Disable this test for now as we have issues with tokio accross tests
        if get_admin_status() && false {
            // Wait for resolution with a timeout
            let resolution_result = timeout(Duration::from_secs(30), async {
                loop {
                    if let Some(conn_info) = capture.connections.get(&connection) {
                        if conn_info.dst_domain.is_some() {
                            return conn_info.dst_domain.clone();
                        }
                    }
                    sleep(Duration::from_millis(5000)).await;
                }
            })
            .await;

            match resolution_result {
                Ok(Some(domain)) => {
                    assert_eq!(domain, "dns.google");
                }
                Ok(None) => panic!("Unexpected None result"),
                Err(_) => panic!("Timeout waiting for resolution"),
            }

            // Check active connections
            let active_connections = capture.active_connections.read().await;
            assert!(active_connections.contains(&connection));

            // Check whitelist exceptions
            let whitelist_exceptions = capture.whitelist_exceptions.read().await;
            assert!(whitelist_exceptions.contains(&connection));

            // Check whitelist conformance
            assert!(!capture.whitelist_conformance.load(Ordering::Relaxed));

            // Check if connections are captured
            let connections = capture.active_connections.read().await;
            assert!(connections.len() > 1);
        }

        // Stop the capture
        capture.stop().await;
    }
}
