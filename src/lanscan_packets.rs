use crate::blacklists::*;
use crate::lanscan_asn::*;
use crate::lanscan_ip::is_lan_ip;
use crate::lanscan_l7::LANScanL7;
use crate::lanscan_port_vulns::get_name_from_port;
use crate::lanscan_sessions::session_macros::*;
use crate::lanscan_sessions::*;
use crate::rwlock::CustomRwLock;
use chrono::Utc;
use dashmap::DashMap;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::{TcpFlags, TcpPacket};
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet as PnetPacket;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio;
use tracing::{trace, warn};
use uuid::Uuid;

// Add a constant for the TCP PSH flag if it's not already defined
const TCP_PSH: u8 = 0x08; // PSH (push) flag in TCP

#[derive(Debug, PartialEq)]
pub enum ParsedPacket {
    SessionPacket(SessionPacketData),
    DnsPacket(DnsPacketData),
}

#[derive(Debug, PartialEq, Clone)]
pub struct SessionPacketData {
    pub session: Session,
    pub packet_length: usize,
    pub ip_packet_length: usize,
    pub flags: Option<u8>,
}

#[derive(Debug, PartialEq)]
pub struct DnsPacketData {
    pub dns_payload: Vec<u8>,
}

pub async fn process_parsed_packet(
    parsed_packet: SessionPacketData,
    sessions: &Arc<DashMap<Session, SessionInfo>>,
    current_sessions: &Arc<CustomRwLock<Vec<Session>>>,
    self_ips: &HashSet<IpAddr>,
    filter: &Arc<CustomRwLock<SessionFilter>>,
    l7: Option<&Arc<LANScanL7>>,
) {
    let now = Utc::now();

    // Check if the ports are known service ports
    let src_service_name = get_name_from_port(parsed_packet.session.src_port).await;
    let dst_service_name = get_name_from_port(parsed_packet.session.dst_port).await;

    let src_is_service_port = !src_service_name.is_empty();
    let dst_is_service_port = !dst_service_name.is_empty();

    // Determine the session key based on actual packet direction and port information
    // We'll use the following logic:
    // 1. Keep original direction by default (source is initiator)
    // 2. If destination has a well-known service port and source doesn't, keep original
    // 3. If source has a well-known service port and destination doesn't, swap them
    // 4. If both are service ports, use TCP flags or default to keeping original direction
    let key = if src_is_service_port && !dst_is_service_port {
        // Source is likely a server, swap to make the client (initiator) the source
        Session {
            protocol: parsed_packet.session.protocol.clone(),
            src_ip: parsed_packet.session.dst_ip,
            src_port: parsed_packet.session.dst_port,
            dst_ip: parsed_packet.session.src_ip,
            dst_port: parsed_packet.session.src_port,
        }
    } else if src_is_service_port && dst_is_service_port {
        // Both are service ports - first try TCP flags, then use port numbers as tiebreaker
        if let Some(flags) = parsed_packet.flags {
            if parsed_packet.session.protocol == Protocol::TCP
                && flags & TcpFlags::SYN != 0
                && flags & TcpFlags::ACK == 0
            {
                // SYN without ACK - keep original direction
                parsed_packet.session.clone()
            } else if parsed_packet.session.protocol == Protocol::TCP
                && flags & TcpFlags::SYN != 0
                && flags & TcpFlags::ACK != 0
            {
                // SYN+ACK - swap direction
                Session {
                    protocol: parsed_packet.session.protocol.clone(),
                    src_ip: parsed_packet.session.dst_ip,
                    src_port: parsed_packet.session.dst_port,
                    dst_ip: parsed_packet.session.src_ip,
                    dst_port: parsed_packet.session.src_port,
                }
            } else {
                // For other flag combinations, use port numbers as tiebreaker
                // Lower port number is likely to be the more canonical service
                if parsed_packet.session.src_port < parsed_packet.session.dst_port {
                    // Source has the smaller port, so it's likely the server - swap direction
                    Session {
                        protocol: parsed_packet.session.protocol.clone(),
                        src_ip: parsed_packet.session.dst_ip,
                        src_port: parsed_packet.session.dst_port,
                        dst_ip: parsed_packet.session.src_ip,
                        dst_port: parsed_packet.session.src_port,
                    }
                } else {
                    // Destination has smaller port, keep original direction
                    parsed_packet.session.clone()
                }
            }
        } else {
            // No flags (e.g., UDP), use port numbers as tiebreaker
            if parsed_packet.session.src_port < parsed_packet.session.dst_port {
                // Source has the smaller port, so it's likely the server - swap direction
                Session {
                    protocol: parsed_packet.session.protocol.clone(),
                    src_ip: parsed_packet.session.dst_ip,
                    src_port: parsed_packet.session.dst_port,
                    dst_ip: parsed_packet.session.src_ip,
                    dst_port: parsed_packet.session.src_port,
                }
            } else {
                // Destination has smaller port, keep original direction
                parsed_packet.session.clone()
            }
        }
    } else {
        // Keep original direction
        parsed_packet.session.clone()
    };

    // Determine if this packet is from originator to responder or vice versa
    // A packet is from the originator if it matches the flow direction of the session key
    // Otherwise it's a response packet from responder to originator
    let is_originator = parsed_packet.session.src_ip == key.src_ip
        && parsed_packet.session.src_port == key.src_port
        && parsed_packet.session.dst_ip == key.dst_ip
        && parsed_packet.session.dst_port == key.dst_port;

    // Apply filter before processing
    let filter = filter.read().await.clone();
    if filter == SessionFilter::LocalOnly && is_global_session!(parsed_packet) {
        return;
    } else if filter == SessionFilter::GlobalOnly && is_local_session!(parsed_packet) {
        return;
    }

    if let Some(mut info) = sessions.get_mut(&key) {
        let stats = &mut info.stats;

        if is_originator {
            // Packet from originator to responder
            stats.outbound_bytes += parsed_packet.packet_length as u64;
            stats.orig_pkts += 1;
            stats.orig_ip_bytes += parsed_packet.ip_packet_length as u64;
        } else {
            // Packet from responder to originator
            stats.inbound_bytes += parsed_packet.packet_length as u64;
            stats.resp_pkts += 1;
            stats.resp_ip_bytes += parsed_packet.ip_packet_length as u64;
        }

        // Calculate average packet size after adding bytes
        let total_packets = stats.orig_pkts + stats.resp_pkts;
        let total_bytes = stats.inbound_bytes + stats.outbound_bytes;
        stats.average_packet_size = if total_packets > 0 {
            total_bytes as f64 / total_packets as f64
        } else {
            0.0
        };

        // Update inbound/outbound ratio
        stats.inbound_outbound_ratio = if stats.outbound_bytes > 0 {
            stats.inbound_bytes as f64 / stats.outbound_bytes as f64
        } else {
            0.0
        };

        // Segment detection logic
        let time_since_last_activity =
            (now - stats.last_activity).num_milliseconds() as f64 / 1000.0; // in seconds

        // Check if this packet ends a segment (PUSH flag or timeout)
        let is_segment_end = if parsed_packet.session.protocol == Protocol::TCP {
            if let Some(flags) = parsed_packet.flags {
                // Check for PUSH flag in TCP packets
                (flags & TCP_PSH) != 0
            } else {
                false
            }
        } else {
            false
        } || (stats.in_segment
            && time_since_last_activity >= stats.segment_timeout);

        // If we're starting a new segment (because we weren't in one before this packet)
        if !stats.in_segment {
            stats.in_segment = true;
            stats.current_segment_start = now; // Start of the *new* segment
        }

        // If this packet ends a segment
        if is_segment_end && stats.in_segment {
            // Check in_segment *again* ensures we only process the end of the *current* segment
            let previous_segment_end_time = stats.last_segment_end; // Store the *previous* end time

            stats.segment_count += 1;
            stats.in_segment = false; // End current segment
            stats.last_segment_end = Some(now); // Update with the end time of the *current* segment

            // Calculate interarrival time using the *previous* end time
            if let Some(prev_end) = previous_segment_end_time {
                // Interarrival is time between previous end and current start
                let segment_interarrival =
                    (stats.current_segment_start - prev_end).num_milliseconds() as f64 / 1000.0;

                if segment_interarrival >= 0.0 {
                    // Only add non-negative interarrivals
                    stats.total_segment_interarrival += segment_interarrival;
                    // Calculate average interarrival time over (segment_count - 1) intervals
                    stats.segment_interarrival = if stats.segment_count > 1 {
                        stats.total_segment_interarrival / (stats.segment_count - 1) as f64
                    } else {
                        0.0 // First interarrival time IS the average
                    };
                } else {
                    warn!(
                         "Negative segment interarrival calculated ({}ms). Current start: {:?}, Previous end: {:?}. Skipping.",
                         (stats.current_segment_start - prev_end).num_milliseconds(),
                         stats.current_segment_start,
                         prev_end
                     );
                    // Keep the previous average if the new calculation is invalid
                }
            }
            // No 'else' needed here - if previous_segment_end_time is None, it's the first segment ending, no interarrival yet.

            // Start a new segment immediately if this is a timeout-based end
            // (for TCP with PUSH flag, a new segment typically starts with next packet)
            if time_since_last_activity >= stats.segment_timeout {
                stats.in_segment = true;
                stats.current_segment_start = now;
            }
        }

        // Update last activity AFTER segment processing uses the previous value
        stats.last_activity = now;

        // Update history with correct direction
        if let Some(flags) = parsed_packet.flags {
            let c = map_tcp_flags(flags, parsed_packet.packet_length, is_originator);
            stats.history.push(c);
            if (flags & (TcpFlags::FIN | TcpFlags::RST)) != 0 && stats.end_time.is_none() {
                stats.end_time = Some(now);
                stats.conn_state = Some(determine_conn_state(&stats.history));
            }
        }
    } else {
        // New session
        let uid = Uuid::new_v4().to_string();

        let mut stats = SessionStats {
            start_time: now,
            end_time: None,
            last_activity: now,
            inbound_bytes: 0,
            outbound_bytes: 0,
            orig_pkts: 0,
            resp_pkts: 0,
            orig_ip_bytes: 0,
            resp_ip_bytes: 0,
            history: String::new(),
            conn_state: None,
            missed_bytes: 0,

            // Initialize new traffic statistics
            average_packet_size: 0.0, // Initialize to 0, will be updated after we add bytes
            inbound_outbound_ratio: 0.0, // Will update after we add bytes

            // Initialize segment tracking
            segment_count: 0,
            current_segment_start: now,
            last_segment_end: None,
            segment_interarrival: 0.0,
            total_segment_interarrival: 0.0,
            in_segment: true, // First packet starts a segment

            // Default timeout for segment detection
            segment_timeout: 5.0, // 5 seconds by default
        };

        // Update session stats based on the first packet
        if is_originator {
            stats.outbound_bytes += parsed_packet.packet_length as u64;
            stats.orig_pkts += 1;
            stats.orig_ip_bytes += parsed_packet.ip_packet_length as u64;
        } else {
            stats.inbound_bytes += parsed_packet.packet_length as u64;
            stats.resp_pkts += 1;
            stats.resp_ip_bytes += parsed_packet.ip_packet_length as u64;
        }

        // Calculate average packet size after adding bytes
        let total_packets = stats.orig_pkts + stats.resp_pkts;
        let total_bytes = stats.inbound_bytes + stats.outbound_bytes;
        stats.average_packet_size = if total_packets > 0 {
            total_bytes as f64 / total_packets as f64
        } else {
            0.0
        };

        // Calculate inbound/outbound ratio (might be 0.0 or infinity initially)
        stats.inbound_outbound_ratio = if stats.outbound_bytes > 0 {
            stats.inbound_bytes as f64 / stats.outbound_bytes as f64
        } else {
            0.0
        };

        // Update history with correct direction
        if let Some(flags) = parsed_packet.flags {
            let c = map_tcp_flags(flags, parsed_packet.packet_length, is_originator);
            stats.history.push(c);

            // Check for TCP PUSH flag for segment tracking
            if parsed_packet.session.protocol == Protocol::TCP && (flags & TCP_PSH) != 0 {
                // This packet ends a segment
                stats.segment_count = 1;
                stats.in_segment = false;
                stats.last_segment_end = Some(now);
            }

            // Check for FIN or RST flags to properly set end_time for new sessions
            if (flags & (TcpFlags::FIN | TcpFlags::RST)) != 0 {
                stats.end_time = Some(now);
                stats.conn_state = Some(determine_conn_state(&stats.history));
            }
        }

        // Determine locality flags based on the session key (which might be swapped)
        let is_local_src = is_lan_ip(&key.src_ip);
        let is_local_dst = is_lan_ip(&key.dst_ip);

        // Update self flags based on the session key (which might be swapped)
        let is_self_src = self_ips.contains(&key.src_ip);
        let is_self_dst = self_ips.contains(&key.dst_ip);

        trace!("New session: {:?}. Performing lookups concurrently.", key);

        // --- Perform lookups concurrently ---
        let src_ip_lookup = key.src_ip;
        let dst_ip_lookup = key.dst_ip;
        // Perform string conversion once if needed for blacklist lookups
        let src_ip_str = src_ip_lookup.to_string();
        let dst_ip_str = dst_ip_lookup.to_string();

        // Get the service name for destination port
        let dst_service = if key.dst_port == parsed_packet.session.dst_port {
            // If we didn't swap, use the dst_service_name we already looked up
            if !dst_service_name.is_empty() {
                Some(dst_service_name)
            } else {
                None
            }
        } else if key.dst_port == parsed_packet.session.src_port {
            // If we swapped, use the src_service_name we already looked up
            if !src_service_name.is_empty() {
                Some(src_service_name)
            } else {
                None
            }
        } else {
            // This shouldn't happen, but just in case
            trace!("Unexpected port mismatch in session key. Will look up service name.");
            let name = get_name_from_port(key.dst_port).await;
            if !name.is_empty() {
                Some(name)
            } else {
                None
            }
        };

        let (src_asn_opt, dst_asn_opt, src_blacklist_result, dst_blacklist_result) = tokio::join!(
            // Source ASN lookup (only if not local)
            async {
                if !is_local_src {
                    get_asn(src_ip_lookup).await
                } else {
                    None
                }
            },
            // Destination ASN lookup (only if not local)
            async {
                if !is_local_dst {
                    get_asn(dst_ip_lookup).await
                } else {
                    None
                }
            },
            // Source IP blacklist check
            is_ip_blacklisted(&src_ip_str), // Returns (bool, Vec<String>)
            // Destination IP blacklist check
            is_ip_blacklisted(&dst_ip_str) // Returns (bool, Vec<String>)
        );
        // --- Lookups finished ---

        trace!("Lookups completed for session: {:?}", key);

        // Queue the new session for L7 resolution (can happen after lookups)
        if let Some(l7) = l7 {
            l7.add_connection_to_resolver(&key).await;
            trace!("Added session {:?} to L7 resolver queue", key);
        }

        // Set initial status
        let status = SessionStatus {
            active: true, // A new session is active by definition
            added: true,
            activated: true, // It's newly activated
            deactivated: false,
        };

        // Create the SessionInfo struct using the results from join!
        let mut session_info = SessionInfo {
            session: key.clone(),
            stats,
            status,
            is_local_src,
            is_local_dst,
            is_self_src,
            is_self_dst,
            src_domain: None, // Domain resolution happens later
            dst_domain: None, // Domain resolution happens later
            dst_service: dst_service,
            l7: None, // L7 resolution happens later
            src_asn: src_asn_opt,
            dst_asn: dst_asn_opt,
            is_whitelisted: WhitelistState::Unknown, // Whitelist check happens later
            criticality: "".to_string(),
            whitelist_reason: None,
            uid: uid,
            last_modified: Utc::now(),
        };

        // --- Process blacklist results ---
        let (src_blacklisted, src_lists) = src_blacklist_result;
        let (dst_blacklisted, dst_lists) = dst_blacklist_result;

        let mut criticality_parts = Vec::new();
        // Only add tags if the IP is actually blacklisted AND is not a local/LAN IP
        if src_blacklisted && !is_local_src {
            criticality_parts.extend(src_lists);
        }
        if dst_blacklisted && !is_local_dst {
            criticality_parts.extend(dst_lists);
        }

        // Remove duplicates and set criticality
        if !criticality_parts.is_empty() {
            criticality_parts.sort();
            criticality_parts.dedup();
            session_info.criticality = format!(
                "{}",
                criticality_parts
                    .iter()
                    .map(|name| format!("blacklist:{}", name))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            trace!(
                "Set criticality for session {:?}: {}",
                key,
                session_info.criticality
            );
        }
        // --- End blacklist processing ---

        // Insert the newly created session info into the main map
        sessions.insert(key.clone(), session_info);
        trace!("Inserted session info for {:?} into main map", key);

        // Add the key to the current sessions vector
        // This still requires a write lock, but happens after concurrent lookups
        current_sessions.write().await.push(key.clone());
        trace!("Added session key {:?} to current sessions vector", key);
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

pub fn parse_packet_pcap(packet_data: &[u8]) -> Option<ParsedPacket> {
    let ethernet = match EthernetPacket::new(packet_data) {
        Some(packet) => packet,
        None => {
            warn!("Failed to parse Ethernet packet");
            return None;
        }
    };
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = match Ipv4Packet::new(ethernet.payload()) {
                Some(packet) => packet,
                None => {
                    warn!("Failed to parse IPv4 packet");
                    return None;
                }
            };
            let ip_packet_length = ipv4.get_total_length() as usize;
            let next_protocol = ipv4.get_next_level_protocol();
            match next_protocol {
                IpNextHeaderProtocols::Tcp => {
                    let tcp = match TcpPacket::new(ipv4.payload()) {
                        Some(packet) => packet,
                        None => {
                            warn!("Failed to parse TCP packet");
                            return None;
                        }
                    };
                    let src_ip = IpAddr::V4(ipv4.get_source());
                    let dst_ip = IpAddr::V4(ipv4.get_destination());
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let flags = tcp.get_flags(); // flags is u8
                    let packet_length = tcp.payload().len();

                    if src_port == 53 || dst_port == 53 {
                        // This is DNS over TCP
                        let mut dns_payload = tcp.payload().to_vec();
                        // Ensure that the payload has at least 2 bytes for the length
                        if dns_payload.len() < 2 {
                            warn!("DNS-over-TCP payload too short: {:?}", dns_payload);
                            return None;
                        }
                        // Strip the first two bytes (length prefix)
                        dns_payload.drain(0..2);
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
                    let udp = match UdpPacket::new(ipv4.payload()) {
                        Some(packet) => packet,
                        None => {
                            warn!("Failed to parse UDP packet");
                            return None;
                        }
                    };
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
            let ipv6 = match Ipv6Packet::new(ethernet.payload()) {
                Some(packet) => packet,
                None => {
                    warn!("Failed to parse IPv6 packet");
                    return None;
                }
            };
            let ip_packet_length = ipv6.get_payload_length() as usize + 40; // IPv6 header is 40 bytes
            let next_protocol = ipv6.get_next_header();
            match next_protocol {
                IpNextHeaderProtocols::Tcp => {
                    let tcp = match TcpPacket::new(ipv6.payload()) {
                        Some(packet) => packet,
                        None => {
                            warn!("Failed to parse TCP packet");
                            return None;
                        }
                    };
                    let src_ip = IpAddr::V6(ipv6.get_source());
                    let dst_ip = IpAddr::V6(ipv6.get_destination());
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let flags = tcp.get_flags(); // flags is u8
                    let packet_length = tcp.payload().len();

                    if src_port == 53 || dst_port == 53 {
                        // This is DNS over TCP
                        let mut dns_payload = tcp.payload().to_vec();
                        // Ensure that the payload has at least 2 bytes for the length
                        if dns_payload.len() < 2 {
                            warn!("DNS-over-TCP payload too short: {:?}", dns_payload);
                            return None;
                        }
                        // Strip the first two bytes (length prefix)
                        dns_payload.drain(0..2);
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
                    let udp = match UdpPacket::new(ipv6.payload()) {
                        Some(packet) => packet,
                        None => {
                            warn!("Failed to parse UDP packet");
                            return None;
                        }
                    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blacklists::{BlacklistInfo, Blacklists, BlacklistsJSON};
    use serial_test::serial;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};

    // Add this helper function for the test
    async fn ensure_port_is_service_port(port: u16, name: &str) {
        use crate::lanscan_port_vulns::*;

        // Check if the port is already recognized
        let service_name = get_name_from_port(port).await;

        if service_name.is_empty() {
            println!("DEBUG: Port {} is not recognized as a service port", port);
            println!("DEBUG: Temporarily fixing by adding port to VULNS for test");

            // Create a temporary port info
            let port_info = VulnerabilityPortInfo {
                port,
                name: name.to_string(),
                description: format!("Test port {}", port),
                vulnerabilities: Vec::new(),
                count: 1,
                protocol: "tcp".to_string(),
            };

            // Add it to the VULNS data model
            let data = VULNS.data.read().await;
            data.port_vulns.insert(port, port_info);

            // Verify it worked
            let updated_name = get_name_from_port(port).await;
            println!(
                "DEBUG: After fix: Port {} service name: '{}'",
                port, updated_name
            );
        } else {
            println!(
                "DEBUG: Port {} is recognized as service: '{}'",
                port, service_name
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_blacklisted_ip_criticality() {
        // Create a test blacklist
        let blacklist_info = BlacklistInfo {
            name: "test_blacklist".to_string(),
            description: Some("Test blacklist".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec![
                "192.168.1.100/32".to_string(), // Specific IP
                "10.0.0.0/8".to_string(),       // Private IP range
                "8.8.8.0/24".to_string(),       // Google DNS range
            ],
        };

        let blacklists_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![blacklist_info],
        };

        let blacklists = Blacklists::new_from_json(blacklists_json);

        // Override global blacklists with our test data to ensure we only have our test blacklist
        LISTS.overwrite_with_test_data(blacklists.clone()).await;

        // Create session data with a blacklisted IP (8.8.8.8)
        let session_data = SessionPacketData {
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

        // Create necessary objects for the test
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session was added with the correct criticality
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_port: 80,
        };

        let session_info = sessions.get(&session_key).unwrap();
        assert_eq!(session_info.criticality, "blacklist:test_blacklist");
    }

    #[tokio::test]
    #[serial]
    async fn test_non_blacklisted_ip_criticality() {
        // Create a test blacklist that doesn't include our test IPs
        let blacklist_info = BlacklistInfo {
            name: "test_blacklist".to_string(),
            description: Some("Test blacklist".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec![
                "172.16.0.0/12".to_string(),  // Different private range
                "203.0.113.0/24".to_string(), // TEST-NET-3 range
            ],
        };

        let blacklists_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![blacklist_info],
        };

        let blacklists = Blacklists::new_from_json(blacklists_json);

        // Override global blacklists with our test data to ensure we only have our test blacklist
        LISTS.overwrite_with_test_data(blacklists.clone()).await;

        // Create session data with a non-blacklisted IP
        let session_data = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), // Cloudflare DNS
                dst_port: 80,
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        // Create necessary objects for the test
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session was added without a criticality
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            dst_port: 80,
        };

        let session_info = sessions.get(&session_key).unwrap();
        assert_eq!(session_info.criticality, "");
    }

    #[tokio::test]
    #[serial]
    async fn test_service_port_based_direction() {
        // Create a test packet with a well-known service port as the source
        // This simulates a server sending a packet to a client
        let session_data = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), // Server IP
                src_port: 80,                                  // HTTP server port
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // Client IP
                dst_port: 12345,                               // Client random high port
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN | TcpFlags::ACK), // Server response
        };

        // Create necessary objects for the test
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session was added with the client as source and server as destination
        // (swapped from the original packet)
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // Now client is source
            src_port: 12345,                                   // Client port
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),     // Server is destination
            dst_port: 80,                                      // Server port
        };

        // Verify the session was stored with the swapped key
        assert!(sessions.contains_key(&session_key),
            "Session key should have been swapped to put client as source and server as destination");

        // Verify service name was assigned from the server port
        let session_info = sessions.get(&session_key).unwrap();
        assert!(
            session_info.dst_service.is_some(),
            "Destination service name should have been set"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_regular_client_server_direction() {
        // Regular client-to-server packet with client using high port and server using well-known port
        let session_data = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // Client IP
                src_port: 54321,                                   // Random high port
                dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),     // Server IP
                dst_port: 443,                                     // HTTPS port
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN), // Client initiating
        };

        // Create necessary objects for the test
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // The original direction should be preserved (client to server)
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // Client as source
            src_port: 54321,                                   // Client port
            dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),     // Server as destination
            dst_port: 443,                                     // Server port
        };

        // Verify the session was stored with the original key
        assert!(
            sessions.contains_key(&session_key),
            "Session key should remain as original client-to-server direction"
        );

        // Verify service name was assigned for the destination port
        let session_info = sessions.get(&session_key).unwrap();
        assert!(
            session_info.dst_service.is_some(),
            "Destination service name should have been set"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_both_ports_are_service_ports() {
        // Create a test packet with both source and destination being service ports
        // This simulates a connection between two servers
        let session_data = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // Server 1 IP
                src_port: 80,                                   // HTTP server port
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // Server 2 IP
                dst_port: 443,                                  // HTTPS server port
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN), // Client initiating with SYN
        };

        // Create necessary objects for the test
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]; // Neither IP is ours
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data.clone(),
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session was added with the same source/dest as the original packet
        // Since SYN without ACK indicates initiation, and both are service ports
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // Original source (initiator)
            src_port: 80,                                   // Original source port
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // Original destination
            dst_port: 443,                                  // Original destination port
        };

        // Verify the session was stored with the original key (not swapped)
        assert!(sessions.contains_key(&session_key),
            "Session key should maintain original direction when both are service ports and SYN flag is set");

        // Verify service name was assigned for the destination port
        let session_info = sessions.get(&session_key).unwrap();
        assert!(
            session_info.dst_service.is_some(),
            "Destination service name should have been set"
        );

        // Now test with a SYN+ACK packet - should swap direction
        let sessions2 = Arc::new(DashMap::new());
        let current_sessions2 = Arc::new(CustomRwLock::new(Vec::new()));

        let session_data2 = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // Server 2 IP
                src_port: 443,                                  // HTTPS server port
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // Server 1 IP
                dst_port: 80,                                   // HTTP server port
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN | TcpFlags::ACK), // Response with SYN+ACK
        };

        // Process the packet
        process_parsed_packet(
            session_data2,
            &sessions2,
            &current_sessions2,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // SYN+ACK indicates this is a response, so we should swap to make the initiator the source
        assert_eq!(sessions2.len(), 1);
        let session_key2 = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // Initiator as source
            src_port: 80,                                   // Initiator port
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // Responder as destination
            dst_port: 443,                                  // Responder port
        };

        // Verify the session was stored with the swapped key
        assert!(
            sessions2.contains_key(&session_key2),
            "Session key should be swapped when both are service ports and SYN+ACK flags are set"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_packet_statistics() {
        // Create test data
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let self_ips = vec![src_ip];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();

        // *** IMPORTANT: Ensure port 80 is recognized as HTTP service ***
        ensure_port_is_service_port(80, "HTTP").await;

        // Set up session storage
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Create session key
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip,
            src_port: 12345,
            dst_ip,
            dst_port: 80,
        };

        // 1. Create and process the first packet (100 bytes, outbound)
        let packet1 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };
        process_parsed_packet(
            packet1,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Check initial statistics
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.average_packet_size, 100.0,
                "Initial average packet size should be 100.0"
            );
            assert_eq!(
                session_info.stats.inbound_outbound_ratio, 0.0,
                "Initial inbound/outbound ratio should be 0.0"
            );
            assert_eq!(
                session_info.stats.segment_count, 0,
                "Initial segment count should be 0"
            );
            assert!(
                session_info.stats.in_segment,
                "Initial packet should start a segment"
            );
        }

        // 2. Process a second packet (200 bytes, inbound)
        let packet2 = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: dst_ip,
                src_port: 80,
                dst_ip: src_ip,
                dst_port: 12345,
            },
            packet_length: 200,
            ip_packet_length: 220,
            flags: Some(TcpFlags::ACK),
        };

        // Debug check direction swapping logic
        let src_service_name = get_name_from_port(packet2.session.src_port).await;
        let dst_service_name = get_name_from_port(packet2.session.dst_port).await;

        // Process the packet (using clone)
        process_parsed_packet(
            packet2.clone(),
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        println!(
            "DEBUG: Inbound packet - src port {} service: '{}', dst port {} service: '{}'",
            packet2.session.src_port, src_service_name, packet2.session.dst_port, dst_service_name
        );

        let src_is_service_port = !src_service_name.is_empty();
        let dst_is_service_port = !dst_service_name.is_empty();
        println!(
            "DEBUG: src_is_service_port: {}, dst_is_service_port: {}",
            src_is_service_port, dst_is_service_port
        );

        // Debug session map contents
        println!("DEBUG: After packet 2, sessions in map: {}", sessions.len());
        for entry in sessions.iter() {
            let key = entry.key();
            let value = entry.value();
            println!(
                "DEBUG: Session key: {}:{} -> {}:{}, bytes: inbound={}, outbound={}, avg_size={}",
                key.src_ip,
                key.src_port,
                key.dst_ip,
                key.dst_port,
                value.stats.inbound_bytes,
                value.stats.outbound_bytes,
                value.stats.average_packet_size
            );
        }

        // Check updated statistics after packet 2
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.orig_pkts, 1,
                "Originator packets should be 1"
            );
            assert_eq!(
                session_info.stats.resp_pkts, 1,
                "Responder packets should be 1"
            );
            assert_eq!(
                session_info.stats.outbound_bytes, 100,
                "Outbound bytes should be 100"
            );
            assert_eq!(
                session_info.stats.inbound_bytes, 200,
                "Inbound bytes should be 200"
            );
            let total_packets = session_info.stats.orig_pkts + session_info.stats.resp_pkts;
            let total_bytes = session_info.stats.inbound_bytes + session_info.stats.outbound_bytes;
            assert_eq!(total_packets, 2, "Total packets should be 2");
            assert_eq!(total_bytes, 300, "Total bytes should be 300");
            // Check average with a tolerance for floating point comparisons
            let expected_avg = 150.0;
            assert!(
                (session_info.stats.average_packet_size - expected_avg).abs() < 0.001,
                "Average packet size should be close to {}, got {}",
                expected_avg,
                session_info.stats.average_packet_size
            );

            assert_eq!(
                session_info.stats.segment_count, 0,
                "No segments completed yet"
            );
        }

        // 3. Process a third packet with PSH flag to end the first segment
        let packet3 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 300,
            ip_packet_length: 320,
            flags: Some(TcpFlags::ACK | TCP_PSH),
        };
        process_parsed_packet(
            packet3,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Check statistics after segment completion
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.average_packet_size, 200.0,
                "Average packet size should be 200.0 after Pkt 3"
            );
            assert_eq!(
                session_info.stats.segment_count, 1,
                "One segment should be completed after Pkt 3"
            );
            assert!(
                !session_info.stats.in_segment,
                "Should not be in a segment after PSH"
            );
            assert!(
                session_info.stats.last_segment_end.is_some(),
                "Last segment end should be set"
            );
        }

        // Introduce a small delay to ensure Packet 4's timestamp is distinct and later
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 4. Process packet to start a new segment
        let packet4 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 150,
            ip_packet_length: 170,
            flags: Some(TcpFlags::ACK),
        };
        process_parsed_packet(
            packet4,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Check that we're in a segment again
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert!(
                session_info.stats.in_segment,
                "Should be in a segment after Packet 4"
            );
        }

        // Introduce a delay LONGER than the segment timeout
        let segment_timeout_duration = {
            let info = sessions.get(&session_key).unwrap();
            std::time::Duration::from_secs_f64(info.stats.segment_timeout)
        };
        tokio::time::sleep(segment_timeout_duration + std::time::Duration::from_secs(1)).await;

        // 5. Process another packet - this should trigger a timeout detection for segment 2
        let packet5 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 250,
            ip_packet_length: 270,
            flags: Some(TcpFlags::ACK),
        };
        process_parsed_packet(
            packet5,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Check statistics after timeout-based segment completion
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 2,
                "A second segment should be completed due to timeout"
            );
            assert!(
                session_info.stats.segment_interarrival > 0.0,
                "Segment interarrival time should be positive"
            );
            // Note: The average interarrival is just the first calculated one here.
        }

        // 6. Test UDP segment detection (only timeout-based)
        let udp_session_key = Session {
            protocol: Protocol::UDP,
            src_ip,
            src_port: 54321,
            dst_ip,
            dst_port: 53, // Using DNS port for service detection consistency if needed
        };

        let udp_packet1 = SessionPacketData {
            session: udp_session_key.clone(),
            packet_length: 100,
            ip_packet_length: 120,
            flags: None, // UDP has no flags
        };
        process_parsed_packet(
            udp_packet1,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Check that UDP session is created and in a segment
        {
            let session_info = sessions.get(&udp_session_key).unwrap();
            assert!(
                session_info.stats.in_segment,
                "UDP session should start in a segment"
            );
            assert_eq!(
                session_info.stats.segment_count, 0,
                "No segments completed yet in UDP session"
            );
        }

        // Final check on packet statistics
        {
            let session_info = sessions.get(&session_key).unwrap();

            // Calculated values based on our test packets (100 + 200 + 300 + 150 + 250 = 1000 bytes, 5 packets)
            let expected_avg = 200.0; // 1000 / 5 = 200
            assert!(
                (session_info.stats.average_packet_size - expected_avg).abs() < 0.001,
                "Final average packet size should be approximately {}, got {}",
                expected_avg,
                session_info.stats.average_packet_size
            );

            // 3 outbound packets (100 + 300 + 150 + 250 = 800), 1 inbound packet (200)
            assert_eq!(
                session_info.stats.inbound_outbound_ratio, 0.25,
                "Final inbound/outbound ratio should be 0.25, got {}",
                session_info.stats.inbound_outbound_ratio
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_session_direction_with_standard_and_ephemeral_ports() {
        // Test case: client with high port connects to server with standard port
        // Expected: session maintained as-is (standard client->server with well-known port)

        let session_packet = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 54321, // Random high port (client)
                dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                dst_port: 443, // HTTPS port (server)
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        // Create necessary objects for the test
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_packet.clone(),
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session direction is maintained as-is
        assert_eq!(sessions.len(), 1);
        for item in sessions.iter() {
            let session = item.key();
            let info = item.value();

            // Session key should match original packet
            assert_eq!(session.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(session.src_port, 54321);
            assert_eq!(session.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
            assert_eq!(session.dst_port, 443);

            // Verify it's classified as outbound
            assert_eq!(info.stats.outbound_bytes, 100);
            assert_eq!(info.stats.inbound_bytes, 0);
            assert_eq!(info.stats.history, "S"); // 'S' for originator SYN
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_session_direction_server_to_client() {
        // Test case: server with standard port connects to client with high port
        // Expected: direction flipped (non-standard but possible scenario)

        let session_packet = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                src_port: 80, // HTTP port (server)
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_port: 54321, // Random high port (client)
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        // Create necessary objects for the test
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_packet.clone(),
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session direction is flipped
        assert_eq!(sessions.len(), 1);
        for item in sessions.iter() {
            let session = item.key();
            let info = item.value();

            // Session key should be flipped due to service port detection
            assert_eq!(session.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(session.src_port, 54321);
            assert_eq!(session.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
            assert_eq!(session.dst_port, 80);

            // Because the packet was from the responder in this flipped session,
            // it should be counted as inbound
            assert_eq!(info.stats.outbound_bytes, 0);
            assert_eq!(info.stats.inbound_bytes, 100);
            assert_eq!(info.stats.history, "s"); // lowercase 's' for responder SYN
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_session_direction_both_standard_ports() {
        // Test case: communication between two well-known service ports
        // Expected: direction determined by TCP flags - SYN identifies client

        let session_packet_syn = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 443, // HTTPS
                dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                dst_port: 80, // HTTP
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN), // Client initiating with SYN
        };

        // Create necessary objects for the test
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_packet_syn.clone(),
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session direction is maintained due to SYN flag
        assert_eq!(sessions.len(), 1);
        for item in sessions.iter() {
            let session = item.key();
            let info = item.value();

            // Session key should match original packet
            assert_eq!(session.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(session.src_port, 443);
            assert_eq!(session.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
            assert_eq!(session.dst_port, 80);

            // Verify it's classified as outbound since this was a SYN packet
            assert_eq!(info.stats.outbound_bytes, 100);
            assert_eq!(info.stats.inbound_bytes, 0);
            assert_eq!(info.stats.history, "S"); // 'S' for originator SYN
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_session_direction_with_synack() {
        // Test case: Response with SYN+ACK between two well-known service ports
        // Expected: direction flipped to make the originator the source

        // Create the first session
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Server responding with SYN+ACK
        let session_packet_synack = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                src_port: 80, // HTTP
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_port: 443, // HTTPS
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN | TcpFlags::ACK), // Server responding with SYN+ACK
        };

        // Process the SYN+ACK packet
        process_parsed_packet(
            session_packet_synack.clone(),
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session direction was flipped (client as source)
        assert_eq!(sessions.len(), 1);
        for item in sessions.iter() {
            let session = item.key();
            let info = item.value();

            // Session key should be flipped due to SYN+ACK indicating the responder
            assert_eq!(session.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            assert_eq!(session.src_port, 443);
            assert_eq!(session.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
            assert_eq!(session.dst_port, 80);

            // The SYN+ACK packet came from the responder in this flipped session
            assert_eq!(info.stats.outbound_bytes, 0);
            assert_eq!(info.stats.inbound_bytes, 100);
            assert_eq!(info.stats.history, "h"); // lowercase 'h' for responder SYN+ACK
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_segment_interarrival_edge_cases() {
        // Create test data
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let self_ips = vec![src_ip];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();

        // Set up session storage
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Create session key
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip,
            src_port: 12345,
            dst_ip,
            dst_port: 80,
        };

        // Ensure port 80 is recognized as a service port
        ensure_port_is_service_port(80, "HTTP").await;

        // 1. Create and process the first packet
        let packet1 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };
        process_parsed_packet(
            packet1,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Sleep to ensure time difference
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // 2. Process a PSH packet to end the first segment
        let packet2 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 200,
            ip_packet_length: 220,
            flags: Some(TcpFlags::ACK | TCP_PSH),
        };
        process_parsed_packet(
            packet2,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify first segment ended
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 1,
                "First segment should be completed"
            );
            assert!(
                !session_info.stats.in_segment,
                "Should not be in a segment after PSH"
            );
        }

        // 3. Very quickly send a packet to start a new segment and another to end it
        // Start segment 2
        let packet3 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 150,
            ip_packet_length: 170,
            flags: Some(TcpFlags::ACK),
        };
        process_parsed_packet(
            packet3,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Immediately end segment 2 without sleeping
        let packet4 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 250,
            ip_packet_length: 270,
            flags: Some(TcpFlags::ACK | TCP_PSH),
        };
        process_parsed_packet(
            packet4,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Check that segment interarrival time exists but is very small
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 2,
                "Second segment should be completed"
            );
            assert!(
                session_info.stats.segment_interarrival >= 0.0,
                "Segment interarrival time should be positive"
            );
            // We can't be too specific about the exact value since it depends on execution speed
        }

        // 4. Start another segment but with clock time manipulation scenario
        // Sleep to ensure third segment has a clear start time
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Start segment 3
        let packet5 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 300,
            ip_packet_length: 320,
            flags: Some(TcpFlags::ACK),
        };
        process_parsed_packet(
            packet5,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Manually manipulate the last segment end time to be in the future relative to current time
        // This is to simulate clock adjustments or cross-device time discrepancies
        {
            let mut info = sessions.get_mut(&session_key).unwrap();
            // Set last_segment_end to 100ms in the future
            info.stats.last_segment_end = Some(Utc::now() + chrono::Duration::milliseconds(100));
        }

        // End segment 3 with another PSH packet
        let packet6 = SessionPacketData {
            session: session_key.clone(),
            packet_length: 350,
            ip_packet_length: 370,
            flags: Some(TcpFlags::ACK | TCP_PSH),
        };
        process_parsed_packet(
            packet6,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Check that negative interarrival was handled gracefully
        {
            let session_info = sessions.get(&session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 3,
                "Third segment should be completed"
            );

            // The interarrival calculation should either skip the negative value or handle it
            // We're primarily checking that the code didn't crash and the stats are still reasonable
            assert!(
                session_info.stats.segment_interarrival >= 0.0,
                "Segment interarrival should remain non-negative despite time anomaly"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_udp_segment_timeout() {
        // Create test data for UDP
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let self_ips = vec![src_ip];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();

        // Set up session storage
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Create UDP session key
        let udp_session_key = Session {
            protocol: Protocol::UDP,
            src_ip,
            src_port: 12345,
            dst_ip,
            dst_port: 53, // DNS port
        };

        // 1. Create and process the first UDP packet
        let udp_packet1 = SessionPacketData {
            session: udp_session_key.clone(),
            packet_length: 100,
            ip_packet_length: 120,
            flags: None, // UDP has no flags
        };
        process_parsed_packet(
            udp_packet1,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify UDP session creation
        {
            let session_info = sessions.get(&udp_session_key).unwrap();
            assert!(
                session_info.stats.in_segment,
                "UDP session should start in a segment"
            );
            assert_eq!(
                session_info.stats.segment_count, 0,
                "No segments completed yet"
            );
        }

        // Get the session timeout value
        let segment_timeout_duration = {
            let info = sessions.get(&udp_session_key).unwrap();
            std::time::Duration::from_secs_f64(info.stats.segment_timeout)
        };

        // Wait longer than the timeout to trigger segment end
        tokio::time::sleep(segment_timeout_duration + std::time::Duration::from_secs(1)).await;

        // 2. Send another UDP packet - should trigger timeout for first segment
        let udp_packet2 = SessionPacketData {
            session: udp_session_key.clone(),
            packet_length: 200,
            ip_packet_length: 220,
            flags: None,
        };
        process_parsed_packet(
            udp_packet2,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify segment completion due to timeout
        {
            let session_info = sessions.get(&udp_session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 1,
                "First segment should be completed due to timeout"
            );
            assert!(
                session_info.stats.in_segment,
                "Should be in a new segment after packet 2"
            );
            assert!(
                session_info.stats.last_segment_end.is_some(),
                "Last segment end time should be set"
            );
        }

        // 3. Send multiple rapid UDP packets that don't exceed timeout
        for i in 0..5 {
            let udp_packet_n = SessionPacketData {
                session: udp_session_key.clone(),
                packet_length: 100 + i * 20,
                ip_packet_length: 120 + i * 20,
                flags: None,
            };
            process_parsed_packet(
                udp_packet_n,
                &sessions,
                &current_sessions,
                &self_ips_set,
                &filter,
                None,
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Verify no new segments were created
        {
            let session_info = sessions.get(&udp_session_key).unwrap();
            assert_eq!(
                session_info.stats.segment_count, 1,
                "Still only one segment should be completed"
            );
            assert!(
                session_info.stats.in_segment,
                "Should still be in the same segment after rapid packets"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_packet_ordering_and_statistics() {
        // Create test data
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let self_ips = vec![src_ip];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();

        // Set up session storage
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Create session key
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip,
            src_port: 12345,
            dst_ip,
            dst_port: 80,
        };

        // Ensure HTTP port is recognized
        ensure_port_is_service_port(80, "HTTP").await;

        // 1. Process packets out of order - FIN before SYN
        // First process a FIN packet (which would normally come later in the session)
        let packet_fin = SessionPacketData {
            session: session_key.clone(),
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::FIN | TcpFlags::ACK),
        };
        process_parsed_packet(
            packet_fin,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Now process a SYN packet (which would normally start the session)
        let packet_syn = SessionPacketData {
            session: session_key.clone(),
            packet_length: 150,
            ip_packet_length: 170,
            flags: Some(TcpFlags::SYN),
        };
        process_parsed_packet(
            packet_syn,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Check that statistics are still updated correctly despite out-of-order packets
        {
            let session_info = sessions.get(&session_key).unwrap();
            // Both packets should be counted
            assert_eq!(
                session_info.stats.orig_pkts, 2,
                "Both packets should be counted as originator packets"
            );
            // Total bytes should be the sum of both packets
            assert_eq!(
                session_info.stats.outbound_bytes, 250,
                "Total outbound bytes should be 250 (100+150)"
            );

            // Average packet size should account for both
            let expected_avg = 125.0; // (100 + 150) / 2
            assert!(
                (session_info.stats.average_packet_size - expected_avg).abs() < 0.001,
                "Average packet size should be approximately 125 bytes"
            );

            // Check that history contains both flags in the order they were processed
            assert!(
                session_info.stats.history.contains('F'),
                "History should contain FIN flag"
            );
            assert!(
                session_info.stats.history.contains('S'),
                "History should contain SYN flag"
            );
            // The history should have F before S since that's the order we processed them
            let f_pos = session_info.stats.history.find('F').unwrap();
            let s_pos = session_info.stats.history.find('S').unwrap();
            assert!(
                f_pos < s_pos,
                "FIN flag should appear before SYN flag in history"
            );

            // Should have an end time since we saw a FIN
            assert!(
                session_info.stats.end_time.is_some(),
                "End time should be set because of FIN flag"
            );

            // Should have a connection state since we saw a FIN
            assert!(
                session_info.stats.conn_state.is_some(),
                "Connection state should be set"
            );
        }

        // 2. Process out-of-order packets with segment boundaries
        // Create a new session key to avoid interference
        let session_key2 = Session {
            protocol: Protocol::TCP,
            src_ip,
            src_port: 12346, // Different source port
            dst_ip,
            dst_port: 80,
        };

        // Send a PSH packet first (would normally end a segment)
        let packet_psh = SessionPacketData {
            session: session_key2.clone(),
            packet_length: 200,
            ip_packet_length: 220,
            flags: Some(TcpFlags::ACK | TCP_PSH),
        };
        process_parsed_packet(
            packet_psh,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Then send a regular ACK packet (would normally be in the middle of a segment)
        let packet_ack = SessionPacketData {
            session: session_key2.clone(),
            packet_length: 300,
            ip_packet_length: 320,
            flags: Some(TcpFlags::ACK),
        };
        process_parsed_packet(
            packet_ack,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Check segment handling with out-of-order packets
        {
            let session_info = sessions.get(&session_key2).unwrap();

            // Since the first packet had PSH, it should have started and immediately ended a segment
            assert_eq!(
                session_info.stats.segment_count, 1,
                "Should have completed one segment with PSH"
            );

            // The second packet should have started a new segment
            assert!(
                session_info.stats.in_segment,
                "Should be in a new segment after second packet"
            );

            // Packets and bytes should be counted correctly
            assert_eq!(session_info.stats.orig_pkts, 2, "Should count both packets");
            assert_eq!(
                session_info.stats.outbound_bytes, 500,
                "Total outbound bytes should be 500 (200+300)"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_multiple_blacklists_criticality() {
        // Create test blacklists with overlapping entries
        let blacklist_info1 = BlacklistInfo {
            name: "test_blacklist_1".to_string(),
            description: Some("Test blacklist 1".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec![
                "192.168.1.100/32".to_string(),
                "10.0.0.0/8".to_string(),
                "198.51.100.0/24".to_string(), // Overlapping IP range
            ],
        };

        let blacklist_info2 = BlacklistInfo {
            name: "test_blacklist_2".to_string(),
            description: Some("Test blacklist 2".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec![
                "198.51.100.0/24".to_string(), // Overlapping IP range
                "203.0.113.0/24".to_string(),
            ],
        };

        let blacklists_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![blacklist_info1, blacklist_info2],
        };

        let blacklists = Blacklists::new_from_json(blacklists_json);
        LISTS.overwrite_with_test_data(blacklists.clone()).await;

        // Create session with an IP that appears in both blacklists
        let session_data = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)), // IP in the overlapping range
                dst_port: 80,
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        // Create necessary test objects
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify the session was added with criticality from both blacklists
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
            dst_port: 80,
        };

        let session_info = sessions.get(&session_key).unwrap();
        // Both blacklist names should be in the criticality, separated by comma
        assert!(session_info
            .criticality
            .contains("blacklist:test_blacklist_1"));
        assert!(session_info
            .criticality
            .contains("blacklist:test_blacklist_2"));
        // Blacklist names should be sorted
        assert_eq!(
            session_info.criticality,
            "blacklist:test_blacklist_1,blacklist:test_blacklist_2"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_ipv6_blacklisted_ip() {
        // Create a test blacklist with IPv6 addresses
        let blacklist_info = BlacklistInfo {
            name: "ipv6_blacklist".to_string(),
            description: Some("IPv6 Test blacklist".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec![
                "2001:db8::/32".to_string(),           // Documentation IPv6 range
                "2001:db8:1234:5678::/64".to_string(), // More specific prefix
            ],
        };

        let blacklists_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![blacklist_info],
        };

        let blacklists = Blacklists::new_from_json(blacklists_json);
        LISTS.overwrite_with_test_data(blacklists.clone()).await;

        // Create session with a blacklisted IPv6 address
        let session_data = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 12345,
                dst_ip: IpAddr::V6("2001:db8:1234:5678:abcd:ef01:2345:6789".parse().unwrap()),
                dst_port: 80,
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        // Create necessary objects for the test
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that the session was added with the correct criticality
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 12345,
            dst_ip: IpAddr::V6("2001:db8:1234:5678:abcd:ef01:2345:6789".parse().unwrap()),
            dst_port: 80,
        };

        let session_info = sessions.get(&session_key).unwrap();
        assert_eq!(session_info.criticality, "blacklist:ipv6_blacklist");
    }

    #[tokio::test]
    #[serial]
    async fn test_subnet_blacklisting() {
        // Create a test blacklist with public IP ranges (not private ranges)
        let blacklist_info = BlacklistInfo {
            name: "subnet_blacklist".to_string(),
            description: Some("Subnet Test blacklist".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec![
                "198.51.100.0/24".to_string(), // TEST-NET-2 range (small subnet)
                "203.0.113.0/24".to_string(),  // TEST-NET-3 range (small subnet)
                "198.18.0.0/15".to_string(),   // Benchmarking range (large subnet)
            ],
        };

        let blacklists_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![blacklist_info],
        };

        let blacklists = Blacklists::new_from_json(blacklists_json);
        LISTS.overwrite_with_test_data(blacklists.clone()).await;

        // Test multiple IPs from different parts of the subnets using public test ranges
        let test_ips = vec![
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)), true), // In TEST-NET-2 range
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 255)), true), // Edge of TEST-NET-2 range
            (IpAddr::V4(Ipv4Addr::new(198, 51, 101, 1)), false), // Just outside TEST-NET-2 range
            (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 128)), true), // Middle of TEST-NET-3 range
            (IpAddr::V4(Ipv4Addr::new(198, 18, 255, 255)), true), // Part of benchmarking range
            (IpAddr::V4(Ipv4Addr::new(198, 20, 0, 0)), false),  // Just outside benchmarking range
        ];

        for (test_ip, should_be_blacklisted) in test_ips {
            // Create session with the test IP
            let session_data = SessionPacketData {
                session: Session {
                    protocol: Protocol::TCP,
                    src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    src_port: 12345,
                    dst_ip: test_ip,
                    dst_port: 80,
                },
                packet_length: 100,
                ip_packet_length: 120,
                flags: Some(TcpFlags::SYN),
            };

            // Create new test objects for each iteration
            let sessions = Arc::new(DashMap::new());
            let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
            let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
            let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
            let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

            // Process the packet
            process_parsed_packet(
                session_data,
                &sessions,
                &current_sessions,
                &self_ips_set,
                &filter,
                None,
            )
            .await;

            // Verify correct blacklist detection
            assert_eq!(sessions.len(), 1);
            let session_key = Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                src_port: 12345,
                dst_ip: test_ip,
                dst_port: 80,
            };

            let session_info = sessions.get(&session_key).unwrap();
            if should_be_blacklisted {
                assert_eq!(
                    session_info.criticality, "blacklist:subnet_blacklist",
                    "IP {:?} should be blacklisted but isn't",
                    test_ip
                );
            } else {
                assert_eq!(
                    session_info.criticality, "",
                    "IP {:?} shouldn't be blacklisted but is",
                    test_ip
                );
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_local_blacklisted_ip_handling() {
        // Create a test blacklist that includes local LAN IP ranges
        let blacklist_info = BlacklistInfo {
            name: "local_blacklist".to_string(),
            description: Some("Local Network Blacklist".to_string()),
            last_updated: Some("2025-03-29".to_string()),
            source_url: None,
            ip_ranges: vec![
                "192.168.0.0/16".to_string(), // Common home network range
                "10.0.0.0/8".to_string(),     // Common corporate network range
                "172.16.0.0/12".to_string(),  // Other private range
            ],
        };

        let blacklists_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test-signature".to_string(),
            blacklists: vec![blacklist_info],
        };

        let blacklists = Blacklists::new_from_json(blacklists_json);
        LISTS.overwrite_with_test_data(blacklists.clone()).await;

        // Create a session between two local IPs that are also on the blacklist
        let session_data = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), // Local IP in blacklist
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), // Local IP in blacklist
                dst_port: 80,
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        // Create objects for test
        let sessions = Arc::new(DashMap::new());
        let current_sessions = Arc::new(CustomRwLock::new(Vec::new()));
        let self_ips = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))]; // One of the IPs is self
        let self_ips_set: HashSet<IpAddr> = self_ips.into_iter().collect();
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        // Verify that local IPs don't get marked with criticality even if on blacklist
        assert_eq!(sessions.len(), 1);
        let session_key = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            dst_port: 80,
        };

        let session_info = sessions.get(&session_key).unwrap();
        // Criticality should be empty because we don't apply blacklists to local IPs
        assert_eq!(session_info.criticality, "");

        // Now test a mixed case: local source to blacklisted external destination
        let session_data2 = SessionPacketData {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), // Local IP
                src_port: 54321,
                dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), // External IP not in blacklist
                dst_port: 443,
            },
            packet_length: 100,
            ip_packet_length: 120,
            flags: Some(TcpFlags::SYN),
        };

        // Create new session map for this test
        let sessions2 = Arc::new(DashMap::new());
        let current_sessions2 = Arc::new(CustomRwLock::new(Vec::new()));

        // Process the second packet
        process_parsed_packet(
            session_data2,
            &sessions2,
            &current_sessions2,
            &self_ips_set,
            &filter,
            None,
        )
        .await;

        let session_key2 = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            src_port: 54321,
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_port: 443,
        };

        // This IP is not blacklisted, so criticality should be empty
        let session_info2 = sessions2.get(&session_key2).unwrap();
        assert_eq!(session_info2.criticality, "");
    }
}
