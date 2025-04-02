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
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{trace, warn};
use uuid::Uuid;

#[derive(Debug)]
pub enum ParsedPacket {
    SessionPacket(SessionPacketData),
    DnsPacket(DnsPacketData),
}

#[derive(Debug)]
pub struct SessionPacketData {
    pub session: Session,
    pub packet_length: usize,
    pub ip_packet_length: usize,
    pub flags: Option<u8>,
}

#[derive(Debug)]
pub struct DnsPacketData {
    pub dns_payload: Vec<u8>,
}

pub async fn process_parsed_packet(
    parsed_packet: SessionPacketData,
    sessions: &Arc<DashMap<Session, SessionInfo>>,
    current_sessions: &Arc<CustomRwLock<Vec<Session>>>,
    self_ips: &Vec<IpAddr>,
    filter: &Arc<CustomRwLock<SessionFilter>>,
    l7: Option<&Arc<LANScanL7>>,
) {
    let now = Utc::now();
    let is_self_src = self_ips.contains(&parsed_packet.session.src_ip);
    let is_self_dst = self_ips.contains(&parsed_packet.session.dst_ip);

    // Determine if the packet is from the originator (our local machine) or the responder
    let (key, is_originator) = if is_self_src {
        (parsed_packet.session.clone(), true)
    } else if is_self_dst {
        // Swap source and destination to normalize the session key
        (
            Session {
                protocol: parsed_packet.session.protocol.clone(),
                src_ip: parsed_packet.session.dst_ip,
                src_port: parsed_packet.session.dst_port,
                dst_ip: parsed_packet.session.src_ip,
                dst_port: parsed_packet.session.src_port,
            },
            false,
        )
    } else {
        // Neither IP is our own; treat as originator
        (parsed_packet.session.clone(), true)
    };

    // Apply filter before processing
    let filter = filter.read().await.clone();
    if filter == SessionFilter::LocalOnly && is_global_session!(parsed_packet) {
        return;
    } else if filter == SessionFilter::GlobalOnly && is_local_session!(parsed_packet) {
        return;
    }

    if let Some(mut info) = sessions.get_mut(&key) {
        let stats = &mut info.stats;
        stats.last_activity = now;

        if is_originator {
            // Packet from originator (local) to responder
            stats.outbound_bytes += parsed_packet.packet_length as u64;
            stats.orig_pkts += 1;
            stats.orig_ip_bytes += parsed_packet.ip_packet_length as u64;
        } else {
            // Packet from responder to originator
            stats.inbound_bytes += parsed_packet.packet_length as u64;
            stats.resp_pkts += 1;
            stats.resp_ip_bytes += parsed_packet.ip_packet_length as u64;
        }

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
        };

        // Update session stats
        if is_originator {
            stats.outbound_bytes += parsed_packet.packet_length as u64;
            stats.orig_pkts += 1;
            stats.orig_ip_bytes += parsed_packet.ip_packet_length as u64;
        } else {
            stats.inbound_bytes += parsed_packet.packet_length as u64;
            stats.resp_pkts += 1;
            stats.resp_ip_bytes += parsed_packet.ip_packet_length as u64;
        }

        // Update history with correct direction
        if let Some(flags) = parsed_packet.flags {
            let c = map_tcp_flags(flags, parsed_packet.packet_length, is_originator);
            stats.history.push(c);
        }

        // Determine if the session is local
        let is_local_src = is_lan_ip(&key.src_ip);
        let is_local_dst = is_lan_ip(&key.dst_ip);

        trace!("New session: {:?}", key);

        // Queue the new session for L7 resolution immediately
        if let Some(l7) = l7 {
            l7.add_connection_to_resolver(&key).await;
        }

        // Query the ASN database for non-local addresses
        let src_asn = if !is_lan_ip(&key.src_ip) {
            get_asn(key.src_ip).await
        } else {
            None
        };
        let dst_asn = if !is_lan_ip(&key.dst_ip) {
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

        // Create the SessionInfo struct
        let mut session_info = SessionInfo {
            session: key.clone(),
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
            is_whitelisted: WhitelistState::Unknown,
            criticality: "".to_string(),
            whitelist_reason: None,
            uid: uid,
            last_modified: Utc::now(),
        };

        // Check for blacklisted IPs
        let src_ip_str = key.src_ip.to_string();
        let dst_ip_str = key.dst_ip.to_string();

        // Combine checks for blacklist criticality
        let (src_blacklisted, src_lists) = is_ip_blacklisted(&src_ip_str).await;
        let (dst_blacklisted, dst_lists) = is_ip_blacklisted(&dst_ip_str).await;

        let mut criticality_parts = Vec::new();
        if src_blacklisted {
            criticality_parts.extend(src_lists);
        }
        if dst_blacklisted {
            criticality_parts.extend(dst_lists);
        }

        // Remove duplicates
        criticality_parts.sort();
        criticality_parts.dedup();

        // Set criticality if any blacklists matched
        if !criticality_parts.is_empty() {
            session_info.criticality = format!(
                "{}",
                criticality_parts
                    .iter()
                    .map(|name| format!("blacklist:{}", name))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }

        sessions.insert(key.clone(), session_info);
        // Add to current sessions
        current_sessions.write().await.push(key);
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
    use std::net::{IpAddr, Ipv4Addr};

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
        LISTS
            .write()
            .await
            .overwrite_with_test_data(blacklists.clone())
            .await;

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
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &self_ips,
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
        LISTS
            .write()
            .await
            .overwrite_with_test_data(blacklists.clone())
            .await;

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
        let filter = Arc::new(CustomRwLock::new(SessionFilter::All));

        // Process the packet
        process_parsed_packet(
            session_data,
            &sessions,
            &current_sessions,
            &self_ips,
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
}
