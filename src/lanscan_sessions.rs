use crate::asn_db::Record;
use crate::lanscan_interface::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use strum_macros::Display;
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, Serialize, Deserialize, Ord, PartialOrd)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct Session {
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd, Display)]
pub enum WhitelistState {
    Conforming,
    NonConforming,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct SessionL7 {
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct SessionInfo {
    pub session: Session,
    pub status: SessionStatus,
    pub stats: SessionStats,
    pub is_local_src: bool,
    pub is_local_dst: bool,
    pub is_self_src: bool,
    pub is_self_dst: bool,
    pub src_domain: Option<String>,
    pub dst_domain: Option<String>,
    pub dst_service: Option<String>,
    pub l7: Option<SessionL7>,
    pub src_asn: Option<Record>,
    pub dst_asn: Option<Record>,
    pub is_whitelisted: WhitelistState,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct SessionStatus {
    // Protocol independent, for monitoring/reporting
    pub active: bool,
    pub added: bool,
    pub activated: bool,
    pub deactivated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SessionStats {
    // TCP specific
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub last_activity: DateTime<Utc>,
    pub inbound_bytes: u64,         // Bytes from responder to originator
    pub outbound_bytes: u64,        // Bytes from originator to responder
    pub orig_pkts: u64,             // Packets from originator to responder
    pub resp_pkts: u64,             // Packets from responder to originator
    pub orig_ip_bytes: u64,         // IP bytes from originator to responder
    pub resp_ip_bytes: u64,         // IP bytes from responder to originator
    pub history: String,            // Sequence of observed flags
    pub conn_state: Option<String>, // Final session state
    pub missed_bytes: u64,          // Number of bytes missed
    pub uid: String,                // Unique identifier
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd, Display)]
pub enum SessionFilter {
    LocalOnly,
    GlobalOnly,
    All,
}

pub fn filter_local_sessions(
    sessions: &Vec<SessionInfo>,
    interfaces: &LANScanInterfaces,
) -> Vec<SessionInfo> {
    filter_sessions(sessions, SessionFilter::LocalOnly, interfaces)
}

pub fn filter_global_sessions(
    sessions: &Vec<SessionInfo>,
    interfaces: &LANScanInterfaces,
) -> Vec<SessionInfo> {
    filter_sessions(sessions, SessionFilter::GlobalOnly, interfaces)
}

pub mod session_macros {

    macro_rules! is_local_session {
        ($entry:expr, $interfaces:expr) => {
            crate::lanscan_ip::is_local_ip(&$entry.session.src_ip, Some($interfaces))
                && crate::lanscan_ip::is_local_ip(&$entry.session.dst_ip, Some($interfaces))
        };
    }

    macro_rules! is_global_session {
        ($entry:expr, $interfaces:expr) => {
            !crate::lanscan_ip::is_local_ip(&$entry.session.src_ip, Some($interfaces))
                || !crate::lanscan_ip::is_local_ip(&$entry.session.dst_ip, Some($interfaces))
        };
    }

    pub(crate) use is_global_session;
    pub(crate) use is_local_session;
}

pub fn filter_sessions(
    sessions: &Vec<SessionInfo>,
    filter: SessionFilter,
    interfaces: &LANScanInterfaces,
) -> Vec<SessionInfo> {
    match filter {
        SessionFilter::LocalOnly => sessions
            .iter()
            .filter(|c| session_macros::is_local_session!(c, interfaces))
            .cloned()
            .collect(),
        SessionFilter::GlobalOnly => sessions
            .iter()
            .filter(|c| session_macros::is_global_session!(c, interfaces))
            .cloned()
            .collect(),
        SessionFilter::All => sessions.clone(),
    }
}

pub fn format_sessions_zeek(sessions: &Vec<SessionInfo>) -> Vec<String> {
    let mut zeek_logs = Vec::new();

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

    for session in sessions {
        let start_time = session.stats.start_time.timestamp() as f64
            + (session.stats.start_time.timestamp_subsec_micros() as f64 / 1_000_000.0);
        let duration = match session.stats.end_time {
            Some(end_time) => format!(
                "{:.6}",
                (end_time - session.stats.start_time)
                    .num_microseconds()
                    .unwrap_or(0) as f64
                    / 1_000_000.0
            ),
            None => "-".to_string(),
        };
        let orig_bytes = session.stats.outbound_bytes.to_string();
        let resp_bytes = session.stats.inbound_bytes.to_string();
        let proto = match session.session.protocol {
            Protocol::TCP => "tcp",
            Protocol::UDP => "udp",
        };
        let conn_state = session.stats.conn_state.clone().unwrap_or("-".to_string());

        let zeek_entry = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            start_time,
            session.stats.uid,
            session.session.src_ip,
            session.session.src_port,
            session.session.dst_ip,
            session.session.dst_port,
            proto,
            "-", // Service detection not implemented
            duration,
            orig_bytes,
            resp_bytes,
            conn_state,
            "-", // Local origination not determined
            "-", // Local response not determined
            session.stats.missed_bytes,
            session.stats.history,
            session.stats.orig_pkts,
            session.stats.orig_ip_bytes,
            session.stats.resp_pkts,
            session.stats.resp_ip_bytes,
            "-" // Tunnel parents not implemented
        );

        zeek_logs.push(zeek_entry);
    }

    zeek_logs
}

// Get sessions as a vector of String in a readable log format
pub fn format_sessions_log(sessions: &Vec<SessionInfo>) -> Vec<String> {
    let mut log_entries = Vec::new();

    for session_info in sessions.iter() {
        let src_domain = session_info.src_domain.clone();
        let dst_domain = session_info.dst_domain.clone();

        let (username, process_name) = match session_info.l7.clone() {
            Some(l7) => (l7.username, l7.process_name),
            None => ("-".to_string(), "-".to_string()),
        };

        let stats = session_info.stats.clone();
        let is_whitelisted = session_info.is_whitelisted.clone();
        let session = session_info.session.clone();
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
                "Resolving" | "Unknown" => session.src_ip.to_string(),
                _ => name.clone(),
            },
            None => session.src_ip.to_string(),
        };

        let dst_name = match dst_domain {
            Some(name) => match name.as_str() {
                "Resolving" | "Unknown" => session.dst_ip.to_string(),
                _ => name.clone(),
            },
            None => session.dst_ip.to_string(),
        };

        // Add ASN information
        let dst_asn = match session_info.dst_asn.clone() {
            Some(dst_asn) => format!(
                "ASN{} / {} / {}",
                dst_asn.as_number, dst_asn.owner, dst_asn.country
            ),
            None => "Unknown ASN".to_string(),
        };

        let dst_service = match session_info.dst_service.clone() {
            Some(dst_service) => format!("{} ({})", session.dst_port.to_string(), dst_service),
            None => format!("{}", session.dst_port.to_string()),
        };

        let log_entry = format!(
            "[{}] {} {} - {} {}:{} -> {}:{} {} ({} bytes sent, {} bytes received, duration: {}, whitelisted: {})",
            start_time,
            username,
            process_name,
            session.protocol,
            src_name,
            session.src_port,
            dst_name,
            dst_service,
            dst_asn,
            stats.outbound_bytes,
            stats.inbound_bytes,
            duration,
            is_whitelisted
        );

        log_entries.push(log_entry);
    }

    log_entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lanscan_ip::is_local_ip;
    use chrono::{TimeZone, Utc};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_local_ip() {
        // Set an interface with a specific IPv6 /64 prefix.
        let interfaces = LANScanInterfaces {
            interfaces: vec![LANScanInterface {
                name: "test".to_string(),
                ipv4: None,
                ipv6: vec![LANScanInterfaceAddrTypeV6::Local(LANScanInterfaceAddrV6 {
                    ip: Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x0, 0, 0, 0, 0x8888),
                    prefix: 64,
                })],
            }],
        };

        // Test an IPv6 address within the same LAN prefix.
        // This address shares the first 64 bits with the interface (its fourth segment is 0).
        let local_ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x0, 0, 0, 0, 0xabcd));
        assert!(is_local_ip(&local_ipv6, Some(&interfaces)));

        // IPv4 local addresses: should be classified as local.
        let local_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(is_local_ip(&local_ipv4, Some(&interfaces)));

        // IPv4 global address: should not be classified as local.
        let global_ipv4 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!is_local_ip(&global_ipv4, Some(&interfaces)));

        // Loopback IPv6 is inherently local.
        let loopback_ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(is_local_ip(&loopback_ipv6, Some(&interfaces)));

        // Test an IPv6 address outside the LAN prefix.
        // Here, the fourth segment is different (non-zero), so it is in a different /64 subnet.
        let global_ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x1, 0, 0, 0, 0xabcd));
        assert!(!is_local_ip(&global_ipv6, Some(&interfaces)));
    }

    #[test]
    fn test_filter_sessions() {
        let local_ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let local_ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let global_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let interfaces = LANScanInterfaces {
            interfaces: vec![LANScanInterface {
                name: "test".to_string(),
                ipv4: None,
                ipv6: vec![],
            }],
        };

        let session_local = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: local_ip1,
                src_port: 1234,
                dst_ip: local_ip2,
                dst_port: 80,
            },
            status: SessionStatus {
                active: true,
                added: false,
                activated: false,
                deactivated: false,
            },
            stats: SessionStats {
                start_time: Utc::now(),
                end_time: None,
                last_activity: Utc::now(),
                inbound_bytes: 500,
                outbound_bytes: 1000,
                orig_pkts: 10,
                resp_pkts: 15,
                orig_ip_bytes: 1000,
                resp_ip_bytes: 1500,
                history: "ShADadfF".to_string(),
                conn_state: Some("ESTABLISHED".to_string()),
                missed_bytes: 0,
                uid: "S1".to_string(),
            },
            is_local_src: true,
            is_local_dst: true,
            is_self_src: false,
            is_self_dst: false,
            src_domain: Some("local.src.domain".to_string()),
            dst_domain: Some("local.dst.domain".to_string()),
            dst_service: Some("http".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: None,
            is_whitelisted: WhitelistState::Conforming,
        };

        let session_global = SessionInfo {
            session: Session {
                protocol: Protocol::UDP,
                src_ip: local_ip1,
                src_port: 1234,
                dst_ip: global_ip,
                dst_port: 53,
            },
            status: SessionStatus {
                active: false,
                added: true,
                activated: false,
                deactivated: false,
            },
            stats: SessionStats {
                start_time: Utc::now(),
                end_time: Some(Utc::now()),
                last_activity: Utc::now(),
                inbound_bytes: 200,
                outbound_bytes: 300,
                orig_pkts: 5,
                resp_pkts: 7,
                orig_ip_bytes: 300,
                resp_ip_bytes: 400,
                history: "Dd".to_string(),
                conn_state: Some("FINISHED".to_string()),
                missed_bytes: 0,
                uid: "S2".to_string(),
            },
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: Some("local.src.domain".to_string()),
            dst_domain: Some("global.dst.domain".to_string()),
            dst_service: Some("dns".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: Some(Record {
                as_number: 15169,
                owner: "Google LLC".to_string(),
                country: "US".to_string(),
            }),
            is_whitelisted: WhitelistState::NonConforming,
        };

        let sessions = vec![session_local.clone(), session_global.clone()];

        // Test LocalOnly filter
        let local_sessions = filter_sessions(&sessions, SessionFilter::LocalOnly, &interfaces);
        assert_eq!(local_sessions.len(), 1);
        assert_eq!(local_sessions[0], session_local);

        // Test GlobalOnly filter
        let global_sessions = filter_sessions(&sessions, SessionFilter::GlobalOnly, &interfaces);
        assert_eq!(global_sessions.len(), 1);
        assert_eq!(global_sessions[0], session_global);

        // Test All filter
        let all_sessions = filter_sessions(&sessions, SessionFilter::All, &interfaces);
        assert_eq!(all_sessions.len(), 2);
    }

    #[test]
    fn test_format_sessions_zeek() {
        let session = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                src_port: 5555,
                dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                dst_port: 80,
            },
            status: SessionStatus {
                active: true,
                added: false,
                activated: false,
                deactivated: false,
            },
            stats: SessionStats {
                start_time: Utc.timestamp_opt(1_632_143_600, 0).unwrap(),
                end_time: Some(Utc.timestamp_opt(1_632_143_700, 0).unwrap()),
                last_activity: Utc.timestamp_opt(1_632_143_700, 0).unwrap(),
                inbound_bytes: 1500,
                outbound_bytes: 2500,
                orig_pkts: 12,
                resp_pkts: 14,
                orig_ip_bytes: 2500,
                resp_ip_bytes: 1500,
                history: "ShADadfF".to_string(),
                conn_state: Some("ESTABLISHED".to_string()),
                missed_bytes: 0,
                uid: "S3".to_string(),
            },
            is_local_src: true,
            is_local_dst: false,
            is_self_src: false,
            is_self_dst: false,
            src_domain: Some("local.host".to_string()),
            dst_domain: Some("example.com".to_string()),
            dst_service: Some("http".to_string()),
            l7: None,
            src_asn: None,
            dst_asn: Some(Record {
                as_number: 15133,
                owner: "Edgecast Networks Inc.".to_string(),
                country: "US".to_string(),
            }),
            is_whitelisted: WhitelistState::Unknown,
        };

        let sessions = vec![session];

        let zeek_logs = format_sessions_zeek(&sessions);

        // Check header
        assert_eq!(
            zeek_logs[0],
            "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents"
        );

        // Check log entry
        let log_entry = &zeek_logs[1];
        let fields: Vec<&str> = log_entry.split('\t').collect();
        assert_eq!(fields.len(), 21);
        assert_eq!(fields[1], "S3"); // uid
        assert_eq!(fields[2], "192.168.1.2"); // id.orig_h
        assert_eq!(fields[3], "5555"); // id.orig_p
        assert_eq!(fields[4], "93.184.216.34"); // id.resp_h
        assert_eq!(fields[5], "80"); // id.resp_p
        assert_eq!(fields[6], "tcp"); // proto
        assert_eq!(fields[7], "-"); // service
        assert_eq!(fields[10], "1500"); // resp_bytes
        assert_eq!(fields[11], "ESTABLISHED"); // conn_state
    }

    #[test]
    fn test_format_sessions_log() {
        let session = SessionInfo {
            session: Session {
                protocol: Protocol::TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                src_port: 8080,
                dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                dst_port: 443,
            },
            status: SessionStatus {
                active: false,
                added: true,
                activated: false,
                deactivated: true,
            },
            stats: SessionStats {
                start_time: Utc::now(),
                end_time: Some(Utc::now()),
                last_activity: Utc::now(),
                inbound_bytes: 5000,
                outbound_bytes: 4000,
                orig_pkts: 20,
                resp_pkts: 25,
                orig_ip_bytes: 4000,
                resp_ip_bytes: 5000,
                history: "ShADadfF".to_string(),
                conn_state: Some("CLOSED".to_string()),
                missed_bytes: 0,
                uid: "S4".to_string(),
            },
            is_local_src: true,
            is_local_dst: false,
            is_self_src: true,
            is_self_dst: false,
            src_domain: Some("localhost".to_string()),
            dst_domain: Some("example.net".to_string()),
            dst_service: Some("https".to_string()),
            l7: Some(SessionL7 {
                pid: 1234,
                process_name: "test_process".to_string(),
                process_path: "/usr/bin/test_process".to_string(),
                username: "test_user".to_string(),
            }),
            src_asn: None,
            dst_asn: Some(Record {
                as_number: 64496,
                owner: "Example ISP".to_string(),
                country: "US".to_string(),
            }),
            is_whitelisted: WhitelistState::Unknown,
        };

        let sessions = vec![session];

        let log_entries = format_sessions_log(&sessions);

        assert_eq!(log_entries.len(), 1);
        let log_entry = &log_entries[0];

        // Check if the log entry contains expected substrings
        assert!(log_entry.contains("test_user"));
        assert!(log_entry.contains("test_process"));
        assert!(log_entry.contains("localhost"));
        assert!(log_entry.contains("example.net"));
        assert!(log_entry.contains("8080"));
        assert!(log_entry.contains("443"));
        assert!(log_entry.contains("TCP"));
        assert!(log_entry.contains("4000 bytes sent"));
        assert!(log_entry.contains("5000 bytes received"));
    }
}
