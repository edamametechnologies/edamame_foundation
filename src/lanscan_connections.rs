use crate::asn_db::Record;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use strum_macros::Display;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, Serialize, Deserialize, Ord, PartialOrd)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd, Display)]
pub enum WhitelistState {
    Conforming,
    NonConforming,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct ConnectionL7 {
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct ConnectionInfo {
    pub connection: Connection,
    pub stats: ConnectionStats,
    pub src_domain: Option<String>,
    pub dst_domain: Option<String>,
    pub dst_service: Option<String>,
    pub l7: Option<ConnectionL7>,
    pub src_asn: Option<Record>,
    pub dst_asn: Option<Record>,
    pub is_whitelisted: WhitelistState,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct Connection {
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ConnectionStats {
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
    pub conn_state: Option<String>, // Final connection state
    pub missed_bytes: u64,          // Number of bytes missed
    pub uid: String,                // Unique identifier
}
