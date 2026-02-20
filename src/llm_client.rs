/// LLM Prompt Sanitization and Data Preparation
///
/// This module contains all data sanitization and prompt building logic for LLM interactions.
/// It's part of edamame_foundation (open source) for transparency.
///
/// Key principles:
/// - Minimize token usage while preserving security-relevant information
/// - Filter locale-specific data to EN only (user's language handled separately in prompts)
/// - Exclude PII, timestamps, and state flags
/// - Include all security context needed for decision-making
use serde_json::json;
use std::net::IpAddr;

/// Sanitize device info for LLM prompts (compact security-focused summary)
///
/// Excludes: IP/MAC addresses, timestamps, state flags, origin tracking
/// Includes: Security metadata, ports, services, CVE context
///
/// # Returns
/// JSON string with compact device summary (~1-3 KB vs 10-50 KB for full object)
pub fn sanitize_device_for_llm(
    hostname: &str,
    device_type: &str,
    device_vendor: &str,
    os_name: &str,
    os_version: &str,
    mdns_services: &[String],
    open_ports: &[(u16, String, String, String)], // (port, protocol, service, banner)
    criticality: &str,
) -> String {
    // Sanitize mDNS services (keep only _xxx._yyy.local part)
    let sanitized_mdns: Vec<String> = mdns_services
        .iter()
        .filter_map(|s| {
            // Extract pattern like _http._tcp.local
            if let Some(idx) = s.find('_') {
                Some(s[idx..].to_string())
            } else {
                None
            }
        })
        .collect();

    // Build sorted ports array
    let mut ports_info: Vec<_> = open_ports
        .iter()
        .map(|(port, protocol, service, banner)| {
            json!({
                "port": port,
                "protocol": protocol,
                "service": service,
                "banner": banner,
            })
        })
        .collect();
    ports_info.sort_by(|a, b| {
        a["port"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&b["port"].as_u64().unwrap_or(0))
    });

    json!({
        "hostname": if !hostname.is_empty() { hostname } else { "unknown" },
        "device_type": device_type,
        "device_vendor": device_vendor,
        "os_name": os_name,
        "os_version": os_version,
        "mdns_services": sanitized_mdns,
        "open_ports": ports_info,
        "criticality": criticality,
    })
    .to_string()
}

/// Sanitize session info for LLM prompts (comprehensive summary excluding TCP history)
///
/// Excludes: TCP flag history, internal segment tracking
/// Includes: All network metadata, process info (including full L7 details), ASN data, packet/byte stats
///
/// # Returns
/// JSON string with session summary (~3-6 KB vs 65 KB for full object)
pub fn sanitize_session_for_llm(
    uid: &str,
    protocol: &str,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    src_domain: Option<&str>,
    dst_domain: Option<&str>,
    dst_service: Option<&str>,
    process_name: Option<&str>,
    process_path: Option<&str>,
    process_username: Option<&str>,
    process_pid: Option<u32>,
    process_cmd: Option<&[String]>,
    process_cwd: Option<&str>,
    process_memory: Option<u64>,
    process_start_time: Option<u64>,
    process_run_time: Option<u64>,
    process_cpu_usage: Option<u32>,
    process_accumulated_cpu_time: Option<u64>,
    process_disk_usage: Option<&(u64, u64, u64, u64)>, // (total_written_bytes, written_bytes, total_read_bytes, read_bytes)
    process_open_files: &[String],
    parent_pid: Option<u32>,
    parent_process_name: Option<&str>,
    parent_process_path: Option<&str>,
    parent_cmd: Option<&[String]>,
    src_asn: Option<(u32, String, String)>, // (as_number, country, owner)
    dst_asn: Option<(u32, String, String)>,
    criticality: &str,
    status_active: bool,
    start_time: &str,       // ISO8601
    end_time: Option<&str>, // ISO8601
    last_activity: &str,    // ISO8601
    // Stats
    inbound_bytes: u64,
    outbound_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
    orig_ip_bytes: u64,
    resp_ip_bytes: u64,
    conn_state: Option<&str>,
    missed_bytes: u64,
    average_packet_size: f64,
    inbound_outbound_ratio: f64,
    segment_count: u32,
    segment_interarrival: f64,
) -> String {
    json!({
        "uid": uid,
        "protocol": protocol,
        "source_ip": src_ip.to_string(),
        "source_port": src_port,
        "destination_ip": dst_ip.to_string(),
        "destination_port": dst_port,
        "source_domain": src_domain,
        "destination_domain": dst_domain,
        "destination_service": dst_service,
        "process_name": process_name,
        "process_path": process_path,
        "process_username": process_username,
        "process_pid": process_pid,
        "process_cmd": process_cmd,
        "process_cwd": process_cwd,
        "process_memory": process_memory,
        "process_start_time": process_start_time,
        "process_run_time": process_run_time,
        "process_cpu_usage": process_cpu_usage,
        "process_accumulated_cpu_time": process_accumulated_cpu_time,
        "process_disk_usage": process_disk_usage.map(|(tw, w, tr, r)| json!({
            "total_written_bytes": tw,
            "written_bytes": w,
            "total_read_bytes": tr,
            "read_bytes": r,
        })),
        "process_open_files": process_open_files,
        "parent_pid": parent_pid,
        "parent_process_name": parent_process_name,
        "parent_process_path": parent_process_path,
        "parent_cmd": parent_cmd,
        "source_asn": src_asn.map(|(num, country, owner)| json!({
            "as_number": num,
            "country": country,
            "owner": owner,
        })),
        "destination_asn": dst_asn.map(|(num, country, owner)| json!({
            "as_number": num,
            "country": country,
            "owner": owner,
        })),
        "criticality": criticality,
        "status_active": status_active,
        "start_time": start_time,
        "end_time": end_time,
        "last_activity": last_activity,
        "inbound_bytes": inbound_bytes,
        "outbound_bytes": outbound_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "orig_ip_bytes": orig_ip_bytes,
        "resp_ip_bytes": resp_ip_bytes,
        "conn_state": conn_state,
        "missed_bytes": missed_bytes,
        "average_packet_size": average_packet_size,
        "inbound_outbound_ratio": inbound_outbound_ratio,
        "segment_count": segment_count,
        "segment_interarrival": segment_interarrival,
        // Note: Excludes stats.history (TCP flag sequence - can be 10+ KB)
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_device_for_llm() {
        let result = sanitize_device_for_llm(
            "test-device",
            "Router",
            "Netgear",
            "Linux",
            "5.4",
            &vec!["abc123._http._tcp.local".to_string()],
            &vec![
                (
                    80,
                    "tcp".to_string(),
                    "http".to_string(),
                    "nginx".to_string(),
                ),
                (
                    22,
                    "tcp".to_string(),
                    "ssh".to_string(),
                    "OpenSSH 8.9".to_string(),
                ),
            ],
            "Medium",
        );

        assert!(result.contains("test-device"));
        assert!(result.contains("Router"));
        assert!(result.contains("Netgear"));
        assert!(result.contains("_http._tcp.local")); // Sanitized mDNS
        assert!(!result.contains("abc123")); // Serial removed
        assert!(result.contains("22")); // Port 22 should be present (sorted first)
        assert!(result.contains("80")); // Port 80
        assert!(result.contains("OpenSSH 8.9"));
        assert!(result.contains("nginx"));
    }

    #[test]
    fn test_sanitize_session_for_llm() {
        use std::net::Ipv4Addr;

        let cmd = vec!["firefox".to_string(), "--new-window".to_string()];
        let disk_usage = (1000, 500, 2000, 1000);

        let result = sanitize_session_for_llm(
            "test-uid-123",
            "TCP",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            54321,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            443,
            None,
            Some("example.com"),
            Some("https"),
            Some("firefox"),
            Some("/usr/bin/firefox"),
            Some("user"),
            Some(1234),
            Some(cmd.as_slice()),
            Some("/home/user"),
            Some(1048576),
            Some(1698508800),
            Some(3600),
            Some(5),
            Some(1000000),
            Some(&disk_usage),
            &[
                "/usr/lib/libSystem.B.dylib".to_string(),
                "/var/log/syslog".to_string(),
            ],
            Some(1),
            Some("launchd"),
            Some("/sbin/launchd"),
            Some(&["launchd".to_string()]),
            None,
            Some((13335, "US".to_string(), "Cloudflare".to_string())),
            "anomaly:suspicious",
            true,
            "2025-10-28T00:00:00Z",
            None,
            "2025-10-28T00:05:00Z",
            1024,
            2048,
            10,
            15,
            1200,
            2300,
            Some("SF"),
            0,
            102.4,
            0.5,
            5,
            1.2,
        );

        assert!(result.contains("test-uid-123"));
        assert!(result.contains("firefox"));
        assert!(result.contains("example.com"));
        assert!(result.contains("Cloudflare"));
        assert!(result.contains("anomaly:suspicious"));
        assert!(result.contains("1024")); // inbound_bytes value
        assert!(result.contains("2048")); // outbound_bytes value
        assert!(result.contains("segment_count"));
        // Check L7 process fields are included
        assert!(result.contains("process_cmd"));
        assert!(result.contains("process_cwd"));
        assert!(result.contains("process_memory"));
        assert!(result.contains("process_cpu_usage"));
        assert!(result.contains("process_disk_usage"));
        assert!(result.contains("process_open_files"));
        // Should NOT contain history field
        assert!(!result.contains("history"));
    }
}
