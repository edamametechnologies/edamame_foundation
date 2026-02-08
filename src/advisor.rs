use chrono::{DateTime, Utc};
use edamame_backend::advisor_todos_backend::{AdvicePriorityBackend, AdviceTypeBackend};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use tracing::debug;

/// Internal service threats that should be filtered out from user-visible threat counts
pub const INTERNAL_THREATS: [&str; 3] = ["lanscan", "pwned", "egresscan"];

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub enum Advice {
    /// Recommend remediation for a policy failure. Carries the policy name.
    RemediatePolicy {
        /// Name of the failing policy
        name: String,
    },

    /// Recommend remediation for a detected threat. Carries the threat name/identifier.
    RemediateThreat {
        /// Name or identifier of the threat
        name: String,
    },

    /// Recommend remediation for an open or vulnerable network port on a specific device.
    /// Uses a stable device identifier to avoid churn from changing IPv6 addresses.
    RemediateNetworkPort {
        /// Stable device identifier: MAC address or composite key (vendor:type:ipv4)
        device_id: String,
    },

    /// Recommend remediation for a suspicious network session.
    /// Groups sessions by process name (except "unknown") to reduce todo clutter.
    RemediateNetworkSession {
        /// Process group identifier: "process:{process_name}" or fallback to session_group_id for "unknown"
        process_group_id: String,
        /// List of session UIDs in this process group
        session_uids: Vec<String>,
        /// Legacy: session_group_id for backward compatibility (fallback grouping for "unknown" processes)
        session_group_id: String,
    },

    /// Recommend remediation for a pwned breach affecting a specific email address.
    RemediatePwnedBreach {
        /// Name of the breach reported by the Have I Been Pwned API (or similar)
        name: String,
        /// Email address involved in the breach
        email: String,
    },

    /// Recommend enabling LAN scanning when it's disabled
    ConfigureLanScanMonitoring,

    /// Recommend enabling pwned breach monitoring when it's disabled
    ConfigurePwnedMonitoring,

    /// Recommend enabling network session monitoring when it's disabled
    ConfigureSessionMonitoring,
}

// Priority levels for a todo entry
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum AdvicePriority {
    Low,
    Medium,
    High,
    Critical,
}

// A single todo entry in the advisor queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorTodo {
    pub advice: Advice,
    pub priority: AdvicePriority,
    pub timestamp: DateTime<Utc>,
    pub done: bool,
}

impl AdvisorTodo {
    /// Get the sorted undones todos with priority and timestamp
    pub fn get_sorted_todos(todos: &Vec<AdvisorTodo>) -> Vec<AdvisorTodo> {
        let mut sorted_todos = todos.clone();
        sorted_todos.sort_by(|a, b| {
            let priority_cmp = b.priority.cmp(&a.priority);
            if priority_cmp == std::cmp::Ordering::Equal {
                b.timestamp.cmp(&a.timestamp)
            } else {
                priority_cmp
            }
        });
        sorted_todos
    }

    /// Get todos sorted in a deterministic way by category (variant) with a limit of 20 most recent todos per category
    pub fn get_sorted_todos_for_rag(todos: &Vec<AdvisorTodo>) -> Vec<AdvisorTodo> {
        let mut todos = todos.clone();

        // Remove todos that are done
        todos.retain(|t| !t.done);

        // Only keep the critical, high and medium priority todos
        todos.retain(|t| {
            t.priority == AdvicePriority::Critical
                || t.priority == AdvicePriority::High
                || t.priority == AdvicePriority::Medium
        });

        // Use the shared category mapping from advice_type_str to avoid drift

        // Group todos by category, sort each group by timestamp desc, and keep only the most recent 20
        let mut todos_by_category: HashMap<String, Vec<AdvisorTodo>> = HashMap::new();

        for todo in todos.into_iter() {
            let key = advice_type_str(&todo.advice).to_string();
            todos_by_category.entry(key).or_default().push(todo);
        }

        let mut limited: Vec<AdvisorTodo> = Vec::new();
        for (_category, mut group) in todos_by_category.into_iter() {
            // Sort newest first; use priority then advice as deterministic tie-breakers
            group.sort_by(|a, b| {
                let ts_cmp = b.timestamp.cmp(&a.timestamp);
                if ts_cmp == std::cmp::Ordering::Equal {
                    let pr_cmp = b.priority.cmp(&a.priority);
                    if pr_cmp == std::cmp::Ordering::Equal {
                        // Fall back to advice debug string for stable ordering
                        let a_s = format!("{:?}", a.advice);
                        let b_s = format!("{:?}", b.advice);
                        b_s.cmp(&a_s)
                    } else {
                        pr_cmp
                    }
                } else {
                    ts_cmp
                }
            });
            group.truncate(20);
            limited.extend(group);
        }

        // Deterministic final ordering: by category name, then priority desc, then stable advice key (no timestamp)
        limited.sort_by(|a, b| {
            let a_cat = advice_type_str(&a.advice);
            let b_cat = advice_type_str(&b.advice);
            let cat_cmp = a_cat.cmp(&b_cat);
            if cat_cmp == std::cmp::Ordering::Equal {
                let pr_cmp = b.priority.cmp(&a.priority);
                if pr_cmp == std::cmp::Ordering::Equal {
                    let a_key = format!("{:?}", a.advice);
                    let b_key = format!("{:?}", b.advice);
                    a_key.cmp(&b_key)
                } else {
                    pr_cmp
                }
            } else {
                cat_cmp
            }
        });

        limited
    }
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdvisorState {
    /// List of active threat names
    pub active_threats: HashSet<String>,
    // Are we monitoring policies?
    pub policies_monitoring_active: bool,
    /// List of failed policy names
    pub failed_policies: HashSet<String>,
    /// Does the LAN contain any unsafe devices or hasn't been scanned yet?
    pub lanscan_monitoring_active: bool,
    /// Stable identifiers for devices with high criticality that have open ports
    pub critical_devices: HashSet<String>,
    /// Mapping from stable device identifiers to the latest known inspection handle (IP or hostname)
    pub device_handles: HashMap<String, String>,
    /// Either one of the email has been pwned recently or no emails in the list of emails to check
    pub pwned_monitoring_active: bool,
    /// List of pwned breaches as (name, email) pairs
    pub pwned_breaches: HashSet<(String, String)>,
    /// Are we monitoring the network for suspicious sessions?
    pub sessions_monitoring_active: bool,
    /// Stable identifiers for suspicious network session groups
    pub suspicious_sessions: HashSet<String>,
    /// Mapping from stable session group identifiers to the latest observed session UID
    pub session_handles: HashMap<String, String>,
    /// Number of grouped suspicious session patterns (sessions differing only by source port count as 1)
    pub grouped_suspicious_sessions_count: usize,
}

impl AdvisorState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter out internal service threats that should not be shown to users
    pub fn filter_internal_threats(&mut self) {
        for internal in INTERNAL_THREATS.iter() {
            self.active_threats.remove(*internal);
        }
    }

    /// Check if this state has any security issues
    pub fn has_issues(&self) -> bool {
        !self.active_threats.is_empty()
            || !self.failed_policies.is_empty()
            || !self.critical_devices.is_empty()
            || !self.pwned_breaches.is_empty()
            || !self.suspicious_sessions.is_empty()
            || !self.policies_monitoring_active
            || !self.lanscan_monitoring_active
            || !self.pwned_monitoring_active
            || !self.sessions_monitoring_active
    }

    /// Count the total number of security issues
    pub fn count_issues(&self) -> usize {
        // Start with all concrete issues that are currently known.
        // NOTE: We deliberately *exclude* policy failures for now and treat
        // them together with the policy-monitoring flag below so we do not
        // count both a failure and a missing monitoring service for the same
        // category.
        let mut total = 0usize;

        // 1. Threats are always independent from a monitoring flag – count all.
        total += self.active_threats.len();

        // 2. Policies: either count each failed policy **or** (if monitoring is
        //    disabled) add a single issue representing the lack of coverage.
        if self.policies_monitoring_active {
            total += self.failed_policies.len();
        } else {
            total += 0; // monitoring disabled ⇒ no issue - not being connect to a domain is not a security issue
        }

        // 3. LAN scan / critical devices.
        if self.lanscan_monitoring_active {
            total += self.critical_devices.len();
        } else if self.critical_devices.is_empty() {
            // No concrete devices but the scan itself is off – still an issue.
            total += 1;
        } else {
            // Scan disabled *and* we already have concrete device issues – do
            // not double-count.
            total += self.critical_devices.len();
        }

        // 4. Pwned breach monitoring.
        if self.pwned_monitoring_active {
            total += self.pwned_breaches.len();
        } else if self.pwned_breaches.is_empty() {
            total += 1;
        } else {
            total += self.pwned_breaches.len();
        }

        // 5. Suspicious network sessions (grouped by pattern).
        if self.sessions_monitoring_active {
            debug!(
                "Counting {} grouped suspicious session patterns",
                self.grouped_suspicious_sessions_count
            );
            total += self.grouped_suspicious_sessions_count;
        } else if self.suspicious_sessions.is_empty() {
            total += 1;
        } else {
            debug!(
                "Counting {} grouped suspicious session patterns (monitoring disabled)",
                self.grouped_suspicious_sessions_count
            );
            total += self.grouped_suspicious_sessions_count;
        }

        total
    }

    /// Get the difference from another state (items in self but not in other)
    pub fn diff_from(&self, other: &AdvisorState) -> AdvisorStateDiff {
        AdvisorStateDiff {
            new_active_threats: self
                .active_threats
                .difference(&other.active_threats)
                .cloned()
                .collect(),
            new_failed_policies: self
                .failed_policies
                .difference(&other.failed_policies)
                .cloned()
                .collect(),
            new_critical_devices: self
                .critical_devices
                .difference(&other.critical_devices)
                .cloned()
                .collect(),
            new_pwned_breaches: self
                .pwned_breaches
                .difference(&other.pwned_breaches)
                .cloned()
                .collect(),
            new_suspicious_sessions: self
                .suspicious_sessions
                .difference(&other.suspicious_sessions)
                .cloned()
                .collect(),

            resolved_active_threats: other
                .active_threats
                .difference(&self.active_threats)
                .cloned()
                .collect(),
            resolved_failed_policies: other
                .failed_policies
                .difference(&self.failed_policies)
                .cloned()
                .collect(),
            resolved_critical_devices: other
                .critical_devices
                .difference(&self.critical_devices)
                .cloned()
                .collect(),
            resolved_pwned_breaches: other
                .pwned_breaches
                .difference(&self.pwned_breaches)
                .cloned()
                .collect(),
            resolved_suspicious_sessions: other
                .suspicious_sessions
                .difference(&self.suspicious_sessions)
                .cloned()
                .collect(),
        }
    }

    /// Get the number of remaining security issues
    pub fn remaining_issues_count(&self) -> usize {
        self.count_issues()
    }
}

/// Represents the differences between two advisor states
#[derive(Debug, Clone)]
pub struct AdvisorStateDiff {
    pub new_active_threats: HashSet<String>,
    pub new_failed_policies: HashSet<String>,
    pub new_critical_devices: HashSet<String>,
    pub new_pwned_breaches: HashSet<(String, String)>,
    pub new_suspicious_sessions: HashSet<String>,

    pub resolved_active_threats: HashSet<String>,
    pub resolved_failed_policies: HashSet<String>,
    pub resolved_critical_devices: HashSet<String>,
    pub resolved_pwned_breaches: HashSet<(String, String)>,
    pub resolved_suspicious_sessions: HashSet<String>,
}

/// Filter threat descriptions to EN locale only (for LLM prompts)
///
/// Extracts only EN locale descriptions to reduce payload size
///
/// # Arguments
/// * `descriptions` - All threat descriptions as (locale, title, summary) tuples
/// # Returns
/// Vector of EN-only summaries
pub fn filter_threat_descriptions_en_only(
    descriptions: &[(String, String, String)], // (locale, title, summary)
) -> Vec<String> {
    descriptions
        .iter()
        .filter(|(locale, _, _)| locale == "EN")
        .map(|(_, _, summary)| summary.clone())
        .collect()
}

/// Sanitize RemediateThreat advice with threat metric data
pub fn sanitized_remediate_threat(
    name: &str,
    metric_name: &str,
    metric_severity: &str,
    metric_descriptions: &[String],
    remediation_class: &str,
) -> String {
    // Skip business rules threats
    if metric_name.contains("Business rule") {
        return "".to_string();
    } else {
        let summary = metric_descriptions
            .first()
            .map(|d| d.clone())
            .unwrap_or_else(|| "Active threat detected".to_string());
        let remediation = if remediation_class == "cli" || remediation_class == "internal" {
            "automated remediation available through the EDAMAME app"
        } else {
            "remediation instructions available in the EDAMAME app"
        };
        format!(
            "Handle system threat '{}' (severity {}): {} - {}",
            name, metric_severity, summary, remediation
        )
    }
}

/// Sanitize RemediateNetworkPort advice with device data
pub fn sanitized_remediate_network_port(
    vendor: &str,
    device_type: &str,
    open_ports: &Vec<u16>,
    criticality: &str,
) -> String {
    let vendor = if vendor.is_empty() {
        "Unknown vendor".to_string()
    } else {
        vendor.to_string()
    };
    let dev_type = device_type.to_string();
    // Only critical devices require review
    if criticality == "High" {
        format!(
            "Review the following device using the EDAMAME App, vendor: {}, type: {} with {} vulnerable open port(s): {} - mark those devices as handled if proven safe",
            vendor, dev_type, open_ports.len(), open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        )
    } else {
        "".to_string()
    }
}

/// Sanitize RemediateNetworkSession advice with session data
pub fn sanitized_remediate_network_session(
    process_name: Option<&str>,
    process_path: Option<&str>,
    is_local_src: bool,
    dst_domain: Option<&str>,
    src_domain: Option<&str>,
    dst_ip: std::net::IpAddr,
    src_ip: std::net::IpAddr,
    dst_port: u16,
    dst_service: Option<&str>,
    criticality: &str,
) -> String {
    fn normalized_addr(addr: std::net::IpAddr) -> String {
        match addr {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(v6) => {
                let masked = (u128::from(v6) >> 64) << 64;
                let prefix = std::net::Ipv6Addr::from(masked);
                format!("{}/64", prefix)
            }
        }
    }

    let process_name = process_name.unwrap_or("unknown process");
    let process_path = process_path.unwrap_or("unknown process path");
    let (target, is_inbound) = if is_local_src {
        (
            dst_domain
                .map(|v| v.to_string())
                .unwrap_or_else(|| normalized_addr(dst_ip)),
            false,
        )
    } else {
        (
            src_domain
                .map(|v| v.to_string())
                .unwrap_or_else(|| normalized_addr(src_ip)),
            true,
        )
    };
    let target_service = dst_service.unwrap_or("unknown service");

    format!(
        "Review the following network session using the EDAMAME App, process: '{} ({})' had a suspicious session {} '{}':{} ({}) with the following flags: {} - mark those sessions as handled if proven safe",
        process_name, process_path,
        if is_inbound { "originating from" } else { "going to" },
        target, dst_port, target_service, criticality
    )
}

/// Sanitize RemediatePwnedBreach advice with breach data
pub fn sanitized_remediate_pwned_breach(name: &str, breach_description: &str) -> String {
    format!("Review the following identity breach using the EDAMAME App, name: '{}', description: '{} - mark those breaches as handled after following EDAMAME remediation instructions", name.to_string(), breach_description)
}

impl AdvisorStateDiff {
    /// Check if there are any new issues to create advice for
    pub fn has_new_issues(&self) -> bool {
        !self.new_active_threats.is_empty()
            || !self.new_failed_policies.is_empty()
            || !self.new_critical_devices.is_empty()
            || !self.new_pwned_breaches.is_empty()
            || !self.new_suspicious_sessions.is_empty()
    }
}

/// Return a stable category string for an `Advice` variant
pub fn advice_type_str(advice: &Advice) -> &'static str {
    match advice {
        Advice::RemediatePolicy { .. } => "Policy",
        Advice::RemediateThreat { .. } => "Threat",
        Advice::RemediateNetworkPort { .. } => "NetworkPort",
        Advice::RemediateNetworkSession { .. } => "NetworkSession",
        Advice::RemediatePwnedBreach { .. } => "PwnedBreach",
        Advice::ConfigureLanScanMonitoring
        | Advice::ConfigurePwnedMonitoring
        | Advice::ConfigureSessionMonitoring => "Configure",
    }
}

pub fn map_advice_type_to_backend(advice: &Advice) -> AdviceTypeBackend {
    match advice {
        Advice::RemediatePolicy { .. } => AdviceTypeBackend::Policy,
        Advice::RemediateThreat { .. } => AdviceTypeBackend::Threat,
        Advice::RemediateNetworkPort { .. } => AdviceTypeBackend::NetworkPort,
        Advice::RemediateNetworkSession { .. } => AdviceTypeBackend::NetworkSession,
        Advice::RemediatePwnedBreach { .. } => AdviceTypeBackend::PwnedBreach,
        Advice::ConfigureLanScanMonitoring
        | Advice::ConfigurePwnedMonitoring
        | Advice::ConfigureSessionMonitoring => AdviceTypeBackend::Configure,
    }
}

pub fn map_priority_to_backend(priority: &AdvicePriority) -> AdvicePriorityBackend {
    match priority {
        AdvicePriority::Low => AdvicePriorityBackend::Low,
        AdvicePriority::Medium => AdvicePriorityBackend::Medium,
        AdvicePriority::High => AdvicePriorityBackend::High,
        AdvicePriority::Critical => AdvicePriorityBackend::Critical,
    }
}

/// Compute a stable, human-readable identifier for a todo.
///
/// Returns the semantic stable key directly (device_id, session_group_id, threat name, etc.)
/// instead of hashing it. This makes todo IDs stable across metadata changes while remaining
/// human-readable for debugging and tracking dismissals.
pub fn advisor_todo_id(todo: &AdvisorTodo) -> String {
    match &todo.advice {
        Advice::RemediateNetworkPort { device_id } => device_id.clone(),
        Advice::RemediateNetworkSession {
            process_group_id, ..
        } => process_group_id.clone(),
        Advice::RemediateThreat { name } | Advice::RemediatePolicy { name } => name.clone(),
        Advice::RemediatePwnedBreach { name, email } => format!("{}:{}", email, name),
        Advice::ConfigureLanScanMonitoring => "configure:lanscan".to_string(),
        Advice::ConfigurePwnedMonitoring => "configure:pwned".to_string(),
        Advice::ConfigureSessionMonitoring => "configure:sessions".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn mk_threat(i: i64, minutes_ago: i64) -> AdvisorTodo {
        AdvisorTodo {
            advice: Advice::RemediateThreat {
                name: format!("threat-{i}"),
            },
            priority: AdvicePriority::High,
            timestamp: Utc::now() - Duration::minutes(minutes_ago),
            done: false,
        }
    }

    fn mk_session(i: i64, minutes_ago: i64) -> AdvisorTodo {
        AdvisorTodo {
            advice: Advice::RemediateNetworkSession {
                process_group_id: format!("process:test-process-{i}"),
                session_uids: vec![format!("session-uid-{i}")],
                session_group_id: format!("session-group-{i}"),
            },
            priority: AdvicePriority::High,
            timestamp: Utc::now() - Duration::minutes(minutes_ago),
            done: false,
        }
    }

    fn mk_port(i: i64, minutes_ago: i64) -> AdvisorTodo {
        AdvisorTodo {
            advice: Advice::RemediateNetworkPort {
                device_id: format!("device-{i}"),
            },
            priority: AdvicePriority::High,
            timestamp: Utc::now() - Duration::minutes(minutes_ago),
            done: false,
        }
    }

    #[test]
    fn get_sorted_todos_for_rag_keeps_20_per_category_by_recency() {
        let mut todos: Vec<AdvisorTodo> = Vec::new();

        // Create 20 threats (should truncate to 20 newest)
        for i in 0..25i64 {
            todos.push(mk_threat(i, i));
        }

        // Create 18 sessions (should truncate to 20 newest)
        for i in 0..22i64 {
            todos.push(mk_session(i, i));
        }

        // Create 5 network ports (should keep all 5)
        for i in 0..5i64 {
            todos.push(mk_port(i, i));
        }

        // Add some that should be filtered out: done + low priority
        todos.push(AdvisorTodo {
            advice: Advice::RemediateThreat {
                name: "ignored-done".into(),
            },
            priority: AdvicePriority::High,
            timestamp: Utc::now(),
            done: true,
        });
        todos.push(AdvisorTodo {
            advice: Advice::RemediateThreat {
                name: "ignored-low".into(),
            },
            priority: AdvicePriority::Low,
            timestamp: Utc::now(),
            done: false,
        });

        let result = AdvisorTodo::get_sorted_todos_for_rag(&todos);

        // Count per category
        let mut threat_count = 0usize;
        let mut session_count = 0usize;
        let mut port_count = 0usize;
        let mut has_low = false;
        let mut has_done = false;

        for t in &result {
            match &t.advice {
                Advice::RemediateThreat { .. } => threat_count += 1,
                Advice::RemediateNetworkSession { .. } => session_count += 1,
                Advice::RemediateNetworkPort { .. } => port_count += 1,
                _ => {}
            }
            if t.priority == AdvicePriority::Low {
                has_low = true;
            }
            if t.done {
                has_done = true;
            }
        }

        assert_eq!(threat_count, 20, "expected 20 newest threats");
        assert_eq!(session_count, 20, "expected 20 newest sessions");
        assert_eq!(port_count, 5, "expected all 5 ports kept");
        assert!(!has_low, "low-priority items should be filtered out");
        assert!(!has_done, "done items should be filtered out");

        // Verify deterministic ordering: category asc, then priority desc, then stable advice key asc
        let category = |a: &Advice| -> &'static str { advice_type_str(a) };

        let mut last_cat = "".to_string();
        let mut last_prio: Option<AdvicePriority> = None;
        let mut last_key: Option<String> = None;

        for (idx, t) in result.iter().enumerate() {
            let cat = category(&t.advice).to_string();
            if idx == 0 {
                last_cat = cat.clone();
                last_prio = Some(t.priority);
                last_key = Some(format!("{:?}", t.advice));
                continue;
            }

            // Category should be non-decreasing
            assert!(cat >= last_cat, "categories not sorted deterministically");

            if cat == last_cat {
                // Within same category, priority should be non-increasing (High > Medium)
                if let Some(prev_p) = last_prio {
                    assert!(t.priority <= prev_p);
                }
                // When priority is equal, use advice key ascending for determinism
                if let (Some(prev_p), Some(prev_key)) = (last_prio, &last_key) {
                    if t.priority == prev_p {
                        let key = format!("{:?}", t.advice);
                        assert!(key >= *prev_key);
                    }
                }
            } else {
                // New category boundary resets comparisons
                last_cat = cat.clone();
            }

            last_prio = Some(t.priority);
            last_key = Some(format!("{:?}", t.advice));
        }

        // Print a small sample for visual inspection
        println!("Total returned: {}", result.len());
        for t in result.iter().take(10) {
            println!(
                "{:?} | {:?} | {}",
                t.advice,
                t.priority,
                t.timestamp.to_rfc3339()
            );
        }
    }
}
