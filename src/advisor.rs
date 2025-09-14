use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
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
    RemediateNetworkPort {
        /// IP address of the affected device
        ip_addr: IpAddr,
    },

    /// Recommend remediation for a suspicious network session. Carries the session UID.
    RemediateNetworkSession {
        /// Unique identifier of the network session
        uid: String,
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

    /// Get todos sorted in a deterministic way by type with a limit of 15 most recent todos per category
    pub fn get_sorted_todos_for_rag(todos: &Vec<AdvisorTodo>) -> Vec<AdvisorTodo> {
        let mut todos = todos.clone();

        // Remove todos that are done
        todos.retain(|t| !t.done);

        // Only keep the critical and medium priority todos
        todos
            .retain(|t| t.priority == AdvicePriority::High || t.priority == AdvicePriority::Medium);

        // Group todos by advice type, sort each group, and keep only the most recent 15
        let mut todos_by_type: HashMap<Advice, Vec<AdvisorTodo>> = HashMap::new();

        // Group todos by type
        for todo in todos.iter().cloned() {
            todos_by_type
                .entry(todo.advice.clone())
                .or_insert_with(Vec::new)
                .push(todo);
        }

        // Sort each group by priority (higher to lower), then by advice
        let mut sorted_todos = Vec::new();
        for (_advice, mut group_todos) in todos_by_type.into_iter() {
            group_todos.sort_by(|a, b| {
                let priority_cmp = b.priority.cmp(&a.priority);
                if priority_cmp == std::cmp::Ordering::Equal {
                    b.advice.cmp(&a.advice)
                } else {
                    priority_cmp
                }
            });
            // Keep only the most recent 15 todos for each category
            group_todos.truncate(15);
            sorted_todos.extend(group_todos);
        }

        // Sort the final result by advice type, then by priority, then by timestamp
        sorted_todos.sort_by(|a, b| {
            // Compare advice types by their string representation for consistent ordering
            let a_type_str = format!("{:?}", a.advice);
            let b_type_str = format!("{:?}", b.advice);
            let type_cmp = a_type_str.cmp(&b_type_str);
            if type_cmp == std::cmp::Ordering::Equal {
                let priority_cmp = b.priority.cmp(&a.priority);
                if priority_cmp == std::cmp::Ordering::Equal {
                    b.timestamp.cmp(&a.timestamp)
                } else {
                    priority_cmp
                }
            } else {
                type_cmp
            }
        });

        sorted_todos
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
    /// List of IP addresses for devices with high criticality that have open ports
    pub critical_devices: HashSet<IpAddr>,
    /// Either one of the email has been pwned recently or no emails in the list of emails to check
    pub pwned_monitoring_active: bool,
    /// List of pwned breaches as (name, email) pairs
    pub pwned_breaches: HashSet<(String, String)>,
    /// Are we monitoring the network for suspicious sessions?
    pub sessions_monitoring_active: bool,
    /// List of suspicious network session UIDs
    pub suspicious_sessions: HashSet<String>,
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
    pub new_critical_devices: HashSet<IpAddr>,
    pub new_pwned_breaches: HashSet<(String, String)>,
    pub new_suspicious_sessions: HashSet<String>,

    pub resolved_active_threats: HashSet<String>,
    pub resolved_failed_policies: HashSet<String>,
    pub resolved_critical_devices: HashSet<IpAddr>,
    pub resolved_pwned_breaches: HashSet<(String, String)>,
    pub resolved_suspicious_sessions: HashSet<String>,
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
    let process_name = process_name.unwrap_or("unknown process");
    let process_path = process_path.unwrap_or("unknown process path");
    let (target, is_inbound) = if is_local_src {
        (dst_domain.unwrap_or(&dst_ip.to_string()).to_string(), false)
    } else {
        (src_domain.unwrap_or(&src_ip.to_string()).to_string(), true)
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
