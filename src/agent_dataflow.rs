//! Sensitive data-flow map (INC-7, Stage B explainability).
//!
//! Projects the already-discovered MCP endpoints (+ optional taint observations
//! lifted from divergence evidence) into a **source -> sink data-flow map**:
//! which sensitive sources (secret stores, filesystem-read tools, databases,
//! untrusted-web retrieval) can reach which egress sinks (remote SaaS, exposed
//! binds, network/browser tools), annotated with a taint class and the sink's
//! trust zone.
//!
//! This is a *latent* (config-derived) data-flow map -- the analogue of the
//! capability graph's `Declared` edges. Live corroboration (an actual flodbadd
//! session carrying the sensitive bytes) is layered on in core later; the shape
//! here is deterministic and privacy-safe.
//!
//! Invariants:
//! - **I3 Deterministic-first**: edges + severities come from the rules below.
//! - **I5 Privacy tiers**: only metadata (server names, privilege slugs,
//!   exposure, taint class, finding keys) is carried -- never data bodies.
//! - Findings reuse `VisibilityFinding` so the dismissal model (I4) applies.

use crate::agent_visibility::{short_hash, VisibilityFinding, VisibilitySeverity};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Raw inputs (foundation-local; core maps MCP endpoints + divergence in)
// ---------------------------------------------------------------------------

/// A flattened MCP endpoint, carrying only what the data-flow projection needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawFlowEndpoint {
    pub agent_type: String,
    /// Stable endpoint id (from `McpEndpoint.id`).
    pub id: String,
    pub label: String,
    /// `ToolPrivilegeClass` slugs (`secret_access`, `filesystem_read`, ...).
    pub privilege_slugs: Vec<String>,
    /// `ExposureScope` snake string (`stdio`/`loopback`/`lan`/`remote`/`public`/`unknown`).
    pub exposure: String,
    /// `AuthStrength` snake string (`none`/`shared`/`oauth`/`mtls`/`unknown`).
    pub auth: String,
    pub is_edamame: bool,
}

/// A taint observation lifted from divergence evidence (sensitive file / secret
/// access, untrusted retrieval). Optional corroboration that upgrades the
/// data-flow finding from latent to observed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawTaintObservation {
    pub agent_type: String,
    pub agent_instance_id: String,
    /// `secret` | `sensitive_file` | `database` | `untrusted_web`.
    pub taint_class: String,
    pub label: String,
    pub finding_key: String,
    /// Upstream severity string.
    pub severity: String,
    pub dismissed: bool,
}

// ---------------------------------------------------------------------------
// Output projection
// ---------------------------------------------------------------------------

/// What kind of sensitive data a source carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaintClass {
    Secret,
    SensitiveFile,
    Database,
    UntrustedWeb,
    Unknown,
}

impl TaintClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaintClass::Secret => "secret",
            TaintClass::SensitiveFile => "sensitive_file",
            TaintClass::Database => "database",
            TaintClass::UntrustedWeb => "untrusted_web",
            TaintClass::Unknown => "unknown",
        }
    }
    fn from_privilege(slug: &str) -> Option<TaintClass> {
        match slug {
            "secret_access" => Some(TaintClass::Secret),
            "filesystem_read" => Some(TaintClass::SensitiveFile),
            "database" => Some(TaintClass::Database),
            _ => None,
        }
    }
    fn from_class_str(s: &str) -> TaintClass {
        match s.trim().to_ascii_lowercase().as_str() {
            "secret" => TaintClass::Secret,
            "sensitive_file" | "file" => TaintClass::SensitiveFile,
            "database" => TaintClass::Database,
            "untrusted_web" | "web" => TaintClass::UntrustedWeb,
            _ => TaintClass::Unknown,
        }
    }
}

/// Trust zone of a sink, mirroring the capability-graph zones. `trust2` is an
/// untrusted / cross-boundary surface (remote SaaS, exposed bind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkZone {
    /// Local service boundary (loopback / stdio MCP server).
    Trust1,
    /// LAN-reachable bind.
    Trust2Lan,
    /// Public-internet SaaS the agent connects out to.
    Trust2Remote,
    /// Locally-run server exposed to all interfaces.
    Trust2Public,
    Unknown,
}

impl SinkZone {
    pub fn as_str(&self) -> &'static str {
        match self {
            SinkZone::Trust1 => "trust1",
            SinkZone::Trust2Lan => "trust2_lan",
            SinkZone::Trust2Remote => "trust2_remote",
            SinkZone::Trust2Public => "trust2_public",
            SinkZone::Unknown => "unknown",
        }
    }
    fn from_exposure(exposure: &str) -> SinkZone {
        match exposure.trim().to_ascii_lowercase().as_str() {
            "stdio" | "loopback" => SinkZone::Trust1,
            "lan" => SinkZone::Trust2Lan,
            "remote" => SinkZone::Trust2Remote,
            "public" => SinkZone::Trust2Public,
            _ => SinkZone::Unknown,
        }
    }
    /// True for any sink outside the local trust boundary (a real egress risk).
    fn is_cross_boundary(&self) -> bool {
        matches!(
            self,
            SinkZone::Trust2Lan | SinkZone::Trust2Remote | SinkZone::Trust2Public
        )
    }
}

/// One latent source -> sink data-flow edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowEdge {
    /// Stable id over (agent, source, sink, taint).
    pub edge_id: String,
    pub taint_class: TaintClass,
    pub source_id: String,
    pub source_label: String,
    pub sink_id: String,
    pub sink_label: String,
    pub sink_zone: SinkZone,
    /// Sink auth strength (`none`/`shared`/...) -- weak auth escalates.
    pub sink_auth: String,
    /// True when a divergence taint observation corroborates the source.
    pub observed: bool,
    pub severity: VisibilitySeverity,
    pub summary: String,
}

/// The full data-flow map for one agent type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDataFlowMap {
    pub agent_type: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub edges: Vec<DataFlowEdge>,
    /// HIGH/CRITICAL edges count (alertable gate).
    pub alertable_edge_count: u32,
    pub findings: Vec<VisibilityFinding>,
}

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Defensive cap on edges emitted per agent (sources x sinks can be quadratic).
const MAX_EDGES_PER_AGENT: usize = 200;

fn is_sink_endpoint(ep: &RawFlowEndpoint) -> bool {
    let zone = SinkZone::from_exposure(&ep.exposure);
    zone.is_cross_boundary()
        || ep
            .privilege_slugs
            .iter()
            .any(|s| s == "network" || s == "browser")
}

fn weak_auth(auth: &str) -> bool {
    matches!(auth.trim().to_ascii_lowercase().as_str(), "none" | "unknown")
}

/// Severity for a latent edge from taint class + sink zone + sink auth.
fn edge_severity(taint: TaintClass, zone: SinkZone, auth: &str, observed: bool) -> VisibilitySeverity {
    if taint == TaintClass::Unknown {
        return VisibilitySeverity::Info;
    }
    let cross = zone.is_cross_boundary();
    let remote_or_public = matches!(zone, SinkZone::Trust2Remote | SinkZone::Trust2Public);
    let weak = weak_auth(auth);

    // Secret/Database to a public-internet or exposed sink with weak auth is the
    // sharpest latent exfil shape.
    if matches!(taint, TaintClass::Secret | TaintClass::Database) && remote_or_public && weak {
        return if observed {
            VisibilitySeverity::Critical
        } else {
            VisibilitySeverity::High
        };
    }
    if cross && weak {
        return if observed {
            VisibilitySeverity::High
        } else {
            VisibilitySeverity::Medium
        };
    }
    if cross {
        return VisibilitySeverity::Low;
    }
    VisibilitySeverity::Info
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build one agent type's latent data-flow map from its MCP endpoints and any
/// taint observations. Pure given its inputs.
pub fn build_dataflow_map(
    agent_type: &str,
    endpoints: &[RawFlowEndpoint],
    taints: &[RawTaintObservation],
) -> AgentDataFlowMap {
    // Sources: privileged read endpoints + taint observations.
    let mut sources: Vec<(TaintClass, String, String, bool)> = Vec::new();
    for ep in endpoints.iter().filter(|e| !e.is_edamame) {
        for slug in &ep.privilege_slugs {
            if let Some(tc) = TaintClass::from_privilege(slug) {
                sources.push((tc, ep.id.clone(), ep.label.clone(), false));
            }
        }
    }
    for t in taints.iter().filter(|t| !t.dismissed) {
        sources.push((
            TaintClass::from_class_str(&t.taint_class),
            format!("taint:{}", t.finding_key),
            t.label.clone(),
            true,
        ));
    }

    // Sinks: cross-boundary endpoints or network/browser tools.
    let sinks: Vec<&RawFlowEndpoint> = endpoints
        .iter()
        .filter(|e| !e.is_edamame && is_sink_endpoint(e))
        .collect();

    let mut edges: Vec<DataFlowEdge> = Vec::new();
    'outer: for (taint, src_id, src_label, observed) in &sources {
        for sink in &sinks {
            // A source that *is* the sink endpoint is self-access, not a flow.
            if src_id == &sink.id {
                continue;
            }
            let zone = SinkZone::from_exposure(&sink.exposure);
            let severity = edge_severity(*taint, zone, &sink.auth, *observed);
            let edge_id = format!(
                "flow-{}",
                short_hash(&format!(
                    "{}:{}:{}:{}",
                    agent_type,
                    src_id,
                    sink.id,
                    taint.as_str()
                ))
            );
            let summary = format!(
                "{} data from {} can reach {} ({})",
                taint.as_str(),
                src_label,
                sink.label,
                zone.as_str()
            );
            edges.push(DataFlowEdge {
                edge_id,
                taint_class: *taint,
                source_id: src_id.clone(),
                source_label: src_label.clone(),
                sink_id: sink.id.clone(),
                sink_label: sink.label.clone(),
                sink_zone: zone,
                sink_auth: sink.auth.clone(),
                observed: *observed,
                severity,
                summary,
            });
            if edges.len() >= MAX_EDGES_PER_AGENT {
                break 'outer;
            }
        }
    }

    // Highest severity first, then observed before latent.
    edges.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| b.observed.cmp(&a.observed))
            .then_with(|| a.edge_id.cmp(&b.edge_id))
    });

    let alertable_edge_count = edges.iter().filter(|e| e.severity.is_alertable()).count() as u32;
    let findings = derive_findings(agent_type, &edges);

    AgentDataFlowMap {
        agent_type: agent_type.to_string(),
        generated_at: chrono::Utc::now(),
        edges,
        alertable_edge_count,
        findings,
    }
}

fn severity_rank(s: VisibilitySeverity) -> u8 {
    match s {
        VisibilitySeverity::Critical => 5,
        VisibilitySeverity::High => 4,
        VisibilitySeverity::Medium => 3,
        VisibilitySeverity::Low => 2,
        VisibilitySeverity::Info => 1,
    }
}

fn derive_findings(agent_type: &str, edges: &[DataFlowEdge]) -> Vec<VisibilityFinding> {
    let mut findings = Vec::new();
    if let Some(top) = edges
        .iter()
        .filter(|e| e.severity.is_alertable())
        .max_by(|a, b| severity_rank(a.severity).cmp(&severity_rank(b.severity)))
    {
        findings.push(
            VisibilityFinding::new(
                "dataflow",
                "dataflow_sensitive_egress",
                top.severity,
                &top.edge_id,
                format!("sensitive data-flow to cross-boundary sink on {}", agent_type),
                format!(
                    "{} ({} potential sensitive flow{} on this agent)",
                    top.summary,
                    edges.iter().filter(|e| e.severity.is_alertable()).count(),
                    if edges.iter().filter(|e| e.severity.is_alertable()).count() == 1 {
                        ""
                    } else {
                        "s"
                    }
                ),
            )
            .with_evidence("agent_type", agent_type)
            .with_evidence("taint_class", top.taint_class.as_str())
            .with_evidence("sink_zone", top.sink_zone.as_str())
            .with_evidence("sink_auth", top.sink_auth.clone())
            .with_evidence("observed", top.observed.to_string())
            .with_owasp(),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(
        id: &str,
        label: &str,
        privs: &[&str],
        exposure: &str,
        auth: &str,
    ) -> RawFlowEndpoint {
        RawFlowEndpoint {
            agent_type: "cursor".to_string(),
            id: id.to_string(),
            label: label.to_string(),
            privilege_slugs: privs.iter().map(|s| s.to_string()).collect(),
            exposure: exposure.to_string(),
            auth: auth.to_string(),
            is_edamame: false,
        }
    }

    #[test]
    fn secret_source_to_remote_unauth_sink_is_high() {
        let endpoints = vec![
            ep("src", "vault", &["secret_access"], "stdio", "shared"),
            ep("sink", "vendor-saas", &["network"], "remote", "none"),
        ];
        let m = build_dataflow_map("cursor", &endpoints, &[]);
        assert!(!m.edges.is_empty());
        let top = &m.edges[0];
        assert_eq!(top.taint_class, TaintClass::Secret);
        assert_eq!(top.sink_zone, SinkZone::Trust2Remote);
        assert_eq!(top.severity, VisibilitySeverity::High);
        assert_eq!(m.alertable_edge_count, 1);
        assert!(m
            .findings
            .iter()
            .any(|f| f.rule_id == "dataflow_sensitive_egress"));
    }

    #[test]
    fn observed_taint_upgrades_to_critical() {
        let endpoints = vec![ep("sink", "vendor-saas", &["network"], "remote", "none")];
        let taints = vec![RawTaintObservation {
            agent_type: "cursor".to_string(),
            agent_instance_id: "inst-1".to_string(),
            taint_class: "secret".to_string(),
            label: "/home/u/.aws/credentials".to_string(),
            finding_key: "div:secret:1".to_string(),
            severity: "HIGH".to_string(),
            dismissed: false,
        }];
        let m = build_dataflow_map("cursor", &endpoints, &taints);
        assert_eq!(m.edges[0].severity, VisibilitySeverity::Critical);
        assert!(m.edges[0].observed);
    }

    #[test]
    fn stdio_only_topology_has_no_alertable_flow() {
        let endpoints = vec![
            ep("src", "fs", &["filesystem_read"], "stdio", "none"),
            ep("sink", "local", &["network"], "loopback", "none"),
        ];
        let m = build_dataflow_map("cursor", &endpoints, &[]);
        // sink is trust1 (loopback) -> not cross-boundary -> info only.
        assert_eq!(m.alertable_edge_count, 0);
        assert!(m.findings.is_empty());
    }

    #[test]
    fn dismissed_taint_is_ignored() {
        let endpoints = vec![ep("sink", "saas", &["network"], "remote", "none")];
        let taints = vec![RawTaintObservation {
            agent_type: "cursor".to_string(),
            agent_instance_id: "inst-1".to_string(),
            taint_class: "secret".to_string(),
            label: "x".to_string(),
            finding_key: "k".to_string(),
            severity: "HIGH".to_string(),
            dismissed: true,
        }];
        let m = build_dataflow_map("cursor", &endpoints, &taints);
        assert!(m.edges.is_empty());
    }
}
