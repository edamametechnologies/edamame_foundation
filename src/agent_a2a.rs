//! Agent-to-Agent (A2A) mapping (INC-9, Stage B explainability).
//!
//! Projects the discovered MCP endpoints + capability-graph edges into an
//! **A2A surface map**: which endpoints look like agent-to-agent peers
//! (an A2A agent card at `/.well-known/agent.json`, a known multi-agent
//! framework backend, or a remote peer the agent connects out to) and which
//! capability edges cross a trust boundary in a way that enables a
//! *confused-deputy* handoff (an inner-trust identity bridged to an untrusted
//! peer).
//!
//! This is a config + capability-graph derived map; live A2A protocol
//! corroboration is layered in core later. Deterministic and privacy-safe.
//!
//! Invariants:
//! - **I3 Deterministic-first**: classification + severity from the rules below.
//! - **I5 Privacy tiers**: only metadata (server names, urls' host/path shape,
//!   trust zones) is carried -- never message bodies.
//! - Findings reuse `VisibilityFinding` so the dismissal model (I4) applies.

use crate::agent_visibility::{short_hash, VisibilityFinding, VisibilitySeverity};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Raw inputs (foundation-local; core maps endpoints + graph edges in)
// ---------------------------------------------------------------------------

/// A flattened MCP endpoint for A2A endpoint discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawA2aEndpoint {
    pub agent_type: String,
    pub id: String,
    pub server_name: String,
    pub command: Option<String>,
    pub url: Option<String>,
    /// `ExposureScope` snake string.
    pub exposure: String,
    /// `AuthStrength` snake string.
    pub auth: String,
    pub is_edamame: bool,
}

/// A flattened capability-graph edge for cross-zone handoff detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawA2aEdge {
    pub id: String,
    pub src_label: String,
    pub dst_label: String,
    /// `declares` | `exposes` | `connects_to` | ...
    pub edge_type: String,
    /// `trust0` | `trust1` | `trust2`.
    pub src_zone: String,
    /// `trust0` | `trust1` | `trust2`.
    pub dst_zone: String,
}

// ---------------------------------------------------------------------------
// Output projection
// ---------------------------------------------------------------------------

/// How an A2A peer was recognized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum A2aPeerKind {
    /// Exposes a standard A2A agent card (`/.well-known/agent.json`).
    WellKnownCard,
    /// A known multi-agent framework backend (LangGraph, CrewAI, AutoGen, ...).
    FrameworkBackend,
    /// A remote peer endpoint the agent connects out to (generic).
    RemotePeer,
}

impl A2aPeerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            A2aPeerKind::WellKnownCard => "well_known_card",
            A2aPeerKind::FrameworkBackend => "framework_backend",
            A2aPeerKind::RemotePeer => "remote_peer",
        }
    }
}

/// One discovered A2A peer endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aPeer {
    pub peer_id: String,
    pub agent_type: String,
    pub server_name: String,
    pub kind: A2aPeerKind,
    /// The keyword/path that matched (e.g. `langgraph`, `.well-known/agent.json`).
    pub matched_on: String,
    pub exposure: String,
    pub auth: String,
    pub severity: VisibilitySeverity,
    pub summary: String,
}

/// A capability edge that bridges an inner-trust identity to an untrusted peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfusedDeputyEdge {
    pub edge_id: String,
    pub src_label: String,
    pub dst_label: String,
    pub src_zone: String,
    pub dst_zone: String,
    pub severity: VisibilitySeverity,
    pub summary: String,
}

/// The full A2A surface map across discovered agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aGraph {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub peers: Vec<A2aPeer>,
    pub cross_zone_edges: Vec<ConfusedDeputyEdge>,
    /// HIGH/CRITICAL peers + edges (alertable gate).
    pub alertable_count: u32,
    pub findings: Vec<VisibilityFinding>,
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Multi-agent framework keywords that signal an A2A backend.
const FRAMEWORK_KEYWORDS: &[&str] = &[
    "langgraph",
    "crewai",
    "autogen",
    "autogpt",
    "metagpt",
    "openai-swarm",
    "swarm",
    "agentverse",
    "a2a",
    "agent-to-agent",
];

fn classify_peer(ep: &RawA2aEndpoint) -> Option<(A2aPeerKind, String)> {
    let url = ep.url.as_deref().unwrap_or("").to_ascii_lowercase();
    let name = ep.server_name.to_ascii_lowercase();
    let cmd = ep.command.as_deref().unwrap_or("").to_ascii_lowercase();

    if url.contains(".well-known/agent.json") || url.contains("/agent-card") {
        return Some((A2aPeerKind::WellKnownCard, ".well-known/agent.json".to_string()));
    }
    for kw in FRAMEWORK_KEYWORDS {
        if name.contains(kw) || url.contains(kw) || cmd.contains(kw) {
            return Some((A2aPeerKind::FrameworkBackend, (*kw).to_string()));
        }
    }
    None
}

fn cross_boundary(exposure: &str) -> bool {
    matches!(
        exposure.trim().to_ascii_lowercase().as_str(),
        "lan" | "remote" | "public"
    )
}

fn weak_auth(auth: &str) -> bool {
    matches!(auth.trim().to_ascii_lowercase().as_str(), "none" | "unknown")
}

fn peer_severity(kind: A2aPeerKind, exposure: &str, auth: &str) -> VisibilitySeverity {
    let cross = cross_boundary(exposure);
    let weak = weak_auth(auth);
    match kind {
        // A standard A2A card or framework backend reachable across a boundary
        // with weak auth is a real delegation-hijack / confused-deputy surface.
        A2aPeerKind::WellKnownCard | A2aPeerKind::FrameworkBackend => {
            if cross && weak {
                VisibilitySeverity::High
            } else if cross {
                VisibilitySeverity::Medium
            } else {
                VisibilitySeverity::Low
            }
        }
        A2aPeerKind::RemotePeer => {
            if cross && weak {
                VisibilitySeverity::Medium
            } else {
                VisibilitySeverity::Info
            }
        }
    }
}

fn zone_rank(zone: &str) -> u8 {
    match zone.trim().to_ascii_lowercase().as_str() {
        "trust0" => 0,
        "trust1" => 1,
        "trust2" => 2,
        _ => 3,
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Build the A2A surface map. Pure given its inputs.
pub fn build_a2a_graph(endpoints: &[RawA2aEndpoint], edges: &[RawA2aEdge]) -> A2aGraph {
    let mut peers: Vec<A2aPeer> = Vec::new();
    for ep in endpoints.iter().filter(|e| !e.is_edamame) {
        let Some((kind, matched_on)) = classify_peer(ep) else {
            continue;
        };
        let severity = peer_severity(kind, &ep.exposure, &ep.auth);
        let peer_id = format!(
            "a2a-{}",
            short_hash(&format!("{}:{}:{}", ep.agent_type, ep.server_name, kind.as_str()))
        );
        let summary = format!(
            "{} peer ({}) reachable {} with {} auth",
            kind.as_str(),
            matched_on,
            ep.exposure,
            ep.auth
        );
        peers.push(A2aPeer {
            peer_id,
            agent_type: ep.agent_type.clone(),
            server_name: ep.server_name.clone(),
            kind,
            matched_on,
            exposure: ep.exposure.clone(),
            auth: ep.auth.clone(),
            severity,
            summary,
        });
    }

    // Confused-deputy edges: a `connects_to` edge from an inner-trust node
    // (trust0/trust1) to an untrusted (trust2) peer. The agent lends its
    // identity to reach an untrusted surface.
    let mut cross_zone_edges: Vec<ConfusedDeputyEdge> = Vec::new();
    for e in edges {
        let et = e.edge_type.to_ascii_lowercase();
        if et != "connects_to" {
            continue;
        }
        if zone_rank(&e.src_zone) <= 1 && zone_rank(&e.dst_zone) == 2 {
            let edge_id = format!(
                "a2a-cd-{}",
                short_hash(&format!("{}:{}:{}", e.id, e.src_zone, e.dst_zone))
            );
            cross_zone_edges.push(ConfusedDeputyEdge {
                edge_id,
                src_label: e.src_label.clone(),
                dst_label: e.dst_label.clone(),
                src_zone: e.src_zone.clone(),
                dst_zone: e.dst_zone.clone(),
                severity: VisibilitySeverity::Medium,
                summary: format!(
                    "{} ({}) bridges to untrusted peer {} ({})",
                    e.src_label, e.src_zone, e.dst_label, e.dst_zone
                ),
            });
        }
    }

    peers.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| a.agent_type.cmp(&b.agent_type))
            .then_with(|| a.server_name.cmp(&b.server_name))
    });
    cross_zone_edges.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));

    let alertable_count = peers.iter().filter(|p| p.severity.is_alertable()).count() as u32
        + cross_zone_edges
            .iter()
            .filter(|e| e.severity.is_alertable())
            .count() as u32;

    let findings = derive_findings(&peers, &cross_zone_edges);

    A2aGraph {
        generated_at: chrono::Utc::now(),
        peers,
        cross_zone_edges,
        alertable_count,
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

fn derive_findings(peers: &[A2aPeer], edges: &[ConfusedDeputyEdge]) -> Vec<VisibilityFinding> {
    let mut findings = Vec::new();
    for p in peers.iter().filter(|p| p.severity.is_alertable()) {
        findings.push(
            VisibilityFinding::new(
                "a2a",
                "a2a_exposed_peer",
                p.severity,
                &p.peer_id,
                format!("exposed A2A peer on {}", p.agent_type),
                format!(
                    "{} -- a cross-boundary, weakly-authenticated agent peer can be impersonated to hijack delegated tasks.",
                    p.summary
                ),
            )
            .with_evidence("agent_type", p.agent_type.clone())
            .with_evidence("peer_kind", p.kind.as_str())
            .with_evidence("matched_on", p.matched_on.clone())
            .with_evidence("exposure", p.exposure.clone())
            .with_evidence("auth", p.auth.clone())
            .with_owasp(),
        );
    }
    // One rollup finding for confused-deputy edges (kept MEDIUM by design, so
    // not alertable on its own, but surfaced for triage).
    if let Some(top) = edges.first() {
        findings.push(
            VisibilityFinding::new(
                "a2a",
                "a2a_confused_deputy",
                top.severity,
                &top.edge_id,
                "agent bridges inner-trust identity to untrusted peer",
                format!(
                    "{} ({} cross-zone handoff edge{})",
                    top.summary,
                    edges.len(),
                    if edges.len() == 1 { "" } else { "s" }
                ),
            )
            .with_evidence("src_zone", top.src_zone.clone())
            .with_evidence("dst_zone", top.dst_zone.clone())
            .with_owasp(),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(name: &str, url: Option<&str>, exposure: &str, auth: &str) -> RawA2aEndpoint {
        RawA2aEndpoint {
            agent_type: "openclaw".to_string(),
            id: format!("id-{}", name),
            server_name: name.to_string(),
            command: None,
            url: url.map(|s| s.to_string()),
            exposure: exposure.to_string(),
            auth: auth.to_string(),
            is_edamame: false,
        }
    }

    #[test]
    fn detects_well_known_agent_card() {
        let endpoints = vec![ep(
            "peer",
            Some("https://peer.example.com/.well-known/agent.json"),
            "remote",
            "none",
        )];
        let g = build_a2a_graph(&endpoints, &[]);
        assert_eq!(g.peers.len(), 1);
        assert_eq!(g.peers[0].kind, A2aPeerKind::WellKnownCard);
        assert_eq!(g.peers[0].severity, VisibilitySeverity::High);
        assert!(g.findings.iter().any(|f| f.rule_id == "a2a_exposed_peer"));
    }

    #[test]
    fn detects_framework_backend() {
        let endpoints = vec![ep("langgraph-server", None, "lan", "shared")];
        let g = build_a2a_graph(&endpoints, &[]);
        assert_eq!(g.peers.len(), 1);
        assert_eq!(g.peers[0].kind, A2aPeerKind::FrameworkBackend);
        assert_eq!(g.peers[0].matched_on, "langgraph");
    }

    #[test]
    fn confused_deputy_edge_detected() {
        let edges = vec![RawA2aEdge {
            id: "e1".to_string(),
            src_label: "agent:openclaw".to_string(),
            dst_label: "host:evil.example.com".to_string(),
            edge_type: "connects_to".to_string(),
            src_zone: "trust0".to_string(),
            dst_zone: "trust2".to_string(),
        }];
        let g = build_a2a_graph(&[], &edges);
        assert_eq!(g.cross_zone_edges.len(), 1);
        assert!(g.findings.iter().any(|f| f.rule_id == "a2a_confused_deputy"));
    }

    #[test]
    fn intra_zone_edge_not_flagged() {
        let edges = vec![RawA2aEdge {
            id: "e1".to_string(),
            src_label: "a".to_string(),
            dst_label: "b".to_string(),
            edge_type: "connects_to".to_string(),
            src_zone: "trust1".to_string(),
            dst_zone: "trust1".to_string(),
        }];
        let g = build_a2a_graph(&[], &edges);
        assert!(g.cross_zone_edges.is_empty());
    }

    #[test]
    fn non_a2a_servers_skipped() {
        let endpoints = vec![ep("github", Some("https://api.github.com"), "remote", "oauth")];
        let g = build_a2a_graph(&endpoints, &[]);
        assert!(g.peers.is_empty());
    }
}
