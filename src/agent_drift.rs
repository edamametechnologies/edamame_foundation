//! Goal / delegation drift timeline (INC-6, Stage B explainability).
//!
//! A *drift event* is a deterministic, point-in-time projection of how far an
//! agent's observed behavior has moved from its declared intent, derived from
//! the divergence verdict history the engine already produces. This module is
//! **pure**: it takes foundation-local raw inputs (so it does not depend on
//! `edamame_core`'s divergence types -- the dependency only flows down) and
//! emits an `AgentDriftTimeline` per agent instance.
//!
//! Invariants:
//! - **I3 Deterministic-first**: severity/score come from the rules below, not
//!   from an LLM. The upstream verdicts MAY be LLM-adjudicated, but the drift
//!   projection only re-reads them.
//! - **I5 Privacy tiers**: only metadata (finding keys, categories, severities,
//!   process paths, counts) is ever carried -- never transcript/file bodies.
//! - Findings reuse `VisibilityFinding` so the recurrence-aware dismissal
//!   model (I4) suppresses drift findings through the same path.

use crate::agent_visibility::{short_hash, VisibilityFinding, VisibilitySeverity};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Raw inputs (foundation-local; core maps its divergence/recursion types in)
// ---------------------------------------------------------------------------

/// One divergence-evidence item, flattened to the metadata the drift
/// projection needs. Mirrors the fields of `DivergenceEvidence` that survive
/// the privacy boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDriftEvidence {
    pub finding_key: String,
    pub category: String,
    /// Upstream severity string (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`).
    pub severity: String,
    pub description: String,
    pub process_path: Option<String>,
    pub dismissed: bool,
}

/// One divergence verdict, flattened for the drift projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDriftVerdict {
    pub ts: chrono::DateTime<chrono::Utc>,
    /// Verdict kind string (`CLEAN`/`CLEAN_HEARTBEAT`/`DIVERGENCE`/`NO_MODEL`/`STALE`).
    pub verdict_kind: String,
    pub unexplained_observations: usize,
    pub evidence: Vec<RawDriftEvidence>,
}

/// Per-agent delegation summary (from the recursion analysis) used to emit a
/// delegation-drift event when recursion runs deep or loops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDelegationDrift {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub max_depth: u32,
    pub total_nodes: u32,
    pub loop_detected: bool,
}

// ---------------------------------------------------------------------------
// Output projection
// ---------------------------------------------------------------------------

/// Coarse drift category. Determines which behavioral dimension drifted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftCategory {
    /// The agent's high-level goal/intent could not be verified (no model,
    /// or an action with no declared counterpart).
    Goal,
    /// A tool / process the agent used drifted from what it declared.
    Tool,
    /// Observed system impact (egress, sensitive-file access) drifted from
    /// the declared expectation.
    SystemImpact,
    /// The delegation / recursion structure drifted (deep or looping spawns).
    Delegation,
    /// Model lifecycle drift: staleness or a clean recovery transition.
    Stability,
}

impl DriftCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            DriftCategory::Goal => "goal",
            DriftCategory::Tool => "tool",
            DriftCategory::SystemImpact => "system_impact",
            DriftCategory::Delegation => "delegation",
            DriftCategory::Stability => "stability",
        }
    }
}

/// A flattened evidence reference carried on a drift event (drives the
/// `explain_run_drift` decomposition + UI detail without re-querying history).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvidenceRef {
    pub finding_key: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub process_path: Option<String>,
}

/// One point-in-time drift event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    /// Stable id `drift-<hash>` over (agent, ts, category, verdict kind).
    pub event_id: String,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub category: DriftCategory,
    /// Normalized drift magnitude in `[0.0, 1.0]`.
    pub drift_score: f64,
    pub severity: VisibilitySeverity,
    pub title: String,
    pub summary: String,
    /// Metadata refs (verdict kind, counts) for the timeline row.
    pub refs: Vec<String>,
    /// Contributing evidence (bounded), for explain + detail rendering.
    pub evidence_refs: Vec<DriftEvidenceRef>,
}

/// The full drift timeline for one agent instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDriftTimeline {
    pub agent_type: String,
    pub agent_instance_id: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Chronological drift events (oldest first).
    pub events: Vec<DriftEvent>,
    /// Highest drift score across the timeline (0.0 when no drift).
    pub peak_drift_score: f64,
    /// Number of HIGH/CRITICAL drift events (alertable gate).
    pub alertable_event_count: u32,
    /// Deterministic findings (alertable drift onset), reusing the shared
    /// `VisibilityFinding` shape so the dismissal model (I4) applies.
    pub findings: Vec<VisibilityFinding>,
}

/// "Prove-why" decomposition for a single drift event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEventExplanation {
    pub event: DriftEvent,
    /// Verdict kind immediately preceding this event (`""` when first).
    pub prior_verdict_kind: String,
    /// Human-readable transition (e.g. `CLEAN -> DIVERGENCE`).
    pub transition: String,
    /// Deterministic rationale string assembled from the score inputs.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// Tunables (deterministic scoring)
// ---------------------------------------------------------------------------

/// Delegation depth at/above which a delegation-drift event is emitted.
const DELEGATION_DEPTH_THRESHOLD: u32 = 3;
/// Max number of contributing evidence refs retained per event.
const MAX_EVIDENCE_REFS: usize = 12;

fn severity_weight(sev: &str) -> f64 {
    match sev.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => 0.45,
        "HIGH" => 0.30,
        "MEDIUM" => 0.12,
        "LOW" => 0.05,
        _ => 0.0,
    }
}

/// Map a normalized drift score to a finding severity. Mirrors the
/// attack-pattern severity ladder so the alertable gate stays consistent.
pub fn severity_from_score(score: f64) -> VisibilitySeverity {
    if score >= 0.8 {
        VisibilitySeverity::Critical
    } else if score >= 0.6 {
        VisibilitySeverity::High
    } else if score >= 0.4 {
        VisibilitySeverity::Medium
    } else if score >= 0.2 {
        VisibilitySeverity::Low
    } else {
        VisibilitySeverity::Info
    }
}

fn category_from_evidence(evidence: &[RawDriftEvidence]) -> DriftCategory {
    // Pick the category implied by the highest-severity active evidence item.
    let mut best: Option<(&RawDriftEvidence, f64)> = None;
    for ev in evidence.iter().filter(|e| !e.dismissed) {
        let w = severity_weight(&ev.severity);
        if best.as_ref().map(|(_, bw)| w > *bw).unwrap_or(true) {
            best = Some((ev, w));
        }
    }
    let cat = best.map(|(e, _)| e.category.to_ascii_lowercase());
    match cat.as_deref() {
        Some(c)
            if c.contains("network")
                || c.contains("egress")
                || c.contains("traffic")
                || c.contains("file")
                || c.contains("sensitive")
                || c.contains("blacklist") =>
        {
            DriftCategory::SystemImpact
        }
        Some(c) if c.contains("process") || c.contains("lineage") || c.contains("tool") => {
            DriftCategory::Tool
        }
        Some(_) | None => DriftCategory::Goal,
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Project the divergence verdict history (+ optional delegation summary) for
/// one agent instance into a drift timeline. `verdicts` may be in any order;
/// they are sorted ascending by timestamp here.
pub fn build_drift_timeline(
    agent_type: &str,
    agent_instance_id: &str,
    verdicts: &[RawDriftVerdict],
    delegation: Option<&RawDelegationDrift>,
) -> AgentDriftTimeline {
    let mut sorted: Vec<&RawDriftVerdict> = verdicts.iter().collect();
    sorted.sort_by(|a, b| a.ts.cmp(&b.ts));

    let mut events: Vec<DriftEvent> = Vec::new();
    let mut prev_kind: Option<String> = None;

    for v in &sorted {
        let kind = v.verdict_kind.trim().to_ascii_uppercase();
        let active: Vec<&RawDriftEvidence> = v.evidence.iter().filter(|e| !e.dismissed).collect();

        let (mut score, category, base_title) = match kind.as_str() {
            "DIVERGENCE" => {
                let max_w = active
                    .iter()
                    .map(|e| severity_weight(&e.severity))
                    .fold(0.0_f64, f64::max);
                let breadth = 0.05 * (active.len().min(5) as f64);
                let cat = category_from_evidence(&v.evidence);
                (0.5 + max_w + breadth, cat, "behavior diverged from intent")
            }
            "STALE" => (
                0.35,
                DriftCategory::Stability,
                "behavioral model went stale",
            ),
            "NO_MODEL" => (
                0.25,
                DriftCategory::Goal,
                "no behavioral model to verify intent",
            ),
            // Clean transitions: only emit a (low) recovery event when the
            // previous state was a divergence, so the timeline shows the
            // resolution without flooding on every clean heartbeat.
            "CLEAN" | "CLEAN_HEARTBEAT" => {
                if prev_kind.as_deref() == Some("DIVERGENCE") {
                    (0.1, DriftCategory::Stability, "divergence cleared")
                } else {
                    prev_kind = Some(kind);
                    continue;
                }
            }
            _ => {
                prev_kind = Some(kind);
                continue;
            }
        };

        // Fresh-onset bonus: an observed CLEAN -> DIVERGENCE transition is a
        // sharper signal than a divergence that was already ongoing. A
        // first-ever observation (prev = None) is NOT treated as onset -- we
        // have no evidence the prior state was clean, so it could be ongoing
        // divergence we only just started observing.
        let onset = matches!(
            prev_kind.as_deref(),
            Some("CLEAN") | Some("CLEAN_HEARTBEAT")
        ) && kind == "DIVERGENCE";
        if onset {
            score += 0.1;
        }
        score = score.clamp(0.0, 1.0);

        let severity = severity_from_score(score);
        let event_id = format!(
            "drift-{}",
            short_hash(&format!(
                "{}:{}:{}:{}:{}",
                agent_type,
                agent_instance_id,
                v.ts.to_rfc3339(),
                category.as_str(),
                kind
            ))
        );

        let mut refs = vec![
            format!("verdict={}", kind),
            format!("unexplained_observations={}", v.unexplained_observations),
            format!("active_evidence={}", active.len()),
        ];
        if onset {
            refs.push("onset=true".to_string());
        }

        let evidence_refs: Vec<DriftEvidenceRef> = active
            .iter()
            .take(MAX_EVIDENCE_REFS)
            .map(|e| DriftEvidenceRef {
                finding_key: e.finding_key.clone(),
                category: e.category.clone(),
                severity: e.severity.clone(),
                description: truncate(&e.description, 220),
                process_path: e.process_path.clone(),
            })
            .collect();

        let summary = if active.is_empty() {
            base_title.to_string()
        } else {
            format!(
                "{} ({} observation{})",
                base_title,
                active.len(),
                if active.len() == 1 { "" } else { "s" }
            )
        };

        events.push(DriftEvent {
            event_id,
            ts: v.ts,
            category,
            drift_score: round2(score),
            severity,
            title: title_for(category),
            summary,
            refs,
            evidence_refs,
        });

        prev_kind = Some(kind);
    }

    // Delegation-drift event (structural recursion signal, time-anchored to the
    // recursion refresh).
    if let Some(d) = delegation {
        if d.max_depth >= DELEGATION_DEPTH_THRESHOLD || d.loop_detected {
            let mut score = 0.3 + 0.1 * ((d.max_depth.saturating_sub(2)).min(5) as f64);
            if d.loop_detected {
                score += 0.3;
            }
            score = score.clamp(0.0, 1.0);
            let severity = severity_from_score(score);
            let event_id = format!(
                "drift-{}",
                short_hash(&format!(
                    "{}:{}:delegation:{}:{}",
                    agent_type, agent_instance_id, d.max_depth, d.loop_detected
                ))
            );
            events.push(DriftEvent {
                event_id,
                ts: d.generated_at,
                category: DriftCategory::Delegation,
                drift_score: round2(score),
                severity,
                title: title_for(DriftCategory::Delegation),
                summary: format!(
                    "delegation depth {} across {} node{}{}",
                    d.max_depth,
                    d.total_nodes,
                    if d.total_nodes == 1 { "" } else { "s" },
                    if d.loop_detected {
                        " (loop detected)"
                    } else {
                        ""
                    }
                ),
                refs: vec![
                    format!("max_depth={}", d.max_depth),
                    format!("total_nodes={}", d.total_nodes),
                    format!("loop_detected={}", d.loop_detected),
                ],
                evidence_refs: Vec::new(),
            });
        }
    }

    // Keep the timeline chronological after appending the delegation event.
    events.sort_by(|a, b| a.ts.cmp(&b.ts));

    let peak_drift_score = events.iter().map(|e| e.drift_score).fold(0.0_f64, f64::max);
    let alertable_event_count = events.iter().filter(|e| e.severity.is_alertable()).count() as u32;

    let findings = derive_findings(agent_type, agent_instance_id, &events);

    AgentDriftTimeline {
        agent_type: agent_type.to_string(),
        agent_instance_id: agent_instance_id.to_string(),
        generated_at: chrono::Utc::now(),
        events,
        peak_drift_score: round2(peak_drift_score),
        alertable_event_count,
        findings,
    }
}

impl AgentDriftTimeline {
    /// "Prove-why" for a single event (by id). `None` when the event is
    /// unknown. Reconstructs the prior verdict / transition by walking the
    /// already-ordered event list.
    pub fn explain(&self, event_id: &str) -> Option<DriftEventExplanation> {
        let idx = self.events.iter().position(|e| e.event_id == event_id)?;
        let event = self.events[idx].clone();
        // Prior verdict kind is whatever the previous event recorded in its
        // refs (the timeline is chronological).
        let prior_verdict_kind = if idx == 0 {
            String::new()
        } else {
            verdict_kind_of(&self.events[idx - 1]).unwrap_or_default()
        };
        let cur_kind =
            verdict_kind_of(&event).unwrap_or_else(|| event.category.as_str().to_string());
        let transition = if prior_verdict_kind.is_empty() {
            format!("(first) -> {}", cur_kind)
        } else {
            format!("{} -> {}", prior_verdict_kind, cur_kind)
        };
        let rationale = build_rationale(&event);
        Some(DriftEventExplanation {
            event,
            prior_verdict_kind,
            transition,
            rationale,
        })
    }
}

fn verdict_kind_of(event: &DriftEvent) -> Option<String> {
    event
        .refs
        .iter()
        .find_map(|r| r.strip_prefix("verdict=").map(|s| s.to_string()))
}

/// Extract a `key=value` metadata ref value (e.g. `max_depth`, `total_nodes`,
/// `loop_detected`) carried on a drift event.
fn ref_value(event: &DriftEvent, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    event
        .refs
        .iter()
        .find_map(|r| r.strip_prefix(prefix.as_str()).map(|s| s.to_string()))
}

fn build_rationale(event: &DriftEvent) -> String {
    let mut parts = vec![format!(
        "category={} drift_score={:.2} severity={:?}",
        event.category.as_str(),
        event.drift_score,
        event.severity
    )];
    if !event.evidence_refs.is_empty() {
        let cats: std::collections::BTreeSet<String> = event
            .evidence_refs
            .iter()
            .map(|e| e.category.clone())
            .collect();
        parts.push(format!(
            "{} contributing observation(s) across categories [{}]",
            event.evidence_refs.len(),
            cats.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if event.refs.iter().any(|r| r == "onset=true") {
        parts.push("fresh divergence onset (clean -> divergence transition)".to_string());
    }
    parts.join("; ")
}

fn derive_findings(
    agent_type: &str,
    agent_instance_id: &str,
    events: &[DriftEvent],
) -> Vec<VisibilityFinding> {
    let mut findings = Vec::new();

    // Highest-severity behavioral (non-delegation) drift event.
    if let Some(top) = events
        .iter()
        .filter(|e| e.category != DriftCategory::Delegation && e.severity.is_alertable())
        .max_by(|a, b| a.drift_score.partial_cmp(&b.drift_score).unwrap())
    {
        findings.push(
            VisibilityFinding::new(
                "drift",
                "drift_goal_divergence",
                top.severity,
                agent_instance_id,
                format!("{} drift on {}", top.category.as_str(), agent_type),
                format!(
                    "Observed behavior diverged from declared intent (peak drift {:.2}). {}",
                    top.drift_score, top.summary
                ),
            )
            .with_evidence("agent_type", agent_type)
            .with_evidence("drift_score", format!("{:.2}", top.drift_score))
            .with_evidence("category", top.category.as_str())
            .with_evidence("event_id", top.event_id.clone())
            .with_owasp(),
        );
    }

    // Delegation recursion escalation. The same alertable delegation drift
    // event also surfaces two OWASP-labeled sibling findings -- cascading
    // failure (ASI08) and unbounded consumption (LLM10) -- so the deep/looping
    // delegation structure is visible under both taxonomies. They are derived
    // from the same event and inherit its severity, so they can only fire when
    // `drift_recursion_escalation` already fires: labeling of an already-alertable
    // condition, not a new alert source / threshold.
    if let Some(deleg) = events
        .iter()
        .filter(|e| e.category == DriftCategory::Delegation && e.severity.is_alertable())
        .max_by(|a, b| a.drift_score.partial_cmp(&b.drift_score).unwrap())
    {
        let max_depth = ref_value(deleg, "max_depth").unwrap_or_default();
        let total_nodes = ref_value(deleg, "total_nodes").unwrap_or_default();
        let loop_detected = ref_value(deleg, "loop_detected").unwrap_or_default();
        let drift_score = format!("{:.2}", deleg.drift_score);

        findings.push(
            VisibilityFinding::new(
                "drift",
                "drift_recursion_escalation",
                deleg.severity,
                agent_instance_id,
                format!("recursive delegation escalation on {}", agent_type),
                deleg.summary.clone(),
            )
            .with_evidence("agent_type", agent_type)
            .with_evidence("drift_score", drift_score.clone())
            .with_evidence("event_id", deleg.event_id.clone())
            .with_owasp(),
        );

        // OWASP-ASI08 (cascading failures): deep / looping delegation can
        // cascade faults through dependent sub-agents.
        findings.push(
            VisibilityFinding::new(
                "drift",
                "cascading_failure",
                deleg.severity,
                agent_instance_id,
                format!("cascading delegation failure surface on {}", agent_type),
                deleg.summary.clone(),
            )
            .with_evidence("agent_type", agent_type)
            .with_evidence("max_depth", max_depth.clone())
            .with_evidence("total_nodes", total_nodes.clone())
            .with_evidence("loop_detected", loop_detected.clone())
            .with_evidence("drift_score", drift_score.clone())
            .with_evidence("event_id", deleg.event_id.clone())
            .with_owasp(),
        );

        // OWASP-LLM10 (unbounded consumption): deep / looping delegation drives
        // unbounded resource and token consumption.
        findings.push(
            VisibilityFinding::new(
                "drift",
                "unbounded_consumption",
                deleg.severity,
                agent_instance_id,
                format!("unbounded delegation consumption surface on {}", agent_type),
                deleg.summary.clone(),
            )
            .with_evidence("agent_type", agent_type)
            .with_evidence("max_depth", max_depth)
            .with_evidence("total_nodes", total_nodes)
            .with_evidence("loop_detected", loop_detected)
            .with_evidence("drift_score", drift_score)
            .with_evidence("event_id", deleg.event_id.clone())
            .with_owasp(),
        );
    }

    findings
}

fn title_for(category: DriftCategory) -> String {
    match category {
        DriftCategory::Goal => "Goal drift",
        DriftCategory::Tool => "Tool drift",
        DriftCategory::SystemImpact => "System-impact drift",
        DriftCategory::Delegation => "Delegation drift",
        DriftCategory::Stability => "Model stability",
    }
    .to_string()
}

fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max).collect();
    format!("{}...", truncated)
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn ev(sev: &str, category: &str, key: &str) -> RawDriftEvidence {
        RawDriftEvidence {
            finding_key: key.to_string(),
            category: category.to_string(),
            severity: sev.to_string(),
            description: "observed egress to unexpected host".to_string(),
            process_path: Some("/usr/bin/curl".to_string()),
            dismissed: false,
        }
    }

    fn verdict(
        ts_offset_secs: i64,
        kind: &str,
        evidence: Vec<RawDriftEvidence>,
    ) -> RawDriftVerdict {
        RawDriftVerdict {
            ts: Utc::now() - Duration::seconds(600 - ts_offset_secs),
            verdict_kind: kind.to_string(),
            unexplained_observations: evidence.iter().filter(|e| !e.dismissed).count(),
            evidence,
        }
    }

    #[test]
    fn clean_history_yields_no_events() {
        let verdicts = vec![
            verdict(0, "CLEAN", vec![]),
            verdict(60, "CLEAN_HEARTBEAT", vec![]),
        ];
        let t = build_drift_timeline("cursor", "inst-1", &verdicts, None);
        assert!(t.events.is_empty());
        assert_eq!(t.peak_drift_score, 0.0);
        assert_eq!(t.alertable_event_count, 0);
        assert!(t.findings.is_empty());
    }

    #[test]
    fn divergence_onset_is_high_and_alertable() {
        let verdicts = vec![
            verdict(0, "CLEAN", vec![]),
            verdict(60, "DIVERGENCE", vec![ev("HIGH", "network", "fk-1")]),
        ];
        let t = build_drift_timeline("cursor", "inst-1", &verdicts, None);
        assert_eq!(t.events.len(), 1);
        let e = &t.events[0];
        assert_eq!(e.category, DriftCategory::SystemImpact);
        assert!(e.severity.is_alertable(), "score {}", e.drift_score);
        // 0.5 base + 0.30 HIGH + 0.05 breadth + 0.1 onset = 0.95
        assert!(e.drift_score >= 0.8);
        assert!(e.refs.iter().any(|r| r == "onset=true"));
        assert_eq!(t.alertable_event_count, 1);
        assert!(t
            .findings
            .iter()
            .any(|f| f.rule_id == "drift_goal_divergence"));
    }

    #[test]
    fn dismissed_evidence_does_not_drive_score() {
        let mut dismissed = ev("CRITICAL", "network", "fk-x");
        dismissed.dismissed = true;
        let verdicts = vec![verdict(0, "DIVERGENCE", vec![dismissed])];
        let t = build_drift_timeline("cursor", "inst-1", &verdicts, None);
        // base 0.5, no active evidence, no onset (first) -> 0.5 medium
        assert_eq!(t.events.len(), 1);
        assert!(!t.events[0].severity.is_alertable());
    }

    #[test]
    fn stale_then_recovery_tracks_stability() {
        let verdicts = vec![
            verdict(0, "DIVERGENCE", vec![ev("MEDIUM", "file", "fk-2")]),
            verdict(120, "CLEAN", vec![]),
        ];
        let t = build_drift_timeline("cursor", "inst-1", &verdicts, None);
        // divergence event + a clean-recovery stability event
        assert_eq!(t.events.len(), 2);
        assert_eq!(t.events[1].category, DriftCategory::Stability);
    }

    #[test]
    fn delegation_loop_emits_alertable_event() {
        let deleg = RawDelegationDrift {
            generated_at: Utc::now(),
            max_depth: 5,
            total_nodes: 12,
            loop_detected: true,
        };
        let t = build_drift_timeline("openclaw", "inst-9", &[], Some(&deleg));
        assert_eq!(t.events.len(), 1);
        assert_eq!(t.events[0].category, DriftCategory::Delegation);
        assert!(t.events[0].severity.is_alertable());
        let escalation = t
            .findings
            .iter()
            .find(|f| f.rule_id == "drift_recursion_escalation")
            .expect("escalation finding present");

        // ASI08 + LLM10 siblings are derived from the same alertable event.
        let cascading = t
            .findings
            .iter()
            .find(|f| f.rule_id == "cascading_failure")
            .expect("cascading_failure (ASI08) finding present");
        let unbounded = t
            .findings
            .iter()
            .find(|f| f.rule_id == "unbounded_consumption")
            .expect("unbounded_consumption (LLM10) finding present");

        // Siblings inherit the escalation severity (no new threshold).
        assert_eq!(cascading.severity, escalation.severity);
        assert_eq!(unbounded.severity, escalation.severity);
        assert_eq!(cascading.domain, "drift");
        assert_eq!(unbounded.domain, "drift");

        // Siblings carry the delegation signals as metadata-only evidence.
        for f in [cascading, unbounded] {
            assert_eq!(f.evidence.get("max_depth").map(String::as_str), Some("5"));
            assert_eq!(
                f.evidence.get("total_nodes").map(String::as_str),
                Some("12")
            );
            assert_eq!(
                f.evidence.get("loop_detected").map(String::as_str),
                Some("true")
            );
            assert!(f.evidence.contains_key("drift_score"));
            assert_eq!(
                f.evidence.get("event_id").map(String::as_str),
                Some(t.events[0].event_id.as_str())
            );
        }
    }

    #[test]
    fn delegation_below_alert_threshold_emits_no_owasp_siblings() {
        // max_depth at threshold with no loop -> score 0.4 (Medium), which is
        // not alertable, so no escalation finding and no ASI08/LLM10 siblings.
        let deleg = RawDelegationDrift {
            generated_at: Utc::now(),
            max_depth: DELEGATION_DEPTH_THRESHOLD,
            total_nodes: 3,
            loop_detected: false,
        };
        let t = build_drift_timeline("openclaw", "inst-10", &[], Some(&deleg));
        // The structural event is still recorded on the timeline...
        assert_eq!(t.events.len(), 1);
        assert_eq!(t.events[0].category, DriftCategory::Delegation);
        assert!(!t.events[0].severity.is_alertable());
        // ...but no alertable findings are derived from it.
        assert!(!t
            .findings
            .iter()
            .any(|f| f.rule_id == "drift_recursion_escalation"));
        assert!(!t.findings.iter().any(|f| f.rule_id == "cascading_failure"));
        assert!(!t
            .findings
            .iter()
            .any(|f| f.rule_id == "unbounded_consumption"));
    }

    #[test]
    fn explain_reconstructs_transition() {
        let verdicts = vec![
            verdict(0, "CLEAN", vec![]),
            verdict(60, "DIVERGENCE", vec![ev("HIGH", "network", "fk-1")]),
        ];
        let t = build_drift_timeline("cursor", "inst-1", &verdicts, None);
        let id = t.events[0].event_id.clone();
        let exp = t.explain(&id).unwrap();
        assert_eq!(exp.transition, "(first) -> DIVERGENCE");
        assert!(exp.rationale.contains("drift_score"));
        assert!(t.explain("nope").is_none());
    }
}
