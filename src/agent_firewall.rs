//! Tool-call firewall + action receipts (INC-10, Stage C enforcement).
//!
//! A deterministic per-tool-call risk scorer and policy engine. Per invariant
//! I6 (staged enforcement, reversible-first) this ships in **recommend mode**:
//! it scores every evaluated tool call and explains the verdict, but NEVER
//! gates in recommend mode. The verdict ladder is `allow -> recommend ->
//! confirm -> block`; `confirm` and `block` are only reachable when an operator
//! has explicitly graduated the policy past recommend, and `block` is further
//! restricted to a narrow, deterministic catastrophic set.
//!
//! Every evaluation produces a tamper-evident `ActionReceipt` whose
//! `receipt_hash` chains the prior receipt's hash -- the same append-only
//! hash-chain primitive the flight recorder (INC-5) reuses.
//!
//! Invariants:
//! - **I3 Deterministic-first**: the score + verdict are a fixed function of the
//!   inputs (origin trust zone, data-flow taint, tool privilege class, live
//!   attack-pattern corroboration). No LLM is consulted here.
//! - **I6 Staged enforcement**: recommend mode never gates; block is restricted
//!   to the deterministic catastrophic set even in block mode.
//! - **I1 (enforced in core)**: every policy/receipt *mutation* is operator-only
//!   RPC, never an MCP tool. This module is pure logic; the read/mutate split is
//!   enforced at the core/MCP layer.

use crate::agent_visibility::short_hash;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Policy mode (I6 ladder)
// ---------------------------------------------------------------------------

/// Firewall enforcement mode. Defaults to `Recommend` (never gates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    /// Score + explain only. NEVER gates. The I6 default.
    #[default]
    Recommend,
    /// High-risk + catastrophic calls require human-in-the-loop confirmation.
    Confirm,
    /// The deterministic catastrophic set is blocked outright; everything else
    /// degrades to confirm/recommend/allow.
    Block,
}

impl FirewallMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            FirewallMode::Recommend => "recommend",
            FirewallMode::Confirm => "confirm",
            FirewallMode::Block => "block",
        }
    }
    pub fn from_str_lenient(s: &str) -> Option<FirewallMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "recommend" => Some(FirewallMode::Recommend),
            "confirm" => Some(FirewallMode::Confirm),
            "block" => Some(FirewallMode::Block),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Verdict ladder
// ---------------------------------------------------------------------------

/// The firewall's per-call decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCallVerdict {
    /// Below the recommend threshold -- proceed silently.
    Allow,
    /// Surface a recommendation/warning; do NOT gate (recommend mode ceiling).
    Recommend,
    /// Require human-in-the-loop confirmation (confirm/block modes only).
    Confirm,
    /// Block outright (block mode + catastrophic set only).
    Block,
}

impl ToolCallVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            ToolCallVerdict::Allow => "allow",
            ToolCallVerdict::Recommend => "recommend",
            ToolCallVerdict::Confirm => "confirm",
            ToolCallVerdict::Block => "block",
        }
    }
    /// True when the verdict actually stops/pauses the call (confirm or block).
    /// recommend mode verdicts are always non-gating.
    pub fn gates(&self) -> bool {
        matches!(self, ToolCallVerdict::Confirm | ToolCallVerdict::Block)
    }
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// The evidence a single tool-call evaluation reads -- all derivable from the
/// Stage A/B projections (capability graph privilege classes, data-flow taint
/// + sink trust zone, live attack-pattern corroboration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRiskInput {
    pub agent_type: String,
    pub tool_name: String,
    /// `ToolPrivilegeClass` slugs the called tool carries.
    pub tool_privilege_slugs: Vec<String>,
    /// Trust zone the triggering input originated in (`trust0`/`trust1`/`trust2`).
    pub origin_trust_zone: String,
    /// Data-flow taint class moved by the call, if any
    /// (`secret`/`sensitive_file`/`database`/`untrusted_web`).
    pub data_flow_taint: Option<String>,
    /// Sink trust zone the call egresses to
    /// (`trust1`/`trust2_lan`/`trust2_remote`/`trust2_public`/`unknown`).
    pub sink_trust_zone: String,
    /// True when a live attack-pattern CRITICAL finding corroborates this run.
    pub attack_pattern_corroborated: bool,
}

// ---------------------------------------------------------------------------
// Output: risk score + verdict
// ---------------------------------------------------------------------------

/// Severity bucket derived from the numeric risk score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskSeverity::Info => "info",
            RiskSeverity::Low => "low",
            RiskSeverity::Medium => "medium",
            RiskSeverity::High => "high",
            RiskSeverity::Critical => "critical",
        }
    }
}

/// One contributing factor in the risk score (for the decomposed UX, I3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor: String,
    pub points: f64,
    pub detail: String,
}

/// The per-call risk decomposition + verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRiskScore {
    pub agent_type: String,
    pub tool_name: String,
    /// 0-100 (higher == riskier).
    pub score: f64,
    pub severity: RiskSeverity,
    pub verdict: ToolCallVerdict,
    pub mode: FirewallMode,
    /// True when the call is in the deterministic catastrophic set (the only
    /// set `block` mode actually blocks).
    pub catastrophic: bool,
    pub factors: Vec<RiskFactor>,
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// Scoring (deterministic; refinable by CloudModel later)
// ---------------------------------------------------------------------------

fn privilege_points(slug: &str) -> f64 {
    match slug {
        "secret_access" => 40.0,
        "shell" | "filesystem_write" => 35.0,
        "database" => 28.0,
        "network" | "browser" => 25.0,
        "git" => 18.0,
        "filesystem_read" => 15.0,
        _ => 5.0,
    }
}

fn taint_points(taint: &str) -> f64 {
    match taint.trim().to_ascii_lowercase().as_str() {
        "secret" => 30.0,
        "database" => 26.0,
        "sensitive_file" => 20.0,
        "untrusted_web" => 15.0,
        _ => 0.0,
    }
}

fn sink_points(zone: &str) -> f64 {
    match zone.trim().to_ascii_lowercase().as_str() {
        "trust2_remote" | "trust2_public" => 20.0,
        "trust2_lan" => 10.0,
        _ => 0.0,
    }
}

fn origin_untrusted(zone: &str) -> bool {
    matches!(zone.trim().to_ascii_lowercase().as_str(), "trust2")
}

fn is_cross_boundary_sink(zone: &str) -> bool {
    matches!(
        zone.trim().to_ascii_lowercase().as_str(),
        "trust2_lan" | "trust2_remote" | "trust2_public"
    )
}

fn severity_for(score: f64) -> RiskSeverity {
    if score >= 80.0 {
        RiskSeverity::Critical
    } else if score >= 60.0 {
        RiskSeverity::High
    } else if score >= 40.0 {
        RiskSeverity::Medium
    } else if score >= 20.0 {
        RiskSeverity::Low
    } else {
        RiskSeverity::Info
    }
}

/// The deterministic catastrophic set -- the only verdicts `block` mode blocks.
/// Mirrors Appendix B: secret/db source -> cross-boundary sink; or an
/// attack-pattern-corroborated high-score call.
fn is_catastrophic(input: &ToolCallRiskInput, score: f64) -> bool {
    let secret_or_db = matches!(
        input.data_flow_taint.as_deref().map(|s| s.to_ascii_lowercase()),
        Some(ref t) if t == "secret" || t == "database"
    );
    if secret_or_db && is_cross_boundary_sink(&input.sink_trust_zone) {
        return true;
    }
    if input.attack_pattern_corroborated && score >= 80.0 {
        return true;
    }
    false
}

/// Map a score + catastrophic flag to a verdict given the active mode (I6). In
/// recommend mode the verdict ceiling is `Recommend` -- it NEVER gates.
fn verdict_for(mode: FirewallMode, score: f64, catastrophic: bool) -> ToolCallVerdict {
    match mode {
        FirewallMode::Recommend => {
            if score >= 50.0 {
                ToolCallVerdict::Recommend
            } else {
                ToolCallVerdict::Allow
            }
        }
        FirewallMode::Confirm => {
            if catastrophic || score >= 70.0 {
                ToolCallVerdict::Confirm
            } else if score >= 50.0 {
                ToolCallVerdict::Recommend
            } else {
                ToolCallVerdict::Allow
            }
        }
        FirewallMode::Block => {
            if catastrophic {
                ToolCallVerdict::Block
            } else if score >= 70.0 {
                ToolCallVerdict::Confirm
            } else if score >= 50.0 {
                ToolCallVerdict::Recommend
            } else {
                ToolCallVerdict::Allow
            }
        }
    }
}

/// Score one tool call deterministically and pick its verdict for `mode`. Pure.
pub fn build_tool_call_risk(input: &ToolCallRiskInput, mode: FirewallMode) -> ToolCallRiskScore {
    let mut factors: Vec<RiskFactor> = Vec::new();

    // Highest-privilege slug dominates the base.
    let (top_slug, base) = input
        .tool_privilege_slugs
        .iter()
        .map(|s| (s.clone(), privilege_points(s)))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or_else(|| ("none".to_string(), 5.0));
    factors.push(RiskFactor {
        factor: "tool_privilege".to_string(),
        points: base,
        detail: format!("highest tool privilege class: {}", top_slug),
    });
    let mut score = base;

    if let Some(taint) = input.data_flow_taint.as_deref() {
        let p = taint_points(taint);
        if p > 0.0 {
            factors.push(RiskFactor {
                factor: "data_flow_taint".to_string(),
                points: p,
                detail: format!("moves {} data", taint),
            });
            score += p;
        }
    }

    let sp = sink_points(&input.sink_trust_zone);
    if sp > 0.0 {
        factors.push(RiskFactor {
            factor: "sink_trust_zone".to_string(),
            points: sp,
            detail: format!("egress sink in {}", input.sink_trust_zone),
        });
        score += sp;
    }

    if origin_untrusted(&input.origin_trust_zone) {
        factors.push(RiskFactor {
            factor: "origin_untrusted".to_string(),
            points: 10.0,
            detail: "triggering input originated in an untrusted (trust2) zone".to_string(),
        });
        score += 10.0;
    }

    if input.attack_pattern_corroborated {
        factors.push(RiskFactor {
            factor: "attack_pattern_corroboration".to_string(),
            points: 20.0,
            detail: "a live attack-pattern CRITICAL finding corroborates this run".to_string(),
        });
        score += 20.0;
    }

    let score = score.clamp(0.0, 100.0);
    let severity = severity_for(score);
    let catastrophic = is_catastrophic(input, score);
    let verdict = verdict_for(mode, score, catastrophic);

    let rationale = if catastrophic {
        format!(
            "Catastrophic shape ({}): {} -> {} verdict in {} mode (score {:.0}/100).",
            top_slug,
            input
                .data_flow_taint
                .as_deref()
                .map(|t| format!("{} flow", t))
                .unwrap_or_else(|| "high-privilege call".to_string()),
            verdict.as_str(),
            mode.as_str(),
            score
        )
    } else {
        format!(
            "{} risk {:.0}/100 -> {} in {} mode; top driver: {}.",
            severity.as_str(),
            score,
            verdict.as_str(),
            mode.as_str(),
            top_slug
        )
    };

    ToolCallRiskScore {
        agent_type: input.agent_type.clone(),
        tool_name: input.tool_name.clone(),
        score: round2(score),
        severity,
        verdict,
        mode,
        catastrophic,
        factors,
        rationale,
    }
}

// ---------------------------------------------------------------------------
// Action receipt (tamper-evident hash chain)
// ---------------------------------------------------------------------------

/// A tamper-evident receipt for one adjudicated tool call. `receipt_hash`
/// chains `prior_hash` so any reorder/edit of the append-only log is detectable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub receipt_id: String,
    pub agent_type: String,
    pub tool_name: String,
    pub verdict: String,
    pub score: f64,
    pub severity: String,
    pub mode: String,
    pub catastrophic: bool,
    /// Hash of the prior receipt in the chain ("" for the genesis receipt).
    pub prior_hash: String,
    /// Hash over (prior_hash, receipt_id, verdict, score, tool, ts).
    pub receipt_hash: String,
    /// True once an operator has resolved a `confirm` verdict.
    pub resolved: bool,
    /// Operator decision once resolved (`approved`/`denied`/"").
    pub resolution: String,
    pub rationale: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Build the next receipt in an append-only chain from a scored call.
pub fn build_action_receipt(score: &ToolCallRiskScore, prior_hash: &str) -> ActionReceipt {
    let created_at = chrono::Utc::now();
    let receipt_id = format!(
        "rcpt-{}",
        short_hash(&format!(
            "{}:{}:{}:{}",
            score.agent_type,
            score.tool_name,
            score.score,
            created_at.timestamp_nanos_opt().unwrap_or_default()
        ))
    );
    let receipt_hash = short_hash(&format!(
        "{}|{}|{}|{:.2}|{}|{}",
        prior_hash,
        receipt_id,
        score.verdict.as_str(),
        score.score,
        score.tool_name,
        created_at.to_rfc3339()
    ));
    ActionReceipt {
        receipt_id,
        agent_type: score.agent_type.clone(),
        tool_name: score.tool_name.clone(),
        verdict: score.verdict.as_str().to_string(),
        score: score.score,
        severity: score.severity.as_str().to_string(),
        mode: score.mode.as_str().to_string(),
        catastrophic: score.catastrophic,
        prior_hash: prior_hash.to_string(),
        receipt_hash,
        resolved: !score.verdict.gates(),
        resolution: String::new(),
        rationale: score.rationale.clone(),
        created_at,
    }
}

/// Verify a receipt chain: each `prior_hash` must equal the previous
/// `receipt_hash`, and the genesis receipt's `prior_hash` must be empty.
/// Returns the index of the first broken link, or `None` when intact.
pub fn first_broken_receipt(chain: &[ActionReceipt]) -> Option<usize> {
    let mut prev = String::new();
    for (i, r) in chain.iter().enumerate() {
        if r.prior_hash != prev {
            return Some(i);
        }
        prev = r.receipt_hash.clone();
    }
    None
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(
        privs: &[&str],
        taint: Option<&str>,
        sink: &str,
        origin: &str,
        ap: bool,
    ) -> ToolCallRiskInput {
        ToolCallRiskInput {
            agent_type: "cursor".to_string(),
            tool_name: "http_post".to_string(),
            tool_privilege_slugs: privs.iter().map(|s| s.to_string()).collect(),
            origin_trust_zone: origin.to_string(),
            data_flow_taint: taint.map(|s| s.to_string()),
            sink_trust_zone: sink.to_string(),
            attack_pattern_corroborated: ap,
        }
    }

    #[test]
    fn recommend_mode_never_gates() {
        // A secret->remote shape is catastrophic, but recommend mode caps at recommend.
        let inp = input(
            &["network", "secret_access"],
            Some("secret"),
            "trust2_remote",
            "trust2",
            true,
        );
        let r = build_tool_call_risk(&inp, FirewallMode::Recommend);
        assert!(r.catastrophic);
        assert_eq!(r.verdict, ToolCallVerdict::Recommend);
        assert!(!r.verdict.gates());
    }

    #[test]
    fn block_mode_blocks_catastrophic_only() {
        let cata = input(
            &["network"],
            Some("secret"),
            "trust2_remote",
            "trust1",
            false,
        );
        let r = build_tool_call_risk(&cata, FirewallMode::Block);
        assert!(r.catastrophic);
        assert_eq!(r.verdict, ToolCallVerdict::Block);

        // High score but not catastrophic -> confirm, not block.
        let high = input(&["shell"], None, "trust1", "trust2", false);
        let r2 = build_tool_call_risk(&high, FirewallMode::Block);
        assert!(!r2.catastrophic);
        assert_ne!(r2.verdict, ToolCallVerdict::Block);
    }

    #[test]
    fn confirm_mode_confirms_catastrophic() {
        let inp = input(
            &["network"],
            Some("database"),
            "trust2_public",
            "trust1",
            false,
        );
        let r = build_tool_call_risk(&inp, FirewallMode::Confirm);
        assert!(r.catastrophic);
        assert_eq!(r.verdict, ToolCallVerdict::Confirm);
    }

    #[test]
    fn benign_local_call_allows() {
        let inp = input(&["filesystem_read"], None, "trust1", "trust1", false);
        let r = build_tool_call_risk(&inp, FirewallMode::Block);
        assert_eq!(r.verdict, ToolCallVerdict::Allow);
        assert!(!r.catastrophic);
    }

    #[test]
    fn receipt_chain_is_tamper_evident() {
        let inp = input(
            &["network"],
            Some("secret"),
            "trust2_remote",
            "trust2",
            true,
        );
        let s = build_tool_call_risk(&inp, FirewallMode::Recommend);
        let r1 = build_action_receipt(&s, "");
        let r2 = build_action_receipt(&s, &r1.receipt_hash);
        let chain = vec![r1.clone(), r2.clone()];
        assert_eq!(first_broken_receipt(&chain), None);

        // Tamper: swap order.
        let broken = vec![r2, r1];
        assert!(first_broken_receipt(&broken).is_some());
    }

    #[test]
    fn gating_verdict_receipt_starts_unresolved() {
        let inp = input(
            &["network"],
            Some("secret"),
            "trust2_remote",
            "trust1",
            false,
        );
        let s = build_tool_call_risk(&inp, FirewallMode::Block);
        assert_eq!(s.verdict, ToolCallVerdict::Block);
        let r = build_action_receipt(&s, "");
        assert!(!r.resolved);
    }
}
