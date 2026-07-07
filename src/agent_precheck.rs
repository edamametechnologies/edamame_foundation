//! Synchronous pre-execution tool-call check (A3, Stage C live gating).
//!
//! The tool-call firewall (`agent_firewall`) scores telemetry-derived data-flow
//! edges *after* the fact. This module is its **synchronous** counterpart: an
//! agent's pre-execution hook (Claude Code `PreToolUse`, Codex/Cursor/OpenClaw
//! equivalents) submits a proposed tool call BEFORE it runs and receives an
//! `allow` / `hold` / `block` decision.
//!
//! The decision reuses the SAME deterministic verdict engine
//! (`agent_firewall::build_tool_call_risk` + the I6 mode ladder) -- there is no
//! second scoring model. This module adds only:
//!   1. `PreExecutionRequest`  -- the metadata-only intake shape the hook sends.
//!   2. `PreExecutionDecision` -- the allow/hold/block projection of a verdict.
//!   3. `PendingToolCall`      -- a held call awaiting an operator decision.
//!
//! Observer-independence (I1) is enforced at the core/MCP layer, NOT here:
//! submitting a call for evaluation is a legitimate reasoning-plane intake
//! (MCP-safe -- the agent may ask "is this allowed?"), while *resolving* a held
//! call is operator-only RPC (the agent may never approve its own held call).
//! This module is pure logic; the read/mutate split lives in `edamame_core`.
//!
//! Invariants:
//! - **I3 Deterministic-first**: verdict is a fixed function of the inputs.
//! - **I5 Privacy tiers**: the intake carries only metadata (agent type, tool
//!   name, coarse tool class, taint class, sink zone) -- never raw arguments,
//!   command strings, file contents, or URLs.
//! - **I6 Staged enforcement**: `recommend` mode never yields `hold`/`block`.

use crate::agent_enforcement::{
    TOOL_CLASS_BROWSER, TOOL_CLASS_FILE_READ, TOOL_CLASS_FILE_WRITE, TOOL_CLASS_MCP_TOOL,
    TOOL_CLASS_NETWORK, TOOL_CLASS_SECRET_ACCESS, TOOL_CLASS_SHELL,
};
use crate::agent_firewall::{ToolCallRiskInput, ToolCallRiskScore, ToolCallVerdict};
use crate::agent_visibility::short_hash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// TTL after which an unresolved held tool call is auto-expired. The agent
/// hook fails **closed** (treats an expired hold as a deny) so a call left
/// unattended by the operator never silently proceeds.
pub const PRE_EXECUTION_HOLD_TTL_SECS: i64 = 300;

// ---------------------------------------------------------------------------
// Intake: what the agent's pre-execution hook sends
// ---------------------------------------------------------------------------

/// Metadata-only description of a proposed tool call, submitted by the agent's
/// pre-execution hook before the call runs (I5: no raw arguments).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreExecutionRequest {
    pub agent_type: String,
    /// The concrete tool name (e.g. `Bash`, `Read`, `WebFetch`, `mcp__x__y`).
    pub tool_name: String,
    /// One of the `agent_enforcement::TOOL_CLASS_*` slugs.
    pub tool_class: String,
    /// Data-flow taint the hook can attribute (`secret` / `sensitive_file` /
    /// `database` / `untrusted_web`), or `None`/empty when the hook cannot tell.
    #[serde(default)]
    pub data_flow_taint: Option<String>,
    /// Sink trust zone the call egresses to, if the hook can classify it
    /// (`trust1` / `trust2_lan` / `trust2_remote` / `trust2_public` /
    /// `unknown`). Defaults to `unknown`.
    #[serde(default)]
    pub sink_trust_zone: Option<String>,
    /// True when the triggering input is known to originate from an untrusted
    /// (trust2) source (e.g. web-fetched content driving the call).
    #[serde(default)]
    pub origin_untrusted: bool,
}

/// Map a coarse tool class to the `ToolPrivilegeClass` slugs the firewall
/// scorer reads. Unknown classes fall through to their raw slug (the scorer's
/// default 5.0 base), so a new tool class is scored conservatively rather than
/// panicking or silently scoring zero.
pub fn privilege_slugs_for_tool_class(tool_class: &str) -> Vec<String> {
    match tool_class.trim().to_ascii_lowercase().as_str() {
        TOOL_CLASS_SHELL => vec!["shell".to_string()],
        TOOL_CLASS_FILE_READ => vec!["filesystem_read".to_string()],
        TOOL_CLASS_FILE_WRITE => vec!["filesystem_write".to_string()],
        TOOL_CLASS_NETWORK => vec!["network".to_string()],
        TOOL_CLASS_BROWSER => vec!["browser".to_string()],
        TOOL_CLASS_SECRET_ACCESS => vec!["secret_access".to_string()],
        // MCP tools egress by nature; score them as a network call at minimum.
        TOOL_CLASS_MCP_TOOL => vec!["network".to_string()],
        other if !other.is_empty() => vec![other.to_string()],
        _ => vec!["none".to_string()],
    }
}

/// Build the firewall scorer input from a pre-execution intake + host
/// corroboration. Empty/whitespace taint collapses to `None`; empty sink
/// collapses to `unknown` (the safe, non-egress-assuming default).
pub fn risk_input_from_precheck(
    req: &PreExecutionRequest,
    attack_pattern_corroborated: bool,
) -> ToolCallRiskInput {
    let data_flow_taint = req
        .data_flow_taint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());
    let sink_trust_zone = req
        .sink_trust_zone
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "unknown".to_string());
    ToolCallRiskInput {
        agent_type: req.agent_type.clone(),
        tool_name: req.tool_name.clone(),
        tool_privilege_slugs: privilege_slugs_for_tool_class(&req.tool_class),
        origin_trust_zone: if req.origin_untrusted {
            "trust2"
        } else {
            "trust1"
        }
        .to_string(),
        data_flow_taint,
        sink_trust_zone,
        attack_pattern_corroborated,
    }
}

// ---------------------------------------------------------------------------
// Decision: the allow/hold/block projection of a verdict
// ---------------------------------------------------------------------------

/// The live pre-execution decision the hook enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreExecutionDecision {
    /// Proceed -- verdict was `allow` or `recommend` (recommend never gates, I6).
    Allow,
    /// Hold: wait for an operator approve/deny -- verdict was `confirm`.
    Hold,
    /// Deny before execution -- verdict was `block` (block mode + catastrophic).
    Block,
}

impl PreExecutionDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            PreExecutionDecision::Allow => "allow",
            PreExecutionDecision::Hold => "hold",
            PreExecutionDecision::Block => "block",
        }
    }
}

/// Project a firewall verdict onto the live pre-execution decision. `recommend`
/// is non-gating (I6) so it maps to `allow`; only `confirm` holds and only
/// `block` denies.
pub fn decision_for_verdict(verdict: ToolCallVerdict) -> PreExecutionDecision {
    match verdict {
        ToolCallVerdict::Allow | ToolCallVerdict::Recommend => PreExecutionDecision::Allow,
        ToolCallVerdict::Confirm => PreExecutionDecision::Hold,
        ToolCallVerdict::Block => PreExecutionDecision::Block,
    }
}

// ---------------------------------------------------------------------------
// Pending queue: held calls awaiting an operator decision
// ---------------------------------------------------------------------------

/// Lifecycle status of a held pre-execution tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingStatus {
    /// Awaiting an operator approve/deny.
    Pending,
    /// Operator approved -- the hook may proceed.
    Approved,
    /// Operator denied, OR the call was auto-blocked by a `block` verdict.
    Denied,
    /// TTL elapsed with no operator decision. The hook fails closed (deny).
    Expired,
}

impl PendingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PendingStatus::Pending => "pending",
            PendingStatus::Approved => "approved",
            PendingStatus::Denied => "denied",
            PendingStatus::Expired => "expired",
        }
    }
}

/// A tool call the firewall gated (held for confirmation, or auto-blocked),
/// recorded for the operator's pending-approvals surface and as the audit
/// trail for gated calls. Metadata only (I5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingToolCall {
    pub pending_id: String,
    pub agent_type: String,
    pub tool_name: String,
    pub tool_class: String,
    /// The live decision that created this entry (`hold` or `block`).
    pub decision: String,
    /// The underlying firewall verdict (`confirm` / `block`).
    pub verdict: String,
    pub score: f64,
    pub severity: String,
    pub rationale: String,
    /// [`PendingStatus`] slug.
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    /// Operator resolution note (`approved` / `denied` / `expired` /
    /// `blocked_by_policy` / "").
    pub resolution: String,
}

impl PendingToolCall {
    /// True while the entry is still awaiting an operator decision.
    pub fn is_pending(&self) -> bool {
        self.status == PendingStatus::Pending.as_str()
    }

    /// True when a `pending` entry has outlived [`PRE_EXECUTION_HOLD_TTL_SECS`].
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.is_pending() && (now - self.created_at).num_seconds() >= PRE_EXECUTION_HOLD_TTL_SECS
    }
}

/// Build a pending/blocked record from a scored call + its decision. A `Hold`
/// starts `Pending`; a `Block` is recorded already resolved as `Denied`
/// (`blocked_by_policy`) so the operator sees what the firewall auto-denied.
/// `Allow` decisions are non-events and MUST NOT be recorded here.
pub fn build_pending_tool_call(
    req: &PreExecutionRequest,
    score: &ToolCallRiskScore,
    decision: PreExecutionDecision,
) -> PendingToolCall {
    let created_at = Utc::now();
    let pending_id = format!(
        "pend-{}",
        short_hash(&format!(
            "{}:{}:{:.2}:{}",
            req.agent_type,
            req.tool_name,
            score.score,
            created_at.timestamp_nanos_opt().unwrap_or_default()
        ))
    );
    let (status, resolved_at, resolution) = match decision {
        PreExecutionDecision::Block => (
            PendingStatus::Denied,
            Some(created_at),
            "blocked_by_policy".to_string(),
        ),
        // Hold (the only other decision that reaches here).
        _ => (PendingStatus::Pending, None, String::new()),
    };
    PendingToolCall {
        pending_id,
        agent_type: req.agent_type.clone(),
        tool_name: req.tool_name.clone(),
        tool_class: req.tool_class.clone(),
        decision: decision.as_str().to_string(),
        verdict: score.verdict.as_str().to_string(),
        score: score.score,
        severity: score.severity.as_str().to_string(),
        rationale: score.rationale.clone(),
        status: status.as_str().to_string(),
        created_at,
        resolved_at,
        resolution,
    }
}

/// The decision the agent hook must enforce for a given pending-entry status.
/// `Pending` returns `Hold` (keep waiting); `Approved` returns `Allow`;
/// everything else (`Denied` / `Expired`) fails closed to `Block`.
pub fn decision_for_status(status: &str) -> PreExecutionDecision {
    if status == PendingStatus::Approved.as_str() {
        PreExecutionDecision::Allow
    } else if status == PendingStatus::Pending.as_str() {
        PreExecutionDecision::Hold
    } else {
        PreExecutionDecision::Block
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_firewall::{build_tool_call_risk, FirewallMode};

    fn req(
        tool_class: &str,
        taint: Option<&str>,
        sink: Option<&str>,
        untrusted: bool,
    ) -> PreExecutionRequest {
        PreExecutionRequest {
            agent_type: "claude_code".to_string(),
            tool_name: "Bash".to_string(),
            tool_class: tool_class.to_string(),
            data_flow_taint: taint.map(|s| s.to_string()),
            sink_trust_zone: sink.map(|s| s.to_string()),
            origin_untrusted: untrusted,
        }
    }

    #[test]
    fn tool_class_maps_to_privilege_slugs() {
        assert_eq!(privilege_slugs_for_tool_class("shell"), vec!["shell"]);
        assert_eq!(
            privilege_slugs_for_tool_class("secret_access"),
            vec!["secret_access"]
        );
        assert_eq!(privilege_slugs_for_tool_class("mcp_tool"), vec!["network"]);
        // Unknown class -> its own slug (conservative 5.0 base), never panics.
        assert_eq!(privilege_slugs_for_tool_class("weird"), vec!["weird"]);
        assert_eq!(privilege_slugs_for_tool_class(""), vec!["none"]);
    }

    #[test]
    fn empty_hints_collapse_to_safe_defaults() {
        let r = req("network", Some("  "), Some(""), false);
        let input = risk_input_from_precheck(&r, false);
        assert_eq!(input.data_flow_taint, None);
        assert_eq!(input.sink_trust_zone, "unknown");
        assert_eq!(input.origin_trust_zone, "trust1");
    }

    #[test]
    fn recommend_mode_never_holds_or_blocks() {
        // Catastrophic secret->remote shape, but recommend caps at recommend.
        let r = req("network", Some("secret"), Some("trust2_remote"), true);
        let input = risk_input_from_precheck(&r, true);
        let score = build_tool_call_risk(&input, FirewallMode::Recommend);
        assert_eq!(
            decision_for_verdict(score.verdict),
            PreExecutionDecision::Allow
        );
    }

    #[test]
    fn confirm_mode_holds_catastrophic() {
        let r = req("network", Some("secret"), Some("trust2_remote"), false);
        let input = risk_input_from_precheck(&r, false);
        let score = build_tool_call_risk(&input, FirewallMode::Confirm);
        assert_eq!(
            decision_for_verdict(score.verdict),
            PreExecutionDecision::Hold
        );
    }

    #[test]
    fn block_mode_blocks_catastrophic() {
        let r = req("network", Some("secret"), Some("trust2_remote"), false);
        let input = risk_input_from_precheck(&r, false);
        let score = build_tool_call_risk(&input, FirewallMode::Block);
        assert_eq!(
            decision_for_verdict(score.verdict),
            PreExecutionDecision::Block
        );
    }

    #[test]
    fn benign_local_read_allows_even_in_block() {
        let r = req("file_read", None, Some("trust1"), false);
        let input = risk_input_from_precheck(&r, false);
        let score = build_tool_call_risk(&input, FirewallMode::Block);
        assert_eq!(
            decision_for_verdict(score.verdict),
            PreExecutionDecision::Allow
        );
    }

    #[test]
    fn hold_entry_starts_pending_block_entry_starts_denied() {
        let r = req("network", Some("secret"), Some("trust2_remote"), false);
        let input = risk_input_from_precheck(&r, false);
        let score = build_tool_call_risk(&input, FirewallMode::Confirm);
        let held = build_pending_tool_call(&r, &score, PreExecutionDecision::Hold);
        assert!(held.is_pending());
        assert_eq!(held.resolution, "");
        assert!(held.resolved_at.is_none());

        let blocked = build_pending_tool_call(&r, &score, PreExecutionDecision::Block);
        assert!(!blocked.is_pending());
        assert_eq!(blocked.status, PendingStatus::Denied.as_str());
        assert_eq!(blocked.resolution, "blocked_by_policy");
        assert!(blocked.resolved_at.is_some());
    }

    #[test]
    fn expiry_is_ttl_bounded_and_pending_only() {
        let r = req("network", Some("secret"), Some("trust2_remote"), false);
        let input = risk_input_from_precheck(&r, false);
        let score = build_tool_call_risk(&input, FirewallMode::Confirm);
        let mut held = build_pending_tool_call(&r, &score, PreExecutionDecision::Hold);
        // Fresh -> not expired.
        assert!(!held.is_expired(Utc::now()));
        // Backdate past the TTL -> expired while pending.
        held.created_at = Utc::now() - chrono::Duration::seconds(PRE_EXECUTION_HOLD_TTL_SECS + 1);
        assert!(held.is_expired(Utc::now()));
        // Once resolved, never "expired" again regardless of age.
        held.status = PendingStatus::Approved.as_str().to_string();
        assert!(!held.is_expired(Utc::now()));
    }

    #[test]
    fn status_to_decision_fails_closed() {
        assert_eq!(decision_for_status("approved"), PreExecutionDecision::Allow);
        assert_eq!(decision_for_status("pending"), PreExecutionDecision::Hold);
        assert_eq!(decision_for_status("denied"), PreExecutionDecision::Block);
        assert_eq!(decision_for_status("expired"), PreExecutionDecision::Block);
        // Unknown status also fails closed.
        assert_eq!(decision_for_status("garbage"), PreExecutionDecision::Block);
    }
}
