//! Per-agent pre-execution enforcement capability model (A3 -- tool-call
//! firewall reach).
//!
//! The tool-call firewall (`agent_firewall`) is the policy brain: it scores a
//! proposed tool call and picks a verdict (`allow`/`recommend`/`confirm`/
//! `block`). Whether that verdict can actually *gate* an agent's own tool call
//! before it executes depends entirely on the host agent's pre-execution hook
//! surface -- which differs sharply per agent. This module is the single,
//! code-owned source of truth for that per-agent reality so the app, the CLI,
//! and the posture daemon all describe "what EDAMAME can and cannot enforce for
//! this agent" identically, and never over-promise live blocking where only
//! post-hoc observation is possible.
//!
//! This is deliberately honest about the current state: `plugin_hook_wired` is
//! `false` for every agent in this increment. The capability `tier` is the
//! *ceiling* achievable once the pre-execution hook is wired into the agent's
//! plugin -- it is NOT a claim that live gating is active today. Consumers MUST
//! surface `plugin_hook_wired` and `validation` alongside the tier so the UX
//! reads "achievable: block; not wired yet" rather than implying enforcement
//! that does not exist.
//!
//! Invariants:
//! - **I2 Core as single source of truth**: the capability catalog lives here;
//!   consumers read it through the core RPC, they do not re-derive it.
//! - **I3 Deterministic-first**: the catalog is a fixed function of the agent
//!   type -- no LLM, no runtime probing. It encodes the documented hook surface.
//! - **Truth-in-UX** (mirrors `agent_response`'s `wired` flag): a tier that
//!   cannot be honestly delivered today MUST carry `plugin_hook_wired = false`
//!   and a `validation` other than `Validated`.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Enforcement tier (achievable ceiling)
// ---------------------------------------------------------------------------

/// How much of an agent's own tool-call blast radius the firewall can
/// synchronously gate once its pre-execution hook is wired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementTier {
    /// Synchronous deny/approve across the agent's whole tool surface (shell,
    /// file, network, browser, MCP tools).
    TrueBlock,
    /// Synchronous deny/approve for a subset of the tool surface (e.g. shell
    /// only); the remaining tool classes stay observe-only.
    PartialBlock,
    /// Interception only for calls routed through an EDAMAME-controlled MCP
    /// server/gateway; the agent's native tool actions are not covered.
    ProxyOnly,
    /// Post-hoc visibility + alerts only; no live interception is possible.
    ObserveOnly,
}

impl EnforcementTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnforcementTier::TrueBlock => "true_block",
            EnforcementTier::PartialBlock => "partial_block",
            EnforcementTier::ProxyOnly => "proxy_only",
            EnforcementTier::ObserveOnly => "observe_only",
        }
    }

    /// True when the tier can synchronously stop/hold at least some tool calls
    /// (everything above observe-only).
    pub fn gates(&self) -> bool {
        !matches!(self, EnforcementTier::ObserveOnly)
    }
}

// ---------------------------------------------------------------------------
// Validation confidence (how sure we are the tier is deliverable)
// ---------------------------------------------------------------------------

/// Confidence that the agent's pre-execution hook can actually deliver the
/// stated tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementValidation {
    /// Hook is documented AND verified to reliably deny/hold at the stated tier.
    Validated,
    /// Hook exists upstream but has NOT been verified against the currently
    /// shipped agent build (deny reliability / tool coverage unconfirmed).
    NeedsExternalValidation,
    /// An upstream platform bug prevents the hook from firing reliably today;
    /// live gating waits on a vendor fix.
    PlatformBug,
}

impl EnforcementValidation {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnforcementValidation::Validated => "validated",
            EnforcementValidation::NeedsExternalValidation => "needs_external_validation",
            EnforcementValidation::PlatformBug => "platform_bug",
        }
    }
}

// ---------------------------------------------------------------------------
// Tool classes (the firewall's coarse tool taxonomy)
// ---------------------------------------------------------------------------

/// Coarse tool classes the firewall reasons about when describing coverage.
/// Slugs are stable identifiers the UX maps to labels/icons.
pub const TOOL_CLASS_SHELL: &str = "shell";
pub const TOOL_CLASS_FILE_READ: &str = "file_read";
pub const TOOL_CLASS_FILE_WRITE: &str = "file_write";
pub const TOOL_CLASS_NETWORK: &str = "network";
pub const TOOL_CLASS_BROWSER: &str = "browser";
pub const TOOL_CLASS_MCP_TOOL: &str = "mcp_tool";
pub const TOOL_CLASS_SECRET_ACCESS: &str = "secret_access";

/// The full tool surface -- what a `TrueBlock` agent can gate end to end.
fn full_surface() -> Vec<String> {
    vec![
        TOOL_CLASS_SHELL.to_string(),
        TOOL_CLASS_FILE_READ.to_string(),
        TOOL_CLASS_FILE_WRITE.to_string(),
        TOOL_CLASS_NETWORK.to_string(),
        TOOL_CLASS_BROWSER.to_string(),
        TOOL_CLASS_MCP_TOOL.to_string(),
        TOOL_CLASS_SECRET_ACCESS.to_string(),
    ]
}

fn classes(slugs: &[&str]) -> Vec<String> {
    slugs.iter().map(|s| s.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Per-agent capability descriptor
// ---------------------------------------------------------------------------

/// One agent's pre-execution enforcement capability (read-only catalog entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnforcementCapability {
    pub agent_type: String,
    pub display_name: String,
    /// The enforcement ceiling achievable once the pre-execution hook is wired.
    pub tier: String,
    /// The native pre-execution hook mechanism this agent exposes ("" if none).
    pub hook_mechanism: String,
    /// Tool classes the firewall can synchronously gate at this tier.
    pub blockable_tool_classes: Vec<String>,
    /// Tool classes that remain observe-only (cannot be gated pre-execution).
    pub observe_only_tool_classes: Vec<String>,
    /// True when human-in-the-loop confirmation (approve/deny) is reachable.
    pub confirm_supported: bool,
    /// True when outright block (deny before execution) is reachable.
    pub block_supported: bool,
    /// Whether OUR plugin currently wires the pre-execution hook to the core
    /// firewall. `false` for every agent in this increment: the hook wiring
    /// lands per-agent behind this capability gate.
    pub plugin_hook_wired: bool,
    /// Confidence the stated tier is actually deliverable.
    pub validation: String,
    /// Plain-language "what EDAMAME can do" for this agent (UX copy hint).
    pub can_do: String,
    /// Plain-language "what EDAMAME cannot do (yet)" for this agent.
    pub cannot_do: String,
}

#[allow(clippy::too_many_arguments)]
fn cap(
    agent_type: &str,
    display_name: &str,
    tier: EnforcementTier,
    hook_mechanism: &str,
    blockable: Vec<String>,
    observe_only: Vec<String>,
    validation: EnforcementValidation,
    plugin_hook_wired: bool,
    can_do: &str,
    cannot_do: &str,
) -> AgentEnforcementCapability {
    AgentEnforcementCapability {
        agent_type: agent_type.to_string(),
        display_name: display_name.to_string(),
        tier: tier.as_str().to_string(),
        hook_mechanism: hook_mechanism.to_string(),
        blockable_tool_classes: blockable,
        observe_only_tool_classes: observe_only,
        // confirm/block are reachable whenever the tier gates at all.
        confirm_supported: tier.gates(),
        block_supported: tier.gates(),
        // Per-agent: `true` only where OUR plugin actually wires the
        // pre-execution hook to the core firewall (`evaluate_pre_execution_tool_call`).
        plugin_hook_wired,
        validation: validation.as_str().to_string(),
        can_do: can_do.to_string(),
        cannot_do: cannot_do.to_string(),
    }
}

/// The full, code-owned per-agent enforcement capability catalog. Ordered
/// most-actionable first (validated + highest tier), so the UX can render the
/// list top-down without re-sorting.
pub fn agent_enforcement_catalog() -> Vec<AgentEnforcementCapability> {
    vec![
        // Claude Code -- PreToolUse hooks reliably deny/hold across the whole
        // tool surface. The clearest first target for a real TrueBlock wire-up.
        cap(
            "claude_code",
            "Claude Code",
            EnforcementTier::TrueBlock,
            "PreToolUse hook",
            full_surface(),
            vec![],
            EnforcementValidation::Validated,
            // Wired: the Claude Code plugin ships a PreToolUse hook that calls
            // the core firewall's `evaluate_pre_execution_tool_call` and
            // enforces the returned allow/hold/block decision.
            true,
            "Review, require approval for, or block any tool call -- shell, file, \
             web, and MCP tools -- synchronously before it runs.",
            "Live gating requires the EDAMAME Claude Code plugin installed and \
             the firewall in confirm or block mode; in recommend mode calls are \
             scored and explained but never held.",
        ),
        // Codex -- PreToolUse is reliable for Bash only; other tools would need
        // an MCP proxy to gate pre-execution.
        cap(
            "codex",
            "Codex",
            EnforcementTier::PartialBlock,
            "PreToolUse hook (Bash)",
            classes(&[TOOL_CLASS_SHELL]),
            classes(&[
                TOOL_CLASS_FILE_READ,
                TOOL_CLASS_FILE_WRITE,
                TOOL_CLASS_NETWORK,
                TOOL_CLASS_BROWSER,
                TOOL_CLASS_MCP_TOOL,
                TOOL_CLASS_SECRET_ACCESS,
            ]),
            EnforcementValidation::Validated,
            false,
            "Review, approve, or block Bash commands synchronously before they run.",
            "File, web, and other MCP tools cannot be gated before execution \
             without an MCP proxy; they stay observe-only.",
        ),
        // Cursor -- shell + MCP hooks likely gate; file-op deny reliability is
        // inconsistent across builds and must be validated externally.
        cap(
            "cursor",
            "Cursor",
            EnforcementTier::PartialBlock,
            "beforeShellExecution / beforeMCPExecution hooks",
            classes(&[TOOL_CLASS_SHELL, TOOL_CLASS_MCP_TOOL]),
            classes(&[
                TOOL_CLASS_FILE_READ,
                TOOL_CLASS_FILE_WRITE,
                TOOL_CLASS_NETWORK,
                TOOL_CLASS_BROWSER,
                TOOL_CLASS_SECRET_ACCESS,
            ]),
            EnforcementValidation::NeedsExternalValidation,
            false,
            "Shell commands and MCP tool calls can likely be reviewed or blocked \
             before they run.",
            "File-operation deny reliability is inconsistent across Cursor builds \
             and must be validated; those tools stay observe-only for now.",
        ),
        // OpenClaw -- documented before_tool_call + requireApproval; broad reach
        // but unverified against the installed build; CLI paths may bypass.
        cap(
            "openclaw",
            "OpenClaw",
            EnforcementTier::TrueBlock,
            "before_tool_call plugin hook (requireApproval)",
            classes(&[
                TOOL_CLASS_SHELL,
                TOOL_CLASS_FILE_READ,
                TOOL_CLASS_FILE_WRITE,
                TOOL_CLASS_NETWORK,
                TOOL_CLASS_BROWSER,
                TOOL_CLASS_MCP_TOOL,
            ]),
            vec![],
            EnforcementValidation::NeedsExternalValidation,
            false,
            "A documented plugin hook can require approval for or block exec, file, \
             browser, and MCP tool calls before they run.",
            "Not wired yet, and CLI-driven paths (e.g. `openclaw message send`) may \
             bypass the hook -- coverage must be validated against the installed build.",
        ),
        // Hermes -- Python plugin pre_tool_call can block/hold; our current
        // plugin is Node-based, so a Python pre-exec plugin must be added.
        cap(
            "hermes",
            "Hermes",
            EnforcementTier::TrueBlock,
            "pre_tool_call (Python plugin API)",
            classes(&[
                TOOL_CLASS_SHELL,
                TOOL_CLASS_FILE_READ,
                TOOL_CLASS_FILE_WRITE,
                TOOL_CLASS_NETWORK,
                TOOL_CLASS_BROWSER,
                TOOL_CLASS_MCP_TOOL,
            ]),
            vec![],
            EnforcementValidation::NeedsExternalValidation,
            false,
            "A Python plugin hook can block or hold tool calls for approval before \
             execution.",
            "Our current Hermes plugin is Node-based; a Python pre-execution plugin \
             must be added and validated. Not wired yet.",
        ),
        // Claude Desktop -- Cowork pre-exec hooks are unreliable upstream today.
        cap(
            "claude_desktop",
            "Claude Desktop",
            EnforcementTier::ObserveOnly,
            "PreToolUse (Cowork -- unreliable)",
            vec![],
            full_surface(),
            EnforcementValidation::PlatformBug,
            false,
            "Post-hoc visibility and alerts on the agent's behaviour.",
            "Cowork pre-execution hooks are unreliable upstream today, so EDAMAME \
             cannot block or hold tool calls before they run. Live enforcement \
             waits on a platform fix.",
        ),
    ]
}

/// Look up a single agent's enforcement capability by type, or `None` for an
/// agent type not in the catalog (caller may synthesize an `ObserveOnly`
/// default for unknown agents).
pub fn enforcement_capability_for(agent_type: &str) -> Option<AgentEnforcementCapability> {
    let want = agent_type.trim().to_ascii_lowercase();
    agent_enforcement_catalog()
        .into_iter()
        .find(|c| c.agent_type == want)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_covers_all_six_agents() {
        let cat = agent_enforcement_catalog();
        assert_eq!(cat.len(), 6);
        for t in [
            "claude_code",
            "codex",
            "cursor",
            "openclaw",
            "hermes",
            "claude_desktop",
        ] {
            assert!(
                cat.iter().any(|c| c.agent_type == t),
                "missing capability for {t}"
            );
        }
    }

    #[test]
    fn only_claude_code_hook_is_wired() {
        // Truth-in-UX: claude_code ships the PreToolUse hook that calls the core
        // firewall; every other agent stays unwired until its plugin lands one.
        for c in agent_enforcement_catalog() {
            let expected = c.agent_type == "claude_code";
            assert_eq!(
                c.plugin_hook_wired, expected,
                "plugin_hook_wired mismatch for {}",
                c.agent_type
            );
        }
    }

    #[test]
    fn claude_code_is_true_block_validated() {
        let c = enforcement_capability_for("claude_code").unwrap();
        assert_eq!(c.tier, EnforcementTier::TrueBlock.as_str());
        assert_eq!(c.validation, EnforcementValidation::Validated.as_str());
        assert!(c.block_supported && c.confirm_supported);
        assert!(c.observe_only_tool_classes.is_empty());
        assert!(c
            .blockable_tool_classes
            .contains(&TOOL_CLASS_SECRET_ACCESS.to_string()));
    }

    #[test]
    fn claude_desktop_is_observe_only_platform_bug() {
        let c = enforcement_capability_for("claude_desktop").unwrap();
        assert_eq!(c.tier, EnforcementTier::ObserveOnly.as_str());
        assert_eq!(c.validation, EnforcementValidation::PlatformBug.as_str());
        assert!(!c.block_supported && !c.confirm_supported);
        assert!(c.blockable_tool_classes.is_empty());
    }

    #[test]
    fn codex_partial_block_gates_shell_only() {
        let c = enforcement_capability_for("codex").unwrap();
        assert_eq!(c.tier, EnforcementTier::PartialBlock.as_str());
        assert_eq!(c.blockable_tool_classes, vec![TOOL_CLASS_SHELL.to_string()]);
        assert!(c
            .observe_only_tool_classes
            .contains(&TOOL_CLASS_MCP_TOOL.to_string()));
    }

    #[test]
    fn tier_gating_semantics() {
        assert!(EnforcementTier::TrueBlock.gates());
        assert!(EnforcementTier::PartialBlock.gates());
        assert!(EnforcementTier::ProxyOnly.gates());
        assert!(!EnforcementTier::ObserveOnly.gates());
    }

    #[test]
    fn unknown_agent_has_no_entry() {
        assert!(enforcement_capability_for("nonexistent_agent").is_none());
    }

    #[test]
    fn catalog_serializes_to_json_array() {
        let json = serde_json::to_string(&agent_enforcement_catalog()).unwrap();
        assert!(json.starts_with('['));
        assert!(json.contains("\"tier\":\"true_block\""));
        assert!(json.contains("\"validation\":\"platform_bug\""));
    }
}
