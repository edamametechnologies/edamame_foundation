//! ADR response actions + case export (INC-11, Stage D response).
//!
//! A fixed catalog of **reversible-first** containment actions plus a portable
//! incident `case_export` shape. Per invariant I6, every response action is
//! reversible-first with an explicit undo, irreversible actions are
//! operator-gated, and a **simulate-first** dry run is mandatory before any
//! real execution.
//!
//! This module is pure logic: it defines the catalog, validates requested
//! actions, and shapes the case export. The actual side effects (pausing the
//! transcript observer, severing an egress session, revoking an MCP pairing)
//! are performed by the core layer using existing primitives -- and every
//! `execute`/`undo` is an operator-only RPC, NEVER an MCP tool (I1).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Response action catalog
// ---------------------------------------------------------------------------

/// The fixed set of ADR response actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionKind {
    // --- reversible-first set (each ships with an explicit undo) ---
    /// Pause the transcript observer for an agent (reuses `unsecured_<agent>`).
    PauseAgent,
    /// Revoke a single tool grant from an agent's effective capability set.
    RevokeToolGrant,
    /// Quarantine a memory namespace so retrievals from it are blocked.
    QuarantineMemoryNamespace,
    /// Flip the firewall to confirm-all for an agent (temporary tightening).
    RequireConfirmAllCalls,
    /// Sever a live egress session (reversible: the agent may re-establish).
    KillEgressSession,

    // --- operator-gated irreversible set ---
    /// Disable an agent entirely (no automatic undo; operator re-enables).
    DisableAgent,
    /// Rotate an exposed secret (irreversible: the old secret is invalidated).
    RotateExposedSecret,
}

impl ResponseActionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseActionKind::PauseAgent => "pause_agent",
            ResponseActionKind::RevokeToolGrant => "revoke_tool_grant",
            ResponseActionKind::QuarantineMemoryNamespace => "quarantine_memory_namespace",
            ResponseActionKind::RequireConfirmAllCalls => "require_confirm_all_calls",
            ResponseActionKind::KillEgressSession => "kill_egress_session",
            ResponseActionKind::DisableAgent => "disable_agent",
            ResponseActionKind::RotateExposedSecret => "rotate_exposed_secret",
        }
    }

    pub fn from_str_lenient(s: &str) -> Option<ResponseActionKind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "pause_agent" => Some(ResponseActionKind::PauseAgent),
            "revoke_tool_grant" => Some(ResponseActionKind::RevokeToolGrant),
            "quarantine_memory_namespace" => Some(ResponseActionKind::QuarantineMemoryNamespace),
            "require_confirm_all_calls" => Some(ResponseActionKind::RequireConfirmAllCalls),
            "kill_egress_session" => Some(ResponseActionKind::KillEgressSession),
            "disable_agent" => Some(ResponseActionKind::DisableAgent),
            "rotate_exposed_secret" => Some(ResponseActionKind::RotateExposedSecret),
            _ => None,
        }
    }

    /// True when the action ships with an explicit, automatic undo.
    pub fn reversible(&self) -> bool {
        !matches!(
            self,
            ResponseActionKind::DisableAgent | ResponseActionKind::RotateExposedSecret
        )
    }

    /// True when the action requires explicit operator gating (no auto-trigger).
    pub fn operator_gated(&self) -> bool {
        // Irreversible actions are always operator-gated; reversible ones may be
        // auto-proposed but still execute only via the operator RPC (I1).
        !self.reversible()
    }

    /// True when the action's side-effect primitive is actually wired to a real
    /// containment mechanism in `edamame_core`. When false, a non-simulated
    /// request records an auditable operator-decision intent but performs NO
    /// live side effect -- the primitive is not yet implemented.
    ///
    /// `mcp_enabled` reflects whether `edamame_core` was built with the `mcp`
    /// feature: `RevokeToolGrant` is wired to the MCP pairing store, so it is a
    /// live action only when MCP is compiled in. This MUST stay in lockstep with
    /// the dispatch match in `CoreManager::request_response_action`
    /// (core_manager_visibility_enforce.rs) -- a `wired == true` here whose
    /// dispatch arm is a no-op would reintroduce the truth-in-UX bug this flag
    /// exists to fix.
    pub fn wired(&self, mcp_enabled: bool) -> bool {
        match self {
            ResponseActionKind::PauseAgent | ResponseActionKind::RequireConfirmAllCalls => true,
            ResponseActionKind::RevokeToolGrant => mcp_enabled,
            // Side-effect primitives not yet implemented (intent recorded only).
            ResponseActionKind::QuarantineMemoryNamespace
            | ResponseActionKind::KillEgressSession
            | ResponseActionKind::DisableAgent
            | ResponseActionKind::RotateExposedSecret => false,
        }
    }

    /// Human-readable description for the catalog UI.
    pub fn description(&self) -> &'static str {
        match self {
            ResponseActionKind::PauseAgent => {
                "Pause the transcript observer for this agent (reversible)"
            }
            ResponseActionKind::RevokeToolGrant => {
                "Revoke a single tool grant from the agent (reversible)"
            }
            ResponseActionKind::QuarantineMemoryNamespace => {
                "Block retrievals from a memory namespace (reversible)"
            }
            ResponseActionKind::RequireConfirmAllCalls => {
                "Temporarily require confirmation for every tool call (reversible)"
            }
            ResponseActionKind::KillEgressSession => {
                "Sever a live egress session (reversible -- agent may reconnect)"
            }
            ResponseActionKind::DisableAgent => {
                "Disable the agent entirely (IRREVERSIBLE -- operator re-enables)"
            }
            ResponseActionKind::RotateExposedSecret => {
                "Rotate an exposed secret (IRREVERSIBLE -- old secret invalidated)"
            }
        }
    }

    pub fn all() -> Vec<ResponseActionKind> {
        vec![
            ResponseActionKind::PauseAgent,
            ResponseActionKind::RevokeToolGrant,
            ResponseActionKind::QuarantineMemoryNamespace,
            ResponseActionKind::RequireConfirmAllCalls,
            ResponseActionKind::KillEgressSession,
            ResponseActionKind::DisableAgent,
            ResponseActionKind::RotateExposedSecret,
        ]
    }
}

/// A catalog descriptor for one response action (the read-only `list` surface).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionDescriptor {
    pub kind: String,
    pub description: String,
    pub reversible: bool,
    pub operator_gated: bool,
    /// True when a simulate-first dry run is mandatory before real execution
    /// (always true for irreversible actions per I6).
    pub simulate_required: bool,
    /// True when the action's side-effect primitive is actually wired in
    /// `edamame_core`. When false, a non-simulated request records an auditable
    /// operator-decision intent but performs no live containment. Consumers MUST
    /// surface this honestly (record-intent vs execute) rather than implying the
    /// action took effect.
    pub wired: bool,
}

/// Build the full read-only catalog. `mcp_enabled` reflects whether
/// `edamame_core` was built with the `mcp` feature and governs the `wired`
/// status of `RevokeToolGrant` (see [`ResponseActionKind::wired`]).
pub fn response_action_catalog(mcp_enabled: bool) -> Vec<ResponseActionDescriptor> {
    ResponseActionKind::all()
        .into_iter()
        .map(|k| ResponseActionDescriptor {
            kind: k.as_str().to_string(),
            description: k.description().to_string(),
            reversible: k.reversible(),
            operator_gated: k.operator_gated(),
            // Irreversible actions MUST be simulated first; reversible ones
            // default to simulate-encouraged but allowed direct.
            simulate_required: !k.reversible(),
            wired: k.wired(mcp_enabled),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Response action request + record
// ---------------------------------------------------------------------------

/// A requested response action (the operator RPC input shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionRequest {
    pub kind: String,
    /// Target reference (agent_type, session id, namespace, tool name, ...).
    pub target_ref: String,
    pub reason: String,
    /// When true, perform a dry run only (no side effects). I6 mandatory for
    /// irreversible actions.
    pub simulated: bool,
}

/// Validation outcome for a requested action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseValidation {
    Ok,
    UnknownKind,
    /// An irreversible action was requested without a prior simulate run.
    IrreversibleRequiresSimulateFirst,
    EmptyTarget,
}

/// Validate a response request per I6 (irreversible requires simulate-first).
/// `already_simulated` is whether a dry run of the same (kind,target) was
/// recorded earlier.
pub fn validate_response_request(
    req: &ResponseActionRequest,
    already_simulated: bool,
) -> ResponseValidation {
    let Some(kind) = ResponseActionKind::from_str_lenient(&req.kind) else {
        return ResponseValidation::UnknownKind;
    };
    if req.target_ref.trim().is_empty() {
        return ResponseValidation::EmptyTarget;
    }
    // Irreversible + real execution requires a prior simulate of the same shape.
    if !kind.reversible() && !req.simulated && !already_simulated {
        return ResponseValidation::IrreversibleRequiresSimulateFirst;
    }
    ResponseValidation::Ok
}

/// An executed (or simulated) response-action record (append-only history).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionRecord {
    pub action_id: String,
    pub kind: String,
    pub target_ref: String,
    pub reason: String,
    pub reversible: bool,
    pub simulated: bool,
    pub executed_at: chrono::DateTime<chrono::Utc>,
    /// True once an undo has been applied (reversible actions only).
    pub undone: bool,
    pub undone_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Build an executed/simulated record from a validated request.
pub fn build_response_record(req: &ResponseActionRequest) -> ResponseActionRecord {
    let kind = ResponseActionKind::from_str_lenient(&req.kind);
    let reversible = kind.map(|k| k.reversible()).unwrap_or(false);
    let executed_at = chrono::Utc::now();
    let action_id = format!(
        "resp-{}",
        crate::agent_visibility::short_hash(&format!(
            "{}:{}:{}",
            req.kind,
            req.target_ref,
            executed_at.timestamp_nanos_opt().unwrap_or_default()
        ))
    );
    ResponseActionRecord {
        action_id,
        kind: req.kind.clone(),
        target_ref: req.target_ref.clone(),
        reason: req.reason.clone(),
        reversible,
        simulated: req.simulated,
        executed_at,
        undone: false,
        undone_at: None,
    }
}

// ---------------------------------------------------------------------------
// Case export (portable incident bundle)
// ---------------------------------------------------------------------------

/// Reference to one evidence artifact bundled into a case export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEvidenceRef {
    pub kind: String,
    pub ref_id: String,
    pub summary: String,
}

/// A portable incident case bundle (OCSF/STIX-shaped projection). Content is
/// metadata + refs by default; full content is break-glass only (I5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseExport {
    pub case_id: String,
    pub run_id: String,
    pub format: String,
    pub exported_at: chrono::DateTime<chrono::Utc>,
    pub evidence_refs: Vec<CaseEvidenceRef>,
    pub summary: String,
}

/// Build a case export bundling the supplied evidence refs for a run.
pub fn build_case_export(run_id: &str, evidence_refs: Vec<CaseEvidenceRef>) -> CaseExport {
    let exported_at = chrono::Utc::now();
    let case_id = format!(
        "case-{}",
        crate::agent_visibility::short_hash(&format!(
            "{}:{}",
            run_id,
            exported_at.timestamp_nanos_opt().unwrap_or_default()
        ))
    );
    let summary = format!(
        "Incident case for run {} with {} evidence artifact(s).",
        run_id,
        evidence_refs.len()
    );
    CaseExport {
        case_id,
        run_id: run_id.to_string(),
        format: "ocsf_json".to_string(),
        exported_at,
        evidence_refs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_marks_reversibility_and_simulate() {
        let cat = response_action_catalog(true);
        assert_eq!(cat.len(), 7);
        let pause = cat.iter().find(|d| d.kind == "pause_agent").unwrap();
        assert!(pause.reversible);
        assert!(!pause.simulate_required);
        let disable = cat.iter().find(|d| d.kind == "disable_agent").unwrap();
        assert!(!disable.reversible);
        assert!(disable.operator_gated);
        assert!(disable.simulate_required);
    }

    #[test]
    fn catalog_marks_wired_status() {
        // With MCP enabled, the three wired actions are pause_agent,
        // require_confirm_all_calls, and revoke_tool_grant. The rest record
        // intent only.
        let cat = response_action_catalog(true);
        let wired: std::collections::BTreeSet<&str> = cat
            .iter()
            .filter(|d| d.wired)
            .map(|d| d.kind.as_str())
            .collect();
        assert_eq!(
            wired,
            [
                "pause_agent",
                "require_confirm_all_calls",
                "revoke_tool_grant"
            ]
            .into_iter()
            .collect()
        );
        // kill_egress_session is conceptually reversible but NOT wired: it must
        // never be presented as executed containment.
        let kill = cat
            .iter()
            .find(|d| d.kind == "kill_egress_session")
            .unwrap();
        assert!(kill.reversible);
        assert!(!kill.wired);

        // Without MCP, revoke_tool_grant drops out of the wired set.
        let cat_no_mcp = response_action_catalog(false);
        let revoke = cat_no_mcp
            .iter()
            .find(|d| d.kind == "revoke_tool_grant")
            .unwrap();
        assert!(!revoke.wired);
    }

    #[test]
    fn irreversible_requires_simulate_first() {
        let req = ResponseActionRequest {
            kind: "rotate_exposed_secret".to_string(),
            target_ref: "AWS_SECRET_ACCESS_KEY".to_string(),
            reason: "exposed in egress".to_string(),
            simulated: false,
        };
        // No prior simulate -> rejected.
        assert_eq!(
            validate_response_request(&req, false),
            ResponseValidation::IrreversibleRequiresSimulateFirst
        );
        // With a prior simulate -> ok.
        assert_eq!(
            validate_response_request(&req, true),
            ResponseValidation::Ok
        );
        // Simulated run itself -> ok.
        let sim = ResponseActionRequest {
            simulated: true,
            ..req.clone()
        };
        assert_eq!(
            validate_response_request(&sim, false),
            ResponseValidation::Ok
        );
    }

    #[test]
    fn reversible_action_no_simulate_needed() {
        let req = ResponseActionRequest {
            kind: "pause_agent".to_string(),
            target_ref: "cursor".to_string(),
            reason: "drift spike".to_string(),
            simulated: false,
        };
        assert_eq!(
            validate_response_request(&req, false),
            ResponseValidation::Ok
        );
    }

    #[test]
    fn unknown_kind_and_empty_target_rejected() {
        let bad = ResponseActionRequest {
            kind: "nuke_from_orbit".to_string(),
            target_ref: "x".to_string(),
            reason: "".to_string(),
            simulated: false,
        };
        assert_eq!(
            validate_response_request(&bad, false),
            ResponseValidation::UnknownKind
        );

        let empty = ResponseActionRequest {
            kind: "pause_agent".to_string(),
            target_ref: "  ".to_string(),
            reason: "".to_string(),
            simulated: false,
        };
        assert_eq!(
            validate_response_request(&empty, false),
            ResponseValidation::EmptyTarget
        );
    }

    #[test]
    fn case_export_bundles_refs() {
        let refs = vec![CaseEvidenceRef {
            kind: "data_flow_finding".to_string(),
            ref_id: "df-abc".to_string(),
            summary: "secret -> trust2".to_string(),
        }];
        let c = build_case_export("run-1", refs);
        assert_eq!(c.run_id, "run-1");
        assert_eq!(c.evidence_refs.len(), 1);
        assert!(c.case_id.starts_with("case-"));
    }

    #[test]
    fn record_carries_reversibility() {
        let req = ResponseActionRequest {
            kind: "kill_egress_session".to_string(),
            target_ref: "sess-1".to_string(),
            reason: "exfil".to_string(),
            simulated: true,
        };
        let rec = build_response_record(&req);
        assert!(rec.reversible);
        assert!(rec.simulated);
        assert!(!rec.undone);
    }
}
