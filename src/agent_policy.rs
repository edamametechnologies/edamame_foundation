//! Enterprise policy packs, content-addressed attestations, and cross-zone
//! approval workflow (INC-13, Stage D+ governance).
//!
//! This is the governance layer on top of the Stage A-D projections. It is pure
//! deterministic logic with three concerns:
//!
//! - **Policy packs** -- a declarative set of governance rules an enterprise
//!   applies to the agent fleet. Each rule is a deterministic predicate over a
//!   `PolicyInputs` snapshot (which the core assembles from the visibility
//!   projections it already owns: firewall mode, MCP findings, agent approval
//!   state, active alertable divergence/attack-pattern findings,
//!   cross-boundary data flow).
//!   `evaluate_policy_pack` produces a `PolicyEvaluation` compliance report.
//! - **Attestations** -- a tamper-evident, content-addressed digest over an
//!   artifact (a policy evaluation). The digest is a full SHA-256 over the
//!   canonical bytes; `verify_attestation` re-derives it. This
//!   is the deterministic-first primitive; a cryptographic signature
//!   (cosign / in-toto) is the deployment-time extension that wraps this digest.
//! - **Cross-zone approval** -- an operator workflow record for promoting an
//!   agent into a more-trusted zone. Request -> approve/deny, all operator-only
//!   at the core/RPC layer (I1).
//!
//! Invariants:
//! - **I3 Deterministic-first**: every rule verdict and the attestation digest
//!   are fixed functions of the inputs; no LLM is consulted here.
//! - **I1 (enforced in core)**: pack activation, evaluation refresh, and every
//!   zone-promotion decision are operator-only RPCs, never MCP tools. This
//!   module is pure logic; the read/mutate split is enforced at the core layer.
//! - **I2 Core as source of truth**: the inputs are assembled from projections
//!   the core already owns; nothing here re-derives state.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Content digest (full SHA-256, the attestation primitive)
// ---------------------------------------------------------------------------

/// Full SHA-256 hex digest of `input` (64 hex chars). The content-addressed
/// attestation primitive -- distinct from `agent_visibility::short_hash`, which
/// truncates to 16 chars for ids.
pub fn content_digest(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Policy rules
// ---------------------------------------------------------------------------

/// The fixed catalog of deterministic policy-rule kinds. Each maps to a
/// predicate over `PolicyInputs`. Adding a kind is a code change (I3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleKind {
    /// The tool-call firewall mode must be at least `param` (recommend < confirm
    /// < block). Graduating enforcement is the core governance lever (I6).
    RequireFirewallModeAtLeast,
    /// No MCP endpoint may carry agent traffic over cleartext transport.
    ForbidCleartextMcp,
    /// No locally-bound MCP server may be publicly reachable without strong auth.
    ForbidPublicMcpWithoutStrongAuth,
    /// The fleet must carry no active alertable (HIGH/CRITICAL, non-dismissed)
    /// divergence or attack-pattern findings.
    ForbidActiveAlertableFindings,
    /// No cross-trust-boundary egress edge may move secret/credential taint.
    ForbidCrossBoundarySecretEgress,
}

impl PolicyRuleKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyRuleKind::RequireFirewallModeAtLeast => "require_firewall_mode_at_least",
            PolicyRuleKind::ForbidCleartextMcp => "forbid_cleartext_mcp",
            PolicyRuleKind::ForbidPublicMcpWithoutStrongAuth => {
                "forbid_public_mcp_without_strong_auth"
            }
            PolicyRuleKind::ForbidActiveAlertableFindings => "forbid_active_alertable_findings",
            PolicyRuleKind::ForbidCrossBoundarySecretEgress => {
                "forbid_cross_boundary_secret_egress"
            }
        }
    }
}

/// One declarative governance rule in a policy pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub kind: PolicyRuleKind,
    /// Threshold parameter for parameterised kinds (firewall mode); `None` for
    /// boolean kinds.
    pub param: Option<String>,
    /// Severity attributed to a violation (`critical`/`high`/`medium`/`low`).
    pub severity: String,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Policy pack
// ---------------------------------------------------------------------------

/// A named, versioned set of governance rules an enterprise applies to the
/// fleet. Portable: serialise to JSON and ship it as an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPack {
    pub pack_id: String,
    pub version: String,
    pub name: String,
    pub description: String,
    pub rules: Vec<PolicyRule>,
}

/// The built-in EDAMAME baseline policy pack. Conservative defaults that any
/// fleet should clear: no cleartext/public-unauth MCP, no active alertable
/// divergence/attack-pattern findings, no cross-boundary secret egress, and
/// the firewall at least in `recommend`.
pub fn default_policy_pack() -> PolicyPack {
    PolicyPack {
        pack_id: "edamame-baseline".to_string(),
        version: "1".to_string(),
        name: "EDAMAME Baseline".to_string(),
        description: "Conservative governance baseline for monitored coding-agent fleets (INC-13)."
            .to_string(),
        rules: vec![
            PolicyRule {
                rule_id: "fw-recommend".to_string(),
                kind: PolicyRuleKind::RequireFirewallModeAtLeast,
                param: Some("recommend".to_string()),
                severity: "low".to_string(),
                description: "Tool-call firewall must be at least in recommend mode.".to_string(),
            },
            PolicyRule {
                rule_id: "mcp-no-cleartext".to_string(),
                kind: PolicyRuleKind::ForbidCleartextMcp,
                param: None,
                severity: "high".to_string(),
                description: "No MCP endpoint may carry agent traffic over cleartext transport."
                    .to_string(),
            },
            PolicyRule {
                rule_id: "mcp-no-public-unauth".to_string(),
                kind: PolicyRuleKind::ForbidPublicMcpWithoutStrongAuth,
                param: None,
                severity: "critical".to_string(),
                description:
                    "No locally-bound MCP server may be publicly reachable without strong auth."
                        .to_string(),
            },
            PolicyRule {
                rule_id: "no-active-alertable-findings".to_string(),
                kind: PolicyRuleKind::ForbidActiveAlertableFindings,
                param: None,
                severity: "high".to_string(),
                description:
                    "No active alertable (HIGH/CRITICAL) divergence or attack-pattern findings."
                        .to_string(),
            },
            PolicyRule {
                rule_id: "no-secret-egress".to_string(),
                kind: PolicyRuleKind::ForbidCrossBoundarySecretEgress,
                param: None,
                severity: "critical".to_string(),
                description:
                    "No cross-trust-boundary egress edge may move secret/credential taint."
                        .to_string(),
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Policy inputs (the deterministic snapshot the core assembles)
// ---------------------------------------------------------------------------

/// The metadata snapshot a policy pack is evaluated against. The core assembles
/// this from the visibility projections it already owns (I2). Metadata only --
/// no bodies, no secrets (I5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyInputs {
    /// Active firewall mode slug (`recommend`/`confirm`/`block`).
    pub firewall_mode: String,
    /// Count of MCP findings keyed `mcp_remote_cleartext_transport`.
    pub mcp_cleartext_findings: u32,
    /// Count of MCP findings keyed `mcp_public_no_strong_auth`.
    pub mcp_public_no_auth_findings: u32,
    /// Count of active alertable (HIGH/CRITICAL, non-dismissed) divergence and
    /// attack-pattern findings across the fleet.
    pub active_alertable_findings: u32,
    /// Count of alertable cross-boundary data-flow edges moving secret taint.
    pub cross_boundary_secret_egress_count: u32,
}

// ---------------------------------------------------------------------------
// Evaluation result
// ---------------------------------------------------------------------------

/// The verdict for a single evaluated rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleResult {
    pub rule_id: String,
    pub kind: String,
    pub satisfied: bool,
    pub severity: String,
    pub detail: String,
}

/// A full policy-pack compliance evaluation. `compliant` is true iff every rule
/// is satisfied. Deterministic apart from the `evaluated_at` clock stamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub pack_id: String,
    pub pack_version: String,
    pub evaluated_at: chrono::DateTime<chrono::Utc>,
    pub compliant: bool,
    pub total_rules: u32,
    pub satisfied_rules: u32,
    pub violated_rules: u32,
    pub results: Vec<PolicyRuleResult>,
    pub summary: String,
}

// --- ordering helpers (deterministic ladders) ---

fn firewall_rank(mode: &str) -> i32 {
    match mode.trim().to_ascii_lowercase().as_str() {
        "recommend" => 0,
        "confirm" => 1,
        "block" => 2,
        _ => -1,
    }
}

/// Evaluate one rule against the inputs. Pure.
fn evaluate_rule(rule: &PolicyRule, inputs: &PolicyInputs) -> PolicyRuleResult {
    let (satisfied, detail) = match rule.kind {
        PolicyRuleKind::RequireFirewallModeAtLeast => {
            let required = rule.param.as_deref().unwrap_or("recommend");
            let ok = firewall_rank(&inputs.firewall_mode) >= firewall_rank(required);
            (
                ok,
                format!(
                    "firewall mode is '{}', required at least '{}'",
                    inputs.firewall_mode, required
                ),
            )
        }
        PolicyRuleKind::ForbidCleartextMcp => {
            let ok = inputs.mcp_cleartext_findings == 0;
            (
                ok,
                format!(
                    "{} cleartext MCP transport finding(s)",
                    inputs.mcp_cleartext_findings
                ),
            )
        }
        PolicyRuleKind::ForbidPublicMcpWithoutStrongAuth => {
            let ok = inputs.mcp_public_no_auth_findings == 0;
            (
                ok,
                format!(
                    "{} public-without-strong-auth MCP finding(s)",
                    inputs.mcp_public_no_auth_findings
                ),
            )
        }
        PolicyRuleKind::ForbidActiveAlertableFindings => {
            let ok = inputs.active_alertable_findings == 0;
            (
                ok,
                format!(
                    "{} active alertable divergence/attack-pattern finding(s)",
                    inputs.active_alertable_findings
                ),
            )
        }
        PolicyRuleKind::ForbidCrossBoundarySecretEgress => {
            let ok = inputs.cross_boundary_secret_egress_count == 0;
            (
                ok,
                format!(
                    "{} cross-boundary secret-egress edge(s)",
                    inputs.cross_boundary_secret_egress_count
                ),
            )
        }
    };

    PolicyRuleResult {
        rule_id: rule.rule_id.clone(),
        kind: rule.kind.as_str().to_string(),
        satisfied,
        severity: rule.severity.clone(),
        detail,
    }
}

/// Evaluate every rule in `pack` against `inputs`, producing a compliance
/// report. `compliant` is true iff every rule is satisfied. Pure apart from the
/// clock stamp.
pub fn evaluate_policy_pack(pack: &PolicyPack, inputs: &PolicyInputs) -> PolicyEvaluation {
    let results: Vec<PolicyRuleResult> = pack
        .rules
        .iter()
        .map(|r| evaluate_rule(r, inputs))
        .collect();
    let total_rules = results.len() as u32;
    let satisfied_rules = results.iter().filter(|r| r.satisfied).count() as u32;
    let violated_rules = total_rules - satisfied_rules;
    let compliant = violated_rules == 0;

    let summary = if compliant {
        format!(
            "Compliant with '{}' v{}: {}/{} rules satisfied.",
            pack.pack_id, pack.version, satisfied_rules, total_rules
        )
    } else {
        let worst: Vec<&str> = results
            .iter()
            .filter(|r| !r.satisfied)
            .map(|r| r.rule_id.as_str())
            .take(3)
            .collect();
        format!(
            "Non-compliant with '{}' v{}: {}/{} rules violated (e.g. {}).",
            pack.pack_id,
            pack.version,
            violated_rules,
            total_rules,
            worst.join(", ")
        )
    };

    PolicyEvaluation {
        pack_id: pack.pack_id.clone(),
        pack_version: pack.version.clone(),
        evaluated_at: chrono::Utc::now(),
        compliant,
        total_rules,
        satisfied_rules,
        violated_rules,
        results,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Attestation (content-addressed; tamper-evident)
// ---------------------------------------------------------------------------

/// A content-addressed attestation over an artifact. `digest` is a full SHA-256
/// over the canonical bytes of the subject; `verify_attestation` re-derives it.
/// `algorithm` names the digest primitive; a cryptographic signature
/// (cosign / in-toto) is the deployment-time wrapper around this digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub attestation_id: String,
    /// What was attested (`policy_evaluation`).
    pub subject: String,
    /// Reference to the attested subject (pack id, agent type, ...).
    pub subject_ref: String,
    /// Full SHA-256 hex over the canonical subject bytes.
    pub digest: String,
    pub algorithm: String,
    /// For an evaluation attestation, whether the evaluation was compliant.
    pub compliant: Option<bool>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub summary: String,
}

fn build_attestation(
    subject: &str,
    subject_ref: &str,
    canonical_bytes: &str,
    compliant: Option<bool>,
    summary: String,
) -> Attestation {
    let digest = content_digest(canonical_bytes);
    let created_at = chrono::Utc::now();
    let attestation_id = format!(
        "att-{}",
        crate::agent_visibility::short_hash(&format!(
            "{}:{}:{}",
            subject,
            subject_ref,
            &digest[..16.min(digest.len())]
        ))
    );
    Attestation {
        attestation_id,
        subject: subject.to_string(),
        subject_ref: subject_ref.to_string(),
        digest,
        algorithm: "sha256-content-addressed".to_string(),
        compliant,
        created_at,
        summary,
    }
}

/// Attest a policy evaluation: digest over its canonical JSON. The returned
/// attestation's `digest` covers the full evaluation (including its timestamp),
/// so any later edit of the evaluation is detectable.
pub fn attest_evaluation(eval: &PolicyEvaluation) -> Attestation {
    let canonical = serde_json::to_string(eval).unwrap_or_default();
    build_attestation(
        "policy_evaluation",
        &format!("{}@{}", eval.pack_id, eval.pack_version),
        &canonical,
        Some(eval.compliant),
        format!(
            "attestation of '{}' v{} evaluation: {}",
            eval.pack_id,
            eval.pack_version,
            if eval.compliant {
                "compliant"
            } else {
                "non-compliant"
            }
        ),
    )
}

/// Verify an attestation against the canonical bytes it claims to cover.
/// Returns true iff the recomputed digest matches.
pub fn verify_attestation(att: &Attestation, canonical_bytes: &str) -> bool {
    content_digest(canonical_bytes) == att.digest
}

// ---------------------------------------------------------------------------
// Cross-zone approval workflow
// ---------------------------------------------------------------------------

/// Status of a cross-zone promotion request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZonePromotionStatus {
    Requested,
    Approved,
    Denied,
}

impl ZonePromotionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ZonePromotionStatus::Requested => "requested",
            ZonePromotionStatus::Approved => "approved",
            ZonePromotionStatus::Denied => "denied",
        }
    }
}

/// True for a recognised trust-zone slug (`trust0`/`trust1`/`trust2`). The
/// firewall's origin zones; a promotion grants an agent a more-trusted origin.
pub fn is_valid_trust_zone(zone: &str) -> bool {
    matches!(
        zone.trim().to_ascii_lowercase().as_str(),
        "trust0" | "trust1" | "trust2"
    )
}

/// An operator cross-zone promotion record (append-only governance log). A
/// request to let `agent_type` operate in `target_zone`, then operator-decided.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePromotionRecord {
    pub promotion_id: String,
    pub agent_type: String,
    pub target_zone: String,
    pub reason: String,
    pub status: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub decided_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Build a new `Requested` cross-zone promotion record.
pub fn build_zone_promotion(
    agent_type: &str,
    target_zone: &str,
    reason: &str,
) -> ZonePromotionRecord {
    let requested_at = chrono::Utc::now();
    let promotion_id = format!(
        "zp-{}",
        crate::agent_visibility::short_hash(&format!(
            "{}:{}:{}",
            agent_type,
            target_zone,
            requested_at.timestamp_nanos_opt().unwrap_or_default()
        ))
    );
    ZonePromotionRecord {
        promotion_id,
        agent_type: agent_type.to_string(),
        target_zone: target_zone.trim().to_ascii_lowercase(),
        reason: reason.to_string(),
        status: ZonePromotionStatus::Requested.as_str().to_string(),
        requested_at,
        decided_at: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_inputs() -> PolicyInputs {
        PolicyInputs {
            firewall_mode: "recommend".to_string(),
            mcp_cleartext_findings: 0,
            mcp_public_no_auth_findings: 0,
            active_alertable_findings: 0,
            cross_boundary_secret_egress_count: 0,
        }
    }

    #[test]
    fn default_pack_is_compliant_on_clean_inputs() {
        let pack = default_policy_pack();
        let eval = evaluate_policy_pack(&pack, &clean_inputs());
        assert!(eval.compliant, "{}", eval.summary);
        assert_eq!(eval.violated_rules, 0);
        assert_eq!(eval.satisfied_rules, eval.total_rules);
    }

    #[test]
    fn cleartext_mcp_violates() {
        let pack = default_policy_pack();
        let mut inp = clean_inputs();
        inp.mcp_cleartext_findings = 1;
        let eval = evaluate_policy_pack(&pack, &inp);
        assert!(!eval.compliant);
        let r = eval
            .results
            .iter()
            .find(|r| r.rule_id == "mcp-no-cleartext")
            .unwrap();
        assert!(!r.satisfied);
        assert_eq!(r.severity, "high");
    }

    #[test]
    fn active_alertable_findings_violate_rule() {
        let pack = default_policy_pack();
        let mut inp = clean_inputs();
        inp.active_alertable_findings = 2;
        let eval = evaluate_policy_pack(&pack, &inp);
        assert!(!eval.compliant);
        let r = eval
            .results
            .iter()
            .find(|r| r.rule_id == "no-active-alertable-findings")
            .unwrap();
        assert!(!r.satisfied);
        assert_eq!(r.severity, "high");
        assert!(r.detail.contains("2 active alertable"));
    }

    #[test]
    fn firewall_mode_ladder() {
        let pack = default_policy_pack();
        // recommend satisfies "at least recommend".
        let eval = evaluate_policy_pack(&pack, &clean_inputs());
        assert!(
            eval.results
                .iter()
                .find(|r| r.rule_id == "fw-recommend")
                .unwrap()
                .satisfied
        );
        // An unknown/invalid mode (rank -1) fails the >= recommend (rank 0) check.
        let mut inp = clean_inputs();
        inp.firewall_mode = "off".to_string();
        let eval2 = evaluate_policy_pack(&pack, &inp);
        assert!(
            !eval2
                .results
                .iter()
                .find(|r| r.rule_id == "fw-recommend")
                .unwrap()
                .satisfied
        );
    }

    #[test]
    fn secret_egress_violates() {
        let pack = default_policy_pack();
        let mut inp = clean_inputs();
        inp.cross_boundary_secret_egress_count = 1;
        let eval = evaluate_policy_pack(&pack, &inp);
        assert!(!eval.compliant);
        let r = eval
            .results
            .iter()
            .find(|r| r.rule_id == "no-secret-egress")
            .unwrap();
        assert!(!r.satisfied);
        assert_eq!(r.severity, "critical");
    }

    #[test]
    fn evaluation_attestation_round_trips() {
        let pack = default_policy_pack();
        let eval = evaluate_policy_pack(&pack, &clean_inputs());
        let att = attest_evaluation(&eval);
        assert_eq!(att.subject, "policy_evaluation");
        assert_eq!(att.compliant, Some(true));
        assert_eq!(att.digest.len(), 64);
        // Verify against the same canonical bytes.
        let canonical = serde_json::to_string(&eval).unwrap();
        assert!(verify_attestation(&att, &canonical));
        // Tamper: a different evaluation has a different digest.
        let mut tampered = eval.clone();
        tampered.compliant = false;
        let tampered_canonical = serde_json::to_string(&tampered).unwrap();
        assert!(!verify_attestation(&att, &tampered_canonical));
    }

    #[test]
    fn zone_promotion_validation_and_build() {
        assert!(is_valid_trust_zone("trust1"));
        assert!(is_valid_trust_zone("TRUST2"));
        assert!(!is_valid_trust_zone("trust9"));
        let z = build_zone_promotion("cursor", "Trust1", "promote to local-trusted");
        assert_eq!(z.status, "requested");
        assert_eq!(z.target_zone, "trust1");
        assert!(z.promotion_id.starts_with("zp-"));
        assert!(z.decided_at.is_none());
    }

    #[test]
    fn pack_is_portable_json() {
        let pack = default_policy_pack();
        let json = serde_json::to_string(&pack).unwrap();
        let back: PolicyPack = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pack_id, "edamame-baseline");
        assert_eq!(back.rules.len(), pack.rules.len());
    }
}
