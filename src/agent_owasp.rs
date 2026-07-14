//! OWASP GenAI crosswalk scorecard (read-only, derived).
//!
//! A live scoreboard mapping EDAMAME's runtime evidence onto the two flagship
//! OWASP GenAI taxonomies (Agentic `ASI01..ASI10` and LLM `LLM01..LLM10`). Each
//! row carries:
//! - a **static coverage grade** (Strong / Partial / Indirect / Out of scope)
//!   taken verbatim from `edamame_core/OWASPGENAI.md` (the derived crosswalk
//!   doc), and
//! - **live finding attribution** parsed from the `OWASP-<id>` reference tokens
//!   that visibility findings already carry in `evidence["owasp_refs"]` and that
//!   attack-pattern findings carry in their `reference` string.
//!
//! The headline status is derived directly from the attributed live findings:
//! `critical` when any alertable CRITICAL finding is mapped to a category,
//! `attention` when there is any other alertable finding, and `clean`
//! otherwise. There is no separate composite score to disagree with.
//!
//! Invariants:
//! - **I3 Deterministic-first**: grades are static; live attribution is a pure
//!   function of the reference tokens. No LLM is consulted here (the underlying
//!   findings MAY have been LLM-adjudicated upstream).
//! - **I2 Core as source of truth**: this rolls up signals core already owns.
//! - OWASP tags are metadata only -- they never become a new alert source and
//!   never change a finding's severity or alertable behavior. This scorecard
//!   only *re-presents* existing findings grouped by OWASP category.
//! - Pure: no I/O, no clock except `generated_at` via `chrono::Utc::now()`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Taxonomy enums
// ---------------------------------------------------------------------------

/// Which OWASP GenAI Top-10 list a row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwaspFramework {
    /// OWASP Top 10 for Agentic Applications (2026), `ASI01..ASI10`.
    Agentic,
    /// OWASP Top 10 for LLM Applications (2025), `LLM01..LLM10`.
    Llm,
}

impl OwaspFramework {
    pub fn as_str(&self) -> &'static str {
        match self {
            OwaspFramework::Agentic => "agentic",
            OwaspFramework::Llm => "llm",
        }
    }

    /// Canonical OWASP GenAI page for this framework, used as the drill-down
    /// reference link on every row. Framework-level (not per-id) so the link is
    /// always a maintained OWASP page rather than a guessed per-risk slug.
    pub fn reference_url(&self) -> &'static str {
        match self {
            OwaspFramework::Agentic => {
                "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
            }
            OwaspFramework::Llm => "https://genai.owasp.org/llm-top-10/",
        }
    }
}

/// Static per-category coverage grade (from `OWASPGENAI.md`). Honest grading:
/// EDAMAME is a runtime observer, so a few rows are intentionally Indirect /
/// Out of scope rather than over-claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwaspCoverageGrade {
    /// Shipped, deterministic-first capability that directly observes/gates/responds.
    Strong,
    /// Core signal/inventory shipped; full reach pending a connector/UI/labeling.
    Partial,
    /// Not targeted directly, but EDAMAME evidence materially helps an operator.
    Indirect,
    /// Lives outside a runtime host/network observer (training-time, embedding math, factuality).
    OutOfScope,
}

impl OwaspCoverageGrade {
    pub fn as_str(&self) -> &'static str {
        match self {
            OwaspCoverageGrade::Strong => "strong",
            OwaspCoverageGrade::Partial => "partial",
            OwaspCoverageGrade::Indirect => "indirect",
            OwaspCoverageGrade::OutOfScope => "out_of_scope",
        }
    }
}

/// Honest enforcement status per row: whether EDAMAME can actively deliver the
/// control's required *enforcement* effect today, or only observe and evidence
/// it. Distinct from the coverage grade (which grades detection/evidence
/// reach): a row can be `Strong` coverage yet `MonitoringOnly` enforcement --
/// e.g. egress exfiltration is detected with full session telemetry but there
/// is no traffic firewall to block it yet.
///
/// Shared by the OWASP GenAI scorecard and the Trust Controls scorecard
/// (`agent_trust_controls`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    /// EDAMAME actively delivers the control's required function today
    /// (detection controls where monitoring IS the control, wired containment).
    Enforced,
    /// An enforcement path is wired but with material gaps: pre-execution
    /// tool-call gating is live only on agents whose plugin wires the hook
    /// (Claude Code today), and the firewall default mode is `recommend`.
    Partial,
    /// The control requires blocking/gating that EDAMAME does not perform yet;
    /// EDAMAME observes, scores, and evidences only (e.g. no traffic firewall,
    /// memory quarantine / kill-egress / disable-agent primitives unwired).
    MonitoringOnly,
    /// Enforcement is not the control shape for this row (organizational,
    /// design-time, or out-of-scope for a runtime observer); EDAMAME supplies
    /// evidence at most.
    NotApplicable,
}

impl EnforcementStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnforcementStatus::Enforced => "enforced",
            EnforcementStatus::Partial => "partial",
            EnforcementStatus::MonitoringOnly => "monitoring_only",
            EnforcementStatus::NotApplicable => "not_applicable",
        }
    }
}

// ---------------------------------------------------------------------------
// Static catalog (verbatim from OWASPGENAI.md per-row "Coverage" column)
// ---------------------------------------------------------------------------

use OwaspCoverageGrade::{Indirect, OutOfScope, Partial, Strong};
use OwaspFramework::{Agentic, Llm};

use EnforcementStatus::Partial as PartialEnforcement;
use EnforcementStatus::{MonitoringOnly, NotApplicable};

/// `(id, framework, title, grade, rationale, enforcement, enforcement_note)`
/// for every OWASP GenAI category. Titles are verbatim from the official
/// OWASP GenAI lists (Agentic 2026, LLM 2025). `rationale` is the per-category
/// "why this grade" sentence -- what EDAMAME concretely does for this risk and
/// (for non-Strong rows) what is pending or out of scope. Kept aligned with the
/// per-row "How EDAMAME maps" column in `edamame_core/OWASPGENAI.md`; surfaced
/// in the scorecard drill-down so a grade is never an opaque label.
///
/// `enforcement` is the honest enforcement status (see [`EnforcementStatus`]):
/// coverage grades detection/evidence reach; enforcement grades whether EDAMAME
/// can actively gate/contain the risk today. Grounded in the shipped
/// primitives: pre-execution tool-call gating is wired only where an agent
/// plugin ships the hook (Claude Code today) and the firewall default is
/// `recommend`; there is no traffic firewall (egress is detected, not
/// blocked); response actions QuarantineMemoryNamespace / KillEgressSession /
/// DisableAgent / RotateExposedSecret record intent but are not wired.
const OWASP_CATALOG: &[(
    &str,
    OwaspFramework,
    &str,
    OwaspCoverageGrade,
    &str,
    EnforcementStatus,
    &str,
)] = &[
    // OWASP Top 10 for Agentic Applications (2026).
    (
        "ASI01",
        Agentic,
        "Agent Goal Hijack",
        Strong,
        "Two-plane divergence is built for hijacked objectives: a redirected plan diverges from the declared intent, and hidden-prompt exfil surfaces as token / sensitive-material egress on the system plane.",
        MonitoringOnly,
        "Hijack is detected post-hoc from divergence and egress evidence; no inline goal gate blocks the redirected action before it lands.",
    ),
    (
        "ASI02",
        Agentic,
        "Tool Misuse and Exploitation",
        Strong,
        "The tool-call firewall scores every call (allow / recommend / confirm / block) with tamper-evident receipts; a bent legitimate tool also trips file-system-tampering or sandbox-exploitation.",
        PartialEnforcement,
        "Pre-execution gating is live only on agents whose plugin wires the hook (Claude Code today); other agents are scored post-hoc and the firewall default mode is recommend.",
    ),
    (
        "ASI03",
        Agentic,
        "Identity and Privilege Abuse",
        Strong,
        "MCP discovery and the agent component inventory map the real capability/identity surface, trust zones gate privilege boundaries, and out-of-scope credential use is caught by credential-harvest / token-exfiltration.",
        PartialEnforcement,
        "Revoking a paired MCP client's grant is wired; broader credential rotation and privilege revocation record operator intent without an active primitive yet.",
    ),
    (
        "ASI04",
        Agentic,
        "Agentic Supply Chain Vulnerabilities",
        Strong,
        "The agent component inventory catches runtime self-extension, MCP servers are risk-scored, and the skill-supply-chain check flags blacklisted component sources.",
        MonitoringOnly,
        "Drift and blacklisted components are detected and alerted; installs are not blocked or rolled back by EDAMAME.",
    ),
    (
        "ASI05",
        Agentic,
        "Unexpected Code Execution",
        Strong,
        "Code execution lands on the host EDAMAME watches: the sandbox-exploitation check grades suspicious process lineage, corroborated by L7 attribution and file-system-tampering.",
        MonitoringOnly,
        "Suspicious execution is detected and graded; EDAMAME does not sandbox or kill the offending process.",
    ),
    (
        "ASI06",
        Agentic,
        "Memory and Context Poisoning",
        Partial,
        "On-host memory / context-poisoning heuristics and a provenance DAG ship, but external vector-store connectors (Pinecone, Qdrant, Weaviate, Mem0) and per-run retrieval drill-down are still pending, so a managed vector DB is not yet introspected end to end.",
        MonitoringOnly,
        "Poisoning heuristics alert; the quarantine-memory-namespace response action records intent but its primitive is not wired yet.",
    ),
    (
        "ASI07",
        Agentic,
        "Insecure Inter-Agent Communication",
        Partial,
        "The A2A graph maps inter-agent endpoints and flags spoofed / replayed / cross-zone patterns from network telemetry, but EDAMAME does not itself sign or authenticate A2A messages (that is the framework's job) and the UI surface is pending.",
        MonitoringOnly,
        "Inter-agent patterns are observed from network telemetry; message signing/authentication belongs to the agent framework, and EDAMAME does not block A2A traffic.",
    ),
    (
        "ASI08",
        Agentic,
        "Cascading Failures",
        Strong,
        "Recursion and delegation detection tracks depth and loops and emits an explicit cascading-failure finding from the same alertable drift event; cascades deeper than delegation structure stay bounded by what the host observer sees.",
        MonitoringOnly,
        "Runaway recursion is detected and alerted; the circuit-breaker / disable-agent containment primitives are not wired yet.",
    ),
    (
        "ASI09",
        Agentic,
        "Human-Agent Trust Exploitation",
        Partial,
        "EDAMAME gives the operator hash-chained ground truth independent of the agent's narrative (deterministic-first, no naked scores), but it does not yet parse the agent's natural-language output for manipulation or social-pressure cues.",
        NotApplicable,
        "The control shape is independent evidence for human judgment, which EDAMAME supplies; there is no enforcement step to automate.",
    ),
    (
        "ASI10",
        Agentic,
        "Rogue Agents",
        Strong,
        "A rogue agent is exactly what the two-plane model catches -- divergence verdict, drift, policy-pack evaluation, and reversible-first response -- and observer-independence guarantees it cannot dismiss its own findings.",
        PartialEnforcement,
        "Pause-agent and confirm-all-calls responses are wired and reversible; hard containment (disable agent, kill egress session) records intent without a wired primitive yet.",
    ),
    // OWASP Top 10 for LLM Applications (2025).
    (
        "LLM01",
        Llm,
        "Prompt Injection",
        Strong,
        "EDAMAME is not an inline prompt scanner; it catches the consequence of a successful injection -- the divergent action and cross-trust-boundary egress after untrusted retrieval -- which is the durable answer to a string attack you cannot fully enumerate.",
        MonitoringOnly,
        "Consequences of injection are detected on the system plane; prompts are not filtered or blocked inline.",
    ),
    (
        "LLM02",
        Llm,
        "Sensitive Information Disclosure",
        Strong,
        "Core attack-pattern detection (token-exfiltration, credential-harvest, sensitive-material-egress) plus the data-flow map from taint class to sink trust zone.",
        MonitoringOnly,
        "Exfiltration is detected with full session evidence; there is no traffic firewall yet, so the egress itself is not blocked.",
    ),
    (
        "LLM03",
        Llm,
        "Supply Chain",
        Strong,
        "The same machinery as ASI04: the agent component inventory, MCP discovery and risk-scoring, and the skill-supply-chain check.",
        MonitoringOnly,
        "Supply-chain drift and blacklisted sources are detected and alerted; component installs are not blocked.",
    ),
    (
        "LLM04",
        Llm,
        "Data and Model Poisoning",
        Partial,
        "The runtime-reachable slice (retrieval and memory poisoning) is covered by the memory and RAG heuristics; training-time data and model poisoning is outside a runtime observer's scope and is not claimed.",
        MonitoringOnly,
        "Runtime-reachable poisoning is detected; nothing is quarantined or rolled back automatically.",
    ),
    (
        "LLM05",
        Llm,
        "Improper Output Handling",
        Indirect,
        "EDAMAME does not sanitize LLM output strings; it catches the downstream effect when mishandled output triggers a dangerous action (a firewall verdict, file-system-tampering or sandbox-exploitation). Effect-level, not string-level.",
        MonitoringOnly,
        "Downstream effects are detected; output strings are not sanitized or blocked before consumption.",
    ),
    (
        "LLM06",
        Llm,
        "Excessive Agency",
        Strong,
        "The direct enforcement answer: the tool-call firewall verdict ladder, the capability graph with privilege classes, policy packs, and reversible-first response.",
        PartialEnforcement,
        "The firewall verdict ladder is live but gates pre-execution only where the agent plugin wires the hook (Claude Code today), and the default mode is recommend.",
    ),
    (
        "LLM07",
        Llm,
        "System Prompt Leakage",
        Strong,
        "Instruction files (CLAUDE.md, AGENTS.md, .cursorrules, mcp.json) are inventoried as components and tagged sensitive, so exfil of their contents to an external sink trips sensitive-material-egress while local IDE self-reads stay quiet.",
        MonitoringOnly,
        "Leakage is detected as sensitive-material egress; no traffic firewall blocks the leaking connection yet.",
    ),
    (
        "LLM08",
        Llm,
        "Vector and Embedding Weaknesses",
        Partial,
        "The memory / RAG store inventory and chunk-risk grading ship, but embedding-math weaknesses (inversion, adversarial embeddings) are largely outside a host / network observer's scope.",
        MonitoringOnly,
        "Store inventory and chunk-risk grading are observational; no retrieval path is gated.",
    ),
    (
        "LLM09",
        Llm,
        "Misinformation",
        OutOfScope,
        "EDAMAME is a runtime security observer, not a factuality or hallucination evaluator; provenance can trace what an agent acted on, but EDAMAME does not judge truthfulness.",
        NotApplicable,
        "Factuality evaluation is outside a runtime security observer's scope; there is nothing for EDAMAME to enforce.",
    ),
    (
        "LLM10",
        Llm,
        "Unbounded Consumption",
        Strong,
        "The same signals as ASI08 -- recursion / loop detection and drift escalation plus runaway-egress visibility -- surfaced as an explicit unbounded-consumption finding; token or budget accounting beyond fan-out and egress volume is out of a host observer's scope.",
        MonitoringOnly,
        "Runaway consumption is detected and daily budgets alert (recommend/confirm); nothing is throttled or halted automatically.",
    ),
];

/// OWASP categories whose *live* assessment depends on the behavioral-divergence
/// engine (two-plane intent-vs-action). That engine builds the behavioral model
/// from agent transcripts and adjudicates intent against system telemetry using
/// the configured LLM provider, so without a usable LLM these categories cannot
/// be assessed live -- absence of findings is not evidence of safety. The UI
/// surfaces "Unknown" for these rows when the LLM is unavailable instead of the
/// (misleading) "no live findings" state.
///
/// Every other category is deterministic-first: its findings fire from
/// host/network telemetry without an LLM (the LLM only adjudicates upstream),
/// so those rows stay meaningful regardless of LLM availability.
const OWASP_LLM_DEPENDENT_IDS: &[&str] = &["ASI01", "ASI10", "LLM01"];

/// True when category `id`'s live assessment depends on the behavioral-divergence
/// engine (and therefore on a configured LLM provider). See
/// [`OWASP_LLM_DEPENDENT_IDS`].
pub fn is_llm_dependent(id: &str) -> bool {
    OWASP_LLM_DEPENDENT_IDS.contains(&id)
}

// ---------------------------------------------------------------------------
// Drill-down record (one contributing finding, metadata-only)
// ---------------------------------------------------------------------------

/// A single finding that contributes to an OWASP category row, carried so the
/// UI can drill down from the category into the concrete evidence without a
/// second resolver round-trip. Metadata only (I5): finding key, human title,
/// severity, originating domain, and the alertable flag -- never transcript /
/// file bodies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwaspContributingFinding {
    /// Stable finding key (`<domain>:<rule_id>:<subject_id>` for visibility
    /// findings, the attack-pattern finding key otherwise).
    pub finding_key: String,
    /// Short human-readable title for the drill-down list row.
    pub title: String,
    /// Uppercase severity string (`CRITICAL`..`INFO`).
    pub severity: String,
    /// Originating domain (`mcp`, `graph`, `attack_pattern`, ...).
    pub domain: String,
    /// True when this finding counts toward the alertable total.
    pub alertable: bool,
}

// ---------------------------------------------------------------------------
// Input (per-category aggregated live signal, built by the core manager)
// ---------------------------------------------------------------------------

/// Aggregated live-finding signal for one OWASP category. Keyed by canonical id
/// (`"ASI01"`). Built by the core manager from the union of visibility findings
/// and attack-pattern findings that reference this category.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OwaspRowInput {
    pub total_findings: u32,
    pub alertable_findings: u32,
    /// Worst severity string across contributing findings (`CRITICAL`..`NONE`).
    pub worst_severity: String,
    /// Drill-down records for the findings referencing this category (deduped
    /// by finding key, sorted for deterministic output).
    pub contributing_findings: Vec<OwaspContributingFinding>,
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// One OWASP category row: static grade + live attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspRow {
    /// Canonical id, e.g. `"ASI01"` / `"LLM02"`.
    pub id: String,
    pub framework: OwaspFramework,
    pub title: String,
    pub grade: OwaspCoverageGrade,
    /// Per-category "why this grade" rationale: what EDAMAME concretely does for
    /// this risk and (for non-Strong rows) what is pending or out of scope.
    /// Static, sourced from the catalog (mirrors `OWASPGENAI.md`). Lets the UI
    /// explain a grade instead of showing an opaque label.
    pub coverage_rationale: String,
    /// Honest enforcement status: whether EDAMAME actively delivers the
    /// control's required enforcement effect today or only observes/evidences
    /// it. See [`EnforcementStatus`].
    pub enforcement: EnforcementStatus,
    /// One-sentence "why this enforcement status" note (what is wired today
    /// and what is pending), shown next to the enforcement badge.
    pub enforcement_note: String,
    /// Canonical OWASP GenAI page for this row's framework, for drill-down to
    /// the authoritative risk description.
    pub reference_url: String,
    pub total_findings: u32,
    pub alertable_findings: u32,
    /// Worst severity across contributing findings (`CRITICAL`..`NONE`).
    pub worst_severity: String,
    /// True when at least one live finding references this category.
    pub has_live_findings: bool,
    /// True when this category's live assessment depends on the
    /// behavioral-divergence engine (and therefore a configured LLM provider).
    /// When the scorecard's [`OwaspScorecard::llm_available`] is false, these
    /// rows are "Unknown" rather than clean -- the LLM-backed detection is not
    /// running, so absence of findings carries no signal. Deterministic rows
    /// keep their normal live state regardless of LLM availability.
    pub llm_dependent: bool,
    /// Drill-down records for contributing findings (tap-through to the
    /// concrete evidence behind this category).
    pub contributing_findings: Vec<OwaspContributingFinding>,
}

/// The composite OWASP scorecard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspScorecard {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Headline status derived directly from the attributed live findings:
    /// `critical` (an alertable CRITICAL finding is mapped to a category),
    /// `attention` (any other alertable finding), or `clean` (none).
    pub headline_status: String,
    /// True when at least one alertable CRITICAL finding is attributed to a
    /// category (hard-fail gate).
    pub hard_fail: bool,
    /// Total alertable findings attributed to any OWASP category.
    pub total_alertable: u32,
    /// Number of categories (across both lists) with at least one live finding.
    pub categories_with_findings: u32,
    /// True when a usable LLM provider is configured (EDAMAME Portal OR
    /// bring-your-own). When false, the behavioral-divergence engine cannot run,
    /// so every `llm_dependent` row is "Unknown" rather than clean. Deterministic
    /// rows are unaffected. This lets the UI honestly say "we can't assess these
    /// categories right now" instead of implying a clean result.
    pub llm_available: bool,
    /// Agentic rows (`ASI01..ASI10`), catalog order.
    pub agentic_rows: Vec<OwaspRow>,
    /// LLM rows (`LLM01..LLM10`), catalog order.
    pub llm_rows: Vec<OwaspRow>,
}

// ---------------------------------------------------------------------------
// Reference-token parsing
// ---------------------------------------------------------------------------

/// Extract canonical OWASP ids (`ASInn` / `LLMnn`) from a free-form reference
/// string such as `"OWASP-ASI01,OWASP-LLM02"` or
/// `"CVE-2024-1234; OWASP-LLM02, OWASP-ASI03"`. Deduplicated, order-preserving.
/// Pure and panic-free (uses `str::get` for boundary-safe slicing).
pub fn extract_owasp_ids(s: &str) -> Vec<String> {
    const NEEDLE: &str = "OWASP-";
    let mut ids: Vec<String> = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = s[search_from..].find(NEEDLE) {
        let start = search_from + rel + NEEDLE.len();
        // Candidate is exactly 5 chars: 3 letters + 2 digits.
        if let Some(cand) = s.get(start..start + 5) {
            let b = cand.as_bytes();
            let well_formed = b[0].is_ascii_uppercase()
                && b[1].is_ascii_uppercase()
                && b[2].is_ascii_uppercase()
                && b[3].is_ascii_digit()
                && b[4].is_ascii_digit();
            if well_formed && (cand.starts_with("ASI") || cand.starts_with("LLM")) {
                let norm = cand.to_string();
                if !ids.contains(&norm) {
                    ids.push(norm);
                }
            }
        }
        // Advance past this match to avoid re-matching the same needle.
        search_from = start;
        if search_from >= s.len() {
            break;
        }
    }
    ids
}

// ---------------------------------------------------------------------------
// Builder (deterministic, pure)
// ---------------------------------------------------------------------------

/// Merge the static catalog with the per-category live signal into a full
/// scorecard, deriving the headline status directly from the attributed
/// findings. Pure.
///
/// `llm_available` reflects whether a usable LLM provider is configured. It is
/// recorded on the scorecard and drives the UI's "Unknown" treatment of every
/// `llm_dependent` (behavioral-divergence-backed) row when false; it does not
/// change any finding count, severity, or the deterministic headline.
pub fn build_owasp_scorecard(
    inputs: &HashMap<String, OwaspRowInput>,
    llm_available: bool,
) -> OwaspScorecard {
    let mut agentic_rows: Vec<OwaspRow> = Vec::new();
    let mut llm_rows: Vec<OwaspRow> = Vec::new();
    let mut total_alertable = 0u32;
    let mut categories_with_findings = 0u32;
    let mut hard_fail = false;

    for (id, framework, title, grade, rationale, enforcement, enforcement_note) in OWASP_CATALOG {
        let input = inputs.get(*id);
        let (total, alertable, worst, findings) = match input {
            Some(i) => {
                let worst = if i.worst_severity.trim().is_empty() {
                    "NONE".to_string()
                } else {
                    i.worst_severity.trim().to_ascii_uppercase()
                };
                (
                    i.total_findings,
                    i.alertable_findings,
                    worst,
                    i.contributing_findings.clone(),
                )
            }
            None => (0, 0, "NONE".to_string(), Vec::new()),
        };
        let has_live = total > 0;
        if has_live {
            categories_with_findings += 1;
        }
        total_alertable += alertable;
        if findings
            .iter()
            .any(|f| f.alertable && f.severity.trim().eq_ignore_ascii_case("CRITICAL"))
        {
            hard_fail = true;
        }
        let row = OwaspRow {
            id: (*id).to_string(),
            framework: *framework,
            title: (*title).to_string(),
            grade: *grade,
            coverage_rationale: (*rationale).to_string(),
            enforcement: *enforcement,
            enforcement_note: (*enforcement_note).to_string(),
            reference_url: framework.reference_url().to_string(),
            total_findings: total,
            alertable_findings: alertable,
            worst_severity: worst,
            has_live_findings: has_live,
            llm_dependent: is_llm_dependent(id),
            contributing_findings: findings,
        };
        match framework {
            OwaspFramework::Agentic => agentic_rows.push(row),
            OwaspFramework::Llm => llm_rows.push(row),
        }
    }

    let headline_status = if hard_fail {
        "critical"
    } else if total_alertable > 0 {
        "attention"
    } else {
        "clean"
    }
    .to_string();

    OwaspScorecard {
        generated_at: chrono::Utc::now(),
        headline_status,
        hard_fail,
        total_alertable,
        categories_with_findings,
        llm_available,
        agentic_rows,
        llm_rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_twenty_rows_ten_each() {
        let agentic = OWASP_CATALOG
            .iter()
            .filter(|(_, f, _, _, _, _, _)| *f == OwaspFramework::Agentic)
            .count();
        let llm = OWASP_CATALOG
            .iter()
            .filter(|(_, f, _, _, _, _, _)| *f == OwaspFramework::Llm)
            .count();
        assert_eq!(agentic, 10);
        assert_eq!(llm, 10);
    }

    #[test]
    fn every_row_carries_a_nonempty_coverage_rationale() {
        let sc = build_owasp_scorecard(&HashMap::new(), true);
        for r in sc.agentic_rows.iter().chain(sc.llm_rows.iter()) {
            assert!(
                r.coverage_rationale.trim().len() > 20,
                "{} missing a coverage rationale",
                r.id
            );
        }
    }

    #[test]
    fn every_row_carries_an_enforcement_status_and_note() {
        let sc = build_owasp_scorecard(&HashMap::new(), true);
        for r in sc.agentic_rows.iter().chain(sc.llm_rows.iter()) {
            assert!(
                r.enforcement_note.trim().len() > 20,
                "{} missing an enforcement note",
                r.id
            );
        }
        // Spot-check the honest grading: no traffic firewall means sensitive
        // disclosure stays monitoring-only; the tool-call firewall hook makes
        // tool misuse partial; misinformation has nothing to enforce.
        let by_id = |id: &str| {
            sc.agentic_rows
                .iter()
                .chain(sc.llm_rows.iter())
                .find(|r| r.id == id)
                .unwrap()
                .enforcement
        };
        assert_eq!(by_id("LLM02"), EnforcementStatus::MonitoringOnly);
        assert_eq!(by_id("ASI02"), EnforcementStatus::Partial);
        assert_eq!(by_id("LLM09"), EnforcementStatus::NotApplicable);
        // Nothing is graded fully Enforced yet -- the firewall default is
        // recommend and the hook is wired on one agent only. If a primitive
        // graduates, update the catalog AND this expectation deliberately.
        assert!(sc
            .agentic_rows
            .iter()
            .chain(sc.llm_rows.iter())
            .all(|r| r.enforcement != EnforcementStatus::Enforced));
    }

    #[test]
    fn extract_handles_compact_and_messy_strings() {
        assert_eq!(
            extract_owasp_ids("OWASP-ASI01,OWASP-ASI10,OWASP-LLM01"),
            vec!["ASI01", "ASI10", "LLM01"]
        );
        assert_eq!(
            extract_owasp_ids("CVE-2024-1234; OWASP-LLM02, OWASP-ASI03"),
            vec!["LLM02", "ASI03"]
        );
        // Dedup + reject malformed tokens.
        assert_eq!(
            extract_owasp_ids("OWASP-ASI01 OWASP-ASI01 OWASP-XYZ9 OWASP-AS"),
            vec!["ASI01"]
        );
        assert!(extract_owasp_ids("no owasp tokens here").is_empty());
    }

    #[test]
    fn clean_scorecard_has_no_live_findings() {
        let inputs: HashMap<String, OwaspRowInput> = HashMap::new();
        let sc = build_owasp_scorecard(&inputs, true);
        assert_eq!(sc.agentic_rows.len(), 10);
        assert_eq!(sc.llm_rows.len(), 10);
        assert_eq!(sc.total_alertable, 0);
        assert_eq!(sc.categories_with_findings, 0);
        assert!(sc.agentic_rows.iter().all(|r| !r.has_live_findings));
        // Headline is clean with no live findings.
        assert_eq!(sc.headline_status, "clean");
        assert!(!sc.hard_fail);
    }

    #[test]
    fn live_findings_attribute_and_count_alertable() {
        let mut inputs: HashMap<String, OwaspRowInput> = HashMap::new();
        inputs.insert(
            "ASI05".to_string(),
            OwaspRowInput {
                total_findings: 2,
                alertable_findings: 1,
                worst_severity: "high".to_string(),
                contributing_findings: vec![
                    OwaspContributingFinding {
                        finding_key: "k2".to_string(),
                        title: "Tool misuse".to_string(),
                        severity: "HIGH".to_string(),
                        domain: "graph".to_string(),
                        alertable: true,
                    },
                    OwaspContributingFinding {
                        finding_key: "k1".to_string(),
                        title: "RCE path".to_string(),
                        severity: "LOW".to_string(),
                        domain: "recursion".to_string(),
                        alertable: false,
                    },
                ],
            },
        );
        inputs.insert(
            "LLM02".to_string(),
            OwaspRowInput {
                total_findings: 1,
                alertable_findings: 1,
                worst_severity: "CRITICAL".to_string(),
                contributing_findings: vec![OwaspContributingFinding {
                    finding_key: "k3".to_string(),
                    title: "Sensitive egress".to_string(),
                    severity: "CRITICAL".to_string(),
                    domain: "dataflow".to_string(),
                    alertable: true,
                }],
            },
        );
        let sc = build_owasp_scorecard(&inputs, true);
        assert_eq!(sc.total_alertable, 2);
        assert_eq!(sc.categories_with_findings, 2);
        // The LLM02 alertable CRITICAL egress trips the hard-fail headline.
        assert!(sc.hard_fail);
        assert_eq!(sc.headline_status, "critical");
        let asi05 = sc
            .agentic_rows
            .iter()
            .find(|r| r.id == "ASI05")
            .expect("ASI05 row present");
        assert!(asi05.has_live_findings);
        assert_eq!(asi05.total_findings, 2);
        assert_eq!(asi05.alertable_findings, 1);
        assert_eq!(asi05.worst_severity, "HIGH");
        // Drill-down records survive into the row, in input order.
        assert_eq!(asi05.contributing_findings.len(), 2);
        assert_eq!(asi05.contributing_findings[0].finding_key, "k2");
        assert_eq!(asi05.contributing_findings[0].title, "Tool misuse");
        assert!(asi05.contributing_findings[0].alertable);
        assert!(!asi05.contributing_findings[1].alertable);
        // Every row carries its framework's canonical drill-down reference.
        assert!(asi05.reference_url.starts_with("https://genai.owasp.org/"));
        let llm02 = sc
            .llm_rows
            .iter()
            .find(|r| r.id == "LLM02")
            .expect("LLM02 row present");
        assert_eq!(llm02.worst_severity, "CRITICAL");
        assert_eq!(llm02.contributing_findings.len(), 1);
        assert_eq!(llm02.contributing_findings[0].domain, "dataflow");
        assert_ne!(asi05.reference_url, llm02.reference_url);
    }

    #[test]
    fn every_row_carries_a_framework_reference_url() {
        let sc = build_owasp_scorecard(&HashMap::new(), true);
        for r in sc.agentic_rows.iter().chain(sc.llm_rows.iter()) {
            assert!(
                r.reference_url.starts_with("https://genai.owasp.org/"),
                "{} missing reference url",
                r.id
            );
        }
        // Frameworks resolve to distinct canonical pages.
        let agentic_url = sc.agentic_rows[0].reference_url.clone();
        let llm_url = sc.llm_rows[0].reference_url.clone();
        assert!(agentic_url.contains("agentic"));
        assert!(llm_url.contains("llm-top-10"));
    }

    #[test]
    fn headline_is_attention_when_alertable_but_not_critical() {
        let mut inputs: HashMap<String, OwaspRowInput> = HashMap::new();
        inputs.insert(
            "ASI05".to_string(),
            OwaspRowInput {
                total_findings: 1,
                alertable_findings: 1,
                worst_severity: "HIGH".to_string(),
                contributing_findings: vec![OwaspContributingFinding {
                    finding_key: "k1".to_string(),
                    title: "Tool misuse".to_string(),
                    severity: "HIGH".to_string(),
                    domain: "graph".to_string(),
                    alertable: true,
                }],
            },
        );
        let sc = build_owasp_scorecard(&inputs, true);
        assert!(!sc.hard_fail);
        assert_eq!(sc.headline_status, "attention");
    }

    #[test]
    fn headline_is_critical_only_when_the_critical_is_alertable() {
        // A CRITICAL finding that is NOT alertable must not trip hard_fail.
        let mut inputs: HashMap<String, OwaspRowInput> = HashMap::new();
        inputs.insert(
            "LLM02".to_string(),
            OwaspRowInput {
                total_findings: 1,
                alertable_findings: 0,
                worst_severity: "CRITICAL".to_string(),
                contributing_findings: vec![OwaspContributingFinding {
                    finding_key: "k1".to_string(),
                    title: "Sensitive egress".to_string(),
                    severity: "CRITICAL".to_string(),
                    domain: "dataflow".to_string(),
                    alertable: false,
                }],
            },
        );
        let sc = build_owasp_scorecard(&inputs, true);
        assert!(!sc.hard_fail);
        assert_eq!(sc.headline_status, "clean");
    }

    #[test]
    fn llm_dependent_rows_are_the_divergence_backed_categories() {
        let sc = build_owasp_scorecard(&HashMap::new(), true);
        let dependent: Vec<&str> = sc
            .agentic_rows
            .iter()
            .chain(sc.llm_rows.iter())
            .filter(|r| r.llm_dependent)
            .map(|r| r.id.as_str())
            .collect();
        // Exactly the two-plane behavioral-divergence categories.
        assert_eq!(dependent, vec!["ASI01", "ASI10", "LLM01"]);
        assert!(is_llm_dependent("ASI01"));
        assert!(!is_llm_dependent("ASI02"));
    }

    #[test]
    fn llm_available_flag_is_passed_through() {
        let with = build_owasp_scorecard(&HashMap::new(), true);
        assert!(with.llm_available);
        let without = build_owasp_scorecard(&HashMap::new(), false);
        assert!(!without.llm_available);
        // The flag does not change the deterministic headline or finding counts.
        assert_eq!(with.headline_status, without.headline_status);
        assert_eq!(with.total_alertable, without.total_alertable);
        assert_eq!(
            with.categories_with_findings,
            without.categories_with_findings
        );
    }
}
