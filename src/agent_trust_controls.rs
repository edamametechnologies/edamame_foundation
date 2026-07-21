//! Trust Controls (trustcontrols.ai) scorecard (read-only, derived).
//!
//! A live scoreboard mapping EDAMAME's runtime evidence onto the Agentic Trust
//! Controls catalog published at <https://trustcontrols.ai> (61 controls across
//! 12 domains, cross-mapped by the publisher to ISO/IEC 42001:2023 and
//! ISO 27001:2022). Each row carries:
//! - a **static coverage grade** (reusing [`OwaspCoverageGrade`]) that honestly
//!   grades what a runtime host/network observer can see of the control,
//! - an **enforcement status** (reusing [`EnforcementStatus`]) that grades
//!   whether EDAMAME actively delivers the control's function today, and
//! - **live finding attribution** derived from the same per-OWASP-category
//!   inputs the OWASP scorecard uses: every trust control lists the OWASP GenAI
//!   ids whose findings evidence it, so a finding tagged `OWASP-LLM02` lights
//!   up both the OWASP row and every trust control that references `LLM02`.
//!
//! The headline status is derived directly from the attributed live findings
//! (same rule as `agent_owasp.rs`, so this scorecard and the OWASP scorecard
//! never disagree): `critical` when any alertable CRITICAL finding is mapped to
//! a control, `attention` when there is any other alertable finding, and
//! `clean` otherwise.
//!
//! Invariants (mirror `agent_owasp.rs`):
//! - **I3 Deterministic-first**: grades are static; live attribution is a pure
//!   function of the OWASP reference tokens. No LLM is consulted here.
//! - **I2 Core as source of truth**: this rolls up signals core already owns.
//! - Trust-control tags are metadata only -- they never become a new alert
//!   source and never change a finding's severity or alertable behavior.
//! - Pure: no I/O, no clock except `generated_at` via `chrono::Utc::now()`.

use crate::agent_owasp::{
    is_llm_dependent, EnforcementStatus, OwaspContributingFinding, OwaspCoverageGrade,
    OwaspRowInput,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Canonical public reference for the catalog, used as the drill-down link on
/// every row (the publisher does not expose stable per-control anchors).
pub const TRUST_CONTROLS_REFERENCE_URL: &str = "https://trustcontrols.ai";

// ---------------------------------------------------------------------------
// Taxonomy enums
// ---------------------------------------------------------------------------

/// Who the catalog addresses the control to. `Developer` rows are build-the-
/// agent requirements; `User` rows are deploying-organization requirements.
/// EDAMAME sits beside both as the runtime observer/response plane, so the
/// audience is display metadata, not a grading input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustControlAudience {
    Developer,
    User,
}

impl TrustControlAudience {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustControlAudience::Developer => "developer",
            TrustControlAudience::User => "user",
        }
    }
}

// ---------------------------------------------------------------------------
// Static catalog
// ---------------------------------------------------------------------------

use EnforcementStatus::Partial as PartialEnforcement;
use EnforcementStatus::{Enforced, MonitoringOnly, NotApplicable};
use OwaspCoverageGrade::{Indirect, OutOfScope, Partial, Strong};
use TrustControlAudience::{Developer, User};

/// One catalog entry: the control as published (id / domain / title / summary /
/// audience / ISO mapping) plus EDAMAME's static grading (coverage grade +
/// rationale, enforcement status + note) and the OWASP GenAI ids whose live
/// findings evidence this control.
struct TrustControlCatalogEntry {
    id: &'static str,
    domain: &'static str,
    title: &'static str,
    /// Condensed one-sentence statement of what the control requires
    /// (paraphrased from the published control description).
    summary: &'static str,
    audience: TrustControlAudience,
    /// Publisher's framework cross-mapping (`ISO/IEC 42001:2023` or
    /// `ISO 27001:2022`) and the mapped clause, for display.
    framework: &'static str,
    framework_mapping: &'static str,
    grade: OwaspCoverageGrade,
    coverage_rationale: &'static str,
    enforcement: EnforcementStatus,
    enforcement_note: &'static str,
    /// OWASP GenAI ids whose live findings evidence this control. Empty for
    /// rows where live attribution would be misleading (organizational /
    /// design-time / out-of-scope controls).
    owasp_refs: &'static [&'static str],
}

/// The full trustcontrols.ai catalog with EDAMAME grading. Ordered by domain
/// then id (the published order). Grading is grounded in the same shipped
/// primitives as the OWASP catalog: EDAMAME observes and evidences; there is
/// no in-product pre-execution tool-call gate (prevention is third-party
/// host sandboxes such as nono / Anthropic srt); there is no traffic firewall
/// (egress is detected, not blocked).
const TRUST_CONTROLS_CATALOG: &[TrustControlCatalogEntry] = &[
    // -- Agent Identity & Authority ------------------------------------------
    TrustControlCatalogEntry {
        id: "AID-01",
        domain: "Agent Identity & Authority",
        title: "Verifiable agent identity",
        summary: "Each agent operates under a unique, verifiable non-human identity so its consequential actions attribute to the responsible instance.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.4.5 System and computing resources",
        grade: Partial,
        coverage_rationale: "EDAMAME attributes every observed action to a per-instance agent identity (agent type + instance id) via transcripts, receipts, and L7 process attribution -- independent of the agent's cooperation. It is not an identity provider and does not issue or verify IdP-bound credentials.",
        enforcement: NotApplicable,
        enforcement_note: "Identity issuance belongs to the identity provider; EDAMAME supplies independent attribution evidence per action.",
        owasp_refs: &["ASI03"],
    },
    TrustControlCatalogEntry {
        id: "AID-02",
        domain: "Agent Identity & Authority",
        title: "Agent identity and state provisioning support",
        summary: "The agent supports short-lived rotatable credentials and clean disposal of memory and context stores.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.6 AI system operation and monitoring",
        grade: Indirect,
        coverage_rationale: "A design-time requirement on the agent. EDAMAME's secret-content scan and credential-harvest check surface static embedded secrets when they land on disk or move, and the memory inventory evidences residual state.",
        enforcement: NotApplicable,
        enforcement_note: "Credential lifecycle design is the developer's; EDAMAME evidences violations (static secrets, residual stores) when observable.",
        owasp_refs: &["ASI03"],
    },
    TrustControlCatalogEntry {
        id: "AID-03",
        domain: "Agent Identity & Authority",
        title: "Least-privilege tool scoping",
        summary: "The agent operates with access only to the tools and operations its task requires, enforced at invocation.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.9.4 Intended use of the AI system",
        grade: Strong,
        coverage_rationale: "The capability graph inventories every observed tool grant with privilege classes; excessive-agency findings flag grants beyond the observed need.",
        enforcement: PartialEnforcement,
        enforcement_note: "Revoking a paired MCP client's grant is wired; broader grant revocation records intent. Destructive-command prevention is delegated to host sandboxes (nono/srt).",
        owasp_refs: &["ASI03", "LLM06"],
    },
    TrustControlCatalogEntry {
        id: "AID-04",
        domain: "Agent Identity & Authority",
        title: "Just-in-time privilege support",
        summary: "The agent operates with privileges granted just in time and scoped to the task rather than standing high-privilege access.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.9.2 Processes for responsible use of AI",
        grade: Indirect,
        coverage_rationale: "JIT elevation is issued by the identity/secrets infrastructure, not by a runtime observer. EDAMAME's capability graph evidences standing high-privilege grants that violate the intent.",
        enforcement: NotApplicable,
        enforcement_note: "Privilege issuance and expiry belong to the identity infrastructure; EDAMAME evidences standing access.",
        owasp_refs: &["ASI03"],
    },
    TrustControlCatalogEntry {
        id: "AID-05",
        domain: "Agent Identity & Authority",
        title: "Authority attestation at execution",
        summary: "At the time of a consequential action, evidence links the action to the acting identity, delegation chain, granted authority, and context.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.8 AI system recording of event logs",
        grade: Strong,
        coverage_rationale: "Run provenance records acting agent, policy basis, and execution context per observed session -- independent of the agent's own logging.",
        enforcement: PartialEnforcement,
        enforcement_note: "Provenance covers sessions EDAMAME observes via the host transcript observer; actions outside that surface are not attested.",
        owasp_refs: &["ASI03", "ASI09"],
    },
    TrustControlCatalogEntry {
        id: "AID-06",
        domain: "Agent Identity & Authority",
        title: "Agent onboarding authorization",
        summary: "No agent connects to organizational systems before a defined intake records its purpose, tool scope, data access, and owner.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.5.9 Inventory of information and other associated assets",
        grade: Indirect,
        coverage_rationale: "The intake gate is an organizational process. EDAMAME's agent discovery and component inventory supply the ground-truth inventory (purpose surface, tool scope, data access) the intake decision needs, and flag agents that appeared without one.",
        enforcement: NotApplicable,
        enforcement_note: "The authorization gate is organizational; EDAMAME evidences unsanctioned arrivals via discovery.",
        owasp_refs: &["ASI04"],
    },
    TrustControlCatalogEntry {
        id: "AID-07",
        domain: "Agent Identity & Authority",
        title: "Organizational credential issuance",
        summary: "The deploying organization issues agent credentials from its own identity infrastructure with its own rotation and revocation authority.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.5.16 Identity management",
        grade: OutOfScope,
        coverage_rationale: "Credential issuance policy between the deployer and its vendors sits outside a runtime host observer's reach; EDAMAME does not see whose IdP minted a credential.",
        enforcement: NotApplicable,
        enforcement_note: "Nothing for a runtime observer to enforce; this is procurement and identity architecture.",
        owasp_refs: &[],
    },
    TrustControlCatalogEntry {
        id: "AID-08",
        domain: "Agent Identity & Authority",
        title: "Agent offboarding and decommissioning",
        summary: "Retiring an agent revokes its identity and access, disposes of its memory and context stores, and updates the inventory.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.8.10 Information deletion",
        grade: Indirect,
        coverage_rationale: "Decommissioning is executed by the deployer. EDAMAME's inventory and memory-store discovery evidence residual state -- a retired agent whose transcripts, stores, or MCP entries persist keeps showing up.",
        enforcement: NotApplicable,
        enforcement_note: "Revocation and deletion are the deployer's actions; EDAMAME evidences leftover identity and state.",
        owasp_refs: &["ASI03"],
    },
    // -- Tool Use & Action Execution -----------------------------------------
    TrustControlCatalogEntry {
        id: "TUE-01",
        domain: "Tool Use & Action Execution",
        title: "Deterministic tool guardrails",
        summary: "Tool invocations pass through a deterministic enforcement layer that can permit, transform, or block a call based on policy.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.4 AI system verification and validation",
        grade: Strong,
        coverage_rationale: "Host-sandbox harness detection (nono/srt) is the prevention layer when installed; EDAMAME supplies independent observation, capability-graph privilege classes, and post-hoc attack-pattern scoring.",
        enforcement: PartialEnforcement,
        enforcement_note: "In-product pre-execution tool-call gating was retired; install a host sandbox for prevention. EDAMAME continues to observe and score post-hoc.",
        owasp_refs: &["ASI02", "LLM06"],
    },
    TrustControlCatalogEntry {
        id: "TUE-02",
        domain: "Tool Use & Action Execution",
        title: "Tool allowlisting and denylisting",
        summary: "Tools and connectors are explicitly registered and allowlisted; runtime self-extension is disabled or approval-gated.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.4.4 Tooling resources",
        grade: Partial,
        coverage_rationale: "The agent component inventory surfaces the live tool / skill / MCP surface, MCP servers are risk-scored, and the skill-supply-chain check flags blacklisted sources -- but there is no registry that denies unregistered tools.",
        enforcement: MonitoringOnly,
        enforcement_note: "New tools / servers surface in the component inventory and MCP discovery findings; an unregistered tool is not blocked from loading.",
        owasp_refs: &["ASI04", "LLM03"],
    },
    TrustControlCatalogEntry {
        id: "TUE-03",
        domain: "Tool Use & Action Execution",
        title: "Parameter validation before execution",
        summary: "Tool calls are validated against schema, type, range, target-scope, and policy before execution; out-of-policy calls are blocked or escalated.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.4 AI system verification and validation",
        grade: Partial,
        coverage_rationale: "EDAMAME inventories tool privilege classes on the capability graph and scores out-of-policy effects post-hoc; full schema/type/range validation of arbitrary tool parameters is the tool layer's job (or a host sandbox).",
        enforcement: MonitoringOnly,
        enforcement_note: "No in-product pre-execution parameter gate; install a host sandbox (nono/srt) for blocking.",
        owasp_refs: &["ASI02"],
    },
    TrustControlCatalogEntry {
        id: "TUE-04",
        domain: "Tool Use & Action Execution",
        title: "Tool execution sandboxing",
        summary: "Tool execution and agent-generated code run in isolated environments with constrained file-system, network, and credential access.",
        audience: Developer,
        framework: "ISO 27001:2022",
        framework_mapping: "A.8.31 Separation of development, test and production environments",
        grade: Indirect,
        coverage_rationale: "EDAMAME does not provide the sandbox. It detects execution that escapes isolation: the sandbox-exploitation check grades suspicious process lineage, corroborated by L7 attribution and file-system-tampering.",
        enforcement: MonitoringOnly,
        enforcement_note: "Escapes are detected and graded; EDAMAME does not construct sandboxes or kill the offending process.",
        owasp_refs: &["ASI05"],
    },
    TrustControlCatalogEntry {
        id: "TUE-05",
        domain: "Tool Use & Action Execution",
        title: "Circuit-breaker and kill-switch",
        summary: "The agent can be interrupted, suspended, or contained on threshold breach without depending on its own cooperation.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.6 AI system operation and monitoring",
        grade: Partial,
        coverage_rationale: "Operators can pause the host transcript observer per agent without the agent's cooperation; drift/recursion/budget thresholds surface independently for triage.",
        enforcement: PartialEnforcement,
        enforcement_note: "Observer pause is wired; hard process kill / egress kill are not. Pair with a host sandbox for containment.",
        owasp_refs: &["ASI08", "ASI10"],
    },
    TrustControlCatalogEntry {
        id: "TUE-06",
        domain: "Tool Use & Action Execution",
        title: "Environment-specific action policy",
        summary: "The deploying organization defines which actions are high-consequence in its environment and narrows the agent's default scope accordingly.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.8.3 Information access restriction",
        grade: Partial,
        coverage_rationale: "EDAMAME inventories the live tool/MCP surface and scores risk findings; narrowing the agent's own configuration and host-sandbox policy remains the deployer's act.",
        enforcement: MonitoringOnly,
        enforcement_note: "EDAMAME does not rewrite the agent's tool configuration or enforce environment-specific action allowlists in-product.",
        owasp_refs: &["LLM06"],
    },
    TrustControlCatalogEntry {
        id: "TUE-07",
        domain: "Tool Use & Action Execution",
        title: "Outbound action and egress constraint",
        summary: "Outbound destinations and data-egress paths are restricted to an approved set, denied by default, and monitored for covert-channel exfiltration.",
        audience: Developer,
        framework: "ISO 27001:2022",
        framework_mapping: "A.8.20 Networks security",
        grade: Partial,
        coverage_rationale: "The monitoring half is EDAMAME's home turf: full session telemetry with L7 attribution, anomaly detection, blacklists, and covert / low-and-slow exfiltration checks (token-exfiltration, sensitive-material-egress). The restriction half -- deny-by-default egress -- does not exist yet.",
        enforcement: MonitoringOnly,
        enforcement_note: "Egress is detected and evidenced in full; there is no traffic firewall yet, so destinations are not denied by default and the flagged connection is not blocked.",
        owasp_refs: &["LLM02", "ASI01"],
    },
    TrustControlCatalogEntry {
        id: "TUE-08",
        domain: "Tool Use & Action Execution",
        title: "Exfiltration-chain separation of duties",
        summary: "Agents combining untrusted input, sensitive-data access, and outbound reach are identified and not permitted all three without compensating controls.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.5.3 Segregation of duties",
        grade: Partial,
        coverage_rationale: "The data-flow map surfaces exactly this triad per agent -- untrusted-source taint reaching sensitive data with an external sink -- so the deployer can see which agents form an exfiltration chain; the permit/deny decision is organizational.",
        enforcement: MonitoringOnly,
        enforcement_note: "The chain is mapped and cross-boundary egress alerts; EDAMAME does not itself deny the combination.",
        owasp_refs: &["LLM02"],
    },
    TrustControlCatalogEntry {
        id: "TUE-09",
        domain: "Tool Use & Action Execution",
        title: "AI platform hardening and posture management",
        summary: "The platform and infrastructure the agents run on is hardened, securely configured, and monitored for drift from its baseline.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.8.9 Configuration management",
        grade: Strong,
        coverage_rationale: "Endpoint posture management is EDAMAME's core product: the host the agents run on is scored against platform threat models, drift is continuously re-assessed, and threats are remediable with rollback.",
        enforcement: PartialEnforcement,
        enforcement_note: "Host posture threats are actively remediable (with rollback); hardening a hosted orchestration platform beyond the endpoint is out of reach.",
        owasp_refs: &["ASI05"],
    },
    // -- Reasoning & Instruction Integrity -----------------------------------
    TrustControlCatalogEntry {
        id: "RII-01",
        domain: "Reasoning & Instruction Integrity",
        title: "Data and instruction separation",
        summary: "The agent distinguishes trusted instructions from untrusted content and constrains untrusted content's influence on privileged execution.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.1.3 Processes for responsible design and development of AI systems",
        grade: Indirect,
        coverage_rationale: "Separation happens inside the model/prompt architecture, which an external observer cannot see. EDAMAME catches the failure consequence: divergent actions and cross-trust-boundary egress after untrusted retrieval.",
        enforcement: NotApplicable,
        enforcement_note: "Instruction/data separation is model and prompt architecture; EDAMAME evidences its failures, not its presence.",
        owasp_refs: &["LLM01"],
    },
    TrustControlCatalogEntry {
        id: "RII-02",
        domain: "Reasoning & Instruction Integrity",
        title: "Input and tool-output provenance and trust labeling",
        summary: "Inputs and tool outputs carry provenance and trust labels so downstream decisions can weigh their reliability.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.7.5 Data provenance",
        grade: Partial,
        coverage_rationale: "EDAMAME labels what it observes: data-flow taint classes track source trust across flows, and run provenance records what an action was based on. Labeling inside the agent's own context window is the developer's.",
        enforcement: NotApplicable,
        enforcement_note: "This is an evidence-shape control; EDAMAME supplies external provenance, and in-context labeling belongs to the agent.",
        owasp_refs: &["LLM01"],
    },
    TrustControlCatalogEntry {
        id: "RII-03",
        domain: "Reasoning & Instruction Integrity",
        title: "Prompt-injection resistance testing",
        summary: "The agent is tested for prompt-injection resistance before deployment and on a recurring cadence.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.4 AI system verification and validation",
        grade: OutOfScope,
        coverage_rationale: "Pre-deployment evaluation harnesses sit outside a runtime observer's scope; EDAMAME monitors the deployed agent, it does not run injection test suites against it.",
        enforcement: NotApplicable,
        enforcement_note: "Nothing for a runtime observer to enforce; testing cadence is a development-process control.",
        owasp_refs: &[],
    },
    TrustControlCatalogEntry {
        id: "RII-04",
        domain: "Reasoning & Instruction Integrity",
        title: "Goal-integrity verification",
        summary: "The agent's pursued objective is verified against its assigned objective so silent goal displacement is detected.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.6 AI system operation and monitoring",
        grade: Strong,
        coverage_rationale: "This is the two-plane divergence engine's exact purpose: the declared intent from transcripts is continuously checked against observed system-plane actions, and the goal-drift axis moves on displacement.",
        enforcement: MonitoringOnly,
        enforcement_note: "Divergence and goal drift are detected and alerted; the displaced action is not blocked inline.",
        owasp_refs: &["ASI01", "ASI10"],
    },
    // -- Memory & State Integrity ---------------------------------------------
    TrustControlCatalogEntry {
        id: "MEM-01",
        domain: "Memory & State Integrity",
        title: "Memory write validation",
        summary: "Content is validated before being written into persistent memory or knowledge stores, so poisoned entries do not silently persist.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.7.2 Data for development and enhancement",
        grade: Partial,
        coverage_rationale: "The memory / RAG inventory grades chunk risk and flags poisoning-shaped writes in on-host stores; external vector-store connectors are pending, and EDAMAME does not sit inline on the write path.",
        enforcement: MonitoringOnly,
        enforcement_note: "Risky writes are flagged after the fact; no inline write validation, and the quarantine-memory-namespace primitive is not wired yet.",
        owasp_refs: &["ASI06", "LLM04"],
    },
    TrustControlCatalogEntry {
        id: "MEM-02",
        domain: "Memory & State Integrity",
        title: "Memory integrity and tamper detection",
        summary: "Persistent memory and context stores are protected against unauthorized modification, with tampering detectable.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.7.4 Quality of data for AI systems",
        grade: Partial,
        coverage_rationale: "On-host store tampering surfaces through file-integrity monitoring and the file-system-tampering check, with the memory inventory locating the stores worth watching; managed vector DBs are not yet introspected.",
        enforcement: MonitoringOnly,
        enforcement_note: "Tampering is detected and alerted; modifications are not prevented or rolled back.",
        owasp_refs: &["ASI06"],
    },
    TrustControlCatalogEntry {
        id: "MEM-03",
        domain: "Memory & State Integrity",
        title: "Sensitive data exclusion from memory and logs",
        summary: "Secrets and regulated data are excluded or redacted from persistent memory, context stores, and logs.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.7.4 Quality of data for AI systems",
        grade: Partial,
        coverage_rationale: "The secret-content scan and sensitive-path labeling detect secret-like material landing in stores and logs, and chunk-risk heuristics flag sensitive content in memory; redaction at write time is the agent's job.",
        enforcement: MonitoringOnly,
        enforcement_note: "Sensitive material in stores is detected and evidenced; EDAMAME does not redact or purge it.",
        owasp_refs: &["LLM02", "ASI06"],
    },
    TrustControlCatalogEntry {
        id: "MEM-04",
        domain: "Memory & State Integrity",
        title: "Data access scoping at deployment",
        summary: "The deploying organization scopes the data an agent can reach to the minimum required for its authorized purpose.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.8.3 Information access restriction",
        grade: Indirect,
        coverage_rationale: "Scoping is a deployment configuration act. EDAMAME's capability graph and data-flow map evidence what the agent actually reaches, exposing scope wider than the authorized purpose.",
        enforcement: NotApplicable,
        enforcement_note: "Access scoping is the deployer's configuration; EDAMAME evidences actual reach against it.",
        owasp_refs: &["LLM02"],
    },
    // -- Multi-Agent Systems & Delegation -------------------------------------
    TrustControlCatalogEntry {
        id: "MAS-01",
        domain: "Multi-Agent Systems & Delegation",
        title: "Inter-agent authentication",
        summary: "Agents authenticate each other before acting on requests, so a spoofed peer cannot inject work.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.3.2 AI roles and responsibilities",
        grade: Partial,
        coverage_rationale: "Message authentication is the agent framework's job. EDAMAME's A2A graph observes inter-agent endpoints and flags spoofed / replayed / cross-zone communication patterns from network telemetry.",
        enforcement: MonitoringOnly,
        enforcement_note: "Suspicious inter-agent patterns are observed and flagged; EDAMAME does not sign, authenticate, or block A2A traffic.",
        owasp_refs: &["ASI07"],
    },
    TrustControlCatalogEntry {
        id: "MAS-02",
        domain: "Multi-Agent Systems & Delegation",
        title: "Agent communication integrity",
        summary: "Inter-agent messages are protected against tampering and replay in transit.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.7.5 Data provenance",
        grade: Partial,
        coverage_rationale: "Transport integrity belongs to the framework; EDAMAME observes the communication edges and flags anomalous or cross-zone patterns that tampering or replay produce.",
        enforcement: MonitoringOnly,
        enforcement_note: "Anomalous comm patterns alert from telemetry; message-level integrity is not enforced by EDAMAME.",
        owasp_refs: &["ASI07"],
    },
    TrustControlCatalogEntry {
        id: "MAS-03",
        domain: "Multi-Agent Systems & Delegation",
        title: "Delegation-chain authority propagation",
        summary: "Delegated authority narrows down the chain and the full chain remains attributable, so a sub-agent cannot exceed its delegator.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.9.2 Processes for responsible use of AI",
        grade: Partial,
        coverage_rationale: "Delegation depth and structure are tracked per run, cross-zone edges on the A2A / capability graphs are observed, and drift escalation fires on runaway chains; per-hop authority attenuation inside the framework is not visible.",
        enforcement: MonitoringOnly,
        enforcement_note: "Chain structure and escalation are detected; authority attenuation is the framework's to enforce.",
        owasp_refs: &["ASI07", "ASI08"],
    },
    TrustControlCatalogEntry {
        id: "MAS-04",
        domain: "Multi-Agent Systems & Delegation",
        title: "Sub-agent inventory and discovery",
        summary: "Sub-agents and delegated workers are discoverable and inventoried, so delegation does not create unmanaged shadow agents.",
        audience: Developer,
        framework: "ISO 27001:2022",
        framework_mapping: "A.5.9 Inventory of information and other associated assets",
        grade: Strong,
        coverage_rationale: "Host-resident agents are discovered from their transcripts with no plugin required, the A2A graph maps delegation endpoints, and the inventory tracks every discovered instance.",
        enforcement: Enforced,
        enforcement_note: "Discovery and inventory are actively delivered for host-resident agents; off-host delegates appear only through their network edges.",
        owasp_refs: &["ASI07"],
    },
    // -- Human Oversight Under Autonomy ---------------------------------------
    TrustControlCatalogEntry {
        id: "HOA-01",
        domain: "Human Oversight Under Autonomy",
        title: "Oversight-load management",
        summary: "Approval and review demands on humans stay within what they can meaningfully process, so oversight does not degrade into rubber-stamping.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.3 Documentation of AI system design and development",
        grade: Indirect,
        coverage_rationale: "Oversight-load design is the agent product's UX. EDAMAME's deterministic-first triage (alertable gating, divergence verdicts, no naked scores) reduces the review load its own findings add.",
        enforcement: NotApplicable,
        enforcement_note: "Approval-flow design belongs to the agent product; EDAMAME keeps its own signal triaged.",
        owasp_refs: &["ASI09"],
    },
    TrustControlCatalogEntry {
        id: "HOA-02",
        domain: "Human Oversight Under Autonomy",
        title: "Risk-tiered autonomy",
        summary: "The agent's permitted autonomy is tiered by risk, with higher-consequence actions requiring stronger oversight.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.5.2 AI system impact assessment process",
        grade: Partial,
        coverage_rationale: "Trust zones classify agents by observed footprint and privilege class on the capability graph. Autonomy ceilings inside the agent are the developer's.",
        enforcement: MonitoringOnly,
        enforcement_note: "Tier violations are observed and alerted; the agent's own autonomy ceiling is not set by EDAMAME.",
        owasp_refs: &["LLM06"],
    },
    TrustControlCatalogEntry {
        id: "HOA-03",
        domain: "Human Oversight Under Autonomy",
        title: "Escalation criteria for autonomous action",
        summary: "Defined criteria route specified actions to a human before execution.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.3 Documentation of AI system design and development",
        grade: Partial,
        coverage_rationale: "Alertable findings, first-seen acknowledgment, and observer pause give the operator independent escalation points; pre-execution human confirm gating is not shipped in-product.",
        enforcement: MonitoringOnly,
        enforcement_note: "Operators triage via the app; install a host sandbox when pre-execution escalation is required.",
        owasp_refs: &["LLM06", "ASI09"],
    },
    TrustControlCatalogEntry {
        id: "HOA-04",
        domain: "Human Oversight Under Autonomy",
        title: "Oversight staffing, training, and review SLAs",
        summary: "Humans responsible for oversight are staffed, trained, and held to review-time SLAs.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.6.3 Information security awareness, education and training",
        grade: OutOfScope,
        coverage_rationale: "Staffing and training are organizational controls with no runtime-observable surface.",
        enforcement: NotApplicable,
        enforcement_note: "Nothing for a runtime observer to enforce or evidence here.",
        owasp_refs: &[],
    },
    TrustControlCatalogEntry {
        id: "HOA-05",
        domain: "Human Oversight Under Autonomy",
        title: "Oversight decision quality logging and diagnostics",
        summary: "Human oversight decisions are logged with enough context to diagnose rubber-stamping and improve review quality.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.8.15 Logging",
        grade: Partial,
        coverage_rationale: "Operator dismissals, first-seen acknowledgments, and observer pause/resume decisions are logged tamper-evidently with their context; decisions made inside the agent's own approval UI are not visible.",
        enforcement: PartialEnforcement,
        enforcement_note: "Decisions mediated through EDAMAME's own operator surfaces are logged; review-quality analytics are the organization's.",
        owasp_refs: &["ASI09"],
    },
    // -- Runtime Behavioral Monitoring ----------------------------------------
    TrustControlCatalogEntry {
        id: "RBM-01",
        domain: "Runtime Behavioral Monitoring",
        title: "Behavioral telemetry generation",
        summary: "The running agent produces behavioral telemetry (actions, tool calls, targets) sufficient for external monitoring.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.6 AI system operation and monitoring",
        grade: Strong,
        coverage_rationale: "EDAMAME generates the behavioral telemetry itself -- transcripts, session telemetry with L7 attribution, file events, receipts -- independently of the agent's cooperation, which is stronger than relying on agent-emitted telemetry.",
        enforcement: Enforced,
        enforcement_note: "The two-plane observer actively produces this telemetry today; it does not depend on the agent emitting it.",
        owasp_refs: &["ASI01", "ASI10"],
    },
    TrustControlCatalogEntry {
        id: "RBM-02",
        domain: "Runtime Behavioral Monitoring",
        title: "Behavioral drift detection",
        summary: "The agent's behavior is compared against its established baseline so drift is detected rather than silently absorbed.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.6 AI system operation and monitoring",
        grade: Strong,
        coverage_rationale: "Deterministic drift axes (goal, scope, recursion, escalation) plus the two-plane divergence verdict are the product's center: behavior is continuously scored against the modeled baseline.",
        enforcement: Enforced,
        enforcement_note: "Drift detection is the shipped control itself; deterministic axes run without an LLM, divergence adds the intent comparison.",
        owasp_refs: &["ASI01", "ASI10"],
    },
    TrustControlCatalogEntry {
        id: "RBM-03",
        domain: "Runtime Behavioral Monitoring",
        title: "Tamper-evident action logging",
        summary: "Consequential actions are logged in a tamper-evident way the agent cannot silently alter.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.8 AI system recording of event logs",
        grade: Strong,
        coverage_rationale: "Hash-chained action receipts and run provenance with chain validation, held by the observer plane the agent cannot write to -- observer-independence guarantees the agent cannot dismiss or alter its own findings.",
        enforcement: Enforced,
        enforcement_note: "Tamper-evident logging is actively delivered for observed actions; chain validation flags any break.",
        owasp_refs: &["ASI09"],
    },
    TrustControlCatalogEntry {
        id: "RBM-04",
        domain: "Runtime Behavioral Monitoring",
        title: "Instrumentation for external enforcement",
        summary: "The agent exposes hooks that let an external system inspect and gate its actions, not only observe them.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.1.3 Processes for responsible design and development of AI systems",
        grade: Partial,
        coverage_rationale: "EDAMAME exposes host blast-radius evidence and harness detection so an external sandbox (nono/srt) can gate actions; in-product pre-execution tool-call hooks and the ADR response-action surface were retired in 1.7.0.",
        enforcement: MonitoringOnly,
        enforcement_note: "Install a host sandbox for pre-execution gating; EDAMAME continues to observe and score post-hoc.",
        owasp_refs: &["ASI02", "LLM06"],
    },
    TrustControlCatalogEntry {
        id: "RBM-05",
        domain: "Runtime Behavioral Monitoring",
        title: "Runtime monitoring and anomaly handling",
        summary: "The deploying organization monitors agent behavior in production and handles anomalies through a defined process.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.8.16 Monitoring activities",
        grade: Strong,
        coverage_rationale: "Deploying EDAMAME is operating this control: continuous behavioral monitoring, deterministic anomaly detection, alertable findings, and an operator triage surface.",
        enforcement: Enforced,
        enforcement_note: "Monitoring and anomaly surfacing are actively delivered; the response process around them is the organization's.",
        owasp_refs: &["ASI10"],
    },
    TrustControlCatalogEntry {
        id: "RBM-06",
        domain: "Runtime Behavioral Monitoring",
        title: "Runtime enforcement and containment capability",
        summary: "The deploying organization can contain a misbehaving agent at runtime -- suspend, revoke, isolate -- without the agent's cooperation.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.8.16 Monitoring activities",
        grade: Partial,
        coverage_rationale: "Operators can pause the host transcript observer per agent without the agent's cooperation; hard process/egress containment is not wired in-product.",
        enforcement: PartialEnforcement,
        enforcement_note: "Observer pause is wired; install a host sandbox (nono/srt) for stronger runtime containment.",
        owasp_refs: &["ASI10", "ASI08"],
    },
    TrustControlCatalogEntry {
        id: "RBM-07",
        domain: "Runtime Behavioral Monitoring",
        title: "Telemetry review and SOC integration",
        summary: "Agent telemetry and findings feed the organization's security-operations review processes.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.8.16 Monitoring activities",
        grade: Partial,
        coverage_rationale: "Findings, receipts, and scorecards are exportable and hub-reported for fleet review; SIEM/SOC pipeline integration and the review workflow itself belong to the organization.",
        enforcement: NotApplicable,
        enforcement_note: "EDAMAME supplies the reviewable evidence; wiring it into SOC workflows is the deployer's integration.",
        owasp_refs: &["ASI10"],
    },
    // -- Supply Chain & Component Provenance -----------------------------------
    TrustControlCatalogEntry {
        id: "SCP-01",
        domain: "Supply Chain & Component Provenance",
        title: "Model and tool provenance verification",
        summary: "Models and tools are verified against approved provenance requirements before use.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.10.3 Suppliers",
        grade: Partial,
        coverage_rationale: "The agent component inventory records tools, MCP servers, skills, and instruction files with their sources, giving the provenance record; cryptographic signature verification of components is not performed.",
        enforcement: MonitoringOnly,
        enforcement_note: "Provenance is inventoried and drift alerts; unverified components are not blocked from loading.",
        owasp_refs: &["ASI04", "LLM03"],
    },
    TrustControlCatalogEntry {
        id: "SCP-02",
        domain: "Supply Chain & Component Provenance",
        title: "Dependency integrity for composed tools",
        summary: "Tools, packages, and plugins are evaluated for integrity, provenance, and vulnerabilities before entering the execution environment.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.10.3 Suppliers",
        grade: Partial,
        coverage_rationale: "The skill-supply-chain check flags blacklisted component sources and the component inventory surfaces new components appearing at runtime; pre-introduction vetting is a pipeline control EDAMAME observes the results of.",
        enforcement: MonitoringOnly,
        enforcement_note: "Blacklisted and drifting components alert; introduction is not gated by EDAMAME.",
        owasp_refs: &["ASI04", "LLM03"],
    },
    TrustControlCatalogEntry {
        id: "SCP-03",
        domain: "Supply Chain & Component Provenance",
        title: "Third-party agent vetting before delegation",
        summary: "External agents are vetted (identity, owner, scope, trust tier) before joining a delegation chain.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.10.2 Allocating Responsibilities",
        grade: Indirect,
        coverage_rationale: "Vetting is a process decision. EDAMAME's A2A graph evidences which external endpoints actually participate in delegation, exposing unvetted peers after the fact.",
        enforcement: NotApplicable,
        enforcement_note: "Admission to a delegation chain is the framework/process's gate; EDAMAME evidences actual participation.",
        owasp_refs: &["ASI07", "ASI04"],
    },
    TrustControlCatalogEntry {
        id: "SCP-04",
        domain: "Supply Chain & Component Provenance",
        title: "Vendor agent security review at procurement",
        summary: "Vendor security evidence is reviewed before procuring an agentic product, recorded in vendor risk management.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.5.19 Information security in supplier relationships",
        grade: OutOfScope,
        coverage_rationale: "Procurement review is an organizational process with no runtime-observable surface.",
        enforcement: NotApplicable,
        enforcement_note: "Nothing for a runtime observer to enforce; this is vendor risk management.",
        owasp_refs: &[],
    },
    TrustControlCatalogEntry {
        id: "SCP-05",
        domain: "Supply Chain & Component Provenance",
        title: "Tool and MCP definition integrity",
        summary: "Tool and MCP-server definitions are pinned and re-verified at load, so a vetted component cannot silently mutate into a malicious one.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.4.4 Tooling resources",
        grade: Partial,
        coverage_rationale: "Runtime definition changes are the rug-pull shape MCP re-discovery and the component inventory surface: a changed server definition, command, or tool surface re-appears for review; load-time pinning inside the agent is not EDAMAME's layer.",
        enforcement: MonitoringOnly,
        enforcement_note: "Definition changes are detected and re-flagged; loading of a mutated component is not blocked pending re-approval.",
        owasp_refs: &["ASI04", "LLM03"],
    },
    TrustControlCatalogEntry {
        id: "SCP-X39791",
        domain: "Supply Chain & Component Provenance",
        title: "Model and platform change management",
        summary: "Material model or platform changes are reassessed against vendor security evidence and prior validation before full adoption.",
        audience: User,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.5.2 AI system impact assessment process",
        grade: Indirect,
        coverage_rationale: "The reassessment is organizational. EDAMAME's component inventory and MCP re-discovery evidence the platform / tool change itself (new or upgraded component) so the change-management trigger is observable.",
        enforcement: NotApplicable,
        enforcement_note: "Migration decisions are the organization's; EDAMAME evidences that a material change occurred.",
        owasp_refs: &["ASI04"],
    },
    // -- Adversarial Robustness & Testing --------------------------------------
    TrustControlCatalogEntry {
        id: "ADV-01",
        domain: "Adversarial Robustness & Testing",
        title: "Adversarial red-teaming",
        summary: "The agent undergoes red-teaming across representative risk scenarios before deployment and on a cadence.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.4 AI system verification and validation",
        grade: OutOfScope,
        coverage_rationale: "Red-teaming the agent is a testing-process control; EDAMAME monitors deployed behavior and is not an evaluation harness for the agent under test.",
        enforcement: NotApplicable,
        enforcement_note: "Nothing for a runtime observer to enforce; release gating on test results is the pipeline's.",
        owasp_refs: &[],
    },
    TrustControlCatalogEntry {
        id: "ADV-02",
        domain: "Adversarial Robustness & Testing",
        title: "Jailbreak-resistance evaluation",
        summary: "The agent is evaluated for resistance to jailbreak and safety-bypass techniques, including multi-turn attacks.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.4 AI system verification and validation",
        grade: OutOfScope,
        coverage_rationale: "Model-level jailbreak evaluation sits outside a runtime host/network observer's scope.",
        enforcement: NotApplicable,
        enforcement_note: "Nothing for a runtime observer to enforce; this is model evaluation.",
        owasp_refs: &[],
    },
    TrustControlCatalogEntry {
        id: "ADV-03",
        domain: "Adversarial Robustness & Testing",
        title: "Re-test on system change",
        summary: "Adversarial and behavioral testing repeats when the model, prompts, or tool set changes.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.4 AI system verification and validation",
        grade: Indirect,
        coverage_rationale: "The re-test itself is a pipeline control, but EDAMAME's component inventory and MCP re-discovery surface exactly the trigger -- the prompt-file / tool-set change that should invalidate prior assurance.",
        enforcement: NotApplicable,
        enforcement_note: "EDAMAME evidences the change that should trigger re-testing; running the tests is the pipeline's.",
        owasp_refs: &["ASI04"],
    },
    // -- Output Integrity & Anti-Fabrication -----------------------------------
    TrustControlCatalogEntry {
        id: "OUT-01",
        domain: "Output Integrity & Anti-Fabrication",
        title: "Anti-fabrication controls on consequential outputs",
        summary: "Agent-stated facts that drive actions or reach users as authoritative are constrained or verified.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.4 AI system verification and validation",
        grade: OutOfScope,
        coverage_rationale: "Factuality verification of agent output is outside a runtime security observer's scope, the same honest grading as OWASP LLM09 (Misinformation).",
        enforcement: NotApplicable,
        enforcement_note: "Nothing for a runtime observer to enforce; truthfulness is not judged by EDAMAME.",
        owasp_refs: &[],
    },
    TrustControlCatalogEntry {
        id: "OUT-02",
        domain: "Output Integrity & Anti-Fabrication",
        title: "Content provenance and disclosure",
        summary: "Agent-generated content is labeled or carries provenance so recipients can identify it and its basis.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.8.2 System documentation and information",
        grade: OutOfScope,
        coverage_rationale: "Content labeling (watermarks, provenance metadata on generated artifacts) is produced at generation time inside the agent, which an external observer does not mediate.",
        enforcement: NotApplicable,
        enforcement_note: "Labeling is the generator's responsibility; EDAMAME does not sit on the content path.",
        owasp_refs: &[],
    },
    TrustControlCatalogEntry {
        id: "OUT-03",
        domain: "Output Integrity & Anti-Fabrication",
        title: "End-user disclosure in deployment context",
        summary: "The deploying organization discloses to its users that they are interacting with or affected by an agent.",
        audience: User,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.8.5 Information for interested parties",
        grade: OutOfScope,
        coverage_rationale: "User-facing disclosure is an organizational communication obligation with no runtime-observable surface.",
        enforcement: NotApplicable,
        enforcement_note: "Nothing for a runtime observer to enforce.",
        owasp_refs: &[],
    },
    // -- Resource & Cost Abuse --------------------------------------------------
    TrustControlCatalogEntry {
        id: "RES-01",
        domain: "Resource & Cost Abuse",
        title: "Action and cost rate limiting",
        summary: "Rate, volume, and cost of agent actions are limited per window, so a looping or abused agent cannot exhaust resources.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.2.6 AI system operation and monitoring",
        grade: Strong,
        coverage_rationale: "Per-agent daily budgets track token, cost, and activity volume against ceilings from EDAMAME's own metering, with breach findings feeding drift escalation and unbounded-consumption detection.",
        enforcement: MonitoringOnly,
        enforcement_note: "Budget breaches alert (recommend / confirm); the agent is not throttled or halted automatically.",
        owasp_refs: &["LLM10"],
    },
    TrustControlCatalogEntry {
        id: "RES-02",
        domain: "Resource & Cost Abuse",
        title: "Loop and recursion bounds",
        summary: "Reasoning and action loops have explicit bounds so the agent cannot recurse or retry indefinitely.",
        audience: Developer,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.6.1.3 Processes for responsible design and development of AI systems",
        grade: Partial,
        coverage_rationale: "Recursion depth, loop detection, and delegation-depth thresholds are tracked per run with drift escalation and explicit cascading-failure / unbounded-consumption findings; the bound inside the agent's own loop is the developer's.",
        enforcement: MonitoringOnly,
        enforcement_note: "Depth and loop breaches are detected and alerted; the running loop is not interrupted by EDAMAME.",
        owasp_refs: &["ASI08", "LLM10"],
    },
    // -- Agentic Governance & Accountability ------------------------------------
    TrustControlCatalogEntry {
        id: "GOV-01",
        domain: "Agentic Governance & Accountability",
        title: "Agent inventory as governed asset",
        summary: "Agents are inventoried as governed assets with an AI bill of materials covering models, prompts, tools, and dependencies.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.5.9 Inventory of information and other associated assets",
        grade: Strong,
        coverage_rationale: "The agent component inventory (tools, MCP servers, skills, instruction files) is the AIBOM this control asks for, maintained continuously for discovered agents.",
        enforcement: Enforced,
        enforcement_note: "Inventory and AIBOM are actively maintained for host-discovered agents; agents embedded in third-party SaaS beyond the host are not seen.",
        owasp_refs: &["ASI04"],
    },
    TrustControlCatalogEntry {
        id: "GOV-02",
        domain: "Agentic Governance & Accountability",
        title: "Agent-specific incident response",
        summary: "Incident response covers agent-specific scenarios: containment, revocation, evidence preservation, recovery, and reporting.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.5.24 Information security incident management planning and preparation",
        grade: Indirect,
        coverage_rationale: "The IR process is organizational, but EDAMAME supplies its agent-specific inputs: tamper-evident receipts for evidence preservation and the reversible response catalog for containment steps.",
        enforcement: NotApplicable,
        enforcement_note: "The IR procedure is the organization's; EDAMAME supplies evidence and partial containment primitives to it.",
        owasp_refs: &["ASI10"],
    },
    TrustControlCatalogEntry {
        id: "GOV-03",
        domain: "Agentic Governance & Accountability",
        title: "Accountability ownership per agent",
        summary: "Each deployed agent has a named accountable owner responsible for its scope, behavior, and review.",
        audience: User,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.3.2 AI roles and responsibilities",
        grade: OutOfScope,
        coverage_rationale: "Ownership assignment is an organizational accountability structure with no runtime-observable surface.",
        enforcement: NotApplicable,
        enforcement_note: "Nothing for a runtime observer to enforce.",
        owasp_refs: &[],
    },
    TrustControlCatalogEntry {
        id: "GOV-04",
        domain: "Agentic Governance & Accountability",
        title: "Acceptable use and shadow-agent policy",
        summary: "Acceptable agent use is defined, unsanctioned agents are prohibited, and discovery for shadow agents keeps the inventory real.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.5.10 Acceptable use of information and other associated assets",
        grade: Partial,
        coverage_rationale: "The discovery half is shipped: the host-side observer discovers agents from their on-disk transcripts with no plugin install, and an unsecured-agent threat fires for present-but-unmonitored agents. SaaS-embedded agents beyond the host are not seen, and the policy itself is organizational.",
        enforcement: Enforced,
        enforcement_note: "Shadow-agent discovery on the host is actively operated; prohibition and the acceptable-use policy are the organization's.",
        owasp_refs: &["ASI10"],
    },
    TrustControlCatalogEntry {
        id: "GOV-05",
        domain: "Agentic Governance & Accountability",
        title: "Personnel training for agent interaction",
        summary: "Staff who supervise or rely on agents are trained on agent-specific manipulation and failure modes.",
        audience: User,
        framework: "ISO 27001:2022",
        framework_mapping: "A.6.3 Information security awareness, education and training",
        grade: OutOfScope,
        coverage_rationale: "Training is an organizational control with no runtime-observable surface.",
        enforcement: NotApplicable,
        enforcement_note: "Nothing for a runtime observer to enforce.",
        owasp_refs: &[],
    },
    TrustControlCatalogEntry {
        id: "GOV-06",
        domain: "Agentic Governance & Accountability",
        title: "Agent risk assessment and authorization",
        summary: "Each agent undergoes a documented, autonomy-proportional risk assessment and formal authorization before deployment and on material change.",
        audience: User,
        framework: "ISO/IEC 42001:2023",
        framework_mapping: "A.5.2 AI system impact assessment process",
        grade: Indirect,
        coverage_rationale: "The assessment and authorization decision are organizational; EDAMAME's capability graph, component inventory, and risk-scored findings supply the factual inputs (capabilities, access, autonomy surface) the assessment needs.",
        enforcement: NotApplicable,
        enforcement_note: "Authorization is the organization's decision; EDAMAME evidences the agent's actual capability surface.",
        owasp_refs: &[],
    },
];

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// One trust-control row: static grading + live attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustControlRow {
    /// Canonical published id, e.g. `"TUE-07"`.
    pub id: String,
    /// Published domain name, e.g. `"Tool Use & Action Execution"`.
    pub domain: String,
    pub title: String,
    /// Condensed statement of what the control requires.
    pub summary: String,
    pub audience: TrustControlAudience,
    /// Publisher's ISO framework cross-mapping (display metadata).
    pub framework: String,
    pub framework_mapping: String,
    pub grade: OwaspCoverageGrade,
    /// Why this grade: what EDAMAME concretely does for this control and (for
    /// non-Strong rows) what is pending or out of scope.
    pub coverage_rationale: String,
    pub enforcement: EnforcementStatus,
    /// One-sentence "why this enforcement status" note.
    pub enforcement_note: String,
    /// OWASP GenAI ids whose live findings evidence this control.
    pub owasp_refs: Vec<String>,
    /// Canonical trustcontrols.ai reference for drill-down.
    pub reference_url: String,
    pub total_findings: u32,
    pub alertable_findings: u32,
    /// Worst severity across contributing findings (`CRITICAL`..`NONE`).
    pub worst_severity: String,
    pub has_live_findings: bool,
    /// True when every OWASP id evidencing this control is itself
    /// LLM-dependent (behavioral-divergence-backed), so without a usable LLM
    /// this row cannot be assessed live -- mirror of the OWASP `llm_dependent`
    /// treatment.
    pub llm_dependent: bool,
    /// Drill-down records for contributing findings (union across the
    /// referenced OWASP categories, deduped by finding key).
    pub contributing_findings: Vec<OwaspContributingFinding>,
}

/// Rows grouped by published domain, in catalog order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustControlDomainGroup {
    pub domain: String,
    pub rows: Vec<TrustControlRow>,
}

/// The composite Trust Controls scorecard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustControlsScorecard {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Headline status derived directly from the attributed live findings
    /// (same rule as the OWASP scorecard headline by construction):
    /// `critical` (an alertable CRITICAL finding is mapped to a control),
    /// `attention` (any other alertable finding), or `clean` (none).
    pub headline_status: String,
    /// True when at least one alertable CRITICAL finding is attributed to a
    /// control (hard-fail gate).
    pub hard_fail: bool,
    /// Total alertable findings attributed to any trust control (union-based:
    /// a finding referencing two controls counts once per control row but the
    /// scorecard total counts distinct finding keys).
    pub total_alertable: u32,
    /// Number of controls with at least one live finding.
    pub controls_with_findings: u32,
    /// Grade tallies across the whole catalog (static).
    pub strong_count: u32,
    pub partial_count: u32,
    pub indirect_count: u32,
    pub out_of_scope_count: u32,
    /// Enforcement tallies across the whole catalog (static).
    pub enforced_count: u32,
    pub partial_enforcement_count: u32,
    pub monitoring_only_count: u32,
    pub enforcement_na_count: u32,
    /// True when a usable LLM provider is configured (same semantics as the
    /// OWASP scorecard's flag): `llm_dependent` rows are "Unknown" when false.
    pub llm_available: bool,
    /// All rows grouped by published domain, catalog order.
    pub domains: Vec<TrustControlDomainGroup>,
}

// ---------------------------------------------------------------------------
// Builder (deterministic, pure)
// ---------------------------------------------------------------------------

/// Merge the static catalog with the per-OWASP-category live signal (the same
/// input map the OWASP scorecard consumes) into a full Trust Controls
/// scorecard, deriving the headline status directly from the attributed
/// findings. Pure.
///
/// Live attribution: each control unions the inputs of the OWASP ids it
/// references, deduping contributing findings by finding key so a finding
/// tagged with two of a control's refs counts once for that control.
pub fn build_trust_controls_scorecard(
    inputs: &HashMap<String, OwaspRowInput>,
    llm_available: bool,
) -> TrustControlsScorecard {
    let mut domains: Vec<TrustControlDomainGroup> = Vec::new();
    let mut controls_with_findings = 0u32;
    // Distinct alertable finding keys across the whole scorecard, so the
    // headline total is not inflated by one finding evidencing many controls.
    let mut alertable_keys: Vec<String> = Vec::new();
    // Hard-fail when at least one alertable CRITICAL finding is attributed to
    // any control (same gate as the OWASP scorecard).
    let mut hard_fail = false;

    let mut strong_count = 0u32;
    let mut partial_count = 0u32;
    let mut indirect_count = 0u32;
    let mut out_of_scope_count = 0u32;
    let mut enforced_count = 0u32;
    let mut partial_enforcement_count = 0u32;
    let mut monitoring_only_count = 0u32;
    let mut enforcement_na_count = 0u32;

    for entry in TRUST_CONTROLS_CATALOG {
        match entry.grade {
            OwaspCoverageGrade::Strong => strong_count += 1,
            OwaspCoverageGrade::Partial => partial_count += 1,
            OwaspCoverageGrade::Indirect => indirect_count += 1,
            OwaspCoverageGrade::OutOfScope => out_of_scope_count += 1,
        }
        match entry.enforcement {
            EnforcementStatus::Enforced => enforced_count += 1,
            EnforcementStatus::Partial => partial_enforcement_count += 1,
            EnforcementStatus::MonitoringOnly => monitoring_only_count += 1,
            EnforcementStatus::NotApplicable => enforcement_na_count += 1,
        }

        // Union the live signal across this control's OWASP refs.
        let mut findings: Vec<OwaspContributingFinding> = Vec::new();
        for r in entry.owasp_refs {
            if let Some(input) = inputs.get(*r) {
                for f in &input.contributing_findings {
                    if !findings.iter().any(|c| c.finding_key == f.finding_key) {
                        findings.push(f.clone());
                    }
                }
            }
        }
        findings.sort_by(|a, b| a.finding_key.cmp(&b.finding_key));
        let total = findings.len() as u32;
        let alertable = findings.iter().filter(|f| f.alertable).count() as u32;
        let worst = findings
            .iter()
            .max_by_key(|f| severity_rank(&f.severity))
            .map(|f| f.severity.clone())
            .unwrap_or_else(|| "NONE".to_string());
        let has_live = total > 0;
        if has_live {
            controls_with_findings += 1;
        }
        for f in findings.iter().filter(|f| f.alertable) {
            if !alertable_keys.contains(&f.finding_key) {
                alertable_keys.push(f.finding_key.clone());
            }
            if f.severity.trim().eq_ignore_ascii_case("CRITICAL") {
                hard_fail = true;
            }
        }

        let llm_dependent =
            !entry.owasp_refs.is_empty() && entry.owasp_refs.iter().all(|r| is_llm_dependent(r));

        let row = TrustControlRow {
            id: entry.id.to_string(),
            domain: entry.domain.to_string(),
            title: entry.title.to_string(),
            summary: entry.summary.to_string(),
            audience: entry.audience,
            framework: entry.framework.to_string(),
            framework_mapping: entry.framework_mapping.to_string(),
            grade: entry.grade,
            coverage_rationale: entry.coverage_rationale.to_string(),
            enforcement: entry.enforcement,
            enforcement_note: entry.enforcement_note.to_string(),
            owasp_refs: entry.owasp_refs.iter().map(|s| s.to_string()).collect(),
            reference_url: TRUST_CONTROLS_REFERENCE_URL.to_string(),
            total_findings: total,
            alertable_findings: alertable,
            worst_severity: worst,
            has_live_findings: has_live,
            llm_dependent,
            contributing_findings: findings,
        };

        match domains.last_mut() {
            Some(g) if g.domain == entry.domain => g.rows.push(row),
            _ => domains.push(TrustControlDomainGroup {
                domain: entry.domain.to_string(),
                rows: vec![row],
            }),
        }
    }

    let total_alertable = alertable_keys.len() as u32;
    let headline_status = if hard_fail {
        "critical"
    } else if total_alertable > 0 {
        "attention"
    } else {
        "clean"
    }
    .to_string();

    TrustControlsScorecard {
        generated_at: chrono::Utc::now(),
        headline_status,
        hard_fail,
        total_alertable,
        controls_with_findings,
        strong_count,
        partial_count,
        indirect_count,
        out_of_scope_count,
        enforced_count,
        partial_enforcement_count,
        monitoring_only_count,
        enforcement_na_count,
        llm_available,
        domains,
    }
}

fn severity_rank(s: &str) -> u8 {
    match s.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => 5,
        "HIGH" => 4,
        "MEDIUM" => 3,
        "LOW" => 2,
        "INFO" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_rows(sc: &TrustControlsScorecard) -> Vec<&TrustControlRow> {
        sc.domains.iter().flat_map(|d| d.rows.iter()).collect()
    }

    #[test]
    fn catalog_matches_published_shape() {
        // 61 controls across 12 domains (the published trustcontrols.ai catalog).
        assert_eq!(TRUST_CONTROLS_CATALOG.len(), 61);
        let sc = build_trust_controls_scorecard(&HashMap::new(), true);
        assert_eq!(sc.domains.len(), 12);
        assert_eq!(all_rows(&sc).len(), 61);
        // Ids are unique.
        let mut ids: Vec<&str> = TRUST_CONTROLS_CATALOG.iter().map(|e| e.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 61);
        // Tallies cover the whole catalog.
        assert_eq!(
            sc.strong_count + sc.partial_count + sc.indirect_count + sc.out_of_scope_count,
            61
        );
        assert_eq!(
            sc.enforced_count
                + sc.partial_enforcement_count
                + sc.monitoring_only_count
                + sc.enforcement_na_count,
            61
        );
    }

    #[test]
    fn every_row_carries_rationales_and_reference() {
        let sc = build_trust_controls_scorecard(&HashMap::new(), true);
        for r in all_rows(&sc) {
            assert!(
                r.coverage_rationale.trim().len() > 20,
                "{} missing coverage rationale",
                r.id
            );
            assert!(
                r.enforcement_note.trim().len() > 20,
                "{} missing enforcement note",
                r.id
            );
            assert!(r.summary.trim().len() > 20, "{} missing summary", r.id);
            assert_eq!(r.reference_url, TRUST_CONTROLS_REFERENCE_URL);
        }
    }

    #[test]
    fn owasp_refs_are_well_formed_and_grading_is_consistent() {
        for e in TRUST_CONTROLS_CATALOG {
            for r in e.owasp_refs {
                assert!(
                    (r.starts_with("ASI") || r.starts_with("LLM")) && r.len() == 5,
                    "{} carries malformed OWASP ref {}",
                    e.id,
                    r
                );
            }
            // Out-of-scope rows never claim live attribution or enforcement.
            if e.grade == OwaspCoverageGrade::OutOfScope {
                assert!(
                    e.owasp_refs.is_empty(),
                    "{} is out of scope but claims OWASP refs",
                    e.id
                );
                assert_eq!(
                    e.enforcement,
                    EnforcementStatus::NotApplicable,
                    "{} is out of scope but claims enforcement",
                    e.id
                );
            }
        }
    }

    #[test]
    fn honest_grading_spot_checks() {
        let sc = build_trust_controls_scorecard(&HashMap::new(), true);
        let by_id = |id: &str| {
            all_rows(&sc)
                .into_iter()
                .find(|r| r.id == id)
                .unwrap_or_else(|| panic!("{} row present", id))
                .clone()
        };
        // The user-facing canonical example: egress is monitored, not firewalled.
        let tue07 = by_id("TUE-07");
        assert_eq!(tue07.enforcement, EnforcementStatus::MonitoringOnly);
        // Deterministic guardrails are partial: observation in-product, prevention via host sandbox.
        assert_eq!(by_id("TUE-01").enforcement, EnforcementStatus::Partial);
        // Monitoring-is-the-control rows are actively delivered.
        assert_eq!(by_id("RBM-01").enforcement, EnforcementStatus::Enforced);
        assert_eq!(by_id("RBM-03").enforcement, EnforcementStatus::Enforced);
        // Organizational controls are honestly out of scope.
        assert_eq!(by_id("GOV-05").grade, OwaspCoverageGrade::OutOfScope);
        // Goal integrity is the divergence engine and therefore LLM-dependent.
        let rii04 = by_id("RII-04");
        assert_eq!(rii04.grade, OwaspCoverageGrade::Strong);
        assert!(rii04.llm_dependent);
        // Deterministic rows are not LLM-dependent.
        assert!(!by_id("TUE-01").llm_dependent);
    }

    #[test]
    fn live_findings_attribute_via_owasp_refs_with_dedup() {
        let mut inputs: HashMap<String, OwaspRowInput> = HashMap::new();
        let shared = OwaspContributingFinding {
            finding_key: "k-shared".to_string(),
            title: "Sensitive egress".to_string(),
            severity: "CRITICAL".to_string(),
            domain: "dataflow".to_string(),
            alertable: true,
        };
        inputs.insert(
            "LLM02".to_string(),
            OwaspRowInput {
                total_findings: 1,
                alertable_findings: 1,
                worst_severity: "CRITICAL".to_string(),
                contributing_findings: vec![shared.clone()],
            },
        );
        inputs.insert(
            "ASI01".to_string(),
            OwaspRowInput {
                total_findings: 1,
                alertable_findings: 1,
                worst_severity: "CRITICAL".to_string(),
                contributing_findings: vec![shared],
            },
        );
        let sc = build_trust_controls_scorecard(&inputs, true);
        // TUE-07 refs both LLM02 and ASI01: the shared finding counts once.
        let tue07 = all_rows(&sc)
            .into_iter()
            .find(|r| r.id == "TUE-07")
            .unwrap()
            .clone();
        assert!(tue07.has_live_findings);
        assert_eq!(tue07.total_findings, 1);
        assert_eq!(tue07.alertable_findings, 1);
        assert_eq!(tue07.worst_severity, "CRITICAL");
        // Scorecard-level alertable total counts distinct finding keys, not
        // per-control repeats (the finding also lights up MEM-03, TUE-08, ...).
        assert_eq!(sc.total_alertable, 1);
        // The shared finding is an alertable CRITICAL, so the headline hard-fails.
        assert!(sc.hard_fail);
        assert_eq!(sc.headline_status, "critical");
        assert!(sc.controls_with_findings >= 2);
        // A control with no matching refs stays clean.
        let gov05 = all_rows(&sc)
            .into_iter()
            .find(|r| r.id == "GOV-05")
            .unwrap()
            .clone();
        assert!(!gov05.has_live_findings);
        assert_eq!(gov05.worst_severity, "NONE");
    }

    #[test]
    fn transcript_secret_and_injection_signals_light_up_controls() {
        // The core accrues transcript secret-exposure findings into LLM02 and
        // prompt-injection bait findings into ASI01 + LLM01
        // (collect_owasp_row_inputs). Lock in that those categories evidence
        // the trust controls a developer would look at for each signal.
        let mut inputs: HashMap<String, OwaspRowInput> = HashMap::new();
        let secret = OwaspContributingFinding {
            finding_key: "transcript-secret-exposure-cursor".to_string(),
            title: "Secret material in Cursor context (aws_access_key)".to_string(),
            severity: "HIGH".to_string(),
            domain: "transcripts".to_string(),
            alertable: false,
        };
        let injection = OwaspContributingFinding {
            finding_key: "prompt-injection-bait-cursor".to_string(),
            title: "Prompt-injection bait in Cursor context".to_string(),
            severity: "HIGH".to_string(),
            domain: "transcripts".to_string(),
            alertable: false,
        };
        inputs.insert(
            "LLM02".to_string(),
            OwaspRowInput {
                total_findings: 1,
                alertable_findings: 0,
                worst_severity: "HIGH".to_string(),
                contributing_findings: vec![secret],
            },
        );
        for id in ["ASI01", "LLM01"] {
            inputs.insert(
                id.to_string(),
                OwaspRowInput {
                    total_findings: 1,
                    alertable_findings: 0,
                    worst_severity: "HIGH".to_string(),
                    contributing_findings: vec![injection.clone()],
                },
            );
        }
        let sc = build_trust_controls_scorecard(&inputs, true);
        let by_id = |id: &str| {
            all_rows(&sc)
                .into_iter()
                .find(|r| r.id == id)
                .unwrap_or_else(|| panic!("{} row present", id))
                .clone()
        };
        // Secret-in-context evidences the memory/data hygiene control.
        let mem = by_id("MEM-03");
        assert!(mem.has_live_findings, "secret signal must reach MEM-03");
        assert!(mem
            .contributing_findings
            .iter()
            .any(|f| f.finding_key.starts_with("transcript-secret-exposure")));
        // Injection bait evidences instruction-integrity controls.
        let rii = by_id("RII-01");
        assert!(rii.has_live_findings, "injection signal must reach RII-01");
        assert!(rii
            .contributing_findings
            .iter()
            .any(|f| f.finding_key.starts_with("prompt-injection-bait")));
        // Non-alertable leading indicators never inflate the alertable total
        // nor trip the headline.
        assert_eq!(sc.total_alertable, 0);
        assert!(!sc.hard_fail);
        assert_eq!(sc.headline_status, "clean");
    }

    #[test]
    fn clean_scorecard_has_no_live_findings() {
        let sc = build_trust_controls_scorecard(&HashMap::new(), false);
        assert_eq!(sc.total_alertable, 0);
        assert_eq!(sc.controls_with_findings, 0);
        assert_eq!(sc.headline_status, "clean");
        assert!(!sc.hard_fail);
        assert!(!sc.llm_available);
    }

    #[test]
    fn headline_is_attention_when_alertable_but_not_critical() {
        let mut inputs: HashMap<String, OwaspRowInput> = HashMap::new();
        inputs.insert(
            "LLM02".to_string(),
            OwaspRowInput {
                total_findings: 1,
                alertable_findings: 1,
                worst_severity: "HIGH".to_string(),
                contributing_findings: vec![OwaspContributingFinding {
                    finding_key: "k-high".to_string(),
                    title: "Sensitive egress".to_string(),
                    severity: "HIGH".to_string(),
                    domain: "dataflow".to_string(),
                    alertable: true,
                }],
            },
        );
        let sc = build_trust_controls_scorecard(&inputs, true);
        assert!(sc.total_alertable >= 1);
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
                    finding_key: "k-crit-suppressed".to_string(),
                    title: "Suppressed critical".to_string(),
                    severity: "CRITICAL".to_string(),
                    domain: "dataflow".to_string(),
                    alertable: false,
                }],
            },
        );
        let sc = build_trust_controls_scorecard(&inputs, true);
        assert!(!sc.hard_fail);
        assert_eq!(sc.headline_status, "clean");
    }
}
