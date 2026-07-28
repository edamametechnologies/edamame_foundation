//! MITRE ATLAS runtime detection coverage map (scoped subset).
//!
//! This is deliberately **not** the full ATLAS matrix. ATLAS publishes 170+
//! techniques across 16 tactics, and the large majority of them live outside
//! what a host/network runtime observer can see at all: training-time data
//! poisoning, model-extraction math, adversarial-example crafting, and the
//! attacker's own offline preparation. Rendering all 170 rows would produce a
//! card that is ~80% grey, which tells an operator nothing.
//!
//! The catalog below is the **runtime-observable** subset: 39 parent
//! techniques across 12 tactics, each of which produces a signal EDAMAME's
//! system-plane telemetry (process attribution, FIM, egress, credential-store
//! access, MCP/A2A inventory) or reasoning-plane observer (agent transcripts,
//! divergence) can actually carry. Four ATLAS tactics are excluded wholesale
//! because nothing in them is host-observable:
//!
//! | Excluded tactic | Why |
//! |---|---|
//! | `AML.TA0002` Reconnaissance | Attacker-side research, off-host |
//! | `AML.TA0003` Resource Development | Attacker-side staging, off-host |
//! | `AML.TA0000` AI Model Access | Model-API semantics, not host telemetry |
//! | `AML.TA0001` AI Attack Staging | Offline crafting (proxy models, adversarial data) |
//!
//! Sub-techniques are rolled up to their parent (see [`extract_atlas_ids`]):
//! the threatmodel JSON may tag a specific sub-technique such as
//! `AML.T0010.005` because that is more informative for a human reading the
//! check, but the scorecard renders one row per parent technique.
//!
//! Live attribution flows from `AML.T*` reference tokens exactly the way the
//! OWASP scorecard flows from `OWASP-*` tokens: attack-pattern checks carry
//! them in their CloudModel `reference` field
//! (`threatmodels/cve-detection-params-db.json`) and visibility findings carry
//! them via `VisibilityFinding::with_atlas()`. This module is pure: it merges
//! the static catalog with a caller-supplied per-technique input map.
//!
//! Grading follows the same three-tier contract as the OWASP scorecard, with
//! one additional invariant enforced by unit test: a `Strong` row MUST have at
//! least one detector rule tagged with its ID, so a `Strong` row can never be
//! one that is structurally unable to light up.

use crate::agent_owasp::{OwaspContributingFinding, OwaspCoverageGrade, OwaspRowInput};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Published ATLAS matrix, linked from the scorecard header.
pub const ATLAS_MATRIX_URL: &str = "https://atlas.mitre.org/matrices/ATLAS";

/// Per-technique deep link prefix. ATLAS technique pages are keyed by ID.
const ATLAS_TECHNIQUE_URL_PREFIX: &str = "https://atlas.mitre.org/techniques/";

/// The live-signal input shape. Identical to the OWASP row input by
/// construction -- both scorecards consume the same finding-attribution pass
/// in `edamame_core`, keyed by their respective reference token.
pub type AtlasRowInput = OwaspRowInput;

/// A finding attributed to an ATLAS technique. Alias of the OWASP shape so a
/// single attribution pass can feed both scorecards without a second clone of
/// the finding metadata.
pub type AtlasContributingFinding = OwaspContributingFinding;

/// Techniques whose only evidence path runs through the behavioral-divergence
/// engine, which requires a configured LLM provider. When no provider is
/// available these rows are "Unknown" rather than "clean" -- the same
/// treatment the OWASP scorecard gives its `llm_dependent` rows.
const ATLAS_LLM_DEPENDENT_IDS: &[&str] = &[
    "AML.T0051", // LLM Prompt Injection -- inferred from declared-vs-observed drift
    "AML.T0054", // LLM Jailbreak -- same
    "AML.T0080", // AI Agent Context Poisoning -- memory surface + drift
    "AML.T0092", // Manipulate User LLM Chat History -- transcript-store diffing
    "AML.T0093", // Prompt Infiltration via Public-Facing Application
    "AML.T0108", // AI Agent (as C2 channel)
];

/// True when the technique's evidence path depends on the divergence engine.
pub fn is_llm_dependent(id: &str) -> bool {
    ATLAS_LLM_DEPENDENT_IDS.contains(&id)
}

// ---------------------------------------------------------------------------
// Static catalog
// ---------------------------------------------------------------------------

struct AtlasCatalogEntry {
    /// Parent technique ID, e.g. `AML.T0010`.
    id: &'static str,
    /// Tactic this row is grouped under. For multi-tactic techniques this is
    /// the first tactic in ATLAS matrix order.
    tactic_id: &'static str,
    tactic: &'static str,
    /// Every tactic the technique appears under, ATLAS matrix order. Length 1
    /// for all but four techniques.
    tactics: &'static [&'static str],
    /// Canonical ATLAS technique name.
    name: &'static str,
    grade: OwaspCoverageGrade,
    /// What the runtime observer actually sees, and where the reach stops.
    coverage_rationale: &'static str,
    /// OWASP GenAI categories this technique typically manifests as. Purely a
    /// cross-reference for the operator -- attribution flows through the
    /// `AML.T*` tags, never through these.
    owasp_refs: &'static [&'static str],
}

/// The scoped catalog: 39 parent techniques, ATLAS matrix tactic order.
const ATLAS_CATALOG: &[AtlasCatalogEntry] = &[
    // -- AML.TA0004 Initial Access -------------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0010",
        tactic_id: "AML.TA0004",
        tactic: "Initial Access",
        tactics: &["Initial Access"],
        name: "AI Supply Chain Compromise",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: the skill/tool supply-chain check fires on agent \
            skill and tool definitions arriving from an untrusted origin, and FIM records the \
            write to the agent's plugin, skill, and MCP tool directories with process \
            attribution on the writer.",
        owasp_refs: &["ASI05", "LLM03"],
    },
    AtlasCatalogEntry {
        id: "AML.T0049",
        tactic_id: "AML.TA0004",
        tactic: "Initial Access",
        tactics: &["Initial Access"],
        name: "Exploit Public-Facing Application",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "The MCP inventory records every listener the agent exposes and \
            flags the ones bound beyond loopback or running unauthenticated, so the exposure \
            is visible. The exploitation of that listener is not -- EDAMAME does not inspect \
            request payloads.",
        owasp_refs: &["ASI02"],
    },
    AtlasCatalogEntry {
        id: "AML.T0093",
        tactic_id: "AML.TA0004",
        tactic: "Initial Access",
        tactics: &["Initial Access", "Persistence"],
        name: "Prompt Infiltration via Public-Facing Application",
        grade: OwaspCoverageGrade::Indirect,
        coverage_rationale: "Requires application-layer content inspection EDAMAME does not \
            perform. What is observable is the consequence: if infiltrated instructions cause \
            the agent to act outside its declared intent, the divergence engine reports it \
            without ever seeing the injected text.",
        owasp_refs: &["ASI01", "LLM01"],
    },
    // -- AML.TA0005 Execution ------------------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0011",
        tactic_id: "AML.TA0005",
        tactic: "Execution",
        tactics: &["Execution"],
        name: "User Execution",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: subprocess observation records every process the \
            agent spawns with full lineage, so an agent-induced execution is attributed to the \
            agent rather than to the user's shell.",
        owasp_refs: &["ASI03"],
    },
    AtlasCatalogEntry {
        id: "AML.T0050",
        tactic_id: "AML.TA0005",
        tactic: "Execution",
        tactics: &["Execution"],
        name: "Command and Scripting Interpreter",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: shell and interpreter invocations are a first-class \
            subprocess category, carrying the resolved binary path, argv, parent lineage, and \
            the agent instance that requested them.",
        owasp_refs: &["ASI03", "LLM05"],
    },
    AtlasCatalogEntry {
        id: "AML.T0051",
        tactic_id: "AML.TA0005",
        tactic: "Execution",
        tactics: &["Execution"],
        name: "LLM Prompt Injection",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Detected primarily by consequence, not by content: the observer \
            compares the agent's declared intent against what it actually did and reports the \
            gap, so injection that changes behavior is caught while injected text that never \
            leads to an observable action is not. A deterministic bait-phrase match over \
            ingested transcript text adds a leading indicator, but it evidences exposure to \
            an injection attempt rather than a successful one and never alerts on its own.",
        owasp_refs: &["ASI01", "LLM01"],
    },
    AtlasCatalogEntry {
        id: "AML.T0053",
        tactic_id: "AML.TA0005",
        tactic: "Execution",
        tactics: &["Execution", "Privilege Escalation"],
        name: "AI Agent Tool Invocation",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: every tool invocation that reaches the OS surfaces \
            as an attributed subprocess or MCP call, so the tool-mediated action is recorded \
            even when the agent's own logs are unavailable or tampered with.",
        owasp_refs: &["ASI03", "ASI04"],
    },
    AtlasCatalogEntry {
        id: "AML.T0103",
        tactic_id: "AML.TA0005",
        tactic: "Execution",
        tactics: &["Execution"],
        name: "Deploy AI Agent",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "The transcript observer discovers a newly-installed agent as soon \
            as its transcript root appears on disk, and the unsecured-agent threat fires when a \
            discovered agent is not being observed. Deployment of an agent that writes no \
            local transcript store is not covered.",
        owasp_refs: &["ASI06"],
    },
    // -- AML.TA0006 Persistence ----------------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0080",
        tactic_id: "AML.TA0006",
        tactic: "Persistence",
        tactics: &["Persistence"],
        name: "AI Agent Context Poisoning",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "The memory-poisoning surface check inventories the writable \
            context and memory stores the agent reads back across turns, and FIM attributes \
            writes to them. Whether the written content is actually adversarial is not \
            evaluated -- only that a poisonable surface was written to.",
        owasp_refs: &["ASI01", "LLM08"],
    },
    AtlasCatalogEntry {
        id: "AML.T0081",
        tactic_id: "AML.TA0006",
        tactic: "Persistence",
        tactics: &["Persistence", "Defense Evasion"],
        name: "Modify AI Agent Configuration",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: agent configuration files (MCP server lists, \
            allowed-tool sets, system prompts) are FIM-watched, and the config-drift check \
            reports a change against the last known-good state with the writing process \
            attributed.",
        owasp_refs: &["ASI05", "ASI06"],
    },
    AtlasCatalogEntry {
        id: "AML.T0099",
        tactic_id: "AML.TA0006",
        tactic: "Persistence",
        tactics: &["Persistence"],
        name: "AI Agent Tool Data Poisoning",
        grade: OwaspCoverageGrade::Indirect,
        coverage_rationale: "The data a tool returns to the agent is not inspected. FIM does \
            record writes to local files a tool later reads, which gives an operator the \
            timeline, but there is no detector rule that adjudicates the returned content.",
        owasp_refs: &["ASI05", "LLM04"],
    },
    AtlasCatalogEntry {
        id: "AML.T0110",
        tactic_id: "AML.TA0006",
        tactic: "Persistence",
        tactics: &["Persistence"],
        name: "AI Agent Tool Poisoning",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: MCP tool definitions are inventoried and hashed, so \
            a changed tool description or a silently added tool is reported, and FIM attributes \
            the write to the tool definition file.",
        owasp_refs: &["ASI05", "LLM03"],
    },
    // -- AML.TA0012 Privilege Escalation -------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0105",
        tactic_id: "AML.TA0012",
        tactic: "Privilege Escalation",
        tactics: &["Privilege Escalation"],
        name: "Escape to Host",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: the sandbox-exploitation check fires on host access \
            from a process whose lineage places it inside a sandbox or container, corroborated \
            by process path, parent lineage, and sensitive-material access.",
        owasp_refs: &["ASI04", "ASI03"],
    },
    AtlasCatalogEntry {
        id: "AML.T0054",
        tactic_id: "AML.TA0012",
        tactic: "Privilege Escalation",
        tactics: &["Privilege Escalation", "Defense Evasion"],
        name: "LLM Jailbreak",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Observed as a behavioral outcome: a successful jailbreak shows up \
            as the agent taking actions outside its declared intent, which the divergence \
            engine reports. The jailbreak prompt itself is never inspected.",
        owasp_refs: &["ASI01", "LLM01"],
    },
    // -- AML.TA0007 Defense Evasion ------------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0097",
        tactic_id: "AML.TA0007",
        tactic: "Defense Evasion",
        tactics: &["Defense Evasion"],
        name: "Virtualization/Sandbox Evasion",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: the sandbox-exploitation check covers the evasion \
            side of the same signal as escape-to-host -- a sandboxed process reaching host \
            paths, host sockets, or the container runtime socket.",
        owasp_refs: &["ASI04"],
    },
    AtlasCatalogEntry {
        id: "AML.T0074",
        tactic_id: "AML.TA0007",
        tactic: "Defense Evasion",
        tactics: &["Defense Evasion"],
        name: "Masquerading",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: process attribution resolves the real binary path \
            behind a process name, and the file-system-tampering check fires when a binary is \
            written to a location that mimics a system or packaged-application path.",
        owasp_refs: &["ASI05"],
    },
    AtlasCatalogEntry {
        id: "AML.T0092",
        tactic_id: "AML.TA0007",
        tactic: "Defense Evasion",
        tactics: &["Defense Evasion"],
        name: "Manipulate User LLM Chat History",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "The transcript observer reads the agent's own session store, so \
            edits and truncations to it are observable in principle and the observer's \
            independence means a compromised agent cannot hide them. There is no dedicated \
            detector rule attributing a history rewrite today.",
        owasp_refs: &["ASI01", "LLM08"],
    },
    AtlasCatalogEntry {
        id: "AML.T0109",
        tactic_id: "AML.TA0007",
        tactic: "Defense Evasion",
        tactics: &["Defense Evasion"],
        name: "AI Supply Chain Rug Pull",
        grade: OwaspCoverageGrade::Indirect,
        coverage_rationale: "Requires diffing a remote artifact across time, which is a \
            registry-side concern rather than a host one. The local consequence -- a tool or \
            skill definition whose hash changed under the agent -- is what the tool-poisoning \
            check reports.",
        owasp_refs: &["ASI05", "LLM03"],
    },
    // -- AML.TA0013 Credential Access ----------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0055",
        tactic_id: "AML.TA0013",
        tactic: "Credential Access",
        tactics: &["Credential Access"],
        name: "Unsecured Credentials",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: the credential-harvest check fires on reads of \
            plaintext credential material (dotenv files, cloud credential files, SSH private \
            keys, token caches) with the reading process attributed, and content scanning \
            classifies the material.",
        owasp_refs: &["ASI07", "LLM02"],
    },
    AtlasCatalogEntry {
        id: "AML.T0083",
        tactic_id: "AML.TA0013",
        tactic: "Credential Access",
        tactics: &["Credential Access"],
        name: "Credentials from AI Agent Configuration",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: agent configuration paths are in the sensitive-path \
            set, so a read of MCP server credentials or an API key embedded in agent config is \
            attributed to the reading process by the credential-harvest check.",
        owasp_refs: &["ASI07", "ASI06"],
    },
    AtlasCatalogEntry {
        id: "AML.T0098",
        tactic_id: "AML.TA0013",
        tactic: "Credential Access",
        tactics: &["Credential Access"],
        name: "AI Agent Tool Credential Harvesting",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "When the harvesting tool runs as a local subprocess its credential \
            reads are caught by the same credential-harvest path. A tool that harvests entirely \
            inside a remote MCP server, returning only the secret, leaves no local read to \
            observe.",
        owasp_refs: &["ASI07", "ASI04"],
    },
    AtlasCatalogEntry {
        id: "AML.T0090",
        tactic_id: "AML.TA0013",
        tactic: "Credential Access",
        tactics: &["Credential Access"],
        name: "OS Credential Dumping",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: access to the platform credential stores (macOS \
            Keychain, Linux keyrings and KWallet, Windows Credential Manager) is classified by \
            store kind and graded on the writer's attribution strength and corroborating \
            evidence.",
        owasp_refs: &["ASI07"],
    },
    // -- AML.TA0008 Discovery ------------------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0089",
        tactic_id: "AML.TA0008",
        tactic: "Discovery",
        tactics: &["Discovery"],
        name: "Process Discovery",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Enumeration performed by spawning a process (process listing, \
            service queries) is recorded as an attributed subprocess. Enumeration done in-process \
            through a syscall or an API leaves no subprocess to attribute, and there is no \
            dedicated rule for the pattern.",
        owasp_refs: &["ASI03"],
    },
    AtlasCatalogEntry {
        id: "AML.T0084",
        tactic_id: "AML.TA0008",
        tactic: "Discovery",
        tactics: &["Discovery"],
        name: "Discover AI Agent Configuration",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Reads of agent configuration paths are visible through open-file \
            enrichment and FIM, and the MCP inventory records what the agent is configured to \
            reach. Reconnaissance-only reads are not separated from legitimate config loads by \
            any current rule.",
        owasp_refs: &["ASI06"],
    },
    AtlasCatalogEntry {
        id: "AML.T0007",
        tactic_id: "AML.TA0008",
        tactic: "Discovery",
        tactics: &["Discovery"],
        name: "Discover AI Artifacts",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Reads under model, weight, and dataset directories surface through \
            open-file enrichment with the reading process attributed. Distinguishing \
            enumeration from normal model loading needs a rule that does not exist yet.",
        owasp_refs: &["ASI07", "LLM10"],
    },
    AtlasCatalogEntry {
        id: "AML.T0075",
        tactic_id: "AML.TA0008",
        tactic: "Discovery",
        tactics: &["Discovery"],
        name: "Cloud Service Discovery",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Egress to cloud metadata endpoints and control-plane APIs is \
            captured with process attribution and destination classification, which is the \
            observable half. The scope of what was enumerated in the response is not.",
        owasp_refs: &["ASI04"],
    },
    // -- AML.TA0015 Lateral Movement -----------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0091",
        tactic_id: "AML.TA0015",
        tactic: "Lateral Movement",
        tactics: &["Lateral Movement"],
        name: "Use Alternate Authentication Material",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "The agent-to-agent surface check records delegated-identity and \
            token-passing relationships between agents, and credential reads followed by egress \
            are correlated. Validating whether the presented material was legitimately issued \
            is out of host scope.",
        owasp_refs: &["ASI08", "ASI07"],
    },
    // -- AML.TA0009 Collection -----------------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0037",
        tactic_id: "AML.TA0009",
        tactic: "Collection",
        tactics: &["Collection"],
        name: "Data from Local System",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: sensitive local reads are attributed per process \
            through live open-file enumeration plus content classification, and feed both the \
            credential-harvest and sensitive-material-egress checks.",
        owasp_refs: &["ASI07", "LLM02"],
    },
    AtlasCatalogEntry {
        id: "AML.T0035",
        tactic_id: "AML.TA0009",
        tactic: "Collection",
        tactics: &["Collection"],
        name: "AI Artifact Collection",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Bulk reads of model and artifact directories are visible through \
            the same open-file enrichment that backs local-system collection, but no rule \
            currently distinguishes staging-for-exfiltration from routine model loading.",
        owasp_refs: &["ASI07", "LLM10"],
    },
    AtlasCatalogEntry {
        id: "AML.T0085",
        tactic_id: "AML.TA0009",
        tactic: "Collection",
        tactics: &["Collection"],
        name: "Data from AI Services",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Sessions to AI service endpoints are captured with process \
            attribution, destination classification, and volume, so bulk retrieval is visible \
            as a traffic shape. The retrieved content is not inspected.",
        owasp_refs: &["ASI07", "LLM02"],
    },
    // -- AML.TA0014 Command and Control --------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0072",
        tactic_id: "AML.TA0014",
        tactic: "Command and Control",
        tactics: &["Command and Control"],
        name: "Reverse Shell",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: an interpreter subprocess holding an outbound \
            socket to a non-routine destination is the canonical shape the \
            sandbox-exploitation and egress checks fire on, with full lineage attribution.",
        owasp_refs: &["ASI03", "ASI04"],
    },
    AtlasCatalogEntry {
        id: "AML.T0096",
        tactic_id: "AML.TA0014",
        tactic: "Command and Control",
        tactics: &["Command and Control"],
        name: "AI Service API",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Egress to AI service APIs is captured and classified, so an \
            unexpected provider or an anomalous traffic pattern to a known one is visible. \
            Instructions tunnelled inside otherwise-normal API traffic are not, because the \
            payload is not inspected.",
        owasp_refs: &["ASI04", "ASI08"],
    },
    AtlasCatalogEntry {
        id: "AML.T0108",
        tactic_id: "AML.TA0014",
        tactic: "Command and Control",
        tactics: &["Command and Control"],
        name: "AI Agent",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "The agent-to-agent and MCP surfaces record which agents talk to \
            which peers and over what transport, so an agent being driven by another is \
            structurally visible. Deciding that the relationship is malicious control rather \
            than legitimate orchestration needs the divergence verdict.",
        owasp_refs: &["ASI08", "ASI04"],
    },
    // -- AML.TA0010 Exfiltration ---------------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0025",
        tactic_id: "AML.TA0010",
        tactic: "Exfiltration",
        tactics: &["Exfiltration"],
        name: "Exfiltration via Cyber Means",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: the token-exfiltration and sensitive-material-egress \
            checks correlate a sensitive local read with sustained outbound traffic from the \
            same process, including the approved-destination case where credentials leave \
            through the application's own backend.",
        owasp_refs: &["ASI07", "LLM02"],
    },
    AtlasCatalogEntry {
        id: "AML.T0086",
        tactic_id: "AML.TA0010",
        tactic: "Exfiltration",
        tactics: &["Exfiltration"],
        name: "Exfiltration via AI Agent Tool Invocation",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "A tool that exfiltrates by running locally is caught by the \
            standard read-then-egress correlation. A tool whose implementation lives in a \
            remote MCP server can carry the data out inside its own request, where only the \
            invocation and its destination are observable.",
        owasp_refs: &["ASI04", "ASI07"],
    },
    AtlasCatalogEntry {
        id: "AML.T0057",
        tactic_id: "AML.TA0010",
        tactic: "Exfiltration",
        tactics: &["Exfiltration"],
        name: "LLM Data Leakage",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "The dataflow check reports sensitive material moving from a local \
            read into an LLM request, which is the leak path a host observer can see. Leakage \
            that originates in the model's own memorized training data has no host-side \
            signal.",
        owasp_refs: &["ASI07", "LLM02"],
    },
    // -- AML.TA0011 Impact ---------------------------------------------------
    AtlasCatalogEntry {
        id: "AML.T0112",
        tactic_id: "AML.TA0011",
        tactic: "Impact",
        tactics: &["Impact"],
        name: "Machine Compromise",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Composite: the individual host signals (privilege escalation, \
            persistence writes, credential dumping, C2 egress) each have their own detector, \
            and the security score plus blast-radius view aggregate them. There is no single \
            rule that declares the machine compromised.",
        owasp_refs: &["ASI03", "ASI04"],
    },
    AtlasCatalogEntry {
        id: "AML.T0101",
        tactic_id: "AML.TA0011",
        tactic: "Impact",
        tactics: &["Impact"],
        name: "Data Destruction via AI Agent Tool Invocation",
        grade: OwaspCoverageGrade::Strong,
        coverage_rationale: "Deterministic: destructive writes and deletions on watched paths \
            are reported by the file-system-tampering check with the writing process \
            attributed, and the destructive subprocess that performed them is recorded \
            alongside.",
        owasp_refs: &["ASI03", "ASI09"],
    },
    AtlasCatalogEntry {
        id: "AML.T0034",
        tactic_id: "AML.TA0011",
        tactic: "Impact",
        tactics: &["Impact"],
        name: "Cost Harvesting",
        grade: OwaspCoverageGrade::Partial,
        coverage_rationale: "Runaway agent loops are reported by the recursion and \
            cascading-failure checks, and request volume to paid endpoints is visible in \
            session telemetry. The billing consequence itself is provider-side and not \
            observable from the host.",
        owasp_refs: &["ASI09", "LLM10"],
    },
];

// ---------------------------------------------------------------------------
// Reference-token parsing
// ---------------------------------------------------------------------------

/// Extract ATLAS technique IDs from a free-form reference string, rolling
/// sub-techniques up to their parent.
///
/// Accepts `AML.T0000` (parent) and `AML.T0000.000` (sub-technique) shapes and
/// always yields the parent ID, because the scorecard renders one row per
/// parent technique. Order-preserving and de-duplicated, mirroring
/// `extract_owasp_ids`.
///
/// ```text
/// "CVE-2024-1234, AML.T0010.005, AML.T0055" -> ["AML.T0010", "AML.T0055"]
/// ```
pub fn extract_atlas_ids(s: &str) -> Vec<String> {
    const NEEDLE: &str = "AML.T";
    // Parent ID length: "AML.T" + 4 digits.
    const PARENT_LEN: usize = NEEDLE.len() + 4;
    let mut ids: Vec<String> = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = s[search_from..].find(NEEDLE) {
        let start = search_from + rel;
        let digits_at = start + NEEDLE.len();
        // Advance past the needle regardless of whether this candidate parses,
        // so a malformed token cannot loop forever.
        search_from = digits_at;
        if let Some(digits) = s.get(digits_at..digits_at + 4) {
            let well_formed = digits.as_bytes().iter().all(|b| b.is_ascii_digit());
            // Reject a longer digit run (e.g. "AML.T00101"), which is not a
            // valid ATLAS ID and must not be silently truncated to a parent.
            let terminated = !s
                .as_bytes()
                .get(digits_at + 4)
                .is_some_and(|b| b.is_ascii_digit());
            if well_formed && terminated {
                let parent = s[start..start + PARENT_LEN].to_string();
                if !ids.contains(&parent) {
                    ids.push(parent);
                }
                // Skip a trailing ".NNN" sub-technique suffix so its digits are
                // never re-read as a fresh token.
                if let Some(suffix) = s.get(start + PARENT_LEN..start + PARENT_LEN + 4) {
                    let b = suffix.as_bytes();
                    if b[0] == b'.' && b[1..].iter().all(|c| c.is_ascii_digit()) {
                        search_from = start + PARENT_LEN + 4;
                    }
                }
            }
        }
        if search_from >= s.len() {
            break;
        }
    }
    ids
}

// ---------------------------------------------------------------------------
// Output shapes
// ---------------------------------------------------------------------------

/// One technique row: static grading plus live attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasRow {
    pub id: String,
    /// Tactic this row is grouped under (first tactic in matrix order).
    pub tactic_id: String,
    pub tactic: String,
    /// Every tactic the technique appears under. Length 1 for most rows.
    pub tactics: Vec<String>,
    pub name: String,
    pub grade: OwaspCoverageGrade,
    pub coverage_rationale: String,
    /// Cross-reference to OWASP GenAI categories. Not an attribution path.
    pub owasp_refs: Vec<String>,
    pub reference_url: String,
    pub total_findings: u32,
    pub alertable_findings: u32,
    pub worst_severity: String,
    pub has_live_findings: bool,
    /// True when this row's only evidence path needs the divergence engine.
    pub llm_dependent: bool,
    pub contributing_findings: Vec<OwaspContributingFinding>,
}

/// Rows grouped by ATLAS tactic, matrix order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasTacticGroup {
    pub tactic_id: String,
    pub tactic: String,
    pub rows: Vec<AtlasRow>,
}

/// The composite ATLAS detection coverage scorecard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasScorecard {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Headline derived from the attributed live findings, same rule as the
    /// OWASP and Trust Controls scorecards: `critical` (an alertable CRITICAL
    /// finding is mapped to a technique), `attention` (any other alertable
    /// finding), or `clean` (none).
    pub headline_status: String,
    /// True when at least one alertable CRITICAL finding is attributed.
    pub hard_fail: bool,
    /// Alertable findings summed across technique rows. A finding tagged with
    /// two techniques counts once per row.
    pub total_alertable: u32,
    /// Number of techniques with at least one live finding.
    pub techniques_with_findings: u32,
    /// Size of the scoped catalog, so the UI can state the denominator
    /// honestly ("39 runtime-observable of 170+ published").
    pub technique_count: u32,
    /// Grade tallies across the scoped catalog (static).
    pub strong_count: u32,
    pub partial_count: u32,
    pub indirect_count: u32,
    /// True when a usable LLM provider is configured. `llm_dependent` rows are
    /// "Unknown" rather than "clean" when false.
    pub llm_available: bool,
    /// Published ATLAS matrix, so the header link is owned by the core rather
    /// than hardcoded per consumer.
    pub matrix_url: String,
    pub tactics: Vec<AtlasTacticGroup>,
}

// ---------------------------------------------------------------------------
// Builder (deterministic, pure)
// ---------------------------------------------------------------------------

/// Merge the static scoped catalog with the per-technique live signal into a
/// full ATLAS scorecard, deriving the headline status from the attributed
/// findings. Pure.
///
/// `inputs` is keyed by parent ATLAS technique ID (`AML.T0010`), produced by
/// the same finding-attribution pass in `edamame_core` that feeds the OWASP
/// scorecard -- see `extract_atlas_ids`.
pub fn build_atlas_scorecard(
    inputs: &HashMap<String, AtlasRowInput>,
    llm_available: bool,
) -> AtlasScorecard {
    let mut groups: Vec<AtlasTacticGroup> = Vec::new();
    let mut total_alertable = 0u32;
    let mut techniques_with_findings = 0u32;
    let mut hard_fail = false;
    let mut strong_count = 0u32;
    let mut partial_count = 0u32;
    let mut indirect_count = 0u32;

    for entry in ATLAS_CATALOG {
        let (total, alertable, worst, findings) = match inputs.get(entry.id) {
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
            techniques_with_findings += 1;
        }
        total_alertable += alertable;
        if findings
            .iter()
            .any(|f| f.alertable && f.severity.trim().eq_ignore_ascii_case("CRITICAL"))
        {
            hard_fail = true;
        }
        match entry.grade {
            OwaspCoverageGrade::Strong => strong_count += 1,
            OwaspCoverageGrade::Partial => partial_count += 1,
            OwaspCoverageGrade::Indirect => indirect_count += 1,
            // The scoped catalog contains no out-of-scope rows by
            // construction; see `catalog_has_no_out_of_scope_rows`.
            OwaspCoverageGrade::OutOfScope => {}
        }

        let row = AtlasRow {
            id: entry.id.to_string(),
            tactic_id: entry.tactic_id.to_string(),
            tactic: entry.tactic.to_string(),
            tactics: entry.tactics.iter().map(|t| (*t).to_string()).collect(),
            name: entry.name.to_string(),
            grade: entry.grade,
            coverage_rationale: entry.coverage_rationale.to_string(),
            owasp_refs: entry.owasp_refs.iter().map(|r| (*r).to_string()).collect(),
            reference_url: format!("{}{}", ATLAS_TECHNIQUE_URL_PREFIX, entry.id),
            total_findings: total,
            alertable_findings: alertable,
            worst_severity: worst,
            has_live_findings: has_live,
            llm_dependent: is_llm_dependent(entry.id),
            contributing_findings: findings,
        };

        // Catalog order is matrix order, so a tactic's rows are contiguous and
        // appending to the trailing group preserves that order.
        match groups.last_mut() {
            Some(g) if g.tactic_id == entry.tactic_id => g.rows.push(row),
            _ => groups.push(AtlasTacticGroup {
                tactic_id: entry.tactic_id.to_string(),
                tactic: entry.tactic.to_string(),
                rows: vec![row],
            }),
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

    AtlasScorecard {
        generated_at: chrono::Utc::now(),
        headline_status,
        hard_fail,
        total_alertable,
        techniques_with_findings,
        technique_count: ATLAS_CATALOG.len() as u32,
        strong_count,
        partial_count,
        indirect_count,
        llm_available,
        matrix_url: ATLAS_MATRIX_URL.to_string(),
        tactics: groups,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical ATLAS tactic matrix order, minus the four tactics excluded
    /// wholesale as non-host-observable (Reconnaissance, Resource Development,
    /// AI Model Access, AI Attack Staging).
    const EXPECTED_TACTIC_ORDER: &[(&str, &str)] = &[
        ("AML.TA0004", "Initial Access"),
        ("AML.TA0005", "Execution"),
        ("AML.TA0006", "Persistence"),
        ("AML.TA0012", "Privilege Escalation"),
        ("AML.TA0007", "Defense Evasion"),
        ("AML.TA0013", "Credential Access"),
        ("AML.TA0008", "Discovery"),
        ("AML.TA0015", "Lateral Movement"),
        ("AML.TA0009", "Collection"),
        ("AML.TA0014", "Command and Control"),
        ("AML.TA0010", "Exfiltration"),
        ("AML.TA0011", "Impact"),
    ];

    #[test]
    fn catalog_is_thirty_nine_unique_parent_techniques() {
        assert_eq!(ATLAS_CATALOG.len(), 39, "scoped catalog size changed");
        let mut ids: Vec<&str> = ATLAS_CATALOG.iter().map(|e| e.id).collect();
        ids.sort_unstable();
        let unique = ids.len();
        ids.dedup();
        assert_eq!(unique, ids.len(), "duplicate technique ID in catalog");
        for e in ATLAS_CATALOG {
            assert_eq!(
                extract_atlas_ids(e.id),
                vec![e.id.to_string()],
                "catalog ID {} is not a well-formed parent technique",
                e.id
            );
        }
    }

    #[test]
    fn catalog_groups_by_tactic_in_matrix_order() {
        let mut seen: Vec<(&str, &str)> = Vec::new();
        for e in ATLAS_CATALOG {
            match seen.last() {
                Some((id, _)) if *id == e.tactic_id => {}
                _ => seen.push((e.tactic_id, e.tactic)),
            }
        }
        assert_eq!(
            seen, EXPECTED_TACTIC_ORDER,
            "tactic grouping drifted from ATLAS matrix order (or a tactic's \
             rows are no longer contiguous, which would split its group)"
        );
    }

    #[test]
    fn every_row_declares_its_primary_tactic_first() {
        for e in ATLAS_CATALOG {
            assert!(!e.tactics.is_empty(), "{} declares no tactics", e.id);
            assert_eq!(
                e.tactics[0], e.tactic,
                "{} groups under {} but lists {} first",
                e.id, e.tactic, e.tactics[0]
            );
        }
    }

    #[test]
    fn catalog_has_no_out_of_scope_rows() {
        // The whole point of the scoped catalog: anything genuinely outside a
        // runtime observer's reach is excluded rather than rendered grey.
        for e in ATLAS_CATALOG {
            assert_ne!(
                e.grade,
                OwaspCoverageGrade::OutOfScope,
                "{} is OutOfScope and should be dropped from the scoped catalog",
                e.id
            );
        }
    }

    #[test]
    fn grade_tallies_match_catalog() {
        let card = build_atlas_scorecard(&HashMap::new(), true);
        assert_eq!(
            card.strong_count + card.partial_count + card.indirect_count,
            card.technique_count
        );
        assert_eq!(card.technique_count, 39);
        assert_eq!(card.strong_count, 16);
        assert_eq!(card.partial_count, 20);
        assert_eq!(card.indirect_count, 3);
    }

    #[test]
    fn every_strong_row_has_a_live_attribution_path() {
        // A `Strong` row claims shipped, deterministic detection. If no
        // detector rule carries its ID the row can never light up, which would
        // make the claim false. Visibility-side tags are checked here; the
        // attack-pattern side lives in the CloudModel threatmodel JSON and is
        // validated by that repo's `make validate`.
        let tagged = crate::agent_visibility::all_atlas_tagged_ids();
        for e in ATLAS_CATALOG {
            if e.grade == OwaspCoverageGrade::Strong {
                assert!(
                    tagged.contains(&e.id) || ATTACK_PATTERN_TAGGED_IDS.contains(&e.id),
                    "{} ({}) is graded Strong but no detector rule is tagged with it",
                    e.id,
                    e.name
                );
            }
        }
    }

    /// ATLAS IDs carried by attack-pattern checks via their CloudModel
    /// `reference` field in `threatmodels/cve-detection-params-db.json`. Kept
    /// here so the Strong-row invariant above can be enforced at test time;
    /// the JSON remains the source of truth for the tags themselves.
    const ATTACK_PATTERN_TAGGED_IDS: &[&str] = &[
        "AML.T0010", // skill_supply_chain
        "AML.T0025", // token_exfiltration
        "AML.T0037", // credential_harvest
        "AML.T0050", // sandbox_exploitation
        "AML.T0055", // credential_harvest
        "AML.T0057", // token_exfiltration
        "AML.T0072", // sandbox_exploitation
        "AML.T0074", // file_system_tampering
        "AML.T0081", // file_system_tampering
        "AML.T0083", // credential_harvest
        "AML.T0090", // credential_harvest
        "AML.T0101", // file_system_tampering
        "AML.T0105", // sandbox_exploitation
        "AML.T0110", // skill_supply_chain
    ];

    #[test]
    fn every_tagged_id_is_in_the_catalog() {
        // A tag pointing at a technique the catalog does not carry would
        // silently drop live findings on the floor.
        let catalog: Vec<&str> = ATLAS_CATALOG.iter().map(|e| e.id).collect();
        for id in crate::agent_visibility::all_atlas_tagged_ids() {
            assert!(
                catalog.contains(&id),
                "visibility tag {} has no catalog row; its findings would be dropped",
                id
            );
        }
        for id in ATTACK_PATTERN_TAGGED_IDS {
            assert!(
                catalog.contains(id),
                "attack-pattern tag {} has no catalog row; its findings would be dropped",
                id
            );
        }
    }

    #[test]
    fn llm_dependent_ids_are_all_in_the_catalog() {
        let catalog: Vec<&str> = ATLAS_CATALOG.iter().map(|e| e.id).collect();
        for id in ATLAS_LLM_DEPENDENT_IDS {
            assert!(catalog.contains(id), "{} is not in the catalog", id);
        }
    }

    #[test]
    fn owasp_cross_refs_are_well_formed() {
        for e in ATLAS_CATALOG {
            assert!(
                !e.owasp_refs.is_empty(),
                "{} has no OWASP cross-reference",
                e.id
            );
            for r in e.owasp_refs {
                assert!(
                    r.starts_with("ASI") || r.starts_with("LLM"),
                    "{} has malformed OWASP cross-ref {}",
                    e.id,
                    r
                );
                assert_eq!(r.len(), 5, "{} has malformed OWASP cross-ref {}", e.id, r);
            }
        }
    }

    #[test]
    fn every_row_has_a_concrete_rationale() {
        for e in ATLAS_CATALOG {
            // Long enough to actually say what is and is not observed, rather
            // than a one-word placeholder.
            assert!(
                e.coverage_rationale.len() > 80,
                "{} rationale is too thin to be useful",
                e.id
            );
            assert!(
                !e.name.trim().is_empty(),
                "{} has an empty technique name",
                e.id
            );
        }
    }

    #[test]
    fn extract_rolls_sub_techniques_up_to_parent() {
        assert_eq!(
            extract_atlas_ids("AML.T0010.005"),
            vec!["AML.T0010".to_string()]
        );
        assert_eq!(
            extract_atlas_ids("CVE-2024-1234, AML.T0010.005, AML.T0055"),
            vec!["AML.T0010".to_string(), "AML.T0055".to_string()]
        );
        // Parent and one of its sub-techniques collapse to a single row.
        assert_eq!(
            extract_atlas_ids("AML.T0010 AML.T0010.005"),
            vec!["AML.T0010".to_string()]
        );
    }

    #[test]
    fn extract_is_order_preserving_and_deduped() {
        assert_eq!(
            extract_atlas_ids("AML.T0055 AML.T0010 AML.T0055"),
            vec!["AML.T0055".to_string(), "AML.T0010".to_string()]
        );
    }

    #[test]
    fn extract_rejects_malformed_tokens() {
        assert!(extract_atlas_ids("").is_empty());
        assert!(extract_atlas_ids("no atlas tags here").is_empty());
        // Too few digits.
        assert!(extract_atlas_ids("AML.T001").is_empty());
        // Too many digits: must not be truncated to a valid-looking parent.
        assert!(extract_atlas_ids("AML.T00101").is_empty());
        // Non-digit body.
        assert!(extract_atlas_ids("AML.TABCD").is_empty());
        // Truncated needle at end of input must not panic.
        assert!(extract_atlas_ids("trailing AML.T").is_empty());
        assert!(extract_atlas_ids("AML.").is_empty());
    }

    #[test]
    fn extract_handles_multibyte_input() {
        // `find` returns byte offsets; slicing must stay on char boundaries.
        assert_eq!(
            extract_atlas_ids("crédential harvest -> AML.T0055 (clé)"),
            vec!["AML.T0055".to_string()]
        );
    }

    #[test]
    fn empty_inputs_produce_a_clean_card_with_full_catalog() {
        let card = build_atlas_scorecard(&HashMap::new(), true);
        assert_eq!(card.headline_status, "clean");
        assert!(!card.hard_fail);
        assert_eq!(card.total_alertable, 0);
        assert_eq!(card.techniques_with_findings, 0);
        assert_eq!(card.tactics.len(), EXPECTED_TACTIC_ORDER.len());
        let rows: usize = card.tactics.iter().map(|t| t.rows.len()).sum();
        assert_eq!(
            rows, 39,
            "every catalog row must render even with no findings"
        );
        for t in &card.tactics {
            for r in &t.rows {
                assert_eq!(r.worst_severity, "NONE");
                assert!(!r.has_live_findings);
                assert!(r.reference_url.starts_with(ATLAS_TECHNIQUE_URL_PREFIX));
                assert!(r.reference_url.ends_with(&r.id));
            }
        }
    }

    fn finding(key: &str, severity: &str, alertable: bool) -> OwaspContributingFinding {
        OwaspContributingFinding {
            finding_key: key.to_string(),
            title: format!("finding {}", key),
            severity: severity.to_string(),
            domain: "capture".to_string(),
            alertable,
        }
    }

    #[test]
    fn critical_alertable_finding_hard_fails() {
        let mut inputs: HashMap<String, AtlasRowInput> = HashMap::new();
        inputs.insert(
            "AML.T0055".to_string(),
            AtlasRowInput {
                total_findings: 1,
                alertable_findings: 1,
                worst_severity: "critical".to_string(),
                contributing_findings: vec![finding("k1", "CRITICAL", true)],
            },
        );
        let card = build_atlas_scorecard(&inputs, true);
        assert!(card.hard_fail);
        assert_eq!(card.headline_status, "critical");
        assert_eq!(card.total_alertable, 1);
        assert_eq!(card.techniques_with_findings, 1);
        let row = card
            .tactics
            .iter()
            .flat_map(|t| &t.rows)
            .find(|r| r.id == "AML.T0055")
            .expect("AML.T0055 row");
        assert!(row.has_live_findings);
        // Severity is normalized to upper case regardless of input casing.
        assert_eq!(row.worst_severity, "CRITICAL");
    }

    #[test]
    fn non_critical_alertable_finding_is_attention_only() {
        let mut inputs: HashMap<String, AtlasRowInput> = HashMap::new();
        inputs.insert(
            "AML.T0025".to_string(),
            AtlasRowInput {
                total_findings: 2,
                alertable_findings: 1,
                worst_severity: "HIGH".to_string(),
                contributing_findings: vec![
                    finding("k1", "HIGH", true),
                    finding("k2", "LOW", false),
                ],
            },
        );
        let card = build_atlas_scorecard(&inputs, true);
        assert!(!card.hard_fail);
        assert_eq!(card.headline_status, "attention");
        assert_eq!(card.total_alertable, 1);
    }

    #[test]
    fn non_alertable_findings_alone_stay_clean() {
        let mut inputs: HashMap<String, AtlasRowInput> = HashMap::new();
        inputs.insert(
            "AML.T0034".to_string(),
            AtlasRowInput {
                total_findings: 1,
                alertable_findings: 0,
                worst_severity: "LOW".to_string(),
                contributing_findings: vec![finding("k1", "LOW", false)],
            },
        );
        let card = build_atlas_scorecard(&inputs, true);
        assert_eq!(card.headline_status, "clean");
        assert!(!card.hard_fail);
        // The finding is still surfaced for triage even though it is not
        // alertable -- same contract as the OWASP card.
        assert_eq!(card.techniques_with_findings, 1);
    }

    #[test]
    fn unknown_technique_ids_in_inputs_are_ignored() {
        let mut inputs: HashMap<String, AtlasRowInput> = HashMap::new();
        inputs.insert(
            "AML.T9999".to_string(),
            AtlasRowInput {
                total_findings: 1,
                alertable_findings: 1,
                worst_severity: "CRITICAL".to_string(),
                contributing_findings: vec![finding("k1", "CRITICAL", true)],
            },
        );
        let card = build_atlas_scorecard(&inputs, true);
        assert_eq!(card.headline_status, "clean");
        assert_eq!(card.techniques_with_findings, 0);
    }

    #[test]
    fn llm_available_is_recorded_and_does_not_gate_rows() {
        let card = build_atlas_scorecard(&HashMap::new(), false);
        assert!(!card.llm_available);
        let rows: usize = card.tactics.iter().map(|t| t.rows.len()).sum();
        assert_eq!(rows, 39, "rows must render regardless of LLM availability");
        let dependent = card
            .tactics
            .iter()
            .flat_map(|t| &t.rows)
            .filter(|r| r.llm_dependent)
            .count();
        assert_eq!(dependent, ATLAS_LLM_DEPENDENT_IDS.len());
    }
}
