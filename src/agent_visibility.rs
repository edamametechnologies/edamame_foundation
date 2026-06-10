//! Agent visibility collectors (MVP engine).
//!
//! Single source of truth for the four MVP visibility domains, shared by the
//! standalone core path (direct calls) and the helper path
//! (`helper_rx_utility::utility_collect_agent_visibility` calls these same
//! functions on the other side of the macOS sandbox boundary). Every public
//! function takes an explicit `home: &Path` so the helper can target a
//! specific user's home directory when running as root.
//!
//! Privacy stance (invariant I5): this module is metadata-first by design.
//! It records MCP server *names*, transports, classified privilege classes,
//! and environment-variable *key names* (never values), and content-addressed
//! hashes of instruction files (never their bodies). No transcript or file
//! content is captured here.
//!
//! Dependency-light on purpose: only `serde`, `serde_json`, `sha2`, `hex`,
//! `chrono`, and `supported_agents`. No new heavy crates, so the module keeps
//! compiling for iOS/Android (where the agent plugins never install and the
//! collectors simply find nothing on disk).

use crate::supported_agents;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Shared severity + finding model (reuses the dismissal model via finding_key)
// ---------------------------------------------------------------------------

/// Severity grade for a deterministic visibility finding. Mirrors the
/// attack-pattern detector severities so the alertable gate is consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VisibilitySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl VisibilitySeverity {
    /// A finding is alertable (can trip a CI gate / score) only at HIGH or
    /// CRITICAL, mirroring `VulnerabilityReport::active_alertable_findings_count`.
    pub fn is_alertable(&self) -> bool {
        matches!(
            self,
            VisibilitySeverity::High | VisibilitySeverity::Critical
        )
    }
}

/// A deterministic finding produced by one of the visibility domains. The
/// `finding_key` is stable across ticks so the existing recurrence-aware
/// `AgenticDismissalRule` model (invariant I4) can suppress it without a
/// parallel exception store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityFinding {
    /// `<domain>:<rule_id>:<subject_id>` -- stable across ticks.
    pub finding_key: String,
    /// Domain that produced this finding (`mcp`, `sbom`, `graph`, `recursion`).
    pub domain: String,
    /// Deterministic rule identifier (e.g. `mcp_public_no_auth`).
    pub rule_id: String,
    pub severity: VisibilitySeverity,
    pub title: String,
    pub description: String,
    /// Stable identifier of the subject (endpoint id, agent id, edge id, ...).
    pub subject_id: String,
    /// Structured, metadata-only evidence (no secret values / file bodies).
    pub evidence: BTreeMap<String, String>,
}

impl VisibilityFinding {
    /// Construct a finding with the canonical `<domain>:<rule_id>:<subject_id>`
    /// stable key. `pub` so the explainability domain modules (drift, dataflow,
    /// memory, a2a, alignment) emit findings with the identical shape and the
    /// recurrence-aware `AgenticDismissalRule` model (invariant I4) suppresses
    /// them through the same path as the structural domains.
    pub fn new(
        domain: &str,
        rule_id: &str,
        severity: VisibilitySeverity,
        subject_id: &str,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            finding_key: format!("{}:{}:{}", domain, rule_id, subject_id),
            domain: domain.to_string(),
            rule_id: rule_id.to_string(),
            severity,
            title: title.into(),
            description: description.into(),
            subject_id: subject_id.to_string(),
            evidence: BTreeMap::new(),
        }
    }

    /// Attach one metadata-only evidence pair (no secret values / file bodies,
    /// invariant I5). `pub` for cross-domain reuse (see `new`).
    pub fn with_evidence(mut self, key: &str, value: impl Into<String>) -> Self {
        self.evidence.insert(key.to_string(), value.into());
        self
    }

    /// Attach the OWASP GenAI cross-reference tags for this finding's `rule_id`
    /// as a metadata-only `owasp_refs` evidence entry (no-op when the rule has
    /// no mapping). Labeling only: OWASP tags are metadata and never change a
    /// finding's severity, the alertable gate, or the finding key -- they are
    /// not a new alert source. Append `.with_owasp()` last in the builder chain
    /// at each emitter site so it tags whatever rule the finding carries.
    pub fn with_owasp(mut self) -> Self {
        if let Some(refs) = owasp_refs_for_rule(&self.rule_id) {
            self.evidence
                .insert("owasp_refs".to_string(), refs.to_string());
        }
        self
    }
}

/// Central mapping from a visibility `rule_id` to its OWASP GenAI
/// cross-reference tags (Agentic Security Initiative `ASI*` and LLM Top-10
/// `LLM*` identifiers). Metadata only: consumed by
/// `VisibilityFinding::with_owasp` to populate the `owasp_refs` evidence entry.
/// Returning `None` leaves a finding untagged rather than inventing a mapping.
/// Keep aligned with the mapping table in `edamame_core/OWASPGENAI.md`.
pub(crate) fn owasp_refs_for_rule(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        "drift_goal_divergence" | "drift_recursion_escalation" => {
            Some("OWASP-ASI01,OWASP-ASI10,OWASP-LLM01")
        }
        "cascading_failure" | "unbounded_consumption" => Some("OWASP-ASI08,OWASP-LLM10"),
        "dataflow_sensitive_egress" => Some("OWASP-ASI01,OWASP-ASI03,OWASP-LLM01,OWASP-LLM02"),
        "memory_poisoning_surface" => Some("OWASP-ASI06,OWASP-LLM04,OWASP-LLM08"),
        // Agent supply-chain drift: the agent's capability surface (MCP servers,
        // tool classes, secret bindings, instruction files) changed vs the
        // approved baseline -- the canonical "agentic supply chain" violation.
        "sbom_baseline_drift" => Some("OWASP-ASI02,OWASP-ASI04,OWASP-LLM03"),
        _ if rule_id.starts_with("mcp_") => Some("OWASP-ASI02,OWASP-ASI03,OWASP-LLM06"),
        _ if rule_id.starts_with("recursion_") => Some("OWASP-ASI08,OWASP-LLM10"),
        _ if rule_id.starts_with("a2a_") => Some("OWASP-ASI07,OWASP-ASI08"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// MCP endpoint inventory (INC-1)
// ---------------------------------------------------------------------------

/// Where an MCP endpoint is reachable from. Drives the deterministic risk
/// rules. The headline distinction is between an *inbound* exposure (a local
/// server this host listens on, reachable beyond loopback) and an *outbound*
/// connection (the agent is a client of a remote third-party / SaaS endpoint).
/// They are completely different risk profiles and MUST NOT be conflated: an
/// exposed local bind lets others reach into this machine, while a remote SaaS
/// endpoint is about third-party data egress + transport security.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureScope {
    /// stdio transport -- no network surface, child of the agent process.
    Stdio,
    /// Bound to loopback (127.0.0.0/8 / ::1 / localhost).
    Loopback,
    /// Bound to a private/LAN address or `.local` mDNS name.
    Lan,
    /// The agent connects OUT to a remote, public-internet endpoint -- a
    /// third-party / SaaS MCP server (e.g. `https://mcp.vendor.com`). This is an
    /// outbound client connection, NOT a server this host listens on. The risk
    /// is third-party data egress and transport security (cleartext vs TLS),
    /// not inbound reachability of this machine.
    Remote,
    /// A locally-run server bound to ALL interfaces (`0.0.0.0` / `[::]`),
    /// reachable inbound from the LAN or internet depending on host networking.
    /// This is the genuine "exposed beyond loopback" case.
    Public,
    Unknown,
}

/// Strength of the authentication guarding an MCP endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStrength {
    /// No discernible auth (no token env, no headers, no oauth).
    None,
    /// Shared secret (bearer token / API key in env or headers).
    Shared,
    /// OAuth 2.x (protected-resource metadata or `type: "oauth"`).
    OAuth,
    /// Mutual TLS (client cert + key present).
    Mtls,
    Unknown,
}

/// Coarse privilege class a server's tools likely expose. Derived from the
/// server name + command + url via keyword heuristics; refined by the LLM
/// later (deterministic-first, invariant I3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPrivilegeClass {
    Shell,
    FilesystemWrite,
    FilesystemRead,
    Browser,
    Git,
    Database,
    SecretAccess,
    Network,
    Unknown,
}

impl ToolPrivilegeClass {
    /// High-blast-radius classes that escalate an endpoint's risk when paired
    /// with weak auth or a non-loopback bind.
    pub fn is_high_privilege(&self) -> bool {
        matches!(
            self,
            ToolPrivilegeClass::Shell
                | ToolPrivilegeClass::FilesystemWrite
                | ToolPrivilegeClass::SecretAccess
                | ToolPrivilegeClass::Database
        )
    }

    /// Lowercased snake_case slug used to build stable node / bom-ref ids.
    pub fn slug(&self) -> &'static str {
        match self {
            ToolPrivilegeClass::Shell => "shell",
            ToolPrivilegeClass::FilesystemWrite => "filesystem_write",
            ToolPrivilegeClass::FilesystemRead => "filesystem_read",
            ToolPrivilegeClass::Browser => "browser",
            ToolPrivilegeClass::Git => "git",
            ToolPrivilegeClass::Database => "database",
            ToolPrivilegeClass::SecretAccess => "secret_access",
            ToolPrivilegeClass::Network => "network",
            ToolPrivilegeClass::Unknown => "unclassified",
        }
    }

    /// Human-readable label rendered in the UI / graph.
    pub fn label(&self) -> &'static str {
        match self {
            ToolPrivilegeClass::Shell => "Shell",
            ToolPrivilegeClass::FilesystemWrite => "Filesystem Write",
            ToolPrivilegeClass::FilesystemRead => "Filesystem Read",
            ToolPrivilegeClass::Browser => "Browser",
            ToolPrivilegeClass::Git => "Git",
            ToolPrivilegeClass::Database => "Database",
            ToolPrivilegeClass::SecretAccess => "Secret Access",
            ToolPrivilegeClass::Network => "Network",
            ToolPrivilegeClass::Unknown => "Unclassified",
        }
    }
}

/// One discovered MCP server entry, attributed to the agent whose config
/// declared it. Built from each agent's `config_targets` (the same file set
/// the transcript observer already watches) plus EDAMAME's own server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpEndpoint {
    /// Stable id: sha256(agent_type|server_name|transport|target)[..16].
    pub id: String,
    pub agent_type: String,
    /// Server key as written in the agent's MCP config map.
    pub server_name: String,
    /// `stdio` | `http` | `sse` | `ws` | `unknown`.
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub bind_host: Option<String>,
    pub exposure_scope: ExposureScope,
    pub auth_strength: AuthStrength,
    pub oauth_metadata_uri: Option<String>,
    pub tool_privilege_classes: Vec<ToolPrivilegeClass>,
    /// True when this is EDAMAME's own observer MCP server (the `server_key`
    /// from the agent definition). EDAMAME's own server is read-only and is
    /// never the subject of a risk finding.
    pub is_edamame_server: bool,
    /// Absolute path of the config file the entry was discovered in.
    pub config_path: String,
    /// Names (NOT values) of environment variables passed to the server.
    pub env_keys: Vec<String>,
}

/// Aggregate MCP inventory across all discovered agents on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpInventory {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub endpoints: Vec<McpEndpoint>,
    pub findings: Vec<VisibilityFinding>,
}

// ---------------------------------------------------------------------------
// Agent SBOM (INC-2) -- CycloneDX-shaped projection from live discovery
// ---------------------------------------------------------------------------

/// One component in the agent bill of materials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomComponent {
    /// Stable bom-ref used as the CycloneDX `bom-ref` and dependency key.
    pub bom_ref: String,
    /// CycloneDX component type: `application` | `service` | `data` |
    /// `machine-learning-model` | `file` | `library`.
    pub component_type: String,
    pub name: String,
    pub version: Option<String>,
    /// Content-addressed hash for `file` components (never the body, I5).
    pub content_hash: Option<String>,
    /// Extra metadata-only properties (transport, exposure, privilege, ...).
    pub properties: BTreeMap<String, String>,
}

/// A `depends_on`-style relationship between two components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SbomDependency {
    pub bom_ref: String,
    pub depends_on: Vec<String>,
}

/// Live-discovered bill of materials for a single agent instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSbom {
    pub agent_type: String,
    pub agent_instance_id: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub components: Vec<SbomComponent>,
    pub dependencies: Vec<SbomDependency>,
}

/// Diff of a current SBOM against an approved baseline (INC-2 drift).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SbomDiff {
    pub added: Vec<SbomComponent>,
    pub removed: Vec<SbomComponent>,
    /// bom_refs whose version or content hash changed.
    pub changed: Vec<String>,
    pub baseline_present: bool,
}

// ---------------------------------------------------------------------------
// Capability graph (INC-3)
// ---------------------------------------------------------------------------

/// Confidence in a capability-graph edge. `Declared` = config-only (latent
/// capability); `Observed` = corroborated by live telemetry (effective
/// capability). Foundation emits `Declared`; core upgrades to `Observed`
/// when a live flodbadd session corroborates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeConfidence {
    Declared,
    Observed,
}

/// A single edge in the agent capability graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    /// `agent` | `mcp_server` | `tool_class` | `network_endpoint` | `file` | `model`.
    pub src_type: String,
    /// Stable node id (`agent:<type>`, `mcp:<hash>`, `tool_class:<class>`, ...).
    /// Opaque on purpose -- the human-readable form is `src_label`.
    pub src_id: String,
    /// Human-readable label for the source node (agent type, MCP server name,
    /// capability label, host). The UI renders this; `src_id` stays stable for
    /// dedup/correlation. Populated by the builder so the client never has to
    /// resolve the opaque id (invariant I2: core is the source of truth).
    pub src_label: String,
    /// `declares` | `exposes` | `connects_to` | `reads_file` | `writes_file` | `uses_model`.
    pub edge_type: String,
    pub dst_type: String,
    pub dst_id: String,
    /// Human-readable label for the destination node (see `src_label`).
    pub dst_label: String,
    /// Trust zone of the source node (`trust0` | `trust1` | `trust2`). Computed
    /// deterministically from node type + exposure (INC-10, C3). `trust0` is the
    /// agent identity (innermost), `trust1` a local service boundary
    /// (stdio/loopback MCP servers, capability classes), `trust2` an untrusted
    /// surface (LAN/public binds, unknown hosts).
    pub src_zone: String,
    /// Trust zone of the destination node (see `src_zone`).
    pub dst_zone: String,
    pub confidence: EdgeConfidence,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Recursive / delegation detection (INC-4) -- transcript-derived tree
// ---------------------------------------------------------------------------

/// One node in an agent's delegation tree, reconstructed from the transcript's
/// sub-agent spawn markers. Depth comes from the JSONL record graph
/// (`uuid`/`parentUuid` linkage plus the `isSidechain` sub-agent flag) when the
/// transcript is JSONL, or from an indentation hint for plain-text transcripts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationNode {
    pub node_id: String,
    pub agent_type: String,
    pub agent_instance_id: String,
    /// Depth from the root agent run (root = 0).
    pub delegation_depth: u32,
    /// Why the child was spawned (the tool/command marker that triggered it).
    pub spawn_reason: Option<String>,
    /// Hash of the repeated goal tokens -- equal hashes at increasing depth
    /// indicate a same-purpose recursion loop.
    pub loop_hash: Option<String>,
    pub children: Vec<DelegationNode>,
}

/// Delegation tree + derived recursion-risk signals for one agent instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationTree {
    pub agent_type: String,
    pub agent_instance_id: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub root: DelegationNode,
    pub max_depth: u32,
    pub total_nodes: u32,
    /// True when a repeated goal hash recurs at increasing depth.
    pub loop_detected: bool,
    pub findings: Vec<VisibilityFinding>,
}

// ---------------------------------------------------------------------------
// Host blast radius (INC-7): host-level privilege + per-agent OS confinement
// ---------------------------------------------------------------------------

/// Host-level privilege assessment shared by every agent on this machine. An
/// agent inherits the privileges of the user session that launched it, so this
/// answers: "if any agent on this host is compromised, what can it reach
/// without further authentication?". Computed on the privileged side
/// (standalone core or the helper daemon) where `/etc/sudoers` and group
/// membership are readable; the target user is derived from the home directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPrivilege {
    /// The login session is already root / an elevated administrator.
    pub elevated_session: bool,
    /// The login user is an administrator: member of `admin`/`sudo`/`wheel` on
    /// unix, or the Administrators group on Windows.
    pub admin_user: bool,
    /// The login user can become root WITHOUT a password -- a `NOPASSWD`
    /// sudoers rule on unix. (Windows UAC elevation policy is not assessed, so
    /// this stays `false` there.)
    pub passwordless_root: bool,
    /// Short human-readable evidence lines (e.g. the matched sudoers rule, the
    /// admin group, the integrity level).
    pub evidence: Vec<String>,
    /// OS family that produced the assessment (`macos`/`linux`/`windows`).
    pub platform: String,
    /// The user the assessment targets (derived from the home directory).
    pub user: String,
    /// `false` when the assessment could not be performed (unsupported platform
    /// or unreadable privilege config) -- the booleans are then not a claim.
    pub assessed: bool,
}

/// Per-agent OS-confinement ("sandbox") assessment. Most workstation coding
/// agents run unconfined with the user's full file access; that is itself the
/// high-signal case -- an unsandboxed agent combined with passwordless root is
/// the maximum host blast radius. Positive confinement (app-sandbox container,
/// snap/flatpak) is detected from on-disk evidence where present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSandbox {
    pub agent_type: String,
    /// `Some(true)` = OS-confined, `Some(false)` = unconfined, `None` =
    /// could not be determined on this platform.
    pub sandboxed: Option<bool>,
    /// Confinement mechanism (`app-sandbox`, `snap`, `flatpak`, `none`,
    /// `unknown`).
    pub mechanism: String,
    /// Human-readable detail line for the UI.
    pub detail: String,
    /// Coarse filesystem reach: `user_files`, `sandbox_container`, or
    /// `unknown`. This is OS-level reach, not a claim about what the LLM is
    /// instructed to touch.
    pub file_access_scope: String,
    /// Human-readable filesystem reach detail.
    pub file_access_detail: String,
    /// OS-level ability for the agent process to spawn arbitrary host commands
    /// as the same user. `None` means a sandbox exists but exact exec
    /// entitlement/capability policy was not parsed.
    pub can_launch_arbitrary_commands: Option<bool>,
    /// Human-readable process-launch detail.
    pub command_execution_detail: String,
}

fn build_agent_sandbox(
    agent_type: String,
    sandboxed: Option<bool>,
    mechanism: &str,
    detail: String,
) -> AgentSandbox {
    let (
        file_access_scope,
        file_access_detail,
        can_launch_arbitrary_commands,
        command_execution_detail,
    ) = match sandboxed {
        Some(true) => (
            "sandbox_container",
            "Limited to the app sandbox/container plus explicitly granted folders",
            None,
            "Confinement detected; exact process-launch entitlement was not parsed",
        ),
        Some(false) => (
            "user_files",
            "Can read/write user files and any ACL-permitted folders",
            Some(true),
            "Unconfined desktop process can spawn executables as this user",
        ),
        None => (
            "unknown",
            "Filesystem reach not assessed on this platform",
            None,
            "Process-launch permission not assessed on this platform",
        ),
    };
    AgentSandbox {
        agent_type,
        sandboxed,
        mechanism: mechanism.to_string(),
        detail,
        file_access_scope: file_access_scope.to_string(),
        file_access_detail: file_access_detail.to_string(),
        can_launch_arbitrary_commands,
        command_execution_detail: command_execution_detail.to_string(),
    }
}

/// One present, OS-unconfined agent whose compromise would carry outsized host
/// blast radius. INC-7 aggregate signal feeding the `agents_with_blast_radius`
/// internal threat. An agent qualifies when it runs unsandboxed AND at least
/// one privilege amplifier applies:
/// - the host grants the agent's user passwordless root (a `NOPASSWD` sudoers
///   rule), so a compromised agent can become root with no prompt; and/or
/// - the agent has already been observed spawning a `Critical` subprocess
///   (ssh/scp/nc/socat/docker/...), i.e. it can reach off-box or open a shell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusAgent {
    pub agent_type: String,
    /// The agent is OS-unconfined (`AgentSandbox.sandboxed == Some(false)`).
    pub unsandboxed: bool,
    /// The host grants the agent's user passwordless root.
    pub passwordless_root: bool,
    /// The agent has been observed spawning a `Critical` subprocess.
    pub critical_subprocess: bool,
    /// Short human-readable reasons (for the UI / threat description).
    pub reasons: Vec<String>,
}

/// Pure host blast-radius rule (INC-7). Given the host privilege assessment,
/// the per-agent OS-confinement rows (already filtered to agents actually
/// present on the host by the caller), and a map of `agent_type -> Critical
/// subprocess observation count`, return the agents whose compromise would have
/// outsized host reach: unsandboxed AND (passwordless root OR an observed
/// `Critical` subprocess). Deterministic, sorted by `agent_type`.
///
/// The host-level `passwordless_root` applies to every agent on the host (they
/// all inherit the launching user's session), so it is the same amplifier for
/// each candidate; the per-agent `Critical` subprocess count is the
/// agent-specific amplifier. A positively OS-confined (or unassessed) agent
/// never qualifies regardless of host privilege, because the OS sandbox bounds
/// its reach.
pub fn agents_with_blast_radius(
    host_privilege: &HostPrivilege,
    agent_sandboxes: &[AgentSandbox],
    critical_subprocess_by_agent: &BTreeMap<String, u32>,
) -> Vec<BlastRadiusAgent> {
    // Only a positively-assessed passwordless-root host counts as the amplifier
    // (an unassessed host must not be treated as privileged).
    let passwordless_root = host_privilege.assessed && host_privilege.passwordless_root;
    let mut out: Vec<BlastRadiusAgent> = Vec::new();
    for sandbox in agent_sandboxes {
        // Only OS-unconfined agents have host blast radius; a positively
        // confined (`Some(true)`) or unassessed (`None`) agent is bounded by
        // its sandbox / not a claim.
        if sandbox.sandboxed != Some(false) {
            continue;
        }
        let critical_subprocess = critical_subprocess_by_agent
            .get(&sandbox.agent_type)
            .copied()
            .unwrap_or(0)
            > 0;
        if !passwordless_root && !critical_subprocess {
            continue;
        }
        let mut reasons: Vec<String> = vec!["unsandboxed (full user-file access)".to_string()];
        if passwordless_root {
            reasons.push("passwordless root on host".to_string());
        }
        if critical_subprocess {
            reasons.push("observed critical subprocess (ssh/nc/docker/...)".to_string());
        }
        out.push(BlastRadiusAgent {
            agent_type: sandbox.agent_type.clone(),
            unsandboxed: true,
            passwordless_root,
            critical_subprocess,
            reasons,
        });
    }
    out.sort_by(|a, b| a.agent_type.cmp(&b.agent_type));
    out
}

// ---------------------------------------------------------------------------
// Agent governance harness presence (AI-SDLC posture)
// ---------------------------------------------------------------------------

/// A known agent-governance "harness" / control-plane product and whether its
/// per-user footprint is present on this host. A harness is the AI-SDLC control
/// layer that wraps coding agents with policy enforcement, cryptographic
/// identity, guardrails (budgets / turn caps / tool allow-lists), and an audit
/// trail -- so a redirected or compromised agent is bounded and provable rather
/// than running bare. Detection is a cross-platform *presence* signal (the
/// product's standard per-user config directory and/or CLI binary), not a deep
/// configuration assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHarness {
    /// Stable lowercase product slug (`agentfield`, `rippletide`, ...).
    pub slug: String,
    /// Human-readable product name for the UI.
    pub display_name: String,
    /// Whether the product's footprint was found on this host for this user.
    pub detected: bool,
    /// The on-disk markers / binaries that matched (display paths / names),
    /// for the UI and threat evidence. Empty when `detected` is false.
    pub evidence: Vec<String>,
}

/// Known agent harnesses with a detectable, cross-platform per-user footprint.
/// Each row is `(slug, display_name, extra_markers, binaries)`:
/// - `slug` also drives the standard per-user config locations checked
///   automatically: `~/.{slug}`, `~/.config/{slug}`, (macOS)
///   `~/Library/Application Support/{slug}`, and (Windows)
///   `~/AppData/Roaming/{slug}` + `~/AppData/Local/{slug}`.
/// - `extra_markers` are additional `$HOME`-relative files/dirs to check.
/// - `binaries` are CLI names looked up in the standard per-user bin dirs (so
///   the helper-as-root path finds a user-installed binary) and on `$PATH`.
///
/// Kept deliberately small and limited to products we can actually detect on
/// macOS/Windows/Linux from a per-user on-disk footprint. Extend by adding a
/// row. Cloud-only control planes with no local footprint (a pure SaaS
/// dashboard) are intentionally out of scope: there is nothing on the host to
/// detect, so claiming detection would be dishonest.
const KNOWN_AGENT_HARNESSES: &[(&str, &str, &[&str], &[&str])] = &[
    // AgentField (agentfield.ai): open-source agent control plane / harness.
    // The `af` CLI scaffolds projects; `app.harness(...)` dispatches governed
    // multi-turn coding tasks to Claude Code / Codex / Gemini CLI / OpenCode
    // with budgets, turn caps, tool allow-lists, W3C-DID identity, and audit
    // trails.
    ("agentfield", "AgentField", &[".af"], &["agentfield", "af"]),
    // Rippletide (rippletide.com): decision-runtime / policy-enforcement layer
    // that validates every proposed agent action against business rules before
    // it executes (local SDK + CLI footprint).
    ("rippletide", "Rippletide", &[], &["rippletide"]),
];

/// Standard per-user "bin" directories (relative to `$HOME`) where a harness
/// CLI may live without being on the privileged process's `$PATH` -- so the
/// helper running as root can still find a binary the user installed under
/// their own home. The list is checked unconditionally on every OS; `/` is a
/// valid path separator on Windows for `Path::join`, so the Windows-relative
/// entries resolve there and are harmless no-ops on Unix.
const HARNESS_HOME_BIN_DIRS: &[&str] = &[
    ".local/bin",
    "bin",
    ".cargo/bin",
    "go/bin",
    ".npm-global/bin",
    ".bun/bin",
    ".deno/bin",
    // Windows-native per-user bin locations: npm's global prefix is
    // %APPDATA%\npm (the shims sit directly there, no `bin` subdir); winget /
    // Store execution aliases live under %LOCALAPPDATA%\Microsoft\WindowsApps.
    "AppData/Roaming/npm",
    "AppData/Local/Microsoft/WindowsApps",
];

/// Render a path for evidence relative to `home` when possible (`~/...`) so the
/// UI / threat text is compact and does not leak the absolute home prefix.
fn harness_display_path(home: &Path, p: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.to_string_lossy()),
        Err(_) => p.to_string_lossy().to_string(),
    }
}

/// Directories on the process `$PATH` (best-effort; mainly helps the standalone
/// posture-as-user path -- the helper-as-root path relies on the home bin dirs).
fn harness_path_dirs() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default()
}

/// Candidate executable file names for `bin` on this OS (Windows adds the common
/// executable extensions).
fn harness_binary_names(bin: &str) -> Vec<String> {
    if cfg!(target_os = "windows") {
        vec![
            format!("{bin}.exe"),
            format!("{bin}.cmd"),
            format!("{bin}.bat"),
            bin.to_string(),
        ]
    } else {
        vec![bin.to_string()]
    }
}

/// Look for harness CLI `bin` in the per-user home bin dirs and on `$PATH`.
/// Returns a display string for the first match (for evidence).
fn find_harness_binary(home: &Path, path_dirs: &[PathBuf], bin: &str) -> Option<String> {
    let names = harness_binary_names(bin);
    for rel in HARNESS_HOME_BIN_DIRS {
        let dir = home.join(rel);
        for name in &names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(harness_display_path(home, &candidate));
            }
        }
    }
    for dir in path_dirs {
        for name in &names {
            if dir.join(name).is_file() {
                return Some(format!("{bin} (on PATH)"));
            }
        }
    }
    None
}

/// Detect which known agent harnesses are present for the given user `home`.
/// Cross-platform and read-only (filesystem existence + `$PATH` probing). Both
/// the standalone core and the helper converge here (the helper passes the
/// target user's home so a root-side scan still resolves the user's footprint).
/// Returns one entry per known harness (detected or not), sorted by slug.
pub fn detect_agent_harnesses(home: &Path) -> Vec<AgentHarness> {
    detect_agent_harnesses_with(home, &harness_path_dirs())
}

/// `detect_agent_harnesses` with an explicit `$PATH` directory list so unit
/// tests are deterministic regardless of the host's real `$PATH`.
fn detect_agent_harnesses_with(home: &Path, path_dirs: &[PathBuf]) -> Vec<AgentHarness> {
    let mut out: Vec<AgentHarness> = KNOWN_AGENT_HARNESSES
        .iter()
        .map(|(slug, display, extra, binaries)| {
            let mut evidence: Vec<String> = Vec::new();

            // Standard per-user config locations for this slug.
            let mut markers: Vec<PathBuf> = vec![
                home.join(format!(".{slug}")),
                home.join(".config").join(slug),
                home.join("Library").join("Application Support").join(slug),
                // Windows-native per-user config dirs (%APPDATA% / %LOCALAPPDATA%).
                // Checked unconditionally like the macOS path above; harmless
                // no-ops on Unix where these directories do not exist.
                home.join("AppData").join("Roaming").join(slug),
                home.join("AppData").join("Local").join(slug),
            ];
            for m in *extra {
                markers.push(home.join(m));
            }
            for m in &markers {
                if m.exists() {
                    evidence.push(harness_display_path(home, m));
                }
            }

            // CLI binary (home bin dirs first for the helper-as-root case).
            for bin in *binaries {
                if let Some(found) = find_harness_binary(home, path_dirs, bin) {
                    evidence.push(found);
                }
            }

            evidence.sort();
            evidence.dedup();
            AgentHarness {
                slug: (*slug).to_string(),
                display_name: (*display).to_string(),
                detected: !evidence.is_empty(),
                evidence,
            }
        })
        .collect();
    out.sort_by(|a, b| a.slug.cmp(&b.slug));
    out
}

/// AI-SDLC posture rule: the host is "running AI agents without a
/// governance harness" when at least one agent is present/discovered on the host
/// AND no known harness is detected. This is a posture *gap* signal -- the
/// common workstation default is no harness, which is exactly the gap to
/// surface -- and it clears as soon as any recognized harness (AgentField,
/// Rippletide, ...) is installed for the user. Deterministic and pure so it is
/// unit-testable without touching disk.
pub fn agents_without_harness(discovered_agent_count: usize, harnesses: &[AgentHarness]) -> bool {
    discovered_agent_count > 0 && !harnesses.iter().any(|h| h.detected)
}

/// Derive the target username from a home directory path
/// (`/Users/alice` -> `alice`, `/home/bob` -> `bob`, `C:\\Users\\carol` ->
/// `carol`). Robust regardless of which user the privileged process runs as.
fn user_from_home(home: &Path) -> String {
    home.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Pure parse of an `/etc/group` body into the list of group names `user`
/// belongs to via the trailing member list. Extracted so the policy logic is
/// testable without touching the real filesystem.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn groups_for_user(group_file: &str, user: &str) -> Vec<String> {
    let mut groups = Vec::new();
    for line in group_file.lines() {
        // Format: name:passwd:gid:member1,member2,...
        let mut parts = line.splitn(4, ':');
        let gname = parts.next().unwrap_or("");
        let _passwd = parts.next();
        let _gid = parts.next();
        let members = parts.next().unwrap_or("");
        if !gname.is_empty() && members.split(',').any(|m| m.trim() == user) {
            groups.push(gname.to_string());
        }
    }
    groups
}

/// Pure scan of a sudoers policy body for `NOPASSWD` rules whose principal is
/// the user, `ALL`, or one of the `%group` principals the user belongs to.
/// Returns the matching principals (for evidence). Comment and blank lines are
/// skipped; `Defaults`/alias lines never have a principal in column 0 so they
/// are naturally ignored.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn scan_sudoers_nopasswd(text: &str, user: &str, group_principals: &[String]) -> Vec<String> {
    let mut hits = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains("NOPASSWD") {
            continue;
        }
        let principal = line.split_whitespace().next().unwrap_or("");
        if principal.is_empty() || principal == "Defaults" {
            continue;
        }
        let applies = principal == user
            || principal == "ALL"
            || group_principals.iter().any(|g| g == principal);
        if applies {
            hits.push(principal.to_string());
        }
    }
    hits
}

/// macOS/Linux host-privilege assessment, file-based (no process spawn). Reads
/// `/etc/group` for admin membership and `/etc/sudoers`(+`.d/*`) for a
/// `NOPASSWD` rule that applies to the user, a group the user is in, or `ALL`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn assess_host_privilege(home: &Path) -> HostPrivilege {
    let user = user_from_home(home);
    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
    .to_string();
    let mut evidence: Vec<String> = Vec::new();

    // The assessment is about the *user's* session, not the helper's: report an
    // elevated session only when the target user itself is root.
    let elevated_session = user == "root";
    if elevated_session {
        evidence.push("session runs as root".to_string());
    }

    // Admin membership + the groups the user belongs to (drives the sudoers
    // `%group` match below). On macOS admins live in the `admin` group; on
    // Linux the sudo-granting groups are `sudo`/`wheel`/`admin`.
    let admin_groups: &[&str] = if cfg!(target_os = "macos") {
        &["admin"]
    } else {
        &["sudo", "wheel", "admin"]
    };
    let mut admin_user = elevated_session;
    let mut user_groups: Vec<String> = Vec::new();
    if let Ok(group_file) = std::fs::read_to_string("/etc/group") {
        user_groups = groups_for_user(&group_file, &user);
        for g in &user_groups {
            if admin_groups.contains(&g.as_str()) {
                admin_user = true;
                evidence.push(format!("member of '{}' group", g));
            }
        }
    }

    // Passwordless sudo: scan the sudoers policy for a NOPASSWD rule whose
    // principal is the user, a `%group` the user belongs to, or `ALL`.
    let mut passwordless_root = false;
    let mut sudoers_readable = false;
    let mut sources: Vec<PathBuf> = vec![PathBuf::from("/etc/sudoers")];
    if let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file() {
                sources.push(p);
            }
        }
    }
    let group_principals: Vec<String> = user_groups.iter().map(|g| format!("%{}", g)).collect();
    for src in &sources {
        let Ok(text) = std::fs::read_to_string(src) else {
            continue;
        };
        sudoers_readable = true;
        let where_ = src
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "sudoers".to_string());
        // A single sudoers drop-in legitimately carries many NOPASSWD command
        // rules for the same principal (one per allowed command). Collapse them
        // to one evidence line per (principal, file) with a rule count so the
        // panel shows the signal once instead of flooding with identical lines.
        let mut counts: Vec<(String, usize)> = Vec::new();
        for principal in scan_sudoers_nopasswd(&text, &user, &group_principals) {
            passwordless_root = true;
            if let Some(entry) = counts.iter_mut().find(|(p, _)| p == &principal) {
                entry.1 += 1;
            } else {
                counts.push((principal, 1));
            }
        }
        for (principal, count) in counts {
            if count > 1 {
                evidence.push(format!(
                    "NOPASSWD for '{}' in {} ({} rules)",
                    principal, where_, count
                ));
            } else {
                evidence.push(format!("NOPASSWD for '{}' in {}", principal, where_));
            }
        }
    }
    if !sudoers_readable {
        evidence.push(
            "sudoers not readable (run with elevated access to assess passwordless sudo)"
                .to_string(),
        );
    }

    HostPrivilege {
        elevated_session,
        admin_user,
        passwordless_root,
        evidence,
        platform,
        user,
        assessed: true,
    }
}

/// Windows host-privilege assessment, best-effort via `whoami /groups`
/// (spawned with `CREATE_NO_WINDOW` so no console flashes). Detects the
/// Administrators SID and the High integrity level. UAC elevation policy is
/// not parsed, so `passwordless_root` stays `false`.
#[cfg(target_os = "windows")]
fn assess_host_privilege(home: &Path) -> HostPrivilege {
    let user = user_from_home(home);
    let mut evidence: Vec<String> = Vec::new();
    let mut admin_user = false;
    let mut elevated_session = false;

    let mut cmd = std::process::Command::new("whoami");
    cmd.arg("/groups");
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    if let Ok(out) = cmd.output() {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("S-1-5-32-544") {
            admin_user = true;
            evidence.push("member of Administrators group".to_string());
        }
        if text.contains("S-1-16-12288") {
            elevated_session = true;
            evidence.push("running at High integrity (elevated)".to_string());
        }
    }
    evidence.push("UAC elevation policy not assessed".to_string());

    HostPrivilege {
        elevated_session,
        admin_user,
        passwordless_root: false,
        evidence,
        platform: "windows".to_string(),
        user,
        assessed: true,
    }
}

/// Fallback host-privilege assessment for platforms where agents never run
/// (iOS/Android): no claim is made (`assessed = false`), no process spawned.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn assess_host_privilege(home: &Path) -> HostPrivilege {
    HostPrivilege {
        elevated_session: false,
        admin_user: false,
        passwordless_root: false,
        evidence: Vec::new(),
        platform: std::env::consts::OS.to_string(),
        user: user_from_home(home),
        assessed: false,
    }
}

/// Per-agent OS-confinement assessment for every supported agent (registry
/// loop, so coverage tracks the full supported set including agents that have
/// no MCP config).
fn assess_agent_sandboxes(home: &Path) -> Vec<AgentSandbox> {
    supported_agents::ordered_supported_agents()
        .iter()
        .map(|def| assess_one_agent_sandbox(def, home))
        .collect()
}

/// macOS confinement: an App-sandboxed app owns a container directory under
/// `~/Library/Containers/<bundle-id>/`. A container exists only when the app
/// declared `com.apple.security.app-sandbox`, so its presence is positive
/// evidence of confinement. Dev agents (Cursor, Claude Desktop, ...) are
/// Electron apps with no container, so they correctly report unconfined.
#[cfg(target_os = "macos")]
fn assess_one_agent_sandbox(
    def: &supported_agents::SupportedAgentDefinition,
    home: &Path,
) -> AgentSandbox {
    let token = def
        .agent_type
        .split('_')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let containers = home.join("Library/Containers");
    if let Ok(entries) = std::fs::read_dir(&containers) {
        for e in entries.flatten() {
            let raw = e.file_name();
            let name = raw.to_string_lossy().to_ascii_lowercase();
            if !token.is_empty() && name.contains(&token) {
                return build_agent_sandbox(
                    def.agent_type.clone(),
                    Some(true),
                    "app-sandbox",
                    format!("App-sandbox container present ({})", raw.to_string_lossy()),
                );
            }
        }
    }
    build_agent_sandbox(
        def.agent_type.clone(),
        Some(false),
        "none",
        "Unsandboxed - full access to your user files".to_string(),
    )
}

/// Linux confinement: flatpak apps store per-app data under
/// `~/.var/app/<app-id>/`, snap under `~/snap/<name>/`. Either implies the
/// runtime confines the app. Otherwise the agent runs unconfined.
#[cfg(target_os = "linux")]
fn assess_one_agent_sandbox(
    def: &supported_agents::SupportedAgentDefinition,
    home: &Path,
) -> AgentSandbox {
    let token = def
        .agent_type
        .split('_')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    for (subdir, mechanism) in [(".var/app", "flatpak"), ("snap", "snap")] {
        if let Ok(entries) = std::fs::read_dir(home.join(subdir)) {
            for e in entries.flatten() {
                let raw = e.file_name();
                let name = raw.to_string_lossy().to_ascii_lowercase();
                if !token.is_empty() && name.contains(&token) {
                    return build_agent_sandbox(
                        def.agent_type.clone(),
                        Some(true),
                        mechanism,
                        format!("{}-confined ({})", mechanism, raw.to_string_lossy()),
                    );
                }
            }
        }
    }
    build_agent_sandbox(
        def.agent_type.clone(),
        Some(false),
        "none",
        "Unsandboxed - full access to your user files".to_string(),
    )
}

/// Windows / fallback confinement. Win32 desktop dev tools are not
/// UWP-sandboxed (reported unconfined); on platforms where agents never run
/// (iOS/Android) no claim is made.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn assess_one_agent_sandbox(
    def: &supported_agents::SupportedAgentDefinition,
    _home: &Path,
) -> AgentSandbox {
    #[cfg(target_os = "windows")]
    {
        build_agent_sandbox(
            def.agent_type.clone(),
            Some(false),
            "none",
            "Win32 desktop app - not UWP/AppContainer-sandboxed".to_string(),
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        build_agent_sandbox(
            def.agent_type.clone(),
            None,
            "unknown",
            "Sandbox status not assessed on this platform".to_string(),
        )
    }
}

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

pub(crate) fn short_hash(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let full = hex::encode(hasher.finalize());
    full[..16].to_string()
}

fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// MCP discovery + classifiers (INC-1)
// ---------------------------------------------------------------------------

/// Build the full MCP inventory for the host: discover every endpoint from
/// every supported agent's config targets, then run the deterministic risk
/// rules. This is the public entry point both the standalone and helper
/// paths converge on.
pub fn build_mcp_inventory(home: &Path) -> McpInventory {
    let endpoints = discover_mcp_endpoints(home);
    let findings = assess_mcp_risk(&endpoints);
    McpInventory {
        generated_at: chrono::Utc::now(),
        endpoints,
        findings,
    }
}

/// Combined output of the structural visibility domains (MCP inventory, agent
/// SBOMs, capability graph) for one host. Built from a single endpoint
/// discovery pass so the helper crosses the sandbox boundary only once.
///
/// Recursion / delegation (INC-4) is NOT part of the bundle: it derives from
/// transcript bodies that core already collects via `collect_agent_transcripts`,
/// so core computes it from that existing payload rather than re-reading disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityBundle {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub inventory: McpInventory,
    pub sboms: Vec<AgentSbom>,
    pub graph_edges: Vec<GraphEdge>,
    /// Host-level privilege (INC-7): the blast radius every agent inherits from
    /// the user session. Shared across all agents on this host.
    pub host_privilege: HostPrivilege,
    /// Per-agent OS confinement (INC-7), one entry per supported agent type.
    pub agent_sandboxes: Vec<AgentSandbox>,
    /// Agent governance harnesses (AI-SDLC control plane) detected on this host,
    /// one entry per known harness. All-undetected means agents here
    /// run without a harness (the `agents_without_harness` gap).
    pub harnesses: Vec<AgentHarness>,
}

/// Build the full structural visibility bundle for a host in a single
/// endpoint-discovery pass. Shared by the standalone core path (direct call)
/// and the helper path (`utility_collect_agent_visibility`).
pub fn build_visibility_bundle(home: &Path) -> VisibilityBundle {
    let now = chrono::Utc::now();
    let endpoints = discover_mcp_endpoints(home);
    let findings = assess_mcp_risk(&endpoints);
    let sboms = build_agent_sboms_from_endpoints_with_home(&endpoints, Some(home));
    let graph_edges = build_capability_graph_from_endpoints(&endpoints);
    let host_privilege = assess_host_privilege(home);
    let agent_sandboxes = assess_agent_sandboxes(home);
    let harnesses = detect_agent_harnesses(home);
    let inventory = McpInventory {
        generated_at: now,
        endpoints,
        findings,
    };
    VisibilityBundle {
        generated_at: now,
        inventory,
        sboms,
        graph_edges,
        host_privilege,
        agent_sandboxes,
        harnesses,
    }
}

/// Discover MCP endpoints declared by every supported agent's config targets
/// plus EDAMAME's own server key. JSON config formats (Cursor `mcp.json`,
/// Claude `.claude.json`, Claude Desktop config) are parsed fully; TOML
/// (Codex) and YAML (Hermes) configs are parsed with a tolerant line scan so
/// at least server names/commands surface without pulling in toml/yaml deps.
pub fn discover_mcp_endpoints(home: &Path) -> Vec<McpEndpoint> {
    let mut endpoints = Vec::new();
    for def in supported_agents::ordered_supported_agents() {
        let server_key = def.mcp_server_key().map(|s| s.to_string());
        for config_path in def.resolve_global_mcp_configs(home) {
            if !config_path.exists() {
                continue;
            }
            let raw = match std::fs::read_to_string(&config_path) {
                Ok(text) => text,
                Err(_) => continue,
            };
            let path_str = config_path.to_string_lossy().to_string();
            let servers = parse_mcp_config(&raw, &path_str);
            for server in servers {
                let is_edamame = server_key
                    .as_deref()
                    .map(|key| server.name == key)
                    .unwrap_or(false);
                endpoints.push(build_endpoint(
                    &def.agent_type,
                    server,
                    &path_str,
                    is_edamame,
                ));
            }
        }
    }
    endpoints
}

/// Intermediate parsed server entry (format-agnostic).
struct RawMcpServer {
    name: String,
    command: Option<String>,
    args: Vec<String>,
    url: Option<String>,
    env_keys: Vec<String>,
    explicit_type: Option<String>,
    has_auth_header: bool,
    has_oauth: bool,
    has_tls_client_cert: bool,
}

fn build_endpoint(
    agent_type: &str,
    server: RawMcpServer,
    config_path: &str,
    is_edamame: bool,
) -> McpEndpoint {
    let transport = classify_transport(&server);
    let bind_host = server.url.as_deref().and_then(extract_host);
    let exposure_scope = classify_exposure(&transport, bind_host.as_deref());
    // Auth + privilege are classified from the raw server (inline-credential
    // detection needs the original query string); the stored URL is redacted
    // afterwards so the secret value never leaves this function (invariant I5).
    let auth_strength = classify_auth(&server);
    let tool_privilege_classes = classify_tool_privileges(&server);
    let redacted_url = server.url.as_deref().map(redact_url_credentials);
    let id = short_hash(&format!(
        "{}|{}|{}|{}",
        agent_type,
        server.name,
        transport,
        redacted_url
            .as_deref()
            .or(server.command.as_deref())
            .unwrap_or("")
    ));
    let oauth_metadata_uri = if server.has_oauth {
        server
            .url
            .as_deref()
            .and_then(extract_host)
            .map(|host| format!("https://{}/.well-known/oauth-protected-resource", host))
    } else {
        None
    };
    McpEndpoint {
        id,
        agent_type: agent_type.to_string(),
        server_name: server.name,
        transport,
        command: server.command,
        args: server.args,
        url: redacted_url,
        bind_host,
        exposure_scope,
        auth_strength,
        oauth_metadata_uri,
        tool_privilege_classes,
        is_edamame_server: is_edamame,
        config_path: config_path.to_string(),
        env_keys: server.env_keys,
    }
}

/// Dispatch config parsing on file extension. JSON is authoritative; TOML and
/// YAML use a tolerant scan.
fn parse_mcp_config(raw: &str, path: &str) -> Vec<RawMcpServer> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".toml") {
        parse_mcp_toml(raw)
    } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        parse_mcp_yaml(raw)
    } else {
        parse_mcp_json(raw)
    }
}

/// Parse JSON MCP configs. Handles both the top-level `mcpServers` object
/// (Cursor / Claude Desktop) and Claude's per-project `projects.<path>.mcpServers`.
fn parse_mcp_json(raw: &str) -> Vec<RawMcpServer> {
    let value: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut servers = Vec::new();
    if let Some(map) = value.get("mcpServers").and_then(|v| v.as_object()) {
        for (name, entry) in map {
            servers.push(parse_json_server(name, entry));
        }
    }
    if let Some(projects) = value.get("projects").and_then(|v| v.as_object()) {
        for (_proj, proj_val) in projects {
            if let Some(map) = proj_val.get("mcpServers").and_then(|v| v.as_object()) {
                for (name, entry) in map {
                    servers.push(parse_json_server(name, entry));
                }
            }
        }
    }
    servers
}

fn parse_json_server(name: &str, entry: &serde_json::Value) -> RawMcpServer {
    let command = entry
        .get("command")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let args = entry
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let url = entry
        .get("url")
        .or_else(|| entry.get("serverUrl"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let env_keys = entry
        .get("env")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let explicit_type = entry
        .get("type")
        .or_else(|| entry.get("transport"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_lowercase());
    let headers_obj = entry.get("headers").and_then(|v| v.as_object());
    let has_auth_header = headers_obj
        .map(|h| {
            h.keys().any(|k| {
                let kl = k.to_ascii_lowercase();
                kl == "authorization" || kl.contains("api-key") || kl.contains("token")
            })
        })
        .unwrap_or(false);
    let has_oauth = explicit_type.as_deref() == Some("oauth")
        || entry.get("oauth").is_some()
        || entry.get("authorization_server").is_some();
    let has_tls_client_cert = entry.get("clientCert").is_some()
        || entry.get("tlsClientCert").is_some()
        || entry.get("cert").is_some();
    RawMcpServer {
        name: name.to_string(),
        command,
        args,
        url,
        env_keys,
        explicit_type,
        has_auth_header,
        has_oauth,
        has_tls_client_cert,
    }
}

/// Tolerant TOML scan for Codex `[mcp_servers.NAME]` sections. Avoids a `toml`
/// dependency; extracts server name + command + url + env keys best-effort.
fn parse_mcp_toml(raw: &str) -> Vec<RawMcpServer> {
    let mut servers: Vec<RawMcpServer> = Vec::new();
    let mut current: Option<RawMcpServer> = None;
    let mut in_env = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("[mcp_servers.") {
            let inner = rest.trim_end_matches(']');
            // `[mcp_servers.NAME.env]` is the env subtable for NAME, NOT a new
            // server. Keep the current server open and switch to env mode.
            if inner.ends_with(".env") {
                in_env = true;
                continue;
            }
            // A genuinely new server section.
            if let Some(server) = current.take() {
                servers.push(server);
            }
            let name = inner.trim_matches('"').to_string();
            current = Some(RawMcpServer {
                name,
                command: None,
                args: Vec::new(),
                url: None,
                env_keys: Vec::new(),
                explicit_type: None,
                has_auth_header: false,
                has_oauth: false,
                has_tls_client_cert: false,
            });
            in_env = false;
            continue;
        }
        if trimmed.starts_with('[') {
            // Any other table ends the current server.
            if let Some(server) = current.take() {
                servers.push(server);
            }
            in_env = false;
            continue;
        }
        if let Some(server) = current.as_mut() {
            if in_env {
                if let Some((key, _)) = trimmed.split_once('=') {
                    let key = key.trim().trim_matches('"');
                    if !key.is_empty() {
                        server.env_keys.push(key.to_string());
                    }
                }
                continue;
            }
            if let Some((key, val)) = trimmed.split_once('=') {
                let key = key.trim();
                let val = val.trim().trim_matches('"');
                match key {
                    "command" => server.command = Some(val.to_string()),
                    "url" => server.url = Some(val.to_string()),
                    _ => {}
                }
            }
        }
    }
    if let Some(server) = current.take() {
        servers.push(server);
    }
    servers
}

/// Tolerant YAML scan for Hermes `mcp_servers:` block. Avoids a `serde_yaml`
/// dependency; extracts server name + command + url best-effort by indentation.
fn parse_mcp_yaml(raw: &str) -> Vec<RawMcpServer> {
    let mut servers: Vec<RawMcpServer> = Vec::new();
    let mut in_block = false;
    let mut block_indent = 0usize;
    let mut current: Option<RawMcpServer> = None;
    for line in raw.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if !in_block {
            if trimmed.starts_with("mcp_servers:") {
                in_block = true;
                block_indent = indent;
            }
            continue;
        }
        // Leaving the mcp_servers block when indentation returns to <= header.
        if indent <= block_indent && !trimmed.starts_with('-') {
            if let Some(server) = current.take() {
                servers.push(server);
            }
            in_block = false;
            continue;
        }
        // A server name key is `name:` indented one level under the header.
        if let Some((key, val)) = trimmed.split_once(':') {
            let key = key.trim();
            let val = val.trim().trim_matches('"');
            if val.is_empty() && indent == block_indent + 2 {
                if let Some(server) = current.take() {
                    servers.push(server);
                }
                current = Some(RawMcpServer {
                    name: key.to_string(),
                    command: None,
                    args: Vec::new(),
                    url: None,
                    env_keys: Vec::new(),
                    explicit_type: None,
                    has_auth_header: false,
                    has_oauth: false,
                    has_tls_client_cert: false,
                });
            } else if let Some(server) = current.as_mut() {
                match key {
                    "command" => server.command = Some(val.to_string()),
                    "url" => server.url = Some(val.to_string()),
                    _ => {}
                }
            }
        }
    }
    if let Some(server) = current.take() {
        servers.push(server);
    }
    servers
}

fn classify_transport(server: &RawMcpServer) -> String {
    if let Some(explicit) = &server.explicit_type {
        match explicit.as_str() {
            "stdio" => return "stdio".to_string(),
            "http" | "streamable-http" | "streamable_http" => return "http".to_string(),
            "sse" => return "sse".to_string(),
            "ws" | "websocket" => return "ws".to_string(),
            _ => {}
        }
    }
    if server.command.is_some() {
        return "stdio".to_string();
    }
    if let Some(url) = &server.url {
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("ws://") || lower.starts_with("wss://") {
            return "ws".to_string();
        }
        if lower.contains("/sse") {
            return "sse".to_string();
        }
        if lower.starts_with("http://") || lower.starts_with("https://") {
            return "http".to_string();
        }
    }
    "unknown".to_string()
}

/// Extract the host portion of a URL without an external URL-parsing crate.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let authority = after_scheme
        .split('/')
        .next()
        .unwrap_or(after_scheme)
        .split('@')
        .last()
        .unwrap_or(after_scheme);
    // Strip a trailing :port (but keep IPv6 brackets intact).
    let host = if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .unwrap_or(authority)
            .trim_start_matches('[')
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// True when a URL uses a non-TLS scheme (`http://` or `ws://`). HTTPS / WSS
/// (and anything we don't recognize) is treated as encrypted. Used to grade a
/// remote-endpoint finding: cleartext to a public host is the real risk.
fn url_is_cleartext(url: &str) -> bool {
    let lower = url.trim_start().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("ws://")
}

/// Human-readable phrase for an auth strength, used in finding descriptions
/// (`"no detected authentication"` reads better than `"None authentication"`).
fn auth_phrase(auth: AuthStrength) -> &'static str {
    match auth {
        AuthStrength::None => "no detected",
        AuthStrength::Shared => "shared-secret",
        AuthStrength::OAuth => "OAuth",
        AuthStrength::Mtls => "mutual-TLS",
        AuthStrength::Unknown => "unverified",
    }
}

/// Query-parameter keys that conventionally carry a credential. Matched
/// case-insensitively. Only the *presence* of the key is ever used; the value
/// is never read or stored (invariant I5).
fn is_secret_query_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "secret"
            | "token"
            | "access_token"
            | "accesstoken"
            | "refresh_token"
            | "api_key"
            | "apikey"
            | "api-key"
            | "key"
            | "auth"
            | "authorization"
            | "password"
            | "passwd"
            | "pwd"
            | "sig"
            | "signature"
    )
}

/// True when the URL carries an inline credential -- a `user:pass@` authority or
/// a secret-bearing query parameter (`?secret=`, `?token=`, ...). Presence only;
/// the value is never inspected or persisted (invariant I5).
fn url_carries_inline_credential(url: &str) -> bool {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let authority = after_scheme.split('/').next().unwrap_or("");
    // `user:pass@host` -- a password in the userinfo (a bare `user@host` with no
    // colon is not a credential).
    if let Some((userinfo, _)) = authority.split_once('@') {
        if userinfo.contains(':') {
            return true;
        }
    }
    if let Some((_, query)) = url.split_once('?') {
        let query = query.split('#').next().unwrap_or(query);
        if query
            .split(['&', ';'])
            .filter_map(|pair| pair.split('=').next())
            .any(is_secret_query_key)
        {
            return true;
        }
    }
    false
}

/// Redact inline credentials from a URL for storage / display / hashing: drop
/// the password from a `user:pass@` authority and rewrite any secret-bearing
/// query-parameter value to `REDACTED`. The raw secret is never stored
/// (invariant I5); redacting before the id hash also keeps the endpoint id
/// stable across secret rotation.
fn redact_url_credentials(url: &str) -> String {
    let (base, rest) = match url.split_once('?') {
        Some((b, r)) => (b.to_string(), Some(r.to_string())),
        None => (url.to_string(), None),
    };
    let mut out = redact_userinfo(&base);
    if let Some(rest) = rest {
        let (query, frag) = match rest.split_once('#') {
            Some((q, f)) => (q.to_string(), Some(f.to_string())),
            None => (rest, None),
        };
        let redacted_query = query
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, _)) if is_secret_query_key(k) => format!("{}=REDACTED", k),
                _ => pair.to_string(),
            })
            .collect::<Vec<_>>()
            .join("&");
        out.push('?');
        out.push_str(&redacted_query);
        if let Some(frag) = frag {
            out.push('#');
            out.push_str(&frag);
        }
    }
    out
}

/// Strip the password from a `scheme://user:pass@host/...` authority, keeping
/// only `scheme://user@host/...`. Authority-free inputs pass through unchanged.
fn redact_userinfo(base: &str) -> String {
    let (scheme, rest) = match base.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, base),
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a.to_string(), Some(p.to_string())),
        None => (rest.to_string(), None),
    };
    let authority = match authority.split_once('@') {
        Some((userinfo, host)) => {
            let user = userinfo.split(':').next().unwrap_or("");
            if user.is_empty() {
                host.to_string()
            } else {
                format!("{}@{}", user, host)
            }
        }
        None => authority,
    };
    let mut out = String::new();
    if let Some(s) = scheme {
        out.push_str(s);
        out.push_str("://");
    }
    out.push_str(&authority);
    if let Some(p) = path {
        out.push('/');
        out.push_str(&p);
    }
    out
}

fn classify_exposure(transport: &str, host: Option<&str>) -> ExposureScope {
    if transport == "stdio" {
        return ExposureScope::Stdio;
    }
    let host = match host {
        Some(h) => h.to_ascii_lowercase(),
        None => return ExposureScope::Unknown,
    };
    // Bind-all wildcards only make sense as a *listen* address: a locally-run
    // server bound to every interface, reachable inbound from the LAN/internet.
    // This is the only client-URL shape that genuinely means "local server
    // exposed beyond loopback".
    if host == "0.0.0.0" || host == "::" || host == "[::]" {
        return ExposureScope::Public;
    }
    if host == "localhost" || host.starts_with("127.") || host == "::1" {
        return ExposureScope::Loopback;
    }
    if host.ends_with(".local")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || is_172_private(&host)
        || host.starts_with("169.254.")
        || host.starts_with("fe80:")
        || host.starts_with("fc")
        || host.starts_with("fd")
    {
        return ExposureScope::Lan;
    }
    // A public host behind an http/sse/ws *client* URL means the agent dials
    // OUT to a remote third-party (SaaS) endpoint -- an egress/trust surface,
    // not a local inbound bind.
    ExposureScope::Remote
}

fn is_172_private(host: &str) -> bool {
    if let Some(rest) = host.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(octet) = second.parse::<u8>() {
                return (16..=31).contains(&octet);
            }
        }
    }
    false
}

fn classify_auth(server: &RawMcpServer) -> AuthStrength {
    if server.has_tls_client_cert {
        return AuthStrength::Mtls;
    }
    if server.has_oauth {
        return AuthStrength::OAuth;
    }
    let url_inline_cred = server
        .url
        .as_deref()
        .map(url_carries_inline_credential)
        .unwrap_or(false);
    if server.has_auth_header || url_inline_cred || env_keys_look_like_secret(&server.env_keys) {
        // A bearer token in a header / env var or a secret embedded in the URL
        // query (`?secret=...`) is a shared secret, not "no auth".
        return AuthStrength::Shared;
    }
    // stdio servers run as a child process and inherit the agent's identity;
    // absence of a token there is not itself "no auth" in the network sense.
    if server.command.is_some() && server.url.is_none() {
        return AuthStrength::Unknown;
    }
    AuthStrength::None
}

fn env_keys_look_like_secret(env_keys: &[String]) -> bool {
    env_keys.iter().any(|k| {
        let kl = k.to_ascii_uppercase();
        kl.contains("TOKEN")
            || kl.contains("KEY")
            || kl.contains("SECRET")
            || kl.contains("PASSWORD")
            || kl.contains("CREDENTIAL")
            || kl.contains("PAT")
    })
}

fn classify_tool_privileges(server: &RawMcpServer) -> Vec<ToolPrivilegeClass> {
    let mut haystack = String::new();
    haystack.push_str(&server.name.to_ascii_lowercase());
    haystack.push(' ');
    if let Some(cmd) = &server.command {
        haystack.push_str(&cmd.to_ascii_lowercase());
        haystack.push(' ');
    }
    for arg in &server.args {
        haystack.push_str(&arg.to_ascii_lowercase());
        haystack.push(' ');
    }
    if let Some(url) = &server.url {
        // Only the scheme+host+path describes the service. The query string
        // carries call arguments and inline credentials (e.g. `?secret=...`)
        // that must NOT be mined for capability keywords -- otherwise a
        // `secret=` auth token is misread as a `SecretAccess` tool.
        let url_no_query = url.split(['?', '#']).next().unwrap_or(url);
        haystack.push_str(&url_no_query.to_ascii_lowercase());
    }

    let mut classes = Vec::new();
    let add = |class: ToolPrivilegeClass, classes: &mut Vec<ToolPrivilegeClass>| {
        if !classes.contains(&class) {
            classes.push(class);
        }
    };

    let contains_any = |needles: &[&str]| needles.iter().any(|n| haystack.contains(n));

    if contains_any(&[
        "shell",
        "bash",
        "terminal",
        "exec",
        "command",
        "subprocess",
        "run-command",
    ]) {
        add(ToolPrivilegeClass::Shell, &mut classes);
    }
    if contains_any(&[
        "filesystem",
        "file-write",
        "write-file",
        "fs-write",
        "edit",
        "editor",
    ]) {
        add(ToolPrivilegeClass::FilesystemWrite, &mut classes);
    }
    if contains_any(&["read-file", "fs-read", "filesystem", "files", "fetch-file"]) {
        add(ToolPrivilegeClass::FilesystemRead, &mut classes);
    }
    if contains_any(&[
        "browser",
        "puppeteer",
        "playwright",
        "chrome",
        "webdriver",
        "selenium",
    ]) {
        add(ToolPrivilegeClass::Browser, &mut classes);
    }
    if contains_any(&["git", "github", "gitlab", "bitbucket"]) {
        add(ToolPrivilegeClass::Git, &mut classes);
    }
    if contains_any(&[
        "postgres", "mysql", "sqlite", "mongo", "database", "db-", "sql", "redis",
    ]) {
        add(ToolPrivilegeClass::Database, &mut classes);
    }
    if contains_any(&[
        "secret",
        "vault",
        "credential",
        "keychain",
        "1password",
        "keyring",
        "aws-secrets",
    ]) {
        add(ToolPrivilegeClass::SecretAccess, &mut classes);
    }
    if contains_any(&[
        "fetch",
        "http",
        "web-search",
        "websearch",
        "brave",
        "search",
        "scrape",
        "request",
    ]) {
        add(ToolPrivilegeClass::Network, &mut classes);
    }

    if classes.is_empty() {
        classes.push(ToolPrivilegeClass::Unknown);
    }
    classes
}

/// Deterministic MCP risk rules (invariant I3). EDAMAME's own server is never
/// flagged. The LLM later classifies/explains; these are the hard signals.
pub fn assess_mcp_risk(endpoints: &[McpEndpoint]) -> Vec<VisibilityFinding> {
    let mut findings = Vec::new();
    for ep in endpoints {
        if ep.is_edamame_server {
            continue;
        }
        let high_priv = ep
            .tool_privilege_classes
            .iter()
            .any(|c| c.is_high_privilege());
        let privilege_summary = ep
            .tool_privilege_classes
            .iter()
            .map(|c| format!("{:?}", c))
            .collect::<Vec<_>>()
            .join(",");

        // Rule 1: a locally-run server bound to ALL interfaces (0.0.0.0 / [::])
        // without strong auth is reachable inbound from the LAN/internet -> HIGH
        // (CRITICAL when it also exposes high-privilege tools). This is the
        // genuine inbound-exposure case; remote third-party endpoints are
        // handled separately by Rule 1b below.
        if matches!(ep.exposure_scope, ExposureScope::Public)
            && matches!(ep.auth_strength, AuthStrength::None | AuthStrength::Shared)
        {
            let severity = if high_priv {
                VisibilitySeverity::Critical
            } else {
                VisibilitySeverity::High
            };
            findings.push(
                VisibilityFinding::new(
                    "mcp",
                    "mcp_public_no_strong_auth",
                    severity,
                    &ep.id,
                    "Local MCP server exposed beyond loopback without strong auth",
                    format!(
                        "MCP server '{}' ({}) declared by agent '{}' is bound to all network interfaces ({} authentication), so it is reachable inbound from the LAN or internet.",
                        ep.server_name, ep.transport, ep.agent_type, auth_phrase(ep.auth_strength)
                    ),
                )
                .with_evidence("server_name", ep.server_name.clone())
                .with_evidence("agent_type", ep.agent_type.clone())
                .with_evidence("exposure", format!("{:?}", ep.exposure_scope))
                .with_evidence("auth", format!("{:?}", ep.auth_strength))
                .with_evidence("privilege_classes", privilege_summary.clone())
                .with_evidence("config_path", ep.config_path.clone())
                .with_owasp(),
            );
        }

        // Rule 1b: the agent is a CLIENT of a remote third-party (SaaS) endpoint
        // reached over the internet. The risk is data egress + transport
        // security, NOT an inbound bind, so it is graded very differently from
        // Rule 1:
        //   * cleartext transport (http:// / ws:// to a public host) -> HIGH
        //     (CRITICAL if high-privilege) -- agent context and any credentials
        //     cross the internet unencrypted.
        //   * TLS transport (https:// / wss://) -> LOW informational (the normal
        //     SaaS shape), escalated to MEDIUM only when high-privilege tools
        //     pair with no detectable auth. TLS remote is never alertable on its
        //     own: trusting a vendor is an operator decision, not a host breach.
        if matches!(ep.exposure_scope, ExposureScope::Remote) {
            let cleartext = ep.url.as_deref().map(url_is_cleartext).unwrap_or(false);
            if cleartext {
                let severity = if high_priv {
                    VisibilitySeverity::Critical
                } else {
                    VisibilitySeverity::High
                };
                findings.push(
                    VisibilityFinding::new(
                        "mcp",
                        "mcp_remote_cleartext_transport",
                        severity,
                        &ep.id,
                        "Remote MCP endpoint reached over cleartext transport",
                        format!(
                            "MCP server '{}' ({}) declared by agent '{}' is a remote third-party endpoint reached over a cleartext (non-TLS) connection; agent context and any credentials traverse the internet unencrypted.",
                            ep.server_name, ep.transport, ep.agent_type
                        ),
                    )
                    .with_evidence("server_name", ep.server_name.clone())
                    .with_evidence("agent_type", ep.agent_type.clone())
                    .with_evidence("exposure", format!("{:?}", ep.exposure_scope))
                    .with_evidence("auth", format!("{:?}", ep.auth_strength))
                    .with_evidence("privilege_classes", privilege_summary.clone())
                    .with_evidence("config_path", ep.config_path.clone())
                    .with_owasp(),
                );
            } else {
                let severity = if high_priv && matches!(ep.auth_strength, AuthStrength::None) {
                    VisibilitySeverity::Medium
                } else {
                    VisibilitySeverity::Low
                };
                findings.push(
                    VisibilityFinding::new(
                        "mcp",
                        "mcp_remote_saas_endpoint",
                        severity,
                        &ep.id,
                        "Agent uses a remote third-party (SaaS) MCP endpoint",
                        format!(
                            "MCP server '{}' ({}) declared by agent '{}' is hosted off-host by a third party and reached over the internet with {} authentication. Agent context is sent to an external service; review the vendor's data handling and confirm the connection should be trusted.",
                            ep.server_name, ep.transport, ep.agent_type, auth_phrase(ep.auth_strength)
                        ),
                    )
                    .with_evidence("server_name", ep.server_name.clone())
                    .with_evidence("agent_type", ep.agent_type.clone())
                    .with_evidence("exposure", format!("{:?}", ep.exposure_scope))
                    .with_evidence("auth", format!("{:?}", ep.auth_strength))
                    .with_evidence("privilege_classes", privilege_summary.clone())
                    .with_evidence("config_path", ep.config_path.clone())
                    .with_owasp(),
                );
            }
        }

        // Rule 2: LAN-reachable + high-privilege + weak auth -> HIGH.
        if matches!(ep.exposure_scope, ExposureScope::Lan)
            && high_priv
            && matches!(ep.auth_strength, AuthStrength::None)
        {
            findings.push(
                VisibilityFinding::new(
                    "mcp",
                    "mcp_lan_privileged_no_auth",
                    VisibilitySeverity::High,
                    &ep.id,
                    "LAN-reachable privileged MCP server without auth",
                    format!(
                        "MCP server '{}' exposes high-privilege tools ({}) on a LAN address with no authentication.",
                        ep.server_name, privilege_summary
                    ),
                )
                .with_evidence("server_name", ep.server_name.clone())
                .with_evidence("agent_type", ep.agent_type.clone())
                .with_evidence("privilege_classes", privilege_summary.clone())
                .with_evidence("config_path", ep.config_path.clone())
                .with_owasp(),
            );
        }

        // Rule 3: unclassified transport -> LOW (visibility gap, not alertable).
        if ep.transport == "unknown" {
            findings.push(
                VisibilityFinding::new(
                    "mcp",
                    "mcp_unclassified_transport",
                    VisibilitySeverity::Low,
                    &ep.id,
                    "MCP server transport could not be classified",
                    format!(
                        "MCP server '{}' declared by agent '{}' could not be classified (no command, no recognizable URL).",
                        ep.server_name, ep.agent_type
                    ),
                )
                .with_evidence("server_name", ep.server_name.clone())
                .with_evidence("agent_type", ep.agent_type.clone())
                .with_evidence("config_path", ep.config_path.clone())
                .with_owasp(),
            );
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Agent SBOM (INC-2)
// ---------------------------------------------------------------------------

/// Build one SBOM per discovered agent type from the live MCP inventory plus
/// the agent's on-disk instruction/skill artifacts. The agent application is
/// the root component; each MCP server it declares is a `service` component,
/// each distinct tool-privilege class a `data` component, each secret-bearing
/// env binding a `data` component, and each instruction/skill/rule/command
/// file a content-hashed `file` component.
pub fn build_agent_sboms(home: &Path) -> Vec<AgentSbom> {
    let endpoints = discover_mcp_endpoints(home);
    build_agent_sboms_from_endpoints_with_home(&endpoints, Some(home))
}

/// Endpoint-only SBOM projection (no on-disk instruction scan). Retained for
/// callers/tests that only have endpoints; prefer the `_with_home` variant in
/// the live bundle path so instruction/skill files surface too.
pub fn build_agent_sboms_from_endpoints(endpoints: &[McpEndpoint]) -> Vec<AgentSbom> {
    build_agent_sboms_from_endpoints_with_home(endpoints, None)
}

/// Full SBOM projection. When `home` is provided, each agent's instruction /
/// skill / rule / command / subagent files are discovered from its config dir
/// and projected as content-hashed `file` components (bodies are never stored,
/// invariant I5).
pub fn build_agent_sboms_from_endpoints_with_home(
    endpoints: &[McpEndpoint],
    home: Option<&Path>,
) -> Vec<AgentSbom> {
    let mut by_agent: BTreeMap<String, Vec<&McpEndpoint>> = BTreeMap::new();
    for ep in endpoints {
        by_agent.entry(ep.agent_type.clone()).or_default().push(ep);
    }
    // Some agents have instruction files but no MCP servers; make sure they
    // still get an SBOM when a home is available.
    if let Some(home) = home {
        for def in supported_agents::ordered_supported_agents() {
            by_agent.entry(def.agent_type.clone()).or_default();
            let _ = home; // referenced below per-agent
        }
    }

    let now = chrono::Utc::now();
    let mut sboms = Vec::new();
    for (agent_type, agent_endpoints) in by_agent {
        let app_ref = format!("agent:{}", agent_type);
        let mut components = Vec::new();
        // Deduped side-component tables (deterministic ordering via BTreeMap).
        let mut tool_components: BTreeMap<String, SbomComponent> = BTreeMap::new();
        let mut env_components: BTreeMap<String, SbomComponent> = BTreeMap::new();
        let mut app_dep_refs: Vec<String> = Vec::new();
        let mut service_deps: Vec<SbomDependency> = Vec::new();

        components.push(SbomComponent {
            bom_ref: app_ref.clone(),
            component_type: "application".to_string(),
            name: agent_type.clone(),
            version: None,
            content_hash: None,
            properties: {
                let mut p = BTreeMap::new();
                p.insert("edamame:role".to_string(), "agent_runtime".to_string());
                p.insert("edamame:kind".to_string(), "agent".to_string());
                p
            },
        });

        for ep in &agent_endpoints {
            let svc_ref = format!("mcp:{}", ep.id);
            app_dep_refs.push(svc_ref.clone());
            let mut props = BTreeMap::new();
            props.insert("edamame:kind".to_string(), "mcp_server".to_string());
            props.insert("edamame:transport".to_string(), ep.transport.clone());
            props.insert(
                "edamame:exposure".to_string(),
                format!("{:?}", ep.exposure_scope),
            );
            props.insert(
                "edamame:auth".to_string(),
                format!("{:?}", ep.auth_strength),
            );
            props.insert(
                "edamame:privilege_classes".to_string(),
                ep.tool_privilege_classes
                    .iter()
                    .map(|c| format!("{:?}", c))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            props.insert(
                "edamame:is_edamame_server".to_string(),
                ep.is_edamame_server.to_string(),
            );
            components.push(SbomComponent {
                bom_ref: svc_ref.clone(),
                component_type: "service".to_string(),
                name: ep.server_name.clone(),
                version: None,
                content_hash: None,
                properties: props,
            });

            // Each server depends on the tool capabilities it exposes and the
            // secret bindings it is wired to.
            let mut svc_dep_refs: Vec<String> = Vec::new();

            for class in &ep.tool_privilege_classes {
                if matches!(class, ToolPrivilegeClass::Unknown) {
                    continue;
                }
                let tool_ref = format!("tool:{}:{}", agent_type, class.slug());
                svc_dep_refs.push(tool_ref.clone());
                tool_components.entry(tool_ref.clone()).or_insert_with(|| {
                    let mut p = BTreeMap::new();
                    p.insert("edamame:kind".to_string(), "tool_capability".to_string());
                    p.insert(
                        "edamame:high_privilege".to_string(),
                        class.is_high_privilege().to_string(),
                    );
                    SbomComponent {
                        bom_ref: tool_ref,
                        component_type: "data".to_string(),
                        name: class.label().to_string(),
                        version: None,
                        content_hash: None,
                        properties: p,
                    }
                });
            }

            for key in &ep.env_keys {
                if !is_secret_env_key(key) {
                    continue;
                }
                let env_ref = format!("env:{}:{}", agent_type, key);
                svc_dep_refs.push(env_ref.clone());
                env_components.entry(env_ref.clone()).or_insert_with(|| {
                    let mut p = BTreeMap::new();
                    p.insert("edamame:kind".to_string(), "secret_binding".to_string());
                    // Name only -- never the value (invariant I5).
                    SbomComponent {
                        bom_ref: env_ref,
                        component_type: "data".to_string(),
                        name: key.clone(),
                        version: None,
                        content_hash: None,
                        properties: p,
                    }
                });
            }

            if !svc_dep_refs.is_empty() {
                service_deps.push(SbomDependency {
                    bom_ref: svc_ref,
                    depends_on: svc_dep_refs,
                });
            }
        }

        // Instruction / skill / rule / command / subagent files (I5: hashes,
        // never bodies). Only when a real home is available.
        let instruction_components = home
            .map(|h| discover_agent_instruction_components(h, &agent_type))
            .unwrap_or_default();
        for comp in &instruction_components {
            app_dep_refs.push(comp.bom_ref.clone());
        }

        // Assemble components in a stable order: app, services already pushed;
        // append tools, env bindings, instruction files.
        components.extend(tool_components.into_values());
        components.extend(env_components.into_values());
        components.extend(instruction_components);

        // Skip agents that carry nothing beyond the implicit application root
        // (no servers, no instructions) -- they are not yet "present" on host.
        if components.len() == 1 && agent_endpoints.is_empty() {
            continue;
        }

        let mut dependencies = vec![SbomDependency {
            bom_ref: app_ref,
            depends_on: app_dep_refs,
        }];
        dependencies.append(&mut service_deps);

        // Multi-instance correctness (Fix #4): key the SBOM on the same
        // per-(host, agent_type) instance id the divergence observer uses, so
        // the Agents tab no longer collapses distinct instances of one agent
        // type. When no home is available (endpoint-only callers/tests) fall
        // back to the agent_type as the instance id.
        let agent_instance_id = match home {
            Some(h) => crate::agent_transcripts::observer_agent_instance_id(&agent_type, h),
            None => agent_type.clone(),
        };
        sboms.push(AgentSbom {
            agent_type: agent_type.clone(),
            agent_instance_id,
            generated_at: now,
            components,
            dependencies,
        });
    }
    sboms
}

/// Env-var names that look like they carry a secret/credential. Used to
/// project secret bindings into the SBOM (names only, invariant I5).
fn is_secret_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    const NEEDLES: &[&str] = &[
        "TOKEN",
        "KEY",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "API_KEY",
        "APIKEY",
        "AUTH",
        "BEARER",
        "ACCESS_KEY",
        "PRIVATE",
        "PAT",
        "SESSION",
        "COOKIE",
    ];
    NEEDLES.iter().any(|n| upper.contains(n))
}

/// Subdirectories within an agent's config dir that carry agent instructions /
/// skills / commands / subagents, paired with the SBOM `edamame:kind` each
/// projects to. This is an allowlist on purpose: only these well-known dirs are
/// walked, so transcript / session / log stores (`projects/`, `sessions/`,
/// `history/`, ...) are never scanned.
const INSTRUCTION_SUBDIRS: &[(&str, &str)] = &[
    ("rules", "rule"),
    ("skills", "skill"),
    ("commands", "command"),
    ("agents", "subagent"),
    ("subagents", "subagent"),
    ("memories", "memory"),
    ("prompts", "prompt"),
    ("instructions", "instruction"),
    ("hooks", "hook"),
];

/// File extensions considered instruction/skill artifacts inside the
/// allowlisted subdirectories.
const INSTRUCTION_EXTS: &[&str] = &["md", "mdc", "txt", "json", "toml", "yaml", "yml"];

/// Classify a top-level file (directly under the config dir) as an instruction
/// artifact. Returns its `edamame:kind`, or `None` if it is not one.
fn classify_toplevel_instruction(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "claude.md" | "agents.md" | "gemini.md" | "codex.md" | "rules.md" | "instructions.md"
        | "memory.md" | ".cursorrules" => Some("instruction"),
        _ if lower.ends_with(".mdc") => Some("rule"),
        _ => None,
    }
}

/// Discover an agent's instruction / skill / rule / command / subagent files
/// from its config dir and project them as content-hashed `file` SBOM
/// components. Bounded (depth + count + size) and limited to the
/// `INSTRUCTION_SUBDIRS` allowlist plus top-level instruction files, so
/// transcript / session stores are never walked. Bodies are hashed, never
/// stored (invariant I5).
fn discover_agent_instruction_components(home: &Path, agent_type: &str) -> Vec<SbomComponent> {
    const MAX_FILES: usize = 256;
    const MAX_DEPTH: usize = 4;
    const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

    let def = match supported_agents::find_supported_agent(agent_type) {
        Some(d) => d,
        None => return Vec::new(),
    };
    let config_dir = match def.resolve_config_dir_with_home(home) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if !config_dir.is_dir() {
        return Vec::new();
    }

    // Collect (path, kind) pairs, then sort by path for deterministic output.
    let mut found: Vec<(PathBuf, &'static str)> = Vec::new();

    // Top-level instruction files directly under the config dir.
    if let Ok(entries) = std::fs::read_dir(&config_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(kind) = classify_toplevel_instruction(name) {
                    found.push((path, kind));
                }
            }
        }
    }

    // Allowlisted instruction-bearing subdirectories (bounded walk).
    for (subdir, kind) in INSTRUCTION_SUBDIRS {
        let root = config_dir.join(subdir);
        if !root.is_dir() {
            continue;
        }
        collect_instruction_files(&root, kind, MAX_DEPTH, &mut found, MAX_FILES);
    }

    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.dedup_by(|a, b| a.0 == b.0);

    let mut out: Vec<SbomComponent> = Vec::new();
    for (path, kind) in found.into_iter().take(MAX_FILES) {
        if let Some(comp) =
            instruction_file_component(&config_dir, agent_type, &path, kind, MAX_FILE_BYTES)
        {
            out.push(comp);
        }
    }
    out
}

/// Bounded DFS over an instruction subdirectory, collecting files whose
/// extension is in `INSTRUCTION_EXTS`.
fn collect_instruction_files(
    root: &Path,
    kind: &'static str,
    max_depth: usize,
    acc: &mut Vec<(PathBuf, &'static str)>,
    cap: usize,
) {
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if acc.len() >= cap {
            return;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            if acc.len() >= cap {
                return;
            }
            let path = entry.path();
            let ftype = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ftype.is_dir() {
                if depth + 1 <= max_depth {
                    stack.push((path, depth + 1));
                }
            } else if ftype.is_file() {
                let ext_ok = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| INSTRUCTION_EXTS.iter().any(|x| x.eq_ignore_ascii_case(e)))
                    .unwrap_or(false);
                if ext_ok {
                    acc.push((path, kind));
                }
            }
        }
    }
}

/// Build a content-hashed `file` component for one instruction artifact.
/// Returns `None` for unreadable files or files above `max_bytes`.
fn instruction_file_component(
    config_dir: &Path,
    agent_type: &str,
    path: &Path,
    kind: &str,
    max_bytes: u64,
) -> Option<SbomComponent> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > max_bytes {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let hash = hash_bytes(&bytes);
    let rel = path.strip_prefix(config_dir).unwrap_or(path);
    let rel_str = rel.to_string_lossy().to_string();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| rel_str.clone());
    let mut props = BTreeMap::new();
    props.insert("edamame:kind".to_string(), kind.to_string());
    props.insert("edamame:relpath".to_string(), rel_str.clone());
    Some(SbomComponent {
        bom_ref: format!(
            "file:{}:{}",
            agent_type,
            short_hash(&format!("{}|{}", agent_type, rel_str))
        ),
        component_type: "file".to_string(),
        name,
        version: None,
        content_hash: Some(hash),
        properties: props,
    })
}

/// Known LLM model-family prefixes used to recognize model identifiers in
/// agent transcripts. Conservative on purpose: a token is only treated as a
/// model when it begins with one of these AND carries a version digit, so
/// arbitrary prose never produces a `machine-learning-model` component.
const MODEL_FAMILY_PREFIXES: &[&str] = &[
    "claude-",
    "gpt-",
    "gemini-",
    "gemma-",
    "llama-",
    "mistral-",
    "mixtral-",
    "codestral-",
    "deepseek-",
    "qwen",
    "command-r",
    "grok-",
    "phi-",
    "o1-",
    "o3-",
    "o4-",
];

/// Cap on the number of distinct models projected per agent SBOM.
const MAX_MODELS_PER_AGENT: usize = 24;

/// Extract distinct LLM model identifiers from raw transcript text. Pure: no
/// IO. Bodies are never stored -- only the recognized model strings are
/// returned (invariant I5). Output is sorted + deduped for determinism.
pub fn extract_models_from_transcript(text: &str) -> Vec<String> {
    let mut models: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for raw in text.split(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == ':')
    }) {
        if models.len() >= MAX_MODELS_PER_AGENT {
            break;
        }
        if let Some(model) = normalize_model_token(raw) {
            models.insert(model);
        }
    }
    models.into_iter().take(MAX_MODELS_PER_AGENT).collect()
}

/// Normalize a candidate token to a model id, or `None` if it is not one.
/// Strips a leading `provider/` or `provider:` qualifier (e.g.
/// `anthropic/claude-3-5-sonnet`, `openai:gpt-4o`).
fn normalize_model_token(raw: &str) -> Option<String> {
    let trimmed = raw.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.len() < 3 || trimmed.len() > 64 {
        return None;
    }
    // Drop a provider qualifier if present.
    let candidate = trimmed
        .rsplit(['/', ':'])
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if candidate.len() < 3 || candidate.len() > 64 {
        return None;
    }
    let starts_with_family = MODEL_FAMILY_PREFIXES
        .iter()
        .any(|p| candidate.starts_with(p));
    if !starts_with_family {
        return None;
    }
    // Require a version digit so bare family words ("claude-code") are skipped.
    if !candidate.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(candidate)
}

/// SBOM application-component property recording how the agent's model(s) were
/// determined: `recorded` (read from an authoritative structured transcript
/// field) or `not_recorded` (the agent was observed but records no model
/// field at all, e.g. Cursor). Lets the UI show "models not recorded by this
/// agent" instead of guessing model names from conversational prose.
pub const MODELS_SOURCE_PROP: &str = "edamame:models_source";

/// Field names that carry an authoritative model identifier in agent
/// transcript JSON (checked top-level and one level inside a known container).
const MODEL_FIELD_KEYS: &[&str] = &["model", "modelId", "model_id"];

/// Container objects descended into exactly one level when scanning for an
/// authoritative model field. Bounded on purpose -- never a blind whole-tree
/// walk that could mistake an unrelated `model` key (e.g. a device model) for
/// an LLM identifier.
const MODEL_CONTAINER_KEYS: &[&str] = &[
    "message",
    "request",
    "response",
    "metadata",
    "usage",
    "assistant",
];

/// Extract **authoritative** LLM model identifiers from a raw JSONL transcript.
///
/// Unlike [`extract_models_from_transcript`] (a text heuristic that scans prose
/// for family-prefixed tokens), this reads ONLY explicit structured fields
/// (`model` / `modelId` / `model_id`, top-level or inside a known
/// message/request/response container), so the SBOM reflects the model(s) the
/// agent actually recorded -- never a model name merely mentioned in a comment
/// or chat message. Agents that record no such field (e.g. Cursor) yield an
/// empty set and are marked `not_recorded` by the caller rather than guessed.
///
/// Pure: no IO. Bodies are never stored (invariant I5); only the recognized
/// model strings are returned, sorted + deduped, capped at
/// [`MAX_MODELS_PER_AGENT`].
pub fn extract_models_from_transcript_structured(raw_text: &str) -> Vec<String> {
    let mut models: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in raw_text.lines() {
        if models.len() >= MAX_MODELS_PER_AGENT {
            break;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        collect_authoritative_models(&value, &mut models);
    }
    models.into_iter().take(MAX_MODELS_PER_AGENT).collect()
}

/// Pull authoritative model ids out of one parsed JSON object: the top-level
/// model fields plus the same fields one level inside a known container.
fn collect_authoritative_models(
    value: &serde_json::Value,
    out: &mut std::collections::BTreeSet<String>,
) {
    let obj = match value.as_object() {
        Some(o) => o,
        None => return,
    };
    let mut pull = |v: &serde_json::Value| {
        if let Some(s) = v.as_str() {
            if let Some(m) = normalize_authoritative_model(s) {
                out.insert(m);
            }
        }
    };
    for key in MODEL_FIELD_KEYS {
        if let Some(v) = obj.get(*key) {
            pull(v);
        }
    }
    for key in MODEL_CONTAINER_KEYS {
        if let Some(child) = obj.get(*key).and_then(|c| c.as_object()) {
            for fk in MODEL_FIELD_KEYS {
                if let Some(v) = child.get(*fk) {
                    pull(v);
                }
            }
        }
    }
}

/// Normalize an authoritative model field value to a model id, or `None` if it
/// is obviously not a model token. Trusts the field (no family-prefix / version
/// requirement -- the agent explicitly declared it), but strips a `provider/`
/// or `provider:` qualifier, lowercases, and rejects empty / overlong /
/// non-identifier-shaped values so a stray field cannot pollute the SBOM.
fn normalize_authoritative_model(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.len() < 2 || trimmed.len() > 64 {
        return None;
    }
    let candidate = trimmed
        .rsplit(['/', ':'])
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_ascii_lowercase();
    if candidate.len() < 2 || candidate.len() > 64 {
        return None;
    }
    // Must look like a model identifier (alphanumerics plus - . _) and carry at
    // least one letter -- rejects pure-numeric or symbol-only stray values.
    if !candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
    {
        return None;
    }
    if !candidate.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    Some(candidate)
}

/// Set the [`MODELS_SOURCE_PROP`] marker on an agent SBOM's application root
/// component. Idempotent. Returns `true` if the property value changed (so the
/// caller can report the SBOM as updated).
pub fn mark_models_source(sbom: &mut AgentSbom, source: &str) -> bool {
    let app_ref = format!("agent:{}", sbom.agent_type);
    match sbom.components.iter_mut().find(|c| c.bom_ref == app_ref) {
        Some(app) => {
            let prev = app
                .properties
                .insert(MODELS_SOURCE_PROP.to_string(), source.to_string());
            prev.as_deref() != Some(source)
        }
        None => false,
    }
}

/// Append `machine-learning-model` components for the given model ids onto an
/// existing agent SBOM (deduped against models already present) and wire them
/// as dependencies of the agent application root. Returns `true` when the SBOM
/// gained at least one new model component.
pub fn merge_models_into_sbom(sbom: &mut AgentSbom, model_ids: &[String]) -> bool {
    if model_ids.is_empty() {
        return false;
    }
    // Authoritative models are being merged -> record on the app root that this
    // agent's models came from a structured transcript field (not a guess).
    let marked = mark_models_source(sbom, "recorded");
    let app_ref = format!("agent:{}", sbom.agent_type);
    let mut present: std::collections::BTreeSet<String> = sbom
        .components
        .iter()
        .filter(|c| c.component_type == "machine-learning-model")
        .map(|c| c.bom_ref.clone())
        .collect();

    let mut new_refs: Vec<String> = Vec::new();
    for model in model_ids {
        let model_ref = format!("model:{}:{}", sbom.agent_type, model);
        if present.contains(&model_ref) {
            continue;
        }
        present.insert(model_ref.clone());
        let mut p = BTreeMap::new();
        p.insert("edamame:kind".to_string(), "model".to_string());
        // Authoritative: read from an explicit transcript model field.
        p.insert("edamame:source".to_string(), "recorded".to_string());
        sbom.components.push(SbomComponent {
            bom_ref: model_ref.clone(),
            component_type: "machine-learning-model".to_string(),
            name: model.clone(),
            version: None,
            content_hash: None,
            properties: p,
        });
        new_refs.push(model_ref);
    }

    if new_refs.is_empty() {
        return marked;
    }
    if let Some(dep) = sbom.dependencies.iter_mut().find(|d| d.bom_ref == app_ref) {
        dep.depends_on.extend(new_refs);
    } else {
        sbom.dependencies.push(SbomDependency {
            bom_ref: app_ref,
            depends_on: new_refs,
        });
    }
    true
}

/// Project an `AgentSbom` to a minimal CycloneDX 1.5 JSON document. Pure
/// serialization -- no network, no file IO.
pub fn sbom_to_cyclonedx(sbom: &AgentSbom) -> serde_json::Value {
    let components: Vec<serde_json::Value> = sbom
        .components
        .iter()
        .map(|c| {
            let mut obj = serde_json::Map::new();
            obj.insert("type".to_string(), serde_json::json!(c.component_type));
            obj.insert("bom-ref".to_string(), serde_json::json!(c.bom_ref));
            obj.insert("name".to_string(), serde_json::json!(c.name));
            if let Some(v) = &c.version {
                obj.insert("version".to_string(), serde_json::json!(v));
            }
            if let Some(h) = &c.content_hash {
                obj.insert(
                    "hashes".to_string(),
                    serde_json::json!([{ "alg": "SHA-256", "content": h }]),
                );
            }
            if !c.properties.is_empty() {
                let props: Vec<serde_json::Value> = c
                    .properties
                    .iter()
                    .map(|(k, v)| serde_json::json!({ "name": k, "value": v }))
                    .collect();
                obj.insert("properties".to_string(), serde_json::json!(props));
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    let dependencies: Vec<serde_json::Value> = sbom
        .dependencies
        .iter()
        .map(|d| {
            serde_json::json!({
                "ref": d.bom_ref,
                "dependsOn": d.depends_on,
            })
        })
        .collect();

    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": sbom.generated_at.to_rfc3339(),
            "component": {
                "type": "application",
                "name": sbom.agent_type,
                "bom-ref": format!("agent:{}", sbom.agent_type),
            },
            "properties": [
                { "name": "edamame:agent_instance_id", "value": sbom.agent_instance_id },
            ],
        },
        "components": components,
        "dependencies": dependencies,
    })
}

/// Diff a current SBOM against an approved baseline. `added`/`removed` are by
/// bom_ref; `changed` lists refs whose version or content hash differs.
pub fn diff_sboms(baseline: Option<&AgentSbom>, current: &AgentSbom) -> SbomDiff {
    let baseline = match baseline {
        Some(b) => b,
        None => {
            return SbomDiff {
                added: current.components.clone(),
                removed: Vec::new(),
                changed: Vec::new(),
                baseline_present: false,
            }
        }
    };
    let base_by_ref: BTreeMap<&str, &SbomComponent> = baseline
        .components
        .iter()
        .map(|c| (c.bom_ref.as_str(), c))
        .collect();
    let cur_by_ref: BTreeMap<&str, &SbomComponent> = current
        .components
        .iter()
        .map(|c| (c.bom_ref.as_str(), c))
        .collect();

    let mut diff = SbomDiff {
        baseline_present: true,
        ..Default::default()
    };
    for (cref, comp) in &cur_by_ref {
        match base_by_ref.get(cref) {
            None => diff.added.push((*comp).clone()),
            Some(base_comp) => {
                if base_comp.version != comp.version || base_comp.content_hash != comp.content_hash
                {
                    diff.changed.push(cref.to_string());
                }
            }
        }
    }
    for (bref, comp) in &base_by_ref {
        if !cur_by_ref.contains_key(bref) {
            diff.removed.push((*comp).clone());
        }
    }
    diff
}

/// `true` when a component is part of the agent's **structural** capability
/// surface that the baseline-drift alarm cares about: MCP servers, tool
/// classes, secret/env bindings, instruction files, and the agent root.
/// Model components are explicitly excluded -- which model an agent happens to
/// call on a given run is dynamic, informational state, not a supply-chain
/// change, so a model appearing/disappearing must NOT raise a drift alarm.
fn is_structural_component(c: &SbomComponent) -> bool {
    c.component_type != "machine-learning-model"
        && c.properties.get("edamame:kind").map(String::as_str) != Some("model")
}

/// Deterministic outcome of grading an SBOM diff for baseline-drift alarming.
#[derive(Debug, Clone)]
pub struct SbomDriftAlarm {
    /// The alertable/visible finding to record + notify on.
    pub finding: VisibilityFinding,
    /// Stable signature of the structural drift set. The caller persists this
    /// per `agent_instance_id` and only (re-)notifies when it changes, so an
    /// unchanged drift does not re-alarm every tick (notification dedup).
    pub signature: String,
}

/// Grade an SBOM `diff` for an agent instance into an optional baseline-drift
/// alarm. Pure: no IO, no notification side effects.
///
/// Only **structural** capability changes count (see [`is_structural_component`]):
/// a new/removed MCP server, tool class, secret binding, or instruction file,
/// or a changed instruction-file content hash. Model add/remove is ignored.
///
/// Severity grading (mirrors the attack-pattern alertable gate -- only HIGH/
/// CRITICAL trip a CI gate / score):
/// - **High**: the capability surface *expanded* (any structural addition) or
///   an instruction file's content changed -- the security-relevant direction
///   (new server/tool/secret = new attack surface; changed instructions =
///   prompt-injection / behavior-change surface).
/// - **Medium**: only *removals* (capability shrank) -- still drift the
///   operator should see, but not alertable on its own.
///
/// Returns `None` when the baseline is absent (nothing to drift from) or when
/// no structural change remains after filtering models out.
pub fn sbom_drift_alarm(
    agent_type: &str,
    agent_instance_id: &str,
    diff: &SbomDiff,
) -> Option<SbomDriftAlarm> {
    if !diff.baseline_present {
        return None;
    }
    let added: Vec<&SbomComponent> = diff
        .added
        .iter()
        .filter(|c| is_structural_component(c))
        .collect();
    let removed: Vec<&SbomComponent> = diff
        .removed
        .iter()
        .filter(|c| is_structural_component(c))
        .collect();
    // Only instruction files carry a content_hash, so any `changed` ref is an
    // instruction-file content change. Models never appear here (no hash).
    let changed: Vec<&String> = diff
        .changed
        .iter()
        .filter(|r| !r.starts_with("model:"))
        .collect();

    if added.is_empty() && removed.is_empty() && changed.is_empty() {
        return None;
    }

    let severity = if !added.is_empty() || !changed.is_empty() {
        VisibilitySeverity::High
    } else {
        VisibilitySeverity::Medium
    };

    // Stable signature over the structural drift set -- sorted bom_refs tagged
    // by direction so the caller can dedup notifications across ticks.
    let mut sig_parts: Vec<String> = Vec::new();
    for c in &added {
        sig_parts.push(format!("+{}", c.bom_ref));
    }
    for c in &removed {
        sig_parts.push(format!("-{}", c.bom_ref));
    }
    for r in &changed {
        sig_parts.push(format!("~{}", r));
    }
    sig_parts.sort();
    let signature = short_hash(&sig_parts.join("|"));

    // Human-readable subject names (capped) for the description.
    let names = |comps: &[&SbomComponent]| -> String {
        let mut v: Vec<&str> = comps.iter().map(|c| c.name.as_str()).collect();
        v.sort_unstable();
        v.truncate(6);
        v.join(", ")
    };

    let mut parts: Vec<String> = Vec::new();
    if !added.is_empty() {
        parts.push(format!("added {} ({})", added.len(), names(&added)));
    }
    if !changed.is_empty() {
        parts.push(format!("changed {} instruction file(s)", changed.len()));
    }
    if !removed.is_empty() {
        parts.push(format!("removed {} ({})", removed.len(), names(&removed)));
    }
    let description = format!(
        "Agent '{}' capability surface drifted from its approved baseline: {}.",
        agent_type,
        parts.join("; ")
    );

    let finding = VisibilityFinding::new(
        "sbom",
        "sbom_baseline_drift",
        severity,
        agent_instance_id,
        format!("{} SBOM drifted from approved baseline", agent_type),
        description,
    )
    .with_evidence("agent_type", agent_type)
    .with_evidence("agent_instance_id", agent_instance_id)
    .with_evidence("added_count", added.len().to_string())
    .with_evidence("removed_count", removed.len().to_string())
    .with_evidence("changed_count", changed.len().to_string())
    .with_evidence("drift_signature", signature.clone())
    .with_owasp();

    Some(SbomDriftAlarm { finding, signature })
}

// ---------------------------------------------------------------------------
// Capability graph (INC-3)
// ---------------------------------------------------------------------------

/// Build the declared capability graph edges from the live MCP inventory.
/// Every edge is `Declared` confidence here; core upgrades edges to `Observed`
/// when live flodbadd telemetry corroborates a `connects_to` edge.
pub fn build_capability_graph(home: &Path) -> Vec<GraphEdge> {
    let endpoints = discover_mcp_endpoints(home);
    build_capability_graph_from_endpoints(&endpoints)
}

pub fn build_capability_graph_from_endpoints(endpoints: &[McpEndpoint]) -> Vec<GraphEdge> {
    let now = chrono::Utc::now();
    let mut edges = Vec::new();
    for ep in endpoints {
        let agent_node = format!("agent:{}", ep.agent_type);
        let server_node = format!("mcp:{}", ep.id);
        let server_zone = zone_for_exposure(ep.exposure_scope);

        // agent --declares--> mcp_server
        edges.push(make_edge(
            "agent",
            &agent_node,
            &ep.agent_type,
            ZONE_AGENT,
            "declares",
            "mcp_server",
            &server_node,
            &ep.server_name,
            server_zone,
            now,
        ));

        // mcp_server --exposes--> tool_class. `Unknown` means "could not be
        // classified" -- it is not an exposed capability, so we omit it here
        // to avoid a misleading `exposes Unclassified` edge.
        for class in &ep.tool_privilege_classes {
            if matches!(class, ToolPrivilegeClass::Unknown) {
                continue;
            }
            let class_node = format!("tool_class:{}", class.slug());
            edges.push(make_edge(
                "mcp_server",
                &server_node,
                &ep.server_name,
                server_zone,
                "exposes",
                "tool_class",
                &class_node,
                class.label(),
                ZONE_TOOL_CLASS,
                now,
            ));
        }

        // mcp_server --connects_to--> network_endpoint (declared, host only).
        // The network endpoint inherits the endpoint's exposure zone (a public
        // bind is a trust2 surface).
        if let Some(host) = &ep.bind_host {
            let net_node = format!("network_endpoint:{}", host);
            edges.push(make_edge(
                "mcp_server",
                &server_node,
                &ep.server_name,
                server_zone,
                "connects_to",
                "network_endpoint",
                &net_node,
                host,
                server_zone,
                now,
            ));
        }
    }
    edges
}

/// The agent identity node is the innermost trust zone.
const ZONE_AGENT: &str = "trust0";
/// Capability classes are a local service boundary.
const ZONE_TOOL_CLASS: &str = "trust1";

/// Map an MCP endpoint exposure scope to a trust zone. Local transports
/// (stdio / loopback) are the `trust1` service boundary; anything reachable
/// off-host (LAN / public) -- or unclassifiable -- is the untrusted `trust2`
/// surface. Conservative on `Unknown` (treated as `trust2`).
fn zone_for_exposure(scope: ExposureScope) -> &'static str {
    match scope {
        ExposureScope::Stdio | ExposureScope::Loopback => "trust1",
        ExposureScope::Lan
        | ExposureScope::Remote
        | ExposureScope::Public
        | ExposureScope::Unknown => "trust2",
    }
}

#[allow(clippy::too_many_arguments)]
fn make_edge(
    src_type: &str,
    src_id: &str,
    src_label: &str,
    src_zone: &str,
    edge_type: &str,
    dst_type: &str,
    dst_id: &str,
    dst_label: &str,
    dst_zone: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> GraphEdge {
    let id = short_hash(&format!(
        "{}|{}|{}|{}|{}",
        src_type, src_id, edge_type, dst_type, dst_id
    ));
    GraphEdge {
        id,
        src_type: src_type.to_string(),
        src_id: src_id.to_string(),
        src_label: src_label.to_string(),
        src_zone: src_zone.to_string(),
        edge_type: edge_type.to_string(),
        dst_type: dst_type.to_string(),
        dst_id: dst_id.to_string(),
        dst_label: dst_label.to_string(),
        dst_zone: dst_zone.to_string(),
        confidence: EdgeConfidence::Declared,
        first_seen: now,
        last_seen: now,
    }
}

// ---------------------------------------------------------------------------
// Trust-zone graph queries (INC-10, C3)
// ---------------------------------------------------------------------------

/// Numeric rank of a trust zone for "least trusted reachable" comparisons.
/// Higher = less trusted. Unknown zone strings rank as the most-trusted (0)
/// so an unexpected value never silently inflates a reachability verdict.
fn zone_rank(zone: &str) -> u8 {
    match zone {
        "trust0" => 0,
        "trust1" => 1,
        "trust2" => 2,
        _ => 0,
    }
}

/// Per-agent reachability summary over the declared capability graph: which
/// trust zones an agent can reach, the least-trusted zone reachable, and
/// whether any path crosses out to a `trust2` (LAN/public/unknown) surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentReachability {
    pub agent_type: String,
    /// Number of distinct destination nodes reachable from the agent node.
    pub reachable_node_count: u32,
    /// Least-trusted zone reachable (`trust0` | `trust1` | `trust2`).
    pub max_zone: String,
    /// True when the agent can reach a `trust2` node (the headline signal).
    pub crosses_to_untrusted: bool,
    /// Edge ids that cross from a more-trusted to a `trust2` node.
    pub boundary_edge_ids: Vec<String>,
}

/// Per-agent effective capability summary: the deduped set of capability
/// classes reachable from the agent, plus whether any high-privilege class
/// coexists with an off-host reach (the dangerous combination, INC-3/INC-10).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentEffectiveCapabilities {
    pub agent_type: String,
    /// Human-readable capability labels (e.g. `Shell`, `Git`).
    pub capabilities: Vec<String>,
    /// True when any reachable capability class is high-privilege.
    pub high_privilege: bool,
    /// True when the agent reaches a `trust2` node.
    pub reaches_untrusted: bool,
}

/// Compute per-agent reachability over the declared graph edges. Pure: a
/// breadth-first walk from each `agent:<type>` node following every edge,
/// tracking the set of reachable destination ids and the least-trusted zone
/// touched. Deterministic ordering (sorted by agent_type) for stable output.
pub fn compute_graph_reachability(edges: &[GraphEdge]) -> Vec<AgentReachability> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    // Adjacency keyed by src_id -> outgoing edges (index into `edges`).
    let mut adjacency: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut agent_nodes: BTreeMap<&str, &str> = BTreeMap::new(); // node id -> agent_type
    for (idx, e) in edges.iter().enumerate() {
        adjacency.entry(e.src_id.as_str()).or_default().push(idx);
        if e.src_type == "agent" {
            agent_nodes.insert(e.src_id.as_str(), e.src_label.as_str());
        }
    }

    let mut out = Vec::new();
    for (agent_node, agent_type) in &agent_nodes {
        let mut visited: BTreeSet<&str> = BTreeSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        let mut max_zone = "trust0".to_string();
        let mut boundary: BTreeSet<String> = BTreeSet::new();
        queue.push_back(agent_node);
        visited.insert(agent_node);
        while let Some(node) = queue.pop_front() {
            if let Some(out_edges) = adjacency.get(node) {
                for &idx in out_edges {
                    let e = &edges[idx];
                    if zone_rank(&e.dst_zone) > zone_rank(&max_zone) {
                        max_zone = e.dst_zone.clone();
                    }
                    if e.dst_zone == "trust2" && zone_rank(&e.src_zone) < zone_rank(&e.dst_zone) {
                        boundary.insert(e.id.clone());
                    }
                    if visited.insert(e.dst_id.as_str()) {
                        queue.push_back(e.dst_id.as_str());
                    }
                }
            }
        }
        // The agent node itself is in `visited`; reachable destinations exclude it.
        let reachable_node_count = visited.len().saturating_sub(1) as u32;
        out.push(AgentReachability {
            agent_type: agent_type.to_string(),
            reachable_node_count,
            crosses_to_untrusted: max_zone == "trust2",
            max_zone,
            boundary_edge_ids: boundary.into_iter().collect(),
        });
    }
    out
}

/// Compute per-agent effective capabilities over the declared graph edges.
/// Pure: collects every `tool_class` destination reachable from each agent
/// (one hop through its mcp_server nodes), flags high-privilege classes, and
/// notes whether the agent also reaches a `trust2` surface.
pub fn compute_effective_capabilities(edges: &[GraphEdge]) -> Vec<AgentEffectiveCapabilities> {
    use std::collections::{BTreeMap, BTreeSet};

    let reach = compute_graph_reachability(edges);
    let reaches: BTreeMap<&str, bool> = reach
        .iter()
        .map(|r| (r.agent_type.as_str(), r.crosses_to_untrusted))
        .collect();

    // For each agent, gather reachable tool_class labels by walking
    // agent -> mcp_server -> tool_class. Reuse the reachability node set by
    // re-deriving from adjacency (cheap; graphs are tiny).
    let mut adjacency: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut agent_nodes: BTreeMap<&str, &str> = BTreeMap::new();
    for (idx, e) in edges.iter().enumerate() {
        adjacency.entry(e.src_id.as_str()).or_default().push(idx);
        if e.src_type == "agent" {
            agent_nodes.insert(e.src_id.as_str(), e.src_label.as_str());
        }
    }

    let mut out = Vec::new();
    for (agent_node, agent_type) in &agent_nodes {
        let mut caps: BTreeSet<String> = BTreeSet::new();
        let mut high_priv = false;
        // agent -> mcp_server
        if let Some(server_edges) = adjacency.get(agent_node) {
            for &si in server_edges {
                let server = &edges[si];
                if server.dst_type != "mcp_server" {
                    continue;
                }
                // mcp_server -> tool_class
                if let Some(tool_edges) = adjacency.get(server.dst_id.as_str()) {
                    for &ti in tool_edges {
                        let te = &edges[ti];
                        if te.dst_type != "tool_class" {
                            continue;
                        }
                        caps.insert(te.dst_label.clone());
                        if is_high_privilege_label(&te.dst_label) {
                            high_priv = true;
                        }
                    }
                }
            }
        }
        out.push(AgentEffectiveCapabilities {
            agent_type: agent_type.to_string(),
            capabilities: caps.into_iter().collect(),
            high_privilege: high_priv,
            reaches_untrusted: reaches.get(*agent_type).copied().unwrap_or(false),
        });
    }
    out
}

/// Whether a capability label corresponds to a high-privilege class. Mirrors
/// `ToolPrivilegeClass::is_high_privilege` on the human-readable label so the
/// graph queries stay pure over edges (which carry labels, not enums).
fn is_high_privilege_label(label: &str) -> bool {
    matches!(
        label,
        "Shell" | "Filesystem Write" | "Secret Access" | "Database"
    )
}

// ---------------------------------------------------------------------------
// Agent inventory & classification (INC-10, C1)
// ---------------------------------------------------------------------------

/// Operator-facing classification of a discovered agent, framed as a
/// first-seen tripwire rather than a governance allow-list. The deterministic
/// rule lives in `classify_agent`; core assembles the inputs from the
/// transcript-observer status, the MCP/SBOM discovery, and the operator
/// acknowledgment set. Precedence (most → least specific):
/// `acknowledged` > `shadow` > `new`.
///
/// "Acknowledged" replaces the former "approved": a one-tap "yes, this is me"
/// confirmation that the operator recognizes the agent. Everything not yet
/// acknowledged (`new`, `shadow`) is an unexpected first-seen footprint that
/// raises the new-agent alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentClassification {
    /// Operator tapped "yes, this is me" for this agent type -- a recognized,
    /// expected footprint. Observer health is surfaced separately (the
    /// `unsecured_<agent>` internal threat), not by this class.
    Acknowledged,
    /// Present/discovered but its observer is disabled/paused -- a newly-seen
    /// agent running unobserved. Unacknowledged AND a blind spot: the
    /// evasion-shaped, highest-risk first-seen class.
    Shadow,
    /// Newly discovered footprint (present, typically observed) that the
    /// operator has not acknowledged yet. The one-tap "yes, this is me"
    /// tripwire target.
    New,
}

impl AgentClassification {
    pub fn slug(&self) -> &'static str {
        match self {
            AgentClassification::Acknowledged => "acknowledged",
            AgentClassification::Shadow => "shadow",
            AgentClassification::New => "new",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            AgentClassification::Acknowledged => "Acknowledged",
            AgentClassification::Shadow => "Shadow",
            AgentClassification::New => "New",
        }
    }

    /// True for classes the operator should review -- every not-yet-acknowledged
    /// first-seen footprint (`new`, `shadow`). Drives the new-agent alarm.
    pub fn needs_review(&self) -> bool {
        !matches!(self, AgentClassification::Acknowledged)
    }
}

/// Deterministic first-seen classification rule. `present` means the agent has
/// any structural footprint (discovered on disk, plugin installed, or declared
/// MCP endpoints). Precedence is acknowledgment-first, then evasion-biased: an
/// acknowledged agent is `acknowledged` regardless of observer state, an
/// unacknowledged present agent whose observer is off is `shadow`, and any
/// other unacknowledged footprint is `new`.
pub fn classify_agent(
    acknowledged: bool,
    discovered: bool,
    observer_enabled: bool,
    present: bool,
) -> AgentClassification {
    if acknowledged {
        return AgentClassification::Acknowledged;
    }
    // Newly seen and we are not even observing it -> shadow (blind spot).
    if (discovered || present) && !observer_enabled {
        return AgentClassification::Shadow;
    }
    // Newly seen, unacknowledged -> first-seen tripwire.
    AgentClassification::New
}

/// One row of the operator agent inventory (INC-10). Pure data container;
/// core fills it by joining observer status + MCP/SBOM discovery + allow-list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInventoryEntry {
    pub agent_type: String,
    pub display_name: String,
    pub classification: AgentClassification,
    /// EDAMAME plugin installed in the agent's MCP config.
    pub installed: bool,
    /// Transcript root present on disk.
    pub discovered: bool,
    /// Host-side transcript observer enabled for this agent.
    pub observer_enabled: bool,
    /// Operator tapped "yes, this is me" -- this agent type is acknowledged.
    pub acknowledged: bool,
    /// Count of MCP endpoints declared by this agent.
    pub mcp_endpoint_count: u32,
    /// Count of SBOM components attributed to this agent.
    pub sbom_component_count: u32,
    /// Count of high-or-critical visibility findings touching this agent.
    pub alertable_finding_count: u32,
}

// ---------------------------------------------------------------------------
// Recursive / delegation detection (INC-4)
// ---------------------------------------------------------------------------

/// A flattened spawn marker extracted from a transcript. `depth` is the
/// reconstructed delegation depth (1 for a top-level spawn). Pure input to
/// `analyze_delegation`.
#[derive(Debug, Clone)]
pub struct RawSpawn {
    pub depth: u32,
    pub spawn_reason: Option<String>,
    /// Free-text goal/intent; tokenized + hashed for loop detection.
    pub goal_text: String,
}

/// Threshold beyond which delegation depth is itself a finding, regardless of
/// loop detection. Sub-agent fan-out deeper than this is unusual on a
/// workstation and worth surfacing.
const RECURSION_DEPTH_HIGH: u32 = 4;

/// The same goal re-delegated at least this many times in one session is a
/// same-purpose loop even when every spawn reads at the same depth. This is the
/// common shape on a single-transcript workstation, where nested sub-agent
/// turns are not inlined into the parent transcript so depth-only detection
/// collapses to 1. Depth-based detection (a repeated hash at *increasing*
/// depth) still applies on top of this.
const RECURSION_LOOP_MIN_REPEATS: u32 = 3;

/// Sub-agent fan-out at or above this count in a single session is itself worth
/// surfacing even without a detected loop or deep nesting -- a parent agent
/// dispatching this many sub-agents is an unusual control pattern.
const RECURSION_FANOUT_HIGH: u32 = 8;

/// Extract sub-agent spawn markers from a raw transcript body. Generic across
/// agents.
///
/// Modern agent transcripts (Claude Code, Cursor, OpenClaw, ...) are stored as
/// JSONL -- one compact JSON object per line, no indentation. For those, real
/// delegation depth is derived from the structural parent/child linkage
/// (`uuid`/`parentUuid`) and the sub-agent (`isSidechain`) flag rather than
/// from leading whitespace, which is always zero in compact JSONL and collapses
/// every spawn to depth 1. When no JSON object lines are present (a plain-text
/// or pretty-printed transcript), it falls back to the legacy text scan with an
/// indentation-based depth hint.
pub fn extract_spawn_markers(transcript: &str) -> Vec<RawSpawn> {
    match extract_spawn_markers_structured(transcript) {
        Some(spawns) => spawns,
        None => extract_spawn_markers_textual(transcript),
    }
}

/// Legacy text-scan extractor. Matches the common `Task(`, `subagent`,
/// `spawn`, `delegate`, and `dispatch_agent` markers and infers depth from
/// indentation hints. Used for non-JSONL transcripts.
fn extract_spawn_markers_textual(transcript: &str) -> Vec<RawSpawn> {
    let mut spawns = Vec::new();
    for line in transcript.lines() {
        let lower = line.to_ascii_lowercase();
        let is_spawn = lower.contains("\"name\":\"task\"")
            || lower.contains("\"name\": \"task\"")
            || lower.contains("subagent_type")
            || lower.contains("dispatch_agent")
            || lower.contains("delegate_to")
            || lower.contains("spawn_agent");
        if !is_spawn {
            continue;
        }
        // Depth hint: count leading indentation in 2-space units, capped.
        let indent = line.len() - line.trim_start().len();
        let depth = ((indent / 2) as u32).min(16);
        let reason = extract_marker_reason(&lower);
        let goal_text = line.trim().chars().take(400).collect::<String>();
        spawns.push(RawSpawn {
            depth,
            spawn_reason: reason,
            goal_text,
        });
    }
    spawns
}

/// One parsed JSONL record relevant to delegation-tree reconstruction. The
/// record's own `uuid` is captured in the `by_uuid` index at parse time rather
/// than stored here (depth reconstruction only walks `parent_uuid`).
struct StructRecord {
    parent_uuid: Option<String>,
    is_sidechain: bool,
    /// `Some((reason, goal))` when this record is a sub-agent spawn marker.
    spawn: Option<(Option<String>, String)>,
}

/// Structured JSONL extractor. Returns `None` when the transcript contains no
/// JSON object lines (so the caller falls back to the text scan). Otherwise it
/// reconstructs delegation depth from the record graph:
///
/// * each line is parsed as a JSON object; `uuid` / `parentUuid` build the
///   parent linkage and `isSidechain` marks records produced *inside* a
///   sub-agent turn;
/// * a record is a spawn when it carries a `Task` / `subagent` tool-use block
///   (or a top-level `subagent_type` / `delegate_to` / `spawn_agent` key);
/// * a spawn's depth is `1 + (number of `isSidechain` ancestors)`, so a spawn
///   issued from the top-level agent is depth 1, a spawn issued from within a
///   sub-agent turn is depth 2, and so on -- capped at 16 with a cycle guard.
fn extract_spawn_markers_structured(transcript: &str) -> Option<Vec<RawSpawn>> {
    let mut records: Vec<StructRecord> = Vec::new();
    let mut by_uuid: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut saw_object = false;

    for line in transcript.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(serde_json::Value::Object(map)) => serde_json::Value::Object(map),
            _ => continue,
        };
        saw_object = true;

        let uuid = value
            .get("uuid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let parent_uuid = value
            .get("parentUuid")
            .or_else(|| value.get("parent_uuid"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let is_sidechain = value
            .get("isSidechain")
            .or_else(|| value.get("is_sidechain"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let spawn = json_spawn_marker(&value);

        let idx = records.len();
        if let Some(u) = uuid {
            by_uuid.insert(u, idx);
        }
        records.push(StructRecord {
            parent_uuid,
            is_sidechain,
            spawn,
        });
    }

    if !saw_object {
        return None;
    }

    let mut spawns = Vec::new();
    for rec in &records {
        let Some((reason, goal_text)) = &rec.spawn else {
            continue;
        };
        let depth = sidechain_depth(rec, &records, &by_uuid);
        spawns.push(RawSpawn {
            depth,
            spawn_reason: reason.clone(),
            goal_text: goal_text.chars().take(400).collect::<String>(),
        });
    }
    Some(spawns)
}

/// Compute a spawn record's delegation depth as `1 + sidechain ancestor count`.
/// Walks the `parentUuid` chain with a cycle guard (bounded to 64 hops) and
/// caps the result at 16 to match the legacy depth ceiling.
fn sidechain_depth(
    rec: &StructRecord,
    records: &[StructRecord],
    by_uuid: &std::collections::HashMap<String, usize>,
) -> u32 {
    let mut sidechain_ancestors = 0u32;
    let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut cursor = rec.parent_uuid.clone();
    let mut hops = 0;
    while let Some(parent) = cursor {
        hops += 1;
        if hops > 64 {
            break;
        }
        let Some(&pidx) = by_uuid.get(&parent) else {
            break;
        };
        if !visited.insert(pidx) {
            break; // cycle
        }
        let parent_rec = &records[pidx];
        if parent_rec.is_sidechain {
            sidechain_ancestors += 1;
        }
        cursor = parent_rec.parent_uuid.clone();
    }
    (1 + sidechain_ancestors).min(16)
}

/// Detect whether a parsed JSONL record represents a sub-agent spawn, returning
/// `(spawn_reason, goal_text)` when it does. Recognises both the tool-use
/// envelope shape (`message.content[].type == "tool_use"` with a `Task` /
/// `subagent` name) and a bare top-level tool-use object, plus a top-level
/// `subagent_type` / `delegate_to` / `spawn_agent` key as a last resort.
fn json_spawn_marker(value: &serde_json::Value) -> Option<(Option<String>, String)> {
    // Bare tool-use object on the line itself.
    if let Some(found) = tool_use_spawn(value) {
        return Some(found);
    }
    // Standard envelope: message.content is an array of content blocks.
    if let Some(content) = value
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
    {
        for item in content {
            if let Some(found) = tool_use_spawn(item) {
                return Some(found);
            }
        }
    }
    // Last resort: a top-level delegation key.
    for key in ["subagent_type", "delegate_to", "spawn_agent"] {
        if let Some(val) = value.get(key).and_then(|v| v.as_str()) {
            if !val.is_empty() {
                return Some((Some(val.to_string()), val.to_string()));
            }
        }
    }
    None
}

/// Inspect a single content block / object for a `Task`-class tool use and, if
/// found, derive `(spawn_reason, goal_text)` from its `input` payload.
fn tool_use_spawn(item: &serde_json::Value) -> Option<(Option<String>, String)> {
    let ty = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if !ty.eq_ignore_ascii_case("tool_use") && !ty.eq_ignore_ascii_case("tooluse") {
        return None;
    }
    let name = item
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let name_lower = name.to_ascii_lowercase();
    let input = item.get("input");

    let input_key = |k: &str| -> Option<String> {
        input
            .and_then(|i| i.get(k))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };

    let subagent_type = input_key("subagent_type");
    let delegate_to = input_key("delegate_to");
    let spawn_agent = input_key("spawn_agent");

    let is_task = name_lower == "task"
        || name_lower == "subagent"
        || name_lower == "dispatch_agent"
        || subagent_type.is_some()
        || delegate_to.is_some()
        || spawn_agent.is_some();
    if !is_task {
        return None;
    }

    let reason = subagent_type
        .clone()
        .or_else(|| delegate_to.clone())
        .or_else(|| spawn_agent.clone())
        .or_else(|| (!name.is_empty()).then(|| name.clone()));

    let goal_text = input_key("description")
        .or_else(|| input_key("prompt"))
        .or_else(|| input_key("goal"))
        .or_else(|| subagent_type.clone())
        .or_else(|| (!name.is_empty()).then(|| name.clone()))
        .unwrap_or_else(|| "task".to_string());

    Some((reason, goal_text))
}

fn extract_marker_reason(lower: &str) -> Option<String> {
    for key in [
        "subagent_type",
        "delegate_to",
        "spawn_agent",
        "dispatch_agent",
    ] {
        if let Some(idx) = lower.find(key) {
            let tail = &lower[idx + key.len()..];
            let val: String = tail
                .chars()
                .skip_while(|c| *c == '"' || *c == ':' || *c == ' ' || *c == '=')
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

fn goal_loop_hash(goal_text: &str) -> String {
    let mut tokens: Vec<String> = goal_text
        .to_ascii_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 3)
        .map(|t| t.to_string())
        .collect();
    tokens.sort();
    tokens.dedup();
    short_hash(&tokens.join(" "))
}

/// Analyze a set of spawn markers into a delegation tree with recursion-risk
/// findings. Three independent signals can fire:
///
/// * **Same-purpose loop** -- the same goal hash recurs either at increasing
///   delegation depth (nested transcripts) or at least `RECURSION_LOOP_MIN_REPEATS`
///   times overall (flat transcripts where nested sub-agent turns are not
///   inlined and every spawn reads at depth 1).
/// * **Excessive depth** -- `max_depth >= RECURSION_DEPTH_HIGH`.
/// * **Excessive fan-out** -- a single session dispatches
///   `>= RECURSION_FANOUT_HIGH` sub-agents.
pub fn analyze_delegation(
    agent_type: &str,
    agent_instance_id: &str,
    spawns: &[RawSpawn],
) -> DelegationTree {
    let now = chrono::Utc::now();
    let root = DelegationNode {
        node_id: short_hash(&format!("{}|{}|root", agent_type, agent_instance_id)),
        agent_type: agent_type.to_string(),
        agent_instance_id: agent_instance_id.to_string(),
        delegation_depth: 0,
        spawn_reason: None,
        loop_hash: None,
        children: Vec::new(),
    };

    let mut tree = DelegationTree {
        agent_type: agent_type.to_string(),
        agent_instance_id: agent_instance_id.to_string(),
        generated_at: now,
        root,
        max_depth: 0,
        total_nodes: 1,
        loop_detected: false,
        findings: Vec::new(),
    };

    // Track the first depth a goal hash was seen at (for the increasing-depth
    // loop signal) and how many times each goal hash recurs (for the flat
    // repetition signal). `repeated_goal_loop` records the strongest repeat.
    let mut hash_first_depth: BTreeMap<String, u32> = BTreeMap::new();
    let mut hash_counts: BTreeMap<String, u32> = BTreeMap::new();
    let mut max_depth = 0u32;
    let mut repeated_goal_loop = false;
    let mut max_repeat = 1u32;

    // Flat children attached to root for the MVP (the depth field preserves
    // the nesting signal without a full reconstruction of the call tree).
    for spawn in spawns {
        let depth = spawn.depth.max(1);
        max_depth = max_depth.max(depth);
        let loop_hash = goal_loop_hash(&spawn.goal_text);
        let node = DelegationNode {
            node_id: short_hash(&format!(
                "{}|{}|{}|{}",
                agent_type, agent_instance_id, depth, spawn.goal_text
            )),
            agent_type: agent_type.to_string(),
            agent_instance_id: agent_instance_id.to_string(),
            delegation_depth: depth,
            spawn_reason: spawn.spawn_reason.clone(),
            loop_hash: Some(loop_hash.clone()),
            children: Vec::new(),
        };
        tree.root.children.push(node);
        tree.total_nodes += 1;

        let count = hash_counts.entry(loop_hash.clone()).or_insert(0);
        *count += 1;
        max_repeat = max_repeat.max(*count);
        if *count >= RECURSION_LOOP_MIN_REPEATS {
            repeated_goal_loop = true;
        }

        match hash_first_depth.get(&loop_hash) {
            Some(&first) if depth > first => {
                tree.loop_detected = true;
            }
            None => {
                hash_first_depth.insert(loop_hash, depth);
            }
            _ => {}
        }
    }
    tree.max_depth = max_depth;
    tree.loop_detected = tree.loop_detected || repeated_goal_loop;

    // Sub-agents spawned from root (every node except the synthetic root).
    let fan_out = tree.total_nodes.saturating_sub(1);

    let subject = short_hash(&format!("{}|{}", agent_type, agent_instance_id));
    if tree.loop_detected {
        let detail = if tree.max_depth >= 2 {
            format!(
                "Agent '{}' delegated to a sub-agent with the same goal at increasing depth (max depth {}).",
                agent_type, tree.max_depth
            )
        } else {
            format!(
                "Agent '{}' re-delegated the same goal {} times in one session (>= {}).",
                agent_type, max_repeat, RECURSION_LOOP_MIN_REPEATS
            )
        };
        tree.findings.push(
            VisibilityFinding::new(
                "recursion",
                "recursion_same_purpose_loop",
                VisibilitySeverity::High,
                &subject,
                "Same-purpose delegation loop detected",
                detail,
            )
            .with_evidence("agent_type", agent_type.to_string())
            .with_evidence("max_depth", tree.max_depth.to_string())
            .with_evidence("max_repeat", max_repeat.to_string())
            .with_evidence("total_nodes", tree.total_nodes.to_string())
            .with_owasp(),
        );
    } else if tree.max_depth >= RECURSION_DEPTH_HIGH {
        tree.findings.push(
            VisibilityFinding::new(
                "recursion",
                "recursion_excessive_depth",
                VisibilitySeverity::Medium,
                &subject,
                "Excessive delegation depth",
                format!(
                    "Agent '{}' reached delegation depth {} (>= {}).",
                    agent_type, tree.max_depth, RECURSION_DEPTH_HIGH
                ),
            )
            .with_evidence("agent_type", agent_type.to_string())
            .with_evidence("max_depth", tree.max_depth.to_string())
            .with_owasp(),
        );
    } else if fan_out >= RECURSION_FANOUT_HIGH {
        tree.findings.push(
            VisibilityFinding::new(
                "recursion",
                "recursion_excessive_fanout",
                VisibilitySeverity::Medium,
                &subject,
                "High sub-agent fan-out",
                format!(
                    "Agent '{}' spawned {} sub-agents in one session (>= {}).",
                    agent_type, fan_out, RECURSION_FANOUT_HIGH
                ),
            )
            .with_evidence("agent_type", agent_type.to_string())
            .with_evidence("fan_out", fan_out.to_string())
            .with_evidence("max_depth", tree.max_depth.to_string())
            .with_owasp(),
        );
    }

    tree
}

/// Convenience: extract spawn markers from a transcript and analyze in one
/// call. Core uses this on each collected transcript body.
pub fn analyze_delegation_from_transcript(
    agent_type: &str,
    agent_instance_id: &str,
    transcript: &str,
) -> DelegationTree {
    let spawns = extract_spawn_markers(transcript);
    analyze_delegation(agent_type, agent_instance_id, &spawns)
}

/// Content-addressed hash of an instruction/config file body for SBOM `file`
/// components. Never stores the body (invariant I5). Returns `None` if the
/// file cannot be read.
pub fn hash_instruction_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(hash_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn groups_for_user_matches_trailing_member_list_only() {
        let group_file = "\
root:x:0:
wheel:*:0:alice
admin:*:80:alice,bob
staff:*:20:bob
sudo:x:27:alice
";
        let mut groups = groups_for_user(group_file, "alice");
        groups.sort();
        assert_eq!(groups, vec!["admin", "sudo", "wheel"]);
        // bob is in admin + staff but not wheel/sudo.
        let mut bob = groups_for_user(group_file, "bob");
        bob.sort();
        assert_eq!(bob, vec!["admin", "staff"]);
        // A user in no member list gets nothing.
        assert!(groups_for_user(group_file, "carol").is_empty());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn scan_sudoers_nopasswd_matches_user_group_and_all() {
        let group_principals = vec!["%admin".to_string(), "%wheel".to_string()];
        // Direct user grant.
        let by_user = "alice ALL=(ALL) NOPASSWD: ALL";
        assert_eq!(
            scan_sudoers_nopasswd(by_user, "alice", &group_principals),
            vec!["alice".to_string()]
        );
        // Group grant via %admin.
        let by_group = "%admin ALL=(ALL) NOPASSWD: ALL";
        assert_eq!(
            scan_sudoers_nopasswd(by_group, "alice", &group_principals),
            vec!["%admin".to_string()]
        );
        // Wildcard principal.
        let by_all = "ALL ALL=(ALL) NOPASSWD: /usr/bin/whatever";
        assert_eq!(
            scan_sudoers_nopasswd(by_all, "alice", &group_principals),
            vec!["ALL".to_string()]
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn scan_sudoers_nopasswd_ignores_comments_defaults_and_password_rules() {
        let group_principals = vec!["%admin".to_string()];
        let text = "\
# alice ALL=(ALL) NOPASSWD: ALL  -- commented out, must NOT match
Defaults env_reset
Defaults!/usr/bin/foo NOPASSWD
%wheel ALL=(ALL) ALL
bob ALL=(ALL) NOPASSWD: ALL
%staff ALL=(ALL) NOPASSWD: ALL
";
        // alice is not bob, not in %staff, %admin is the only group she'd match
        // and it isn't present -> no hits despite the commented line mentioning her.
        assert!(scan_sudoers_nopasswd(text, "alice", &group_principals).is_empty());
        // bob has a real NOPASSWD line.
        assert_eq!(
            scan_sudoers_nopasswd(text, "bob", &group_principals),
            vec!["bob".to_string()]
        );
    }

    fn host_privilege_fixture(assessed: bool, passwordless_root: bool) -> HostPrivilege {
        HostPrivilege {
            elevated_session: false,
            admin_user: passwordless_root,
            passwordless_root,
            evidence: Vec::new(),
            platform: "test".to_string(),
            user: "alice".to_string(),
            assessed,
        }
    }

    fn agent_sandbox_fixture(agent_type: &str, sandboxed: Option<bool>) -> AgentSandbox {
        AgentSandbox {
            agent_type: agent_type.to_string(),
            sandboxed,
            mechanism: "none".to_string(),
            detail: String::new(),
            file_access_scope: "user_files".to_string(),
            file_access_detail: String::new(),
            can_launch_arbitrary_commands: Some(true),
            command_execution_detail: String::new(),
        }
    }

    #[test]
    fn blast_radius_fires_on_unsandboxed_plus_passwordless_root() {
        let host = host_privilege_fixture(true, true);
        let sandboxes = vec![agent_sandbox_fixture("cursor", Some(false))];
        let out = agents_with_blast_radius(&host, &sandboxes, &BTreeMap::new());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].agent_type, "cursor");
        assert!(out[0].unsandboxed);
        assert!(out[0].passwordless_root);
        assert!(!out[0].critical_subprocess);
    }

    #[test]
    fn blast_radius_fires_on_unsandboxed_plus_critical_subprocess() {
        // No passwordless root, but the agent has spawned a critical subprocess.
        let host = host_privilege_fixture(true, false);
        let sandboxes = vec![agent_sandbox_fixture("claude_code", Some(false))];
        let mut critical = BTreeMap::new();
        critical.insert("claude_code".to_string(), 2u32);
        let out = agents_with_blast_radius(&host, &sandboxes, &critical);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].agent_type, "claude_code");
        assert!(out[0].critical_subprocess);
        assert!(!out[0].passwordless_root);
    }

    #[test]
    fn blast_radius_quiet_when_unsandboxed_but_no_amplifier() {
        // Unsandboxed alone is not enough -- it is the common workstation case.
        let host = host_privilege_fixture(true, false);
        let sandboxes = vec![agent_sandbox_fixture("cursor", Some(false))];
        let out = agents_with_blast_radius(&host, &sandboxes, &BTreeMap::new());
        assert!(out.is_empty());
    }

    #[test]
    fn blast_radius_quiet_when_os_confined_even_with_amplifiers() {
        // A positively OS-confined agent is bounded by its sandbox regardless of
        // host passwordless root or its own critical subprocess usage.
        let host = host_privilege_fixture(true, true);
        let sandboxes = vec![agent_sandbox_fixture("sandboxed_agent", Some(true))];
        let mut critical = BTreeMap::new();
        critical.insert("sandboxed_agent".to_string(), 5u32);
        let out = agents_with_blast_radius(&host, &sandboxes, &critical);
        assert!(out.is_empty());
    }

    #[test]
    fn blast_radius_quiet_when_sandbox_unassessed() {
        // `None` is "could not determine" -- not a claim, so never qualifies.
        let host = host_privilege_fixture(true, true);
        let sandboxes = vec![agent_sandbox_fixture("unknown_agent", None)];
        let out = agents_with_blast_radius(&host, &sandboxes, &BTreeMap::new());
        assert!(out.is_empty());
    }

    #[test]
    fn blast_radius_ignores_unassessed_host_passwordless_root() {
        // An unassessed host must not be treated as privileged; only the
        // per-agent critical subprocess amplifier can fire here.
        let host = host_privilege_fixture(false, true);
        let sandboxes = vec![
            agent_sandbox_fixture("cursor", Some(false)),
            agent_sandbox_fixture("claude_code", Some(false)),
        ];
        let mut critical = BTreeMap::new();
        critical.insert("claude_code".to_string(), 1u32);
        let out = agents_with_blast_radius(&host, &sandboxes, &critical);
        // cursor has no amplifier (host unassessed, no critical subprocess);
        // claude_code fires on its critical subprocess only.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].agent_type, "claude_code");
        assert!(!out[0].passwordless_root);
        assert!(out[0].critical_subprocess);
    }

    #[test]
    fn blast_radius_is_sorted_by_agent_type() {
        let host = host_privilege_fixture(true, true);
        let sandboxes = vec![
            agent_sandbox_fixture("openclaw", Some(false)),
            agent_sandbox_fixture("cursor", Some(false)),
            agent_sandbox_fixture("claude_code", Some(false)),
        ];
        let out = agents_with_blast_radius(&host, &sandboxes, &BTreeMap::new());
        let names: Vec<&str> = out.iter().map(|a| a.agent_type.as_str()).collect();
        assert_eq!(names, vec!["claude_code", "cursor", "openclaw"]);
    }

    // --- Agent governance harness presence (AI-SDLC posture) -----------------

    fn harness_fixture(slug: &str, detected: bool) -> AgentHarness {
        AgentHarness {
            slug: slug.to_string(),
            display_name: slug.to_string(),
            detected,
            evidence: if detected {
                vec![format!("~/.config/{slug}")]
            } else {
                Vec::new()
            },
        }
    }

    #[test]
    fn agents_without_harness_fires_when_agents_present_and_no_harness() {
        let harnesses = vec![
            harness_fixture("agentfield", false),
            harness_fixture("rippletide", false),
        ];
        // Agents present + no harness detected -> the AI-SDLC gap fires.
        assert!(agents_without_harness(2, &harnesses));
        // No agents present -> nothing to govern, so it never fires.
        assert!(!agents_without_harness(0, &harnesses));
    }

    #[test]
    fn agents_without_harness_clears_when_any_harness_detected() {
        let harnesses = vec![
            harness_fixture("agentfield", true),
            harness_fixture("rippletide", false),
        ];
        // A single detected harness clears the gap even with agents present.
        assert!(!agents_without_harness(3, &harnesses));
    }

    #[test]
    fn detect_agent_harnesses_all_undetected_on_empty_home() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Empty PATH so the host's real PATH cannot flake the result.
        let harnesses = detect_agent_harnesses_with(tmp.path(), &[]);
        assert_eq!(harnesses.len(), KNOWN_AGENT_HARNESSES.len());
        assert!(harnesses
            .iter()
            .all(|h| !h.detected && h.evidence.is_empty()));
        // Stable, sorted slugs.
        let slugs: Vec<&str> = harnesses.iter().map(|h| h.slug.as_str()).collect();
        assert_eq!(slugs, vec!["agentfield", "rippletide"]);
    }

    #[test]
    fn detect_agent_harnesses_finds_xdg_config_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".config").join("agentfield")).unwrap();
        let harnesses = detect_agent_harnesses_with(tmp.path(), &[]);
        let af = harnesses.iter().find(|h| h.slug == "agentfield").unwrap();
        assert!(af.detected);
        assert!(af.evidence.iter().any(|e| e.contains("agentfield")));
        // The sibling harness stays undetected.
        let rt = harnesses.iter().find(|h| h.slug == "rippletide").unwrap();
        assert!(!rt.detected);
    }

    #[test]
    fn detect_agent_harnesses_finds_home_bin_cli() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bin_dir = tmp.path().join(".local").join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let bin_name = if cfg!(target_os = "windows") {
            "rippletide.exe"
        } else {
            "rippletide"
        };
        std::fs::write(bin_dir.join(bin_name), b"#!/bin/sh\n").unwrap();
        let harnesses = detect_agent_harnesses_with(tmp.path(), &[]);
        let rt = harnesses.iter().find(|h| h.slug == "rippletide").unwrap();
        assert!(rt.detected);
        assert!(rt.evidence.iter().any(|e| e.contains("rippletide")));
    }

    #[test]
    fn detect_agent_harnesses_finds_binary_on_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path_dir = tmp.path().join("opt-bin");
        std::fs::create_dir_all(&path_dir).unwrap();
        let bin_name = if cfg!(target_os = "windows") {
            "agentfield.exe"
        } else {
            "agentfield"
        };
        std::fs::write(path_dir.join(bin_name), b"#!/bin/sh\n").unwrap();
        // Home is empty; the binary is only reachable via the injected PATH.
        let harnesses = detect_agent_harnesses_with(tmp.path(), &[path_dir]);
        let af = harnesses.iter().find(|h| h.slug == "agentfield").unwrap();
        assert!(af.detected);
        assert!(af.evidence.iter().any(|e| e.contains("on PATH")));
    }

    #[test]
    fn detect_agent_harnesses_finds_windows_appdata_config_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        // %APPDATA%\{slug} == ~/AppData/Roaming/{slug}. The marker scan is
        // unconditional across platforms, so this resolves on any host (the
        // Windows config gap this guards against would otherwise be missed).
        std::fs::create_dir_all(tmp.path().join("AppData").join("Roaming").join("rippletide"))
            .unwrap();
        let harnesses = detect_agent_harnesses_with(tmp.path(), &[]);
        let rt = harnesses.iter().find(|h| h.slug == "rippletide").unwrap();
        assert!(rt.detected);
        assert!(rt.evidence.iter().any(|e| e.contains("rippletide")));
        // The sibling harness stays undetected.
        let af = harnesses.iter().find(|h| h.slug == "agentfield").unwrap();
        assert!(!af.detected);
    }

    #[test]
    fn detect_agent_harnesses_finds_windows_localappdata_config_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        // %LOCALAPPDATA%\{slug} == ~/AppData/Local/{slug}.
        std::fs::create_dir_all(tmp.path().join("AppData").join("Local").join("agentfield"))
            .unwrap();
        let harnesses = detect_agent_harnesses_with(tmp.path(), &[]);
        let af = harnesses.iter().find(|h| h.slug == "agentfield").unwrap();
        assert!(af.detected);
        assert!(af.evidence.iter().any(|e| e.contains("agentfield")));
    }

    #[test]
    fn detect_agent_harnesses_finds_windows_npm_global_bin() {
        let tmp = tempfile::TempDir::new().unwrap();
        // npm's Windows global prefix (%APPDATA%\npm) is a home bin dir, so the
        // helper-as-root path resolves a user-installed CLI shim there.
        let bin_dir = tmp.path().join("AppData").join("Roaming").join("npm");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let bin_name = if cfg!(target_os = "windows") {
            "agentfield.cmd"
        } else {
            "agentfield"
        };
        std::fs::write(bin_dir.join(bin_name), b"#!/bin/sh\n").unwrap();
        let harnesses = detect_agent_harnesses_with(tmp.path(), &[]);
        let af = harnesses.iter().find(|h| h.slug == "agentfield").unwrap();
        assert!(af.detected);
        assert!(af.evidence.iter().any(|e| e.contains("agentfield")));
    }

    fn endpoint_from_json(agent: &str, name: &str, entry: &str) -> McpEndpoint {
        let raw = format!(r#"{{"mcpServers":{{"{}":{}}}}}"#, name, entry);
        let servers = parse_mcp_json(&raw);
        assert_eq!(servers.len(), 1, "expected one server from {}", raw);
        let server = servers.into_iter().next().unwrap();
        build_endpoint(agent, server, "/tmp/mcp.json", false)
    }

    #[test]
    fn owasp_refs_cover_every_emitted_rule_and_tag_is_metadata_only() {
        // Every rule_id emitted by a visibility domain MUST resolve to an OWASP
        // mapping so `.with_owasp()` is never a silent no-op at a real emitter
        // site. Adding a new emitter rule without extending
        // `owasp_refs_for_rule` fails this test.
        let emitted_rules = [
            "mcp_public_no_strong_auth",
            "mcp_remote_cleartext_transport",
            "mcp_remote_saas_endpoint",
            "mcp_lan_privileged_no_auth",
            "mcp_unclassified_transport",
            "recursion_same_purpose_loop",
            "recursion_excessive_depth",
            "recursion_excessive_fanout",
            "drift_goal_divergence",
            "drift_recursion_escalation",
            "cascading_failure",
            "unbounded_consumption",
            "dataflow_sensitive_egress",
            "memory_poisoning_surface",
            "a2a_exposed_peer",
            "a2a_confused_deputy",
        ];
        for rule in emitted_rules {
            assert!(
                owasp_refs_for_rule(rule).is_some(),
                "rule_id '{}' has no OWASP mapping",
                rule
            );
        }
        // An unmapped rule_id stays untagged rather than getting a bogus mapping.
        assert!(owasp_refs_for_rule("definitely_unmapped_rule_xyz").is_none());

        // `with_owasp` is metadata-only: it adds the `owasp_refs` evidence entry
        // and changes nothing else (severity / finding_key / rule_id preserved),
        // so the OWASP tag is never a new alert source.
        let base = VisibilityFinding::new(
            "drift",
            "cascading_failure",
            VisibilitySeverity::High,
            "subj-1",
            "t",
            "d",
        );
        let key_before = base.finding_key.clone();
        let sev_before = base.severity;
        let tagged = base.with_owasp();
        assert_eq!(
            tagged.evidence.get("owasp_refs").map(String::as_str),
            Some("OWASP-ASI08,OWASP-LLM10")
        );
        assert_eq!(tagged.finding_key, key_before);
        assert_eq!(tagged.severity, sev_before);

        // Unmapped rule_id -> no `owasp_refs` key inserted (pure no-op).
        let untagged = VisibilityFinding::new(
            "sbom",
            "definitely_unmapped_rule_xyz",
            VisibilitySeverity::Low,
            "subj-2",
            "t",
            "d",
        )
        .with_owasp();
        assert!(!untagged.evidence.contains_key("owasp_refs"));
    }

    #[test]
    fn stdio_command_server_is_stdio_scope() {
        let ep = endpoint_from_json(
            "cursor",
            "fs",
            r#"{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/"]}"#,
        );
        assert_eq!(ep.transport, "stdio");
        assert_eq!(ep.exposure_scope, ExposureScope::Stdio);
        // filesystem keyword -> FilesystemWrite + FilesystemRead.
        assert!(ep
            .tool_privilege_classes
            .iter()
            .any(|c| c.is_high_privilege()));
    }

    #[test]
    fn loopback_http_is_loopback() {
        let ep = endpoint_from_json("cursor", "local", r#"{"url":"http://127.0.0.1:8080/mcp"}"#);
        assert_eq!(ep.transport, "http");
        assert_eq!(ep.exposure_scope, ExposureScope::Loopback);
    }

    #[test]
    fn remote_https_no_auth_is_low_informational() {
        // A public hostname behind an https client URL is the agent connecting
        // OUT to a third-party SaaS endpoint -- NOT a local server exposed
        // beyond loopback. It must be classified Remote and graded LOW (not
        // alertable), never as the inbound-exposure HIGH finding.
        let ep = endpoint_from_json("cursor", "remote", r#"{"url":"https://example.com/mcp"}"#);
        assert_eq!(ep.exposure_scope, ExposureScope::Remote);
        assert_eq!(ep.auth_strength, AuthStrength::None);
        let findings = assess_mcp_risk(&[ep]);
        // No inbound-exposure finding for a remote SaaS endpoint.
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "mcp_public_no_strong_auth"));
        let saas = findings
            .iter()
            .find(|f| f.rule_id == "mcp_remote_saas_endpoint")
            .expect("remote saas finding present");
        assert_eq!(saas.severity, VisibilitySeverity::Low);
        assert!(!saas.severity.is_alertable());
    }

    #[test]
    fn remote_tls_privileged_no_auth_is_medium_not_alertable() {
        // A remote endpoint that exposes high-privilege tools with no detectable
        // auth is escalated to MEDIUM (a visible heads-up) but stays below the
        // alertable HIGH/CRITICAL bar -- trusting a vendor is an operator
        // decision, not a host breach.
        let ep = endpoint_from_json(
            "cursor",
            "shell",
            r#"{"url":"https://exposed.example/mcp","type":"http"}"#,
        );
        assert_eq!(ep.exposure_scope, ExposureScope::Remote);
        assert!(ep
            .tool_privilege_classes
            .iter()
            .any(|c| c.is_high_privilege()));
        let findings = assess_mcp_risk(&[ep]);
        let saas = findings
            .iter()
            .find(|f| f.rule_id == "mcp_remote_saas_endpoint")
            .expect("remote saas finding present");
        assert_eq!(saas.severity, VisibilitySeverity::Medium);
        assert!(!saas.severity.is_alertable());
    }

    #[test]
    fn remote_cleartext_transport_is_high_alertable() {
        // http:// to a public host = agent context + creds over cleartext
        // internet. This IS the real, alertable remote risk.
        let ep = endpoint_from_json(
            "cursor",
            "remote",
            r#"{"url":"http://api.example.com/mcp","type":"http"}"#,
        );
        assert_eq!(ep.exposure_scope, ExposureScope::Remote);
        let findings = assess_mcp_risk(&[ep]);
        let cleartext = findings
            .iter()
            .find(|f| f.rule_id == "mcp_remote_cleartext_transport")
            .expect("cleartext finding present");
        assert_eq!(cleartext.severity, VisibilitySeverity::High);
        assert!(cleartext.severity.is_alertable());
    }

    #[test]
    fn bind_all_no_auth_is_public_high_alertable() {
        // 0.0.0.0 is a bind-all *listen* address: a local server exposed beyond
        // loopback. This is the inbound-exposure case that keeps the HIGH
        // "mcp_public_no_strong_auth" finding.
        let ep = endpoint_from_json(
            "cursor",
            "localsrv",
            r#"{"url":"http://0.0.0.0:8080/mcp","type":"http"}"#,
        );
        assert_eq!(ep.exposure_scope, ExposureScope::Public);
        let findings = assess_mcp_risk(&[ep]);
        let public = findings
            .iter()
            .find(|f| f.rule_id == "mcp_public_no_strong_auth")
            .expect("public finding present");
        assert_eq!(public.severity, VisibilitySeverity::High);
        assert!(public.severity.is_alertable());
        // A bind-all server is NOT a remote SaaS endpoint.
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "mcp_remote_saas_endpoint"));
    }

    #[test]
    fn inline_url_secret_is_shared_auth_and_redacted() {
        // Mirrors the real `framer` Cursor config: an https SSE endpoint with a
        // `?...&secret=...` token. The token is auth (Shared, not None), the URL
        // query must NOT mint a SecretAccess privilege, and the stored URL must
        // be redacted (invariant I5).
        let ep = endpoint_from_json(
            "cursor",
            "framer",
            r#"{"type":"sse","url":"https://mcp.unframer.co/sse?id=abc123&secret=topsecretvalue"}"#,
        );
        assert_eq!(ep.transport, "sse");
        assert_eq!(ep.exposure_scope, ExposureScope::Remote);
        assert_eq!(ep.auth_strength, AuthStrength::Shared);
        // The `secret=` query param must not be mined as a SecretAccess tool.
        assert!(!ep
            .tool_privilege_classes
            .contains(&ToolPrivilegeClass::SecretAccess));
        // Stored URL is redacted -- never the raw secret (I5).
        let url = ep.url.as_deref().unwrap_or_default();
        assert!(url.contains("secret=REDACTED"), "url not redacted: {}", url);
        assert!(
            !url.contains("topsecretvalue"),
            "raw secret leaked: {}",
            url
        );
        // A TLS remote with shared-secret auth is LOW informational.
        let findings = assess_mcp_risk(&[ep]);
        let saas = findings
            .iter()
            .find(|f| f.rule_id == "mcp_remote_saas_endpoint")
            .expect("remote saas finding present");
        assert_eq!(saas.severity, VisibilitySeverity::Low);
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "mcp_public_no_strong_auth"));
    }

    #[test]
    fn userinfo_password_redacted_and_shared_auth() {
        let ep = endpoint_from_json(
            "cursor",
            "basicauth",
            r#"{"url":"https://user:hunter2@host.example/mcp","type":"http"}"#,
        );
        assert_eq!(ep.auth_strength, AuthStrength::Shared);
        let url = ep.url.as_deref().unwrap_or_default();
        assert!(!url.contains("hunter2"), "password leaked: {}", url);
        assert!(url.contains("user@host.example"), "userinfo wrong: {}", url);
    }

    #[test]
    fn oauth_server_is_oauth_strength() {
        let ep = endpoint_from_json(
            "cursor",
            "oauthsrv",
            r#"{"url":"https://example.com/mcp","type":"oauth"}"#,
        );
        assert_eq!(ep.auth_strength, AuthStrength::OAuth);
        // OAuth -> not flagged by the no-strong-auth rule.
        let findings = assess_mcp_risk(&[ep]);
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "mcp_public_no_strong_auth"));
    }

    #[test]
    fn edamame_own_server_never_flagged() {
        let raw = r#"{"mcpServers":{"edamame":{"url":"https://0.0.0.0/mcp"}}}"#;
        let server = parse_mcp_json(raw).into_iter().next().unwrap();
        let ep = build_endpoint("cursor", server, "/tmp/mcp.json", true);
        assert!(ep.is_edamame_server);
        let findings = assess_mcp_risk(&[ep]);
        assert!(findings.is_empty(), "edamame server must never be flagged");
    }

    #[test]
    fn shared_secret_env_is_shared_auth() {
        let ep = endpoint_from_json(
            "cursor",
            "tokensrv",
            r#"{"url":"https://example.com/mcp","env":{"API_TOKEN":"x"}}"#,
        );
        assert_eq!(ep.auth_strength, AuthStrength::Shared);
        // env captured by KEY only, never value.
        assert_eq!(ep.env_keys, vec!["API_TOKEN".to_string()]);
    }

    #[test]
    fn toml_codex_config_parses_servers() {
        let toml = r#"
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[mcp_servers.github.env]
GITHUB_TOKEN = "ghp_x"

[mcp_servers.fetch]
command = "uvx"
"#;
        let servers = parse_mcp_toml(toml);
        assert_eq!(servers.len(), 2);
        let github = servers.iter().find(|s| s.name == "github").unwrap();
        assert_eq!(github.command.as_deref(), Some("npx"));
        assert!(github.env_keys.contains(&"GITHUB_TOKEN".to_string()));
    }

    #[test]
    fn sbom_projects_app_and_services() {
        let ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let sboms = build_agent_sboms_from_endpoints(&[ep]);
        assert_eq!(sboms.len(), 1);
        let sbom = &sboms[0];
        assert_eq!(sbom.agent_type, "cursor");
        // app + one service.
        assert_eq!(sbom.components.len(), 2);
        assert!(sbom
            .components
            .iter()
            .any(|c| c.component_type == "application"));
        assert!(sbom
            .components
            .iter()
            .any(|c| c.component_type == "service"));
        // CycloneDX projection is well-formed.
        let cdx = sbom_to_cyclonedx(sbom);
        assert_eq!(cdx["bomFormat"], "CycloneDX");
        assert_eq!(cdx["specVersion"], "1.5");
        assert!(cdx["components"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn sbom_diff_detects_added_and_removed() {
        let base_ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let base = build_agent_sboms_from_endpoints(&[base_ep]).remove(0);

        let new_ep = endpoint_from_json("cursor", "git", r#"{"command":"npx"}"#);
        let current = build_agent_sboms_from_endpoints(&[new_ep]).remove(0);

        let diff = diff_sboms(Some(&base), &current);
        assert!(diff.baseline_present);
        // git service added, fs service removed (app ref is stable).
        assert!(diff.added.iter().any(|c| c.component_type == "service"));
        assert!(diff.removed.iter().any(|c| c.component_type == "service"));
    }

    #[test]
    fn capability_graph_has_declares_and_exposes_edges() {
        let ep = endpoint_from_json(
            "cursor",
            "shellsrv",
            r#"{"command":"bash","args":["-c","exec mcp"]}"#,
        );
        let edges = build_capability_graph_from_endpoints(&[ep]);
        assert!(edges.iter().any(|e| e.edge_type == "declares"));
        assert!(edges.iter().any(|e| e.edge_type == "exposes"));
        assert!(edges
            .iter()
            .all(|e| e.confidence == EdgeConfidence::Declared));
    }

    #[test]
    fn delegation_loop_detected_across_depth() {
        let spawns = vec![
            RawSpawn {
                depth: 1,
                spawn_reason: Some("research".to_string()),
                goal_text: "investigate the authentication bug in login flow".to_string(),
            },
            RawSpawn {
                depth: 2,
                spawn_reason: Some("research".to_string()),
                goal_text: "investigate the authentication bug in login flow".to_string(),
            },
        ];
        let tree = analyze_delegation("cursor", "host", &spawns);
        assert!(tree.loop_detected);
        assert!(tree
            .findings
            .iter()
            .any(|f| f.rule_id == "recursion_same_purpose_loop"));
    }

    #[test]
    fn delegation_excessive_depth_flagged() {
        let spawns = vec![RawSpawn {
            depth: 5,
            spawn_reason: None,
            goal_text: "do unrelated thing".to_string(),
        }];
        let tree = analyze_delegation("cursor", "host", &spawns);
        assert!(!tree.loop_detected);
        assert_eq!(tree.max_depth, 5);
        assert!(tree
            .findings
            .iter()
            .any(|f| f.rule_id == "recursion_excessive_depth"));
    }

    #[test]
    fn spawn_marker_extraction_from_transcript() {
        let transcript = r#"
{"type":"tool_use","name":"Task","input":{"subagent_type":"explore"}}
some normal line
  {"type":"tool_use","name":"Task","input":{"subagent_type":"general"}}
"#;
        let spawns = extract_spawn_markers(transcript);
        assert_eq!(spawns.len(), 2);
        assert!(spawns
            .iter()
            .any(|s| s.spawn_reason.as_deref() == Some("explore")));
    }

    #[test]
    fn structured_depth_from_sidechain_lineage() {
        // Compact JSONL (no indentation). The nested spawn (line C) is issued
        // from inside a sub-agent turn (line B has isSidechain=true), so its
        // reconstructed depth is 2 while the top-level spawn (line A) is 1.
        let transcript = concat!(
            r#"{"uuid":"a","parentUuid":null,"isSidechain":false,"type":"tool_use","name":"Task","input":{"subagent_type":"research","prompt":"top level goal"}}"#,
            "\n",
            r#"{"uuid":"b","parentUuid":"a","isSidechain":true,"type":"text","text":"sub-agent working"}"#,
            "\n",
            r#"{"uuid":"c","parentUuid":"b","isSidechain":true,"type":"tool_use","name":"Task","input":{"subagent_type":"research","prompt":"nested goal"}}"#,
            "\n",
        );
        let spawns = extract_spawn_markers(transcript);
        assert_eq!(spawns.len(), 2, "two Task spawns expected");
        assert!(
            spawns.iter().any(|s| s.depth == 1),
            "top-level spawn is depth 1"
        );
        assert!(
            spawns.iter().any(|s| s.depth == 2),
            "sidechain-nested spawn is depth 2, got {:?}",
            spawns.iter().map(|s| s.depth).collect::<Vec<_>>()
        );
    }

    #[test]
    fn spawn_marker_extraction_from_envelope_content() {
        // The standard envelope shape: tool_use lives under message.content[].
        let transcript = concat!(
            r#"{"uuid":"x","parentUuid":null,"isSidechain":false,"message":{"content":[{"type":"tool_use","name":"Task","input":{"description":"do X"}}]}}"#,
            "\n",
        );
        let spawns = extract_spawn_markers(transcript);
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0].depth, 1);
        assert_eq!(spawns[0].goal_text, "do X");
    }

    #[test]
    fn delegation_flat_repetition_loop_detected() {
        // The common flat-transcript shape: the same goal re-delegated three
        // times, all at depth 1 (nested sub-agent turns not inlined). The
        // repetition signal flags the loop even though depth never increases.
        let spawn = || RawSpawn {
            depth: 1,
            spawn_reason: Some("research".to_string()),
            goal_text: "scan the repository for hardcoded secrets".to_string(),
        };
        let spawns = vec![spawn(), spawn(), spawn()];
        let tree = analyze_delegation("cursor", "host", &spawns);
        assert!(tree.loop_detected, "flat repeated goal must flag a loop");
        assert_eq!(tree.max_depth, 1);
        assert!(tree
            .findings
            .iter()
            .any(|f| f.rule_id == "recursion_same_purpose_loop"));
    }

    #[test]
    fn delegation_excessive_fanout_flagged() {
        // Eight distinct sub-agent goals at depth 1: no loop, no deep nesting,
        // but the fan-out itself is worth surfacing.
        let goals = [
            "alpha repository inventory",
            "bravo database migration",
            "charlie network topology",
            "delta filesystem audit",
            "echo registry cleanup",
            "foxtrot kernel profiling",
            "golf scheduler tuning",
            "hotel compiler upgrade",
        ];
        let spawns: Vec<RawSpawn> = goals
            .iter()
            .map(|g| RawSpawn {
                depth: 1,
                spawn_reason: None,
                goal_text: g.to_string(),
            })
            .collect();
        let tree = analyze_delegation("cursor", "host", &spawns);
        assert!(!tree.loop_detected, "distinct goals must not flag a loop");
        assert_eq!(tree.max_depth, 1);
        assert!(tree
            .findings
            .iter()
            .any(|f| f.rule_id == "recursion_excessive_fanout"));
    }

    #[test]
    fn sbom_projects_tool_and_secret_components() {
        // A shell server wired to a secret env var yields, besides app +
        // service: a tool_capability component (Shell) and a secret_binding
        // component (the env key), each a dependency of the service.
        let ep = endpoint_from_json(
            "cursor",
            "shellsrv",
            r#"{"command":"bash","args":["-c","mcp"],"env":{"OPENAI_API_KEY":"x"}}"#,
        );
        let sbom = build_agent_sboms_from_endpoints(&[ep]).remove(0);

        let tool = sbom
            .components
            .iter()
            .find(|c| {
                c.properties.get("edamame:kind").map(|k| k.as_str()) == Some("tool_capability")
            })
            .expect("tool_capability component present");
        assert_eq!(tool.name, "Shell");
        assert_eq!(tool.component_type, "data");

        let secret = sbom
            .components
            .iter()
            .find(|c| {
                c.properties.get("edamame:kind").map(|k| k.as_str()) == Some("secret_binding")
            })
            .expect("secret_binding component present");
        // I5: the key name is captured, never the value.
        assert_eq!(secret.name, "OPENAI_API_KEY");
        assert!(secret.content_hash.is_none());

        // The service depends on both the tool and the secret binding.
        let svc_dep = sbom
            .dependencies
            .iter()
            .find(|d| d.bom_ref.starts_with("mcp:"))
            .expect("service dependency present");
        assert!(svc_dep
            .depends_on
            .iter()
            .any(|r| r.starts_with("tool:cursor:shell")));
        assert!(svc_dep
            .depends_on
            .iter()
            .any(|r| r.starts_with("env:cursor:OPENAI_API_KEY")));
    }

    #[test]
    fn unknown_tool_class_is_not_projected() {
        // "fs"/"npx" classifies as Unknown -> no tool component, just app+service.
        let ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let sbom = build_agent_sboms_from_endpoints(&[ep]).remove(0);
        assert!(!sbom
            .components
            .iter()
            .any(|c| c.bom_ref.contains("unclassified")));
    }

    #[test]
    fn is_secret_env_key_matches_credential_names() {
        assert!(is_secret_env_key("OPENAI_API_KEY"));
        assert!(is_secret_env_key("GITHUB_TOKEN"));
        assert!(is_secret_env_key("db_password"));
        assert!(is_secret_env_key("AWS_SECRET_ACCESS_KEY"));
        // Non-secret config keys are not flagged.
        assert!(!is_secret_env_key("LOG_LEVEL"));
        assert!(!is_secret_env_key("HOME"));
        assert!(!is_secret_env_key("PORT"));
    }

    #[test]
    fn capability_graph_edges_carry_human_labels() {
        let ep = endpoint_from_json(
            "cursor",
            "github",
            r#"{"command":"npx","args":["-y","server-github"],"url":"https://api.github.com/mcp"}"#,
        );
        let edges = build_capability_graph_from_endpoints(&[ep]);
        // declares edge: src is the agent type, dst is the server name (not hash).
        let declares = edges.iter().find(|e| e.edge_type == "declares").unwrap();
        assert_eq!(declares.src_label, "cursor");
        assert_eq!(declares.dst_label, "github");
        // exposes edge: dst label is the human-readable privilege class label.
        let exposes = edges.iter().find(|e| e.edge_type == "exposes").unwrap();
        assert_eq!(exposes.src_label, "github");
        assert_eq!(exposes.dst_label, "Git");
        // no edge ever carries the "Unclassified" label.
        assert!(edges.iter().all(|e| e.dst_label != "Unclassified"));
    }

    #[test]
    fn extract_models_from_transcript_recognizes_known_families() {
        let text = r#"
        {"model":"claude-opus-4-20250514","role":"assistant"}
        used openai:gpt-4o-mini for the cheap pass
        fallback to anthropic/claude-3-5-sonnet-20241022
        also tried gemini-2.0-flash and o3-mini
        prose mentioning claude code and a key should not match
        "#;
        let models = extract_models_from_transcript(text);
        assert!(models.iter().any(|m| m == "claude-opus-4-20250514"));
        assert!(models.iter().any(|m| m == "gpt-4o-mini"));
        // provider qualifier stripped.
        assert!(models.iter().any(|m| m == "claude-3-5-sonnet-20241022"));
        assert!(models.iter().any(|m| m == "gemini-2.0-flash"));
        assert!(models.iter().any(|m| m == "o3-mini"));
        // bare family words without a version digit are rejected.
        assert!(!models.iter().any(|m| m == "claude-code"));
        // deterministic ordering (sorted).
        let mut sorted = models.clone();
        sorted.sort();
        assert_eq!(models, sorted);
    }

    #[test]
    fn merge_models_into_sbom_dedups_and_wires_app_dependency() {
        let ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let mut sbom = build_agent_sboms_from_endpoints(&[ep]).remove(0);

        let first = merge_models_into_sbom(&mut sbom, &["claude-opus-4".to_string()]);
        assert!(first);
        let model_comp = sbom
            .components
            .iter()
            .find(|c| c.component_type == "machine-learning-model")
            .expect("model component present");
        assert_eq!(model_comp.name, "claude-opus-4");
        // wired as a dependency of the agent application root.
        let app_dep = sbom
            .dependencies
            .iter()
            .find(|d| d.bom_ref == "agent:cursor")
            .unwrap();
        assert!(app_dep
            .depends_on
            .iter()
            .any(|r| r == "model:cursor:claude-opus-4"));

        // Re-merging the same model is a no-op (dedup).
        let second = merge_models_into_sbom(&mut sbom, &["claude-opus-4".to_string()]);
        assert!(!second);
        assert_eq!(
            sbom.components
                .iter()
                .filter(|c| c.component_type == "machine-learning-model")
                .count(),
            1
        );
    }

    #[test]
    fn graph_edges_carry_trust_zones() {
        // Remote https SaaS URL (no command -> http transport) -> trust2 surface.
        let ep = endpoint_from_json(
            "cursor",
            "github",
            r#"{"url":"https://api.github.com/mcp"}"#,
        );
        assert_eq!(ep.exposure_scope, ExposureScope::Remote);
        let edges = build_capability_graph_from_endpoints(&[ep]);
        let declares = edges.iter().find(|e| e.edge_type == "declares").unwrap();
        assert_eq!(declares.src_zone, "trust0"); // agent identity
        assert_eq!(declares.dst_zone, "trust2"); // remote third-party mcp server
        let exposes = edges.iter().find(|e| e.edge_type == "exposes").unwrap();
        assert_eq!(exposes.dst_zone, "trust1"); // capability class

        // stdio command -> loopback/local, trust1 server.
        let stdio_ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let stdio_edges = build_capability_graph_from_endpoints(&[stdio_ep]);
        let stdio_declares = stdio_edges
            .iter()
            .find(|e| e.edge_type == "declares")
            .unwrap();
        assert_eq!(stdio_declares.dst_zone, "trust1");
    }

    #[test]
    fn reachability_flags_untrusted_crossing() {
        let ep = endpoint_from_json(
            "cursor",
            "github",
            r#"{"url":"https://api.github.com/mcp"}"#,
        );
        let edges = build_capability_graph_from_endpoints(&[ep]);
        let reach = compute_graph_reachability(&edges);
        let cursor = reach.iter().find(|r| r.agent_type == "cursor").unwrap();
        assert_eq!(cursor.max_zone, "trust2");
        assert!(cursor.crosses_to_untrusted);
        assert!(!cursor.boundary_edge_ids.is_empty());
        // agent reaches the mcp_server + tool_class(Git) + network_endpoint.
        assert!(cursor.reachable_node_count >= 2);
    }

    #[test]
    fn effective_capabilities_collects_reachable_classes() {
        let ep = endpoint_from_json(
            "cursor",
            "shell",
            r#"{"command":"bash","args":["-c","run"]}"#,
        );
        let edges = build_capability_graph_from_endpoints(&[ep]);
        let caps = compute_effective_capabilities(&edges);
        let cursor = caps.iter().find(|c| c.agent_type == "cursor").unwrap();
        // bash command -> Shell capability class (high privilege).
        assert!(cursor.capabilities.iter().any(|c| c == "Shell"));
        assert!(cursor.high_privilege);
    }

    #[test]
    fn classify_agent_precedence() {
        // acknowledged wins over everything (even observer off).
        assert_eq!(
            classify_agent(true, true, false, true),
            AgentClassification::Acknowledged
        );
        // unacknowledged + present + observer off -> shadow (blind spot).
        assert_eq!(
            classify_agent(false, true, false, true),
            AgentClassification::Shadow
        );
        // unacknowledged + discovered + observer off -> shadow.
        assert_eq!(
            classify_agent(false, true, false, false),
            AgentClassification::Shadow
        );
        // unacknowledged + present + observed -> new (first-seen tripwire).
        assert_eq!(
            classify_agent(false, true, true, true),
            AgentClassification::New
        );
        // unacknowledged + observed but no on-disk footprint -> new.
        assert_eq!(
            classify_agent(false, false, true, true),
            AgentClassification::New
        );
        // every not-acknowledged class needs operator review (alarm source).
        assert!(AgentClassification::New.needs_review());
        assert!(AgentClassification::Shadow.needs_review());
        assert!(!AgentClassification::Acknowledged.needs_review());
    }

    // -- Fix #1: authoritative structured model extraction -------------------

    #[test]
    fn extract_models_structured_reads_only_explicit_fields() {
        // A top-level `model` field, a `model` field nested one level inside a
        // `message` container, plus a model-shaped string sitting in a NON-model
        // field (`text`) and a prose mention on a non-JSON line. Only the two
        // explicit structured fields must be picked up; the prose / wrong-field
        // mentions are ignored (this is the whole point of authoritative-only).
        let transcript = r#"
{"role":"assistant","model":"claude-opus-4-20250514"}
{"type":"message","message":{"role":"assistant","model":"openai/gpt-4o-mini"}}
{"role":"assistant","text":"we should switch to claude-3-5-sonnet-20241022 here"}
plain prose mentioning gemini-2.0-flash should never match
"#;
        let models = extract_models_from_transcript_structured(transcript);
        // provider qualifier stripped, lowercased, sorted + deduped.
        assert_eq!(
            models,
            vec![
                "claude-opus-4-20250514".to_string(),
                "gpt-4o-mini".to_string()
            ]
        );
        // the model-shaped token in a non-model field is NOT mined.
        assert!(!models.iter().any(|m| m == "claude-3-5-sonnet-20241022"));
        // the prose mention is NOT mined.
        assert!(!models.iter().any(|m| m == "gemini-2.0-flash"));
    }

    #[test]
    fn extract_models_structured_empty_when_no_model_field() {
        // The canonical Cursor case: transcript text / JSON lines that carry no
        // explicit `model` field at all. We yield an empty set (the caller then
        // marks the agent `not_recorded`) rather than guessing from prose.
        let transcript = r#"
User: please refactor this function
{"role":"user","content":"please refactor this function"}
{"role":"assistant","content":"done, used the usual approach"}
"#;
        assert!(extract_models_from_transcript_structured(transcript).is_empty());
    }

    #[test]
    fn merge_models_marks_recorded_and_mark_source_is_idempotent() {
        let ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let mut sbom = build_agent_sboms_from_endpoints(&[ep]).remove(0);
        let app_ref = "agent:cursor".to_string();

        // Merging authoritative models marks the app root as `recorded`.
        assert!(merge_models_into_sbom(
            &mut sbom,
            &["claude-opus-4".to_string()]
        ));
        let app = sbom
            .components
            .iter()
            .find(|c| c.bom_ref == app_ref)
            .unwrap();
        assert_eq!(
            app.properties.get(MODELS_SOURCE_PROP).map(String::as_str),
            Some("recorded")
        );

        // An agent with no recorded models is explicitly marked `not_recorded`
        // (Cursor case) -- and re-marking the same value is a no-op.
        let no_model_ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let mut bare = build_agent_sboms_from_endpoints(&[no_model_ep]).remove(0);
        assert!(mark_models_source(&mut bare, "not_recorded"));
        assert!(!mark_models_source(&mut bare, "not_recorded"));
        let bare_app = bare
            .components
            .iter()
            .find(|c| c.bom_ref == app_ref)
            .unwrap();
        assert_eq!(
            bare_app
                .properties
                .get(MODELS_SOURCE_PROP)
                .map(String::as_str),
            Some("not_recorded")
        );
    }

    // -- Fix #4: per-(host, agent_type) instance id -------------------------

    #[test]
    fn sbom_instance_id_is_distinct_per_home() {
        let ep_a = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let ep_b = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let home_a = std::path::Path::new("/tmp/edamame-test-home-a");
        let home_b = std::path::Path::new("/tmp/edamame-test-home-b");

        let sbom_a = build_agent_sboms_from_endpoints_with_home(&[ep_a], Some(home_a)).remove(0);
        let sbom_b = build_agent_sboms_from_endpoints_with_home(&[ep_b], Some(home_b)).remove(0);

        // Same agent_type, two homes -> two DISTINCT instance ids, so the
        // Agents tab keys them separately instead of collapsing into one.
        assert_eq!(sbom_a.agent_type, "cursor");
        assert_eq!(sbom_b.agent_type, "cursor");
        assert_ne!(sbom_a.agent_instance_id, sbom_b.agent_instance_id);
        assert!(sbom_a.agent_instance_id.ends_with("-observer"));

        // Endpoint-only callers (no home) fall back to agent_type as the id.
        let ep_c = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let sbom_c = build_agent_sboms_from_endpoints(&[ep_c]).remove(0);
        assert_eq!(sbom_c.agent_instance_id, "cursor");
    }

    // -- Fix #5: structural-only baseline-drift alarm + signature -----------

    #[test]
    fn drift_alarm_ignores_model_only_change() {
        // Baseline and current have the SAME structural surface; the only
        // difference is a model component appearing on the current SBOM. A
        // model add/remove is dynamic state, NOT a supply-chain drift, so no
        // alarm must be raised.
        let base_ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let baseline = build_agent_sboms_from_endpoints(&[base_ep]).remove(0);

        let cur_ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let mut current = build_agent_sboms_from_endpoints(&[cur_ep]).remove(0);
        assert!(merge_models_into_sbom(
            &mut current,
            &["claude-opus-4".to_string()]
        ));

        let diff = diff_sboms(Some(&baseline), &current);
        // The model component is the only added component.
        assert!(diff
            .added
            .iter()
            .all(|c| c.component_type == "machine-learning-model"));
        assert!(sbom_drift_alarm("cursor", "cursor-inst", &diff).is_none());
    }

    #[test]
    fn drift_alarm_high_on_server_addition_with_stable_signature() {
        // Baseline = one server (fs); current = a different server (git).
        // Structurally: git added, fs removed -> capability surface expanded
        // -> HIGH (alertable), and the signature is deterministic across calls.
        let base_ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let baseline = build_agent_sboms_from_endpoints(&[base_ep]).remove(0);
        let new_ep = endpoint_from_json("cursor", "git", r#"{"command":"npx"}"#);
        let current = build_agent_sboms_from_endpoints(&[new_ep]).remove(0);

        let diff = diff_sboms(Some(&baseline), &current);
        let alarm =
            sbom_drift_alarm("cursor", "cursor-inst", &diff).expect("structural drift -> alarm");
        assert_eq!(alarm.finding.severity, VisibilitySeverity::High);
        assert!(alarm.finding.severity.is_alertable());
        assert_eq!(alarm.finding.rule_id, "sbom_baseline_drift");
        assert_eq!(alarm.finding.subject_id, "cursor-inst");
        assert_eq!(
            alarm.finding.evidence.get("drift_signature"),
            Some(&alarm.signature)
        );
        // OWASP metadata is attached (drift is a mapped rule).
        assert!(alarm.finding.evidence.contains_key("owasp_refs"));

        // Signature is a pure function of the structural drift set.
        let again = sbom_drift_alarm("cursor", "cursor-inst", &diff).unwrap();
        assert_eq!(alarm.signature, again.signature);
    }

    #[test]
    fn drift_alarm_medium_on_removal_only_and_distinct_signature() {
        // Baseline = two servers (fs + git); current = only fs (git removed).
        // Capability surface SHRANK -> MEDIUM (visible, not alertable), and the
        // signature differs from the add-and-remove case above.
        let fs_ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let git_ep = endpoint_from_json("cursor", "git", r#"{"command":"npx"}"#);
        let baseline = build_agent_sboms_from_endpoints(&[fs_ep, git_ep]).remove(0);

        let cur_fs = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let current = build_agent_sboms_from_endpoints(&[cur_fs]).remove(0);

        let diff = diff_sboms(Some(&baseline), &current);
        assert!(diff.added.iter().all(|c| !is_structural_component(c)));
        assert!(diff.removed.iter().any(is_structural_component));
        let alarm =
            sbom_drift_alarm("cursor", "cursor-inst", &diff).expect("removal is still drift");
        assert_eq!(alarm.finding.severity, VisibilitySeverity::Medium);
        assert!(!alarm.finding.severity.is_alertable());

        // Add-and-remove drift vs removal-only drift produce different sigs.
        let new_ep = endpoint_from_json("cursor", "git", r#"{"command":"npx"}"#);
        let only_fs_base = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let add_remove_base = build_agent_sboms_from_endpoints(&[only_fs_base]).remove(0);
        let add_remove_cur = build_agent_sboms_from_endpoints(&[new_ep]).remove(0);
        let add_remove_diff = diff_sboms(Some(&add_remove_base), &add_remove_cur);
        let add_remove_alarm = sbom_drift_alarm("cursor", "cursor-inst", &add_remove_diff).unwrap();
        assert_ne!(alarm.signature, add_remove_alarm.signature);
    }

    #[test]
    fn drift_alarm_none_without_baseline() {
        // No baseline present -> nothing to drift FROM -> no alarm.
        let ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let current = build_agent_sboms_from_endpoints(&[ep]).remove(0);
        let diff = diff_sboms(None, &current);
        assert!(!diff.baseline_present);
        assert!(sbom_drift_alarm("cursor", "cursor-inst", &diff).is_none());
    }
}
