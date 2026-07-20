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

use crate::agent_visibility_params;
use crate::supported_agents;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
    /// Domain that produced this finding (`mcp`, `graph`, `recursion`).
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
// Agent component inventory -- live-discovered instruction/capability surface
// ---------------------------------------------------------------------------

/// One component in an agent's live-discovered component inventory. This is the
/// augmentation / Enlightenment Coach backing: instruction/skill/rule/command
/// files, plus the MCP servers, tool-privilege classes, and secret bindings the
/// agent declares.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentComponent {
    /// Stable ref used as the dependency/dedup key.
    pub bom_ref: String,
    /// Component class: `application` | `service` | `data` | `file`.
    pub component_type: String,
    pub name: String,
    pub version: Option<String>,
    /// Content-addressed hash for `file` components (never the body, I5).
    pub content_hash: Option<String>,
    /// Extra metadata-only properties (transport, exposure, privilege, load,
    /// size, relpath, ...).
    pub properties: BTreeMap<String, String>,
}

/// Live-discovered component inventory for a single agent instance. Backs the
/// augmentation / Enlightenment Coach instruction-inventory path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentComponentInventory {
    pub agent_type: String,
    pub agent_instance_id: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub components: Vec<AgentComponent>,
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
///   (ssh/scp/nc/socat/docker/...), i.e. it can reach off-box or open a shell;
///   and/or
/// - secret material (vendor-anchored key prefixes / PEM private-key headers)
///   was observed in the agent's transcript context (BR-1), so a compromised
///   or prompt-injected agent already HOLDS credentials it could exfiltrate
///   through any egress channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusAgent {
    pub agent_type: String,
    /// The agent is OS-unconfined (`AgentSandbox.sandboxed == Some(false)`).
    pub unsandboxed: bool,
    /// The host grants the agent's user passwordless root.
    pub passwordless_root: bool,
    /// The agent has been observed spawning a `Critical` subprocess.
    pub critical_subprocess: bool,
    /// Secret material was observed in the agent's transcript context (BR-1).
    pub secret_exposure: bool,
    /// Sorted secret-signature labels behind `secret_exposure`
    /// (`private_key`, `github_token`, ...). Labels only, never content.
    pub secret_exposure_labels: Vec<String>,
    /// Short human-readable reasons (for the UI / threat description).
    pub reasons: Vec<String>,
}

/// Pure host blast-radius rule (INC-7). Given the host privilege assessment,
/// the per-agent OS-confinement rows (already filtered to agents actually
/// present on the host by the caller), a map of `agent_type -> Critical
/// subprocess observation count`, and a map of `agent_type -> transcript
/// secret-exposure labels` (BR-1), return the agents whose compromise would
/// have outsized host reach: unsandboxed AND (passwordless root OR an observed
/// `Critical` subprocess OR secret material in the agent's context).
/// Deterministic, sorted by `agent_type`.
///
/// The host-level `passwordless_root` applies to every agent on the host (they
/// all inherit the launching user's session), so it is the same amplifier for
/// each candidate; the per-agent `Critical` subprocess count and the per-agent
/// secret-exposure labels are the agent-specific amplifiers. A positively
/// OS-confined (or unassessed) agent never qualifies regardless of host
/// privilege, because the OS sandbox bounds its reach.
pub fn agents_with_blast_radius(
    host_privilege: &HostPrivilege,
    agent_sandboxes: &[AgentSandbox],
    critical_subprocess_by_agent: &BTreeMap<String, u32>,
    secret_exposure_by_agent: &BTreeMap<String, Vec<String>>,
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
        let secret_exposure_labels: Vec<String> = secret_exposure_by_agent
            .get(&sandbox.agent_type)
            .cloned()
            .unwrap_or_default();
        let secret_exposure = !secret_exposure_labels.is_empty();
        if !passwordless_root && !critical_subprocess && !secret_exposure {
            continue;
        }
        let mut reasons: Vec<String> = vec!["unsandboxed (full user-file access)".to_string()];
        if passwordless_root {
            reasons.push("passwordless root on host".to_string());
        }
        if critical_subprocess {
            reasons.push("observed critical subprocess (ssh/nc/docker/...)".to_string());
        }
        if secret_exposure {
            reasons.push(format!(
                "secret material in agent context ({})",
                secret_exposure_labels.join(", ")
            ));
        }
        out.push(BlastRadiusAgent {
            agent_type: sandbox.agent_type.clone(),
            unsandboxed: true,
            passwordless_root,
            critical_subprocess,
            secret_exposure,
            secret_exposure_labels,
            reasons,
        });
    }
    out.sort_by(|a, b| a.agent_type.cmp(&b.agent_type));
    out
}

// ---------------------------------------------------------------------------
// Agent governance harness presence (AI agent governance posture)
// ---------------------------------------------------------------------------

/// A known agent-governance "harness" / control-plane product and whether its
/// per-user footprint is present on this host. A harness is the AI agent control
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
    /// Best-effort governed-agent identity token read from the harness's own
    /// on-disk footprint (e.g. AgentField's W3C-DID / project id), so EDAMAME
    /// evidence can be joined back to the harness audit trail (governed-identity
    /// binding). Honest best-effort: `None` when the harness is absent OR no
    /// recognizable identity-bearing file is present -- never fabricated. The
    /// exact per-product identity file/key is not yet pinned, so today this is
    /// populated only when a clearly identity-named file (`did` / `identity`)
    /// exists and yields a plausible token.
    pub identity: Option<String>,
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

/// Best-effort read of a governed-agent identity token from a harness's own
/// on-disk footprint, so EDAMAME evidence can be joined to the harness audit
/// trail (governed-identity binding). Read-only and honest: returns `None`
/// unless a clearly identity-bearing file exists and yields a plausible token.
/// The exact identity file/key per product is not yet confirmed, so the
/// candidate set is deliberately conservative and never lifts a token out of an
/// arbitrary/general config blob.
fn read_harness_identity(home: &Path, slug: &str) -> Option<String> {
    // Per-slug candidate identity files (relative to `$HOME`). Only files whose
    // *name* signals identity (`did` / `identity`) are probed, so we never lift
    // an unrelated value out of a general config file.
    let rels: &[&str] = match slug {
        // AgentField issues a W3C-DID per governed agent/project. The exact
        // on-disk location is unconfirmed; these are the plausible per-user
        // spots under its standard config roots.
        "agentfield" => &[
            ".af/did",
            ".af/identity",
            ".af/identity.json",
            ".config/agentfield/did",
            ".config/agentfield/identity",
            ".config/agentfield/identity.json",
        ],
        // No confirmed local identity file for other harnesses yet.
        _ => &[],
    };
    for rel in rels {
        let path = home.join(rel);
        if !path.is_file() {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(token) = extract_identity_token(&raw) {
            return Some(token);
        }
    }
    None
}

/// Extract a plausible identity token from a candidate file body. Accepts
/// either a JSON object carrying a recognized identity key, or a short
/// single-line token. Returns `None` for anything that does not look like an
/// identity so the field stays honestly empty rather than fabricated.
fn extract_identity_token(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 4096 {
        return None;
    }
    // JSON object: pull the first recognized identity key.
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(trimmed) {
        for key in [
            "did",
            "identity",
            "agent_did",
            "agent_id",
            "project_id",
            "id",
        ] {
            if let Some(serde_json::Value::String(s)) = map.get(key) {
                let s = s.trim();
                if is_plausible_identity(s) {
                    return Some(s.to_string());
                }
            }
        }
        return None;
    }
    // Plain token: accept a single short line that looks like an id / DID.
    let first = trimmed.lines().next().unwrap_or("").trim();
    if is_plausible_identity(first) {
        return Some(first.to_string());
    }
    None
}

/// A token is a plausible identity if it is non-empty, bounded in length, has
/// no whitespace, and is made of identity-ish characters (DID / UUID / slug
/// shapes). Deliberately strict to avoid lifting prose or secrets into the
/// identity field.
fn is_plausible_identity(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && !s.chars().any(|c| c.is_whitespace())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | '.' | '/' | '#'))
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

            // Best-effort governed-agent identity (governed-identity binding):
            // only when the harness footprint is actually present, and only from
            // a clearly identity-bearing file. `None` otherwise (honest, never
            // fabricated).
            let identity = if evidence.is_empty() {
                None
            } else {
                read_harness_identity(home, slug)
            };

            AgentHarness {
                slug: (*slug).to_string(),
                display_name: (*display).to_string(),
                detected: !evidence.is_empty(),
                evidence,
                identity,
            }
        })
        .collect();
    out.sort_by(|a, b| a.slug.cmp(&b.slug));
    out
}

/// AI agent governance rule: the host is "running AI agents without a
/// governance harness" when at least one agent is present/discovered on the host
/// AND no known harness is detected. This is a posture *gap* signal -- the
/// common workstation default is no harness, which is exactly the gap to
/// surface -- and it clears as soon as any recognized harness (AgentField,
/// Rippletide, ...) is installed for the user. Deterministic and pure so it is
/// unit-testable without touching disk.
pub fn agents_without_harness(discovered_agent_count: usize, harnesses: &[AgentHarness]) -> bool {
    discovered_agent_count > 0 && !harnesses.iter().any(|h| h.detected)
}

/// AI agent governance rule: "a governance harness is installed on this host, yet a
/// discovered agent still shows host blast-radius escape" -- i.e. the control
/// plane is present but is not actually confining the agent. This is the
/// complement of `agents_without_harness`: that rule fires when NO harness wraps
/// the agents (the common workstation default gap); this one fires when a
/// harness IS detected (AgentField, Rippletide, ...) but an agent on the box can
/// still reach off-host / become root / open a shell, which is strictly worse --
/// a deployed control failed to bound the agent.
///
/// Inputs are the detected harnesses (`detect_agent_harnesses`) and the
/// already-computed host blast-radius agents (`agents_with_blast_radius`, whose
/// caller has already filtered to agents actually present on the host). Returns
/// the diverging agent types, sorted and de-duplicated. Returns empty when no
/// harness is detected (so `agents_without_harness` owns that case and the two
/// signals never double-count) and empty when no agent breaches its boundary
/// (the harness is doing its job). Deterministic and pure so it is unit-testable
/// without touching disk.
pub fn agents_with_harness_divergence(
    harnesses: &[AgentHarness],
    blast_radius_agents: &[BlastRadiusAgent],
) -> Vec<String> {
    // Only meaningful when a governance harness IS present: the divergence is
    // "a control exists yet the agent still escapes". With no harness detected,
    // `agents_without_harness` is the right signal, so stay silent here.
    if !harnesses.iter().any(|h| h.detected) {
        return Vec::new();
    }
    let mut out: Vec<String> = blast_radius_agents
        .iter()
        .map(|a| a.agent_type.clone())
        .collect();
    out.sort();
    out.dedup();
    out
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
/// component inventories, capability graph) for one host. Built from a single
/// endpoint discovery pass so the helper crosses the sandbox boundary only once.
///
/// Recursion / delegation (INC-4) is NOT part of the bundle: it derives from
/// transcript bodies that core already collects via `collect_agent_transcripts`,
/// so core computes it from that existing payload rather than re-reading disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityBundle {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub inventory: McpInventory,
    pub component_inventories: Vec<AgentComponentInventory>,
    pub graph_edges: Vec<GraphEdge>,
    /// Host-level privilege (INC-7): the blast radius every agent inherits from
    /// the user session. Shared across all agents on this host.
    pub host_privilege: HostPrivilege,
    /// Per-agent OS confinement (INC-7), one entry per supported agent type.
    pub agent_sandboxes: Vec<AgentSandbox>,
    /// Agent governance harnesses (AI agent control plane) detected on this host,
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
    let component_inventories =
        build_agent_component_inventories_from_endpoints_with_home(&endpoints, Some(home));
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
        component_inventories,
        graph_edges,
        host_privilege,
        agent_sandboxes,
        harnesses,
    }
}

/// Maximum bytes read from a single MCP config file. Config files
/// (`~/.cursor/mcp.json`, `~/.claude.json`, Claude Desktop config, Codex TOML,
/// Hermes YAML) are at most a few KB in practice; a multi-MB one is malformed
/// or an adversarial attempt to exhaust memory through the parser. Capping the
/// read bounds the parser input and the resulting endpoint list.
const MAX_MCP_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// Maximum number of MCP endpoints retained across all agents and config
/// files. Each endpoint seeds A2A peers, capability-graph nodes, data-flow
/// edges, inventory components, and confused-deputy analysis, so an unbounded
/// endpoint list would propagate unbounded growth across the entire visibility
/// surface. Far above any realistic per-host MCP server count.
const MAX_MCP_ENDPOINTS: usize = 512;

/// Maximum directory depth walked under `~/.cursor/plugins/` when discovering
/// plugin-shipped `mcp.json` files. Marketplace installs land at
/// `plugins/cache/<publisher>/<name>/<hash>/mcp.json` (depth 4), so a small
/// cap covers the real layout while bounding traversal of an adversarial or
/// pathological plugin tree.
const MAX_PLUGIN_SCAN_DEPTH: usize = 6;

/// Maximum number of plugin `mcp.json` files parsed under `~/.cursor/plugins/`.
/// A hard stop so a plugin cache stuffed with thousands of config files can't
/// stall discovery. Well above any realistic installed-plugin count.
const MAX_PLUGIN_MCP_FILES: usize = 128;

/// Read a file, capping the read at `max_bytes`. Returns the UTF-8 lossy
/// contents (truncation lands on a byte boundary; lossy decoding repairs any
/// split multibyte sequence). Used for user/agent-writable config files whose
/// size is not otherwise bounded.
fn read_capped(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(max_bytes).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Discover MCP endpoints declared by every supported agent's config targets
/// plus EDAMAME's own server key. JSON config formats (Cursor `mcp.json`,
/// Claude `.claude.json`, Claude Desktop config) are parsed fully; TOML
/// (Codex) and YAML (Hermes) configs are parsed with a tolerant line scan so
/// at least server names/commands surface without pulling in toml/yaml deps.
///
/// Bounded on two axes: each config read is capped at `MAX_MCP_CONFIG_BYTES`
/// and the total endpoint count at `MAX_MCP_ENDPOINTS`, so the entire
/// downstream visibility surface seeded from these endpoints stays bounded.
///
/// Beyond the per-agent global configs, Cursor marketplace plugins ship their
/// own `mcp.json` under `~/.cursor/plugins/**` (not referenced by
/// `~/.cursor/mcp.json`). Those are discovered separately via
/// `discover_cursor_plugin_mcp_endpoints` and merged in (deduped by id) so a
/// plugin like Notion / Slack / Sentry declaring a remote MCP endpoint is not
/// invisible on the exposure surface.
pub fn discover_mcp_endpoints(home: &Path) -> Vec<McpEndpoint> {
    let mut endpoints = Vec::new();
    'agents: for def in supported_agents::ordered_supported_agents() {
        let server_key = def.mcp_server_key().map(|s| s.to_string());
        for config_path in def.resolve_global_mcp_configs(home) {
            if endpoints.len() >= MAX_MCP_ENDPOINTS {
                break 'agents;
            }
            if !config_path.exists() {
                continue;
            }
            let raw = match read_capped(&config_path, MAX_MCP_CONFIG_BYTES) {
                Ok(text) => text,
                Err(_) => continue,
            };
            let path_str = config_path.to_string_lossy().to_string();
            let servers = parse_mcp_config(&raw, &path_str);
            for server in servers {
                if endpoints.len() >= MAX_MCP_ENDPOINTS {
                    break 'agents;
                }
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
    // Cursor marketplace plugins ship their own `mcp.json` under
    // `~/.cursor/plugins/**`. Merge those endpoints in, deduped by id so a
    // server also present in `~/.cursor/mcp.json` is not double-counted.
    if endpoints.len() < MAX_MCP_ENDPOINTS {
        let mut seen: BTreeSet<String> = endpoints.iter().map(|e| e.id.clone()).collect();
        for ep in discover_cursor_plugin_mcp_endpoints(home) {
            if endpoints.len() >= MAX_MCP_ENDPOINTS {
                break;
            }
            if seen.insert(ep.id.clone()) {
                endpoints.push(ep);
            }
        }
    }
    endpoints
}

/// Discover MCP endpoints declared by Cursor marketplace plugins.
///
/// Cursor installs plugins under `~/.cursor/plugins/` (marketplace installs at
/// `plugins/cache/<publisher>/<name>/<hash>/`, local installs elsewhere in the
/// tree). A plugin that integrates a remote MCP service ships its own
/// `mcp.json` there; that file is NOT referenced by the user-level
/// `~/.cursor/mcp.json`, so without this scan a plugin-provided endpoint (e.g.
/// Notion / Slack / Sentry) is invisible to the exposure surface.
///
/// Plugin `mcp.json` files come in two shapes: the standard
/// `{ "mcpServers": { ... } }` wrapper AND a bare object whose top-level keys
/// are server names (`{ "notion": { "type": "http", "url": "..." } }`). Both
/// are handled by `parse_mcp_json_with_bare_fallback`.
///
/// Traversal is bounded on three axes (depth, files parsed, and the global
/// `MAX_MCP_ENDPOINTS` cap) and prunes `node_modules` / `.git` subtrees, so a
/// large or adversarial plugin cache cannot stall discovery. All endpoints are
/// attributed to the `cursor` agent and are never the EDAMAME bridge.
fn discover_cursor_plugin_mcp_endpoints(home: &Path) -> Vec<McpEndpoint> {
    let plugins_root = home.join(".cursor").join("plugins");
    if !plugins_root.is_dir() {
        return Vec::new();
    }
    let mut endpoints: Vec<McpEndpoint> = Vec::new();
    let mut files_parsed = 0usize;
    // Explicit stack DFS with a depth cap; the cap also breaks any symlink
    // cycle without needing to track visited inodes.
    let mut stack: Vec<(PathBuf, usize)> = vec![(plugins_root, 0)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_PLUGIN_SCAN_DEPTH {
            continue;
        }
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in read_dir.flatten() {
            if endpoints.len() >= MAX_MCP_ENDPOINTS || files_parsed >= MAX_PLUGIN_MCP_FILES {
                return endpoints;
            }
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                // Prune vendored/VCS subtrees that never carry a plugin's own
                // MCP config but can hold thousands of files.
                let skip = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n == "node_modules" || n == ".git")
                    .unwrap_or(false);
                if !skip {
                    stack.push((path, depth + 1));
                }
            } else if file_type.is_file()
                && path.file_name().map(|n| n == "mcp.json").unwrap_or(false)
            {
                files_parsed += 1;
                let raw = match read_capped(&path, MAX_MCP_CONFIG_BYTES) {
                    Ok(text) => text,
                    Err(_) => continue,
                };
                let path_str = path.to_string_lossy().to_string();
                for server in parse_mcp_json_with_bare_fallback(&raw) {
                    if endpoints.len() >= MAX_MCP_ENDPOINTS {
                        return endpoints;
                    }
                    // Plugin-provided servers are third-party integrations, never
                    // EDAMAME's own bridge.
                    endpoints.push(build_endpoint("cursor", server, &path_str, false));
                }
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

/// Parse a plugin `mcp.json` that may use either the standard `mcpServers`
/// wrapper OR a bare object whose top-level keys are server names. Tries the
/// wrapper form first (via `parse_mcp_json`); if that yields nothing, falls
/// back to treating each top-level object that looks like a server definition
/// as a bare server entry. The bare-object fallback is scoped to plugin files
/// only -- the global-config parser (`parse_mcp_json`) intentionally does NOT
/// use it, so a config like `~/.claude.json` (many unrelated top-level keys) is
/// never misinterpreted as a flat server map.
fn parse_mcp_json_with_bare_fallback(raw: &str) -> Vec<RawMcpServer> {
    let servers = parse_mcp_json(raw);
    if !servers.is_empty() {
        return servers;
    }
    let value: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    let mut bare = Vec::new();
    for (name, entry) in map {
        // Skip the wrapper keys `parse_mcp_json` already handled (defensive:
        // reached only when those produced no servers).
        if name == "mcpServers" || name == "projects" {
            continue;
        }
        if entry.is_object() && looks_like_bare_mcp_server(entry) {
            bare.push(parse_json_server(name, entry));
        }
    }
    bare
}

/// Heuristic: does a top-level JSON object value look like an MCP server
/// definition (as opposed to some unrelated config section)? A server entry
/// carries at least one of the recognized connection keys.
fn looks_like_bare_mcp_server(entry: &serde_json::Value) -> bool {
    entry.get("url").is_some()
        || entry.get("serverUrl").is_some()
        || entry.get("command").is_some()
        || entry.get("type").is_some()
        || entry.get("transport").is_some()
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
    // OAuth is signalled by an explicit type, an `oauth` / `authorization_server`
    // block, or an `auth` object carrying an OAuth client registration
    // (`CLIENT_ID`) -- the shape Cursor marketplace plugins (e.g. Slack) use.
    let has_oauth = explicit_type.as_deref() == Some("oauth")
        || entry.get("oauth").is_some()
        || entry.get("authorization_server").is_some()
        || entry
            .get("auth")
            .and_then(|a| a.as_object())
            .map(|a| {
                a.keys().any(|k| {
                    k.eq_ignore_ascii_case("client_id") || k.eq_ignore_ascii_case("clientid")
                })
            })
            .unwrap_or(false);
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

    // CloudModel-tunable per-class keyword lists (lowercased by
    // `CveDetectionParams::new_from_json`).
    let keywords = agent_visibility_params::agent_tool_privilege_keywords();
    let contains_any = |needles: &[String]| needles.iter().any(|n| haystack.contains(n.as_str()));

    if contains_any(&keywords.shell) {
        add(ToolPrivilegeClass::Shell, &mut classes);
    }
    if contains_any(&keywords.filesystem_write) {
        add(ToolPrivilegeClass::FilesystemWrite, &mut classes);
    }
    if contains_any(&keywords.filesystem_read) {
        add(ToolPrivilegeClass::FilesystemRead, &mut classes);
    }
    if contains_any(&keywords.browser) {
        add(ToolPrivilegeClass::Browser, &mut classes);
    }
    if contains_any(&keywords.git) {
        add(ToolPrivilegeClass::Git, &mut classes);
    }
    if contains_any(&keywords.database) {
        add(ToolPrivilegeClass::Database, &mut classes);
    }
    if contains_any(&keywords.secret_access) {
        add(ToolPrivilegeClass::SecretAccess, &mut classes);
    }
    if contains_any(&keywords.network) {
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
// Agent component inventory (INC-2)
// ---------------------------------------------------------------------------

/// Best-effort "is this agent installed on this host?" check used to decide
/// whether an agent with an otherwise-empty surface (no MCP servers, no
/// instruction/skill files) still deserves a minimal inventory. An agent counts
/// as installed when any of its resolved global MCP config files exists on disk
/// (even if it declares zero servers) or its instruction/config root directory
/// exists. This mirrors the "present on host" intent so an installed-but-empty
/// agent (e.g. Claude Desktop) yields a valid, minimal inventory with just the
/// application root component instead of being dropped entirely.
fn agent_installed_on_host(home: &Path, agent_type: &str) -> bool {
    let Some(def) = supported_agents::find_supported_agent(agent_type) else {
        return false;
    };
    if def
        .resolve_global_mcp_configs(home)
        .iter()
        .any(|p| p.exists())
    {
        return true;
    }
    match def.resolve_instruction_root_with_home(home) {
        Some(root) => root.is_dir(),
        None => false,
    }
}

/// Build one component inventory per discovered agent type from the live MCP
/// inventory plus the agent's on-disk instruction/skill artifacts. The agent
/// application is the root component; each MCP server it declares is a `service`
/// component, each distinct tool-privilege class a `data` component, each
/// secret-bearing env binding a `data` component, and each
/// instruction/skill/rule/command file a content-hashed `file` component.
pub fn build_agent_component_inventories(home: &Path) -> Vec<AgentComponentInventory> {
    let endpoints = discover_mcp_endpoints(home);
    build_agent_component_inventories_from_endpoints_with_home(&endpoints, Some(home))
}

/// Endpoint-only projection (no on-disk instruction scan). Retained for
/// callers/tests that only have endpoints; prefer the `_with_home` variant in
/// the live bundle path so instruction/skill files surface too.
pub fn build_agent_component_inventories_from_endpoints(
    endpoints: &[McpEndpoint],
) -> Vec<AgentComponentInventory> {
    build_agent_component_inventories_from_endpoints_with_home(endpoints, None)
}

/// Full component-inventory projection. When `home` is provided, each agent's
/// instruction / skill / rule / command / subagent files are discovered from
/// its config dir and projected as content-hashed `file` components (bodies are
/// never stored, invariant I5).
pub fn build_agent_component_inventories_from_endpoints_with_home(
    endpoints: &[McpEndpoint],
    home: Option<&Path>,
) -> Vec<AgentComponentInventory> {
    let mut by_agent: BTreeMap<String, Vec<&McpEndpoint>> = BTreeMap::new();
    for ep in endpoints {
        by_agent.entry(ep.agent_type.clone()).or_default().push(ep);
    }
    // Some agents have instruction files but no MCP servers; make sure they
    // still get an inventory when a home is available.
    if let Some(home) = home {
        for def in supported_agents::ordered_supported_agents() {
            by_agent.entry(def.agent_type.clone()).or_default();
            let _ = home; // referenced below per-agent
        }
    }

    let now = chrono::Utc::now();
    let mut inventories = Vec::new();
    for (agent_type, agent_endpoints) in by_agent {
        let app_ref = format!("agent:{}", agent_type);
        let mut components = Vec::new();
        // Deduped side-component tables (deterministic ordering via BTreeMap).
        let mut tool_components: BTreeMap<String, AgentComponent> = BTreeMap::new();
        let mut env_components: BTreeMap<String, AgentComponent> = BTreeMap::new();

        components.push(AgentComponent {
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
            components.push(AgentComponent {
                bom_ref: svc_ref.clone(),
                component_type: "service".to_string(),
                name: ep.server_name.clone(),
                version: None,
                content_hash: None,
                properties: props,
            });

            // Project the tool capabilities the server exposes and the secret
            // bindings it is wired to as deduped side components.
            for class in &ep.tool_privilege_classes {
                if matches!(class, ToolPrivilegeClass::Unknown) {
                    continue;
                }
                let tool_ref = format!("tool:{}:{}", agent_type, class.slug());
                tool_components.entry(tool_ref.clone()).or_insert_with(|| {
                    let mut p = BTreeMap::new();
                    p.insert("edamame:kind".to_string(), "tool_capability".to_string());
                    p.insert(
                        "edamame:high_privilege".to_string(),
                        class.is_high_privilege().to_string(),
                    );
                    AgentComponent {
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
                env_components.entry(env_ref.clone()).or_insert_with(|| {
                    let mut p = BTreeMap::new();
                    p.insert("edamame:kind".to_string(), "secret_binding".to_string());
                    // Name only -- never the value (invariant I5).
                    AgentComponent {
                        bom_ref: env_ref,
                        component_type: "data".to_string(),
                        name: key.clone(),
                        version: None,
                        content_hash: None,
                        properties: p,
                    }
                });
            }
        }

        // Instruction / skill / rule / command / subagent files (I5: hashes,
        // never bodies). Only when a real home is available.
        let instruction_components = home
            .map(|h| discover_agent_instruction_components(h, &agent_type))
            .unwrap_or_default();

        // Assemble components in a stable order: app, services already pushed;
        // append tools, env bindings, instruction files.
        components.extend(tool_components.into_values());
        components.extend(env_components.into_values());
        components.extend(instruction_components);

        // Skip agents that carry nothing beyond the implicit application root
        // (no servers, no instructions). Exception: an agent actually installed
        // on this host (its global MCP config file or instruction/config root
        // exists) still gets a minimal application-only inventory, so the
        // Agents tab stays consistent with the rest of the fleet instead of
        // returning `{}` -- e.g. Claude Desktop configured with an empty
        // `"mcpServers": {}` and no skills. Endpoint-only callers
        // (`home == None`, tests) keep the strict skip.
        if components.len() == 1 && agent_endpoints.is_empty() {
            let installed = home
                .map(|h| agent_installed_on_host(h, &agent_type))
                .unwrap_or(false);
            if !installed {
                continue;
            }
        }

        // Multi-instance correctness (Fix #4): key the inventory on the same
        // per-(host, agent_type) instance id the divergence observer uses, so
        // the Agents tab no longer collapses distinct instances of one agent
        // type. When no home is available (endpoint-only callers/tests) fall
        // back to the agent_type as the instance id.
        let agent_instance_id = match home {
            Some(h) => crate::agent_transcripts::observer_agent_instance_id(&agent_type, h),
            None => agent_type.clone(),
        };
        inventories.push(AgentComponentInventory {
            agent_type: agent_type.clone(),
            agent_instance_id,
            generated_at: now,
            components,
        });
    }
    inventories
}

/// Env-var names that look like they carry a secret/credential. Used to
/// project secret bindings into the component inventory (names only, I5).
fn is_secret_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    // CloudModel-tunable needles (uppercased by `CveDetectionParams::new_from_json`).
    agent_visibility_params::agent_secret_env_key_needles()
        .iter()
        .any(|n| upper.contains(n.as_str()))
}

/// Subdirectories within an agent's config dir that carry agent instructions /
/// skills / commands / subagents, paired with the component `edamame:kind` each
/// projects to. This is an allowlist on purpose: only these well-known dirs are
/// walked, so transcript / session / log stores (`projects/`, `sessions/`,
/// `history/`, ...) are never scanned.
const INSTRUCTION_SUBDIRS: &[(&str, &str)] = &[
    ("rules", "rule"),
    ("skills", "skill"),
    // Cursor keeps its built-in / product skills under `skills-cursor`
    // (`~/.cursor/skills-cursor`), separate from the user `skills` dir; other
    // agents have no such dir so this is a no-op for them.
    ("skills-cursor", "skill"),
    ("commands", "command"),
    ("agents", "subagent"),
    ("subagents", "subagent"),
    ("memories", "memory"),
    ("prompts", "prompt"),
    ("instructions", "instruction"),
    ("hooks", "hook"),
];

/// File extensions considered instruction/skill artifacts inside the
/// allowlisted subdirectories. This is the *permissive* set used only by the
/// on-demand content-drill-down guard ([`path_is_instruction_artifact`]): if the
/// agent was observed reading a bundled supporting file (a builder script's
/// sibling `.txt` fixture, a `.json` config) under a skill, the UI must still be
/// able to show what was read.
const INSTRUCTION_EXTS: &[&str] = &["md", "mdc", "txt", "json", "toml", "yaml", "yml"];

/// File extensions enumerated as first-class instruction artifacts into the
/// component inventory (the "what skills / rules / commands / subagents does
/// this agent HAVE" list).
///
/// Deliberately narrower than [`INSTRUCTION_EXTS`]: an authored instruction
/// artifact -- a skill (`SKILL.md` / `DESCRIPTION.md`), rule (`*.mdc`), command,
/// subagent, prompt, memory, or instruction -- is a Markdown document. The
/// bundled non-Markdown files a skill ships alongside its doc (a `LICENSE.txt`, a
/// `.cursor-managed-skills-manifest.json`, an agent runtime `models.json` /
/// `sessions.json` / `runs.json` state file, a `*.trajectory-path.json`) are
/// data/config/state, NOT instruction artifacts, and MUST NOT each become their
/// own "skill" row (they surface as phantom, perpetually-"dead" skills and as
/// spurious duplicate clusters). Enumerating only Markdown docs is generic --
/// no per-filename allowlist/blocklist -- and matches how every supported agent
/// authors its instruction set.
const INSTRUCTION_DOC_EXTS: &[&str] = &["md", "mdc"];

/// Max instruction artifacts discovered per agent- or workspace-scope root.
/// Sized to cover a large first-party skills library (Hermes, for example,
/// ships 300+ skills under `~/.hermes/skills`) with headroom, so the component
/// inventory / self-augmentation report does not silently truncate an agent's
/// real on-disk instruction set. Still bounded so a pathological config dir
/// cannot grow the inventory without limit; each artifact is additionally
/// bounded by [`INSTRUCTION_MAX_FILE_BYTES`] and the walk by [`INSTRUCTION_MAX_DEPTH`].
const INSTRUCTION_MAX_FILES: usize = 1024;
/// Max directory depth walked under an instruction subdirectory.
const INSTRUCTION_MAX_DEPTH: usize = 4;
/// Max body size of a single instruction artifact that is read+hashed into the
/// inventory. Larger files are skipped (the body is a data blob, not an instruction).
const INSTRUCTION_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

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

// ---------------------------------------------------------------------------
// On-demand instruction content reads (invariant I5, privacy-tiered).
//
// The augmentation / visibility UI can drill into a specific skill / command /
// rule and view its body. Because EDAMAME monitors developer workstations, this
// read honors the three privacy tiers (metadata-only / redacted-excerpt /
// forensic-full-content). The read is the single source of truth shared by the
// standalone core path and the helper path, mirroring `build_visibility_bundle`.
// ---------------------------------------------------------------------------

/// Excerpt ceiling for the `redacted_excerpt` tier (bytes of the head returned).
pub const INSTRUCTION_CONTENT_EXCERPT_BYTES: usize = 8 * 1024;
/// Hard ceiling for the `forensic_full_content` tier (bytes returned).
pub const INSTRUCTION_CONTENT_MAX_BYTES: usize = 256 * 1024;

/// Result of an on-demand instruction content read. Output-only over the RPC
/// boundary (serialized to JSON by the core RPC / helper utility).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionContentResult {
    /// Absolute path that was read (echoed back for the UI).
    pub path: String,
    /// True when the path resolved to a readable instruction artifact.
    pub found: bool,
    /// Effective tier applied: `metadata_only` | `redacted_excerpt` |
    /// `forensic_full_content`.
    pub tier: String,
    /// On-disk size of the file in bytes (0 when not found).
    pub size_bytes: u64,
    /// Number of bytes actually returned in `content`.
    pub returned_bytes: usize,
    /// True when `content` is a head slice of a larger file.
    pub truncated: bool,
    /// True when one or more secret-like spans were masked in `content`.
    pub redacted: bool,
    /// Number of lines that had a secret-like value masked.
    pub redacted_lines: usize,
    /// The body per the effective tier. Empty at `metadata_only`.
    pub content: String,
    /// Human-readable reason when `found` is false or the read was refused.
    pub error: Option<String>,
}

impl InstructionContentResult {
    /// Build a "read refused / not found" result carrying a human-readable
    /// reason. Public so the core dispatch layer can produce the same shape for
    /// its own pre-flight failures (no home dir, helper transport error,
    /// unsupported platform) without duplicating the field list.
    pub fn refused(path: &str, tier: &str, error: impl Into<String>) -> Self {
        Self {
            path: path.to_string(),
            found: false,
            tier: tier.to_string(),
            size_bytes: 0,
            returned_bytes: 0,
            truncated: false,
            redacted: false,
            redacted_lines: 0,
            content: String::new(),
            error: Some(error.into()),
        }
    }
}

/// Normalize a caller-supplied tier string to one of the three known tiers.
/// Unknown values collapse to the safest tier (`metadata_only`) so a typo can
/// never accidentally widen disclosure.
fn normalize_content_tier(tier: &str) -> &'static str {
    match tier.trim().to_ascii_lowercase().as_str() {
        "forensic_full_content" | "forensic" | "full" => "forensic_full_content",
        "redacted_excerpt" | "redacted" | "excerpt" => "redacted_excerpt",
        _ => "metadata_only",
    }
}

/// True when `path` has the shape of a readable instruction artifact: a
/// top-level instruction file (`CLAUDE.md`, `.cursorrules`, ...), ANY regular
/// file under a `skills/` (or `skills-cursor/`) tree, or a file with an
/// instruction extension living under one of the other `INSTRUCTION_SUBDIRS`
/// segments (`rules/`, `commands/`, ...).
///
/// Skill folders are special-cased to allow any extension because a skill
/// legitimately bundles supporting files -- builder scripts, fixtures, assets --
/// that the agent reads while running the skill, so the drill-down must be able
/// to show exactly what the agent read (e.g. `skills/deck_suite/builders/*.py`),
/// not only the `SKILL.md` doc. Rejecting those made the UI claim on-disk files
/// were "not found".
///
/// This stays an allowlist, not an arbitrary-file read: guard 2 in
/// [`read_instruction_content`] confines the canonicalized path to the user's
/// home directory, and guard 3 re-runs THIS check on the canonicalized path, so
/// a symlink under `skills/` pointing at `/etc/shadow` or `~/.ssh/id_rsa`
/// resolves to a path with no `skills` ancestor (and outside any instruction
/// subdir) and is rejected.
fn path_is_instruction_artifact(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if classify_toplevel_instruction(name).is_some() {
        return true;
    }
    // Lower-cased ancestor directory segments, computed once.
    let segments: Vec<String> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str().map(|s| s.to_ascii_lowercase()))
        .collect();
    // A skill folder bundles supporting files (scripts / assets / fixtures) the
    // agent reads as part of running the skill; allow any extension under it.
    if segments
        .iter()
        .any(|s| s.as_str() == "skills" || s.as_str() == "skills-cursor")
    {
        return true;
    }
    // Other instruction subdirs (rules / commands / prompts / ...) are doc-only:
    // require a recognized instruction extension there.
    let ext_ok = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| INSTRUCTION_EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false);
    if !ext_ok {
        return false;
    }
    segments.iter().any(|seg| {
        INSTRUCTION_SUBDIRS
            .iter()
            .any(|(dir, _)| *dir == seg.as_str())
    })
}

/// Key-name hints that mark a `key = value` / `key: value` line as carrying a
/// secret value to mask at the `redacted_excerpt` tier.
const SECRET_KEY_HINTS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "private_key",
    "client_secret",
    "auth",
    "bearer",
    "credential",
    "session_key",
];

/// Standalone token prefixes that are masked wherever they appear, regardless
/// of the surrounding line shape.
const SECRET_TOKEN_PREFIXES: &[&str] = &[
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "xox",
    "akia",
    "asia",
    "aiza",
    "ya29.",
    "eyj",
];

fn char_is_token(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-' | '=' | '.')
}

/// True when `tok` looks like a high-entropy secret: a known secret prefix, or a
/// long mixed alphanumeric run (>= 28 chars with at least one digit and one
/// letter). Conservative on purpose -- this is defense in depth behind the tier
/// gate, not the primary control.
fn token_looks_secret(tok: &str) -> bool {
    let lower = tok.to_ascii_lowercase();
    if SECRET_TOKEN_PREFIXES
        .iter()
        .any(|p| lower.starts_with(p) && tok.len() >= p.len() + 6)
    {
        return true;
    }
    if tok.len() < 28 {
        return false;
    }
    let has_digit = tok.chars().any(|c| c.is_ascii_digit());
    let has_alpha = tok.chars().any(|c| c.is_ascii_alphabetic());
    let all_token = tok.chars().all(char_is_token);
    has_digit && has_alpha && all_token
}

/// Mask secret-like spans in `line`. Returns the (possibly rewritten) line and
/// whether anything was masked.
fn redact_secret_line(line: &str) -> (String, bool) {
    let mut masked = false;

    // 1. `key <sep> value` where the key name hints at a secret.
    if let Some(sep_idx) = line.find([':', '=']) {
        let (key, rest) = line.split_at(sep_idx);
        let key_lower = key.to_ascii_lowercase();
        if SECRET_KEY_HINTS.iter().any(|h| key_lower.contains(h)) {
            let sep = &rest[..1];
            let value = &rest[1..];
            if !value.trim().is_empty() {
                let leading_ws: String = value.chars().take_while(|c| c.is_whitespace()).collect();
                return (format!("{key}{sep}{leading_ws}REDACTED"), true);
            }
        }
    }

    // 2. Standalone high-entropy tokens anywhere in the line.
    let mut out = String::with_capacity(line.len());
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut String, masked: &mut bool| {
        if !cur.is_empty() {
            if token_looks_secret(cur) {
                out.push_str("REDACTED");
                *masked = true;
            } else {
                out.push_str(cur);
            }
            cur.clear();
        }
    };
    for c in line.chars() {
        if char_is_token(c) {
            cur.push(c);
        } else {
            flush(&mut cur, &mut out, &mut masked);
            out.push(c);
        }
    }
    flush(&mut cur, &mut out, &mut masked);
    (out, masked)
}

/// Apply line-level secret redaction to `text`. Returns the redacted text and
/// the number of lines that had a value masked.
fn redact_secret_like_text(text: &str) -> (String, usize) {
    let mut redacted_lines = 0usize;
    let mut out = String::with_capacity(text.len());
    for segment in text.split_inclusive('\n') {
        let (body, nl) = match segment.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (segment, ""),
        };
        let (line, masked) = redact_secret_line(body);
        if masked {
            redacted_lines += 1;
        }
        out.push_str(&line);
        out.push_str(nl);
    }
    (out, redacted_lines)
}

/// Truncate `bytes` to at most `max` bytes on a UTF-8 char boundary, returning
/// the lossy string and whether truncation occurred.
fn head_str_lossy(bytes: &[u8], max: usize) -> (String, bool) {
    if bytes.len() <= max {
        return (String::from_utf8_lossy(bytes).into_owned(), false);
    }
    let mut end = max;
    // Back up to a char boundary so from_utf8_lossy does not split a codepoint
    // mid-sequence at the cut (cheap: at most 3 bytes).
    while end > 0 && (bytes[end] & 0xC0) == 0x80 {
        end -= 1;
    }
    (String::from_utf8_lossy(&bytes[..end]).into_owned(), true)
}

/// Read an instruction artifact body on demand, honoring the privacy tier
/// (invariant I5). Single source of truth shared by the standalone core path
/// (direct call) and the helper path (`utility_read_instruction_content`).
///
/// - `path`: absolute path of the artifact to read (as discovered by the inventory).
/// - `home`: the user's real home dir; the read is refused unless `path`
///   canonicalizes to a location under `home` (no reads outside the user's home).
/// - `tier`: one of `metadata_only` | `redacted_excerpt` | `forensic_full_content`.
///
/// Two independent guards prevent arbitrary file disclosure regardless of tier:
/// the path must (1) be a recognized instruction artifact shape and (2) resolve
/// under the user's home directory.
pub fn read_instruction_content(path: &Path, home: &Path, tier: &str) -> InstructionContentResult {
    let tier = normalize_content_tier(tier);
    let path_str = path.to_string_lossy().to_string();

    // Guard 1: instruction-artifact shape (uses the raw path so a symlink whose
    // name is not instruction-shaped is rejected before any canonicalization).
    if !path_is_instruction_artifact(path) {
        return InstructionContentResult::refused(
            &path_str,
            tier,
            "path is not a recognized instruction artifact",
        );
    }

    // Guard 2: resolve and confine to the user's home directory.
    let canonical = match path.canonicalize() {
        Ok(c) => c,
        Err(e) => {
            return InstructionContentResult::refused(
                &path_str,
                tier,
                format!("cannot resolve path: {e}"),
            )
        }
    };
    let home_canonical = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    if !canonical.starts_with(&home_canonical) {
        return InstructionContentResult::refused(
            &path_str,
            tier,
            "path is outside the user home directory",
        );
    }
    // Re-check the shape post-canonicalization (defends against a symlink under
    // an instruction dir pointing at a non-instruction file).
    if !path_is_instruction_artifact(&canonical) {
        return InstructionContentResult::refused(
            &path_str,
            tier,
            "resolved path is not a recognized instruction artifact",
        );
    }

    let metadata = match std::fs::metadata(&canonical) {
        Ok(m) if m.is_file() => m,
        Ok(_) => {
            return InstructionContentResult::refused(&path_str, tier, "path is not a file");
        }
        Err(e) => {
            return InstructionContentResult::refused(
                &path_str,
                tier,
                format!("cannot stat file: {e}"),
            );
        }
    };
    let size_bytes = metadata.len();

    // Metadata-only: never touch the body.
    if tier == "metadata_only" {
        return InstructionContentResult {
            path: path_str,
            found: true,
            tier: tier.to_string(),
            size_bytes,
            returned_bytes: 0,
            truncated: size_bytes > 0,
            redacted: false,
            redacted_lines: 0,
            content: String::new(),
            error: None,
        };
    }

    let read_cap = if tier == "forensic_full_content" {
        INSTRUCTION_CONTENT_MAX_BYTES
    } else {
        INSTRUCTION_CONTENT_EXCERPT_BYTES
    };

    let bytes = match std::fs::read(&canonical) {
        Ok(b) => b,
        Err(e) => {
            return InstructionContentResult::refused(
                &path_str,
                tier,
                format!("cannot read file: {e}"),
            );
        }
    };

    let (mut content, truncated) = head_str_lossy(&bytes, read_cap);
    let mut redacted_lines = 0usize;
    if tier == "redacted_excerpt" {
        let (red, n) = redact_secret_like_text(&content);
        content = red;
        redacted_lines = n;
    }

    InstructionContentResult {
        path: path_str,
        found: true,
        tier: tier.to_string(),
        size_bytes,
        returned_bytes: content.len(),
        truncated,
        redacted: redacted_lines > 0,
        redacted_lines,
        content,
        error: None,
    }
}

/// Discover an agent's instruction / skill / rule / command / subagent files
/// from its config dir and project them as content-hashed `file` inventory
/// components. Bounded (depth + count + size) and limited to the
/// `INSTRUCTION_SUBDIRS` allowlist plus top-level instruction files, so
/// transcript / session stores are never walked. Bodies are hashed, never
/// stored (invariant I5).
fn discover_agent_instruction_components(home: &Path, agent_type: &str) -> Vec<AgentComponent> {
    const MAX_FILES: usize = INSTRUCTION_MAX_FILES;
    const MAX_DEPTH: usize = INSTRUCTION_MAX_DEPTH;
    const MAX_FILE_BYTES: u64 = INSTRUCTION_MAX_FILE_BYTES;

    let def = match supported_agents::find_supported_agent(agent_type) {
        Some(d) => d,
        None => return Vec::new(),
    };
    // Walk the AGENT's real config/instruction root (`~/.cursor`, `~/.claude`,
    // ...), NOT the EDAMAME plugin's `<agent>-edamame` data dir. Using the
    // plugin dir (`resolve_config_dir_with_home`) finds nothing and leaves
    // skills unassociated across the whole fleet.
    let config_dir = match def.resolve_instruction_root_with_home(home) {
        Some(d) => d,
        None => return Vec::new(),
    };
    if !config_dir.is_dir() {
        return Vec::new();
    }

    // Collect (path, kind) pairs, then sort by path for deterministic output.
    let mut found: Vec<(PathBuf, &'static str)> = Vec::new();

    // Top-level instruction files directly under the config dir. Capped at
    // MAX_FILES so a config dir stuffed with `*.mdc` files cannot grow `found`
    // without bound before the trailing `.take(MAX_FILES)`.
    if let Ok(entries) = std::fs::read_dir(&config_dir) {
        for entry in entries.flatten() {
            if found.len() >= MAX_FILES {
                break;
            }
            let path = entry.path();
            let (_is_dir, is_file) = entry_kind_following_symlinks(&entry, &path);
            if !is_file {
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

    let mut out: Vec<AgentComponent> = Vec::new();
    for (path, kind) in found.into_iter().take(MAX_FILES) {
        if let Some(comp) =
            instruction_file_component(&config_dir, agent_type, &path, kind, MAX_FILE_BYTES)
        {
            out.push(comp);
        }
    }
    out
}

/// Classify a directory entry as `(is_dir, is_file)`, FOLLOWING symlinks.
///
/// `DirEntry::file_type()` is an `lstat`: it reports a symlink AS a symlink, so
/// `is_dir()` / `is_file()` are BOTH false for a symlink-to-dir /
/// symlink-to-file. Agent skill managers routinely install instruction
/// artifacts as symlinks -- agentfield links `~/.claude/skills/<name>` and
/// `~/.claude/commands/<name>.md` into `~/.agentfield/skills/<name>/current`,
/// and the EDAMAME plugins install `<agent>-edamame/current` the same way -- so
/// walking with the non-following `file_type()` silently skips the entire
/// symlinked subtree (the canonical "skill wrongly marked not on disk" cause).
///
/// This resolves through the link with `fs::metadata`. A dangling symlink
/// (target missing, e.g. an unmounted drive or a deleted skill) yields
/// `(false, false)` and is therefore correctly excluded -- the artifact is not
/// actually present. Non-symlink entries pay no extra syscall.
fn entry_kind_following_symlinks(entry: &std::fs::DirEntry, path: &Path) -> (bool, bool) {
    match entry.file_type() {
        Ok(t) if t.is_symlink() => match std::fs::metadata(path) {
            Ok(m) => (m.is_dir(), m.is_file()),
            Err(_) => (false, false),
        },
        Ok(t) => (t.is_dir(), t.is_file()),
        Err(_) => (false, false),
    }
}

/// Bounded DFS over an instruction subdirectory, collecting Markdown
/// instruction documents (extension in [`INSTRUCTION_DOC_EXTS`]).
///
/// Hidden entries (name starting with `.`) are skipped for BOTH files and
/// directories. Inside an instruction tree, hidden entries are tool-managed /
/// system internals -- Codex's built-in `skills/.system/` bundle, Cursor's
/// `.cursor-managed-skills-manifest.json` / `.sync-manifest.json`, stray `.git`
/// / `.DS_Store` -- never user-authored instruction docs. Combined with the
/// Markdown-only extension gate, this keeps runtime state, manifests, and
/// license files out of the inventory so they cannot surface as phantom "dead"
/// skills or spurious duplicates. (The config-dir ROOTS -- `~/.cursor`,
/// `~/.claude`, ... -- are themselves dot-dirs, but the walk STARTS inside
/// them, so this only filters dot-entries *within* an instruction subtree; the
/// top-level `.cursorrules` file is handled separately by
/// [`classify_toplevel_instruction`] and is unaffected.)
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
            // Skip hidden files/dirs (tool-managed / system internals), never
            // descending into them.
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with('.'))
                .unwrap_or(false)
            {
                continue;
            }
            let (is_dir, is_file) = entry_kind_following_symlinks(&entry, &path);
            if is_dir {
                if depth + 1 <= max_depth {
                    stack.push((path, depth + 1));
                }
            } else if is_file {
                let ext_ok = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| {
                        INSTRUCTION_DOC_EXTS
                            .iter()
                            .any(|x| x.eq_ignore_ascii_case(e))
                    })
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
) -> Option<AgentComponent> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > max_bytes {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let hash = hash_bytes(&bytes);
    let rel = path.strip_prefix(config_dir).unwrap_or(path);
    // Normalize to forward slashes so `edamame:relpath` is a stable, OS-independent
    // identity/display string. The core-side observed-path derivation
    // (`observed_scope_owner_relpath`) and the id join (`instruction_join_id`) both
    // normalize separators; emitting a native `\` here on Windows would make the
    // same artifact display two different relpaths depending on its discovery source.
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| rel_str.clone());
    let mut props = BTreeMap::new();
    props.insert("edamame:kind".to_string(), kind.to_string());
    props.insert("edamame:relpath".to_string(), rel_str.clone());
    // Absolute on-disk path. This is the user's own path on their own machine,
    // surfaced in their own app; the *body* is still never stored (I5). It lets
    // the app offer "reveal in file manager" and a privacy-gated content read
    // without re-deriving per-agent config dirs on the (sandboxed) app side.
    props.insert(
        "edamame:abspath".to_string(),
        path.to_string_lossy().to_string(),
    );
    // Canonical (symlink-resolved) on-disk path. Agent skill managers install
    // one physical artifact reachable via multiple symlink aliases -- e.g.
    // agentfield links BOTH `~/.claude/commands/<name>.md` AND
    // `~/.claude/skills/<name>/commands/<name>.md` to the same file under
    // `~/.agentfield/skills/<name>/current/...`. Without a canonical identity,
    // the two aliases look like two byte-identical copies and get flagged as a
    // (false) duplicate. Resolved here (helper-side / standalone, where the file
    // is actually reachable) so the sandboxed core need not -- and cannot --
    // canonicalize. Falls back to the plain abspath when canonicalization fails.
    let canonical = std::fs::canonicalize(path)
        .map(|c| c.to_string_lossy().to_string())
        .unwrap_or_else(|_| path.to_string_lossy().to_string());
    props.insert("edamame:canonical_abspath".to_string(), canonical);
    // Byte size (the body was already read to hash it) and the load class
    // (always-in-context vs conditional / on-demand) drive the per-workspace
    // prompt-weight ("context tax") accounting in the self-augmentation report.
    props.insert("edamame:size_bytes".to_string(), bytes.len().to_string());
    props.insert(
        "edamame:load".to_string(),
        classify_instruction_load(kind, &bytes).to_string(),
    );
    // Structural-quality signal (metadata-only, I5): does the artifact carry a
    // YAML frontmatter block, does that frontmatter declare a title + a
    // description (the progressive-disclosure contract for a skill/command), and
    // how many Markdown headings structure the body. Feeds the per-skill
    // "how well is this authored" hint in the self-augmentation report. Derived
    // from the already-in-memory bytes; the body itself is never stored.
    let structure = analyze_instruction_structure(&bytes);
    props.insert(
        "edamame:struct_frontmatter".to_string(),
        structure.has_frontmatter.to_string(),
    );
    props.insert(
        "edamame:struct_description".to_string(),
        structure.has_description.to_string(),
    );
    props.insert(
        "edamame:struct_headings".to_string(),
        structure.heading_count.to_string(),
    );
    props.insert(
        "edamame:struct_quality".to_string(),
        structure.quality().to_string(),
    );
    // Metadata-only (I5) structural references to *other* instruction artifacts
    // (markdown link targets, `@file` refs, bare instruction-file paths). The
    // body is not stored -- only the extracted, deduped, bounded path-like
    // tokens. These become the edges of the skill reference graph.
    let refs = extract_instruction_refs(&bytes);
    if !refs.is_empty() {
        props.insert("edamame:refs".to_string(), refs.join("\n"));
    }
    Some(AgentComponent {
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

/// Max instruction references extracted per artifact. Bounds both the stored
/// `edamame:refs` property and, downstream, the skill reference graph.
const MAX_INSTRUCTION_REFS: usize = 32;
/// Max characters of a single extracted reference token (defends against a
/// pathological one-line file being treated as one giant "path").
const MAX_REF_LEN: usize = 256;

/// Well-known top-level instruction filenames that qualify as references even
/// without a recognizable directory segment (compared lowercased).
const INSTRUCTION_REF_BASENAMES: &[&str] = &[
    "skill.md",
    "agents.md",
    "claude.md",
    "gemini.md",
    "codex.md",
    "rules.md",
    "instructions.md",
    "memory.md",
    ".cursorrules",
    "copilot-instructions.md",
];

/// Instruction directory segments whose artifacts are *folders* (`skills/foo`,
/// `agents/foo`). A reference to the folder name -- or to any doc/support file
/// under it -- names a concrete artifact, so a folder-name token qualifies.
const INSTRUCTION_REF_FOLDER_DIR_SEGMENTS: &[&str] = &["skills/", "agents/", "subagents/"];

/// Instruction directory segments whose artifacts are *files* (`rules/foo.mdc`,
/// `commands/foo.md`). A reference must name an actual document file with a
/// recognized doc extension; the bare directory (`rules/preferences`) names no
/// artifact and must not become an edge.
const INSTRUCTION_REF_FILE_DIR_SEGMENTS: &[&str] = &["commands/", "rules/", "prompts/"];

/// Document extensions an instruction artifact body can carry. This is the doc
/// subset of [`INSTRUCTION_EXTS`]; the config/data extensions (`json`, `toml`,
/// `yaml`, `yml`) are deliberately excluded so a prose mention of a config file
/// (`hooks.json`, `settings.json`, `cli-config.json`) never becomes a reference
/// edge -- those are data the skill reads, not other instruction artifacts.
const INSTRUCTION_REF_DOC_EXTS: &[&str] = &["md", "mdc", "txt"];

/// Extract path-like references to *other* instruction artifacts from an
/// instruction file body. Pure and metadata-only (invariant I5): the body is
/// NOT stored; only the extracted path-like tokens (markdown link targets,
/// `@file` refs, and bare instruction-file paths) are returned. Output is
/// deduped, sorted, and bounded by [`MAX_INSTRUCTION_REFS`].
///
/// A token qualifies as an instruction reference when, after trimming anchors /
/// queries / surrounding punctuation, it is not a URL and it either
/// (a) is a well-known top-level instruction filename referenced with a path or
/// an explicit `@` mention, (b) contains a folder-instruction directory segment
/// (`skills/`, `agents/`, `subagents/`) AND is either the extension-less folder
/// name or a *doc* file under it (a `.py`/`.json`/`.png` inside the package is
/// the package's own internals, not another instruction artifact), or
/// (c) contains a file-instruction directory segment (`rules/`, `commands/`,
/// `prompts/`) AND names a document file (doc extension). A plain doc path that
/// is NOT anchored under any instruction directory (`docs/ARCHITECTURE.md`,
/// `sub/README.md`) is a reference to the *codebase the rule operates on*, not
/// to another instruction artifact, and does NOT qualify.
/// This is deliberately conservative -- prose sentences, plain web links, config
/// files, package-internal code, unanchored documentation, and arbitrary code
/// paths do not become edges. Three additional guards
/// keep authoring guides (skills that TEACH how to write skills/rules/hooks)
/// from emitting phantom edges to their illustrative placeholders:
/// - content inside fenced code blocks (```` ``` ```` / `~~~`) is skipped
///   entirely (it is example markup, not a live dependency);
/// - directory-only tokens (`skills/foo/`, `rules/`) are rejected (they name no
///   concrete artifact);
/// - a bare top-level basename dropped into prose ("...or AGENTS.md") is only
///   kept when written as an explicit `@AGENTS.md` mention or with a path.
pub fn extract_instruction_refs(body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    let mut refs: BTreeSet<String> = BTreeSet::new();
    let mut in_fence = false;
    let mut fence_marker = "";
    'lines: for line in text.lines() {
        let trimmed = line.trim_start();
        // Toggle fenced code-block state on ``` / ~~~ fences. Everything inside
        // a fence is illustrative (authoring examples, shell snippets, config
        // samples) and must NOT contribute reference edges.
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            let marker = if trimmed.starts_with("```") {
                "```"
            } else {
                "~~~"
            };
            if in_fence {
                if marker == fence_marker {
                    in_fence = false;
                }
            } else {
                in_fence = true;
                fence_marker = marker;
            }
            continue;
        }
        if in_fence {
            continue;
        }
        for raw in line.split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '(' | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '"'
                        | '\''
                        | '`'
                        | '<'
                        | '>'
                        | '|'
                        | ','
                        | ';'
                        | '='
                        | '*'
                )
        }) {
            let raw_trim = raw.trim();
            if raw_trim.is_empty() {
                continue;
            }
            // `@file` is an *explicit* reference; a bare basename in prose is
            // not. Capture the signal before normalization strips the `@`.
            let explicit = raw_trim.starts_with('@');
            // A directory-only token (`skills/foo/`, `rules/`) names no concrete
            // artifact -- skip it rather than emit a dangling ghost edge.
            if raw_trim.ends_with('/') {
                continue;
            }
            if let Some(tok) = normalize_ref_token(raw_trim) {
                if looks_like_instruction_ref(&tok, explicit) {
                    refs.insert(tok);
                    if refs.len() >= MAX_INSTRUCTION_REFS * 4 {
                        // Hard stop scanning a pathological file once we have far
                        // more than we will keep; the take() below trims to cap.
                        break 'lines;
                    }
                }
            }
        }
    }
    refs.into_iter().take(MAX_INSTRUCTION_REFS).collect()
}

/// Normalize a raw split token into a candidate path: strip a leading `@` / `./`,
/// drop anchors (`#...`) and queries (`?...`), trim surrounding punctuation, and
/// reject empties / over-long tokens.
fn normalize_ref_token(raw: &str) -> Option<String> {
    let mut t = raw.trim();
    // Markdown reference-style link labels sometimes arrive as `]:` fragments;
    // and colons appear in `mailto:` / URLs handled by the URL reject below.
    t = t.trim_matches(|c: char| matches!(c, '.' | ':' | '!' | '?' | '#'));
    let mut s = t.to_string();
    if let Some(rest) = s.strip_prefix('@') {
        s = rest.to_string();
    }
    if let Some(rest) = s.strip_prefix("./") {
        s = rest.to_string();
    }
    if let Some(i) = s.find('#') {
        s.truncate(i);
    }
    if let Some(i) = s.find('?') {
        s.truncate(i);
    }
    let s = s
        .trim()
        .trim_matches(|c: char| matches!(c, '.' | ':' | '/'));
    if s.is_empty() || s.len() > MAX_REF_LEN {
        return None;
    }
    Some(s.to_string())
}

/// Decide whether a normalized token names an instruction artifact. `explicit`
/// is true when the raw token was written as an `@file` mention (which promotes
/// an otherwise-ambiguous bare top-level basename to a real reference).
fn looks_like_instruction_ref(tok: &str, explicit: bool) -> bool {
    if tok.contains("://") || tok.starts_with("mailto:") {
        return false; // web link / email, not an instruction file
    }
    let lower = tok.to_ascii_lowercase();
    let has_sep = lower.contains('/');
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    let ext = std::path::Path::new(basename)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    let is_doc_ext = ext
        .as_deref()
        .map(|e| INSTRUCTION_REF_DOC_EXTS.contains(&e))
        .unwrap_or(false);
    // A recognized-but-non-doc instruction extension is a config/data file
    // (`json`, `yaml`, `toml`, ...). These are data a skill reads, never other
    // instruction artifacts, so a mention of one never becomes an edge.
    let is_config_ext = ext
        .as_deref()
        .map(|e| INSTRUCTION_EXTS.contains(&e) && !INSTRUCTION_REF_DOC_EXTS.contains(&e))
        .unwrap_or(false);

    // (a) Well-known top-level instruction filename (AGENTS.md, CLAUDE.md,
    // .cursorrules, ...). A real reference either carries a path
    // (`.cursor/AGENTS.md`) or is an explicit `@AGENTS.md` mention; a bare
    // basename dropped into prose ("...or AGENTS.md") is a passing mention.
    if INSTRUCTION_REF_BASENAMES.contains(&basename) {
        return has_sep || explicit;
    }

    if is_config_ext {
        return false;
    }

    let in_folder_dir = INSTRUCTION_REF_FOLDER_DIR_SEGMENTS
        .iter()
        .any(|seg| lower.contains(seg));
    // (b) Folder-instruction dir segment: the folder name itself
    // (`skills/gtm_report`, extension-less) or a *doc* under it
    // (`skills/gtm_report/SKILL.md`) is a concrete artifact reference. A
    // code/data file living inside the package (`skills/foo/surface_registry.py`,
    // `skills/foo/config.json`, `agents/bar/impl.ts`) is the package's own
    // internals -- data the skill reads or code it runs, never *another*
    // instruction artifact -- so it must NOT become a reference edge. Without
    // this extension gate every `.py`/`.json`/`.png` mentioned under a `skills/`
    // path in prose became a phantom "broken" edge.
    if in_folder_dir {
        return ext.is_none() || is_doc_ext;
    }
    let in_file_dir = INSTRUCTION_REF_FILE_DIR_SEGMENTS
        .iter()
        .any(|seg| lower.contains(seg));
    // (c) File-instruction dir segment: must name an actual document file.
    if in_file_dir {
        return is_doc_ext;
    }

    // (d) A doc path that is NOT anchored under any instruction directory
    // segment -- `docs/ARCHITECTURE.md`, `private/notes/plan.md`, a nested
    // `sub/README.md` -- is a reference to the *codebase the rule operates on*,
    // not to another instruction artifact. In code-heavy workspaces these plain
    // documentation paths are the dominant phantom-edge source, so they do not
    // qualify. A genuine instruction cross-reference always lives under an
    // instruction directory segment (caught by (b)/(c)) or is a well-known
    // top-level basename (caught by (a)).
    false
}

/// Classify whether an instruction artifact is *always* injected into the model
/// context (a standing "context tax" paid on every prompt) or loaded
/// *conditionally* / on demand (progressive disclosure, glob-scoped, or
/// agent-requestable). Drives the per-workspace prompt-weight accounting.
///
/// - Top-level instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`,
///   `copilot-instructions.md`, ...) and memories are always loaded.
/// - Cursor `.mdc` rules are classified from their YAML frontmatter (see
///   [`classify_rule_load`]).
/// - Skills, commands, subagents, prompts, hooks are progressive-disclosure
///   artifacts, loaded only when invoked -> conditional.
fn classify_instruction_load(kind: &str, body: &[u8]) -> &'static str {
    match kind {
        "instruction" | "memory" => "always",
        "rule" => classify_rule_load(body),
        _ => "conditional",
    }
}

/// Lightweight structural-quality signal for an instruction artifact, derived
/// from its (markdown) body: whether it carries a leading YAML frontmatter
/// block, whether that frontmatter (or a body H1) supplies a title, whether it
/// declares a non-empty `description`, and how many Markdown ATX headings
/// structure the body. Metadata-only (invariant I5): computed from the
/// already-in-memory bytes, never stored.
#[derive(Debug, Clone, Copy, Default)]
struct InstructionStructure {
    has_frontmatter: bool,
    has_title: bool,
    has_description: bool,
    heading_count: u32,
}

impl InstructionStructure {
    /// Compact `0..=100` authoring-quality score: `description` (40) + `title`
    /// (20) + heading structure (up to 40: 25 for `>=1`, `+15` for `>=3`). A
    /// fully-authored skill (frontmatter name + description + `>=3` headings)
    /// scores 100; a thin body-only stub scores low. Used as the per-skill
    /// structural-quality hint in the self-augmentation report.
    fn quality(&self) -> u8 {
        let mut q = 0u32;
        if self.has_description {
            q += 40;
        }
        if self.has_title {
            q += 20;
        }
        if self.heading_count >= 1 {
            q += 25;
        }
        if self.heading_count >= 3 {
            q += 15;
        }
        q.min(100) as u8
    }
}

/// Analyze the structural quality of an instruction artifact body. Pure and
/// metadata-only: parses a leading `---` YAML frontmatter block for
/// `name`/`title`/`description` keys and counts Markdown ATX headings
/// (`#`..`######`) in the body region. Fenced code blocks are skipped so `#`
/// comments inside examples do not inflate the heading count. A body-level H1
/// counts as a title when the frontmatter supplied none.
fn analyze_instruction_structure(body: &[u8]) -> InstructionStructure {
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => return InstructionStructure::default(),
    };
    let mut out = InstructionStructure::default();
    let trimmed = text.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);

    // Frontmatter block between the first two `---` fences.
    let mut body_start = 0usize;
    if trimmed.starts_with("---") {
        let after = &trimmed[3..];
        if let Some(end) = after.find("\n---") {
            out.has_frontmatter = true;
            let front = &after[..end];
            for line in front.lines() {
                let l = line.trim();
                for key in ["name:", "title:"] {
                    if let Some(rest) = l.strip_prefix(key) {
                        if !rest.trim().trim_matches(['"', '\'']).is_empty() {
                            out.has_title = true;
                        }
                    }
                }
                if let Some(rest) = l.strip_prefix("description:") {
                    if !rest.trim().trim_matches(['"', '\'']).is_empty() {
                        out.has_description = true;
                    }
                }
            }
            // Advance the heading scan past the closing fence: 3 for the leading
            // `---`, `end` to the "\n---", plus 4 for the "\n---" itself.
            body_start = 3 + end + 4;
        }
    }

    // Count ATX headings in the body region, skipping fenced code blocks.
    let scan = trimmed.get(body_start..).unwrap_or("");
    let mut in_fence = false;
    for line in scan.lines() {
        let l = line.trim_start();
        if l.starts_with("```") || l.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        // ATX heading: 1..=6 leading '#' (ASCII, so byte offset == count)
        // followed by a space (CommonMark requires the space).
        let hashes = l.chars().take_while(|&c| c == '#').count();
        if (1..=6).contains(&hashes) && l[hashes..].starts_with(' ') {
            out.heading_count = out.heading_count.saturating_add(1);
            // A body H1 supplies a title when the frontmatter had none.
            if hashes == 1 && !out.has_title {
                out.has_title = true;
            }
        }
    }
    out
}

/// Classify a Cursor `.mdc` rule as `always` or `conditional` from its leading
/// YAML frontmatter block. Only `alwaysApply: true` counts as always-loaded;
/// glob-scoped (`globs:`) and description-only (agent-requestable) rules are
/// conditional. A rule with no parseable frontmatter defaults to conditional so
/// the context-tax estimate is not inflated by ambiguous artifacts.
fn classify_rule_load(body: &[u8]) -> &'static str {
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => return "conditional",
    };
    let trimmed = text.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
    if !trimmed.starts_with("---") {
        return "conditional";
    }
    // Isolate the frontmatter block between the first two `---` fences.
    let after = &trimmed[3..];
    let front = match after.find("\n---") {
        Some(i) => &after[..i],
        None => after,
    };
    for line in front.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("alwaysApply:") {
            if rest.trim().eq_ignore_ascii_case("true") {
                return "always";
            }
        }
    }
    "conditional"
}

/// Workspace-root top-level instruction files (project-scoped, always loaded).
const WORKSPACE_TOPLEVEL_INSTRUCTION_FILES: &[(&str, &str)] = &[
    ("AGENTS.md", "instruction"),
    ("CLAUDE.md", "instruction"),
    ("GEMINI.md", "instruction"),
    ("CODEX.md", "instruction"),
    (".cursorrules", "instruction"),
    (".github/copilot-instructions.md", "instruction"),
];

/// Workspace-root config directories walked for project-scoped instruction /
/// skill / rule artifacts. Each is treated like a per-agent config dir: its
/// top-level instruction files plus the [`INSTRUCTION_SUBDIRS`] allowlist.
const WORKSPACE_CONFIG_DIRS: &[&str] = &[".cursor", ".claude"];

/// Instruction subdirectories that live directly under the workspace root
/// (not under `.cursor` / `.claude`). Many first-party skill libraries use a
/// top-level `skills/<name>/SKILL.md` layout (SIFU, custom agent packs); if we
/// only walk `.cursor`/`.claude`, those packages stay out of the inventory and
/// every rule that references them surfaces as a false "broken reference".
///
/// Narrower than [`INSTRUCTION_SUBDIRS`]: omit `rules` / `hooks` / `prompts`
/// at the repo root so ordinary project docs (`docs/`, prose `rules.md`) are
/// not sucked into the instruction inventory. Keep the folder-artifact kinds
/// that match the reference-graph resolver (`skills/`, `agents/`, …).
const WORKSPACE_ROOT_INSTRUCTION_SUBDIRS: &[(&str, &str)] = &[
    ("skills", "skill"),
    ("skills-cursor", "skill"),
    ("commands", "command"),
    ("agents", "subagent"),
    ("subagents", "subagent"),
];

/// Discover a *workspace repository's* instruction / skill / rule / command /
/// subagent files and project them as content-hashed `file` inventory components,
/// tagged `edamame:scope=workspace`. Mirrors
/// [`discover_agent_instruction_components`] but roots the walk at a project
/// directory (`<root>/.cursor`, `<root>/.claude`, top-level `skills/` /
/// `agents/` / `commands/`, and top-level `AGENTS.md` / `CLAUDE.md` /
/// `.github/copilot-instructions.md`). Bounded (depth + count + size) and
/// limited to the same allowlist, so transcript / session stores are never
/// scanned. Bodies are hashed, never stored (invariant I5).
pub fn discover_workspace_instruction_components(workspace_root: &Path) -> Vec<AgentComponent> {
    const MAX_FILES: usize = INSTRUCTION_MAX_FILES;
    const MAX_DEPTH: usize = INSTRUCTION_MAX_DEPTH;
    const MAX_FILE_BYTES: u64 = INSTRUCTION_MAX_FILE_BYTES;

    if !workspace_root.is_dir() {
        return Vec::new();
    }
    let ws_label = workspace_root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "workspace".to_string());
    let agent_scope = format!("workspace:{ws_label}");

    let mut found: Vec<(PathBuf, &'static str)> = Vec::new();

    // Top-level workspace instruction files.
    for (rel, kind) in WORKSPACE_TOPLEVEL_INSTRUCTION_FILES {
        if found.len() >= MAX_FILES {
            break;
        }
        let p = workspace_root.join(rel);
        if p.is_file() {
            found.push((p, kind));
        }
    }

    // Workspace-root skill / agent / command libraries (e.g. `skills/burn_rate/
    // SKILL.md`). Same collector + caps as the per-agent walk; these are the
    // packages rules under `.cursor/rules/` typically reference by relative
    // path, so omitting them produces false broken-reference edges.
    for (subdir, kind) in WORKSPACE_ROOT_INSTRUCTION_SUBDIRS {
        if found.len() >= MAX_FILES {
            break;
        }
        let root = workspace_root.join(subdir);
        if root.is_dir() {
            collect_instruction_files(&root, kind, MAX_DEPTH, &mut found, MAX_FILES);
        }
    }

    // `.cursor` / `.claude` config dirs at the workspace root: reuse the same
    // top-level classification + INSTRUCTION_SUBDIRS allowlist as per-agent.
    for cfg in WORKSPACE_CONFIG_DIRS {
        if found.len() >= MAX_FILES {
            break;
        }
        let cfg_dir = workspace_root.join(cfg);
        if !cfg_dir.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&cfg_dir) {
            for entry in entries.flatten() {
                if found.len() >= MAX_FILES {
                    break;
                }
                let path = entry.path();
                let (_is_dir, is_file) = entry_kind_following_symlinks(&entry, &path);
                if !is_file {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(kind) = classify_toplevel_instruction(name) {
                        found.push((path, kind));
                    }
                }
            }
        }
        for (subdir, kind) in INSTRUCTION_SUBDIRS {
            if found.len() >= MAX_FILES {
                break;
            }
            let root = cfg_dir.join(subdir);
            if root.is_dir() {
                collect_instruction_files(&root, kind, MAX_DEPTH, &mut found, MAX_FILES);
            }
        }
    }

    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.dedup_by(|a, b| a.0 == b.0);

    let mut out: Vec<AgentComponent> = Vec::new();
    for (path, kind) in found.into_iter().take(MAX_FILES) {
        if let Some(mut comp) =
            instruction_file_component(workspace_root, &agent_scope, &path, kind, MAX_FILE_BYTES)
        {
            comp.properties
                .insert("edamame:scope".to_string(), "workspace".to_string());
            comp.properties
                .insert("edamame:workspace".to_string(), ws_label.clone());
            out.push(comp);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Workspace-root derivation + per-workspace instruction inventory
// ---------------------------------------------------------------------------

/// Maximum number of `-`-split tokens fused into a single path segment while
/// disambiguating a project slug. Bounds the separator-combination search to
/// `2^(MAX_SEGMENT_TOKENS - 1)` candidates per segment.
const MAX_SEGMENT_TOKENS: usize = 6;

/// Upper bound on the number of `-`-split tokens in a slug we will attempt to
/// resolve. Guards against pathological `source_path` values.
const MAX_SLUG_TOKENS: usize = 64;

/// Cap on the number of distinct workspace roots resolved per inventory pass.
const MAX_WORKSPACE_ROOTS: usize = 64;

/// Cap on the number of directory entries examined per level while resolving a
/// slug via the directory-scan fallback. Guards against pathological
/// directories (huge caches, node_modules at an unexpected level, ...).
const MAX_DIR_SCAN_ENTRIES: usize = 4096;

/// Extract the encoded project slug from a Cursor/Claude transcript
/// `source_path`. Both encode the workspace as the path component immediately
/// after a `projects` directory:
///
/// - Cursor: `~/.cursor/projects/<slug>/agent-transcripts/<uuid>.jsonl`
/// - Claude: `~/.claude/projects/<slug>/<uuid>.jsonl`
///
/// Returns `None` for agents that do not use this scheme.
pub fn project_slug_from_source_path(source_path: &str) -> Option<String> {
    let comps: Vec<String> = Path::new(source_path)
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    for i in 0..comps.len() {
        if comps[i] == "projects" && i + 1 < comps.len() {
            let slug = &comps[i + 1];
            if !slug.is_empty() {
                return Some(slug.clone());
            }
        }
    }
    None
}

/// Resolve a dash-encoded project slug back to an existing absolute directory,
/// using the filesystem to disambiguate `-` (which the slug scheme uses for both
/// path separators AND literal `-`/`_` characters in directory names). Greedy
/// longest-segment match with an `is_dir()` check at each step. Returns `None`
/// when no existing directory can be reconstructed.
pub fn resolve_slug_to_existing_dir(slug: &str) -> Option<PathBuf> {
    resolve_slug_under(Path::new(std::path::MAIN_SEPARATOR_STR), slug)
}

/// Filesystem-parameterized core of [`resolve_slug_to_existing_dir`]; walks the
/// slug tokens under `base_root`. Split out so unit tests can drive it against a
/// tempdir instead of the real root.
pub fn resolve_slug_under(base_root: &Path, slug: &str) -> Option<PathBuf> {
    // A leading '-' (Claude's `-Users-...`) encodes the root '/'; splitting on
    // '-' and dropping empties normalizes that away.
    let tokens: Vec<&str> = slug.split('-').filter(|t| !t.is_empty()).collect();
    if tokens.is_empty() || tokens.len() > MAX_SLUG_TOKENS {
        return None;
    }

    let mut base = base_root.to_path_buf();
    let mut i = 0usize;
    while i < tokens.len() {
        let remaining = &tokens[i..];
        // Cheap stat-probe path first (handles '-'/'_' only; no read_dir), then
        // the directory-scan fallback which reconstructs names with arbitrary
        // separator characters (spaces, parentheses, '@', '.', non-breaking
        // spaces, ... -- e.g. a localized Google Drive mount like
        // `Mon Drive (user@example.org)`). Prefer whichever consumes the most
        // slug tokens so `edamame_core` still wins over `edamame`.
        let stat_hit = stat_probe_slug_match(&base, remaining);
        let scan_hit = scan_dir_for_slug_match(&base, remaining);
        let hit = match (stat_hit, scan_hit) {
            (Some(a), Some(b)) => Some(if b.1 > a.1 { b } else { a }),
            (a, b) => a.or(b),
        };
        match hit {
            Some((next, take)) => {
                base = next;
                i += take;
            }
            None => return None,
        }
    }

    if base.is_dir() {
        Some(base)
    } else {
        None
    }
}

/// Stat-probe arm of [`resolve_slug_under`]: re-materialize candidate segment
/// names by re-joining the leading `remaining` tokens with every `-`/`_`
/// combination and `is_dir()`-checking each candidate. Longest segment first.
/// Returns the matched child and the number of tokens it consumes.
fn stat_probe_slug_match(base: &Path, remaining: &[&str]) -> Option<(PathBuf, usize)> {
    let max_take = remaining.len().min(MAX_SEGMENT_TOKENS);
    for take in (1..=max_take).rev() {
        let seg_tokens = &remaining[..take];
        let gaps = seg_tokens.len() - 1;
        let combos: u32 = 1 << gaps; // gaps <= MAX_SEGMENT_TOKENS-1 (=5)
        for mask in 0..combos {
            let mut seg = String::new();
            for (idx, tok) in seg_tokens.iter().enumerate() {
                if idx > 0 {
                    // bit set -> '_', clear -> '-'
                    seg.push(if (mask >> (idx - 1)) & 1 == 1 {
                        '_'
                    } else {
                        '-'
                    });
                }
                seg.push_str(tok);
            }
            let cand = base.join(&seg);
            if cand.is_dir() {
                return Some((cand, take));
            }
        }
    }
    None
}

/// Tokenize a directory name the way the Cursor/Claude slug encoder does:
/// every run of non-alphanumeric characters collapses into one separator.
fn slug_tokens_of_name(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

/// Directory-scan arm of [`resolve_slug_under`]: list `base`'s child
/// directories, tokenize each name with [`slug_tokens_of_name`], and pick the
/// child whose token sequence is the longest prefix of `remaining`. This is
/// what resolves segments whose original name contains separator characters
/// the slug collapsed to '-' (spaces, parentheses, '@', '.', ...). Returns the
/// matched child and the number of tokens it consumes.
fn scan_dir_for_slug_match(base: &Path, remaining: &[&str]) -> Option<(PathBuf, usize)> {
    let entries = std::fs::read_dir(base).ok()?;
    let mut best: Option<(PathBuf, usize)> = None;
    for entry in entries.flatten().take(MAX_DIR_SCAN_ENTRIES) {
        let path = entry.path();
        let is_dir = match entry.file_type() {
            Ok(ft) if ft.is_dir() => true,
            // Follow symlinked workspace roots.
            Ok(ft) if ft.is_symlink() => path.is_dir(),
            _ => false,
        };
        if !is_dir {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let name_tokens = slug_tokens_of_name(&name);
        if name_tokens.is_empty() || name_tokens.len() > remaining.len() {
            continue;
        }
        if name_tokens
            .iter()
            .zip(remaining.iter())
            .all(|(a, b)| a == *b)
        {
            let take = name_tokens.len();
            if best.as_ref().map_or(true, |(_, t)| take > *t) {
                best = Some((path, take));
            }
        }
    }
    best
}

/// Derive the workspace root directory for a session from its transcript
/// `source_path`: decode the project slug, then reconstruct + verify the path on
/// disk. Returns `None` for agents without the `projects/<slug>` scheme or when
/// the directory can no longer be found (moved/deleted workspace).
pub fn workspace_root_from_source_path(source_path: &str) -> Option<PathBuf> {
    let slug = project_slug_from_source_path(source_path)?;
    resolve_slug_to_existing_dir(&slug)
}

/// Dash-encode an absolute working-directory into the same slug shape the
/// `projects/<slug>` scheme uses (leading `-` for the root, path separators as
/// `-`). Used to give agents that record only a raw `cwd` (Codex) a stable,
/// join-able workspace slug that groups by directory exactly like the
/// transcript-path agents. The encoding does NOT need to round-trip through
/// [`resolve_slug_to_existing_dir`] because the cwd IS the resolved root (see
/// [`workspace_root_and_slug_for_session`]); it only has to be stable so a
/// session's slug matches its [`WorkspaceInventory::slug`]. Empty for an empty
/// or root-only path.
pub fn slug_from_workspace_dir(dir: &str) -> String {
    let comps: Vec<String> = Path::new(dir)
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    if comps.is_empty() {
        return String::new();
    }
    format!("-{}", comps.join("-"))
}

/// Resolve a session's workspace slug, preferring the `projects/<slug>` segment
/// decoded from `source_path` and falling back to a slug derived from
/// `workspace_hint` (the agent's recorded `cwd`, e.g. Codex). Pure string work,
/// no filesystem access -- safe to call from the sandboxed core. Returns `None`
/// when neither signal yields a slug (a chat session with no working directory).
pub fn workspace_slug_for_session(source_path: &str, workspace_hint: &str) -> Option<String> {
    if let Some(slug) = project_slug_from_source_path(source_path) {
        return Some(slug);
    }
    if !workspace_hint.trim().is_empty() {
        let slug = slug_from_workspace_dir(workspace_hint);
        if !slug.is_empty() {
            return Some(slug);
        }
    }
    None
}

/// Resolve a session's `(workspace_root, slug)` for filesystem inventory
/// scanning, honouring `workspace_hint`. Requires filesystem access, so it runs
/// only on the unsandboxed path (standalone core / helper daemon).
///
/// - When `source_path` carries a `projects/<slug>` segment: identical to
///   [`workspace_root_from_source_path`] -- resolve the slug back to an on-disk
///   directory. This preserves today's behaviour for Cursor / Claude exactly.
/// - Otherwise, when `workspace_hint` names an existing directory (Codex's
///   recorded `cwd`): that directory IS the root, and the slug is
///   [`slug_from_workspace_dir`].
/// - Otherwise `None`.
pub fn workspace_root_and_slug_for_session(
    source_path: &str,
    workspace_hint: &str,
) -> Option<(PathBuf, String)> {
    if let Some(slug) = project_slug_from_source_path(source_path) {
        let root = resolve_slug_to_existing_dir(&slug)?;
        return Some((root, slug));
    }
    if !workspace_hint.trim().is_empty() {
        let dir = Path::new(workspace_hint);
        if dir.is_dir() {
            let slug = slug_from_workspace_dir(workspace_hint);
            if !slug.is_empty() {
                return Some((dir.to_path_buf(), slug));
            }
        }
    }
    None
}

/// A single workspace repository's discovered instruction inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceInventory {
    /// Canonical project slug (from `project_slug_from_source_path`) of the first
    /// transcript source path that resolved to this root. Empty when the source
    /// path carried no `projects/<slug>` scheme. Lets callers join per-session
    /// usage (keyed by decoded slug) back to this resolved root's label.
    pub slug: String,
    /// Absolute workspace-root directory that was resolved + scanned.
    pub root: String,
    /// Short workspace label (the root's final path component).
    pub label: String,
    /// Project-scoped instruction / skill / rule / command / subagent
    /// components discovered under the root (tagged `edamame:scope=workspace`).
    pub components: Vec<AgentComponent>,
}

/// Resolve the distinct workspace roots referenced by a set of transcript
/// `source_paths` and collect each root's project-scoped instruction inventory.
///
/// This is the single shared primitive behind both dispatch paths of the
/// self-augmentation report: the standalone core calls it directly, and the
/// (sandboxed) macOS app reaches it through the `collect_workspace_inventory`
/// helper utility. Source paths that carry no `projects/<slug>` scheme, or whose
/// slug no longer resolves to an on-disk directory, are silently skipped.
/// Bounded to [`MAX_WORKSPACE_ROOTS`] distinct roots so a noisy transcript set
/// cannot fan out an unbounded filesystem walk.
///
/// Each entry is either a bare `source_path` or `"<source_path>\t<workspace_hint>"`.
/// The optional tab-separated hint carries an agent-recorded `cwd` for agents
/// (Codex) whose transcript path has no `projects/<slug>` segment, so the scan
/// can still resolve a workspace root. The encoding keeps the wire contract a
/// plain `Vec<String>` (the `collect_workspace_inventory` helper utility forwards
/// the strings untouched): a hint is appended ONLY when non-empty, so an older
/// helper that predates hint support sees the bare source path for every
/// transcript agent and degrades exactly to its prior behaviour (Codex, which
/// had no resolvable root before, simply stays unresolved until the helper is
/// rebuilt).
pub fn collect_workspace_inventories(source_paths: &[String]) -> Vec<WorkspaceInventory> {
    let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    let mut out: Vec<WorkspaceInventory> = Vec::new();
    for sp_raw in source_paths {
        if out.len() >= MAX_WORKSPACE_ROOTS {
            break;
        }
        let (sp, hint) = match sp_raw.split_once('\t') {
            Some((p, h)) => (p, h),
            None => (sp_raw.as_str(), ""),
        };
        let (root, slug) = match workspace_root_and_slug_for_session(sp, hint) {
            Some(rs) => rs,
            None => continue,
        };
        if !seen.insert(root.clone()) {
            continue;
        }
        let label = root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "workspace".to_string());
        let components = discover_workspace_instruction_components(&root);
        out.push(WorkspaceInventory {
            slug,
            root: root.to_string_lossy().to_string(),
            label,
            components,
        });
    }
    out
}

/// Return the subset of `paths` that are CONFIRMED ABSENT on disk.
///
/// A path is reported absent only when stat-ing it (symlinks followed) fails
/// with a `NotFound` error -- i.e. the file, or a broken symlink's target, is
/// genuinely gone (a deleted skill, an unmounted network drive, ...). Any path
/// that exists, or whose status is ambiguous for any other reason (a permission
/// error, a transient I/O error), is intentionally omitted so the caller can
/// fail open and never drop a path it is not sure about.
///
/// This is the shared primitive behind the self-augmentation builder's
/// observed-path pruning: an observed skill is "rescued" to `available=true` on
/// the strength of a past transcript read, and without a live existence check it
/// would stay available forever even after its backing file vanished. The check
/// runs unsandboxed -- in-process for the standalone core, or across the macOS
/// sandbox boundary via the `confirm_absent_instruction_paths` helper utility so
/// the app can reach the user's real project directories.
pub fn confirm_absent_instruction_paths(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter(|p| {
            !p.is_empty()
                && matches!(
                    std::fs::metadata(Path::new(p.as_str())),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound
                )
        })
        .cloned()
        .collect()
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
/// transcript-observer status, the MCP/component discovery, and the operator
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
/// core fills it by joining observer status + MCP/component discovery + allow-list.
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
    /// Count of discovered components attributed to this agent.
    pub component_count: u32,
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

/// Hard cap on the number of sub-agent spawn markers extracted from a single
/// transcript body. Bounds the delegation-tree node count, the goal-hash maps
/// in `analyze_delegation`, and the serialized payload sent to the UI, so a
/// pathologically large or adversarial transcript cannot exhaust memory. Far
/// above every CloudModel recursion threshold (`fanout_high` default 8), so the
/// cap only saturates the *reported* fan-out count -- it never suppresses a
/// recursion finding, which fires well before this ceiling.
const MAX_SPAWN_MARKERS: usize = 4096;

/// Hard cap on the number of JSON object records retained for structured
/// delegation-depth reconstruction. Bounds the `records` vec and the `by_uuid`
/// index built by `extract_spawn_markers_structured` independently of the
/// per-file byte cap, so a transcript that is entirely compact JSONL cannot
/// build an unbounded parent-linkage graph.
const MAX_TRANSCRIPT_RECORDS: usize = 100_000;

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
        if spawns.len() >= MAX_SPAWN_MARKERS {
            break;
        }
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
        // Bound the parent-linkage graph independently of the per-file byte cap:
        // a transcript that is entirely compact JSONL objects would otherwise
        // grow `records`/`by_uuid` without limit. `saw_object` is already set, so
        // the structured path is still chosen (we never fall back to the text
        // scan just because the record cap was hit).
        if records.len() >= MAX_TRANSCRIPT_RECORDS {
            break;
        }

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
        if spawns.len() >= MAX_SPAWN_MARKERS {
            break;
        }
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
///   delegation depth (nested transcripts) or at least `loop_min_repeats`
///   times overall (flat transcripts where nested sub-agent turns are not
///   inlined and every spawn reads at depth 1).
/// * **Excessive depth** -- `max_depth >= depth_high`.
/// * **Excessive fan-out** -- a single session dispatches `>= fanout_high`
///   sub-agents.
///
/// All three thresholds are CloudModel-tunable via
/// `agent_visibility_params::agent_recursion_thresholds()`.
pub fn analyze_delegation(
    agent_type: &str,
    agent_instance_id: &str,
    spawns: &[RawSpawn],
) -> DelegationTree {
    let now = chrono::Utc::now();
    // CloudModel-tunable recursion thresholds:
    // * `depth_high` -- delegation depth at/above which depth alone is a finding.
    // * `loop_min_repeats` -- same-goal re-delegations at/above which a
    //   same-purpose loop is flagged even when every spawn reads at depth 1.
    // * `fanout_high` -- sub-agent fan-out at/above which fan-out alone fires.
    let thresholds = agent_visibility_params::agent_recursion_thresholds();
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
    // `.take(MAX_SPAWN_MARKERS)` keeps this self-bounding even for direct
    // callers that did not go through the capped extractors -- the fan-out
    // threshold (default 8) fires long before this ceiling, so the cap only
    // saturates the reported node count.
    for spawn in spawns.iter().take(MAX_SPAWN_MARKERS) {
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
        if *count >= thresholds.loop_min_repeats {
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
                agent_type, max_repeat, thresholds.loop_min_repeats
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
    } else if tree.max_depth >= thresholds.depth_high {
        tree.findings.push(
            VisibilityFinding::new(
                "recursion",
                "recursion_excessive_depth",
                VisibilitySeverity::Medium,
                &subject,
                "Excessive delegation depth",
                format!(
                    "Agent '{}' reached delegation depth {} (>= {}).",
                    agent_type, tree.max_depth, thresholds.depth_high
                ),
            )
            .with_evidence("agent_type", agent_type.to_string())
            .with_evidence("max_depth", tree.max_depth.to_string())
            .with_owasp(),
        );
    } else if fan_out >= thresholds.fanout_high {
        tree.findings.push(
            VisibilityFinding::new(
                "recursion",
                "recursion_excessive_fanout",
                VisibilitySeverity::Medium,
                &subject,
                "High sub-agent fan-out",
                format!(
                    "Agent '{}' spawned {} sub-agents in one session (>= {}).",
                    agent_type, fan_out, thresholds.fanout_high
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

/// Content-addressed hash of an instruction/config file body for inventory
/// `file` components. Never stores the body (invariant I5). Returns `None` if the
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
        let out = agents_with_blast_radius(&host, &sandboxes, &BTreeMap::new(), &BTreeMap::new());
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
        let out = agents_with_blast_radius(&host, &sandboxes, &critical, &BTreeMap::new());
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
        let out = agents_with_blast_radius(&host, &sandboxes, &BTreeMap::new(), &BTreeMap::new());
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
        let out = agents_with_blast_radius(&host, &sandboxes, &critical, &BTreeMap::new());
        assert!(out.is_empty());
    }

    #[test]
    fn blast_radius_quiet_when_sandbox_unassessed() {
        // `None` is "could not determine" -- not a claim, so never qualifies.
        let host = host_privilege_fixture(true, true);
        let sandboxes = vec![agent_sandbox_fixture("unknown_agent", None)];
        let out = agents_with_blast_radius(&host, &sandboxes, &BTreeMap::new(), &BTreeMap::new());
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
        let out = agents_with_blast_radius(&host, &sandboxes, &critical, &BTreeMap::new());
        // cursor has no amplifier (host unassessed, no critical subprocess);
        // claude_code fires on its critical subprocess only.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].agent_type, "claude_code");
        assert!(!out[0].passwordless_root);
        assert!(out[0].critical_subprocess);
    }

    #[test]
    fn blast_radius_fires_on_unsandboxed_plus_secret_exposure() {
        // No passwordless root, no critical subprocess -- but secret material
        // was observed in the agent's transcript context (BR-1).
        let host = host_privilege_fixture(true, false);
        let sandboxes = vec![agent_sandbox_fixture("codex", Some(false))];
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "codex".to_string(),
            vec!["github_token".to_string(), "private_key".to_string()],
        );
        let out = agents_with_blast_radius(&host, &sandboxes, &BTreeMap::new(), &secrets);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].agent_type, "codex");
        assert!(out[0].secret_exposure);
        assert_eq!(
            out[0].secret_exposure_labels,
            vec!["github_token".to_string(), "private_key".to_string()]
        );
        assert!(!out[0].passwordless_root);
        assert!(!out[0].critical_subprocess);
        assert!(out[0]
            .reasons
            .iter()
            .any(|r| r.contains("secret material in agent context")));
    }

    #[test]
    fn blast_radius_secret_exposure_still_bounded_by_os_confinement() {
        // Secret exposure on a positively OS-confined agent does NOT qualify:
        // the sandbox bounds what the agent can reach even with the material.
        let host = host_privilege_fixture(true, false);
        let sandboxes = vec![agent_sandbox_fixture("sandboxed_agent", Some(true))];
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "sandboxed_agent".to_string(),
            vec!["private_key".to_string()],
        );
        let out = agents_with_blast_radius(&host, &sandboxes, &BTreeMap::new(), &secrets);
        assert!(out.is_empty());
    }

    #[test]
    fn blast_radius_is_sorted_by_agent_type() {
        let host = host_privilege_fixture(true, true);
        let sandboxes = vec![
            agent_sandbox_fixture("openclaw", Some(false)),
            agent_sandbox_fixture("cursor", Some(false)),
            agent_sandbox_fixture("claude_code", Some(false)),
        ];
        let out = agents_with_blast_radius(&host, &sandboxes, &BTreeMap::new(), &BTreeMap::new());
        let names: Vec<&str> = out.iter().map(|a| a.agent_type.as_str()).collect();
        assert_eq!(names, vec!["claude_code", "cursor", "openclaw"]);
    }

    // --- Agent governance harness presence (AI agent governance posture) -----------------

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
            identity: None,
        }
    }

    #[test]
    fn agents_without_harness_fires_when_agents_present_and_no_harness() {
        let harnesses = vec![
            harness_fixture("agentfield", false),
            harness_fixture("rippletide", false),
        ];
        // Agents present + no harness detected -> the AI agent governance gap fires.
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
        std::fs::create_dir_all(
            tmp.path()
                .join("AppData")
                .join("Roaming")
                .join("rippletide"),
        )
        .unwrap();
        let harnesses = detect_agent_harnesses_with(tmp.path(), &[]);
        let rt = harnesses.iter().find(|h| h.slug == "rippletide").unwrap();
        assert!(rt.detected);
        assert!(rt.evidence.iter().any(|e| e.contains("rippletide")));
        // The sibling harness stays undetected.
        let af = harnesses.iter().find(|h| h.slug == "agentfield").unwrap();
        assert!(!af.detected);
    }

    fn blast_radius_fixture(agent_type: &str) -> BlastRadiusAgent {
        BlastRadiusAgent {
            agent_type: agent_type.to_string(),
            unsandboxed: true,
            passwordless_root: true,
            critical_subprocess: false,
            secret_exposure: false,
            secret_exposure_labels: Vec::new(),
            reasons: vec!["unsandboxed (full user-file access)".to_string()],
        }
    }

    #[test]
    fn agents_with_harness_divergence_fires_when_harness_present_and_breach() {
        let harnesses = vec![
            harness_fixture("agentfield", true),
            harness_fixture("rippletide", false),
        ];
        let blast = vec![
            blast_radius_fixture("cursor"),
            blast_radius_fixture("claude_code"),
        ];
        // A harness IS installed yet two agents still escape their boundary ->
        // the control is present but not confining them. Sorted, de-duplicated.
        let diverging = agents_with_harness_divergence(&harnesses, &blast);
        assert_eq!(
            diverging,
            vec!["claude_code".to_string(), "cursor".to_string()]
        );
    }

    #[test]
    fn agents_with_harness_divergence_clears_when_no_harness() {
        let harnesses = vec![
            harness_fixture("agentfield", false),
            harness_fixture("rippletide", false),
        ];
        let blast = vec![blast_radius_fixture("cursor")];
        // No harness detected -> this is the `agents_without_harness` gap, not
        // a divergence, so this rule stays silent (no double-counting).
        assert!(agents_with_harness_divergence(&harnesses, &blast).is_empty());
    }

    #[test]
    fn agents_with_harness_divergence_clears_when_no_breach() {
        let harnesses = vec![harness_fixture("agentfield", true)];
        // A harness is present and no agent breaches its boundary -> the harness
        // is doing its job, so the divergence threat does not fire.
        assert!(agents_with_harness_divergence(&harnesses, &[]).is_empty());
    }

    // --- Governed-agent identity binding (best-effort, honest) ---------------

    #[test]
    fn extract_identity_token_reads_plain_did() {
        assert_eq!(
            extract_identity_token("did:web:agentfield.ai:projects:acme\n"),
            Some("did:web:agentfield.ai:projects:acme".to_string())
        );
    }

    #[test]
    fn extract_identity_token_reads_json_did_key() {
        assert_eq!(
            extract_identity_token(r#"{"did": "did:key:z6Mk-acme", "other": 1}"#),
            Some("did:key:z6Mk-acme".to_string())
        );
    }

    #[test]
    fn extract_identity_token_rejects_prose_and_empty() {
        // Whitespace-bearing prose is not an identity (no fabrication).
        assert_eq!(extract_identity_token("this is a config file"), None);
        assert_eq!(extract_identity_token("   \n  "), None);
        // JSON object without a recognized identity key yields nothing.
        assert_eq!(extract_identity_token(r#"{"theme": "dark"}"#), None);
    }

    #[test]
    fn detect_agent_harnesses_reads_identity_when_did_file_present() {
        let tmp = tempfile::TempDir::new().unwrap();
        let af = tmp.path().join(".af");
        std::fs::create_dir_all(&af).unwrap();
        std::fs::write(af.join("did"), "did:web:agentfield.ai:projects:acme\n").unwrap();
        let harnesses = detect_agent_harnesses_with(tmp.path(), &[]);
        let af = harnesses.iter().find(|h| h.slug == "agentfield").unwrap();
        assert!(af.detected);
        assert_eq!(
            af.identity.as_deref(),
            Some("did:web:agentfield.ai:projects:acme")
        );
    }

    #[test]
    fn detect_agent_harnesses_identity_is_none_without_identity_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Footprint present (config dir) but NO identity-bearing file -> honest
        // `None`, never fabricated from the directory's mere existence.
        std::fs::create_dir_all(tmp.path().join(".config").join("agentfield")).unwrap();
        let harnesses = detect_agent_harnesses_with(tmp.path(), &[]);
        let af = harnesses.iter().find(|h| h.slug == "agentfield").unwrap();
        assert!(af.detected);
        assert_eq!(af.identity, None);
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

    // --- Follow-up #1: Cursor marketplace-plugin MCP discovery ---------------

    /// Write a Cursor plugin `mcp.json` at the marketplace cache layout depth
    /// (`plugins/cache/<publisher>/<name>/<hash>/mcp.json`).
    fn write_cursor_plugin_mcp(home: &Path, name: &str, contents: &str) {
        let dir = home
            .join(".cursor")
            .join("plugins")
            .join("cache")
            .join("cursor-public")
            .join(name)
            .join("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("mcp.json"), contents).unwrap();
    }

    #[test]
    fn cursor_plugin_bare_object_mcp_json_is_discovered() {
        // The Notion marketplace plugin ships a BARE object (top-level keys are
        // server names), NOT the `mcpServers` wrapper. It must still surface.
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        write_cursor_plugin_mcp(
            home,
            "notion-workspace",
            r#"{ "notion": { "type": "http", "url": "https://mcp.notion.com/mcp" } }"#,
        );
        let endpoints = discover_mcp_endpoints(home);
        let notion = endpoints
            .iter()
            .find(|e| e.server_name == "notion")
            .expect("notion plugin endpoint discovered");
        assert_eq!(notion.agent_type, "cursor");
        assert!(!notion.is_edamame_server);
        assert_eq!(notion.url.as_deref(), Some("https://mcp.notion.com/mcp"));
        assert!(notion.config_path.contains("plugins"));
    }

    #[test]
    fn cursor_plugin_wrapper_with_auth_client_id_is_oauth() {
        // The Slack marketplace plugin uses the `mcpServers` wrapper plus an
        // `auth: { CLIENT_ID: ... }` OAuth registration.
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        write_cursor_plugin_mcp(
            home,
            "slack",
            r#"{ "mcpServers": { "slack": { "url": "https://mcp.slack.com/mcp", "auth": { "CLIENT_ID": "abc.123" } } } }"#,
        );
        let endpoints = discover_mcp_endpoints(home);
        let slack = endpoints
            .iter()
            .find(|e| e.server_name == "slack")
            .expect("slack plugin endpoint discovered");
        assert_eq!(slack.agent_type, "cursor");
        // `auth.CLIENT_ID` -> OAuth: the OAuth metadata URI is derived from the
        // server host, which is only populated when `has_oauth` was detected.
        assert_eq!(
            slack.oauth_metadata_uri.as_deref(),
            Some("https://mcp.slack.com/.well-known/oauth-protected-resource"),
        );
    }

    #[test]
    fn cursor_plugin_endpoint_deduped_against_global_config() {
        // Same server declared in both ~/.cursor/mcp.json and a plugin file must
        // collapse to a single endpoint (identical id).
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".cursor")).unwrap();
        std::fs::write(
            home.join(".cursor").join("mcp.json"),
            r#"{ "mcpServers": { "notion": { "type": "http", "url": "https://mcp.notion.com/mcp" } } }"#,
        )
        .unwrap();
        write_cursor_plugin_mcp(
            home,
            "notion-workspace",
            r#"{ "notion": { "type": "http", "url": "https://mcp.notion.com/mcp" } }"#,
        );
        let endpoints = discover_mcp_endpoints(home);
        let notion_count = endpoints
            .iter()
            .filter(|e| e.server_name == "notion")
            .count();
        assert_eq!(notion_count, 1, "duplicate global+plugin server must dedup");
    }

    #[test]
    fn bare_fallback_ignores_non_server_top_level_objects() {
        // A global-style JSON object with unrelated top-level keys (the shape of
        // `~/.claude.json`) must NOT be misparsed as a flat server map.
        let raw = r#"{ "numStartups": 7, "installMethod": "brew", "tips": { "shown": true } }"#;
        assert!(parse_mcp_json_with_bare_fallback(raw).is_empty());
        // But a real bare server map IS parsed.
        let raw2 = r#"{ "notion": { "type": "http", "url": "https://mcp.notion.com/mcp" } }"#;
        let servers = parse_mcp_json_with_bare_fallback(raw2);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "notion");
    }

    // --- Follow-up #3: installed-but-empty agents get a minimal inventory -----

    #[test]
    fn installed_empty_agent_gets_minimal_inventory_uninstalled_skipped() {
        // Cursor is "installed" (its ~/.cursor root exists) but has no MCP
        // servers and no skills -> it still gets a minimal application-only
        // inventory. Claude Code has no footprint at all -> it stays skipped.
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".cursor")).unwrap();

        assert!(agent_installed_on_host(home, "cursor"));
        assert!(!agent_installed_on_host(home, "claude_code"));

        let inventories = build_agent_component_inventories(home);
        let cursor = inventories
            .iter()
            .find(|s| s.agent_type == "cursor")
            .expect("installed cursor gets a minimal inventory");
        assert_eq!(
            cursor.components.len(),
            1,
            "minimal inventory carries just the application root component",
        );
        assert!(
            !inventories.iter().any(|s| s.agent_type == "claude_code"),
            "an agent with no on-host footprint is still skipped",
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn claude_desktop_empty_config_yields_minimal_inventory() {
        // The exact user scenario: Claude Desktop is installed with an empty
        // `"mcpServers": {}` config and no skills. It must still yield a valid,
        // minimal inventory with just the application root component.
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        let dir = home.join("Library/Application Support/Claude");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("claude_desktop_config.json"),
            r#"{ "mcpServers": {} }"#,
        )
        .unwrap();

        assert!(agent_installed_on_host(home, "claude_desktop"));
        let inventories = build_agent_component_inventories(home);
        let desktop = inventories
            .iter()
            .find(|s| s.agent_type == "claude_desktop")
            .expect("installed claude_desktop gets a minimal inventory");
        assert!(
            !desktop.components.is_empty(),
            "minimal inventory carries at least the application root component",
        );
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
            "graph",
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
    fn inventory_projects_app_and_services() {
        let ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let inventories = build_agent_component_inventories_from_endpoints(&[ep]);
        assert_eq!(inventories.len(), 1);
        let inv = &inventories[0];
        assert_eq!(inv.agent_type, "cursor");
        // app + one service.
        assert_eq!(inv.components.len(), 2);
        assert!(inv
            .components
            .iter()
            .any(|c| c.component_type == "application"));
        assert!(inv.components.iter().any(|c| c.component_type == "service"));
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
    fn delegation_node_count_bounded_by_cap() {
        // A transcript (or a direct caller) that produces more spawn markers
        // than MAX_SPAWN_MARKERS must not grow the delegation tree without
        // limit: the node count saturates at the cap (+1 for the synthetic
        // root) and the children vec is bounded identically.
        let spawns: Vec<RawSpawn> = (0..(MAX_SPAWN_MARKERS + 50))
            .map(|i| RawSpawn {
                depth: 1,
                spawn_reason: None,
                goal_text: format!("distinct sub-agent goal number {i}"),
            })
            .collect();
        let tree = analyze_delegation("cursor", "host", &spawns);
        assert_eq!(
            tree.total_nodes,
            MAX_SPAWN_MARKERS as u32 + 1,
            "node count must saturate at MAX_SPAWN_MARKERS + root"
        );
        assert_eq!(
            tree.root.children.len(),
            MAX_SPAWN_MARKERS,
            "children vec must be bounded at MAX_SPAWN_MARKERS"
        );
    }

    #[test]
    fn sidechain_depth_cycle_guard_terminates() {
        // A malformed/adversarial transcript whose parentUuid links form a
        // cycle (a <- b <- a) must NOT hang the depth walk. The visited-set
        // cycle guard breaks the loop; extraction returns with a bounded,
        // finite depth.
        let transcript = concat!(
            r#"{"uuid":"a","parentUuid":"b","isSidechain":true,"type":"tool_use","name":"Task","input":{"subagent_type":"x","prompt":"cyclic spawn"}}"#,
            "\n",
            r#"{"uuid":"b","parentUuid":"a","isSidechain":true,"type":"text","text":"cyclic parent"}"#,
            "\n",
        );
        let spawns = extract_spawn_markers(transcript);
        assert!(!spawns.is_empty(), "the cyclic spawn is still extracted");
        assert!(
            spawns.iter().all(|s| s.depth <= 16),
            "cycle guard keeps depth bounded, got {:?}",
            spawns.iter().map(|s| s.depth).collect::<Vec<_>>()
        );
    }

    #[test]
    fn sidechain_depth_capped_at_16() {
        // A sidechain lineage deeper than the 16-level ceiling: a non-sidechain
        // root followed by 19 sidechain turns, the deepest of which spawns a
        // sub-agent. Raw depth would be 20 (1 + 19 sidechain ancestors); the
        // reconstructed depth must saturate at 16.
        let mut transcript = String::new();
        transcript.push_str(
            r#"{"uuid":"n0","parentUuid":null,"isSidechain":false,"type":"text","text":"root"}"#,
        );
        transcript.push('\n');
        for i in 1..=19 {
            if i == 19 {
                transcript.push_str(&format!(
                    r#"{{"uuid":"n{i}","parentUuid":"n{}","isSidechain":true,"type":"tool_use","name":"Task","input":{{"subagent_type":"deep","prompt":"deep spawn"}}}}"#,
                    i - 1
                ));
            } else {
                transcript.push_str(&format!(
                    r#"{{"uuid":"n{i}","parentUuid":"n{}","isSidechain":true,"type":"text","text":"turn"}}"#,
                    i - 1
                ));
            }
            transcript.push('\n');
        }
        let spawns = extract_spawn_markers(&transcript);
        assert_eq!(spawns.len(), 1, "exactly one Task spawn expected");
        assert_eq!(
            spawns[0].depth, 16,
            "depth must saturate at the 16-level ceiling"
        );
    }

    #[test]
    fn structured_spawns_bounded_by_cap() {
        // A compact-JSONL transcript with more spawn records than
        // MAX_SPAWN_MARKERS must not return an unbounded spawn list: the
        // structured extractor stops collecting at the cap. (The separate
        // MAX_TRANSCRIPT_RECORDS cap bounds the internal record/parent-linkage
        // graph used for depth reconstruction; the returned list is bounded by
        // MAX_SPAWN_MARKERS, which is the bound an upstream caller observes.)
        let mut transcript = String::with_capacity((MAX_SPAWN_MARKERS + 100) * 96);
        for i in 0..(MAX_SPAWN_MARKERS + 100) {
            transcript.push_str(&format!(
                r#"{{"uuid":"u{i}","parentUuid":null,"isSidechain":false,"type":"tool_use","name":"Task","input":{{"subagent_type":"x"}}}}"#,
            ));
            transcript.push('\n');
        }
        let spawns = extract_spawn_markers(&transcript);
        assert_eq!(
            spawns.len(),
            MAX_SPAWN_MARKERS,
            "returned spawn list must saturate at MAX_SPAWN_MARKERS"
        );
    }

    #[test]
    fn inventory_projects_tool_and_secret_components() {
        // A shell server wired to a secret env var yields, besides app +
        // service: a tool_capability component (Shell) and a secret_binding
        // component (the env key).
        let ep = endpoint_from_json(
            "cursor",
            "shellsrv",
            r#"{"command":"bash","args":["-c","mcp"],"env":{"OPENAI_API_KEY":"x"}}"#,
        );
        let inv = build_agent_component_inventories_from_endpoints(&[ep]).remove(0);

        let tool = inv
            .components
            .iter()
            .find(|c| {
                c.properties.get("edamame:kind").map(|k| k.as_str()) == Some("tool_capability")
            })
            .expect("tool_capability component present");
        assert_eq!(tool.name, "Shell");
        assert_eq!(tool.component_type, "data");

        let secret = inv
            .components
            .iter()
            .find(|c| {
                c.properties.get("edamame:kind").map(|k| k.as_str()) == Some("secret_binding")
            })
            .expect("secret_binding component present");
        // I5: the key name is captured, never the value.
        assert_eq!(secret.name, "OPENAI_API_KEY");
        assert!(secret.content_hash.is_none());
    }

    #[test]
    fn unknown_tool_class_is_not_projected() {
        // "fs"/"npx" classifies as Unknown -> no tool component, just app+service.
        let ep = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let inv = build_agent_component_inventories_from_endpoints(&[ep]).remove(0);
        assert!(!inv
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

    // -- Fix #4: per-(host, agent_type) instance id -------------------------

    #[test]
    fn inventory_instance_id_is_distinct_per_home() {
        let ep_a = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let ep_b = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let home_a = std::path::Path::new("/tmp/edamame-test-home-a");
        let home_b = std::path::Path::new("/tmp/edamame-test-home-b");

        let inv_a =
            build_agent_component_inventories_from_endpoints_with_home(&[ep_a], Some(home_a))
                .remove(0);
        let inv_b =
            build_agent_component_inventories_from_endpoints_with_home(&[ep_b], Some(home_b))
                .remove(0);

        // Same agent_type, two homes -> two DISTINCT instance ids, so the
        // Agents tab keys them separately instead of collapsing into one.
        assert_eq!(inv_a.agent_type, "cursor");
        assert_eq!(inv_b.agent_type, "cursor");
        assert_ne!(inv_a.agent_instance_id, inv_b.agent_instance_id);
        assert!(inv_a.agent_instance_id.ends_with("-observer"));

        // Endpoint-only callers (no home) fall back to agent_type as the id.
        let ep_c = endpoint_from_json("cursor", "fs", r#"{"command":"npx"}"#);
        let inv_c = build_agent_component_inventories_from_endpoints(&[ep_c]).remove(0);
        assert_eq!(inv_c.agent_instance_id, "cursor");
    }

    #[test]
    fn classify_rule_load_reads_always_apply_frontmatter() {
        let always = b"---\ndescription: x\nglobs:\nalwaysApply: true\n---\nbody";
        assert_eq!(classify_rule_load(always), "always");
        // alwaysApply true is case-insensitive on the value.
        let always_caps = b"---\nalwaysApply: TRUE\n---\nbody";
        assert_eq!(classify_rule_load(always_caps), "always");
        // Glob-scoped (auto-attached) rule -> conditional.
        let scoped = b"---\ndescription: x\nglobs: **/*.rs\nalwaysApply: false\n---\nbody";
        assert_eq!(classify_rule_load(scoped), "conditional");
        // Description-only (agent-requestable) rule -> conditional.
        let requestable = b"---\ndescription: only when relevant\n---\nbody";
        assert_eq!(classify_rule_load(requestable), "conditional");
        // No frontmatter at all -> conditional (do not inflate context tax).
        let bare = b"# just a heading\nsome prose";
        assert_eq!(classify_rule_load(bare), "conditional");
    }

    #[test]
    fn analyze_instruction_structure_scores_authoring_quality() {
        // Fully authored skill: frontmatter name + description + 3 headings.
        let full = b"---\nname: security-posture\ndescription: Assess posture\n---\n\
                     # Security posture\n\n## Usage\ntext\n\n## Notes\nmore";
        let s = analyze_instruction_structure(full);
        assert!(s.has_frontmatter);
        assert!(s.has_title);
        assert!(s.has_description);
        assert_eq!(s.heading_count, 3);
        assert_eq!(s.quality(), 100);

        // Thin stub: frontmatter present but no description and no headings.
        let thin = b"---\nname: stub\n---\njust one line of body";
        let s = analyze_instruction_structure(thin);
        assert!(s.has_frontmatter);
        assert!(s.has_title); // name supplies a title
        assert!(!s.has_description);
        assert_eq!(s.heading_count, 0);
        assert_eq!(s.quality(), 20); // title only

        // Body-only prose with an H1 and two more headings, no frontmatter.
        let prose = b"# Title\nintro\n## A\nx\n## B\ny";
        let s = analyze_instruction_structure(prose);
        assert!(!s.has_frontmatter);
        assert!(s.has_title); // body H1 counts as a title
        assert!(!s.has_description);
        assert_eq!(s.heading_count, 3);
        assert_eq!(s.quality(), 60); // title(20) + headings>=1(25) + >=3(15)

        // Fenced code block `#` lines must not inflate the heading count.
        let fenced = b"# Real\n```\n# not a heading\n## also not\n```\n## Real2";
        let s = analyze_instruction_structure(fenced);
        assert_eq!(s.heading_count, 2);

        // Empty body -> zero everything.
        let s = analyze_instruction_structure(b"");
        assert!(!s.has_frontmatter);
        assert_eq!(s.heading_count, 0);
        assert_eq!(s.quality(), 0);
    }

    #[test]
    fn classify_instruction_load_by_kind() {
        // Top-level instruction files and memories are always in context.
        assert_eq!(
            classify_instruction_load("instruction", b"anything"),
            "always"
        );
        assert_eq!(classify_instruction_load("memory", b"anything"), "always");
        // Progressive-disclosure artifacts are conditional regardless of body.
        assert_eq!(
            classify_instruction_load("skill", b"anything"),
            "conditional"
        );
        assert_eq!(
            classify_instruction_load("command", b"anything"),
            "conditional"
        );
        assert_eq!(
            classify_instruction_load("subagent", b"anything"),
            "conditional"
        );
        // Rules defer to frontmatter classification.
        assert_eq!(
            classify_instruction_load("rule", b"---\nalwaysApply: true\n---\n"),
            "always"
        );
    }

    #[test]
    fn extract_instruction_refs_picks_up_instruction_paths_only() {
        let body = br#"# Orchestrator skill

See the [code-update](../code-update/SKILL.md) skill and the
[divergence monitor](skills/divergence-monitor/SKILL.md).
Also load @rules/invariants.mdc before editing.
Read the full policy at https://example.com/docs/policy.md (web link, ignore).
Unrelated config.json mentioned in prose should be ignored.
Absolute ref: /Users/dev/.claude/skills/deploy/SKILL.md
"#;
        let refs = extract_instruction_refs(body);
        assert!(
            refs.iter().any(|r| r.ends_with("code-update/SKILL.md")),
            "relative skill ref missing: {refs:?}"
        );
        assert!(
            refs.contains(&"skills/divergence-monitor/SKILL.md".to_string()),
            "dir-segment skill ref missing: {refs:?}"
        );
        assert!(
            refs.contains(&"rules/invariants.mdc".to_string()),
            "@-prefixed rule ref missing: {refs:?}"
        );
        assert!(
            refs.iter()
                .any(|r| r.ends_with(".claude/skills/deploy/SKILL.md")),
            "absolute skill ref missing: {refs:?}"
        );
        // Web link and bare prose config.json are NOT instruction refs.
        assert!(
            !refs.iter().any(|r| r.contains("example.com")),
            "web link leaked as ref: {refs:?}"
        );
        assert!(
            !refs.iter().any(|r| r == "config.json"),
            "bare prose filename leaked as ref: {refs:?}"
        );
    }

    #[test]
    fn extract_instruction_refs_is_bounded_and_deduped() {
        let mut body = String::new();
        for i in 0..200 {
            body.push_str(&format!(
                "[x](skills/dup/SKILL.md) [y](skills/n{i}/SKILL.md)\n"
            ));
        }
        let refs = extract_instruction_refs(body.as_bytes());
        assert!(
            refs.len() <= MAX_INSTRUCTION_REFS,
            "unbounded: {}",
            refs.len()
        );
        // Deduped: the repeated `skills/dup/SKILL.md` appears at most once.
        assert_eq!(
            refs.iter().filter(|r| *r == "skills/dup/SKILL.md").count(),
            1
        );
    }

    /// Authoring-guide skills (skills that TEACH how to write skills / rules /
    /// hooks / subagents) are riddled with illustrative placeholders inside
    /// fenced code blocks, config-file mentions, directory-only paths, and bare
    /// top-level basenames dropped into prose. NONE of those are live
    /// dependencies and must NOT become reference edges -- otherwise the
    /// capability graph paints them as red "broken" nodes. This mirrors the real
    /// Cursor meta-skills (`create-subagent`, `migrate-to-skills`, `create-hook`,
    /// `update-cli-config`, `create-rule`, `onboard`, `create-skill`).
    #[test]
    fn extract_instruction_refs_suppresses_authoring_guide_phantoms() {
        let body = br#"# How to author things

## Subagent example
```bash
# For project-level
mkdir -p .cursor/agents
touch .cursor/agents/my-agent.md
```

## Rule migration
```markdown
# Before: .cursor/rules/my-rule.mdc
# After: .cursor/skills/commit/SKILL.md
```

The config lives at ~/.cursor/hooks.json and ~/.cursor/cli-config.json.
Projects layer overrides via .cursor/cli.json and settings.json files.
This rule is created when the user asks about .cursor/rules/ or AGENTS.md.
Skills are stored as skills/skill-name/ directories.
Ask about rules/preferences and team setup.

Real dependency: see @AGENTS.md and the [helper](skills/deploy/SKILL.md).
Also load @rules/invariants.mdc first.
"#;
        let refs = extract_instruction_refs(body);

        // --- Phantoms that MUST be suppressed ---
        for phantom in [
            "my-agent",    // fenced bash example
            "my-rule",     // fenced markdown example
            "commit",      // fenced markdown example
            "hooks",       // config file (.json)
            "cli-config",  // config file (.json)
            "cli",         // config file (.json)
            "settings",    // config file (.json)
            "skill-name",  // directory-only (trailing slash)
            "preferences", // file-dir (rules/) without a doc extension
        ] {
            assert!(
                !refs.iter().any(|r| ref_candidate_name(r) == phantom),
                "phantom edge '{phantom}' leaked as ref: {refs:?}"
            );
        }
        // A bare `AGENTS.md` in prose (no `@`, no path) must NOT be a ref, but
        // an explicit `@AGENTS.md` mention below MUST be. Assert both.
        assert!(
            refs.iter().any(|r| r == "AGENTS.md"),
            "explicit @AGENTS.md mention should be a ref: {refs:?}"
        );

        // --- Legit refs that MUST survive ---
        assert!(
            refs.contains(&"skills/deploy/SKILL.md".to_string()),
            "legit skill ref missing: {refs:?}"
        );
        assert!(
            refs.contains(&"rules/invariants.mdc".to_string()),
            "legit @-rule ref missing: {refs:?}"
        );
    }

    /// Code-heavy workspaces (e.g. a marketing/sales automation repo whose
    /// `.cursor/rules/*.mdc` describe a parallel `skills/<pkg>/` Python tree)
    /// mention their OWN codebase constantly: package-internal source files
    /// (`skills/foo/surface_registry.py`), config/data (`private/config/x.json`),
    /// and plain documentation (`docs/ARCHITECTURE.md`, `sub/README.md`). None of
    /// those are references to *another instruction artifact*, so none may become
    /// reference edges -- otherwise the capability graph paints a rule red for
    /// merely describing the code it operates on. This is the dominant residual
    /// phantom class after fenced-block / config / directory-only suppression.
    #[test]
    fn extract_instruction_refs_suppresses_codebase_phantoms() {
        let body = br#"# GTM rule

The single source of truth is `skills/partner_complement_outreach/surface_registry.py`
and its `skills/partner_complement_outreach/discover.py` entry point, plus the
package init at skills/partner_complement_outreach/__init__.py.
Config lives in private/config/customer_journey.json and settings.json.
Architecture notes: docs/ARCHITECTURE.md and the nested reference/api_reference.md.
See also docs/ONBOARDING.md and the top-level README.md write-up.

Real dependency: the [helper](skills/deploy/SKILL.md) skill and the bare package
skills/gtm-report and @rules/invariants.mdc.
"#;
        let refs = extract_instruction_refs(body);

        // --- Codebase phantoms that MUST be suppressed ---
        for phantom in [
            "surface_registry", // package-internal .py under skills/
            "discover",         // package-internal .py under skills/
            "__init__",         // package init .py under skills/
            "customer_journey", // config .json
            "settings",         // config .json
            "architecture",     // unanchored doc (docs/*.md)
            "api_reference",    // unanchored doc (nested */*.md)
            "onboarding",       // unanchored doc (docs/*.md)
            "readme",           // unanchored top-level doc
        ] {
            assert!(
                !refs.iter().any(|r| ref_candidate_name(r) == phantom),
                "codebase phantom '{phantom}' leaked as ref: {refs:?}"
            );
        }

        // --- Legit instruction refs that MUST survive ---
        assert!(
            refs.contains(&"skills/deploy/SKILL.md".to_string()),
            "doc under skills/ dropped: {refs:?}"
        );
        assert!(
            refs.iter().any(|r| ref_candidate_name(r) == "gtm-report"),
            "extension-less skill package folder dropped: {refs:?}"
        );
        assert!(
            refs.contains(&"rules/invariants.mdc".to_string()),
            "@-rule ref dropped: {refs:?}"
        );
    }

    /// Helper used above to derive the slug the reference graph resolves against,
    /// so the phantom assertions match how the core builds edge labels.
    fn ref_candidate_name(token: &str) -> String {
        let lower = token.trim().trim_matches('/').to_ascii_lowercase();
        let segs: Vec<&str> = lower.split('/').filter(|s| !s.is_empty()).collect();
        let basename = match segs.last() {
            Some(b) => *b,
            None => return String::new(),
        };
        if basename == "skill.md" {
            if segs.len() >= 2 {
                return segs[segs.len() - 2].to_string();
            }
            return String::new();
        }
        match basename.rsplit_once('.') {
            Some((stem, _ext)) if !stem.is_empty() => stem.to_string(),
            _ => basename.to_string(),
        }
    }

    #[test]
    fn instruction_components_carry_abspath_and_refs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let skill_dir = root.join(".claude").join("skills").join("orchestrator");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            b"# orchestrator\nUses [code-update](../code-update/SKILL.md).\n",
        )
        .unwrap();

        let comps = discover_workspace_instruction_components(root);
        let orch = comps
            .iter()
            .find(|c| c.name == "SKILL.md")
            .expect("skill component present");
        let abspath = orch
            .properties
            .get("edamame:abspath")
            .expect("abspath property present");
        assert!(
            std::path::Path::new(abspath).is_absolute(),
            "abspath not absolute: {abspath}"
        );
        let refs = orch
            .properties
            .get("edamame:refs")
            .expect("refs property present");
        assert!(
            refs.contains("code-update/SKILL.md"),
            "refs missing edge: {refs}"
        );
    }

    #[test]
    fn read_instruction_content_metadata_only_hides_body() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        let skill = home.join(".cursor").join("skills").join("demo");
        std::fs::create_dir_all(&skill).unwrap();
        let path = skill.join("SKILL.md");
        std::fs::write(&path, b"# demo\nsome body content\n").unwrap();

        let res = read_instruction_content(&path, home, "metadata_only");
        assert!(res.found, "should resolve: {:?}", res.error);
        assert_eq!(res.tier, "metadata_only");
        assert!(res.content.is_empty(), "body leaked at metadata-only tier");
        assert!(res.size_bytes > 0);
        assert!(!res.redacted);
    }

    #[test]
    fn read_instruction_content_redacts_secret_excerpt() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        let skill = home.join(".cursor").join("skills").join("deploy");
        std::fs::create_dir_all(&skill).unwrap();
        let path = skill.join("SKILL.md");
        std::fs::write(
            &path,
            b"# deploy\nexport API_KEY = sk-abcdef0123456789abcdef0123\nprose line stays\n",
        )
        .unwrap();

        let res = read_instruction_content(&path, home, "redacted_excerpt");
        assert!(res.found, "should resolve: {:?}", res.error);
        assert_eq!(res.tier, "redacted_excerpt");
        assert!(res.redacted, "secret not masked");
        assert!(res.redacted_lines >= 1);
        assert!(
            !res.content.contains("sk-abcdef0123456789abcdef0123"),
            "raw secret leaked: {}",
            res.content
        );
        assert!(res.content.contains("REDACTED"), "no redaction marker");
        assert!(res.content.contains("prose line stays"), "prose dropped");
    }

    #[test]
    fn read_instruction_content_forensic_returns_full_unredacted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        let skill = home.join(".cursor").join("skills").join("full");
        std::fs::create_dir_all(&skill).unwrap();
        let path = skill.join("SKILL.md");
        let body = "# full\nline one\nline two\n";
        std::fs::write(&path, body.as_bytes()).unwrap();

        let res = read_instruction_content(&path, home, "forensic_full_content");
        assert!(res.found, "should resolve: {:?}", res.error);
        assert_eq!(res.tier, "forensic_full_content");
        assert!(!res.redacted, "forensic tier must not redact");
        assert_eq!(res.content, body);
        assert!(!res.truncated);
    }

    #[test]
    fn read_instruction_content_refuses_non_instruction_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        // A plain file NOT under any instruction subdir and not a top-level
        // instruction file name.
        let path = home.join("notes.md");
        std::fs::write(&path, b"secret plans").unwrap();

        let res = read_instruction_content(&path, home, "forensic_full_content");
        assert!(!res.found, "arbitrary .md read must be refused");
        assert!(res.content.is_empty());
        assert!(res.error.is_some());
    }

    #[test]
    fn read_instruction_content_refuses_outside_home() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        // Instruction-shaped path, but living OUTSIDE the declared home.
        let other = tmp.path().join("elsewhere").join("skills").join("evil");
        std::fs::create_dir_all(&other).unwrap();
        let path = other.join("SKILL.md");
        std::fs::write(&path, b"# evil\nbody").unwrap();

        let res = read_instruction_content(&path, &home, "forensic_full_content");
        assert!(!res.found, "read outside home must be refused");
        assert!(res.error.as_deref().unwrap_or("").contains("home"));
    }

    #[test]
    fn read_instruction_content_unknown_tier_is_metadata_only() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        let skill = home.join(".cursor").join("skills").join("demo");
        std::fs::create_dir_all(&skill).unwrap();
        let path = skill.join("SKILL.md");
        std::fs::write(&path, b"# demo\nbody\n").unwrap();

        // A typo / unknown tier must collapse to the safest tier.
        let res = read_instruction_content(&path, home, "full_send_please");
        assert_eq!(res.tier, "metadata_only");
        assert!(res.content.is_empty());
    }

    // A skill bundles supporting files (builder scripts, fixtures, assets) that
    // the agent reads while running the skill. Those must be previewable in the
    // drill-down, not reported as "not found on disk". This is the deck_suite
    // regression: `.../skills/deck_suite/builders/*.py` was refused because `.py`
    // is not an INSTRUCTION_EXTS doc extension.
    #[test]
    fn read_instruction_content_allows_skill_support_script() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        let builders = home
            .join("proj")
            .join("skills")
            .join("deck_suite")
            .join("builders");
        std::fs::create_dir_all(&builders).unwrap();
        let path = builders.join("build_deck.py");
        let body = "#!/usr/bin/env python3\nprint('hi')\n";
        std::fs::write(&path, body.as_bytes()).unwrap();

        let res = read_instruction_content(&path, home, "forensic_full_content");
        assert!(
            res.found,
            "skill support .py must be readable: {:?}",
            res.error
        );
        assert_eq!(res.content, body);
    }

    // Cursor product skills live under `skills-cursor/`; support files there are
    // readable too (any extension, same rationale as `skills/`).
    #[test]
    fn read_instruction_content_allows_skills_cursor_support_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        let assets = home
            .join(".cursor")
            .join("skills-cursor")
            .join("canvas")
            .join("assets");
        std::fs::create_dir_all(&assets).unwrap();
        let path = assets.join("helper.sh");
        std::fs::write(&path, b"#!/bin/sh\necho ok\n").unwrap();

        let res = read_instruction_content(&path, home, "forensic_full_content");
        assert!(
            res.found,
            "skills-cursor support file must be readable: {:?}",
            res.error
        );
    }

    // The any-extension relaxation is SCOPED to skill folders. A non-doc file
    // under a doc-only instruction subdir (`rules/`) stays refused.
    #[test]
    fn read_instruction_content_refuses_non_doc_under_rules() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        let rules = home.join(".cursor").join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        let path = rules.join("exfil.py");
        std::fs::write(&path, b"# not a doc").unwrap();

        let res = read_instruction_content(&path, home, "forensic_full_content");
        assert!(!res.found, ".py under rules/ must stay refused");
        assert!(res.content.is_empty());
    }

    // A non-doc file at the home root (no instruction subdir ancestor) stays
    // refused regardless of the skill relaxation.
    #[test]
    fn read_instruction_content_refuses_non_doc_at_home_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();
        let path = home.join("secrets.py");
        std::fs::write(&path, b"TOKEN=deadbeef").unwrap();

        let res = read_instruction_content(&path, home, "forensic_full_content");
        assert!(!res.found, "arbitrary .py at home root must be refused");
    }

    // Defense in depth: a symlink UNDER a skills/ dir that points at a sensitive
    // in-home file (`~/.ssh/id_rsa`) passes guard 1 (raw path is skill-shaped)
    // and guard 2 (target is under home), but the post-canonicalize re-check
    // (guard 3) rejects it because the resolved path has no skill/instruction
    // ancestor. The any-extension relaxation must NOT open this hole.
    #[cfg(unix)]
    #[test]
    fn read_instruction_content_refuses_skill_symlink_escape() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();

        // Sensitive in-home target, NOT under any instruction dir.
        let ssh = home.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let secret = ssh.join("id_rsa");
        std::fs::write(&secret, b"-----BEGIN PRIVATE KEY-----\n").unwrap();

        // Symlink placed under a skills/ tree pointing at the secret.
        let skills = home.join(".claude").join("skills").join("evil");
        std::fs::create_dir_all(&skills).unwrap();
        let link = skills.join("stolen_key");
        symlink(&secret, &link).unwrap();

        let res = read_instruction_content(&link, home, "forensic_full_content");
        assert!(!res.found, "symlink escape out of skills/ must be refused");
        assert!(res.content.is_empty());
        assert!(
            res.error
                .as_deref()
                .unwrap_or("")
                .contains("resolved path is not a recognized instruction artifact"),
            "expected post-canonicalize refusal, got: {:?}",
            res.error
        );
    }

    #[test]
    fn agent_instruction_discovery_uses_real_config_dir_and_isolates_agents() {
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();

        // Cursor's user skill lives under ~/.cursor/skills, NOT the EDAMAME
        // plugin's `cursor-edamame` data dir.
        let cursor_skill = home.join(".cursor").join("skills").join("demo");
        std::fs::create_dir_all(&cursor_skill).unwrap();
        std::fs::write(cursor_skill.join("SKILL.md"), b"# cursor demo\n").unwrap();

        // Cursor product skills live under ~/.cursor/skills-cursor.
        let cursor_builtin = home.join(".cursor").join("skills-cursor").join("canvas");
        std::fs::create_dir_all(&cursor_builtin).unwrap();
        std::fs::write(cursor_builtin.join("SKILL.md"), b"# canvas\n").unwrap();

        // Claude Code's skill lives under ~/.claude/skills.
        let claude_skill = home.join(".claude").join("skills").join("agentfield");
        std::fs::create_dir_all(&claude_skill).unwrap();
        std::fs::write(claude_skill.join("SKILL.md"), b"# agentfield\n").unwrap();

        // A skill dropped into the OLD (buggy) plugin config dir must NOT be
        // attributed to the agent -- discovery no longer walks it.
        if let Some(plugin_dir) = supported_agents::find_supported_agent("cursor")
            .and_then(|d| d.resolve_config_dir_with_home(home))
        {
            let stray = plugin_dir.join("skills").join("stray");
            std::fs::create_dir_all(&stray).unwrap();
            std::fs::write(stray.join("SKILL.md"), b"# stray\n").unwrap();
        }

        let cursor_rels: Vec<String> = discover_agent_instruction_components(home, "cursor")
            .iter()
            .filter_map(|c| c.properties.get("edamame:relpath").cloned())
            .collect();
        assert!(
            cursor_rels.iter().any(|r| r == "skills/demo/SKILL.md"),
            "cursor user skill missing: {cursor_rels:?}"
        );
        assert!(
            cursor_rels
                .iter()
                .any(|r| r == "skills-cursor/canvas/SKILL.md"),
            "cursor product skill missing: {cursor_rels:?}"
        );
        // Proper association: cursor must NOT pick up Claude's skill ...
        assert!(
            !cursor_rels.iter().any(|r| r.contains("agentfield")),
            "claude skill leaked into cursor: {cursor_rels:?}"
        );
        // ... nor the stray file from the EDAMAME plugin data dir.
        assert!(
            !cursor_rels.iter().any(|r| r.contains("stray")),
            "plugin-dir stray leaked into cursor: {cursor_rels:?}"
        );

        let claude_rels: Vec<String> = discover_agent_instruction_components(home, "claude_code")
            .iter()
            .filter_map(|c| c.properties.get("edamame:relpath").cloned())
            .collect();
        assert!(
            claude_rels
                .iter()
                .any(|r| r == "skills/agentfield/SKILL.md"),
            "claude skill missing: {claude_rels:?}"
        );
        assert!(
            !claude_rels.iter().any(|r| r.contains("demo")),
            "cursor skill leaked into claude: {claude_rels:?}"
        );
    }

    // Regression: agent skill managers (agentfield, the EDAMAME plugins, ...)
    // install skills/commands as SYMLINKS into an external `.../current` store.
    // `DirEntry::file_type()` does not follow symlinks, so the pre-fix walk
    // reported symlink-to-dir / symlink-to-file as neither and silently skipped
    // the entire subtree -- the canonical "skill wrongly marked not on disk"
    // cause. Discovery must follow the link. A DANGLING symlink (unmounted
    // drive / deleted target) must still be excluded.
    #[cfg(unix)]
    #[test]
    fn agent_instruction_discovery_follows_symlinked_skills_and_drops_dangling() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path();

        // External store the way agentfield lays it out:
        //   ~/.agentfield/skills/agentfield/current/{SKILL.md,commands/agentfield.md}
        let store = home
            .join(".agentfield")
            .join("skills")
            .join("agentfield")
            .join("current");
        std::fs::create_dir_all(store.join("commands")).unwrap();
        std::fs::write(store.join("SKILL.md"), b"# agentfield\n").unwrap();
        std::fs::write(store.join("commands").join("agentfield.md"), b"# cmd\n").unwrap();

        // ~/.claude/skills/agentfield -> external current dir (symlinked dir)
        let claude_skills = home.join(".claude").join("skills");
        std::fs::create_dir_all(&claude_skills).unwrap();
        symlink(&store, claude_skills.join("agentfield")).unwrap();

        // ~/.claude/commands/agentfield.md -> external file (symlinked file)
        let claude_commands = home.join(".claude").join("commands");
        std::fs::create_dir_all(&claude_commands).unwrap();
        symlink(
            store.join("commands").join("agentfield.md"),
            claude_commands.join("agentfield.md"),
        )
        .unwrap();

        // Dangling symlinks (target missing -- unmounted drive / deleted skill).
        let missing_dir = home.join("unmounted_drive").join("skills").join("ghost");
        let missing_file = home.join("unmounted_drive").join("ghost.md");
        symlink(&missing_dir, claude_skills.join("ghost")).unwrap();
        symlink(&missing_file, claude_commands.join("ghost.md")).unwrap();

        let rels: Vec<String> = discover_agent_instruction_components(home, "claude_code")
            .iter()
            .filter_map(|c| c.properties.get("edamame:relpath").cloned())
            .collect();

        // Symlinked skill dir is traversed through the link.
        assert!(
            rels.iter().any(|r| r == "skills/agentfield/SKILL.md"),
            "symlinked skill dir not discovered: {rels:?}"
        );
        // Symlinked command file is discovered through the link.
        assert!(
            rels.iter().any(|r| r == "commands/agentfield.md"),
            "symlinked command file not discovered: {rels:?}"
        );
        // Dangling symlinks are excluded (the artifact is not actually present).
        assert!(
            !rels.iter().any(|r| r.contains("ghost")),
            "dangling symlink surfaced as present: {rels:?}"
        );
    }

    // Observed-path existence filter: only paths CONFIRMED absent (NotFound) are
    // returned. Present files -- including those reached through a symlink -- are
    // kept (omitted from the absent set). This backs the augmentation builder's
    // pruning of stale observed-skill "rescues" (unmounted drive / deleted
    // skill) without ever dropping a legitimately-present skill.
    #[test]
    fn confirm_absent_instruction_paths_reports_only_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let present = tmp.path().join("present_skill.md");
        std::fs::write(&present, b"# skill\n").unwrap();
        let missing = tmp.path().join("unmounted").join("ghost_skill.md");

        let present_s = present.to_string_lossy().to_string();
        let missing_s = missing.to_string_lossy().to_string();
        let absent = confirm_absent_instruction_paths(&[
            present_s.clone(),
            missing_s.clone(),
            String::new(),
        ]);

        assert!(
            absent.contains(&missing_s),
            "missing path not reported absent: {absent:?}"
        );
        assert!(
            !absent.contains(&present_s),
            "present path wrongly reported absent: {absent:?}"
        );
        // Empty string is ignored, never reported as absent.
        assert!(
            !absent.iter().any(|p| p.is_empty()),
            "empty path leaked into absent set: {absent:?}"
        );
    }

    // A symlink to an existing target must be treated as present (metadata
    // follows the link); a dangling symlink must be reported absent.
    #[cfg(unix)]
    #[test]
    fn confirm_absent_instruction_paths_follows_symlinks() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("real_skill.md");
        std::fs::write(&target, b"# skill\n").unwrap();

        let good_link = tmp.path().join("good_link.md");
        symlink(&target, &good_link).unwrap();
        let dangling = tmp.path().join("dangling_link.md");
        symlink(tmp.path().join("gone.md"), &dangling).unwrap();

        let good_s = good_link.to_string_lossy().to_string();
        let dangling_s = dangling.to_string_lossy().to_string();
        let absent = confirm_absent_instruction_paths(&[good_s.clone(), dangling_s.clone()]);

        assert!(
            !absent.contains(&good_s),
            "valid symlink reported absent: {absent:?}"
        );
        assert!(
            absent.contains(&dangling_s),
            "dangling symlink not reported absent: {absent:?}"
        );
    }

    /// Host-dependent broad audit: run the REAL instruction discovery against
    /// EVERY supported agent that is actually installed on this machine and
    /// cross-check it two independent ways, per agent:
    ///
    ///   * PHANTOM: every discovered component's absolute path must still exist
    ///     on disk right now (`fs::metadata`, which follows symlinks). A
    ///     discovered artifact that is not on disk is a phantom.
    ///   * MISS: an independent symlink-following walk of the same config root
    ///     (top-level instruction files + the `INSTRUCTION_SUBDIRS` allowlist,
    ///     `INSTRUCTION_EXTS`, depth <= 4) must not surface any readable,
    ///     <=2 MB artifact that discovery failed to return. Files above the
    ///     2 MB body cap or an agent whose candidate set exceeds the
    ///     `INSTRUCTION_MAX_FILES` cap are excluded from the miss assertion
    ///     (discovery legitimately drops / truncates those), and reported instead.
    ///
    /// Ignored by default because it reads the developer's own agent dirs; run
    /// explicitly on a host to audit the live fleet:
    ///   cargo test -p edamame_foundation --lib \
    ///     local_host_all_agents_discovery_consistency -- --ignored --nocapture
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    #[ignore = "host-dependent: reads the developer's real agent config dirs"]
    fn local_host_all_agents_discovery_consistency() {
        const MAX_FILES: usize = INSTRUCTION_MAX_FILES;
        const MAX_DEPTH: usize = INSTRUCTION_MAX_DEPTH;
        const MAX_FILE_BYTES: u64 = INSTRUCTION_MAX_FILE_BYTES;

        let home = match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            Some(h) => PathBuf::from(h),
            None => {
                eprintln!("[audit] no HOME/USERPROFILE; skipping");
                return;
            }
        };

        // Independent, symlink-following reproduction of discovery's traversal.
        // Reuses the module's own consts/helpers so it tracks the real rules,
        // but walks the tree independently of `discover_agent_instruction_components`.
        fn independent_walk(config_dir: &Path) -> Vec<PathBuf> {
            let mut found: Vec<PathBuf> = Vec::new();
            if let Ok(entries) = std::fs::read_dir(config_dir) {
                for entry in entries.flatten() {
                    if found.len() >= MAX_FILES {
                        break;
                    }
                    let path = entry.path();
                    let (_d, is_file) = entry_kind_following_symlinks(&entry, &path);
                    if !is_file {
                        continue;
                    }
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if classify_toplevel_instruction(name).is_some() {
                            found.push(path);
                        }
                    }
                }
            }
            for (subdir, _kind) in INSTRUCTION_SUBDIRS {
                let root = config_dir.join(subdir);
                if !root.is_dir() {
                    continue;
                }
                let mut stack: Vec<(PathBuf, usize)> = vec![(root, 0)];
                while let Some((dir, depth)) = stack.pop() {
                    if found.len() >= MAX_FILES {
                        break;
                    }
                    let entries = match std::fs::read_dir(&dir) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    for entry in entries.flatten() {
                        if found.len() >= MAX_FILES {
                            break;
                        }
                        let path = entry.path();
                        // Mirror discovery: skip hidden files/dirs.
                        if path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| n.starts_with('.'))
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        let (is_dir, is_file) = entry_kind_following_symlinks(&entry, &path);
                        if is_dir {
                            if depth + 1 <= MAX_DEPTH {
                                stack.push((path, depth + 1));
                            }
                        } else if is_file {
                            // Mirror discovery: Markdown instruction docs only.
                            let ext_ok = path
                                .extension()
                                .and_then(|e| e.to_str())
                                .map(|e| {
                                    INSTRUCTION_DOC_EXTS
                                        .iter()
                                        .any(|x| x.eq_ignore_ascii_case(e))
                                })
                                .unwrap_or(false);
                            if ext_ok {
                                found.push(path);
                            }
                        }
                    }
                }
            }
            found.sort();
            found.dedup();
            found
        }

        let mut total_present = 0usize;
        let mut total_discovered = 0usize;
        let mut total_phantoms: Vec<String> = Vec::new();
        let mut total_misses: Vec<String> = Vec::new();
        let mut capped_agents: Vec<String> = Vec::new();

        eprintln!("\n[audit] local-host agent discovery consistency (home={home:?})");
        eprintln!(
            "[audit] {:<16} {:>10} {:>7} {:>8}  root",
            "agent", "discovered", "phantom", "miss"
        );

        for def in supported_agents::ordered_supported_agents() {
            let root = match def.resolve_instruction_root_with_home(&home) {
                Some(r) => r,
                None => continue,
            };
            if !root.is_dir() {
                continue; // agent not installed on this host
            }
            total_present += 1;

            // REAL, freshly-compiled discovery under test.
            let comps = discover_agent_instruction_components(&home, &def.agent_type);
            let discovered: BTreeSet<String> = comps
                .iter()
                .filter_map(|c| c.properties.get("edamame:abspath").cloned())
                .collect();
            total_discovered += discovered.len();

            // PHANTOM: discovered but not present on disk (follows symlinks).
            let mut agent_phantoms: Vec<String> = Vec::new();
            for p in &discovered {
                if std::fs::metadata(Path::new(p)).is_err() {
                    agent_phantoms.push(p.clone());
                }
            }

            // MISS: independent walk finds a readable <=2MB artifact discovery dropped.
            let candidates = independent_walk(&root);
            let capped = candidates.len() >= MAX_FILES;
            let mut agent_misses: Vec<String> = Vec::new();
            if capped {
                capped_agents.push(def.agent_type.clone());
            } else {
                for c in &candidates {
                    let cs = c.to_string_lossy().to_string();
                    if discovered.contains(&cs) {
                        continue;
                    }
                    // Excluded-by-design: >2 MB body cap or unreadable.
                    match std::fs::metadata(c) {
                        Ok(m) if m.is_file() && m.len() <= MAX_FILE_BYTES => {
                            if std::fs::read(c).is_ok() {
                                agent_misses.push(cs);
                            }
                        }
                        _ => {}
                    }
                }
            }

            eprintln!(
                "[audit] {:<16} {:>10} {:>7} {:>8}{}  {}",
                def.agent_type,
                discovered.len(),
                agent_phantoms.len(),
                agent_misses.len(),
                if capped { " (capped)" } else { "" },
                root.display()
            );
            for p in &agent_phantoms {
                eprintln!("[audit]     PHANTOM {p}");
            }
            for m in &agent_misses {
                eprintln!("[audit]     MISS    {m}");
            }
            total_phantoms.extend(agent_phantoms);
            total_misses.extend(agent_misses);
        }

        eprintln!(
            "[audit] SUMMARY present={total_present} discovered={total_discovered} \
             phantoms={} misses={} capped_agents={:?}",
            total_phantoms.len(),
            total_misses.len(),
            capped_agents
        );

        assert!(
            total_phantoms.is_empty(),
            "discovery returned {} phantom artifact(s) not on disk: {:#?}",
            total_phantoms.len(),
            total_phantoms
        );
        assert!(
            total_misses.is_empty(),
            "discovery missed {} on-disk instruction artifact(s): {:#?}",
            total_misses.len(),
            total_misses
        );
    }

    #[test]
    fn discover_workspace_instruction_components_walks_project_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        // Top-level instruction file (always).
        std::fs::write(root.join("AGENTS.md"), b"# agents guide\n").unwrap();

        // .cursor/rules with one always-applied and one glob-scoped rule.
        let rules = root.join(".cursor").join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(
            rules.join("always.mdc"),
            b"---\nalwaysApply: true\n---\nalways on",
        )
        .unwrap();
        std::fs::write(
            rules.join("scoped.mdc"),
            b"---\nglobs: **/*.rs\nalwaysApply: false\n---\nscoped",
        )
        .unwrap();

        // .claude/skills with a SKILL.md (conditional).
        let skill_dir = root.join(".claude").join("skills").join("demo");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), b"# demo skill\nbody").unwrap();

        // Workspace-root skills library (SIFU / first-party layout). Must be
        // indexed so rules that reference `skills/burn_rate/SKILL.md` resolve.
        let root_skill = root.join("skills").join("burn_rate");
        std::fs::create_dir_all(&root_skill).unwrap();
        std::fs::write(root_skill.join("SKILL.md"), b"# burn rate\nbody").unwrap();
        // Non-doc sidecar under the package must NOT become its own skill row.
        std::fs::write(root_skill.join("analyze.py"), b"print('hi')\n").unwrap();

        // A transcript-store-looking dir MUST NOT be walked.
        let projects = root.join(".claude").join("projects");
        std::fs::create_dir_all(&projects).unwrap();
        std::fs::write(projects.join("session.jsonl"), b"{\"noise\":true}\n").unwrap();

        let comps = discover_workspace_instruction_components(root);

        // AGENTS.md + 2 rules + .claude skill + root skills/burn_rate == 5;
        // none from projects/ and none from analyze.py.
        assert_eq!(comps.len(), 5, "components: {comps:#?}");
        assert!(comps
            .iter()
            .all(|c| c.properties.get("edamame:scope").map(String::as_str) == Some("workspace")));
        assert!(comps
            .iter()
            .all(|c| c.properties.contains_key("edamame:size_bytes")));
        assert!(
            comps.iter().all(|c| c.name != "analyze.py"),
            "non-doc sidecar leaked into inventory: {comps:#?}"
        );

        let by_name = |n: &str| comps.iter().find(|c| c.name == n).unwrap();
        assert_eq!(
            by_name("AGENTS.md").properties.get("edamame:load"),
            Some(&"always".to_string())
        );
        assert_eq!(
            by_name("always.mdc").properties.get("edamame:load"),
            Some(&"always".to_string())
        );
        assert_eq!(
            by_name("scoped.mdc").properties.get("edamame:load"),
            Some(&"conditional".to_string())
        );
        // Two SKILL.md files (`.claude/skills/demo` + `skills/burn_rate`).
        let skill_md_count = comps.iter().filter(|c| c.name == "SKILL.md").count();
        assert_eq!(skill_md_count, 2, "components: {comps:#?}");
        assert!(comps.iter().any(|c| {
            c.name == "SKILL.md"
                && c.properties
                    .get("edamame:relpath")
                    .map(|p| p.contains("skills/burn_rate"))
                    .unwrap_or(false)
        }));
        // The workspace label is the project dir name on every component.
        let ws = root.file_name().unwrap().to_string_lossy().to_string();
        assert!(comps
            .iter()
            .all(|c| c.properties.get("edamame:workspace") == Some(&ws)));
    }

    #[test]
    fn project_slug_extracted_for_cursor_and_claude() {
        assert_eq!(
            project_slug_from_source_path(
                "/Users/x/.cursor/projects/Users-x-Programming-foo/agent-transcripts/abc.jsonl"
            )
            .as_deref(),
            Some("Users-x-Programming-foo")
        );
        assert_eq!(
            project_slug_from_source_path("/Users/x/.claude/projects/-Users-x-foo/abc.jsonl")
                .as_deref(),
            Some("-Users-x-foo")
        );
        // No `projects` component -> no slug.
        assert_eq!(
            project_slug_from_source_path("/Users/x/.codex/history/abc.jsonl"),
            None
        );
    }

    #[test]
    fn resolve_slug_disambiguates_underscores_and_dashes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("Programming").join("edamame_core")).unwrap();
        std::fs::create_dir_all(root.join("my-repo")).unwrap();

        // Underscore encoded as '-' in the slug is recovered via is_dir().
        assert_eq!(
            resolve_slug_under(root, "Programming-edamame-core"),
            Some(root.join("Programming").join("edamame_core"))
        );
        // A literal dash resolves too.
        assert_eq!(
            resolve_slug_under(root, "my-repo"),
            Some(root.join("my-repo"))
        );
        assert_eq!(resolve_slug_under(root, "does-not-exist"), None);
    }

    #[test]
    fn resolve_slug_handles_arbitrary_separator_characters() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        // Localized Google Drive mount shape: spaces, parentheses, '@', '.',
        // plus a non-breaking space -- all of which the slug encoder collapses
        // to '-'. The stat-probe arm cannot reconstruct these; the directory
        // scan must.
        let drive = root.join("Mon\u{a0}Drive (frank@lyonnet.org)");
        std::fs::create_dir_all(drive.join("jarvis")).unwrap();
        assert_eq!(
            resolve_slug_under(root, "Mon-Drive-frank-lyonnet-org-jarvis"),
            Some(drive.join("jarvis"))
        );
        // A partial-token mismatch must not match.
        assert_eq!(
            resolve_slug_under(root, "Mon-Drive-frank-lyonnet-com-jarvis"),
            None
        );
    }

    #[test]
    fn resolve_slug_prefers_longest_existing_segment() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("edamame")).unwrap();
        std::fs::create_dir_all(root.join("edamame_core")).unwrap();
        assert_eq!(
            resolve_slug_under(root, "edamame-core"),
            Some(root.join("edamame_core"))
        );
    }

    #[test]
    fn collect_workspace_inventories_dedupes_and_skips_unresolvable() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        // A real workspace with a top-level AGENTS.md.
        let ws = root.join("Programming").join("edamame_core");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("AGENTS.md"), b"# guide\n").unwrap();

        // Build two Cursor-style source paths that decode to the SAME workspace
        // (different transcript uuids) plus one that cannot resolve. The public
        // collector resolves under the real FS root '/', so the slug it consumes
        // is the full absolute path (leading '/' dropped, separators -> '-').
        let base_slug = ws
            .strip_prefix(std::path::Path::new(std::path::MAIN_SEPARATOR_STR))
            .unwrap_or(&ws)
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "-")
            .replace('_', "-");
        let sp1 = format!("/home/.cursor/projects/{base_slug}/agent-transcripts/a.jsonl");
        let sp2 = format!("/home/.cursor/projects/{base_slug}/agent-transcripts/b.jsonl");
        let sp3 = "/home/.cursor/projects/totally-missing-xyz/agent-transcripts/c.jsonl";

        // resolve_slug_under walks the slug tokens relative to its base_root, so
        // drive determinism against the tempdir with the slug *relative to root*
        // (the full path prefix `var-folders-...` does not exist under `root`).
        let rel_slug = ws
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "-")
            .replace('_', "-");
        assert_eq!(
            resolve_slug_under(root, &rel_slug),
            Some(ws.clone()),
            "sanity: slug decodes to the workspace"
        );

        // The public collector resolves under the real FS root, so with a
        // tempdir path it will return empty; assert it never panics and skips
        // the unresolvable path.
        let inv = collect_workspace_inventories(&[sp1.clone(), sp2.clone(), sp3.to_string()]);
        // Under the real root these tempdir slugs won't resolve; the contract
        // we assert here is bounded, panic-free, de-duplicated behavior.
        assert!(
            inv.len() <= 1,
            "at most one distinct root, got {}",
            inv.len()
        );
    }

    #[test]
    fn workspace_slug_for_session_prefers_source_path_over_hint() {
        // A Cursor-style transcript already carries the workspace in its
        // `projects/<slug>` segment; the cwd hint must never override it.
        let slug = workspace_slug_for_session(
            "/home/.cursor/projects/-Users-me-proj/agent-transcripts/a.jsonl",
            "/some/other/dir",
        );
        assert_eq!(slug.as_deref(), Some("-Users-me-proj"));
    }

    #[test]
    fn workspace_slug_for_session_falls_back_to_cwd_hint() {
        // A Codex rollout path lives under ~/.codex/sessions/ with no
        // `projects/<slug>` segment; the recorded cwd is the only workspace
        // signal, so the slug is derived from it (pure string work, no FS).
        let slug = workspace_slug_for_session(
            "/home/me/.codex/sessions/2026/07/16/rollout-abc.jsonl",
            "/Users/me/work/edamame_core",
        );
        assert_eq!(slug.as_deref(), Some("-Users-me-work-edamame_core"));
    }

    #[test]
    fn workspace_slug_for_session_none_without_any_signal() {
        // No project segment AND no cwd hint (a bare chat session) -> unresolved.
        let slug =
            workspace_slug_for_session("/home/me/.codex/sessions/2026/07/16/rollout-abc.jsonl", "");
        assert_eq!(slug, None);
    }

    #[test]
    fn collect_workspace_inventories_resolves_cwd_hint_when_source_path_has_no_project() {
        // Codex writes rollout transcripts outside any `projects/<slug>` tree but
        // records the real cwd. The tab-encoded `"<source_path>\t<cwd>"` entry
        // must resolve to that cwd as the workspace root and scan its
        // instruction inventory -- deterministic because the hint path is used
        // directly (is_dir), not decoded under the real FS root.
        let tmp = tempfile::TempDir::new().unwrap();
        let ws = tmp.path().join("edamame_core");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("AGENTS.md"), b"# guide\n").unwrap();

        let codex_sp = "/home/me/.codex/sessions/2026/07/16/rollout-abc.jsonl";
        let entry = format!("{}\t{}", codex_sp, ws.to_string_lossy());

        // Bare (no hint) resolves nothing under the real root -> empty; the
        // tab-encoded hint entry resolves the real tempdir workspace.
        assert!(collect_workspace_inventories(&[codex_sp.to_string()]).is_empty());

        let inv = collect_workspace_inventories(&[entry]);
        assert_eq!(inv.len(), 1, "cwd hint should resolve one workspace root");
        assert_eq!(inv[0].root, ws.to_string_lossy());
        assert_eq!(inv[0].slug, slug_from_workspace_dir(&ws.to_string_lossy()));
        assert!(
            inv[0].components.iter().any(|c| c.name == "AGENTS.md"),
            "expected the cwd workspace's AGENTS.md to be discovered, got {:?}",
            inv[0]
                .components
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
        );
    }
}
