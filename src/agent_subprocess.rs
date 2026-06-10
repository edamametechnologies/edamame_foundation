//! Agent critical-subprocess usage (read-only, derived, LLM-free).
//!
//! Reveals when a discovered AI agent (cursor, claude_code, claude_desktop,
//! openclaw, codex, hermes, ...) is or has been spawning *critical
//! subprocesses* -- `ssh`, `scp`, `nc`, raw shells, interpreters, package
//! managers, container CLIs, etc. The signal is built purely from the L7
//! process-lineage already carried by captured network sessions (and,
//! optionally, FIM events): no LLM, no new privileged collection.
//!
//! Attribution is structural and best-effort: a subprocess is attributed to an
//! agent when any node of its process lineage (process / parent / grandparent
//! path, argv, or script path) matches a known agent identity needle. The raw
//! lineage is preserved in each observation so an operator can verify the
//! attribution.
//!
//! Invariants (mirror `agent_visibility.rs` / `agent_owasp.rs`):
//! - **I3 Deterministic-first**: classification and attribution are pure
//!   functions of the lineage strings. No LLM is consulted.
//! - **Reveal, not alert**: this is a visibility surface. Findings are capped at
//!   `Medium` severity so a normal developer `ssh`/`git` spawned by an agent is
//!   *visible* but never by itself trips a CI gate / score. The real
//!   attack-pattern detector (token_exfiltration / sandbox_exploitation) still
//!   owns the corroborated HIGH/CRITICAL alerting path.
//! - OWASP tags are metadata only -- attached for the crosswalk scorecard, they
//!   never change a finding's severity or the alertable gate.
//! - Pure: no I/O, no clock except `generated_at` via `chrono::Utc::now()`.

use crate::agent_visibility::{VisibilityFinding, VisibilitySeverity};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Criticality
// ---------------------------------------------------------------------------

/// Inherent risk of a subprocess binary, independent of the (capped) finding
/// severity. Drives the badge shown on the Agents tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SubprocessCriticality {
    /// Expected dev tooling (git, npm, cargo, docker) -- informative.
    Routine,
    /// Shells, interpreters, HTTP fetchers -- broad capability.
    Elevated,
    /// Remote-access / raw-network binaries (ssh, scp, nc, socat) -- the
    /// canonical "agent reaching off-box / opening a shell" shape.
    Critical,
}

impl SubprocessCriticality {
    pub fn as_str(&self) -> &'static str {
        match self {
            SubprocessCriticality::Routine => "routine",
            SubprocessCriticality::Elevated => "elevated",
            SubprocessCriticality::Critical => "critical",
        }
    }

    fn rank(&self) -> u8 {
        match self {
            SubprocessCriticality::Critical => 3,
            SubprocessCriticality::Elevated => 2,
            SubprocessCriticality::Routine => 1,
        }
    }

    /// Visibility-finding severity for this criticality. Capped at `Medium` so
    /// subprocess usage is a reveal surface, never a standalone alert source.
    fn finding_severity(&self) -> VisibilitySeverity {
        match self {
            SubprocessCriticality::Critical => VisibilitySeverity::Medium,
            SubprocessCriticality::Elevated => VisibilitySeverity::Low,
            SubprocessCriticality::Routine => VisibilitySeverity::Info,
        }
    }
}

// ---------------------------------------------------------------------------
// Static catalog of critical subprocess binaries
// ---------------------------------------------------------------------------

/// One catalog entry: the binary basenames it matches, a category slug, the
/// inherent criticality, and the OWASP GenAI crosswalk tags.
pub struct CriticalSubprocessClass {
    pub names: &'static [&'static str],
    pub category: &'static str,
    pub criticality: SubprocessCriticality,
    pub owasp_refs: &'static str,
}

use SubprocessCriticality::{Critical, Elevated, Routine};

/// Critical-subprocess catalog. Names are matched case-insensitively against
/// the basename of the subprocess (with a trailing `.exe` stripped on Windows).
const CRITICAL_SUBPROCESS_CATALOG: &[CriticalSubprocessClass] = &[
    // Remote access / data movement off the host.
    CriticalSubprocessClass {
        names: &["ssh", "scp", "sftp", "rsync", "telnet"],
        category: "remote_access",
        criticality: Critical,
        owasp_refs: "OWASP-ASI02,OWASP-ASI05,OWASP-LLM06",
    },
    // Raw network / reverse-shell capable.
    CriticalSubprocessClass {
        names: &["nc", "ncat", "netcat", "socat"],
        category: "raw_network",
        criticality: Critical,
        owasp_refs: "OWASP-ASI02,OWASP-ASI05,OWASP-LLM06",
    },
    // HTTP(S) fetchers -- download/exfil capable.
    CriticalSubprocessClass {
        names: &["curl", "wget"],
        category: "http_fetch",
        criticality: Elevated,
        owasp_refs: "OWASP-ASI02,OWASP-LLM06",
    },
    // Shells.
    CriticalSubprocessClass {
        names: &[
            "bash",
            "sh",
            "zsh",
            "fish",
            "dash",
            "ksh",
            "pwsh",
            "powershell",
            "cmd",
        ],
        category: "shell",
        criticality: Elevated,
        owasp_refs: "OWASP-ASI05,OWASP-LLM06",
    },
    // Interpreters.
    CriticalSubprocessClass {
        names: &[
            "python",
            "python3",
            "node",
            "deno",
            "bun",
            "ruby",
            "perl",
            "php",
            "osascript",
        ],
        category: "interpreter",
        criticality: Elevated,
        owasp_refs: "OWASP-ASI05,OWASP-LLM06",
    },
    // Version control -- can push code / secrets off-box.
    CriticalSubprocessClass {
        names: &["git", "gh"],
        category: "vcs",
        criticality: Routine,
        owasp_refs: "OWASP-ASI02,OWASP-LLM06",
    },
    // Package managers -- supply-chain surface.
    CriticalSubprocessClass {
        names: &[
            "pip", "pip3", "npm", "npx", "pnpm", "yarn", "cargo", "gem", "brew", "apt", "apt-get",
            "uv", "poetry",
        ],
        category: "package_manager",
        criticality: Routine,
        owasp_refs: "OWASP-ASI04,OWASP-LLM03",
    },
    // Container / orchestration CLIs -- privilege & RCE surface.
    CriticalSubprocessClass {
        names: &["docker", "podman", "kubectl", "nerdctl"],
        category: "container",
        criticality: Critical,
        owasp_refs: "OWASP-ASI03,OWASP-ASI05,OWASP-LLM06",
    },
];

/// Normalize a process name to a lowercase basename with a trailing `.exe`
/// stripped (Windows). `"/usr/bin/SSH"` and `"ssh.exe"` both become `"ssh"`.
pub fn normalize_process_basename(raw: &str) -> String {
    let trimmed = raw.trim();
    // Basename across both path separators.
    let base = trimmed
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(trimmed);
    let lower = base.to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .map(|s| s.to_string())
        .unwrap_or(lower)
}

/// Classify a subprocess by name. Returns the catalog entry when the (basename,
/// case-insensitive) name is a known critical subprocess, else `None`.
pub fn classify_subprocess(process_name: &str) -> Option<&'static CriticalSubprocessClass> {
    let base = normalize_process_basename(process_name);
    if base.is_empty() {
        return None;
    }
    CRITICAL_SUBPROCESS_CATALOG
        .iter()
        .find(|c| c.names.iter().any(|n| *n == base))
}

// ---------------------------------------------------------------------------
// Agent attribution
// ---------------------------------------------------------------------------

/// Best-effort agent identity needles, checked in order (first match wins).
/// More specific markers come before generic ones so `claude_desktop` is not
/// shadowed by `claude_code`'s `.claude` directory marker. Matched against a
/// pre-lowercased combined lineage identity string.
const AGENT_IDENTITY_NEEDLES: &[(&str, &str)] = &[
    // Claude Desktop (Electron app) -- before claude_code's ".claude".
    ("claude_desktop", "claude_desktop"),
    ("claude desktop", "claude_desktop"),
    ("claude.app", "claude_desktop"),
    ("anthropic.claude", "claude_desktop"),
    // Claude Code (CLI).
    ("claude-code", "claude_code"),
    ("claude_code", "claude_code"),
    ("claudecode", "claude_code"),
    ("@anthropic-ai/claude-code", "claude_code"),
    (".claude/", "claude_code"),
    ("/.claude", "claude_code"),
    // Cursor.
    ("cursor_edamame", "cursor"),
    (".cursor", "cursor"),
    ("cursor.app", "cursor"),
    ("/cursor", "cursor"),
    ("cursor-", "cursor"),
    // OpenClaw.
    ("openclaw", "openclaw"),
    (".openclaw", "openclaw"),
    // Codex (anchored to avoid matching unrelated repos).
    (".codex", "codex"),
    ("codex-cli", "codex"),
    ("openai-codex", "codex"),
    // Hermes (anchored).
    (".hermes", "hermes"),
    ("hermes-agent", "hermes"),
];

/// Attribute a (pre-lowercased) lineage identity string to a known agent type.
/// Returns `None` when no needle matches (the subprocess is not attributable to
/// a tracked agent and is excluded from the usage surface).
pub fn agent_type_for_identity(identity_lower: &str) -> Option<&'static str> {
    AGENT_IDENTITY_NEEDLES
        .iter()
        .find(|(needle, _)| identity_lower.contains(needle))
        .map(|(_, agent_type)| *agent_type)
}

// ---------------------------------------------------------------------------
// Input (one candidate subprocess observation, built by the core manager)
// ---------------------------------------------------------------------------

/// A normalized candidate built by the core manager from a session L7 record or
/// a FIM event. The builder classifies + attributes + dedups these.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubprocessInput {
    pub process_name: String,
    pub process_path: String,
    pub parent_process_name: String,
    pub parent_process_path: String,
    pub grandparent_process_name: String,
    pub grandparent_process_path: String,
    pub parent_script_path: String,
    /// Full argv of the subprocess (joined + truncated for display).
    pub command: Vec<String>,
    pub pid: u32,
    pub parent_pid: u32,
    /// `"domain:port"` / `"ip:port"` for session-sourced inputs; `None` for FIM.
    pub destination: Option<String>,
    /// `"session"` or `"fim"`.
    pub source: String,
    pub session_uid: Option<String>,
    pub observed_at: chrono::DateTime<chrono::Utc>,
}

impl SubprocessInput {
    /// Combined lowercase lineage identity used for agent attribution.
    fn identity_lower(&self) -> String {
        let mut s = String::new();
        for part in [
            self.process_path.as_str(),
            self.parent_process_name.as_str(),
            self.parent_process_path.as_str(),
            self.grandparent_process_name.as_str(),
            self.grandparent_process_path.as_str(),
            self.parent_script_path.as_str(),
        ] {
            if !part.is_empty() {
                s.push(' ');
                s.push_str(part);
            }
        }
        for c in &self.command {
            s.push(' ');
            s.push_str(c);
        }
        s.to_ascii_lowercase()
    }

    /// Destination host (domain or IP, port stripped) or `"local"`.
    fn dest_host(&self) -> String {
        match &self.destination {
            Some(d) if !d.trim().is_empty() => {
                // Strip a trailing `:port` (handle bracketed IPv6 too).
                let d = d.trim();
                if let Some(rest) = d.strip_prefix('[') {
                    // [ipv6]:port
                    if let Some(end) = rest.find(']') {
                        return rest[..end].to_string();
                    }
                }
                match d.rfind(':') {
                    Some(idx) if d[idx + 1..].chars().all(|c| c.is_ascii_digit()) => {
                        d[..idx].to_string()
                    }
                    _ => d.to_string(),
                }
            }
            _ => "local".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// One deduplicated subprocess observation: an agent, a critical binary, and
/// (optionally) a destination, with an occurrence count and a time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSubprocessObservation {
    pub agent_type: String,
    pub process_name: String,
    pub category: String,
    pub criticality: SubprocessCriticality,
    pub process_path: String,
    pub parent_process_name: String,
    pub parent_process_path: String,
    /// Joined argv, truncated.
    pub command: String,
    pub destination: Option<String>,
    pub pid: u32,
    pub parent_pid: u32,
    pub source: String,
    pub session_uid: Option<String>,
    pub count: u32,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub owasp_refs: String,
    /// Stable key matching the emitted `VisibilityFinding`.
    pub finding_key: String,
}

/// Per-agent rollup of subprocess usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSubprocessAgentSummary {
    pub agent_type: String,
    pub total: u32,
    pub critical: u32,
    pub elevated: u32,
    pub routine: u32,
    /// Distinct categories observed for this agent (sorted).
    pub categories: Vec<String>,
}

/// The composite agent subprocess-usage surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSubprocessUsage {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub total_observations: u32,
    /// Observations whose binary is `Critical` criticality (ssh/nc/docker/...).
    pub critical_observations: u32,
    pub agents_with_usage: u32,
    pub by_agent: Vec<AgentSubprocessAgentSummary>,
    pub observations: Vec<AgentSubprocessObservation>,
    pub findings: Vec<VisibilityFinding>,
}

const MAX_COMMAND_CHARS: usize = 256;

fn join_command(cmd: &[String]) -> String {
    let joined = cmd.join(" ");
    if joined.chars().count() > MAX_COMMAND_CHARS {
        let truncated: String = joined.chars().take(MAX_COMMAND_CHARS).collect();
        format!("{truncated}...")
    } else {
        joined
    }
}

// ---------------------------------------------------------------------------
// Builder (deterministic, pure)
// ---------------------------------------------------------------------------

/// Build the agent subprocess-usage surface from candidate inputs. Pure: keeps
/// only inputs that classify as a critical subprocess AND attribute to a known
/// agent, dedups them, rolls up per-agent counts, and synthesizes one
/// `VisibilityFinding` per deduped observation (severity capped at `Medium`).
pub fn build_agent_subprocess_usage(inputs: &[SubprocessInput]) -> AgentSubprocessUsage {
    use std::collections::BTreeMap;

    // dedup key -> accumulating observation
    let mut acc: BTreeMap<String, AgentSubprocessObservation> = BTreeMap::new();

    for input in inputs {
        let class = match classify_subprocess(&input.process_name) {
            Some(c) => c,
            None => continue,
        };
        let agent_type = match agent_type_for_identity(&input.identity_lower()) {
            Some(a) => a.to_string(),
            None => continue,
        };
        let proc_base = normalize_process_basename(&input.process_name);
        let dest_host = input.dest_host();
        let key = format!(
            "{}|{}|{}|{}",
            agent_type, proc_base, dest_host, input.source
        );

        let subject_id = format!("{}:{}:{}", agent_type, proc_base, dest_host);
        let finding_key = format!("subprocess:subprocess_{}:{}", class.category, subject_id);

        acc.entry(key)
            .and_modify(|o| {
                o.count += 1;
                if input.observed_at < o.first_seen {
                    o.first_seen = input.observed_at;
                }
                if input.observed_at > o.last_seen {
                    o.last_seen = input.observed_at;
                }
            })
            .or_insert_with(|| AgentSubprocessObservation {
                agent_type: agent_type.clone(),
                process_name: proc_base.clone(),
                category: class.category.to_string(),
                criticality: class.criticality,
                process_path: input.process_path.clone(),
                parent_process_name: input.parent_process_name.clone(),
                parent_process_path: input.parent_process_path.clone(),
                command: join_command(&input.command),
                destination: input.destination.clone(),
                pid: input.pid,
                parent_pid: input.parent_pid,
                source: input.source.clone(),
                session_uid: input.session_uid.clone(),
                count: 1,
                first_seen: input.observed_at,
                last_seen: input.observed_at,
                owasp_refs: class.owasp_refs.to_string(),
                finding_key,
            });
    }

    let mut observations: Vec<AgentSubprocessObservation> = acc.into_values().collect();
    // Sort: criticality desc, then count desc, then agent + name for stability.
    observations.sort_by(|a, b| {
        b.criticality
            .rank()
            .cmp(&a.criticality.rank())
            .then(b.count.cmp(&a.count))
            .then(a.agent_type.cmp(&b.agent_type))
            .then(a.process_name.cmp(&b.process_name))
            .then(a.finding_key.cmp(&b.finding_key))
    });

    // Per-agent rollup.
    let mut by_agent_map: BTreeMap<String, AgentSubprocessAgentSummary> = BTreeMap::new();
    let mut critical_observations = 0u32;
    for o in &observations {
        if o.criticality == SubprocessCriticality::Critical {
            critical_observations += 1;
        }
        let entry = by_agent_map.entry(o.agent_type.clone()).or_insert_with(|| {
            AgentSubprocessAgentSummary {
                agent_type: o.agent_type.clone(),
                total: 0,
                critical: 0,
                elevated: 0,
                routine: 0,
                categories: Vec::new(),
            }
        });
        entry.total += 1;
        match o.criticality {
            SubprocessCriticality::Critical => entry.critical += 1,
            SubprocessCriticality::Elevated => entry.elevated += 1,
            SubprocessCriticality::Routine => entry.routine += 1,
        }
        if !entry.categories.contains(&o.category) {
            entry.categories.push(o.category.clone());
        }
    }
    for s in by_agent_map.values_mut() {
        s.categories.sort();
    }
    let mut by_agent: Vec<AgentSubprocessAgentSummary> = by_agent_map.into_values().collect();
    by_agent.sort_by(|a, b| {
        b.critical
            .cmp(&a.critical)
            .then(a.agent_type.cmp(&b.agent_type))
    });

    // Synthesize findings (one per deduped observation).
    let findings: Vec<VisibilityFinding> = observations
        .iter()
        .map(|o| {
            let rule_id = format!("subprocess_{}", o.category);
            let subject_id = format!(
                "{}:{}:{}",
                o.agent_type,
                o.process_name,
                o.destination
                    .as_deref()
                    .map(host_only)
                    .unwrap_or_else(|| "local".to_string())
            );
            let dest_str = o
                .destination
                .as_deref()
                .filter(|d| !d.trim().is_empty())
                .unwrap_or("local");
            let title = format!(
                "Agent '{}' spawned critical subprocess '{}'",
                o.agent_type, o.process_name
            );
            let description = format!(
                "The '{}' agent spawned '{}' ({}, {} criticality) -> {} (observed {}x).",
                o.agent_type,
                o.process_name,
                o.category,
                o.criticality.as_str(),
                dest_str,
                o.count
            );
            let mut f = VisibilityFinding::new(
                "subprocess",
                &rule_id,
                o.criticality.finding_severity(),
                &subject_id,
                title,
                description,
            )
            .with_evidence("agent_type", o.agent_type.as_str())
            .with_evidence("process_name", o.process_name.as_str())
            .with_evidence("category", o.category.as_str())
            .with_evidence("criticality", o.criticality.as_str())
            .with_evidence("count", o.count.to_string())
            .with_evidence("source", o.source.as_str())
            .with_evidence("owasp_refs", o.owasp_refs.as_str());
            if !o.process_path.is_empty() {
                f = f.with_evidence("process_path", o.process_path.as_str());
            }
            if !o.parent_process_name.is_empty() {
                f = f.with_evidence("parent_process_name", o.parent_process_name.as_str());
            }
            if !o.parent_process_path.is_empty() {
                f = f.with_evidence("parent_process_path", o.parent_process_path.as_str());
            }
            if !o.command.is_empty() {
                f = f.with_evidence("command", o.command.as_str());
            }
            if let Some(d) = &o.destination {
                f = f.with_evidence("destination", d.as_str());
            }
            f
        })
        .collect();

    let total_observations = observations.len() as u32;
    let agents_with_usage = by_agent.len() as u32;

    AgentSubprocessUsage {
        generated_at: chrono::Utc::now(),
        total_observations,
        critical_observations,
        agents_with_usage,
        by_agent,
        observations,
        findings,
    }
}

/// Host-only (port stripped) form of a `destination` string, for finding keys.
fn host_only(d: &str) -> String {
    let d = d.trim();
    if d.is_empty() {
        return "local".to_string();
    }
    if let Some(rest) = d.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    match d.rfind(':') {
        Some(idx) if d[idx + 1..].chars().all(|c| c.is_ascii_digit()) => d[..idx].to_string(),
        _ => d.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(process: &str, parent_path: &str, dest: Option<&str>) -> SubprocessInput {
        SubprocessInput {
            process_name: process.to_string(),
            process_path: format!("/usr/bin/{process}"),
            parent_process_name: "node".to_string(),
            parent_process_path: parent_path.to_string(),
            grandparent_process_name: String::new(),
            grandparent_process_path: String::new(),
            parent_script_path: String::new(),
            command: vec![process.to_string(), "host".to_string()],
            pid: 100,
            parent_pid: 1,
            destination: dest.map(|d| d.to_string()),
            source: "session".to_string(),
            session_uid: Some("uid-1".to_string()),
            observed_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn classify_known_and_unknown() {
        assert_eq!(
            classify_subprocess("ssh").unwrap().category,
            "remote_access"
        );
        assert_eq!(
            classify_subprocess("/usr/bin/SSH").unwrap().category,
            "remote_access"
        );
        assert_eq!(
            classify_subprocess("ssh.exe").unwrap().category,
            "remote_access"
        );
        assert_eq!(classify_subprocess("curl").unwrap().criticality, Elevated);
        assert_eq!(classify_subprocess("git").unwrap().criticality, Routine);
        assert!(classify_subprocess("ls").is_none());
        assert!(classify_subprocess("").is_none());
    }

    #[test]
    fn attribute_known_agents() {
        assert_eq!(
            agent_type_for_identity("/users/me/.cursor/extensions/foo node"),
            Some("cursor")
        );
        assert_eq!(
            agent_type_for_identity("/users/me/.claude/projects node claude-code"),
            Some("claude_code")
        );
        assert_eq!(
            agent_type_for_identity("/applications/claude.app/contents/macos/claude"),
            Some("claude_desktop")
        );
        assert_eq!(
            agent_type_for_identity("/home/me/.openclaw/plugins/edamame"),
            Some("openclaw")
        );
        assert_eq!(agent_type_for_identity("/usr/bin/ssh /bin/bash"), None);
    }

    #[test]
    fn dest_host_strips_port() {
        let i = input("ssh", "/home/me/.cursor/x", Some("example.com:22"));
        assert_eq!(i.dest_host(), "example.com");
        let i6 = input("ssh", "/home/me/.cursor/x", Some("[2001:db8::1]:22"));
        assert_eq!(i6.dest_host(), "2001:db8::1");
        let none = input("ssh", "/home/me/.cursor/x", None);
        assert_eq!(none.dest_host(), "local");
    }

    #[test]
    fn build_keeps_attributed_critical_only_and_dedups() {
        let inputs = vec![
            // Attributed + critical (ssh from cursor) -- kept, x2 dedup.
            input("ssh", "/home/me/.cursor/x", Some("example.com:22")),
            input("ssh", "/home/me/.cursor/x", Some("example.com:22")),
            // Attributed + elevated (curl from claude_code) -- kept.
            input(
                "curl",
                "/home/me/.claude/projects/p",
                Some("api.example.com:443"),
            ),
            // Critical but NOT attributable -- dropped.
            input("scp", "/usr/bin/sshd", Some("h:22")),
            // Attributable but NOT critical (ls) -- dropped.
            input("ls", "/home/me/.cursor/x", None),
        ];
        let usage = build_agent_subprocess_usage(&inputs);
        assert_eq!(usage.total_observations, 2);
        assert_eq!(usage.critical_observations, 1); // only ssh
        assert_eq!(usage.findings.len(), 2);
        assert_eq!(usage.agents_with_usage, 2);

        // ssh observation deduped to count 2, sorted first (Critical).
        let ssh = &usage.observations[0];
        assert_eq!(ssh.process_name, "ssh");
        assert_eq!(ssh.agent_type, "cursor");
        assert_eq!(ssh.count, 2);
        assert_eq!(ssh.criticality, Critical);
        assert!(ssh.owasp_refs.contains("OWASP-ASI05"));

        // findings are non-alertable (capped at Medium).
        assert!(usage.findings.iter().all(|f| !f.severity.is_alertable()));
        // owasp_refs propagated into finding evidence for the crosswalk.
        assert!(usage
            .findings
            .iter()
            .all(|f| f.evidence.contains_key("owasp_refs")));
    }

    #[test]
    fn empty_inputs_yield_empty_usage() {
        let usage = build_agent_subprocess_usage(&[]);
        assert_eq!(usage.total_observations, 0);
        assert_eq!(usage.critical_observations, 0);
        assert_eq!(usage.agents_with_usage, 0);
        assert!(usage.findings.is_empty());
    }
}
