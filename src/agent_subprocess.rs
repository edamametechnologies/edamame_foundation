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
use crate::agent_visibility_params::{self, CriticalSubprocessClassJSON};
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

    /// Map a CloudModel criticality label (already lowercased by
    /// `CveDetectionParams::new_from_json`) to the enum. Unknown labels fall
    /// back to `Routine` (the least-severe, reveal-only bucket).
    pub fn from_label(label: &str) -> Self {
        match label {
            "critical" => SubprocessCriticality::Critical,
            "elevated" => SubprocessCriticality::Elevated,
            _ => SubprocessCriticality::Routine,
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

/// One classified subprocess class: the category slug, inherent criticality,
/// and the OWASP GenAI crosswalk tags. Built from the CloudModel-tunable
/// `agent_critical_subprocess_catalog` entry that matched the binary basename.
///
/// Owned (not `&'static`) because the catalog is loaded from the CloudModel
/// snapshot at runtime and can be refreshed without a release.
pub struct CriticalSubprocessClass {
    pub category: String,
    pub criticality: SubprocessCriticality,
    pub owasp_refs: String,
}

impl CriticalSubprocessClass {
    fn from_json(json: &CriticalSubprocessClassJSON) -> Self {
        Self {
            category: json.category.clone(),
            criticality: SubprocessCriticality::from_label(&json.criticality),
            owasp_refs: json.owasp_refs.clone(),
        }
    }
}

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

/// Classify a subprocess by name. Returns the matching class when the
/// (basename, case-insensitive) name is a known critical subprocess, else
/// `None`. The catalog is the CloudModel-tunable
/// `agent_critical_subprocess_catalog` (names are pre-lowercased by
/// `CveDetectionParams::new_from_json`).
pub fn classify_subprocess(process_name: &str) -> Option<CriticalSubprocessClass> {
    let base = normalize_process_basename(process_name);
    if base.is_empty() {
        return None;
    }
    agent_visibility_params::agent_critical_subprocess_catalog()
        .iter()
        .find(|c| c.names.iter().any(|n| n.as_str() == base))
        .map(CriticalSubprocessClass::from_json)
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
        // For session-sourced inputs `command` is the subprocess argv and is
        // legitimate attribution material. For FIM-sourced inputs it carries
        // the touched file path instead -- an unrelated process writing into
        // an agent's config directory must NOT be attributed to that agent,
        // so the command is display-only there.
        if self.source != "fim" {
            for c in &self.command {
                s.push(' ');
                s.push_str(c);
            }
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

impl AgentSubprocessObservation {
    /// The deduplication key used to collapse repeated sightings of the same
    /// agent/binary/destination/source into a single observation. Identical to
    /// the key computed in [`build_subprocess_observations`], so a persisted
    /// history entry re-keys stably against a freshly built one (used by
    /// [`merge_and_window_subprocess_history`]).
    pub fn dedup_key(&self) -> String {
        let dest_host = self
            .destination
            .as_deref()
            .map(host_only)
            .unwrap_or_else(|| "local".to_string());
        format!(
            "{}|{}|{}|{}",
            self.agent_type, self.process_name, dest_host, self.source
        )
    }
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
    /// Rolling capture window (seconds) these observations are drawn from --
    /// the session-retention horizon supplied by the caller. `0` means the
    /// window is unknown (capture pipeline compiled out). The UI renders it as
    /// "critical commands launched in the past N minutes".
    pub window_seconds: u32,
    pub total_observations: u32,
    /// Observations whose binary is `Critical` criticality (ssh/nc/docker/...).
    pub critical_observations: u32,
    pub agents_with_usage: u32,
    pub by_agent: Vec<AgentSubprocessAgentSummary>,
    pub observations: Vec<AgentSubprocessObservation>,
    pub findings: Vec<VisibilityFinding>,
}

const MAX_COMMAND_CHARS: usize = 256;

/// Maximum number of distinct deduplicated subprocess observations retained.
///
/// The dedup key is `agent_type | process_basename | dest_host | source`. The
/// agent, process basename (catalog-bounded), and source ("session"/"fim")
/// dimensions are all bounded, but `dest_host` is attacker-influenceable -- an
/// agent can reach arbitrarily many distinct hosts -- so the distinct-key count
/// is otherwise unbounded. Capping the dedup map bounds `observations` and the
/// one-finding-per-observation `findings` vec that flow into `CoreVisibility`
/// and the serialized UI payload. Existing keys keep accumulating their counts;
/// only brand-new keys past the cap are dropped. Far above any realistic count
/// of distinct critical-subprocess destinations a host legitimately produces.
fn max_subprocess_observations() -> usize {
    agent_visibility_params::history_retention()
        .subprocess_max_observations
        .max(1)
}

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

/// Deduplicate + classify + attribute candidate inputs into observations,
/// WITHOUT the sort / rollup / finding synthesis (that is [`finalize_usage`]).
/// Pure: keeps only inputs that classify as a critical subprocess AND
/// attribute to a known agent, and collapses repeated sightings by the dedup
/// key `agent|process_basename|dest_host|source`. The returned vec is in
/// dedup-key order (not display order); pass it to [`finalize_usage`] to get a
/// sorted, rolled-up [`AgentSubprocessUsage`].
///
/// Split out from [`build_agent_subprocess_usage`] so the core manager can feed
/// the fresh observations into a persisted history merge
/// ([`merge_and_window_subprocess_history`]) before finalizing.
pub fn build_subprocess_observations(
    inputs: &[SubprocessInput],
) -> Vec<AgentSubprocessObservation> {
    use std::collections::BTreeMap;

    // dedup key -> accumulating observation
    let mut acc: BTreeMap<String, AgentSubprocessObservation> = BTreeMap::new();

    // Load the CloudModel catalog once for the whole batch (names are
    // pre-lowercased by `CveDetectionParams::new_from_json`).
    let catalog = agent_visibility_params::agent_critical_subprocess_catalog();

    for input in inputs {
        let proc_base = normalize_process_basename(&input.process_name);
        if proc_base.is_empty() {
            continue;
        }
        let class = match catalog
            .iter()
            .find(|c| c.names.iter().any(|n| n.as_str() == proc_base))
        {
            Some(c) => c,
            None => continue,
        };
        let criticality = SubprocessCriticality::from_label(&class.criticality);
        let agent_type = match agent_type_for_identity(&input.identity_lower()) {
            Some(a) => a.to_string(),
            None => continue,
        };
        let dest_host = input.dest_host();
        let key = format!(
            "{}|{}|{}|{}",
            agent_type, proc_base, dest_host, input.source
        );

        let subject_id = format!("{}:{}:{}", agent_type, proc_base, dest_host);
        let finding_key = format!("subprocess:subprocess_{}:{}", class.category, subject_id);

        // Bound the dedup map on its only attacker-influenceable dimension
        // (dest_host). A brand-new key past the cap is dropped; existing keys
        // keep accumulating so occurrence counts stay accurate.
        if acc.len() >= max_subprocess_observations() && !acc.contains_key(&key) {
            continue;
        }

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
                criticality,
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

    acc.into_values().collect()
}

/// Finalize a set of deduplicated observations into the wire surface: sort them
/// into display order, roll up per-agent counts, synthesize one capped
/// `VisibilityFinding` per observation, and stamp the caller-supplied
/// `window_seconds`. Shared by [`build_agent_subprocess_usage`] (live build)
/// and [`merge_and_window_subprocess_history`] (windowed history read).
pub fn finalize_usage(
    mut observations: Vec<AgentSubprocessObservation>,
    window_seconds: u32,
) -> AgentSubprocessUsage {
    use std::collections::BTreeMap;

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
    let findings: Vec<VisibilityFinding> =
        observations.iter().map(finding_for_observation).collect();

    let total_observations = observations.len() as u32;
    let agents_with_usage = by_agent.len() as u32;

    AgentSubprocessUsage {
        generated_at: chrono::Utc::now(),
        window_seconds,
        total_observations,
        critical_observations,
        agents_with_usage,
        by_agent,
        observations,
        findings,
    }
}

/// Build the capped `VisibilityFinding` (Medium/Low/Info per criticality) for a
/// single observation. Reveal-only: severity never reaches the alertable gate.
fn finding_for_observation(o: &AgentSubprocessObservation) -> VisibilityFinding {
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
}

/// Build the agent subprocess-usage surface from candidate inputs. Pure: keeps
/// only inputs that classify as a critical subprocess AND attribute to a known
/// agent, dedups them, rolls up per-agent counts, and synthesizes one
/// `VisibilityFinding` per deduped observation (severity capped at `Medium`).
///
/// `window_seconds` is the rolling capture-retention horizon the `inputs` were
/// drawn from (the caller's session-retention bound). It is carried through to
/// [`AgentSubprocessUsage::window_seconds`] so the UI can state the time window
/// explicitly; pass `0` when no capture window applies.
pub fn build_agent_subprocess_usage(
    inputs: &[SubprocessInput],
    window_seconds: u32,
) -> AgentSubprocessUsage {
    finalize_usage(build_subprocess_observations(inputs), window_seconds)
}

/// Merge freshly built observations into a persisted history vector, prune the
/// history to `retention_seconds`, cap it, and return the finalized surface for
/// the requested `window_seconds`.
///
/// `history` is the caller-owned persisted set of deduplicated observations
/// (the full retained horizon, mutated in place so the caller can persist it).
/// `fresh` is the current live surface's observations (from
/// [`build_subprocess_observations`]). Merge semantics per dedup key:
/// - `first_seen` = earliest ever seen, `last_seen` = latest ever seen;
/// - display fields (path/command/destination/pid/session_uid) are refreshed
///   from the freshest sighting so the row reflects the most recent activity;
/// - `count` = the PEAK single-window occurrence count (`max`, never a running
///   sum) so a long-lived session re-counted across many live reads does not
///   inflate the lifetime total without bound.
///
/// Then: entries older than `retention_seconds` (by `last_seen`) are pruned;
/// the history is capped at the unified retention policy's
/// `subprocess_max_observations`, evicting the
/// oldest `last_seen` first; and the returned surface contains only entries
/// whose `last_seen` is within `window_seconds` of `now`. `window_seconds == 0`
/// means "no window filter" (return the full retained set). Pure except for the
/// injected `now` (no clock, no IO), so it is unit-testable.
pub fn merge_and_window_subprocess_history(
    history: &mut Vec<AgentSubprocessObservation>,
    fresh: &[AgentSubprocessObservation],
    now: chrono::DateTime<chrono::Utc>,
    retention_seconds: i64,
    window_seconds: u32,
) -> AgentSubprocessUsage {
    use std::collections::HashMap;

    // Index existing history by dedup key for O(1) merge.
    let mut index: HashMap<String, usize> = HashMap::with_capacity(history.len());
    for (i, o) in history.iter().enumerate() {
        index.insert(o.dedup_key(), i);
    }

    for f in fresh {
        let key = f.dedup_key();
        if let Some(&i) = index.get(&key) {
            let o = &mut history[i];
            if f.first_seen < o.first_seen {
                o.first_seen = f.first_seen;
            }
            if f.last_seen >= o.last_seen {
                o.last_seen = f.last_seen;
                // Refresh display fields from the freshest sighting.
                o.process_path = f.process_path.clone();
                o.parent_process_name = f.parent_process_name.clone();
                o.parent_process_path = f.parent_process_path.clone();
                o.command = f.command.clone();
                o.destination = f.destination.clone();
                o.pid = f.pid;
                o.parent_pid = f.parent_pid;
                o.session_uid = f.session_uid.clone();
                o.criticality = f.criticality;
                o.category = f.category.clone();
                o.owasp_refs = f.owasp_refs.clone();
                o.finding_key = f.finding_key.clone();
            }
            // Peak single-window occurrence count (never a running sum).
            if f.count > o.count {
                o.count = f.count;
            }
        } else {
            let idx = history.len();
            history.push(f.clone());
            index.insert(key, idx);
        }
    }

    // Prune by retention horizon (by last activity).
    if retention_seconds > 0 {
        history.retain(|o| (now - o.last_seen).num_seconds() <= retention_seconds);
    }

    // Cap the retained set, evicting the oldest `last_seen` first.
    let cap = max_subprocess_observations();
    if history.len() > cap {
        history.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        history.truncate(cap);
    }

    // Windowed projection: entries active within `window_seconds` of `now`.
    let windowed: Vec<AgentSubprocessObservation> = if window_seconds == 0 {
        history.clone()
    } else {
        let cutoff = window_seconds as i64;
        history
            .iter()
            .filter(|o| (now - o.last_seen).num_seconds() <= cutoff)
            .cloned()
            .collect()
    };

    finalize_usage(windowed, window_seconds)
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
        assert_eq!(
            classify_subprocess("curl").unwrap().criticality,
            SubprocessCriticality::Elevated
        );
        assert_eq!(
            classify_subprocess("git").unwrap().criticality,
            SubprocessCriticality::Routine
        );
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
        let usage = build_agent_subprocess_usage(&inputs, 7200);
        assert_eq!(usage.total_observations, 2);
        assert_eq!(usage.critical_observations, 1); // only ssh
        assert_eq!(usage.findings.len(), 2);
        assert_eq!(usage.agents_with_usage, 2);
        // The caller-supplied capture window is carried through verbatim.
        assert_eq!(usage.window_seconds, 7200);

        // ssh observation deduped to count 2, sorted first (Critical).
        let ssh = &usage.observations[0];
        assert_eq!(ssh.process_name, "ssh");
        assert_eq!(ssh.agent_type, "cursor");
        assert_eq!(ssh.count, 2);
        assert_eq!(ssh.criticality, SubprocessCriticality::Critical);
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
    fn fim_command_is_display_only_never_attribution() {
        // FIM-sourced inputs carry the touched file path in `command`. A
        // random (non-agent) process writing into an agent's config dir must
        // NOT be attributed to that agent off the file path alone.
        let mut unattributed = input("ssh", "/usr/bin/sshd", None);
        unattributed.source = "fim".to_string();
        unattributed.session_uid = None;
        unattributed.command = vec![
            "modify".to_string(),
            "/home/me/.cursor/mcp.json".to_string(),
        ];
        let usage = build_agent_subprocess_usage(&[unattributed], 0);
        assert_eq!(usage.total_observations, 0);

        // The same FIM input WITH real agent lineage is kept, sourced "fim",
        // destination-less ("local" host bucket).
        let mut attributed = input("ssh", "/home/me/.cursor/x", None);
        attributed.source = "fim".to_string();
        attributed.session_uid = None;
        attributed.command = vec!["create".to_string(), "/tmp/staging".to_string()];
        let usage = build_agent_subprocess_usage(&[attributed], 0);
        assert_eq!(usage.total_observations, 1);
        assert_eq!(usage.observations[0].source, "fim");
        assert_eq!(usage.observations[0].agent_type, "cursor");
        assert!(usage.observations[0].destination.is_none());
    }

    #[test]
    fn empty_inputs_yield_empty_usage() {
        let usage = build_agent_subprocess_usage(&[], 0);
        assert_eq!(usage.total_observations, 0);
        assert_eq!(usage.critical_observations, 0);
        assert_eq!(usage.agents_with_usage, 0);
        assert!(usage.findings.is_empty());
    }

    #[test]
    fn build_bounds_observations_at_cap() {
        // Distinct destination hosts are the only attacker-influenceable
        // dimension of the dedup key, so a flood of distinct ssh destinations
        // must not grow the observation set without limit. Feed
        // cap + 50 distinct destinations, then one
        // duplicate of the FIRST (already-inserted) destination to prove that
        // existing keys keep accumulating even after the cap is reached.
        let cap = max_subprocess_observations();
        let mut inputs: Vec<SubprocessInput> = (0..(cap + 50))
            .map(|i| {
                input(
                    "ssh",
                    "/home/me/.cursor/x",
                    Some(&format!("host-{i}.example.com:22")),
                )
            })
            .collect();
        // Duplicate of the first destination (host-0) -- its key is already in
        // the map, so it must NOT be dropped by the cap; its count increments.
        inputs.push(input(
            "ssh",
            "/home/me/.cursor/x",
            Some("host-0.example.com:22"),
        ));

        let usage = build_agent_subprocess_usage(&inputs, 7200);
        assert_eq!(
            usage.total_observations, cap as u32,
            "observation set must saturate at subprocess_max_observations"
        );
        assert_eq!(
            usage.observations.len(),
            cap,
            "observations vec must be bounded at subprocess_max_observations"
        );
        // host-0 was seen twice; it sorts first (count desc) and proves
        // existing keys keep accumulating past the cap.
        assert_eq!(
            usage.observations[0].count, 2,
            "an already-tracked key keeps accumulating after the cap is hit"
        );
        assert_eq!(
            usage.observations[0].destination.as_deref(),
            Some("host-0.example.com:22")
        );
    }

    fn input_at(
        process: &str,
        parent_path: &str,
        dest: Option<&str>,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> SubprocessInput {
        let mut i = input(process, parent_path, dest);
        i.observed_at = observed_at;
        i
    }

    #[test]
    fn merge_history_dedups_and_tracks_first_last_seen() {
        let now = chrono::Utc::now();
        let t_old = now - chrono::Duration::hours(6);
        let t_new = now - chrono::Duration::minutes(5);

        // History: one ssh sighting 6h ago.
        let mut history = build_subprocess_observations(&[input_at(
            "ssh",
            "/home/me/.cursor/x",
            Some("example.com:22"),
            t_old,
        )]);
        assert_eq!(history.len(), 1);

        // Fresh: same key, seen 5 min ago.
        let fresh = build_subprocess_observations(&[input_at(
            "ssh",
            "/home/me/.cursor/x",
            Some("example.com:22"),
            t_new,
        )]);

        // 30-day retention, no window filter.
        let usage =
            merge_and_window_subprocess_history(&mut history, &fresh, now, 30 * 24 * 3600, 0);
        // Same dedup key -> still ONE observation, not two.
        assert_eq!(history.len(), 1);
        assert_eq!(usage.total_observations, 1);
        let o = &usage.observations[0];
        assert_eq!(
            o.first_seen, t_old,
            "first_seen keeps the earliest sighting"
        );
        assert_eq!(
            o.last_seen, t_new,
            "last_seen advances to the freshest sighting"
        );
    }

    #[test]
    fn merge_history_windows_out_stale_entries() {
        let now = chrono::Utc::now();
        let t_2d = now - chrono::Duration::days(2);
        let t_now = now - chrono::Duration::minutes(1);

        // History has an ssh from 2 days ago and a curl from 1 min ago.
        let mut history = build_subprocess_observations(&[
            input_at(
                "ssh",
                "/home/me/.cursor/x",
                Some("old.example.com:22"),
                t_2d,
            ),
            input_at(
                "curl",
                "/home/me/.claude/projects/p",
                Some("api.example.com:443"),
                t_now,
            ),
        ]);
        assert_eq!(history.len(), 2);

        // 24h window: the 2-day-old ssh drops out of the projection but stays
        // in the retained history (retention is 30d).
        let usage =
            merge_and_window_subprocess_history(&mut history, &[], now, 30 * 24 * 3600, 24 * 3600);
        assert_eq!(history.len(), 2, "retention keeps both entries on disk");
        assert_eq!(
            usage.total_observations, 1,
            "24h window projects only the recent curl"
        );
        assert_eq!(usage.observations[0].process_name, "curl");

        // 7d window: both entries are within the window.
        let usage7 = merge_and_window_subprocess_history(
            &mut history,
            &[],
            now,
            30 * 24 * 3600,
            7 * 24 * 3600,
        );
        assert_eq!(usage7.total_observations, 2);
    }

    #[test]
    fn merge_history_prunes_beyond_retention() {
        let now = chrono::Utc::now();
        let t_40d = now - chrono::Duration::days(40);

        let mut history = build_subprocess_observations(&[input_at(
            "ssh",
            "/home/me/.cursor/x",
            Some("ancient.example.com:22"),
            t_40d,
        )]);
        assert_eq!(history.len(), 1);

        // 30-day retention prunes the 40-day-old entry entirely.
        let usage = merge_and_window_subprocess_history(&mut history, &[], now, 30 * 24 * 3600, 0);
        assert!(history.is_empty(), "entry older than retention is pruned");
        assert_eq!(usage.total_observations, 0);
    }

    #[test]
    fn merge_history_count_is_peak_not_sum() {
        let now = chrono::Utc::now();
        let t = now - chrono::Duration::minutes(10);

        // Fresh window A: ssh seen 3x.
        let fresh_a = build_subprocess_observations(&[
            input_at("ssh", "/home/me/.cursor/x", Some("example.com:22"), t),
            input_at("ssh", "/home/me/.cursor/x", Some("example.com:22"), t),
            input_at("ssh", "/home/me/.cursor/x", Some("example.com:22"), t),
        ]);
        assert_eq!(fresh_a[0].count, 3);

        let mut history: Vec<AgentSubprocessObservation> = Vec::new();
        merge_and_window_subprocess_history(&mut history, &fresh_a, now, 30 * 24 * 3600, 0);
        assert_eq!(history[0].count, 3);

        // Fresh window B (later read): same session re-counted at 2x. The peak
        // stays 3 -- counts do NOT accumulate into 5 across reads.
        let fresh_b = build_subprocess_observations(&[
            input_at("ssh", "/home/me/.cursor/x", Some("example.com:22"), now),
            input_at("ssh", "/home/me/.cursor/x", Some("example.com:22"), now),
        ]);
        merge_and_window_subprocess_history(&mut history, &fresh_b, now, 30 * 24 * 3600, 0);
        assert_eq!(
            history[0].count, 3,
            "count is the peak single-window occurrence, never a running sum"
        );

        // A higher peak DOES raise the stored count.
        let fresh_c = build_subprocess_observations(
            &(0..5)
                .map(|_| input_at("ssh", "/home/me/.cursor/x", Some("example.com:22"), now))
                .collect::<Vec<_>>(),
        );
        merge_and_window_subprocess_history(&mut history, &fresh_c, now, 30 * 24 * 3600, 0);
        assert_eq!(
            history[0].count, 5,
            "a higher single-window peak raises the count"
        );
    }
}
