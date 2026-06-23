//! Agent transcript collection adapters.
//!
//! Each per-agent submodule walks the host filesystem for an agent's session
//! transcripts and produces a `RawReasoningSessionPayload`-shaped JSON value
//! that EDAMAME core feeds to `upsert_behavioral_model_from_raw_sessions`.
//!
//! These adapters are the single source of truth for transcript parsing in
//! the standalone path (`edamame_core` calls them directly) and the helper
//! path (`helper_rx_utility::utility_collect_agent_transcripts` calls the
//! same functions on the other side of the macOS sandbox boundary).
//!
//! The Node-side extrapolators in the per-agent plugin repos still ship and
//! still push behavioral models; the observer is additive. Hash-skip on the
//! core side prevents redundant LLM work when both producers emit equivalent
//! payloads.
//!
//! On iOS / Android the module compiles but every adapter returns an empty
//! payload (the agent plugins only install on desktop targets). Keeping the
//! types available unconditionally means `edamame_core` can reference
//! `CollectResult` without target-specific cfg fences.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub mod claude_code;
pub mod claude_desktop;
pub mod codex;
pub mod cursor;
pub mod hermes;
pub mod openclaw;
pub mod parsing;

#[cfg(test)]
mod tests;

/// Tunables for a single transcript collection pass.
///
/// `active_window_minutes` is the only age filter. A session is included
/// only if its mtime is within that many minutes from now. Older sessions
/// are concluded work whose intent has already been ingested in earlier
/// ticks; re-including them just bloats the LLM prompt with stale paths
/// and commands without adding signal.
///
/// When no sessions are active, the collector returns an empty payload.
/// The existing merged behavioral model in the registry stays valid (it
/// is the snapshot from the last active period), and the observer
/// hash-skips on the empty result so we don't pay for an LLM round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectOptions {
    /// Maximum number of sessions to include per call.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Only sessions whose mtime is within this many minutes of "now"
    /// qualify for ingestion. Older transcripts are ignored.
    #[serde(default = "default_active_window_minutes")]
    pub active_window_minutes: u64,
    /// Optional substrings used to filter transcript file paths to a workspace
    /// or project the operator cares about. Empty means "no filter".
    #[serde(default)]
    pub project_hints: Vec<String>,
}

fn default_limit() -> usize {
    6
}
fn default_active_window_minutes() -> u64 {
    // 30 minutes is generous enough to cover a typical multi-step agent
    // turn (Cursor in particular only flushes the agent-transcript jsonl
    // when a turn completes, so a single long investigation can leave the
    // file's mtime stale for many minutes during execution), while still
    // excluding sessions that are hours old.
    30
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            limit: default_limit(),
            active_window_minutes: default_active_window_minutes(),
            project_hints: Vec::new(),
        }
    }
}

/// JSON-shape twin of `edamame_core::agentic::divergence::RawReasoningSession`.
/// Foundation does not depend on core, so we redefine the shape here. Field
/// names match exactly so serde round-trips identically through
/// `upsert_behavioral_model_from_raw_sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedRawSession {
    pub session_key: String,
    pub title: String,
    pub user_text: String,
    pub assistant_text: String,
    pub raw_text: String,
    pub tool_names: Vec<String>,
    pub commands: Vec<String>,
    pub derived_expected_traffic: Vec<String>,
    pub derived_expected_local_open_ports: Vec<u16>,
    pub derived_expected_process_paths: Vec<String>,
    pub derived_expected_parent_paths: Vec<String>,
    pub derived_expected_grandparent_paths: Vec<String>,
    pub derived_scope_process_paths: Vec<String>,
    pub derived_scope_parent_paths: Vec<String>,
    pub derived_scope_grandparent_paths: Vec<String>,
    pub derived_scope_any_lineage_paths: Vec<String>,
    pub derived_expected_open_files: Vec<String>,
    pub source_path: String,
    pub started_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
}

/// Derive `derived_scope_any_lineage_paths` for an agent from its
/// `derived_scope_parent_paths`, keeping ONLY the agent-identity-specific
/// entries (the launcher/binary patterns carrying the agent's own product
/// name) and dropping the generic runtime/sandbox patterns (`*/node`,
/// `*\node.exe`, `*/python`, `*/.nvm/`, `*/.volta/`, `*/flatpak/`,
/// `*/nix/store/`, `*/WindowsApps/`, ...).
///
/// The divergence engine's `session_matches_scope_filter` checks
/// `any_lineage_paths` against the process, parent, AND grandparent of an
/// egressing session. On Windows the agent launcher (`claude.exe`,
/// `codex.exe`, `hermes.exe`, ...) double-execs through Git Bash, so the
/// egressing `bash.exe`'s real owner is its GRANDPARENT, not its parent.
/// Scoping the agent identity at any-lineage depth keeps divergence
/// attributed (and the multiplatform divergence test hard-gated) on Windows
/// without weakening the parent-only scope on Unix.
///
/// Identity tokens are intentionally the agent's own product name, never a
/// generic interpreter -- a `node` / `python` grandparent must NOT silently
/// own an egress just because some agent happens to run on that runtime. The
/// returned entries are kept verbatim (mixed slashes intact); the engine
/// normalizes both the stored rule and the candidate value at match time.
pub(crate) fn agent_identity_lineage_paths(agent_type: &str, parent_paths: &[&str]) -> Vec<String> {
    let tokens: &[&str] = match agent_type {
        "claude_code" => &["claude"],
        "claude_desktop" => &["claude", "anthropic"],
        "cursor" => &["cursor"],
        "codex" => &["codex"],
        "hermes" => &["hermes"],
        "openclaw" => &["openclaw"],
        _ => &[],
    };
    if tokens.is_empty() {
        return Vec::new();
    }
    parent_paths
        .iter()
        .filter(|p| {
            let lower = p.to_ascii_lowercase();
            tokens.iter().any(|t| lower.contains(t))
        })
        .map(|p| (*p).to_string())
        .collect()
}

/// JSON-shape twin of `edamame_core::agentic::divergence::RawReasoningSessionPayload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedPayload {
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub agent_type: String,
    pub agent_instance_id: String,
    pub source_kind: String,
    pub sessions: Vec<CollectedRawSession>,
}

/// Diagnostic payload returned to the observer alongside the collected sessions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectDiagnostics {
    /// Whether the agent's primary transcript root resolved to an existing,
    /// readable directory. Used by the healthcheck "Observer" subsection.
    pub transcripts_root_accessible: bool,
    /// All transcript roots that were considered (for audit/log).
    pub transcripts_roots: Vec<String>,
    /// Hostname captured at collection time (used to derive agent_instance_id).
    pub hostname: String,
}

/// Final result of a collection pass: payload plus diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectResult {
    pub payload: CollectedPayload,
    pub diagnostics: CollectDiagnostics,
}

/// Deterministic per-session "run economics": exact token usage, cache
/// breakdown, tool-call counts, wall-clock duration, and an estimated dollar
/// cost, parsed from the transcript a session was already loaded from.
///
/// This is developer-centric observability EDAMAME already has the raw data
/// for -- the transcript observer reads the agent's `.jsonl` (Claude Code,
/// Codex) which carries `message.usage` / `total_token_usage` per turn -- but
/// historically discarded, keeping only the divergence-relevant fields. We
/// surface it here without feeding it to the LLM behavioral-model path (it is
/// computed locally in core from `CollectedRawSession.raw_text`, never added
/// to the `RawReasoningSession` payload).
///
/// `est_cost_usd` is an ESTIMATE derived from an embedded per-model price
/// table (`parsing::model_price`). The token counts themselves are EXACT when
/// the transcript carries usage metadata. Plain `.txt` transcripts (Cursor's
/// text export) carry no usage, so `has_token_data` is false and the
/// token/cost fields stay zero -- the UI shows "token data not available"
/// rather than a misleading $0.00.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SessionEconomics {
    pub session_key: String,
    pub source_path: String,
    /// Most recent non-empty model identifier seen in the transcript.
    pub model: String,
    /// Number of assistant turns that carried usage metadata.
    pub assistant_turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_read_input_tokens: u64,
    /// input + output + cache_creation + cache_read.
    pub total_tokens: u64,
    /// Number of tool invocations (`tool_use` / `function_call` blocks).
    pub tool_calls: u64,
    /// Number of tool results flagged as errors (`is_error` / error output).
    pub tool_errors: u64,
    /// Estimated cost in USD from the embedded per-model price table.
    pub est_cost_usd: f64,
    pub first_event_at: Option<DateTime<Utc>>,
    pub last_event_at: Option<DateTime<Utc>>,
    /// last_event_at - first_event_at, in seconds (0 when timestamps absent).
    pub duration_secs: u64,
    /// True when the transcript carried real `usage` token metadata.
    pub has_token_data: bool,
}

/// One tool result the transcript flagged as an error
/// (`tool_result.is_error == true` / `function_call_output` carrying an
/// `error`). This is the structured, LLM-free drill-down behind the
/// `tool_errors` count: it names the failing tool (correlated by
/// `tool_use_id` / `call_id` back to its `tool_use` / `function_call`) and a
/// truncated, body-free error snippet so the Agents-tab flight recorder can
/// surface "Read failed: permission denied" instead of just "1 tool error".
///
/// Metadata only -- the message is truncated and carries no file/transcript
/// body. Parsed deterministically from `CollectedRawSession.raw_text`; never
/// sent to the LLM behavioral-model path.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ToolErrorDetail {
    /// Best-effort tool name from the matching `tool_use` / `function_call`.
    /// Empty when the result could not be correlated back to its invocation.
    pub tool_name: String,
    /// Truncated, single-line error snippet (no bodies).
    pub message: String,
    /// In-transcript timestamp of the erroring result, when present.
    pub at: Option<DateTime<Utc>>,
}

/// Dispatch to the per-agent adapter.
///
/// `agent_type` MUST be one of `cursor`, `claude_code`, `claude_desktop`,
/// `codex`, `hermes`, `openclaw`. Unknown agent types return an empty payload
/// + diagnostics so upstream callers can surface "no observer for this agent"
/// cleanly.
pub fn collect(
    agent_type: &str,
    home: &Path,
    options: &CollectOptions,
) -> anyhow::Result<CollectResult> {
    match agent_type {
        "cursor" => cursor::collect(home, options),
        "claude_code" => claude_code::collect(home, options),
        "claude_desktop" => claude_desktop::collect(home, options),
        "codex" => codex::collect(home, options),
        "hermes" => hermes::collect(home, options),
        "openclaw" => openclaw::collect(home, options),
        other => Ok(CollectResult {
            payload: empty_payload(other, home),
            diagnostics: CollectDiagnostics {
                transcripts_root_accessible: false,
                transcripts_roots: Vec::new(),
                hostname: hostname_string(),
            },
        }),
    }
}

/// JSON convenience wrapper used by the helper utility order.
pub fn collect_to_json(
    agent_type: &str,
    home: &Path,
    options: &CollectOptions,
) -> anyhow::Result<String> {
    let result = collect(agent_type, home, options)?;
    serde_json::to_string(&result).map_err(|e| anyhow::anyhow!(e))
}

/// Build an empty payload (no sessions) tagged for `agent_type`.
/// EDAMAME core's validate_and_normalize will reject this with
/// "raw reasoning payload contains no sessions"; the observer interprets that
/// failure mode as "nothing to ingest right now" and short-circuits.
pub fn empty_payload(agent_type: &str, home: &Path) -> CollectedPayload {
    let now = Utc::now();
    CollectedPayload {
        window_start: now,
        window_end: now,
        agent_type: agent_type.to_string(),
        agent_instance_id: observer_agent_instance_id(agent_type, home),
        source_kind: agent_type.to_string(),
        sessions: Vec::new(),
    }
}

/// Stable per-host, per-agent identifier for observer-produced behavioral
/// model slices. Plugin-side pushes use a per-workspace ID so observer slices
/// and plugin slices coexist as separate contributors of the same agent_type.
pub fn observer_agent_instance_id(agent_type: &str, home: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(home.to_string_lossy().as_bytes());
    hasher.update(b"|");
    hasher.update(agent_type.as_bytes());
    let hash = hex::encode(hasher.finalize());
    format!(
        "{}-{}-observer",
        sanitize_hostname(&hostname_string()),
        &hash[..12]
    )
}

/// Best-effort hostname read. Falls back to `edamame-host` when no env var
/// is set (some sandboxed contexts).
pub fn hostname_string() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("COMPUTERNAME")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            std::env::var("HOST")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| "edamame-host".to_string())
}

fn sanitize_hostname(raw: &str) -> String {
    raw.trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Helper for adapters: walk a directory tree non-recursively to a depth of
/// `max_depth`, returning files whose basename matches one of the suffixes
/// in `suffixes`. Skips hidden directories (those starting with `.`) except
/// for the root itself.
pub(crate) fn walk_files_with_suffix(
    root: &Path,
    suffixes: &[&str],
    max_depth: usize,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_files_with_suffix_inner(root, suffixes, max_depth, 0, &mut out);
    out
}

fn walk_files_with_suffix_inner(
    dir: &Path,
    suffixes: &[&str],
    max_depth: usize,
    depth: usize,
    out: &mut Vec<PathBuf>,
) {
    if depth > max_depth {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            // Skip hidden subdirectories (e.g. `.git`) below the root.
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if depth > 0 && name.starts_with('.') {
                    continue;
                }
                if name == "subagents" {
                    continue;
                }
            }
            walk_files_with_suffix_inner(&path, suffixes, max_depth, depth + 1, out);
        } else if file_type.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if suffixes.iter().any(|s| name.ends_with(s)) {
                out.push(path);
            }
        }
    }
}

/// Maximum number of bytes read from a single transcript file.
///
/// Transcript files are normally a few hundred KB. A multi-MB file is already
/// an outlier (a very long multi-hour agent session) and a hundreds-of-MB file
/// is either corruption or an adversarial attempt to exhaust memory through the
/// observer / divergence / delegation pipeline -- the body flows into the
/// combined-transcript buffer in core, the LLM behavioral-model payload, the
/// derived-signal extraction, and the delegation-depth reconstruction. Capping
/// the per-file read bounds every one of those downstream consumers. With the
/// default `CollectOptions.limit` of 6 sessions, the combined buffer is bounded
/// at `6 * MAX_TRANSCRIPT_BYTES`.
pub(crate) const MAX_TRANSCRIPT_BYTES: u64 = 16 * 1024 * 1024;

/// Read a transcript file, capping the read at [`MAX_TRANSCRIPT_BYTES`].
///
/// Reads from the START of the file (where the session header and the earliest
/// turns / parent-linkage records live, keeping the JSONL parent/child graph
/// internally consistent) and returns the UTF-8 lossy contents. Truncation
/// lands on a raw byte boundary; `String::from_utf8_lossy` repairs any split
/// multibyte sequence at the cut. Drop-in for the adapters' previous
/// `std::fs::read_to_string(path)` calls: same `io::Result<String>` shape, so
/// the existing `match ... { Ok(text) => ..., Err(_) => continue }` arms are
/// unchanged.
pub(crate) fn read_transcript_capped(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(MAX_TRANSCRIPT_BYTES).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// File mtime in seconds since unix epoch. Returns 0 on error.
pub(crate) fn mtime_secs(path: &Path) -> u64 {
    use std::time::UNIX_EPOCH;
    std::fs::metadata(path)
        .ok()
        .and_then(|meta| meta.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// File birthtime in seconds since unix epoch, falling back to mtime.
pub(crate) fn birthtime_secs(path: &Path) -> u64 {
    use std::time::UNIX_EPOCH;
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return 0,
    };
    let birth = meta
        .created()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if birth > 0 {
        birth
    } else {
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

pub(crate) fn datetime_from_secs(secs: u64) -> DateTime<Utc> {
    use chrono::TimeZone;
    Utc.timestamp_opt(secs as i64, 0)
        .single()
        .unwrap_or_else(Utc::now)
}
