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
pub mod craft;
pub mod cursor;
pub mod hermes;
pub mod openclaw;
pub mod parsing;
mod session_cache;

pub(crate) use session_cache::get_or_build_session;

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
    /// Optional usage-bearing transcript text for the deterministic economics
    /// parser, used ONLY when it cannot recover exact token usage from
    /// `raw_text`. Two cases populate it (see [`economics_override_text`]):
    ///   * Cursor's preferred divergence source is the usage-free `.txt`
    ///     export while a usage-bearing `.jsonl` sibling exists (G4).
    ///   * A transcript exceeds [`MAX_TRANSCRIPT_BYTES`], so `raw_text` is the
    ///     head-only capped read and the cumulative end-of-file usage snapshot
    ///     (Codex `total_token_usage`) was truncated away (G5). The override
    ///     carries a head+tail read so both early per-turn usage and the final
    ///     cumulative snapshot survive.
    /// Empty means "raw_text already carries complete usage"; the economics
    /// parser then reads `raw_text` directly. `#[serde(default)]` keeps an
    /// older helper's JSON (which omits this field) deserializable in a newer
    /// core, so the shared divergence collection path never breaks on a
    /// rolling helper/core update.
    #[serde(default)]
    pub economics_raw_text: String,
    /// True when [`economics_raw_text`] is a head+tail read of a transcript that
    /// exceeded [`MAX_TRANSCRIPT_BYTES`] (the middle was dropped). Per-turn
    /// summation over such a transcript can undercount, so downstream economics
    /// surface the session's cost as a partial estimate (`truncated = true`).
    /// `#[serde(default)]` for the same rolling helper/core compatibility reason
    /// as [`economics_raw_text`].
    #[serde(default)]
    pub economics_truncated: bool,
    /// Cursor-only context-window occupancy snapshot for this conversation,
    /// read from Cursor's local Electron `state.vscdb`
    /// (`composerData:<id>.contextTokensUsed` / `.contextTokenLimit` /
    /// `.contextUsagePercent`, where `<id>` is exactly [`session_key`]). This is
    /// the share of the model's context window the conversation currently fills
    /// -- it is NOT billed token usage and NOT a dollar cost. Cursor exposes
    /// neither token usage nor cost on disk (both live server-side), so this is
    /// the only economics-adjacent signal recoverable locally for Cursor.
    /// `None` for every other agent, and for Cursor conversations whose
    /// `composerData` row is absent or carries no context numbers.
    /// `#[serde(default)]` for the same rolling helper/core compatibility reason
    /// as [`economics_raw_text`] (an older helper omits these fields entirely).
    #[serde(default)]
    pub context_tokens_used: Option<u64>,
    #[serde(default)]
    pub context_token_limit: Option<u64>,
    #[serde(default)]
    pub context_usage_percent: Option<f64>,
    /// Absolute working-directory the agent operated in for this session, when
    /// the agent records it out-of-band from `source_path`. This is the ONLY
    /// workspace signal for agents whose transcript files do not live under a
    /// `projects/<slug>/` tree (Codex writes `~/.codex/sessions/...` rollout
    /// files while recording the real `cwd` in its SQLite thread index; chat
    /// agents may carry none). Attribution prefers the `projects/<slug>` slug
    /// decoded from `source_path` and falls back to a slug derived from this
    /// directory (see `agent_visibility::workspace_slug_for_session`). Empty
    /// when the agent exposes no working-directory signal.
    /// `#[serde(default)]` for the same rolling helper/core compatibility reason
    /// as [`economics_raw_text`] (an older helper omits this field entirely).
    #[serde(default)]
    pub workspace_hint: String,
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
/// `est_cost_usd` is an ESTIMATE derived from the CloudModel-refreshable
/// per-model price table in `cve-detection-params-db.json`, resolved via
/// `crate::agent_visibility_params::resolve_model_price`. The token counts
/// themselves are EXACT when the transcript carries usage metadata. Plain
/// `.txt` transcripts (Cursor's text export) carry no usage, so
/// `has_token_data` is false and the token/cost fields stay zero -- the UI
/// shows "token data not available" rather than a misleading $0.00.
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
    /// Total tokens, counted once each. The provider's authoritative
    /// `total_tokens` when reported (Codex); otherwise the disjoint
    /// four-bucket sum for Anthropic, or `input + output + cache_creation`
    /// for cache-inclusive providers (OpenAI / Codex) where the cached subset
    /// is already inside `input`.
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
    /// True when `est_cost_usd` was computed with the fallback price because the
    /// model id was not found in the CloudModel price table (G3). The token
    /// counts stay exact; only the dollar conversion is a rougher estimate, so
    /// consumers can flag the cost as lower-confidence for unknown models.
    pub price_is_fallback: bool,

    // ---- Derived, APPROXIMATE per-turn responsiveness (Workstream C) --------
    //
    // These are passive, transcript-derived signals for external agents whose
    // provider latency EDAMAME cannot measure directly (unlike its own
    // `LLMClient` calls, which are measured precisely by `llm_telemetry`). They
    // are computed as `assistant_ts - preceding-trigger_ts` per turn, so they
    // INCLUDE the model's think-time and any tool round-trip, and are absent
    // entirely for transcript shapes without per-turn timestamps (Cursor's
    // `.txt` export). Consumers MUST treat them as low-confidence and tag them
    // as transcript-derived, never as a precise provider SLA.
    //
    // Raw components (not pre-divided) so they re-aggregate correctly when the
    // model-usage summary unions sessions per normalized model across agents:
    //   avg_turn_latency_ms        = turn_latency_ms_total / turn_latency_samples
    //   derived_tokens_per_second  = turn_output_tokens_total * 1000
    //                                  / turn_throughput_ms_total
    /// Sum of measured per-turn latencies (ms) over turns where both the
    /// assistant timestamp and a preceding trigger timestamp were present.
    pub turn_latency_ms_total: u64,
    /// Number of turns that contributed to `turn_latency_ms_total` (the divisor
    /// for the average; 0 when the transcript carried no usable timestamps).
    pub turn_latency_samples: u64,
    /// Slowest single measured turn latency (ms); the responsiveness tail.
    pub turn_latency_ms_max: u64,
    /// Output tokens summed over the subset of measured turns that had BOTH a
    /// positive latency AND output tokens (numerator for tokens/sec).
    pub turn_output_tokens_total: u64,
    /// Latency (ms) summed over that same throughput subset (denominator for
    /// tokens/sec); kept separate from `turn_latency_ms_total` because a turn
    /// can have a measurable latency yet zero output tokens.
    pub turn_throughput_ms_total: u64,
    /// Count of transcript lines carrying a canonical provider-error marker
    /// (`rate_limit` / `overloaded_error` / `server_error` /
    /// `service_unavailable` / `insufficient_quota` / `too_many_requests`).
    /// An inferred outage/throttle signal for the external agent's provider;
    /// distinct from `tool_errors` (which are local tool failures).
    pub inferred_provider_errors: u64,

    // ---- Per-MCP-server tool-call attribution (Workstream C Phase 2) --------
    //
    // Counts of tool invocations attributed to each MCP server, derived purely
    // from the tool name's `mcp__<server>__<tool>` convention (the standard MCP
    // namespacing used by Claude Code / Cursor / Codex when they expose an MCP
    // server's tools). Native agent tools (`Read`, `Edit`, `Bash`, ...) carry no
    // `mcp__` prefix and are NOT counted here -- only `tool_calls` (the
    // aggregate) includes them. This needs no MCP config file read: the server
    // identity is already encoded in the tool name the transcript records, which
    // is more robust than parsing a possibly-stale `~/.cursor/mcp.json` /
    // `~/.claude.json`. Empty when the session invoked no MCP-namespaced tool.
    pub mcp_calls_by_server: std::collections::BTreeMap<String, u64>,

    // ---- Skill / command / rule usage attribution (Self-Augmentation) -------
    //
    // Counts of skill-bearing invocations attributed to a normalized skill id,
    // one of `skill:<slug>`, `command:<slug>`, `rule:<slug>`, `subagent:<slug>`.
    // Derived deterministically from the transcript's structured tool calls --
    // explicit dispatch tools (`Skill`, `SlashCommand`, `Task`) and file-reads
    // of skill/command/rule artifacts (a progressive-disclosure load counts as
    // a use) -- plus leading `/command` tokens (and Claude Code's
    // `<command-name>` marker) in user turns. This is the "which skills am I
    // actually using" signal that the Self-Augmentation report joins against
    // the on-disk component inventory of AVAILABLE skills. Transcript-mined and
    // heuristic: explicit `Skill`/slash-command hits are high precision;
    // SKILL.md reads are a good proxy for progressive-disclosure loads. Empty
    // for transcript shapes with no recognizable skill activity (e.g. Cursor
    // `.txt` export with no tool blocks and no slash commands).
    pub skill_invocations_by_name: std::collections::BTreeMap<String, u64>,

    /// Absolute on-disk path a skill/command/rule artifact was actually read
    /// from during the session, keyed by the same normalized `kind:slug` id as
    /// `skill_invocations_by_name`. Populated only for invocations that were a
    /// file-read of the artifact (the path the agent opened); name-only dispatch
    /// (`Skill`, `SlashCommand`, `Task`) contributes no entry. This is the
    /// "observed path" signal the Self-Augmentation report uses to mark a used
    /// artifact as on-disk even when it lives in a sibling workspace root the
    /// session's `source_path` did not resolve to (multi-root Cursor sessions),
    /// and to render the artifact's parent folder in the capability graph. Only
    /// the path is retained, never file contents (I5 no-body-content invariant).
    /// Empty for transcripts with no file-read skill activity.
    pub skill_observed_paths: std::collections::BTreeMap<String, String>,

    /// Counts of tool invocations attributed to each tool name (native + MCP),
    /// e.g. `Read`, `Edit`, `Bash`, `mcp__edamame__get_score`. The per-tool
    /// breakdown behind the aggregate `tool_calls`, feeding the "most/least used
    /// tools" histogram. Empty for `.txt` transcripts that carry no structured
    /// tool blocks (consistent with `has_token_data == false`).
    pub tool_calls_by_name: std::collections::BTreeMap<String, u64>,

    // ---- Deterministic "path directness" / friction signals -----------------
    //
    // Passive, LLM-free proxies for "did the model go straight to the point, or
    // thrash back and forth". Derived from the per-turn `(tool, target)` call
    // sequence the transcript records -- NOT from any outcome/quality oracle, so
    // they measure observable REWORK, never "was the answer good". They are only
    // meaningful for structured `.jsonl` transcripts (Claude Code / Codex /
    // Claude Desktop / OpenClaw / Hermes) that carry typed `tool_use` /
    // `function_call` blocks; Cursor's `.txt` export has no such blocks so all
    // three stay zero/false for it (consistent with `has_token_data == false`).
    //
    /// Number of tool invocations whose `(tool_name, target)` signature already
    /// appeared earlier in the SAME session -- re-reading the same file,
    /// re-running the same command, re-grepping the same pattern. The purest
    /// "going in circles" signal. `<= tool_calls`.
    pub repeated_tool_calls: u64,
    /// Number of tool invocations whose `(tool_name, target)` signature had
    /// already ERRORED earlier in the same session (tried X, it failed, tried X
    /// again). A strict-superset-worse form of a one-off error. `<= tool_calls`.
    pub retried_after_error_calls: u64,
    /// True when the session's FINAL tool result was an error -- the last action
    /// the agent took failed and it did not recover before the transcript ended.
    /// A weak, aggregate-only "clean finish" proxy (a single session ending
    /// mid-work is noise; the RATE across many sessions of one model is the
    /// signal). False when the session had no tool results at all. Counts both
    /// explicitly-flagged errors (`is_error`) and content-inferred failures.
    pub ended_with_tool_error: bool,

    // ---- Content-inferred failures + run outcome + compaction + churn -------
    //
    // Deterministic signals that go beyond the provider's explicit error
    // flags. Many agents (Codex `shell`, Claude Code `Bash`) return a FAILED
    // command as a plain, unflagged `tool_result` whose content carries the
    // failure shape ("command not found", "No such file or directory",
    // non-zero exit code, a Python traceback). Counting only `is_error`
    // undercounts real friction on exactly the runs that need attention.
    //
    /// Number of tool results NOT flagged `is_error` whose content matched a
    /// conservative failure shape (anchored near the start of the result:
    /// "error:", "command not found", "permission denied", "no such file or
    /// directory", a traceback header, a non-zero exit-code marker, a rustc
    /// `error[E...]`). Disjoint from `tool_errors` (never double-counted).
    /// These ALSO feed the retry-after-error signature set and the
    /// `ended_with_tool_error` clean-finish proxy.
    pub inferred_tool_failures: u64,
    /// Role of the last transcript line that carried a non-empty prose text
    /// block (`"user"` / `"assistant"`; empty when the transcript had none).
    /// Tool-result carrier lines (role user with only `tool_result` blocks)
    /// do NOT update this -- it tracks actual conversation turns.
    pub last_text_role: String,
    /// Deterministic run-outcome classification:
    ///   * `"errored"`   -- the session's final tool result failed
    ///     (explicit or content-inferred) and the agent never recovered.
    ///   * `"abandoned"` -- the last prose turn was the USER's (a question or
    ///     instruction the agent never answered before the session went idle).
    ///   * `"completed"` -- the last prose turn was the assistant's and the
    ///     final tool result (if any) succeeded.
    ///   * `""`          -- unknown (no prose turns at all, e.g. empty file).
    /// Aggregate-only: one session's label is noise, the completion RATE
    /// across sessions is the signal (used by the augmentation leverage axis).
    pub run_outcome: String,
    /// Number of context-compaction boundaries observed mid-session (Claude
    /// Code `compact_boundary` / `isCompactSummary` markers, Codex `compacted`
    /// events, or the canonical "continued from a previous conversation"
    /// summary text). A compaction means the task OUTGREW the context window
    /// -- the causal, per-session form of the context-pressure signal that the
    /// static always-on token tax can only approximate.
    pub compaction_events: u64,
    /// Distinct files targeted by edit-class tools (`Edit`, `Write`,
    /// `StrReplace`, `ApplyPatch`, `MultiEdit`, notebook edits) this session.
    pub edited_file_count: u64,
    /// Edit-class calls whose target file had ALREADY been edited earlier in
    /// the same session -- rewrite churn ("wrote it, then rewrote it").
    /// `0` when every edited file was touched exactly once.
    pub re_edited_file_count: u64,
    /// Sorted, deduplicated secret-signature labels that matched anywhere in
    /// this session's transcript text (`private_key`, `github_token`,
    /// `aws_secret`, ...). Matching uses the high-precision
    /// `transcript_secret_signatures` tunable (vendor-anchored prefixes + PEM
    /// headers only), NOT the broader file-scan list. Labels only -- the
    /// matched content itself NEVER leaves the parser. Non-empty means
    /// secret material entered the agent's context window (BR-1 blast-radius
    /// amplifier: the LLM can exfiltrate it through any egress channel).
    pub secret_exposure_labels: Vec<String>,
    /// Total transcript secret-signature hits behind `secret_exposure_labels`.
    pub secret_exposure_hits: u64,
    /// Sorted, deduplicated prompt-injection bait labels that matched in this
    /// session's transcript text (`instruction_override`,
    /// `system_prompt_exfil`, `covert_instruction`, `role_override`).
    /// Matching uses the deterministic `prompt_injection_signatures` tunable.
    /// Non-empty means injection bait ENTERED the agent's context window --
    /// the OWASP ASI01/LLM01 leading indicator (BR-2). Labels only, never
    /// content.
    pub prompt_injection_labels: Vec<String>,
    /// Total prompt-injection signature hits behind `prompt_injection_labels`.
    pub prompt_injection_hits: u64,

    // ---- Craft heuristics (prompt / workflow quality; deterministic) --------
    //
    // The HUMAN side of the augmentation equation: how well the user drives
    // the agent. Computed by `craft::analyze_craft` from the session's user
    // prose turns and resolved tool-call sequence. All heuristic, LLM-free,
    // labels/scores only -- prompt content never leaves the parser. Only
    // meaningful when `craft_substantive_prompts > 0`; a session with no
    // substantive user prompt (control-only, tool-result carriers, empty
    // `.txt` export) leaves every dimension at 0 and `craft_intent_class`
    // empty, which consumers MUST treat as "not scored", never as an F.
    //
    /// Constraints dimension (0-100): 100 when the FIRST substantive prompt
    /// carries constraint language / spec structure, 50 when only a later
    /// prompt does, 0 when absent.
    pub prompt_maturity_constraints: u64,
    /// Success-criteria dimension (0-100), same front-loading grade.
    pub prompt_maturity_success_criteria: u64,
    /// Verification-language dimension (0-100), same front-loading grade.
    pub prompt_maturity_verification: u64,
    /// Context-provision dimension (0-100): file refs / code fences in the
    /// prompt (100/50 by position) or, failing that, 60 when the session ran
    /// context-gathering tools (read/grep/glob, `rg`/`git`/... exec calls).
    pub prompt_maturity_context: u64,
    /// Specificity dimension (0-100): first substantive prompt's length plus
    /// a structure bonus (headings/bullets/spec phrases).
    pub prompt_maturity_specificity: u64,
    /// Mean of the five maturity dimensions (0 when not scored).
    pub prompt_maturity_score: u64,
    /// Substantive (non-control) user prompts behind the maturity analysis.
    /// 0 means the craft block is "not scored" for this session.
    pub craft_substantive_prompts: u64,
    /// Prompts that exact-match or Jaccard-match (>= 0.85) an earlier prompt
    /// in the SAME session -- the user asking the same thing again.
    pub duplicate_prompt_count: u64,
    /// True when duplicate prompts co-occur with tool errors/retries: the
    /// user re-asking while the session fails (the stuck re-ask shape).
    pub stuck_reask: bool,
    /// User prompts reading as frustration (repeated `!!!`/`???`, hostile
    /// phrases, ALL-CAPS ratio) -- code fences stripped first so pasted logs
    /// never count as tone.
    pub frustration_marker_count: u64,
    /// True when the tool sequence shows a runaway loop: >= 5 identical
    /// consecutive signatures with >= 3 failures, or a 12-call window with
    /// >= 6 failures / a failure-heavy dominant-class saturation. Refines
    /// `repeated_tool_calls` into a hard "it is going in circles" flag.
    pub runaway_tool_loop: bool,
    /// `planning` / `implementation` / `debugging` / `review` /
    /// `exploration` from the first substantive prompt + edit activity;
    /// empty when not scored.
    pub craft_intent_class: String,
    /// True when the first substantive prompt has spec structure (headings,
    /// bullets, or canonical spec phrases).
    pub spec_driven_start: bool,
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
    let mut result = match agent_type {
        "cursor" => cursor::collect(home, options)?,
        "claude_code" => claude_code::collect(home, options)?,
        "claude_desktop" => claude_desktop::collect(home, options)?,
        "codex" => codex::collect(home, options)?,
        "hermes" => hermes::collect(home, options)?,
        "openclaw" => openclaw::collect(home, options)?,
        other => CollectResult {
            payload: empty_payload(other, home),
            diagnostics: CollectDiagnostics {
                transcripts_root_accessible: false,
                transcripts_roots: Vec::new(),
                hostname: hostname_string(),
            },
        },
    };

    // Populate the economics override (usage-bearing text the divergence
    // `raw_text` cannot carry) once, centrally, for every adapter. Runs on the
    // collection side where transcript files are reachable; the result (text +
    // truncation flag) rides to core in `CollectedRawSession::economics_raw_text`
    // / `economics_truncated`.
    for session in &mut result.payload.sessions {
        let resolved = economics_override_text(&session.source_path);
        session.economics_raw_text = resolved.text;
        session.economics_truncated = resolved.truncated;
    }

    Ok(result)
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

/// Bytes read from the START of an oversized transcript for the economics
/// override (early per-turn usage and the model/timestamp header).
const ECONOMICS_HEAD_BYTES: u64 = 10 * 1024 * 1024;
/// Bytes read from the END of an oversized transcript for the economics
/// override (the cumulative end-of-file usage snapshot, e.g. Codex
/// `total_token_usage`). HEAD + TAIL stays at the same `MAX_TRANSCRIPT_BYTES`
/// memory bound as the head-only read.
const ECONOMICS_TAIL_BYTES: u64 = 6 * 1024 * 1024;

/// True when the file is larger than the head-only transcript cap, i.e. a plain
/// [`read_transcript_capped`] would lose its end-of-file usage snapshot.
fn transcript_exceeds_cap(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.len() > MAX_TRANSCRIPT_BYTES)
        .unwrap_or(false)
}

/// Read a transcript for the economics parser, head+tail when it exceeds the
/// cap.
///
/// Within the cap this is identical to [`read_transcript_capped`]. Beyond it,
/// the head ([`ECONOMICS_HEAD_BYTES`]) preserves the session header and the
/// earliest per-turn usage records (Anthropic-style summation), and the tail
/// ([`ECONOMICS_TAIL_BYTES`]) preserves the final cumulative usage snapshot
/// (Codex `total_token_usage`, which only appears at EOF). The dropped middle
/// can split a JSON line at either seam; the economics parser skips
/// unparseable lines, and `from_utf8_lossy` repairs split multibyte sequences.
fn read_transcript_capped_tailed(path: &Path) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len <= MAX_TRANSCRIPT_BYTES {
        let mut buf = Vec::new();
        (&mut file)
            .take(MAX_TRANSCRIPT_BYTES)
            .read_to_end(&mut buf)?;
        return Ok(String::from_utf8_lossy(&buf).into_owned());
    }

    let mut head = Vec::new();
    (&mut file)
        .take(ECONOMICS_HEAD_BYTES)
        .read_to_end(&mut head)?;

    let tail_start = len.saturating_sub(ECONOMICS_TAIL_BYTES);
    file.seek(SeekFrom::Start(tail_start))?;
    let mut tail = Vec::new();
    (&mut file)
        .take(ECONOMICS_TAIL_BYTES)
        .read_to_end(&mut tail)?;

    let mut combined = String::from_utf8_lossy(&head).into_owned();
    combined.push('\n');
    combined.push_str(&String::from_utf8_lossy(&tail));
    Ok(combined)
}

/// Resolved economics override for one session: the usage-bearing transcript
/// text the economics parser should read instead of `raw_text`, plus whether
/// that text was produced by a head+tail read of an oversized transcript (the
/// middle was dropped, so per-turn summation may undercount).
struct EconomicsOverride {
    /// Usage-bearing text, or empty to mean "use `raw_text` directly".
    text: String,
    /// True when `text` came from a head+tail read of a transcript larger than
    /// [`MAX_TRANSCRIPT_BYTES`].
    truncated: bool,
}

/// Resolve the usage-bearing transcript text for the economics parser when
/// `raw_text` cannot carry exact usage, else an empty string ("use raw_text").
///
/// Runs on the collection side (standalone in-process or helper daemon), where
/// transcript files are reachable. The result is transported to core in
/// [`CollectedRawSession::economics_raw_text`] /
/// [`CollectedRawSession::economics_truncated`]. Two cases populate the text
/// (see those fields):
///   * G4 -- a `.txt` source (Cursor's divergence export) with a usage-bearing
///     `.jsonl` sibling: read the sibling. `truncated` reflects whether that
///     sibling itself exceeded the cap.
///   * G5 -- a transcript larger than [`MAX_TRANSCRIPT_BYTES`]: re-read it
///     head+tail so the cumulative EOF usage snapshot survives truncation, and
///     flag `truncated = true` (the dropped middle can undercount per-turn sums).
fn economics_override_text(source_path: &str) -> EconomicsOverride {
    if source_path.is_empty() {
        return EconomicsOverride {
            text: String::new(),
            truncated: false,
        };
    }
    let path = Path::new(source_path);

    if source_path.ends_with(".txt") {
        let jsonl = path.with_extension("jsonl");
        if jsonl.is_file() {
            if let Ok(text) = read_transcript_capped_tailed(&jsonl) {
                return EconomicsOverride {
                    text,
                    truncated: transcript_exceeds_cap(&jsonl),
                };
            }
        }
        // A `.txt`-only session carries no usage; raw_text is that same text.
        return EconomicsOverride {
            text: String::new(),
            truncated: false,
        };
    }

    if transcript_exceeds_cap(path) {
        if let Ok(text) = read_transcript_capped_tailed(path) {
            return EconomicsOverride {
                text,
                truncated: true,
            };
        }
    }
    EconomicsOverride {
        text: String::new(),
        truncated: false,
    }
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
