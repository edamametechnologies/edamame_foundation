//! OpenClaw transcript adapter. OpenClaw stores per-agent session transcripts
//! under `~/.openclaw/agents/<agent_name>/sessions/*.jsonl`. The CLI creates
//! the `agents/<name>` subtree on first run for any agent the operator
//! defines (default: `main`), so the observer enumerates every
//! `agents/<name>/sessions/` directory rather than relying on a fixed slug.
//!
//! When OpenClaw is not host-resident (running in Lima or remote), nothing
//! is collected and `transcripts_root_accessible=false` is reported. The
//! OpenClaw plugin's existing MCP push path is unaffected -- this adapter
//! only powers the external transcript observer's "discovered" signal.

use std::path::{Path, PathBuf};

use chrono::Utc;

use super::claude_code::{gather_jsonl_transcripts, GenericTranscriptCandidate};
use super::parsing::{
    classify_open_files_excluding_sensitive, classify_sensitive_paths, extract_commands,
    extract_paths, extract_ports, extract_tool_names, extract_traffic, ParsedTranscript,
};
use super::{
    datetime_from_secs, hostname_string, observer_agent_instance_id, CollectDiagnostics,
    CollectOptions, CollectResult, CollectedPayload, CollectedRawSession,
};

const OPENCLAW_LLM_HOSTS: &[&str] = &[
    "api.anthropic.com:443",
    "api.openai.com:443",
    "amazonaws.com:443",
    "asn:CLOUDFLARENET",
    "asn:AMAZON",
];

const OPENCLAW_SCOPE_PARENT_PATHS: &[&str] = &[
    "*/openclaw",
    "*/openclaw/cli",
    "*/.openclaw/",
    "*/.openclaw/edamame-openclaw/",
    "/usr/bin/openclaw",
    "/usr/local/bin/openclaw",
    "*/snap/openclaw/",
    "/snap/bin/openclaw",
    "*/node",
    "*\\node.exe",
];

pub fn collect(home: &Path, options: &CollectOptions) -> anyhow::Result<CollectResult> {
    let probed_roots = openclaw_session_roots(home);
    let accessible_roots: Vec<PathBuf> = probed_roots
        .iter()
        .filter(|p| is_sessions_dir(p))
        .cloned()
        .collect();
    let diagnostics = CollectDiagnostics {
        transcripts_root_accessible: !accessible_roots.is_empty(),
        transcripts_roots: probed_roots
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        hostname: hostname_string(),
    };

    let agent_instance_id = observer_agent_instance_id("openclaw", home);
    let now = Utc::now();
    // One fleet-wide workspace for host-resident OpenClaw: `~/.openclaw`.
    // Sessions under `agents/<name>/sessions/` have no `projects/<slug>`
    // segment, so without a hint they never join the Augmentation /
    // Enlightenment workspace strip (regression after the workspace-only
    // selector retired the per-agent filter).
    let workspace_hint = crate::supported_agents::find_supported_agent("openclaw")
        .and_then(|a| a.resolve_instruction_root_with_home(home))
        .filter(|p| p.is_dir())
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut candidates: Vec<GenericTranscriptCandidate> = Vec::new();
    for root in &accessible_roots {
        candidates.extend(gather_jsonl_transcripts(root, options));
    }
    // Re-sort across multi-agent collation so the most recent transcripts
    // win regardless of which agent subdir they came from.
    candidates.sort_by(|left, right| right.mtime_secs.cmp(&left.mtime_secs));

    if candidates.is_empty() {
        return Ok(CollectResult {
            payload: CollectedPayload {
                window_start: now,
                window_end: now,
                agent_type: "openclaw".to_string(),
                agent_instance_id,
                source_kind: "openclaw".to_string(),
                sessions: Vec::new(),
            },
            diagnostics,
        });
    }

    let workspace_root = home.to_string_lossy().to_string();
    let home_str = home.to_string_lossy().to_string();
    let mut sessions: Vec<CollectedRawSession> = Vec::new();

    for candidate in candidates.into_iter().take(options.limit.max(1)) {
        // Cached by (path, mtime, size): unchanged transcripts skip the whole
        // parse+extract build, and a session built under one window is reused
        // verbatim when the window widens (see cursor.rs for the full rationale).
        let session = match super::get_or_build_session(
            &candidate.path,
            candidate.is_jsonl,
            |parsed: ParsedTranscript| {
                let combined = format!(
                    "{}\n\n{}\n\n{}",
                    parsed.user_text, parsed.assistant_text, parsed.raw_text
                );
                let extracted_paths = extract_paths(&combined, &workspace_root);
                let tool_names = extract_tool_names(&parsed.raw_text, &parsed.assistant_text);
                let commands = extract_commands(&parsed.raw_text, &parsed.assistant_text);
                let traffic = extract_traffic(&combined, &commands, OPENCLAW_LLM_HOSTS);
                let ports = extract_ports(&combined, &commands);
                let inferred = super::parsing::infer_process_paths(&commands, &workspace_root);
                let expected_open =
                    classify_open_files_excluding_sensitive(&extracted_paths, &home_str);
                let _expected_sensitive = classify_sensitive_paths(&extracted_paths, &home_str);

                let session_id = transcript_session_id(&candidate.path);
                let title = first_non_empty_line(&parsed.user_text)
                    .unwrap_or_else(|| format!("OpenClaw session {}", session_id));
                let started_at = datetime_from_secs(candidate.birthtime_secs);
                let modified_at = datetime_from_secs(candidate.mtime_secs);

                CollectedRawSession {
                    session_key: session_id,
                    title,
                    user_text: parsed.user_text.clone(),
                    assistant_text: parsed.assistant_text.clone(),
                    raw_text: parsed.raw_text.clone(),
                    tool_names,
                    commands,
                    derived_expected_traffic: traffic,
                    derived_expected_local_open_ports: ports,
                    derived_expected_process_paths: inferred.process_paths,
                    derived_expected_parent_paths: inferred.parent_paths,
                    derived_expected_grandparent_paths: Vec::new(),
                    derived_scope_process_paths: Vec::new(),
                    derived_scope_parent_paths: OPENCLAW_SCOPE_PARENT_PATHS
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect(),
                    derived_scope_grandparent_paths: Vec::new(),
                    derived_scope_any_lineage_paths: super::agent_identity_lineage_paths(
                        "openclaw",
                        OPENCLAW_SCOPE_PARENT_PATHS,
                    ),
                    derived_expected_open_files: expected_open,
                    source_path: candidate.path.to_string_lossy().to_string(),
                    started_at,
                    modified_at,
                    economics_raw_text: String::new(),
                    economics_truncated: false,
                    context_tokens_used: None,
                    context_token_limit: None,
                    context_usage_percent: None,
                    workspace_hint: workspace_hint.clone(),
                }
            },
        ) {
            Some(session) => session,
            None => continue,
        };
        sessions.push(session);
    }

    let (window_start, window_end) = if sessions.is_empty() {
        (now, now)
    } else {
        let start = sessions.iter().map(|s| s.started_at).min().unwrap_or(now);
        let end = sessions.iter().map(|s| s.modified_at).max().unwrap_or(now);
        (start, end)
    };

    Ok(CollectResult {
        payload: CollectedPayload {
            window_start,
            window_end,
            agent_type: "openclaw".to_string(),
            agent_instance_id,
            source_kind: "openclaw".to_string(),
            sessions,
        },
        diagnostics,
    })
}

/// Enumerate every `~/.openclaw/agents/<name>/sessions/` directory.
///
/// OpenClaw's CLI creates one subtree per agent the operator defines, with
/// the default agent named `main`. We scan all subdirectories under
/// `agents/` rather than hardcoding a slug because:
///
/// - Operators routinely run multiple named agents in parallel
///   (`main`, `sales_marketing_machine`, etc. on this workstation).
/// - The session UUID-based filenames make cross-agent collisions
///   essentially impossible, so combining transcripts is safe.
///
/// When `~/.openclaw/agents/` does not exist (OpenClaw never run on this
/// host), we still surface that path in the diagnostics so the operator
/// can see where we look. The caller filters with [`is_sessions_dir`] to
/// decide whether anything is actually accessible.
fn openclaw_session_roots(home: &Path) -> Vec<PathBuf> {
    let agents_dir = home.join(".openclaw").join("agents");
    let mut roots = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&agents_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                roots.push(path.join("sessions"));
            }
        }
    }
    // Stable diagnostic ordering across runs.
    roots.sort();

    if roots.is_empty() {
        // Surface the parent so operators can see where the observer is
        // probing even when no agents have been provisioned yet.
        roots.push(agents_dir);
    }

    roots
}

fn is_sessions_dir(path: &Path) -> bool {
    path.is_dir() && path.file_name().and_then(|n| n.to_str()) == Some("sessions")
}

fn transcript_session_id(path: &Path) -> String {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if let Some(stem) = name.strip_suffix(".jsonl") {
        return stem.to_string();
    }
    if let Some(stem) = name.strip_suffix(".txt") {
        return stem.to_string();
    }
    name.to_string()
}

fn first_non_empty_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !(line.starts_with('<') && line.ends_with('>')))
        .map(str::to_string)
}
