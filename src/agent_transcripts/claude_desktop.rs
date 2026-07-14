//! Claude Desktop transcript adapter. Pulls from the platform-specific
//! local agent mode session directory.

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

const CLAUDE_DESKTOP_LLM_HOSTS: &[&str] = &[
    "api.anthropic.com:443",
    "api.openai.com:443",
    "amazonaws.com:443",
    "asn:CLOUDFLARENET",
    "asn:NOTION",
    "asn:MICROSOFT-CORP",
    "asn:AMAZON",
];

const CLAUDE_DESKTOP_SCOPE_PARENT_PATHS: &[&str] = &[
    "*/Claude.app/Contents/MacOS/Claude",
    "*/Claude.app/Contents/MacOS/*",
    "*/Claude/Claude.exe",
    "*\\Claude\\Claude.exe",
    "*/Claude.exe",
    "*\\Claude.exe",
    "*/WindowsApps/Claude*",
    "*\\WindowsApps\\Claude*",
    "*/Program Files/WindowsApps/Claude*",
    "*\\Program Files\\WindowsApps\\Claude*",
    "*/Program Files/Anthropic*",
    "*\\Program Files\\Anthropic*",
    "*/AppData/Local/Programs/Claude",
    "*\\AppData\\Local\\Programs\\Claude",
    "/opt/claude*",
    "*/.local/share/claude*",
    "/usr/bin/claude",
    "/usr/local/bin/claude",
    "/snap/claude/",
    "*/snap/claude/",
    "*/flatpak/",
    "/tmp/.mount_claude",
    "*/node",
    "*/node.exe",
    "*\\node.exe",
    "*/claude_desktop_edamame_mcp.mjs",
];

pub fn collect(home: &Path, options: &CollectOptions) -> anyhow::Result<CollectResult> {
    let cowork_root = cowork_sessions_root(home);

    let roots: Vec<PathBuf> = vec![cowork_root.clone()];
    let mut diagnostics = CollectDiagnostics {
        transcripts_root_accessible: cowork_root.is_dir(),
        transcripts_roots: roots
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        hostname: hostname_string(),
    };

    let agent_instance_id = observer_agent_instance_id("claude_desktop", home);
    let now = Utc::now();

    let mut candidates: Vec<GenericTranscriptCandidate> = Vec::new();
    if cowork_root.is_dir() {
        candidates.extend(gather_jsonl_transcripts(&cowork_root, options));
    }
    candidates.sort_by(|left, right| right.mtime_secs.cmp(&left.mtime_secs));

    if candidates.is_empty() {
        return Ok(CollectResult {
            payload: CollectedPayload {
                window_start: now,
                window_end: now,
                agent_type: "claude_desktop".to_string(),
                agent_instance_id,
                source_kind: "claude_desktop".to_string(),
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
                let traffic = extract_traffic(&combined, &commands, CLAUDE_DESKTOP_LLM_HOSTS);
                let ports = extract_ports(&combined, &commands);
                let inferred = super::parsing::infer_process_paths(&commands, &workspace_root);
                let expected_open =
                    classify_open_files_excluding_sensitive(&extracted_paths, &home_str);
                let _expected_sensitive = classify_sensitive_paths(&extracted_paths, &home_str);

                let session_id = transcript_session_id(&candidate.path);
                let title = first_non_empty_line(&parsed.user_text)
                    .unwrap_or_else(|| format!("Claude Desktop session {}", session_id));
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
                    derived_scope_parent_paths: CLAUDE_DESKTOP_SCOPE_PARENT_PATHS
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect(),
                    derived_scope_grandparent_paths: Vec::new(),
                    derived_scope_any_lineage_paths: super::agent_identity_lineage_paths(
                        "claude_desktop",
                        CLAUDE_DESKTOP_SCOPE_PARENT_PATHS,
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

    diagnostics.transcripts_root_accessible = cowork_root.is_dir();

    Ok(CollectResult {
        payload: CollectedPayload {
            window_start,
            window_end,
            agent_type: "claude_desktop".to_string(),
            agent_instance_id,
            source_kind: "claude_desktop".to_string(),
            sessions,
        },
        diagnostics,
    })
}

fn cowork_sessions_root(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support/Claude/local-agent-mode-sessions")
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|appdata| {
                std::path::PathBuf::from(appdata).join("Claude/local-agent-mode-sessions")
            })
            .unwrap_or_else(|| home.join("AppData/Roaming/Claude/local-agent-mode-sessions"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_DATA_HOME")
            .ok()
            .map(|xdg| {
                std::path::PathBuf::from(xdg).join("claude-desktop/local-agent-mode-sessions")
            })
            .unwrap_or_else(|| home.join(".local/share/claude-desktop/local-agent-mode-sessions"))
    }
    // Mobile fallback: Claude Desktop is not installed on iOS / Android, so
    // the path is a non-existent placeholder. The adapter detects the
    // missing root and returns an empty payload + diagnostics.
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        home.join(".claude-desktop/local-agent-mode-sessions")
    }
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
