//! Cursor transcript adapter.
//!
//! Mirrors the JS adapter at
//! `edamame_cursor/adapters/session_prediction_adapter.mjs`.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use super::parsing::{
    classify_open_files_excluding_sensitive, classify_sensitive_paths, extract_commands,
    extract_paths, extract_ports, extract_tool_names, extract_traffic, parse_jsonl_transcript,
    parse_txt_transcript, ParsedTranscript,
};
use super::{
    birthtime_secs, datetime_from_secs, hostname_string, mtime_secs, observer_agent_instance_id,
    walk_files_with_suffix, CollectDiagnostics, CollectOptions, CollectResult, CollectedPayload,
    CollectedRawSession,
};

/// `cursorLlmHosts` from `edamame_cursor/service/config.mjs`.
const CURSOR_LLM_HOSTS: &[&str] = &[
    "cursor.sh:443",
    "api.openai.com:443",
    "api.anthropic.com:443",
    "amazonaws.com:443",
    "awsglobalaccelerator.com:443",
    "asn:CLOUDFLARENET",
    "asn:NOTION",
    "asn:MICROSOFT-CORP",
    "asn:AMAZON",
];

/// `scopeParentPaths` from `edamame_cursor/service/config.mjs`.
const CURSOR_SCOPE_PARENT_PATHS: &[&str] = &[
    "*/Cursor.app/Contents/MacOS/Cursor",
    "*/Cursor Helper*",
    "*/Cursor/Cursor.exe",
    "*\\Cursor\\Cursor.exe",
    "*/Cursor/Cursor Helper*.exe",
    "*\\Cursor\\Cursor Helper*.exe",
    "*/Programs/Cursor/",
    "*\\Programs\\Cursor\\",
    "*/AppData/Local/Programs/Cursor",
    "*\\AppData\\Local\\Programs\\Cursor",
    "*/WindowsApps/Cursor*",
    "*\\WindowsApps\\Cursor*",
    "/tmp/.mount_cursor*",
    "*/cursor/cursor",
    "/opt/cursor*",
    "*/.local/bin/cursor",
    "/usr/bin/cursor",
    "/usr/local/bin/cursor",
    "*/flatpak/",
    "/snap/bin/cursor",
    "*/snap/cursor/",
    "*/node",
    "*/node.exe",
    "*\\node.exe",
    "*/cursor_edamame_mcp.mjs",
];

pub fn collect(home: &Path, options: &CollectOptions) -> anyhow::Result<CollectResult> {
    let projects_root = home.join(".cursor").join("projects");
    let roots = vec![projects_root.clone()];
    let mut diagnostics = CollectDiagnostics {
        transcripts_root_accessible: projects_root.is_dir(),
        transcripts_roots: roots
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        hostname: hostname_string(),
    };

    let candidates = if diagnostics.transcripts_root_accessible {
        gather_cursor_transcripts(&projects_root, options)
    } else {
        Vec::new()
    };

    let agent_instance_id = observer_agent_instance_id("cursor", home);
    let now = Utc::now();
    if candidates.is_empty() {
        return Ok(CollectResult {
            payload: CollectedPayload {
                window_start: now,
                window_end: now,
                agent_type: "cursor".to_string(),
                agent_instance_id,
                source_kind: "cursor".to_string(),
                sessions: Vec::new(),
            },
            diagnostics,
        });
    }

    let workspace_root = home.to_string_lossy().to_string();
    let home_str = home.to_string_lossy().to_string();
    let mut sessions: Vec<CollectedRawSession> = Vec::new();

    for candidate in candidates.into_iter().take(options.limit.max(1)) {
        let raw_text = match std::fs::read_to_string(&candidate.preferred_source) {
            Ok(text) => text,
            Err(_) => continue,
        };
        let parsed: ParsedTranscript = if candidate.preferred_source_is_jsonl {
            parse_jsonl_transcript(&raw_text)
        } else {
            parse_txt_transcript(&raw_text)
        };

        let combined = format!(
            "{}\n\n{}\n\n{}",
            parsed.user_text, parsed.assistant_text, parsed.raw_text
        );
        let extracted_paths = extract_paths(&combined, &workspace_root);
        let tool_names = extract_tool_names(&parsed.raw_text, &parsed.assistant_text);
        let commands = extract_commands(&parsed.raw_text, &parsed.assistant_text);
        let traffic = extract_traffic(&combined, &commands, CURSOR_LLM_HOSTS);
        let ports = extract_ports(&combined, &commands);
        let inferred = super::parsing::infer_process_paths(&commands, &workspace_root);
        let expected_open = classify_open_files_excluding_sensitive(&extracted_paths, &home_str);
        let _expected_sensitive = classify_sensitive_paths(&extracted_paths, &home_str);

        let session_id = transcript_session_id(&candidate.preferred_source);
        let title = first_non_empty_line(&parsed.user_text)
            .unwrap_or_else(|| format!("Cursor session {}", session_id));
        let started_at = datetime_from_secs(candidate.birthtime_secs);
        let modified_at = datetime_from_secs(candidate.mtime_secs);

        sessions.push(CollectedRawSession {
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
            derived_scope_parent_paths: CURSOR_SCOPE_PARENT_PATHS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            derived_scope_grandparent_paths: Vec::new(),
            derived_scope_any_lineage_paths: Vec::new(),
            derived_expected_open_files: expected_open,
            source_path: candidate.preferred_source.to_string_lossy().to_string(),
            started_at,
            modified_at,
        });
    }

    let (window_start, window_end) = window_bounds(&sessions, now);
    diagnostics.transcripts_root_accessible = projects_root.is_dir();

    Ok(CollectResult {
        payload: CollectedPayload {
            window_start,
            window_end,
            agent_type: "cursor".to_string(),
            agent_instance_id,
            source_kind: "cursor".to_string(),
            sessions,
        },
        diagnostics,
    })
}

#[derive(Debug, Clone)]
struct TranscriptCandidate {
    preferred_source: PathBuf,
    preferred_source_is_jsonl: bool,
    mtime_secs: u64,
    birthtime_secs: u64,
}

fn gather_cursor_transcripts(root: &Path, options: &CollectOptions) -> Vec<TranscriptCandidate> {
    let mut files = walk_files_with_suffix(root, &[".txt", ".jsonl"], 6);
    files.retain(|path| {
        path.to_string_lossy().contains("agent-transcripts")
            && matches_hint(path, &options.project_hints)
    });

    let now_secs = Utc::now().timestamp() as u64;
    // Strict active-window filter: only include sessions modified within
    // `active_window_minutes` of now. A 38-hour-old chat is concluded work
    // whose intent was already ingested earlier; re-including it just
    // bloats the prompt with stale derived paths/commands.
    let active_cutoff = now_secs.saturating_sub(options.active_window_minutes.saturating_mul(60));

    let mut by_session: std::collections::HashMap<String, TranscriptGroup> =
        std::collections::HashMap::new();
    for path in files {
        let mtime = mtime_secs(&path);
        if mtime < active_cutoff {
            continue;
        }
        let session_id = transcript_session_id(&path);
        let entry = by_session.entry(session_id).or_default();
        let is_jsonl = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.eq_ignore_ascii_case("jsonl"))
            .unwrap_or(false);
        let birth = birthtime_secs(&path);
        if is_jsonl {
            if mtime >= entry.jsonl_mtime {
                entry.jsonl_path = Some(path.clone());
                entry.jsonl_mtime = mtime;
            }
        } else if mtime >= entry.txt_mtime {
            entry.txt_path = Some(path.clone());
            entry.txt_mtime = mtime;
        }
        entry.latest_mtime = entry.latest_mtime.max(mtime);
        entry.earliest_birth = if entry.earliest_birth == 0 {
            birth
        } else if birth == 0 {
            entry.earliest_birth
        } else {
            entry.earliest_birth.min(birth)
        };
    }

    let mut candidates: Vec<TranscriptCandidate> = by_session
        .into_values()
        .filter(|group| group.latest_mtime > 0)
        .map(|group| {
            let (preferred, is_jsonl) = match (&group.txt_path, &group.jsonl_path) {
                (Some(txt), Some(jsonl)) => {
                    if group.txt_mtime >= group.jsonl_mtime {
                        (txt.clone(), false)
                    } else {
                        (jsonl.clone(), true)
                    }
                }
                (Some(txt), None) => (txt.clone(), false),
                (None, Some(jsonl)) => (jsonl.clone(), true),
                (None, None) => return None,
            };
            Some(TranscriptCandidate {
                preferred_source: preferred,
                preferred_source_is_jsonl: is_jsonl,
                mtime_secs: group.latest_mtime,
                birthtime_secs: if group.earliest_birth > 0 {
                    group.earliest_birth
                } else {
                    group.latest_mtime
                },
            })
        })
        .flatten()
        .collect();

    candidates.sort_by(|left, right| right.mtime_secs.cmp(&left.mtime_secs));
    candidates
}

#[derive(Debug, Clone, Default)]
struct TranscriptGroup {
    txt_path: Option<PathBuf>,
    txt_mtime: u64,
    jsonl_path: Option<PathBuf>,
    jsonl_mtime: u64,
    latest_mtime: u64,
    earliest_birth: u64,
}

fn matches_hint(path: &Path, hints: &[String]) -> bool {
    if hints.is_empty() {
        return true;
    }
    let lower = path.to_string_lossy().to_lowercase();
    hints
        .iter()
        .any(|hint| lower.contains(&hint.to_lowercase()))
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

fn window_bounds(
    sessions: &[CollectedRawSession],
    fallback: DateTime<Utc>,
) -> (DateTime<Utc>, DateTime<Utc>) {
    if sessions.is_empty() {
        return (fallback, fallback);
    }
    let start = sessions
        .iter()
        .map(|s| s.started_at)
        .min()
        .unwrap_or(fallback);
    let end = sessions
        .iter()
        .map(|s| s.modified_at)
        .max()
        .unwrap_or(fallback);
    (start, end)
}
