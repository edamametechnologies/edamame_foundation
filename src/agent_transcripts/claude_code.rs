//! Claude Code transcript adapter.

use std::path::Path;

use chrono::Utc;

use super::parsing::{
    classify_open_files_excluding_sensitive, classify_sensitive_paths, extract_commands,
    extract_paths, extract_ports, extract_tool_names, extract_traffic, parse_jsonl_transcript,
    parse_txt_transcript, ParsedTranscript,
};
use super::{
    datetime_from_secs, hostname_string, mtime_secs, observer_agent_instance_id,
    walk_files_with_suffix, CollectDiagnostics, CollectOptions, CollectResult, CollectedPayload,
    CollectedRawSession,
};

const CLAUDE_CODE_LLM_HOSTS: &[&str] = &[
    "api.anthropic.com:443",
    "api.openai.com:443",
    "amazonaws.com:443",
    "asn:CLOUDFLARENET",
    "asn:NOTION",
    "asn:MICROSOFT-CORP",
    "asn:AMAZON",
];

const CLAUDE_CODE_SCOPE_PARENT_PATHS: &[&str] = &[
    "*/claude",
    "*/claude-code",
    "*/bin/claude",
    "/usr/bin/claude",
    "/usr/local/bin/claude",
    "*/node",
    "*/node_modules/.bin/claude",
    "*/.local/bin/claude",
    "*/.nvm/",
    "*/.volta/",
    "*\\claude.exe",
    "*\\claude.cmd",
    "*\\bin\\claude",
    "*\\node.exe",
    "*\\node_modules\\.bin\\claude",
    "*\\.local\\bin\\claude",
    "*/windowsapps/",
    "*\\windowsapps\\",
    "*/appdata/local/programs/claude",
    "*\\appdata\\local\\programs\\claude",
    "*/program files/claude",
    "*\\program files\\claude",
    "/snap/bin/claude",
    "*/snap/claude/",
    "*/flatpak/",
    "*/nix/store/",
    "*/claude_code_edamame_mcp.mjs",
];

pub fn collect(home: &Path, options: &CollectOptions) -> anyhow::Result<CollectResult> {
    let projects_root = home.join(".claude").join("projects");
    let roots = vec![projects_root.clone()];
    let diagnostics = CollectDiagnostics {
        transcripts_root_accessible: projects_root.is_dir(),
        transcripts_roots: roots
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        hostname: hostname_string(),
    };
    build_payload(
        "claude_code",
        home,
        &projects_root,
        diagnostics,
        options,
        CLAUDE_CODE_LLM_HOSTS,
        CLAUDE_CODE_SCOPE_PARENT_PATHS,
    )
}

pub(crate) fn build_payload(
    agent_type: &str,
    home: &Path,
    primary_root: &Path,
    diagnostics: CollectDiagnostics,
    options: &CollectOptions,
    llm_hosts: &[&str],
    scope_parent_paths: &[&str],
) -> anyhow::Result<CollectResult> {
    let agent_instance_id = observer_agent_instance_id(agent_type, home);
    let now = Utc::now();

    let candidates = if diagnostics.transcripts_root_accessible {
        gather_jsonl_transcripts(primary_root, options)
    } else {
        Vec::new()
    };

    if candidates.is_empty() {
        return Ok(CollectResult {
            payload: CollectedPayload {
                window_start: now,
                window_end: now,
                agent_type: agent_type.to_string(),
                agent_instance_id,
                source_kind: agent_type.to_string(),
                sessions: Vec::new(),
            },
            diagnostics,
        });
    }

    let workspace_root = home.to_string_lossy().to_string();
    let home_str = home.to_string_lossy().to_string();
    let mut sessions: Vec<CollectedRawSession> = Vec::new();

    for candidate in candidates.into_iter().take(options.limit.max(1)) {
        let raw_text = match std::fs::read_to_string(&candidate.path) {
            Ok(text) => text,
            Err(_) => continue,
        };
        let parsed: ParsedTranscript = if candidate.is_jsonl {
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
        let traffic = extract_traffic(&combined, &commands, llm_hosts);
        let ports = extract_ports(&combined, &commands);
        let inferred = super::parsing::infer_process_paths(&commands, &workspace_root);
        let expected_open = classify_open_files_excluding_sensitive(&extracted_paths, &home_str);
        let _expected_sensitive = classify_sensitive_paths(&extracted_paths, &home_str);

        let session_id = transcript_session_id(&candidate.path);
        let title = first_non_empty_line(&parsed.user_text)
            .unwrap_or_else(|| format!("{} session {}", agent_type, session_id));
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
            derived_scope_parent_paths: scope_parent_paths
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            derived_scope_grandparent_paths: Vec::new(),
            derived_scope_any_lineage_paths: Vec::new(),
            derived_expected_open_files: expected_open,
            source_path: candidate.path.to_string_lossy().to_string(),
            started_at,
            modified_at,
        });
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
            agent_type: agent_type.to_string(),
            agent_instance_id,
            source_kind: agent_type.to_string(),
            sessions,
        },
        diagnostics,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct GenericTranscriptCandidate {
    pub path: std::path::PathBuf,
    pub is_jsonl: bool,
    pub mtime_secs: u64,
    pub birthtime_secs: u64,
}

pub(crate) fn gather_jsonl_transcripts(
    root: &Path,
    options: &CollectOptions,
) -> Vec<GenericTranscriptCandidate> {
    let mut files = walk_files_with_suffix(root, &[".jsonl", ".txt"], 4);
    files.retain(|path| matches_hint(path, &options.project_hints));

    let now = Utc::now().timestamp() as u64;
    // Strict active-window filter (see CollectOptions doc): a transcript
    // qualifies only if it was modified within `active_window_minutes` of
    // now. Older sessions have already had their intent ingested; pulling
    // them back in just contributes stale derived hints to the prompt.
    let active_cutoff = now.saturating_sub(options.active_window_minutes.saturating_mul(60));

    let mut candidates: Vec<GenericTranscriptCandidate> = files
        .into_iter()
        .filter_map(|path| {
            let mtime = mtime_secs(&path);
            if mtime < active_cutoff {
                return None;
            }
            let is_jsonl = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.eq_ignore_ascii_case("jsonl"))
                .unwrap_or(false);
            let birth = super::birthtime_secs(&path);
            Some(GenericTranscriptCandidate {
                path,
                is_jsonl,
                mtime_secs: mtime,
                birthtime_secs: if birth > 0 { birth } else { mtime },
            })
        })
        .collect();

    candidates.sort_by(|left, right| right.mtime_secs.cmp(&left.mtime_secs));
    candidates
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
