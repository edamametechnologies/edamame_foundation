//! OpenClaw transcript adapter. Best-effort host-resident: OpenClaw runs in
//! Lima or remote, so on most developer workstations there will be nothing
//! to collect. We probe a small set of plausible directories under
//! `~/.openclaw/` and return an empty payload when nothing is found.
//!
//! When OpenClaw is not host-resident, the OpenClaw plugin's existing MCP
//! path keeps working unchanged; the host observer simply reports
//! `transcripts_root_accessible=false` in diagnostics.

use std::path::{Path, PathBuf};

use chrono::Utc;

use super::claude_code::{gather_jsonl_transcripts, GenericTranscriptCandidate};
use super::parsing::{
    classify_open_files_excluding_sensitive, classify_sensitive_paths, extract_commands,
    extract_paths, extract_ports, extract_tool_names, extract_traffic, parse_jsonl_transcript,
    parse_txt_transcript, ParsedTranscript,
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
    let candidate_roots = openclaw_session_roots(home);
    let accessible_root = candidate_roots.iter().find(|p| p.is_dir()).cloned();
    let mut diagnostics = CollectDiagnostics {
        transcripts_root_accessible: accessible_root.is_some(),
        transcripts_roots: candidate_roots
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        hostname: hostname_string(),
    };

    let agent_instance_id = observer_agent_instance_id("openclaw", home);
    let now = Utc::now();

    let candidates: Vec<GenericTranscriptCandidate> = if let Some(root) = accessible_root.as_ref() {
        gather_jsonl_transcripts(root, options)
    } else {
        Vec::new()
    };

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
        let traffic = extract_traffic(&combined, &commands, OPENCLAW_LLM_HOSTS);
        let ports = extract_ports(&combined, &commands);
        let inferred = super::parsing::infer_process_paths(&commands, &workspace_root);
        let expected_open = classify_open_files_excluding_sensitive(&extracted_paths, &home_str);
        let _expected_sensitive = classify_sensitive_paths(&extracted_paths, &home_str);

        let session_id = transcript_session_id(&candidate.path);
        let title = first_non_empty_line(&parsed.user_text)
            .unwrap_or_else(|| format!("OpenClaw session {}", session_id));
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
            derived_scope_parent_paths: OPENCLAW_SCOPE_PARENT_PATHS
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

    diagnostics.transcripts_root_accessible = accessible_root.is_some();

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

fn openclaw_session_roots(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".openclaw/sessions"),
        home.join(".openclaw/edamame-openclaw/sessions"),
        home.join(".openclaw/state/sessions"),
    ]
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
