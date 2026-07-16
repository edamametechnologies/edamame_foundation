//! Hermes Agent transcript adapter.
//!
//! Hermes (Nous Research, an OpenClaw successor) installs to `~/.hermes` and
//! stores session history in a SQLite+FTS5 database, alongside a
//! `sessions.json` manifest and -- in some builds -- per-session JSON/JSONL
//! transcript files. The L1 host-side observer deliberately does NOT link a
//! SQLite driver (foundation carries no sqlite dependency and these adapters
//! must compile on iOS/Android, where they return empty). Instead it:
//!
//!   1. Marks Hermes "discovered" whenever ANY recognizable Hermes session
//!      store or config file is present (`transcripts_root_accessible`). This
//!      is what drives the `unsecured_hermes` internal threat, so it must be
//!      true even for SQLite-only installs we cannot yet ingest.
//!   2. Best-effort ingests any on-disk JSON-lines / `.txt` transcripts (via
//!      the shared `gather_jsonl_transcripts` walk) plus a tolerant
//!      `sessions.json` manifest reader.
//!
//! Full SQLite ingestion (and off-host Hermes coverage) is the L2
//! `edamame_hermes` Node extrapolator's job, which links `better-sqlite3` and
//! pushes through `upsert_behavioral_model_from_raw_sessions`. The observer is
//! additive; core-side hash-skip prevents redundant LLM work when both
//! producers emit equivalent payloads.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::codex::{gather_jsonl_transcripts, GenericTranscriptCandidate};
use super::parsing::{
    classify_open_files_excluding_sensitive, classify_sensitive_paths, extract_commands,
    extract_paths, extract_ports, extract_tool_names, extract_traffic, infer_process_paths,
    parse_txt_transcript, ParsedTranscript,
};
use super::{
    datetime_from_secs, hostname_string, mtime_secs, observer_agent_instance_id,
    CollectDiagnostics, CollectOptions, CollectResult, CollectedPayload, CollectedRawSession,
};

const HERMES_LLM_HOSTS: &[&str] = &[
    "api.anthropic.com:443",
    "api.openai.com:443",
    "openrouter.ai:443",
    "api.nousresearch.com:443",
    "inference.nousresearch.com:443",
    "amazonaws.com:443",
    "asn:CLOUDFLARENET",
    "asn:AMAZON",
];

const HERMES_SCOPE_PARENT_PATHS: &[&str] = &[
    "*/hermes",
    "*/bin/hermes",
    "/usr/bin/hermes",
    "/usr/local/bin/hermes",
    "*/.hermes/",
    "*/.local/bin/hermes",
    "*/python",
    "*/python3",
    "*/.venv/bin/python",
    "*/node",
    "*\\hermes.exe",
    "*\\hermes.cmd",
    "*\\bin\\hermes",
    "*\\python.exe",
    "*\\node.exe",
    "*/snap/hermes/",
    "/snap/bin/hermes",
    "*/hermes_edamame_mcp.mjs",
];

pub fn collect(home: &Path, options: &CollectOptions) -> anyhow::Result<CollectResult> {
    let hermes_home = resolve_hermes_home(home);
    let roots = session_roots(&hermes_home);
    let manifest = hermes_home.join("sessions.json");

    let mut probed: Vec<String> = roots
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    probed.push(manifest.to_string_lossy().to_string());

    let diagnostics = CollectDiagnostics {
        transcripts_root_accessible: hermes_store_present(&hermes_home),
        transcripts_roots: probed,
        hostname: hostname_string(),
    };

    let agent_instance_id = observer_agent_instance_id("hermes", home);
    let now = Utc::now();
    let workspace_root = home.to_string_lossy().to_string();
    let home_str = home.to_string_lossy().to_string();
    let limit = options.limit.max(1);

    // 1) File-based JSONL / TXT transcripts across candidate roots.
    let mut candidates: Vec<GenericTranscriptCandidate> = Vec::new();
    for root in &roots {
        if root.is_dir() {
            candidates.extend(gather_jsonl_transcripts(root, options));
        }
    }
    candidates.sort_by(|left, right| right.mtime_secs.cmp(&left.mtime_secs));
    let mut seen_paths: BTreeSet<PathBuf> = BTreeSet::new();
    candidates.retain(|candidate| seen_paths.insert(candidate.path.clone()));

    let mut sessions: Vec<CollectedRawSession> = Vec::new();
    for candidate in candidates.into_iter().take(limit) {
        // Cached by (path, mtime, size): `build_session` is a pure function of
        // the transcript bytes plus the per-host-constant `workspace_root`/
        // `home_str`, so unchanged transcripts skip the parse+extract build and
        // a session built under one window is reused verbatim when the window
        // widens.
        let session = match super::get_or_build_session(
            &candidate.path,
            candidate.is_jsonl,
            |parsed: ParsedTranscript| {
                let inputs = SessionInputs {
                    session_key: transcript_session_id(&candidate.path),
                    title_hint: None,
                    user_text: parsed.user_text,
                    assistant_text: parsed.assistant_text,
                    raw_text: parsed.raw_text,
                    source_path: candidate.path.to_string_lossy().to_string(),
                    started_at: datetime_from_secs(candidate.birthtime_secs),
                    modified_at: datetime_from_secs(candidate.mtime_secs),
                };
                build_session(inputs, &workspace_root, &home_str)
            },
        ) {
            Some(session) => session,
            None => continue,
        };
        sessions.push(session);
    }

    // 2) Tolerant sessions.json manifest reader. File transcripts take
    //    priority; the manifest only fills any remaining headroom under the
    //    limit (and contributes nothing when no manifest exists).
    if sessions.len() < limit {
        let remaining = limit - sessions.len();
        let manifest_sessions =
            sessions_from_manifest(&manifest, options, &workspace_root, &home_str, remaining);
        let mut existing_keys: BTreeSet<String> =
            sessions.iter().map(|s| s.session_key.clone()).collect();
        for session in manifest_sessions {
            if existing_keys.insert(session.session_key.clone()) {
                sessions.push(session);
            }
        }
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
            agent_type: "hermes".to_string(),
            agent_instance_id,
            source_kind: "hermes".to_string(),
            sessions,
        },
        diagnostics,
    })
}

/// Resolve the Hermes home directory. `HERMES_HOME` overrides the default
/// `~/.hermes`. On Windows, fall back to `%LOCALAPPDATA%\hermes` when the
/// default does not exist.
fn resolve_hermes_home(home: &Path) -> PathBuf {
    if let Ok(custom) = std::env::var("HERMES_HOME") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let default = home.join(".hermes");
    #[cfg(target_os = "windows")]
    {
        if !default.exists() {
            if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
                let alt = PathBuf::from(localappdata).join("hermes");
                if alt.exists() {
                    return alt;
                }
            }
        }
    }
    default
}

/// Candidate transcript roots. Prefer the dedicated `sessions/` (and
/// `projects/`) subtree; only fall back to scanning the Hermes home directly
/// when no `sessions/` directory exists, to avoid double-walking.
fn session_roots(hermes_home: &Path) -> Vec<PathBuf> {
    let sessions = hermes_home.join("sessions");
    if sessions.is_dir() {
        let mut roots = vec![sessions];
        let projects = hermes_home.join("projects");
        if projects.is_dir() {
            roots.push(projects);
        }
        roots
    } else {
        vec![hermes_home.to_path_buf()]
    }
}

/// Hermes is "discovered" (host-resident) when any recognizable session store
/// or its config file is present. Independent of whether we can ingest the
/// content, so SQLite-only installs still fire `unsecured_hermes`.
fn hermes_store_present(hermes_home: &Path) -> bool {
    if !hermes_home.exists() {
        return false;
    }
    if hermes_home.join("sessions").is_dir() {
        return true;
    }
    if hermes_home.join("projects").is_dir() {
        return true;
    }
    if hermes_home.join("sessions.json").is_file() {
        return true;
    }
    if hermes_home.join("config.yaml").is_file() || hermes_home.join("config.yml").is_file() {
        return true;
    }
    has_sqlite_db(hermes_home) || has_sqlite_db(&hermes_home.join("sessions"))
}

fn has_sqlite_db(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.path().file_name().and_then(|n| n.to_str()) {
            let lower = name.to_ascii_lowercase();
            if lower.ends_with(".db") || lower.ends_with(".sqlite") || lower.ends_with(".sqlite3") {
                return true;
            }
        }
    }
    false
}

struct SessionInputs {
    session_key: String,
    title_hint: Option<String>,
    user_text: String,
    assistant_text: String,
    raw_text: String,
    source_path: String,
    started_at: DateTime<Utc>,
    modified_at: DateTime<Utc>,
}

fn build_session(
    inputs: SessionInputs,
    workspace_root: &str,
    home_str: &str,
) -> CollectedRawSession {
    let combined = format!(
        "{}\n\n{}\n\n{}",
        inputs.user_text, inputs.assistant_text, inputs.raw_text
    );
    let extracted_paths = extract_paths(&combined, workspace_root);
    let tool_names = extract_tool_names(&inputs.raw_text, &inputs.assistant_text);
    let commands = extract_commands(&inputs.raw_text, &inputs.assistant_text);
    let traffic = extract_traffic(&combined, &commands, HERMES_LLM_HOSTS);
    let ports = extract_ports(&combined, &commands);
    let inferred = infer_process_paths(&commands, workspace_root);
    let expected_open = classify_open_files_excluding_sensitive(&extracted_paths, home_str);
    let _expected_sensitive = classify_sensitive_paths(&extracted_paths, home_str);

    let title = inputs
        .title_hint
        .filter(|hint| !hint.trim().is_empty())
        .or_else(|| first_non_empty_line(&inputs.user_text))
        .unwrap_or_else(|| format!("Hermes session {}", inputs.session_key));

    CollectedRawSession {
        session_key: inputs.session_key,
        title,
        user_text: inputs.user_text,
        assistant_text: inputs.assistant_text,
        raw_text: inputs.raw_text,
        tool_names,
        commands,
        derived_expected_traffic: traffic,
        derived_expected_local_open_ports: ports,
        derived_expected_process_paths: inferred.process_paths,
        derived_expected_parent_paths: inferred.parent_paths,
        derived_expected_grandparent_paths: Vec::new(),
        derived_scope_process_paths: Vec::new(),
        derived_scope_parent_paths: HERMES_SCOPE_PARENT_PATHS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        derived_scope_grandparent_paths: Vec::new(),
        derived_scope_any_lineage_paths: super::agent_identity_lineage_paths(
            "hermes",
            HERMES_SCOPE_PARENT_PATHS,
        ),
        derived_expected_open_files: expected_open,
        source_path: inputs.source_path,
        started_at: inputs.started_at,
        modified_at: inputs.modified_at,
        economics_raw_text: String::new(),
        economics_truncated: false,
        context_tokens_used: None,
        context_token_limit: None,
        context_usage_percent: None,
        // Hermes manifests do not expose a per-session working directory yet.
        workspace_hint: String::new(),
    }
}

/// Best-effort reader for a Hermes `sessions.json` manifest. Tolerant of the
/// several shapes Hermes builds might emit (array of sessions, `{sessions:[]}`,
/// `{sessions:{}}`, an id->session map, or a single session object). Never
/// errors out the whole collect pass; malformed entries are skipped.
fn sessions_from_manifest(
    manifest_path: &Path,
    options: &CollectOptions,
    workspace_root: &str,
    home_str: &str,
    remaining: usize,
) -> Vec<CollectedRawSession> {
    if remaining == 0 {
        return Vec::new();
    }
    // Capped read: a malformed / adversarial manifest cannot exhaust memory.
    // A real Hermes manifest is well under the cap; a truncated oversized one
    // fails the JSON parse below and is skipped gracefully.
    let Ok(raw) = super::read_transcript_capped(manifest_path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return Vec::new();
    };

    let manifest_mtime = mtime_secs(manifest_path);
    let now = Utc::now().timestamp() as u64;
    let active_cutoff = now.saturating_sub(options.active_window_minutes.saturating_mul(60));

    let mut built: Vec<(u64, CollectedRawSession)> = Vec::new();
    for (key_hint, obj) in normalize_manifest_entries(value) {
        if !obj.is_object() {
            continue;
        }
        let started = manifest_field_time(
            &obj,
            &[
                "created_at",
                "started_at",
                "created",
                "start",
                "timestamp",
                "ts",
            ],
        );
        let modified = manifest_field_time(
            &obj,
            &[
                "updated_at",
                "modified_at",
                "modified",
                "last_active",
                "last_activity",
                "updated",
                "ended_at",
                "end",
            ],
        );
        let modified_secs = modified.or(started).unwrap_or(manifest_mtime);
        if modified_secs < active_cutoff {
            continue;
        }
        let started_secs = started.unwrap_or(modified_secs);

        let (user_text, assistant_text, raw_text) = manifest_text(&obj);
        if user_text.trim().is_empty()
            && assistant_text.trim().is_empty()
            && raw_text.trim().is_empty()
        {
            // Pure metadata row with no usable transcript text.
            continue;
        }

        let session_key = obj_str(&obj, &["id", "session_id", "sessionId", "uuid", "key"])
            .or(key_hint)
            .unwrap_or_else(|| format!("hermes-manifest-{modified_secs}"));
        let title_hint = obj_str(&obj, &["title", "name", "summary", "description", "topic"]);

        let inputs = SessionInputs {
            session_key,
            title_hint,
            user_text,
            assistant_text,
            raw_text,
            source_path: manifest_path.to_string_lossy().to_string(),
            started_at: datetime_from_secs(started_secs),
            modified_at: datetime_from_secs(modified_secs),
        };
        built.push((
            modified_secs,
            build_session(inputs, workspace_root, home_str),
        ));
    }

    built.sort_by(|left, right| right.0.cmp(&left.0));
    built
        .into_iter()
        .take(remaining)
        .map(|(_, session)| session)
        .collect()
}

/// Normalize the several possible manifest container shapes into a flat list
/// of `(optional key hint, session value)` pairs.
fn normalize_manifest_entries(value: Value) -> Vec<(Option<String>, Value)> {
    match value {
        Value::Array(arr) => arr.into_iter().map(|item| (None, item)).collect(),
        Value::Object(map) => {
            if let Some(sessions) = map.get("sessions") {
                return normalize_manifest_entries(sessions.clone());
            }
            if looks_like_session(&Value::Object(map.clone())) {
                return vec![(None, Value::Object(map))];
            }
            // Treat as an id -> session object map.
            map.into_iter()
                .filter(|(_, value)| value.is_object())
                .map(|(key, value)| (Some(key), value))
                .collect()
        }
        _ => Vec::new(),
    }
}

fn looks_like_session(value: &Value) -> bool {
    const SESSION_KEYS: &[&str] = &[
        "id",
        "session_id",
        "sessionId",
        "uuid",
        "title",
        "messages",
        "content",
        "text",
        "transcript",
        "created_at",
        "updated_at",
        "started_at",
    ];
    value.as_object().map_or(false, |obj| {
        SESSION_KEYS.iter().any(|key| obj.contains_key(*key))
    })
}

/// Extract `(user_text, assistant_text, raw_text)` from a manifest session
/// object. Handles a `messages` array (role/content) and several freeform
/// content field names.
fn manifest_text(obj: &Value) -> (String, String, String) {
    if let Some(messages) = obj.get("messages").and_then(|m| m.as_array()) {
        let mut user: Vec<String> = Vec::new();
        let mut assistant: Vec<String> = Vec::new();
        let mut raw: Vec<String> = Vec::new();
        for msg in messages {
            let role = msg
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("")
                .to_lowercase();
            let content = message_content_to_string(msg);
            if content.trim().is_empty() {
                continue;
            }
            let label = if role.is_empty() { "message" } else { &role };
            raw.push(format!("{label}: {content}"));
            match role.as_str() {
                "user" | "human" | "operator" => user.push(content),
                "assistant" | "ai" | "model" | "agent" => assistant.push(content),
                _ => {}
            }
        }
        return (user.join("\n\n"), assistant.join("\n\n"), raw.join("\n"));
    }

    let content = obj_str(
        obj,
        &["text", "content", "transcript", "prompt", "body", "summary"],
    )
    .unwrap_or_default();
    if content.is_empty() {
        return (String::new(), String::new(), String::new());
    }
    let parsed = parse_txt_transcript(&content);
    if !parsed.user_text.is_empty() || !parsed.assistant_text.is_empty() {
        (parsed.user_text, parsed.assistant_text, parsed.raw_text)
    } else {
        // No role markers: treat the blob as the user-side intent record so
        // title inference and path/command extraction still have signal.
        (content.clone(), String::new(), content)
    }
}

fn message_content_to_string(msg: &Value) -> String {
    if let Some(text) = msg.get("content").and_then(|c| c.as_str()) {
        return text.to_string();
    }
    if let Some(items) = msg.get("content").and_then(|c| c.as_array()) {
        return items
            .iter()
            .filter_map(|item| {
                item.get("text")
                    .and_then(|t| t.as_str())
                    .map(str::to_string)
                    .or_else(|| item.as_str().map(str::to_string))
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    msg.get("text")
        .and_then(|t| t.as_str())
        .map(str::to_string)
        .unwrap_or_default()
}

fn obj_str(obj: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(text) = obj.get(*key).and_then(|v| v.as_str()) {
            if !text.trim().is_empty() {
                return Some(text.to_string());
            }
        }
    }
    None
}

fn manifest_field_time(obj: &Value, keys: &[&str]) -> Option<u64> {
    for key in keys {
        let Some(value) = obj.get(*key) else {
            continue;
        };
        if let Some(n) = value.as_u64() {
            return Some(normalize_epoch(n));
        }
        if let Some(f) = value.as_f64() {
            if f > 0.0 {
                return Some(normalize_epoch(f as u64));
            }
        }
        if let Some(text) = value.as_str() {
            let trimmed = text.trim();
            if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
                return Some(dt.timestamp().max(0) as u64);
            }
            if let Ok(n) = trimmed.parse::<u64>() {
                return Some(normalize_epoch(n));
            }
        }
    }
    None
}

/// Treat very large epoch values as milliseconds.
fn normalize_epoch(value: u64) -> u64 {
    if value > 100_000_000_000 {
        value / 1000
    } else {
        value
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
