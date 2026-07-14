//! Codex CLI transcript adapter.

use std::path::Path;

use chrono::Utc;

use super::parsing::{
    classify_open_files_excluding_sensitive, classify_sensitive_paths, extract_commands,
    extract_paths, extract_ports, extract_tool_names, extract_traffic, ParsedTranscript,
};
use super::{
    datetime_from_secs, hostname_string, mtime_secs, observer_agent_instance_id,
    walk_files_with_suffix, CollectDiagnostics, CollectOptions, CollectResult, CollectedPayload,
    CollectedRawSession,
};

const CODEX_LLM_HOSTS: &[&str] = &[
    "api.anthropic.com:443",
    "api.openai.com:443",
    "amazonaws.com:443",
    "asn:CLOUDFLARENET",
    "asn:NOTION",
    "asn:MICROSOFT-CORP",
    "asn:AMAZON",
];

const CODEX_SCOPE_PARENT_PATHS: &[&str] = &[
    "*/codex",
    "*/bin/codex",
    "/usr/bin/codex",
    "/usr/local/bin/codex",
    "*/node",
    "*/node_modules/.bin/codex",
    "*/.local/bin/codex",
    "*/.nvm/",
    "*/.volta/",
    "*\\codex.exe",
    "*\\codex.cmd",
    "*\\bin\\codex",
    "*\\node.exe",
    "*\\node_modules\\.bin\\codex",
    "*\\.local\\bin\\codex",
    "*/windowsapps/",
    "*\\windowsapps\\",
    "*/appdata/local/programs/codex",
    "*\\appdata\\local\\programs\\codex",
    "*/program files/codex",
    "*\\program files\\codex",
    "/snap/bin/codex",
    "*/snap/codex/",
    "*/flatpak/",
    "*/nix/store/",
    "*/codex_edamame_mcp.mjs",
];

pub fn collect(home: &Path, options: &CollectOptions) -> anyhow::Result<CollectResult> {
    let codex_home = resolve_codex_home(home);
    let sessions_root = codex_home.join("sessions");
    let diagnostics = CollectDiagnostics {
        // Presence-based discovery (mirrors the Hermes adapter): any
        // recognizable ~/.codex store -- the legacy sessions/ rollout tree,
        // the shared config.toml/auth.json, history, the installation id, or a
        // modern state_*.sqlite thread index -- marks Codex as "discovered".
        // The modern CLI (0.137+) and the desktop app no longer create
        // sessions/ at all, so gating on that directory hid every modern
        // install and never fired unsecured_codex / the agent inventory row.
        transcripts_root_accessible: codex_store_present(&codex_home),
        transcripts_roots: vec![
            codex_home.to_string_lossy().to_string(),
            sessions_root.to_string_lossy().to_string(),
        ],
        hostname: hostname_string(),
    };

    // Legacy path: flat rollout JSONL/TXT under ~/.codex/sessions/. Still
    // present for older CLIs and honored unchanged.
    let result = build_payload(
        "codex",
        home,
        &sessions_root,
        diagnostics,
        options,
        CODEX_LLM_HOSTS,
        CODEX_SCOPE_PARENT_PATHS,
    )?;

    // Modern path (desktop only): the thread index lives in a SQLite store
    // (~/.codex/state_*.sqlite). Read it directly so the host-side observer can
    // ingest real conversation intent without requiring the optional plugin.
    // Agentic features are unsupported on iOS/Android, so the SQLite path is
    // compiled out there (and `result` stays immutable, hence the cfg-shadow).
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    let result = {
        let mut result = result;
        let sqlite_sessions = collect_sqlite_sessions(&codex_home, home, options);
        if !sqlite_sessions.is_empty() {
            merge_sqlite_sessions(&mut result, sqlite_sessions, options);
        }
        result
    };

    Ok(result)
}

/// Resolve the Codex home directory, honoring `CODEX_HOME` (the same override
/// the Codex CLI/app respect) and falling back to `~/.codex`.
fn resolve_codex_home(home: &Path) -> std::path::PathBuf {
    std::env::var("CODEX_HOME")
        .ok()
        .map(std::path::PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| home.join(".codex"))
}

/// Presence-based discovery for a Codex install. Pure filesystem checks, so it
/// runs on every platform with no dependency. Returns true for any recognizable
/// marker so a paused-but-present install still trips `unsecured_codex`.
pub(crate) fn codex_store_present(codex_home: &Path) -> bool {
    if !codex_home.exists() {
        return false;
    }
    if codex_home.join("sessions").is_dir() {
        return true;
    }
    if codex_home.join("config.toml").is_file() {
        return true;
    }
    if codex_home.join("auth.json").is_file() {
        return true;
    }
    if codex_home.join("history.jsonl").is_file() {
        return true;
    }
    if codex_home.join("installation_id").is_file() {
        return true;
    }
    has_codex_sqlite_db(codex_home)
}

/// True when `dir` directly contains a SQLite database file (the modern Codex
/// store keeps state_*.sqlite / logs_*.sqlite directly under ~/.codex).
fn has_codex_sqlite_db(dir: &Path) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            let lower = name.to_ascii_lowercase();
            if lower.ends_with(".sqlite") || lower.ends_with(".sqlite3") || lower.ends_with(".db") {
                return true;
            }
        }
    }
    false
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
                let traffic = extract_traffic(&combined, &commands, llm_hosts);
                let ports = extract_ports(&combined, &commands);
                let inferred = super::parsing::infer_process_paths(&commands, &workspace_root);
                let expected_open =
                    classify_open_files_excluding_sensitive(&extracted_paths, &home_str);
                let _expected_sensitive = classify_sensitive_paths(&extracted_paths, &home_str);

                let session_id = transcript_session_id(&candidate.path);
                let title = first_non_empty_line(&parsed.user_text)
                    .unwrap_or_else(|| format!("{} session {}", agent_type, session_id));
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
                    derived_scope_parent_paths: scope_parent_paths
                        .iter()
                        .map(|s| (*s).to_string())
                        .collect(),
                    derived_scope_grandparent_paths: Vec::new(),
                    derived_scope_any_lineage_paths: super::agent_identity_lineage_paths(
                        agent_type,
                        scope_parent_paths,
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
    // Strict active-window filter (see CollectOptions doc).
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

// ---------------------------------------------------------------------------
// Modern Codex SQLite store ingestion (desktop only).
//
// The Codex CLI (0.137+) and the desktop app store their conversation thread
// index in ~/.codex/state_<schema>.sqlite (e.g. state_5.sqlite) -- a `sqlx`
// migrated database whose `threads` table carries the per-thread intent
// (`first_user_message`), an assistant `preview`, the working directory
// (`cwd`), the model, and a `rollout_path` pointing at the full turn-by-turn
// rollout. We read that index directly so the host-side observer ingests real
// conversation intent without depending on the optional Node plugin.
//
// The reader is schema-tolerant (it reflects on the live column set rather than
// hardcoding a SELECT list) because the schema number changes across Codex
// releases. When a rollout file is reachable and parses, its text enriches the
// session; otherwise the thread-table fields are the authoritative signal.
// ---------------------------------------------------------------------------

/// Merge SQLite-derived sessions into the (legacy file-based) payload, dedup
/// against rollouts already collected from the sessions/ walk, then re-sort
/// most-recent-first, cap to the per-call limit, and recompute the window.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn merge_sqlite_sessions(
    result: &mut CollectResult,
    sqlite_sessions: Vec<CollectedRawSession>,
    options: &CollectOptions,
) {
    // A rollout discovered by the legacy sessions/ walk and the same rollout
    // referenced by a thread's rollout_path are the same conversation; skip the
    // SQLite copy when its source_path was already collected. (Fallback SQLite
    // sessions with no rollout file anchor on cwd/codex_home and won't collide.)
    let existing: std::collections::HashSet<String> = result
        .payload
        .sessions
        .iter()
        .map(|s| s.source_path.clone())
        .collect();
    for session in sqlite_sessions {
        if !session.source_path.is_empty() && existing.contains(&session.source_path) {
            continue;
        }
        result.payload.sessions.push(session);
    }

    result
        .payload
        .sessions
        .sort_by(|a, b| b.modified_at.cmp(&a.modified_at));
    result.payload.sessions.truncate(options.limit.max(1));

    let now = Utc::now();
    let (start, end) = if result.payload.sessions.is_empty() {
        (now, now)
    } else {
        let start = result
            .payload
            .sessions
            .iter()
            .map(|s| s.started_at)
            .min()
            .unwrap_or(now);
        let end = result
            .payload
            .sessions
            .iter()
            .map(|s| s.modified_at)
            .max()
            .unwrap_or(now);
        (start, end)
    };
    result.payload.window_start = start;
    result.payload.window_end = end;
}

/// Locate the newest `state_*.sqlite` thread index directly under `codex_home`.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn newest_state_db(codex_home: &Path) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(codex_home).ok()?;
    let mut best: Option<(u64, std::path::PathBuf)> = None;
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_ascii_lowercase(),
            None => continue,
        };
        let is_state = name.starts_with("state")
            && (name.ends_with(".sqlite") || name.ends_with(".sqlite3") || name.ends_with(".db"));
        if !is_state {
            continue;
        }
        let mtime = mtime_secs(&path);
        if best.as_ref().map(|(m, _)| mtime > *m).unwrap_or(true) {
            best = Some((mtime, path));
        }
    }
    best.map(|(_, path)| path)
}

/// Collect sessions from the modern Codex SQLite thread index. Returns an empty
/// vec on any error (no DB, unreadable, unknown schema) so ingestion stays
/// best-effort and never blocks the legacy/file path.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn collect_sqlite_sessions(
    codex_home: &Path,
    home: &Path,
    options: &CollectOptions,
) -> Vec<CollectedRawSession> {
    let db_path = match newest_state_db(codex_home) {
        Some(p) => p,
        None => return Vec::new(),
    };
    match read_threads_as_sessions(&db_path, codex_home, home, options) {
        Ok(sessions) => sessions,
        Err(e) => {
            tracing::debug!(
                "codex sqlite ingest skipped for {}: {}",
                db_path.display(),
                e
            );
            Vec::new()
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn read_threads_as_sessions(
    db_path: &Path,
    codex_home: &Path,
    home: &Path,
    options: &CollectOptions,
) -> anyhow::Result<Vec<CollectedRawSession>> {
    use rusqlite::types::Value;
    use rusqlite::{Connection, OpenFlags};
    use std::collections::HashMap;

    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    // The threads table may be absent on an older/newer schema; treat that as
    // "nothing to ingest" rather than an error.
    let mut stmt = match conn.prepare("SELECT * FROM threads") {
        Ok(stmt) => stmt,
        Err(_) => return Ok(Vec::new()),
    };
    let column_names: Vec<String> = stmt
        .column_names()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    let rows = stmt.query_map([], |row| {
        let mut map: HashMap<String, Value> = HashMap::with_capacity(column_names.len());
        for (idx, name) in column_names.iter().enumerate() {
            map.insert(name.clone(), row.get::<_, Value>(idx)?);
        }
        Ok(map)
    })?;

    let now = Utc::now().timestamp() as u64;
    let active_cutoff = now.saturating_sub(options.active_window_minutes.saturating_mul(60));

    // Filter to the active window, then keep only the most recent `limit`
    // threads so we bound the number of rollout-file reads below.
    let mut qualifying: Vec<(u64, HashMap<String, Value>)> = Vec::new();
    for row in rows {
        let map = match row {
            Ok(map) => map,
            Err(_) => continue,
        };
        let updated = row_updated_secs(&map);
        if updated > 0 && updated < active_cutoff {
            continue;
        }
        qualifying.push((updated, map));
    }
    qualifying.sort_by(|a, b| b.0.cmp(&a.0));
    qualifying.truncate(options.limit.max(1));

    let workspace_root = home.to_string_lossy().to_string();
    let mut out = Vec::new();
    for (_, map) in qualifying {
        if let Some(session) = thread_row_to_session(&map, codex_home, &workspace_root) {
            out.push(session);
        }
    }
    Ok(out)
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn row_updated_secs(map: &std::collections::HashMap<String, rusqlite::types::Value>) -> u64 {
    value_i64(map, "updated_at_ms")
        .map(|ms| ms / 1000)
        .or_else(|| value_i64(map, "updated_at"))
        .filter(|secs| *secs > 0)
        .unwrap_or(0)
        .max(0) as u64
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn value_str(
    map: &std::collections::HashMap<String, rusqlite::types::Value>,
    key: &str,
) -> Option<String> {
    match map.get(key) {
        Some(rusqlite::types::Value::Text(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        _ => None,
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn value_i64(
    map: &std::collections::HashMap<String, rusqlite::types::Value>,
    key: &str,
) -> Option<i64> {
    match map.get(key) {
        Some(rusqlite::types::Value::Integer(i)) => Some(*i),
        Some(rusqlite::types::Value::Real(r)) => Some(*r as i64),
        Some(rusqlite::types::Value::Text(s)) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// Resolve a thread's `rollout_path` against the likely roots: an absolute
/// path as-is, `~/` expanded against the user home, relative to ~/.codex, and
/// relative to ~/.codex/sessions.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn resolve_rollout_path(codex_home: &Path, rollout_path: &str) -> Option<std::path::PathBuf> {
    let raw = rollout_path.trim();
    if raw.is_empty() {
        return None;
    }
    let home_relative = raw
        .strip_prefix("~/")
        .and_then(|rest| codex_home.parent().map(|user_home| user_home.join(rest)));
    let candidates = [
        home_relative,
        Some(std::path::PathBuf::from(raw)),
        Some(codex_home.join(raw)),
        Some(codex_home.join("sessions").join(raw)),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|candidate| candidate.is_file())
}

/// Build a `CollectedRawSession` from a single `threads` row. Rollout-file text
/// (when reachable) is the richest source; `first_user_message`/`preview`/
/// `cwd`/`model` from the row are the authoritative fallback.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn thread_row_to_session(
    map: &std::collections::HashMap<String, rusqlite::types::Value>,
    codex_home: &Path,
    workspace_root: &str,
) -> Option<CollectedRawSession> {
    let updated_secs = row_updated_secs(map);
    let created_secs = value_i64(map, "created_at_ms")
        .map(|ms| ms / 1000)
        .or_else(|| value_i64(map, "created_at"))
        .filter(|secs| *secs > 0)
        .unwrap_or(updated_secs as i64)
        .max(0) as u64;

    let thread_id = value_str(map, "id")
        .or_else(|| value_str(map, "rollout_path"))
        .unwrap_or_else(|| "thread".to_string());

    let first_user = value_str(map, "first_user_message");
    let preview = value_str(map, "preview");
    let title_col = value_str(map, "title");
    let cwd = value_str(map, "cwd");
    let model = value_str(map, "model");
    let rollout_path = value_str(map, "rollout_path");

    // Best-effort: follow rollout_path to a JSONL rollout file and parse it.
    // NOTE: unlike the file-driven `collect()` loop, this session is a function
    // of the sqlite thread row (title/cwd/model/first_user/preview) as much as
    // the rollout file, so it must NOT go through the per-file session cache
    // (the file key does not capture the DB row). A direct read+parse is cheap
    // here (OS-cached bytes) and correct.
    let (mut user_text, mut assistant_text, mut raw_text, source_path) = rollout_path
        .as_deref()
        .and_then(|rp| resolve_rollout_path(codex_home, rp))
        .and_then(|path| {
            super::read_transcript_capped(&path)
                .ok()
                .map(|raw| (path, super::parsing::parse_jsonl_transcript(&raw)))
        })
        .map(|(path, parsed)| {
            (
                parsed.user_text,
                parsed.assistant_text,
                parsed.raw_text,
                path.to_string_lossy().to_string(),
            )
        })
        .unwrap_or_default();

    // Fall back to / augment with the thread-table fields. first_user_message
    // is the authoritative user intent for divergence modeling.
    if user_text.trim().is_empty() {
        if let Some(message) = first_user.clone() {
            user_text = message;
        }
    }
    if assistant_text.trim().is_empty() {
        if let Some(snippet) = preview.clone() {
            assistant_text = snippet;
        }
    }
    if raw_text.trim().is_empty() {
        let mut parts: Vec<String> = Vec::new();
        if let Some(message) = first_user.as_ref() {
            parts.push(message.clone());
        }
        if let Some(snippet) = preview.as_ref() {
            parts.push(snippet.clone());
        }
        if let Some(dir) = cwd.as_ref() {
            parts.push(format!("cwd: {}", dir));
        }
        if let Some(name) = model.as_ref() {
            parts.push(format!("model: {}", name));
        }
        raw_text = parts.join("\n\n");
    }

    if user_text.trim().is_empty() && assistant_text.trim().is_empty() && raw_text.trim().is_empty()
    {
        return None;
    }

    let source_path = if source_path.is_empty() {
        cwd.clone()
            .unwrap_or_else(|| codex_home.to_string_lossy().to_string())
    } else {
        source_path
    };

    let combined = format!("{}\n\n{}\n\n{}", user_text, assistant_text, raw_text);
    let extracted_paths = extract_paths(&combined, workspace_root);
    let tool_names = extract_tool_names(&raw_text, &assistant_text);
    let commands = extract_commands(&raw_text, &assistant_text);
    let traffic = extract_traffic(&combined, &commands, CODEX_LLM_HOSTS);
    let ports = extract_ports(&combined, &commands);
    let inferred = super::parsing::infer_process_paths(&commands, workspace_root);
    let expected_open = classify_open_files_excluding_sensitive(&extracted_paths, workspace_root);
    let _expected_sensitive = classify_sensitive_paths(&extracted_paths, workspace_root);

    let title = title_col
        .or_else(|| first_non_empty_line(&user_text))
        .unwrap_or_else(|| format!("codex thread {}", thread_id));

    let started_at = datetime_from_secs(if created_secs > 0 {
        created_secs
    } else {
        updated_secs
    });
    let modified_at = datetime_from_secs(if updated_secs > 0 {
        updated_secs
    } else {
        created_secs
    });

    Some(CollectedRawSession {
        session_key: thread_id,
        title,
        user_text,
        assistant_text,
        raw_text,
        tool_names,
        commands,
        derived_expected_traffic: traffic,
        derived_expected_local_open_ports: ports,
        derived_expected_process_paths: inferred.process_paths,
        derived_expected_parent_paths: inferred.parent_paths,
        derived_expected_grandparent_paths: Vec::new(),
        derived_scope_process_paths: Vec::new(),
        derived_scope_parent_paths: CODEX_SCOPE_PARENT_PATHS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        derived_scope_grandparent_paths: Vec::new(),
        derived_scope_any_lineage_paths: super::agent_identity_lineage_paths(
            "codex",
            CODEX_SCOPE_PARENT_PATHS,
        ),
        derived_expected_open_files: expected_open,
        source_path,
        started_at,
        modified_at,
        economics_raw_text: String::new(),
        economics_truncated: false,
        context_tokens_used: None,
        context_token_limit: None,
        context_usage_percent: None,
    })
}

#[cfg(all(
    test,
    any(target_os = "macos", target_os = "linux", target_os = "windows")
))]
mod sqlite_tests {
    use super::*;
    use rusqlite::Connection;
    use serial_test::serial;

    fn now_ms() -> i64 {
        Utc::now().timestamp_millis()
    }

    /// Create a minimal modern-Codex thread index (a subset of the real
    /// `threads` columns -- the reader reflects on the live column set).
    fn create_state_db(codex_home: &Path) -> std::path::PathBuf {
        std::fs::create_dir_all(codex_home).expect("create codex home");
        let db = codex_home.join("state_5.sqlite");
        let conn = Connection::open(&db).expect("open state db");
        conn.execute_batch(
            "CREATE TABLE threads (
                id TEXT PRIMARY KEY,
                title TEXT,
                first_user_message TEXT,
                preview TEXT,
                cwd TEXT,
                model TEXT,
                rollout_path TEXT,
                created_at_ms INTEGER,
                updated_at_ms INTEGER
            );",
        )
        .expect("create threads table");
        db
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_thread(
        db: &Path,
        id: &str,
        title: &str,
        first_user_message: &str,
        preview: &str,
        rollout_path: &str,
        updated_at_ms: i64,
    ) {
        let conn = Connection::open(db).expect("open for insert");
        conn.execute(
            "INSERT INTO threads
                (id, title, first_user_message, preview, cwd, model, rollout_path, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                id,
                title,
                first_user_message,
                preview,
                "/work/project",
                "gpt-5-codex",
                rollout_path,
                updated_at_ms,
                updated_at_ms,
            ],
        )
        .expect("insert thread");
    }

    #[test]
    fn presence_discovery_recognizes_modern_and_legacy_markers() {
        let temp = tempfile::tempdir().expect("tempdir");

        // Non-existent home -> not discovered.
        assert!(!codex_store_present(&temp.path().join("missing/.codex")));

        // Empty ~/.codex (dir exists, no markers) -> not discovered.
        let empty = temp.path().join("empty/.codex");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(!codex_store_present(&empty));

        // config.toml present (no sessions/) -> discovered.
        let cfg_home = temp.path().join("cfg/.codex");
        std::fs::create_dir_all(&cfg_home).unwrap();
        std::fs::write(cfg_home.join("config.toml"), "model = \"gpt-5-codex\"\n").unwrap();
        assert!(codex_store_present(&cfg_home));

        // Modern SQLite store present (no sessions/, no config) -> discovered.
        let sqlite_home = temp.path().join("sqlite/.codex");
        create_state_db(&sqlite_home);
        assert!(codex_store_present(&sqlite_home));

        // Legacy sessions/ dir present -> discovered.
        let legacy_home = temp.path().join("legacy/.codex");
        std::fs::create_dir_all(legacy_home.join("sessions")).unwrap();
        assert!(codex_store_present(&legacy_home));
    }

    #[test]
    fn sqlite_ingest_uses_rollout_file_when_reachable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let codex_home = home.join(".codex");
        let db = create_state_db(&codex_home);

        let rollout_dir = codex_home.join("sessions/2026/06/06");
        std::fs::create_dir_all(&rollout_dir).unwrap();
        let rollout = rollout_dir.join("rollout-2026-06-06T10-00-00-abc.jsonl");
        std::fs::write(
            &rollout,
            "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"deploy staging via /usr/local/bin/deploy.sh\"}]}}\n{\"role\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"running deploy\"}]}}\n",
        )
        .unwrap();

        insert_thread(
            &db,
            "thread-1",
            "Deploy staging",
            "deploy staging please",
            "running deploy",
            &rollout.to_string_lossy(),
            now_ms(),
        );

        let sessions = collect_sqlite_sessions(&codex_home, home, &CollectOptions::default());
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.session_key, "thread-1");
        // Rollout text wins over the thread-table preview/first_user_message.
        assert!(session.user_text.contains("deploy staging via"));
        assert!(session.assistant_text.contains("running deploy"));
        assert_eq!(session.source_path, rollout.to_string_lossy());
    }

    #[test]
    fn sqlite_ingest_falls_back_to_thread_fields_without_rollout() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let codex_home = home.join(".codex");
        let db = create_state_db(&codex_home);

        // rollout_path empty -> no file to follow; use first_user_message.
        insert_thread(
            &db,
            "thread-2",
            "Audit DB",
            "audit the production database for leaked secrets",
            "scanning tables",
            "",
            now_ms(),
        );

        let sessions = collect_sqlite_sessions(&codex_home, home, &CollectOptions::default());
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.session_key, "thread-2");
        assert_eq!(
            session.user_text,
            "audit the production database for leaked secrets"
        );
        assert!(session.assistant_text.contains("scanning tables"));
    }

    #[test]
    fn sqlite_ingest_empty_when_no_state_db() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let codex_home = home.join(".codex");
        std::fs::create_dir_all(&codex_home).unwrap();
        // Only a config.toml (discovered) but no state_*.sqlite -> no sessions.
        std::fs::write(codex_home.join("config.toml"), "x = 1\n").unwrap();

        let sessions = collect_sqlite_sessions(&codex_home, home, &CollectOptions::default());
        assert!(sessions.is_empty());
    }

    #[test]
    fn sqlite_ingest_respects_active_window() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let codex_home = home.join(".codex");
        let db = create_state_db(&codex_home);

        // Updated two hours ago -> outside the default 30-minute window.
        let two_hours_ago = now_ms() - 2 * 60 * 60 * 1000;
        insert_thread(
            &db,
            "stale-thread",
            "Old work",
            "old intent",
            "old preview",
            "",
            two_hours_ago,
        );

        let sessions = collect_sqlite_sessions(&codex_home, home, &CollectOptions::default());
        assert!(sessions.is_empty());
    }

    #[test]
    #[serial]
    fn collect_merges_sqlite_sessions_end_to_end() {
        // Drive the full collect() path (discovery + merge) via CODEX_HOME so
        // a modern install with NO sessions/ directory still yields sessions.
        let saved = std::env::var("CODEX_HOME").ok();
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let codex_home = home.join(".codex");
        let db = create_state_db(&codex_home);
        insert_thread(
            &db,
            "thread-e2e",
            "End to end",
            "refactor the auth module",
            "done",
            "",
            now_ms(),
        );
        std::env::set_var("CODEX_HOME", &codex_home);

        let result = collect(home, &CollectOptions::default());

        match saved {
            Some(value) => std::env::set_var("CODEX_HOME", value),
            None => std::env::remove_var("CODEX_HOME"),
        }

        let result = result.expect("codex collect");
        assert_eq!(result.payload.agent_type, "codex");
        // Discovered via the SQLite store even with no sessions/ directory.
        assert!(result.diagnostics.transcripts_root_accessible);
        assert_eq!(result.payload.sessions.len(), 1);
        assert_eq!(result.payload.sessions[0].session_key, "thread-e2e");
        assert!(result.payload.sessions[0]
            .user_text
            .contains("refactor the auth module"));
    }
}
