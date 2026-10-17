//! Claude Code transcript adapter.

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
        // The agent's own model traffic, declared on every session: CloudModel
        // data (`agent_visibility_params::agent_llm_hosts`).
        &crate::agent_visibility_params::agent_llm_hosts("claude_code"),
        CLAUDE_CODE_SCOPE_PARENT_PATHS,
    )
}

pub(crate) fn build_payload(
    agent_type: &str,
    home: &Path,
    primary_root: &Path,
    diagnostics: CollectDiagnostics,
    options: &CollectOptions,
    llm_hosts: &[String],
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
        // Cached by (path, mtime, size): the whole parse+extract build is a
        // pure function of the transcript bytes plus the per-host-constant
        // `workspace_root`/`home_str` and the agent's compile-time path
        // constants, so an unchanged file is served without re-extracting, and
        // a session built under one window is reused verbatim when the window
        // widens.
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
                // Traffic and port hints derive from what the agent SAID and
                // the tool-call arguments it issued -- never from tool RESULT
                // bodies (in `raw_text`), whose every domain-shaped string
                // would inflate the egress allowlist (e.g. URLs inside
                // WebSearch results) and whose every port a listing shows
                // (`netstat`, `lsof`) would read as one the agent opens
                // (FP-DIV-15).
                let hint_text = format!(
                    "{}\n\n{}\n\n{}",
                    parsed.user_text, parsed.assistant_text, parsed.tool_input_text
                );
                let traffic = extract_traffic(&hint_text, &commands, llm_hosts);
                let ports = extract_ports(&hint_text, &commands);
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
                    harness_process: None,
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
                    economics: None,
                    tool_error_details: Vec::new(),
                    context_tokens_used: None,
                    context_token_limit: None,
                    context_usage_percent: None,
                    // Claude Code transcripts live under ~/.claude/projects/<slug>/,
                    // so source_path already yields the workspace slug.
                    workspace_hint: String::new(),
                    tool_events: Vec::new(),
                    denylist_bypass_events: Vec::new(),
                    launch_context: Default::default(),
                    agent_launches: Vec::new(),
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

    // B2: bind each transcript to the live harness process that owns it.
    let harness = harness_processes(home);
    for session in sessions.iter_mut() {
        session.harness_process = harness.get(session.session_key.trim()).cloned();
    }

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

/// The live Claude Code harness processes, keyed by session id, from
/// `~/.claude/sessions/<pid>.json` (B2). Each file carries `pid`,
/// `sessionId` and `startedAt` (UNIX ms); the sibling `*.key` files are
/// never opened. A pid is reported only when the process is alive and its
/// start matches the file within five seconds (a reused pid is a different
/// process), or when the system cannot say when it started.
pub(crate) fn harness_processes(
    home: &Path,
) -> std::collections::BTreeMap<String, super::HarnessProcess> {
    let found = harness_pid_files(home);
    if found.is_empty() {
        return Default::default();
    }
    live_harness_processes(found)
}

/// `(pid, session id, recorded start)` from each `<pid>.json` file, unchecked.
fn harness_pid_files(home: &Path) -> Vec<(u32, String, Option<u64>)> {
    let mut found: Vec<(u32, String, Option<u64>)> = Vec::new();
    let dir = home.join(".claude").join("sessions");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Default::default();
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let pid = value
            .get("pid")
            .and_then(|v| v.as_u64())
            .and_then(|p| u32::try_from(p).ok());
        let session_id = value
            .get("sessionId")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let started_at_ms = value.get("startedAt").and_then(|v| v.as_u64());
        if let (Some(pid), Some(session_id)) = (pid, session_id) {
            found.push((pid, session_id, started_at_ms));
        }
    }
    found
}

/// The pid files whose process is alive with a matching start. `sysinfo`
/// is a desktop dependency (the same targets as the helper); a phone runs no
/// agent harness, so the other targets bind nothing.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn live_harness_processes(
    found: Vec<(u32, String, Option<u64>)>,
) -> std::collections::BTreeMap<String, super::HarnessProcess> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
    // One refresh per distinct pid: two pid files can name one process (a
    // session that was cleared and restarted in the same harness).
    let pids: Vec<Pid> = found
        .iter()
        .map(|(pid, _, _)| *pid)
        .collect::<std::collections::BTreeSet<u32>>()
        .into_iter()
        .map(Pid::from_u32)
        .collect();
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&pids),
        true,
        ProcessRefreshKind::nothing(),
    );
    let mut map = std::collections::BTreeMap::new();
    for (pid, session_id, started_at_ms) in found {
        let Some(process) = system.process(Pid::from_u32(pid)) else {
            continue;
        };
        let live_start_ms = process.start_time().saturating_mul(1000);
        let start_matches = match started_at_ms {
            Some(recorded) if live_start_ms > 0 => recorded.abs_diff(live_start_ms) <= 5_000,
            _ => true,
        };
        if !start_matches {
            continue;
        }
        map.insert(
            session_id,
            super::HarnessProcess {
                pid,
                proc_started_at_ms: started_at_ms,
                source: "claude_sessions_pid_file".to_string(),
            },
        );
    }
    map
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn live_harness_processes(
    _found: Vec<(u32, String, Option<u64>)>,
) -> std::collections::BTreeMap<String, super::HarnessProcess> {
    Default::default()
}

#[cfg(all(
    test,
    any(target_os = "macos", target_os = "linux", target_os = "windows")
))]
mod harness_process_tests {
    use super::*;

    fn scratch_home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edamame_harness_{}_{}_{}",
            tag,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(dir.join(".claude").join("sessions")).unwrap();
        dir
    }

    fn own_start_ms() -> Option<u64> {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
        let pid = Pid::from_u32(std::process::id());
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing(),
        );
        system
            .process(pid)
            .map(|p| p.start_time().saturating_mul(1000))
            .filter(|ms| *ms > 0)
    }

    #[test]
    fn pid_files_bind_live_harnesses_and_skip_dead_or_reused_pids() {
        let home = scratch_home("live");
        let sessions = home.join(".claude").join("sessions");
        let me = std::process::id();
        let started = own_start_ms().unwrap_or(0);
        std::fs::write(
            sessions.join(format!("{me}.json")),
            format!(
                r#"{{"pid":{me},"sessionId":"s-live","cwd":"/tmp/x","startedAt":{started},"kind":"interactive"}}"#
            ),
        )
        .unwrap();
        // A reused pid: the file says the process started a day earlier.
        std::fs::write(
            sessions.join("reused.json"),
            format!(
                r#"{{"pid":{me},"sessionId":"s-reused","startedAt":{}}}"#,
                started.saturating_sub(86_400_000)
            ),
        )
        .unwrap();
        // A pid that is not alive.
        std::fs::write(
            sessions.join("dead.json"),
            r#"{"pid":4000000,"sessionId":"s-dead","startedAt":1}"#,
        )
        .unwrap();
        // The key file beside a pid file is never read.
        std::fs::write(sessions.join(format!("{me}.deadbeef.key")), "not json").unwrap();
        let map = harness_processes(&home);
        let live = map.get("s-live").unwrap_or_else(|| {
            panic!(
                "the live harness binds: map={map:?} me={me} started={started} sysinfo_start={:?}",
                own_start_ms()
            )
        });
        assert_eq!(live.pid, me);
        assert_eq!(live.source, "claude_sessions_pid_file");
        if started > 0 {
            assert!(!map.contains_key("s-reused"), "a reused pid does not bind");
        }
        assert!(!map.contains_key("s-dead"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_home_without_pid_files_binds_nothing() {
        let home = scratch_home("empty");
        assert!(harness_processes(&home).is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }
}
