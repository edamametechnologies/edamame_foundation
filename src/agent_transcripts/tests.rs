//! Unit tests for the per-agent transcript adapters.
//!
//! Each test seeds a synthetic home directory under `tempfile::tempdir`,
//! drops representative transcript files, and asserts that
//! `agent_transcripts::collect(...)` produces a payload that
//! `RawReasoningSessionPayload::validate_and_normalize` would accept (we
//! cannot import the core type from foundation, so we re-validate the
//! invariants here directly).

#![cfg(all(
    test,
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]

use std::path::Path;

use super::{collect, CollectOptions};

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, contents).expect("write file");
}

fn options() -> CollectOptions {
    CollectOptions {
        limit: 4,
        recency_hours: 24 * 365 * 5,
        active_window_minutes: 60,
        project_hints: Vec::new(),
    }
}

#[test]
fn cursor_collects_txt_and_jsonl() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let txn_dir = home
        .join(".cursor/projects/some-project/agent-transcripts");
    write(
        &txn_dir.join("session-a.txt"),
        "user:\nplease run cargo build\n\nassistant:\nRunning `cargo build` now.\n",
    );
    let result = collect("cursor", home, &options()).expect("cursor collect");
    assert_eq!(result.payload.agent_type, "cursor");
    assert!(
        result.diagnostics.transcripts_root_accessible,
        "transcripts root should be accessible"
    );
    assert_eq!(
        result.payload.sessions.len(),
        1,
        "expected one session, got {:?}",
        result.payload.sessions
    );
    let session = &result.payload.sessions[0];
    assert!(session.user_text.contains("cargo build"));
    assert!(session.assistant_text.contains("Running `cargo build`"));
    assert!(session
        .derived_expected_traffic
        .iter()
        .any(|h| h == "crates.io:443"));
}

#[test]
fn claude_code_collects_jsonl() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let projects = home.join(".claude/projects/sample");
    let line_user =
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"deploy to staging\"}]}}";
    let line_assistant = "{\"role\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"running kubectl apply -f deploy.yaml\"}]}}";
    write(
        &projects.join("session-1.jsonl"),
        &format!("{}\n{}\n", line_user, line_assistant),
    );
    let result = collect("claude_code", home, &options()).expect("claude_code collect");
    assert_eq!(result.payload.agent_type, "claude_code");
    assert!(result.diagnostics.transcripts_root_accessible);
    assert_eq!(result.payload.sessions.len(), 1);
    let session = &result.payload.sessions[0];
    assert!(session.user_text.contains("deploy to staging"));
    assert!(session.assistant_text.contains("kubectl apply"));
    assert!(session.commands.iter().any(|c| c.starts_with("kubectl apply")));
}

#[test]
fn claude_desktop_collects_from_two_roots() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let code_root = home.join(".claude/projects/proj");
    write(
        &code_root.join("code.jsonl"),
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"hello from code\"}]}}\n",
    );
    #[cfg(target_os = "macos")]
    let cowork_root = home.join("Library/Application Support/Claude/local-agent-mode-sessions/x");
    #[cfg(target_os = "windows")]
    let cowork_root = home.join("AppData/Roaming/Claude/local-agent-mode-sessions/x");
    #[cfg(target_os = "linux")]
    let cowork_root = home.join(".local/share/claude-desktop/local-agent-mode-sessions/x");
    write(
        &cowork_root.join("cowork.jsonl"),
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"hello from cowork\"}]}}\n",
    );

    // The cowork lookup respects XDG_DATA_HOME on Linux; clear it so the
    // default home-relative path is picked up.
    #[cfg(target_os = "linux")]
    std::env::remove_var("XDG_DATA_HOME");

    let result = collect("claude_desktop", home, &options()).expect("claude_desktop collect");
    assert_eq!(result.payload.agent_type, "claude_desktop");
    assert!(result.diagnostics.transcripts_root_accessible);
    assert_eq!(result.payload.sessions.len(), 2);
    let texts: Vec<String> = result
        .payload
        .sessions
        .iter()
        .map(|s| s.user_text.clone())
        .collect();
    assert!(texts.iter().any(|t| t.contains("hello from code")));
    assert!(texts.iter().any(|t| t.contains("hello from cowork")));
}

#[test]
fn codex_collects_rollout_jsonl() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let sessions = home.join(".codex/sessions/2026/04/28");
    let line_user =
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"inspect repo and run tests\"}]}}";
    let line_assistant = "{\"role\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"running cargo test --lib\"}]}}";
    write(
        &sessions.join("rollout-2026-04-28T12-00-00-test.jsonl"),
        &format!("{}\n{}\n", line_user, line_assistant),
    );
    let result = collect("codex", home, &options()).expect("codex collect");
    assert_eq!(result.payload.agent_type, "codex");
    assert!(result.diagnostics.transcripts_root_accessible);
    assert_eq!(result.payload.sessions.len(), 1);
    let session = &result.payload.sessions[0];
    assert!(session.user_text.contains("inspect repo"));
    assert!(session.commands.iter().any(|c| c.starts_with("cargo test")));
}

#[test]
fn openclaw_returns_empty_when_no_sessions() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let result = collect("openclaw", home, &options()).expect("openclaw collect");
    assert_eq!(result.payload.agent_type, "openclaw");
    assert!(!result.diagnostics.transcripts_root_accessible);
    assert!(result.payload.sessions.is_empty());
}

#[test]
fn openclaw_collects_from_session_root_when_present() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let root = home.join(".openclaw/sessions/x");
    write(
        &root.join("oc.jsonl"),
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"openclaw scan\"}]}}\n",
    );
    let result = collect("openclaw", home, &options()).expect("openclaw collect");
    assert!(result.diagnostics.transcripts_root_accessible);
    assert_eq!(result.payload.sessions.len(), 1);
    assert!(result.payload.sessions[0].user_text.contains("openclaw scan"));
}

#[test]
fn unknown_agent_type_returns_empty_payload() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = collect("does_not_exist", temp.path(), &options()).expect("collect");
    assert_eq!(result.payload.agent_type, "does_not_exist");
    assert!(result.payload.sessions.is_empty());
    assert!(!result.diagnostics.transcripts_root_accessible);
}

#[test]
fn collect_to_json_round_trips() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let txn_dir = home
        .join(".cursor/projects/proj/agent-transcripts");
    write(
        &txn_dir.join("session.txt"),
        "user:\nrun curl https://example.com/health\nassistant:\nokay\n",
    );
    let json = super::collect_to_json("cursor", home, &options()).expect("collect to json");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("json");
    assert_eq!(parsed["payload"]["agent_type"], "cursor");
    assert!(parsed["payload"]["sessions"].as_array().unwrap().len() >= 1);
    let traffic = &parsed["payload"]["sessions"][0]["derived_expected_traffic"];
    assert!(
        traffic
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "example.com:443"),
        "expected example.com:443 in traffic, got: {}",
        traffic
    );
}
