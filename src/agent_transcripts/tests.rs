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

use std::fs::File;
use std::path::Path;
use std::time::{Duration, SystemTime};

use serial_test::serial;

use super::{collect, CollectOptions};

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, contents).expect("write file");
}

/// Stamp `path`'s mtime to `seconds_ago` seconds in the past. Used to
/// simulate stale transcripts that should fall outside the active-window
/// filter. Uses the stable `File::set_modified` API (Rust 1.75+) to avoid
/// pulling in a dev-dep just for this.
fn make_stale(path: &Path, seconds_ago: u64) {
    let target = SystemTime::now()
        .checked_sub(Duration::from_secs(seconds_ago))
        .expect("time math");
    let f = File::options()
        .write(true)
        .open(path)
        .expect("open for set_modified");
    f.set_modified(target).expect("set_modified");
}

fn options() -> CollectOptions {
    // Use a very generous active window for unit tests so freshly-written
    // fixture files (mtime = now) always qualify regardless of any small
    // clock skew or delays during the test run.
    CollectOptions {
        limit: 4,
        active_window_minutes: 60,
        project_hints: Vec::new(),
    }
}

#[test]
fn cursor_collects_txt_and_jsonl() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let txn_dir = home.join(".cursor/projects/some-project/agent-transcripts");
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
fn active_window_excludes_stale_sessions_across_agents() {
    // The collectors must apply `active_window_minutes` as a strict
    // filter: a session whose mtime is older than the active window has
    // already had its intent ingested by an earlier tick and should not
    // come back in. This test exercises every per-agent adapter to
    // guarantee none of them regress to a recency-only filter.
    //
    // Strategy:
    //   1. Drop a "fresh" transcript and a "stale" transcript per agent.
    //   2. Backdate the stale transcript well past the active window.
    //   3. Collect with active_window_minutes = 1 minute.
    //   4. Assert: only the fresh transcript appears in the payload.
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let stale_age_secs = 60 * 60; // 1 hour ago, comfortably past 1-minute window

    let line =
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"FRESH\"}]}}\n";
    let line_stale =
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"STALE\"}]}}\n";

    // Cursor: fresh and stale agent-transcripts under .cursor/projects.
    let cursor_fresh = home.join(".cursor/projects/proj/agent-transcripts/fresh/fresh.jsonl");
    let cursor_stale = home.join(".cursor/projects/proj/agent-transcripts/stale/stale.jsonl");
    write(&cursor_fresh, line);
    write(&cursor_stale, line_stale);
    make_stale(&cursor_stale, stale_age_secs);

    // Claude Code: fresh and stale projects.
    let cc_fresh = home.join(".claude/projects/fresh/fresh.jsonl");
    let cc_stale = home.join(".claude/projects/stale/stale.jsonl");
    write(&cc_fresh, line);
    write(&cc_stale, line_stale);
    make_stale(&cc_stale, stale_age_secs);

    // OpenClaw: fresh and stale agents.
    let oc_fresh = home.join(".openclaw/agents/main/sessions/fresh.jsonl");
    let oc_stale = home.join(".openclaw/agents/main/sessions/stale.jsonl");
    write(&oc_fresh, line);
    write(&oc_stale, line_stale);
    make_stale(&oc_stale, stale_age_secs);

    let opts = CollectOptions {
        limit: 10,
        active_window_minutes: 1,
        project_hints: Vec::new(),
    };

    for agent in &["cursor", "claude_code", "openclaw"] {
        let result = collect(agent, home, &opts).expect("collect");
        let texts: Vec<String> = result
            .payload
            .sessions
            .iter()
            .map(|s| s.user_text.clone())
            .collect();
        assert!(
            texts.iter().any(|t| t.contains("FRESH")),
            "{}: expected FRESH session in payload, got {:?}",
            agent,
            texts
        );
        assert!(
            !texts.iter().any(|t| t.contains("STALE")),
            "{}: stale session should be filtered out, got {:?}",
            agent,
            texts
        );
    }
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
    assert!(session
        .commands
        .iter()
        .any(|c| c.starts_with("kubectl apply")));
}

#[test]
#[serial]
fn claude_desktop_collects_cowork_root_only() {
    // Save originals so concurrent or subsequent tests in the same binary
    // (notably runner_cli's APPDATA-reading tests) see the runner-provided
    // values after this test exits. `#[serial]` keeps env-var-touching tests
    // mutually exclusive.
    let saved_xdg = std::env::var("XDG_DATA_HOME").ok();
    let saved_appdata = std::env::var("APPDATA").ok();

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

    // The cowork lookup respects XDG_DATA_HOME on Linux and APPDATA on Windows;
    // override or clear them so the test's home-relative path is picked up. On
    // CI runners these env vars point at the runner user's actual profile, not
    // the test's tempdir.
    #[cfg(target_os = "linux")]
    std::env::remove_var("XDG_DATA_HOME");
    #[cfg(target_os = "windows")]
    {
        let appdata = home.join("AppData").join("Roaming");
        std::env::set_var("APPDATA", &appdata);
    }

    let result = collect("claude_desktop", home, &options()).expect("claude_desktop collect");

    // Restore env-var state before assertions so a panic still leaves the
    // process in a clean state for subsequent serial tests.
    match saved_xdg {
        Some(value) => std::env::set_var("XDG_DATA_HOME", value),
        None => std::env::remove_var("XDG_DATA_HOME"),
    }
    match saved_appdata {
        Some(value) => std::env::set_var("APPDATA", value),
        None => std::env::remove_var("APPDATA"),
    }

    assert_eq!(result.payload.agent_type, "claude_desktop");
    assert!(result.diagnostics.transcripts_root_accessible);
    assert_eq!(result.payload.sessions.len(), 1);
    let texts: Vec<String> = result
        .payload
        .sessions
        .iter()
        .map(|s| s.user_text.clone())
        .collect();
    assert!(
        !texts.iter().any(|t| t.contains("hello from code")),
        "Claude Desktop must not re-ingest Claude Code project transcripts"
    );
    assert!(texts.iter().any(|t| t.contains("hello from cowork")));
    assert_eq!(result.diagnostics.transcripts_roots.len(), 1);
    assert!(result.diagnostics.transcripts_roots[0].contains("local-agent-mode-sessions"));
}

#[test]
#[serial]
fn codex_collects_rollout_jsonl() {
    // Codex respects CODEX_HOME if set; clear it so the default home-relative
    // path is picked up. On CI runners this is normally unset, but we clear
    // defensively so the test stays deterministic.
    let saved_codex_home = std::env::var("CODEX_HOME").ok();
    std::env::remove_var("CODEX_HOME");

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

    // Restore CODEX_HOME so other tests (and the runner-provided value) are
    // unaffected.
    match saved_codex_home {
        Some(value) => std::env::set_var("CODEX_HOME", value),
        None => std::env::remove_var("CODEX_HOME"),
    }

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
fn openclaw_collects_from_default_main_agent() {
    // OpenClaw stores per-agent sessions under
    // `~/.openclaw/agents/<name>/sessions/`. The default agent created by
    // `openclaw init` is `main`; the observer must follow that layout.
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let sessions = home.join(".openclaw/agents/main/sessions");
    write(
        &sessions.join("session-1.jsonl"),
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"openclaw scan\"}]}}\n",
    );
    let result = collect("openclaw", home, &options()).expect("openclaw collect");
    assert!(result.diagnostics.transcripts_root_accessible);
    // Use Path::ends_with so the assertion is path-component-aware and
    // works on Windows runners where transcripts_roots come back with
    // backslash separators.
    assert!(
        result.diagnostics.transcripts_roots.iter().any(
            |r| std::path::Path::new(r).ends_with(std::path::Path::new("agents/main/sessions"))
        ),
        "diagnostics should expose the per-agent sessions dir, got {:?}",
        result.diagnostics.transcripts_roots
    );
    assert_eq!(result.payload.sessions.len(), 1);
    assert!(result.payload.sessions[0]
        .user_text
        .contains("openclaw scan"));
}

#[test]
fn openclaw_collates_transcripts_across_multiple_agents() {
    // Operators routinely run several named OpenClaw agents in parallel
    // (e.g. `main` plus a dedicated `sales` agent); discovery must walk
    // every `agents/<name>/sessions/` rather than hardcoding a single
    // slug.
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let agents_dir = home.join(".openclaw/agents");
    write(
        &agents_dir.join("main/sessions/main-1.jsonl"),
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"main agent intent\"}]}}\n",
    );
    write(
        &agents_dir.join("sales/sessions/sales-1.jsonl"),
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"sales agent intent\"}]}}\n",
    );
    let result = collect("openclaw", home, &options()).expect("openclaw collect");
    assert!(result.diagnostics.transcripts_root_accessible);
    assert_eq!(result.payload.sessions.len(), 2);
    let texts: Vec<String> = result
        .payload
        .sessions
        .iter()
        .map(|s| s.user_text.clone())
        .collect();
    assert!(texts.iter().any(|t| t.contains("main agent intent")));
    assert!(texts.iter().any(|t| t.contains("sales agent intent")));
}

#[test]
fn openclaw_legacy_root_layout_is_no_longer_probed() {
    // The earlier (pre-fix) heuristic probed `~/.openclaw/sessions/` and
    // `~/.openclaw/state/sessions/`. OpenClaw never actually wrote there;
    // confirm transcripts in those locations stay invisible to discovery
    // so we don't regress to the broken layout.
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    write(
        &home.join(".openclaw/sessions/legacy.jsonl"),
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"legacy\"}]}}\n",
    );
    write(
        &home.join(".openclaw/state/sessions/legacy.jsonl"),
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"legacy\"}]}}\n",
    );
    let result = collect("openclaw", home, &options()).expect("openclaw collect");
    assert!(!result.diagnostics.transcripts_root_accessible);
    assert!(result.payload.sessions.is_empty());
}

#[test]
#[serial]
fn hermes_returns_empty_and_undiscovered_when_absent() {
    // HERMES_HOME overrides the default ~/.hermes; clear it so the test's
    // home-relative path is used and stays deterministic on CI runners.
    let saved_hermes_home = std::env::var("HERMES_HOME").ok();
    std::env::remove_var("HERMES_HOME");

    let temp = tempfile::tempdir().expect("tempdir");
    let result = collect("hermes", temp.path(), &options()).expect("hermes collect");

    match saved_hermes_home {
        Some(value) => std::env::set_var("HERMES_HOME", value),
        None => std::env::remove_var("HERMES_HOME"),
    }

    assert_eq!(result.payload.agent_type, "hermes");
    assert!(
        !result.diagnostics.transcripts_root_accessible,
        "no ~/.hermes should mean not discovered"
    );
    assert!(result.payload.sessions.is_empty());
}

#[test]
#[serial]
fn hermes_discovered_via_config_even_without_transcripts() {
    // The unsecured_hermes threat fires on discovered && !enabled. Hermes
    // stores sessions in SQLite, which the L1 observer does not read, so
    // "discovered" MUST be driven by the presence of a Hermes store/config,
    // not by ingestible transcript content.
    let saved_hermes_home = std::env::var("HERMES_HOME").ok();
    std::env::remove_var("HERMES_HOME");

    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    write(&home.join(".hermes/config.yaml"), "mcp_servers: {}\n");
    write(&home.join(".hermes/sessions.db"), "SQLite format 3\0");

    let result = collect("hermes", home, &options()).expect("hermes collect");

    match saved_hermes_home {
        Some(value) => std::env::set_var("HERMES_HOME", value),
        None => std::env::remove_var("HERMES_HOME"),
    }

    assert!(
        result.diagnostics.transcripts_root_accessible,
        "Hermes config + SQLite db must mark the host as discovered"
    );
    assert!(
        result.payload.sessions.is_empty(),
        "no JSON/JSONL transcripts means no ingested sessions"
    );
}

#[test]
#[serial]
fn hermes_collects_jsonl_sessions() {
    let saved_hermes_home = std::env::var("HERMES_HOME").ok();
    std::env::remove_var("HERMES_HOME");

    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let sessions = home.join(".hermes/sessions");
    let line_user =
        "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"clone the repo and run tests\"}]}}";
    let line_assistant = "{\"role\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"running cargo test --lib now\"}]}}";
    write(
        &sessions.join("session-1.jsonl"),
        &format!("{}\n{}\n", line_user, line_assistant),
    );
    let result = collect("hermes", home, &options()).expect("hermes collect");

    match saved_hermes_home {
        Some(value) => std::env::set_var("HERMES_HOME", value),
        None => std::env::remove_var("HERMES_HOME"),
    }

    assert_eq!(result.payload.agent_type, "hermes");
    assert!(result.diagnostics.transcripts_root_accessible);
    assert_eq!(result.payload.sessions.len(), 1);
    let session = &result.payload.sessions[0];
    assert!(session.user_text.contains("clone the repo"));
    assert!(session.commands.iter().any(|c| c.starts_with("cargo test")));
}

#[test]
#[serial]
fn hermes_collects_from_sessions_json_manifest() {
    // When Hermes exposes a sessions.json manifest (rather than per-session
    // JSONL files), the tolerant manifest reader should still ingest the
    // recorded intent.
    let saved_hermes_home = std::env::var("HERMES_HOME").ok();
    std::env::remove_var("HERMES_HOME");

    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let manifest = home.join(".hermes/sessions.json");
    let body = r#"{
        "sessions": [
            {
                "id": "abc123",
                "title": "deploy staging",
                "messages": [
                    {"role": "user", "content": "deploy to staging with kubectl apply -f deploy.yaml"},
                    {"role": "assistant", "content": "running kubectl apply -f deploy.yaml"}
                ]
            }
        ]
    }"#;
    write(&manifest, body);

    let result = collect("hermes", home, &options()).expect("hermes collect");

    match saved_hermes_home {
        Some(value) => std::env::set_var("HERMES_HOME", value),
        None => std::env::remove_var("HERMES_HOME"),
    }

    assert!(result.diagnostics.transcripts_root_accessible);
    assert_eq!(result.payload.sessions.len(), 1);
    let session = &result.payload.sessions[0];
    assert_eq!(session.session_key, "abc123");
    assert_eq!(session.title, "deploy staging");
    assert!(session.user_text.contains("deploy to staging"));
    assert!(session
        .commands
        .iter()
        .any(|c| c.starts_with("kubectl apply")));
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
fn agent_identity_lineage_paths_keeps_identity_drops_generic() {
    // Representative mix of identity-specific and generic runtime patterns,
    // mirroring the shape of the real `*_SCOPE_PARENT_PATHS` constants.
    let mixed = [
        "*/claude",
        "*\\claude.exe",
        "*/program files/claude",
        "*/node",
        "*\\node.exe",
        "*/.nvm/",
        "*/.volta/",
        "*/flatpak/",
        "*/nix/store/",
        "*/windowsapps/",
    ];
    let kept = super::agent_identity_lineage_paths("claude_code", &mixed);
    assert!(
        kept.iter()
            .all(|p| p.to_ascii_lowercase().contains("claude")),
        "every kept entry must carry the agent identity token, got: {:?}",
        kept
    );
    for generic in [
        "*/node",
        "*\\node.exe",
        "*/.nvm/",
        "*/.volta/",
        "*/flatpak/",
        "*/nix/store/",
        "*/windowsapps/",
    ] {
        assert!(
            !kept.iter().any(|p| p == generic),
            "generic runtime pattern {} must be dropped, got: {:?}",
            generic,
            kept
        );
    }
    assert!(kept.iter().any(|p| p == "*\\claude.exe"));

    // Unknown agent types contribute no any-lineage scope.
    assert!(super::agent_identity_lineage_paths("does_not_exist", &mixed).is_empty());
}

#[test]
fn collect_populates_identity_only_any_lineage_scope() {
    // Drives the REAL CURSOR_SCOPE_PARENT_PATHS through the wiring and asserts
    // the produced session's any-lineage scope is non-empty and identity-only
    // (no generic `node` / `flatpak` runtime patterns leak in).
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let txn_dir = home.join(".cursor/projects/proj/agent-transcripts");
    write(
        &txn_dir.join("session.txt"),
        "user:\nrun curl https://example.com/health\nassistant:\nokay\n",
    );
    let result = collect("cursor", home, &options()).expect("collect");
    let session = result
        .payload
        .sessions
        .first()
        .expect("at least one cursor session");
    assert!(
        !session.derived_scope_any_lineage_paths.is_empty(),
        "cursor any-lineage scope must be populated for Windows grandparent attribution"
    );
    assert!(
        session
            .derived_scope_any_lineage_paths
            .iter()
            .all(|p| p.to_ascii_lowercase().contains("cursor")),
        "any-lineage scope must be identity-only, got: {:?}",
        session.derived_scope_any_lineage_paths
    );
    assert!(
        !session
            .derived_scope_any_lineage_paths
            .iter()
            .any(|p| p == "*/node" || p == "*/flatpak/"),
        "generic runtime patterns must not leak into any-lineage scope"
    );
}

#[test]
fn cursor_economics_prefers_jsonl_sibling_over_txt() {
    // G4: Cursor's divergence text comes from the `.txt` export (newer mtime),
    // which carries NO token usage. A usage-bearing `.jsonl` sibling exists.
    // `collect` must populate `economics_raw_text` from that sibling so the
    // economics parser recovers exact usage, while `raw_text` (the `.txt`) stays
    // the usage-free divergence source.
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let txn_dir = home.join(".cursor/projects/proj/agent-transcripts");
    // jsonl first (older), then txt (newer) so divergence prefers the txt.
    write(
        &txn_dir.join("session-econ.jsonl"),
        concat!(
            r#"{"type":"assistant","timestamp":"2026-05-06T18:15:10.000Z","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1200,"output_tokens":340,"cache_read_input_tokens":900}}}"#,
            "\n",
        ),
    );
    write(
        &txn_dir.join("session-econ.txt"),
        "user:\nplease run cargo build\n\nassistant:\nRunning `cargo build` now.\n",
    );

    let result = collect("cursor", home, &options()).expect("cursor collect");
    let session = result
        .payload
        .sessions
        .iter()
        .find(|s| s.session_key == "session-econ")
        .expect("session-econ present");

    // Divergence text is the usage-free .txt: parsing it directly yields nothing.
    let from_raw = super::parsing::parse_session_economics(
        &session.session_key,
        &session.source_path,
        &session.raw_text,
    );
    assert!(
        !from_raw.has_token_data,
        "the .txt divergence source must carry no usage"
    );

    // The override carries the usage-bearing .jsonl sibling.
    assert!(
        !session.economics_raw_text.is_empty(),
        "economics_raw_text must be populated from the .jsonl sibling"
    );
    // The tiny sibling is well within the cap, so it is not flagged truncated.
    assert!(
        !session.economics_truncated,
        "a within-cap .jsonl sibling must not be flagged truncated"
    );
    let from_override = super::parsing::parse_session_economics(
        &session.session_key,
        &session.source_path,
        &session.economics_raw_text,
    );
    assert!(from_override.has_token_data, "override must carry usage");
    assert_eq!(from_override.input_tokens, 1200);
    assert_eq!(from_override.output_tokens, 340);
    assert_eq!(from_override.cache_read_input_tokens, 900);
    assert!(from_override.est_cost_usd > 0.0);
}

#[test]
fn economics_override_recovers_codex_eof_usage_past_cap() {
    // G5: Codex writes the cumulative `total_token_usage` snapshot at EOF. A
    // long session exceeds MAX_TRANSCRIPT_BYTES, so the head-only
    // `read_transcript_capped` loses that EOF snapshot. The economics override
    // re-reads head+tail so the final cumulative count survives.
    use std::io::Write;

    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("codex-oversized.jsonl");

    let head_snapshot = concat!(
        r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":"#,
        r#"{"input_tokens":10,"output_tokens":5,"total_tokens":15}}}}"#,
    );
    let eof_snapshot = concat!(
        r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":"#,
        r#"{"input_tokens":500000,"output_tokens":90000,"total_tokens":590000}}}}"#,
    );

    {
        let file = File::create(&path).expect("create oversized transcript");
        let mut writer = std::io::BufWriter::new(file);
        writeln!(writer, "{}", head_snapshot).expect("write head");
        // ~17 MiB of non-JSON filler so the file exceeds the 16 MiB cap and the
        // EOF snapshot lands beyond the head-only read. Each filler line parses
        // as an error and is skipped by the economics parser.
        let filler = "x".repeat(1024 * 1024);
        for _ in 0..17 {
            writeln!(writer, "{}", filler).expect("write filler");
        }
        writeln!(writer, "{}", eof_snapshot).expect("write eof");
        writer.flush().expect("flush");
    }

    assert!(
        std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > super::MAX_TRANSCRIPT_BYTES,
        "fixture must exceed the transcript cap"
    );

    // Head-only capped read sees only the small head snapshot -> undercount.
    let capped = super::read_transcript_capped(&path).expect("capped read");
    let from_capped =
        super::parsing::parse_session_economics("codex-1", &path.to_string_lossy(), &capped);
    assert_eq!(
        from_capped.total_tokens, 15,
        "head-only read must miss the EOF cumulative snapshot"
    );

    // Head+tail override recovers the final cumulative snapshot.
    let override_econ = super::economics_override_text(&path.to_string_lossy());
    assert!(
        !override_econ.text.is_empty(),
        "oversized transcript must trigger a head+tail override"
    );
    assert!(
        override_econ.truncated,
        "an oversized transcript override must be flagged truncated"
    );
    let from_override = super::parsing::parse_session_economics(
        "codex-1",
        &path.to_string_lossy(),
        &override_econ.text,
    );
    assert_eq!(from_override.input_tokens, 500000);
    assert_eq!(from_override.output_tokens, 90000);
    assert_eq!(
        from_override.total_tokens, 590000,
        "override must recover the EOF cumulative usage"
    );
}

#[test]
fn economics_derives_per_turn_latency_throughput_and_provider_errors() {
    // Workstream C (derived tier): a Claude-shape transcript with per-turn
    // timestamps. Two user->assistant turns (2.0s and 1.5s) and one provider
    // overload event. Latency, throughput, and the inferred-error signal must
    // be derived from `assistant_ts - preceding-trigger_ts` per turn.
    let raw = concat!(
        r#"{"type":"user","timestamp":"2026-05-06T18:15:00.000Z","message":{"role":"user","content":[{"type":"text","text":"hi"}]}}"#,
        "\n",
        r#"{"type":"assistant","timestamp":"2026-05-06T18:15:02.000Z","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1000,"output_tokens":340}}}"#,
        "\n",
        r#"{"type":"user","timestamp":"2026-05-06T18:15:05.000Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":"done"}]}}"#,
        "\n",
        r#"{"type":"assistant","timestamp":"2026-05-06T18:15:06.500Z","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"done"}],"usage":{"input_tokens":1100,"output_tokens":150}}}"#,
        "\n",
        r#"{"type":"error","timestamp":"2026-05-06T18:15:07.000Z","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
        "\n",
    );

    let econ =
        super::parsing::parse_session_economics("claude-turns", "/tmp/claude-turns.jsonl", raw);

    assert_eq!(econ.turn_latency_samples, 2, "two measurable turns");
    assert_eq!(
        econ.turn_latency_ms_total, 3500,
        "2000ms + 1500ms summed latency"
    );
    assert_eq!(econ.turn_latency_ms_max, 2000, "slowest turn was 2.0s");
    assert_eq!(
        econ.turn_output_tokens_total, 490,
        "340 + 150 output tokens over the throughput subset"
    );
    assert_eq!(
        econ.turn_throughput_ms_total, 3500,
        "both turns had output and positive latency"
    );
    assert_eq!(
        econ.inferred_provider_errors, 1,
        "one overloaded_error event line"
    );

    // Derived convenience values consumers compute from the raw components.
    let avg_latency_ms = econ.turn_latency_ms_total / econ.turn_latency_samples;
    assert_eq!(avg_latency_ms, 1750);
    let tokens_per_second =
        econ.turn_output_tokens_total as f64 * 1000.0 / econ.turn_throughput_ms_total as f64;
    assert!(
        (tokens_per_second - 140.0).abs() < 1e-9,
        "490 tok / 3.5s = 140 tok/s"
    );
}

#[test]
fn economics_per_turn_timing_absent_without_timestamps() {
    // Cursor `.txt` and any usage-free / timestamp-free shape must yield zero
    // per-turn responsiveness rather than fabricated samples.
    let raw = "user:\nplease build\n\nassistant:\nbuilding now\n";
    let econ = super::parsing::parse_session_economics("notxt", "/tmp/notxt.txt", raw);
    assert_eq!(econ.turn_latency_samples, 0);
    assert_eq!(econ.turn_latency_ms_total, 0);
    assert_eq!(econ.turn_throughput_ms_total, 0);
    assert_eq!(econ.inferred_provider_errors, 0);
}

#[test]
fn collect_to_json_round_trips() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path();
    let txn_dir = home.join(".cursor/projects/proj/agent-transcripts");
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
