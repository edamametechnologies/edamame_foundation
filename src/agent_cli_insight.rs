//! Agent-CLI transport for the Enlightenment Coach and the fix runner.
//!
//! Two spawn disciplines share the binary-resolution and parsing logic:
//!
//! - **Insight** (`run_agent_cli_insight`): read-only, ephemeral, tools
//!   disabled, prompt on stdin, waits for completion and extracts the model's
//!   text answer from the CLI's structured stdout. Used ONLY when no
//!   `LLMClient` provider is configured -- the observed agent grades its own
//!   homework, which the caller must badge visibly.
//! - **Fix** (`run_agent_cli_fix`): user-initiated, workspace cwd, normal
//!   tool permissions, session persistence ON (the resulting session is
//!   recorded and re-graded by the transcript observer like any other).
//!   Spawns detached and returns the spawn confirmation, never the output.
//!
//! Both standalone core and the helper daemon converge on these functions per
//! the Standalone vs Helper Dispatch Pattern.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use tracing::info;

/// Wall-clock budget for a blocking insight generation.
const INSIGHT_TIMEOUT_SECS: u64 = 180;

/// Agent types with a known headless CLI, in detection preference order.
/// (agent_type, binary name). Cursor ranks last for the insight transport:
/// `cursor-agent` has no ephemeral-session flag, so its insight runs land in
/// the observed transcript corpus (ask-mode read-only, but still recorded).
const AGENT_CLI_BINARIES: &[(&str, &str)] = &[
    ("claude_code", "claude"),
    ("codex", "codex"),
    ("cursor", "cursor-agent"),
];

/// The CLI binary name for a supported agent type, if it has one.
pub fn agent_cli_binary_name(agent_type: &str) -> Option<&'static str> {
    AGENT_CLI_BINARIES
        .iter()
        .find(|(t, _)| *t == agent_type)
        .map(|(_, b)| *b)
}

/// Candidate directories to search besides `$PATH`. The helper daemon runs
/// as root with a minimal PATH, so the user's standard install locations
/// (npm globals, homebrew, ~/.local) must be probed explicitly against the
/// provided real home.
fn candidate_bin_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(path_env) = std::env::var("PATH") {
        dirs.extend(std::env::split_paths(&path_env));
    }
    for fixed in [
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/bin",
        "/snap/bin",
    ] {
        dirs.push(PathBuf::from(fixed));
    }
    if let Some(home) = home {
        for rel in [
            ".local/bin",
            ".npm-global/bin",
            ".volta/bin",
            ".bun/bin",
            "bin",
            "AppData/Roaming/npm",
            "AppData/Local/Programs/claude/bin",
        ] {
            dirs.push(home.join(rel));
        }
    }
    dirs
}

fn binary_file_names(binary: &str) -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        vec![
            format!("{}.exe", binary),
            format!("{}.cmd", binary),
            format!("{}.bat", binary),
            binary.to_string(),
        ]
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![binary.to_string()]
    }
}

/// Resolve the absolute path of the agent's CLI binary, or `None` when it is
/// not installed. `home` is the (real) user home used to probe user-level
/// install locations; pass `None` to rely on `$PATH` + fixed system dirs.
pub fn resolve_agent_cli_binary(agent_type: &str, home: Option<&Path>) -> Option<PathBuf> {
    let binary = agent_cli_binary_name(agent_type)?;
    let names = binary_file_names(binary);
    for dir in candidate_bin_dirs(home) {
        for name in &names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Which of the given agent types have a detected CLI on this host, in the
/// canonical preference order (claude_code, then codex, then cursor).
/// Unknown agent types are skipped.
pub fn detect_agent_clis(agent_types: &[String], home: Option<&Path>) -> Vec<String> {
    AGENT_CLI_BINARIES
        .iter()
        .filter(|(t, _)| agent_types.iter().any(|a| a == t))
        .filter(|(t, _)| resolve_agent_cli_binary(t, home).is_some())
        .map(|(t, _)| t.to_string())
        .collect()
}

/// Spawn confirmation for a detached fix run. The agent's output is NOT
/// captured -- the resulting session shows up in the transcript observer
/// and gets graded by the normal pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCliFixSpawn {
    pub agent_type: String,
    pub binary: String,
    pub workspace_path: String,
    pub pid: u32,
    /// The exact argv (binary + args) shown to the user in the confirmation
    /// dialog and logged for the audit trail.
    pub command: Vec<String>,
}

fn insight_args(agent_type: &str) -> Vec<String> {
    match agent_type {
        // Prompt on stdin, JSON result on stdout, no session persistence,
        // all tools disabled -- the coach transport must never mutate state
        // or pollute the observed transcript corpus.
        "claude_code" => vec![
            "-p".into(),
            "--output-format".into(),
            "json".into(),
            "--no-session-persistence".into(),
            "--tools".into(),
            String::new(),
        ],
        // Prompt on stdin (trailing `-`), JSONL events on stdout, read-only
        // sandbox, ephemeral session.
        "codex" => vec![
            "exec".into(),
            "--json".into(),
            "--sandbox".into(),
            "read-only".into(),
            "--skip-git-repo-check".into(),
            "--ephemeral".into(),
            "-".into(),
        ],
        // Prompt on stdin, plain-text answer on stdout (no structured parse
        // needed), ask mode = read-only Q&A. No ephemeral flag exists, so the
        // run is recorded in Cursor's session history -- acceptable for the
        // last-resort transport, and why cursor ranks last in preference.
        "cursor" => vec![
            "-p".into(),
            "--output-format".into(),
            "text".into(),
            "--mode".into(),
            "ask".into(),
            "--trust".into(),
        ],
        _ => Vec::new(),
    }
}

fn fix_args(agent_type: &str, prompt: &str) -> Vec<String> {
    match agent_type {
        // Session persistence stays ON: the fix session IS recorded so the
        // same pipeline grades it.
        "claude_code" => vec!["-p".into(), prompt.to_string()],
        "codex" => vec![
            "exec".into(),
            "--skip-git-repo-check".into(),
            prompt.to_string(),
        ],
        // Print mode with full tool access; `--force` allows command
        // execution and `--trust` skips the workspace-trust prompt (the run
        // is detached with stdin closed, so any interactive prompt would
        // wedge it). The workspace itself is already user-confirmed and
        // report-guardrailed by the caller.
        "cursor" => vec![
            "-p".into(),
            "--force".into(),
            "--trust".into(),
            prompt.to_string(),
        ],
        _ => Vec::new(),
    }
}

fn configure_command(command: &mut Command, home: Option<&Path>) {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(home) = home {
        command.env("HOME", home);
        // Make user-level installs resolvable from the helper's minimal PATH.
        if let Ok(path_env) = std::env::var("PATH") {
            let mut paths: Vec<PathBuf> = std::env::split_paths(&path_env).collect();
            paths.extend(candidate_bin_dirs(Some(home)));
            if let Ok(joined) = std::env::join_paths(paths) {
                command.env("PATH", joined);
            }
        }
    }
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
}

/// Run a read-only, ephemeral insight generation through the detected agent
/// CLI. The prompt goes to stdin; the returned string is the extracted model
/// text (the caller validates it against the coach envelope schema).
pub async fn run_agent_cli_insight(
    agent_type: &str,
    prompt: &str,
    home: Option<&Path>,
) -> Result<String> {
    let binary = resolve_agent_cli_binary(agent_type, home)
        .ok_or_else(|| anyhow!("No CLI detected for agent type '{}'", agent_type))?;
    let args = insight_args(agent_type);
    if args.is_empty() {
        return Err(anyhow!(
            "Agent type '{}' has no insight CLI invocation",
            agent_type
        ));
    }

    info!(
        "Running agent-CLI insight via {} ({} bytes of prompt)",
        binary.display(),
        prompt.len()
    );
    let mut command = Command::new(&binary);
    command.args(&args);
    configure_command(&mut command, home);

    let mut child = command
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn {}: {}", binary.display(), e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(prompt.as_bytes())
            .await
            .map_err(|e| anyhow!("Failed to write prompt to agent CLI stdin: {}", e))?;
        drop(stdin);
    }

    let output = timeout(
        Duration::from_secs(INSIGHT_TIMEOUT_SECS),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "Agent CLI insight timed out after {}s",
            INSIGHT_TIMEOUT_SECS
        )
    })?
    .map_err(|e| anyhow!("Agent CLI insight failed: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Agent CLI exited with {}: {}",
            output.status,
            stderr.chars().take(500).collect::<String>()
        ));
    }

    let text = parse_agent_cli_output(agent_type, &stdout);
    if text.trim().is_empty() {
        return Err(anyhow!("Agent CLI produced no extractable output"));
    }
    Ok(text)
}

/// Spawn a user-confirmed fix run in the given workspace and return the
/// spawn confirmation immediately (detached -- output is not captured).
pub async fn run_agent_cli_fix(
    agent_type: &str,
    workspace_path: &str,
    prompt: &str,
    home: Option<&Path>,
) -> Result<AgentCliFixSpawn> {
    let binary = resolve_agent_cli_binary(agent_type, home)
        .ok_or_else(|| anyhow!("No CLI detected for agent type '{}'", agent_type))?;
    let workspace = Path::new(workspace_path);
    if !workspace.is_dir() {
        return Err(anyhow!(
            "Workspace path '{}' is not a directory",
            workspace_path
        ));
    }
    let args = fix_args(agent_type, prompt);
    if args.is_empty() {
        return Err(anyhow!(
            "Agent type '{}' has no fix CLI invocation",
            agent_type
        ));
    }

    let mut command = Command::new(&binary);
    command.args(&args).current_dir(workspace);
    configure_command(&mut command, home);
    // Detached: nothing reads these pipes after spawn.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = command
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn {}: {}", binary.display(), e))?;
    let pid = child.id().unwrap_or(0);

    let mut argv = vec![binary.to_string_lossy().to_string()];
    argv.extend(args);
    info!(
        "Spawned fix run: agent={} pid={} workspace={}",
        agent_type, pid, workspace_path
    );

    Ok(AgentCliFixSpawn {
        agent_type: agent_type.to_string(),
        binary: binary.to_string_lossy().to_string(),
        workspace_path: workspace_path.to_string(),
        pid,
        command: argv,
    })
}

/// Extract the model's text answer from the CLI's structured stdout.
///
/// - Claude (`--output-format json`): a single JSON object with a `result`
///   string, OR (older CLI versions) a JSON array of events where the last
///   `{"type":"result"}` entry carries the text.
/// - Codex (`--json`): JSONL events; the answer is the last agent-message
///   item (`item.completed` with `item.type == "agent_message"`, or an
///   `agent_message` / `AgentMessage` event with a text/message field).
///
/// Falls back to the raw stdout when no structured shape matches, so the
/// downstream envelope validator still gets a chance.
pub fn parse_agent_cli_output(agent_type: &str, stdout: &str) -> String {
    let trimmed = stdout.trim();
    match agent_type {
        "claude_code" => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(text) = claude_result_text(&value) {
                    return text;
                }
            }
            trimmed.to_string()
        }
        "codex" => {
            let mut last_message: Option<String> = None;
            for line in trimmed.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if let Some(text) = codex_event_text(&value) {
                    last_message = Some(text);
                }
            }
            last_message.unwrap_or_else(|| trimmed.to_string())
        }
        _ => trimmed.to_string(),
    }
}

fn claude_result_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => map
            .get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string()),
        serde_json::Value::Array(events) => events
            .iter()
            .rev()
            .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("result"))
            .and_then(|e| e.get("result"))
            .and_then(|r| r.as_str())
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn codex_event_text(value: &serde_json::Value) -> Option<String> {
    // Shape 1: {"type":"item.completed","item":{"type":"agent_message","text":"..."}}
    if value.get("type").and_then(|t| t.as_str()) == Some("item.completed") {
        let item = value.get("item")?;
        if item.get("type").and_then(|t| t.as_str()) == Some("agent_message") {
            return item
                .get("text")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());
        }
        return None;
    }
    // Shape 2: {"msg":{"type":"agent_message","message":"..."}} (event stream)
    if let Some(msg) = value.get("msg") {
        if msg.get("type").and_then(|t| t.as_str()) == Some("agent_message") {
            return msg
                .get("message")
                .or_else(|| msg.get("text"))
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_object_result_is_extracted() {
        let out = r#"{"type":"result","subtype":"success","result":"{\"summary\":\"ok\"}","total_cost_usd":0.01}"#;
        assert_eq!(
            parse_agent_cli_output("claude_code", out),
            "{\"summary\":\"ok\"}"
        );
    }

    #[test]
    fn claude_event_array_result_is_extracted() {
        let out = r#"[
            {"type":"system","subtype":"init"},
            {"type":"assistant","message":{"content":[{"type":"text","text":"thinking"}]}},
            {"type":"result","subtype":"success","result":"FINAL ANSWER"}
        ]"#;
        assert_eq!(parse_agent_cli_output("claude_code", out), "FINAL ANSWER");
    }

    #[test]
    fn claude_unstructured_output_falls_back_to_raw() {
        let out = "plain text answer";
        assert_eq!(parse_agent_cli_output("claude_code", out), out);
    }

    #[test]
    fn codex_jsonl_last_agent_message_wins() {
        let out = r#"{"type":"thread.started","thread_id":"t1"}
{"type":"item.completed","item":{"type":"reasoning","text":"hmm"}}
{"type":"item.completed","item":{"type":"agent_message","text":"first"}}
{"type":"item.completed","item":{"type":"agent_message","text":"LAST"}}
{"type":"turn.completed","usage":{"input_tokens":10}}"#;
        assert_eq!(parse_agent_cli_output("codex", out), "LAST");
    }

    #[test]
    fn codex_msg_event_shape_is_extracted() {
        let out = r#"{"id":"0","msg":{"type":"task_started"}}
{"id":"1","msg":{"type":"agent_message","message":"answer body"}}"#;
        assert_eq!(parse_agent_cli_output("codex", out), "answer body");
    }

    #[test]
    fn codex_no_agent_message_falls_back_to_raw() {
        let out = r#"{"type":"turn.completed"}"#;
        assert_eq!(parse_agent_cli_output("codex", out), out);
    }

    #[test]
    fn binary_names_map_known_agents_only() {
        assert_eq!(agent_cli_binary_name("claude_code"), Some("claude"));
        assert_eq!(agent_cli_binary_name("codex"), Some("codex"));
        assert_eq!(agent_cli_binary_name("cursor"), Some("cursor-agent"));
        assert_eq!(agent_cli_binary_name("openclaw"), None);
    }

    #[test]
    fn detect_skips_unknown_and_missing() {
        // "hermes" has no CLI mapping; a nonexistent home yields no user dirs
        // and an empty PATH hit for the mapped types.
        let detected = detect_agent_clis(
            &["hermes".to_string(), "openclaw".to_string()],
            Some(Path::new("/nonexistent")),
        );
        assert!(detected.is_empty());
    }

    #[test]
    fn insight_args_are_read_only_and_ephemeral() {
        let claude = insight_args("claude_code");
        assert!(claude.contains(&"--no-session-persistence".to_string()));
        assert!(claude.contains(&"--tools".to_string()));

        let codex = insight_args("codex");
        assert!(codex.contains(&"read-only".to_string()));
        assert!(codex.contains(&"--ephemeral".to_string()));

        // Cursor has no ephemeral flag; ask mode is its read-only discipline.
        let cursor = insight_args("cursor");
        assert!(cursor.contains(&"ask".to_string()));
        assert!(!cursor.contains(&"--force".to_string()));

        assert!(insight_args("hermes").is_empty());
    }

    #[test]
    fn fix_args_keep_session_persistence_and_normal_tools() {
        // The fix run must be recorded and re-graded by the transcript
        // observer, so the ephemeral/read-only insight flags must NOT leak in.
        let claude = fix_args("claude_code", "do the fix");
        assert_eq!(claude, vec!["-p".to_string(), "do the fix".to_string()]);
        assert!(!claude.contains(&"--no-session-persistence".to_string()));
        assert!(!claude.contains(&"--tools".to_string()));

        let codex = fix_args("codex", "do the fix");
        assert!(codex.contains(&"do the fix".to_string()));
        assert!(!codex.contains(&"--sandbox".to_string()));
        assert!(!codex.contains(&"--ephemeral".to_string()));

        let cursor = fix_args("cursor", "do the fix");
        assert!(cursor.contains(&"--force".to_string()));
        assert!(cursor.contains(&"do the fix".to_string()));
        assert!(!cursor.contains(&"ask".to_string()));

        assert!(fix_args("hermes", "x").is_empty());
    }

    #[tokio::test]
    async fn fix_spawn_rejects_undetected_agent() {
        let err = run_agent_cli_fix("hermes", "/tmp", "fix it", Some(Path::new("/nonexistent")))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("No CLI detected"), "got: {}", err);
    }
}
