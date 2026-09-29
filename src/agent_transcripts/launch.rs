//! Agent-launched sessions: what a transcript says about how its session
//! started, and which of its tool calls started another agent.
//!
//! An agent that runs `claude -p` or `codex exec` (directly, or through a
//! script it wrote) creates a session with a transcript of its own, usually in
//! a throwaway directory. The Agents view files each session under the
//! workspace its transcript path names, so every such child became a
//! workspace of its own, named after the leaf of a directory that no longer
//! exists. The facts extracted here let
//! [`crate::agent_workspaces::attribute_session_workspaces`] file the child
//! under the workspace of the session that launched it.
//!
//! Two kinds of fact, read from the transcript files on the collection side
//! (the standalone core, or the helper on the sandboxed app path), so the core
//! never needs the transcript text:
//!
//! - [`SessionLaunchContext`], the child side: the working directory the
//!   harness recorded when the session started, the first in-transcript
//!   timestamp, and whether a program rather than a person started it (Claude
//!   Code `entrypoint: sdk-*`, Codex `originator: codex_exec`). The harness
//!   writes these fields; the model's text is never read for them.
//! - [`AgentLaunchCall`], the parent side: a shell tool call that starts an
//!   agent CLI, directly (`claude`, `codex`, `cursor-agent`) or through a
//!   script the same transcript wrote whose body starts one, with the call's
//!   timestamp, the time its result came back when it ran in the foreground,
//!   and the absolute directories the command names.
//!
//! Scanning is streaming and incremental: transcripts are append-only JSONL,
//! so a per-file state remembers the offset of the last complete line and a
//! grown file is read from there, never re-read from the start. A session's
//! Task subagent transcripts (`<session>/subagents/*.jsonl` for Claude Code,
//! `<id>/subagents/*.jsonl` for Cursor) are scanned with it: an orchestrator's
//! subagents are where the launches usually are, and the walker does not
//! collect subagents as sessions of their own.

use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{CollectOptions, CollectedRawSession};

/// Agent CLIs whose invocation starts a session EDAMAME observes. Same set as
/// `agent_cli_insight::AGENT_CLI_BINARIES` (the headless CLIs of the
/// supported agents).
const AGENT_CLI_NAMES: &[&str] = &["claude", "codex", "cursor-agent"];

/// Package names that start an agent CLI through `npx` / `bunx` / `node`.
const AGENT_CLI_PACKAGE_MARKERS: &[&str] = &["@anthropic-ai/claude-code", "@openai/codex"];

/// Launch calls kept per session (the most recent ones win).
const MAX_LAUNCHES_PER_SESSION: usize = 64;
/// Directories kept per launch call.
const MAX_DIRS_PER_LAUNCH: usize = 16;
/// Script basenames remembered per transcript file.
const MAX_AGENT_SCRIPTS_PER_FILE: usize = 256;
/// Foreground launch calls waiting for their result, per file.
const MAX_PENDING_PER_FILE: usize = 256;
/// A line longer than this is consumed without being parsed (tool output
/// dumps; a launch call is a few KB at most).
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
/// Bytes of one transcript file the scanner will read over its lifetime.
const MAX_SCAN_BYTES_PER_FILE: u64 = 256 * 1024 * 1024;
/// Lines read looking for the launch context before giving up.
const CONTEXT_MAX_LINES: u64 = 400;
/// Subagent transcripts older than the collection window by more than this
/// are not scanned (a launch must precede the child it started, and the
/// child is inside the window).
const SUBAGENT_LOOKBACK_MARGIN: Duration = Duration::from_secs(60 * 60);
/// Transcript files whose scan state is kept.
const MAX_CACHED_FILES: usize = 8192;

/// What a session's own transcript says about how it started.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLaunchContext {
    /// Working directory the harness recorded when the session started
    /// (Claude Code's first `cwd`, Codex `session_meta.cwd`). Empty when the
    /// transcript records none (Cursor).
    pub cwd: String,
    /// First in-transcript timestamp. `None` for formats without timestamps.
    pub started_at: Option<DateTime<Utc>>,
    /// A program, not a person, started the session: Claude Code
    /// `entrypoint` `sdk-*` (`claude -p`, the Agent SDK) or Codex
    /// `originator` `codex_exec` / `source` `exec`. Interactive sessions
    /// (terminal, IDE, desktop app) are `false`.
    pub headless: bool,
}

/// A tool call that started an agent CLI.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLaunchCall {
    /// Timestamp of the line that carries the call. `None` for formats
    /// without timestamps (Cursor).
    pub at: Option<DateTime<Utc>>,
    /// Timestamp of the call's result when it ran in the foreground (the
    /// launched agent started before this).
    pub finished_at: Option<DateTime<Utc>>,
    /// The call returned before its work finished (`&`, `run_in_background`,
    /// `Start-Process`, ...): a launched agent may start later than
    /// `finished_at`.
    pub background: bool,
    /// Absolute directories the command names, normalized to `/` separators:
    /// literal paths, `~/...` for `~`, `$HOME` and `%USERPROFILE%`,
    /// `$TMPDIR/...` for `$TMPDIR`, `%TEMP%` and `$env:TEMP`, plus the shell's
    /// working directory at the time of the call.
    pub dirs: Vec<String>,
}

/// Incremental scan state of one transcript file.
#[derive(Debug, Clone, Default)]
struct FileScan {
    mtime_ns: u128,
    size: u64,
    /// End of the last complete line consumed.
    offset: u64,
    lines_seen: u64,
    context: SessionLaunchContext,
    context_settled: bool,
    entrypoint_seen: bool,
    launches: Vec<(u64, AgentLaunchCall)>,
    next_seq: u64,
    /// Foreground launch calls waiting for their result: tool id -> seq.
    pending: HashMap<String, u64>,
    /// Lower-cased basenames of scripts this transcript wrote whose body
    /// starts an agent CLI.
    agent_scripts: BTreeSet<String>,
    /// Hash of the first [`HEAD_FINGERPRINT_BYTES`] bytes: a file whose head
    /// changed was rewritten, not appended to, and is scanned again.
    head_fingerprint: u64,
}

/// Bytes hashed to tell an appended file from a rewritten one.
const HEAD_FINGERPRINT_BYTES: usize = 256;

static FILE_SCANS: Lazy<undeadlock::CustomDashMap<String, FileScan>> =
    Lazy::new(|| undeadlock::CustomDashMap::new("agent_launch_file_scans"));

/// Attach [`SessionLaunchContext`] and [`AgentLaunchCall`]s to every collected
/// session whose transcript is a JSONL file (its own, or the `.jsonl` twin of
/// a Cursor `.txt` export), scanning its subagent transcripts too.
pub(crate) fn attach_launch_facts(sessions: &mut [CollectedRawSession], options: &CollectOptions) {
    let horizon = SystemTime::now()
        .checked_sub(
            Duration::from_secs(options.active_window_minutes.saturating_mul(60))
                + SUBAGENT_LOOKBACK_MARGIN,
        )
        .unwrap_or(UNIX_EPOCH);
    for session in sessions.iter_mut() {
        let Some(main) = jsonl_source(&session.source_path) else {
            continue;
        };
        let Some(main_scan) = scan_file(&main) else {
            continue;
        };
        let mut launches: Vec<AgentLaunchCall> = main_scan
            .launches
            .iter()
            .map(|(_, call)| call.clone())
            .collect();
        for sub in subagent_transcripts(&main, horizon) {
            if let Some(sub_scan) = scan_file(&sub) {
                launches.extend(sub_scan.launches.iter().map(|(_, call)| call.clone()));
            }
        }
        // Most recent last; a session with more launches than the cap keeps
        // the latest ones. A call read from two transcripts (a subagent
        // replays its parent's context) is one call.
        launches.sort_by(|a, b| {
            (a.at, a.finished_at, a.background, &a.dirs).cmp(&(
                b.at,
                b.finished_at,
                b.background,
                &b.dirs,
            ))
        });
        launches.dedup();
        if launches.len() > MAX_LAUNCHES_PER_SESSION {
            let drop = launches.len() - MAX_LAUNCHES_PER_SESSION;
            launches.drain(..drop);
        }
        session.launch_context = main_scan.context.clone();
        session.agent_launches = launches;
    }
}

/// The JSONL file carrying a session's structured lines: the source itself,
/// or the `.jsonl` twin of a `.txt` export.
fn jsonl_source(source_path: &str) -> Option<PathBuf> {
    if source_path.trim().is_empty() {
        return None;
    }
    let path = PathBuf::from(source_path);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("jsonl") => Some(path),
        Some("txt") => {
            let twin = path.with_extension("jsonl");
            twin.is_file().then_some(twin)
        }
        _ => None,
    }
}

/// Subagent transcripts of a session file modified after `horizon`: Claude
/// Code keeps them in `<dir>/<stem>/subagents/`, Cursor in
/// `<dir>/subagents/` when the transcript sits in a directory named after it.
fn subagent_transcripts(main: &Path, horizon: SystemTime) -> Vec<PathBuf> {
    let (Some(dir), Some(stem)) = (main.parent(), main.file_stem().and_then(|s| s.to_str())) else {
        return Vec::new();
    };
    let mut roots = vec![dir.join(stem).join("subagents")];
    if dir.file_name().and_then(|n| n.to_str()) == Some(stem) {
        roots.push(dir.join("subagents"));
    }
    let mut out = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            if meta.modified().map(|m| m >= horizon).unwrap_or(false) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn mtime_ns(meta: &std::fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Current scan of `path`, read incrementally from the cached state.
fn scan_file(path: &Path) -> Option<FileScan> {
    let key = path.to_string_lossy().to_string();
    let meta = std::fs::metadata(path).ok()?;
    let size = meta.len();
    let mtime = mtime_ns(&meta);
    let cached = FILE_SCANS.get(&key).map(|entry| (*entry).clone());
    let head = head_fingerprint(path);
    let mut scan = match cached {
        Some(scan) if scan.size == size && scan.mtime_ns == mtime => return Some(scan),
        // Appended to: continue from the last complete line.
        Some(scan) if size >= scan.size && head == Some(scan.head_fingerprint) => scan,
        // Truncated or rewritten: start over.
        _ => FileScan::default(),
    };
    if scan_increment(path, &mut scan, size).is_err() {
        return None;
    }
    scan.size = size;
    scan.mtime_ns = mtime;
    scan.head_fingerprint = head.unwrap_or(0);
    if FILE_SCANS.len() >= MAX_CACHED_FILES {
        evict_oldest();
    }
    FILE_SCANS.insert(key, scan.clone());
    Some(scan)
}

fn head_fingerprint(path: &Path) -> Option<u64> {
    use std::hash::{Hash, Hasher};
    let mut file = std::fs::File::open(path).ok()?;
    let mut head = vec![0u8; HEAD_FINGERPRINT_BYTES];
    let mut filled = 0usize;
    while filled < head.len() {
        match file.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    head.truncate(filled);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    head.hash(&mut hasher);
    Some(hasher.finish())
}

/// Drop the quarter of the cache whose files are oldest.
fn evict_oldest() {
    let mut entries: Vec<(u128, String)> = FILE_SCANS
        .iter()
        .map(|entry| (entry.value().mtime_ns, entry.key().clone()))
        .collect();
    entries.sort();
    for (_, key) in entries.into_iter().take(MAX_CACHED_FILES / 4) {
        FILE_SCANS.remove(&key);
    }
}

fn scan_increment(path: &Path, scan: &mut FileScan, size: u64) -> std::io::Result<()> {
    if scan.offset >= size || scan.offset >= MAX_SCAN_BYTES_PER_FILE {
        return Ok(());
    }
    let budget = size.min(MAX_SCAN_BYTES_PER_FILE) - scan.offset;
    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(scan.offset))?;
    let mut reader = BufReader::new(file.take(budget));
    let mut line = Vec::new();
    loop {
        line.clear();
        let (consumed, complete, oversized) = read_line_capped(&mut reader, &mut line)?;
        if consumed == 0 || !complete {
            // End of data, or a line still being written: resume here next time.
            break;
        }
        scan.offset += consumed as u64;
        scan.lines_seen += 1;
        if !oversized {
            process_line(&line, scan);
        }
    }
    Ok(())
}

/// Read one `\n`-terminated line, keeping at most [`MAX_LINE_BYTES`] of it.
/// Returns `(bytes consumed, ended with a newline, longer than the cap)`.
fn read_line_capped<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> std::io::Result<(usize, bool, bool)> {
    let mut consumed = 0usize;
    let mut oversized = false;
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok((consumed, false, oversized));
        }
        let (chunk, found) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (&buf[..=i], true),
            None => (buf, false),
        };
        let take = chunk.len();
        if !oversized {
            if out.len() + take > MAX_LINE_BYTES {
                oversized = true;
                out.clear();
            } else {
                out.extend_from_slice(chunk);
            }
        }
        reader.consume(take);
        consumed += take;
        if found {
            return Ok((consumed, true, oversized));
        }
    }
}

/// Markers of a line carrying a tool call (the closing quote keeps
/// `"tool_use_id"` and `"function_call_output"` out).
const CALL_LINE_MARKERS: &[&str] = &[
    "\"tool_use\"",
    "\"function_call\"",
    "\"custom_tool_call\"",
    "\"local_shell_call\"",
];
/// Markers of a line carrying a tool result.
const RESULT_LINE_MARKERS: &[&str] = &[
    "\"tool_result\"",
    "\"function_call_output\"",
    "\"custom_tool_call_output\"",
];

fn process_line(line: &[u8], scan: &mut FileScan) {
    // JSONL is UTF-8; a line that is not cannot be parsed either.
    let Ok(text) = std::str::from_utf8(line) else {
        return;
    };
    let wants_context = !scan.context_settled;
    let has_call = CALL_LINE_MARKERS.iter().any(|m| text.contains(m));
    // Result lines (often large tool output) are parsed only while a
    // foreground launch waits for one.
    let has_result =
        !scan.pending.is_empty() && RESULT_LINE_MARKERS.iter().any(|m| text.contains(m));
    if !wants_context && !has_call && !has_result {
        return;
    }
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let line_ts = line_timestamp(&value);
    if wants_context {
        absorb_context(&value, line_ts, scan);
    }
    for block in structured_blocks(&value) {
        match block_kind(block) {
            BlockKind::Call => absorb_tool_call(block, &value, line_ts, scan),
            BlockKind::Result => {
                if let Some(id) = result_id(block) {
                    if let Some(seq) = scan.pending.remove(&id) {
                        if let Some((_, call)) = scan.launches.iter_mut().find(|(s, _)| *s == seq) {
                            call.finished_at = line_ts.or(call.at);
                        }
                    }
                }
            }
            BlockKind::Other => {}
        }
    }
}

fn line_timestamp(value: &Value) -> Option<DateTime<Utc>> {
    [
        value.get("timestamp"),
        value.get("payload").and_then(|p| p.get("timestamp")),
        value.get("ts"),
    ]
    .into_iter()
    .flatten()
    .find_map(ts_from_value)
}

fn ts_from_value(value: &Value) -> Option<DateTime<Utc>> {
    let epoch = |n: i64| {
        // Seconds or milliseconds since the epoch.
        if n > 100_000_000_000 {
            DateTime::<Utc>::from_timestamp_millis(n)
        } else {
            DateTime::<Utc>::from_timestamp(n, 0)
        }
    };
    match value {
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                return Some(dt.with_timezone(&Utc));
            }
            s.parse::<i64>().ok().and_then(epoch)
        }
        Value::Number(n) => n.as_i64().and_then(epoch),
        _ => None,
    }
}

fn absorb_context(value: &Value, line_ts: Option<DateTime<Utc>>, scan: &mut FileScan) {
    if scan.context.started_at.is_none() {
        scan.context.started_at = line_ts;
    }
    // Claude Code (and Claude Desktop's local agent mode) stamp every line.
    if scan.context.cwd.is_empty() {
        if let Some(cwd) = value.get("cwd").and_then(|v| v.as_str()) {
            if !cwd.trim().is_empty() {
                scan.context.cwd = cwd.trim().to_string();
            }
        }
    }
    if !scan.entrypoint_seen {
        if let Some(entrypoint) = value.get("entrypoint").and_then(|v| v.as_str()) {
            scan.entrypoint_seen = true;
            scan.context.headless = entrypoint.trim().to_ascii_lowercase().starts_with("sdk");
        }
    }
    // Codex: the first line of a rollout.
    if value.get("type").and_then(|v| v.as_str()) == Some("session_meta") {
        if let Some(meta) = value.get("payload") {
            if let Some(cwd) = meta.get("cwd").and_then(|v| v.as_str()) {
                if !cwd.trim().is_empty() {
                    scan.context.cwd = cwd.trim().to_string();
                }
            }
            let originator = meta
                .get("originator")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let source = meta.get("source").and_then(|v| v.as_str()).unwrap_or("");
            scan.context.headless = originator == "codex_exec" || source == "exec";
            if let Some(ts) = meta.get("timestamp").and_then(ts_from_value) {
                scan.context.started_at = Some(ts);
            }
            scan.entrypoint_seen = true;
        }
    }
    if (!scan.context.cwd.is_empty() && scan.entrypoint_seen)
        || scan.lines_seen >= CONTEXT_MAX_LINES
    {
        scan.context_settled = true;
    }
}

enum BlockKind {
    Call,
    Result,
    Other,
}

/// The structured blocks of a line: Anthropic `message.content[]` (Claude
/// Code, Cursor), a Codex `payload`, or the line itself (older rollouts).
fn structured_blocks(value: &Value) -> Vec<&Value> {
    if let Some(items) = value
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
        .or_else(|| value.get("content").and_then(|c| c.as_array()))
    {
        return items.iter().collect();
    }
    if let Some(payload) = value.get("payload") {
        return vec![payload];
    }
    vec![value]
}

fn block_kind(block: &Value) -> BlockKind {
    match block.get("type").and_then(|v| v.as_str()).unwrap_or("") {
        "tool_use" | "function_call" | "custom_tool_call" | "local_shell_call" => BlockKind::Call,
        "tool_result" | "function_call_output" | "custom_tool_call_output" => BlockKind::Result,
        _ => BlockKind::Other,
    }
}

fn block_id(block: &Value) -> Option<String> {
    ["id", "call_id"]
        .iter()
        .find_map(|k| block.get(*k).and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn result_id(block: &Value) -> Option<String> {
    ["tool_use_id", "call_id"]
        .iter()
        .find_map(|k| block.get(*k).and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The call's arguments as an object: Anthropic `input`, Codex `arguments`
/// (a JSON string) or `action` (`local_shell_call`).
fn call_arguments(block: &Value) -> Option<Value> {
    if let Some(input) = block.get("input") {
        if input.is_object() {
            return Some(input.clone());
        }
    }
    if let Some(arguments) = block.get("arguments") {
        match arguments {
            Value::String(s) => {
                return serde_json::from_str::<Value>(s)
                    .ok()
                    .filter(|v| v.is_object())
            }
            Value::Object(_) => return Some(arguments.clone()),
            _ => {}
        }
    }
    block.get("action").filter(|v| v.is_object()).cloned()
}

fn str_field<'a>(object: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|k| object.get(*k).and_then(|v| v.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn absorb_tool_call(
    block: &Value,
    line: &Value,
    line_ts: Option<DateTime<Utc>>,
    scan: &mut FileScan,
) {
    // A patch (Codex `apply_patch`, Cursor `ApplyPatch`) arrives as a string.
    if let Some(patch) = block.get("input").and_then(|v| v.as_str()) {
        remember_patched_scripts(patch, scan);
        return;
    }
    let Some(args) = call_arguments(block) else {
        return;
    };
    // A file write: remember the script when its body starts an agent CLI.
    if let Some(path) = str_field(&args, &["file_path", "path", "target_file", "filePath"]) {
        let mut body = String::new();
        for key in ["content", "contents", "new_string", "code_edit", "text"] {
            if let Some(text) = args.get(key).and_then(|v| v.as_str()) {
                body.push_str(text);
                body.push('\n');
            }
        }
        if let Some(edits) = args.get("edits").and_then(|v| v.as_array()) {
            for edit in edits {
                if let Some(text) = edit.get("new_string").and_then(|v| v.as_str()) {
                    body.push_str(text);
                    body.push('\n');
                }
            }
        }
        if !body.is_empty() && script_starts_agent(&body) {
            remember_script(path, scan);
        }
    }
    let Some(command) = command_text(&args) else {
        return;
    };
    let shell_cwd = str_field(&args, &["workdir", "working_directory", "cwd", "directory"])
        .or_else(|| str_field(line, &["cwd"]))
        .unwrap_or("")
        .to_string();
    let lexed = lex_shell(&command);
    let mut direct = lexed.commands.iter().any(|words| starts_agent_cli(words));
    // A heredoc is written to a file (`cat > run.sh <<EOF`) or fed to the
    // program it follows (`bash <<EOF`, `python3 - <<EOF`). A body that starts
    // an agent CLI (as a shell command, or as a name a program spawns) makes
    // the file an agent script, and feeding it to a shell or an interpreter is
    // a launch.
    let shell_body = lexed.heredocs.iter().any(|body| {
        lex_shell(body)
            .commands
            .iter()
            .any(|words| starts_agent_cli(words))
    });
    let literal_body = lexed
        .heredocs
        .iter()
        .any(|body| names_agent_cli_literal(body));
    if shell_body || literal_body {
        let targets: Vec<String> = lexed.redirect_targets.clone();
        for target in targets {
            remember_script(&target, scan);
        }
        direct |= lexed.commands.iter().any(|words| {
            command_word_index(words)
                .map(|i| {
                    let name = exe_basename(&words[i]);
                    (is_shell(&name) && shell_body) || (is_interpreter(&name) && literal_body)
                })
                .unwrap_or(false)
        });
    }
    let via_script = lexed
        .commands
        .iter()
        .any(|words| runs_script(words, &scan.agent_scripts));
    if !direct && !via_script {
        return;
    }
    let background = lexed.background
        || lexed.commands.iter().any(|words| detaches(words))
        || ["run_in_background", "is_background", "background"]
            .iter()
            .any(|k| args.get(*k).and_then(|v| v.as_bool()) == Some(true))
        || args.get("block_until_ms").and_then(|v| v.as_u64()) == Some(0);
    let call = AgentLaunchCall {
        at: line_ts,
        finished_at: None,
        background,
        dirs: named_directories(&lexed, &shell_cwd),
    };
    let seq = scan.next_seq;
    scan.next_seq += 1;
    if !background {
        if let Some(id) = block_id(block) {
            if scan.pending.len() < MAX_PENDING_PER_FILE {
                scan.pending.insert(id, seq);
            }
        }
    }
    scan.launches.push((seq, call));
    if scan.launches.len() > MAX_LAUNCHES_PER_SESSION {
        let (dropped, _) = scan.launches.remove(0);
        scan.pending.retain(|_, s| *s != dropped);
    }
}

/// Extensions of files a command can run as a program.
const SCRIPT_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "fish", "ps1", "psm1", "cmd", "bat", "py", "js", "mjs", "cjs", "ts", "rb",
    "pl",
];

fn remember_script(path: &str, scan: &mut FileScan) {
    let base = file_basename_lower(path);
    // A document that mentions an agent (`README.md`) is not something a
    // command runs; a script has a script extension or none.
    let runnable = match base.rsplit_once('.') {
        Some((stem, ext)) => !stem.is_empty() && SCRIPT_EXTENSIONS.contains(&ext),
        None => true,
    };
    if runnable && !base.is_empty() && scan.agent_scripts.len() < MAX_AGENT_SCRIPTS_PER_FILE {
        scan.agent_scripts.insert(base);
    }
}

/// Files a patch adds or updates whose added lines start an agent CLI.
fn remember_patched_scripts(patch: &str, scan: &mut FileScan) {
    let mut current: Option<String> = None;
    let mut added = String::new();
    let flush = |path: Option<String>, body: &mut String, scan: &mut FileScan| {
        if let Some(path) = path {
            if script_starts_agent(body) {
                remember_script(&path, scan);
            }
        }
        body.clear();
    };
    for line in patch.lines() {
        let header = line
            .strip_prefix("*** Add File:")
            .or_else(|| line.strip_prefix("*** Update File:"));
        if let Some(path) = header {
            flush(current.take(), &mut added, scan);
            current = Some(path.trim().to_string());
        } else if let Some(text) = line.strip_prefix('+') {
            added.push_str(text);
            added.push('\n');
        }
    }
    flush(current, &mut added, scan);
}

/// The shell command of a call: `command` / `cmd` as a string, or as an argv
/// array (`["bash", "-lc", "<script>"]` yields the script).
fn command_text(args: &Value) -> Option<String> {
    for key in ["command", "cmd"] {
        match args.get(key) {
            Some(Value::String(s)) if !s.trim().is_empty() => return Some(s.clone()),
            Some(Value::Array(items)) => {
                let argv: Vec<&str> = items.iter().filter_map(|v| v.as_str()).collect();
                if argv.is_empty() {
                    continue;
                }
                if argv.len() >= 3
                    && is_shell(&exe_basename(argv[0]))
                    && argv[1].starts_with('-')
                    && argv[1].to_ascii_lowercase().contains('c')
                {
                    return Some(argv[2..].join(" "));
                }
                return Some(
                    argv.iter()
                        .map(|a| {
                            if a.contains(char::is_whitespace) {
                                format!("'{}'", a.replace('\'', ""))
                            } else {
                                (*a).to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Shell lexing
// ---------------------------------------------------------------------------

/// A shell command split into simple commands.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Lexed {
    /// Words of each simple command, quotes removed, redirections dropped.
    commands: Vec<Vec<String>>,
    /// A lone `&` ended a command (sent it to the background).
    background: bool,
    /// Files written by `>` / `>>` / `&>` redirections.
    redirect_targets: Vec<String>,
    /// Heredoc bodies (`<<EOF ... EOF`), kept out of `commands`: they are
    /// data (a script being written, a program fed to an interpreter), not
    /// commands of this shell.
    heredocs: Vec<String>,
}

/// Split a shell command (POSIX shells; PowerShell's `&` call operator and
/// unquoted Windows paths tolerated) into simple commands. Quote-aware
/// (single, double, backslash escapes, `${...}`); newline, `;`, `&&`, `||`,
/// `|`, `&`, `(`, `)`, `{`, `}`, backticks and `$(` end a simple command.
/// Heredoc bodies are set aside in [`Lexed::heredocs`].
fn lex_shell(input: &str) -> Lexed {
    struct Lexer {
        out: Lexed,
        words: Vec<String>,
        cur: String,
        in_word: bool,
        /// 0: none, 1: the next word is a redirect target, 2: a heredoc
        /// delimiter.
        pending_redirect: u8,
        /// Nothing but separators since the last statement boundary: an `&`
        /// here is PowerShell's call operator, not a background job.
        statement_start: bool,
        /// `Some(strip_tabs)` while the next word is a heredoc delimiter.
        heredoc_word: Option<bool>,
        /// Heredocs opened on the current line: (delimiter, strip tabs).
        heredocs_open: Vec<(String, bool)>,
    }
    impl Lexer {
        fn end_word(&mut self) {
            if !self.in_word {
                return;
            }
            let word = std::mem::take(&mut self.cur);
            match self.pending_redirect {
                1 => self.out.redirect_targets.push(word),
                2 => {
                    if let Some(strip_tabs) = self.heredoc_word.take() {
                        self.heredocs_open.push((word, strip_tabs));
                    }
                }
                _ => self.words.push(word),
            }
            self.pending_redirect = 0;
            self.in_word = false;
            self.statement_start = false;
        }
        fn end_command(&mut self, statement_start: bool) {
            self.end_word();
            if !self.words.is_empty() {
                let words = std::mem::take(&mut self.words);
                self.out.commands.push(words);
            }
            self.statement_start = statement_start;
        }
    }

    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut lx = Lexer {
        out: Lexed::default(),
        words: Vec::new(),
        cur: String::new(),
        in_word: false,
        pending_redirect: 0,
        statement_start: true,
        heredoc_word: None,
        heredocs_open: Vec::new(),
    };
    let mut i = 0usize;
    while i < len {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            '\'' => {
                lx.in_word = true;
                i += 1;
                while i < len && chars[i] != '\'' {
                    lx.cur.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                lx.in_word = true;
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == '\\'
                        && i + 1 < len
                        && matches!(chars[i + 1], '"' | '\\' | '$' | '`')
                    {
                        lx.cur.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    lx.cur.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '\\' => match next {
                // Line continuation.
                Some('\n') => i += 2,
                // An escaped shell character.
                Some(n) if n.is_whitespace() || "'\"$\\;&|()<>`{}*?#~".contains(n) => {
                    lx.cur.push(n);
                    lx.in_word = true;
                    i += 2;
                }
                // A path separator (`C:\Users\me`): keep it.
                _ => {
                    lx.cur.push('\\');
                    lx.in_word = true;
                    i += 1;
                }
            },
            '$' if next == Some('{') => {
                lx.in_word = true;
                while i < len {
                    lx.cur.push(chars[i]);
                    i += 1;
                    if chars[i - 1] == '}' {
                        break;
                    }
                }
            }
            '$' if next == Some('(') => {
                lx.end_command(true);
                i += 2;
            }
            ' ' | '\t' | '\r' => {
                lx.end_word();
                i += 1;
            }
            '\n' => {
                lx.end_command(true);
                i += 1;
                // The bodies of the heredocs this line opened follow it.
                for (delimiter, strip_tabs) in std::mem::take(&mut lx.heredocs_open) {
                    let mut body = String::new();
                    while i < len {
                        let end = chars[i..]
                            .iter()
                            .position(|c| *c == '\n')
                            .map(|p| i + p)
                            .unwrap_or(len);
                        let line: String = chars[i..end].iter().collect();
                        i = (end + 1).min(len);
                        let candidate = if strip_tabs {
                            line.trim_start_matches('\t')
                        } else {
                            line.as_str()
                        };
                        if candidate.trim_end_matches('\r') == delimiter {
                            break;
                        }
                        body.push_str(&line);
                        body.push('\n');
                    }
                    lx.out.heredocs.push(body);
                }
            }
            ';' | '(' | '{' | '`' => {
                lx.end_command(true);
                i += 1;
            }
            ')' | '}' => {
                // `( ... ) &` backgrounds the group.
                lx.end_command(false);
                i += 1;
            }
            '|' => {
                lx.end_command(true);
                i += if matches!(next, Some('|') | Some('&')) {
                    2
                } else {
                    1
                };
            }
            '&' => {
                if next == Some('&') {
                    lx.end_command(true);
                    i += 2;
                } else if next == Some('>') {
                    // `&>` / `&>>`: stdout and stderr to a file.
                    lx.end_word();
                    i += 2;
                    if chars.get(i) == Some(&'>') {
                        i += 1;
                    }
                    lx.pending_redirect = 1;
                    lx.statement_start = false;
                } else {
                    lx.end_word();
                    if !lx.statement_start {
                        lx.out.background = true;
                    }
                    lx.end_command(true);
                    i += 1;
                }
            }
            '>' | '<' => {
                // A leading fd number (`2>`) belongs to the redirection.
                if lx.in_word && !lx.cur.is_empty() && lx.cur.chars().all(|d| d.is_ascii_digit()) {
                    lx.cur.clear();
                    lx.in_word = false;
                } else {
                    lx.end_word();
                }
                let mut j = i + 1;
                while j < len && matches!(chars[j], '>' | '<' | '&' | '|') {
                    j += 1;
                }
                let operator: String = chars[i..j].iter().collect();
                let duplicates_fd = operator.contains('&');
                i = j;
                if duplicates_fd {
                    // `2>&1`, `<&0`, `>&-`: the target is a descriptor.
                    while i < len && (chars[i].is_ascii_digit() || chars[i] == '-') {
                        i += 1;
                    }
                } else if operator == "<<" {
                    // A heredoc: the next word is its delimiter (`<<-` strips
                    // leading tabs from the body lines).
                    let strip_tabs = chars.get(i) == Some(&'-');
                    if strip_tabs {
                        i += 1;
                    }
                    lx.pending_redirect = 2;
                    lx.heredoc_word = Some(strip_tabs);
                } else if operator == "<<<" {
                    // A here-string: the next word is data.
                    lx.pending_redirect = 2;
                } else {
                    lx.pending_redirect = 1;
                }
                lx.statement_start = false;
            }
            _ => {
                lx.cur.push(c);
                lx.in_word = true;
                i += 1;
            }
        }
    }
    lx.end_command(true);
    lx.out
}

/// Basename of a word, lower-cased, keeping the extension (`./agents.sh` ->
/// `agents.sh`).
fn file_basename_lower(word: &str) -> String {
    word.trim_matches(|c| c == '"' || c == '\'')
        .rsplit(['/', '\\'])
        .find(|p| !p.is_empty())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Basename of an executable word, lower-cased, without a Windows launcher
/// extension (`C:\...\claude.exe` -> `claude`).
fn exe_basename(word: &str) -> String {
    let base = file_basename_lower(word);
    for ext in [".exe", ".cmd", ".bat", ".ps1"] {
        if let Some(stem) = base.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    base
}

fn is_shell(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish" | "pwsh" | "powershell"
    )
}

fn is_interpreter(name: &str) -> bool {
    name.starts_with("python") || matches!(name, "node" | "bun" | "deno" | "ruby" | "perl")
}

fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Options of a wrapper command that take a value as the next word.
fn option_takes_value(wrapper: &str, option: &str) -> bool {
    match wrapper {
        "env" => matches!(
            option,
            "-u" | "--unset" | "-C" | "--chdir" | "-S" | "--split-string"
        ),
        "sudo" | "doas" => matches!(
            option,
            "-u" | "-g" | "-C" | "-D" | "-h" | "-p" | "-r" | "-t" | "-U"
        ),
        "nice" => matches!(option, "-n" | "--adjustment"),
        "ionice" => matches!(option, "-c" | "-n" | "-p"),
        "timeout" | "gtimeout" => matches!(option, "-s" | "--signal" | "-k" | "--kill-after"),
        "xargs" => matches!(
            option,
            "-n" | "-I" | "-P" | "-L" | "-s" | "-d" | "-E" | "-a"
        ),
        "stdbuf" => matches!(option, "-i" | "-o" | "-e"),
        _ => false,
    }
}

/// Index of the word a simple command runs, skipping variable assignments
/// and wrapper commands (`env`, `nohup`, `timeout 900`, `sudo -u x`, ...).
fn command_word_index(words: &[String]) -> Option<usize> {
    let mut i = 0usize;
    while i < words.len() {
        let word = &words[i];
        if is_assignment(word) {
            i += 1;
            continue;
        }
        let name = exe_basename(word);
        match name.as_str() {
            "env" | "nohup" | "exec" | "command" | "builtin" | "time" | "caffeinate" | "setsid"
            | "stdbuf" | "unbuffer" | "sudo" | "doas" | "nice" | "ionice" | "xargs" | "then"
            | "do" | "else" | "elif" | "if" | "while" | "until" | "!" | "start-process"
            | "start" | "call" | "timeout" | "gtimeout" | "cmd" => {
                let wrapper = name.clone();
                i += 1;
                while i < words.len() {
                    let w = &words[i];
                    let is_option = w.starts_with('-')
                        || (wrapper == "cmd" && w.starts_with('/'))
                        || (wrapper == "start" && w.starts_with('/'))
                        || (wrapper == "env" && is_assignment(w));
                    if !is_option {
                        break;
                    }
                    if wrapper == "command" && (w == "-v" || w == "-V") {
                        return None;
                    }
                    if wrapper == "start-process" && w.eq_ignore_ascii_case("-filepath") {
                        return (i + 1 < words.len()).then_some(i + 1);
                    }
                    i += if option_takes_value(&wrapper, w) {
                        2
                    } else {
                        1
                    };
                }
                if matches!(wrapper.as_str(), "timeout" | "gtimeout") && i < words.len() {
                    // The duration.
                    i += 1;
                }
                if wrapper == "start" && i < words.len() && words[i].is_empty() {
                    // `start "" <command>`: the window title.
                    i += 1;
                }
            }
            _ => return Some(i),
        }
    }
    None
}

/// The simple command starts an agent CLI.
fn starts_agent_cli(words: &[String]) -> bool {
    let Some(i) = command_word_index(words) else {
        return false;
    };
    let name = exe_basename(&words[i]);
    if AGENT_CLI_NAMES.contains(&name.as_str()) {
        return true;
    }
    let rest = &words[i + 1..];
    let first_arg = rest.iter().find(|w| !w.starts_with('-'));
    match name.as_str() {
        // The Cursor CLI's agent subcommand.
        "cursor" => first_arg.map(|w| w == "agent").unwrap_or(false),
        "npx" | "bunx" | "pnpx" | "node" | "bun" | "deno" => first_arg
            .map(|w| {
                let lower = w.to_ascii_lowercase();
                AGENT_CLI_NAMES.contains(&exe_basename(w).as_str())
                    || AGENT_CLI_PACKAGE_MARKERS.iter().any(|m| lower.contains(m))
                    || lower.contains("/claude-code/")
            })
            .unwrap_or(false),
        "pnpm" | "yarn" => {
            rest.first()
                .map(|w| w == "dlx" || w == "exec")
                .unwrap_or(false)
                && rest.iter().skip(1).any(|w| {
                    AGENT_CLI_NAMES.contains(&exe_basename(w).as_str())
                        || AGENT_CLI_PACKAGE_MARKERS.iter().any(|m| w.contains(m))
                })
        }
        shell if is_shell(shell) => {
            // `bash -lc '<script>'`, `pwsh -Command '<script>'`.
            let powershell = matches!(shell, "pwsh" | "powershell");
            let mut k = 0;
            while k < rest.len() {
                let w = &rest[k];
                if !w.starts_with('-') {
                    break;
                }
                let lower = w.to_ascii_lowercase();
                let takes_script = if powershell {
                    lower == "-c" || lower == "-command"
                } else {
                    !lower.starts_with("--") && lower[1..].contains('c')
                };
                if takes_script {
                    return rest
                        .get(k + 1)
                        .map(|script| {
                            lex_shell(script)
                                .commands
                                .iter()
                                .any(|c| starts_agent_cli(c))
                        })
                        .unwrap_or(false);
                }
                k += 1;
            }
            false
        }
        _ => false,
    }
}

/// The simple command detaches what it runs from the calling shell.
fn detaches(words: &[String]) -> bool {
    words.first().map(|w| {
        matches!(
            exe_basename(w).as_str(),
            "start-process" | "start" | "setsid" | "daemonize" | "disown"
        )
    }) == Some(true)
}

/// A script body (shell, or a scripting language that spawns the CLI by
/// name) starts an agent CLI.
fn script_starts_agent(body: &str) -> bool {
    lex_shell(body)
        .commands
        .iter()
        .any(|words| starts_agent_cli(words))
        || names_agent_cli_literal(body)
}

/// A program spawns an agent CLI by name: `subprocess.run(["claude", "-p",
/// ...])`, `spawn('codex', [...])`.
fn names_agent_cli_literal(body: &str) -> bool {
    AGENT_CLI_NAMES
        .iter()
        .any(|name| body.contains(&format!("\"{name}\"")) || body.contains(&format!("'{name}'")))
}

/// The simple command runs one of `scripts`: as its program (`./agents.sh`,
/// `timeout 900 $FS/run.sh`) or as the script of a shell or interpreter
/// (`bash agents.sh`, `python3 spawn.py`, `. ./env.sh`). Naming a script
/// (`chmod +x run.sh`, `cat run.sh`) is not running it.
fn runs_script(words: &[String], scripts: &BTreeSet<String>) -> bool {
    if scripts.is_empty() {
        return false;
    }
    let Some(i) = command_word_index(words) else {
        return false;
    };
    if scripts.contains(&file_basename_lower(&words[i])) {
        return true;
    }
    let name = exe_basename(&words[i]);
    if !(is_shell(&name) || is_interpreter(&name) || name == "source" || name == ".") {
        return false;
    }
    words[i + 1..]
        .iter()
        .find(|w| !w.starts_with('-'))
        .map(|w| scripts.contains(&file_basename_lower(w)))
        .unwrap_or(false)
}

/// Normalize one word into an absolute directory reference, or `None` when
/// it is relative or unresolvable (`$BASE/x`).
fn normalize_named_path(word: &str) -> Option<String> {
    let w = word
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_end_matches([';', ',', ')', ':']);
    if w.is_empty() {
        return None;
    }
    let lower = w.to_ascii_lowercase();
    const HOME_PREFIXES: &[&str] = &[
        "${home}",
        "$home",
        "%userprofile%",
        "${env:userprofile}",
        "$env:userprofile",
    ];
    const TEMP_PREFIXES: &[&str] = &[
        "${tmpdir}",
        "$tmpdir",
        "%temp%",
        "%tmp%",
        "${env:temp}",
        "$env:temp",
        "${env:tmp}",
        "$env:tmp",
    ];
    let (prefix, rest): (&str, &str) = if w == "~" || w.starts_with("~/") || w.starts_with("~\\") {
        ("~", &w[1..])
    } else if let Some(p) = HOME_PREFIXES.iter().find(|p| lower.starts_with(**p)) {
        let rest = &w[p.len()..];
        // `$HOMEBREW_PREFIX` is not `$HOME`.
        if !(rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\')) {
            return None;
        }
        ("~", rest)
    } else if let Some(p) = TEMP_PREFIXES.iter().find(|p| lower.starts_with(**p)) {
        let rest = &w[p.len()..];
        if rest
            .chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric() || c == '_')
            .unwrap_or(false)
            && p.starts_with('$')
            && !p.ends_with('}')
        {
            // `$TMPDIRX` is another variable; `${TMPDIR}x` is `$TMPDIR` + `x`
            // (macOS sets it with a trailing slash).
            return None;
        }
        ("$TMPDIR", rest)
    } else if w.starts_with('/') {
        ("", w)
    } else {
        let bytes = w.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
        {
            ("", w)
        } else {
            return None;
        }
    };
    // Text that happens to start with a slash (a comment, a regex) is not a
    // path.
    if w.contains(['\n', '\r', '\t']) {
        return None;
    }
    let mut comps: Vec<&str> = Vec::new();
    for comp in rest.split(['/', '\\']) {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp.starts_with(char::is_whitespace) || comp.ends_with(char::is_whitespace) {
            return None;
        }
        if comp.contains(['$', '*', '?', '`', '{', '}', '%']) {
            break;
        }
        comps.push(comp);
    }
    let joined = comps.join("/");
    Some(match prefix {
        "" if w.starts_with('/') => format!("/{joined}"),
        "" => {
            // `C:\x` / `C:/x`: the drive is the first component.
            joined
        }
        p if joined.is_empty() => p.to_string(),
        p => format!("{p}/{joined}"),
    })
}

/// Absolute directories a launch command names, the shell's working
/// directory first, then `cd` targets (relative ones resolved against it),
/// then every other absolute path word.
fn named_directories(lexed: &Lexed, shell_cwd: &str) -> Vec<String> {
    let mut dirs: Vec<String> = Vec::new();
    let push = |dir: String, dirs: &mut Vec<String>| {
        if !dir.is_empty() && !dirs.contains(&dir) && dirs.len() < MAX_DIRS_PER_LAUNCH {
            dirs.push(dir);
        }
    };
    let cwd = normalize_named_path(shell_cwd);
    if let Some(cwd) = cwd.clone() {
        push(cwd, &mut dirs);
    }
    for words in &lexed.commands {
        let Some(i) = command_word_index(words) else {
            continue;
        };
        let name = exe_basename(&words[i]);
        if matches!(
            name.as_str(),
            "cd" | "pushd" | "set-location" | "sl" | "chdir"
        ) {
            if let Some(target) = words.get(i + 1).filter(|w| !w.starts_with('-')) {
                match normalize_named_path(target) {
                    Some(abs) => push(abs, &mut dirs),
                    None => {
                        if let (Some(base), false) = (cwd.as_deref(), target.contains('$')) {
                            let joined = format!("{}/{}", base.trim_end_matches('/'), target);
                            if let Some(abs) = normalize_named_path(&joined) {
                                push(abs, &mut dirs);
                            }
                        }
                    }
                }
            }
        }
    }
    for word in lexed.commands.iter().flatten() {
        let value = match word.split_once('=') {
            Some((name, value)) if name.starts_with('-') || is_assignment(word) => value,
            _ => word.as_str(),
        };
        if let Some(abs) = normalize_named_path(value) {
            push(abs, &mut dirs);
        }
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(cmd: &str) -> Vec<Vec<String>> {
        lex_shell(cmd).commands
    }

    #[test]
    fn lexer_splits_operators_and_keeps_quoted_words() {
        let lexed = lex_shell(r#"cd /tmp/x && ./run.sh "a b" 'c;d' | tee log.txt; echo $! &"#);
        assert_eq!(
            lexed.commands,
            vec![
                vec!["cd".to_string(), "/tmp/x".to_string()],
                vec!["./run.sh".to_string(), "a b".to_string(), "c;d".to_string()],
                vec!["tee".to_string(), "log.txt".to_string()],
                vec!["echo".to_string(), "$!".to_string()],
            ]
        );
        assert!(lexed.background);
    }

    #[test]
    fn lexer_tells_background_from_redirections() {
        assert!(!lex_shell("cargo test 2>&1 | tail").background);
        assert!(!lex_shell("cargo test &> out.log").background);
        assert!(!lex_shell("a && b || c").background);
        assert!(lex_shell("( ./agents.sh 1 /tmp/x ) > log 2>&1 &\necho $!").background);
        // PowerShell's call operator is not a background job.
        let lexed = lex_shell(r#"& "C:\Program Files\claude\claude.exe" -p hi"#);
        assert!(!lexed.background);
        assert!(lexed.commands.iter().any(|w| starts_agent_cli(w)));
    }

    #[test]
    fn lexer_keeps_braced_variables_in_the_word() {
        let lexed = lex_shell(r#"./agents.sh 2 "${TMPDIR}edsim-agents""#);
        assert_eq!(
            lexed.commands,
            vec![vec![
                "./agents.sh".to_string(),
                "2".to_string(),
                "${TMPDIR}edsim-agents".to_string()
            ]]
        );
    }

    #[test]
    fn heredoc_bodies_are_data_not_commands() {
        let lexed = lex_shell("python3 - <<'EOF'\nclaude = 1\nprint('/ comment')\nEOF\necho done");
        assert_eq!(
            lexed.commands,
            vec![
                vec!["python3".to_string(), "-".to_string()],
                vec!["echo".to_string(), "done".to_string()],
            ]
        );
        assert_eq!(
            lexed.heredocs,
            vec!["claude = 1\nprint('/ comment')\n".to_string()]
        );
        let tabbed = lex_shell("cat > run.sh <<-EOF\n\tclaude -p x\n\tEOF\nbash run.sh");
        assert_eq!(tabbed.redirect_targets, vec!["run.sh".to_string()]);
        assert_eq!(tabbed.heredocs.len(), 1);
        assert_eq!(
            tabbed.commands.last().unwrap(),
            &vec!["bash".to_string(), "run.sh".to_string()]
        );
    }

    #[test]
    fn heredoc_scripts_are_remembered_and_heredoc_code_is_not_a_launch() {
        let mut scan = FileScan::default();
        feed(
            &mut scan,
            &[
                serde_json::json!({"type":"user","timestamp":"2026-09-28T10:00:00Z","cwd":"/Users/me/p","entrypoint":"cli","message":{"content":"hi"}}),
                // Editing code that mentions the CLI is not a launch.
                serde_json::json!({"type":"assistant","timestamp":"2026-09-28T10:01:00Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"a","name":"Bash","input":{"command":"python3 - <<'EOF'\ns = open('x.rs').read()\nclaude -p would be here\nEOF"}}]}}),
                // Writing a launcher through a heredoc registers it...
                serde_json::json!({"type":"assistant","timestamp":"2026-09-28T10:02:00Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"b","name":"Bash","input":{"command":"cat > /Users/me/p/spawn.sh <<'EOF'\ncd \"$1\" && claude -p \"$2\"\nEOF\nchmod +x /Users/me/p/spawn.sh"}}]}}),
                serde_json::json!({"type":"user","timestamp":"2026-09-28T10:02:01Z","message":{"content":[{"type":"tool_result","tool_use_id":"b","content":""}]}}),
                // ...and running it is a launch.
                serde_json::json!({"type":"assistant","timestamp":"2026-09-28T10:03:00Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"c","name":"Bash","input":{"command":"./spawn.sh /Users/me/work/job1 'go'"}}]}}),
            ],
        );
        assert!(scan.agent_scripts.contains("spawn.sh"));
        let at: Vec<String> = scan
            .launches
            .iter()
            .filter_map(|(_, l)| l.at.map(|t| t.to_rfc3339()))
            .collect();
        // The python edit mentions the CLI only as code, not as a spawned
        // name; writing and chmod-ing the launcher does not run it.
        assert_eq!(at, vec!["2026-09-28T10:03:00+00:00".to_string()]);
        let run = scan
            .launches
            .iter()
            .find(|(_, l)| {
                l.at.map(|t| t.to_rfc3339()) == Some("2026-09-28T10:03:00+00:00".to_string())
            })
            .unwrap();
        assert!(run.1.dirs.contains(&"/Users/me/work/job1".to_string()));
    }

    #[test]
    fn agent_cli_is_recognised_in_command_position_only() {
        let starts = |cmd: &str| words(cmd).iter().any(|w| starts_agent_cli(w));
        assert!(starts("claude -p 'fix the build'"));
        assert!(starts(
            "cd /tmp/x && env -u CLAUDECODE -u CLAUDE_PID claude -p \"$P\""
        ));
        assert!(starts("timeout 900 codex exec -C /tmp/x 'do it'"));
        assert!(starts("nohup cursor-agent -p hi > out.log 2>&1 &"));
        assert!(starts("npx @anthropic-ai/claude-code -p hi"));
        assert!(starts("/Users/me/.local/bin/claude -p hi"));
        assert!(starts(r#"bash -lc "cd /tmp/y && claude -p hi""#));
        assert!(starts(
            r#"Start-Process -FilePath claude -ArgumentList '-p','hi'"#
        ));
        assert!(starts("cursor agent -p hi"));
        assert!(!starts("pgrep -f claude"));
        assert!(!starts("ls ~/.claude/projects"));
        assert!(!starts("echo claude"));
        assert!(!starts("cat claude.md"));
    }

    #[test]
    fn named_paths_expand_home_and_temp_markers() {
        assert_eq!(
            normalize_named_path("/private/tmp/edsim-agents/").as_deref(),
            Some("/private/tmp/edsim-agents")
        );
        assert_eq!(
            normalize_named_path("$HOME/Library/Caches/x").as_deref(),
            Some("~/Library/Caches/x")
        );
        assert_eq!(normalize_named_path("${HOME}").as_deref(), Some("~"));
        assert_eq!(
            normalize_named_path("~/code/x").as_deref(),
            Some("~/code/x")
        );
        assert_eq!(
            normalize_named_path("${TMPDIR}edsim-agents").as_deref(),
            Some("$TMPDIR/edsim-agents")
        );
        assert_eq!(
            normalize_named_path("$TMPDIR/edsim").as_deref(),
            Some("$TMPDIR/edsim")
        );
        assert_eq!(
            normalize_named_path("%TEMP%\\edsim\\a1").as_deref(),
            Some("$TMPDIR/edsim/a1")
        );
        assert_eq!(
            normalize_named_path("$env:TEMP\\edsim").as_deref(),
            Some("$TMPDIR/edsim")
        );
        assert_eq!(
            normalize_named_path("%USERPROFILE%\\src\\app").as_deref(),
            Some("~/src/app")
        );
        assert_eq!(
            normalize_named_path(r"C:\Users\me\AppData\Local\Temp\x").as_deref(),
            Some("C:/Users/me/AppData/Local/Temp/x")
        );
        assert_eq!(
            normalize_named_path("/tmp/run-$ID/x").as_deref(),
            Some("/tmp")
        );
        assert_eq!(normalize_named_path("$HOMEBREW_PREFIX/bin"), None);
        assert_eq!(normalize_named_path("$TMPDIRX/a"), None);
        assert_eq!(normalize_named_path("relative/dir"), None);
        assert_eq!(normalize_named_path("$BASE/edsim"), None);
        assert_eq!(normalize_named_path("/ Catalog labels / naming"), None);
        assert_eq!(normalize_named_path("/a\nb"), None);
        assert_eq!(
            normalize_named_path("/Users/me/Mon Drive (x)/jarvis").as_deref(),
            Some("/Users/me/Mon Drive (x)/jarvis")
        );
    }

    #[test]
    fn named_directories_resolve_relative_cd_against_the_shell_cwd() {
        let lexed = lex_shell("cd sub && claude -p hi; mkdir -p /private/tmp/a --dir=/opt/data/x");
        let dirs = named_directories(&lexed, "/Users/me/proj");
        assert_eq!(
            dirs,
            vec![
                "/Users/me/proj".to_string(),
                "/Users/me/proj/sub".to_string(),
                "/private/tmp/a".to_string(),
                "/opt/data/x".to_string(),
            ]
        );
    }

    #[test]
    fn running_a_script_is_not_naming_it() {
        let scripts: BTreeSet<String> = ["agents.sh".to_string(), "spawn.py".to_string()].into();
        let runs = |cmd: &str| {
            lex_shell(cmd)
                .commands
                .iter()
                .any(|w| runs_script(w, &scripts))
        };
        assert!(runs("./agents.sh 1 /private/tmp/edsim-agents"));
        assert!(runs(
            "( ./agents.sh 1 /tmp/a; ./agents.sh 2 /tmp/b ) > log 2>&1 &"
        ));
        assert!(runs("timeout 900 $FS/agents.sh 3 /tmp/c"));
        assert!(runs("bash agents.sh 4 /tmp/d"));
        assert!(runs("python3 -u spawn.py"));
        assert!(!runs("chmod +x agents.sh"));
        assert!(!runs("cat agents.sh; grep claude agents.sh"));
        assert!(!runs("sed -i '' 's/a/b/' agents.sh"));
    }

    #[test]
    fn scripts_that_start_agents_are_recognised() {
        assert!(script_starts_agent("#!/bin/bash\ncd \"$D\" || exit 1\nclaude -p \"$P\" --output-format json > out.json 2>&1\n"));
        assert!(script_starts_agent(
            "import subprocess\nsubprocess.run([\"codex\", \"exec\", prompt])\n"
        ));
        assert!(!script_starts_agent(
            "#!/bin/bash\ncargo test\nls ~/.claude\n"
        ));
    }

    #[test]
    fn patches_register_agent_scripts() {
        let mut scan = FileScan::default();
        remember_patched_scripts(
            "*** Begin Patch\n*** Add File: tools/spawn.sh\n+#!/bin/sh\n+codex exec -C \"$1\" \"$2\"\n*** Update File: README.md\n+claude is mentioned here\n*** End Patch\n",
            &mut scan,
        );
        assert!(scan.agent_scripts.contains("spawn.sh"));
        assert!(!scan.agent_scripts.contains("readme.md"));
    }

    fn line(v: serde_json::Value) -> Vec<u8> {
        let mut s = serde_json::to_vec(&v).unwrap();
        s.push(b'\n');
        s
    }

    fn feed(scan: &mut FileScan, lines: &[serde_json::Value]) {
        for l in lines {
            scan.lines_seen += 1;
            process_line(&line(l.clone()), scan);
        }
    }

    #[test]
    fn claude_code_launch_through_a_written_script_is_recorded() {
        let mut scan = FileScan::default();
        feed(
            &mut scan,
            &[
                serde_json::json!({"type":"user","timestamp":"2026-09-28T17:50:00Z","cwd":"/Users/me/code/edamame_core","entrypoint":"claude-vscode","message":{"role":"user","content":"simulate"}}),
                serde_json::json!({"type":"assistant","timestamp":"2026-09-28T17:56:24Z","cwd":"/Users/me/code/edamame_core","message":{"content":[{"type":"tool_use","id":"t1","name":"Write","input":{"file_path":"/Users/me/Library/Caches/sim/agents.sh","content":"#!/bin/bash\nD=\"$BASE/edsim-agent$N\"; cd \"$D\" || exit 1\nclaude -p \"$P\" > \"$D/../r.json\" 2>&1\n"}}]}}),
                serde_json::json!({"type":"assistant","timestamp":"2026-09-28T19:22:30Z","cwd":"/Users/me/code/edamame_core","message":{"content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"cd $HOME/Library/Caches/sim; ( ./agents.sh 1 /private/tmp/edsim-agents; ./agents.sh 2 \"${TMPDIR}edsim-agents\" ) > log 2>&1 &\necho $!"}}]}}),
                serde_json::json!({"type":"user","timestamp":"2026-09-28T19:22:32Z","message":{"content":[{"type":"tool_result","tool_use_id":"t2","content":"4242"}]}}),
                serde_json::json!({"type":"assistant","timestamp":"2026-09-28T19:24:57Z","cwd":"/Users/me/code/edamame_core","message":{"content":[{"type":"tool_use","id":"t3","name":"Bash","input":{"command":"cd $HOME/Library/Caches/sim; ./agents.sh 3 /private/var/tmp/edsim-agents >> log 2>&1; tail -2 log"}}]}}),
                serde_json::json!({"type":"user","timestamp":"2026-09-28T19:25:21Z","message":{"content":[{"type":"tool_result","tool_use_id":"t3","content":"done"}]}}),
                serde_json::json!({"type":"assistant","timestamp":"2026-09-28T19:30:00Z","cwd":"/Users/me/code/edamame_core","message":{"content":[{"type":"tool_use","id":"t4","name":"Bash","input":{"command":"rm -rf /private/tmp/edsim-agents"}}]}}),
            ],
        );
        assert_eq!(scan.context.cwd, "/Users/me/code/edamame_core");
        assert!(!scan.context.headless);
        assert!(scan.agent_scripts.contains("agents.sh"));
        assert_eq!(scan.launches.len(), 2, "{:?}", scan.launches);
        let (_, bg) = &scan.launches[0];
        assert!(bg.background);
        assert!(bg.dirs.contains(&"/private/tmp/edsim-agents".to_string()));
        assert!(bg.dirs.contains(&"$TMPDIR/edsim-agents".to_string()));
        assert!(bg.dirs.contains(&"~/Library/Caches/sim".to_string()));
        assert!(bg.dirs.contains(&"/Users/me/code/edamame_core".to_string()));
        let (_, fg) = &scan.launches[1];
        assert!(!fg.background);
        assert_eq!(
            fg.finished_at.map(|t| t.to_rfc3339()),
            Some("2026-09-28T19:25:21+00:00".to_string())
        );
        assert!(scan.pending.is_empty());
    }

    #[test]
    fn headless_context_is_read_from_the_harness_fields() {
        let mut claude = FileScan::default();
        feed(
            &mut claude,
            &[
                serde_json::json!({"type":"queue-operation","operation":"enqueue","timestamp":"2026-09-28T19:22:33.370Z"}),
                serde_json::json!({"type":"user","timestamp":"2026-09-28T19:22:34Z","cwd":"/private/tmp/edsim-agents/edsim-agent1","entrypoint":"sdk-cli","message":{"role":"user","content":"Create a small Rust CLI"}}),
            ],
        );
        assert!(claude.context_settled);
        assert!(claude.context.headless);
        assert_eq!(claude.context.cwd, "/private/tmp/edsim-agents/edsim-agent1");
        assert_eq!(
            claude.context.started_at.map(|t| t.to_rfc3339()),
            Some("2026-09-28T19:22:33.370+00:00".to_string())
        );

        let mut codex = FileScan::default();
        feed(
            &mut codex,
            &[
                serde_json::json!({"timestamp":"2026-09-28T19:24:21Z","type":"session_meta","payload":{"id":"x","timestamp":"2026-09-28T19:24:20Z","cwd":"/private/tmp/edsim-agents/edsim-agent6","originator":"codex_exec","source":"exec"}}),
            ],
        );
        assert!(codex.context.headless);
        assert_eq!(codex.context.cwd, "/private/tmp/edsim-agents/edsim-agent6");

        let mut interactive = FileScan::default();
        feed(
            &mut interactive,
            &[
                serde_json::json!({"type":"user","timestamp":"2026-09-28T10:00:00Z","cwd":"/Users/me/p","entrypoint":"cli","message":{"content":"hi"}}),
            ],
        );
        assert!(!interactive.context.headless);
    }

    #[test]
    fn codex_and_cursor_launch_calls_are_recorded() {
        let mut codex = FileScan::default();
        feed(
            &mut codex,
            &[
                serde_json::json!({"timestamp":"2026-09-28T10:00:00Z","type":"session_meta","payload":{"cwd":"/home/me/app","originator":"codex_cli_rs"}}),
                serde_json::json!({"timestamp":"2026-09-28T10:01:00Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"c1","arguments":"{\"cmd\":\"claude -p 'review'\",\"workdir\":\"/home/me/app/sub\"}"}}),
                serde_json::json!({"timestamp":"2026-09-28T10:03:00Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"ok"}}),
            ],
        );
        assert_eq!(codex.launches.len(), 1);
        let (_, call) = &codex.launches[0];
        assert_eq!(call.dirs, vec!["/home/me/app/sub".to_string()]);
        assert!(call.finished_at.is_some());

        let mut cursor = FileScan::default();
        feed(
            &mut cursor,
            &[
                serde_json::json!({"role":"assistant","message":{"content":[{"type":"tool_use","name":"Shell","input":{"command":"claude -p 'go'","working_directory":"C:\\Users\\me\\AppData\\Local\\Temp\\run1","block_until_ms":0}}]}}),
            ],
        );
        assert_eq!(cursor.launches.len(), 1);
        let (_, call) = &cursor.launches[0];
        assert!(call.at.is_none());
        assert!(call.background);
        assert_eq!(
            call.dirs,
            vec!["C:/Users/me/AppData/Local/Temp/run1".to_string()]
        );
    }

    #[test]
    fn incremental_scan_resumes_after_the_last_complete_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        let first = line(
            serde_json::json!({"type":"user","timestamp":"2026-09-28T10:00:00Z","cwd":"/Users/me/p","entrypoint":"cli","message":{"content":"hi"}}),
        );
        let call = line(
            serde_json::json!({"type":"assistant","timestamp":"2026-09-28T10:01:00Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"a","name":"Bash","input":{"command":"claude -p x","run_in_background":true}}]}}),
        );
        // A partial trailing line is not consumed.
        let mut bytes = first.clone();
        bytes.extend_from_slice(&call[..call.len() / 2]);
        std::fs::write(&path, &bytes).unwrap();
        let scan = scan_file(&path).expect("scan");
        assert_eq!(scan.offset, first.len() as u64);
        assert!(scan.launches.is_empty());
        // The rest of the line lands: the next scan picks it up from the offset.
        let mut all = first.clone();
        all.extend_from_slice(&call);
        std::fs::write(&path, &all).unwrap();
        let scan = scan_file(&path).expect("scan");
        assert_eq!(scan.offset, all.len() as u64);
        assert_eq!(scan.launches.len(), 1);
        assert!(scan.launches[0].1.background);
    }
}
