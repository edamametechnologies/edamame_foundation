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
//!   timestamp, and whether a program rather than a person started it (a
//!   Claude Code `entrypoint`, a Codex `originator` / `source` the params list
//!   as programmatic). The harness writes these fields; the model's text is
//!   never read for them.
//! - [`AgentLaunchCall`], the parent side: a shell tool call that starts an
//!   agent CLI, directly or through a script the same transcript wrote whose
//!   body starts one, with the call's timestamp, the time its result came
//!   back when it ran in the foreground, and the absolute directories the
//!   command names.
//!
//! What counts as an agent CLI, a shell, a wrapper, a working-directory
//! argument or a programmatic start is data: it comes from the
//! agent-visibility params (`workspace_attribution`, see
//! [`crate::agent_visibility_params::WorkspaceAttributionJSON`]). This module
//! keeps the mechanics: the shell grammar, the transcript line structure and
//! the incremental scan.
//!
//! Scanning is streaming and incremental: transcripts are append-only JSONL,
//! so a per-file state remembers the offset of the last complete line and a
//! grown file is read from there, never re-read from the start. A session's
//! Task subagent transcripts are scanned with it: an orchestrator's subagents
//! are where the launches usually are, and the walker does not collect
//! subagents as sessions of their own.

use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{CollectOptions, CollectedRawSession};
use crate::agent_visibility_params::{self, ProgramOptionsJSON, WorkspaceAttributionJSON};

// Resource bounds of the scanner (not attribution rules): they cap memory and
// I/O whatever a transcript contains.

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
/// Transcript files whose scan state is kept.
const MAX_CACHED_FILES: usize = 8192;
/// Bytes hashed to tell an appended file from a rewritten one.
const HEAD_FINGERPRINT_BYTES: usize = 256;

/// What a session's own transcript says about how it started.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLaunchContext {
    /// Working directory the harness recorded when the session started
    /// (Claude Code's first `cwd`, Codex `session_meta.cwd`). Empty when the
    /// transcript records none (Cursor).
    pub cwd: String,
    /// First in-transcript timestamp. `None` for formats without timestamps.
    pub started_at: Option<DateTime<Utc>>,
    /// A program, not a person, started the session (`claude -p`, the Agent
    /// SDK, `codex exec`). Interactive sessions (terminal, IDE, desktop app)
    /// are `false`.
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
    /// The call returned before its work finished (`&`, a background flag, a
    /// detaching program): a launched agent may start later than
    /// `finished_at`.
    pub background: bool,
    /// Absolute directories the command names, normalized to `/` separators:
    /// literal paths, `~/...` for the home directory (`~`, `$HOME`, ...),
    /// `$TMPDIR/...` for the per-user temporary directory (`$TMPDIR`,
    /// `%TEMP%`, ...), plus the shell's working directory at the time of the
    /// call.
    pub dirs: Vec<String>,
}

/// Incremental scan state of one transcript file.
#[derive(Debug, Clone, Default)]
struct FileScan {
    /// Signature of the params the state was computed under.
    params_signature: String,
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

static FILE_SCANS: Lazy<undeadlock::CustomDashMap<String, FileScan>> =
    Lazy::new(|| undeadlock::CustomDashMap::new("agent_launch_file_scans"));

/// Attach [`SessionLaunchContext`] and [`AgentLaunchCall`]s to every collected
/// session whose transcript is a JSONL file (its own, or the `.jsonl` twin of
/// a Cursor `.txt` export), scanning its subagent transcripts too.
pub(crate) fn attach_launch_facts(sessions: &mut [CollectedRawSession], options: &CollectOptions) {
    let params = agent_visibility_params::workspace_attribution();
    let vocab = &params.workspace_attribution;
    let horizon = SystemTime::now()
        .checked_sub(Duration::from_secs(
            options
                .active_window_minutes
                .saturating_mul(60)
                .saturating_add(vocab.subagent_lookback_margin_secs),
        ))
        .unwrap_or(UNIX_EPOCH);
    for session in sessions.iter_mut() {
        let Some(main) = jsonl_source(&session.source_path) else {
            continue;
        };
        let Some(main_scan) = scan_file(&main, vocab, &params.signature) else {
            continue;
        };
        let mut launches: Vec<AgentLaunchCall> = main_scan
            .launches
            .iter()
            .map(|(_, call)| call.clone())
            .collect();
        for sub in subagent_transcripts(&main, &vocab.subagent_directory, horizon) {
            if let Some(sub_scan) = scan_file(&sub, vocab, &params.signature) {
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

/// Subagent transcripts of a session file modified after `horizon`: in
/// `<dir>/<stem>/<subagents>/` (Claude Code), or in `<dir>/<subagents>/` when
/// the transcript sits in a directory named after it (Cursor).
fn subagent_transcripts(main: &Path, subagents: &str, horizon: SystemTime) -> Vec<PathBuf> {
    let (Some(dir), Some(stem)) = (main.parent(), main.file_stem().and_then(|s| s.to_str())) else {
        return Vec::new();
    };
    if subagents.is_empty() {
        return Vec::new();
    }
    let mut roots = vec![dir.join(stem).join(subagents)];
    if dir.file_name().and_then(|n| n.to_str()) == Some(stem) {
        roots.push(dir.join(subagents));
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
fn scan_file(path: &Path, vocab: &WorkspaceAttributionJSON, signature: &str) -> Option<FileScan> {
    let key = path.to_string_lossy().to_string();
    let meta = std::fs::metadata(path).ok()?;
    let size = meta.len();
    let mtime = mtime_ns(&meta);
    let cached = FILE_SCANS.get(&key).map(|entry| (*entry).clone());
    let head = head_fingerprint(path);
    let mut scan = match cached {
        // A state computed under other params is recomputed from the start.
        Some(scan) if scan.params_signature != signature => FileScan::default(),
        Some(scan) if scan.size == size && scan.mtime_ns == mtime => return Some(scan),
        // Appended to: continue from the last complete line.
        Some(scan) if size >= scan.size && head == Some(scan.head_fingerprint) => scan,
        // Truncated or rewritten: start over.
        _ => FileScan::default(),
    };
    if scan_increment(path, &mut scan, size, vocab).is_err() {
        return None;
    }
    scan.params_signature = signature.to_string();
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

fn scan_increment(
    path: &Path,
    scan: &mut FileScan,
    size: u64,
    vocab: &WorkspaceAttributionJSON,
) -> std::io::Result<()> {
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
            process_line(&line, scan, vocab);
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

// Transcript line structure (mechanics of the Anthropic and Codex JSONL
// formats, not attribution data).

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
/// Marker of a Codex code-mode line recording what the model's script ran
/// (`event_msg` / `item_completed`, see [`super::parsing::codex_completed_item`]).
const CODE_MODE_LINE_MARKER: &str = "\"item_completed\"";
/// The code-mode items that can start an agent: a command, and a patch that
/// writes a script.
const CODE_MODE_ITEM_MARKERS: &[&str] = &["\"CommandExecution\"", "\"FileChange\""];

fn process_line(line: &[u8], scan: &mut FileScan, vocab: &WorkspaceAttributionJSON) {
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
    let has_code_mode_item = text.contains(CODE_MODE_LINE_MARKER)
        && CODE_MODE_ITEM_MARKERS.iter().any(|m| text.contains(m));
    if !wants_context && !has_call && !has_result && !has_code_mode_item {
        return;
    }
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let line_ts = line_timestamp(&value);
    if wants_context {
        absorb_context(&value, line_ts, scan, vocab);
    }
    if has_code_mode_item {
        if let Some(item) = super::parsing::codex_completed_item(&value) {
            absorb_code_mode_item(item, &value, line_ts, scan, vocab);
        }
    }
    for block in structured_blocks(&value) {
        match block_kind(block) {
            BlockKind::Call => absorb_tool_call(block, &value, line_ts, scan, vocab),
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

fn absorb_context(
    value: &Value,
    line_ts: Option<DateTime<Utc>>,
    scan: &mut FileScan,
    vocab: &WorkspaceAttributionJSON,
) {
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
            let entrypoint = entrypoint.trim().to_ascii_lowercase();
            scan.context.headless = vocab
                .headless_entrypoint_prefixes
                .iter()
                .any(|prefix| !prefix.is_empty() && entrypoint.starts_with(prefix.as_str()));
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
            let field = |key: &str| {
                meta.get(key)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase()
            };
            let (originator, source) = (field("originator"), field("source"));
            scan.context.headless = vocab.headless_originators.contains(&originator)
                || vocab.headless_sources.contains(&source);
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

fn str_field<'a>(object: &'a Value, keys: &[String]) -> Option<&'a str> {
    keys.iter()
        .find_map(|k| object.get(k.as_str()).and_then(|v| v.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn absorb_tool_call(
    block: &Value,
    line: &Value,
    line_ts: Option<DateTime<Utc>>,
    scan: &mut FileScan,
    vocab: &WorkspaceAttributionJSON,
) {
    // A patch (Codex `apply_patch`, Cursor `ApplyPatch`) arrives as a string.
    if let Some(patch) = block.get("input").and_then(|v| v.as_str()) {
        remember_patched_scripts(patch, scan, vocab);
        return;
    }
    let Some(args) = call_arguments(block) else {
        return;
    };
    // A file write: remember the script when its body starts an agent CLI.
    if let Some(path) = str_field(&args, &vocab.write_path_keys) {
        let mut body = String::new();
        for key in &vocab.write_content_keys {
            if let Some(text) = args.get(key.as_str()).and_then(|v| v.as_str()) {
                body.push_str(text);
                body.push('\n');
            }
        }
        for key in &vocab.write_edit_list_keys {
            if let Some(edits) = args.get(key.as_str()).and_then(|v| v.as_array()) {
                for edit in edits {
                    for content_key in &vocab.write_content_keys {
                        if let Some(text) = edit.get(content_key.as_str()).and_then(|v| v.as_str())
                        {
                            body.push_str(text);
                            body.push('\n');
                        }
                    }
                }
            }
        }
        if !body.is_empty() && script_starts_agent(&body, vocab) {
            remember_script(path, scan, vocab);
        }
    }
    let Some(command) = command_text(&args, vocab) else {
        return;
    };
    let shell_cwd = str_field(&args, &vocab.working_directory_keys)
        .or_else(|| line.get("cwd").and_then(|v| v.as_str()).map(str::trim))
        .unwrap_or("")
        .to_string();
    absorb_shell_command(
        ShellCommand {
            command: &command,
            shell_cwd: &shell_cwd,
            args: &args,
            id: block_id(block),
            at: line_ts,
            finished_at: None,
        },
        scan,
        vocab,
    );
}

/// One shell command a tool call ran, with what is known about its run.
struct ShellCommand<'a> {
    command: &'a str,
    /// The shell's working directory at the time of the call.
    shell_cwd: &'a str,
    /// The call's arguments (background flags are read from them).
    args: &'a Value,
    /// The call's id, to match the result of a foreground call.
    id: Option<String>,
    at: Option<DateTime<Utc>>,
    /// When the command's result is already known: a Codex code-mode item
    /// is recorded once the command has finished.
    finished_at: Option<DateTime<Utc>>,
}

/// Record `cmd` as a launch call when it starts an agent CLI, directly or
/// through a script this transcript wrote.
fn absorb_shell_command(
    cmd: ShellCommand<'_>,
    scan: &mut FileScan,
    vocab: &WorkspaceAttributionJSON,
) {
    let args = cmd.args;
    let lexed = lex_shell(cmd.command);
    let mut direct = lexed
        .commands
        .iter()
        .any(|words| starts_agent_cli(words, vocab));
    // A heredoc is written to a file (`cat > run.sh <<EOF`) or fed to the
    // program it follows (`bash <<EOF`, `python3 - <<EOF`). A body that starts
    // an agent CLI (as a shell command, or as a name a program spawns) makes
    // the file an agent script, and feeding it to a shell or an interpreter is
    // a launch.
    let shell_body = lexed.heredocs.iter().any(|body| {
        lex_shell(body)
            .commands
            .iter()
            .any(|words| starts_agent_cli(words, vocab))
    });
    let literal_body = lexed
        .heredocs
        .iter()
        .any(|body| names_agent_cli_literal(body, vocab));
    if shell_body || literal_body {
        let targets: Vec<String> = lexed.redirect_targets.clone();
        for target in targets {
            remember_script(&target, scan, vocab);
        }
        direct |= lexed.commands.iter().any(|words| {
            command_word_index(words, vocab)
                .map(|i| {
                    let name = exe_basename(&words[i], vocab);
                    (is_shell(&name, vocab) && shell_body)
                        || (is_interpreter(&name, vocab) && literal_body)
                })
                .unwrap_or(false)
        });
    }
    let via_script = lexed
        .commands
        .iter()
        .any(|words| runs_script(words, &scan.agent_scripts, vocab));
    if !direct && !via_script {
        return;
    }
    let background = lexed.background
        || lexed.commands.iter().any(|words| detaches(words, vocab))
        || vocab
            .background_flag_keys
            .iter()
            .any(|k| args.get(k.as_str()).and_then(|v| v.as_bool()) == Some(true))
        || vocab
            .background_wait_keys
            .iter()
            .any(|k| args.get(k.as_str()).and_then(|v| v.as_u64()) == Some(0));
    // A background call's result says nothing about when the agent it
    // started finished.
    let finished_at = if background { None } else { cmd.finished_at };
    let call = AgentLaunchCall {
        at: cmd.at,
        finished_at,
        background,
        dirs: named_directories(&lexed, cmd.shell_cwd, vocab),
    };
    let seq = scan.next_seq;
    scan.next_seq += 1;
    if !background && finished_at.is_none() {
        if let Some(id) = cmd.id {
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

fn remember_script(path: &str, scan: &mut FileScan, vocab: &WorkspaceAttributionJSON) {
    let base = file_basename_lower(path);
    // A document that mentions an agent (`README.md`) is not something a
    // command runs; a script has a script extension or none.
    let runnable = match base.rsplit_once('.') {
        Some((stem, ext)) => !stem.is_empty() && vocab.script_extensions.iter().any(|e| e == ext),
        None => true,
    };
    if runnable && !base.is_empty() && scan.agent_scripts.len() < MAX_AGENT_SCRIPTS_PER_FILE {
        scan.agent_scripts.insert(base);
    }
}

/// Files a patch adds or updates whose added lines start an agent CLI.
fn remember_patched_scripts(patch: &str, scan: &mut FileScan, vocab: &WorkspaceAttributionJSON) {
    let mut current: Option<String> = None;
    let mut added = String::new();
    let flush = |path: Option<String>, body: &mut String, scan: &mut FileScan| {
        if let Some(path) = path {
            if script_starts_agent(body, vocab) {
                remember_script(&path, scan, vocab);
            }
        }
        body.clear();
    };
    for line in patch.lines() {
        let header = vocab
            .patch_file_headers
            .iter()
            .find_map(|h| line.strip_prefix(h.as_str()));
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

/// A Codex code-mode item (CLI 0.160). The model's `exec` script is not what
/// ran; the `CommandExecution` and `FileChange` items its run recorded are
/// (see [`super::parsing::codex_completed_item`]), so a `codex exec` or a
/// `claude -p` Codex starts through a command, or through a script a patch
/// wrote, is seen here. A command is recorded once it has finished: its
/// start and end come on the line (`started_at_ms` / `completed_at_ms`),
/// and no result follows to wait for.
fn absorb_code_mode_item(
    item: &Value,
    line: &Value,
    line_ts: Option<DateTime<Utc>>,
    scan: &mut FileScan,
    vocab: &WorkspaceAttributionJSON,
) {
    match item.get("type").and_then(|v| v.as_str()).unwrap_or("") {
        "CommandExecution" => {
            let argv: Vec<&str> = item
                .get("command")
                .and_then(|v| v.as_array())
                .map(|words| words.iter().filter_map(|w| w.as_str()).collect())
                .unwrap_or_default();
            let Some(command) =
                unwrap_shell_argv(&argv, vocab).or_else(|| command_text(item, vocab))
            else {
                return;
            };
            let payload = line.get("payload");
            let started = payload
                .and_then(|p| p.get("started_at_ms"))
                .and_then(ts_from_value);
            let completed = payload
                .and_then(|p| p.get("completed_at_ms"))
                .and_then(ts_from_value);
            let shell_cwd = item
                .get("cwd")
                .and_then(|v| v.as_str())
                .map(file_url_path)
                .unwrap_or_default();
            absorb_shell_command(
                ShellCommand {
                    command: &command,
                    shell_cwd: &shell_cwd,
                    args: item,
                    id: None,
                    at: started.or(line_ts),
                    finished_at: completed.or(line_ts),
                },
                scan,
                vocab,
            );
        }
        // `changes: {<path>: {"type": "add", "content": ...}}`; an update
        // carries a `unified_diff` whose added lines are what the file now
        // says. A deleted file runs nothing.
        "FileChange" => {
            let Some(changes) = item.get("changes").and_then(|v| v.as_object()) else {
                return;
            };
            for (path, change) in changes {
                if change.get("type").and_then(|v| v.as_str()) == Some("delete") {
                    continue;
                }
                let mut body = String::new();
                for key in &vocab.write_content_keys {
                    if let Some(text) = change.get(key.as_str()).and_then(|v| v.as_str()) {
                        body.push_str(text);
                        body.push('\n');
                    }
                }
                if let Some(diff) = change.get("unified_diff").and_then(|v| v.as_str()) {
                    for text in diff.lines().filter_map(|l| l.strip_prefix('+')) {
                        if !text.starts_with("++") {
                            body.push_str(text);
                            body.push('\n');
                        }
                    }
                }
                if !body.is_empty() && script_starts_agent(&body, vocab) {
                    remember_script(path, scan, vocab);
                }
            }
        }
        _ => {}
    }
}

/// The path a `file://` URL names, percent-decoded (Codex code mode records
/// a command's `cwd` as one: `file:///Users/me/p`, `file:///C:/Users/me/p`
/// for `C:/Users/me/p`). Any other value is returned trimmed.
fn file_url_path(value: &str) -> String {
    let value = value.trim();
    let Some(rest) = value.strip_prefix("file://") else {
        return value.to_string();
    };
    let bytes = rest.as_bytes();
    let path = if bytes.len() >= 3
        && bytes[0] == b'/'
        && bytes[1].is_ascii_alphabetic()
        && bytes[2] == b':'
    {
        &rest[1..]
    } else {
        rest
    };
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The script a shell wrapper argv runs: `[sh|bash|zsh|dash, -c|-lc, X]`,
/// `[pwsh|powershell(.exe), -Command|-c, X]`, `[cmd(.exe), /c, X]`. Which
/// programs are shells, PowerShells and `/`-option wrappers, the PowerShell
/// script options and the launcher extensions are the params'; the option
/// grammar is the shells' own: a POSIX short-option cluster that includes
/// `c`, cmd's `/c`. Program names compare by basename, case-insensitively.
/// `None` when `argv` is not such a wrapper.
pub(super) fn unwrap_shell_argv(argv: &[&str], vocab: &WorkspaceAttributionJSON) -> Option<String> {
    let [program, option, script] = argv else {
        return None;
    };
    let script = script.trim();
    if script.is_empty() {
        return None;
    }
    let name = exe_basename(program, vocab);
    let runs_script = if vocab.powershell_programs.contains(&name) {
        vocab
            .powershell_script_options
            .iter()
            .any(|o| o.eq_ignore_ascii_case(option))
    } else if is_shell(&name, vocab) {
        option.strip_prefix('-').is_some_and(|cluster| {
            cluster.contains('c') && cluster.chars().all(|c| c.is_ascii_alphabetic())
        })
    } else if vocab.wrapper_slash_option_programs.contains(&name) {
        option.eq_ignore_ascii_case("/c")
    } else {
        false
    };
    runs_script.then(|| script.to_string())
}

/// The shell command of a call: a command key as a string, or as an argv
/// array (`["bash", "-lc", "<script>"]` yields the script).
fn command_text(args: &Value, vocab: &WorkspaceAttributionJSON) -> Option<String> {
    for key in &vocab.command_keys {
        match args.get(key.as_str()) {
            Some(Value::String(s)) if !s.trim().is_empty() => return Some(s.clone()),
            Some(Value::Array(items)) => {
                let argv: Vec<&str> = items.iter().filter_map(|v| v.as_str()).collect();
                if argv.is_empty() {
                    continue;
                }
                if argv.len() >= 3
                    && is_shell(&exe_basename(argv[0], vocab), vocab)
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
// Shell lexing (grammar mechanics)
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
fn exe_basename(word: &str, vocab: &WorkspaceAttributionJSON) -> String {
    let base = file_basename_lower(word);
    if let Some((stem, ext)) = base.rsplit_once('.') {
        if !stem.is_empty() && vocab.executable_extensions.iter().any(|e| e == ext) {
            return stem.to_string();
        }
    }
    base
}

fn is_shell(name: &str, vocab: &WorkspaceAttributionJSON) -> bool {
    vocab.shell_programs.iter().any(|s| s == name)
}

fn is_interpreter(name: &str, vocab: &WorkspaceAttributionJSON) -> bool {
    vocab
        .interpreter_program_prefixes
        .iter()
        .any(|p| !p.is_empty() && name.starts_with(p.as_str()))
}

fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `option` is one of `program`'s options in `table`.
fn program_option(table: &[ProgramOptionsJSON], program: &str, option: &str) -> bool {
    table
        .iter()
        .any(|p| p.program == program && p.options.iter().any(|o| o == option))
}

/// `option` is one of `program`'s options in `table`, ignoring case
/// (PowerShell parameters).
fn program_option_ignore_case(table: &[ProgramOptionsJSON], program: &str, option: &str) -> bool {
    table
        .iter()
        .any(|p| p.program == program && p.options.iter().any(|o| o.eq_ignore_ascii_case(option)))
}

/// Index of the word a simple command runs, skipping variable assignments
/// and wrapper commands (`env`, `nohup`, `timeout 900`, `sudo -u x`, ...).
/// `None` when the command runs nothing or only looks a program up.
fn command_word_index(words: &[String], vocab: &WorkspaceAttributionJSON) -> Option<usize> {
    let mut i = 0usize;
    while i < words.len() {
        let word = &words[i];
        if is_assignment(word) {
            i += 1;
            continue;
        }
        let name = exe_basename(word, vocab);
        if !vocab.wrapper_programs.contains(&name) {
            return Some(i);
        }
        let slash_options = vocab.wrapper_slash_option_programs.contains(&name);
        i += 1;
        while i < words.len() {
            let w = &words[i];
            let is_option = w.starts_with('-')
                || (slash_options && w.starts_with('/'))
                || (is_assignment(w) && i > 0);
            if !is_option {
                break;
            }
            if program_option(&vocab.lookup_options, &name, w) {
                return None;
            }
            if program_option_ignore_case(&vocab.wrapper_program_options, &name, w) {
                return (i + 1 < words.len()).then_some(i + 1);
            }
            i += if program_option(&vocab.wrapper_value_options, &name, w) {
                2
            } else {
                1
            };
        }
        if vocab.wrapper_duration_programs.contains(&name) && i < words.len() {
            // The duration.
            i += 1;
        }
        if vocab.wrapper_title_programs.contains(&name) && i < words.len() && words[i].is_empty() {
            // `start "" <command>`: the window title.
            i += 1;
        }
    }
    None
}

/// The word names an agent CLI, directly or as its package.
fn names_agent_cli(word: &str, vocab: &WorkspaceAttributionJSON) -> bool {
    let lower = word.to_ascii_lowercase();
    vocab
        .agent_cli_programs
        .contains(&exe_basename(word, vocab))
        || vocab
            .agent_cli_package_markers
            .iter()
            .any(|m| !m.is_empty() && lower.contains(m.as_str()))
}

/// The simple command starts an agent CLI.
fn starts_agent_cli(words: &[String], vocab: &WorkspaceAttributionJSON) -> bool {
    let Some(i) = command_word_index(words, vocab) else {
        return false;
    };
    let name = exe_basename(&words[i], vocab);
    if vocab.agent_cli_programs.contains(&name) {
        return true;
    }
    let rest = &words[i + 1..];
    let first_arg = rest.iter().find(|w| !w.starts_with('-'));
    if let Some(arg) = first_arg {
        let arg = arg.to_ascii_lowercase();
        if vocab
            .agent_cli_subcommands
            .iter()
            .any(|c| c.program == name && c.subcommand == arg)
        {
            return true;
        }
    }
    if vocab.package_runner_programs.contains(&name) {
        return first_arg
            .map(|w| names_agent_cli(w, vocab))
            .unwrap_or(false);
    }
    if vocab.package_exec_programs.contains(&name) {
        return rest
            .first()
            .map(|w| {
                vocab
                    .package_exec_subcommands
                    .contains(&w.to_ascii_lowercase())
            })
            .unwrap_or(false)
            && rest.iter().skip(1).any(|w| names_agent_cli(w, vocab));
    }
    if is_shell(&name, vocab) {
        // `bash -lc '<script>'`, `pwsh -Command '<script>'`.
        let powershell = vocab.powershell_programs.contains(&name);
        let mut k = 0;
        while k < rest.len() {
            let w = &rest[k];
            if !w.starts_with('-') {
                break;
            }
            let lower = w.to_ascii_lowercase();
            let takes_script = if powershell {
                vocab.powershell_script_options.contains(&lower)
            } else {
                // POSIX shells: a short option cluster carrying `c`.
                !lower.starts_with("--") && lower[1..].contains('c')
            };
            if takes_script {
                return rest
                    .get(k + 1)
                    .map(|script| {
                        lex_shell(script)
                            .commands
                            .iter()
                            .any(|c| starts_agent_cli(c, vocab))
                    })
                    .unwrap_or(false);
            }
            k += 1;
        }
    }
    false
}

/// The simple command detaches what it runs from the calling shell.
fn detaches(words: &[String], vocab: &WorkspaceAttributionJSON) -> bool {
    words
        .first()
        .map(|w| vocab.detaching_programs.contains(&exe_basename(w, vocab)))
        .unwrap_or(false)
}

/// A script body (shell, or a scripting language that spawns the CLI by
/// name) starts an agent CLI.
fn script_starts_agent(body: &str, vocab: &WorkspaceAttributionJSON) -> bool {
    lex_shell(body)
        .commands
        .iter()
        .any(|words| starts_agent_cli(words, vocab))
        || names_agent_cli_literal(body, vocab)
}

/// A program spawns an agent CLI by name: `subprocess.run(["claude", "-p",
/// ...])`, `spawn('codex', [...])`.
fn names_agent_cli_literal(body: &str, vocab: &WorkspaceAttributionJSON) -> bool {
    vocab.agent_cli_programs.iter().any(|name| {
        !name.is_empty()
            && (body.contains(&format!("\"{name}\"")) || body.contains(&format!("'{name}'")))
    })
}

/// The simple command runs one of `scripts`: as its program (`./agents.sh`,
/// `timeout 900 $FS/run.sh`) or as the script of a shell, an interpreter or
/// a `source` (`bash agents.sh`, `python3 spawn.py`, `. ./env.sh`). Naming a
/// script (`chmod +x run.sh`, `cat run.sh`) is not running it.
fn runs_script(
    words: &[String],
    scripts: &BTreeSet<String>,
    vocab: &WorkspaceAttributionJSON,
) -> bool {
    if scripts.is_empty() {
        return false;
    }
    let Some(i) = command_word_index(words, vocab) else {
        return false;
    };
    if scripts.contains(&file_basename_lower(&words[i])) {
        return true;
    }
    let name = exe_basename(&words[i], vocab);
    if !(is_shell(&name, vocab)
        || is_interpreter(&name, vocab)
        || vocab.source_programs.contains(&name))
    {
        return false;
    }
    words[i + 1..]
        .iter()
        .find(|w| !w.starts_with('-'))
        .map(|w| scripts.contains(&file_basename_lower(w)))
        .unwrap_or(false)
}

/// The variable spelling `lower` starts with, when what follows it does not
/// continue the variable's name (`$HOMEBREW` is not `$HOME`).
fn variable_prefix<'a>(lower: &str, spellings: &'a [String]) -> Option<&'a str> {
    spellings
        .iter()
        .filter(|s| !s.is_empty() && lower.starts_with(s.as_str()))
        .find(|s| {
            let rest = &lower[s.len()..];
            let continues_name = rest
                .chars()
                .next()
                .map(|c| c.is_ascii_alphanumeric() || c == '_')
                .unwrap_or(false);
            // A bare `$NAME` / `$env:NAME` ends where the name does; a braced
            // or percent spelling ends at its delimiter (`${TMPDIR}x`).
            !(continues_name && s.starts_with('$') && !s.ends_with('}'))
        })
        .map(String::as_str)
}

/// Normalize one word into an absolute directory reference, or `None` when
/// it is relative or unresolvable (`$BASE/x`).
fn normalize_named_path(word: &str, vocab: &WorkspaceAttributionJSON) -> Option<String> {
    let w = word
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_end_matches([';', ',', ')', ':']);
    if w.is_empty() {
        return None;
    }
    // Text that happens to start with a slash (a comment, a regex) is not a
    // path.
    if w.contains(['\n', '\r', '\t']) {
        return None;
    }
    let lower = w.to_ascii_lowercase();
    let (prefix, rest): (&str, &str) = if w == "~" || w.starts_with("~/") || w.starts_with("~\\") {
        ("~", &w[1..])
    } else if let Some(spelling) = variable_prefix(&lower, &vocab.home_variables) {
        let rest = &w[spelling.len()..];
        if !(rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\')) {
            return None;
        }
        ("~", rest)
    } else if let Some(spelling) = variable_prefix(&lower, &vocab.temp_variables) {
        // macOS sets `$TMPDIR` with a trailing slash: `${TMPDIR}x` is
        // `$TMPDIR` + `x`.
        ("$TMPDIR", &w[spelling.len()..])
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
        // `C:\x` / `C:/x`: the drive is the first component.
        "" => joined,
        p if joined.is_empty() => p.to_string(),
        p => format!("{p}/{joined}"),
    })
}

/// Absolute directories a launch command names, the shell's working
/// directory first, then directory changes (relative ones resolved against
/// it), then every other absolute path word.
fn named_directories(
    lexed: &Lexed,
    shell_cwd: &str,
    vocab: &WorkspaceAttributionJSON,
) -> Vec<String> {
    let mut dirs: Vec<String> = Vec::new();
    let push = |dir: String, dirs: &mut Vec<String>| {
        if !dir.is_empty() && !dirs.contains(&dir) && dirs.len() < MAX_DIRS_PER_LAUNCH {
            dirs.push(dir);
        }
    };
    let cwd = normalize_named_path(shell_cwd, vocab);
    if let Some(cwd) = cwd.clone() {
        push(cwd, &mut dirs);
    }
    for words in &lexed.commands {
        let Some(i) = command_word_index(words, vocab) else {
            continue;
        };
        let name = exe_basename(&words[i], vocab);
        if !vocab.change_directory_programs.contains(&name) {
            continue;
        }
        if let Some(target) = words.get(i + 1).filter(|w| !w.starts_with('-')) {
            match normalize_named_path(target, vocab) {
                Some(abs) => push(abs, &mut dirs),
                None => {
                    if let (Some(base), false) = (cwd.as_deref(), target.contains('$')) {
                        let joined = format!("{}/{}", base.trim_end_matches('/'), target);
                        if let Some(abs) = normalize_named_path(&joined, vocab) {
                            push(abs, &mut dirs);
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
        if let Some(abs) = normalize_named_path(value, vocab) {
            push(abs, &mut dirs);
        }
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rules production reads.
    fn vocab() -> std::sync::Arc<crate::agent_visibility_params::AgentVisibilityParams> {
        agent_visibility_params::workspace_attribution()
    }

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
        let p = vocab();
        let v = &p.workspace_attribution;
        assert!(!lex_shell("cargo test 2>&1 | tail").background);
        assert!(!lex_shell("cargo test &> out.log").background);
        assert!(!lex_shell("a && b || c").background);
        assert!(lex_shell("( ./agents.sh 1 /tmp/x ) > log 2>&1 &\necho $!").background);
        // PowerShell's call operator is not a background job.
        let lexed = lex_shell(r#"& "C:\Program Files\claude\claude.exe" -p hi"#);
        assert!(!lexed.background);
        assert!(lexed.commands.iter().any(|w| starts_agent_cli(w, v)));
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
        let p = vocab();
        let v = &p.workspace_attribution;
        let starts = |cmd: &str| words(cmd).iter().any(|w| starts_agent_cli(w, v));
        assert!(starts("claude -p 'fix the build'"));
        assert!(starts(
            "cd /tmp/x && env -u CLAUDECODE -u CLAUDE_PID claude -p \"$P\""
        ));
        assert!(starts("timeout 900 codex exec -C /tmp/x 'do it'"));
        assert!(starts("nohup cursor-agent -p hi > out.log 2>&1 &"));
        assert!(starts("npx @anthropic-ai/claude-code -p hi"));
        assert!(starts("/Users/me/.local/bin/claude -p hi"));
        assert!(starts(r#"bash -lc "cd /tmp/y && claude -p hi""#));
        assert!(starts(r#"pwsh -NoProfile -Command "claude -p hi""#));
        assert!(starts(
            r#"Start-Process -FilePath claude -ArgumentList '-p','hi'"#
        ));
        assert!(starts("cursor agent -p hi"));
        assert!(!starts("pgrep -f claude"));
        assert!(!starts("command -v claude"));
        assert!(!starts("ls ~/.claude/projects"));
        assert!(!starts("echo claude"));
        assert!(!starts("cat claude.md"));
    }

    #[test]
    fn named_paths_expand_home_and_temp_markers() {
        let p = vocab();
        let v = &p.workspace_attribution;
        let n = |w: &str| normalize_named_path(w, v);
        assert_eq!(
            n("/private/tmp/edsim-agents/").as_deref(),
            Some("/private/tmp/edsim-agents")
        );
        assert_eq!(
            n("$HOME/Library/Caches/x").as_deref(),
            Some("~/Library/Caches/x")
        );
        assert_eq!(n("${HOME}").as_deref(), Some("~"));
        assert_eq!(n("~/code/x").as_deref(), Some("~/code/x"));
        assert_eq!(
            n("${TMPDIR}edsim-agents").as_deref(),
            Some("$TMPDIR/edsim-agents")
        );
        assert_eq!(n("$TMPDIR/edsim").as_deref(), Some("$TMPDIR/edsim"));
        assert_eq!(n("%TEMP%\\edsim\\a1").as_deref(), Some("$TMPDIR/edsim/a1"));
        assert_eq!(n("$env:TEMP\\edsim").as_deref(), Some("$TMPDIR/edsim"));
        assert_eq!(n("%USERPROFILE%\\src\\app").as_deref(), Some("~/src/app"));
        assert_eq!(
            n(r"C:\Users\me\AppData\Local\Temp\x").as_deref(),
            Some("C:/Users/me/AppData/Local/Temp/x")
        );
        assert_eq!(n("/tmp/run-$ID/x").as_deref(), Some("/tmp"));
        assert_eq!(n("$HOMEBREW_PREFIX/bin"), None);
        assert_eq!(n("$TMPDIRX/a"), None);
        assert_eq!(n("$env:TEMPLATE_DIR/a"), None);
        assert_eq!(n("relative/dir"), None);
        assert_eq!(n("$BASE/edsim"), None);
        assert_eq!(n("/ Catalog labels / naming"), None);
        assert_eq!(n("/a\nb"), None);
        assert_eq!(
            n("/Users/me/Mon Drive (x)/jarvis").as_deref(),
            Some("/Users/me/Mon Drive (x)/jarvis")
        );
    }

    #[test]
    fn named_directories_resolve_relative_cd_against_the_shell_cwd() {
        let p = vocab();
        let v = &p.workspace_attribution;
        let lexed = lex_shell("cd sub && claude -p hi; mkdir -p /private/tmp/a --dir=/opt/data/x");
        let dirs = named_directories(&lexed, "/Users/me/proj", v);
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
        let p = vocab();
        let v = &p.workspace_attribution;
        let scripts: BTreeSet<String> = ["agents.sh".to_string(), "spawn.py".to_string()].into();
        let runs = |cmd: &str| {
            lex_shell(cmd)
                .commands
                .iter()
                .any(|w| runs_script(w, &scripts, v))
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
        let p = vocab();
        let v = &p.workspace_attribution;
        assert!(script_starts_agent(
            "#!/bin/bash\ncd \"$D\" || exit 1\nclaude -p \"$P\" --output-format json > out.json 2>&1\n",
            v
        ));
        assert!(script_starts_agent(
            "import subprocess\nsubprocess.run([\"codex\", \"exec\", prompt])\n",
            v
        ));
        assert!(!script_starts_agent(
            "#!/bin/bash\ncargo test\nls ~/.claude\n",
            v
        ));
    }

    #[test]
    fn patches_register_agent_scripts() {
        let p = vocab();
        let v = &p.workspace_attribution;
        let mut scan = FileScan::default();
        remember_patched_scripts(
            "*** Begin Patch\n*** Add File: tools/spawn.sh\n+#!/bin/sh\n+codex exec -C \"$1\" \"$2\"\n*** Update File: README.md\n+claude is mentioned here\n*** End Patch\n",
            &mut scan,
            v,
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
        let p = vocab();
        for l in lines {
            scan.lines_seen += 1;
            process_line(&line(l.clone()), scan, &p.workspace_attribution);
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
        assert!(!codex.context.headless);
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
    fn shell_wrapper_argv_unwraps_to_its_script() {
        let p = vocab();
        let v = &p.workspace_attribution;
        let unwrap = |argv: &[&str]| unwrap_shell_argv(argv, v);
        assert_eq!(unwrap(&["/bin/bash", "-lc", "ls"]).as_deref(), Some("ls"));
        assert_eq!(unwrap(&["dash", "-c", "ls"]).as_deref(), Some("ls"));
        assert_eq!(
            unwrap(&[
                "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
                "-Command",
                "ls"
            ])
            .as_deref(),
            Some("ls")
        );
        assert_eq!(
            unwrap(&["POWERSHELL.EXE", "-c", "ls"]).as_deref(),
            Some("ls")
        );
        assert_eq!(unwrap(&["cmd.exe", "/C", "dir"]).as_deref(), Some("dir"));
        assert_eq!(unwrap(&["bash", "--norc", "x.sh"]), None);
        assert_eq!(unwrap(&["pwsh", "-File", "x.ps1"]), None);
        assert_eq!(unwrap(&["python3", "-c", "print(1)"]), None);
        assert_eq!(unwrap(&["bash", "-lc", "  "]), None);
        assert_eq!(unwrap(&["bash", "-lc", "ls", "extra"]), None);

        assert_eq!(
            file_url_path("file:///Users/me/My%20Work/ws"),
            "/Users/me/My Work/ws"
        );
        assert_eq!(file_url_path("file:///C:/Users/me/ws"), "C:/Users/me/ws");
        assert_eq!(file_url_path("file:///tmp/100%"), "/tmp/100%");
        assert_eq!(file_url_path(" /plain/path "), "/plain/path");
    }

    #[test]
    fn codex_code_mode_launches_are_read_from_its_items() {
        // Codex 0.160 code mode (FP lab 2026-10-06 shapes): the model's
        // `exec` script names the command; the `CommandExecution` item is
        // what ran, with its start and end.
        let mut mac = FileScan::default();
        feed(
            &mut mac,
            &[
                serde_json::json!({"timestamp":"2026-10-06T00:01:26Z","type":"session_meta","payload":{"cwd":"/Users/runner/ws","originator":"codex_exec","source":"exec"}}),
                serde_json::json!({"timestamp":"2026-10-06T00:01:30Z","type":"response_item","payload":{"type":"custom_tool_call","call_id":"call_1","name":"exec","input":"text(await tools.exec_command({cmd:\"codex exec 'review the diff'\"}));\n"}}),
                serde_json::json!({"timestamp":"2026-10-06T00:01:40Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-1","command":["/bin/bash","-lc","codex exec 'review the diff'"],"cwd":"file:///Users/runner/My%20Work/ws","status":"completed","exit_code":0},"started_at_ms":1_791_244_890_000_i64,"completed_at_ms":1_791_244_900_000_i64}}),
                serde_json::json!({"timestamp":"2026-10-06T00:01:41Z","type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"call_1","output":[{"type":"input_text","text":"Script completed"}]}}),
            ],
        );
        assert_eq!(mac.launches.len(), 1, "{:?}", mac.launches);
        let (_, call) = &mac.launches[0];
        assert!(!call.background);
        assert_eq!(
            call.at.map(|t| t.timestamp_millis()),
            Some(1_791_244_890_000)
        );
        assert_eq!(
            call.finished_at.map(|t| t.timestamp_millis()),
            Some(1_791_244_900_000)
        );
        assert_eq!(call.dirs, vec!["/Users/runner/My Work/ws".to_string()]);
        assert!(mac.pending.is_empty());

        // Windows: a patch writes a script that starts an agent and a command
        // runs it; `cmd /c` starts one directly; reading a file that names an
        // agent starts none.
        let mut win = FileScan::default();
        feed(
            &mut win,
            &[
                serde_json::json!({"timestamp":"2026-10-06T00:20:00Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"FileChange","id":"exec-2","changes":{"C:\\Users\\me\\ws\\spawn.ps1":{"type":"add","content":"claude -p 'summarize' | Out-File r.txt\n"},"C:\\Users\\me\\ws\\README.md":{"type":"add","content":"run claude -p\n"}},"status":"completed"}}}),
                serde_json::json!({"timestamp":"2026-10-06T00:20:05Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-3","command":["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","-Command","& .\\spawn.ps1"],"cwd":"file:///C:/Users/me/ws","status":"completed","exit_code":0}}}),
                serde_json::json!({"timestamp":"2026-10-06T00:21:00Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-4","command":["C:\\Windows\\System32\\cmd.exe","/c","codex exec hi"],"cwd":"file:///C:/Users/me/ws","status":"completed","exit_code":0}}}),
                serde_json::json!({"timestamp":"2026-10-06T00:22:00Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-5","command":["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","-Command","Get-Content claude_notes.md"],"cwd":"file:///C:/Users/me/ws","status":"completed","exit_code":0}}}),
            ],
        );
        assert!(win.agent_scripts.contains("spawn.ps1"));
        assert!(!win.agent_scripts.contains("readme.md"));
        assert_eq!(win.launches.len(), 2, "{:?}", win.launches);
        for (_, call) in &win.launches {
            assert!(!call.background);
            assert_eq!(call.dirs, vec!["C:/Users/me/ws".to_string()]);
            // No start / end on the line: its timestamp stands for both.
            assert_eq!(call.at, call.finished_at);
            assert!(call.at.is_some());
        }
        assert!(win.pending.is_empty());
    }

    #[test]
    fn incremental_scan_resumes_after_the_last_complete_line() {
        let p = vocab();
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
        let scan = scan_file(&path, &p.workspace_attribution, &p.signature).expect("scan");
        assert_eq!(scan.offset, first.len() as u64);
        assert!(scan.launches.is_empty());
        // The rest of the line lands: the next scan picks it up from the offset.
        let mut all = first.clone();
        all.extend_from_slice(&call);
        std::fs::write(&path, &all).unwrap();
        let scan = scan_file(&path, &p.workspace_attribution, &p.signature).expect("scan");
        assert_eq!(scan.offset, all.len() as u64);
        assert_eq!(scan.launches.len(), 1);
        assert!(scan.launches[0].1.background);
        // State computed under other params is recomputed, not reused.
        let rescan = scan_file(&path, &p.workspace_attribution, "another-signature").expect("scan");
        assert_eq!(rescan.launches.len(), 1);
        assert_eq!(rescan.params_signature, "another-signature");
    }
}
