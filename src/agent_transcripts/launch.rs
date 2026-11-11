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
//! Three kinds of fact, read from the transcript files on the collection side
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
//! - [`ShellCall`]: every tool call that ran a shell command, with the time
//!   of the call, the time its result came back, and the names of the
//!   programs in command position. The command text is not kept. With the
//!   list goes [`ShellCallGaps`], which says what the list does not hold.
//!   Core reads both to tell which conversation's call started an observed
//!   process tree.
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
/// Program names kept per shell call.
pub const MAX_PROGRAMS_PER_CALL: usize = 16;
/// Characters kept of one program name.
pub const MAX_PROGRAM_NAME_CHARS: usize = 64;
/// How deep the programs of an inline script are read (`bash -lc "sh -c
/// '...'"`).
const MAX_INLINE_SCRIPT_DEPTH: usize = 2;
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

/// A tool call that ran a shell command: when, and which programs. The
/// command itself is not kept.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellCall {
    /// Timestamp of the line that carries the call. `None` when the line has
    /// none (Cursor), when the line records a command that already ran (a
    /// Codex code-mode item: see `started_at`), and when the timestamp is
    /// later than `read_at`.
    pub at: Option<DateTime<Utc>>,
    /// When the command started, as the harness measured it (Codex code
    /// mode's `started_at_ms`). `None` where the harness records no start,
    /// and when the value is later than `read_at`.
    pub started_at: Option<DateTime<Utc>>,
    /// When the call's result came back (the measured completion in Codex
    /// code mode), never later than `read_at`. `None` until a result is
    /// read.
    pub finished_at: Option<DateTime<Utc>>,
    /// The call returned before its work finished (`&`, a background flag, a
    /// detaching program).
    pub background: bool,
    /// Lower-cased names of the programs in command position, in order of
    /// first appearance: of every simple command, the wrappers it goes
    /// through and the program they run, the programs of a script handed to
    /// a shell inline, and the programs of a heredoc a shell reads as its
    /// input. The shell of a wrapper argv (`["bash", "-lc", "<script>"]`) is
    /// the harness's own and is not one of them. Empty when the command has
    /// no name in command position.
    pub programs: Vec<String>,
    /// When the scanner read the call's line.
    pub read_at: DateTime<Utc>,
    /// A time the transcript gave for this call was later than `read_at` and
    /// is not kept as given.
    pub time_bounded: bool,
    /// The line records a command that had already run (a Codex code-mode
    /// item): the moment the line was written does not date the command's
    /// start.
    pub recorded_after_run: bool,
}

impl ShellCall {
    /// The call carries a time the harness gave it: its line's, or a start
    /// the harness measured.
    pub fn has_own_time(&self) -> bool {
        self.at.is_some() || self.started_at.is_some()
    }

    /// Where the call sorts among a transcript's calls: its own time, else
    /// the start the harness measured, else its result, else the moment it
    /// was read. Never later than `read_at`.
    pub fn order_time(&self) -> DateTime<Utc> {
        self.at
            .or(self.started_at)
            .or(self.finished_at)
            .unwrap_or(self.read_at)
            .min(self.read_at)
    }
}

/// What a session's list of shell calls does not hold. A reader that asks
/// whether the session made a call at some instant reads these before it
/// reads the list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellCallGaps {
    /// Calls that sort before this instant ([`ShellCall::order_time`]) are
    /// not in the list: the session made more calls than are kept, or its
    /// calls were set aside while its transcript was not being written.
    /// `None`: no call was left out for either reason.
    pub calls_before: Option<DateTime<Utc>>,
    /// Part of the transcript was not read (a line longer than the scanner
    /// parses, a file larger than it reads, a subagent transcript it could
    /// not open): the lines written from `unread_from` (`None`: from the
    /// start of the file) to `unread_until`. `unread_until` is `None` when
    /// every line was read.
    pub unread_from: Option<DateTime<Utc>>,
    pub unread_until: Option<DateTime<Utc>>,
}

impl ShellCallGaps {
    /// Lines written between `from` (`None`: any time before) and `until`
    /// were not read.
    pub fn add_unread(&mut self, from: Option<DateTime<Utc>>, until: DateTime<Utc>) {
        self.unread_from = match (self.unread_until, self.unread_from, from) {
            // The first unread part sets the start; a later one can only
            // move it back.
            (None, _, from) => from,
            (Some(_), Some(known), Some(from)) => Some(known.min(from)),
            (Some(_), _, _) => None,
        };
        self.unread_until = Some(self.unread_until.map_or(until, |known| known.max(until)));
    }

    /// Calls that sort before `instant` were left out of the list.
    pub fn add_calls_before(&mut self, instant: DateTime<Utc>) {
        self.calls_before = Some(
            self.calls_before
                .map_or(instant, |known| known.max(instant)),
        );
    }

    /// What `other` does not hold is not held here either.
    pub fn merge(&mut self, other: &ShellCallGaps) {
        if let Some(instant) = other.calls_before {
            self.add_calls_before(instant);
        }
        if let Some(until) = other.unread_until {
            self.add_unread(other.unread_from, until);
        }
    }
}

/// Keep the `max_calls` calls that sort last, oldest first, a call that
/// appears twice once. When calls are left out, `gaps` says from which
/// instant the list is whole.
pub fn bound_shell_calls(calls: &mut Vec<ShellCall>, gaps: &mut ShellCallGaps, max_calls: usize) {
    calls.sort_by(|a, b| {
        (
            a.order_time(),
            a.at,
            a.started_at,
            a.finished_at,
            a.background,
            &a.programs,
        )
            .cmp(&(
                b.order_time(),
                b.at,
                b.started_at,
                b.finished_at,
                b.background,
                &b.programs,
            ))
    });
    // Two readings of one call are one call. A call without a time of its
    // own is told by its programs and its result alone.
    calls.dedup_by(|b, a| {
        (a.at, a.started_at, a.background, &a.programs)
            == (b.at, b.started_at, b.background, &b.programs)
            && (a.finished_at == b.finished_at || a.has_own_time())
    });
    if calls.len() > max_calls {
        let mut excess = calls.len() - max_calls;
        let mut boundary: Option<DateTime<Utc>> = None;
        // A call without a time of its own takes no place from a dated one.
        let mut index = 0;
        while excess > 0 && index < calls.len() {
            if calls[index].has_own_time() {
                index += 1;
            } else {
                let gone = calls.remove(index).order_time();
                boundary = Some(boundary.map_or(gone, |known| known.max(gone)));
                excess -= 1;
            }
        }
        if excess > 0 {
            // Every call left out sorts at or before the first one kept (the
            // last one left out when none is kept).
            let kept = calls
                .get(excess)
                .or(calls.last())
                .map(ShellCall::order_time);
            calls.drain(..excess);
            boundary = match (boundary, kept) {
                (Some(known), Some(kept)) => Some(known.max(kept)),
                (known, kept) => known.or(kept),
            };
        }
        if let Some(boundary) = boundary {
            gaps.add_calls_before(boundary);
        }
    }
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
    /// The file's shell calls, most recent last, at most `max_shell_calls`.
    shell_calls: Vec<(u64, ShellCall)>,
    next_shell_seq: u64,
    /// Shell calls waiting for their result: tool id -> (seq, the line
    /// count when the call was read).
    shell_pending: HashMap<String, (u64, u64)>,
    /// What `shell_calls` does not hold.
    shell_gaps: ShellCallGaps,
    /// Shell calls kept for this file (the published
    /// `session_binding_max_calls_per_transcript`).
    max_shell_calls: usize,
    /// The scan records shell calls. A collection's scan does not: it reads
    /// the launch facts only.
    record_shell_calls: bool,
    /// Lines a shell call waits for its result before the reader stops
    /// looking for it (the published `session_binding_result_wait_lines`).
    result_wait_lines: u64,
    /// A line of this transcript carried a time of its own. In such a
    /// transcript a line without one is not a turn record.
    timed_lines_seen: bool,
    /// The line being read is a turn record: its shell calls are recorded.
    line_is_turn_record: bool,
    /// Calls recorded from lines without a time while no line had shown one.
    untimed_calls: Vec<u64>,
    /// What the line being read changed: results that came back, calls that
    /// stopped waiting for one, calls taken back.
    shell_finished: Vec<u64>,
    shell_gave_up: Vec<u64>,
    shell_withdrawn: Vec<u64>,
    /// The moment this line is read.
    read_at: DateTime<Utc>,
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

/// What reading one line changed in a [`ShellCallReader`]'s list. A number
/// is the reader's own for a call: one per call, in the order they were read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShellCallLineEvents {
    /// Calls the line carries.
    pub started: Vec<u64>,
    /// Calls whose result the line carries.
    pub finished: Vec<u64>,
    /// Calls that stopped waiting for their result.
    pub gave_up: Vec<u64>,
    /// Calls read from lines without a time before the transcript showed
    /// that its lines carry one: they were not turn records, and are no
    /// longer in the list.
    pub withdrawn: Vec<u64>,
}

/// The shell calls of one transcript, read from its lines as they are handed
/// over, oldest first. It is the extractor of the launch scan without the
/// file: a reader that follows a transcript keeps one per file and hands it
/// each complete line with the moment it read it. No collection uses it.
///
/// It keeps what [`ShellCall`] keeps (times, a background flag, program
/// names) and nothing else of a line.
#[derive(Debug, Clone)]
pub struct ShellCallReader {
    scan: FileScan,
}

impl Default for ShellCallReader {
    fn default() -> Self {
        Self::new()
    }
}

impl ShellCallReader {
    /// A reader under the published limits (`cve-detection-params`:
    /// `session_binding_max_calls_per_transcript`,
    /// `session_binding_result_wait_lines`).
    pub fn new() -> Self {
        Self::with_limits(
            usize::try_from(crate::vuln_detector_params::session_binding_max_calls_per_transcript())
                .unwrap_or(usize::MAX),
            crate::vuln_detector_params::session_binding_result_wait_lines(),
        )
    }

    /// A reader that keeps `max_calls` calls and lets a call wait
    /// `result_wait_lines` lines for its result.
    pub fn with_limits(max_calls: usize, result_wait_lines: u64) -> Self {
        Self {
            scan: FileScan {
                record_shell_calls: true,
                max_shell_calls: max_calls,
                result_wait_lines,
                ..FileScan::default()
            },
        }
    }

    /// Read one complete line, read at `read_at`.
    pub fn read_line(&mut self, line: &[u8], read_at: DateTime<Utc>) -> ShellCallLineEvents {
        let params = agent_visibility_params::workspace_attribution();
        let scan = &mut self.scan;
        scan.read_at = read_at;
        scan.lines_seen += 1;
        let first = scan.next_shell_seq;
        process_line(line, scan, &params.workspace_attribution);
        ShellCallLineEvents {
            started: (first..scan.next_shell_seq).collect(),
            finished: std::mem::take(&mut scan.shell_finished),
            gave_up: std::mem::take(&mut scan.shell_gave_up),
            withdrawn: std::mem::take(&mut scan.shell_withdrawn),
        }
    }

    /// A part of the transcript was not handed over (a line longer than the
    /// reader parses, bytes it skipped): what was written between `from`
    /// (`None`: any time before) and `until`.
    pub fn note_unread(&mut self, from: Option<DateTime<Utc>>, until: DateTime<Utc>) {
        self.scan.shell_gaps.add_unread(from, until);
    }

    /// The calls kept, oldest first, each with its number.
    pub fn calls(&self) -> impl Iterator<Item = (u64, &ShellCall)> {
        self.scan.shell_calls.iter().map(|(seq, call)| (*seq, call))
    }

    /// The call numbered `number`, while the list keeps it.
    pub fn call(&self, number: u64) -> Option<&ShellCall> {
        self.calls()
            .find(|(seq, _)| *seq == number)
            .map(|(_, call)| call)
    }

    /// What the list does not hold.
    pub fn gaps(&self) -> &ShellCallGaps {
        &self.scan.shell_gaps
    }

    /// A program, not a person, started the session
    /// ([`SessionLaunchContext::headless`]). `None` until the lines that say
    /// how the session started were read.
    pub fn headless(&self) -> Option<bool> {
        self.scan
            .context_settled
            .then_some(self.scan.context.headless)
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
/// `"tool_use_id"`, `"function_call_output"` and `"toolCallId"` out).
const CALL_LINE_MARKERS: &[&str] = &[
    "\"tool_use\"",
    "\"function_call\"",
    "\"custom_tool_call\"",
    "\"local_shell_call\"",
];
/// Marker of a line carrying OpenClaw's call block, which is read for its
/// shell command only: a scan that records no shell call does not look for
/// it.
const SHELL_CALL_ONLY_LINE_MARKER: &str = "\"toolCall\"";
/// Markers of a line carrying a tool result. `toolResult` is the role of an
/// OpenClaw result message.
const RESULT_LINE_MARKERS: &[&str] = &[
    "\"tool_result\"",
    "\"function_call_output\"",
    "\"custom_tool_call_output\"",
    "\"toolResult\"",
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
    let has_call = CALL_LINE_MARKERS.iter().any(|m| text.contains(m))
        || (scan.record_shell_calls && text.contains(SHELL_CALL_ONLY_LINE_MARKER));
    // A shell call stops waiting for its result after the published number
    // of lines. Its end is then not known: what the transcript says from its
    // line on is a part the list does not vouch for.
    if !scan.shell_pending.is_empty() {
        let (lines_seen, wait) = (scan.lines_seen, scan.result_wait_lines);
        let gave_up: Vec<u64> = scan
            .shell_pending
            .values()
            .filter(|(_, read_on_line)| lines_seen.saturating_sub(*read_on_line) > wait)
            .map(|(seq, _)| *seq)
            .collect();
        if !gave_up.is_empty() {
            scan.shell_pending
                .retain(|_, (seq, _)| !gave_up.contains(seq));
            let since = scan
                .shell_calls
                .iter()
                .filter(|(seq, _)| gave_up.contains(seq))
                .map(|(_, call)| call.order_time())
                .min();
            scan.shell_gaps.add_unread(since, scan.read_at);
            scan.shell_gave_up.extend(gave_up);
        }
    }
    // Result lines (often large tool output) are parsed only while a call
    // waits for one: a foreground launch, or a shell call whose id the line
    // carries.
    let has_result = RESULT_LINE_MARKERS.iter().any(|m| text.contains(m))
        && (!scan.pending.is_empty()
            || scan
                .shell_pending
                .keys()
                .any(|id| text.contains(id.as_str())));
    let has_code_mode_item = text.contains(CODE_MODE_LINE_MARKER)
        && CODE_MODE_ITEM_MARKERS.iter().any(|m| text.contains(m));
    if !wants_context && !has_call && !has_result && !has_code_mode_item {
        return;
    }
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let line_ts = line_timestamp(&value);
    if scan.record_shell_calls {
        // A turn record carries a time of its own wherever the transcript's
        // lines do. A line without one in such a transcript is something
        // else (a logged request that repeats an earlier message): no shell
        // call is read from it, and the ones read from such lines before the
        // transcript showed a time are taken back.
        if line_ts.is_some() && !scan.timed_lines_seen {
            scan.timed_lines_seen = true;
            let untimed = std::mem::take(&mut scan.untimed_calls);
            if !untimed.is_empty() {
                scan.shell_calls.retain(|(seq, _)| !untimed.contains(seq));
                scan.shell_pending
                    .retain(|_, (seq, _)| !untimed.contains(seq));
                scan.shell_withdrawn.extend(untimed);
            }
        }
        scan.line_is_turn_record = line_ts.is_some() || !scan.timed_lines_seen;
    }
    if wants_context {
        absorb_context(&value, line_ts, scan, vocab);
    }
    if has_code_mode_item {
        if let Some(item) = super::parsing::codex_completed_item(&value) {
            absorb_code_mode_item(item, &value, line_ts, scan, vocab);
        }
    }
    if has_result {
        if let Some(id) = message_result_id(&value) {
            settle_result(&id, line_ts, scan);
        }
    }
    for block in structured_blocks(&value) {
        match block_kind(block) {
            BlockKind::Call => absorb_tool_call(block, &value, line_ts, scan, vocab),
            BlockKind::ShellCallOnly => absorb_shell_call_block(block, line_ts, scan, vocab),
            BlockKind::Result => {
                if let Some(id) = result_id(block) {
                    settle_result(&id, line_ts, scan);
                }
            }
            BlockKind::Other => {}
        }
    }
}

/// The result of call `id` came back on a line stamped `line_ts`: the launch
/// and the shell call waiting for it are finished.
fn settle_result(id: &str, line_ts: Option<DateTime<Utc>>, scan: &mut FileScan) {
    if let Some(seq) = scan.pending.remove(id) {
        if let Some((_, call)) = scan.launches.iter_mut().find(|(s, _)| *s == seq) {
            call.finished_at = line_ts.or(call.at);
        }
    }
    if let Some((seq, _)) = scan.shell_pending.remove(id) {
        scan.shell_finished.push(seq);
        let read_at = scan.read_at;
        if let Some((_, call)) = scan.shell_calls.iter_mut().find(|(s, _)| *s == seq) {
            let (finished_at, bounded) = not_after(line_ts, read_at);
            call.finished_at = finished_at.or(call.at);
            call.time_bounded |= bounded;
        }
    }
}

/// `time`, or the read time when `time` is later than it, and whether it was.
fn not_after(time: Option<DateTime<Utc>>, read_at: DateTime<Utc>) -> (Option<DateTime<Utc>>, bool) {
    match time {
        Some(time) if time > read_at => (Some(read_at), true),
        other => (other, false),
    }
}

/// The call a result line answers when the result is a message of its own
/// rather than a block (OpenClaw: `message.role == "toolResult"`, the call's
/// id in `message.toolCallId`).
fn message_result_id(value: &Value) -> Option<String> {
    let message = value.get("message")?;
    if message.get("role").and_then(|v| v.as_str()) != Some("toolResult") {
        return None;
    }
    message
        .get("toolCallId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
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
    /// A call read for its shell command only (OpenClaw's `toolCall`).
    ShellCallOnly,
    Result,
    Other,
}

/// The structured blocks of a line: `message.content[]` (Anthropic blocks for
/// Claude Code and Cursor, OpenClaw's `toolCall` blocks), a Codex `payload`,
/// or the line itself (older rollouts).
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
        "toolCall" => BlockKind::ShellCallOnly,
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
/// (a JSON string), OpenClaw `arguments` (an object) or `action`
/// (`local_shell_call`).
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
            line_at: line_ts,
            measured_start: None,
            finished_at: None,
            after_run: false,
        },
        scan,
        vocab,
    );
}

/// A call block read for its shell command only: the times and program names
/// of a [`ShellCall`]. It is not read as a launch and writes no script.
fn absorb_shell_call_block(
    block: &Value,
    line_ts: Option<DateTime<Utc>>,
    scan: &mut FileScan,
    vocab: &WorkspaceAttributionJSON,
) {
    if !scan.record_shell_calls {
        return;
    }
    let Some(args) = call_arguments(block) else {
        return;
    };
    let Some(command) = command_text(&args, vocab) else {
        return;
    };
    let cmd = ShellCommand {
        command: &command,
        shell_cwd: "",
        args: &args,
        id: block_id(block),
        at: line_ts,
        line_at: line_ts,
        measured_start: None,
        finished_at: None,
        after_run: false,
    };
    let lexed = lex_shell(cmd.command);
    let background = runs_in_background(&lexed, cmd.args, vocab);
    record_shell_call(&lexed, &cmd, background, scan, vocab);
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
    /// When the call was made, as a launch reads it: the line's timestamp,
    /// or the measured start of a Codex code-mode command.
    at: Option<DateTime<Utc>>,
    /// Timestamp of the line that carries the call. `None` when the line
    /// records a command that already ran (Codex code mode).
    line_at: Option<DateTime<Utc>>,
    /// The command's start as the harness measured it (Codex code mode).
    measured_start: Option<DateTime<Utc>>,
    /// When the command's result is already known: a Codex code-mode item
    /// is recorded once the command has finished.
    finished_at: Option<DateTime<Utc>>,
    /// The line records a command that had already run (a Codex code-mode
    /// item).
    after_run: bool,
}

/// Record `cmd` as a shell call, and as a launch call when it starts an agent
/// CLI, directly or through a script this transcript wrote.
fn absorb_shell_command(
    cmd: ShellCommand<'_>,
    scan: &mut FileScan,
    vocab: &WorkspaceAttributionJSON,
) {
    let lexed = lex_shell(cmd.command);
    let background = runs_in_background(&lexed, cmd.args, vocab);
    record_shell_call(&lexed, &cmd, background, scan, vocab);
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

/// The call returns before its work finishes: a trailing `&`, a detaching
/// program, a background flag or a zero wait among its arguments.
fn runs_in_background(lexed: &Lexed, args: &Value, vocab: &WorkspaceAttributionJSON) -> bool {
    lexed.background
        || lexed.commands.iter().any(|words| detaches(words, vocab))
        || vocab
            .background_flag_keys
            .iter()
            .any(|k| args.get(k.as_str()).and_then(|v| v.as_bool()) == Some(true))
        || vocab
            .background_wait_keys
            .iter()
            .any(|k| args.get(k.as_str()).and_then(|v| v.as_u64()) == Some(0))
}

/// Record the shell call `cmd` made: its times and the names of the programs
/// it runs. Every call is recorded, also one whose command has no name in
/// command position (its `programs` is then empty). A time later than the
/// read time is not kept as given: the call's own time and measured start
/// are dropped, its result time becomes the read time.
fn record_shell_call(
    lexed: &Lexed,
    cmd: &ShellCommand<'_>,
    background: bool,
    scan: &mut FileScan,
    vocab: &WorkspaceAttributionJSON,
) {
    if !scan.record_shell_calls || !scan.line_is_turn_record {
        return;
    }
    let mut programs = Vec::new();
    collect_command_programs(lexed, vocab, 0, &mut programs);
    let read_at = scan.read_at;
    let mut time_bounded = false;
    let mut earlier = |time: Option<DateTime<Utc>>| match time {
        Some(time) if time > read_at => {
            time_bounded = true;
            None
        }
        other => other,
    };
    let at = earlier(cmd.line_at);
    let started_at = earlier(cmd.measured_start);
    let (finished_at, bounded) = not_after(cmd.finished_at, read_at);
    time_bounded |= bounded;
    let seq = scan.next_shell_seq;
    scan.next_shell_seq += 1;
    if finished_at.is_none() {
        if let Some(id) = cmd.id.clone() {
            scan.shell_pending.insert(id, (seq, scan.lines_seen));
        }
    }
    // A call line without a time, read before the transcript showed one.
    if cmd.line_at.is_none() && !cmd.after_run && !scan.timed_lines_seen {
        scan.untimed_calls.push(seq);
        if scan.untimed_calls.len() > scan.max_shell_calls.max(1) {
            scan.untimed_calls.remove(0);
        }
    }
    scan.shell_calls.push((
        seq,
        ShellCall {
            at,
            started_at,
            finished_at,
            background,
            programs,
            read_at,
            time_bounded,
            recorded_after_run: cmd.after_run,
        },
    ));
    if scan.shell_calls.len() > scan.max_shell_calls {
        // A call without a time of its own takes no place from a dated one.
        let index = scan
            .shell_calls
            .iter()
            .position(|(_, call)| !call.has_own_time())
            .unwrap_or(0);
        let (dropped, gone) = scan.shell_calls.remove(index);
        scan.shell_pending.retain(|_, (s, _)| *s != dropped);
        // The call left out sorts at or before the oldest one kept.
        let boundary = scan
            .shell_calls
            .first()
            .map(|(_, call)| call.order_time())
            .unwrap_or(read_at)
            .max(gone.order_time());
        scan.shell_gaps.add_calls_before(boundary);
    }
}

/// A program name as a shell call keeps it: a plain file name. A word that
/// is not one (a variable, a substitution, a quoted sentence) names no
/// program the kernel could report.
fn plain_program_name(name: &str) -> Option<String> {
    let plain = !name.is_empty()
        && name.chars().count() <= MAX_PROGRAM_NAME_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        && name.chars().any(|c| c.is_ascii_alphanumeric());
    plain.then(|| name.to_string())
}

/// The names of the programs `lexed` runs, appended to `out` in order of
/// first appearance: for each simple command the wrappers it goes through
/// and the program they run (`sudo -u x git push`: `sudo`, `git`), the
/// programs of a script handed to a shell inline (`bash -lc '<script>'`,
/// `pwsh -Command '<script>'`), and the programs of a heredoc that is the
/// input of a shell reading its commands from it (`bash <<EOF`,
/// `sh -s <<EOF`). A heredoc that is the input of any other command is that
/// command's data and gives no name. Names are basenames, lower-cased,
/// without a launcher extension.
fn collect_command_programs(
    lexed: &Lexed,
    vocab: &WorkspaceAttributionJSON,
    depth: usize,
    out: &mut Vec<String>,
) {
    let push = |name: &str, out: &mut Vec<String>| {
        if let Some(name) = plain_program_name(name) {
            if !out.contains(&name) && out.len() < MAX_PROGRAMS_PER_CALL {
                out.push(name);
            }
        }
    };
    for (position, words) in lexed.commands.iter().enumerate() {
        let Some(index) = command_word_index(words, vocab) else {
            continue;
        };
        for word in &words[..index] {
            let name = exe_basename(word, vocab);
            if vocab.wrapper_programs.contains(&name) {
                push(&name, out);
            }
        }
        let name = exe_basename(&words[index], vocab);
        push(&name, out);
        if !is_shell(&name, vocab) || depth >= MAX_INLINE_SCRIPT_DEPTH {
            continue;
        }
        let rest = &words[index + 1..];
        if let Some(script) = shell_inline_script(&name, rest, vocab) {
            collect_command_programs(&lex_shell(script), vocab, depth + 1, out);
        } else if shell_reads_commands_from_input(rest) {
            for (body, command) in lexed.heredocs.iter().zip(&lexed.heredoc_commands) {
                if *command == Some(position) {
                    collect_command_programs(&lex_shell(body), vocab, depth + 1, out);
                }
            }
        }
    }
}

/// A shell given these words after its name reads its commands from its
/// input: it is given no script file. `-s` says so explicitly, and what
/// follows it are the script's arguments.
fn shell_reads_commands_from_input(rest: &[String]) -> bool {
    for word in rest {
        if !word.starts_with('-') || word == "-" {
            return word == "-";
        }
        if !word.starts_with("--") && word[1..].contains('s') {
            return true;
        }
    }
    true
}

/// The script a shell is handed inline: the word after `-c` (a POSIX
/// short-option cluster carrying `c`) or after one of PowerShell's script
/// options. `rest` are the words after the shell `name`. `None` when the
/// shell runs a file or reads its input.
fn shell_inline_script<'a>(
    name: &str,
    rest: &'a [String],
    vocab: &WorkspaceAttributionJSON,
) -> Option<&'a String> {
    let powershell = vocab.powershell_programs.iter().any(|p| p == name);
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
            return rest.get(k + 1);
        }
        k += 1;
    }
    None
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
                    // The item is recorded once the command has finished:
                    // its line is the completion, not the call.
                    line_at: None,
                    measured_start: started,
                    finished_at: completed.or(line_ts),
                    after_run: true,
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
// The words of a command that act on this host
// ---------------------------------------------------------------------------

/// The words of a shell `command` that act on this host: the words of every
/// simple command, its redirection targets and heredoc bodies, except the
/// remote command of a remote-shell call (`ssh [options] host <command>`,
/// the params' `transcript_hints.remote_shell_programs`). The remote command
/// runs on the remote host, so a path it names is that host's file, not one
/// of this host's (`ssh build 'cat ~/.aws/config'` reads the remote copy).
/// The destination word is kept (it names a host, not a path), and so are
/// the options before it (`-i ~/.ssh/key` is a local file). Wrappers and
/// assignments are skipped as for the launch recognizer (`sudo ssh host
/// ...`). A heredoc cannot be tied to its command by the lexer and stays in
/// the result, as before.
pub fn local_command_words(command: &str) -> Vec<String> {
    let params = agent_visibility_params::params();
    let vocab = &params.workspace_attribution;
    let shells = &params.transcript_hints.remote_shell_programs;
    let lexed = lex_shell(command);
    let mut out = Vec::new();
    for words in &lexed.commands {
        let keep = command_word_index(words, vocab)
            .and_then(|index| remote_command_start(words, index, vocab, shells))
            .unwrap_or(words.len());
        out.extend(words[..keep].iter().cloned());
    }
    out.extend(lexed.redirect_targets);
    out.extend(lexed.heredocs);
    out
}

/// The index of the first word of a remote-shell call's remote command: the
/// word after the destination, the options before it skipped (an option the
/// params list takes the next word as its value). `None` when
/// `words[command]` is not a remote shell, or the call names no remote
/// command (an interactive login).
fn remote_command_start(
    words: &[String],
    command: usize,
    vocab: &WorkspaceAttributionJSON,
    shells: &[ProgramOptionsJSON],
) -> Option<usize> {
    let program = exe_basename(&words[command], vocab);
    let shell = shells.iter().find(|shell| shell.program == program)?;
    let mut i = command + 1;
    while i < words.len() {
        let word = &words[i];
        if word == "--" {
            i += 1;
            break;
        }
        if !word.starts_with('-') || word == "-" {
            break;
        }
        i += if shell.options.iter().any(|option| option == word) {
            2
        } else {
            1
        };
    }
    // `words[i]` is the destination.
    let start = i + 1;
    (start < words.len()).then_some(start)
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
    /// For each heredoc, the index in `commands` of the simple command whose
    /// input it is. `None` when that command has no word.
    heredoc_commands: Vec<Option<usize>>,
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
        /// Heredocs opened on the current line: (delimiter, strip tabs, the
        /// index its command takes in `commands`).
        heredocs_open: Vec<(String, bool, usize)>,
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
                        // The command the redirection belongs to is the one
                        // being read: it is pushed when it ends.
                        let command = self.out.commands.len();
                        self.heredocs_open.push((word, strip_tabs, command));
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
                for (delimiter, strip_tabs, command) in std::mem::take(&mut lx.heredocs_open) {
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
                    // The line has ended, so the command is in `commands`
                    // unless it had no word.
                    lx.out
                        .heredoc_commands
                        .push((command < lx.out.commands.len()).then_some(command));
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
        return shell_inline_script(&name, rest, vocab)
            .map(|script| {
                lex_shell(script)
                    .commands
                    .iter()
                    .any(|c| starts_agent_cli(c, vocab))
            })
            .unwrap_or(false);
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

    /// The remote command of an ssh call is the remote host's, its options
    /// and anything outside it are this host's.
    #[test]
    #[serial_test::serial]
    fn local_command_words_leave_out_the_remote_command() {
        let has = |words: &[String], w: &str| words.iter().any(|x| x.contains(w));
        let words = local_command_words(
            "ssh -o ConnectTimeout=15 -i ~/.ssh/lab_key me@lab-host 'ls -la ~/.aws/config'",
        );
        assert!(
            has(&words, "~/.ssh/lab_key"),
            "a local option value: {words:?}"
        );
        assert!(has(&words, "me@lab-host"), "{words:?}");
        assert!(!has(&words, "~/.aws/config"), "remote: {words:?}");

        let words = local_command_words("ssh lab-host 'cat ~/.aws/config'; cat ~/.aws/credentials");
        assert!(!has(&words, "~/.aws/config"), "{words:?}");
        assert!(
            has(&words, "~/.aws/credentials"),
            "a local command after it: {words:?}"
        );

        let words =
            local_command_words("cat ~/.aws/config | sudo ssh -p 2222 lab-host 'cat > /tmp/x'");
        assert!(has(&words, "~/.aws/config"), "piped from here: {words:?}");
        assert!(!has(&words, "/tmp/x"), "{words:?}");

        // An unquoted redirection is applied by this shell.
        let words = local_command_words("ssh lab-host uptime > ~/.ssh/uptime.log");
        assert!(has(&words, "~/.ssh/uptime.log"), "{words:?}");
        assert!(
            !words.iter().any(|w| w == "uptime"),
            "the remote command: {words:?}"
        );

        // Not a remote shell, and an interactive login, keep every word.
        let words = local_command_words("cat ~/.aws/config");
        assert!(has(&words, "~/.aws/config"));
        assert_eq!(local_command_words("ssh lab-host"), vec!["ssh", "lab-host"]);
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

    /// The limits the tests read under (the published defaults).
    const TEST_MAX_CALLS: usize = 64;
    const TEST_RESULT_WAIT_LINES: u64 = 2048;

    fn feed(scan: &mut FileScan, lines: &[serde_json::Value]) {
        let p = vocab();
        scan.read_at = Utc::now();
        scan.record_shell_calls = true;
        scan.result_wait_lines = TEST_RESULT_WAIT_LINES;
        if scan.max_shell_calls == 0 {
            scan.max_shell_calls = TEST_MAX_CALLS;
        }
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
        let scan =
            scan_file(&path, &p.workspace_attribution, &p.signature).expect("scan");
        assert_eq!(scan.offset, first.len() as u64);
        assert!(scan.launches.is_empty());
        // The rest of the line lands: the next scan picks it up from the offset.
        let mut all = first.clone();
        all.extend_from_slice(&call);
        std::fs::write(&path, &all).unwrap();
        let scan =
            scan_file(&path, &p.workspace_attribution, &p.signature).expect("scan");
        assert_eq!(scan.offset, all.len() as u64);
        assert_eq!(scan.launches.len(), 1);
        assert!(scan.launches[0].1.background);
        // State computed under other params is recomputed, not reused.
        let rescan = scan_file(
            &path,
            &p.workspace_attribution,
            "another-signature",
        )
        .expect("scan");
        assert_eq!(rescan.launches.len(), 1);
        assert_eq!(rescan.params_signature, "another-signature");
    }

    fn shell_calls(scan: &FileScan) -> Vec<&ShellCall> {
        scan.shell_calls.iter().map(|(_, call)| call).collect()
    }

    fn rfc3339(at: Option<DateTime<Utc>>) -> Option<String> {
        at.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    }

    fn names(call: &ShellCall) -> Vec<&str> {
        call.programs.iter().map(String::as_str).collect()
    }

    fn programs_of(command: &str) -> Vec<String> {
        let p = vocab();
        let mut out = Vec::new();
        collect_command_programs(&lex_shell(command), &p.workspace_attribution, 0, &mut out);
        out
    }

    /// The programs of a command are the names in command position: the
    /// wrappers a command goes through, the program they run, and the
    /// programs of a script handed to a shell. Arguments, options, paths,
    /// assignments and variables are not names.
    #[test]
    fn shell_call_programs_are_the_names_in_command_position() {
        assert_eq!(
            programs_of("cd /srv/app && TOKEN=abc123 git push origin main 2>&1 | tail -3"),
            vec!["cd", "git", "tail"]
        );
        assert_eq!(
            programs_of("sudo -u deploy /usr/local/bin/kubectl apply -f x.yaml"),
            vec!["sudo", "kubectl"]
        );
        assert_eq!(
            programs_of("timeout 900 env FOO=1 cargo build"),
            vec!["timeout", "env", "cargo"]
        );
        assert_eq!(
            programs_of(r#"bash -lc "cd /tmp/y && npm test""#),
            vec!["bash", "cd", "npm"]
        );
        assert_eq!(
            programs_of(r#"pwsh -NoProfile -Command "Invoke-RestMethod https://example.org""#),
            vec!["pwsh", "invoke-restmethod"]
        );
        assert_eq!(
            programs_of(r"C:\Users\me\venv\Scripts\python.exe -m pip install requests"),
            vec!["python"]
        );
        assert_eq!(programs_of("cmd /c dir C:\\Users"), vec!["cmd", "dir"]);
        // A heredoc is read as a script when it is the input of a shell that
        // reads its commands from it.
        assert_eq!(
            programs_of("bash <<'EOF'\ncurl -s https://example.org\nEOF"),
            vec!["bash", "curl"]
        );
        assert_eq!(
            programs_of("sh -s -- stable <<'EOF'\ntar xzf pkg.tgz\nEOF"),
            vec!["sh", "tar"]
        );
        // The input of any other command is that command's data: of an
        // interpreter, of a program writing a file, of a program a shell
        // reads through a pipe, of a shell that runs a script file.
        assert_eq!(
            programs_of("python3 - <<'EOF'\nimport os\nprint(os.getcwd())\nEOF"),
            vec!["python3"]
        );
        assert_eq!(
            programs_of("cat > token <<EOF\n0123456789abcdef0123456789abcdef\nEOF\nsh install.sh"),
            vec!["cat", "sh"]
        );
        assert_eq!(
            programs_of("cat <<EOF | sh\nmake install\nEOF"),
            vec!["cat", "sh"]
        );
        assert_eq!(
            programs_of("bash deploy.sh <<EOF\nproduction\nEOF"),
            vec!["bash"]
        );
        // No program: assignments only, a lookup, a variable as the command.
        assert!(programs_of("FOO=1 BAR=2").is_empty());
        assert!(programs_of("command -v claude").is_empty());
        assert!(programs_of("\"$TOOL\" --version").is_empty());
    }

    /// Claude Code: every Bash call is a shell call dated by its line, its
    /// result read by id; a tool that runs no command is not one. Only names
    /// are kept.
    #[test]
    fn claude_code_shell_calls_keep_times_and_program_names_only() {
        let mut scan = FileScan::default();
        feed(
            &mut scan,
            &[
                serde_json::json!({"type":"user","timestamp":"2026-11-08T10:00:00.000Z","cwd":"/Users/me/p","entrypoint":"cli","message":{"content":"ship it"}}),
                serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:05.120Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"cd /Users/me/p && TOKEN=abc123 git push origin main 2>&1 | tail -3"}}]}}),
                serde_json::json!({"type":"user","timestamp":"2026-11-08T10:00:09.480Z","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"Everything up-to-date"}]}}),
                serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:12.000Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"t2","name":"Read","input":{"file_path":"/Users/me/p/Cargo.toml"}}]}}),
                serde_json::json!({"type":"user","timestamp":"2026-11-08T10:00:12.100Z","message":{"content":[{"type":"tool_result","tool_use_id":"t2","content":"[package]"}]}}),
                serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:20.000Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"t3","name":"Bash","input":{"command":"./server --port 8080","run_in_background":true}}]}}),
                serde_json::json!({"type":"user","timestamp":"2026-11-08T10:00:20.300Z","message":{"content":[{"type":"tool_result","tool_use_id":"t3","content":"Command running in background"}]}}),
            ],
        );
        let calls = shell_calls(&scan);
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(names(calls[0]), vec!["cd", "git", "tail"]);
        assert_eq!(
            rfc3339(calls[0].at),
            Some("2026-11-08T10:00:05.120Z".to_string())
        );
        assert_eq!(
            rfc3339(calls[0].finished_at),
            Some("2026-11-08T10:00:09.480Z".to_string())
        );
        assert_eq!(calls[0].started_at, None);
        assert!(!calls[0].background);
        // A background call's result still bounds when its process started.
        assert_eq!(names(calls[1]), vec!["server"]);
        assert!(calls[1].background);
        assert_eq!(
            rfc3339(calls[1].finished_at),
            Some("2026-11-08T10:00:20.300Z".to_string())
        );
        assert!(scan.shell_pending.is_empty());
        // Neither is a launch.
        assert!(scan.launches.is_empty());
        let stored = serde_json::to_string(&calls).unwrap();
        for text in ["abc123", "origin", "8080", "/Users/me", "TOKEN"] {
            assert!(!stored.contains(text), "{text} in {stored}");
        }
    }

    /// A command with no name in command position is a shell call too, with
    /// no program.
    #[test]
    fn a_command_without_a_program_name_is_recorded_with_none() {
        let mut scan = FileScan::default();
        feed(
            &mut scan,
            &[
                serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:05.000Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"\"$TOOL\" --version"}}]}}),
                serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:06.000Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"FOO=1 BAR=2"}}]}}),
            ],
        );
        let calls = shell_calls(&scan);
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(calls.iter().all(|call| call.programs.is_empty()));
        assert_eq!(
            rfc3339(calls[0].at),
            Some("2026-11-08T10:00:05.000Z".to_string())
        );
    }

    /// Codex: a function call carries the time of its line and the time of
    /// its output; the shell of a wrapper argv is not one of its programs. A
    /// code-mode command is recorded once it has finished: it carries the
    /// start the harness measured when there is one, and no time of its own.
    #[test]
    fn codex_shell_calls_carry_the_line_time_or_the_measured_start() {
        let mut calls_mode = FileScan::default();
        feed(
            &mut calls_mode,
            &[
                serde_json::json!({"timestamp":"2026-11-08T10:00:00Z","type":"session_meta","payload":{"cwd":"/home/me/app","originator":"codex_cli_rs"}}),
                serde_json::json!({"timestamp":"2026-11-08T10:01:00.250Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"c1","arguments":"{\"cmd\":\"cargo test -p core\",\"workdir\":\"/home/me/app\"}"}}),
                serde_json::json!({"timestamp":"2026-11-08T10:01:42.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"ok"}}),
                serde_json::json!({"timestamp":"2026-11-08T10:02:00.000Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c2","arguments":"{\"command\":[\"bash\",\"-lc\",\"npm test && node scripts/report.js\"]}"}}),
            ],
        );
        let calls = shell_calls(&calls_mode);
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(names(calls[0]), vec!["cargo"]);
        assert_eq!(
            rfc3339(calls[0].at),
            Some("2026-11-08T10:01:00.250Z".to_string())
        );
        assert_eq!(
            rfc3339(calls[0].finished_at),
            Some("2026-11-08T10:01:42.000Z".to_string())
        );
        assert_eq!(names(calls[1]), vec!["npm", "node"]);
        assert_eq!(calls[1].finished_at, None);
        assert_eq!(calls_mode.shell_pending.len(), 1);

        let mut code_mode = FileScan::default();
        feed(
            &mut code_mode,
            &[
                serde_json::json!({"timestamp":"2026-10-06T00:01:26Z","type":"session_meta","payload":{"cwd":"/Users/runner/ws","originator":"codex_exec","source":"exec"}}),
                // The script the model wrote is not what ran.
                serde_json::json!({"timestamp":"2026-10-06T00:01:34.420Z","type":"response_item","payload":{"type":"custom_tool_call","call_id":"call_1","name":"exec","input":"text(await tools.exec_command({cmd:\"python3 -m unittest discover -s tests\"}));\n"}}),
                serde_json::json!({"timestamp":"2026-10-06T00:01:34.672Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-8a98f9cf","process_id":"26973","command":["/bin/bash","-lc","python3 -m unittest discover -s tests"],"cwd":"file:///Users/runner/ws","status":"completed","exit_code":0},"started_at_ms":1_791_244_894_594_i64,"completed_at_ms":1_791_244_894_672_i64}}),
                // No measured start on the line: only the completion is known.
                serde_json::json!({"timestamp":"2026-10-06T00:02:00.000Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-2","command":["/bin/bash","-lc","git status"],"cwd":"file:///Users/runner/ws","status":"completed","exit_code":0}}}),
            ],
        );
        let calls = shell_calls(&code_mode);
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(names(calls[0]), vec!["python3"]);
        assert_eq!(calls[0].at, None);
        assert_eq!(
            calls[0].started_at.map(|t| t.timestamp_millis()),
            Some(1_791_244_894_594)
        );
        assert_eq!(
            calls[0].finished_at.map(|t| t.timestamp_millis()),
            Some(1_791_244_894_672)
        );
        assert_eq!(names(calls[1]), vec!["git"]);
        assert_eq!((calls[1].at, calls[1].started_at), (None, None));
        assert_eq!(
            rfc3339(calls[1].finished_at),
            Some("2026-10-06T00:02:00.000Z".to_string())
        );
        assert!(code_mode.shell_pending.is_empty());
        // The launch recognizer reads the same items as before.
        assert!(code_mode.launches.is_empty());
    }

    /// OpenClaw writes `toolCall` blocks with the arguments as an object,
    /// and a result as a message of its own that names the call. The blocks
    /// are read for their shell calls; the launch facts of such a transcript
    /// are what they were.
    #[test]
    fn openclaw_tool_call_blocks_are_shell_calls() {
        let mut scan = FileScan::default();
        feed(
            &mut scan,
            &[
                serde_json::json!({"type":"message","id":"m1","parentId":null,"timestamp":"2026-11-08T10:00:00.250Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"call_1","name":"exec","arguments":{"command":"git -C /srv/app status","workdir":"/srv/app","timeout":30,"yieldMs":10000}}],"timestamp":1_794_132_000_250_i64}}),
                serde_json::json!({"type":"message","id":"m2","parentId":"m1","timestamp":"2026-11-08T10:00:01.900Z","message":{"role":"toolResult","toolCallId":"call_1","toolName":"exec","content":[{"type":"text","text":"On branch main"}],"isError":false,"timestamp":1_794_132_001_900_i64}}),
                serde_json::json!({"type":"message","id":"m3","parentId":"m2","timestamp":"2026-11-08T10:00:03.000Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"call_2","name":"read","arguments":{"path":"/srv/app/README.md"}}],"timestamp":1_794_132_003_000_i64}}),
                serde_json::json!({"type":"message","id":"m4","parentId":"m3","timestamp":"2026-11-08T10:00:05.000Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"call_3","name":"exec","arguments":{"command":"claude -p 'summarize the diff'","workdir":"/srv/app"}}],"timestamp":1_794_132_005_000_i64}}),
            ],
        );
        let calls = shell_calls(&scan);
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(names(calls[0]), vec!["git"]);
        assert_eq!(
            rfc3339(calls[0].at),
            Some("2026-11-08T10:00:00.250Z".to_string())
        );
        assert_eq!(
            rfc3339(calls[0].finished_at),
            Some("2026-11-08T10:00:01.900Z".to_string())
        );
        assert_eq!(names(calls[1]), vec!["claude"]);
        assert!(scan.launches.is_empty(), "{:?}", scan.launches);
        assert!(scan.agent_scripts.is_empty());
    }

    /// A line without a time gives a call without one (Cursor).
    #[test]
    fn shell_calls_of_lines_without_a_time_carry_none() {
        let mut scan = FileScan::default();
        feed(
            &mut scan,
            &[
                serde_json::json!({"role":"assistant","message":{"content":[{"type":"tool_use","name":"Shell","input":{"command":"npm run build","working_directory":"/w"}}]}}),
                serde_json::json!({"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"/w/package.json"}}]}}),
            ],
        );
        let calls = shell_calls(&scan);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert_eq!(names(calls[0]), vec!["npm"]);
        assert_eq!(
            (calls[0].at, calls[0].started_at, calls[0].finished_at),
            (None, None, None)
        );
        assert_eq!(calls[0].order_time(), calls[0].read_at);
        assert!(!calls[0].time_bounded);
    }

    /// A time later than the moment the line is read is not kept as given:
    /// the call's own time is dropped, the result time becomes the read
    /// time, and the call says so.
    #[test]
    fn times_later_than_the_read_time_are_not_kept_as_given() {
        let mut scan = FileScan::default();
        feed(
            &mut scan,
            &[
                serde_json::json!({"type":"assistant","timestamp":"2099-01-01T00:00:00.000Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"late-call","name":"Bash","input":{"command":"git status"}}]}}),
                serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:05.000Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"late-result","name":"Bash","input":{"command":"git log"}}]}}),
                serde_json::json!({"type":"user","timestamp":"2099-01-01T00:00:09.000Z","message":{"content":[{"type":"tool_result","tool_use_id":"late-result","content":"ok"}]}}),
            ],
        );
        let calls = shell_calls(&scan);
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[0].at, None);
        assert!(calls[0].time_bounded);
        assert_eq!(calls[0].order_time(), calls[0].read_at);
        assert_eq!(
            rfc3339(calls[1].at),
            Some("2026-11-08T10:00:05.000Z".to_string())
        );
        assert_eq!(calls[1].finished_at, Some(calls[1].read_at));
        assert!(calls[1].time_bounded);
    }

    /// A call waits for its result by its id, for a bounded number of lines.
    #[test]
    fn a_result_is_looked_for_by_its_id_for_a_bounded_number_of_lines() {
        let mut scan = FileScan::default();
        feed(
            &mut scan,
            &[
                serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:05.000Z","message":{"content":[{"type":"tool_use","id":"toolu_wait_1","name":"Bash","input":{"command":"git status"}}]}}),
                // Another call's result leaves this one waiting.
                serde_json::json!({"type":"user","timestamp":"2026-11-08T10:00:06.000Z","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_other","content":"ok"}]}}),
            ],
        );
        assert!(scan.shell_pending.contains_key("toolu_wait_1"));
        let filler: Vec<serde_json::Value> = (0..=TEST_RESULT_WAIT_LINES)
            .map(|_| serde_json::json!({"type":"progress","timestamp":"2026-11-08T10:00:07.000Z"}))
            .collect();
        feed(&mut scan, &filler);
        assert!(scan.shell_pending.is_empty());
        // The call's end is not known: the list says so.
        assert_eq!(scan.shell_gave_up, vec![0]);
        assert_eq!(
            rfc3339(scan.shell_gaps.unread_from),
            Some("2026-11-08T10:00:05.000Z".to_string())
        );
        assert!(scan.shell_gaps.unread_until.is_some());
        feed(
            &mut scan,
            &[
                serde_json::json!({"type":"user","timestamp":"2026-11-08T10:30:00.000Z","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_wait_1","content":"ok"}]}}),
            ],
        );
        assert_eq!(shell_calls(&scan)[0].finished_at, None);
    }

    /// The list keeps the most recent calls and says from when it is whole;
    /// a session's list is its own calls and its subagents', oldest first,
    /// each once.
    #[test]
    fn the_list_keeps_the_most_recent_calls_and_says_what_it_left_out() {
        let mut scan = FileScan {
            max_shell_calls: 4,
            ..Default::default()
        };
        let lines: Vec<serde_json::Value> = (0..6)
            .map(|i| {
                serde_json::json!({"type":"assistant","timestamp":format!("2026-11-08T10:00:{:02}.000Z", 10 * i),"message":{"content":[{"type":"tool_use","id":format!("call-{i}"),"name":"Bash","input":{"command":format!("tool{i} --run")}}]}})
            })
            .collect();
        feed(&mut scan, &lines[..4]);
        assert_eq!(scan.shell_gaps, ShellCallGaps::default());
        feed(&mut scan, &lines[4..]);
        assert_eq!(scan.shell_calls.len(), 4);
        assert_eq!(scan.shell_calls[0].1.programs, vec!["tool2".to_string()]);
        assert_eq!(
            rfc3339(scan.shell_gaps.calls_before),
            Some("2026-11-08T10:00:20.000Z".to_string())
        );
        // The calls that left the list no longer wait for a result.
        assert_eq!(scan.shell_pending.len(), 4);
        assert!(!scan.shell_pending.contains_key("call-1"));

        let at = |secs: i64| DateTime::<Utc>::from_timestamp(1_794_132_000 + secs, 0);
        let read_at = at(600).unwrap();
        let call = |secs: Option<i64>, program: &str| ShellCall {
            at: secs.and_then(at),
            programs: vec![program.to_string()],
            read_at,
            ..Default::default()
        };
        let mut merged = vec![
            call(Some(30), "git"),
            call(None, "npm"),
            call(Some(10), "cargo"),
            // The same call read from a second transcript, a moment later.
            ShellCall {
                read_at: at(601).unwrap(),
                ..call(Some(30), "git")
            },
            call(None, "npm"),
        ];
        let mut gaps = ShellCallGaps::default();
        bound_shell_calls(&mut merged, &mut gaps, 64);
        // Two readings of a call without a time are one call too.
        assert_eq!(
            merged
                .iter()
                .map(|c| c.programs[0].as_str())
                .collect::<Vec<_>>(),
            vec!["cargo", "git", "npm"]
        );
        assert_eq!(gaps, ShellCallGaps::default());
        // The call without a time is the first to go.
        bound_shell_calls(&mut merged, &mut gaps, 2);
        assert_eq!(
            merged
                .iter()
                .map(|c| c.programs[0].as_str())
                .collect::<Vec<_>>(),
            vec!["cargo", "git"]
        );
        assert_eq!(gaps.calls_before, Some(read_at));
    }

    /// A collection's scan reads the launch facts and records no shell call:
    /// nothing waits for a result, nothing is listed.
    #[test]
    fn a_scan_that_does_not_record_shell_calls_reads_the_launch_facts_only() {
        let p = vocab();
        let mut scan = FileScan::default();
        for l in [
            serde_json::json!({"type":"user","timestamp":"2026-11-08T10:00:00Z","cwd":"/Users/me/p","entrypoint":"cli","message":{"content":"hi"}}),
            serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:05Z","cwd":"/Users/me/p","message":{"content":[{"type":"tool_use","id":"a","name":"Bash","input":{"command":"claude -p x","run_in_background":true}}]}}),
            serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:09Z","message":{"content":[{"type":"tool_use","id":"b","name":"Bash","input":{"command":"git status"}}]}}),
            serde_json::json!({"type":"message","timestamp":"2026-11-08T10:00:12Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"c","name":"exec","arguments":{"command":"git push"}}]}}),
        ] {
            scan.lines_seen += 1;
            process_line(&line(l), &mut scan, &p.workspace_attribution);
        }
        assert_eq!(scan.launches.len(), 1);
        assert!(scan.shell_calls.is_empty());
        assert!(scan.shell_pending.is_empty());
        assert_eq!(scan.next_shell_seq, 0);
        assert_eq!(scan.shell_gaps, ShellCallGaps::default());
    }

    /// The reader says what each line changed: the calls it carries, the
    /// results that came back, the calls that stopped waiting (with the part
    /// of the transcript the list then does not vouch for), and what its
    /// caller did not hand over.
    #[test]
    fn the_reader_reports_what_each_line_changed() {
        let at = |secs: i64| DateTime::<Utc>::from_timestamp(1_794_132_000 + secs, 0).unwrap();
        let mut reader = ShellCallReader::with_limits(8, 3);
        assert_eq!(reader.headless(), None);
        let read = |reader: &mut ShellCallReader, value: serde_json::Value, secs: i64| {
            reader.read_line(&line(value), at(secs))
        };
        let events = read(
            &mut reader,
            serde_json::json!({"type":"user","timestamp":"2026-11-08T10:00:00Z","cwd":"/Users/me/p","entrypoint":"cli","message":{"content":"hi"}}),
            1,
        );
        assert_eq!(events, ShellCallLineEvents::default());
        let events = read(
            &mut reader,
            serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:05Z","message":{"content":[{"type":"tool_use","id":"a","name":"Bash","input":{"command":"git status"}},{"type":"tool_use","id":"b","name":"Bash","input":{"command":"cargo build"}}]}}),
            6,
        );
        assert_eq!(events.started, vec![0, 1]);
        assert_eq!(reader.call(0).unwrap().read_at, at(6));
        assert_eq!(reader.call(1).unwrap().programs, vec!["cargo".to_string()]);
        let events = read(
            &mut reader,
            serde_json::json!({"type":"user","timestamp":"2026-11-08T10:00:07Z","message":{"content":[{"type":"tool_result","tool_use_id":"a","content":"ok"}]}}),
            8,
        );
        assert_eq!(events.finished, vec![0]);
        assert!(reader.call(0).unwrap().finished_at.is_some());
        assert_eq!(reader.gaps(), &ShellCallGaps::default());
        // The second call's result does not come within three lines.
        let mut gave_up = Vec::new();
        for n in 0..4 {
            let events = read(
                &mut reader,
                serde_json::json!({"type":"progress","timestamp":"2026-11-08T10:00:09Z"}),
                10 + n,
            );
            gave_up.extend(events.gave_up);
        }
        assert_eq!(gave_up, vec![1]);
        assert_eq!(reader.call(1).unwrap().finished_at, None);
        assert_eq!(
            rfc3339(reader.gaps().unread_from),
            Some("2026-11-08T10:00:05.000Z".to_string())
        );
        assert!(reader.gaps().unread_until.is_some());
        assert_eq!(reader.calls().count(), 2);
        // What the caller could not hand over is unread too.
        let mut other = ShellCallReader::with_limits(8, 3);
        other.note_unread(None, at(20));
        assert_eq!(
            (other.gaps().unread_from, other.gaps().unread_until),
            (None, Some(at(20)))
        );
        let mut gaps = ShellCallGaps::default();
        gaps.add_unread(Some(at(9)), at(9));
        gaps.add_unread(Some(at(3)), at(9));
        assert_eq!((gaps.unread_from, gaps.unread_until), (Some(at(3)), Some(at(9))));
    }

    /// A line that repeats a message of the conversation without being a
    /// turn of it (a logged request: no time of its own) yields no call in a
    /// transcript whose lines carry a time. Read before the transcript showed
    /// one, its call is taken back when it does.
    #[test]
    fn a_line_without_a_time_is_not_a_turn_record_where_lines_carry_one() {
        let turn = serde_json::json!({"type":"assistant","timestamp":"2026-11-08T10:00:05Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_a","name":"Bash","input":{"command":"git status","description":"d"}}]}});
        let logged = serde_json::json!({"type":"api-request-blob","sessionId":"s","hash":"h","message":{"role":"assistant","content":[{"type":"thinking","thinking":"","signature":"x"},{"type":"tool_use","id":"toolu_a","name":"Bash","input":{"command":"git status","description":"d"},"caller":{"type":"direct"}}]}});
        let mut scan = FileScan::default();
        feed(&mut scan, &[turn.clone(), logged.clone(), logged.clone()]);
        let calls = shell_calls(&scan);
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(calls[0].at.is_some());

        let now = Utc::now();
        let mut reader = ShellCallReader::with_limits(8, 64);
        let first = reader.read_line(&line(logged.clone()), now);
        assert_eq!(first.started, vec![0]);
        let second = reader.read_line(&line(turn), now);
        assert_eq!(second.withdrawn, vec![0]);
        assert_eq!(second.started, vec![1]);
        let third = reader.read_line(&line(logged), now);
        assert_eq!(third, ShellCallLineEvents::default());
        assert_eq!(reader.calls().map(|(seq, _)| seq).collect::<Vec<_>>(), vec![1]);
    }

    /// A call without a time of its own takes no place from a dated one: it
    /// is the first to leave a full list.
    #[test]
    fn a_call_without_a_time_leaves_a_full_list_first() {
        let mut scan = FileScan {
            max_shell_calls: 2,
            ..Default::default()
        };
        feed(
            &mut scan,
            &[
                serde_json::json!({"timestamp":"2026-11-08T10:00:00Z","type":"session_meta","payload":{"cwd":"/home/me/app","originator":"codex_exec","source":"exec"}}),
                serde_json::json!({"timestamp":"2026-11-08T10:00:10.000Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"c1","arguments":"{\"cmd\":\"cargo test\"}"}}),
                // A command recorded once it had run, without a measured start.
                serde_json::json!({"timestamp":"2026-11-08T10:00:20.000Z","type":"event_msg","payload":{"type":"item_completed","item":{"type":"CommandExecution","id":"exec-2","command":["/bin/bash","-lc","git status"],"cwd":"file:///home/me/app","status":"completed","exit_code":0}}}),
            ],
        );
        let calls = shell_calls(&scan);
        assert_eq!(calls.len(), 2);
        assert!(calls[1].recorded_after_run && !calls[1].has_own_time());
        assert!(!calls[0].recorded_after_run);
        feed(
            &mut scan,
            &[
                serde_json::json!({"timestamp":"2026-11-08T10:00:30.000Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","call_id":"c3","arguments":"{\"cmd\":\"npm test\"}"}}),
            ],
        );
        let calls = shell_calls(&scan);
        assert_eq!(
            calls.iter().map(|c| names(c)[0]).collect::<Vec<_>>(),
            vec!["cargo", "npm"]
        );
        assert!(scan.shell_gaps.calls_before.is_some());
    }
}
