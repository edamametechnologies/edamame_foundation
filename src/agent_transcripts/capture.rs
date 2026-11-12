//! The shell calls read when a transcript grows.
//!
//! `flodbadd::store_writers` reports which files of the agent transcript
//! stores changed and which processes operated on them. This module reads
//! the lines appended to a transcript since it last read it, hands each
//! complete line to an extractor, and keeps, for each shell call a line
//! carries, what the extractor keeps of the call together with when the line
//! arrived and which process the reports name for it.
//!
//! One thread does it ([`start`]): it waits for a change
//! (`store_writers::wait_dirty`), takes the changed files, and for each one
//! reads from the offset it holds. It runs in the process that runs the
//! sensors, started and stopped with the file monitor.
//!
//! What is held, in memory only, per transcript: the file's identity, the
//! offset of the last complete line read, a digest of the bytes just before
//! that offset, the extractor's parse state, the calls and the intervals
//! that were not read line by line ([`CaptureGap`]). What is published
//! ([`since`]) holds no byte of a line: the extractor's result for each
//! call, times, a process identity, and counts.
//!
//! A path is read only when it names a regular file, reached without
//! following a symbolic link (in any component where the platform allows,
//! else the last), opened without blocking, and, when the record reported
//! the identity of the file its latest operation was made on, only when the
//! file opened is that file. The number of files held is bounded
//! (`transcript_capture.max_files_held`): beyond it the least recently
//! appended one is released, with a gap. A panic of the extractor is a gap
//! for its file; the thread goes on. The thread publishes a heartbeat; a
//! reply whose heartbeat is stale says the reader does not run.
//!
//! The extractor is a parameter ([`CallExtractor`]): this module knows what a
//! line is and when it arrived, not what a shell call looks like in a given
//! transcript format.

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use flodbadd::store_writers::{
    self, ops, CreationSeen, DirtyFile, DirtyTake, FileId, StoreFileKind, WriterInstance,
    WriterSpan,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::capture_wire::{self as wire, CaptureArrival, ProcessIdentity};
use super::launch::{ShellCall, ShellCallReader};

/// Calls one reply of [`since`] carries.
pub const MAX_CALLS_PER_REPLY: usize = 512;
/// Calls held that no reader asked past yet; the oldest leaves beyond it.
pub const MAX_UNREAD_CALLS: usize = 1_024;
/// Gaps held per transcript; the oldest two merge beyond it.
const MAX_GAPS_PER_FILE: usize = 16;
/// Results awaited per transcript (calls whose result line was not read).
const MAX_PENDING_RESULTS: usize = 256;
/// Reports kept per transcript to name the process of a line read earlier.
const MAX_RECENT_SPANS: usize = 64;
/// Bytes before the offset whose digest is kept.
const PREFIX_DIGEST_BYTES: u64 = 4_096;
/// Passes over one file per wake-up before the others get their turn.
const MAX_PASSES_PER_WAKE: usize = 8;
/// How often every held transcript's size is compared with what was read:
/// the watermark (`served_at_ms`) moves at each sweep. One metadata read per
/// held file.
const SWEEP_INTERVAL_MS: u64 = 2_000;
/// Bytes read across every file in one wake-up: the files left are read at
/// the next one.
const WAKE_BYTE_BUDGET: u64 = 32 << 20;
/// How long the thread waits for a change before it looks at its stop flag.
const WAIT_SLICE: Duration = Duration::from_millis(500);
/// A heartbeat older than this is a reader that does not run.
pub const HEARTBEAT_STALE_MS: u64 = 30_000;

/// What one complete line of a transcript carries, as the extractor reads it.
#[derive(Debug, Clone, PartialEq)]
pub enum LineItem {
    /// A shell call. `key` pairs it with its result line (the call's id in
    /// the transcript), `None` for a format without one. `call` is what is
    /// kept of the call.
    Call {
        key: Option<String>,
        call: ShellCall,
    },
    /// The result of the call `key`. `call`, when given, replaces what is
    /// kept of that call.
    Result {
        key: String,
        call: Option<ShellCall>,
    },
    /// The call `key` is no longer one (the extractor withdrew it).
    Withdrawn { key: String },
    /// The line carries the conversation's first user turn.
    FirstUserTurn,
    /// How the session started is known: by a program (`true`) or by a
    /// person.
    Headless(bool),
}

/// Reads the shell calls of a transcript line.
pub trait CallExtractor: Send + 'static {
    /// Parse state carried from one line of a file to the next.
    type State: Default + Send;

    /// The calls and results `line` carries (a complete line, without its
    /// line ending), for a transcript of `agent`.
    fn extract(
        &self,
        state: &mut Self::State,
        agent: &str,
        line: &[u8],
        read_at_ms: u64,
    ) -> Vec<LineItem>;
}

/// The extractor of the transcripts: the shell calls, the first user turn
/// and how the session started, as the launch scan reads them
/// ([`ShellCallReader`], one per file), under the published limits.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShellCallExtractor;

impl CallExtractor for ShellCallExtractor {
    type State = ShellCallReader;

    fn extract(
        &self,
        reader: &mut ShellCallReader,
        _agent: &str,
        line: &[u8],
        read_at_ms: u64,
    ) -> Vec<LineItem> {
        let read_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            i64::try_from(read_at_ms).unwrap_or(i64::MAX),
        )
        .unwrap_or_default();
        let headless_before = reader.headless();
        let events = reader.read_line(line, read_at);
        let mut items = Vec::new();
        for number in events.withdrawn {
            items.push(LineItem::Withdrawn {
                key: number.to_string(),
            });
        }
        for number in events.started {
            if let Some(call) = reader.call(number) {
                items.push(LineItem::Call {
                    key: Some(number.to_string()),
                    call: call.clone(),
                });
            }
        }
        for number in events.finished {
            items.push(LineItem::Result {
                key: number.to_string(),
                call: reader.call(number).cloned(),
            });
        }
        if events.first_user_turn {
            items.push(LineItem::FirstUserTurn);
        }
        let headless = reader.headless();
        if headless != headless_before {
            if let Some(headless) = headless {
                items.push(LineItem::Headless(headless));
            }
        }
        items
    }
}

/// The conversation a transcript file belongs to, as the collectors key it
/// (the file's name without its ending), and, for a subagent's file (one in
/// a `subagents` directory), the main conversation's key (the directory
/// above it).
pub fn transcript_session_keys(path: &str) -> (String, Option<String>) {
    let parts: Vec<&str> = path
        .split(['/', '\\'])
        .filter(|part| !part.is_empty())
        .collect();
    let name = parts.last().copied().unwrap_or_default();
    let key = name
        .strip_suffix(".jsonl")
        .or_else(|| name.strip_suffix(".txt"))
        .unwrap_or(name)
        .to_string();
    let parent = parts
        .iter()
        .rposition(|part| *part == "subagents")
        .and_then(|index| index.checked_sub(1))
        .map(|index| parts[index].to_string())
        .filter(|parent| !parent.is_empty() && *parent != key);
    (key, parent)
}

/// The reader's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureConfig {
    /// The longest line handed to the extractor.
    pub max_line_bytes: u64,
    /// Bytes read from one file in one pass.
    pub max_pass_bytes: u64,
    /// How far behind the end of a file the reader may be, in bytes and in
    /// time, before it moves to the end.
    pub max_backlog_bytes: u64,
    pub max_backlog_ms: u64,
    /// How far a file's own creation time may differ from the creation
    /// recorded for it.
    pub creation_time_slack_ms: u64,
    /// How long after a line was read a report may still name its process.
    pub late_report_ms: u64,
    /// Calls kept per transcript once a reader asked past them.
    pub max_calls_per_file: usize,
    /// Transcripts held at once.
    pub max_files_held: usize,
    /// The account that owns the stores' home (its uid, on Unix): a file
    /// owned by another account is not read. `None` where accounts have no
    /// uid (Windows).
    pub owner_uid: Option<u32>,
    /// Bytes one wake-up reads across every file; the files left are read
    /// at the next one.
    pub wake_byte_budget: u64,
}

impl CaptureConfig {
    /// The published bounds (`transcript_capture`), with the number of calls
    /// kept per transcript the caller reads from its own parameters and the
    /// account that owns the stores' home.
    pub fn from_params(max_calls_per_file: usize, owner_uid: Option<u32>) -> Self {
        let params = crate::agent_visibility_params::transcript_capture();
        Self {
            max_line_bytes: params.max_line_bytes,
            max_pass_bytes: params.max_pass_bytes.max(params.max_line_bytes),
            max_backlog_bytes: params.max_backlog_bytes,
            max_backlog_ms: params.max_backlog_secs.saturating_mul(1000),
            creation_time_slack_ms: params.creation_time_slack_ms,
            late_report_ms: params.late_report_ms,
            max_calls_per_file: max_calls_per_file.max(1),
            max_files_held: usize::try_from(params.max_files_held)
                .unwrap_or(usize::MAX)
                .max(1),
            owner_uid,
            wake_byte_budget: WAKE_BYTE_BUDGET,
        }
    }
}

/// One shell call, as it was read when its line arrived.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapturedCall {
    /// Number of the call, in the order calls were read by this instance.
    pub id: u64,
    /// The transcript file and its agent type.
    pub path: String,
    pub agent: String,
    /// The line arrived between `arrival_from_ms` and `arrived_at_ms` (epoch
    /// milliseconds): from the first report of a change of the file since
    /// the bytes before the line were read (`announced`), or from that
    /// earlier read when no report announced the line, until the read that
    /// found it.
    pub arrival_from_ms: u64,
    pub announced: bool,
    pub arrived_at_ms: u64,
    /// When the read that found the call's result line happened.
    pub result_arrived_at_ms: Option<u64>,
    /// The one process the reports name for the interval. `None` when none
    /// was reported for it, or when more than one was (`writers_differ`).
    pub writer: Option<WriterInstance>,
    pub writers_differ: bool,
    /// `writer` and `writers_differ` are final: the time a report may take
    /// after the read (`late_report_ms`) has passed, and every report that
    /// arrived in it was applied. Until then they may still change; a
    /// report that arrives later for the line's interval leaves it with no
    /// writer.
    pub writer_final: bool,
    /// The line was read from a file that replaced the transcript, not
    /// appended to it.
    pub in_rewrite: bool,
    /// What the extractor kept of the call.
    pub call: ShellCall,
    /// The capture's sequence number when this entry last changed.
    pub changed_seq: u64,
}

/// Why an interval of a transcript was not read line by line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureGapReason {
    /// The file held content when the reader first took it.
    BeforeCapture,
    /// The file's content before the offset changed, or its size was set.
    Rewrite,
    /// Another file took the path.
    Replaced,
    /// The file was removed.
    Removed,
    /// A line longer than the reader hands to the extractor.
    OversizedLine,
    /// The reader moved to the end of the file to catch up.
    Backlog,
    /// A sensor reported dropped events.
    EventsLost,
    /// The file grew without a report of the change.
    Unannounced,
    /// The store-writer record started a new instance.
    RecordRestarted,
    /// The file could not be read.
    Unreadable,
    /// Calls left the list to make room.
    CallsDropped,
    /// The path names something that is not a regular file reached without
    /// a symbolic link (a link, a pipe, a directory, a device, a reparse
    /// point): it is not read.
    NotRegular,
    /// The file at the path is not the one the record's latest operation
    /// was made on: it is not read until an operation on it is reported.
    IdentityMismatch,
    /// The reader released the file to stay within the number of files it
    /// holds: nothing of it is read from then on.
    Released,
    /// The extractor failed on a line of the interval.
    ExtractorFailed,
    /// The file had more than one name when it was read.
    MultipleNames,
    /// The file is owned by another account than the stores' home: it is
    /// not read.
    ForeignOwner,
}

/// What the reader does with a transcript now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapturedFileStatus {
    /// Reported, not read yet: nothing of it is watched.
    Pending,
    /// Read as it grows.
    Watched,
    /// Not read now: the path holds no file, or one the reader does not
    /// read; the gap that opened says why. It is read again when it comes
    /// back.
    Desynced,
    /// No longer held: nothing of it is read from then on.
    Released,
}

/// An interval of a transcript that was not read line by line: calls made
/// in it are not in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureGap {
    pub path: String,
    pub agent: String,
    /// `None`: from the start of the file.
    pub from_ms: Option<u64>,
    pub until_ms: u64,
    pub reason: CaptureGapReason,
    /// For a `Rewrite` or a `Replaced`: the one process the record reported
    /// an operation of for the interval that sets a file's content or puts
    /// a file at the path (a creation, a truncation, a move onto the path, a
    /// clone, an exchange). `None` when none was reported, or more than one
    /// process: nothing recorded explains the change.
    pub replaced_by: Option<WriterInstance>,
    pub changed_seq: u64,
}

/// A transcript the reader holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedFile {
    pub path: String,
    pub agent: String,
    pub status: CapturedFileStatus,
    /// The store-writer record's id for the path when it was last read.
    pub record_id: u64,
    /// Every line the file holds was read as it arrived, from the file's
    /// recorded creation on.
    pub since_creation: bool,
    /// A creation was recorded for the file, and the file's own creation
    /// time differs from it by more than the published slack: the file was
    /// not taken from that creation.
    pub creation_contradicted: bool,
    /// When the reader took the file: the creation it was read from, or the
    /// read that took it from its end.
    pub watching_since_ms: u64,
    /// Every complete line written to the file before this instant was read
    /// (or lies in a gap). `None` while it was never read through. A file
    /// that is `Watched` is read through at least the reader's
    /// `watermark_ms` as well.
    pub read_through_ms: Option<u64>,
    /// When it last read it, and the offset it holds.
    pub last_read_ms: u64,
    pub offset: u64,
    /// Times the file was found rewritten or replaced.
    pub rewrites: u64,
    /// The file had more than one name at its last read, and at any read.
    pub multiple_names: bool,
    pub multiple_names_seen: bool,
    /// Calls read before this instant are no longer in the list.
    pub calls_before_ms: Option<u64>,
    /// When the conversation's first user turn arrived, read once as it was
    /// appended to a file read since its creation; `None` otherwise (before
    /// the reader, in a gap, read again from the start).
    pub first_user_turn: Option<CaptureArrival>,
    /// How the session started, once the extractor read it.
    pub headless: Option<bool>,
    pub changed_seq: u64,
}

/// Counters of the reader since it started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureCounters {
    pub passes: u64,
    pub bytes_read: u64,
    pub lines_read: u64,
    pub calls_captured: u64,
    pub results_paired: u64,
    pub late_reports_applied: u64,
    pub rewrites: u64,
    pub gaps: u64,
    pub oversized_lines: u64,
    pub backlog_skips: u64,
    pub unannounced_reads: u64,
    pub read_errors: u64,
    pub calls_dropped: u64,
    /// Passes that found the path not to be a regular file, or another file
    /// than the record reported; files released; extractor failures; times
    /// the reader started a new instance.
    pub not_regular: u64,
    pub identity_mismatches: u64,
    pub released: u64,
    pub extractor_panics: u64,
    pub restarts: u64,
    /// Passes that began before the previous one (the clock moved back):
    /// each is read as a restart of the record. Files owned by another
    /// account. Wake-ups that stopped at the byte budget. Reports that
    /// arrived for a call whose writer was final.
    pub clock_steps: u64,
    pub foreign_owner: u64,
    pub wake_budget_cuts: u64,
    pub late_after_final: u64,
    /// From the first report of a change to the read that found the line:
    /// reads that took at most 1, 2, 5, 10, 20, 50, 100, 250, 500, 1,000 and
    /// 5,000 ms, then the longer ones; and the longest.
    pub latency_ms_buckets: [u64; 12],
    pub latency_ms_max: u64,
}

const LATENCY_BUCKET_LIMITS_MS: [u64; 11] = [1, 2, 5, 10, 20, 50, 100, 250, 500, 1_000, 5_000];

/// Reply of [`since`]: the reader's state for the relay, and what changed,
/// in the wire type the session binding reads ([`wire::CaptureBatch`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureReply {
    /// Identifies the reader: it changes each time it starts. Empty while it
    /// does not run.
    pub instance: String,
    /// Whether the reader runs. While it does not, nothing below is read.
    pub running: bool,
    pub started_at_ms: u64,
    /// The sequence number to ask from next.
    pub seq: u64,
    /// More changed than one reply carries: ask again from `seq`.
    pub more: bool,
    pub counters: CaptureCounters,
    /// When the reader's thread last made progress (epoch milliseconds). A
    /// reply is `running` only while it is recent.
    pub heartbeat_ms: u64,
    /// The store-writer record's instance and sequence number up to which
    /// the reader took what the record reported, and when: a consumer
    /// joining the record's rows with this reply reads the rows up to it.
    pub record_instance: String,
    pub record_seq: u64,
    pub record_taken_at_ms: u64,
    /// Files held now (released ones not counted).
    pub files_held: usize,
    /// What changed: the transcripts, the calls whose writer is final, the
    /// gaps; `served_at_ms` the watermark, cut before every call held back
    /// or whose writer is not final yet.
    pub batch: wire::CaptureBatch,
}

impl CaptureReply {
    /// The reply while the reader does not run.
    pub fn not_running() -> Self {
        Self {
            instance: String::new(),
            running: false,
            started_at_ms: 0,
            seq: 0,
            more: false,
            counters: CaptureCounters::default(),
            heartbeat_ms: 0,
            record_instance: String::new(),
            record_seq: 0,
            record_taken_at_ms: 0,
            files_held: 0,
            batch: wire::CaptureBatch {
                capture_instance: String::new(),
                served_at_ms: 0,
                stores: Vec::new(),
                transcripts: Vec::new(),
                calls: Vec::new(),
            },
        }
    }
}

/// A process as the wire names it.
fn wire_identity(writer: WriterInstance) -> ProcessIdentity {
    ProcessIdentity {
        pid: writer.pid,
        start_ms: writer.started_at_ms,
    }
}

/// A gap's reason as the wire spells it.
fn reason_name(reason: CaptureGapReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

impl CaptureGap {
    fn to_wire(&self) -> wire::CaptureGap {
        wire::CaptureGap {
            from_ms: self.from_ms,
            until_ms: self.until_ms,
            reason: reason_name(self.reason),
            replaced_by: self.replaced_by.map(wire_identity),
        }
    }
}

impl CapturedCall {
    fn to_wire(&self) -> wire::CaptureCall {
        let (session_key, _) = transcript_session_keys(&self.path);
        wire::CaptureCall {
            transcript_path: self.path.clone(),
            session_key,
            agent_type: self.agent.clone(),
            seq: self.id,
            call: self.call.clone(),
            arrival_from_ms: self.arrival_from_ms,
            arrived_at_ms: self.arrived_at_ms,
            result_arrived_at_ms: self.result_arrived_at_ms,
            writer: self.writer.map(wire_identity),
            in_rewrite: self.in_rewrite,
            writers_differ: self.writers_differ,
            writer_final: Some(self.writer_final),
        }
    }
}

impl CapturedFile {
    fn to_wire(&self, gaps: Vec<wire::CaptureGap>) -> wire::CaptureTranscript {
        let (session_key, parent_session_key) = transcript_session_keys(&self.path);
        wire::CaptureTranscript {
            transcript_path: self.path.clone(),
            session_key,
            parent_session_key,
            agent_type: self.agent.clone(),
            watched_since_ms: self.watching_since_ms,
            watched_from_creation: self.since_creation,
            headless: self.headless,
            first_user_turn: self.first_user_turn,
            coverage: match self.status {
                CapturedFileStatus::Pending => wire::CaptureCoverage::Pending,
                CapturedFileStatus::Watched => wire::CaptureCoverage::Watched,
                CapturedFileStatus::Desynced => wire::CaptureCoverage::Desynced,
                CapturedFileStatus::Released => wire::CaptureCoverage::Released,
            },
            read_through_ms: self.read_through_ms,
            gaps,
        }
    }
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// A file's identity on its volume: another file under the same path has
/// another one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume: u64,
    index: u64,
}

/// The identity of an open file, its number of names, and whether the
/// handle is something the reader does not read (a reparse point).
#[cfg(unix)]
fn file_identity(
    _file: &std::fs::File,
    meta: &std::fs::Metadata,
) -> (Option<FileIdentity>, Option<u64>, bool) {
    use std::os::unix::fs::MetadataExt;
    (
        Some(FileIdentity {
            volume: meta.dev(),
            index: meta.ino(),
        }),
        Some(meta.nlink()),
        false,
    )
}

#[cfg(windows)]
fn file_identity(
    file: &std::fs::File,
    _meta: &std::fs::Metadata,
) -> (Option<FileIdentity>, Option<u64>, bool) {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_DEVICE: u32 = 0x0000_0040;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is this open file's and `info` outlives the call.
    // Without the handle's information the file is not known to be a
    // regular one: not read.
    if unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle() as _), &mut info) }.is_err()
    {
        return (None, None, true);
    }
    let special = info.dwFileAttributes
        & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT)
        != 0;
    (
        Some(FileIdentity {
            volume: u64::from(info.dwVolumeSerialNumber),
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        }),
        Some(u64::from(info.nNumberOfLinks)),
        special,
    )
}

#[cfg(not(any(unix, windows)))]
fn file_identity(
    _file: &std::fs::File,
    _meta: &std::fs::Metadata,
) -> (Option<FileIdentity>, Option<u64>, bool) {
    // No identity is read here: a file is then never taken as the one read
    // before.
    (None, None, false)
}

/// Whether the file the reader opened is the one a sensor reported the
/// latest operation on. A sensor that reported none leaves nothing to
/// compare; an opened file whose identity is unknown does not match a
/// reported one.
fn identity_matches(opened: Option<FileIdentity>, reported: Option<FileId>) -> bool {
    match (opened, reported) {
        (_, None) => true,
        (Some(opened), Some(reported)) => {
            opened.volume == reported.device && opened.index == reported.inode
        }
        (None, Some(_)) => false,
    }
}

/// Why a path was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenRefusal {
    /// No file at the path.
    NotFound,
    /// A symbolic link (in a component the platform checks), a pipe, a
    /// directory, a device, a reparse point.
    NotRegular,
    /// Anything else (permissions, an I/O error).
    Unreadable,
}

/// A transcript opened for reading: the file, its metadata from the handle,
/// its identity and its number of names when the platform gives them.
struct OpenedTranscript {
    file: std::fs::File,
    meta: std::fs::Metadata,
    identity: Option<FileIdentity>,
    links: Option<u64>,
}

/// Open `path` for reading as the reader may: never through a symbolic link
/// (`O_NOFOLLOW_ANY` on macOS, `openat2` with `RESOLVE_NO_SYMLINKS` on Linux,
/// `O_NOFOLLOW` without them; a reparse point is refused on Windows), never
/// blocking on the open, and only a regular file.
fn open_transcript(path: &Path) -> Result<OpenedTranscript, OpenRefusal> {
    let file = open_no_follow(path)?;
    let meta = file.metadata().map_err(|_| OpenRefusal::Unreadable)?;
    if !meta.file_type().is_file() {
        return Err(OpenRefusal::NotRegular);
    }
    let (identity, links, special) = file_identity(&file, &meta);
    if special {
        return Err(OpenRefusal::NotRegular);
    }
    Ok(OpenedTranscript {
        file,
        meta,
        identity,
        links,
    })
}

#[cfg(unix)]
fn refusal_of(error: &std::io::Error) -> OpenRefusal {
    match error.raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => OpenRefusal::NotFound,
        Some(libc::ELOOP) | Some(libc::ENXIO) | Some(libc::EISDIR) => OpenRefusal::NotRegular,
        _ if error.kind() == std::io::ErrorKind::NotFound => OpenRefusal::NotFound,
        _ => OpenRefusal::Unreadable,
    }
}

#[cfg(target_os = "linux")]
fn open_no_follow(path: &Path) -> Result<std::fs::File, OpenRefusal> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::FromRawFd;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let c_path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| OpenRefusal::NotFound)?;
    // SAFETY: `open_how` is plain data, zeroed then filled; `c_path` is a
    // NUL-terminated string that outlives the call.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = flags as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c_path.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd >= 0 {
        // SAFETY: the descriptor was just opened and is owned here.
        return Ok(unsafe { std::fs::File::from_raw_fd(fd as i32) });
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENOSYS) {
        return Err(refusal_of(&error));
    }
    // A kernel without openat2: `O_NOFOLLOW`.
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| refusal_of(&error))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn open_no_follow(path: &Path) -> Result<std::fs::File, OpenRefusal> {
    use std::os::unix::fs::OpenOptionsExt;
    let open = |flags: i32| {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
    };
    // `O_NOFOLLOW_ANY` covers the last component too, and is refused in
    // combination with `O_NOFOLLOW`.
    match open(libc::O_NONBLOCK | libc::O_NOFOLLOW_ANY) {
        Ok(file) => Ok(file),
        // A system that does not know the flag: `O_NOFOLLOW`.
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            open(libc::O_NOFOLLOW | libc::O_NONBLOCK).map_err(|error| refusal_of(&error))
        }
        Err(error) => Err(refusal_of(&error)),
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "macos", target_os = "ios"))
))]
fn open_no_follow(path: &Path) -> Result<std::fs::File, OpenRefusal> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| refusal_of(&error))
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> Result<std::fs::File, OpenRefusal> {
    use std::os::windows::fs::OpenOptionsExt;
    // The reparse point itself, not its target: refused below on the
    // handle's attributes.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => OpenRefusal::NotFound,
            _ => OpenRefusal::Unreadable,
        })
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(path: &Path) -> Result<std::fs::File, OpenRefusal> {
    std::fs::File::open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => OpenRefusal::NotFound,
        _ => OpenRefusal::Unreadable,
    })
}

fn system_time_ms(time: std::time::SystemTime) -> Option<u64> {
    time.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

fn key_hash(key: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

/// A call as the engine holds it: the published entry and the interval its
/// line arrived in, for the reports that come after the read.
#[derive(Debug, Clone)]
struct HeldCall {
    entry: CapturedCall,
    /// The line was written after `interval_from_ms` and by `arrived_at_ms`.
    interval_from_ms: u64,
    /// A sensor reported dropped events for the interval: no report names
    /// the line's process, then or later.
    lost: bool,
}

struct FileState<S> {
    path: String,
    agent: String,
    record_id: u64,
    /// `None` until the file was read once, and again after the record
    /// restarted: the next read takes the file as new to the reader.
    identity: Option<FileIdentity>,
    synced: bool,
    /// The file was read at least once by this instance.
    ever_synced: bool,
    /// The latest creation the record reported at the path, and whether it
    /// is the one the record opened with.
    latest_creation: Option<CreationSeen>,
    creation_is_first: bool,
    /// The creation the file now held was read from its start for.
    creation_taken: Option<CreationSeen>,
    /// A file new to the reader and younger than the time a report of its
    /// creation may take: it is taken when the report arrives, or at this
    /// instant without it.
    first_sight_deadline_ms: Option<u64>,
    offset: u64,
    prefix_digest: Option<[u8; 32]>,
    /// Bytes are dropped up to the next line ending (the reader stands
    /// inside a line it does not read).
    discard_until_newline: bool,
    since_creation: bool,
    creation_contradicted: bool,
    watching_since_ms: u64,
    last_read_ms: u64,
    /// The size at the end of the last pass.
    size_seen: u64,
    /// The bytes from `offset` on were written after this instant.
    consumed_bound_ms: u64,
    /// The first report of a change since `consumed_bound_ms`.
    first_announce_ms: Option<u64>,
    /// A sensor reported dropped events since `consumed_bound_ms`.
    lost_pending: bool,
    behind_since_ms: Option<u64>,
    parse_state: S,
    pending_results: VecDeque<(u64, u64)>,
    calls: VecDeque<HeldCall>,
    calls_before_ms: Option<u64>,
    gaps: Vec<CaptureGap>,
    recent_spans: VecDeque<WriterSpan>,
    rewrites: u64,
    changed_seq: u64,
    /// The identity the record reported for the latest operation on the
    /// path (`None`: none reported).
    reported_identity: Option<FileId>,
    /// Not read now, why, and since when.
    desync: Option<(CaptureGapReason, u64)>,
    /// No longer held: kept only until a reader asked past what it has.
    released: bool,
    /// When a pass last took bytes from the file, or when it was first
    /// reported: the least recent one is released first.
    last_growth_ms: u64,
    /// More than one name at the last read, and at any read.
    multiple_names: bool,
    multiple_names_seen: bool,
    /// Every complete line written before this instant was read: set by a
    /// pass that read up to the end, published.
    read_through_ms: Option<u64>,
    /// The same, confirmed by a sweep that found the size unchanged: not
    /// published per file, it makes the watermark.
    confirmed_through_ms: Option<u64>,
    /// The earliest report of the file to the reader, or the record's
    /// opening for it if earlier.
    first_report_ms: u64,
    /// A file read from its start without its creation: the lines up to
    /// this offset name no process.
    unattributed_until: Option<u64>,
    /// The creation a reader already read the file from, as the record
    /// keeps it (`DirtyFile::creation_read_at_ms`): one this state did not
    /// take itself was not followed since, and is not read "since its
    /// creation" again.
    creation_read_at_ms: Option<u64>,
    /// The first user turn: when it arrived (measured once), whether its
    /// line was read at all (it is never stamped again), and how the
    /// session started.
    first_user_turn: Option<CaptureArrival>,
    first_user_turn_seen: bool,
    headless: Option<bool>,
}

impl<S> FileState<S> {
    fn status(&self) -> CapturedFileStatus {
        if self.released {
            CapturedFileStatus::Released
        } else if self.desync.is_some() {
            CapturedFileStatus::Desynced
        } else if !self.ever_synced {
            CapturedFileStatus::Pending
        } else {
            CapturedFileStatus::Watched
        }
    }
}

/// What a pass found the file to be, against what the reader holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassKind {
    /// The file is new to the reader.
    FirstSight,
    /// Bytes were appended (or nothing changed).
    Append,
    /// The content before the offset is not what was read.
    Rewrite,
    /// Another file is under the path.
    Replaced,
}

/// The reader, without its thread: every method takes what the thread would
/// have taken from the store-writer record, so it is driven directly in
/// tests.
pub struct Capture<E: CallExtractor> {
    extractor: E,
    config: CaptureConfig,
    clock: Box<dyn Fn() -> u64 + Send>,
    instance: String,
    started_at_ms: u64,
    record_instance: Option<String>,
    seq: u64,
    next_call_id: u64,
    files: BTreeMap<String, FileState<E::State>>,
    counters: CaptureCounters,
    last_sweep_ms: u64,
    /// The reader's thread drives this capture: its progress is the
    /// published heartbeat.
    publishes_heartbeat: bool,
    /// Every watched file was read through this instant (the last sweep).
    watermark_ms: Option<u64>,
    /// The record's sequence number at the last take handled, and when it
    /// was handled.
    record_seq: u64,
    record_taken_at_ms: u64,
    /// When the last pass began: a pass that begins before it means the
    /// clock moved back.
    last_pass_start_ms: u64,
    /// Bytes this wake-up may still read across files.
    wake_bytes_left: u64,
    /// What to give back to the store-writer record
    /// ([`store_writers::note_reader_facts`]): path, record id, facts.
    facts_out: Vec<(String, u64, store_writers::ReaderFacts)>,
}

impl<E: CallExtractor> Capture<E> {
    pub fn new(extractor: E, config: CaptureConfig) -> Self {
        Self::with_clock(extractor, config, Box::new(store_writers::now_ms))
    }

    /// With the clock the passes are stamped with (tests).
    pub fn with_clock(
        extractor: E,
        config: CaptureConfig,
        clock: Box<dyn Fn() -> u64 + Send>,
    ) -> Self {
        let now = clock();
        let wake_bytes_left = config.wake_byte_budget.max(1);
        Self {
            extractor,
            config,
            clock,
            instance: uuid::Uuid::new_v4().simple().to_string(),
            started_at_ms: now,
            record_instance: None,
            seq: 0,
            next_call_id: 1,
            files: BTreeMap::new(),
            counters: CaptureCounters::default(),
            last_sweep_ms: now,
            publishes_heartbeat: false,
            watermark_ms: None,
            record_seq: 0,
            record_taken_at_ms: 0,
            last_pass_start_ms: now,
            wake_bytes_left,
            facts_out: Vec::new(),
        }
    }

    /// What the reader found since the last call, to give back to the
    /// store-writer record, where it outlives this reader's state.
    pub fn take_reader_facts(&mut self) -> Vec<(String, u64, store_writers::ReaderFacts)> {
        std::mem::take(&mut self.facts_out)
    }

    /// Give a writer to no call that did not get it as final: each call
    /// whose writer is still open is made final once the time a report may
    /// take has passed since its read (the reports that arrived meanwhile
    /// were applied when they arrived).
    pub fn finalize_writers(&mut self) {
        let now = (self.clock)();
        let late_window = self.config.late_report_ms;
        let mut changed: Vec<(String, usize)> = Vec::new();
        for state in self.files.values_mut() {
            for (index, held) in state.calls.iter_mut().enumerate() {
                if !held.entry.writer_final
                    && (held.lost || now.saturating_sub(held.entry.arrived_at_ms) >= late_window)
                {
                    held.entry.writer_final = true;
                    changed.push((state.path.clone(), index));
                }
            }
        }
        for (path, index) in changed {
            let seq = self.bump();
            if let Some(state) = self.files.get_mut(&path) {
                if let Some(held) = state.calls.get_mut(index) {
                    held.entry.changed_seq = seq;
                }
                state.changed_seq = seq;
            }
        }
    }

    /// Start a wake-up: the bytes it may read across files.
    fn begin_wake(&mut self) {
        self.wake_bytes_left = self.config.wake_byte_budget.max(1);
    }

    /// Start over: a new instance, nothing held. A reader of the previous
    /// instance reads everything again from the start, and whatever it read
    /// before is a gap from its last read.
    fn start_over(&mut self) {
        self.instance = uuid::Uuid::new_v4().simple().to_string();
        self.started_at_ms = (self.clock)();
        self.record_instance = None;
        self.files.clear();
        self.watermark_ms = None;
        self.record_seq = 0;
        self.counters.restarts += 1;
        self.seq += 1;
        tracing::info!("transcript reader: started over");
    }

    /// Files held now (released ones not counted).
    pub fn files_held(&self) -> usize {
        self.files.values().filter(|state| !state.released).count()
    }

    /// Drop the released files a reader asked past, release the least
    /// recently appended ones beyond `max_files_held`, and start a new
    /// instance while released files wait for a reader past the bound.
    fn release_beyond_bound(&mut self, acked_seq: u64) {
        self.files
            .retain(|_, state| !(state.released && state.changed_seq <= acked_seq));
        let now = (self.clock)();
        while self.files_held() > self.config.max_files_held {
            let Some(path) = self
                .files
                .values()
                .filter(|state| !state.released)
                .min_by_key(|state| (state.last_growth_ms, state.path.clone()))
                .map(|state| state.path.clone())
            else {
                break;
            };
            let seq = self.bump();
            if let Some(state) = self.files.get_mut(&path) {
                let from = state.synced.then_some(state.consumed_bound_ms);
                push_gap(
                    state,
                    from,
                    now,
                    CaptureGapReason::Released,
                    seq,
                    &mut self.counters,
                );
                state.released = true;
                state.changed_seq = seq;
                self.counters.released += 1;
            }
        }
        if self.files.len() > self.config.max_files_held.saturating_mul(2) {
            self.start_over();
        }
    }

    fn bump(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Take what the store-writer record reported: read every changed
    /// transcript. `acked_seq` is the sequence number readers asked past.
    pub fn handle_take(&mut self, take: &DirtyTake, acked_seq: u64) {
        let now = (self.clock)();
        let restarted = self
            .record_instance
            .as_deref()
            .is_some_and(|known| known != take.instance);
        if restarted {
            self.record_restarted(now);
        }
        self.record_instance = Some(take.instance.clone());
        self.record_seq = take.seq;
        self.record_taken_at_ms = now;
        self.begin_wake();
        for dirty in &take.files {
            if dirty.kind != StoreFileKind::Transcript {
                continue;
            }
            self.merge_report(dirty, now);
            self.read_file(&dirty.path, acked_seq);
        }
        self.release_beyond_bound(acked_seq);
    }

    /// Whether a transcript was left with complete lines to read (a wake-up
    /// reads a bounded number of passes per file).
    pub fn has_backlog(&self) -> bool {
        self.files
            .values()
            .any(|state| state.behind_since_ms.is_some())
    }

    /// Go on reading the transcripts a wake-up left behind, and take the
    /// new files whose wait for a creation (`late_report_ms`) is over.
    pub fn continue_reads(&mut self, acked_seq: u64) {
        let now = (self.clock)();
        self.begin_wake();
        let behind: Vec<String> = self
            .files
            .values()
            .filter(|state| !state.released)
            .filter(|state| {
                state.behind_since_ms.is_some()
                    || state
                        .first_sight_deadline_ms
                        .is_some_and(|deadline| now >= deadline)
            })
            .map(|state| state.path.clone())
            .collect();
        for path in behind {
            self.read_file(&path, acked_seq);
        }
    }

    /// Compare every held transcript's size with what was read, and read
    /// those that differ without a report (at most once per sweep
    /// interval).
    pub fn sweep_if_due(&mut self, acked_seq: u64) {
        let now = (self.clock)();
        if now.saturating_sub(self.last_sweep_ms) < SWEEP_INTERVAL_MS {
            return;
        }
        self.sweep(acked_seq);
    }

    /// The sweep itself, whatever the time since the last one. Every held
    /// file is looked at: a watched one whose size is unchanged is read
    /// through the sweep's start, any other one is read (a file not read now
    /// is tried again). Then the watermark is the earliest instant every
    /// watched file is read through.
    pub fn sweep(&mut self, acked_seq: u64) {
        let started = (self.clock)();
        self.last_sweep_ms = started;
        self.begin_wake();
        let mut candidates: Vec<String> = Vec::new();
        for state in self.files.values_mut() {
            if state.released {
                continue;
            }
            // Another file under the path at the same size is a change: the
            // size and, where the metadata carries it, the identity.
            let unchanged = state.synced
                && state.desync.is_none()
                && state.behind_since_ms.is_none()
                && std::fs::symlink_metadata(&state.path).is_ok_and(|meta| {
                    meta.len() == state.size_seen
                        && metadata_identity(&meta)
                            .map_or(true, |found| Some(found) == state.identity)
                });
            if unchanged {
                state.confirmed_through_ms = Some(
                    state
                        .confirmed_through_ms
                        .map_or(started, |known| known.max(started)),
                );
            } else {
                candidates.push(state.path.clone());
            }
        }
        for path in candidates {
            self.read_file(&path, acked_seq);
        }
        self.release_beyond_bound(acked_seq);
        self.watermark_ms = Some(
            self.files
                .values()
                .filter(|state| state.status() == CapturedFileStatus::Watched)
                .map(|state| state.confirmed_through_ms.unwrap_or(0))
                .min()
                .unwrap_or(started)
                .min(started),
        );
    }

    /// The record started a new instance: the record holds nothing of the
    /// files in between. Each file keeps its position; its next pass
    /// names no process for what it reads, and the interval since its last
    /// read is a gap up to that pass. The calls read so far stay.
    fn record_restarted(&mut self, now: u64) {
        let paths: Vec<String> = self.files.keys().cloned().collect();
        for path in paths {
            let seq = self.bump();
            let Some(state) = self.files.get_mut(&path) else {
                continue;
            };
            if state.released {
                continue;
            }
            let from = state.synced.then_some(state.consumed_bound_ms);
            state.since_creation = false;
            state.lost_pending = true;
            state.recent_spans.clear();
            state.confirmed_through_ms = state.read_through_ms;
            state.changed_seq = seq;
            push_gap(
                state,
                from,
                now,
                CaptureGapReason::RecordRestarted,
                seq,
                &mut self.counters,
            );
        }
    }

    /// Fold one report of the record into the file's state.
    fn merge_report(&mut self, dirty: &DirtyFile, now: u64) {
        let seq = self.bump();
        let state = self
            .files
            .entry(dirty.path.clone())
            .or_insert_with(|| FileState {
                path: dirty.path.clone(),
                agent: dirty.agent.clone(),
                record_id: dirty.record_id,
                identity: None,
                synced: false,
                ever_synced: false,
                latest_creation: None,
                creation_is_first: false,
                creation_taken: None,
                first_sight_deadline_ms: None,
                offset: 0,
                prefix_digest: None,
                discard_until_newline: false,
                since_creation: false,
                creation_contradicted: false,
                watching_since_ms: now,
                last_read_ms: now,
                size_seen: 0,
                consumed_bound_ms: now,
                first_announce_ms: None,
                lost_pending: false,
                behind_since_ms: None,
                parse_state: E::State::default(),
                pending_results: VecDeque::new(),
                calls: VecDeque::new(),
                calls_before_ms: None,
                gaps: Vec::new(),
                recent_spans: VecDeque::new(),
                rewrites: 0,
                changed_seq: seq,
                reported_identity: None,
                desync: None,
                released: false,
                last_growth_ms: now,
                multiple_names: false,
                multiple_names_seen: false,
                read_through_ms: None,
                confirmed_through_ms: None,
                first_report_ms: dirty.first_seen_ms.min(dirty.dirty_since_ms).min(now),
                unattributed_until: None,
                creation_read_at_ms: None,
                first_user_turn: None,
                first_user_turn_seen: false,
                headless: None,
            });
        state.first_report_ms = state
            .first_report_ms
            .min(dirty.first_seen_ms)
            .min(dirty.dirty_since_ms);
        if state.released {
            // Reported again after it was released: held again, as new.
            state.released = false;
            state.synced = false;
            state.ever_synced = false;
            state.identity = None;
            state.since_creation = false;
            state.watching_since_ms = now;
            state.last_growth_ms = now;
        }
        if state.record_id != dirty.record_id {
            // The path's record left the table and came back: its reports in
            // between are not held.
            state.record_id = dirty.record_id;
            state.lost_pending = true;
            state.since_creation = false;
        }
        state.first_announce_ms = Some(
            state
                .first_announce_ms
                .map_or(dirty.dirty_since_ms, |known| {
                    known.min(dirty.dirty_since_ms)
                }),
        );
        if dirty.lost || dirty.spans_overflowed {
            state.lost_pending = true;
        }
        for span in &dirty.spans {
            if state.recent_spans.len() >= MAX_RECENT_SPANS {
                state.recent_spans.pop_front();
            }
            state.recent_spans.push_back(*span);
        }
        state.reported_identity = dirty.identity;
        state.creation_read_at_ms = dirty.creation_read_at_ms;
        // What the record says of the creation of the file at the path.
        state.latest_creation = dirty.last_creation;
        state.creation_is_first = dirty.creation.is_some() && dirty.creation == dirty.last_creation;
        self.apply_late_reports(&dirty.path, &dirty.spans, now);
    }

    /// Name the process of the calls read a moment ago from the reports
    /// that arrived since (a sensor may deliver its report after the read).
    fn apply_late_reports(&mut self, path: &str, new_spans: &[WriterSpan], now: u64) {
        let late_window = self.config.late_report_ms;
        let mut changed: Vec<usize> = Vec::new();
        let mut late_after_final = 0;
        {
            let Some(state) = self.files.get_mut(path) else {
                return;
            };
            let spans: Vec<WriterSpan> = state.recent_spans.iter().copied().collect();
            for (index, held) in state.calls.iter_mut().enumerate() {
                if held.lost {
                    continue;
                }
                if held.entry.writer_final
                    || now.saturating_sub(held.entry.arrived_at_ms) > late_window
                {
                    // Too late to name a writer: a report that arrives now
                    // for the line's interval and names another process
                    // leaves the line with none.
                    let late =
                        resolve_writer(new_spans, held.interval_from_ms, held.entry.arrived_at_ms);
                    let disagrees = held.entry.writer.is_some()
                        && (late.differ
                            || late
                                .writer
                                .is_some_and(|late| Some(late) != held.entry.writer));
                    if disagrees {
                        held.entry.writer = None;
                        held.entry.writers_differ = true;
                        held.entry.writer_final = true;
                        changed.push(index);
                        late_after_final += 1;
                    }
                    continue;
                }
                let resolved =
                    resolve_writer(&spans, held.interval_from_ms, held.entry.arrived_at_ms);
                let mut entry_changed = false;
                if resolved.differ && !held.entry.writers_differ {
                    held.entry.writers_differ = true;
                    held.entry.writer = None;
                    entry_changed = true;
                } else if !held.entry.writers_differ
                    && held.entry.writer.is_none()
                    && resolved.writer.is_some()
                {
                    held.entry.writer = resolved.writer;
                    entry_changed = true;
                }
                if let Some(first) = resolved.first_ms {
                    let first = first.max(held.interval_from_ms);
                    if first < held.entry.arrival_from_ms || !held.entry.announced {
                        held.entry.arrival_from_ms = first.min(held.entry.arrived_at_ms);
                        held.entry.announced = true;
                        entry_changed = true;
                    }
                }
                if entry_changed {
                    changed.push(index);
                }
            }
        }
        self.counters.late_after_final += late_after_final;
        for index in changed {
            let seq = self.bump();
            if let Some(state) = self.files.get_mut(path) {
                if let Some(held) = state.calls.get_mut(index) {
                    held.entry.changed_seq = seq;
                }
                state.changed_seq = seq;
            }
            self.counters.late_reports_applied += 1;
        }
    }

    /// Read `path` from the offset held, in passes of at most
    /// `max_pass_bytes`.
    fn read_file(&mut self, path: &str, acked_seq: u64) {
        for _ in 0..MAX_PASSES_PER_WAKE {
            if self.wake_bytes_left == 0 {
                // Left for the next wake-up: a file behind is read on.
                self.counters.wake_budget_cuts += 1;
                let now = (self.clock)();
                if let Some(state) = self.files.get_mut(path) {
                    if state.ever_synced && !state.released && state.desync.is_none() {
                        state.behind_since_ms.get_or_insert(now);
                    }
                }
                break;
            }
            let read_before = self.counters.bytes_read;
            let more = self.read_pass(path);
            let read = self.counters.bytes_read.saturating_sub(read_before);
            self.wake_bytes_left = self.wake_bytes_left.saturating_sub(read);
            if !more {
                break;
            }
        }
        self.trim_calls(path, acked_seq);
    }

    /// One pass. `true` when complete lines are still to be read.
    fn read_pass(&mut self, path: &str) -> bool {
        let t_before = (self.clock)();
        if t_before < self.last_pass_start_ms {
            // The clock moved back: the times held may lie ahead of the
            // passes to come. Read as a restart of the record: a gap on
            // every file, each read on from where it stands.
            self.counters.clock_steps += 1;
            self.record_restarted(t_before);
        }
        self.last_pass_start_ms = t_before;
        self.counters.passes += 1;
        let Some(mut state) = self.files.remove(path) else {
            return false;
        };
        if state.released {
            self.files.insert(path.to_string(), state);
            return false;
        }
        if self.publishes_heartbeat {
            HEARTBEAT_MS.store(store_writers::now_ms(), Ordering::Release);
        }
        let more = self.read_pass_on(&mut state, t_before);
        if state.released && !state.ever_synced {
            // Gone before it was ever read: nothing of it was watched, and a
            // reader that saw it pending keeps reading it as not watched.
            return false;
        }
        self.files.insert(path.to_string(), state);
        more
    }

    fn read_pass_on(&mut self, state: &mut FileState<E::State>, t_before: u64) -> bool {
        let seq = self.bump();
        state.changed_seq = seq;
        let opened = match open_transcript(Path::new(&state.path)) {
            Ok(opened) => opened,
            Err(refusal) => {
                let reason = match refusal {
                    OpenRefusal::NotFound => CaptureGapReason::Removed,
                    OpenRefusal::NotRegular => {
                        self.counters.not_regular += 1;
                        CaptureGapReason::NotRegular
                    }
                    OpenRefusal::Unreadable => {
                        self.counters.read_errors += 1;
                        CaptureGapReason::Unreadable
                    }
                };
                if !state.ever_synced && reason == CaptureGapReason::Removed {
                    // Reported and gone before it was ever read: nothing of
                    // it was watched (dropped by the caller).
                    state.released = true;
                    return false;
                }
                if state.desync.is_none() {
                    let from = state.synced.then_some(state.consumed_bound_ms);
                    push_gap(state, from, t_before, reason, seq, &mut self.counters);
                    state.desync = Some((reason, t_before));
                }
                // The next file under the path is new to the reader.
                state.synced = false;
                state.identity = None;
                state.offset = 0;
                state.size_seen = 0;
                state.prefix_digest = None;
                state.discard_until_newline = false;
                state.since_creation = false;
                state.parse_state = E::State::default();
                state.pending_results.clear();
                state.first_announce_ms = None;
                state.lost_pending = false;
                state.behind_since_ms = None;
                state.consumed_bound_ms = t_before;
                state.last_read_ms = t_before;
                state.recent_spans.clear();
                return false;
            }
        };
        let OpenedTranscript {
            mut file,
            meta,
            identity,
            links,
        } = opened;
        // A file another account owns is not read (the reader may run with
        // more rights than the home's owner).
        if let Some(owner) = self.config.owner_uid {
            if metadata_owner(&meta) != Some(owner) {
                self.counters.foreign_owner += 1;
                if state.desync.is_none() {
                    let from = state.synced.then_some(state.consumed_bound_ms);
                    push_gap(
                        state,
                        from,
                        t_before,
                        CaptureGapReason::ForeignOwner,
                        seq,
                        &mut self.counters,
                    );
                    state.desync = Some((CaptureGapReason::ForeignOwner, t_before));
                }
                return false;
            }
        }
        // The file opened is not the one the record's latest operation was
        // made on: not read until an operation on it is reported.
        if !identity_matches(identity, state.reported_identity) {
            self.counters.identity_mismatches += 1;
            if state.desync.is_none() {
                let from = state.synced.then_some(state.consumed_bound_ms);
                push_gap(
                    state,
                    from,
                    t_before,
                    CaptureGapReason::IdentityMismatch,
                    seq,
                    &mut self.counters,
                );
                state.desync = Some((CaptureGapReason::IdentityMismatch, t_before));
            }
            return false;
        }
        let resumed_from = state.desync.take();
        // A file with more than one name: the lines of this pass name no
        // process, and the interval since the last read is a gap.
        // A number of names that was not read is not one name.
        let multiple_names = links.is_none() || links.is_some_and(|links| links != 1);
        state.multiple_names = multiple_names;
        if multiple_names && !state.multiple_names_seen {
            self.facts_out.push((
                state.path.clone(),
                state.record_id,
                store_writers::ReaderFacts {
                    multiple_names: true,
                    ..Default::default()
                },
            ));
        }
        state.multiple_names_seen |= multiple_names;
        let size = meta.len();

        // What the file is against what is held.
        let replacing_reported = state
            .recent_spans
            .iter()
            .any(|span| span.ops & ops::REPLACING != 0 && span.last_ms >= state.consumed_bound_ms);
        let kind = if !state.synced {
            PassKind::FirstSight
        } else if identity.is_none() || identity != state.identity {
            PassKind::Replaced
        } else if size < state.offset
            || replacing_reported
            || !prefix_matches(&mut file, state.offset, state.prefix_digest)
        {
            PassKind::Rewrite
        } else {
            PassKind::Append
        };

        // A file is read from its start only when the record reported its
        // creation, no report was dropped since, the creation was not taken
        // already for an earlier file, and the file's own creation time
        // agrees with it.
        let fresh_creation = state.latest_creation.filter(|creation| {
            Some(*creation) != state.creation_taken
                && state.creation_read_at_ms != Some(creation.at_ms)
                && !state.lost_pending
                && identity.is_some()
                && creation_time_agrees(&meta, creation.at_ms, self.config.creation_time_slack_ms)
        });
        // A file new to the reader, with no creation in the record, that is
        // younger than `late_report_ms`: it is taken when the record holds
        // its creation or when that bound has passed. Nothing of it is read
        // meanwhile.
        if kind == PassKind::FirstSight
            && state.latest_creation.is_none()
            && !state.ever_synced
            && !state.lost_pending
        {
            if let Some(born_ms) = meta.created().ok().and_then(system_time_ms) {
                let deadline = born_ms.saturating_add(self.config.late_report_ms);
                if t_before < deadline {
                    state.first_sight_deadline_ms = Some(deadline);
                    state.desync = resumed_from;
                    return false;
                }
            }
        }
        state.first_sight_deadline_ms = None;
        // A file not read for a while and taken again without the position
        // it was read at: the interval it was not read in is a gap up to
        // this read.
        if let Some((reason, since)) = resumed_from {
            if matches!(kind, PassKind::FirstSight | PassKind::Replaced) {
                push_gap(
                    state,
                    Some(since),
                    t_before,
                    reason,
                    seq,
                    &mut self.counters,
                );
            }
        }

        let mut in_rewrite = false;
        match kind {
            PassKind::Append => {}
            PassKind::FirstSight => {
                state.identity = identity;
                state.synced = true;
                state.parse_state = E::State::default();
                state.pending_results.clear();
                match fresh_creation {
                    Some(creation) => {
                        state.offset = 0;
                        state.prefix_digest = None;
                        state.discard_until_newline = false;
                        state.creation_taken = Some(creation);
                        state.creation_read_at_ms = Some(creation.at_ms);
                        self.facts_out.push((
                            state.path.clone(),
                            state.record_id,
                            store_writers::ReaderFacts {
                                creation_read_at_ms: Some(creation.at_ms),
                                ..Default::default()
                            },
                        ));
                        // The first file the record saw at the path is read
                        // since its creation; a file created there after
                        // another one was unlinked replaced it.
                        state.since_creation = state.creation_is_first;
                        in_rewrite = !state.creation_is_first;
                        state.consumed_bound_ms = creation.at_ms.saturating_sub(1);
                        if !state.ever_synced {
                            state.watching_since_ms = creation.at_ms;
                        }
                    }
                    None => {
                        state.since_creation = false;
                        // A creation was recorded, and the file's own time
                        // says it is not this file's.
                        if let Some(creation) = state.latest_creation {
                            if Some(creation) != state.creation_taken
                                && !creation_time_agrees(
                                    &meta,
                                    creation.at_ms,
                                    self.config.creation_time_slack_ms,
                                )
                            {
                                if !state.creation_contradicted {
                                    self.facts_out.push((
                                        state.path.clone(),
                                        state.record_id,
                                        store_writers::ReaderFacts {
                                            creation_contradicted: true,
                                            ..Default::default()
                                        },
                                    ));
                                }
                                state.creation_contradicted = true;
                            }
                        }
                        // A file born after the reader started, small enough
                        // to read: read from its start, its lines naming no
                        // process and arriving from the earlier of its birth
                        // and its first report (a birth time can be set: it
                        // only widens the interval). Otherwise from its end.
                        let born_ms = meta.created().ok().and_then(system_time_ms);
                        let from_start = born_ms
                            .filter(|born| *born >= self.started_at_ms)
                            .filter(|_| size <= self.config.max_backlog_bytes);
                        let lower = from_start.map(|born| born.min(state.first_report_ms));
                        match lower {
                            Some(lower) => {
                                state.offset = 0;
                                state.prefix_digest = None;
                                state.discard_until_newline = false;
                                state.unattributed_until = Some(size);
                                state.consumed_bound_ms = lower.saturating_sub(1);
                            }
                            None => {
                                move_to_end(state, &mut file, size);
                                state.consumed_bound_ms = t_before;
                            }
                        }
                        if !state.ever_synced {
                            push_gap(
                                state,
                                lower,
                                t_before,
                                CaptureGapReason::BeforeCapture,
                                seq,
                                &mut self.counters,
                            );
                            // Watched from this read on.
                            state.watching_since_ms = t_before;
                        }
                        state.first_announce_ms = None;
                        state.lost_pending = false;
                    }
                }
                state.ever_synced = true;
            }
            PassKind::Rewrite | PassKind::Replaced => {
                state.rewrites += 1;
                self.counters.rewrites += 1;
                // Another file took the path when its identity says so, and
                // when the record reported a creation there since (the
                // volume may give the new file the number of the old one).
                let reason = if kind == PassKind::Replaced || fresh_creation.is_some() {
                    CaptureGapReason::Replaced
                } else {
                    CaptureGapReason::Rewrite
                };
                let replaced_by = replacing_writer(&state.recent_spans, state.consumed_bound_ms);
                push_gap(
                    state,
                    Some(state.consumed_bound_ms),
                    t_before,
                    reason,
                    seq,
                    &mut self.counters,
                );
                if let Some(gap) = state.gaps.last_mut() {
                    gap.replaced_by = replaced_by;
                }
                state.parse_state = E::State::default();
                state.pending_results.clear();
                state.identity = identity;
                state.since_creation = false;
                match fresh_creation {
                    Some(creation) => {
                        // The file that took the path is read from its
                        // start: its lines arrived by replacement.
                        state.offset = 0;
                        state.prefix_digest = None;
                        state.discard_until_newline = false;
                        state.creation_taken = Some(creation);
                        state.creation_read_at_ms = Some(creation.at_ms);
                        self.facts_out.push((
                            state.path.clone(),
                            state.record_id,
                            store_writers::ReaderFacts {
                                creation_read_at_ms: Some(creation.at_ms),
                                ..Default::default()
                            },
                        ));
                        state.consumed_bound_ms = creation.at_ms.saturating_sub(1);
                        in_rewrite = true;
                    }
                    None => {
                        move_to_end(state, &mut file, size);
                        state.consumed_bound_ms = t_before;
                        state.first_announce_ms = None;
                        state.lost_pending = false;
                    }
                }
            }
        }

        // Too far behind: move to the end.
        let pending = size.saturating_sub(state.offset);
        let behind_too_long = state
            .behind_since_ms
            .is_some_and(|since| t_before.saturating_sub(since) > self.config.max_backlog_ms);
        if pending > self.config.max_backlog_bytes || (behind_too_long && pending > 0) {
            self.counters.backlog_skips += 1;
            push_gap(
                state,
                Some(state.consumed_bound_ms),
                t_before,
                CaptureGapReason::Backlog,
                seq,
                &mut self.counters,
            );
            move_to_end(state, &mut file, size);
            state.since_creation = false;
            state.behind_since_ms = None;
            state.consumed_bound_ms = t_before;
            state.first_announce_ms = None;
            state.lost_pending = false;
            state.last_read_ms = t_before;
            state.size_seen = size;
            // What was skipped is the gap: read through from here.
            state.read_through_ms = Some(t_before);
            state.confirmed_through_ms = Some(t_before);
            return false;
        }

        // Read what the pass may read. A pass that starts in the lines that
        // name no process names none for any of its lines.
        let unattributed = state
            .unattributed_until
            .is_some_and(|until| state.offset < until);
        let want = pending.min(self.config.max_pass_bytes) as usize;
        let mut buffer = vec![0u8; want];
        let mut filled = 0usize;
        if want > 0 {
            if file.seek(SeekFrom::Start(state.offset)).is_err() {
                self.counters.read_errors += 1;
                return false;
            }
            while filled < want {
                match file.read(&mut buffer[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        self.counters.read_errors += 1;
                        break;
                    }
                }
            }
        }
        buffer.truncate(filled);
        self.counters.bytes_read += filled as u64;
        let t_after = (self.clock)().max(t_before);

        // The lines, and what the extractor reads in them.
        let mut items: Vec<LineItem> = Vec::new();
        let mut consumed = 0usize;
        let mut oversized = false;
        let mut extractor_failed = false;
        while consumed < buffer.len() {
            let rest = &buffer[consumed..];
            let Some(newline) = rest.iter().position(|byte| *byte == b'\n') else {
                // No line ending in what is left: the rest of a line being
                // dropped, a line longer than the reader takes (also a full
                // pass without any line ending), or a line still being
                // written, which is left for the read that finds its end.
                let pass_was_cut = consumed == 0 && filled == want && (want as u64) < pending;
                if state.discard_until_newline {
                    consumed = buffer.len();
                } else if rest.len() as u64 > self.config.max_line_bytes || pass_was_cut {
                    consumed = buffer.len();
                    state.discard_until_newline = true;
                    oversized = true;
                }
                break;
            };
            let line = &rest[..newline];
            consumed += newline + 1;
            if state.discard_until_newline {
                state.discard_until_newline = false;
                continue;
            }
            if line.len() as u64 > self.config.max_line_bytes {
                oversized = true;
                continue;
            }
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            self.counters.lines_read += 1;
            let extractor = &self.extractor;
            let parse_state = &mut state.parse_state;
            let agent = state.agent.as_str();
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                extractor.extract(parse_state, agent, line, t_after)
            })) {
                Ok(found) => items.extend(found),
                Err(_) => {
                    // The parse state may be anything now: start it over.
                    state.parse_state = E::State::default();
                    extractor_failed = true;
                }
            }
        }
        // The bytes are not kept past this point.
        drop(buffer);
        state.offset += consumed as u64;
        if oversized {
            self.counters.oversized_lines += 1;
            push_gap(
                state,
                Some(state.consumed_bound_ms),
                t_after,
                CaptureGapReason::OversizedLine,
                seq,
                &mut self.counters,
            );
        }

        if extractor_failed {
            self.counters.extractor_panics += 1;
            push_gap(
                state,
                Some(state.consumed_bound_ms),
                t_after,
                CaptureGapReason::ExtractorFailed,
                seq,
                &mut self.counters,
            );
        }
        if consumed > 0 {
            state.last_growth_ms = t_after;
        }

        // When and from whom the lines of this pass arrived.
        let interval_from = state.consumed_bound_ms;
        let spans: Vec<WriterSpan> = state.recent_spans.iter().copied().collect();
        let resolved = resolve_writer(&spans, interval_from, t_after);
        let lost = state.lost_pending || multiple_names || unattributed;
        if unattributed
            && state
                .unattributed_until
                .is_some_and(|until| state.offset >= until)
        {
            state.unattributed_until = None;
        }
        if multiple_names {
            push_gap(
                state,
                Some(interval_from),
                t_after,
                CaptureGapReason::MultipleNames,
                seq,
                &mut self.counters,
            );
        }
        // The first report of a change in the interval: the record's mark
        // or the first operation, whichever is earlier.
        let announce = match (state.first_announce_ms, resolved.first_ms) {
            (Some(mark), Some(first)) => Some(mark.min(first)),
            (mark, first) => mark.or(first),
        }
        .map(|at| at.max(interval_from).min(t_after));
        let announced = announce.is_some() && !lost;
        let arrival_from = if announced {
            announce.unwrap_or(interval_from)
        } else {
            interval_from
        };
        if consumed > 0 {
            if lost && !multiple_names && !unattributed {
                push_gap(
                    state,
                    Some(interval_from),
                    t_after,
                    CaptureGapReason::EventsLost,
                    seq,
                    &mut self.counters,
                );
            } else if !announced && !multiple_names && !unattributed {
                self.counters.unannounced_reads += 1;
                push_gap(
                    state,
                    Some(interval_from),
                    t_after,
                    CaptureGapReason::Unannounced,
                    seq,
                    &mut self.counters,
                );
            } else {
                record_latency(&mut self.counters, t_after.saturating_sub(arrival_from));
            }
        }
        for item in items {
            match item {
                LineItem::Call { key, call } => {
                    let id = self.next_call_id;
                    self.next_call_id += 1;
                    self.counters.calls_captured += 1;
                    if let Some(key) = key {
                        if state.pending_results.len() >= MAX_PENDING_RESULTS {
                            state.pending_results.pop_front();
                        }
                        state.pending_results.push_back((key_hash(&key), id));
                    }
                    state.calls.push_back(HeldCall {
                        entry: CapturedCall {
                            id,
                            path: state.path.clone(),
                            agent: state.agent.clone(),
                            arrival_from_ms: arrival_from,
                            announced,
                            arrived_at_ms: t_after,
                            result_arrived_at_ms: None,
                            writer: if lost { None } else { resolved.writer },
                            writers_differ: !lost && resolved.differ,
                            writer_final: lost,
                            in_rewrite,
                            call,
                            changed_seq: seq,
                        },
                        interval_from_ms: interval_from,
                        lost,
                    });
                }
                LineItem::Result { key, call } => {
                    let hash = key_hash(&key);
                    let Some(position) = state
                        .pending_results
                        .iter()
                        .position(|(pending, _)| *pending == hash)
                    else {
                        continue;
                    };
                    let Some((_, id)) = state.pending_results.remove(position) else {
                        continue;
                    };
                    if let Some(held) = state.calls.iter_mut().find(|held| held.entry.id == id) {
                        held.entry.result_arrived_at_ms = Some(t_after);
                        if let Some(call) = call {
                            held.entry.call = call;
                        }
                        held.entry.changed_seq = seq;
                        self.counters.results_paired += 1;
                    }
                }
                LineItem::Withdrawn { key } => {
                    let hash = key_hash(&key);
                    let Some(position) = state
                        .pending_results
                        .iter()
                        .position(|(pending, _)| *pending == hash)
                    else {
                        continue;
                    };
                    if let Some((_, id)) = state.pending_results.remove(position) {
                        state.calls.retain(|held| held.entry.id != id);
                    }
                }
                LineItem::FirstUserTurn => {
                    // Stamped once, and only when its arrival is measured:
                    // read as appended to a file read since its creation,
                    // naming a process, outside any gap.
                    if !state.first_user_turn_seen {
                        state.first_user_turn_seen = true;
                        if announced
                            && !lost
                            && !unattributed
                            && !multiple_names
                            && !in_rewrite
                            && state.since_creation
                        {
                            state.first_user_turn = Some(CaptureArrival {
                                arrival_from_ms: arrival_from,
                                arrived_at_ms: t_after,
                            });
                        }
                    }
                }
                LineItem::Headless(headless) => {
                    state.headless = Some(headless);
                }
            }
        }

        // Where the next pass starts. More is to be read when this pass was
        // cut by its size and made progress.
        let more = filled == want && (want as u64) < pending && consumed > 0;
        if state.offset >= size {
            // Everything was read: what comes next was written after this
            // pass began.
            state.consumed_bound_ms = t_before;
            state.first_announce_ms = None;
            state.lost_pending = false;
        }
        // Otherwise bytes are left (a line still being written, or more
        // than one pass reads): they may predate this pass, so the bound and
        // what was reported for them stay.
        state.behind_since_ms = if more {
            Some(state.behind_since_ms.unwrap_or(t_before))
        } else {
            None
        };
        if !more {
            // Every complete line written before this pass began was read,
            // or lies in a gap.
            state.read_through_ms = Some(t_before);
            state.confirmed_through_ms = Some(
                state
                    .confirmed_through_ms
                    .map_or(t_before, |known| known.max(t_before)),
            );
        }
        state.prefix_digest = prefix_digest(&mut file, state.offset);
        state.size_seen = size;
        state.last_read_ms = t_after;
        // Reports older than any line still to be named are dropped.
        let keep_from = t_after.saturating_sub(self.config.late_report_ms.saturating_mul(2));
        while state
            .recent_spans
            .front()
            .is_some_and(|span| span.last_ms < keep_from && span.last_ms < state.consumed_bound_ms)
        {
            state.recent_spans.pop_front();
        }
        more
    }

    /// Keep per transcript the calls no reader asked past yet, and of the
    /// others the most recent `max_calls_per_file`; overall, at most
    /// [`MAX_UNREAD_CALLS`] of the former.
    fn trim_calls(&mut self, path: &str, acked_seq: u64) {
        let max_read = self.config.max_calls_per_file;
        let mut dropped: Vec<u64> = Vec::new();
        if let Some(state) = self.files.get_mut(path) {
            loop {
                let read = state
                    .calls
                    .iter()
                    .filter(|held| held.entry.changed_seq <= acked_seq)
                    .count();
                if read <= max_read {
                    break;
                }
                let Some(position) = state
                    .calls
                    .iter()
                    .position(|held| held.entry.changed_seq <= acked_seq)
                else {
                    break;
                };
                if let Some(held) = state.calls.remove(position) {
                    dropped.push(held.entry.arrived_at_ms);
                }
            }
        }
        // The overall bound on what no reader asked past.
        loop {
            let unread: usize = self
                .files
                .values()
                .map(|state| {
                    state
                        .calls
                        .iter()
                        .filter(|held| held.entry.changed_seq > acked_seq)
                        .count()
                })
                .sum();
            if unread <= MAX_UNREAD_CALLS {
                break;
            }
            let oldest = self
                .files
                .iter()
                .filter_map(|(path, state)| {
                    state
                        .calls
                        .iter()
                        .filter(|held| held.entry.changed_seq > acked_seq)
                        .map(|held| held.entry.id)
                        .min()
                        .map(|id| (id, path.clone()))
                })
                .min();
            let Some((id, owner)) = oldest else {
                break;
            };
            let seq = self.bump();
            if let Some(state) = self.files.get_mut(&owner) {
                if let Some(position) = state.calls.iter().position(|held| held.entry.id == id) {
                    if let Some(held) = state.calls.remove(position) {
                        self.counters.calls_dropped += 1;
                        let at = held.entry.arrived_at_ms;
                        state.calls_before_ms =
                            Some(state.calls_before_ms.map_or(at, |known| known.max(at)));
                        state.changed_seq = seq;
                        push_gap(
                            state,
                            Some(held.interval_from_ms),
                            at,
                            CaptureGapReason::CallsDropped,
                            seq,
                            &mut self.counters,
                        );
                    }
                }
            }
        }
        if !dropped.is_empty() {
            let seq = self.bump();
            if let Some(state) = self.files.get_mut(path) {
                let newest = dropped.into_iter().max().unwrap_or(0);
                state.calls_before_ms = Some(
                    state
                        .calls_before_ms
                        .map_or(newest, |known| known.max(newest)),
                );
                state.changed_seq = seq;
            }
        }
    }

    /// Everything held, as published.
    pub fn view(&self) -> CaptureView {
        let mut files: Vec<CapturedFile> = Vec::with_capacity(self.files.len());
        let mut calls: Vec<CapturedCall> = Vec::new();
        let mut gaps: Vec<CaptureGap> = Vec::new();
        for state in self.files.values() {
            files.push(CapturedFile {
                path: state.path.clone(),
                agent: state.agent.clone(),
                status: state.status(),
                record_id: state.record_id,
                since_creation: state.since_creation,
                creation_contradicted: state.creation_contradicted,
                watching_since_ms: state.watching_since_ms,
                read_through_ms: state.read_through_ms,
                last_read_ms: state.last_read_ms,
                offset: state.offset,
                rewrites: state.rewrites,
                multiple_names: state.multiple_names,
                multiple_names_seen: state.multiple_names_seen,
                calls_before_ms: state.calls_before_ms,
                first_user_turn: state.first_user_turn,
                headless: state.headless,
                changed_seq: state.changed_seq,
            });
            calls.extend(state.calls.iter().map(|held| held.entry.clone()));
            gaps.extend(state.gaps.iter().cloned());
        }
        files.sort_by_key(|file| file.changed_seq);
        calls.sort_by_key(|call| (call.changed_seq, call.id));
        gaps.sort_by_key(|gap| gap.changed_seq);
        CaptureView {
            instance: self.instance.clone(),
            running: true,
            started_at_ms: self.started_at_ms,
            seq: self.seq,
            files,
            calls,
            gaps,
            counters: self.counters,
            files_held: self.files_held(),
            watermark_ms: self.watermark_ms,
            record_instance: self.record_instance.clone().unwrap_or_default(),
            record_seq: self.record_seq,
            record_taken_at_ms: self.record_taken_at_ms,
        }
    }
}

/// The one process the spans report an operation of since `since_ms` that
/// sets a file's content or puts a file at the path; `None` for none, or
/// for more than one.
fn replacing_writer(spans: &VecDeque<WriterSpan>, since_ms: u64) -> Option<WriterInstance> {
    let explaining = ops::CREATE | ops::TRUNCATE | ops::RENAME_TO | ops::CLONE | ops::EXCHANGE;
    let mut found: Option<WriterInstance> = None;
    for span in spans
        .iter()
        .filter(|span| span.ops & explaining != 0 && span.last_ms >= since_ms)
    {
        match found {
            None => found = Some(span.writer),
            Some(known) if known != span.writer => return None,
            Some(_) => {}
        }
    }
    found
}

/// A file's identity from its metadata, where the metadata carries it.
#[cfg(unix)]
fn metadata_identity(meta: &std::fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity {
        volume: meta.dev(),
        index: meta.ino(),
    })
}

/// A file's identity from its metadata, where the metadata carries it (not
/// here: the sweep compares the size only).
#[cfg(not(unix))]
fn metadata_identity(_meta: &std::fs::Metadata) -> Option<FileIdentity> {
    None
}

/// The account that owns a file (its uid).
#[cfg(unix)]
fn metadata_owner(meta: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(meta.uid())
}

/// The account that owns a file: no uid here.
#[cfg(not(unix))]
fn metadata_owner(_meta: &std::fs::Metadata) -> Option<u32> {
    None
}

/// Which process the reports name for the interval `(from_ms, until_ms]`.
struct ResolvedWriter {
    writer: Option<WriterInstance>,
    differ: bool,
    /// The first report in the interval.
    first_ms: Option<u64>,
}

fn resolve_writer(spans: &[WriterSpan], from_ms: u64, until_ms: u64) -> ResolvedWriter {
    let content = ops::CREATE | ops::WRITE | ops::REPLACING | ops::LINK;
    let mut writer: Option<WriterInstance> = None;
    let mut differ = false;
    let mut first_ms: Option<u64> = None;
    for span in spans {
        if span.ops & content == 0 || span.last_ms < from_ms || span.first_ms > until_ms {
            continue;
        }
        first_ms = Some(first_ms.map_or(span.first_ms, |known| known.min(span.first_ms)));
        match writer {
            None => writer = Some(span.writer),
            Some(known) if known != span.writer => differ = true,
            Some(_) => {}
        }
    }
    ResolvedWriter {
        writer: if differ { None } else { writer },
        differ,
        first_ms,
    }
}

fn record_latency(counters: &mut CaptureCounters, latency_ms: u64) {
    let bucket = LATENCY_BUCKET_LIMITS_MS
        .iter()
        .position(|limit| latency_ms <= *limit)
        .unwrap_or(LATENCY_BUCKET_LIMITS_MS.len());
    counters.latency_ms_buckets[bucket] += 1;
    counters.latency_ms_max = counters.latency_ms_max.max(latency_ms);
}

/// Whether the file's own creation time, where the filesystem gives one,
/// lies within `slack_ms` of the creation recorded for it. A filesystem
/// that gives none does not contradict the record.
fn creation_time_agrees(meta: &std::fs::Metadata, recorded_ms: u64, slack_ms: u64) -> bool {
    match meta.created().ok().and_then(system_time_ms) {
        Some(born_ms) => born_ms.abs_diff(recorded_ms) <= slack_ms,
        None => true,
    }
}

/// The digest of the bytes just before `offset` (at most
/// [`PREFIX_DIGEST_BYTES`] of them). `None` at offset 0 and when they cannot
/// be read.
fn prefix_digest(file: &mut std::fs::File, offset: u64) -> Option<[u8; 32]> {
    if offset == 0 {
        return None;
    }
    let length = offset.min(PREFIX_DIGEST_BYTES);
    file.seek(SeekFrom::Start(offset - length)).ok()?;
    let mut bytes = vec![0u8; length as usize];
    file.read_exact(&mut bytes).ok()?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    Some(digest)
}

/// Whether the bytes just before `offset` are the ones whose digest is
/// held. At offset 0 there is nothing to compare.
fn prefix_matches(file: &mut std::fs::File, offset: u64, held: Option<[u8; 32]>) -> bool {
    if offset == 0 {
        return true;
    }
    match held {
        Some(held) => prefix_digest(file, offset) == Some(held),
        // No digest was taken at this offset: the content cannot be told
        // from another one.
        None => false,
    }
}

/// Stand at the end of the file: nothing before it is read. When the file
/// does not end with a line ending, the reader stands inside a line.
fn move_to_end<S>(state: &mut FileState<S>, file: &mut std::fs::File, size: u64) {
    state.offset = size;
    state.discard_until_newline = false;
    if size > 0 {
        let mut last = [0u8; 1];
        let ends_a_line = file.seek(SeekFrom::Start(size - 1)).is_ok()
            && file.read_exact(&mut last).is_ok()
            && last[0] == b'\n';
        state.discard_until_newline = !ends_a_line;
    }
    state.prefix_digest = prefix_digest(file, size);
}

fn push_gap<S>(
    state: &mut FileState<S>,
    from_ms: Option<u64>,
    until_ms: u64,
    reason: CaptureGapReason,
    seq: u64,
    counters: &mut CaptureCounters,
) {
    counters.gaps += 1;
    // The reason and the agent: never the path, never a line.
    tracing::debug!(
        "transcript reader: gap ({:?}) in a {} transcript",
        reason,
        state.agent
    );
    state.gaps.push(CaptureGap {
        path: state.path.clone(),
        agent: state.agent.clone(),
        from_ms,
        until_ms: until_ms.max(from_ms.unwrap_or(0)),
        reason,
        replaced_by: None,
        changed_seq: seq,
    });
    // Bounded: the two oldest merge into one that covers both.
    while state.gaps.len() > MAX_GAPS_PER_FILE {
        let second = state.gaps.remove(1);
        let first = &mut state.gaps[0];
        first.from_ms = match (first.from_ms, second.from_ms) {
            (Some(left), Some(right)) => Some(left.min(right)),
            _ => None,
        };
        first.until_ms = first.until_ms.max(second.until_ms);
        if first.replaced_by != second.replaced_by {
            first.replaced_by = None;
        }
        first.changed_seq = seq;
    }
}

// ---------------------------------------------------------------------------
// The published view and the thread
// ---------------------------------------------------------------------------

/// Everything the reader holds, as published after each change.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureView {
    pub instance: String,
    pub running: bool,
    pub started_at_ms: u64,
    pub seq: u64,
    pub files: Vec<CapturedFile>,
    pub calls: Vec<CapturedCall>,
    pub gaps: Vec<CaptureGap>,
    pub counters: CaptureCounters,
    pub files_held: usize,
    pub watermark_ms: Option<u64>,
    pub record_instance: String,
    pub record_seq: u64,
    pub record_taken_at_ms: u64,
}

impl CaptureView {
    fn stopped() -> Self {
        Self {
            instance: String::new(),
            running: false,
            started_at_ms: 0,
            seq: 0,
            files: Vec::new(),
            calls: Vec::new(),
            gaps: Vec::new(),
            counters: CaptureCounters::default(),
            files_held: 0,
            watermark_ms: None,
            record_instance: String::new(),
            record_seq: 0,
            record_taken_at_ms: 0,
        }
    }

    /// What changed after `since_seq` for a reader that last read
    /// `instance` (anything else: everything), at most
    /// [`MAX_CALLS_PER_REPLY`] calls, cut between two sequence numbers
    /// only: the calls one pass read share one, and a group larger than the
    /// bound is served whole. The calls whose writer is not final yet are
    /// not served: they come with the reply after they are. The watermark
    /// (`served_at_ms`), and the read-through of each file, end before the
    /// earliest arrival of a call held back or not final yet.
    pub fn batch_since(&self, instance: &str, since_seq: u64) -> CaptureReply {
        if !self.running {
            return CaptureReply::not_running();
        }
        let since_seq = if instance == self.instance {
            since_seq
        } else {
            0
        };
        // The view holds its calls in order of their sequence number.
        let changed_calls: Vec<&CapturedCall> = self
            .calls
            .iter()
            .filter(|call| call.changed_seq > since_seq)
            .collect();
        let mut end = changed_calls.len();
        if end > MAX_CALLS_PER_REPLY {
            let boundary = changed_calls[MAX_CALLS_PER_REPLY].changed_seq;
            end = changed_calls[..MAX_CALLS_PER_REPLY]
                .iter()
                .take_while(|call| call.changed_seq < boundary)
                .count();
            if end == 0 {
                let first = changed_calls[0].changed_seq;
                end = changed_calls
                    .iter()
                    .take_while(|call| call.changed_seq == first)
                    .count();
            }
        }
        let held_back = &changed_calls[end..];
        let more = !held_back.is_empty();
        let seq = if more {
            changed_calls[end - 1].changed_seq
        } else {
            self.seq
        };
        // What the calls held back, and those whose writer is not final,
        // could have arrived from: what this reply covers ends just before.
        let not_final = || self.calls.iter().filter(|call| !call.writer_final);
        let open_from = |path: Option<&str>| {
            held_back
                .iter()
                .copied()
                .chain(not_final())
                .filter(|call| path.is_none_or(|path| call.path == path))
                .map(|call| call.arrival_from_ms)
                .min()
        };
        let cut = |through: Option<u64>, from: Option<u64>| match (through, from) {
            (Some(through), Some(from)) => Some(through.min(from.saturating_sub(1))),
            (through, _) => through,
        };
        let transcripts = self
            .files
            .iter()
            .filter(|file| file.changed_seq > since_seq && file.changed_seq <= seq)
            .map(|file| {
                let mut file = file.clone();
                file.read_through_ms = cut(file.read_through_ms, open_from(Some(&file.path)));
                let gaps = self
                    .gaps
                    .iter()
                    .filter(|gap| gap.path == file.path)
                    .map(CaptureGap::to_wire)
                    .collect();
                file.to_wire(gaps)
            })
            .collect();
        let calls = changed_calls[..end]
            .iter()
            .filter(|call| call.writer_final)
            .map(|call| call.to_wire())
            .collect();
        CaptureReply {
            instance: self.instance.clone(),
            running: true,
            started_at_ms: self.started_at_ms,
            seq,
            more,
            counters: self.counters,
            heartbeat_ms: 0,
            record_instance: self.record_instance.clone(),
            record_seq: self.record_seq,
            record_taken_at_ms: self.record_taken_at_ms,
            files_held: self.files_held,
            batch: wire::CaptureBatch {
                capture_instance: self.instance.clone(),
                served_at_ms: cut(self.watermark_ms, open_from(None)).unwrap_or(0),
                stores: Vec::new(),
                transcripts,
                calls,
            },
        }
    }
}

static VIEW: Lazy<ArcSwap<CaptureView>> =
    Lazy::new(|| ArcSwap::from_pointee(CaptureView::stopped()));
static RUNNING: AtomicBool = AtomicBool::new(false);
static GENERATION: AtomicU64 = AtomicU64::new(0);
/// The sequence number readers asked past, for the running instance.
static ACKED_SEQ: AtomicU64 = AtomicU64::new(0);
/// When the thread last made progress (epoch milliseconds).
static HEARTBEAT_MS: AtomicU64 = AtomicU64::new(0);

/// Start the reader thread with `extractor`. `false` when it already runs
/// or the thread could not be spawned.
pub fn start<E: CallExtractor>(extractor: E, config: CaptureConfig) -> bool {
    if RUNNING.swap(true, Ordering::AcqRel) {
        return false;
    }
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    ACKED_SEQ.store(0, Ordering::Release);
    let spawned = std::thread::Builder::new()
        .name("transcript-capture".into())
        .spawn(move || run(Capture::new(extractor, config), generation));
    if spawned.is_err() {
        RUNNING.store(false, Ordering::Release);
        tracing::warn!("transcript reader: its thread could not be started");
        return false;
    }
    tracing::info!("transcript reader: started");
    true
}

/// Stop the reader: what it held is dropped, and [`since`] answers that it
/// does not run.
pub fn stop() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
    let was_running = RUNNING.swap(false, Ordering::AcqRel);
    VIEW.store(Arc::new(CaptureView::stopped()));
    if was_running {
        tracing::info!("transcript reader: stopped");
    }
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Acquire)
}

fn run<E: CallExtractor>(mut capture: Capture<E>, generation: u64) {
    let current = |generation: u64| {
        RUNNING.load(Ordering::Acquire) && GENERATION.load(Ordering::Acquire) == generation
    };
    capture.publishes_heartbeat = true;
    HEARTBEAT_MS.store(store_writers::now_ms(), Ordering::Release);
    VIEW.store(Arc::new(capture.view()));
    let mut published_seq = capture.seq;
    let mut published_watermark = capture.watermark_ms;
    let mut published_record_seq = capture.record_seq;
    while current(generation) {
        HEARTBEAT_MS.store(store_writers::now_ms(), Ordering::Release);
        // Woken by a change or not, the record is asked at every turn: a
        // take it could not give (held) is asked again one slice later. A
        // transcript left behind is read on without waiting.
        let slice = if capture.has_backlog() {
            Duration::ZERO
        } else {
            WAIT_SLICE
        };
        let _ = store_writers::wait_dirty(slice);
        if !current(generation) {
            break;
        }
        let acked = ACKED_SEQ.load(Ordering::Acquire);
        let turn = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(take) = store_writers::take_dirty() {
                capture.handle_take(&take, acked);
            }
            capture.continue_reads(acked);
            capture.sweep_if_due(acked);
            capture.finalize_writers();
        }));
        if turn.is_err() {
            // What the turn left behind may be anything: start over, as a
            // new instance (a reader reads that as a gap for every file).
            capture.start_over();
        }
        // What the reader found goes back to the record, where it outlives
        // this reader's state; the sensor's state is polled (a break in
        // what it delivers is recorded as dropped events).
        for (path, record_id, facts) in capture.take_reader_facts() {
            store_writers::note_reader_facts(&path, record_id, facts);
        }
        let _ = store_writers::sensor();
        let moved = capture.seq != published_seq
            || capture.watermark_ms != published_watermark
            || capture.record_seq != published_record_seq;
        if moved && current(generation) {
            VIEW.store(Arc::new(capture.view()));
            published_seq = capture.seq;
            published_watermark = capture.watermark_ms;
            published_record_seq = capture.record_seq;
        }
    }
}

/// What the reader holds that changed after `since_seq`, for a consumer
/// that last read `instance` (pass an empty one, or another, to read
/// everything). While the reader does not run the reply says so
/// (`running: false`): never an empty list standing for "no call".
pub fn since(instance: &str, since_seq: u64) -> CaptureReply {
    let view = VIEW.load_full();
    let batch = reply(
        &view,
        instance,
        since_seq,
        HEARTBEAT_MS.load(Ordering::Acquire),
        store_writers::now_ms(),
    );
    if batch.running && instance == view.instance {
        ACKED_SEQ.fetch_max(since_seq, Ordering::AcqRel);
    }
    batch
}

/// The reply of [`since`] from a published view, the thread's heartbeat and
/// the time now: a reader whose thread made no progress for
/// [`HEARTBEAT_STALE_MS`] does not run.
fn reply(
    view: &CaptureView,
    instance: &str,
    since_seq: u64,
    heartbeat_ms: u64,
    now_ms: u64,
) -> CaptureReply {
    if view.running && now_ms.saturating_sub(heartbeat_ms) > HEARTBEAT_STALE_MS {
        let mut stalled = CaptureReply::not_running();
        stalled.heartbeat_ms = heartbeat_ms;
        stalled.counters = view.counters;
        return stalled;
    }
    let mut batch = view.batch_since(instance, since_seq);
    batch.heartbeat_ms = heartbeat_ms;
    batch
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    /// The extractor's stand-in: a line `C <key> <program> ...` is a call
    /// whose program is its third word, `R <key>` the result of a call, and
    /// any other line carries nothing. Only the program word is kept.
    struct WordExtractor;

    #[derive(Default)]
    struct WordState {
        lines: u64,
    }

    impl CallExtractor for WordExtractor {
        type State = WordState;

        fn extract(
            &self,
            state: &mut WordState,
            _agent: &str,
            line: &[u8],
            read_at_ms: u64,
        ) -> Vec<LineItem> {
            state.lines += 1;
            let text = String::from_utf8_lossy(line);
            let mut words = text.split(' ');
            let read_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(read_at_ms as i64)
                .unwrap_or_default();
            match (words.next(), words.next(), words.next()) {
                (Some("C"), Some(key), Some(program)) => vec![LineItem::Call {
                    key: Some(key.to_string()),
                    call: ShellCall {
                        programs: vec![program.to_ascii_lowercase()],
                        read_at,
                        ..Default::default()
                    },
                }],
                (Some("R"), Some(key), _) => vec![LineItem::Result {
                    key: key.to_string(),
                    call: None,
                }],
                (Some("U"), _, _) => vec![LineItem::FirstUserTurn],
                (Some("H"), _, _) => vec![LineItem::Headless(true)],
                _ => Vec::new(),
            }
        }
    }

    const HARNESS: WriterInstance = WriterInstance {
        pid: 4_242,
        started_at_ms: Some(1_000),
    };
    const OTHER: WriterInstance = WriterInstance {
        pid: 5_151,
        started_at_ms: Some(2_000),
    };

    fn config() -> CaptureConfig {
        CaptureConfig {
            max_line_bytes: 64,
            max_pass_bytes: 256,
            max_backlog_bytes: 1 << 20,
            max_backlog_ms: 30_000,
            creation_time_slack_ms: 2_000,
            late_report_ms: 15_000,
            max_calls_per_file: 64,
            max_files_held: 64,
            owner_uid: None,
            wake_byte_budget: 1 << 20,
        }
    }

    /// A capture on a clock the test moves, a temporary directory and the
    /// transcript in it. The clock starts at the real time so a file's own
    /// creation time agrees with a creation recorded "now".
    struct Bench {
        capture: Capture<WordExtractor>,
        clock: Arc<AtomicU64>,
        _dir: tempfile::TempDir,
        /// The temporary directory, canonical: the reader does not open a
        /// path through a symbolic link (the system's temporary directory is
        /// one on some platforms).
        base: PathBuf,
        path: PathBuf,
        record_instance: String,
        acked: u64,
        /// What the record keeps of the creation a reader read the file
        /// from (`note_reader_facts`), given with each report.
        creation_read: Option<u64>,
        /// Everything the reader gave back, in order.
        given_back: Vec<store_writers::ReaderFacts>,
    }

    impl Bench {
        fn new(config: CaptureConfig) -> Self {
            let clock = Arc::new(AtomicU64::new(store_writers::now_ms()));
            let reader = Arc::clone(&clock);
            let dir = tempfile::tempdir().expect("temporary directory");
            let base = std::fs::canonicalize(dir.path()).expect("canonical temporary directory");
            let path = base.join("session.jsonl");
            Self {
                capture: Capture::with_clock(
                    WordExtractor,
                    config,
                    Box::new(move || reader.load(Ordering::Acquire)),
                ),
                clock,
                _dir: dir,
                base,
                path,
                record_instance: "record-1".to_string(),
                acked: 0,
                creation_read: None,
                given_back: Vec::new(),
            }
        }

        fn now(&self) -> u64 {
            self.clock.load(Ordering::Acquire)
        }

        /// The reader started after the files of the test were born: a file
        /// it first sees without a creation is taken from its end.
        fn started_after_the_files(&mut self) {
            self.capture.started_at_ms = u64::MAX;
        }

        fn advance(&self, ms: u64) -> u64 {
            self.clock.fetch_add(ms, Ordering::AcqRel) + ms
        }

        fn path_str(&self) -> String {
            self.path.to_string_lossy().to_string()
        }

        fn append(&self, text: &str) {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .expect("open the transcript");
            file.write_all(text.as_bytes()).expect("append");
        }

        fn span(&self, writer: WriterInstance, ops: u32, at_ms: u64) -> WriterSpan {
            WriterSpan {
                writer,
                first_ms: at_ms,
                last_ms: at_ms,
                ops,
            }
        }

        fn dirty(&self, creation: Option<CreationSeen>, spans: Vec<WriterSpan>) -> DirtyFile {
            let dirty_since_ms = spans
                .iter()
                .map(|span| span.first_ms)
                .min()
                .unwrap_or_else(|| self.now());
            DirtyFile {
                path: self.path_str(),
                agent: "claude_code".to_string(),
                kind: StoreFileKind::Transcript,
                record_id: 7,
                first_seen_ms: dirty_since_ms,
                creation,
                last_creation: creation,
                dirty_since_ms,
                spans,
                spans_overflowed: false,
                size_at_close: None,
                identity: None,
                lost: false,
                unlinked: false,
                creation_read_at_ms: self.creation_read,
            }
        }

        fn take(&mut self, file: DirtyFile) {
            let take = DirtyTake {
                instance: self.record_instance.clone(),
                seq: 0,
                configured: true,
                files: vec![file],
            };
            self.capture.handle_take(&take, self.acked);
            self.give_back();
        }

        /// What the reader gave back, kept as the record keeps it.
        fn give_back(&mut self) {
            for (_, _, facts) in self.capture.take_reader_facts() {
                if let Some(at_ms) = facts.creation_read_at_ms {
                    self.creation_read = Some(at_ms);
                }
                self.given_back.push(facts);
            }
        }

        /// Create the transcript, report its creation by the harness, and
        /// let the reader take it: the file is read since its creation.
        fn created_by_harness(&mut self) -> CreationSeen {
            self.append("");
            let creation = CreationSeen {
                writer: HARNESS,
                at_ms: self.now(),
            };
            let span = self.span(HARNESS, ops::CREATE, creation.at_ms);
            self.advance(2);
            self.take(self.dirty(Some(creation), vec![span]));
            creation
        }

        /// Append `text` as `writer`, report the write, read it 2 ms later.
        /// Returns the time of the write.
        fn appended_by(
            &mut self,
            writer: WriterInstance,
            creation: CreationSeen,
            text: &str,
        ) -> u64 {
            let at = self.advance(10);
            self.append(text);
            let span = self.span(writer, ops::WRITE, at);
            self.advance(2);
            self.take(self.dirty(Some(creation), vec![span]));
            at
        }

        fn view(&self) -> CaptureView {
            self.capture.view()
        }

        fn programs(&self) -> Vec<String> {
            let mut calls = self.view().calls;
            calls.sort_by_key(|call| call.id);
            calls
                .iter()
                .map(|call| call.call.programs.first().cloned().unwrap_or_default())
                .collect()
        }

        fn gap_reasons(&self) -> Vec<CaptureGapReason> {
            self.view().gaps.iter().map(|gap| gap.reason).collect()
        }

        fn file(&self) -> CapturedFile {
            self.view()
                .files
                .into_iter()
                .next()
                .expect("the transcript is held")
        }
    }

    #[test]
    fn an_appended_line_is_captured_with_its_arrival_and_its_writer() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        assert!(bench.view().calls.is_empty());
        assert!(bench.file().since_creation);
        assert!(bench.view().gaps.is_empty());

        let wrote_at = bench.appended_by(HARNESS, creation, "C k1 Curl https://x\nplain text\n");
        let view = bench.view();
        assert_eq!(view.calls.len(), 1);
        let call = &view.calls[0];
        assert_eq!(call.agent, "claude_code");
        assert_eq!(call.path, bench.path_str());
        assert_eq!(call.arrival_from_ms, wrote_at);
        assert!(call.announced);
        assert_eq!(call.arrived_at_ms, wrote_at + 2);
        assert_eq!(call.writer, Some(HARNESS));
        assert!(!call.writers_differ && !call.in_rewrite);
        assert_eq!(call.result_arrived_at_ms, None);
        assert_eq!(call.call.programs, vec!["curl".to_string()]);
        assert!(view.gaps.is_empty());
        assert_eq!(view.counters.lines_read, 2);
        assert_eq!(view.counters.calls_captured, 1);
        // Read 2 ms after the write: the second latency bucket.
        assert_eq!(view.counters.latency_ms_buckets[1], 1);
        assert_eq!(view.counters.latency_ms_max, 2);

        // The result line names the read that found it.
        let result_at = bench.appended_by(HARNESS, creation, "R k1\n");
        let view = bench.view();
        assert_eq!(view.calls.len(), 1);
        assert_eq!(view.calls[0].result_arrived_at_ms, Some(result_at + 2));
        assert_eq!(view.counters.results_paired, 1);
        assert!(bench.file().since_creation);
    }

    #[test]
    fn a_burst_is_one_report_and_every_complete_line_is_read() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        let mut text = String::new();
        for i in 0..100 {
            text.push_str(&format!("C k{i} tool{i}\n"));
        }
        // 100 lines in one report: several passes of 256 bytes.
        bench.appended_by(HARNESS, creation, &text);
        let programs = bench.programs();
        assert_eq!(programs.len(), 100);
        assert_eq!(programs[0], "tool0");
        assert_eq!(programs[99], "tool99");
        assert!(bench.view().counters.passes > 2);
        assert!(bench.view().gaps.is_empty());
        assert!(bench
            .view()
            .calls
            .iter()
            .all(|call| call.writer == Some(HARNESS)));
    }

    #[test]
    fn a_line_written_in_several_writes_is_captured_when_its_end_arrives() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        let first_at = bench.appended_by(HARNESS, creation, "C k1 cu");
        assert!(bench.view().calls.is_empty(), "no line ending yet");
        let end_at = bench.appended_by(HARNESS, creation, "rl\n");
        let view = bench.view();
        assert_eq!(bench.programs(), vec!["curl".to_string()]);
        // The interval runs from the first report, and one process wrote.
        assert_eq!(view.calls[0].arrival_from_ms, first_at);
        assert_eq!(view.calls[0].arrived_at_ms, end_at + 2);
        assert_eq!(view.calls[0].writer, Some(HARNESS));

        // The same with two processes in the interval: no writer is named.
        bench.appended_by(HARNESS, creation, "C k2 gi");
        bench.appended_by(OTHER, creation, "t\n");
        let view = bench.view();
        let second = view.calls.iter().find(|call| call.id == 2).unwrap();
        assert_eq!(second.call.programs, vec!["git".to_string()]);
        assert_eq!(second.writer, None);
        assert!(second.writers_differ);
    }

    #[test]
    fn a_line_longer_than_the_bound_is_a_gap_and_the_next_lines_are_read() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        // Longer than a line (64), shorter than a pass (256).
        let long = format!("C big {}\n", "x".repeat(150));
        bench.appended_by(HARNESS, creation, &format!("{long}C k2 ls\n"));
        assert_eq!(bench.programs(), vec!["ls".to_string()]);
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::OversizedLine]);
        assert_eq!(bench.view().counters.oversized_lines, 1);

        // Longer than several passes: dropped across them, then reading
        // goes on at the next line.
        let longer = format!("C huge {}\n", "y".repeat(700));
        bench.appended_by(HARNESS, creation, &format!("{longer}C k3 pwd\n"));
        assert_eq!(bench.programs(), vec!["ls".to_string(), "pwd".to_string()]);
        assert!(bench
            .gap_reasons()
            .iter()
            .all(|reason| *reason == CaptureGapReason::OversizedLine));
    }

    #[test]
    fn a_truncated_file_is_a_rewrite_and_the_captured_calls_stay() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\nC k2 ssh\n");
        assert_eq!(bench.programs().len(), 2);

        // Rewritten shorter, with another call in it.
        let at = bench.advance(10);
        std::fs::write(&bench.path, "C k9 other\n").unwrap();
        let span = bench.span(HARNESS, ops::WRITE, at);
        bench.advance(2);
        bench.take(bench.dirty(Some(creation), vec![span]));
        // The calls read as they arrived stay; the rewritten body is not
        // read; the interval is a gap; the file is no longer read since
        // its creation.
        assert_eq!(
            bench.programs(),
            vec!["curl".to_string(), "ssh".to_string()]
        );
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::Rewrite]);
        let file = bench.file();
        assert_eq!(file.rewrites, 1);
        assert!(!file.since_creation);
        // A rewrite does not contradict the file's recorded creation.
        assert!(!file.creation_contradicted);
        assert_eq!(file.offset, "C k9 other\n".len() as u64);

        // What is appended afterwards is read again.
        bench.appended_by(HARNESS, creation, "C k3 ls\n");
        assert_eq!(
            bench.programs(),
            vec!["curl".to_string(), "ssh".to_string(), "ls".to_string()]
        );
    }

    #[test]
    fn content_changed_before_the_offset_is_a_rewrite_at_the_same_size() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\nC k2 ssh\n");
        // Same length, another call in place of the second line, and a line
        // appended in the same write.
        let at = bench.advance(10);
        std::fs::write(&bench.path, "C k1 curl\nC k2 scp\nC k3 nc\n").unwrap();
        let span = bench.span(HARNESS, ops::WRITE, at);
        bench.advance(2);
        bench.take(bench.dirty(Some(creation), vec![span]));
        assert_eq!(
            bench.programs(),
            vec!["curl".to_string(), "ssh".to_string()]
        );
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::Rewrite]);
        assert_eq!(bench.file().rewrites, 1);
    }

    #[test]
    fn a_reported_truncation_is_a_rewrite_whatever_the_size() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        // Truncated and written again with the same first line and one more:
        // the size is above the offset and the bytes before it are equal.
        let at = bench.advance(10);
        std::fs::write(&bench.path, "C k1 curl\nC k2 nc\n").unwrap();
        let span = bench.span(HARNESS, ops::TRUNCATE | ops::WRITE, at);
        bench.advance(2);
        bench.take(bench.dirty(Some(creation), vec![span]));
        assert_eq!(bench.programs(), vec!["curl".to_string()]);
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::Rewrite]);
        // The report is not held against the appends that follow.
        bench.appended_by(HARNESS, creation, "C k3 ls\n");
        assert_eq!(bench.programs(), vec!["curl".to_string(), "ls".to_string()]);
        assert_eq!(bench.file().rewrites, 1);
    }

    #[test]
    fn another_file_under_the_path_is_read_from_its_start_only_with_its_creation() {
        // Replaced by a rename, no creation reported for the new file.
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let at = bench.advance(10);
        let staged = bench.path.with_extension("tmp");
        std::fs::write(&staged, "C k7 planted\nC k8 planted\n").unwrap();
        std::fs::rename(&staged, &bench.path).unwrap();
        let span = bench.span(OTHER, ops::RENAME_TO, at);
        bench.advance(2);
        bench.take(bench.dirty(Some(creation), vec![span]));
        assert_eq!(bench.programs(), vec!["curl".to_string()]);
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::Replaced]);
        assert!(!bench.file().since_creation);

        // Removed and created again, the creation reported: read from its
        // start, as lines that arrived by replacement.
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let at = bench.advance(10);
        std::fs::remove_file(&bench.path).unwrap();
        std::fs::write(&bench.path, "C k7 wget\n").unwrap();
        let recreation = CreationSeen {
            writer: OTHER,
            at_ms: at,
        };
        let mut dirty = bench.dirty(
            Some(creation),
            vec![bench.span(OTHER, ops::REMOVE | ops::CREATE | ops::WRITE, at)],
        );
        dirty.last_creation = Some(recreation);
        bench.advance(2);
        bench.take(dirty);
        let view = bench.view();
        assert_eq!(
            bench.programs(),
            vec!["curl".to_string(), "wget".to_string()]
        );
        let replaced = view.calls.iter().find(|call| call.id == 2).unwrap();
        assert!(replaced.in_rewrite);
        assert_eq!(replaced.writer, Some(OTHER));
        assert!(
            !view
                .calls
                .iter()
                .find(|call| call.id == 1)
                .unwrap()
                .in_rewrite
        );
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::Replaced]);
        assert!(!bench.file().since_creation);
    }

    #[test]
    fn more_than_a_wake_up_reads_stays_to_read_and_too_far_behind_moves_to_the_end() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        let mut text = String::new();
        for i in 0..400 {
            text.push_str(&format!("C k{i} t{i}\n"));
        }
        // About 4 KiB: more than the passes of one wake-up read.
        bench.appended_by(HARNESS, creation, &text);
        let after_wake = bench.programs().len();
        assert!(after_wake > 0 && after_wake < 400, "{after_wake}");
        assert!(bench.capture.has_backlog());
        // Reading goes on without a new report.
        while bench.capture.has_backlog() {
            bench.capture.continue_reads(0);
        }
        assert_eq!(bench.programs().len(), 400);
        assert!(bench.view().gaps.is_empty());

        // Left behind for longer than the bound: the reader moves to the
        // end, with a gap.
        let mut text = String::new();
        for i in 400..800 {
            text.push_str(&format!("C k{i} t{i}\n"));
        }
        bench.appended_by(HARNESS, creation, &text);
        assert!(bench.capture.has_backlog());
        let held = bench.programs().len();
        bench.advance(31_000);
        bench.capture.continue_reads(0);
        assert!(!bench.capture.has_backlog());
        assert_eq!(bench.programs().len(), held);
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::Backlog]);
        assert_eq!(bench.view().counters.backlog_skips, 1);
        assert!(!bench.file().since_creation);

        // More pending than the byte bound moves to the end at once.
        let mut small = config();
        small.max_backlog_bytes = 512;
        let mut bench = Bench::new(small);
        let creation = bench.created_by_harness();
        let mut text = String::new();
        for i in 0..100 {
            text.push_str(&format!("C k{i} t{i}\n"));
        }
        bench.appended_by(HARNESS, creation, &text);
        assert!(bench.programs().is_empty());
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::Backlog]);
        bench.appended_by(HARNESS, creation, "C last ls\n");
        assert_eq!(bench.programs(), vec!["ls".to_string()]);
    }

    #[test]
    fn dropped_events_leave_the_calls_without_a_writer_and_a_gap() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        let before = bench.now();
        let at = bench.advance(10);
        bench.append("C k1 curl\n");
        let mut dirty = bench.dirty(Some(creation), vec![bench.span(HARNESS, ops::WRITE, at)]);
        dirty.lost = true;
        bench.advance(2);
        bench.take(dirty);
        let view = bench.view();
        assert_eq!(view.calls.len(), 1);
        assert_eq!(view.calls[0].writer, None);
        assert!(!view.calls[0].announced);
        // The interval is the whole time since the previous read.
        assert!(view.calls[0].arrival_from_ms <= before);
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::EventsLost]);
        // A report that arrives later names nobody for that call.
        bench.take(bench.dirty(Some(creation), vec![bench.span(HARNESS, ops::WRITE, at)]));
        assert_eq!(bench.view().calls[0].writer, None);
        // The next append is read as usual.
        bench.appended_by(HARNESS, creation, "C k2 ls\n");
        let view = bench.view();
        assert_eq!(
            view.calls.iter().find(|call| call.id == 2).unwrap().writer,
            Some(HARNESS)
        );
    }

    #[test]
    fn growth_nobody_reported_is_found_by_the_sweep_as_a_gap() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let read_at = bench.now();
        bench.advance(5_000);
        bench.append("C k2 nc\n");
        bench.advance(5);
        bench.capture.sweep(0);
        let view = bench.view();
        let found = view.calls.iter().find(|call| call.id == 2).unwrap();
        assert_eq!(found.writer, None);
        assert!(!found.announced);
        // From the previous read, not from the sweep.
        assert!(found.arrival_from_ms <= read_at);
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::Unannounced]);
        assert_eq!(view.counters.unannounced_reads, 1);
        // A sweep that finds nothing new reads nothing.
        let passes = view.counters.passes;
        bench.advance(5);
        bench.capture.sweep(0);
        assert_eq!(bench.view().counters.passes, passes);
    }

    #[test]
    fn a_file_older_than_the_reader_is_read_from_its_end_on() {
        let mut bench = Bench::new(config());
        bench.started_after_the_files();
        // Content, the last line without its ending, no creation reported,
        // and older than the time a report of its creation could take.
        bench.append("C old rm\nC part");
        let at = bench.advance(20_000);
        bench.take(bench.dirty(None, vec![bench.span(HARNESS, ops::WRITE, at)]));
        assert!(bench.view().calls.is_empty());
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::BeforeCapture]);
        assert_eq!(bench.view().gaps[0].from_ms, None);
        assert!(!bench.file().since_creation);

        // The rest of the line the reader stood in is dropped; the next
        // line is read.
        let at = bench.advance(10);
        bench.append("ial x\nC k1 ls\n");
        bench.advance(2);
        bench.take(bench.dirty(None, vec![bench.span(HARNESS, ops::WRITE, at)]));
        assert_eq!(bench.programs(), vec!["ls".to_string()]);
        assert!(!bench.file().since_creation);
    }

    #[test]
    fn a_new_file_waits_for_the_report_of_its_creation() {
        // The change is noted before the sensor reports the creation.
        let mut bench = Bench::new(config());
        bench.append("C k1 curl\n");
        let created_at = bench.now();
        let noted_at = bench.advance(5);
        let mut noted = bench.dirty(None, Vec::new());
        noted.dirty_since_ms = noted_at;
        bench.take(noted);
        // Not taken yet: nothing read, no gap.
        assert!(bench.view().calls.is_empty());
        assert!(bench.view().gaps.is_empty());
        assert!(!bench.capture.has_backlog());
        bench.capture.continue_reads(0);
        assert!(bench.view().calls.is_empty());

        // The creation arrives two seconds later, with the time it happened.
        bench.advance(2_000);
        let creation = CreationSeen {
            writer: HARNESS,
            at_ms: created_at,
        };
        bench.take(bench.dirty(
            Some(creation),
            vec![bench.span(HARNESS, ops::CREATE | ops::WRITE, created_at)],
        ));
        let view = bench.view();
        assert_eq!(bench.programs(), vec!["curl".to_string()]);
        assert!(bench.file().since_creation);
        assert_eq!(view.calls[0].writer, Some(HARNESS));
        assert!(view.gaps.is_empty());

        // No creation within the bound: the file is taken as one that held
        // content.
        let mut bench = Bench::new(config());
        bench.started_after_the_files();
        bench.append("C k1 curl\n");
        let noted_at = bench.advance(5);
        let mut noted = bench.dirty(None, Vec::new());
        noted.dirty_since_ms = noted_at;
        bench.take(noted);
        bench.advance(14_000);
        bench.capture.continue_reads(0);
        assert!(
            bench.view().gaps.is_empty(),
            "still within the time a report may take"
        );
        bench.advance(2_000);
        bench.capture.continue_reads(0);
        assert!(bench.view().calls.is_empty());
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::BeforeCapture]);
        assert!(!bench.file().since_creation);
        bench.appended_by(
            HARNESS,
            CreationSeen {
                writer: HARNESS,
                at_ms: 0,
            },
            "C k2 ls\n",
        );
        assert_eq!(bench.programs(), vec!["ls".to_string()]);
    }

    #[test]
    fn a_report_that_arrives_after_the_read_names_the_writer() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        // The change is noted without a process (a directory notification),
        // 3 ms after the write; the read follows.
        let wrote_at = bench.advance(10);
        bench.append("C k1 curl\n");
        let noted_at = bench.advance(3);
        let mut noted = bench.dirty(Some(creation), Vec::new());
        noted.dirty_since_ms = noted_at;
        bench.advance(2);
        bench.take(noted);
        let call = bench.view().calls[0].clone();
        assert!(call.announced);
        assert_eq!(call.arrival_from_ms, noted_at);
        assert_eq!(call.writer, None);
        assert!(bench.view().gaps.is_empty());

        // Two seconds later the sensor's report of the write arrives, with
        // the time of the write.
        bench.advance(2_000);
        bench.take(bench.dirty(
            Some(creation),
            vec![bench.span(HARNESS, ops::WRITE, wrote_at)],
        ));
        let named = bench.view().calls[0].clone();
        assert_eq!(named.writer, Some(HARNESS));
        assert_eq!(named.arrival_from_ms, wrote_at);
        assert!(named.changed_seq > call.changed_seq);
        assert_eq!(bench.view().counters.late_reports_applied, 1);
        assert_eq!(bench.view().counters.rewrites, 0);

        // A report of another process in the same interval: no writer.
        bench.advance(1_000);
        bench.take(bench.dirty(
            Some(creation),
            vec![bench.span(OTHER, ops::WRITE, wrote_at + 1)],
        ));
        let contested = bench.view().calls[0].clone();
        assert_eq!(contested.writer, None);
        assert!(contested.writers_differ);

        // Past the window a report changes nothing.
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        let wrote_at = bench.advance(10);
        bench.append("C k1 curl\n");
        let mut noted = bench.dirty(Some(creation), Vec::new());
        noted.dirty_since_ms = bench.advance(3);
        bench.take(noted);
        bench.advance(16_000);
        bench.take(bench.dirty(
            Some(creation),
            vec![bench.span(HARNESS, ops::WRITE, wrote_at)],
        ));
        assert_eq!(bench.view().calls[0].writer, None);
    }

    #[test]
    fn calls_a_reader_asked_past_are_kept_up_to_the_bound_and_the_others_all() {
        let mut small = config();
        small.max_calls_per_file = 4;
        let mut bench = Bench::new(small);
        let creation = bench.created_by_harness();
        for i in 0..6 {
            bench.appended_by(HARNESS, creation, &format!("C k{i} t{i}\n"));
        }
        // No reader asked yet: every call is held.
        assert_eq!(bench.programs().len(), 6);
        assert_eq!(bench.file().calls_before_ms, None);

        // A reader asked past everything: the four most recent stay.
        bench.acked = bench.view().seq;
        let dropped_until = bench
            .view()
            .calls
            .iter()
            .find(|c| c.id == 2)
            .unwrap()
            .arrived_at_ms;
        bench.appended_by(HARNESS, creation, "C k6 t6\n");
        let programs = bench.programs();
        assert_eq!(
            programs,
            vec!["t2", "t3", "t4", "t5", "t6"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>(),
            "four read calls and the one not asked past yet"
        );
        assert_eq!(bench.file().calls_before_ms, Some(dropped_until));
    }

    #[test]
    fn nothing_of_a_line_is_published_but_what_the_extractor_kept() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(
            HARNESS,
            creation,
            "C KEYID77 curl AuthBearer:SECRET_TOKEN_VALUE /private/path\nSECRET_PLAIN_LINE\nR KEYID77 SECRET_RESULT\n",
        );
        // Served once its writer is final.
        bench.advance(config().late_report_ms);
        bench.capture.finalize_writers();
        let view = bench.view();
        assert_eq!(view.calls.len(), 1);
        let reply = view.batch_since("", 0);
        let wire = serde_json::to_string(&reply).unwrap();
        for leaked in [
            "SECRET_TOKEN_VALUE",
            "AuthBearer",
            "/private/path",
            "SECRET_PLAIN_LINE",
            "SECRET_RESULT",
            "KEYID77",
        ] {
            assert!(!wire.contains(leaked), "{leaked} is in the batch");
        }
        // A call is the extractor's value in the wire's fields.
        let call = serde_json::to_value(&reply.batch.calls[0]).unwrap();
        let mut keys: Vec<&str> = call
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "agent_type",
                "arrival_from_ms",
                "arrived_at_ms",
                "call",
                "in_rewrite",
                "result_arrived_at_ms",
                "seq",
                "session_key",
                "transcript_path",
                "writer",
                "writer_final",
                "writers_differ",
            ]
        );
        assert_eq!(reply.batch.calls[0].call.programs, vec!["curl".to_string()]);
        // The reply round-trips on the wire.
        let back: CaptureReply = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, reply);
    }

    #[test]
    fn a_recorded_creation_the_files_own_time_contradicts_is_not_taken() {
        let mut bench = Bench::new(config());
        bench.started_after_the_files();
        bench.append("C k0 planted\n");
        // The record names a creation ten minutes after the file was made.
        let creation = CreationSeen {
            writer: HARNESS,
            at_ms: bench.advance(600_000),
        };
        bench.advance(2);
        bench.take(bench.dirty(
            Some(creation),
            vec![bench.span(HARNESS, ops::CREATE, creation.at_ms)],
        ));
        assert!(bench.view().calls.is_empty());
        assert!(!bench.file().since_creation);
        assert!(bench.file().creation_contradicted);
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::BeforeCapture]);
        // What is appended from now on is read.
        bench.appended_by(HARNESS, creation, "C k1 ls\n");
        assert_eq!(bench.programs(), vec!["ls".to_string()]);
        assert!(!bench.file().since_creation);
        assert!(bench.file().creation_contradicted);
    }

    #[test]
    fn a_new_instance_of_the_record_is_a_gap_and_the_file_is_taken_again() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let last_read = bench.file().last_read_ms;
        // Appended while nothing was recorded, then the record comes back.
        bench.advance(1_000);
        bench.append("C k2 between\n");
        bench.record_instance = "record-2".to_string();
        let at = bench.advance(10);
        bench.append("C k3 nc\n");
        bench.advance(2);
        bench.take(bench.dirty(None, vec![bench.span(HARNESS, ops::WRITE, at)]));
        // The position is kept: what arrived in between is read, named by
        // no process, and the interval since the last read is a gap up to
        // this read: nothing skipped, nothing uncovered.
        assert_eq!(
            bench.programs(),
            vec!["curl".to_string(), "between".to_string(), "nc".to_string()]
        );
        let view = bench.view();
        for call in view.calls.iter().filter(|call| call.id > 1) {
            assert_eq!(call.writer, None);
            assert!(!call.announced);
        }
        let reasons: Vec<CaptureGapReason> = view.gaps.iter().map(|gap| gap.reason).collect();
        assert!(reasons.contains(&CaptureGapReason::RecordRestarted));
        assert!(reasons.contains(&CaptureGapReason::EventsLost));
        assert!(view.gaps.iter().all(|gap| gap.from_ms == Some(last_read)));
        assert!(view.gaps.iter().any(|gap| gap.until_ms >= at));
        assert!(!bench.file().since_creation);
        // Appends are named again from here.
        bench.appended_by(HARNESS, creation, "C k4 ls\n");
        let view = bench.view();
        let ls = view
            .calls
            .iter()
            .find(|call| call.call.programs[0] == "ls")
            .unwrap();
        assert_eq!(ls.writer, Some(HARNESS));
    }

    #[test]
    fn a_removed_file_is_a_gap_and_its_successor_is_read_as_a_replacement() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let at = bench.advance(10);
        std::fs::remove_file(&bench.path).unwrap();
        let mut removed = bench.dirty(Some(creation), vec![bench.span(OTHER, ops::REMOVE, at)]);
        removed.unlinked = true;
        bench.advance(2);
        bench.take(removed);
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::Removed]);
        assert_eq!(bench.programs(), vec!["curl".to_string()]);
        assert!(!bench.file().since_creation);

        // Created again, with its creation reported.
        let at = bench.advance(10);
        bench.append("C k2 wget\n");
        let recreation = CreationSeen {
            writer: OTHER,
            at_ms: at,
        };
        let mut dirty = bench.dirty(
            Some(creation),
            vec![bench.span(OTHER, ops::CREATE | ops::WRITE, at)],
        );
        dirty.last_creation = Some(recreation);
        bench.advance(2);
        bench.take(dirty);
        let view = bench.view();
        let again = view.calls.iter().find(|call| call.id == 2).unwrap();
        assert!(again.in_rewrite);
        assert_eq!(again.writer, Some(OTHER));
        assert!(!bench.file().since_creation);
    }

    #[test]
    fn a_reply_carries_a_bounded_number_of_calls_and_says_when_more_remain() {
        let call = |id: u64| CapturedCall {
            id,
            path: "/t/s.jsonl".to_string(),
            agent: "claude_code".to_string(),
            arrival_from_ms: 1,
            announced: true,
            arrived_at_ms: 2,
            result_arrived_at_ms: None,
            writer: Some(HARNESS),
            writers_differ: false,
            writer_final: true,
            in_rewrite: false,
            call: ShellCall {
                programs: vec!["ls".to_string()],
                ..Default::default()
            },
            changed_seq: id,
        };
        let total = MAX_CALLS_PER_REPLY as u64 + 88;
        let view = CaptureView {
            instance: "capture-1".to_string(),
            running: true,
            started_at_ms: 1,
            seq: total + 5,
            files: vec![CapturedFile {
                path: "/t/s.jsonl".to_string(),
                agent: "claude_code".to_string(),
                status: CapturedFileStatus::Watched,
                record_id: 1,
                since_creation: true,
                creation_contradicted: false,
                watching_since_ms: 1,
                read_through_ms: Some(2),
                last_read_ms: 2,
                offset: 10,
                rewrites: 0,
                multiple_names: false,
                multiple_names_seen: false,
                calls_before_ms: None,
                first_user_turn: None,
                headless: None,
                changed_seq: total + 5,
            }],
            calls: (1..=total).map(call).collect(),
            gaps: vec![CaptureGap {
                path: "/t/s.jsonl".to_string(),
                agent: "claude_code".to_string(),
                from_ms: Some(1),
                until_ms: 2,
                reason: CaptureGapReason::Unannounced,
                replaced_by: None,
                changed_seq: 3,
            }],
            counters: CaptureCounters::default(),
            files_held: 1,
            watermark_ms: None,
            record_instance: String::new(),
            record_seq: 0,
            record_taken_at_ms: 0,
        };
        let first = view.batch_since("capture-1", 0);
        assert!(first.running && first.more);
        assert_eq!(first.batch.calls.len(), MAX_CALLS_PER_REPLY);
        assert_eq!(first.seq, MAX_CALLS_PER_REPLY as u64);
        // The file changed after the part sent: it comes, with its gap,
        // in the next reply.
        assert!(first.batch.transcripts.is_empty());
        let second = view.batch_since("capture-1", first.seq);
        assert!(!second.more);
        assert_eq!(second.batch.calls.len(), 88);
        assert_eq!(second.batch.calls[0].seq, MAX_CALLS_PER_REPLY as u64 + 1);
        assert_eq!(second.seq, total + 5);
        assert_eq!(second.batch.transcripts.len(), 1);
        assert_eq!(second.batch.transcripts[0].gaps.len(), 1);
        assert_eq!(second.batch.transcripts[0].gaps[0].reason, "unannounced");
        assert!(view
            .batch_since("capture-1", second.seq)
            .batch
            .calls
            .is_empty());
        // A reader of another instance is sent everything again.
        assert_eq!(
            view.batch_since("capture-0", total).batch.calls.len(),
            MAX_CALLS_PER_REPLY
        );
        // A reader that does not run says so, whatever is asked.
        let stopped = CaptureView::stopped().batch_since("capture-1", 0);
        assert_eq!(stopped, CaptureReply::not_running());
        assert!(!stopped.running);
    }

    #[test]
    fn the_published_bounds_are_read_with_the_callers_call_count() {
        let from_params = CaptureConfig::from_params(64, Some(501));
        assert_eq!(from_params.owner_uid, Some(501));
        assert_eq!(from_params.max_line_bytes, 4 * 1024 * 1024);
        assert_eq!(from_params.max_pass_bytes, 8 * 1024 * 1024);
        assert_eq!(from_params.max_backlog_bytes, 64 * 1024 * 1024);
        assert_eq!(from_params.max_backlog_ms, 30_000);
        assert_eq!(from_params.creation_time_slack_ms, 2_000);
        assert_eq!(from_params.late_report_ms, 15_000);
        assert_eq!(from_params.max_calls_per_file, 64);
        assert_eq!(CaptureConfig::from_params(0, None).max_calls_per_file, 1);
    }

    /// The thread, on the process-wide store-writer record: a store is
    /// published, a file of it is created and appended to, the operations
    /// are reported as a sensor would, and the call is read. Stopped, the
    /// reader says it does not run.
    #[test]
    #[serial_test::serial(store_writers)]
    fn the_thread_reads_what_the_record_reports_and_stops() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let root = std::fs::canonicalize(dir.path())
            .expect("canonical temporary directory")
            .join("projects");
        std::fs::create_dir_all(root.join("p")).unwrap();
        let path = root.join("p").join("session.jsonl");
        let path_str = path.to_string_lossy().to_string();
        store_writers::configure(&[store_writers::StoreSpec {
            agent: "claude_code".to_string(),
            roots: vec![root.clone()],
            path_segment: String::new(),
            excluded_segments: Vec::new(),
            file_suffixes: vec![".jsonl".to_string()],
            pid_file_roots: Vec::new(),
            pid_file_suffixes: Vec::new(),
            creation_reorder_ms: 1_000,
        }]);
        assert!(!since("", 0).running);
        // Writers final soon after their read: the reply serves final calls.
        let quick = CaptureConfig {
            late_report_ms: 50,
            ..config()
        };
        assert!(start(WordExtractor, quick));
        assert!(!start(WordExtractor, config()), "one reader at a time");
        assert!(is_running());

        let report = |ops: u32| {
            store_writers::record(&store_writers::Operation {
                path: &path_str,
                ops,
                pid: HARNESS.pid,
                started_at_ms: HARNESS.started_at_ms,
                process_path: "/opt/harness/bin/harness",
                at_ms: store_writers::now_ms(),
                size: None,
                identity: None,
            });
        };
        std::fs::write(&path, "").unwrap();
        report(ops::CREATE);
        std::thread::sleep(Duration::from_millis(50));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"C k1 curl\n")
            .unwrap();
        report(ops::WRITE);

        let mut batch = since("", 0);
        for _ in 0..100 {
            if !batch.batch.calls.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
            batch = since("", 0);
        }
        assert!(batch.running);
        assert_eq!(batch.batch.calls.len(), 1, "the appended call is read");
        assert_eq!(batch.batch.calls[0].writer, Some(wire_identity(HARNESS)));
        assert_eq!(batch.batch.calls[0].writer_final, Some(true));
        assert_eq!(batch.batch.calls[0].transcript_path, path_str);
        // Asked again from the reply's sequence number: nothing new.
        let again = since(&batch.instance, batch.seq);
        assert!(again.running && again.batch.calls.is_empty());

        stop();
        assert!(!is_running());
        // Not running; the reply keeps the thread's last heartbeat.
        let stopped = since(&batch.instance, 0);
        assert_eq!(
            CaptureReply {
                heartbeat_ms: 0,
                ..stopped
            },
            CaptureReply::not_running()
        );
        store_writers::clear();
    }

    // -- what the reader opens, what it holds, how it survives ----------------

    /// A symbolic link at a store path is not followed: nothing of the file
    /// it points at is read, and the path is a gap.
    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_in_the_store_is_not_followed() {
        let mut bench = Bench::new(config());
        let outside = bench.base.as_path().join("outside-the-store.log");
        std::fs::write(&outside, "C k1 outsideprog\n").unwrap();
        std::os::unix::fs::symlink(&outside, &bench.path).unwrap();
        let creation = CreationSeen {
            writer: OTHER,
            at_ms: bench.now(),
        };
        let span = bench.span(OTHER, ops::CREATE, creation.at_ms);
        bench.advance(2);
        bench.take(bench.dirty(Some(creation), vec![span]));
        assert!(bench.programs().is_empty());
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::NotRegular]);
        assert_eq!(bench.file().status, CapturedFileStatus::Desynced);
        assert_eq!(bench.view().counters.not_regular, 1);

        // A link in a directory component is not followed either where the
        // platform refuses it in any component.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let real = bench.base.as_path().join("real");
            std::fs::create_dir_all(&real).unwrap();
            std::fs::write(real.join("t.jsonl"), "C k1 linkedprog\n").unwrap();
            let linked = bench.base.as_path().join("linked");
            std::os::unix::fs::symlink(&real, &linked).unwrap();
            assert_eq!(
                open_transcript(&linked.join("t.jsonl")).err(),
                Some(OpenRefusal::NotRegular)
            );
            assert!(open_transcript(&real.join("t.jsonl")).is_ok());
        }
    }

    /// A named pipe at a store path neither blocks the reader nor is read.
    #[cfg(unix)]
    #[test]
    fn a_named_pipe_in_the_store_does_not_block_the_reader() {
        let mut bench = Bench::new(config());
        let status = std::process::Command::new("mkfifo")
            .arg(&bench.path)
            .status()
            .unwrap();
        assert!(status.success());
        let creation = CreationSeen {
            writer: OTHER,
            at_ms: bench.now(),
        };
        let span = bench.span(OTHER, ops::CREATE, creation.at_ms);
        bench.advance(2);
        let started = std::time::Instant::now();
        bench.take(bench.dirty(Some(creation), vec![span]));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::NotRegular]);
        // A directory is refused the same way.
        assert_eq!(
            open_transcript(bench.base.as_path()).err(),
            Some(OpenRefusal::NotRegular)
        );
    }

    /// The file opened must be the one the record's latest operation was
    /// made on, when the record reported its identity: another file at the
    /// path is not read until an operation on it is reported.
    #[cfg(unix)]
    #[test]
    fn a_file_the_record_did_not_report_is_not_read() {
        use std::os::unix::fs::MetadataExt;
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let held = std::fs::metadata(&bench.path).unwrap();
        let other = FileId {
            device: held.dev(),
            inode: held.ino() + 1_000_000,
        };
        let at = bench.advance(10);
        bench.append("C k2 nc\n");
        let mut dirty = bench.dirty(Some(creation), vec![bench.span(OTHER, ops::WRITE, at)]);
        dirty.identity = Some(other);
        bench.advance(2);
        bench.take(dirty);
        assert_eq!(bench.programs(), vec!["curl".to_string()]);
        assert_eq!(
            bench.gap_reasons(),
            vec![CaptureGapReason::IdentityMismatch]
        );
        assert_eq!(bench.file().status, CapturedFileStatus::Desynced);
        assert_eq!(bench.view().counters.identity_mismatches, 1);

        // An operation reported on the file at the path: read again.
        let at = bench.advance(10);
        bench.append("C k3 git\n");
        let mut dirty = bench.dirty(Some(creation), vec![bench.span(HARNESS, ops::WRITE, at)]);
        dirty.identity = Some(FileId {
            device: held.dev(),
            inode: held.ino(),
        });
        bench.advance(2);
        bench.take(dirty);
        assert_eq!(bench.file().status, CapturedFileStatus::Watched);
        assert!(bench.programs().contains(&"git".to_string()));
    }

    /// The reader holds a bounded number of files: reports of paths that do
    /// not exist leave nothing held, and beyond the bound
    /// the least recently appended file is released with a gap.
    #[test]
    fn the_files_held_are_bounded() {
        let mut bench = Bench::new(config());
        let files: Vec<DirtyFile> = (0..5_000u64)
            .map(|i| {
                let mut dirty = bench.dirty(None, Vec::new());
                dirty.path = format!("{}/gone-{i}.jsonl", bench.base.as_path().display());
                dirty.record_id = 100 + i;
                dirty
            })
            .collect();
        let take = DirtyTake {
            instance: bench.record_instance.clone(),
            seq: 0,
            configured: true,
            files,
        };
        bench.capture.handle_take(&take, 0);
        assert_eq!(bench.capture.files_held(), 0);
        // Once a reader asked past them, nothing of them is kept.
        let acked = bench.capture.seq;
        bench.capture.release_beyond_bound(acked);
        assert!(bench.view().files.is_empty());

        // Six transcripts and room for four.
        let mut bound = config();
        bound.max_files_held = 4;
        let mut bench = Bench::new(bound);
        let dir = bench.base.clone();
        for i in 0..6u64 {
            let path = dir.join(format!("t{i}.jsonl"));
            std::fs::write(&path, "").unwrap();
            let at = bench.advance(10);
            let creation = CreationSeen {
                writer: HARNESS,
                at_ms: at,
            };
            let mut dirty = bench.dirty(Some(creation), vec![bench.span(HARNESS, ops::CREATE, at)]);
            dirty.path = path.to_string_lossy().to_string();
            dirty.record_id = 10 + i;
            bench.advance(2);
            bench.take(dirty);
        }
        assert_eq!(bench.capture.files_held(), 4);
        assert_eq!(bench.view().counters.released, 2);
        let released: Vec<String> = bench
            .view()
            .files
            .iter()
            .filter(|file| file.status == CapturedFileStatus::Released)
            .map(|file| file.path.clone())
            .collect();
        let first_two: Vec<String> = (0..2)
            .map(|i| {
                dir.join(format!("t{i}.jsonl"))
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        assert_eq!(released, first_two);
        assert_eq!(
            bench
                .view()
                .gaps
                .iter()
                .filter(|gap| gap.reason == CaptureGapReason::Released)
                .count(),
            2
        );
        // Released files wait for a reader: a new instance.
        let instance = bench.view().instance;
        for i in 6..20u64 {
            let path = dir.join(format!("t{i}.jsonl"));
            std::fs::write(&path, "").unwrap();
            let at = bench.advance(10);
            let creation = CreationSeen {
                writer: HARNESS,
                at_ms: at,
            };
            let mut dirty = bench.dirty(Some(creation), vec![bench.span(HARNESS, ops::CREATE, at)]);
            dirty.path = path.to_string_lossy().to_string();
            dirty.record_id = 10 + i;
            bench.advance(2);
            bench.take(dirty);
        }
        assert_ne!(bench.view().instance, instance);
        assert!(bench.view().counters.restarts >= 1);
        assert!(bench.capture.files_held() <= 4);
    }

    struct PanicExtractor;

    impl CallExtractor for PanicExtractor {
        type State = WordState;

        fn extract(
            &self,
            state: &mut WordState,
            agent: &str,
            line: &[u8],
            read_at_ms: u64,
        ) -> Vec<LineItem> {
            if line.starts_with(b"BOOM") {
                panic!("a test extractor fails");
            }
            WordExtractor.extract(state, agent, line, read_at_ms)
        }
    }

    /// A failing extractor is a gap for its file; the lines after it are
    /// read.
    #[test]
    fn an_extractor_that_fails_is_a_gap_and_the_reader_goes_on() {
        let clock = Arc::new(AtomicU64::new(store_writers::now_ms()));
        let reader = Arc::clone(&clock);
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("session.jsonl");
        std::fs::write(&path, "").unwrap();
        let mut capture = Capture::with_clock(
            PanicExtractor,
            config(),
            Box::new(move || reader.load(Ordering::Acquire)),
        );
        let now = clock.load(Ordering::Acquire);
        let creation = CreationSeen {
            writer: HARNESS,
            at_ms: now,
        };
        let dirty = |at: u64| DirtyFile {
            path: path.to_string_lossy().to_string(),
            agent: "claude_code".to_string(),
            kind: StoreFileKind::Transcript,
            record_id: 7,
            first_seen_ms: at,
            creation: Some(creation),
            last_creation: Some(creation),
            dirty_since_ms: at,
            spans: vec![WriterSpan {
                writer: HARNESS,
                first_ms: at,
                last_ms: at,
                ops: ops::WRITE,
            }],
            spans_overflowed: false,
            size_at_close: None,
            identity: None,
            lost: false,
            unlinked: false,
            creation_read_at_ms: None,
        };
        let take = |at: u64| DirtyTake {
            instance: "record-1".to_string(),
            seq: 0,
            configured: true,
            files: vec![dirty(at)],
        };
        clock.fetch_add(2, Ordering::AcqRel);
        capture.handle_take(&take(now), 0);
        let at = clock.fetch_add(10, Ordering::AcqRel) + 10;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"C k1 curl\nBOOM\nC k2 git\n")
            .unwrap();
        clock.fetch_add(2, Ordering::AcqRel);
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        capture.handle_take(&take(at), 0);
        std::panic::set_hook(hook);
        let view = capture.view();
        let programs: Vec<String> = view
            .calls
            .iter()
            .map(|call| call.call.programs[0].clone())
            .collect();
        assert_eq!(programs, vec!["curl".to_string(), "git".to_string()]);
        assert_eq!(view.counters.extractor_panics, 1);
        assert!(view
            .gaps
            .iter()
            .any(|gap| gap.reason == CaptureGapReason::ExtractorFailed));
    }

    /// A reader whose thread made no progress for too long does not run,
    /// whatever its view says.
    #[test]
    fn a_stale_heartbeat_is_a_reader_that_does_not_run() {
        let bench = Bench::new(config());
        let mut view = bench.view();
        view.running = true;
        let now = 1_000_000;
        let fresh = reply(&view, &view.instance, 0, now - 1_000, now);
        assert!(fresh.running);
        assert_eq!(fresh.heartbeat_ms, now - 1_000);
        let stale = reply(&view, &view.instance, 0, now - HEARTBEAT_STALE_MS - 1, now);
        assert!(!stale.running);
        assert!(stale.batch.transcripts.is_empty() && stale.batch.calls.is_empty());
    }

    /// A line written through another name of the file is not named as the
    /// harness's, and the interval is a gap. The name
    /// gone, the file is read as before, and it keeps that it had two.
    #[cfg(unix)]
    #[test]
    fn a_file_with_another_name_names_no_writer_for_what_was_read() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 ls\n");
        let link = bench.base.join("elsewhere.bin");
        std::fs::hard_link(&bench.path, &link).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&link)
            .unwrap()
            .write_all(b"C k2 linked\n")
            .unwrap();
        bench.appended_by(HARNESS, creation, "C k3 git\n");
        let view = bench.view();
        let linked = view
            .calls
            .iter()
            .find(|call| call.call.programs[0] == "linked")
            .expect("the line is read");
        assert_eq!(linked.writer, None);
        assert!(view
            .gaps
            .iter()
            .any(|gap| gap.reason == CaptureGapReason::MultipleNames));
        assert!(bench.file().multiple_names && bench.file().multiple_names_seen);

        std::fs::remove_file(&link).unwrap();
        bench.appended_by(HARNESS, creation, "C k4 make\n");
        let view = bench.view();
        let after = view
            .calls
            .iter()
            .find(|call| call.call.programs[0] == "make")
            .unwrap();
        assert_eq!(after.writer, Some(HARNESS));
        assert!(!bench.file().multiple_names);
        assert!(bench.file().multiple_names_seen);
    }

    // -- "watched, and no call arrived" ---------------------------------------

    /// Every pass that reads up to the end says until when the file was read
    /// through; a pass cut by its size does not. A file taken from its end is
    /// watched from that read, not from its first report.
    #[test]
    fn a_file_is_read_through_the_start_of_the_pass_that_reached_its_end() {
        let mut bench = Bench::new(config());
        bench.started_after_the_files();
        // Older than the time a creation report may take, no creation.
        bench.append("C old rm\n");
        let reported = bench.advance(20_000);
        let read_at = bench.advance(5);
        bench.take(bench.dirty(None, vec![bench.span(HARNESS, ops::WRITE, reported)]));
        let file = bench.file();
        assert_eq!(file.status, CapturedFileStatus::Watched);
        assert_eq!(file.watching_since_ms, read_at);
        assert_eq!(file.read_through_ms, Some(read_at));

        // A pass cut by its size: not read through, until a pass reaches
        // the end.
        let mut small = config();
        small.max_pass_bytes = 64;
        let mut bench = Bench::new(small);
        let creation = bench.created_by_harness();
        let created = bench.file().read_through_ms;
        let mut text = String::new();
        for i in 0..80 {
            text.push_str(&format!("C k{i} tool{i}\n"));
        }
        let at = bench.advance(10);
        bench.append(&text);
        let dirty = bench.dirty(Some(creation), vec![bench.span(HARNESS, ops::WRITE, at)]);
        bench.advance(2);
        bench.take(dirty);
        // A bounded number of passes per wake: not all of it.
        assert!(bench.programs().len() < 80);
        assert_eq!(bench.file().read_through_ms, created);
        let resumed_at = bench.advance(3);
        bench.capture.continue_reads(0);
        bench.capture.continue_reads(0);
        assert_eq!(bench.programs().len(), 80);
        assert_eq!(bench.file().read_through_ms, Some(resumed_at));
    }

    /// Read through the start of a pass, not its end: a line written while
    /// the pass ran may lie after what it read. With a clock that moves at
    /// every reading, the pass that found a line began before it ended.
    #[test]
    fn read_through_is_the_time_a_pass_began() {
        let clock = Arc::new(AtomicU64::new(store_writers::now_ms()));
        let reader = Arc::clone(&clock);
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("session.jsonl");
        std::fs::write(&path, "").unwrap();
        let mut capture = Capture::with_clock(
            WordExtractor,
            config(),
            Box::new(move || reader.fetch_add(1, Ordering::AcqRel) + 1),
        );
        let now = clock.load(Ordering::Acquire);
        let creation = CreationSeen {
            writer: HARNESS,
            at_ms: now,
        };
        let take = |at: u64| DirtyTake {
            instance: "record-1".to_string(),
            seq: 0,
            configured: true,
            files: vec![DirtyFile {
                path: path.to_string_lossy().to_string(),
                agent: "claude_code".to_string(),
                kind: StoreFileKind::Transcript,
                record_id: 7,
                first_seen_ms: now,
                creation: Some(creation),
                last_creation: Some(creation),
                dirty_since_ms: at,
                spans: vec![WriterSpan {
                    writer: HARNESS,
                    first_ms: at,
                    last_ms: at,
                    ops: ops::WRITE,
                }],
                spans_overflowed: false,
                size_at_close: None,
                identity: None,
                lost: false,
                unlinked: false,
                creation_read_at_ms: None,
            }],
        };
        capture.handle_take(&take(now), 0);
        let at = clock.fetch_add(10, Ordering::AcqRel) + 10;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"C k1 curl\n")
            .unwrap();
        capture.handle_take(&take(at), 0);
        let view = capture.view();
        assert_eq!(view.calls.len(), 1);
        let file = &view.files[0];
        let read_through = file.read_through_ms.expect("read through");
        assert!(read_through < view.calls[0].arrived_at_ms);
        assert!(read_through > at);
    }

    /// A file reported and not read yet is pending: never published as
    /// watched, nothing read through.
    #[test]
    fn a_file_waiting_for_its_first_read_is_pending() {
        let mut bench = Bench::new(config());
        bench.append("C k1 curl\n");
        let span = bench.span(HARNESS, ops::WRITE, bench.now());
        bench.advance(2);
        bench.take(bench.dirty(None, vec![span]));
        let file = bench.file();
        assert_eq!(file.status, CapturedFileStatus::Pending);
        assert_eq!(file.read_through_ms, None);
        assert!(bench.view().calls.is_empty());
    }

    /// Each sweep sets the watermark: every watched file was read through
    /// its start, also when nothing changed; a file not read now does not
    /// hold it back, its status says it is not watched.
    #[test]
    fn the_watermark_moves_at_every_sweep() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        assert_eq!(bench.view().watermark_ms, None);
        let first = bench.advance(10_000);
        bench.capture.sweep(0);
        assert_eq!(bench.view().watermark_ms, Some(first));
        // Nothing changed: it moves anyway.
        let second = bench.advance(10_000);
        bench.capture.sweep(0);
        assert_eq!(bench.view().watermark_ms, Some(second));
        // Growth nobody reported: read by the sweep, the watermark moves.
        bench.append("C k2 nc\n");
        let third = bench.advance(10_000);
        bench.capture.sweep(0);
        assert!(bench.programs().contains(&"nc".to_string()));
        assert_eq!(bench.view().watermark_ms, Some(third));
        // Removed: desynced, and the watermark is the sweep's start.
        std::fs::remove_file(&bench.path).unwrap();
        let fourth = bench.advance(10_000);
        bench.capture.sweep(0);
        assert_eq!(bench.file().status, CapturedFileStatus::Desynced);
        assert_eq!(bench.view().watermark_ms, Some(fourth));
    }

    /// A file removed and created again without a reported creation is a
    /// gap from the read that found it gone up to the read that takes it
    /// again, and the sweep takes it again without a
    /// report.
    #[test]
    fn a_file_created_again_without_a_reported_creation_is_a_gap_up_to_its_read() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let at = bench.advance(10);
        std::fs::remove_file(&bench.path).unwrap();
        let mut removed = bench.dirty(Some(creation), vec![bench.span(HARNESS, ops::REMOVE, at)]);
        removed.unlinked = true;
        bench.advance(2);
        bench.take(removed);
        assert_eq!(bench.file().status, CapturedFileStatus::Desynced);
        let again_at = bench.advance(5_000);
        bench.append("C k2 wget\n");
        // No report: the sweep finds it.
        let swept = bench.advance(10_000);
        bench.capture.sweep(0);
        let view = bench.view();
        assert!(view.gaps.iter().any(|gap| {
            gap.reason == CaptureGapReason::Removed
                && gap.from_ms.is_some_and(|from| from <= again_at)
                && gap.until_ms >= again_at
                && gap.until_ms == swept
        }));
        assert_eq!(bench.file().status, CapturedFileStatus::Watched);
    }

    /// A file born after the reader started whose creation was not
    /// recorded is read from its start: its lines name no process, arrive
    /// from the earlier of its birth and its first report, and never make
    /// the file read since its creation. A file too large is taken from its
    /// end.
    #[test]
    fn a_file_born_after_the_reader_started_is_read_from_its_start() {
        let mut bench = Bench::new(config());
        bench.append("C k1 curl\nC k2 ls\n");
        let born = std::fs::metadata(&bench.path)
            .unwrap()
            .created()
            .ok()
            .and_then(system_time_ms);
        let reported = bench.advance(20_000);
        let read_at = bench.advance(5);
        bench.take(bench.dirty(None, vec![bench.span(HARNESS, ops::WRITE, reported)]));
        assert_eq!(bench.programs(), vec!["curl".to_string(), "ls".to_string()]);
        let view = bench.view();
        for call in &view.calls {
            assert_eq!(call.writer, None);
            assert!(!call.announced);
            assert_eq!(call.arrived_at_ms, read_at);
            if let Some(born) = born {
                assert!(call.arrival_from_ms < born.max(1));
            }
        }
        assert!(!bench.file().since_creation);
        assert_eq!(bench.file().status, CapturedFileStatus::Watched);
        assert_eq!(bench.file().watching_since_ms, read_at);
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::BeforeCapture]);
        assert!(view.gaps[0].from_ms.is_some());
        // Lines appended from then on name their process.
        bench.appended_by(
            HARNESS,
            CreationSeen {
                writer: HARNESS,
                at_ms: 0,
            },
            "C k3 git\n",
        );
        let view = bench.view();
        let git = view
            .calls
            .iter()
            .find(|call| call.call.programs[0] == "git")
            .unwrap();
        assert_eq!(git.writer, Some(HARNESS));

        // Too large to read: from its end, as before.
        let mut small = config();
        small.max_backlog_bytes = 8;
        let mut bench = Bench::new(small);
        bench.append("C k1 curl\nC k2 ls\n");
        let reported = bench.advance(20_000);
        bench.advance(5);
        bench.take(bench.dirty(None, vec![bench.span(HARNESS, ops::WRITE, reported)]));
        assert!(bench.programs().is_empty());
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::BeforeCapture]);
        assert_eq!(bench.view().gaps[0].from_ms, None);
    }

    /// A file created again without a reported creation, after the reader
    /// started: its content is read, naming no process, and the time it was
    /// not read is a gap.
    #[test]
    fn a_file_created_again_without_its_creation_is_read_and_a_gap() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let at = bench.advance(10);
        std::fs::remove_file(&bench.path).unwrap();
        let mut removed = bench.dirty(Some(creation), vec![bench.span(HARNESS, ops::REMOVE, at)]);
        removed.unlinked = true;
        bench.advance(2);
        bench.take(removed);
        bench.advance(5_000);
        bench.append("C k2 wget\n");
        bench.advance(10_000);
        bench.capture.sweep(0);
        let view = bench.view();
        let wget = view
            .calls
            .iter()
            .find(|call| call.call.programs[0] == "wget")
            .expect("read from its start");
        assert_eq!(wget.writer, None);
        assert!(view
            .gaps
            .iter()
            .any(|gap| gap.reason == CaptureGapReason::Removed
                && gap.until_ms >= wget.arrival_from_ms));
    }

    // -- round 4: what nothing recorded explains, re-reads, cuts, finality ---

    /// A reported truncation names its process in the rewrite gap; a
    /// rewrite nothing reported names none.
    #[test]
    fn a_rewrite_gap_names_the_one_process_whose_report_explains_it() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let at = bench.advance(10);
        std::fs::write(&bench.path, "C k1 curl\nC k2 nc\n").unwrap();
        let span = bench.span(HARNESS, ops::TRUNCATE | ops::WRITE, at);
        bench.advance(2);
        bench.take(bench.dirty(Some(creation), vec![span]));
        let gap = bench.view().gaps.pop().expect("a rewrite gap");
        assert_eq!(gap.reason, CaptureGapReason::Rewrite);
        assert_eq!(gap.replaced_by, Some(HARNESS));

        // Rewritten shorter with nothing reported but a write by another.
        bench.advance(10);
        let at = bench.advance(10);
        std::fs::write(&bench.path, "C k9 x\n").unwrap();
        bench.advance(2);
        bench.take(bench.dirty(Some(creation), vec![bench.span(OTHER, ops::WRITE, at)]));
        let gap = bench.view().gaps.pop().expect("a second rewrite gap");
        assert_eq!(gap.reason, CaptureGapReason::Rewrite);
        assert_eq!(gap.replaced_by, None);
    }

    /// The `mv` of a prepared directory holding a forged transcript into a
    /// store: no operation on the file is reported, the forged file has the
    /// size of the one it replaces, and the sweep finds another file under
    /// the path by its identity. Nothing of the forged file is read and the
    /// replacement names no process.
    #[cfg(unix)]
    #[test]
    fn a_directory_moved_into_a_store_is_another_file_for_the_sweep() {
        let mut bench = Bench::new(config());
        let store = bench.base.join("projects").join("p");
        std::fs::create_dir_all(&store).unwrap();
        bench.path = store.join("k.jsonl");
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        assert_eq!(bench.programs(), vec!["curl".to_string()]);
        // Prepared elsewhere: the same size, a forged call.
        let prepared = bench.base.join("x").join("p");
        std::fs::create_dir_all(&prepared).unwrap();
        std::fs::write(prepared.join("k.jsonl"), "C k1 sudo\n").unwrap();
        std::fs::rename(&store, bench.base.join("x").join("p.old")).unwrap();
        std::fs::rename(&prepared, &store).unwrap();
        bench.advance(SWEEP_INTERVAL_MS);
        bench.capture.sweep(0);
        let view = bench.view();
        assert_eq!(bench.programs(), vec!["curl".to_string()]);
        let replaced = view
            .gaps
            .iter()
            .find(|gap| gap.reason == CaptureGapReason::Replaced)
            .expect("the sweep finds another file");
        assert_eq!(replaced.replaced_by, None);
        assert!(!bench.file().since_creation);
    }

    /// A reader that starts a new instance (a failing turn does the same)
    /// holds nothing, and the record keeps the creation it read the file
    /// from: the
    /// file is not read "since its creation" again, no old line is served as
    /// arriving now or by the harness, and a gap covers what came before.
    #[test]
    fn a_reader_that_starts_over_serves_no_old_line_as_new() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        assert_eq!(bench.creation_read, Some(creation.at_ms));
        bench.capture.start_over();
        let restarted_at = bench.advance(600_000);
        bench.appended_by(HARNESS, creation, "C k2 git\n");
        let view = bench.view();
        assert!(view
            .calls
            .iter()
            .all(|call| call.call.programs.first().map(String::as_str) != Some("curl")));
        let file = bench.file();
        assert!(!file.since_creation);
        assert!(view.gaps.iter().any(
            |gap| gap.reason == CaptureGapReason::BeforeCapture && gap.until_ms >= restarted_at
        ));
        // What is appended afterwards is read as it arrives.
        bench.appended_by(HARNESS, creation, "C k3 ls\n");
        let ls = bench
            .view()
            .calls
            .into_iter()
            .find(|call| call.call.programs[0] == "ls")
            .expect("read");
        assert_eq!(ls.writer, Some(HARNESS));
    }

    /// Files beyond the bound, about 4,100: the reader releases files and
    /// starts a new instance. The harness's transcript, reported again, is
    /// not read "since its creation" and none of its old lines is served
    /// again by the harness.
    #[test]
    fn a_flood_of_files_is_no_lever_on_old_lines() {
        let mut flood_config = config();
        flood_config.max_files_held = 2_048;
        let mut bench = Bench::new(flood_config);
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let restarts = bench.view().counters.restarts;
        let flood_dir = bench.base.join("flood");
        std::fs::create_dir_all(&flood_dir).unwrap();
        let at = bench.advance(10);
        let mut files = Vec::new();
        for index in 0..4_100 {
            let path = flood_dir.join(format!("f{index}.jsonl"));
            std::fs::write(&path, "").unwrap();
            let mut dirty = bench.dirty(None, vec![bench.span(OTHER, ops::CREATE, at)]);
            dirty.path = path.to_string_lossy().to_string();
            dirty.record_id = 100 + index;
            dirty.creation_read_at_ms = None;
            files.push(dirty);
        }
        bench.advance(2);
        let take = DirtyTake {
            instance: bench.record_instance.clone(),
            seq: 0,
            configured: true,
            files,
        };
        bench.capture.handle_take(&take, 0);
        bench.give_back();
        assert!(bench.view().counters.restarts > restarts);
        bench.appended_by(HARNESS, creation, "C k2 git\n");
        let harness_calls: Vec<CapturedCall> = bench
            .view()
            .calls
            .into_iter()
            .filter(|call| call.path == bench.path_str())
            .collect();
        assert!(harness_calls
            .iter()
            .all(|call| call.call.programs.first().map(String::as_str) != Some("curl")));
        let file = bench
            .view()
            .files
            .into_iter()
            .find(|file| file.path == bench.path_str())
            .expect("held again");
        assert!(!file.since_creation);
    }

    /// A file released, dropped and reported again is read from its start
    /// with every old line naming no process, its arrival from the file's
    /// birth, and a gap over that interval.
    #[test]
    fn a_released_file_taken_again_names_no_process_for_its_old_lines() {
        let mut small = config();
        small.max_files_held = 1;
        let mut bench = Bench::new(small);
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        // Another file takes the only place: the transcript is released,
        // then dropped once a reader asked past it.
        let other = bench.base.join("other.jsonl");
        std::fs::write(&other, "").unwrap();
        let at = bench.advance(10);
        let mut dirty = bench.dirty(None, vec![bench.span(OTHER, ops::CREATE, at)]);
        dirty.path = other.to_string_lossy().to_string();
        dirty.record_id = 9;
        bench.advance(2);
        bench.take(dirty);
        bench.acked = bench.view().seq;
        let at = bench.advance(10);
        let mut again = bench.dirty(None, vec![bench.span(OTHER, ops::WRITE, at)]);
        again.path = other.to_string_lossy().to_string();
        again.record_id = 9;
        bench.take(again);
        // Reported again: read from its start, no process named.
        let reported_at = bench.advance(10);
        bench.append("C k2 git\n");
        bench.take(bench.dirty(
            Some(creation),
            vec![bench.span(HARNESS, ops::WRITE, reported_at)],
        ));
        let calls: Vec<CapturedCall> = bench
            .view()
            .calls
            .into_iter()
            .filter(|call| call.path == bench.path_str())
            .collect();
        let curl = calls
            .iter()
            .find(|call| call.call.programs[0] == "curl")
            .expect("read again from the start");
        assert_eq!(curl.writer, None);
        assert!(!curl.announced);
        assert!(curl.arrival_from_ms < reported_at);
        let file = bench
            .view()
            .files
            .into_iter()
            .find(|file| file.path == bench.path_str())
            .unwrap();
        assert!(!file.since_creation);
    }

    /// A reply is cut between two passes' calls, never inside one pass's,
    /// and a pass's calls beyond the bound are served whole; with calls held
    /// back, the watermark and the read-through end before the earliest of
    /// them.
    #[test]
    fn a_reply_is_cut_between_passes_and_covers_only_what_it_carries() {
        let call = |id: u64, seq: u64, from: u64| CapturedCall {
            id,
            path: "/t/s.jsonl".to_string(),
            agent: "claude_code".to_string(),
            arrival_from_ms: from,
            announced: true,
            arrived_at_ms: from + 1,
            result_arrived_at_ms: None,
            writer: Some(HARNESS),
            writers_differ: false,
            writer_final: true,
            in_rewrite: false,
            call: ShellCall {
                programs: vec!["ls".to_string()],
                ..Default::default()
            },
            changed_seq: seq,
        };
        let file = CapturedFile {
            path: "/t/s.jsonl".to_string(),
            agent: "claude_code".to_string(),
            status: CapturedFileStatus::Watched,
            record_id: 1,
            since_creation: true,
            creation_contradicted: false,
            watching_since_ms: 1,
            read_through_ms: Some(5_000),
            last_read_ms: 5_000,
            offset: 10,
            rewrites: 0,
            multiple_names: false,
            multiple_names_seen: false,
            calls_before_ms: None,
            first_user_turn: None,
            headless: None,
            changed_seq: 2,
        };
        // 500 calls of a first pass (seq 1, arrived from 1,000), 100 of a
        // second (seq 2, from 3,000).
        let mut calls: Vec<CapturedCall> = (1..=500).map(|id| call(id, 1, 1_000)).collect();
        calls.extend((501..=600).map(|id| call(id, 2, 3_000)));
        let view = CaptureView {
            instance: "capture-1".to_string(),
            running: true,
            started_at_ms: 1,
            seq: 2,
            files: vec![CapturedFile {
                changed_seq: 1,
                ..file.clone()
            }],
            calls,
            gaps: Vec::new(),
            counters: CaptureCounters::default(),
            files_held: 1,
            watermark_ms: Some(5_000),
            record_instance: String::new(),
            record_seq: 0,
            record_taken_at_ms: 0,
        };
        let first = view.batch_since("capture-1", 0);
        assert!(first.more);
        assert_eq!(first.batch.calls.len(), 500);
        assert_eq!(first.seq, 1);
        assert_eq!(first.batch.served_at_ms, 2_999);
        assert_eq!(first.batch.transcripts[0].read_through_ms, Some(2_999));
        let second = view.batch_since("capture-1", first.seq);
        assert!(!second.more);
        assert_eq!(second.batch.calls.len(), 100);
        assert_eq!(second.batch.served_at_ms, 5_000);
        // A call whose writer is not final is not served, and the watermark
        // stays before it.
        let mut open = view.clone();
        open.calls[550].writer_final = false;
        let held = open.batch_since("capture-1", first.seq);
        assert_eq!(held.batch.calls.len(), 99);
        assert_eq!(held.batch.served_at_ms, 2_999);
        // One pass of 600 calls: served whole, nothing lost.
        let one_pass = CaptureView {
            calls: (1..=600).map(|id| call(id, 1, 1_000)).collect(),
            ..view.clone()
        };
        let whole = one_pass.batch_since("capture-1", 0);
        assert_eq!(whole.batch.calls.len(), 600);
        assert!(!whole.more);
        assert!(one_pass
            .batch_since("capture-1", whole.seq)
            .batch
            .calls
            .is_empty());
    }

    /// The watermark is the earliest read-through of the watched files: a
    /// file left behind by the bound of its passes keeps it back, whatever
    /// time the sweep ran.
    #[test]
    fn the_watermark_is_held_back_by_a_file_left_behind() {
        let mut small = config();
        small.max_pass_bytes = 64;
        let mut bench = Bench::new(small);
        let creation = bench.created_by_harness();
        let through = bench
            .file()
            .read_through_ms
            .expect("read through its creation");
        let mut text = String::new();
        for index in 0..400 {
            text.push_str(&format!("C k{index} tool{index}\n"));
        }
        let at = bench.advance(10);
        bench.append(&text);
        bench.advance(2);
        bench.take(bench.dirty(Some(creation), vec![bench.span(HARNESS, ops::WRITE, at)]));
        let swept_at = bench.advance(SWEEP_INTERVAL_MS);
        bench.capture.sweep(0);
        let watermark = bench.view().watermark_ms.expect("a sweep ran");
        assert!(watermark < swept_at);
        assert_eq!(watermark, through);
    }

    /// A call's writer stays open until the time a report may take has
    /// passed; then it is final. A report that arrives afterwards for the
    /// line's interval and names another process leaves it with none.
    #[test]
    fn a_writer_is_final_after_the_late_report_bound_and_no_writer_after_it() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        let wrote_at = bench.appended_by(HARNESS, creation, "C k1 ls\n");
        let call = bench.view().calls.pop().unwrap();
        assert_eq!(call.writer, Some(HARNESS));
        assert!(!call.writer_final);
        bench.capture.finalize_writers();
        assert!(!bench.view().calls.pop().unwrap().writer_final);
        bench.advance(config().late_report_ms);
        bench.capture.finalize_writers();
        let call = bench.view().calls.pop().unwrap();
        assert!(call.writer_final);
        assert_eq!(call.writer, Some(HARNESS));
        // Another process's write in the line's interval, reported now.
        bench.take(bench.dirty(
            Some(creation),
            vec![bench.span(OTHER, ops::WRITE, wrote_at)],
        ));
        let call = bench.view().calls.pop().unwrap();
        assert_eq!(call.writer, None);
        assert!(call.writers_differ);
        assert!(call.writer_final);
        assert_eq!(bench.view().counters.late_after_final, 1);
    }

    /// A line read before the report of its write: its writer is the
    /// harness's for now, not final; the report arrives within the bound and
    /// the line has no writer, final once the bound has passed.
    #[test]
    fn a_line_read_before_its_report_is_not_final_until_the_report() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        let harness_at = bench.advance(10);
        bench.append("C k1 ls\n");
        let other_at = bench.advance(1);
        bench.append("C k2 sudo\n");
        bench.advance(2);
        // Only the harness's write was reported at the read.
        bench.take(bench.dirty(
            Some(creation),
            vec![bench.span(HARNESS, ops::WRITE, harness_at)],
        ));
        let sudo = |bench: &Bench| {
            bench
                .view()
                .calls
                .into_iter()
                .find(|call| call.call.programs[0] == "sudo")
                .unwrap()
        };
        assert_eq!(sudo(&bench).writer, Some(HARNESS));
        assert!(!sudo(&bench).writer_final);
        bench.advance(100);
        bench.take(bench.dirty(
            Some(creation),
            vec![bench.span(OTHER, ops::WRITE, other_at)],
        ));
        assert_eq!(sudo(&bench).writer, None);
        bench.advance(config().late_report_ms);
        bench.capture.finalize_writers();
        assert!(sudo(&bench).writer_final);
        assert_eq!(sudo(&bench).writer, None);
    }

    /// A pass that begins before the previous one (the clock moved back) is
    /// a restart of the record for the reader: a gap on every file, and the
    /// lines read next name no process.
    #[test]
    fn a_clock_that_moves_back_is_a_restart_for_the_reader() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 ls\n");
        bench.clock.fetch_sub(60_000, Ordering::AcqRel);
        bench.appended_by(HARNESS, creation, "C k2 git\n");
        let view = bench.view();
        assert_eq!(view.counters.clock_steps, 1);
        assert!(view
            .gaps
            .iter()
            .any(|gap| gap.reason == CaptureGapReason::RecordRestarted));
        let git = view
            .calls
            .iter()
            .find(|call| call.call.programs[0] == "git")
            .unwrap();
        assert_eq!(git.writer, None);
    }

    /// A file owned by another account than the stores' home is not read.
    #[cfg(unix)]
    #[test]
    fn a_file_another_account_owns_is_not_read() {
        use std::os::unix::fs::MetadataExt;
        let probe = tempfile::tempdir().unwrap();
        let mine = std::fs::metadata(probe.path()).unwrap().uid();
        let mut foreign = config();
        foreign.owner_uid = Some(mine.wrapping_add(1));
        let mut bench = Bench::new(foreign);
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 ls\n");
        assert!(bench.programs().is_empty());
        assert_eq!(bench.gap_reasons(), vec![CaptureGapReason::ForeignOwner]);
        assert_eq!(bench.file().status, CapturedFileStatus::Desynced);
        assert!(bench.view().counters.foreign_owner >= 1);

        let mut own = config();
        own.owner_uid = Some(mine);
        let mut bench = Bench::new(own);
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 ls\n");
        assert_eq!(bench.programs(), vec!["ls".to_string()]);
    }

    /// One wake-up reads at most its byte budget across files; a file left
    /// is read on at the next one.
    #[test]
    fn a_wake_up_reads_a_bounded_number_of_bytes_across_files() {
        let mut budget = config();
        budget.wake_byte_budget = 64;
        let mut bench = Bench::new(budget);
        let creation = bench.created_by_harness();
        let second = bench.base.join("second.jsonl");
        std::fs::write(&second, "").unwrap();
        let second_creation = CreationSeen {
            writer: HARNESS,
            at_ms: bench.now(),
        };
        let mut created = bench.dirty(
            Some(second_creation),
            vec![bench.span(HARNESS, ops::CREATE, second_creation.at_ms)],
        );
        created.path = second.to_string_lossy().to_string();
        created.record_id = 8;
        created.creation_read_at_ms = None;
        bench.advance(2);
        bench.take(created);
        // Both files grow by more than the budget in one wake-up.
        let at = bench.advance(10);
        let mut text = String::new();
        for index in 0..10 {
            text.push_str(&format!("C k{index} tool{index}\n"));
        }
        bench.append(&text);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&second)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        let first = bench.dirty(Some(creation), vec![bench.span(HARNESS, ops::WRITE, at)]);
        let mut other = bench.dirty(
            Some(second_creation),
            vec![bench.span(HARNESS, ops::WRITE, at)],
        );
        other.path = second.to_string_lossy().to_string();
        other.record_id = 8;
        bench.advance(2);
        let take = DirtyTake {
            instance: bench.record_instance.clone(),
            seq: 0,
            configured: true,
            files: vec![first, other],
        };
        bench.capture.handle_take(&take, 0);
        assert!(bench.view().counters.wake_budget_cuts >= 1);
        assert!(bench.programs().len() < 20);
        for _ in 0..10 {
            bench.capture.continue_reads(0);
        }
        assert_eq!(bench.programs().len(), 20);
    }

    /// What the reader finds of a file is given back to the record: the
    /// creation it read the file from, and a second name.
    #[cfg(unix)]
    #[test]
    fn the_reader_gives_its_facts_back_to_the_record() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        assert!(bench
            .given_back
            .iter()
            .any(|facts| facts.creation_read_at_ms == Some(creation.at_ms)));
        std::fs::hard_link(&bench.path, bench.base.join("second-name")).unwrap();
        bench.appended_by(HARNESS, creation, "C k1 ls\n");
        assert!(bench.given_back.iter().any(|facts| facts.multiple_names));
    }

    // -- round 5: the wire ------------------------------------------------------

    /// The first user turn is stamped once, when its arrival is measured
    /// (read as appended to a file read since its creation); a turn read
    /// again from the start of a file taken again is never stamped.
    #[test]
    fn the_first_user_turn_is_stamped_once_and_only_when_measured() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        let at = bench.appended_by(HARNESS, creation, "U hello\n");
        let turn = bench.file().first_user_turn.expect("measured");
        assert!(turn.arrival_from_ms <= at && turn.arrived_at_ms >= at);
        bench.appended_by(HARNESS, creation, "U again\n");
        assert_eq!(bench.file().first_user_turn, Some(turn));
        // How the session started, once read.
        bench.appended_by(HARNESS, creation, "H\n");
        assert_eq!(bench.file().headless, Some(true));
        // A reader that starts a new instance reads the file again from its
        // start or its end: the turn is not stamped again.
        bench.capture.start_over();
        bench.advance(600_000);
        bench.appended_by(HARNESS, creation, "C k1 ls\n");
        assert_eq!(bench.file().first_user_turn, None);

        // A file older than the reader: its first turn came before.
        let mut bench = Bench::new(config());
        bench.started_after_the_files();
        bench.append("U before\n");
        let at = bench.advance(10);
        bench.append("C k1 ls\n");
        bench.advance(2);
        bench.take(bench.dirty(None, vec![bench.span(HARNESS, ops::WRITE, at)]));
        // A later turn of the same file, reported with no creation (the
        // record has none for a file older than the sensor).
        let later = bench.advance(10);
        bench.append("U later\n");
        bench.advance(2);
        bench.take(bench.dirty(None, vec![bench.span(HARNESS, ops::WRITE, later)]));
        assert_eq!(bench.file().first_user_turn, None);
    }

    /// A transcript's conversation is keyed by its file name, as the
    /// collectors key it; a subagent's file names its main conversation too.
    #[test]
    fn a_transcript_names_its_conversation_and_a_subagents_its_parent() {
        assert_eq!(
            transcript_session_keys("/h/.claude/projects/p/1234-abcd.jsonl"),
            ("1234-abcd".to_string(), None)
        );
        assert_eq!(
            transcript_session_keys("/h/.claude/projects/p/1234-abcd/subagents/agent-9.jsonl"),
            ("agent-9".to_string(), Some("1234-abcd".to_string()))
        );
        assert_eq!(
            transcript_session_keys(r"C:\Users\u\.cursor\projects\x\agent-transcripts\s1.txt"),
            ("s1".to_string(), None)
        );
    }

    /// The reply's wire batch: transcripts with their keys, coverage and
    /// gaps; final calls with their writer as a process identity.
    #[test]
    fn the_reply_serves_the_wire_batch() {
        let mut bench = Bench::new(config());
        let creation = bench.created_by_harness();
        bench.appended_by(HARNESS, creation, "C k1 curl\n");
        let reply = bench.view().batch_since("", 0);
        // Not final yet: not served, and the watermark stays before it.
        assert!(reply.batch.calls.is_empty());
        bench.advance(config().late_report_ms);
        bench.capture.finalize_writers();
        bench.capture.sweep(0);
        let reply = bench.view().batch_since("", 0);
        assert_eq!(reply.batch.capture_instance, reply.instance);
        let call = &reply.batch.calls[0];
        assert_eq!(call.writer, Some(wire_identity(HARNESS)));
        assert_eq!(call.session_key, "session");
        let transcript = &reply.batch.transcripts[0];
        assert_eq!(transcript.session_key, "session");
        assert_eq!(transcript.coverage, wire::CaptureCoverage::Watched);
        assert!(transcript.watched_from_creation);
        assert!(reply.batch.served_at_ms >= call.arrived_at_ms);
    }
}
