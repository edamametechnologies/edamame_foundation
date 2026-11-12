//! What the transcript capture serves to the session binding: one wire type
//! for the capture's relay (the process that reads the transcripts as they
//! are appended) and for the core's index of shell calls, so both sides read
//! and write the same thing.
//!
//! Compatibility across the helper boundary: no struct here denies unknown
//! fields (a batch from a newer helper still reads), and every field added
//! later is an `Option` (a batch from an older helper still reads).
//!
//! Times are milliseconds since the Unix epoch, on the host's wall clock.

use serde::{Deserialize, Serialize};

use super::launch::ShellCall;

/// The start of a live process as the kernel records it, in milliseconds
/// since the Unix epoch: the one derivation the kernel sensors use for the
/// process records, and the one the capture uses for a transcript's owner
/// and a line's writer, so the two sides read one process alike (flodbadd's
/// `process_events::process_start_ms`; see there what each platform gives).
pub use flodbadd::process_events::process_start_ms;

/// A process instance: its pid and its start as the kernel records it
/// (macOS `start_time` of the process, Linux the start ticks of
/// `/proc/<pid>/stat` with the boot time of `/proc/stat`, Windows the
/// creation time of the process), in milliseconds ([`process_start_ms`]).
/// Never the time a sensor delivered an event. Two readings of one process
/// can still differ by up to about a second on Linux (the boot time is whole
/// seconds and moves with the clock), so they are compared with a tolerance
/// of at least a second. `start_ms` is `None` where the start could not be
/// read (a process gone before the read; on Windows a file whose creator was
/// not recorded); such an instance is compared with no other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ms: Option<u64>,
}

impl ProcessIdentity {
    /// The same process: the same pid and starts that agree within
    /// `tolerance_ms` (the readers' resolutions differ). Unknown when either
    /// start is missing.
    pub fn same_process(&self, other: &ProcessIdentity, tolerance_ms: u64) -> Option<bool> {
        let (a, b) = (self.start_ms?, other.start_ms?);
        Some(self.pid == other.pid && a.abs_diff(b) <= tolerance_ms)
    }
}

/// One shell call the capture read when its line was appended. The times are
/// the capture's; the transcript's own times in `call` are not read, except
/// the start a harness measured for a command it records once it has run
/// (`ShellCall::recorded_after_run`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureCall {
    /// The transcript file the line was appended to.
    pub transcript_path: String,
    /// The conversation the file belongs to ([`CaptureTranscript::session_key`]).
    pub session_key: String,
    pub agent_type: String,
    /// The capture's number for the call within its transcript: a call
    /// served again (its result came back, the relay repeated it) carries the
    /// same number.
    pub seq: u64,
    pub call: ShellCall,
    /// The first write the sensor announced since the capture's previous
    /// read of the file (that read, when no event announced one): the line
    /// was not there before.
    pub arrival_from_ms: u64,
    /// The read that found the line.
    pub arrived_at_ms: u64,
    /// The read that found the call's result. `None` while it has not come
    /// back.
    pub result_arrived_at_ms: Option<u64>,
    /// The one process whose writes cover the interval the line arrived in.
    /// `None` when there were none or several.
    pub writer: Option<ProcessIdentity>,
    /// The line arrived while the file was being rewritten.
    pub in_rewrite: bool,
    /// Another process than `writer` wrote the file in that interval.
    pub writers_differ: bool,
}

/// When the capture read one line: the first write the sensor announced
/// since its previous read of the file (`arrival_from_ms`; the line was not
/// there before) and the read that found it (`arrived_at_ms`). An interval,
/// never a point: the line arrived somewhere in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureArrival {
    pub arrival_from_ms: u64,
    pub arrived_at_ms: u64,
}

/// How far the capture vouches for a followed file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureCoverage {
    /// Every append the sensor announced has been read up to the batch's
    /// `served_at_ms` (the file's own read-through is not earlier).
    Watched,
    /// Followed, its read-through not confirmed yet.
    Pending,
    /// The capture lost its place in the file (a rewrite it could not
    /// follow, lost events) and has not caught up.
    Desynced,
    /// No longer followed.
    Released,
    /// A state this build does not know: read as not covered.
    #[serde(other)]
    Unknown,
}

/// A part of a transcript, or of a store, the capture could not read: what
/// was written between `from_ms` (`None`: any time before) and `until_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureGap {
    pub from_ms: Option<u64>,
    pub until_ms: u64,
    /// Why (`oversized_line`, `rewrite`, `lost_events`, `result_not_found`,
    /// `unmarked_directory`, ...): never read as anything but a gap.
    pub reason: String,
}

/// One transcript file the capture follows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureTranscript {
    pub transcript_path: String,
    /// The conversation the file belongs to. A subagent's file names its own
    /// key here and the main conversation's in `parent_session_key`.
    pub session_key: String,
    /// The main conversation of a subagent's file (Claude Code's Task
    /// subagents write files of their own). `None` for a conversation's own
    /// file. The binding reads a subagent's calls as the main conversation's.
    pub parent_session_key: Option<String>,
    pub agent_type: String,
    /// Since when every line appended to the file has been read.
    pub watched_since_ms: u64,
    /// The capture saw the file created: it holds no line older than
    /// `watched_since_ms`.
    pub watched_from_creation: bool,
    /// A program, not a person, started the session (print or headless
    /// mode), as the harness recorded its own launch in the file (Claude
    /// Code's `entrypoint`, Codex's `session_meta`; read by
    /// `ShellCallReader::headless`). `None` until those lines were read.
    pub headless: Option<bool>,
    /// When the capture read the conversation's first user turn
    /// (`ShellCallLineEvents::first_user_turn`). `None` when that is not
    /// known: the turn came before the capture read the file from its
    /// creation, it lies in a gap (a rewrite, a desync, a release, a restart
    /// of the capture), or it is bounded only by a time a process can set (a
    /// file's birth time).
    pub first_user_turn: Option<CaptureArrival>,
    /// How far the capture vouches for the file.
    pub coverage: CaptureCoverage,
    /// Up to when every append announced on the file has been read. `None`
    /// when not confirmed.
    pub read_through_ms: Option<u64>,
    /// What the capture could not read.
    pub gaps: Vec<CaptureGap>,
}

/// One agent's transcript store as the capture follows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureStore {
    pub agent_type: String,
    /// Since when the capture has read every transcript of the store as it
    /// was appended to.
    pub watched_since_ms: u64,
    /// Times at which a file of the store may have been written unseen (a
    /// directory whose first files came before its watch): the store
    /// vouches for nothing written then.
    pub gaps: Vec<CaptureGap>,
}

/// What one relay of the capture serves.
///
/// `served_at_ms` is the batch's watermark, the contract the binding relies
/// on: the earliest confirmed read-through over the files whose coverage is
/// [`CaptureCoverage::Watched`], capped at the start of the sweep that built
/// the batch, never the time the relay built it. Every append the sensor
/// announced on a watched file before that instant has been read, and each
/// call it carried is in this batch or an earlier one (a capture that holds
/// calls back serves the instant up to which it served them). Files in
/// another state are not covered by it. A process created after
/// `served_at_ms`, less a second of slack, may still have its call on the
/// way: its binding is pending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureBatch {
    /// The capture's own instance: another one (a restart of the process
    /// that runs it) lost what it had not served.
    pub capture_instance: String,
    pub served_at_ms: u64,
    pub stores: Vec<CaptureStore>,
    pub transcripts: Vec<CaptureTranscript>,
    pub calls: Vec<CaptureCall>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A batch from a newer capture, with fields this build does not know,
    /// still reads; one from an older capture without the optional fields
    /// reads with them unset.
    #[test]
    fn a_batch_reads_across_versions() {
        let newer = serde_json::json!({
            "capture_instance": "c", "served_at_ms": 10, "a_later_field": 1,
            "stores": [{"agent_type": "claude_code", "watched_since_ms": 1, "gaps": [],
                        "another": true}],
            "transcripts": [{"transcript_path": "/t.jsonl", "session_key": "k",
                             "parent_session_key": null, "agent_type": "claude_code",
                             "watched_since_ms": 1, "watched_from_creation": true,
                             "headless": false,
                             "first_user_turn": {"arrival_from_ms": 5, "arrived_at_ms": 6,
                                                 "more": 1},
                             "coverage": "a_later_state", "read_through_ms": 9,
                             "gaps": [], "extra": "x"}],
            "calls": [{"transcript_path": "/t.jsonl", "session_key": "k",
                       "agent_type": "claude_code", "seq": 0,
                       "call": {"at": null, "started_at": null, "finished_at": null,
                                "background": false, "programs": ["git"],
                                "read_at": "2026-11-11T10:00:00Z", "time_bounded": false,
                                "recorded_after_run": false},
                       "arrival_from_ms": 3, "arrived_at_ms": 4,
                       "result_arrived_at_ms": null,
                       "writer": {"pid": 7, "start_ms": 2, "more": 0},
                       "in_rewrite": false, "writers_differ": false}]
        });
        let batch: CaptureBatch = serde_json::from_value(newer).expect("a newer batch reads");
        assert_eq!(
            batch.calls[0].writer,
            Some(ProcessIdentity {
                pid: 7,
                start_ms: Some(2)
            })
        );
        // A state this build does not know is not covered.
        assert_eq!(batch.transcripts[0].coverage, CaptureCoverage::Unknown);
        let older = serde_json::json!({
            "capture_instance": "c", "served_at_ms": 10,
            "stores": [{"agent_type": "claude_code", "watched_since_ms": 1, "gaps": []}],
            "transcripts": [{"transcript_path": "/t.jsonl", "session_key": "k",
                             "agent_type": "claude_code", "watched_since_ms": 1,
                             "watched_from_creation": false, "coverage": "pending",
                             "gaps": []}],
            "calls": []
        });
        let batch: CaptureBatch = serde_json::from_value(older).expect("an older batch reads");
        let transcript = &batch.transcripts[0];
        assert_eq!(
            (
                transcript.parent_session_key.as_deref(),
                transcript.headless,
                transcript.first_user_turn,
                transcript.read_through_ms
            ),
            (None, None, None, None)
        );
    }

    #[test]
    fn two_readings_of_one_process_are_compared_by_pid_and_start() {
        let a = ProcessIdentity {
            pid: 7,
            start_ms: Some(1_000),
        };
        assert_eq!(
            a.same_process(
                &ProcessIdentity {
                    pid: 7,
                    start_ms: Some(1_400)
                },
                500
            ),
            Some(true)
        );
        assert_eq!(
            a.same_process(
                &ProcessIdentity {
                    pid: 7,
                    start_ms: Some(9_000)
                },
                500
            ),
            Some(false)
        );
        assert_eq!(
            a.same_process(
                &ProcessIdentity {
                    pid: 8,
                    start_ms: Some(1_000)
                },
                500
            ),
            Some(false)
        );
        assert_eq!(
            a.same_process(
                &ProcessIdentity {
                    pid: 7,
                    start_ms: None
                },
                500
            ),
            None
        );
    }
}
