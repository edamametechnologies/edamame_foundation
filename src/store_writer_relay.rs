//! The store-writer record and the transcript reader for a consumer in
//! another process.
//!
//! The sensors feed `flodbadd::store_writers`, and the reader of
//! `agent_transcripts::capture` runs, in the process that runs the file
//! monitor: the posture daemon standalone, the helper on the app path. The
//! standalone core calls [`store_writers_since`] in process; the app's core
//! asks the helper through the `store_writers_since` order. Either way the
//! consumer passes what it read last ([`StoreWritersCursor`]) and gets what
//! changed since: the rows per file, the shell calls read as they arrived
//! and the intervals that were not read line by line.
//!
//! Reading is not destructive: a consumer that lost its copy asks again
//! from an empty cursor.
use crate::agent_transcripts::capture::{self, CaptureBatch};
use flodbadd::store_writers::{self, StoreWriterRows, StoreWriterSensor};
use serde::{Deserialize, Serialize};

/// What a consumer read last. Empty (the default): nothing yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreWritersCursor {
    /// The record's instance and sequence number of the last reply.
    pub record_instance: String,
    pub rows_seq: u64,
    /// The reader's instance and sequence number of the last reply.
    pub capture_instance: String,
    pub calls_seq: u64,
}

/// Reply of [`store_writers_since`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreWriterBatch {
    /// The rows that changed since the cursor. `None` when the record was
    /// held: nothing was read, ask again with the same cursor. Never an
    /// empty reply standing for "no rows".
    pub rows: Option<StoreWriterRows>,
    /// The calls, gaps and files of the transcript reader that changed
    /// since the cursor. `running: false` while it does not run.
    pub capture: CaptureBatch,
    /// The sensor that feeds the record in the serving process.
    pub sensor: StoreWriterSensor,
    /// When the reply was built (epoch milliseconds, the serving process's
    /// clock: the clock of every time in the reply).
    pub served_at_ms: u64,
}

impl StoreWriterBatch {
    /// The cursor to ask from next: this reply's instances and sequence
    /// numbers; the rows' part of `previous` when the record was held.
    pub fn next_cursor(&self, previous: &StoreWritersCursor) -> StoreWritersCursor {
        let (record_instance, rows_seq) = match &self.rows {
            Some(rows) => (rows.instance.clone(), rows.seq),
            None => (previous.record_instance.clone(), previous.rows_seq),
        };
        StoreWritersCursor {
            record_instance,
            rows_seq,
            capture_instance: self.capture.instance.clone(),
            calls_seq: self.capture.seq,
        }
    }
}

/// What the record and the reader hold that changed since `cursor`. A
/// cursor of another instance than the one running is answered from the
/// start: its sequence numbers were that instance's.
pub fn store_writers_since(cursor: &StoreWritersCursor) -> StoreWriterBatch {
    let rows = match store_writers::rows_since(cursor.rows_seq) {
        Some(rows) if rows.instance == cursor.record_instance => Some(rows),
        Some(_) => store_writers::rows_since(0),
        None => None,
    };
    StoreWriterBatch {
        rows,
        capture: capture::since(&cursor.capture_instance, cursor.calls_seq),
        sensor: store_writers::sensor(),
        served_at_ms: store_writers::now_ms(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flodbadd::store_writers::{ops, Operation, StoreSpec};
    use serial_test::serial;

    fn spec(root: &std::path::Path) -> StoreSpec {
        StoreSpec {
            agent: "claude_code".to_string(),
            roots: vec![root.join("projects")],
            path_segment: String::new(),
            file_suffixes: vec![".jsonl".to_string()],
            pid_file_roots: vec![root.join("sessions")],
            pid_file_suffixes: vec![".json".to_string()],
        }
    }

    fn report(path: &str, operations: u32, pid: u32) {
        store_writers::record(&Operation {
            path,
            ops: operations,
            pid,
            started_at_ms: Some(1_000),
            process_path: "/opt/harness/bin/harness",
            at_ms: store_writers::now_ms(),
            size: None,
        });
    }

    /// A consumer reads everything with an empty cursor, then only what
    /// changed; a cursor of another record instance is answered from the
    /// start; and the reply round-trips on the wire.
    #[test]
    #[serial(store_writers)]
    fn a_batch_follows_the_cursor_and_round_trips() {
        let root = std::env::temp_dir().join(format!("edamame-swr-{}", std::process::id()));
        store_writers::configure(&[spec(&root)]);
        let transcript = root
            .join("projects")
            .join("p")
            .join("s.jsonl")
            .to_string_lossy()
            .to_string();
        let pid_file = root
            .join("sessions")
            .join("4242.json")
            .to_string_lossy()
            .to_string();
        report(&transcript, ops::CREATE, 4_242);
        report(&pid_file, ops::CREATE | ops::WRITE, 4_242);

        let empty = StoreWritersCursor::default();
        let first = store_writers_since(&empty);
        let rows = first.rows.as_ref().expect("the record is free");
        assert!(rows.configured);
        assert_eq!(rows.files.len(), 2);
        assert_eq!(rows.files_recorded, 2);
        // The reader was not started here: the reply says so.
        assert!(!first.capture.running);
        assert!(first.served_at_ms > 0);
        let json = serde_json::to_string(&first).unwrap();
        let back: StoreWriterBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(back, first);

        // Nothing changed since.
        let cursor = first.next_cursor(&empty);
        assert_eq!(cursor.record_instance, rows.instance);
        assert_eq!(cursor.rows_seq, rows.seq);
        let second = store_writers_since(&cursor);
        assert!(second.rows.as_ref().unwrap().files.is_empty());
        // One file changed.
        report(&transcript, ops::WRITE, 5_151);
        let third = store_writers_since(&cursor);
        let changed = &third.rows.as_ref().unwrap().files;
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].path, transcript);
        assert_eq!(changed[0].rows.len(), 2);

        // The stores are published again: another instance, and the old
        // cursor is answered from the start of the new one.
        store_writers::configure(&[spec(&root)]);
        report(&transcript, ops::WRITE, 4_242);
        let after_restart = store_writers_since(&cursor);
        let rows = after_restart.rows.as_ref().unwrap();
        assert_ne!(rows.instance, cursor.record_instance);
        assert_eq!(rows.files.len(), 1);
        assert_eq!(rows.files[0].creation, None);
        store_writers::clear();
        let cleared = store_writers_since(&StoreWritersCursor::default());
        assert!(!cleared.rows.as_ref().unwrap().configured);
    }

    /// The order goes through the helper's dispatcher to this function; an
    /// order the dispatcher does not know is an error, and so is a cursor
    /// that does not parse: neither is an empty batch.
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    #[tokio::test]
    #[serial(store_writers)]
    async fn the_order_dispatches_and_an_unknown_order_is_an_error() {
        let version = env!("CARGO_PKG_VERSION");
        let cursor = serde_json::to_string(&StoreWritersCursor::default()).unwrap();
        let output = crate::helper_rx::rpc_run(
            "utilityorder",
            "store_writers_since",
            &cursor,
            "",
            "",
            version,
        )
        .await
        .expect("the order is dispatched");
        let batch: StoreWriterBatch = serde_json::from_str(&output).expect("a batch");
        assert!(batch.rows.is_some());
        assert_eq!(batch.sensor, store_writers::sensor());
        // No argument is an empty cursor.
        let output =
            crate::helper_rx::rpc_run("utilityorder", "store_writers_since", "", "", "", version)
                .await
                .expect("the order is dispatched");
        assert!(serde_json::from_str::<StoreWriterBatch>(&output).is_ok());

        assert!(crate::helper_rx::rpc_run(
            "utilityorder",
            "store_writers_since_v0",
            &cursor,
            "",
            "",
            version
        )
        .await
        .is_err());
        assert!(crate::helper_rx::rpc_run(
            "utilityorder",
            "store_writers_since",
            "{\"rows_seq\": \"x\"}",
            "",
            "",
            version
        )
        .await
        .is_err());
        // A cursor missing a field does not parse either: both sides are
        // built from the same struct.
        assert!(serde_json::from_str::<StoreWritersCursor>("{\"rows_seq\": 1}").is_err());
    }
}
