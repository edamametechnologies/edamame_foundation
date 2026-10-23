//! The kernel process-event stream for a consumer in another process.
//!
//! The sensors (Endpoint Security, ETW, eBPF) push into flodbadd's ring in
//! the process that runs the capture: the posture daemon standalone, the
//! helper on the app path. The standalone core drains the ring in process;
//! the app's core asks the helper for what it has not read yet through the
//! `process_events_since` order, and feeds the same lineage table.
use flodbadd::process_events::{self, ProcessEvent};
use serde::{Deserialize, Serialize};

/// Reply of [`process_events_since`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessEventBatch {
    /// Events at or after the asked timestamp, oldest first.
    pub events: Vec<ProcessEvent>,
    /// The ring lock was contended: nothing was read, ask again. Never an
    /// empty `events` standing for "no events".
    pub contended: bool,
    /// Timestamp of the oldest event the ring still holds. A consumer whose
    /// watermark is older lost the events the ring evicted in between.
    pub oldest_ms: Option<u64>,
    /// The sensor's counters, so the consumer reports the sensor that feeds
    /// it rather than its own, idle one.
    pub counters: process_events::ProcessEventCountersSnapshot,
}

/// What the ring holds at or after `since_ms` (the whole ring for 0).
pub fn process_events_since(since_ms: u64) -> ProcessEventBatch {
    let counters = process_events::counters();
    match process_events::since(since_ms, process_events::PROCESS_EVENT_RING_MAX) {
        Some((events, oldest_ms)) => ProcessEventBatch {
            events,
            contended: false,
            oldest_ms,
            counters,
        },
        None => ProcessEventBatch {
            events: Vec::new(),
            contended: true,
            oldest_ms: None,
            counters,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_round_trips_on_the_wire() {
        let batch = process_events_since(0);
        let json = serde_json::to_string(&batch).unwrap();
        let back: ProcessEventBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(back, batch);
    }
}
