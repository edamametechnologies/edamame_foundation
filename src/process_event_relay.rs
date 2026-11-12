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
    /// The processes holding the pids the consumer asked about
    /// ([`process_listing`]); `None` when it asked about none, and from a
    /// sender that predates the question.
    pub listing: Option<ProcessListing>,
}

/// One running process of a [`ProcessListing`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedProcess {
    pub pid: u32,
    /// The process's start as the operating system reports it, in Unix
    /// seconds; `None` when it could not be read.
    pub start_secs: Option<u64>,
}

/// Which of a set of pids hold a running process now. A pid in neither list
/// was not measured: it is never read as absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessListing {
    /// Pids that hold a running process.
    pub running: Vec<ListedProcess>,
    /// Pids that hold no process.
    pub absent: Vec<u32>,
}

/// The most pids one [`process_listing`] answers for.
pub const PROCESS_LISTING_MAX_PIDS: usize = 512;

/// Look up `pids` (at most [`PROCESS_LISTING_MAX_PIDS`]) among the running
/// processes: for each, whether a process holds it and when that process
/// started. Used by a consumer that keeps records of processes across the
/// life of the sensor, to tell a record whose process is gone from one that
/// is still running. Measures nothing on a platform without a process table
/// this process can read.
pub fn process_listing(pids: &[u32]) -> ProcessListing {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
        let pids: Vec<u32> = pids
            .iter()
            .copied()
            .filter(|pid| *pid != 0)
            .take(PROCESS_LISTING_MAX_PIDS)
            .collect();
        let wanted: Vec<Pid> = pids.iter().map(|pid| Pid::from_u32(*pid)).collect();
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&wanted),
            true,
            ProcessRefreshKind::nothing(),
        );
        let mut listing = ProcessListing::default();
        for pid in pids {
            match system.process(Pid::from_u32(pid)) {
                Some(process) => listing.running.push(ListedProcess {
                    pid,
                    start_secs: Some(process.start_time()).filter(|secs| *secs > 0),
                }),
                // Not in the table this process could read: another user's
                // process is running all the same, so the pid is absent only
                // when the system says no process holds it.
                None if crate::process_control::process_is_alive(pid) => {
                    listing.running.push(ListedProcess {
                        pid,
                        start_secs: None,
                    })
                }
                None => listing.absent.push(pid),
            }
        }
        listing
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = pids;
        ProcessListing::default()
    }
}

/// What the ring holds at or after `since_ms` (the whole ring for 0), with
/// the listing of `listed_pids` when the consumer asked about any.
pub fn process_events_since(since_ms: u64, listed_pids: &[u32]) -> ProcessEventBatch {
    let counters = process_events::counters();
    let listing = (!listed_pids.is_empty()).then(|| process_listing(listed_pids));
    match process_events::since(since_ms, process_events::PROCESS_EVENT_RING_MAX) {
        Some((events, oldest_ms)) => ProcessEventBatch {
            events,
            contended: false,
            oldest_ms,
            counters,
            listing,
        },
        None => ProcessEventBatch {
            events: Vec::new(),
            contended: true,
            oldest_ms: None,
            counters,
            listing,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_round_trips_on_the_wire() {
        let batch = process_events_since(0, &[std::process::id()]);
        let json = serde_json::to_string(&batch).unwrap();
        let back: ProcessEventBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(back, batch);
        // A reply from a sender that predates the listing parses, and says
        // nothing about any pid.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value.as_object_mut().unwrap().remove("listing");
        let old: ProcessEventBatch = serde_json::from_value(value).unwrap();
        assert_eq!(old.listing, None);
        assert_eq!(process_events_since(0, &[]).listing, None);
    }

    /// The listing tells a running process from a pid nothing holds, and
    /// never reports a pid it was not asked about.
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn the_listing_tells_a_running_process_from_a_free_pid() {
        let own = std::process::id();
        // A pid above every platform's pid range names no process.
        let free = 4_000_000_000u32;
        let listing = process_listing(&[own, free, 0]);
        let me = listing
            .running
            .iter()
            .find(|process| process.pid == own)
            .expect("this process is running");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let start = me.start_secs.expect("its own start is readable");
        assert!(start <= now && now - start < 24 * 60 * 60, "{start} {now}");
        assert_eq!(listing.absent, vec![free]);
        assert_eq!(listing.running.len(), 1);
        // The same answer when asked again: a start time does not move.
        assert_eq!(process_listing(&[own]).running[0].start_secs, Some(start));
        assert_eq!(process_listing(&[]), ProcessListing::default());
    }
}
