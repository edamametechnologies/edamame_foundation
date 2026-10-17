//! B4 (ENGINES-ASSESSMENT-2026-10): which kernel-side sensors run in this
//! process, as a snapshot the core turns into its coverage record.
//!
//! The sensors live where the capture runs: the helper on the app path, the
//! posture daemon standalone. The core reads this snapshot in process
//! (standalone) or through the `collect_sensor_coverage` helper order, and
//! judges it against what protection relies on. `None` means the sensor is
//! not measurable in this build ("unmeasured"), never "absent".
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SensorCoverageSnapshot {
    /// The kernel process-event sensor delivered events (exec, fork, or the
    /// start rundown) since it started.
    pub kernel_process_events_delivered: u64,
    /// Events the sensor's ring evicted before a tick read them.
    pub kernel_process_events_evicted: u64,
    /// The FIM writer-attribution sensor (Endpoint Security on macOS) has
    /// its sink installed. `None`: not measurable in this build.
    pub fim_attribution_active: Option<bool>,
    /// Kernel credential-open notifications recorded since start.
    pub credential_opens_recorded: u64,
    /// Credential opens dropped because the table was contended.
    pub credential_opens_dropped: u64,
}

/// Read the sensors of this process.
pub fn collect_sensor_coverage() -> SensorCoverageSnapshot {
    let process = flodbadd::process_events::counters();
    let (credential_recorded, credential_dropped) = flodbadd::credential_opens::counters();
    SensorCoverageSnapshot {
        kernel_process_events_delivered: process.exec + process.fork + process.running,
        kernel_process_events_evicted: process.evicted,
        fim_attribution_active: fim_attribution_active(),
        credential_opens_recorded: credential_recorded,
        credential_opens_dropped: credential_dropped,
    }
}

#[cfg(all(target_os = "macos", feature = "fim"))]
fn fim_attribution_active() -> Option<bool> {
    Some(flodbadd::fim_es::is_active())
}

#[cfg(not(all(target_os = "macos", feature = "fim")))]
fn fim_attribution_active() -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_round_trips() {
        let snapshot = collect_sensor_coverage();
        let json = serde_json::to_string(&snapshot).unwrap();
        let back: SensorCoverageSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, snapshot);
    }
}
