//! Open files of a batch of processes, read now, for the attack pattern
//! detector's live open-file scan.
//!
//! Measured where other processes' open files are readable: in-process for
//! standalone core (posture, root), and in the helper for the app
//! (`process_open_files` utility order), which keeps the per-process handle
//! enumeration out of the app process.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Processes measured per batch; the rest are reported as `truncated`.
pub const MAX_PROCESSES: usize = 1024;

/// Time spent enumerating per batch; the processes left are reported as
/// `truncated`. Below the helper order's 45 s timeout.
pub const MEASUREMENT_BUDGET: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessOpenFiles {
    pub pid: u32,
    /// Open disk-backed file paths, read from the OS now.
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessOpenFilesBatch {
    /// Only the processes with at least one open file.
    pub processes: Vec<ProcessOpenFiles>,
    /// Processes past `MAX_PROCESSES` or the time budget were not measured.
    pub truncated: bool,
}

/// Read the open files of each pid now, bypassing the per-pid cache the
/// L7 resolver uses (one shared handle snapshot per batch on Windows).
pub fn collect_process_open_files(pids: &[u32]) -> ProcessOpenFilesBatch {
    collect_with(
        pids,
        MEASUREMENT_BUDGET,
        flodbadd::open_files::get_open_file_paths_fresh,
    )
}

fn collect_with(
    pids: &[u32],
    budget: Duration,
    mut read: impl FnMut(u32) -> Vec<String>,
) -> ProcessOpenFilesBatch {
    let mut seen: HashSet<u32> = HashSet::new();
    let unique: Vec<u32> = pids
        .iter()
        .copied()
        .filter(|pid| *pid != 0 && seen.insert(*pid))
        .collect();
    let mut truncated = unique.len() > MAX_PROCESSES;
    let measured = &unique[..unique.len().min(MAX_PROCESSES)];
    if measured.is_empty() {
        return ProcessOpenFilesBatch {
            processes: Vec::new(),
            truncated,
        };
    }

    flodbadd::open_files::begin_fresh_open_files_scan();
    let started = Instant::now();
    let mut processes = Vec::new();
    for pid in measured {
        if started.elapsed() >= budget {
            truncated = true;
            break;
        }
        let files = read(*pid);
        if !files.is_empty() {
            processes.push(ProcessOpenFiles { pid: *pid, files });
        }
    }
    ProcessOpenFilesBatch {
        processes,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_and_pid_zero_are_read_once_and_empty_lists_left_out() {
        let mut asked = Vec::new();
        let batch = collect_with(&[7, 0, 7, 9], MEASUREMENT_BUDGET, |pid| {
            asked.push(pid);
            if pid == 7 {
                vec!["/home/user/.ssh/id_ed25519".to_string()]
            } else {
                Vec::new()
            }
        });
        assert_eq!(asked, vec![7, 9]);
        assert_eq!(
            batch,
            ProcessOpenFilesBatch {
                processes: vec![ProcessOpenFiles {
                    pid: 7,
                    files: vec!["/home/user/.ssh/id_ed25519".to_string()],
                }],
                truncated: false,
            }
        );
    }

    #[test]
    fn a_spent_budget_reports_the_batch_truncated() {
        let batch = collect_with(&[1, 2, 3], Duration::ZERO, |_| vec!["/x".to_string()]);
        assert!(batch.processes.is_empty());
        assert!(batch.truncated);
    }

    #[test]
    fn past_the_process_cap_is_truncated() {
        let pids: Vec<u32> = (1..=(MAX_PROCESSES as u32 + 1)).collect();
        let mut count = 0usize;
        let batch = collect_with(&pids, MEASUREMENT_BUDGET, |_| {
            count += 1;
            Vec::new()
        });
        assert_eq!(count, MAX_PROCESSES);
        assert!(batch.truncated);
    }

    #[test]
    fn the_batch_round_trips_through_json() {
        let batch = ProcessOpenFilesBatch {
            processes: vec![ProcessOpenFiles {
                pid: 42,
                files: vec!["C:\\Users\\u\\AppData\\Local\\x.db".to_string()],
            }],
            truncated: true,
        };
        let json = serde_json::to_string(&batch).unwrap();
        assert_eq!(
            serde_json::from_str::<ProcessOpenFilesBatch>(&json).unwrap(),
            batch
        );
    }
}
