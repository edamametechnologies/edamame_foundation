//! Open files of a batch of processes, read now, for the attack pattern
//! detector's live open-file scan.
//!
//! Measured where other processes' open files are readable: in-process for
//! standalone core (posture, root), and in the helper for the app
//! (`process_open_files` utility order), which keeps the per-process handle
//! enumeration out of the app process.
//!
//! A pid names whichever process holds it when the files are read, and a
//! pid the consumer took from an old record may belong to another process
//! by then. Each reported process therefore carries the identity of the
//! process that held the pid during the read (its start and its image), so
//! the consumer can tell its own process from a later one.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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
    /// The start of the process that held the pid while its files were
    /// read, in milliseconds since the Unix epoch, as every reader of a
    /// live process derives it (`flodbadd::process_events::process_start_ms`).
    /// `None` when it was not measured: the pid was read before and after
    /// the files and the two readings disagreed, or the start could not be
    /// read. A missing field (a sender that predates it) reads as `None`.
    pub start_ms: Option<u64>,
    /// The image of that process (`process_control::process_image_path`),
    /// under the same rule as `start_ms`.
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessOpenFilesBatch {
    /// Only the processes with at least one open file.
    pub processes: Vec<ProcessOpenFiles>,
    /// Processes past `MAX_PROCESSES` or the time budget were not measured.
    pub truncated: bool,
    /// The processes holding each lock file found around `lock_material`
    /// (`flodbadd::open_files::lock_file_candidates`), by path. Only where
    /// the enumeration above cannot see a handle held for writing (Windows,
    /// `flodbadd::open_files::lock_file_holders`); empty elsewhere, and when
    /// no material was given.
    pub lock_holders: HashMap<String, Vec<u32>>,
}

/// Read the open files of each pid now, bypassing the per-pid cache the
/// L7 resolver uses (one shared handle snapshot per batch on Windows), and
/// the holders of the lock files around `lock_material` (paths the
/// processes hold open) where the enumeration leaves those out.
///
/// The process taking the measurement (this one: a standalone daemon, or
/// the helper) is never reported, as a holder of a lock file neither: what
/// it holds open is what the observation opened, the file monitor's watches
/// and the files it hashes or scans, not material of its own
/// (`flodbadd::open_files::is_measuring_process`).
pub fn collect_process_open_files(pids: &[u32], lock_material: &[String]) -> ProcessOpenFilesBatch {
    let measured: Vec<u32> = pids
        .iter()
        .copied()
        .filter(|pid| !flodbadd::open_files::is_measuring_process(*pid))
        .collect();
    let mut batch = collect_with(
        &measured,
        MEASUREMENT_BUDGET,
        flodbadd::open_files::get_open_file_paths_fresh,
        read_occupant,
    );
    if !lock_material.is_empty() {
        batch.lock_holders = without_measuring_process(flodbadd::open_files::lock_file_holders(
            &flodbadd::open_files::lock_file_candidates(lock_material),
        ));
    }
    batch
}

/// The lock holders with the process taking the measurement left out; a
/// lock file no other process holds is dropped.
fn without_measuring_process(holders: HashMap<String, Vec<u32>>) -> HashMap<String, Vec<u32>> {
    holders
        .into_iter()
        .filter_map(|(path, pids)| {
            let pids: Vec<u32> = pids
                .into_iter()
                .filter(|pid| !flodbadd::open_files::is_measuring_process(*pid))
                .collect();
            (!pids.is_empty()).then_some((path, pids))
        })
        .collect()
}

/// The process holding a pid, as one reading sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Occupant {
    start_ms: Option<u64>,
    image_path: Option<String>,
}

/// One reading of the process holding `pid` now: its start and its image,
/// each `None` where it could not be read (a free pid, a process this one
/// may not inspect, a platform without a process table).
fn read_occupant(pid: u32) -> Occupant {
    Occupant {
        start_ms: flodbadd::process_events::process_start_ms(pid),
        image_path: crate::process_control::process_image_path(pid),
    }
}

/// The identity reported for a pid read between two readings of its
/// occupant: the readings when they are the same, nothing otherwise. Two
/// different readings mean the pid changed hands (or its process replaced
/// its image) while the files were read, so the files cannot be tied to
/// either process.
fn agreed_occupant(before: Option<Occupant>, after: Occupant) -> Occupant {
    match before {
        Some(before) if before == after => after,
        _ => Occupant::default(),
    }
}

fn collect_with(
    pids: &[u32],
    budget: Duration,
    mut read: impl FnMut(u32) -> Vec<String>,
    mut occupant: impl FnMut(u32) -> Occupant,
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
            lock_holders: HashMap::new(),
        };
    }

    let started = Instant::now();
    // Every occupant is read once before the files (and before the shared
    // handle snapshot on Windows) and once after them, so the two readings
    // bracket the moment the files were read.
    let before: HashMap<u32, Occupant> =
        measured.iter().map(|pid| (*pid, occupant(*pid))).collect();
    flodbadd::open_files::begin_fresh_open_files_scan();
    let mut processes = Vec::new();
    for pid in measured {
        if started.elapsed() >= budget {
            truncated = true;
            break;
        }
        let files = read(*pid);
        if !files.is_empty() {
            processes.push(ProcessOpenFiles {
                pid: *pid,
                files,
                start_ms: None,
                image_path: None,
            });
        }
    }
    for process in &mut processes {
        let agreed = agreed_occupant(before.get(&process.pid).cloned(), occupant(process.pid));
        process.start_ms = agreed.start_ms;
        process.image_path = agreed.image_path;
    }
    ProcessOpenFilesBatch {
        processes,
        truncated,
        lock_holders: HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_and_pid_zero_are_read_once_and_empty_lists_left_out() {
        let mut asked = Vec::new();
        let batch = collect_with(
            &[7, 0, 7, 9],
            MEASUREMENT_BUDGET,
            |pid| {
                asked.push(pid);
                if pid == 7 {
                    vec!["/home/user/.ssh/id_ed25519".to_string()]
                } else {
                    Vec::new()
                }
            },
            |_| Occupant::default(),
        );
        assert_eq!(asked, vec![7, 9]);
        assert_eq!(
            batch,
            ProcessOpenFilesBatch {
                processes: vec![ProcessOpenFiles {
                    pid: 7,
                    files: vec!["/home/user/.ssh/id_ed25519".to_string()],
                    start_ms: None,
                    image_path: None,
                }],
                truncated: false,
                lock_holders: HashMap::new(),
            }
        );
    }

    #[test]
    fn a_spent_budget_reports_the_batch_truncated() {
        let batch = collect_with(
            &[1, 2, 3],
            Duration::ZERO,
            |_| vec!["/x".to_string()],
            |_| Occupant::default(),
        );
        assert!(batch.processes.is_empty());
        assert!(batch.truncated);
    }

    #[test]
    fn past_the_process_cap_is_truncated() {
        let pids: Vec<u32> = (1..=(MAX_PROCESSES as u32 + 1)).collect();
        let mut count = 0usize;
        let batch = collect_with(
            &pids,
            MEASUREMENT_BUDGET,
            |_| {
                count += 1;
                Vec::new()
            },
            |_| Occupant::default(),
        );
        assert_eq!(count, MAX_PROCESSES);
        assert!(batch.truncated);
    }

    #[test]
    fn the_batch_round_trips_through_json() {
        let batch = ProcessOpenFilesBatch {
            processes: vec![ProcessOpenFiles {
                pid: 42,
                files: vec!["C:\\Users\\u\\AppData\\Local\\x.db".to_string()],
                start_ms: Some(1_794_839_456_000),
                image_path: Some("C:\\Program Files\\Tool\\tool.exe".to_string()),
            }],
            truncated: true,
            lock_holders: HashMap::from([(
                "C:\\Users\\u\\AppData\\Local\\lockfile".to_string(),
                vec![42, 7],
            )]),
        };
        let json = serde_json::to_string(&batch).unwrap();
        assert_eq!(
            serde_json::from_str::<ProcessOpenFilesBatch>(&json).unwrap(),
            batch
        );
    }

    /// The occupant is read before and after the files: the same reading
    /// both times is reported, a pid that changed hands in between (a later
    /// process took it, or the process replaced its image) reports none.
    #[test]
    fn the_occupant_is_reported_only_when_both_readings_agree() {
        let gh = Occupant {
            start_ms: Some(1_794_839_456_120),
            image_path: Some("/opt/homebrew/bin/gh".to_string()),
        };
        let daemon = Occupant {
            start_ms: Some(1_794_850_000_000),
            image_path: Some("/usr/libexec/daemon".to_string()),
        };
        let mut readings: HashMap<u32, Vec<Occupant>> = HashMap::from([
            (11, vec![gh.clone(), gh.clone()]),
            // Another process took the pid while its files were read.
            (12, vec![gh.clone(), daemon.clone()]),
            // The process exited while its files were read.
            (13, vec![daemon.clone(), Occupant::default()]),
            (14, vec![Occupant::default(), Occupant::default()]),
        ]);
        let batch = collect_with(
            &[11, 12, 13, 14],
            MEASUREMENT_BUDGET,
            |_| vec!["/Library/Keychains/system-keychain-2.db".to_string()],
            |pid| readings.get_mut(&pid).unwrap().remove(0),
        );
        assert!(readings.values().all(Vec::is_empty), "two readings each");
        let identity = |pid: u32| {
            let process = batch.processes.iter().find(|p| p.pid == pid).unwrap();
            (process.start_ms, process.image_path.clone())
        };
        assert_eq!(identity(11), (gh.start_ms, gh.image_path.clone()));
        assert_eq!(identity(12), (None, None));
        assert_eq!(identity(13), (None, None));
        assert_eq!(identity(14), (None, None));
    }

    /// A reply from a sender that predates the identity parses, and its
    /// processes read as unmeasured.
    #[test]
    fn a_reply_without_the_identity_parses_as_unmeasured() {
        let old =
            r#"{"processes":[{"pid":985,"files":["/x"]}],"truncated":false,"lock_holders":{}}"#;
        let batch: ProcessOpenFilesBatch = serde_json::from_str(old).unwrap();
        assert_eq!(batch.processes[0].start_ms, None);
        assert_eq!(batch.processes[0].image_path, None);
    }

    /// On the host platform the identity of a live process is measured: this
    /// test process, holding a file open, is reported with its start (the
    /// reading every sensor uses) and its own executable.
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn the_identity_of_a_live_process_is_measured() {
        let path = std::env::temp_dir().join(format!(
            "edamame_open_files_identity_{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "held").unwrap();
        let held = std::fs::File::open(&path).unwrap();
        let own = std::process::id();
        // The readers the public batch uses, on this process: the batch
        // itself leaves the measuring process out (the test below).
        let batch = collect_with(
            &[own],
            MEASUREMENT_BUDGET,
            flodbadd::open_files::get_open_file_paths_fresh,
            read_occupant,
        );
        drop(held);
        let _ = std::fs::remove_file(&path);

        let me = batch
            .processes
            .iter()
            .find(|process| process.pid == own)
            .expect("this process holds a file open");
        assert_eq!(
            me.start_ms,
            flodbadd::process_events::process_start_ms(own),
            "the start every sensor reads"
        );
        let start = me.start_ms.expect("its own start is readable");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(start <= now + 1_000, "{start} {now}");
        let image = me.image_path.as_deref().expect("its own image is readable");
        let canonical = |p: &std::path::Path| std::fs::canonicalize(p).unwrap();
        assert_eq!(
            canonical(std::path::Path::new(image)),
            canonical(&std::env::current_exe().unwrap())
        );
    }

    /// The process taking the measurement holds a file open and is not
    /// reported: its open files are the observation's (FP-WIN-51, the
    /// Windows helper credited with the stores its file monitor watches).
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn the_measuring_process_is_not_reported() {
        let path = std::env::temp_dir().join(format!(
            "edamame_open_files_measuring_{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "held").unwrap();
        let held = std::fs::File::open(&path).unwrap();
        let own = std::process::id();
        let batch = collect_process_open_files(&[own], &[]);
        drop(held);
        let _ = std::fs::remove_file(&path);

        assert!(
            batch.processes.iter().all(|process| process.pid != own),
            "{:?}",
            batch.processes
        );
        assert!(!batch.truncated);
    }

    /// A lock file the measuring process holds is not credited to it, and a
    /// lock file only it holds is dropped; another holder stays.
    #[test]
    fn the_measuring_process_holds_no_lock_file() {
        let own = std::process::id();
        let other = own.wrapping_add(1).max(1);
        let holders = HashMap::from([
            ("/profile/lockfile".to_string(), vec![own, other]),
            ("/profile/parent.lock".to_string(), vec![own]),
        ]);
        let kept = without_measuring_process(holders);
        assert_eq!(
            kept,
            HashMap::from([("/profile/lockfile".to_string(), vec![other])])
        );
    }
}
