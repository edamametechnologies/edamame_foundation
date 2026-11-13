//! Whether an agent harness process was started in print (non-interactive)
//! mode, read from its command line against the published markers
//! (`agent_visibility_params::print_mode_markers`): Claude Code's `-p` /
//! `--print`, Codex's `exec` subcommand and the like.
//!
//! Only the answer leaves this module: the command line is read, compared
//! with the markers and dropped. It is never stored, returned, logged or
//! traced, here or by a caller. A command line that cannot be read (the
//! process is gone, another process holds its pid now, the platform or the
//! caller's rights do not allow it) is unmeasured, never "no marker".
//!
//! One function serves both paths: the standalone core calls
//! [`measure_print_modes`] in process, and the helper calls it for the app
//! (the `harness_print_mode` utility order), so both give the same answer.

use crate::agent_visibility_params::PrintModeMarkersJSON;
use serde::{Deserialize, Serialize};

/// A harness process to measure: its pid, its start as the kernel records
/// it (`flodbadd::process_events::process_start_ms`), and its agent type
/// (which markers apply).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintModeQuery {
    pub pid: u32,
    pub start_ms: u64,
    pub agent_type: String,
}

/// The answer for one query: `Some(true)` a print-mode marker is on the
/// process's command line, `Some(false)` none is, `None` not measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintModeAnswer {
    pub pid: u32,
    pub start_ms: u64,
    pub print_mode: Option<bool>,
}

/// Whether the arguments of a command line (the program first) carry one of
/// `markers`. Any argument may: a marker that is not where the agent's CLI
/// reads it only reads as print mode, the direction that never narrows. An
/// option counts as written, with an attached value (`--print=...`), and a
/// one-letter option also inside a cluster of one-letter options (`-cp`).
/// The program itself (the first argument) is not compared.
pub fn argv_has_print_marker<S: AsRef<str>>(args: &[S], markers: &PrintModeMarkersJSON) -> bool {
    let single_letters: Vec<char> = markers
        .flags
        .iter()
        .filter_map(|flag| {
            let mut chars = flag.strip_prefix('-')?.chars();
            let letter = chars.next()?;
            (chars.next().is_none() && letter.is_ascii_alphabetic()).then_some(letter)
        })
        .collect();
    args.iter().skip(1).any(|arg| {
        let arg = arg.as_ref();
        if markers.flags.iter().any(|flag| flag == arg)
            || markers.subcommands.iter().any(|sub| sub == arg)
        {
            return true;
        }
        if let Some((name, _value)) = arg.split_once('=') {
            if name.starts_with("--") && markers.flags.iter().any(|flag| flag == name) {
                return true;
            }
        }
        match arg.strip_prefix('-') {
            Some(cluster)
                if !cluster.starts_with('-')
                    && cluster.len() > 1
                    && cluster.chars().all(|c| c.is_ascii_alphabetic()) =>
            {
                cluster.chars().any(|c| single_letters.contains(&c))
            }
            _ => false,
        }
    })
}

/// Measure each query's process: its start is read before and after its
/// command line, and both readings must be the query's start (within the
/// published `session_binding_process_start_tolerance_ms`), so the command
/// line is the queried process's own. Unmeasured for a process that is gone,
/// one whose pid another process holds now, an agent type with no published
/// markers, and on a platform without the reading.
pub fn measure_print_modes(queries: &[PrintModeQuery]) -> Vec<PrintModeAnswer> {
    let answers = read_print_modes(queries);
    queries
        .iter()
        .zip(answers)
        .map(|(query, print_mode)| PrintModeAnswer {
            pid: query.pid,
            start_ms: query.start_ms,
            print_mode,
        })
        .collect()
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn read_print_modes(queries: &[PrintModeQuery]) -> Vec<Option<bool>> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let tolerance = crate::vuln_detector_params::session_binding_process_start_tolerance_ms();
    let same_start = |query: &PrintModeQuery| {
        flodbadd::process_events::process_start_ms(query.pid)
            .is_some_and(|start| start.abs_diff(query.start_ms) <= tolerance)
    };
    let markers: Vec<Option<PrintModeMarkersJSON>> = queries
        .iter()
        .map(|query| crate::agent_visibility_params::print_mode_markers(&query.agent_type))
        .collect();
    let before: Vec<bool> = queries.iter().map(same_start).collect();
    let mut pids: Vec<Pid> = queries
        .iter()
        .zip(&before)
        .zip(&markers)
        .filter(|((_, same), markers)| **same && markers.is_some())
        .map(|((query, _), _)| Pid::from_u32(query.pid))
        .collect();
    // Each pid once: a refresh of a list that names a pid twice drops that
    // process from the table it fills (the second visit reads it as not
    // refreshed), which would leave every query of the pid unmeasured.
    pids.sort_unstable();
    pids.dedup();
    let mut found: Vec<Option<bool>> = vec![None; queries.len()];
    if pids.is_empty() {
        return found;
    }
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&pids),
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    for (index, query) in queries.iter().enumerate() {
        let (true, Some(markers)) = (before[index], markers[index].as_ref()) else {
            continue;
        };
        let Some(process) = system.process(Pid::from_u32(query.pid)) else {
            continue;
        };
        let args = process.cmd();
        if args.is_empty() {
            // Not readable (rights, a process that is exiting): unmeasured.
            continue;
        }
        let args: Vec<std::borrow::Cow<'_, str>> =
            args.iter().map(|arg| arg.to_string_lossy()).collect();
        found[index] = Some(argv_has_print_marker(&args, markers));
    }
    drop(system);
    // The pid must still be the queried process: a process that exited and
    // whose pid was handed out again while its command line was read is
    // unmeasured.
    for (index, query) in queries.iter().enumerate() {
        if found[index].is_some() && !same_start(query) {
            found[index] = None;
        }
    }
    found
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn read_print_modes(queries: &[PrintModeQuery]) -> Vec<Option<bool>> {
    vec![None; queries.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claude() -> PrintModeMarkersJSON {
        PrintModeMarkersJSON {
            flags: vec!["-p".to_string(), "--print".to_string()],
            subcommands: Vec::new(),
        }
    }

    fn codex() -> PrintModeMarkersJSON {
        PrintModeMarkersJSON {
            flags: Vec::new(),
            subcommands: vec!["exec".to_string(), "e".to_string(), "review".to_string()],
        }
    }

    #[test]
    fn a_print_mode_marker_is_found_wherever_the_cli_takes_it() {
        let has =
            |args: &[&str], markers: &PrintModeMarkersJSON| argv_has_print_marker(args, markers);
        assert!(has(&["claude", "-p"], &claude()));
        assert!(has(&["claude", "--model", "x", "--print"], &claude()));
        assert!(has(&["claude", "--print=true"], &claude()));
        // A cluster of one-letter options.
        assert!(has(&["claude", "-cp"], &claude()));
        // Through an interpreter: the script comes first.
        assert!(has(&["node", "/opt/claude/cli.js", "-p"], &claude()));
        // Interactive, with or without a prompt.
        assert!(!has(&["claude"], &claude()));
        assert!(!has(&["claude", "--continue", "a prompt"], &claude()));
        assert!(!has(&["claude", "-c"], &claude()));
        assert!(!has(&["claude", "--printer"], &claude()));
        // The program is not an argument.
        assert!(!has(&["-p"], &claude()));
        // Codex: the subcommand, its alias, anywhere after global options.
        assert!(has(&["codex", "exec", "a prompt"], &codex()));
        assert!(has(&["codex", "-c", "key=value", "e"], &codex()));
        assert!(has(&["codex", "review"], &codex()));
        assert!(!has(&["codex", "resume", "--last"], &codex()));
        assert!(!has(&["codex"], &codex()));
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn only_the_queried_process_is_measured() {
        let own = std::process::id();
        let start = flodbadd::process_events::process_start_ms(own).expect("this process's start");
        let answers = measure_print_modes(&[
            // This test process: its command line carries no marker.
            PrintModeQuery {
                pid: own,
                start_ms: start,
                agent_type: "codex".to_string(),
            },
            // The same pid, another start: another process, unmeasured.
            PrintModeQuery {
                pid: own,
                start_ms: start.saturating_sub(3_600_000),
                agent_type: "codex".to_string(),
            },
            // No published markers for the agent type.
            PrintModeQuery {
                pid: own,
                start_ms: start,
                agent_type: "unlisted".to_string(),
            },
            // A pid no process holds.
            PrintModeQuery {
                pid: u32::MAX - 1,
                start_ms: start,
                agent_type: "codex".to_string(),
            },
        ]);
        let found: Vec<Option<bool>> = answers.iter().map(|a| a.print_mode).collect();
        assert_eq!(found, vec![Some(false), None, None, None]);
    }

    /// Two queries of one process (two starts within the identity
    /// tolerance, or one query repeated) are both measured.
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn a_process_queried_twice_is_measured_for_each_query() {
        let own = std::process::id();
        let start = flodbadd::process_events::process_start_ms(own).expect("this process's start");
        let query = |start_ms: u64| PrintModeQuery {
            pid: own,
            start_ms,
            agent_type: "codex".to_string(),
        };
        let answers = measure_print_modes(&[query(start), query(start + 1)]);
        let found: Vec<Option<bool>> = answers.iter().map(|a| a.print_mode).collect();
        assert_eq!(found, vec![Some(false), Some(false)]);
    }
}
