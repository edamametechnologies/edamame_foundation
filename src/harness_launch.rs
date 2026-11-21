//! How an agent harness process was launched, as two measures the observed
//! agent does not set: whether its command line carries a print-mode
//! (non-interactive) marker of the published list
//! (`agent_visibility_params::print_mode_markers`: Claude Code's `-p` /
//! `--print`, Codex's `exec` subcommand and the like), and whether its
//! standard input and output are both its own terminal.
//!
//! Only the answers leave this module: the command line is read, compared
//! with the markers and dropped, and of the standard input and output only
//! whether each is the process's controlling terminal is kept (no path, no
//! name, no device number). Nothing is stored, returned, logged or traced,
//! here or by a caller. What cannot be read (the process is gone, another
//! process holds its pid now, the platform or the caller's rights do not
//! allow it) is unmeasured, never "no marker" or "no terminal".
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

/// The answer for one query, each part `None` when not measured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrintModeAnswer {
    pub pid: u32,
    pub start_ms: u64,
    /// `Some(true)` a print-mode marker is on the process's command line,
    /// `Some(false)` none is.
    pub print_mode: Option<bool>,
    /// `Some(true)` its standard input and its standard output are both its
    /// controlling terminal (a terminal or a pseudo-terminal it runs in),
    /// `Some(false)` at least one is not (a pipe, a socket, a file,
    /// `/dev/null`, another device, a closed descriptor).
    pub terminal_stdio: Option<bool>,
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
/// command line and its standard input and output, and both readings must be
/// the query's start (within the published
/// `session_binding_process_start_tolerance_ms`), so what was read is the
/// queried process's own. Unmeasured for a process that is gone, one whose
/// pid another process holds now, and on a platform without the reading; the
/// print mode also for an agent type with no published markers, or whose
/// published lists are both empty (no marker could ever be found, so "none
/// found" would say nothing).
pub fn measure_print_modes(queries: &[PrintModeQuery]) -> Vec<PrintModeAnswer> {
    let answers = read_launches(queries);
    queries
        .iter()
        .zip(answers)
        .map(|(query, (print_mode, terminal_stdio))| PrintModeAnswer {
            pid: query.pid,
            start_ms: query.start_ms,
            print_mode,
            terminal_stdio,
        })
        .collect()
}

/// The published markers of `agent_type`, when there is one to find.
#[cfg(any(test, target_os = "macos", target_os = "linux", target_os = "windows"))]
fn markers_for(agent_type: &str) -> Option<PrintModeMarkersJSON> {
    usable_markers(crate::agent_visibility_params::print_mode_markers(
        agent_type,
    ))
}

/// Markers that can be found: an entry with both lists empty says nothing.
#[cfg(any(test, target_os = "macos", target_os = "linux", target_os = "windows"))]
fn usable_markers(markers: Option<PrintModeMarkersJSON>) -> Option<PrintModeMarkersJSON> {
    markers.filter(|markers| !markers.flags.is_empty() || !markers.subcommands.is_empty())
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn read_launches(queries: &[PrintModeQuery]) -> Vec<(Option<bool>, Option<bool>)> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let tolerance = crate::vuln_detector_params::session_binding_process_start_tolerance_ms();
    let same_start = |query: &PrintModeQuery| {
        flodbadd::process_events::process_start_ms(query.pid)
            .is_some_and(|start| start.abs_diff(query.start_ms) <= tolerance)
    };
    let markers: Vec<Option<PrintModeMarkersJSON>> = queries
        .iter()
        .map(|query| markers_for(&query.agent_type))
        .collect();
    let before: Vec<bool> = queries.iter().map(same_start).collect();
    let mut found: Vec<(Option<bool>, Option<bool>)> = vec![(None, None); queries.len()];
    for (index, query) in queries.iter().enumerate() {
        if before[index] {
            found[index].1 = stdio_is_terminal(query.pid);
        }
    }
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
    if !pids.is_empty() {
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
            found[index].0 = Some(argv_has_print_marker(&args, markers));
        }
    }
    // The pid must still be the queried process: a process that exited and
    // whose pid was handed out again while it was read is unmeasured.
    for (index, query) in queries.iter().enumerate() {
        if (found[index].0.is_some() || found[index].1.is_some()) && !same_start(query) {
            found[index] = (None, None);
        }
    }
    found
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn read_launches(queries: &[PrintModeQuery]) -> Vec<(Option<bool>, Option<bool>)> {
    vec![(None, None); queries.len()]
}

/// Whether `pid`'s standard input and standard output are both its
/// controlling terminal: each a character device whose device is the one
/// the kernel records as the process's controlling terminal. Comparing with
/// the controlling terminal needs no list of terminal devices: a pipe, a
/// socket, a file, `/dev/null` or a terminal that is not the process's own
/// reads `false`; a process without one reads `false`. `None` when the
/// descriptors or the process record cannot be read. Nothing is opened: the
/// descriptors' targets are only looked at.
#[cfg(target_os = "linux")]
fn stdio_is_terminal(pid: u32) -> Option<bool> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    // `/proc/<pid>/stat`: the fields after the command name in parentheses
    // (which may itself hold a parenthesis) are state, ppid, pgrp, session
    // and tty_nr, the controlling terminal (0 for none).
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = &stat[stat.rfind(')')? + 1..];
    let tty_nr: u64 = fields.split_whitespace().nth(4)?.parse().ok()?;
    // The kernel's device encoding: the major in bits 8 to 19, the minor in
    // bits 0 to 7 and 20 to 31.
    let terminal = (tty_nr != 0).then(|| {
        (
            (tty_nr >> 8) & 0xfff,
            (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00),
        )
    });
    let mut both = true;
    for fd in [0, 1] {
        // Follows the descriptor to what it names; unreadable: unmeasured.
        let target = std::fs::metadata(format!("/proc/{pid}/fd/{fd}")).ok()?;
        let rdev = target.rdev();
        let device = (u64::from(libc::major(rdev)), u64::from(libc::minor(rdev)));
        both &= target.file_type().is_char_device() && terminal == Some(device);
    }
    Some(both)
}

/// See the Linux version. macOS: the controlling terminal is `e_tdev` of the
/// process's BSD info, and each descriptor's type and device come from
/// `proc_pidfdinfo` (a pipe or a socket is no vnode, so not a terminal).
#[cfg(target_os = "macos")]
fn stdio_is_terminal(pid: u32) -> Option<bool> {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};

    // `PROC_PIDFDVNODEINFO` and its `struct vnode_fdinfo`
    // (`sys/proc_info.h`), which the libc crate does not carry.
    const PROC_PIDFDVNODEINFO: libc::c_int = 1;
    #[repr(C)]
    struct ProcFileInfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: libc::off_t,
        fi_type: i32,
        fi_guardflags: u32,
    }
    #[repr(C)]
    struct VnodeFdInfo {
        pfi: ProcFileInfo,
        pvi: libc::vnode_info,
    }
    // No controlling terminal (`NODEV`).
    const NO_DEVICE: u32 = u32::MAX;

    let pid = libc::c_int::try_from(pid).ok()?;
    // SAFETY: plain data, written by the kernel up to `size` bytes.
    let mut bsd: libc::proc_bsdinfo = unsafe { zeroed() };
    let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut bsd as *mut libc::proc_bsdinfo as *mut c_void,
            size,
        )
    };
    if read != size {
        return None;
    }
    let terminal = (bsd.e_tdev != NO_DEVICE).then_some(bsd.e_tdev);
    let mut both = true;
    for fd in [0, 1] {
        // SAFETY: as above.
        let mut info: VnodeFdInfo = unsafe { zeroed() };
        let size = libc::c_int::try_from(size_of::<VnodeFdInfo>()).ok()?;
        let read = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd,
                PROC_PIDFDVNODEINFO,
                &mut info as *mut VnodeFdInfo as *mut c_void,
                size,
            )
        };
        if read == size {
            let stat = &info.pvi.vi_stat;
            let char_device =
                u32::from(stat.vst_mode) & u32::from(libc::S_IFMT) == u32::from(libc::S_IFCHR);
            both &= char_device && terminal == Some(stat.vst_rdev);
        } else {
            // Not a vnode (a pipe, a socket) or not readable: the descriptor
            // list tells them apart.
            match descriptor_type(pid, fd)? {
                Some(kind) if kind == libc::PROX_FDTYPE_VNODE as u32 => return None,
                _ => both = false,
            }
        }
    }
    Some(both)
}

/// The type of `pid`'s descriptor `fd` (`PROX_FDTYPE_*`), `Some(None)` when
/// it is not open, `None` when the list cannot be read.
#[cfg(target_os = "macos")]
fn descriptor_type(pid: libc::c_int, fd: libc::c_int) -> Option<Option<u32>> {
    use std::ffi::c_void;
    use std::mem::size_of;
    let entry = size_of::<libc::proc_fdinfo>();
    // SAFETY: a size query (no buffer).
    let bytes =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    let bytes = usize::try_from(bytes).ok().filter(|bytes| *bytes > 0)?;
    // Room for descriptors opened since the size query.
    let mut list: Vec<libc::proc_fdinfo> = Vec::with_capacity(bytes / entry + 16);
    let capacity = libc::c_int::try_from(list.capacity() * entry).ok()?;
    // SAFETY: the kernel writes at most `capacity` bytes of entries.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            list.as_mut_ptr() as *mut c_void,
            capacity,
        )
    };
    let written = usize::try_from(written)
        .ok()
        .filter(|written| *written > 0)?;
    // SAFETY: `written` bytes of whole entries were written.
    unsafe { list.set_len((written / entry).min(list.capacity())) };
    Some(
        list.iter()
            .find(|info| info.proc_fd == fd)
            .map(|info| info.proc_fdtype),
    )
}

/// Windows: no way to read another process's standard handles without
/// duplicating them into this process, which a behaviour engine reads as
/// handle theft (the project's rule): unmeasured.
#[cfg(target_os = "windows")]
fn stdio_is_terminal(_pid: u32) -> Option<bool> {
    None
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

    /// An entry whose two lists are empty can find no marker: unmeasured,
    /// never "no marker" (the answer that may narrow).
    #[test]
    fn an_agent_with_no_marker_to_find_is_unmeasured() {
        let empty = PrintModeMarkersJSON {
            flags: Vec::new(),
            subcommands: Vec::new(),
        };
        assert_eq!(usable_markers(Some(empty)), None);
        assert_eq!(usable_markers(None), None);
        assert_eq!(usable_markers(Some(claude())), Some(claude()));
        assert_eq!(usable_markers(Some(codex())), Some(codex()));
    }

    /// A child of this test on a new pseudo-terminal that is its controlling
    /// terminal, standard input and output both on it; the pty's controlling
    /// side is returned too (it stays open while the child is measured).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn child_on_its_own_terminal() -> (std::process::Child, libc::c_int) {
        use std::os::fd::FromRawFd;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let (mut controller, mut terminal) = (0, 0);
        // SAFETY: openpty writes the two descriptors.
        let opened = unsafe {
            libc::openpty(
                &mut controller,
                &mut terminal,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(opened, 0, "a pseudo-terminal");
        // SAFETY: fresh descriptors, each owned by its Stdio.
        let (input, output) = unsafe {
            (
                Stdio::from_raw_fd(libc::dup(terminal)),
                Stdio::from_raw_fd(libc::dup(terminal)),
            )
        };
        let mut command = Command::new("sleep");
        command
            .arg("30")
            .stdin(input)
            .stdout(output)
            .stderr(Stdio::null());
        // SAFETY: async-signal-safe calls only, after the standard
        // descriptors were set up: a new session whose controlling terminal
        // is the pty on standard input.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("a child on the terminal");
        // SAFETY: this process's copy only.
        unsafe { libc::close(terminal) };
        (child, controller)
    }

    /// Standard input and output are measured as the process's controlling
    /// terminal, or not: a child running on its own pseudo-terminal is a
    /// terminal; one whose input is `/dev/null` and whose output is a pipe is
    /// not, nor one on `/dev/null` for both (character devices, not its
    /// terminal); a process whose start differs is not measured at all.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn standard_input_and_output_are_measured_as_a_terminal_or_not() {
        use std::process::{Command, Stdio};
        let measure = |pid: u32| {
            let start = flodbadd::process_events::process_start_ms(pid).expect("the child's start");
            let query = |start_ms: u64| PrintModeQuery {
                pid,
                start_ms,
                agent_type: "codex".to_string(),
            };
            let answers = measure_print_modes(&[query(start), query(start - 3_600_000)]);
            (
                (answers[0].print_mode, answers[0].terminal_stdio),
                (answers[1].print_mode, answers[1].terminal_stdio),
            )
        };
        // `spawn` can return while the child is still inside `execve`, before
        // the kernel has laid out its arguments: `/proc/<pid>/cmdline` reads
        // empty then and the launch is unmeasured (the Android leg's runner,
        // 2026-11-21). Measure again while the launch is unmeasured; the
        // assertions still read what was measured.
        let measure_settled = |pid: u32| {
            let mut answer = measure(pid);
            for _ in 0..50 {
                if answer.0 .0.is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                answer = measure(pid);
            }
            answer
        };
        let (mut on_terminal, controller) = child_on_its_own_terminal();
        let (own, other) = measure_settled(on_terminal.id());
        let _ = on_terminal.kill();
        let _ = on_terminal.wait();
        // SAFETY: the descriptor openpty gave this test.
        unsafe { libc::close(controller) };
        assert_eq!(own, (Some(false), Some(true)));
        assert_eq!(other, (None, None));
        let mut piped = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("a child on a pipe");
        let (own, _) = measure_settled(piped.id());
        let _ = piped.kill();
        let _ = piped.wait();
        assert_eq!(own, (Some(false), Some(false)));
        // Character devices that are not its terminal: `/dev/null` on both.
        let mut nulled = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("a child on /dev/null");
        let (own, _) = measure_settled(nulled.id());
        let _ = nulled.kill();
        let _ = nulled.wait();
        assert_eq!(own, (Some(false), Some(false)));
    }

    /// Windows reads no other process's standard handles (that needs a
    /// duplicate of them): unmeasured.
    #[cfg(target_os = "windows")]
    #[test]
    fn standard_handles_are_not_measured_on_windows() {
        let own = std::process::id();
        let start = flodbadd::process_events::process_start_ms(own).expect("this process's start");
        let answers = measure_print_modes(&[PrintModeQuery {
            pid: own,
            start_ms: start,
            agent_type: "codex".to_string(),
        }]);
        assert_eq!(answers[0].terminal_stdio, None);
    }
}
