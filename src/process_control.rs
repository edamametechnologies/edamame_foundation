//! Operator process control: a hard kill (`SIGKILL` / `TerminateProcess`)
//! of one process by pid, guarded by an identity check.
//!
//! Single source of truth for both dispatch paths (invariants: "Standalone
//! vs Helper Dispatch Pattern"): the posture CLI and tests call
//! [`kill_process`] directly; the sandboxed app reaches it through the
//! helper's `kill_process` utility order, which is a thin delegate to the
//! same function. The RPC that exposes it is operator-only -- it is not,
//! and must not be, an MCP tool (observer-independence: the observed agent
//! must not be able to terminate the observer or its peers; and a kill is
//! not observation).
//!
//! Guards, in order:
//! - refuse system-critical and EDAMAME processes (pid 0/1, the caller, the
//!   helper / posture / app / CLI images, Windows session-critical images),
//! - `expected_path` must match the pid's current image when given (the
//!   pid the operator saw in a finding may have been recycled),
//! - the kill is confirmed by re-probing the pid for up to two seconds.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Outcome of one kill request. `Refused` and `IdentityMismatch` mean the
/// kill was NOT attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum KillProcessOutcome {
    Killed {
        pid: u32,
        process_path: String,
    },
    NotRunning {
        pid: u32,
    },
    IdentityMismatch {
        pid: u32,
        expected_path: String,
        observed_path: String,
    },
    Refused {
        pid: u32,
        reason: String,
    },
    PermissionDenied {
        pid: u32,
    },
    Failed {
        pid: u32,
        error: String,
    },
}

impl KillProcessOutcome {
    pub fn is_killed(&self) -> bool {
        matches!(self, KillProcessOutcome::Killed { .. })
    }
}

/// Image basenames (lower-case, no `.exe`) EDAMAME never kills: its own
/// components and the OS processes whose death takes the session down.
const PROTECTED_BASENAMES: &[&str] = &[
    // EDAMAME
    "edamame_helper",
    "edamame_posture",
    "edamame_cli",
    "edamame",
    "edamame security",
    // Windows session-critical
    "system",
    "smss",
    "csrss",
    "wininit",
    "winlogon",
    "services",
    "lsass",
    "svchost",
    "dwm",
    "explorer",
    // macOS / Linux init and login
    "launchd",
    "systemd",
    "init",
    "loginwindow",
    "windowserver",
];

fn basename_lower(path: &str) -> String {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path).trim();
    let base = base.to_ascii_lowercase();
    base.strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(base)
}

fn paths_match(expected: &str, observed: &str) -> bool {
    let norm = |p: &str| p.trim().replace('\\', "/");
    let e = norm(expected);
    let o = norm(observed);
    if cfg!(any(target_os = "windows", target_os = "macos")) {
        e.eq_ignore_ascii_case(&o)
    } else {
        e == o
    }
}

/// Refusal reason for pids EDAMAME must never terminate, `None` when the
/// pid is fair game.
pub fn refusal_reason(pid: u32, image_path: Option<&str>) -> Option<String> {
    if pid <= 1 {
        return Some(format!("pid {pid} is a system process"));
    }
    if cfg!(target_os = "windows") && pid == 4 {
        return Some("pid 4 is the Windows System process".to_string());
    }
    if pid == std::process::id() {
        return Some("refusing to terminate the EDAMAME process itself".to_string());
    }
    if let Some(path) = image_path {
        let base = basename_lower(path);
        if PROTECTED_BASENAMES.contains(&base.as_str()) {
            return Some(format!("{base} is a protected process"));
        }
    }
    None
}

/// Image path of a live pid, `None` when the pid is gone or unreadable.
pub fn process_image_path(pid: u32) -> Option<String> {
    platform::image_path(pid)
}

pub fn process_is_alive(pid: u32) -> bool {
    platform::is_alive(pid)
}

/// Hard-kill `pid`. `expected_path` (empty = no check) must match the pid's
/// current image, so a finding's pid that was recycled by another program
/// is never acted on.
pub fn kill_process(pid: u32, expected_path: &str) -> KillProcessOutcome {
    // Structural refusals first: they do not depend on being able to
    // observe the process at all.
    if let Some(reason) = refusal_reason(pid, None) {
        return KillProcessOutcome::Refused { pid, reason };
    }
    if !process_is_alive(pid) {
        return KillProcessOutcome::NotRunning { pid };
    }
    let observed = process_image_path(pid);
    if let Some(reason) = refusal_reason(pid, observed.as_deref()) {
        return KillProcessOutcome::Refused { pid, reason };
    }
    let expected = expected_path.trim();
    if !expected.is_empty() {
        match observed.as_deref() {
            Some(observed_path) if paths_match(expected, observed_path) => {}
            Some(observed_path) => {
                return KillProcessOutcome::IdentityMismatch {
                    pid,
                    expected_path: expected.to_string(),
                    observed_path: observed_path.to_string(),
                }
            }
            None => {
                return KillProcessOutcome::IdentityMismatch {
                    pid,
                    expected_path: expected.to_string(),
                    observed_path: String::new(),
                }
            }
        }
    }
    match platform::terminate(pid) {
        Ok(()) => {}
        Err(TerminateError::NotRunning) => return KillProcessOutcome::NotRunning { pid },
        Err(TerminateError::PermissionDenied) => {
            return KillProcessOutcome::PermissionDenied { pid }
        }
        Err(TerminateError::Other(error)) => return KillProcessOutcome::Failed { pid, error },
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while process_is_alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if process_is_alive(pid) {
        return KillProcessOutcome::Failed {
            pid,
            error: "process still alive two seconds after the kill".to_string(),
        };
    }
    KillProcessOutcome::Killed {
        pid,
        process_path: observed.unwrap_or_default(),
    }
}

#[derive(Debug)]
pub(crate) enum TerminateError {
    NotRunning,
    PermissionDenied,
    Other(String),
}

#[cfg(unix)]
mod platform {
    use super::TerminateError;

    pub fn is_alive(pid: u32) -> bool {
        // SAFETY: kill(2) with signal 0 only probes existence / permission.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        let exists = rc == 0
            // EPERM: exists but not ours -- still alive.
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        // A killed process stays a zombie until its parent reaps it; the
        // signal probe still succeeds on it. Dead is dead.
        exists && !is_zombie(pid)
    }

    #[cfg(target_os = "linux")]
    fn is_zombie(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                // "pid (comm) S ..." -- the state follows the last ')'.
                let rest = stat.rsplit(')').next()?;
                rest.trim_start().chars().next()
            })
            .is_some_and(|state| state == 'Z' || state == 'X')
    }

    #[cfg(target_os = "macos")]
    fn is_zombie(pid: u32) -> bool {
        const SZOMB: u32 = 5;
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        // SAFETY: proc_pidinfo fills at most size_of::<proc_bsdinfo>() bytes.
        let len = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut libc::proc_bsdinfo as *mut libc::c_void,
                std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
            )
        };
        if len as usize == std::mem::size_of::<libc::proc_bsdinfo>() {
            return info.pbi_status == SZOMB;
        }
        // A zombie answers the signal probe but not proc_pidinfo (ESRCH);
        // a permission failure means a live process that is not ours.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn is_zombie(_pid: u32) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    pub fn image_path(pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| {
                p.to_string_lossy()
                    .trim_end_matches(" (deleted)")
                    .to_string()
            })
            .filter(|p| !p.is_empty())
    }

    #[cfg(target_os = "macos")]
    pub fn image_path(pid: u32) -> Option<String> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: proc_pidpath writes at most `buf.len()` bytes.
        let len = unsafe {
            libc::proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as u32,
            )
        };
        if len <= 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&buf[..len as usize]).to_string())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn image_path(_pid: u32) -> Option<String> {
        None
    }

    pub fn terminate(pid: u32) -> Result<(), TerminateError> {
        // SAFETY: plain kill(2).
        let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if rc == 0 {
            return Ok(());
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Err(TerminateError::NotRunning),
            Some(libc::EPERM) => Err(TerminateError::PermissionDenied),
            other => Err(TerminateError::Other(format!(
                "kill failed: errno {other:?}"
            ))),
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::TerminateError;
    use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
        PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    const STILL_ACTIVE: u32 = 259;

    pub fn is_alive(pid: u32) -> bool {
        // SAFETY: handle closed below.
        unsafe {
            let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
                // Access denied still means it exists.
                return windows::core::Error::from_thread().code()
                    == ERROR_ACCESS_DENIED.to_hresult();
            };
            let mut code: u32 = 0;
            let alive = GetExitCodeProcess(handle, &mut code).is_ok() && code == STILL_ACTIVE;
            let _ = CloseHandle(handle);
            alive
        }
    }

    pub fn image_path(pid: u32) -> Option<String> {
        // SAFETY: handle closed below; buffer sized by `len`.
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buf = vec![0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_FORMAT(0),
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
            .is_ok();
            let _ = CloseHandle(handle);
            if !ok || len == 0 {
                return None;
            }
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    pub fn terminate(pid: u32) -> Result<(), TerminateError> {
        // SAFETY: handle closed below.
        unsafe {
            let handle = match OpenProcess(PROCESS_TERMINATE, false, pid) {
                Ok(h) => h,
                Err(e) => {
                    return Err(if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
                        TerminateError::PermissionDenied
                    } else if e.code() == ERROR_INVALID_PARAMETER.to_hresult() {
                        TerminateError::NotRunning
                    } else {
                        TerminateError::Other(format!("OpenProcess failed: {e}"))
                    })
                }
            };
            let result = TerminateProcess(handle, 137);
            let _ = CloseHandle(handle);
            result.map_err(|e| TerminateError::Other(format!("TerminateProcess failed: {e}")))
        }
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
mod platform {
    use super::TerminateError;
    pub fn is_alive(_pid: u32) -> bool {
        false
    }
    pub fn image_path(_pid: u32) -> Option<String> {
        None
    }
    pub fn terminate(_pid: u32) -> Result<(), TerminateError> {
        Err(TerminateError::Other("unsupported platform".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_pids_and_images_are_refused_before_any_kill() {
        assert!(refusal_reason(0, None).is_some());
        assert!(refusal_reason(1, Some("/sbin/launchd")).is_some());
        assert!(refusal_reason(std::process::id(), None).is_some());
        assert!(refusal_reason(4242, Some("/usr/local/bin/edamame_posture")).is_some());
        assert!(refusal_reason(4242, Some("C:\\Windows\\System32\\lsass.exe")).is_some());
        assert!(
            refusal_reason(4242, Some("C:\\Program Files\\EDAMAME\\edamame_helper.exe")).is_some()
        );
        assert!(refusal_reason(4242, Some("/usr/bin/python3")).is_none());
        assert!(refusal_reason(4242, None).is_none());
        assert!(matches!(
            kill_process(1, ""),
            KillProcessOutcome::Refused { .. } | KillProcessOutcome::PermissionDenied { .. }
        ));
    }

    #[test]
    fn identity_mismatch_and_not_running_never_kill() {
        // A pid nobody has: the OS reports it gone.
        assert_eq!(
            kill_process(u32::MAX - 7, "/nope"),
            KillProcessOutcome::NotRunning { pid: u32::MAX - 7 }
        );
        // A live child whose image is not what the caller expects is left
        // alone.
        #[cfg(unix)]
        {
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn sleep");
            let pid = child.id();
            let outcome = kill_process(pid, "/definitely/not/sleep");
            assert!(
                matches!(outcome, KillProcessOutcome::IdentityMismatch { .. }),
                "{outcome:?}"
            );
            assert!(process_is_alive(pid), "mismatch must not kill");
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn kill_terminates_a_matching_child() {
        #[cfg(unix)]
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        #[cfg(target_os = "windows")]
        let mut child = std::process::Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn ping");
        let pid = child.id();
        let expected = process_image_path(pid).expect("image path of a live child");
        let outcome = kill_process(pid, &expected);
        assert!(outcome.is_killed(), "{outcome:?}");
        let status = child.wait().expect("wait");
        assert!(!status.success());
        assert!(!process_is_alive(pid) || child.try_wait().is_ok());
        assert_eq!(
            kill_process(pid, ""),
            KillProcessOutcome::NotRunning { pid }
        );
    }
}
