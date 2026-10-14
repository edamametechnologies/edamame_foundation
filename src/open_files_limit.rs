//! The open-files limit of a long-running EDAMAME process (2.0.8).
//!
//! A long-running process (the helper, the posture daemon, the app's core)
//! holds sockets, capture handles, file watches and child pipes at once, for
//! days. launchd starts a daemon with a soft `RLIMIT_NOFILE` of 256
//! (`launchctl limit maxfiles`), which leaves such a process little headroom.
//! [`raise_open_files_limit`] raises the soft limit to [`OPEN_FILES_TARGET`]
//! within the hard limit. It never lowers the soft limit and never touches
//! the hard one. The helper calls it at start; the posture daemon and the
//! app's core can too.
//!
//! The target is `FD_SETSIZE` (1024) and goes no higher: code in these
//! processes waits on descriptors with `select` (`pnet_datalink`'s BPF and
//! Linux channels, used by the ARP scan), and an `fd_set` holds only
//! descriptor numbers below `FD_SETSIZE`. A soft limit of 1024 keeps every
//! descriptor the process opens below it.
//!
//! | Platform | Effect |
//! |---|---|
//! | macOS | soft limit up to min([`OPEN_FILES_TARGET`], hard, `OPEN_MAX`, `kern.maxfilesperproc`) |
//! | Linux | soft limit up to min([`OPEN_FILES_TARGET`], hard) (a systemd service already starts at 1024) |
//! | Windows | not applicable: no per-process descriptor limit of this kind |
//! | iOS, Android | not applicable: app processes, not called |

use std::sync::OnceLock;

/// The soft open-files limit a long-running EDAMAME process asks for:
/// `FD_SETSIZE`, four times launchd's default of 256, and the highest
/// limit under which every descriptor number still fits an `fd_set` (see
/// the module docs).
pub const OPEN_FILES_TARGET: u64 = 1024;

// The target never passes FD_SETSIZE where the limit is raised.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const _: () = assert!(OPEN_FILES_TARGET <= libc::FD_SETSIZE as u64);

/// The soft open-files limit before and after [`raise_open_files_limit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFilesLimit {
    /// Soft limit found at the call.
    pub before: u64,
    /// Soft limit in force after it (`before` when nothing changed).
    pub after: u64,
    /// Hard limit, `None` when unlimited.
    pub hard: Option<u64>,
}

/// The soft limit to ask for: [`OPEN_FILES_TARGET`] within the hard limit
/// and the platform's own ceiling, never below the current soft limit.
pub fn soft_limit_goal(current: u64, hard: Option<u64>, platform_cap: Option<u64>) -> u64 {
    let ceiling = [Some(OPEN_FILES_TARGET), hard, platform_cap]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(OPEN_FILES_TARGET);
    current.max(ceiling)
}

/// Raise this process's soft open-files limit (see the module docs), once:
/// the first call does it and logs the values before and after, later calls
/// return what it did. `None` where the platform has no such limit, or when
/// the limit could not be read or set (logged).
pub fn raise_open_files_limit() -> Option<OpenFilesLimit> {
    static RAISED: OnceLock<Option<OpenFilesLimit>> = OnceLock::new();
    *RAISED.get_or_init(|| match raise_soft_limit() {
        Ok(Some(limit)) => {
            let hard = limit
                .hard
                .map_or_else(|| "unlimited".to_string(), |hard| hard.to_string());
            if limit.after > limit.before {
                tracing::info!(
                    "Open files limit raised from {} to {} (hard limit {})",
                    limit.before,
                    limit.after,
                    hard
                );
            } else {
                tracing::info!(
                    "Open files limit kept at {} (hard limit {})",
                    limit.after,
                    hard
                );
            }
            Some(limit)
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("Open files limit could not be raised: {}", e);
            None
        }
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn raise_soft_limit() -> std::io::Result<Option<OpenFilesLimit>> {
    let current = read_limit()?;
    let before = current.rlim_cur as u64;
    let hard = (current.rlim_max != libc::RLIM_INFINITY).then_some(current.rlim_max as u64);
    let goal = soft_limit_goal(before, hard, platform_cap());
    if goal > before {
        let wanted = libc::rlimit {
            rlim_cur: goal as libc::rlim_t,
            rlim_max: current.rlim_max,
        };
        // SAFETY: setrlimit only reads the struct it is given.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &wanted) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(Some(OpenFilesLimit {
        before,
        after: read_limit()?.rlim_cur as u64,
        hard,
    }))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn raise_soft_limit() -> std::io::Result<Option<OpenFilesLimit>> {
    Ok(None)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn read_limit() -> std::io::Result<libc::rlimit> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes the struct it is given.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(limit)
}

/// macOS refuses a soft limit above `OPEN_MAX` (10240, `<sys/syslimits.h>`)
/// on some versions and never grants more than `kern.maxfilesperproc`.
#[cfg(target_os = "macos")]
fn platform_cap() -> Option<u64> {
    const OPEN_MAX: u64 = 10240;
    let mut per_process: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is NUL-terminated; `per_process` and `size` outlive
    // the call, which writes at most `size` bytes into `per_process`.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            &mut per_process as *mut libc::c_int as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    let per_process = (rc == 0 && per_process > 0).then_some(per_process as u64);
    Some(per_process.map_or(OPEN_MAX, |limit| limit.min(OPEN_MAX)))
}

/// Linux takes any soft limit up to the hard one.
#[cfg(target_os = "linux")]
fn platform_cap() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_goal_is_the_target_within_the_hard_limit_and_the_platform_cap() {
        assert_eq!(OPEN_FILES_TARGET, 1024);
        // launchd's default under an unlimited hard limit.
        assert_eq!(soft_limit_goal(256, None, Some(10240)), OPEN_FILES_TARGET);
        // A hard limit and a platform cap above the target do not lift it
        // past FD_SETSIZE.
        assert_eq!(
            soft_limit_goal(256, Some(1_048_576), Some(10240)),
            OPEN_FILES_TARGET
        );
        // systemd's default (1024 / 524288) is the target already.
        assert_eq!(
            soft_limit_goal(1024, Some(524_288), None),
            OPEN_FILES_TARGET
        );
        // A hard limit below the target is the ceiling.
        assert_eq!(soft_limit_goal(256, Some(512), None), 512);
        // So is a platform cap below it (a low kern.maxfilesperproc).
        assert_eq!(soft_limit_goal(256, None, Some(768)), 768);
        // Never lowered, even above the target.
        assert_eq!(soft_limit_goal(65_536, Some(1_048_576), None), 65_536);
        assert_eq!(soft_limit_goal(4096, Some(4096), None), 4096);
        assert_eq!(soft_limit_goal(2048, None, Some(10240)), 2048);
    }

    /// In a child process, whose limit can be lowered without starving the
    /// tests running next to this one: from launchd's 256 the soft limit is
    /// raised to the goal, the hard limit untouched, and a second call does
    /// nothing more.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn the_soft_limit_is_raised_from_launchds_default() {
        const CHILD: &str = "EDAMAME_OPEN_FILES_LIMIT_CHILD";
        const NAME: &str =
            "open_files_limit::tests::the_soft_limit_is_raised_from_launchds_default";
        if std::env::var_os(CHILD).is_some() {
            let mut start = read_limit().unwrap();
            start.rlim_cur = 256;
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &start) }, 0);
            let hard = (start.rlim_max != libc::RLIM_INFINITY).then_some(start.rlim_max as u64);
            let limit = raise_open_files_limit().expect("raised");
            assert_eq!(limit.before, 256);
            assert_eq!(limit.hard, hard);
            assert_eq!(limit.after, soft_limit_goal(256, hard, platform_cap()));
            assert!(limit.after > 256, "{limit:?}");
            let now = read_limit().unwrap();
            assert_eq!(now.rlim_cur as u64, limit.after);
            assert_eq!(now.rlim_max, start.rlim_max);
            assert_eq!(raise_open_files_limit(), Some(limit));
            println!("{CHILD} ok");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains(&format!("{CHILD} ok")),
            "child failed: {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
