//! Console-user resolution for a privileged daemon.
//!
//! A posture daemon started by systemd runs as root before anyone has logged
//! in, so `$HOME` is `/root`. Everything that keys off "the user's home" --
//! the FIM watch roots, the agent surface (`~/.claude`, `~/.cursor`), the
//! secret-content scan -- then targets root's empty home, and the desktop
//! user's is invisible. Observed on the Linux dogfood host on 2026-09-12: FIM
//! had watched `/root/.ssh`, `/root/.config` and `/root/.local/share` for
//! seven days while `azureuser` was the only person on the box.
//!
//! [`console_user_home`] answers "whose desktop is this?" for a root process:
//! `SUDO_USER` when an operator ran us interactively, otherwise the single
//! distinct non-root user holding an active `Class=user` logind session, of
//! ANY type. Session type is deliberately not consulted. On that dogfood host
//! the GUI runs under xrdp, so every session is `Type=tty`, `Display=` empty,
//! `Remote=yes`, and a "graphical session" rule matches nothing exactly where
//! it is needed. The fixture in the tests below is that host's real
//! `loginctl` output, not an invented one.
//!
//! An explicit non-root `$HOME` wins before any of this runs: `sudo -E`, an
//! operator exporting `HOME` on purpose, or a test harness planting a
//! temporary home have all said where home is, and second-guessing them
//! through `SUDO_USER` or logind sent the Linux transcript-observer tests to
//! the runner's real home instead of the planted one (`edamame_core`
//! tests.yml, red from 34696139049 to 34752753183). A root process whose
//! `$HOME` is unset, empty or root's own home is the systemd case this module
//! exists for.
//!
//! Fails closed. Not root, no logind, no active non-root user, or more than
//! one distinct active user all yield `None`, and callers keep today's
//! behaviour. Cached for 30 s behind an `ArcSwap` because
//! [`crate::agent_plugin::real_home_dir`] is called from synchronous paths
//! and the answer only changes on login or logout.
//!
//! Platform matrix: Linux is the only platform with a systemd-started root
//! daemon and logind, so it is the only active arm. macOS and Windows return
//! `None` and are unchanged; on macOS the app runs as the user and the helper
//! never resolves a home (core passes it), and the Windows service running as
//! SYSTEM has the same class of problem but no logind, which is recorded as a
//! follow-up rather than guessed at here.

use std::path::PathBuf;

/// One logind session as reported by `loginctl show-session`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogindSession {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub class: String,
    pub session_type: String,
    pub display: String,
    pub remote: bool,
}

/// Session ids from `loginctl list-sessions --no-legend`. The first
/// whitespace-separated column is the id; everything else varies by
/// systemd version, so nothing else is read from this listing.
pub fn parse_list_sessions(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_string)
        .collect()
}

/// `Key=Value` lines from `loginctl show-session <id> -p ...`.
pub fn parse_show_session(id: &str, text: &str) -> LogindSession {
    let mut s = LogindSession {
        id: id.to_string(),
        ..Default::default()
    };
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "Name" => s.name = v.to_string(),
            "Active" => s.active = v.eq_ignore_ascii_case("yes"),
            "Class" => s.class = v.to_string(),
            "Type" => s.session_type = v.to_string(),
            "Display" => s.display = v.to_string(),
            "Remote" => s.remote = v.eq_ignore_ascii_case("yes"),
            _ => {}
        }
    }
    s
}

/// The single distinct non-root user with an active user-class session.
///
/// Ambiguity fails closed: two different people logged in means there is no
/// one "console user", and guessing would point every home-relative check at
/// the wrong account. Duplicate sessions of the SAME user (a closing tty
/// beside the live one, as on the dogfood host) are one user, not two.
pub fn pick_console_user(sessions: &[LogindSession]) -> Option<String> {
    let mut names: Vec<&str> = sessions
        .iter()
        .filter(|s| s.active && s.class == "user" && !s.name.is_empty() && s.name != "root")
        .map(|s| s.name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    match names.as_slice() {
        [one] => Some((*one).to_string()),
        _ => None,
    }
}

/// The X/Wayland display of the first active session that has one. Used by
/// the agent-CLI launcher; kept here so it shares one logind walk with the
/// home resolution instead of shelling out twice.
pub fn pick_console_display(sessions: &[LogindSession]) -> Option<String> {
    sessions
        .iter()
        .find(|s| s.active && !s.display.is_empty())
        .map(|s| s.display.clone())
}

/// `true` when the process was handed a home of its own: `$HOME` set, non-empty
/// and not root's home. The resolver then stays out of the way and
/// `dirs::home_dir()` follows `$HOME` as it always did.
pub fn explicit_home_wins(home_env: Option<&str>, root_home: &std::path::Path) -> bool {
    match home_env.map(str::trim) {
        None | Some("") => false,
        Some(home) => {
            let home = std::path::Path::new(home);
            home != std::path::Path::new("/root") && home != root_home
        }
    }
}

#[cfg(target_os = "linux")]
pub fn enumerate_sessions() -> Vec<LogindSession> {
    let Ok(list) = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .output()
    else {
        return Vec::new();
    };
    let ids = parse_list_sessions(&String::from_utf8_lossy(&list.stdout));
    ids.iter()
        .filter_map(|id| {
            std::process::Command::new("loginctl")
                .args([
                    "show-session",
                    id,
                    "-p",
                    "Name",
                    "-p",
                    "Active",
                    "-p",
                    "Class",
                    "-p",
                    "Type",
                    "-p",
                    "Display",
                    "-p",
                    "Remote",
                ])
                .output()
                .ok()
                .map(|out| parse_show_session(id, &String::from_utf8_lossy(&out.stdout)))
        })
        .collect()
}

#[cfg(target_os = "linux")]
mod resolve {
    use super::*;
    use arc_swap::ArcSwap;
    use lazy_static::lazy_static;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    // `User::home_dir` is a trait method, not inherent. This module only
    // compiles on Linux, so the macOS cross-target sweep cannot see a missing
    // import here; the Lima VM check is what caught it.
    use uzers::os::unix::UserExt;

    const CACHE_TTL: Duration = Duration::from_secs(30);

    lazy_static! {
        static ref CACHE: ArcSwap<Option<(Instant, Option<PathBuf>)>> = ArcSwap::from_pointee(None);
    }

    fn home_of(name: &str) -> Option<PathBuf> {
        uzers::get_user_by_name(name).map(|u| u.home_dir().to_path_buf())
    }

    fn resolve_uncached() -> Option<PathBuf> {
        // Only a privileged process has the problem this solves. A daemon
        // running as the user already has the right `$HOME`.
        if unsafe { libc::getuid() } != 0 {
            return None;
        }
        // A home the process was explicitly given is the answer; see the
        // module docs for why SUDO_USER and logind must not override it.
        let root_home = uzers::get_user_by_uid(0)
            .map(|u| u.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/root"));
        if explicit_home_wins(std::env::var("HOME").ok().as_deref(), &root_home) {
            return None;
        }
        // Interactive `sudo edamame_posture ...`: the invoking user is known
        // exactly, no need to consult logind.
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            let sudo_user = sudo_user.trim();
            if !sudo_user.is_empty() && sudo_user != "root" {
                if let Some(home) = home_of(sudo_user) {
                    return Some(home);
                }
            }
        }
        let name = pick_console_user(&enumerate_sessions())?;
        home_of(&name)
    }

    pub fn console_user_home() -> Option<PathBuf> {
        if let Some((at, cached)) = CACHE.load().as_ref() {
            if at.elapsed() < CACHE_TTL {
                return cached.clone();
            }
        }
        let resolved = resolve_uncached();
        CACHE.store(Arc::new(Some((Instant::now(), resolved.clone()))));
        resolved
    }
}

/// Home directory of the console user, for a process running as root.
/// See the module docs for the rule and the platform matrix.
#[cfg(target_os = "linux")]
pub fn console_user_home() -> Option<PathBuf> {
    resolve::console_user_home()
}

/// No logind and no systemd-started root daemon on these platforms; callers
/// fall through to their existing home resolution unchanged.
#[cfg(not(target_os = "linux"))]
pub fn console_user_home() -> Option<PathBuf> {
    None
}

/// The home of the user at this machine's console, for core's
/// `resolve_user_home` when the process runs as a privileged account whose
/// own home stands in for the user's (macOS: root, `/var/root`; Windows:
/// SYSTEM, its profile under the Windows directory). The helper never calls
/// it: it is handed the home in its order. `None` when the process is not
/// privileged, when it was given a home of its own (an explicit `$HOME`
/// that is not the privileged account's), or when no user is at the
/// console: callers keep the home they had.
///
/// The rule, without the system calls: the invoking user of `sudo` first,
/// then the user at the console.
pub fn console_home_choice(
    process_privileged: bool,
    own_home_is_privileged: bool,
    sudo_user_home: impl FnOnce() -> Option<PathBuf>,
    console_user_home: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    if !process_privileged || !own_home_is_privileged {
        return None;
    }
    sudo_user_home().or_else(console_user_home)
}

/// macOS: root's console user, by `SUDO_USER` and else by the owner of
/// `/dev/console` (the user logged in at the screen; root while nobody is).
#[cfg(target_os = "macos")]
pub fn privileged_console_user_home(own_home: Option<&std::path::Path>) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    use uzers::os::unix::UserExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    let own_home_is_roots = own_home.map_or(true, |home| {
        std::fs::metadata(home).map_or(true, |meta| meta.uid() == 0)
    });
    console_home_choice(
        root,
        own_home_is_roots,
        || {
            let name = std::env::var("SUDO_USER").ok()?;
            let name = name.trim();
            if name.is_empty() || name == "root" {
                return None;
            }
            uzers::get_user_by_name(name).map(|user| user.home_dir().to_path_buf())
        },
        || {
            let uid = std::fs::metadata("/dev/console").ok()?.uid();
            if uid == 0 {
                return None;
            }
            uzers::get_user_by_uid(uid).map(|user| user.home_dir().to_path_buf())
        },
    )
}

/// Windows: SYSTEM's console user, the profile of the user logged on to the
/// console session (`WTSGetActiveConsoleSessionId`, `WTSQueryUserToken`,
/// the profile in that user's environment block). `SUDO_USER` has no
/// meaning here.
#[cfg(target_os = "windows")]
pub fn privileged_console_user_home(own_home: Option<&std::path::Path>) -> Option<PathBuf> {
    let windows_dir = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .map(|dir| dir.to_string_lossy().to_lowercase())
        .unwrap_or_else(|| "c:\\windows".to_string());
    let own_home_is_system = own_home.map_or(true, |home| {
        home.to_string_lossy()
            .to_lowercase()
            .starts_with(windows_dir.trim_end_matches('\\'))
    });
    console_home_choice(
        own_home_is_system,
        own_home_is_system,
        || None,
        windows_console_profile,
    )
}

#[cfg(target_os = "windows")]
fn windows_console_profile() -> Option<PathBuf> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
    // SAFETY: no preconditions; 0xFFFFFFFF means no session is attached.
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == u32::MAX {
        return None;
    }
    let mut token = HANDLE::default();
    // SAFETY: `token` outlives the call; only SYSTEM holds the privilege
    // this needs, any other caller gets an error.
    unsafe { WTSQueryUserToken(session, &mut token) }.ok()?;
    let mut block: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `block` and `token` outlive the call; the block is destroyed
    // below and the token closed.
    let created = unsafe { CreateEnvironmentBlock(&mut block, Some(token), false) };
    let profile = if created.is_ok() && !block.is_null() {
        // SAFETY: the block is a sequence of NUL-terminated UTF-16 strings
        // ended by an empty one, as CreateEnvironmentBlock returns it.
        let units = unsafe { environment_block_units(block as *const u16) };
        let profile = profile_from_environment_block(&units);
        // SAFETY: the block was created above and is not used afterwards.
        let _ = unsafe { DestroyEnvironmentBlock(block) };
        profile
    } else {
        None
    };
    // SAFETY: the token was opened above and is not used afterwards.
    let _ = unsafe { CloseHandle(token) };
    profile
}

/// The UTF-16 units of an environment block, up to its terminating empty
/// string.
///
/// # Safety
/// `block` points to NUL-terminated UTF-16 strings ended by an empty one.
#[cfg(target_os = "windows")]
unsafe fn environment_block_units(block: *const u16) -> Vec<u16> {
    let mut units = Vec::new();
    let mut index = 0usize;
    loop {
        // SAFETY: within the block, per the caller's contract.
        let unit = unsafe { *block.add(index) };
        let previous = units.last().copied();
        units.push(unit);
        index += 1;
        if unit == 0 && (previous == Some(0) || units.len() == 1) {
            break;
        }
    }
    units
}

/// `USERPROFILE` from an environment block (NUL-separated UTF-16
/// `NAME=value` strings), the name in any letter case.
pub fn profile_from_environment_block(units: &[u16]) -> Option<PathBuf> {
    units
        .split(|unit| *unit == 0)
        .map(String::from_utf16_lossy)
        .find_map(|entry| {
            let (name, value) = entry.split_once('=')?;
            (name.eq_ignore_ascii_case("USERPROFILE") && !value.trim().is_empty())
                .then(|| PathBuf::from(value))
        })
}

/// Other platforms: no privileged console resolution here (Linux resolves
/// its console user inside `real_home_dir`, [`console_user_home`]).
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn privileged_console_user_home(_own_home: Option<&std::path::Path>) -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The console user is looked up only for a privileged process whose
    /// own home is the privileged account's; the invoking user of `sudo`
    /// comes first.
    #[test]
    fn the_console_user_is_the_answer_only_for_a_privileged_process() {
        let user = || Some(PathBuf::from("/Users/u"));
        let console = || Some(PathBuf::from("/Users/c"));
        assert_eq!(
            console_home_choice(true, true, user, console),
            Some(PathBuf::from("/Users/u"))
        );
        assert_eq!(
            console_home_choice(true, true, || None, console),
            Some(PathBuf::from("/Users/c"))
        );
        assert_eq!(console_home_choice(true, true, || None, || None), None);
        // Not privileged, or given a home of its own: none.
        assert_eq!(console_home_choice(false, true, user, console), None);
        assert_eq!(console_home_choice(true, false, user, console), None);
    }

    /// The profile is read from an environment block, the name in any case.
    #[test]
    fn the_profile_is_read_from_an_environment_block() {
        let block: Vec<u16> = "PATH=C:\\x\0UserProfile=C:\\Users\\u\0TEMP=C:\\t\0\0"
            .encode_utf16()
            .collect();
        assert_eq!(
            profile_from_environment_block(&block),
            Some(PathBuf::from("C:\\Users\\u"))
        );
        let none: Vec<u16> = "PATH=C:\\x\0\0".encode_utf16().collect();
        assert_eq!(profile_from_environment_block(&none), None);
    }

    /// Verbatim `loginctl list-sessions --no-legend` from the Linux dogfood
    /// host (test-mint) on 2026-09-12. Three sessions for one user, two of
    /// them "closing", the GUI under xrdp so none carries a Display.
    const MINT_LIST: &str = "333 1000 azureuser - - closing no -\n\
                             415 1000 azureuser - - closing no -\n\
                             820 1000 azureuser - - active  no -\n";

    /// Verbatim `show-session 820` from the same host.
    const MINT_SHOW_820: &str =
        "Name=azureuser\nDisplay=\nRemote=yes\nType=tty\nClass=user\nActive=yes\n";

    fn sess(id: &str, name: &str, active: bool, class: &str, display: &str) -> LogindSession {
        LogindSession {
            id: id.into(),
            name: name.into(),
            active,
            class: class.into(),
            session_type: "tty".into(),
            display: display.into(),
            remote: true,
        }
    }

    #[test]
    fn list_sessions_yields_ids_only() {
        assert_eq!(parse_list_sessions(MINT_LIST), vec!["333", "415", "820"]);
        assert!(parse_list_sessions("").is_empty());
    }

    #[test]
    fn show_session_parses_the_real_dogfood_shape() {
        let s = parse_show_session("820", MINT_SHOW_820);
        assert_eq!(s.id, "820");
        assert_eq!(s.name, "azureuser");
        assert!(s.active);
        assert_eq!(s.class, "user");
        assert_eq!(s.session_type, "tty");
        assert_eq!(s.display, "");
        assert!(s.remote);
    }

    /// The case that motivated the rule: an xrdp desktop presents as three
    /// remote tty sessions of one user with no Display. A graphical-session
    /// rule would return None here; this returns the user.
    #[test]
    fn console_user_is_found_without_any_graphical_session() {
        let sessions: Vec<LogindSession> = parse_list_sessions(MINT_LIST)
            .iter()
            .map(|id| parse_show_session(id, MINT_SHOW_820))
            .collect();
        assert_eq!(pick_console_user(&sessions).as_deref(), Some("azureuser"));
        assert_eq!(
            pick_console_display(&sessions),
            None,
            "no session on that host carries a display"
        );
    }

    #[test]
    fn root_only_and_empty_fail_closed() {
        assert_eq!(pick_console_user(&[]), None);
        assert_eq!(
            pick_console_user(&[sess("1", "root", true, "user", "")]),
            None
        );
        assert_eq!(pick_console_user(&[sess("1", "", true, "user", "")]), None);
    }

    #[test]
    fn two_distinct_users_is_ambiguous_and_fails_closed() {
        let sessions = [
            sess("1", "alice", true, "user", ""),
            sess("2", "bob", true, "user", ""),
        ];
        assert_eq!(
            pick_console_user(&sessions),
            None,
            "two people logged in means there is no single console user"
        );
    }

    #[test]
    fn inactive_and_non_user_class_sessions_are_ignored() {
        let sessions = [
            sess("1", "alice", false, "user", ""),
            sess("2", "gdm", true, "greeter", ""),
            sess("3", "bob", true, "user", ""),
        ];
        assert_eq!(pick_console_user(&sessions).as_deref(), Some("bob"));
    }

    /// The CI shape that stayed red for a day: `sudo -E cargo test` keeps the
    /// runner's `$HOME`, the observer tests plant a temporary one on top, and
    /// the resolver must follow it instead of SUDO_USER's passwd entry.
    #[test]
    fn explicit_non_root_home_wins_over_sudo_user_and_logind() {
        let root = std::path::Path::new("/root");
        assert!(explicit_home_wins(Some("/tmp/planted-home"), root));
        assert!(explicit_home_wins(Some("/home/runner"), root));
        assert!(
            explicit_home_wins(Some("  /home/runner  "), root),
            "whitespace is trimmed"
        );
    }

    /// The systemd case the module exists for: HOME unset, empty or root's own.
    #[test]
    fn root_or_absent_home_does_not_block_resolution() {
        let root = std::path::Path::new("/root");
        assert!(!explicit_home_wins(None, root));
        assert!(!explicit_home_wins(Some(""), root));
        assert!(!explicit_home_wins(Some("/root"), root));
        assert!(
            !explicit_home_wins(Some("/var/root"), std::path::Path::new("/var/root")),
            "a non-standard root home from passwd counts as root's home"
        );
    }

    #[test]
    fn display_picker_prefers_the_active_session_with_a_display() {
        let sessions = [
            sess("1", "alice", true, "user", ""),
            sess("2", "alice", true, "user", ":0"),
        ];
        assert_eq!(pick_console_display(&sessions).as_deref(), Some(":0"));
    }
}
