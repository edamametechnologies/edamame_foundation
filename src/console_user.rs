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
    use users::os::unix::UserExt;

    const CACHE_TTL: Duration = Duration::from_secs(30);

    lazy_static! {
        static ref CACHE: ArcSwap<Option<(Instant, Option<PathBuf>)>> = ArcSwap::from_pointee(None);
    }

    fn home_of(name: &str) -> Option<PathBuf> {
        users::get_user_by_name(name).map(|u| u.home_dir().to_path_buf())
    }

    fn resolve_uncached() -> Option<PathBuf> {
        // Only a privileged process has the problem this solves. A daemon
        // running as the user already has the right `$HOME`.
        if unsafe { libc::getuid() } != 0 {
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn display_picker_prefers_the_active_session_with_a_display() {
        let sessions = [
            sess("1", "alice", true, "user", ""),
            sess("2", "alice", true, "user", ":0"),
        ];
        assert_eq!(pick_console_display(&sessions).as_deref(), Some(":0"));
    }
}
