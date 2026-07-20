//! Agent-CLI transport for the Enlightenment Coach and the fix runner.
//!
//! Two spawn disciplines share the binary-resolution and parsing logic:
//!
//! - **Insight** (`run_agent_cli_insight`): read-only, ephemeral, tools
//!   disabled, prompt on stdin, waits for completion and extracts the model's
//!   text answer from the CLI's structured stdout. Used ONLY when no
//!   `LLMClient` provider is configured -- the observed agent grades its own
//!   homework, which the caller must badge visibly.
//! - **Fix** (`run_agent_cli_fix_interactive`): user-initiated, workspace cwd,
//!   normal tool permissions, session persistence ON (the resulting session is
//!   recorded and re-graded by the transcript observer like any other). Opens
//!   the agent's interactive TUI in the operator's GUI session -- the agent's
//!   own approval UI gates every tool call -- and returns the spawn
//!   confirmation, never the output.
//!
//! Both standalone core and the helper daemon converge on these functions per
//! the Standalone vs Helper Dispatch Pattern.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use tracing::info;

/// Wall-clock budget for a blocking insight generation.
const INSIGHT_TIMEOUT_SECS: u64 = 180;

/// Agent types with a known headless CLI, in detection preference order.
/// (agent_type, binary name). Cursor ranks last for the insight transport:
/// `cursor-agent` has no ephemeral-session flag, so its insight runs land in
/// the observed transcript corpus (ask-mode read-only, but still recorded).
const AGENT_CLI_BINARIES: &[(&str, &str)] = &[
    ("claude_code", "claude"),
    ("codex", "codex"),
    ("cursor", "cursor-agent"),
];

/// The CLI binary name for a supported agent type, if it has one.
pub fn agent_cli_binary_name(agent_type: &str) -> Option<&'static str> {
    AGENT_CLI_BINARIES
        .iter()
        .find(|(t, _)| *t == agent_type)
        .map(|(_, b)| *b)
}

/// Candidate directories to search besides `$PATH`. The helper daemon runs
/// as root with a minimal PATH, so the user's standard install locations
/// (npm globals, homebrew, ~/.local) must be probed explicitly against the
/// provided real home.
fn candidate_bin_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(path_env) = std::env::var("PATH") {
        dirs.extend(std::env::split_paths(&path_env));
    }
    for fixed in [
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/bin",
        "/snap/bin",
    ] {
        dirs.push(PathBuf::from(fixed));
    }
    if let Some(home) = home {
        for rel in [
            ".local/bin",
            ".npm-global/bin",
            ".volta/bin",
            ".bun/bin",
            "bin",
            "AppData/Roaming/npm",
            "AppData/Local/Programs/claude/bin",
        ] {
            dirs.push(home.join(rel));
        }
    }
    dirs
}

fn binary_file_names(binary: &str) -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        vec![
            format!("{}.exe", binary),
            format!("{}.cmd", binary),
            format!("{}.bat", binary),
            binary.to_string(),
        ]
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![binary.to_string()]
    }
}

/// Resolve the absolute path of the agent's CLI binary, or `None` when it is
/// not installed. `home` is the (real) user home used to probe user-level
/// install locations; pass `None` to rely on `$PATH` + fixed system dirs.
pub fn resolve_agent_cli_binary(agent_type: &str, home: Option<&Path>) -> Option<PathBuf> {
    let binary = agent_cli_binary_name(agent_type)?;
    let names = binary_file_names(binary);
    for dir in candidate_bin_dirs(home) {
        for name in &names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Which of the given agent types have a detected CLI on this host, in the
/// canonical preference order (claude_code, then codex, then cursor).
/// Unknown agent types are skipped.
pub fn detect_agent_clis(agent_types: &[String], home: Option<&Path>) -> Vec<String> {
    AGENT_CLI_BINARIES
        .iter()
        .filter(|(t, _)| agent_types.iter().any(|a| a == t))
        .filter(|(t, _)| resolve_agent_cli_binary(t, home).is_some())
        .map(|(t, _)| t.to_string())
        .collect()
}

/// Spawn confirmation for an interactive fix run. The resulting session shows
/// up in the transcript observer and gets graded by the normal pipeline; the
/// run's live output is watched by the operator directly in the terminal
/// window opened in their desktop session (there is no captured log file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCliFixSpawn {
    pub agent_type: String,
    pub binary: String,
    pub workspace_path: String,
    pub pid: u32,
    /// The exact argv (binary + args) shown to the user in the confirmation
    /// dialog and logged for the audit trail.
    pub command: Vec<String>,
}

/// Sanitize an arbitrary string into a filesystem-safe log filename fragment
/// (ASCII alphanumerics, `-` and `_` kept; everything else collapsed to `-`).
fn sanitize_log_fragment(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "run".to_string()
    } else {
        trimmed.chars().take(48).collect()
    }
}

/// Give the newly-created log file (and its parent dir) back to the real user
/// when we are running as root (helper daemon case). No-op when not root or
/// on non-unix. Best-effort -- a chown failure never blocks the run.
#[cfg(unix)]
fn chown_fix_log_to_user(path: &Path, home: Option<&Path>) {
    use std::os::unix::fs::MetadataExt;
    if unsafe { libc::getuid() } != 0 {
        return;
    }
    let Some(home) = home else {
        return;
    };
    let Ok(meta) = std::fs::metadata(home) else {
        return;
    };
    let (uid, gid) = (meta.uid(), meta.gid());
    if let Ok(c_path) = std::ffi::CString::new(path.to_string_lossy().as_bytes()) {
        unsafe {
            libc::chown(c_path.as_ptr(), uid, gid);
        }
    }
}

#[cfg(not(unix))]
fn chown_fix_log_to_user(_path: &Path, _home: Option<&Path>) {}

fn insight_args(agent_type: &str) -> Vec<String> {
    match agent_type {
        // Prompt on stdin, JSON result on stdout, no session persistence,
        // all tools disabled -- the coach transport must never mutate state
        // or pollute the observed transcript corpus.
        "claude_code" => vec![
            "-p".into(),
            "--output-format".into(),
            "json".into(),
            "--no-session-persistence".into(),
            "--tools".into(),
            String::new(),
        ],
        // Prompt on stdin (trailing `-`), JSONL events on stdout, read-only
        // sandbox, ephemeral session.
        "codex" => vec![
            "exec".into(),
            "--json".into(),
            "--sandbox".into(),
            "read-only".into(),
            "--skip-git-repo-check".into(),
            "--ephemeral".into(),
            "-".into(),
        ],
        // Prompt on stdin, plain-text answer on stdout (no structured parse
        // needed), ask mode = read-only Q&A. No ephemeral flag exists, so the
        // run is recorded in Cursor's session history -- acceptable for the
        // last-resort transport, and why cursor ranks last in preference.
        "cursor" => vec![
            "-p".into(),
            "--output-format".into(),
            "text".into(),
            "--mode".into(),
            "ask".into(),
            "--trust".into(),
        ],
        _ => Vec::new(),
    }
}

/// Interactive (human-in-the-loop) CLI invocation for a fix run. These
/// intentionally OMIT any auto-approve / print-mode flags (`-p`, `--force`,
/// `--trust`, `exec`) so the agent launches its normal interactive TUI and its
/// own approval UI gates each tool call. Returns the flag list (the prompt is
/// NOT included -- the launching app seeds it) and how the prompt should be
/// delivered: `"arg"` (trailing positional) or `"stdin"`. Returns `None` for
/// agent types with no interactive invocation.
fn interactive_fix_args(agent_type: &str) -> Option<(Vec<String>, &'static str)> {
    match agent_type {
        // `claude "<prompt>"` opens the interactive REPL seeded with the
        // initial turn; dropping `-p` keeps it interactive.
        "claude_code" => Some((Vec::new(), "arg")),
        // `codex "<prompt>"` (no `exec`) opens the interactive TUI seeded with
        // the prompt.
        "codex" => Some((Vec::new(), "arg")),
        // `cursor-agent "<prompt>"` (no `-p/--force/--trust`) opens the
        // interactive TUI; the native trust + per-action approval prompts then
        // gate the run.
        "cursor" => Some((Vec::new(), "arg")),
        _ => None,
    }
}

/// Directory for interactive fix-run launch assets (the seeded prompt file and
/// the generated launcher script): `<home>/.edamame/agent-fix-runs/`, falling
/// back to the system temp dir when no home is known. The prompt is written
/// here and read back by the launcher script at launch time, so a multi-line
/// prompt never has to be embedded in a command line (side-stepping every
/// shell / PowerShell escaping hazard).
fn fix_run_dir(home: Option<&Path>) -> PathBuf {
    match home {
        Some(h) => h.join(".edamame").join("agent-fix-runs"),
        None => std::env::temp_dir().join("edamame-agent-fix-runs"),
    }
}

/// Single-quote a string for safe inclusion in a POSIX shell script.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Single-quote a string for safe inclusion in a PowerShell script.
#[cfg(target_os = "windows")]
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// When running as root (`uid == 0`, the helper daemon / a sudo'd standalone
/// posture), return the uid that owns `home` -- i.e. the human operator whose
/// GUI session we must cross back into to open a terminal. Returns `None` when
/// we are already the (non-root) interactive user, in which case the launch
/// happens directly in the current session.
#[cfg(unix)]
fn root_target_uid(home: Option<&Path>) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    if unsafe { libc::getuid() } != 0 {
        return None;
    }
    let home = home?;
    std::fs::metadata(home).ok().map(|m| m.uid())
}

/// Launch an INTERACTIVE fix run for `agent_type` in `workspace_path`, seeded
/// with `prompt`. This opens a real terminal window IN THE OPERATOR'S GUI SESSION
/// and starts the agent's normal interactive TUI, so the agent's own approval
/// UI gates every tool call -- the operator reads and confirms each step.
///
/// Called from the privileged side only (the helper daemon in app mode, or
/// `edamame_posture` in standalone mode), NEVER from the sandboxed app. A root
/// LaunchDaemon (macOS), a SYSTEM service (Windows, session-0 isolated), and a
/// `User=root` systemd unit (Linux) are all OUTSIDE the operator's GUI session,
/// so each platform crosses back into it:
///
/// - **macOS**: `launchctl asuser <uid> /usr/bin/open -a Terminal <script>`
///   (root daemon -> Aqua session); a direct `open` when already the user.
/// - **Linux**: a detected terminal emulator, via `sudo -u <user> env
///   DISPLAY=.. XAUTHORITY=..` when root; a direct launch when already the user.
/// - **Windows**: `WTSQueryUserToken` + `CreateProcessAsUserW` into
///   `winsta0\default` when running as SYSTEM; a `CREATE_NEW_CONSOLE` spawn when
///   `WTSQueryUserToken` is denied (the standalone-user case).
///
/// The prompt is written to a file and read back by the launcher script, so it
/// never crosses a command line. Returns an [`AgentCliFixSpawn`] whose `pid` is
/// the launcher's (interactive output lives in the operator's terminal, not a
/// captured file). Observer grading is unchanged: the resulting session is
/// recorded on disk like any other run.
pub fn run_agent_cli_fix_interactive(
    agent_type: &str,
    workspace_path: &str,
    prompt: &str,
    home: Option<&Path>,
) -> Result<AgentCliFixSpawn> {
    let binary = resolve_agent_cli_binary(agent_type, home)
        .ok_or_else(|| anyhow!("No CLI detected for agent type '{}'", agent_type))?;
    let workspace = Path::new(workspace_path);
    if !workspace.is_dir() {
        return Err(anyhow!(
            "Workspace path '{}' is not a directory",
            workspace_path
        ));
    }
    let (extra_argv, prompt_via) = interactive_fix_args(agent_type).ok_or_else(|| {
        anyhow!(
            "Agent type '{}' has no interactive CLI invocation",
            agent_type
        )
    })?;

    // Write the seeded prompt into a user-owned assets dir.
    let run_dir = fix_run_dir(home);
    std::fs::create_dir_all(&run_dir)
        .map_err(|e| anyhow!("Failed to create fix-run dir {}: {}", run_dir.display(), e))?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let slug = sanitize_log_fragment(agent_type);
    let prompt_path = run_dir.join(format!("{}-{}.prompt.txt", slug, ts));
    std::fs::write(&prompt_path, prompt)
        .map_err(|e| anyhow!("Failed to write prompt file: {}", e))?;
    chown_fix_log_to_user(&run_dir, home);
    chown_fix_log_to_user(&prompt_path, home);

    let binary_str = binary.to_string_lossy().to_string();
    let human_command = {
        let mut c = vec![binary_str.clone()];
        c.extend(extra_argv.iter().cloned());
        c.push("<seeded prompt>".to_string());
        c
    };

    let pid = launch_interactive_terminal(LaunchCtx {
        binary: &binary_str,
        extra_argv: &extra_argv,
        prompt_via,
        workspace,
        prompt_path: &prompt_path,
        run_dir: &run_dir,
        slug: &slug,
        ts,
        home,
    })?;

    info!(
        "Launched interactive fix run: agent={} pid={} workspace={} binary={}",
        agent_type, pid, workspace_path, binary_str
    );

    Ok(AgentCliFixSpawn {
        agent_type: agent_type.to_string(),
        binary: binary_str,
        workspace_path: workspace_path.to_string(),
        pid,
        command: human_command,
    })
}

/// Bundle of resolved parameters handed to the per-platform terminal launcher
/// (avoids a `too_many_arguments` signature across the `#[cfg]` variants).
struct LaunchCtx<'a> {
    binary: &'a str,
    extra_argv: &'a [String],
    prompt_via: &'a str,
    workspace: &'a Path,
    prompt_path: &'a Path,
    run_dir: &'a Path,
    slug: &'a str,
    ts: u64,
    // Operator home: the macOS/Linux launchers read it to chown launch artifacts
    // and resolve the target uid for root->session crossing. The Windows launcher
    // crosses into the active console session via its user token (WTSQueryUserToken)
    // rather than a home path, so it never reads this field.
    #[cfg_attr(target_os = "windows", allow(dead_code))]
    home: Option<&'a Path>,
}

/// Write a POSIX `#!/bin/bash` launcher script that `cd`s into the workspace,
/// reads the seeded prompt back from its file, and `exec`s the agent CLI with
/// the operator's interactive TUI. Returns the script path (0755, chowned to
/// the user when created as root). Shared by the macOS and Linux launchers.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn write_posix_launch_script(ctx: &LaunchCtx, ext: &str) -> Result<PathBuf> {
    let mut argv_str = sh_single_quote(ctx.binary);
    for a in ctx.extra_argv {
        argv_str.push(' ');
        argv_str.push_str(&sh_single_quote(a));
    }
    let prompt_q = sh_single_quote(&ctx.prompt_path.to_string_lossy());
    let invoke = if ctx.prompt_via == "stdin" {
        format!("exec {} < {}", argv_str, prompt_q)
    } else {
        format!("exec {} \"$(cat {})\"", argv_str, prompt_q)
    };
    let body = format!(
        "#!/bin/bash\ncd {} || {{ echo 'EDAMAME: workspace not found'; exec \"$SHELL\"; }}\nclear\necho 'EDAMAME interactive fix run -- review each step; the agent asks before acting.'\necho\n{}\n",
        sh_single_quote(&ctx.workspace.to_string_lossy()),
        invoke,
    );
    let script = ctx.run_dir.join(format!("{}-{}.{}", ctx.slug, ctx.ts, ext));
    std::fs::write(&script, body).map_err(|e| anyhow!("Failed to write launch script: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755));
    }
    chown_fix_log_to_user(&script, ctx.home);
    Ok(script)
}

#[cfg(target_os = "macos")]
fn launch_interactive_terminal(ctx: LaunchCtx) -> Result<u32> {
    let script = write_posix_launch_script(&ctx, "command")?;
    let script_str = script.to_string_lossy().to_string();
    // Cross into the user's Aqua session when running as root (helper daemon).
    let uid = root_target_uid(ctx.home);
    let mut cmd = std::process::Command::new(if uid.is_some() {
        "/bin/launchctl"
    } else {
        "/usr/bin/open"
    });
    if let Some(uid) = uid {
        cmd.arg("asuser").arg(uid.to_string()).arg("/usr/bin/open");
    }
    cmd.arg("-a").arg("Terminal").arg(&script_str);
    let child = cmd
        .spawn()
        .map_err(|e| anyhow!("Failed to open Terminal: {}", e))?;
    Ok(child.id())
}

#[cfg(target_os = "linux")]
fn launch_interactive_terminal(ctx: LaunchCtx) -> Result<u32> {
    let script = write_posix_launch_script(&ctx, "sh")?;
    let script_str = script.to_string_lossy().to_string();
    let (term_bin, exec_flag) = detect_linux_terminal().ok_or_else(|| {
        anyhow!("No terminal emulator found (tried x-terminal-emulator, gnome-terminal, konsole, xfce4-terminal, alacritty, xterm)")
    })?;

    let mut cmd = if root_target_uid(ctx.home).is_some() {
        // root -> user's graphical session: sudo -u <user> env DISPLAY/XAUTHORITY.
        let user = ctx
            .home
            .and_then(user_name_from_home)
            .ok_or_else(|| anyhow!("Cannot resolve target user for interactive launch"))?;
        let display = detect_user_display().unwrap_or_else(|| ":0".to_string());
        let mut c = std::process::Command::new("sudo");
        c.arg("-u")
            .arg(&user)
            .arg("env")
            .arg(format!("DISPLAY={}", display));
        if let Some(home) = ctx.home {
            let xauth = home.join(".Xauthority");
            if xauth.is_file() {
                c.arg(format!("XAUTHORITY={}", xauth.to_string_lossy()));
            }
        }
        c.arg(term_bin).arg(exec_flag).arg(&script_str);
        c
    } else {
        let mut c = std::process::Command::new(term_bin);
        c.arg(exec_flag).arg(&script_str);
        c
    };
    let child = cmd
        .spawn()
        .map_err(|e| anyhow!("Failed to launch terminal '{}': {}", term_bin, e))?;
    Ok(child.id())
}

/// First installed terminal emulator + its "run this command" flag.
#[cfg(target_os = "linux")]
fn detect_linux_terminal() -> Option<(&'static str, &'static str)> {
    const CANDIDATES: &[(&str, &str)] = &[
        ("x-terminal-emulator", "-e"),
        ("gnome-terminal", "--"),
        ("konsole", "-e"),
        ("xfce4-terminal", "-x"),
        ("alacritty", "-e"),
        ("xterm", "-e"),
    ];
    CANDIDATES
        .iter()
        .find(|(bin, _)| which_in_path(bin).is_some())
        .map(|(bin, flag)| (*bin, *flag))
}

/// Locate an executable on `$PATH` plus the usual absolute fallbacks a minimal
/// root systemd `PATH` might omit.
#[cfg(target_os = "linux")]
fn which_in_path(bin: &str) -> Option<PathBuf> {
    if let Some(path_env) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_env) {
            let p = dir.join(bin);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    for fixed in ["/usr/bin", "/bin", "/usr/local/bin"] {
        let p = Path::new(fixed).join(bin);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Best-effort DISPLAY for the active graphical session (via logind), so a root
/// launcher can target the console user's X/Wayland display. Falls back to the
/// inherited `$DISPLAY`, then `None`.
#[cfg(target_os = "linux")]
fn detect_user_display() -> Option<String> {
    if let Ok(d) = std::env::var("DISPLAY") {
        if !d.is_empty() {
            return Some(d);
        }
    }
    let list = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&list.stdout);
    for line in text.lines() {
        let Some(sid) = line.split_whitespace().next() else {
            continue;
        };
        let Ok(show) = std::process::Command::new("loginctl")
            .args(["show-session", sid, "-p", "Display", "-p", "Active"])
            .output()
        else {
            continue;
        };
        let s = String::from_utf8_lossy(&show.stdout);
        let mut display = None;
        let mut active = false;
        for l in s.lines() {
            if let Some(v) = l.strip_prefix("Display=") {
                if !v.is_empty() {
                    display = Some(v.to_string());
                }
            }
            if l.trim() == "Active=yes" {
                active = true;
            }
        }
        if active {
            if let Some(d) = display {
                return Some(d);
            }
        }
    }
    None
}

/// Resolve the account name that owns `home` (the target of `sudo -u`).
#[cfg(target_os = "linux")]
fn user_name_from_home(home: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata(home).ok()?.uid();
    users::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().to_string())
}

#[cfg(target_os = "windows")]
fn launch_interactive_terminal(ctx: LaunchCtx) -> Result<u32> {
    // PowerShell launcher: cd, read the seeded prompt from its file, invoke the
    // agent. `-NoExit` keeps the window open after the agent exits so the
    // operator can read the final output.
    let mut invoke = format!("& {}", ps_single_quote(ctx.binary));
    for a in ctx.extra_argv {
        invoke.push(' ');
        invoke.push_str(&ps_single_quote(a));
    }
    let prompt_read = format!(
        "$EdamamePrompt = Get-Content -Raw -LiteralPath {}",
        ps_single_quote(&ctx.prompt_path.to_string_lossy())
    );
    let call = if ctx.prompt_via == "stdin" {
        format!("$EdamamePrompt | {}", invoke)
    } else {
        format!("{} $EdamamePrompt", invoke)
    };
    let body = format!(
        "Set-Location -LiteralPath {}\r\nWrite-Host 'EDAMAME interactive fix run -- review each step; the agent asks before acting.'\r\n{}\r\n{}\r\n",
        ps_single_quote(&ctx.workspace.to_string_lossy()),
        prompt_read,
        call,
    );
    let script = ctx.run_dir.join(format!("{}-{}.ps1", ctx.slug, ctx.ts));
    std::fs::write(&script, body).map_err(|e| anyhow!("Failed to write launch script: {}", e))?;
    let script_str = script.to_string_lossy().to_string();
    let workspace_str = ctx.workspace.to_string_lossy().to_string();
    let cmdline = format!(
        "powershell.exe -NoExit -NoProfile -ExecutionPolicy Bypass -File \"{}\"",
        script_str
    );

    // SYSTEM (helper service) -> active console session via a duplicated user
    // token. When WTSQueryUserToken is denied we are already the interactive
    // user (standalone posture), so fall back to a plain new-console spawn.
    match launch_in_active_session_windows(&cmdline, &workspace_str) {
        Ok(pid) => Ok(pid),
        Err(e) => {
            info!(
                "Interactive launch: session-crossing unavailable ({}); spawning in current session",
                e
            );
            use std::os::windows::process::CommandExt;
            const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
            let child = std::process::Command::new("powershell.exe")
                .args([
                    "-NoExit",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    &script_str,
                ])
                .current_dir(ctx.workspace)
                .creation_flags(CREATE_NEW_CONSOLE)
                .spawn()
                .map_err(|e| anyhow!("Failed to launch PowerShell console: {}", e))?;
            Ok(child.id())
        }
    }
}

/// Launch `cmdline` in the active console session's `winsta0\default` desktop
/// using the console user's duplicated primary token. Only succeeds for a
/// caller holding `SeTcbPrivilege` (SYSTEM); returns `Err` otherwise so the
/// caller can fall back to a same-session spawn.
#[cfg(target_os = "windows")]
fn launch_in_active_session_windows(cmdline: &str, workdir: &str) -> Result<u32> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    unsafe {
        let session_id = WTSGetActiveConsoleSessionId();
        if session_id == 0xFFFF_FFFF {
            return Err(anyhow!("No active console session"));
        }
        let mut user_token = HANDLE(std::ptr::null_mut());
        WTSQueryUserToken(session_id, &mut user_token)
            .map_err(|e| anyhow!("WTSQueryUserToken failed: {}", e))?;

        // Duplicate into a primary token usable by CreateProcessAsUserW.
        let mut primary = HANDLE(std::ptr::null_mut());
        let dup = DuplicateTokenEx(
            user_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        );
        let _ = CloseHandle(user_token);
        dup.map_err(|e| anyhow!("DuplicateTokenEx failed: {}", e))?;

        // User environment block so PATH etc. resolve for the launched agent.
        let mut env_block: *mut core::ffi::c_void = std::ptr::null_mut();
        let have_env = CreateEnvironmentBlock(&mut env_block, Some(primary), false).is_ok();

        let mut cmd_wide: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
        let workdir_wide: Vec<u16> = workdir.encode_utf16().chain(std::iter::once(0)).collect();
        let mut desktop: Vec<u16> = "winsta0\\default"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop.as_mut_ptr()),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        let mut flags = CREATE_NEW_CONSOLE;
        if have_env {
            flags |= CREATE_UNICODE_ENVIRONMENT;
        }

        let result = CreateProcessAsUserW(
            Some(primary),
            PCWSTR::null(),
            Some(PWSTR(cmd_wide.as_mut_ptr())),
            None,
            None,
            false,
            flags,
            if have_env {
                Some(env_block as *const core::ffi::c_void)
            } else {
                None
            },
            PCWSTR(workdir_wide.as_ptr()),
            &si,
            &mut pi,
        );

        if have_env {
            let _ = DestroyEnvironmentBlock(env_block);
        }
        let _ = CloseHandle(primary);

        match result {
            Ok(()) => {
                let pid = pi.dwProcessId;
                let _ = CloseHandle(pi.hThread);
                let _ = CloseHandle(pi.hProcess);
                Ok(pid)
            }
            Err(e) => Err(anyhow!("CreateProcessAsUserW failed: {}", e)),
        }
    }
}

fn configure_command(command: &mut Command, home: Option<&Path>) {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(home) = home {
        command.env("HOME", home);
        // Make user-level installs resolvable from the helper's minimal PATH.
        if let Ok(path_env) = std::env::var("PATH") {
            let mut paths: Vec<PathBuf> = std::env::split_paths(&path_env).collect();
            paths.extend(candidate_bin_dirs(Some(home)));
            if let Ok(joined) = std::env::join_paths(paths) {
                command.env("PATH", joined);
            }
        }
    }
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
}

/// Run a read-only, ephemeral insight generation through the detected agent
/// CLI. The prompt goes to stdin; the returned string is the extracted model
/// text (the caller validates it against the coach envelope schema).
pub async fn run_agent_cli_insight(
    agent_type: &str,
    prompt: &str,
    home: Option<&Path>,
) -> Result<String> {
    let binary = resolve_agent_cli_binary(agent_type, home)
        .ok_or_else(|| anyhow!("No CLI detected for agent type '{}'", agent_type))?;
    let args = insight_args(agent_type);
    if args.is_empty() {
        return Err(anyhow!(
            "Agent type '{}' has no insight CLI invocation",
            agent_type
        ));
    }

    info!(
        "Running agent-CLI insight via {} ({} bytes of prompt)",
        binary.display(),
        prompt.len()
    );
    let mut command = Command::new(&binary);
    command.args(&args);
    configure_command(&mut command, home);

    let mut child = command
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn {}: {}", binary.display(), e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(prompt.as_bytes())
            .await
            .map_err(|e| anyhow!("Failed to write prompt to agent CLI stdin: {}", e))?;
        drop(stdin);
    }

    let output = timeout(
        Duration::from_secs(INSIGHT_TIMEOUT_SECS),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "Agent CLI insight timed out after {}s",
            INSIGHT_TIMEOUT_SECS
        )
    })?
    .map_err(|e| anyhow!("Agent CLI insight failed: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Agent CLI exited with {}: {}",
            output.status,
            stderr.chars().take(500).collect::<String>()
        ));
    }

    let text = parse_agent_cli_output(agent_type, &stdout);
    if text.trim().is_empty() {
        return Err(anyhow!("Agent CLI produced no extractable output"));
    }
    Ok(text)
}

/// Extract the model's text answer from the CLI's structured stdout.
///
/// - Claude (`--output-format json`): a single JSON object with a `result`
///   string, OR (older CLI versions) a JSON array of events where the last
///   `{"type":"result"}` entry carries the text.
/// - Codex (`--json`): JSONL events; the answer is the last agent-message
///   item (`item.completed` with `item.type == "agent_message"`, or an
///   `agent_message` / `AgentMessage` event with a text/message field).
///
/// Falls back to the raw stdout when no structured shape matches, so the
/// downstream envelope validator still gets a chance.
pub fn parse_agent_cli_output(agent_type: &str, stdout: &str) -> String {
    let trimmed = stdout.trim();
    match agent_type {
        "claude_code" => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(text) = claude_result_text(&value) {
                    return text;
                }
            }
            trimmed.to_string()
        }
        "codex" => {
            let mut last_message: Option<String> = None;
            for line in trimmed.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if let Some(text) = codex_event_text(&value) {
                    last_message = Some(text);
                }
            }
            last_message.unwrap_or_else(|| trimmed.to_string())
        }
        _ => trimmed.to_string(),
    }
}

fn claude_result_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => map
            .get("result")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string()),
        serde_json::Value::Array(events) => events
            .iter()
            .rev()
            .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("result"))
            .and_then(|e| e.get("result"))
            .and_then(|r| r.as_str())
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn codex_event_text(value: &serde_json::Value) -> Option<String> {
    // Shape 1: {"type":"item.completed","item":{"type":"agent_message","text":"..."}}
    if value.get("type").and_then(|t| t.as_str()) == Some("item.completed") {
        let item = value.get("item")?;
        if item.get("type").and_then(|t| t.as_str()) == Some("agent_message") {
            return item
                .get("text")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());
        }
        return None;
    }
    // Shape 2: {"msg":{"type":"agent_message","message":"..."}} (event stream)
    if let Some(msg) = value.get("msg") {
        if msg.get("type").and_then(|t| t.as_str()) == Some("agent_message") {
            return msg
                .get("message")
                .or_else(|| msg.get("text"))
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_object_result_is_extracted() {
        let out = r#"{"type":"result","subtype":"success","result":"{\"summary\":\"ok\"}","total_cost_usd":0.01}"#;
        assert_eq!(
            parse_agent_cli_output("claude_code", out),
            "{\"summary\":\"ok\"}"
        );
    }

    #[test]
    fn claude_event_array_result_is_extracted() {
        let out = r#"[
            {"type":"system","subtype":"init"},
            {"type":"assistant","message":{"content":[{"type":"text","text":"thinking"}]}},
            {"type":"result","subtype":"success","result":"FINAL ANSWER"}
        ]"#;
        assert_eq!(parse_agent_cli_output("claude_code", out), "FINAL ANSWER");
    }

    #[test]
    fn claude_unstructured_output_falls_back_to_raw() {
        let out = "plain text answer";
        assert_eq!(parse_agent_cli_output("claude_code", out), out);
    }

    #[test]
    fn codex_jsonl_last_agent_message_wins() {
        let out = r#"{"type":"thread.started","thread_id":"t1"}
{"type":"item.completed","item":{"type":"reasoning","text":"hmm"}}
{"type":"item.completed","item":{"type":"agent_message","text":"first"}}
{"type":"item.completed","item":{"type":"agent_message","text":"LAST"}}
{"type":"turn.completed","usage":{"input_tokens":10}}"#;
        assert_eq!(parse_agent_cli_output("codex", out), "LAST");
    }

    #[test]
    fn codex_msg_event_shape_is_extracted() {
        let out = r#"{"id":"0","msg":{"type":"task_started"}}
{"id":"1","msg":{"type":"agent_message","message":"answer body"}}"#;
        assert_eq!(parse_agent_cli_output("codex", out), "answer body");
    }

    #[test]
    fn codex_no_agent_message_falls_back_to_raw() {
        let out = r#"{"type":"turn.completed"}"#;
        assert_eq!(parse_agent_cli_output("codex", out), out);
    }

    #[test]
    fn binary_names_map_known_agents_only() {
        assert_eq!(agent_cli_binary_name("claude_code"), Some("claude"));
        assert_eq!(agent_cli_binary_name("codex"), Some("codex"));
        assert_eq!(agent_cli_binary_name("cursor"), Some("cursor-agent"));
        assert_eq!(agent_cli_binary_name("openclaw"), None);
    }

    #[test]
    fn detect_skips_unknown_and_missing() {
        // "hermes" has no CLI mapping; a nonexistent home yields no user dirs
        // and an empty PATH hit for the mapped types.
        let detected = detect_agent_clis(
            &["hermes".to_string(), "openclaw".to_string()],
            Some(Path::new("/nonexistent")),
        );
        assert!(detected.is_empty());
    }

    #[test]
    fn insight_args_are_read_only_and_ephemeral() {
        let claude = insight_args("claude_code");
        assert!(claude.contains(&"--no-session-persistence".to_string()));
        assert!(claude.contains(&"--tools".to_string()));

        let codex = insight_args("codex");
        assert!(codex.contains(&"read-only".to_string()));
        assert!(codex.contains(&"--ephemeral".to_string()));

        // Cursor has no ephemeral flag; ask mode is its read-only discipline.
        let cursor = insight_args("cursor");
        assert!(cursor.contains(&"ask".to_string()));
        assert!(!cursor.contains(&"--force".to_string()));

        assert!(insight_args("hermes").is_empty());
    }

    #[test]
    fn interactive_fix_args_are_human_in_the_loop() {
        // The interactive invocation must OMIT the auto-approve / print-mode
        // flags so the agent's own approval UI gates every tool call. The
        // prompt is delivered as a trailing positional ("arg"), never a flag.
        for agent in ["claude_code", "codex", "cursor"] {
            let (argv, prompt_via) = interactive_fix_args(agent)
                .unwrap_or_else(|| panic!("{agent} should have an interactive invocation"));
            assert_eq!(prompt_via, "arg");
            assert!(!argv.iter().any(|a| a == "-p"));
            assert!(!argv.iter().any(|a| a == "--force"));
            assert!(!argv.iter().any(|a| a == "--trust"));
            assert!(!argv.iter().any(|a| a == "exec"));
        }
        assert!(interactive_fix_args("hermes").is_none());
    }

    #[test]
    fn interactive_fix_rejects_undetected_agent() {
        let err = run_agent_cli_fix_interactive(
            "hermes",
            "/tmp",
            "fix it",
            Some(Path::new("/nonexistent")),
        )
        .unwrap_err();
        assert!(err.to_string().contains("No CLI detected"), "got: {}", err);
    }
}
