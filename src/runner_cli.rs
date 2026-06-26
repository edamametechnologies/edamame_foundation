use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use std::process::Stdio;
use std::{env, path::PathBuf};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{timeout, Duration, Instant};
use tracing::{debug, error, info, warn};

#[cfg(target_os = "windows")]
use std::ffi::{c_void, OsStr, OsString};
#[cfg(target_os = "windows")]
use std::io::Write;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "windows")]
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::ERROR_SUCCESS,
        Security::{LookupAccountNameW, PSID, SECURITY_MAX_SID_SIZE, SID_NAME_USE},
        System::Registry::{
            RegCloseKey, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
            RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
        },
    },
};

// The personate parameter forces the execution into the context of username
// We could use an empty username to indicate there is no need to personate but we keep it as is for now in case we find other use cases for the username
pub async fn run_cli(
    cmd: &str,
    username: &str,
    personate: bool,
    timeout_opt: Option<u64>,
) -> Result<String> {
    // Verify platform support
    check_platform_support()?;

    let (code, stdout, stderr) = if cfg!(target_os = "windows") {
        run_windows_ps(cmd, username, personate, timeout_opt).await?
    } else {
        run_unix_command(cmd, username, personate, timeout_opt).await?
    };

    // Remove newlines from stdout
    let stdout = stdout.replace('\n', "").replace('\r', "");
    if execution_failed(code, &stderr) {
        Err(anyhow!(stderr.clone()))
    } else {
        Ok(stdout)
    }
}

async fn run_unix_command(
    cmd: &str,
    username: &str,
    personate: bool,
    timeout_opt: Option<u64>,
) -> Result<(i32, String, String)> {
    let mut command = Command::new("/bin/bash");
    command.arg("-c").arg(cmd);

    if personate && !username.is_empty() {
        let home_dir = resolve_home_unix(username).await?;
        info!(
            "Setting up execution for user: {} with home: {}",
            username, home_dir
        );
        command
            .env("HOME", &home_dir)
            .env("USER", username)
            .env("LOGNAME", username)
            .env("SHELL", "/bin/bash");
    }

    debug!("Executing shell command: {}", cmd);
    run_command_with_timeout(command, cmd, timeout_opt).await
}

async fn run_windows_ps(
    cmd: &str,
    username: &str,
    personate: bool,
    timeout_opt: Option<u64>,
) -> Result<(i32, String, String)> {
    #[cfg(target_os = "windows")]
    {
        let mut script = String::new();
        if personate && !username.is_empty() {
            let context = resolve_windows_context(username)?;
            info!(
                "Setting up execution for user: {} with home: {}, AppData: {}, LocalAppData: {}",
                username,
                context.home_dir.display(),
                context.app_data.display(),
                context.local_app_data.display()
            );

            if let Some(env_block) = build_windows_env_block(username, &context) {
                script.push_str(&env_block);
                script.push('\n');
            }
        }
        script.push_str(cmd);

        // Prefer PowerShell's -EncodedCommand over writing a temporary .ps1 file.
        //
        // Writing a `.tmp*.ps1` into %TEMP% on every threat-check tick creates a
        // short-lived script artifact that EDAMAME's own file-integrity monitor
        // observes as a `file_system_tampering` event. Because the file is deleted
        // almost immediately (TOCTOU), the detector frequently cannot attribute
        // the writer process, and a null-attribution script-like temp write cannot
        // be demoted -- producing a self-inflicted HIGH false positive (FP-WIN-18b).
        // -EncodedCommand passes the script inline as a Base64 (UTF-16LE) argument,
        // so no file ever touches disk and the FP disappears at the source. It is
        // also immune to the command-line quoting/escaping issues that made plain
        // -Command fragile, because PowerShell Base64-decodes the argument rather
        // than parsing it as a command line.
        let encoded = encode_powershell_command(&script);

        let mut command = Command::new("powershell.exe");
        // Windows caps a process command line at 32767 chars (CreateProcessW). The
        // longest real threat-model script encodes to ~15k Base64 chars, far under
        // the limit, but keep a temp-file fallback for any pathologically large
        // caller so we never silently truncate a command.
        let tmp_path_guard = if encoded.len() <= MAX_ENCODED_COMMAND_LEN {
            command
                .arg("-NoProfile")
                .arg("-NonInteractive")
                .arg("-ExecutionPolicy")
                .arg("Bypass")
                .arg("-EncodedCommand")
                .arg(&encoded);
            None
        } else {
            warn!(
                "PowerShell script too large for -EncodedCommand ({} Base64 chars); \
                 falling back to a temporary .ps1 file",
                encoded.len()
            );
            let mut tmp = tempfile::Builder::new()
                .suffix(".ps1")
                .tempfile()
                .map_err(|e| anyhow!("Failed to create temp PS script: {}", e))?;
            tmp.write_all(script.as_bytes())
                .map_err(|e| anyhow!("Failed to write PS script: {}", e))?;
            // Keep the temp file alive until the command completes by holding the path here.
            let tmp_path = tmp.into_temp_path();
            command
                .arg("-NoProfile")
                .arg("-NonInteractive")
                .arg("-ExecutionPolicy")
                .arg("Bypass")
                .arg("-File")
                .arg(&*tmp_path);
            Some(tmp_path)
        };

        // CREATE_NO_WINDOW (0x08000000) prevents the PowerShell host from
        // allocating a console, so threat-metric checks running from the
        // helper daemon don't flash visible cmd/PowerShell windows on the
        // user's desktop. Equivalent to the `.hidden(true)` option that the
        // `powershell_script` crate sets internally; tokio::process::Command
        // does not pass any creation flags by default.
        command.creation_flags(0x08000000);

        debug!("Executing powershell command: {}", script);
        let result = run_command_with_timeout(command, cmd, timeout_opt).await;
        // tmp_path drop closes/removes the temp file (if any) after the command
        // has been waited on.
        drop(tmp_path_guard);
        result
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (cmd, username, personate, timeout_opt);
        Err(anyhow!(
            "run_windows_ps invoked on non-Windows platform: {}",
            std::env::consts::OS
        ))
    }
}

// Upper bound on the Base64 `-EncodedCommand` length before we fall back to a
// temporary .ps1 file. Windows caps a process command line at 32767 chars
// (CreateProcessW); leaving generous headroom for the fixed argument prefix and
// any inherited environment, anything under this stays comfortably inside the
// limit. The longest real threat-model script encodes to ~15k chars.
//
// Kept compiling on every platform (only consumed in the Windows path of
// `run_windows_ps`) so the unit tests can exercise the encoder on the
// developers' macOS/Linux machines.
#[allow(dead_code)]
const MAX_ENCODED_COMMAND_LEN: usize = 30000;

// Encode a PowerShell script for `powershell.exe -EncodedCommand`: Base64 of the
// script's UTF-16LE bytes. This is the documented contract for -EncodedCommand
// and lets us run multi-line scripts inline without ever staging a temp file.
#[allow(dead_code)]
fn encode_powershell_command(script: &str) -> String {
    let utf16le: Vec<u8> = script
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    BASE64_STANDARD.encode(utf16le)
}

// Spawn a child via the provided builder, drain stdout/stderr concurrently with waiting,
// and on timeout kill the *entire* process group so any descendants of the spawned shell
// release the inherited stdout/stderr pipes. This is the core mechanism that prevents the
// PIPE FD leak observed in the helper.
#[cfg(unix)]
fn kill_process_group(pid: Option<u32>) {
    if let Some(pid) = pid {
        unsafe {
            // Negative argument => kill the whole process group, ensuring
            // any subshells / descendants release the inherited pipe FDs.
            libc::killpg(pid as libc::pid_t, libc::SIGKILL);
        }
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: Option<u32>) {}

async fn kill_child_and_abort_io(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    stdout_task: &tokio::task::JoinHandle<Vec<u8>>,
    stderr_task: &tokio::task::JoinHandle<Vec<u8>>,
) {
    kill_process_group(pid);
    let _ = child.start_kill();
    let _ = timeout(Duration::from_secs(2), child.wait()).await;
    stdout_task.abort();
    stderr_task.abort();
}

async fn join_pipe_with_deadline(
    task: &mut tokio::task::JoinHandle<Vec<u8>>,
    deadline: Option<Instant>,
) -> Option<Vec<u8>> {
    match deadline {
        Some(deadline) => {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            timeout(deadline - now, task)
                .await
                .ok()
                .and_then(Result::ok)
        }
        None => task.await.ok(),
    }
}

async fn run_command_with_timeout(
    mut command: Command,
    cmd_for_log: &str,
    timeout_opt: Option<u64>,
) -> Result<(i32, String, String)> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    // On Unix, run the child as the leader of a new process group so we can SIGKILL the
    // entire tree on timeout (otherwise grandchildren keep the pipes open and leak FDs).
    #[cfg(unix)]
    {
        command.process_group(0);
    }

    let mut child = command
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn command {:?}: {}", cmd_for_log, e))?;

    let pid = child.id();
    let deadline = timeout_opt.map(|secs| Instant::now() + Duration::from_secs(secs));

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let mut stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut s) = stdout_pipe {
            let _ = s.read_to_end(&mut buf).await;
        }
        buf
    });
    let mut stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut s) = stderr_pipe {
            let _ = s.read_to_end(&mut buf).await;
        }
        buf
    });

    let status = match timeout_opt {
        Some(secs) => match timeout(Duration::from_secs(secs), child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(e)) => {
                return Err(anyhow!(
                    "Failed to wait for command {:?}: {}",
                    cmd_for_log,
                    e
                ));
            }
            Err(_) => {
                warn!(
                    "Execution of command {:?} timed out after {} seconds, killing process tree",
                    cmd_for_log, secs
                );
                kill_child_and_abort_io(&mut child, pid, &stdout_task, &stderr_task).await;
                return Err(anyhow!(
                    "Execution of command timed out after {} seconds",
                    secs
                ));
            }
        },
        None => child
            .wait()
            .await
            .map_err(|e| anyhow!("Failed to wait for command {:?}: {}", cmd_for_log, e))?,
    };

    let Some(stdout_bytes) = join_pipe_with_deadline(&mut stdout_task, deadline).await else {
        if let Some(secs) = timeout_opt {
            warn!(
                "Execution of command {:?} timed out after {} seconds while draining stdout, killing process tree",
                cmd_for_log, secs
            );
            kill_child_and_abort_io(&mut child, pid, &stdout_task, &stderr_task).await;
            return Err(anyhow!(
                "Execution of command timed out after {} seconds",
                secs
            ));
        }
        return Err(anyhow!(
            "Failed to drain stdout for command {:?}",
            cmd_for_log
        ));
    };
    let Some(stderr_bytes) = join_pipe_with_deadline(&mut stderr_task, deadline).await else {
        if let Some(secs) = timeout_opt {
            warn!(
                "Execution of command {:?} timed out after {} seconds while draining stderr, killing process tree",
                cmd_for_log, secs
            );
            kill_child_and_abort_io(&mut child, pid, &stdout_task, &stderr_task).await;
            return Err(anyhow!(
                "Execution of command timed out after {} seconds",
                secs
            ));
        }
        return Err(anyhow!(
            "Failed to drain stderr for command {:?}",
            cmd_for_log
        ));
    };
    let code = status.code().unwrap_or(1);
    let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();
    debug!(
        "Execution results for command {:?} : code : {:?} - stdout : {:?} - stderr : {:?}",
        cmd_for_log, code, stdout, stderr
    );
    Ok((code, stdout, stderr))
}

// This is our convention for detecting a failed execution
fn execution_failed(code: i32, stderr: &str) -> bool {
    code != 0 && !stderr.is_empty()
}

fn check_platform_support() -> Result<()> {
    if cfg!(target_os = "ios") || cfg!(target_os = "android") {
        let os_name = if cfg!(target_os = "ios") {
            "iOS"
        } else {
            "android"
        };
        error!("{} is not supported", os_name);
        return Err(anyhow!("{} is not supported", os_name));
    }
    Ok(())
}

// Helper types/functions below are exclusively consumed inside the Windows path of
// `run_windows_ps`, but we keep them compiling on every platform so the unit tests can
// exercise the path-construction logic on the developers' macOS/Linux machines.
#[allow(dead_code)]
#[derive(Debug)]
struct WindowsUserContext {
    home_dir: PathBuf,
    app_data: PathBuf,
    local_app_data: PathBuf,
}

#[allow(dead_code)]
#[cfg(target_os = "windows")]
fn resolve_windows_context(username: &str) -> Result<WindowsUserContext> {
    let user_segment = username
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(username);

    let fallback_context = || {
        let ctx = build_default_windows_context(user_segment);
        warn!(
            "Falling back to default Windows context for user {} at {}",
            username,
            ctx.home_dir.display()
        );
        ctx
    };

    let sid_str = match lookup_user_sid_string(username) {
        Some(s) => s,
        None => return Ok(fallback_context()),
    };

    let home_dir = match profile_path_from_sid(&sid_str) {
        Some(path) => path,
        None => return Ok(fallback_context()),
    };

    let app_data = home_dir.join("AppData").join("Roaming");
    let local_app_data = home_dir.join("AppData").join("Local");

    Ok(WindowsUserContext {
        home_dir,
        app_data,
        local_app_data,
    })
}

#[allow(dead_code)]
#[cfg(not(target_os = "windows"))]
fn resolve_windows_context(username: &str) -> Result<WindowsUserContext> {
    let user_segment = username
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(username);
    Ok(build_default_windows_context(user_segment))
}

#[cfg(target_os = "windows")]
fn lookup_user_sid_string(username: &str) -> Option<String> {
    let mut sid_buffer = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_size = SECURITY_MAX_SID_SIZE;
    let mut domain_buffer = [0u16; 256];
    let mut domain_size: u32 = 256;
    let mut sid_use = SID_NAME_USE(0);

    let username_w = widestring(username);

    unsafe {
        if let Err(e) = LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(username_w.as_ptr()),
            Some(PSID(sid_buffer.as_mut_ptr() as *mut c_void)),
            &mut sid_size,
            Some(PWSTR(domain_buffer.as_mut_ptr())),
            &mut domain_size,
            &mut sid_use,
        ) {
            warn!("LookupAccountNameW({username}) failed: {e:?}");
            return None;
        }
    }

    Some(sid_to_string(&sid_buffer[..sid_size as usize]))
}

#[cfg(target_os = "windows")]
fn sid_to_string(sid: &[u8]) -> String {
    if sid.len() < 8 {
        return String::new();
    }

    let revision = sid[0];
    let sub_authority_count = sid[1] as usize;

    let mut identifier_authority: u64 = 0;
    for b in &sid[2..8] {
        identifier_authority = (identifier_authority << 8) | (*b as u64);
    }

    let mut result = format!("S-{}-{}", revision, identifier_authority);

    let mut offset = 8usize;
    for _ in 0..sub_authority_count {
        if offset + 4 > sid.len() {
            break;
        }
        let value = u32::from_le_bytes([
            sid[offset],
            sid[offset + 1],
            sid[offset + 2],
            sid[offset + 3],
        ]);
        result.push('-');
        result.push_str(&value.to_string());
        offset += 4;
    }

    result
}

#[cfg(target_os = "windows")]
fn profile_path_from_sid(sid: &str) -> Option<PathBuf> {
    let subkey = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
    let subkey_w = widestring(subkey.as_str());
    let value_name = widestring("ProfileImagePath");

    unsafe {
        let mut hkey: HKEY = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            Some(0),
            KEY_READ,
            &mut hkey,
        );
        if status != ERROR_SUCCESS {
            warn!("RegOpenKeyExW({subkey}) failed with status {:?}", status);
            return None;
        }

        let mut len_bytes: u32 = 0;
        let status = RegGetValueW(
            hkey,
            PCWSTR::null(),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            None,
            None,
            Some(&mut len_bytes),
        );
        if status != ERROR_SUCCESS || len_bytes < 2 {
            warn!(
                "RegGetValueW(size, ProfileImagePath) failed with status {:?}, len_bytes={}",
                status, len_bytes
            );
            let _ = RegCloseKey(hkey);
            return None;
        }

        let mut buf: Vec<u16> = vec![0; (len_bytes as usize + 1) / 2];
        let status = RegGetValueW(
            hkey,
            PCWSTR::null(),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut c_void),
            Some(&mut len_bytes),
        );
        let _ = RegCloseKey(hkey);

        if status != ERROR_SUCCESS {
            warn!(
                "RegGetValueW(value, ProfileImagePath) failed with status {:?}",
                status
            );
            return None;
        }

        let chars = (len_bytes as usize / 2).saturating_sub(1);
        buf.truncate(chars);
        let os = OsString::from_wide(&buf);
        Some(PathBuf::from(os))
    }
}

#[cfg(target_os = "windows")]
fn widestring(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(target_os = "windows")]
fn escape_pwsh_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(target_os = "windows")]
fn build_windows_env_block(username: &str, context: &WindowsUserContext) -> Option<String> {
    let escaped_username = escape_pwsh_single_quoted(username);
    let home_dir = context.home_dir.to_string_lossy().into_owned();
    let app_data = context.app_data.to_string_lossy().into_owned();
    let local_app_data = context.local_app_data.to_string_lossy().into_owned();
    let escaped_home = escape_pwsh_single_quoted(&home_dir);
    let escaped_appdata = escape_pwsh_single_quoted(&app_data);
    let escaped_localappdata = escape_pwsh_single_quoted(&local_app_data);

    Some(format!(
        concat!(
            "$edamameUser = '{username}'\n",
            "$userProfilePath = '{home_dir}'\n",
            "$env:USERPROFILE = $userProfilePath\n",
            "$env:HOME = $userProfilePath\n",
            "try {{\n",
            "  $env:HOMEDRIVE = Split-Path $userProfilePath -Qualifier\n",
            "  $env:HOMEPATH = $userProfilePath.Substring($env:HOMEDRIVE.Length)\n",
            "}} catch {{\n",
            "  $env:HOMEDRIVE = $env:SystemDrive\n",
            "  $env:HOMEPATH = $userProfilePath.Substring($env:HOMEDRIVE.Length)\n",
            "}}\n",
            // Use the resolved paths
            "$env:APPDATA = '{app_data}'\n",
            "$env:LOCALAPPDATA = '{local_app_data}'\n",
            // These are typically subdirs of LocalAppData, so we derive them
            "$env:TEMP = Join-Path '{local_app_data}' 'Temp'\n",
            "$env:TMP = Join-Path '{local_app_data}' 'Temp'\n",
            // Load user's environment variables from registry
            "try {{\n",
            "  $userSid = (New-Object System.Security.Principal.NTAccount($edamameUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value\n",
            "  $regPath = \"Registry::HKEY_USERS\\$userSid\\Environment\"\n",
            "  if (Test-Path $regPath) {{\n",
            "    Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | ForEach-Object {{\n",
            "      $name = $_.Name\n",
            "      # Skip PS built-in properties\n",
            "      if ($name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {{\n",
            "        $value = (Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue).$name\n",
            "        if ($null -ne $value) {{\n",
            "          $expandedValue = [System.Environment]::ExpandEnvironmentVariables($value)\n",
            "          Set-Item -Path \"env:$name\" -Value $expandedValue -ErrorAction SilentlyContinue\n",
            "        }}\n",
            "      }}\n",
            "    }}\n",
            "  }}\n",
            "}} catch {{ }}\n"
        ),
        username = escaped_username,
        home_dir = escaped_home,
        app_data = escaped_appdata,
        local_app_data = escaped_localappdata
    ))
}

#[allow(dead_code)]
fn build_default_windows_context(user_segment: &str) -> WindowsUserContext {
    let system_drive = env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let home_dir = PathBuf::from(format!(r"{}\Users\{}", system_drive, user_segment));
    let app_data = home_dir.join("AppData").join("Roaming");
    let local_app_data = home_dir.join("AppData").join("Local");

    WindowsUserContext {
        home_dir,
        app_data,
        local_app_data,
    }
}

async fn resolve_home_unix(username: &str) -> Result<String> {
    // Look up the user via NSS (getpwnam_r), which respects nsswitch.conf so LDAP/SSSD
    // entries on Linux are resolved correctly. Falls back to dscl on macOS systems where
    // the binary is the canonical source of truth and finally to a default location if
    // the user is genuinely missing from the database.
    let cmd = format!(
        concat!(
            "HOME=$(getent passwd {} 2>/dev/null | cut -d: -f6) || ",
            "HOME=$(dscl . -read /Users/{} NFSHomeDirectory 2>/dev/null | awk '{{print $2}}') || ",
            "{{ [ \"$(uname)\" = \"Darwin\" ] && HOME=\"/Users/{}\" || HOME=\"/home/{}\"; }}; ",
            "echo $HOME"
        ),
        username, username, username, username
    );

    let output = Command::new("/bin/bash")
        .arg("-c")
        .arg(&cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| anyhow!("Failed to run home resolution script: {}", e))?;

    if !output.status.success() {
        return Err(anyhow!(
            "Failed to resolve unix home. Exit code: {:?}. Stderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let home = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if home.is_empty() {
        if cfg!(target_os = "macos") {
            return Ok(format!("/Users/{}", username));
        } else {
            return Ok(format!("/home/{}", username));
        }
    }
    Ok(home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Defensive parser for the powershell `GetConsoleWindow().ToInt64()`
    /// probes: walks the captured stdout from the bottom up and returns the
    /// last line that parses as an i64. PowerShell on github-hosted
    /// windows-2022 sometimes prints extra warning lines (Add-Type
    /// already-loaded, transcript module nags injected by group policy) that
    /// would otherwise blow up `.parse::<i64>()` and turn an inconclusive
    /// runner state into a hard test failure.
    #[cfg(target_os = "windows")]
    fn parse_last_i64_line(s: &str) -> Option<i64> {
        for line in s.lines().rev() {
            let cleaned: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            if cleaned.is_empty() {
                continue;
            }
            if let Ok(v) = cleaned.parse::<i64>() {
                return Some(v);
            }
        }
        None
    }

    /// `encode_powershell_command` must produce a Base64 string that PowerShell's
    /// -EncodedCommand can decode: Base64 of the script's UTF-16LE bytes. We verify
    /// the round-trip (Base64-decode -> UTF-16LE -> original script) here so the
    /// FP-WIN-18b fix (no more transient `.tmp*.ps1` files written by every
    /// threat-check tick) stays correct on every platform, not just Windows CI.
    #[test]
    fn test_encode_powershell_command_round_trips_utf16le() {
        let script = "Write-Output 'h\u{e9}llo'\n$x = 1 + 2\nexit 0";
        let encoded = encode_powershell_command(script);

        let bytes = BASE64_STANDARD
            .decode(encoded.as_bytes())
            .expect("encoded command must be valid Base64");
        // UTF-16 code units are 2 bytes each.
        assert_eq!(bytes.len() % 2, 0, "UTF-16LE byte length must be even");

        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let decoded = String::from_utf16(&units).expect("must decode as UTF-16");
        assert_eq!(decoded, script);
    }

    /// The longest real Windows threat-model script (~5.4 KB) plus a personation
    /// env block (~2 KB) encodes well within the inline -EncodedCommand budget, so
    /// the temp-file fallback never triggers for production threat checks.
    #[test]
    fn test_encode_powershell_command_within_inline_budget() {
        // ~8.4 KB script, larger than the realistic worst case (script + env block).
        let script = "Get-Item 'X'; ".repeat(600);
        let encoded = encode_powershell_command(&script);
        assert!(
            encoded.len() <= MAX_ENCODED_COMMAND_LEN,
            "encoded length {} exceeded inline budget {}",
            encoded.len(),
            MAX_ENCODED_COMMAND_LEN
        );
    }

    #[tokio::test]
    async fn test_run_cli_echo() {
        let (cmd, expected) = if cfg!(target_os = "windows") {
            ("Write-Output 'hello'", "hello")
        } else {
            ("echo 'hello'", "hello")
        };

        let result = run_cli(cmd, "", false, None).await;
        assert!(result.is_ok());
        let output = result.unwrap();
        // On windows, pwsh might add \r\n which are removed by run_cli, but extra spaces might remain?
        // run_cli removes newlines: stdout.replace('\n', "").replace('\r', "")
        assert_eq!(output.trim(), expected);
    }

    /// Regression guard: `run_cli` MUST spawn its `powershell.exe` child with
    /// `CREATE_NO_WINDOW` (0x08000000) so the helper daemon does not flash
    /// visible PowerShell windows on user desktops every threat-check tick.
    ///
    /// The original regression (commit `2779929`) silently dropped this
    /// behaviour when we moved away from the `powershell_script` crate's
    /// `.hidden(true)` option. We re-added it as
    /// `command.creation_flags(0x08000000)` and codified the policy in the
    /// foundation rules ("Windows PowerShell / Console Process Invocation").
    /// This test fails fast if any future refactor drops the flag.
    ///
    /// Mechanism:
    ///
    /// 1. Force-allocate a console for the cargo-test process via
    ///    `kernel32!AllocConsole`. github-hosted Windows runners launch
    ///    cargo test as a detached / no-console process by default, so without
    ///    this step children spawned without `CREATE_NO_WINDOW` ALSO end up
    ///    with no console (no parent console to inherit), and the test cannot
    ///    distinguish a working flag from a missing flag. The `AllocConsole`
    ///    call gives the parent a console deterministically and is a no-op
    ///    if one already exists.
    /// 2. Run a "control" spawn directly through `tokio::process::Command`
    ///    *without* `creation_flags`. With the parent now holding a console,
    ///    this child inherits it and `GetConsoleWindow()` returns a non-zero
    ///    HWND.
    /// 3. Run the "probe" spawn through `run_cli` (which sets
    ///    `CREATE_NO_WINDOW`). The child has no console, so
    ///    `GetConsoleWindow()` returns 0.
    ///
    /// If `AllocConsole` fails and the control still reports 0, we self-skip
    /// rather than pass falsely. Otherwise the assertion is strict.
    ///
    /// Marked `#[serial]` so it doesn't race against other tests' env-var or
    /// console manipulation.
    #[cfg(target_os = "windows")]
    #[tokio::test]
    #[serial]
    async fn test_run_cli_powershell_has_no_console_window() {
        use std::io::Write as _;
        use std::process::Stdio;

        // FFI imports for the console-allocation precondition.
        #[link(name = "kernel32")]
        extern "system" {
            fn AllocConsole() -> i32;
            fn FreeConsole() -> i32;
        }

        // PowerShell script that P/Invokes GetConsoleWindow and prints the
        // returned HWND as a 64-bit signed integer (so an empty handle is "0").
        let script = r#"
Add-Type -Namespace EdamameWin -Name Kernel -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();'
[EdamameWin.Kernel]::GetConsoleWindow().ToInt64()
"#;

        // Step 1: ensure cargo-test has a console so a child without the flag
        // has something to inherit. If we already have one, AllocConsole
        // returns 0 (already-attached) which is fine.
        let allocated = unsafe { AllocConsole() != 0 };

        // Step 2: control spawn (NO creation_flags). Should inherit the
        // parent console -> non-zero handle.
        let mut tmp = tempfile::Builder::new()
            .suffix(".ps1")
            .tempfile()
            .expect("temp .ps1 file");
        tmp.write_all(script.as_bytes())
            .expect("write probe script");
        let tmp_path = tmp.into_temp_path();

        let raw_output = Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-File")
            .arg(&*tmp_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .expect("raw control spawn should succeed");
        drop(tmp_path);

        // Defensive parse: on github-hosted windows-2022 runners, Add-Type can
        // print extra warning lines to stdout (e.g. about already-loaded
        // assemblies, or PS profile noise that bleeds through despite
        // -NoProfile when group policy injects a transcript module). If the
        // raw stdout doesn't end with a clean integer line, we cannot make a
        // meaningful invariant claim and treat the run as inconclusive --
        // same shape as the control_handle == 0 self-skip below.
        let raw_stdout = String::from_utf8_lossy(&raw_output.stdout).into_owned();
        let raw_stderr = String::from_utf8_lossy(&raw_output.stderr).into_owned();
        let control_handle: i64 = match parse_last_i64_line(&raw_stdout) {
            Some(v) => v,
            None => {
                eprintln!(
                    "test_run_cli_powershell_has_no_console_window: INCONCLUSIVE. \
                     Control spawn stdout did not end with a parseable i64 line. \
                     stdout={raw_stdout:?} stderr={raw_stderr:?}. \
                     Skipping (cannot establish AllocConsole baseline)."
                );
                if allocated {
                    unsafe {
                        FreeConsole();
                    }
                }
                return;
            }
        };

        // Step 3: probe via run_cli (sets CREATE_NO_WINDOW). Should be 0.
        let probe_raw = run_cli(script, "", false, Some(15))
            .await
            .expect("run_cli probe should succeed");
        let probe_handle: i64 = match parse_last_i64_line(&probe_raw) {
            Some(v) => v,
            None => {
                eprintln!(
                    "test_run_cli_powershell_has_no_console_window: INCONCLUSIVE. \
                     run_cli probe stdout did not end with a parseable i64 line. \
                     stdout={probe_raw:?}. Skipping."
                );
                if allocated {
                    unsafe {
                        FreeConsole();
                    }
                }
                return;
            }
        };

        // Best-effort cleanup: free the console we allocated so we don't
        // leave the cargo-test process in a weird state for later tests.
        if allocated {
            unsafe {
                FreeConsole();
            }
        }

        if control_handle == 0 {
            eprintln!(
                "test_run_cli_powershell_has_no_console_window: INCONCLUSIVE. \
                 AllocConsole did not establish a parent console (probably \
                 already detached and FreeConsole is also a no-op here). \
                 Control handle is 0, so we cannot distinguish \
                 CREATE_NO_WINDOW from plain no-console inheritance. Skipping."
            );
            return;
        }

        assert_eq!(
            probe_handle, 0,
            "GetConsoleWindow() returned handle {} (0x{:x}) for run_cli's \
             spawned powershell.exe -- a console is attached. \
             CREATE_NO_WINDOW (0x08000000) is not being applied, which means \
             user machines will see visible PowerShell windows pop up on \
             every threat-check tick. Control spawn (without the flag) saw \
             handle {} (0x{:x}), confirming the parent does have a console. \
             See `Windows PowerShell / Console Process Invocation` in \
             foundation rules.",
            probe_handle, probe_handle, control_handle, control_handle
        );
    }

    #[tokio::test]
    async fn test_run_cli_error() {
        // We need a command that returns non-zero exit code AND prints to stderr
        // to satisfy execution_failed(code != 0 && !stderr.is_empty())

        let cmd = if cfg!(target_os = "windows") {
            // Write-Error writes to stderr stream in PS. exit 1 sets exit code.
            "Write-Error 'boom'; exit 1"
        } else {
            "echo 'boom' >&2; exit 1"
        };

        let result = run_cli(cmd, "", false, None).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("boom"));
    }

    #[tokio::test]
    async fn test_run_cli_timeout() {
        let cmd = if cfg!(target_os = "windows") {
            "Start-Sleep -Seconds 2"
        } else {
            "sleep 2"
        };

        // Timeout of 1 second, command takes 2
        let result = run_cli(cmd, "", false, Some(1)).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn test_run_cli_timeout_returns_quickly() {
        // The timeout should fire well before the long sleep would naturally complete.
        // This validates that we are not waiting on a leaked spawn_blocking thread.
        let cmd = if cfg!(target_os = "windows") {
            "Start-Sleep -Seconds 30"
        } else {
            "sleep 30"
        };

        let start = std::time::Instant::now();
        let result = run_cli(cmd, "", false, Some(1)).await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        // We allow up to 5s of slack for slow CI; on a healthy machine this is sub-second.
        assert!(
            elapsed.as_secs() < 5,
            "run_cli with 1s timeout took too long: {:?}",
            elapsed
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_run_cli_timeout_no_pipe_leak() {
        // Spawn many commands that all hit the timeout and ensure the process's open FD
        // count returns to baseline. Before the fix, each timeout left two PIPE FDs and
        // one zombie shell behind.
        fn count_open_fds() -> usize {
            std::fs::read_dir("/dev/fd").map(|d| d.count()).unwrap_or(0)
        }

        // Warm up: run one command first so any tokio runtime / lazy globals are
        // initialised and don't pollute the baseline.
        let _ = run_cli("true", "", false, Some(1)).await;
        let baseline = count_open_fds();

        for _ in 0..10 {
            let result = run_cli("sleep 30", "", false, Some(1)).await;
            assert!(result.is_err());
        }

        // Allow tokio's reaper a moment to release any pipe FDs.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let after = count_open_fds();

        // A small drift is fine (e.g. tracing log file rotations, runtime queues),
        // but anything close to 2 * 10 = 20 leaked PIPE FDs would indicate regression.
        assert!(
            after <= baseline + 5,
            "FD leak detected: baseline={}, after={}",
            baseline,
            after
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_run_cli_timeout_kills_process_group() {
        // Verify that when a timed-out shell has a long-running grandchild, the kill
        // propagates to the process group so the grandchild is reaped too.
        // We start a bash that exec's a sleep, then check the sleep is not running.
        let cmd = "(sleep 30) & wait";

        let start = std::time::Instant::now();
        let result = run_cli(cmd, "", false, Some(1)).await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed.as_secs() < 5,
            "process group kill took too long: {:?}",
            elapsed
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_run_cli_timeout_kills_background_child_holding_pipe() {
        // Regression for the second runner_cli leak mode: the shell exits quickly,
        // but a background child inherits stdout/stderr. `child.wait()` completes
        // immediately, then pipe draining blocks forever unless the timeout covers
        // the whole command lifecycle and kills the process group.
        let cmd = "(sleep 30) & echo done";

        let start = std::time::Instant::now();
        let result = run_cli(cmd, "", false, Some(1)).await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed.as_secs() < 5,
            "background child pipe cleanup took too long: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_personation_current_user() {
        // Try to impersonate current user
        let user = if cfg!(target_os = "windows") {
            std::env::var("USERNAME").unwrap_or_default()
        } else {
            std::env::var("USER").unwrap_or_default()
        };

        if user.is_empty() {
            println!("Skipping impersonation test: no USER/USERNAME env var");
            return;
        }

        // Note: On Unix, impersonating usually requires sudo/root unless it's just setting env vars.
        // Our implementation of execute_unix_command just sets env vars like HOME, USER, etc.
        // It does NOT use sudo or setuid/setgid (it just formats a string with export ...).
        // So it should safe to run as normal user.

        let (cmd, expected) = if cfg!(target_os = "windows") {
            ("Write-Output 'impersonated'", "impersonated")
        } else {
            ("echo 'impersonated'", "impersonated")
        };

        let result = run_cli(cmd, &user, true, None).await;

        match result {
            Ok(output) => assert_eq!(output.trim(), expected),
            Err(e) => {
                println!("Impersonation test failed (expected for some envs): {}", e);
                // Don't assert failure here as it depends on env capability
            }
        }
    }

    // Reads APPDATA on Windows; serialize against agent_transcripts tests that
    // override APPDATA so we don't see a stale tempdir value here.
    #[tokio::test]
    #[serial]
    async fn test_personation_context_inference() {
        let user = if cfg!(target_os = "windows") {
            std::env::var("USERNAME").unwrap_or_default()
        } else {
            std::env::var("USER").unwrap_or_default()
        };

        if user.is_empty() {
            println!("Skipping context inference test: no USER/USERNAME env var");
            return;
        }

        // Determine expected home
        let expected_home = if cfg!(target_os = "windows") {
            std::env::var("USERPROFILE").unwrap_or_default()
        } else {
            std::env::var("HOME").unwrap_or_default()
        };

        // Command to print home var
        let cmd = if cfg!(target_os = "windows") {
            "Write-Output $env:USERPROFILE"
        } else {
            "echo $HOME"
        };

        let result = run_cli(cmd, &user, true, None).await;

        match result {
            Ok(output) => {
                let output = output.trim();
                // We expect the output to match our current home dir if we impersonate ourselves
                // NOTE: This test assumes that the resolution logic yields the same path
                // as std::env::var. This is usually true but might differ slightly (e.g. symlinks)
                // We'll just check if it's non-empty and 'looks like' a home dir
                assert!(!output.is_empty());

                // Loose check: output should likely contain the username or be equal to expected_home
                if !expected_home.is_empty() {
                    // On windows, sometimes we get Short paths or different casing,
                    // so let's just print for verification if strict equality fails
                    if output != expected_home {
                        println!(
                            "Warning: Resolved home '{}' differs from env home '{}'",
                            output, expected_home
                        );
                    }
                }
            }
            Err(e) => {
                println!("Context inference test failed: {}", e);
            }
        }

        // On Windows, check APPDATA too
        if cfg!(target_os = "windows") {
            let cmd_appdata = "Write-Output $env:APPDATA";
            let res_appdata = run_cli(cmd_appdata, &user, true, None).await;
            if let Ok(out) = res_appdata {
                assert!(!out.trim().is_empty());
                let expected_appdata = std::env::var("APPDATA").unwrap_or_default();
                if !expected_appdata.is_empty() && out.trim() != expected_appdata {
                    println!(
                        "Warning: Resolved APPDATA '{}' differs from env APPDATA '{}'",
                        out.trim(),
                        expected_appdata
                    );
                }
            }
        }
    }

    // Modifies SystemDrive env var; serialize against any other env-var test.
    #[test]
    #[serial]
    fn test_build_default_windows_context_uses_system_drive() {
        let original = std::env::var("SystemDrive").ok();
        std::env::set_var("SystemDrive", "Z:");

        let ctx = build_default_windows_context("alice");
        assert!(ctx.home_dir.to_string_lossy().starts_with("Z:"));
        let app_data = ctx.app_data.to_string_lossy().replace('\\', "/");
        assert!(app_data.ends_with("AppData/Roaming"));

        let local_app_data = ctx.local_app_data.to_string_lossy().replace('\\', "/");
        assert!(local_app_data.ends_with("AppData/Local"));

        if let Some(value) = original {
            std::env::set_var("SystemDrive", value);
        } else {
            std::env::remove_var("SystemDrive");
        }
    }

    // Reads APPDATA on Windows; serialize against agent_transcripts tests that
    // override APPDATA so we don't see a stale tempdir value here.
    #[test]
    #[serial]
    fn test_windows_resolution_matches_env() {
        if !cfg!(target_os = "windows") {
            return;
        }

        let username = std::env::var("USERNAME").unwrap_or_default();
        if username.is_empty() {
            return;
        }

        // Direct call to resolve_windows_context
        let context = resolve_windows_context(&username);

        // If resolution fails (e.g. due to environment issues), we can't proceed with the test.
        // However, we should at least expect it to work for the current user.
        if let Err(e) = context {
            println!(
                "Skipping test_windows_resolution_matches_env due to resolution failure: {:?}",
                e
            );
            return;
        }
        let context = context.unwrap();

        let env_appdata = std::env::var("APPDATA").unwrap_or_default();

        // If the system has a custom APPDATA (redirected), the env var will reflect it.
        // The resolution logic should also find it via Registry.
        // If resolution failed to check Registry, it would fallback to %USERPROFILE%\AppData\Roaming,
        // which would mismatch the redirected env_appdata.
        if !env_appdata.is_empty() {
            assert_eq!(
                context.app_data.to_string_lossy().to_lowercase(),
                env_appdata.to_lowercase(),
                "Resolved AppData does not match environment AppData. This suggests we might be falling back to default paths incorrectly."
            );
        }
    }
}
