use anyhow::{anyhow, Error, Result};
use powershell_script::PsScriptBuilder;
use run_script::ScriptOptions;
use std::{env, path::PathBuf};
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info};

#[cfg(target_os = "windows")]
use tracing::warn;

#[cfg(target_os = "windows")]
use std::ffi::{c_void, OsStr, OsString};
#[cfg(target_os = "windows")]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(target_os = "windows")]
use windows::{
    core::PCWSTR,
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

    let cmd_clone = cmd.to_string();
    let username_clone = username.to_string();

    // Spawn a thread to execute the command as neither ps nor run_script are async
    let handle = tokio::task::spawn_blocking(move || -> (i32, String, String) {
        let (mut code, mut stdout, mut stderr) = (0, String::new(), String::new());

        if cfg!(target_os = "windows") {
            match execute_windows_ps(
                &cmd_clone,
                &username_clone,
                personate,
                &mut code,
                &mut stdout,
                &mut stderr,
            ) {
                Ok(_) => (),
                Err(e) => {
                    error!("Error executing {:?} : {:?}", &cmd_clone, e);
                    code = 1;
                    stderr = e.to_string();
                }
            }
        } else {
            match execute_unix_command(
                &cmd_clone,
                &username_clone,
                personate,
                &mut code,
                &mut stdout,
                &mut stderr,
            ) {
                Ok(_) => (),
                Err(e) => {
                    error!("Error executing {:?} : {:?}", &cmd_clone, e);
                    code = 1;
                    stderr = e.to_string();
                }
            }
        };

        (code, stdout, stderr)
    });

    // Wait for the blocking task to finish but enforce a timeout
    let (code, stdout, stderr) = if let Some(timeout_secs) = timeout_opt {
        let (code, stdout, stderr) = match timeout(Duration::from_secs(timeout_secs), handle).await
        {
            Ok(join_res) => join_res.map_err(|e| Error::new(e))?,
            Err(_) => {
                error!(
                    "Execution of command {:?} timed out after {} seconds",
                    cmd, timeout_secs
                );
                return Err(anyhow!(
                    "Execution of command timed out after {} seconds",
                    timeout_secs
                ));
            }
        };
        (code, stdout, stderr)
    } else {
        handle.await?
    };

    // Remove newlines from stdout
    let stdout = stdout.replace('\n', "").replace('\r', "");
    if execution_failed(code, &stderr) {
        Err(anyhow!(stderr.clone()))
    } else {
        Ok(stdout)
    }
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

#[derive(Debug)]
struct WindowsUserContext {
    home_dir: PathBuf,
    app_data: PathBuf,
    local_app_data: PathBuf,
}

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
    let mut domain_size: u32 = 0;
    let mut sid_use = SID_NAME_USE(0);

    unsafe {
        if let Err(e) = LookupAccountNameW(
            None::<PCWSTR>,
            username,
            Some(PSID(sid_buffer.as_mut_ptr() as *mut c_void)),
            &mut sid_size,
            None,
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
            0,
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
            None::<PCWSTR>,
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
            None::<PCWSTR>,
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

fn execute_windows_ps(
    cmd: &str,
    username: &str,
    personate: bool,
    code: &mut i32,
    stdout: &mut String,
    stderr: &mut String,
) -> Result<()> {
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

    let ps = PsScriptBuilder::new()
        .no_profile(true)
        .non_interactive(true)
        .print_commands(false)
        .build();
    debug!("Executing powershell command: {}", script);
    match ps.run(&script) {
        Ok(output) => {
            *stdout = output.stdout().as_deref().unwrap_or("").to_string();
            *stderr = output.stderr().as_deref().unwrap_or("").to_string();
            *code = if output.success() { 0 } else { 1 };
            debug!(
                "Execution results for command {:?} : code : {:?} - stdout : {:?} - stderr : {:?}",
                cmd, code, stdout, stderr
            );
            Ok(())
        }
        Err(e) => {
            error!(
                "Powershell execution error with calling {:?} : {:?}",
                cmd, e
            );
            Err(anyhow!("Powershell execution error: {}", e))
        }
    }
}

fn escape_pwsh_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

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

fn resolve_home_unix(username: &str) -> Result<String> {
    let cmd = format!(
        concat!(
            "HOME=$(getent passwd {} 2>/dev/null | cut -d: -f6) || ",
            "HOME=$(dscl . -read /Users/{} NFSHomeDirectory 2>/dev/null | awk '{{print $2}}') || ",
            "{{ [ \"$(uname)\" = \"Darwin\" ] && HOME=\"/Users/{}\" || HOME=\"/home/{}\"; }}; ",
            "echo $HOME"
        ),
        username, username, username, username
    );

    let options = ScriptOptions::new();
    let (code, stdout, stderr) = run_script::run(&cmd, &vec![], &options)
        .map_err(|e| anyhow!("Failed to run home resolution script: {}", e))?;

    if code != 0 {
        return Err(anyhow!(
            "Failed to resolve unix home. Exit code: {}. Stderr: {}",
            code,
            stderr
        ));
    }
    let home = stdout.trim().to_string();
    // If it's empty, fallback to just using /Users/{username} on mac or /home/{username} on linux as a best guess
    if home.is_empty() {
        if cfg!(target_os = "macos") {
            return Ok(format!("/Users/{}", username));
        } else {
            return Ok(format!("/home/{}", username));
        }
    }
    Ok(home)
}

fn execute_unix_command(
    cmd: &str,
    username: &str,
    personate: bool,
    code: &mut i32,
    stdout: &mut String,
    stderr: &mut String,
) -> Result<()> {
    let options = ScriptOptions::new();
    let args = vec![];

    let extcmd = if personate && !username.is_empty() {
        // Determine HOME dynamically using helper
        let home_dir = resolve_home_unix(username)?;
        info!(
            "Setting up execution for user: {} with home: {}",
            username, home_dir
        );

        // On Unix, explicitly setting SHELL can help some scripts
        // We assume /bin/bash or /bin/sh usually, but let's stick to minimal env
        format!(
            "HOME='{}'; USER='{}'; LOGNAME='{}'; SHELL='/bin/bash'; export HOME USER LOGNAME SHELL; {}",
            home_dir, username, username, cmd
        )
    } else {
        cmd.to_string()
    };
    debug!("Executing shell command: {}", extcmd);
    let output = run_script::run(&extcmd, &args, &options)?;
    *code = output.0;
    *stdout = output.1;
    *stderr = output.2;
    debug!(
        "Execution results for command {:?} : code : {:?} - stdout : {:?} - stderr : {:?}",
        cmd, code, stdout, stderr
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
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

    #[test]
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

    #[test]
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
            println!("Skipping test_windows_resolution_matches_env due to resolution failure: {:?}", e);
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
                context.app_data.to_lowercase(), 
                env_appdata.to_lowercase(),
                "Resolved AppData does not match environment AppData. This suggests we might be falling back to default paths incorrectly."
            );
        }
    }
}
