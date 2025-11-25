use anyhow::{anyhow, Error, Result};
use powershell_script::PsScriptBuilder;
use run_script::ScriptOptions;
use tokio::time::{timeout, Duration};
use tracing::{debug, error};

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
                Err(e) => error!("Error executing {:?} : {:?}", &cmd_clone, e),
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
                Err(e) => error!("Error executing {:?} : {:?}", &cmd_clone, e),
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
        if let Some(env_block) = build_windows_env_block(username) {
            script.push_str(&env_block);
            script.push('\n');
        }
    }
    script.push_str(cmd);

    let ps = PsScriptBuilder::new()
        .no_profile(true)
        .non_interactive(true)
        .hidden(true)
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

fn build_windows_env_block(username: &str) -> Option<String> {
    let user_segment = username
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(username);
    let escaped_username = escape_pwsh_single_quoted(username);
    let escaped_segment = escape_pwsh_single_quoted(user_segment);

    Some(format!(
        concat!(
            "$edamameUser = '{username}'\n",
            "$edamameUserFolder = '{segment}'\n",
            "$userProfilePath = Join-Path $env:SystemDrive ('Users\\' + $edamameUserFolder)\n",
            "if (-not (Test-Path $userProfilePath)) {{\n",
            "  try {{\n",
            "    $profileObj = Get-CimInstance Win32_UserProfile -ErrorAction Stop |\n",
            "      Where-Object {{ $_.LocalPath -like \"*\\\\{segment}\" }} |\n",
            "      Select-Object -First 1\n",
            "    if ($profileObj -and (Test-Path $profileObj.LocalPath)) {{\n",
            "      $userProfilePath = $profileObj.LocalPath\n",
            "    }}\n",
            "  }} catch {{ }}\n",
            "}}\n",
            "if (-not (Test-Path $userProfilePath)) {{\n",
            "  $userProfilePath = Join-Path $env:SystemDrive ('Users\\' + $edamameUserFolder)\n",
            "}}\n",
            // Set core path variables
            "$env:USERPROFILE = $userProfilePath\n",
            "$env:HOME = $userProfilePath\n",
            "try {{\n",
            "  $env:HOMEDRIVE = Split-Path $userProfilePath -Qualifier\n",
            "  $env:HOMEPATH = $userProfilePath.Substring($env:HOMEDRIVE.Length)\n",
            "}} catch {{\n",
            "  $env:HOMEDRIVE = $env:SystemDrive\n",
            "  $env:HOMEPATH = $userProfilePath.Substring($env:HOMEDRIVE.Length)\n",
            "}}\n",
            "$env:LOCALAPPDATA = Join-Path $userProfilePath 'AppData\\Local'\n",
            "$env:APPDATA = Join-Path $userProfilePath 'AppData\\Roaming'\n",
            "$env:TEMP = Join-Path $userProfilePath 'AppData\\Local\\Temp'\n",
            "$env:TMP = Join-Path $userProfilePath 'AppData\\Local\\Temp'\n",
            // Load user's environment variables from registry
            // Get the user's SID to access their registry hive
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
            "          # Expand any environment variable references in the value\n",
            "          $expandedValue = [System.Environment]::ExpandEnvironmentVariables($value)\n",
            "          Set-Item -Path \"env:$name\" -Value $expandedValue -ErrorAction SilentlyContinue\n",
            "        }}\n",
            "      }}\n",
            "    }}\n",
            "  }}\n",
            "}} catch {{ }}\n"
        ),
        username = escaped_username,
        segment = escaped_segment
    ))
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
        // Like Windows: run as root but set user's environment variables
        // Determine HOME dynamically using platform-specific methods
        format!(
            concat!(
                "HOME=$(getent passwd {} 2>/dev/null | cut -d: -f6) || ",
                "HOME=$(dscl . -read /Users/{} NFSHomeDirectory 2>/dev/null | awk '{{print $2}}') || ",
                "{{ [ \"$(uname)\" = \"Darwin\" ] && HOME=\"/Users/{}\" || HOME=\"/home/{}\"; }}; ",
                "USER='{}'; ",
                "LOGNAME='{}'; ",
                "export HOME USER LOGNAME; ",
                "{}"
            ),
            username, username, username, username, username, username, cmd
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
