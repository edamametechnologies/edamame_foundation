use log::{error, trace};
use run_script::ScriptOptions;
use std::error::Error;
use std::thread::spawn;

use powershell_script::PsScriptBuilder;

// The personate parameter forces the execution into the context of username
// We could use an empty username to indicate there is no need to personate but we keep it as is for now in case we find other use cases for the username
pub async fn run_cli(cmd: &str, username: &str, personate: bool) -> Result<String, Box<dyn Error>> {
    // Verify platform support
    check_platform_support()?;

    let cmd_clone = cmd.to_string();
    let username_clone = username.to_string();

    // Spawn a thread to execute the command as neither ps nor run_script are async
    let handle = spawn(move || -> (i32, String, String) {
        let (mut code, mut stdout, mut stderr) = (0, String::new(), String::new());

        if cfg!(target_os = "windows") {
            match execute_windows_ps(&cmd_clone, &mut code, &mut stdout, &mut stderr) {
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

    // Wait for the thread to finish
    let (code, mut stdout, stderr) = handle.join().unwrap();

    // Remove newlines from stdout
    stdout = stdout.replace('\n', "");
    stdout = stdout.replace('\r', "");

    trace!(
        "Execution results for {:?} - code : {:?} - stdout : {:?} - stderr : {:?}",
        cmd,
        code,
        stdout,
        stderr
    );

    if execution_failed(code, &stderr) {
        Err(From::from(stderr.clone()))
    } else {
        Ok(stdout.clone())
    }
}

// This is our convention for detecting a failed execution
fn execution_failed(code: i32, stderr: &str) -> bool {
    code != 0 && !stderr.is_empty()
}

fn check_platform_support() -> Result<(), Box<dyn Error>> {
    if cfg!(target_os = "ios") || cfg!(target_os = "Android") {
        let os_name = if cfg!(target_os = "ios") {
            "iOS"
        } else {
            "Android"
        };
        error!("{} is not supported", os_name);
        return Err(From::from(format!("{} is not supported", os_name)));
    }
    Ok(())
}

fn execute_windows_ps(
    cmd: &str,
    code: &mut i32,
    stdout: &mut String,
    stderr: &mut String,
) -> Result<(), Box<dyn Error>> {
    let ps = PsScriptBuilder::new()
        .no_profile(true)
        .non_interactive(true)
        .hidden(true)
        .print_commands(false)
        .build();
    match ps.run(cmd) {
        Ok(output) => {
            *stdout = output.stdout().as_deref().unwrap_or("").to_string();
            *stderr = output.stderr().as_deref().unwrap_or("").to_string();
            *code = if output.success() { 0 } else { 1 };
            Ok(())
        }
        Err(e) => {
            error!(
                "Powershell execution error with calling {:?} : {:?}",
                cmd,
                e.to_string()
            );
            Err(From::from(e.to_string()))
        }
    }
}

fn execute_unix_command(
    cmd: &str,
    username: &str,
    personate: bool,
    code: &mut i32,
    stdout: &mut String,
    stderr: &mut String,
) -> Result<(), Box<dyn Error>> {
    let options = ScriptOptions::new();
    let args = vec![];

    let extcmd = if personate {
        format!("sudo -u {} /bin/bash -c '{}'", username, cmd)
    } else {
        cmd.to_string()
    };
    trace!("Executing shell command: {}", extcmd);
    let output = run_script::run(&extcmd, &args, &options)?;
    *code = output.0;
    *stdout = output.1;
    *stderr = output.2;
    Ok(())
}
