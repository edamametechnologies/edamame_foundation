#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn get_admin_status() -> bool {
    // macOS and Linux
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::process::Command;
        use std::str;

        // Run the "id -u" command to check the user ID
        match Command::new("id").arg("-u").output() {
            Ok(output) => {
                if output.status.success() {
                    let uid = str::from_utf8(&output.stdout).unwrap_or("").trim();
                    if uid == "0" {
                        return true;
                    } else {
                        // Check if the process has the SUDO_USER environment variable
                        if std::env::var("SUDO_USER").is_ok() {
                            return true;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Error running id -u: {}", e);
                return false;
            }
        }
    }

    // Windows
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token_handle: HANDLE = HANDLE::default();
        let process_handle = unsafe { GetCurrentProcess() };

        unsafe {
            if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_ok() {
                let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
                let mut return_length = 0;

                if GetTokenInformation(
                    token_handle,
                    TokenElevation,
                    Some(&mut elevation as *mut _ as *mut _),
                    std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                    &mut return_length,
                )
                .is_ok()
                {
                    if elevation.TokenIsElevated != 0 {
                        return true;
                    }
                }
            }
        }
    }

    false
}
