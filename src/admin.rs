#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform_impl {
    use std::process::Command;
    use std::str;

    pub fn is_admin() -> bool {
        // Run the "id -u" command to check the user ID
        match Command::new("id").arg("-u").output() {
            Ok(output) => {
                if output.status.success() {
                    let uid = str::from_utf8(&output.stdout).unwrap_or("").trim();
                    if uid == "0" {
                        true
                    } else {
                        // Check if the process has the SUDO_USER environment variable
                        if std::env::var("SUDO_USER").is_ok() {
                            true
                        } else {
                            false
                        }
                    }
                } else {
                    false
                }
            }
            Err(e) => {
                tracing::error!("Error running id -u: {}", e);
                false
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod platform_impl {
    use std::mem;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub fn is_admin() -> bool {
        let mut token_handle: HANDLE = HANDLE::default();
        let process_handle = unsafe { GetCurrentProcess() };

        unsafe {
            if OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).is_ok() {
                let mut elevation: TOKEN_ELEVATION = mem::zeroed();
                let mut return_length = 0;

                if GetTokenInformation(
                    token_handle,
                    TokenElevation,
                    Some(&mut elevation as *mut _ as *mut _),
                    mem::size_of::<TOKEN_ELEVATION>() as u32,
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

        false
    }
}

// Re-export a single platform-agnostic function name
pub use platform_impl::is_admin as get_admin_status;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_status() {
        let status = get_admin_status();
        println!("Admin status: {}", status);
        // We do not assert here because different test environments might have different privileges.
    }
}
