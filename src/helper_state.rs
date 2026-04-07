use edamame_backend::helper_state_backend::HelperStateBackend;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
#[cfg(target_os = "macos")]
use tracing::error;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum HelperState {
    Enabled,
    // macOS only
    EnabledFullDisk,
    Disabled,
    EnabledOutdated,
    Fatal,
    Unsupported,
}

impl Display for HelperState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelperState::Enabled => write!(f, "Enabled"),
            HelperState::EnabledFullDisk => write!(f, "EnabledFullDisk"),
            HelperState::Disabled => write!(f, "Disabled"),
            HelperState::EnabledOutdated => write!(f, "EnabledOutdated"),
            HelperState::Fatal => write!(f, "Fatal"),
            HelperState::Unsupported => write!(f, "Unsupported"),
        }
    }
}

/// Probe helper capability flags. On macOS, checks TCC full-disk-access by
/// attempting to open the TCC database; on other platforms returns an empty string.
pub fn get_helper_flags() -> String {
    #[cfg(target_os = "macos")]
    {
        #[cfg(target_os = "macos")]
        use libc::EACCES;
        use std::fs::File;
        use std::io::ErrorKind;

        let path = "/Library/Application Support/com.apple.TCC/TCC.db";
        let full_disk_access = match File::open(path) {
            Ok(_) => true,
            Err(ref e) if e.kind() == ErrorKind::PermissionDenied => false,
            Err(ref e) if e.raw_os_error() == Some(EACCES) => false,
            Err(e) => {
                error!("Failed to check full disk access: {}", e);
                false
            }
        };
        format!("full_disk_access={}", full_disk_access)
    }
    #[cfg(not(target_os = "macos"))]
    {
        String::new()
    }
}

impl Into<HelperStateBackend> for HelperState {
    fn into(self) -> HelperStateBackend {
        match self {
            HelperState::Enabled => HelperStateBackend::Enabled,
            HelperState::EnabledFullDisk => HelperStateBackend::EnabledFullDisk,
            HelperState::Disabled => HelperStateBackend::Disabled,
            HelperState::EnabledOutdated => HelperStateBackend::Outdated,
            HelperState::Fatal => HelperStateBackend::Fatal,
            HelperState::Unsupported => HelperStateBackend::Unsupported,
        }
    }
}
