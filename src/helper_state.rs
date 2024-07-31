use edamame_backend::helper_state_backend::HelperStateBackend;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

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
