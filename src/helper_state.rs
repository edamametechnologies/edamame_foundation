use std::fmt::Display;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum HelperState {
    Enabled,
    Disabled,
    Fatal,
    Unsupported
}

impl Display for HelperState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelperState::Enabled => write!(f, "Enabled"),
            HelperState::Disabled => write!(f, "Disabled"),
            HelperState::Fatal => write!(f, "Fatal"),
            HelperState::Unsupported => write!(f, "Unsupported"),
        }
    }
}