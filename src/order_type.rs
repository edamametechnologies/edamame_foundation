use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub enum MetricOrderType {
    Capture,
    Remediate,
    Rollback,
}

impl fmt::Display for MetricOrderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetricOrderType::Capture => write!(f, "capture"),
            MetricOrderType::Remediate => write!(f, "remediate"),
            MetricOrderType::Rollback => write!(f, "rollback"),
        }
    }
}
