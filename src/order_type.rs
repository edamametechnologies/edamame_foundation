use serde::{Deserialize, Serialize};
use std::fmt;
use edamame_backend::order_type_backend::MetricOrderTypeBackend;

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

impl Into<MetricOrderTypeBackend> for MetricOrderType {
    fn into(self) -> MetricOrderTypeBackend {
        match self {
            MetricOrderType::Capture => MetricOrderTypeBackend::Capture,
            MetricOrderType::Remediate => MetricOrderTypeBackend::Remediate,
            MetricOrderType::Rollback => MetricOrderTypeBackend::Rollback,
        }
    }
}