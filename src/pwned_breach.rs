use chrono::{DateTime, Utc};
use edamame_backend::pwned_breach_backend::PwnedCriticalityBackend;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum PwnedCriticality {
    Unknown,
    Low,
    Medium,
    High,
}

impl Display for PwnedCriticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PwnedCriticality::Unknown => write!(f, "Unknown"),
            PwnedCriticality::Low => write!(f, "Low"),
            PwnedCriticality::Medium => write!(f, "Medium"),
            PwnedCriticality::High => write!(f, "High"),
        }
    }
}

impl From<PwnedCriticalityBackend> for PwnedCriticality {
    fn from(c: PwnedCriticalityBackend) -> Self {
        match c {
            PwnedCriticalityBackend::Unknown => PwnedCriticality::Unknown,
            PwnedCriticalityBackend::Low => PwnedCriticality::Low,
            PwnedCriticalityBackend::Medium => PwnedCriticality::Medium,
            PwnedCriticalityBackend::High => PwnedCriticality::High,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct BreachDetail {
    pub name: String,
    pub title: String,
    pub domain: String,
    pub breachdate: String,
    pub count: u64,
    pub description: String,
    pub short_data_classes: Vec<String>,
    pub data_classes: Vec<String>,
    pub is_verified: bool,
    pub is_sensitive: bool,
    pub dismiss: bool,
    pub timestamp_dismiss: DateTime<Utc>,
    pub criticality: PwnedCriticality,
}
