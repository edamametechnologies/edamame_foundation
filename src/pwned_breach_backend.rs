use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum PwnedCriticalityBackend {
    Unknown,
    Low,
    Medium,
    High,
}

impl Display for PwnedCriticalityBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PwnedCriticalityBackend::Unknown => write!(f, "Unknown"),
            PwnedCriticalityBackend::Low => write!(f, "Low"),
            PwnedCriticalityBackend::Medium => write!(f, "Medium"),
            PwnedCriticalityBackend::High => write!(f, "High"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct BreachDetailBackend {
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
    pub criticality: PwnedCriticalityBackend,
}
