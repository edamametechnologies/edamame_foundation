use crate::history_backend::OrderHistoryBackend;
use crate::threat::ThreatMetrics;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ScoreBackend {
    pub network: i32,
    pub system_integrity: i32,
    pub system_services: i32,
    pub applications: i32,
    pub credentials: i32,
    pub overall: i32,
    pub stars: f64,
    // We don't use a hashmap here to keep it simple with the backend
    pub compliance: Vec<(String, f64)>,
    pub metrics: ThreatMetrics,
    pub history: OrderHistoryBackend,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct NumericalScoreBackend {
    pub device_id: String,
    pub os_name: String,
    pub os_version: String,
    pub ip: String,
    pub ip6: String,
    pub mac: String,
    pub score: f64,
    pub connected_user: String,
    pub connected_domain: String,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct DetailedScoreBackend {
    pub device_id: String,
    pub os_name: String,
    pub os_version: String,
    pub ip: String,
    pub ip6: String,
    pub mac: String,
    pub core_version: String,
    pub city: String,
    pub region: String,
    pub country: String,
    pub timezone: String,
    pub latitude: String,
    pub longitude: String,
    pub helper_state: String,
    pub score: ScoreBackend,
    // RFC3339
    pub timestamp: String,
    pub connected_user: String,
    pub connected_domain: String,
}
