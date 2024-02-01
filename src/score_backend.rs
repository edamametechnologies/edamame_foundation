use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::history::OrderHistory;
use crate::threat::ThreatMetrics;
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScoreBackend {
    // % of compliance
    pub network: i32,
    pub system_integrity: i32,
    pub system_services: i32,
    pub applications: i32,
    pub credentials: i32,
    pub overall: i32,
    // Stars are computed according to a variety of criteria - on 5 stars (0.0 to 5.0)
    pub stars: f64,
    #[serde_as(as = "Vec<(_, _)>")]
    pub compliance: HashMap<String, f64>,
    pub metrics: ThreatMetrics,
    pub history: OrderHistory,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
#[derive(Serialize, Deserialize, Debug, Clone)]
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