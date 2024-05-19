use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use std::error::Error;

use crate::history::*;
use crate::order::MetricOrderResult;
use crate::threat::*;
use crate::update::UpdateStatus;

// Score
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Score {
    pub network: i32,
    pub system_integrity: i32,
    pub system_services: i32,
    pub applications: i32,
    pub credentials: i32,
    pub overall: i32,
    pub stars: f64,
    #[serde_as(as = "Vec<(_, _)>")]
    pub compliance: HashMap<String, f64>,
    pub metrics: ThreatMetrics,
    pub history: OrderHistory,
    pub last_compute: Option<DateTime<Utc>>,
    pub compute_in_progress: bool,
}

pub trait ScoreTrait {
    async fn compute(&mut self, compute_requested: bool) -> bool;
    async fn get_progress_percent(&self) -> f32;
    async fn get_last_completed_metric(&self) -> ThreatMetric;
    fn get_metrics_summary(&self) -> String;
    async fn get_history(&mut self) -> Result<OrderHistory, Box<dyn Error>>;
    async fn remediate(&mut self, name: &str) -> Result<MetricOrderResult, Box<dyn Error>>;
    async fn rollback(&mut self, name: &str) -> Result<MetricOrderResult, Box<dyn Error>>;
    async fn update_threats(
        &mut self,
        platform: &str,
        branch: &str,
    ) -> Result<UpdateStatus, Box<dyn Error>>;
    async fn threat_active(&mut self, name: &str) -> Result<bool, Box<dyn Error>>;
}

impl Score {
    pub fn new(platform: &str) -> Score {
        // Will read it later
        let history = OrderHistory {
            history: Vec::new(),
        };
        Score {
            network: 0,
            system_integrity: 0,
            system_services: 0,
            applications: 0,
            credentials: 0,
            overall: 0,
            stars: 0.0,
            compliance: HashMap::new(),
            metrics: ThreatMetrics::new(platform),
            history,
            last_compute: None,
            compute_in_progress: false,
        }
    }
}
