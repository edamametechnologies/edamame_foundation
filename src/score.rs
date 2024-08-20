use crate::history::*;
use crate::order::MetricOrderResult;
use crate::threat::*;
use crate::update::UpdateStatus;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::{HashMap, HashSet};
use tracing::trace;

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
}

impl Score {
    pub fn new(platform: &str) -> Score {
        // Will read it later
        let history = OrderHistory { history: None };
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
        }
    }

    pub async fn compute_score(&mut self) {
        trace!("Starting score calculation");

        let mut dim = HashMap::new();
        dim.insert("network", (0, 0));
        dim.insert("system services", (0, 0));
        dim.insert("system integrity", (0, 0));
        dim.insert("credentials", (0, 0));
        dim.insert("applications", (0, 0));

        // Compute score
        for m in &self.metrics.metrics {
            trace!(
                "Computing score for metric: {:?} - dimension {:?} - status {:?}",
                m.metric.name,
                m.metric.dimension,
                m.status
            );
            // Compute totals
            let dimension: &str = &m.metric.dimension;
            let (mut current, mut max) = dim[dimension];
            max += m.metric.severity;
            // Increment if not threat or not unknown
            if matches!(m.status, ThreatStatus::Inactive) {
                current += m.metric.severity;
            }
            // Insert back
            dim.insert(&m.metric.dimension, (current, max));

            // TODO: implement complex logic (amplifiers, exceptions) into a configurable scheme
            // TODO: support metrics those type is beyond bool
        }
        let mut overall = 0;
        let mut overall_max = 0;

        let (current, max) = dim["network"];
        overall_max += max;
        overall += current;
        if max > 0 {
            self.network = 100 * current / max;
        } else {
            // Tell the UX to ignore this dimension
            trace!("Network dimension is ignored");
            self.network = -1;
        }

        let (current, max) = dim["system services"];
        overall_max += max;
        overall += current;
        if max > 0 {
            self.system_services = 100 * current / max;
        } else {
            // Tell the UX to ignore this dimension
            trace!("System services dimension is ignored");
            self.system_services = -1;
        }

        let (current, max) = dim["system integrity"];
        overall_max += max;
        overall += current;
        if max > 0 {
            self.system_integrity = 100 * current / max;
        } else {
            // Tell the UX to ignore this dimension
            trace!("System integrity dimension is ignored");
            self.system_integrity = -1;
        }

        let (current, max) = dim["credentials"];
        overall_max += max;
        overall += current;
        if max > 0 {
            self.credentials = 100 * current / max;
        } else {
            // Tell the UX to ignore this dimension
            trace!("Credentials dimension is ignored");
            self.credentials = -1;
        }

        let (current, max) = dim["applications"];
        overall_max += max;
        overall += current;
        if max > 0 {
            self.applications = 100 * current / max;
        } else {
            // Tell the UX to ignore this dimension
            trace!("Applications dimension is ignored");
            self.applications = -1;
        }

        if overall_max > 0 {
            self.overall = 100 * overall / overall_max;
        } else {
            self.overall = 0;
        }
        self.stars = self.overall as f64 * 5.0 / 100.0;
    }

    // Compliance computation
    pub async fn compute_compliance(&mut self) {
        // List all tags in metrics, retain only their comma separated prefix
        let mut tags: HashSet<String> = HashSet::new();

        for m in &self.metrics.metrics {
            for tag in &m.metric.tags {
                if let Some(index) = tag.find(',') {
                    let prefix = tag[0..index].to_string();
                    tags.insert(prefix);
                } else {
                    tags.insert(tag.clone());
                }
            }
        }

        trace!("Compliance tags: {:?}", tags);

        // Create a vector of compliance % per tag
        let mut compliance: HashMap<String, f64> = HashMap::new();
        // Scan through self.metrics.metrics and compute compliance for each tag
        for tag in tags {
            let mut total = 0;
            let mut compliant = 0;
            for m in &self.metrics.metrics {
                for metric_tag in m.metric.tags.clone() {
                    if metric_tag.starts_with(&tag) {
                        total += 1;
                        if matches!(m.status, ThreatStatus::Inactive) {
                            compliant += 1;
                        }
                    }
                }
            }
            if total > 0 {
                let compliance_of_tag = (100.0 * compliant as f64) / total as f64;
                trace!(
                    "Compliance of tag {} is {} over {} which is {} %",
                    tag,
                    compliant,
                    total,
                    compliance_of_tag
                );
                compliance.insert(tag, compliance_of_tag);
            }
        }
        // Write the compliance
        self.compliance = compliance;
    }
}

pub trait ScoreTrait {
    async fn get_metrics_summary(&self) -> String;
    async fn get_history(&self) -> Result<OrderHistory>;
    async fn remediate(&self, name: &str) -> Result<MetricOrderResult>;
    async fn rollback(&self, name: &str) -> Result<MetricOrderResult>;
    async fn update_threats(&mut self, platform: &str, branch: &str) -> Result<UpdateStatus>;
    async fn threat_active(&self, name: &str) -> Result<bool>;
    async fn get_threats_url(&self, platform: &str, branch: &str) -> String;
}
