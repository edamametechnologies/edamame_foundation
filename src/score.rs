use crate::history::*;
use crate::order::MetricOrderResult;
use crate::threat::*;
use crate::threat_factory::*;
use anyhow::Result;
use chrono::{DateTime, Utc};
use edamame_models::*;
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
    pub fn new() -> Score {
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
            metrics: ThreatMetrics::new(),
            history,
            last_compute: None,
        }
    }

    pub async fn compute_score(&mut self) {
        trace!("Starting score calculation");

        // Initialize the metrics if not already initialized
        if self.metrics.metrics.is_empty() {
            self.metrics = get_threat_metrics().await;
        }

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

    // List all tags in metrics, retain only their comma separated prefix
    pub async fn get_tag_prefixes(&self) -> HashSet<String> {
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
        tags
    }

    // Compliance computation
    pub async fn compute_compliance(&mut self) {
        let tags: HashSet<String> = self.get_tag_prefixes().await;

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

    pub async fn check_policy(
        &self,
        minimum_score: f32,
        threat_ids: HashSet<String>,
        tag_prefixes: HashSet<String>,
    ) -> Result<bool> {
        // Start with the assumption that the policy check will pass
        let mut passed = true;

        // Check if the score meets the minimum requirement
        if self.stars < (minimum_score as f64) {
            trace!(
                "Policy check failed: score {:.1} < minimum {:.1}",
                self.stars,
                minimum_score
            );
            passed = false;
        } else {
            trace!(
                "Policy check passed: score {:.1} >= minimum {:.1}",
                self.stars,
                minimum_score
            );
        }

        // Check if all specified threats are fixed
        for threat_id in threat_ids {
            match self
                .metrics
                .metrics
                .iter()
                .find(|m| m.metric.name == threat_id)
            {
                Some(metric) => {
                    if matches!(metric.status, ThreatStatus::Active) {
                        trace!("Policy check failed: threat '{}' is active", threat_id);
                        passed = false;
                    } else {
                        trace!("Policy check passed: threat '{}' is not active", threat_id);
                    }
                }
                None => {
                    trace!("Policy check failed: threat '{}' not found", threat_id);
                    passed = false;
                }
            }
        }

        // Check compliance for each tag prefix
        for tag in tag_prefixes {
            if let Some(compliance_value) = self.compliance.get(&tag) {
                // Consider compliance below 100% as a failure
                if *compliance_value < 100.0 {
                    trace!(
                        "Policy check failed: tag '{}' compliance is {:.1}%",
                        tag,
                        compliance_value
                    );
                    passed = false;
                } else {
                    trace!(
                        "Policy check passed: tag '{}' compliance is {:.1}%",
                        tag,
                        compliance_value
                    );
                }
            } else {
                // If the tag is not found in compliance data, consider it a failure
                trace!(
                    "Policy check failed: tag '{}' not found in compliance data",
                    tag
                );
                passed = false;
            }
        }

        if passed {
            trace!("Overall policy check: PASSED");
        } else {
            trace!("Overall policy check: FAILED");
        }

        Ok(passed)
    }
}

pub trait ScoreTrait {
    async fn get_metrics_summary(&self) -> String;
    async fn get_history(&self) -> Result<OrderHistory>;
    async fn remediate(&self, name: &str) -> Result<MetricOrderResult>;
    async fn rollback(&self, name: &str) -> Result<MetricOrderResult>;
    async fn update_threats(&mut self, branch: &str) -> Result<UpdateStatus>;
    async fn threat_active(&self, name: &str) -> Result<MetricOrderResult>;
    async fn get_threats_url(&self, platform: &str, branch: &str) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_score_check_policy() {
        let mut score = Score::new();
        let metrics = get_threat_metrics().await;
        score.metrics = metrics;

        // Mock the score computation
        score.stars = 4.0;

        let stars = score.stars as f32;
        // Check policy with minimum score
        let result = score
            .check_policy(stars, HashSet::new(), HashSet::new())
            .await;
        assert!(result.is_ok() && result.unwrap());

        // Check policy with minimum score
        let result = score
            .check_policy(stars + 1.0, HashSet::new(), HashSet::new())
            .await;
        assert!(result.is_ok() && !result.unwrap());

        // Check policy with minimum score
        let result = score
            .check_policy(stars - 1.0, HashSet::new(), HashSet::new())
            .await;
        assert!(result.is_ok() && result.unwrap());
    }
}
