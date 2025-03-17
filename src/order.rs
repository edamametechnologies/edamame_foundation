use crate::order_type::*;
use crate::threat::ThreatMetric;
use edamame_backend::order_backend::MetricOrderResultBackend;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct MetricOrderResult {
    pub order_type: MetricOrderType,
    pub timestamp: String,
    // Execution result
    pub success: bool,
    // Validation status - includes a verification that the Order had the expected effect
    pub validated: bool,
    pub output: String,
    // Associated metric
    pub metric: ThreatMetric,
}

impl Display for MetricOrderResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Result for Order: {} for Metric: {}",
            self.order_type, self.metric.metric.name
        )?;
        write!(f, "- Timestamp: {}", self.timestamp)?;
        write!(f, "- Success: {}", self.success)?;
        write!(f, "- Validated: {}", self.validated)?;
        write!(f, "- Output: {}", self.output)?;
        Ok(())
    }
}

// Convert from MetricOrderResult to MetricOrderResultBackend
impl Into<MetricOrderResultBackend> for MetricOrderResult {
    fn into(self) -> MetricOrderResultBackend {
        MetricOrderResultBackend {
            ordertype: self.order_type.into(),
            timestamp: self.timestamp,
            success: self.success,
            validated: self.validated,
            output: self.output,
            metricname: self.metric.metric.name.clone(),
        }
    }
}
