use serde::{Deserialize, Serialize};

use crate::order_type::*;
use crate::threat::ThreatMetric;
use edamame_backend::order_backend::MetricOrderResultBackend;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct MetricOrderResult {
    pub order_type: MetricOrderType,
    pub timestamp: String,
    // Execution status
    pub success: bool,
    // Validation status - includes a verification that the Order had the expected effect
    pub validated: bool,
    pub output: String,
    // Associated metric
    pub metric: ThreatMetric,
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
