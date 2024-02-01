use serde::{Deserialize, Serialize};

use crate::order_type::*;
use crate::threat::ThreatMetric;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MetricOrderResult {
    pub ordertype: MetricOrderType,
    pub timestamp: String,
    // Execution status
    pub success: bool,
    // Validation status - includes a verification that the Order had the expected effect
    pub validated: bool,
    pub output: String,
    // Associated metric
    pub metric: ThreatMetric,
}

