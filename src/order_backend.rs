use serde::{Deserialize, Serialize};
use crate::order_type::MetricOrderType;

// Compact version of MetricOrderResult to transmit to the backend
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MetricOrderResultBackend {
    pub metricname: String,
    pub ordertype: MetricOrderType,
    pub timestamp: String,
    pub success: bool,
    pub validated: bool,
    pub output: String,
}
