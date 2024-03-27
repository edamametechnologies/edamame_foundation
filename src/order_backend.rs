use crate::order_type::MetricOrderType;
use serde::{Deserialize, Serialize};

// Compact version of MetricOrderResult to transmit to the backend
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct MetricOrderResultBackend {
    pub metricname: String,
    pub ordertype: MetricOrderType,
    pub timestamp: String,
    pub success: bool,
    pub validated: bool,
    pub output: String,
}
