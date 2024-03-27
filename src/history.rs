use crate::order::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct OrderHistory {
    pub history: Vec<MetricOrderResult>,
}
