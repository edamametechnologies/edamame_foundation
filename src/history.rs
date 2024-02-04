use serde::{Serialize, Deserialize};
use crate::order_backend::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderHistory {
    pub history: Vec<MetricOrderResultBackend>,
}
