use serde::{Serialize, Deserialize};
use crate::order_backend::*;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct OrderHistory {
    pub history: Vec<MetricOrderResultBackend>,
}
