use serde::{Serialize, Deserialize};
use crate::order_backend::*;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct OrderHistoryBackend {
    pub history: Vec<MetricOrderResultBackend>,
}
