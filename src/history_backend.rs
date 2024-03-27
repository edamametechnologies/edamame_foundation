use crate::order_backend::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct OrderHistoryBackend {
    pub history: Vec<MetricOrderResultBackend>,
}
