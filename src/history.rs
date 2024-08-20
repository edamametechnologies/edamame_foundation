use crate::order::*;
use edamame_backend::history_backend::OrderHistoryBackend;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct OrderHistory {
    pub history: Option<Vec<MetricOrderResult>>,
}

// Convert from OrderHistory to OrderHistoryBackend
impl Into<OrderHistoryBackend> for OrderHistory {
    fn into(self) -> OrderHistoryBackend {
        let history = self
            .history
            .unwrap_or_default()
            .into_iter()
            .map(|x| x.into())
            .collect();
        OrderHistoryBackend { history }
    }
}
