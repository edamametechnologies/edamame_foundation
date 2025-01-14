use crate::helper_tx::*;
use crate::order_type::*;
use anyhow::Result;
use envcrypt::envc;
use lazy_static::lazy_static;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
lazy_static! {
    static ref EDAMAME_TARGET: String = envc!("EDAMAME_TARGET").trim_matches('"').to_string();
    static ref EDAMAME_CA_PEM: String = envc!("EDAMAME_CA_PEM").trim_matches('"').to_string();
    static ref EDAMAME_CLIENT_PEM: String =
        envc!("EDAMAME_CLIENT_PEM").trim_matches('"').to_string();
    static ref EDAMAME_CLIENT_KEY: String =
        envc!("EDAMAME_CLIENT_KEY").trim_matches('"').to_string();
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub async fn helper_run_metric_secured(
    subordertype: MetricOrderType,
    metric_name: &str,
    user: &str,
    signature: &str,
) -> Result<String> {
    return helper_run_metric(
        subordertype,
        metric_name,
        user,
        signature,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    )
    .await;
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub async fn helper_run_utility_secured(order: &str, arg1: &str, arg2: &str) -> Result<String> {
    return helper_run_utility(
        order,
        arg1,
        arg2,
        &EDAMAME_CA_PEM,
        &EDAMAME_CLIENT_PEM,
        &EDAMAME_CLIENT_KEY,
        &EDAMAME_TARGET,
    )
    .await;
}
