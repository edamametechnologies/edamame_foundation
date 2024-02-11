pub mod backend;
pub mod foundation;
pub mod history;
pub mod history_backend;
#[cfg(not(feature = "disable-helper"))]
pub mod helper_proto;
#[cfg(not(feature = "disable-helper"))]
pub mod helper_tx;
#[cfg(not(feature = "disable-helper"))]
pub mod helper_rx;
#[cfg(not(feature = "disable-helper"))]
pub mod helper_rx_utility;
pub mod lanscan_arp;
pub mod lanscan_device_info;
pub mod lanscan_device_info_backend;
pub mod lanscan_mdns;
pub mod lanscan_port_vulns;
pub mod lanscan_port_vulns_db;
pub mod lanscan_profiles;
pub mod lanscan_profiles_db;
pub mod lanscan_oui;
pub mod lanscan_oui_db;
pub mod lanscan_port_info;
pub mod lanscan_interface;
pub mod logger;
pub mod order;
pub mod order_backend;
pub mod order_type;
pub mod pwned_breach;
#[cfg(not(feature = "disable-helper"))]
pub mod runner_cli;
pub mod runtime;
pub mod score;
pub mod score_backend;
pub mod threat;
pub mod threat_factory;
pub mod threat_metrics_android;
pub mod threat_metrics_ios;
pub mod threat_metrics_linux;
pub mod threat_metrics_macos;
pub mod threat_metrics_windows;

// For config files pulled from the backend
pub enum UpdateStatus {
    Updated,
    NotUpdated,
    FormatError,
}