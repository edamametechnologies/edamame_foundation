use log::{error, info, warn};
use reqwest;
use reqwest::Client;
use std::error::Error;
use std::time::Duration;

use crate::threat::*;
use crate::threat_metrics_android::*;
use crate::threat_metrics_ios::*;
use crate::threat_metrics_linux::*;
use crate::threat_metrics_macos::*;
use crate::threat_metrics_windows::*;
use crate::update::*;

static THREAT_MODEL_URL: &str =
    "https://raw.githubusercontent.com/edamametechnologies/threatmodels";

impl ThreatMetric {
    pub fn new() -> ThreatMetric {
        ThreatMetric {
            metric: ThreatMetricJSON::new(),
            timestamp: "".to_string(),
            // No threat by default
            status: ThreatStatus::Unknown,
            // internal_metrics: None,
        }
    }
}

impl ThreatMetricJSON {
    pub fn new() -> ThreatMetricJSON {
        ThreatMetricJSON {
            name: "".to_string(),
            metrictype: "".to_string(),
            dimension: "".to_string(),
            severity: 0,
            scope: "".to_string(),
            tags: Vec::new(),
            description: Vec::new(),
            implementation: ThreatMetricImplementationJSON::new(),
            remediation: ThreatMetricImplementationJSON::new(),
            rollback: ThreatMetricImplementationJSON::new(),
        }
    }
}

impl ThreatMetricImplementationJSON {
    pub fn new() -> ThreatMetricImplementationJSON {
        ThreatMetricImplementationJSON {
            class: "".to_string(),
            elevation: "".to_string(),
            target: "".to_string(),
            education: Vec::new(),
            maxversion: 0,
            minversion: 0,
            system: "".to_string(),
        }
    }
}

impl ThreatMetrics {
    // Initialize with the appropriate built-in version of the threat model
    fn get_builtin_version(platform: &str) -> Result<&'static str, String> {
        if !platform.is_empty() {
            if platform == "macos" {
                Ok(THREAT_METRICS_MACOS)
            } else if platform == "windows" {
                Ok(THREAT_METRICS_WINDOWS)
            } else if platform == "ios" {
                Ok(THREAT_METRICS_IOS)
            } else if platform == "android" {
                Ok(THREAT_METRICS_ANDROID)
            } else if platform == "linux" {
                Ok(THREAT_METRICS_LINUX)
            } else {
                Err("Unsupported platform.".to_string())
            }
        } else if cfg!(target_os = "macos") {
            Ok(THREAT_METRICS_MACOS)
        } else if cfg!(target_os = "windows") {
            Ok(THREAT_METRICS_WINDOWS)
        } else if cfg!(target_os = "ios") {
            Ok(THREAT_METRICS_IOS)
        } else if cfg!(target_os = "android") {
            Ok(THREAT_METRICS_ANDROID)
        } else if cfg!(target_os = "linux") {
            Ok(THREAT_METRICS_LINUX)
        } else {
            Err("Unsupported operating system.".to_string())
        }
    }

    // Get the appropriate threat model JSON file based on the platform
    fn get_model_name(platform: &str) -> Result<&'static str, Box<dyn Error>> {
        if !platform.is_empty() {
            if platform == "macos" {
                Ok("threatmodel-macOS.json")
            } else if platform == "windows" {
                Ok("threatmodel-Windows.json")
            } else if platform == "ios" {
                Ok("threatmodel-iOS.json")
            } else if platform == "android" {
                Ok("threatmodel-Android.json")
            } else if platform == "linux" {
                Ok("threatmodel-Linux.json")
            } else {
                Err(format!("Unsupported platform: {}", platform).into())
            }
        } else if cfg!(target_os = "macos") {
            Ok("threatmodel-macOS.json")
        } else if cfg!(target_os = "windows") {
            Ok("threatmodel-Windows.json")
        } else if cfg!(target_os = "ios") {
            Ok("threatmodel-iOS.json")
        } else if cfg!(target_os = "android") {
            Ok("threatmodel-Android.json")
        } else if cfg!(target_os = "linux") {
            Ok("threatmodel-Linux.json")
        } else {
            Err(format!("Unsupported operating system: {}", std::env::consts::OS).into())
        }
    }

    pub fn new(platform: &str) -> ThreatMetrics {
        // Initialize with the builtin version
        let builtin = match Self::get_builtin_version(platform) {
            Ok(_builtin) => {
                // Use the built-in version
                _builtin
            }
            Err(error) => {
                // Handle the error
                error!("Error: {}", error);
                std::process::exit(1);
            }
        };
        let json: ThreatMetricsJSON = serde_json::from_str(builtin)
            .expect("builtin threat model json does not have correct format");

        info!("Threat model initialized to builtin version");
        // Then create complete versions of objects

        let clone_json = json.clone();
        ThreatMetrics {
            name: json.name,
            extends: json.extends,
            date: json.date,
            signature: json.signature,
            metrics: Self::create_metrics(&clone_json),
            timestamp: "".to_string(),
        }
    }

    fn create_metrics(json: &ThreatMetricsJSON) -> Vec<ThreatMetric> {
        let mut metrics = Vec::new();
        let clone_json = json.clone();
        for j in clone_json.metrics {
            metrics.push(ThreatMetric {
                metric: j,
                timestamp: "".to_string(),
                // No threat by default
                status: ThreatStatus::Unknown,
                // internal_metrics: None,
            })
        }
        metrics
    }

    // Update the threat model from the backend
    pub async fn update(
        &mut self,
        platform: &str,
        branch: &str,
    ) -> Result<UpdateStatus, Box<dyn Error>> {
        info!("Starting threat model update from backend");

        let mut status = UpdateStatus::NotUpdated;

        let model = match Self::get_model_name(platform) {
            Ok(_model) => {
                // Use the appropriate threat model JSON file
                info!("Using threat model: {}", _model);
                _model
            }
            Err(error) => {
                // Handle the error
                error!("Error: {}", error);
                std::process::exit(1);
            }
        };

        let url = format!("{}/{}/{}", THREAT_MODEL_URL, branch, model);

        info!("Fetching threat model from {}", url);
        // Create a client with a timeout
        let client = Client::builder().timeout(Duration::from_secs(20)).build()?;

        // Use the client to make a request
        let response = client.get(&url).send().await;

        match response {
            Ok(res) => {
                if res.status().is_success() {
                    info!("Threat model transfer complete");

                    let json: ThreatMetricsJSON = match res.json().await {
                        Ok(json) => json,
                        Err(err) => {
                            error!("Profiles transfer failed: {:?}", err);
                            return if err.is_decode() {
                                Ok(UpdateStatus::FormatError)
                            } else {
                                Err(err.into())
                            };
                        }
                    };

                    // Then create complete versions of objects
                    let metrics = Self::create_metrics(&json);
                    self.name = json.name;
                    self.extends = json.extends;
                    self.date = json.date;
                    self.signature = json.signature;
                    self.metrics = metrics;
                    self.timestamp = "".to_string();

                    // Success
                    status = UpdateStatus::Updated;
                } else {
                    error!(
                        "Threat model transfer failed with status: {:?}",
                        res.status()
                    );
                }
            }
            Err(err) => {
                // Only warn this can happen if the device is offline
                warn!("Threat model transfer failed: {:?}", err);
            }
        }

        Ok(status)
    }
}
