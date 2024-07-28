use crate::threat::*;
use crate::threat_metrics_android::*;
use crate::threat_metrics_ios::*;
use crate::threat_metrics_linux::*;
use crate::threat_metrics_macos::*;
use crate::threat_metrics_windows::*;
use crate::update::*;
use anyhow::{anyhow, Result};
use reqwest;
use reqwest::Client;
use std::time::Duration;
use tracing::{error, info, warn};

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
    fn get_model_name(platform: &str) -> Result<&'static str> {
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
                Err(anyhow!("Unsupported platform: {}", platform.to_string()))
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
            Err(anyhow!(
                "Unsupported operating system: {}",
                std::env::consts::OS
            ))
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

    pub fn get_model_url(platform: &str, branch: &str) -> Result<String> {
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

        Ok(format!("{}/{}/{}", THREAT_MODEL_URL, branch, model))
    }

    // Update the threat model from the backend
    pub async fn update(&mut self, platform: &str, branch: &str) -> Result<UpdateStatus> {
        info!("Starting threat model update from backend");

        let mut status = UpdateStatus::NotUpdated;

        let url = Self::get_model_url(platform, branch)?;

        info!("Fetching threat model from {}", url);
        // Create a client with a timeout
        let client = Client::builder()
            .gzip(true)
            .timeout(Duration::from_secs(20))
            .build()?;

        // Use the client to make a request
        let response = client.get(&url).send().await;

        match response {
            Ok(res) => {
                if res.status().is_success() {
                    info!("Model transfer complete");
                    // Perform the transfer and decode in 2 steps in order to catch format errors
                    let json: ThreatMetricsJSON = match res.text().await {
                        Ok(json) => {
                            match serde_json::from_str(&json) {
                                Ok(json) => json,
                                Err(err) => {
                                    error!("Model decoding failed : {:?}", err);
                                    // Catch a JSON format mismatch
                                    return Ok(UpdateStatus::FormatError);
                                }
                            }
                        }
                        Err(err) => {
                            // Only warn this can happen if the device is offline
                            warn!("Model transfer failed: {:?}", err);
                            return Err(err.into());
                        }
                    };

                    // Then create complete versions of objects
                    let metrics = Self::create_metrics(&json);
                    self.name = json.name;
                    self.extends = json.extends;
                    self.date = json.date;
                    self.signature = json.signature;
                    self.metrics = metrics;

                    // Success
                    status = UpdateStatus::Updated;
                } else {
                    // Only warn this can happen if the device is offline
                    warn!("Model transfer failed with status: {:?}", res.status());
                }
            }
            Err(err) => {
                // Only warn this can happen if the device is offline
                warn!("Model transfer failed: {:?}", err);
            }
        }

        Ok(status)
    }
}
