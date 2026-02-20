use crate::threat::*;
use crate::threat_metrics_android::*;
use crate::threat_metrics_ios::*;
use crate::threat_metrics_linux::*;
use crate::threat_metrics_macos::*;
use crate::threat_metrics_windows::*;
use anyhow::{anyhow, Context, Result};
use lazy_static::lazy_static;
use threatmodels_rs::*;
use tracing::{info, warn};

// Constants for model names and built-in data
pub const THREAT_MODEL_MACOS: &str = "threatmodel-macOS.json";
pub const THREAT_MODEL_WINDOWS: &str = "threatmodel-Windows.json";
pub const THREAT_MODEL_IOS: &str = "threatmodel-iOS.json";
pub const THREAT_MODEL_ANDROID: &str = "threatmodel-Android.json";
pub const THREAT_MODEL_LINUX: &str = "threatmodel-Linux.json";

fn get_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(target_os = "android") {
        "android"
    } else {
        "linux"
    }
}

lazy_static! {
    // Global THREATS variable using CloudModel and a custom RwLock
    pub static ref THREATS: CloudModel<ThreatMetrics> = {
        // Determine the built-in data and model name
        let builtin_data = get_builtin_version(get_platform()).expect("Unsupported platform");
        let model_name = get_model_name(get_platform()).expect("Unsupported platform");

        // Initialize the CloudModel with the built-in data
        let model = CloudModel::initialize(
            model_name.to_string(),
            builtin_data,
            |data| {
                let threat_metrics_json: ThreatMetricsJSON = serde_json::from_str(data)
                    .with_context(|| "Failed to parse JSON data")?;
                ThreatMetrics::new_from_json(&threat_metrics_json, get_platform())
            },
        )
        .expect("Failed to initialize CloudModel");

        model
    };
}

// Helper functions to get built-in versions and model names
pub fn get_builtin_version(platform: &str) -> Result<&'static str> {
    match platform.to_lowercase().as_str() {
        "macos" => Ok(THREAT_METRICS_MACOS),
        "windows" => Ok(THREAT_METRICS_WINDOWS),
        "ios" => Ok(THREAT_METRICS_IOS),
        "android" => Ok(THREAT_METRICS_ANDROID),
        "linux" => Ok(THREAT_METRICS_LINUX),
        _ => Err(anyhow!("Unsupported platform: {}", platform)),
    }
}

pub fn get_model_name(platform: &str) -> Result<&'static str> {
    // If set to autodetect
    let platform = if platform == "" {
        get_platform()
    } else {
        platform
    };

    match platform.to_lowercase().as_str() {
        "macos" => Ok(THREAT_MODEL_MACOS),
        "windows" => Ok(THREAT_MODEL_WINDOWS),
        "ios" => Ok(THREAT_MODEL_IOS),
        "android" => Ok(THREAT_MODEL_ANDROID),
        "linux" => Ok(THREAT_MODEL_LINUX),
        _ => Err(anyhow!("Unsupported platform: {}", platform)),
    }
}

impl ThreatMetrics {
    pub async fn get_threats_url(platform: &str, branch: &str) -> Result<String> {
        let model_name = get_model_name(platform)?;
        let url = CloudModel::<ThreatMetrics>::get_data_url(branch, &model_name);
        Ok(url)
    }

    pub fn new_from_json(json: &ThreatMetricsJSON, platform: &str) -> Result<Self> {
        info!(
            "Loading threat metrics from JSON for platform: {}",
            platform
        );

        let mut metrics = Vec::new();

        for metric_json in &json.metrics {
            let metric = ThreatMetric {
                metric: metric_json.clone(),
                timestamp: "".to_string(),
                status: ThreatStatus::Unknown,
                output: "".to_string(),
            };
            metrics.push(metric);
        }

        info!("Loaded {} threat metrics", metrics.len());

        Ok(ThreatMetrics {
            metrics,
            name: json.name.clone(),
            extends: json.extends.clone(),
            date: json.date.clone(),
            signature: json.signature.clone(),
        })
    }
}

impl CloudSignature for ThreatMetrics {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

impl ThreatMetricImplementationJSON {
    /// Creates a new ThreatMetricImplementationJSON instance with default values.
    pub fn new() -> Self {
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

// Allow to force the platform
pub async fn update(branch: &str, force: bool, platform: &str) -> Result<UpdateStatus> {
    let platform = if platform == "" {
        get_platform()
    } else {
        platform
    };
    info!(
        "Starting threat metrics update for platform '{}' from branch '{}'",
        platform, branch
    );

    // Access the model directly now
    // Perform the update with automatic date validation via CloudDate trait
    let status = THREATS
        .update_with_date_check(branch, force, |data| {
            let threat_metrics_json: ThreatMetricsJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            ThreatMetrics::new_from_json(&threat_metrics_json, get_platform())
        })
        .await?;

    match status {
        UpdateStatus::SkippedCustom => {
            info!("Threat metrics were skipped because custom data is in use.")
        }
        UpdateStatus::Updated => info!("Threat metrics were successfully updated."),
        UpdateStatus::NotUpdated => info!("Threat metrics are already up to date."),
        UpdateStatus::FormatError => {
            warn!("There was a format error in the threat metrics data.")
        }
    }

    Ok(status)
}

pub async fn get_threat_metrics() -> ThreatMetrics {
    THREATS.data.read().await.clone()
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // Initialize logging or other necessary setup here
    fn setup() {
        // Setup code here if needed
    }

    #[tokio::test]
    #[serial]
    async fn test_builtin_version() {
        setup();
        let builtin = THREATS.clone();
        assert!(
            !builtin.get_signature().await.is_empty(),
            "Signature should not be empty"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_update_threat_metrics() {
        setup();
        let branch = "main";
        let status = update(branch, false, "").await.expect("Update failed");
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::NotUpdated),
            "Update status should be one of the expected variants"
        );
    }

    // Forced update
    #[tokio::test]
    #[serial]
    async fn test_forced_update_threat_metrics() {
        setup();
        let branch = "main";

        // Run the update
        let status = update(branch, true, "").await.expect("Update failed");
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::NotUpdated),
            "Update status should be one of the expected variants"
        );
    }

    // New test: Modify the signature to zeros, perform an update, and check the signature changes
    // Note: This test might return NotUpdated if the remote model has an older date than built-in,
    // which is correct behavior due to date validation.
    #[tokio::test]
    #[serial]
    async fn test_signature_update_after_modification() {
        setup();
        let branch = "main";

        // Acquire a write lock to modify the signature
        {
            THREATS
                .set_signature("00000000000000000000000000000000".to_string())
                .await;
        }

        // Perform the update
        let status = update(branch, false, "").await.expect("Update failed");

        // Check that the update was performed OR rejected due to date validation
        // Both are valid outcomes - Updated means remote is newer, NotUpdated means rejected due to older date
        assert!(
            matches!(status, UpdateStatus::Updated | UpdateStatus::NotUpdated),
            "Expected the update to be performed or rejected due to date validation, got: {:?}",
            status
        );

        // If update was performed, signature should have changed
        // If update was rejected (NotUpdated due to older date), signature might be restored to builtin
        let current_signature = THREATS.get_signature().await;

        if status == UpdateStatus::Updated {
            assert_ne!(
                current_signature, "00000000000000000000000000000000",
                "Signature should have been updated when update succeeds"
            );
        }

        assert!(
            !current_signature.is_empty(),
            "Signature should not be empty after update attempt"
        );
    }

    // Additional test: Ensure that an invalid update does not change the signature
    #[tokio::test]
    #[serial]
    async fn test_invalid_update_does_not_change_signature() {
        setup();
        let branch = "nonexistent-branch";

        // Get the current signature
        let original_signature = THREATS.get_signature().await;

        // Attempt to perform an update from a nonexistent branch
        let result = update(branch, false, "").await;

        // The update should fail
        assert!(result.is_err(), "Update should have failed");

        // Check that the signature has not changed
        let current_signature = THREATS.get_signature().await;
        assert_eq!(
            current_signature, original_signature,
            "Signature should not have changed after failed update"
        );
    }

    #[tokio::test]
    async fn test_platform() {
        let builtin_data = get_builtin_version("macOS").expect("Unsupported platform");
        let threat_metrics_json: ThreatMetricsJSON = serde_json::from_str(builtin_data)
            .unwrap_or_else(|e| {
                panic!("Failed to parse JSON data: {}", e);
            });
        let threat_metrics = ThreatMetrics::new_from_json(&threat_metrics_json, "macOS")
            .unwrap_or_else(|e| {
                panic!("Failed to create ThreatMetrics: {}", e);
            });

        assert!(threat_metrics.metrics.len() > 0);

        let model_name = get_model_name("macOS").expect("Unsupported platform");
        assert!(
            model_name == THREAT_MODEL_MACOS,
            "Model name {} should be {}",
            model_name,
            THREAT_MODEL_MACOS
        );
    }
}
