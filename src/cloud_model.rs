use crate::rwlock::CustomRwLock;
use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info, trace};

const BASE_URL: &str = "https://raw.githubusercontent.com/edamametechnologies/threatmodels";
static TIMEOUT: Duration = Duration::from_secs(120);

pub trait CloudSignature {
    fn get_signature(&self) -> String;
    fn set_signature(&mut self, signature: String);
}

/// Represents the status of an update operation.
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateStatus {
    Updated,
    NotUpdated,
    FormatError,
    SkippedCustom,
}

/// A generic model for handling cloud-based data fetching and updating.
#[derive(Debug, Clone)]
pub struct CloudModel<T: CloudSignature + Send + Sync + 'static> {
    pub data: Arc<CustomRwLock<T>>,
    file_name: String,
    is_custom: Arc<CustomRwLock<bool>>,
    builtin_data: Arc<T>,
}

impl<T> CloudModel<T>
where
    T: CloudSignature + Send + Sync + Clone + 'static,
{
    /// Initializes the CloudModel with built-in data.
    pub fn initialize<F>(file_name: String, builtin: &'static str, parser: F) -> Result<Self>
    where
        F: Fn(&str) -> Result<T>,
    {
        let initial_data = parser(builtin)
            .with_context(|| format!("Failed to parse built-in data for file: {}", file_name))?;

        let builtin_data = Arc::new(initial_data.clone());

        Ok(Self {
            data: Arc::new(CustomRwLock::new(initial_data)),
            file_name,
            is_custom: Arc::new(CustomRwLock::new(false)),
            builtin_data,
        })
    }

    /// Sets custom data, replacing the current data.
    pub async fn set_custom_data(&self, data: T) {
        *self.data.write().await = data;
        *self.is_custom.write().await = true;
        info!(
            "Set custom data for file: '{}'. Updates will be skipped.",
            self.file_name
        );
    }

    /// Resets the data to the original built-in data.
    pub async fn reset_to_default(&self) {
        if *self.is_custom.read().await {
            *self.data.write().await = (*self.builtin_data).clone();
            *self.is_custom.write().await = false;
            info!(
                "Reset data to default for file: '{}'. Updates are now enabled.",
                self.file_name
            );
        } else {
            info!(
                "Data for file '{}' is already default. No reset needed.",
                self.file_name
            );
        }
    }

    /// Checks if the model is currently using custom data.
    pub async fn is_custom(&self) -> bool {
        *self.is_custom.read().await
    }

    /// Overwrites the current data with test data (useful for testing).
    /// This marks the data as custom.
    pub async fn overwrite_with_test_data(&self, data: T) {
        *self.data.write().await = data;
        *self.is_custom.write().await = true;
        info!(
            "Overwrote with test data for file: '{}'. Marked as custom.",
            self.file_name
        );
    }

    /// Constructs the URL to fetch the signature file.
    pub fn get_sig_url(branch: &str, file_name: &str) -> String {
        let file_name = file_name.replace(".json", "");
        format!("{}/{}/{}.sig", BASE_URL, branch, file_name)
    }

    /// Constructs the URL to fetch the data file.
    pub fn get_data_url(branch: &str, file_name: &str) -> String {
        format!("{}/{}/{}", BASE_URL, branch, file_name)
    }

    /// Retrieves the current signature from the data.
    pub async fn get_signature(&self) -> String {
        let data = self.data.read().await;
        data.get_signature()
    }

    /// Sets a new signature in the data.
    pub async fn set_signature(&self, signature: String) {
        let mut data = self.data.write().await;
        data.set_signature(signature);
    }

    /// Determines if an update is needed by comparing the current signature with the remote one.
    /// Returns `Ok(false)` if the model is using custom data.
    pub async fn needs_update(&self, branch: &str) -> Result<bool> {
        if *self.is_custom.read().await {
            trace!(
                "Skipping needs_update check for '{}' because custom data is active.",
                self.file_name
            );
            return Ok(false);
        }

        let sig_url = Self::get_sig_url(branch, &self.file_name);

        let client = Client::builder()
            .gzip(true)
            .timeout(TIMEOUT)
            .build()
            .context("Failed to build reqwest client")?;

        let sig_response = client
            .get(&sig_url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch signature from: {}", sig_url))?;

        if !sig_response.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch signature from: {}. HTTP Status: {}",
                sig_url,
                sig_response.status()
            ));
        }

        let new_signature = sig_response
            .text()
            .await
            .with_context(|| format!("Failed to read signature text from response: {}", sig_url))?;

        trace!("Fetched new signature: {}", new_signature);

        let current_signature = {
            let data = self.data.read().await;
            data.get_signature()
        };

        Ok(new_signature != current_signature)
    }

    /// Updates the data if a new version is available or if forced.
    /// Skips the update if the model is currently using custom data, unless `force` is true.
    pub async fn update<F>(&self, branch: &str, force: bool, parser: F) -> Result<UpdateStatus>
    where
        F: Fn(&str) -> Result<T>,
    {
        if *self.is_custom.read().await && !force {
            info!(
                "Skipping update for file: '{}' on branch: '{}' because custom data is active and force=false.",
                self.file_name, branch
            );
            return Ok(UpdateStatus::SkippedCustom);
        }

        if *self.is_custom.read().await && force {
            info!(
                "Forcing update for file: '{}'. Resetting to default first.",
                self.file_name
            );
            self.reset_to_default().await;
        }

        info!(
            "Starting update check for file: '{}' on branch: '{}'",
            self.file_name, branch
        );

        let client = Client::builder()
            .gzip(true)
            .timeout(TIMEOUT)
            .build()
            .context("Failed to build reqwest client")?;

        let sig_url = Self::get_sig_url(branch, &self.file_name);

        let sig_response = client
            .get(&sig_url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch signature from: {}", sig_url))?;

        if !sig_response.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch signature from: {}. HTTP Status: {}",
                sig_url,
                sig_response.status()
            ));
        }

        let new_signature = sig_response
            .text()
            .await
            .with_context(|| format!("Failed to read signature text from response: {}", sig_url))?;

        trace!("Fetched new signature: {}", new_signature);

        let current_signature = {
            let data = self.data.read().await;
            data.get_signature()
        };

        let needs_update = current_signature != new_signature;

        if !needs_update && !force {
            info!(
                "No update required for file: '{}'. Signatures match.",
                self.file_name
            );
            return Ok(UpdateStatus::NotUpdated);
        }

        let data_url = Self::get_data_url(branch, &self.file_name);
        trace!("Fetching data from URL: {}", data_url);

        let response = client
            .get(&data_url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch data from: {}", data_url))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch data from: {}. HTTP Status: {}",
                data_url,
                response.status()
            ));
        }

        let json_text = response
            .text()
            .await
            .with_context(|| format!("Failed to read response text from: {}", data_url))?;

        trace!("Received JSON data: {}", json_text);

        match parser(&json_text) {
            Ok(mut new_data) => {
                new_data.set_signature(new_signature);
                let mut data = self.data.write().await;
                *data = new_data;
                info!("Successfully updated file: '{}'", self.file_name);
                Ok(UpdateStatus::Updated)
            }
            Err(err) => {
                error!(
                    "Failed to decode JSON data for file: '{}'. Error: {:?}",
                    self.file_name, err
                );
                Ok(UpdateStatus::FormatError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use serial_test::serial; // Using serial_test just in case network tests interfere

    // Helper struct for testing CloudModel
    #[derive(Debug, Clone, PartialEq)]
    struct TestData {
        content: String,
        signature: String,
    }

    impl CloudSignature for TestData {
        fn get_signature(&self) -> String {
            self.signature.clone()
        }
        fn set_signature(&mut self, signature: String) {
            self.signature = signature;
        }
    }

    // Simple parser for test data (format: "content,signature")
    fn test_parser(data: &str) -> Result<TestData> {
        let parts: Vec<&str> = data.split(',').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid test data format"));
        }
        Ok(TestData {
            content: parts[0].to_string(),
            signature: parts[1].to_string(),
        })
    }

    const TEST_BUILTIN: &str = "builtin_content,builtin_sig";
    const TEST_FILE_NAME: &str = "test_model.json";

    #[tokio::test]
    #[serial]
    async fn test_initialize_and_defaults() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let data = model.data.read().await;
        assert_eq!(data.content, "builtin_content");
        assert_eq!(data.signature, "builtin_sig");
        assert!(!model.is_custom().await, "Model should not be custom initially");
    }

    #[tokio::test]
    #[serial]
    async fn test_set_custom_data() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let custom_data = TestData {
            content: "custom_content".to_string(),
            signature: "custom_sig".to_string(),
        };

        model.set_custom_data(custom_data.clone()).await;

        let data = model.data.read().await;
        assert_eq!(data.content, "custom_content");
        assert_eq!(data.signature, "custom_sig");
        assert!(model.is_custom().await, "Model should be custom after setting custom data");
    }

    #[tokio::test]
    #[serial]
    async fn test_reset_to_default() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let custom_data = TestData {
            content: "custom_content".to_string(),
            signature: "custom_sig".to_string(),
        };

        // Set custom data first
        model.set_custom_data(custom_data).await;
        assert!(model.is_custom().await, "Model should be custom initially in this test");

        // Reset to default
        model.reset_to_default().await;

        let data = model.data.read().await;
        assert_eq!(data.content, "builtin_content");
        assert_eq!(data.signature, "builtin_sig");
        assert!(!model.is_custom().await, "Model should not be custom after reset");

        // Test resetting when already default
        let initial_sig = data.signature.clone();
        drop(data); // Release read lock
        model.reset_to_default().await; // Should do nothing
        let data_after_reset = model.data.read().await;
        assert_eq!(data_after_reset.signature, initial_sig, "Resetting default should not change data");
        assert!(!model.is_custom().await, "Model should still not be custom");
    }

    #[tokio::test]
    #[serial]
    async fn test_update_skipped_custom() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let custom_data = TestData {
            content: "custom_content".to_string(),
            signature: "custom_sig".to_string(),
        };
        model.set_custom_data(custom_data.clone()).await;

        // Attempt update without force
        let update_status = model.update("main", false, test_parser).await.unwrap();

        assert_eq!(update_status, UpdateStatus::SkippedCustom, "Update should be skipped for custom data without force");

        // Verify data hasn't changed
        let data = model.data.read().await;
        assert_eq!(data.content, "custom_content"); // Should still be custom
    }

    // Note: Testing force update requires a mock HTTP server or careful setup.
    // This test checks the logic flow but doesn't verify the actual network update part.
    #[tokio::test]
    #[serial]
    async fn test_update_force_custom_flow() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let custom_data = TestData {
            content: "custom_content".to_string(),
            signature: "custom_sig".to_string(),
        };
        model.set_custom_data(custom_data.clone()).await;

        // Attempt update *with* force. We expect it to fail because the URLs are invalid,
        // but the key is that it should *attempt* the update after resetting.
        let update_result = model.update("main", true, test_parser).await;

        assert!(update_result.is_err(), "Update should fail due to network error, but it attempted");

        // Verify model was reset to default *before* the failed update attempt
        assert!(!model.is_custom().await, "Model should have been reset to default during forced update");
        let data = model.data.read().await;
        assert_eq!(data.content, "builtin_content"); // Should be reset
    }

    #[tokio::test]
    #[serial]
    async fn test_needs_update_custom() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let custom_data = TestData {
            content: "custom_content".to_string(),
            signature: "custom_sig".to_string(),
        };
        model.set_custom_data(custom_data).await;

        // needs_update should return Ok(false) when custom data is set
        let needs_update_result = model.needs_update("main").await;
        assert!(needs_update_result.is_ok(), "needs_update should succeed");
        assert_eq!(needs_update_result.unwrap(), false, "needs_update should return false for custom data");
    }
}
