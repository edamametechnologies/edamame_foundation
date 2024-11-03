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
}

/// A generic model for handling cloud-based data fetching and updating.
#[derive(Debug, Clone)]
pub struct CloudModel<T: CloudSignature + Send + Sync + 'static> {
    pub data: Arc<CustomRwLock<T>>,
    file_name: String,
}

impl<T> CloudModel<T>
where
    T: CloudSignature + Send + Sync + 'static,
{
    /// Initializes the CloudModel with built-in data.
    pub fn initialize<F>(file_name: String, builtin: &'static str, parser: F) -> Result<Self>
    where
        F: Fn(&str) -> Result<T>,
    {
        let data = parser(builtin)
            .with_context(|| format!("Failed to parse built-in data for file: {}", file_name))?;

        Ok(Self {
            data: Arc::new(CustomRwLock::new(data)),
            file_name,
        })
    }

    /// Overwrites the current data with test data (useful for testing).
    pub async fn overwrite_with_test_data(&self, data: T) {
        *self.data.write().await = data;
    }

    /// Constructs the URL to fetch the signature file.
    pub fn get_sig_url(branch: &str, file_name: &str) -> String {
        // Remove the .json from the file name
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
    pub async fn needs_update(&self, branch: &str) -> Result<bool> {
        let sig_url = Self::get_sig_url(branch, &self.file_name);

        // Build the client
        let client = Client::builder()
            .gzip(true)
            .timeout(TIMEOUT)
            .build()
            .context("Failed to build reqwest client")?;

        // Fetch the signature
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

        // Get current signature
        let current_signature = {
            let data = self.data.read().await;
            data.get_signature()
        };

        Ok(new_signature != current_signature)
    }

    /// Updates the data if a new version is available or if forced.
    pub async fn update<F>(&self, branch: &str, force: bool, parser: F) -> Result<UpdateStatus>
    where
        F: Fn(&str) -> Result<T>,
    {
        info!(
            "Starting update for file: '{}' on branch: '{}'",
            self.file_name, branch
        );

        // Build the client
        let client = Client::builder()
            .gzip(true)
            .timeout(TIMEOUT)
            .build()
            .context("Failed to build reqwest client")?;

        let sig_url = Self::get_sig_url(branch, &self.file_name);

        // Fetch the signature
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

        // Get current signature
        let current_signature = {
            let data = self.data.read().await;
            data.get_signature()
        };

        let needs_update = current_signature != new_signature;

        // Check if update is needed
        if !needs_update && !force {
            info!(
                "No update required for file: '{}'. Signatures match.",
                self.file_name
            );
            return Ok(UpdateStatus::NotUpdated);
        }

        // Fetch new data
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
