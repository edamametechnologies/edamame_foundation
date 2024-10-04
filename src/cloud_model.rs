use anyhow::{Context, Result};
use reqwest::Client;
use tokio::time::Duration;
use tracing::{error, info, trace, warn};

const BASE_URL: &str = "https://raw.githubusercontent.com/edamametechnologies/threatmodels";

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
    pub data: T,
    file_name: String,
}

impl<T> CloudModel<T>
where
    T: CloudSignature + Send + Sync + 'static,
{
    pub fn initialize<F>(file_name: String, builtin: &'static str, parser: F) -> Result<Self>
    where
        F: Fn(&str) -> Result<T>,
    {
        let data = parser(builtin)
            .with_context(|| format!("Failed to parse built-in data for file: {}", file_name))?;

        Ok(Self { data, file_name })
    }

    pub fn get_sig_url(branch: &str, file_name: &str) -> String {
        // Remove the .json from the file name
        let file_name = file_name.replace(".json", "");
        format!("{}/{}/{}.sig", BASE_URL, branch, file_name)
    }

    pub fn get_data_url(branch: &str, file_name: &str) -> String {
        format!("{}/{}/{}", BASE_URL, branch, file_name)
    }

    pub fn get_signature(&self) -> String {
        self.data.get_signature()
    }

    pub fn set_signature(&mut self, signature: String) {
        self.data.set_signature(signature);
    }

    pub async fn update<F>(&mut self, branch: &str, parser: F) -> Result<UpdateStatus>
    where
        F: Fn(&str) -> Result<T>,
    {
        info!(
            "Starting update for file: '{}' on branch: '{}'",
            self.file_name, branch
        );

        let client = Client::builder()
            .gzip(true)
            .timeout(Duration::from_secs(120))
            .build()
            .context("Failed to build reqwest client")?;

        let sig_url = Self::get_sig_url(branch, &self.file_name);
        trace!("Fetching signature from URL: {}", sig_url);

        let new_signature = client
            .get(&sig_url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch signature from: {}", sig_url))?
            .text()
            .await
            .with_context(|| format!("Failed to read signature text from response: {}", sig_url))?;

        trace!("Fetched new signature: {}", new_signature);

        if new_signature == self.data.get_signature() {
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

        if response.status().is_success() {
            let json_text = response
                .text()
                .await
                .with_context(|| format!("Failed to read response text from: {}", data_url))?;
            trace!("Received JSON data: {}", json_text);

            match parser(&json_text) {
                Ok(new_data) => {
                    self.data = new_data;
                    self.data.set_signature(new_signature);
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
        } else {
            warn!(
                "Failed to fetch data from URL: '{}'. HTTP Status: {:?}",
                data_url,
                response.status()
            );
            Ok(UpdateStatus::NotUpdated)
        }
    }
}
