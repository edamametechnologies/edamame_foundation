use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use threatmodels_rs::*;
use tracing::{info, warn};

use crate::cve_detection_params_db::CVE_DETECTION_PARAMS_DB;

const CVE_PARAMS_NAME: &str = "cve-detection-params-db.json";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckMetadata {
    pub severity: String,
    pub description: String,
    pub reference: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CveDetectionParamsJSON {
    pub date: String,
    pub signature: String,
    pub checks: HashMap<String, CheckMetadata>,
    #[serde(default = "default_credential_harvest_min_labels")]
    pub credential_harvest_min_labels: usize,
    pub generic_reuse_tokens: Vec<String>,
    pub generic_application_tokens: Vec<String>,
    pub init_process_names: Vec<String>,
    pub suspicious_parent_path_patterns: Vec<String>,
    #[serde(default = "default_fim_hash_size_threshold")]
    pub fim_hash_size_threshold: u64,
    #[serde(default)]
    pub fim_temp_executable_patterns: Vec<String>,
}

fn default_credential_harvest_min_labels() -> usize {
    3
}

fn default_fim_hash_size_threshold() -> u64 {
    10_485_760
}

#[derive(Clone)]
pub struct CveDetectionParams {
    pub date: String,
    pub signature: String,
    pub checks: HashMap<String, CheckMetadata>,
    pub credential_harvest_min_labels: usize,
    pub generic_reuse_tokens: HashSet<String>,
    pub generic_application_tokens: HashSet<String>,
    pub init_process_names: HashSet<String>,
    pub suspicious_parent_path_patterns: Vec<String>,
    pub fim_hash_size_threshold: u64,
    pub fim_temp_executable_patterns: Vec<String>,
}

impl CloudSignature for CveDetectionParams {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

impl CveDetectionParams {
    pub fn new_from_json(json: &CveDetectionParamsJSON) -> Self {
        info!(
            "Loading CVE detection params: {} checks, {} reuse tokens, {} app tokens",
            json.checks.len(),
            json.generic_reuse_tokens.len(),
            json.generic_application_tokens.len()
        );

        CveDetectionParams {
            date: json.date.clone(),
            signature: json.signature.clone(),
            checks: json.checks.clone(),
            credential_harvest_min_labels: json.credential_harvest_min_labels,
            generic_reuse_tokens: json.generic_reuse_tokens.iter().cloned().collect(),
            generic_application_tokens: json.generic_application_tokens.iter().cloned().collect(),
            init_process_names: json.init_process_names.iter().cloned().collect(),
            suspicious_parent_path_patterns: json.suspicious_parent_path_patterns.clone(),
            fim_hash_size_threshold: json.fim_hash_size_threshold,
            fim_temp_executable_patterns: json.fim_temp_executable_patterns.clone(),
        }
    }

    pub fn check_metadata(&self, check_name: &str) -> Option<&CheckMetadata> {
        self.checks.get(check_name)
    }
}

fn build_fallback_params() -> CveDetectionParams {
    let json: CveDetectionParamsJSON = serde_json::from_str(CVE_DETECTION_PARAMS_DB)
        .expect("Built-in cve-detection-params-db.json must be valid");
    CveDetectionParams::new_from_json(&json)
}

lazy_static! {
    pub static ref CVE_PARAMS: CloudModel<CveDetectionParams> = {
        let model = CloudModel::initialize(
            CVE_PARAMS_NAME.to_string(),
            CVE_DETECTION_PARAMS_DB,
            |data| {
                let json: CveDetectionParamsJSON = serde_json::from_str(data)
                    .with_context(|| "Failed to parse CVE params JSON")?;
                Ok(CveDetectionParams::new_from_json(&json))
            },
        );
        match model {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "FATAL: Failed to initialize CloudModel for CVE detection params: {:?}",
                    e
                );
                panic!(
                    "Failed to initialize CloudModel for CVE detection params: {:?}",
                    e
                );
            }
        }
    };
    static ref PARAMS_SNAPSHOT: ArcSwap<CveDetectionParams> =
        ArcSwap::from_pointee(build_fallback_params());
}

async fn refresh_params_snapshot() {
    let db = CVE_PARAMS.data.read().await;
    PARAMS_SNAPSHOT.store(Arc::new(db.clone()));
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting CVE detection params update from backend");

    let status = CVE_PARAMS
        .update(branch, force, |data| {
            let json: CveDetectionParamsJSON = serde_json::from_str(data)?;
            Ok(CveDetectionParams::new_from_json(&json))
        })
        .await?;

    match status {
        UpdateStatus::Updated => {
            info!("CVE detection params were successfully updated.");
            refresh_params_snapshot().await;
        }
        UpdateStatus::NotUpdated => info!("CVE detection params are already up to date."),
        UpdateStatus::FormatError => {
            warn!("There was a format error in the CVE detection params data.")
        }
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom CVE detection params are in use.")
        }
    }

    Ok(status)
}

pub fn params() -> Arc<CveDetectionParams> {
    PARAMS_SNAPSHOT.load().clone()
}

pub fn is_generic_reuse_token(token: &str) -> bool {
    PARAMS_SNAPSHOT.load().generic_reuse_tokens.contains(token)
}

pub fn is_generic_application_token(token: &str) -> bool {
    PARAMS_SNAPSHOT
        .load()
        .generic_application_tokens
        .contains(token)
}

pub fn is_init_process(name: &str) -> bool {
    PARAMS_SNAPSHOT.load().init_process_names.contains(name)
}

pub fn suspicious_parent_path_patterns() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .suspicious_parent_path_patterns
        .clone()
}

pub fn fim_hash_size_threshold() -> u64 {
    PARAMS_SNAPSHOT.load().fim_hash_size_threshold
}

pub fn fim_temp_executable_patterns() -> Vec<String> {
    PARAMS_SNAPSHOT.load().fim_temp_executable_patterns.clone()
}

pub fn check_severity(check_name: &str, fallback: &str) -> String {
    PARAMS_SNAPSHOT
        .load()
        .check_metadata(check_name)
        .map(|m| m.severity.clone())
        .unwrap_or_else(|| fallback.to_string())
}

pub fn check_description(check_name: &str, fallback: &str) -> String {
    PARAMS_SNAPSHOT
        .load()
        .check_metadata(check_name)
        .map(|m| m.description.clone())
        .unwrap_or_else(|| fallback.to_string())
}

pub fn check_reference(check_name: &str, fallback: &str) -> String {
    PARAMS_SNAPSHOT
        .load()
        .check_metadata(check_name)
        .map(|m| m.reference.clone())
        .unwrap_or_else(|| fallback.to_string())
}

pub fn credential_harvest_min_labels() -> usize {
    PARAMS_SNAPSHOT.load().credential_harvest_min_labels
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_params_loaded() {
        let p = params();
        assert!(!p.checks.is_empty());
        assert!(!p.generic_reuse_tokens.is_empty());
        assert!(!p.generic_application_tokens.is_empty());
    }

    #[test]
    fn test_generic_reuse_token_lookup() {
        assert!(is_generic_reuse_token("app"));
        assert!(is_generic_reuse_token("cache"));
        assert!(!is_generic_reuse_token("python3"));
    }

    #[test]
    fn test_generic_application_token_lookup() {
        assert!(is_generic_application_token("helper"));
        assert!(is_generic_application_token("resources"));
        assert!(!is_generic_application_token("chrome"));
    }

    #[test]
    fn test_init_process_lookup() {
        assert!(is_init_process("launchd"));
        assert!(is_init_process("systemd"));
        assert!(!is_init_process("python3"));
    }

    #[test]
    fn test_fim_hash_size_threshold_defaults() {
        assert_eq!(fim_hash_size_threshold(), 10_485_760);
    }

    #[test]
    fn test_fim_temp_executable_patterns_defaults() {
        assert_eq!(
            fim_temp_executable_patterns(),
            vec![
                "/tmp/".to_string(),
                "/var/tmp/".to_string(),
                "\\Temp\\".to_string(),
                "\\AppData\\Local\\Temp\\".to_string(),
            ]
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_update_runs() {
        let status = update("main", false).await.expect("Update failed");
        assert!(matches!(
            status,
            UpdateStatus::Updated
                | UpdateStatus::NotUpdated
                | UpdateStatus::SkippedCustom
                | UpdateStatus::FormatError
        ));
    }
}
