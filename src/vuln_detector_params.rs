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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PlatformStringLists {
    pub macos: Vec<String>,
    pub linux: Vec<String>,
    pub windows: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HelperMatcherConfig {
    pub exact_paths: Vec<String>,
    pub path_contains: Vec<String>,
    pub path_starts_with: Vec<String>,
    pub path_ends_with: Vec<String>,
    pub compact_names: Vec<String>,
    pub compact_leaf_names: Vec<String>,
    pub leaf_trusted_dir_prefixes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PlatformHelperMatcherConfigs {
    #[serde(default = "default_generic_git_credential_helper")]
    pub generic_git: HelperMatcherConfig,
    #[serde(default = "default_macos_credential_helper")]
    pub macos: HelperMatcherConfig,
    #[serde(default = "default_linux_credential_helper")]
    pub linux: HelperMatcherConfig,
    #[serde(default = "default_windows_credential_helper")]
    pub windows: HelperMatcherConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CveDetectionParamsJSON {
    pub date: String,
    pub signature: String,
    pub checks: HashMap<String, CheckMetadata>,
    #[serde(default = "default_credential_harvest_min_labels")]
    pub credential_harvest_min_labels: usize,
    pub secret_content_scan_max_bytes: u64,
    pub secret_content_min_hits: usize,
    pub recent_sensitive_open_file_ttl_secs: u64,
    pub generic_reuse_tokens: Vec<String>,
    pub generic_application_tokens: Vec<String>,
    pub init_process_names: Vec<String>,
    #[serde(default = "default_ci_runner_process_name_prefixes")]
    pub ci_runner_process_name_prefixes: Vec<String>,
    pub suspicious_parent_path_patterns: Vec<String>,
    #[serde(default = "default_benign_temp_artifact_suffixes")]
    pub benign_temp_artifact_suffixes: Vec<String>,
    #[serde(default = "default_application_storage_patterns")]
    pub application_storage_patterns: Vec<String>,
    #[serde(default = "default_credential_store_patterns")]
    pub credential_store_patterns: PlatformStringLists,
    #[serde(default = "default_trusted_credential_helpers")]
    pub trusted_credential_helpers: PlatformHelperMatcherConfigs,
    #[serde(default = "default_packaged_application_contains_patterns")]
    pub packaged_application_contains_patterns: Vec<String>,
    #[serde(default = "default_packaged_application_starts_with_patterns")]
    pub packaged_application_starts_with_patterns: Vec<String>,
    #[serde(default = "default_packaged_application_ends_with_patterns")]
    pub packaged_application_ends_with_patterns: Vec<String>,
    #[serde(default = "default_fim_hash_size_threshold")]
    pub fim_hash_size_threshold: u64,
    pub fim_temp_executable_patterns: Vec<String>,
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn platform_string_lists(macos: &[&str], linux: &[&str], windows: &[&str]) -> PlatformStringLists {
    PlatformStringLists {
        macos: strings(macos),
        linux: strings(linux),
        windows: strings(windows),
    }
}

fn helper_matcher_config(
    exact_paths: &[&str],
    path_contains: &[&str],
    path_starts_with: &[&str],
    path_ends_with: &[&str],
    compact_names: &[&str],
    compact_leaf_names: &[&str],
    leaf_trusted_dir_prefixes: &[&str],
) -> HelperMatcherConfig {
    HelperMatcherConfig {
        exact_paths: strings(exact_paths),
        path_contains: strings(path_contains),
        path_starts_with: strings(path_starts_with),
        path_ends_with: strings(path_ends_with),
        compact_names: strings(compact_names),
        compact_leaf_names: strings(compact_leaf_names),
        leaf_trusted_dir_prefixes: strings(leaf_trusted_dir_prefixes),
    }
}

fn default_credential_harvest_min_labels() -> usize {
    3
}

/// CI runner provisioning daemons that legitimately live in /tmp or
/// %TEMP% on ephemeral build hosts. The sandbox_exploitation detector
/// would otherwise flag these as "suspicious parent-process path" with
/// HIGH severity every time a GitHub-hosted runner executes, which is a
/// pure false positive that poisons the pre-release baseline on Linux
/// and Windows.
///
/// These names are documented, public GitHub Actions infrastructure:
///   - `provjobd` (Linux+Windows): the provisioning job daemon that
///     spawns under the hosted-compute-agent / sudo on first run,
///     lives at `/tmp/provjobdNNN` / `%TEMP%\provjobd.exeNNN`.
fn default_ci_runner_process_name_prefixes() -> Vec<String> {
    strings(&["provjobd"])
}

fn default_benign_temp_artifact_suffixes() -> Vec<String> {
    strings(&[
        ".tmp",
        ".temp",
        ".swp",
        ".swo",
        ".part",
        ".partial",
        ".download",
        ".crdownload",
        ".lock",
        ".log",
        ".txt",
        ".json",
        ".cache",
        ".sqlite",
        ".db",
        ".plist",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
    ])
}

fn default_application_storage_patterns() -> Vec<String> {
    strings(&[
        "/library/application support/",
        "/library/containers/",
        "/library/group containers/",
        "/library/keychains/",
        "/library/preferences/",
        "/library/caches/",
        "/library/webkit/",
        "/appdata/roaming/",
        "/appdata/local/",
        "/programdata/",
        "/.config/",
        "/.cache/",
        "/.local/share/",
        "/.local/state/",
    ])
}

fn default_credential_store_patterns() -> PlatformStringLists {
    platform_string_lists(
        &["/library/keychains/"],
        &[
            "/.local/share/keyrings/",
            "/.gnome2/keyrings/",
            "/.local/share/kwalletd/",
            "/.kde/share/apps/kwallet/",
        ],
        &[
            "/appdata/local/microsoft/credentials/",
            "/appdata/roaming/microsoft/credentials/",
            "/appdata/local/microsoft/vault/",
            "/appdata/roaming/microsoft/vault/",
            "/programdata/microsoft/vault/",
        ],
    )
}

fn default_generic_git_credential_helper() -> HelperMatcherConfig {
    helper_matcher_config(
        &[],
        &["/git-credential-manager", "/git-credential-manager-core"],
        &[],
        &[],
        &[
            "gitcredentialmanager",
            "gitcredentialmanagercore",
            "gitcredentialmanagerexe",
            "gitcredentialmanagercoreexe",
        ],
        &[
            "gitcredentialmanager",
            "gitcredentialmanagercore",
            "gitcredentialmanagerexe",
            "gitcredentialmanagercoreexe",
        ],
        &[],
    )
}

fn default_macos_credential_helper() -> HelperMatcherConfig {
    helper_matcher_config(
        &["/usr/bin/security"],
        &[
            "/git-core/git-credential-osxkeychain",
            "/keychain access.app/",
        ],
        &[],
        &["/git-credential-osxkeychain"],
        &[
            "security",
            "gitcredentialosxkeychain",
            "keychainaccess",
            "secd",
            "securityd",
        ],
        &[
            "secd",
            "securityd",
            "assistantd",
            "commcenter",
            "networkserviceproxy",
        ],
        &["/system/library/", "/usr/libexec/"],
    )
}

fn default_linux_credential_helper() -> HelperMatcherConfig {
    helper_matcher_config(
        &[],
        &[
            "/git-core/git-credential-libsecret",
            "/gnome-keyring/gnome-keyring-daemon",
        ],
        &[],
        &[
            "/git-credential-libsecret",
            "/secret-tool",
            "/gnome-keyring-daemon",
        ],
        &[
            "gitcredentiallibsecret",
            "secrettool",
            "gnomekeyringdaemon",
            "kwalletd",
            "kwalletd5",
            "kwalletd6",
            "ksecretsservice",
            "kwalletmanager",
            "kwalletmanager5",
            "kwalletmanager6",
        ],
        &[
            "kwalletd",
            "kwalletd5",
            "kwalletd6",
            "ksecretsservice",
            "kwalletmanager",
            "kwalletmanager5",
            "kwalletmanager6",
        ],
        &["/usr/bin/", "/usr/lib/", "/usr/libexec/"],
    )
}

fn default_windows_credential_helper() -> HelperMatcherConfig {
    helper_matcher_config(
        &[],
        &[],
        &[],
        &[],
        &[
            "cmdkey",
            "cmdkeyexe",
            "vaultcmd",
            "vaultcmdexe",
            "credentialuibroker",
            "credentialuibrokerexe",
            "lsass",
            "lsassexe",
        ],
        &[
            "cmdkeyexe",
            "vaultcmdexe",
            "credentialuibrokerexe",
            "lsassexe",
        ],
        &["/windows/system32/", "/windows/syswow64/"],
    )
}

fn default_trusted_credential_helpers() -> PlatformHelperMatcherConfigs {
    PlatformHelperMatcherConfigs {
        generic_git: default_generic_git_credential_helper(),
        macos: default_macos_credential_helper(),
        linux: default_linux_credential_helper(),
        windows: default_windows_credential_helper(),
    }
}

fn default_packaged_application_contains_patterns() -> Vec<String> {
    strings(&[
        ".app/",
        "/applications/",
        "/program files/",
        "/appdata/local/programs/",
    ])
}

fn default_packaged_application_starts_with_patterns() -> Vec<String> {
    strings(&["/opt/", "/usr/lib/", "/snap/", "/usr/share/"])
}

fn default_packaged_application_ends_with_patterns() -> Vec<String> {
    strings(&[".app"])
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
    pub secret_content_scan_max_bytes: u64,
    pub secret_content_min_hits: usize,
    pub recent_sensitive_open_file_ttl_secs: u64,
    pub generic_reuse_tokens: HashSet<String>,
    pub generic_application_tokens: HashSet<String>,
    pub init_process_names: HashSet<String>,
    pub ci_runner_process_name_prefixes: Vec<String>,
    pub suspicious_parent_path_patterns: Vec<String>,
    pub benign_temp_artifact_suffixes: Vec<String>,
    pub application_storage_patterns: Vec<String>,
    pub credential_store_patterns: PlatformStringLists,
    pub trusted_credential_helpers: PlatformHelperMatcherConfigs,
    pub packaged_application_contains_patterns: Vec<String>,
    pub packaged_application_starts_with_patterns: Vec<String>,
    pub packaged_application_ends_with_patterns: Vec<String>,
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
            secret_content_scan_max_bytes: json.secret_content_scan_max_bytes,
            secret_content_min_hits: json.secret_content_min_hits,
            recent_sensitive_open_file_ttl_secs: json.recent_sensitive_open_file_ttl_secs,
            generic_reuse_tokens: json.generic_reuse_tokens.iter().cloned().collect(),
            generic_application_tokens: json.generic_application_tokens.iter().cloned().collect(),
            init_process_names: json.init_process_names.iter().cloned().collect(),
            ci_runner_process_name_prefixes: json
                .ci_runner_process_name_prefixes
                .iter()
                .map(|prefix| prefix.to_ascii_lowercase())
                .collect(),
            suspicious_parent_path_patterns: json.suspicious_parent_path_patterns.clone(),
            benign_temp_artifact_suffixes: json.benign_temp_artifact_suffixes.clone(),
            application_storage_patterns: json.application_storage_patterns.clone(),
            credential_store_patterns: json.credential_store_patterns.clone(),
            trusted_credential_helpers: json.trusted_credential_helpers.clone(),
            packaged_application_contains_patterns: json
                .packaged_application_contains_patterns
                .clone(),
            packaged_application_starts_with_patterns: json
                .packaged_application_starts_with_patterns
                .clone(),
            packaged_application_ends_with_patterns: json
                .packaged_application_ends_with_patterns
                .clone(),
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

/// Returns true if `name` is a known CI runner provisioning daemon
/// (e.g. GitHub Actions' `provjobd`). The match is a case-insensitive
/// prefix check because these names carry per-run integer suffixes
/// (e.g. `provjobd2003115`, `provjobd.exe1134032012`).
pub fn is_ci_runner_internal_process(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    PARAMS_SNAPSHOT
        .load()
        .ci_runner_process_name_prefixes
        .iter()
        .any(|prefix| !prefix.is_empty() && lower.starts_with(prefix))
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

pub fn secret_content_scan_max_bytes() -> u64 {
    PARAMS_SNAPSHOT.load().secret_content_scan_max_bytes
}

pub fn secret_content_min_hits() -> usize {
    PARAMS_SNAPSHOT.load().secret_content_min_hits
}

pub fn recent_sensitive_open_file_ttl_secs() -> u64 {
    PARAMS_SNAPSHOT.load().recent_sensitive_open_file_ttl_secs
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
    fn test_ci_runner_internal_process_lookup() {
        // GitHub Actions provjobd is named with a per-run numeric suffix,
        // so our allow-list must match on a case-insensitive prefix.
        assert!(is_ci_runner_internal_process("provjobd"));
        assert!(is_ci_runner_internal_process("provjobd2003115"));
        assert!(is_ci_runner_internal_process("provjobd.exe1134032012"));
        assert!(is_ci_runner_internal_process("PROVJOBD.EXE999"));
        // Empty and unrelated names must not be matched.
        assert!(!is_ci_runner_internal_process(""));
        assert!(!is_ci_runner_internal_process("python3"));
        assert!(!is_ci_runner_internal_process("provjo"));
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

    #[test]
    fn test_detector_heuristic_defaults() {
        let p = params();
        assert!(p
            .benign_temp_artifact_suffixes
            .contains(&".json".to_string()));
        assert!(p
            .application_storage_patterns
            .contains(&"/library/keychains/".to_string()));
        assert!(!p
            .suspicious_parent_path_patterns
            .contains(&"/../".to_string()));
        assert!(p
            .trusted_credential_helpers
            .macos
            .compact_leaf_names
            .contains(&"assistantd".to_string()));
        assert!(p
            .packaged_application_contains_patterns
            .contains(&"/applications/".to_string()));
        assert!(p.secret_content_scan_max_bytes >= 16 * 1024);
        assert!(p.secret_content_min_hits >= 1);
        assert!(p.recent_sensitive_open_file_ttl_secs >= 30);
    }

    #[tokio::test]
    #[serial]
    #[ignore] // requires network access to GitHub
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
