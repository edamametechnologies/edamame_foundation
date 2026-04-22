use crate::vuln_detector_params;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretContentFileMatch {
    pub path: String,
    pub secret_labels: Vec<String>,
    pub secret_hits: usize,
    pub script_like: bool,
    pub network_command_like: bool,
}

pub fn inspect_secret_like_file(path: &str) -> Option<SecretContentFileMatch> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return None;
    }
    if metadata.len() > vuln_detector_params::secret_content_scan_max_bytes() {
        return None;
    }

    let bytes = fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }

    let contents = String::from_utf8_lossy(&bytes);
    let normalized = contents.to_ascii_lowercase();
    let mut labels = BTreeSet::new();
    let mut secret_hits = 0usize;

    if normalized.contains("-----begin openssh private key-----")
        || normalized.contains("-----begin rsa private key-----")
        || normalized.contains("-----begin ec private key-----")
        || normalized.contains("-----begin private key-----")
    {
        labels.insert("ssh".to_string());
        secret_hits += 2;
    }

    if normalized.contains("aws_access_key_id")
        || normalized.contains("aws_secret_access_key")
        || normalized.contains("[default]")
    {
        labels.insert("aws".to_string());
        secret_hits += 2;
    }

    if normalized.contains("apiversion:")
        && normalized.contains("clusters:")
        && normalized.contains("server:")
    {
        labels.insert("kube".to_string());
        secret_hits += 2;
    }

    if normalized.contains("ghp_")
        || normalized.contains("github_pat_")
        || normalized.contains("github_token")
    {
        labels.insert("git".to_string());
        secret_hits += 2;
    }

    for marker in [
        "api_token=",
        "access_token=",
        "secret=",
        "password=",
        "private_key=",
        "ssh_private_key=",
        "database_password=",
        "token=",
    ] {
        if normalized.contains(marker) {
            labels.insert("env".to_string());
            secret_hits += 1;
        }
    }

    let basename = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .trim()
        .to_ascii_lowercase();
    let script_like = normalized.starts_with("#!")
        || [
            ".sh", ".py", ".pl", ".rb", ".ps1", ".bat", ".cmd", ".js", ".vbs",
        ]
        .iter()
        .any(|ext| basename.ends_with(ext));
    let network_command_like = [
        "curl ",
        "wget ",
        " nc ",
        "netcat",
        "invoke-webrequest",
        "invoke-restmethod",
        "http://",
        "https://",
        "socket.create_connection",
    ]
    .iter()
    .any(|needle| normalized.contains(needle));

    Some(SecretContentFileMatch {
        path: path.to_string(),
        secret_labels: labels.into_iter().collect(),
        secret_hits,
        script_like,
        network_command_like,
    })
}

/// Batched scan used by the vulnerability detector tick. Returns every signal
/// that carries at least one indicator the detector may promote:
///   - `secret_hits >= secret_content_min_hits` (primary sensitive-material
///     signal used by `sensitive_material_egress`)
///   - `script_like` (used by FIM temp-mutation heuristic)
///   - `network_command_like` (used by FIM temp-mutation heuristic)
///
/// Per-check thresholds are enforced downstream in the detector; the batch
/// scanner intentionally avoids dropping low-hits-but-script-like signals so
/// the FIM pipeline keeps parity with the synchronous in-process path.
pub fn scan_secret_like_files(paths: &[String]) -> Vec<SecretContentFileMatch> {
    let mut unique_paths = BTreeSet::new();
    let mut matches = Vec::new();
    let min_hits = vuln_detector_params::secret_content_min_hits();

    for path in paths {
        let trimmed = path.trim();
        if trimmed.is_empty() || !unique_paths.insert(trimmed.to_string()) {
            continue;
        }
        let Some(signal) = inspect_secret_like_file(trimmed) else {
            continue;
        };
        let has_indicator =
            signal.secret_hits >= min_hits || signal.script_like || signal.network_command_like;
        if !has_indicator {
            continue;
        }
        matches.push(signal);
    }

    matches
}
