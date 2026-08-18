//! Operator consent markdown: try GitHub, fall back to the embedded snapshot.
//!
//! Source of truth is `../threatmodels/consent/`. `update-threats.sh` copies
//! that tree into `consent/` and regenerates [`consent_documents_db`]. Runtime
//! fetch uses the same `raw.githubusercontent.com/edamametechnologies/threatmodels`
//! origin as CloudModel. A 429 / timeout / empty body is not a dialog failure:
//! the embedded snapshot is returned instead.

use crate::consent_documents_db::{embedded_consent, embedded_consent_filenames};
use std::time::Duration;
use tracing::{info, warn};

const FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const USER_AGENT: &str = "EDAMAME-Security (consent-documents)";

const STATIC_DOCUMENTS: &[&str] = &[
    "compliance-scanner",
    "user-feedback",
    "profiling-feedback",
    "request-report",
    "vulnerability-feedback",
    "privacy-LLM",
];

/// Resolve the on-disk / remote filename for a consent document id.
pub fn consent_filename(document: &str, locale: &str) -> Option<String> {
    let locale = normalize_locale(locale);
    match document {
        "privacy-detailed" => Some(format!(
            "privacy-detailed-{}-{}.md",
            host_platform(),
            locale
        )),
        "privacy-detailed-ai" => {
            let platform = host_platform();
            if matches!(platform, "macOS" | "Windows" | "Linux") {
                Some(format!("privacy-detailed-ai-{platform}-{locale}.md"))
            } else {
                Some(format!("privacy-detailed-{platform}-{locale}.md"))
            }
        }
        other if STATIC_DOCUMENTS.contains(&other) => Some(format!("{other}-{locale}.md")),
        _ => None,
    }
}

/// Load a consent page: remote first, embedded snapshot if the fetch fails.
///
/// `branch` is the CloudModel branch (`main` / `dev`). An empty or unknown
/// branch is treated as `main`.
pub async fn load_consent_document(document: &str, locale: &str, branch: &str) -> String {
    let Some(filename) = consent_filename(document, locale) else {
        warn!("Unknown consent document id '{}'", document);
        return String::new();
    };
    let branch = normalize_branch(branch);
    if let Some(remote) = try_fetch_remote(&filename, branch).await {
        return remote;
    }
    if let Some(embedded) = load_embedded(&filename) {
        return embedded;
    }
    if normalize_locale(locale) != "EN" {
        if let Some(en_name) = consent_filename(document, "EN") {
            if let Some(embedded) = load_embedded(&en_name) {
                warn!(
                    "Consent {} missing localized embed; using English snapshot",
                    filename
                );
                return embedded;
            }
        }
    }
    warn!(
        "Consent {} has no remote copy and no embedded snapshot",
        filename
    );
    String::new()
}

pub fn load_embedded(filename: &str) -> Option<String> {
    embedded_consent(filename).map(|text| text.to_string())
}

pub fn snapshot_filenames() -> &'static [&'static str] {
    embedded_consent_filenames()
}

fn normalize_locale(locale: &str) -> &'static str {
    if locale.eq_ignore_ascii_case("fr") {
        "FR"
    } else {
        "EN"
    }
}

fn normalize_branch(branch: &str) -> &str {
    match branch {
        "dev" | "main" => branch,
        _ => "main",
    }
}

fn host_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "ios") {
        "iOS"
    } else if cfg!(target_os = "android") {
        "Android"
    } else {
        "macOS"
    }
}

const THREATMODELS_RAW: &str = "https://raw.githubusercontent.com/edamametechnologies/threatmodels";

fn remote_url(branch: &str, filename: &str) -> String {
    format!("{THREATMODELS_RAW}/{branch}/consent/{filename}")
}

async fn try_fetch_remote(filename: &str, branch: &str) -> Option<String> {
    let url = remote_url(branch, filename);
    let client = match threatmodels_rs::tls::client_builder()
        .user_agent(USER_AGENT)
        .timeout(FETCH_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            warn!("Consent HTTP client failed: {}", error);
            return None;
        }
    };

    match client.get(&url).send().await {
        Ok(response) if response.status().is_success() => match response.text().await {
            Ok(body) if !body.trim().is_empty() && !looks_like_github_block_page(&body) => {
                info!("Loaded consent {} from {}", filename, url);
                Some(body)
            }
            Ok(_) => {
                warn!(
                    "Consent {} from {} was empty or a block page",
                    filename, url
                );
                None
            }
            Err(error) => {
                warn!("Consent {} body read failed: {}", filename, error);
                None
            }
        },
        Ok(response) => {
            warn!(
                "Consent {} fetch returned HTTP {} from {}",
                filename,
                response.status(),
                url
            );
            None
        }
        Err(error) => {
            warn!("Consent {} fetch failed: {}", filename, error);
            None
        }
    }
}

fn looks_like_github_block_page(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("you have triggered an abuse detection")
        || (lower.contains("rate limit") && lower.contains("github"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_document_filenames() {
        assert_eq!(
            consent_filename("compliance-scanner", "fr").as_deref(),
            Some("compliance-scanner-FR.md")
        );
        assert_eq!(
            consent_filename("privacy-LLM", "en").as_deref(),
            Some("privacy-LLM-EN.md")
        );
        assert_eq!(consent_filename("not-a-doc", "EN"), None);
    }

    #[test]
    fn privacy_detailed_uses_host_platform() {
        let name = consent_filename("privacy-detailed", "EN").expect("filename");
        assert!(
            name.starts_with("privacy-detailed-") && name.ends_with("-EN.md"),
            "{name}"
        );
        assert!(embedded_consent(&name).is_some(), "missing embed {name}");
    }

    #[test]
    fn remote_url_matches_cloudmodel_origin() {
        assert_eq!(
            remote_url("main", "compliance-scanner-EN.md"),
            "https://raw.githubusercontent.com/edamametechnologies/threatmodels/main/consent/compliance-scanner-EN.md"
        );
    }

    #[test]
    fn every_snapshot_file_is_non_empty() {
        for filename in snapshot_filenames() {
            let body = embedded_consent(filename).expect(filename);
            assert!(!body.trim().is_empty(), "{filename} is empty");
        }
        assert!(
            snapshot_filenames().len() >= 12,
            "expected static + generated consent pages"
        );
    }
}
