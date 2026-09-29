//! Authenticity of the models this process downloaded from threatmodels
//! (threatmodels_rs `authenticity`, the `model-signatures` feature).
//!
//! [`snapshot`] is the one reader: a standalone core calls it in-process,
//! and the helper answers the `model_authenticity` utility order with it, so
//! the app can report the copies each process runs scripts from and matches
//! traffic against (in the app, the elevated threat-model scripts and the
//! capture's lists are the helper's own copies, not the app's).
//!
//! Who verifies what (2.0.3): every process that downloads a model verifies
//! it itself, and runs scripts only from its own copy. The helper looks a
//! script up by name in its copy and downloads a new copy when the app's
//! model signature differs; the app never sends script text. A download that
//! does not verify is never parsed: the process keeps its embedded snapshot
//! or its last verified download.

use serde::{Deserialize, Serialize};
use threatmodels_rs::authenticity::{ManifestScope, ModelAuthenticator};

/// Whether this build authenticates downloads: the `model-signatures`
/// feature, as unified across the whole build.
pub const ENFORCED: bool = threatmodels_rs::authenticity::SIGNATURES_ENFORCED;

/// First helper release built with `model-signatures`. The app reads an
/// older helper as one that downloads and runs, as root/SYSTEM, whatever
/// threatmodels `main` serves, and warns until it is updated.
/// `edamame_helper` does not compile without the feature, so a helper at or
/// above this version always verifies.
pub const FIRST_VERIFYING_HELPER_VERSION: &str = "2.0.3";

/// Whether a helper reporting `helper_version` (its `helper_check` answer)
/// verifies model signatures. A version that does not parse is treated as
/// one that does not.
pub fn helper_verifies_models(helper_version: &str) -> bool {
    use crate::version::Version;
    let first = Version::parse(FIRST_VERIFYING_HELPER_VERSION)
        .expect("FIRST_VERIFYING_HELPER_VERSION is a version");
    match Version::parse(helper_version.trim()) {
        Ok(version) => version >= first,
        Err(_) => false,
    }
}

/// Whether the helper verifies the models it downloads, as the app sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperModelSignatures {
    /// No helper in this build (standalone posture / cli, iOS, Android): the
    /// process that downloads a model is the one that runs it.
    NotApplicable,
    /// The helper has not answered (not installed, stopped, starting).
    Unknown,
    /// The helper verifies: its version is at least
    /// [`FIRST_VERIFYING_HELPER_VERSION`].
    Verifying { version: String },
    /// The helper predates verification and runs whatever threatmodels
    /// `main` serves. `version` is empty when the helper refused the app's
    /// orders as an older major / minor.
    NotVerifying { version: String },
}

impl HelperModelSignatures {
    /// From the version a helper reported (`helper_check`).
    pub fn for_helper_version(version: &str) -> Self {
        let version = version.trim().to_string();
        if helper_verifies_models(&version) {
            Self::Verifying { version }
        } else {
            Self::NotVerifying { version }
        }
    }

    /// Wire name: `not_applicable`, `unknown`, `verifying`, `not_verifying`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Unknown => "unknown",
            Self::Verifying { .. } => "verifying",
            Self::NotVerifying { .. } => "not_verifying",
        }
    }

    /// The helper's version when it reported one, else empty.
    pub fn version(&self) -> &str {
        match self {
            Self::Verifying { version } | Self::NotVerifying { version } => version,
            Self::NotApplicable | Self::Unknown => "",
        }
    }
}

/// One model a process initialized.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ModelAuthenticityEntry {
    /// Published path, e.g. `threatmodel-macOS.json`.
    pub file_name: String,
    /// `exec` (threat models: their scripts are run) or `data`.
    pub scope: String,
    /// `embedded`, `custom` (set locally), `downloaded` (not authenticated:
    /// the feature is off) or `downloaded_verified`.
    pub provenance: String,
    /// Why the last download was refused; empty when it was not.
    pub last_authenticity_error: String,
}

/// The authenticity state of one process's models.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ModelAuthenticitySnapshot {
    /// This build verifies downloads against the signed manifests.
    pub enforced: bool,
    /// Highest exec manifest sequence accepted: the embedded rollback floor
    /// until a newer manifest verifies. 0 when not enforced.
    pub exec_sequence: u64,
    /// Same for the data manifest.
    pub data_sequence: u64,
    /// The models this process initialized, by file name. The threat model
    /// is always listed.
    pub models: Vec<ModelAuthenticityEntry>,
}

/// This process's snapshot.
pub async fn snapshot() -> ModelAuthenticitySnapshot {
    // The threat model is the one whose scripts run: list it even before the
    // first order touches it (a fresh helper), at its embedded provenance.
    lazy_static::initialize(&crate::threat_factory::THREATS);

    let authenticator = ModelAuthenticator::production();
    let sequence = |scope| {
        authenticator
            .as_ref()
            .map(|a| a.highest_sequence(scope))
            .unwrap_or(0)
    };
    let models = threatmodels_rs::model_authenticity_states()
        .await
        .into_iter()
        .map(|state| ModelAuthenticityEntry {
            file_name: state.file_name,
            scope: state.scope.as_str().to_string(),
            provenance: state.provenance.as_str().to_string(),
            last_authenticity_error: state.last_authenticity_error.unwrap_or_default(),
        })
        .collect();
    ModelAuthenticitySnapshot {
        enforced: authenticator.is_some(),
        exec_sequence: sequence(ManifestScope::Exec),
        data_sequence: sequence(ManifestScope::Data),
        models,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_factory::{get_model_name, THREATS};

    #[test]
    fn helpers_from_the_first_verifying_version_verify() {
        assert!(!helper_verifies_models("2.0.2"));
        assert!(!helper_verifies_models("1.9.9"));
        assert!(!helper_verifies_models("0.0.0"));
        assert!(helper_verifies_models("2.0.3"));
        assert!(helper_verifies_models(" 2.0.3\n"));
        assert!(helper_verifies_models("2.0.10"));
        assert!(helper_verifies_models("2.1.0"));
        assert!(helper_verifies_models("3.0.0"));
        // Unreadable: not assumed to verify.
        assert!(!helper_verifies_models(""));
        assert!(!helper_verifies_models("helper is not responding"));
    }

    #[test]
    fn the_helper_version_maps_to_its_verification() {
        assert_eq!(
            HelperModelSignatures::for_helper_version("2.0.2"),
            HelperModelSignatures::NotVerifying {
                version: "2.0.2".to_string()
            }
        );
        assert_eq!(
            HelperModelSignatures::for_helper_version("2.0.3\n"),
            HelperModelSignatures::Verifying {
                version: "2.0.3".to_string()
            }
        );
        assert_eq!(
            HelperModelSignatures::for_helper_version("2.1.0").as_str(),
            "verifying"
        );
        assert_eq!(
            HelperModelSignatures::for_helper_version("").as_str(),
            "not_verifying"
        );
        assert_eq!(HelperModelSignatures::Unknown.as_str(), "unknown");
        assert_eq!(HelperModelSignatures::Unknown.version(), "");
        assert_eq!(
            HelperModelSignatures::NotApplicable.as_str(),
            "not_applicable"
        );
    }

    /// The process-wide `THREATS` model -- the copy the helper runs elevated
    /// scripts from -- authenticates its downloads exactly when the build
    /// enables `model-signatures`.
    #[test]
    fn the_threat_model_the_helper_runs_verifies_in_a_verifying_build() {
        assert_eq!(THREATS.authenticity_enforced(), ENFORCED);
        assert_eq!(
            ModelAuthenticator::production().is_some(),
            cfg!(feature = "model-signatures")
        );
    }

    #[tokio::test]
    async fn the_snapshot_always_lists_the_threat_model() {
        let snapshot = snapshot().await;
        assert_eq!(snapshot.enforced, ENFORCED);
        let name = get_model_name("").unwrap();
        let entry = snapshot
            .models
            .iter()
            .find(|m| m.file_name == name)
            .expect("the threat model is listed");
        assert_eq!(entry.scope, "exec");
        if ENFORCED {
            assert!(
                snapshot.exec_sequence
                    >= threatmodels_rs::authenticity::EMBEDDED_SEQUENCE_FLOOR_EXEC
            );
            assert!(
                snapshot.data_sequence
                    >= threatmodels_rs::authenticity::EMBEDDED_SEQUENCE_FLOOR_DATA
            );
        } else {
            assert_eq!((snapshot.exec_sequence, snapshot.data_sequence), (0, 0));
        }
    }
}
