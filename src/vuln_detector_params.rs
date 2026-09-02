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
    pub generic_git: HelperMatcherConfig,
    pub macos: HelperMatcherConfig,
    pub linux: HelperMatcherConfig,
    pub windows: HelperMatcherConfig,
}

/// Path-substring lists used to suppress browser-cache /
/// browser-state false positives in `file_system_tampering`.
///
/// The sensitive-path classifier inherits "appdata" sensitivity from
/// the parent directory (e.g. `…/AppData/Local/Google/Chrome/User Data/`).
/// That's correct for `Login Data`, `Cookies`, `Web Data` -- but wrong
/// for the recomputable browser-cache subtrees (`Code Cache`,
/// `GPUCache`, `Service Worker`, etc.) and for the routine-rotation
/// state files (`Local State`, `Preferences`) that browsers atomically
/// rewrite many times an hour.
///
/// All patterns are case-insensitive substring matches against the
/// FIM event path (after lowercasing). The detector requires BOTH
/// the user-data root marker AND the cache/state subtree to match
/// before suppressing -- a coincidentally-named subtree elsewhere on
/// disk is never sufficient on its own.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BrowserDataSubtreesJSON {
    pub chromium_family: Vec<String>,
    pub chromium_state_files_routine: Vec<String>,
    pub chromium_profile_state_volatile: Vec<String>,
    pub chromium_user_data_root_markers: Vec<String>,
    pub firefox_family_subtrees: Vec<String>,
    pub firefox_profile_state_volatile: Vec<String>,
    pub firefox_user_data_root_markers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BrowserAppdataUnknownWriterJSON {
    pub chromium_user_data_root_markers: Vec<String>,
    pub firefox_user_data_root_markers: Vec<String>,
    pub chromium_process_names: Vec<String>,
    pub firefox_process_names: Vec<String>,
    pub directory_target_names: Vec<String>,
}

/// Per-platform routine egress destinations for trusted platform
/// credential helpers. Used by the session-side credential-helper
/// self-access suppression hook (FP-MAC-8): when a process attested
/// as a trusted platform credential helper (e.g. macOS `xpcproxy`
/// mediating M365 sign-in) reads ONLY OS-managed credential-store
/// files and egresses to one of these destinations, the
/// `token_exfiltration` / `sensitive_material_egress` finding is
/// suppressed.
///
/// Match semantics:
/// - `asn_owners`: case-insensitive substring match against the
///   session's `dst_asn.owner` field.
/// - `domain_patterns`: each pattern is matched as a case-insensitive
///   substring against the resolved destination domain. Patterns that
///   start with `.` (e.g. `.login.microsoftonline.com`) match any
///   subdomain of the suffix; patterns without a leading dot match
///   anywhere in the domain string.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CredentialHelperDestinationListJSON {
    pub asn_owners: Vec<String>,
    pub domain_patterns: Vec<String>,
    pub ip_prefixes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PlatformCredentialHelperRoutineDestinationsJSON {
    pub macos: CredentialHelperDestinationListJSON,
    pub linux: CredentialHelperDestinationListJSON,
    pub windows: CredentialHelperDestinationListJSON,
}

/// Per-cloud-provider SDK control-plane destinations, used by the
/// `cloud_provider_sdk_self_auth` token-exfiltration demotion. Unlike
/// `CredentialHelperDestinationListJSON` (which is platform-keyed and
/// uses `domain_patterns` substring semantics), this list is
/// provider-keyed and uses strict suffix semantics on `domain_suffixes`:
/// each entry begins with `.` and matches a host that equals the suffix
/// without the leading dot, or ends with the suffix.
///
/// - `asn_owners`: case-insensitive substring match against the
///   session's `dst_asn.owner` (so a bare-IP Bedrock session with no
///   reverse DNS still matches via `Amazon`).
/// - `domain_suffixes`: case-insensitive suffix match against the
///   resolved destination domain.
/// - `ip_prefixes`: case-insensitive prefix match for vendor ranges
///   that routinely arrive without DNS/ASN enrichment.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CloudProviderSdkDestinationListJSON {
    pub asn_owners: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub ip_prefixes: Vec<String>,
}

/// Provider-keyed cloud-SDK destination allowlist. Keys MUST match the
/// sensitive-path label strings emitted by `flodbadd`'s sensitive-path
/// classifier (`aws` -> `~/.aws/`, `azure` -> `~/.azure/`,
/// `gcp` -> `~/.config/gcloud/`) so the detector can map a credential
/// file's provider label directly to the matching destination list.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CloudProviderSdkDestinationsJSON {
    pub aws: CloudProviderSdkDestinationListJSON,
    pub azure: CloudProviderSdkDestinationListJSON,
    pub gcp: CloudProviderSdkDestinationListJSON,
}

/// CI-runner workspace path substrings + suppressible filename
/// basenames for the FP-CI-7 dotenv demotion. Path substrings are
/// matched against a forward-slash-normalized, lowercased version of
/// the FIM event path so a single canonical form covers every platform
/// AND every CI provider (GitHub Actions, GitLab CI, Jenkins, CircleCI,
/// Buildkite, Travis, TeamCity, Azure DevOps, Bitbucket Pipelines,
/// Drone, Woodpecker, Cirrus CI, AppVeyor, Bamboo, GoCD, Codefresh,
/// Semaphore, ...).
///
/// `suppressible_basenames` is the complementary axis: the demotion
/// only fires for filenames in this allowlist (the canonical
/// `.env`-family). Other writes inside a CI runner workspace stay
/// graded by their normal severity rules.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CiRunnerWorkspacePathPatternsJSON {
    pub path_substrings: Vec<String>,
    pub suppressible_basenames: Vec<String>,
}

/// Per-platform list of build-output tree path substrings used by the
/// FP-CI-6 sandbox-exploitation severity demotion. When BOTH the process
/// binary path AND its parent process path lie inside one of these
/// substrings (matched on lowercased, forward-slash-normalized paths),
/// the bare-lineage signal "process spawned from a temp-class location"
/// is treated as a build-tool self-spawn (cargo/flutter/gradle/lima
/// builds running their own freshly-compiled output) and graded LOW
/// instead of HIGH.
///
/// `PlatformStringLists` is reused here because the patterns are
/// already platform-agnostic in shape (they're keyed by WHICH OS the
/// CI runner is on, not by the *binary's* target triple). The detector
/// reads all three lists per call so a Linux runner finding can match
/// macOS-style absolute paths if that's what got reported in process
/// attribution.
///
/// Tunable via CloudModel so new build-tool layouts (e.g. a future
/// Flutter target, a new Cargo profile) can be added without a release.
///
/// Per-platform runtime perfdata path entry. JVM HotSpot writes
/// `/tmp/hsperfdata_<user>/<pid>` files for performance counters;
/// these are entirely benign FIM noise. The detector fully suppresses
/// `file_system_tampering` findings whose artifact path matches
/// `artifact_path_substring` AND whose writer is one of the
/// allowlisted JVM basenames or installs.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RuntimePerfdataEntryJSON {
    pub artifact_path_substring: String,
    pub writer_basenames: Vec<String>,
    pub writer_path_prefixes: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PlatformRuntimePerfdataPathsJSON {
    pub macos: Vec<RuntimePerfdataEntryJSON>,
    pub linux: Vec<RuntimePerfdataEntryJSON>,
    pub windows: Vec<RuntimePerfdataEntryJSON>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ManagedTempStagingPatternsJSON {
    pub suppress_path_patterns: PlatformStringLists,
    pub demote_path_patterns: PlatformStringLists,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TrustedBuildTempStagingJSON {
    pub writer_path_patterns: PlatformStringLists,
    pub artifact_path_patterns: PlatformStringLists,
}

/// Pair-wise writer/target allowlist entry for FP-WIN-7c
/// "trusted-app self-temp-staging" deterministic suppression.
///
/// Each entry documents a single vendor's legitimate self-update or
/// self-extract pattern as a pair (writer_path_patterns,
/// target_path_patterns). Both lists are case-insensitive substring
/// matches against the lowercased path. A finding is suppressed only
/// when the writer matches AND the target matches in the SAME entry --
/// the pair shape prevents collapsing two unrelated legitimate writers
/// and trusted targets into a cross-match (e.g. it would NOT suppress
/// `chrome.exe` writing to a WinGet target directory).
///
/// `name` is a stable identifier used in logs and audit evidence.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AppSelfTempStagingEntryJSON {
    pub name: String,
    pub writer_path_patterns: Vec<String>,
    pub target_path_patterns: Vec<String>,
}

/// Per-platform list of `AppSelfTempStagingEntryJSON` (FP-WIN-7c).
/// See [`AppSelfTempStagingEntryJSON`] for the pair-wise semantics.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AppSelfTempStagingJSON {
    pub macos: Vec<AppSelfTempStagingEntryJSON>,
    pub linux: Vec<AppSelfTempStagingEntryJSON>,
    pub windows: Vec<AppSelfTempStagingEntryJSON>,
}

/// Symmetric-evidence weight table (`evidence_weights`).
///
/// The CloudModel JSON shape mirrors `EvidenceWeights` in
/// `edamame_core::agentic::vulnerability_score`. We deliberately keep
/// it as flat `f32` fields rather than a generic
/// `HashMap<String, f32>` so:
///
/// - the schema is self-documenting (one struct field per signal),
/// - the embedded fallback can be a typed default (no risk of a
///   stringly-typed CloudModel publish silently dropping a signal),
/// - the `EvidenceWeights` runtime view shares the same shape and the
///   conversion is field-by-field.
///
/// **Parse policy.** Fields are required at the CloudModel wire
/// boundary: a published JSON missing any weight fails the update
/// parse and falls back to the embedded snapshot (which is always
/// complete). Runtime `Default` for `EvidenceWeightsJSON` still
/// uses the calibrated `default_ew_*` helpers below so unit tests
/// and in-process construction get meaningful initial weights
/// without silent serde zeros, per the "born complete" CloudModel
/// decision in the core/foundation invariants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EvidenceWeightsJSON {
    // ---- Attack signals ----
    pub session_is_anomalous: f32,
    /// Graded-anomaly signal: ADDITIVE extra weight applied on
    /// top of `session_is_anomalous` when the originating session's
    /// iForest grade is `abnormal` (>= the p99.75 threshold) rather
    /// than merely `suspicious` (>= p99.5). Lets calibration weight
    /// strong outliers above the guaranteed ~0.5% base-rate band
    /// without touching the boolean signal. Default 0.0 (inert) until
    /// calibrated via CloudModel.
    pub session_is_abnormal_extra: f32,
    pub session_is_blacklisted: f32,
    /// Signal: the originating session's whitelist conformance
    /// state is `NonConforming`. Deterministic corroboration computed
    /// by the flodbadd whitelist engine that previously never reached
    /// the detector (only the Conforming direction was ever debated,
    /// and it is deliberately NOT a suppression signal). Default 0.0
    /// (inert) until calibrated via CloudModel.
    pub session_whitelist_nonconforming: f32,
    pub destination_is_public_diagnostic: f32,
    pub destination_is_blacklisted: f32,
    pub sensitive_material_evidence_present: f32,
    pub suspicious_lineage_present: f32,
    pub process_path_matches_suspicious_lineage: f32,
    /// Signal: the session's GRANDPARENT process path or
    /// grandparent script path matches a suspicious-lineage pattern.
    /// The parent-level lineage signals stop one level up, so a
    /// `/tmp/` grandparent currently evades the lineage corroboration
    /// axis entirely (the data is on every session; divergence already
    /// consumes it, the detector did not). Default 0.0 (inert) until
    /// calibrated via CloudModel.
    pub grandparent_matches_suspicious_lineage: f32,
    pub is_system_binary_target: f32,
    /// Structural attack signal: the finding's target path is in a
    /// sensitive class (ssh private key, AWS credentials, .env file,
    /// platform credential store, etc.). Distinct from
    /// `sensitive_material_evidence_present` -- that signal captures
    /// "a related session/process holds sensitive material"; this
    /// signal captures "this finding's actual target IS sensitive".
    ///
    /// Populated for both FIM evidence (`build_fim_finding_evidence`,
    /// derived from `is_sensitive`) and session evidence
    /// (`build_session_finding_evidence`, derived from the first
    /// sensitive_file label). Default weight 50.0 -- meets the
    /// `apply_crs_severity` CRITICAL guardrail ARIS floor of 50, so
    /// a FIM-only finding on a sensitive file (the canonical
    /// `cve_file_events` strict-gate shape) lands at CRITICAL alone.
    pub target_in_sensitive_path_class: f32,

    // ---- Benign signals ----
    pub destination_is_routine_vendor_backend: f32,
    /// Destination<->publisher affinity: the destination's
    /// organization (ASN owner or registrable-domain label) matches the
    /// egressing binary's verified signing publisher ("this app is
    /// talking to its own vendor"). Structural replacement for the
    /// routine-destination vocabularies; token matching is deliberately
    /// conservative and the weight stays 0.0 until calibrated via
    /// CloudModel.
    pub destination_org_matches_publisher: f32,
    pub process_in_trusted_credential_helper_list: f32,
    pub process_in_generic_git_credential_manager_list: f32,
    pub process_path_matches_packaged_application: f32,
    pub process_in_ci_runner_internal_agent_list: f32,
    pub process_in_ide_project_config_helper_list: f32,
    pub process_in_jvm_hsperfdata_writer_list: f32,
    pub process_name_matches_known_system_daemon_hint: f32,
    /// P2 writer-equal-egresser predicate. Benign weight applied when
    /// a session-based finding fires for a process that owns its
    /// sensitive material AND talks to a routine destination AND has
    /// no anomaly/blacklist corroboration. This is the structural
    /// "OS daemon doing ambient self-access to its own backend"
    /// shape; targeted at session-based FPs (the FIM-based dogfood
    /// FP class is already covered by the system-daemon hint signal).
    pub ambient_external_egress: f32,
    /// P3 publisher attestation: writer process binary carries a valid
    /// platform-publisher signature (Apple Developer ID + canonical
    /// `/usr/*` or `/System/*` path on macOS, Microsoft Authenticode +
    /// `C:\Windows\*` or `C:\Program Files\*` path on Windows, distro
    /// package signature + `/usr/bin` / `/usr/lib` path on Linux).
    /// Benign weight applied when the signature verifies AND the
    /// canonical-path predicate holds.
    pub publisher_attestation_signed_by_canonical_publisher: f32,
    /// P3 publisher attestation impostor: writer process binary lives
    /// under a canonical OS install path BUT lacks a valid platform-
    /// publisher signature (relocated tool / spoofed-OS-publisher
    /// shape, `Stealga.HAK!MTB`-class). Attack weight applied when
    /// the binary's path matches a canonical OS install path AND its
    /// signature does NOT verify against the expected publisher.
    pub invalid_signature_in_canonical_path: f32,
    /// P4 ambient baseline credit: finding's `lineage_key` is present
    /// in the per-host `vuln_ambient_baseline.json` snapshot for at
    /// least N consecutive days (default 7) without operator
    /// escalation. Small benign weight that dampens the long-tail of
    /// persistent FPs that recur day-after-day. Anti-spoofing: weight
    /// is intentionally small (15) so a single attack signal swamps
    /// it; CVE scenarios still alert on the first observation.
    pub ambient_baseline_credit: f32,
    pub attribution_full_path: f32,
    pub attribution_name_only: f32,
    pub attribution_missing: f32,
}

impl Default for EvidenceWeightsJSON {
    fn default() -> Self {
        Self {
            session_is_anomalous: default_ew_session_is_anomalous(),
            session_is_abnormal_extra: default_ew_session_is_abnormal_extra(),
            session_is_blacklisted: default_ew_session_is_blacklisted(),
            session_whitelist_nonconforming: default_ew_session_whitelist_nonconforming(),
            destination_is_public_diagnostic: default_ew_destination_is_public_diagnostic(),
            destination_is_blacklisted: default_ew_destination_is_blacklisted(),
            sensitive_material_evidence_present: default_ew_sensitive_material_evidence_present(),
            suspicious_lineage_present: default_ew_suspicious_lineage_present(),
            process_path_matches_suspicious_lineage:
                default_ew_process_path_matches_suspicious_lineage(),
            grandparent_matches_suspicious_lineage:
                default_ew_grandparent_matches_suspicious_lineage(),
            is_system_binary_target: default_ew_is_system_binary_target(),
            target_in_sensitive_path_class: default_ew_target_in_sensitive_path_class(),
            destination_is_routine_vendor_backend: default_ew_destination_is_routine_vendor_backend(
            ),
            destination_org_matches_publisher: default_ew_destination_org_matches_publisher(),
            process_in_trusted_credential_helper_list:
                default_ew_process_in_trusted_credential_helper_list(),
            process_in_generic_git_credential_manager_list:
                default_ew_process_in_generic_git_credential_manager_list(),
            process_path_matches_packaged_application:
                default_ew_process_path_matches_packaged_application(),
            process_in_ci_runner_internal_agent_list:
                default_ew_process_in_ci_runner_internal_agent_list(),
            process_in_ide_project_config_helper_list:
                default_ew_process_in_ide_project_config_helper_list(),
            process_in_jvm_hsperfdata_writer_list: default_ew_process_in_jvm_hsperfdata_writer_list(
            ),
            process_name_matches_known_system_daemon_hint:
                default_ew_process_name_matches_known_system_daemon_hint(),
            ambient_external_egress: default_ew_ambient_external_egress(),
            publisher_attestation_signed_by_canonical_publisher:
                default_ew_publisher_attestation_signed_by_canonical_publisher(),
            invalid_signature_in_canonical_path: default_ew_invalid_signature_in_canonical_path(),
            ambient_baseline_credit: default_ew_ambient_baseline_credit(),
            attribution_full_path: default_ew_attribution_full_path(),
            attribution_name_only: default_ew_attribution_name_only(),
            attribution_missing: default_ew_attribution_missing(),
        }
    }
}

// Initial weights -- mirror EvidenceWeights::default in
// `edamame_core::agentic::vulnerability_score`. Do NOT tune these here
// outside the fixture-driven shadow window; the CloudModel publish is
// the authoritative knob.
fn default_ew_session_is_anomalous() -> f32 {
    50.0
}
fn default_ew_session_is_blacklisted() -> f32 {
    50.0
}
// Inert-by-default signals: land at 0.0 and are calibrated via the
// CloudModel publish, never here.
fn default_ew_session_is_abnormal_extra() -> f32 {
    0.0
}
fn default_ew_session_whitelist_nonconforming() -> f32 {
    0.0
}
fn default_ew_grandparent_matches_suspicious_lineage() -> f32 {
    0.0
}
fn default_ew_destination_org_matches_publisher() -> f32 {
    0.0
}
fn default_ew_destination_is_public_diagnostic() -> f32 {
    30.0
}
fn default_ew_destination_is_blacklisted() -> f32 {
    50.0
}
fn default_ew_sensitive_material_evidence_present() -> f32 {
    40.0
}
fn default_ew_suspicious_lineage_present() -> f32 {
    30.0
}
fn default_ew_process_path_matches_suspicious_lineage() -> f32 {
    30.0
}
fn default_ew_is_system_binary_target() -> f32 {
    60.0
}
// ITER 1 calibration target: FIM-only sensitive-file tampering (the
// `cve_file_events` scenario) produced 0 ARIS / 0 ABIS under P5 LIVE
// because the legacy classifier's "is_sensitive == true => CRITICAL"
// gate did not have a corresponding boolean attack signal in the
// CRS model. The result on iter 1 (tests.yml run 25998184563) was
// 4 platform-scenario failures (file_events FAIL on all 4 platforms)
// while the idle baseline was CLEAN 4/4. Weight set to 50.0 so the
// signal alone meets the `apply_crs_severity` CRITICAL guardrail
// ARIS floor of 50; a benign signal must therefore add real weight
// (or several benigns must stack) to demote the finding below LOW.
fn default_ew_target_in_sensitive_path_class() -> f32 {
    50.0
}
fn default_ew_destination_is_routine_vendor_backend() -> f32 {
    25.0
}
fn default_ew_process_in_trusted_credential_helper_list() -> f32 {
    40.0
}
fn default_ew_process_in_generic_git_credential_manager_list() -> f32 {
    35.0
}
fn default_ew_process_path_matches_packaged_application() -> f32 {
    20.0
}
fn default_ew_process_in_ci_runner_internal_agent_list() -> f32 {
    30.0
}
fn default_ew_process_in_ide_project_config_helper_list() -> f32 {
    25.0
}
fn default_ew_process_in_jvm_hsperfdata_writer_list() -> f32 {
    30.0
}
// ITER 1 calibration: raised from 15 -> 40 so the FP-MAC-9 / FP-MAC-10 /
// FP-MAC-11 class (macOS sharingd / mobilesoftwareupdate / assistantd
// renaming login.keychain-db) can offset the new
// `target_in_sensitive_path_class` 50-weight attack signal and demote
// to LOW. The CRS model is additive, so a real attack on the same
// daemon (anomaly + blacklist = 100 ARIS) still wins handily
// (CRS = 60/140 = 0.43 -> HIGH alertable). The earlier "informational
// only" comment reflected the legacy LLM-driven model where the hint
// was a soft suggestion; under CRS, structural signals ARE the
// adjudicator and the daemon-hint list -- vetted against dogfood
// evidence on macOS, Linux, Windows -- earns a stronger benign weight.
fn default_ew_process_name_matches_known_system_daemon_hint() -> f32 {
    40.0
}
// P2 -- writer-equal-egresser predicate. Conservative benign weight
// matching the system-daemon-hint level: enough to dampen findings
// whose only attack contribution is weak corroboration, not enough
// to swamp a real anomaly/blacklist/lineage signal.
fn default_ew_ambient_external_egress() -> f32 {
    15.0
}
// P3 -- publisher attestation signed. Stronger than the system-
// daemon hint because it is a cryptographically verified signal:
// when the OS verifies an Apple/Microsoft/distro publisher signature
// on a binary in its canonical install path, the binary is what its
// path claims it is. Targeted at the FP-MAC-9/10/11 + Windows
// DismHost class.
fn default_ew_publisher_attestation_signed_by_canonical_publisher() -> f32 {
    35.0
}
// P3 -- publisher attestation impostor. NEW attack class: a binary
// living under a canonical OS install path with INVALID publisher
// signature is the canonical relocated-tool / spoofed-OS-publisher
// shape (`Stealga.HAK!MTB`-class). Strong attack weight because the
// path claim is structural and the signature failure is decisive.
fn default_ew_invalid_signature_in_canonical_path() -> f32 {
    60.0
}
// P4 -- ambient baseline credit. Intentionally small so a single
// attack signal (anomaly, blacklist, suspicious lineage, sensitive
// material) swamps it. The shape catches the long tail of persistent
// FPs that recur day-after-day without escalation.
fn default_ew_ambient_baseline_credit() -> f32 {
    15.0
}
fn default_ew_attribution_full_path() -> f32 {
    0.0
}
fn default_ew_attribution_name_only() -> f32 {
    0.0
}
fn default_ew_attribution_missing() -> f32 {
    0.0
}

/// One secret-marker signature consumed by the secret-content scanner. When
/// the (lowercased) file body matches, the signature contributes its `label`
/// and `hits` weight to the scan result.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretContentSignatureJSON {
    /// Label inserted into the match's `secret_labels` set (e.g. `ssh`, `aws`).
    pub label: String,
    /// `"any"` => match if any marker is present; `"all"` => match only when
    /// every marker is present.
    pub mode: String,
    /// Hit weight added when the signature matches. With `per_marker`, this is
    /// added once per present marker.
    pub hits: usize,
    /// When true, each present marker independently adds `hits` (the legacy
    /// `env`-block shape). When false, the signature adds `hits` once on match.
    pub per_marker: bool,
    /// Lowercased substrings searched for in the file body.
    pub markers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CveDetectionParamsJSON {
    pub date: String,
    pub signature: String,
    pub checks: HashMap<String, CheckMetadata>,
    pub credential_harvest_min_labels: usize,
    pub secret_content_scan_max_bytes: u64,
    pub secret_content_min_hits: usize,
    pub secret_content_script_extensions: Vec<String>,
    pub secret_content_network_command_tokens: Vec<String>,
    pub secret_content_scan_excluded_path_patterns: Vec<String>,
    pub secret_content_scan_skip_extensions: Vec<String>,
    pub recent_sensitive_open_file_ttl_secs: u64,
    pub generic_reuse_tokens: Vec<String>,
    pub generic_application_tokens: Vec<String>,
    pub init_process_names: Vec<String>,
    pub ci_runner_process_name_prefixes: Vec<String>,
    pub ci_runner_workspace_path_patterns: CiRunnerWorkspacePathPatternsJSON,
    pub ci_workspace_path_patterns: Vec<String>,
    pub keychain_transactional_filename_patterns: Vec<String>,
    pub non_sensitive_browser_data_subtrees: BrowserDataSubtreesJSON,
    pub browser_appdata_unknown_writer: BrowserAppdataUnknownWriterJSON,
    pub build_output_tree_self_spawn_patterns: PlatformStringLists,
    pub suspicious_parent_path_patterns: Vec<String>,
    pub benign_temp_artifact_suffixes: Vec<String>,
    pub application_storage_patterns: Vec<String>,
    pub credential_store_patterns: PlatformStringLists,
    pub trusted_credential_helpers: PlatformHelperMatcherConfigs,
    pub packaged_application_contains_patterns: Vec<String>,
    pub packaged_application_starts_with_patterns: Vec<String>,
    pub packaged_application_ends_with_patterns: Vec<String>,
    pub managed_temp_staging_patterns: ManagedTempStagingPatternsJSON,
    pub trusted_build_temp_staging: TrustedBuildTempStagingJSON,
    pub app_self_temp_staging: AppSelfTempStagingJSON,
    pub package_manager_temp_path_patterns: PlatformStringLists,
    pub package_manager_temp_writers: PlatformStringLists,
    pub edamame_daemon_self_telemetry_writers: PlatformStringLists,
    pub edamame_daemon_self_telemetry_install_prefixes: PlatformStringLists,
    pub cloud_provider_sdk_destinations: CloudProviderSdkDestinationsJSON,
    /// Software-distribution / self-update / CDN backends that packaged
    /// desktop applications legitimately reach to fetch updates, plugin
    /// manifests, and config (FP-MAC-14). Single org-identity list:
    /// `asn_owners` (case-insensitive substring on `dst_asn.owner`),
    /// `domain_suffixes` (case-insensitive suffix), `ip_prefixes`
    /// (case-insensitive prefix). It is intentionally ONE gate of the
    /// `software_distribution_self_update` demotion conjunction (packaged
    /// app + OS-init parent + non-credential material + zero corroboration
    /// + recognized backend); recognizing a broad CDN here is safe because
    /// it never demotes on its own.
    pub software_distribution_backends: CloudProviderSdkDestinationListJSON,
    pub platform_credential_helper_routine_destinations:
        PlatformCredentialHelperRoutineDestinationsJSON,
    pub platform_metadata_endpoints: PlatformStringLists,
    pub platform_runtime_probe_filename_patterns: PlatformStringLists,
    pub platform_self_state_directories: PlatformStringLists,
    pub platform_self_state_processes: PlatformStringLists,
    pub runtime_perfdata_paths: PlatformRuntimePerfdataPathsJSON,
    /// Informational hint to the LLM adjudicator. Per-platform process
    /// names of well-known OS system daemons whose legitimate job
    /// includes touching platform credential stores (e.g. macOS
    /// `sharingd`/`accountsd`/`apsd` syncing iCloud Keychain, Linux
    /// `dbus-daemon`/`accounts-daemon`, Windows `lsass.exe`). The
    /// vulnerability detector flags this in `FindingEvidence` so the
    /// LLM can weigh "writer is a recognized system daemon AND target
    /// is a platform credential store AND no corroboration" as benign
    /// maintenance. NOT a deterministic suppression -- a name match
    /// alone never silences a finding.
    pub known_system_daemon_credential_maintenance_hints: PlatformStringLists,
    /// Per-platform basenames of trusted OS/vendor *self-extracting
    /// installers* that unpack a worker into `%LocalAppData%\Temp\<random>\`
    /// (Windows) or an equivalent temp extraction directory and write their
    /// own payload there by design. Windows examples: `dismhost.exe` (the
    /// DISM worker copied out by `Dism.exe`/TrustedInstaller) and
    /// `wixstdba.exe` (the WiX Burn standard bootstrapper application).
    ///
    /// A basename match alone NEVER suppresses a finding -- the
    /// `file_system_tampering` detector additionally requires structural
    /// self-containment (the writer runs from a temp extraction dir AND
    /// writes into that same dir). These FIM events carry NO parent
    /// attribution, so parent-invoker attestation is impossible; the
    /// self-containment conjunction is what keeps a same-named dropper
    /// writing elsewhere alertable. See FP-WIN-3 / FP-WIN-8.
    pub trusted_self_extracting_installers: PlatformStringLists,
    /// Per-platform process basenames of trusted OS *content indexer*
    /// services (Windows Search `searchindexer.exe`/`searchprotocolhost.exe`,
    /// macOS Spotlight `mds`/`mds_stores`/`mdworker*`, Linux GNOME Tracker
    /// `tracker-*` and KDE `baloo_file*`). These daemons crawl and update
    /// index metadata over user files as a routine OS task, so a
    /// `file_system_tampering` write by one of them to a sensitive but
    /// NON-credential file (e.g. a Chromium profile's `Network` cookie-state
    /// file) is index maintenance, not exfiltration -- the indexer never
    /// egresses the bytes.
    ///
    /// A basename match alone NEVER suppresses a finding -- the
    /// `file_system_tampering` detector additionally requires the writer to
    /// run from a system binary path AND the target to NOT be a platform
    /// credential store. A same-named impostor in `%TEMP%` or an indexer
    /// touching the OS keychain / Credential Manager / keyring stays
    /// alertable. See FP-WIN-23.
    pub os_content_indexer_processes: PlatformStringLists,
    /// Path substrings that classify a file as a credential-class
    /// artifact for severity / adjudication floors. Distinct from
    /// `credential_store_patterns` (platform keychain / vault paths).
    pub credential_class_path_patterns: Vec<String>,
    /// Path roots that classify a process binary as a system binary
    /// (e.g. `/usr/bin/`, `/System/`, `C:/Windows/System32/`).
    pub system_binary_path_roots: Vec<String>,
    /// Path substrings that exclude a system-binary-root match
    /// (e.g. user-writable trees under an otherwise-system prefix).
    pub system_binary_path_excludes: Vec<String>,
    /// Destination tokens that mark a remote as a public diagnostic
    /// endpoint (e.g. `ifconfig.me`, `icanhazip.com`).
    pub public_diagnostic_destination_tokens: Vec<String>,
    /// Path prefixes for random temp scratch children (e.g. `/tmp/`,
    /// `%TEMP%/`, `AppData/Local/Temp/`).
    pub random_temp_scratch_path_prefixes: Vec<String>,
    /// Parent shell basenames whose presence under a temp path marks
    /// a temp-installer orchestration pattern.
    pub temp_installer_shell_names: Vec<String>,
    /// Identity tokens that mark a process as a packaged developer
    /// tool (IDE / SDK / package-manager helper) for FP suppression.
    pub packaged_developer_tool_identity_tokens: Vec<String>,
    pub fim_hash_size_threshold: u64,
    pub fim_temp_executable_patterns: Vec<String>,
    /// P3 publisher-attestation master switch. When `false` (the
    /// shipped default) the enrichment pipeline never invokes the
    /// platform signature check and the two publisher-attestation
    /// evidence fields stay unpopulated (unmeasured). Flipped via
    /// CloudModel once the predicate is calibrated against the FP
    /// corpus. Born-complete on the wire: a published JSON
    /// missing this key fails parse and falls back to the embedded
    /// snapshot.
    pub publisher_attestation_enabled: bool,
    /// Gate: when true, high-volume udp/53 and udp/123
    /// egress is treated as a non-routine destination (closes the
    /// BS-5/BS-6 DNS/NTP tunnel blindness that the hard "routine
    /// protocol" arm created). Default false = current behaviour;
    /// flipped via CloudModel after corpus replay.
    pub treat_high_volume_dns_ntp_as_non_routine: bool,
    /// Outbound-byte floor for the DNS/NTP non-routine gate: udp/53 or
    /// udp/123 sessions below this volume stay routine even when the
    /// gate above is enabled.
    pub dns_ntp_non_routine_min_outbound_bytes: u64,
    /// Gate: when true, the anomaly arm of the
    /// EvidenceFloor rule "anomalous AND credential-class files"
    /// requires the graded `abnormal` band (p99.75) instead of any
    /// anomaly (p99.5), so a guaranteed-base-rate suspicious grade
    /// alone can no longer pin a finding beyond LLM/CRS authority.
    /// The blacklist arm is unaffected. Default false = current
    /// behaviour.
    pub evidence_floor_requires_graded_anomaly: bool,
    /// Ambient-baseline master switch: when true the
    /// enrichment pipeline marks process identities that have recurred
    /// benignly on THIS host, feeding the `ambient_baseline_credit`
    /// evidence signal. Default false.
    pub ambient_baseline_enabled: bool,
    /// Distinct days a benign (non-corroborated, non-credential) shape
    /// must recur before it earns the ambient-baseline credit.
    pub ambient_baseline_min_recurrent_days: u64,
    /// Days after which a baseline entry that stopped recurring is
    /// pruned.
    pub ambient_baseline_ttl_days: u64,
    /// Symmetric-evidence shadow-scoring weight table. See
    /// `EvidenceWeightsJSON` for the per-field documentation. Required
    /// on the CloudModel wire: a publish that omits this field fails
    /// parse and falls back to the embedded snapshot (born complete).
    pub evidence_weights: EvidenceWeightsJSON,
    /// PowerShell read-only probe verbs. Their presence in a script body
    /// marks the file as a system-probe (recon) script for the
    /// secret-content scanner.
    pub secret_content_powershell_probe_read_verbs: Vec<String>,
    /// PowerShell / shell verbs that disqualify a script from the benign
    /// read-only-probe classification (download, exec, registry/firewall
    /// mutation, base64 decode, raw netcat, ...).
    pub secret_content_powershell_dangerous_verbs: Vec<String>,
    /// Secret-marker signatures (SSH/AWS/kube/git PEM headers, env
    /// `token=`/`secret=` markers) the secret-content scanner searches for.
    pub secret_content_signatures: Vec<SecretContentSignatureJSON>,
}

fn normalize_runtime_perfdata_entry(entry: &RuntimePerfdataEntryJSON) -> RuntimePerfdataEntryJSON {
    RuntimePerfdataEntryJSON {
        artifact_path_substring: entry
            .artifact_path_substring
            .to_ascii_lowercase()
            .replace('\\', "/"),
        writer_basenames: entry
            .writer_basenames
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect(),
        writer_path_prefixes: entry
            .writer_path_prefixes
            .iter()
            .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
            .collect(),
    }
}

/// Lowercase every entry of a cloud-provider SDK destination list for
/// the snapshot (matching is done against lowercased session fields).
fn lowercase_cloud_provider_sdk_destination_list(
    list: &CloudProviderSdkDestinationListJSON,
) -> CloudProviderSdkDestinationListJSON {
    CloudProviderSdkDestinationListJSON {
        asn_owners: list
            .asn_owners
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect(),
        domain_suffixes: list
            .domain_suffixes
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect(),
        ip_prefixes: list
            .ip_prefixes
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect(),
    }
}

#[derive(Clone)]
pub struct CveDetectionParams {
    pub date: String,
    pub signature: String,
    pub checks: HashMap<String, CheckMetadata>,
    pub credential_harvest_min_labels: usize,
    pub secret_content_scan_max_bytes: u64,
    pub secret_content_min_hits: usize,
    pub secret_content_script_extensions: Vec<String>,
    pub secret_content_network_command_tokens: Vec<String>,
    pub secret_content_scan_excluded_path_patterns: Vec<String>,
    pub secret_content_scan_skip_extensions: Vec<String>,
    pub recent_sensitive_open_file_ttl_secs: u64,
    pub generic_reuse_tokens: HashSet<String>,
    pub generic_application_tokens: HashSet<String>,
    pub init_process_names: HashSet<String>,
    pub ci_runner_process_name_prefixes: Vec<String>,
    pub ci_runner_workspace_path_patterns: CiRunnerWorkspacePathPatternsJSON,
    pub ci_workspace_path_patterns: Vec<String>,
    pub keychain_transactional_filename_patterns: Vec<String>,
    pub non_sensitive_browser_data_subtrees: BrowserDataSubtreesJSON,
    pub browser_appdata_unknown_writer: BrowserAppdataUnknownWriterJSON,
    pub build_output_tree_self_spawn_patterns: PlatformStringLists,
    pub suspicious_parent_path_patterns: Vec<String>,
    pub benign_temp_artifact_suffixes: Vec<String>,
    pub application_storage_patterns: Vec<String>,
    pub credential_store_patterns: PlatformStringLists,
    pub trusted_credential_helpers: PlatformHelperMatcherConfigs,
    pub packaged_application_contains_patterns: Vec<String>,
    pub packaged_application_starts_with_patterns: Vec<String>,
    pub packaged_application_ends_with_patterns: Vec<String>,
    pub managed_temp_staging_patterns: ManagedTempStagingPatternsJSON,
    pub trusted_build_temp_staging: TrustedBuildTempStagingJSON,
    pub app_self_temp_staging: AppSelfTempStagingJSON,
    pub package_manager_temp_path_patterns: PlatformStringLists,
    pub package_manager_temp_writers: PlatformStringLists,
    pub edamame_daemon_self_telemetry_writers: PlatformStringLists,
    pub edamame_daemon_self_telemetry_install_prefixes: PlatformStringLists,
    pub platform_credential_helper_routine_destinations:
        PlatformCredentialHelperRoutineDestinationsJSON,
    pub cloud_provider_sdk_destinations: CloudProviderSdkDestinationsJSON,
    pub software_distribution_backends: CloudProviderSdkDestinationListJSON,
    pub platform_metadata_endpoints: PlatformStringLists,
    pub platform_runtime_probe_filename_patterns: PlatformStringLists,
    pub platform_self_state_directories: PlatformStringLists,
    pub platform_self_state_processes: PlatformStringLists,
    pub runtime_perfdata_paths: PlatformRuntimePerfdataPathsJSON,
    pub known_system_daemon_credential_maintenance_hints: PlatformStringLists,
    pub trusted_self_extracting_installers: PlatformStringLists,
    pub os_content_indexer_processes: PlatformStringLists,
    pub credential_class_path_patterns: Vec<String>,
    pub system_binary_path_roots: Vec<String>,
    pub system_binary_path_excludes: Vec<String>,
    pub public_diagnostic_destination_tokens: Vec<String>,
    pub random_temp_scratch_path_prefixes: Vec<String>,
    pub temp_installer_shell_names: Vec<String>,
    pub packaged_developer_tool_identity_tokens: Vec<String>,
    pub fim_hash_size_threshold: u64,
    pub fim_temp_executable_patterns: Vec<String>,
    /// P3 publisher-attestation master switch. When `false` (the
    /// shipped default) the enrichment pipeline never invokes the
    /// platform signature check and the two publisher-attestation
    /// evidence fields stay unpopulated (unmeasured). Flipped via
    /// CloudModel once the predicate is calibrated against the FP
    /// corpus. Born-complete on the wire: a published JSON
    /// missing this key fails parse and falls back to the embedded
    /// snapshot.
    pub publisher_attestation_enabled: bool,
    /// Gate: when true, high-volume udp/53 and udp/123
    /// egress is treated as a non-routine destination (closes the
    /// BS-5/BS-6 DNS/NTP tunnel blindness that the hard "routine
    /// protocol" arm created). Default false = current behaviour;
    /// flipped via CloudModel after corpus replay.
    pub treat_high_volume_dns_ntp_as_non_routine: bool,
    /// Outbound-byte floor for the DNS/NTP non-routine gate: udp/53 or
    /// udp/123 sessions below this volume stay routine even when the
    /// gate above is enabled.
    pub dns_ntp_non_routine_min_outbound_bytes: u64,
    /// Gate: when true, the anomaly arm of the
    /// EvidenceFloor rule "anomalous AND credential-class files"
    /// requires the graded `abnormal` band (p99.75) instead of any
    /// anomaly (p99.5), so a guaranteed-base-rate suspicious grade
    /// alone can no longer pin a finding beyond LLM/CRS authority.
    /// The blacklist arm is unaffected. Default false = current
    /// behaviour.
    pub evidence_floor_requires_graded_anomaly: bool,
    /// Ambient-baseline master switch: when true the
    /// enrichment pipeline marks process identities that have recurred
    /// benignly on THIS host, feeding the `ambient_baseline_credit`
    /// evidence signal. Default false.
    pub ambient_baseline_enabled: bool,
    /// Distinct days a benign (non-corroborated, non-credential) shape
    /// must recur before it earns the ambient-baseline credit.
    pub ambient_baseline_min_recurrent_days: u64,
    /// Days after which a baseline entry that stopped recurring is
    /// pruned.
    pub ambient_baseline_ttl_days: u64,
    pub evidence_weights: EvidenceWeightsJSON,
    pub secret_content_powershell_probe_read_verbs: Vec<String>,
    pub secret_content_powershell_dangerous_verbs: Vec<String>,
    pub secret_content_signatures: Vec<SecretContentSignatureJSON>,
}

impl CloudSignature for CveDetectionParams {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

fn normalize_platform_string_lists_patterns(lists: &PlatformStringLists) -> PlatformStringLists {
    PlatformStringLists {
        macos: lists
            .macos
            .iter()
            .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
            .collect(),
        linux: lists
            .linux
            .iter()
            .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
            .collect(),
        windows: lists
            .windows
            .iter()
            .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
            .collect(),
    }
}

fn normalize_managed_temp_staging_patterns(
    patterns: &ManagedTempStagingPatternsJSON,
) -> ManagedTempStagingPatternsJSON {
    ManagedTempStagingPatternsJSON {
        suppress_path_patterns: normalize_platform_string_lists_patterns(
            &patterns.suppress_path_patterns,
        ),
        demote_path_patterns: normalize_platform_string_lists_patterns(
            &patterns.demote_path_patterns,
        ),
    }
}

fn normalize_trusted_build_temp_staging(
    patterns: &TrustedBuildTempStagingJSON,
) -> TrustedBuildTempStagingJSON {
    TrustedBuildTempStagingJSON {
        writer_path_patterns: normalize_platform_string_lists_patterns(
            &patterns.writer_path_patterns,
        ),
        artifact_path_patterns: normalize_platform_string_lists_patterns(
            &patterns.artifact_path_patterns,
        ),
    }
}

fn normalize_app_self_temp_staging_entry(
    entry: &AppSelfTempStagingEntryJSON,
) -> AppSelfTempStagingEntryJSON {
    AppSelfTempStagingEntryJSON {
        name: entry.name.clone(),
        writer_path_patterns: entry
            .writer_path_patterns
            .iter()
            .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
            .collect(),
        target_path_patterns: entry
            .target_path_patterns
            .iter()
            .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
            .collect(),
    }
}

fn normalize_app_self_temp_staging(patterns: &AppSelfTempStagingJSON) -> AppSelfTempStagingJSON {
    AppSelfTempStagingJSON {
        macos: patterns
            .macos
            .iter()
            .map(normalize_app_self_temp_staging_entry)
            .collect(),
        linux: patterns
            .linux
            .iter()
            .map(normalize_app_self_temp_staging_entry)
            .collect(),
        windows: patterns
            .windows
            .iter()
            .map(normalize_app_self_temp_staging_entry)
            .collect(),
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
            secret_content_script_extensions: json
                .secret_content_script_extensions
                .iter()
                .map(|ext| ext.to_ascii_lowercase())
                .collect(),
            secret_content_network_command_tokens: json
                .secret_content_network_command_tokens
                .iter()
                .map(|tok| tok.to_ascii_lowercase())
                .collect(),
            secret_content_scan_excluded_path_patterns: json
                .secret_content_scan_excluded_path_patterns
                .iter()
                .map(|pat| pat.to_ascii_lowercase().replace('\\', "/"))
                .collect(),
            secret_content_scan_skip_extensions: json
                .secret_content_scan_skip_extensions
                .iter()
                .map(|ext| ext.to_ascii_lowercase())
                .collect(),
            recent_sensitive_open_file_ttl_secs: json.recent_sensitive_open_file_ttl_secs,
            generic_reuse_tokens: json.generic_reuse_tokens.iter().cloned().collect(),
            generic_application_tokens: json.generic_application_tokens.iter().cloned().collect(),
            init_process_names: json.init_process_names.iter().cloned().collect(),
            ci_runner_process_name_prefixes: json
                .ci_runner_process_name_prefixes
                .iter()
                .map(|prefix| prefix.to_ascii_lowercase())
                .collect(),
            ci_runner_workspace_path_patterns: CiRunnerWorkspacePathPatternsJSON {
                path_substrings: json
                    .ci_runner_workspace_path_patterns
                    .path_substrings
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                suppressible_basenames: json
                    .ci_runner_workspace_path_patterns
                    .suppressible_basenames
                    .iter()
                    .map(|b| b.to_ascii_lowercase())
                    .collect(),
            },
            ci_workspace_path_patterns: json
                .ci_workspace_path_patterns
                .iter()
                .map(|pattern| pattern.to_ascii_lowercase())
                .collect(),
            keychain_transactional_filename_patterns: json
                .keychain_transactional_filename_patterns
                .iter()
                .map(|pattern| pattern.to_ascii_lowercase())
                .collect(),
            non_sensitive_browser_data_subtrees: BrowserDataSubtreesJSON {
                chromium_family: json
                    .non_sensitive_browser_data_subtrees
                    .chromium_family
                    .iter()
                    .map(|p| p.to_ascii_lowercase())
                    .collect(),
                chromium_state_files_routine: json
                    .non_sensitive_browser_data_subtrees
                    .chromium_state_files_routine
                    .iter()
                    .map(|p| p.to_ascii_lowercase())
                    .collect(),
                chromium_profile_state_volatile: json
                    .non_sensitive_browser_data_subtrees
                    .chromium_profile_state_volatile
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                chromium_user_data_root_markers: json
                    .non_sensitive_browser_data_subtrees
                    .chromium_user_data_root_markers
                    .iter()
                    .map(|p| p.to_ascii_lowercase())
                    .collect(),
                firefox_family_subtrees: json
                    .non_sensitive_browser_data_subtrees
                    .firefox_family_subtrees
                    .iter()
                    .map(|p| p.to_ascii_lowercase())
                    .collect(),
                firefox_profile_state_volatile: json
                    .non_sensitive_browser_data_subtrees
                    .firefox_profile_state_volatile
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                firefox_user_data_root_markers: json
                    .non_sensitive_browser_data_subtrees
                    .firefox_user_data_root_markers
                    .iter()
                    .map(|p| p.to_ascii_lowercase())
                    .collect(),
            },
            browser_appdata_unknown_writer: BrowserAppdataUnknownWriterJSON {
                chromium_user_data_root_markers: json
                    .browser_appdata_unknown_writer
                    .chromium_user_data_root_markers
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                firefox_user_data_root_markers: json
                    .browser_appdata_unknown_writer
                    .firefox_user_data_root_markers
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                chromium_process_names: json
                    .browser_appdata_unknown_writer
                    .chromium_process_names
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                firefox_process_names: json
                    .browser_appdata_unknown_writer
                    .firefox_process_names
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                directory_target_names: json
                    .browser_appdata_unknown_writer
                    .directory_target_names
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
            },
            build_output_tree_self_spawn_patterns: PlatformStringLists {
                macos: json
                    .build_output_tree_self_spawn_patterns
                    .macos
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                linux: json
                    .build_output_tree_self_spawn_patterns
                    .linux
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                windows: json
                    .build_output_tree_self_spawn_patterns
                    .windows
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
            },
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
            managed_temp_staging_patterns: normalize_managed_temp_staging_patterns(
                &json.managed_temp_staging_patterns,
            ),
            trusted_build_temp_staging: normalize_trusted_build_temp_staging(
                &json.trusted_build_temp_staging,
            ),
            app_self_temp_staging: normalize_app_self_temp_staging(&json.app_self_temp_staging),
            package_manager_temp_path_patterns: PlatformStringLists {
                macos: json
                    .package_manager_temp_path_patterns
                    .macos
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                linux: json
                    .package_manager_temp_path_patterns
                    .linux
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                windows: json
                    .package_manager_temp_path_patterns
                    .windows
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
            },
            package_manager_temp_writers: PlatformStringLists {
                macos: json
                    .package_manager_temp_writers
                    .macos
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                linux: json
                    .package_manager_temp_writers
                    .linux
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                windows: json
                    .package_manager_temp_writers
                    .windows
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
            },
            edamame_daemon_self_telemetry_writers: PlatformStringLists {
                macos: json
                    .edamame_daemon_self_telemetry_writers
                    .macos
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                linux: json
                    .edamame_daemon_self_telemetry_writers
                    .linux
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                windows: json
                    .edamame_daemon_self_telemetry_writers
                    .windows
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
            },
            edamame_daemon_self_telemetry_install_prefixes: PlatformStringLists {
                macos: json
                    .edamame_daemon_self_telemetry_install_prefixes
                    .macos
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                linux: json
                    .edamame_daemon_self_telemetry_install_prefixes
                    .linux
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                windows: json
                    .edamame_daemon_self_telemetry_install_prefixes
                    .windows
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
            },
            platform_credential_helper_routine_destinations:
                PlatformCredentialHelperRoutineDestinationsJSON {
                    macos: CredentialHelperDestinationListJSON {
                        asn_owners: json
                            .platform_credential_helper_routine_destinations
                            .macos
                            .asn_owners
                            .iter()
                            .map(|s| s.to_ascii_lowercase())
                            .collect(),
                        domain_patterns: json
                            .platform_credential_helper_routine_destinations
                            .macos
                            .domain_patterns
                            .iter()
                            .map(|s| s.to_ascii_lowercase())
                            .collect(),
                        ip_prefixes: json
                            .platform_credential_helper_routine_destinations
                            .macos
                            .ip_prefixes
                            .iter()
                            .map(|s| s.to_ascii_lowercase())
                            .collect(),
                    },
                    linux: CredentialHelperDestinationListJSON {
                        asn_owners: json
                            .platform_credential_helper_routine_destinations
                            .linux
                            .asn_owners
                            .iter()
                            .map(|s| s.to_ascii_lowercase())
                            .collect(),
                        domain_patterns: json
                            .platform_credential_helper_routine_destinations
                            .linux
                            .domain_patterns
                            .iter()
                            .map(|s| s.to_ascii_lowercase())
                            .collect(),
                        ip_prefixes: json
                            .platform_credential_helper_routine_destinations
                            .linux
                            .ip_prefixes
                            .iter()
                            .map(|s| s.to_ascii_lowercase())
                            .collect(),
                    },
                    windows: CredentialHelperDestinationListJSON {
                        asn_owners: json
                            .platform_credential_helper_routine_destinations
                            .windows
                            .asn_owners
                            .iter()
                            .map(|s| s.to_ascii_lowercase())
                            .collect(),
                        domain_patterns: json
                            .platform_credential_helper_routine_destinations
                            .windows
                            .domain_patterns
                            .iter()
                            .map(|s| s.to_ascii_lowercase())
                            .collect(),
                        ip_prefixes: json
                            .platform_credential_helper_routine_destinations
                            .windows
                            .ip_prefixes
                            .iter()
                            .map(|s| s.to_ascii_lowercase())
                            .collect(),
                    },
                },
            cloud_provider_sdk_destinations: CloudProviderSdkDestinationsJSON {
                aws: lowercase_cloud_provider_sdk_destination_list(
                    &json.cloud_provider_sdk_destinations.aws,
                ),
                azure: lowercase_cloud_provider_sdk_destination_list(
                    &json.cloud_provider_sdk_destinations.azure,
                ),
                gcp: lowercase_cloud_provider_sdk_destination_list(
                    &json.cloud_provider_sdk_destinations.gcp,
                ),
            },
            software_distribution_backends: lowercase_cloud_provider_sdk_destination_list(
                &json.software_distribution_backends,
            ),
            platform_metadata_endpoints: PlatformStringLists {
                macos: json
                    .platform_metadata_endpoints
                    .macos
                    .iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                linux: json
                    .platform_metadata_endpoints
                    .linux
                    .iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                windows: json
                    .platform_metadata_endpoints
                    .windows
                    .iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            },
            platform_runtime_probe_filename_patterns: PlatformStringLists {
                macos: json
                    .platform_runtime_probe_filename_patterns
                    .macos
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                linux: json
                    .platform_runtime_probe_filename_patterns
                    .linux
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                windows: json
                    .platform_runtime_probe_filename_patterns
                    .windows
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
            },
            platform_self_state_directories: PlatformStringLists {
                macos: json
                    .platform_self_state_directories
                    .macos
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                linux: json
                    .platform_self_state_directories
                    .linux
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                windows: json
                    .platform_self_state_directories
                    .windows
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
            },
            platform_self_state_processes: PlatformStringLists {
                macos: json
                    .platform_self_state_processes
                    .macos
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                linux: json
                    .platform_self_state_processes
                    .linux
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
                windows: json
                    .platform_self_state_processes
                    .windows
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect(),
            },
            runtime_perfdata_paths: PlatformRuntimePerfdataPathsJSON {
                macos: json
                    .runtime_perfdata_paths
                    .macos
                    .iter()
                    .map(normalize_runtime_perfdata_entry)
                    .collect(),
                linux: json
                    .runtime_perfdata_paths
                    .linux
                    .iter()
                    .map(normalize_runtime_perfdata_entry)
                    .collect(),
                windows: json
                    .runtime_perfdata_paths
                    .windows
                    .iter()
                    .map(normalize_runtime_perfdata_entry)
                    .collect(),
            },
            known_system_daemon_credential_maintenance_hints: PlatformStringLists {
                macos: json
                    .known_system_daemon_credential_maintenance_hints
                    .macos
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
                linux: json
                    .known_system_daemon_credential_maintenance_hints
                    .linux
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
                windows: json
                    .known_system_daemon_credential_maintenance_hints
                    .windows
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
            },
            trusted_self_extracting_installers: PlatformStringLists {
                macos: json
                    .trusted_self_extracting_installers
                    .macos
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
                linux: json
                    .trusted_self_extracting_installers
                    .linux
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
                windows: json
                    .trusted_self_extracting_installers
                    .windows
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
            },
            os_content_indexer_processes: PlatformStringLists {
                macos: json
                    .os_content_indexer_processes
                    .macos
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
                linux: json
                    .os_content_indexer_processes
                    .linux
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
                windows: json
                    .os_content_indexer_processes
                    .windows
                    .iter()
                    .map(|name| name.to_ascii_lowercase())
                    .collect(),
            },
            credential_class_path_patterns: json
                .credential_class_path_patterns
                .iter()
                .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                .collect(),
            system_binary_path_roots: json
                .system_binary_path_roots
                .iter()
                .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                .collect(),
            system_binary_path_excludes: json
                .system_binary_path_excludes
                .iter()
                .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                .collect(),
            public_diagnostic_destination_tokens: json
                .public_diagnostic_destination_tokens
                .iter()
                .map(|t| t.to_ascii_lowercase())
                .collect(),
            random_temp_scratch_path_prefixes: json
                .random_temp_scratch_path_prefixes
                .iter()
                .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                .collect(),
            temp_installer_shell_names: json
                .temp_installer_shell_names
                .iter()
                .map(|n| n.to_ascii_lowercase())
                .collect(),
            packaged_developer_tool_identity_tokens: json
                .packaged_developer_tool_identity_tokens
                .iter()
                .map(|t| t.to_ascii_lowercase())
                .collect(),
            fim_hash_size_threshold: json.fim_hash_size_threshold,
            publisher_attestation_enabled: json.publisher_attestation_enabled,
            treat_high_volume_dns_ntp_as_non_routine: json.treat_high_volume_dns_ntp_as_non_routine,
            dns_ntp_non_routine_min_outbound_bytes: json.dns_ntp_non_routine_min_outbound_bytes,
            evidence_floor_requires_graded_anomaly: json.evidence_floor_requires_graded_anomaly,
            ambient_baseline_enabled: json.ambient_baseline_enabled,
            ambient_baseline_min_recurrent_days: json.ambient_baseline_min_recurrent_days,
            ambient_baseline_ttl_days: json.ambient_baseline_ttl_days,
            fim_temp_executable_patterns: json.fim_temp_executable_patterns.clone(),
            evidence_weights: json.evidence_weights.clone(),
            secret_content_powershell_probe_read_verbs: json
                .secret_content_powershell_probe_read_verbs
                .iter()
                .map(|v| v.to_ascii_lowercase())
                .collect(),
            secret_content_powershell_dangerous_verbs: json
                .secret_content_powershell_dangerous_verbs
                .iter()
                .map(|v| v.to_ascii_lowercase())
                .collect(),
            secret_content_signatures: json
                .secret_content_signatures
                .iter()
                .map(|sig| SecretContentSignatureJSON {
                    label: sig.label.clone(),
                    mode: sig.mode.to_ascii_lowercase(),
                    hits: sig.hits,
                    per_marker: sig.per_marker,
                    markers: sig.markers.iter().map(|m| m.to_ascii_lowercase()).collect(),
                })
                .collect(),
        }
    }

    pub fn check_metadata(&self, check_name: &str) -> Option<&CheckMetadata> {
        self.checks.get(check_name)
    }
}

fn build_fallback_params() -> CveDetectionParams {
    // CVE_DETECTION_PARAMS_DB is now an obfuscated Lazy<String>; deref
    // through the Lazy to get a `&str` for from_str.
    let json: CveDetectionParamsJSON = serde_json::from_str(&CVE_DETECTION_PARAMS_DB)
        .expect("Built-in cve-detection-params-db.json must be valid");
    CveDetectionParams::new_from_json(&json)
}

lazy_static! {
    pub static ref CVE_PARAMS: CloudModel<CveDetectionParams> = {
        let model = CloudModel::initialize(
            CVE_PARAMS_NAME.to_string(),
            &CVE_DETECTION_PARAMS_DB,
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

/// Returns true if `name` is in the per-platform
/// `known_system_daemon_credential_maintenance_hints` list. Match is
/// case-insensitive on the basename (stripping any directory prefix).
///
/// This is an **informational signal** for the LLM adjudicator. It
/// answers: "the writer process name looks like a recognized OS
/// system daemon whose legitimate maintenance work includes touching
/// platform credential stores". The match alone never suppresses a
/// finding -- the LLM still adjudicates KEEP/DEMOTE/SUPPRESS in the
/// context of corroboration (anomaly, blacklist, suspicious lineage).
pub fn is_known_system_daemon_credential_maintenance_hint(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return false;
    }
    let basename = trimmed
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    let params = PARAMS_SNAPSHOT.load();
    let lists = &params.known_system_daemon_credential_maintenance_hints;
    lists
        .macos
        .iter()
        .chain(lists.linux.iter())
        .chain(lists.windows.iter())
        .any(|hint| !hint.is_empty() && hint == &basename)
}

/// Returns true if `name` is in the per-platform
/// `trusted_self_extracting_installers` list. Match is case-insensitive
/// on the basename (stripping any directory prefix).
///
/// This is a NECESSARY but not SUFFICIENT condition for
/// `file_system_tampering` suppression. The detector additionally requires
/// structural self-containment (the writer runs from a temp extraction dir
/// AND writes only into that same dir subtree). A same-named dropper that
/// writes its payload elsewhere does NOT satisfy self-containment and stays
/// alertable. See FP-WIN-3 / FP-WIN-8.
pub fn is_trusted_self_extracting_installer(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return false;
    }
    let basename = trimmed
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    let params = PARAMS_SNAPSHOT.load();
    let lists = &params.trusted_self_extracting_installers;
    lists
        .macos
        .iter()
        .chain(lists.linux.iter())
        .chain(lists.windows.iter())
        .any(|entry| !entry.is_empty() && entry == &basename)
}

/// Returns true if `name` is in the per-platform
/// `os_content_indexer_processes` list. Match is case-insensitive on the
/// basename (stripping any directory prefix).
///
/// This is a NECESSARY but not SUFFICIENT condition for
/// `file_system_tampering` demotion. The detector additionally requires
/// the writer to run from a system binary path AND the sensitive target
/// to NOT be a platform credential store, so a same-named impostor in
/// `%TEMP%` or an indexer touching the OS keychain stays alertable.
/// See FP-WIN-23.
pub fn is_os_content_indexer_process(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return false;
    }
    let basename = trimmed
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    let params = PARAMS_SNAPSHOT.load();
    let lists = &params.os_content_indexer_processes;
    lists
        .macos
        .iter()
        .chain(lists.linux.iter())
        .chain(lists.windows.iter())
        .any(|entry| !entry.is_empty() && entry == &basename)
}

/// Returns true if `name` is a known CI runner agent or provisioning
/// daemon (e.g. GitHub Actions' `provjobd`, `Runner.Worker[.exe]`,
/// `Runner.Listener[.exe]`). The match is a case-insensitive prefix
/// check because these names carry per-run integer suffixes (e.g.
/// `provjobd2003115`, `Runner.Worker.exe1134032012`).
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

/// Returns true if `path` lies inside a directory owned by the GitHub
/// Actions runner agent (workspace, action cache, runner diagnostic
/// logs). Used to suppress `file_system_tampering` events on CI scratch
/// trees -- e.g. the repo `.env` written by `actions/checkout` or
/// runner log rotations -- which are not actionable security signals.
pub fn is_ci_workspace_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    PARAMS_SNAPSHOT
        .load()
        .ci_workspace_path_patterns
        .iter()
        .any(|pattern| !pattern.is_empty() && lower.contains(pattern))
}

/// Returns true if `path` is the canonical CI runner workspace home for
/// a `.env`-family file written by a checkout-style step (FP-CI-7).
///
/// Match semantics:
/// 1. The path's basename (final segment after the last `/` or `\`) must
///    be in `ci_runner_workspace_path_patterns.suppressible_basenames`
///    (case-insensitive exact match).
/// 2. The lowercased, forward-slash-normalized path must contain one of
///    the substrings in `ci_runner_workspace_path_patterns.path_substrings`.
///
/// The path-shape allowlist covers the canonical workspace root for
/// every supported CI provider: GitHub Actions (self-hosted +
/// hosted), GitLab CI, Jenkins, CircleCI, Buildkite, Travis,
/// TeamCity, Azure DevOps, Bitbucket Pipelines, Drone, Woodpecker,
/// Cirrus, AppVeyor, Bamboo, GoCD, Codefresh, Semaphore. Backslash
/// folding lets a single canonical forward-slash form match both POSIX
/// and Windows paths transparently.
///
/// Used by the `file_system_tampering` detector to demote (not
/// suppress) findings whose only suspicious signal is "an `.env` file
/// got written somewhere a checkout step would legitimately write
/// one". The finding still appears in the dashboard for operator
/// triage; it just no longer trips the runtime alertable gate.
pub fn is_ci_runner_workspace_committed_dotenv(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let normalized = path.to_ascii_lowercase().replace('\\', "/");
    let basename = normalized
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(&normalized);

    let snapshot = PARAMS_SNAPSHOT.load();
    let patterns = &snapshot.ci_runner_workspace_path_patterns;
    if !patterns
        .suppressible_basenames
        .iter()
        .any(|name| !name.is_empty() && basename == name.as_str())
    {
        return false;
    }
    patterns
        .path_substrings
        .iter()
        .any(|p| !p.is_empty() && normalized.contains(p))
}

/// Returns true when a process under a known build-output tree was
/// launched in a benign CI/install shape (FP-CI-6):
///
/// 1. **Self-spawn:** BOTH `process_path` AND `parent_process_path`
///    match `build_output_tree_self_spawn_patterns` (cargo/flutter/
///    gradle/Lima trees), OR
/// 2. **Trusted launcher:** `process_path` matches a build-output
///    pattern AND `parent_process_path` is an exact system privilege
///    launcher (`/usr/bin/sudo`, `/bin/sudo`, `/usr/bin/doas`, ...).
///    CI routinely runs just-built binaries via
///    `sudo /tmp/.../target/release/edamame_posture`; requiring the
///    parent to also live in the build tree missed that shape.
///
/// A `bash` from `/tmp/.hidden/` invoking a target binary still
/// returns false -- parent is neither a build-tree path nor a
/// trusted system launcher.
///
/// Matching is case-insensitive and `\` is folded to `/` before the
/// substring check, so a single canonical forward-slash form covers
/// every host OS. Per-platform lists are all consulted (the loader
/// has no way to know which OS produced the FIM event) -- there is no
/// privilege risk because all three lists are restricted to
/// well-known build-output shapes.
pub fn is_build_output_tree_self_spawn(
    process_path: Option<&str>,
    parent_process_path: Option<&str>,
) -> bool {
    let proc = match process_path {
        Some(p) if !p.is_empty() => p.to_ascii_lowercase().replace('\\', "/"),
        _ => return false,
    };
    let parent = match parent_process_path {
        Some(p) if !p.is_empty() => p.to_ascii_lowercase().replace('\\', "/"),
        _ => return false,
    };

    let snapshot = PARAMS_SNAPSHOT.load();
    let patterns = &snapshot.build_output_tree_self_spawn_patterns;
    let lists: [&Vec<String>; 3] = [&patterns.macos, &patterns.linux, &patterns.windows];

    let path_matches = |path: &str| -> bool {
        lists
            .iter()
            .any(|list| list.iter().any(|p| !p.is_empty() && path.contains(p)))
    };

    if !path_matches(&proc) {
        return false;
    }
    path_matches(&parent) || is_trusted_system_launcher_path(&parent)
}

/// Exact system privilege-launcher paths used to elevate a just-built
/// CI binary. Path-exact (not basename) so a dropper named `sudo`
/// under `/tmp/.hidden/` cannot inherit the carve-out.
fn is_trusted_system_launcher_path(parent_path: &str) -> bool {
    matches!(
        parent_path,
        "/usr/bin/sudo"
            | "/bin/sudo"
            | "/usr/bin/doas"
            | "/usr/bin/runuser"
            | "/usr/bin/systemd-run"
            | "/bin/su"
            | "/usr/bin/su"
    )
}

/// Returns true if `egress_destination_domain` and/or
/// `egress_destination_asn_owner` match the per-platform routine
/// destination allowlist for trusted credential helpers (FP-MAC-8).
///
/// Match semantics:
/// - If `domain` is non-empty, each configured `domain_patterns` entry
///   is checked. A pattern that starts with `.` (e.g.
///   `.login.microsoftonline.com`) matches any host that ends with the
///   suffix; other patterns are case-insensitive substring matches.
/// - If `ip` is non-empty, each configured `ip_prefixes` entry is
///   checked as a case-insensitive prefix. These prefixes are only for
///   vendor identity-service ranges that routinely arrive without
///   DNS/ASN enrichment in packet telemetry.
/// - If `asn_owner` is non-empty, each configured `asn_owners` entry
///   is checked as a case-insensitive substring (`Microsoft Azure`
///   matches `MICROSOFT-CORP-MSN-AS-BLOCK Microsoft Azure`).
/// - `process_name` and `process_path` are used to pick which
///   platform's allowlist to check: macOS / Windows are determined from
///   suspicious-path tokens (`/usr/libexec/`, `\system32\`, ...); when
///   no platform tokens are present, ALL configured platform lists are
///   consulted so the caller doesn't need to know which OS the helper
///   lives on.
pub fn is_platform_credential_helper_routine_destination(
    process_name: Option<&str>,
    process_path: Option<&str>,
    egress_destination_domain: Option<&str>,
    egress_destination_ip: Option<&str>,
    egress_destination_asn_owner: Option<&str>,
) -> bool {
    let domain_lower = egress_destination_domain
        .map(|d| d.to_ascii_lowercase())
        .filter(|d| !d.is_empty());
    let ip_lower = egress_destination_ip
        .map(|ip| ip.to_ascii_lowercase())
        .filter(|ip| !ip.is_empty());
    let asn_lower = egress_destination_asn_owner
        .map(|a| a.to_ascii_lowercase())
        .filter(|a| !a.is_empty());
    if domain_lower.is_none() && ip_lower.is_none() && asn_lower.is_none() {
        return false;
    }

    let snapshot = PARAMS_SNAPSHOT.load();
    let dests = &snapshot.platform_credential_helper_routine_destinations;

    let proc_path_lower = process_path
        .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
        .unwrap_or_default();
    let proc_name_lower = process_name
        .map(|n| n.to_ascii_lowercase())
        .unwrap_or_default();

    let looks_macos = proc_path_lower.starts_with("/usr/libexec/")
        || proc_path_lower.starts_with("/system/library/")
        || proc_path_lower.starts_with("/library/")
        || proc_path_lower.starts_with("/applications/")
        || proc_name_lower == "xpcproxy"
        || proc_name_lower == "securityd"
        || proc_name_lower == "cloudd";
    let looks_windows = proc_path_lower.contains("/system32/")
        || proc_path_lower.contains("/syswow64/")
        || proc_name_lower.ends_with(".exe");
    let looks_linux = proc_path_lower.starts_with("/usr/bin/")
        || proc_path_lower.starts_with("/usr/sbin/")
        || proc_path_lower.starts_with("/usr/lib/")
        || proc_name_lower == "gnome-keyring-daemon"
        || proc_name_lower.starts_with("kwalletd");

    let mut candidate_lists: Vec<&CredentialHelperDestinationListJSON> = Vec::new();
    if looks_macos {
        candidate_lists.push(&dests.macos);
    }
    if looks_linux {
        candidate_lists.push(&dests.linux);
    }
    if looks_windows {
        candidate_lists.push(&dests.windows);
    }
    if candidate_lists.is_empty() {
        // Unknown platform shape -- consult all three lists (safe; each
        // is constrained to that OS's canonical credential-validation
        // backends, not arbitrary destinations).
        candidate_lists.push(&dests.macos);
        candidate_lists.push(&dests.linux);
        candidate_lists.push(&dests.windows);
    }

    candidate_lists.iter().any(|list| {
        if let Some(domain) = domain_lower.as_deref() {
            for pattern in &list.domain_patterns {
                if pattern.is_empty() {
                    continue;
                }
                if pattern.starts_with('.') {
                    let suffix = &pattern[1..];
                    if domain == suffix
                        || domain.ends_with(pattern.as_str())
                        || domain.ends_with(&format!(".{suffix}"))
                    {
                        return true;
                    }
                } else if domain.contains(pattern) {
                    return true;
                }
            }
        }
        if let Some(asn) = asn_lower.as_deref() {
            for owner in &list.asn_owners {
                if !owner.is_empty() && asn.contains(owner) {
                    return true;
                }
            }
        }
        if let Some(ip) = ip_lower.as_deref() {
            for prefix in &list.ip_prefixes {
                if !prefix.is_empty() && ip.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    })
}

fn cloud_provider_sdk_list_for_label<'a>(
    dests: &'a CloudProviderSdkDestinationsJSON,
    label: &str,
) -> Option<&'a CloudProviderSdkDestinationListJSON> {
    match label.to_ascii_lowercase().as_str() {
        "aws" => Some(&dests.aws),
        "azure" => Some(&dests.azure),
        "gcp" => Some(&dests.gcp),
        _ => None,
    }
}

/// True when `label` is a sensitive-path label that names a cloud
/// provider with a configured (non-empty) SDK-destination policy. Used
/// by the `cloud_provider_sdk_self_auth` token-exfiltration demotion to
/// decide whether a finding's single credential family is a known
/// cloud provider. An operator who clears a provider's destination list
/// in the tunable disables the demotion for that provider (the label is
/// then no longer "known"), so the feature is fully data-driven.
pub fn is_known_cloud_provider_sdk_label(label: &str) -> bool {
    let snapshot = PARAMS_SNAPSHOT.load();
    cloud_provider_sdk_list_for_label(&snapshot.cloud_provider_sdk_destinations, label)
        .map(|list| {
            !list.asn_owners.is_empty()
                || !list.domain_suffixes.is_empty()
                || !list.ip_prefixes.is_empty()
        })
        .unwrap_or(false)
}

/// True when the egress destination belongs to the cloud provider named
/// by `provider_label`'s configured SDK-destination list. Matching is:
///
/// - `domain_suffixes`: every configured entry begins with `.`; a host
///   matches when it equals the suffix without the leading dot OR ends
///   with the suffix. The leading dot defeats the `evil-amazonaws.com`
///   bypass (it does not end with `.amazonaws.com`).
/// - `asn_owners`: case-insensitive substring (so a bare-IP Bedrock
///   session whose `dst_asn.owner` is `AMAZON-02 Amazon.com, Inc.`
///   matches `amazon`).
/// - `ip_prefixes`: case-insensitive prefix (for ranges that arrive
///   without DNS/ASN enrichment).
///
/// Returns false when the provider label is unknown or when every
/// destination field is empty.
pub fn cloud_provider_sdk_destination_matches(
    provider_label: &str,
    egress_destination_domain: Option<&str>,
    egress_destination_ip: Option<&str>,
    egress_destination_asn_owner: Option<&str>,
) -> bool {
    let domain_lower = egress_destination_domain
        .map(|d| d.to_ascii_lowercase())
        .filter(|d| !d.is_empty());
    let ip_lower = egress_destination_ip
        .map(|ip| ip.to_ascii_lowercase())
        .filter(|ip| !ip.is_empty());
    let asn_lower = egress_destination_asn_owner
        .map(|a| a.to_ascii_lowercase())
        .filter(|a| !a.is_empty());
    if domain_lower.is_none() && ip_lower.is_none() && asn_lower.is_none() {
        return false;
    }

    let snapshot = PARAMS_SNAPSHOT.load();
    let Some(list) = cloud_provider_sdk_list_for_label(
        &snapshot.cloud_provider_sdk_destinations,
        provider_label,
    ) else {
        return false;
    };

    if let Some(domain) = domain_lower.as_deref() {
        for suffix in &list.domain_suffixes {
            if suffix.is_empty() {
                continue;
            }
            let bare = suffix.strip_prefix('.').unwrap_or(suffix.as_str());
            if domain == bare || domain.ends_with(suffix.as_str()) {
                return true;
            }
        }
    }
    if let Some(asn) = asn_lower.as_deref() {
        for owner in &list.asn_owners {
            if !owner.is_empty() && asn.contains(owner) {
                return true;
            }
        }
    }
    if let Some(ip) = ip_lower.as_deref() {
        for prefix in &list.ip_prefixes {
            if !prefix.is_empty() && ip.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

/// True when the egress destination belongs to a recognized
/// software-distribution / self-update / CDN backend (FP-MAC-14).
///
/// Matching mirrors `cloud_provider_sdk_destination_matches` but against
/// the single (non-provider-keyed) `software_distribution_backends` list:
/// - `domain_suffixes`: each configured entry begins with `.`; a host
///   matches when it equals the suffix without the leading dot OR ends
///   with the suffix.
/// - `asn_owners`: case-insensitive substring (so a domainless Fastly /
///   GitHub IPv6 anycast egress whose `dst_asn.owner` is `FASTLY` still
///   matches even with no reverse DNS -- the exact FP-MAC-14 shape).
/// - `ip_prefixes`: case-insensitive prefix (for ranges without
///   DNS/ASN enrichment).
///
/// This is ONE gate of the `software_distribution_self_update` demotion
/// conjunction in `edamame_core`; it never demotes a finding on its own.
/// Returns false when every destination field is empty/absent or the
/// configured list is empty.
pub fn is_software_distribution_backend(
    egress_destination_domain: Option<&str>,
    egress_destination_ip: Option<&str>,
    egress_destination_asn_owner: Option<&str>,
) -> bool {
    let domain_lower = egress_destination_domain
        .map(|d| d.to_ascii_lowercase())
        .filter(|d| !d.is_empty());
    let ip_lower = egress_destination_ip
        .map(|ip| ip.to_ascii_lowercase())
        .filter(|ip| !ip.is_empty());
    let asn_lower = egress_destination_asn_owner
        .map(|a| a.to_ascii_lowercase())
        .filter(|a| !a.is_empty());
    if domain_lower.is_none() && ip_lower.is_none() && asn_lower.is_none() {
        return false;
    }

    let snapshot = PARAMS_SNAPSHOT.load();
    let list = &snapshot.software_distribution_backends;

    if let Some(domain) = domain_lower.as_deref() {
        for suffix in &list.domain_suffixes {
            if suffix.is_empty() {
                continue;
            }
            let bare = suffix.strip_prefix('.').unwrap_or(suffix.as_str());
            if domain == bare || domain.ends_with(suffix.as_str()) {
                return true;
            }
        }
    }
    if let Some(asn) = asn_lower.as_deref() {
        for owner in &list.asn_owners {
            if !owner.is_empty() && asn.contains(owner) {
                return true;
            }
        }
    }
    if let Some(ip) = ip_lower.as_deref() {
        for prefix in &list.ip_prefixes {
            if !prefix.is_empty() && ip.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

/// Returns true when `artifact_path`, `process_name`, and
/// `process_path` together match a JVM HotSpot perfdata write
/// (`/tmp/hsperfdata_<user>/<pid>` on Linux / macOS) authored by a
/// recognized JVM install (FP-CI-5). The detector fully suppresses
/// these `file_system_tampering` findings -- they are transient
/// performance counter files that HotSpot creates for every JVM PID,
/// never security-relevant, never editable to plant a payload.
///
/// All comparisons are case-insensitive on forward-slash-normalized
/// paths. The writer attestation is conjunctive: the artifact-path
/// substring must match AND (the writer basename matches OR the
/// writer path prefix matches a recognized JVM install location).
/// A malicious binary writing to `/tmp/hsperfdata_user/12345` from a
/// non-JVM path is NOT suppressed.
pub fn is_runtime_perfdata_self_write(
    artifact_path: &str,
    process_name: Option<&str>,
    process_path: Option<&str>,
) -> bool {
    if artifact_path.is_empty() {
        return false;
    }
    let path_lower = artifact_path.to_ascii_lowercase().replace('\\', "/");
    let proc_name_lower = process_name
        .map(|n| n.to_ascii_lowercase())
        .unwrap_or_default();
    let proc_path_lower = process_path
        .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
        .unwrap_or_default();

    let snapshot = PARAMS_SNAPSHOT.load();
    let entries = &snapshot.runtime_perfdata_paths;
    let lists: [&Vec<RuntimePerfdataEntryJSON>; 3] =
        [&entries.macos, &entries.linux, &entries.windows];

    for list in &lists {
        for entry in list.iter() {
            if entry.artifact_path_substring.is_empty()
                || !path_lower.contains(&entry.artifact_path_substring)
            {
                continue;
            }
            // Path-shape gate (FP-CI-5): for every JVM HotSpot
            // perfdata entry the basename of the artifact path MUST
            // be all decimal digits (the JVM PID). HotSpot creates
            // exactly `/tmp/hsperfdata_<user>/<pid>` -- a
            // non-numeric basename like `notdigits` is not a JVM
            // perfdata file even when the parent directory matches.
            // Without this guard an attacker could drop arbitrary
            // payloads under `/tmp/hsperfdata_*/` and have them
            // suppressed if the writer happened to be a trusted JDK.
            let basename = path_lower.rsplit('/').next().unwrap_or("");
            let basename_is_digits =
                !basename.is_empty() && basename.chars().all(|c| c.is_ascii_digit());
            if !basename_is_digits {
                continue;
            }
            // Writer attestation is **conjunctive**: BOTH the basename
            // AND the install-path prefix must match. A bare basename
            // match is too weak (a malicious `/tmp/java` writing
            // `/tmp/hsperfdata_root/12345` would otherwise be
            // suppressed). A bare install-prefix match is also too
            // weak (the prefix list spans large parent dirs like
            // `/usr/lib/jvm/`, an attacker dropping a non-`java`
            // binary into `/usr/lib/jvm/evil` would otherwise be
            // suppressed). Combined with the artifact-path-substring
            // gate above, this is the path-shape + writer-identity
            // attestation pair.
            let basename_match = !proc_name_lower.is_empty()
                && entry
                    .writer_basenames
                    .iter()
                    .any(|b| !b.is_empty() && b == &proc_name_lower);
            let prefix_match = !proc_path_lower.is_empty()
                && entry
                    .writer_path_prefixes
                    .iter()
                    .any(|p| !p.is_empty() && proc_path_lower.contains(p));
            if basename_match && prefix_match {
                return true;
            }
        }
    }
    false
}

/// Returns true if `path` is a macOS Keychain transactional artifact
/// (the short-lived sandbox/transactional copies the Security framework
/// creates on every Keychain read). Caller must already have confirmed
/// the path is under the macOS Keychain directory; this helper only
/// matches the filename suffix portion.
pub fn is_keychain_transactional_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    PARAMS_SNAPSHOT
        .load()
        .keychain_transactional_filename_patterns
        .iter()
        .any(|pattern| !pattern.is_empty() && lower.contains(pattern))
}

/// Returns true when `path` is part of a browser's recomputable cache
/// subtree or a routine atomic-rewrite state file (e.g. Chrome
/// `Code Cache/`, `Local State`, `Preferences`). Used by the
/// `file_system_tampering` detector to suppress sensitive-file FPs
/// that derive from the appdata-class inheritance rule.
///
/// Matching is conjunctive on purpose: BOTH a known browser-user-data
/// root marker AND a known cache/state subtree must be present in the
/// path. A `Code Cache/` directory anywhere else on disk is not
/// suppressed, and a non-cache file inside the browser data root is
/// not suppressed (`Login Data`, `Cookies`, `Web Data`, etc. continue
/// to fire).
pub fn is_non_sensitive_browser_data(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    // Normalize Windows backslashes to forward slashes before matching.
    // Real-world FIM events on Windows can mix separators within the
    // same path (e.g. `C:\Users\frank\AppData/Local\Google\Chrome\...`)
    // depending on which API surfaced the event. Storing both `\` and
    // `/` variants in the JSON would be brittle; normalizing once here
    // is more robust and matches how `is_ci_workspace_path` is used
    // (its patterns are stored with both variants up front, but new
    // pattern lists should prefer the normalize-then-match shape).
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    let snapshot = PARAMS_SNAPSHOT.load();
    let subtrees = &snapshot.non_sensitive_browser_data_subtrees;

    let in_chromium_root = subtrees
        .chromium_user_data_root_markers
        .iter()
        .any(|marker| !marker.is_empty() && lower.contains(marker));
    if in_chromium_root {
        let cache_match = subtrees
            .chromium_family
            .iter()
            .any(|sub| browser_subtree_path_matches(&lower, sub));
        if cache_match {
            return true;
        }
        let state_match = subtrees
            .chromium_state_files_routine
            .iter()
            .any(|state| !state.is_empty() && lower.ends_with(state));
        if state_match {
            return true;
        }
    }

    let in_firefox_root = subtrees
        .firefox_user_data_root_markers
        .iter()
        .any(|marker| !marker.is_empty() && lower.contains(marker));
    if in_firefox_root {
        let cache_match = subtrees
            .firefox_family_subtrees
            .iter()
            .any(|sub| browser_subtree_path_matches(&lower, sub));
        if cache_match {
            return true;
        }
    }

    false
}

fn browser_subtree_path_matches(lower_path: &str, pattern: &str) -> bool {
    let pattern = pattern.trim().trim_matches('/');
    if pattern.is_empty() {
        return false;
    }

    let pattern_with_separators = format!("/{}/", pattern);
    if lower_path.contains(&pattern_with_separators) {
        return true;
    }

    let pattern_suffix = format!("/{}", pattern);
    lower_path.ends_with(&pattern_suffix)
}

fn browser_profile_state_group_for_root(
    lower: &str,
    family: &str,
    root_markers: &[String],
    volatile_patterns: &[String],
) -> Option<String> {
    for marker in root_markers {
        if marker.is_empty() {
            continue;
        }
        let Some(marker_index) = lower.find(marker) else {
            continue;
        };
        let suffix = &lower[marker_index + marker.len()..];
        let segments: Vec<&str> = suffix
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        if segments.is_empty() {
            continue;
        }

        for pattern in volatile_patterns {
            let pattern_segments: Vec<&str> = pattern
                .trim_matches('/')
                .split('/')
                .filter(|segment| !segment.is_empty())
                .collect();
            if pattern_segments.is_empty() || pattern_segments.len() > segments.len() {
                continue;
            }

            for start in 0..=segments.len() - pattern_segments.len() {
                if segments[start..start + pattern_segments.len()] == pattern_segments[..] {
                    let profile = if start == 0 {
                        "root".to_string()
                    } else {
                        segments[..start].join("/")
                    };
                    return Some(format!(
                        "{}:{}:{}",
                        family,
                        profile,
                        pattern_segments.join("/")
                    ));
                }
            }
        }
    }
    None
}

/// Returns a stable browser-managed volatile-state bucket for FIM paths
/// such as Chromium `Session Storage`, `Sessions`, and `Sync Data`.
///
/// These files may contain privacy-sensitive browser state, so callers
/// should not treat them as fully non-sensitive cache. The bucket exists
/// to demote/group unknown-writer browser housekeeping bursts only when
/// an independent browser-alive signal is present; credential stores such
/// as `Login Data`, `Cookies`, and `Web Data` intentionally do not match.
pub fn browser_volatile_profile_state_group(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    let snapshot = PARAMS_SNAPSHOT.load();
    let subtrees = &snapshot.non_sensitive_browser_data_subtrees;

    browser_profile_state_group_for_root(
        &lower,
        "chromium",
        &subtrees.chromium_user_data_root_markers,
        &subtrees.chromium_profile_state_volatile,
    )
    .or_else(|| {
        browser_profile_state_group_for_root(
            &lower,
            "firefox",
            &subtrees.firefox_user_data_root_markers,
            &subtrees.firefox_profile_state_volatile,
        )
    })
}

/// Returns true if `ip` is a well-known platform metadata service
/// endpoint (Azure Wire Server, EC2/GCE Instance Metadata Service,
/// ...) on the current host's OS. Empty `ip` returns false.
///
/// Used by the `sensitive_material_egress` suppression hook
/// `should_suppress_sensitive_material_egress_as_platform_metadata_call`.
/// Match is exact -- `168.63.129.16` matches but `168.63.129.166` does
/// not.
pub fn is_platform_metadata_endpoint(ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    let snapshot = PARAMS_SNAPSHOT.load();
    let endpoints = &snapshot.platform_metadata_endpoints;
    let lists: [&Vec<String>; 3] = [&endpoints.macos, &endpoints.linux, &endpoints.windows];
    lists
        .iter()
        .any(|list| list.iter().any(|known| known == ip))
}

/// Returns true if the normalized `path` lies within one of the
/// platform-managed cloud-agent state directories (Azure Wire Agent
/// `/var/lib/waagent/`, cloud-init `/etc/cloud/`, Windows
/// `\WindowsAzure\`, ...).
///
/// Path matching is case-insensitive and tolerant of separator style:
/// the input is lowercased and `\` is folded to `/` before substring
/// matching against the configured patterns (which are also stored
/// in normalized form).
pub fn is_platform_self_state_directory(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    let snapshot = PARAMS_SNAPSHOT.load();
    let dirs = &snapshot.platform_self_state_directories;
    let lists: [&Vec<String>; 3] = [&dirs.macos, &dirs.linux, &dirs.windows];
    lists.iter().any(|list| {
        list.iter()
            .any(|pattern| !pattern.is_empty() && lower.contains(pattern))
    })
}

/// Returns true if `name` is the basename of a recognized platform
/// cloud-agent process (Azure Wire Agent, cloud-init, ...). Match is
/// case-insensitive exact-match against the configured per-OS lists.
///
/// This is intentionally exact-match (not prefix-match) because
/// platform agent names are stable; CI runner agents that need
/// prefix matching use `is_ci_runner_internal_process` instead.
pub fn is_platform_self_state_process_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    let snapshot = PARAMS_SNAPSHOT.load();
    let procs = &snapshot.platform_self_state_processes;
    let lists: [&Vec<String>; 3] = [&procs.macos, &procs.linux, &procs.windows];
    lists
        .iter()
        .any(|list| list.iter().any(|known| known == &lower))
}

/// Returns true if `name` is the basename of a recognized
/// package-manager toolchain that legitimately stages downloaded
/// dependency archives (`dart`, `npm`, `pip`, `cargo`, ...). Match
/// is case-insensitive exact-match against the configured per-OS
/// lists.
///
/// Used by the `file_system_tampering` package-manager temp-write
/// suppression hook (FP-WIN-11). The hook also requires the artifact
/// path to match `is_package_manager_temp_path` -- both gates must
/// fire so a malicious binary writing to a similarly-named
/// directory does not get a free pass.
pub fn is_package_manager_temp_writer(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    let snapshot = PARAMS_SNAPSHOT.load();
    let writers = &snapshot.package_manager_temp_writers;
    let lists: [&Vec<String>; 3] = [&writers.macos, &writers.linux, &writers.windows];
    lists
        .iter()
        .any(|list| list.iter().any(|known| known == &lower))
}

/// Returns true if `name` (a process basename, lowercased) belongs
/// to the EDAMAME daemon family: the GUI app (`edamame`,
/// `edamame_security`), the posture CLI (`edamame_posture`), or the
/// privileged helper (`edamame_helper`). Windows variants include
/// `.exe`. Comparison is case-insensitive.
///
/// Used by the deterministic `file_system_tampering` severity grader
/// to extend the FP-WIN-4 LOW-demote carve-out to allow
/// `has_external_process` when the writer is an EDAMAME daemon AND
/// the script content has no network-command tokens. This is the
/// canonical FP-WIN-15 shape (the daemon writes a `.tmp*.ps1`
/// threat-check stub into `%TEMP%` while uploading self-telemetry
/// to `hub.edamame.tech`). The conjunctive content gate prevents
/// adversary spoofing: a malicious `.tmp*.ps1` carrying `curl ...`
/// or `Invoke-WebRequest` would still fire HIGH because
/// `network_command_like` flips the gate off, regardless of
/// process attribution.
pub fn is_edamame_daemon_self_telemetry_writer(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    let snapshot = PARAMS_SNAPSHOT.load();
    let writers = &snapshot.edamame_daemon_self_telemetry_writers;
    let lists: [&Vec<String>; 3] = [&writers.macos, &writers.linux, &writers.windows];
    lists
        .iter()
        .any(|list| list.iter().any(|known| known == &lower))
}

/// Path-attested version of [`is_edamame_daemon_self_telemetry_writer`].
///
/// Empty/missing paths are accepted for backwards compatibility with older
/// attribution, but full process paths must live under a configured EDAMAME
/// install root. The only user-profile exception is the CI posture-action
/// cache (`C:\Users\{edamame,runneradmin}\edamame_posture.exe`). This keeps
/// the FP-WIN-15/18 LOW-demote from matching a spoofed `edamame.exe` dropped
/// into `%TEMP%` or a user profile.
pub fn is_edamame_daemon_self_telemetry_writer_for_path(name: &str, path: Option<&str>) -> bool {
    if !is_edamame_daemon_self_telemetry_writer(name) {
        return false;
    }

    let Some(path) = path.map(str::trim).filter(|path| !path.is_empty()) else {
        return true;
    };

    let normalized = path.to_ascii_lowercase().replace('\\', "/");
    let lower_name = name.to_ascii_lowercase();
    if normalized.starts_with("c:/users/") {
        let rest = normalized.trim_start_matches("c:/users/");
        let mut parts = rest.split('/');
        if let (Some(user), Some(file), None) = (parts.next(), parts.next(), parts.next()) {
            let known_runner_user = matches!(user, "edamame" | "runneradmin");
            if known_runner_user && file == "edamame_posture.exe" && file == lower_name {
                return true;
            }
        }
    }

    let snapshot = PARAMS_SNAPSHOT.load();
    let prefixes = &snapshot.edamame_daemon_self_telemetry_install_prefixes;
    let lists: [&Vec<String>; 3] = [&prefixes.macos, &prefixes.linux, &prefixes.windows];
    lists.iter().any(|list| {
        list.iter()
            .any(|prefix| !prefix.is_empty() && normalized.starts_with(prefix))
    })
}

pub fn browser_appdata_unknown_writer_expected_processes(path: &str) -> Vec<String> {
    if path.is_empty() {
        return Vec::new();
    }

    let normalized = path.to_ascii_lowercase().replace('\\', "/");
    let snapshot = PARAMS_SNAPSHOT.load();
    let config = &snapshot.browser_appdata_unknown_writer;

    if config
        .chromium_user_data_root_markers
        .iter()
        .any(|marker| !marker.is_empty() && normalized.contains(marker))
    {
        return config.chromium_process_names.clone();
    }

    if config
        .firefox_user_data_root_markers
        .iter()
        .any(|marker| !marker.is_empty() && normalized.contains(marker))
    {
        return config.firefox_process_names.clone();
    }

    Vec::new()
}

pub fn is_browser_appdata_unknown_writer_directory_target(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }

    if browser_appdata_unknown_writer_expected_processes(path).is_empty() {
        return false;
    }

    let leaf = path
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .trim()
        .to_ascii_lowercase();
    if leaf.is_empty() {
        return false;
    }

    PARAMS_SNAPSHOT
        .load()
        .browser_appdata_unknown_writer
        .directory_target_names
        .iter()
        .any(|name| name == &leaf)
}

/// Returns true if the normalized `path` lies within one of the
/// per-OS package-manager temp/cache working directories
/// (`%TEMP%\pub_*\`, `~/.npm/_cacache/`, `~/.cargo/registry/cache/`,
/// ...).
///
/// Path matching is case-insensitive and tolerant of separator
/// style: the input is lowercased and `\` is folded to `/` before
/// substring matching against the configured patterns (which are
/// also stored in normalized form).
///
/// Used together with `is_package_manager_temp_writer` to suppress
/// `file_system_tampering` events where a recognized toolchain
/// downloads a dependency archive into its working dir.
pub fn is_package_manager_temp_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    let snapshot = PARAMS_SNAPSHOT.load();
    let dirs = &snapshot.package_manager_temp_path_patterns;
    let lists: [&Vec<String>; 3] = [&dirs.macos, &dirs.linux, &dirs.windows];
    lists.iter().any(|list| {
        list.iter()
            .any(|pattern| !pattern.is_empty() && lower.contains(pattern))
    })
}

fn matches_platform_patterns(path: &str, dirs: &PlatformStringLists) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    let lists: [&Vec<String>; 3] = [&dirs.macos, &dirs.linux, &dirs.windows];
    lists.iter().any(|list| {
        list.iter()
            .any(|pattern| !pattern.is_empty() && lower.contains(pattern))
    })
}

/// Returns true for managed temp-staging artifacts that are specific enough to
/// suppress entirely (compiler/build-tool scratch trees such as prost-build,
/// WiX `wix-ir`, CMake populate temp, and NuGetScratch).
pub fn is_managed_temp_staging_suppressed_path(path: &str) -> bool {
    if is_linux_systemd_coredump_private_tmp(path) || is_linux_x11_runtime_artifact(path) {
        return true;
    }
    let snapshot = PARAMS_SNAPSHOT.load();
    matches_platform_patterns(
        path,
        &snapshot
            .managed_temp_staging_patterns
            .suppress_path_patterns,
    )
}

fn is_linux_systemd_coredump_private_tmp(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    (lower.starts_with("/tmp/systemd-private-") || lower.starts_with("/var/tmp/systemd-private-"))
        && lower.contains("-systemd-coredump@")
        && lower.contains(".service-")
}

fn is_ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

fn is_linux_x11_runtime_artifact(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    if let Some(display) = lower.strip_prefix("/tmp/.x11-unix/x") {
        return is_ascii_digits(display);
    }
    if let Some(display) = lower
        .strip_prefix("/tmp/.x")
        .and_then(|rest| rest.strip_suffix("-lock"))
    {
        return is_ascii_digits(display);
    }
    if let Some(display) = lower
        .strip_prefix("/tmp/.tx")
        .and_then(|rest| rest.strip_suffix("-lock"))
    {
        return is_ascii_digits(display);
    }
    if let Some(lock_id) = lower.strip_prefix("/tmp/#") {
        return is_ascii_digits(lock_id);
    }
    false
}

/// Returns true for managed temp-staging artifacts that should stay visible as
/// LOW audit evidence instead of disappearing.
pub fn is_managed_temp_staging_demoted_path(path: &str) -> bool {
    let snapshot = PARAMS_SNAPSHOT.load();
    matches_platform_patterns(
        path,
        &snapshot.managed_temp_staging_patterns.demote_path_patterns,
    )
}

/// Returns true when a trusted build/signing tool is writing its own
/// installer/signing scratch artifact under an OS temp directory. This is a
/// LOW audit signal, not a HIGH alert, because the tool's network egress is
/// expected package/signature activity.
pub fn is_trusted_build_temp_staging_artifact(path: &str, process_path: Option<&str>) -> bool {
    let Some(process_path) = process_path else {
        return false;
    };
    if path.is_empty() || process_path.is_empty() {
        return false;
    }

    let snapshot = PARAMS_SNAPSHOT.load();
    matches_platform_patterns(
        process_path,
        &snapshot.trusted_build_temp_staging.writer_path_patterns,
    ) && matches_platform_patterns(
        path,
        &snapshot.trusted_build_temp_staging.artifact_path_patterns,
    )
}

/// FP-WIN-7c -- trusted-app self-temp-staging deterministic suppression.
///
/// Returns true when `process_path` (writer) and `target_path` BOTH
/// match patterns in the SAME `AppSelfTempStagingEntryJSON` entry across
/// any platform list. The pair-wise shape is critical: collapsing the
/// writer and target pattern lists into one would suppress a malicious
/// writer that happened to write into ANY trusted target -- this
/// function requires the writer-target pair to be co-listed in a
/// single entry, so adding a new vendor only widens the trust for that
/// vendor's own paths.
///
/// Inputs are case-insensitive substring matches against the lowercased
/// path (normalization done at snapshot load time in
/// `normalize_app_self_temp_staging`).
pub fn is_app_self_temp_staging_pair(target_path: &str, process_path: &str) -> bool {
    if target_path.is_empty() || process_path.is_empty() {
        return false;
    }
    let lower_target = target_path.to_ascii_lowercase().replace('\\', "/");
    let lower_writer = process_path.to_ascii_lowercase().replace('\\', "/");

    let snapshot = PARAMS_SNAPSHOT.load();
    let lists: [&Vec<AppSelfTempStagingEntryJSON>; 3] = [
        &snapshot.app_self_temp_staging.macos,
        &snapshot.app_self_temp_staging.linux,
        &snapshot.app_self_temp_staging.windows,
    ];
    lists.iter().any(|list| {
        list.iter().any(|entry| {
            let writer_match = entry
                .writer_path_patterns
                .iter()
                .any(|p| !p.is_empty() && lower_writer.contains(p));
            if !writer_match {
                return false;
            }
            entry
                .target_path_patterns
                .iter()
                .any(|p| !p.is_empty() && lower_target.contains(p))
        })
    })
}

/// Returns true if the leaf basename of `path` starts with one of
/// the platform runtime-probe filename prefixes (e.g. Windows
/// PowerShell's `__PSScriptPolicyTest_*.ps1` execution-policy
/// probe). The probe is recognized, well-documented Microsoft
/// behaviour, NOT user activity.
///
/// Match is case-insensitive against the lowercased filename leaf
/// only; the directory portion is irrelevant. Storing the prefix
/// is sufficient because the random suffix portion has no security
/// relevance.
pub fn is_platform_runtime_probe_filename(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    // Extract leaf (basename) tolerant of both separator styles.
    let leaf = path
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    if leaf.is_empty() {
        return false;
    }
    let snapshot = PARAMS_SNAPSHOT.load();
    let probes = &snapshot.platform_runtime_probe_filename_patterns;
    let lists: [&Vec<String>; 3] = [&probes.macos, &probes.linux, &probes.windows];
    lists.iter().any(|list| {
        list.iter()
            .any(|prefix| !prefix.is_empty() && leaf.starts_with(prefix))
    })
}

pub fn suspicious_parent_path_patterns() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .suspicious_parent_path_patterns
        .clone()
}

pub fn credential_class_path_patterns() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .credential_class_path_patterns
        .clone()
}

pub fn system_binary_path_roots() -> Vec<String> {
    PARAMS_SNAPSHOT.load().system_binary_path_roots.clone()
}

pub fn system_binary_path_excludes() -> Vec<String> {
    PARAMS_SNAPSHOT.load().system_binary_path_excludes.clone()
}

pub fn public_diagnostic_destination_tokens() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .public_diagnostic_destination_tokens
        .clone()
}

pub fn random_temp_scratch_path_prefixes() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .random_temp_scratch_path_prefixes
        .clone()
}

pub fn temp_installer_shell_names() -> Vec<String> {
    PARAMS_SNAPSHOT.load().temp_installer_shell_names.clone()
}

pub fn packaged_developer_tool_identity_tokens() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .packaged_developer_tool_identity_tokens
        .clone()
}

pub fn fim_hash_size_threshold() -> u64 {
    PARAMS_SNAPSHOT.load().fim_hash_size_threshold
}

pub fn fim_temp_executable_patterns() -> Vec<String> {
    PARAMS_SNAPSHOT.load().fim_temp_executable_patterns.clone()
}

/// P3 publisher-attestation master switch (see the field doc on
/// `CveDetectionParamsJSON::publisher_attestation_enabled`). Checked by
/// the core enrichment pipeline before any signature verification runs.
pub fn publisher_attestation_enabled() -> bool {
    PARAMS_SNAPSHOT.load().publisher_attestation_enabled
}

/// DNS/NTP tunnel gate (see the field docs).
pub fn treat_high_volume_dns_ntp_as_non_routine() -> bool {
    PARAMS_SNAPSHOT.load().treat_high_volume_dns_ntp_as_non_routine
}

pub fn dns_ntp_non_routine_min_outbound_bytes() -> u64 {
    PARAMS_SNAPSHOT.load().dns_ntp_non_routine_min_outbound_bytes
}

/// Graded EvidenceFloor gate (see the field docs).
pub fn evidence_floor_requires_graded_anomaly() -> bool {
    PARAMS_SNAPSHOT.load().evidence_floor_requires_graded_anomaly
}

/// Ambient-baseline switch and tunables (see field docs).
pub fn ambient_baseline_enabled() -> bool {
    PARAMS_SNAPSHOT.load().ambient_baseline_enabled
}

pub fn ambient_baseline_min_recurrent_days() -> u64 {
    PARAMS_SNAPSHOT.load().ambient_baseline_min_recurrent_days
}

pub fn ambient_baseline_ttl_days() -> u64 {
    PARAMS_SNAPSHOT.load().ambient_baseline_ttl_days
}

/// Symmetric-evidence weight table accessor.
///
/// Returns a clone of the current `EvidenceWeightsJSON` snapshot from
/// the CloudModel. Cheap: `EvidenceWeightsJSON` is a flat set of `f32` fields,
/// no heap allocation. Callers should clone-then-reuse for the
/// duration of one detector tick rather than calling this per-finding,
/// even though both shapes are cheap.
pub fn evidence_weights() -> EvidenceWeightsJSON {
    PARAMS_SNAPSHOT.load().evidence_weights.clone()
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

/// Lowercased filename suffixes treated as "script-like" by the secret-
/// content scanner. Returned as an owned `Vec<String>` so callers can
/// hold onto the snapshot without keeping the `ArcSwap` guard alive.
pub fn secret_content_script_extensions() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .secret_content_script_extensions
        .clone()
}

/// Lowercased substrings that mark file content as "network-command-like"
/// by the secret-content scanner. Returned as an owned `Vec<String>` for
/// the same reason as `secret_content_script_extensions()`.
pub fn secret_content_network_command_tokens() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .secret_content_network_command_tokens
        .clone()
}

/// Lowercased PowerShell read-only probe verbs. Their presence marks a
/// script body as a system-probe (recon) script for the secret-content
/// scanner. Returned owned because the snapshot is swapped atomically.
pub fn secret_content_powershell_probe_read_verbs() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .secret_content_powershell_probe_read_verbs
        .clone()
}

/// Lowercased PowerShell / shell verbs that disqualify a script from the
/// benign read-only-probe classification (download, exec, registry /
/// firewall mutation, base64 decode, raw netcat, ...).
pub fn secret_content_powershell_dangerous_verbs() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .secret_content_powershell_dangerous_verbs
        .clone()
}

/// Normalized secret-marker signatures (markers and mode lowercased)
/// searched for in file bodies by the secret-content scanner.
pub fn secret_content_signatures() -> Vec<SecretContentSignatureJSON> {
    PARAMS_SNAPSHOT.load().secret_content_signatures.clone()
}

/// Lowercased, slash-normalized path substrings that mark a path as
/// "transient build-artifact, do not content-scan". Patterns live in
/// the CloudModel JSON / embedded snapshot (Win32 build-artifact
/// races, cargo/target trees, etc.); this accessor returns the
/// active snapshot slice.
pub fn secret_content_scan_excluded_path_patterns() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .secret_content_scan_excluded_path_patterns
        .clone()
}

/// Returns true when the path is in a transient build-artifact tree and
/// MUST NOT be content-scanned. This is the canonical filter the
/// vulnerability detector's content-scan candidate collector uses.
///
/// Match semantics: lowercase the path, replace `\` with `/`, then check
/// if any configured pattern is a substring of the result. The patterns
/// themselves are already normalized to lowercase + forward slashes by
/// `CveDetectionParams::new_from_json`.
pub fn is_secret_content_scan_excluded_path(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase().replace('\\', "/");
    let snapshot = PARAMS_SNAPSHOT.load();
    snapshot
        .secret_content_scan_excluded_path_patterns
        .iter()
        .any(|pattern| normalized.contains(pattern.as_str()))
}

/// Lowercased, dot-prefixed file extensions whose content is never
/// worth secret-scanning (binary / media). Values live in the
/// CloudModel JSON / embedded snapshot (avoids TCC re-prompts on
/// `~/Music` / `~/Pictures` / `~/Movies` media assets opened by
/// media/browser processes and enumerated via
/// `flodbadd::open_files`).
pub fn secret_content_scan_skip_extensions() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .secret_content_scan_skip_extensions
        .clone()
}

/// Returns true when the path's extension marks it as binary/media content
/// that MUST NOT be content-scanned. Checked BEFORE any filesystem access
/// so a media candidate is dropped without a `metadata()` / open() probe
/// (which would otherwise trigger a macOS TCC consent prompt for protected
/// media directories).
///
/// Match semantics: lowercase the path, then check whether it ends with
/// any configured extension. The extensions are already normalized to
/// lowercase by `CveDetectionParams::new_from_json`.
pub fn is_secret_content_scan_skipped_extension(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase();
    let snapshot = PARAMS_SNAPSHOT.load();
    snapshot
        .secret_content_scan_skip_extensions
        .iter()
        .any(|ext| normalized.ends_with(ext.as_str()))
}

pub fn recent_sensitive_open_file_ttl_secs() -> u64 {
    PARAMS_SNAPSHOT.load().recent_sensitive_open_file_ttl_secs
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Regression guard (helper/app/posture startup): the embedded CVE/FIM
    /// detection-params snapshot MUST decode and parse. If a bad regen of
    /// `cve_detection_params_db.rs` makes it unparseable, the `CVE_PARAMS`
    /// CloudModel `lazy_static` panics on its first deref and the daemon dies at
    /// startup. This catches it in CI instead. See also
    /// whitelists/blacklists/sensitive_paths/threats.
    #[test]
    fn test_embedded_cve_params_snapshot_parses() {
        serde_json::from_str::<CveDetectionParamsJSON>(&CVE_DETECTION_PARAMS_DB)
            .expect("embedded CVE detection params snapshot must parse as CveDetectionParamsJSON");
    }

    /// Missing required CloudModel fields must fail parse
    /// (no silent serde defaults). A published JSON that drops a field
    /// falls back to the embedded snapshot rather than zeros.
    #[test]
    fn test_cve_params_missing_required_field_fails_parse() {
        let mut value: serde_json::Value = serde_json::from_str(&CVE_DETECTION_PARAMS_DB)
            .expect("embedded snapshot is valid JSON");
        let obj = value
            .as_object_mut()
            .expect("embedded snapshot root is an object");
        assert!(
            obj.remove("evidence_weights").is_some(),
            "embedded snapshot must include evidence_weights so the removal is meaningful"
        );
        let err = serde_json::from_value::<CveDetectionParamsJSON>(value)
            .expect_err("missing evidence_weights must fail deserialize");
        let msg = err.to_string();
        assert!(
            msg.contains("evidence_weights") || msg.contains("missing field"),
            "error should name the missing field, got: {msg}"
        );
    }

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

    // FP-WS-1: cloud-provider SDK destination accessors backing the
    // `cloud_provider_sdk_self_auth` demotion (Claude Code on Bedrock /
    // Vertex / Azure-OpenAI reading ~/.aws|~/.config/gcloud|az creds).
    #[test]
    fn test_is_known_cloud_provider_sdk_label() {
        // The embedded snapshot ships non-empty aws/azure/gcp lists, so
        // each provider label is "known" (case-insensitive).
        assert!(is_known_cloud_provider_sdk_label("aws"));
        assert!(is_known_cloud_provider_sdk_label("AWS"));
        assert!(is_known_cloud_provider_sdk_label("azure"));
        assert!(is_known_cloud_provider_sdk_label("gcp"));
        // Anything that is not a configured provider key is not "known",
        // so the demotion never fires for it.
        assert!(!is_known_cloud_provider_sdk_label("ssh"));
        assert!(!is_known_cloud_provider_sdk_label("generic_credential"));
        assert!(!is_known_cloud_provider_sdk_label(""));
    }

    #[test]
    fn test_cloud_provider_sdk_destination_matches_domain_suffix() {
        // Bedrock control-plane domain ends with .amazonaws.com.
        assert!(cloud_provider_sdk_destination_matches(
            "aws",
            Some("bedrock-runtime.us-east-1.amazonaws.com"),
            None,
            None,
        ));
        // Leading-dot anti-bypass: evil-amazonaws.com does NOT end with
        // ".amazonaws.com" so it must NOT match.
        assert!(!cloud_provider_sdk_destination_matches(
            "aws",
            Some("evil-amazonaws.com"),
            None,
            None,
        ));
        // Cross-provider: an AWS domain must not match the gcp list.
        assert!(!cloud_provider_sdk_destination_matches(
            "gcp",
            Some("bedrock-runtime.us-east-1.amazonaws.com"),
            None,
            None,
        ));
        // Vertex / Azure-OpenAI control-plane suffixes.
        assert!(cloud_provider_sdk_destination_matches(
            "gcp",
            Some("us-central1-aiplatform.googleapis.com"),
            None,
            None,
        ));
        assert!(cloud_provider_sdk_destination_matches(
            "azure",
            Some("my-resource.openai.azure.com"),
            None,
            None,
        ));
    }

    #[test]
    fn test_cloud_provider_sdk_destination_matches_asn_owner_substring() {
        // Bare-IP Bedrock session whose only enrichment is the ASN owner
        // string -- case-insensitive substring against "amazon".
        assert!(cloud_provider_sdk_destination_matches(
            "aws",
            None,
            Some("16.182.40.10"),
            Some("AMAZON-02 Amazon Data Services"),
        ));
        // A non-Amazon ASN owner must not match the aws list.
        assert!(!cloud_provider_sdk_destination_matches(
            "aws",
            None,
            Some("203.0.113.10"),
            Some("DigitalOcean, LLC"),
        ));
    }

    #[test]
    fn test_cloud_provider_sdk_destination_matches_empty_and_unknown() {
        // No egress fields at all -> no match (cannot affirm provider).
        assert!(!cloud_provider_sdk_destination_matches(
            "aws", None, None, None
        ));
        // Unknown provider label -> no match regardless of destination.
        assert!(!cloud_provider_sdk_destination_matches(
            "ssh",
            Some("bedrock-runtime.us-east-1.amazonaws.com"),
            None,
            None,
        ));
    }

    /// FP-MAC-6 regression guard at the params level: the network-command
    /// token list MUST NOT contain the bare `http://` / `https://`
    /// substrings -- those caused HIGH false positives on benign log/text
    /// content carrying a single URL (git error, OpenSSH warning, CI step
    /// summary). The list MUST still contain the explicit verb tokens that
    /// every CVE trigger payload uses.
    #[test]
    fn test_secret_content_network_command_tokens_excludes_bare_urls() {
        let tokens = secret_content_network_command_tokens();
        assert!(
            !tokens.iter().any(|t| t == "http://" || t == "https://"),
            "bare http(s):// substrings must NOT be in the token list (got: {tokens:?})"
        );
        for required in [
            "curl ",
            "wget ",
            " nc ",
            "netcat",
            "invoke-webrequest",
            "invoke-restmethod",
            "socket.create_connection",
        ] {
            assert!(
                tokens.iter().any(|t| t == required),
                "required verb token {required:?} missing from {tokens:?}"
            );
        }
    }

    /// FP-CI-1 regression guard at the params level: the build-artifact
    /// excluded-path list MUST cover canonical cargo dep-info / rmeta paths
    /// (both POSIX and Windows separators) so the vulnerability detector's
    /// content-scan candidate collector skips them. These are the paths
    /// that triggered the Win32 atomic-rename race against rustc and broke
    /// `test_windows.yml` from 2026-05-01 onward.
    #[test]
    fn test_is_secret_content_scan_excluded_path_covers_cargo_artifacts() {
        // Canonical path that broke test_windows.yml run 25513313561.
        assert!(is_secret_content_scan_excluded_path(
            "C:\\Users\\edamame\\actions-runner\\_work\\edamame_app\\edamame_app\\edamame_core\\target\\release\\deps\\quick_error-9b6e3a7c2d4f1a08.d"
        ));
        // POSIX form on macOS / Linux runners.
        assert!(is_secret_content_scan_excluded_path(
            "/home/runner/work/edamame_app/edamame_app/edamame_core/target/debug/deps/serde-12345.rmeta"
        ));
        // Cross-compile target triple (iOS sim).
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/proj/target/aarch64-apple-ios-sim/debug/deps/foo-abc.rlib"
        ));
        // Cargo registry source dir.
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/.cargo/registry/src/index.crates.io-XXXX/quick-error-2.0.1/src/lib.rs"
        ));
        // Generic node_modules.
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/proj/node_modules/some-pkg/dist/index.js"
        ));
        // Flutter desktop / mobile per-platform build outputs: these are
        // the paths that hold MSVC PDBs, CMake project caches, Xcode
        // intermediates, etc. Keep them out of the content-scan candidate
        // set as hardening, without treating the observed C1090 family as a
        // demonstrated detector side effect.
        assert!(is_secret_content_scan_excluded_path(
            "C:\\Users\\edamame\\actions-runner\\_work\\edamame_app\\edamame_app\\build\\windows\\x64\\plugins\\system_tray\\system_tray_plugin.dir\\Debug\\vc143.pdb"
        ));
        // MSBuild per-project dep-info / tlog under the same tree.
        assert!(is_secret_content_scan_excluded_path(
            "C:\\Users\\edamame\\actions-runner\\_work\\edamame_app\\edamame_app\\build\\windows\\x64\\plugins\\tray_manager\\tray_manager_plugin.dir\\Debug\\unsuccessfulbuild.tlog"
        ));
        // Flutter macOS Xcode intermediates / products.
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/proj/build/macos/Build/Intermediates.noindex/Pods.build/Debug/Pods-Runner.build/Objects-normal/x86_64/Pods_Runner.o"
        ));
        // Flutter iOS Xcode build output.
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/proj/build/ios/Build/Products/Debug-iphonesimulator/Runner.app/Runner"
        ));
        // Flutter Linux desktop build output.
        assert!(is_secret_content_scan_excluded_path(
            "/home/runner/work/edamame_app/edamame_app/build/linux/x64/debug/bundle/edamame"
        ));
        // Flutter Web build output.
        assert!(is_secret_content_scan_excluded_path(
            "/home/runner/work/edamame_app/edamame_app/build/web/main.dart.js"
        ));
        // prost-build descriptor temp dir on Windows -- the canonical path
        // that broke edamame_helper/test_windows.yml run 25774821450 with
        // `os error 32` on prost-descriptor-set. tonic-build runs
        // prost-build during the edamame_foundation build script and the
        // runner-installed posture daemon's open-files enumeration was
        // racing build.rs's atomic descriptor rewrite.
        assert!(is_secret_content_scan_excluded_path(
            "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\prost-buildGWIvnp\\prost-descriptor-set"
        ));
        // prost-build descriptor temp dir on Linux.
        assert!(is_secret_content_scan_excluded_path(
            "/tmp/prost-buildAbc123/prost-descriptor-set"
        ));
        // prost-build descriptor temp dir on macOS (under /var/folders/).
        assert!(is_secret_content_scan_excluded_path(
            "/var/folders/zz/abc/T/prost-buildXyz/prost-descriptor-set"
        ));
        // `cargo install --target-dir` bootstrap path.
        assert!(is_secret_content_scan_excluded_path(
            "/tmp/cargo-install_xyz/release/deps/foo-bar.d"
        ));
    }

    /// TCC regression guard: files INSIDE a macOS media-app library bundle
    /// MUST be excluded from content scanning, including the non-media
    /// catalog files (`.plist`, `.db`, `.sqlite`) that pass the extension
    /// gate. Probing a file inside `Photos Library.photoslibrary` triggers
    /// the macOS Photos TCC consent prompt (`kTCCServicePhotos`); the WHERE
    /// path filter must drop the whole bundle up front.
    #[test]
    fn test_is_secret_content_scan_excluded_path_covers_media_libraries() {
        // The exact case that triggered the edamame_helper Photos TCC prompt:
        // a non-media catalog file inside the Photos library bundle.
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/Pictures/Photos Library.photoslibrary/database/Photos.sqlite"
        ));
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/Pictures/Photos Library.photoslibrary/resources/renders/somefile.plist"
        ));
        // Media assets inside the bundle are covered too (belt and braces
        // with the extension gate).
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/Pictures/Photos Library.photoslibrary/originals/0/IMG_0001.jpg"
        ));
        // Legacy iPhoto / Aperture library bundles.
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/Pictures/iPhoto Library.photolibrary/AlbumData.xml"
        ));
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/Pictures/Aperture Library.migratedphotolibrary/Database/apdb/Library.apdb"
        ));
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/Pictures/Old.aplibrary/Database/Library.apdb"
        ));
        // Music / TV app library bundles under ~/Music.
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/Music/Music/Music Library.musiclibrary/Library.musicdb"
        ));
        assert!(is_secret_content_scan_excluded_path(
            "/Users/me/Movies/TV/Media.tvlibrary/Library.tvdb"
        ));
        // A credential file living in a normal ~/Pictures subfolder (NOT a
        // library bundle) must still be scanned.
        assert!(!is_secret_content_scan_excluded_path(
            "/Users/me/Pictures/backup/.aws/credentials"
        ));
    }

    /// Negative-control companion: paths that legitimately need
    /// content-scanning MUST NOT be excluded by the build-artifact filter.
    /// In particular the credential / secret paths that the detector exists
    /// to catch (`~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.kube/config`,
    /// etc.) MUST pass through.
    #[test]
    fn test_is_secret_content_scan_excluded_path_does_not_skip_credentials() {
        assert!(!is_secret_content_scan_excluded_path(
            "/Users/me/.aws/credentials"
        ));
        assert!(!is_secret_content_scan_excluded_path(
            "C:\\Users\\me\\.aws\\credentials"
        ));
        assert!(!is_secret_content_scan_excluded_path(
            "/Users/me/.ssh/id_rsa"
        ));
        assert!(!is_secret_content_scan_excluded_path(
            "/Users/me/.kube/config"
        ));
        // /private/tmp/sifu-autopull.log was the FP-MAC-6 reproducer --
        // it lives in /tmp/, not in a build-artifact tree, and the
        // content-scan filter must not silently exclude /tmp/ files.
        assert!(!is_secret_content_scan_excluded_path(
            "/private/tmp/sifu-autopull.log"
        ));
        // A legitimate user document inside a folder that happens to
        // contain "target" or "build" but not the cargo/build-tool
        // sub-shape MUST still be content-scanned.
        assert!(!is_secret_content_scan_excluded_path(
            "/Users/me/Documents/sales-target.txt"
        ));
        assert!(!is_secret_content_scan_excluded_path(
            "/Users/me/Documents/build-plan.md"
        ));
        // Flutter build-output negative controls. The new Flutter
        // desktop build patterns are anchored on `/build/<platform>/`
        // which is unambiguous Flutter output, but let's sanity-check
        // a few user-doc shapes that happen to mention `build` or a
        // platform name.
        assert!(!is_secret_content_scan_excluded_path(
            "/Users/me/Documents/windows-build-notes.md"
        ));
        assert!(!is_secret_content_scan_excluded_path(
            "/Users/me/Documents/macos-build/notes.txt"
        ));
        // A user file inside a folder literally named `build/` but NOT
        // followed by a recognized Flutter desktop platform subdir
        // MUST still be content-scanned -- the suppression is shape-
        // anchored, not just substring `/build/`.
        assert!(!is_secret_content_scan_excluded_path(
            "/Users/me/proj/build/notes/credentials.txt"
        ));
    }

    /// Companion check: the script-extension list MUST cover the standard
    /// operator-script suffixes used by CVE triggers.
    #[test]
    fn test_secret_content_script_extensions_covers_common_suffixes() {
        let exts = secret_content_script_extensions();
        for required in [
            ".sh", ".py", ".pl", ".rb", ".ps1", ".bat", ".cmd", ".js", ".vbs",
        ] {
            assert!(
                exts.iter().any(|e| e == required),
                "required script extension {required:?} missing from {exts:?}"
            );
        }
    }

    /// The binary/media skip-extension list MUST cover the audio / image /
    /// video assets found under `~/Music`, `~/Pictures`, and `~/Movies`.
    /// These are the paths that a media/browser process holds open and that
    /// `flodbadd::open_files` surfaces to the content-scan candidate
    /// collector -- probing them triggers a macOS TCC consent prompt for
    /// protected media directories.
    #[test]
    fn test_is_secret_content_scan_skipped_extension_covers_media() {
        for media in [
            "/Users/me/Music/Music/Media.localized/Song.m4a",
            "/Users/me/Music/iTunes/Track.mp3",
            "/Users/me/Pictures/Photos Library.photoslibrary/originals/1/IMG.heic",
            "/Users/me/Pictures/Screenshot.png",
            "/Users/me/Pictures/vacation.jpg",
            "/Users/me/Movies/clip.mov",
            "/Users/me/Movies/render.mp4",
            // Case-insensitive match (macOS assets often use uppercase).
            "/Users/me/Pictures/RAW/DSC_0001.NEF",
            // Media library on-disk databases.
            "/Users/me/Music/Music/Music Library.musicdb",
        ] {
            assert!(
                is_secret_content_scan_skipped_extension(media),
                "media path {media:?} must be skipped by extension"
            );
        }
    }

    /// Negative control: text-bearing candidates the detector exists to
    /// catch (credentials, scripts, config, prose) MUST NOT be dropped by
    /// the extension gate, even when they live under a media directory.
    #[test]
    fn test_is_secret_content_scan_skipped_extension_keeps_text() {
        for keep in [
            "/Users/me/.aws/credentials",
            "/Users/me/.ssh/id_rsa",
            "/Users/me/.kube/config",
            "/private/tmp/exfil.py",
            "/private/tmp/sifu-autopull.log",
            "/Users/me/project/.env",
            // Extension-less credential files.
            "/Users/me/.netrc",
            // A note that merely mentions media in its name but is text.
            "/Users/me/Documents/music-notes.txt",
            // A stray text file dropped inside a media directory.
            "/Users/me/Music/playlist-export.json",
        ] {
            assert!(
                !is_secret_content_scan_skipped_extension(keep),
                "text-bearing path {keep:?} must NOT be skipped by extension"
            );
        }
    }

    #[test]
    fn test_ci_runner_internal_process_lookup() {
        // GitHub Actions provjobd is named with a per-run numeric suffix,
        // so our allow-list must match on a case-insensitive prefix.
        assert!(is_ci_runner_internal_process("provjobd"));
        assert!(is_ci_runner_internal_process("provjobd2003115"));
        assert!(is_ci_runner_internal_process("provjobd.exe1134032012"));
        assert!(is_ci_runner_internal_process("PROVJOBD.EXE999"));
        // GitHub Actions runner agent processes have per-run integer
        // suffixes (Runner.Worker.exe1134032012, Runner.Listener.exe1234)
        // and live under `actions-runner/` on Linux/macOS or under a
        // `node20/bin/` subpath on Windows.
        assert!(is_ci_runner_internal_process("Runner.Worker"));
        assert!(is_ci_runner_internal_process("Runner.Worker.exe"));
        assert!(is_ci_runner_internal_process("Runner.Worker.exe1134032012"));
        assert!(is_ci_runner_internal_process("RUNNER.WORKER.EXE999"));
        assert!(is_ci_runner_internal_process("Runner.Listener"));
        assert!(is_ci_runner_internal_process("Runner.Listener.exe"));
        assert!(is_ci_runner_internal_process("Runner.Listener.exe9999"));
        // Empty and unrelated names must not be matched.
        assert!(!is_ci_runner_internal_process(""));
        assert!(!is_ci_runner_internal_process("python3"));
        assert!(!is_ci_runner_internal_process("provjo"));
        assert!(!is_ci_runner_internal_process("runner"));
        assert!(!is_ci_runner_internal_process("runner.exe"));
    }

    #[test]
    fn test_is_non_sensitive_browser_data_chromium_cache() {
        // Chrome / Edge / Brave Code Cache, GPUCache, Service Worker etc. -- recomputable.
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Profile 1/Code Cache/js/abc_0"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/GPUCache/data_0"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Microsoft/Edge/User Data/Default/Service Worker/CacheStorage/foo"
        ));
        assert!(is_non_sensitive_browser_data(
            "/Users/me/Library/Application Support/BraveSoftware/Brave-Browser/User Data/Default/Code Cache/js/0"
        ));
    }

    #[test]
    fn test_is_non_sensitive_browser_data_chromium_state_files() {
        // Local State / Preferences atomic rewrite at the User Data root or per profile.
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Local State"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Profile 1/Preferences"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Microsoft/Edge/User Data/Default/Secure Preferences"
        ));
    }

    #[test]
    fn test_browser_volatile_profile_state_group_lookup() {
        assert_eq!(
            browser_volatile_profile_state_group(
                "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Profile 1/Session Storage/000003.log"
            )
            .as_deref(),
            Some("chromium:profile 1:session storage")
        );
        assert_eq!(
            browser_volatile_profile_state_group(
                "C:/Users/frank/AppData/Local/Microsoft/Edge/User Data/Default/Sync Data/LevelDB/000001.log"
            )
            .as_deref(),
            Some("chromium:default:sync data")
        );
        assert_eq!(
            browser_volatile_profile_state_group(
                "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Profile 1/DownloadMetadata"
            )
            .as_deref(),
            Some("chromium:profile 1:downloadmetadata")
        );
        assert_eq!(
            browser_volatile_profile_state_group(
                "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Profile 1/Bookmarks"
            )
            .as_deref(),
            Some("chromium:profile 1:bookmarks")
        );
        assert_eq!(
            browser_volatile_profile_state_group(
                "/home/me/.mozilla/firefox/abc.default/sessionstore-backups/recovery.jsonlz4"
            )
            .as_deref(),
            Some("firefox:abc.default:sessionstore-backups")
        );
        assert!(browser_volatile_profile_state_group(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Login Data"
        )
        .is_none());
        assert!(browser_volatile_profile_state_group("/tmp/Session Storage/000003.log").is_none());
    }

    #[test]
    fn test_is_non_sensitive_browser_data_does_not_suppress_credentials() {
        // Login Data / Cookies / Web Data / History MUST stay sensitive.
        // These files live under the same User Data root but are NOT in
        // any allow-listed subtree.
        assert!(!is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Login Data"
        ));
        assert!(!is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Cookies"
        ));
        assert!(!is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Web Data"
        ));
        assert!(!is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/History"
        ));
        assert!(!is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Microsoft/Edge/User Data/Default/Login Data For Account"
        ));
    }

    #[test]
    fn test_is_non_sensitive_browser_data_outside_browser_root_not_suppressed() {
        // A `Code Cache/` directory elsewhere on disk must NOT be suppressed
        // -- the suppression requires BOTH a browser user-data root marker
        // AND a cache subtree to match.
        assert!(!is_non_sensitive_browser_data(
            "C:/AttackerStaging/Code Cache/js/abc_0"
        ));
        assert!(!is_non_sensitive_browser_data("/tmp/sandbox/Local State"));
    }

    #[test]
    fn test_is_non_sensitive_browser_data_firefox_cache() {
        assert!(is_non_sensitive_browser_data(
            "/Users/me/Library/Application Support/Firefox/Profiles/abc.default-release/cache2/entries/foo"
        ));
        assert!(is_non_sensitive_browser_data(
            "/home/me/.mozilla/firefox/abc.default/storage/permanent/chrome/idb/blah.sqlite"
        ));
        // Firefox sensitive files (e.g. logins.json, key4.db) must keep firing
        assert!(!is_non_sensitive_browser_data(
            "/home/me/.mozilla/firefox/abc.default/logins.json"
        ));
        assert!(!is_non_sensitive_browser_data(
            "/home/me/.mozilla/firefox/abc.default/key4.db"
        ));
    }

    #[test]
    fn test_is_non_sensitive_browser_data_empty() {
        assert!(!is_non_sensitive_browser_data(""));
    }

    #[test]
    fn test_fp_win_21_chromium_extension_housekeeping_suppressed() {
        // FP-WIN-21: installed-extension subtree under a Chromium
        // user-data root is now in the `chromium_family` allowlist.
        // Manifest cache, locale resources, verified-contents
        // regeneration, and extension state DB all match.
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Extensions/abc/1.0/manifest.json"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Extensions/abcdef0123456789/2.5.1/_locales/en/messages.json"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Extensions/abcdef0123456789/2.5.1/_metadata/verified_contents.json"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Microsoft/Edge/User Data/Profile 1/Extensions/xyz/3.0/background.js"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Extension Rules/000003.log"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Extension State/MANIFEST-000001"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Extension Scripts/000004.ldb"
        ));
    }

    #[test]
    fn test_fp_win_21_extension_path_outside_browser_root_not_suppressed() {
        // Defense-in-depth: an `Extensions/` directory OUTSIDE the
        // Chromium user-data root MUST NOT be suppressed -- the
        // double-gate is what makes the FP-WIN-21 allowlist safe.
        assert!(!is_non_sensitive_browser_data(
            "/tmp/sandbox/Extensions/abc/1.0/manifest.json"
        ));
        assert!(!is_non_sensitive_browser_data(
            "C:/AttackerStaging/Extensions/evil/1.0/manifest.json"
        ));
    }

    #[test]
    fn test_fp_win_21_does_not_relax_credential_store_guard() {
        // Negative regression: the new /extensions/ allowlist must
        // NOT broaden coverage to credential-store files at the
        // Default/ root. Login Data / Cookies / Web Data are at the
        // profile root, not inside Extensions/.
        assert!(!is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Login Data"
        ));
        assert!(!is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/Cookies"
        ));
        assert!(!is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Microsoft/Edge/User Data/Default/Web Data"
        ));
    }

    #[test]
    fn test_fp_win_18_iter3_indexeddb_leveldb_housekeeping_suppressed() {
        // FP-WIN-18 iter-3: Chrome's IndexedDB leveldb store under a
        // Chromium user-data root churns MANIFEST-*/*.ldb/CURRENT/LOG
        // files during routine compaction with null process
        // attribution. iter-2 carved out only LOG/LOG.old; the data /
        // manifest files stayed sensitive because /indexeddb/ was
        // missing from chromium_family. They are the same browser-
        // managed web-storage leveldb class as /local storage/leveldb/.
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Profile 1/IndexedDB/chrome-extension_aeblfdkhhhdcdjpifhhbdiojplfjncoa_0.indexeddb.leveldb/MANIFEST-000001"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Profile 1/IndexedDB/chrome-extension_aeblfdkhhhdcdjpifhhbdiojplfjncoa_0.indexeddb.leveldb/000066.ldb"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Google/Chrome/User Data/Default/IndexedDB/https_example.com_0.indexeddb.leveldb/CURRENT"
        ));
        assert!(is_non_sensitive_browser_data(
            "C:/Users/frank/AppData/Local/Microsoft/Edge/User Data/Default/IndexedDB/https_example.com_0.indexeddb.leveldb/000003.log"
        ));
    }

    #[test]
    fn test_fp_win_18_iter3_indexeddb_outside_browser_root_not_suppressed() {
        // Defense-in-depth: an IndexedDB/*.leveldb directory OUTSIDE a
        // Chromium user-data root MUST NOT be suppressed -- the
        // double-gate (in_chromium_root + subtree match) is what keeps
        // the /indexeddb/ carve-out safe against attacker staging.
        assert!(!is_non_sensitive_browser_data(
            "/tmp/sandbox/IndexedDB/evil_0.indexeddb.leveldb/MANIFEST-000001"
        ));
        assert!(!is_non_sensitive_browser_data(
            "C:/AttackerStaging/IndexedDB/evil_0.indexeddb.leveldb/000066.ldb"
        ));
    }

    #[test]
    fn test_ci_workspace_path_lookup() {
        // GitHub Actions workspace and diagnostic dirs on Linux/macOS:
        assert!(is_ci_workspace_path(
            "/home/runner/actions-runner/_work/repo/repo/.env"
        ));
        assert!(is_ci_workspace_path(
            "/home/runner/runner/_work/repo/repo/Cargo.toml"
        ));
        assert!(is_ci_workspace_path(
            "/Users/runner/actions-runner/_diag/Worker_2026.log"
        ));
        // Windows variant with backslashes (case-insensitive).
        assert!(is_ci_workspace_path(
            "C:\\Users\\runneradmin\\actions-runner\\_work\\repo\\repo\\.env"
        ));
        assert!(is_ci_workspace_path(
            "C:\\Users\\runneradmin\\Actions-Runner\\_Diag\\Worker_2026.log"
        ));
        // Unrelated paths must not match.
        assert!(!is_ci_workspace_path(""));
        assert!(!is_ci_workspace_path("/home/user/.ssh/id_rsa"));
        assert!(!is_ci_workspace_path(
            "/Library/Keychains/login.keychain-db"
        ));
        assert!(!is_ci_workspace_path("/home/user/repo-checkout/.env"));
    }

    #[test]
    fn test_keychain_transactional_path_lookup() {
        // macOS Keychain transactional artifacts created on every read.
        assert!(is_keychain_transactional_path(
            "/Users/me/Library/Keychains/login.keychain-db.sb-a883c359-jYUWtI"
        ));
        assert!(is_keychain_transactional_path(
            "/Users/me/Library/Keychains/login.keychain-db-shm.sb-deadbeef-XYZ"
        ));
        assert!(is_keychain_transactional_path(
            "/Users/me/Library/Keychains/.fl34AC2A0A"
        ));
        // Real keychain DB writes (not transactional) must NOT match;
        // a tampering event there is a real signal.
        assert!(!is_keychain_transactional_path(
            "/Users/me/Library/Keychains/login.keychain-db"
        ));
        assert!(!is_keychain_transactional_path(""));
        assert!(!is_keychain_transactional_path("/etc/passwd"));
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
        // FP-CI-1 guard: the build-artifact excluded-path list MUST be
        // populated and MUST cover at minimum the cargo profile dirs that
        // race against rustc on Windows self-hosted runners.
        assert!(!p.secret_content_scan_excluded_path_patterns.is_empty());
        for required in ["/target/debug/", "/target/release/", "/node_modules/"] {
            assert!(
                p.secret_content_scan_excluded_path_patterns
                    .iter()
                    .any(|pat| pat == required),
                "required excluded-path pattern {required:?} missing from {:?}",
                p.secret_content_scan_excluded_path_patterns
            );
        }
    }

    #[test]
    fn test_platform_metadata_endpoint_lookup() {
        // Azure Wire Server -- known platform metadata endpoint on
        // both Linux and Windows guest VMs.
        assert!(is_platform_metadata_endpoint("168.63.129.16"));
        // EC2 / GCE / generic link-local IMDS address.
        assert!(is_platform_metadata_endpoint("169.254.169.254"));
        // Unrelated address -- not a metadata endpoint.
        assert!(!is_platform_metadata_endpoint("8.8.8.8"));
        // Subset of a known IP must NOT match (exact-match only).
        assert!(!is_platform_metadata_endpoint("168.63.129.166"));
        assert!(!is_platform_metadata_endpoint(""));
    }

    #[test]
    fn test_platform_credential_helper_routine_destination_ip_prefix_lookup() {
        assert!(is_platform_credential_helper_routine_destination(
            Some("securityd"),
            None,
            None,
            Some("2603:1026:3000::1"),
            None,
        ));
        assert!(is_platform_credential_helper_routine_destination(
            Some("accountsd"),
            None,
            None,
            Some("2603:1061:1000::5"),
            None,
        ));
        assert!(!is_platform_credential_helper_routine_destination(
            Some("securityd"),
            None,
            None,
            Some("2001:db8::1"),
            None,
        ));
    }

    #[test]
    fn test_software_distribution_backend_lookup() {
        // FP-MAC-14 exact shape: domainless Fastly IPv6 anycast egress
        // (GitHub release CDN) with no reverse DNS, matched on ASN owner.
        assert!(is_software_distribution_backend(
            None,
            Some("2606:50c0:8000::153"),
            Some("FASTLY"),
        ));
        // Domain-suffix match (raw.githubusercontent.com release fetch).
        assert!(is_software_distribution_backend(
            Some("objects.githubusercontent.com"),
            None,
            None,
        ));
        // GitHub ASN owner substring (e.g. "GITHUB, INC.").
        assert!(is_software_distribution_backend(
            None,
            None,
            Some("GitHub, Inc."),
        ));
        // Non-distribution destination: no domain suffix / ASN / IP match.
        assert!(!is_software_distribution_backend(
            Some("evil.example.com"),
            Some("203.0.113.5"),
            Some("DIGITALOCEAN-ASN"),
        ));
        // All destination fields empty/absent -> never matches.
        assert!(!is_software_distribution_backend(None, None, None));
    }

    #[test]
    fn test_platform_self_state_directory_lookup() {
        // Azure Linux guest agent state directory.
        assert!(is_platform_self_state_directory(
            "/var/lib/waagent/Certificates.pem"
        ));
        // cloud-init state.
        assert!(is_platform_self_state_directory(
            "/etc/cloud/cloud.cfg.d/90_dpkg.cfg"
        ));
        // Windows guest agent (case + separator-insensitive match).
        assert!(is_platform_self_state_directory(
            "C:\\WindowsAzure\\GuestAgent_2.7\\TransparentInstaller.log"
        ));
        // User-controlled paths must not match.
        assert!(!is_platform_self_state_directory("/home/user/.ssh/id_rsa"));
        assert!(!is_platform_self_state_directory(
            "/var/lib/postgresql/data"
        ));
        assert!(!is_platform_self_state_directory(""));
    }

    #[test]
    fn test_package_manager_temp_writer_lookup() {
        // Cross-platform toolchain basenames.
        assert!(is_package_manager_temp_writer("dart"));
        assert!(is_package_manager_temp_writer("DART"));
        assert!(is_package_manager_temp_writer("npm"));
        assert!(is_package_manager_temp_writer("cargo"));
        assert!(is_package_manager_temp_writer("pip"));
        assert!(is_package_manager_temp_writer("pip3"));
        // Windows variants.
        assert!(is_package_manager_temp_writer("dart.exe"));
        assert!(is_package_manager_temp_writer("npm.cmd"));
        assert!(is_package_manager_temp_writer("yarn.cmd"));
        assert!(is_package_manager_temp_writer("pnpm.exe"));
        assert!(is_package_manager_temp_writer("cargo.exe"));
        // Generic interpreters and arbitrary process names must NOT
        // be treated as toolchains -- a malicious python3 or bash
        // dropping a file into a pub-cache-shaped directory should
        // still trip.
        assert!(!is_package_manager_temp_writer("python3"));
        assert!(!is_package_manager_temp_writer("bash"));
        assert!(!is_package_manager_temp_writer("powershell.exe"));
        assert!(!is_package_manager_temp_writer(""));
    }

    #[test]
    fn test_build_output_tree_sudo_launcher() {
        assert!(is_build_output_tree_self_spawn(
            Some("/tmp/edamame_posture/target/release/edamame_posture"),
            Some("/usr/bin/sudo"),
        ));
        assert!(is_build_output_tree_self_spawn(
            Some("/tmp/edamame_posture/target/release/edamame_posture"),
            Some("/tmp/edamame_posture/target/release/edamame_posture"),
        ));
        assert!(!is_build_output_tree_self_spawn(
            Some("/tmp/edamame_posture/target/release/edamame_posture"),
            Some("/tmp/.hidden/bash"),
        ));
    }

    #[test]
    fn test_edamame_daemon_self_telemetry_writer_lookup() {
        // Unix-style daemon basenames (CLI / helper / GUI).
        assert!(is_edamame_daemon_self_telemetry_writer("edamame"));
        assert!(is_edamame_daemon_self_telemetry_writer("edamame_posture"));
        assert!(is_edamame_daemon_self_telemetry_writer("edamame_helper"));
        assert!(is_edamame_daemon_self_telemetry_writer("edamame_security"));
        // Windows variants with `.exe`.
        assert!(is_edamame_daemon_self_telemetry_writer("edamame.exe"));
        assert!(is_edamame_daemon_self_telemetry_writer(
            "edamame_posture.exe"
        ));
        assert!(is_edamame_daemon_self_telemetry_writer(
            "edamame_helper.exe"
        ));
        assert!(is_edamame_daemon_self_telemetry_writer(
            "edamame_security.exe"
        ));
        // Case-insensitive matching (FIM / process attribution may
        // upper-case basenames on Windows).
        assert!(is_edamame_daemon_self_telemetry_writer(
            "EDAMAME_POSTURE.EXE"
        ));
        assert!(is_edamame_daemon_self_telemetry_writer("EDAMAME"));
        // Adversary spoofing attempt with a similarly-named binary
        // that is NOT in the daemon family must NOT match -- the
        // carve-out applies to the EDAMAME-shipped binaries only.
        assert!(!is_edamame_daemon_self_telemetry_writer("edamame_cli"));
        assert!(!is_edamame_daemon_self_telemetry_writer(
            "edamame_attacker.exe"
        ));
        assert!(!is_edamame_daemon_self_telemetry_writer("powershell.exe"));
        assert!(!is_edamame_daemon_self_telemetry_writer("cmd.exe"));
        assert!(!is_edamame_daemon_self_telemetry_writer("python3"));
        assert!(!is_edamame_daemon_self_telemetry_writer(""));
    }

    #[test]
    fn test_edamame_daemon_self_telemetry_writer_path_attestation() {
        assert!(is_edamame_daemon_self_telemetry_writer_for_path(
            "edamame.exe",
            Some("C:\\Program Files\\WindowsApps\\EDAMAMETechnologies.EDAMAMESecurity_1.3.5.0_x64__rx2dyyqk4mc6r\\edamame.exe")
        ));
        assert!(is_edamame_daemon_self_telemetry_writer_for_path(
            "edamame_helper",
            Some("/usr/local/bin/edamame_helper")
        ));
        assert!(is_edamame_daemon_self_telemetry_writer_for_path(
            "edamame_posture.exe",
            Some("C:\\Users\\edamame\\edamame_posture.exe")
        ));
        assert!(is_edamame_daemon_self_telemetry_writer_for_path(
            "edamame_posture.exe",
            Some("C:\\Users\\runneradmin\\edamame_posture.exe")
        ));
        assert!(is_edamame_daemon_self_telemetry_writer_for_path(
            "edamame_posture.exe",
            None
        ));
        assert!(!is_edamame_daemon_self_telemetry_writer_for_path(
            "edamame.exe",
            Some("C:\\Users\\frank\\edamame.exe")
        ));
        assert!(!is_edamame_daemon_self_telemetry_writer_for_path(
            "edamame_posture.exe",
            Some("C:\\Users\\frank\\edamame_posture.exe")
        ));
        assert!(!is_edamame_daemon_self_telemetry_writer_for_path(
            "edamame.exe",
            Some("C:\\Users\\frank\\AppData\\Local\\Temp\\edamame.exe")
        ));
        assert!(!is_edamame_daemon_self_telemetry_writer_for_path(
            "python.exe",
            Some("C:\\Program Files\\WindowsApps\\EDAMAMETechnologies.EDAMAMESecurity_1.3.5.0_x64__rx2dyyqk4mc6r\\python.exe")
        ));
    }

    #[test]
    fn test_browser_appdata_unknown_writer_matchers() {
        let chrome_path =
            "C:\\Users\\frank\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1\\Safe Browsing\\UrlSoceng.store";
        let expected = browser_appdata_unknown_writer_expected_processes(chrome_path);
        assert!(expected.iter().any(|name| name == "chrome.exe"));

        assert!(is_browser_appdata_unknown_writer_directory_target(
            "C:\\Users\\frank\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1\\Network"
        ));
        assert!(!is_browser_appdata_unknown_writer_directory_target(
            chrome_path
        ));
        assert!(browser_appdata_unknown_writer_expected_processes(
            "C:\\Users\\frank\\AppData\\Local\\Microsoft\\Windows\\Recent\\foo.lnk"
        )
        .is_empty());
    }

    #[test]
    fn test_package_manager_temp_path_lookup() {
        // Windows: dart.exe pub-cache temp download.
        assert!(is_package_manager_temp_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\pub_9931f52b\\flutter_widget_from_html-0.17.1.tar.gz"
        ));
        assert!(is_package_manager_temp_path(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\npm-cache-foo\\package.tgz"
        ));
        assert!(is_package_manager_temp_path(
            "D:\\Users\\runner\\AppData\\Local\\Temp\\.yarn-cache\\pkg.tgz"
        ));
        // Linux: pub / npm / pip / cargo temp paths.
        assert!(is_package_manager_temp_path(
            "/tmp/pub_abc123/flutter_widget_from_html-0.17.1.tar.gz"
        ));
        assert!(is_package_manager_temp_path(
            "/home/runner/.npm/_cacache/content-v2/sha512/abc/def.tgz"
        ));
        assert!(is_package_manager_temp_path(
            "/home/runner/.cargo/registry/cache/index.crates.io-XYZ/some-pkg-1.0.0.crate"
        ));
        // macOS: dart pub-cache.
        assert!(is_package_manager_temp_path(
            "/Users/me/.pub-cache/hosted/pub.dev/flutter_widget_from_html-0.17.1.tar.gz"
        ));
        assert!(is_package_manager_temp_path(
            "/private/var/folders/abc/T/pub_xyz/pkg.tar.gz"
        ));
        // Paths outside any known package-cache pattern must NOT
        // match. Note: the path-only check is permissive on purpose
        // (anything under `\temp\pub_` matches) -- the conjunctive
        // gate with `is_package_manager_temp_writer` is what
        // prevents adversary spoofing.
        assert!(!is_package_manager_temp_path(
            "/home/user/repos/some-project/dist/pkg.tar.gz"
        ));
        assert!(!is_package_manager_temp_path("/etc/passwd"));
        assert!(!is_package_manager_temp_path(
            "C:\\Windows\\System32\\config\\SAM"
        ));
        assert!(!is_package_manager_temp_path(""));
    }

    #[test]
    fn test_platform_runtime_probe_filename_lookup() {
        // Canonical Windows PowerShell execution-policy probe.
        assert!(is_platform_runtime_probe_filename(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\__PSScriptPolicyTest_pfet2d4g.i4l.ps1"
        ));
        // Case-insensitive.
        assert!(is_platform_runtime_probe_filename(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\__PSSCRIPTPOLICYTEST_ABCDEF.GHI.ps1"
        ));
        // Forward-slash separator (FIM events sometimes mix styles).
        assert!(is_platform_runtime_probe_filename(
            "C:/Users/edamame/AppData/Local/Temp/__PSScriptPolicyTest_xyz.abc.ps1"
        ));
        // Bare leaf without directory portion.
        assert!(is_platform_runtime_probe_filename(
            "__PSScriptPolicyTest_aaa.bbb.ps1"
        ));
        // Random temp `.ps1` (FP-WIN-4 shape, NOT a runtime probe)
        // must NOT match -- the operator-scratch carve-out handles
        // that one with a severity demote, not a full suppression.
        assert!(!is_platform_runtime_probe_filename(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\.tmpW09dzI.ps1"
        ));
        // Adversary trying to hide behind the prefix from a non-temp
        // path is still suppressed by basename (suppression is about
        // the file shape, not the directory). Acceptable trade-off:
        // the real PSScriptPolicyTest only ever lives in %TEMP% so
        // the worst case is a file with this exact basename pattern
        // anywhere on disk being skipped by the FIM detector.
        assert!(is_platform_runtime_probe_filename(
            "C:\\Users\\victim\\Documents\\__PSScriptPolicyTest_attacker.fake.ps1"
        ));
        assert!(!is_platform_runtime_probe_filename(""));
        assert!(!is_platform_runtime_probe_filename("foo.ps1"));
    }

    #[test]
    fn test_managed_temp_staging_path_lookup() {
        // FP-CI-9: tonic/prost descriptor temp trees during Cargo
        // build-script execution.
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\prost-buildSHbPlE\\prost-descriptor-set"
        ));
        assert!(is_managed_temp_staging_suppressed_path(
            "/tmp/prost-buildabc123/prost-descriptor-set"
        ));
        assert!(is_managed_temp_staging_suppressed_path(
            "/var/folders/aa/bb/T/prost-buildabc123/prost-descriptor-set"
        ));
        assert!(!is_managed_temp_staging_suppressed_path(
            "C:\\Users\\runneradmin\\AppData\\Local\\Temp\\evil\\prost-descriptor-set"
        ));

        // Canonical WiX BootstrapperApplication extraction during a
        // `cargo wix` MSI build on the Windows runner.
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\41ftcnya.p4m\\WixToolset.BootstrapperApplications.wixext_HPVZ2YWGIB0GOTbsOi2MVHIa9bk\\wix-ir\\HyperlinkTheme.wxl"
        ));
        // Same shape with forward-slash separators (FIM events
        // sometimes mix styles after normalization).
        assert!(is_managed_temp_staging_suppressed_path(
            "C:/Users/edamame/AppData/Local/Temp/abc.def/WixToolset.BootstrapperApplications.wixext_XYZ/wix-ir/Theme.wxl"
        ));
        // The bare `wix-ir` directory pattern should also match
        // (covers wix-ir intermediate output written outside the
        // BootstrapperApplications hash dir).
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\some-build\\wix-ir\\foo.wixobj"
        ));
        // Case-insensitive matching.
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\USERS\\EDAMAME\\APPDATA\\LOCAL\\TEMP\\X.Y\\WIXTOOLSET.BOOTSTRAPPERAPPLICATIONS.WIXEXT_HASH\\WIX-IR\\HYPERLINKTHEME.WXL"
        ));
        // Non-WiX paths must NOT match: a malicious binary writing
        // to a similarly-suffixed file outside the WiX staging
        // directory shape gets no free pass.
        assert!(!is_managed_temp_staging_suppressed_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\malicious.wxl"
        ));
        assert!(!is_managed_temp_staging_suppressed_path(
            "/home/user/repos/some-project/wix-ir.txt"
        ));
        assert!(!is_managed_temp_staging_suppressed_path("/etc/passwd"));
        assert!(!is_managed_temp_staging_suppressed_path(""));

        // FP-WIN-14a: CMake `FetchContent_Populate` writes
        // `<pkg>-mkdirs.cmake` (and `<pkg>-download.cmake`,
        // `<pkg>-update.cmake`, ...) into
        // `build\<arch>\_deps\<pkg>-subbuild\<pkg>-populate-prefix\tmp\`
        // on every Flutter Windows build. The unique substring
        // `-populate-prefix\tmp\` is what we suppress on.
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\edamame\\actions-runner\\_work\\edamame_app\\edamame_app\\build\\windows\\x64\\_deps\\nuget-subbuild\\nuget-populate-prefix\\tmp\\nuget-populate-mkdirs.cmake"
        ));
        assert!(is_managed_temp_staging_suppressed_path(
            "C:/Users/edamame/actions-runner/_work/edamame_app/edamame_app/build/windows/x64/_deps/corrosion-subbuild/corrosion-populate-prefix/tmp/corrosion-populate-download.cmake"
        ));
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\edamame\\actions-runner\\_work\\edamame_app\\edamame_app\\build\\windows\\x64\\_deps\\sentry-native-subbuild\\sentry-native-populate-prefix\\tmp\\sentry-native-populate-update.cmake"
        ));
        // FP-WIN-14a impostor: a temp file that just happens to
        // mention "populate-prefix" but is NOT in the
        // `\tmp\` subdir of a CMake FetchContent populate-prefix
        // tree must NOT match.
        assert!(!is_managed_temp_staging_suppressed_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\malware-populate-prefix.exe"
        ));

        // FP-WIN-14b: NuGet's global cross-process scratch/lock dir
        // at `%LOCALAPPDATA%\Temp\NuGetScratch\lock\` (and
        // `\plan\`, `\v3-cache\`). Hex-named lock files trip the
        // detector with a non-benign suffix; FIM L7 attribution is
        // unreliable here.
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\NuGetScratch\\lock\\db433f173e9b75688465fde95d3d04684cfdb3ae"
        ));
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\NuGetScratch\\plan\\abc123"
        ));
        assert!(is_managed_temp_staging_suppressed_path(
            "C:/Users/edamame/AppData/Local/Temp/NuGetScratch/v3-cache/foo"
        ));
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\NuGetScratch"
        ));
        // Case-insensitive.
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\USERS\\EDAMAME\\APPDATA\\LOCAL\\TEMP\\NUGETSCRATCH\\LOCK\\HEX"
        ));
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\chocolatey\\ChocolateyScratch\\protoc\\25.3.0\\protoc.25.3.0.nupkg"
        ));
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\system-commandline-sentinel-files\\dotnet-suggest-registration-git-credential-manager, Version=2.7.3.0, Culture=neutral, PublicKeyToken=null"
        ));
        assert!(is_managed_temp_staging_suppressed_path(
            "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\tmp_phcbtzg1.x2e\\remoteIpMoProxy_ConfigDefender_1.0_localhost_a84523b9-7559-4633-8baf-e255b093fcaa.psd1"
        ));
        // FP-WIN-14b impostor: a directory whose name contains
        // "nuget" but is NOT the `NuGetScratch` global cache must
        // NOT match.
        assert!(!is_managed_temp_staging_suppressed_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\my-nuget-stash\\foo"
        ));
        assert!(!is_managed_temp_staging_suppressed_path(
            "C:\\Users\\edamame\\AppData\\Roaming\\NuGet\\packages\\foo.dll"
        ));
        assert!(!is_managed_temp_staging_suppressed_path(
            "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\remoteIpMoProxy_OtherModule_1.0\\payload.ps1"
        ));

        assert!(is_managed_temp_staging_demoted_path(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\{6d8f8f9a-1111-4444-9999-2bdf4d7a9c3c}\\.ba\\wixstdba.exe"
        ));
        assert!(!is_managed_temp_staging_demoted_path(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\ordinary\\wixstdba.exe"
        ));
    }

    /// FP-WIN-7c regression guard at the params level: the pair-wise
    /// trusted-app self-temp-staging allowlist MUST recognize the four
    /// canonical legitimate writer/target shapes observed on the
    /// shiawase Windows dogfood host (Chrome self-update bits, Edge
    /// self-update bits, WinGet svchost staging, Visual Studio Setup
    /// `BackgroundDownload.exe` self-extracted scratch), AND MUST NOT
    /// cross-match an impostor writer against a trusted target (the
    /// suppression is pair-wise, not "any trusted writer + any trusted
    /// target").
    #[test]
    fn test_is_app_self_temp_staging_pair_positive_and_impostor_cases() {
        // Positive: Chrome self-update writing chrome_chrome_bits_*.
        assert!(is_app_self_temp_staging_pair(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\chrome_chrome_bits_12345.tmp",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        ));
        // Positive: Edge self-update writing msedge_chrome_bits_*.
        assert!(is_app_self_temp_staging_pair(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\msedge_chrome_bits_67890.tmp",
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        ));
        // Positive: WinGet svchost staging under \AppData\Local\Temp\WinGet\.
        assert!(is_app_self_temp_staging_pair(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\WinGet\\Microsoft.Edge.0fcfde91\\Edge.exe",
            "C:\\Windows\\System32\\svchost.exe",
        ));
        // Positive: Visual Studio Setup BackgroundDownload writing
        // dd_BackgroundDownload_*.
        assert!(is_app_self_temp_staging_pair(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\dd_BackgroundDownload_20260520.log",
            "C:\\Users\\frank\\AppData\\Local\\Microsoft\\VisualStudio\\Setup\\Cache\\InstallerCache\\Resources\\App\\ServiceHub\\Services\\Microsoft.VisualStudio.Setup.Service\\BackgroundDownload.exe",
        ));

        // Impostor 1: a writer in /tmp/ (suspicious) writing to a
        // Chrome trusted target. MUST NOT suppress.
        assert!(!is_app_self_temp_staging_pair(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\chrome_chrome_bits_12345.tmp",
            "C:\\Users\\frank\\AppData\\Local\\Temp\\malware.exe",
        ));
        // Impostor 2: Chrome legitimately running, but writing to a
        // sensitive target (e.g. ~/.ssh/id_rsa). MUST NOT suppress.
        assert!(!is_app_self_temp_staging_pair(
            "C:\\Users\\frank\\.ssh\\id_rsa",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        ));
        // Impostor 3: svchost (legitimate WinGet writer) writing to a
        // Chrome target. Cross-bucket match -- MUST NOT suppress.
        assert!(!is_app_self_temp_staging_pair(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\chrome_chrome_bits_99999.tmp",
            "C:\\Windows\\System32\\svchost.exe",
        ));
        // Impostor 4: chrome.exe writing to a WinGet target. Cross-
        // bucket match -- MUST NOT suppress.
        assert!(!is_app_self_temp_staging_pair(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\WinGet\\some-app\\installer.exe",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        ));
        // Empty arguments are never a pair match.
        assert!(!is_app_self_temp_staging_pair("", ""));
        assert!(!is_app_self_temp_staging_pair(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\chrome_chrome_bits_12345.tmp",
            "",
        ));
    }

    #[test]
    fn test_platform_self_state_process_name_lookup() {
        // Linux Azure Wire Agent + cloud-init.
        assert!(is_platform_self_state_process_name("waagent"));
        assert!(is_platform_self_state_process_name("WAAGENT"));
        assert!(is_platform_self_state_process_name("cloud-init"));
        assert!(is_platform_self_state_process_name("cloud-init-local"));
        // Windows guest agent.
        assert!(is_platform_self_state_process_name(
            "WindowsAzureGuestAgent.exe"
        ));
        // Generic interpreter -- the agent runs under python3 but we
        // intentionally match the agent name (script basename), not
        // the interpreter, so a malicious python3 elsewhere does not
        // get a free pass.
        assert!(!is_platform_self_state_process_name("python3"));
        assert!(!is_platform_self_state_process_name("bash"));
        assert!(!is_platform_self_state_process_name(""));
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
