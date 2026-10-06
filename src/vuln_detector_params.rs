use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
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
    /// INC-19: own image or ANY kernel ancestor matches the
    /// suspicious-lineage patterns (the polled lineage stops at the
    /// grandparent). Default 0.0 (inert, shadow tag only) until the
    /// `kernel_lineage_flip_enabled` switch and a calibrated weight land
    /// together via CloudModel.
    pub kernel_lineage_suspicious: f32,
    // ---- B4 cross-engine bus signals (attack axis; 0.0 until calibrated) ----
    /// The session's agent has a live Divergence verdict this tick.
    pub divergence_verdict_active: f32,
    /// A `correlation:not_expected` (explicit prohibition violated) row of
    /// the live verdict names this session.
    pub divergence_prohibition_on_session: f32,
    /// The agent's transcripts carry a prompt-injection marker hit.
    pub transcript_prompt_injection_hit: f32,
    /// The agent's transcripts carry a secret-exposure hit.
    pub transcript_secret_exposure_hit: f32,
    /// The session's destination is a risk-flagged MCP endpoint.
    pub mcp_endpoint_risk: f32,
    /// A declared confinement (prohibited path / binary) was crossed by this
    /// session's agent in the live verdict.
    pub declared_confinement_mismatch: f32,
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
            kernel_lineage_suspicious: default_ew_kernel_lineage_suspicious(),
            divergence_verdict_active: 0.0,
            divergence_prohibition_on_session: 0.0,
            transcript_prompt_injection_hit: 0.0,
            transcript_secret_exposure_hit: 0.0,
            mcp_endpoint_risk: 0.0,
            declared_confinement_mismatch: 0.0,
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
fn default_ew_kernel_lineage_suspicious() -> f32 {
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

/// A sandboxed-application container whose data directory mirrors a user
/// profile, so the per-user application data roots apply again inside it:
/// macOS App Sandbox `Library/Containers/<bundle id>/Data/`, Windows MSIX
/// `AppData/Local/Packages/<family>/LocalCache/`, Linux Flatpak
/// `.var/app/<app id>/`. Relative to the profile and matched on a
/// lowercased, `/`-separated path:
/// `<container_root><container id>/<data_dir><inner root><owner>/...`.
/// `data_dir` is empty when the container directory holds the mirrored
/// roots itself.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxContainerLayoutJSON {
    pub container_root: String,
    pub data_dir: String,
    pub inner_roots: Vec<String>,
}

/// Per-user stores the operating system owns (macOS): below
/// `library_root` (profile-relative, `library/`), the owner directory --
/// the component below one of `library_state_directories` (`Caches`,
/// `HTTPStorages`, ...), or a direct child of the root -- starts with one of
/// `owner_prefixes` (`com.apple.`, `group.com.apple.`); a direct child may
/// also start with one of `direct_owner_prefixes` (`apple`). Lowercase.
/// File and directory NAMES (case-sensitive, as on disk) that mark a
/// developer toolchain tree, read by `dev_tree_attestation` on disk and by
/// the detector in the FIM stream:
/// - `cachedir_tag_file`: the Cache Directory Tagging file (its content
///   signature is fixed by the spec, see
///   `dev_tree_attestation::CACHEDIR_TAG_SIGNATURE`);
/// - `cmake_cache_file`: a CMake build directory;
/// - `node_manifest_file` next to `node_modules_directory` holding one of
///   `node_install_state_files` (npm, pnpm, yarn), or next to it and one of
///   `bun_lockfiles`: a JavaScript project root;
/// - `swiftpm_build_directory` holding `swiftpm_state_file`, next to
///   `swiftpm_manifest_file`: a SwiftPM build directory;
/// - one of `bazel_workspace_files` next to `bazel_output_link` or
///   `bazel_workspace_link_prefix` + the directory name: a Bazel workspace
///   that has built;
/// - `go_build_work_directory_prefix` + digits, with an action directory
///   holding one of `go_build_action_config_files`: a Go build work dir;
/// - `venv_config_file`: a PEP 405 virtual environment root.
///
/// The PEP 405 layout around a venv root, read by the detector from a FIM
/// event itself rather than from a marker file (FP-WIN-28, compared
/// case-insensitively): the interpreter lies in one of
/// `venv_interpreter_directories` (`Scripts` on Windows, `bin` on POSIX)
/// directly below the root, and the packages in one of
/// `venv_package_directories` (`site-packages`) below one of
/// `venv_library_directories` (`Lib`, `lib`), directly
/// (`Lib/site-packages`, Windows) or one version directory down
/// (`lib/python3.12/site-packages`, POSIX).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct DevTreeMarkersJSON {
    pub cachedir_tag_file: String,
    pub cmake_cache_file: String,
    pub node_manifest_file: String,
    pub node_modules_directory: String,
    pub node_install_state_files: Vec<String>,
    pub bun_lockfiles: Vec<String>,
    pub swiftpm_build_directory: String,
    pub swiftpm_state_file: String,
    pub swiftpm_manifest_file: String,
    pub bazel_workspace_files: Vec<String>,
    pub bazel_output_link: String,
    pub bazel_workspace_link_prefix: String,
    pub go_build_work_directory_prefix: String,
    pub go_build_action_config_files: Vec<String>,
    pub venv_config_file: String,
    pub venv_interpreter_directories: Vec<String>,
    pub venv_library_directories: Vec<String>,
    pub venv_package_directories: Vec<String>,
}

/// OS temp roots by role, matched on a lowercased, `/`-separated path:
/// - `windows_user_temp_marker` (`/appdata/local/temp/`) and
///   `windows_system_temp_marker` (`/windows/temp/`, where elevated
///   installers stage): found anywhere in the path; the temp root ends with
///   the marker;
/// - `posix_temp_roots` (`/tmp/`, `/var/tmp/` and their `/private`
///   spellings, which `notify` reports on macOS): at the start of the path;
/// - `macos_per_user_temp_trees` (`/private/var/folders/`): every path below
///   is in an OS temp directory, though the tree is not itself a temp root;
/// - the macOS per-user temp root `<macos_per_user_temp_parent><xx>/<hash>/
///   <macos_per_user_temp_leaf>` (`/var/folders/.../t`).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct OsTempRootsJSON {
    pub windows_user_temp_marker: String,
    pub windows_system_temp_marker: String,
    pub posix_temp_roots: Vec<String>,
    pub macos_per_user_temp_trees: Vec<String>,
    pub macos_per_user_temp_parent: String,
    pub macos_per_user_temp_leaf: String,
}

/// The name of a per-invocation temp scratch directory: optional leading
/// dots, `prefix` (`tmp`), optional dots, then an alphanumeric random token
/// of at least `min_token_len` characters (`.tmpTbnGVs` from Rust
/// `tempfile`, `tmp.A1b2C3d4e5` from `mktemp -d`, `tmpab12cd34` from
/// Python's `TemporaryDirectory`).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct TempScratchNameJSON {
    pub prefix: String,
    pub min_token_len: usize,
}

/// The names Python's `tempfile` module gives its scratch entries
/// (`tempfile.template`, then `_RandomNameSequence`): `<prefix><random>`
/// with an optional suffix (`TemporaryDirectory()`, `mkstemp(suffix=...)`),
/// and the bare `<random>` file `_get_default_tempdir` writes and deletes at
/// once when `tempfile` is first used. `alphabet` is the random part's
/// characters.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct PythonTempfileNameJSON {
    pub prefix: String,
    pub random_len: usize,
    pub alphabet: String,
}

/// The name of an ephemeral PowerShell stub in the Windows per-user temp
/// root: `<name_prefix><random><name_suffix>` (`.tmp*.ps1`).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsTempPowershellStubJSON {
    pub name_prefix: String,
    pub name_suffix: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformOwnedUserStoreJSON {
    pub library_root: String,
    pub library_state_directories: Vec<String>,
    pub owner_prefixes: Vec<String>,
    pub direct_owner_prefixes: Vec<String>,
}

/// One class of hosts the divergence correlation plane does not count as
/// unexplained egress: DNS resolvers, time sync, certificate revocation
/// responders, connectivity probes, OS update, toolchain telemetry. A host
/// (lowercase, no port, no trailing dot) belongs to the class on one of its
/// `ports` when it:
/// - is one of `hosts`;
/// - ends with one of `suffixes`, each starting with a dot (the bare domain
///   is not covered by its own suffix);
/// - has one of `first_labels` as its first DNS label;
/// - has a first label that is one of `numbered_first_labels` followed only
///   by digits (`crl` covers `crl` and `crl3`, never `crlx` or `crl-sync`).
///
/// No substring or prefix matching beyond these (G-39: a `time.` / `ntp.`
/// prefix or a `crl` substring is not an exemption).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct DivergenceInfrastructureEndpointClassJSON {
    pub class: String,
    pub hosts: Vec<String>,
    pub suffixes: Vec<String>,
    pub first_labels: Vec<String>,
    pub numbered_first_labels: Vec<String>,
    pub ports: Vec<u16>,
}

/// The files an agent harness captures the output of the commands it runs
/// into: Claude Code writes a background command's stdout and stderr to
/// `<temp>/claude[-<uid>]/<project>/<session>/tasks/<id>.output` on every
/// platform. The command's process holds the file, so FIM names whatever
/// the agent ran as its writer (FP lab 2026-10-06, shiawase: a temp venv's
/// `python.exe` that had fetched from PyPI read as a dropper staging a
/// payload). A path matches an entry when one of its segments is a
/// `root_names` entry or starts with a `root_prefixes` entry, exactly
/// `levels_below_root` segments follow it, then `capture_dir`, then the
/// file, which ends with `file_suffix`.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentHarnessOutputCaptureJSON {
    pub agent: String,
    pub root_names: Vec<String>,
    pub root_prefixes: Vec<String>,
    pub levels_below_root: usize,
    pub capture_dir: String,
    pub file_suffix: String,
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
    /// Names a FIM writer carries when the kernel performed the write on
    /// another process's behalf and no image path exists: Windows' `System`
    /// (PID 4), the cache manager's lazy writer flushing dirty pages. Such a
    /// write is unattributed, not attributed to a process of that name.
    pub fim_kernel_pseudo_writer_names: Vec<String>,
    pub fim_temp_executable_patterns: Vec<String>,
    /// Basenames (lowercase, `.exe` stripped by the consumer) of processes
    /// whose memory holds credentials or tokens (CI runner workers, key
    /// agents, password managers, browsers, cloud CLIs). Consumed by
    /// `process_memory_scrape`. Born complete on the wire.
    pub process_memory_scrape_sensitive_target_basenames: Vec<String>,
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
    /// R4 (A4): when true, the CRS band is authoritative for non-floor
    /// findings -- the monotonic-down clamp and the legacy-LOW keep are
    /// bypassed (EvidenceFloor findings keep legacy severity either
    /// way, and the ARIS>=50 CRITICAL floor still applies). Flip via
    /// CloudModel only after a clean shadow-disagreement observation
    /// window (`crs_shadow_disagreements_total` flat across the fleet).
    /// Default false.
    pub crs_authoritative_enabled: bool,
    /// INC-19 kernel-lineage flip: when true, `kernel_lineage_suspicious`
    /// (own image or ANY kernel ancestor matches the suspicious-lineage
    /// patterns) feeds `suspicious_lineage_present` -- and with it the
    /// EvidenceFloor tier for `file_system_tampering` /
    /// `sandbox_exploitation` -- instead of only stamping the
    /// `kernel_lineage_shadow:suspicious` basis tag. Flip via CloudModel
    /// after a flat `kernel_lineage_shadow_total` window on the fleet and a
    /// green 4-platform gate. Default false.
    pub kernel_lineage_flip_enabled: bool,
    /// Deterministic divergence floor (DETECTIONGAPSPLAN-2026-09 Inc 5):
    /// when true, an agent-attributed session with untrusted lineage
    /// (`spawned_from_tmp` or kernel `lineage_suspicious`) that is
    /// corroborated by undeclared external egress or sensitive-material
    /// access emits `correlation:untrusted_lineage_floor` (HIGH) even when
    /// the declared plan never mentioned the lineage dimension, and the
    /// prediction-independent half of the correlation keeps running on
    /// Stale / NoModel ticks. Shadow-tagged while false. Default false.
    pub divergence_lineage_floor_enabled: bool,
    /// B4 cross-engine evidence bus, injection direction: when true, active
    /// attack-pattern findings on agent-bound sessions are injected into the
    /// same tick's divergence correlation as `vulnerability:<check>`
    /// evidence (non-clearable) and a session carrying both signals is
    /// escalated to CRITICAL. The detector-side bus fields are populated
    /// regardless (their weights are what gate their effect). Default false.
    pub cross_engine_bus_enabled: bool,
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
    /// Per-user application data roots, relative to the profile directory
    /// (lowercase, `/`): the FIRST component below one is the directory an
    /// application creates for its own state (`library/application
    /// support/<App>/`, `appdata/roaming/<Vendor>/`, `.config/<app>/`). Read
    /// by the owned-store demotes of `token_exfiltration` and
    /// `sensitive_material_egress`.
    pub per_user_app_data_roots: Vec<String>,
    /// Sandboxed-application containers that mirror a user profile (see
    /// [`SandboxContainerLayoutJSON`]).
    pub sandbox_container_layouts: Vec<SandboxContainerLayoutJSON>,
    /// Install roots whose next path component names the installed product
    /// on Windows and Linux (`/program files/`, `/appdata/local/programs/`),
    /// found anywhere in a lowercased, `/`-separated process path.
    pub application_install_roots: Vec<String>,
    /// Install roots only an administrator can write to (Windows
    /// `/program files/`, `/program files (x86)/`, `/program files (arm64)/`),
    /// matched at the start of a path after its drive letter. A directory
    /// named `Temp` under one (EdgeUpdate's `Program Files (x86)/Microsoft/
    /// Temp/`) is a product's own staging area, not user-writable staging.
    pub admin_only_install_roots: Vec<String>,
    /// Install prefixes whose next component names the installed product
    /// (`/opt/`, `/usr/lib/`, ...), matched at the start of the path.
    pub application_install_prefixes: Vec<String>,
    /// Tokens that name a layout, a platform, a vendor-neutral role or a
    /// reverse-DNS prefix, never a product (`com`, `data`, `helper`,
    /// `packages`, ...): dropped when an owner directory is matched against
    /// the reading application.
    pub owned_store_generic_tokens: Vec<String>,
    /// Shortest owner token that can name a product.
    pub owned_store_min_token_len: usize,
    /// Per-user stores the operating system owns (see
    /// [`PlatformOwnedUserStoreJSON`]).
    pub platform_owned_user_store: PlatformOwnedUserStoreJSON,
    /// Path prefixes of operating-system SERVICE images (daemons, XPC
    /// services, the launch trampoline): `/system/library/`,
    /// `/usr/libexec/`. General-purpose tools (`/usr/bin`) are not services.
    pub os_service_image_path_prefixes: Vec<String>,
    /// Binary roots on the macOS sealed system volume that hold only
    /// platform daemons and helpers (`/system/library/`, `/usr/libexec/`,
    /// `/usr/sbin/`; not `/usr/bin`, which holds general-purpose tools).
    pub macos_sealed_system_binary_path_prefixes: Vec<String>,
    /// Process lineage agent-subtree binding: agent slug (the plugin slugs
    /// of `agent_plugin`) -> the tool names of its images (lowercase, `.exe`
    /// stripped). A name belongs to one agent. Monitoring-only evidence: the
    /// kernel-vouched signing identity is the intended replacement.
    pub agent_process_names: BTreeMap<String, Vec<String>>,
    /// Directory names that hold a tool's versioned releases rather than
    /// name it (`<tool>/versions/<ver>`, `<tool>/current/<ver>`): skipped
    /// when a version-named image takes its tool name from a directory.
    pub version_layout_directories: Vec<String>,
    /// Tool names of the desktop shell and the session / service managers
    /// that launch every application the user starts (`explorer`,
    /// `svchost`, `launchd`, `loginwindow`, `systemd`, desktop sessions and
    /// shells). Being their child says nothing about a relationship between
    /// two applications. Command shells are deliberately not roles.
    pub desktop_session_root_roles: Vec<String>,
    /// IPv4 ranges (CIDR) on the host's own side of the access network:
    /// `192.0.0.0/29`, the RFC 7335 service continuity prefix (DS-Lite B4 /
    /// AFTR, the 464XLAT CLAT). A flow to one ends at the CPE / tunnel
    /// endpoint, never at a remote peer, so it is not external egress. A
    /// range wider than a /16 is ignored.
    pub access_network_plumbing_ipv4_cidrs: Vec<String>,
    /// Script / language runtimes: processes that execute code handed to
    /// them rather than act on their own behalf. Compared with a basename
    /// lowercased, without a Windows `.exe` / `.cmd` / `.bat` suffix and any
    /// trailing version (`python3.12`, `perl5.34`).
    pub script_runtime_basenames: Vec<String>,
    /// Path fragments (lowercase, `/`) that identify a dependency tree
    /// (`/node_modules/`, `/site-packages/`, `/.cargo/registry/`, ...),
    /// tried in order: the first one a path contains is reported.
    pub dependency_tree_markers: Vec<String>,
    /// Basenames (version suffix stripped) of the runtimes that drive an
    /// install: the package managers and the interpreters they hand
    /// lifecycle scripts to.
    pub package_manager_runtimes: Vec<String>,
    /// Lockfiles and manifests an install legitimately rewrites (lowercase
    /// basenames).
    pub install_artifact_basenames: Vec<String>,
    /// The bare language runtimes among `package_manager_runtimes` (`node`,
    /// `python`): they run any program, not only installs. A lineage whose
    /// only package-manager names are these, anchored only under a global
    /// CLI install root, is an installed CLI running, not an install.
    pub package_bare_runtimes: Vec<String>,
    /// Path fragments (lowercase, `/`) of global CLI install roots: npm's
    /// global prefix (`/lib/node_modules/`, Windows `/npm/node_modules/`),
    /// bun's and pnpm's global stores, pipx and uv tool environments.
    pub global_package_roots: Vec<String>,
    /// Developer toolchain tree markers (see [`DevTreeMarkersJSON`]).
    pub dev_tree_markers: DevTreeMarkersJSON,
    /// Suffixes (lowercase) of code and persistence definitions that are
    /// never a data artifact, even where `benign_temp_artifact_suffixes`
    /// lists them: PowerShell modules and the launchd / systemd / XDG
    /// autostart / Task Scheduler definitions.
    pub code_module_suffixes: Vec<String>,
    /// Labels of the sensitive-paths catalog (`sensitive-paths-db.json`)
    /// that denote credential material. A label the catalog emits but that
    /// is absent here counts as non-credential (`env` deliberately: `.env`
    /// also ships committed in repositories).
    pub sensitive_material_labels: Vec<String>,
    /// Catalog labels that name agent instruction / configuration surfaces
    /// (`instruction`, `claude`, `codex`, `openclaw`).
    pub agent_instruction_labels: Vec<String>,
    /// Agent slug -> path suffixes (lowercase, `/`) of that agent's
    /// ENFORCEMENT configuration (`agent_control_tampering`): the documented
    /// location of each agent's control config. Session transcripts,
    /// caches, history and project state under the same roots deliberately
    /// do not match. A suffix belongs to one agent.
    pub agent_control_config_path_suffixes: BTreeMap<String, Vec<String>>,
    /// Generic certificate / legal-entity vocabulary (lowercase) dropped
    /// from a code-signing publisher's name (`Developer ID Application:
    /// Google LLC (EQHXZ8M8AV)` -> `google`) before its organization tokens
    /// are compared with a destination's owner.
    pub publisher_org_stop_tokens: Vec<String>,
    /// Shortest publisher organization token kept.
    pub publisher_org_min_token_len: usize,
    /// `process_memory_scrape`: distinct targets one requester has to open
    /// read-only within a tick before its reads read as an inventory sweep
    /// rather than a targeted scrape (a theft names its victim).
    pub memory_scrape_read_enumeration_min_distinct_targets: usize,
    /// `process_memory_scrape` census: shortest hex run that marks a path
    /// segment as naming one invocation (`<crate>-<hash>`, a GUID unpack
    /// directory) rather than a tool.
    pub memory_scrape_per_invocation_min_hex_run: usize,
    /// `sensitive_material_egress` process-tree relay: distinct credential
    /// classes the sibling must hold (a single ambient secret next door is
    /// ordinary developer work).
    pub relay_min_credential_classes: usize,
    /// Distinct local processes reaching one blacklisted prefix before it
    /// reads as shared infrastructure (VPN / proxy / CDN egress) rather than
    /// a C2 endpoint.
    /// Domains under which every subdomain belongs to whoever registered it
    /// (the shared-hosting part of the Public Suffix List, curated: cloud
    /// storage and app hosting, static-site platforms, tunnels, SaaS tenant
    /// hosts). A human grant of a domain covers its subdomains only when no
    /// such suffix lies between them (`divergence_policy`).
    pub shared_hosting_public_suffixes: Vec<String>,
    /// Evaluator integrity (`divergence_policy`): directory names that hold
    /// test cases (`tests`, `__tests__`, `fixtures`, ...).
    pub measurement_test_directory_segments: Vec<String>,
    /// File-name prefixes of a test case (`test_`).
    pub measurement_test_filename_prefixes: Vec<String>,
    /// File-name suffixes of a test case (`_test.go`, `.spec.ts`, ...).
    pub measurement_test_filename_suffixes: Vec<String>,
    /// Runner and CI configuration files that decide what runs for every
    /// case (`conftest.py`, `vitest.config.ts`, `.gitlab-ci.yml`, ...).
    pub measurement_harness_filenames: Vec<String>,
    /// Directories (relative, `/`-separated) whose files are harness
    /// configuration (`.github/workflows`).
    pub measurement_harness_directory_paths: Vec<String>,
    /// Directory names whose content is derived or third-party, never the
    /// project's measurement surface: bytecode and tool caches
    /// (`__pycache__`, `.pytest_cache`) and installed packages
    /// (`site-packages`, `node_modules`), tests they ship included.
    pub measurement_derived_directory_segments: Vec<String>,
    /// Words of a declared task that make it measurement work (`test`,
    /// `coverage`, `fixture`, ...): such a task may touch the surface.
    pub measurement_intent_tokens: Vec<String>,
    /// Distinct paths one writer must lay down within the burst before its
    /// writes read as a materialisation batch (a clone, an extract).
    pub evaluator_materialisation_min_paths: usize,
    /// The measurement surface may be at most `1 / N` of such a batch.
    pub evaluator_materialisation_measurement_divisor: usize,
    /// How far either side of a graded write the writer's other writes
    /// count towards its batch.
    pub evaluator_materialisation_burst_secs: i64,
    /// How far outside a session's transcript span (file birth to last
    /// write) a write is still graded against that session.
    pub evaluator_session_attribution_slack_secs: i64,
    /// The SSH client's own host-key state (`~/.ssh/known_hosts`): a human
    /// who authorizes an SSH connection authorizes the client reading and
    /// updating these. Never private keys.
    pub ssh_client_state_files: Vec<String>,
    /// Hosts the divergence correlation plane never counts as unexplained
    /// egress, by class with the ports each covers (see
    /// [`DivergenceInfrastructureEndpointClassJSON`]).
    pub divergence_infrastructure_endpoints: Vec<DivergenceInfrastructureEndpointClassJSON>,
    /// Agent harness output-capture files (see
    /// [`AgentHarnessOutputCaptureJSON`]).
    pub agent_harness_output_capture: Vec<AgentHarnessOutputCaptureJSON>,
    /// Python's `tempfile` scratch names (see [`PythonTempfileNameJSON`]).
    pub python_tempfile_name: PythonTempfileNameJSON,
    pub shared_infrastructure_min_local_processes: usize,
    /// OS temp roots by role (see [`OsTempRootsJSON`]).
    pub os_temp_roots: OsTempRootsJSON,
    /// Per-invocation temp scratch directory names (see
    /// [`TempScratchNameJSON`]).
    pub temp_scratch_name: TempScratchNameJSON,
    /// Ephemeral PowerShell stub names in the Windows per-user temp root
    /// (see [`WindowsTempPowershellStubJSON`]).
    pub windows_temp_powershell_stub: WindowsTempPowershellStubJSON,
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
    /// Names a FIM writer carries when the kernel performed the write on
    /// another process's behalf and no image path exists: Windows' `System`
    /// (PID 4), the cache manager's lazy writer flushing dirty pages. Such a
    /// write is unattributed, not attributed to a process of that name.
    pub fim_kernel_pseudo_writer_names: Vec<String>,
    pub fim_temp_executable_patterns: Vec<String>,
    /// Basenames (lowercase, `.exe` stripped by the consumer) of processes
    /// whose memory holds credentials or tokens (CI runner workers, key
    /// agents, password managers, browsers, cloud CLIs). Consumed by
    /// `process_memory_scrape`. Born complete on the wire.
    pub process_memory_scrape_sensitive_target_basenames: Vec<String>,
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
    /// R4 (A4): when true, the CRS band is authoritative for non-floor
    /// findings -- the monotonic-down clamp and the legacy-LOW keep are
    /// bypassed (EvidenceFloor findings keep legacy severity either
    /// way, and the ARIS>=50 CRITICAL floor still applies). Flip via
    /// CloudModel only after a clean shadow-disagreement observation
    /// window (`crs_shadow_disagreements_total` flat across the fleet).
    /// Default false.
    pub crs_authoritative_enabled: bool,
    pub kernel_lineage_flip_enabled: bool,
    pub divergence_lineage_floor_enabled: bool,
    pub cross_engine_bus_enabled: bool,
    pub evidence_weights: EvidenceWeightsJSON,
    pub secret_content_powershell_probe_read_verbs: Vec<String>,
    pub secret_content_powershell_dangerous_verbs: Vec<String>,
    pub secret_content_signatures: Vec<SecretContentSignatureJSON>,
    pub per_user_app_data_roots: Vec<String>,
    pub sandbox_container_layouts: Vec<SandboxContainerLayoutJSON>,
    pub application_install_roots: Vec<String>,
    pub admin_only_install_roots: Vec<String>,
    pub application_install_prefixes: Vec<String>,
    pub owned_store_generic_tokens: HashSet<String>,
    pub owned_store_min_token_len: usize,
    pub platform_owned_user_store: PlatformOwnedUserStoreJSON,
    pub os_service_image_path_prefixes: Vec<String>,
    pub macos_sealed_system_binary_path_prefixes: Vec<String>,
    pub agent_process_names: BTreeMap<String, Vec<String>>,
    pub version_layout_directories: HashSet<String>,
    pub desktop_session_root_roles: HashSet<String>,
    /// `access_network_plumbing_ipv4_cidrs` parsed as (network, mask).
    pub access_network_plumbing_ipv4_ranges: Vec<(u32, u32)>,
    pub script_runtime_basenames: HashSet<String>,
    pub dependency_tree_markers: Vec<String>,
    pub package_manager_runtimes: HashSet<String>,
    pub install_artifact_basenames: HashSet<String>,
    pub package_bare_runtimes: HashSet<String>,
    /// `global_package_roots` as lowercase `/` fragments.
    pub global_package_roots: Vec<String>,
    pub dev_tree_markers: DevTreeMarkersJSON,
    pub code_module_suffixes: Vec<String>,
    pub sensitive_material_labels: HashSet<String>,
    pub agent_instruction_labels: HashSet<String>,
    pub agent_control_config_path_suffixes: BTreeMap<String, Vec<String>>,
    pub publisher_org_stop_tokens: HashSet<String>,
    pub publisher_org_min_token_len: usize,
    pub memory_scrape_read_enumeration_min_distinct_targets: usize,
    pub memory_scrape_per_invocation_min_hex_run: usize,
    pub relay_min_credential_classes: usize,
    /// Domains under which every subdomain belongs to whoever registered it
    /// (the shared-hosting part of the Public Suffix List, curated: cloud
    /// storage and app hosting, static-site platforms, tunnels, SaaS tenant
    /// hosts). A human grant of a domain covers its subdomains only when no
    /// such suffix lies between them (`divergence_policy`).
    pub shared_hosting_public_suffixes: Vec<String>,
    /// The `measurement_*` lists, lowercase (see the JSON struct).
    pub measurement_test_directory_segments: HashSet<String>,
    pub measurement_test_filename_prefixes: Vec<String>,
    pub measurement_test_filename_suffixes: Vec<String>,
    pub measurement_harness_filenames: HashSet<String>,
    pub measurement_harness_directory_paths: Vec<String>,
    pub measurement_derived_directory_segments: HashSet<String>,
    pub measurement_intent_tokens: Vec<String>,
    pub evaluator_materialisation_min_paths: usize,
    pub evaluator_materialisation_measurement_divisor: usize,
    pub evaluator_materialisation_burst_secs: i64,
    pub evaluator_session_attribution_slack_secs: i64,
    pub ssh_client_state_files: Vec<String>,
    /// `divergence_infrastructure_endpoints`, lowercase and trimmed, each
    /// suffix with its leading dot, empty entries dropped.
    pub divergence_infrastructure_endpoints: Vec<DivergenceInfrastructureEndpointClassJSON>,
    /// `agent_harness_output_capture`, lowercase and trimmed.
    pub agent_harness_output_capture: Vec<AgentHarnessOutputCaptureJSON>,
    /// Python's `tempfile` scratch names (see [`PythonTempfileNameJSON`]).
    pub python_tempfile_name: PythonTempfileNameJSON,
    pub shared_infrastructure_min_local_processes: usize,
    pub os_temp_roots: OsTempRootsJSON,
    pub temp_scratch_name: TempScratchNameJSON,
    pub windows_temp_powershell_stub: WindowsTempPowershellStubJSON,
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

/// Path fragments lowercased with `/` separators, empty entries dropped (an
/// empty fragment would match every path).
fn normalized_path_fragments(list: &[String]) -> Vec<String> {
    list.iter()
        .map(|fragment| fragment.trim().to_ascii_lowercase().replace('\\', "/"))
        .filter(|fragment| !fragment.is_empty())
        .collect()
}

/// Substrings matched, in order, against a lowercased value. Kept as
/// written apart from case: the intent token `"ci "` carries its space.
fn lowercase_tokens(list: &[String]) -> Vec<String> {
    list.iter()
        .map(|token| token.to_ascii_lowercase())
        .filter(|token| !token.trim().is_empty())
        .collect()
}

/// Names and tokens compared for equality with a lowercased value.
fn lowercase_token_set(list: &[String]) -> HashSet<String> {
    list.iter()
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

/// Names, tokens and name prefixes lowercased, in order, empty entries
/// dropped (an empty prefix would match every name).
fn lowercase_token_list(list: &[String]) -> Vec<String> {
    list.iter()
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

fn normalized_platform_owned_user_store(
    store: &PlatformOwnedUserStoreJSON,
) -> PlatformOwnedUserStoreJSON {
    PlatformOwnedUserStoreJSON {
        library_root: store
            .library_root
            .trim()
            .to_ascii_lowercase()
            .replace('\\', "/"),
        library_state_directories: lowercase_token_list(&store.library_state_directories),
        owner_prefixes: lowercase_token_list(&store.owner_prefixes),
        direct_owner_prefixes: lowercase_token_list(&store.direct_owner_prefixes),
    }
}

/// Temp roots lowercased with `/` separators; empty list entries dropped.
/// An empty single root stays empty and never matches (the detector
/// checks).
fn normalized_divergence_infrastructure_endpoints(
    classes: &[DivergenceInfrastructureEndpointClassJSON],
) -> Vec<DivergenceInfrastructureEndpointClassJSON> {
    classes
        .iter()
        .map(|class| DivergenceInfrastructureEndpointClassJSON {
            class: class.class.trim().to_ascii_lowercase(),
            hosts: class
                .hosts
                .iter()
                .map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|host| !host.is_empty())
                .collect(),
            // A suffix always keeps its leading dot: `windowsupdate.com`
            // published without one must not cover `evilwindowsupdate.com`.
            suffixes: class
                .suffixes
                .iter()
                .map(|suffix| suffix.trim().trim_matches('.').to_ascii_lowercase())
                .filter(|suffix| !suffix.is_empty())
                .map(|suffix| format!(".{suffix}"))
                .collect(),
            first_labels: lowercase_token_list(&class.first_labels),
            // An empty prefix would cover every all-digit first label (an
            // IPv4 address's first octet).
            numbered_first_labels: lowercase_token_list(&class.numbered_first_labels),
            ports: class.ports.clone(),
        })
        .collect()
}

fn normalized_os_temp_roots(roots: &OsTempRootsJSON) -> OsTempRootsJSON {
    let fragment = |value: &str| value.trim().to_ascii_lowercase().replace('\\', "/");
    OsTempRootsJSON {
        windows_user_temp_marker: fragment(&roots.windows_user_temp_marker),
        windows_system_temp_marker: fragment(&roots.windows_system_temp_marker),
        posix_temp_roots: normalized_path_fragments(&roots.posix_temp_roots),
        macos_per_user_temp_trees: normalized_path_fragments(&roots.macos_per_user_temp_trees),
        macos_per_user_temp_parent: fragment(&roots.macos_per_user_temp_parent),
        macos_per_user_temp_leaf: fragment(&roots.macos_per_user_temp_leaf),
    }
}

/// On-disk names are trimmed but keep their case; empty list entries are
/// dropped. An empty single name stays empty and its marker never matches
/// (`dev_tree_attestation` checks).
fn trimmed_dev_tree_markers(markers: &DevTreeMarkersJSON) -> DevTreeMarkersJSON {
    let names = |list: &[String]| -> Vec<String> {
        list.iter()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .collect()
    };
    DevTreeMarkersJSON {
        cachedir_tag_file: markers.cachedir_tag_file.trim().to_string(),
        cmake_cache_file: markers.cmake_cache_file.trim().to_string(),
        node_manifest_file: markers.node_manifest_file.trim().to_string(),
        node_modules_directory: markers.node_modules_directory.trim().to_string(),
        node_install_state_files: names(&markers.node_install_state_files),
        bun_lockfiles: names(&markers.bun_lockfiles),
        swiftpm_build_directory: markers.swiftpm_build_directory.trim().to_string(),
        swiftpm_state_file: markers.swiftpm_state_file.trim().to_string(),
        swiftpm_manifest_file: markers.swiftpm_manifest_file.trim().to_string(),
        bazel_workspace_files: names(&markers.bazel_workspace_files),
        bazel_output_link: markers.bazel_output_link.trim().to_string(),
        bazel_workspace_link_prefix: markers.bazel_workspace_link_prefix.trim().to_string(),
        go_build_work_directory_prefix: markers.go_build_work_directory_prefix.trim().to_string(),
        go_build_action_config_files: names(&markers.go_build_action_config_files),
        venv_config_file: markers.venv_config_file.trim().to_string(),
        venv_interpreter_directories: names(&markers.venv_interpreter_directories),
        venv_library_directories: names(&markers.venv_library_directories),
        venv_package_directories: names(&markers.venv_package_directories),
    }
}

/// Narrowest accepted prefix for a range the detector treats as "not
/// external": a wider one (a publishing mistake) would blind egress
/// detection for it, so it is ignored.
const ACCESS_NETWORK_PLUMBING_MIN_PREFIX_LEN: u32 = 16;

/// `a.b.c.d/len` as (network, mask); `None` for anything else, or for a
/// range wider than [`ACCESS_NETWORK_PLUMBING_MIN_PREFIX_LEN`].
fn parse_access_network_plumbing_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (address, len) = cidr.trim().split_once('/')?;
    let address: std::net::Ipv4Addr = address.trim().parse().ok()?;
    let len: u32 = len.trim().parse().ok()?;
    if !(ACCESS_NETWORK_PLUMBING_MIN_PREFIX_LEN..=32).contains(&len) {
        return None;
    }
    let mask = u32::MAX << (32 - len);
    Some((u32::from(address) & mask, mask))
}

/// Layouts normalized like path fragments; one without a container root is
/// dropped (it would read every profile directory as a container).
fn normalized_sandbox_container_layouts(
    layouts: &[SandboxContainerLayoutJSON],
) -> Vec<SandboxContainerLayoutJSON> {
    layouts
        .iter()
        .map(|layout| SandboxContainerLayoutJSON {
            container_root: layout
                .container_root
                .trim()
                .to_ascii_lowercase()
                .replace('\\', "/"),
            data_dir: layout
                .data_dir
                .trim()
                .to_ascii_lowercase()
                .replace('\\', "/"),
            inner_roots: normalized_path_fragments(&layout.inner_roots),
        })
        .filter(|layout| !layout.container_root.is_empty())
        .collect()
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
            fim_kernel_pseudo_writer_names: json
                .fim_kernel_pseudo_writer_names
                .iter()
                .map(|name| name.trim().to_ascii_lowercase())
                .filter(|name| !name.is_empty())
                .collect(),
            publisher_attestation_enabled: json.publisher_attestation_enabled,
            treat_high_volume_dns_ntp_as_non_routine: json.treat_high_volume_dns_ntp_as_non_routine,
            dns_ntp_non_routine_min_outbound_bytes: json.dns_ntp_non_routine_min_outbound_bytes,
            evidence_floor_requires_graded_anomaly: json.evidence_floor_requires_graded_anomaly,
            ambient_baseline_enabled: json.ambient_baseline_enabled,
            ambient_baseline_min_recurrent_days: json.ambient_baseline_min_recurrent_days,
            ambient_baseline_ttl_days: json.ambient_baseline_ttl_days,
            crs_authoritative_enabled: json.crs_authoritative_enabled,
            kernel_lineage_flip_enabled: json.kernel_lineage_flip_enabled,
            divergence_lineage_floor_enabled: json.divergence_lineage_floor_enabled,
            cross_engine_bus_enabled: json.cross_engine_bus_enabled,
            process_memory_scrape_sensitive_target_basenames: json
                .process_memory_scrape_sensitive_target_basenames
                .iter()
                .map(|b| b.trim().to_ascii_lowercase())
                .filter(|b| !b.is_empty())
                .collect(),
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
            per_user_app_data_roots: normalized_path_fragments(&json.per_user_app_data_roots),
            sandbox_container_layouts: normalized_sandbox_container_layouts(
                &json.sandbox_container_layouts,
            ),
            application_install_roots: normalized_path_fragments(&json.application_install_roots),
            admin_only_install_roots: normalized_path_fragments(&json.admin_only_install_roots),
            application_install_prefixes: normalized_path_fragments(
                &json.application_install_prefixes,
            ),
            owned_store_generic_tokens: lowercase_token_set(&json.owned_store_generic_tokens),
            owned_store_min_token_len: json.owned_store_min_token_len,
            platform_owned_user_store: normalized_platform_owned_user_store(
                &json.platform_owned_user_store,
            ),
            os_service_image_path_prefixes: normalized_path_fragments(
                &json.os_service_image_path_prefixes,
            ),
            macos_sealed_system_binary_path_prefixes: normalized_path_fragments(
                &json.macos_sealed_system_binary_path_prefixes,
            ),
            agent_process_names: json
                .agent_process_names
                .iter()
                .map(|(slug, names)| (slug.trim().to_string(), lowercase_token_list(names)))
                .filter(|(slug, _)| !slug.is_empty())
                .collect(),
            version_layout_directories: lowercase_token_set(&json.version_layout_directories),
            desktop_session_root_roles: lowercase_token_set(&json.desktop_session_root_roles),
            access_network_plumbing_ipv4_ranges: json
                .access_network_plumbing_ipv4_cidrs
                .iter()
                .filter_map(|cidr| parse_access_network_plumbing_cidr(cidr))
                .collect(),
            script_runtime_basenames: lowercase_token_set(&json.script_runtime_basenames),
            dependency_tree_markers: normalized_path_fragments(&json.dependency_tree_markers),
            package_manager_runtimes: lowercase_token_set(&json.package_manager_runtimes),
            package_bare_runtimes: lowercase_token_set(&json.package_bare_runtimes),
            global_package_roots: normalized_path_fragments(&json.global_package_roots),
            install_artifact_basenames: lowercase_token_set(&json.install_artifact_basenames),
            dev_tree_markers: trimmed_dev_tree_markers(&json.dev_tree_markers),
            code_module_suffixes: lowercase_token_list(&json.code_module_suffixes),
            sensitive_material_labels: lowercase_token_set(&json.sensitive_material_labels),
            agent_instruction_labels: lowercase_token_set(&json.agent_instruction_labels),
            agent_control_config_path_suffixes: json
                .agent_control_config_path_suffixes
                .iter()
                .map(|(agent, suffixes)| {
                    (
                        agent.trim().to_string(),
                        normalized_path_fragments(suffixes),
                    )
                })
                .filter(|(agent, _)| !agent.is_empty())
                .collect(),
            publisher_org_stop_tokens: lowercase_token_set(&json.publisher_org_stop_tokens),
            publisher_org_min_token_len: json.publisher_org_min_token_len,
            memory_scrape_read_enumeration_min_distinct_targets: json
                .memory_scrape_read_enumeration_min_distinct_targets,
            memory_scrape_per_invocation_min_hex_run: json.memory_scrape_per_invocation_min_hex_run,
            relay_min_credential_classes: json.relay_min_credential_classes,
            measurement_test_directory_segments: lowercase_token_set(
                &json.measurement_test_directory_segments,
            ),
            measurement_test_filename_prefixes: lowercase_tokens(
                &json.measurement_test_filename_prefixes,
            ),
            measurement_test_filename_suffixes: lowercase_tokens(
                &json.measurement_test_filename_suffixes,
            ),
            measurement_harness_filenames: lowercase_token_set(&json.measurement_harness_filenames),
            measurement_harness_directory_paths: json
                .measurement_harness_directory_paths
                .iter()
                .map(|dir| {
                    dir.trim()
                        .to_ascii_lowercase()
                        .replace('\\', "/")
                        .trim_matches('/')
                        .to_string()
                })
                .filter(|dir| !dir.is_empty())
                .collect(),
            measurement_derived_directory_segments: lowercase_token_set(
                &json.measurement_derived_directory_segments,
            ),
            measurement_intent_tokens: lowercase_tokens(&json.measurement_intent_tokens),
            evaluator_materialisation_min_paths: json.evaluator_materialisation_min_paths,
            evaluator_materialisation_measurement_divisor: json
                .evaluator_materialisation_measurement_divisor
                .max(1),
            evaluator_materialisation_burst_secs: json.evaluator_materialisation_burst_secs,
            evaluator_session_attribution_slack_secs: json.evaluator_session_attribution_slack_secs,
            ssh_client_state_files: json
                .ssh_client_state_files
                .iter()
                .map(|path| path.trim().to_string())
                .filter(|path| !path.is_empty())
                .collect(),
            divergence_infrastructure_endpoints: normalized_divergence_infrastructure_endpoints(
                &json.divergence_infrastructure_endpoints,
            ),
            agent_harness_output_capture: json
                .agent_harness_output_capture
                .iter()
                .map(|entry| {
                    let lower = |list: &[String]| -> Vec<String> {
                        list.iter()
                            .map(|v| v.trim().to_ascii_lowercase())
                            .filter(|v| !v.is_empty())
                            .collect()
                    };
                    AgentHarnessOutputCaptureJSON {
                        agent: entry.agent.trim().to_string(),
                        root_names: lower(&entry.root_names),
                        root_prefixes: lower(&entry.root_prefixes),
                        levels_below_root: entry.levels_below_root,
                        capture_dir: entry.capture_dir.trim().to_ascii_lowercase(),
                        file_suffix: entry.file_suffix.trim().to_ascii_lowercase(),
                    }
                })
                .collect(),
            shared_hosting_public_suffixes: json
                .shared_hosting_public_suffixes
                .iter()
                .map(|suffix| suffix.trim().trim_matches('.').to_ascii_lowercase())
                .filter(|suffix| !suffix.is_empty())
                .collect(),
            shared_infrastructure_min_local_processes: json
                .shared_infrastructure_min_local_processes,
            python_tempfile_name: PythonTempfileNameJSON {
                prefix: json.python_tempfile_name.prefix.trim().to_ascii_lowercase(),
                random_len: json.python_tempfile_name.random_len,
                alphabet: json
                    .python_tempfile_name
                    .alphabet
                    .trim()
                    .to_ascii_lowercase(),
            },
            os_temp_roots: normalized_os_temp_roots(&json.os_temp_roots),
            temp_scratch_name: TempScratchNameJSON {
                prefix: json.temp_scratch_name.prefix.trim().to_ascii_lowercase(),
                min_token_len: json.temp_scratch_name.min_token_len,
            },
            windows_temp_powershell_stub: WindowsTempPowershellStubJSON {
                name_prefix: json
                    .windows_temp_powershell_stub
                    .name_prefix
                    .trim()
                    .to_ascii_lowercase(),
                name_suffix: json
                    .windows_temp_powershell_stub
                    .name_suffix
                    .trim()
                    .to_ascii_lowercase(),
            },
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
        .any(|prefix| {
            // Only the name is folded: the prefixes are already lowercased by
            // `CveDetectionParams::new_from_json`, so a capitalised entry in
            // the published list (`Runner.Worker`, `Runner.Listener`) reaches
            // here as its lower-case form. Same convention as the other
            // params-backed lookups; the test below pins the invariant.
            !prefix.is_empty() && lower.starts_with(prefix.as_str())
        })
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

/// Whether a FIM writer named `name` with no image path is the kernel
/// writing on another process's behalf (`fim_kernel_pseudo_writer_names`).
pub fn is_fim_kernel_pseudo_writer_name(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    !name.is_empty()
        && PARAMS_SNAPSHOT
            .load()
            .fim_kernel_pseudo_writer_names
            .contains(&name)
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
    PARAMS_SNAPSHOT
        .load()
        .treat_high_volume_dns_ntp_as_non_routine
}

pub fn dns_ntp_non_routine_min_outbound_bytes() -> u64 {
    PARAMS_SNAPSHOT
        .load()
        .dns_ntp_non_routine_min_outbound_bytes
}

/// Graded EvidenceFloor gate (see the field docs).
pub fn evidence_floor_requires_graded_anomaly() -> bool {
    PARAMS_SNAPSHOT
        .load()
        .evidence_floor_requires_graded_anomaly
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

/// R4 (A4) clamp-flip switch (see the field docs).
pub fn crs_authoritative_enabled() -> bool {
    PARAMS_SNAPSHOT.load().crs_authoritative_enabled
}

/// INC-19 kernel-lineage flip switch (see the field docs).
pub fn kernel_lineage_flip_enabled() -> bool {
    PARAMS_SNAPSHOT.load().kernel_lineage_flip_enabled
}

/// Deterministic divergence lineage floor switch (see the field docs).
pub fn divergence_lineage_floor_enabled() -> bool {
    PARAMS_SNAPSHOT.load().divergence_lineage_floor_enabled
}

/// B4 cross-engine bus injection switch (see the field docs).
pub fn cross_engine_bus_enabled() -> bool {
    PARAMS_SNAPSHOT.load().cross_engine_bus_enabled
}

/// `process_memory_scrape` credential-holder basenames (lowercase).
pub fn process_memory_scrape_sensitive_target_basenames() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .process_memory_scrape_sensitive_target_basenames
        .clone()
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

/// Every attack-pattern check's `reference` string from the params snapshot
/// (`checks.<name>.reference`), in check-name order. Read by
/// `agent_framework_tags` to crosswalk the umbrella `vulnerabilities` check.
pub fn all_check_references() -> Vec<String> {
    let snapshot = PARAMS_SNAPSHOT.load();
    let mut names: Vec<&String> = snapshot.checks.keys().collect();
    names.sort();
    names
        .into_iter()
        .filter_map(|name| snapshot.checks.get(name).map(|m| m.reference.clone()))
        .collect()
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

/// Per-user application data roots, profile-relative (lowercase, `/`).
pub fn per_user_app_data_roots() -> Vec<String> {
    PARAMS_SNAPSHOT.load().per_user_app_data_roots.clone()
}

/// Sandboxed-application container layouts (lowercase, `/`).
pub fn sandbox_container_layouts() -> Vec<SandboxContainerLayoutJSON> {
    PARAMS_SNAPSHOT.load().sandbox_container_layouts.clone()
}

/// Install roots whose next component names the product (lowercase, `/`).
pub fn application_install_roots() -> Vec<String> {
    PARAMS_SNAPSHOT.load().application_install_roots.clone()
}

/// Install roots only an administrator can write to (lowercase, `/`, no
/// drive letter).
pub fn admin_only_install_roots() -> Vec<String> {
    PARAMS_SNAPSHOT.load().admin_only_install_roots.clone()
}

/// Install prefixes whose next component names the product (lowercase, `/`).
pub fn application_install_prefixes() -> Vec<String> {
    PARAMS_SNAPSHOT.load().application_install_prefixes.clone()
}

/// True when a lowercase token names a layout, platform or role rather than
/// a product (`owned_store_generic_tokens`).
pub fn is_owned_store_generic_token(token: &str) -> bool {
    PARAMS_SNAPSHOT
        .load()
        .owned_store_generic_tokens
        .contains(token)
}

/// Shortest owner token that can name a product.
pub fn owned_store_min_token_len() -> usize {
    PARAMS_SNAPSHOT.load().owned_store_min_token_len
}

/// Per-user stores the operating system owns (lowercase, `/`).
pub fn platform_owned_user_store() -> PlatformOwnedUserStoreJSON {
    PARAMS_SNAPSHOT.load().platform_owned_user_store.clone()
}

/// Path prefixes of operating-system service images (lowercase, `/`).
pub fn os_service_image_path_prefixes() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .os_service_image_path_prefixes
        .clone()
}

/// Binary roots on the macOS sealed system volume (lowercase, `/`).
pub fn macos_sealed_system_binary_path_prefixes() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .macos_sealed_system_binary_path_prefixes
        .clone()
}

/// The agent slug whose `agent_process_names` list a lowercase tool name.
pub fn agent_slug_for_process_name(tool_name: &str) -> Option<String> {
    PARAMS_SNAPSHOT
        .load()
        .agent_process_names
        .iter()
        .find(|(_, names)| names.iter().any(|name| name == tool_name))
        .map(|(slug, _)| slug.clone())
}

/// True for a lowercase directory name that holds versioned releases.
pub fn is_version_layout_directory(name: &str) -> bool {
    PARAMS_SNAPSHOT
        .load()
        .version_layout_directories
        .contains(name)
}

/// True for the lowercase tool name of a desktop-session root role.
pub fn is_desktop_session_root_role(tool_name: &str) -> bool {
    PARAMS_SNAPSHOT
        .load()
        .desktop_session_root_roles
        .contains(tool_name)
}

/// True when `address` is in one of the `access_network_plumbing_ipv4_cidrs`
/// ranges.
pub fn is_access_network_plumbing_ipv4(address: std::net::Ipv4Addr) -> bool {
    let address = u32::from(address);
    PARAMS_SNAPSHOT
        .load()
        .access_network_plumbing_ipv4_ranges
        .iter()
        .any(|(network, mask)| address & mask == *network)
}

/// True for the stem of a script / language runtime (`script_runtime_basenames`).
pub fn is_script_runtime_basename(stem: &str) -> bool {
    PARAMS_SNAPSHOT
        .load()
        .script_runtime_basenames
        .contains(stem)
}

/// Dependency-tree path fragments, in order (lowercase, `/`).
pub fn dependency_tree_markers() -> Vec<String> {
    PARAMS_SNAPSHOT.load().dependency_tree_markers.clone()
}

/// True for the basename of a package-manager runtime
/// (`package_manager_runtimes`).
pub fn is_package_manager_runtime_name(name: &str) -> bool {
    PARAMS_SNAPSHOT
        .load()
        .package_manager_runtimes
        .contains(name)
}

/// True for the basename of a bare language runtime among the
/// package-manager runtimes (`package_bare_runtimes`).
pub fn is_package_bare_runtime_name(name: &str) -> bool {
    PARAMS_SNAPSHOT.load().package_bare_runtimes.contains(name)
}

/// True when `path` (any separator, any case) sits under a global CLI
/// install root (`global_package_roots`).
pub fn is_under_global_package_root(path: &str) -> bool {
    let normalized = path.to_ascii_lowercase().replace('\\', "/");
    PARAMS_SNAPSHOT
        .load()
        .global_package_roots
        .iter()
        .any(|root| normalized.contains(root.as_str()))
}

/// True for the lowercase basename of a lockfile / manifest an install
/// rewrites (`install_artifact_basenames`).
pub fn is_install_artifact_basename(basename: &str) -> bool {
    PARAMS_SNAPSHOT
        .load()
        .install_artifact_basenames
        .contains(basename)
}

/// Developer toolchain tree markers (names as on disk).
pub fn dev_tree_markers() -> DevTreeMarkersJSON {
    PARAMS_SNAPSHOT.load().dev_tree_markers.clone()
}

/// Code / persistence definition suffixes (lowercase).
pub fn code_module_suffixes() -> Vec<String> {
    PARAMS_SNAPSHOT.load().code_module_suffixes.clone()
}

/// True for a lowercase catalog label that denotes credential material.
pub fn is_sensitive_material_label(label: &str) -> bool {
    PARAMS_SNAPSHOT
        .load()
        .sensitive_material_labels
        .contains(label)
}

/// The credential-material catalog labels, sorted.
pub fn sensitive_material_labels() -> Vec<String> {
    let mut labels: Vec<String> = PARAMS_SNAPSHOT
        .load()
        .sensitive_material_labels
        .iter()
        .cloned()
        .collect();
    labels.sort();
    labels
}

/// True for a lowercase catalog label that names an agent instruction /
/// configuration surface.
pub fn is_agent_instruction_label(label: &str) -> bool {
    PARAMS_SNAPSHOT
        .load()
        .agent_instruction_labels
        .contains(label)
}

/// Agent slug -> enforcement-configuration path suffixes (lowercase, `/`),
/// in slug order.
pub fn agent_control_config_path_suffixes() -> BTreeMap<String, Vec<String>> {
    PARAMS_SNAPSHOT
        .load()
        .agent_control_config_path_suffixes
        .clone()
}

/// True for a lowercase publisher-name token that names no organization.
pub fn is_publisher_org_stop_token(token: &str) -> bool {
    PARAMS_SNAPSHOT
        .load()
        .publisher_org_stop_tokens
        .contains(token)
}

/// Shortest publisher organization token kept.
pub fn publisher_org_min_token_len() -> usize {
    PARAMS_SNAPSHOT.load().publisher_org_min_token_len
}

/// Read breadth at which process-memory reads are an inventory sweep.
pub fn memory_scrape_read_enumeration_min_distinct_targets() -> usize {
    PARAMS_SNAPSHOT
        .load()
        .memory_scrape_read_enumeration_min_distinct_targets
}

/// Hex run that marks a per-invocation path segment.
pub fn memory_scrape_per_invocation_min_hex_run() -> usize {
    PARAMS_SNAPSHOT
        .load()
        .memory_scrape_per_invocation_min_hex_run
}

/// Credential classes a process-tree relay sibling must hold.
pub fn relay_min_credential_classes() -> usize {
    PARAMS_SNAPSHOT.load().relay_min_credential_classes
}

/// Local processes that make a blacklisted prefix shared infrastructure.
/// Whether `domain` (lowercase, no port) is, or sits under, a shared-hosting
/// public suffix: returns the suffix it sits at or under, if any.
pub fn shared_hosting_suffix_of(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    PARAMS_SNAPSHOT
        .load()
        .shared_hosting_public_suffixes
        .iter()
        .find(|suffix| domain == **suffix || domain.ends_with(&format!(".{suffix}")))
        .cloned()
}

/// The shared-hosting public suffixes (lowercase, no dots at the ends).
pub fn shared_hosting_public_suffixes() -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .shared_hosting_public_suffixes
        .clone()
}

pub fn shared_infrastructure_min_local_processes() -> usize {
    PARAMS_SNAPSHOT
        .load()
        .shared_infrastructure_min_local_processes
}

/// Whether `host` on `port` is infrastructure the divergence correlation
/// plane does not count as unexplained egress (see
/// [`DivergenceInfrastructureEndpointClassJSON`] for the matching). `host` is
/// a DNS name or an address without the port; it is compared lowercase,
/// without a trailing dot.
pub fn is_divergence_infrastructure_endpoint(host: &str, port: u16) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    let first_label = host.split('.').next().unwrap_or("");
    PARAMS_SNAPSHOT
        .load()
        .divergence_infrastructure_endpoints
        .iter()
        .any(|class| {
            class.ports.contains(&port)
                && (class.hosts.iter().any(|known| *known == host)
                    || class
                        .suffixes
                        .iter()
                        .any(|suffix| host.ends_with(suffix.as_str()))
                    || class.first_labels.iter().any(|label| label == first_label)
                    || class
                        .numbered_first_labels
                        .iter()
                        .any(|prefix| is_numbered_label(first_label, prefix)))
        })
}

/// Whether `path` is a file an agent harness captures a command's output
/// into ([`AgentHarnessOutputCaptureJSON`]): the layout, segment for segment,
/// case-insensitive, either separator. The agent's identity (`agent`) is
/// informational: the layout is what is matched.
pub fn is_agent_harness_output_capture(path: &str) -> bool {
    let lowered = path.trim().replace('\\', "/").to_ascii_lowercase();
    let segments: Vec<&str> = lowered.split('/').filter(|s| !s.is_empty()).collect();
    let snapshot = PARAMS_SNAPSHOT.load();
    snapshot.agent_harness_output_capture.iter().any(|entry| {
        if entry.capture_dir.is_empty() || entry.file_suffix.is_empty() {
            return false;
        }
        let depth = entry.levels_below_root + 2;
        if segments.len() < depth + 1 {
            return false;
        }
        let root = segments.len() - 1 - depth;
        let root_segment = segments[root];
        let root_matches = entry.root_names.iter().any(|name| root_segment == name)
            || entry.root_prefixes.iter().any(|prefix| {
                root_segment.len() > prefix.len() && root_segment.starts_with(prefix.as_str())
            });
        let file = segments[segments.len() - 1];
        root_matches
            && segments[segments.len() - 2] == entry.capture_dir
            && file.len() > entry.file_suffix.len()
            && file.ends_with(entry.file_suffix.as_str())
    })
}

/// `label` is `prefix` followed only by ASCII digits (none counts).
fn is_numbered_label(label: &str, prefix: &str) -> bool {
    !prefix.is_empty()
        && label
            .strip_prefix(prefix)
            .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
}

/// OS temp roots by role (lowercase, `/`).
pub fn os_temp_roots() -> OsTempRootsJSON {
    PARAMS_SNAPSHOT.load().os_temp_roots.clone()
}

/// Per-invocation temp scratch directory name shape (lowercase prefix).
pub fn temp_scratch_name() -> TempScratchNameJSON {
    PARAMS_SNAPSHOT.load().temp_scratch_name.clone()
}

/// Python's `tempfile` scratch names (see [`PythonTempfileNameJSON`]).
pub fn python_tempfile_name() -> PythonTempfileNameJSON {
    PARAMS_SNAPSHOT.load().python_tempfile_name.clone()
}

/// Ephemeral PowerShell stub name shape (lowercase).
pub fn windows_temp_powershell_stub() -> WindowsTempPowershellStubJSON {
    PARAMS_SNAPSHOT.load().windows_temp_powershell_stub.clone()
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
        // The capitalised assertions above hold because the constructor folds
        // the list, not because the predicate folds each prefix. Pin that:
        // `new_from_json` is the only producer of `CveDetectionParams`, and if
        // a refactor ever stops lowercasing there, every capitalised entry
        // would go inert with no other signal. Data-independent -- it holds
        // for any published list, however it is spelled.
        assert!(
            PARAMS_SNAPSHOT
                .load()
                .ci_runner_process_name_prefixes
                .iter()
                .all(|p| p.chars().all(|c| !c.is_ascii_uppercase())),
            "CveDetectionParams::new_from_json must lowercase \
             ci_runner_process_name_prefixes; the prefix comparison relies on it"
        );
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

    /// FP-WIN-30: the data components Chrome's component updater installs
    /// below `User Data\<component>\<version>\` (Crowd Deny, file-type
    /// policies, origin trials, ...) are re-downloadable data, the class of
    /// `CertificateRevocation` and `PKIMetadata`; the component directory
    /// itself (its mtime change) matches too. Components that ship native
    /// code Chrome loads (`WidevineCdm`) and the credential stores are not
    /// listed.
    #[test]
    fn test_is_non_sensitive_browser_data_chromium_component_updater() {
        let root = "C:\\Users\\frank\\AppData/Local\\Google\\Chrome\\User Data";
        for component in [
            "Crowd Deny\\2026.10.5.75",
            "Crowd Deny",
            "FileTypePolicies\\72\\download_file_types.pb",
            "OriginTrials\\1.0.0.18\\manifest.json",
            "Subresource Filter\\Unindexed Rules\\9.62.0\\Filtering Rules",
            "ZxcvbnData\\3\\passwords.txt",
        ] {
            let path = format!("{root}\\{component}");
            assert!(is_non_sensitive_browser_data(&path), "{path}");
        }
        for kept in [
            "WidevineCdm\\4.10.2891.0\\_platform_specific\\win_x64\\widevinecdm.dll",
            "Default\\Login Data",
            "Default\\Network\\Cookies",
            "Local Extension Settings\\nngceckbapebfimnlniiiahkandclblb\\000003.log",
        ] {
            let path = format!("{root}\\{kept}");
            assert!(!is_non_sensitive_browser_data(&path), "{path}");
        }
        // Outside a browser root the component name vouches for nothing.
        assert!(!is_non_sensitive_browser_data(
            "C:\\Users\\frank\\AppData\\Local\\Temp\\Crowd Deny\\stage.bin"
        ));
        // The variations seed is browser state, graded like its safe twin.
        assert!(
            browser_volatile_profile_state_group(&format!("{root}\\VariationsSeedV2")).is_some()
        );
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
        assert_eq!(
            shared_hosting_suffix_of("evil.s3.amazonaws.com").as_deref(),
            Some("amazonaws.com")
        );
        assert_eq!(shared_hosting_suffix_of("api.github.com"), None);
        assert!(!shared_hosting_public_suffixes().is_empty());
        assert!(is_fim_kernel_pseudo_writer_name("System"));
        assert!(!is_fim_kernel_pseudo_writer_name("svchost.exe"));
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

    /// The embedded snapshot with `edit` applied, loaded the way an update
    /// loads a published JSON.
    fn params_from_edited_snapshot(
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> CveDetectionParams {
        let mut value: serde_json::Value = serde_json::from_str(&CVE_DETECTION_PARAMS_DB)
            .expect("embedded snapshot is valid JSON");
        edit(&mut value);
        let json: CveDetectionParamsJSON =
            serde_json::from_value(value).expect("edited snapshot must parse");
        CveDetectionParams::new_from_json(&json)
    }

    /// The per-user store ownership lists load lowercased with `/`
    /// separators, and an empty entry (which would match every path) is
    /// dropped rather than kept.
    #[test]
    fn test_per_user_store_ownership_lists_are_normalized() {
        let p = params_from_edited_snapshot(|value| {
            value["per_user_app_data_roots"] = serde_json::json!(["Library\\Caches\\", " "]);
            value["application_install_roots"] = serde_json::json!(["\\Program Files\\", ""]);
            value["admin_only_install_roots"] = serde_json::json!(["\\Program Files (x86)\\", " "]);
            value["application_install_prefixes"] = serde_json::json!(["/OPT/"]);
            value["owned_store_generic_tokens"] = serde_json::json!(["Helper", ""]);
            value["sandbox_container_layouts"] = serde_json::json!([
                {"container_root": "Library\\Containers\\", "data_dir": "Data\\",
                 "inner_roots": ["Library\\Caches\\"]},
                {"container_root": "", "data_dir": "", "inner_roots": ["config/"]},
            ]);
        });
        assert_eq!(p.per_user_app_data_roots, vec!["library/caches/"]);
        assert_eq!(p.application_install_roots, vec!["/program files/"]);
        assert_eq!(p.admin_only_install_roots, vec!["/program files (x86)/"]);
        assert_eq!(p.application_install_prefixes, vec!["/opt/"]);
        assert_eq!(
            p.owned_store_generic_tokens,
            HashSet::from(["helper".to_string()])
        );
        assert_eq!(
            p.sandbox_container_layouts,
            vec![SandboxContainerLayoutJSON {
                container_root: "library/containers/".to_string(),
                data_dir: "data/".to_string(),
                inner_roots: vec!["library/caches/".to_string()],
            }]
        );
    }

    /// The shipped snapshot carries the per-user store ownership model.
    #[test]
    fn test_per_user_store_ownership_defaults() {
        assert!(per_user_app_data_roots()
            .iter()
            .all(|root| !root.starts_with('/') && root.ends_with('/')));
        assert!(!per_user_app_data_roots().is_empty());
        assert!(!sandbox_container_layouts().is_empty());
        assert!(!admin_only_install_roots().is_empty());
        assert!(application_install_roots()
            .iter()
            .chain(application_install_prefixes().iter())
            .chain(admin_only_install_roots().iter())
            .all(|root| root.starts_with('/') && root.ends_with('/')));
        assert!(is_owned_store_generic_token("helper"));
        assert!(!is_owned_store_generic_token("zoom"));
        assert!(owned_store_min_token_len() > 0);
    }

    /// The OS-owned store model loads lowercased; an empty owner prefix
    /// (which would claim every directory for the OS) is dropped.
    #[test]
    fn test_platform_owned_user_store_is_normalized() {
        let p = params_from_edited_snapshot(|value| {
            value["platform_owned_user_store"] = serde_json::json!({
                "library_root": "Library\\",
                "library_state_directories": ["HTTPStorages"],
                "owner_prefixes": ["COM.APPLE.", ""],
                "direct_owner_prefixes": [" Apple "],
            });
            value["os_service_image_path_prefixes"] = serde_json::json!(["/System/Library/"]);
            value["macos_sealed_system_binary_path_prefixes"] =
                serde_json::json!(["/usr/sbin/", ""]);
        });
        assert_eq!(
            p.platform_owned_user_store,
            PlatformOwnedUserStoreJSON {
                library_root: "library/".to_string(),
                library_state_directories: vec!["httpstorages".to_string()],
                owner_prefixes: vec!["com.apple.".to_string()],
                direct_owner_prefixes: vec!["apple".to_string()],
            }
        );
        assert_eq!(p.os_service_image_path_prefixes, vec!["/system/library/"]);
        assert_eq!(
            p.macos_sealed_system_binary_path_prefixes,
            vec!["/usr/sbin/"]
        );
    }

    /// Process-lineage names load lowercased; the agent lookup answers by
    /// tool name.
    #[test]
    fn test_process_lineage_names() {
        let p = params_from_edited_snapshot(|value| {
            value["agent_process_names"] =
                serde_json::json!({"claude_code": ["Claude", ""], " ": ["orphan"]});
            value["version_layout_directories"] = serde_json::json!(["Versions"]);
            value["desktop_session_root_roles"] = serde_json::json!(["Explorer", ""]);
        });
        assert_eq!(
            p.agent_process_names,
            BTreeMap::from([("claude_code".to_string(), vec!["claude".to_string()])])
        );
        assert_eq!(
            p.version_layout_directories,
            HashSet::from(["versions".to_string()])
        );
        assert_eq!(
            p.desktop_session_root_roles,
            HashSet::from(["explorer".to_string()])
        );
        assert_eq!(
            agent_slug_for_process_name("claude").as_deref(),
            Some("claude_code")
        );
        assert_eq!(
            agent_slug_for_process_name("cursor helper (plugin)").as_deref(),
            Some("cursor")
        );
        assert_eq!(agent_slug_for_process_name("python3"), None);
        assert!(is_version_layout_directory("versions"));
        assert!(!is_version_layout_directory("claude"));
        assert!(is_desktop_session_root_role("explorer"));
        assert!(!is_desktop_session_root_role("bash"));
    }

    /// Plumbing ranges parse as strict CIDRs; anything else, or anything
    /// wider than a /16, is ignored rather than read as "not external".
    #[test]
    fn test_access_network_plumbing_ranges() {
        let p = params_from_edited_snapshot(|value| {
            value["access_network_plumbing_ipv4_cidrs"] = serde_json::json!([
                "192.0.0.0/29",
                "10.0.0.0/8",
                "0.0.0.0/0",
                "bad",
                "192.0.0.6",
                "198.51.100.1/32"
            ]);
        });
        assert_eq!(
            p.access_network_plumbing_ipv4_ranges,
            vec![(0xC000_0000, 0xFFFF_FFF8), (0xC633_6401, 0xFFFF_FFFF)]
        );
        for (address, plumbing) in [
            ([192, 0, 0, 0], true),
            ([192, 0, 0, 7], true),
            ([192, 0, 0, 8], false),
            ([192, 0, 0, 9], false),
            ([10, 0, 0, 1], false),
        ] {
            assert_eq!(
                is_access_network_plumbing_ipv4(std::net::Ipv4Addr::from(address)),
                plumbing,
                "{address:?}"
            );
        }
    }

    /// The shipped install roots, bare runtimes and measurement-surface
    /// lists load and match on both separators.
    #[test]
    fn test_global_install_roots_and_measurement_surface_lists() {
        assert!(is_package_bare_runtime_name("node"));
        assert!(is_package_bare_runtime_name("python3"));
        assert!(!is_package_bare_runtime_name("npm"));
        assert!(is_under_global_package_root(
            "/Users/runner/hostedtoolcache/node/24.20.0/arm64/lib/node_modules/@openai/codex/bin/codex.js"
        ));
        assert!(is_under_global_package_root(
            r"C:\Users\me\AppData\Roaming\npm\node_modules\@openai\codex\bin\codex.js"
        ));
        assert!(!is_under_global_package_root(
            "/Users/me/proj/node_modules/.bin/esbuild"
        ));
        let p = params();
        assert!(p.measurement_test_directory_segments.contains("tests"));
        assert!(p
            .measurement_derived_directory_segments
            .contains("__pycache__"));
        assert!(p
            .measurement_derived_directory_segments
            .contains("site-packages"));
        assert!(p.measurement_harness_filenames.contains("conftest.py"));
        assert!(p.measurement_intent_tokens.iter().any(|t| t == "ci "));
        assert_eq!(
            p.measurement_harness_directory_paths,
            vec![".github/workflows".to_string()]
        );
        assert_eq!(p.evaluator_materialisation_min_paths, 8);
        assert_eq!(p.evaluator_materialisation_measurement_divisor, 4);
        assert_eq!(p.evaluator_materialisation_burst_secs, 120);
        assert_eq!(p.evaluator_session_attribution_slack_secs, 300);
        assert!(p
            .ssh_client_state_files
            .iter()
            .any(|path| path == "~/.ssh/known_hosts"));
        assert!(p.ssh_client_state_files.iter().all(|path| !path
            .rsplit('/')
            .next()
            .unwrap_or("")
            .starts_with("id_")));
    }

    /// Runtime and dependency-tree lists load lowercased; the marker order
    /// is kept (the first match is reported).
    #[test]
    fn test_runtime_and_dependency_tree_lists() {
        let p = params_from_edited_snapshot(|value| {
            value["script_runtime_basenames"] = serde_json::json!(["Python", ""]);
            value["dependency_tree_markers"] =
                serde_json::json!(["\\Node_Modules\\", "/site-packages/", ""]);
            value["package_manager_runtimes"] = serde_json::json!(["NPM"]);
            value["install_artifact_basenames"] = serde_json::json!(["Cargo.lock"]);
        });
        assert_eq!(
            p.script_runtime_basenames,
            HashSet::from(["python".to_string()])
        );
        assert_eq!(
            p.dependency_tree_markers,
            vec!["/node_modules/".to_string(), "/site-packages/".to_string()]
        );
        assert_eq!(
            p.package_manager_runtimes,
            HashSet::from(["npm".to_string()])
        );
        assert_eq!(
            p.install_artifact_basenames,
            HashSet::from(["cargo.lock".to_string()])
        );
        assert!(is_script_runtime_basename("osascript"));
        assert!(!is_script_runtime_basename("slack"));
        assert_eq!(
            dependency_tree_markers().first().map(String::as_str),
            Some("/node_modules/")
        );
        assert!(is_package_manager_runtime_name("cargo"));
        assert!(!is_package_manager_runtime_name("bash"));
        assert!(is_install_artifact_basename("go.sum"));
        assert!(!is_install_artifact_basename(".bashrc"));
    }

    /// Dev-tree markers are on-disk names: trimmed, case kept, empty list
    /// entries dropped. Code-module suffixes load lowercased.
    #[test]
    fn test_dev_tree_markers_keep_their_case() {
        let p = params_from_edited_snapshot(|value| {
            value["dev_tree_markers"]["swiftpm_manifest_file"] =
                serde_json::json!(" Package.swift ");
            value["dev_tree_markers"]["bazel_workspace_files"] =
                serde_json::json!(["MODULE.bazel", " "]);
            value["code_module_suffixes"] = serde_json::json!([".PSM1", ""]);
        });
        assert_eq!(p.dev_tree_markers.swiftpm_manifest_file, "Package.swift");
        assert_eq!(
            p.dev_tree_markers.bazel_workspace_files,
            vec!["MODULE.bazel"]
        );
        assert_eq!(p.code_module_suffixes, vec![".psm1"]);
        let shipped = dev_tree_markers();
        assert_eq!(shipped.cmake_cache_file, "CMakeCache.txt");
        assert_eq!(shipped.venv_config_file, "pyvenv.cfg");
        assert!(shipped
            .venv_interpreter_directories
            .iter()
            .any(|name| name == "Scripts"));
        assert!(shipped
            .venv_interpreter_directories
            .iter()
            .any(|name| name == "bin"));
        assert!(shipped
            .venv_library_directories
            .iter()
            .any(|name| name.eq_ignore_ascii_case("lib")));
        assert_eq!(shipped.venv_package_directories, vec!["site-packages"]);
        assert!(code_module_suffixes()
            .iter()
            .any(|suffix| suffix == ".plist"));
    }

    /// Catalog label classes load lowercased and do not overlap.
    #[test]
    fn test_catalog_label_classes() {
        let p = params_from_edited_snapshot(|value| {
            value["sensitive_material_labels"] = serde_json::json!(["SSH", ""]);
            value["agent_instruction_labels"] = serde_json::json!(["Instruction"]);
        });
        assert_eq!(
            p.sensitive_material_labels,
            HashSet::from(["ssh".to_string()])
        );
        assert_eq!(
            p.agent_instruction_labels,
            HashSet::from(["instruction".to_string()])
        );
        assert!(is_sensitive_material_label("keychain"));
        assert!(!is_sensitive_material_label("env"));
        assert!(is_agent_instruction_label("claude"));
        assert!(!is_agent_instruction_label("ssh"));
        assert!(sensitive_material_labels()
            .iter()
            .all(|label| !is_agent_instruction_label(label)));
        assert!(sensitive_material_labels().windows(2).all(|w| w[0] < w[1]));
    }

    /// Control-config suffixes load lowercased with `/` separators; an
    /// empty suffix (it would match every path) is dropped.
    #[test]
    fn test_agent_control_config_path_suffixes() {
        let p = params_from_edited_snapshot(|value| {
            value["agent_control_config_path_suffixes"] =
                serde_json::json!({"codex": ["\\.Codex\\config.toml", ""]});
        });
        assert_eq!(
            p.agent_control_config_path_suffixes,
            BTreeMap::from([("codex".to_string(), vec!["/.codex/config.toml".to_string()])])
        );
        let shipped = agent_control_config_path_suffixes();
        assert!(shipped["claude_code"].contains(&"/.claude/settings.json".to_string()));
        assert!(shipped
            .values()
            .flatten()
            .all(|suffix| suffix.starts_with('/')));
    }

    #[test]
    fn test_publisher_org_stop_tokens() {
        let p = params_from_edited_snapshot(|value| {
            value["publisher_org_stop_tokens"] = serde_json::json!(["LLC", " "]);
        });
        assert_eq!(
            p.publisher_org_stop_tokens,
            HashSet::from(["llc".to_string()])
        );
        assert!(is_publisher_org_stop_token("developer"));
        assert!(!is_publisher_org_stop_token("google"));
        assert!(publisher_org_min_token_len() > 0);
    }

    /// The temp model loads lowercased with `/` separators; empty list
    /// entries are dropped.
    #[test]
    fn test_os_temp_roots_are_normalized() {
        let p = params_from_edited_snapshot(|value| {
            value["os_temp_roots"]["windows_user_temp_marker"] =
                serde_json::json!("\\AppData\\Local\\Temp\\");
            value["os_temp_roots"]["posix_temp_roots"] = serde_json::json!(["/TMP/", ""]);
            value["os_temp_roots"]["macos_per_user_temp_leaf"] = serde_json::json!("T");
            value["temp_scratch_name"]["prefix"] = serde_json::json!("TMP");
            value["windows_temp_powershell_stub"]["name_suffix"] = serde_json::json!(".PS1");
        });
        assert_eq!(
            p.os_temp_roots.windows_user_temp_marker,
            "/appdata/local/temp/"
        );
        assert_eq!(p.os_temp_roots.posix_temp_roots, vec!["/tmp/"]);
        assert_eq!(p.os_temp_roots.macos_per_user_temp_leaf, "t");
        assert_eq!(p.temp_scratch_name.prefix, "tmp");
        assert_eq!(p.windows_temp_powershell_stub.name_suffix, ".ps1");
        let shipped = os_temp_roots();
        assert_eq!(shipped.windows_system_temp_marker, "/windows/temp/");
        assert!(shipped
            .posix_temp_roots
            .contains(&"/private/var/tmp/".to_string()));
        assert!(temp_scratch_name().min_token_len > 0);
    }

    #[test]
    fn test_detector_thresholds_are_loaded() {
        assert!(memory_scrape_read_enumeration_min_distinct_targets() > 1);
        assert!(memory_scrape_per_invocation_min_hex_run() > 0);
        assert!(relay_min_credential_classes() > 0);
        assert!(shared_infrastructure_min_local_processes() > 0);
    }

    /// The divergence infrastructure classes, read through the accessor the
    /// divergence engine reads: exact hosts, dotted suffixes, exact and
    /// numbered first labels, each on its own ports only (G-39 negatives
    /// kept).
    #[test]
    fn test_divergence_infrastructure_endpoints() {
        let infra = is_divergence_infrastructure_endpoint;
        // DNS resolvers: 53, 853, 443 only.
        assert!(infra("1.1.1.1", 53));
        assert!(infra("dns.google", 853));
        assert!(infra("one.one.one.one", 443));
        assert!(!infra("8.8.8.8", 80));
        assert!(!infra("dns.google", 80));
        assert!(!infra("1.1.1.3", 53));
        // Time sync: 123 only; exact names and the NTP pool suffix.
        assert!(infra("time.apple.com", 123));
        assert!(infra("pool.ntp.org", 123));
        assert!(infra("2.pool.ntp.org", 123));
        assert!(!infra("time.apple.com", 443));
        assert!(!infra("time.attacker.example", 123));
        assert!(!infra("ntp.attacker.example", 123));
        assert!(!infra("evilpool.ntp.org", 123));
        // Certificate revocation: 80, 443; `ocsp`, `crl` + digits, lencr.
        assert!(infra("ocsp.digicert.com", 80));
        assert!(infra("crl3.digicert.com", 80));
        assert!(infra("crl.globalsign.com", 443));
        assert!(infra("r3.o.lencr.org", 80));
        assert!(infra("x1.c.lencr.org", 443));
        assert!(!infra("ocsp.digicert.com", 123));
        assert!(!infra("myocsp.attacker.example", 443));
        assert!(!infra("crlx.attacker.example", 443));
        assert!(!infra("crl-sync.attacker.example", 443));
        assert!(!infra("crl3x.attacker.example", 443));
        assert!(!infra("o.lencr.org.attacker.example", 80));
        // Connectivity probes: 80, 443.
        assert!(infra("captive.apple.com", 80));
        assert!(infra("www.msftconnecttest.com", 443));
        assert!(!infra("captive.apple.com", 53));
        assert!(!infra("captive.apple.com.attacker.example", 80));
        // OS update: 80, 443; exact names and the Windows Update suffix.
        assert!(infra("download.windowsupdate.com", 443));
        assert!(infra("ctldl.windowsupdate.com", 80));
        assert!(infra("swcdn.apple.com", 443));
        assert!(!infra("evilwindowsupdate.com", 443));
        assert!(!infra("windowsupdate.com.attacker.example", 443));
        assert!(!infra("swcdn.apple.com", 8443));
        // Toolchain telemetry: MSVC vctip.exe on 443 only.
        assert!(infra("telemetry.visualstudio.microsoft.com", 443));
        assert!(infra("TELEMETRY.VisualStudio.Microsoft.com.", 443));
        assert!(!infra("telemetry.visualstudio.microsoft.com", 80));
        assert!(!infra("telemetry.visualstudio.microsoft.com", 8443));
        assert!(!infra(
            "telemetry.visualstudio.microsoft.com.attacker.example",
            443
        ));
        assert!(!infra("x.telemetry.visualstudio.microsoft.com", 443));
        assert!(!infra("visualstudio.microsoft.com", 443));
        // Nothing else.
        assert!(!infra("", 443));
        assert!(!infra("registry.npmjs.org", 443));
        assert!(!infra("203.0.113.44", 443));
    }

    /// Classes load lowercase and trimmed; a suffix keeps its leading dot even
    /// when published without one, and an empty entry (an empty numbered
    /// prefix would cover every IPv4 first octet) is dropped. A class missing
    /// a field fails the parse (born complete).
    #[test]
    fn test_python_tempfile_name_is_pythons() {
        let shape = python_tempfile_name();
        assert_eq!(shape.prefix, "tmp");
        assert_eq!(shape.random_len, 8);
        assert!(shape.alphabet.contains('_') && shape.alphabet.contains('0'));
        assert!(!shape.alphabet.chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn test_agent_harness_output_capture_layout() {
        // FP lab 2026-10-06, shiawase and the macOS shape of the same file.
        assert!(is_agent_harness_output_capture(
            r"C:\Users\frank\AppData\Local\Temp\claude\C--Users-frank-ws\4d0a361b-8166\tasks\bw6l06abk.output"
        ));
        assert!(is_agent_harness_output_capture(
            "/private/tmp/claude-501/-Users-flyonnet-Programming-edamame-core/60ebf757/tasks/b0wp6imft.output"
        ));
        assert!(is_agent_harness_output_capture(
            "/tmp/claude-1000/-home-u-repo/0e2f/tasks/a1.output"
        ));
        // The layout, not a substring: other depths, names and suffixes miss.
        for path in [
            "/private/tmp/claude-501/p/tasks/b0.output",
            "/private/tmp/claude-501/p/s/x/tasks/b0.output",
            "/private/tmp/claude-501/p/s/tasks/b0.sh",
            "/private/tmp/claude-501/p/s/scratchpad/b0.output",
            "/private/tmp/claudette/p/s/tasks/b0.output",
            "/private/tmp/claude-/p/s/tasks/b0.output",
            "/private/tmp/claude-501/p/s/tasks/.output",
            "/home/u/tasks/b0.output",
        ] {
            assert!(!is_agent_harness_output_capture(path), "{path}");
        }
    }

    #[test]
    fn test_divergence_infrastructure_endpoints_are_normalized() {
        let p = params_from_edited_snapshot(|value| {
            value["divergence_infrastructure_endpoints"] = serde_json::json!([{
                "class": " Toolchain_Telemetry ",
                "hosts": [" Telemetry.Example.COM. ", ""],
                "suffixes": ["Example.org", ".cdn.example.net.", " "],
                "first_labels": ["OCSP", ""],
                "numbered_first_labels": ["", " CRL "],
                "ports": [443],
            }]);
        });
        assert_eq!(
            p.divergence_infrastructure_endpoints,
            vec![DivergenceInfrastructureEndpointClassJSON {
                class: "toolchain_telemetry".to_string(),
                hosts: vec!["telemetry.example.com".to_string()],
                suffixes: vec![".example.org".to_string(), ".cdn.example.net".to_string()],
                first_labels: vec!["ocsp".to_string()],
                numbered_first_labels: vec!["crl".to_string()],
                ports: vec![443],
            }]
        );
        assert!(p
            .divergence_infrastructure_endpoints
            .iter()
            .all(|class| !class.ports.is_empty()));

        let mut value: serde_json::Value = serde_json::from_str(&CVE_DETECTION_PARAMS_DB)
            .expect("embedded snapshot is valid JSON");
        value["divergence_infrastructure_endpoints"][0]
            .as_object_mut()
            .expect("a class is an object")
            .remove("first_labels")
            .expect("the embedded classes carry every field");
        assert!(serde_json::from_value::<CveDetectionParamsJSON>(value).is_err());
    }

    /// The published params must parse with this code. A `FormatError` means
    /// they do not -- every client then keeps its embedded snapshot and
    /// ignores the published tuning -- so it fails the test like any other
    /// unexpected status instead of passing as a "transient" state: the
    /// release order publishes threatmodels first, so the published JSON
    /// carries every field the code on main reads.
    #[tokio::test]
    #[serial]
    #[ignore] // requires network access to GitHub
    async fn test_update_runs() {
        let status = update("main", false).await.expect("Update failed");
        assert!(
            matches!(
                status,
                UpdateStatus::Updated | UpdateStatus::NotUpdated | UpdateStatus::SkippedCustom
            ),
            "unexpected update status: {status:?}"
        );
    }
}
