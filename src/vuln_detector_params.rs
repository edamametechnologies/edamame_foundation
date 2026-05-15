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

/// Path-substring lists used to suppress browser-cache /
/// browser-state false positives in `file_system_tampering`.
///
/// The sensitive-path classifier inherits "appdata" sensitivity from
/// the parent directory (e.g. `…/AppData/Local/Google/Chrome/User Data/`).
/// That's correct for `Login Data`, `Cookies`, `Web Data` -- but wrong
/// for the recomputable browser-cache subtrees (`Code Cache`,
/// `GPUCache`, `Service Worker`, etc.) and for the routine-rotation
/// state files (`Local State`, `Preferences`) that browsers atomically
/// rewrite many times an hour. See `FALSEPOSITIVES.md`
/// FP-WIN-1 / FP-WIN-2 / FP-WIN-5.
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CveDetectionParamsJSON {
    pub date: String,
    pub signature: String,
    pub checks: HashMap<String, CheckMetadata>,
    #[serde(default = "default_credential_harvest_min_labels")]
    pub credential_harvest_min_labels: usize,
    pub secret_content_scan_max_bytes: u64,
    pub secret_content_min_hits: usize,
    #[serde(default = "default_secret_content_script_extensions")]
    pub secret_content_script_extensions: Vec<String>,
    #[serde(default = "default_secret_content_network_command_tokens")]
    pub secret_content_network_command_tokens: Vec<String>,
    #[serde(default = "default_secret_content_scan_excluded_path_patterns")]
    pub secret_content_scan_excluded_path_patterns: Vec<String>,
    pub recent_sensitive_open_file_ttl_secs: u64,
    pub generic_reuse_tokens: Vec<String>,
    pub generic_application_tokens: Vec<String>,
    pub init_process_names: Vec<String>,
    #[serde(default = "default_ci_runner_process_name_prefixes")]
    pub ci_runner_process_name_prefixes: Vec<String>,
    #[serde(default = "default_ci_runner_workspace_path_patterns")]
    pub ci_runner_workspace_path_patterns: CiRunnerWorkspacePathPatternsJSON,
    #[serde(default = "default_ci_workspace_path_patterns")]
    pub ci_workspace_path_patterns: Vec<String>,
    #[serde(default = "default_keychain_transactional_filename_patterns")]
    pub keychain_transactional_filename_patterns: Vec<String>,
    #[serde(default = "default_non_sensitive_browser_data_subtrees")]
    pub non_sensitive_browser_data_subtrees: BrowserDataSubtreesJSON,
    #[serde(default = "default_browser_appdata_unknown_writer")]
    pub browser_appdata_unknown_writer: BrowserAppdataUnknownWriterJSON,
    #[serde(default = "default_build_output_tree_self_spawn_patterns")]
    pub build_output_tree_self_spawn_patterns: PlatformStringLists,
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
    #[serde(default = "default_managed_temp_staging_patterns")]
    pub managed_temp_staging_patterns: ManagedTempStagingPatternsJSON,
    #[serde(default = "default_trusted_build_temp_staging")]
    pub trusted_build_temp_staging: TrustedBuildTempStagingJSON,
    #[serde(default = "default_package_manager_temp_path_patterns")]
    pub package_manager_temp_path_patterns: PlatformStringLists,
    #[serde(default = "default_package_manager_temp_writers")]
    pub package_manager_temp_writers: PlatformStringLists,
    #[serde(default = "default_edamame_daemon_self_telemetry_writers")]
    pub edamame_daemon_self_telemetry_writers: PlatformStringLists,
    #[serde(default = "default_edamame_daemon_self_telemetry_install_prefixes")]
    pub edamame_daemon_self_telemetry_install_prefixes: PlatformStringLists,
    #[serde(default = "default_platform_credential_helper_routine_destinations")]
    pub platform_credential_helper_routine_destinations:
        PlatformCredentialHelperRoutineDestinationsJSON,
    #[serde(default = "default_platform_metadata_endpoints")]
    pub platform_metadata_endpoints: PlatformStringLists,
    #[serde(default = "default_platform_runtime_probe_filename_patterns")]
    pub platform_runtime_probe_filename_patterns: PlatformStringLists,
    #[serde(default = "default_platform_self_state_directories")]
    pub platform_self_state_directories: PlatformStringLists,
    #[serde(default = "default_platform_self_state_processes")]
    pub platform_self_state_processes: PlatformStringLists,
    #[serde(default = "default_runtime_perfdata_paths")]
    pub runtime_perfdata_paths: PlatformRuntimePerfdataPathsJSON,
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

/// Filename suffixes that mark a file as "script-like" for the
/// secret-content scanner (`secret_content_scan::inspect_secret_like_file`).
/// Used by the FIM `file_system_tampering` heuristic to corroborate that
/// a write to `/tmp/` (or `%TEMP%\`) carries an actual script payload.
///
/// Tunable in CloudModel so we can add new operator-script extensions
/// (or remove ones that turn out to be ambiguous) without a release.
fn default_secret_content_script_extensions() -> Vec<String> {
    strings(&[
        ".sh", ".py", ".pl", ".rb", ".ps1", ".bat", ".cmd", ".js", ".vbs",
    ])
}

/// Substrings that mark file content as "network-command-like" for the
/// secret-content scanner. Combined with `script_like` above they let the
/// vulnerability detector promote a `/tmp/`-resident write that contains an
/// outbound-fetch payload (`curl `, `wget `, `Invoke-WebRequest`, ...) from
/// LOW to HIGH severity in `detect_file_system_tampering`.
///
/// Bare `http://` / `https://` are intentionally excluded from the default
/// list: they appear inside benign log/text content (git error messages
/// referencing https URLs, OpenSSH warnings linking to documentation,
/// CI step summaries with permalink URLs) and were a noise driver in
/// `FALSEPOSITIVES.md` FP-MAC-6 on `kralizec-3.local` 1.3.3. Genuine
/// outbound-fetch payloads always pair URLs with explicit verb tokens
/// (`curl`, `wget`, `Invoke-WebRequest`, raw socket constructors), all of
/// which remain in the default. Tunable via CloudModel so new IOC verbs
/// can be added without a release.
fn default_secret_content_network_command_tokens() -> Vec<String> {
    strings(&[
        "curl ",
        "wget ",
        " nc ",
        "netcat",
        "invoke-webrequest",
        "invoke-restmethod",
        "socket.create_connection",
    ])
}

/// Path substrings that mark a file as "in a transient build-artifact tree"
/// and therefore NOT worth content-scanning by `inspect_secret_like_file`.
///
/// The vulnerability detector enriches input sessions with the live open-file
/// list of every L7-attributed process via `flodbadd::open_files`. On CI hosts
/// (and developer machines) those open files routinely include cargo/rustc
/// intermediate artifacts (`target/<profile>/deps/<crate>-<hash>.d`,
/// `.rmeta`, `.rlib`, `.o`, `.pdb`, ...), npm `node_modules/`, gradle caches,
/// pub-cache packages, and so on. None of those artifacts carry security
/// intent (they are produced and rewritten in tight loops by the build tool),
/// and content-scanning them is pure waste.
///
/// Worse, on Windows the daemon's read momentarily races with the producer's
/// atomic rename: rustc writes `crate.d.tmp`, atomic-renames it to `crate.d`,
/// and immediately rewrites the file -- if the daemon has the file open via
/// `fs::read` (default Win32 share mode lacks `FILE_SHARE_DELETE`), the
/// producer's next `unlink` or `rename` fails with `os error 32` "process
/// cannot access the file because it is being used by another process". This
/// was the root cause of the Windows self-hosted runner test_windows.yml
/// failure cluster from 2026-05-01 onward (correlated exactly with enabling
/// `vulnerability_detection: true` on every self-hosted-runner job in
/// `edamame_app` commit `1b7099f2`).
///
/// Match semantics: paths are lowercased and `\` is normalized to `/` BEFORE
/// the substring check, so JSON entries use forward slashes only and apply
/// to both POSIX and Windows paths transparently.
///
/// Tunable via CloudModel so new build-tool layouts can be added (or
/// trimmed) without a release.
fn default_secret_content_scan_excluded_path_patterns() -> Vec<String> {
    strings(&[
        // Cargo profile/triple build outputs (covers debug, release, and
        // every cross-compile triple we ship).
        "/target/debug/",
        "/target/release/",
        "/target/aarch64-",
        "/target/x86_64-",
        "/target/i686-",
        "/target/armv7-",
        "/target/riscv64-",
        "/target/wasm32-",
        "/target/thumbv",
        // Cargo registry + git checkouts (downloaded crate sources/caches).
        "/.cargo/registry/cache/",
        "/.cargo/registry/index/",
        "/.cargo/registry/src/",
        "/.cargo/git/db/",
        "/.cargo/git/checkouts/",
        // npm / yarn / pnpm.
        "/node_modules/",
        // Gradle (wrapper + dep cache).
        "/.gradle/caches/",
        "/.gradle/wrapper/",
        // npm + pub caches outside node_modules / .cargo.
        "/.npm/_cacache/",
        "/.pub-cache/",
        // Dart / Flutter generated tool output.
        "/.dart_tool/",
        // Generic Android / Gradle build outputs.
        "/build/intermediates/",
        "/build/outputs/",
        "/build/generated/",
        // Flutter desktop / mobile per-platform build trees. These hold
        // the MSVC PDB (`vc143.pdb`), MSBuild dep-info (`*.tlog`), Xcode
        // intermediates, and CMake project caches. The demonstrated FP-CI-2
        // root cause is Cargo/rustc atomic-renaming under `target/`; the
        // observed C1090 PDB failures are handled as a separate MSBuild /
        // `mspdbsrv.exe` contention family. These transient build outputs
        // still have no value as secret content-scan candidates, so skip
        // them up front.
        "/build/windows/x64/",
        "/build/macos/build/",
        "/build/ios/build/",
        "/build/linux/x64/",
        "/build/web/",
        // Xcode (DerivedData lives under the user library; the lowercase
        // forms catch both `~/Library/Developer/Xcode/DerivedData` and
        // per-project copies). DerivedSources is the SwiftPM equivalent.
        "/derived data/",
        "/derivedsources/",
        // prost-build / tonic-build descriptor temp dirs (FP-CI-2 family).
        // tonic-build runs prost-build during cargo build script execution
        // and writes the protobuf descriptor to a `prost-buildXXXXXX/`
        // mkdtemp directory under the OS temp dir
        // (`%TEMP%\prost-buildXXX\prost-descriptor-set` on Windows,
        //  `/tmp/prost-buildXXX/...` on Linux,
        //  `/var/folders/.../T/prost-buildXXX/...` on macOS). The detector's
        // open-files enumeration would otherwise race the build's atomic
        // descriptor rewrite and trip `os error 32` on the build side.
        "/prost-build",
        // `cargo install --target-dir` and cargo bootstrap scratch trees.
        // Same race shape -- build-tool transient outputs with no secret
        // content value.
        "/cargo-install",
    ])
}

/// CI runner provisioning daemons and runner agent processes that
/// legitimately live in unusual locations on ephemeral build hosts.
/// Without this allowlist:
///   - the `sandbox_exploitation` detector flags `provjobd` as
///     "suspicious parent-process path" because it lives in `/tmp`;
///   - the `sensitive_material_egress` detector flags
///     `Runner.Worker.exe` as a credential-exfil candidate because it
///     simultaneously reads its own `_diag/*.log` files (which the
///     sensitive-file FIM classifier considers sensitive) and sustains
///     long-lived outbound connections to GitHub Actions backends.
/// Both are pure false positives intrinsic to running CI on
/// github-hosted runners, not indicative of compromised software.
///
/// These names are documented, public GitHub Actions infrastructure:
///   - `provjobd` (Linux+Windows): the provisioning job daemon that
///     spawns under the hosted-compute-agent / sudo on first run,
///     lives at `/tmp/provjobdNNN` / `%TEMP%\provjobd.exeNNN`.
///   - `Runner.Worker[.exe]`: the runner agent worker process that
///     executes a single workflow job. Spawns under `node20/bin/` on
///     Windows and under the runner directory on Linux/macOS. Suffixed
///     with the run id (e.g. `Runner.Worker.exe1134032012`).
///   - `Runner.Listener[.exe]`: the long-lived runner agent listener
///     that polls GitHub for workflow jobs.
fn default_ci_runner_process_name_prefixes() -> Vec<String> {
    strings(&["provjobd", "runner.worker", "runner.listener"])
}

/// Path substrings that identify directories owned by the GitHub
/// Actions runner agent. Files in these locations are part of the CI
/// runtime itself (workspace checkouts, runner diagnostic logs, action
/// caches). The `file_system_tampering` detector would otherwise flag
/// every fresh repo checkout as a sensitive-file Create event (e.g.
/// `actions-runner/_work/<repo>/<repo>/.env`) and every runner log
/// rotation as suspicious.
///
/// Patterns include both forward-slash and backslash variants so a
/// single normalized substring check covers Linux/macOS and Windows
/// runners. Patterns are matched against the raw event path
/// (case-insensitive) so callers do not need a separate normalization
/// step. `_work/` (workflow workspace) and `_diag/` (runner logs) are
/// the two directory namespaces that the runner manages.
fn default_ci_workspace_path_patterns() -> Vec<String> {
    strings(&[
        "/actions-runner/_work/",
        "/runner/_work/",
        "/actions-runner/_diag/",
        "/runner/_diag/",
        "\\actions-runner\\_work\\",
        "\\runner\\_work\\",
        "\\actions-runner\\_diag\\",
        "\\runner\\_diag\\",
    ])
}

/// Default CI runner workspace path patterns + suppressible filename
/// basenames (FP-CI-7).
///
/// The path substrings are matched against the FIM event path AFTER it
/// has been lowercased AND `\` has been folded to `/` -- so a single
/// canonical forward-slash form covers Linux, macOS, and Windows
/// runners across every CI provider in the table below. The detector
/// suppresses (demotes to LOW) `file_system_tampering` findings
/// whose:
///   1. resolved basename is in `suppressible_basenames`, AND
///   2. normalized path contains one of the substrings here.
///
/// Coverage:
///
/// | Provider | Canonical workspace shape (Linux/macOS) |
/// |---|---|
/// | GitHub Actions self-hosted | `/actions-runner[N]/_work/<repo>/<repo>/` |
/// | GitHub Actions hosted | `/home/runner/work/<repo>/<repo>/` |
/// | GitLab CI | `/home/gitlab-runner/builds/<group>/<project>/` |
/// | Jenkins | `/var/lib/jenkins[-agent]/workspace/<job>/` |
/// | CircleCI | `/home/circleci/project/` |
/// | Buildkite | `/var/lib/buildkite-agent/builds/...` |
/// | Travis CI | `/home/travis/build/<owner>/<repo>/` |
/// | TeamCity | `/opt/buildAgent/work/<id>/`, `/var/lib/teamcity/buildagent/work/` |
/// | Azure DevOps | `/agent/_work/<id>/s/`, `/home/vsts/work/<id>/s/`, `/home/AzDevOps/agent/_work/` |
/// | Bitbucket Pipelines | `/opt/atlassian/pipelines/agent/build/` |
/// | Drone CI | `/drone/src/` |
/// | Woodpecker CI | `/woodpecker/src/` |
/// | Cirrus CI | `/tmp/cirrus-ci-build/` |
/// | Codefresh | `/codefresh/volume/` |
/// | Semaphore CI | `/home/semaphore/<repo>/` |
/// | AppVeyor | `/home/appveyor/projects/<repo>/` |
/// | Bamboo | `/home/bamboo/bamboo-agent/xml-data/build-dir/` |
/// | GoCD | `/var/lib/go-agent/pipelines/` |
///
/// On Windows the same patterns match because backslashes are folded
/// to forward slashes before the substring check (e.g. Jenkins
/// `C:\Jenkins\workspace\Foo\` -> `c:/jenkins/workspace/foo/`).
fn default_ci_runner_workspace_path_patterns() -> CiRunnerWorkspacePathPatternsJSON {
    CiRunnerWorkspacePathPatternsJSON {
        path_substrings: strings(&[
            "/actions-runner/_work/",
            "/actions-runner1/_work/",
            "/actions-runner2/_work/",
            "/actions-runner3/_work/",
            "/actions-runner4/_work/",
            "/runneradmin/actions-runner/_work/",
            "/runner/_work/",
            "/runner/work/",
            "/gitlab-runner/builds/",
            "/builds/runner/",
            "/jenkins/workspace/",
            "/jenkins-agent/workspace/",
            "/jenkins_home/workspace/",
            "/var/lib/jenkins/workspace/",
            "/var/lib/jenkins-agent/workspace/",
            "/circleci/project/",
            "/buildkite-agent/builds/",
            "/buildkite/builds/",
            "/home/travis/build/",
            "/travis/build/",
            "/buildagent/work/",
            "/teamcity/buildagent/work/",
            "/var/lib/teamcity/buildagent/work/",
            "/agent/_work/",
            "/azdevops/agent/_work/",
            "/vsts/work/",
            "/atlassian/pipelines/agent/build/",
            "/drone/src/",
            "/woodpecker/src/",
            "/cirrus-ci-build/",
            "/codefresh/volume/",
            "/home/semaphore/",
            "/home/appveyor/projects/",
            "/appveyor/projects/",
            "/bamboo-agent/xml-data/build-dir/",
            "/go-agent/pipelines/",
        ]),
        suppressible_basenames: strings(&[
            ".env",
            ".env.example",
            ".env.local",
            ".env.template",
            ".env.test",
            ".env.development",
            ".env.production",
            ".env.sample",
        ]),
    }
}

/// Filename substrings that identify macOS Keychain transactional
/// artifacts (short-lived sandbox/transactional copies of the Keychain
/// DB created by the Security framework on every Keychain read). Any
/// process that touches the Keychain via the standard CFKeychain APIs
/// causes these files to appear and disappear within seconds; the
/// FIM/file_system_tampering classifier would otherwise flag them as
/// sensitive-file Create events on the writer process (which can be
/// anything from `iCloudNotificationAgent` to a packaged user app
/// using OneDrive/iCloud sync).
///
/// Patterns are case-insensitive substring checks evaluated against
/// the normalized path. Limited to filenames found *inside*
/// `credential_store_patterns.macos` paths (`/library/keychains/`)
/// so they are scoped to the actual Keychain directory, never to a
/// user file that happens to share a similar name.
fn default_keychain_transactional_filename_patterns() -> Vec<String> {
    strings(&[".keychain-db.sb-", ".keychain-db-shm.sb-", "/.fl"])
}

/// Default browser-cache / browser-state suppression patterns. See
/// the doc comment on [`BrowserDataSubtreesJSON`] for the suppression
/// model. Patterns are case-insensitive substring matches against the
/// FIM event path. Intentionally kept narrow: only directories /
/// state files that are recomputable or that hold browser-internal
/// configuration with no credential value. Credential-class artifacts
/// (`Login Data`, `Cookies`, `Web Data`, `History`, `Bookmarks`,
/// `Network/Cookies`, `Affiliation Database`) are deliberately NOT
/// in any list here -- those keep their sensitive classification so
/// a non-browser process touching them still fires.
fn default_non_sensitive_browser_data_subtrees() -> BrowserDataSubtreesJSON {
    BrowserDataSubtreesJSON {
        chromium_family: strings(&[
            "/code cache/",
            "/gpucache/",
            "/service worker/cachestorage/",
            "/service worker/database/",
            "/service worker/scriptcache/",
            "/cache/cache_data/",
            "/local storage/leveldb/",
            "/sessionstorage/",
            "/file system/",
            "/blob_storage/",
            "/crashpad/",
            "/component_crx_cache/",
            "/extensions/temp/",
            "/extensions_crx_cache/",
            "/dawn_graphite_cache/",
            "/dawn_webgpu_cache/",
            "/grshadercache/",
            "/shadercache/",
            "/optimizationhints/",
            "/segmentation_platform/",
            "/safe browsing/",
            "/certificaterevocation/",
        ]),
        chromium_state_files_routine: strings(&[
            "/local state",
            "/local state.bak",
            "/preferences",
            "/preferences.bak",
            "/secure preferences",
            "/network/network persistent state",
            "/network/transportsecurity",
            "/network/reportingandnel",
        ]),
        chromium_profile_state_volatile: strings(&[
            "/bookmarks",
            "/bookmarks.bak",
            "/downloadmetadata",
            "/session storage/",
            "/sessionstorage/",
            "/sessions/",
            "/sync data/",
            "/current session",
            "/current tabs",
            "/last session",
            "/last tabs",
        ]),
        chromium_user_data_root_markers: strings(&[
            "/google/chrome/user data/",
            "/google/chrome beta/user data/",
            "/google/chrome canary/user data/",
            "/microsoft/edge/user data/",
            "/microsoft/edge beta/user data/",
            "/brave-browser/user data/",
            "/brave software/brave-browser/user data/",
            "/vivaldi/user data/",
            "/opera software/opera stable/",
            "/chromium/user data/",
        ]),
        firefox_family_subtrees: strings(&[
            "/cache2/",
            "/startupcache/",
            "/jumplistcache/",
            "/offlinecache/",
            "/storage/permanent/chrome/",
            "/safebrowsing/",
            "/datareporting/archived/",
            "/saved-telemetry-pings/",
        ]),
        firefox_profile_state_volatile: strings(&["/sessionstore-backups/"]),
        firefox_user_data_root_markers: strings(&[
            "/mozilla/firefox/profiles/",
            "/firefox/profiles/",
            "/.mozilla/firefox/",
        ]),
    }
}

fn default_browser_appdata_unknown_writer() -> BrowserAppdataUnknownWriterJSON {
    BrowserAppdataUnknownWriterJSON {
        chromium_user_data_root_markers: strings(&[
            "/google/chrome/user data/",
            "/google/chrome beta/user data/",
            "/google/chrome canary/user data/",
            "/microsoft/edge/user data/",
            "/microsoft/edge beta/user data/",
            "/brave-browser/user data/",
            "/brave software/brave-browser/user data/",
            "/vivaldi/user data/",
            "/opera software/opera stable/",
            "/chromium/user data/",
        ]),
        firefox_user_data_root_markers: strings(&[
            "/mozilla/firefox/profiles/",
            "/firefox/profiles/",
            "/.mozilla/firefox/",
        ]),
        chromium_process_names: strings(&[
            "chrome",
            "chrome.exe",
            "google chrome",
            "msedge",
            "msedge.exe",
            "microsoft edge",
            "brave",
            "brave.exe",
            "brave browser",
            "vivaldi",
            "vivaldi.exe",
            "opera",
            "opera.exe",
            "chromium",
            "chromium.exe",
        ]),
        firefox_process_names: strings(&["firefox", "firefox.exe", "firefox-bin"]),
        directory_target_names: strings(&[
            "user data",
            "default",
            "profile 1",
            "profile 2",
            "profile 3",
            "profile 4",
            "profile 5",
            "guest profile",
            "system profile",
            "network",
            "profiles",
        ]),
    }
}

/// Per-platform build-output tree path substrings (FP-CI-6). Matched
/// case-insensitively against forward-slash-normalized paths. The
/// detector demotes `sandbox_exploitation` "bare lineage" findings
/// (process living in `/tmp/` with no other suspicious signal) to
/// LOW when BOTH the process binary path AND its parent process path
/// contain one of these substrings -- i.e. the binary that just got
/// spawned is the freshly-built output of a build tool whose own
/// staging tree it lives in (cargo `target/`, Flutter
/// `build/<platform>/`, Gradle `build/outputs/`, Lima
/// `edamame_posture_build/release/`, ...).
///
/// Substring (not prefix/regex) matching is intentional: it makes
/// the patterns trivial to extend across CI provider conventions
/// without rewriting the detector.
fn default_build_output_tree_self_spawn_patterns() -> PlatformStringLists {
    platform_string_lists(
        // macOS
        &[
            "/target/debug/",
            "/target/release/",
            "/build/macos/build/",
            "/build/macos/x64/release/",
            "/build/macos/x64/debug/",
            "/build/macos/x64/profile/",
            "/build/macos/arm64/release/",
            "/build/macos/arm64/debug/",
            "/build/macos/arm64/profile/",
            "/build/outputs/",
        ],
        // Linux
        &[
            "/target/debug/",
            "/target/release/",
            "/build/outputs/",
            "/build/linux/x64/release/",
            "/build/linux/x64/debug/",
            "/build/linux/x64/profile/",
            "/build/linux/arm64/release/",
            "/build/linux/arm64/debug/",
            "/build/linux/arm64/profile/",
            "/edamame_posture_build/release/",
            "/edamame_posture_build/debug/",
            "/edamame_posture/release/",
            "/edamame_posture/debug/",
        ],
        // Windows
        &[
            "/target/debug/",
            "/target/release/",
            "/build/windows/x64/release/",
            "/build/windows/x64/debug/",
            "/build/windows/x64/profile/",
            "/build/outputs/",
        ],
    )
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
        ".aamdownload",
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
            // FP-MAC-9: Apple-maintained Keychain peers and Safari
            // platform helpers legitimately update real Keychain DB
            // sidecars. These are trusted only by compact name and,
            // for path matches, by the system-library prefix gate.
            "trustedpeershelper",
            "comapplesafariplatformsupporthelper",
            // FP-MAC-8: xpcproxy is the launchd-spawned XPC service
            // launcher that mediates Keychain unlocks for M365 /
            // CloudKit / Mail.app sign-in. cloudd is the macOS
            // CloudKit daemon that talks to icloud.com/apple.com on
            // behalf of every iCloud-using app.
            "xpcproxy",
            "cloudd",
        ],
        &[
            "secd",
            "securityd",
            "assistantd",
            "commcenter",
            "networkserviceproxy",
            "trustedpeershelper",
            "comapplesafariplatformsupporthelper",
            // FP-MAC-8: same xpcproxy/cloudd attestation, leaf-name
            // form. Combined with the `/system/library/` /
            // `/usr/libexec/` prefix gate below, an impostor binary
            // at `/tmp/xpcproxy` does NOT match.
            "xpcproxy",
            "cloudd",
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

/// Well-known platform metadata service endpoints. Communication
/// to these IPs is performed by the OS-managed cloud-agent stack
/// (Azure Wire Server, EC2/GCE Instance Metadata Service, ...) and
/// is structurally part of the host's own life-cycle, not user
/// network activity.
///
/// Used by the `sensitive_material_egress` suppression hook
/// `should_suppress_sensitive_material_egress_as_platform_metadata_call`
/// so that e.g. `python3 /usr/sbin/waagent` reading
/// `/var/lib/waagent/Certificates.pem` while talking to
/// `168.63.129.16` (Azure Wire Server) does not trip a CRITICAL
/// finding on every Azure Linux VM the daemon runs on.
///
/// macOS deliberately ships an empty list -- there is no equivalent
/// platform metadata endpoint on Apple hosts.
fn default_platform_metadata_endpoints() -> PlatformStringLists {
    platform_string_lists(
        // macos
        &[],
        // linux
        &["168.63.129.16", "169.254.169.254"],
        // windows
        &["168.63.129.16", "169.254.169.254"],
    )
}

/// Filesystem locations whose contents belong to the platform's own
/// cloud-agent stack. Companion to
/// `platform_metadata_endpoints`: a sensitive-material finding is
/// only suppressed when ALL credential/secret-like files in the
/// finding live under one of these directories.
///
/// Patterns are case-insensitive substring matches against the
/// normalized (forward-slash, lowercase) file path. Windows entries
/// keep `\` because the FIM event paths there typically retain the
/// original separator.
fn default_platform_self_state_directories() -> PlatformStringLists {
    platform_string_lists(
        // macos
        &[],
        // linux
        &[
            "/var/lib/waagent/",
            "/etc/cloud/",
            "/var/lib/cloud/",
            "/var/log/waagent/",
            "/var/log/cloud-init/",
        ],
        // windows
        &["\\windowsazure\\", "\\packages\\plugins\\microsoft.azure."],
    )
}

/// Process basenames recognized as platform-managed cloud-agent
/// daemons. Matched case-insensitively against the process name,
/// parent process name, script basename, and parent-script basename
/// of the session attribution.
///
/// Used as a third gate by
/// `should_suppress_sensitive_material_egress_as_platform_metadata_call`:
/// suppression only applies when the responsible process is one of
/// these platform agents (so a malicious binary impersonating them
/// from `/tmp/` or `~/.cache/` still trips the gate via the existing
/// suspicious-lineage / suspicious-path checks).
fn default_platform_self_state_processes() -> PlatformStringLists {
    platform_string_lists(
        // macos
        &[],
        // linux
        &[
            "waagent",
            "cloud-init",
            "cloud-init-local",
            "azure-network-watcher-agent",
        ],
        // windows
        &[
            "windowsazureguestagent.exe",
            "waappagent.exe",
            "azurewatsoncrashhandler.exe",
            "azurediagnosticshealthagent.exe",
        ],
    )
}

/// Per-platform routine egress destinations for trusted platform
/// credential helpers (FP-MAC-8). The detector consults this list
/// from `should_suppress_session_credential_helper_self_access`
/// after confirming:
///   1. The session's process is a trusted platform credential
///      helper (`looks_like_trusted_platform_credential_helper_*`),
///      AND
///   2. Every derived sensitive file is an OS-managed credential
///      store (`credential_store_kind_for_path`).
///
/// Only then does the egress destination get checked here. The check
/// is cheap and intentionally per-platform: macOS `xpcproxy` mediating
/// M365 sign-in legitimately egresses to Microsoft Azure, but a Linux
/// `gnome-keyring-daemon` should not be talking to Microsoft. A
/// helper egressing to a destination not on its platform's allowlist
/// stays alertable.
fn default_platform_credential_helper_routine_destinations(
) -> PlatformCredentialHelperRoutineDestinationsJSON {
    PlatformCredentialHelperRoutineDestinationsJSON {
        macos: CredentialHelperDestinationListJSON {
            asn_owners: strings(&[
                "Microsoft Corporation",
                "Microsoft Azure",
                "Apple Inc",
                "Apple Inc.",
                "Akamai Technologies",
                "Akamai International",
            ]),
            domain_patterns: strings(&[
                ".login.microsoftonline.com",
                ".login.live.com",
                ".graph.microsoft.com",
                ".outlook.office365.com",
                ".outlook.office.com",
                ".office365.com",
                ".office.com",
                ".appleid.apple.com",
                ".icloud.com",
                ".gsa.apple.com",
                ".gsas.apple.com",
                ".apple.com",
            ]),
            ip_prefixes: strings(&["2603:1026:", "2603:1061:"]),
        },
        linux: CredentialHelperDestinationListJSON::default(),
        windows: CredentialHelperDestinationListJSON {
            asn_owners: strings(&["Microsoft Corporation", "Microsoft Azure"]),
            domain_patterns: strings(&[
                ".login.microsoftonline.com",
                ".login.live.com",
                ".graph.microsoft.com",
                ".outlook.office365.com",
                ".outlook.office.com",
                ".office365.com",
                ".office.com",
            ]),
            ip_prefixes: strings(&["2603:1026:", "2603:1061:"]),
        },
    }
}

/// Per-platform JVM HotSpot perfdata path entries (FP-CI-5). The
/// detector fully suppresses `file_system_tampering` findings whose
/// artifact path contains `artifact_path_substring` AND whose writer
/// matches one of the allowlisted JVM basenames OR install path
/// prefixes. These are transient counter files HotSpot creates for
/// every JVM PID, never security-relevant.
fn default_runtime_perfdata_paths() -> PlatformRuntimePerfdataPathsJSON {
    let java_basenames = strings(&["java"]);
    PlatformRuntimePerfdataPathsJSON {
        macos: vec![
            RuntimePerfdataEntryJSON {
                artifact_path_substring: "/private/tmp/hsperfdata_".to_string(),
                writer_basenames: java_basenames.clone(),
                writer_path_prefixes: strings(&[
                    "/Library/Java/JavaVirtualMachines/",
                    "/Applications/Android Studio.app/Contents/jbr/",
                    "/opt/homebrew/Cellar/openjdk",
                    "/usr/local/Cellar/openjdk",
                ]),
            },
            RuntimePerfdataEntryJSON {
                artifact_path_substring: "/tmp/hsperfdata_".to_string(),
                writer_basenames: java_basenames.clone(),
                writer_path_prefixes: strings(&[
                    "/Library/Java/JavaVirtualMachines/",
                    "/Applications/Android Studio.app/Contents/jbr/",
                    "/opt/homebrew/Cellar/openjdk",
                    "/usr/local/Cellar/openjdk",
                ]),
            },
        ],
        linux: vec![RuntimePerfdataEntryJSON {
            artifact_path_substring: "/tmp/hsperfdata_".to_string(),
            writer_basenames: java_basenames,
            writer_path_prefixes: strings(&[
                "/usr/lib/jvm/",
                "/opt/temurin",
                "/opt/openjdk",
                "/opt/jdk",
                "/Library/Java/JavaVirtualMachines/",
                "/actions-runner/_work/_tool/Java_",
                "/actions-runner1/_work/_tool/Java_",
                "/actions-runner2/_work/_tool/Java_",
                "/actions-runner3/_work/_tool/Java_",
                "/actions-runner4/_work/_tool/Java_",
                "/.sdkman/candidates/java/",
                "/.gradle/jdks/",
                "/.android/sdk/",
            ]),
        }],
        windows: vec![],
    }
}

/// Path substrings that identify per-OS package-manager working
/// directories where toolchains legitimately stage downloaded
/// dependency archives. The `file_system_tampering` detector would
/// otherwise flag every Flutter/dart `pub_*\<pkg>.tar.gz`,
/// `npm_-_-_-/cache.tgz`, `pip-build-*\source.tar.gz`, etc. that a
/// CI build downloads while the toolchain has external sessions to
/// the registry.
///
/// The carve-out is conjunctive: BOTH the writer process basename
/// (matched against `package_manager_temp_writers`) AND the path
/// pattern (here) must match before the FIM event is suppressed.
/// A malicious binary writing to a directory that happens to share
/// the name of a package-manager temp dir does NOT get a free pass
/// because its process basename will not appear in the writer
/// allowlist.
///
/// Patterns are case-insensitive substring matches against the
/// normalized (forward-slash, lowercase) FIM event path. Windows
/// entries keep `\` for the host's native separator style; the
/// detector normalizes both representations before matching.
///
/// Path patterns identifying well-known managed temp-staging
/// directories where benign extraction / build output is written into
/// OS temp directories during builds. One canonical Windows case is
/// the WiX Toolset's `light.exe`, which extracts
/// `WixToolset.BootstrapperApplications.wixext_<HASH>` into a
/// per-build temp directory and emits `wix-ir/*.wxl` localization
/// resources during `cargo wix` packaging on the Windows runner.
/// Another cross-platform case is tonic/prost writing protobuf
/// descriptor sets into `prost-buildXXXXXX/` temp trees during Cargo
/// build-script execution.
///
/// Patterns are case-insensitive substring matches against the
/// normalized (forward-slash, lowercase) FIM event path. Windows
/// entries keep `\` for the host's native separator style; the
/// detector normalizes both representations before matching.
///
/// Suppression here is path-only (no writer-process gate) because
/// FIM events for `light.exe`-spawned `BootstrapperApplications`
/// extraction frequently arrive with no L7 attribution. The
/// patterns themselves are deeply specific to the WiX toolchain
/// (`WixToolset.BootstrapperApplications.wixext_<HASH>` and the
/// `wix-ir/` intermediate output directory) and combined with the
/// implicit `\Temp\` gate from the surrounding non-temp branch
/// they cannot be confused with an attacker drop.
///
/// See `FALSEPOSITIVES.md` (FP-WIN-13).
fn default_managed_temp_staging_patterns() -> ManagedTempStagingPatternsJSON {
    ManagedTempStagingPatternsJSON {
        suppress_path_patterns: platform_string_lists(
            // macos
            &["/prost-build"],
            // linux
            &["/prost-build"],
            // windows
            &[
                "\\prost-build",
                "\\wixtoolset.bootstrapperapplications.wixext_",
                "\\wix-ir\\",
                "-populate-prefix\\tmp\\",
                "\\nugetscratch",
                "\\chocolatey\\chocolateyscratch",
                "\\system-commandline-sentinel-files",
                "\\remoteipmoproxy_configdefender_",
            ],
        ),
        // Weaker path-only evidence: keep as LOW audit evidence instead of
        // suppressing it completely.
        demote_path_patterns: platform_string_lists(
            // macos
            &[],
            // linux
            &[],
            // windows -- WiX Bootstrapper Application runtime extraction tree
            // and Chromium extension install/unpack staging.
            &["\\.ba", "\\chromecrx_"],
        ),
    }
}

/// Build and signing tools that legitimately materialize installer
/// artifacts under OS temp directories while also talking to package or
/// signing services. The detector demotes these to LOW only when BOTH the
/// writer path and artifact path match, so a spoofed `light.exe` in temp does
/// not inherit trust.
fn default_trusted_build_temp_staging() -> TrustedBuildTempStagingJSON {
    TrustedBuildTempStagingJSON {
        writer_path_patterns: platform_string_lists(
            // macos
            &[],
            // linux
            &[],
            // windows
            &[
                "\\program files (x86)\\wix toolset",
                "\\program files\\wix toolset",
                "\\.dotnet\\tools\\azuresigntool.exe",
            ],
        ),
        artifact_path_patterns: platform_string_lists(
            // macos
            &[],
            // linux
            &[],
            // windows
            &[
                "\\appdata\\local\\temp\\",
                "\\temp\\axs.",
                "\\temp\\00000001.",
                "\\temp\\npmiemut\\",
                "\\temp\\#media",
            ],
        ),
    }
}

/// See `FALSEPOSITIVES.md` (FP-WIN-11).
fn default_package_manager_temp_path_patterns() -> PlatformStringLists {
    platform_string_lists(
        // macos
        &[
            "/private/var/folders/",
            "/library/caches/pub/",
            "/.pub-cache/",
            "/.npm/_cacache/",
            "/.yarn/cache/",
            "/.cargo/registry/cache/",
        ],
        // linux
        &[
            "/tmp/pub_",
            "/tmp/pub-cache-",
            "/tmp/npm-",
            "/tmp/yarn-",
            "/tmp/pip-",
            "/tmp/cargo-install",
            "/.cache/pub/",
            "/.npm/_cacache/",
            "/.yarn/cache/",
            "/.cargo/registry/cache/",
        ],
        // windows
        &[
            "\\temp\\pub_",
            "\\temp\\npm-",
            "\\temp\\yarn-",
            "\\temp\\.yarn-cache\\",
            "\\temp\\pip-",
            "\\appdata\\local\\pub-cache\\",
            "\\appdata\\local\\npm-cache\\",
            "\\appdata\\roaming\\npm-cache\\",
            "\\appdata\\local\\yarn\\cache\\",
            "\\.cargo\\registry\\cache\\",
        ],
    )
}

/// Process basenames recognized as legitimate package-manager
/// toolchains that download dependency archives into their own
/// temp/cache directories. Companion to
/// `package_manager_temp_path_patterns`: a `file_system_tampering`
/// finding is only suppressed when BOTH the writer basename matches
/// here AND the artifact path matches the temp pattern list.
///
/// Match is case-insensitive exact-match against `process_name`.
/// Windows entries include the `.exe`/`.cmd` suffix that FIM events
/// carry; non-Windows variants omit the suffix.
fn default_package_manager_temp_writers() -> PlatformStringLists {
    platform_string_lists(
        // macos
        &[
            "dart", "node", "npm", "yarn", "pnpm", "pip", "pip3", "cargo",
        ],
        // linux
        &[
            "dart", "node", "npm", "yarn", "pnpm", "pip", "pip3", "cargo",
        ],
        // windows
        &[
            "dart.exe",
            "node.exe",
            "npm.cmd",
            "npm.exe",
            "yarn.cmd",
            "yarn.js",
            "pnpm.cmd",
            "pnpm.exe",
            "pip.exe",
            "pip3.exe",
            "cargo.exe",
        ],
    )
}

/// Per-OS process basenames that identify the EDAMAME daemon family
/// (the GUI app, the posture CLI, the privileged helper). Used to
/// recognize legitimate self-access during the daemon's own threat
/// checks and self-telemetry uploads.
///
/// The deterministic `file_system_tampering` severity grading uses
/// this list to extend the FP-WIN-4 LOW-demote carve-out
/// (`operator_scratch_script_shape`) to also fire when
/// `has_external_process` is true, AS LONG AS the writer is an
/// EDAMAME daemon binary AND the script content has no
/// network-command tokens. This handles the canonical FP-WIN-15
/// shape: `edamame_posture.exe` writes a `.tmp*.ps1` threat-check
/// stub into `%TEMP%` while concurrently uploading telemetry to
/// `hub.edamame.tech`. The egress is real but it is the daemon's
/// own self-telemetry, not malicious payload exfil. Without this
/// allowance the FP-WIN-4 demote misses the EDAMAME case and the
/// daemon flags itself HIGH on every CI / dogfood run.
///
/// The carve-out is conjunctive (writer name AND no network-command
/// content AND not in `/tmp/`): an attacker who happens to drop a
/// `.tmp*.ps1` containing `curl evil.example.com` into `%TEMP%`
/// would still trip HIGH because `network_command_like` flips the
/// gate off, regardless of process attribution.
///
/// See `FALSEPOSITIVES.md` (FP-WIN-15) and
/// `FALSEPOSITIVESFIX.md` (FP-WIN-15) for the full case study.
fn default_edamame_daemon_self_telemetry_writers() -> PlatformStringLists {
    platform_string_lists(
        // macos
        &[
            "edamame",
            "edamame_posture",
            "edamame_helper",
            "edamame_security",
        ],
        // linux
        &[
            "edamame",
            "edamame_posture",
            "edamame_helper",
            "edamame_security",
        ],
        // windows
        &[
            "edamame.exe",
            "edamame_posture.exe",
            "edamame_helper.exe",
            "edamame_security.exe",
        ],
    )
}

fn default_edamame_daemon_self_telemetry_install_prefixes() -> PlatformStringLists {
    platform_string_lists(
        // macos
        &[
            "/applications/edamame security.app/contents/macos/",
            "/usr/local/bin/",
            "/opt/homebrew/bin/",
        ],
        // linux
        &[
            "/usr/lib/edamame-security/",
            "/opt/edamame/",
            "/usr/local/bin/",
        ],
        // windows
        &[
            "c:/program files/windowsapps/edamametechnologies.edamamesecurity_",
            "c:/program files/edamame/",
        ],
    )
}

/// Filename leaf-prefixes that identify well-known platform-runtime
/// probe scripts. The canonical case is Windows PowerShell, which
/// drops a tiny one-line probe `__PSScriptPolicyTest_<random>.<random>.ps1`
/// into `%TEMP%` every time any process spawns `powershell.exe` to
/// verify the current execution policy. The probe is recognized,
/// well-documented Microsoft behaviour, NOT user activity.
///
/// Matched as a case-insensitive prefix against the lowercased
/// filename leaf (path basename). Storing the prefix is sufficient
/// because the random suffix portion has no security relevance.
///
/// See `FALSEPOSITIVES.md` (FP-WIN-12).
fn default_platform_runtime_probe_filename_patterns() -> PlatformStringLists {
    platform_string_lists(
        // macos
        &[],
        // linux
        &[],
        // windows
        &["__psscriptpolicytest_"],
    )
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
    pub secret_content_script_extensions: Vec<String>,
    pub secret_content_network_command_tokens: Vec<String>,
    pub secret_content_scan_excluded_path_patterns: Vec<String>,
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
    pub package_manager_temp_path_patterns: PlatformStringLists,
    pub package_manager_temp_writers: PlatformStringLists,
    pub edamame_daemon_self_telemetry_writers: PlatformStringLists,
    pub edamame_daemon_self_telemetry_install_prefixes: PlatformStringLists,
    pub platform_credential_helper_routine_destinations:
        PlatformCredentialHelperRoutineDestinationsJSON,
    pub platform_metadata_endpoints: PlatformStringLists,
    pub platform_runtime_probe_filename_patterns: PlatformStringLists,
    pub platform_self_state_directories: PlatformStringLists,
    pub platform_self_state_processes: PlatformStringLists,
    pub runtime_perfdata_paths: PlatformRuntimePerfdataPathsJSON,
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
            fim_hash_size_threshold: json.fim_hash_size_threshold,
            fim_temp_executable_patterns: json.fim_temp_executable_patterns.clone(),
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

/// Returns true when BOTH `process_path` and `parent_process_path`
/// lie inside one of the configured per-platform build-output trees
/// (cargo `target/`, Flutter `build/<platform>/`, Gradle
/// `build/outputs/`, Lima `edamame_posture_build/release/`, ...).
///
/// Used by the `sandbox_exploitation` detector to demote bare-lineage
/// HIGH findings to LOW when the binary that just got spawned is
/// clearly the freshly-built output of the parent build tool whose
/// own staging tree it lives in (FP-CI-6). Both halves of the
/// conjunction must match -- a single half is not enough to rule out
/// a malicious dropper that happens to live in `/tmp/`.
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

    path_matches(&proc) && path_matches(&parent)
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
            // attestation pair documented in `FALSEPOSITIVESFIX.md`
            // (FP-CI-5).
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
///
/// See `FALSEPOSITIVES.md` (FP-WIN-15) and
/// `FALSEPOSITIVESFIX.md` (FP-WIN-15).
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

/// Lowercased, slash-normalized path substrings that mark a path as
/// "transient build-artifact, do not content-scan". See
/// [`default_secret_content_scan_excluded_path_patterns`] for the
/// rationale and Win32 race details.
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
