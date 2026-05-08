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
    pub chromium_user_data_root_markers: Vec<String>,
    pub firefox_family_subtrees: Vec<String>,
    pub firefox_user_data_root_markers: Vec<String>,
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
    #[serde(default = "default_ci_workspace_path_patterns")]
    pub ci_workspace_path_patterns: Vec<String>,
    #[serde(default = "default_keychain_transactional_filename_patterns")]
    pub keychain_transactional_filename_patterns: Vec<String>,
    #[serde(default = "default_non_sensitive_browser_data_subtrees")]
    pub non_sensitive_browser_data_subtrees: BrowserDataSubtreesJSON,
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
    #[serde(default = "default_installer_toolchain_temp_path_patterns")]
    pub installer_toolchain_temp_path_patterns: PlatformStringLists,
    #[serde(default = "default_package_manager_temp_path_patterns")]
    pub package_manager_temp_path_patterns: PlatformStringLists,
    #[serde(default = "default_package_manager_temp_writers")]
    pub package_manager_temp_writers: PlatformStringLists,
    #[serde(default = "default_edamame_daemon_self_telemetry_writers")]
    pub edamame_daemon_self_telemetry_writers: PlatformStringLists,
    #[serde(default = "default_platform_metadata_endpoints")]
    pub platform_metadata_endpoints: PlatformStringLists,
    #[serde(default = "default_platform_runtime_probe_filename_patterns")]
    pub platform_runtime_probe_filename_patterns: PlatformStringLists,
    #[serde(default = "default_platform_self_state_directories")]
    pub platform_self_state_directories: PlatformStringLists,
    #[serde(default = "default_platform_self_state_processes")]
    pub platform_self_state_processes: PlatformStringLists,
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
        // intermediates, and CMake project caches. Scanning them is what
        // produced the `error C1090: PDB API call failed, error code '5'`
        // wedge on Windows self-hosted runners (FP-CI-2 second symptom):
        // `mspdbsrv.exe` cannot tolerate concurrent foreign opens of the
        // active PDB even when ours uses `FILE_SHARE_DELETE`. Skipping
        // these paths up-front is cheaper than retrying the read with
        // increasingly permissive share modes.
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
            "/component_crx_cache/",
            "/dawn_graphite_cache/",
            "/dawn_webgpu_cache/",
            "/grshadercache/",
            "/shadercache/",
            "/optimizationhints/",
            "/segmentation_platform/",
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
        firefox_user_data_root_markers: strings(&[
            "/mozilla/firefox/profiles/",
            "/firefox/profiles/",
            "/.mozilla/firefox/",
        ]),
    }
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
/// Path patterns identifying well-known Windows installer-toolchain
/// staging directories where benign extraction / build output is
/// written into `%TEMP%` during MSI builds. The canonical case is
/// the WiX Toolset's `light.exe`, which extracts
/// `WixToolset.BootstrapperApplications.wixext_<HASH>` into a
/// per-build temp directory and emits `wix-ir/*.wxl` localization
/// resources during `cargo wix` packaging on the Windows runner.
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
fn default_installer_toolchain_temp_path_patterns() -> PlatformStringLists {
    platform_string_lists(
        // macos
        &[],
        // linux
        &[],
        // windows
        &[
            "\\wixtoolset.bootstrapperapplications.wixext_",
            "\\wix-ir\\",
            // FP-WIN-14: CMake `FetchContent_Populate` writes
            // `<pkg>-mkdirs.cmake`, `<pkg>-download.cmake`,
            // `<pkg>-update.cmake`, etc. into
            // `build\<arch>\_deps\<pkg>-subbuild\<pkg>-populate-prefix\tmp\`
            // on every Flutter Windows build that uses CMake
            // FetchContent (corrosion, sentry-native, nuget, ...).
            // FIM events for these arrive without L7 attribution
            // and trip `temp_staging` + `temp_mutation` HIGH.
            "-populate-prefix\\tmp\\",
            // FP-WIN-14: NuGet's global cross-process scratch/lock
            // directory at `%LOCALAPPDATA%\Temp\NuGetScratch\lock\`
            // (also `\plan\`, `\v3-cache\`). Any Visual Studio / MSBuild
            // / `cargo wix` / Flutter Windows build that resolves NuGet
            // packages writes hex-named lock files into this tree.
            // FIM L7 attribution is unreliable here (frequently
            // misattributed to whichever process happened to be active
            // during the FIM tick).
            "\\nugetscratch\\",
        ],
    )
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
    pub ci_workspace_path_patterns: Vec<String>,
    pub keychain_transactional_filename_patterns: Vec<String>,
    pub non_sensitive_browser_data_subtrees: BrowserDataSubtreesJSON,
    pub suspicious_parent_path_patterns: Vec<String>,
    pub benign_temp_artifact_suffixes: Vec<String>,
    pub application_storage_patterns: Vec<String>,
    pub credential_store_patterns: PlatformStringLists,
    pub trusted_credential_helpers: PlatformHelperMatcherConfigs,
    pub packaged_application_contains_patterns: Vec<String>,
    pub packaged_application_starts_with_patterns: Vec<String>,
    pub packaged_application_ends_with_patterns: Vec<String>,
    pub installer_toolchain_temp_path_patterns: PlatformStringLists,
    pub package_manager_temp_path_patterns: PlatformStringLists,
    pub package_manager_temp_writers: PlatformStringLists,
    pub edamame_daemon_self_telemetry_writers: PlatformStringLists,
    pub platform_metadata_endpoints: PlatformStringLists,
    pub platform_runtime_probe_filename_patterns: PlatformStringLists,
    pub platform_self_state_directories: PlatformStringLists,
    pub platform_self_state_processes: PlatformStringLists,
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
                firefox_user_data_root_markers: json
                    .non_sensitive_browser_data_subtrees
                    .firefox_user_data_root_markers
                    .iter()
                    .map(|p| p.to_ascii_lowercase())
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
            installer_toolchain_temp_path_patterns: PlatformStringLists {
                macos: json
                    .installer_toolchain_temp_path_patterns
                    .macos
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                linux: json
                    .installer_toolchain_temp_path_patterns
                    .linux
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
                windows: json
                    .installer_toolchain_temp_path_patterns
                    .windows
                    .iter()
                    .map(|p| p.to_ascii_lowercase().replace('\\', "/"))
                    .collect(),
            },
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
            .any(|sub| !sub.is_empty() && lower.contains(sub));
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
            .any(|sub| !sub.is_empty() && lower.contains(sub));
        if cache_match {
            return true;
        }
    }

    false
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

/// Returns true if the normalized `path` lies within one of the
/// per-OS installer-toolchain temp staging directories (e.g. the
/// WiX Toolset's `WixToolset.BootstrapperApplications.wixext_<HASH>`
/// extraction directory and its `wix-ir/` sub-directory, written
/// during `cargo wix` MSI builds).
///
/// Path matching is case-insensitive and tolerant of separator
/// style: the input is lowercased and `\` is folded to `/` before
/// substring matching against the configured patterns (which are
/// also stored in normalized form).
///
/// Suppression here is path-only (no writer-process gate) because
/// FIM events for `light.exe`-spawned `BootstrapperApplications`
/// extraction frequently arrive without L7 attribution. The
/// patterns themselves are deeply specific to the WiX toolchain
/// and combined with the `\Temp\` gate from the surrounding
/// detector branch they cannot be confused with an attacker drop.
///
/// Used by the `file_system_tampering` installer-toolchain
/// suppression hook (FP-WIN-13).
pub fn is_installer_toolchain_temp_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase().replace('\\', "/");
    let snapshot = PARAMS_SNAPSHOT.load();
    let dirs = &snapshot.installer_toolchain_temp_path_patterns;
    let lists: [&Vec<String>; 3] = [&dirs.macos, &dirs.linux, &dirs.windows];
    lists.iter().any(|list| {
        list.iter()
            .any(|pattern| !pattern.is_empty() && lower.contains(pattern))
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
        // Flutter desktop / mobile per-platform build outputs (FP-CI-2
        // second symptom -- these are the paths that hold MSVC PDBs,
        // CMake project caches, Xcode intermediates, etc.).
        // Canonical Windows path that broke test_windows.yml run
        // 25544402336 with `error C1090: PDB API call failed,
        // error code '5'`.
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
        // FP-CI-2 second-symptom negative controls. The new Flutter
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
    fn test_installer_toolchain_temp_path_lookup() {
        // Canonical WiX BootstrapperApplication extraction during a
        // `cargo wix` MSI build on the Windows runner.
        assert!(is_installer_toolchain_temp_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\41ftcnya.p4m\\WixToolset.BootstrapperApplications.wixext_HPVZ2YWGIB0GOTbsOi2MVHIa9bk\\wix-ir\\HyperlinkTheme.wxl"
        ));
        // Same shape with forward-slash separators (FIM events
        // sometimes mix styles after normalization).
        assert!(is_installer_toolchain_temp_path(
            "C:/Users/edamame/AppData/Local/Temp/abc.def/WixToolset.BootstrapperApplications.wixext_XYZ/wix-ir/Theme.wxl"
        ));
        // The bare `wix-ir` directory pattern should also match
        // (covers wix-ir intermediate output written outside the
        // BootstrapperApplications hash dir).
        assert!(is_installer_toolchain_temp_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\some-build\\wix-ir\\foo.wixobj"
        ));
        // Case-insensitive matching.
        assert!(is_installer_toolchain_temp_path(
            "C:\\USERS\\EDAMAME\\APPDATA\\LOCAL\\TEMP\\X.Y\\WIXTOOLSET.BOOTSTRAPPERAPPLICATIONS.WIXEXT_HASH\\WIX-IR\\HYPERLINKTHEME.WXL"
        ));
        // Non-WiX paths must NOT match: a malicious binary writing
        // to a similarly-suffixed file outside the WiX staging
        // directory shape gets no free pass.
        assert!(!is_installer_toolchain_temp_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\malicious.wxl"
        ));
        assert!(!is_installer_toolchain_temp_path(
            "/home/user/repos/some-project/wix-ir.txt"
        ));
        assert!(!is_installer_toolchain_temp_path("/etc/passwd"));
        assert!(!is_installer_toolchain_temp_path(""));

        // FP-WIN-14a: CMake `FetchContent_Populate` writes
        // `<pkg>-mkdirs.cmake` (and `<pkg>-download.cmake`,
        // `<pkg>-update.cmake`, ...) into
        // `build\<arch>\_deps\<pkg>-subbuild\<pkg>-populate-prefix\tmp\`
        // on every Flutter Windows build. The unique substring
        // `-populate-prefix\tmp\` is what we suppress on.
        assert!(is_installer_toolchain_temp_path(
            "C:\\Users\\edamame\\actions-runner\\_work\\edamame_app\\edamame_app\\build\\windows\\x64\\_deps\\nuget-subbuild\\nuget-populate-prefix\\tmp\\nuget-populate-mkdirs.cmake"
        ));
        assert!(is_installer_toolchain_temp_path(
            "C:/Users/edamame/actions-runner/_work/edamame_app/edamame_app/build/windows/x64/_deps/corrosion-subbuild/corrosion-populate-prefix/tmp/corrosion-populate-download.cmake"
        ));
        assert!(is_installer_toolchain_temp_path(
            "C:\\Users\\edamame\\actions-runner\\_work\\edamame_app\\edamame_app\\build\\windows\\x64\\_deps\\sentry-native-subbuild\\sentry-native-populate-prefix\\tmp\\sentry-native-populate-update.cmake"
        ));
        // FP-WIN-14a impostor: a temp file that just happens to
        // mention "populate-prefix" but is NOT in the
        // `\tmp\` subdir of a CMake FetchContent populate-prefix
        // tree must NOT match.
        assert!(!is_installer_toolchain_temp_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\malware-populate-prefix.exe"
        ));

        // FP-WIN-14b: NuGet's global cross-process scratch/lock dir
        // at `%LOCALAPPDATA%\Temp\NuGetScratch\lock\` (and
        // `\plan\`, `\v3-cache\`). Hex-named lock files trip the
        // detector with a non-benign suffix; FIM L7 attribution is
        // unreliable here.
        assert!(is_installer_toolchain_temp_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\NuGetScratch\\lock\\db433f173e9b75688465fde95d3d04684cfdb3ae"
        ));
        assert!(is_installer_toolchain_temp_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\NuGetScratch\\plan\\abc123"
        ));
        assert!(is_installer_toolchain_temp_path(
            "C:/Users/edamame/AppData/Local/Temp/NuGetScratch/v3-cache/foo"
        ));
        // Case-insensitive.
        assert!(is_installer_toolchain_temp_path(
            "C:\\USERS\\EDAMAME\\APPDATA\\LOCAL\\TEMP\\NUGETSCRATCH\\LOCK\\HEX"
        ));
        // FP-WIN-14b impostor: a directory whose name contains
        // "nuget" but is NOT the `NuGetScratch` global cache must
        // NOT match.
        assert!(!is_installer_toolchain_temp_path(
            "C:\\Users\\edamame\\AppData\\Local\\Temp\\my-nuget-stash\\foo"
        ));
        assert!(!is_installer_toolchain_temp_path(
            "C:\\Users\\edamame\\AppData\\Roaming\\NuGet\\packages\\foo.dll"
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
