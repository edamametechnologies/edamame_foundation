use flodbadd::fim::{self, FimConfig, FimMode};
use std::path::{Path, PathBuf};

pub fn current_fim_config() -> FimConfig {
    FimConfig {
        hash_size_threshold: crate::vuln_detector_params::fim_hash_size_threshold(),
        ..Default::default()
    }
}

/// Resolve the effective FIM watch paths.
///
/// Both the standalone (`core_manager_fim`) and helper-daemon
/// (`helper_rx_utility`) FIM startup paths call this with the same arguments:
/// explicit `paths` win, otherwise we delegate to the single shared
/// `flodbadd::fim` default helpers so the two paths watch exactly the same
/// directories. See `edamame_core/.cursor/rules/invariants.mdc` --
/// "Content-Based Detection Heuristics MUST Be Pre-Enriched".
pub fn resolve_fim_watch_paths(
    paths: &[String],
    user_home: Option<&Path>,
    mode: FimMode,
) -> Vec<PathBuf> {
    if !paths.is_empty() {
        return paths.iter().map(PathBuf::from).collect();
    }

    match user_home {
        Some(home) => default_watch_paths_for_home(home),
        None => fim::default_watch_paths(mode),
    }
}

fn default_watch_paths_for_home(home: &Path) -> Vec<PathBuf> {
    // Delegate to the shared flodbadd helpers so the helper path (called here
    // with an explicit home) and the standalone path (which calls
    // `fim::default_watch_paths(Desktop)`) converge on the same default set.
    let mut paths = fim::default_sensitive_watch_paths_for_home(home);

    #[cfg(target_os = "windows")]
    {
        // Helper runs as a privileged daemon and targets the calling user's
        // home explicitly. The user-scoped `AppData/Roaming` and
        // `AppData/Local` roots are watched recursively, so any sensitive
        // child path under them (e.g. `Microsoft/Credentials/`,
        // `Microsoft/Protect/`, `Microsoft/Vault/`, browser User Data) is
        // already covered by the parent watch.
        //
        // We deliberately do NOT enumerate those credential-vault subpaths
        // explicitly here. Listing them as static `&str` literals adds a
        // textbook info-stealer reconnaissance fingerprint to the helper
        // binary's rodata section (Microsoft Defender flags the corpus as
        // `Trojan:Win32/Stealga.HAK!MTB`). Since the broader recursive
        // watches already cover them, the explicit list was strictly
        // redundant -- only its ML signal mattered.
        for dir in &["AppData/Roaming", "AppData/Local"] {
            let p = home.join(dir);
            if p.exists() && !paths.contains(&p) {
                paths.push(p);
            }
        }
    }

    for p in fim::default_temp_watch_paths() {
        if !paths.contains(&p) {
            paths.push(p);
        }
    }

    paths
}
