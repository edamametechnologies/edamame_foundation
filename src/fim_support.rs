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
    // Delegate to the shared flodbadd helper so the helper path (called here
    // with an explicit home) and the standalone path (which calls
    // `fim::default_watch_paths(Desktop)`) converge on the same default set.
    //
    // The directory list itself is sourced from the CloudModel
    // (`sensitive-paths-db.json::watch_roots`) -- there are intentionally NO
    // hardcoded directory literals on this side either. On Windows that
    // previously included an inline `AppData/Roaming` + `AppData/Local`
    // append; that list now lives in `watch_roots.windows_home_relative`
    // and is returned by the shared helper, so the inline append was
    // strictly redundant. Avoiding hardcoded `&str` literals also keeps
    // the helper binary's rodata clean of credential-store reconnaissance
    // fingerprints (`Trojan:Win32/Stealga.HAK!MTB`).
    let mut paths = fim::default_sensitive_watch_paths_for_home(home);

    for p in fim::default_temp_watch_paths() {
        if !paths.contains(&p) {
            paths.push(p);
        }
    }

    paths
}
