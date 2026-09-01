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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edamame-fim-support-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn assert_well_formed(paths: &[PathBuf], home: &Path) {
        for p in paths {
            assert!(
                !p.as_os_str().is_empty(),
                "watch path list must not contain empty entries: {:?}",
                paths
            );
            assert!(p.is_absolute(), "watch path must be absolute: {:?}", p);
            assert!(
                p.starts_with(home) || fim::default_temp_watch_paths().contains(p),
                "watch path {:?} is neither under home {:?} nor a temp root",
                p,
                home
            );
        }
        let mut dedup = paths.to_vec();
        dedup.sort();
        dedup.dedup();
        assert_eq!(
            dedup.len(),
            paths.len(),
            "duplicate watch paths: {:?}",
            paths
        );
    }

    #[test]
    fn test_default_watch_paths_for_home_includes_existing_sensitive_dirs() {
        let home = temp_home("sensitive");
        // `.ssh` is in `watch_roots.common_home_relative` on every platform;
        // only directories that exist under the home are watched.
        std::fs::create_dir_all(home.join(".ssh")).unwrap();

        let paths = default_watch_paths_for_home(&home);
        assert!(!paths.is_empty());
        assert!(
            paths.contains(&home.join(".ssh")),
            "existing ~/.ssh must be watched: {:?}",
            paths
        );
        assert_well_formed(&paths, &home);

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn test_default_watch_paths_for_home_skips_missing_dirs() {
        let home = temp_home("empty");
        let paths = default_watch_paths_for_home(&home);
        // Nothing under the home exists, so only the (existing) temp roots
        // can be returned -- never a path under home that does not exist.
        assert!(
            paths.iter().all(|p| !p.starts_with(&home)),
            "no non-existent home-relative path may be watched: {:?}",
            paths
        );
        for p in &paths {
            assert!(p.exists(), "returned watch path must exist: {:?}", p);
        }
        assert_well_formed(&paths, &home);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn test_default_watch_paths_for_home_appends_temp_roots_once() {
        let home = temp_home("temp");
        let paths = default_watch_paths_for_home(&home);
        for t in fim::default_temp_watch_paths() {
            assert_eq!(
                paths.iter().filter(|p| **p == t).count(),
                1,
                "temp root {:?} must appear exactly once in {:?}",
                t,
                paths
            );
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn test_resolve_fim_watch_paths_explicit_paths_win() {
        let home = temp_home("explicit");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let explicit = vec!["/nonexistent/a".to_string(), "/nonexistent/b".to_string()];

        for mode in [FimMode::CI, FimMode::Desktop] {
            for user_home in [Some(home.as_path()), None] {
                let got = resolve_fim_watch_paths(&explicit, user_home, mode);
                assert_eq!(
                    got,
                    vec![
                        PathBuf::from("/nonexistent/a"),
                        PathBuf::from("/nonexistent/b")
                    ],
                    "explicit paths must be returned verbatim (mode {:?}, home {:?})",
                    mode,
                    user_home
                );
            }
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn test_resolve_fim_watch_paths_with_home_uses_home_defaults() {
        let home = temp_home("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();

        for mode in [FimMode::CI, FimMode::Desktop] {
            let got = resolve_fim_watch_paths(&[], Some(&home), mode);
            assert_eq!(
                got,
                default_watch_paths_for_home(&home),
                "an explicit home must delegate to default_watch_paths_for_home regardless of mode"
            );
            assert!(got.contains(&home.join(".ssh")));
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn test_resolve_fim_watch_paths_without_home_uses_mode_defaults() {
        for mode in [FimMode::CI, FimMode::Desktop] {
            let got = resolve_fim_watch_paths(&[], None, mode);
            assert_eq!(
                got,
                fim::default_watch_paths(mode),
                "no home must delegate to flodbadd's per-mode defaults"
            );
            for p in &got {
                assert!(!p.as_os_str().is_empty());
                assert!(p.is_absolute(), "{:?}", p);
            }
        }
    }

    #[test]
    fn test_current_fim_config_uses_params_threshold() {
        let cfg = current_fim_config();
        assert_eq!(
            cfg.hash_size_threshold,
            crate::vuln_detector_params::fim_hash_size_threshold()
        );
        assert!(cfg.recursive, "default FIM config is recursive");
    }
}
