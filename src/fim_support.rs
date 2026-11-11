use flodbadd::fim::{self, FimConfig, FimMode, FimWatchRoots};
use flodbadd::store_writers::StoreSpec;
use std::path::{Path, PathBuf};

pub fn current_fim_config() -> FimConfig {
    FimConfig {
        hash_size_threshold: crate::vuln_detector_params::fim_hash_size_threshold(),
        delivery_probe_dir: delivery_probe_dir(),
        ..Default::default()
    }
}

/// Where the file monitor's delivery probe writes (`flodbadd::fim_delivery`):
/// the process's own application data, never a temp or watched home tree,
/// so another file monitor on the host drops the probe's events. A root
/// process uses root's home from the user database, not an inherited
/// `$HOME` (as `secret_store::secrets_location`): `sudo` keeps the calling
/// user's home on macOS. Both FIM startup paths (standalone core, helper
/// daemon) take it through [`current_fim_config`].
pub fn delivery_probe_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        crate::secret_store::account_home_dir(crate::secret_store::effective_uid())
            .map(|home| home.join("Library/Application Support/EDAMAME/fim-probe"))
    }
    #[cfg(target_os = "linux")]
    {
        crate::secret_store::account_home_dir(crate::secret_store::effective_uid())
            .map(|home| home.join(".local/share/edamame/fim-probe"))
    }
    #[cfg(target_os = "windows")]
    {
        dirs::data_local_dir().map(|dir| dir.join("EDAMAME").join("fim-probe"))
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

/// [`resolve_fim_watch_paths`] with who chose each root ([`FimWatchRoots`]):
/// explicit `paths` are the operator's and keep every event; the default
/// roots are split by `sensitive-paths-db.json::watch_roots_early_drop`, the
/// generic application-data trees taking the watcher's early drop. Both FIM
/// startup paths (standalone core, helper daemon) call this with the same
/// arguments.
///
/// The agent transcript stores are attached whatever the other roots are
/// ([`attach_stores`], under `user_home`): explicit paths replace the default
/// roots, never the stores.
pub fn resolve_fim_watch_roots(
    paths: &[String],
    user_home: Option<&Path>,
    mode: FimMode,
) -> FimWatchRoots {
    let roots = if !paths.is_empty() {
        FimWatchRoots::operator(paths.iter().map(PathBuf::from).collect())
    } else {
        match user_home {
            Some(home) => default_watch_roots_for_home(home),
            None => fim::default_watch_roots(mode),
        }
    };
    attach_stores(roots, user_home.ok_or(NO_HOME))
}

/// Why no home was resolved for the stores: the caller gave none.
pub const NO_HOME: &str = "no_home";

/// `roots` with the agent transcript stores a file monitor started for
/// `stores_home` records the writers of (`flodbadd::store_writers`): the
/// published `transcript_stores` under that home.
///
/// The home is the caller's to give: none is resolved here. A caller that
/// has none gives why (a word the status shows) and gets roots that say the
/// stores were not resolved ([`FimWatchRoots::with_unresolved_stores`]),
/// which the file monitor publishes as such. While
/// `transcript_write_trust_enabled` is published false there is no store to
/// resolve, with or without a home.
///
/// A caller whose roots need no home (explicit paths, the CI roots) passes
/// the home it resolved for the stores here.
pub fn attach_stores(roots: FimWatchRoots, stores_home: Result<&Path, &str>) -> FimWatchRoots {
    if !crate::vuln_detector_params::transcript_write_trust_enabled() {
        return roots.with_stores(Vec::new());
    }
    match stores_home {
        Ok(home) => roots.with_stores(store_specs_for_home(home)),
        Err(reason) => roots.with_unresolved_stores(reason),
    }
}

/// The published `transcript_stores` under `home`, one per agent type with
/// a root on this platform: the store roots and the pid-file roots joined
/// onto the home, the path segment and the endings as published, and the
/// published `transcript_capture.creation_reorder_ms`.
pub fn store_specs_for_home(home: &Path) -> Vec<StoreSpec> {
    // Component by component, so the separators are the platform's.
    let under_home = |relative: &String| -> PathBuf {
        relative
            .split('/')
            .filter(|part| !part.is_empty())
            .fold(home.to_path_buf(), |path, part| path.join(part))
    };
    let creation_reorder_ms =
        crate::agent_visibility_params::transcript_capture().creation_reorder_ms;
    crate::agent_visibility_params::transcript_stores()
        .into_iter()
        .filter_map(|(agent, store)| {
            let roots: Vec<PathBuf> = store
                .roots
                .for_this_platform()
                .iter()
                .map(under_home)
                .collect();
            if roots.is_empty() {
                return None;
            }
            Some(StoreSpec {
                agent,
                roots,
                path_segment: store.path_segment,
                excluded_segments: store.excluded_segments,
                file_suffixes: store.file_suffixes,
                pid_file_roots: store.pid_file_roots.iter().map(under_home).collect(),
                pid_file_suffixes: store.pid_file_suffixes,
                creation_reorder_ms,
            })
        })
        .collect()
}

/// [`default_watch_paths_for_home`] with who chose each root, as in
/// [`resolve_fim_watch_roots`].
pub fn default_watch_roots_for_home(home: &Path) -> FimWatchRoots {
    fim::default_watch_roots_for_home(home)
}

pub fn default_watch_paths_for_home(home: &Path) -> Vec<PathBuf> {
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

    /// The roots split the same directories the plain paths list, each
    /// once, and explicit paths stay the operator's whole.
    #[test]
    fn test_resolve_fim_watch_roots_matches_the_paths() {
        let home = temp_home("roots");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let paths = resolve_fim_watch_paths(&[], Some(&home), FimMode::Desktop);
        let roots = resolve_fim_watch_roots(&[], Some(&home), FimMode::Desktop);
        let mut split = roots.all();
        let mut plain = paths.clone();
        split.sort();
        plain.sort();
        assert_eq!(split, plain);
        assert!(roots.operator.contains(&home.join(".ssh")));

        let explicit = vec![home.join("project").to_string_lossy().to_string()];
        let roots = resolve_fim_watch_roots(&explicit, Some(&home), FimMode::Desktop);
        assert_eq!(
            roots,
            FimWatchRoots::operator(vec![home.join("project")])
                .with_stores(store_specs_for_home(&home))
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The stores are attached to the default roots and to explicit paths
    /// alike, under the home the caller gave: every published agent type
    /// with its roots joined onto it, and the pid-file roots of the agents
    /// that have them.
    #[test]
    fn test_the_transcript_stores_are_attached_whatever_the_roots() {
        let home = temp_home("stores");
        let specs = store_specs_for_home(&home);
        let agents: Vec<&str> = specs.iter().map(|spec| spec.agent.as_str()).collect();
        assert_eq!(
            agents,
            vec![
                "claude_code",
                "claude_desktop",
                "codex",
                "cursor",
                "hermes",
                "openclaw"
            ]
        );
        for spec in &specs {
            assert!(!spec.roots.is_empty(), "{}", spec.agent);
            assert!(!spec.file_suffixes.is_empty(), "{}", spec.agent);
            for root in spec.roots.iter().chain(spec.pid_file_roots.iter()) {
                assert!(root.starts_with(&home), "{:?} is not under the home", root);
                assert!(root.is_absolute());
            }
        }
        let claude = &specs[0];
        assert_eq!(claude.roots, vec![home.join(".claude").join("projects")]);
        assert_eq!(
            claude.pid_file_roots,
            vec![home.join(".claude").join("sessions")]
        );
        assert_eq!(claude.pid_file_suffixes, vec![".json".to_string()]);
        let cursor = specs.iter().find(|spec| spec.agent == "cursor").unwrap();
        assert_eq!(cursor.path_segment, "agent-transcripts");
        // Every store carries the published reorder bound.
        let reorder = crate::agent_visibility_params::transcript_capture().creation_reorder_ms;
        assert_eq!(reorder, 1_000);
        assert!(specs.iter().all(|spec| spec.creation_reorder_ms == reorder));

        for explicit in [
            Vec::new(),
            vec![home.join("audit").to_string_lossy().to_string()],
        ] {
            let roots = resolve_fim_watch_roots(&explicit, Some(&home), FimMode::Desktop);
            assert_eq!(roots.stores, specs, "explicit paths: {:?}", explicit);
            assert!(roots.stores_unresolved.is_none());
        }
        // A store root under a watched root is delivered with it; the others
        // are watched for the record only.
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let roots = resolve_fim_watch_roots(&[], Some(&home), FimMode::Desktop);
        let only = roots.store_only_roots();
        assert!(!only.contains(&home.join(".claude").join("projects")));
        assert!(only.contains(&home.join(".codex").join("sessions")));
        let _ = std::fs::remove_dir_all(&home);
    }

    /// No home is resolved here for the stores. A caller that gives none
    /// gets no store and roots that say so, whatever its other roots are;
    /// a caller whose roots need no home attaches the stores under the home
    /// it resolved.
    #[test]
    fn test_the_stores_are_resolved_under_the_callers_home_only() {
        assert!(crate::vuln_detector_params::transcript_write_trust_enabled());
        let home = temp_home("stores-home");
        let explicit = vec![home.join("audit").to_string_lossy().to_string()];
        for (paths, mode) in [
            (explicit.clone(), FimMode::Desktop),
            (explicit.clone(), FimMode::CI),
            (Vec::new(), FimMode::CI),
            (Vec::new(), FimMode::Desktop),
        ] {
            let roots = resolve_fim_watch_roots(&paths, None, mode);
            assert!(roots.stores.is_empty(), "{:?} {:?}", paths, mode);
            assert_eq!(
                roots.stores_unresolved.as_deref(),
                Some(NO_HOME),
                "{:?} {:?}",
                paths,
                mode
            );
            assert!(roots.store_only_roots().is_empty());

            // The same roots, with the stores under a home the caller
            // resolved: the watch roots are unchanged.
            let attached = attach_stores(roots.clone(), Ok(&home));
            assert_eq!(attached.stores, store_specs_for_home(&home));
            assert!(attached.stores_unresolved.is_none());
            assert_eq!(attached.operator, roots.operator);
            assert_eq!(attached.defaults, roots.defaults);
        }
        // None of the stores lies under a home this process could resolve
        // for itself.
        let attached = attach_stores(
            FimWatchRoots::operator(Vec::new()),
            Err("privileged_account"),
        );
        assert!(attached.stores.is_empty());
        assert_eq!(
            attached.stores_unresolved.as_deref(),
            Some("privileged_account")
        );
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
