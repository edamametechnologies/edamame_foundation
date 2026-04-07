use flodbadd::fim::{self, FimConfig, FimMode};
use std::path::{Path, PathBuf};

pub fn current_fim_config() -> FimConfig {
    FimConfig {
        hash_size_threshold: crate::vuln_detector_params::fim_hash_size_threshold(),
        ..Default::default()
    }
}

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

fn push_existing_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if path.exists() {
        paths.push(path);
    }
}

fn default_watch_paths_for_home(home: &Path) -> Vec<PathBuf> {
    let common_dirs = [
        ".ssh", ".gnupg", ".aws", ".kube", ".docker", ".cursor", ".claude",
    ];

    let mut paths = Vec::new();
    for dir in &common_dirs {
        push_existing_path(&mut paths, home.join(dir));
    }

    #[cfg(target_os = "macos")]
    {
        push_existing_path(&mut paths, home.join("Library/Keychains"));
    }

    #[cfg(target_os = "linux")]
    {
        for dir in &[".config", ".local/share"] {
            push_existing_path(&mut paths, home.join(dir));
        }
    }

    #[cfg(target_os = "windows")]
    {
        for dir in &[
            "AppData/Roaming",
            "AppData/Local",
            "AppData/Local/Microsoft/Credentials",
            "AppData/Roaming/Microsoft/Credentials",
            "AppData/Local/Microsoft/Vault",
            "AppData/Roaming/Microsoft/Vault",
        ] {
            push_existing_path(&mut paths, home.join(dir));
        }
    }

    paths
}
