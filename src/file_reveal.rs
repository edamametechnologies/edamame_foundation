//! Reveal a path in the operator's file manager (Finder / Explorer / xdg-open).
//!
//! Used by the sandboxed EDAMAME app: transcript folders and instruction roots
//! live outside the app container, so Reveal MUST run on the privileged /
//! standalone side (helper daemon or `standalone` core), never via
//! `Uri.file` from Flutter.
//!
//! When the helper runs as root, macOS/Linux launches cross into the owning
//! user's GUI session (`launchctl asuser` / `sudo -u`), matching
//! `agent_cli_insight`'s interactive Terminal spawn.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::info;

/// Result of a reveal attempt. Serialized across the helper gRPC boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealPathResult {
    pub success: bool,
    /// Absolute path that was opened (folder, or file for select/reveal).
    pub opened_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RevealPathResult {
    pub fn ok(opened: impl Into<String>) -> Self {
        Self {
            success: true,
            opened_path: opened.into(),
            error: None,
        }
    }

    pub fn err(path: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            success: false,
            opened_path: path.into(),
            error: Some(error.into()),
        }
    }
}

/// Resolve `path` to an on-disk target under `home`, then open it in the
/// file manager. Accepts:
/// - Absolute file/dir paths under `home`
/// - Dash-encoded Claude/Cursor workspace slugs (`-Users-me-code-repo`)
///   resolved to `~/.claude/projects/<slug>` (etc.) when that dir exists
pub fn reveal_path_in_file_manager(path: &str, home: &Path) -> RevealPathResult {
    match resolve_reveal_target(path, home) {
        Ok(target) => match open_in_file_manager(&target, home) {
            Ok(()) => {
                info!(
                    "file_reveal: opened {} (input={})",
                    target.display(),
                    path
                );
                RevealPathResult::ok(target.to_string_lossy())
            }
            Err(e) => RevealPathResult::err(target.to_string_lossy(), e.to_string()),
        },
        Err(e) => RevealPathResult::err(path, e.to_string()),
    }
}

fn resolve_reveal_target(path: &str, home: &Path) -> Result<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("empty path"));
    }

    let looks_like_slug = trimmed.starts_with('-')
        && !trimmed.contains('/')
        && !trimmed.contains('\\');

    if looks_like_slug {
        for rel in [
            format!(".claude/projects/{trimmed}"),
            format!(".cursor/projects/{trimmed}"),
            format!(".codex/sessions/{trimmed}"),
        ] {
            let candidate = home.join(&rel);
            if candidate.is_dir() {
                return ensure_under_home(candidate, home);
            }
        }
        // Prefer Claude projects even when not yet visible -- helper may see
        // it while the app cannot; existence is re-checked at open time.
        return ensure_under_home(home.join(".claude/projects").join(trimmed), home);
    }

    let raw = PathBuf::from(trimmed);
    let abs = if raw.is_absolute() {
        raw
    } else {
        home.join(&raw)
    };

    // If it's a file, reveal the file (Finder -R / Explorer /select).
    // If missing, try its parent directory.
    if abs.exists() {
        return ensure_under_home(abs, home);
    }
    if let Some(parent) = abs.parent() {
        if parent.exists() {
            return ensure_under_home(parent.to_path_buf(), home);
        }
    }
    Err(anyhow!(
        "path not found under home: {}",
        abs.display()
    ))
}

fn ensure_under_home(path: PathBuf, home: &Path) -> Result<PathBuf> {
    let home_canon = home
        .canonicalize()
        .unwrap_or_else(|_| home.to_path_buf());
    let path_canon = path
        .canonicalize()
        .unwrap_or_else(|_| path.clone());
    if !path_canon.starts_with(&home_canon) {
        return Err(anyhow!(
            "refusing to reveal path outside home: {}",
            path.display()
        ));
    }
    Ok(path_canon)
}

fn open_in_file_manager(path: &Path, home: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        return open_macos(path, home);
    }
    #[cfg(target_os = "windows")]
    {
        let _ = home;
        return open_windows(path);
    }
    #[cfg(target_os = "linux")]
    {
        return open_linux(path, home);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = (path, home);
        Err(anyhow!("reveal_path_in_file_manager unsupported on this platform"))
    }
}

#[cfg(target_os = "macos")]
fn open_macos(path: &Path, home: &Path) -> Result<()> {
    let path_str = path.to_string_lossy().to_string();
    // Reveal file in Finder when it's a file; open the folder otherwise.
    let reveal_file = path.is_file();
    let uid = root_target_uid(Some(home));
    let mut cmd = std::process::Command::new(if uid.is_some() {
        "/bin/launchctl"
    } else {
        "/usr/bin/open"
    });
    if let Some(uid) = uid {
        cmd.arg("asuser").arg(uid.to_string()).arg("/usr/bin/open");
    }
    if reveal_file {
        cmd.arg("-R").arg(&path_str);
    } else {
        cmd.arg(&path_str);
    }
    let status = cmd
        .status()
        .map_err(|e| anyhow!("Failed to spawn open: {e}"))?;
    if !status.success() {
        return Err(anyhow!("open exited with {status}"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn open_windows(path: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let path_str = path.to_string_lossy().to_string();
    let mut cmd = std::process::Command::new("explorer");
    if path.is_file() {
        cmd.arg(format!("/select,{path_str}"));
    } else {
        cmd.arg(&path_str);
    }
    cmd.creation_flags(CREATE_NO_WINDOW);
    let status = cmd
        .status()
        .map_err(|e| anyhow!("Failed to spawn explorer: {e}"))?;
    // explorer often returns non-zero even on success; only fail on spawn.
    let _ = status;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_linux(path: &Path, home: &Path) -> Result<()> {
    let dir = if path.is_file() {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| path.to_path_buf())
    } else {
        path.to_path_buf()
    };
    let dir_str = dir.to_string_lossy().to_string();

    let mut cmd = if root_target_uid(Some(home)).is_some() {
        let user = user_name_from_home(home)
            .ok_or_else(|| anyhow!("Cannot resolve target user for reveal"))?;
        let display = std::env::var("DISPLAY").unwrap_or_else(|_| ":0".to_string());
        let mut c = std::process::Command::new("sudo");
        c.arg("-u")
            .arg(&user)
            .arg("env")
            .arg(format!("DISPLAY={display}"));
        let xauth = home.join(".Xauthority");
        if xauth.is_file() {
            c.arg(format!("XAUTHORITY={}", xauth.to_string_lossy()));
        }
        c.arg("xdg-open").arg(&dir_str);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(&dir_str);
        c
    };
    let status = cmd
        .status()
        .map_err(|e| anyhow!("Failed to spawn xdg-open: {e}"))?;
    if !status.success() {
        return Err(anyhow!("xdg-open exited with {status}"));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn root_target_uid(home: Option<&Path>) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    if unsafe { libc::getuid() } != 0 {
        return None;
    }
    let home = home?;
    std::fs::metadata(home).ok().map(|m| m.uid())
}

#[cfg(target_os = "linux")]
fn user_name_from_home(home: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata(home).ok()?.uid();
    users::get_user_by_uid(uid).map(|u| u.name().to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rejects_path_outside_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let outside = tmp.path().join("other");
        fs::create_dir_all(&outside).unwrap();
        let err = resolve_reveal_target(outside.to_str().unwrap(), &home).unwrap_err();
        assert!(err.to_string().contains("outside home"));
    }

    #[test]
    fn resolves_dash_slug_under_claude_projects() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let slug = "-Users-me-code-repo";
        let project = home.join(".claude/projects").join(slug);
        fs::create_dir_all(&project).unwrap();
        let resolved = resolve_reveal_target(slug, &home).unwrap();
        assert_eq!(resolved, project.canonicalize().unwrap());
    }
}
