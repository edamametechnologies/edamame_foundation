use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use tracing::{info, warn};

/// When running as root (e.g. helper daemon), installed files end up root-owned.
/// This function re-chowns a directory tree to match the owner of `home`.
#[cfg(unix)]
fn chown_to_home_owner(path: &Path, home: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if !path.exists() {
        return Ok(());
    }

    let meta = std::fs::metadata(home)?;
    let uid = meta.uid();
    let gid = meta.gid();

    if unsafe { libc::getuid() } != 0 {
        return Ok(());
    }

    info!(
        "Chowning {} to uid={} gid={} (matching {})",
        path.display(),
        uid,
        gid,
        home.display()
    );

    chown_recursive(path, uid, gid)?;
    Ok(())
}

#[cfg(unix)]
fn chown_recursive(path: &Path, uid: u32, gid: u32) -> anyhow::Result<()> {
    use std::ffi::CString;

    let c_path =
        CString::new(path.to_string_lossy().as_bytes()).map_err(|e| anyhow!("bad path: {}", e))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        warn!("chown failed for {}: {}", path.display(), err);
    }

    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            chown_recursive(&entry.path(), uid, gid)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn chown_to_home_owner(_path: &Path, _home: &Path) -> anyhow::Result<()> {
    Ok(())
}

const GITHUB_ORG: &str = "edamametechnologies";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPluginProvisionResult {
    pub success: bool,
    pub agent_type: String,
    pub version: String,
    pub install_path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPluginStatus {
    pub agent_type: String,
    pub installed: bool,
    pub version: String,
    pub install_path: String,
    pub repo_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPluginUninstallResult {
    pub success: bool,
    pub agent_type: String,
    pub message: String,
}

pub struct AgentPluginDef {
    pub agent_type: &'static str,
    pub repo_name: &'static str,
    pub display_name: &'static str,
}

pub const AGENT_PLUGINS: &[AgentPluginDef] = &[
    AgentPluginDef {
        agent_type: "cursor",
        repo_name: "edamame_cursor",
        display_name: "EDAMAME for Cursor",
    },
    AgentPluginDef {
        agent_type: "claude_code",
        repo_name: "edamame_claude_code",
        display_name: "EDAMAME for Claude Code",
    },
    AgentPluginDef {
        agent_type: "openclaw",
        repo_name: "edamame_openclaw",
        display_name: "EDAMAME for OpenClaw",
    },
];

pub fn find_plugin_def(agent_type: &str) -> Option<&'static AgentPluginDef> {
    AGENT_PLUGINS.iter().find(|p| p.agent_type == agent_type)
}

pub fn repo_url(repo_name: &str) -> String {
    format!("https://github.com/{}/{}", GITHUB_ORG, repo_name)
}

fn zipball_url(repo_name: &str) -> String {
    format!(
        "https://api.github.com/repos/{}/{}/zipball/main",
        GITHUB_ORG, repo_name
    )
}

/// Return the real (unsandboxed) home directory.
///
/// On macOS the App Sandbox remaps **both** `dirs::home_dir()` and `$HOME` to
/// the container path `~/Library/Containers/<bundle-id>/Data`.  We detect this
/// pattern and strip the container suffix to recover the actual user home.
/// Falls back to `$HOME` if the path doesn't match the container pattern.
///
/// When running inside the helper (root), callers should pass an explicit
/// `user_home` override instead.
pub fn real_home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").ok()?;
        let path = PathBuf::from(&home);
        // Sandboxed: ~/Library/Containers/<bundle-id>/Data
        // Extract the real home by taking everything before /Library/Containers/
        if let Some(pos) = home.find("/Library/Containers/") {
            Some(PathBuf::from(&home[..pos]))
        } else {
            Some(path)
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::home_dir()
    }
}

/// Return the real (unsandboxed) Application Support directory on macOS,
/// or the platform-appropriate data directory elsewhere.
pub fn real_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        real_home_dir().map(|h| h.join("Library/Application Support"))
    }
    #[cfg(target_os = "windows")]
    {
        dirs::data_local_dir()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        dirs::data_dir()
    }
}

/// Variant that uses an explicit home directory (for helper running as root).
pub fn data_dir_for_home(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support")
    }
    #[cfg(target_os = "windows")]
    {
        dirs::data_local_dir().unwrap_or_else(|| home.join("AppData/Local"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::env::var("XDG_DATA_HOME")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
    }
}

pub fn resolve_install_path(agent_type: &str) -> Option<PathBuf> {
    resolve_install_path_with_home(agent_type, &real_home_dir()?, &real_data_dir()?)
}

/// Resolve install path using explicit home/data dirs (for helper running as a
/// different user).
pub fn resolve_install_path_with_home(
    agent_type: &str,
    home: &Path,
    data_dir: &Path,
) -> Option<PathBuf> {
    match agent_type {
        "cursor" => Some(data_dir.join("cursor-edamame/current")),
        "claude_code" => Some(data_dir.join("claude-code-edamame/current")),
        "openclaw" => Some(home.join(".openclaw/edamame-openclaw")),
        _ => None,
    }
}

pub fn resolve_config_dir(agent_type: &str) -> Option<PathBuf> {
    resolve_config_dir_with_home(agent_type, &real_home_dir()?)
}

pub fn resolve_config_dir_with_home(agent_type: &str, home: &Path) -> Option<PathBuf> {
    let slug = match agent_type {
        "cursor" => "cursor-edamame",
        "claude_code" => "claude-code-edamame",
        _ => return None,
    };

    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library/Application Support").join(slug))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|a| PathBuf::from(a).join(slug))
            .or_else(|| dirs::config_dir().map(|c| c.join(slug)))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Some(home.join(".config").join(slug))
    }
}

pub fn resolve_state_dir(agent_type: &str) -> Option<PathBuf> {
    resolve_state_dir_with_home(agent_type, &real_home_dir()?)
}

pub fn resolve_state_dir_with_home(agent_type: &str, home: &Path) -> Option<PathBuf> {
    let slug = match agent_type {
        "cursor" => "cursor-edamame",
        "claude_code" => "claude-code-edamame",
        _ => return None,
    };

    #[cfg(target_os = "macos")]
    {
        Some(
            home.join("Library/Application Support")
                .join(slug)
                .join("state"),
        )
    }
    #[cfg(target_os = "windows")]
    {
        dirs::data_local_dir().map(|d| d.join(slug).join("state"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::env::var("XDG_STATE_HOME")
            .ok()
            .map(|s| PathBuf::from(s).join(slug))
            .or_else(|| Some(home.join(".local/state").join(slug)))
    }
}

fn username_from_home(home: &Path) -> String {
    home.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

pub fn read_package_version(install_path: &Path) -> Option<String> {
    let pkg_path = install_path.join("package.json");
    let content = std::fs::read_to_string(&pkg_path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&content).ok()?;
    v["version"].as_str().map(|s| s.to_string())
}

async fn download_zipball(repo_name: &str) -> anyhow::Result<Vec<u8>> {
    let url = zipball_url(repo_name);
    info!("Downloading {} zipball from {}", repo_name, url);

    let client = reqwest::Client::builder()
        .user_agent("edamame-core/1.0")
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        bail!("GitHub API returned {} for {}", resp.status(), url);
    }

    let bytes = resp.bytes().await?;
    Ok(bytes.to_vec())
}

fn extract_zipball(zip_bytes: &[u8], target_dir: &Path) -> anyhow::Result<()> {
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;

    let prefix = if archive.len() > 0 {
        let first = archive.by_index(0)?.name().to_string();
        if let Some(slash_pos) = first.find('/') {
            first[..=slash_pos].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let raw_name = file.name().to_string();

        let relative = if !prefix.is_empty() && raw_name.starts_with(&prefix) {
            &raw_name[prefix.len()..]
        } else {
            &raw_name
        };

        if relative.is_empty() {
            continue;
        }

        let out_path = target_dir.join(relative);

        if file.is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut outfile = std::fs::File::create(&out_path)?;
            std::io::copy(&mut file, &mut outfile)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(mode))?;
                }
            }
        }
    }

    Ok(())
}

fn resolve_install_script(source_root: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let ps1 = source_root.join("setup").join("install.ps1");
        if ps1.is_file() {
            return Some(ps1);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let sh = source_root.join("setup").join("install.sh");
        if sh.is_file() {
            return Some(sh);
        }
    }
    None
}

/// Resolve the global MCP configuration file that the host IDE reads.
///
/// - Cursor: `~/.cursor/mcp.json`
/// - Claude Code: `~/.claude.json`
fn resolve_global_mcp_config(agent_type: &str, home: &Path) -> Option<PathBuf> {
    match agent_type {
        "cursor" => Some(home.join(".cursor/mcp.json")),
        "claude_code" => Some(home.join(".claude.json")),
        _ => None,
    }
}

const MCP_SERVER_KEY: &str = "edamame";

/// Back up a file to `<path>.bak` before we modify it.  Best-effort: a
/// failure here is logged but does not abort the operation.
fn backup_file(path: &Path) {
    if !path.exists() {
        return;
    }
    let bak = path.with_extension(format!(
        "{}.bak",
        path.extension()
            .unwrap_or_default()
            .to_string_lossy()
    ));
    if let Err(e) = std::fs::copy(path, &bak) {
        warn!(
            "Could not back up {} to {}: {}",
            path.display(),
            bak.display(),
            e
        );
    }
}

/// Inject (upsert) the `"edamame"` MCP server entry into the IDE's global
/// MCP configuration file.  Preserves every other key in the file -- both
/// sibling `mcpServers` entries and any unrelated top-level fields.
///
/// If the file exists but is not valid JSON the function returns an error
/// rather than silently replacing user content with a fresh object.
#[cfg_attr(not(test), allow(dead_code))]
fn inject_mcp_server_entry(
    agent_type: &str,
    home: &Path,
    server_entry: &serde_json::Value,
) -> anyhow::Result<()> {
    let config_path = match resolve_global_mcp_config(agent_type, home) {
        Some(p) => p,
        None => return Ok(()),
    };

    let mut root: serde_json::Value = if config_path.exists() {
        let raw = std::fs::read_to_string(&config_path)?;
        serde_json::from_str(&raw).map_err(|e| {
            anyhow!(
                "Refusing to modify {}: file is not valid JSON ({}). \
                 Fix or remove the file and retry.",
                config_path.display(),
                e
            )
        })?
    } else {
        serde_json::json!({})
    };

    let servers = root
        .as_object_mut()
        .ok_or_else(|| anyhow!("MCP config root is not a JSON object"))?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));

    let servers_map = servers
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcpServers is not a JSON object"))?;

    servers_map.insert(MCP_SERVER_KEY.to_string(), server_entry.clone());

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    backup_file(&config_path);

    let pretty = serde_json::to_string_pretty(&root)?;
    std::fs::write(&config_path, pretty)?;

    info!(
        "Injected '{}' MCP server into {}",
        MCP_SERVER_KEY,
        config_path.display()
    );
    Ok(())
}

/// Remove the `"edamame"` MCP server entry from the IDE's global MCP
/// configuration file.  Preserves every other key -- both sibling
/// `mcpServers` entries and any unrelated top-level fields.  If the entry
/// is already absent, or the file does not exist or is not valid JSON, the
/// function is a no-op.
fn remove_mcp_server_entry(agent_type: &str, home: &Path) -> anyhow::Result<()> {
    let config_path = match resolve_global_mcp_config(agent_type, home) {
        Some(p) => p,
        None => return Ok(()),
    };

    if !config_path.exists() {
        return Ok(());
    }

    let raw = std::fs::read_to_string(&config_path)?;
    let mut root: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let removed = root
        .as_object_mut()
        .and_then(|obj| obj.get_mut("mcpServers"))
        .and_then(|s| s.as_object_mut())
        .map(|servers| servers.remove(MCP_SERVER_KEY).is_some())
        .unwrap_or(false);

    if removed {
        backup_file(&config_path);

        let pretty = serde_json::to_string_pretty(&root)?;
        std::fs::write(&config_path, pretty)?;
        info!(
            "Removed '{}' MCP server from {}",
            MCP_SERVER_KEY,
            config_path.display()
        );
    }

    Ok(())
}

async fn install_cursor_or_claude_code(
    agent_type: &str,
    source_root: &Path,
    workspace_root: &str,
    home: &Path,
) -> anyhow::Result<String> {
    let script = resolve_install_script(source_root)
        .ok_or_else(|| anyhow!("No install script found in {}/setup/", source_root.display()))?;

    let username = username_from_home(home);

    let workspace_arg = if workspace_root.is_empty() {
        std::env::current_dir()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    } else {
        workspace_root.to_string()
    };

    #[cfg(target_os = "windows")]
    let cmd = format!(
        "& '{}' -WorkspaceRoot '{}'",
        script.to_string_lossy().replace('\'', "''"),
        workspace_arg.replace('\'', "''"),
    );
    #[cfg(not(target_os = "windows"))]
    let cmd = format!(
        "bash '{}' '{}'",
        script.to_string_lossy().replace('\'', "'\\''"),
        workspace_arg.replace('\'', "'\\''"),
    );

    info!(
        "Delegating {} install to script: {}",
        agent_type,
        script.display()
    );

    let personate = !username.is_empty();
    crate::runner_cli::run_cli(&cmd, &username, personate, Some(120)).await?;

    let data_dir = data_dir_for_home(home);
    let install_path = resolve_install_path_with_home(agent_type, home, &data_dir)
        .ok_or_else(|| anyhow!("Cannot resolve install path for {}", agent_type))?;

    let version = read_package_version(&install_path).unwrap_or_else(|| "unknown".to_string());

    // The install script runs as root (helper daemon) with personate only setting
    // env vars -- the process uid is still 0.  All created directories end up
    // root-owned.  Chown the entire plugin tree back to the target user.
    let slug = match agent_type {
        "cursor" => Some("cursor-edamame"),
        "claude_code" => Some("claude-code-edamame"),
        _ => None,
    };
    if let Some(slug) = slug {
        let top_dir = data_dir.join(slug);
        if top_dir.exists() {
            chown_to_home_owner(&top_dir, home)?;
        }
    }

    if let Some(global_mcp) = resolve_global_mcp_config(agent_type, home) {
        chown_to_home_owner(&global_mcp, home)?;
    }

    Ok(version)
}

fn install_openclaw(source_root: &Path, home: &Path) -> anyhow::Result<String> {
    let openclaw_dir = home.join(".openclaw");

    let ext_dst = openclaw_dir.join("extensions/edamame");
    let skill_ex_dst = openclaw_dir.join("skills/edamame-extrapolator");
    let skill_posture_dst = openclaw_dir.join("skills/edamame-posture");
    let meta_dst = openclaw_dir.join("edamame-openclaw");
    let state_dst = meta_dst.join("state");

    std::fs::create_dir_all(&ext_dst)?;
    std::fs::create_dir_all(&skill_ex_dst)?;
    std::fs::create_dir_all(&skill_posture_dst)?;
    std::fs::create_dir_all(&meta_dst)?;
    std::fs::create_dir_all(&state_dst)?;

    let plugin_src = source_root.join("extensions/edamame");
    for name in &["openclaw.plugin.json", "index.ts"] {
        let src = plugin_src.join(name);
        if src.is_file() {
            std::fs::copy(&src, ext_dst.join(name))?;
        }
    }

    let ex_skill = source_root.join("skill/edamame-extrapolator/SKILL.md");
    if ex_skill.is_file() {
        std::fs::copy(&ex_skill, skill_ex_dst.join("SKILL.md"))?;
    }

    let posture_skill = source_root.join("skill/edamame-posture/SKILL.md");
    if posture_skill.is_file() {
        std::fs::copy(&posture_skill, skill_posture_dst.join("SKILL.md"))?;
    }

    let pkg_src = source_root.join("package.json");
    if pkg_src.is_file() {
        std::fs::copy(&pkg_src, meta_dst.join("package.json"))?;
    }

    let version = read_package_version(&meta_dst).unwrap_or_else(|| "unknown".to_string());

    match StdCommand::new("openclaw")
        .args(["plugins", "enable", "edamame"])
        .output()
    {
        Ok(out) if out.status.success() => {
            info!("Enabled OpenClaw edamame plugin via CLI");
        }
        Ok(out) => {
            warn!(
                "openclaw plugins enable edamame exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => {
            info!("openclaw CLI not on PATH, skipping plugin enable: {}", e);
        }
    }

    // Chown after `openclaw plugins enable` which may rewrite openclaw.json as root
    chown_to_home_owner(&openclaw_dir, home)?;

    Ok(version)
}

/// Full provisioning: download from GitHub, extract, install. Uses the real
/// (unsandboxed) home directory by default. Pass `user_home_override` when
/// running as root in the helper to target the correct user directory.
pub async fn provision_agent_plugin(
    agent_type: &str,
    workspace_root: &str,
    user_home_override: Option<&Path>,
) -> AgentPluginProvisionResult {
    let def = match find_plugin_def(agent_type) {
        Some(d) => d,
        None => {
            return AgentPluginProvisionResult {
                success: false,
                agent_type: agent_type.to_string(),
                version: String::new(),
                install_path: String::new(),
                message: format!(
                    "Unknown agent type '{}'. Valid types: cursor, claude_code, openclaw",
                    agent_type
                ),
            };
        }
    };

    let home = match user_home_override {
        Some(h) => h.to_path_buf(),
        None => match real_home_dir() {
            Some(h) => h,
            None => {
                return AgentPluginProvisionResult {
                    success: false,
                    agent_type: agent_type.to_string(),
                    version: String::new(),
                    install_path: String::new(),
                    message: "Cannot resolve home directory".to_string(),
                };
            }
        },
    };

    info!(
        "Provisioning {} from GitHub (HTTP zipball)",
        def.display_name
    );

    let zip_bytes = match download_zipball(def.repo_name).await {
        Ok(b) => b,
        Err(e) => {
            return AgentPluginProvisionResult {
                success: false,
                agent_type: agent_type.to_string(),
                version: String::new(),
                install_path: String::new(),
                message: format!("Failed to download from GitHub: {}", e),
            };
        }
    };

    info!(
        "Downloaded {} bytes for {}, extracting...",
        zip_bytes.len(),
        def.display_name
    );

    let tmp_base = std::env::temp_dir().join(format!("edamame-provision-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&tmp_base) {
        return AgentPluginProvisionResult {
            success: false,
            agent_type: agent_type.to_string(),
            version: String::new(),
            install_path: String::new(),
            message: format!("Failed to create temp directory: {}", e),
        };
    }
    let extract_dir = tmp_base.join(def.repo_name);

    if let Err(e) = extract_zipball(&zip_bytes, &extract_dir) {
        let _ = std::fs::remove_dir_all(&tmp_base);
        return AgentPluginProvisionResult {
            success: false,
            agent_type: agent_type.to_string(),
            version: String::new(),
            install_path: String::new(),
            message: format!("Failed to extract zipball: {}", e),
        };
    }

    let result = match agent_type {
        "openclaw" => install_openclaw(&extract_dir, &home),
        _ => {
            install_cursor_or_claude_code(agent_type, &extract_dir, workspace_root, &home).await
        }
    };

    let _ = std::fs::remove_dir_all(&tmp_base);

    match result {
        Ok(version) => {
            let data_dir = data_dir_for_home(&home);
            let install_path =
                resolve_install_path_with_home(agent_type, &home, &data_dir).unwrap_or_default();
            info!("Successfully provisioned {} v{}", def.display_name, version);
            AgentPluginProvisionResult {
                success: true,
                agent_type: agent_type.to_string(),
                version,
                install_path: install_path.to_string_lossy().to_string(),
                message: format!("{} installed successfully", def.display_name),
            }
        }
        Err(e) => AgentPluginProvisionResult {
            success: false,
            agent_type: agent_type.to_string(),
            version: String::new(),
            install_path: String::new(),
            message: format!("Installation failed: {}", e),
        },
    }
}

/// Get the status of a specific agent plugin.
pub fn get_agent_plugin_status(agent_type: &str) -> AgentPluginStatus {
    let def = match find_plugin_def(agent_type) {
        Some(d) => d,
        None => {
            return AgentPluginStatus {
                agent_type: agent_type.to_string(),
                installed: false,
                version: String::new(),
                install_path: String::new(),
                repo_url: String::new(),
            };
        }
    };

    let install_path = resolve_install_path(agent_type).unwrap_or_default();
    let version = read_package_version(&install_path).unwrap_or_default();
    let installed = !version.is_empty();

    AgentPluginStatus {
        agent_type: agent_type.to_string(),
        installed,
        version,
        install_path: install_path.to_string_lossy().to_string(),
        repo_url: repo_url(def.repo_name),
    }
}

/// Get status using an explicit home directory (for the helper).
pub fn get_agent_plugin_status_for_home(agent_type: &str, home: &Path) -> AgentPluginStatus {
    let def = match find_plugin_def(agent_type) {
        Some(d) => d,
        None => {
            return AgentPluginStatus {
                agent_type: agent_type.to_string(),
                installed: false,
                version: String::new(),
                install_path: String::new(),
                repo_url: String::new(),
            };
        }
    };

    let data_dir = data_dir_for_home(home);
    let install_path =
        resolve_install_path_with_home(agent_type, home, &data_dir).unwrap_or_default();
    let version = read_package_version(&install_path).unwrap_or_default();
    let installed = !version.is_empty();

    AgentPluginStatus {
        agent_type: agent_type.to_string(),
        installed,
        version,
        install_path: install_path.to_string_lossy().to_string(),
        repo_url: repo_url(def.repo_name),
    }
}

/// List all agent plugins.
pub fn list_agent_plugins() -> Vec<AgentPluginStatus> {
    AGENT_PLUGINS
        .iter()
        .map(|def| get_agent_plugin_status(def.agent_type))
        .collect()
}

/// List all agent plugins using an explicit home directory (for the helper).
pub fn list_agent_plugins_for_home(home: &Path) -> Vec<AgentPluginStatus> {
    AGENT_PLUGINS
        .iter()
        .map(|def| get_agent_plugin_status_for_home(def.agent_type, home))
        .collect()
}

/// Uninstall an agent plugin by removing all installed files, config, state, and pairing data.
pub fn uninstall_agent_plugin(
    agent_type: &str,
    user_home_override: Option<&Path>,
) -> AgentPluginUninstallResult {
    let def = match find_plugin_def(agent_type) {
        Some(d) => d,
        None => {
            return AgentPluginUninstallResult {
                success: false,
                agent_type: agent_type.to_string(),
                message: format!(
                    "Unknown agent type '{}'. Valid types: cursor, claude_code, openclaw",
                    agent_type
                ),
            };
        }
    };

    let home = match user_home_override {
        Some(h) => h.to_path_buf(),
        None => match real_home_dir() {
            Some(h) => h,
            None => {
                return AgentPluginUninstallResult {
                    success: false,
                    agent_type: agent_type.to_string(),
                    message: "Cannot resolve home directory".to_string(),
                };
            }
        },
    };

    info!("Uninstalling {}", def.display_name);

    let result = match agent_type {
        "openclaw" => uninstall_openclaw(&home),
        _ => uninstall_cursor_or_claude_code(agent_type, &home),
    };

    match result {
        Ok(()) => {
            info!("Successfully uninstalled {}", def.display_name);
            AgentPluginUninstallResult {
                success: true,
                agent_type: agent_type.to_string(),
                message: format!("{} uninstalled successfully", def.display_name),
            }
        }
        Err(e) => AgentPluginUninstallResult {
            success: false,
            agent_type: agent_type.to_string(),
            message: format!("Uninstall failed: {}", e),
        },
    }
}

/// Uninstall using an explicit home directory (for the helper running as root).
pub fn uninstall_agent_plugin_for_home(
    agent_type: &str,
    home: &Path,
) -> AgentPluginUninstallResult {
    uninstall_agent_plugin(agent_type, Some(home))
}

fn uninstall_cursor_or_claude_code(agent_type: &str, home: &Path) -> anyhow::Result<()> {
    if let Err(e) = remove_mcp_server_entry(agent_type, home) {
        warn!(
            "Could not remove MCP server entry from {} global config: {}",
            agent_type, e
        );
    }

    let data_dir = data_dir_for_home(home);
    let slug = match agent_type {
        "cursor" => "cursor-edamame",
        "claude_code" => "claude-code-edamame",
        _ => bail!("Unsupported agent type for uninstall: {}", agent_type),
    };

    let top_dir = data_dir.join(slug);
    if top_dir.exists() {
        info!("Removing {}", top_dir.display());
        std::fs::remove_dir_all(&top_dir)?;
    } else {
        info!("Nothing to remove at {}", top_dir.display());
    }

    if let Some(config_dir) = resolve_config_dir_with_home(agent_type, home) {
        if config_dir != top_dir && config_dir.exists() {
            info!("Removing config dir {}", config_dir.display());
            std::fs::remove_dir_all(&config_dir)?;
        }
    }
    if let Some(state_dir) = resolve_state_dir_with_home(agent_type, home) {
        if state_dir != top_dir && state_dir.exists() {
            info!("Removing state dir {}", state_dir.display());
            std::fs::remove_dir_all(&state_dir)?;
        }
    }

    Ok(())
}

fn uninstall_openclaw(home: &Path) -> anyhow::Result<()> {
    match StdCommand::new("openclaw")
        .args(["plugins", "disable", "edamame"])
        .output()
    {
        Ok(out) if out.status.success() => {
            info!("Disabled OpenClaw edamame plugin via CLI");
        }
        Ok(out) => {
            warn!(
                "openclaw plugins disable edamame exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => {
            info!("openclaw CLI not on PATH, skipping plugin disable: {}", e);
        }
    }

    let openclaw_dir = home.join(".openclaw");

    // Chown after `openclaw plugins disable` which may rewrite openclaw.json as root
    chown_to_home_owner(&openclaw_dir, home)?;

    let dirs_to_remove = [
        openclaw_dir.join("extensions/edamame"),
        openclaw_dir.join("skills/edamame-extrapolator"),
        openclaw_dir.join("skills/edamame-posture"),
        openclaw_dir.join("edamame-openclaw"),
    ];
    for dir in &dirs_to_remove {
        if dir.exists() {
            info!("Removing {}", dir.display());
            std::fs::remove_dir_all(dir)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_type_to_repo_mapping() {
        assert!(find_plugin_def("cursor").is_some());
        assert!(find_plugin_def("claude_code").is_some());
        assert!(find_plugin_def("openclaw").is_some());
        assert!(find_plugin_def("invalid").is_none());
    }

    #[test]
    fn test_install_path_resolution() {
        let cursor_path = resolve_install_path("cursor");
        assert!(cursor_path.is_some());
        assert!(cursor_path
            .unwrap()
            .to_string_lossy()
            .contains("cursor-edamame"));

        let claude_path = resolve_install_path("claude_code");
        assert!(claude_path.is_some());
        assert!(claude_path
            .unwrap()
            .to_string_lossy()
            .contains("claude-code-edamame"));

        let openclaw_path = resolve_install_path("openclaw");
        assert!(openclaw_path.is_some());
        assert!(openclaw_path
            .unwrap()
            .to_string_lossy()
            .contains(".openclaw/edamame-openclaw"));
    }

    #[test]
    fn test_paths_are_not_sandboxed() {
        let cursor_str = resolve_install_path("cursor")
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(
            !cursor_str.contains("Library/Containers"),
            "cursor install path must not be inside App Sandbox container: {}",
            cursor_str
        );
    }

    #[test]
    fn test_status_serialization() {
        let status = AgentPluginStatus {
            agent_type: "cursor".to_string(),
            installed: true,
            version: "1.0.0".to_string(),
            install_path: "/tmp/test".to_string(),
            repo_url: "https://github.com/test/test".to_string(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: AgentPluginStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_type, "cursor");
        assert!(parsed.installed);
    }

    #[test]
    fn test_provision_result_serialization() {
        let result = AgentPluginProvisionResult {
            success: true,
            agent_type: "cursor".to_string(),
            version: "1.2.3".to_string(),
            install_path: "/tmp/test".to_string(),
            message: "OK".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: AgentPluginProvisionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "1.2.3");
    }

    #[test]
    fn test_extract_zipball_basic() {
        let tmp = std::env::temp_dir().join("edamame-foundation-test-zip");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);

        let buf = Vec::new();
        let w = std::io::Cursor::new(buf);
        let mut zip_writer = zip::ZipWriter::new(w);
        let options = zip::write::SimpleFileOptions::default();
        zip_writer
            .start_file("prefix-abc123/package.json", options)
            .unwrap();
        std::io::Write::write_all(&mut zip_writer, br#"{"name":"test","version":"1.0.0"}"#)
            .unwrap();
        let cursor = zip_writer.finish().unwrap();
        let zip_bytes = cursor.into_inner();

        extract_zipball(&zip_bytes, &tmp).unwrap();
        assert!(tmp.join("package.json").exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_resolve_global_mcp_config() {
        let home = PathBuf::from("/home/testuser");
        assert_eq!(
            resolve_global_mcp_config("cursor", &home),
            Some(PathBuf::from("/home/testuser/.cursor/mcp.json"))
        );
        assert_eq!(
            resolve_global_mcp_config("claude_code", &home),
            Some(PathBuf::from("/home/testuser/.claude.json"))
        );
        assert_eq!(resolve_global_mcp_config("openclaw", &home), None);
    }

    #[test]
    fn test_inject_mcp_server_creates_file() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-inject-create");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".cursor")).unwrap();

        let entry = serde_json::json!({
            "type": "stdio",
            "command": "/usr/bin/node",
            "args": ["bridge.mjs"]
        });

        inject_mcp_server_entry("cursor", &tmp, &entry).unwrap();

        let config_path = tmp.join(".cursor/mcp.json");
        assert!(config_path.exists());

        let raw = std::fs::read_to_string(&config_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["mcpServers"]["edamame"]["command"], "/usr/bin/node");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_inject_mcp_server_preserves_existing() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-inject-preserve");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".cursor")).unwrap();

        let existing = serde_json::json!({
            "mcpServers": {
                "other-server": {
                    "command": "other-cmd",
                    "args": ["--flag"]
                }
            }
        });
        std::fs::write(
            tmp.join(".cursor/mcp.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        let entry = serde_json::json!({
            "type": "stdio",
            "command": "/usr/bin/node",
            "args": ["bridge.mjs"]
        });

        inject_mcp_server_entry("cursor", &tmp, &entry).unwrap();

        let raw = std::fs::read_to_string(tmp.join(".cursor/mcp.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["mcpServers"]["edamame"]["command"], "/usr/bin/node");
        assert_eq!(parsed["mcpServers"]["other-server"]["command"], "other-cmd");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_remove_mcp_server_entry() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-remove");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".cursor")).unwrap();

        let existing = serde_json::json!({
            "mcpServers": {
                "edamame": { "command": "node", "args": ["bridge.mjs"] },
                "other": { "command": "other" }
            }
        });
        std::fs::write(
            tmp.join(".cursor/mcp.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        remove_mcp_server_entry("cursor", &tmp).unwrap();

        let raw = std::fs::read_to_string(tmp.join(".cursor/mcp.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(parsed["mcpServers"].get("edamame").is_none());
        assert_eq!(parsed["mcpServers"]["other"]["command"], "other");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_remove_mcp_server_missing_file() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-remove-missing");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let result = remove_mcp_server_entry("cursor", &tmp);
        assert!(result.is_ok());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_inject_refuses_malformed_json() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-malformed");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".cursor")).unwrap();

        std::fs::write(tmp.join(".cursor/mcp.json"), "not valid json {{{").unwrap();

        let entry = serde_json::json!({ "command": "node" });
        let result = inject_mcp_server_entry("cursor", &tmp, &entry);
        assert!(result.is_err(), "Should refuse to overwrite malformed JSON");

        let raw = std::fs::read_to_string(tmp.join(".cursor/mcp.json")).unwrap();
        assert_eq!(raw, "not valid json {{{", "Original content must be preserved");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_remove_noop_on_malformed_json() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-remove-malformed");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".cursor")).unwrap();

        std::fs::write(tmp.join(".cursor/mcp.json"), "broken json").unwrap();

        let result = remove_mcp_server_entry("cursor", &tmp);
        assert!(result.is_ok(), "Should be a silent no-op");

        let raw = std::fs::read_to_string(tmp.join(".cursor/mcp.json")).unwrap();
        assert_eq!(raw, "broken json", "Original content must be preserved");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_inject_preserves_top_level_keys() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-toplevel");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let existing = serde_json::json!({
            "oauthTokens": { "service": "tok_abc" },
            "sessionCache": [1, 2, 3],
            "mcpServers": {
                "other": { "command": "other-bin" }
            }
        });
        std::fs::write(
            tmp.join(".claude.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        let entry = serde_json::json!({ "command": "node", "args": ["bridge.mjs"] });
        inject_mcp_server_entry("claude_code", &tmp, &entry).unwrap();

        let raw = std::fs::read_to_string(tmp.join(".claude.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["oauthTokens"]["service"], "tok_abc");
        assert_eq!(parsed["sessionCache"][0], 1);
        assert_eq!(parsed["mcpServers"]["other"]["command"], "other-bin");
        assert_eq!(parsed["mcpServers"]["edamame"]["command"], "node");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_remove_preserves_top_level_keys() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-remove-toplevel");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let existing = serde_json::json!({
            "oauthTokens": { "service": "tok_xyz" },
            "mcpServers": {
                "edamame": { "command": "node" },
                "other": { "command": "other-bin" }
            }
        });
        std::fs::write(
            tmp.join(".claude.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        remove_mcp_server_entry("claude_code", &tmp).unwrap();

        let raw = std::fs::read_to_string(tmp.join(".claude.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["oauthTokens"]["service"], "tok_xyz");
        assert!(parsed["mcpServers"].get("edamame").is_none());
        assert_eq!(parsed["mcpServers"]["other"]["command"], "other-bin");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_inject_creates_backup() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-backup-inject");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".cursor")).unwrap();

        let original = serde_json::json!({ "mcpServers": {} });
        std::fs::write(
            tmp.join(".cursor/mcp.json"),
            serde_json::to_string_pretty(&original).unwrap(),
        )
        .unwrap();

        let entry = serde_json::json!({ "command": "node" });
        inject_mcp_server_entry("cursor", &tmp, &entry).unwrap();

        assert!(
            tmp.join(".cursor/mcp.json.bak").exists(),
            "Backup should be created before modifying existing file"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_remove_creates_backup() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-backup-remove");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".cursor")).unwrap();

        let existing = serde_json::json!({
            "mcpServers": { "edamame": { "command": "node" } }
        });
        std::fs::write(
            tmp.join(".cursor/mcp.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        remove_mcp_server_entry("cursor", &tmp).unwrap();

        assert!(
            tmp.join(".cursor/mcp.json.bak").exists(),
            "Backup should be created before modifying existing file"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_remove_noop_when_key_absent() {
        let tmp = std::env::temp_dir().join("edamame-test-mcp-remove-absent");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join(".cursor")).unwrap();

        let existing = serde_json::json!({
            "mcpServers": { "other": { "command": "other-bin" } }
        });
        let original_json = serde_json::to_string_pretty(&existing).unwrap();
        std::fs::write(tmp.join(".cursor/mcp.json"), &original_json).unwrap();

        remove_mcp_server_entry("cursor", &tmp).unwrap();

        let raw = std::fs::read_to_string(tmp.join(".cursor/mcp.json")).unwrap();
        assert_eq!(raw, original_json, "File must not be rewritten when key is absent");
        assert!(
            !tmp.join(".cursor/mcp.json.bak").exists(),
            "No backup when nothing changed"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
