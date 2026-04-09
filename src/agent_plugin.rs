use anyhow::{anyhow, bail};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use tracing::{info, warn};

use crate::agent_plugin_icons::{
    CLAUDE_CODE_ICON_BASE64, CLAUDE_DESKTOP_ICON_BASE64, CURSOR_ICON_BASE64, OPENCLAW_ICON_BASE64,
};
use crate::supported_agents::{self, SupportedAgentDefinition};

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
        return Err(anyhow!("chown failed for {}: {}", path.display(), err));
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
    pub display_name: String,
    pub description: String,
    pub installed: bool,
    pub version: String,
    pub install_path: String,
    pub repo_url: String,
    pub strategy_kind: String,
    pub sort_order: u32,
    pub icon_base64: String,
    pub icon_mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPluginUninstallResult {
    pub success: bool,
    pub agent_type: String,
    pub message: String,
}

pub type AgentPluginDef = SupportedAgentDefinition;

pub fn find_plugin_def(agent_type: &str) -> Option<AgentPluginDef> {
    supported_agents::find_supported_agent(agent_type)
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
        home.join("AppData/Local")
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
    find_plugin_def(agent_type)?.resolve_install_path_with_home(home, data_dir)
}

pub fn resolve_config_dir(agent_type: &str) -> Option<PathBuf> {
    resolve_config_dir_with_home(agent_type, &real_home_dir()?)
}

pub fn resolve_config_dir_with_home(agent_type: &str, home: &Path) -> Option<PathBuf> {
    find_plugin_def(agent_type)?.resolve_config_dir_with_home(home)
}

pub fn resolve_state_dir(agent_type: &str) -> Option<PathBuf> {
    resolve_state_dir_with_home(agent_type, &real_home_dir()?)
}

pub fn resolve_state_dir_with_home(agent_type: &str, home: &Path) -> Option<PathBuf> {
    find_plugin_def(agent_type)?.resolve_state_dir_with_home(home)
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
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(10))
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
        let canonical_target = target_dir
            .canonicalize()
            .unwrap_or_else(|_| target_dir.to_path_buf());
        let canonical_out = out_path.canonicalize().unwrap_or_else(|_| {
            if let Some(parent) = out_path.parent() {
                let parent_canon = parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf());
                parent_canon.join(out_path.file_name().unwrap_or_default())
            } else {
                out_path.clone()
            }
        });
        if !canonical_out.starts_with(&canonical_target) {
            return Err(anyhow!(
                "Zip entry {:?} would escape target directory (path traversal)",
                relative
            ));
        }

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

fn resolve_install_script(definition: &AgentPluginDef, source_root: &Path) -> Option<PathBuf> {
    if let Some(relpath) = definition.install_script_relpath() {
        let script = source_root.join(relpath);
        if script.is_file() {
            return Some(script);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let fallback = source_root.join("setup").join("install.ps1");
        if fallback.is_file() {
            return Some(fallback);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let fallback = source_root.join("setup").join("install.sh");
        if fallback.is_file() {
            return Some(fallback);
        }
    }

    None
}

/// Resolve the global MCP configuration files that the host IDE reads.
///
/// - Cursor: `~/.cursor/mcp.json`
/// - Claude Code: `~/.claude.json`
/// - Claude Desktop: `~/.claude.json` + the Electron app config
///   (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`,
///    Windows: `%APPDATA%/Claude/claude_desktop_config.json`,
///    Linux: `~/.config/Claude/claude_desktop_config.json`)
fn resolve_global_mcp_configs(agent_type: &str, home: &Path) -> Vec<PathBuf> {
    find_plugin_def(agent_type)
        .map(|definition| definition.resolve_global_mcp_configs(home))
        .unwrap_or_default()
}

fn mcp_server_key(agent_type: &str) -> String {
    find_plugin_def(agent_type)
        .and_then(|definition| definition.mcp_server_key().map(str::to_string))
        .unwrap_or_else(|| "edamame".to_string())
}

/// Back up a file to `<path>.bak` before we modify it.  Best-effort: a
/// failure here is logged but does not abort the operation.
fn backup_file(path: &Path) {
    if !path.exists() {
        return;
    }
    let bak = path.with_extension(format!(
        "{}.bak",
        path.extension().unwrap_or_default().to_string_lossy()
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

#[cfg(test)]
fn inject_mcp_server_entry(
    agent_type: &str,
    home: &Path,
    server_entry: &serde_json::Value,
) -> anyhow::Result<()> {
    let config_paths = resolve_global_mcp_configs(agent_type, home);
    if config_paths.is_empty() {
        return Ok(());
    }
    for config_path in config_paths {
        inject_mcp_server_entry_into_file(agent_type, &config_path, server_entry)?;
    }
    Ok(())
}

#[cfg(test)]
fn inject_mcp_server_entry_into_file(
    agent_type: &str,
    config_path: &Path,
    server_entry: &serde_json::Value,
) -> anyhow::Result<()> {
    let mut root: serde_json::Value = if config_path.exists() {
        let raw = std::fs::read_to_string(config_path)?;
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

    let key = mcp_server_key(agent_type);
    servers_map.insert(key.clone(), server_entry.clone());

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    backup_file(config_path);

    let pretty = serde_json::to_string_pretty(&root)?;
    std::fs::write(config_path, pretty)?;

    info!(
        "Injected '{}' MCP server into {}",
        key,
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
    let config_paths = resolve_global_mcp_configs(agent_type, home);
    for config_path in config_paths {
        remove_mcp_server_entry_from_file(agent_type, &config_path)?;
    }
    Ok(())
}

fn remove_mcp_server_entry_from_file(agent_type: &str, config_path: &Path) -> anyhow::Result<()> {
    if !config_path.exists() {
        return Ok(());
    }

    let raw = std::fs::read_to_string(config_path)?;
    let mut root: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let key = mcp_server_key(agent_type);
    let removed = root
        .as_object_mut()
        .and_then(|obj| obj.get_mut("mcpServers"))
        .and_then(|s| s.as_object_mut())
        .map(|servers| servers.remove(&key).is_some())
        .unwrap_or(false);

    if removed {
        backup_file(config_path);

        let pretty = serde_json::to_string_pretty(&root)?;
        std::fs::write(config_path, pretty)?;
        info!(
            "Removed '{}' MCP server from {}",
            key,
            config_path.display()
        );
    }

    Ok(())
}

/// Build the shell command string for running an install script.
///
/// On Windows the command prepends `Unblock-File` to strip the Zone.Identifier
/// ADS that marks downloaded files as untrusted, then invokes the `.ps1` via
/// PowerShell's call operator (`&`).
///
/// On Unix the command delegates to `bash`.
///
/// `workspace_root` is only forwarded for cursor / claude_code.
fn build_install_command(
    definition: &AgentPluginDef,
    script: &Path,
    workspace_root: &str,
) -> String {
    let workspace_arg = if definition.requires_workspace_arg {
        if workspace_root.is_empty() {
            std::env::current_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        } else {
            workspace_root.to_string()
        }
    } else {
        String::new()
    };

    #[cfg(target_os = "windows")]
    {
        build_install_command_windows(script, definition.requires_workspace_arg, &workspace_arg)
    }
    #[cfg(not(target_os = "windows"))]
    {
        build_install_command_unix(script, definition.requires_workspace_arg, &workspace_arg)
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn build_install_command_windows(
    script: &Path,
    needs_workspace_arg: bool,
    workspace_arg: &str,
) -> String {
    let script_escaped = script.to_string_lossy().replace('\'', "''");
    if needs_workspace_arg {
        format!(
            "Unblock-File -Path '{}'; & '{}' -WorkspaceRoot '{}'",
            script_escaped,
            script_escaped,
            workspace_arg.replace('\'', "''"),
        )
    } else {
        format!(
            "Unblock-File -Path '{}'; & '{}'",
            script_escaped, script_escaped,
        )
    }
}

#[cfg_attr(target_os = "windows", allow(dead_code))]
fn build_install_command_unix(
    script: &Path,
    needs_workspace_arg: bool,
    workspace_arg: &str,
) -> String {
    let script_escaped = script.to_string_lossy().replace('\'', "'\\''");
    if needs_workspace_arg {
        format!(
            "bash '{}' '{}'",
            script_escaped,
            workspace_arg.replace('\'', "'\\''"),
        )
    } else {
        format!("bash '{}'", script_escaped)
    }
}

async fn install_via_script(
    definition: &AgentPluginDef,
    source_root: &Path,
    workspace_root: &str,
    home: &Path,
) -> anyhow::Result<String> {
    let script = resolve_install_script(definition, source_root).ok_or_else(|| {
        anyhow!(
            "No install script found in {}/setup/",
            source_root.display()
        )
    })?;

    let username = username_from_home(home);

    let cmd = build_install_command(definition, &script, workspace_root);

    info!(
        "Delegating {} install to script: {}",
        definition.agent_type,
        script.display()
    );

    let personate = !username.is_empty();
    crate::runner_cli::run_cli(&cmd, &username, personate, Some(120)).await?;

    let data_dir = data_dir_for_home(home);
    let install_path = definition
        .resolve_install_path_with_home(home, &data_dir)
        .ok_or_else(|| anyhow!("Cannot resolve install path for {}", definition.agent_type))?;

    let version = read_package_version(&install_path).unwrap_or_else(|| "unknown".to_string());

    match definition.strategy_kind.as_str() {
        "workstation_stdio_mcp" | "claude_desktop_dual_mcp" => {
            if let Some(top_dir) = install_path.parent() {
                let top_dir = top_dir.to_path_buf();
                if top_dir.exists() {
                    chown_to_home_owner(&top_dir, home)?;
                }
            }
            for global_mcp in definition.resolve_global_mcp_configs(home) {
                chown_to_home_owner(&global_mcp, home)?;
            }
            if let Some(config_dir) = definition.resolve_config_dir_with_home(home) {
                if config_dir.exists() {
                    chown_to_home_owner(&config_dir, home)?;
                }
            }
            if let Some(state_dir) = definition.resolve_state_dir_with_home(home) {
                if state_dir.exists() {
                    chown_to_home_owner(&state_dir, home)?;
                }
            }
        }
        "openclaw_plugin_bundle" => {
            let openclaw_dir = home.join(".openclaw");
            if openclaw_dir.exists() {
                chown_to_home_owner(&openclaw_dir, home)?;
            }
        }
        _ => {}
    }

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
                    "Unknown agent type '{}'. Valid types: {}",
                    agent_type,
                    supported_agents::supported_agent_types_display()
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

    let zip_bytes = match download_zipball(&def.repo_name).await {
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
    let extract_dir = tmp_base.join(&def.repo_name);

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

    let result = install_via_script(&def, &extract_dir, workspace_root, &home).await;

    let _ = std::fs::remove_dir_all(&tmp_base);

    match result {
        Ok(version) => {
            let data_dir = data_dir_for_home(&home);
            let install_path = def
                .resolve_install_path_with_home(&home, &data_dir)
                .unwrap_or_default();
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

fn empty_plugin_status(agent_type: &str) -> AgentPluginStatus {
    AgentPluginStatus {
        agent_type: agent_type.to_string(),
        display_name: agent_type.to_string(),
        description: String::new(),
        installed: false,
        version: String::new(),
        install_path: String::new(),
        repo_url: String::new(),
        strategy_kind: String::new(),
        sort_order: 0,
        icon_base64: String::new(),
        icon_mime_type: String::new(),
    }
}

fn embedded_icon_payload(agent_type: &str) -> Option<(String, String)> {
    let base64 = match agent_type {
        "cursor" => CURSOR_ICON_BASE64,
        "claude_code" => CLAUDE_CODE_ICON_BASE64,
        "claude_desktop" => CLAUDE_DESKTOP_ICON_BASE64,
        "openclaw" => OPENCLAW_ICON_BASE64,
        _ => return None,
    };
    Some((base64.to_string(), "image/png".to_string()))
}

fn encode_icon_file(path: &Path) -> Option<(String, String)> {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("svg") => {
            let svg = std::fs::read_to_string(path).ok()?;
            Some((
                BASE64_STANDARD.encode(svg.as_bytes()),
                "image/svg+xml".to_string(),
            ))
        }
        Some("png") => {
            let bytes = std::fs::read(path).ok()?;
            Some((BASE64_STANDARD.encode(bytes), "image/png".to_string()))
        }
        Some("jpg") | Some("jpeg") => {
            let bytes = std::fs::read(path).ok()?;
            Some((BASE64_STANDARD.encode(bytes), "image/jpeg".to_string()))
        }
        Some("webp") => {
            let bytes = std::fs::read(path).ok()?;
            Some((BASE64_STANDARD.encode(bytes), "image/webp".to_string()))
        }
        _ => {
            let bytes = std::fs::read(path).ok()?;
            Some((
                BASE64_STANDARD.encode(bytes),
                "application/octet-stream".to_string(),
            ))
        }
    }
}

fn status_from_definition(definition: &AgentPluginDef, home: &Path) -> AgentPluginStatus {
    let data_dir = data_dir_for_home(home);
    let install_path = definition
        .resolve_install_path_with_home(home, &data_dir)
        .unwrap_or_default();
    let version = read_package_version(&install_path).unwrap_or_default();
    let installed = !version.is_empty();

    let icon_payload = definition
        .bundle_icon_path(&install_path)
        .filter(|path| path.is_file())
        .and_then(|path| encode_icon_file(&path))
        .or_else(|| embedded_icon_payload(&definition.agent_type))
        .or_else(|| {
            supported_agents::registry_dir()
                .and_then(|registry_dir| definition.registry_icon_path(&registry_dir))
                .filter(|path| path.is_file())
                .and_then(|path| encode_icon_file(&path))
        });

    let (icon_base64, icon_mime_type) = icon_payload.unwrap_or_default();

    AgentPluginStatus {
        agent_type: definition.agent_type.clone(),
        display_name: definition.display_name.clone(),
        description: definition.description.clone(),
        installed,
        version,
        install_path: install_path.to_string_lossy().to_string(),
        repo_url: repo_url(&definition.repo_name),
        strategy_kind: definition.strategy_kind.clone(),
        sort_order: definition.sort_order,
        icon_base64,
        icon_mime_type,
    }
}

/// Get the status of a specific agent plugin.
pub fn get_agent_plugin_status(agent_type: &str) -> AgentPluginStatus {
    let Some(definition) = find_plugin_def(agent_type) else {
        return empty_plugin_status(agent_type);
    };
    let Some(home) = real_home_dir() else {
        return empty_plugin_status(agent_type);
    };
    status_from_definition(&definition, &home)
}

/// Get status using an explicit home directory (for the helper).
pub fn get_agent_plugin_status_for_home(agent_type: &str, home: &Path) -> AgentPluginStatus {
    let Some(definition) = find_plugin_def(agent_type) else {
        return empty_plugin_status(agent_type);
    };
    status_from_definition(&definition, home)
}

/// List all agent plugins.
pub fn list_agent_plugins() -> Vec<AgentPluginStatus> {
    let Some(home) = real_home_dir() else {
        return Vec::new();
    };
    supported_agents::ordered_supported_agents()
        .iter()
        .map(|definition| status_from_definition(definition, &home))
        .collect()
}

/// List all agent plugins using an explicit home directory (for the helper).
pub fn list_agent_plugins_for_home(home: &Path) -> Vec<AgentPluginStatus> {
    supported_agents::ordered_supported_agents()
        .iter()
        .map(|definition| status_from_definition(definition, home))
        .collect()
}

fn resolve_uninstall_script_from_install(
    definition: &AgentPluginDef,
    install_path: &Path,
) -> Option<PathBuf> {
    if let Some(relpath) = definition.uninstall_script_relpath() {
        let script = install_path.join(relpath);
        if script.is_file() {
            return Some(script);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let fallback = install_path.join("setup/uninstall.ps1");
        if fallback.is_file() {
            return Some(fallback);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let fallback = install_path.join("setup/uninstall.sh");
        if fallback.is_file() {
            return Some(fallback);
        }
    }

    None
}

fn run_uninstall_script(script: &Path, home: &Path) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    let output = StdCommand::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(script)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()?;

    #[cfg(not(target_os = "windows"))]
    let output = StdCommand::new("bash")
        .arg(script)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .output()?;

    if output.status.success() {
        return Ok(());
    }

    bail!(
        "uninstall script {} failed with {}: {}",
        script.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn uninstall_via_script(definition: &AgentPluginDef, home: &Path) -> anyhow::Result<()> {
    let data_dir = data_dir_for_home(home);
    let install_path = definition
        .resolve_install_path_with_home(home, &data_dir)
        .ok_or_else(|| anyhow!("Cannot resolve install path for {}", definition.agent_type))?;
    let script = resolve_uninstall_script_from_install(definition, &install_path)
        .ok_or_else(|| anyhow!("No uninstall script found in {}", install_path.display()))?;
    run_uninstall_script(&script, home)
}

fn resolve_healthcheck_script_from_install(install_path: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let wrapper = install_path.join("setup/healthcheck.ps1");
        if wrapper.is_file() {
            return Some(wrapper);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let wrapper = install_path.join("setup/healthcheck.sh");
        if wrapper.is_file() {
            return Some(wrapper);
        }
    }

    None
}

fn run_healthcheck_script(
    script: &Path,
    config_path: Option<&Path>,
    home: &Path,
) -> anyhow::Result<std::process::Output> {
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut cmd = StdCommand::new("powershell");
        cmd.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(script);
        cmd
    };

    #[cfg(not(target_os = "windows"))]
    let mut cmd = {
        let mut cmd = StdCommand::new("bash");
        cmd.arg(script);
        cmd
    };

    cmd.arg("--json").arg("--strict");
    if let Some(config_path) = config_path {
        cmd.arg("--config").arg(config_path);
    }
    cmd.env("HOME", home).env("USERPROFILE", home);
    Ok(cmd.output()?)
}

fn run_healthcheck_node(
    script: &Path,
    config_path: Option<&Path>,
    home: &Path,
) -> anyhow::Result<std::process::Output> {
    let mut cmd = StdCommand::new("node");
    cmd.arg(script).arg("--json").arg("--strict");
    if let Some(config_path) = config_path {
        cmd.arg("--config").arg(config_path);
    }
    cmd.env("HOME", home).env("USERPROFILE", home);
    Ok(cmd.output()?)
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
                    "Unknown agent type '{}'. Valid types: {}",
                    agent_type,
                    supported_agents::supported_agent_types_display()
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

    let result = uninstall_via_script(&def, &home).or_else(|script_error| {
        warn!(
            "Falling back to internal uninstall for {} after script error: {}",
            def.display_name, script_error
        );
        match def.strategy_kind.as_str() {
            "workstation_stdio_mcp" | "claude_desktop_dual_mcp" => {
                uninstall_cursor_or_claude_code(agent_type, &home)
            }
            "openclaw_plugin_bundle" => uninstall_openclaw(&home),
            _ => bail!("No uninstall strategy available for {}", agent_type),
        }
    });

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
        "claude_desktop" => "claude-desktop-edamame",
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

    let agent_id_file = home.join(".edamame_openclaw_agent_instance_id");
    if agent_id_file.exists() {
        info!("Removing {}", agent_id_file.display());
        std::fs::remove_file(&agent_id_file)?;
    }

    Ok(())
}

/// Run the Node.js healthcheck script for an agent plugin.
///
/// Shared implementation used by both standalone core (`#[cfg(feature = "standalone")]`)
/// and the helper daemon (`helper_rx_utility`). Returns a JSON string with the
/// healthcheck result (always valid JSON, never an `Err`).
pub fn run_agent_plugin_healthcheck(agent_type: &str, user_home: &str) -> String {
    let Some(definition) = find_plugin_def(agent_type) else {
        return serde_json::json!({
            "ok": false, "checks": [],
            "message": format!("Unknown or unsupported agent type: {}", agent_type)
        })
        .to_string();
    };

    let home = PathBuf::from(if user_home.is_empty() {
        real_home_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    } else {
        user_home.to_string()
    });

    let data_dir = data_dir_for_home(&home);
    let install_path = match resolve_install_path_with_home(agent_type, &home, &data_dir) {
        Some(p) => p,
        None => {
            return serde_json::json!({
                "ok": false, "checks": [],
                "message": format!("Cannot resolve install path for {}", agent_type)
            })
            .to_string()
        }
    };

    let config_path = resolve_config_dir_with_home(agent_type, &home)
        .map(|config_dir| config_dir.join("config.json"))
        .filter(|path| path.exists());

    let healthcheck_wrapper = resolve_healthcheck_script_from_install(&install_path);
    let healthcheck_script = healthcheck_wrapper
        .clone()
        .unwrap_or_else(|| install_path.join(definition.healthcheck_relpath()));
    if !healthcheck_script.exists() {
        return serde_json::json!({
            "ok": false, "checks": [],
            "message": format!("Healthcheck script not found at {}", healthcheck_script.display())
        })
        .to_string();
    }

    let output = match if healthcheck_wrapper.is_some() {
        info!(
            "Running agent plugin healthcheck wrapper: {} --json --strict",
            healthcheck_script.display()
        );
        run_healthcheck_script(&healthcheck_script, config_path.as_deref(), &home)
    } else {
        info!(
            "Running agent plugin healthcheck: node {} --json --strict",
            healthcheck_script.display()
        );
        run_healthcheck_node(&healthcheck_script, config_path.as_deref(), &home)
    } {
        Ok(o) => o,
        Err(e) => {
            let io_not_found = e
                .downcast_ref::<std::io::Error>()
                .map(|err| err.kind() == std::io::ErrorKind::NotFound)
                .unwrap_or(false);
            let msg = if io_not_found && healthcheck_wrapper.is_some() {
                "healthcheck_runner_not_found".to_string()
            } else if io_not_found {
                "node_not_found".to_string()
            } else {
                format!("Failed to run healthcheck: {}", e)
            };
            return serde_json::json!({"ok": false, "checks": [], "message": msg}).to_string();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stderr.is_empty() {
        info!("Healthcheck stderr: {}", stderr);
    }

    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return serde_json::json!({
            "ok": false, "checks": [],
            "message": format!(
                "Healthcheck produced no output (exit code: {}). stderr: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )
        })
        .to_string();
    }

    if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
        trimmed.to_string()
    } else {
        serde_json::json!({
            "ok": false, "checks": [],
            "message": format!("Healthcheck output is not valid JSON: {}", trimmed)
        })
        .to_string()
    }
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
            display_name: "EDAMAME for Cursor".to_string(),
            description: "Cursor test plugin".to_string(),
            installed: true,
            version: "1.0.0".to_string(),
            install_path: "/tmp/test".to_string(),
            repo_url: "https://github.com/test/test".to_string(),
            strategy_kind: "workstation_stdio_mcp".to_string(),
            sort_order: 10,
            icon_base64: String::new(),
            icon_mime_type: String::new(),
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
            resolve_global_mcp_configs("cursor", &home),
            vec![PathBuf::from("/home/testuser/.cursor/mcp.json")]
        );
        assert_eq!(
            resolve_global_mcp_configs("claude_code", &home),
            vec![PathBuf::from("/home/testuser/.claude.json")]
        );
        assert!(resolve_global_mcp_configs("openclaw", &home).is_empty());
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
        assert_eq!(
            raw, "not valid json {{{",
            "Original content must be preserved"
        );

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
        assert_eq!(parsed["mcpServers"]["edamame-code"]["command"], "node");

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
                "edamame-code": { "command": "node" },
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
        assert!(parsed["mcpServers"].get("edamame-code").is_none());
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
        assert_eq!(
            raw, original_json,
            "File must not be rewritten when key is absent"
        );
        assert!(
            !tmp.join(".cursor/mcp.json.bak").exists(),
            "No backup when nothing changed"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_windows_command_includes_unblock_file() {
        let script = PathBuf::from(r"C:\Users\test\AppData\Local\edamame\setup\install.ps1");
        let cmd = build_install_command_windows(&script, false, "");
        assert!(
            cmd.starts_with("Unblock-File -Path '"),
            "Windows command must start with Unblock-File: {cmd}"
        );
        assert!(
            cmd.contains("; & '"),
            "Windows command must chain Unblock-File before script invocation: {cmd}"
        );
    }

    #[test]
    fn test_windows_command_with_workspace_arg() {
        let script = PathBuf::from(r"C:\tmp\setup\install.ps1");
        let cmd = build_install_command_windows(&script, true, r"C:\Projects\myapp");
        assert!(
            cmd.contains("Unblock-File"),
            "Must include Unblock-File: {cmd}"
        );
        assert!(
            cmd.contains("-WorkspaceRoot 'C:\\Projects\\myapp'"),
            "Must pass workspace root to cursor/claude_code scripts: {cmd}"
        );
    }

    #[test]
    fn test_windows_command_without_workspace_arg() {
        let script = PathBuf::from(r"C:\tmp\setup\install.ps1");
        let cmd = build_install_command_windows(&script, false, "");
        assert!(
            !cmd.contains("-WorkspaceRoot"),
            "Openclaw must not receive workspace arg: {cmd}"
        );
        assert!(
            cmd.ends_with("& 'C:\\tmp\\setup\\install.ps1'"),
            "Must end with script invocation: {cmd}"
        );
    }

    #[test]
    fn test_windows_command_escapes_single_quotes() {
        let script = PathBuf::from(r"C:\User's Dir\setup\install.ps1");
        let cmd = build_install_command_windows(&script, true, r"C:\O'Brien\project");
        assert!(
            cmd.contains("User''s Dir"),
            "Script path single quotes must be doubled: {cmd}"
        );
        assert!(
            cmd.contains("O''Brien"),
            "Workspace arg single quotes must be doubled: {cmd}"
        );
    }

    #[test]
    fn test_unix_command_cursor_with_workspace() {
        let script = PathBuf::from("/tmp/setup/install.sh");
        let cmd = build_install_command_unix(&script, true, "/home/user/project");
        assert_eq!(
            cmd, "bash '/tmp/setup/install.sh' '/home/user/project'",
            "cursor/claude_code must pass workspace arg"
        );
    }

    #[test]
    fn test_unix_command_openclaw_without_workspace() {
        let script = PathBuf::from("/tmp/setup/install.sh");
        let cmd = build_install_command_unix(&script, false, "");
        assert_eq!(
            cmd, "bash '/tmp/setup/install.sh'",
            "openclaw must not pass workspace arg"
        );
    }

    #[test]
    fn test_unix_command_escapes_single_quotes() {
        let script = PathBuf::from("/tmp/user's dir/setup/install.sh");
        let cmd = build_install_command_unix(&script, false, "");
        assert!(
            cmd.contains("user'\\''s dir"),
            "Single quotes in path must be shell-escaped: {cmd}"
        );
    }

    #[test]
    fn test_build_install_command_agent_type_routing() {
        let tmp = std::env::temp_dir().join("edamame-test-cmd-routing");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("setup")).unwrap();

        #[cfg(target_os = "windows")]
        let script_name = "install.ps1";
        #[cfg(not(target_os = "windows"))]
        let script_name = "install.sh";

        let script = tmp.join("setup").join(script_name);
        std::fs::write(&script, "# stub").unwrap();

        let cursor_def = find_plugin_def("cursor").unwrap();
        let openclaw_def = find_plugin_def("openclaw").unwrap();
        let cursor_cmd = build_install_command(&cursor_def, &script, "/workspace");
        let openclaw_cmd = build_install_command(&openclaw_def, &script, "/workspace");

        #[cfg(target_os = "windows")]
        {
            assert!(cursor_cmd.contains("-WorkspaceRoot"));
            assert!(!openclaw_cmd.contains("-WorkspaceRoot"));
            assert!(cursor_cmd.contains("Unblock-File"));
            assert!(openclaw_cmd.contains("Unblock-File"));
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert!(cursor_cmd.contains("/workspace"));
            assert!(!openclaw_cmd.contains("/workspace"));
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_resolve_install_script_finds_correct_script() {
        let tmp = std::env::temp_dir().join("edamame-test-resolve-script");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("setup")).unwrap();
        let cursor_def = find_plugin_def("cursor").unwrap();

        assert!(
            resolve_install_script(&cursor_def, &tmp).is_none(),
            "No script should be found yet"
        );

        #[cfg(target_os = "windows")]
        {
            std::fs::write(tmp.join("setup/install.ps1"), "# stub").unwrap();
            let found = resolve_install_script(&cursor_def, &tmp).unwrap();
            assert!(found.ends_with("install.ps1"));
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::fs::write(tmp.join("setup/install.sh"), "# stub").unwrap();
            let found = resolve_install_script(&cursor_def, &tmp).unwrap();
            assert!(found.ends_with("install.sh"));
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
