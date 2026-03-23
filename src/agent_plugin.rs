use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use tracing::{info, warn};

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
        dirs::config_dir().map(|c| c.join(slug))
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

fn find_executable(name: &str) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let output = StdCommand::new("where").arg(name).output().ok()?;
    #[cfg(not(target_os = "windows"))]
    let output = StdCommand::new("which").arg(name).output().ok()?;

    if output.status.success() {
        let path_str = String::from_utf8(output.stdout).ok()?;
        let first_line = path_str.lines().next()?;
        Some(PathBuf::from(first_line.trim()))
    } else {
        None
    }
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

fn copy_dir_recursive(src: &Path, dst: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn copy_dir_if_exists(source_root: &Path, install_root: &Path, dir_name: &str) {
    let src = source_root.join(dir_name);
    if src.is_dir() {
        let dst = install_root.join(dir_name);
        if let Err(e) = copy_dir_recursive(&src, &dst) {
            warn!("Failed to copy {}: {}", dir_name, e);
        }
    }
}

fn copy_file_if_exists(source_root: &Path, install_root: &Path, file_name: &str) {
    let src = source_root.join(file_name);
    if src.is_file() {
        let dst = install_root.join(file_name);
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::copy(&src, &dst) {
            warn!("Failed to copy {}: {}", file_name, e);
        }
    }
}

fn render_template(src: &Path, dst: &Path, replacements: &[(&str, &str)]) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(src)?;
    let mut rendered = content;
    for (placeholder, value) in replacements {
        rendered = rendered.replace(placeholder, value);
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(dst, rendered)?;
    Ok(())
}

fn portable_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn compute_agent_instance_id(workspace_root: &str) -> String {
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| {
            StdCommand::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });
    let hash = format!("{:x}", md5::compute(workspace_root.as_bytes()));
    format!("{}-{}", hostname, &hash[..12.min(hash.len())])
}

fn install_cursor_or_claude_code(
    agent_type: &str,
    source_root: &Path,
    workspace_root: &str,
    home: &Path,
) -> anyhow::Result<String> {
    let data_dir = data_dir_for_home(home);
    let install_path = resolve_install_path_with_home(agent_type, home, &data_dir)
        .ok_or_else(|| anyhow!("Cannot resolve install path for {}", agent_type))?;
    let config_dir = resolve_config_dir_with_home(agent_type, home)
        .ok_or_else(|| anyhow!("Cannot resolve config dir for {}", agent_type))?;
    let state_dir = resolve_state_dir_with_home(agent_type, home)
        .ok_or_else(|| anyhow!("Cannot resolve state dir for {}", agent_type))?;

    let rendered_dir = config_dir.join("rendered");

    std::fs::create_dir_all(&config_dir)?;
    std::fs::create_dir_all(&state_dir)?;
    std::fs::create_dir_all(&rendered_dir)?;

    if install_path.exists() {
        std::fs::remove_dir_all(&install_path)?;
    }
    std::fs::create_dir_all(&install_path)?;

    let dirs_to_copy = [
        "bridge",
        "adapters",
        "prompts",
        "scheduler",
        "service",
        "docs",
        "tests",
        "setup",
        "agents",
        "assets",
        "skills",
    ];
    for dir_name in &dirs_to_copy {
        copy_dir_if_exists(source_root, &install_path, dir_name);
    }

    copy_file_if_exists(source_root, &install_path, "package.json");
    copy_file_if_exists(source_root, &install_path, "README.md");

    if agent_type == "cursor" {
        copy_dir_if_exists(source_root, &install_path, ".cursor-plugin");
        copy_file_if_exists(source_root, &install_path, ".mcp.json");
        copy_dir_if_exists(source_root, &install_path, "rules");
        copy_dir_if_exists(source_root, &install_path, "commands");
    } else {
        copy_dir_if_exists(source_root, &install_path, ".claude-plugin");
        copy_file_if_exists(source_root, &install_path, ".mcp.json");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir_name in &["bridge", "service", "setup"] {
            let dir = install_path.join(dir_name);
            if dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let name = path.file_name().unwrap_or_default().to_string_lossy();
                        if name.ends_with(".mjs") || name.ends_with(".sh") {
                            let _ = std::fs::set_permissions(
                                &path,
                                std::fs::Permissions::from_mode(0o755),
                            );
                        }
                    }
                }
            }
        }
    }

    let workspace_path = PathBuf::from(if workspace_root.is_empty() {
        std::env::current_dir()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    } else {
        workspace_root.to_string()
    });

    let node_bin = find_executable("node")
        .map(|p| portable_path(&p))
        .unwrap_or_else(|| "node".to_string());

    let instance_id = compute_agent_instance_id(&workspace_path.to_string_lossy());
    let workspace_basename = workspace_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let psk_path = state_dir.join("edamame-mcp.psk");

    let host_kind = if cfg!(target_os = "linux") {
        "edamame_posture"
    } else {
        "edamame_app"
    };
    let posture_cli = if cfg!(target_os = "linux") {
        "edamame_posture"
    } else {
        ""
    };

    let replacements: Vec<(&str, String)> = vec![
        ("__PACKAGE_ROOT__", portable_path(&install_path)),
        (
            "__CONFIG_PATH__",
            portable_path(&config_dir.join("config.json")),
        ),
        ("__WORKSPACE_ROOT__", portable_path(&workspace_path)),
        ("__WORKSPACE_BASENAME__", workspace_basename),
        ("__DEFAULT_AGENT_INSTANCE_ID__", instance_id),
        ("__DEFAULT_HOST_KIND__", host_kind.to_string()),
        ("__DEFAULT_POSTURE_CLI_COMMAND__", posture_cli.to_string()),
        ("__STATE_DIR__", portable_path(&state_dir)),
        ("__EDAMAME_MCP_PSK_FILE__", portable_path(&psk_path)),
        ("__NODE_BIN__", node_bin),
    ];

    let replacement_refs: Vec<(&str, &str)> =
        replacements.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let config_path = config_dir.join("config.json");
    if !config_path.exists() {
        let template_name = if agent_type == "cursor" {
            "cursor-edamame-config.template.json"
        } else {
            "claude-code-edamame-config.template.json"
        };
        let template = install_path.join("setup").join(template_name);
        if template.exists() {
            render_template(&template, &config_path, &replacement_refs)?;
        }
    }

    let mcp_template_name = if agent_type == "cursor" {
        "cursor-mcp.template.json"
    } else {
        "claude-code-mcp.template.json"
    };
    let mcp_dest_name = if agent_type == "cursor" {
        "cursor-mcp.json"
    } else {
        "claude-code-mcp.json"
    };
    let mcp_template = install_path.join("setup").join(mcp_template_name);
    let mcp_dest = config_dir.join(mcp_dest_name);
    if mcp_template.exists() {
        render_template(&mcp_template, &mcp_dest, &replacement_refs)?;
    }

    let version = read_package_version(&install_path).unwrap_or_else(|| "unknown".to_string());
    Ok(version)
}

fn install_openclaw(source_root: &Path, home: &Path) -> anyhow::Result<String> {
    let openclaw_dir = home.join(".openclaw");

    let ext_dst = openclaw_dir.join("extensions/edamame");
    let skill_ex_dst = openclaw_dir.join("skills/edamame-extrapolator");
    let skill_posture_dst = openclaw_dir.join("skills/edamame-posture");
    let meta_dst = openclaw_dir.join("edamame-openclaw");

    std::fs::create_dir_all(&ext_dst)?;
    std::fs::create_dir_all(&skill_ex_dst)?;
    std::fs::create_dir_all(&skill_posture_dst)?;
    std::fs::create_dir_all(&meta_dst)?;

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
        _ => install_cursor_or_claude_code(agent_type, &extract_dir, workspace_root, &home),
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
    Ok(())
}

fn uninstall_openclaw(home: &Path) -> anyhow::Result<()> {
    let openclaw_dir = home.join(".openclaw");
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
}
