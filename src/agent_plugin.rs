use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::agent_plugin_icons::{
    CLAUDE_CODE_ICON_BASE64, CLAUDE_DESKTOP_ICON_BASE64, CODEX_ICON_SVG_BASE64, CURSOR_ICON_BASE64,
    HERMES_ICON_SVG_BASE64, OPENCLAW_ICON_BASE64,
};
use crate::supported_agents::{self, SupportedAgentDefinition};

const GITHUB_ORG: &str = "edamametechnologies";

/// Directory name of EDAMAME's own OpenClaw extension under
/// `~/.openclaw/extensions/`, and the `id` its `openclaw.plugin.json` declares.
///
/// OpenClaw has no `mcpServers` config map, so this is the only way to tell our
/// own bridge apart from a third-party extension when building the MCP
/// inventory (see `agent_visibility::discover_openclaw_extension_endpoints`).
/// Must stay in sync with `edamame_openclaw/setup/install.{sh,ps1}`.
pub const OPENCLAW_EDAMAME_EXTENSION_ID: &str = "edamame";

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

pub fn read_package_version(install_path: &Path) -> Option<String> {
    let pkg_path = install_path.join("package.json");
    let content = std::fs::read_to_string(&pkg_path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&content).ok()?;
    v["version"].as_str().map(|s| s.to_string())
}

/// Embedded brand icon payload (base64, mime) for a supported agent type, or
/// `None` for an unknown type. This is the compiled-in fallback the real
/// status path uses when an installed bundle icon is absent, and it is also the
/// single source of truth for the demo-mode plugin list so screenshots render
/// the same brand glyphs as the live app.
pub fn embedded_icon_payload(agent_type: &str) -> Option<(String, String)> {
    // The mime MUST match the embedded bytes' actual format: cursor/openclaw
    // are PNG, claude_code/claude_desktop are JPEG, codex/hermes are SVG
    // source. The app's AgentPluginIcon only branches on `image/svg+xml`
    // (SvgPicture vs Image.memory), but an accurate mime keeps the API
    // contract honest for any future consumer.
    let (base64, mime) = match agent_type {
        "cursor" => (CURSOR_ICON_BASE64, "image/png"),
        "claude_code" => (CLAUDE_CODE_ICON_BASE64, "image/jpeg"),
        "claude_desktop" => (CLAUDE_DESKTOP_ICON_BASE64, "image/jpeg"),
        "openclaw" => (OPENCLAW_ICON_BASE64, "image/png"),
        "codex" => (CODEX_ICON_SVG_BASE64, "image/svg+xml"),
        "hermes" => (HERMES_ICON_SVG_BASE64, "image/svg+xml"),
        _ => return None,
    };
    Some((base64.to_string(), mime.to_string()))
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

fn registry_entry_from_definition(definition: &AgentPluginDef) -> AgentPluginStatus {
    let icon_payload = embedded_icon_payload(&definition.agent_type).or_else(|| {
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
        installed: false,
        version: String::new(),
        install_path: String::new(),
        repo_url: repo_url(&definition.repo_name),
        strategy_kind: definition.strategy_kind.clone(),
        sort_order: definition.sort_order,
        icon_base64,
        icon_mime_type,
    }
}

/// Read-only supported-agent registry metadata for UI surfaces (icons,
/// display names, sort order). Does not probe on-disk plugin installs.
pub fn list_agent_registry() -> Vec<AgentPluginStatus> {
    supported_agents::ordered_supported_agents()
        .iter()
        .map(registry_entry_from_definition)
        .collect()
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

    /// Every supported agent type MUST have an embedded icon payload so the UI
    /// never renders a blank/fallback glyph when the registry SVG file is
    /// absent in production (the regression that left codex/hermes iconless).
    /// PNG agents declare `image/png` with the PNG magic; codex/hermes declare
    /// `image/svg+xml` and decode to SVG source.
    #[test]
    fn test_embedded_icon_payload_present_for_all_agents() {
        for agent in ["cursor", "openclaw"] {
            let (b64, mime) =
                embedded_icon_payload(agent).unwrap_or_else(|| panic!("{agent} icon missing"));
            assert_eq!(mime, "image/png", "{agent} must be png");
            let bytes = BASE64_STANDARD
                .decode(&b64)
                .unwrap_or_else(|_| panic!("{agent} icon must base64-decode"));
            assert!(
                bytes.starts_with(&[0x89, b'P', b'N', b'G']),
                "{agent} payload must be a PNG"
            );
        }
        for agent in ["claude_code", "claude_desktop"] {
            let (b64, mime) =
                embedded_icon_payload(agent).unwrap_or_else(|| panic!("{agent} icon missing"));
            assert_eq!(mime, "image/jpeg", "{agent} must be jpeg");
            let bytes = BASE64_STANDARD
                .decode(&b64)
                .unwrap_or_else(|_| panic!("{agent} icon must base64-decode"));
            assert!(
                bytes.starts_with(&[0xFF, 0xD8, 0xFF]),
                "{agent} payload must be a JPEG"
            );
        }
        for agent in ["codex", "hermes"] {
            let (b64, mime) =
                embedded_icon_payload(agent).unwrap_or_else(|| panic!("{agent} icon missing"));
            assert_eq!(mime, "image/svg+xml", "{agent} must be svg");
            let bytes = BASE64_STANDARD
                .decode(&b64)
                .unwrap_or_else(|_| panic!("{agent} icon must base64-decode"));
            let svg = String::from_utf8(bytes).expect("svg payload must be utf-8");
            assert!(svg.contains("<svg"), "{agent} payload must be SVG source");
        }
        assert!(
            embedded_icon_payload("not_an_agent").is_none(),
            "unknown agent must have no embedded payload"
        );
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
}
