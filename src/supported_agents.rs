use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::warn;

const CACHE_TTL: Duration = Duration::from_secs(60);
const DEFAULT_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/edamametechnologies/agent_security/main/supported_agents/index.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedAgentsIndex {
    pub schema_version: u32,
    pub default_agent_type: String,
    pub agents: Vec<SupportedAgentDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedAgentDefinition {
    pub agent_type: String,
    pub display_name: String,
    pub description: String,
    pub repo_name: String,
    pub strategy_kind: String,
    pub sort_order: u32,
    pub requires_workspace_arg: bool,
    pub repo_scripts: AgentRepoScripts,
    pub install_layout: AgentInstallLayout,
    pub mcp: Option<AgentMcpConfig>,
    pub e2e: Option<AgentE2eConfig>,
    pub registry_icon_relpath: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRepoScripts {
    pub install_unix: Option<String>,
    pub install_windows: Option<String>,
    pub uninstall_unix: Option<String>,
    pub uninstall_windows: Option<String>,
    pub healthcheck_relpath: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInstallLayout {
    pub install_base: String,
    pub install_relative_path: String,
    pub config_kind: String,
    pub config_slug: Option<String>,
    pub state_kind: String,
    pub state_slug: Option<String>,
    pub bundle_icon_relpath: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMcpConfig {
    pub server_key: String,
    pub config_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentE2eConfig {
    pub repo_env_var: Option<String>,
    pub intent_script: Option<String>,
    pub intent_timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct LoadedSupportedAgents {
    pub index: SupportedAgentsIndex,
    pub registry_dir: Option<PathBuf>,
    pub source: String,
}

#[derive(Debug, Clone)]
struct CachedRegistry {
    loaded_at: Instant,
    registry: LoadedSupportedAgents,
}

static REGISTRY_CACHE: Lazy<Mutex<Option<CachedRegistry>>> = Lazy::new(|| Mutex::new(None));

impl SupportedAgentDefinition {
    pub fn install_script_relpath(&self) -> Option<&str> {
        #[cfg(target_os = "windows")]
        {
            self.repo_scripts.install_windows.as_deref()
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.repo_scripts.install_unix.as_deref()
        }
    }

    pub fn uninstall_script_relpath(&self) -> Option<&str> {
        #[cfg(target_os = "windows")]
        {
            self.repo_scripts.uninstall_windows.as_deref()
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.repo_scripts.uninstall_unix.as_deref()
        }
    }

    pub fn healthcheck_relpath(&self) -> &str {
        &self.repo_scripts.healthcheck_relpath
    }

    pub fn resolve_install_path_with_home(&self, home: &Path, data_dir: &Path) -> Option<PathBuf> {
        match self.install_layout.install_base.as_str() {
            "data_dir" => Some(data_dir.join(&self.install_layout.install_relative_path)),
            "home" => Some(home.join(&self.install_layout.install_relative_path)),
            _ => None,
        }
    }

    pub fn resolve_config_dir_with_home(&self, home: &Path) -> Option<PathBuf> {
        match self.install_layout.config_kind.as_str() {
            "none" => None,
            "platform_config_slug" => self
                .install_layout
                .config_slug
                .as_deref()
                .map(|slug| platform_config_dir_for_slug(home, slug)),
            _ => None,
        }
    }

    pub fn resolve_state_dir_with_home(&self, home: &Path) -> Option<PathBuf> {
        match self.install_layout.state_kind.as_str() {
            "none" => None,
            "platform_state_slug" => self
                .install_layout
                .state_slug
                .as_deref()
                .map(|slug| platform_state_dir_for_slug(home, slug)),
            _ => None,
        }
    }

    pub fn resolve_global_mcp_configs(&self, home: &Path) -> Vec<PathBuf> {
        let Some(mcp) = &self.mcp else {
            return Vec::new();
        };

        let mut paths = Vec::new();
        for target in &mcp.config_targets {
            match target.as_str() {
                "cursor_user_mcp" => paths.push(home.join(".cursor/mcp.json")),
                "claude_cli_config" => paths.push(home.join(".claude.json")),
                "claude_desktop_app_config" => {
                    #[cfg(target_os = "macos")]
                    {
                        let desktop = home
                            .join("Library/Application Support/Claude/claude_desktop_config.json");
                        if desktop.parent().map_or(false, |p| p.exists()) {
                            paths.push(desktop);
                        }
                    }
                    #[cfg(target_os = "windows")]
                    {
                        if let Ok(appdata) = std::env::var("APPDATA") {
                            let desktop =
                                PathBuf::from(appdata).join("Claude/claude_desktop_config.json");
                            if desktop.parent().map_or(false, |p| p.exists()) {
                                paths.push(desktop);
                            }
                        }
                    }
                    #[cfg(target_os = "linux")]
                    {
                        let config_home = std::env::var("XDG_CONFIG_HOME")
                            .map(PathBuf::from)
                            .unwrap_or_else(|_| home.join(".config"));
                        let desktop = config_home.join("Claude/claude_desktop_config.json");
                        if desktop.parent().map_or(false, |p| p.exists()) {
                            paths.push(desktop);
                        }
                    }
                }
                _ => {}
            }
        }
        paths
    }

    pub fn mcp_server_key(&self) -> Option<&str> {
        self.mcp.as_ref().map(|mcp| mcp.server_key.as_str())
    }

    pub fn bundle_icon_path(&self, install_path: &Path) -> Option<PathBuf> {
        self.install_layout
            .bundle_icon_relpath
            .as_deref()
            .map(|relpath| install_path.join(relpath))
    }

    pub fn registry_icon_path(&self, registry_dir: &Path) -> Option<PathBuf> {
        self.registry_icon_relpath
            .as_deref()
            .map(|relpath| registry_dir.join(relpath))
    }
}

pub fn load_supported_agents() -> LoadedSupportedAgents {
    {
        let cache = REGISTRY_CACHE.lock();
        if let Some(cached) = cache.as_ref() {
            if cached.loaded_at.elapsed() < CACHE_TTL {
                return cached.registry.clone();
            }
        }
    }

    let loaded = try_load_local_registry()
        .or_else(|| try_load_remote_registry())
        .unwrap_or_else(builtin_supported_agents);

    *REGISTRY_CACHE.lock() = Some(CachedRegistry {
        loaded_at: Instant::now(),
        registry: loaded.clone(),
    });

    loaded
}

pub fn supported_agent_types() -> Vec<String> {
    ordered_supported_agents()
        .iter()
        .map(|agent| agent.agent_type.clone())
        .collect()
}

pub fn ordered_supported_agents() -> Vec<SupportedAgentDefinition> {
    let mut agents = load_supported_agents().index.agents;
    agents.sort_by(|a, b| {
        a.sort_order
            .cmp(&b.sort_order)
            .then_with(|| a.display_name.cmp(&b.display_name))
    });
    agents
}

pub fn supported_agent_types_display() -> String {
    supported_agent_types().join(", ")
}

pub fn default_agent_type() -> String {
    load_supported_agents().index.default_agent_type
}

pub fn find_supported_agent(agent_type: &str) -> Option<SupportedAgentDefinition> {
    ordered_supported_agents()
        .into_iter()
        .find(|agent| agent.agent_type == agent_type)
}

pub fn registry_dir() -> Option<PathBuf> {
    load_supported_agents().registry_dir
}

fn try_load_local_registry() -> Option<LoadedSupportedAgents> {
    for candidate in local_registry_candidates() {
        if !candidate.exists() {
            continue;
        }
        match read_registry_from_path(&candidate) {
            Ok(loaded) => return Some(loaded),
            Err(error) => warn!(
                "Failed to parse supported-agent registry at {}: {}",
                candidate.display(),
                error
            ),
        }
    }
    None
}

fn try_load_remote_registry() -> Option<LoadedSupportedAgents> {
    let url = std::env::var("EDAMAME_SUPPORTED_AGENTS_URL")
        .unwrap_or_else(|_| DEFAULT_REGISTRY_URL.to_string());

    let client = match reqwest::blocking::Client::builder()
        .user_agent("edamame-foundation-supported-agents/1.0")
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            warn!(
                "Failed to build supported-agent registry HTTP client: {}",
                error
            );
            return None;
        }
    };

    let response = match client.get(&url).send() {
        Ok(response) => response,
        Err(error) => {
            warn!(
                "Failed to fetch supported-agent registry from {}: {}",
                url, error
            );
            return None;
        }
    };

    if !response.status().is_success() {
        warn!(
            "Supported-agent registry fetch from {} returned {}",
            url,
            response.status()
        );
        return None;
    }

    let body = match response.text() {
        Ok(body) => body,
        Err(error) => {
            warn!(
                "Failed to read supported-agent registry response body from {}: {}",
                url, error
            );
            return None;
        }
    };

    match serde_json::from_str::<SupportedAgentsIndex>(&body) {
        Ok(mut index) => {
            index.agents.sort_by_key(|agent| agent.sort_order);
            Some(LoadedSupportedAgents {
                index,
                registry_dir: None,
                source: url,
            })
        }
        Err(error) => {
            warn!(
                "Failed to deserialize supported-agent registry from {}: {}",
                url, error
            );
            None
        }
    }
}

fn read_registry_from_path(path: &Path) -> anyhow::Result<LoadedSupportedAgents> {
    let content = std::fs::read_to_string(path)?;
    let mut index: SupportedAgentsIndex = serde_json::from_str(&content)?;
    index.agents.sort_by_key(|agent| agent.sort_order);
    Ok(LoadedSupportedAgents {
        index,
        registry_dir: path.parent().map(Path::to_path_buf),
        source: path.display().to_string(),
    })
}

fn local_registry_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(index_path) = std::env::var("EDAMAME_SUPPORTED_AGENTS_INDEX") {
        candidates.push(PathBuf::from(index_path));
    }

    if let Ok(dir_path) = std::env::var("EDAMAME_SUPPORTED_AGENTS_DIR") {
        candidates.push(PathBuf::from(dir_path).join("index.json"));
    }

    if let Ok(current_dir) = std::env::current_dir() {
        for ancestor in current_dir.ancestors() {
            candidates.push(ancestor.join("supported_agents/index.json"));
            candidates.push(ancestor.join("agent_security/supported_agents/index.json"));
        }
    }

    dedupe_paths(candidates)
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut unique = Vec::new();
    for path in paths {
        if !unique.iter().any(|existing| existing == &path) {
            unique.push(path);
        }
    }
    unique
}

fn builtin_supported_agents() -> LoadedSupportedAgents {
    let mut index = SupportedAgentsIndex {
        schema_version: 1,
        default_agent_type: "openclaw".to_string(),
        agents: vec![
            SupportedAgentDefinition {
                agent_type: "cursor".to_string(),
                display_name: "EDAMAME for Cursor".to_string(),
                description: "Cursor workstation integration with transcript ingest, pairing, verdicts, and health checks.".to_string(),
                repo_name: "edamame_cursor".to_string(),
                strategy_kind: "workstation_stdio_mcp".to_string(),
                sort_order: 10,
                requires_workspace_arg: true,
                repo_scripts: AgentRepoScripts {
                    install_unix: Some("setup/install.sh".to_string()),
                    install_windows: Some("setup/install.ps1".to_string()),
                    uninstall_unix: Some("setup/uninstall.sh".to_string()),
                    uninstall_windows: Some("setup/uninstall.ps1".to_string()),
                    healthcheck_relpath: "service/healthcheck_cli.mjs".to_string(),
                },
                install_layout: AgentInstallLayout {
                    install_base: "data_dir".to_string(),
                    install_relative_path: "cursor-edamame/current".to_string(),
                    config_kind: "platform_config_slug".to_string(),
                    config_slug: Some("cursor-edamame".to_string()),
                    state_kind: "platform_state_slug".to_string(),
                    state_slug: Some("cursor-edamame".to_string()),
                    bundle_icon_relpath: Some("assets/plugin_cursor.png".to_string()),
                },
                mcp: Some(AgentMcpConfig {
                    server_key: "edamame".to_string(),
                    config_targets: vec!["cursor_user_mcp".to_string()],
                }),
                e2e: Some(AgentE2eConfig {
                    repo_env_var: Some("CURSOR_REPO".to_string()),
                    intent_script: Some("tests/e2e_inject_intent.sh".to_string()),
                    intent_timeout_seconds: Some(900),
                }),
                registry_icon_relpath: Some("cursor/icon.svg".to_string()),
            },
            SupportedAgentDefinition {
                agent_type: "claude_code".to_string(),
                display_name: "EDAMAME for Claude Code".to_string(),
                description: "Claude Code workstation integration with transcript ingest, pairing, verdicts, and health checks.".to_string(),
                repo_name: "edamame_claude_code".to_string(),
                strategy_kind: "workstation_stdio_mcp".to_string(),
                sort_order: 20,
                requires_workspace_arg: true,
                repo_scripts: AgentRepoScripts {
                    install_unix: Some("setup/install.sh".to_string()),
                    install_windows: Some("setup/install.ps1".to_string()),
                    uninstall_unix: Some("setup/uninstall.sh".to_string()),
                    uninstall_windows: Some("setup/uninstall.ps1".to_string()),
                    healthcheck_relpath: "service/healthcheck_cli.mjs".to_string(),
                },
                install_layout: AgentInstallLayout {
                    install_base: "data_dir".to_string(),
                    install_relative_path: "claude-code-edamame/current".to_string(),
                    config_kind: "platform_config_slug".to_string(),
                    config_slug: Some("claude-code-edamame".to_string()),
                    state_kind: "platform_state_slug".to_string(),
                    state_slug: Some("claude-code-edamame".to_string()),
                    bundle_icon_relpath: Some("assets/plugin_claude_code.png".to_string()),
                },
                mcp: Some(AgentMcpConfig {
                    server_key: "edamame-code".to_string(),
                    config_targets: vec!["claude_cli_config".to_string()],
                }),
                e2e: Some(AgentE2eConfig {
                    repo_env_var: Some("CLAUDE_REPO".to_string()),
                    intent_script: Some("tests/e2e_inject_intent.sh".to_string()),
                    intent_timeout_seconds: Some(900),
                }),
                registry_icon_relpath: Some("claude_code/icon.svg".to_string()),
            },
            SupportedAgentDefinition {
                agent_type: "claude_desktop".to_string(),
                display_name: "EDAMAME for Claude Desktop".to_string(),
                description: "Claude Desktop workstation integration with transcript ingest, pairing, verdicts, and desktop-specific MCP registration.".to_string(),
                repo_name: "edamame_claude_desktop".to_string(),
                strategy_kind: "claude_desktop_dual_mcp".to_string(),
                sort_order: 30,
                requires_workspace_arg: true,
                repo_scripts: AgentRepoScripts {
                    install_unix: Some("setup/install.sh".to_string()),
                    install_windows: Some("setup/install.ps1".to_string()),
                    uninstall_unix: Some("setup/uninstall.sh".to_string()),
                    uninstall_windows: Some("setup/uninstall.ps1".to_string()),
                    healthcheck_relpath: "service/healthcheck_cli.mjs".to_string(),
                },
                install_layout: AgentInstallLayout {
                    install_base: "data_dir".to_string(),
                    install_relative_path: "claude-desktop-edamame/current".to_string(),
                    config_kind: "platform_config_slug".to_string(),
                    config_slug: Some("claude-desktop-edamame".to_string()),
                    state_kind: "platform_state_slug".to_string(),
                    state_slug: Some("claude-desktop-edamame".to_string()),
                    bundle_icon_relpath: Some("assets/plugin_claude_desktop.png".to_string()),
                },
                mcp: Some(AgentMcpConfig {
                    server_key: "edamame".to_string(),
                    config_targets: vec![
                        "claude_cli_config".to_string(),
                        "claude_desktop_app_config".to_string(),
                    ],
                }),
                e2e: Some(AgentE2eConfig {
                    repo_env_var: Some("CLAUDE_DESKTOP_REPO".to_string()),
                    intent_script: Some("tests/e2e_inject_intent.sh".to_string()),
                    intent_timeout_seconds: Some(900),
                }),
                registry_icon_relpath: Some("claude_desktop/icon.svg".to_string()),
            },
            SupportedAgentDefinition {
                agent_type: "openclaw".to_string(),
                display_name: "EDAMAME for OpenClaw".to_string(),
                description: "OpenClaw plugin bundle with skills, health checks, and local plugin enablement.".to_string(),
                repo_name: "edamame_openclaw".to_string(),
                strategy_kind: "openclaw_plugin_bundle".to_string(),
                sort_order: 40,
                requires_workspace_arg: false,
                repo_scripts: AgentRepoScripts {
                    install_unix: Some("setup/install.sh".to_string()),
                    install_windows: Some("setup/install.ps1".to_string()),
                    uninstall_unix: Some("setup/uninstall.sh".to_string()),
                    uninstall_windows: Some("setup/uninstall.ps1".to_string()),
                    healthcheck_relpath: "service/healthcheck_cli.mjs".to_string(),
                },
                install_layout: AgentInstallLayout {
                    install_base: "home".to_string(),
                    install_relative_path: ".openclaw/edamame-openclaw".to_string(),
                    config_kind: "none".to_string(),
                    config_slug: None,
                    state_kind: "none".to_string(),
                    state_slug: None,
                    bundle_icon_relpath: Some("assets/plugin_openclaw.png".to_string()),
                },
                mcp: None,
                e2e: Some(AgentE2eConfig {
                    repo_env_var: Some("OPENCLAW_REPO".to_string()),
                    intent_script: Some("tests/e2e_inject_intent.sh".to_string()),
                    intent_timeout_seconds: Some(600),
                }),
                registry_icon_relpath: Some("openclaw/icon.svg".to_string()),
            },
        ],
    };
    index.agents.sort_by_key(|agent| agent.sort_order);
    LoadedSupportedAgents {
        index,
        registry_dir: None,
        source: "builtin".to_string(),
    }
}

fn platform_config_dir_for_slug(home: &Path, slug: &str) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support").join(slug)
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|appdata| PathBuf::from(appdata).join(slug))
            .or_else(|| dirs::config_dir().map(|config_dir| config_dir.join(slug)))
            .unwrap_or_else(|| home.join("AppData/Roaming").join(slug))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        home.join(".config").join(slug)
    }
}

fn platform_state_dir_for_slug(home: &Path, slug: &str) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support")
            .join(slug)
            .join("state")
    }
    #[cfg(target_os = "windows")]
    {
        dirs::data_local_dir()
            .map(|data_local| data_local.join(slug).join("state"))
            .unwrap_or_else(|| home.join("AppData/Local").join(slug).join("state"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::env::var("XDG_STATE_HOME")
            .ok()
            .map(|state_home| PathBuf::from(state_home).join(slug))
            .unwrap_or_else(|| home.join(".local/state").join(slug))
    }
}
