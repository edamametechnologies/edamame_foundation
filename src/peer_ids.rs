use crate::admin::get_admin_status;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, error, warn};

/// Execute a command with a 20-second timeout
async fn execute_command_with_timeout(mut cmd: Command) -> std::io::Result<std::process::Output> {
    match timeout(Duration::from_secs(20), cmd.output()).await {
        Ok(output_res) => output_res,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Command execution timed out after 20 seconds",
        )),
    }
}

/// Check if a binary exists in PATH or as absolute path
fn binary_exists(binary_name: &str) -> bool {
    if Path::new(binary_name).is_absolute() {
        Path::new(binary_name).exists()
    } else if let Ok(path_env) = std::env::var("PATH") {
        std::env::split_paths(&path_env).any(|p| {
            let full_path = p.join(binary_name);
            if full_path.exists() {
                return true;
            }
            // Also check with .exe extension on Windows
            #[cfg(target_os = "windows")]
            {
                let exe_path = p.join(format!("{}.exe", binary_name.trim_end_matches(".exe")));
                if exe_path.exists() {
                    return true;
                }
            }
            false
        })
    } else {
        false
    }
}

/// Read a file with a 10-second timeout (async version)
async fn read_file_with_timeout(path: &str) -> std::io::Result<String> {
    match timeout(Duration::from_secs(10), tokio::fs::read_to_string(path)).await {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "File read timed out after 10 seconds",
        )),
    }
}

/* -------------------------------------------------------------------------- */
/*                              Helper functions                              */
/* -------------------------------------------------------------------------- */

/// Discover peer IDs from the local Tailscale agent
async fn discover_tailscale() -> Vec<(String, String)> {
    debug!("Checking for Tailscale...");
    let tailscale_cmd = if cfg!(target_os = "windows") {
        "C:\\Program Files\\Tailscale\\tailscale.exe"
    } else if cfg!(target_os = "macos") {
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
    } else {
        "tailscale"
    };

    let mut out = Vec::new();

    if binary_exists(tailscale_cmd) {
        debug!("Tailscale binary found: {}", tailscale_cmd);
        let mut cmd = Command::new(tailscale_cmd);
        cmd.args(["status", "--json"]);
        match execute_command_with_timeout(cmd).await {
            Ok(ts) => {
                debug!(
                    "Tailscale command found and executed: {} status --json",
                    tailscale_cmd
                );
                if ts.status.success() {
                    match serde_json::from_slice::<Value>(&ts.stdout) {
                        Ok(v) => {
                            if let Some(self_node) = v.get("Self").and_then(|p| p.as_object()) {
                                if let Some(id) = self_node.get("ID").and_then(|id| id.as_str()) {
                                    if !id.is_empty() {
                                        out.push(("tailscale/ID".into(), id.into()));
                                        debug!("Found Tailscale node ID: {}", id);
                                    } else {
                                        debug!("Tailscale node ID is empty");
                                    }
                                } else {
                                    debug!("No Tailscale node ID found in Self node");
                                }
                            } else {
                                debug!("No Tailscale Self node found in status output");
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse Tailscale status JSON: {}", e);
                            debug!("Tailscale stdout: {}", String::from_utf8_lossy(&ts.stdout));
                        }
                    }
                } else {
                    error!("Tailscale command failed with exit code: {}", ts.status);
                    if !ts.stderr.is_empty() {
                        error!("Tailscale stderr: {}", String::from_utf8_lossy(&ts.stderr));
                    }
                }
            }
            Err(e) => {
                error!(
                    "Tailscale binary exists but failed to execute: {} - {}",
                    tailscale_cmd, e
                );
            }
        }
    } else {
        debug!("Tailscale binary not found: {}", tailscale_cmd);
    }

    out
}

/// Discover peer IDs from the local ZeroTier agent
async fn discover_zerotier() -> Vec<(String, String)> {
    debug!("Checking for ZeroTier...");
    let zerotier_cmd = if cfg!(target_os = "windows") {
        "C:\\ProgramData\\ZeroTier\\One\\zerotier-one_x64.exe"
    } else if cfg!(target_os = "macos") {
        "/Library/Application Support/ZeroTier/One/zerotier-cli"
    } else {
        "zerotier-cli"
    };

    let mut out = Vec::new();

    if binary_exists(zerotier_cmd) {
        debug!("ZeroTier binary found: {}", zerotier_cmd);
        let mut cmd = Command::new(zerotier_cmd);
        if cfg!(target_os = "windows") {
            cmd.args(["-q", "info"]);
        } else {
            cmd.arg("info");
        }
        match execute_command_with_timeout(cmd).await {
            Ok(zt) => {
                debug!("ZeroTier command found and executed: {} info", zerotier_cmd);
                if zt.status.success() {
                    let stdout = String::from_utf8_lossy(&zt.stdout);
                    let parts: Vec<&str> = stdout.trim().split_whitespace().collect();
                    if parts.len() >= 3 && parts[0] == "200" && parts[1] == "info" {
                        let node_id = parts[2];
                        if !node_id.is_empty() {
                            out.push(("zerotier/nodeID".into(), node_id.into()));
                            debug!("Found ZeroTier node ID: {}", node_id);
                        } else {
                            debug!("ZeroTier node ID is empty");
                        }
                    } else {
                        warn!("Unexpected ZeroTier info output format");
                        debug!("ZeroTier stdout: {}", stdout);
                    }
                } else {
                    error!(
                        "ZeroTier command failed with exit code: {} - {}",
                        zt.status,
                        String::from_utf8_lossy(&zt.stderr)
                    );
                }
            }
            Err(e) => {
                error!(
                    "ZeroTier binary exists but failed to execute: {} - {}",
                    zerotier_cmd, e
                );
            }
        }
    } else {
        debug!("ZeroTier binary not found: {}", zerotier_cmd);
    }

    out
}

/// Discover peer IDs from the local NetBird agent
async fn discover_netbird() -> Vec<(String, String)> {
    debug!("Checking for NetBird...");
    let netbird_cmd = if cfg!(target_os = "windows") {
        "C:\\Program Files\\NetBird\\netbird.exe"
    } else if cfg!(target_os = "macos") {
        "/Applications/NetBird.app/Contents/MacOS/netbird"
    } else {
        "netbird"
    };

    let mut out = Vec::new();

    if binary_exists(netbird_cmd) {
        debug!("NetBird binary found: {}", netbird_cmd);
        let mut cmd = Command::new(netbird_cmd);
        cmd.args(["status", "--json"]);
        match execute_command_with_timeout(cmd).await {
            Ok(nb) => {
                debug!(
                    "NetBird command found and executed: {} status --json",
                    netbird_cmd
                );
                if nb.status.success() {
                    let json_str = String::from_utf8_lossy(&nb.stdout);
                    debug!("NetBird JSON response: {}", json_str);
                    match serde_json::from_slice::<Value>(&nb.stdout) {
                        Ok(v) => {
                            // Helper closure to push non-empty string values with a given tag
                            let mut insert_if_present = |tag: &str, val_opt: Option<&str>| {
                                if let Some(val) = val_opt {
                                    if !val.is_empty() {
                                        out.push((tag.to_owned(), val.to_owned()));
                                        debug!("Found NetBird {}: {}", tag, val);
                                    }
                                }
                            };

                            insert_if_present(
                                "netbird/netbirdIp",
                                v.get("netbirdIp").and_then(|ip| ip.as_str()),
                            );
                        }
                        Err(e) => {
                            error!("Failed to parse NetBird status JSON: {}", e);
                            debug!("NetBird stdout: {}", json_str);
                        }
                    }
                } else {
                    error!("NetBird command failed with exit code: {}", nb.status);
                    if !nb.stderr.is_empty() {
                        error!("NetBird stderr: {}", String::from_utf8_lossy(&nb.stderr));
                    }
                }
            }
            Err(e) => {
                error!(
                    "NetBird binary exists but failed to execute: {} - {}",
                    netbird_cmd, e
                );
            }
        }
    } else {
        debug!("NetBird binary not found: {}", netbird_cmd);
    }

    out
}

/// Discover peer IDs from the local Netskope agent configuration
async fn discover_netskope() -> Vec<(String, String)> {
    debug!("Checking for Netskope...");
    let nsconfig_path = if cfg!(target_os = "windows") {
        r"C:\\ProgramData\\netskopestagent\\nsconfig.json"
    } else if cfg!(target_os = "macos") {
        "/Library/Application Support/Netskope/STAgent/nsconfig.json"
    } else {
        "/opt/netskope/stagent/nsconfig.json"
    };

    let mut out = Vec::new();

    if Path::new(nsconfig_path).exists() {
        debug!("Netskope config file found: {}", nsconfig_path);
        match read_file_with_timeout(nsconfig_path).await {
            Ok(config_content) => {
                debug!("Netskope config file read: {}", nsconfig_path);
                match serde_json::from_str::<Value>(&config_content) {
                    Ok(config) => {
                        if let Some(user_key) = config
                            .get("clientConfig")
                            .and_then(|cc| cc.get("userkey"))
                            .and_then(|k| k.as_str())
                        {
                            if !user_key.is_empty() {
                                out.push(("netskope/userkey".into(), user_key.into()));
                                debug!("Found Netskope user key");
                            }
                        }
                        if let Some(hostname) = config
                            .get("cache")
                            .and_then(|cache| cache.get("device"))
                            .and_then(|device| device.get("hostname"))
                            .and_then(|h| h.as_str())
                        {
                            if !hostname.is_empty() {
                                out.push(("netskope/hostname".into(), hostname.into()));
                                debug!("Found Netskope hostname: {}", hostname);
                            }
                        }
                        if let Some(serial) = config
                            .get("cache")
                            .and_then(|cache| cache.get("device"))
                            .and_then(|device| device.get("serial_num"))
                            .and_then(|s| s.as_str())
                        {
                            if !serial.is_empty() {
                                out.push(("netskope/serial".into(), serial.into()));
                                debug!("Found Netskope serial: {}", serial);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse Netskope config JSON: {}", e);
                        debug!("Netskope raw content: {}", config_content);
                    }
                }
            }
            Err(e) => {
                error!(
                    "Netskope config file exists but failed to read: {} - {}",
                    nsconfig_path, e
                );
            }
        }
    } else {
        debug!("Netskope config file not found: {}", nsconfig_path);
    }

    out
}

/* -------------------------------------------------------------------------- */
/*                              Public function                               */
/* -------------------------------------------------------------------------- */

/// Try to discover peer- or gateway-IDs for the VPN / ZTNA agents that may be
/// installed on the local host.  Runs entirely from userspace, never needs
/// elevation; any missing binary, socket or registry key is simply skipped.
///
/// The tuple returned is always (vendor_tag, peer_or_gateway_id).
pub async fn get_peer_ids() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    // Abort early if we don't have admin privileges.
    if !get_admin_status() {
        warn!("Running as non-admin, skipping VPN/ZTNA agent discovery");
        return out;
    }
    debug!("Running as admin");

    // Run the discovery routines concurrently.
    let (mut tailscale_ids, mut zerotier_ids, mut netbird_ids, mut netskope_ids) = tokio::join!(
        discover_tailscale(),
        discover_zerotier(),
        discover_netbird(),
        discover_netskope()
    );

    out.append(&mut tailscale_ids);
    out.append(&mut zerotier_ids);
    out.append(&mut netbird_ids);
    out.append(&mut netskope_ids);

    debug!("Total peer IDs discovered: {}", out.len());
    if out.is_empty() {
        debug!("No VPN/ZTNA agents detected on this system");
    } else {
        let mut unique_vendors: Vec<&str> = out
            .iter()
            .map(|(vendor, _)| vendor.split('/').next().unwrap_or(vendor))
            .collect();
        unique_vendors.sort();
        unique_vendors.dedup();
        debug!("VPN/ZTNA agents found: {}", unique_vendors.join(", "));
    }

    out
}

mod tests {

    #[tokio::test]
    async fn test_get_peer_ids() {
        use crate::peer_ids::get_peer_ids;

        let peer_ids = get_peer_ids().await;
        println!("Peer IDs: {:?}", peer_ids);
    }
}
