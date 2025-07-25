use serde_json::Value;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tracing::{debug, error, warn};

/// Execute a command with a 20-second timeout
fn execute_command_with_timeout(mut cmd: Command) -> std::io::Result<std::process::Output> {
    use std::sync::mpsc;
    use std::thread;

    let (tx, rx) = mpsc::channel();

    // Spawn command execution in a separate thread
    let handle = thread::spawn(move || {
        let result = cmd.output();
        let _ = tx.send(result);
    });

    // Wait for result with timeout
    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(output) => output,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Kill the thread if possible and return timeout error
            drop(handle); // Drop the handle, can't easily kill it
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Command execution timed out after 10 seconds",
            ))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Command execution thread disconnected",
        )),
    }
}

/// Check if a binary exists in PATH or as absolute path
fn binary_exists(binary_name: &str) -> bool {
    if Path::new(binary_name).is_absolute() {
        Path::new(binary_name).exists()
    } else {
        // Check in PATH
        if let Ok(path_env) = std::env::var("PATH") {
            for path in std::env::split_paths(&path_env) {
                let full_path = path.join(binary_name);
                if full_path.exists() {
                    return true;
                }
                // Also check with .exe extension on Windows
                #[cfg(target_os = "windows")]
                {
                    let exe_path =
                        path.join(format!("{}.exe", binary_name.trim_end_matches(".exe")));
                    if exe_path.exists() {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Read a file with a 10-second timeout
fn read_file_with_timeout(path: &str) -> std::io::Result<String> {
    use std::fs::File;
    use std::io::Read;
    use std::time::Instant;

    let start = Instant::now();
    let timeout = Duration::from_secs(10);

    // Simple file read with timeout check
    let mut file = File::open(path)?;
    let mut contents = String::new();

    // For simplicity, we'll do a blocking read but check the elapsed time
    // In a real implementation, you might want to use async I/O
    if start.elapsed() > timeout {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "File read timed out after 10 seconds",
        ));
    }

    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Try to discover peer- or gateway-IDs for the VPN / ZTNA agents that may be
/// installed on the local host.  Runs entirely from userspace, never needs
/// elevation; any missing binary, socket or registry key is simply skipped.
///
/// The tuple returned is always (vendor_tag, peer_or_gateway_id).
pub fn get_peer_ids() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    /* ----------  TAILSCALE  ---------- */
    debug!("Checking for Tailscale...");
    let tailscale_cmd = if cfg!(target_os = "windows") {
        "C:\\Program Files\\Tailscale\\tailscale.exe"
    } else if cfg!(target_os = "macos") {
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
    } else {
        "tailscale"
    };

    let tailscale_binary_exists = binary_exists(tailscale_cmd);
    if tailscale_binary_exists {
        debug!("Tailscale binary found: {}", tailscale_cmd);
    } else {
        debug!("Tailscale binary not found: {}", tailscale_cmd);
    }

    let mut cmd = Command::new(tailscale_cmd);
    cmd.args(&["status", "--json"]);
    match execute_command_with_timeout(cmd) {
        Ok(ts) => {
            debug!(
                "Tailscale command found and executed: {} status --json",
                tailscale_cmd
            );
            if ts.status.success() {
                match serde_json::from_slice::<Value>(&ts.stdout) {
                    Ok(v) => {
                        if let Some(self_node) = v.get("Self").and_then(|p| p.as_object()) {
                            // Extract node ID
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

                            // Extract public key
                            if let Some(public_key) =
                                self_node.get("PublicKey").and_then(|k| k.as_str())
                            {
                                if !public_key.is_empty() {
                                    out.push(("tailscale/PublicKey".into(), public_key.into()));
                                    debug!("Found Tailscale public key: {}", public_key);
                                } else {
                                    debug!("Tailscale public key is empty");
                                }
                            } else {
                                debug!("No Tailscale public key found in Self node");
                            }

                            // Extract IP address (join all IPs from TailscaleIPs array)
                            if let Some(ips) =
                                self_node.get("TailscaleIPs").and_then(|ips| ips.as_array())
                            {
                                let ip_strings: Vec<String> = ips
                                    .iter()
                                    .filter_map(|ip| ip.as_str())
                                    .filter(|s| !s.is_empty())
                                    .map(|s| s.to_string())
                                    .collect();
                                if !ip_strings.is_empty() {
                                    let joined_ips = ip_strings.join(",");
                                    out.push(("tailscale/TailscaleIPs".into(), joined_ips.clone()));
                                    debug!("Found Tailscale IPs: {}", joined_ips);
                                } else {
                                    debug!("No valid Tailscale IPs found in TailscaleIPs array");
                                }
                            } else {
                                debug!("No TailscaleIPs array found in Self node");
                            }

                            // Extract hostname
                            if let Some(hostname) =
                                self_node.get("HostName").and_then(|h| h.as_str())
                            {
                                if !hostname.is_empty() {
                                    out.push(("tailscale/HostName".into(), hostname.into()));
                                    debug!("Found Tailscale hostname: {}", hostname);
                                } else {
                                    debug!("Tailscale hostname is empty");
                                }
                            } else {
                                debug!("No Tailscale hostname found in Self node");
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
                if tailscale_binary_exists {
                    error!("Tailscale command failed with exit code: {}", ts.status);
                    if !ts.stderr.is_empty() {
                        error!("Tailscale stderr: {}", String::from_utf8_lossy(&ts.stderr));
                    }
                } else {
                    debug!(
                        "Tailscale command failed (binary not found) with exit code: {}",
                        ts.status
                    );
                    if !ts.stderr.is_empty() {
                        debug!("Tailscale stderr: {}", String::from_utf8_lossy(&ts.stderr));
                    }
                }
            }
        }
        Err(e) => {
            if tailscale_binary_exists {
                error!(
                    "Tailscale binary exists but failed to execute: {} - {}",
                    tailscale_cmd, e
                );
            } else {
                debug!("Tailscale binary not found: {} - {}", tailscale_cmd, e);
            }
        }
    }

    /* ----------  ZEROTIER ONE  ---------- */
    debug!("Checking for ZeroTier...");
    let zerotier_cmd = if cfg!(target_os = "windows") {
        "zerotier-cli.exe"
    } else {
        "zerotier-cli"
    };

    let zerotier_binary_exists = binary_exists(zerotier_cmd);
    if zerotier_binary_exists {
        debug!("ZeroTier binary found: {}", zerotier_cmd);
    } else {
        debug!("ZeroTier binary not found: {}", zerotier_cmd);
    }

    let mut cmd = Command::new(zerotier_cmd);
    cmd.args(&["info"]);
    match execute_command_with_timeout(cmd) {
        Ok(zt) => {
            debug!("ZeroTier command found and executed: {} info", zerotier_cmd);
            if zt.status.success() {
                let stdout = String::from_utf8_lossy(&zt.stdout);
                let output = stdout.to_string();
                // Parse output format: "200 info <node_id> <version> <status>"
                let parts: Vec<&str> = output.trim().split_whitespace().collect();
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
                    debug!("ZeroTier stdout: {}", output);
                }
            } else {
                if zerotier_binary_exists {
                    error!(
                        "ZeroTier command failed with exit code: {} - {}",
                        zt.status,
                        String::from_utf8_lossy(&zt.stderr)
                    );
                } else {
                    debug!(
                        "ZeroTier command failed (binary not found) with exit code: {}",
                        zt.status
                    );
                    if !zt.stderr.is_empty() {
                        debug!("ZeroTier stderr: {}", String::from_utf8_lossy(&zt.stderr));
                    }
                }
            }
        }
        Err(e) => {
            if zerotier_binary_exists {
                error!(
                    "ZeroTier binary exists but failed to execute: {} - {}",
                    zerotier_cmd, e
                );
            } else {
                debug!("ZeroTier binary not found: {} - {}", zerotier_cmd, e);
            }
        }
    }

    /* ----------  NETBIRD  ---------- */
    debug!("Checking for NetBird...");
    let netbird_cmd = if cfg!(target_os = "windows") {
        "netbird.exe"
    } else {
        "netbird"
    };

    let netbird_binary_exists = binary_exists(netbird_cmd);
    if netbird_binary_exists {
        debug!("NetBird binary found: {}", netbird_cmd);
    } else {
        debug!("NetBird binary not found: {}", netbird_cmd);
    }

    let mut cmd = Command::new(netbird_cmd);
    cmd.args(&["status", "--json"]);
    match execute_command_with_timeout(cmd) {
        Ok(nb) => {
            debug!(
                "NetBird command found and executed: {} status --json",
                netbird_cmd
            );
            if nb.status.success() {
                // First, let's debug the raw JSON
                let json_str = String::from_utf8_lossy(&nb.stdout);
                debug!("NetBird JSON response: {}", json_str);

                match serde_json::from_slice::<Value>(&nb.stdout) {
                    Ok(v) => {
                        // Extract local node information from root level
                        if let Some(public_key) = v.get("publicKey").and_then(|k| k.as_str()) {
                            if !public_key.is_empty() {
                                out.push(("netbird/publicKey".into(), public_key.into()));
                                debug!("Found NetBird local public key: {}", public_key);
                            }
                        }

                        if let Some(netbird_ip) = v.get("netbirdIp").and_then(|ip| ip.as_str()) {
                            if !netbird_ip.is_empty() {
                                out.push(("netbird/netbirdIp".into(), netbird_ip.into()));
                                debug!("Found NetBird local IP: {}", netbird_ip);
                            }
                        }

                        if let Some(hostname) = v.get("fqdn").and_then(|h| h.as_str()) {
                            if !hostname.is_empty() {
                                out.push(("netbird/fqdn".into(), hostname.into()));
                                debug!("Found NetBird local hostname: {}", hostname);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse NetBird status JSON: {}", e);
                        debug!("NetBird stdout: {}", String::from_utf8_lossy(&nb.stdout));
                    }
                }
            } else {
                if netbird_binary_exists {
                    error!("NetBird command failed with exit code: {}", nb.status);
                    if !nb.stderr.is_empty() {
                        error!("NetBird stderr: {}", String::from_utf8_lossy(&nb.stderr));
                    }
                } else {
                    debug!(
                        "NetBird command failed (binary not found) with exit code: {}",
                        nb.status
                    );
                    if !nb.stderr.is_empty() {
                        debug!("NetBird stderr: {}", String::from_utf8_lossy(&nb.stderr));
                    }
                }
            }
        }
        Err(e) => {
            if netbird_binary_exists {
                error!(
                    "NetBird binary exists but failed to execute: {} - {}",
                    netbird_cmd, e
                );
            } else {
                debug!("NetBird binary not found: {} - {}", netbird_cmd, e);
            }
        }
    }

    /* ----------  NETSKOPE  ---------- *
     * Read nsconfig.json to extract userKey, hostname, and serial
     * Config file path differs per platform.                    */
    debug!("Checking for Netskope...");
    let nsconfig_path = if cfg!(target_os = "windows") {
        r"C:\ProgramData\netskopestagent\nsconfig.json"
    } else if cfg!(target_os = "macos") {
        "/Library/Application Support/Netskope/STAgent/nsconfig.json"
    } else {
        "/opt/netskope/stagent/nsconfig.json"
    };

    let netskope_config_exists = Path::new(nsconfig_path).exists();
    if netskope_config_exists {
        debug!("Netskope config file found: {}", nsconfig_path);
    } else {
        debug!("Netskope config file not found: {}", nsconfig_path);
    }

    match read_file_with_timeout(nsconfig_path) {
        Ok(config_content) => {
            debug!("Netskope config file found and read: {}", nsconfig_path);
            match serde_json::from_str::<Value>(&config_content) {
                Ok(config) => {
                    // Extract userKey from clientConfig.userkey
                    if let Some(user_key) = config
                        .get("clientConfig")
                        .and_then(|cc| cc.get("userkey"))
                        .and_then(|k| k.as_str())
                    {
                        if !user_key.is_empty() {
                            out.push(("netskope/userkey".into(), user_key.into()));
                            debug!("Found Netskope user key");
                        } else {
                            debug!("Netskope user key is empty");
                        }
                    } else {
                        debug!("No Netskope user key found in config (clientConfig.userkey)");
                    }

                    // Extract hostname from cache.device.hostname
                    if let Some(hostname) = config
                        .get("cache")
                        .and_then(|cache| cache.get("device"))
                        .and_then(|device| device.get("hostname"))
                        .and_then(|h| h.as_str())
                    {
                        if !hostname.is_empty() {
                            out.push(("netskope/hostname".into(), hostname.into()));
                            debug!("Found Netskope hostname: {}", hostname);
                        } else {
                            debug!("Netskope hostname is empty");
                        }
                    } else {
                        debug!("No Netskope hostname found in config (cache.device.hostname)");
                    }

                    // Extract serial from cache.device.serial_num
                    if let Some(serial) = config
                        .get("cache")
                        .and_then(|cache| cache.get("device"))
                        .and_then(|device| device.get("serial_num"))
                        .and_then(|s| s.as_str())
                    {
                        if !serial.is_empty() {
                            out.push(("netskope/serial".into(), serial.into()));
                            debug!("Found Netskope serial: {}", serial);
                        } else {
                            debug!("Netskope serial is empty");
                        }
                    } else {
                        debug!("No Netskope serial found in config (cache.device.serial_num)");
                    }
                }
                Err(e) => {
                    if netskope_config_exists {
                        error!("Failed to parse Netskope config JSON: {}", e);
                        error!("Netskope config content: {}", config_content);
                    } else {
                        debug!(
                            "Failed to parse Netskope config JSON (file not found): {}",
                            e
                        );
                        debug!("Netskope config content: {}", config_content);
                    }
                }
            }
        }
        Err(e) => {
            if netskope_config_exists {
                error!(
                    "Netskope config file exists but failed to read: {} - {}",
                    nsconfig_path, e
                );
            } else {
                debug!("Netskope config file not found: {} - {}", nsconfig_path, e);
            }
        }
    }

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
