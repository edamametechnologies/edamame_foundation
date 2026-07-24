#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use crate::admin::get_admin_status;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, warn};

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
                let exe_path = p.join(format!("'{}.exe'", binary_name.trim_end_matches(".exe")));
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
use crate::runner_cli::run_cli;

/// Discover peer IDs from the local Tailscale agent. Executes the Tailscale
/// CLI via the generic `run_cli` helper so that we can transparently
/// personate `username` when needed (e.g. when running as root on Unix).
async fn discover_tailscale(username: &str) -> Vec<(String, String)> {
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
        // Build the command string and execute it via the generic `run_cli` helper.
        let cmd_string = if cfg!(target_os = "windows") {
            format!("& '{}' status --json", tailscale_cmd)
        } else {
            format!("'{}' status --json", tailscale_cmd)
        };
        match run_cli(&cmd_string, username, true, Some(20)).await {
            Ok(ts) => {
                debug!(
                    "Tailscale command found and executed: {} status --json",
                    tailscale_cmd
                );
                // `run_cli` already returns an `Err` on non-zero exit code, so we can
                // directly parse the returned stdout string.
                match serde_json::from_str::<Value>(&ts) {
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
                        warn!("Failed to parse Tailscale status JSON: {}", e);
                        debug!("Tailscale stdout: {}", ts);
                    }
                }
            }
            Err(e) => {
                warn!(
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
    use crate::runner_cli::run_cli;
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
        // Build the command string: on Windows we need the quiet flag to avoid decorative output.
        let cmd_string = if cfg!(target_os = "windows") {
            format!("& '{}' -q info", zerotier_cmd)
        } else {
            format!("'{}' info", zerotier_cmd)
        };

        match run_cli(&cmd_string, "", false, Some(20)).await {
            Ok(stdout) => {
                debug!("ZeroTier stdout: {}", stdout);
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
                }
            }
            Err(e) => {
                warn!("ZeroTier command execution failed: {} - {}", cmd_string, e);
            }
        }
    } else {
        debug!("ZeroTier binary not found: {}", zerotier_cmd);
    }

    out
}

/// Discover peer IDs from the local NetBird agent
async fn discover_netbird() -> Vec<(String, String)> {
    use crate::runner_cli::run_cli;
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
        let cmd_string = if cfg!(target_os = "windows") {
            format!("& '{}' status --json", netbird_cmd)
        } else {
            format!("'{}' status --json", netbird_cmd)
        };
        match run_cli(&cmd_string, "", false, Some(20)).await {
            Ok(stdout) => {
                if stdout.is_empty() {
                    warn!(
                        "NetBird command execution returned empty string: {}",
                        cmd_string
                    );
                } else {
                    debug!("NetBird JSON response: {}", stdout);
                    match serde_json::from_str::<Value>(&stdout) {
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
                            warn!("Failed to parse NetBird status JSON: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("NetBird command execution failed: {} - {}", cmd_string, e);
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
        r"C:\ProgramData\netskopestagent\nsconfig.json"
    } else if cfg!(target_os = "macos") {
        "/Library/Application Support/Netskope/STAgent/nsconfig.json"
    } else {
        "/opt/netskope/stagent/nsconfig.json"
    };

    let mut out = Vec::new();
    // Track the user key so we can assemble Netskope's composite device
    // identifier (`<userkey>_<nsdeviceuid>`) once the provisioning device UID is
    // discovered below.
    let mut user_key: Option<String> = None;

    if Path::new(nsconfig_path).exists() {
        debug!("Netskope config file found: {}", nsconfig_path);
        match read_file_with_timeout(nsconfig_path).await {
            Ok(config_content) => {
                debug!("Netskope config file read: {}", nsconfig_path);
                match serde_json::from_str::<Value>(&config_content) {
                    Ok(config) => {
                        if let Some(uk) = config
                            .get("clientConfig")
                            .and_then(|cc| cc.get("userkey"))
                            .and_then(|k| k.as_str())
                        {
                            if !uk.is_empty() {
                                out.push(("netskope/userkey".into(), uk.into()));
                                user_key = Some(uk.to_string());
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
                        warn!("Failed to parse Netskope config JSON: {}", e);
                        debug!("Netskope raw content: {}", config_content);
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Netskope config file exists but failed to read: {} - {}",
                    nsconfig_path, e
                );
            }
        }
    } else {
        debug!("Netskope config file not found: {}", nsconfig_path);
    }

    // The provisioning "device UID" lives in a platform-specific store that is
    // separate from nsconfig.json (macOS plist / Windows registry). Combined
    // with the user key it forms Netskope's composite device identifier
    // (`<userkey>_<nsdeviceuid>`), the value the Netskope backend keys devices on.
    if let Some(device_uid) = discover_netskope_device_uid().await {
        out.push(("netskope/nsdeviceuid".into(), device_uid.clone()));
        debug!("Found Netskope device UID");
        if let Some(user_key) = user_key.as_ref() {
            out.push((
                "netskope/device_id".into(),
                format!("{}_{}", user_key, device_uid),
            ));
            debug!("Assembled Netskope composite device_id");
        }
    }

    out
}

/// Discover the Netskope provisioning **device UID** (`nsdeviceuid`).
///
/// This value is stored in a platform-specific *provisioning* store, distinct
/// from `nsconfig.json` (which carries the user key, hostname and serial):
///
/// | Platform | Location | Field |
/// |----------|----------|-------|
/// | macOS    | `/Library/Preferences/com.netskope.provisioning.plist`   | `nsdeviceuid`   |
/// | Windows  | `HKLM\SOFTWARE\NetSkope\Provisioning` (or WOW6432Node)   | `nsdeviceidnew` |
/// | Linux    | not exposed by the Netskope client                       | (none)          |
///
/// Combined with the user key from `nsconfig.json`, `<userkey>_<nsdeviceuid>` is
/// the composite device identifier Netskope uses on its backend.
async fn discover_netskope_device_uid() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let plist_path = "/Library/Preferences/com.netskope.provisioning.plist";
        if !Path::new(plist_path).exists() {
            debug!("Netskope provisioning plist not found: {}", plist_path);
            return None;
        }
        // `defaults` reads both binary and XML plists; the domain argument is the
        // plist path WITHOUT the `.plist` suffix. No personation is required for a
        // global /Library/Preferences store (get_peer_ids already gates on admin).
        let cmd = "defaults read /Library/Preferences/com.netskope.provisioning nsdeviceuid";
        match run_cli(cmd, "", false, Some(20)).await {
            Ok(uid) => {
                let uid = uid.trim().to_string();
                if uid.is_empty() {
                    debug!("Netskope nsdeviceuid present but empty (macOS)");
                    None
                } else {
                    debug!("Found Netskope device UID (macOS provisioning plist)");
                    Some(uid)
                }
            }
            Err(e) => {
                debug!("Netskope nsdeviceuid not readable (macOS plist): {}", e);
                None
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Only spawn PowerShell if the Netskope client is actually installed.
        let installed = Path::new(r"C:\ProgramData\netskopestagent").exists()
            || Path::new(r"C:\ProgramData\Netskope").exists();
        if !installed {
            debug!("Netskope ProgramData directory not found; skipping registry probe");
            return None;
        }
        // The Netskope client stores the provisioning device UID in the registry
        // as `nsdeviceidnew`. A 32-bit client is redirected under WOW6432Node, so
        // probe both the native and WOW64 views.
        let cmd = r#"$v = $null
foreach ($p in @('HKLM:\SOFTWARE\NetSkope\Provisioning','HKLM:\SOFTWARE\WOW6432Node\NetSkope\Provisioning')) {
  try { $v = (Get-ItemProperty -Path $p -Name nsdeviceidnew -ErrorAction Stop).nsdeviceidnew } catch { }
  if ($v) { break }
}
if ($v) { Write-Output $v } else { exit 1 }"#;
        match run_cli(cmd, "", false, Some(20)).await {
            Ok(uid) => {
                let uid = uid.trim().to_string();
                if uid.is_empty() {
                    debug!("Netskope nsdeviceidnew present but empty (Windows)");
                    None
                } else {
                    debug!("Found Netskope device UID (Windows registry)");
                    Some(uid)
                }
            }
            Err(e) => {
                debug!(
                    "Netskope nsdeviceidnew not readable (Windows registry): {}",
                    e
                );
                None
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        // The Netskope Linux client does not expose a provisioning store for the
        // device UID (only classification data under
        // /opt/netskope/stagent/data/nsdeviceid.json), so there is nothing to read.
        debug!("Netskope device UID discovery not supported on this platform");
        None
    }
}

/* -------------------------------------------------------------------------- */
/*                              Public function                               */
/* -------------------------------------------------------------------------- */

/// Try to discover peer- or gateway-IDs for the VPN / ZTNA agents that may be
/// installed on the local host.  Runs entirely from userspace, never needs
/// elevation; any missing binary, socket or registry key is simply skipped.
///
/// The tuple returned is always (vendor_tag, peer_or_gateway_id).
pub async fn get_peer_ids(username: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    // Abort early if we don't have admin privileges.
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    if !get_admin_status() {
        warn!("Running as non-admin, skipping VPN/ZTNA agent discovery");
        return out;
    }
    debug!("Running as admin");

    // Run the discovery routines concurrently.
    let (mut tailscale_ids, mut zerotier_ids, mut netbird_ids, mut netskope_ids) = tokio::join!(
        discover_tailscale(username),
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

        let user = std::env::var("USER").unwrap_or_else(|_| "".to_string());
        let peer_ids = get_peer_ids(&user).await;
        println!("Peer IDs: {:?}", peer_ids);
    }
}
