use crate::cloud_model::*;
use crate::customlock::*;
use crate::lanscan::blacklists_db::BLACKLISTS;
use crate::lanscan::sessions::{Session, SessionInfo};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};

// Constants
const BLACKLISTS_FILE_NAME: &str = "blacklists-db.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct BlacklistInfo {
    pub name: String,
    pub description: Option<String>,
    pub last_updated: Option<String>,
    pub source_url: Option<String>,
    pub ip_ranges: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)] // Enforce no unknown fields
pub struct BlacklistsJSON {
    pub date: String,
    pub signature: String,
    pub blacklists: Vec<BlacklistInfo>,
}

#[derive(Clone)]
pub struct Blacklists {
    pub date: String,
    pub signature: String,
    pub blacklists: Arc<CustomDashMap<String, BlacklistInfo>>,
    // Cache for parsed IP ranges for performance
    pub parsed_ranges: Arc<CustomDashMap<String, Vec<IpNet>>>,
}

impl From<Blacklists> for BlacklistsJSON {
    fn from(blacklists: Blacklists) -> Self {
        BlacklistsJSON {
            date: blacklists.date,
            signature: blacklists.signature,
            blacklists: blacklists
                .blacklists
                .iter()
                .map(|r| r.value().clone())
                .collect(),
        }
    }
}

impl CloudSignature for Blacklists {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

lazy_static! {
    static ref LOCAL_IPV4_RANGES_TO_FILTER: Vec<IpNet> = vec![
        "0.0.0.0/8".parse().expect("Failed to parse 0.0.0.0/8"),       // Unspecified range
        "10.0.0.0/8".parse().expect("Failed to parse 10.0.0.0/8"),      // Private Class A
        "127.0.0.0/8".parse().expect("Failed to parse 127.0.0.0/8"),     // Loopback
        "169.254.0.0/16".parse().expect("Failed to parse 169.254.0.0/16"),  // Link-Local
        "172.16.0.0/12".parse().expect("Failed to parse 172.16.0.0/12"),   // Private Class B
        "192.168.0.0/16".parse().expect("Failed to parse 192.168.0.0/16"),  // Private Class C
    ];
    static ref LOCAL_IPV6_RANGES_TO_FILTER: Vec<IpNet> = vec![
        "::/128".parse().expect("Failed to parse ::/128"),          // Unspecified
        "::1/128".parse().expect("Failed to parse ::1/128"),         // Loopback
        "fc00::/7".parse().expect("Failed to parse fc00::/7"),        // Unique Local Address (ULA)
        "fe80::/10".parse().expect("Failed to parse fe80::/10"),       // Link-Local
    ];
}

/// Checks if a given IpNet is entirely contained within known local/private ranges.
fn is_range_local_to_filter(net_to_check: &IpNet) -> bool {
    match net_to_check {
        IpNet::V4(v4_net_to_check) => {
            for local_v4_range in LOCAL_IPV4_RANGES_TO_FILTER.iter() {
                if local_v4_range.contains(&IpNet::V4(*v4_net_to_check)) {
                    return true;
                }
            }
        }
        IpNet::V6(v6_net_to_check) => {
            for local_v6_range in LOCAL_IPV6_RANGES_TO_FILTER.iter() {
                if local_v6_range.contains(&IpNet::V6(*v6_net_to_check)) {
                    return true;
                }
            }
        }
    }
    false
}

impl Blacklists {
    /// Creates a new Blacklists instance from the provided JSON data.
    /// If `filter_local_ranges` is true, known local/private IP ranges will be omitted.
    pub fn new_from_json(blacklist_info_json: BlacklistsJSON, filter_local_ranges: bool) -> Self {
        if filter_local_ranges {
            info!("Loading blacklists from JSON and filtering known local/private ranges.");
        } else {
            info!("Loading blacklists from JSON without filtering local/private ranges (custom blacklist).");
        }

        let blacklists_map = Arc::new(CustomDashMap::new("blacklists"));
        let parsed_ranges_map = Arc::new(CustomDashMap::new("parsed_ranges"));

        for info_orig in blacklist_info_json.blacklists {
            let list_name = info_orig.name.clone();

            let mut filtered_ip_range_strings = Vec::new();
            let mut current_list_parsed_nets = Vec::new();

            for ip_range_str in &info_orig.ip_ranges {
                let ip_str_to_parse = if let Ok(ip) = ip_range_str.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(_) => format!("{}/32", ip_range_str),
                        IpAddr::V6(_) => format!("{}/128", ip_range_str),
                    }
                } else {
                    ip_range_str.clone()
                };

                match ip_str_to_parse.parse::<IpNet>() {
                    Ok(net) => {
                        if filter_local_ranges && is_range_local_to_filter(&net) {
                            info!(
                                "Filtering local range {} from blacklist {} during load.",
                                net, list_name
                            );
                        } else {
                            current_list_parsed_nets.push(net);
                            filtered_ip_range_strings.push(ip_range_str.clone());
                            // Keep original string if not filtered
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse IP range '{}' from blacklist '{}': {}",
                            ip_range_str, list_name, e
                        );
                    }
                }
            }

            if !current_list_parsed_nets.is_empty() {
                parsed_ranges_map.insert(list_name.clone(), current_list_parsed_nets);
            }

            // Store BlacklistInfo with potentially filtered ip_ranges (string list)
            let new_info = BlacklistInfo {
                name: info_orig.name,
                description: info_orig.description,
                last_updated: info_orig.last_updated,
                source_url: info_orig.source_url,
                ip_ranges: filtered_ip_range_strings, // Use the filtered list of strings
            };
            blacklists_map.insert(list_name.clone(), new_info);
        }

        info!(
            "Loaded {} blacklists (after any filtering).",
            blacklists_map.len()
        );

        Blacklists {
            date: blacklist_info_json.date,
            signature: blacklist_info_json.signature,
            blacklists: blacklists_map,
            parsed_ranges: parsed_ranges_map,
        }
    }

    /// Retrieves all IP ranges for a given blacklist.
    fn get_all_ip_ranges(&self, blacklist_name: &str) -> Result<Vec<IpNet>> {
        // Get the blacklist info and handle the case where it's not found
        let _info = self
            .blacklists
            .get(blacklist_name)
            .ok_or_else(|| anyhow!("Blacklist not found: {}", blacklist_name))?;

        // Get the parsed ranges for this blacklist
        let ip_ranges = match self.parsed_ranges.get(blacklist_name) {
            Some(ranges) => ranges.clone(),
            None => Vec::new(),
        };

        Ok(ip_ranges)
    }

    /// Checks if a given IP is in the blacklist.
    pub fn is_ip_in_blacklist(&self, ip_str: &str, blacklist_name: &str) -> Result<bool> {
        // Add detailed logging for IP checking
        trace!(
            "Checking if IP '{}' is in blacklist '{}'",
            ip_str,
            blacklist_name
        );

        let ip = match ip_str.parse::<IpAddr>() {
            Ok(addr) => addr,
            Err(e) => {
                warn!("Invalid IP address '{}': {}", ip_str, e);
                return Err(anyhow!("Invalid IP address: {}", e));
            }
        };

        let ranges = match self.get_all_ip_ranges(blacklist_name) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "Error getting ranges for blacklist '{}': {}",
                    blacklist_name, e
                );
                return Err(e);
            }
        };

        trace!(
            "Found {} IP ranges in blacklist '{}'",
            ranges.len(),
            blacklist_name
        );

        // Debug print all ranges
        for (i, range) in ranges.iter().enumerate().take(10) {
            // Only print first 10 to avoid log spam
            trace!("  Range {}: {}", i + 1, range);
        }
        if ranges.len() > 10 {
            trace!("  ... and {} more ranges", ranges.len() - 10);
        }

        for range in ranges {
            trace!("Checking if IP '{}' is in range '{}'", ip, range);
            if range.contains(&ip) {
                trace!(
                    "✓ MATCH: IP '{}' matched blacklist '{}' with range '{}'",
                    ip_str,
                    blacklist_name,
                    range
                );
                return Ok(true);
            }
        }

        trace!(
            "✗ NO MATCH: IP '{}' is not in any range for blacklist '{}'",
            ip_str,
            blacklist_name
        );
        Ok(false)
    }
}

lazy_static! {
    static ref LISTS: CloudModel<Blacklists> = {
        let model = CloudModel::initialize(BLACKLISTS_FILE_NAME.to_string(), BLACKLISTS, |data| {
            let blacklist_info_json: BlacklistsJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            // Filter local ranges for default/embedded blacklists
            Ok(Blacklists::new_from_json(blacklist_info_json, true))
        })
        .expect("Failed to initialize CloudModel");
        model
    };

    // Cache: IP -> Vec<matching list names>
    // Keep private, manage through functions in this module
    static ref IP_CACHE: CustomDashMap<String, Vec<String>> = CustomDashMap::new("ip_cache");

    // Track the last time we ran the recomputation as well as the blacklist
    static ref LAST_BLACKLIST_RUN: Arc<CustomRwLock<DateTime<Utc>>> =
        Arc::new(CustomRwLock::new(DateTime::<Utc>::from(std::time::UNIX_EPOCH)));

    // Flag indicating a full blacklist recompute is required.
    static ref NEED_FULL_RECOMPUTE_BLACKLIST: AtomicBool = AtomicBool::new(false);
}

// Private helper function to clear the cache
fn clear_ip_cache() {
    trace!("Clearing blacklist IP cache.");
    IP_CACHE.clear();
}

/// Checks if a blacklist name exists in the current model (default or custom).
pub async fn is_valid_blacklist(blacklist_name: &str) -> bool {
    let blacklists_map = LISTS.data.read().await.blacklists.clone();
    blacklists_map.contains_key(blacklist_name)
}

/// Checks if a given IP is blacklisted.
/// Returns a tuple (bool, Vec<String>) where:
/// - The boolean indicates whether the IP is blacklisted in any list
/// - The Vec<String> contains the names of all blacklists that match
pub async fn is_ip_blacklisted(ip: &str) -> (bool, Vec<String>) {
    // Add more verbose debug logging for blacklist issues
    trace!("Checking if IP: {} is blacklisted", ip);

    // Cache key using IP only (cache cleared on updates)
    let cache_key = ip.to_string();

    if let Some(entry) = IP_CACHE.get(&cache_key) {
        let lists = entry.clone();
        return (!lists.is_empty(), lists);
    }

    let mut matching_blacklists = Vec::new();

    // Take a snapshot of the current blacklist names to avoid holding any DashMap
    // iterator guards while performing the (potentially expensive) per-list checks.
    let list_data = LISTS.data.read().await;
    let blacklist_names: Vec<String> = list_data
        .blacklists
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    let list_data_instance = list_data.clone();
    // Drop the original read lock *and* the iterator guard before iterating again.
    drop(list_data);

    // Now iterate over the collected names without holding any DashMap guard.
    for blacklist_name in blacklist_names {
        trace!("Checking blacklist: {} for IP: {}", blacklist_name, ip);

        let result = list_data_instance.is_ip_in_blacklist(ip, &blacklist_name);

        match result {
            Ok(true) => {
                debug!("IP {} matched blacklist {}", ip, &blacklist_name);
                matching_blacklists.push(blacklist_name);
            }
            Ok(false) => {
                trace!("IP {} did NOT match blacklist {}", ip, &blacklist_name);
            }
            Err(e) => {
                warn!("Error checking blacklist {}: {}", &blacklist_name, e);
            }
        }
    }

    let is_blacklisted = !matching_blacklists.is_empty();
    if is_blacklisted {
        info!(
            "IP {} blacklisted: {}, matching lists: {:?}",
            ip, is_blacklisted, matching_blacklists
        );
    }

    let result = (is_blacklisted, matching_blacklists.clone());

    // Store in cache
    IP_CACHE.insert(cache_key, matching_blacklists);

    result
}

/// Updates the blacklists by fetching the latest data from the specified branch.
/// This function utilizes the `CloudModel` to perform the update.
pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting blacklists update from backend");

    let status = LISTS
        .update(branch, force, |data| {
            let blacklist_info_json: BlacklistsJSON =
                serde_json::from_str(data).with_context(|| "Failed to parse JSON data")?;
            // Filter local ranges for updated default blacklists
            Ok(Blacklists::new_from_json(blacklist_info_json, true))
        })
        .await?;

    // Clear IP cache as underlying data changed
    clear_ip_cache();
    // Signal need for full recomputation
    NEED_FULL_RECOMPUTE_BLACKLIST.store(true, Ordering::SeqCst);

    match status {
        UpdateStatus::Updated => info!("Blacklists were successfully updated."),
        UpdateStatus::NotUpdated => info!("Blacklists are already up to date."),
        UpdateStatus::FormatError => warn!("There was a format error in the blacklists data."),
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom blacklists are in use.")
        }
    }

    Ok(status)
}

/// Sets custom blacklist data, replacing the current data (default or previous custom).
/// Clears the IP cache upon successful update or reset.
pub async fn set_custom_blacklists(blacklist_json: &str) -> Result<(), anyhow::Error> {
    info!("Attempting to set custom blacklists.");
    if blacklist_json.is_empty() {
        info!("Received empty JSON, resetting blacklists to default.");
        LISTS.reset_to_default().await; // This will re-initialize with filtering
        clear_ip_cache();
        NEED_FULL_RECOMPUTE_BLACKLIST.store(true, Ordering::SeqCst);
        return Ok(());
    }

    let blacklist_result = serde_json::from_str::<BlacklistsJSON>(blacklist_json);

    match blacklist_result {
        Ok(blacklist_data) => {
            info!("Successfully parsed custom blacklist JSON.");
            // Do NOT filter local ranges for custom blacklists
            let blacklist = Blacklists::new_from_json(blacklist_data, false);
            LISTS.set_custom_data(blacklist).await;
            clear_ip_cache();
            NEED_FULL_RECOMPUTE_BLACKLIST.store(true, Ordering::SeqCst);
            return Ok(());
        }
        Err(e) => {
            error!(
                "Error parsing custom blacklist JSON: {}. Resetting to default.",
                e
            );
            LISTS.reset_to_default().await;
            clear_ip_cache(); // Clear cache after reset due to error
            NEED_FULL_RECOMPUTE_BLACKLIST.store(true, Ordering::SeqCst);
            return Err(anyhow!("Error parsing custom blacklist JSON: {}", e));
        }
    }
}

// ----- Incremental Session Blacklist Recalculation -----
// The following helper maintains an incremental mechanism for recalculating the
// blacklist related criticality and auxiliary data for a large `DashMap` of
// `SessionInfo`.  The heavy part of the computation (iterating all blacklist
// CIDR ranges) is only done for sessions that have actually been *modified*
// since the last execution **or** when the blacklist CloudModel has changed
// ( signature is different ) is now handled internally in this module; callers only
// need to rely on the NEED_FULL_RECOMPUTE_BLACKLIST flag which is toggled by
// update/set_custom/reset helpers.

/// Incrementally (re)calculates the blacklist criticality for the supplied
/// session map.
///
/// * `sessions` – the central DashMap containing all sessions.
/// * `blacklisted_sessions` – shared vector of keys of sessions currently
///   considered black-listed.  This is updated atomically at the end of the
///   run.
pub async fn recompute_blacklist_for_sessions(
    sessions: &Arc<CustomDashMap<Session, SessionInfo>>,
    blacklisted_sessions: &Arc<CustomRwLock<Vec<Session>>>,
) {
    debug!("Starting incremental blacklist recomputation");

    // Determine if a full recomputation has been signalled via the global flag.
    let db_changed = NEED_FULL_RECOMPUTE_BLACKLIST.swap(false, Ordering::SeqCst);

    // Snapshot last run timestamp (then release lock to avoid holding across await)
    let last_run_ts = {
        let guard = LAST_BLACKLIST_RUN.read().await;
        *guard
    };

    let full_recompute = db_changed;

    // Collection phase - gather all data we need without holding locks
    // ----------------------------------------------------------------------------------

    // 1a. Get all current blacklist names and create working sets
    let list_data = LISTS.data.read().await.clone(); // Take a clone to avoid holding the lock
    let blacklist_names: Vec<String> = list_data
        .blacklists
        .iter()
        .map(|entry| entry.key().clone())
        .collect();

    // 1b. Collect existing blacklisted sessions (with filtering)
    let existing_blacklisted = {
        let current = blacklisted_sessions.read().await.clone();
        // Only keep sessions that still exist in the map
        current
            .into_iter()
            .filter(|session| sessions.contains_key(session))
            .collect::<Vec<Session>>()
    };

    // 1c. Collect sessions we need to evaluate with their snapshots
    let (sessions_to_evaluate, session_snapshots) = {
        // Determine which sessions to evaluate based on full_recompute flag
        let to_evaluate: Vec<Session> = if full_recompute {
            // If full recompute, gather all sessions
            sessions.iter().map(|entry| entry.key().clone()).collect()
        } else {
            // Otherwise just sessions modified since last run
            sessions
                .iter()
                .filter(|entry| entry.value().last_modified > last_run_ts)
                .map(|entry| entry.key().clone())
                .collect()
        };

        // Take snapshots of all sessions we need to evaluate
        let mut snapshots = HashMap::with_capacity(to_evaluate.len());
        for session_key in &to_evaluate {
            if let Some(entry) = sessions.get(session_key) {
                snapshots.insert(session_key.clone(), entry.clone());
            }
        }

        (to_evaluate, snapshots)
    };

    info!(
        "Blacklist evaluation: evaluating {} sessions out of total {}",
        sessions_to_evaluate.len(),
        sessions.len()
    );

    // Evaluation phase - compute all blacklist results without locks
    // ----------------------------------------------------------------------------------

    // Start with existing blacklisted sessions as our base
    let mut new_blacklisted_sessions = existing_blacklisted.clone();

    // Store update information for each session
    struct SessionUpdate {
        key: Session,
        new_criticality: String,
    }

    let mut updates = Vec::with_capacity(sessions_to_evaluate.len());

    info!("Processing {} sessions", sessions_to_evaluate.len());

    for session_key in &sessions_to_evaluate {
        // Skip if we don't have a snapshot (session might have been removed)
        if let Some(snapshot) = session_snapshots.get(session_key) {
            let src_ip = snapshot.session.src_ip.to_string();
            let dst_ip = snapshot.session.dst_ip.to_string();

            // Perform blacklist matching - this is the expensive part
            let mut matching_names = Vec::<String>::new();

            for list_name in &blacklist_names {
                let mut matched = false;
                if !snapshot.is_local_src {
                    if let Ok(true) = list_data.is_ip_in_blacklist(&src_ip, list_name) {
                        matched = true;
                    }
                }
                if !matched && !snapshot.is_local_dst {
                    if let Ok(true) = list_data.is_ip_in_blacklist(&dst_ip, list_name) {
                        matched = true;
                    }
                }
                if matched {
                    matching_names.push(list_name.clone());
                }
            }

            // Build final criticality combining existing non-blacklist tags
            let non_bl_tags: Vec<String> = snapshot
                .criticality
                .split(',')
                .filter(|s| !s.is_empty() && !s.starts_with("blacklist:"))
                .map(|s| s.to_string())
                .collect();

            let mut final_tags = non_bl_tags;
            if !matching_names.is_empty() {
                let new_tags: Vec<String> = matching_names
                    .iter()
                    .map(|n| format!("blacklist:{}", n))
                    .collect();
                final_tags.extend(new_tags);
            }

            final_tags.sort();
            final_tags.dedup();
            let new_criticality = final_tags.join(",");

            // Only create an update if criticality changed
            if snapshot.criticality != new_criticality {
                updates.push(SessionUpdate {
                    key: session_key.clone(),
                    new_criticality,
                });
            }

            // Update our working blacklisted sessions list
            if !matching_names.is_empty() {
                if !new_blacklisted_sessions.contains(session_key) {
                    new_blacklisted_sessions.push(session_key.clone());
                }
            } else {
                new_blacklisted_sessions.retain(|s| s != session_key);
            }
        }
    }

    // Update phase - apply all changes with minimal lock time
    // ----------------------------------------------------------------------------------

    trace!(
        "Applying {} blacklist updates with minimal lock time",
        updates.len()
    );

    // Store the update count before consuming the vector
    let update_count = updates.len();

    // Apply updates to sessions - very brief locks per session
    let now = Utc::now();
    for update in updates {
        // Very brief write lock just for the update
        if let Some(mut entry) = sessions.get_mut(&update.key) {
            let info_mut = entry.value_mut();

            // Update criticality if different
            if info_mut.criticality != update.new_criticality {
                info_mut.criticality = update.new_criticality;
                info_mut.last_modified = now;
            }
        }
    }

    // OPTIMIZATION 3: Minimize write lock time by preparing data before acquiring the lock
    new_blacklisted_sessions.sort();
    new_blacklisted_sessions.dedup();

    // Check if the blacklisted sessions list has actually changed
    let has_changed = {
        let current = blacklisted_sessions.read().await;
        let mut current_sorted = current.clone();
        current_sorted.sort();
        current_sorted != new_blacklisted_sessions
    };

    // Only acquire write lock if the list changed
    if has_changed {
        let old_len = blacklisted_sessions.read().await.len();
        trace!(
            "Updating blacklisted sessions list: {} items -> {} items",
            old_len,
            new_blacklisted_sessions.len()
        );
        *blacklisted_sessions.write().await = new_blacklisted_sessions;
    } else {
        trace!(
            "Blacklisted sessions list unchanged ({} items)",
            new_blacklisted_sessions.len()
        );
    }

    // Update last run timestamp.
    {
        let mut guard = LAST_BLACKLIST_RUN.write().await;
        *guard = Utc::now();
    }

    info!(
        "Optimized blacklist recomputation completed ({} sessions evaluated, {} updates applied)",
        sessions_to_evaluate.len(),
        update_count
    );
}

// ----- Public wrapper helpers (LISTS remains private) -----

/// Reset the blacklist CloudModel to its built-in/default data set.
pub async fn reset_to_default() {
    LISTS.reset_to_default().await;
    clear_ip_cache();
    NEED_FULL_RECOMPUTE_BLACKLIST.store(true, Ordering::SeqCst);
}

/// Returns `true` when a custom blacklist set is active.
pub async fn is_custom() -> bool {
    LISTS.is_custom().await
}

/// Obtain a snapshot of the current blacklist data as `BlacklistsJSON`.
pub async fn current_json() -> BlacklistsJSON {
    let data = LISTS.data.read().await.clone();
    BlacklistsJSON::from(data)
}

pub async fn get_blacklists() -> String {
    let list_model = &LISTS;
    let data = list_model.data.read().await;
    let json_data = BlacklistsJSON::from(data.clone()); // Clone the data inside the lock
    serde_json::to_string(&json_data).unwrap_or_default()
}

/// Overwrite the CloudModel with test data (for unit-tests/integration tests).
#[cfg(test)]
pub async fn overwrite_with_test_data(data: Blacklists) {
    LISTS.overwrite_with_test_data(data).await;
    clear_ip_cache();
    NEED_FULL_RECOMPUTE_BLACKLIST.store(true, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Helper function to initialize LISTS with controlled test data
    async fn initialize_test_blacklists_for_filtering_tests() -> BlacklistsJSON {
        // Clear the IP cache to ensure test isolation
        IP_CACHE.clear();
        NEED_FULL_RECOMPUTE_BLACKLIST.store(false, Ordering::SeqCst);

        let test_blacklist_json = BlacklistsJSON {
            date: "2025-03-30".to_string(),
            signature: "filtering_test_signature".to_string(),
            blacklists: vec![
                BlacklistInfo {
                    name: "mixed_list".to_string(),
                    description: Some("List with mixed local and public ranges".to_string()),
                    last_updated: Some("2025-03-30".to_string()),
                    source_url: None,
                    ip_ranges: vec![
                        "192.168.1.0/24".to_string(),           // Local IPv4 range
                        "10.0.0.0/8".to_string(),               // Local IPv4 range
                        "127.0.0.1/32".to_string(),             // Local IPv4 single
                        "fe80::/10".to_string(),                // Link-local IPv6 range
                        "fc00::1/128".to_string(),              // Unique Local IPv6 single
                        "::1/128".to_string(),                  // IPv6 Loopback
                        "8.8.8.8/32".to_string(),               // Public IPv4 single
                        "2001:4860:4860::8888/128".to_string(), // Public IPv6 single
                        "9.9.9.0/24".to_string(),               // Public IPv4 range
                    ],
                },
                BlacklistInfo {
                    name: "all_local_list".to_string(),
                    description: Some("List with only local ranges".to_string()),
                    last_updated: Some("2025-03-30".to_string()),
                    source_url: None,
                    ip_ranges: vec!["172.16.0.0/12".to_string(), "169.254.10.20/32".to_string()],
                },
                BlacklistInfo {
                    name: "all_public_list".to_string(),
                    description: Some("List with only public ranges".to_string()),
                    last_updated: Some("2025-03-30".to_string()),
                    source_url: None,
                    ip_ranges: vec![
                        "1.1.1.1/32".to_string(),
                        "2606:4700:4700::1111/128".to_string(),
                    ],
                },
            ],
        };
        test_blacklist_json
    }

    #[tokio::test]
    #[serial]
    async fn test_blacklist_loading_with_local_filtering() {
        let json_data = initialize_test_blacklists_for_filtering_tests().await;
        let blacklists = Blacklists::new_from_json(json_data, true); // filter_local_ranges = true

        // Check "mixed_list"
        let mixed_list_info = blacklists
            .blacklists
            .get("mixed_list")
            .expect("mixed_list should exist");
        let mixed_list_ranges = &mixed_list_info.ip_ranges;

        assert!(
            mixed_list_ranges.contains(&"8.8.8.8/32".to_string()),
            "Public IPv4 single should be present"
        );
        assert!(
            mixed_list_ranges.contains(&"2001:4860:4860::8888/128".to_string()),
            "Public IPv6 single should be present"
        );
        assert!(
            mixed_list_ranges.contains(&"9.9.9.0/24".to_string()),
            "Public IPv4 range should be present"
        );

        assert!(
            !mixed_list_ranges.contains(&"192.168.1.0/24".to_string()),
            "Local 192.168.1.0/24 should be filtered"
        );
        assert!(
            !mixed_list_ranges.contains(&"10.0.0.0/8".to_string()),
            "Local 10.0.0.0/8 should be filtered"
        );
        assert!(
            !mixed_list_ranges.contains(&"127.0.0.1/32".to_string()),
            "Local 127.0.0.1/32 should be filtered"
        );
        assert!(
            !mixed_list_ranges.contains(&"fe80::/10".to_string()),
            "Local fe80::/10 should be filtered"
        );
        assert!(
            !mixed_list_ranges.contains(&"fc00::1/128".to_string()),
            "Local fc00::1/128 should be filtered"
        );
        assert!(
            !mixed_list_ranges.contains(&"::1/128".to_string()),
            "Local ::1/128 should be filtered"
        );

        let mixed_list_parsed_ranges = blacklists
            .parsed_ranges
            .get("mixed_list")
            .expect("parsed_ranges for mixed_list");
        assert_eq!(
            mixed_list_parsed_ranges.len(),
            3,
            "mixed_list should have 3 parsed public ranges"
        );

        // Check "all_local_list"
        let all_local_info = blacklists
            .blacklists
            .get("all_local_list")
            .expect("all_local_list should exist");
        assert!(
            all_local_info.ip_ranges.is_empty(),
            "all_local_list strings should be empty after filtering"
        );
        assert!(
            !blacklists.parsed_ranges.contains_key("all_local_list"),
            "all_local_list should have no parsed ranges after filtering"
        );

        // Check "all_public_list"
        let all_public_info = blacklists
            .blacklists
            .get("all_public_list")
            .expect("all_public_list should exist");
        assert_eq!(
            all_public_info.ip_ranges.len(),
            2,
            "all_public_list strings should have 2 entries"
        );
        let all_public_parsed = blacklists
            .parsed_ranges
            .get("all_public_list")
            .expect("parsed_ranges for all_public_list");
        assert_eq!(
            all_public_parsed.len(),
            2,
            "all_public_list should have 2 parsed public ranges"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_blacklist_loading_without_local_filtering_custom() {
        let json_data = initialize_test_blacklists_for_filtering_tests().await;
        // Simulate custom blacklist loading by calling new_from_json directly with filter_local_ranges = false
        let blacklists = Blacklists::new_from_json(json_data.clone(), false);

        // Check "mixed_list" - all original ranges should be present
        let mixed_list_info = blacklists
            .blacklists
            .get("mixed_list")
            .expect("mixed_list should exist");
        let original_mixed_list_count = json_data
            .blacklists
            .iter()
            .find(|b| b.name == "mixed_list")
            .unwrap()
            .ip_ranges
            .len();
        assert_eq!(
            mixed_list_info.ip_ranges.len(),
            original_mixed_list_count,
            "All ranges should be present in mixed_list strings for custom load"
        );

        let mixed_list_parsed_ranges = blacklists
            .parsed_ranges
            .get("mixed_list")
            .expect("parsed_ranges for mixed_list for custom load");
        assert_eq!(
            mixed_list_parsed_ranges.len(),
            original_mixed_list_count,
            "All ranges should be parsed in mixed_list for custom load"
        );

        // Check "all_local_list" - all original ranges should be present
        let all_local_info = blacklists
            .blacklists
            .get("all_local_list")
            .expect("all_local_list should exist");
        let original_all_local_count = json_data
            .blacklists
            .iter()
            .find(|b| b.name == "all_local_list")
            .unwrap()
            .ip_ranges
            .len();
        assert_eq!(
            all_local_info.ip_ranges.len(),
            original_all_local_count,
            "All ranges should be present in all_local_list strings for custom load"
        );
        let all_local_parsed_ranges = blacklists
            .parsed_ranges
            .get("all_local_list")
            .expect("parsed_ranges for all_local_list for custom load");
        assert_eq!(
            all_local_parsed_ranges.len(),
            original_all_local_count,
            "All ranges should be parsed in all_local_list for custom load"
        );

        // Test actual `set_custom_blacklists` flow
        let json_string = serde_json::to_string(&json_data).unwrap();
        set_custom_blacklists(&json_string)
            .await
            .expect("Failed to set custom blacklists");

        let custom_loaded_data = LISTS.data.read().await;
        let custom_mixed_list_info = custom_loaded_data
            .blacklists
            .get("mixed_list")
            .expect("mixed_list via LISTS");
        assert_eq!(
            custom_mixed_list_info.ip_ranges.len(),
            original_mixed_list_count,
            "Custom set via LISTS: mixed_list strings incorrect"
        );
        let custom_mixed_parsed = custom_loaded_data
            .parsed_ranges
            .get("mixed_list")
            .expect("parsed_ranges for mixed_list via LISTS");
        assert_eq!(
            custom_mixed_parsed.len(),
            original_mixed_list_count,
            "Custom set via LISTS: mixed_list parsed incorrect"
        );

        // Reset to default to ensure it re-filters
        LISTS.reset_to_default().await;
        let default_data_after_reset = LISTS.data.read().await;
        // This check assumes the default embedded blacklist (BLACKLISTS string) also has some filterable content
        // or at least exercises the filtering path. A more specific check would require knowing its content.
        // For now, just ensure it doesn't crash and some lists are loaded.
        assert!(
            !default_data_after_reset.blacklists.is_empty(),
            "Default blacklists (after reset) should not be empty"
        );
    }

    /// Original helper, may need adjustment or new tests if it relied on local IPs in default data
    async fn initialize_test_blacklists() {
        IP_CACHE.clear();
        NEED_FULL_RECOMPUTE_BLACKLIST.store(false, Ordering::SeqCst);

        let test_blacklist_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test_signature".to_string(),
            blacklists: vec![
                BlacklistInfo {
                    name: "base_blacklist".to_string(),
                    description: Some("Base test blacklist".to_string()),
                    last_updated: Some("2025-03-29".to_string()),
                    source_url: None,
                    // These will be filtered if loaded as "default"
                    ip_ranges: vec![
                        "192.168.0.0/16".to_string(),
                        "10.0.0.0/8".to_string(),
                        "8.8.8.8/32".to_string(),
                    ],
                },
                BlacklistInfo {
                    name: "another_blacklist".to_string(),
                    description: Some("Another test blacklist".to_string()),
                    last_updated: Some("2025-03-29".to_string()),
                    source_url: None,
                    // These will be filtered if loaded as "default"
                    ip_ranges: vec![
                        "172.16.0.0/12".to_string(),
                        "169.254.0.0/16".to_string(),
                        "9.9.9.9/32".to_string(),
                    ],
                },
            ],
        };

        // When using overwrite_with_test_data, it bypasses the CloudModel's own loading logic.
        // So, to test filtering, we must pass a pre-filtered Blacklists instance if desired.
        // For these older tests, let's assume they want unfiltered data as if it were custom.
        let blacklists = Blacklists::new_from_json(test_blacklist_json, false); // false = treat as custom
        LISTS.overwrite_with_test_data(blacklists).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_ip_matching() {
        initialize_test_blacklists().await;

        // Test IP in range
        let (is_blacklisted, _) = is_ip_blacklisted("192.168.1.1").await;
        assert!(is_blacklisted, "IP in range should be blacklisted");

        // Test IP not in range - corrected IP to one actually not in test lists
        let (is_blacklisted, _) = is_ip_blacklisted("1.2.3.4").await;
        assert!(
            !is_blacklisted,
            "IP 1.2.3.4 not in range should not be blacklisted"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_blacklist() {
        initialize_test_blacklists().await;

        // Test with IP that is not in any blacklist - corrected IP
        let (is_blacklisted, _) = is_ip_blacklisted("1.2.3.4").await;
        assert!(
            !is_blacklisted,
            "Should return false for non-blacklisted IP 1.2.3.4"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_is_valid_blacklist() {
        initialize_test_blacklists().await;

        assert!(
            is_valid_blacklist("base_blacklist").await,
            "Should return true for existing blacklist"
        );
        assert!(
            !is_valid_blacklist("nonexistent_blacklist").await,
            "Should return false for non-existent blacklist"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_ip_format() {
        initialize_test_blacklists().await;

        // Invalid IP format should return false
        let (is_blacklisted, _) = is_ip_blacklisted("not-an-ip").await;
        assert!(!is_blacklisted, "Invalid IP should not be blacklisted");
    }

    #[tokio::test]
    #[serial]
    async fn test_ipv6_support() {
        let test_blacklist_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test_signature".to_string(),
            blacklists: vec![BlacklistInfo {
                name: "ipv6_blacklist".to_string(),
                description: Some("IPv6 test blacklist".to_string()),
                last_updated: Some("2025-03-29".to_string()),
                source_url: None,
                ip_ranges: vec!["2001:db8::/32".to_string(), "::1/128".to_string()],
            }],
        };

        let blacklists = Blacklists::new_from_json(test_blacklist_json, false);
        LISTS.overwrite_with_test_data(blacklists).await;

        // Test IPv6 in range
        let (is_blacklisted, _) = is_ip_blacklisted("2001:db8:1:2:3:4:5:6").await;
        assert!(is_blacklisted, "IPv6 in range should be blacklisted");

        // Test IPv6 not in range
        let (is_blacklisted, _) = is_ip_blacklisted("2002:db8:1:2:3:4:5:6").await;
        assert!(
            !is_blacklisted,
            "IPv6 not in range should not be blacklisted"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_blacklist_ip_check() {
        initialize_test_blacklists().await;

        // Test with IP in blacklist range (192.168.1.10 is local, but loaded with filter_locals:false)
        let (is_blacklisted, _) = is_ip_blacklisted("192.168.1.10").await;
        assert!(is_blacklisted, "IP in range should be blacklisted");

        // Test with IP that is genuinely not in any of the test blacklists
        let (is_blacklisted_not_present, _) = is_ip_blacklisted("1.2.3.4").await;
        assert!(
            !is_blacklisted_not_present,
            "IP 1.2.3.4, not in any list, should not be blacklisted"
        );

        // Test with an IP that *is* in a list (8.8.8.8/32 in base_blacklist)
        let (is_blacklisted_present, _) = is_ip_blacklisted("8.8.8.8").await;
        assert!(
            is_blacklisted_present,
            "IP 8.8.8.8, present in base_blacklist, should be blacklisted"
        );

        // Test IP in second blacklist (172.16.1.1 is local, but loaded with filter_locals:false)
        let (is_blacklisted_another, _) = is_ip_blacklisted("172.16.1.1").await;
        assert!(
            is_blacklisted_another,
            "IP in second blacklist should be blacklisted"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_ipv6_blacklist() {
        let test_blacklist_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test_signature".to_string(),
            blacklists: vec![BlacklistInfo {
                name: "ipv6_blacklist".to_string(),
                description: Some("IPv6 test blacklist".to_string()),
                last_updated: Some("2025-03-29".to_string()),
                source_url: None,
                ip_ranges: vec!["2001:db8::/32".to_string(), "::1/128".to_string()],
            }],
        };

        let blacklists = Blacklists::new_from_json(test_blacklist_json, false);
        // Overwrite the global model directly for this test
        LISTS.overwrite_with_test_data(blacklists).await;

        // Test IPv6 in blacklist range
        let (is_blacklisted, _) = is_ip_blacklisted("2001:db8:1:2:3:4:5:6").await;
        assert!(is_blacklisted, "IPv6 in range should be blacklisted");

        // Test IPv6 not in range
        let (is_blacklisted, _) = is_ip_blacklisted("2002:db8:1:2:3:4:5:6").await;
        assert!(
            !is_blacklisted,
            "IPv6 not in range should not be blacklisted"
        );

        // Test IPv6 localhost
        let (is_blacklisted, _) = is_ip_blacklisted("::1").await;
        assert!(is_blacklisted, "IPv6 localhost should be blacklisted");

        // Reset LISTS back to default after the test
        LISTS.reset_to_default().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_empty_blacklist_name() {
        initialize_test_blacklists().await;

        // Empty blacklist name should never match (though the function currently loops through all)
        let (is_blacklisted, _) = is_ip_blacklisted("1.2.3.4").await;
        // The behavior depends on the test data; if 1.2.3.4 isn't in any list, it should be false.
        assert!(
            !is_blacklisted,
            "Empty blacklist name check (behavior test)"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_direct_ip_without_cidr() {
        // Ensure we start with a clean state
        IP_CACHE.clear();

        // Test blacklist with direct IPs without CIDR notation
        let test_blacklist_json = BlacklistsJSON {
            date: "2025-03-29".to_string(),
            signature: "test_direct_ip_signature".to_string(), // Use a unique signature
            blacklists: vec![BlacklistInfo {
                name: "direct_ip_blacklist".to_string(),
                description: Some("Direct IP test blacklist".to_string()),
                last_updated: Some("2025-03-29".to_string()),
                source_url: None,
                ip_ranges: vec![
                    "192.168.1.1".to_string(),     // IPv4 without CIDR
                    "2001:db8::1".to_string(),     // IPv6 without CIDR
                    "10.0.0.0/8".to_string(),      // IPv4 with CIDR
                    "2001:db8:1::/64".to_string(), // IPv6 with CIDR
                ],
            }],
        };

        // Create a fresh blacklist with only the test data to avoid cross-test interference
        let blacklists = Blacklists::new_from_json(test_blacklist_json, false);
        LISTS.overwrite_with_test_data(blacklists).await;

        // Test direct IPv4 without CIDR
        let (is_blacklisted, matching_lists) = is_ip_blacklisted("192.168.1.1").await;
        println!(
            "For IP 192.168.1.1: is_blacklisted={}, matching_lists={:?}",
            is_blacklisted, matching_lists
        );
        assert!(is_blacklisted, "IPv4 without CIDR should be blacklisted");
        assert!(
            matching_lists.contains(&"direct_ip_blacklist".to_string()),
            "IP should be found in direct_ip_blacklist, got lists: {:?}",
            matching_lists
        );

        // Test direct IPv6 without CIDR
        let (is_blacklisted, matching_lists) = is_ip_blacklisted("2001:db8::1").await;
        println!(
            "For IP 2001:db8::1: is_blacklisted={}, matching_lists={:?}",
            is_blacklisted, matching_lists
        );
        assert!(is_blacklisted, "IPv6 without CIDR should be blacklisted");
        assert!(matching_lists.contains(&"direct_ip_blacklist".to_string()));

        // Test IPv4 with CIDR
        let (is_blacklisted, matching_lists) = is_ip_blacklisted("10.1.2.3").await;
        println!(
            "For IP 10.1.2.3: is_blacklisted={}, matching_lists={:?}",
            is_blacklisted, matching_lists
        );
        assert!(is_blacklisted, "IPv4 in CIDR range should be blacklisted");
        assert!(matching_lists.contains(&"direct_ip_blacklist".to_string()));

        // Test IPv6 with CIDR
        let (is_blacklisted, matching_lists) = is_ip_blacklisted("2001:db8:1::abc").await;
        println!(
            "For IP 2001:db8:1::abc: is_blacklisted={}, matching_lists={:?}",
            is_blacklisted, matching_lists
        );
        assert!(is_blacklisted, "IPv6 in CIDR range should be blacklisted");
        assert!(matching_lists.contains(&"direct_ip_blacklist".to_string()));

        // Test IPs not in blacklist
        let (is_blacklisted, _) = is_ip_blacklisted("192.168.1.2").await;
        println!("For IP 192.168.1.2: is_blacklisted={}", is_blacklisted);
        assert!(
            !is_blacklisted,
            "IPv4 not in blacklist should not be blacklisted"
        );

        let (is_blacklisted, _) = is_ip_blacklisted("2001:db8::2").await;
        println!("For IP 2001:db8::2: is_blacklisted={}", is_blacklisted);
        assert!(
            !is_blacklisted,
            "IPv6 not in blacklist should not be blacklisted"
        );

        // Reset LISTS back to default after the test to avoid affecting other tests
        LISTS.reset_to_default().await;
    }
}
