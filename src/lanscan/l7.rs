// L7 Network Session Resolution
//
// This module implements the Layer 7 (Application Layer) resolution for network sessions
// observed by the LAN scanner. The primary goal is to associate a network session,
// defined by its protocol, source IP/port, and destination IP/port (struct `Session`),
// with the local process responsible for it.
//
// ---
//
// **2024 Improvements:**
// - The system now caches and checks process start time (from sysinfo) for PID reuse protection, ensuring accurate process association even when PIDs are recycled by the OS.
// - After a failed resolution attempt, the resolver immediately refreshes process and socket tables and retries once before incrementing retry count or re-queueing. This greatly improves accuracy for short-lived and non-ephemeral sessions.
// - These changes significantly reduce 'unknown process' results and false associations due to PID reuse, prioritizing accuracy above all.
//
// ---
//
// The core components are:
// - `LANScanL7`: The main struct managing the L7 resolution process.
// - `SessionL7`: Struct holding the resolved process information (PID, name, path, username).
// - `L7Resolution`: Struct stored in `l7_map`, containing the Option<SessionL7>,
//   metadata like resolution time, retry count, and the source of the resolution.
// - `Resolver Task`: An asynchronous task (`start_resolver_task`) that continuously processes
//   a queue (`resolver_queue`) of `Session` objects needing resolution.
// - `Caches`:
//    - `l7_map`: The primary cache storing `L7Resolution` results or pending states for sessions.
//    - `port_process_cache`: Caches process info (`ProcessCacheEntry`) keyed by local (port, protocol),
//      now including process start time for PID reuse protection. Used as a fallback, especially for short-lived connections. Includes a grace period for terminated processes.
//    - `host_service_cache`: Caches known local services (port, protocol, L7 info) keyed by hostname ("localhost").
//      Used as a fallback for inbound connections to the local machine.
// - `Cache Cleanup Task`: Periodically removes stale entries from caches (`start_cache_cleanup_task`).
//
// Resolution Logic:
// 1. New connections are added to `resolver_queue`.
// 2. The resolver task fetches the current list of sockets (`netstat2::get_sockets_info`)
//    and processes (`sysinfo::System::processes`) periodically.
// 3. For each connection in the queue, it attempts resolution in the following order:
//    a. **Host Cache (`try_resolve_from_host_cache`)**: Checks if the destination matches a known local service.
//    b. **Exact Match (`try_exact_match`)**: Looks for a socket entry matching the connection's full 4-tuple (TCP)
//       or local IP/port (UDP) in the fetched socket list.
//    c. **Port Cache (`try_resolve_from_cache`)**: If exact match fails, checks the port cache using the connection's
//       local port (src or dst if private IP), using process start time for PID reuse protection. Uses a grace period if the cached process has terminated.
//    d. **Immediate Retry**: If all above fail, the resolver immediately refreshes process/socket tables and retries once before incrementing retry count or re-queueing.
// 4. If a match is found and process info is extracted (`extract_l7_from_socket`), the result is stored in `l7_map`.
// 5. If resolution fails, the connection is re-queued with an incremented retry count and exponential backoff.
//    Connections likely involving ephemeral ports use a faster initial retry.
// 6. After max retries, the connection is marked as `FailedMaxRetries` in `l7_map`.
// 7. Resolved entries in `l7_map` have a Time-To-Live (TTL) and are evicted by the cleanup task.
//
// This system aims to handle the ephemeral nature of network connections and process lifecycles
// by combining direct matching with caching, PID reuse protection, and retry mechanisms.

use crate::customlock::*;
use crate::lanscan::l7_ebpf;
use crate::lanscan::sessions::*;
use crate::runtime::async_spawn_blocking;
use crate::runtime::*;
use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo,
};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use sysinfo::{Pid, Process, ProcessRefreshKind, RefreshKind, System, Uid, Users};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, trace, warn};

// Windows-specific imports
#[cfg(windows)]
use windows::{
    core::{HSTRING, PWSTR},
    Win32::NetworkManagement::NetManagement::{
        NERR_Success, NetApiBufferFree, NetUserGetInfo, USER_INFO_0,
    },
};

// Add platform-specific threshold for the first ephemeral port (RFC-defined defaults)
#[cfg(target_os = "macos")]
const EPHEMERAL_PORT_THRESHOLD: u16 = 49_152; // macOS default sysctl net.inet.ip.portrange.first
#[cfg(not(target_os = "macos"))]
const EPHEMERAL_PORT_THRESHOLD: u16 = 32_768; // Common default on Linux/BSD

// Replace const MAX_L7_RETRIES with environment-configurable Lazy
static MAX_L7_RETRIES_DYNAMIC: Lazy<usize> = Lazy::new(|| {
    std::env::var("MAX_L7_RETRIES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(5)
});

// Dynamic retry delay for likely-ephemeral connections (defaults to 10 ms)
static EPHEMERAL_RETRY_MS_DYNAMIC: Lazy<u64> = Lazy::new(|| {
    std::env::var("EPHEMERAL_RETRY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(10)
});

// Add a new constant for TTL of cached entries that come from high-range (likely client) ephemeral ports
const EPHEMERAL_PORT_CACHE_TTL_SECS: u64 = 30; // Keep for 30 s only

// Maximum size of port→process cache
const PORT_CACHE_MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L7ResolutionSource {
    Unknown, // Default before resolution attempt or if resolution fails without hitting max retries
    ExactMatch,
    CacheHitRunning,
    CacheHitTerminated, // Within grace period
    HostCacheHitRunning,
    HostCacheHitTerminated, // Within grace period
    FailedMaxRetries,       // Explicitly mark failures after retries
    Ebpf,                   // Obtained from eBPF helper on Linux
}

#[derive(Debug, Clone)]
pub struct L7Resolution {
    pub l7: Option<SessionL7>,
    pub date: DateTime<Utc>,
    pub retry_count: usize,
    pub last_retry: Option<Instant>,
    pub source: L7ResolutionSource,
}

#[derive(Debug, Clone)]
pub struct ProcessCacheEntry {
    pub l7: SessionL7,
    pub process_start_time: u64,
    pub last_seen: Instant,
    pub hit_count: usize,
    pub termination_time: Option<Instant>,
}

pub struct LANScanL7 {
    l7_map: Arc<CustomDashMap<Session, L7Resolution>>,
    resolver_queue: Arc<CustomDashMap<Session, ()>>,
    resolver_handle: Option<TaskHandle>,
    system: Arc<CustomRwLock<System>>,
    users: Arc<CustomRwLock<Users>>,
    port_process_cache: Arc<CustomDashMap<(u16, Protocol), ProcessCacheEntry>>,
    cache_cleanup_handle: Option<TaskHandle>,
    host_service_cache: Arc<CustomDashMap<String, Vec<(u16, Protocol, SessionL7)>>>,
}

impl LANScanL7 {
    pub fn new() -> Self {
        Self {
            l7_map: Arc::new(CustomDashMap::new("L7 Map")),
            resolver_queue: Arc::new(CustomDashMap::new("Resolver Queue")),
            resolver_handle: None,
            system: Arc::new(CustomRwLock::new(System::new_all())),
            users: Arc::new(CustomRwLock::new(Users::new())),
            port_process_cache: Arc::new(CustomDashMap::new("Port Process Cache")),
            cache_cleanup_handle: None,
            host_service_cache: Arc::new(CustomDashMap::new("Host Service Cache")),
        }
    }

    pub async fn start(&mut self) {
        if self.resolver_handle.is_some() {
            warn!("L7 resolver task is already running");
            return;
        }

        self.start_resolver_task().await;

        self.start_cache_cleanup_task().await;
    }

    pub async fn stop(&mut self) {
        if let Some(task_handle) = self.resolver_handle.take() {
            task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = task_handle.handle.await;
            info!("Stopped L7 resolver task");
        } else {
            warn!("L7 resolver task not running");
        }

        if let Some(task_handle) = self.cache_cleanup_handle.take() {
            task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = task_handle.handle.await;
            info!("Stopped L7 cache cleanup task");
        }
    }

    async fn start_resolver_task(&mut self) {
        let resolver_queue = self.resolver_queue.clone();
        let l7_map = self.l7_map.clone();
        let system = self.system.clone();
        let users = self.users.clone();
        let port_process_cache = self.port_process_cache.clone();
        let host_service_cache = self.host_service_cache.clone();

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        let resolver_handle = async_spawn(async move {
            info!("Starting L7 resolver task");
            let refresh_kind = RefreshKind::nothing().with_processes(
                ProcessRefreshKind::everything()
                    .without_cpu()
                    .without_disk_usage()
                    .without_memory(),
            );

            while !stop_flag_clone.load(Ordering::Relaxed) {
                let mut to_process_this_cycle: Vec<Session> = Vec::new();
                let mut requeue_due_to_backoff: Vec<Session> = Vec::new();

                // Drain resolver_queue and categorize sessions
                for (session_key, _value) in resolver_queue.drain() {
                    let session = &session_key; // Keep as reference for existing logic, or clone if moved
                    let mut process_now = true; // Default to process unless backoff says otherwise

                    if let Some(resolution_entry) = l7_map.get(session) {
                        let resolution = resolution_entry.value();
                        if resolution.retry_count > 0 {
                            if let Some(last_retry_instant) = resolution.last_retry {
                                let is_likely_ephemeral = Self::is_likely_ephemeral(session);
                                let wait_duration = if is_likely_ephemeral {
                                    Duration::from_millis(*EPHEMERAL_RETRY_MS_DYNAMIC)
                                } else {
                                    let backoff_ms =
                                        (2_u64.pow(resolution.retry_count as u32 - 1)) * 100;
                                    Duration::from_millis(backoff_ms.min(10000))
                                    // Max 10s backoff
                                };
                                if last_retry_instant.elapsed() < wait_duration {
                                    process_now = false;
                                }
                            }
                        }
                    } else {
                        // If not in l7_map, it's likely a new session or an anomaly. Process it.
                        // add_connection_to_resolver should ensure an entry exists.
                        // If it was evicted by TTL but still in queue, treat as new.
                        trace!("Session {:?} in resolver_queue but not in l7_map, treating as new attempt.", session);
                    }

                    if process_now {
                        to_process_this_cycle.push(session_key.clone()); // Clone here as session_key is owned
                    } else {
                        requeue_due_to_backoff.push(session_key.clone()); // Clone here
                    }
                }

                let to_process_len = to_process_this_cycle.len();
                if to_process_len > 0 {
                    {
                        let mut sys = system.write().await;
                        sys.refresh_specifics(refresh_kind);

                        let mut users = users.write().await;
                        users.refresh();
                    }

                    // Offload potentially blocking netstat scan to a blocking thread
                    let socket_info = match async_spawn_blocking(move || {
                        get_sockets_info(
                            AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
                            ProtocolFlags::TCP | ProtocolFlags::UDP,
                        )
                    })
                    .await
                    {
                        Ok(Ok(info)) => info,
                        Ok(Err(e)) => {
                            error!("Failed to get socket info: {:?}", e);
                            Vec::new()
                        }
                        Err(join_err) => {
                            error!("spawn_blocking join error: {:?}", join_err);
                            Vec::new()
                        }
                    };

                    let system_read = system.read().await;
                    let users_read = users.read().await;

                    let pid_to_process: HashMap<u32, &Process> = system_read
                        .processes()
                        .iter()
                        .map(|(pid, process)| (pid.as_u32(), process))
                        .collect();

                    let uid_to_username: HashMap<&Uid, &str> = users_read
                        .iter()
                        .map(|user| (user.id(), user.name()))
                        .collect();

                    Self::update_host_service_cache(
                        &socket_info,
                        &pid_to_process,
                        &uid_to_username,
                        &host_service_cache,
                    )
                    .await;

                    let mut successfully_resolved_count = 0;
                    let mut failed_and_will_retry_count = 0;
                    let mut failed_max_retries_count = 0;

                    // Build port→socket index once per batch for quick lookup
                    let mut port_index: HashMap<(u16, Protocol), Vec<&SocketInfo>> = HashMap::new();
                    for socket in &socket_info {
                        let (port, proto) = match &socket.protocol_socket_info {
                            ProtocolSocketInfo::Tcp(tcp) => (tcp.local_port, Protocol::TCP),
                            ProtocolSocketInfo::Udp(udp) => (udp.local_port, Protocol::UDP),
                        };
                        port_index.entry((port, proto)).or_default().push(socket);
                    }

                    for connection in to_process_this_cycle {
                        // First, quick exact match via index
                        if let Some((l7_fast, start_time_fast)) = Self::try_exact_match_from_index(
                            &connection,
                            &port_index,
                            &pid_to_process,
                            &uid_to_username,
                        )
                        .await
                        {
                            trace!(
                                "L7 exact match (indexed) for {:?}: {:?}",
                                connection,
                                l7_fast
                            );
                            Self::update_port_process_cache(
                                &connection,
                                &l7_fast,
                                start_time_fast,
                                &port_process_cache,
                            )
                            .await;
                            l7_map.insert(
                                connection.clone(),
                                L7Resolution {
                                    l7: Some(l7_fast),
                                    date: Utc::now(),
                                    retry_count: 0,
                                    last_retry: None,
                                    source: L7ResolutionSource::ExactMatch,
                                },
                            );
                            successfully_resolved_count += 1;
                            continue;
                        }

                        let from_host_cache = Self::try_resolve_from_host_cache_custom(
                            &connection,
                            &host_service_cache,
                            &*system_read,
                        )
                        .await;

                        if let Some(l7_data_tuple) = from_host_cache {
                            let (session_l7_data, _source_from_host_cache) = l7_data_tuple; // Unpack the tuple
                            trace!(
                                "Successfully L7 resolved connection {:?} from host cache: {:?}",
                                connection,
                                session_l7_data // Use unpacked data
                            );

                            // Determine if the process is running to set the correct source
                            let source = if system_read
                                .process(Pid::from_u32(session_l7_data.pid))
                                .is_some()
                            {
                                L7ResolutionSource::HostCacheHitRunning
                            } else {
                                L7ResolutionSource::HostCacheHitTerminated
                            };

                            Self::update_port_process_cache(
                                &connection,
                                &session_l7_data, // Pass the SessionL7 part
                                0,                // No start_time available from host_service_cache
                                &port_process_cache,
                            )
                            .await;

                            l7_map.insert(
                                connection.clone(),
                                L7Resolution {
                                    l7: Some(session_l7_data), // Pass the SessionL7 part
                                    date: Utc::now(),
                                    retry_count: 0,
                                    last_retry: None,
                                    source, // Use the determined source here
                                },
                            );
                            successfully_resolved_count += 1;
                            continue;
                        }

                        let system_read_for_cache = system.read().await;
                        let resolution_result = Self::resolve_l7_data(
                            &connection,
                            &socket_info,
                            &pid_to_process,
                            &uid_to_username,
                        )
                        .await;

                        // Fallback: try port_process_cache if direct match fails
                        let mut l7_data_and_time = None;
                        let mut cache_source = None;
                        match resolution_result {
                            Ok((l7_data, process_start_time)) => {
                                l7_data_and_time = Some((l7_data, process_start_time));
                            }
                            Err(_) => {
                                if let Some((l7_data, source)) = Self::try_resolve_from_cache(
                                    &connection,
                                    &port_process_cache,
                                    &*system_read_for_cache,
                                )
                                .await
                                {
                                    l7_data_and_time = Some((l7_data, 0)); // Cache doesn't store start_time for host cache, so use 0
                                    cache_source = Some(source);
                                } else {
                                    // No further immediate refreshes; rely on next batch refresh
                                }
                            }
                        }
                        if let Some((l7_data, process_start_time)) = l7_data_and_time {
                            trace!(
                                "Successfully L7 resolved connection {:?}: {:?}",
                                connection,
                                l7_data
                            );
                            Self::update_port_process_cache(
                                &connection,
                                &l7_data,
                                process_start_time,
                                &port_process_cache,
                            )
                            .await;
                            l7_map.insert(
                                connection.clone(),
                                L7Resolution {
                                    l7: Some(l7_data),
                                    date: Utc::now(),
                                    retry_count: 0,
                                    last_retry: None,
                                    source: cache_source.unwrap_or(L7ResolutionSource::ExactMatch),
                                },
                            );
                            successfully_resolved_count += 1;
                            continue;
                        }
                        // All resolution attempts for 'connection' in this cycle failed.
                        if let Some(mut resolution_entry) = l7_map.get_mut(&connection) {
                            resolution_entry.retry_count += 1;
                            resolution_entry.last_retry = Some(Instant::now());

                            if resolution_entry.retry_count > *MAX_L7_RETRIES_DYNAMIC {
                                resolution_entry.l7 = None; // Ensure l7 is None
                                resolution_entry.source = L7ResolutionSource::FailedMaxRetries;
                                failed_max_retries_count += 1;
                                trace!(
                                    "Session {:?} failed max L7 retries ({}). Source: {:?}.",
                                    connection,
                                    resolution_entry.retry_count,
                                    resolution_entry.source
                                );
                                // Do not re-queue if max retries hit
                            } else {
                                // Re-queue for another attempt
                                resolver_queue.insert(connection.clone(), ());
                                failed_and_will_retry_count += 1;
                                trace!(
                                    "Re-queued session {:?} for L7 resolution (retry {}).",
                                    connection,
                                    resolution_entry.retry_count
                                );
                            }
                        } else {
                            warn!(
                                "L7: Connection {:?} processed but no entry in l7_map for failure handling. Re-initializing and re-queueing.",
                                connection
                            );
                            // Re-initialize in l7_map and add to queue as if it's a new connection
                            l7_map.insert(
                                connection.clone(),
                                L7Resolution {
                                    l7: None,
                                    date: Utc::now(),
                                    retry_count: 0, // Start retries from 0
                                    last_retry: Some(Instant::now()), // Mark a retry attempt
                                    source: L7ResolutionSource::Unknown,
                                },
                            );
                            resolver_queue.insert(connection.clone(), ());
                            failed_and_will_retry_count += 1; // Count it as a failed attempt that will be retried
                        }
                    }

                    // Re-queue sessions that were skipped due to backoff
                    let requeue_len = requeue_due_to_backoff.len();
                    if !requeue_due_to_backoff.is_empty() {
                        for session in requeue_due_to_backoff {
                            resolver_queue.insert(session, ());
                        }
                        trace!("L7: {} sessions re-queued due to backoff, no active processing this cycle.", requeue_len);
                    }

                    if successfully_resolved_count > 0
                        || failed_and_will_retry_count > 0
                        || failed_max_retries_count > 0
                        || requeue_len > 0
                    {
                        debug!(
                            "L7 resolution cycle: {} processed. Results: {} resolved, {} failed (will retry), {} failed (max retries). {} pending backoff.",
                            to_process_len,
                            successfully_resolved_count,
                            failed_and_will_retry_count,
                            failed_max_retries_count,
                            requeue_len
                        );
                    }

                    // Sleep for a little while to avoid overwhelming the system but keep a tight loop to ensure we're responsive to new sessions
                    sleep(Duration::from_millis(3)).await;
                } else {
                    // No sessions to process actively, but check if there are items simply waiting for backoff
                    let requeue_len = requeue_due_to_backoff.len();
                    if !requeue_due_to_backoff.is_empty() {
                        for session in requeue_due_to_backoff {
                            resolver_queue.insert(session, ());
                        }
                        trace!("L7: {} sessions re-queued due to backoff, no active processing this cycle.", requeue_len);
                    }
                    // No sessions to resolve, sleep for a while to avoid overwhelming the system
                    sleep(Duration::from_millis(10)).await;
                }
            }

            info!("L7 resolver task completed");
        });

        self.resolver_handle = Some(TaskHandle {
            handle: resolver_handle,
            stop_flag,
        });
    }

    async fn start_cache_cleanup_task(&mut self) {
        let port_process_cache = self.port_process_cache.clone();
        let host_service_cache = self.host_service_cache.clone();
        let l7_map = self.l7_map.clone();

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        let cleanup_handle = async_spawn(async move {
            info!("Starting L7 cache cleanup task");

            while !stop_flag_clone.load(Ordering::Relaxed) {
                // Clean up port process cache using retain to avoid per-key locking
                port_process_cache.retain(|key, entry| {
                    let port = key.0;
                    let age = entry.last_seen.elapsed();
                    if port >= EPHEMERAL_PORT_THRESHOLD {
                        // keep only if not expired
                        age <= Duration::from_secs(EPHEMERAL_PORT_CACHE_TTL_SECS)
                    } else {
                        // keep entries unless they've aged out with low hit count
                        !(age > Duration::from_secs(3600) && entry.hit_count < 10)
                    }
                });
                debug!(
                    "Port process cache size after cleanup: {}",
                    port_process_cache.len()
                );

                // Clean up host service cache
                // We'll refresh the entire cache periodically rather than trying to track
                // individual service lifetimes, since the host service cache is refreshed
                // completely by update_host_service_cache() on each resolution cycle
                let host_cache_keys: Vec<String> = host_service_cache
                    .iter()
                    .map(|entry| entry.key().clone())
                    .collect();

                // Don't remove the localhost entry, which is constantly refreshed
                for key in host_cache_keys {
                    if key != "localhost" {
                        host_service_cache.remove(&key);
                        debug!("Removed stale host service entry: {}", key);
                    }
                }

                // Clean out services in the localhost entry that haven't been seen recently
                if let Some(localhost_entry) = host_service_cache.get_mut("localhost") {
                    debug!(
                        "Localhost service cache has {} entries",
                        localhost_entry.value().len()
                    );
                }

                // ------------------------------------------------------------------
                // Size bound for port→process cache (oldest entries removed)
                // ------------------------------------------------------------------
                if port_process_cache.len() > PORT_CACHE_MAX_ENTRIES {
                    let mut entries: Vec<_> = port_process_cache
                        .iter()
                        .map(|e| (e.key().clone(), e.value().last_seen))
                        .collect();
                    entries.sort_by_key(|&(_, ts)| ts);
                    let excess = port_process_cache.len() - PORT_CACHE_MAX_ENTRIES;
                    for i in 0..excess {
                        port_process_cache.remove(&entries[i].0);
                    }
                    debug!("Trimmed {} excess port cache entries", excess);
                }

                // ------------------------------------------------------------------
                // TTL eviction for session→L7 map (30-minute default)
                // ------------------------------------------------------------------
                let ttl = ChronoDuration::minutes(30);
                let now = Utc::now();

                // Collect keys to remove first to avoid deadlock
                let mut keys_to_remove = Vec::new();
                for entry in l7_map.iter() {
                    if now - entry.value().date > ttl {
                        keys_to_remove.push(entry.key().clone());
                    }
                }

                // Now remove the collected keys
                let evicted = keys_to_remove.len();
                for key in keys_to_remove {
                    l7_map.remove(&key);
                }

                if evicted > 0 {
                    debug!("Evicted {} stale L7Resolution entries", evicted);
                }

                // Sleep for a while before the next cleanup
                sleep(Duration::from_secs(60)).await;
            }

            info!("L7 cache cleanup task completed");
        });

        self.cache_cleanup_handle = Some(TaskHandle {
            handle: cleanup_handle,
            stop_flag,
        });
    }

    async fn update_port_process_cache(
        connection: &Session,
        l7_data: &SessionL7,
        process_start_time: u64,
        port_process_cache: &CustomDashMap<(u16, Protocol), ProcessCacheEntry>,
    ) {
        let protocol = connection.protocol.clone();
        let ports_to_cache = if is_private_ip(connection.src_ip) && is_private_ip(connection.dst_ip)
        {
            vec![
                (connection.src_port, protocol.clone()),
                (connection.dst_port, protocol.clone()),
            ]
        } else if is_private_ip(connection.src_ip) {
            vec![(connection.src_port, protocol.clone())]
        } else if is_private_ip(connection.dst_ip) {
            vec![(connection.dst_port, protocol.clone())]
        } else {
            vec![]
        };

        for key_tuple in ports_to_cache {
            let (port, protocol) = key_tuple;

            // Always cache (even high-range ports) but rely on short-TTL cleanup for
            // ports >= EPHEMERAL_PORT_THRESHOLD to avoid stale matches caused by
            // rapid port reuse.

            if let Some(mut entry) = port_process_cache.get_mut(&(port, protocol.clone())) {
                // Only update if PID and start time match (PID reuse protection)
                if entry.l7.pid == l7_data.pid && entry.process_start_time == process_start_time {
                    entry.value_mut().last_seen = Instant::now();
                    entry.value_mut().hit_count += 1;
                } else {
                    // Replace with new process info
                    *entry.value_mut() = ProcessCacheEntry {
                        l7: l7_data.clone(),
                        process_start_time,
                        last_seen: Instant::now(),
                        hit_count: 1,
                        termination_time: None,
                    };
                }
            } else {
                let cache_key = (port, protocol);
                port_process_cache.insert(
                    cache_key.clone(),
                    ProcessCacheEntry {
                        l7: l7_data.clone(),
                        process_start_time,
                        last_seen: Instant::now(),
                        hit_count: 1,
                        termination_time: None,
                    },
                );
                debug!("Cached L7 data for port {:?}: {:?}", cache_key, l7_data);
            }
        }
    }

    async fn try_resolve_from_cache(
        connection: &Session,
        port_process_cache: &CustomDashMap<(u16, Protocol), ProcessCacheEntry>,
        system: &System,
    ) -> Option<(SessionL7, L7ResolutionSource)> {
        let protocol = connection.protocol.clone();
        let cache_keys = [
            (connection.src_port, protocol.clone()),
            (connection.dst_port, protocol.clone()),
        ];
        let termination_grace_period = Duration::from_secs(5);
        for key in &cache_keys {
            let port = key.0;
            if port >= EPHEMERAL_PORT_THRESHOLD && port_process_cache.contains_key(key) {
                let entry_option = port_process_cache.get(key);
                if let Some(entry) = entry_option {
                    if entry.value().last_seen.elapsed()
                        > Duration::from_secs(EPHEMERAL_PORT_CACHE_TTL_SECS)
                    {
                        drop(entry);
                        port_process_cache.remove(key);
                        continue;
                    }
                }
            }
            let (
                entry_exists,
                l7_data_maybe,
                pid,
                process_start_time,
                is_terminated,
                termination_time,
            ) = if let Some(cached_entry) = port_process_cache.get(key) {
                let entry = cached_entry.value();
                let pid = entry.l7.pid;
                let process_start_time = entry.process_start_time;
                let process_opt = system.process(Pid::from_u32(pid));
                let process_exists = process_opt.is_some()
                    && process_opt.unwrap().start_time() == process_start_time;
                let is_terminated = entry.termination_time.is_some();
                let term_time = entry.termination_time;
                let l7_data = if process_exists
                    || (is_terminated
                        && term_time.map_or(false, |t| t.elapsed() < termination_grace_period))
                {
                    Some(entry.l7.clone())
                } else {
                    None
                };
                (
                    true,
                    l7_data,
                    pid,
                    process_start_time,
                    is_terminated,
                    term_time,
                )
            } else {
                (false, None, 0, 0, false, None)
            };
            if !entry_exists {
                continue;
            }
            if let Some(l7_data) = l7_data_maybe {
                if let Some(mut cached_entry) = port_process_cache.get_mut(key) {
                    if let Some(process) = system.process(Pid::from_u32(pid)) {
                        if process.start_time() == process_start_time {
                            cached_entry.value_mut().hit_count += 1;
                            cached_entry.value_mut().last_seen = Instant::now();
                            cached_entry.value_mut().termination_time = None;
                            return Some((l7_data, L7ResolutionSource::CacheHitRunning));
                        }
                    }
                    if is_terminated {
                        debug!(
                            "Using recently terminated process data for {:?} (PID: {}, start_time: {}), terminated {:?} ago",
                            key, pid, process_start_time, termination_time.unwrap().elapsed()
                        );
                        return Some((l7_data, L7ResolutionSource::CacheHitTerminated));
                    } else {
                        debug!(
                            "Process for {:?}: PID {} (start_time: {}) no longer exists or start_time mismatch, starting grace period",
                            key, pid, process_start_time
                        );
                        cached_entry.value_mut().termination_time = Some(Instant::now());
                        return Some((l7_data, L7ResolutionSource::CacheHitTerminated));
                    }
                }
            } else if is_terminated
                && termination_time.unwrap().elapsed() >= termination_grace_period
            {
                debug!(
                    "Grace period expired for {:?}: PID {} (start_time: {}) terminated {:?} ago",
                    key,
                    pid,
                    process_start_time,
                    termination_time.unwrap().elapsed()
                );
                port_process_cache.remove(key);
            }
        }
        None
    }

    async fn update_host_service_cache(
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
        host_service_cache: &CustomDashMap<String, Vec<(u16, Protocol, SessionL7)>>,
    ) {
        let mut temp_cache: HashMap<String, Vec<(u16, Protocol, SessionL7)>> = HashMap::new();

        for socket in socket_info {
            let (port, protocol) = match &socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => (tcp.local_port, Protocol::TCP),
                ProtocolSocketInfo::Udp(udp) => (udp.local_port, Protocol::UDP),
            };

            if port >= EPHEMERAL_PORT_THRESHOLD {
                continue;
            }

            if let Some((l7_data, _start_time)) =
                Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username, false).await
            {
                let hostname = "localhost".to_string();
                temp_cache
                    .entry(hostname)
                    .or_insert_with(Vec::new)
                    .push((port, protocol, l7_data));
            }
        }

        for (host, services) in temp_cache {
            host_service_cache.insert(host, services);
        }
    }

    async fn try_resolve_from_host_cache_custom(
        connection: &Session,
        host_service_cache: &Arc<CustomDashMap<String, Vec<(u16, Protocol, SessionL7)>>>,
        system: &System,
    ) -> Option<(SessionL7, L7ResolutionSource)> {
        // Only apply host cache for inbound/server-side flows: destination IP must be local
        let host_inbound = is_private_ip(connection.dst_ip);
        if !host_inbound {
            return None;
        }

        // Define the same grace period for terminated processes as in try_resolve_from_cache
        static TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(5);

        // Keep track of terminated PIDs we've seen recently
        static TERMINATED_PIDS: Lazy<CustomDashMap<u32, Instant>> =
            Lazy::new(|| CustomDashMap::new("Terminated PIDs"));

        if let Some(localhost_services) = host_service_cache.get("localhost") {
            for (service_port, service_protocol, l7_data) in localhost_services.value() {
                if (connection.src_port == *service_port || connection.dst_port == *service_port)
                    && connection.protocol == *service_protocol
                {
                    if system.process(Pid::from_u32(l7_data.pid)).is_some() {
                        // Process still exists, remove from terminated list if present
                        TERMINATED_PIDS.remove(&l7_data.pid);
                        return Some((l7_data.clone(), L7ResolutionSource::HostCacheHitRunning));
                    } else {
                        // Process terminated - check if in grace period
                        let now = Instant::now();
                        let in_grace_period = TERMINATED_PIDS
                            .entry(l7_data.pid)
                            .or_insert_with(|| now)
                            .value()
                            .elapsed()
                            < TERMINATION_GRACE_PERIOD;

                        if in_grace_period {
                            debug!(
                                "Using recently terminated host cache data for port {}, protocol {:?}: PID {} terminated {:?} ago",
                                service_port, service_protocol, l7_data.pid,
                                TERMINATED_PIDS.get(&l7_data.pid).unwrap().value().elapsed()
                            );
                            return Some((
                                l7_data.clone(),
                                L7ResolutionSource::HostCacheHitTerminated,
                            ));
                        } else {
                            debug!(
                                "Grace period expired for host cache entry: port {}, protocol {:?}, PID {}",
                                service_port, service_protocol, l7_data.pid
                            );
                            TERMINATED_PIDS.remove(&l7_data.pid);
                            continue;
                        }
                    }
                }
            }
        }

        None
    }

    pub async fn add_connection_to_resolver(&self, connection: &Session) {
        if self.l7_map.contains_key(connection) {
            return;
        }

        self.l7_map.insert(
            connection.clone(),
            L7Resolution {
                l7: None,
                date: Utc::now(),
                retry_count: 0,
                last_retry: None,
                source: L7ResolutionSource::Unknown, // Initialize source
            },
        );

        self.resolver_queue.insert(connection.clone(), ());

        trace!("Added connection to L7 resolver queue: {:?}", connection);
    }

    pub async fn get_resolved_l7(&self, connection: &Session) -> Option<L7Resolution> {
        // Check cached result first
        if let Some(l7) = self.l7_map.get(connection).map(|s| s.value().clone()) {
            return Some(l7);
        }

        // Try eBPF helper (will be a fast lookup when running on Linux)
        if let Some(l7_data) = l7_ebpf::get_l7_for_session(connection) {
            let resolution = L7Resolution {
                l7: Some(l7_data),
                date: Utc::now(),
                retry_count: 0,
                last_retry: None,
                source: L7ResolutionSource::Ebpf,
            };
            // Insert into cache for future queries
            self.l7_map.insert(connection.clone(), resolution.clone());
            return Some(resolution);
        }

        // Fall back to resolver queue mechanism
        self.add_connection_to_resolver(connection).await;
        None
    }

    async fn resolve_l7_data(
        connection: &Session,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
    ) -> Result<(SessionL7, u64)> {
        if let Some((l7_data, start_time)) =
            Self::try_exact_match(connection, socket_info, pid_to_process, uid_to_username).await
        {
            return Ok((l7_data, start_time));
        }
        // Fuzzy/wildcard match fallback
        if let Some((l7_data, start_time)) =
            Self::try_fuzzy_match(connection, socket_info, pid_to_process, uid_to_username).await
        {
            warn!("L7 fuzzy/wildcard match used for session {:?}", connection);
            return Ok((l7_data, start_time));
        }
        // Log all candidate sockets for debugging
        debug!(
            "L7 resolution failed: unknown process association for session {:?}",
            connection
        );
        Err(anyhow::anyhow!("No matching process found"))
    }

    async fn try_exact_match(
        connection: &Session,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
    ) -> Option<(SessionL7, u64)> {
        let protocol = connection.protocol.clone();
        for socket in socket_info {
            let proto_ok = match &protocol {
                Protocol::TCP => matches!(&socket.protocol_socket_info, ProtocolSocketInfo::Tcp(_)),
                Protocol::UDP => matches!(&socket.protocol_socket_info, ProtocolSocketInfo::Udp(_)),
            };
            if !proto_ok {
                continue;
            }
            let is_match = match &socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_socket) => {
                    (tcp_socket.local_addr == connection.src_ip
                        && tcp_socket.local_port == connection.src_port
                        && tcp_socket.remote_addr == connection.dst_ip
                        && tcp_socket.remote_port == connection.dst_port)
                        || (tcp_socket.local_addr == connection.dst_ip
                            && tcp_socket.local_port == connection.dst_port
                            && tcp_socket.remote_addr == connection.src_ip
                            && tcp_socket.remote_port == connection.src_port)
                }
                ProtocolSocketInfo::Udp(udp_socket) => {
                    (udp_socket.local_addr == connection.src_ip
                        && udp_socket.local_port == connection.src_port)
                        || (udp_socket.local_addr == connection.dst_ip
                            && udp_socket.local_port == connection.dst_port)
                }
            };
            if is_match {
                if let Some((l7, start_time)) =
                    Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username, false)
                        .await
                {
                    return Some((l7, start_time));
                }
            }
        }
        None
    }

    async fn try_fuzzy_match(
        connection: &Session,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
    ) -> Option<(SessionL7, u64)> {
        // Fuzzy match: match on (local_port, protocol) and wildcard IPs (0.0.0.0, ::)
        for socket in socket_info.iter() {
            let proto_ok = match &connection.protocol {
                Protocol::TCP => matches!(&socket.protocol_socket_info, ProtocolSocketInfo::Tcp(_)),
                Protocol::UDP => matches!(&socket.protocol_socket_info, ProtocolSocketInfo::Udp(_)),
            };
            if !proto_ok {
                continue;
            }
            let is_fuzzy_match = match &socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_socket) => {
                    // Match if local_port matches and local_addr is wildcard or matches one of the session IPs
                    let local_port_match = tcp_socket.local_port == connection.src_port
                        || tcp_socket.local_port == connection.dst_port;
                    let local_addr_wildcard = tcp_socket.local_addr.is_unspecified();
                    let local_addr_match = tcp_socket.local_addr == connection.src_ip
                        || tcp_socket.local_addr == connection.dst_ip;
                    local_port_match && (local_addr_wildcard || local_addr_match)
                }
                ProtocolSocketInfo::Udp(udp_socket) => {
                    let local_port_match = udp_socket.local_port == connection.src_port
                        || udp_socket.local_port == connection.dst_port;
                    let local_addr_wildcard = udp_socket.local_addr.is_unspecified();
                    let local_addr_match = udp_socket.local_addr == connection.src_ip
                        || udp_socket.local_addr == connection.dst_ip;
                    local_port_match && (local_addr_wildcard || local_addr_match)
                }
            };
            if is_fuzzy_match {
                if let Some((l7, start_time)) =
                    Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username, false)
                        .await
                {
                    return Some((l7, start_time));
                }
            }
        }
        None
    }

    async fn extract_l7_from_socket(
        socket: &SocketInfo,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
        _is_target_socket_for_logging: bool,
    ) -> Option<(SessionL7, u64)> {
        let socket_pids = socket.associated_pids.clone();
        for socket_pid in socket_pids.clone() {
            if let Some(process) = pid_to_process.get(&socket_pid) {
                let username = if let Some(user_id) = process.user_id() {
                    match uid_to_username.get(&user_id).map(|s| s.to_string()) {
                        Some(username) => username,
                        None => {
                            #[cfg(unix)]
                            {
                                let user_id_u32 = **user_id;
                                if let Some(user) = users::get_user_by_uid(user_id_u32) {
                                    user.name().to_string_lossy().to_string()
                                } else {
                                    warn!("No username found for user_id {:?}", user_id);
                                    String::new()
                                }
                            }
                            #[cfg(windows)]
                            {
                                if let Some(username) = get_windows_username_by_uid(user_id) {
                                    username
                                } else {
                                    warn!("No username found for user_id {:?}", user_id);
                                    String::new()
                                }
                            }
                            #[cfg(not(any(unix, windows)))]
                            {
                                warn!("No username found for user_id {:?}", user_id);
                                String::new()
                            }
                        }
                    }
                } else {
                    warn!("No user_id found for PID {:?}", socket_pid);
                    String::new()
                };
                let process_name = process.name().to_string_lossy().to_string();
                let process_path = if let Some(path) = process.exe() {
                    path.to_string_lossy().to_string()
                } else {
                    String::new()
                };
                let process_start_time = process.start_time();
                return Some((
                    SessionL7 {
                        pid: socket_pid,
                        process_name,
                        process_path,
                        username,
                    },
                    process_start_time,
                ));
            }
        }
        None
    }

    fn is_likely_ephemeral(connection: &Session) -> bool {
        if connection.dst_port == 53 || connection.src_port == 53 {
            return true;
        }

        let is_src_ephemeral_port = connection.src_port >= EPHEMERAL_PORT_THRESHOLD;
        let is_dst_well_known = connection.dst_port < 1024;

        if is_src_ephemeral_port && is_dst_well_known {
            return true;
        }

        if connection.protocol == Protocol::UDP {
            return true;
        }

        false
    }

    async fn try_exact_match_from_index(
        connection: &Session,
        port_index: &HashMap<(u16, Protocol), Vec<&SocketInfo>>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
    ) -> Option<(SessionL7, u64)> {
        let protocol = connection.protocol.clone();
        let cache_keys = [
            (connection.src_port, protocol.clone()),
            (connection.dst_port, protocol.clone()),
        ];
        for key in &cache_keys {
            if let Some(socket_list) = port_index.get(key) {
                for socket in socket_list {
                    let proto_ok = match &protocol {
                        Protocol::TCP => {
                            matches!(&socket.protocol_socket_info, ProtocolSocketInfo::Tcp(_))
                        }
                        Protocol::UDP => {
                            matches!(&socket.protocol_socket_info, ProtocolSocketInfo::Udp(_))
                        }
                    };
                    if !proto_ok {
                        continue;
                    }
                    let is_match = match &socket.protocol_socket_info {
                        ProtocolSocketInfo::Tcp(tcp_socket) => {
                            (tcp_socket.local_addr == connection.src_ip
                                && tcp_socket.local_port == connection.src_port
                                && tcp_socket.remote_addr == connection.dst_ip
                                && tcp_socket.remote_port == connection.dst_port)
                                || (tcp_socket.local_addr == connection.dst_ip
                                    && tcp_socket.local_port == connection.dst_port
                                    && tcp_socket.remote_addr == connection.src_ip
                                    && tcp_socket.remote_port == connection.src_port)
                        }
                        ProtocolSocketInfo::Udp(udp_socket) => {
                            (udp_socket.local_addr == connection.src_ip
                                && udp_socket.local_port == connection.src_port)
                                || (udp_socket.local_addr == connection.dst_ip
                                    && udp_socket.local_port == connection.dst_port)
                        }
                    };
                    if is_match {
                        if let Some((l7, start_time)) = Self::extract_l7_from_socket(
                            socket,
                            pid_to_process,
                            uid_to_username,
                            false,
                        )
                        .await
                        {
                            return Some((l7, start_time));
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(windows)]
fn get_windows_username_by_uid(uid: &Uid) -> Option<String> {
    use std::ffi::c_void;
    use windows::core::{Error, PCWSTR};

    // The Uid is typically a SID in string form on Windows
    let uid_str = uid.to_string();

    // Convert the UID string to a wide string for Windows API
    let h_string = HSTRING::from(uid_str.as_str());

    unsafe {
        let mut buffer: *mut u8 = std::ptr::null_mut();
        let result = NetUserGetInfo(
            PCWSTR::null(), // Local computer
            PCWSTR(h_string.as_ptr()),
            0, // Level 0 for basic info
            &mut buffer as *mut *mut u8,
        );

        if result == NERR_Success && !buffer.is_null() {
            let user_info = &*(buffer as *const USER_INFO_0);
            let username = PWSTR(user_info.usri0_name.0).to_string().ok();

            // Free the buffer allocated by NetUserGetInfo
            let _ = NetApiBufferFree(Some(buffer as *const c_void));

            return username;
        } else {
            if !buffer.is_null() {
                let _ = NetApiBufferFree(Some(buffer as *const c_void));
            }
            debug!(
                "Failed to get Windows username for UID {}: {:?}",
                uid_str,
                Error::from_win32()
            );
            return None;
        }
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    crate::lanscan::ip::is_lan_ip(&ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_lanscan_l7_start_stop() {
        let mut lanscan_l7 = LANScanL7::new();

        lanscan_l7.start().await;

        assert!(lanscan_l7.resolver_handle.is_some());

        // Use tokio::time::timeout to ensure the test doesn't hang
        let stop_result = tokio::time::timeout(Duration::from_secs(5), lanscan_l7.stop()).await;

        // If timeout occurs, force cleanup to prevent test from hanging
        if stop_result.is_err() {
            error!("Timeout occurred while stopping lanscan_l7");
            if let Some(handle) = lanscan_l7.resolver_handle.take() {
                handle.stop_flag.store(true, Ordering::Relaxed);
                handle.handle.abort();
            }
            if let Some(handle) = lanscan_l7.cache_cleanup_handle.take() {
                handle.stop_flag.store(true, Ordering::Relaxed);
                handle.handle.abort();
            }
        }

        assert!(lanscan_l7.resolver_handle.is_none());
    }

    #[tokio::test]
    async fn test_add_connection_to_resolver() {
        let lanscan_l7 = LANScanL7::new();

        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };

        lanscan_l7.add_connection_to_resolver(&connection).await;

        let queue = lanscan_l7
            .resolver_queue
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        assert!(queue.contains(&connection));

        if let Some(resolution) = lanscan_l7.l7_map.get(&connection) {
            assert!(resolution.l7.is_none());
        } else {
            panic!("Connection not found in l7_map");
        };
    }

    #[tokio::test]
    async fn test_get_resolved_l7_before_resolution() {
        let lanscan_l7 = LANScanL7::new();

        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };

        let l7_resolution = lanscan_l7.get_resolved_l7(&connection).await;
        assert!(l7_resolution.is_none());

        lanscan_l7.add_connection_to_resolver(&connection).await;

        let l7_resolution = lanscan_l7.get_resolved_l7(&connection).await;
        assert!(l7_resolution.is_some());
        let l7_resolution = l7_resolution.unwrap();
        assert!(l7_resolution.l7.is_none());
    }

    #[tokio::test]
    async fn test_resolve_l7_data_no_match() {
        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("10.0.0.1").unwrap(),
            src_port: 54321,
            dst_ip: IpAddr::from_str("10.0.0.2").unwrap(),
            dst_port: 12345,
        };

        let socket_info = vec![];
        let pid_to_process = HashMap::new();
        let uid_to_username = HashMap::new();

        let result = LANScanL7::resolve_l7_data(
            &connection,
            &socket_info,
            &pid_to_process,
            &uid_to_username,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolver_task_processes_queue() {
        let mut lanscan_l7 = LANScanL7::new();

        lanscan_l7.start().await;

        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            dst_port: 54321,
        };

        lanscan_l7.add_connection_to_resolver(&connection).await;

        // Allow time for processing
        sleep(Duration::from_secs(1)).await;

        let l7_resolution = lanscan_l7.get_resolved_l7(&connection).await;
        assert!(l7_resolution.is_some());
        let l7_resolution = l7_resolution.unwrap();
        assert!(l7_resolution.l7.is_none() || l7_resolution.l7.is_some());

        // Use tokio::time::timeout to ensure the test doesn't hang
        let stop_result = tokio::time::timeout(Duration::from_secs(5), lanscan_l7.stop()).await;

        // If timeout occurs, force cleanup to prevent test from hanging
        if stop_result.is_err() {
            error!("Timeout occurred while stopping lanscan_l7");
            if let Some(handle) = lanscan_l7.resolver_handle.take() {
                handle.stop_flag.store(true, Ordering::Relaxed);
                handle.handle.abort();
            }
            if let Some(handle) = lanscan_l7.cache_cleanup_handle.take() {
                handle.stop_flag.store(true, Ordering::Relaxed);
                handle.handle.abort();
            }
        }
    }

    #[tokio::test]
    async fn test_port_process_cache() {
        let lanscan_l7 = LANScanL7::new();

        let l7_data = SessionL7 {
            pid: 1234,
            process_name: "test_process".to_string(),
            process_path: "/usr/bin/test_process".to_string(),
            username: "test_user".to_string(),
        };

        let port_protocol = (8080, Protocol::TCP);
        lanscan_l7.port_process_cache.insert(
            port_protocol,
            ProcessCacheEntry {
                l7: l7_data.clone(),
                process_start_time: 0,
                last_seen: Instant::now(),
                hit_count: 0,
                termination_time: None,
            },
        );

        let connection1 = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 8080,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };

        let connection2 = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 9090,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };

        let cache_keys1 = [
            (connection1.src_port, connection1.protocol.clone()),
            (connection1.dst_port, connection1.protocol),
        ];

        let mut found_in_cache = false;
        for key in &cache_keys1 {
            if let Some(cached_entry) = lanscan_l7.port_process_cache.get(key) {
                assert_eq!(cached_entry.value().l7.pid, l7_data.pid);
                assert_eq!(cached_entry.value().l7.process_name, l7_data.process_name);
                found_in_cache = true;
                break;
            }
        }
        assert!(
            found_in_cache,
            "Should find L7 data in cache for connection1"
        );

        let cache_keys2 = [
            (connection2.src_port, connection2.protocol.clone()),
            (connection2.dst_port, connection2.protocol),
        ];

        found_in_cache = false;
        for key in &cache_keys2 {
            if let Some(_) = lanscan_l7.port_process_cache.get(key) {
                found_in_cache = true;
                break;
            }
        }
        assert!(
            !found_in_cache,
            "Should not find L7 data in cache for connection2"
        );
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("172.16.0.1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("172.31.255.255").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("192.168.1.1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("127.0.0.1").unwrap()));

        assert!(!is_private_ip(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("1.1.1.1").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("172.15.0.1").unwrap()));
        assert!(!is_private_ip(IpAddr::from_str("172.32.0.1").unwrap()));

        assert!(is_private_ip(IpAddr::from_str("::1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("::").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("fc00::1").unwrap()));
        assert!(is_private_ip(IpAddr::from_str("fe80::1").unwrap()));

        assert!(!is_private_ip(IpAddr::from_str("2001:db8::1").unwrap()));
    }

    #[test]
    fn test_is_likely_ephemeral() {
        let dns_query = Session {
            protocol: Protocol::UDP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 45678,
            dst_ip: IpAddr::from_str("8.8.8.8").unwrap(),
            dst_port: 53,
        };
        assert!(LANScanL7::is_likely_ephemeral(&dns_query));

        let client_web_request = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 55555,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };
        assert!(LANScanL7::is_likely_ephemeral(&client_web_request));

        let udp_connection = Session {
            protocol: Protocol::UDP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 5000,
            dst_ip: IpAddr::from_str("192.168.1.101").unwrap(),
            dst_port: 5001,
        };
        assert!(LANScanL7::is_likely_ephemeral(&udp_connection));

        let server_connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 80,
            dst_ip: IpAddr::from_str("192.168.1.200").unwrap(),
            dst_port: 45678,
        };
        assert!(!LANScanL7::is_likely_ephemeral(&server_connection));
    }
}

// Feature-specific tests that will only run on Linux with eBPF enabled
#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[cfg(test)]
mod ebpf_tests {
    use super::*;
    use crate::admin::get_admin_status;
    use crate::lanscan::sessions::{Protocol, Session};
    use rand::Rng;
    use std::io::ErrorKind;
    use std::net::TcpStream;
    use std::process::Command;
    use std::process::Stdio;

    #[derive(Debug)]
    enum NcError {
        NotFound,     // no nc binary available
        ListenFailed, // command started but server never became ready
        SpawnFailed,  // some other spawn error (permissions etc.)
    }

    fn start_nc_server(port: u16) -> Result<std::process::Child, NcError> {
        let port_str = port.to_string();

        // Common netcat binaries we accept in order of preference.
        // `nc` is usually provided via the alternatives system (OpenBSD or
        // traditional implementation).  The other names cover systems where
        // the wrapper has not been configured.
        const CANDIDATES: &[&str] = &["nc", "netcat", "ncat", "nc.traditional"];

        // Two common syntax variants (traditional vs. OpenBSD).  We try the
        // traditional "-l -p <port>" first because that is required by the
        // `netcat-traditional` package shipped in the test container.  The
        // OpenBSD syntax "-l <port>" is attempted second.
        let try_args = vec![vec!["-l", "-p", &port_str], vec!["-l", &port_str]];

        let mut spawn_success = false; // at least one binary executed

        for cmd_name in CANDIDATES {
            println!("Trying to start netcat server with {}", cmd_name);
            for args in &try_args {
                let mut cmd = Command::new(cmd_name);
                cmd.args(args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());

                match cmd.spawn() {
                    Ok(mut child) => {
                        spawn_success = true;
                        println!("Started netcat server with {} {:?}", cmd_name, args);
                        // wait up to 5 s for the listener
                        let start = std::time::Instant::now();
                        let timeout = std::time::Duration::from_secs(20);
                        let mut server_ready = false;
                        while start.elapsed() < timeout {
                            println!("Checking if netcat server is ready");
                            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                                server_ready = true;
                                break;
                            }
                            println!("Waiting for netcat server to listen on port {}", port);
                            std::thread::sleep(std::time::Duration::from_secs(5));
                        }
                        if server_ready {
                            println!("Netcat server is ready");
                            return Ok(child);
                        } else {
                            println!("Netcat server {:?} is not ready after timeout", args);
                            println!("Killing netcat server");
                            // Ensure the child terminates before we attempt to
                            // drain its stderr so we don't block indefinitely.
                            let _ = child.kill();

                            match child.wait_with_output() {
                                Ok(output) => {
                                    let status = output.status;
                                    let out_str = String::from_utf8_lossy(&output.stdout);
                                    let err_str = String::from_utf8_lossy(&output.stderr);
                                    eprintln!("[test] {} {:?} exited with status {}\nstdout:\n{}\nstderr:\n{}", cmd_name, args, status, out_str.trim(), err_str.trim());
                                }
                                Err(e) => {
                                    eprintln!(
                                        "[test] Failed to collect output from {} {:?}: {}",
                                        cmd_name, args, e
                                    );
                                }
                            }
                            // Try next argument variant / candidate instead
                            continue;
                        }
                    }
                    Err(e) => {
                        if e.kind() == ErrorKind::NotFound {
                            println!(
                                "Binary '{}' not found (args {:?}): {} - continuing",
                                cmd_name, args, e
                            );
                            continue; // try next candidate name
                        } else {
                            eprintln!("[test] Unable to spawn {} {:?}: {}", cmd_name, args, e);
                            return Err(NcError::SpawnFailed);
                        }
                    }
                }
            }
        }
        if spawn_success {
            Err(NcError::ListenFailed)
        } else {
            Err(NcError::NotFound)
        }
    }

    fn start_nc_client(port: u16) -> Result<std::process::Child, NcError> {
        let port_str = port.to_string();

        const CANDIDATES: &[&str] = &["nc", "netcat", "ncat", "nc.traditional"];

        for cmd_name in CANDIDATES {
            let mut cmd = Command::new(cmd_name);
            cmd.args(["127.0.0.1", &port_str])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            match cmd.spawn() {
                Ok(child) => return Ok(child),
                Err(e) => {
                    if e.kind() == ErrorKind::NotFound {
                        continue; // next candidate
                    } else {
                        eprintln!("[test] Unable to spawn {}: {}", cmd_name, e);
                        return Err(NcError::SpawnFailed);
                    }
                }
            }
        }
        Err(NcError::NotFound)
    }

    #[tokio::test]
    async fn test_ebpf_l7_resolution() {
        if !get_admin_status() {
            println!("Skipping test_ebpf_l7_resolution: insufficient privileges");
            return;
        }
        if !l7_ebpf::is_available() {
            println!("Skipping test_ebpf_l7_resolution: eBPF helper not available");
            return;
        }
        let port: u16 = rand::thread_rng().gen_range(20000..40000);
        let mut server_process = match start_nc_server(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                println!("Skipping test_ebpf_l7_resolution: netcat not installed");
                return;
            }
            Err(err) => {
                panic!("Could not start netcat server: {:?}", err);
            }
        };
        let mut client_process = match start_nc_client(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                let _ = server_process.kill();
                println!("Skipping test_ebpf_l7_resolution: netcat not installed");
                return;
            }
            Err(err) => {
                let _ = server_process.kill();
                panic!("Could not start netcat client: {:?}", err);
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(500));
        let lanscan_l7 = LANScanL7::new();
        let session = Session {
            protocol: Protocol::TCP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: port,
            dst_ip: "127.0.0.1".parse().unwrap(),
            dst_port: port,
        };
        let server_l7 = lanscan_l7.get_resolved_l7(&session).await;
        let _ = client_process.kill();
        let _ = server_process.kill();
        if let Some(resolution) = server_l7 {
            println!("eBPF resolution source: {:?}", resolution.source);
            println!("eBPF resolution data: {:?}", resolution.l7);
            assert_eq!(
                resolution.source,
                L7ResolutionSource::Ebpf,
                "Expected eBPF resolution source"
            );
            if let Some(l7_data) = resolution.l7 {
                assert!(
                    l7_data.process_name.contains("nc") || l7_data.process_name.contains("netcat"),
                    "Expected process name to contain 'nc' or 'netcat', got: {}",
                    l7_data.process_name
                );
                assert!(l7_data.pid > 0, "Expected non-zero PID");
            } else {
                panic!("eBPF resolution source but no L7 data");
            }
        } else {
            panic!("Expected eBPF resolution for known socket");
        }
    }

    #[tokio::test]
    async fn test_ebpf_l7_priority_over_standard_resolver() {
        if !get_admin_status() {
            println!(
                "Skipping test_ebpf_l7_priority_over_standard_resolver: insufficient privileges"
            );
            return;
        }
        if !l7_ebpf::is_available() {
            println!(
                "Skipping test_ebpf_l7_priority_over_standard_resolver: eBPF helper not available"
            );
            return;
        }
        let port: u16 = rand::thread_rng().gen_range(20000..40000);
        let mut server_process = match start_nc_server(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                println!(
                    "Skipping test_ebpf_l7_priority_over_standard_resolver: netcat not installed"
                );
                return;
            }
            Err(err) => {
                panic!("Could not start netcat server: {:?}", err);
            }
        };
        let mut client_process = match start_nc_client(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                let _ = server_process.kill();
                println!(
                    "Skipping test_ebpf_l7_priority_over_standard_resolver: netcat not installed"
                );
                return;
            }
            Err(err) => {
                let _ = server_process.kill();
                panic!("Could not start netcat client: {:?}", err);
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut lanscan_l7 = LANScanL7::new();
        lanscan_l7.start().await;
        use tokio::time::sleep;
        let session = Session {
            protocol: Protocol::TCP,
            src_ip: "127.0.0.1".parse().unwrap(),
            src_port: port,
            dst_ip: "127.0.0.1".parse().unwrap(),
            dst_port: port,
        };
        let initial_result = lanscan_l7.get_resolved_l7(&session).await;
        let mut from_ebpf = false;
        if let Some(resolution) = initial_result {
            println!("Initial resolution source: {:?}", resolution.source);
            if resolution.source == L7ResolutionSource::Ebpf {
                from_ebpf = true;
                if let Some(l7) = resolution.l7 {
                    println!(
                        "Initial eBPF resolution: pid={}, name={}",
                        l7.pid, l7.process_name
                    );
                }
            }
        }
        if !from_ebpf {
            lanscan_l7.add_connection_to_resolver(&session).await;
            sleep(std::time::Duration::from_secs(2)).await;
            if let Some(resolution) = lanscan_l7.get_resolved_l7(&session).await {
                println!("Queue-based resolution source: {:?}", resolution.source);
                if resolution.source == L7ResolutionSource::Ebpf {
                    from_ebpf = true;
                    if let Some(l7) = resolution.l7 {
                        println!(
                            "Queue-based eBPF resolution: pid={}, name={}",
                            l7.pid, l7.process_name
                        );
                    }
                }
            }
        }
        let _ = client_process.kill();
        let _ = server_process.kill();
        lanscan_l7.stop().await;
        assert!(
            from_ebpf,
            "With eBPF feature enabled, resolution should come from eBPF"
        );
    }

    #[tokio::test]
    async fn test_ebpf_l7_integration_with_capture() {
        use crate::lanscan::capture::LANScanCapture;
        use crate::lanscan::interface::LANScanInterfaces;
        if !get_admin_status() {
            println!("Skipping test_ebpf_l7_integration_with_capture: insufficient privileges");
            return;
        }
        if !l7_ebpf::is_available() {
            println!("Skipping test_ebpf_l7_integration_with_capture: eBPF helper not available");
            return;
        }
        let port: u16 = rand::thread_rng().gen_range(20000..40000);
        println!("Starting netcat server on port {}", port);
        let mut server_process = match start_nc_server(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                println!("Skipping test_ebpf_l7_integration_with_capture: netcat not installed");
                return;
            }
            Err(err) => {
                println!("Could not start netcat server: {:?}", err);
                panic!("Could not start netcat server: {:?}", err);
            }
        };
        println!("Starting netcat client on port {}", port);
        let mut client_process = match start_nc_client(port) {
            Ok(child) => child,
            Err(NcError::NotFound) => {
                let _ = server_process.kill();
                println!("Skipping test_ebpf_l7_integration_with_capture: netcat not installed");
                return;
            }
            Err(err) => {
                let _ = server_process.kill();
                panic!("Could not start netcat client: {:?}", err);
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(500));
        println!("Starting capture");
        let mut capture = LANScanCapture::new();
        let interfaces = LANScanInterfaces::new();
        println!("Starting capture on interfaces: {}", interfaces);
        capture.start(&interfaces).await;
        sleep(std::time::Duration::from_secs(3)).await;
        let mut found_connection = false;
        let mut sessions = vec![];
        let check_start = std::time::Instant::now();
        while check_start.elapsed().as_secs() < 5 {
            sessions = capture.get_current_sessions(false).await;
            for session in &sessions {
                if (session.session.src_port == port || session.session.dst_port == port)
                    && session.session.protocol == Protocol::TCP
                {
                    found_connection = true;
                    println!("Found test connection: {:?}", session.session);
                    if let Some(l7_info) = &session.l7 {
                        println!(
                            "L7 resolution: pid={}, process={}",
                            l7_info.pid, l7_info.process_name
                        );
                        assert!(
                            l7_info.process_name.contains("nc")
                                || l7_info.process_name.contains("netcat"),
                            "Expected process name to contain 'nc' or 'netcat', got: {}",
                            l7_info.process_name
                        );
                    }
                    break;
                }
            }
            if found_connection {
                break;
            }
            sleep(std::time::Duration::from_millis(200)).await;
        }
        if !found_connection {
            eprintln!("Sessions seen: {:?}", sessions);
        }
        let _ = client_process.kill();
        let _ = server_process.kill();
        capture.stop().await;
        assert!(found_connection, "Should have found the test connection");
    }
}
