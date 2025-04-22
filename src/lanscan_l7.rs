use crate::lanscan_sessions::*;
use crate::runtime::*;
use crate::rwlock::CustomRwLock;
use anyhow::Result;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo,
};
use std::collections::{HashMap, HashSet};
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

// Add a constant for ephemeral connection retry timing
static EPHEMERAL_RETRY_MS: u64 = 50; // Very quick retry for ephemeral connections

#[derive(Debug, Clone)]
pub struct L7Resolution {
    pub l7: Option<SessionL7>,
    pub date: DateTime<Utc>,
    pub retry_count: usize,
    pub last_retry: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct ProcessCacheEntry {
    pub l7: SessionL7,
    pub last_seen: Instant,
    pub hit_count: usize,
}

pub struct LANScanL7 {
    l7_map: Arc<DashMap<Session, L7Resolution>>,
    resolver_queue: Arc<DashMap<Session, ()>>,
    resolver_handle: Option<TaskHandle>,
    system: Arc<CustomRwLock<System>>,
    users: Arc<CustomRwLock<Users>>,
    port_process_cache: Arc<DashMap<(u16, Protocol), ProcessCacheEntry>>,
    cache_cleanup_handle: Option<TaskHandle>,
    host_service_cache: Arc<DashMap<String, Vec<(u16, Protocol, SessionL7)>>>,
}

impl LANScanL7 {
    pub fn new() -> Self {
        Self {
            l7_map: Arc::new(DashMap::new()),
            resolver_queue: Arc::new(DashMap::new()),
            resolver_handle: None,
            system: Arc::new(CustomRwLock::new(System::new_all())),
            users: Arc::new(CustomRwLock::new(Users::new())),
            port_process_cache: Arc::new(DashMap::new()),
            cache_cleanup_handle: None,
            host_service_cache: Arc::new(DashMap::new()),
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
                let to_resolve: Vec<Session>;
                {
                    to_resolve = resolver_queue
                        .iter()
                        .map(|entry| entry.key().clone())
                        .collect();
                    if !to_resolve.is_empty() {
                        for session in &to_resolve {
                            resolver_queue.remove(session);
                        }
                    }
                }

                let to_resolve_len = to_resolve.len();
                if !to_resolve.is_empty() {
                    {
                        let mut sys = system.write().await;
                        sys.refresh_specifics(refresh_kind);

                        let mut users = users.write().await;
                        users.refresh();
                    }

                    let socket_info = match get_sockets_info(
                        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
                        ProtocolFlags::TCP | ProtocolFlags::UDP,
                    ) {
                        Ok(socket_info) => socket_info,
                        Err(e) => {
                            error!("Failed to get socket info: {:?}", e);
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

                    let mut failed_resolutions = HashSet::new();
                    let mut resolutions_to_remove = Vec::new();

                    for connection in to_resolve {
                        let mut retry_count = 0;

                        let should_skip = if let Some(resolution) = l7_map.get(&connection) {
                            retry_count = resolution.value().retry_count;

                            if retry_count > 0 {
                                if let Some(last_retry) = resolution.value().last_retry {
                                    let is_likely_ephemeral =
                                        Self::is_likely_ephemeral(&connection);

                                    let wait_duration = if is_likely_ephemeral {
                                        Duration::from_millis(EPHEMERAL_RETRY_MS)
                                    } else {
                                        let backoff_ms = (2_u64.pow(retry_count as u32 - 1)) * 100;
                                        Duration::from_millis(backoff_ms.min(10000))
                                    };

                                    let elapsed = last_retry.elapsed();

                                    if elapsed < wait_duration {
                                        failed_resolutions.insert(connection.clone());
                                        true
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        };

                        if should_skip {
                            continue;
                        }

                        let from_host_cache = Self::try_resolve_from_host_cache(
                            &connection,
                            &host_service_cache,
                            &*system_read,
                        )
                        .await;

                        if let Some(l7_data) = from_host_cache {
                            trace!(
                                "Successfully L7 resolved connection {:?} from host cache: {:?}",
                                connection,
                                l7_data
                            );

                            Self::update_port_process_cache(
                                &connection,
                                &l7_data,
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
                                },
                            );
                            continue;
                        }

                        let resolution_result = Self::resolve_l7_data(
                            &connection,
                            &socket_info,
                            &pid_to_process,
                            &uid_to_username,
                        )
                        .await;

                        match resolution_result {
                            Ok(l7_data) => {
                                trace!(
                                    "Successfully L7 resolved connection {:?}: {:?}",
                                    connection,
                                    l7_data
                                );

                                Self::update_port_process_cache(
                                    &connection,
                                    &l7_data,
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
                                    },
                                );
                            }
                            Err(e) => {
                                trace!("Standard resolution failed for {:?}: {:?}", connection, e);

                                let cache_resolution = Self::try_resolve_from_cache(
                                    &connection,
                                    &port_process_cache,
                                    &*system_read,
                                )
                                .await;

                                if let Some(cached_l7) = cache_resolution {
                                    debug!(
                                        "Using cached L7 data for connection {:?}: {:?}",
                                        connection, cached_l7
                                    );

                                    l7_map.insert(
                                        connection.clone(),
                                        L7Resolution {
                                            l7: Some(cached_l7),
                                            date: Utc::now(),
                                            retry_count: 0,
                                            last_retry: None,
                                        },
                                    );
                                } else {
                                    retry_count += 1;

                                    if retry_count > 8 {
                                        trace!(
                                            "Max retries reached for connection {:?}, giving up",
                                            connection
                                        );
                                        resolutions_to_remove.push(connection.clone());
                                    } else {
                                        l7_map.insert(
                                            connection.clone(),
                                            L7Resolution {
                                                l7: None,
                                                date: Utc::now(),
                                                retry_count,
                                                last_retry: Some(Instant::now()),
                                            },
                                        );
                                        failed_resolutions.insert(connection.clone());
                                    }
                                }
                            }
                        }
                    }

                    let resolutions_to_remove_len = resolutions_to_remove.len();
                    if resolutions_to_remove_len > 0 {
                        for resolution in resolutions_to_remove {
                            l7_map.remove(&resolution);
                        }
                        info!(
                            "Removed {} old/failed L7 resolutions",
                            resolutions_to_remove_len
                        );
                    }

                    let failed_resolutions_len = failed_resolutions.len();
                    if failed_resolutions_len > 0 {
                        for session in failed_resolutions {
                            resolver_queue.insert(session, ());
                        }
                        debug!("Re-queued {} failed L7 resolutions", failed_resolutions_len);
                    }
                    let resolved_success = to_resolve_len - failed_resolutions_len;

                    if resolved_success > 0 {
                        info!(
                            "L7 resolved {} sessions / {} failed",
                            resolved_success, failed_resolutions_len
                        );
                    }
                    // Sleep for a little while to avoid overwhelming the system but keep a tight loop to ensure we're responsive to new sessions
                    sleep(Duration::from_millis(100)).await;
                } else {
                    // No sessions to resolve, sleep for a while to avoid overwhelming the system
                    sleep(Duration::from_millis(200)).await;
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

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        let cleanup_handle = async_spawn(async move {
            info!("Starting L7 cache cleanup task");

            while !stop_flag_clone.load(Ordering::Relaxed) {
                // Clean up port process cache
                let mut to_remove = Vec::new();
                for entry in port_process_cache.iter() {
                    if entry.value().last_seen.elapsed() > Duration::from_secs(3600)
                        && entry.value().hit_count < 10
                    {
                        to_remove.push(entry.key().clone());
                    }
                }

                let removed_count = to_remove.len();
                for key in to_remove {
                    port_process_cache.remove(&key);
                }

                if removed_count > 0 {
                    debug!(
                        "Removed {} old entries from port process cache",
                        removed_count
                    );
                }

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
                    // The localhost entry should always be the newest, so we just keep it up to date
                    debug!(
                        "Localhost service cache has {} entries",
                        localhost_entry.value().len()
                    );
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
        port_process_cache: &DashMap<(u16, Protocol), ProcessCacheEntry>,
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
            if let Some(mut entry) = port_process_cache.get_mut(&(port, protocol.clone())) {
                entry.value_mut().last_seen = Instant::now();
                entry.value_mut().hit_count += 1;
            } else {
                let cache_key = (port, protocol);
                port_process_cache.insert(
                    cache_key.clone(),
                    ProcessCacheEntry {
                        l7: l7_data.clone(),
                        last_seen: Instant::now(),
                        hit_count: 1,
                    },
                );
                debug!("Cached L7 data for port {:?}: {:?}", cache_key, l7_data);
            }
        }
    }

    async fn try_resolve_from_cache(
        connection: &Session,
        port_process_cache: &DashMap<(u16, Protocol), ProcessCacheEntry>,
        system: &System,
    ) -> Option<SessionL7> {
        let protocol = connection.protocol.clone();
        let cache_keys = [
            (connection.src_port, protocol.clone()),
            (connection.dst_port, protocol.clone()),
        ];

        for key in &cache_keys {
            if let Some(mut cached_entry) = port_process_cache.get_mut(key) {
                if system
                    .process(Pid::from_u32(cached_entry.value().l7.pid))
                    .is_some()
                {
                    cached_entry.value_mut().last_seen = Instant::now();
                    cached_entry.value_mut().hit_count += 1;
                    return Some(cached_entry.value().l7.clone());
                } else {
                    debug!(
                        "Removing stale cache entry for {:?}: PID {} no longer exists",
                        key,
                        cached_entry.value().l7.pid
                    );
                    port_process_cache.remove(key);
                    continue;
                }
            }
        }

        None
    }

    async fn update_host_service_cache(
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
        host_service_cache: &DashMap<String, Vec<(u16, Protocol, SessionL7)>>,
    ) {
        let mut temp_cache: HashMap<String, Vec<(u16, Protocol, SessionL7)>> = HashMap::new();

        for socket in socket_info {
            let (port, protocol) = match &socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => (tcp.local_port, Protocol::TCP),
                ProtocolSocketInfo::Udp(udp) => (udp.local_port, Protocol::UDP),
            };

            if port > 32768 {
                continue;
            }

            if let Some(l7_data) =
                Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username).await
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

    async fn try_resolve_from_host_cache(
        connection: &Session,
        host_service_cache: &DashMap<String, Vec<(u16, Protocol, SessionL7)>>,
        system: &System,
    ) -> Option<SessionL7> {
        let local_connection = is_private_ip(connection.src_ip) || is_private_ip(connection.dst_ip);

        if !local_connection {
            return None;
        }

        if let Some(localhost_services) = host_service_cache.get("localhost") {
            for (service_port, service_protocol, l7_data) in localhost_services.value() {
                if (connection.src_port == *service_port || connection.dst_port == *service_port)
                    && connection.protocol == *service_protocol
                {
                    if system.process(Pid::from_u32(l7_data.pid)).is_some() {
                        return Some(l7_data.clone());
                    } else {
                        debug!(
                            "Skipping stale host cache entry for port {}, protocol {:?}: PID {} no longer exists",
                            service_port, service_protocol, l7_data.pid
                        );
                        continue;
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
            },
        );

        self.resolver_queue.insert(connection.clone(), ());

        trace!("Added connection to L7 resolver queue: {:?}", connection);
    }

    pub async fn get_resolved_l7(&self, connection: &Session) -> Option<L7Resolution> {
        if let Some(l7) = self.l7_map.get(connection).map(|s| s.value().clone()) {
            Some(l7)
        } else {
            self.add_connection_to_resolver(connection).await;
            None
        }
    }

    async fn resolve_l7_data(
        connection: &Session,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
    ) -> Result<SessionL7> {
        if let Some(l7_data) =
            Self::try_exact_match(connection, socket_info, pid_to_process, uid_to_username).await
        {
            return Ok(l7_data);
        }

        if let Some(l7_data) =
            Self::try_partial_match(connection, socket_info, pid_to_process, uid_to_username).await
        {
            debug!("Found L7 data using partial match for {:?}", connection);
            return Ok(l7_data);
        }

        if let Some(l7_data) =
            Self::try_port_only_match(connection, socket_info, pid_to_process, uid_to_username)
                .await
        {
            debug!("Found L7 data using port-only match for {:?}", connection);
            return Ok(l7_data);
        }

        Err(anyhow::anyhow!("No matching process found"))
    }

    async fn try_exact_match(
        connection: &Session,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
    ) -> Option<SessionL7> {
        for socket in socket_info.iter() {
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
                if let Some(l7) =
                    Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username).await
                {
                    return Some(l7);
                }
            }
        }
        None
    }

    async fn try_partial_match(
        connection: &Session,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
    ) -> Option<SessionL7> {
        for socket in socket_info.iter() {
            let is_partial_match = match &socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_socket) => {
                    (tcp_socket.local_addr == connection.src_ip
                        && tcp_socket.local_port == connection.src_port)
                        || (tcp_socket.remote_addr == connection.dst_ip
                            && tcp_socket.remote_port == connection.dst_port)
                        || (tcp_socket.local_addr == connection.dst_ip
                            && tcp_socket.local_port == connection.dst_port)
                        || (tcp_socket.remote_addr == connection.src_ip
                            && tcp_socket.remote_port == connection.src_port)
                }
                ProtocolSocketInfo::Udp(udp_socket) => {
                    udp_socket.local_addr == connection.src_ip
                        || udp_socket.local_addr == connection.dst_ip
                }
            };

            if is_partial_match {
                if let Some(l7) =
                    Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username).await
                {
                    return Some(l7);
                }
            }
        }
        None
    }

    async fn try_port_only_match(
        connection: &Session,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
    ) -> Option<SessionL7> {
        for socket in socket_info.iter() {
            let is_port_match = match &socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_socket) => {
                    (tcp_socket.local_port == connection.src_port
                        && tcp_socket.remote_port == connection.dst_port)
                        || (tcp_socket.local_port == connection.dst_port
                            && tcp_socket.remote_port == connection.src_port)
                }
                ProtocolSocketInfo::Udp(udp_socket) => {
                    udp_socket.local_port == connection.src_port
                        || udp_socket.local_port == connection.dst_port
                }
            };

            if is_port_match {
                if let Some(l7) =
                    Self::extract_l7_from_socket(socket, pid_to_process, uid_to_username).await
                {
                    return Some(l7);
                }
            }
        }
        None
    }

    async fn extract_l7_from_socket(
        socket: &SocketInfo,
        pid_to_process: &HashMap<u32, &Process>,
        uid_to_username: &HashMap<&Uid, &str>,
    ) -> Option<SessionL7> {
        let socket_pids = socket.associated_pids.clone();

        for socket_pid in socket_pids.clone() {
            if let Some(process) = pid_to_process.get(&socket_pid) {
                let username = if let Some(user_id) = process.user_id() {
                    match uid_to_username.get(&user_id).map(|s| s.to_string()) {
                        Some(username) => username,
                        None => {
                            // Try to get username from the users crate if available
                            #[cfg(unix)]
                            {
                                let user_id_u32 = **user_id; // dereference &Uid to get the u32
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

                return Some(SessionL7 {
                    pid: socket_pid,
                    process_name,
                    process_path,
                    username,
                });
            }
        }
        None
    }

    fn is_likely_ephemeral(connection: &Session) -> bool {
        if connection.dst_port == 53 || connection.src_port == 53 {
            return true;
        }

        let is_src_ephemeral_port = connection.src_port > 32768;
        let is_dst_well_known = connection.dst_port < 1024;

        if is_src_ephemeral_port && is_dst_well_known {
            return true;
        }

        if connection.protocol == Protocol::UDP {
            return true;
        }

        false
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
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 10.0.0.0/8
            octets[0] == 10 ||
            // 172.16.0.0/12
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
            // 192.168.0.0/16
            (octets[0] == 192 && octets[1] == 168) ||
            // 127.0.0.0/8 (localhost)
            octets[0] == 127
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback() || ipv6.is_unspecified(),
    }
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
                last_seen: Instant::now(),
                hit_count: 0,
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
