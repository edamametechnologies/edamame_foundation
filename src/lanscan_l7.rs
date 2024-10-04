use crate::lanscan_connections::*;
use crate::runtime::async_spawn;
use crate::rwlock::CustomRwLock;
use anyhow::Result;
use chrono::{DateTime, TimeDelta, Utc};
use dashmap::DashMap;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use sysinfo::{System, Users};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, trace, warn};

static RESOLUTION_TIMEOUT: TimeDelta = TimeDelta::seconds(600);

#[derive(Debug, Clone)]
pub struct L7Resolution {
    pub l7: Option<ConnectionL7>,
    pub date: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct LANScanL7 {
    l7_map: Arc<DashMap<Connection, L7Resolution>>,
    resolver_queue: Arc<CustomRwLock<HashSet<Connection>>>,
    resolver_handle: Arc<CustomRwLock<Option<JoinHandle<()>>>>,
    resolver_stop_flag: Arc<AtomicBool>,
    system: Arc<CustomRwLock<System>>,
    users: Arc<CustomRwLock<Users>>,
}

impl LANScanL7 {
    pub fn new() -> Self {
        Self {
            l7_map: Arc::new(DashMap::new()),
            resolver_queue: Arc::new(CustomRwLock::new(HashSet::new())),
            resolver_handle: Arc::new(CustomRwLock::new(None)),
            resolver_stop_flag: Arc::new(AtomicBool::new(false)),
            system: Arc::new(CustomRwLock::new(System::new_all())),
            users: Arc::new(CustomRwLock::new(Users::new())),
        }
    }

    pub async fn start(&mut self) {
        let resolver_queue = self.resolver_queue.clone();
        let l7_map = self.l7_map.clone();
        let resolver_stop_flag = self.resolver_stop_flag.clone();
        let system = self.system.clone();
        let users = self.users.clone();

        let mut resolver_handle_guard = self.resolver_handle.write().await;
        if resolver_handle_guard.is_some() {
            warn!("L7 resolver task is already running");
            return;
        }

        let resolver_handle = async_spawn(async move {
            info!("Starting L7 resolver task");
            while !resolver_stop_flag.load(Ordering::Relaxed) {
                let to_resolve: Vec<Connection>;
                {
                    let mut queue = resolver_queue.write().await;
                    to_resolve = queue.drain().collect();
                    // Suppress the older resolutions
                }

                let to_resolve_len = to_resolve.len();
                if !to_resolve.is_empty() {
                    // Refresh the system information
                    {
                        let mut sys = system.write().await;
                        sys.refresh_all();

                        let mut users = users.write().await;
                        users.refresh_list();
                    }

                    // Get the socket info
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

                    // Build mappings
                    let system_read = system.read().await;
                    let users_read = users.read().await;

                    let pid_to_process: HashMap<u32, &sysinfo::Process> = system_read
                        .processes()
                        .iter()
                        .map(|(pid, process)| (pid.as_u32(), process))
                        .collect();

                    let uid_to_username: HashMap<&sysinfo::Uid, &str> = users_read
                        .iter()
                        .map(|user| (user.id(), user.name()))
                        .collect();

                    let mut failed_resolutions = HashSet::new();

                    for connection in to_resolve {
                        match Self::resolve_l7_data(
                            &connection,
                            &socket_info,
                            &pid_to_process,
                            &uid_to_username,
                        )
                        .await
                        {
                            Ok(l7_data) => {
                                trace!(
                                    "Successfully L7 resolved connection {:?}: {:?}",
                                    connection,
                                    l7_data
                                );
                                // Update the L7 map
                                l7_map.insert(
                                    connection,
                                    L7Resolution {
                                        l7: Some(l7_data),
                                        date: Utc::now(),
                                    },
                                );
                            }
                            Err(e) => {
                                trace!("Failed to L7 resolve connection {:?}: {:?}", connection, e);
                                // Check if the resolution attempt time is too old
                                if let Some(resolution) = l7_map.get(&connection) {
                                    let resolution_date = resolution.value().date;
                                    if Utc::now() - resolution_date < RESOLUTION_TIMEOUT {
                                        // Will try again next time
                                        failed_resolutions.insert(connection.clone());
                                    } else {
                                        debug!(
                                            "Removing old resolution for connection {:?}",
                                            connection
                                        );
                                        // The resolution attempt is too old, so we remove it
                                        l7_map.remove(&connection);
                                    }
                                } else {
                                    error!("No resolution found for connection {:?}", connection);
                                }
                            }
                        }
                    }

                    if !failed_resolutions.is_empty() {
                        let mut queue = resolver_queue.write().await;
                        let failed_resolutions_len = failed_resolutions.len();
                        queue.extend(failed_resolutions);
                        debug!("Re-queued {} failed L7 resolutions", queue.len());
                        info!(
                            "L7 resolved {} connections / {} failed",
                            to_resolve_len - failed_resolutions_len,
                            failed_resolutions_len
                        );
                    }
                }

                sleep(Duration::from_secs(5)).await;
            }

            info!("L7 resolver task completed");
        });

        *resolver_handle_guard = Some(resolver_handle);
    }

    pub async fn stop(&mut self) {
        if let Some(resolver_handle) = self.resolver_handle.write().await.take() {
            self.resolver_stop_flag.store(true, Ordering::Relaxed);
            let _ = resolver_handle.await;
            info!("Stopped L7 resolver task");
        }
    }

    pub async fn add_connection_to_resolver(&self, connection: &Connection) {
        if self.l7_map.contains_key(connection) {
            return;
        }

        self.resolver_queue.write().await.insert(connection.clone());
        // Populate the resolution map
        self.l7_map.insert(
            connection.clone(),
            L7Resolution {
                l7: None,
                date: Utc::now(),
            },
        );

        trace!("Added connection to L7 resolver queue: {:?}", connection);
    }

    pub async fn get_resolved_l7(&self, connection: &Connection) -> Option<L7Resolution> {
        if let Some(l7) = self.l7_map.get(connection).map(|s| s.value().clone()) {
            Some(l7)
        } else {
            self.add_connection_to_resolver(connection).await;
            None
        }
    }

    async fn resolve_l7_data(
        connection: &Connection,
        socket_info: &Vec<SocketInfo>,
        pid_to_process: &HashMap<u32, &sysinfo::Process>,
        uid_to_username: &HashMap<&sysinfo::Uid, &str>,
    ) -> Result<ConnectionL7> {
        // Try to match the connection to a socket
        for socket in socket_info.iter() {
            // Get the PID of the socket
            let socket_pid = match socket.associated_pids.get(0) {
                Some(pid) => *pid,
                None => continue, // No PID, skip this socket
            };

            // Check if the socket matches the connection
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
                // Find the process by PID
                if let Some(process) = pid_to_process.get(&socket_pid) {
                    // Get the username
                    let username = if let Some(user_id) = process.user_id() {
                        match uid_to_username.get(&user_id).map(|s| s.to_string()) {
                            Some(username) => username,
                            None => {
                                warn!("No username found for user_id {:?}", user_id);
                                String::new()
                            }
                        }
                    } else {
                        warn!("No user_id found for PID {:?}", socket_pid);
                        String::new()
                    };

                    // Get process name and path
                    let process_name = process.name().to_string_lossy().to_string();
                    let process_path = if let Some(path) = process.exe() {
                        path.to_string_lossy().to_string()
                    } else {
                        String::new()
                    };

                    return Ok(ConnectionL7 {
                        pid: socket_pid,
                        process_name,
                        process_path,
                        username,
                    });
                } else {
                    return Err(anyhow::anyhow!("Process not found for PID {}", socket_pid));
                }
            }
        }

        Err(anyhow::anyhow!("No matching process found"))
    }
}
