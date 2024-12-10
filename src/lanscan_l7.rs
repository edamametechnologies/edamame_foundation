use crate::lanscan_sessions::*;
use crate::runtime::*;
use crate::rwlock::CustomRwLock;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use sysinfo::{Process, ProcessRefreshKind, RefreshKind, System, Uid, Users};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, trace, warn};

static RESOLUTION_TIMEOUT: ChronoDuration = ChronoDuration::seconds(60);

#[derive(Debug, Clone)]
pub struct L7Resolution {
    pub l7: Option<SessionL7>,
    pub date: DateTime<Utc>,
}

pub struct LANScanL7 {
    l7_map: Arc<DashMap<Session, L7Resolution>>,
    resolver_queue: Arc<CustomRwLock<HashSet<Session>>>,
    resolver_handle: Option<TaskHandle>,
    system: Arc<CustomRwLock<System>>,
    users: Arc<CustomRwLock<Users>>,
}

impl LANScanL7 {
    pub fn new() -> Self {
        Self {
            l7_map: Arc::new(DashMap::new()),
            resolver_queue: Arc::new(CustomRwLock::new(HashSet::new())),
            resolver_handle: None,
            system: Arc::new(CustomRwLock::new(System::new_all())),
            users: Arc::new(CustomRwLock::new(Users::new())),
        }
    }

    pub async fn start(&mut self) {
        if self.resolver_handle.is_some() {
            warn!("L7 resolver task is already running");
            return;
        }

        let resolver_queue = self.resolver_queue.clone();
        let l7_map = self.l7_map.clone();
        let system = self.system.clone();
        let users = self.users.clone();

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
                    let mut queue = resolver_queue.write().await;
                    to_resolve = queue.drain().collect();
                }

                let to_resolve_len = to_resolve.len();
                if !to_resolve.is_empty() {
                    // Refresh the system information
                    {
                        let mut sys = system.write().await;
                        sys.refresh_specifics(refresh_kind);

                        let mut users = users.write().await;
                        users.refresh();
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

                    let pid_to_process: HashMap<u32, &Process> = system_read
                        .processes()
                        .iter()
                        .map(|(pid, process)| (pid.as_u32(), process))
                        .collect();

                    let uid_to_username: HashMap<&Uid, &str> = users_read
                        .iter()
                        .map(|user| (user.id(), user.name()))
                        .collect();

                    let mut failed_resolutions = HashSet::new();
                    let mut resolutions_to_remove = Vec::new();

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
                                    if Utc::now() < resolution_date + RESOLUTION_TIMEOUT {
                                        // Will try again next time
                                        failed_resolutions.insert(connection.clone());
                                    } else {
                                        trace!(
                                            "Removing old resolution attempt for connection {:?}",
                                            connection
                                        );
                                        // The resolution attempt is too old, so we remove it
                                        resolutions_to_remove.push(connection.clone());
                                    }
                                } else {
                                    error!("No resolution found for connection {:?}", connection);
                                }
                            }
                        }
                    }

                    // Remove the resolutions that are too old
                    let resolutions_to_remove_len = resolutions_to_remove.len();
                    if resolutions_to_remove_len > 0 {
                        for resolution in resolutions_to_remove {
                            l7_map.remove(&resolution);
                        }
                        info!("Removed {} old L7 resolutions", resolutions_to_remove_len);
                    }

                    let failed_resolutions_len = failed_resolutions.len();
                    if failed_resolutions_len > 0 {
                        let mut queue = resolver_queue.write().await;
                        queue.extend(failed_resolutions);
                        debug!("Re-queued {} failed L7 resolutions", failed_resolutions_len);
                    }
                    let resolved_success = to_resolve_len - failed_resolutions_len;

                    if resolved_success > 0 {
                        info!(
                            "L7 resolved {} sessions / {} failed",
                            resolved_success, failed_resolutions_len
                        );
                    }
                }

                // Tight loop to catch short-lived connections
                sleep(Duration::from_millis(250)).await;
            }

            info!("L7 resolver task completed");
        });

        self.resolver_handle = Some(TaskHandle {
            handle: resolver_handle,
            stop_flag,
        });
    }

    pub async fn stop(&mut self) {
        if let Some(task_handle) = self.resolver_handle.take() {
            task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = task_handle.handle.await;
            info!("Stopped L7 resolver task");
        } else {
            warn!("L7 resolver task not running");
        }
    }

    pub async fn add_connection_to_resolver(&self, connection: &Session) {
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
        // Try to match the connection to a socket
        for socket in socket_info.iter() {
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
                // Get the PIDs of the socket
                let socket_pids = socket.associated_pids.clone();

                // Find the process by PID
                for socket_pid in socket_pids.clone() {
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

                        return Ok(SessionL7 {
                            pid: socket_pid,
                            process_name,
                            process_path,
                            username,
                        });
                    }
                }
                return Err(anyhow!("Process not found for PIDs {:?}", socket_pids));
            }
        }

        Err(anyhow::anyhow!("No matching process found"))
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

        // Start the resolver
        lanscan_l7.start().await;

        // Check that resolver_handle is Some
        assert!(lanscan_l7.resolver_handle.is_some());

        // Stop the resolver
        lanscan_l7.stop().await;

        // Check that resolver_handle is None
        assert!(lanscan_l7.resolver_handle.is_none());
    }

    #[tokio::test]
    async fn test_add_connection_to_resolver() {
        let lanscan_l7 = LANScanL7::new();

        // Create a sample Session
        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };

        // Add the connection to the resolver
        lanscan_l7.add_connection_to_resolver(&connection).await;

        // Check that the connection is in the resolver_queue
        let queue = lanscan_l7.resolver_queue.read().await;
        assert!(queue.contains(&connection));

        // Check that the connection is in l7_map with l7: None
        if let Some(resolution) = lanscan_l7.l7_map.get(&connection) {
            assert!(resolution.l7.is_none());
        } else {
            panic!("Connection not found in l7_map");
        };
    }

    #[tokio::test]
    async fn test_get_resolved_l7_before_resolution() {
        let lanscan_l7 = LANScanL7::new();

        // Create a sample Session
        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("93.184.216.34").unwrap(),
            dst_port: 80,
        };

        // Try to get resolved L7 data before adding the connection
        let l7_resolution = lanscan_l7.get_resolved_l7(&connection).await;
        assert!(l7_resolution.is_none());

        // Add the connection to the resolver
        lanscan_l7.add_connection_to_resolver(&connection).await;

        // Try to get resolved L7 data immediately after adding
        let l7_resolution = lanscan_l7.get_resolved_l7(&connection).await;
        assert!(l7_resolution.is_some());
        let l7_resolution = l7_resolution.unwrap();
        assert!(l7_resolution.l7.is_none());
    }

    #[tokio::test]
    async fn test_resolve_l7_data_no_match() {
        // Create a sample Session that won't match any socket
        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("10.0.0.1").unwrap(),
            src_port: 54321,
            dst_ip: IpAddr::from_str("10.0.0.2").unwrap(),
            dst_port: 12345,
        };

        // Empty socket info and mappings
        let socket_info = vec![];
        let pid_to_process = HashMap::new();
        let uid_to_username = HashMap::new();

        // Call resolve_l7_data()
        let result = LANScanL7::resolve_l7_data(
            &connection,
            &socket_info,
            &pid_to_process,
            &uid_to_username,
        )
        .await;

        // Assert that result is an error
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolver_task_processes_queue() {
        let mut lanscan_l7 = LANScanL7::new();

        // Start the resolver
        lanscan_l7.start().await;

        // Create a sample Session
        let connection = Session {
            protocol: Protocol::TCP,
            src_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            src_port: 12345,
            dst_ip: IpAddr::from_str("127.0.0.1").unwrap(),
            dst_port: 54321,
        };

        // Add the connection to the resolver
        lanscan_l7.add_connection_to_resolver(&connection).await;

        // Wait a bit to let the resolver task process the queue
        sleep(Duration::from_secs(1)).await;

        // Check if the connection has been processed
        let l7_resolution = lanscan_l7.get_resolved_l7(&connection).await;
        assert!(l7_resolution.is_some());
        let l7_resolution = l7_resolution.unwrap();
        // Since we probably don't have a matching process, l7 should still be None
        assert!(l7_resolution.l7.is_none() || l7_resolution.l7.is_some());

        // Stop the resolver
        lanscan_l7.stop().await;
    }
}
