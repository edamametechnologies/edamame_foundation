use crate::runtime::*;
use crate::rwlock::CustomRwLock;
use dashmap::DashMap;
use dns_parser::Packet as DnsPacket;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{debug, info, trace, warn};

struct PendingQuery {
    domain_name: String,
    timestamp: Instant,
}

pub struct DnsPacketProcessor {
    pending_dns_queries: Arc<CustomRwLock<HashMap<u16, PendingQuery>>>,
    dns_resolutions: Arc<DashMap<IpAddr, String>>,
    dns_query_cleanup_handle: Option<TaskHandle>,
}

impl DnsPacketProcessor {
    pub fn new() -> Self {
        Self {
            pending_dns_queries: Arc::new(CustomRwLock::new(HashMap::new())),
            dns_resolutions: Arc::new(DashMap::new()),
            dns_query_cleanup_handle: None,
        }
    }

    pub fn get_dns_resolutions(&self) -> Arc<DashMap<IpAddr, String>> {
        self.dns_resolutions.clone()
    }

    pub async fn process_dns_packet(&self, dns_payload: Vec<u8>) {
        match DnsPacket::parse(&dns_payload) {
            Ok(dns_packet) => {
                trace!("DNS Packet: {:?}", dns_packet);

                let tx_id = dns_packet.header.id;
                if dns_packet.header.query {
                    // DNS Query
                    if let Some(question) = dns_packet.questions.get(0) {
                        let domain_name = question.qname.to_string();
                        // Exclude reverse lookups
                        if domain_name.ends_with(".in-addr.arpa")
                            || domain_name.ends_with(".ip6.arpa")
                        {
                            return;
                        }
                        // Store the transaction ID and domain name
                        let mut queries = self.pending_dns_queries.write().await;
                        debug!("DNS Query to {} ({})", domain_name, tx_id);
                        queries.insert(
                            tx_id,
                            PendingQuery {
                                domain_name,
                                timestamp: Instant::now(),
                            },
                        );
                    }
                } else {
                    // DNS Response
                    // Retrieve the domain name using the transaction ID
                    let pending_query = {
                        let mut queries = self.pending_dns_queries.write().await;
                        queries.remove(&tx_id)
                    };
                    if let Some(pending_query) = pending_query {
                        debug!(
                            "DNS Response from {} ({})",
                            pending_query.domain_name, tx_id
                        );
                        let domain_name = pending_query.domain_name;
                        // Collect IP addresses from the answer section
                        for answer in dns_packet.answers {
                            match answer.data {
                                dns_parser::rdata::RData::A(ipv4_addr) => {
                                    let ip_addr = IpAddr::V4(ipv4_addr.0);
                                    self.dns_resolutions.insert(ip_addr, domain_name.clone());
                                }
                                dns_parser::rdata::RData::AAAA(ipv6_addr) => {
                                    let ip_addr = IpAddr::V6(ipv6_addr.0);
                                    self.dns_resolutions.insert(ip_addr, domain_name.clone());
                                }
                                _ => {
                                    // Handle other record types if necessary
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse DNS packet: {}", e);
            }
        }
    }

    pub async fn start_dns_query_cleanup_task(&mut self) {
        let pending_dns_queries = self.pending_dns_queries.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        let handle = async_spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(10));
            loop {
                cleanup_interval.tick().await;
                if stop_flag_clone.load(Ordering::Relaxed) {
                    break;
                }
                let now = Instant::now();
                let mut queries = pending_dns_queries.write().await;
                queries.retain(|_, pending_query| {
                    now.duration_since(pending_query.timestamp) < Duration::from_secs(30)
                });
            }
            info!("DNS query cleanup task terminated");
        });

        self.dns_query_cleanup_handle = Some(TaskHandle { handle, stop_flag });
    }

    pub async fn stop_dns_query_cleanup_task(&mut self) {
        if let Some(task_handle) = self.dns_query_cleanup_handle.take() {
            task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = task_handle.handle.await;
        } else {
            warn!("DNS query cleanup task not running");
        }
    }
}
