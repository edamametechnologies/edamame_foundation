use crate::runtime::*;
use crate::rwlock::CustomRwLock;
use dashmap::DashMap;
use hickory_resolver::{
    config::ResolverConfig, name_server::TokioConnectionProvider, TokioResolver,
};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, trace, warn};

// Add constant for resolution retry parameters
const MAX_RESOLUTION_ATTEMPTS: usize = 3;
const RESOLUTION_RETRY_DELAY_MS: u64 = 500;

#[derive(Debug)]
pub struct LANScanResolver {
    resolvers: Arc<CustomRwLock<Vec<TokioResolver>>>,
    reverse_dns: Arc<DashMap<IpAddr, String>>,
    resolver_queue: Arc<CustomRwLock<VecDeque<IpAddr>>>,
    resolver_handle: Arc<CustomRwLock<Option<TaskHandle>>>,
}

impl LANScanResolver {
    pub fn new() -> Self {
        Self {
            resolvers: Arc::new(CustomRwLock::new(Vec::new())),
            reverse_dns: Arc::new(DashMap::new()),
            resolver_queue: Arc::new(CustomRwLock::new(VecDeque::new())),
            resolver_handle: Arc::new(CustomRwLock::new(None)),
        }
    }

    // Create resolvers for public DNS servers
    fn create_resolvers() -> Vec<TokioResolver> {
        let mut resolvers = Vec::new();

        // Google DNS
        let mut resolver_builder = TokioResolver::builder_with_config(
            ResolverConfig::google(),
            TokioConnectionProvider::default(),
        );
        resolver_builder.options_mut().try_tcp_on_error = true;
        let resolver = resolver_builder.build();
        resolvers.push(resolver);

        // Cloudflare DNS
        let mut resolver_builder = TokioResolver::builder_with_config(
            ResolverConfig::cloudflare(),
            TokioConnectionProvider::default(),
        );
        resolver_builder.options_mut().try_tcp_on_error = true;
        let resolver = resolver_builder.build();
        resolvers.push(resolver);

        // Quad9 DNS
        let mut resolver_builder = TokioResolver::builder_with_config(
            ResolverConfig::quad9(),
            TokioConnectionProvider::default(),
        );
        resolver_builder.options_mut().try_tcp_on_error = true;
        let resolver = resolver_builder.build();
        resolvers.push(resolver);

        resolvers
    }

    async fn perform_reverse_dns_lookup(
        ip_addr: IpAddr,
        reverse_dns: Arc<DashMap<IpAddr, String>>,
        resolvers: Vec<TokioResolver>,
    ) {
        // Skip if already resolved
        if let Some(entry) = reverse_dns.get(&ip_addr) {
            if entry.value() != "Resolving" {
                return;
            }
        }

        // Try each resolver with retries
        for (index, resolver) in resolvers.iter().enumerate() {
            for attempt in 1..=MAX_RESOLUTION_ATTEMPTS {
                match resolver.reverse_lookup(ip_addr).await {
                    Ok(lookup) => {
                        if let Some(name) = lookup.into_iter().next() {
                            let domain = name.to_string().trim_end_matches('.').to_string();
                            trace!(
                                "DNS resolution succeeded using resolver #{}: {} -> {}",
                                index,
                                ip_addr,
                                domain
                            );
                            reverse_dns.insert(ip_addr, domain);
                            return;
                        }
                    }
                    Err(e) => {
                        if attempt < MAX_RESOLUTION_ATTEMPTS {
                            trace!(
                                "Retry #{} for {} with resolver #{}: {}",
                                attempt,
                                ip_addr,
                                index,
                                e
                            );
                            sleep(Duration::from_millis(RESOLUTION_RETRY_DELAY_MS)).await;
                        } else {
                            debug!("Error with resolver #{} for {}: {}", index, ip_addr, e);
                        }
                    }
                }
            }
        }

        // All resolvers failed
        debug!("All resolvers failed for {}. Marking as Unknown.", ip_addr);
        reverse_dns.insert(ip_addr, "Unknown".to_string());
    }

    pub async fn start(&self) {
        if self.resolver_handle.read().await.is_some() {
            warn!("Resolver task is already running");
            return;
        }

        // Create resolvers
        let resolvers = Self::create_resolvers();
        *self.resolvers.write().await = resolvers.clone();

        // Spawn resolver task
        if !resolvers.is_empty() {
            let resolver_queue = self.resolver_queue.clone();
            let reverse_dns = self.reverse_dns.clone();
            let stop_flag = Arc::new(AtomicBool::new(false));
            let stop_flag_clone = stop_flag.clone();
            let resolvers_clone = resolvers.clone();

            let resolver_handle = async_spawn(async move {
                info!("Starting resolver task");

                while !stop_flag_clone.load(Ordering::Relaxed)
                    || !resolver_queue.read().await.is_empty()
                {
                    // Get the IPs to resolve from the queue
                    let to_resolve: Vec<IpAddr> = resolver_queue.write().await.drain(..).collect();
                    let to_resolve_len = to_resolve.len();
                    if to_resolve_len > 0 {
                        trace!("Resolving {} IPs", to_resolve_len);

                        // Resolve the IPs in parallel
                        let _ = futures::future::join_all(to_resolve.into_iter().map(|ip| {
                            let resolvers = resolvers_clone.clone();
                            let reverse_dns = reverse_dns.clone();
                            async move {
                                Self::perform_reverse_dns_lookup(ip, reverse_dns, resolvers).await
                            }
                        }))
                        .await;

                        info!("Resolved {} IPs", to_resolve_len);
                    }

                    // Sleep briefly before checking queue again
                    sleep(Duration::from_secs(2)).await;
                }

                info!("Resolver task completed");
            });

            *self.resolver_handle.write().await = Some(TaskHandle {
                handle: resolver_handle,
                stop_flag,
            });
        }
    }

    pub async fn stop(&self) {
        if let Some(task_handle) = self.resolver_handle.write().await.take() {
            task_handle.stop_flag.store(true, Ordering::Relaxed);
            let _ = task_handle.handle.await;
            info!("Stopped resolver task");
        } else {
            warn!("Resolver task not running");
        }
    }

    pub async fn add_ip_to_resolver(&self, ip_addr: &IpAddr) {
        // Check if the IP has already been resolved
        if self.reverse_dns.get(ip_addr).is_some() {
            return;
        }

        // Add the IP to the resolver queue
        self.resolver_queue.write().await.push_back(*ip_addr);
        debug!("Added IP to resolver queue: {}", ip_addr);
        // Mark the IP as resolving
        self.reverse_dns.insert(*ip_addr, "Resolving".to_string());
    }

    pub async fn get_resolved_ip(&self, ip_addr: &IpAddr) -> Option<String> {
        // Check if the IP is already resolved
        match self.reverse_dns.get(ip_addr).map(|s| s.value().clone()) {
            Some(domain) => match domain.as_str() {
                "Resolving" => None,
                _ => Some(domain),
            },
            None => None,
        }
    }

    // Add a new method to integrate DNS resolutions from packet capture
    pub fn add_dns_resolutions(&self, dns_resolutions: &DashMap<IpAddr, String>) -> usize {
        let mut added_count = 0;

        for entry in dns_resolutions.iter() {
            let ip = *entry.key();
            let domain = entry.value().clone();

            // Only use captured DNS if it looks like a proper domain
            // Skip .local and .arpa domains which are typically not useful for user display
            if domain.contains('.') && !domain.ends_with(".local") && !domain.ends_with(".arpa") {
                let should_update = match self.reverse_dns.get(&ip) {
                    Some(existing) => {
                        let existing_value = existing.value();
                        // Always update if current value is "Unknown" or "Resolving"
                        if existing_value == "Unknown" || existing_value == "Resolving" {
                            true
                        } else {
                            if domain != existing_value.as_str() {
                                // For other values (likely from reverse DNS), prefer forward DNS
                                // but log that we're replacing the value
                                debug!(
                                    "Replacing reverse DNS {} with forward DNS {} for IP {}",
                                    existing_value, domain, ip
                                );
                                true
                            } else {
                                false
                            }
                        }
                    }
                    None => true, // No existing entry, so add it
                };

                if should_update {
                    debug!(
                        "Adding forward DNS resolution to resolver cache: {} -> {}",
                        ip, domain
                    );
                    self.reverse_dns.insert(ip, domain);
                    added_count += 1;
                }
            }
        }

        if added_count > 0 {
            info!(
                "Integrated {} DNS resolutions from packet capture",
                added_count
            );
        }

        added_count
    }

    // Add a method to prioritize DNS resolution for important services
    pub async fn prioritize_resolution(&self, ip: &IpAddr, is_important: bool) {
        // If this IP is already being resolved or has been resolved, we're done
        if self.reverse_dns.contains_key(ip) {
            return;
        }

        // Add to resolver queue
        self.add_ip_to_resolver(ip).await;

        // For important IPs (e.g., connected servers), try to resolve immediately
        // instead of waiting for the background task
        if is_important {
            if let Some(resolver) = self.resolvers.read().await.first().cloned() {
                // Try immediate resolution in a separate task
                let ip_copy = *ip;
                let reverse_dns = self.reverse_dns.clone();
                let resolvers_vec = vec![resolver];

                tokio::spawn(async move {
                    Self::perform_reverse_dns_lookup(ip_copy, reverse_dns, resolvers_vec).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_reverse_dns_lookup_success() {
        let resolver = Arc::new(LANScanResolver::new());
        resolver.start().await;

        // Use a real IP address for testing (Google's DNS)
        let ip_addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        resolver.add_ip_to_resolver(&ip_addr).await;

        // Wait for the resolver to complete
        while resolver.get_resolved_ip(&ip_addr).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        let domain = resolver.get_resolved_ip(&ip_addr).await.unwrap();
        assert_eq!(domain, "dns.google");
    }

    #[tokio::test]
    async fn test_reverse_dns_lookup_unknown() {
        let resolver = Arc::new(LANScanResolver::new());
        resolver.start().await;

        // Use a non-existent IP address for testing
        let ip_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)); // Reserved IP for documentation
        resolver.add_ip_to_resolver(&ip_addr).await;

        // Wait for the resolver to complete
        while resolver.get_resolved_ip(&ip_addr).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        let domain = resolver.get_resolved_ip(&ip_addr).await.unwrap();
        assert_eq!(domain, "Unknown");
    }

    #[tokio::test]
    async fn test_add_same_ip_multiple_times() {
        let resolver = Arc::new(LANScanResolver::new());
        resolver.start().await;

        let ip_addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        resolver.add_ip_to_resolver(&ip_addr).await;
        resolver.add_ip_to_resolver(&ip_addr).await; // Adding the same IP again

        // Wait for the resolver to complete
        while resolver.get_resolved_ip(&ip_addr).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        let domain = resolver.get_resolved_ip(&ip_addr).await.unwrap();
        assert_eq!(domain, "dns.google");
    }

    #[tokio::test]
    async fn test_concurrent_ip_additions() {
        let resolver = Arc::new(LANScanResolver::new());
        resolver.start().await;

        let ip_addr1 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)); // Google DNS
        let ip_addr2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)); // Cloudflare DNS

        // Add IPs concurrently
        let resolver_clone = Arc::clone(&resolver);
        let handle1 = async_spawn(async move {
            resolver_clone.add_ip_to_resolver(&ip_addr1).await;
        });
        let resolver_clone = Arc::clone(&resolver);
        let handle2 = async_spawn(async move {
            resolver_clone.add_ip_to_resolver(&ip_addr2).await;
        });

        let _ = tokio::join!(handle1, handle2);

        // Wait for both to resolve
        while resolver.get_resolved_ip(&ip_addr1).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        while resolver.get_resolved_ip(&ip_addr2).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }

        let domain1 = resolver.get_resolved_ip(&ip_addr1).await.unwrap();
        let domain2 = resolver.get_resolved_ip(&ip_addr2).await.unwrap();

        assert_eq!(domain1, "dns.google");
        assert_eq!(domain2, "one.one.one.one");
    }

    #[tokio::test]
    async fn test_stop_resolver() {
        let resolver = Arc::new(LANScanResolver::new());
        resolver.start().await;

        // Ensure the resolver is running
        assert!(resolver.resolver_handle.read().await.is_some());

        // Stop the resolver
        resolver.stop().await;

        // Ensure the resolver handle is None after stopping
        assert!(resolver.resolver_handle.read().await.is_none());
    }

    #[tokio::test]
    async fn test_forward_dns_priority_over_reverse() {
        let resolver = Arc::new(LANScanResolver::new());
        resolver.start().await;

        // Use a well-known IP address for testing
        let ip_addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        // First, let's do reverse DNS resolution
        resolver.add_ip_to_resolver(&ip_addr).await;

        // Wait for the resolver to complete
        while resolver.get_resolved_ip(&ip_addr).await.is_none() {
            sleep(Duration::from_millis(100)).await;
        }

        // Verify we got a reverse DNS result (should be something like dns.google)
        let reverse_domain = resolver.get_resolved_ip(&ip_addr).await.unwrap();
        assert!(reverse_domain.contains("dns"));

        // Now simulate a forward DNS resolution from captured DNS packets
        let dns_resolutions = DashMap::new();
        let forward_domain = "forward-dns-resolution.example.com";
        dns_resolutions.insert(ip_addr, forward_domain.to_string());

        // Add the forward DNS resolution
        let added = resolver.add_dns_resolutions(&dns_resolutions);
        assert_eq!(added, 1);

        // The forward resolution should override the reverse resolution
        let final_domain = resolver.get_resolved_ip(&ip_addr).await.unwrap();
        assert_eq!(final_domain, forward_domain);
    }
}
