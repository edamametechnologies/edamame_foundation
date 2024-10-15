use crate::runtime::async_spawn;
use crate::rwlock::CustomRwLock;
use dashmap::DashMap;
use hickory_resolver::{name_server::TokioConnectionProvider, TokioAsyncResolver};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, trace, warn};

#[derive(Debug, Clone)]
pub struct LANScanResolver {
    resolver: Arc<CustomRwLock<Option<TokioAsyncResolver>>>,
    reverse_dns: Arc<DashMap<IpAddr, String>>,
    resolver_queue: Arc<CustomRwLock<VecDeque<IpAddr>>>,
    // We wrap the resolver handle in a CustomRwLock to allow for cloning
    resolver_handle: Arc<CustomRwLock<Option<JoinHandle<()>>>>,
    resolver_stop_flag: Arc<AtomicBool>,
}

impl LANScanResolver {
    pub fn new() -> Self {
        Self {
            resolver: Arc::new(CustomRwLock::new(None)),
            reverse_dns: Arc::new(DashMap::new()),
            resolver_queue: Arc::new(CustomRwLock::new(VecDeque::new())),
            resolver_handle: Arc::new(CustomRwLock::new(None)),
            resolver_stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    fn create_resolver() -> Option<TokioAsyncResolver> {
        // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
        #[cfg(any(unix, windows))]
        {
            // Use the system resolver configuration
            match TokioAsyncResolver::from_system_conf(TokioConnectionProvider::default()) {
                Ok(resolver) => Some(resolver),
                Err(err) => {
                    error!(
                        "Failed to create resolver from system configuration: {:?}",
                        err
                    );
                    return None;
                }
            }
        }

        // For other operating systems, we can use one of the preconfigured definitions
        #[cfg(not(any(unix, windows)))]
        {
            // Directly reference the config types
            use hickory_resolver::config::{ResolverConfig, ResolverOpts};

            // Get a new resolver with the google nameservers as the upstream recursive resolvers
            match TokioAsyncResolver::new(
                ResolverConfig::google(),
                ResolverOpts::default(),
                runtime.handle().clone(),
            ) {
                Ok(resolver) => Some(resolver),
                Err(err) => {
                    error!("Failed to create resolver: {:?}", err);
                    return None;
                }
            }
        }
    }

    async fn perform_reverse_dns_lookup(
        ip_addr: IpAddr,
        reverse_dns: Arc<DashMap<IpAddr, String>>,
        resolver: &TokioAsyncResolver,
    ) {
        match resolver.reverse_lookup(ip_addr).await {
            Ok(lookup) => {
                let domain = lookup.into_iter().next().unwrap().to_string();
                // Remove the trailing dot from the domain
                let domain = domain.trim_end_matches('.').to_string();
                trace!("DNS resolution (using resolver): {} -> {}", ip_addr, domain);
                reverse_dns.insert(ip_addr, domain);
            }
            Err(e) => {
                trace!("Error performing reverse DNS lookup for {}: {}", ip_addr, e);
                reverse_dns.insert(ip_addr, "Unknown".to_string());
            }
        }
    }

    pub async fn start(&mut self) {
        if self.resolver_handle.read().await.is_some() {
            warn!("L7 resolver task is already running");
            return;
        }

        // Spawn resolver task
        if let Some(resolver) = Self::create_resolver() {
            let resolver_queue = self.resolver_queue.clone();
            let reverse_dns = self.reverse_dns.clone();
            let resolver_stop_flag = self.resolver_stop_flag.clone();
            let resolver_clone = resolver.clone();
            let resolver_handle = async_spawn(async move {
                info!("Starting resolver task");

                while !resolver_stop_flag.load(Ordering::Relaxed)
                    || !resolver_queue.read().await.is_empty()
                {
                    // Get the IPs to resolve from the queue
                    let to_resolve: Vec<IpAddr> = resolver_queue.write().await.drain(..).collect();
                    let to_resolve_len = to_resolve.len();
                    if to_resolve_len > 0 {
                        trace!("Resolving {} IPs", to_resolve_len);

                        // Resolve the IPs in parallel
                        let _ = futures::future::join_all(to_resolve.into_iter().map(|ip| {
                            let resolver = resolver.clone();
                            let reverse_dns = reverse_dns.clone();
                            async move {
                                Self::perform_reverse_dns_lookup(ip, reverse_dns, &resolver).await
                            }
                        }))
                        .await;

                        info!("Resolved {} IPs", to_resolve_len);
                    }

                    // Sleep for 5 seconds
                    sleep(Duration::from_secs(5)).await;
                }

                info!("Resolver task completed");
            });
            *self.resolver.write().await = Some(resolver_clone);
            *self.resolver_handle.write().await = Some(resolver_handle);
        }
    }

    pub async fn stop(&mut self) {
        if let Some(resolver_handle) = self.resolver_handle.write().await.take() {
            self.resolver_stop_flag.store(true, Ordering::Relaxed);
            let _ = resolver_handle.await;
            info!("Stopped resolver task");
        }
    }

    pub async fn add_ip_to_resolver(&self, ip_addr: &IpAddr) {
        // Check if the IP has already been resolved
        if self.reverse_dns.get(ip_addr).is_some() {
            return;
        }

        // Add the IP to the resolver queue
        self.resolver_queue.write().await.push_back(ip_addr.clone());
        debug!("Added IP to resolver queue: {}", ip_addr);
        // Mark the IP as resolving
        self.reverse_dns
            .insert(ip_addr.clone(), "Resolving".to_string());
    }

    pub async fn get_resolved_ip(&self, ip_addr: &IpAddr) -> Option<String> {
        // Check if the IP is already resolved
        match self.reverse_dns.get(ip_addr).map(|s| s.value().clone()) {
            Some(domain) => match domain.as_str() {
                "Resolving" => None,
                _ => Some(domain),
            },
            None => {
                // Just return None if we don't have it cached, the caller can add it to the resolver queue if they want
                None
            }
        }
    }
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_reverse_dns_lookup_success() {
        let mut resolver = LANScanResolver::new();
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
        let mut resolver = LANScanResolver::new();
        resolver.start().await;

        // Use a non-existent IP address for testing
        let ip_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)); // Usually not resolved
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
        let mut resolver = LANScanResolver::new();
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
        let mut resolver = LANScanResolver::new();
        resolver.start().await;

        let ip_addr1 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)); // Google DNS
        let ip_addr2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)); // Cloudflare DNS

        // Add IPs concurrently
        let resolver_clone = resolver.clone();
        let handle1 = tokio::spawn(async move {
            resolver_clone.add_ip_to_resolver(&ip_addr1).await;
        });
        let resolver_clone = resolver.clone();
        let handle2 = tokio::spawn(async move {
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
        let mut resolver = LANScanResolver::new();
        resolver.start().await;

        // Ensure the resolver is running
        assert!(resolver.resolver_handle.read().await.is_some());

        // Stop the resolver
        resolver.stop().await;

        // Ensure the resolver handle is None after stopping
        assert!(resolver.resolver_handle.read().await.is_none());
    }
}
