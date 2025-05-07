use crate::asn_db::{Db, Record};
use crate::customlock::*;
use crate::lanscan::asn_v4_db::*;
use crate::lanscan::asn_v6_db::*;
use lazy_static::lazy_static;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::warn;

// TODO load from the cloud regularly and store locally
// const ASN_V4_DB_URL: &str = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";
// const ASN_V6_DB_URL: &str = "https://iptoasn.com/data/ip2asn-v6.tsv.gz";

lazy_static! {
    static ref ASN_V4: Arc<Db> = {
        let asn_v4 = Db::from_tsv(BufReader::new(ASN_V4_DB.as_bytes())).unwrap();
        Arc::new(asn_v4)
    };
    static ref ASN_V6: Arc<Db> = {
        let asn_v6 = Db::from_tsv(BufReader::new(ASN_V6_DB.as_bytes())).unwrap();
        Arc::new(asn_v6)
    };

    // Global cache for IP ASN lookups.
    // The key is the IpAddr and the value is the (possibly missing) Record.
    static ref ASN_CACHE: CustomDashMap<IpAddr, Option<Record>> = CustomDashMap::new("ASN Cache");
}

// Private helper that performs the direct database lookup (without caching).
async fn lookup_asn_no_cache(ip: IpAddr) -> Option<Record> {
    match ip {
        IpAddr::V4(ipv4) => match ASN_V4.lookup(IpAddr::V4(ipv4)) {
            Some(record) => Some(record),
            None => {
                warn!("Failed to lookup IPv4 address: {}", ipv4);
                None
            }
        },
        IpAddr::V6(ipv6) => match ASN_V6.lookup(IpAddr::V6(ipv6)) {
            Some(record) => Some(record),
            None => {
                warn!("Failed to lookup IPv6 address: {}", ipv6);
                None
            }
        },
    }
}

/// Cached lookup for an IP address ASN record.
///
/// This function first checks the global cache, and if the IP hasn't been seen before,
/// it performs a lookup against the underlying database and stores the result in the cache.
#[inline(always)]
pub async fn get_asn(ip: IpAddr) -> Option<Record> {
    if let Some(entry) = ASN_CACHE.get(&ip) {
        return entry.value().clone();
    }
    let result = lookup_asn_no_cache(ip).await;
    ASN_CACHE.insert(ip, result.clone());
    result
}

/// IPv4 lookup using the cached `get_asn` implementation.
pub async fn get_ipv4_asn(ipv4: &Ipv4Addr) -> Option<Record> {
    get_asn(IpAddr::V4(*ipv4)).await
}

/// IPv6 lookup using the cached `get_asn` implementation.
pub async fn get_ipv6_asn(ipv6: &Ipv6Addr) -> Option<Record> {
    get_asn(IpAddr::V6(*ipv6)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    #[serial]
    async fn test_get_ipv4_asn() {
        // Use a known good IPv4 address (non local):
        // 217.147.96.0	217.147.111.255	174	US	COGENT-174
        ASN_CACHE.clear();

        let ipv4 = Ipv4Addr::new(217, 147, 96, 0);
        let asn = get_ipv4_asn(&ipv4).await;
        assert!(asn.is_some());
        let asn = asn.unwrap();
        assert_eq!(asn.as_number, 174);
        assert_eq!(asn.country, "US");
        assert_eq!(asn.owner, "COGENT-174");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_ipv6_asn() {
        // Use a known good IPv6 address (non local):
        // 2001:200::
        // 2001:200:5ff:ffff:ffff:ffff:ffff:ffff	2500	JP	WIDE-BB WIDE Project
        ASN_CACHE.clear();

        let ipv6 = Ipv6Addr::new(0x2001, 0x200, 0, 0, 0, 0, 0, 1);
        let asn = get_ipv6_asn(&ipv6).await;
        assert!(asn.is_some());
        let asn = asn.unwrap();
        assert_eq!(asn.as_number, 2500);
        assert_eq!(asn.country, "JP");
        assert_eq!(asn.owner, "WIDE-BB WIDE Project");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_asn_caching_ipv4() {
        // Clear the cache to isolate this test.
        ASN_CACHE.clear();

        let ip = IpAddr::V4(Ipv4Addr::new(217, 147, 96, 0)); // known valid IPv4
                                                             // First lookup should populate the cache.
        let record_first = get_asn(ip).await;
        assert!(record_first.is_some());
        assert!(
            ASN_CACHE.contains_key(&ip),
            "Cache should contain the key after lookup"
        );

        // Second lookup should fetch the value from the cache.
        let record_second = get_asn(ip).await;
        assert_eq!(
            record_first, record_second,
            "Repeated lookup should return the same result"
        );

        // Cache should only have one entry.
        assert_eq!(ASN_CACHE.len(), 1, "Cache should only contain one entry");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_asn_caching_ipv6() {
        // Clear the cache to isolate this test.
        ASN_CACHE.clear();

        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x200, 0, 0, 0, 0, 0, 1)); // known valid IPv6
        let record_first = get_asn(ip).await;
        assert!(record_first.is_some());
        assert!(ASN_CACHE.contains_key(&ip));

        let record_second = get_asn(ip).await;
        assert_eq!(record_first, record_second);
        assert_eq!(ASN_CACHE.len(), 1, "Cache should only contain one entry");
    }

    #[tokio::test]
    #[serial]
    async fn test_get_asn_not_found() {
        // Clear the cache to isolate this test.
        ASN_CACHE.clear();

        // Choose an IPv4 address that's unlikely to be in the DB.
        let ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let result_first = get_asn(ip).await;
        // Expect None since the lookup should fail.
        assert!(result_first.is_none());
        // The failed lookup should still be cached.
        assert!(ASN_CACHE.contains_key(&ip));

        let result_second = get_asn(ip).await;
        assert!(result_second.is_none());
        // Ensure the cache only contains a single entry for this key.
        assert_eq!(ASN_CACHE.len(), 1, "Cache should only contain one entry");
    }

    #[tokio::test]
    #[serial]
    async fn test_concurrent_lookups() {
        // Clear the cache to isolate this test.
        ASN_CACHE.clear();

        let ip = IpAddr::V4(Ipv4Addr::new(217, 147, 96, 0));
        // Spawn several concurrent tasks performing the lookup.
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let ip = ip.clone();
                tokio::spawn(async move { get_asn(ip).await })
            })
            .collect();

        // Await all the tasks.
        let results = futures::future::join_all(tasks).await;
        for task_result in results {
            let lookup_result = task_result.unwrap();
            assert!(lookup_result.is_some());
            let record = lookup_result.unwrap();
            assert_eq!(record.as_number, 174);
        }

        // The cache should contain only one entry for this IP.
        assert_eq!(
            ASN_CACHE.len(),
            1,
            "Cache should only contain one entry for the IP"
        );
    }
}
