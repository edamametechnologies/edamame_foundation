use crate::asn_db::{Db, Record};
use crate::lanscan_asn_v4_db::*;
use crate::lanscan_asn_v6_db::*;
use crate::rwlock::CustomRwLock;
use lazy_static::lazy_static;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::warn;

// TODO load from the cloud regularly and store locally
// const ASN_V4_DB_URL: &str = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";
// const ASN_V6_DB_URL: &str = "https://iptoasn.com/data/ip2asn-v6.tsv.gz";

lazy_static! {
    static ref ASN_V4: Arc<CustomRwLock<Db>> = {
        let asn_v4 = Db::from_tsv(BufReader::new(ASN_V4_DB.as_bytes())).unwrap();
        Arc::new(CustomRwLock::new(asn_v4))
    };
    static ref ASN_V6: Arc<CustomRwLock<Db>> = {
        let asn_v6 = Db::from_tsv(BufReader::new(ASN_V6_DB.as_bytes())).unwrap();
        Arc::new(CustomRwLock::new(asn_v6))
    };
}

pub async fn get_ipv4_asn(ipv4: &Ipv4Addr) -> Option<Record> {
    let asn_v4 = ASN_V4.read().await;
    match asn_v4.lookup(IpAddr::V4(*ipv4)) {
        Some(record) => Some(record),
        None => {
            warn!("Failed to lookup IPv4 address: {}", ipv4);
            None
        }
    }
}

pub async fn get_ipv6_asn(ipv6: &Ipv6Addr) -> Option<Record> {
    let asn_v6 = ASN_V6.read().await;
    match asn_v6.lookup(IpAddr::V6(*ipv6)) {
        Some(record) => Some(record),
        None => {
            warn!("Failed to lookup IPv6 address: {}", ipv6);
            None
        }
    }
}

pub async fn get_asn(ip: IpAddr) -> Option<Record> {
    match ip {
        IpAddr::V4(ipv4) => get_ipv4_asn(&ipv4).await,
        IpAddr::V6(ipv6) => get_ipv6_asn(&ipv6).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_ipv4_asn() {
        // Use a known good IPv4 address (non local): 217.147.96.0	217.147.111.255	174	US	COGENT-174
        let ipv4 = Ipv4Addr::new(217, 147, 96, 0);
        let asn = get_ipv4_asn(&ipv4).await;
        assert!(asn.is_some());
        let asn = asn.unwrap();
        assert_eq!(asn.as_number, 174);
        assert_eq!(asn.country, "US");
        assert_eq!(asn.owner, "COGENT-174");
    }

    #[tokio::test]
    async fn test_get_ipv6_asn() {
        // Use a known good IPv6 address (non local): 2001:200::	2001:200:5ff:ffff:ffff:ffff:ffff:ffff	2500	JP	WIDE-BB WIDE Project
        let ipv6 = Ipv6Addr::new(0x2001, 0x200, 0, 0, 0, 0, 0, 1);
        let asn = get_ipv6_asn(&ipv6).await;
        assert!(asn.is_some());
        let asn = asn.unwrap();
        assert_eq!(asn.as_number, 2500);
        assert_eq!(asn.country, "JP");
        assert_eq!(asn.owner, "WIDE-BB WIDE Project");
    }
}
