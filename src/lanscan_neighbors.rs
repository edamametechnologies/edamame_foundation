use crate::lanscan_interface::get_own_ips;
use macaddr::MacAddr6;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// We'll just expose a type alias for a boxed error to keep it flexible.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Re-export the single cross-platform async function that calls the correct platform impl.
pub use platform_impl::scan_neighbors;

/// A consolidated neighbor entry: multiple IPv4 addresses, multiple IPv6 addresses for a given MAC.
pub type ConsolidatedNeighbor = (MacAddr6, Vec<Ipv4Addr>, Vec<Ipv6Addr>);

/// Helper to unify multiple (IpAddr, MacAddr6) pairs per MAC into a single
/// (Vec<Ipv4Addr>, Vec<Ipv6Addr>, MacAddr6) entry. Also filter out our own IPs.
fn unify_neighbors(neighbors: Vec<(IpAddr, MacAddr6)>) -> Vec<ConsolidatedNeighbor> {
    // Filter out our own IPs
    let own_ips = get_own_ips();
    let neighbors: Vec<(IpAddr, MacAddr6)> = neighbors
        .into_iter()
        .filter(|(ip, _)| !own_ips.contains(ip))
        .collect();

    let mut map: HashMap<MacAddr6, (HashSet<Ipv4Addr>, HashSet<Ipv6Addr>)> = HashMap::new();
    for (ip, mac) in neighbors {
        let (v4set, v6set) = map
            .entry(mac)
            .or_insert_with(|| (HashSet::new(), HashSet::new()));
        match ip {
            IpAddr::V4(v4) => {
                v4set.insert(v4);
            }
            IpAddr::V6(v6) => {
                v6set.insert(v6);
            }
        }
    }
    // Flatten our collected sets into final results:
    map.into_iter()
        .map(|(mac, (v4s, v6s))| (mac, v4s.into_iter().collect(), v6s.into_iter().collect()))
        .collect()
}

#[cfg(target_os = "windows")]
mod platform_impl {
    use super::*;
    use std::ffi::OsStr;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use tokio::task;
    use winapi::shared::{
        netioapi::{
            ConvertInterfaceAliasToLuid, FreeMibTable, GetIpNetTable2, MIB_IPNET_ROW2,
            PMIB_IPNET_TABLE2,
        },
        ws2def::{AF_INET, AF_INET6},
    };

    /// Parse Windows MIB_IPNET_ROW2 into an IP + MAC (+ LUID) tuple (if valid).
    fn parse_address(row: &MIB_IPNET_ROW2) -> Option<(IpAddr, MacAddr6, u64)> {
        if row.PhysicalAddressLength != 6 {
            return None;
        }
        let mac = MacAddr6::new(
            row.PhysicalAddress[0],
            row.PhysicalAddress[1],
            row.PhysicalAddress[2],
            row.PhysicalAddress[3],
            row.PhysicalAddress[4],
            row.PhysicalAddress[5],
        );

        let family = unsafe { *row.Address.si_family() as i32 };
        let ip = match family {
            AF_INET => {
                let bytes = unsafe { row.Address.Ipv4().sin_addr.S_un.S_un_b() };
                IpAddr::V4(Ipv4Addr::new(
                    bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
                ))
            }
            AF_INET6 => {
                let bytes = unsafe { row.Address.Ipv6().sin6_addr.u.Byte() };
                IpAddr::V6(Ipv6Addr::from(*bytes))
            }
            _ => return None,
        };

        let luid_val = unsafe { row.InterfaceLuid.Value };
        Some((ip, mac, luid_val))
    }

    /// Collect neighbor table using Win32 IP helper APIs, optionally filtering by interface alias.
    ///
    /// This is wrapped in a blocking task, because the Windows IP helper calls are synchronous.
    pub async fn scan_neighbors(
        interface_name: Option<&str>,
    ) -> Result<Vec<super::ConsolidatedNeighbor>> {
        let raw_neighbors = task::spawn_blocking(move || {
            let mut pairs = vec![];

            unsafe {
                let mut filter_luid = None;
                if let Some(iface_alias) = interface {
                    let wide: Vec<u16> = OsStr::new(iface_alias)
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect();

                    let mut luid: u64 = 0;
                    let ret = ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid);
                    if ret != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("ConvertInterfaceAliasToLuid failed with code {ret}"),
                        )
                        .into());
                    }
                    filter_luid = Some(luid);
                }

                let mut table_ptr: PMIB_IPNET_TABLE2 = null_mut();
                let res = GetIpNetTable2(0, &mut table_ptr);
                if res != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("GetIpNetTable2 failed with code {res}"),
                    )
                    .into());
                }
                if table_ptr.is_null() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "GetIpNetTable2 returned a null pointer",
                    )
                    .into());
                }

                let table_entries = (*table_ptr).Table.as_ptr();
                for i in 0..(*table_ptr).NumEntries as isize {
                    let row = *table_entries.offset(i);
                    if let Some((ip, mac, luid_val)) = parse_address(&row) {
                        if let Some(fluid) = filter_luid {
                            if luid_val != fluid {
                                continue;
                            }
                        }
                        pairs.push((ip, mac));
                    }
                }
                FreeMibTable(table_ptr as *mut _);
            }

            Ok(pairs)
        })
        .await??;

        // Consolidate multiple IPs per MAC:
        Ok(super::unify_neighbors(raw_neighbors))
    }
}

#[cfg(target_os = "linux")]
mod platform_impl {
    use super::*;
    use tokio::process::Command;

    /// Parse a single line of `ip neigh` (Linux).
    fn parse(line: &str) -> Option<(IpAddr, MacAddr6)> {
        // Example line: "192.168.1.5 dev eth0 lladdr 00:11:22:33:44:55 STALE"
        let mut parts = line.split_whitespace();
        let ip = parts.next()?.parse().ok()?;
        // Skip 'dev', device name, 'lladdr'
        let mac = parts.skip(3).next()?.parse().ok()?;
        Some((ip, mac))
    }

    /// Get neighbors from `ip neigh`, optionally filtered by interface name, in an async manner.
    /// Returns consolidated neighbors so that the same MAC can have multiple IPs.
    pub async fn scan_neighbors(
        interface_name: Option<&str>,
    ) -> Result<Vec<super::ConsolidatedNeighbor>> {
        let mut cmd = Command::new("ip");
        cmd.arg("neigh");

        if let Some(iface_name) = interface_name {
            cmd.arg("show").arg("dev").arg(iface_name);
        }

        let output = cmd.output().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to execute 'ip neigh': {e}"),
            )
        })?;

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let raw_neighbors = stdout_str.lines().filter_map(parse).collect();

        Ok(super::unify_neighbors(raw_neighbors))
    }
}

#[cfg(target_os = "macos")]
mod platform_impl {
    use super::*;
    use tokio::process::Command;

    /// Run a command with args, returning stdout as String.
    async fn run(cmd: &str, args: &[&str]) -> Result<String> {
        let mut c = Command::new(cmd);
        c.args(args);

        let output = c.output().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to execute {cmd}: {e}"),
            )
        })?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn sanitize_mac(s: &str) -> Option<MacAddr6> {
        let mut bytes_iter = s.split(':').flat_map(|x| u8::from_str_radix(x, 16).ok());
        Some(MacAddr6::from([
            bytes_iter.next()?,
            bytes_iter.next()?,
            bytes_iter.next()?,
            bytes_iter.next()?,
            bytes_iter.next()?,
            bytes_iter.next()?,
        ]))
    }

    /// Parse a line from "ndp -anr" when it looks like:
    ///   2a01:e0a:17f:a660:b7:18b5:3dd8:7fd2     a2:e0:22:d3:49:93    en0  9h48m19s  S
    fn v6_parse(row: &str, interface_name: Option<&str>) -> Option<(IpAddr, MacAddr6)> {
        let cols: Vec<&str> = row.split_whitespace().collect();
        // We need at least [IP, MAC, NetIf] columns
        if cols.len() < 3 {
            return None;
        }
        let raw_ip = cols[0]; // e.g. "2a01:e0a:17f:..."
        let raw_mac = cols[1]; // e.g. "a2:e0:22:d3:49:93" or "(incomplete)"
        let netif = cols[2]; // e.g. "en0"

        // Skip lines where MAC is "(incomplete)"
        if raw_mac == "(incomplete)" {
            return None;
        }

        // If the user specified an interface, skip lines where netif doesn't match
        if let Some(iface) = interface_name {
            if netif != iface {
                return None;
            }
        }

        // Some addresses may have a %en0 suffix (e.g. fe80::XXXX%en0), so strip that
        let ip_str = raw_ip.split('%').next().unwrap_or(raw_ip);
        let ipv6: Ipv6Addr = ip_str.parse().ok()?; // parse IP

        // Convert the MAC string to MacAddr6
        let mac = sanitize_mac(raw_mac)?;

        Some((IpAddr::V6(ipv6), mac))
    }

    /// Parse lines from "arp -an" (IPv4).
    /// Each line yields (IpAddr::V4(...), MacAddr6) if valid.
    fn v4_parse(row: &str) -> Option<(IpAddr, MacAddr6)> {
        // e.g. "? (192.168.1.5) at 00:11:22:33:44:55 on en0 ...
        let mut parts = row.split_whitespace().skip(1); // skip "?"
        let ip_str = parts.next()?; // "(192.168.1.5)"
        let ip_str = ip_str.trim_start_matches('(').trim_end_matches(')');
        let ip_addr = IpAddr::V4(ip_str.parse().ok()?);

        let at_word = parts.next()?; // "at"
        if at_word != "at" {
            return None;
        }
        let mac_str = parts.next()?; // e.g. "00:11:22:33:44:55"
        let mac = sanitize_mac(mac_str)?;
        Some((ip_addr, mac))
    }

    /// Get neighbors on macOS, optionally filtered by interface, consolidating multiple
    /// addresses per MAC in a single Vec<(Vec<Ipv4Addr>, Vec<Ipv6Addr>, MacAddr6)>.
    pub async fn scan_neighbors(
        interface_name: Option<&str>,
    ) -> Result<Vec<super::ConsolidatedNeighbor>> {
        // Gather raw IPv6 neighbors:
        let ndp_lines = run("ndp", &["-anr"]).await?;
        let ndp_lines: Vec<_> = ndp_lines.lines().skip(1).collect(); // skip heading

        let mut raw_neighbors = vec![];
        for line in ndp_lines {
            if let Some(x) = v6_parse(line, interface_name) {
                // x is (IpAddr::V6(...), MacAddr6)
                raw_neighbors.push(x);
            }
        }

        // Gather raw IPv4 neighbors:
        let mut arp_args = vec!["-an"];
        if let Some(iface) = interface_name {
            arp_args.push("-i");
            arp_args.push(iface);
        }
        let arp_lines = run("arp", &arp_args).await?;
        for line in arp_lines.lines() {
            if let Some(x) = v4_parse(line) {
                // x is (IpAddr::V4(...), MacAddr6)
                raw_neighbors.push(x);
            }
        }

        // Filter out link-local, broadcast, or multicast addresses, etc. if needed:
        let raw_neighbors: Vec<(IpAddr, MacAddr6)> = raw_neighbors
            .into_iter()
            .filter(|(ip, _)| match ip {
                IpAddr::V4(v4) => {
                    !(v4.is_link_local()
                        // is_broadcast() is true for 255.255.255.255
                        // || v4.is_broadcast()
                        || v4.octets()[3] == 255 // Check if last octet is 255
                        || v4.is_multicast()
                        || v4.is_unspecified()
                        || v4.is_loopback())
                }
                IpAddr::V6(v6) => !(v6.is_multicast() || v6.is_unspecified() || v6.is_loopback()),
            })
            .collect();

        // Consolidate by MAC
        Ok(super::unify_neighbors(raw_neighbors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::get_admin_status;
    use crate::lanscan_interface::get_default_interface;

    // Converted test to async. Requires you to run with a test runtime (e.g. cargo test -- --test-threads=1 under tokio).
    #[tokio::test]
    async fn test_neighbors_default_interface() {
        // Many systems may require admin rights (or elevated privileges) to read neighbor tables.
        if !get_admin_status() {
            println!("Skipping neighbor test because admin privileges are not detected.");
            return;
        }

        // Attempt to fetch a default interface (non-loopback, with IP).
        let Some(interface) = get_default_interface() else {
            println!("No suitable default interface found for neighbor test.");
            return;
        };

        println!(
            "Detected default interface for neighbor test: {}",
            interface.name
        );

        // Attempt to get neighbors for that interface (async).
        match scan_neighbors(Some(&interface.name)).await {
            Ok(neighbors) => {
                println!(
                    "Found {} neighbor groupings on '{}':",
                    neighbors.len(),
                    interface.name
                );
                for (mac, v4_addrs, v6_addrs) in neighbors {
                    println!(" -> MAC {mac}, v4 = {v4_addrs:?}, v6 = {v6_addrs:?}");
                }
            }
            Err(e) => {
                println!(
                    "Failed to retrieve neighbors on '{}': {}",
                    interface.name, e
                );
            }
        }
    }
}
