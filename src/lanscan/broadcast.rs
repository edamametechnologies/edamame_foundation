use anyhow::Result;
use std::net::IpAddr;

// We define separate modules for Windows vs. other platforms.
#[cfg(target_os = "windows")]
mod platform_impl {
    use super::*;
    use anyhow::anyhow;
    use rand::random;
    use std::time::Duration;
    use tokio::time;
    use tracing::{info, trace, warn};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    /// Thin wrapper around a Windows kernel handle, implementing Send + Sync.
    /// Safety note: Windows kernel handles are typically valid to share across threads
    /// as long as the underlying resource is used correctly. Declaring this as "Send" and
    /// "Sync" is safe so long as the usage code doesn't cause race hazards.
    #[derive(Clone, Copy)]
    struct IcmpHandle(HANDLE);

    unsafe impl Send for IcmpHandle {}
    unsafe impl Sync for IcmpHandle {}

    pub async fn scan_hosts_broadcast(
        broadcast_addr: std::net::Ipv4Addr,
        timeout_msecs: u64,
        echo_requests: u16,
    ) -> Result<Vec<IpAddr>> {
        info!(
            "Broadcast ping (Windows) to {} with timeout {} ms, attempts {}",
            broadcast_addr, timeout_msecs, echo_requests
        );

        // Create an ICMP handle. On success, it's a valid handle; on failure, INVALID_HANDLE_VALUE.
        // Wrap it immediately, so we only hold the IcmpHandle across .await calls (not the raw HANDLE).
        let icmp_handle = match unsafe { IcmpCreateFile() } {
            Ok(handle) => IcmpHandle(handle),
            Err(e) => {
                return Err(anyhow!(
                    "Failed to create ICMP handle (IcmpCreateFile): {}",
                    e
                ))
            }
        };

        // We'll attempt to gather responsive IPs in a vector.
        let mut responsive_ips = Vec::new();

        // We'll attempt multiple requests.
        let mut interval = time::interval(Duration::from_secs(1));

        // We'll create a large enough buffer for the reply data for each request.
        let reply_size = 1024u32;
        let mut reply_buffer = vec![0u8; reply_size as usize];

        // Build a small dummy payload (56 bytes) with a random ID at the start.
        let payload_len = 56;
        let mut data_buffer = vec![0u8; payload_len];
        let random_id: u16 = random();
        data_buffer[0] = (random_id >> 8) as u8;
        data_buffer[1] = (random_id & 0xFF) as u8;

        for seq_idx in 0..echo_requests {
            trace!(
                "Sending broadcast request #{} to {}",
                seq_idx,
                broadcast_addr
            );

            // Convert broadcast_addr octets into a little-endian u32 for IcmpSendEcho.
            let dest_ip = u32::from_le_bytes(broadcast_addr.octets());

            // Perform the ICMP echo call (blocking from the OS perspective, but we're in an async function).
            let num_replies = unsafe {
                IcmpSendEcho(
                    icmp_handle.0,
                    dest_ip,
                    data_buffer.as_ptr().cast(),
                    data_buffer.len() as u16,
                    None,
                    reply_buffer.as_mut_ptr().cast(),
                    reply_size,
                    timeout_msecs as u32,
                )
            };

            if num_replies == 0 {
                trace!("No replies returned for broadcast request #{}", seq_idx);
            } else {
                // Interpret the replies as an array of ICMP_ECHO_REPLY.
                let reply_structs = unsafe {
                    std::slice::from_raw_parts(
                        reply_buffer.as_ptr().cast::<ICMP_ECHO_REPLY>(),
                        num_replies as usize,
                    )
                };
                for (i, reply) in reply_structs.iter().enumerate() {
                    let addr_u32 = reply.Address;
                    let ip = IpAddr::from(addr_u32.to_le_bytes());
                    trace!("Reply #{} from {}", i, ip);
                    if !responsive_ips.contains(&ip) {
                        responsive_ips.push(ip);
                    }
                }
            }

            interval.tick().await;
        }

        // Cleanup
        unsafe {
            let _ = IcmpCloseHandle(icmp_handle.0);
        }

        if responsive_ips.is_empty() {
            warn!("No hosts responded to broadcast ping on Windows");
        }

        Ok(responsive_ips)
    }
}

#[cfg(not(target_os = "windows"))]
mod platform_impl {
    use super::*;
    use rand::random;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::mem::MaybeUninit;
    use std::net::Ipv4Addr;
    use std::net::SocketAddrV4;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};
    use tokio::time;
    use tracing::{info, trace, warn};

    /// Compute the classic RFC 1071 checksum for an ICMP packet.
    fn icmp_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i < data.len() - 1 {
            let word = u32::from_be_bytes([0, 0, data[i], data[i + 1]]);
            sum = sum.wrapping_add(word);
            i += 2;
        }
        if data.len() % 2 == 1 {
            sum = sum.wrapping_add(u32::from_be_bytes([0, 0, data[data.len() - 1], 0]));
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF).wrapping_add(sum >> 16);
        }
        !(sum as u16)
    }

    /// Build an ICMP Echo Request packet.
    fn build_icmp_echo_request(id: u16, seq: u16, payload_len: usize) -> Vec<u8> {
        // ICMP header (8 bytes) + payload
        //  Byte 0: Type (8 for echo request)
        //  Byte 1: Code (0)
        //  Byte 2..3: Checksum
        //  Byte 4..5: Identifier (BE)
        //  Byte 6..7: Sequence (BE)
        let mut packet = vec![0u8; 8 + payload_len];

        // Type=8, Code=0
        packet[0] = 8;
        packet[1] = 0;

        // Identifier
        packet[4] = (id >> 8) as u8;
        packet[5] = (id & 0xFF) as u8;

        // Sequence
        packet[6] = (seq >> 8) as u8;
        packet[7] = (seq & 0xFF) as u8;

        // Payload can be zeros or random
        // We leave it at zeros.

        // Compute checksum
        let chksum = icmp_checksum(&packet);
        packet[2] = (chksum >> 8) as u8;
        packet[3] = (chksum & 0xFF) as u8;

        packet
    }

    pub async fn scan_hosts_broadcast(
        broadcast_addr: Ipv4Addr,
        timeout_msecs: u64,
        echo_requests: u16,
    ) -> Result<Vec<IpAddr>> {
        info!(
            "Broadcasting raw ICMP (Unix-like) to {} with timeout {} ms, attempts {}",
            broadcast_addr, timeout_msecs, echo_requests
        );

        // Create a raw socket for ICMPv4.
        // Requires root / CAP_NET_RAW on Linux, or similar privileges on macOS.
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        socket.set_broadcast(true)?;

        // Bind to 0.0.0.0
        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        socket.bind(&bind_addr.into())?;
        socket.set_nonblocking(true)?;

        let raw_fd = socket.as_raw_fd();
        trace!("Raw socket fd: {}", raw_fd);

        let mut responsive_ips = Vec::new();
        let id: u16 = random();
        let payload_len = 56;

        let mut interval = time::interval(Duration::from_secs(1));

        for seq in 0..echo_requests {
            let packet = build_icmp_echo_request(id, seq, payload_len);

            // Send to the broadcast address
            let destination = SocketAddrV4::new(broadcast_addr, 0);
            match socket.send_to(&packet, &destination.into()) {
                Ok(bytes_sent) => {
                    trace!(
                        "Sent {} bytes (seq={}) to broadcast {}",
                        bytes_sent,
                        seq,
                        broadcast_addr
                    );
                }
                Err(e) => {
                    trace!("Error sending broadcast echo request: {}", e);
                }
            }

            // Check for responses until timeout
            let start_time = Instant::now();
            while start_time.elapsed().as_millis() < timeout_msecs as u128 {
                let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
                match socket.recv_from(&mut buf) {
                    Ok((recv_len, addr)) => {
                        // The source IP
                        let source_ip = match addr.as_socket_ipv4() {
                            Some(a) => IpAddr::V4(*a.ip()),
                            None => continue,
                        };

                        // IP header is typically 20 bytes for IPv4, then ICMP data after that.
                        // We check if it's an ICMP Echo Reply (type=0, code=0) with matching id/seq.
                        if recv_len >= 28 {
                            let icmp_offset = 20;
                            let icmp_type = unsafe { buf[icmp_offset].assume_init() };
                            let icmp_code = unsafe { buf[icmp_offset + 1].assume_init() };
                            let reply_id = unsafe {
                                ((buf[icmp_offset + 4].assume_init() as u16) << 8)
                                    | (buf[icmp_offset + 5].assume_init() as u16)
                            };
                            let reply_seq = unsafe {
                                ((buf[icmp_offset + 6].assume_init() as u16) << 8)
                                    | (buf[icmp_offset + 7].assume_init() as u16)
                            };

                            if icmp_type == 0
                                && icmp_code == 0
                                && reply_id == id
                                && reply_seq == seq
                            {
                                trace!("Got reply from {}", source_ip);
                                if !responsive_ips.contains(&source_ip) {
                                    responsive_ips.push(source_ip);
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Typically a WouldBlock or NotReady if nothing yet
                    }
                }
            }

            interval.tick().await;
        }

        if responsive_ips.is_empty() {
            warn!("No hosts responded to broadcast ping on Unix-like system");
        }

        Ok(responsive_ips)
    }
}

// Re-export a single cross-platform function name that calls the correct impl
#[cfg(target_os = "windows")]
pub use platform_impl::scan_hosts_broadcast;

#[cfg(not(target_os = "windows"))]
pub use platform_impl::scan_hosts_broadcast;

// ------- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::get_admin_status;
    use crate::lanscan::interface::get_default_interface;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    /// Test the broadcast ping on a default non-loopback interface that has IPv4 configured.
    #[tokio::test]
    async fn test_broadcast() {
        // On Windows, a broadcast ping can be blocked or require special privileges.
        // On Unix-like systems, raw sockets require root or CAP_NET_RAW.

        // Skip the test if admin_status is false
        if !get_admin_status() {
            println!("Skipping broadcast test because admin privileges are not detected.");
            return;
        }

        // Find a non-loopback interface with IPv4
        let interface = get_default_interface();

        let Some(interface) = interface else {
            println!("No suitable interface found for broadcast test");
            return;
        };

        println!("Detected interface for broadcast test: {}", interface.name);

        // Get the IPv4 address
        let ipv4 = interface.ipv4;

        // Very rough approach: we just set the last octet = 255
        // for a likely broadcast on many typical home/office subnets
        let Some(ipv4) = ipv4 else {
            println!("No IPv4 address found for broadcast test");
            return;
        };
        let broadcast = Ipv4Addr::new(
            ipv4.ip.octets()[0],
            ipv4.ip.octets()[1],
            ipv4.ip.octets()[2],
            255,
        );

        let timeout = 1000;
        let attempts = 3;

        let result = scan_hosts_broadcast(broadcast, timeout, attempts).await;
        match result {
            Ok(ips) => {
                println!("Received responses from {} IP(s).", ips.len());
                for ip in ips {
                    println!(" -> {}", ip);
                }
            }
            Err(e) => {
                println!("No responses or error: {}", e);
            }
        }
    }

    #[test]
    fn test_broadcast_address_parsing() {
        let addr = Ipv4Addr::from_str("192.168.1.255").unwrap();
        assert_eq!(addr.octets(), [192, 168, 1, 255]);
    }
}
