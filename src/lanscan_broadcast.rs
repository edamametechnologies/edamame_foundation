use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr};

// We define separate modules for Windows vs. other platforms.
#[cfg(target_os = "windows")]
mod platform_impl {
    use super::*;
    use rand::random;
    use std::mem::size_of;
    use std::net::SocketAddrV4;
    use std::ptr::null_mut;
    use std::time::Duration;
    use tokio::time;
    use tracing::{info, trace};

    // Pull in Windows-specific crates (winapi).
    use winapi::shared::minwindef::{DWORD, LPVOID};
    use winapi::shared::ws2def::AF_INET;
    use winapi::um::icmpapi::{IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho};
    use winapi::um::winsock2::{in_addr, sockaddr_in};

    // On Windows, we’ll rely on the IP Helper API, using IcmpSendEcho to send/receive ICMP:
    //   https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho
    //
    // Note: Windows typically blocks broadcast pings; you need admin privileges, and even then,
    // some system policies might disallow sending broadcast pings.
    // If your environment blocks them, you may get no replies even from reachable hosts.

    pub async fn scan_hosts_broadcast(
        broadcast_addr: Ipv4Addr,
        timeout_msecs: u64,
        echo_requests: u16,
    ) -> Result<Vec<IpAddr>> {
        info!(
            "Broadcast ping (Windows) to {} with timeout {} ms, attempts {}",
            broadcast_addr, timeout_msecs, echo_requests
        );

        // Create an ICMP handle. On success, it's a pointer; on failure, INVALID_HANDLE_VALUE.
        let icmp_handle = unsafe { IcmpCreateFile() };
        if icmp_handle.is_null() {
            return Err(anyhow!("Failed to create ICMP handle (IcmpCreateFile)."));
        }

        // We'll attempt to gather responsive IPs in a vector.
        let mut responsive_ips = Vec::new();

        // Prepare the address structure
        let mut dest_in_addr = in_addr {
            S_un: Default::default(),
        };
        dest_in_addr.S_un.S_addr = u32::from_le_bytes(broadcast_addr.octets());
        let dest_sockaddr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: dest_in_addr,
            sin_zero: [0; 8],
        };

        // We'll attempt multiple requests
        let mut interval = time::interval(Duration::from_secs(1));
        // We'll create a large enough buffer for the reply data (for each request).
        let reply_size = 1024u32;
        let mut reply_buffer = vec![0u8; reply_size as usize];

        // We’ll use a dummy payload
        let payload_len = 56;
        let mut data_buffer = vec![0u8; payload_len];

        // Assign a random identifier in the payload (just to differentiate).
        // Not strictly necessary, since IcmpSendEcho handles ID/sequence internally,
        // but we’ll show how you might do it if needed.
        let random_id: u16 = random();
        data_buffer[0] = (random_id >> 8) as u8;
        data_buffer[1] = (random_id & 0xFF) as u8;

        for seq_idx in 0..echo_requests {
            trace!(
                "Sending broadcast request #{} to {}",
                seq_idx,
                broadcast_addr
            );
            // Perform the synchronous call in a blocking manner. For real concurrency,
            // you might spin up a tokio task or a blocking thread, but here we keep it simple.
            //
            // IcmpSendEcho params:
            //   HANDLE IcmpHandle,
            //   IPAddr DestinationAddress,
            //   LPVOID RequestData,
            //   WORD RequestSize,
            //   PIP_OPTION_INFORMATION RequestOptions,
            //   LPVOID ReplyBuffer,
            //   DWORD ReplySize,
            //   DWORD Timeout
            //
            // We pass the sockaddr, data buffer, and reply buffer.
            // Timeout is in milliseconds.
            let num_replies = unsafe {
                IcmpSendEcho(
                    icmp_handle,
                    u32::from_le_bytes(broadcast_addr.octets()),
                    data_buffer.as_ptr() as LPVOID,
                    data_buffer.len() as u16,
                    null_mut(), // No IP option info
                    reply_buffer.as_mut_ptr() as LPVOID,
                    reply_size,
                    timeout_msecs as DWORD,
                )
            };

            if num_replies == 0 {
                trace!("No replies returned for broadcast request #{}", seq_idx);
            } else {
                // The reply data will be in reply_buffer. The structure layout is:
                //   struct ICMP_ECHO_REPLY {
                //       IPAddr  Address;
                //       ULONG   Status;
                //       ULONG   RoundTripTime;
                //       USHORT  DataSize;
                //       USHORT  Reserved;
                //       PVOID   Data;
                //       struct IP_OPTION_INFORMATION   Options;
                //   };
                // See https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/ns-icmpapi-icmp_echo_reply
                //
                // We'll read out up to 'num_replies' replies,
                // though typically we expect just 1.
                // Each reply is size_of(ICMP_ECHO_REPLY) + data.
                // size_of(ICMP_ECHO_REPLY) is commonly 36 bytes on 64-bit, but let's be cautious.
                let reply_struct_size = 36usize; // On 64-bit, this can vary.
                                                 // However, for simple usage, we can treat the data we need carefully.

                for i in 0..(num_replies as usize) {
                    let base_offset = i * reply_struct_size;
                    if base_offset + reply_struct_size > reply_buffer.len() {
                        break;
                    }
                    // Address field is the first 4 bytes (IPAddr) in ICMP_ECHO_REPLY.
                    let addr_bytes = &reply_buffer[base_offset..base_offset + 4];
                    let addr_u32 = u32::from_le_bytes(addr_bytes.try_into().unwrap());
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
        unsafe { IcmpCloseHandle(icmp_handle) };

        if responsive_ips.is_empty() {
            return Err(anyhow!("No hosts responded to broadcast ping on Windows"));
        }

        Ok(responsive_ips)
    }
}

#[cfg(not(target_os = "windows"))]
mod platform_impl {
    use super::*;
    use anyhow::anyhow;
    use rand::random;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::mem::MaybeUninit;
    use std::net::SocketAddrV4;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};
    use tokio::time;
    use tracing::{info, trace};
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
                        // We check if it’s an ICMP Echo Reply (type=0, code=0) with matching id/seq.
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
            return Err(anyhow!(
                "No hosts responded to broadcast ping on Unix-like system"
            ));
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
    use std::str::FromStr;

    #[tokio::test]
    async fn test_broadcast() {
        // On Windows, a broadcast ping can be blocked or require special privileges.
        // On Unix-like systems, raw sockets require root or CAP_NET_RAW.

        // Skip the test if admin_status is false
        if !get_admin_status() {
            println!("Skipping test due to admin status");
            return;
        }

        // Adjust the address to match your local LAN broadcast or a test address.
        let broadcast = Ipv4Addr::new(192, 168, 1, 255);
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
