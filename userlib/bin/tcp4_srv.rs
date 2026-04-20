#![no_std]
#![no_main]

// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024-2026 Nadia Chambers
// Reference codebases: Linux networking stack (TCP/IPv4 semantics)

//! IPv4 + ICMP + TCP server, running atop eth_srv via the netif IPC protocol.
//!
//! Registers with eth_srv for ethertype 0x0800 (IPv4), receives frames via
//! grant pages, and handles:
//! - ICMPv4 echo request/reply (ping)
//! - Full TCP state machine (connect, listen, accept, send, recv, close)
//!
//! Registers as "net" service for backward compatibility with existing clients
//! (init test suite, sshd, proxy_srv, etc.).

extern crate userlib;

use userlib::syscall;

// --- Netif IPC protocol (must match eth_srv) ---
const NETIF_REGISTER: u64 = 0x5000;
const NETIF_REGISTER_OK: u64 = 0x5001;
const NETIF_INPUT: u64 = 0x5100;
const NETIF_XMIT: u64 = 0x5200;
const NETIF_XMIT_OK: u64 = 0x5201;
const NETIF_RESOLVE: u64 = 0x5300;
const NETIF_RESOLVE_OK: u64 = 0x5301;
const NETIF_RESOLVE_FAIL: u64 = 0x53FF;
const NETIF_STATUS: u64 = 0x5400;
const NETIF_STATUS_OK: u64 = 0x5401;

// --- Legacy net IPC (backward compat) ---
const NET_STATUS: u64 = 0x4000;
const NET_STATUS_OK: u64 = 0x4001;
const NET_PING: u64 = 0x4100;
const NET_PING_OK: u64 = 0x4101;
const NET_PING_FAIL: u64 = 0x41FF;

const NET_TCP_CONNECT: u64 = 0x4200;
const NET_TCP_CONNECTED: u64 = 0x4201;
const NET_TCP_FAIL: u64 = 0x42FF;
const NET_TCP_SEND: u64 = 0x4300;
const NET_TCP_SEND_OK: u64 = 0x4301;
const NET_TCP_RECV: u64 = 0x4400;
const NET_TCP_DATA: u64 = 0x4401;
const NET_TCP_CLOSED: u64 = 0x44FF;
const NET_TCP_CLOSE: u64 = 0x4500;
const NET_TCP_CLOSE_OK: u64 = 0x4501;

const NET_TCP_BIND: u64 = 0x4600;
const NET_TCP_BIND_OK: u64 = 0x4601;
const NET_TCP_LISTEN: u64 = 0x4700;
const NET_TCP_LISTEN_OK: u64 = 0x4701;
const NET_TCP_LISTEN_FAIL: u64 = 0x47FF;

// DNS resolution via UDP to 10.0.2.3:53 (QEMU SLIRP DNS).
const DNS_RESOLVE: u64 = 0x4800;
const DNS_RESOLVE_OK: u64 = 0x4801;
const DNS_RESOLVE_FAIL: u64 = 0x48FF;
const DNS_SERVER_IP: [u8; 4] = [10, 0, 2, 3];
const DNS_PORT: u16 = 53;
const DNS_LOCAL_PORT: u16 = 61053;
const NET_TCP_ACCEPT: u64 = 0x4710;
const NET_TCP_ACCEPT_OK: u64 = 0x4711;
const NET_TCP_ACCEPT_FAIL: u64 = 0x47FE;

const NET_TCP_RECV_NB: u64 = 0x4410;
const NET_TCP_RECV_NONE: u64 = 0x4412;

// --- TCP flags ---
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

// --- TCP states ---
const TCP_CLOSED: u8 = 0;
const TCP_SYN_SENT: u8 = 1;
const TCP_ESTABLISHED: u8 = 2;
const TCP_FIN_WAIT_1: u8 = 3;
const TCP_FIN_WAIT_2: u8 = 4;
const TCP_TIME_WAIT: u8 = 5;
const TCP_CLOSE_WAIT: u8 = 6;
const TCP_LAST_ACK: u8 = 7;
const TCP_SYN_RECEIVED: u8 = 8;

const MAX_TCP_CONNS: usize = 8;
const MAX_LISTEN_SLOTS: usize = 4;
const TCP_RX_BUF_SIZE: usize = 2048;
const TCP_TIMEOUT: u32 = 10000;
const TCP_TIME_WAIT_TIMEOUT: u32 = 5000;
const PING_TIMEOUT: u32 = 5000;

const ETHERTYPE_IPV4: u16 = 0x0800;

// Static IP config (matches QEMU user-net defaults).
const MY_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

// ---------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------

struct ListenSlot {
    active: bool,
    port: u16,
    accept_reply_port: u64,
}

impl ListenSlot {
    const fn new() -> Self {
        Self {
            active: false,
            port: 0,
            accept_reply_port: 0,
        }
    }
}

struct TcpConn {
    state: u8,
    local_port: u16,
    remote_ip: [u8; 4],
    remote_port: u16,
    snd_nxt: u32,
    snd_una: u32,
    rcv_nxt: u32,
    reply_port: u64,
    recv_reply_port: u64,
    rx_buf: [u8; TCP_RX_BUF_SIZE],
    rx_head: usize,
    rx_tail: usize,
    timeout: u32,
}

impl TcpConn {
    const fn new() -> Self {
        Self {
            state: TCP_CLOSED,
            local_port: 0,
            remote_ip: [0; 4],
            remote_port: 0,
            snd_nxt: 0,
            snd_una: 0,
            rcv_nxt: 0,
            reply_port: 0,
            recv_reply_port: 0,
            rx_buf: [0; TCP_RX_BUF_SIZE],
            rx_head: 0,
            rx_tail: 0,
            timeout: 0,
        }
    }

    fn rx_len(&self) -> usize {
        if self.rx_head >= self.rx_tail {
            self.rx_head - self.rx_tail
        } else {
            TCP_RX_BUF_SIZE - self.rx_tail + self.rx_head
        }
    }

    fn rx_push(&mut self, data: &[u8]) {
        for &b in data {
            let next = (self.rx_head + 1) % TCP_RX_BUF_SIZE;
            if next == self.rx_tail {
                break;
            }
            self.rx_buf[self.rx_head] = b;
            self.rx_head = next;
        }
    }

    fn rx_pop(&mut self, dst: &mut [u8]) -> usize {
        let mut n = 0;
        while n < dst.len() && self.rx_tail != self.rx_head {
            dst[n] = self.rx_buf[self.rx_tail];
            self.rx_tail = (self.rx_tail + 1) % TCP_RX_BUF_SIZE;
            n += 1;
        }
        n
    }
}

// ---------------------------------------------------------------
// IPv4 device atop eth_srv
// ---------------------------------------------------------------

struct Tcp4Dev {
    eth_port: u64,
    my_port: u64,
    client_id: u64,
    mac: [u8; 6],
    rx_va: usize,
    tx_va: usize,

    // TCP connections.
    tcp: [TcpConn; MAX_TCP_CONNS],
    listen: [ListenSlot; MAX_LISTEN_SLOTS],
    next_ephemeral_port: u16,
    tcp_isn: u32,

    // Set when TCP data arrives for a connection with a pending recv.
    deliver_pending: bool,

    // Cached gateway MAC for non-blocking ARP.
    gateway_mac: [u8; 6],

    // Ping state.
    ping_active: bool,
    ping_target: [u8; 4],
    ping_reply_port: u64,
    ping_seq: u16,
    ping_polls: u32,
    ping_sent_icmp: bool,

    // DNS resolver state.
    dns_active: bool,
    dns_reply_port: u64,
    dns_txid: u16,
    dns_polls: u32,
}

impl Tcp4Dev {
    fn new(eth_port: u64, my_port: u64, client_id: u64, mac: [u8; 6], rx_va: usize, tx_va: usize) -> Self {
        Self {
            eth_port,
            my_port,
            client_id,
            mac,
            rx_va,
            tx_va,
            tcp: [const { TcpConn::new() }; MAX_TCP_CONNS],
            listen: [const { ListenSlot::new() }; MAX_LISTEN_SLOTS],
            next_ephemeral_port: 49152,
            tcp_isn: 100000,
            gateway_mac: [0; 6],
            ping_active: false,
            ping_target: [0; 4],
            ping_reply_port: 0,
            ping_seq: 0,
            ping_polls: 0,
            ping_sent_icmp: false,
            deliver_pending: false,
            dns_active: false,
            dns_reply_port: 0,
            dns_txid: 0,
            dns_polls: 0,
        }
    }

    // ---------------------------------------------------------------
    // Packet TX via NETIF_XMIT
    // ---------------------------------------------------------------

    /// Send an IPv4 packet via eth_srv. Builds IPv4 header + payload into the
    /// TX grant page, then issues NETIF_XMIT.
    fn send_ipv4(&self, dst_ip: [u8; 4], proto: u8, payload: &[u8], dst_mac: [u8; 6]) {
        let ip_total = 20 + payload.len();
        if ip_total > 1500 {
            return;
        }

        let buf = self.tx_va as *mut u8;
        unsafe {
            // IPv4 header (20 bytes).
            let hdr = buf;
            *hdr.add(0) = 0x45; // version=4, IHL=5
            *hdr.add(1) = 0x00; // DSCP/ECN
            *hdr.add(2) = (ip_total >> 8) as u8;
            *hdr.add(3) = ip_total as u8;
            // Identification.
            *hdr.add(4) = 0;
            *hdr.add(5) = 0;
            // Flags + fragment offset: DF.
            *hdr.add(6) = 0x40;
            *hdr.add(7) = 0x00;
            // TTL.
            *hdr.add(8) = 64;
            // Protocol.
            *hdr.add(9) = proto;
            // Header checksum (zero for now).
            *hdr.add(10) = 0;
            *hdr.add(11) = 0;
            // Source IP.
            core::ptr::copy_nonoverlapping(MY_IP.as_ptr(), hdr.add(12), 4);
            // Destination IP.
            core::ptr::copy_nonoverlapping(dst_ip.as_ptr(), hdr.add(16), 4);
            // Compute IP header checksum.
            let cksum = inet_checksum_raw(hdr, 20);
            *hdr.add(10) = (cksum >> 8) as u8;
            *hdr.add(11) = cksum as u8;
            // Payload.
            core::ptr::copy_nonoverlapping(payload.as_ptr(), hdr.add(20), payload.len());
        }

        // Send NETIF_XMIT to eth_srv.
        let reply_port = syscall::port_create();
        let mac_val = mac_to_u64(dst_mac);
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            ip_total as u64,
            mac_val,
            ETHERTYPE_IPV4 as u64 | (reply_port << 16),
            self.client_id,
        );
        let _ = syscall::recv_msg_timeout(reply_port, 100_000);
        syscall::port_destroy(reply_port);
    }

    /// Get the destination MAC for an IPv4 address.
    /// Uses the cached gateway MAC if available, otherwise broadcasts.
    /// In QEMU user-net (SLIRP), broadcast works for all destinations
    /// since the virtual router processes all guest frames.
    fn dst_mac_for(&self, _ip: [u8; 4]) -> [u8; 6] {
        if self.gateway_mac != [0; 6] {
            self.gateway_mac
        } else {
            [0xFF; 6] // broadcast fallback
        }
    }

    /// Try to resolve the gateway MAC via eth_srv's ARP cache.
    /// Non-critical — broadcast works as fallback.
    fn resolve_gateway(&mut self) {
        let reply_port = syscall::port_create();
        let ip_be = u32::from_be_bytes(GATEWAY_IP);
        syscall::send_nb(self.eth_port, NETIF_RESOLVE, ip_be as u64, reply_port);
        if let Some(msg) = syscall::recv_msg_timeout(reply_port, 500_000) {
            if msg.tag == NETIF_RESOLVE_OK {
                self.gateway_mac = u64_to_mac(msg.data[0]);
            }
        }
        syscall::port_destroy(reply_port);
    }

    // ---------------------------------------------------------------
    // Frame input from eth_srv
    // ---------------------------------------------------------------

    fn handle_input(&mut self, payload_len: usize, _src_mac: [u8; 6]) {
        if payload_len == 0 {
            return;
        }
        // Read the IPv4 payload from our RX grant page.
        let buf = self.rx_va as *const u8;
        let data = unsafe { core::slice::from_raw_parts(buf, payload_len.min(4096)) };
        self.handle_ipv4(data);
    }

    fn handle_ipv4(&mut self, data: &[u8]) {
        if data.len() < 20 {
            return;
        }
        let ihl = (data[0] & 0x0F) as usize * 4;
        let total_len = get_u16_be(data, 2) as usize;
        let proto = data[9];
        let end = total_len.min(data.len());
        if end <= ihl {
            return;
        }
        let src_ip = [data[12], data[13], data[14], data[15]];
        match proto {
            1 => self.handle_icmp(src_ip, &data[ihl..end]),
            6 => self.handle_tcp_rx(src_ip, &data[ihl..end]),
            17 => self.handle_udp_rx(src_ip, &data[ihl..end]),
            _ => {}
        }
    }

    // ---------------------------------------------------------------
    // ICMPv4
    // ---------------------------------------------------------------

    fn handle_icmp(&mut self, src_ip: [u8; 4], data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        match data[0] {
            0 => {
                // Echo reply.
                let seq = get_u16_be(data, 6);
                syscall::debug_puts(b"  [tcp4_srv] ICMP echo reply seq=");
                print_num(seq as u64);
                syscall::debug_puts(b"\n");
                if self.ping_active && seq == self.ping_seq {
                    syscall::send_nb(self.ping_reply_port, NET_PING_OK, 0, 0);
                    self.ping_active = false;
                }
            }
            8 => {
                // Echo request — reply.
                self.send_icmp_echo_reply(src_ip, data);
            }
            _ => {}
        }
    }

    fn send_icmp_echo_reply(&self, dst_ip: [u8; 4], request: &[u8]) {
        if request.len() < 8 {
            return;
        }
        let mut icmp = [0u8; 1480];
        let icmp_len = request.len().min(1480);
        icmp[..icmp_len].copy_from_slice(&request[..icmp_len]);
        icmp[0] = 0; // echo reply
        icmp[1] = 0;
        icmp[2] = 0; // zero checksum
        icmp[3] = 0;
        let cksum = inet_checksum(&icmp[..icmp_len]);
        icmp[2] = (cksum >> 8) as u8;
        icmp[3] = cksum as u8;

        // Use cached gateway MAC or broadcast — never blocks.
        let mac = self.dst_mac_for(dst_ip);
        self.send_ipv4(dst_ip, 1, &icmp[..icmp_len], mac);
    }

    fn send_icmp_echo_request(&self, dst_ip: [u8; 4], dst_mac: [u8; 6], seq: u16) {
        let mut icmp = [0u8; 40]; // type + code + cksum + id + seq + 32 payload
        icmp[0] = 8; // echo request
        icmp[4] = 0x12;
        icmp[5] = 0x34; // identifier
        icmp[6] = (seq >> 8) as u8;
        icmp[7] = seq as u8;
        for i in 0..32 {
            icmp[8 + i] = i as u8;
        }
        let cksum = inet_checksum(&icmp);
        icmp[2] = (cksum >> 8) as u8;
        icmp[3] = cksum as u8;
        self.send_ipv4(dst_ip, 1, &icmp, dst_mac);
    }

    // ---------------------------------------------------------------
    // DNS resolver (UDP to 10.0.2.3:53)
    // ---------------------------------------------------------------

    /// Handle incoming UDP packet — only used for DNS responses.
    fn handle_udp_rx(&mut self, _src_ip: [u8; 4], data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        let dst_port = get_u16_be(data, 2);
        if dst_port != DNS_LOCAL_PORT || !self.dns_active {
            return;
        }
        // UDP payload starts at offset 8.
        let payload = &data[8..];
        self.handle_dns_response(payload);
    }

    /// Parse DNS response and reply to caller.
    fn handle_dns_response(&mut self, data: &[u8]) {
        // DNS header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
        if data.len() < 12 {
            return;
        }
        let txid = get_u16_be(data, 0);
        if txid != self.dns_txid {
            return;
        }
        let flags = get_u16_be(data, 2);
        let rcode = flags & 0x000F;
        if rcode != 0 {
            // Non-zero RCODE = error.
            syscall::send_nb(self.dns_reply_port, DNS_RESOLVE_FAIL, 0, 0);
            self.dns_active = false;
            return;
        }
        let ancount = get_u16_be(data, 6);
        if ancount == 0 {
            syscall::send_nb(self.dns_reply_port, DNS_RESOLVE_FAIL, 0, 0);
            self.dns_active = false;
            return;
        }
        // Skip question section: find the first answer.
        let mut off = 12;
        // Skip QDCOUNT questions (each: name + QTYPE(2) + QCLASS(2)).
        let qdcount = get_u16_be(data, 4);
        for _ in 0..qdcount {
            off = self.skip_dns_name(data, off);
            off += 4; // QTYPE + QCLASS
        }
        // Parse answer records looking for A (type 1) or AAAA (type 28).
        for _ in 0..ancount {
            if off >= data.len() {
                break;
            }
            off = self.skip_dns_name(data, off);
            if off + 10 > data.len() {
                break;
            }
            let rtype = get_u16_be(data, off);
            let rdlength = get_u16_be(data, off + 8) as usize;
            off += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
            if rtype == 1 && rdlength == 4 && off + 4 <= data.len() {
                // A record: 4-byte IPv4 address.
                let ip = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
                syscall::send_nb(self.dns_reply_port, DNS_RESOLVE_OK, ip as u64, 0);
                self.dns_active = false;
                return;
            }
            if rtype == 28 && rdlength == 16 && off + 16 <= data.len() {
                // AAAA record: 16-byte IPv6 address. Pack into 2 u64s.
                let mut a0 = 0u64;
                let mut a1 = 0u64;
                for i in 0..8 {
                    a0 |= (data[off + i] as u64) << (i * 8);
                }
                for i in 0..8 {
                    a1 |= (data[off + 8 + i] as u64) << (i * 8);
                }
                // Return as type=28 in data[2] so caller knows it's IPv6.
                syscall::send_nb_4(self.dns_reply_port, DNS_RESOLVE_OK, a0, a1, 28, 0);
                self.dns_active = false;
                return;
            }
            off += rdlength;
        }
        // No A/AAAA found.
        syscall::send_nb(self.dns_reply_port, DNS_RESOLVE_FAIL, 0, 0);
        self.dns_active = false;
    }

    /// Skip a DNS name (handles compression pointers).
    fn skip_dns_name(&self, data: &[u8], mut off: usize) -> usize {
        loop {
            if off >= data.len() {
                return off;
            }
            let len = data[off] as usize;
            if len == 0 {
                return off + 1;
            }
            if len & 0xC0 == 0xC0 {
                // Compression pointer — 2 bytes total.
                return off + 2;
            }
            off += 1 + len;
        }
    }

    /// Build and send a DNS A query for the given hostname (max 24 bytes).
    fn handle_dns_resolve(&mut self, name: &[u8], name_len: usize, reply_port: u64) {
        if self.dns_active {
            // Already have a pending query.
            syscall::send_nb(reply_port, DNS_RESOLVE_FAIL, 0, 0);
            return;
        }

        // Build DNS query packet.
        // Header(12) + Question(name_encoded + QTYPE(2) + QCLASS(2))
        let mut pkt = [0u8; 512];
        // Transaction ID.
        self.dns_txid = self.dns_txid.wrapping_add(1);
        let txid = self.dns_txid;
        pkt[0] = (txid >> 8) as u8;
        pkt[1] = txid as u8;
        // Flags: standard query, recursion desired.
        pkt[2] = 0x01; // RD=1
        pkt[3] = 0x00;
        // QDCOUNT = 1.
        pkt[4] = 0;
        pkt[5] = 1;
        // ANCOUNT, NSCOUNT, ARCOUNT = 0.

        // Encode hostname as DNS name (labels).
        let mut off = 12;
        let mut label_start = 0;
        let actual_len = name_len.min(name.len());
        for i in 0..actual_len {
            if name[i] == b'.' {
                let label_len = i - label_start;
                if label_len == 0 || label_len > 63 || off + 1 + label_len > 500 {
                    syscall::send_nb(reply_port, DNS_RESOLVE_FAIL, 0, 0);
                    return;
                }
                pkt[off] = label_len as u8;
                off += 1;
                pkt[off..off + label_len].copy_from_slice(&name[label_start..i]);
                off += label_len;
                label_start = i + 1;
            }
        }
        // Last label (after final dot, or no dots at all).
        let label_len = actual_len - label_start;
        if label_len > 0 {
            if label_len > 63 || off + 1 + label_len > 500 {
                syscall::send_nb(reply_port, DNS_RESOLVE_FAIL, 0, 0);
                return;
            }
            pkt[off] = label_len as u8;
            off += 1;
            pkt[off..off + label_len].copy_from_slice(&name[label_start..actual_len]);
            off += label_len;
        }
        // Null terminator for name.
        pkt[off] = 0;
        off += 1;
        // QTYPE = A (1).
        pkt[off] = 0;
        pkt[off + 1] = 1;
        off += 2;
        // QCLASS = IN (1).
        pkt[off] = 0;
        pkt[off + 1] = 1;
        off += 2;

        let dns_payload_len = off;

        // Build UDP header (8 bytes) + DNS payload.
        let udp_len = 8 + dns_payload_len;
        let mut udp = [0u8; 600];
        // Src port.
        udp[0] = (DNS_LOCAL_PORT >> 8) as u8;
        udp[1] = DNS_LOCAL_PORT as u8;
        // Dst port.
        udp[2] = (DNS_PORT >> 8) as u8;
        udp[3] = DNS_PORT as u8;
        // Length.
        udp[4] = (udp_len >> 8) as u8;
        udp[5] = udp_len as u8;
        // Checksum = 0 (optional for IPv4 UDP).
        udp[6] = 0;
        udp[7] = 0;
        // DNS payload.
        udp[8..8 + dns_payload_len].copy_from_slice(&pkt[..dns_payload_len]);

        // Send as IPv4 UDP (proto 17) to DNS server.
        let mac = self.dst_mac_for(DNS_SERVER_IP);
        self.send_ipv4(DNS_SERVER_IP, 17, &udp[..udp_len], mac);

        self.dns_active = true;
        self.dns_reply_port = reply_port;
        self.dns_polls = 0;
    }

    /// Tick DNS timeout.
    fn tick_dns(&mut self) {
        if self.dns_active {
            self.dns_polls += 1;
            if self.dns_polls > 5000 {
                syscall::send_nb(self.dns_reply_port, DNS_RESOLVE_FAIL, 0, 0);
                self.dns_active = false;
            }
        }
    }

    // ---------------------------------------------------------------
    // Ping management
    // ---------------------------------------------------------------

    fn start_ping(&mut self, target_ip: [u8; 4], reply_port: u64) {
        if self.ping_active {
            syscall::send_nb(reply_port, NET_PING_FAIL, 2, 0);
            return;
        }
        self.ping_target = target_ip;
        self.ping_reply_port = reply_port;
        self.ping_seq = self.ping_seq.wrapping_add(1);
        self.ping_polls = 0;
        self.ping_active = true;
        self.ping_sent_icmp = false;
        // Send immediately if ARP is cached, else tick_ping will retry.
        self.try_send_ping();
    }

    fn try_send_ping(&mut self) {
        let target = self.ping_target;
        let mac = self.dst_mac_for(target);
        let seq = self.ping_seq;
        self.send_icmp_echo_request(target, mac, seq);
        self.ping_sent_icmp = true;
    }

    fn tick_ping(&mut self) {
        if !self.ping_active {
            return;
        }
        self.ping_polls += 1;
        // Retransmit ICMP echo every 200 ticks in case the first one was lost.
        if self.ping_polls % 200 == 0 {
            self.try_send_ping();
        }
        if self.ping_polls >= PING_TIMEOUT {
            syscall::send_nb(self.ping_reply_port, NET_PING_FAIL, 1, 0);
            self.ping_active = false;
        }
    }

    // ---------------------------------------------------------------
    // TCP: build + send packets
    // ---------------------------------------------------------------

    fn build_tcp_packet(
        &self,
        dst_ip: [u8; 4],
        dst_mac: [u8; 6],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) {
        let tcp_len = 20 + payload.len();
        let mut tcp_seg = [0u8; 20 + 1460]; // max TCP segment
        put_u16_be(&mut tcp_seg, 0, src_port);
        put_u16_be(&mut tcp_seg, 2, dst_port);
        put_u32_be(&mut tcp_seg, 4, seq);
        put_u32_be(&mut tcp_seg, 8, ack);
        tcp_seg[12] = 5 << 4; // data offset = 5 (20 bytes)
        tcp_seg[13] = flags;
        put_u16_be(&mut tcp_seg, 14, 2048); // window size
        if !payload.is_empty() {
            tcp_seg[20..20 + payload.len()].copy_from_slice(payload);
        }
        // TCP checksum (pseudo-header + segment).
        let cksum = tcp_checksum(&MY_IP, &dst_ip, &tcp_seg[..tcp_len]);
        tcp_seg[16] = (cksum >> 8) as u8;
        tcp_seg[17] = cksum as u8;

        // Send as IPv4 packet via eth_srv.
        self.send_ipv4(dst_ip, 6, &tcp_seg[..tcp_len], dst_mac);
    }

    fn send_tcp_for_conn(&self, conn_idx: usize, flags: u8, payload: &[u8]) {
        let dst_ip = self.tcp[conn_idx].remote_ip;
        let src_port = self.tcp[conn_idx].local_port;
        let dst_port = self.tcp[conn_idx].remote_port;
        let seq = self.tcp[conn_idx].snd_nxt;
        let ack = self.tcp[conn_idx].rcv_nxt;
        let mac = self.dst_mac_for(dst_ip);
        self.build_tcp_packet(dst_ip, mac, src_port, dst_port, seq, ack, flags, payload);
    }

    // ---------------------------------------------------------------
    // TCP: connect (active open)
    // ---------------------------------------------------------------

    fn handle_tcp_connect(&mut self, dst_ip_be: u32, dst_port: u16, reply_port: u64) {
        let slot = self.tcp.iter().position(|c| c.state == TCP_CLOSED);
        let slot = match slot {
            Some(s) => s,
            None => {
                syscall::send_nb(reply_port, NET_TCP_FAIL, 1, 0);
                return;
            }
        };
        let local_port = self.next_ephemeral_port;
        self.next_ephemeral_port = self.next_ephemeral_port.wrapping_add(1);
        if self.next_ephemeral_port < 49152 {
            self.next_ephemeral_port = 49152;
        }

        let isn = self.tcp_isn;
        self.tcp_isn = self.tcp_isn.wrapping_add(64000);

        let remote_ip = dst_ip_be.to_be_bytes();
        self.tcp[slot] = TcpConn {
            state: TCP_SYN_SENT,
            local_port,
            remote_ip,
            remote_port: dst_port,
            snd_nxt: isn,
            snd_una: isn,
            rcv_nxt: 0,
            reply_port,
            recv_reply_port: 0,
            rx_buf: [0; TCP_RX_BUF_SIZE],
            rx_head: 0,
            rx_tail: 0,
            timeout: 0,
        };

        syscall::debug_puts(b"  [tcp4_srv] TCP connect to ");
        print_ip(remote_ip);
        syscall::debug_puts(b":");
        print_num(dst_port as u64);
        syscall::debug_puts(b" slot=");
        print_num(slot as u64);
        syscall::debug_puts(b"\n");

        // Send SYN immediately — dst_mac_for never blocks.
        let mac = self.dst_mac_for(remote_ip);
        self.build_tcp_packet(remote_ip, mac, local_port, dst_port, isn, 0, TCP_SYN, &[]);
    }

    // ---------------------------------------------------------------
    // TCP: full RX state machine
    // ---------------------------------------------------------------

    fn handle_tcp_rx(&mut self, src_ip: [u8; 4], tcp_data: &[u8]) {
        if tcp_data.len() < 20 {
            return;
        }
        let src_port = get_u16_be(tcp_data, 0);
        let dst_port = get_u16_be(tcp_data, 2);
        let seq = get_u32_be(tcp_data, 4);
        let ack = get_u32_be(tcp_data, 8);
        let data_off = ((tcp_data[12] >> 4) as usize) * 4;
        let flags = tcp_data[13];
        let payload = if data_off < tcp_data.len() {
            &tcp_data[data_off..]
        } else {
            &[]
        };

        // Find matching connection.
        let idx = self.tcp.iter().position(|c| {
            c.state != TCP_CLOSED
                && c.local_port == dst_port
                && c.remote_port == src_port
                && c.remote_ip == src_ip
        });
        let idx = match idx {
            Some(i) => i,
            None => {
                if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
                    self.handle_incoming_syn(src_ip, src_port, dst_port, seq);
                }
                return;
            }
        };

        if flags & TCP_RST != 0 {
            let reply_port = self.tcp[idx].reply_port;
            self.tcp[idx].state = TCP_CLOSED;
            syscall::send_nb(reply_port, NET_TCP_FAIL, 2, 0);
            return;
        }

        match self.tcp[idx].state {
            TCP_SYN_SENT => {
                if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 {
                    if ack != self.tcp[idx].snd_nxt.wrapping_add(1) {
                        return;
                    }
                    self.tcp[idx].snd_una = ack;
                    self.tcp[idx].snd_nxt = ack;
                    self.tcp[idx].rcv_nxt = seq.wrapping_add(1);
                    self.tcp[idx].state = TCP_ESTABLISHED;
                    self.tcp[idx].timeout = 0;
                    self.send_tcp_for_conn(idx, TCP_ACK, &[]);
                    let reply_port = self.tcp[idx].reply_port;
                    syscall::send_nb(reply_port, NET_TCP_CONNECTED, idx as u64, 0);
                    syscall::debug_puts(b"  [tcp4_srv] TCP ESTABLISHED slot=");
                    print_num(idx as u64);
                    syscall::debug_puts(b"\n");
                }
            }
            TCP_SYN_RECEIVED => {
                if flags & TCP_ACK != 0 {
                    self.tcp[idx].snd_una = ack;
                    self.tcp[idx].state = TCP_ESTABLISHED;
                    self.tcp[idx].timeout = 0;
                    syscall::debug_puts(b"  [tcp4_srv] TCP accept ESTABLISHED slot=");
                    print_num(idx as u64);
                    syscall::debug_puts(b"\n");
                    let reply_port = self.tcp[idx].reply_port;
                    if reply_port != 0 {
                        self.tcp[idx].reply_port = 0;
                        syscall::send_nb(reply_port, NET_TCP_ACCEPT_OK, idx as u64, 0);
                    }
                }
            }
            TCP_ESTABLISHED => {
                if flags & TCP_ACK != 0 {
                    self.tcp[idx].snd_una = ack;
                }
                if !payload.is_empty() && seq == self.tcp[idx].rcv_nxt {
                    self.tcp[idx].rcv_nxt = seq.wrapping_add(payload.len() as u32);
                    self.tcp[idx].rx_push(payload);
                    self.send_tcp_for_conn(idx, TCP_ACK, &[]);
                    // Reset coalesce countdown on each segment arrival
                    // so split segments accumulate before delivery.
                    if self.tcp[idx].recv_reply_port != 0 {
                        self.deliver_pending = true;
                    }
                }
                if flags & TCP_FIN != 0 {
                    self.tcp[idx].rcv_nxt = self.tcp[idx].rcv_nxt.wrapping_add(1);
                    self.send_tcp_for_conn(idx, TCP_ACK, &[]);
                    self.tcp[idx].state = TCP_CLOSE_WAIT;
                }
            }
            TCP_FIN_WAIT_1 => {
                if flags & TCP_ACK != 0 {
                    self.tcp[idx].snd_una = ack;
                    if flags & TCP_FIN != 0 {
                        self.tcp[idx].rcv_nxt = seq.wrapping_add(1);
                        self.send_tcp_for_conn(idx, TCP_ACK, &[]);
                        self.tcp[idx].state = TCP_TIME_WAIT;
                        self.tcp[idx].timeout = 0;
                    } else {
                        self.tcp[idx].state = TCP_FIN_WAIT_2;
                    }
                }
            }
            TCP_FIN_WAIT_2 => {
                if flags & TCP_FIN != 0 {
                    self.tcp[idx].rcv_nxt = seq.wrapping_add(1);
                    self.send_tcp_for_conn(idx, TCP_ACK, &[]);
                    self.tcp[idx].state = TCP_TIME_WAIT;
                    self.tcp[idx].timeout = 0;
                }
            }
            TCP_LAST_ACK => {
                if flags & TCP_ACK != 0 {
                    self.tcp[idx].state = TCP_CLOSED;
                    let reply_port = self.tcp[idx].reply_port;
                    syscall::send_nb(reply_port, NET_TCP_CLOSE_OK, idx as u64, 0);
                }
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------------
    // TCP: data delivery
    // ---------------------------------------------------------------

    fn deliver_tcp_data(&mut self, idx: usize, reply_port: u64) {
        let mut buf = [0u8; 24];
        let n = self.tcp[idx].rx_pop(&mut buf);
        if n == 0 {
            return;
        }
        let mut d1: u64 = 0;
        let mut d2: u64 = 0;
        let mut d3: u64 = 0;
        for i in 0..n.min(8) {
            d1 |= (buf[i] as u64) << (i * 8);
        }
        for i in 0..n.saturating_sub(8).min(8) {
            d2 |= (buf[8 + i] as u64) << (i * 8);
        }
        for i in 0..n.saturating_sub(16).min(8) {
            d3 |= (buf[16 + i] as u64) << (i * 8);
        }
        syscall::send_nb_4(reply_port, NET_TCP_DATA, n as u64, d1, d2, d3);
    }

    fn handle_tcp_send(&mut self, conn_id: usize, payload: &[u8], reply_port: u64) {
        if conn_id >= MAX_TCP_CONNS || self.tcp[conn_id].state != TCP_ESTABLISHED {
            syscall::send_nb(reply_port, NET_TCP_FAIL, 0, 0);
            return;
        }
        self.send_tcp_for_conn(conn_id, TCP_ACK | TCP_PSH, payload);
        self.tcp[conn_id].snd_nxt = self.tcp[conn_id].snd_nxt.wrapping_add(payload.len() as u32);
        syscall::send_nb(reply_port, NET_TCP_SEND_OK, conn_id as u64, 0);
    }

    fn handle_tcp_recv(&mut self, conn_id: usize, reply_port: u64) {
        if conn_id >= MAX_TCP_CONNS || self.tcp[conn_id].state == TCP_CLOSED {
            syscall::send_nb(reply_port, NET_TCP_FAIL, 0, 0);
            return;
        }
        if self.tcp[conn_id].state == TCP_ESTABLISHED || self.tcp[conn_id].rx_len() > 0 {
            // Store the reply port — delivery happens through the
            // coalesce countdown in the main loop.
            self.tcp[conn_id].recv_reply_port = reply_port;
            if self.tcp[conn_id].rx_len() > 0 {
                self.deliver_pending = true;
            }
        } else {
            // Connection closed/closing with no data.
            syscall::send_nb(reply_port, NET_TCP_CLOSED, conn_id as u64, 0);
        }
    }

    fn handle_tcp_close(&mut self, conn_id: usize, reply_port: u64) {
        if conn_id >= MAX_TCP_CONNS {
            syscall::send_nb(reply_port, NET_TCP_FAIL, 0, 0);
            return;
        }
        self.tcp[conn_id].reply_port = reply_port;
        match self.tcp[conn_id].state {
            TCP_ESTABLISHED => {
                self.send_tcp_for_conn(conn_id, TCP_FIN | TCP_ACK, &[]);
                self.tcp[conn_id].snd_nxt = self.tcp[conn_id].snd_nxt.wrapping_add(1);
                self.tcp[conn_id].state = TCP_FIN_WAIT_1;
                self.tcp[conn_id].timeout = 0;
            }
            TCP_CLOSE_WAIT => {
                self.send_tcp_for_conn(conn_id, TCP_FIN | TCP_ACK, &[]);
                self.tcp[conn_id].snd_nxt = self.tcp[conn_id].snd_nxt.wrapping_add(1);
                self.tcp[conn_id].state = TCP_LAST_ACK;
                self.tcp[conn_id].timeout = 0;
            }
            _ => {
                self.tcp[conn_id].state = TCP_CLOSED;
                syscall::send_nb(reply_port, NET_TCP_CLOSE_OK, conn_id as u64, 0);
            }
        }
    }

    // ---------------------------------------------------------------
    // TCP: passive open (listen/accept)
    // ---------------------------------------------------------------

    fn handle_incoming_syn(&mut self, src_ip: [u8; 4], src_port: u16, dst_port: u16, seq: u32) {
        let listen_idx = self
            .listen
            .iter()
            .position(|l| l.active && l.port == dst_port);
        if listen_idx.is_none() {
            return;
        }
        let listen_idx = listen_idx.unwrap();

        let slot = self.tcp.iter().position(|c| c.state == TCP_CLOSED);
        let slot = match slot {
            Some(s) => s,
            None => return,
        };

        let isn = self.tcp_isn;
        self.tcp_isn = self.tcp_isn.wrapping_add(64000);

        self.tcp[slot] = TcpConn {
            state: TCP_SYN_RECEIVED,
            local_port: dst_port,
            remote_ip: src_ip,
            remote_port: src_port,
            snd_nxt: isn.wrapping_add(1),
            snd_una: isn,
            rcv_nxt: seq.wrapping_add(1),
            reply_port: 0,
            recv_reply_port: 0,
            rx_buf: [0; TCP_RX_BUF_SIZE],
            rx_head: 0,
            rx_tail: 0,
            timeout: 0,
        };

        // Send SYN-ACK.
        let mac = self.dst_mac_for(src_ip);
        self.build_tcp_packet(
            src_ip,
            mac,
            dst_port,
            src_port,
            isn,
            seq.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            &[],
        );

        syscall::debug_puts(b"  [tcp4_srv] SYN-ACK sent slot=");
        print_num(slot as u64);
        syscall::debug_puts(b"\n");

        // Wire up pending accept.
        let accept_rp = self.listen[listen_idx].accept_reply_port;
        if accept_rp != 0 {
            self.listen[listen_idx].accept_reply_port = 0;
            self.tcp[slot].reply_port = accept_rp;
        }
    }

    fn handle_tcp_bind(&self, port: u16, reply_port: u64) {
        syscall::send_nb(reply_port, NET_TCP_BIND_OK, port as u64, 0);
    }

    fn handle_tcp_listen_req(&mut self, port: u16, _backlog: u32, reply_port: u64) {
        let slot = self.listen.iter().position(|l| !l.active);
        match slot {
            Some(s) => {
                self.listen[s] = ListenSlot {
                    active: true,
                    port,
                    accept_reply_port: 0,
                };
                syscall::debug_puts(b"  [tcp4_srv] TCP LISTEN port=");
                print_num(port as u64);
                syscall::debug_puts(b"\n");
                syscall::send_nb(reply_port, NET_TCP_LISTEN_OK, port as u64, 0);
            }
            None => {
                syscall::send_nb(reply_port, NET_TCP_LISTEN_FAIL, 0, 0);
            }
        }
    }

    fn handle_tcp_accept(&mut self, port: u16, reply_port: u64) {
        // Check for already-established or in-handshake connections.
        for i in 0..MAX_TCP_CONNS {
            if (self.tcp[i].state == TCP_ESTABLISHED || self.tcp[i].state == TCP_SYN_RECEIVED)
                && self.tcp[i].local_port == port
            {
                if self.tcp[i].state == TCP_ESTABLISHED {
                    syscall::send_nb(reply_port, NET_TCP_ACCEPT_OK, i as u64, 0);
                    return;
                }
                self.tcp[i].reply_port = reply_port;
                return;
            }
        }
        // No pending connections — defer in listen slot.
        for l in self.listen.iter_mut() {
            if l.active && l.port == port {
                l.accept_reply_port = reply_port;
                return;
            }
        }
        syscall::send_nb(reply_port, NET_TCP_ACCEPT_FAIL, 0, 0);
    }

    // ---------------------------------------------------------------
    // TCP: timeouts
    // ---------------------------------------------------------------

    fn tick_tcp(&mut self) {
        for i in 0..MAX_TCP_CONNS {
            match self.tcp[i].state {
                TCP_SYN_SENT => {
                    self.tcp[i].timeout += 1;
                    // Retransmit SYN every 500 ticks (ARP may not have
                    // resolved on the initial attempt).
                    if self.tcp[i].timeout % 500 == 0 && self.tcp[i].timeout < TCP_TIMEOUT {
                        let dst_ip = self.tcp[i].remote_ip;
                        let src_port = self.tcp[i].local_port;
                        let dst_port = self.tcp[i].remote_port;
                        let seq = self.tcp[i].snd_una;
                        let mac = self.dst_mac_for(dst_ip);
                        self.build_tcp_packet(
                            dst_ip, mac, src_port, dst_port, seq, 0, TCP_SYN, &[],
                        );
                    }
                    if self.tcp[i].timeout >= TCP_TIMEOUT {
                        let reply_port = self.tcp[i].reply_port;
                        self.tcp[i].state = TCP_CLOSED;
                        syscall::send_nb(reply_port, NET_TCP_FAIL, 3, 0);
                    }
                }
                TCP_SYN_RECEIVED => {
                    self.tcp[i].timeout += 1;
                    if self.tcp[i].timeout >= TCP_TIMEOUT {
                        self.tcp[i].state = TCP_CLOSED;
                    }
                }
                TCP_FIN_WAIT_1 | TCP_FIN_WAIT_2 | TCP_LAST_ACK => {
                    self.tcp[i].timeout += 1;
                    if self.tcp[i].timeout >= TCP_TIMEOUT {
                        let reply_port = self.tcp[i].reply_port;
                        self.tcp[i].state = TCP_CLOSED;
                        syscall::send_nb(reply_port, NET_TCP_CLOSE_OK, i as u64, 0);
                    }
                }
                TCP_TIME_WAIT => {
                    self.tcp[i].timeout += 1;
                    if self.tcp[i].timeout >= TCP_TIME_WAIT_TIMEOUT {
                        let reply_port = self.tcp[i].reply_port;
                        self.tcp[i].state = TCP_CLOSED;
                        syscall::send_nb(reply_port, NET_TCP_CLOSE_OK, i as u64, 0);
                    }
                }
                _ => {}
            }
        }
    }

    /// Deliver buffered data to connections with pending recv requests.
    /// Called after draining all IPC messages so that TCP segments from
    /// multiple NETIF_INPUT notifications are coalesced before delivery.
    fn deliver_pending_recvs(&mut self) {
        for i in 0..MAX_TCP_CONNS {
            let recv_port = self.tcp[i].recv_reply_port;
            if recv_port == 0 {
                continue;
            }
            if self.tcp[i].rx_len() > 0 {
                self.tcp[i].recv_reply_port = 0;
                self.deliver_tcp_data(i, recv_port);
            } else if self.tcp[i].state != TCP_ESTABLISHED {
                // Connection closed/closing with no data — notify.
                self.tcp[i].recv_reply_port = 0;
                syscall::send_nb(recv_port, NET_TCP_CLOSED, i as u64, 0);
            }
        }
    }
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

fn mac_to_u64(mac: [u8; 6]) -> u64 {
    (mac[0] as u64)
        | ((mac[1] as u64) << 8)
        | ((mac[2] as u64) << 16)
        | ((mac[3] as u64) << 24)
        | ((mac[4] as u64) << 32)
        | ((mac[5] as u64) << 40)
}

fn u64_to_mac(v: u64) -> [u8; 6] {
    [
        v as u8,
        (v >> 8) as u8,
        (v >> 16) as u8,
        (v >> 24) as u8,
        (v >> 32) as u8,
        (v >> 40) as u8,
    ]
}

fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute internet checksum over a raw pointer range.
unsafe fn inet_checksum_raw(ptr: *const u8, len: usize) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < len {
        sum += ((*ptr.add(i) as u32) << 8) | (*ptr.add(i + 1) as u32);
        i += 2;
    }
    if i < len {
        sum += (*ptr.add(i) as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_data: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += ((src_ip[0] as u32) << 8) | (src_ip[1] as u32);
    sum += ((src_ip[2] as u32) << 8) | (src_ip[3] as u32);
    sum += ((dst_ip[0] as u32) << 8) | (dst_ip[1] as u32);
    sum += ((dst_ip[2] as u32) << 8) | (dst_ip[3] as u32);
    sum += 6u32; // protocol = TCP
    sum += tcp_data.len() as u32;
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += ((tcp_data[i] as u32) << 8) | (tcp_data[i + 1] as u32);
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn get_u16_be(buf: &[u8], off: usize) -> u16 {
    ((buf[off] as u16) << 8) | (buf[off + 1] as u16)
}

fn get_u32_be(buf: &[u8], off: usize) -> u32 {
    ((buf[off] as u32) << 24)
        | ((buf[off + 1] as u32) << 16)
        | ((buf[off + 2] as u32) << 8)
        | (buf[off + 3] as u32)
}

fn put_u16_be(buf: &mut [u8], off: usize, val: u16) {
    buf[off] = (val >> 8) as u8;
    buf[off + 1] = val as u8;
}

fn put_u32_be(buf: &mut [u8], off: usize, val: u32) {
    buf[off] = (val >> 24) as u8;
    buf[off + 1] = (val >> 16) as u8;
    buf[off + 2] = (val >> 8) as u8;
    buf[off + 3] = val as u8;
}

fn print_num(n: u64) {
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

fn print_ip(ip: [u8; 4]) {
    for i in 0..4 {
        if i > 0 {
            syscall::debug_putchar(b'.');
        }
        print_num(ip[i] as u64);
    }
}

fn print_mac(mac: [u8; 6]) {
    for i in 0..6 {
        if i > 0 {
            syscall::debug_putchar(b':');
        }
        let hi = mac[i] >> 4;
        let lo = mac[i] & 0xF;
        syscall::debug_putchar(if hi < 10 { b'0' + hi } else { b'a' + hi - 10 });
        syscall::debug_putchar(if lo < 10 { b'0' + lo } else { b'a' + lo - 10 });
    }
}

// ---------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------

fn handle_msg(dev: &mut Tcp4Dev, msg: &syscall::Message) {
    match msg.tag {
        NETIF_INPUT => {
            let payload_len = msg.data[0] as usize;
            let src_mac = u64_to_mac(msg.data[1]);
            dev.handle_input(payload_len, src_mac);
        }
        NET_STATUS => {
            let reply_port = msg.data[0];
            let mac_val = mac_to_u64(dev.mac);
            let ip_val = u32::from_be_bytes(MY_IP) as u64;
            syscall::send_nb(reply_port, NET_STATUS_OK, mac_val, ip_val);
        }
        NET_PING => {
            let target = (msg.data[0] as u32).to_be_bytes();
            let reply_port = msg.data[1];
            syscall::debug_puts(b"  [tcp4_srv] ping ");
            print_ip(target);
            syscall::debug_puts(b"\n");
            dev.start_ping(target, reply_port);
        }
        NET_TCP_CONNECT => {
            let dst_ip_be = msg.data[0] as u32;
            let dst_port = msg.data[1] as u16;
            let reply_port = msg.data[1] >> 16;
            dev.handle_tcp_connect(dst_ip_be, dst_port, reply_port);
        }
        NET_TCP_SEND => {
            let conn_id = msg.data[0] as usize;
            let len = (msg.data[1] & 0xFFFF) as usize;
            let reply_port = msg.data[1] >> 16;
            let mut payload = [0u8; 16];
            let d2 = msg.data[2];
            let d3 = msg.data[3];
            for i in 0..8 {
                payload[i] = (d2 >> (i * 8)) as u8;
            }
            for i in 0..8 {
                payload[8 + i] = (d3 >> (i * 8)) as u8;
            }
            dev.handle_tcp_send(conn_id, &payload[..len.min(16)], reply_port);
        }
        NET_TCP_RECV => {
            let conn_id = msg.data[0] as usize;
            let reply_port = msg.data[1] >> 16;
            dev.handle_tcp_recv(conn_id, reply_port);
        }
        NET_TCP_CLOSE => {
            let conn_id = msg.data[0] as usize;
            let reply_port = msg.data[1];
            dev.handle_tcp_close(conn_id, reply_port);
        }
        NET_TCP_BIND => {
            let port_num = msg.data[0] as u16;
            let reply_port = msg.data[1] >> 32;
            dev.handle_tcp_bind(port_num, reply_port);
        }
        NET_TCP_LISTEN => {
            let port_num = msg.data[0] as u16;
            let backlog = msg.data[1] as u32;
            let reply_port = msg.data[2] >> 32;
            dev.handle_tcp_listen_req(port_num, backlog, reply_port);
        }
        NET_TCP_ACCEPT => {
            let port_num = msg.data[0] as u16;
            let reply_port = msg.data[1] >> 32;
            dev.handle_tcp_accept(port_num, reply_port);
        }
        DNS_RESOLVE => {
            // data[0..2] = hostname (up to 24 bytes packed LE in 3 u64s)
            // data[3] = name_len(low32) | reply_port(high32)
            let mut name_buf = [0u8; 24];
            let d0 = msg.data[0];
            let d1 = msg.data[1];
            let d2 = msg.data[2];
            for i in 0..8 { name_buf[i] = (d0 >> (i * 8)) as u8; }
            for i in 0..8 { name_buf[8 + i] = (d1 >> (i * 8)) as u8; }
            for i in 0..8 { name_buf[16 + i] = (d2 >> (i * 8)) as u8; }
            let name_len = (msg.data[3] & 0xFFFFFFFF) as usize;
            let reply_port = msg.data[3] >> 32;
            dev.handle_dns_resolve(&name_buf, name_len.min(24), reply_port);
        }
        NET_TCP_RECV_NB => {
            let conn_id = msg.data[0] as usize;
            let reply_port = msg.data[1] >> 16;
            if conn_id >= MAX_TCP_CONNS || dev.tcp[conn_id].state == TCP_CLOSED {
                syscall::send_nb(reply_port, NET_TCP_FAIL, 0, 0);
            } else if dev.tcp[conn_id].rx_len() > 0 {
                dev.deliver_tcp_data(conn_id, reply_port);
            } else if dev.tcp[conn_id].state != TCP_ESTABLISHED {
                syscall::send_nb(reply_port, NET_TCP_CLOSED, conn_id as u64, 0);
            } else {
                syscall::send_nb(reply_port, NET_TCP_RECV_NONE, 0, 0);
            }
        }
        _ => {}
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [tcp4_srv] starting\n");

    // Wait for eth_srv to register.
    let eth_port = match syscall::ns_lookup_wait(b"eth") {
        Some(p) => p,
        None => {
            syscall::debug_puts(b"  [tcp4_srv] eth service not found\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    syscall::debug_puts(b"  [tcp4_srv] found eth_srv on port ");
    print_num(eth_port);
    syscall::debug_puts(b"\n");

    // Query link status for MAC address.
    let reply_port = syscall::port_create();
    syscall::send_nb(eth_port, NETIF_STATUS, reply_port, 0);
    let mac = if let Some(msg) = syscall::recv_msg_timeout(reply_port, 2_000_000) {
        if msg.tag == NETIF_STATUS_OK {
            u64_to_mac(msg.data[0])
        } else {
            [0; 6]
        }
    } else {
        [0; 6]
    };
    syscall::port_destroy(reply_port);

    syscall::debug_puts(b"  [tcp4_srv] MAC=");
    print_mac(mac);
    syscall::debug_puts(b" IP=");
    print_ip(MY_IP);
    syscall::debug_puts(b"\n");

    // Create our IPC port.
    let my_port = syscall::port_create();

    // Allocate RX and TX grant pages.
    let rx_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [tcp4_srv] mmap rx failed\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };
    let tx_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [tcp4_srv] mmap tx failed\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    // Register with eth_srv for IPv4 frames (ethertype 0x0800).
    let reg_reply = syscall::port_create();
    syscall::send_nb_4(
        eth_port,
        NETIF_REGISTER,
        ETHERTYPE_IPV4 as u64,
        my_port,
        reg_reply,
        0,
    );

    let client_id = if let Some(msg) = syscall::recv_msg_timeout(reg_reply, 2_000_000) {
        if msg.tag == NETIF_REGISTER_OK {
            let cid = msg.data[0];
            let eth_rx_va = msg.data[1] as usize;
            let eth_tx_va = msg.data[2] as usize;
            syscall::debug_puts(b"  [tcp4_srv] registered with eth_srv, client_id=");
            print_num(cid);
            syscall::debug_puts(b"\n");

            if !syscall::grant_pages(eth_port, rx_va, eth_rx_va, 1, false) {
                syscall::debug_puts(b"  [tcp4_srv] grant rx failed\n");
            }
            if !syscall::grant_pages(eth_port, tx_va, eth_tx_va, 1, false) {
                syscall::debug_puts(b"  [tcp4_srv] grant tx failed\n");
            }
            syscall::debug_puts(b"  [tcp4_srv] grant pages established\n");
            cid
        } else {
            syscall::debug_puts(b"  [tcp4_srv] register failed\n");
            loop {
                core::hint::spin_loop();
            }
        }
    } else {
        syscall::debug_puts(b"  [tcp4_srv] register timeout\n");
        loop {
            core::hint::spin_loop();
        }
    };
    syscall::port_destroy(reg_reply);

    let mut dev = Tcp4Dev::new(eth_port, my_port, client_id, mac, rx_va, tx_va);

    // Register as "net" service (backward compat).
    syscall::ns_register(b"net", my_port);
    syscall::debug_puts(b"  [tcp4_srv] registered as 'net' on port ");
    print_num(my_port);
    syscall::debug_puts(b"\n");

    // Try to learn the gateway MAC from eth_srv's ARP cache (optional — broadcast works).
    dev.resolve_gateway();

    // Poll-based server loop.
    loop {
        // 1. Drain all queued IPC messages.
        while let Some(msg) = syscall::recv_nb_msg(my_port) {
            handle_msg(&mut dev, &msg);
        }

        // 2. Deliver pending TCP data.
        if dev.deliver_pending {
            dev.deliver_pending = false;
            dev.deliver_pending_recvs();
        }

        // 3. Tick timeouts.
        dev.tick_ping();
        dev.tick_tcp();
        dev.tick_dns();

        // 4. Yield.
        syscall::yield_now();
    }
}
