#![no_std]
#![no_main]

// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024-2026 Nadia Chambers
// Reference codebases: Linux networking stack (IPv6/ICMPv6 semantics)

//! IPv6 network-layer server.
//!
//! Registers with eth_srv via the netif IPC protocol (ethertype 0x86DD),
//! receives IPv6 frames, and handles:
//! - ICMPv6 Echo Request/Reply (ping6)
//! - Neighbor Discovery Protocol (NDP) — Neighbor Solicitation/Advertisement
//! - Router Solicitation (for SLAAC)
//!
//! Exposes an IPC interface for upper-layer transports (future TCP6, UDP6).

extern crate userlib;

use userlib::syscall;

// --- Netif IPC protocol (must match eth_srv) ---
const NETIF_REGISTER: u64 = 0x5000;
const NETIF_REGISTER_OK: u64 = 0x5001;
const NETIF_INPUT: u64 = 0x5100;
const NETIF_XMIT: u64 = 0x5200;
const NETIF_XMIT_OK: u64 = 0x5201;
const NETIF_STATUS: u64 = 0x5400;
const NETIF_STATUS_OK: u64 = 0x5401;

// --- IPv6 IPC protocol ---
const IP6_PING: u64 = 0x6100;
const IP6_PING_OK: u64 = 0x6101;
const IP6_PING_FAIL: u64 = 0x61FF;
const IP6_STATUS: u64 = 0x6000;
const IP6_STATUS_OK: u64 = 0x6001;
const IP6_GATEWAY: u64 = 0x6200;
const IP6_GATEWAY_OK: u64 = 0x6201;
const IP6_GATEWAY_NONE: u64 = 0x62FF;

// --- TCP6 IPC protocol ---
const TCP6_CONNECT: u64 = 0x6300;
const TCP6_CONNECTED: u64 = 0x6301;
const TCP6_FAIL: u64 = 0x63FF;
const TCP6_SEND: u64 = 0x6400;
const TCP6_SEND_OK: u64 = 0x6401;
const TCP6_RECV: u64 = 0x6500;
const TCP6_DATA: u64 = 0x6501;
const TCP6_CLOSED: u64 = 0x65FF;
const TCP6_RECV_NB: u64 = 0x6510;
const TCP6_RECV_NONE: u64 = 0x6512;
const TCP6_CLOSE: u64 = 0x6600;
const TCP6_CLOSE_OK: u64 = 0x6601;
const TCP6_BIND: u64 = 0x6700;
const TCP6_BIND_OK: u64 = 0x6701;
const TCP6_LISTEN: u64 = 0x6800;
const TCP6_LISTEN_OK: u64 = 0x6801;
const TCP6_LISTEN_FAIL: u64 = 0x68FF;
const TCP6_ACCEPT: u64 = 0x6810;
const TCP6_ACCEPT_OK: u64 = 0x6811;
const TCP6_ACCEPT_FAIL: u64 = 0x68FE;

// --- UDP6 IPC protocol ---
const UDP6_BIND: u64 = 0x6900;
const UDP6_BIND_OK: u64 = 0x6901;
const UDP6_BIND_FAIL: u64 = 0x69FF;
const UDP6_SEND: u64 = 0x6A00;
const UDP6_SEND_OK: u64 = 0x6A01;
const UDP6_SEND_FAIL: u64 = 0x6AFF;
const UDP6_RECV: u64 = 0x6B00;
const UDP6_DATA: u64 = 0x6B01;
const UDP6_RECV_NB: u64 = 0x6B10;
const UDP6_RECV_NONE: u64 = 0x6B12;
const UDP6_CLOSE: u64 = 0x6C00;
const UDP6_CLOSE_OK: u64 = 0x6C01;

const MAX_UDP6_BINDS: usize = 8;
const UDP6_RX_BUF_SIZE: usize = 1024;

// --- TCP constants ---
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

const TCP_ST_CLOSED: u8 = 0;
const TCP_ST_SYN_SENT: u8 = 1;
const TCP_ST_ESTABLISHED: u8 = 2;
const TCP_ST_FIN_WAIT_1: u8 = 3;
const TCP_ST_FIN_WAIT_2: u8 = 4;
const TCP_ST_TIME_WAIT: u8 = 5;
const TCP_ST_CLOSE_WAIT: u8 = 6;
const TCP_ST_LAST_ACK: u8 = 7;
const TCP_ST_SYN_RECEIVED: u8 = 8;

const MAX_TCP6_CONNS: usize = 8;
const MAX_TCP6_LISTEN: usize = 4;
const TCP6_RX_BUF_SIZE: usize = 2048;
const TCP6_WINDOW: u16 = 2048;
const TCP6_TIMEOUT: u32 = 10000;
const TCP6_TIME_WAIT_TIMEOUT: u32 = 5000;

// --- Ethertypes ---
const ETHERTYPE_IPV6: u16 = 0x86DD;

// --- IPv6 next header values ---
const IPPROTO_ICMPV6: u8 = 58;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// --- ICMPv6 types ---
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMPV6_NEIGHBOR_SOLICIT: u8 = 135;
const ICMPV6_NEIGHBOR_ADVERT: u8 = 136;
const ICMPV6_ROUTER_SOLICIT: u8 = 133;
const ICMPV6_ROUTER_ADVERT: u8 = 134;

// IPv6 header is always 40 bytes.
const IPV6_HDR_LEN: usize = 40;
// ICMPv6 header is 4 bytes (type + code + checksum), but echo adds 4 more.
const ICMPV6_HDR_LEN: usize = 4;
// Max payload we can fit in an ethernet frame (MTU=1500 minus IPv6 header).
const MAX_IPV6_PAYLOAD: usize = 1460;

// --- Link-local address from MAC (EUI-64) ---
// fe80::xxxx:xxff:fexx:xxxx

// --- Neighbor cache ---
const NEIGHBOR_CACHE_SIZE: usize = 8;

struct NeighborEntry {
    valid: bool,
    ip6: [u8; 16],
    mac: [u8; 6],
}

impl NeighborEntry {
    const fn new() -> Self {
        Self {
            valid: false,
            ip6: [0; 16],
            mac: [0; 6],
        }
    }
}

// --- Pending ping state ---
struct PingState {
    active: bool,
    target: [u8; 16],
    reply_port: u64,
    seq: u16,
    polls: u32,
    sent: bool,
}

impl PingState {
    const fn new() -> Self {
        Self {
            active: false,
            target: [0; 16],
            reply_port: 0,
            seq: 0,
            polls: 0,
            sent: false,
        }
    }
}

// --- TCP6 connection ---

struct TcpConn6 {
    state: u8,
    local_port: u16,
    remote_ip: [u8; 16],
    remote_port: u16,
    snd_nxt: u32,
    snd_una: u32,
    rcv_nxt: u32,
    reply_port: u64,
    recv_reply_port: u64,
    rx_buf: [u8; TCP6_RX_BUF_SIZE],
    rx_head: usize,
    rx_tail: usize,
    timeout: u32,
}

impl TcpConn6 {
    const fn new() -> Self {
        Self {
            state: TCP_ST_CLOSED,
            local_port: 0,
            remote_ip: [0; 16],
            remote_port: 0,
            snd_nxt: 0,
            snd_una: 0,
            rcv_nxt: 0,
            reply_port: 0,
            recv_reply_port: 0,
            rx_buf: [0; TCP6_RX_BUF_SIZE],
            rx_head: 0,
            rx_tail: 0,
            timeout: 0,
        }
    }

    fn rx_len(&self) -> usize {
        if self.rx_head >= self.rx_tail {
            self.rx_head - self.rx_tail
        } else {
            TCP6_RX_BUF_SIZE - self.rx_tail + self.rx_head
        }
    }

    fn rx_push(&mut self, data: &[u8]) {
        for &b in data {
            let next = (self.rx_head + 1) % TCP6_RX_BUF_SIZE;
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
            self.rx_tail = (self.rx_tail + 1) % TCP6_RX_BUF_SIZE;
            n += 1;
        }
        n
    }
}

struct ListenSlot6 {
    active: bool,
    port: u16,
    accept_reply_port: u64,
}

impl ListenSlot6 {
    const fn new() -> Self {
        Self {
            active: false,
            port: 0,
            accept_reply_port: 0,
        }
    }
}

// --- UDP6 binding ---

struct Udp6Binding {
    active: bool,
    local_port: u16,
    recv_reply_port: u64,   // pending recv caller (0 = none)
    // Small circular RX buffer for one queued datagram.
    rx_buf: [u8; UDP6_RX_BUF_SIZE],
    rx_len: usize,          // bytes in current datagram (0 = empty)
    rx_src_ip: [u8; 16],
    rx_src_port: u16,
}

impl Udp6Binding {
    const fn new() -> Self {
        Self {
            active: false,
            local_port: 0,
            recv_reply_port: 0,
            rx_buf: [0; UDP6_RX_BUF_SIZE],
            rx_len: 0,
            rx_src_ip: [0; 16],
            rx_src_port: 0,
        }
    }
}

// --- IPv6 device ---

struct Ip6Dev {
    eth_port: u64,      // eth_srv's IPC port
    my_port: u64,       // our IPC port
    client_id: u64,     // eth_srv client slot (for NETIF_XMIT data[3])
    mac: [u8; 6],       // link-layer address
    link_local: [u8; 16], // fe80::eui64
    global_addr: [u8; 16], // SLAAC global address (from RA prefix + EUI-64)
    has_global: bool,    // true once RA prefix processed
    gateway_ip6: [u8; 16], // default router link-local (from RA source)
    gateway_mac: [u8; 6],  // default router MAC
    has_gateway: bool,     // true once RA received
    rx_va: usize,       // grant page for receiving frames from eth_srv
    tx_va: usize,       // grant page for sending frames to eth_srv
    // Neighbor cache (IPv6 → MAC).
    neighbors: [NeighborEntry; NEIGHBOR_CACHE_SIZE],
    neigh_next: usize,
    // Pending ping.
    ping: PingState,
    // TCP6 state.
    tcp6: [TcpConn6; MAX_TCP6_CONNS],
    listen6: [ListenSlot6; MAX_TCP6_LISTEN],
    tcp6_next_port: u16,
    tcp6_isn: u32,
    tcp6_deliver_pending: bool,
    // UDP6 state.
    udp6: [Udp6Binding; MAX_UDP6_BINDS],
}

impl Ip6Dev {
    fn new(eth_port: u64, my_port: u64, client_id: u64, mac: [u8; 6], rx_va: usize, tx_va: usize) -> Self {
        let link_local = eui64_link_local(mac);
        Self {
            eth_port,
            my_port,
            client_id,
            mac,
            link_local,
            global_addr: [0; 16],
            has_global: false,
            gateway_ip6: [0; 16],
            gateway_mac: [0; 6],
            has_gateway: false,
            rx_va,
            tx_va,
            neighbors: [const { NeighborEntry::new() }; NEIGHBOR_CACHE_SIZE],
            neigh_next: 0,
            ping: PingState::new(),
            tcp6: [const { TcpConn6::new() }; MAX_TCP6_CONNS],
            listen6: [const { ListenSlot6::new() }; MAX_TCP6_LISTEN],
            tcp6_next_port: 49152,
            tcp6_isn: 200000,
            tcp6_deliver_pending: false,
            udp6: [const { Udp6Binding::new() }; MAX_UDP6_BINDS],
        }
    }

    // ---------------------------------------------------------------
    // Neighbor cache
    // ---------------------------------------------------------------

    fn neigh_lookup(&self, ip6: &[u8; 16]) -> Option<[u8; 6]> {
        for e in &self.neighbors {
            if e.valid && e.ip6 == *ip6 {
                return Some(e.mac);
            }
        }
        None
    }

    fn neigh_store(&mut self, ip6: [u8; 16], mac: [u8; 6]) {
        for e in &mut self.neighbors {
            if e.valid && e.ip6 == ip6 {
                e.mac = mac;
                return;
            }
        }
        let idx = self.neigh_next % NEIGHBOR_CACHE_SIZE;
        self.neighbors[idx] = NeighborEntry {
            valid: true,
            ip6,
            mac,
        };
        self.neigh_next += 1;
    }

    // ---------------------------------------------------------------
    // Packet TX
    // ---------------------------------------------------------------

    /// Send an IPv6 packet via eth_srv. Builds IPv6 header + copies payload
    /// into the TX grant page, then sends NETIF_XMIT.
    fn send_ipv6(&mut self, dst_ip6: &[u8; 16], next_header: u8, payload: &[u8], dst_mac: [u8; 6], hop_limit: u8) {
        let payload_len = payload.len();
        if payload_len > MAX_IPV6_PAYLOAD {
            return;
        }
        let total = IPV6_HDR_LEN + payload_len;

        // Build IPv6 header + payload in TX grant page.
        let buf = self.tx_va as *mut u8;
        unsafe {
            // IPv6 header (40 bytes).
            // Version (4) | Traffic class (8) | Flow label (20) = 0x60000000
            let hdr = buf;
            *hdr.add(0) = 0x60; // version=6, TC high nibble=0
            *hdr.add(1) = 0x00; // TC low nibble=0, flow label high
            *hdr.add(2) = 0x00; // flow label
            *hdr.add(3) = 0x00; // flow label
            // Payload length (big-endian u16).
            *hdr.add(4) = (payload_len >> 8) as u8;
            *hdr.add(5) = payload_len as u8;
            // Next header.
            *hdr.add(6) = next_header;
            // Hop limit.
            *hdr.add(7) = hop_limit;
            // Source address: use global if available and dest is non-link-local.
            let src = if self.has_global && !Self::is_link_local(&dst_ip6) {
                &self.global_addr
            } else {
                &self.link_local
            };
            core::ptr::copy_nonoverlapping(src.as_ptr(), hdr.add(8), 16);
            // Destination address (16 bytes).
            core::ptr::copy_nonoverlapping(dst_ip6.as_ptr(), hdr.add(24), 16);
            // Payload.
            core::ptr::copy_nonoverlapping(payload.as_ptr(), hdr.add(IPV6_HDR_LEN), payload_len);
        }

        // Send NETIF_XMIT to eth_srv (blocking send to guarantee delivery).
        let reply_port = syscall::port_create();
        let mac_val = mac_to_u64(dst_mac);
        // data[0]=payload_len, data[1]=dst_mac, data[2]=ethertype|(reply_port<<16), data[3]=client_id
        syscall::send(
            self.eth_port,
            NETIF_XMIT,
            total as u64,
            mac_val,
            ETHERTYPE_IPV6 as u64 | (reply_port << 16),
            self.client_id,
        );
        // Wait for eth_srv to read TX page and reply XMIT_OK (must complete
        // before we overwrite the TX page with the next send).
        let _ = syscall::recv_msg_timeout(reply_port, 500_000);
        syscall::port_destroy(reply_port);
    }

    // ---------------------------------------------------------------
    // ICMPv6
    // ---------------------------------------------------------------

    /// Compute ICMPv6 checksum (pseudo-header + ICMPv6 data).
    fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmpv6_data: &[u8]) -> u16 {
        let mut sum = 0u32;
        // Pseudo-header: src (16) + dst (16) + upper-layer length (4) + next header (4).
        let mut i = 0;
        while i < 16 {
            sum += ((src[i] as u32) << 8) | (src[i + 1] as u32);
            i += 2;
        }
        i = 0;
        while i < 16 {
            sum += ((dst[i] as u32) << 8) | (dst[i + 1] as u32);
            i += 2;
        }
        let len = icmpv6_data.len() as u32;
        sum += len >> 16;
        sum += len & 0xFFFF;
        sum += IPPROTO_ICMPV6 as u32;
        // ICMPv6 data.
        i = 0;
        while i + 1 < icmpv6_data.len() {
            sum += ((icmpv6_data[i] as u32) << 8) | (icmpv6_data[i + 1] as u32);
            i += 2;
        }
        if i < icmpv6_data.len() {
            sum += (icmpv6_data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Pick source address: global for non-link-local dests, link-local otherwise.
    fn src_for(&self, dst: &[u8; 16]) -> [u8; 16] {
        if self.has_global && !Self::is_link_local(dst) {
            self.global_addr
        } else {
            self.link_local
        }
    }

    /// Send ICMPv6 Echo Request.
    fn send_echo_request(&mut self, dst_ip6: &[u8; 16], dst_mac: [u8; 6], seq: u16) {
        // ICMPv6 echo: type(1) + code(1) + checksum(2) + id(2) + seq(2) + data(32) = 40 bytes
        let mut icmp = [0u8; 40];
        icmp[0] = ICMPV6_ECHO_REQUEST;
        icmp[1] = 0; // code
        // checksum at [2..4] — fill after
        icmp[4] = 0x12; // identifier high
        icmp[5] = 0x34; // identifier low
        icmp[6] = (seq >> 8) as u8;
        icmp[7] = seq as u8;
        // 32 bytes payload.
        for i in 0..32 {
            icmp[8 + i] = i as u8;
        }
        let src = self.src_for(dst_ip6);
        let cksum = Self::icmpv6_checksum(&src, dst_ip6, &icmp);
        icmp[2] = (cksum >> 8) as u8;
        icmp[3] = cksum as u8;
        self.send_ipv6(dst_ip6, IPPROTO_ICMPV6, &icmp, dst_mac, 64);
    }

    /// Send ICMPv6 Echo Reply (mirror back the received echo request).
    fn send_echo_reply(
        &mut self,
        dst_ip6: &[u8; 16],
        dst_mac: [u8; 6],
        id: u16,
        seq: u16,
        data: &[u8],
    ) {
        let total_len = 8 + data.len(); // type+code+cksum+id+seq + data
        if total_len > MAX_IPV6_PAYLOAD {
            return;
        }
        let mut icmp = [0u8; 1460];
        icmp[0] = ICMPV6_ECHO_REPLY;
        icmp[1] = 0;
        // checksum at [2..4]
        icmp[4] = (id >> 8) as u8;
        icmp[5] = id as u8;
        icmp[6] = (seq >> 8) as u8;
        icmp[7] = seq as u8;
        icmp[8..8 + data.len()].copy_from_slice(data);
        let cksum = Self::icmpv6_checksum(&self.link_local, dst_ip6, &icmp[..total_len]);
        icmp[2] = (cksum >> 8) as u8;
        icmp[3] = cksum as u8;
        self.send_ipv6(dst_ip6, IPPROTO_ICMPV6, &icmp[..total_len], dst_mac, 64);
    }

    /// Send NDP Neighbor Solicitation for the given target address.
    fn send_neighbor_solicit(&mut self, target_ip6: &[u8; 16]) {
        // NS: type(135) + code(0) + cksum(2) + reserved(4) + target(16) + option(8) = 32 bytes
        let mut ns = [0u8; 32];
        ns[0] = ICMPV6_NEIGHBOR_SOLICIT;
        // reserved [4..8] = 0
        ns[8..24].copy_from_slice(target_ip6);
        // Source link-layer address option: type=1, len=1(8 bytes), MAC.
        ns[24] = 1; // option type
        ns[25] = 1; // option length (units of 8 bytes)
        ns[26..32].copy_from_slice(&self.mac);

        // Solicited-node multicast address: ff02::1:ffXX:XXXX
        let mut sol_node = [0u8; 16];
        sol_node[0] = 0xFF;
        sol_node[1] = 0x02;
        sol_node[11] = 0x01;
        sol_node[12] = 0xFF;
        sol_node[13] = target_ip6[13];
        sol_node[14] = target_ip6[14];
        sol_node[15] = target_ip6[15];

        let cksum = Self::icmpv6_checksum(&self.link_local, &sol_node, &ns);
        ns[2] = (cksum >> 8) as u8;
        ns[3] = cksum as u8;

        // Solicited-node multicast MAC: 33:33:ff:XX:XX:XX
        let dst_mac = [
            0x33,
            0x33,
            0xFF,
            target_ip6[13],
            target_ip6[14],
            target_ip6[15],
        ];
        self.send_ipv6(&sol_node, IPPROTO_ICMPV6, &ns, dst_mac, 255);
    }

    /// Send NDP Neighbor Advertisement in response to a solicitation.
    fn send_neighbor_advert(&mut self, dst_ip6: &[u8; 16], dst_mac: [u8; 6], target: &[u8; 16]) {
        // NA: type(136) + code(0) + cksum(2) + flags(4) + target(16) + option(8) = 32 bytes
        let mut na = [0u8; 32];
        na[0] = ICMPV6_NEIGHBOR_ADVERT;
        // Flags: Solicited=1, Override=1 → 0x60000000 in bytes 4-7.
        na[4] = 0x60;
        // Target address: the address that was solicited.
        na[8..24].copy_from_slice(target);
        // Target link-layer address option.
        na[24] = 2; // option type (target link-layer)
        na[25] = 1; // length in 8-byte units
        na[26..32].copy_from_slice(&self.mac);

        // Checksum must use the same source address that send_ipv6 will put
        // in the IPv6 header (global for non-link-local destinations).
        let src = self.src_for(dst_ip6);
        let cksum = Self::icmpv6_checksum(&src, dst_ip6, &na);
        na[2] = (cksum >> 8) as u8;
        na[3] = cksum as u8;
        self.send_ipv6(dst_ip6, IPPROTO_ICMPV6, &na, dst_mac, 255);
    }

    /// Send Router Solicitation to discover default router.
    fn send_router_solicit(&mut self) {
        // RS: type(133) + code(0) + cksum(2) + reserved(4) + option(8) = 16 bytes
        let mut rs = [0u8; 16];
        rs[0] = ICMPV6_ROUTER_SOLICIT;
        // Source link-layer address option.
        rs[8] = 1; // option type
        rs[9] = 1; // length
        rs[10..16].copy_from_slice(&self.mac);

        // All-routers multicast: ff02::2
        let all_routers: [u8; 16] = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let cksum = Self::icmpv6_checksum(&self.link_local, &all_routers, &rs);
        rs[2] = (cksum >> 8) as u8;
        rs[3] = cksum as u8;

        // All-routers multicast MAC: 33:33:00:00:00:02
        let dst_mac = [0x33, 0x33, 0x00, 0x00, 0x00, 0x02];
        self.send_ipv6(&all_routers, IPPROTO_ICMPV6, &rs, dst_mac, 255);
    }

    // ---------------------------------------------------------------
    // Packet RX dispatch
    // ---------------------------------------------------------------

    fn handle_input(&mut self, payload_len: usize, src_mac: [u8; 6]) {
        if payload_len < IPV6_HDR_LEN {
            return;
        }
        let pkt = unsafe {
            core::slice::from_raw_parts(self.rx_va as *const u8, payload_len)
        };

        // Verify IPv6 version.
        if (pkt[0] >> 4) != 6 {
            return;
        }

        let ipv6_payload_len = ((pkt[4] as usize) << 8) | (pkt[5] as usize);
        let next_header = pkt[6];
        let _hop_limit = pkt[7];
        let src_ip6: [u8; 16] = {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[8..24]);
            a
        };
        let dst_ip6: [u8; 16] = {
            let mut a = [0u8; 16];
            a.copy_from_slice(&pkt[24..40]);
            a
        };

        let data_end = (IPV6_HDR_LEN + ipv6_payload_len).min(payload_len);
        if data_end <= IPV6_HDR_LEN {
            return;
        }
        let data = &pkt[IPV6_HDR_LEN..data_end];

        // Cache neighbor: source IP → source MAC.
        if src_ip6 != [0; 16] {
            self.neigh_store(src_ip6, src_mac);
        }

        match next_header {
            IPPROTO_ICMPV6 => self.handle_icmpv6(&src_ip6, &dst_ip6, src_mac, data),
            IPPROTO_TCP => self.handle_tcp6_rx(&src_ip6, data),
            IPPROTO_UDP => self.handle_udp6_rx(&src_ip6, data),
            _ => {}
        }
    }

    fn handle_icmpv6(&mut self, src_ip6: &[u8; 16], _dst_ip6: &[u8; 16], src_mac: [u8; 6], data: &[u8]) {
        if data.len() < ICMPV6_HDR_LEN {
            return;
        }
        let icmp_type = data[0];
        let _icmp_code = data[1];

        match icmp_type {
            ICMPV6_ECHO_REQUEST => {
                // Reply to ping6.
                if data.len() >= 8 {
                    let id = ((data[4] as u16) << 8) | (data[5] as u16);
                    let seq = ((data[6] as u16) << 8) | (data[7] as u16);
                    let echo_data = if data.len() > 8 { &data[8..] } else { &[] };
                    self.send_echo_reply(src_ip6, src_mac, id, seq, echo_data);
                }
            }
            ICMPV6_ECHO_REPLY => {
                // Received ping reply.
                if self.ping.active {
                    syscall::send_nb(self.ping.reply_port, IP6_PING_OK, 0, 0);
                    self.ping.active = false;
                }
            }
            ICMPV6_NEIGHBOR_SOLICIT => {
                // Someone is asking for our MAC.
                if data.len() >= 24 {
                    let mut t16 = [0u8; 16];
                    t16.copy_from_slice(&data[8..24]);
                    // Match against link-local or global address.
                    if t16 == self.link_local
                        || (self.has_global && t16 == self.global_addr)
                    {
                        // If NS from :: (DAD), reply to all-nodes multicast.
                        let (na_dst, na_mac) = if *src_ip6 == [0u8; 16] {
                            let all_nodes: [u8; 16] = [0xFF,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
                            (all_nodes, [0x33,0x33,0x00,0x00,0x00,0x01])
                        } else {
                            (*src_ip6, src_mac)
                        };
                        self.send_neighbor_advert(&na_dst, na_mac, &t16);
                    }
                }
            }
            ICMPV6_NEIGHBOR_ADVERT => {
                // Learn neighbor.
                if data.len() >= 24 {
                    let target: [u8; 16] = {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(&data[8..24]);
                        a
                    };
                    // Look for target link-layer address option.
                    let mut opt_mac = src_mac;
                    let mut off = 24;
                    while off + 2 <= data.len() {
                        let otype = data[off];
                        let olen = data[off + 1] as usize * 8;
                        if olen == 0 {
                            break;
                        }
                        if otype == 2 && olen >= 8 && off + 8 <= data.len() {
                            opt_mac = [
                                data[off + 2],
                                data[off + 3],
                                data[off + 4],
                                data[off + 5],
                                data[off + 6],
                                data[off + 7],
                            ];
                        }
                        off += olen;
                    }
                    self.neigh_store(target, opt_mac);

                    // If ping was waiting for this neighbor, send echo now.
                    if self.ping.active && !self.ping.sent && self.ping.target == target {
                        let tgt = self.ping.target;
                        let seq = self.ping.seq;
                        self.send_echo_request(&tgt, opt_mac, seq);
                        self.ping.sent = true;
                    }
                }
            }
            ICMPV6_ROUTER_ADVERT => {
                // RA layout: type(1)+code(1)+cksum(2)+hop_limit(1)+flags(1)+
                //   router_lifetime(2)+reachable(4)+retrans(4) = 16 bytes header
                // then options.
                if data.len() >= 16 {
                    // Source IP of the RA is the router's link-local.
                    if !self.has_gateway {
                        self.gateway_ip6 = *src_ip6;
                        self.gateway_mac = src_mac;
                        self.has_gateway = true;
                        self.neigh_store(*src_ip6, src_mac);
                    }
                    // Parse options for Prefix Information (type=3).
                    let mut off = 16;
                    while off + 2 <= data.len() {
                        let otype = data[off];
                        let olen = data[off + 1] as usize * 8;
                        if olen == 0 { break; }
                        if otype == 3 && olen >= 32 && off + 32 <= data.len() {
                            // Prefix Information option.
                            let prefix_len = data[off + 2];
                            let flags = data[off + 3]; // L=0x80, A=0x40
                            if flags & 0x40 != 0 && prefix_len == 64 && !self.has_global {
                                // Autonomous flag set, /64 prefix → SLAAC.
                                let mut addr = [0u8; 16];
                                addr[..8].copy_from_slice(&data[off + 16..off + 24]);
                                // EUI-64 interface ID for lower 8 bytes.
                                addr[8] = self.mac[0] ^ 0x02;
                                addr[9] = self.mac[1];
                                addr[10] = self.mac[2];
                                addr[11] = 0xFF;
                                addr[12] = 0xFE;
                                addr[13] = self.mac[3];
                                addr[14] = self.mac[4];
                                addr[15] = self.mac[5];
                                self.global_addr = addr;
                                self.has_global = true;
                            }
                        }
                        off += olen;
                    }
                }
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------------
    // Ping6 handling
    // ---------------------------------------------------------------

    /// Check if target is on-link (same link-local prefix fe80::/10).
    fn is_link_local(addr: &[u8; 16]) -> bool {
        addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80
    }

    /// Resolve destination MAC for a target: neighbor cache, gateway, or broadcast.
    fn dst_mac_for(&self, target: &[u8; 16]) -> [u8; 6] {
        // 1. Check neighbor cache.
        if let Some(mac) = self.neigh_lookup(target) {
            return mac;
        }
        // 2. For non-link-local, route through gateway.
        if !Self::is_link_local(target) && self.has_gateway {
            return self.gateway_mac;
        }
        // 3. Broadcast fallback (works in QEMU SLIRP).
        [0xFF; 6]
    }

    fn start_ping6(&mut self, target: [u8; 16], reply_port: u64) {
        self.ping.target = target;
        self.ping.reply_port = reply_port;
        self.ping.seq = self.ping.seq.wrapping_add(1);
        self.ping.polls = 0;
        self.ping.active = true;
        self.ping.sent = false;

        let mac = self.dst_mac_for(&target);
        let seq = self.ping.seq;
        self.send_echo_request(&target, mac, seq);
        self.ping.sent = true;
    }

    fn tick_ping(&mut self) {
        if !self.ping.active {
            return;
        }
        self.ping.polls += 1;
        // Retransmit every 200 ticks.
        if self.ping.polls % 200 == 0 {
            let target = self.ping.target;
            let mac = self.dst_mac_for(&target);
            let seq = self.ping.seq;
            self.send_echo_request(&target, mac, seq);
        }
        if self.ping.polls > 5000 {
            syscall::send_nb(self.ping.reply_port, IP6_PING_FAIL, 0, 0);
            self.ping.active = false;
        }
    }

    // ---------------------------------------------------------------
    // TCP6: checksum
    // ---------------------------------------------------------------

    /// TCP checksum with IPv6 pseudo-header (RFC 2460 §8.1).
    fn tcp6_checksum(src: &[u8; 16], dst: &[u8; 16], tcp_data: &[u8]) -> u16 {
        let mut sum = 0u32;
        // Pseudo-header: src (16) + dst (16) + TCP length (4) + next_header (4).
        let mut i = 0;
        while i < 16 {
            sum += ((src[i] as u32) << 8) | (src[i + 1] as u32);
            i += 2;
        }
        i = 0;
        while i < 16 {
            sum += ((dst[i] as u32) << 8) | (dst[i + 1] as u32);
            i += 2;
        }
        let len = tcp_data.len() as u32;
        sum += len >> 16;
        sum += len & 0xFFFF;
        sum += IPPROTO_TCP as u32; // next header = 6
        // TCP segment data.
        i = 0;
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

    // ---------------------------------------------------------------
    // TCP6: send segments
    // ---------------------------------------------------------------

    fn build_tcp6_segment(
        &mut self,
        dst_ip: &[u8; 16],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) {
        let tcp_len = 20 + payload.len();
        let mut seg = [0u8; 1460];
        put_u16_be(&mut seg, 0, src_port);
        put_u16_be(&mut seg, 2, dst_port);
        put_u32_be(&mut seg, 4, seq);
        put_u32_be(&mut seg, 8, ack);
        seg[12] = 5 << 4; // data offset = 5 (20 bytes header)
        seg[13] = flags;
        put_u16_be(&mut seg, 14, TCP6_WINDOW);
        if !payload.is_empty() {
            seg[20..20 + payload.len()].copy_from_slice(payload);
        }
        // Compute checksum.
        let src = self.src_for(dst_ip);
        let cksum = Self::tcp6_checksum(&src, dst_ip, &seg[..tcp_len]);
        seg[16] = (cksum >> 8) as u8;
        seg[17] = cksum as u8;

        let mac = self.dst_mac_for(dst_ip);
        self.send_ipv6(dst_ip, IPPROTO_TCP, &seg[..tcp_len], mac, 64);
    }

    fn send_tcp6_for_conn(&mut self, idx: usize, flags: u8, payload: &[u8]) {
        let dst_ip = self.tcp6[idx].remote_ip;
        let src_port = self.tcp6[idx].local_port;
        let dst_port = self.tcp6[idx].remote_port;
        let seq = self.tcp6[idx].snd_nxt;
        let ack = self.tcp6[idx].rcv_nxt;
        self.build_tcp6_segment(&dst_ip, src_port, dst_port, seq, ack, flags, payload);
    }

    // ---------------------------------------------------------------
    // TCP6: connect (active open)
    // ---------------------------------------------------------------

    fn handle_tcp6_connect(&mut self, dst_ip: [u8; 16], dst_port: u16, reply_port: u64) {
        // Loopback: if connecting to our own address, short-circuit.
        let is_loopback = dst_ip == self.link_local
            || (self.has_global && dst_ip == self.global_addr);

        if is_loopback {
            self.handle_tcp6_connect_loopback(dst_ip, dst_port, reply_port);
            return;
        }

        let slot = self.tcp6.iter().position(|c| c.state == TCP_ST_CLOSED);
        let slot = match slot {
            Some(s) => s,
            None => {
                syscall::send_nb(reply_port, TCP6_FAIL, 1, 0);
                return;
            }
        };
        let local_port = self.tcp6_next_port;
        self.tcp6_next_port = self.tcp6_next_port.wrapping_add(1);
        if self.tcp6_next_port < 49152 {
            self.tcp6_next_port = 49152;
        }

        let isn = self.tcp6_isn;
        self.tcp6_isn = self.tcp6_isn.wrapping_add(64000);

        self.tcp6[slot] = TcpConn6 {
            state: TCP_ST_SYN_SENT,
            local_port,
            remote_ip: dst_ip,
            remote_port: dst_port,
            snd_nxt: isn,
            snd_una: isn,
            rcv_nxt: 0,
            reply_port,
            recv_reply_port: 0,
            rx_buf: [0; TCP6_RX_BUF_SIZE],
            rx_head: 0,
            rx_tail: 0,
            timeout: 0,
        };

        // Send SYN.
        self.build_tcp6_segment(&dst_ip, local_port, dst_port, isn, 0, TCP_SYN, &[]);
    }

    /// Loopback connect: create both client and server connections internally.
    fn handle_tcp6_connect_loopback(&mut self, dst_ip: [u8; 16], dst_port: u16, reply_port: u64) {
        // Check listen slot.
        let listen_idx = self.listen6.iter().position(|l| l.active && l.port == dst_port);
        if listen_idx.is_none() {
            syscall::send_nb(reply_port, TCP6_FAIL, 2, 0);
            return;
        }
        let listen_idx = listen_idx.unwrap();

        // Need two free connection slots.
        let client_slot = self.tcp6.iter().position(|c| c.state == TCP_ST_CLOSED);
        let client_slot = match client_slot {
            Some(s) => s,
            None => {
                syscall::send_nb(reply_port, TCP6_FAIL, 1, 0);
                return;
            }
        };
        // Find second free slot, skipping client_slot.
        let server_slot = self.tcp6.iter().enumerate().position(|(i, c)| {
            i != client_slot && c.state == TCP_ST_CLOSED
        });
        let server_slot = match server_slot {
            Some(s) => s,
            None => {
                syscall::send_nb(reply_port, TCP6_FAIL, 1, 0);
                return;
            }
        };

        let local_port = self.tcp6_next_port;
        self.tcp6_next_port = self.tcp6_next_port.wrapping_add(1);
        if self.tcp6_next_port < 49152 {
            self.tcp6_next_port = 49152;
        }

        let isn_c = self.tcp6_isn;
        self.tcp6_isn = self.tcp6_isn.wrapping_add(64000);
        let isn_s = self.tcp6_isn;
        self.tcp6_isn = self.tcp6_isn.wrapping_add(64000);

        // Client connection (active open).
        self.tcp6[client_slot] = TcpConn6 {
            state: TCP_ST_ESTABLISHED,
            local_port,
            remote_ip: dst_ip,
            remote_port: dst_port,
            snd_nxt: isn_c.wrapping_add(1),
            snd_una: isn_c.wrapping_add(1),
            rcv_nxt: isn_s.wrapping_add(1),
            reply_port: 0,
            recv_reply_port: 0,
            rx_buf: [0; TCP6_RX_BUF_SIZE],
            rx_head: 0,
            rx_tail: 0,
            timeout: 0,
        };

        // Server connection (passive open).
        self.tcp6[server_slot] = TcpConn6 {
            state: TCP_ST_ESTABLISHED,
            local_port: dst_port,
            remote_ip: dst_ip,
            remote_port: local_port,
            snd_nxt: isn_s.wrapping_add(1),
            snd_una: isn_s.wrapping_add(1),
            rcv_nxt: isn_c.wrapping_add(1),
            reply_port: 0,
            recv_reply_port: 0,
            rx_buf: [0; TCP6_RX_BUF_SIZE],
            rx_head: 0,
            rx_tail: 0,
            timeout: 0,
        };

        // Reply CONNECTED with client slot.
        syscall::send_nb(reply_port, TCP6_CONNECTED, client_slot as u64, 0);

        // Wire up pending accept if any.
        let accept_rp = self.listen6[listen_idx].accept_reply_port;
        if accept_rp != 0 {
            self.listen6[listen_idx].accept_reply_port = 0;
            syscall::send_nb(accept_rp, TCP6_ACCEPT_OK, server_slot as u64, 0);
        }
    }

    // ---------------------------------------------------------------
    // TCP6: RX state machine
    // ---------------------------------------------------------------

    fn handle_tcp6_rx(&mut self, src_ip: &[u8; 16], tcp_data: &[u8]) {
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
        let idx = self.tcp6.iter().position(|c| {
            c.state != TCP_ST_CLOSED
                && c.local_port == dst_port
                && c.remote_port == src_port
                && c.remote_ip == *src_ip
        });
        let idx = match idx {
            Some(i) => i,
            None => {
                if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 {
                    self.handle_incoming_syn6(*src_ip, src_port, dst_port, seq);
                }
                return;
            }
        };

        if flags & TCP_RST != 0 {
            let reply_port = self.tcp6[idx].reply_port;
            self.tcp6[idx].state = TCP_ST_CLOSED;
            syscall::send_nb(reply_port, TCP6_FAIL, 2, 0);
            return;
        }

        match self.tcp6[idx].state {
            TCP_ST_SYN_SENT => {
                if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 {
                    if ack != self.tcp6[idx].snd_nxt.wrapping_add(1) {
                        return;
                    }
                    self.tcp6[idx].snd_una = ack;
                    self.tcp6[idx].snd_nxt = ack;
                    self.tcp6[idx].rcv_nxt = seq.wrapping_add(1);
                    self.tcp6[idx].state = TCP_ST_ESTABLISHED;
                    self.tcp6[idx].timeout = 0;
                    self.send_tcp6_for_conn(idx, TCP_ACK, &[]);
                    let reply_port = self.tcp6[idx].reply_port;
                    syscall::send_nb(reply_port, TCP6_CONNECTED, idx as u64, 0);
                }
            }
            TCP_ST_SYN_RECEIVED => {
                if flags & TCP_ACK != 0 {
                    self.tcp6[idx].snd_una = ack;
                    self.tcp6[idx].state = TCP_ST_ESTABLISHED;
                    self.tcp6[idx].timeout = 0;
                    let reply_port = self.tcp6[idx].reply_port;
                    if reply_port != 0 {
                        self.tcp6[idx].reply_port = 0;
                        syscall::send_nb(reply_port, TCP6_ACCEPT_OK, idx as u64, 0);
                    }
                }
            }
            TCP_ST_ESTABLISHED => {
                if flags & TCP_ACK != 0 {
                    self.tcp6[idx].snd_una = ack;
                }
                if !payload.is_empty() && seq == self.tcp6[idx].rcv_nxt {
                    self.tcp6[idx].rcv_nxt = seq.wrapping_add(payload.len() as u32);
                    self.tcp6[idx].rx_push(payload);
                    self.send_tcp6_for_conn(idx, TCP_ACK, &[]);
                    if self.tcp6[idx].recv_reply_port != 0 {
                        self.tcp6_deliver_pending = true;
                    }
                }
                if flags & TCP_FIN != 0 {
                    self.tcp6[idx].rcv_nxt = self.tcp6[idx].rcv_nxt.wrapping_add(1);
                    self.send_tcp6_for_conn(idx, TCP_ACK, &[]);
                    self.tcp6[idx].state = TCP_ST_CLOSE_WAIT;
                }
            }
            TCP_ST_FIN_WAIT_1 => {
                if flags & TCP_ACK != 0 {
                    self.tcp6[idx].snd_una = ack;
                    if flags & TCP_FIN != 0 {
                        self.tcp6[idx].rcv_nxt = seq.wrapping_add(1);
                        self.send_tcp6_for_conn(idx, TCP_ACK, &[]);
                        self.tcp6[idx].state = TCP_ST_TIME_WAIT;
                        self.tcp6[idx].timeout = 0;
                    } else {
                        self.tcp6[idx].state = TCP_ST_FIN_WAIT_2;
                    }
                }
            }
            TCP_ST_FIN_WAIT_2 => {
                if flags & TCP_FIN != 0 {
                    self.tcp6[idx].rcv_nxt = seq.wrapping_add(1);
                    self.send_tcp6_for_conn(idx, TCP_ACK, &[]);
                    self.tcp6[idx].state = TCP_ST_TIME_WAIT;
                    self.tcp6[idx].timeout = 0;
                }
            }
            TCP_ST_LAST_ACK => {
                if flags & TCP_ACK != 0 {
                    self.tcp6[idx].state = TCP_ST_CLOSED;
                    let reply_port = self.tcp6[idx].reply_port;
                    syscall::send_nb(reply_port, TCP6_CLOSE_OK, idx as u64, 0);
                }
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------------
    // TCP6: passive open (listen/accept)
    // ---------------------------------------------------------------

    fn handle_incoming_syn6(&mut self, src_ip: [u8; 16], src_port: u16, dst_port: u16, seq: u32) {
        let listen_idx = self.listen6.iter().position(|l| l.active && l.port == dst_port);
        if listen_idx.is_none() {
            return;
        }
        let listen_idx = listen_idx.unwrap();

        let slot = self.tcp6.iter().position(|c| c.state == TCP_ST_CLOSED);
        let slot = match slot {
            Some(s) => s,
            None => return,
        };

        let isn = self.tcp6_isn;
        self.tcp6_isn = self.tcp6_isn.wrapping_add(64000);

        self.tcp6[slot] = TcpConn6 {
            state: TCP_ST_SYN_RECEIVED,
            local_port: dst_port,
            remote_ip: src_ip,
            remote_port: src_port,
            snd_nxt: isn.wrapping_add(1),
            snd_una: isn,
            rcv_nxt: seq.wrapping_add(1),
            reply_port: 0,
            recv_reply_port: 0,
            rx_buf: [0; TCP6_RX_BUF_SIZE],
            rx_head: 0,
            rx_tail: 0,
            timeout: 0,
        };

        // Send SYN-ACK.
        self.build_tcp6_segment(&src_ip, dst_port, src_port, isn, seq.wrapping_add(1), TCP_SYN | TCP_ACK, &[]);

        // Wire up pending accept.
        let accept_rp = self.listen6[listen_idx].accept_reply_port;
        if accept_rp != 0 {
            self.listen6[listen_idx].accept_reply_port = 0;
            self.tcp6[slot].reply_port = accept_rp;
        }
    }

    // ---------------------------------------------------------------
    // TCP6: data delivery
    // ---------------------------------------------------------------

    fn deliver_tcp6_data(&mut self, idx: usize, reply_port: u64) {
        let mut buf = [0u8; 24];
        let n = self.tcp6[idx].rx_pop(&mut buf);
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
        syscall::send_nb_4(reply_port, TCP6_DATA, n as u64, d1, d2, d3);
    }

    fn handle_tcp6_send(&mut self, conn_id: usize, payload: &[u8], reply_port: u64) {
        if conn_id >= MAX_TCP6_CONNS || self.tcp6[conn_id].state != TCP_ST_ESTABLISHED {
            syscall::send_nb(reply_port, TCP6_FAIL, 0, 0);
            return;
        }

        // Check for loopback peer: find the matching reverse connection.
        let remote_ip = self.tcp6[conn_id].remote_ip;
        let is_loopback = remote_ip == self.link_local
            || (self.has_global && remote_ip == self.global_addr);

        if is_loopback {
            // Find peer connection (reverse direction).
            let local_port = self.tcp6[conn_id].local_port;
            let remote_port = self.tcp6[conn_id].remote_port;
            let peer = self.tcp6.iter().enumerate().position(|(i, c)| {
                i != conn_id
                    && c.state == TCP_ST_ESTABLISHED
                    && c.local_port == remote_port
                    && c.remote_port == local_port
                    && c.remote_ip == remote_ip
            });
            if let Some(peer_idx) = peer {
                self.tcp6[peer_idx].rx_push(payload);
                self.tcp6[peer_idx].rcv_nxt = self.tcp6[peer_idx].rcv_nxt.wrapping_add(payload.len() as u32);
                if self.tcp6[peer_idx].recv_reply_port != 0 {
                    self.tcp6_deliver_pending = true;
                }
            }
            self.tcp6[conn_id].snd_nxt = self.tcp6[conn_id].snd_nxt.wrapping_add(payload.len() as u32);
            syscall::send_nb(reply_port, TCP6_SEND_OK, conn_id as u64, 0);
        } else {
            self.send_tcp6_for_conn(conn_id, TCP_ACK | TCP_PSH, payload);
            self.tcp6[conn_id].snd_nxt = self.tcp6[conn_id].snd_nxt.wrapping_add(payload.len() as u32);
            syscall::send_nb(reply_port, TCP6_SEND_OK, conn_id as u64, 0);
        }
    }

    fn handle_tcp6_recv(&mut self, conn_id: usize, reply_port: u64) {
        if conn_id >= MAX_TCP6_CONNS || self.tcp6[conn_id].state == TCP_ST_CLOSED {
            syscall::send_nb(reply_port, TCP6_FAIL, 0, 0);
            return;
        }
        if self.tcp6[conn_id].state == TCP_ST_ESTABLISHED || self.tcp6[conn_id].rx_len() > 0 {
            self.tcp6[conn_id].recv_reply_port = reply_port;
            if self.tcp6[conn_id].rx_len() > 0 {
                self.tcp6_deliver_pending = true;
            }
        } else {
            syscall::send_nb(reply_port, TCP6_CLOSED, conn_id as u64, 0);
        }
    }

    fn handle_tcp6_close(&mut self, conn_id: usize, reply_port: u64) {
        if conn_id >= MAX_TCP6_CONNS {
            syscall::send_nb(reply_port, TCP6_FAIL, 0, 0);
            return;
        }
        self.tcp6[conn_id].reply_port = reply_port;
        match self.tcp6[conn_id].state {
            TCP_ST_ESTABLISHED => {
                self.send_tcp6_for_conn(conn_id, TCP_FIN | TCP_ACK, &[]);
                self.tcp6[conn_id].snd_nxt = self.tcp6[conn_id].snd_nxt.wrapping_add(1);
                self.tcp6[conn_id].state = TCP_ST_FIN_WAIT_1;
                self.tcp6[conn_id].timeout = 0;
            }
            TCP_ST_CLOSE_WAIT => {
                self.send_tcp6_for_conn(conn_id, TCP_FIN | TCP_ACK, &[]);
                self.tcp6[conn_id].snd_nxt = self.tcp6[conn_id].snd_nxt.wrapping_add(1);
                self.tcp6[conn_id].state = TCP_ST_LAST_ACK;
                self.tcp6[conn_id].timeout = 0;
            }
            _ => {
                self.tcp6[conn_id].state = TCP_ST_CLOSED;
                syscall::send_nb(reply_port, TCP6_CLOSE_OK, conn_id as u64, 0);
            }
        }
    }

    // ---------------------------------------------------------------
    // TCP6: bind/listen/accept
    // ---------------------------------------------------------------

    fn handle_tcp6_bind(&self, _port: u16, reply_port: u64) {
        syscall::send_nb(reply_port, TCP6_BIND_OK, 0, 0);
    }

    fn handle_tcp6_listen(&mut self, port: u16, reply_port: u64) {
        let slot = self.listen6.iter().position(|l| !l.active);
        match slot {
            Some(s) => {
                self.listen6[s] = ListenSlot6 {
                    active: true,
                    port,
                    accept_reply_port: 0,
                };
                syscall::send_nb(reply_port, TCP6_LISTEN_OK, port as u64, 0);
            }
            None => {
                syscall::send_nb(reply_port, TCP6_LISTEN_FAIL, 0, 0);
            }
        }
    }

    fn handle_tcp6_accept(&mut self, port: u16, reply_port: u64) {
        // Check for already-established connections on this port.
        for i in 0..MAX_TCP6_CONNS {
            if (self.tcp6[i].state == TCP_ST_ESTABLISHED || self.tcp6[i].state == TCP_ST_SYN_RECEIVED)
                && self.tcp6[i].local_port == port
            {
                if self.tcp6[i].state == TCP_ST_ESTABLISHED {
                    syscall::send_nb(reply_port, TCP6_ACCEPT_OK, i as u64, 0);
                    return;
                }
                self.tcp6[i].reply_port = reply_port;
                return;
            }
        }
        // Defer in listen slot.
        for l in self.listen6.iter_mut() {
            if l.active && l.port == port {
                l.accept_reply_port = reply_port;
                return;
            }
        }
        syscall::send_nb(reply_port, TCP6_ACCEPT_FAIL, 0, 0);
    }

    // ---------------------------------------------------------------
    // TCP6: timeouts
    // ---------------------------------------------------------------

    fn tick_tcp6(&mut self) {
        for i in 0..MAX_TCP6_CONNS {
            match self.tcp6[i].state {
                TCP_ST_SYN_SENT => {
                    self.tcp6[i].timeout += 1;
                    if self.tcp6[i].timeout % 500 == 0 && self.tcp6[i].timeout < TCP6_TIMEOUT {
                        let dst_ip = self.tcp6[i].remote_ip;
                        let src_port = self.tcp6[i].local_port;
                        let dst_port = self.tcp6[i].remote_port;
                        let seq = self.tcp6[i].snd_una;
                        self.build_tcp6_segment(&dst_ip, src_port, dst_port, seq, 0, TCP_SYN, &[]);
                    }
                    if self.tcp6[i].timeout >= TCP6_TIMEOUT {
                        let reply_port = self.tcp6[i].reply_port;
                        self.tcp6[i].state = TCP_ST_CLOSED;
                        syscall::send_nb(reply_port, TCP6_FAIL, 3, 0);
                    }
                }
                TCP_ST_SYN_RECEIVED => {
                    self.tcp6[i].timeout += 1;
                    if self.tcp6[i].timeout >= TCP6_TIMEOUT {
                        self.tcp6[i].state = TCP_ST_CLOSED;
                    }
                }
                TCP_ST_FIN_WAIT_1 | TCP_ST_FIN_WAIT_2 | TCP_ST_LAST_ACK => {
                    self.tcp6[i].timeout += 1;
                    if self.tcp6[i].timeout >= TCP6_TIMEOUT {
                        let reply_port = self.tcp6[i].reply_port;
                        self.tcp6[i].state = TCP_ST_CLOSED;
                        syscall::send_nb(reply_port, TCP6_CLOSE_OK, i as u64, 0);
                    }
                }
                TCP_ST_TIME_WAIT => {
                    self.tcp6[i].timeout += 1;
                    if self.tcp6[i].timeout >= TCP6_TIME_WAIT_TIMEOUT {
                        let reply_port = self.tcp6[i].reply_port;
                        self.tcp6[i].state = TCP_ST_CLOSED;
                        syscall::send_nb(reply_port, TCP6_CLOSE_OK, i as u64, 0);
                    }
                }
                _ => {}
            }
        }
    }

    fn deliver_pending_tcp6_recvs(&mut self) {
        for i in 0..MAX_TCP6_CONNS {
            let recv_port = self.tcp6[i].recv_reply_port;
            if recv_port == 0 {
                continue;
            }
            if self.tcp6[i].rx_len() > 0 {
                self.tcp6[i].recv_reply_port = 0;
                self.deliver_tcp6_data(i, recv_port);
            } else if self.tcp6[i].state != TCP_ST_ESTABLISHED {
                self.tcp6[i].recv_reply_port = 0;
                syscall::send_nb(recv_port, TCP6_CLOSED, i as u64, 0);
            }
        }
    }

    // ---------------------------------------------------------------
    // UDP6: receive from network
    // ---------------------------------------------------------------

    fn handle_udp6_rx(&mut self, src_ip: &[u8; 16], udp_data: &[u8]) {
        // UDP header: src_port(2) + dst_port(2) + length(2) + checksum(2) = 8 bytes
        if udp_data.len() < 8 {
            return;
        }
        let src_port = get_u16_be(udp_data, 0);
        let dst_port = get_u16_be(udp_data, 2);
        let udp_len = get_u16_be(udp_data, 4) as usize;
        let payload = if udp_len > 8 && udp_len <= udp_data.len() {
            &udp_data[8..udp_len]
        } else if udp_data.len() > 8 {
            &udp_data[8..]
        } else {
            return;
        };

        // Find matching binding.
        let idx = self.udp6.iter().position(|b| b.active && b.local_port == dst_port);
        let idx = match idx {
            Some(i) => i,
            None => return, // No binding, drop silently.
        };

        // If there's a pending recv, deliver immediately.
        let recv_rp = self.udp6[idx].recv_reply_port;
        if recv_rp != 0 {
            self.udp6[idx].recv_reply_port = 0;
            self.deliver_udp6_datagram(recv_rp, src_ip, src_port, payload);
        } else {
            // Queue in binding buffer (one datagram deep; drop if full).
            let copy_len = payload.len().min(UDP6_RX_BUF_SIZE);
            self.udp6[idx].rx_buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            self.udp6[idx].rx_len = copy_len;
            self.udp6[idx].rx_src_ip = *src_ip;
            self.udp6[idx].rx_src_port = src_port;
        }
    }

    /// Deliver a UDP datagram to a waiting receiver.
    /// Format: tag=UDP6_DATA, data[0]=payload_len | (src_port << 16),
    ///         data[1..2]=src_ip6 (16 bytes), data[3]=payload (up to 8 bytes inline).
    fn deliver_udp6_datagram(&self, reply_port: u64, src_ip: &[u8; 16], src_port: u16, payload: &[u8]) {
        let plen = payload.len().min(8); // inline payload limit per message
        let d0 = (plen as u64) | ((src_port as u64) << 16);
        // Pack source IP into d1, d2.
        let mut d1 = 0u64;
        let mut d2 = 0u64;
        for i in 0..8 { d1 |= (src_ip[i] as u64) << (i * 8); }
        for i in 0..8 { d2 |= (src_ip[8 + i] as u64) << (i * 8); }
        // Pack payload into d3.
        let mut d3 = 0u64;
        for i in 0..plen { d3 |= (payload[i] as u64) << (i * 8); }
        syscall::send_nb_4(reply_port, UDP6_DATA, d0, d1, d2, d3);
    }

    // ---------------------------------------------------------------
    // UDP6: send datagram
    // ---------------------------------------------------------------

    fn handle_udp6_send(
        &mut self,
        dst_ip: &[u8; 16],
        dst_port: u16,
        src_port: u16,
        payload: &[u8],
        reply_port: u64,
    ) {
        // Loopback: if destination is our own address, deliver directly.
        let is_loopback = *dst_ip == self.link_local
            || (self.has_global && *dst_ip == self.global_addr);
        if is_loopback {
            let src = self.src_for(dst_ip);
            // Find matching binding for dst_port and deliver.
            if let Some(idx) = self.udp6.iter().position(|b| b.active && b.local_port == dst_port) {
                let recv_rp = self.udp6[idx].recv_reply_port;
                if recv_rp != 0 {
                    self.udp6[idx].recv_reply_port = 0;
                    self.deliver_udp6_datagram(recv_rp, &src, src_port, payload);
                } else {
                    let copy_len = payload.len().min(UDP6_RX_BUF_SIZE);
                    self.udp6[idx].rx_buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                    self.udp6[idx].rx_len = copy_len;
                    self.udp6[idx].rx_src_ip = src;
                    self.udp6[idx].rx_src_port = src_port;
                }
            }
            syscall::send_nb(reply_port, UDP6_SEND_OK, 0, 0);
            return;
        }

        // Build UDP datagram: header(8) + payload.
        let udp_len = 8 + payload.len();
        if udp_len > MAX_IPV6_PAYLOAD {
            syscall::send_nb(reply_port, UDP6_SEND_FAIL, 0, 0);
            return;
        }
        let mut dgram = [0u8; 1460];
        put_u16_be(&mut dgram, 0, src_port);
        put_u16_be(&mut dgram, 2, dst_port);
        put_u16_be(&mut dgram, 4, udp_len as u16);
        // Checksum at [6..8] — compute with pseudo-header.
        dgram[6] = 0;
        dgram[7] = 0;
        if !payload.is_empty() {
            dgram[8..8 + payload.len()].copy_from_slice(payload);
        }
        let src = self.src_for(dst_ip);
        let cksum = Self::udp6_checksum(&src, dst_ip, &dgram[..udp_len]);
        dgram[6] = (cksum >> 8) as u8;
        dgram[7] = cksum as u8;

        let mac = self.dst_mac_for(dst_ip);
        self.send_ipv6(dst_ip, IPPROTO_UDP, &dgram[..udp_len], mac, 64);
        syscall::send_nb(reply_port, UDP6_SEND_OK, 0, 0);
    }

    /// UDP checksum with IPv6 pseudo-header (mandatory for UDP over IPv6).
    fn udp6_checksum(src: &[u8; 16], dst: &[u8; 16], udp_data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i < 16 {
            sum += ((src[i] as u32) << 8) | (src[i + 1] as u32);
            i += 2;
        }
        i = 0;
        while i < 16 {
            sum += ((dst[i] as u32) << 8) | (dst[i + 1] as u32);
            i += 2;
        }
        let len = udp_data.len() as u32;
        sum += len >> 16;
        sum += len & 0xFFFF;
        sum += IPPROTO_UDP as u32;
        i = 0;
        while i + 1 < udp_data.len() {
            sum += ((udp_data[i] as u32) << 8) | (udp_data[i + 1] as u32);
            i += 2;
        }
        if i < udp_data.len() {
            sum += (udp_data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let result = !(sum as u16);
        // RFC 2460: UDP checksum of 0 must be transmitted as 0xFFFF.
        if result == 0 { 0xFFFF } else { result }
    }

    // ---------------------------------------------------------------
    // UDP6: bind / recv / close
    // ---------------------------------------------------------------

    fn handle_udp6_bind(&mut self, port: u16, reply_port: u64) {
        // Check for duplicate binding.
        if self.udp6.iter().any(|b| b.active && b.local_port == port) {
            syscall::send_nb(reply_port, UDP6_BIND_FAIL, 0, 0);
            return;
        }
        let slot = self.udp6.iter().position(|b| !b.active);
        match slot {
            Some(s) => {
                self.udp6[s] = Udp6Binding {
                    active: true,
                    local_port: port,
                    recv_reply_port: 0,
                    rx_buf: [0; UDP6_RX_BUF_SIZE],
                    rx_len: 0,
                    rx_src_ip: [0; 16],
                    rx_src_port: 0,
                };
                syscall::send_nb(reply_port, UDP6_BIND_OK, s as u64, 0);
            }
            None => {
                syscall::send_nb(reply_port, UDP6_BIND_FAIL, 0, 0);
            }
        }
    }

    fn handle_udp6_recv(&mut self, bind_id: usize, reply_port: u64) {
        if bind_id >= MAX_UDP6_BINDS || !self.udp6[bind_id].active {
            syscall::send_nb(reply_port, UDP6_RECV_NONE, 0, 0);
            return;
        }
        // If we have a queued datagram, deliver immediately.
        if self.udp6[bind_id].rx_len > 0 {
            let src_ip = self.udp6[bind_id].rx_src_ip;
            let src_port = self.udp6[bind_id].rx_src_port;
            let len = self.udp6[bind_id].rx_len;
            let mut payload = [0u8; UDP6_RX_BUF_SIZE];
            payload[..len].copy_from_slice(&self.udp6[bind_id].rx_buf[..len]);
            self.udp6[bind_id].rx_len = 0;
            self.deliver_udp6_datagram(reply_port, &src_ip, src_port, &payload[..len]);
        } else {
            // Park the recv — will be delivered when datagram arrives.
            self.udp6[bind_id].recv_reply_port = reply_port;
        }
    }

    fn handle_udp6_recv_nb(&mut self, bind_id: usize, reply_port: u64) {
        if bind_id >= MAX_UDP6_BINDS || !self.udp6[bind_id].active {
            syscall::send_nb(reply_port, UDP6_RECV_NONE, 0, 0);
            return;
        }
        if self.udp6[bind_id].rx_len > 0 {
            let src_ip = self.udp6[bind_id].rx_src_ip;
            let src_port = self.udp6[bind_id].rx_src_port;
            let len = self.udp6[bind_id].rx_len;
            let mut payload = [0u8; UDP6_RX_BUF_SIZE];
            payload[..len].copy_from_slice(&self.udp6[bind_id].rx_buf[..len]);
            self.udp6[bind_id].rx_len = 0;
            self.deliver_udp6_datagram(reply_port, &src_ip, src_port, &payload[..len]);
        } else {
            syscall::send_nb(reply_port, UDP6_RECV_NONE, 0, 0);
        }
    }

    fn handle_udp6_close(&mut self, bind_id: usize, reply_port: u64) {
        if bind_id < MAX_UDP6_BINDS && self.udp6[bind_id].active {
            self.udp6[bind_id].active = false;
            // Wake any parked recv with close notification.
            let rp = self.udp6[bind_id].recv_reply_port;
            if rp != 0 {
                syscall::send_nb(rp, UDP6_RECV_NONE, 0, 0);
                self.udp6[bind_id].recv_reply_port = 0;
            }
        }
        syscall::send_nb(reply_port, UDP6_CLOSE_OK, bind_id as u64, 0);
    }
}

// --- Helpers ---

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

/// Build a link-local IPv6 address from a MAC using EUI-64.
/// fe80::xxxx:xxff:fexx:xxxx with the U/L bit flipped.
fn eui64_link_local(mac: [u8; 6]) -> [u8; 16] {
    let mut addr = [0u8; 16];
    addr[0] = 0xFE;
    addr[1] = 0x80;
    // bytes 2-7 = 0
    addr[8] = mac[0] ^ 0x02; // flip U/L bit
    addr[9] = mac[1];
    addr[10] = mac[2];
    addr[11] = 0xFF;
    addr[12] = 0xFE;
    addr[13] = mac[3];
    addr[14] = mac[4];
    addr[15] = mac[5];
    addr
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

// ---------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [ip6_srv] starting\n");

    // Wait for eth_srv to register.
    let eth_port = match syscall::ns_lookup_wait(b"eth") {
        Some(p) => p,
        None => {
            syscall::debug_puts(b"  [ip6_srv] eth service not found\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };


    // Query link status to get our MAC address.
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


    // Create our IPC port.
    let my_port = syscall::port_create();

    // Allocate local RX and TX pages for grant-based frame exchange.
    let rx_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [ip6_srv] mmap rx failed\n");
            loop { core::hint::spin_loop(); }
        }
    };
    let tx_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [ip6_srv] mmap tx failed\n");
            loop { core::hint::spin_loop(); }
        }
    };

    // Register with eth_srv for IPv6 frames (ethertype 0x86DD).
    let reg_reply = syscall::port_create();
    syscall::send_nb_4(
        eth_port,
        NETIF_REGISTER,
        ETHERTYPE_IPV6 as u64, // data[0] = ethertype
        my_port,                // data[1] = our notification port
        reg_reply,              // data[2] = reply port
        0,
    );

    let client_id = if let Some(msg) = syscall::recv_msg_timeout(reg_reply, 2_000_000) {
        if msg.tag == NETIF_REGISTER_OK {
            let cid = msg.data[0];
            let eth_rx_va = msg.data[1] as usize; // VA in eth_srv's aspace for RX page
            let eth_tx_va = msg.data[2] as usize; // VA in eth_srv's aspace for TX page

            // Grant our RX page to eth_srv (eth_srv writes incoming frames here).
            if !syscall::grant_pages(eth_port, rx_va, eth_rx_va, 1, false) {
                syscall::debug_puts(b"  [ip6_srv] grant rx failed\n");
            }
            // Grant our TX page to eth_srv (we write outgoing frames here, eth_srv reads).
            if !syscall::grant_pages(eth_port, tx_va, eth_tx_va, 1, false) {
                syscall::debug_puts(b"  [ip6_srv] grant tx failed\n");
            }
            cid
        } else {
            syscall::debug_puts(b"  [ip6_srv] register failed\n");
            loop { core::hint::spin_loop(); }
        }
    } else {
        syscall::debug_puts(b"  [ip6_srv] register timeout\n");
        loop { core::hint::spin_loop(); }
    };
    syscall::port_destroy(reg_reply);

    let mut dev = Ip6Dev::new(eth_port, my_port, client_id, mac, rx_va, tx_va);

    // Register with name server.
    syscall::ns_register(b"ip6", my_port);
    syscall::debug_puts(b"  [ip6_srv] ready\n");

    // Send Router Solicitation to discover default gateway.
    dev.send_router_solicit();

    // Poll-based server loop.
    let mut tick: u64 = 0;
    loop {
        // 1. Drain all queued IPC messages.
        while let Some(msg) = syscall::recv_nb_msg(my_port) {
            match msg.tag {
                NETIF_INPUT => {
                    let payload_len = msg.data[0] as usize;
                    let src_mac = u64_to_mac(msg.data[1]);
                    dev.handle_input(payload_len, src_mac);
                }
                IP6_PING => {
                    let reply_port = msg.data[2];
                    let mut target = [0u8; 16];
                    let d0 = msg.data[0];
                    let d1 = msg.data[1];
                    for i in 0..8 {
                        target[i] = (d0 >> (i * 8)) as u8;
                    }
                    for i in 0..8 {
                        target[8 + i] = (d1 >> (i * 8)) as u8;
                    }
                    dev.start_ping6(target, reply_port);
                }
                IP6_STATUS => {
                    let reply_port = msg.data[0];
                    let mut a0 = 0u64;
                    let mut a1 = 0u64;
                    for i in 0..8 {
                        a0 |= (dev.link_local[i] as u64) << (i * 8);
                    }
                    for i in 0..8 {
                        a1 |= (dev.link_local[8 + i] as u64) << (i * 8);
                    }
                    syscall::send_nb_4(reply_port, IP6_STATUS_OK, a0, a1, mac_to_u64(dev.mac), 0);
                }
                IP6_GATEWAY => {
                    let reply_port = msg.data[0];
                    if dev.has_gateway {
                        let mut g0 = 0u64;
                        let mut g1 = 0u64;
                        for i in 0..8 {
                            g0 |= (dev.gateway_ip6[i] as u64) << (i * 8);
                        }
                        for i in 0..8 {
                            g1 |= (dev.gateway_ip6[8 + i] as u64) << (i * 8);
                        }
                        syscall::send_nb_4(reply_port, IP6_GATEWAY_OK, g0, g1, mac_to_u64(dev.gateway_mac), 0);
                    } else {
                        syscall::send_nb(reply_port, IP6_GATEWAY_NONE, 0, 0);
                    }
                }
                // --- TCP6 IPC ---
                TCP6_CONNECT => {
                    // data[0..1] = dest IPv6 (16 bytes in 2 u64s)
                    // data[2] = dst_port(low16) | reply_port(high48)
                    let mut dst = [0u8; 16];
                    let d0 = msg.data[0];
                    let d1 = msg.data[1];
                    for i in 0..8 { dst[i] = (d0 >> (i * 8)) as u8; }
                    for i in 0..8 { dst[8 + i] = (d1 >> (i * 8)) as u8; }
                    let dst_port = msg.data[2] as u16;
                    let reply_port = msg.data[2] >> 16;
                    dev.handle_tcp6_connect(dst, dst_port, reply_port);
                }
                TCP6_SEND => {
                    let conn_id = msg.data[0] as usize;
                    let len = (msg.data[1] & 0xFFFF) as usize;
                    let reply_port = msg.data[1] >> 16;
                    let mut payload = [0u8; 16];
                    let d2 = msg.data[2];
                    let d3 = msg.data[3];
                    for i in 0..8 { payload[i] = (d2 >> (i * 8)) as u8; }
                    for i in 0..8 { payload[8 + i] = (d3 >> (i * 8)) as u8; }
                    dev.handle_tcp6_send(conn_id, &payload[..len.min(16)], reply_port);
                }
                TCP6_RECV => {
                    let conn_id = msg.data[0] as usize;
                    let reply_port = msg.data[1] >> 16;
                    dev.handle_tcp6_recv(conn_id, reply_port);
                }
                TCP6_RECV_NB => {
                    let conn_id = msg.data[0] as usize;
                    let reply_port = msg.data[1] >> 16;
                    if conn_id >= MAX_TCP6_CONNS || dev.tcp6[conn_id].state == TCP_ST_CLOSED {
                        syscall::send_nb(reply_port, TCP6_FAIL, 0, 0);
                    } else if dev.tcp6[conn_id].rx_len() > 0 {
                        dev.deliver_tcp6_data(conn_id, reply_port);
                    } else if dev.tcp6[conn_id].state != TCP_ST_ESTABLISHED {
                        syscall::send_nb(reply_port, TCP6_CLOSED, conn_id as u64, 0);
                    } else {
                        syscall::send_nb(reply_port, TCP6_RECV_NONE, 0, 0);
                    }
                }
                TCP6_CLOSE => {
                    let conn_id = msg.data[0] as usize;
                    let reply_port = msg.data[1];
                    dev.handle_tcp6_close(conn_id, reply_port);
                }
                TCP6_BIND => {
                    let port_num = msg.data[0] as u16;
                    let reply_port = msg.data[1] >> 32;
                    dev.handle_tcp6_bind(port_num, reply_port);
                }
                TCP6_LISTEN => {
                    let port_num = msg.data[0] as u16;
                    let reply_port = msg.data[2] >> 32;
                    dev.handle_tcp6_listen(port_num, reply_port);
                }
                TCP6_ACCEPT => {
                    let port_num = msg.data[0] as u16;
                    let reply_port = msg.data[1] >> 32;
                    dev.handle_tcp6_accept(port_num, reply_port);
                }
                // --- UDP6 IPC ---
                UDP6_BIND => {
                    // data[0] = port(low16) | reply_port(high48)
                    let port_num = msg.data[0] as u16;
                    let reply_port = msg.data[0] >> 16;
                    dev.handle_udp6_bind(port_num, reply_port);
                }
                UDP6_SEND => {
                    // data[0..1] = dest IPv6 (16 bytes in 2 u64s)
                    // data[2] = dst_port(low16) | bind_id(16-31) | reply_port(high32)
                    // data[3] = inline payload (up to 8 bytes)
                    let mut dst = [0u8; 16];
                    let d0 = msg.data[0];
                    let d1 = msg.data[1];
                    for i in 0..8 { dst[i] = (d0 >> (i * 8)) as u8; }
                    for i in 0..8 { dst[8 + i] = (d1 >> (i * 8)) as u8; }
                    let dst_port = msg.data[2] as u16;
                    let bind_id = ((msg.data[2] >> 16) & 0xFFFF) as usize;
                    let reply_port = msg.data[2] >> 32;
                    let payload_len = (msg.data[3] & 0xFF) as usize;
                    let mut payload = [0u8; 8];
                    let d3 = msg.data[3] >> 8;
                    for i in 0..payload_len.min(7) { payload[i] = (d3 >> (i * 8)) as u8; }
                    if bind_id >= MAX_UDP6_BINDS || !dev.udp6[bind_id].active {
                        syscall::send_nb(reply_port, UDP6_SEND_FAIL, 0, 0);
                    } else {
                        let src_port = dev.udp6[bind_id].local_port;
                        dev.handle_udp6_send(&dst, dst_port, src_port, &payload[..payload_len.min(7)], reply_port);
                    }
                }
                UDP6_RECV => {
                    // data[0] = bind_id(low32) | reply_port(high32)
                    let bind_id = (msg.data[0] & 0xFFFFFFFF) as usize;
                    let reply_port = msg.data[0] >> 32;
                    dev.handle_udp6_recv(bind_id, reply_port);
                }
                UDP6_RECV_NB => {
                    // data[0] = bind_id(low32) | reply_port(high32)
                    let bind_id = (msg.data[0] & 0xFFFFFFFF) as usize;
                    let reply_port = msg.data[0] >> 32;
                    dev.handle_udp6_recv_nb(bind_id, reply_port);
                }
                UDP6_CLOSE => {
                    // data[0] = bind_id(low32) | reply_port(high32)
                    let bind_id = (msg.data[0] & 0xFFFFFFFF) as usize;
                    let reply_port = msg.data[0] >> 32;
                    dev.handle_udp6_close(bind_id, reply_port);
                }
                _ => {}
            }
        }

        // 2. Deliver pending TCP6 data.
        if dev.tcp6_deliver_pending {
            dev.tcp6_deliver_pending = false;
            dev.deliver_pending_tcp6_recvs();
        }

        // 3. Tick timeouts.
        dev.tick_ping();
        dev.tick_tcp6();
        tick += 1;

        // 4. Retransmit RS periodically until gateway discovered.
        if !dev.has_gateway && tick % 500 == 0 {
            dev.send_router_solicit();
        }

        // 5. Yield.
        syscall::yield_now();
    }
}
