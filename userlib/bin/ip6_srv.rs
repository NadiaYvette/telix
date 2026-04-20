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

// --- IPv6 device ---

struct Ip6Dev {
    eth_port: u64,      // eth_srv's IPC port
    my_port: u64,       // our IPC port
    mac: [u8; 6],       // link-layer address
    link_local: [u8; 16], // fe80::eui64
    rx_va: usize,       // grant page for receiving frames from eth_srv
    tx_va: usize,       // grant page for sending frames to eth_srv
    // Neighbor cache (IPv6 → MAC).
    neighbors: [NeighborEntry; NEIGHBOR_CACHE_SIZE],
    neigh_next: usize,
    // Pending ping.
    ping: PingState,
}

impl Ip6Dev {
    fn new(eth_port: u64, my_port: u64, mac: [u8; 6], rx_va: usize, tx_va: usize) -> Self {
        let link_local = eui64_link_local(mac);
        Self {
            eth_port,
            my_port,
            mac,
            link_local,
            rx_va,
            tx_va,
            neighbors: [const { NeighborEntry::new() }; NEIGHBOR_CACHE_SIZE],
            neigh_next: 0,
            ping: PingState::new(),
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
    fn send_ipv6(&mut self, dst_ip6: &[u8; 16], next_header: u8, payload: &[u8], dst_mac: [u8; 6]) {
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
            *hdr.add(7) = 64;
            // Source address (16 bytes).
            core::ptr::copy_nonoverlapping(self.link_local.as_ptr(), hdr.add(8), 16);
            // Destination address (16 bytes).
            core::ptr::copy_nonoverlapping(dst_ip6.as_ptr(), hdr.add(24), 16);
            // Payload.
            core::ptr::copy_nonoverlapping(payload.as_ptr(), hdr.add(IPV6_HDR_LEN), payload_len);
        }

        // Send NETIF_XMIT to eth_srv.
        let reply_port = syscall::port_create();
        let mac_val = mac_to_u64(dst_mac);
        // data[0]=payload_len, data[1]=dst_mac, data[2]=ethertype|(reply_port<<16), data[3]=client_id(0)
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            total as u64,
            mac_val,
            ETHERTYPE_IPV6 as u64 | (reply_port << 16),
            0, // client_id — we're the first registered client
        );
        // Wait briefly for XMIT_OK.
        let _ = syscall::recv_msg_timeout(reply_port, 100_000);
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
        let cksum = Self::icmpv6_checksum(&self.link_local, dst_ip6, &icmp);
        icmp[2] = (cksum >> 8) as u8;
        icmp[3] = cksum as u8;
        self.send_ipv6(dst_ip6, IPPROTO_ICMPV6, &icmp, dst_mac);
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
        self.send_ipv6(dst_ip6, IPPROTO_ICMPV6, &icmp[..total_len], dst_mac);
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
        self.send_ipv6(&sol_node, IPPROTO_ICMPV6, &ns, dst_mac);
    }

    /// Send NDP Neighbor Advertisement in response to a solicitation.
    fn send_neighbor_advert(&mut self, dst_ip6: &[u8; 16], dst_mac: [u8; 6]) {
        // NA: type(136) + code(0) + cksum(2) + flags(4) + target(16) + option(8) = 32 bytes
        let mut na = [0u8; 32];
        na[0] = ICMPV6_NEIGHBOR_ADVERT;
        // Flags: Solicited=1, Override=1 → 0x60000000 in bytes 4-7.
        na[4] = 0x60;
        // Target address: our link-local.
        na[8..24].copy_from_slice(&self.link_local);
        // Target link-layer address option.
        na[24] = 2; // option type (target link-layer)
        na[25] = 1; // length in 8-byte units
        na[26..32].copy_from_slice(&self.mac);

        let cksum = Self::icmpv6_checksum(&self.link_local, dst_ip6, &na);
        na[2] = (cksum >> 8) as u8;
        na[3] = cksum as u8;
        self.send_ipv6(dst_ip6, IPPROTO_ICMPV6, &na, dst_mac);
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
        self.send_ipv6(&all_routers, IPPROTO_ICMPV6, &rs, dst_mac);
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
            IPPROTO_TCP => {
                // Future: dispatch to tcp6 client.
                let _ = (IPPROTO_TCP, IPPROTO_UDP);
            }
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
                    syscall::debug_puts(b"  [ip6_srv] echo request, replying\n");
                    self.send_echo_reply(src_ip6, src_mac, id, seq, echo_data);
                }
            }
            ICMPV6_ECHO_REPLY => {
                // Received ping reply.
                if self.ping.active {
                    syscall::debug_puts(b"  [ip6_srv] ping6 reply received\n");
                    syscall::send_nb(self.ping.reply_port, IP6_PING_OK, 0, 0);
                    self.ping.active = false;
                }
            }
            ICMPV6_NEIGHBOR_SOLICIT => {
                // Someone is asking for our MAC.
                if data.len() >= 24 {
                    let target = &data[8..24];
                    if target == self.link_local {
                        syscall::debug_puts(b"  [ip6_srv] NS for us, sending NA\n");
                        self.send_neighbor_advert(src_ip6, src_mac);
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
                // Parse Router Advertisement for prefix info (future SLAAC).
                syscall::debug_puts(b"  [ip6_srv] RA received\n");
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------------
    // Ping6 handling
    // ---------------------------------------------------------------

    fn start_ping6(&mut self, target: [u8; 16], reply_port: u64) {
        self.ping.target = target;
        self.ping.reply_port = reply_port;
        self.ping.seq = self.ping.seq.wrapping_add(1);
        self.ping.polls = 0;
        self.ping.active = true;
        self.ping.sent = false;

        if let Some(mac) = self.neigh_lookup(&target) {
            self.send_echo_request(&target, mac, self.ping.seq);
            self.ping.sent = true;
        } else {
            // Need neighbor discovery first.
            self.send_neighbor_solicit(&target);
        }
    }

    fn tick_ping(&mut self) {
        if !self.ping.active {
            return;
        }
        self.ping.polls += 1;
        if self.ping.polls > 5000 {
            syscall::debug_puts(b"  [ip6_srv] ping6 timeout\n");
            syscall::send_nb(self.ping.reply_port, IP6_PING_FAIL, 0, 0);
            self.ping.active = false;
        }
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

fn print_hex(n: u64) {
    syscall::debug_puts(b"0x");
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 16];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        let d = (val & 0xF) as u8;
        buf[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        val >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

fn print_ipv6(addr: &[u8; 16]) {
    for i in 0..8 {
        if i > 0 {
            syscall::debug_putchar(b':');
        }
        let hi = addr[i * 2];
        let lo = addr[i * 2 + 1];
        let val = ((hi as u16) << 8) | (lo as u16);
        print_hex(val as u64);
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

    syscall::debug_puts(b"  [ip6_srv] found eth_srv on port ");
    print_num(eth_port);
    syscall::debug_puts(b"\n");

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

    syscall::debug_puts(b"  [ip6_srv] MAC=");
    print_mac(mac);
    syscall::debug_puts(b"\n");

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

    if let Some(msg) = syscall::recv_msg_timeout(reg_reply, 2_000_000) {
        if msg.tag == NETIF_REGISTER_OK {
            let _client_id = msg.data[0];
            let eth_rx_va = msg.data[1] as usize; // VA in eth_srv's aspace for RX page
            let eth_tx_va = msg.data[2] as usize; // VA in eth_srv's aspace for TX page
            syscall::debug_puts(b"  [ip6_srv] registered with eth_srv, client_id=");
            print_num(_client_id);
            syscall::debug_puts(b"\n");

            // Grant our RX page to eth_srv (eth_srv writes incoming frames here).
            if !syscall::grant_pages(eth_port, rx_va, eth_rx_va, 1, false) {
                syscall::debug_puts(b"  [ip6_srv] grant rx failed\n");
            }
            // Grant our TX page to eth_srv (we write outgoing frames here, eth_srv reads).
            if !syscall::grant_pages(eth_port, tx_va, eth_tx_va, 1, false) {
                syscall::debug_puts(b"  [ip6_srv] grant tx failed\n");
            }
            syscall::debug_puts(b"  [ip6_srv] grant pages established\n");
        } else {
            syscall::debug_puts(b"  [ip6_srv] register failed\n");
            loop { core::hint::spin_loop(); }
        }
    } else {
        syscall::debug_puts(b"  [ip6_srv] register timeout\n");
        loop { core::hint::spin_loop(); }
    };
    syscall::port_destroy(reg_reply);

    let mut dev = Ip6Dev::new(eth_port, my_port, mac, rx_va, tx_va);

    // Print our link-local address.
    syscall::debug_puts(b"  [ip6_srv] link-local ");
    print_ipv6(&dev.link_local);
    syscall::debug_puts(b"\n");

    // Register with name server.
    syscall::ns_register(b"ip6", my_port);
    syscall::debug_puts(b"  [ip6_srv] registered on port ");
    print_num(my_port);
    syscall::debug_puts(b"\n");

    // Send Router Solicitation to discover default gateway.
    dev.send_router_solicit();

    // Poll-based server loop.
    loop {
        // 1. Poll IPC (netif input notifications + client requests).
        if let Some(msg) = syscall::recv_nb_msg(my_port) {
            match msg.tag {
                NETIF_INPUT => {
                    // Frame from eth_srv.
                    let payload_len = msg.data[0] as usize;
                    let src_mac = u64_to_mac(msg.data[1]);
                    dev.handle_input(payload_len, src_mac);
                }
                IP6_PING => {
                    // Ping6 request from a client.
                    // data[0..1] = target IPv6 address (16 bytes packed in 2 u64s)
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
                    syscall::debug_puts(b"  [ip6_srv] ping6 ");
                    print_ipv6(&target);
                    syscall::debug_puts(b"\n");
                    dev.start_ping6(target, reply_port);
                }
                IP6_STATUS => {
                    let reply_port = msg.data[0];
                    // Pack link-local address into 2 u64s.
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
                _ => {}
            }
        }

        // 2. Tick timeouts.
        dev.tick_ping();

        // 3. Yield.
        syscall::yield_now();
    }
}
