#![no_std]
#![no_main]
#![cfg_attr(target_arch = "mips64", feature(asm_experimental_arch))]

//! B.A.T.M.A.N. Layer 2 Mesh Routing Server (batman-adv style).
//!
//! Acts as a transparent NETIF proxy between eth_srv and upper-layer
//! protocol services (tcp4_srv, ip6_srv). Registers as "bat0".
//!
//! Phase 1: Transparent pass-through (no encapsulation).
//! Phase 2: B.A.T.M.A.N. IV OGM generation + neighbor/originator tables.

extern crate userlib;

use userlib::syscall;

// -------------------------------------------------------------------
// NETIF IPC protocol constants (same as eth_srv / tcp4_srv).
// -------------------------------------------------------------------

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

// B.A.T.M.A.N. status query.
const BAT_STATUS: u64 = 0x5500;
const BAT_STATUS_OK: u64 = 0x5501;

// B.A.T.M.A.N. EtherType (standard ETH_P_BATMAN = 0x4305).
const ETHERTYPE_BATMAN: u16 = 0x4305;

const MTU: usize = 1500;

// -------------------------------------------------------------------
// B.A.T.M.A.N. IV constants.
// -------------------------------------------------------------------

const BATMAN_VERSION: u8 = 15;
const BATMAN_PACKET_OGM: u8 = 0x01;
const BATMAN_PACKET_BCAST: u8 = 0x02;
const BATMAN_PACKET_UNICAST: u8 = 0x03;
const OGM_SIZE: usize = 26;       // 26-byte OGM (no TVLVs)
const UNICAST_HDR_SIZE: usize = 12; // unicast encapsulation header
const BCAST_HDR_SIZE: usize = 14;   // broadcast encapsulation header
const INNER_ETH_HDR: usize = 14;    // inner ethernet header (dst+src+ethertype)
const BATMAN_MTU: usize = MTU - BCAST_HDR_SIZE - INNER_ETH_HDR; // 1472

const OGM_INTERVAL_NS: u64 = 1_000_000_000;   // 1 second
const OGM_PURGE_NS: u64 = 200_000_000_000;     // 200 seconds
const OGM_DEFAULT_TTL: u8 = 50;
const TQ_MAX: u8 = 255;
const TQ_LOCAL_WINDOW_SIZE: u32 = 64;

const MAX_NEIGHBORS: usize = 16;
const MAX_ORIGINATORS: usize = 16;
const BCAST_DEDUP_SIZE: usize = 64;

// -------------------------------------------------------------------
// B.A.T.M.A.N. V constants (ELP + OGMv2).
// -------------------------------------------------------------------

const BATMAN_PACKET_ELP: u8 = 0x05;
const BATMAN_PACKET_OGM2: u8 = 0x06;
const ELP_SIZE: usize = 18;
const OGM2_SIZE: usize = 24;  // 24-byte OGMv2 (no TVLVs)

const ELP_INTERVAL_NS: u64 = 500_000_000;     // 500ms
const ELP_WINDOW_SIZE: u32 = 32;               // sliding window for ELP loss
const DEFAULT_THROUGHPUT: u32 = 10000;          // 10000 * 100 Kbit/s = 1 Gbit/s

const BATMAN_MODE_IV: u8 = 0;
const BATMAN_MODE_V: u8 = 1;
/// Active routing mode. Set at compile time.
const BATMAN_MODE: u8 = BATMAN_MODE_IV;

// -------------------------------------------------------------------
// Gateway support constants.
// -------------------------------------------------------------------

/// TVLV type for gateway announcement (appended to OGM tvlv area).
const TVLV_GW_TYPE: u8 = 0x01;
const TVLV_GW_LEN: u8 = 4; // 4 bytes: download(u16 LE) + upload(u16 LE)

/// Gateway speeds in 100 Kbit/s units.
const GW_DOWN_SPEED: u16 = 10000; // 1 Gbit/s
const GW_UP_SPEED: u16 = 1000;    // 100 Mbit/s

const MAX_GATEWAYS: usize = 8;

// -------------------------------------------------------------------
// Data structures.
// -------------------------------------------------------------------

const MAX_DOWNSTREAM: usize = 4;
const MAX_UPSTREAM: usize = 4;

/// A downstream connection to eth_srv for a single EtherType.
/// batman_srv registers once per proxied ethertype + once for 0x4305.
struct DownstreamConn {
    active: bool,
    ethertype: u16,
    client_id: u64,  // client_id assigned by eth_srv
    port: u64,       // IPC port where eth_srv sends NETIF_INPUT
    rx_va: usize,    // our local page for receiving from eth_srv
    tx_va: usize,    // our local page for sending to eth_srv
}

impl DownstreamConn {
    const fn new() -> Self {
        Self {
            active: false,
            ethertype: 0,
            client_id: 0,
            port: 0,
            rx_va: 0,
            tx_va: 0,
        }
    }
}

/// An upstream client (e.g. tcp4_srv, ip6_srv) that registered with us.
struct UpstreamClient {
    active: bool,
    ethertype: u16,
    port: u64,            // client's IPC port (for NETIF_INPUT notifications)
    rx_va: usize,         // VA in our aspace where client's RX page is granted
    tx_va: usize,         // VA in our aspace where client's TX page is granted
    downstream_idx: usize, // index into downstream[] for this ethertype
}

impl UpstreamClient {
    const fn new() -> Self {
        Self {
            active: false,
            ethertype: 0,
            port: 0,
            rx_va: 0,
            tx_va: 0,
            downstream_idx: 0,
        }
    }
}

// -------------------------------------------------------------------
// B.A.T.M.A.N. IV neighbor + originator tables.
// -------------------------------------------------------------------

/// A directly-connected neighbor (one-hop peer).
struct Neighbor {
    active: bool,
    mac: [u8; 6],
    last_seen_ns: u64,
    /// Sliding window: bit i = 1 means OGM seqno (last_seqno - i) was received.
    rx_window: u64,
    /// Last OGM seqno received from this neighbor as prev_sender.
    last_seqno: u32,
    /// Estimated receive quality (0..TQ_MAX): fraction of OGMs received. (IV mode)
    tq_recv: u8,
    // --- B.A.T.M.A.N. V (ELP) fields ---
    /// ELP sliding window for packet loss estimation.
    elp_window: u32,
    /// Last ELP seqno received from this neighbor.
    elp_last_seqno: u32,
    /// Estimated throughput to this neighbor (units of 100 Kbit/s).
    throughput: u32,
}

impl Neighbor {
    const fn new() -> Self {
        Self {
            active: false,
            mac: [0; 6],
            last_seen_ns: 0,
            rx_window: 0,
            last_seqno: 0,
            tq_recv: 0,
            elp_window: 0,
            elp_last_seqno: 0,
            throughput: 0,
        }
    }
}

/// A known originator (any node in the mesh, possibly multi-hop).
struct Originator {
    active: bool,
    orig_mac: [u8; 6],
    best_next_hop: [u8; 6],
    best_tq: u8,            // IV mode: best TQ
    best_throughput: u32,    // V mode: best min-throughput path (100 Kbit/s units)
    last_seqno: u32,
    last_seen_ns: u64,
}

impl Originator {
    const fn new() -> Self {
        Self {
            active: false,
            orig_mac: [0; 6],
            best_next_hop: [0; 6],
            best_tq: 0,
            best_throughput: 0,
            last_seqno: 0,
            last_seen_ns: 0,
        }
    }
}

/// A known gateway node in the mesh.
struct Gateway {
    active: bool,
    orig_mac: [u8; 6],
    next_hop: [u8; 6],
    down_speed: u16,   // 100 Kbit/s units
    up_speed: u16,     // 100 Kbit/s units
    tq: u8,            // IV: path TQ to this gateway
    throughput: u32,   // V: min-throughput path to gateway
    last_seen_ns: u64,
}

impl Gateway {
    const fn new() -> Self {
        Self {
            active: false,
            orig_mac: [0; 6],
            next_hop: [0; 6],
            down_speed: 0,
            up_speed: 0,
            tq: 0,
            throughput: 0,
            last_seen_ns: 0,
        }
    }
}

/// Main device state.
struct BatmanDev {
    eth_port: u64,
    my_port: u64,
    mac: [u8; 6],
    downstream: [DownstreamConn; MAX_DOWNSTREAM],
    upstream: [UpstreamClient; MAX_UPSTREAM],
    ogm_seqno: u32,
    // B.A.T.M.A.N. IV mesh state
    neighbors: [Neighbor; MAX_NEIGHBORS],
    originators: [Originator; MAX_ORIGINATORS],
    last_ogm_ns: u64,
    bat_ctrl_idx: usize, // downstream index for 0x4305
    // B.A.T.M.A.N. V state
    elp_seqno: u32,
    last_elp_ns: u64,
    ogm2_seqno: u32,
    // Gateway state
    gateways: [Gateway; MAX_GATEWAYS],
    is_gateway: bool,  // true if we announce ourselves as a gateway
    // Broadcast encapsulation
    bcast_seqno: u32,
    bcast_dedup_orig: [[u8; 6]; BCAST_DEDUP_SIZE],
    bcast_dedup_seq: [u32; BCAST_DEDUP_SIZE],
    bcast_dedup_head: usize,
}

// Grant page VA base for upstream clients.
// Each client gets [rx_page, tx_page] pair.
const UPSTREAM_GRANT_BASE: usize = 0x3_0001_0000;

// -------------------------------------------------------------------
// Helpers.
// -------------------------------------------------------------------

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

fn print_hex(v: u64) {
    let digits = b"0123456789abcdef";
    syscall::debug_puts(b"0x");
    let mut started = false;
    for shift in (0..16).rev() {
        let nibble = ((v >> (shift * 4)) & 0xF) as usize;
        if nibble != 0 || started || shift == 0 {
            syscall::debug_putchar(digits[nibble]);
            started = true;
        }
    }
}

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

fn print_mac(m: [u8; 6]) {
    let hex = b"0123456789abcdef";
    for i in 0..6 {
        if i > 0 {
            syscall::debug_putchar(b':');
        }
        syscall::debug_putchar(hex[(m[i] >> 4) as usize]);
        syscall::debug_putchar(hex[(m[i] & 0xF) as usize]);
    }
}

// -------------------------------------------------------------------
// Downstream: register with eth_srv for a given ethertype.
// -------------------------------------------------------------------

impl BatmanDev {
    /// Register a new downstream connection with eth_srv for `ethertype`.
    /// Returns the downstream slot index on success.
    fn register_downstream(&mut self, ethertype: u16) -> Option<usize> {
        // Find free downstream slot.
        let slot = self.downstream.iter().position(|d| !d.active)?;

        // Create a dedicated IPC port for this downstream channel.
        let down_port = syscall::port_create();

        // Allocate local RX and TX pages.
        let rx_va = match syscall::mmap_anon(0, 1, 1) {
            Some(va) => va,
            None => return None,
        };
        let tx_va = match syscall::mmap_anon(0, 1, 1) {
            Some(va) => va,
            None => return None,
        };

        // NETIF_REGISTER with eth_srv.
        let reg_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_REGISTER,
            ethertype as u64,  // data[0] = ethertype
            down_port,         // data[1] = our port for NETIF_INPUT
            reg_reply,         // data[2] = reply port
            0,
        );

        let result = syscall::recv_msg_timeout(reg_reply, 2_000_000);
        syscall::port_destroy(reg_reply);

        match result {
            Some(msg) if msg.tag == NETIF_REGISTER_OK => {
                let client_id = msg.data[0];
                let eth_rx_va = msg.data[1] as usize;
                let eth_tx_va = msg.data[2] as usize;

                // Grant our pages to eth_srv.
                if !syscall::grant_pages(self.eth_port, rx_va, eth_rx_va, 1, false) {
                    syscall::debug_puts(b"  [batman_srv] grant rx failed\n");
                    return None;
                }
                if !syscall::grant_pages(self.eth_port, tx_va, eth_tx_va, 1, false) {
                    syscall::debug_puts(b"  [batman_srv] grant tx failed\n");
                    return None;
                }

                self.downstream[slot] = DownstreamConn {
                    active: true,
                    ethertype,
                    client_id,
                    port: down_port,
                    rx_va,
                    tx_va,
                };

                syscall::debug_puts(b"  [batman_srv] downstream registered: ethertype=");
                print_hex(ethertype as u64);
                syscall::debug_puts(b" cid=");
                print_num(client_id);
                syscall::debug_puts(b"\n");

                Some(slot)
            }
            _ => {
                syscall::debug_puts(b"  [batman_srv] downstream register failed\n");
                None
            }
        }
    }

    // ---------------------------------------------------------------
    // Upstream: handle NETIF_REGISTER from clients (tcp4_srv, ip6_srv).
    // ---------------------------------------------------------------

    fn handle_register(&mut self, ethertype: u16, client_port: u64, reply_port: u64) {
        // Find free upstream slot.
        let slot = match self.upstream.iter().position(|u| !u.active) {
            Some(s) => s,
            None => {
                syscall::debug_puts(b"  [batman_srv] no free upstream slots\n");
                return;
            }
        };

        // Register downstream for this ethertype if not already done.
        let down_idx = match self.downstream.iter().position(|d| d.active && d.ethertype == ethertype) {
            Some(i) => i,
            None => match self.register_downstream(ethertype) {
                Some(i) => i,
                None => return,
            },
        };

        // Assign grant page VAs for this upstream client in our address space.
        let ps = syscall::page_size();
        let rx_va = UPSTREAM_GRANT_BASE + slot * 2 * ps;
        let tx_va = rx_va + ps;

        self.upstream[slot] = UpstreamClient {
            active: true,
            ethertype,
            port: client_port,
            rx_va,
            tx_va,
            downstream_idx: down_idx,
        };

        // Reply with client_id and the VAs where the client should grant pages.
        syscall::send_nb_4(
            reply_port,
            NETIF_REGISTER_OK,
            slot as u64,   // data[0] = client_id
            rx_va as u64,  // data[1] = bat_rx_va (client grants RX page here)
            tx_va as u64,  // data[2] = bat_tx_va (client grants TX page here)
            0,
        );

        syscall::debug_puts(b"  [batman_srv] upstream client ");
        print_num(slot as u64);
        syscall::debug_puts(b" registered: ethertype=");
        print_hex(ethertype as u64);
        syscall::debug_puts(b"\n");
    }

    // ---------------------------------------------------------------
    // Proxy: NETIF_XMIT from upstream client → forward to eth_srv.
    // If mesh peers exist, encapsulate in BATMAN unicast/broadcast.
    // ---------------------------------------------------------------

    fn handle_xmit(&mut self, client_id: usize, payload_len: usize,
                    dst_mac_val: u64, ethertype: u16, reply_port: u64) {
        if client_id >= MAX_UPSTREAM || !self.upstream[client_id].active {
            return;
        }
        if payload_len > MTU {
            return;
        }

        let dst_mac = if dst_mac_val == 0 { [0xFF; 6] } else { u64_to_mac(dst_mac_val) };
        let is_broadcast = dst_mac == [0xFF; 6];
        let has_mesh = self.neighbors.iter().any(|n| n.active);

        if has_mesh {
            if is_broadcast {
                // Broadcast: encapsulate and flood via 0x4305 for mesh peers.
                self.send_broadcast_encap(client_id, payload_len, dst_mac, ethertype);
                // Also proxy directly for local/gateway destinations (fall through).
            } else if let Some(next_hop) = self.lookup_next_hop(dst_mac) {
                // Known mesh destination: unicast encapsulate to next-hop.
                self.send_unicast_encap(client_id, payload_len, dst_mac, ethertype, next_hop);
                syscall::send_nb(reply_port, NETIF_XMIT_OK, 0, 0);
                return; // Don't also proxy directly for mesh-routed frames.
            } else if let Some(gw_hop) = self.best_gateway() {
                // Unknown destination, but we have a gateway — route through it.
                self.send_unicast_encap(client_id, payload_len, dst_mac, ethertype, gw_hop);
                syscall::send_nb(reply_port, NETIF_XMIT_OK, 0, 0);
                return;
            }
            // No gateway, unknown destination: fall through to direct proxy.
        }

        // Direct proxy (Phase 1 behavior): copy payload and forward.
        let down_idx = self.upstream[client_id].downstream_idx;
        if !self.downstream[down_idx].active {
            return;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.upstream[client_id].tx_va as *const u8,
                self.downstream[down_idx].tx_va as *mut u8,
                payload_len,
            );
        }
        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            payload_len as u64,
            dst_mac_val,
            (ethertype as u64) | ((xmit_reply as u64) << 16),
            self.downstream[down_idx].client_id,
        );
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);
        syscall::send_nb(reply_port, NETIF_XMIT_OK, 0, 0);
    }

    // ---------------------------------------------------------------
    // Mesh routing: originator lookup.
    // ---------------------------------------------------------------

    /// Look up the best next-hop MAC for a destination.
    /// For mesh nodes without bridging, dst_mac == originator MAC.
    fn lookup_next_hop(&self, dst_mac: [u8; 6]) -> Option<[u8; 6]> {
        for o in &self.originators {
            if o.active && o.orig_mac == dst_mac {
                return Some(o.best_next_hop);
            }
        }
        None
    }

    // ---------------------------------------------------------------
    // Unicast encapsulation: wrap frame in BATMAN unicast header.
    // ---------------------------------------------------------------

    /// Encapsulate an upstream client's payload in a BATMAN unicast frame
    /// and send to the next-hop via 0x4305.
    fn send_unicast_encap(
        &self,
        client_id: usize,
        payload_len: usize,
        dst_mac: [u8; 6],
        ethertype: u16,
        next_hop: [u8; 6],
    ) {
        let ctrl = &self.downstream[self.bat_ctrl_idx];
        if !ctrl.active {
            return;
        }

        // Total frame: unicast_hdr(12) + inner_eth_hdr(14) + payload
        let total = UNICAST_HDR_SIZE + INNER_ETH_HDR + payload_len;
        if total > MTU {
            return;
        }

        let tx = ctrl.tx_va as *mut u8;
        unsafe {
            // Build unicast header [0..12]
            *tx.add(0) = BATMAN_PACKET_UNICAST;  // packet_type
            *tx.add(1) = BATMAN_VERSION;          // version
            *tx.add(2) = OGM_DEFAULT_TTL;         // ttl
            *tx.add(3) = 0;                       // reserved
            // [4..10] destination originator MAC
            core::ptr::copy_nonoverlapping(dst_mac.as_ptr(), tx.add(4), 6);
            *tx.add(10) = 0; // ttvn
            *tx.add(11) = 0; // reserved

            // Build inner ethernet header [12..26]
            core::ptr::copy_nonoverlapping(dst_mac.as_ptr(), tx.add(12), 6);     // inner dst
            core::ptr::copy_nonoverlapping(self.mac.as_ptr(), tx.add(18), 6);    // inner src
            *tx.add(24) = (ethertype >> 8) as u8;  // ethertype big-endian
            *tx.add(25) = ethertype as u8;

            // Copy payload [26..]
            core::ptr::copy_nonoverlapping(
                self.upstream[client_id].tx_va as *const u8,
                tx.add(UNICAST_HDR_SIZE + INNER_ETH_HDR),
                payload_len,
            );
        }

        // Send via 0x4305 to next_hop.
        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            total as u64,
            mac_to_u64(next_hop),
            (ETHERTYPE_BATMAN as u64) | ((xmit_reply as u64) << 16),
            ctrl.client_id,
        );
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);
    }

    // ---------------------------------------------------------------
    // Broadcast encapsulation: wrap frame in BATMAN broadcast header.
    // ---------------------------------------------------------------

    /// Encapsulate an upstream client's payload in a BATMAN broadcast frame
    /// and flood via 0x4305 (ethernet broadcast).
    fn send_broadcast_encap(
        &mut self,
        client_id: usize,
        payload_len: usize,
        dst_mac: [u8; 6],
        ethertype: u16,
    ) {
        let ctrl = &self.downstream[self.bat_ctrl_idx];
        if !ctrl.active {
            return;
        }

        // Total frame: bcast_hdr(14) + inner_eth_hdr(14) + payload
        let total = BCAST_HDR_SIZE + INNER_ETH_HDR + payload_len;
        if total > MTU {
            return;
        }

        let tx = ctrl.tx_va as *mut u8;
        let seq = self.bcast_seqno;
        unsafe {
            // Build broadcast header [0..14]
            *tx.add(0) = BATMAN_PACKET_BCAST;  // packet_type
            *tx.add(1) = BATMAN_VERSION;        // version
            *tx.add(2) = OGM_DEFAULT_TTL;       // ttl
            *tx.add(3) = 0;                     // reserved
            // [4..10] originator MAC
            core::ptr::copy_nonoverlapping(self.mac.as_ptr(), tx.add(4), 6);
            // [10..14] broadcast seqno (u32 LE)
            *tx.add(10) = seq as u8;
            *tx.add(11) = (seq >> 8) as u8;
            *tx.add(12) = (seq >> 16) as u8;
            *tx.add(13) = (seq >> 24) as u8;

            // Build inner ethernet header [14..28]
            core::ptr::copy_nonoverlapping(dst_mac.as_ptr(), tx.add(14), 6);     // inner dst
            core::ptr::copy_nonoverlapping(self.mac.as_ptr(), tx.add(20), 6);    // inner src
            *tx.add(26) = (ethertype >> 8) as u8;  // ethertype big-endian
            *tx.add(27) = ethertype as u8;

            // Copy payload [28..]
            core::ptr::copy_nonoverlapping(
                self.upstream[client_id].tx_va as *const u8,
                tx.add(BCAST_HDR_SIZE + INNER_ETH_HDR),
                payload_len,
            );
        }

        self.bcast_seqno = self.bcast_seqno.wrapping_add(1);

        // Send via 0x4305 as ethernet broadcast (dst_mac=0).
        let ctrl = &self.downstream[self.bat_ctrl_idx];
        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            total as u64,
            0u64, // broadcast
            (ETHERTYPE_BATMAN as u64) | ((xmit_reply as u64) << 16),
            ctrl.client_id,
        );
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);
    }

    // ---------------------------------------------------------------
    // Proxy: NETIF_INPUT from eth_srv → forward to upstream client.
    // ---------------------------------------------------------------

    fn handle_input(&mut self, down_idx: usize, payload_len: usize, src_mac_val: u64) {
        if !self.downstream[down_idx].active {
            return;
        }
        let ethertype = self.downstream[down_idx].ethertype;

        // Find upstream client for this ethertype.
        let up_idx = match self.upstream.iter().position(|u| u.active && u.ethertype == ethertype) {
            Some(i) => i,
            None => return, // no upstream client registered for this ethertype
        };

        let plen = payload_len.min(MTU);

        // Copy from downstream RX grant page to upstream client's RX grant page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.downstream[down_idx].rx_va as *const u8,
                self.upstream[up_idx].rx_va as *mut u8,
                plen,
            );
        }

        // Send NETIF_INPUT to upstream client (blocking, so client copies before overwrite).
        syscall::send(
            self.upstream[up_idx].port,
            NETIF_INPUT,
            plen as u64,
            src_mac_val,
            0, 0,
        );
    }

    // ---------------------------------------------------------------
    // Proxy: NETIF_RESOLVE → forward to eth_srv.
    // ---------------------------------------------------------------

    fn handle_resolve(&self, ip_be: u32, reply_port: u64) {
        // Forward to eth_srv directly. The reply goes straight to the caller.
        syscall::send_nb(self.eth_port, NETIF_RESOLVE, ip_be as u64, reply_port);
    }

    // ---------------------------------------------------------------
    // NETIF_STATUS → reply with our MAC and MTU.
    // ---------------------------------------------------------------

    fn handle_status(&self, reply_port: u64) {
        // Report reduced MTU if mesh is active so upstream clients
        // don't send frames larger than we can encapsulate.
        let has_mesh = self.neighbors.iter().any(|n| n.active);
        let mtu = if has_mesh { BATMAN_MTU } else { MTU };
        syscall::send_nb(
            reply_port,
            NETIF_STATUS_OK,
            mac_to_u64(self.mac),
            mtu as u64 | (1u64 << 32), // mtu | link_up flag
        );
    }

    // ---------------------------------------------------------------
    // BAT_STATUS → reply with mesh state.
    // ---------------------------------------------------------------

    fn handle_bat_status(&self, reply_port: u64) {
        let orig_count = self.originators.iter().filter(|o| o.active).count() as u64;
        let neigh_count = self.neighbors.iter().filter(|n| n.active).count() as u64;
        let gw_count = self.gateways.iter().filter(|g| g.active).count() as u64;
        syscall::send_nb_4(
            reply_port,
            BAT_STATUS_OK,
            orig_count,
            neigh_count,
            self.ogm_seqno as u64,
            gw_count,
        );
    }

    // ---------------------------------------------------------------
    // B.A.T.M.A.N. IV: OGM construction and broadcast.
    // ---------------------------------------------------------------

    /// Build a 26-byte OGMv1 packet in `buf`. Returns OGM_SIZE.
    fn build_ogm(&self, buf: &mut [u8], ttl: u8, tq: u8, prev_sender: [u8; 6]) -> usize {
        if buf.len() < OGM_SIZE {
            return 0;
        }
        buf[0] = BATMAN_PACKET_OGM;     // packet_type
        buf[1] = BATMAN_VERSION;         // version
        buf[2] = ttl;                    // ttl
        buf[3] = 0;                      // flags byte (reserved)
        // [4..6] flags (u16 LE)
        buf[4] = 0;
        buf[5] = 0;
        // [6..10] seqno (u32 LE)
        let s = self.ogm_seqno;
        buf[6] = s as u8;
        buf[7] = (s >> 8) as u8;
        buf[8] = (s >> 16) as u8;
        buf[9] = (s >> 24) as u8;
        // [10..16] orig MAC
        buf[10..16].copy_from_slice(&self.mac);
        // [16..22] prev_sender MAC
        buf[16..22].copy_from_slice(&prev_sender);
        // [22] reserved
        buf[22] = 0;
        // [23] tq
        buf[23] = tq;
        // [24..26] tvlv_len (u16 LE)
        // Append gateway TVLV if we're a gateway.
        let tvlv_written = if self.is_gateway && buf.len() >= OGM_SIZE + 8 {
            self.build_gw_tvlv(&mut buf[OGM_SIZE..])
        } else {
            0
        };
        buf[24] = tvlv_written as u8;
        buf[25] = (tvlv_written >> 8) as u8;
        OGM_SIZE + tvlv_written
    }

    /// Broadcast our own OGM via the 0x4305 downstream channel.
    fn send_ogm(&mut self) {
        let ctrl = &self.downstream[self.bat_ctrl_idx];
        if !ctrl.active {
            return;
        }

        let tx_ptr = ctrl.tx_va as *mut u8;
        let mut buf = [0u8; OGM_SIZE + 8]; // room for TVLV
        let len = self.build_ogm(&mut buf, OGM_DEFAULT_TTL, TQ_MAX, self.mac);

        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), tx_ptr, len);
        }

        // XMIT to eth_srv: dst_mac=0 → broadcast, ethertype=0x4305.
        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            len as u64,
            0u64, // dst_mac=0 → broadcast
            (ETHERTYPE_BATMAN as u64) | ((xmit_reply as u64) << 16),
            ctrl.client_id,
        );
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);

        self.ogm_seqno = self.ogm_seqno.wrapping_add(1);
    }

    /// Re-broadcast a received OGM with decremented TTL and adjusted TQ.
    fn rebroadcast_ogm(&self, ogm: &[u8; OGM_SIZE], new_ttl: u8, new_tq: u8) {
        let ctrl = &self.downstream[self.bat_ctrl_idx];
        if !ctrl.active {
            return;
        }

        let tx_ptr = ctrl.tx_va as *mut u8;
        let mut buf = *ogm;
        buf[2] = new_ttl;
        buf[23] = new_tq;
        // Set prev_sender to our own MAC.
        buf[16..22].copy_from_slice(&self.mac);

        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), tx_ptr, OGM_SIZE);
        }

        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            OGM_SIZE as u64,
            0u64, // broadcast
            (ETHERTYPE_BATMAN as u64) | ((xmit_reply as u64) << 16),
            ctrl.client_id,
        );
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);
    }

    // ---------------------------------------------------------------
    // B.A.T.M.A.N. IV: OGM receive + table updates.
    // ---------------------------------------------------------------

    /// Process an incoming batman control frame from the 0x4305 channel.
    fn handle_bat_ctrl(&mut self, payload_len: usize, src_mac: [u8; 6]) {
        if payload_len < 2 {
            return;
        }
        let rx_ptr = self.downstream[self.bat_ctrl_idx].rx_va as *const u8;
        let ptype = unsafe { *rx_ptr };

        match ptype {
            BATMAN_PACKET_OGM => {
                if payload_len < OGM_SIZE {
                    return;
                }
                let mut ogm = [0u8; OGM_SIZE];
                unsafe {
                    core::ptr::copy_nonoverlapping(rx_ptr, ogm.as_mut_ptr(), OGM_SIZE);
                }
                self.handle_rx_ogm(&ogm, payload_len, src_mac);
            }
            BATMAN_PACKET_UNICAST => {
                self.handle_rx_unicast(payload_len);
            }
            BATMAN_PACKET_BCAST => {
                self.handle_rx_broadcast(payload_len, src_mac);
            }
            BATMAN_PACKET_ELP => {
                if payload_len >= ELP_SIZE {
                    self.handle_rx_elp(src_mac);
                }
            }
            BATMAN_PACKET_OGM2 => {
                if payload_len >= OGM2_SIZE {
                    self.handle_rx_ogm2(src_mac);
                }
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------------
    // Receive-side unicast decapsulation.
    // ---------------------------------------------------------------

    fn handle_rx_unicast(&mut self, payload_len: usize) {
        if payload_len < UNICAST_HDR_SIZE + INNER_ETH_HDR {
            return;
        }

        let rx_ptr = self.downstream[self.bat_ctrl_idx].rx_va as *const u8;
        let ttl = unsafe { *rx_ptr.add(2) };

        // Read destination originator MAC.
        let mut dest_orig = [0u8; 6];
        unsafe {
            core::ptr::copy_nonoverlapping(rx_ptr.add(4), dest_orig.as_mut_ptr(), 6);
        }

        // Is this frame for us?
        if dest_orig == self.mac {
            // Decapsulate: extract inner ethernet frame.
            let inner_start = UNICAST_HDR_SIZE; // offset 12
            let inner_len = payload_len - UNICAST_HDR_SIZE;
            self.deliver_inner_frame(rx_ptr, inner_start, inner_len);
        } else if ttl > 1 {
            // Relay: forward to next-hop with decremented TTL.
            if let Some(next_hop) = self.lookup_next_hop(dest_orig) {
                self.relay_unicast(payload_len, next_hop, ttl - 1);
            }
        }
    }

    /// Relay a unicast frame to the next-hop with updated TTL.
    fn relay_unicast(&self, payload_len: usize, next_hop: [u8; 6], new_ttl: u8) {
        let ctrl = &self.downstream[self.bat_ctrl_idx];
        if !ctrl.active {
            return;
        }

        // Copy entire frame from RX to TX, update TTL.
        unsafe {
            core::ptr::copy_nonoverlapping(
                ctrl.rx_va as *const u8,
                ctrl.tx_va as *mut u8,
                payload_len,
            );
            *(ctrl.tx_va as *mut u8).add(2) = new_ttl;
        }

        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            payload_len as u64,
            mac_to_u64(next_hop),
            (ETHERTYPE_BATMAN as u64) | ((xmit_reply as u64) << 16),
            ctrl.client_id,
        );
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);
    }

    // ---------------------------------------------------------------
    // Receive-side broadcast decapsulation.
    // ---------------------------------------------------------------

    fn handle_rx_broadcast(&mut self, payload_len: usize, _src_mac: [u8; 6]) {
        if payload_len < BCAST_HDR_SIZE + INNER_ETH_HDR {
            return;
        }

        let rx_ptr = self.downstream[self.bat_ctrl_idx].rx_va as *const u8;
        let ttl = unsafe { *rx_ptr.add(2) };

        // Read originator MAC and seqno.
        let mut orig = [0u8; 6];
        unsafe {
            core::ptr::copy_nonoverlapping(rx_ptr.add(4), orig.as_mut_ptr(), 6);
        }

        // Ignore our own broadcasts.
        if orig == self.mac {
            return;
        }

        let seqno = unsafe {
            (*rx_ptr.add(10) as u32)
                | ((*rx_ptr.add(11) as u32) << 8)
                | ((*rx_ptr.add(12) as u32) << 16)
                | ((*rx_ptr.add(13) as u32) << 24)
        };

        // Dedup check: if we've seen this (orig, seqno), drop it.
        if !self.bcast_dedup_check(orig, seqno) {
            return;
        }

        // Decapsulate: extract inner ethernet frame.
        let inner_start = BCAST_HDR_SIZE; // offset 14
        let inner_len = payload_len - BCAST_HDR_SIZE;
        self.deliver_inner_frame(rx_ptr, inner_start, inner_len);

        // Re-flood with TTL-1 if still alive.
        if ttl > 1 {
            self.reflood_broadcast(payload_len, ttl - 1);
        }
    }

    /// Re-flood a broadcast frame with updated TTL.
    fn reflood_broadcast(&self, payload_len: usize, new_ttl: u8) {
        let ctrl = &self.downstream[self.bat_ctrl_idx];
        if !ctrl.active {
            return;
        }

        unsafe {
            core::ptr::copy_nonoverlapping(
                ctrl.rx_va as *const u8,
                ctrl.tx_va as *mut u8,
                payload_len,
            );
            *(ctrl.tx_va as *mut u8).add(2) = new_ttl;
        }

        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            payload_len as u64,
            0u64, // broadcast
            (ETHERTYPE_BATMAN as u64) | ((xmit_reply as u64) << 16),
            ctrl.client_id,
        );
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);
    }

    // ---------------------------------------------------------------
    // Inner frame delivery to upstream clients.
    // ---------------------------------------------------------------

    /// Extract inner ethernet frame and deliver payload to the correct
    /// upstream client based on inner ethertype.
    fn deliver_inner_frame(&self, rx_ptr: *const u8, inner_start: usize, inner_len: usize) {
        if inner_len < INNER_ETH_HDR {
            return;
        }

        // Parse inner ethernet header.
        let mut inner_src = [0u8; 6];
        unsafe {
            // inner_dst at inner_start+0 (6 bytes) — we don't need it
            core::ptr::copy_nonoverlapping(rx_ptr.add(inner_start + 6), inner_src.as_mut_ptr(), 6);
        }
        let inner_ethertype = unsafe {
            ((*rx_ptr.add(inner_start + 12) as u16) << 8) | (*rx_ptr.add(inner_start + 13) as u16)
        };
        let payload_start = inner_start + INNER_ETH_HDR;
        let payload_len = inner_len - INNER_ETH_HDR;

        // Find upstream client for this ethertype.
        let up_idx = match self.upstream.iter().position(|u| u.active && u.ethertype == inner_ethertype) {
            Some(i) => i,
            None => return,
        };

        if payload_len == 0 {
            return;
        }

        // Copy payload to upstream client's RX grant page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                rx_ptr.add(payload_start),
                self.upstream[up_idx].rx_va as *mut u8,
                payload_len.min(MTU),
            );
        }

        // Send NETIF_INPUT to upstream client.
        syscall::send(
            self.upstream[up_idx].port,
            NETIF_INPUT,
            payload_len.min(MTU) as u64,
            mac_to_u64(inner_src),
            0, 0,
        );
    }

    // ---------------------------------------------------------------
    // Broadcast dedup ring buffer.
    // ---------------------------------------------------------------

    /// Check if (orig, seqno) is new. Returns true if new (not a dup),
    /// and adds it to the ring buffer.
    fn bcast_dedup_check(&mut self, orig: [u8; 6], seqno: u32) -> bool {
        // Search ring for duplicate.
        for i in 0..BCAST_DEDUP_SIZE {
            if self.bcast_dedup_orig[i] == orig && self.bcast_dedup_seq[i] == seqno {
                return false; // duplicate
            }
        }
        // Not found — add to ring.
        let h = self.bcast_dedup_head;
        self.bcast_dedup_orig[h] = orig;
        self.bcast_dedup_seq[h] = seqno;
        self.bcast_dedup_head = (h + 1) % BCAST_DEDUP_SIZE;
        true
    }

    /// Parse and process a received OGMv1 packet.
    fn handle_rx_ogm(&mut self, ogm: &[u8; OGM_SIZE], payload_len: usize, src_mac: [u8; 6]) {
        let _version = ogm[1];
        let ttl = ogm[2];
        let seqno = (ogm[6] as u32)
            | ((ogm[7] as u32) << 8)
            | ((ogm[8] as u32) << 16)
            | ((ogm[9] as u32) << 24);
        let mut orig = [0u8; 6];
        orig.copy_from_slice(&ogm[10..16]);
        let mut prev_sender = [0u8; 6];
        prev_sender.copy_from_slice(&ogm[16..22]);
        let tq = ogm[23];
        let tvlv_len = (ogm[24] as usize) | ((ogm[25] as usize) << 8);

        // Ignore our own OGMs.
        if orig == self.mac {
            return;
        }

        // Ignore if TQ is zero (dead route).
        if tq == 0 {
            return;
        }

        let now = syscall::clock_gettime();

        // Update neighbor table for the direct sender (src_mac from Ethernet).
        let neigh_tq = self.update_neighbor(src_mac, seqno, now);

        // Compute path TQ: incoming TQ * local link quality.
        let path_tq = if neigh_tq > 0 {
            ((tq as u32) * (neigh_tq as u32) / (TQ_MAX as u32)) as u8
        } else {
            0
        };

        if path_tq == 0 {
            return;
        }

        // Update originator table.
        self.update_originator(orig, src_mac, path_tq, seqno, now);

        // Parse TVLVs for gateway announcements.
        if tvlv_len > 0 && payload_len >= OGM_SIZE + tvlv_len {
            self.parse_tvlv_gw(orig, src_mac, path_tq, 0, now, OGM_SIZE, tvlv_len);
        }

        // Rebroadcast with decremented TTL if still alive.
        if ttl > 1 {
            self.rebroadcast_ogm(ogm, ttl - 1, path_tq);
        }

        // Debug output (only on new/changed originators).
        syscall::debug_puts(b"  [batman_srv] OGM: orig=");
        print_mac(orig);
        syscall::debug_puts(b" via=");
        print_mac(src_mac);
        syscall::debug_puts(b" tq=");
        print_num(path_tq as u64);
        syscall::debug_puts(b" seq=");
        print_num(seqno as u64);
        syscall::debug_puts(b"\n");
    }

    /// Update or insert a neighbor entry. Returns the neighbor's receive TQ.
    fn update_neighbor(&mut self, mac: [u8; 6], seqno: u32, now: u64) -> u8 {
        // Find existing neighbor or free slot.
        let mut idx = None;
        let mut free = None;
        for i in 0..MAX_NEIGHBORS {
            if self.neighbors[i].active && self.neighbors[i].mac == mac {
                idx = Some(i);
                break;
            }
            if !self.neighbors[i].active && free.is_none() {
                free = Some(i);
            }
        }

        let i = match idx {
            Some(i) => i,
            None => match free {
                Some(f) => {
                    self.neighbors[f] = Neighbor {
                        active: true,
                        mac,
                        last_seen_ns: now,
                        rx_window: 1,
                        last_seqno: seqno,
                        tq_recv: TQ_MAX,
                        elp_window: 0,
                        elp_last_seqno: 0,
                        throughput: 0,
                    };
                    syscall::debug_puts(b"  [batman_srv] new neighbor: ");
                    print_mac(mac);
                    syscall::debug_puts(b"\n");
                    return TQ_MAX;
                }
                None => return 0, // table full
            },
        };

        let n = &mut self.neighbors[i];
        n.last_seen_ns = now;

        // Sliding window update: shift by the seqno difference.
        let diff = seqno.wrapping_sub(n.last_seqno);
        if diff == 0 {
            // Duplicate — already counted.
            return n.tq_recv;
        }
        if diff <= 64 {
            // Forward seqno: shift window and mark this one received.
            n.rx_window = if diff >= 64 { 0 } else { n.rx_window << diff };
            n.rx_window |= 1;
            n.last_seqno = seqno;
        } else if diff > 0xFFFF_FF00 {
            // Slightly old (wrapped): mark bit if within window.
            let back = seqno.wrapping_sub(n.last_seqno.wrapping_sub(63));
            if (back as usize) < 64 {
                n.rx_window |= 1u64 << back;
            }
        }
        // else: very old or very far ahead — ignore for window purposes.

        // Compute TQ from window population count.
        let ones = n.rx_window.count_ones();
        n.tq_recv = ((ones as u32 * TQ_MAX as u32) / TQ_LOCAL_WINDOW_SIZE) as u8;
        n.tq_recv
    }

    /// Update or insert an originator entry.
    fn update_originator(
        &mut self,
        orig: [u8; 6],
        next_hop: [u8; 6],
        tq: u8,
        seqno: u32,
        now: u64,
    ) {
        // Find existing entry or free slot.
        let mut idx = None;
        let mut free = None;
        for i in 0..MAX_ORIGINATORS {
            if self.originators[i].active && self.originators[i].orig_mac == orig {
                idx = Some(i);
                break;
            }
            if !self.originators[i].active && free.is_none() {
                free = Some(i);
            }
        }

        match idx {
            Some(i) => {
                let o = &mut self.originators[i];
                // Accept if newer seqno, or same seqno with better TQ.
                let sdiff = seqno.wrapping_sub(o.last_seqno);
                if sdiff > 0 && sdiff < 0x8000_0000 {
                    // Newer seqno — always accept.
                    o.best_next_hop = next_hop;
                    o.best_tq = tq;
                    o.last_seqno = seqno;
                    o.last_seen_ns = now;
                } else if sdiff == 0 && tq > o.best_tq {
                    // Same seqno, better TQ.
                    o.best_next_hop = next_hop;
                    o.best_tq = tq;
                    o.last_seen_ns = now;
                }
                // Else: older seqno or worse TQ — ignore.
            }
            None => {
                if let Some(f) = free {
                    self.originators[f] = Originator {
                        active: true,
                        orig_mac: orig,
                        best_next_hop: next_hop,
                        best_tq: tq,
                        best_throughput: 0,
                        last_seqno: seqno,
                        last_seen_ns: now,
                    };
                    syscall::debug_puts(b"  [batman_srv] new originator: ");
                    print_mac(orig);
                    syscall::debug_puts(b" via ");
                    print_mac(next_hop);
                    syscall::debug_puts(b" tq=");
                    print_num(tq as u64);
                    syscall::debug_puts(b"\n");
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Purge stale neighbors and originators.
    // ---------------------------------------------------------------

    fn purge_stale(&mut self, now: u64) {
        for n in self.neighbors.iter_mut() {
            if n.active && now.wrapping_sub(n.last_seen_ns) > OGM_PURGE_NS {
                syscall::debug_puts(b"  [batman_srv] purge neighbor: ");
                print_mac(n.mac);
                syscall::debug_puts(b"\n");
                n.active = false;
            }
        }
        for o in self.originators.iter_mut() {
            if o.active && now.wrapping_sub(o.last_seen_ns) > OGM_PURGE_NS {
                syscall::debug_puts(b"  [batman_srv] purge originator: ");
                print_mac(o.orig_mac);
                syscall::debug_puts(b"\n");
                o.active = false;
            }
        }
        for gw in self.gateways.iter_mut() {
            if gw.active && now.wrapping_sub(gw.last_seen_ns) > OGM_PURGE_NS {
                syscall::debug_puts(b"  [batman_srv] purge gateway: ");
                print_mac(gw.orig_mac);
                syscall::debug_puts(b"\n");
                gw.active = false;
            }
        }
    }

    // ---------------------------------------------------------------
    // Gateway support.
    // ---------------------------------------------------------------

    /// Parse TVLV area from an OGM for gateway announcements.
    /// `tvlv_start` is the byte offset into the rx buffer where TVLVs begin.
    /// `tvlv_len` is the total TVLV area length.
    fn parse_tvlv_gw(
        &mut self,
        orig: [u8; 6],
        next_hop: [u8; 6],
        tq: u8,
        throughput: u32,
        now: u64,
        tvlv_start: usize,
        tvlv_len: usize,
    ) {
        if tvlv_len < 6 {
            return; // minimum: type(1) + version(1) + length(2) + payload(2)
        }
        let rx_ptr = self.downstream[self.bat_ctrl_idx].rx_va as *const u8;
        let mut off = tvlv_start;
        let end = tvlv_start + tvlv_len;

        while off + 4 <= end {
            let ttype = unsafe { *rx_ptr.add(off) };
            let _tver = unsafe { *rx_ptr.add(off + 1) };
            let tlen = unsafe {
                (*rx_ptr.add(off + 2) as usize) | ((*rx_ptr.add(off + 3) as usize) << 8)
            };
            off += 4;
            if off + tlen > end {
                break;
            }

            if ttype == TVLV_GW_TYPE && tlen >= 4 {
                let down = unsafe {
                    (*rx_ptr.add(off) as u16) | ((*rx_ptr.add(off + 1) as u16) << 8)
                };
                let up = unsafe {
                    (*rx_ptr.add(off + 2) as u16) | ((*rx_ptr.add(off + 3) as u16) << 8)
                };
                self.update_gateway(orig, next_hop, down, up, tq, throughput, now);
            }

            off += tlen;
        }
    }

    /// Update or insert a gateway entry.
    fn update_gateway(
        &mut self,
        orig: [u8; 6],
        next_hop: [u8; 6],
        down_speed: u16,
        up_speed: u16,
        tq: u8,
        throughput: u32,
        now: u64,
    ) {
        let mut idx = None;
        let mut free = None;
        for i in 0..MAX_GATEWAYS {
            if self.gateways[i].active && self.gateways[i].orig_mac == orig {
                idx = Some(i);
                break;
            }
            if !self.gateways[i].active && free.is_none() {
                free = Some(i);
            }
        }

        match idx {
            Some(i) => {
                let gw = &mut self.gateways[i];
                gw.next_hop = next_hop;
                gw.down_speed = down_speed;
                gw.up_speed = up_speed;
                gw.tq = tq;
                gw.throughput = throughput;
                gw.last_seen_ns = now;
            }
            None => {
                if let Some(f) = free {
                    self.gateways[f] = Gateway {
                        active: true,
                        orig_mac: orig,
                        next_hop,
                        down_speed,
                        up_speed,
                        tq,
                        throughput,
                        last_seen_ns: now,
                    };
                    syscall::debug_puts(b"  [batman_srv] new gateway: ");
                    print_mac(orig);
                    syscall::debug_puts(b" down=");
                    print_num(down_speed as u64);
                    syscall::debug_puts(b" up=");
                    print_num(up_speed as u64);
                    syscall::debug_puts(b"\n");
                }
            }
        }
    }

    /// Select the best gateway (highest TQ in IV mode, highest throughput in V).
    fn best_gateway(&self) -> Option<[u8; 6]> {
        let mut best_idx: Option<usize> = None;
        let mut best_score: u64 = 0;

        for i in 0..MAX_GATEWAYS {
            if !self.gateways[i].active {
                continue;
            }
            let score = if BATMAN_MODE == BATMAN_MODE_IV {
                self.gateways[i].tq as u64 * self.gateways[i].down_speed as u64
            } else {
                self.gateways[i].throughput as u64
            };
            if score > best_score {
                best_score = score;
                best_idx = Some(i);
            }
        }

        best_idx.map(|i| self.gateways[i].next_hop)
    }

    /// Build the TVLV gateway announcement bytes (8 bytes: header + payload).
    /// Returns number of bytes written.
    fn build_gw_tvlv(&self, buf: &mut [u8]) -> usize {
        if buf.len() < 8 || !self.is_gateway {
            return 0;
        }
        buf[0] = TVLV_GW_TYPE;  // type
        buf[1] = 1;              // version
        buf[2] = TVLV_GW_LEN;   // length low byte
        buf[3] = 0;              // length high byte
        buf[4] = GW_DOWN_SPEED as u8;
        buf[5] = (GW_DOWN_SPEED >> 8) as u8;
        buf[6] = GW_UP_SPEED as u8;
        buf[7] = (GW_UP_SPEED >> 8) as u8;
        8
    }

    // ---------------------------------------------------------------
    // OGM timer tick (called from main loop).
    // ---------------------------------------------------------------

    fn tick_ogm(&mut self) {
        let now = syscall::clock_gettime();
        if BATMAN_MODE == BATMAN_MODE_IV {
            if now.wrapping_sub(self.last_ogm_ns) >= OGM_INTERVAL_NS {
                self.send_ogm();
                self.last_ogm_ns = now;
            }
        } else {
            // B.A.T.M.A.N. V: ELP for neighbor discovery, OGMv2 for routing.
            if now.wrapping_sub(self.last_elp_ns) >= ELP_INTERVAL_NS {
                self.send_elp();
                self.last_elp_ns = now;
            }
            if now.wrapping_sub(self.last_ogm_ns) >= OGM_INTERVAL_NS {
                self.send_ogm2();
                self.last_ogm_ns = now;
            }
        }
        // Purge every ~10 intervals.
        if self.ogm_seqno.wrapping_add(self.ogm2_seqno) % 10 == 0 {
            self.purge_stale(now);
        }
    }

    // ---------------------------------------------------------------
    // B.A.T.M.A.N. V: ELP (Echo Location Protocol).
    // ---------------------------------------------------------------

    /// Build and broadcast an 18-byte ELP packet for neighbor discovery.
    fn send_elp(&mut self) {
        let ctrl = &self.downstream[self.bat_ctrl_idx];
        if !ctrl.active {
            return;
        }

        let tx = ctrl.tx_va as *mut u8;
        unsafe {
            // ELP header [0..18]
            *tx.add(0) = BATMAN_PACKET_ELP;   // packet_type
            *tx.add(1) = BATMAN_VERSION;       // version
            *tx.add(2) = 0;                    // reserved
            *tx.add(3) = 0;                    // reserved
            // [4..10] originator MAC
            core::ptr::copy_nonoverlapping(self.mac.as_ptr(), tx.add(4), 6);
            // [10..14] seqno (u32 LE)
            let s = self.elp_seqno;
            *tx.add(10) = s as u8;
            *tx.add(11) = (s >> 8) as u8;
            *tx.add(12) = (s >> 16) as u8;
            *tx.add(13) = (s >> 24) as u8;
            // [14..18] interval (u32 LE, milliseconds)
            let interval_ms = (ELP_INTERVAL_NS / 1_000_000) as u32;
            *tx.add(14) = interval_ms as u8;
            *tx.add(15) = (interval_ms >> 8) as u8;
            *tx.add(16) = (interval_ms >> 16) as u8;
            *tx.add(17) = (interval_ms >> 24) as u8;
        }

        self.elp_seqno = self.elp_seqno.wrapping_add(1);

        // Broadcast ELP via 0x4305.
        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            ELP_SIZE as u64,
            0u64, // broadcast
            (ETHERTYPE_BATMAN as u64) | ((xmit_reply as u64) << 16),
            ctrl.client_id,
        );
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);
    }

    /// Process a received ELP packet. Updates neighbor's throughput estimate.
    fn handle_rx_elp(&mut self, src_mac: [u8; 6]) {
        let rx_ptr = self.downstream[self.bat_ctrl_idx].rx_va as *const u8;

        let mut orig = [0u8; 6];
        unsafe { core::ptr::copy_nonoverlapping(rx_ptr.add(4), orig.as_mut_ptr(), 6); }

        // Ignore our own ELPs.
        if orig == self.mac {
            return;
        }

        let seqno = unsafe {
            (*rx_ptr.add(10) as u32)
                | ((*rx_ptr.add(11) as u32) << 8)
                | ((*rx_ptr.add(12) as u32) << 16)
                | ((*rx_ptr.add(13) as u32) << 24)
        };

        let now = syscall::clock_gettime();

        // Find or create neighbor.
        let mut idx = None;
        let mut free = None;
        for i in 0..MAX_NEIGHBORS {
            if self.neighbors[i].active && self.neighbors[i].mac == src_mac {
                idx = Some(i);
                break;
            }
            if !self.neighbors[i].active && free.is_none() {
                free = Some(i);
            }
        }

        let i = match idx {
            Some(i) => i,
            None => match free {
                Some(f) => {
                    self.neighbors[f] = Neighbor {
                        active: true,
                        mac: src_mac,
                        last_seen_ns: now,
                        rx_window: 0,
                        last_seqno: 0,
                        tq_recv: 0,
                        elp_window: 1,
                        elp_last_seqno: seqno,
                        throughput: DEFAULT_THROUGHPUT,
                    };
                    syscall::debug_puts(b"  [batman_srv] new ELP neighbor: ");
                    print_mac(src_mac);
                    syscall::debug_puts(b"\n");
                    return;
                }
                None => return,
            },
        };

        let n = &mut self.neighbors[i];
        n.last_seen_ns = now;

        // Update ELP sliding window.
        let diff = seqno.wrapping_sub(n.elp_last_seqno);
        if diff == 0 {
            return; // duplicate
        }
        if diff <= 32 {
            n.elp_window = if diff >= 32 { 0 } else { n.elp_window << diff };
            n.elp_window |= 1;
            n.elp_last_seqno = seqno;
        }

        // Estimate throughput from packet reception ratio.
        let ones = n.elp_window.count_ones();
        n.throughput = (DEFAULT_THROUGHPUT as u64 * ones as u64 / ELP_WINDOW_SIZE as u64) as u32;
    }

    // ---------------------------------------------------------------
    // B.A.T.M.A.N. V: OGMv2 (throughput-based routing).
    // ---------------------------------------------------------------

    /// Build and broadcast a 24-byte OGMv2 packet.
    fn send_ogm2(&mut self) {
        let ctrl = &self.downstream[self.bat_ctrl_idx];
        if !ctrl.active {
            return;
        }

        let tx = ctrl.tx_va as *mut u8;
        unsafe {
            // OGMv2 header [0..24]
            *tx.add(0) = BATMAN_PACKET_OGM2;  // packet_type
            *tx.add(1) = BATMAN_VERSION;       // version
            *tx.add(2) = OGM_DEFAULT_TTL;      // ttl
            *tx.add(3) = 0;                    // reserved
            // [4..6] flags (u16)
            *tx.add(4) = 0;
            *tx.add(5) = 0;
            // [6..10] seqno (u32 LE)
            let s = self.ogm2_seqno;
            *tx.add(6) = s as u8;
            *tx.add(7) = (s >> 8) as u8;
            *tx.add(8) = (s >> 16) as u8;
            *tx.add(9) = (s >> 24) as u8;
            // [10..16] originator MAC
            core::ptr::copy_nonoverlapping(self.mac.as_ptr(), tx.add(10), 6);
            // [16..18] tvlv_len + pad
            *tx.add(16) = 0;
            *tx.add(17) = 0;
            *tx.add(18) = 0;
            *tx.add(19) = 0;
            // [20..24] throughput (u32 LE, units of 100 Kbit/s)
            let tp = DEFAULT_THROUGHPUT;
            *tx.add(20) = tp as u8;
            *tx.add(21) = (tp >> 8) as u8;
            *tx.add(22) = (tp >> 16) as u8;
            *tx.add(23) = (tp >> 24) as u8;
        }

        self.ogm2_seqno = self.ogm2_seqno.wrapping_add(1);

        // Broadcast OGMv2 via 0x4305.
        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            OGM2_SIZE as u64,
            0u64, // broadcast
            (ETHERTYPE_BATMAN as u64) | ((xmit_reply as u64) << 16),
            ctrl.client_id,
        );
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);
    }

    /// Process a received OGMv2 packet. Throughput-based route selection.
    fn handle_rx_ogm2(&mut self, src_mac: [u8; 6]) {
        let rx_ptr = self.downstream[self.bat_ctrl_idx].rx_va as *const u8;

        let ttl = unsafe { *rx_ptr.add(2) };
        let seqno = unsafe {
            (*rx_ptr.add(6) as u32)
                | ((*rx_ptr.add(7) as u32) << 8)
                | ((*rx_ptr.add(8) as u32) << 16)
                | ((*rx_ptr.add(9) as u32) << 24)
        };
        let mut orig = [0u8; 6];
        unsafe { core::ptr::copy_nonoverlapping(rx_ptr.add(10), orig.as_mut_ptr(), 6); }
        let path_throughput = unsafe {
            (*rx_ptr.add(20) as u32)
                | ((*rx_ptr.add(21) as u32) << 8)
                | ((*rx_ptr.add(22) as u32) << 16)
                | ((*rx_ptr.add(23) as u32) << 24)
        };

        // Ignore our own OGMv2s.
        if orig == self.mac {
            return;
        }

        if path_throughput == 0 {
            return;
        }

        let now = syscall::clock_gettime();

        // Get neighbor's link throughput for the minimum calculation.
        let link_tp = {
            let mut tp = 0u32;
            for n in &self.neighbors {
                if n.active && n.mac == src_mac {
                    tp = n.throughput;
                    break;
                }
            }
            tp
        };

        if link_tp == 0 {
            return;
        }

        // Path metric: minimum throughput along the path.
        // OGMv2 carries the min-throughput so far; we take the min of that
        // and our link to the sender.
        let min_tp = path_throughput.min(link_tp);

        // Update originator table (V mode: maximize minimum throughput).
        self.update_originator_v(orig, src_mac, min_tp, seqno, now);

        // Rebroadcast with updated throughput and decremented TTL.
        if ttl > 1 {
            self.rebroadcast_ogm2(min_tp, ttl - 1);
        }

        syscall::debug_puts(b"  [batman_srv] OGMv2: orig=");
        print_mac(orig);
        syscall::debug_puts(b" tp=");
        print_num(min_tp as u64);
        syscall::debug_puts(b" seq=");
        print_num(seqno as u64);
        syscall::debug_puts(b"\n");
    }

    /// Update originator table for V mode (throughput-based).
    fn update_originator_v(
        &mut self,
        orig: [u8; 6],
        next_hop: [u8; 6],
        throughput: u32,
        seqno: u32,
        now: u64,
    ) {
        let mut idx = None;
        let mut free = None;
        for i in 0..MAX_ORIGINATORS {
            if self.originators[i].active && self.originators[i].orig_mac == orig {
                idx = Some(i);
                break;
            }
            if !self.originators[i].active && free.is_none() {
                free = Some(i);
            }
        }

        match idx {
            Some(i) => {
                let o = &mut self.originators[i];
                let sdiff = seqno.wrapping_sub(o.last_seqno);
                if sdiff > 0 && sdiff < 0x8000_0000 {
                    // Newer seqno — always accept.
                    o.best_next_hop = next_hop;
                    o.best_throughput = throughput;
                    o.last_seqno = seqno;
                    o.last_seen_ns = now;
                } else if sdiff == 0 && throughput > o.best_throughput {
                    // Same seqno, better throughput — prefer this path.
                    o.best_next_hop = next_hop;
                    o.best_throughput = throughput;
                    o.last_seen_ns = now;
                }
            }
            None => {
                if let Some(f) = free {
                    self.originators[f] = Originator {
                        active: true,
                        orig_mac: orig,
                        best_next_hop: next_hop,
                        best_tq: 0,
                        best_throughput: throughput,
                        last_seqno: seqno,
                        last_seen_ns: now,
                    };
                    syscall::debug_puts(b"  [batman_srv] new originator (V): ");
                    print_mac(orig);
                    syscall::debug_puts(b" tp=");
                    print_num(throughput as u64);
                    syscall::debug_puts(b"\n");
                }
            }
        }
    }

    /// Rebroadcast a received OGMv2 with updated throughput and TTL.
    fn rebroadcast_ogm2(&self, new_throughput: u32, new_ttl: u8) {
        let ctrl = &self.downstream[self.bat_ctrl_idx];
        if !ctrl.active {
            return;
        }

        // Copy OGMv2 from RX to TX, update TTL and throughput.
        unsafe {
            core::ptr::copy_nonoverlapping(
                ctrl.rx_va as *const u8,
                ctrl.tx_va as *mut u8,
                OGM2_SIZE,
            );
            let tx = ctrl.tx_va as *mut u8;
            *tx.add(2) = new_ttl;
            *tx.add(20) = new_throughput as u8;
            *tx.add(21) = (new_throughput >> 8) as u8;
            *tx.add(22) = (new_throughput >> 16) as u8;
            *tx.add(23) = (new_throughput >> 24) as u8;
        }

        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            OGM2_SIZE as u64,
            0u64, // broadcast
            (ETHERTYPE_BATMAN as u64) | ((xmit_reply as u64) << 16),
            ctrl.client_id,
        );
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);
    }
}

// -------------------------------------------------------------------
// Main entry point.
// -------------------------------------------------------------------

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [batman_srv] starting\n");

    // Step 1: Wait for eth_srv.
    let eth_port = match syscall::ns_lookup_wait(b"eth") {
        Some(p) => p,
        None => {
            syscall::debug_puts(b"  [batman_srv] eth service not found\n");
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [batman_srv] found eth_srv on port ");
    print_num(eth_port);
    syscall::debug_puts(b"\n");

    // Step 2: Query MAC from eth_srv.
    let rp = syscall::port_create();
    syscall::send_nb(eth_port, NETIF_STATUS, rp, 0);
    let mac = if let Some(msg) = syscall::recv_msg_timeout(rp, 2_000_000) {
        if msg.tag == NETIF_STATUS_OK {
            u64_to_mac(msg.data[0])
        } else {
            [0; 6]
        }
    } else {
        [0; 6]
    };
    syscall::port_destroy(rp);

    syscall::debug_puts(b"  [batman_srv] MAC=");
    print_mac(mac);
    syscall::debug_puts(b"\n");

    // Step 3: Create our upstream IPC port.
    let my_port = syscall::port_create();

    // Step 4: Initialize device state.
    let mut dev = BatmanDev {
        eth_port,
        my_port,
        mac,
        downstream: [const { DownstreamConn::new() }; MAX_DOWNSTREAM],
        upstream: [const { UpstreamClient::new() }; MAX_UPSTREAM],
        ogm_seqno: 0,
        neighbors: [const { Neighbor::new() }; MAX_NEIGHBORS],
        originators: [const { Originator::new() }; MAX_ORIGINATORS],
        last_ogm_ns: 0,
        bat_ctrl_idx: 0,
        elp_seqno: 0,
        last_elp_ns: 0,
        ogm2_seqno: 0,
        gateways: [const { Gateway::new() }; MAX_GATEWAYS],
        is_gateway: false,
        bcast_seqno: 0,
        bcast_dedup_orig: [[0u8; 6]; BCAST_DEDUP_SIZE],
        bcast_dedup_seq: [0u32; BCAST_DEDUP_SIZE],
        bcast_dedup_head: 0,
    };

    // Step 5: Register for B.A.T.M.A.N. control frames (0x4305) with eth_srv.
    // This is our dedicated batman control channel for OGMs etc.
    match dev.register_downstream(ETHERTYPE_BATMAN) {
        Some(idx) => {
            dev.bat_ctrl_idx = idx;
            syscall::debug_puts(b"  [batman_srv] batman control channel ready (0x4305)\n");
        }
        None => {
            syscall::debug_puts(b"  [batman_srv] WARNING: failed to register 0x4305\n");
        }
    }

    // Step 6: Register as "bat0" so tcp4_srv/ip6_srv can find us.
    syscall::ns_register(b"bat0", my_port);
    syscall::debug_puts(b"  [batman_srv] registered as 'bat0' on port ");
    print_num(my_port);
    syscall::debug_puts(b"\n");

    // -------------------------------------------------------------------
    // Main service loop (poll-based, matching eth_srv pattern).
    // -------------------------------------------------------------------
    loop {
        // Poll downstream channels: NETIF_INPUT from eth_srv.
        for di in 0..MAX_DOWNSTREAM {
            if !dev.downstream[di].active {
                continue;
            }
            let down_port = dev.downstream[di].port;
            while let Some(msg) = syscall::recv_nb_msg(down_port) {
                if msg.tag == NETIF_INPUT {
                    let plen = msg.data[0] as usize;
                    let src_mac_val = msg.data[1];
                    if dev.downstream[di].ethertype == ETHERTYPE_BATMAN {
                        let src_mac = u64_to_mac(src_mac_val);
                        dev.handle_bat_ctrl(plen, src_mac);
                    } else {
                        dev.handle_input(di, plen, src_mac_val);
                    }
                }
            }
        }

        // Poll upstream client requests.
        while let Some(msg) = syscall::recv_nb_msg(my_port) {
            match msg.tag {
                NETIF_REGISTER => {
                    let ethertype = msg.data[0] as u16;
                    let client_port = msg.data[1];
                    let reply_port = msg.data[2];
                    dev.handle_register(ethertype, client_port, reply_port);
                }
                NETIF_XMIT => {
                    let payload_len = msg.data[0] as usize;
                    let dst_mac_val = msg.data[1];
                    let ethertype = msg.data[2] as u16;
                    let reply_port = msg.data[2] >> 16;
                    let client_id = msg.data[3] as usize;
                    dev.handle_xmit(client_id, payload_len, dst_mac_val, ethertype, reply_port);
                }
                NETIF_RESOLVE => {
                    let ip_be = msg.data[0] as u32;
                    let reply_port = msg.data[1];
                    dev.handle_resolve(ip_be, reply_port);
                }
                NETIF_STATUS => {
                    let reply_port = msg.data[0];
                    dev.handle_status(reply_port);
                }
                BAT_STATUS => {
                    let reply_port = msg.data[0];
                    dev.handle_bat_status(reply_port);
                }
                _ => {}
            }
        }

        // B.A.T.M.A.N. IV: periodic OGM broadcast + purge.
        dev.tick_ogm();

        syscall::yield_now();
    }
}
