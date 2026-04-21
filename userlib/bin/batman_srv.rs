#![no_std]
#![no_main]
#![cfg_attr(target_arch = "mips64", feature(asm_experimental_arch))]

//! B.A.T.M.A.N. Layer 2 Mesh Routing Server (batman-adv style).
//!
//! Acts as a transparent NETIF proxy between eth_srv and upper-layer
//! protocol services (tcp4_srv, ip6_srv). Registers as "bat0".
//!
//! Phase 1: Transparent pass-through (no encapsulation).
//! Phase 2+: OGM generation, neighbor discovery, mesh routing.

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

/// Main device state.
struct BatmanDev {
    eth_port: u64,
    my_port: u64,
    mac: [u8; 6],
    downstream: [DownstreamConn; MAX_DOWNSTREAM],
    upstream: [UpstreamClient; MAX_UPSTREAM],
    ogm_seqno: u32,
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
    // ---------------------------------------------------------------

    fn handle_xmit(&mut self, client_id: usize, payload_len: usize,
                    dst_mac_val: u64, ethertype: u16, reply_port: u64) {
        if client_id >= MAX_UPSTREAM || !self.upstream[client_id].active {
            return;
        }
        if payload_len > MTU {
            return;
        }

        let down_idx = self.upstream[client_id].downstream_idx;
        if !self.downstream[down_idx].active {
            return;
        }

        let down = &self.downstream[down_idx];

        // Copy payload from upstream client's TX grant page to downstream TX grant page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.upstream[client_id].tx_va as *const u8,
                down.tx_va as *mut u8,
                payload_len,
            );
        }

        // Forward NETIF_XMIT to eth_srv.
        let xmit_reply = syscall::port_create();
        syscall::send_nb_4(
            self.eth_port,
            NETIF_XMIT,
            payload_len as u64,                              // data[0]
            dst_mac_val,                                      // data[1]
            (ethertype as u64) | ((xmit_reply as u64) << 16), // data[2]
            down.client_id,                                   // data[3]
        );
        // Wait for XMIT_OK from eth_srv.
        let _ = syscall::recv_msg_timeout(xmit_reply, 500_000);
        syscall::port_destroy(xmit_reply);

        // Reply to upstream client.
        syscall::send_nb(reply_port, NETIF_XMIT_OK, 0, 0);
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
        syscall::send_nb(
            reply_port,
            NETIF_STATUS_OK,
            mac_to_u64(self.mac),
            MTU as u64 | (1u64 << 32), // mtu | link_up flag
        );
    }

    // ---------------------------------------------------------------
    // BAT_STATUS → reply with mesh state.
    // ---------------------------------------------------------------

    fn handle_bat_status(&self, reply_port: u64) {
        // Phase 1: just report we're alive with OGM seqno.
        let d0 = 0u64;                     // originator_count
        let d1 = 0u64;                     // neighbor_count
        let d2 = self.ogm_seqno as u64;    // ogm_seqno
        syscall::send_nb_4(reply_port, BAT_STATUS_OK, d0, d1, d2, 0);
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
    };

    // Step 5: Register for B.A.T.M.A.N. control frames (0x4305) with eth_srv.
    // This is our dedicated batman control channel for OGMs etc.
    if dev.register_downstream(ETHERTYPE_BATMAN).is_some() {
        syscall::debug_puts(b"  [batman_srv] batman control channel ready (0x4305)\n");
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
                        // TODO Phase 2: process OGM / batman control frame.
                        let _ = (plen, src_mac_val);
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

        // TODO Phase 2: tick OGM timers, send periodic OGMs.

        syscall::yield_now();
    }
}
