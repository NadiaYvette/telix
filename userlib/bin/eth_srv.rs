#![no_std]
#![no_main]

// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024-2026 Nadia Chambers
// Reference codebases: Linux networking stack (protocol semantics, virtio-net)

//! Ethernet link-layer server: virtio-net driver + ARP + netif IPC.
//!
//! Receives device info (mmio_base/bar0, irq) via arg0 from the kernel.
//! Maps MMIO registers, sets up RX/TX virtqueues, handles ARP at L2,
//! and dispatches inbound frames by ethertype to registered upper-layer
//! servers (e.g. ip6_srv) via the netif IPC protocol.
//!
//! ## Netif IPC protocol
//!
//! Upper-layer servers register with eth_srv to receive frames for a given
//! ethertype. Packet data is exchanged via grant pages (one RX page, one TX
//! page per client) to avoid copying frame payloads through IPC messages.
//!
//! - `NETIF_REGISTER` (0x5000): Register for an ethertype.
//!     data[0] = ethertype (e.g. 0x86DD for IPv6)
//!     data[1] = reply_port
//!   Reply: `NETIF_REGISTER_OK` with data[0] = client_id, data[1] = rx_grant_va,
//!          data[2] = tx_grant_va. The registrant must grant pages at those VAs.
//!
//! - `NETIF_INPUT` (0x5100): eth_srv → client. Frame payload available at rx_grant_va.
//!     data[0] = payload_len
//!     data[1] = src_mac (6 bytes LE-packed in low 48 bits)
//!
//! - `NETIF_XMIT` (0x5200): client → eth_srv. Transmit frame from tx_grant_va.
//!     data[0] = payload_len
//!     data[1] = dst_mac (6 bytes LE-packed, or 0 for broadcast)
//!     data[2] = ethertype
//!
//! - `NETIF_RESOLVE` (0x5300): client → eth_srv. ARP resolve request.
//!     data[0] = IPv4 address (big-endian u32)
//!     data[1] = reply_port
//!   Reply: `NETIF_RESOLVE_OK` with data[0] = MAC (6 bytes LE-packed)
//!          or `NETIF_RESOLVE_FAIL`
//!
//! - `NETIF_STATUS` (0x5400): Query link status.
//!     data[0] = reply_port
//!   Reply: `NETIF_STATUS_OK` with data[0] = mac, data[1] = mtu, data[2] = flags

extern crate userlib;

use userlib::syscall;

// --- Netif IPC protocol tags ---
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

// --- ETH_SUBSCRIBE: forwarding-plane subscription protocol (Piece 1) ---
//
// Distinct from NETIF_REGISTER: registration assumes one ethertype-owner per
// upper-layer (existing ip6_srv usage); subscription is *observer*-style
// — many subscribers can match the same frame, each gets a copy in its own
// rx grant page.  Predicate filters: ethertype, IPv4 destination prefix,
// "non-local-only" flag.  This is the forwarding-plane substrate that
// nat_srv (intercepts non-local IPv4), proxy_srv (forwards remote-bonded
// flows), discovery_srv (multicast advertisements) all attach onto.
//
// Frame delivery is via send_nb_4 (fire-and-forget, frame in the rx grant
// page is read by the subscriber before its next ETH_FRAME).  No "steal"
// semantics yet — subscribers observe alongside the existing client
// dispatch; the future "intercept" variant lives behind a flag bit.
//
// - ETH_SUBSCRIBE (0x5500): client -> eth_srv.  Register a subscription.
//     data[0] = ethertype filter (low 16) | flags (next 8) | reserved
//     data[1] = IPv4 dst (BE u32, low 32) | prefix_len (next 8) | reserved
//     data[2] = reply_port
//   Reply: ETH_SUBSCRIBE_OK with data[0] = sub_id, data[1] = rx_grant_va.
//          The subscriber must grant a page at rx_grant_va.  Or
//          ETH_SUBSCRIBE_FAIL on full table / bad args.
//
// - ETH_FRAME (0x5520): eth_srv -> subscriber.  Frame payload available
//   in this subscriber's rx_grant_va.
//     data[0] = full frame length (Ethernet header + payload)
//     data[1] = ethertype
//     data[2] = sub_id (so a process subscribing multiple times can
//               multiplex)
//
// - ETH_UNSUBSCRIBE (0x5510): client -> eth_srv.  Tear down a subscription.
//     data[0] = sub_id
//   Reply: ETH_UNSUBSCRIBE_OK.
const ETH_SUBSCRIBE: u64 = 0x5500;
const ETH_SUBSCRIBE_OK: u64 = 0x5501;
const ETH_SUBSCRIBE_FAIL: u64 = 0x55FF;
const ETH_UNSUBSCRIBE: u64 = 0x5510;
const ETH_UNSUBSCRIBE_OK: u64 = 0x5511;
const ETH_FRAME: u64 = 0x5520;

/// Subscription filter flags.
#[allow(dead_code)]
const FILTER_FLAG_NON_LOCAL: u8 = 1 << 0;
// Future: const FILTER_FLAG_STEAL: u8 = 1 << 1; // intercept rather than copy

const MAX_SUBSCRIBERS: usize = 8;
/// Each subscriber gets one RX grant page (one frame in flight at a time).
/// Distinct base from CLIENT_GRANT_BASE so the two slot tables don't collide.
const SUBSCRIBER_GRANT_BASE: usize = 0x3_8000_0000;

// Legacy net_srv IPC (kept for backward compat with init test suite).
const NET_STATUS: u64 = 0x4000;
const NET_STATUS_OK: u64 = 0x4001;
const NET_PING: u64 = 0x4100;
const NET_PING_OK: u64 = 0x4101;
const NET_PING_FAIL: u64 = 0x41FF;

// --- Virtio MMIO registers ---
const MMIO_MAGIC_VALUE: usize = 0x000;
const MMIO_VERSION: usize = 0x004;
const MMIO_DEVICE_ID: usize = 0x008;
const MMIO_DEVICE_FEATURES: usize = 0x010;
const MMIO_DEVICE_FEATURES_SEL: usize = 0x014;
const MMIO_DRIVER_FEATURES: usize = 0x020;
const MMIO_DRIVER_FEATURES_SEL: usize = 0x024;
const MMIO_GUEST_PAGE_SIZE: usize = 0x028;
const MMIO_QUEUE_SEL: usize = 0x030;
const MMIO_QUEUE_NUM_MAX: usize = 0x034;
const MMIO_QUEUE_NUM: usize = 0x038;
const MMIO_QUEUE_PFN: usize = 0x040;
const MMIO_QUEUE_READY: usize = 0x044;
const MMIO_QUEUE_NOTIFY: usize = 0x050;
const MMIO_STATUS: usize = 0x070;
const MMIO_QUEUE_DESC_LOW: usize = 0x080;
const MMIO_QUEUE_DESC_HIGH: usize = 0x084;
const MMIO_QUEUE_DRIVER_LOW: usize = 0x090;
const MMIO_QUEUE_DRIVER_HIGH: usize = 0x094;
const MMIO_QUEUE_DEVICE_LOW: usize = 0x0A0;
const MMIO_QUEUE_DEVICE_HIGH: usize = 0x0A4;

const VIRTIO_MAGIC: u32 = 0x74726976;
const DEVICE_NET: u32 = 1;
const STATUS_ACK: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_DRIVER_OK: u32 = 4;
const VIRTIO_NET_F_MAC: u32 = 1 << 5;

const QUEUE_SIZE: usize = 16;
const VRING_DESC_F_WRITE: u16 = 2;

// --- Legacy virtio-PCI BAR0 register offsets ---
#[cfg(any(target_arch = "x86_64", target_arch = "mips64", target_arch = "loongarch64"))]
mod pci_regs {
    pub const DEVICE_FEATURES: u16 = 0x00;
    pub const DRIVER_FEATURES: u16 = 0x04;
    pub const QUEUE_ADDRESS: u16 = 0x08;
    pub const QUEUE_SIZE: u16 = 0x0C;
    pub const QUEUE_SELECT: u16 = 0x0E;
    pub const QUEUE_NOTIFY: u16 = 0x10;
    pub const DEVICE_STATUS: u16 = 0x12;
    #[allow(dead_code)]
    pub const ISR_STATUS: u16 = 0x13;
    pub const NET_MAC: u16 = 0x14;
}

/// Virtio-net header size (without VIRTIO_NET_F_MRG_RXBUF).
const NET_HDR_SIZE: usize = 10;
/// Max ethernet frame: 14 header + 1500 MTU.
const MAX_FRAME: usize = 1514;
/// Ethernet header size.
const ETH_HDR: usize = 14;
/// Max ethernet payload (MTU).
const MTU: usize = 1500;

// Network config (QEMU user-mode defaults).
const MY_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

const PING_TIMEOUT: u32 = 5000;

// --- Max registered netif clients ---
const MAX_CLIENTS: usize = 8;

/// Grant page base addresses for netif clients.
/// Each client gets a RX page and a TX page in our address space.
/// We place them starting at 0x3_0000_0000.
const CLIENT_GRANT_BASE: usize = 0x3_0000_0000;

// --- Virtqueue descriptor ---
#[repr(C)]
#[derive(Clone, Copy)]
struct VringDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

// --- Helpers ---

fn mmio_read32(base: usize, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + off) as *const u32) }
}

fn mmio_write32(base: usize, off: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + off) as *mut u32, val) }
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

fn print_ip(ip: [u8; 4]) {
    for i in 0..4 {
        if i > 0 {
            syscall::debug_putchar(b'.');
        }
        print_num(ip[i] as u64);
    }
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

fn put_u16_be(buf: &mut [u8], off: usize, val: u16) {
    buf[off] = (val >> 8) as u8;
    buf[off + 1] = val as u8;
}

fn get_u16_be(buf: &[u8], off: usize) -> u16 {
    ((buf[off] as u16) << 8) | (buf[off + 1] as u16)
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

// --- Per-queue state ---

struct Virtqueue {
    vq_va: usize,
    buf_va: usize,
    #[allow(dead_code)]
    desc_pa: usize,
    buf_pa: usize,
    avail_offset: usize,
    used_offset: usize,
    last_used: u16,
    queue_size: usize,
}

impl Virtqueue {
    fn avail_va(&self) -> usize {
        self.vq_va + self.avail_offset
    }

    fn used_va(&self) -> usize {
        self.vq_va + self.used_offset
    }

    fn post_desc(&mut self, desc_idx: u16, addr: u64, len: u32, flags: u16) {
        let desc = (self.vq_va + desc_idx as usize * 16) as *mut VringDesc;
        unsafe {
            core::ptr::write_volatile(
                desc,
                VringDesc {
                    addr,
                    len,
                    flags,
                    next: 0,
                },
            );
        }
        let avail = self.avail_va();
        let avail_idx_ptr = (avail + 2) as *mut u16;
        let avail_ring = (avail + 4) as *mut u16;
        unsafe {
            let idx = core::ptr::read_volatile(avail_idx_ptr);
            core::ptr::write_volatile(avail_ring.add((idx as usize) % self.queue_size), desc_idx);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(avail_idx_ptr, idx.wrapping_add(1));
        }
    }

    fn check_used(&mut self) -> Option<u32> {
        let used = self.used_va();
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let used_idx = unsafe { core::ptr::read_volatile((used + 2) as *const u16) };
        if used_idx != self.last_used {
            let elem_off = 4 + (self.last_used as usize % self.queue_size) * 8;
            let len = unsafe { core::ptr::read_volatile((used + elem_off + 4) as *const u32) };
            self.last_used = self.last_used.wrapping_add(1);
            Some(len)
        } else {
            None
        }
    }
}

/// PCI MMIO helpers for LoongArch64 (memory-mapped BAR0).
#[cfg(target_arch = "loongarch64")]
mod pci_mmio {
    #[inline]
    pub fn read8(base: usize, offset: u16) -> u8 {
        unsafe { core::ptr::read_volatile((base + offset as usize) as *const u8) }
    }
    #[inline]
    pub fn read16(base: usize, offset: u16) -> u16 {
        unsafe { core::ptr::read_volatile((base + offset as usize) as *const u16) }
    }
    #[inline]
    pub fn read32(base: usize, offset: u16) -> u32 {
        unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
    }
    #[inline]
    pub fn write8(base: usize, offset: u16, val: u8) {
        unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u8, val) }
    }
    #[inline]
    pub fn write16(base: usize, offset: u16, val: u16) {
        unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u16, val) }
    }
    #[inline]
    pub fn write32(base: usize, offset: u16, val: u32) {
        unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u32, val) }
    }
}

// --- Netif client registration ---

/// Forwarding-plane subscriber (ETH_SUBSCRIBE).  Observer-style: each
/// frame matching the predicate is copied into rx_va and delivered via
/// send_nb_4(ETH_FRAME).  Multiple subscribers can match the same frame.
#[derive(Copy, Clone)]
struct Subscriber {
    active: bool,
    port: u64,
    rx_va: usize,
    /// 0 = match any ethertype; otherwise must equal frame ethertype.
    ethertype_filter: u16,
    flags: u8,
    /// IPv4 destination match.  Only consulted when frame ethertype is
    /// 0x0800 and prefix_len > 0.  prefix_len 0 = match any.
    dst_ipv4: u32,
    dst_prefix_len: u8,
}

impl Subscriber {
    const fn new() -> Self {
        Self {
            active: false,
            port: 0,
            rx_va: 0,
            ethertype_filter: 0,
            flags: 0,
            dst_ipv4: 0,
            dst_prefix_len: 0,
        }
    }
}

struct NetifClient {
    active: bool,
    ethertype: u16,
    port: u64,     // client's IPC port (for NETIF_INPUT notifications)
    rx_va: usize,  // grant page in our aspace for delivering RX frames
    tx_va: usize,  // grant page in our aspace for reading TX frames
}

impl NetifClient {
    const fn new() -> Self {
        Self {
            active: false,
            ethertype: 0,
            port: 0,
            rx_va: 0,
            tx_va: 0,
        }
    }
}

// --- Ethernet device ---

struct EthDev {
    base: usize,
    mac: [u8; 6],
    rx: Virtqueue,
    tx: Virtqueue,
    // ARP cache.
    arp_ip: [[u8; 4]; 8],
    arp_mac: [[u8; 6]; 8],
    arp_valid: [bool; 8],
    arp_next: usize,
    // Registered netif clients.
    clients: [NetifClient; MAX_CLIENTS],
    // Forwarding-plane subscribers.
    subscribers: [Subscriber; MAX_SUBSCRIBERS],
    // Pending ARP resolve requests.
    arp_pending_ip: [[u8; 4]; 4],
    arp_pending_port: [u64; 4],
    arp_pending_active: [bool; 4],
    arp_pending_polls: [u32; 4],
    // Pending legacy ping state.
    ping_target: [u8; 4],
    ping_reply_port: u64,
    ping_seq: u16,
    ping_polls: u32,
    ping_active: bool,
    ping_sent_icmp: bool,
}

impl EthDev {
    fn new_dev(base: usize, mac: [u8; 6], rx: Virtqueue, tx: Virtqueue) -> Self {
        Self {
            base,
            mac,
            rx,
            tx,
            arp_ip: [[0; 4]; 8],
            arp_mac: [[0; 6]; 8],
            arp_valid: [false; 8],
            arp_next: 0,
            clients: [const { NetifClient::new() }; MAX_CLIENTS],
            subscribers: [const { Subscriber::new() }; MAX_SUBSCRIBERS],
            arp_pending_ip: [[0; 4]; 4],
            arp_pending_port: [0; 4],
            arp_pending_active: [false; 4],
            arp_pending_polls: [0; 4],
            ping_target: [0; 4],
            ping_reply_port: 0,
            ping_seq: 0,
            ping_polls: 0,
            ping_active: false,
            ping_sent_icmp: false,
        }
    }

    // ---------------------------------------------------------------
    // Virtio-net init: MMIO transport (aarch64/riscv64)
    // ---------------------------------------------------------------

    #[cfg(not(any(target_arch = "x86_64", target_arch = "mips64", target_arch = "loongarch64")))]
    fn init(mmio_slot: usize, irq: u32) -> Option<Self> {
        let mmio_va = syscall::mmio_map_cap(mmio_slot)?;

        syscall::debug_puts(b"  [eth_srv] MMIO mapped at VA ");
        print_hex(mmio_va as u64);
        syscall::debug_puts(b"\n");

        if mmio_read32(mmio_va, MMIO_MAGIC_VALUE) != VIRTIO_MAGIC {
            syscall::debug_puts(b"  [eth_srv] bad magic\n");
            return None;
        }
        if mmio_read32(mmio_va, MMIO_DEVICE_ID) != DEVICE_NET {
            syscall::debug_puts(b"  [eth_srv] not a net device\n");
            return None;
        }

        let version = mmio_read32(mmio_va, MMIO_VERSION);

        // Reset.
        mmio_write32(mmio_va, MMIO_STATUS, 0);

        // ACK + DRIVER.
        let mut status = STATUS_ACK;
        mmio_write32(mmio_va, MMIO_STATUS, status);
        status |= STATUS_DRIVER;
        mmio_write32(mmio_va, MMIO_STATUS, status);

        // Feature negotiation: accept only MAC.
        mmio_write32(mmio_va, MMIO_DEVICE_FEATURES_SEL, 0);
        let features = mmio_read32(mmio_va, MMIO_DEVICE_FEATURES);
        let accept = features & VIRTIO_NET_F_MAC;
        mmio_write32(mmio_va, MMIO_DRIVER_FEATURES_SEL, 0);
        mmio_write32(mmio_va, MMIO_DRIVER_FEATURES, accept);

        if version >= 2 {
            status |= STATUS_FEATURES_OK;
            mmio_write32(mmio_va, MMIO_STATUS, status);
            if mmio_read32(mmio_va, MMIO_STATUS) & STATUS_FEATURES_OK == 0 {
                syscall::debug_puts(b"  [eth_srv] FEATURES_OK failed\n");
                return None;
            }
        }

        // Read MAC from config (offset 0x100).
        let mut mac = [0u8; 6];
        if features & VIRTIO_NET_F_MAC != 0 {
            for i in 0..6 {
                mac[i] = unsafe { core::ptr::read_volatile((mmio_va + 0x100 + i) as *const u8) };
            }
        }

        // Set up RX queue (0) and TX queue (1).
        if version == 1 {
            mmio_write32(mmio_va, MMIO_GUEST_PAGE_SIZE, 4096);
        }
        let rx = Self::setup_queue_mmio(mmio_va, 0, version)?;
        let tx = Self::setup_queue_mmio(mmio_va, 1, version)?;

        let _ = irq; // poll-based, no irq_wait

        // DRIVER_OK.
        status |= STATUS_DRIVER_OK;
        mmio_write32(mmio_va, MMIO_STATUS, status);

        let mut dev = Self::new_dev(mmio_va, mac, rx, tx);
        dev.post_rx();
        Some(dev)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "mips64", target_arch = "loongarch64")))]
    fn setup_queue_mmio(mmio_va: usize, queue_idx: u32, version: u32) -> Option<Virtqueue> {
        mmio_write32(mmio_va, MMIO_QUEUE_SEL, queue_idx);
        let max = mmio_read32(mmio_va, MMIO_QUEUE_NUM_MAX);
        if max == 0 {
            return None;
        }
        let qsize = (QUEUE_SIZE as u32).min(max);
        mmio_write32(mmio_va, MMIO_QUEUE_NUM, qsize);

        let ps = syscall::page_size();
        let vq_pages = if version == 1 { 2 } else { 1 };
        let vq_va = syscall::mmap_anon(0, vq_pages, 1)?;
        let vq_pa = syscall::virt_to_phys(vq_va)?;
        unsafe {
            core::ptr::write_bytes(vq_va as *mut u8, 0, vq_pages * ps);
        }

        let buf_va = syscall::mmap_anon(0, 1, 1)?;
        let buf_pa = syscall::virt_to_phys(buf_va)?;
        unsafe {
            core::ptr::write_bytes(buf_va as *mut u8, 0, ps);
        }

        let desc_pa = vq_pa;
        let avail_pa = desc_pa + 16 * QUEUE_SIZE;

        let used_offset;
        if version == 1 {
            let avail_end = avail_pa + 6 + 2 * QUEUE_SIZE;
            let used_pa = (avail_end + 4095) & !4095;
            used_offset = used_pa - desc_pa;
            mmio_write32(mmio_va, MMIO_QUEUE_PFN, (vq_pa / 4096) as u32);
        } else {
            let used_pa = (avail_pa + 6 + 2 * QUEUE_SIZE + 3) & !3;
            used_offset = used_pa - desc_pa;
            mmio_write32(mmio_va, MMIO_QUEUE_DESC_LOW, desc_pa as u32);
            mmio_write32(mmio_va, MMIO_QUEUE_DESC_HIGH, (desc_pa >> 32) as u32);
            mmio_write32(mmio_va, MMIO_QUEUE_DRIVER_LOW, avail_pa as u32);
            mmio_write32(mmio_va, MMIO_QUEUE_DRIVER_HIGH, (avail_pa >> 32) as u32);
            let up = desc_pa + used_offset;
            mmio_write32(mmio_va, MMIO_QUEUE_DEVICE_LOW, up as u32);
            mmio_write32(mmio_va, MMIO_QUEUE_DEVICE_HIGH, (up >> 32) as u32);
            mmio_write32(mmio_va, MMIO_QUEUE_READY, 1);
        }

        Some(Virtqueue {
            vq_va,
            buf_va,
            desc_pa,
            buf_pa,
            avail_offset: 16 * QUEUE_SIZE,
            used_offset,
            last_used: 0,
            queue_size: QUEUE_SIZE,
        })
    }

    // ---------------------------------------------------------------
    // Virtio-net init: PCI I/O port transport (x86_64/mips64)
    // ---------------------------------------------------------------

    #[cfg(any(target_arch = "x86_64", target_arch = "mips64"))]
    fn init(bar0_port: usize, irq: u32) -> Option<Self> {
        let base = bar0_port as u16;

        syscall::debug_puts(b"  [eth_srv] PCI BAR0 port ");
        print_hex(base as u64);
        syscall::debug_puts(b"\n");

        // Reset.
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS, 0);

        // ACK + DRIVER.
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS, STATUS_ACK as u8);
        syscall::ioport_outb(
            base + pci_regs::DEVICE_STATUS,
            (STATUS_ACK | STATUS_DRIVER) as u8,
        );

        // Feature negotiation: accept MAC.
        let features = syscall::ioport_inl(base + pci_regs::DEVICE_FEATURES);
        let accept = features & VIRTIO_NET_F_MAC;
        syscall::ioport_outl(base + pci_regs::DRIVER_FEATURES, accept);

        // Read MAC from device config (BAR0 + 0x14).
        let mut mac = [0u8; 6];
        if features & VIRTIO_NET_F_MAC != 0 {
            for i in 0..6 {
                mac[i] = syscall::ioport_inb(base + pci_regs::NET_MAC + i as u16);
            }
        }

        // Set up RX queue (0) and TX queue (1).
        let rx = Self::setup_queue_pci(base, 0)?;
        let tx = Self::setup_queue_pci(base, 1)?;

        let _ = irq;

        // DRIVER_OK.
        syscall::ioport_outb(
            base + pci_regs::DEVICE_STATUS,
            (STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK) as u8,
        );

        let mut dev = Self::new_dev(base as usize, mac, rx, tx);
        dev.post_rx();
        Some(dev)
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "mips64"))]
    fn setup_queue_pci(base: u16, queue_idx: u16) -> Option<Virtqueue> {
        syscall::ioport_outw(base + pci_regs::QUEUE_SELECT, queue_idx);
        let max = syscall::ioport_inw(base + pci_regs::QUEUE_SIZE);
        if max == 0 {
            return None;
        }

        let qsz = max as usize;

        let ps = syscall::page_size();
        let vq_bytes = 16 * qsz + (6 + 2 * qsz) + 4096 + (8 * qsz + 6);
        let vq_pages = (vq_bytes + ps - 1) / ps;
        let vq_va = syscall::mmap_anon(0, vq_pages, 1)?;
        let vq_pa = syscall::virt_to_phys(vq_va)?;
        unsafe {
            core::ptr::write_bytes(vq_va as *mut u8, 0, vq_pages * ps);
        }

        let buf_va = syscall::mmap_anon(0, 1, 1)?;
        let buf_pa = syscall::virt_to_phys(buf_va)?;
        unsafe {
            core::ptr::write_bytes(buf_va as *mut u8, 0, ps);
        }

        let desc_pa = vq_pa;
        let avail_pa = desc_pa + 16 * qsz;
        let avail_end = avail_pa + 6 + 2 * qsz;
        let used_pa = (avail_end + 4095) & !4095;
        let avail_offset = avail_pa - desc_pa;
        let used_offset = used_pa - desc_pa;

        syscall::ioport_outl(base + pci_regs::QUEUE_ADDRESS, (vq_pa / 4096) as u32);

        Some(Virtqueue {
            vq_va,
            buf_va,
            desc_pa,
            buf_pa,
            avail_offset,
            used_offset,
            last_used: 0,
            queue_size: qsz,
        })
    }

    // ---------------------------------------------------------------
    // Virtio-net init: PCI MMIO transport (LoongArch64)
    // ---------------------------------------------------------------

    #[cfg(target_arch = "loongarch64")]
    fn init(mmio_slot: usize, irq: u32) -> Option<Self> {
        let mmio_va = syscall::mmio_map_cap(mmio_slot)?;

        syscall::debug_puts(b"  [eth_srv] PCI BAR0 mapped at VA ");
        print_hex(mmio_va as u64);
        syscall::debug_puts(b"\n");

        // Reset.
        pci_mmio::write8(mmio_va, pci_regs::DEVICE_STATUS, 0);

        // ACK + DRIVER.
        pci_mmio::write8(mmio_va, pci_regs::DEVICE_STATUS, STATUS_ACK as u8);
        pci_mmio::write8(
            mmio_va,
            pci_regs::DEVICE_STATUS,
            (STATUS_ACK | STATUS_DRIVER) as u8,
        );

        // Feature negotiation: accept MAC.
        let features = pci_mmio::read32(mmio_va, pci_regs::DEVICE_FEATURES);
        let accept = features & VIRTIO_NET_F_MAC;
        pci_mmio::write32(mmio_va, pci_regs::DRIVER_FEATURES, accept);

        // Read MAC from device config (BAR0 + 0x14).
        let mut mac = [0u8; 6];
        if features & VIRTIO_NET_F_MAC != 0 {
            for i in 0..6 {
                mac[i] = pci_mmio::read8(mmio_va, pci_regs::NET_MAC + i as u16);
            }
        }

        // Set up RX queue (0) and TX queue (1).
        let rx = Self::setup_queue_pci_mmio(mmio_va, 0)?;
        let tx = Self::setup_queue_pci_mmio(mmio_va, 1)?;

        let _ = irq;

        // DRIVER_OK.
        pci_mmio::write8(
            mmio_va,
            pci_regs::DEVICE_STATUS,
            (STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK) as u8,
        );

        let mut dev = Self::new_dev(mmio_va, mac, rx, tx);
        dev.post_rx();
        Some(dev)
    }

    #[cfg(target_arch = "loongarch64")]
    fn setup_queue_pci_mmio(base: usize, queue_idx: u16) -> Option<Virtqueue> {
        pci_mmio::write16(base, pci_regs::QUEUE_SELECT, queue_idx);
        let max = pci_mmio::read16(base, pci_regs::QUEUE_SIZE);
        if max == 0 {
            return None;
        }

        let qsz = max as usize;

        let ps = syscall::page_size();
        let vq_bytes = 16 * qsz + (6 + 2 * qsz) + 4096 + (8 * qsz + 6);
        let vq_pages = (vq_bytes + ps - 1) / ps;
        let vq_va = syscall::mmap_anon(0, vq_pages, 1)?;
        let vq_pa = syscall::virt_to_phys(vq_va)?;
        unsafe {
            core::ptr::write_bytes(vq_va as *mut u8, 0, vq_pages * ps);
        }

        let buf_va = syscall::mmap_anon(0, 1, 1)?;
        let buf_pa = syscall::virt_to_phys(buf_va)?;
        unsafe {
            core::ptr::write_bytes(buf_va as *mut u8, 0, ps);
        }

        let desc_pa = vq_pa;
        let avail_pa = desc_pa + 16 * qsz;
        let avail_end = avail_pa + 6 + 2 * qsz;
        let used_pa = (avail_end + 4095) & !4095;
        let avail_offset = avail_pa - desc_pa;
        let used_offset = used_pa - desc_pa;

        pci_mmio::write32(base, pci_regs::QUEUE_ADDRESS, (vq_pa / 4096) as u32);

        Some(Virtqueue {
            vq_va,
            buf_va,
            desc_pa,
            buf_pa,
            avail_offset,
            used_offset,
            last_used: 0,
            queue_size: qsz,
        })
    }

    // ---------------------------------------------------------------
    // Common device operations
    // ---------------------------------------------------------------

    fn notify_queue(&self, queue_idx: u16) {
        #[cfg(not(any(target_arch = "x86_64", target_arch = "mips64", target_arch = "loongarch64")))]
        mmio_write32(self.base, MMIO_QUEUE_NOTIFY, queue_idx as u32);
        #[cfg(target_arch = "loongarch64")]
        pci_mmio::write16(self.base, pci_regs::QUEUE_NOTIFY, queue_idx);
        #[cfg(any(target_arch = "x86_64", target_arch = "mips64"))]
        syscall::ioport_outw(self.base as u16 + pci_regs::QUEUE_NOTIFY, queue_idx);
    }

    fn post_rx(&mut self) {
        self.rx.post_desc(
            0,
            self.rx.buf_pa as u64,
            (NET_HDR_SIZE + MAX_FRAME) as u32,
            VRING_DESC_F_WRITE,
        );
        self.notify_queue(0);
    }

    fn poll_rx(&mut self) -> Option<usize> {
        if let Some(len) = self.rx.check_used() {
            if len as usize > NET_HDR_SIZE {
                return Some(len as usize - NET_HDR_SIZE);
            }
        }
        None
    }

    fn tx_send(&mut self, frame: &[u8]) {
        let total = NET_HDR_SIZE + frame.len();
        unsafe {
            core::ptr::write_bytes(self.tx.buf_va as *mut u8, 0, NET_HDR_SIZE);
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                (self.tx.buf_va + NET_HDR_SIZE) as *mut u8,
                frame.len(),
            );
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.tx.post_desc(0, self.tx.buf_pa as u64, total as u32, 0);
        self.notify_queue(1);

        for _ in 0..1000 {
            if self.tx.check_used().is_some() {
                return;
            }
            syscall::yield_now();
        }
    }

    /// Send a raw Ethernet frame with the given dst/src/ethertype header and payload.
    fn tx_frame(&mut self, dst_mac: [u8; 6], ethertype: u16, payload: &[u8]) {
        let frame_len = ETH_HDR + payload.len();
        if frame_len > MAX_FRAME {
            return;
        }
        let total = NET_HDR_SIZE + frame_len;
        let buf = self.tx.buf_va;
        unsafe {
            // Virtio-net header (10 bytes zero).
            core::ptr::write_bytes(buf as *mut u8, 0, NET_HDR_SIZE);
            let f = (buf + NET_HDR_SIZE) as *mut u8;
            // Ethernet header.
            core::ptr::copy_nonoverlapping(dst_mac.as_ptr(), f, 6);
            core::ptr::copy_nonoverlapping(self.mac.as_ptr(), f.add(6), 6);
            *f.add(12) = (ethertype >> 8) as u8;
            *f.add(13) = ethertype as u8;
            // Payload.
            core::ptr::copy_nonoverlapping(payload.as_ptr(), f.add(ETH_HDR), payload.len());
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.tx.post_desc(0, self.tx.buf_pa as u64, total as u32, 0);
        self.notify_queue(1);

        for _ in 0..1000 {
            if self.tx.check_used().is_some() {
                return;
            }
            syscall::yield_now();
        }
    }

    // ---------------------------------------------------------------
    // ARP
    // ---------------------------------------------------------------

    fn arp_lookup(&self, ip: [u8; 4]) -> Option<[u8; 6]> {
        for i in 0..8 {
            if self.arp_valid[i] && self.arp_ip[i] == ip {
                return Some(self.arp_mac[i]);
            }
        }
        None
    }

    fn arp_store(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        for i in 0..8 {
            if self.arp_valid[i] && self.arp_ip[i] == ip {
                self.arp_mac[i] = mac;
                return;
            }
        }
        let idx = self.arp_next % 8;
        self.arp_ip[idx] = ip;
        self.arp_mac[idx] = mac;
        self.arp_valid[idx] = true;
        self.arp_next += 1;
    }

    fn send_arp_request(&mut self, target_ip: [u8; 4]) {
        let mut frame = [0u8; 42]; // 14 eth + 28 arp
        frame[0..6].copy_from_slice(&[0xFF; 6]);
        frame[6..12].copy_from_slice(&self.mac);
        frame[12] = 0x08;
        frame[13] = 0x06;
        put_u16_be(&mut frame, 14, 1); // hw type = ethernet
        put_u16_be(&mut frame, 16, 0x0800); // proto = IPv4
        frame[18] = 6;
        frame[19] = 4;
        put_u16_be(&mut frame, 20, 1); // op = request
        frame[22..28].copy_from_slice(&self.mac);
        frame[28..32].copy_from_slice(&MY_IP);
        frame[32..38].copy_from_slice(&[0; 6]);
        frame[38..42].copy_from_slice(&target_ip);
        self.tx_send(&frame);
    }

    fn send_arp_reply(&mut self, dst_ip: [u8; 4], dst_mac: [u8; 6]) {
        let mut frame = [0u8; 42];
        frame[0..6].copy_from_slice(&dst_mac);
        frame[6..12].copy_from_slice(&self.mac);
        frame[12] = 0x08;
        frame[13] = 0x06;
        put_u16_be(&mut frame, 14, 1);
        put_u16_be(&mut frame, 16, 0x0800);
        frame[18] = 6;
        frame[19] = 4;
        put_u16_be(&mut frame, 20, 2); // op = reply
        frame[22..28].copy_from_slice(&self.mac);
        frame[28..32].copy_from_slice(&MY_IP);
        frame[32..38].copy_from_slice(&dst_mac);
        frame[38..42].copy_from_slice(&dst_ip);
        self.tx_send(&frame);
    }

    fn handle_arp(&mut self, data: &[u8]) {
        if data.len() < 28 {
            return;
        }
        let op = get_u16_be(data, 6);
        if op == 2 {
            // ARP reply: cache it.
            let sender_mac = [data[8], data[9], data[10], data[11], data[12], data[13]];
            let sender_ip = [data[14], data[15], data[16], data[17]];
            self.arp_store(sender_ip, sender_mac);
            // Fulfill pending ARP resolve requests.
            for i in 0..4 {
                if self.arp_pending_active[i] && self.arp_pending_ip[i] == sender_ip {
                    syscall::send_nb(
                        self.arp_pending_port[i],
                        NETIF_RESOLVE_OK,
                        mac_to_u64(sender_mac),
                        0,
                    );
                    self.arp_pending_active[i] = false;
                }
            }
            // Legacy ping: if waiting for ARP, send ICMP now.
            if self.ping_active && !self.ping_sent_icmp && self.ping_target == sender_ip {
                self.send_icmp_echo(self.ping_target, sender_mac, self.ping_seq);
                self.ping_sent_icmp = true;
            }
        } else if op == 1 {
            // ARP request for our IP: reply.
            let target_ip = [data[24], data[25], data[26], data[27]];
            if target_ip == MY_IP {
                let sender_mac = [data[8], data[9], data[10], data[11], data[12], data[13]];
                let sender_ip = [data[14], data[15], data[16], data[17]];
                self.arp_store(sender_ip, sender_mac);
                self.send_arp_reply(sender_ip, sender_mac);
            }
        }
    }

    // ---------------------------------------------------------------
    // Legacy ICMP echo (for backward compat with NET_PING)
    // ---------------------------------------------------------------

    fn send_icmp_echo(&mut self, dst_ip: [u8; 4], dst_mac: [u8; 6], seq: u16) {
        let mut frame = [0u8; 74]; // 14 eth + 20 ip + 8 icmp hdr + 32 payload
        frame[0..6].copy_from_slice(&dst_mac);
        frame[6..12].copy_from_slice(&self.mac);
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        let ip = &mut frame[14..34];
        ip[0] = 0x45;
        put_u16_be(ip, 2, 60);
        put_u16_be(ip, 4, 1);
        put_u16_be(ip, 6, 0x4000);
        ip[8] = 64;
        ip[9] = 1; // ICMP
        ip[12..16].copy_from_slice(&MY_IP);
        ip[16..20].copy_from_slice(&dst_ip);
        let cksum = inet_checksum(ip);
        ip[10] = (cksum >> 8) as u8;
        ip[11] = cksum as u8;
        let icmp = &mut frame[34..74];
        icmp[0] = 8; // echo request
        put_u16_be(icmp, 4, 0x1234);
        put_u16_be(icmp, 6, seq);
        for i in 0..32 {
            icmp[8 + i] = i as u8;
        }
        let cksum = inet_checksum(icmp);
        icmp[2] = (cksum >> 8) as u8;
        icmp[3] = cksum as u8;
        self.tx_send(&frame);
    }

    fn handle_icmp(&mut self, data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        if data[0] == 0 && self.ping_active {
            // Echo reply.
            syscall::debug_puts(b"  [eth_srv] ping reply received\n");
            syscall::send_nb(self.ping_reply_port, NET_PING_OK, 0, 0);
            self.ping_active = false;
        }
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
        if proto == 1 {
            self.handle_icmp(&data[ihl..end]);
        }
    }

    fn start_ping(&mut self, target: [u8; 4], reply_port: u64) {
        self.ping_target = target;
        self.ping_reply_port = reply_port;
        self.ping_seq = self.ping_seq.wrapping_add(1);
        self.ping_polls = 0;
        self.ping_active = true;
        self.ping_sent_icmp = false;

        if let Some(mac) = self.arp_lookup(GATEWAY_IP) {
            self.send_icmp_echo(target, mac, self.ping_seq);
            self.ping_sent_icmp = true;
        } else {
            self.send_arp_request(GATEWAY_IP);
        }
    }

    fn tick_ping(&mut self) {
        if !self.ping_active {
            return;
        }
        self.ping_polls += 1;
        if self.ping_polls > PING_TIMEOUT {
            syscall::debug_puts(b"  [eth_srv] ping timeout\n");
            syscall::send_nb(self.ping_reply_port, NET_PING_FAIL, 0, 0);
            self.ping_active = false;
        }
    }

    // ---------------------------------------------------------------
    // Netif client management
    // ---------------------------------------------------------------

    fn register_client(&mut self, ethertype: u16, port: u64, reply_port: u64) {
        for i in 0..MAX_CLIENTS {
            if !self.clients[i].active {
                // Pick VAs in our aspace where the client will grant pages.
                let rx_va = CLIENT_GRANT_BASE + i * 2 * syscall::page_size();
                let tx_va = rx_va + syscall::page_size();

                self.clients[i] = NetifClient {
                    active: true,
                    ethertype,
                    port,
                    rx_va,
                    tx_va,
                };

                syscall::debug_puts(b"  [eth_srv] client registered: ethertype=");
                print_hex(ethertype as u64);
                syscall::debug_puts(b" id=");
                print_num(i as u64);
                syscall::debug_puts(b"\n");

                // Reply with client_id and the VAs where the client should
                // grant its pages into our address space.
                syscall::send_nb_4(
                    reply_port,
                    NETIF_REGISTER_OK,
                    i as u64,       // data[0] = client_id
                    rx_va as u64,   // data[1] = eth_rx_va (client grants RX page here)
                    tx_va as u64,   // data[2] = eth_tx_va (client grants TX page here)
                    0,
                );
                return;
            }
        }
        syscall::debug_puts(b"  [eth_srv] no free client slots\n");
    }

    // ---------------------------------------------------------------
    // Packet RX dispatch
    // ---------------------------------------------------------------

    fn handle_rx_packet(&mut self, frame_len: usize) {
        let frame = unsafe {
            core::slice::from_raw_parts((self.rx.buf_va + NET_HDR_SIZE) as *const u8, frame_len)
        };
        if frame_len < ETH_HDR {
            return;
        }
        let ethertype = get_u16_be(frame, 12);

        match ethertype {
            0x0806 => {
                // ARP: handle locally (L2 responsibility).
                self.handle_arp(&frame[ETH_HDR..frame_len]);
            }
            0x0800 => {
                // IPv4: first check if any client registered for it.
                if !self.dispatch_to_client(ethertype, frame) {
                    // No client — handle legacy IPv4 (ICMP for ping).
                    self.handle_ipv4(&frame[ETH_HDR..frame_len]);
                }
            }
            _ => {
                // Dispatch to registered client (IPv6 = 0x86DD, etc.).
                self.dispatch_to_client(ethertype, frame);
            }
        }
        // Forwarding-plane subscribers observe regardless of ethertype.
        // Runs after the legacy dispatch so the subscriber's view doesn't
        // race the ethertype-owner copy in CLIENT_GRANT_BASE.
        self.deliver_to_subscribers(ethertype, frame);
    }

    // ---------------------------------------------------------------
    // Forwarding-plane subscription (Piece 1)
    // ---------------------------------------------------------------

    /// Allocate a subscriber slot.  Replies via send_nb_4 with sub_id +
    /// rx_grant_va; the caller must establish a grant at rx_grant_va
    /// before any frame is delivered.
    fn subscribe(
        &mut self,
        ethertype_filter: u16,
        flags: u8,
        dst_ipv4: u32,
        dst_prefix_len: u8,
        reply_port: u64,
    ) {
        for i in 0..MAX_SUBSCRIBERS {
            if !self.subscribers[i].active {
                let rx_va = SUBSCRIBER_GRANT_BASE + i * 4096;
                self.subscribers[i] = Subscriber {
                    active: true,
                    port: reply_port,
                    rx_va,
                    ethertype_filter,
                    flags,
                    dst_ipv4,
                    dst_prefix_len,
                };
                let _ = syscall::send_nb_4(
                    reply_port,
                    ETH_SUBSCRIBE_OK,
                    i as u64,
                    rx_va as u64,
                    0, 0,
                );
                return;
            }
        }
        let _ = syscall::send_nb_4(reply_port, ETH_SUBSCRIBE_FAIL, 0, 0, 0, 0);
    }

    fn unsubscribe(&mut self, sub_id: usize, reply_port: u64) {
        if sub_id < MAX_SUBSCRIBERS {
            self.subscribers[sub_id] = Subscriber::new();
        }
        let _ = syscall::send_nb_4(reply_port, ETH_UNSUBSCRIBE_OK, 0, 0, 0, 0);
    }

    /// Deliver a frame to every matching subscriber.  Observer-style: each
    /// match gets its own copy in its own grant page.  Called from
    /// handle_rx_packet AFTER the existing client dispatch, so subscribers
    /// observe alongside the legacy ethertype-owner path rather than
    /// stealing.  The "intercept" variant lives behind a future flag bit.
    fn deliver_to_subscribers(&mut self, ethertype: u16, frame: &[u8]) {
        if frame.len() < ETH_HDR { return; }
        // Pre-compute IPv4 destination for prefix matching, if applicable.
        let ipv4_dst: Option<u32> = if ethertype == 0x0800 && frame.len() >= ETH_HDR + 20 {
            let ip = &frame[ETH_HDR..];
            Some(((ip[16] as u32) << 24) | ((ip[17] as u32) << 16)
                | ((ip[18] as u32) << 8) | (ip[19] as u32))
        } else {
            None
        };
        let my_ipv4 = ((MY_IP[0] as u32) << 24) | ((MY_IP[1] as u32) << 16)
            | ((MY_IP[2] as u32) << 8) | (MY_IP[3] as u32);

        for i in 0..MAX_SUBSCRIBERS {
            let s = self.subscribers[i];
            if !s.active { continue; }
            // Ethertype filter: 0 means "any."
            if s.ethertype_filter != 0 && s.ethertype_filter != ethertype { continue; }
            // IPv4-only filters: only meaningful when frame is IPv4.
            if let Some(dst) = ipv4_dst {
                if s.dst_prefix_len > 0 {
                    let mask: u32 = if s.dst_prefix_len >= 32 {
                        u32::MAX
                    } else {
                        !((1u32 << (32 - s.dst_prefix_len)) - 1)
                    };
                    if (dst & mask) != (s.dst_ipv4 & mask) { continue; }
                }
                if s.flags & FILTER_FLAG_NON_LOCAL != 0 && dst == my_ipv4 {
                    continue;
                }
            } else {
                // Non-IPv4 frame: skip subscribers that requested IPv4 filtering.
                if s.dst_prefix_len > 0 || s.flags & FILTER_FLAG_NON_LOCAL != 0 {
                    continue;
                }
            }
            // Match — copy frame to subscriber's grant page and notify.
            let payload_len = frame.len();
            if payload_len > MAX_FRAME { continue; }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    frame.as_ptr(),
                    s.rx_va as *mut u8,
                    payload_len,
                );
            }
            let _ = syscall::send_nb_4(
                s.port,
                ETH_FRAME,
                payload_len as u64,
                ethertype as u64,
                i as u64,
                0,
            );
        }
    }

    /// Dispatch a frame to a registered netif client. Returns true if delivered.
    fn dispatch_to_client(&mut self, ethertype: u16, frame: &[u8]) -> bool {
        for i in 0..MAX_CLIENTS {
            if self.clients[i].active && self.clients[i].ethertype == ethertype {
                let payload_len = frame.len() - ETH_HDR;
                if payload_len > MTU {
                    return false;
                }
                // Copy payload into client's RX grant page.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        frame[ETH_HDR..].as_ptr(),
                        self.clients[i].rx_va as *mut u8,
                        payload_len,
                    );
                }
                // Extract source MAC from frame.
                let src_mac = [
                    frame[6], frame[7], frame[8], frame[9], frame[10], frame[11],
                ];
                // Notify client (blocking send so we don't overwrite the
                // RX grant page before the client copies the data out).
                syscall::send(
                    self.clients[i].port,
                    NETIF_INPUT,
                    payload_len as u64,
                    mac_to_u64(src_mac),
                    0, 0,
                );
                return true;
            }
        }
        false
    }

    // ---------------------------------------------------------------
    // Netif XMIT handler
    // ---------------------------------------------------------------

    fn handle_xmit(&mut self, client_id: usize, payload_len: usize, dst_mac_val: u64, ethertype: u16, reply_port: u64) {
        if client_id >= MAX_CLIENTS || !self.clients[client_id].active {
            return;
        }
        if payload_len > MTU {
            return;
        }
        let dst_mac = if dst_mac_val == 0 {
            [0xFF; 6] // broadcast
        } else {
            u64_to_mac(dst_mac_val)
        };

        // Read payload from client's TX grant page.
        let payload = unsafe {
            core::slice::from_raw_parts(self.clients[client_id].tx_va as *const u8, payload_len)
        };
        self.tx_frame(dst_mac, ethertype, payload);
        syscall::send_nb(reply_port, NETIF_XMIT_OK, 0, 0);
    }

    // ---------------------------------------------------------------
    // ARP resolve (for upper-layer servers)
    // ---------------------------------------------------------------

    fn handle_resolve(&mut self, ip_be: u32, reply_port: u64) {
        let ip = ip_be.to_be_bytes();
        if let Some(mac) = self.arp_lookup(ip) {
            syscall::send_nb(reply_port, NETIF_RESOLVE_OK, mac_to_u64(mac), 0);
            return;
        }
        // Queue pending resolve and send ARP request.
        for i in 0..4 {
            if !self.arp_pending_active[i] {
                self.arp_pending_ip[i] = ip;
                self.arp_pending_port[i] = reply_port;
                self.arp_pending_active[i] = true;
                self.arp_pending_polls[i] = 0;
                self.send_arp_request(ip);
                return;
            }
        }
        // All slots full — fail immediately.
        syscall::send_nb(reply_port, NETIF_RESOLVE_FAIL, 0, 0);
    }

    fn tick_arp_pending(&mut self) {
        for i in 0..4 {
            if self.arp_pending_active[i] {
                self.arp_pending_polls[i] += 1;
                if self.arp_pending_polls[i] > 3000 {
                    syscall::send_nb(
                        self.arp_pending_port[i],
                        NETIF_RESOLVE_FAIL,
                        0,
                        0,
                    );
                    self.arp_pending_active[i] = false;
                }
            }
        }
    }
}

// ---------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let irq = (arg0 >> 48) as u32;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "mips64")))]
    let base = (arg0 & 0xFFFF) as usize; // mmio cap slot
    #[cfg(any(target_arch = "x86_64", target_arch = "mips64"))]
    let base = (arg0 & 0xFFFF_FFFF_FFFF) as usize;

    syscall::debug_puts(b"  [eth_srv] starting, base=");
    print_hex(base as u64);
    syscall::debug_puts(b" irq=");
    print_num(irq as u64);
    syscall::debug_puts(b"\n");

    let mut dev = match EthDev::init(base, irq) {
        Some(d) => d,
        None => {
            syscall::debug_puts(b"  [eth_srv] init failed\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    syscall::debug_puts(b"  [eth_srv] ready, MAC=");
    print_mac(dev.mac);
    syscall::debug_puts(b" IP=");
    print_ip(MY_IP);
    syscall::debug_puts(b"\n");

    // Register with name server as "eth" (link-layer service).
    // "net" registration is handled by tcp4_srv for backward compat.
    let port = syscall::port_create();
    syscall::ns_register(b"eth", port);

    syscall::debug_puts(b"  [eth_srv] registered on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // Poll-based server loop.
    loop {
        // 1. Poll RX.
        if let Some(frame_len) = dev.poll_rx() {
            dev.handle_rx_packet(frame_len);
            dev.post_rx();
        }

        // 2. Poll IPC.
        if let Some(msg) = syscall::recv_nb_msg(port) {
            match msg.tag {
                // --- Netif protocol ---
                NETIF_REGISTER => {
                    let ethertype = msg.data[0] as u16;
                    let client_port = msg.data[1];
                    let reply_port = msg.data[2];
                    dev.register_client(ethertype, client_port, reply_port);
                }
                ETH_SUBSCRIBE => {
                    let ethertype_filter = msg.data[0] as u16;
                    let flags = (msg.data[0] >> 16) as u8;
                    let dst_ipv4 = msg.data[1] as u32;
                    let dst_prefix_len = (msg.data[1] >> 32) as u8;
                    let reply_port = msg.data[2];
                    dev.subscribe(
                        ethertype_filter, flags, dst_ipv4, dst_prefix_len, reply_port,
                    );
                }
                ETH_UNSUBSCRIBE => {
                    let sub_id = msg.data[0] as usize;
                    let reply_port = msg.data[1];
                    dev.unsubscribe(sub_id, reply_port);
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
                    syscall::send_nb(
                        reply_port,
                        NETIF_STATUS_OK,
                        mac_to_u64(dev.mac),
                        MTU as u64 | (1u64 << 32), // mtu | link_up flag
                    );
                }

                // --- Legacy net_srv compat ---
                NET_STATUS => {
                    let reply_port = msg.data[0];
                    let mac_val = mac_to_u64(dev.mac);
                    let ip_val = u32::from_be_bytes(MY_IP) as u64;
                    syscall::send_nb(reply_port, NET_STATUS_OK, mac_val, ip_val);
                }
                NET_PING => {
                    let target = (msg.data[0] as u32).to_be_bytes();
                    let reply_port = msg.data[1];
                    syscall::debug_puts(b"  [eth_srv] ping ");
                    print_ip(target);
                    syscall::debug_puts(b"\n");
                    dev.start_ping(target, reply_port);
                }
                _ => {}
            }
        }

        // 3. Tick timeouts.
        dev.tick_ping();
        dev.tick_arp_pending();

        // 4. Yield.
        syscall::yield_now();
    }
}
