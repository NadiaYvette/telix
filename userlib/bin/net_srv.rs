#![no_std]
#![no_main]

//! Userspace virtio-net driver with minimal network stack (ARP/IPv4/ICMP).
//!
//! Receives device info (mmio_base, irq) via arg0 from the kernel.
//! Maps MMIO registers, sets up RX/TX virtqueues, and serves NET_PING
//! requests. Poll-based, following the blk_srv pattern.

extern crate userlib;

use userlib::syscall;

// --- IPC protocol ---
const NET_STATUS: u64 = 0x4000;
const NET_STATUS_OK: u64 = 0x4001;
const NET_PING: u64 = 0x4100;
const NET_PING_OK: u64 = 0x4101;
const NET_PING_FAIL: u64 = 0x41FF;

// TCP IPC protocol.
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

// TCP listen/accept protocol.
const NET_TCP_BIND: u64 = 0x4600;
const NET_TCP_BIND_OK: u64 = 0x4601;
const NET_TCP_LISTEN: u64 = 0x4700;
const NET_TCP_LISTEN_OK: u64 = 0x4701;
const NET_TCP_LISTEN_FAIL: u64 = 0x47FF;
const NET_TCP_ACCEPT: u64 = 0x4710;
const NET_TCP_ACCEPT_OK: u64 = 0x4711;
const NET_TCP_ACCEPT_FAIL: u64 = 0x47FE;

// Non-blocking recv.
const NET_TCP_RECV_NB: u64 = 0x4410;
const NET_TCP_RECV_NONE: u64 = 0x4412;

// TCP flags.
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

// TCP states.
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

// Listen slot: tracks a port in LISTEN state with pending accept.
struct ListenSlot {
    active: bool,
    port: u16,
    accept_reply_port: u64, // 0 = no pending accept
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
const TCP_RX_BUF_SIZE: usize = 2048;
const TCP_TIMEOUT: u32 = 10000;
const TCP_TIME_WAIT_TIMEOUT: u32 = 5000;

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
#[cfg(any(target_arch = "x86_64", target_arch = "mips64"))]
mod pci_regs {
    pub const DEVICE_FEATURES: u16 = 0x00;
    pub const DRIVER_FEATURES: u16 = 0x04;
    pub const QUEUE_ADDRESS: u16 = 0x08;
    pub const QUEUE_SIZE: u16 = 0x0C;
    pub const QUEUE_SELECT: u16 = 0x0E;
    pub const QUEUE_NOTIFY: u16 = 0x10;
    pub const DEVICE_STATUS: u16 = 0x12;
    pub const ISR_STATUS: u16 = 0x13;
    // Net device config at offset 0x14: MAC address (6 bytes).
    pub const NET_MAC: u16 = 0x14;
}

/// Virtio-net header size (without VIRTIO_NET_F_MRG_RXBUF).
const NET_HDR_SIZE: usize = 10;
/// Max ethernet frame: 14 header + 1500 MTU.
const MAX_FRAME: usize = 1514;

// Network config (QEMU user-mode defaults).
const MY_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

const PING_TIMEOUT: u32 = 5000;

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

fn get_u32_be(buf: &[u8], off: usize) -> u32 {
    ((buf[off] as u32) << 24)
        | ((buf[off + 1] as u32) << 16)
        | ((buf[off + 2] as u32) << 8)
        | (buf[off + 3] as u32)
}

fn put_u32_be(buf: &mut [u8], off: usize, val: u32) {
    buf[off] = (val >> 24) as u8;
    buf[off + 1] = (val >> 16) as u8;
    buf[off + 2] = (val >> 8) as u8;
    buf[off + 3] = val as u8;
}

/// TCP checksum with IP pseudo-header.
fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_data: &[u8]) -> u16 {
    let mut sum = 0u32;
    // Pseudo-header: src_ip (4) + dst_ip (4) + zero + proto(6) + tcp_len (2)
    sum += ((src_ip[0] as u32) << 8) | (src_ip[1] as u32);
    sum += ((src_ip[2] as u32) << 8) | (src_ip[3] as u32);
    sum += ((dst_ip[0] as u32) << 8) | (dst_ip[1] as u32);
    sum += ((dst_ip[2] as u32) << 8) | (dst_ip[3] as u32);
    sum += 6u32; // protocol = TCP
    sum += tcp_data.len() as u32;
    // TCP segment data
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
            } // full
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

// --- Network device ---

struct NetDev {
    /// On aarch64/riscv64: MMIO virtual address.
    /// On x86_64: BAR0 I/O port base.
    base: usize,
    mac: [u8; 6],
    rx: Virtqueue,
    tx: Virtqueue,
    // ARP cache.
    arp_ip: [[u8; 4]; 4],
    arp_mac: [[u8; 6]; 4],
    arp_valid: [bool; 4],
    arp_next: usize,
    // Pending ping state.
    ping_target: [u8; 4],
    ping_reply_port: u64,
    ping_seq: u16,
    ping_polls: u32,
    ping_active: bool,
    ping_sent_icmp: bool,
    // TCP state.
    tcp: [TcpConn; MAX_TCP_CONNS],
    next_ephemeral_port: u16,
    tcp_isn: u32,
    // TCP listen state.
    listen: [ListenSlot; MAX_LISTEN_SLOTS],
}

impl NetDev {
    fn new_dev(base: usize, mac: [u8; 6], rx: Virtqueue, tx: Virtqueue) -> Self {
        Self {
            base,
            mac,
            rx,
            tx,
            arp_ip: [[0; 4]; 4],
            arp_mac: [[0; 6]; 4],
            arp_valid: [false; 4],
            arp_next: 0,
            ping_target: [0; 4],
            ping_reply_port: 0,
            ping_seq: 0,
            ping_polls: 0,
            ping_active: false,
            ping_sent_icmp: false,
            tcp: [const { TcpConn::new() }; MAX_TCP_CONNS],
            next_ephemeral_port: 49152,
            tcp_isn: (mac[0] as u32) << 24
                | (mac[1] as u32) << 16
                | (mac[2] as u32) << 8
                | (mac[3] as u32),
            listen: [const { ListenSlot::new() }; MAX_LISTEN_SLOTS],
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "mips64")))]
    fn init(mmio_phys: usize, irq: u32) -> Option<Self> {
        let mmio_va = syscall::mmap_device(mmio_phys, 1)?;

        syscall::debug_puts(b"  [net_srv] MMIO mapped at VA ");
        print_hex(mmio_va as u64);
        syscall::debug_puts(b"\n");

        if mmio_read32(mmio_va, MMIO_MAGIC_VALUE) != VIRTIO_MAGIC {
            syscall::debug_puts(b"  [net_srv] bad magic\n");
            return None;
        }
        if mmio_read32(mmio_va, MMIO_DEVICE_ID) != DEVICE_NET {
            syscall::debug_puts(b"  [net_srv] not a net device\n");
            return None;
        }

        let version = mmio_read32(mmio_va, MMIO_VERSION);
        syscall::debug_puts(b"  [net_srv] virtio version ");
        print_num(version as u64);
        syscall::debug_puts(b"\n");

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
                syscall::debug_puts(b"  [net_srv] FEATURES_OK failed\n");
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

        // NOTE: We don't call irq_wait — net_srv is fully poll-based.
        let _ = irq;

        // DRIVER_OK.
        status |= STATUS_DRIVER_OK;
        mmio_write32(mmio_va, MMIO_STATUS, status);

        let mut dev = Self::new_dev(mmio_va, mac, rx, tx);
        dev.post_rx();
        Some(dev)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "mips64")))]
    fn setup_queue_mmio(mmio_va: usize, queue_idx: u32, version: u32) -> Option<Virtqueue> {
        mmio_write32(mmio_va, MMIO_QUEUE_SEL, queue_idx);
        let max = mmio_read32(mmio_va, MMIO_QUEUE_NUM_MAX);
        if max == 0 {
            return None;
        }
        let qsize = (QUEUE_SIZE as u32).min(max);
        mmio_write32(mmio_va, MMIO_QUEUE_NUM, qsize);

        let vq_va = syscall::mmap_anon(0, 1, 1)?;
        let vq_pa = syscall::virt_to_phys(vq_va)?;
        unsafe {
            core::ptr::write_bytes(vq_va as *mut u8, 0, 4096);
        }

        let buf_va = syscall::mmap_anon(0, 1, 1)?;
        let buf_pa = syscall::virt_to_phys(buf_va)?;
        unsafe {
            core::ptr::write_bytes(buf_va as *mut u8, 0, 4096);
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

    /// PCI transport init for x86_64 / mips64.
    #[cfg(any(target_arch = "x86_64", target_arch = "mips64"))]
    fn init(bar0_port: usize, irq: u32) -> Option<Self> {
        let base = bar0_port as u16;

        syscall::debug_puts(b"  [net_srv] PCI BAR0 port ");
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

        // Legacy PCI: queue size is fixed by the device (read-only).
        let qsz = max as usize;

        // Allocate virtqueue page (64K alloc page fits desc+avail+used with 4K alignment).
        let vq_va = syscall::mmap_anon(0, 1, 1)?;
        let vq_pa = syscall::virt_to_phys(vq_va)?;
        unsafe {
            core::ptr::write_bytes(vq_va as *mut u8, 0, 4096 * 16);
        }

        let buf_va = syscall::mmap_anon(0, 1, 1)?;
        let buf_pa = syscall::virt_to_phys(buf_va)?;
        unsafe {
            core::ptr::write_bytes(buf_va as *mut u8, 0, 4096);
        }

        let desc_pa = vq_pa;
        let avail_pa = desc_pa + 16 * qsz;
        let avail_end = avail_pa + 6 + 2 * qsz;
        let used_pa = (avail_end + 4095) & !4095;
        let avail_offset = avail_pa - desc_pa;
        let used_offset = used_pa - desc_pa;

        // Write queue PFN.
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

    fn notify_queue(&self, queue_idx: u16) {
        #[cfg(not(any(target_arch = "x86_64", target_arch = "mips64")))]
        mmio_write32(self.base, MMIO_QUEUE_NOTIFY, queue_idx as u32);
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
        self.tx.post_desc(0, self.tx.buf_pa as u64, total as u32, 0);
        self.notify_queue(1);

        // Poll for TX completion.
        for _ in 0..1000 {
            if self.tx.check_used().is_some() {
                return;
            }
            syscall::yield_now();
        }
    }

    // --- ARP ---

    fn arp_lookup(&self, ip: [u8; 4]) -> Option<[u8; 6]> {
        for i in 0..4 {
            if self.arp_valid[i] && self.arp_ip[i] == ip {
                return Some(self.arp_mac[i]);
            }
        }
        None
    }

    fn arp_store(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        for i in 0..4 {
            if self.arp_valid[i] && self.arp_ip[i] == ip {
                self.arp_mac[i] = mac;
                return;
            }
        }
        let idx = self.arp_next % 4;
        self.arp_ip[idx] = ip;
        self.arp_mac[idx] = mac;
        self.arp_valid[idx] = true;
        self.arp_next += 1;
    }

    fn send_arp_request(&mut self, target_ip: [u8; 4]) {
        let mut frame = [0u8; 42]; // 14 eth + 28 arp
        // Ethernet: broadcast dst, our src, ethertype ARP.
        frame[0..6].copy_from_slice(&[0xFF; 6]);
        frame[6..12].copy_from_slice(&self.mac);
        frame[12] = 0x08;
        frame[13] = 0x06;
        // ARP request.
        put_u16_be(&mut frame, 14, 1); // hw type = ethernet
        put_u16_be(&mut frame, 16, 0x0800); // proto = IPv4
        frame[18] = 6; // hw addr len
        frame[19] = 4; // proto addr len
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

    // --- ICMP ---

    fn send_icmp_echo(&mut self, dst_ip: [u8; 4], dst_mac: [u8; 6], seq: u16) {
        // 14 eth + 20 ip + 8 icmp hdr + 32 payload = 74 bytes.
        let mut frame = [0u8; 74];
        // Ethernet.
        frame[0..6].copy_from_slice(&dst_mac);
        frame[6..12].copy_from_slice(&self.mac);
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        // IPv4 header (20 bytes at offset 14).
        let ip = &mut frame[14..34];
        ip[0] = 0x45; // v4, IHL=5
        put_u16_be(ip, 2, 60); // total len = 20 + 8 + 32
        put_u16_be(ip, 4, 1); // identification
        put_u16_be(ip, 6, 0x4000); // don't fragment
        ip[8] = 64; // TTL
        ip[9] = 1; // ICMP
        ip[12..16].copy_from_slice(&MY_IP);
        ip[16..20].copy_from_slice(&dst_ip);
        let cksum = inet_checksum(ip);
        ip[10] = (cksum >> 8) as u8;
        ip[11] = cksum as u8;
        // ICMP echo request (offset 34).
        let icmp = &mut frame[34..74];
        icmp[0] = 8; // echo request
        put_u16_be(icmp, 4, 0x1234); // identifier
        put_u16_be(icmp, 6, seq);
        for i in 0..32 {
            icmp[8 + i] = i as u8;
        }
        let cksum = inet_checksum(icmp);
        icmp[2] = (cksum >> 8) as u8;
        icmp[3] = cksum as u8;
        self.tx_send(&frame);
    }

    // --- Packet RX handlers ---

    fn handle_rx_packet(&mut self, frame_len: usize) {
        let frame = unsafe {
            core::slice::from_raw_parts((self.rx.buf_va + NET_HDR_SIZE) as *const u8, frame_len)
        };
        if frame_len < 14 {
            return;
        }
        let ethertype = get_u16_be(frame, 12);
        match ethertype {
            0x0806 => self.handle_arp(&frame[14..frame_len]),
            0x0800 => self.handle_ipv4(&frame[14..frame_len]),
            _ => {}
        }
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
            syscall::debug_puts(b"  [net_srv] ARP reply from ");
            print_ip(sender_ip);
            syscall::debug_puts(b"\n");
            // If pending ping waiting for ARP, send ICMP now.
            if self.ping_active && !self.ping_sent_icmp && self.ping_target == sender_ip {
                self.send_icmp_echo(self.ping_target, sender_mac, self.ping_seq);
                self.ping_sent_icmp = true;
            }
            // Send pending TCP SYNs for this IP.
            self.handle_arp_for_tcp(sender_ip);
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
        match proto {
            1 => self.handle_icmp(&data[ihl..end]),
            6 => {
                let src_ip = [data[12], data[13], data[14], data[15]];
                self.handle_tcp_rx(src_ip, &data[ihl..end]);
            }
            _ => {}
        }
    }

    fn handle_icmp(&mut self, data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        if data[0] == 0 {
            // Echo reply.
            let seq = get_u16_be(data, 6);
            syscall::debug_puts(b"  [net_srv] ICMP echo reply seq=");
            print_num(seq as u64);
            syscall::debug_puts(b"\n");
            if self.ping_active && seq == self.ping_seq {
                syscall::send_nb(self.ping_reply_port, NET_PING_OK, 0, 0);
                self.ping_active = false;
            }
        }
    }

    // --- Ping management ---

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

        if let Some(mac) = self.arp_lookup(target_ip) {
            self.send_icmp_echo(target_ip, mac, self.ping_seq);
            self.ping_sent_icmp = true;
        } else {
            self.send_arp_request(target_ip);
        }
    }

    fn tick_ping(&mut self) {
        if !self.ping_active {
            return;
        }
        self.ping_polls += 1;
        if self.ping_polls >= PING_TIMEOUT {
            syscall::send_nb(self.ping_reply_port, NET_PING_FAIL, 1, 0);
            self.ping_active = false;
        }
    }

    // --- TCP ---

    fn build_tcp_packet(
        &mut self,
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
        let ip_total = 20 + tcp_len;
        let frame_len = 14 + ip_total;
        let mut frame = [0u8; 14 + 20 + 20 + 1460]; // max MTU
        // Ethernet header.
        frame[0..6].copy_from_slice(&dst_mac);
        frame[6..12].copy_from_slice(&self.mac);
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        // IPv4 header (20 bytes at offset 14).
        let ip = &mut frame[14..34];
        ip[0] = 0x45; // v4, IHL=5
        put_u16_be(ip, 2, ip_total as u16);
        put_u16_be(ip, 4, 0); // identification
        put_u16_be(ip, 6, 0x4000); // don't fragment
        ip[8] = 64; // TTL
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&MY_IP);
        ip[16..20].copy_from_slice(&dst_ip);
        let cksum = inet_checksum(ip);
        ip[10] = (cksum >> 8) as u8;
        ip[11] = cksum as u8;
        // TCP header (20 bytes at offset 34).
        let tcp = &mut frame[34..34 + tcp_len];
        put_u16_be(tcp, 0, src_port);
        put_u16_be(tcp, 2, dst_port);
        put_u32_be(tcp, 4, seq);
        put_u32_be(tcp, 8, ack);
        tcp[12] = 5 << 4; // data offset = 5 (20 bytes)
        tcp[13] = flags;
        put_u16_be(tcp, 14, 2048); // window size
        // Copy payload.
        if !payload.is_empty() {
            tcp[20..20 + payload.len()].copy_from_slice(payload);
        }
        // TCP checksum.
        let cksum = tcp_checksum(&MY_IP, &dst_ip, tcp);
        tcp[16] = (cksum >> 8) as u8;
        tcp[17] = cksum as u8;
        self.tx_send(&frame[..frame_len]);
    }

    fn send_tcp_for_conn(&mut self, conn_idx: usize, flags: u8, payload: &[u8]) {
        let dst_ip = self.tcp[conn_idx].remote_ip;
        let src_port = self.tcp[conn_idx].local_port;
        let dst_port = self.tcp[conn_idx].remote_port;
        let seq = self.tcp[conn_idx].snd_nxt;
        let ack = self.tcp[conn_idx].rcv_nxt;
        if let Some(mac) = self.arp_lookup(dst_ip) {
            self.build_tcp_packet(dst_ip, mac, src_port, dst_port, seq, ack, flags, payload);
        }
    }

    fn handle_tcp_connect(&mut self, dst_ip_be: u32, dst_port: u16, reply_port: u64) {
        // Find free slot.
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

        syscall::debug_puts(b"  [net_srv] TCP connect to ");
        print_ip(remote_ip);
        syscall::debug_puts(b":");
        print_num(dst_port as u64);
        syscall::debug_puts(b" slot=");
        print_num(slot as u64);
        syscall::debug_puts(b"\n");

        // ARP lookup — send SYN if cached, else ARP request.
        if let Some(mac) = self.arp_lookup(remote_ip) {
            self.build_tcp_packet(remote_ip, mac, local_port, dst_port, isn, 0, TCP_SYN, &[]);
        } else {
            self.send_arp_request(remote_ip);
        }
    }

    fn handle_arp_for_tcp(&mut self, ip: [u8; 4]) {
        // After ARP reply, send pending SYN for any SYN_SENT connections to this IP.
        let mac = match self.arp_lookup(ip) {
            Some(m) => m,
            None => return,
        };
        for i in 0..MAX_TCP_CONNS {
            if self.tcp[i].state == TCP_SYN_SENT && self.tcp[i].remote_ip == ip {
                let src_port = self.tcp[i].local_port;
                let dst_port = self.tcp[i].remote_port;
                let seq = self.tcp[i].snd_nxt;
                self.build_tcp_packet(ip, mac, src_port, dst_port, seq, 0, TCP_SYN, &[]);
            }
        }
    }

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
                // Check if this is a SYN for a listen port.
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
                // Expect SYN+ACK.
                if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 {
                    // Verify ACK covers our SYN.
                    if ack != self.tcp[idx].snd_nxt.wrapping_add(1) {
                        return;
                    }
                    self.tcp[idx].snd_una = ack;
                    self.tcp[idx].snd_nxt = ack;
                    self.tcp[idx].rcv_nxt = seq.wrapping_add(1);
                    self.tcp[idx].state = TCP_ESTABLISHED;
                    self.tcp[idx].timeout = 0;
                    // Send ACK.
                    self.send_tcp_for_conn(idx, TCP_ACK, &[]);
                    // Notify client.
                    let reply_port = self.tcp[idx].reply_port;
                    syscall::send_nb(reply_port, NET_TCP_CONNECTED, idx as u64, 0);
                    syscall::debug_puts(b"  [net_srv] TCP ESTABLISHED slot=");
                    print_num(idx as u64);
                    syscall::debug_puts(b"\n");
                }
            }
            TCP_SYN_RECEIVED => {
                // Expect ACK completing 3-way handshake.
                if flags & TCP_ACK != 0 {
                    self.tcp[idx].snd_una = ack;
                    self.tcp[idx].state = TCP_ESTABLISHED;
                    self.tcp[idx].timeout = 0;
                    syscall::debug_puts(b"  [net_srv] TCP accept ESTABLISHED slot=");
                    print_num(idx as u64);
                    syscall::debug_puts(b"\n");
                    // Notify pending accept.
                    let reply_port = self.tcp[idx].reply_port;
                    if reply_port != 0 {
                        self.tcp[idx].reply_port = 0;
                        syscall::send_nb(reply_port, NET_TCP_ACCEPT_OK, idx as u64, 0);
                    }
                }
            }
            TCP_ESTABLISHED => {
                // Data and/or FIN.
                if flags & TCP_ACK != 0 {
                    self.tcp[idx].snd_una = ack;
                }
                if !payload.is_empty() && seq == self.tcp[idx].rcv_nxt {
                    self.tcp[idx].rcv_nxt = seq.wrapping_add(payload.len() as u32);
                    self.tcp[idx].rx_push(payload);
                    // Send ACK.
                    self.send_tcp_for_conn(idx, TCP_ACK, &[]);
                    // If someone waiting for recv, deliver now.
                    let recv_port = self.tcp[idx].recv_reply_port;
                    if recv_port != 0 {
                        self.tcp[idx].recv_reply_port = 0;
                        self.deliver_tcp_data(idx, recv_port);
                    }
                }
                if flags & TCP_FIN != 0 {
                    self.tcp[idx].rcv_nxt = self.tcp[idx].rcv_nxt.wrapping_add(1);
                    self.send_tcp_for_conn(idx, TCP_ACK, &[]);
                    self.tcp[idx].state = TCP_CLOSE_WAIT;
                    // Notify pending recv.
                    let recv_port = self.tcp[idx].recv_reply_port;
                    if recv_port != 0 {
                        self.tcp[idx].recv_reply_port = 0;
                        syscall::send_nb(recv_port, NET_TCP_CLOSED, idx as u64, 0);
                    }
                }
            }
            TCP_FIN_WAIT_1 => {
                if flags & TCP_ACK != 0 {
                    self.tcp[idx].snd_una = ack;
                    if flags & TCP_FIN != 0 {
                        // Simultaneous close: FIN+ACK.
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

    fn deliver_tcp_data(&mut self, idx: usize, reply_port: u64) {
        let mut buf = [0u8; 24]; // max inline bytes in 3 IPC data words
        let n = self.tcp[idx].rx_pop(&mut buf);
        if n == 0 {
            return;
        }
        // Pack into IPC: data[0]=len, data[1..3]=bytes (up to 24 bytes in 3 words).
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
        if self.tcp[conn_id].rx_len() > 0 {
            self.deliver_tcp_data(conn_id, reply_port);
        } else if self.tcp[conn_id].state == TCP_ESTABLISHED {
            // Defer: store reply port for when data arrives.
            self.tcp[conn_id].recv_reply_port = reply_port;
        } else {
            // Connection closed and no data.
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

    fn handle_incoming_syn(&mut self, src_ip: [u8; 4], src_port: u16, dst_port: u16, seq: u32) {
        // Check if we have a listen slot for this port.
        let listen_idx = self
            .listen
            .iter()
            .position(|l| l.active && l.port == dst_port);
        if listen_idx.is_none() {
            return;
        }
        let listen_idx = listen_idx.unwrap();

        // Find free TCP conn slot.
        let slot = self.tcp.iter().position(|c| c.state == TCP_CLOSED);
        let slot = match slot {
            Some(s) => s,
            None => return, // No free slots.
        };

        let isn = self.tcp_isn;
        self.tcp_isn = self.tcp_isn.wrapping_add(64000);

        self.tcp[slot] = TcpConn {
            state: TCP_SYN_RECEIVED,
            local_port: dst_port,
            remote_ip: src_ip,
            remote_port: src_port,
            snd_nxt: isn.wrapping_add(1), // SYN consumes 1 seq
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
        if let Some(mac) = self.arp_lookup(src_ip) {
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
        } else {
            // Need ARP first.
            self.send_arp_request(src_ip);
        }

        syscall::debug_puts(b"  [net_srv] SYN-ACK sent slot=");
        print_num(slot as u64);
        syscall::debug_puts(b"\n");

        // If there's a pending accept, wire it up.
        let accept_rp = self.listen[listen_idx].accept_reply_port;
        if accept_rp != 0 {
            self.listen[listen_idx].accept_reply_port = 0;
            self.tcp[slot].reply_port = accept_rp;
            // The accept reply will be sent when SYN_RECEIVED -> ESTABLISHED.
        }
    }

    fn handle_tcp_bind(&mut self, port: u16, reply_port: u64) {
        // Just acknowledge. Actual listen state created in handle_tcp_listen.
        syscall::send_nb(reply_port, NET_TCP_BIND_OK, port as u64, 0);
    }

    fn handle_tcp_listen_req(&mut self, port: u16, _backlog: u32, reply_port: u64) {
        // Find free listen slot.
        let slot = self.listen.iter().position(|l| !l.active);
        match slot {
            Some(s) => {
                self.listen[s] = ListenSlot {
                    active: true,
                    port,
                    accept_reply_port: 0,
                };
                syscall::debug_puts(b"  [net_srv] TCP LISTEN port=");
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
        // Check if there's already an ESTABLISHED connection from a listen on this port.
        // (SYN_RECEIVED that completed before accept was called.)
        for i in 0..MAX_TCP_CONNS {
            if self.tcp[i].state == TCP_ESTABLISHED
                && self.tcp[i].local_port == port
                && self.tcp[i].reply_port == 0
            {
                // This is a connection that completed via listen but hasn't been accepted yet.
                // Actually we can't distinguish this reliably. Let's check for SYN_RECEIVED too.
            }
        }

        // Check for already-established connections waiting to be accepted.
        for i in 0..MAX_TCP_CONNS {
            if (self.tcp[i].state == TCP_ESTABLISHED || self.tcp[i].state == TCP_SYN_RECEIVED)
                && self.tcp[i].local_port == port
            {
                if self.tcp[i].state == TCP_ESTABLISHED {
                    // Already established, return immediately.
                    syscall::send_nb(reply_port, NET_TCP_ACCEPT_OK, i as u64, 0);
                    return;
                }
                // SYN_RECEIVED — store reply port, will notify when handshake completes.
                self.tcp[i].reply_port = reply_port;
                return;
            }
        }

        // No pending connections. Store accept reply port in listen slot for later.
        for l in self.listen.iter_mut() {
            if l.active && l.port == port {
                l.accept_reply_port = reply_port;
                return;
            }
        }
        syscall::send_nb(reply_port, NET_TCP_ACCEPT_FAIL, 0, 0);
    }

    fn tick_tcp(&mut self) {
        for i in 0..MAX_TCP_CONNS {
            match self.tcp[i].state {
                TCP_SYN_SENT => {
                    self.tcp[i].timeout += 1;
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
}

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let base = (arg0 & 0xFFFF_FFFF_FFFF) as usize;
    let irq = (arg0 >> 48) as u32;

    syscall::debug_puts(b"  [net_srv] starting, base=");
    print_hex(base as u64);
    syscall::debug_puts(b" irq=");
    print_num(irq as u64);
    syscall::debug_puts(b"\n");

    let mut dev = match NetDev::init(base, irq) {
        Some(d) => d,
        None => {
            syscall::debug_puts(b"  [net_srv] init failed\n");
            loop {
                core::hint::spin_loop();
            }
        }
    };

    syscall::debug_puts(b"  [net_srv] ready, MAC=");
    print_mac(dev.mac);
    syscall::debug_puts(b" IP=");
    print_ip(MY_IP);
    syscall::debug_puts(b"\n");

    // Register with name server.
    let port = syscall::port_create();
    syscall::ns_register(b"net", port);

    syscall::debug_puts(b"  [net_srv] registered on port ");
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
                NET_STATUS => {
                    let reply_port = msg.data[0];
                    let mac_val = (dev.mac[0] as u64)
                        | ((dev.mac[1] as u64) << 8)
                        | ((dev.mac[2] as u64) << 16)
                        | ((dev.mac[3] as u64) << 24)
                        | ((dev.mac[4] as u64) << 32)
                        | ((dev.mac[5] as u64) << 40);
                    let ip_val = u32::from_be_bytes(MY_IP) as u64;
                    syscall::send_nb(reply_port, NET_STATUS_OK, mac_val, ip_val);
                }
                NET_PING => {
                    let target = (msg.data[0] as u32).to_be_bytes();
                    let reply_port = msg.data[1];
                    syscall::debug_puts(b"  [net_srv] ping ");
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
                    // Payload packed in data[2] and data[3] (up to 16 bytes).
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

        // 3. Tick timeouts.
        dev.tick_ping();
        dev.tick_tcp();

        // 4. Yield.
        syscall::yield_now();
    }
}
