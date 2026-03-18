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

// --- Legacy virtio-PCI BAR0 register offsets (x86_64 only) ---
#[cfg(target_arch = "x86_64")]
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
        if i > 0 { syscall::debug_putchar(b':'); }
        let hi = mac[i] >> 4;
        let lo = mac[i] & 0xF;
        syscall::debug_putchar(if hi < 10 { b'0' + hi } else { b'a' + hi - 10 });
        syscall::debug_putchar(if lo < 10 { b'0' + lo } else { b'a' + lo - 10 });
    }
}

fn print_ip(ip: [u8; 4]) {
    for i in 0..4 {
        if i > 0 { syscall::debug_putchar(b'.'); }
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
            core::ptr::write_volatile(desc, VringDesc { addr, len, flags, next: 0 });
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
    ping_reply_port: u32,
    ping_seq: u16,
    ping_polls: u32,
    ping_active: bool,
    ping_sent_icmp: bool,
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
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
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

    #[cfg(not(target_arch = "x86_64"))]
    fn setup_queue_mmio(mmio_va: usize, queue_idx: u32, version: u32) -> Option<Virtqueue> {
        mmio_write32(mmio_va, MMIO_QUEUE_SEL, queue_idx);
        let max = mmio_read32(mmio_va, MMIO_QUEUE_NUM_MAX);
        if max == 0 { return None; }
        let qsize = (QUEUE_SIZE as u32).min(max);
        mmio_write32(mmio_va, MMIO_QUEUE_NUM, qsize);

        let vq_va = syscall::mmap_anon(0, 1, 1)?;
        let vq_pa = syscall::virt_to_phys(vq_va)?;
        unsafe { core::ptr::write_bytes(vq_va as *mut u8, 0, 4096); }

        let buf_va = syscall::mmap_anon(0, 1, 1)?;
        let buf_pa = syscall::virt_to_phys(buf_va)?;
        unsafe { core::ptr::write_bytes(buf_va as *mut u8, 0, 4096); }

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

    /// PCI transport init for x86_64.
    #[cfg(target_arch = "x86_64")]
    fn init(bar0_port: usize, irq: u32) -> Option<Self> {
        let base = bar0_port as u16;

        syscall::debug_puts(b"  [net_srv] PCI BAR0 port ");
        print_hex(base as u64);
        syscall::debug_puts(b"\n");

        // Reset.
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS, 0);

        // ACK + DRIVER.
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS, STATUS_ACK as u8);
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS,
            (STATUS_ACK | STATUS_DRIVER) as u8);

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
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS,
            (STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK) as u8);

        let mut dev = Self::new_dev(base as usize, mac, rx, tx);
        dev.post_rx();
        Some(dev)
    }

    #[cfg(target_arch = "x86_64")]
    fn setup_queue_pci(base: u16, queue_idx: u16) -> Option<Virtqueue> {
        syscall::ioport_outw(base + pci_regs::QUEUE_SELECT, queue_idx);
        let max = syscall::ioport_inw(base + pci_regs::QUEUE_SIZE);
        if max == 0 { return None; }

        // Legacy PCI: queue size is fixed by the device (read-only).
        let qsz = max as usize;

        // Allocate virtqueue page (64K alloc page fits desc+avail+used with 4K alignment).
        let vq_va = syscall::mmap_anon(0, 1, 1)?;
        let vq_pa = syscall::virt_to_phys(vq_va)?;
        unsafe { core::ptr::write_bytes(vq_va as *mut u8, 0, 4096 * 16); }

        let buf_va = syscall::mmap_anon(0, 1, 1)?;
        let buf_pa = syscall::virt_to_phys(buf_va)?;
        unsafe { core::ptr::write_bytes(buf_va as *mut u8, 0, 4096); }

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
        #[cfg(not(target_arch = "x86_64"))]
        mmio_write32(self.base, MMIO_QUEUE_NOTIFY, queue_idx as u32);
        #[cfg(target_arch = "x86_64")]
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
        put_u16_be(&mut frame, 14, 1);      // hw type = ethernet
        put_u16_be(&mut frame, 16, 0x0800); // proto = IPv4
        frame[18] = 6; // hw addr len
        frame[19] = 4; // proto addr len
        put_u16_be(&mut frame, 20, 1);      // op = request
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
        put_u16_be(ip, 4, 1);  // identification
        put_u16_be(ip, 6, 0x4000); // don't fragment
        ip[8] = 64; // TTL
        ip[9] = 1;  // ICMP
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
            core::slice::from_raw_parts(
                (self.rx.buf_va + NET_HDR_SIZE) as *const u8,
                frame_len,
            )
        };
        if frame_len < 14 { return; }
        let ethertype = get_u16_be(frame, 12);
        match ethertype {
            0x0806 => self.handle_arp(&frame[14..frame_len]),
            0x0800 => self.handle_ipv4(&frame[14..frame_len]),
            _ => {}
        }
    }

    fn handle_arp(&mut self, data: &[u8]) {
        if data.len() < 28 { return; }
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
        if data.len() < 20 { return; }
        let ihl = (data[0] & 0x0F) as usize * 4;
        let total_len = get_u16_be(data, 2) as usize;
        let proto = data[9];
        if proto == 1 && total_len > ihl {
            // ICMP.
            let end = total_len.min(data.len());
            self.handle_icmp(&data[ihl..end]);
        }
    }

    fn handle_icmp(&mut self, data: &[u8]) {
        if data.len() < 8 { return; }
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

    fn start_ping(&mut self, target_ip: [u8; 4], reply_port: u32) {
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
        if !self.ping_active { return; }
        self.ping_polls += 1;
        if self.ping_polls >= PING_TIMEOUT {
            syscall::send_nb(self.ping_reply_port, NET_PING_FAIL, 1, 0);
            self.ping_active = false;
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
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [net_srv] ready, MAC=");
    print_mac(dev.mac);
    syscall::debug_puts(b" IP=");
    print_ip(MY_IP);
    syscall::debug_puts(b"\n");

    // Register with name server.
    let port = syscall::port_create() as u32;
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
                    let reply_port = msg.data[0] as u32;
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
                    let reply_port = msg.data[1] as u32;
                    syscall::debug_puts(b"  [net_srv] ping ");
                    print_ip(target);
                    syscall::debug_puts(b"\n");
                    dev.start_ping(target, reply_port);
                }
                _ => {}
            }
        }

        // 3. Tick ping timeout.
        dev.tick_ping();

        // 4. Yield.
        syscall::yield_now();
    }
}
