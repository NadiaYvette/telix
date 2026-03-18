#![no_std]
#![no_main]

//! Userspace virtio-blk device driver and IPC server.
//!
//! Receives device info (mmio_base, irq) via arg0 from the kernel.
//! Maps MMIO registers, sets up virtqueue, and serves IO_READ/IO_WRITE requests.

extern crate userlib;

use userlib::syscall;

// --- I/O protocol constants ---
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
const IO_WRITE: u64 = 0x300;
const IO_WRITE_OK: u64 = 0x301;
const IO_STAT: u64 = 0x400;
const IO_STAT_OK: u64 = 0x401;
const IO_CLOSE: u64 = 0x500;
const IO_ERROR: u64 = 0xF00;
const ERR_IO: u64 = 1;

const MAX_INLINE_READ: usize = 40;

// --- Virtio MMIO register offsets ---
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
const DEVICE_BLK: u32 = 2;
const STATUS_ACK: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_DRIVER_OK: u32 = 4;

// --- Virtqueue constants ---
const QUEUE_SIZE: usize = 16;
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;

// --- Virtqueue structures ---
#[repr(C)]
#[derive(Clone, Copy)]
struct VringDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
#[allow(dead_code)]
struct VringAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct VringUsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
#[allow(dead_code)]
struct VringUsed {
    flags: u16,
    idx: u16,
    ring: [VringUsedElem; QUEUE_SIZE],
}

#[repr(C)]
struct VirtioBlkReqHdr {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

// --- MMIO read/write helpers ---
fn mmio_read32(base: usize, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

fn mmio_write32(base: usize, offset: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val); }
}

fn pack_inline_data(data: &[u8]) -> [u64; 5] {
    let mut words = [0u64; 5];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE_READ) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
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

/// Userspace block device driver state.
struct BlkDev {
    mmio_va: usize,
    #[allow(dead_code)]
    irq: u32,
    /// VA of the virtqueue page (desc + avail + used rings).
    vq_va: usize,
    /// VA of the buffer page (request header + status + data).
    buf_va: usize,
    /// Physical addresses for DMA descriptors.
    desc_pa: usize,
    #[allow(dead_code)]
    avail_pa: usize,
    used_pa: usize,
    req_hdr_pa: usize,
    status_pa: usize,
    data_pa: usize,
    /// Next descriptor to allocate.
    next_desc: u16,
    /// Last seen used index.
    last_used_idx: u16,
    /// Capacity in 512-byte sectors.
    capacity: u64,
    /// Actual virtqueue size (device-reported on PCI, negotiated on MMIO).
    queue_size: usize,
}

// --- Legacy virtio-PCI BAR0 register offsets ---
#[cfg(target_arch = "x86_64")]
mod pci_regs {
    pub const DEVICE_FEATURES: u16 = 0x00;  // 32-bit read
    pub const DRIVER_FEATURES: u16 = 0x04;  // 32-bit write
    pub const QUEUE_ADDRESS: u16 = 0x08;    // 32-bit write (PFN)
    pub const QUEUE_SIZE: u16 = 0x0C;       // 16-bit read
    pub const QUEUE_SELECT: u16 = 0x0E;     // 16-bit write
    pub const QUEUE_NOTIFY: u16 = 0x10;     // 16-bit write
    pub const DEVICE_STATUS: u16 = 0x12;    // 8-bit r/w
    pub const ISR_STATUS: u16 = 0x13;       // 8-bit read
    // Block device config starts at offset 0x14.
    pub const BLK_CAPACITY_LO: u16 = 0x14;  // 32-bit
    pub const BLK_CAPACITY_HI: u16 = 0x18;  // 32-bit
}

impl BlkDev {
    #[cfg(not(target_arch = "x86_64"))]
    fn init(mmio_phys: usize, irq: u32) -> Option<Self> {
        // Map MMIO registers into our address space.
        let mmio_va = syscall::mmap_device(mmio_phys, 1)?;

        syscall::debug_puts(b"  [blk_srv] MMIO mapped at VA ");
        print_hex(mmio_va as u64);
        syscall::debug_puts(b"\n");

        // Verify magic and device ID.
        if mmio_read32(mmio_va, MMIO_MAGIC_VALUE) != VIRTIO_MAGIC {
            syscall::debug_puts(b"  [blk_srv] bad magic\n");
            return None;
        }
        if mmio_read32(mmio_va, MMIO_DEVICE_ID) != DEVICE_BLK {
            syscall::debug_puts(b"  [blk_srv] not a block device\n");
            return None;
        }

        let version = mmio_read32(mmio_va, MMIO_VERSION);

        // Reset device.
        mmio_write32(mmio_va, MMIO_STATUS, 0);

        // ACK + DRIVER.
        let mut status = STATUS_ACK;
        mmio_write32(mmio_va, MMIO_STATUS, status);
        status |= STATUS_DRIVER;
        mmio_write32(mmio_va, MMIO_STATUS, status);

        // Feature negotiation: accept no optional features.
        mmio_write32(mmio_va, MMIO_DEVICE_FEATURES_SEL, 0);
        let _features = mmio_read32(mmio_va, MMIO_DEVICE_FEATURES);
        mmio_write32(mmio_va, MMIO_DRIVER_FEATURES_SEL, 0);
        mmio_write32(mmio_va, MMIO_DRIVER_FEATURES, 0);

        if version >= 2 {
            status |= STATUS_FEATURES_OK;
            mmio_write32(mmio_va, MMIO_STATUS, status);
            if mmio_read32(mmio_va, MMIO_STATUS) & STATUS_FEATURES_OK == 0 {
                syscall::debug_puts(b"  [blk_srv] FEATURES_OK failed\n");
                return None;
            }
        }

        // Read capacity from config (offset 0x100).
        let cap_lo = mmio_read32(mmio_va, 0x100) as u64;
        let cap_hi = mmio_read32(mmio_va, 0x104) as u64;
        let capacity = cap_lo | (cap_hi << 32);

        // Select queue 0.
        mmio_write32(mmio_va, MMIO_QUEUE_SEL, 0);
        let max_size = mmio_read32(mmio_va, MMIO_QUEUE_NUM_MAX);
        if max_size == 0 {
            return None;
        }
        let qsize = (QUEUE_SIZE as u32).min(max_size);
        mmio_write32(mmio_va, MMIO_QUEUE_NUM, qsize);

        // Allocate virtqueue page.
        let vq_va = syscall::mmap_anon(0, 1, 1)?; // RW
        let vq_pa = syscall::virt_to_phys(vq_va)?;

        // Zero it.
        unsafe { core::ptr::write_bytes(vq_va as *mut u8, 0, 4096); }

        let desc_pa = vq_pa;
        let avail_pa = desc_pa + 16 * QUEUE_SIZE; // 16 bytes per descriptor

        // Allocate buffer page (header + status + 512-byte data).
        let buf_va = syscall::mmap_anon(0, 1, 1)?; // RW
        let buf_pa = syscall::virt_to_phys(buf_va)?;
        unsafe { core::ptr::write_bytes(buf_va as *mut u8, 0, 4096); }

        let req_hdr_pa = buf_pa;
        let status_pa = buf_pa + 16; // After 16-byte header
        let data_pa = buf_pa + 32;   // After header + status gap

        // Register IRQ for userspace dispatch (first irq_wait call with mmio_base).
        // We pass the *physical* MMIO base so the kernel can ACK the virtio interrupt.
        syscall::irq_wait(irq, mmio_phys);

        if version == 1 {
            // Legacy MMIO.
            let queue_align: usize = 4096;
            let avail_end = avail_pa + 6 + 2 * QUEUE_SIZE;
            let used_pa = (avail_end + queue_align - 1) & !(queue_align - 1);

            mmio_write32(mmio_va, MMIO_GUEST_PAGE_SIZE, 4096);
            mmio_write32(mmio_va, MMIO_QUEUE_PFN, (vq_pa / 4096) as u32);

            status |= STATUS_DRIVER_OK;
            mmio_write32(mmio_va, MMIO_STATUS, status);

            return Some(Self {
                mmio_va,
                irq,
                vq_va,
                buf_va,
                desc_pa,
                avail_pa,
                used_pa,
                req_hdr_pa,
                status_pa,
                data_pa,
                next_desc: 0,
                last_used_idx: 0,
                capacity,
                queue_size: QUEUE_SIZE,
            });
        }

        // Modern (v2): used ring at natural alignment.
        let used_pa = (avail_pa + 6 + 2 * QUEUE_SIZE + 3) & !3;

        mmio_write32(mmio_va, MMIO_QUEUE_DESC_LOW, desc_pa as u32);
        mmio_write32(mmio_va, MMIO_QUEUE_DESC_HIGH, (desc_pa >> 32) as u32);
        mmio_write32(mmio_va, MMIO_QUEUE_DRIVER_LOW, avail_pa as u32);
        mmio_write32(mmio_va, MMIO_QUEUE_DRIVER_HIGH, (avail_pa >> 32) as u32);
        mmio_write32(mmio_va, MMIO_QUEUE_DEVICE_LOW, used_pa as u32);
        mmio_write32(mmio_va, MMIO_QUEUE_DEVICE_HIGH, (used_pa >> 32) as u32);
        mmio_write32(mmio_va, MMIO_QUEUE_READY, 1);

        status |= STATUS_DRIVER_OK;
        mmio_write32(mmio_va, MMIO_STATUS, status);

        Some(Self {
            mmio_va,
            irq,
            vq_va,
            buf_va,
            desc_pa,
            avail_pa,
            used_pa,
            req_hdr_pa,
            status_pa,
            data_pa,
            next_desc: 0,
            last_used_idx: 0,
            capacity,
            queue_size: QUEUE_SIZE,
        })
    }

    /// PCI transport init for x86_64.
    #[cfg(target_arch = "x86_64")]
    fn init(bar0_port: usize, irq: u32) -> Option<Self> {
        let base = bar0_port as u16;

        syscall::debug_puts(b"  [blk_srv] PCI BAR0 port ");
        print_hex(base as u64);
        syscall::debug_puts(b"\n");

        // Reset.
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS, 0);

        // ACK + DRIVER.
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS, STATUS_ACK as u8);
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS,
            (STATUS_ACK | STATUS_DRIVER) as u8);

        // Feature negotiation.
        let _features = syscall::ioport_inl(base + pci_regs::DEVICE_FEATURES);
        syscall::ioport_outl(base + pci_regs::DRIVER_FEATURES, 0);

        // Read capacity from device config (BAR0 + 0x14).
        let cap_lo = syscall::ioport_inl(base + pci_regs::BLK_CAPACITY_LO) as u64;
        let cap_hi = syscall::ioport_inl(base + pci_regs::BLK_CAPACITY_HI) as u64;
        let capacity = cap_lo | (cap_hi << 32);

        // Select queue 0.
        syscall::ioport_outw(base + pci_regs::QUEUE_SELECT, 0);
        let max_size = syscall::ioport_inw(base + pci_regs::QUEUE_SIZE);
        if max_size == 0 {
            syscall::debug_puts(b"  [blk_srv] queue size 0\n");
            return None;
        }

        // Legacy PCI: queue size is fixed by the device (read-only register).
        // We MUST use the device's queue size for ring layout calculations.
        let qsz = max_size as usize;

        // Allocate virtqueue page (64K alloc page fits desc+avail+used with 4K alignment).
        let vq_va = syscall::mmap_anon(0, 1, 1)?;
        let vq_pa = syscall::virt_to_phys(vq_va)?;
        unsafe { core::ptr::write_bytes(vq_va as *mut u8, 0, 4096 * 16); }

        let desc_pa = vq_pa;
        let avail_pa = desc_pa + 16 * qsz;

        // Legacy PCI: used ring is page-aligned after avail.
        let avail_end = avail_pa + 6 + 2 * qsz;
        let used_pa = (avail_end + 4095) & !4095;

        // Write queue PFN (physical frame number = phys_addr / 4096).
        let pfn = (vq_pa / 4096) as u32;
        syscall::ioport_outl(base + pci_regs::QUEUE_ADDRESS, pfn);

        // Allocate buffer page.
        let buf_va = syscall::mmap_anon(0, 1, 1)?;
        let buf_pa = syscall::virt_to_phys(buf_va)?;
        unsafe { core::ptr::write_bytes(buf_va as *mut u8, 0, 4096); }

        let req_hdr_pa = buf_pa;
        let status_pa = buf_pa + 16;
        let data_pa = buf_pa + 32;

        // DRIVER_OK.
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS,
            (STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK) as u8);

        // Store BAR0 base as mmio_va for notify/ISR access.
        Some(Self {
            mmio_va: base as usize,
            irq,
            vq_va,
            buf_va,
            desc_pa,
            avail_pa,
            used_pa,
            req_hdr_pa,
            status_pa,
            data_pa,
            next_desc: 0,
            last_used_idx: 0,
            capacity,
            queue_size: qsz,
        })
    }

    fn read_sector(&mut self, sector: u64, out: &mut [u8; 512]) -> Result<(), ()> {
        if sector >= self.capacity {
            return Err(());
        }

        // Write request header (at buf_va offset 0) using volatile.
        let hdr = self.buf_va as *mut VirtioBlkReqHdr;
        unsafe {
            core::ptr::write_volatile(&raw mut (*hdr).req_type, VIRTIO_BLK_T_IN);
            core::ptr::write_volatile(&raw mut (*hdr).reserved, 0);
            core::ptr::write_volatile(&raw mut (*hdr).sector, sector);
        }

        // Status byte.
        let status_va = self.buf_va + 16;
        unsafe { core::ptr::write_volatile(status_va as *mut u8, 0xFF); }

        self.build_chain(VRING_DESC_F_WRITE);
        self.submit(0);
        self.wait_complete();

        let status = unsafe { core::ptr::read_volatile(status_va as *const u8) };
        if status != 0 {
            return Err(());
        }

        // Copy data from DMA buffer using volatile reads.
        let data_va = self.buf_va + 32;
        unsafe {
            let src = data_va as *const u8;
            for i in 0..512 {
                out[i] = core::ptr::read_volatile(src.add(i));
            }
        }

        self.next_desc = 0;
        Ok(())
    }

    fn write_sector(&mut self, sector: u64, data: &[u8; 512]) -> Result<(), ()> {
        if sector >= self.capacity {
            return Err(());
        }

        let hdr = self.buf_va as *mut VirtioBlkReqHdr;
        unsafe {
            core::ptr::write_volatile(&raw mut (*hdr).req_type, VIRTIO_BLK_T_OUT);
            core::ptr::write_volatile(&raw mut (*hdr).reserved, 0);
            core::ptr::write_volatile(&raw mut (*hdr).sector, sector);
        }

        let status_va = self.buf_va + 16;
        unsafe { core::ptr::write_volatile(status_va as *mut u8, 0xFF); }

        // Copy data into DMA buffer using volatile writes.
        let data_va = self.buf_va + 32;
        unsafe {
            let dst = data_va as *mut u8;
            for i in 0..512 {
                core::ptr::write_volatile(dst.add(i), data[i]);
            }
        }

        // For write: data descriptor is device-read (no WRITE flag).
        self.build_chain(0);
        self.submit(0);
        self.wait_complete();

        let status = unsafe { *(status_va as *const u8) };
        if status != 0 {
            return Err(());
        }

        self.next_desc = 0;
        Ok(())
    }

    /// Build a 3-descriptor chain: header → data → status.
    /// `data_flags` is VRING_DESC_F_WRITE for read ops, 0 for write ops.
    fn build_chain(&mut self, data_flags: u16) {
        let desc_va = self.vq_va; // descriptors at start of vq page
        let descs = desc_va as *mut VringDesc;

        unsafe {
            // Use volatile writes — these are DMA structures read by the device.
            core::ptr::write_volatile(descs.add(0), VringDesc {
                addr: self.req_hdr_pa as u64,
                len: 16,
                flags: VRING_DESC_F_NEXT,
                next: 1,
            });
            core::ptr::write_volatile(descs.add(1), VringDesc {
                addr: self.data_pa as u64,
                len: 512,
                flags: data_flags | VRING_DESC_F_NEXT,
                next: 2,
            });
            core::ptr::write_volatile(descs.add(2), VringDesc {
                addr: self.status_pa as u64,
                len: 1,
                flags: VRING_DESC_F_WRITE,
                next: 0,
            });
        }
    }

    fn submit(&mut self, head: u16) {
        let avail_offset = self.avail_pa - self.desc_pa;
        let avail_va = self.vq_va + avail_offset;
        let avail_idx_ptr = (avail_va + 2) as *mut u16;
        let avail_ring_ptr = (avail_va + 4) as *mut u16;

        unsafe {
            let idx = core::ptr::read_volatile(avail_idx_ptr);
            core::ptr::write_volatile(avail_ring_ptr.add((idx as usize) % self.queue_size), head);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(avail_idx_ptr, idx.wrapping_add(1));
        }
        // Full system barrier before notifying device — ensures all DMA buffer
        // writes are committed to memory (visible to the device), not just ordered.
        // DMB ISH (from fence(Release)) only orders between CPUs; DSB SY / fence iorw,iorw
        // ensures completion for device-observable memory.
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("dsb sy"); }
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("fence iorw, iorw"); }
        // Notify device.
        #[cfg(not(target_arch = "x86_64"))]
        mmio_write32(self.mmio_va, MMIO_QUEUE_NOTIFY, 0);
        #[cfg(target_arch = "x86_64")]
        syscall::ioport_outw(self.mmio_va as u16 + pci_regs::QUEUE_NOTIFY, 0);
    }

    fn wait_complete(&mut self) {
        let used_offset = self.used_pa - self.desc_pa;
        let used_va = self.vq_va + used_offset;
        let used_idx_ptr = (used_va + 2) as *const u16; // VringUsed.idx at offset 2

        // Poll the used ring, yielding between checks.
        loop {
            // DSB ensures device writes to the used ring are visible before we read.
            #[cfg(target_arch = "aarch64")]
            unsafe { core::arch::asm!("dsb sy"); }
            #[cfg(target_arch = "riscv64")]
            unsafe { core::arch::asm!("fence iorw, iorw"); }
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let idx = unsafe { core::ptr::read_volatile(used_idx_ptr) };
            if idx != self.last_used_idx {
                self.last_used_idx = idx;
                return;
            }
            syscall::yield_now();
        }
    }
}

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    // Unpack device info from arg0: base in low 48 bits, irq in bits 48-63.
    // On aarch64/riscv64: base = MMIO physical address.
    // On x86_64: base = BAR0 I/O port number.
    let base = (arg0 & 0xFFFF_FFFF_FFFF) as usize;
    let irq = (arg0 >> 48) as u32;

    syscall::debug_puts(b"  [blk_srv] starting, base=");
    print_hex(base as u64);
    syscall::debug_puts(b" irq=");
    print_num(irq as u64);
    syscall::debug_puts(b"\n");

    let mut dev = match BlkDev::init(base, irq) {
        Some(d) => d,
        None => {
            syscall::debug_puts(b"  [blk_srv] failed to init device\n");
            loop { core::hint::spin_loop(); }
        }
    };

    let capacity = dev.capacity;
    syscall::debug_puts(b"  [blk_srv] virtio-blk ready: ");
    print_num(capacity);
    syscall::debug_puts(b" sectors (");
    print_num(capacity / 2);
    syscall::debug_puts(b" KiB)\n");

    // Create IPC port and register with name server.
    let port = syscall::port_create() as u32;
    let my_aspace = syscall::aspace_id();

    syscall::ns_register(b"blk", port);

    syscall::debug_puts(b"  [blk_srv] server ready on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    // Server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            IO_CONNECT => {
                let reply_port = (msg.data[2] >> 32) as u32;
                syscall::send(reply_port, IO_CONNECT_OK,
                    0, capacity * 512, my_aspace as u64, 0);
            }

            IO_READ => {
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let grant_va = msg.data[3] as usize;

                let sector = (offset / 512) as u64;
                let mut buf = [0u8; 512];

                match dev.read_sector(sector, &mut buf) {
                    Ok(()) => {
                        let bytes_read = length.min(512);
                        if grant_va != 0 {
                            // Grant-based: copy data into granted pages.
                            let dst = grant_va as *mut u8;
                            unsafe {
                                core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, bytes_read);
                            }
                            syscall::send_nb(reply_port, IO_READ_OK, bytes_read as u64, 0);
                        } else {
                            // Inline read.
                            let inline_len = bytes_read.min(MAX_INLINE_READ);
                            let packed = pack_inline_data(&buf[..inline_len]);
                            syscall::send(reply_port, IO_READ_OK,
                                inline_len as u64, packed[0], packed[1], packed[2]);
                        }
                    }
                    Err(()) => {
                        syscall::send_nb(reply_port, IO_ERROR, ERR_IO, 0);
                    }
                }
            }

            IO_WRITE => {
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[2] >> 32) as u32;
                let grant_va = msg.data[3] as usize;

                let sector = (offset / 512) as u64;
                let mut buf = [0u8; 512];

                if grant_va != 0 {
                    let bytes_to_write = length.min(512);
                    let src = grant_va as *const u8;
                    unsafe {
                        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), bytes_to_write);
                    }
                }

                match dev.write_sector(sector, &buf) {
                    Ok(()) => {
                        syscall::send_nb(reply_port, IO_WRITE_OK, length.min(512) as u64, 0);
                    }
                    Err(()) => {
                        syscall::send_nb(reply_port, IO_ERROR, ERR_IO, 0);
                    }
                }
            }

            IO_STAT => {
                let reply_port = (msg.data[0] >> 32) as u32;
                syscall::send_nb(reply_port, IO_STAT_OK, capacity * 512, 0);
            }

            IO_CLOSE => {}
            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
