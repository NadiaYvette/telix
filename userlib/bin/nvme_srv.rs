#![no_std]
#![no_main]

//! Userspace NVMe block device driver and IPC server.
//!
//! Discovers the NVMe controller via MMIO cap (BAR0) granted by the kernel.
//! Initializes controller, creates admin + I/O queue pair, and serves
//! IO_READ/IO_WRITE/IO_STAT requests using the same block I/O protocol as
//! blk_srv (virtio-blk).
//!
//! Currently x86_64-only (PCI NVMe). The driver is polled (no IRQ) for
//! simplicity — QEMU NVMe completions are fast enough.

extern crate userlib;

use userlib::syscall;

// --- I/O protocol constants (same as blk_srv) ---
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
const IO_WRITE: u64 = 0x300;
const IO_WRITE_OK: u64 = 0x301;
const IO_STAT: u64 = 0x400;
const IO_STAT_OK: u64 = 0x401;
#[allow(dead_code)]
const IO_CLOSE: u64 = 0x500;
const IO_ERROR: u64 = 0xF00;
const ERR_IO: u64 = 1;

const MAX_INLINE_READ: usize = 40;

// --- NVMe controller register offsets (within BAR0) ---
const REG_CAP: usize = 0x00;    // Controller Capabilities (64-bit)
const REG_VS: usize = 0x08;     // Version (32-bit)
const REG_CC: usize = 0x14;     // Controller Configuration (32-bit)
const REG_CSTS: usize = 0x1C;   // Controller Status (32-bit)
const REG_AQA: usize = 0x24;    // Admin Queue Attributes (32-bit)
const REG_ASQ: usize = 0x28;    // Admin SQ Base Address (64-bit)
const REG_ACQ: usize = 0x30;    // Admin CQ Base Address (64-bit)

// CC bits
const CC_EN: u32 = 1 << 0;       // Enable
const CC_CSS_NVM: u32 = 0 << 4;  // NVM command set
const CC_MPS_4K: u32 = 0 << 7;   // Memory Page Size = 4096 (2^(12+0))
const CC_AMS_RR: u32 = 0 << 11;  // Round Robin arbitration
const CC_IOSQES: u32 = 6 << 16;  // I/O SQ Entry Size = 2^6 = 64 bytes
const CC_IOCQES: u32 = 4 << 20;  // I/O CQ Entry Size = 2^4 = 16 bytes

// CSTS bits
const CSTS_RDY: u32 = 1 << 0;    // Ready
const CSTS_CFS: u32 = 1 << 1;    // Controller Fatal Status

// NVMe admin opcodes
const ADMIN_IDENTIFY: u8 = 0x06;
const ADMIN_CREATE_IO_CQ: u8 = 0x05;
const ADMIN_CREATE_IO_SQ: u8 = 0x01;

// NVMe I/O opcodes
const IO_CMD_READ: u8 = 0x02;
const IO_CMD_WRITE: u8 = 0x01;

// Queue sizes (number of entries)
const ADMIN_QUEUE_SIZE: u16 = 16;
const IO_QUEUE_SIZE: u16 = 64;

// --- NVMe Submission Queue Entry (64 bytes) ---
#[repr(C)]
#[derive(Clone, Copy)]
struct SqEntry {
    opcode: u8,
    flags: u8,
    command_id: u16,
    nsid: u32,
    _rsvd1: u64,
    _rsvd2: u64,
    prp1: u64,
    prp2: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
}

impl SqEntry {
    const fn zeroed() -> Self {
        Self {
            opcode: 0,
            flags: 0,
            command_id: 0,
            nsid: 0,
            _rsvd1: 0,
            _rsvd2: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }
}

// --- NVMe Completion Queue Entry (16 bytes) ---
#[repr(C)]
#[derive(Clone, Copy)]
struct CqEntry {
    dw0: u32,       // Command-specific
    _rsvd: u32,
    sq_head: u16,    // SQ Head Pointer
    sq_id: u16,      // SQ Identifier
    command_id: u16, // Command Identifier
    status: u16,     // Status Field (bit 0 = phase tag, bits 1-15 = status)
}

// --- MMIO read/write helpers ---
fn mmio_read32(base: usize, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

fn mmio_write32(base: usize, offset: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

fn mmio_read64(base: usize, offset: usize) -> u64 {
    // NVMe spec says 64-bit registers may need two 32-bit reads on some platforms.
    let lo = mmio_read32(base, offset) as u64;
    let hi = mmio_read32(base, offset + 4) as u64;
    lo | (hi << 32)
}

fn mmio_write64(base: usize, offset: usize, val: u64) {
    mmio_write32(base, offset, val as u32);
    mmio_write32(base, offset + 4, (val >> 32) as u32);
}

// --- Utility ---
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

fn pack_inline_data(data: &[u8]) -> [u64; 5] {
    let mut words = [0u64; 5];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE_READ) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}

/// Non-blocking send with retry.
fn send_reply(port: u64, tag: u64, d0: u64, d1: u64, d2: u64, d3: u64) {
    if syscall::send_nb_4(port, tag, d0, d1, d2, d3) == 0 {
        return;
    }
    for _ in 0..50u32 {
        syscall::yield_now();
        if syscall::send_nb_4(port, tag, d0, d1, d2, d3) == 0 {
            return;
        }
    }
    syscall::send(port, tag, d0, d1, d2, d3);
}

// --- NVMe controller state ---
struct NvmeCtrl {
    bar: usize,          // BAR0 virtual address
    dstrd: u32,          // Doorbell Stride (in 32-bit units): from CAP.DSTRD
    // Admin queue
    asq_va: usize,       // Admin SQ virtual address
    acq_va: usize,       // Admin CQ virtual address
    admin_sq_tail: u16,
    admin_cq_head: u16,
    admin_phase: bool,    // Expected phase bit for admin CQ
    admin_cmd_id: u16,
    // I/O queue (QID=1)
    iosq_va: usize,
    iocq_va: usize,
    io_sq_tail: u16,
    io_cq_head: u16,
    io_phase: bool,
    io_cmd_id: u16,
    // Data buffer page (4K) for single-sector I/O
    data_va: usize,
    data_pa: u64,
    // Device info
    capacity_sectors: u64, // Namespace 1 size in 512-byte sectors
    sector_size: u32,      // Logical block size in bytes
}

impl NvmeCtrl {
    /// Compute doorbell offset for a given queue ID and type.
    /// SQ y tail doorbell = 0x1000 + (2y * (4 << DSTRD))
    /// CQ y head doorbell = 0x1000 + ((2y+1) * (4 << DSTRD))
    fn sq_doorbell(&self, qid: u16) -> usize {
        0x1000 + (2 * qid as usize) * (4 << self.dstrd) as usize
    }

    fn cq_doorbell(&self, qid: u16) -> usize {
        0x1000 + (2 * qid as usize + 1) * (4 << self.dstrd) as usize
    }

    /// Submit an admin command and poll for completion.
    fn admin_command(&mut self, mut cmd: SqEntry) -> Result<u32, u16> {
        cmd.command_id = self.admin_cmd_id;
        self.admin_cmd_id = self.admin_cmd_id.wrapping_add(1);

        // Write SQ entry
        let sq_offset = (self.admin_sq_tail as usize) * 64;
        unsafe {
            let dst = (self.asq_va + sq_offset) as *mut SqEntry;
            core::ptr::write_volatile(dst, cmd);
        }

        // Ring SQ doorbell
        self.admin_sq_tail = (self.admin_sq_tail + 1) % ADMIN_QUEUE_SIZE;
        mmio_write32(self.bar, self.sq_doorbell(0), self.admin_sq_tail as u32);

        // Poll CQ
        self.poll_cq_admin()
    }

    fn poll_cq_admin(&mut self) -> Result<u32, u16> {
        let timeout = 1_000_000u32; // iterations
        for _ in 0..timeout {
            let cq_offset = (self.admin_cq_head as usize) * 16;
            let cqe = unsafe {
                core::ptr::read_volatile((self.acq_va + cq_offset) as *const CqEntry)
            };
            let phase = (cqe.status & 1) != 0;
            if phase != self.admin_phase {
                core::hint::spin_loop();
                continue;
            }
            // Got a completion
            self.admin_cq_head = (self.admin_cq_head + 1) % ADMIN_QUEUE_SIZE;
            if self.admin_cq_head == 0 {
                self.admin_phase = !self.admin_phase;
            }
            // Ring CQ doorbell
            mmio_write32(self.bar, self.cq_doorbell(0), self.admin_cq_head as u32);

            let status_code = cqe.status >> 1;
            if status_code != 0 {
                return Err(status_code);
            }
            return Ok(cqe.dw0);
        }
        Err(0xFFFF) // timeout
    }

    /// Submit an I/O command and poll for completion.
    fn io_command(&mut self, mut cmd: SqEntry) -> Result<u32, u16> {
        cmd.command_id = self.io_cmd_id;
        self.io_cmd_id = self.io_cmd_id.wrapping_add(1);

        let sq_offset = (self.io_sq_tail as usize) * 64;
        unsafe {
            let dst = (self.iosq_va + sq_offset) as *mut SqEntry;
            core::ptr::write_volatile(dst, cmd);
        }

        self.io_sq_tail = (self.io_sq_tail + 1) % IO_QUEUE_SIZE;
        mmio_write32(self.bar, self.sq_doorbell(1), self.io_sq_tail as u32);

        self.poll_cq_io()
    }

    fn poll_cq_io(&mut self) -> Result<u32, u16> {
        let timeout = 5_000_000u32;
        for _ in 0..timeout {
            let cq_offset = (self.io_cq_head as usize) * 16;
            let cqe = unsafe {
                core::ptr::read_volatile((self.iocq_va + cq_offset) as *const CqEntry)
            };
            let phase = (cqe.status & 1) != 0;
            if phase != self.io_phase {
                core::hint::spin_loop();
                continue;
            }
            self.io_cq_head = (self.io_cq_head + 1) % IO_QUEUE_SIZE;
            if self.io_cq_head == 0 {
                self.io_phase = !self.io_phase;
            }
            mmio_write32(self.bar, self.cq_doorbell(1), self.io_cq_head as u32);

            let status_code = cqe.status >> 1;
            if status_code != 0 {
                return Err(status_code);
            }
            return Ok(cqe.dw0);
        }
        Err(0xFFFF)
    }

    /// Read a single sector (512 bytes) from namespace 1.
    fn read_sector(&mut self, lba: u64, buf: &mut [u8; 512]) -> Result<(), u16> {
        let mut cmd = SqEntry::zeroed();
        cmd.opcode = IO_CMD_READ;
        cmd.nsid = 1;
        cmd.prp1 = self.data_pa;
        cmd.cdw10 = lba as u32;          // Starting LBA (low 32)
        cmd.cdw11 = (lba >> 32) as u32;  // Starting LBA (high 32)
        cmd.cdw12 = 0;                    // Number of logical blocks - 1 (0 = 1 block)

        self.io_command(cmd)?;

        // Copy from DMA buffer to caller buffer
        unsafe {
            core::ptr::copy_nonoverlapping(self.data_va as *const u8, buf.as_mut_ptr(), 512);
        }
        Ok(())
    }

    /// Write a single sector (512 bytes) to namespace 1.
    fn write_sector(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), u16> {
        // Copy data into DMA buffer first
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), self.data_va as *mut u8, 512);
        }

        let mut cmd = SqEntry::zeroed();
        cmd.opcode = IO_CMD_WRITE;
        cmd.nsid = 1;
        cmd.prp1 = self.data_pa;
        cmd.cdw10 = lba as u32;
        cmd.cdw11 = (lba >> 32) as u32;
        cmd.cdw12 = 0; // 1 block

        self.io_command(cmd)?;
        Ok(())
    }
}

/// Initialize the NVMe controller and return a ready-to-use NvmeCtrl.
fn nvme_init(bar: usize) -> Option<NvmeCtrl> {
    // Read capabilities
    let cap = mmio_read64(bar, REG_CAP);
    let mqes = (cap & 0xFFFF) as u16;      // Maximum Queue Entries Supported (0-based)
    let dstrd = ((cap >> 32) & 0xF) as u32; // Doorbell Stride
    let _timeout = ((cap >> 24) & 0xFF) as u32; // Timeout in 500ms units
    let css = ((cap >> 37) & 0xFF) as u8;   // Command Sets Supported

    let vs = mmio_read32(bar, REG_VS);

    syscall::debug_puts(b"  [nvme_srv] CAP=");
    print_hex(cap);
    syscall::debug_puts(b" VS=");
    print_hex(vs as u64);
    syscall::debug_puts(b" MQES=");
    print_num((mqes + 1) as u64);
    syscall::debug_puts(b" DSTRD=");
    print_num(dstrd as u64);
    syscall::debug_puts(b"\n");

    if css & 1 == 0 {
        syscall::debug_puts(b"  [nvme_srv] NVM command set not supported\n");
        return None;
    }

    // Step 1: Disable controller (clear CC.EN)
    let mut cc = mmio_read32(bar, REG_CC);
    if cc & CC_EN != 0 {
        mmio_write32(bar, REG_CC, cc & !CC_EN);
        // Wait for CSTS.RDY to clear
        for _ in 0..1_000_000u32 {
            let csts = mmio_read32(bar, REG_CSTS);
            if csts & CSTS_RDY == 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }

    // Step 2: Allocate admin queues
    let ps = syscall::page_size();
    // Admin SQ: ADMIN_QUEUE_SIZE entries × 64 bytes = 1024 bytes (fits in 1 page)
    let asq_pages = 1;
    let asq_va = syscall::mmap_anon(0, asq_pages, 1)?;
    let asq_pa = syscall::virt_to_phys(asq_va)? as u64;
    unsafe { core::ptr::write_bytes(asq_va as *mut u8, 0, asq_pages * ps); }

    // Admin CQ: ADMIN_QUEUE_SIZE entries × 16 bytes = 256 bytes (fits in 1 page)
    let acq_pages = 1;
    let acq_va = syscall::mmap_anon(0, acq_pages, 1)?;
    let acq_pa = syscall::virt_to_phys(acq_va)? as u64;
    unsafe { core::ptr::write_bytes(acq_va as *mut u8, 0, acq_pages * ps); }

    // Step 3: Configure admin queue attributes
    // AQA: bits [27:16] = ACQS (0-based), bits [11:0] = ASQS (0-based)
    let aqa = ((ADMIN_QUEUE_SIZE - 1) as u32) << 16 | (ADMIN_QUEUE_SIZE - 1) as u32;
    mmio_write32(bar, REG_AQA, aqa);
    mmio_write64(bar, REG_ASQ, asq_pa);
    mmio_write64(bar, REG_ACQ, acq_pa);

    // Step 4: Configure CC and enable
    cc = CC_EN | CC_CSS_NVM | CC_MPS_4K | CC_AMS_RR | CC_IOSQES | CC_IOCQES;
    mmio_write32(bar, REG_CC, cc);

    // Step 5: Wait for CSTS.RDY
    let mut ready = false;
    for _ in 0..10_000_000u32 {
        let csts = mmio_read32(bar, REG_CSTS);
        if csts & CSTS_CFS != 0 {
            syscall::debug_puts(b"  [nvme_srv] controller fatal status!\n");
            return None;
        }
        if csts & CSTS_RDY != 0 {
            ready = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !ready {
        syscall::debug_puts(b"  [nvme_srv] timeout waiting for CSTS.RDY\n");
        return None;
    }

    syscall::debug_puts(b"  [nvme_srv] controller enabled and ready\n");

    // Allocate data/identify page (reused for admin identifies and I/O data)
    let data_va = syscall::mmap_anon(0, 1, 1)?;
    let data_pa = syscall::virt_to_phys(data_va)? as u64;
    unsafe { core::ptr::write_bytes(data_va as *mut u8, 0, ps); }

    let mut ctrl = NvmeCtrl {
        bar,
        dstrd,
        asq_va,
        acq_va,
        admin_sq_tail: 0,
        admin_cq_head: 0,
        admin_phase: true,
        admin_cmd_id: 0,
        iosq_va: 0,
        iocq_va: 0,
        io_sq_tail: 0,
        io_cq_head: 0,
        io_phase: true,
        io_cmd_id: 0,
        data_va,
        data_pa,
        capacity_sectors: 0,
        sector_size: 512,
    };

    // Step 6: Identify Controller (CNS=1)
    {
        let mut cmd = SqEntry::zeroed();
        cmd.opcode = ADMIN_IDENTIFY;
        cmd.prp1 = data_pa;
        cmd.cdw10 = 1; // CNS=1 (Identify Controller)

        match ctrl.admin_command(cmd) {
            Ok(_) => {
                // Parse controller identify data:
                // Bytes 0-19: PCI Vendor ID, etc.
                // Bytes 24-63: Serial Number (SN)
                // Bytes 64-103: Model Number (MN)
                let id = data_va as *const u8;
                syscall::debug_puts(b"  [nvme_srv] Identify Controller: SN=");
                for i in 4..24 {
                    let c = unsafe { *id.add(i) };
                    if c >= 0x20 && c <= 0x7E {
                        syscall::debug_putchar(c);
                    }
                }
                syscall::debug_puts(b" MN=");
                for i in 24..64 {
                    let c = unsafe { *id.add(i) };
                    if c >= 0x20 && c <= 0x7E {
                        syscall::debug_putchar(c);
                    }
                }
                syscall::debug_puts(b"\n");
            }
            Err(e) => {
                syscall::debug_puts(b"  [nvme_srv] Identify Controller failed: ");
                print_hex(e as u64);
                syscall::debug_puts(b"\n");
                return None;
            }
        }
    }

    // Step 7: Identify Namespace 1 (CNS=0, NSID=1)
    {
        unsafe { core::ptr::write_bytes(data_va as *mut u8, 0, ps); }

        let mut cmd = SqEntry::zeroed();
        cmd.opcode = ADMIN_IDENTIFY;
        cmd.nsid = 1;
        cmd.prp1 = data_pa;
        cmd.cdw10 = 0; // CNS=0 (Identify Namespace)

        match ctrl.admin_command(cmd) {
            Ok(_) => {
                // Namespace size in logical blocks (bytes 0-7)
                let nsze = unsafe { core::ptr::read_volatile(data_va as *const u64) };
                // Formatted LBA Size (byte 26): bits [3:0] = LBAF index
                let flbas = unsafe { *((data_va + 26) as *const u8) };
                let lbaf_idx = (flbas & 0xF) as usize;
                // LBAF table starts at byte 128, each entry is 4 bytes.
                // Bits [23:16] of each LBAF entry = LBADS (LBA Data Size as power of 2)
                let lbaf = unsafe {
                    core::ptr::read_volatile((data_va + 128 + lbaf_idx * 4) as *const u32)
                };
                let lbads = ((lbaf >> 16) & 0xFF) as u32;
                let block_size = if lbads >= 9 { 1u32 << lbads } else { 512 };

                // Convert to 512-byte sectors for our protocol
                let capacity_sectors = if block_size >= 512 {
                    nsze * (block_size as u64 / 512)
                } else {
                    nsze
                };

                ctrl.capacity_sectors = capacity_sectors;
                ctrl.sector_size = block_size;

                syscall::debug_puts(b"  [nvme_srv] NS1: ");
                print_num(nsze);
                syscall::debug_puts(b" blocks x ");
                print_num(block_size as u64);
                syscall::debug_puts(b"B = ");
                print_num(capacity_sectors / 2);
                syscall::debug_puts(b" KiB\n");
            }
            Err(e) => {
                syscall::debug_puts(b"  [nvme_srv] Identify Namespace failed: ");
                print_hex(e as u64);
                syscall::debug_puts(b"\n");
                return None;
            }
        }
    }

    // Step 8: Create I/O Completion Queue (QID=1)
    let io_qsize = IO_QUEUE_SIZE.min(mqes + 1);
    {
        let iocq_pages = 1; // 64 entries × 16 bytes = 1024 bytes
        let iocq_va = syscall::mmap_anon(0, iocq_pages, 1)?;
        let iocq_pa = syscall::virt_to_phys(iocq_va)? as u64;
        unsafe { core::ptr::write_bytes(iocq_va as *mut u8, 0, iocq_pages * ps); }
        ctrl.iocq_va = iocq_va;

        let mut cmd = SqEntry::zeroed();
        cmd.opcode = ADMIN_CREATE_IO_CQ;
        cmd.prp1 = iocq_pa;
        cmd.cdw10 = ((io_qsize - 1) as u32) << 16 | 1; // QID=1, size
        cmd.cdw11 = 1; // Physically Contiguous (PC=1)

        match ctrl.admin_command(cmd) {
            Ok(_) => {
                syscall::debug_puts(b"  [nvme_srv] I/O CQ created (QID=1, size=");
                print_num(io_qsize as u64);
                syscall::debug_puts(b")\n");
            }
            Err(e) => {
                syscall::debug_puts(b"  [nvme_srv] Create I/O CQ failed: ");
                print_hex(e as u64);
                syscall::debug_puts(b"\n");
                return None;
            }
        }
    }

    // Step 9: Create I/O Submission Queue (QID=1, associated CQ=1)
    {
        let iosq_pages = 1; // 64 entries × 64 bytes = 4096 bytes (exactly 1 page)
        let iosq_va = syscall::mmap_anon(0, iosq_pages, 1)?;
        let iosq_pa = syscall::virt_to_phys(iosq_va)? as u64;
        unsafe { core::ptr::write_bytes(iosq_va as *mut u8, 0, iosq_pages * ps); }
        ctrl.iosq_va = iosq_va;

        let mut cmd = SqEntry::zeroed();
        cmd.opcode = ADMIN_CREATE_IO_SQ;
        cmd.prp1 = iosq_pa;
        cmd.cdw10 = ((io_qsize - 1) as u32) << 16 | 1; // QID=1, size
        cmd.cdw11 = (1 << 16) | 1; // CQID=1, Physically Contiguous (PC=1)

        match ctrl.admin_command(cmd) {
            Ok(_) => {
                syscall::debug_puts(b"  [nvme_srv] I/O SQ created (QID=1, size=");
                print_num(io_qsize as u64);
                syscall::debug_puts(b")\n");
            }
            Err(e) => {
                syscall::debug_puts(b"  [nvme_srv] Create I/O SQ failed: ");
                print_hex(e as u64);
                syscall::debug_puts(b"\n");
                return None;
            }
        }
    }

    syscall::debug_puts(b"  [nvme_srv] initialization complete\n");
    Some(ctrl)
}

// --- Entry point ---

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [nvme_srv] starting\n");

    // Decode arg0: low 16 bits = MMIO cap slot, bits 48-63 = IRQ line.
    let cap_slot = (arg0 & 0xFFFF) as usize;
    let _irq = (arg0 >> 48) as u32;

    // Map BAR0 via the MMIO cap the kernel granted us.
    let bar = match syscall::mmio_map_cap(cap_slot) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [nvme_srv] mmio_map_cap failed, exiting\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    syscall::debug_puts(b"  [nvme_srv] BAR0 mapped at ");
    print_hex(bar as u64);
    syscall::debug_puts(b"\n");

    // Initialize the NVMe controller.
    let mut ctrl = match nvme_init(bar) {
        Some(c) => c,
        None => {
            syscall::debug_puts(b"  [nvme_srv] init failed, exiting\n");
            syscall::exit(1);
            loop { core::hint::spin_loop(); }
        }
    };

    let capacity = ctrl.capacity_sectors;
    let capacity_bytes = capacity * 512;

    // Register as "nvme" service (secondary block device alongside "blk").
    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"nvme", port);

    syscall::debug_puts(b"  [nvme_srv] server ready on port ");
    print_num(port as u64);
    syscall::debug_puts(b" (");
    print_num(capacity);
    syscall::debug_puts(b" sectors)\n");

    // IPC server loop — same protocol as blk_srv.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            IO_CONNECT => {
                let reply_port = msg.data[2] >> 32;
                syscall::send(reply_port, IO_CONNECT_OK, 0, capacity_bytes, my_aspace as u64, 0);
            }

            IO_READ => {
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                let lba = (offset / 512) as u64;
                let mut buf = [0u8; 512];

                match ctrl.read_sector(lba, &mut buf) {
                    Ok(()) => {
                        let bytes_read = length.min(512);
                        if grant_va != 0 {
                            let dst = grant_va as *mut u8;
                            unsafe {
                                core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, bytes_read);
                            }
                            send_reply(reply_port, IO_READ_OK, bytes_read as u64, 0, 0, 0);
                        } else {
                            let inline_len = bytes_read.min(MAX_INLINE_READ);
                            let packed = pack_inline_data(&buf[..inline_len]);
                            syscall::send(
                                reply_port,
                                IO_READ_OK,
                                inline_len as u64,
                                packed[0],
                                packed[1],
                                packed[2],
                            );
                        }
                    }
                    Err(_) => {
                        send_reply(reply_port, IO_ERROR, ERR_IO, 0, 0, 0);
                    }
                }
            }

            IO_WRITE => {
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                let lba = (offset / 512) as u64;
                let mut buf = [0u8; 512];

                if grant_va != 0 && length >= 512 {
                    unsafe {
                        core::ptr::copy_nonoverlapping(grant_va as *const u8, buf.as_mut_ptr(), 512);
                    }
                } else if length > 0 {
                    // Inline write: unpack from message data words.
                    let src = [msg.data[3], msg.data[4], 0u64, 0u64, 0u64];
                    for (i, b) in buf.iter_mut().enumerate().take(length.min(40)) {
                        *b = (src[i / 8] >> ((i % 8) * 8)) as u8;
                    }
                }

                match ctrl.write_sector(lba, &buf) {
                    Ok(()) => {
                        send_reply(reply_port, IO_WRITE_OK, length as u64, 0, 0, 0);
                    }
                    Err(_) => {
                        send_reply(reply_port, IO_ERROR, ERR_IO, 0, 0, 0);
                    }
                }
            }

            IO_STAT => {
                let reply_port = msg.data[2] >> 32;
                syscall::send(reply_port, IO_STAT_OK, capacity_bytes, 512, 0, 0);
            }

            _ => {
                // Unknown tag — send error.
                let reply_port = msg.data[2] >> 32;
                if reply_port != 0 {
                    send_reply(reply_port, IO_ERROR, ERR_IO, 0, 0, 0);
                }
            }
        }
    }
}
