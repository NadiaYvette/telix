//! Virtio block device driver.
//!
//! Minimal polling-based driver using virtio-mmio transport.
//! Single virtqueue, supports read and write block operations.

use super::virtio_mmio as mmio;
use crate::mm::phys;
use crate::mm::page::PhysAddr;

/// Virtqueue size (number of descriptors).
const QUEUE_SIZE: usize = 16;

/// Virtqueue descriptor flags.
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

/// Virtio block request types.
const VIRTIO_BLK_T_IN: u32 = 0;  // Read
const VIRTIO_BLK_T_OUT: u32 = 1; // Write

/// Virtqueue descriptor (16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct VringDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// Virtqueue available ring.
#[repr(C)]
struct VringAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE],
}

/// Virtqueue used ring element.
#[repr(C)]
#[derive(Clone, Copy)]
struct VringUsedElem {
    id: u32,
    len: u32,
}

/// Virtqueue used ring.
#[repr(C)]
struct VringUsed {
    flags: u16,
    idx: u16,
    ring: [VringUsedElem; QUEUE_SIZE],
}

/// Virtio block request header (16 bytes).
#[repr(C)]
struct VirtioBlkReqHdr {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

/// A virtio block device.
pub struct VirtioBlk {
    mmio_base: usize,
    /// Physical addresses of virtqueue structures.
    desc_pa: usize,
    avail_pa: usize,
    used_pa: usize,
    /// Next descriptor to allocate.
    next_desc: u16,
    /// Last seen used index.
    last_used_idx: u16,
    /// Device capacity in 512-byte sectors.
    pub capacity: u64,
    /// Request header buffer (physical address).
    req_hdr_pa: usize,
    /// Status byte buffer (physical address).
    status_pa: usize,
}

impl VirtioBlk {
    /// Initialize a virtio-blk device at the given MMIO base.
    pub fn init(base: usize) -> Option<Self> {
        // Verify magic.
        if mmio::read32(base, mmio::MAGIC_VALUE) != mmio::VIRTIO_MAGIC {
            return None;
        }
        if mmio::read32(base, mmio::DEVICE_ID) != mmio::DEVICE_BLK {
            return None;
        }

        let version = mmio::read32(base, mmio::VERSION);

        // Reset device.
        mmio::write32(base, mmio::STATUS, 0);

        // Acknowledge + driver.
        let mut status = mmio::STATUS_ACK;
        mmio::write32(base, mmio::STATUS, status);
        status |= mmio::STATUS_DRIVER;
        mmio::write32(base, mmio::STATUS, status);

        // Feature negotiation: accept no optional features.
        mmio::write32(base, mmio::DEVICE_FEATURES_SEL, 0);
        let _features = mmio::read32(base, mmio::DEVICE_FEATURES);
        mmio::write32(base, mmio::DRIVER_FEATURES_SEL, 0);
        mmio::write32(base, mmio::DRIVER_FEATURES, 0);

        if version >= 2 {
            status |= mmio::STATUS_FEATURES_OK;
            mmio::write32(base, mmio::STATUS, status);
            if mmio::read32(base, mmio::STATUS) & mmio::STATUS_FEATURES_OK == 0 {
                mmio::write32(base, mmio::STATUS, mmio::STATUS_FAILED);
                return None;
            }
        }

        // Read capacity from device config (offset 0x100).
        let cap_lo = mmio::read32(base, 0x100) as u64;
        let cap_hi = mmio::read32(base, 0x104) as u64;
        let capacity = cap_lo | (cap_hi << 32);

        // Set up virtqueue 0.
        mmio::write32(base, mmio::QUEUE_SEL, 0);
        let max_size = mmio::read32(base, mmio::QUEUE_NUM_MAX);
        if max_size == 0 {
            return None;
        }
        let qsize = (QUEUE_SIZE as u32).min(max_size);
        mmio::write32(base, mmio::QUEUE_NUM, qsize);

        // Allocate virtqueue memory — contiguous for all three rings.
        let vq_page = phys::alloc_page()?;
        let vq_base = vq_page.as_usize();
        unsafe { core::ptr::write_bytes(vq_base as *mut u8, 0, 4096); }

        let desc_pa = vq_base;
        let avail_pa = desc_pa + 16 * QUEUE_SIZE;

        if version == 1 {
            // Legacy MMIO: used ring at page-aligned offset from base.
            let queue_align: usize = 4096;
            let avail_end = avail_pa + 6 + 2 * QUEUE_SIZE;
            let used_pa = (avail_end + queue_align - 1) & !(queue_align - 1);

            // Set guest page size (legacy requirement).
            mmio::write32(base, mmio::GUEST_PAGE_SIZE, 4096);
            // Tell device the PFN of the virtqueue.
            mmio::write32(base, mmio::QUEUE_PFN, (vq_base / 4096) as u32);

            status |= mmio::STATUS_DRIVER_OK;
            mmio::write32(base, mmio::STATUS, status);

            // Allocate a page for request headers and status bytes.
            let buf_page = phys::alloc_page()?;
            let buf_base = buf_page.as_usize();
            unsafe { core::ptr::write_bytes(buf_base as *mut u8, 0, 4096); }

            return Some(Self {
                mmio_base: base,
                desc_pa,
                avail_pa,
                used_pa,
                next_desc: 0,
                last_used_idx: 0,
                capacity,
                req_hdr_pa: buf_base,
                status_pa: buf_base + 16,
            });
        }

        // Modern (v2): used ring just needs natural alignment.
        let used_pa = (avail_pa + 6 + 2 * QUEUE_SIZE + 3) & !3;

        mmio::write32(base, mmio::QUEUE_DESC_LOW, desc_pa as u32);
        mmio::write32(base, mmio::QUEUE_DESC_HIGH, (desc_pa >> 32) as u32);
        mmio::write32(base, mmio::QUEUE_DRIVER_LOW, avail_pa as u32);
        mmio::write32(base, mmio::QUEUE_DRIVER_HIGH, (avail_pa >> 32) as u32);
        mmio::write32(base, mmio::QUEUE_DEVICE_LOW, used_pa as u32);
        mmio::write32(base, mmio::QUEUE_DEVICE_HIGH, (used_pa >> 32) as u32);
        mmio::write32(base, mmio::QUEUE_READY, 1);

        status |= mmio::STATUS_DRIVER_OK;
        mmio::write32(base, mmio::STATUS, status);

        // Allocate a page for request headers and status bytes.
        let buf_page = phys::alloc_page()?;
        let buf_base = buf_page.as_usize();
        unsafe { core::ptr::write_bytes(buf_base as *mut u8, 0, 4096); }

        Some(Self {
            mmio_base: base,
            desc_pa,
            avail_pa,
            used_pa,
            next_desc: 0,
            last_used_idx: 0,
            capacity,
            req_hdr_pa: buf_base,
            status_pa: buf_base + 16, // After the 16-byte header
        })
    }

    /// Read a 512-byte sector into `buf`.
    pub fn read_sector(&mut self, sector: u64, buf: &mut [u8; 512]) -> Result<(), ()> {
        if sector >= self.capacity {
            return Err(());
        }

        // Write request header.
        let hdr = self.req_hdr_pa as *mut VirtioBlkReqHdr;
        unsafe {
            (*hdr).req_type = VIRTIO_BLK_T_IN;
            (*hdr).reserved = 0;
            (*hdr).sector = sector;
        }

        // Write status byte to 0xFF (will be overwritten by device).
        let status_ptr = self.status_pa as *mut u8;
        unsafe { *status_ptr = 0xFF; }

        // Build 3-descriptor chain: header → data buffer → status.
        // We need the data buffer at a known physical address.
        // Use offset 32 in our buffer page for the 512-byte data.
        let data_pa = self.req_hdr_pa + 32;

        let descs = self.desc_pa as *mut VringDesc;
        let d0 = self.alloc_desc();
        let d1 = self.alloc_desc();
        let d2 = self.alloc_desc();

        unsafe {
            // Descriptor 0: request header (device reads).
            *descs.add(d0 as usize) = VringDesc {
                addr: self.req_hdr_pa as u64,
                len: 16,
                flags: VRING_DESC_F_NEXT,
                next: d1,
            };
            // Descriptor 1: data buffer (device writes).
            *descs.add(d1 as usize) = VringDesc {
                addr: data_pa as u64,
                len: 512,
                flags: VRING_DESC_F_WRITE | VRING_DESC_F_NEXT,
                next: d2,
            };
            // Descriptor 2: status byte (device writes).
            *descs.add(d2 as usize) = VringDesc {
                addr: self.status_pa as u64,
                len: 1,
                flags: VRING_DESC_F_WRITE,
                next: 0,
            };
        }

        // Add to available ring.
        self.submit(d0);

        // Poll for completion.
        self.wait_complete();

        // Check status.
        let status = unsafe { *status_ptr };
        if status != 0 {
            return Err(());
        }

        // Copy data out.
        unsafe {
            core::ptr::copy_nonoverlapping(data_pa as *const u8, buf.as_mut_ptr(), 512);
        }

        // Free descriptors.
        self.next_desc = 0; // Simple reset since we use descriptors sequentially.

        Ok(())
    }

    /// Write a 512-byte sector from `buf`.
    pub fn write_sector(&mut self, sector: u64, buf: &[u8; 512]) -> Result<(), ()> {
        if sector >= self.capacity {
            return Err(());
        }

        let hdr = self.req_hdr_pa as *mut VirtioBlkReqHdr;
        unsafe {
            (*hdr).req_type = VIRTIO_BLK_T_OUT;
            (*hdr).reserved = 0;
            (*hdr).sector = sector;
        }

        let status_ptr = self.status_pa as *mut u8;
        unsafe { *status_ptr = 0xFF; }

        let data_pa = self.req_hdr_pa + 32;
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), data_pa as *mut u8, 512);
        }

        let descs = self.desc_pa as *mut VringDesc;
        let d0 = self.alloc_desc();
        let d1 = self.alloc_desc();
        let d2 = self.alloc_desc();

        unsafe {
            *descs.add(d0 as usize) = VringDesc {
                addr: self.req_hdr_pa as u64,
                len: 16,
                flags: VRING_DESC_F_NEXT,
                next: d1,
            };
            *descs.add(d1 as usize) = VringDesc {
                addr: data_pa as u64,
                len: 512,
                flags: VRING_DESC_F_NEXT, // Device reads (no WRITE flag).
                next: d2,
            };
            *descs.add(d2 as usize) = VringDesc {
                addr: self.status_pa as u64,
                len: 1,
                flags: VRING_DESC_F_WRITE,
                next: 0,
            };
        }

        self.submit(d0);
        self.wait_complete();

        let status = unsafe { *status_ptr };
        if status != 0 {
            return Err(());
        }

        self.next_desc = 0;
        Ok(())
    }

    fn alloc_desc(&mut self) -> u16 {
        let d = self.next_desc;
        self.next_desc += 1;
        d
    }

    fn submit(&mut self, head: u16) {
        let avail = self.avail_pa as *mut VringAvail;
        unsafe {
            let idx = (*avail).idx;
            (*avail).ring[(idx as usize) % QUEUE_SIZE] = head;
            // Memory barrier before updating index.
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            (*avail).idx = idx.wrapping_add(1);
        }
        // Notify device.
        mmio::write32(self.mmio_base, mmio::QUEUE_NOTIFY, 0);
    }

    fn wait_complete(&mut self) {
        let used = self.used_pa as *mut VringUsed;
        loop {
            let idx = unsafe {
                core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
                (*used).idx
            };
            if idx != self.last_used_idx {
                self.last_used_idx = idx;
                // ACK interrupt.
                mmio::write32(self.mmio_base, mmio::INTERRUPT_ACK,
                    mmio::read32(self.mmio_base, mmio::INTERRUPT_STATUS));
                return;
            }
            core::hint::spin_loop();
        }
    }
}
