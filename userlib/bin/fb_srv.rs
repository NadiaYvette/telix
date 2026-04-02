#![no_std]
#![no_main]

//! Userspace framebuffer server: virtio-gpu 2D (primary) + VBE fallback.
//!
//! Receives device info (bar0, irq) via arg0 from the kernel when a
//! virtio-gpu PCI device is found. Falls back to VBE linear framebuffer
//! if arg0 == 0 (no GPU device discovered).

extern crate userlib;

use userlib::syscall;

// --- FB IPC protocol ---
const FB_GET_INFO: u64 = 0x8000;
const FB_GET_INFO_OK: u64 = 0x8001;
const FB_MAP: u64 = 0x8002;
const FB_MAP_OK: u64 = 0x8003;
const FB_FLIP: u64 = 0x8004;
const FB_FLIP_OK: u64 = 0x8005;

// --- PCI legacy virtio register offsets (BAR0 I/O port) ---
mod pci_regs {
    pub const DEVICE_FEATURES: u16 = 0x00;
    pub const DRIVER_FEATURES: u16 = 0x04;
    pub const QUEUE_ADDRESS: u16 = 0x08;
    pub const QUEUE_SIZE: u16 = 0x0C;
    pub const QUEUE_SELECT: u16 = 0x0E;
    pub const QUEUE_NOTIFY: u16 = 0x10;
    pub const DEVICE_STATUS: u16 = 0x12;
    pub const ISR_STATUS: u16 = 0x13;
    // GPU device config at 0x14:
    pub const GPU_EVENTS_READ: u16 = 0x14;
    #[allow(dead_code)]
    pub const GPU_EVENTS_CLEAR: u16 = 0x18;
    #[allow(dead_code)]
    pub const GPU_NUM_SCANOUTS: u16 = 0x1C;
}

const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;

// --- Virtio-GPU command types ---
const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x100;
const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x101;
const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x103;
const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x104;
const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x105;
const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x106;

// Response types.
const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;

// Resource format: XRGB8888 (B8G8R8X8_UNORM = 2).
const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;

// --- Virtqueue structures ---
const QUEUE_SIZE: usize = 16;
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct VringDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

// --- Virtio-GPU control header ---
#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioGpuCtrlHdr {
    cmd_type: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    padding: u32,
}

// --- Command structures ---
#[repr(C)]
struct GpuRect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
struct ResourceCreate2d {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
struct SetScanout {
    hdr: VirtioGpuCtrlHdr,
    r: GpuRect,
    scanout_id: u32,
    resource_id: u32,
}

#[repr(C)]
struct ResourceFlush {
    hdr: VirtioGpuCtrlHdr,
    r: GpuRect,
    resource_id: u32,
    padding: u32,
}

#[repr(C)]
struct TransferToHost2d {
    hdr: VirtioGpuCtrlHdr,
    r: GpuRect,
    offset: u64,
    resource_id: u32,
    padding: u32,
}

#[repr(C)]
struct MemEntry {
    addr: u64,
    length: u32,
    padding: u32,
}

#[repr(C)]
struct ResourceAttachBacking {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    nr_entries: u32,
    // Followed by MemEntry array.
}

// --- GPU device state ---
struct GpuDev {
    bar0: u16,
    #[allow(dead_code)]
    irq: u32,
    // Virtqueue state.
    vq_va: usize,
    desc_pa: usize,
    avail_pa: usize,
    used_pa: usize,
    queue_size: usize,
    last_used_idx: u16,
    // Command buffer (physical + virtual).
    cmd_va: usize,
    cmd_pa: usize,
    resp_va: usize,
    resp_pa: usize,
    // Display info.
    width: u32,
    height: u32,
    // Backing memory.
    backing_va: usize,
    backing_pa: usize,
    backing_pages: usize,
}

// Framebuffer state (either GPU or VBE).
struct FbState {
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u8,
    fb_va: usize,
    fb_pages: usize,
    gpu: Option<GpuDev>,
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

impl GpuDev {
    fn init(bar0_port: u16, irq: u32) -> Option<Self> {
        let base = bar0_port;

        // Reset.
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS, 0);

        // ACK + DRIVER.
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS, STATUS_ACK);
        syscall::ioport_outb(base + pci_regs::DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);

        // Feature negotiation — accept no features for now.
        let _features = syscall::ioport_inl(base + pci_regs::DEVICE_FEATURES);
        syscall::ioport_outl(base + pci_regs::DRIVER_FEATURES, 0);

        // Select queue 0 (controlq).
        syscall::ioport_outw(base + pci_regs::QUEUE_SELECT, 0);
        let max_size = syscall::ioport_inw(base + pci_regs::QUEUE_SIZE);
        if max_size == 0 {
            syscall::debug_puts(b"  [fb_srv] queue size 0\n");
            return None;
        }
        let qsz = max_size as usize;

        // Allocate virtqueue memory.
        let ps = syscall::page_size();
        let vq_bytes = 16 * qsz + (6 + 2 * qsz) + 4096 + (8 * qsz + 6);
        let vq_pages = (vq_bytes + ps - 1) / ps;
        let vq_va = syscall::mmap_anon(0, vq_pages, 1)?;
        let vq_pa = syscall::virt_to_phys(vq_va)?;
        unsafe {
            core::ptr::write_bytes(vq_va as *mut u8, 0, vq_pages * ps);
        }

        let desc_pa = vq_pa;
        let avail_pa = desc_pa + 16 * qsz;
        let avail_end = avail_pa + 6 + 2 * qsz;
        let used_pa = (avail_end + 4095) & !4095;

        // Write queue PFN.
        let pfn = (vq_pa / 4096) as u32;
        syscall::ioport_outl(base + pci_regs::QUEUE_ADDRESS, pfn);

        // Allocate command/response buffers (2 pages).
        let cmd_va = syscall::mmap_anon(0, 2, 1)?;
        let cmd_pa = syscall::virt_to_phys(cmd_va)?;
        unsafe {
            core::ptr::write_bytes(cmd_va as *mut u8, 0, 2 * ps);
        }
        let resp_va = cmd_va + ps;
        let resp_pa = cmd_pa + ps;

        // DRIVER_OK.
        syscall::ioport_outb(
            base + pci_regs::DEVICE_STATUS,
            STATUS_ACK | STATUS_DRIVER | STATUS_DRIVER_OK,
        );

        Some(Self {
            bar0: base,
            irq,
            vq_va,
            desc_pa,
            avail_pa,
            used_pa,
            queue_size: qsz,
            last_used_idx: 0,
            cmd_va,
            cmd_pa,
            resp_va,
            resp_pa,
            width: 0,
            height: 0,
            backing_va: 0,
            backing_pa: 0,
            backing_pages: 0,
        })
    }

    /// Submit a 2-descriptor chain: cmd (device-read) + resp (device-write).
    fn submit_cmd(&mut self, cmd_len: usize, resp_len: usize) {
        let desc_va = self.vq_va;
        let descs = desc_va as *mut VringDesc;

        unsafe {
            // Descriptor 0: command buffer (device reads).
            core::ptr::write_volatile(
                descs.add(0),
                VringDesc {
                    addr: self.cmd_pa as u64,
                    len: cmd_len as u32,
                    flags: VRING_DESC_F_NEXT,
                    next: 1,
                },
            );
            // Descriptor 1: response buffer (device writes).
            core::ptr::write_volatile(
                descs.add(1),
                VringDesc {
                    addr: self.resp_pa as u64,
                    len: resp_len as u32,
                    flags: VRING_DESC_F_WRITE,
                    next: 0,
                },
            );
        }

        // Add to available ring.
        let avail_offset = self.avail_pa - self.desc_pa;
        let avail_va = self.vq_va + avail_offset;
        let avail_idx_ptr = (avail_va + 2) as *mut u16;
        let avail_ring_ptr = (avail_va + 4) as *mut u16;

        unsafe {
            let idx = core::ptr::read_volatile(avail_idx_ptr);
            core::ptr::write_volatile(
                avail_ring_ptr.add((idx as usize) % self.queue_size),
                0,
            );
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(avail_idx_ptr, idx.wrapping_add(1));
        }

        // Notify device.
        syscall::ioport_outw(self.bar0 + pci_regs::QUEUE_NOTIFY, 0);

        // Wait for completion.
        self.wait_complete();
    }

    fn wait_complete(&mut self) {
        let used_offset = self.used_pa - self.desc_pa;
        let used_va = self.vq_va + used_offset;
        let used_idx_ptr = (used_va + 2) as *const u16;

        loop {
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let idx = unsafe { core::ptr::read_volatile(used_idx_ptr) };
            if idx != self.last_used_idx {
                self.last_used_idx = idx;
                return;
            }
            syscall::yield_now();
        }
    }

    fn make_hdr(cmd_type: u32) -> VirtioGpuCtrlHdr {
        VirtioGpuCtrlHdr {
            cmd_type,
            flags: 0,
            fence_id: 0,
            ctx_id: 0,
            padding: 0,
        }
    }

    fn resp_type(&self) -> u32 {
        unsafe { core::ptr::read_volatile(self.resp_va as *const u32) }
    }

    /// GET_DISPLAY_INFO → discover display resolution.
    fn get_display_info(&mut self) -> Option<(u32, u32)> {
        // Write command header.
        let cmd = self.cmd_va as *mut VirtioGpuCtrlHdr;
        unsafe {
            core::ptr::write_volatile(cmd, Self::make_hdr(VIRTIO_GPU_CMD_GET_DISPLAY_INFO));
        }
        // Clear response.
        unsafe {
            core::ptr::write_bytes(self.resp_va as *mut u8, 0, 4096);
        }

        // Response: hdr (24 bytes) + display[0]: rect (16 bytes) + enabled (u32) + flags (u32).
        // Total response size: 24 + 24*VIRTIO_GPU_MAX_SCANOUTS(16) = 408 bytes.
        self.submit_cmd(24, 408);

        let resp = self.resp_type();
        if resp != VIRTIO_GPU_RESP_OK_DISPLAY_INFO {
            syscall::debug_puts(b"  [fb_srv] GET_DISPLAY_INFO failed: ");
            print_hex(resp as u64);
            syscall::debug_puts(b"\n");
            return None;
        }

        // Read display[0]: offset 24 in response.
        // struct virtio_gpu_display_one { rect: {x,y,w,h}, enabled: u32, flags: u32 }
        let resp_ptr = self.resp_va as *const u8;
        let w = unsafe { core::ptr::read_volatile(resp_ptr.add(24 + 8) as *const u32) };
        let h = unsafe { core::ptr::read_volatile(resp_ptr.add(24 + 12) as *const u32) };
        let enabled = unsafe { core::ptr::read_volatile(resp_ptr.add(24 + 16) as *const u32) };

        if enabled == 0 || w == 0 || h == 0 {
            // Display not enabled; use default.
            return Some((1024, 768));
        }

        Some((w, h))
    }

    /// RESOURCE_CREATE_2D.
    fn resource_create_2d(&mut self, resource_id: u32, width: u32, height: u32) -> bool {
        let cmd = self.cmd_va as *mut ResourceCreate2d;
        unsafe {
            core::ptr::write_volatile(
                cmd,
                ResourceCreate2d {
                    hdr: Self::make_hdr(VIRTIO_GPU_CMD_RESOURCE_CREATE_2D),
                    resource_id,
                    format: VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
                    width,
                    height,
                },
            );
        }
        unsafe {
            core::ptr::write_bytes(self.resp_va as *mut u8, 0, 24);
        }

        self.submit_cmd(
            core::mem::size_of::<ResourceCreate2d>(),
            24,
        );
        self.resp_type() == VIRTIO_GPU_RESP_OK_NODATA
    }

    /// RESOURCE_ATTACH_BACKING — attach guest RAM pages to a resource.
    fn resource_attach_backing(
        &mut self,
        resource_id: u32,
        backing_pa: usize,
        backing_bytes: usize,
    ) -> bool {
        // Layout in cmd buffer: ResourceAttachBacking header + 1 MemEntry.
        let hdr_size = core::mem::size_of::<ResourceAttachBacking>();
        let entry_size = core::mem::size_of::<MemEntry>();
        let total = hdr_size + entry_size;

        let cmd = self.cmd_va as *mut u8;
        unsafe {
            let h = cmd as *mut ResourceAttachBacking;
            core::ptr::write_volatile(
                h,
                ResourceAttachBacking {
                    hdr: Self::make_hdr(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING),
                    resource_id,
                    nr_entries: 1,
                },
            );
            let entry = cmd.add(hdr_size) as *mut MemEntry;
            core::ptr::write_volatile(
                entry,
                MemEntry {
                    addr: backing_pa as u64,
                    length: backing_bytes as u32,
                    padding: 0,
                },
            );
        }
        unsafe {
            core::ptr::write_bytes(self.resp_va as *mut u8, 0, 24);
        }

        self.submit_cmd(total, 24);
        self.resp_type() == VIRTIO_GPU_RESP_OK_NODATA
    }

    /// SET_SCANOUT — wire a resource to a display output.
    fn set_scanout(&mut self, scanout_id: u32, resource_id: u32, w: u32, h: u32) -> bool {
        let cmd = self.cmd_va as *mut SetScanout;
        unsafe {
            core::ptr::write_volatile(
                cmd,
                SetScanout {
                    hdr: Self::make_hdr(VIRTIO_GPU_CMD_SET_SCANOUT),
                    r: GpuRect {
                        x: 0,
                        y: 0,
                        width: w,
                        height: h,
                    },
                    scanout_id,
                    resource_id,
                },
            );
        }
        unsafe {
            core::ptr::write_bytes(self.resp_va as *mut u8, 0, 24);
        }

        self.submit_cmd(core::mem::size_of::<SetScanout>(), 24);
        self.resp_type() == VIRTIO_GPU_RESP_OK_NODATA
    }

    /// TRANSFER_TO_HOST_2D — copy dirty region from guest RAM to resource.
    fn transfer_to_host_2d(&mut self, resource_id: u32, x: u32, y: u32, w: u32, h: u32) -> bool {
        let cmd = self.cmd_va as *mut TransferToHost2d;
        unsafe {
            core::ptr::write_volatile(
                cmd,
                TransferToHost2d {
                    hdr: Self::make_hdr(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D),
                    r: GpuRect {
                        x,
                        y,
                        width: w,
                        height: h,
                    },
                    offset: 0,
                    resource_id,
                    padding: 0,
                },
            );
        }
        unsafe {
            core::ptr::write_bytes(self.resp_va as *mut u8, 0, 24);
        }

        self.submit_cmd(core::mem::size_of::<TransferToHost2d>(), 24);
        self.resp_type() == VIRTIO_GPU_RESP_OK_NODATA
    }

    /// RESOURCE_FLUSH — tell host to update display from resource.
    fn resource_flush(&mut self, resource_id: u32, x: u32, y: u32, w: u32, h: u32) -> bool {
        let cmd = self.cmd_va as *mut ResourceFlush;
        unsafe {
            core::ptr::write_volatile(
                cmd,
                ResourceFlush {
                    hdr: Self::make_hdr(VIRTIO_GPU_CMD_RESOURCE_FLUSH),
                    r: GpuRect {
                        x,
                        y,
                        width: w,
                        height: h,
                    },
                    resource_id,
                    padding: 0,
                },
            );
        }
        unsafe {
            core::ptr::write_bytes(self.resp_va as *mut u8, 0, 24);
        }

        self.submit_cmd(core::mem::size_of::<ResourceFlush>(), 24);
        self.resp_type() == VIRTIO_GPU_RESP_OK_NODATA
    }

    /// Full display init: discover resolution, create resource, attach backing, set scanout.
    fn init_display(&mut self) -> Option<(usize, usize)> {
        // 1. Get display info.
        let (w, h) = self.get_display_info()?;
        self.width = w;
        self.height = h;

        syscall::debug_puts(b"  [fb_srv] display: ");
        print_num(w as u64);
        syscall::debug_puts(b"x");
        print_num(h as u64);
        syscall::debug_puts(b"\n");

        // 2. Create resource (ID=1, XRGB8888).
        if !self.resource_create_2d(1, w, h) {
            syscall::debug_puts(b"  [fb_srv] RESOURCE_CREATE_2D failed\n");
            return None;
        }

        // 3. Allocate backing pages.
        let ps = syscall::page_size();
        let fb_bytes = (w as usize) * (h as usize) * 4;
        let fb_pages = (fb_bytes + ps - 1) / ps;
        let fb_va = syscall::mmap_anon(0, fb_pages, 1)?;
        let fb_pa = syscall::virt_to_phys(fb_va)?;
        unsafe {
            core::ptr::write_bytes(fb_va as *mut u8, 0, fb_pages * ps);
        }
        self.backing_va = fb_va;
        self.backing_pa = fb_pa;
        self.backing_pages = fb_pages;

        // 4. Attach backing.
        if !self.resource_attach_backing(1, fb_pa, fb_bytes) {
            syscall::debug_puts(b"  [fb_srv] RESOURCE_ATTACH_BACKING failed\n");
            return None;
        }

        // 5. Set scanout.
        if !self.set_scanout(0, 1, w, h) {
            syscall::debug_puts(b"  [fb_srv] SET_SCANOUT failed\n");
            return None;
        }

        Some((fb_va, fb_pages))
    }

    /// Flush a region to the display.
    fn flush(&mut self, x: u32, y: u32, w: u32, h: u32) {
        self.transfer_to_host_2d(1, x, y, w, h);
        self.resource_flush(1, x, y, w, h);
    }
}

/// Draw a test gradient pattern into the framebuffer.
fn draw_gradient(fb_va: usize, width: u32, height: u32, pitch: u32) {
    let fb = fb_va as *mut u32;
    let stride = pitch as usize / 4; // pixels per row

    for y in 0..height as usize {
        for x in 0..width as usize {
            // RGB gradient: R varies with X, G varies with Y, B = 128.
            let r = ((x * 255) / width as usize) as u32;
            let g = ((y * 255) / height as usize) as u32;
            let b = 128u32;
            let pixel = (r << 16) | (g << 8) | b;
            unsafe {
                core::ptr::write_volatile(fb.add(y * stride + x), pixel);
            }
        }
    }
}

/// Try VBE fallback: query framebuffer info from kernel, map it.
fn try_vbe() -> Option<FbState> {
    let (addr, width, height, pitch, bpp) = syscall::framebuffer_info()?;

    if addr == 0 || width == 0 || height == 0 {
        return None;
    }

    syscall::debug_puts(b"  [fb_srv] VBE framebuffer: ");
    print_num(width as u64);
    syscall::debug_puts(b"x");
    print_num(height as u64);
    syscall::debug_puts(b"x");
    print_num(bpp as u64);
    syscall::debug_puts(b" at ");
    print_hex(addr);
    syscall::debug_puts(b"\n");

    let fb_bytes = pitch as usize * height as usize;
    // mmap_device maps 4KB hardware pages, not system pages.
    let fb_pages_4k = (fb_bytes + 4095) / 4096;

    // Map the framebuffer physical memory into userspace.
    let fb_va = syscall::mmap_device(addr as usize, fb_pages_4k)?;
    let fb_pages = (fb_bytes + syscall::page_size() - 1) / syscall::page_size();

    Some(FbState {
        width,
        height,
        pitch,
        bpp,
        fb_va,
        fb_pages,
        gpu: None,
    })
}

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let bar0 = (arg0 & 0xFFFF_FFFF_FFFF) as u16;
    let irq = (arg0 >> 48) as u32;

    syscall::debug_puts(b"  [fb_srv] starting");
    if bar0 != 0 {
        syscall::debug_puts(b", GPU bar0=");
        print_hex(bar0 as u64);
        syscall::debug_puts(b" irq=");
        print_num(irq as u64);
    }
    syscall::debug_puts(b"\n");

    // Try virtio-gpu first, then VBE fallback.
    let mut fb = if bar0 != 0 {
        match GpuDev::init(bar0, irq) {
            Some(mut gpu) => {
                match gpu.init_display() {
                    Some((fb_va, fb_pages)) => {
                        let w = gpu.width;
                        let h = gpu.height;
                        let pitch = w * 4;
                        Some(FbState {
                            width: w,
                            height: h,
                            pitch,
                            bpp: 32,
                            fb_va,
                            fb_pages,
                            gpu: Some(gpu),
                        })
                    }
                    None => {
                        syscall::debug_puts(b"  [fb_srv] GPU display init failed, trying VBE\n");
                        try_vbe()
                    }
                }
            }
            None => {
                syscall::debug_puts(b"  [fb_srv] GPU init failed, trying VBE\n");
                try_vbe()
            }
        }
    } else {
        try_vbe()
    };

    let fb = match fb.as_mut() {
        Some(f) => f,
        None => {
            syscall::debug_puts(b"  [fb_srv] no display available, exiting\n");
            return;
        }
    };

    // Draw test gradient.
    draw_gradient(fb.fb_va, fb.width, fb.height, fb.pitch);

    // Flush if GPU backend.
    if let Some(ref mut gpu) = fb.gpu {
        gpu.flush(0, 0, fb.width, fb.height);
    }

    syscall::debug_puts(b"  [fb_srv] test pattern drawn ");
    print_num(fb.width as u64);
    syscall::debug_puts(b"x");
    print_num(fb.height as u64);
    syscall::debug_puts(b"\n");

    // Register with name server.
    let port = syscall::port_create();
    syscall::ns_register(b"fb", port);

    syscall::debug_puts(b"  [fb_srv] server ready on port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    let my_aspace = syscall::aspace_id();

    // IPC server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            FB_GET_INFO => {
                let reply_port = msg.data[2] >> 32;
                // Pack: data[0] = width | (height << 32).
                // data[1] = pitch | (bpp << 32).
                // data[2] = format (0 = XRGB8888).
                let wh = (fb.width as u64) | ((fb.height as u64) << 32);
                let pb = (fb.pitch as u64) | ((fb.bpp as u64) << 32);
                syscall::send(reply_port, FB_GET_INFO_OK, wh, pb, 0, 0);
            }

            FB_MAP => {
                let reply_port = msg.data[2] >> 32;
                let dst_aspace = msg.data[3];
                let _desired_va = msg.data[0] as usize;

                // Grant framebuffer pages to the requesting task.
                let fb_bytes = fb.pitch as usize * fb.height as usize;
                if dst_aspace != 0 {
                    let _ = syscall::grant_pages(
                        dst_aspace,
                        fb.fb_va,
                        0, // let kernel choose destination VA
                        fb.fb_pages,
                        false,
                    );
                }
                // Reply with the granted VA and size (client will get it from the grant).
                syscall::send(
                    reply_port,
                    FB_MAP_OK,
                    fb.fb_va as u64,
                    fb_bytes as u64,
                    0,
                    0,
                );
            }

            FB_FLIP => {
                let reply_port = msg.data[2] >> 32;
                let xy = msg.data[0];
                let wh = msg.data[1];
                let x = xy as u32;
                let y = (xy >> 32) as u32;
                let w = wh as u32;
                let h = (wh >> 32) as u32;

                if let Some(ref mut gpu) = fb.gpu {
                    // Clamp to display bounds.
                    let w = w.min(fb.width.saturating_sub(x));
                    let h = h.min(fb.height.saturating_sub(y));
                    if w > 0 && h > 0 {
                        gpu.flush(x, y, w, h);
                    }
                }
                // VBE: no-op (QEMU scans memory continuously).
                syscall::send(reply_port, FB_FLIP_OK, 0, 0, 0, 0);
            }

            _ => {
                // Unknown command — ignore.
            }
        }
    }
}
