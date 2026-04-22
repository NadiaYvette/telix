#![no_std]
#![no_main]

//! Intel i915 GPU driver for Telix.
//!
//! Supports Generation 9 (Skylake/Kaby Lake), Generation 11 (Ice Lake), and Generation 12
//! (Tiger Lake/Alder Lake/Raptor Lake) display engines. Programs GGTT,
//! DPLL, pipe timing, plane, and DDI for basic framebuffer display.
//!
//! Registers as "gpu" in the nameserver and implements both the base
//! FB protocol (0x8000-0x8005) and extended GPU protocol (0x8100-0x8109).
//!
//! BAR0 (GTTMMADR) is mapped via an MMIO capability granted at spawn.
//! Framebuffer uses system memory pages mapped through the GGTT.

extern crate userlib;

use userlib::syscall;

// ---------------------------------------------------------------------------
// IPC protocol tags
// ---------------------------------------------------------------------------

// Base FB protocol (backwards-compatible with fb_srv).
const FB_GET_INFO: u64 = 0x8000;
const FB_GET_INFO_OK: u64 = 0x8001;
const FB_MAP: u64 = 0x8002;
const FB_MAP_OK: u64 = 0x8003;
const FB_FLIP: u64 = 0x8004;
const FB_FLIP_OK: u64 = 0x8005;

// Extended GPU protocol.
const GPU_GET_CAPS: u64 = 0x8100;
const GPU_GET_CAPS_OK: u64 = 0x8101;
const GPU_ENUM_MODES: u64 = 0x8102;
const GPU_ENUM_MODES_OK: u64 = 0x8103;
const GPU_SET_MODE: u64 = 0x8104;
#[allow(dead_code)]
const GPU_SET_MODE_OK: u64 = 0x8105;
const GPU_SET_CURSOR: u64 = 0x8106;
const GPU_SET_CURSOR_OK: u64 = 0x8107;
const GPU_MOVE_CURSOR: u64 = 0x8108;
const GPU_MOVE_CURSOR_OK: u64 = 0x8109;
const GPU_ERROR: u64 = 0x81FF;

// GPU capability bits (returned by GPU_GET_CAPS).
const CAP_MODE_SETTING: u64 = 1 << 0;
const CAP_HW_CURSOR: u64 = 1 << 1;
#[allow(dead_code)]
const CAP_MULTI_OUTPUT: u64 = 1 << 2;

// ---------------------------------------------------------------------------
// Intel GPU register offsets (from BAR0 / GTTMMADR)
// ---------------------------------------------------------------------------

// GGTT (Global Graphics Translation Table) — Generation 8+ at 8 MiB into BAR0.
const GGTT_BASE_GEN8: usize = 0x80_0000;
const GGTT_PTE_VALID: u64 = 0x1;
// WC (write-combining) cache attribute in PTE for Generation 8+.
const GGTT_PTE_WC: u64 = 0x1 << 1;
// Start our framebuffer PTEs at index 256 (1 MiB offset in GGTT space)
// to avoid conflicting with firmware-allocated stolen memory entries.
const GGTT_FB_START_INDEX: usize = 256;

// DPLL (Display PLL) — Generation 9/11/12 DPLL0.
const DPLL0_ENABLE: usize = 0x46010;
const DPLL0_CFGCR0: usize = 0x6C040; // Generation 9
const DPLL0_CFGCR1: usize = 0x6C044; // Generation 9
const DPLL0_CFGCR0_GEN12: usize = 0x164284;
const DPLL0_CFGCR1_GEN12: usize = 0x164288;

// Pipe A timing registers.
const HTOTAL_A: usize = 0x60000;
const HBLANK_A: usize = 0x60004;
const HSYNC_A: usize = 0x60008;
const VTOTAL_A: usize = 0x6000C;
const VBLANK_A: usize = 0x60010;
const VSYNC_A: usize = 0x60014;
const PIPE_SRCSZ_A: usize = 0x6001C;

// Pipe A configuration.
const PIPE_CONF_A: usize = 0x70008;
const PIPE_CONF_ENABLE: u32 = 1 << 31;
const PIPE_CONF_STATE_ACTIVE: u32 = 1 << 30;

// Plane 1 (primary) on Pipe A.
const PLANE_CTL_1_A: usize = 0x70180;
const PLANE_STRIDE_1_A: usize = 0x70188;
const PLANE_SIZE_1_A: usize = 0x70190;
const PLANE_SURF_1_A: usize = 0x7019C;

// Plane control bits.
const PLANE_CTL_ENABLE: u32 = 1 << 31;
const PLANE_CTL_FORMAT_XRGB8888: u32 = 0x4 << 24; // Format 0100 = XRGB 8:8:8:8
const PLANE_CTL_TILING_LINEAR: u32 = 0; // Bits 12:10 = 000 for linear

// DDI (Digital Display Interface) — port A.
const DDI_BUF_CTL_A: usize = 0x64000;
const DDI_BUF_CTL_ENABLE: u32 = 1 << 31;
// DDI buffer translation count varies; use safe default.
const DDI_BUF_CTL_TRANS_SELECT: u32 = 0; // Translation table entry 0

// Transcoder A → DDI function control.
const TRANS_DDI_FUNC_CTL_A: usize = 0x60400;
const TRANS_DDI_ENABLE: u32 = 1 << 31;
const TRANS_DDI_SELECT_PORT_A: u32 = 0 << 28; // Port A in bits 30:28
const TRANS_DDI_MODE_HDMI: u32 = 1 << 24;
const TRANS_DDI_BPC_8: u32 = 0 << 20; // 8 bits per color

// Hardware cursor (Pipe A).
const CUR_CTL_A: usize = 0x70080;
const CUR_BASE_A: usize = 0x70084;
const CUR_POS_A: usize = 0x70088;
const CUR_CTL_ENABLE_64X64: u32 = 0x27; // Enable + 64x64 ARGB

// South fuse strap (eDP detection).
const SFUSE_STRAP: usize = 0xC2014;
const SFUSE_STRAP_DDID_DETECTED: u32 = 1 << 1;
const SFUSE_STRAP_DDIC_DETECTED: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// Generationeration classification
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Generation {
    Generation9,
    Generation11,
    Generation12,
    Unknown,
}

fn classify_gen(device_id: u16) -> Generation {
    match device_id {
        // Generation 9: Skylake
        0x1902..=0x193D => Generation::Generation9,
        // Generation 9: Kaby Lake / Coffee Lake
        0x5902..=0x593D | 0x3E90..=0x3EA9 => Generation::Generation9,
        // Generation 9.5: Gemini Lake / Whiskey Lake
        0x3184..=0x3185 | 0x3EA0..=0x3EA5 => Generation::Generation9,
        // Generation 11: Ice Lake
        0x8A50..=0x8A5D => Generation::Generation11,
        // Generation 12: Tiger Lake
        0x9A40..=0x9A49 | 0x9A60..=0x9A78 => Generation::Generation12,
        // Generation 12: Rocket Lake
        0x4C80..=0x4C8F => Generation::Generation12,
        // Generation 12: Alder Lake
        0x4680..=0x46B3 | 0x4620..=0x4628 => Generation::Generation12,
        // Generation 12: Raptor Lake
        0xA780..=0xA78B | 0xA720..=0xA721 => Generation::Generation12,
        // Default to Generation 12 for unknown Intel GPUs.
        _ => Generation::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Display output port
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Port {
    A,
    B,
    C,
    D,
    #[allow(dead_code)]
    E,
}

impl Port {
    fn ddi_buf_ctl_offset(self) -> usize {
        match self {
            Port::A => 0x64000,
            Port::B => 0x64100,
            Port::C => 0x64200,
            Port::D => 0x64300,
            Port::E => 0x64400,
        }
    }

    fn trans_ddi_port_bits(self) -> u32 {
        match self {
            Port::A => 0 << 28,
            Port::B => 1 << 28,
            Port::C => 2 << 28,
            Port::D => 3 << 28,
            Port::E => 4 << 28,
        }
    }
}

// ---------------------------------------------------------------------------
// Device state
// ---------------------------------------------------------------------------

struct I915Dev {
    bar: usize,
    #[allow(dead_code)]
    device_id: u16,
    generation: Generation,
    ggtt_base: usize,
    fb_va: usize,
    fb_pages: usize,
    width: u32,
    height: u32,
    pitch: u32,
    active_port: Port,
    cur_ggtt_index: usize, // GGTT index for cursor image
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

fn mmio_read32(base: usize, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + off) as *const u32) }
}

fn mmio_write32(base: usize, off: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + off) as *mut u32, val) }
}

#[allow(dead_code)]
fn mmio_read64(base: usize, off: usize) -> u64 {
    let lo = mmio_read32(base, off) as u64;
    let hi = mmio_read32(base, off + 4) as u64;
    lo | (hi << 32)
}

fn mmio_write64(base: usize, off: usize, val: u64) {
    mmio_write32(base, off, val as u32);
    mmio_write32(base, off + 4, (val >> 32) as u32);
}

// ---------------------------------------------------------------------------
// Utility: print helpers (same as fb_srv)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// GGTT management
// ---------------------------------------------------------------------------

fn ggtt_offset_for_gen(genr: Generation) -> usize {
    match genr {
        // All Generation 8+ use GGTT at 8 MiB into BAR0.
        Generation::Generation9 | Generation::Generation11 | Generation::Generation12 | Generation::Unknown => GGTT_BASE_GEN8,
    }
}

fn write_ggtt_pte(bar: usize, ggtt_base: usize, index: usize, phys: u64) {
    let pte = phys | GGTT_PTE_VALID | GGTT_PTE_WC;
    let off = ggtt_base + index * 8;
    mmio_write64(bar, off, pte);
}

/// Allocate system memory pages and map them into the GGTT for the framebuffer.
/// Returns true on success.
fn setup_framebuffer(dev: &mut I915Dev) -> bool {
    let ps = syscall::page_size();
    let fb_bytes = dev.width as usize * dev.height as usize * 4;
    let fb_pages = (fb_bytes + ps - 1) / ps;

    // Allocate framebuffer pages.
    let fb_va = match syscall::mmap_anon(0, fb_pages, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [i915] mmap_anon failed for framebuffer\n");
            return false;
        }
    };

    // Zero-fill.
    unsafe {
        core::ptr::write_bytes(fb_va as *mut u8, 0, fb_pages * ps);
    }

    // Write GGTT PTEs for each page.
    for i in 0..fb_pages {
        let page_va = fb_va + i * ps;
        let phys = match syscall::virt_to_phys(page_va) {
            Some(p) => p as u64,
            None => {
                syscall::debug_puts(b"  [i915] virt_to_phys failed\n");
                return false;
            }
        };
        write_ggtt_pte(dev.bar, dev.ggtt_base, GGTT_FB_START_INDEX + i, phys);
    }

    // Posting read to ensure PTEs are flushed.
    let _ = mmio_read32(dev.bar, dev.ggtt_base + (GGTT_FB_START_INDEX + fb_pages - 1) * 8);

    dev.fb_va = fb_va;
    dev.fb_pages = fb_pages;
    dev.pitch = dev.width * 4;

    true
}

/// Allocate a single page for the 64x64 ARGB hardware cursor and map in GGTT.
/// Returns true on success.
fn setup_cursor_ggtt(dev: &mut I915Dev) -> bool {
    let ps = syscall::page_size();
    // 64x64x4 = 16384 bytes; needs ceil(16384/4096) = 4 pages.
    let cur_pages = (64 * 64 * 4 + ps - 1) / ps;
    let cur_va = match syscall::mmap_anon(0, cur_pages, 1) {
        Some(va) => va,
        None => return false,
    };
    unsafe {
        core::ptr::write_bytes(cur_va as *mut u8, 0, cur_pages * ps);
    }

    // Place cursor GGTT entries right after the framebuffer.
    let cur_ggtt_start = GGTT_FB_START_INDEX + dev.fb_pages;
    for i in 0..cur_pages {
        let phys = match syscall::virt_to_phys(cur_va + i * ps) {
            Some(p) => p as u64,
            None => return false,
        };
        write_ggtt_pte(dev.bar, dev.ggtt_base, cur_ggtt_start + i, phys);
    }
    let _ = mmio_read32(dev.bar, dev.ggtt_base + (cur_ggtt_start + cur_pages - 1) * 8);

    dev.cur_ggtt_index = cur_ggtt_start;
    true
}

// ---------------------------------------------------------------------------
// Display engine: output detection
// ---------------------------------------------------------------------------

fn detect_output(bar: usize) -> Port {
    // Check eDP on port A via south fuse strap.
    let sfuse = mmio_read32(bar, SFUSE_STRAP);
    // Check port presence via DDI_BUF_CTL status bits on each port.
    // DDI_BUF_CTL bit 0 indicates if the port is idle (presence detection).
    // On real hardware we'd also read the hotplug live status registers,
    // but for a basic driver, check if DDI_BUF_CTL is readable (non-FF).
    let ports = [Port::A, Port::B, Port::C, Port::D];
    for &port in &ports {
        let ctl = mmio_read32(bar, port.ddi_buf_ctl_offset());
        // If DDI_BUF_CTL reads as all-ones, port doesn't exist.
        if ctl != 0xFFFF_FFFF {
            // Port exists. Prefer eDP (Port A) for laptops.
            if matches!(port, Port::A) {
                return Port::A;
            }
        }
    }

    // Check south display fuse strap for connected outputs.
    if sfuse & SFUSE_STRAP_DDID_DETECTED != 0 {
        return Port::D;
    }
    if sfuse & SFUSE_STRAP_DDIC_DETECTED != 0 {
        return Port::C;
    }

    // Default to port A (eDP, most common on Intel iGPUs).
    Port::A
}

// ---------------------------------------------------------------------------
// Display engine: DPLL configuration
// ---------------------------------------------------------------------------

/// Configure DPLL0 for 1024x768 @ 60 Hz (pixel clock 65 MHz).
/// Generation 9 and Generation 12 have different CFGCR register locations.
fn configure_dpll(bar: usize, genr: Generation) -> bool {
    // 1024x768 @ 60 Hz VESA timing: pixel clock = 65.000 MHz.
    // For Generation 9 (Skylake): DPLL CFGCR0/1 encode PLL dividers.
    //   Reference clock = 24 MHz (common on Intel platforms).
    //   Target: 65 MHz pixel clock.
    //   P0=4, P1=1, P2=1 (DCO divider chain) → DCO = 65*4*2 = 520 MHz
    //   DCO integer = 520/24 = 21, fraction = (520 - 21*24)/24 * 2^15 ≈ 21845
    //
    // CFGCR0: DCO integer (bits 8:0) | DCO fraction (bits 24:9)
    // CFGCR1: P0 (bits 2:0=4→0b011) | P1 (bits 5:3=1→0b000) | P2 (bit 8=0→5/10 select)
    //
    // Generation 12 uses different register offsets but same encoding for combo PHY PLLs.

    let (cfgcr0_reg, cfgcr1_reg) = match genr {
        Generation::Generation12 | Generation::Unknown => (DPLL0_CFGCR0_GEN12, DPLL0_CFGCR1_GEN12),
        _ => (DPLL0_CFGCR0, DPLL0_CFGCR1),
    };

    // Disable DPLL0 first.
    mmio_write32(bar, DPLL0_ENABLE, 0);
    // Wait for disable (poll bit 30 = lock status, should clear).
    for _ in 0..1000 {
        let val = mmio_read32(bar, DPLL0_ENABLE);
        if val & (1 << 30) == 0 {
            break;
        }
        syscall::yield_now();
    }

    // Program PLL dividers for 65 MHz.
    // DCO integer = 21, fraction ≈ 21845 (0x5555).
    let cfgcr0_val: u32 = (0x5555 << 9) | 21;
    // P0=4 (encoded as 0b011), P1=1 (encoded as 0b000), P2=5 (bit 8=0).
    let cfgcr1_val: u32 = 0b011; // P0 divider

    mmio_write32(bar, cfgcr0_reg, cfgcr0_val);
    mmio_write32(bar, cfgcr1_reg, cfgcr1_val);

    // Enable DPLL0.
    mmio_write32(bar, DPLL0_ENABLE, 1 << 31);

    // Poll for PLL lock (bit 30).
    for _ in 0..10000 {
        let val = mmio_read32(bar, DPLL0_ENABLE);
        if val & (1 << 30) != 0 {
            return true;
        }
        syscall::yield_now();
    }

    syscall::debug_puts(b"  [i915] DPLL0 lock timeout\n");
    false
}

// ---------------------------------------------------------------------------
// Display engine: pipe timing
// ---------------------------------------------------------------------------

/// Configure Pipe A timing for 1024x768 @ 60 Hz (VESA DMT).
fn configure_pipe_timing(bar: usize, width: u32, height: u32) {
    // VESA DMT 1024x768 @ 60 Hz:
    //   H: active=1024, sync_start=1048, sync_end=1184, total=1344
    //   V: active=768,  sync_start=771,  sync_end=777,  total=806
    let h_active = width;
    let h_sync_start = 1048;
    let h_sync_end = 1184;
    let h_total = 1344;
    let v_active = height;
    let v_sync_start = 771;
    let v_sync_end = 777;
    let v_total = 806;

    // Register encoding: (total-1) << 16 | (active-1)
    mmio_write32(bar, HTOTAL_A, ((h_total - 1) << 16) | (h_active - 1));
    mmio_write32(bar, HBLANK_A, ((h_total - 1) << 16) | (h_active - 1));
    mmio_write32(bar, HSYNC_A, ((h_sync_end - 1) << 16) | (h_sync_start - 1));
    mmio_write32(bar, VTOTAL_A, ((v_total - 1) << 16) | (v_active - 1));
    mmio_write32(bar, VBLANK_A, ((v_total - 1) << 16) | (v_active - 1));
    mmio_write32(bar, VSYNC_A, ((v_sync_end - 1) << 16) | (v_sync_start - 1));

    // Pipe source size.
    mmio_write32(bar, PIPE_SRCSZ_A, ((h_active - 1) << 16) | (v_active - 1));
}

// ---------------------------------------------------------------------------
// Display engine: plane configuration
// ---------------------------------------------------------------------------

/// Configure primary plane on Pipe A.
/// `ggtt_surf` is the GGTT byte offset of the framebuffer.
fn configure_plane(bar: usize, ggtt_surf: u32, width: u32, height: u32, stride: u32) {
    let ctl = PLANE_CTL_ENABLE | PLANE_CTL_FORMAT_XRGB8888 | PLANE_CTL_TILING_LINEAR;

    // Stride is in units of 64 bytes for display engine.
    let stride_64 = stride / 64;

    mmio_write32(bar, PLANE_CTL_1_A, ctl);
    mmio_write32(bar, PLANE_STRIDE_1_A, stride_64);
    mmio_write32(bar, PLANE_SIZE_1_A, ((height - 1) << 16) | (width - 1));
    // PLANE_SURF write triggers an atomic update of the plane registers.
    mmio_write32(bar, PLANE_SURF_1_A, ggtt_surf);
}

// ---------------------------------------------------------------------------
// Display engine: enable sequence
// ---------------------------------------------------------------------------

/// Enable the display pipeline: transcoder → DDI → pipe → plane.
fn enable_display(bar: usize, port: Port) {
    // 1. Configure transcoder A → DDI port mapping.
    let trans_func = TRANS_DDI_ENABLE
        | port.trans_ddi_port_bits()
        | TRANS_DDI_MODE_HDMI
        | TRANS_DDI_BPC_8;
    mmio_write32(bar, TRANS_DDI_FUNC_CTL_A, trans_func);

    // 2. Enable DDI buffer.
    let ddi_ctl = DDI_BUF_CTL_ENABLE | DDI_BUF_CTL_TRANS_SELECT;
    mmio_write32(bar, port.ddi_buf_ctl_offset(), ddi_ctl);

    // 3. Enable Pipe A.
    mmio_write32(bar, PIPE_CONF_A, PIPE_CONF_ENABLE);

    // Poll for pipe active.
    for _ in 0..10000 {
        let val = mmio_read32(bar, PIPE_CONF_A);
        if val & PIPE_CONF_STATE_ACTIVE != 0 {
            break;
        }
        syscall::yield_now();
    }
}

// ---------------------------------------------------------------------------
// Hardware cursor
// ---------------------------------------------------------------------------

fn set_cursor(bar: usize, ggtt_index: usize) {
    let ggtt_addr = (ggtt_index * 4096) as u32;
    mmio_write32(bar, CUR_CTL_A, CUR_CTL_ENABLE_64X64);
    mmio_write32(bar, CUR_BASE_A, ggtt_addr);
}

fn move_cursor(bar: usize, x: i32, y: i32) {
    // CUR_POS: bits 15:0 = X position, bits 31:16 = Y position.
    // Bit 15 = sign for X, bit 31 = sign for Y (for off-screen partial).
    let x_val = if x < 0 {
        (1 << 15) | ((-x) as u32 & 0x7FFF)
    } else {
        x as u32 & 0x7FFF
    };
    let y_val = if y < 0 {
        (1 << 15) | ((-y) as u32 & 0x7FFF)
    } else {
        y as u32 & 0x7FFF
    };
    mmio_write32(bar, CUR_POS_A, (y_val << 16) | x_val);
}

// ---------------------------------------------------------------------------
// Draw test gradient (same as fb_srv)
// ---------------------------------------------------------------------------

fn draw_gradient(fb_va: usize, width: u32, height: u32, pitch: u32) {
    for y in 0..height {
        let row = fb_va + (y * pitch) as usize;
        for x in 0..width {
            let r = ((x * 255) / width.max(1)) as u8;
            let g = ((y * 255) / height.max(1)) as u8;
            let b = 128u8;
            let pixel = (r as u32) << 16 | (g as u32) << 8 | b as u32;
            unsafe {
                core::ptr::write_volatile((row + x as usize * 4) as *mut u32, pixel);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Full initialization sequence
// ---------------------------------------------------------------------------

fn init_device(dev: &mut I915Dev) -> bool {
    // 1. Set up GGTT offset for this generation.
    dev.ggtt_base = ggtt_offset_for_gen(dev.generation);

    // 2. Allocate framebuffer and write GGTT PTEs.
    if !setup_framebuffer(dev) {
        return false;
    }

    // 3. Allocate cursor GGTT region.
    if !setup_cursor_ggtt(dev) {
        syscall::debug_puts(b"  [i915] cursor GGTT setup failed (non-fatal)\n");
    }

    // 4. Detect connected output.
    dev.active_port = detect_output(dev.bar);

    // 5. Configure DPLL for 65 MHz pixel clock.
    if !configure_dpll(dev.bar, dev.generation) {
        // Continue anyway — on real hardware PLL may already be locked
        // by firmware. Display may still work.
        syscall::debug_puts(b"  [i915] DPLL config failed (continuing)\n");
    }

    // 6. Configure pipe timing for 1024x768.
    configure_pipe_timing(dev.bar, dev.width, dev.height);

    // 7. Configure primary plane with GGTT surface address.
    let ggtt_surf = (GGTT_FB_START_INDEX * 4096) as u32;
    configure_plane(dev.bar, ggtt_surf, dev.width, dev.height, dev.pitch);

    // 8. Enable display pipeline.
    enable_display(dev.bar, dev.active_port);

    // 9. Draw test gradient.
    draw_gradient(dev.fb_va, dev.width, dev.height, dev.pitch);

    // 10. Enable hardware cursor (initially hidden at 0,0).
    set_cursor(dev.bar, dev.cur_ggtt_index);
    move_cursor(dev.bar, 0, 0);

    true
}

// ---------------------------------------------------------------------------
// IPC server
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let cap_slot = (arg0 & 0xFFFF) as usize;
    let irq = (arg0 >> 48) as u32;

    syscall::debug_puts(b"  [i915_srv] starting, cap_slot=");
    print_num(cap_slot as u64);
    syscall::debug_puts(b" irq=");
    print_num(irq as u64);
    syscall::debug_puts(b"\n");

    if cap_slot == 0 {
        syscall::debug_puts(b"  [i915_srv] no MMIO cap, exiting\n");
        return;
    }

    // Map BAR0 (GTTMMADR).
    let bar = match syscall::mmio_map_cap(cap_slot) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [i915_srv] mmio_map_cap failed, exiting\n");
            return;
        }
    };

    syscall::debug_puts(b"  [i915_srv] BAR0 mapped at ");
    print_hex(bar as u64);
    syscall::debug_puts(b"\n");

    // Read device ID from PCI config shadow in MMIO space.
    // On Intel GPUs, offset 0x02 within BAR0 mirrors PCI device ID,
    // but more reliably, read from the MMIO DEVEN/DEVICE_ID register.
    // For now, read offset 0x02 of the PCI config space mirror.
    let dev_id_reg = mmio_read32(bar, 0);
    let device_id = (dev_id_reg >> 16) as u16;
    let generation = classify_gen(device_id);

    syscall::debug_puts(b"  [i915_srv] device_id=");
    print_hex(device_id as u64);
    syscall::debug_puts(b" gen=");
    match generation {
        Generation::Generation9 => syscall::debug_puts(b"9"),
        Generation::Generation11 => syscall::debug_puts(b"11"),
        Generation::Generation12 => syscall::debug_puts(b"12"),
        Generation::Unknown => syscall::debug_puts(b"unknown"),
    }
    syscall::debug_puts(b"\n");

    // Initialize device state.
    let mut dev = I915Dev {
        bar,
        device_id,
        generation,
        ggtt_base: 0,
        fb_va: 0,
        fb_pages: 0,
        width: 1024,
        height: 768,
        pitch: 0,
        active_port: Port::A,
        cur_ggtt_index: 0,
    };

    if !init_device(&mut dev) {
        syscall::debug_puts(b"  [i915_srv] init failed, exiting\n");
        return;
    }

    syscall::debug_puts(b"  [i915_srv] display initialized: ");
    print_num(dev.width as u64);
    syscall::debug_puts(b"x");
    print_num(dev.height as u64);
    syscall::debug_puts(b"\n");

    // Register as "gpu" in the nameserver.
    let port = syscall::port_create();
    syscall::ns_register(b"gpu", port);

    syscall::debug_puts(b"  [i915_srv] registered as 'gpu', entering server loop\n");

    // IPC server loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            // --- Base FB protocol (backwards-compatible with fb_srv) ---

            FB_GET_INFO => {
                let reply_port = msg.data[2] >> 32;
                let wh = (dev.width as u64) | ((dev.height as u64) << 32);
                let pb = (dev.pitch as u64) | (32u64 << 32);
                // phys = 0 (GGTT-backed, no direct physical address).
                syscall::send(reply_port, FB_GET_INFO_OK, wh, pb, 0, 0);
            }

            FB_MAP => {
                let reply_port = msg.data[2] >> 32;
                let dst_aspace = msg.data[3];
                let desired_va = msg.data[0] as usize;
                let dst_va = if desired_va != 0 { desired_va } else { dev.fb_va };
                let fb_bytes = dev.pitch as usize * dev.height as usize;
                let mut granted_va = 0u64;
                if dst_aspace != 0 {
                    if syscall::grant_pages(dst_aspace, dev.fb_va, dst_va, dev.fb_pages, false) {
                        granted_va = dst_va as u64;
                    }
                }
                syscall::send(reply_port, FB_MAP_OK, granted_va, fb_bytes as u64, 0, 0);
            }

            FB_FLIP => {
                let reply_port = msg.data[2] >> 32;
                // i915 display engine scans GGTT continuously — no explicit
                // flush needed. Just ACK the flip.
                syscall::send(reply_port, FB_FLIP_OK, 0, 0, 0, 0);
            }

            // --- Extended GPU protocol ---

            GPU_GET_CAPS => {
                let reply_port = msg.data[2] >> 32;
                let features = CAP_MODE_SETTING | CAP_HW_CURSOR;
                // data[0] = features, data[1] = driver signature ("i915" as u32).
                let sig = u32::from_le_bytes(*b"i915") as u64;
                syscall::send(reply_port, GPU_GET_CAPS_OK, features, sig, 0, 0);
            }

            GPU_ENUM_MODES => {
                let reply_port = msg.data[2] >> 32;
                // Return one mode: 1024x768 @ 60 Hz.
                let mode0 = (1024u64) | (768u64 << 16) | (60u64 << 32);
                syscall::send(reply_port, GPU_ENUM_MODES_OK, mode0, 0, 0, 0);
            }

            GPU_SET_MODE => {
                let reply_port = msg.data[2] >> 32;
                // Only one mode supported. Return error for anything else.
                syscall::send(reply_port, GPU_ERROR, 0, 0, 0, 0);
            }

            GPU_SET_CURSOR => {
                let reply_port = msg.data[2] >> 32;
                // Cursor image is expected to be written by the client into
                // a grant page at a fixed address. For now, just acknowledge
                // and re-enable the cursor at the current GGTT address.
                set_cursor(dev.bar, dev.cur_ggtt_index);
                syscall::send(reply_port, GPU_SET_CURSOR_OK, 0, 0, 0, 0);
            }

            GPU_MOVE_CURSOR => {
                let reply_port = msg.data[2] >> 32;
                let xy = msg.data[0];
                let x = xy as i32;
                let y = (xy >> 32) as i32;
                move_cursor(dev.bar, x, y);
                syscall::send(reply_port, GPU_MOVE_CURSOR_OK, 0, 0, 0, 0);
            }

            _ => {
                // Unknown tag — ignore.
            }
        }
    }
}
