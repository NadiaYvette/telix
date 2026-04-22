//! Telix UEFI boot loader for x86-64.
//!
//! Loads the kernel ELF (embedded at build time), queries the UEFI GOP
//! for framebuffer info, locates the ACPI RSDP, calls ExitBootServices(),
//! and jumps to the kernel's 64-bit entry point.
//!
//! Built as a standalone PE/COFF EFI application (target x86_64-unknown-uefi).

#![no_std]
#![no_main]

use core::arch::asm;

// ── Embedded kernel ──────────────────────────────────────────────────
// The build script sets TELIX_KERNEL_PATH to the kernel ELF.
static KERNEL_ELF: &[u8] = include_bytes!(env!("TELIX_KERNEL_PATH"));

// ── UEFI types ───────────────────────────────────────────────────────

type Handle = usize;
type Status = usize;
const EFI_SUCCESS: Status = 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}

fn guid_eq(a: &Guid, b: &Guid) -> bool {
    a.a == b.a && a.b == b.b && a.c == b.c && a.d == b.d
}

#[repr(C)]
struct TableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

#[repr(C)]
struct SystemTable {
    hdr: TableHeader,
    firmware_vendor: usize,
    firmware_revision: u32,
    _pad: u32,
    con_in_handle: usize,
    con_in: usize,
    con_out_handle: usize,
    con_out: *const SimpleTextOutput,
    stderr_handle: usize,
    stderr: usize,
    runtime_services: usize,
    boot_services: *const BootServices,
    num_entries: usize,
    config_table: *const ConfigTable,
}

#[repr(C)]
struct SimpleTextOutput {
    reset: usize,
    output_string: unsafe extern "efiapi" fn(*const SimpleTextOutput, *const u16) -> Status,
}

#[repr(C)]
struct BootServices {
    hdr: TableHeader,
    _tpl: [usize; 2],
    allocate_pages: unsafe extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status,
    _free_pages: usize,
    get_memory_map: unsafe extern "efiapi" fn(
        *mut usize, *mut u8, *mut usize, *mut usize, *mut u32,
    ) -> Status,
    allocate_pool: unsafe extern "efiapi" fn(u32, usize, *mut *mut u8) -> Status,
    free_pool: unsafe extern "efiapi" fn(*mut u8) -> Status,
    _events: [usize; 6],
    _proto_mgmt: [usize; 3],
    handle_protocol:
        unsafe extern "efiapi" fn(Handle, *const Guid, *mut *const u8) -> Status,
    _reserved_proto: [usize; 5],
    _image: [usize; 4],
    exit_boot_services: unsafe extern "efiapi" fn(Handle, usize) -> Status,
    _misc_a: usize,
    stall: unsafe extern "efiapi" fn(usize) -> Status,
    _misc_b: usize,
    _driver: [usize; 2],
    _open: [usize; 3],
    _lib: [usize; 2],
    locate_protocol:
        unsafe extern "efiapi" fn(*const Guid, usize, *mut *const u8) -> Status,
}

#[repr(C)]
struct GraphicsOutput {
    query_mode: usize,
    set_mode: usize,
    blt: usize,
    mode: *const GopMode,
}

#[repr(C)]
struct GopMode {
    max_mode: u32,
    mode: u32,
    info: *const GopModeInfo,
    info_size: usize,
    fb_base: u64,
    fb_size: usize,
}

#[repr(C)]
struct GopModeInfo {
    version: u32,
    h_res: u32,
    v_res: u32,
    pixel_format: u32,
    _pixel_bitmask: [u32; 4],
    pixels_per_scanline: u32,
}

#[repr(C)]
struct ConfigTable {
    vendor_guid: Guid,
    vendor_table: usize,
}

#[repr(C)]
struct MemoryDescriptor {
    mem_type: u32,
    _pad: u32,
    phys_start: u64,
    virt_start: u64,
    num_pages: u64,
    attribute: u64,
}

// ── UEFI GUIDs ───────────────────────────────────────────────────────

const GOP_GUID: Guid = Guid {
    a: 0x9042a9de, b: 0x23dc, c: 0x4a38,
    d: [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
};

const ACPI20_GUID: Guid = Guid {
    a: 0x8868e871, b: 0xe4f1, c: 0x11d3,
    d: [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
};

// ── Boot info (shared with kernel) ───────────────────────────────────

const BOOT_INFO_ADDR: usize = 0x7000;
const BOOT_INFO_MAGIC: u32 = 0x54454649; // "TEFI"

// Flags.
const BIF_FRAMEBUFFER: u32 = 1 << 0;
const BIF_RSDP: u32 = 1 << 1;

#[repr(C)]
struct BootInfo {
    magic: u32,
    flags: u32,
    rsdp_addr: u64,
    fb_addr: u64,
    fb_pitch: u32,
    fb_width: u32,
    fb_height: u32,
    fb_bpp: u32,
    mem_count: u32,
    _reserved: u32,
    mem_entries: [MemEntry; 128],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MemEntry {
    base: u64,
    size: u64,
    kind: u32, // 1 = usable RAM
    _pad: u32,
}

// ── ELF types ────────────────────────────────────────────────────────

const PT_LOAD: u32 = 1;

#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    _e_shoff: u64,
    _e_flags: u32,
    _e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
}

#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    _p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    _p_align: u64,
}

// ── EFI kernel header at kernel_base + 12 ────────────────────────────

const EFI_HDR_MAGIC: u32 = 0x54454649;

#[repr(C)]
struct EfiKernelHeader {
    magic: u32,
    _reserved: u32,
    entry: u64,
    stack_top: u64,
}

// ── Print helper ─────────────────────────────────────────────────────

unsafe fn puts(con_out: *const SimpleTextOutput, s: &[u8]) {
    unsafe {
        let mut buf = [0u16; 128];
        let n = s.len().min(buf.len() - 1);
        for i in 0..n {
            buf[i] = s[i] as u16;
        }
        buf[n] = 0;
        ((*con_out).output_string)(con_out, buf.as_ptr());
    }
}

unsafe fn put_hex(con_out: *const SimpleTextOutput, val: u64) {
    unsafe {
        let mut buf = [0u16; 19]; // "0x" + 16 hex digits + null
        buf[0] = b'0' as u16;
        buf[1] = b'x' as u16;
        for i in 0..16 {
            let nib = ((val >> (60 - i * 4)) & 0xF) as u16;
            buf[2 + i] = if nib < 10 { b'0' as u16 + nib } else { b'a' as u16 + nib - 10 };
        }
        buf[18] = 0;
        ((*con_out).output_string)(con_out, buf.as_ptr());
    }
}

// ── ELF loader ───────────────────────────────────────────────────────

/// Parse the ELF header from the embedded kernel, copy PT_LOAD segments
/// to their physical load addresses, and zero BSS.  Returns the lowest
/// load address (kernel base) on success.
unsafe fn load_kernel(elf: &[u8]) -> Option<usize> {
    unsafe {
        if elf.len() < 64 { return None; }
        let ehdr = &*(elf.as_ptr() as *const Elf64Ehdr);
        if ehdr.e_ident[0..4] != [0x7f, b'E', b'L', b'F'] { return None; }

        let mut lowest = usize::MAX;
        for i in 0..ehdr.e_phnum as usize {
            let off = ehdr.e_phoff as usize + i * ehdr.e_phentsize as usize;
            if off + 56 > elf.len() { return None; }
            let phdr = &*(elf.as_ptr().add(off) as *const Elf64Phdr);
            if phdr.p_type != PT_LOAD { continue; }

            let dst = phdr.p_paddr as usize;
            let file_off = phdr.p_offset as usize;
            let filesz = phdr.p_filesz as usize;
            let memsz = phdr.p_memsz as usize;

            if filesz > 0 && file_off + filesz <= elf.len() {
                core::ptr::copy_nonoverlapping(
                    elf.as_ptr().add(file_off),
                    dst as *mut u8,
                    filesz,
                );
            }
            if memsz > filesz {
                core::ptr::write_bytes((dst + filesz) as *mut u8, 0, memsz - filesz);
            }
            if dst < lowest { lowest = dst; }
        }
        if lowest == usize::MAX { None } else { Some(lowest) }
    }
}

// ── Page table setup ─────────────────────────────────────────────────

/// Fill the PML4 + PDPT at `base` to identity-map 0–4 GiB with 1 GiB
/// pages (same mapping as the kernel's boot.S).
unsafe fn setup_page_tables(base: usize) {
    unsafe {
        let pml4 = base as *mut u64;
        let pdpt = (base + 4096) as *mut u64;
        core::ptr::write_bytes(pml4, 0, 512);
        core::ptr::write_bytes(pdpt, 0, 512);
        *pml4 = (pdpt as u64) | 0x03;
        *pdpt.add(0) = 0x0000_0000_0000_0083; // 0 GiB
        *pdpt.add(1) = 0x0000_0000_4000_0083; // 1 GiB
        *pdpt.add(2) = 0x0000_0000_8000_0083; // 2 GiB
        *pdpt.add(3) = 0x0000_0000_C000_0083; // 3 GiB (includes LAPIC)
    }
}

// ── Entry point ──────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, st: &SystemTable) -> Status {
    let con_out = st.con_out;
    let bs = unsafe { &*st.boot_services };

    unsafe { puts(con_out, b"Telix EFI loader\r\n") };

    // ── 1. Query GOP for framebuffer ─────────────────────────────────
    let mut flags: u32 = 0;
    let mut fb_addr: u64 = 0;
    let mut fb_pitch: u32 = 0;
    let mut fb_width: u32 = 0;
    let mut fb_height: u32 = 0;
    let mut fb_bpp: u32 = 32;

    let mut gop_ptr: *const u8 = core::ptr::null();
    let gop_status = unsafe {
        (bs.locate_protocol)(&GOP_GUID, 0, &mut gop_ptr)
    };
    if gop_status == EFI_SUCCESS && !gop_ptr.is_null() {
        unsafe {
            let gop = &*(gop_ptr as *const GraphicsOutput);
            let mode = &*gop.mode;
            let info = &*mode.info;
            fb_addr = mode.fb_base;
            fb_width = info.h_res;
            fb_height = info.v_res;
            // Pitch = pixels per scanline × bytes per pixel.
            fb_bpp = if info.pixel_format <= 1 { 32 } else { 32 };
            fb_pitch = info.pixels_per_scanline * (fb_bpp / 8);
            flags |= BIF_FRAMEBUFFER;

            puts(con_out, b"  GOP: ");
            put_hex(con_out, fb_width as u64);
            puts(con_out, b"x");
            put_hex(con_out, fb_height as u64);
            puts(con_out, b" fb=");
            put_hex(con_out, fb_addr);
            puts(con_out, b"\r\n");
        }
    } else {
        unsafe { puts(con_out, b"  GOP: not found\r\n") };
    }

    // ── 2. Find ACPI 2.0 RSDP in EFI configuration table ────────────
    let mut rsdp_addr: u64 = 0;
    for i in 0..st.num_entries {
        let entry = unsafe { &*st.config_table.add(i) };
        if guid_eq(&entry.vendor_guid, &ACPI20_GUID) {
            rsdp_addr = entry.vendor_table as u64;
            flags |= BIF_RSDP;
            break;
        }
    }
    unsafe {
        puts(con_out, b"  RSDP: ");
        if rsdp_addr != 0 { put_hex(con_out, rsdp_addr); }
        else { puts(con_out, b"not found"); }
        puts(con_out, b"\r\n");
    }

    // ── 3. Allocate pages for our page tables (2 pages) ──────────────
    let mut pt_addr: u64 = 0;
    let st_pt = unsafe { (bs.allocate_pages)(0, 2, 2, &mut pt_addr) };
    if st_pt != EFI_SUCCESS {
        unsafe { puts(con_out, b"FATAL: cannot allocate page tables\r\n") };
        return 1;
    }
    unsafe { setup_page_tables(pt_addr as usize) };

    // ── 4. Allocate memory at kernel load address (0x100000) ─────────
    // Reserve 16 MiB starting at 1 MiB (covers kernel + initramfs).
    let mut kern_phys: u64 = 0x100000;
    let kern_pages: usize = (16 * 1024 * 1024) / 4096; // 4096 pages
    let st_kern = unsafe { (bs.allocate_pages)(2, 2, kern_pages, &mut kern_phys) };
    if st_kern != EFI_SUCCESS {
        unsafe {
            puts(con_out, b"FATAL: cannot allocate at 0x100000 (");
            put_hex(con_out, st_kern as u64);
            puts(con_out, b")\r\n");
        }
        return 1;
    }

    unsafe {
        puts(con_out, b"  Kernel: ");
        put_hex(con_out, KERNEL_ELF.len() as u64);
        puts(con_out, b" bytes ELF embedded\r\n");
    }

    // ── 5. Get memory map + ExitBootServices ─────────────────────────
    // Allocate a buffer for the memory map.
    let mut mmap_size: usize = 0;
    let mut mmap_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_ver: u32 = 0;

    // First call: get required size.
    unsafe {
        (bs.get_memory_map)(
            &mut mmap_size, core::ptr::null_mut(),
            &mut mmap_key, &mut desc_size, &mut desc_ver,
        );
    }
    mmap_size += desc_size * 8; // headroom for map changes

    let mut mmap_buf: *mut u8 = core::ptr::null_mut();
    let st_pool = unsafe { (bs.allocate_pool)(2, mmap_size, &mut mmap_buf) };
    if st_pool != EFI_SUCCESS || mmap_buf.is_null() {
        unsafe { puts(con_out, b"FATAL: cannot allocate mmap buffer\r\n") };
        return 1;
    }

    // Second call: get actual map.
    let st_map = unsafe {
        (bs.get_memory_map)(
            &mut mmap_size, mmap_buf,
            &mut mmap_key, &mut desc_size, &mut desc_ver,
        )
    };
    if st_map != EFI_SUCCESS {
        unsafe { puts(con_out, b"FATAL: GetMemoryMap failed\r\n") };
        return 1;
    }

    unsafe { puts(con_out, b"  Calling ExitBootServices...\r\n") };

    // ExitBootServices — may need retry if the map key changed.
    let mut exit_status = unsafe {
        (bs.exit_boot_services)(image, mmap_key)
    };
    if exit_status != EFI_SUCCESS {
        // Retry: get fresh memory map and try again.
        mmap_size += desc_size * 4;
        unsafe {
            (bs.get_memory_map)(
                &mut mmap_size, mmap_buf,
                &mut mmap_key, &mut desc_size, &mut desc_ver,
            );
            exit_status = (bs.exit_boot_services)(image, mmap_key);
        }
    }
    if exit_status != EFI_SUCCESS {
        // Cannot print — boot services are gone or in indeterminate state.
        loop { unsafe { asm!("hlt") }; }
    }

    // ═════════════════════════════���═════════════════════════════════════
    // No more UEFI boot services beyond this point.
    // ═══════════════════════════════════════════════════════════════════

    // ── 6. Load kernel ELF segments to 0x100000 ─────────────────────
    let kern_base = unsafe { load_kernel(KERNEL_ELF) };
    let kern_base = match kern_base {
        Some(b) => b,
        None => loop { unsafe { asm!("hlt") }; },
    };

    // ── 7. Read EFI kernel header at kern_base + 12 ──────────────────
    let efi_hdr = unsafe { &*((kern_base + 12) as *const EfiKernelHeader) };
    if efi_hdr.magic != EFI_HDR_MAGIC {
        loop { unsafe { asm!("hlt") }; }
    }
    let entry = efi_hdr.entry;
    let stack_top = efi_hdr.stack_top;

    // ── 8. Write boot info at 0x7000 ─────────────────────────────────
    unsafe {
        let bi = &mut *(BOOT_INFO_ADDR as *mut BootInfo);
        bi.magic = BOOT_INFO_MAGIC;
        bi.flags = flags;
        bi.rsdp_addr = rsdp_addr;
        bi.fb_addr = fb_addr;
        bi.fb_pitch = fb_pitch;
        bi.fb_width = fb_width;
        bi.fb_height = fb_height;
        bi.fb_bpp = fb_bpp;

        // Convert EFI memory map to simplified entries.
        let mut count: u32 = 0;
        let n_descs = mmap_size / desc_size;
        for i in 0..n_descs {
            if count as usize >= 128 { break; }
            let desc = &*(mmap_buf.add(i * desc_size) as *const MemoryDescriptor);
            // EFI memory types 3,4,5,6,7 are usable conventional memory.
            let usable = matches!(desc.mem_type, 3..=7);
            bi.mem_entries[count as usize] = MemEntry {
                base: desc.phys_start,
                size: desc.num_pages * 4096,
                kind: if usable { 1 } else { 0 },
                _pad: 0,
            };
            count += 1;
        }
        bi.mem_count = count;
        bi._reserved = 0;
    }

    // ── 9. Switch to our page tables ─────────────────────────────────
    unsafe {
        asm!(
            "mov cr3, {0}",
            in(reg) pt_addr,
            options(nostack, preserves_flags),
        );
    }

    // ── 10. Jump to kernel ───────────────────────────────────────────
    unsafe {
        asm!(
            "mov rsp, {stack}",
            "xor esi, esi",
            "mov rdi, {info}",
            "jmp {entry}",
            stack = in(reg) stack_top,
            info = in(reg) BOOT_INFO_ADDR as u64,
            entry = in(reg) entry,
            options(noreturn),
        );
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop { unsafe { asm!("hlt") }; }
}
