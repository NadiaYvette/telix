//! Minimal ELF64 loader for statically-linked executables.
//!
//! Loads PT_LOAD segments into a user address space, eagerly mapping pages
//! and copying file data. No dynamic linking, relocations, or TLS.

use crate::mm::{aspace, object, page::{PAGE_SIZE, MMUPAGE_SIZE}};
use crate::mm::aspace::ASpaceId;
use crate::mm::vma::VmaProt;

// ELF64 constants.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3; // PIE executables (x86-64 default)
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
#[allow(dead_code)]
const PF_R: u32 = 4;

use crate::arch::elf::EM_EXPECTED;

/// ELF64 file header (first 64 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// ELF64 program header (56 bytes each).
#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[derive(Debug)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    BadClass,
    BadEndian,
    BadType,
    BadMachine,
    BadPhdr,
    MapFailed,
    AllocFailed,
}

/// Information returned by ELF loader for auxv construction.
#[derive(Debug, Clone, Copy)]
pub struct ElfInfo {
    pub entry: usize,
    pub phdr_vaddr: usize,
    pub phentsize: usize,
    pub phnum: usize,
    /// Interpreter path from PT_INTERP (null-terminated, 0 length if none).
    pub interp: [u8; 64],
    pub interp_len: usize,
}

/// Load an ELF64 binary into the given address space.
/// Returns ElfInfo with entry point, phdr location, and program header details.
pub fn load_elf(
    data: &[u8],
    aspace_id: ASpaceId,
    pt_root: usize,
) -> Result<ElfInfo, ElfError> {
    if data.len() < 64 {
        return Err(ElfError::TooSmall);
    }

    // Parse header from raw bytes (avoiding alignment issues).
    let ehdr = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Elf64Ehdr) };

    // Validate.
    if ehdr.e_ident[0..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    if ehdr.e_ident[4] != ELFCLASS64 {
        return Err(ElfError::BadClass);
    }
    if ehdr.e_ident[5] != ELFDATA2LSB {
        return Err(ElfError::BadEndian);
    }
    if ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN {
        return Err(ElfError::BadType);
    }
    if ehdr.e_machine != EM_EXPECTED {
        return Err(ElfError::BadMachine);
    }

    let phoff = ehdr.e_phoff as usize;
    let phentsize = ehdr.e_phentsize as usize;
    let phnum = ehdr.e_phnum as usize;

    if phentsize < 56 {
        return Err(ElfError::BadPhdr);
    }

    // Find PT_PHDR, PT_INTERP, and compute phdr_vaddr.
    let mut phdr_vaddr: usize = 0;
    let mut interp = [0u8; 64];
    let mut interp_len: usize = 0;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        if off + 56 > data.len() { break; }
        let phdr = unsafe {
            core::ptr::read_unaligned(data.as_ptr().add(off) as *const Elf64Phdr)
        };
        if phdr.p_type == PT_PHDR {
            phdr_vaddr = phdr.p_vaddr as usize;
        }
        if phdr.p_type == PT_INTERP {
            // Extract interpreter path from file data.
            let ioff = phdr.p_offset as usize;
            let ilen = (phdr.p_filesz as usize).min(63);
            if ioff + ilen <= data.len() {
                interp[..ilen].copy_from_slice(&data[ioff..ioff + ilen]);
                // Strip null terminator if present.
                interp_len = if ilen > 0 && interp[ilen - 1] == 0 { ilen - 1 } else { ilen };
            }
        }
        // Fallback: if first PT_LOAD contains the phdrs, compute from file offset.
        if phdr.p_type == PT_LOAD && phdr_vaddr == 0
            && phdr.p_offset as usize <= phoff
            && (phdr.p_offset as usize + phdr.p_filesz as usize) >= phoff + phnum * phentsize
        {
            phdr_vaddr = phdr.p_vaddr as usize + (phoff - phdr.p_offset as usize);
        }
    }

    // Process each PT_LOAD segment.
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        if off + 56 > data.len() {
            return Err(ElfError::BadPhdr);
        }
        let phdr = unsafe {
            core::ptr::read_unaligned(data.as_ptr().add(off) as *const Elf64Phdr)
        };

        if phdr.p_type != PT_LOAD {
            continue;
        }
        if phdr.p_memsz == 0 {
            continue;
        }

        load_segment(data, &phdr, aspace_id, pt_root)?;
    }

    Ok(ElfInfo {
        entry: ehdr.e_entry as usize,
        phdr_vaddr,
        phentsize,
        phnum,
        interp,
        interp_len,
    })
}

/// Load an ET_DYN ELF at a given base address (for dynamic linker loading).
/// All PT_LOAD segment vaddrs are offset by `base`.
pub fn load_elf_at_base(
    data: &[u8],
    aspace_id: ASpaceId,
    pt_root: usize,
    base: usize,
) -> Result<ElfInfo, ElfError> {
    if data.len() < 64 {
        return Err(ElfError::TooSmall);
    }

    let ehdr = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Elf64Ehdr) };

    if ehdr.e_ident[0..4] != ELF_MAGIC { return Err(ElfError::BadMagic); }
    if ehdr.e_ident[4] != ELFCLASS64 { return Err(ElfError::BadClass); }
    if ehdr.e_ident[5] != ELFDATA2LSB { return Err(ElfError::BadEndian); }
    if ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC { return Err(ElfError::BadType); }
    if ehdr.e_machine != EM_EXPECTED { return Err(ElfError::BadMachine); }

    let phoff = ehdr.e_phoff as usize;
    let phentsize = ehdr.e_phentsize as usize;
    let phnum = ehdr.e_phnum as usize;

    if phentsize < 56 { return Err(ElfError::BadPhdr); }

    // For ET_DYN, find the lowest vaddr to compute the actual base offset.
    let mut min_vaddr: usize = usize::MAX;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        if off + 56 > data.len() { break; }
        let phdr = unsafe {
            core::ptr::read_unaligned(data.as_ptr().add(off) as *const Elf64Phdr)
        };
        if phdr.p_type == PT_LOAD && (phdr.p_vaddr as usize) < min_vaddr {
            min_vaddr = phdr.p_vaddr as usize;
        }
    }
    if min_vaddr == usize::MAX { min_vaddr = 0; }
    let offset = base.wrapping_sub(min_vaddr);

    for i in 0..phnum {
        let off = phoff + i * phentsize;
        if off + 56 > data.len() { return Err(ElfError::BadPhdr); }
        let mut phdr = unsafe {
            core::ptr::read_unaligned(data.as_ptr().add(off) as *const Elf64Phdr)
        };

        if phdr.p_type != PT_LOAD || phdr.p_memsz == 0 {
            continue;
        }

        // Offset the vaddr by base.
        phdr.p_vaddr += offset as u64;
        load_segment(data, &phdr, aspace_id, pt_root)?;
    }

    Ok(ElfInfo {
        entry: (ehdr.e_entry as usize).wrapping_add(offset),
        phdr_vaddr: base + phoff, // approximate
        phentsize,
        phnum,
        interp: [0; 64],
        interp_len: 0,
    })
}

fn load_segment(
    data: &[u8],
    phdr: &Elf64Phdr,
    aspace_id: ASpaceId,
    pt_root: usize,
) -> Result<(), ElfError> {
    let vaddr = phdr.p_vaddr as usize;
    let memsz = phdr.p_memsz as usize;
    let filesz = phdr.p_filesz as usize;
    let file_off = phdr.p_offset as usize;

    // Align VA range to PAGE_SIZE.
    let va_start = vaddr & !(PAGE_SIZE - 1);
    let va_end = (vaddr + memsz + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let page_count = (va_end - va_start) / PAGE_SIZE;

    // Determine protection.
    let prot = flags_to_prot(phdr.p_flags);
    let sw_z = crate::mm::fault::sw_zeroed_bit();
    let pte_flags = prot_to_pte_flags(prot) | sw_z;

    // For each page in this segment's range, either create a new mapping
    // or reuse an existing one (when multiple PT_LOAD segments share a page).
    for page_idx in 0..page_count {
        let page_va = va_start + page_idx * PAGE_SIZE;

        // Check if this page is already mapped by a previous segment.
        // If so, merge permissions (take the union) so we don't narrow earlier flags.
        let (obj_id, already_mapped, merged_flags) = aspace::with_aspace(aspace_id, |aspace| {
            if let Some(vma) = aspace.find_vma_mut(page_va) {
                let merged = merge_prot(vma.prot, prot);
                vma.prot = merged;
                Ok::<_, ElfError>((vma.object_id, true, prot_to_pte_flags(merged)))
            } else {
                // Need to create a new single-page VMA.
                let vma = aspace.map_anon(page_va, 1, prot)
                    .ok_or(ElfError::MapFailed)?;
                Ok((vma.object_id, false, pte_flags))
            }
        })?;
        let effective_flags = if already_mapped { merged_flags | sw_z } else { pte_flags };

        // Allocate or get existing physical page.
        let pa = object::with_object(obj_id, |obj| {
            obj.ensure_page(0).map(|(pa, _)| pa) // page_idx within this single-page object is always 0
        }).ok_or(ElfError::AllocFailed)?;

        let pa_usize = pa.as_usize();

        // Zero the page only if we just created it.
        if !already_mapped {
            unsafe {
                core::ptr::write_bytes(pa_usize as *mut u8, 0, PAGE_SIZE);
            }
        }

        // Copy file data for each MMU page in this allocation page.
        let mmu_count = PAGE_SIZE / MMUPAGE_SIZE;
        for mmu_idx in 0..mmu_count {
            let mmu_va = page_va + mmu_idx * MMUPAGE_SIZE;
            let mmu_pa = pa_usize + mmu_idx * MMUPAGE_SIZE;

            // Copy file data if this MMU page overlaps the file region.
            if mmu_va < vaddr + filesz && mmu_va + MMUPAGE_SIZE > vaddr {
                let src_start = if mmu_va >= vaddr {
                    file_off + (mmu_va - vaddr)
                } else {
                    file_off
                };
                let dst_offset = if mmu_va >= vaddr { 0 } else { vaddr - mmu_va };
                let copy_end = (vaddr + filesz).min(mmu_va + MMUPAGE_SIZE);
                let copy_start = vaddr.max(mmu_va);
                let copy_len = copy_end - copy_start;

                if copy_len > 0 && src_start + copy_len <= data.len() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr().add(src_start),
                            (mmu_pa + dst_offset) as *mut u8,
                            copy_len,
                        );
                    }
                }
            }

            // Install PTE with merged permissions (union of all overlapping segments).
            crate::mm::hat::map_single_mmupage(pt_root, mmu_va, mmu_pa, effective_flags);
        }

        // PTE installation with SW_ZEROED is the authority — no bitmap update needed.
    }

    Ok(())
}

/// Merge two VMA protections by taking the union of capabilities.
/// E.g., ReadExec + ReadOnly = ReadExec; ReadWrite + ReadExec = ReadWriteExec.
fn merge_prot(a: VmaProt, b: VmaProt) -> VmaProt {
    let w = a.writable() || b.writable();
    let x = a.executable() || b.executable();
    match (w, x) {
        (false, false) => VmaProt::ReadOnly,
        (true, false) => VmaProt::ReadWrite,
        (false, true) => VmaProt::ReadExec,
        (true, true) => VmaProt::ReadWriteExec,
    }
}

fn flags_to_prot(p_flags: u32) -> VmaProt {
    let w = p_flags & PF_W != 0;
    let x = p_flags & PF_X != 0;
    match (w, x) {
        (false, false) => VmaProt::ReadOnly,
        (true, false) => VmaProt::ReadWrite,
        (false, true) => VmaProt::ReadExec,
        (true, true) => VmaProt::ReadWriteExec,
    }
}

fn prot_to_pte_flags(prot: VmaProt) -> u64 {
    crate::mm::hat::pte_flags_for_prot(prot)
}
