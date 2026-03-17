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
const PF_X: u32 = 1;
const PF_W: u32 = 2;
#[allow(dead_code)]
const PF_R: u32 = 4;

// Per-architecture expected e_machine.
#[cfg(target_arch = "aarch64")]
const EM_EXPECTED: u16 = 183; // EM_AARCH64
#[cfg(target_arch = "riscv64")]
const EM_EXPECTED: u16 = 243; // EM_RISCV
#[cfg(target_arch = "x86_64")]
const EM_EXPECTED: u16 = 62;  // EM_X86_64

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

/// Load an ELF64 binary into the given address space.
/// Returns the entry point virtual address on success.
pub fn load_elf(
    data: &[u8],
    aspace_id: ASpaceId,
    pt_root: usize,
) -> Result<usize, ElfError> {
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

    Ok(ehdr.e_entry as usize)
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
    let pte_flags = prot_to_pte_flags(prot);

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
        let effective_flags = if already_mapped { merged_flags } else { pte_flags };

        // Allocate or get existing physical page.
        let pa = object::with_object(obj_id, |obj| {
            obj.ensure_page(0) // page_idx within this single-page object is always 0
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
            #[cfg(target_arch = "aarch64")]
            crate::arch::aarch64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, effective_flags);
            #[cfg(target_arch = "riscv64")]
            crate::arch::riscv64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, effective_flags);
            #[cfg(target_arch = "x86_64")]
            crate::arch::x86_64::mm::map_single_mmupage(pt_root, mmu_va, mmu_pa, effective_flags);
        }

        // Mark all MMU pages as installed in the VMA.
        if !already_mapped {
            aspace::with_aspace(aspace_id, |aspace| {
                if let Some(vma) = aspace.find_vma_mut(page_va) {
                    for mmu_idx in 0..mmu_count {
                        let idx = vma.mmu_index_of(page_va + mmu_idx * MMUPAGE_SIZE);
                        vma.set_installed(idx);
                        vma.set_zeroed(idx);
                    }
                }
            });
        }
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
    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::mm;
        match prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        use crate::arch::riscv64::mm;
        match prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        use crate::arch::x86_64::mm;
        match prot {
            VmaProt::ReadOnly => mm::USER_RO_FLAGS,
            VmaProt::ReadWrite => mm::USER_RW_FLAGS,
            VmaProt::ReadExec => mm::USER_RWX_FLAGS,
            VmaProt::ReadWriteExec => mm::USER_RWX_FLAGS,
        }
    }
}
