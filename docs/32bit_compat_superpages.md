# 32-bit Process Compatibility and Superpage Interaction

## Overview

Running 32-bit processes on a 64-bit Telix system raises the question of whether the VM subsystem's superpage machinery — in particular, the configurable `PAGE_SIZE` clustering and the two-regime superpage model (guaranteed subpage superpages, improved assembly for larger superpages) — is complicated or undermined by the different superpage size spectrums available in 32-bit page table formats.

The short answer is that the design is largely unaffected. The complications are confined to the virtual mapping layer and are handled by existing mechanisms (the per-memory-object alignment class tracking). The physical allocator, extent-based metadata, and WSCLOCK reclaim are completely untouched by process bitness.

## Principle: PAGE_SIZE Is System-Wide

`PAGE_SIZE` is a property of the physical memory allocator, not of any individual process or page table format. It is set at compile time or boot time and applies system-wide. Every process — 32-bit or 64-bit — has its physical memory allocated at the same `PAGE_SIZE` granularity. The allocator does not know or care whether a given allocation page will be mapped into a 32-bit or 64-bit address space.

This means the physical layer — the allocator, the extent-based metadata, contiguity management, and the slab allocator — is entirely unaffected by 32-bit compatibility. The guarantees about subpage superpage availability (superpage sizes ≤ `PAGE_SIZE` succeed by construction) remain valid regardless of process bitness, because they are properties of physical contiguity, not of virtual mapping.

## What Differs: Virtual Superpage Sizes Per Page Table Format

The superpage sizes available to a process depend on the page table format in use, which may differ between 64-bit and 32-bit processes on the same architecture. The superpage promotion logic needs to know which sizes are available for each mapping. This is already architecture-dependent; the 32-bit compat case adds at most one more set of sizes per architecture.

### x86-64 / i386 Compat

**64-bit (4-level or 5-level page tables):** 4 KiB base, 2 MiB (PDE large page), 1 GiB (PDPE large page).

**32-bit PAE (3-level page tables):** 4 KiB base, 2 MiB (PDE large page). Non-PAE 32-bit has 4 MiB superpages, but any sane implementation uses PAE.

**Impact:** The important superpage size (2 MiB) is the same in both modes. The 1 GiB superpage is unavailable in 32-bit mode, but 1 GiB superpages are rarely used for process mappings anyway (the virtual address space of a 32-bit process is too small to benefit much). `PAGE_SIZE` clustering works identically for both modes. **No design impact.**

### ARM64 / AArch32 Compat

**64-bit (AArch64, 4 KiB granule):** 4 KiB base, 64 KiB (contiguous PTE hint, 16 adjacent PTEs), 2 MiB (block descriptor at level 2), 1 GiB (block descriptor at level 1).

**32-bit (AArch32, short-descriptor format):** 4 KiB base, 64 KiB (large page descriptor), 1 MiB (section descriptor), 16 MiB (supersection descriptor).

**Impact:** The superpage size spectrums differ:

| Size | AArch64 | AArch32 |
|------|---------|---------|
| 64 KiB | contiguous PTE hint | large page descriptor |
| 1 MiB | — | section descriptor |
| 2 MiB | block descriptor | — |
| 16 MiB | — | supersection descriptor |
| 1 GiB | block descriptor | — |

However, this is less problematic than it appears:

- **64 KiB** is available in both modes (via different mechanisms). With `PAGE_SIZE` ≥ 64 KiB, this subpage superpage is guaranteed by construction in both modes.
- **The first "large" superpage differs** (1 MiB for AArch32 vs 2 MiB for AArch64). At 256 KiB `PAGE_SIZE`, assembling a 1 MiB AArch32 section requires only 4 contiguous allocation pages — actually *easier* than the 8 needed for a 2 MiB AArch64 block. At 64 KiB `PAGE_SIZE`, it's 16 pages for 1 MiB vs 32 for 2 MiB — still easier.
- **The 32-bit case is generally friendlier**, not harder, for superpage assembly because the target sizes are smaller.

The promotion logic needs a per-page-table-format table of available superpage sizes and their alignment requirements. This is a small amount of static data per architecture. **Minimal design impact; the 32-bit case is actually easier than 64-bit.**

### MIPS64 / o32 and n32 Compat

**Both modes:** MIPS uses software-managed TLB with paired entries. Page sizes are configured per TLB entry and can range from 4 KiB to 256 MiB (implementation-dependent), and this is the same in 32-bit and 64-bit mode. The TLB does not change behavior based on process address width.

**Impact:** The virtual address space is smaller for 32-bit processes, but the superpage sizes are identical. **No design impact.**

### RISC-V

**RV64 does not natively execute RV32 binaries.** 32-bit RISC-V compat would require full emulation. **The question does not arise for native execution.**

## Handling in the Existing Design

The per-memory-object superpage tracking (§4.6 of the design document) already accounts for the possibility that different mappings of the same memory object may have different promotion characteristics — this is the alignment class mechanism developed for page table sharing (§4.7.2). A file mapped in one process at one alignment and in another process at a different alignment must be tracked in separate promotion groups.

The 32-bit vs 64-bit distinction is handled by the same mechanism: if a memory object is mapped in both a 64-bit process (with 2 MiB block descriptors available on ARM64) and a 32-bit process (with 1 MiB section descriptors available), those mappings are in different promotion groups because they target different superpage sizes. The per-memory-object accounting structure tracks which mappings can share promotion decisions and which cannot, based on both alignment and available page table features.

No new mechanism is needed. The alignment class tracking absorbs the 32-bit case as another dimension of mapping heterogeneity.

## Summary of Impact by Subsystem

| Subsystem | Impact from 32-bit compat |
|-----------|---------------------------|
| Physical allocator | None. PAGE_SIZE is system-wide. |
| Extent-based metadata | None. Operates on physical ranges. |
| Slab allocator | None. Sub-PAGE_SIZE allocations are width-independent. |
| Page cache / tail packing | None. Physical layer. |
| Superpage promotion | Small. Needs per-page-table-format size tables. Handled by existing alignment class mechanism. |
| WSCLOCK reclaim | Minimal. Virtual address range is smaller for 32-bit; clock hand stays within that range. |
| Per-mapping ART | Minimal. ART depth may differ for 32-bit address spaces (fewer levels). |
| Page table sharing | Slightly affected. 32-bit and 64-bit mappings of the same object cannot share page tables (different formats). Already handled by alignment class mechanism. |
| Page zeroing | None. Zeroing is at MMUPAGE_SIZE granularity regardless. |

## Recommendations

1. **Do not vary PAGE_SIZE by process.** This would enormously complicate the physical allocator and extent metadata for no benefit. PAGE_SIZE is a system-wide parameter.

2. **Implement a per-page-table-format superpage size table** as static data: for each supported page table format (AArch64 4K granule, AArch32 short descriptor, x86-64 4-level, x86 PAE, etc.), list the available superpage sizes and their alignment requirements. The promotion logic indexes into this table based on the page table format of the mapping being considered.

3. **Defer 32-bit compat to Phase 4 or later.** The kernel needs 32-bit trap handling and page table format support, but the VM subsystem design does not need modification. 32-bit compat is an additive feature, not a structural change.

4. **ARM64 AArch32 compat may be deprioritised** given that Apple Silicon and some newer Cortex-A implementations have dropped AArch32 support at EL0. The trend in the ARM ecosystem is toward AArch64-only, reducing the long-term value of AArch32 compat investment.
