// Telix kernel entry point for x86-64.
//
// Higher-half kernel: linker places us at VMA 0xFFFFFFFF80100000+, LMA 0x100000.
// The bootloader loads the image at phys 0x100000 and jumps to `_start` at
// phys 0x100000 (Multiboot doesn't care about VMA).  In 32-bit mode we
// reference all symbols via `symbol - KERNEL_VIRT_OFFSET` to recover the
// physical address.  After paging is on we long-jump to the 64-bit code at
// its high-half VMA, where every later symbol reference works without
// adjustment.
//
// Multiboot1 header + 32-bit protected mode entry + transition to 64-bit long mode.

// ============================================================================
// Multiboot1 Header (must be in first 8 KiB of the binary)
// ============================================================================
.section .multiboot, "a"
.balign 4

// Multiboot1 constants
.set MB_MAGIC,    0x1BADB002
.set MB_FLAGS,    0x00000003    // Align modules on page boundaries + provide memory map
.set MB_CHECKSUM, -(MB_MAGIC + MB_FLAGS)

// KERNEL_VIRT_OFFSET = VMA - LMA.  Defined via linker.ld but assemblers can't
// import linker variables, so duplicate here.  Keep in sync with linker.ld.
.set KERNEL_VIRT_OFFSET, 0xFFFFFFFF80000000

multiboot_header:
    .long   MB_MAGIC
    .long   MB_FLAGS
    .long   MB_CHECKSUM

// EFI boot header: lets the EFI stub find the 64-bit entry point and stack.
// Located at kernel_base + 12 (immediately after Multiboot header).
.set EFI_HDR_MAGIC, 0x54454649   // "TEFI"
.global _efi_header
_efi_header:
    .long   EFI_HDR_MAGIC
    .long   0                       // reserved
    .quad   _rust_entry             // 64-bit entry point (high-half VMA)
    .quad   __boot_stack_top        // boot stack top (high-half VMA)

// ============================================================================
// 32-bit entry point
// ============================================================================
.section .text.boot, "ax"
.code32
.global _start

_start:
    // On entry from Multiboot1:
    //   EAX = 0x2BADB002 (Multiboot1 magic)
    //   EBX = physical address of Multiboot info structure
    //   Interrupts disabled, A20 enabled, paging off, protected mode on.
    //
    // CS:EIP points at `_start`'s LMA (= phys 0x100000+).  All symbols in
    // 32-bit code must be referenced via `[symbol - KERNEL_VIRT_OFFSET]` to
    // recover the LMA.

    // Disable interrupts
    cli

    // Save multiboot info pointer in ESI (callee-saved across our code).
    mov     esi, ebx

    // --- Zero BSS FIRST (before setting up page tables which live in BSS) ---
    lea     edi, [__bss_start - KERNEL_VIRT_OFFSET]
    lea     ecx, [__bss_end - KERNEL_VIRT_OFFSET]
    sub     ecx, edi
    shr     ecx, 2             // Count in dwords
    xor     eax, eax
    rep     stosd

    // --- Set up page tables: low identity (PML4[0]) + high-half (PML4[511]) ---
    //
    // Low identity (PML4[0] → boot_pdpt → 4 × 1 GiB gigapages 0..4 GiB):
    //   Needed for (a) the post-paging-on CR3 load that runs at low EIP, and
    //   (b) phys::alloc_page consumers that use the returned PA as a virt.
    //
    // High-half (PML4[511] → boot_pdpt_hi → 1 GiB gigapages 0..2 GiB at
    //   PDPT[510] and PDPT[511]):
    //   Maps VA 0xFFFFFFFF80000000..0xFFFFFFFFFFFFFFFF → PA 0..0x80000000.
    //   Kernel image (loaded at phys 0x100000) is reachable at high-half VMA
    //   0xFFFFFFFF80100000.

    // PML4[0] = boot_pdpt (present + writable)
    lea     eax, [boot_pdpt - KERNEL_VIRT_OFFSET]
    or      eax, 0x03
    lea     ebx, [boot_pml4 - KERNEL_VIRT_OFFSET]
    mov     [ebx], eax

    // PML4[511] = boot_pdpt_hi (present + writable)
    lea     eax, [boot_pdpt_hi - KERNEL_VIRT_OFFSET]
    or      eax, 0x03
    mov     [ebx + 511*8], eax

    // #208 VA-isolation reservations (docs/slab-pt-va-isolation.md).
    // Each PML4 entry points at an empty (all-zero) PDPT, so any access
    // to these VA ranges page-faults until the PDPT is populated.  Phase
    // 1 just establishes the slots; later phases route allocations here.
    //   PML4[510] = PT_REGION          (boot_pdpt_pt)
    //   PML4[509] = SLAB_REGION        (boot_pdpt_slab)
    //   PML4[508] = KSTACK_REGION      (boot_pdpt_kstack)
    //   PML4[507] = PHYS_DIRECT_MAP    (boot_pdpt_phys_direct)
    lea     eax, [boot_pdpt_pt - KERNEL_VIRT_OFFSET]
    or      eax, 0x03
    mov     [ebx + 510*8], eax
    lea     eax, [boot_pdpt_slab - KERNEL_VIRT_OFFSET]
    or      eax, 0x03
    mov     [ebx + 509*8], eax
    lea     eax, [boot_pdpt_kstack - KERNEL_VIRT_OFFSET]
    or      eax, 0x03
    mov     [ebx + 508*8], eax
    lea     eax, [boot_pdpt_phys_direct - KERNEL_VIRT_OFFSET]
    or      eax, 0x03
    mov     [ebx + 507*8], eax

    // Fill boot_pdpt: 4 × 1 GiB gigapages identity-mapping 0..4 GiB.
    // PDPT entry: address | Present | Writable | PageSize (1 GiB page) = 0x83.
    lea     ebx, [boot_pdpt - KERNEL_VIRT_OFFSET]
    mov     dword ptr [ebx + 0x00], 0x00000083     // 0 GiB
    mov     dword ptr [ebx + 0x04], 0x00000000
    mov     dword ptr [ebx + 0x08], 0x40000083     // 1 GiB
    mov     dword ptr [ebx + 0x0C], 0x00000000
    mov     dword ptr [ebx + 0x10], 0x80000083     // 2 GiB
    mov     dword ptr [ebx + 0x14], 0x00000000
    mov     dword ptr [ebx + 0x18], 0xC0000083     // 3 GiB (includes LAPIC)
    mov     dword ptr [ebx + 0x1C], 0x00000000

    // Fill boot_pdpt_hi: only entries 510 + 511 (2 × 1 GiB at low 2 GiB phys).
    // VA 0xFFFFFFFF80000000 → PDPT[510] → phys 0x00000000.
    // VA 0xFFFFFFFFC0000000 → PDPT[511] → phys 0x40000000.
    lea     ebx, [boot_pdpt_hi - KERNEL_VIRT_OFFSET]
    mov     dword ptr [ebx + 510*8 + 0], 0x00000083    // → phys 0x00000000
    mov     dword ptr [ebx + 510*8 + 4], 0x00000000
    mov     dword ptr [ebx + 511*8 + 0], 0x40000083    // → phys 0x40000000
    mov     dword ptr [ebx + 511*8 + 4], 0x00000000

    // #208 VA-isolation Phase 2: PHYS_DIRECT_MAP at PML4[507].
    // Populate boot_pdpt_phys_direct with 4 × 1 GiB gigapages mapping
    // phys 0..4 GiB at VA 0xFFFFFD80_00000000+.  Lets kernel access any
    // phys page via a uniform offset map without going through identity
    // PML4[0], so PML4[0] can eventually be unmapped to enforce
    // VA/phys separation.
    lea     ebx, [boot_pdpt_phys_direct - KERNEL_VIRT_OFFSET]
    mov     dword ptr [ebx + 0x00], 0x00000083    // → phys 0x00000000 (0 GiB)
    mov     dword ptr [ebx + 0x04], 0x00000000
    mov     dword ptr [ebx + 0x08], 0x40000083    // → phys 0x40000000 (1 GiB)
    mov     dword ptr [ebx + 0x0C], 0x00000000
    mov     dword ptr [ebx + 0x10], 0x80000083    // → phys 0x80000000 (2 GiB)
    mov     dword ptr [ebx + 0x14], 0x00000000
    mov     dword ptr [ebx + 0x18], 0xC0000083    // → phys 0xC0000000 (3 GiB)
    mov     dword ptr [ebx + 0x1C], 0x00000000

    // --- Enable PAE + SSE (OSFXSR, OSXMMEXCPT) ---
    mov     eax, cr4
    or      eax, (1 << 5) | (1 << 9) | (1 << 10)   // CR4.PAE | CR4.OSFXSR | CR4.OSXMMEXCPT
    mov     cr4, eax
    // --- Clear CR0.EM, set CR0.MP so SSE instructions work ---
    mov     eax, cr0
    and     eax, ~(1 << 2)  // clear CR0.EM (emulation)
    or      eax, (1 << 1)   // set CR0.MP (monitor coprocessor)
    mov     cr0, eax

    // --- Load PML4 into CR3 ---
    lea     eax, [boot_pml4 - KERNEL_VIRT_OFFSET]
    mov     cr3, eax

    // --- Enable long mode via EFER MSR ---
    mov     ecx, 0xC0000080 // IA32_EFER
    rdmsr
    or      eax, (1 << 8) | (1 << 11) // EFER.LME + EFER.NXE
    wrmsr

    // --- Enable paging (and keep protected mode) ---
    mov     eax, cr0
    or      eax, (1 << 31)  // CR0.PG
    mov     cr0, eax

    // --- Load 64-bit GDT and far jump to 64-bit code at LOW (LMA) RIP first ---
    // We can't ljmp directly to the high-half VMA from 32-bit (immediate is
    // truncated to 32 bits and the high VMA's upper half would be lost).
    // Instead: ljmp to `_start64` at its LMA (phys = VMA - KERNEL_VIRT_OFFSET).
    // PML4[0] still identity-maps low 4 GiB, so the CPU continues fetching
    // at the low VMA without faulting.  Inside _start64, immediately do a
    // 64-bit absolute jump to the high-VMA copy.
    lgdt    [boot_gdt_ptr - KERNEL_VIRT_OFFSET]
    ljmp    0x08, offset _start64_low

// `_start64_low` is the LMA-relative location of the 64-bit entry; the linker
// resolves `_start64_low` to its VMA, but `offset` in a 32-bit ljmp truncates
// to 32 bits.  Define the symbol so it has the same LMA byte position as
// `_start64`'s VMA byte position minus KERNEL_VIRT_OFFSET; the assembler will
// emit the LMA as the immediate.
.set _start64_low, _start64 - KERNEL_VIRT_OFFSET

// ============================================================================
// 64-bit entry point
// ============================================================================
.code64
_start64:
    // We just arrived at LOW (LMA) RIP via ljmp from 32-bit code.  CPU is in
    // 64-bit mode now; we can use full 64-bit immediates.  First, jump to
    // the HIGH-half VMA copy of ourselves.
    movabs  rax, offset _start64_high
    jmp     rax

_start64_high:
    // Now executing at HIGH (VMA) RIP.  All later code uses linker-assigned
    // high VMAs uniformly.

    // Load data segment selectors
    mov     ax, 0x10
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    // Set up the boot stack at its high-half VMA (BSS is in the high mapping).
    lea     rsp, [__boot_stack_top]

    // BSS was already zeroed in 32-bit mode above.

    // Pass multiboot info pointer (saved in ESI) as first argument.
    // Zero-extend ESI to RDI.
    mov     edi, esi
    call    _rust_entry

    // Should not return
.halt64:
    cli
    hlt
    jmp     .halt64

// ============================================================================
// Boot GDT (minimal, just for the 32->64 transition)
// ============================================================================
.section .rodata.boot, "a"
.balign 16

boot_gdt:
    .quad   0x0000000000000000  // Null descriptor
    .quad   0x00AF9A000000FFFF  // Code segment: 64-bit, present, DPL=0, executable, readable
    .quad   0x00CF92000000FFFF  // Data segment: present, DPL=0, writable
boot_gdt_end:

boot_gdt_ptr:
    .short  boot_gdt_end - boot_gdt - 1
    // GDT base needs to be the LMA so the 32-bit lgdt picks up the right
    // physical address.  Subtract KERNEL_VIRT_OFFSET from the linker-assigned
    // VMA to recover the LMA.  The full 64-bit value is encoded as 8 bytes
    // (lgdt with REX.W = 8-byte base in long mode; in 32-bit lgdt it's 4
    // bytes, and the linker truncates to low 32 = the LMA).
    .quad   boot_gdt - KERNEL_VIRT_OFFSET

// ============================================================================
// Boot page tables (must be page-aligned)
// ============================================================================
.section .bss.boot_pt, "aw", @nobits
.balign 4096

.global boot_pml4
boot_pml4:
    .space  4096

boot_pdpt:
    .space  4096

boot_pd:
    .space  4096

// High-half PDPT (PML4[511] → here).  Maps two 1-GiB gigapages covering
// the low 2 GiB physical, exposed at VA 0xFFFFFFFF80000000..0xFFFFFFFFFFFFFFFF.
boot_pdpt_hi:
    .space  4096

// #208 VA-isolation reserved PDPTs (docs/slab-pt-va-isolation.md, Phase 1).
// Empty (zero-initialized) at boot; later phases populate entries as
// allocations happen.  Each backs one PML4 slot:
//   boot_pdpt_pt          → PML4[510] → PT_REGION
//   boot_pdpt_slab        → PML4[509] → SLAB_REGION
//   boot_pdpt_kstack      → PML4[508] → KSTACK_REGION
//   boot_pdpt_phys_direct → PML4[507] → PHYS_DIRECT_MAP
boot_pdpt_pt:
    .space  4096

boot_pdpt_slab:
    .space  4096

boot_pdpt_kstack:
    .space  4096

boot_pdpt_phys_direct:
    .space  4096

// ============================================================================
// Boot stack: 256 KiB in BSS.  Sized large because BSP early init can use
// substantial stack (println! StackBufs, kernel data structure setup) and
// overflow into adjacent .bss boot_pdpt_* pages corrupts page tables —
// surfaces as Phase-5b "kstack VA not present" #PF with garbage in the
// PDPT entry (a kernel function pointer, indicating a stack frame).
// ============================================================================
.section .bss.boot_stack, "aw", @nobits
.balign 16
__boot_stack_bottom:
    .space  262144
.global __boot_stack_top
__boot_stack_top:
