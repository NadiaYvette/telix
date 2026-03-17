// Telix kernel entry point for x86-64.
//
// Multiboot1 header + 32-bit protected mode entry + transition to 64-bit long mode.
// QEMU -kernel loads Multiboot1 images into 32-bit protected mode.

// ============================================================================
// Multiboot1 Header (must be in first 8 KiB of the binary)
// ============================================================================
.section .multiboot, "a"
.balign 4

// Multiboot1 constants
.set MB_MAGIC,    0x1BADB002
.set MB_FLAGS,    0x00000003    // Align modules on page boundaries + provide memory map
.set MB_CHECKSUM, -(MB_MAGIC + MB_FLAGS)

multiboot_header:
    .long   MB_MAGIC
    .long   MB_FLAGS
    .long   MB_CHECKSUM

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

    // Disable interrupts
    cli

    // Save multiboot info pointer in ESI (callee-saved across our code).
    mov     esi, ebx

    // --- Zero BSS FIRST (before setting up page tables which live in BSS) ---
    lea     edi, [__bss_start]
    lea     ecx, [__bss_end]
    sub     ecx, edi
    shr     ecx, 2             // Count in dwords
    xor     eax, eax
    rep     stosd

    // --- Set up page tables for identity mapping first 1 GiB using 2 MiB pages ---
    // PML4[0] -> PDPT
    // PDPT[0] -> PD
    // PD[0..511] -> 2 MiB pages (identity mapped)
    //
    // Page tables are in BSS (just zeroed above), so they start clean.

    // PML4[0] = address of PDPT | present | writable
    lea     eax, [boot_pdpt]
    or      eax, 0x03       // Present + Writable
    mov     [boot_pml4], eax

    // Fill PDPT with 4 entries using 1 GiB pages (identity map 0..4 GiB).
    // This covers the LAPIC MMIO region at 0xFEE00000 (in the 3-4 GiB range).
    // PDPT entry: address | Present | Writable | PageSize (1 GiB page).
    lea     ebx, [boot_pdpt]
    mov     dword ptr [ebx + 0x00], 0x00000083     // 0 GiB
    mov     dword ptr [ebx + 0x04], 0x00000000
    mov     dword ptr [ebx + 0x08], 0x40000083     // 1 GiB
    mov     dword ptr [ebx + 0x0C], 0x00000000
    mov     dword ptr [ebx + 0x10], 0x80000083     // 2 GiB
    mov     dword ptr [ebx + 0x14], 0x00000000
    mov     dword ptr [ebx + 0x18], 0xC0000083     // 3 GiB (includes LAPIC)
    mov     dword ptr [ebx + 0x1C], 0x00000000

    // --- Enable PAE ---
    mov     eax, cr4
    or      eax, (1 << 5)   // CR4.PAE
    mov     cr4, eax

    // --- Load PML4 into CR3 ---
    lea     eax, [boot_pml4]
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

    // --- Load 64-bit GDT and far jump to 64-bit code ---
    lgdt    [boot_gdt_ptr]
    ljmp    0x08, offset _start64

// ============================================================================
// 64-bit entry point
// ============================================================================
.code64
_start64:
    // Load data segment selectors
    mov     ax, 0x10
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    // Set up the boot stack
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
    .long   boot_gdt

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

// ============================================================================
// Boot stack: 64 KiB in BSS
// ============================================================================
.section .bss.boot_stack, "aw", @nobits
.balign 16
__boot_stack_bottom:
    .space  65536
.global __boot_stack_top
__boot_stack_top:
