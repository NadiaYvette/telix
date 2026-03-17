// x86-64 AP (Application Processor) trampoline.
//
// Copied to physical address 0x8000 by the BSP. APs start in 16-bit real mode.
//
// BSP writes startup data at AP_DATA (0x8F00):
//   +0x00: PML4 physical address (u32)
//   +0x08: stack pointer (u64)
//   +0x10: cpu_id (u32)
//   +0x18: 64-bit entry point (u64)
//   +0x20: 64-bit GDT pointer (10 bytes)
//   +0x30: 32-bit GDT (24 bytes: null + code + data)
//   +0x48: 32-bit GDT pointer (6 bytes: limit + base)

.set AP_BASE, 0x8000
.set AP_DATA, 0x8F00

.section .rodata.ap_trampoline, "a"
.global _ap_trampoline_start
.global _ap_trampoline_end

_ap_trampoline_start:

// ---- 16-bit real mode entry ----
.code16
    cli
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     ss, ax

    // lgdt from AP_DATA+0x48 (32-bit GDT pointer written by BSP).
    // Encoded as: 0F 01 16 <16-bit-addr>
    .byte   0x0F, 0x01, 0x16
    .short  0x8F48

    // Enable protected mode.
    mov     eax, cr0
    or      al, 1
    mov     cr0, eax

    // Far jump to 32-bit code (loads CS=0x08).
    // Encoded with 32-bit operand override: 66 EA <32-bit-offset> <16-bit-selector>
    .byte   0x66, 0xEA
    .long   ap_pm32 - _ap_trampoline_start + AP_BASE
    .short  0x08

// ---- 32-bit protected mode ----
.code32
ap_pm32:
    mov     ax, 0x10
    mov     ds, ax
    mov     es, ax
    mov     ss, ax

    // Enable PAE.
    mov     eax, cr4
    or      eax, (1 << 5)
    mov     cr4, eax

    // Load PML4 from data block.
    mov     eax, [0x8F00]
    mov     cr3, eax

    // Enable long mode.
    mov     ecx, 0xC0000080
    rdmsr
    or      eax, (1 << 8) | (1 << 11)  // LME + NXE
    wrmsr

    // Enable paging.
    mov     eax, cr0
    or      eax, (1 << 31)
    mov     cr0, eax

    // Load 64-bit GDT from data block.
    lgdt    [0x8F20]

    // Far jump to 64-bit code (loads CS=0x08 in long mode).
    .byte   0xEA
    .long   ap_lm64 - _ap_trampoline_start + AP_BASE
    .short  0x08

// ---- 64-bit long mode ----
.code64
ap_lm64:
    mov     ax, 0x10
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    // Load stack from data block.
    mov     rsp, [0x8F08]

    // Load cpu_id into edi (first argument).
    mov     edi, [0x8F10]

    // Jump to 64-bit Rust entry point.
    mov     rax, [0x8F18]
    jmp     rax

_ap_trampoline_end:
