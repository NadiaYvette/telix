// Telix kernel entry point for AArch64.
//
// QEMU virt machine loads the kernel at 0x40080000 via -kernel flag.
// CPU 0 enters at _start. Secondary CPUs are held in firmware until
// released via PSCI CPU_ON.
//
// On entry: x0 = DTB pointer (physical address), x1-x3 = 0.

.section .text.boot, "ax"
.global _start

_start:
    // Check current exception level.
    mrs     x9, CurrentEL
    lsr     x9, x9, #2
    cmp     x9, #2
    b.eq    .from_el2
    b       .at_el1

.from_el2:
    // Configure EL1 from EL2: AArch64 execution state at EL1.
    // HCR_EL2.RW (bit 31) = 1 → AArch64 at EL1.
    mov     w9, #0x80000000
    msr     hcr_el2, x9

    // Don't trap FP/SIMD to EL2.
    mov     x9, #0x33ff
    msr     cptr_el2, x9
    msr     hstr_el2, xzr          // Don't trap system register accesses

    // Set SCTLR_EL1 to a safe reset value: MMU off, caches off, RES1 bits.
    // Use movz/movk to construct the value 0x30d00800.
    movz    x9, #0x0800
    movk    x9, #0x30d0, lsl #16
    msr     sctlr_el1, x9

    // Prepare SPSR for EL1h (EL1, SP_EL1, all interrupts masked).
    mov     x9, #0x3c5             // EL1h | DAIF masked
    msr     spsr_el2, x9

    // Return address: .at_el1
    adr     x9, .at_el1
    msr     elr_el2, x9
    eret

.at_el1:
    // Ensure we use SP_EL1 (EL1h mode), not SP_EL0.
    msr     spsel, #1

    // Ensure MMU and caches are disabled. SCTLR_EL1: clear M (bit 0), C (bit 2), I (bit 12).
    // Keep RES1 bits set: 0x30d00800.
    movz    x9, #0x0800
    movk    x9, #0x30d0, lsl #16
    msr     sctlr_el1, x9
    isb

    // Enable FP/SIMD at EL1 (CPACR_EL1.FPEN = 0b11).
    mov     x9, #(3 << 20)
    msr     cpacr_el1, x9
    isb

    // Only CPU 0 proceeds; others spin (for SMP later).
    mrs     x9, mpidr_el1
    and     x9, x9, #0xff          // Aff0 = CPU ID
    cbnz    x9, .secondary_spin

    // Zero BSS.
    adrp    x9, __bss_start
    add     x9, x9, :lo12:__bss_start
    adrp    x10, __bss_end
    add     x10, x10, :lo12:__bss_end
.bss_loop:
    cmp     x9, x10
    b.ge    .bss_done
    stp     xzr, xzr, [x9], #16
    b       .bss_loop
.bss_done:

    // Set up boot stack (grows downward from top of __boot_stack).
    adrp    x9, __boot_stack_top
    add     x9, x9, :lo12:__boot_stack_top
    mov     sp, x9

    // x0 still holds the DTB pointer from firmware.
    bl      _rust_entry

    // Should not return; halt if it does.
.halt:
    wfe
    b       .halt

// Secondaries that arrive during initial boot spin here (held by firmware).
// PSCI CPU_ON will direct them to _secondary_entry instead.
.secondary_spin:
    wfe
    b       .secondary_spin

// ============================================================================
// Secondary CPU entry point (called via PSCI CPU_ON).
// On entry: x0 = stack_top (context_id from PSCI).
// CPU ID is read from MPIDR_EL1.
// ============================================================================
.global _secondary_entry
_secondary_entry:
    // x0 = stack_top (passed by BSP via PSCI context_id).
    mov     x20, x0             // Save stack_top in callee-saved reg.

    // Set SP_EL1 mode.
    msr     spsel, #1

    // Safe SCTLR_EL1 (MMU off, caches off, RES1 bits).
    movz    x9, #0x0800
    movk    x9, #0x30d0, lsl #16
    msr     sctlr_el1, x9
    isb

    // Enable FP/SIMD at EL1.
    mov     x9, #(3 << 20)
    msr     cpacr_el1, x9
    isb

    // Set up stack.
    mov     sp, x20

    // Get CPU ID from MPIDR_EL1 Aff0.
    mrs     x19, mpidr_el1
    and     x19, x19, #0xff

    // Enter Rust secondary init. x0 = cpu_id.
    mov     x0, x19
    bl      secondary_rust_entry

    // Should not return.
.secondary_halt:
    wfe
    b       .secondary_halt

// Boot stack: 64 KiB in BSS.
.section .bss.boot_stack, "aw", @nobits
.balign 16
__boot_stack_bottom:
    .space  65536
.global __boot_stack_top
__boot_stack_top:
