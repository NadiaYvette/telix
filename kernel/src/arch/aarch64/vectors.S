// AArch64 exception vector table.
//
// The table must be 2048-byte aligned. 16 entries of 128 bytes each.
// Each entry branches to a handler stub defined after the table.

.section .text.vectors, "ax"
.balign 2048
.global __exception_vectors
__exception_vectors:

// ---- Current EL with SP_EL0 (entries 0-3, unused) ----
// Entry 0: Sync
    b       vec_unhandled
    .balign 128
// Entry 1: IRQ
    b       vec_unhandled
    .balign 128
// Entry 2: FIQ
    b       vec_unhandled
    .balign 128
// Entry 3: SError
    b       vec_unhandled
    .balign 128

// ---- Current EL with SP_ELx (entries 4-7) ----
// Entry 4: Sync
    b       vec_sync_el1
    .balign 128
// Entry 5: IRQ
    b       vec_irq_el1
    .balign 128
// Entry 6: FIQ
    b       vec_unhandled
    .balign 128
// Entry 7: SError
    b       vec_serror_el1
    .balign 128

// ---- Lower EL using AArch64 (entries 8-11) ----
// Entry 8: Sync
    b       vec_sync_el0
    .balign 128
// Entry 9: IRQ
    b       vec_irq_el0
    .balign 128
// Entry 10: FIQ
    b       vec_unhandled
    .balign 128
// Entry 11: SError
    b       vec_serror_el0
    .balign 128

// ---- Lower EL using AArch32 (entries 12-15, unsupported) ----
// Entry 12: Sync
    b       vec_unhandled
    .balign 128
// Entry 13: IRQ
    b       vec_unhandled
    .balign 128
// Entry 14: FIQ
    b       vec_unhandled
    .balign 128
// Entry 15: SError
    b       vec_unhandled

// ==== End of vector table (2048 bytes from __exception_vectors) ====

// ==== Handler stubs ====
// These are outside the vector table proper.
// They save all registers, call the Rust handler, restore, and eret.

.macro save_regs
    sub     sp, sp, #288
    stp     x0,  x1,  [sp, #0]
    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30,      [sp, #240]
    mrs     x10, sp_el0
    mrs     x11, elr_el1
    mrs     x12, spsr_el1
    mrs     x13, esr_el1
    str     x10, [sp, #248]
    str     x11, [sp, #256]
    str     x12, [sp, #264]
    str     x13, [sp, #272]
.endm

.macro restore_regs
    ldr     x10, [sp, #248]
    ldr     x11, [sp, #256]
    ldr     x12, [sp, #264]
    msr     sp_el0, x10
    msr     elr_el1, x11
    msr     spsr_el1, x12
    ldp     x0,  x1,  [sp, #0]
    ldp     x2,  x3,  [sp, #16]
    ldp     x4,  x5,  [sp, #32]
    ldp     x6,  x7,  [sp, #48]
    ldp     x8,  x9,  [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    ldr     x30,      [sp, #240]
    add     sp, sp, #288
.endm

vec_unhandled:
    save_regs
    mov     x0, sp
    bl      exception_unhandled
    restore_regs
    eret

vec_sync_el1:
    save_regs
    mov     x0, sp
    bl      exception_sync_el1
    mov     sp, x0              // Use return value as new SP (L4 handoff support)
    restore_regs
    eret

vec_irq_el1:
    save_regs
    mov     x0, sp              // Pass current SP (pointing to exception frame) as arg
    bl      exception_irq_el1   // Returns new SP in x0 (may be different thread's stack)
    mov     sp, x0              // Switch to the (potentially new) stack
    restore_regs
    eret

vec_serror_el1:
    save_regs
    mov     x0, sp
    bl      exception_serror_el1
    restore_regs
    eret

vec_sync_el0:
    save_regs
    mov     x0, sp
    bl      exception_sync_el0
    mov     sp, x0              // Use return value as new SP (L4 handoff support)
    restore_regs
    eret

vec_irq_el0:
    save_regs
    mov     x0, sp              // Pass current SP (pointing to exception frame) as arg
    bl      exception_irq_el0   // Returns new SP in x0 (may be different thread's stack)
    mov     sp, x0              // Switch to the (potentially new) stack
    restore_regs
    eret

vec_serror_el0:
    save_regs
    mov     x0, sp
    bl      exception_serror_el0
    restore_regs
    eret
