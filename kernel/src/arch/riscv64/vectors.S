// RISC-V trap entry/exit.
//
// Save all general-purpose registers (x1-x31), sepc, sstatus, scause
// onto the stack, call the Rust trap handler, then restore and sret.
//
// TrapFrame layout (272 bytes = 34 * 8):
//   offset 0..240:   x1-x31 (31 registers, but stored at indices 0..30)
//                    x1(ra) at 0, x2(sp) at 8, x3(gp) at 16, ...
//                    x31 at 240
//   offset 248:      sepc
//   offset 256:      sstatus
//   offset 264:      scause

// sscratch convention:
//   In S-mode: sscratch = 0
//   In U-mode: sscratch = kernel stack pointer for trap entry

.section .text.vectors, "ax"
.balign 4
.global _trap_entry

// Macro to restore x1, x3-x31 (all GP regs except sp).
.macro restore_gp_regs
    ld      x1,  0*8(sp)
    ld      x3,  2*8(sp)
    ld      x4,  3*8(sp)
    ld      x5,  4*8(sp)
    ld      x6,  5*8(sp)
    ld      x7,  6*8(sp)
    ld      x8,  7*8(sp)
    ld      x9,  8*8(sp)
    ld      x10, 9*8(sp)
    ld      x11, 10*8(sp)
    ld      x12, 11*8(sp)
    ld      x13, 12*8(sp)
    ld      x14, 13*8(sp)
    ld      x15, 14*8(sp)
    ld      x16, 15*8(sp)
    ld      x17, 16*8(sp)
    ld      x18, 17*8(sp)
    ld      x19, 18*8(sp)
    ld      x20, 19*8(sp)
    ld      x21, 20*8(sp)
    ld      x22, 21*8(sp)
    ld      x23, 22*8(sp)
    ld      x24, 23*8(sp)
    ld      x25, 24*8(sp)
    ld      x26, 25*8(sp)
    ld      x27, 26*8(sp)
    ld      x28, 27*8(sp)
    ld      x29, 28*8(sp)
    ld      x30, 29*8(sp)
    ld      x31, 30*8(sp)
.endm

_trap_entry:
    // Swap sp and sscratch.
    // From U-mode: sp = kernel_sp (sscratch), sscratch = user_sp
    // From S-mode: sp = 0 (sscratch was 0), sscratch = kernel_sp
    csrrw   sp, sscratch, sp
    bnez    sp, .from_user

    // From S-mode: recover sp from sscratch.
    csrr    sp, sscratch
    addi    sp, sp, -272
    // Save ra, then compute and save original sp.
    sd      x1,  0*8(sp)
    addi    x1, sp, 272
    sd      x1,  1*8(sp)
    j       .save_rest

.from_user:
    // From U-mode: sp = kernel stack, sscratch = user sp.
    addi    sp, sp, -272
    sd      x1,  0*8(sp)
    // Save user sp from sscratch.
    csrr    x1, sscratch
    sd      x1,  1*8(sp)

.save_rest:
    // Save x3-x31.
    sd      x3,  2*8(sp)
    sd      x4,  3*8(sp)
    sd      x5,  4*8(sp)
    sd      x6,  5*8(sp)
    sd      x7,  6*8(sp)
    sd      x8,  7*8(sp)
    sd      x9,  8*8(sp)
    sd      x10, 9*8(sp)
    sd      x11, 10*8(sp)
    sd      x12, 11*8(sp)
    sd      x13, 12*8(sp)
    sd      x14, 13*8(sp)
    sd      x15, 14*8(sp)
    sd      x16, 15*8(sp)
    sd      x17, 16*8(sp)
    sd      x18, 17*8(sp)
    sd      x19, 18*8(sp)
    sd      x20, 19*8(sp)
    sd      x21, 20*8(sp)
    sd      x22, 21*8(sp)
    sd      x23, 22*8(sp)
    sd      x24, 23*8(sp)
    sd      x25, 24*8(sp)
    sd      x26, 25*8(sp)
    sd      x27, 26*8(sp)
    sd      x28, 27*8(sp)
    sd      x29, 28*8(sp)
    sd      x30, 29*8(sp)
    sd      x31, 30*8(sp)

    // Save sepc, sstatus, scause.
    csrr    t0, sepc
    sd      t0, 31*8(sp)
    csrr    t0, sstatus
    sd      t0, 32*8(sp)
    csrr    t0, scause
    sd      t0, 33*8(sp)

    // Call Rust trap handler: a0 = current sp (pointer to TrapFrame).
    mv      a0, sp
    call    trap_handler
    // Return value in a0 = (potentially new) sp.
    mv      sp, a0

    // Restore sepc and sstatus.
    ld      t0, 31*8(sp)
    csrw    sepc, t0
    ld      t0, 32*8(sp)
    csrw    sstatus, t0

    // Check sstatus.SPP to determine return mode.
    // SPP = bit 8: 1 = returning to S-mode, 0 = returning to U-mode.
    andi    t0, t0, (1 << 8)
    beqz    t0, .restore_to_user

.restore_to_kernel:
    // Returning to S-mode: sscratch must be 0.
    csrw    sscratch, zero
    restore_gp_regs
    addi    sp, sp, 272
    sret

.restore_to_user:
    // Returning to U-mode: save kernel stack in sscratch for next trap.
    addi    t0, sp, 272
    csrw    sscratch, t0
    restore_gp_regs
    // Restore user sp from frame (sp still points to frame base).
    ld      sp, 1*8(sp)
    sret
