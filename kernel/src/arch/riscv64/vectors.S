// RISC-V trap entry/exit.
//
// Uses a tp/sscratch swap convention (similar to Linux) so that the
// correct per-CPU identity is always available in kernel mode, even
// when switching between user threads on different CPUs.
//
// sscratch convention:
//   In S-mode: sscratch = 0
//   In U-mode: sscratch = &TRAP_SCRATCH_ARRAY[cpu_id]
//
// TrapScratch layout (32 bytes, from smp.rs):
//   offset 0:  kernel_sp  — kernel stack pointer for this user thread
//   offset 8:  cpu_id     — this hart's CPU index
//   offset 16: user_sp    — temporary save of user sp during trap entry
//   offset 24: (padding)
//
// tp convention:
//   In S-mode: tp = cpu_id (0-based index)
//   In U-mode: tp = user's thread pointer (arbitrary)
//
// Trap entry swaps tp and sscratch:
//   From U-mode: tp = &TrapScratch, sscratch = user_tp  → read cpu_id + kernel_sp
//   From S-mode: tp = 0 (sscratch was 0), sscratch = cpu_id → recover tp from sscratch
//
// TrapFrame layout (272 bytes = 34 * 8):
//   offset 0..240:   x1-x31 (31 registers, indices 0..30)
//                    x1(ra) at 0, x2(sp) at 8, x3(gp) at 16, x4(tp) at 24, ...
//                    x31 at 240
//   offset 248:      sepc
//   offset 256:      sstatus
//   offset 264:      scause

.section .text.vectors, "ax"
.balign 4
.global _trap_entry

_trap_entry:
    // Swap tp and sscratch.
    // From U-mode: tp = &TrapScratch[cpu], sscratch = user_tp
    // From S-mode: tp = 0 (sscratch was 0), sscratch = kernel_tp (cpu_id)
    csrrw   tp, sscratch, tp
    bnez    tp, .from_user

    // ===== S-mode entry =====
    // Recover kernel tp (cpu_id) from sscratch.
    csrr    tp, sscratch
    // sp is already the kernel stack; allocate frame.
    addi    sp, sp, -272
    sd      x1,  0*8(sp)           // save ra
    addi    x1, sp, 272
    sd      x1,  1*8(sp)           // save original sp
    sd      tp,  3*8(sp)           // save tp (cpu_id) in x4 slot
    j       .save_common

.from_user:
    // ===== U-mode entry =====
    // tp = &TrapScratch[cpu], sscratch = user_tp
    sd      sp, 16(tp)              // TrapScratch.user_sp = user sp
    ld      sp,  0(tp)              // sp = kernel_sp
    addi    sp, sp, -272            // sp = frame base
    sd      x1,  0*8(sp)           // save ra
    // Save user sp from TrapScratch to frame[1].
    ld      x1, 16(tp)
    sd      x1,  1*8(sp)           // frame.x2 = user_sp
    // Save user tp from sscratch to frame[3].
    csrr    x1, sscratch
    sd      x1,  3*8(sp)           // frame.x4 = user_tp
    // Set tp = cpu_id for kernel use.
    ld      tp,  8(tp)             // tp = TrapScratch.cpu_id

.save_common:
    // Save x3 (gp) and x5-x31.
    // x1 (ra), x2 (sp), x4 (tp) already saved above.
    sd      x3,  2*8(sp)
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
    // Restore x1, x3, x5-x31. Do NOT restore x4/tp — keep kernel cpu_id.
    ld      x1,  0*8(sp)
    ld      x3,  2*8(sp)
    // x4 (tp) intentionally NOT restored — keep current CPU's cpu_id
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
    addi    sp, sp, 272
    sret

.restore_to_user:
    // Returning to U-mode: set sscratch = &TRAP_SCRATCH_ARRAY[cpu_id].
    // tp = cpu_id (preserved by Rust calling convention across trap_handler call).
    la      t0, TRAP_SCRATCH_ARRAY
    slli    t1, tp, 5               // t1 = cpu_id * 32 (sizeof TrapScratch)
    add     t0, t0, t1              // t0 = &TRAP_SCRATCH_ARRAY[cpu_id]

    // Store kernel_sp for the next user trap.
    addi    t1, sp, 272
    sd      t1, 0(t0)               // TrapScratch.kernel_sp = stack_top

    // Set sscratch for the next user trap.
    csrw    sscratch, t0

    // Restore x1, x3, x5-x31 (NOT x4/tp yet — handle separately).
    ld      x1,  0*8(sp)
    ld      x3,  2*8(sp)
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

    // Restore user tp from frame.
    ld      x4,  3*8(sp)

    // Restore user sp from frame (must be last — clobbers sp).
    ld      sp,  1*8(sp)
    sret
