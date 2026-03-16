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

// We need a scratch register before we can save anything. We use sscratch
// to hold a temp value. In our simple kernel (always in S-mode), sscratch = 0.

.section .text.vectors, "ax"
.balign 4
.global _trap_entry

_trap_entry:
    // Allocate trap frame on current stack.
    // We need 272 bytes (34 * 8), but align to 16 → 272 is already 16-aligned.
    addi    sp, sp, -272

    // Save x1 (ra) first, then use ra as scratch for CSR reads.
    sd      x1,  0*8(sp)
    // Save x3-x31 (skip x2=sp, we save original sp separately).
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

    // Save the original sp (before we subtracted 272) into the frame.
    addi    t0, sp, 272
    sd      t0,  1*8(sp)          // x2 slot = original sp

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

    // Restore sepc, sstatus.
    ld      t0, 31*8(sp)
    csrw    sepc, t0
    ld      t0, 32*8(sp)
    csrw    sstatus, t0

    // Restore x1 (ra).
    ld      x1,  0*8(sp)
    // Skip x2 (sp) — we restore it last.
    // Restore x3-x31.
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

    // Deallocate trap frame.
    addi    sp, sp, 272

    sret
