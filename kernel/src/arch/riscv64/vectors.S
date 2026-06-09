// RISC-V trap entry/exit.
//
// Uses a gp/sscratch swap convention (similar to Linux's tp scheme but
// with cpu_id moved off tp to leave tp free for the user TLS base) so
// that the correct per-CPU identity is always available in kernel mode,
// even when switching between user threads on different CPUs.
//
// #250 history: we previously used `tp` for cpu_id, but `set_tls()` is
// invoked from S-mode (scheduler.rs:6447) and writes the user TLS base
// straight to live `tp`, clobbering cpu_id mid-dispatch.  Moving cpu_id
// to `gp` separates concerns: gp stays the kernel's per-hart id register
// throughout S-mode, while tp is purely the user's TLS base across the
// trap boundary.  See memory/project_riscv64_set_tls_tp_clobber.md.
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
// gp convention:
//   In S-mode: gp = cpu_id (0-based index)
//   In U-mode: gp = user's global pointer (arbitrary)
//
// Trap entry swaps gp and sscratch:
//   From U-mode: gp = &TrapScratch, sscratch = user_gp  → read cpu_id + kernel_sp
//   From S-mode: gp = 0 (sscratch was 0), sscratch = cpu_id → recover gp from sscratch
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
    // Swap gp and sscratch.
    // From U-mode: gp = &TrapScratch[cpu], sscratch = user_gp
    // From S-mode: gp = 0 (sscratch was 0), sscratch = kernel_gp (cpu_id)
    csrrw   gp, sscratch, gp
    bnez    gp, .from_user

    // ===== S-mode entry =====
    // Recover kernel gp (cpu_id) from sscratch.
    csrr    gp, sscratch
    // sp is already the kernel stack; allocate frame.
    addi    sp, sp, -272
    sd      x1,  0*8(sp)           // save ra
    addi    x1, sp, 272
    sd      x1,  1*8(sp)           // save original sp
    sd      gp,  2*8(sp)           // save gp (cpu_id) in x3 slot
    j       .save_common

.from_user:
    // ===== U-mode entry =====
    // gp = &TrapScratch[cpu], sscratch = user_gp
    sd      sp, 16(gp)              // TrapScratch.user_sp = user sp
    ld      sp,  0(gp)              // sp = kernel_sp
    addi    sp, sp, -272            // sp = frame base
    sd      x1,  0*8(sp)           // save ra
    // Save user sp from TrapScratch to frame[1].
    ld      x1, 16(gp)
    sd      x1,  1*8(sp)           // frame.x2 = user_sp
    // Save user gp from sscratch to frame[2].
    csrr    x1, sscratch
    sd      x1,  2*8(sp)           // frame.x3 = user_gp
    // Set gp = cpu_id for kernel use.
    ld      gp,  8(gp)             // gp = TrapScratch.cpu_id

.save_common:
    // Save x4 (tp) and x5-x31.
    // x1 (ra), x2 (sp), x3 (gp) already saved above.
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
    // Restore x1, x4, x5-x31.  Do NOT restore x3/gp — keep kernel cpu_id.
    // (#250: cpu_id is in gp on riscv64; restoring x3 from frame would
    // clobber the hart id we need to look up per-CPU data.)
    ld      x1,  0*8(sp)
    // x3 (gp) intentionally NOT restored — keep current CPU's cpu_id.
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
    addi    sp, sp, 272
    sret

.restore_to_user:
    // Returning to U-mode: set sscratch = &TRAP_SCRATCH[cpu_id].
    // gp = cpu_id (preserved by Rust calling convention across trap_handler call).
    // TRAP_SCRATCH_BASE holds a pointer to the dynamic per-CPU TrapScratch
    // slice (installed by smp::init_dynamic_percpu after phys::init).
    la      t0, TRAP_SCRATCH_BASE
    ld      t0, 0(t0)               // t0 = base of TrapScratch slice
    slli    t1, gp, 5               // t1 = cpu_id * 32 (sizeof TrapScratch)
    add     t0, t0, t1              // t0 = &TRAP_SCRATCH[cpu_id]

    // Store kernel_sp for the next user trap.
    addi    t1, sp, 272
    sd      t1, 0(t0)               // TrapScratch.kernel_sp = stack_top

    // Set sscratch for the next user trap.
    csrw    sscratch, t0

    // Restore x1, x4, x5-x31 (NOT x3/gp yet — handle separately).
    ld      x1,  0*8(sp)
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

    // Restore user gp from frame (was saved at trap entry from user_gp).
    ld      x3,  2*8(sp)

    // Restore user sp from frame (must be last — clobbers sp).
    ld      sp,  1*8(sp)
    sret
