// LoongArch64 exception entry/exit and TLB refill.
//
// CSR.SAVE0 convention (similar to RISC-V sscratch):
//   In kernel mode: SAVE0 = 0
//   In user mode:   SAVE0 = &TRAP_SCRATCH_ARRAY[cpu_id]
//
// TrapScratch layout (32 bytes, from smp.rs):
//   offset 0:  kernel_sp
//   offset 8:  cpu_id
//   offset 16: user_sp (temporary)
//   offset 24: (padding)
//
// TrapFrame layout (280 bytes = 35 * 8):
//   offset 0..255:   r0-r31 (32 regs * 8 bytes)
//   offset 256:      era  (CSR.ERA)
//   offset 264:      prmd (CSR.PRMD)
//   offset 272:      estat (CSR.ESTAT)
//
// On exception entry: CRMD.PLV=0 (kernel), ERA=faulting PC, PRMD=previous mode.
// On TLB refill: separate entry via CSR.TLBRENTRY, uses TLBRERA/TLBRBADV CSRs.
// CSR.SAVE1 used as scratch register during general exception entry.
// CSR.SAVE2/SAVE3 used as scratch during TLB refill.

// -------------------------------------------------------------------------
// TLB Refill Handler
// -------------------------------------------------------------------------
// Uses LDDIR/LDPTE hardware-assisted page walk.
// CSR.PGDL contains the current user page table root.
// PWCL/PWCH configure the walk levels.

.section .text.vectors, "ax"
.balign 4096
.global _tlb_refill

_tlb_refill:
    csrwr   $t0, 0x32               // SAVE2 = t0
    csrwr   $t1, 0x33               // SAVE3 = t1

    csrrd   $t0, 0x19               // t0 = PGDL (user page table root)

    // 4-level walk: PGD → PUD → PMD → PTE
    lddir   $t0, $t0, 3             // walk Dir3 (PGD level, bits 47:39)
    lddir   $t0, $t0, 2             // walk Dir2 (PUD level, bits 38:30)
    lddir   $t0, $t0, 1             // walk Dir1 (PMD level, bits 29:21)
    ldpte   $t0, 0                  // load even PTE → TLBRELO0
    ldpte   $t0, 1                  // load odd PTE → TLBRELO1
    tlbfill                          // fill TLB with the entry
    // ibar synchronizes instruction pipeline after TLB fill, preventing
    // stale instruction fetch from triggering spurious INE exceptions.
    ibar    0

    csrrd   $t0, 0x32               // restore t0
    csrrd   $t1, 0x33               // restore t1
    ertn                             // return from TLB refill

// -------------------------------------------------------------------------
// General Exception Entry
// -------------------------------------------------------------------------

.balign 4096
.global _trap_entry

_trap_entry:
    // Save $r1 (ra) in SAVE1 as scratch.
    csrwr   $r1, 0x31               // SAVE1 = ra

    // Read SAVE0 — non-zero means from user, zero means from kernel.
    csrrd   $r1, 0x30               // r1 = SAVE0
    bnez    $r1, .from_user

    // ===== Kernel-mode entry =====
    // SAVE0 was 0 → kernel trap. sp is already the kernel stack.
    // Restore ra from SAVE1.
    csrrd   $r1, 0x31               // r1 = saved ra

    // Allocate trap frame on current kernel stack.
    addi.d  $sp, $sp, -280

    // Save r1 (ra) and r3 (sp before frame alloc).
    st.d    $r1, $sp, 1*8           // frame.regs[1] = ra
    addi.d  $r1, $sp, 280
    st.d    $r1, $sp, 3*8           // frame.regs[3] = original sp
    b       .save_common

.from_user:
    // ===== User-mode entry =====
    // r1 = &TrapScratch[cpu] (from SAVE0).
    // Save user sp and r12 to TrapScratch (r12 will be used as scratch).
    st.d    $sp, $r1, 16            // TrapScratch.user_sp = user sp
    st.d    $r12, $r1, 24           // TrapScratch.padding = user r12 (save before clobber)
    // Load kernel sp.
    ld.d    $sp, $r1, 0             // sp = TrapScratch.kernel_sp
    // Allocate trap frame.
    addi.d  $sp, $sp, -280

    // Save ra from SAVE1.
    csrrd   $r12, 0x31              // r12 = saved ra (using t0 as temp)
    st.d    $r12, $sp, 1*8          // frame.regs[1] = user ra

    // Save user sp from TrapScratch.
    ld.d    $r12, $r1, 16           // r12 = user sp
    st.d    $r12, $sp, 3*8          // frame.regs[3] = user sp

    // Restore original user r12 from TrapScratch before .save_common.
    ld.d    $r12, $r1, 24           // r12 = original user r12

    // Clear SAVE0 (now in kernel mode).
    csrwr   $zero, 0x30             // SAVE0 = 0

.save_common:
    // Save r0 (always zero, but keep frame consistent).
    st.d    $zero, $sp, 0*8         // frame.regs[0] = 0
    // r1 (ra) and r3 (sp) already saved above.
    // Save r2 (tp).
    st.d    $r2, $sp, 2*8
    // Save r4-r31.
    st.d    $r4,  $sp, 4*8
    st.d    $r5,  $sp, 5*8
    st.d    $r6,  $sp, 6*8
    st.d    $r7,  $sp, 7*8
    st.d    $r8,  $sp, 8*8
    st.d    $r9,  $sp, 9*8
    st.d    $r10, $sp, 10*8
    st.d    $r11, $sp, 11*8
    st.d    $r12, $sp, 12*8
    st.d    $r13, $sp, 13*8
    st.d    $r14, $sp, 14*8
    st.d    $r15, $sp, 15*8
    st.d    $r16, $sp, 16*8
    st.d    $r17, $sp, 17*8
    st.d    $r18, $sp, 18*8
    st.d    $r19, $sp, 19*8
    st.d    $r20, $sp, 20*8
    st.d    $r21, $sp, 21*8
    st.d    $r22, $sp, 22*8
    st.d    $r23, $sp, 23*8
    st.d    $r24, $sp, 24*8
    st.d    $r25, $sp, 25*8
    st.d    $r26, $sp, 26*8
    st.d    $r27, $sp, 27*8
    st.d    $r28, $sp, 28*8
    st.d    $r29, $sp, 29*8
    st.d    $r30, $sp, 30*8
    st.d    $r31, $sp, 31*8

    // Save ERA, PRMD, ESTAT.
    csrrd   $t0, 0x6                // ERA
    st.d    $t0, $sp, 32*8
    csrrd   $t0, 0x1                // PRMD
    st.d    $t0, $sp, 33*8
    csrrd   $t0, 0x5                // ESTAT
    st.d    $t0, $sp, 34*8

    // Call Rust trap handler: a0 = sp (pointer to TrapFrame).
    move    $a0, $sp
    bl      trap_handler
    // Return value in a0 = (potentially new) sp.
    move    $sp, $a0

    // Restore ERA, PRMD.
    ld.d    $t0, $sp, 32*8
    csrwr   $t0, 0x6                // ERA
    ld.d    $t0, $sp, 33*8
    // Check PRMD.PPLV BEFORE csrwr (csrwr swaps: returns old value in rd).
    andi    $t1, $t0, 0x3
    csrwr   $t0, 0x1                // PRMD (t0 now has old PRMD, don't use)
    beqz    $t1, .restore_to_kernel

.restore_to_user:
    // Returning to user mode: set SAVE0 = &TRAP_SCRATCH_ARRAY[cpu_id].
    csrrd   $t0, 0x20               // t0 = CSR.CPUID
    la.pcrel $t1, TRAP_SCRATCH_ARRAY
    slli.d  $t0, $t0, 5             // t0 = cpu_id * 32 (sizeof TrapScratch)
    add.d   $t1, $t1, $t0           // t1 = &TRAP_SCRATCH_ARRAY[cpu_id]

    // Store kernel_sp for the next user trap.
    addi.d  $t0, $sp, 280
    st.d    $t0, $t1, 0             // TrapScratch.kernel_sp = stack_top

    // Set SAVE0 for the next user trap.
    csrwr   $t1, 0x30               // SAVE0 = &TrapScratch[cpu_id]

    // Restore r1-r2, r4-r31 (not r0/zero, not r3/sp yet).
    ld.d    $r1,  $sp, 1*8
    ld.d    $r2,  $sp, 2*8
    ld.d    $r4,  $sp, 4*8
    ld.d    $r5,  $sp, 5*8
    ld.d    $r6,  $sp, 6*8
    ld.d    $r7,  $sp, 7*8
    ld.d    $r8,  $sp, 8*8
    ld.d    $r9,  $sp, 9*8
    ld.d    $r10, $sp, 10*8
    ld.d    $r11, $sp, 11*8
    ld.d    $r12, $sp, 12*8
    ld.d    $r13, $sp, 13*8
    ld.d    $r14, $sp, 14*8
    ld.d    $r15, $sp, 15*8
    ld.d    $r16, $sp, 16*8
    ld.d    $r17, $sp, 17*8
    ld.d    $r18, $sp, 18*8
    ld.d    $r19, $sp, 19*8
    ld.d    $r20, $sp, 20*8
    ld.d    $r21, $sp, 21*8
    ld.d    $r22, $sp, 22*8
    ld.d    $r23, $sp, 23*8
    ld.d    $r24, $sp, 24*8
    ld.d    $r25, $sp, 25*8
    ld.d    $r26, $sp, 26*8
    ld.d    $r27, $sp, 27*8
    ld.d    $r28, $sp, 28*8
    ld.d    $r29, $sp, 29*8
    ld.d    $r30, $sp, 30*8
    ld.d    $r31, $sp, 31*8

    // Restore user sp (must be last — clobbers sp).
    ld.d    $sp, $sp, 3*8
    ertn

.restore_to_kernel:
    // Returning to kernel mode: SAVE0 must stay 0.
    // Restore r1-r2, r4-r31 (not r3/sp — restore at end, not r0/zero).
    ld.d    $r1,  $sp, 1*8
    ld.d    $r2,  $sp, 2*8
    ld.d    $r4,  $sp, 4*8
    ld.d    $r5,  $sp, 5*8
    ld.d    $r6,  $sp, 6*8
    ld.d    $r7,  $sp, 7*8
    ld.d    $r8,  $sp, 8*8
    ld.d    $r9,  $sp, 9*8
    ld.d    $r10, $sp, 10*8
    ld.d    $r11, $sp, 11*8
    ld.d    $r12, $sp, 12*8
    ld.d    $r13, $sp, 13*8
    ld.d    $r14, $sp, 14*8
    ld.d    $r15, $sp, 15*8
    ld.d    $r16, $sp, 16*8
    ld.d    $r17, $sp, 17*8
    ld.d    $r18, $sp, 18*8
    ld.d    $r19, $sp, 19*8
    ld.d    $r20, $sp, 20*8
    ld.d    $r21, $sp, 21*8
    ld.d    $r22, $sp, 22*8
    ld.d    $r23, $sp, 23*8
    ld.d    $r24, $sp, 24*8
    ld.d    $r25, $sp, 25*8
    ld.d    $r26, $sp, 26*8
    ld.d    $r27, $sp, 27*8
    ld.d    $r28, $sp, 28*8
    ld.d    $r29, $sp, 29*8
    ld.d    $r30, $sp, 30*8
    ld.d    $r31, $sp, 31*8

    // Restore kernel sp (deallocate frame).
    addi.d  $sp, $sp, 280
    ertn
