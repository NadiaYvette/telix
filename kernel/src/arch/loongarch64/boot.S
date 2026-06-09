// Telix kernel entry point for LoongArch64.
//
// QEMU virt machine loads ELF at PA 0x200000, enters at _start in PLV0.
// CRMD.DA=1 (direct address translation), MMU off.
// a0 = core id, a1 may contain FW_CFG or 0.

.section .text.boot, "ax"
.global _start

_start:
    // Use an atomic flag to ensure only one core proceeds.
    la.pcrel  $t0, _boot_lock
    li.w      $t1, 1
    amadd.w   $t2, $t1, $t0      // t2 = old value, *t0 += 1
    bnez      $t2, .secondary_spin

    // Save arguments.
    move      $s0, $a0            // s0 = core id
    move      $s1, $a1            // s1 = fw_cfg pointer

    // Zero BSS.
    la.pcrel  $t0, __bss_start
    la.pcrel  $t1, __bss_end
.bss_loop:
    bgeu      $t0, $t1, .bss_done
    st.d      $zero, $t0, 0
    addi.d    $t0, $t0, 8
    b         .bss_loop
.bss_done:

    // Set up boot stack.
    la.pcrel  $sp, __boot_stack_top

    // Call Rust entry. a0 = core_id, a1 = fw_cfg pointer.
    move      $a0, $s0
    move      $a1, $s1
    bl        _rust_entry

    // Should not return.
.halt:
    idle      0
    b         .halt

// Secondary CPUs: poll a per-core slot in _ap_entry_slot waiting for
// the BSP to install (entry, stack_top).  Once the entry pointer is
// non-zero we jump to it with a0 = core_id.  CSR.CPUID (0x20) is the
// authoritative core identity — QEMU may not preserve the original a0
// across the lock branch on every release.
.secondary_spin:
    // #257 (partial): configure DMW0/DMW1 so post-wake APs can access
    // high-half VAs coherently with the BSP.  Currently DEAD CODE on
    // QEMU virt because APs never reach here — see big comment below.
    //
    // KNOWN BUG: QEMU's loongarch64 virt machine does NOT start APs at
    // _start.  APs are halted at reset and require the LoongArch
    // mailbox+IPI wake protocol to bring online:
    //   1. BSP writes (entry_pc, sp, ...) to remote AP's MBUF
    //      via IOCSR_MBUF*_WR_OTHER (target_cpu encoded in payload).
    //   2. BSP sends IPI to remote AP via IOCSR_IPI_SEND.
    //   3. AP, in halt state, wakes and a QEMU-provided stub reads its
    //      MBUF then jumps to the entry_pc.
    //
    // start_secondary_cpus() in smp.rs currently writes
    // _ap_entry_slot and sends IPI, but the APs aren't polling
    // _ap_entry_slot — they're waiting on MBUF.  Result: SMP startup
    // timeout, only BSP runs.  Confirmed empirically by an 'S' marker
    // at the top of _start showing only 1 core enters.
    //
    // The DMW config below is correct preparation; when the mailbox
    // wake-protocol is implemented in smp.rs, APs will be released
    // into a fresh entry point that should jump into something like
    // this stub.  Until then, this code is never reached.
    li.d      $t0, 0x9000000000000011  // VSEG=0x9, MAT=cached, PLV0
    csrwr     $t0, 0x180          // CSR.DMW0
    li.d      $t0, 0x8000000000000001  // VSEG=0x8, MAT=uncached, PLV0
    csrwr     $t0, 0x181          // CSR.DMW1
    dbar      0

    csrrd     $t0, 0x20           // CSR.CPUID
    la.pcrel  $t1, _ap_entry_slot
    slli.d    $t2, $t0, 4         // core_id * 16 (slot stride)
    add.d     $t1, $t1, $t2
.ap_poll:
    dbar      0                   // sync each iteration so cached zero
    ld.d      $t3, $t1, 0         // doesn't lock us out of seeing BSP's write
    beqz      $t3, .ap_poll
    ld.d      $sp, $t1, 8         // stack top
    move      $a0, $t0            // core_id
    jirl      $zero, $t3, 0
    // Should not return; halt if it does.
.ap_unreachable:
    idle      0
    b         .ap_unreachable

// Atomic boot lock.
.section .data
.balign 4
_boot_lock:
    .word     0

// Per-core (entry, stack_top) slots, 16 B each.  BSP writes these from
// arch::loongarch64::smp::start_secondary_cpus(); secondaries poll them
// in .ap_poll above.  Sized for MAX_CPUS=4.
.section .bss._ap_entry_slot, "aw", @nobits
.balign 16
.global _ap_entry_slot
_ap_entry_slot:
    .space    64

// Boot stack: 64 KiB in BSS.
.section .bss.boot_stack, "aw", @nobits
.balign 16
__boot_stack_bottom:
    .space    65536
.global __boot_stack_top
__boot_stack_top:
